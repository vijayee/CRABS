# CRABS Timed Transactions (Scheduler) — Design

Date: 2026-09-03
Status: Approved design, pending implementation plan
Branch note: implement on `feature/devtools-viewer` or a fresh branch off it after merge.

## Goal

Operations whose effects apply only at a future time. A signed operation can be
submitted now, stored durably in the replicated state, and materialized —
applied exactly as signed — when a node's authenticated clock passes the
scheduled time. Recurring schedules (e.g. "mint N tokens every hour") are a
follow-up feature layered on this primitive.

## Decisions made

- **Semantics:** deferred execution (one-shot primitive first; recurring later).
- **Execution:** any node materializes when its authenticated clock passes T.
  Deterministic pending set held in state; eventual convergence across nodes,
  same model as `evaluateTriggers`.
- **Authorization timing:** full verification (signature, policy, key
  staleness, transitions) happens at **submission**. At T the stored op
  applies exactly as signed — no re-check. Scheduled ops keep working when the
  signer's key rotates before T; policy changes do not retroactively cancel
  them.
- **Deferrable ops:** any signed operation may be embedded, except
  `__schedule__` itself (no nesting).
- **Recurring schedules:** out of scope for v1; recorded as the next feature.

## Architecture

```
┌─ C core ─────────────────────────────────────────────────────┐
│ src/Scheduler/scheduler.{h,c}                                │
│  • scheduled_operation_t list on state_t (durable,           │
│    serialized with crabs_serialize_state)                    │
│  • scheduler_schedule / scheduler_cancel /                   │
│    scheduler_process_due / scheduler_count                   │
│  • __schedule__ + __cancel_schedule__ builtin ops            │
│  • state_machine_validate(state, op) — pipeline check steps  │
│    without applying (used at submission)                     │
│  • state_machine_execute_scheduled(state, op) — internal     │
│    executor: transitions/dedup/handlers/log/tx commit,       │
│    skips user-facing auth + ordering check                   │
│  • scheduler_process_due runs at the end of                  │
│    state_machine_execute (same slot as trigger processing)   │
└──────────────┬───────────────────────────────────────────────┘
┌─ Bindings ───▼───────────────────────────────────────────────┐
│ node.schedule(innerOp, executeAtMs) / cancelSchedule(id) /   │
│ processSchedules() / pendingSchedules()                      │
└──────────────┬───────────────────────────────────────────────┘
┌─ Devtools ───▼───────────────────────────────────────────────┐
│ Config tab "Schedules" section: id, execute-at, submitter,   │
│ due status (from the snapshot JSON "schedules" section)      │
└──────────────────────────────────────────────────────────────┘
```

## Data model

```c
typedef struct scheduled_operation_t {
  uint64_t    schedule_id;    // per-state monotonic counter
  uint64_t    execute_at_ms;  // epoch ms; compared against authenticated now
  char        submitter[CRABS_MAX_USER_ID];
  uint8_t*    op_bytes;       // crabs_serialize_operation of the embedded op
  uint32_t    op_len;
  struct scheduled_operation_t* next;
} scheduled_operation_t;
```

- `state_t` gains `scheduled_operations_t* scheduled_operations` (linked list,
  like `items`/`triggers`) and a `schedule_seq` counter.
- The embedded op is stored serialized so the pending set survives state
  serialization and cannot be mutated in memory between submission and T.
- `crabs_serialize_state` (and `_signed`) gains a pending-operations section —
  a wire-format bump; old payloads stay deserializable, new payloads carry the
  section.
- The list is unsorted (scan on process-due); counts are expected small.

## Submission: the `__schedule__` op

- Payload struct: `execute_at_ms` + the full serialized embedded operation
  (the inner op is signed by whoever must authorize it, at submission time).
- `__schedule__` flows through the normal `state_machine_execute` pipeline —
  its own policy applies (e.g. `role:admin`), signature verified, logged.
- On acceptance the scheduler runs `state_machine_validate(state,
  embedded_op)` — extraction of the pipeline's check steps (signature verify,
  policy eval, key staleness, transition/lock feasibility) without applying
  anything. A failing embedded op rejects the whole `__schedule__`
  (`CRABS_ERR_SCHEDULE_INVALID`) — fail-fast, nothing stored.
- An embedded `__schedule__` is rejected — no nesting.
- `__cancel_schedule__` (builtin, policy-gated) removes a pending entry by id.

## Materialization

- `state_machine_execute` ends with `scheduler_process_due(state, now_ms)`
  (`now_ms` from `state_get_time_ms`). **Fail-closed:** no time source →
  nothing materializes. Also exported as `scheduler_process(state)` for
  on-demand invocation from bindings (same pattern as `evaluateTriggers`).
- Per due entry, in `execute_at` order:
  1. Deserialize the stored op bytes.
  2. Remove the entry from the pending list **first** — this is the
     idempotency guard replacing the R7-11 ordering check for scheduled ops
     (the embedded op's HLC is from sign time and would otherwise read as a
     replay). If the embedded op's uuid is already present in the log or
     tx-manager — i.e. the node already applied it via a replicated
     materialization — skip execution and drop the entry (idempotent).
  3. Execute via `state_machine_execute_scheduled(state, op)`: transition
     checks, dedup, handlers, `append_log`, tx-manager commit — **skips**
     signature/policy/key-staleness and the ordering check (authorized at
     submission). Mirrors how trigger effects execute ops internally.
- **Failure at T** (state drifted: resource re-locked, invariant violated —
  e.g. a scheduled drawdown when the balance has already hit zero): the entry
  is consumed, the op is dropped, and the failure is **recorded durably** as
  a log entry (`__schedule_failed__` carrying the schedule id, the embedded
  op's uuid, and the error code) so the hash-chained audit log stays
  complete and other nodes get a deterministic marker that the schedule
  resolved as failed. The tick **does not propagate the error** to the
  enclosing user op — materialization failures are recorded, never returned
  (same rule as trigger processing; an unrelated op must not fail because a
  scheduled one did). No retry: a schedule fires once — success or failure.
  Checks run before effects, so no partial state.
- **Cross-node:** each node materializes on its own authenticated clock and
  converges eventually. The materialized op's uuid enters each node's
  log/dedup, so a node receiving it through replication does not re-apply
  it. Clock-skew caveat: two nodes can resolve the same schedule differently
  (one fails on an invariant, one succeeds after intervening state) — each
  applies its own deterministic check at its own materialization time, the
  same class of divergence as any conflicting concurrent ops in CRABS:
  CRDT-typed items reconcile via merge, non-CRDT items may diverge as any
  conflicting direct ops can. Documented, not hidden.

## API surface

- **C:** `scheduler_schedule`, `scheduler_cancel`, `scheduler_process_due`,
  `scheduler_count`.
- **Bindings:** `node.schedule(innerOp, executeAtMs)`, `node.cancelSchedule(id)`,
  `node.processSchedules()`, `node.pendingSchedules()` →
  `{id, executeAt, submitter}` list. (crabs-node and wasm helpers +
  `bindings-core.js`.)
- **Devtools:** Config tab gains a **Schedules** section (id, execute-at,
  submitter, due?) fed by a `"schedules": [...]` snapshot section.

## Error handling

| Situation | Behavior |
|---|---|
| `execute_at_ms` in the past at submission | Rejected (`CRABS_ERR_INVALID_PARAM`) |
| No authenticated time source at process-due | Nothing materializes (fail-closed) |
| Embedded op fails validation at submission | `__schedule__` rejected; nothing stored |
| Embedded op fails at materialization | Entry consumed, op dropped, `__schedule_failed__` log entry recorded; tick returns normally; no partial state, no retry |
| Embedded `__schedule__` (nesting) | Rejected at submission |
| Cancel of unknown id | `CRABS_ERR_RESOURCE_NOT_FOUND` |
| Clock skew between nodes | Accepted; eventual convergence |

## Testing

- **`test/test_scheduler.cpp`:** schedule → not due → still pending; due →
  materialized exactly once; CRDT mutated by a scheduled handler op; embedded
  validation failures rejected at submission (bad signature, failing policy,
  transition mismatch); nesting rejected; cancel works; past `execute_at`
  rejected; serialization roundtrip preserves the pending set; **failed
  materialization** (invariant violated at T) → entry consumed,
  `__schedule_failed__` log entry present, and the unrelated user op that
  triggered the tick still succeeds.
- **Replay-guard interaction:** a scheduled op whose signer later performs
  normal ops must materialize without tripping the HLC replay check (the
  bypass's regression test).
- Full native suite stays green (`state_machine_validate` touches the
  pipeline).
- **WASM smoke:** `node.schedule` → `pendingSchedules()` → `processSchedules()`
  with injected time materializes it.
- **Devtools demo:** one scheduled mint visible in Config → Schedules,
  materializing into the Timeline.

## Out of scope (v1)

- Persisted failure records for dropped materializations (the consumed-entry +
  error-return contract is the v1 observability; devtools surfaces the rest).
- Cross-node coordination of *which* node materializes (every node does, by
  design).

---

# Addendum: Recurring Schedules (v2)

Date: 2026-09-03. Extends the scheduler above; all v1 decisions carry over.

## Decisions made

- **Termination:** `repeat_count` (0 = infinite, N = fires N times) **and**
  an optional `end_at_ms` (0 = none); whichever limit arrives first stops the
  schedule.
- **Missed occurrences (catch-up):** fire ALL missed occurrences in slot
  order on the next tick, each merged with other ops through the normal
  pipeline. Each node fires what its own clock says it missed; copies
  converge via CRDT merge/replication like any divergent ops — the
  documented reconciliation stance (application's responsibility).
- **Cadence anchoring:** fixed slots — `execute_at += interval_ms` per fire
  (drift-free), NOT materialization-time + interval.
- **API:** new binding `node.scheduleRecurring(op, startAtMs, intervalMs,
  repeatCount, endAtMs)`; the one-shot `node.schedule` is unchanged.
  C-side: `scheduler_schedule_recurring(state, start_at_ms, interval_ms,
  repeat_count, end_at_ms, submitter, op)`.
- **Per-occurrence identity (as implemented — supersedes the original
  random-uuid design):** each occurrence's uuid is derived deterministically
  as the embedded op's uuid XOR the slot's `execute_at_ms` (little-endian,
  first 8 bytes), recomputed at fire time. Injective per series, stable
  across ticks, and identical across replicas — two nodes catching up the
  same missed slot derive the same uuid, so `_uuid_in_log` converges them
  idempotently instead of producing divergent duplicates. Safe because
  materialization skips signature verification (authorized at submission).
  Regression test: `SchedulerRecurring.FiresAcrossSeparateTicksWithDistinctIdentity`.
  Occurrences execute sequentially in slot order, ordered with any other ops
  through the normal pipeline.
- **Catch-up burst risk (documented, accepted):** catch-up fires ALL missed
  slots in one tick by design; a very small interval combined with long
  downtime (or a crafted state blob with a tiny interval) produces a large
  burst on the node's main thread. There is no per-tick occurrence budget in
  v2 — accepted per the "fire ALL missed occurrences" decision; a budget is
  the escape hatch if this ever matters in practice.

## Data model changes

`scheduled_operation_t` gains:

```c
  uint64_t    interval_ms;    // 0 = one-shot
  uint64_t    repeat_count;   // remaining fires; 0 = infinite
  uint64_t    end_at_ms;      // 0 = no end date
```

Serialization v7: the schedules section writes `interval_ms`, `repeat_count`,
`end_at_ms` per entry (after `execute_at_ms`); readers gated on `version >= 7`;
`schedule_seq` clamp and ordering unchanged. `CRABS_SERIAL_VERSION` bumps to 7.

## Materialization (recurring branch)

In `scheduler_process_due`, a due entry with `interval_ms > 0` is NOT removed
from the pending list up front. Instead, before firing each occurrence:

1. If `end_at_ms != 0 && execute_at > end_at_ms` → remove entry, done.
2. If `repeat_count != 0 && fires_used >= repeat_count` → remove entry, done.
3. Fire once (uuid-in-log skip / failure record as in v1; the entry stays in
   the pending list while firing — remove it only on termination).
4. `execute_at += interval_ms`; increment `fires_used` (or decrement
   `repeat_count` when finite).

The catch-up loop repeats while `execute_at <= now_ms`, firing every missed
slot back-to-back in slot order, bounded by the remaining count. The tick
re-entrancy guard is unchanged; a handler that schedules new work defers to
the next tick as before.

**Validation at scheduling:** `interval_ms > 0` when recurring;
`repeat_count >= 0`; `end_at_ms == 0 || end_at_ms > start_at_ms`. The
`node.scheduleRecurring` convenience path runs `state_machine_validate` on
the embedded op, same as `node.schedule`.

## Termination rules

| Condition | Result |
|---|---|
| `repeat_count` exhausted | Entry removed after the final fire |
| `end_at_ms` passed | Entry removed before the next fire (no partial fire past the end) |
| Cancelled by id | Removed immediately (same as one-shot) |
| `end_at` before `start_at` | Rejected at scheduling (`CRABS_ERR_INVALID_PARAM`) |

## API surface (recurring)

- **C:** `scheduler_schedule_recurring(state, start_at_ms, interval_ms,
  repeat_count, end_at_ms, submitter, op)` → id.
- **Bindings:** `node.scheduleRecurring(innerOp, startAtMs, intervalMs,
  repeatCount, endAtMs)` → bigint id (runs validation, like `node.schedule`).
  `pendingSchedules()` rows gain `intervalMs`, `repeatCount`, `endAt`.
- **Devtools:** Config tab rows show the cadence (`every 60s × 24` or
  `every 60s ∞`).

## Testing (recurring)

- Native: fires on cadence; count termination; end_at termination; catch-up
  fires all missed slots in order after simulated downtime; one-shot entries
  unaffected; serialization roundtrip preserves the three new fields;
  validation rejections (interval 0, end before start).
- WASM smoke: `scheduleRecurring` → two due fires via injected ticks →
  exhausted removal; cancel mid-series.
- Demo: a "Schedule 3 mints (every 15s)" button; browser verification.