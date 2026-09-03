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
- **Failure at T** (state drifted: resource re-locked, invariant violated):
  the entry is consumed, the op is dropped, and the error is returned from
  the tick. Checks run before effects, so no partial state.
- **Cross-node:** each node materializes on its own authenticated clock and
  converges eventually. The materialized op's uuid enters each node's
  log/dedup, so a node receiving it through replication does not re-apply it.

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
| Embedded op fails at materialization | Entry consumed, op dropped, error to the tick; no partial state |
| Embedded `__schedule__` (nesting) | Rejected at submission |
| Cancel of unknown id | `CRABS_ERR_RESOURCE_NOT_FOUND` |
| Clock skew between nodes | Accepted; eventual convergence |

## Testing

- **`test/test_scheduler.cpp`:** schedule → not due → still pending; due →
  materialized exactly once; CRDT mutated by a scheduled handler op; embedded
  validation failures rejected at submission (bad signature, failing policy,
  transition mismatch); nesting rejected; cancel works; past `execute_at`
  rejected; serialization roundtrip preserves the pending set.
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

- Recurring schedules (next feature: recurring flag re-inserting the next
  pending instance deterministically at each materialization).
- Persisted failure records for dropped materializations (the consumed-entry +
  error-return contract is the v1 observability; devtools surfaces the rest).
- Cross-node coordination of *which* node materializes (every node does, by
  design).