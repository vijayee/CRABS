---
number: 7
slug: timed-actions
title: Actions that wait for a time
section: Conditions
status: PARTIAL
maturity: STABLE
target: crabs-wasm
languages: c wasm node
---
## Intent

You want an action that must happen *when the clock says so*, not when a
caller remembers to send it: a token that must not count toward anything
until a release time T, a recurring mint every interval, a deadline that
either fires or is cancelled. The submission happens now, by someone
online; the effect happens later, by the machine — with the same
authorization either way.

## The naive version, and where it breaks

The naive version is `setTimeout(() => submit(op), delay)` in the client.
The tab that promised to fire can be closed before T — a page reload, a
phone lock screen, a crash — and the action silently never lands. Fix it
with two tabs? Then it lands twice. Persist the timer to localStorage and
re-arm on load? Now each replica re-fires an unknown number of times, and
the "at most once" question reappears in a place nobody chose to answer
it.

A server-side cron is the usual answer, and it reintroduces the trusted
middleman: the cron holds credentials, decides ordering, and can skip.
What you want is the *schedule itself* as machine state — an op signed at
submission, queued with its due time, and materialized by the machine's
own tick through the full authorization pipeline.

## The shape

- Submission: `schedule(innerOp, executeAtMs) -> bigint` — the op is
  signed NOW (signer, policy, HLC), serialized into the pending entry with
  its submitter, and the machine hands back a schedule id
  (`bindings/wasm/index.d.ts:324`; exercised
  `bindings/wasm/test/schedules.js:25-35`). A recurring version takes a
  start time, an interval, a repeat count and an optional end:
  `scheduleRecurring(op, startAtMs, intervalMs, repeatCount, endAtMs)`
  (:325-326, `schedules.js:60-66`).
- Inspection: `pendingSchedules()` returns the queue —
  `{id, executeAt, intervalMs, repeatCount, endAt, submitter}` with
  bigints (:332-334) — and `cancelSchedule(id)` removes one before due
  (:327).
- Ticking: `processSchedules(nowMs)`. This is an EXPLICIT clock poke — the
  demo passes a fixed `now` and never depends on the wall clock; the
  default argument is `Date.now()`
  (`bindings/wasm/bindings-core.js:1210`). Every due entry
  materializes through the machine's full executor — signature,
  policy, staleness — and a failed materialization is recorded as an
  `__schedule_failed__` entry and never propagated to the caller
  (`src/Scheduler/scheduler.h:42-50`). Catch-up after downtime fires all
  missed slots IN ORDER; a schedule that already executed re-materializes
  nothing (idempotent skip on `CRABS_ERR_ALREADY_EXECUTED`,
  `scheduler.c:257`).
- Burst control: `setScheduleOccurrenceBudget(maxPerTick)` bounds the
  per-tick catch-up burst; deferred slots carry over and keep their exact
  slots; `0` is unlimited (:330-331, `schedules.js:84-93`).
- The schedule IS machine state: the pending set survives a serialize /
  deserialize round trip and schedule ids continue after restore (never
  collide with a restored id — `test/test_scheduler.cpp:111-158,199-230`).

## What it guarantees / what it doesn't

Guaranteed: a materialized op ran through the same verification an
interactive op would have — the embedded op was fully signed at
submission, and authorization is enforced at fire time, so a policy that
changed between submission and fire is honored *at fire* — and it lands
exactly once (the materialization guard keys on the op uuid;
`test/test_scheduler.cpp:485-529`). Cancelled schedules never
materialize; recurring series hold their cadence; the budget bounds how
much a single tick can do, with carry-over rather than loss. The whole
queue is replicated state — another replica loading the machine gets the
same pending set.

Not guaranteed: anything about the clock you don't pin. `processSchedules`
with the default `Date.now()` is the unauthenticated system clock — for a
timed action whose *authority* matters (deadlines, expiries), attach an
authenticated source instead: `setTimeSource({mode:'https'})` which fails
closed (a fetch failure reports invalid time, never a local-clock
fallback, `bindings/wasm/index.d.ts:313-321`; semantics
`src/TimeSource/`). And on crabs-node there is nothing to call — see the
gap below; node carries time plumbing only (`setTime`, `setTimeSource`,
`getTimeSource`, `getHLC`) with no schedule surface.

## Variations

- Deadline-bounded series: `scheduleRecurring(..., endAtMs)` stops the
  series once `execute_at` passes the end even if fires remain
  (`src/Scheduler/scheduler.h:23-30`; `repeatCount: 0` means infinite —
  with an `endAt` that is the only stopper).
- Watching instead of polling: each materialized slot fires a `schedule`
  change event, and cancellations carry the node id (per-materialized-slot
  hooks are pinned in `test/test_scheduler.cpp:1280-1321`), so a UI can
  render the pending countdown from `on('change')` + `pendingSchedules()`.
- Composed with triggers: a *condition* (Recipe 6) decides `whether`, a
  *schedule* decides `when` — e.g. a recurring escalation tick whose
  embedded op is itself policy-gated. Both run through Step 9/9b of the
  same execute pipeline (`src/StateMachine/state_machine.c:1508-1520`).
- Time-ordered reads: `getHLC()` (node only, `bindings/node/index.d.ts:263`)
  exposes the machine's hybrid logical clock for reasoning about event
  order — the C surface (`src/HLC/hlc.h`) implements the same timestamps
  the executor stamps.

## Recipe

### crabs-wasm (browser / Node / edge)

```snippet:wasm/07-timed-actions.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create              bindings/wasm/index.d.ts:372
  KeyPair.generate         bindings/wasm/index.d.ts:21
  publicKeyHex             bindings/wasm/index.d.ts:15
  KeyPair.destroy          bindings/wasm/index.d.ts:17
  registerUser             bindings/wasm/index.d.ts:213
  grantRole                bindings/wasm/index.d.ts:214
  addCounter               bindings/wasm/index.d.ts:223
  getCounter               bindings/wasm/index.d.ts:254
  setPolicy                bindings/wasm/index.d.ts:295
  registerHandlerJs        bindings/wasm/index.d.ts:303
  HandlerState.incrementCounter bindings/wasm/index.d.ts:103
  Operation.create         bindings/wasm/index.d.ts:52
  Operation.signerId       bindings/wasm/index.d.ts:28
  Node.sign                bindings/wasm/index.d.ts:297
  Node.schedule            bindings/wasm/index.d.ts:324
  Node.scheduleRecurring   bindings/wasm/index.d.ts:325-326
  Node.cancelSchedule      bindings/wasm/index.d.ts:327
  Node.processSchedules    bindings/wasm/index.d.ts:328
  Node.setScheduleOccurrenceBudget bindings/wasm/index.d.ts:330
  Node.scheduleOccurrenceBudget    bindings/wasm/index.d.ts:331
  Node.pendingSchedules    bindings/wasm/index.d.ts:332-334
  Node.destroy             bindings/wasm/index.d.ts:368
  (Date.now() default tick)  bindings/wasm/bindings-core.js:1210
  (failures recorded, idempotent skip) src/Scheduler/scheduler.h:42-50 + src/Scheduler/scheduler.c:257
  (exactly-once uuid guard)  test/test_scheduler.cpp:485-529
maturity: all STABLE
test_ref: bindings/wasm/test/schedules.js:25-93 (one-off, cancel, recurring catch-up, occurrence budget)
-->

### crabs-node (native Node.js)

crabs-node has *no schedule surface*. Time is there; execution is not.

> [!WARNING] GAP
>
> **Prose describes:** queueing a signed op with a due time from
> crabs-node and ticking the machine's queue — the Recipe's whole demo,
> on the native Node.js binding.
>
> **Codebase status:** the engine exists in C and is deeply tested —
> `scheduler_schedule` / `scheduler_schedule_recurring` / `scheduler_cancel`
> / `scheduler_process_due` / the occurrence budget
> (`src/Scheduler/scheduler.h:20-55`; 37 tests in
> `test/test_scheduler.cpp`, from exactly-once
> `test_scheduler.cpp:485-529` to budget carry-over `:1029-1082`) — and
> EVERY method is bound on the wasm side (`bindings/wasm/index.d.ts:324-334`).
>
> **Divergence:** `bindings/node/index.d.ts` declares none of it — no
> `schedule`, `scheduleRecurring`, `cancelSchedule`, `processSchedules`,
> `pendingSchedules`, or occurrence-budget symbols anywhere in the node
> surface (api-map §6, "schedules are entirely wasm-only" and difference
> list item 3). crabs-node keeps the *time-plumbing* half:
> `setTime` (:264), `setTimeSource`/`getTimeSource` (:279-280), and
> `getHLC` (:263) are declared and tested (`test/test.js:81,272`).
>
> **Tracking:** an internal implementation plan (not published on this
> site). The gap is recorded in api-map §17 ("R7 | schedules,
> `setTimeSource`, HLC").
>
> **Agent action:** code block omitted. Do not fabricate a
> `node.schedule()` onto the d.ts — drive the wasm binding, or call the C
> scheduler (`src/Scheduler/scheduler.h`) from a native process that owns
> the state.

### C (native)

```snippet:c/07-timed-actions.c
```

<!-- PROVENANCE
target: native-c
verified: executed
symbols:
  scheduler_schedule           src/Scheduler/scheduler.h:20-21
  scheduler_schedule_recurring src/Scheduler/scheduler.h:27-30
  scheduler_cancel             src/Scheduler/scheduler.h:33
  scheduler_count              src/Scheduler/scheduler.h:36
  scheduler_first              src/Scheduler/scheduler.h:40
  scheduler_process_due        src/Scheduler/scheduler.h:50
  scheduler_set_max_occurrences_per_tick src/Scheduler/scheduler.h:55
  scheduled_operation_t        src/CRABS/data_model.h:463-473
  (uuid discipline / materialization guard) test/test_scheduler.cpp:286-299
  attribute_machine_create     src/Attribute/attribute_machine.h:118
  attribute_machine_find_user  src/Attribute/attribute_machine.h:187
  state_add_policy             src/CRABS/data_model.h:720
  state_machine_register_handler src/StateMachine/state_machine.h:238
  operation_create             src/StateMachine/state_machine.h:243
  operation_destroy            src/StateMachine/state_machine.h:244
  crabs_serialize_for_signing  src/Serialization/serialization.h:96
  crypto_sign_operation        src/Crypto/crypto.h:162-164
  crypto_ecdsa_generate        src/Crypto/crypto.h:21
  CRABS_UUID_SIZE              src/CRABS/crabs.h:40
  CRABS_SUCCESS                src/CRABS/crabs.h:65
maturity: all STABLE
test_ref: test/test_scheduler.cpp:485-529 (exactly-once materialization) + :877-891 (cadence exhaustion) + :1029-1082 (budget carry-over) + :199-230 (ids continue after restore)
-->

## Notes

- The wasm `schedule()` call is binding-level sugar over the direct C
  library entry (`crabs_wasm_schedule` → `scheduler_schedule`); it does
  not consult authorization itself. Materialization does: the embedded op
  is executed through `state_machine_execute`, so it must be *fully
  authorized* — a policy-gated type whose registered handler exists, or
  the fire records `resource_not_found` (the engine refuses a
  zero-resource custom op with a valid policy but no handler,
  `test_scheduler.cpp:239-256`).
- `processSchedules(nowMs?)` defaults to the system clock, but the demo
  always passes `nowMs` explicitly — in production, decide this
  consciously: `setTimeSource({mode:'https'})` for authenticated wall
  time (wasm: module-shared source, re-attaching every machine;
  node: machine-local and silently stripped by a sibling destroy — both
  documented in the d.ts prose, `:313-321` wasm / `:267-278` node).
- The occurrence budget is node-local RUNTIME policy, not serialized
  state — a restored state reverts to the default
  (`src/Scheduler/scheduler.h:52-55`).
- The `mint` demo uses `repeatCount: 3` to make assertion finite; a real
  recurring mint is `repeatCount: 0` (infinite, cadence-kept) and you
  bound it via `endAtMs` or `cancelSchedule`.
- Schedule ids are per-state monotonic counters — never reuse, and they
  continue past a serialize/restore round trip
  (`test_scheduler.cpp:199-230`), so they are safe to store in app-level
  ledgers.