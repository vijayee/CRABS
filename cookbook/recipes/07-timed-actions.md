---
number: 7
slug: timed-actions
title: Actions that wait for a time
section: Conditions
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
teaches: clocks, schedules and the submission/fire boundary
---
## Intent

You want an action that must happen *when the clock says so*, not when a
caller remembers to send it: a token that must not count toward anything
until a release time T, a recurring mint every interval, a deadline that
either fires or is cancelled. The submission happens now, by someone
online; the effect happens later, by the machine — and the authorization
happens exactly once, at submission, when the machine can still reject
you.

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
What you want is the *schedule itself* as machine state — an op signed and
validated at submission, queued with its due time, and materialized by the
machine's own tick with no signer online at fire time.

## The shape

- Submission: `schedule(innerOp, executeAtMs) -> bigint` — the op is
  signed NOW (signer, policy, HLC), serialized into the pending entry with
  its submitter, and the machine hands back a schedule id
  (`bindings/wasm/index.d.ts:501`; exercised
  `bindings/wasm/test/schedules.js:25-35`). A recurring version takes a
  start time, an interval, a repeat count and an optional end:
  `scheduleRecurring(op, startAtMs, intervalMs, repeatCount, endAtMs)`
  (:502-503, `schedules.js:60-66`).
- Inspection: `pendingSchedules()` returns the queue —
  `{id, executeAt, intervalMs, repeatCount, endAt, submitter}` with
  bigints (:509-511) — and `cancelSchedule(id)` removes one before due
  (:504).
- Ticking: `processSchedules(nowMs)`. This is an EXPLICIT clock poke — the
  demo passes a fixed `now` and never depends on the wall clock; the
  default argument is `Date.now()`
  (`bindings/wasm/bindings-core.js:1316`). Every due entry materializes
  through the machine's executor with the authorization step *skipped* —
  signature and policy were checked when you submitted, so the fire re-runs
  only the domain check and the engine's guards (transitions, locks, dedup,
  tx-manager) — and a failed materialization (e.g. the op's handler no
  longer resolving) is recorded as an `__schedule_failed__` entry and never
  propagated to the caller (`src/Scheduler/scheduler.h:42-50`). Catch-up
  after downtime fires all missed slots IN ORDER; a schedule that already
  executed re-materializes nothing (idempotent skip on
  `CRABS_ERR_ALREADY_EXECUTED`, `scheduler.c:257`).
- Burst control: `setScheduleOccurrenceBudget(maxPerTick)` bounds the
  per-tick catch-up burst; deferred slots carry over and keep their exact
  slots; `0` is unlimited (:507-508, `schedules.js:84-93`).
- The schedule IS machine state: the pending set survives a serialize /
  deserialize round trip and schedule ids continue after restore (never
  collide with a restored id — `test/test_scheduler.cpp:111-158,199-230`).

## What it guarantees / what it doesn't

Guaranteed: the op you scheduled was validated *at submission* — policy,
signature and key version (plus co-signatures) are checked by the machine
before the entry is queued (`src/Util/wasm_helpers.c:1509-1519`), and the
fire then deliberately skips a second authorization pass
(`src/StateMachine/state_machine.c:1199-1201`). That cuts both ways: a
schedule whose signer loses the required policy *after* submission still
fires — the machine does not re-evaluate policy at fire time. If you need
the policy consulted *then*, that is the trigger-with-a-condition shape
(Recipe 6), not a schedule. What *is* re-run at fire time is narrower: the
domain check and the engine's guards (transitions, locks, dedup,
tx-manager), plus the exactly-once guard that keys the materialization on
the op uuid (`test/test_scheduler.cpp:485-529`). Cancelled schedules never
materialize; recurring series hold their cadence; the budget bounds how
much a single tick can do, with carry-over rather than loss. The whole
queue is replicated state — another replica loading the machine gets the
same pending set.

Not guaranteed: anything about the clock you don't pin. `processSchedules`
with the default `Date.now()` is the unauthenticated system clock — for a
timed action whose *authority* matters (deadlines, expiries), attach an
authenticated source instead: `setTimeSource({mode:'https'})` which fails
closed (a fetch failure reports invalid time, never a local-clock
fallback, `bindings/wasm/index.d.ts:491-498`; semantics
`src/TimeSource/`). The same holds on crabs-node, whose `processSchedules`
default is the wall clock too (`bindings/node/index.d.ts:320-324`) — and
whose `setTimeSource` is machine-local (re-apply it on a surviving wrapper
if a sibling one is destroyed, node d.ts `:346-359`).

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
  same execute pipeline (`src/StateMachine/state_machine.c:1508-1527`).
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
  Node.create              bindings/wasm/index.d.ts:549
  KeyPair.generate         bindings/wasm/index.d.ts:21
  publicKeyHex             bindings/wasm/index.d.ts:15
  KeyPair.destroy          bindings/wasm/index.d.ts:17
  registerUser             bindings/wasm/index.d.ts:353
  grantRole                bindings/wasm/index.d.ts:354
  addCounter               bindings/wasm/index.d.ts:363
  getCounter               bindings/wasm/index.d.ts:394
  setPolicy                bindings/wasm/index.d.ts:435
  registerHandlerJs        bindings/wasm/index.d.ts:480
  HandlerState.incrementCounter bindings/wasm/index.d.ts:103
  Operation.create         bindings/wasm/index.d.ts:52
  Operation.signerId       bindings/wasm/index.d.ts:28
  Node.sign                bindings/wasm/index.d.ts:454
  Node.schedule            bindings/wasm/index.d.ts:501
  Node.scheduleRecurring   bindings/wasm/index.d.ts:502-503
  Node.cancelSchedule      bindings/wasm/index.d.ts:504
  Node.processSchedules    bindings/wasm/index.d.ts:505
  Node.setScheduleOccurrenceBudget bindings/wasm/index.d.ts:507
  Node.scheduleOccurrenceBudget    bindings/wasm/index.d.ts:508
  Node.pendingSchedules    bindings/wasm/index.d.ts:509-511
  Node.destroy             bindings/wasm/index.d.ts:545
  (Date.now() default tick)  bindings/wasm/bindings-core.js:1316
  (failures recorded, idempotent skip) src/Scheduler/scheduler.h:42-50 + src/Scheduler/scheduler.c:257
  (exactly-once uuid guard)  test/test_scheduler.cpp:485-529
maturity: all STABLE
test_ref: bindings/wasm/test/schedules.js:25-93 (one-off, cancel, recurring catch-up, occurrence budget)
-->

### crabs-node (native Node.js)

The whole schedule surface is ported: the same method names as the wasm
wrapper (d.ts `bindings/node/index.d.ts:306-331`), driven by the node's
own machine. `schedule(innerOp, executeAtMs)` runs the machine's read-only
validate pass (policy + signature + key version + co-signatures + domain
check) BEFORE queueing — the same submission-time authorization gate the
wasm wrapper carries (`bindings/node/src/crabs_node.cc:1902-1906`) — and
materialization skips the re-authorization exactly as the C engine does.
One node-specific difference: there is no `registerHandlerJs`, so a
scheduled op's fire is observable through the 'change' event stream —
every materialized slot (and every durable `__schedule_failed__` record)
fires a kind-`schedule` event (`Node.on`,
`bindings/node/index.d.ts:218`), which is how the demo's audit ledger is
asserted. Watch the fire events rather than polling a counter.

```snippet:node/07-timed-actions.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  Node                            bindings/node/index.d.ts:210
  Node.registerUser               bindings/node/index.d.ts:212
  Node.grantRole                  bindings/node/index.d.ts:213
  Node.on                         bindings/node/index.d.ts:218
  Node.addCounter                 bindings/node/index.d.ts:223
  Node.addResource                bindings/node/index.d.ts:229
  Node.setPolicy                  bindings/node/index.d.ts:279
  Node.sign                       bindings/node/index.d.ts:292
  Node.schedule                   bindings/node/index.d.ts:309
  Node.scheduleRecurring          bindings/node/index.d.ts:315-316
  Node.cancelSchedule             bindings/node/index.d.ts:318
  Node.processSchedules           bindings/node/index.d.ts:324
  Node.setScheduleOccurrenceBudget bindings/node/index.d.ts:326
  Node.scheduleOccurrenceBudget   bindings/node/index.d.ts:327
  Node.pendingSchedules           bindings/node/index.d.ts:329-331
  KeyPair.generate                bindings/node/index.d.ts:14
  KeyPair.publicKeyHex            bindings/node/index.d.ts:8
  Operation.addResource           bindings/node/index.d.ts:26
  (submission validate gate)      bindings/node/src/crabs_node.cc:1902-1906 + :1942-1946
  (wall-clock tick default)       bindings/node/src/crabs_node.cc:1980-1984
  C engine unchanged: scheduler_schedule / _recurring / cancel / process_due / count / first / budget
                                  src/Scheduler/scheduler.h:20-55
  (materialization skips signature re-check) src/Scheduler/scheduler.c:337-338
maturity: all STABLE
test_ref: bindings/node/test/test.js (schedule-surface block — one-off exactly-once via change events, not-due skip, cancel pin, unknown-id resource_not_found, recurring 3-fire catch-up, budget defer + lift, unauthorized/unknown-signer submission refusals, typed argument rejections)
-->

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

- The wasm `schedule()` call wraps `crabs_wasm_schedule`, which validates
  the op AT SUBMISSION — policy, signature, key version, co-signatures,
  plus a read-only domain check — via `state_machine_validate` before
  handing it to `scheduler_schedule` (`src/Util/wasm_helpers.c:1509-1519`,
  mirroring the `__schedule__` op path). Materialization deliberately does
  NOT re-run that authorization: the executor is entered with
  `skip_authorization` set ("authorization was already enforced at
  submission time", `src/StateMachine/state_machine.c:1199-1201`;
  "materialization skips signature verification — authorization happened
  at submission", `src/Scheduler/scheduler.c:337-338`). What a fire still
  demands is a *handler and resolvable resources*: a policy-gated type
  whose registered handler exists, or the fire records
  `resource_not_found` (the engine refuses a zero-resource custom op with
  a valid policy but no handler, `test_scheduler.cpp:239-256`).
- `processSchedules(nowMs?)` defaults to the system clock, but the demo
  always passes `nowMs` explicitly — in production, decide this
  consciously: `setTimeSource({mode:'https'})` for authenticated wall
  time (wasm: module-shared source, re-attaching every machine;
  node: machine-local and silently stripped by a sibling destroy — both
  documented in the d.ts prose, `:491-498` wasm / `:346-359` node).
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