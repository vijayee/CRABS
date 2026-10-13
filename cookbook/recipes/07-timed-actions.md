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
## The problem

A community machine runs a vesting promise: one thousand tokens are
minted to each early member, but they must not count until Monday
09:00 — and not a second before. The minter is online *now*, Monday is
days away. The same machine wants a recurring mint: a faucet paying out
five tokens per member per day, forever, even over a weekend nobody
opens the app.

So the action has to happen *when the clock says so*, not when a caller
remembers to send it. The submission happens now, by someone online; the
effect happens later, by the machine; and the authorization — the
decision about who may mint — happens exactly once, at submission, while
the machine can still reject you.

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
validated at submission, queued with its due time, and materialized by
the machine's own tick with no signer online at fire time.

## The idea

Every state transition takes inputs. The op's payload is one; the
accumulated state (Recipe 6's thresholds) is another; and the easy one to
forget is **when**. A schedule treats time as an ordinary input to a
transition: the op is *authorized* at one moment and *executes* at
another, and the machine guarantees the bridge between them.

- **Authorization is a submission-time event.** An online machine can
  reject you only while you are talking to it. Delaying the *effect* does
  not delay the *trust decision* — policy, signature, and key version are
  checked when the entry is queued, and the fire is then mechanical. This
  is a trade, not an oversight: the machine promises the fire, not the
  re-evaluation. A signer whose policy is revoked *after* submission
  still fires. If the authority should be re-consulted at fire time, the
  scheduled thing must be a *question* with a condition — a trigger
  (Recipe 6) — not a queued op.
- **What survives the gap is the exactly-once core.** Between submission
  and fire, anything can happen: replicas restart, ticks are missed, an
  outage accumulates due slots. The machine keys each materialization on
  an id derived from the op and its slot, so a re-check after downtime
  fires every missed slot in order — and only once. No client timer
  survives a crash; no client timer ever had a correct at-most-once story.
- **The clock is an input you choose.** "Due" is a comparison against a
  clock the machine was handed: the wall clock is the default, but it is
  unauthenticated — an authority whose time matters wants an
  authenticated source, passed in like any other input.

## How CRABS encodes it

- **Submission:** `schedule(innerOp, executeAtMs)` — the op is signed
  NOW (signer, policy, HLC), the machine runs a read-only validate pass
  (policy, signature, key version, co-signatures, domain check) before
  queueing anything, and the caller gets back a schedule id. The
  recurring version takes a start time, an interval, a repeat count and
  an optional end: `scheduleRecurring(op, startAtMs, intervalMs,
  repeatCount, endAtMs)` — `repeatCount: 0` is infinite, bounded by
  `endAt` or `cancelSchedule` instead.
- **Inspection and cancel:** `pendingSchedules()` returns the queue —
  `{id, executeAt, intervalMs, repeatCount, endAt, submitter}` with
  bigints — and `cancelSchedule(id)` removes one before due.
- **Ticking:** `processSchedules(nowMs)` is an EXPLICIT clock poke — the
  demo passes a fixed `now` and never depends on the wall clock (the
  default argument is `Date.now()`). Every due entry materializes through
  the machine's executor with the authorization step *skipped* — the fire
  re-runs only the domain check and the engine's guards (transitions,
  locks, dedup, tx-manager). But a fire still demands a resolvable
  handler and resources: an op whose handler no longer registers is
  recorded as an `__schedule_failed__` entry and never propagated to the
  caller. Catch-up after downtime fires all missed slots IN ORDER; an
  already-materialized slot re-materializes nothing (idempotent skip on
  the uuid guard).
- **Burst control:** `setScheduleOccurrenceBudget(maxPerTick)` bounds the
  per-tick catch-up burst; deferred slots carry over and keep their exact
  slots; `0` is unlimited. The budget is machine-local runtime policy — a
  restored state reverts to the default.
- **The schedule is machine state:** the pending set survives a
  serialize/deserialize round trip and schedule ids continue after
  restore (never collide with a restored id), so they are safe to keep in
  app-level ledgers.
- **Observing fires:** on crabs-node there is no custom-handler surface,
  so a scheduled fire is observable through the `change` event stream —
  every materialized slot (and every durable `__schedule_failed__`
  record) fires a kind-`schedule` event. Watch the fire events rather
  than polling a counter; "landed" is `result === 0`.
- **Clocks:** `setTimeSource({mode:'https'})` fails closed — a fetch
  failure reports invalid time, never a local-clock fallback. On wasm the
  source is module-shared (re-attach after loading a machine); on
  crabs-node it is machine-local (a sibling wrapper's destroy silently
  strips it — re-apply on the survivor). Node additionally exposes the
  machine's hybrid logical clock via `getHLC()` (wasm has no HLC getter).

## Try it

### crabs-wasm (browser / Node / edge)

```snippet:wasm/07-timed-actions.js
```

### crabs-node (native Node.js)

```snippet:node/07-timed-actions.js
```

### C (native)

```snippet:c/07-timed-actions.c
```

## What it guarantees / what it doesn't

- The scheduled op is validated at submission — policy, signature, key
  version and co-signatures — before anything is queued.
- The fire is authorized-by-construction: no second pass runs at fire
  time, so a schedule whose signer loses the required policy *after*
  submission still fires. If policy must be consulted *then*, that is the
  trigger-with-a-condition shape (Recipe 6), not a schedule.
- What a fire *does* re-run: the domain check and the engine's guards
  (transitions, locks, dedup, tx-manager), plus the exactly-once guard
  keyed on the op uuid.
- Cancelled schedules never materialize; recurring series hold their
  cadence; a failed materialization is recorded, not thrown; the budget
  bounds a tick with carry-over rather than loss.
- The whole queue is replicated state — another replica loading the
  machine gets the same pending set.
- Not guaranteed: any time you don't pin. The `Date.now()` default is the
  unauthenticated system clock on both bindings — for a timed action
  whose *authority* matters (deadlines, expiries), attach an
  authenticated source with `setTimeSource({mode:'https'})` and pass the
  tick's `now` consciously.

## Variations

- Deadline-bounded series — when the faucet belongs to a program with an
  end date: `scheduleRecurring(..., endAtMs)` stops the series once
  `execute_at` passes the end even if fires remain (and `repeatCount: 0`
  means infinite — with an `endAt` that is the only stopper).
- Watching instead of polling — when a UI should render a countdown:
  each materialized slot fires a `schedule` change event and
  cancellations carry the node id, so `on('change')` +
  `pendingSchedules()` is the whole display.
- Composed with triggers — when *whether* and *when* both need deciding:
  a condition (Recipe 6) decides whether, a schedule decides when — e.g.
  a recurring escalation tick whose embedded op is itself policy-gated.
  Both run through the same pipeline's post-authorization steps.
- Time-ordered reads — when reasoning about event order across replicas:
  `getHLC()` (node only) exposes the machine's hybrid logical clock; the
  C surface implements the same timestamps the executor stamps.

## Verified against the code

<!-- PROVENANCE
submission gate: the machine runs a read-only validate pass (state_machine_validate — policy, signature, key version, co-signatures + domain check) BEFORE queueing, in BOTH bindings: wasm crabs_wasm_schedule/_recurring src/Util/wasm_helpers.c:2052-2076 · node bindings/node/src/crabs_node.cc:2628-2646 (Schedule) + :2658-2673 (ScheduleRecurring). Mirrors the C __schedule__ op path.
fire skips re-authorization (post-submission residual): scheduler materialization explicitly skips signature re-check — "materialization skips signature verification — authorization happened at submission" src/Scheduler/scheduler.c:337-338 · executor entered with skip_authorization, gate comment src/StateMachine/state_machine.c:1594 · execute-internal signature: :1522-1524 (the seed's scheduler.c:337 fact, unchanged).
fire-time requirements: a handler + resolvable resources — a zero-resource custom op with a valid policy but no handler refuses resource_not_found (test/test_scheduler.cpp:243-256); failures record __schedule_failed__ entries, never propagated — src/Scheduler/scheduler.h:43-46 · scheduler.c:229, :272, :320, :354.
exactly-once: materialization keyed on derived uuid, idempotent skip on _uuid_in_log — src/Scheduler/scheduler.c:343-351 · uuid-derivation discipline test/test_scheduler.cpp:281-299 · due-op-materialized-exactly-once :485-529.
catch-up: missed slots fire in order, already-applied ids skip idempotently; budget bounds per-tick with carry-over · ids continue after restore — test_scheduler.cpp:992, :1029, :199-230 · pending-set survives roundtrip :111-158.
budget is runtime policy, not serialized state: src/Scheduler/scheduler.h:47-55.
clock honesty: processSchedules defaults to the wall clock in BOTH bindings — wasm bindings/wasm/bindings-core.js:1839 · node bindings/node/src/crabs_node.cc:2713-2718 — and setTimeSource({mode:'https'}) fails closed, no local-clock fallback; wasm source is module-shared (time-source.js:37,54 — replacing it re-attaches every machine), node source machine-local, silently stripped by a sibling destroy (re-apply, bindings/node/index.d.ts:545-553). C source: src/TimeSource/.
node observes fires as 'schedule' change events (no handler surface): Node.on bindings/node/index.d.ts:310 · event result field bindings/node/src/crabs_node.cc:1376; per-materialized-slot hooks test/test_scheduler.cpp:1280-1321.
recurring cadence + endAt: scheduler.h:27-30 (start/interval/repeat/end); cadence-exhaustion test :877-891.

target: crabs-wasm (snippet wasm/07-timed-actions.js)
verified: executed
symbols:
  Node.create            bindings/wasm/index.d.ts:774
  KeyPair.generate       bindings/wasm/index.d.ts:44
  publicKeyHex           bindings/wasm/index.d.ts:38
  KeyPair.destroy        bindings/wasm/index.d.ts:40
  registerUser           bindings/wasm/index.d.ts:480
  grantRole              bindings/wasm/index.d.ts:481
  addCounter             bindings/wasm/index.d.ts:490
  getCounter             bindings/wasm/index.d.ts:554
  setPolicy              bindings/wasm/index.d.ts:638
  registerHandlerJs      bindings/wasm/index.d.ts:683
  HandlerState.incrementCounter bindings/wasm/index.d.ts:195
  Operation.create       bindings/wasm/index.d.ts:122
  Operation.signerId     bindings/wasm/index.d.ts:63
  Node.sign              bindings/wasm/index.d.ts:657
  Node.schedule          bindings/wasm/index.d.ts:726
  Node.scheduleRecurring bindings/wasm/index.d.ts:727-728
  Node.cancelSchedule    bindings/wasm/index.d.ts:729
  Node.processSchedules  bindings/wasm/index.d.ts:730
  Node.setScheduleOccurrenceBudget bindings/wasm/index.d.ts:732
  Node.scheduleOccurrenceBudget    bindings/wasm/index.d.ts:733
  Node.pendingSchedules  bindings/wasm/index.d.ts:734-737
  Node.destroy           bindings/wasm/index.d.ts:770
  (Date.now() default tick)  bindings/wasm/bindings-core.js:1839
  (submission validate gate) src/Util/wasm_helpers.c:2052-2076
  (failures recorded, idempotent skip) src/Scheduler/scheduler.h:43-46 + src/Scheduler/scheduler.c:343-351
  (exactly-once uuid guard)  test/test_scheduler.cpp:485-529
maturity: all STABLE
test_ref: bindings/wasm/test/schedules.js:25-93 (one-off, cancel, recurring catch-up, occurrence budget)

target: crabs-node (snippet node/07-timed-actions.js)
verified: executed
symbols:
  Node interface            bindings/node/index.d.ts:302
  Node.registerUser         bindings/node/index.d.ts:304
  Node.grantRole            bindings/node/index.d.ts:305
  Node.on                   bindings/node/index.d.ts:310
  Node.addCounter           bindings/node/index.d.ts:315
  Node.addResource          bindings/node/index.d.ts:328
  Node.setPolicy            bindings/node/index.d.ts:450
  Node.sign                 bindings/node/index.d.ts:463
  Node.execute              bindings/node/index.d.ts:464
  Node.schedule             bindings/node/index.d.ts:480
  Node.scheduleRecurring    bindings/node/index.d.ts:486-487
  Node.cancelSchedule       bindings/node/index.d.ts:489
  Node.processSchedules     bindings/node/index.d.ts:495
  Node.setScheduleOccurrenceBudget bindings/node/index.d.ts:497
  Node.scheduleOccurrenceBudget    bindings/node/index.d.ts:498
  Node.pendingSchedules     bindings/node/index.d.ts:500-503
  Node.setTimeSource        bindings/node/index.d.ts:551
  Node.getTimeSource        bindings/node/index.d.ts:552
  Node.getHLC               bindings/node/index.d.ts:535
  HLC interface             bindings/node/index.d.ts:206-212
  NodeStatic.new            bindings/node/index.d.ts:641-642 (new Node)
  KeyPair.generate          bindings/node/index.d.ts:71 (KeyPairStatic :69-73)
  KeyPair.publicKeyHex      bindings/node/index.d.ts:28
  Operation.new             bindings/node/index.d.ts:139 (OperationStatic :138)
  Operation.addResource     bindings/node/index.d.ts:83
  (submission validate gate)      bindings/node/src/crabs_node.cc:2628-2646 + recurring :2658-2673
  (wall-clock tick default)       bindings/node/src/crabs_node.cc:2713-2718
  C engine unchanged: scheduler_schedule / _recurring / cancel / process_due / count / first / budget
                                  src/Scheduler/scheduler.h:20-55
  (materialization skips signature re-check) src/Scheduler/scheduler.c:337-338
maturity: all STABLE
test_ref: bindings/node/test/test.js (schedule-surface block — one-off exactly-once via change events, not-due skip, cancel pin, unknown-id resource_not_found, recurring 3-fire catch-up, budget defer + lift, unauthorized/unknown-signer submission refusals, typed argument rejections)

target: native-c (snippet c/07-timed-actions.c)
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
  (uuid discipline / materialization guard) test/test_scheduler.cpp:281-299
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
test_ref: test/test_scheduler.cpp:485-529 (exactly-once materialization) + :877-891 (cadence exhaustion) + :1029-1115 (budget carry-over + zero-budget) + :199-230 (ids continue after restore)
-->