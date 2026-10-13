---
number: 3
slug: execute-once
title: Execute once, ever
section: Basics
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
teaches: exactly-once semantics vs. monotone flags
---
## The problem

A web service receives a webhook: "invoice #4471 has been paid." It must run
the effect — mark the invoice paid, ship the receipt, release the funds —
at most once, ever. Webhooks are not polite: the delivery service retries
when an acknowledgement is slow, operators replay from a dead-letter queue,
and two instances of the service can pick up the same batch during a deploy.
Different callers arrive — a retry daemon on Monday, a human re-run on
Thursday, a second service instance during failover — and each one carries
the same "run this" instruction.

Whatever record the service keeps of its decision has to outlive any single
process, refuse the *second* run regardless of who asks, and survive two
service instances that have not compared notes yet.

## The naive version, and where it breaks

The naive version is an in-memory boolean. First run sets `done = true`;
the process restarts, the boolean is gone, and the closeout runs again —
over a state that was already closed. Persisting the boolean is the next
attempt, and it still breaks: write-ahead of the effect (crash between the
two) allows a second run, write-behind allows two concurrent writers to
both see `done = false` and both proceed. The useful primitive is a
*monotone* flag whose merge keeps the earliest setter — so no replica can
ever un-see an execution, and two replicas that saw different executions
agree on the first one.

## The idea

Make "has this been executed?" part of the *state itself*, with two
properties. The flag is **monotone**: one transition, false to true, with no
path back, so no replica and no crash can un-see an execution. And the flag
**merges by earliest, not by latest**: when two replicas have seen different
executions, the merged record keeps the first one, so replicas that met late
still agree on which attempt was the execution.

The word the standards use is *exactly-once* — and this page deliberately
teaches a humbler thing. A monotone flag is *seen-once*: every replica
learns that the effect ran, exactly once, forever. It does not stop two
replicas inside their blind window from running a shared effect twice; no
record can, across replicas that have not met. What the flag gives you is a
converged, irrevocable answer to "did this run?" — the primitive that
idempotency, receipting, and one-way doors are built on.

## How CRABS encodes it

- The persisted outcome is a named `ONE_SHOT_FLAG` item:
  `addOneShotFlag('closeout_done')`. It reads false out of the mint, flips
  true once, and has no path back — `flagSet` has no false transition.
- Raising it is `flagSet(name, setBy, setAtMs)`; reading it is
  `flagValue(name)`.
- The guard is a REGISTERED spec: `defineOperationType('closeout', { dedup:
  'global', flagPath: 'closeout_done' })` installs the global form of the
  recipe 2 registry rule — the machine refuses every run after the first,
  from any signer. The op names the flag item as its resource and carries
  nothing else: guard + flag-set mutation are the spec's, resolved by the
  executor before any handler runs.
- Installing the spec is itself a signed op under the machine's admin
  authority: set `setPolicy('__define_operation_type__', 'role:admin')`
  first (the bootstrap admin holds `role:admin`; the `__create_trigger__`
  precedent).
- Merge semantics of the flag: true dominates, the earliest timestamp wins,
  and ties break lexicographically by setter id.

## Try it

### crabs-wasm (browser / Node / edge)

```snippet:wasm/03-execute-once.js
```

### crabs-node (native Node.js)

```snippet:node/03-execute-once.js
```

### C (native)

```snippet:c/03-execute-once.c
```

## What it guarantees / what it doesn't

- Each signed `closeout` op executes at most once on that machine — the
  second attempt, from any signer, is rejected inside the machine before
  any effect re-runs.
- The flag cannot travel backwards on any replica: once true, always true.
- The registered spec cannot be un-installed by a signer's op — only a
  later admin definition replaces one in place.
- Not exclusivity *across* replicas that have not yet met: two replicas can
  each run the effect inside the blind window (both flags read false
  locally); the merged flag stays true either way, so the record converges —
  but the effect ran twice.
- *Which* attempt won is not observable from the JS bindings: the setter /
  timestamp reads live in the C struct.
- A typo'd flag name reads as "not executed yet" rather than erroring —
  assert the name the first time you mint it.

## Variations

- Idempotent-skip instead of reject — when the caller replays the *same*
  op bytes and silence beats an error: the transaction manager refuses a
  duplicate submission with `already_executed` and callers treat that code
  as an idempotent skip. The registered spec covers the different case — a
  fresh op, signed again, intended to run the effect a second time.
- Once-per-window, not once-ever — when rate limiting beats a one-way
  door: a trigger with `cooldownMs` (Recipe 6's territory) gives you "no
  more than once per N milliseconds".
- Once-per-target instead of once-global — when each subject closes once
  but different subjects queue in parallel: one registered flag + op type
  per target, named by the target (`executed_<payloadTarget>` items, one
  `defineOperationType` each) — Recipe 2's per-user pattern keyed by
  target instead of signer.

## Verified against the code

<!-- PROVENANCE
machine shapes: ONE_SHOT_FLAG — add via Node.addOneShotFlag wasm bindings/wasm/index.d.ts:494 · node bindings/node/index.d.ts:319.
C flag struct: one_shot_flag_t (value/set_by/set_at) src/CRDT/one_shot.h:38-41 · create :43 · set :45 · value :46 · merge :47 (true dominates, earliest wins, ties lexicographic by setter id) · destroy :44.
registered-spec executor path: src/StateMachine/state_machine.c:1695-1714 (registered GLOBAL spec refuses the rerun, any signer) · define-op handler state_machine_op_define_operation :2925-2940 · registry store state_register_op_type_def src/CRABS/data_model.c:529-553 — in-place replace, capacity 32 (CRABS_MAX_OP_TYPE_DEFS src/CRABS/data_model.h:381); a dedup 'none' definition removes the guard.
flagValue binding shapes: crabs-wasm returns 0/1 numbers (Emscripten numeric ABI, bindings/wasm/bindings-core.js:1302) · crabs-node returns real booleans (bindings/node/src/crabs_node.cc:2202-2209) — compare truthiness, never === true. An unknown item name reads false: src/Util/wasm_helpers.c:1432-1437.
error surfaced: CRABS_ERR_ALREADY_EXECUTED = 0x7002 'already_executed' — src/CRABS/crabs.h:107 (name map bindings/node/src/crabs_node.cc:141).
idempotent skip: the tx manager refuses a duplicate submission with ALREADY_EXECUTED and the caller treats it as idempotent success — src/StateMachine/state_machine.c:1617-1625.
driver-level flagSet calls are not ops (bypass signatures/policies/guards) — contract of the direct-op surface.

target: crabs-wasm (snippet wasm/03-execute-once.js)
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:774
  KeyPair.generate          bindings/wasm/index.d.ts:44
  publicKeyHex              bindings/wasm/index.d.ts:38
  KeyPair.destroy           bindings/wasm/index.d.ts:40
  registerUser              bindings/wasm/index.d.ts:480
  grantRole                 bindings/wasm/index.d.ts:481
  addOneShotFlag            bindings/wasm/index.d.ts:494
  flagValue                 bindings/wasm/index.d.ts:593
  setPolicy                 bindings/wasm/index.d.ts:638
  defineOperationType       bindings/wasm/index.d.ts:649
  DefineOperationTypeOptions bindings/wasm/index.d.ts:324-345
  Operation.create          bindings/wasm/index.d.ts:122
  Operation.destroy         bindings/wasm/index.d.ts:118
  Operation.addResource     bindings/wasm/index.d.ts:68
  Node.sign                 bindings/wasm/index.d.ts:657
  Node.execute              bindings/wasm/index.d.ts:656
  Node.destroy              bindings/wasm/index.d.ts:770
maturity: all STABLE
test_ref: bindings/wasm/test/dedup-surface.js (global spec: first run sets the flag, rerun refused incl. a different signer)

target: crabs-node (snippet node/03-execute-once.js)
verified: executed
symbols:
  NodeStatic.new      bindings/node/index.d.ts:642 (new Node)
  KeyPair.generate    bindings/node/index.d.ts:71
  publicKeyHex        bindings/node/index.d.ts:28
  registerUser        bindings/node/index.d.ts:304
  grantRole           bindings/node/index.d.ts:305
  addOneShotFlag      bindings/node/index.d.ts:319
  flagValue           bindings/node/index.d.ts:404
  setPolicy           bindings/node/index.d.ts:450
  defineOperationType bindings/node/index.d.ts:462
  DefineOperationTypeOptions bindings/node/index.d.ts:247-266
  Operation           bindings/node/index.d.ts:76-90 (signerId :78, addResource :83)
  Node.sign           bindings/node/index.d.ts:463
  Node.execute        bindings/node/index.d.ts:464
maturity: all STABLE
test_ref: test/test_one_shot.cpp:186-201 (SetIsIdempotent: second set keeps the first setter)

target: native-c (snippet c/03-execute-once.c)
verified: executed
symbols:
  one_shot_flag_create        src/CRDT/one_shot.h:43
  one_shot_flag_set           src/CRDT/one_shot.h:45
  one_shot_flag_value         src/CRDT/one_shot.h:46
  one_shot_flag_merge         src/CRDT/one_shot.h:47
  one_shot_flag_destroy       src/CRDT/one_shot.h:44
  (set_by / set_at fields)    src/CRDT/one_shot.h:38-41
  state_create                src/CRABS/data_model.h:723
  state_destroy               src/CRABS/data_model.h:724
  data_item_create            src/CRABS/data_model.h:675
  state_add_item              src/CRABS/data_model.h:758
  data_value_repr_t           src/CRABS/data_model.h:77-82
  state_register_op_type_def  src/CRABS/data_model.h:796
  state_find_op_type_def      src/CRABS/data_model.h:795
  dedup_spec_t                src/CRABS/data_model.h:365-376
  CRABS_MAX_DEDUP_PATH        src/CRABS/data_model.h:332
  dedup_check_guard_spec      src/Dedup/dedup.h:31-33
  dedup_apply_mutation_spec   src/Dedup/dedup.h:43-45
  operation_create            src/StateMachine/state_machine.h:346
  operation_destroy           src/StateMachine/state_machine.h:347
  CRABS_SUCCESS               src/CRABS/crabs.h:65
  CRABS_ERR_ALREADY_EXECUTED  src/CRABS/crabs.h:107
  crdt_value_destroy          src/CRDT/crdt_merge.h:141
maturity: all STABLE
test_ref: test/test_dedup.cpp:726-762 (GlobalExecutionOnceLifecycle) + test/test_one_shot.cpp:258-292 (merge keeps earlier setter; ties break lexicographic :276) + test/test_one_shot.cpp:43-55, :75-97 (the set behaviors recipe 2 leans on)
-->