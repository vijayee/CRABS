---
number: 3
slug: execute-once
title: Execute once, ever
section: Basics
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
---
## Intent

You want an operation that runs at most one time, ever — a closeout, a
proposal execution, a one-way door. Not once per member (that is Recipe 2's
shape): once *globally*, where the second caller can be a different person,
on a different device, days later, and the machine itself refuses to run
the effect a second time.

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

The C catalog pairs that primitive with a `DEDUP_GLOBAL` spec whose guard
runs inside the executor (`src/Dedup/dedup.h:31-33`, resolved at
`src/StateMachine/state_machine.c:1693-1712`) — and both JS bindings
install it with `defineOperationType`, exactly like the C snippet installs
it with `state_register_op_type_def`. That is what the recipes below do;
the one-way door is the machine's, not the calling code's.

## The shape

- The persisted outcome is a named `ONE_SHOT_FLAG` item:
  `addOneShotFlag('closeout_done')`. It reads false out of the mint, flips
  true once, and has no path back — `flagSet` has no false transition.
- Raising it is `flagSet(name, setBy, setAtMs)`; reading it is
  `flagValue(name)`.
- The guard is a REGISTERED spec: `defineOperationType('closeout', { dedup:
  'global', flagPath: 'closeout_done' })` installs a `DEDUP_GLOBAL` spec —
  guard + flag-set mutation are entirely C-native, so the op itself carries
  nothing the machine has to trust. The op names the flag item as its
  resource and the executor resolves it: on rerun the guard refuses BEFORE
  any handler would run, and stays refused for every signer afterwards
  (`src/StateMachine/state_machine.c:1693-1712`).
- Installing the spec is itself a signed op under the machine's admin
  authority: set `setPolicy('__define_operation_type__', 'role:admin')`
  first (the bootstrap admin holds `role:admin`; the `__create_trigger__`
  precedent).
- Merge semantics of the flag: true dominates, the earliest timestamp wins,
  and ties break lexicographically by setter id (`test/test_one_shot.cpp:258-292`).

## What it guarantees / what it doesn't

Guaranteed on both JS bindings: each signed `closeout` op is executed at
most once on that machine — the second attempt is rejected inside the
machine (any signer) before any effect re-runs; the outcome flag, once
true, cannot become false again on any replica, and the registered spec,
once executed, cannot be un-installed by a signer's op (only a later admin
`defineOperationType` with `dedup: 'none'` replaces it in place).

Not guaranteed: exclusivity *across* replicas that have not yet met. Two
replicas can each run the effect inside the blind window (both flags read
false locally) and both proceed; the merged flag stays true either way, so
the record converges — but the effect ran twice. Also not observable from
the JS bindings: *which* attempt won (the setter/timestamp reads are
C-only, `src/CRDT/one_shot.h:37-41`).

## Variations

- Idempotent-skip instead of reject: replayed UUID semantics —
  `CRABS_ERR_ALREADY_EXECUTED` from the transaction manager is treated as
  an idempotent skip (`src/StateMachine/state_machine.c:1929-1931`), so the
  same op bytes delivered twice never re-run the effect.
- Once-per-window, not once-ever: a trigger with `cooldownMs` (Recipe 6's
  territory) gives you "no more than once per N milliseconds" rather than
  a one-way door.
- Once-per-target instead of once-global: one registered flag + op type per
  target (`executed_<payloadTarget>` items, one `defineOperationType`
  each) — Recipe 2's per-user pattern, keyed by target instead of signer.

## Recipe

### crabs-wasm (browser / Node / edge)

```snippet:wasm/03-execute-once.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:549
  KeyPair.generate          bindings/wasm/index.d.ts:21
  publicKeyHex              bindings/wasm/index.d.ts:15
  KeyPair.destroy           bindings/wasm/index.d.ts:17
  registerUser              bindings/wasm/index.d.ts:353
  grantRole                 bindings/wasm/index.d.ts:354
  addOneShotFlag            bindings/wasm/index.d.ts:367
  flagValue                 bindings/wasm/index.d.ts:433
  setPolicy                 bindings/wasm/index.d.ts:435
  defineOperationType       bindings/wasm/index.d.ts:446
  DefineOperationTypeOptions bindings/wasm/index.d.ts:197-217
  Operation.create          bindings/wasm/index.d.ts:52
  Operation.signerId        bindings/wasm/index.d.ts:28
  Operation.addResource     bindings/wasm/index.d.ts:33
  Node.sign                 bindings/wasm/index.d.ts:454
  Node.execute              bindings/wasm/index.d.ts:453
  Node.destroy              bindings/wasm/index.d.ts:545
  (register semantics)      src/StateMachine/state_machine.c:2909-2925 (define op handler + registry store)
  (execution guard)         src/StateMachine/state_machine.c:1693-1712 (registered GLOBAL spec refuses the rerun, any signer)
  (error surfaced)          src/CRABS/crabs.h:107 (CRABS_ERR_ALREADY_EXECUTED = 0x7002, name 'already_executed')
maturity: all STABLE
test_ref: bindings/wasm/test/dedup-surface.js (global spec: first run sets the flag, rerun refused incl. a different signer)
-->

### crabs-node (native Node.js)

```snippet:node/03-execute-once.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  NodeStatic.new      bindings/node/index.d.ts:412
  KeyPair.generate    bindings/node/index.d.ts:13
  publicKeyHex        bindings/node/index.d.ts:8
  registerUser        bindings/node/index.d.ts:212
  grantRole           bindings/node/index.d.ts:213
  addOneShotFlag      bindings/node/index.d.ts:227
  flagValue           bindings/node/index.d.ts:276
  setPolicy           bindings/node/index.d.ts:279
  defineOperationType bindings/node/index.d.ts:291
  DefineOperationTypeOptions bindings/node/index.d.ts:155-175
  Operation           bindings/node/index.d.ts:19-44 (signerId, addResource)
  Node.sign           bindings/node/index.d.ts:292
  Node.execute        bindings/node/index.d.ts:293
  (unmapped reads)    src/CRDT/one_shot.h:37-41 (set_by/set_at live in the C struct, no JS row)
maturity: all STABLE
test_ref: test/test_one_shot.cpp:186-201 (SetIsIdempotent: second set keeps the first setter)
-->

### C (native)

```snippet:c/03-execute-once.c
```

<!-- PROVENANCE
target: native-c
verified: executed
symbols:
  one_shot_flag_create        src/CRDT/one_shot.h:43
  one_shot_flag_set           src/CRDT/one_shot.h:45
  one_shot_flag_value         src/CRDT/one_shot.h:46
  one_shot_flag_merge         src/CRDT/one_shot.h:47
  one_shot_flag_destroy       src/CRDT/one_shot.h:44
  (set_by / set_at fields)    src/CRDT/one_shot.h:37-41
  state_create                src/CRABS/data_model.h:721
  state_destroy               src/CRABS/data_model.h:722
  data_item_create            src/CRABS/data_model.h:673
  state_add_item              src/CRABS/data_model.h:756
  data_value_repr_t           src/CRABS/data_model.h:77-81
  state_register_op_type_def  src/CRABS/data_model.h:794
  state_find_op_type_def      src/CRABS/data_model.h:793
  dedup_spec_t                src/CRABS/data_model.h:363-374
  CRABS_MAX_DEDUP_PATH        src/CRABS/data_model.h:330
  dedup_check_guard_spec      src/Dedup/dedup.h:31-33
  dedup_apply_mutation_spec   src/Dedup/dedup.h:43-45
  operation_create            src/StateMachine/state_machine.h:243
  operation_destroy           src/StateMachine/state_machine.h:244
  CRABS_SUCCESS               src/CRABS/crabs.h:65
  CRABS_ERR_ALREADY_EXECUTED  src/CRABS/crabs.h:107
  crdt_value_destroy          src/CRDT/crdt_merge.h:141
maturity: all STABLE
test_ref: test/test_dedup.cpp:726-762 (GlobalExecutionOnceLifecycle) + test/test_one_shot.cpp:258-292 (merge keeps earlier setter)
-->

### Notes

- `flagValue` is typed differently per binding: crabs-wasm returns `0`/`1`
  numbers (the raw C `bool` passes through Emscripten's numeric ABI in the
  wasm glue, `bindings/wasm/bindings-core.js` flagValue), crabs-node
  returns real booleans (`bindings/node/src/crabs_node.cc:1734-1742`).
  Compare truthiness, never `=== true`.
- The flag reads as `false` for an unknown item name (`src/Util/wasm_helpers.c:936-941`
  returns false when the item is missing), so a typo in a flag name looks
  like "not executed yet" rather than an error. Assert the name the first
  time you mint it.
- Direct `flagSet` calls are not ops — they bypass signatures, policies,
  and any registered guard (driver-level setup/testing only). The enforced
  path is the signed `closeout` op resolving the registered spec; the
  snippets use `flagValue` reads to assert what the machine did.
- The registry entry is REPLACED on re-definition
  (`state_register_op_type_def`, `src/CRABS/data_model.c:529-553`): a
  later admin `defineOperationType('closeout', { dedup: 'none' })` removes
  the guard. Capacity is 32 entries (`src/CRABS/data_model.h:379`).
- The "idempotent skip" nuance: a *replayed UUID* (same op bytes delivered
  twice) does not re-enter the guard as a fresh op — the duplicate is
  refused with `CRABS_ERR_ALREADY_EXECUTED` by the replay backstops and
  the execute wrapper treats it as an idempotent skip, not an error
  (`src/StateMachine/state_machine.c:1929-1931`). The registered spec
  covers the *different* case: a fresh op, signed again, intended to run
  the effect a second time.