---
number: 2
slug: one-vote-per-member
title: One vote per member
section: Basics
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
---
## Intent

You want each member of a machine to cast exactly one vote — and the "one"
to hold across devices, retries, delivery replays, and concurrent replicas,
with no coordination step at the end. The machine should remember *who*
voted, not just how many votes happened, because a vote count alone cannot
distinguish a replayed tally event from a real one.

## The naive version, and where it breaks

The naive version is a single counter. `votes += 1` on submit: now a client's
retry double-counts, a replayed delivery double-counts, and two devices of
one person double-count. Adding a set of "who voted" next to the counter is
the right instinct, but only if the set is itself a converged CRDT: a plain
per-replica list can lose or duplicate memberships during merge, and a
deletable set breaks the entire property the moment some replica removes an
entry under duplicate-pressure.

The strict version — a `DedupSpec` whose per-user guard is resolved
*inside* the executor, so the signer cannot influence it (`src/Dedup/dedup.h:23-30`,
audit F-2) — is registered on the machine with `defineOperationType` on both
JS bindings, exactly like the C snippet registers it with
`state_register_op_type_def`. That is what the recipes below do; the once
per member rule is the machine's, not the calling code's.

## The shape

- The once-record is a named item of type `ONE_SHOT_SET`:
  `addOneShotSet('proposal-42_voters')`. Its add is idempotent and it cannot
  un-vote — there is no remove: `setRemove` is a no-op for one-shot sets
  (`bindings/node/src/crabs_node.cc:1712-1722` — only OR-sets tombstone).
- The tally is a G-counter per option: `incrementCounter('proposal-42_voted_yea',
  1, voter)`. Attribution is per voter, so (as in Recipe 1) a replayed
  increment from the same voter merges into one entry.
- The guard is a REGISTERED spec: `defineOperationType('vote', { dedup:
  'per-user', trackerPath: 'proposal-42_voters' })` composes and executes a
  node-key-signed `__define_operation_type__` op whose resources[0] carries
  the op type name and whose dedup struct carries the spec
  (`state_machine_op_define_operation`, `src/StateMachine/state_machine.c:2909-2925`);
  the machine registry stores it (`state_register_op_type_def`,
  `src/CRABS/data_model.c:529-553`) and the executor resolves it for every
  later op of that type (`src/StateMachine/state_machine.c:1693-1712`) —
  a registered spec wins over anything the op carries on the wire, so the
  F-2 bypass shape (a `vote` op claiming `dedup: none`) is refused rather
  than honored.
- The tracker must exist before the spec is exercised: the executor
  validates the spec's mutation target BEFORE the handler runs
  (`dedup_validate_mutation_spec`, R8-S-3) and the guard reads it
  (`tracker_not_found` otherwise). The spec's own mutation — not any caller
  code — records membership after a successful run
  (`src/StateMachine/state_machine.c:1854-1862`), keeping the
  check-then-record atomic from the op's point of view.
- Installing the spec is itself a signed op under the machine's admin
  authority: set `setPolicy('__define_operation_type__', 'role:admin')`
  first (the bootstrap admin holds `role:admin`; the `__create_trigger__`
  precedent).

## What it guarantees / what it doesn't

Guaranteed on both JS bindings: a signed op that claims a member's vote is
executed at most once per that member *as far as the machine's merged set is
concerned* — a second op from the same signer is rejected inside the
machine, before any handler or effect can re-run, and the reject path
leaves the tally untouched. The registered spec cannot be bypassed by
calling code: the op's carried dedup field defaults to NONE and the machine
resolves the registered spec anyway; the registered spec also survives
deserialization (`src/Serialization/serialization.c:2016,2569-2598`).

Not guaranteed: a global tally that is exact under concurrent voting from
several replicas. Two replicas can both see "alice has not voted" and both
accept her first vote (each against its local view); the *set* merges back
to one alice, but two per-option counter increments from two replica ids
merge to 2. The registered `DEDUP_PER_USER` spec has the same
single-tracker shape and inherits the same edge — the guard is exact on the
merged state, not across the window in which two replicas have not yet seen
each other.

## Variations

- Per-option membership: mint one one-shot set per option and check them all
  in the handler — then the merged set sizes *are* the tallies, and merge
  dedup applies to the count, not just the record. (The trade: a member's
  concurrent conflicting votes can land in two option sets at once — the
  record stays honest, the "one vote" does not.)
- Anonymous ballots: the element you add does not have to be `op.signerId`;
  any per-member token inside the payload works, as long as the same token
  is derived on every replica.
- The flag-shaped cousin of this recipe (a boolean that turns true once) is
  Recipe 3.

## Recipe

### crabs-wasm (browser / Node / edge)

```snippet:wasm/02-one-vote.js
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
  addOneShotSet             bindings/wasm/index.d.ts:366
  addCounter                bindings/wasm/index.d.ts:363
  setPolicy                 bindings/wasm/index.d.ts:435
  defineOperationType       bindings/wasm/index.d.ts:446
  DefineOperationTypeOptions bindings/wasm/index.d.ts:197-217
  registerHandlerJs         bindings/wasm/index.d.ts:480
  HandlerState.incrementCounter bindings/wasm/index.d.ts:103
  Operation.create          bindings/wasm/index.d.ts:52
  Operation.signerId        bindings/wasm/index.d.ts:28
  Operation.payload         bindings/wasm/index.d.ts:30
  Node.sign                 bindings/wasm/index.d.ts:454
  Node.execute              bindings/wasm/index.d.ts:453
  setContains               bindings/wasm/index.d.ts:407
  getCounter                bindings/wasm/index.d.ts:394
  Node.destroy              bindings/wasm/index.d.ts:545
  (register semantics)      src/CRABS/data_model.c:529-553 (state_register_op_type_def)
  (execution guard)         src/StateMachine/state_machine.c:1693-1712 (registered spec wins over the wire)
  (error surfaced)          src/CRABS/crabs.h:106 (CRABS_ERR_ALREADY_PERFORMED = 0x7001, name 'already_performed')
  (string payload contract) src/Util/wasm_helpers.c:1195-1201 (payload must be NUL-terminated)
maturity: all STABLE
test_ref: bindings/wasm/test/dedup-surface.js (registered per-user/global specs, registry overwrite, malformed-input refusals)
-->

### crabs-node (native Node.js)

```snippet:node/02-one-vote.js
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
  addOneShotSet       bindings/node/index.d.ts:226
  setPolicy           bindings/node/index.d.ts:279
  defineOperationType bindings/node/index.d.ts:291
  DefineOperationTypeOptions bindings/node/index.d.ts:155-175
  Operation           bindings/node/index.d.ts:19-44 (signerId, addResource)
  Node.sign           bindings/node/index.d.ts:292
  Node.execute        bindings/node/index.d.ts:293
  setContains         bindings/node/index.d.ts:265
maturity: all STABLE
test_ref: bindings/node/test/test.js:659 (defineOperationType block: per-user guard, F-2 bypass shape refused) + test/test_dedup.cpp:223-257 (registered spec beats a NONE bypass attempt)
-->

### C (native)

```snippet:c/02-one-vote.c
```

<!-- PROVENANCE
target: native-c
verified: executed
symbols:
  state_create               src/CRABS/data_model.h:721
  state_destroy              src/CRABS/data_model.h:722
  data_item_create           src/CRABS/data_model.h:673
  state_add_item             src/CRABS/data_model.h:756
  one_shot_set_create        src/CRDT/one_shot.h:24
  one_shot_set_count         src/CRDT/one_shot.h:28
  one_shot_set_contains      src/CRDT/one_shot.h:27
  one_shot_set_destroy       src/CRDT/one_shot.h:25
  data_value_repr_t          src/CRABS/data_model.h:77-81
  state_register_op_type_def src/CRABS/data_model.h:794
  state_find_op_type_def     src/CRABS/data_model.h:793
  dedup_spec_t               src/CRABS/data_model.h:363-374
  CRABS_MAX_DEDUP_PATH       src/CRABS/data_model.h:330
  dedup_check_guard_spec     src/Dedup/dedup.h:31-33
  dedup_apply_mutation_spec  src/Dedup/dedup.h:43-45
  operation_create           src/StateMachine/state_machine.h:243
  operation_destroy          src/StateMachine/state_machine.h:244
  CRABS_SUCCESS              src/CRABS/crabs.h:65
  CRABS_ERR_ALREADY_PERFORMED src/CRABS/crabs.h:106
  crdt_value_destroy         src/CRDT/crdt_merge.h:141
maturity: all STABLE
test_ref: test/test_dedup.cpp:680 (PerUserVoteOnceLifecycle) + :226-257 (registered spec beats a NONE bypass attempt)
-->

### Notes

- The guard and the record are the SPEC's, not the handler's: the executor
  runs the registered guard before the handler (`src/StateMachine/state_machine.c:1693-1712`)
  and the spec's mutation after a successful run (`:1854-1862`), so the
  retry demo's tally stays at 1 — a refused op applies nothing afterward
  (the handler result is checked before any post-handler state work,
  `:1823`).
- The registered spec is durable machine state: the dedup registry
  serializes with the machine (`src/Serialization/serialization.c:2016,2569-2598`),
  so a restored replica keeps enforcing without a re-define.
- The registry entry is REPLACED on re-definition
  (`state_register_op_type_def`, `src/CRABS/data_model.c:529-553` —
  first-match update, capacity 32 at `src/CRABS/data_model.h:379`). A
  `dedup: 'none'` definition is therefore the documented way to remove a
  guard; it also seals the type against op-carried specs, which the
  executor ignores whenever ANY spec (even a NONE one) is registered.
- String payloads must be NUL-terminated for a handler to see them
  (`crabs_wasm_handler_op_get_payload_str`, `src/Util/wasm_helpers.c:1195-1201`
  — "demo payloads are null-terminated JSON strings"). Hence the `'\0'`
  appended to the vote option in the wasm snippet.
- Direct mutations are not ops. `node.setAdd` / `node.incrementCounter` (and
  the wasm equivalents) are driver-level calls for setup and testing — they
  bypass signatures, policies, and any registered guard. The snippets only
  use them on the tracker to READ (assert) what the spec recorded.
- The once-record cannot be edited retroactively: `setRemove` tombstones
  OR-set elements only (`bindings/node/src/crabs_node.cc:1712-1722`; the
  wasm glue mirrors it, `src/Util/wasm_helpers.c:928-934`). That is a
  feature for a voters list and a hazard for anything you might ever want
  to retract.
- The idempotent-add and union-merge behavior the demos rely on are pinned
  in C tests: `test/test_one_shot.cpp:43-55` (add is idempotent) and
  `:75-97` (merge is a union); the strict guard lifecycle is
  `test/test_dedup.cpp:680-724`, and the full executor path (define +
  guard + bypass refusal) is `test/test_state_machine.cpp`
  (`DefineOperationTypeExecutesThroughMachine`).