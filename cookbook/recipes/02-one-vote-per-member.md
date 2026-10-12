---
number: 2
slug: one-vote-per-member
title: One vote per member
section: Basics
status: PARTIAL
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

The C catalog has exactly the missing pieces — a `DedupSpec` whose per-user
guard is resolved *inside* the executor, so the signer cannot influence it
(`src/Dedup/dedup.h:23-30`, audit F-2). That is the strict version, and it is
the one whose absence on the JS surfaces drives this recipe's status (see
`### The strict version (dedup)`).

## The shape

- The once-record is a named item of type `ONE_SHOT_SET`:
  `addOneShotSet('proposal-42_voters')`. Its add is idempotent and it cannot
  un-vote — there is no remove: `setRemove` is a no-op for one-shot sets
  (`bindings/node/src/crabs_node.cc:1663-1676` — only OR-sets tombstone).
- The tally is a G-counter per option: `incrementCounter('proposal-42_voted_yea',
  1, voter)`. Attribution is per voter, so (as in Recipe 1) a replayed
  increment from the same voter merges into one entry.
- The guard, on crabs-wasm, runs inside the machine: a custom handler for the
  `vote` op type checks `state.setContains('proposal-42_voters', op.signerId)`
  and returns `CRABS_ERR_ALREADY_PERFORMED` (0x7001) when the member is
  already recorded — the executor propagates that as a thrown
  `already_performed` and, critically, applies nothing afterward (the handler
  result is checked before any post-handler state work, `src/StateMachine/state_machine.c:1431`).
- Membership is checked and written in the same handler body, so within one
  machine the check-then-vote is atomic from the op's point of view: the op
  either lands with membership and tally, or is rejected with both untouched.

## What it guarantees / what it doesn't

Guaranteed on crabs-wasm: a signed op that claims a member's vote is
executed at most once per that member *as far as the machine's merged set is
concerned* — a second op from the same signer is rejected inside the
machine, before `execute` returns, and the reject path leaves the tally
untouched. On crabs-node, no custom-handler surface exists, so the guard is
driver discipline; what the machine itself guarantees is that the
once-record is idempotent and additive (a replay absorbed, nothing
deletable).

Not guaranteed: a global tally that is exact under concurrent voting from
several replicas. Two replicas can both see "alice has not voted" and both
accept her first vote (each against its local view); the *set* merges back
to one alice, but two per-option counter increments from two replica ids
merge to 2. The C `DEDUP_PER_USER` spec has the same single-tracker shape and
inherits the same edge — the guard is exact on the merged state, not across
the window in which two replicas have not yet seen each other. What the C
spec adds, and JS cannot, is enforcement on the *signed-op path*: see the
strict-version gap below.

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
  Node.create               bindings/wasm/index.d.ts:372
  KeyPair.generate          bindings/wasm/index.d.ts:21
  publicKeyHex              bindings/wasm/index.d.ts:15
  KeyPair.destroy           bindings/wasm/index.d.ts:17
  registerUser              bindings/wasm/index.d.ts:213
  grantRole                 bindings/wasm/index.d.ts:214
  addOneShotSet             bindings/wasm/index.d.ts:226
  addCounter                bindings/wasm/index.d.ts:223
  setPolicy                 bindings/wasm/index.d.ts:295
  registerHandlerJs         bindings/wasm/index.d.ts:303
  HandlerState.setContains  bindings/wasm/index.d.ts:123
  HandlerState.setAdd       bindings/wasm/index.d.ts:115
  HandlerState.incrementCounter bindings/wasm/index.d.ts:103
  Operation.create          bindings/wasm/index.d.ts:52
  Operation.signerId        bindings/wasm/index.d.ts:28
  Operation.payload         bindings/wasm/index.d.ts:30
  Node.sign                 bindings/wasm/index.d.ts:297
  Node.execute              bindings/wasm/index.d.ts:296
  getCounter                bindings/wasm/index.d.ts:254
  Node.destroy              bindings/wasm/index.d.ts:368
  (handler return code)     src/CRABS/crabs.h:106 (CRABS_ERR_ALREADY_PERFORMED = 0x7001)
  (string payload contract) src/Util/wasm_helpers.c:1071-1079 (payload must be NUL-terminated)
maturity: all STABLE
test_ref: bindings/wasm/test/smoke.js:59 (registerHandlerJs + policy-gated custom op)
-->

### crabs-node (native Node.js)

```snippet:node/02-one-vote.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  NodeStatic.new     bindings/node/index.d.ts:312
  KeyPair.generate   bindings/node/index.d.ts:14
  publicKeyHex       bindings/node/index.d.ts:8
  registerUser       bindings/node/index.d.ts:182
  grantRole          bindings/node/index.d.ts:183
  addOneShotSet      bindings/node/index.d.ts:196
  addCounter         bindings/node/index.d.ts:193
  setContains        bindings/node/index.d.ts:235
  setAdd             bindings/node/index.d.ts:243
  incrementCounter   bindings/node/index.d.ts:238
  getCounter         bindings/node/index.d.ts:224
maturity: all STABLE
test_ref: bindings/node/test/test.js:53 (addOneShotSet) + test/test_one_shot.cpp:43-55 (idempotent add)
-->

### C (native)

```snippet:c/02-one-vote.c
```

<!-- PROVENANCE
target: native-c
verified: executed
symbols:
  state_create               src/CRABS/data_model.h:684
  state_destroy              src/CRABS/data_model.h:685
  data_item_create           src/CRABS/data_model.h:636
  state_add_item             src/CRABS/data_model.h:719
  one_shot_set_create        src/CRDT/one_shot.h:24
  one_shot_set_count         src/CRDT/one_shot.h:28
  one_shot_set_contains      src/CRDT/one_shot.h:27
  one_shot_set_destroy       src/CRDT/one_shot.h:25
  data_value_repr_t          src/CRABS/data_model.h:79-81
  state_register_op_type_def src/CRABS/data_model.h:757
  state_find_op_type_def     src/CRABS/data_model.h:756
  dedup_spec_t               src/CRABS/data_model.h:364-374
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

### The strict version (dedup)

> [!WARNING] GAP
>
> **Prose describes:** an operation type whose "one per member" rule is
> installed on the machine itself — a registered `DedupSpec` — so the
> executor enforces it on every signed op regardless of what the signer
> carries on the wire, and no replica-side calling code can forget it.
>
> **Codebase status:** exists only in C. The registry is
> `state_register_op_type_def` (`src/CRABS/data_model.h:757`), the executor
> consults `state_find_op_type_def` (`src/CRABS/data_model.h:756`,
> `src/StateMachine/state_machine.c:1297-1316`) and even rejects an op whose
> *carried* dedup spec is non-NONE without a registered definition
> (`src/StateMachine/state_machine.c:1298-1300`). The guard/apply pair lives at
> `src/Dedup/dedup.h:21-52`. The C snippet above exercises the real functions,
> library-style, on a bare `state_t` — mirroring `test/test_dedup.cpp`.
>
> **Divergence:** neither JS binding can install a spec. `Operation`
> (`bindings/wasm/index.d.ts:26-49`, `bindings/node/index.d.ts:19-44`) exposes
> no `dedup` field, no payload builder for the `__define_operation_type__`
> builtin that installs one (`src/CRABS/crabs.h:161` — the op
> itself exists, but the spec rides in C struct fields the bindings do not
> map). So the wasm recipe above emulates the guard *inside a custom
> handler*, and crabs-node cannot guard at all — it gets driver-level
> discipline only. The handler emulation is also weaker than the registered
> spec: a machine-local handler guards only ops routed through *that*
> machine's registry, and the C registry applies to every executor call.
>
> **Tracking:** an internal implementation plan (not published on this site)
> (this task's section). No dedicated binding-gap tracker found for DedupSpec
> exposure; the api-map records the gap at "R2 | DedupSpec / per-user guard".
>
> **Agent action:** code block omitted. Do not fake a dedup field onto the
> JS `Operation`; if you need the strict version from JS today, use the wasm
> handler pattern above and accept the machine-local scope, or run the C core.

### Notes

- Why `0x7001`? Custom handlers return a `crabs_error_e`; the wasm binding
  throws a JS error whose message is the canonical name — `already_performed`
  (`bindings/wasm/bindings-core.js` ERROR_MESSAGES, 0x7001). Returning a
  nonzero code also short-circuits the executor *before* any post-handler
  mutation or logging (`src/StateMachine/state_machine.c:1431` and
  `:1462-1469` — the dedup mutation applies only after a successful handler),
  which is exactly why the retry demo leaves the tally at 1.
- String payloads must be NUL-terminated for a handler to see them
  (`crabs_wasm_handler_op_get_payload_str`, `src/Util/wasm_helpers.c:1071-1077`
  — "demo payloads are null-terminated JSON strings"). Hence the `'\0'`
  appended to the vote option in the wasm snippet.
- Direct mutations are not ops. `node.setAdd` / `node.incrementCounter` (and
  the wasm equivalents) are driver-level calls for setup and testing — they
  bypass signatures, policies, and any handler. The node snippet's cast
  function exists to make that visible: *the caller* is the only thing
  checking `setContains` before mutating.
- The once-record cannot be edited retroactively: `setRemove` tombstones
  OR-set elements only (`bindings/node/src/crabs_node.cc:1663-1676`; the
  wasm glue mirrors it, `src/Util/wasm_helpers.c:833-839`). That is a
  feature for a voters list and a hazard for anything you might ever want
  to retract.
- The idempotent-add and union-merge behavior the JS demos rely on are
  pinned in C tests: `test/test_one_shot.cpp:43-55` (add is idempotent) and
  `:75-97` (merge is a union); the strict guard lifecycle is
  `test/test_dedup.cpp:680-724`.