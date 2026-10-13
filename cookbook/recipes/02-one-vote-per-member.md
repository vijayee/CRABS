---
number: 2
slug: one-vote-per-member
title: One vote per member
section: Basics
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
teaches: one-person-one-vote as a monotone set plus dedup guarding
---
## The problem

A proposal goes up for a vote on a small committee's machine, and each member
may vote once. Member Alice opens the app on her laptop and votes yes. The
vote hangs for a moment, so she refreshes, the app submits again, and her
phone — still on yesterday's cached view — submits it an hour later. Alice
told the app to vote once, but the *state* never promised anything. Three
submissions, and the tally has to decide whether that is one vote or three,
with no coordination step and no list of who already voted that anyone
trusts more than Alice's devices.

If the record is a number, the tally loses: a retry and a real second vote
look identical, so "one per member" is an assertion the calling code keeps
hopelessly. If the record is a list of names, it can grow and shrink in
replicas that disagree, and the once-per-member property evaporates with it.

## The naive version, and where it breaks

The naive version is a single counter. `votes += 1` on submit: now a client's
retry double-counts, a replayed delivery double-counts, and two devices of
one person double-count. Adding a set of "who voted" next to the counter is
the right instinct, but only if the set is itself a converged CRDT: a plain
per-replica list can lose or duplicate memberships during merge, and a
deletable set breaks the entire property the moment some replica removes an
entry under duplicate-pressure.

The other familiar fix — the application checks "has alice voted?" before
submitting — has a deeper flaw: the check happens on the machine that could
be wrong, at a moment the record has not yet moved, and whoever runs it can
skip it. Check-then-act across a network is not an atomic step; the record
itself has to refuse the second act.

## The idea

Two ideas stack. First, membership as an *append-only fact*: once Alice is in
the set, nothing removes her, and adding her again adds nothing — the set
only ever grows, so every replica that merges it converges to the same
members no matter how the delivery replays arrive.

Second, the *guard must run inside the machine that owns the record*, in the
same step as the record's change — never as a courtesy check in caller code.
A registry entry binds an operation type to a rule ("per user, recorded in
that set"); the executor resolves the rule *before* the operation's effects
run and records the membership *after* the operation succeeds, so the check
and the take are one machine step rather than two moments. No signing code
can forget the rule, and no operation on the wire can override it by
claiming it carries no rule.

## How CRABS encodes it

- The once-record is a named item of type `ONE_SHOT_SET`:
  `addOneShotSet('proposal-42_voters')`. Its add is idempotent and it cannot
  un-vote — `setRemove` only tombstones OR-set elements, so one-shot sets
  have no remove.
- The tally is a G-counter per option: `incrementCounter('proposal-42_voted_yea',
  1, voter)`. Attribution is per voter, so (as in Recipe 1) a replayed
  increment from the same voter merges into one entry.
- The guard is a REGISTERED spec: `defineOperationType('vote', { dedup:
  'per-user', trackerPath: 'proposal-42_voters' })` composes and executes a
  node-key-signed `__define_operation_type__` op that stores the spec in the
  machine registry. From then on the executor resolves the registered spec
  for every later op of that type — a registered spec wins over anything the
  op carries on the wire, so a `vote` op claiming `dedup: none` is refused
  rather than honored.
- The machine does the check and the record: the registered guard runs
  before the handler (and the spec's target item is validated there too),
  and the spec's own mutation records membership after a successful run —
  check-then-take is atomic from the op's point of view. A second vote is
  rejected before any handler effect can land, and the tally stays where it
  was.
- Installing the spec is itself a signed op under the machine's admin
  authority: set `setPolicy('__define_operation_type__', 'role:admin')`
  first (the bootstrap admin holds `role:admin`; the `__create_trigger__`
  precedent).

## Try it

### crabs-wasm (browser / Node / edge)

```snippet:wasm/02-one-vote.js
```

### crabs-node (native Node.js)

```snippet:node/02-one-vote.js
```

### C (native)

```snippet:c/02-one-vote.c
```

## What it guarantees / what it doesn't

- At most once per member, on the machine's merged state: a second op from
  the same signer is rejected inside the machine before any effect re-runs,
  and the reject path leaves the tally untouched.
- No bypass from calling code: the carried dedup field defaults to none and
  the machine resolves the registered spec anyway, on both JS bindings.
- Durable: the registry serializes with the machine, so a restored replica
  keeps enforcing without a re-define.
- Not exact across the blind window: two replicas can both see "alice has
  not voted" and both accept her first vote; the *set* merges back to one
  alice, but two per-option counter increments from two replica ids merge
  to 2. The guard is exact on the merged state, not across the window in
  which two replicas have not yet seen each other.
- Direct mutations are not ops: `setAdd` / `incrementCounter`-style driver
  calls bypass signatures, policies, and any registered guard. The snippets
  use them only to read (assert) what the spec recorded.

## Variations

- Per-option membership — when the membership record itself should be the
  tally: mint one one-shot set per option and check them all in the handler,
  and the merged set sizes *are* the tallies. (The trade: a member's
  concurrent conflicting votes can land in two option sets at once — the
  record stays honest, the "one vote" does not.)
- Anonymous ballots — when votes exist but names must not: the element you
  add does not have to be `op.signerId`; any per-member token inside the
  payload works, as long as the same token is derived on every replica.
- The flag-shaped cousin of this recipe (a boolean that turns true once) is
  Recipe 3.

## Verified against the code

<!-- PROVENANCE
machine shapes: ONE_SHOT_SET — add via Node.addOneShotSet wasm bindings/wasm/index.d.ts:493 · node bindings/node/index.d.ts:318.
registered-spec executor path (registered wins over op-carried): src/StateMachine/state_machine.c:1695-1714 · post-handler spec mutation :1863-1869 · handler result checked first :1829 · define-op handler state_machine_op_define_operation :2925-2940 · registry store state_register_op_type_def src/CRABS/data_model.c:529-553 (in-place replace, capacity 32 — CRABS_MAX_OP_TYPE_DEFS src/CRABS/data_model.h:381).
dedup C surface: dedup_check_guard_spec src/Dedup/dedup.h:31-33 · dedup_apply_mutation_spec :43-45 · pre-handler mutation validation dedup_validate_mutation_spec :50 · DEDUP_PER_USER + dedup_spec_t src/CRABS/data_model.h:365-376 · paths capped CRABS_MAX_DEDUP_PATH :332.
error surfaced: CRABS_ERR_ALREADY_PERFORMED = 0x7001 'already_performed' — src/CRABS/crabs.h:106 (name map bindings/node/src/crabs_node.cc:140).
one-shot set behavior: add idempotent + union merge — test/test_one_shot.cpp:43-55, :75-97 · setRemove tombstones OR-sets only: bindings/node/src/crabs_node.cc:2178-2188 (wasm glue mirrors, src/Util/wasm_helpers.c:1421-1428).
registry durability: the dedup registry serializes with the machine — src/Serialization/serialization.c:2010-2016, 2569-2598.
driver-level calls (setAdd/incrementCounter) bypass guards — recipe-level note, contract of the direct-op surface.

target: crabs-wasm (snippet wasm/02-one-vote.js)
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:774
  KeyPair.generate          bindings/wasm/index.d.ts:44
  publicKeyHex              bindings/wasm/index.d.ts:38
  KeyPair.destroy           bindings/wasm/index.d.ts:42
  registerUser              bindings/wasm/index.d.ts:480
  grantRole                 bindings/wasm/index.d.ts:481
  addOneShotSet             bindings/wasm/index.d.ts:493
  addCounter                bindings/wasm/index.d.ts:490
  setPolicy                 bindings/wasm/index.d.ts:638
  defineOperationType       bindings/wasm/index.d.ts:649
  DefineOperationTypeOptions bindings/wasm/index.d.ts:324-345
  registerHandlerJs         bindings/wasm/index.d.ts:683
  HandlerState.incrementCounter bindings/wasm/index.d.ts:195
  HandlerOperation          bindings/wasm/index.d.ts:268-278 (signerId :270, payload :271)
  Operation.create          bindings/wasm/index.d.ts:122
  Operation.destroy         bindings/wasm/index.d.ts:118
  Node.sign                 bindings/wasm/index.d.ts:657
  Node.execute              bindings/wasm/index.d.ts:656
  setContains               bindings/wasm/index.d.ts:567
  getCounter                bindings/wasm/index.d.ts:554
  Node.destroy              bindings/wasm/index.d.ts:770
  (string payload contract) src/Util/wasm_helpers.c:1741-1749 (payload must be NUL-terminated — hence the '\0' on the vote option)
maturity: all STABLE
test_ref: bindings/wasm/test/dedup-surface.js (registered per-user/global specs, registry overwrite, malformed-input refusals)

target: crabs-node (snippet node/02-one-vote.js)
verified: executed
symbols:
  NodeStatic.new      bindings/node/index.d.ts:642 (new Node)
  KeyPair.generate    bindings/node/index.d.ts:71
  publicKeyHex        bindings/node/index.d.ts:28
  registerUser        bindings/node/index.d.ts:304
  grantRole           bindings/node/index.d.ts:305
  addOneShotSet       bindings/node/index.d.ts:318
  setPolicy           bindings/node/index.d.ts:450
  defineOperationType bindings/node/index.d.ts:462
  DefineOperationTypeOptions bindings/node/index.d.ts:247-266
  Operation           bindings/node/index.d.ts:76-90 (signerId :78, addResource :83)
  Node.sign           bindings/node/index.d.ts:463
  Node.execute        bindings/node/index.d.ts:464
  setContains         bindings/node/index.d.ts:393
maturity: all STABLE
test_ref: bindings/node/test/test.js:659ff (defineOperationType block: per-user guard, F-2 bypass shape refused)

target: native-c (snippet c/02-one-vote.c)
verified: executed
symbols:
  state_create               src/CRABS/data_model.h:723
  state_destroy              src/CRABS/data_model.h:724
  data_item_create           src/CRABS/data_model.h:675
  state_add_item             src/CRABS/data_model.h:758
  one_shot_set_create        src/CRDT/one_shot.h:24
  one_shot_set_count         src/CRDT/one_shot.h:28
  one_shot_set_contains      src/CRDT/one_shot.h:27
  one_shot_set_destroy       src/CRDT/one_shot.h:25
  data_value_repr_t          src/CRABS/data_model.h:77-82
  state_register_op_type_def src/CRABS/data_model.h:796
  state_find_op_type_def     src/CRABS/data_model.h:795
  dedup_spec_t               src/CRABS/data_model.h:365-376
  CRABS_MAX_DEDUP_PATH       src/CRABS/data_model.h:332
  dedup_check_guard_spec     src/Dedup/dedup.h:31-33
  dedup_apply_mutation_spec  src/Dedup/dedup.h:43-45
  operation_create           src/StateMachine/state_machine.h:346
  operation_destroy          src/StateMachine/state_machine.h:347
  CRABS_SUCCESS              src/CRABS/crabs.h:65
  CRABS_ERR_ALREADY_PERFORMED src/CRABS/crabs.h:106
  crdt_value_destroy         src/CRDT/crdt_merge.h:141
maturity: all STABLE
test_ref: test/test_dedup.cpp:680 (PerUserVoteOnceLifecycle) + :221-257 (RegisteredSpecEnforcedEvenWhenOpCarriesNone — the F-2 bypass attempt) + test/test_state_machine.cpp:193 (DefineOperationTypeExecutesThroughMachine — the full define + guard + bypass-refusal executor path)
-->