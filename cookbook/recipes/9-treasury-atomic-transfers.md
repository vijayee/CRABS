---
number: 9
slug: treasury-atomic-transfers
title: A treasury with atomic transfers
section: Coordination
status: COMPLETE
maturity: STABLE
target: all-bindings
languages: c wasm node
---
## Intent

You want a *treasury* — a balance many members can spend into — where a
transfer debits one pot and credits another, and no failure, retry, or
concurrent teller can make two debits become one or one debit become two.
The requirement has a shape you can name precisely:

- a *double-submit* by the same teller (the same signed transfer delivered
  twice) must apply exactly once;
- two tellers acting on the same balance concurrently must not both compute
  "read balance, subtract, write" against the same assumed starting point;
- a transfer that dies halfway (debit applied, credit lost) must leave the
  pot in a state that is recoverable — not silently half-paid.

This is the recipe where the machine, not the caller, has to hold the gates.
Recipe 1 got no double-counting out of a merge function; a treasury can't
buy safety that cheaply, because money moves in two directions at once and
a merge that "takes the larger pot" is a merge that invents money.

## The naive version, and where it breaks

The naive version is an integer and two ops: `debit(treasury, 100)` on one
replica, `credit(alice, 100)` on another, each "obviously" safe alone. Each
half fails on its own. Debit and credit can be split by any transport
failure in between, and nothing marks the split — the pot is 100 lighter and
no credit exists anywhere. Retries don't patch that; re-sending `debit` is
exactly the double-spend. Read-modify-write doesn't patch it either: two
tellers each holding `balance = 100` both compute `30` from two `70`-spends,
and the machine has no record that the balance was ever *targeted* twice —
the balance only remembers its last value. And last-writer-wins merging of
replicas converges to a number that belongs to no real history: whichever
replica wrote last erases the other's spend entirely, so the total is
under-spent instead of over-spent — different failure, same missing piece.

The missing piece is not clever merging. It is a protocol around the item:
a way to claim it, a way to record "this op happened" against replays, and
a way for an op to state its preconditions so the machine can check them
*before anything moves*.

## The shape

- The pot is a RESOURCE item — `DATA_TYPE_RESOURCE`
  (`src/CRABS/data_model.h:29`, "PN-Counter + lock"). Locks live on the
  item, in `lock_state_t` (`src/CRABS/data_model.h:117-133`): a 32-byte
  CSPRNG bearer `lock_token` (`src/StateMachine/state_machine.c:312`),
  `lock_owner`, `lock_expiry`, extension count, and a `pre_lock_snapshot`
  for rollback. Lock state is runtime-only — it is *never serialized*
  (`data_model.h:130`); see the honesty section.
- An op names the items it touches: `Operation.addResource` (up to
  `CRABS_MAX_RESOURCES` = 8, `src/CRABS/crabs.h:19`; node wrapper
  `bindings/node/src/crabs_node.cc:756-773`). With each resource the op
  carries a `required_state`/`next_state` protocol pair — that pair is what
  lets the executor enforce timing, and `Operation.setRequiredState(index,
  'locked')` / `setNextState` are how a driver authors it from JS.
- The executor's gates run in order *before any effect*: replay
  (signature, then per-signer ordering monotonicity,
  `src/StateMachine/state_machine.c:1633-1643`), required protocol state
  across **every** named resource
  (`_check_transitions`, `src/StateMachine/state_machine.c:848-866`,
  run at `:1647-1651`), presented lock claims
  (`:1653-1668`), dedup guard (`:1671+`), handler, and only then the
  wildcard apply — which for handler-less custom ops is restricted to
  LOCKED resources (`src/StateMachine/state_machine.c:1825-1851`). A gate
  that fails leaves *nothing*: no log entry, no version bump, no balance
  change (`test/test_state_machine.cpp:1153-1211`,
  `test/test_tx_manager.cpp:246-266`).
- The lock protocol is built-in op types — `__lock__`, `__extend__`,
  `__verify__`, `__rollback__`, `__unlock__`, `__force_unlock__`
  (`src/CRABS/crabs.h:135-140`) — moving the item through
  IDLE → LOCKED → MODIFIED → VERIFIED → IDLE
  (`src/StateMachine/state_machine.c:133-145`). A live lease refuses
  re-acquisition (`:2102-2110`), expires on its own
  (`state_machine_lock_expired`, `:366-385`) and is pruned by the next
  execute (`:389-411`); a rollback is owner-checked
  (`:2282-2289`) and restores the pre-lock snapshot
  (`:2296-2323`), so a locked-and-reverted item hashes back to exactly what
  the lock captured.
- Replay protection is pluggable: a tx manager sits in front of the
  executor with `accept`/`commit`/`destroy`
  (`src/TxManager/tx_manager.h:19-41`) — memory-backed duplicates land as
  `CRABS_ERR_ALREADY_EXECUTED` (`src/CRABS/crabs.h:107`; wired and tested,
  `test/test_tx_manager.cpp:225-243`) — and even with *no* manager, the
  per-signer ordering backstop rejects a replayed op after a restart
  (`state_signer_has_replay`, `src/StateMachine/state_machine.c:587-611`,
  `test/test_tx_manager.cpp:269-295`).

This is the machine's contract. Every surface now *drives* it: the pot mint
(`Node.addResource`), the lease and the bearer token (`Node.getLockState`),
the per-slot protocol states and lock claims
(`Operation.setRequiredState`/`setNextState`/`addLockClaim`), and the
attachable tx manager (`Node.attachTxManager`) are bound on BOTH JS
bindings — the same ceremony runs three times below.

## What it guarantees / what it doesn't

Guaranteed, by the executor (all of it exercised by the snippets below):

- *Refused, not applied.* A handler-less custom op naming an un-locked
  RESOURCE is refused `protocol_violation` instead of half-applying (the
  only custom path crabs-node offers); an op naming an unknown
  resource is refused `resource_not_found`. Preconditions run across every
  named resource before the handler, so one poisoned name voids the whole
  op with no partial apply (C snippet, Demo C;
  `test/test_state_machine.cpp:1153-1211`).
- *Apply at most once.* A committed op's uuid is recorded by the memory tx
  manager and a duplicate submission is `already_executed`
  (`test/test_tx_manager.cpp:225-243`); with no manager configured,
  ordering monotonicity still rejects a replayed op — the same signed op
  cannot land twice (`src/StateMachine/state_machine.c:587-611`,
  `:1633-1643`).
- *One live lease per pot.* A locked RESOURCE refuses acquisition until
  expiry (`state_machine.c:2102-2110`); the lock token is a CSPRNG bearer
  credential (`:312-326`) and any claim an op presents on a
  locked/modified item is verified against it (`:1653-1668`), so a forged
  claim is `lock_token_mismatch`. A lock expires and is pruned; a rollback
  puts back the exact pre-lock balance.

Not guaranteed — say this before building on it:

- *The lock is machine-local, not a distributed lease.* Lock state is
  runtime-only and never serialized (`src/CRABS/data_model.h:130`,
  the chain digest excludes protocol state, `:785`); two replicas do not negotiate
  a shared lease. The lock protocol
  coordinates *one machine's* operators — e.g. a validator process holding
  the treasury — while replica convergence is still CRDT merge after the
  fact. There is no cross-replica atomic commit here.
- *Claim discipline is cooperative at the op level.* The executor verifies
  the claims an op presents (`:1653-1668`) and refuses handler-less custom
  ops on a non-LOCKED resource (`:1825-1851`) — but the wildcard apply does
  not force a claim to be present, and a custom op with a registered
  handler owns its own protocol transitions entirely (`:1808-1831`). "Every treasury
  spend must say LOCKED-and-carry-the-token" is driver discipline the
  machine *verifies* (the C snippet shows both halves of that), not an
  invariant the machine imposes on arbitrary custom ops.
- *No built-in transfer.* The debit/credit arithmetic is your handler's
  (C snippet, Demo B). The machine guards the protocol around the movement;
  it ships no `transfer` op type and no atomic multi-item move primitive.
- *The tx manager's dedup memory is in-process* (`src/TxManager/
  tx_manager.h:4-7` — "in-memory, persistent, no-op"). After a restart the
  manager is empty and replay protection rests on the ordering backstop —
  which is exactly what the tests cover (`test/test_tx_manager.cpp:
  268-291`); attach (`Node.attachTxManager('memory')`) again after a state
  round trip — the manager is host-owned and not serialized.
- *A crabs-node op carries the protocol, not the arithmetic.* crabs-node has
  no custom-handler surface (api-map known difference #2), so its transfer
  op advances the protocol states and is applied at most once, while the
  balance arithmetic stays the driver's (the snippets read balances with
  `Node.getResource`); the handler-owned debit/credit runs on crabs-wasm
  (`registerHandlerJs` + `HandlerState.adjustResource`) and in C.

## Variations

- *Cross-item atomicity*: one op may name up to 8 resources
  (`src/CRABS/crabs.h:19`), and preconditions are checked across all of
  them before anything moves — that is the closest thing to a
  multi-item transaction here (`test/test_state_machine.cpp:1153-1211`).
- *Recovery instead of undo*: `__verify__` promotes MODIFIED → VERIFIED or
  drops the item to ERROR on a failed invariant
  (`state_machine.c:2250-2272`); `__rollback__` takes either MODIFIED or
  ERROR back to IDLE with the snapshot restored (`:2274-2323`).
- *Break-glass unblocking*: `__force_unlock__` releases an *expired but
  not-yet-pruned* lock to IDLE — it is not a lock steal: a live lease is
  refused with `CRABS_ERR_LOCK_NOT_EXPIRED` (`state_machine.c:2350-2362`,
  error at `src/CRABS/crabs.h:72`), and the whole op is refused with
  `force_unlock_disabled` unless `config.allow_force_unlock` is set
  (`src/CRABS/data_model.h:283`; typed string
  `bindings/node/src/crabs_node.cc:131`).
- *Vote-then-spend treasuries* compose Recipe 2's one-shot vote records
  with this item: the vote gate is the caller's, the spend serialization
  is this page's.
- *If you need "never twice" but not exclusivity*: Recipe 3's dedup guard
  is the lighter mechanism — a lock buys serialization you may not need.

## Recipe

### crabs-wasm (browser / Node / edge)

The whole demo now runs on this binding — the mint, the lease, the claims,
the handler-owned debit/credit, and the tx manager.

```snippet:wasm/09-treasury.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  NodeStatic.create         bindings/wasm/index.d.ts:677
  KeyPair.generate          bindings/wasm/index.d.ts:21
  registerUser              bindings/wasm/index.d.ts:429
  grantRole                 bindings/wasm/index.d.ts:430
  Node.addResource          bindings/wasm/index.d.ts:451
  Node.getResource          bindings/wasm/index.d.ts:458
  Node.getLockState         bindings/wasm/index.d.ts:466 (LockStateView :195-203)
  Node.attachTxManager      bindings/wasm/index.d.ts:477
  new Operation             bindings/wasm/index.d.ts:72
  Operation.addResource     bindings/wasm/index.d.ts:33
  Operation.setRequiredState / setNextState bindings/wasm/index.d.ts:49-52
  Operation.addLockClaim    bindings/wasm/index.d.ts:61
  Node.setPolicy            bindings/wasm/index.d.ts:587
  Node.sign                 bindings/wasm/index.d.ts:606
  Node.execute              bindings/wasm/index.d.ts:605
  registerHandlerJs         bindings/wasm/index.d.ts:632 (HandlerState.
                            adjustResource / getResource :167-171, resources
                            on HandlerOperation :211)
  (mint export)             src/Util/wasm_helpers.c:638 (crabs_wasm_add_resource — mirrors the node mint)
  (lock-state read)         src/Util/wasm_helpers.c:730 (crabs_wasm_lock_state)
  (claims + state setters)  src/Util/wasm_helpers.c:759-806
  (tx manager attach)       src/Util/wasm_helpers.c:828
  (handler arithmetic)      src/Util/wasm_helpers.c:682
  (lock protocol op types)  src/CRABS/crabs.h:135-140
  (refusal: un-locked RESOURCE wildcard) src/StateMachine/state_machine.c:1836-1846
  (refusal: re-acquire live lease) src/StateMachine/state_machine.c:2102-2110
  (claim verify, step 5)    src/StateMachine/state_machine.c:1653-1668
  (required-state gate, step 4) src/StateMachine/state_machine.c:848-866
maturity: full ceremony + tx manager STABLE (bindings/wasm/test/locks-tx.js)
test_ref: bindings/wasm/test/locks-tx.js (mirror of the C battery: single lease, forged claim, ceremony, apply-once, poisoned op, cooperative wildcard) + test/test_state_machine.cpp:196-352
-->

### crabs-node (native Node.js)

The pot mint, the lock drive, the claims, and the executor's refusals are
all real on this binding — the same ceremony as wasm's, minus one thing the
api-map pins as a known difference (#2): no custom-handler surface, so the
debit/credit *arithmetic* cannot live in a machine handler here. The op
below carries the protocol (gates, lease, claims, at-most-once
application); the balance arithmetic stays the driver's.

```snippet:node/09-treasury.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  NodeStatic.new            bindings/node/index.d.ts:567
  KeyPair.generate          bindings/node/index.d.ts:14
  registerUser              bindings/node/index.d.ts:252
  grantRole                 bindings/node/index.d.ts:253
  Node.addResource          bindings/node/index.d.ts:276 (seeds the int64
                            balance; implemented bindings/node/src/crabs_node.cc:1745)
  Node.getResource          bindings/node/index.d.ts:283 (crabs_node.cc:1837)
  Node.getLockState         bindings/node/index.d.ts:290 (crabs_node.cc:1756)
  Node.attachTxManager      bindings/node/index.d.ts:304 (crabs_node.cc:1785)
  new Operation             bindings/node/index.d.ts:87
  Operation.addResource     bindings/node/index.d.ts:46
  Operation.setRequiredState / setNextState bindings/node/index.d.ts:61-64
                            (crabs_node.cc:648,800)
  Operation.addLockClaim    bindings/node/index.d.ts:73 (crabs_node.cc:650,820)
  Node.setPolicy            bindings/node/index.d.ts:397
  Node.sign / execute       bindings/node/index.d.ts:410-411
  (tx manager attach)       bindings/node/src/crabs_node.cc:1785
  (lock protocol op types)  src/CRABS/crabs.h:135-140
  (refusal: un-locked RESOURCE wildcard) src/StateMachine/state_machine.c:1836-1846
  (refusal: re-acquire live lease) src/StateMachine/state_machine.c:2102-2110
  (claim verify, step 5)    src/StateMachine/state_machine.c:1653-1668
  (required-state gate, step 4) src/StateMachine/state_machine.c:848-866
  (duplicate refusal)       src/StateMachine/state_machine.c:1600-1620
maturity: full ceremony + tx manager STABLE (no handler surface — the
  arithmetic is the driver's, api-map known difference #2)
test_ref: bindings/node/test/locks-tx.js (17 asserts: the C battery minus the
  handler arithmetic) + test/test_tx_manager.cpp:225-243
-->

What the snippets could not do before — and what closing that gap changed —
is worth stating once, because it was this binding's most famous trap.

**The old "locked pot is unspendable from JS" trap is gone.** What used to
be true: the op builder could not author `required_state` or a lock claim,
so once JS locked a pot it sat locked until lease expiry and the next
execute pruned it (`state_machine.c:364-411`) — the "pot-unspendable
discovery". Now: `Operation.setRequiredState`/`setNextState` author the
protocol states (`crabs_node.cc:800` / wasm `wasm_helpers.c:759-806`) and
`Operation.addLockClaim` carries the live bearer token read from
`Node.getLockState` (`crabs_node.cc:1756` / `wasm_helpers.c:730`) — so the
locked pot is operable under its lease: claim-bearing ops pass the state
gate, and `__verify__`/`__unlock__` complete the ceremony from both JS
bindings. Two caveats survive, deliberately: the claim discipline stays
cooperative (below), and the token is only claimable through
`getLockState` before signing — the signature binds whatever the op
carries, so claim AFTER `__lock__` and BEFORE `sign`.

### C (native)

The full protocol, driven the way the executor actually wants it: single
lease with a contested re-acquisition refused, a forged lock-claim refused,
the lock-modify-verify-unlock ceremony, a real debit/credit applied exactly
once under the memory tx manager, and all-or-nothing preconditions across
two named resources.

```snippet:c/09-treasury.c
```

<!-- PROVENANCE
target: native-c
verified: executed
symbols:
  state_machine_execute        src/StateMachine/state_machine.h:177
  state_machine_register_handler src/StateMachine/state_machine.c:502-527
  CRABS_OP_LOCK/VERIFY/UNLOCK  src/CRABS/crabs.h:135-139
  __lock__ contention refusal  src/StateMachine/state_machine.c:2102-2110
  lock token generation        src/StateMachine/state_machine.c:312-326
  expiry + pruning             src/StateMachine/state_machine.c:366-411
  wildcard apply gate          src/StateMachine/state_machine.c:1825-1851
  required-state check         src/StateMachine/state_machine.c:848-866
  rollback (owner check + snapshot restore) src/StateMachine/state_machine.c:2274-2323
  crabs_tx_manager_memory      src/TxManager/tx_manager_memory.h:16
  CRABS_ERR_ALREADY_EXECUTED   src/CRABS/crabs.h:107
  CRABS_ERR_LOCK_TOKEN_MISMATCH src/CRABS/crabs.h:69
  data_item_create / state_add_item src/CRABS/data_model.h
maturity: all STABLE (executor + lock protocol + tx manager, tested)
test_ref: test/test_state_machine.cpp:196-352 (lock ceremony) + :1153-1211 (atomic across resources) + test/test_tx_manager.cpp:225-243 (duplicate refused) + :269-295 (lamport backstop)
-->

## Notes

- *Where the "atomic" in this recipe's title actually lives.* Three
  different guarantees get called atomicity; the machine delivers all
  three, at different layers: (1) all-or-nothing *preconditions* — the
  executor checks every named resource before the handler runs and a
  failure leaves no log entry, no version bump, and no balance change
  (`test/test_state_machine.cpp:1153-1211`); (2) *apply-once* — duplicate
  submissions are recorded and refused (`test/test_tx_manager.cpp:
  225-243`), with the ordering backstop covering the post-restart window
  (`:269-295`); (3) *recovery* — a locked item snapshots its balance at
  acquisition and rollback restores exactly those bytes (`state_machine.c:
  2296-2323`), which is why the demo's treasury can end where it started.
- *Why the node binding refuses an un-locked spend at all*: crabs-node has
  no custom-handler surface (api-map "Known wasm/node differences" #2), so
  handler-less custom ops go through the wildcard apply — and that path
  only acts on LOCKED resources (`state_machine.c:1836-1851`). The
  refusal is the gate, not a bug.
- *The lock is a lease, not an ownership transfer*: it has an expiry
  (`max_lock_duration_ms` per extension, `src/CRABS/data_model.h:281`) and
  re-acquisition stays refused while it is live regardless of who calls
  (`state_machine.c:2102-2110`) — the snippet's second `__lock__` from the
  same treasurer is refused exactly as a rival's would be.
- *Balance values on RESOURCE items are raw int64s* (`bindings/node/src/
  crabs_node.cc:1741` — "the library contract — dedup mutations, the
  lock snapshot, and destroy all take the raw path"), which is why the
  lock snapshot captures 8 bytes for this item (`state_machine.c:2183-2212`)
  and the restore is the historical 8-byte form (`:2304-2318`).
- *Serialization check*: a rollback "restores exactly the content (and
  digest) the lock captured" (`state_machine.c:2182-2189`, the snapshot
  contract op_lock commits to at acquisition) — so a locked-and-reverted
  item hashes back to its pre-lock form; the snapshot is the recovery
  contract, not a courtesy.
- Related-but-different: sovereign write domains (Recipe 10) make a
  *leader's writes* verifiable and fork-detectable; they do nothing about
  concurrency on a shared balance. A deployment that wants both layers
  (single-writer accountability + item locking) composes them.