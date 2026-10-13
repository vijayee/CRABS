---
number: 9
slug: treasury-atomic-transfers
title: A treasury with atomic transfers
section: Coordination
status: COMPLETE
maturity: STABLE
target: all-bindings
languages: c wasm node
teaches: resource locking — what machines can and cannot promise
---
## The problem

A group treasury holds 1,000 credits, and five tellers can spend from it.
Two tellers get the same balance in front of them: each reads 400, each
spends 300, each writes back 100 — and one of the two spends has simply
ceased to exist. Not stolen, not reversed: *erased*, because the second
write replaced the first instead of building on it.

A third teller's connection drops halfway through a transfer. The pot is
300 credits lighter and the recipient has nothing; the retry the teller
naturally attempts is the exact double-spend the treasury was supposed to
make impossible. Money is not a counter (Recipe 1): it moves in two
directions at once, and a merge rule that "takes the larger pot" is a merge
that invents money. The question is what promise a machine can actually
keep here — and what it cannot.

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

## The idea

Three separate promises hide inside the word "atomic", and databases have
learned to name them apart:

- *Exclusivity.* While one operator works on the pot, no other operator can
  move it. A lock buys this — and a lock is a *lease*: it carries an expiry,
  it releases on its own when a holder dies, and it holds a snapshot so the
  pot can be put back if the operator's work is abandoned.
- *All-or-nothing.* An op that touches several pots states, before anything
  happens, what condition each pot must be in. The machine checks every
  condition first and refuses the whole op if any fails — no half-apply.
  Alongside it, *apply-once*: an op that already ran is recognized and
  refused, so a delivery replay is inert.
- *Recovery.* If an operator did half a move and died, the machine holds
  the pot's previous state and can restore exactly those bytes.

Now the boundary, taught plainly rather than confessed. A lock is a lease
*within one machine's runtime*: the machine that holds the pot enforces the
lease against whoever submits ops to it, and it cannot negotiate a shared
lease with a replica it is not talking to. Convergence between replicas is
still merge after the fact — there is no cross-replica atomic commit here.
And claims are *cooperative*: the machine verifies any claim an op presents
and closes the unlocked-spend path for ops that have no handler of their
own, but an operator who registers a handler owns that handler's discipline.
What the machine *can* deliver is the machinery of the protocol — states,
lease, snapshot, refusal of duplicates, all-or-nothing preconditions — the
same way a database delivers row locks: locally, and verifiably.

## How CRABS encodes it

- The pot is a RESOURCE item — `DATA_TYPE_RESOURCE`, "PN-Counter + lock".
  Locks live on the item in `lock_state_t`: a 32-byte CSPRNG bearer
  `lock_token`, `lock_owner`, `lock_expiry`, extension count, and a
  `pre_lock_snapshot` for rollback. Lock state is runtime-only — it is
  *never serialized* (see "what it doesn't").
- An op names the items it touches: `Operation.addResource` (up to
  `CRABS_MAX_RESOURCES` = 8). With each resource the op carries a
  `required_state`/`next_state` protocol pair — that pair lets the
  executor enforce timing; `Operation.setRequiredState(index, 'locked')` /
  `setNextState` are how a driver authors it from JS.
- The executor's gates run in order *before any effect*: replay
  (signature, then per-signer ordering monotonicity), required protocol
  state across **every** named resource (`_check_transitions`), presented
  lock claims, dedup guard, handler, and only then the wildcard apply —
  which for handler-less custom ops is restricted to LOCKED resources.
  A gate that fails leaves *nothing*: no log entry, no version bump, no
  balance change.
- The lock protocol is built-in op types — `__lock__`, `__extend__`,
  `__verify__`, `__rollback__`, `__unlock__`, `__force_unlock__` — moving
  the item through IDLE → LOCKED → MODIFIED → VERIFIED → IDLE. A live
  lease refuses re-acquisition, expires on its own and is pruned by the
  next execute; a rollback is owner-checked and restores the pre-lock
  snapshot, so a locked-and-reverted item hashes back to exactly what the
  lock captured.
- Replay protection is pluggable: a tx manager sits in front of the
  executor with `accept`/`commit`/`destroy` — memory-backed duplicates
  land as `CRABS_ERR_ALREADY_EXECUTED` — and even with *no* manager, the
  per-signer ordering backstop rejects a replayed op after a restart.
- Every surface *drives* the same contract: the pot mint
  (`Node.addResource`), the lease and the bearer token (`Node.getLockState`),
  the per-slot protocol states and lock claims
  (`Operation.setRequiredState`/`setNextState`/`addLockClaim`), and the
  attachable tx manager (`Node.attachTxManager('memory' | 'none')`) are
  bound on BOTH JS bindings — the same ceremony runs three times below.

## Try it

### crabs-wasm (browser / Node / edge)

The whole demo runs on this binding — the mint, the lease, the claims, the
handler-owned debit/credit, and the tx manager.

```snippet:wasm/09-treasury.js
```

### crabs-node (native Node.js)

The pot mint, the lock drive, the claims, and the executor's refusals are
all real on this binding — the same ceremony as wasm's, minus one thing the
api-map pins as a known difference: no custom-handler surface, so the
debit/credit *arithmetic* cannot live in a machine handler here. The op
below carries the protocol (gates, lease, claims, at-most-once
application); the balance arithmetic stays the driver's.

```snippet:node/09-treasury.js
```

What the snippets could not do before — and what closing that gap changed —
is worth stating once, because it was this binding's most famous trap.

**The old "locked pot is unspendable from JS" trap is gone.** What used to
be true: the op builder could not author `required_state` or a lock claim,
so once JS locked a pot it sat locked until lease expiry and the next
execute pruned it — the "pot-unspendable discovery". Now:
`Operation.setRequiredState`/`setNextState` author the protocol states and
`Operation.addLockClaim` carries the live bearer token read from
`Node.getLockState` — so the locked pot is operable under its lease:
claim-bearing ops pass the state gate, and `__verify__`/`__unlock__`
complete the ceremony from both JS bindings. Two caveats survive,
deliberately: the claim discipline stays cooperative (above), and the token
is only claimable through `getLockState` before signing — the signature
binds whatever the op carries, so claim AFTER `__lock__` and BEFORE `sign`.

### C (native)

The full protocol, driven the way the executor actually wants it: single
lease with a contested re-acquisition refused, a forged lock-claim refused,
the lock-modify-verify-unlock ceremony, a real debit/credit applied exactly
once under the memory tx manager, and all-or-nothing preconditions across
two named resources.

```snippet:c/09-treasury.c
```

## What it guarantees / what it doesn't

Guaranteed, by the executor (all of it exercised by the snippets above):

- *Refused, not applied.* Preconditions run across every named resource
  before the handler; one poisoned name voids the whole op with no partial
  apply — and an un-locked RESOURCE is refused `protocol_violation` on the
  handler-less path, an unknown name `resource_not_found`.
- *Apply at most once.* A committed op's uuid is recorded by the memory tx
  manager; a duplicate submission is `already_executed`, and with no
  manager the per-signer ordering backstop still rejects a replay after a
  restart.
- *One live lease per pot.* A locked RESOURCE refuses acquisition until
  expiry, regardless of who calls; the lock token is a CSPRNG bearer
  credential and any claim an op presents on a locked/modified item is
  verified against it, so a forged claim is `lock_token_mismatch`. A lock
  expires and is pruned; a rollback puts back the exact pre-lock balance.

Not guaranteed — say this before building on it:

- *The lock is machine-local, not a distributed lease.* Lock state is
  runtime-only and never serialized; two replicas do not negotiate a shared
  lease. The lock protocol coordinates *one machine's* operators — e.g. a
  validator process holding the treasury — while replica convergence is
  still CRDT merge after the fact. There is no cross-replica atomic commit
  here.
- *Claim discipline is cooperative at the op level.* The executor verifies
  the claims an op presents and refuses handler-less custom ops on a
  non-LOCKED resource — but the wildcard apply does not force a claim to be
  present, and a custom op with a registered handler owns its own protocol
  transitions entirely. "Every treasury spend must say LOCKED-and-carry-
  the-token" is driver discipline the machine *verifies* (the C snippet
  shows both halves of that), not an invariant it imposes on arbitrary
  custom ops.
- *No built-in transfer.* The debit/credit arithmetic is your handler's (C
  snippet) — the machine guards the protocol around the movement; it ships
  no `transfer` op type and no atomic multi-item move primitive.
- *The tx manager's dedup memory is in-process.* After a restart the
  manager is empty and replay protection rests on the ordering backstop —
  exactly what the tests cover; attach (`Node.attachTxManager('memory')`)
  again after a state round trip, since the manager is host-owned and not
  serialized.
- *A crabs-node op carries the protocol, not the arithmetic.* crabs-node
  has no custom-handler surface (api-map known difference #2), so nodes
  read balances with `Node.getResource` and the handler-owned debit/credit
  runs on crabs-wasm (`registerHandlerJs` + `HandlerState.adjustResource`)
  and in C.

## Variations

- *Cross-item atomicity*: when one move touches several pots, one op may
  name up to 8 resources and preconditions are checked across all of them
  before anything moves — the closest thing to a multi-item transaction
  here.
- *Recovery instead of undo*: to resume rather than abort, `__verify__`
  promotes MODIFIED → VERIFIED or drops the item to ERROR on a failed
  invariant; `__rollback__` takes either MODIFIED or ERROR back to IDLE
  with the snapshot restored.
- *Break-glass unblocking*: when an expired-but-unpruned lease blocks a
  pot, `__force_unlock__` releases it to IDLE — it is not a lock steal: a
  live lease is refused with `CRABS_ERR_LOCK_NOT_EXPIRED`, and the whole op
  is refused `force_unlock_disabled` unless `config.allow_force_unlock` is
  set.
- *Vote-then-spend treasuries*: to take the human decision out of the
  teller's hands, compose Recipe 2's one-shot vote records with this item —
  the vote gate is the caller's, the spend serialization is this page's.
- *If you need "never twice" but not exclusivity*: Recipe 3's dedup guard
  is the lighter mechanism — a lock buys serialization you may not need.

## Verified against the code

<!-- PROVENANCE
target: all-bindings
data model:
  DATA_TYPE_RESOURCE ("PN-Counter + lock") src/CRABS/data_model.h:29
  lock_state_t (token/owner/expiry/extensions/pre_lock_snapshot) src/CRABS/data_model.h:117-133
  lock state runtime-only, never serialized src/CRABS/data_model.h:130
  chain digest excludes protocol state src/CRABS/data_model.h:785
  max_lock_duration_ms src/CRABS/data_model.h:281 · allow_force_unlock src/CRABS/data_model.h:283
  CRABS_MAX_RESOURCES = 8 src/CRABS/crabs.h:19
  built-in lock op types __lock__/__extend__/__verify__/__rollback__/__unlock__/__force_unlock__ src/CRABS/crabs.h:135-140
  CRABS_ERR_ALREADY_EXECUTED src/CRABS/crabs.h:107 · LOCK_NOT_EXPIRED :72 · LOCK_TOKEN_MISMATCH :69
executor (src/StateMachine/state_machine.c):
  protocol states IDLE→LOCKED→MODIFIED→VERIFIED→IDLE :133-145
  per-signer replay ordering :1633-1643
  _check_transitions (required protocol state) :848-866, run at :1647-1651
  claim verify (step 5) :1653-1668
  dedup guard :1671+ · duplicate refusal :1600-1620
  handler-owned transitions :1808-1831 · wildcard apply gate :1825-1851
  lock token generation (32-byte CSPRNG) :312-326
  live-lease re-acquisition refusal :2102-2110
  expiry :366-385 · pruning :389-411
  snapshot contract :2182-2189 · capture :2183-2212 · restore (8-byte form) :2296-2323
  rollback owner check :2282-2289
  ordering backstop (state_signer_has_replay) :587-611
tx manager: src/TxManager/tx_manager.h:19-41 (accept/commit/destroy vtable;
  in-memory, persistent, no-op flavours) · memory impl
  src/TxManager/tx_manager_memory.h:16 · wired at src/CRABS/data_model.h:486
raw-int64 balance note: bindings/node/src/crabs_node.cc:1748 ("the library
  contract — dedup mutations, the lock snapshot, and destroy all take the
  raw path") · snapshot captures 8 bytes for this item
  state_machine.c:2183-2212, restore :2304-2318

target: crabs-wasm (snippet wasm/09-treasury.js)
verified: executed
symbols:
  NodeStatic.create         bindings/wasm/index.d.ts:774
  KeyPair.generate          bindings/wasm/index.d.ts:44
  registerUser              bindings/wasm/index.d.ts:480
  grantRole                 bindings/wasm/index.d.ts:481
  Node.setPolicy            bindings/wasm/index.d.ts:638
  Node.sign / Node.execute  bindings/wasm/index.d.ts:657 / :656
  Node.addResource          bindings/wasm/index.d.ts:502
  Node.getResource          bindings/wasm/index.d.ts:509
  Node.getLockState         bindings/wasm/index.d.ts:517 (LockStateView :258-266)
  Node.attachTxManager      bindings/wasm/index.d.ts:528
  Operation.create          bindings/wasm/index.d.ts:122
  Operation.addResource     bindings/wasm/index.d.ts:68
  Operation.setRequiredState / setNextState bindings/wasm/index.d.ts:84 / :87
  Operation.addLockClaim    bindings/wasm/index.d.ts:96
  registerHandlerJs         bindings/wasm/index.d.ts:683 (HandlerState
                            getResource/adjustResource :219 / :225,
                            resources on HandlerOperation :268-278)
  (mint export)             src/Util/wasm_helpers.c:638 (crabs_wasm_add_resource — mirrors the node mint)
  (lock-state read)         src/Util/wasm_helpers.c:730 (crabs_wasm_lock_state)
  (claims + state setters)  src/Util/wasm_helpers.c:759-806
  (tx manager attach)       src/Util/wasm_helpers.c:829
  (handler arithmetic)      src/Util/wasm_helpers.c:682
maturity: full ceremony + tx manager STABLE
test_ref: bindings/wasm/test/locks-tx.js (mirror of the C battery: single
  lease, forged claim, ceremony, apply-once, poisoned op, cooperative
  wildcard) + test/test_state_machine.cpp:196-352

target: crabs-node (snippet node/09-treasury.js)
verified: executed
symbols:
  NodeStatic.new            bindings/node/index.d.ts:642
  KeyPair.generate          bindings/node/index.d.ts:71
  registerUser              bindings/node/index.d.ts:304
  grantRole                 bindings/node/index.d.ts:305
  Node.setPolicy            bindings/node/index.d.ts:450
  Node.sign / Node.execute  bindings/node/index.d.ts:463 / :464
  Node.addResource          bindings/node/index.d.ts:328 (seeds the int64
                            balance; implemented bindings/node/src/crabs_node.cc:1738)
  Node.getResource          bindings/node/index.d.ts:337 (crabs_node.cc:1830)
  Node.getLockState         bindings/node/index.d.ts:344 (crabs_node.cc:1804)
  Node.attachTxManager      bindings/node/index.d.ts:357 (crabs_node.cc:1778)
  new Operation             bindings/node/index.d.ts:138-140
  Operation.addResource     bindings/node/index.d.ts:83
  Operation.setRequiredState / setNextState bindings/node/index.d.ts:98 / :101
                            (crabs_node.cc:648,800)
  Operation.addLockClaim    bindings/node/index.d.ts:110 (crabs_node.cc:650,820)
  (typed config string)     bindings/node/src/crabs_node.cc:131
maturity: full ceremony + tx manager STABLE (no handler surface — the
  arithmetic is the driver's, api-map known difference #2)
test_ref: bindings/node/test/locks-tx.js (17 asserts: the C battery minus the
  handler arithmetic) + test/test_tx_manager.cpp:225-243

target: native-c (snippet c/09-treasury.c)
verified: executed
symbols:
  state_machine_execute        src/StateMachine/state_machine.h:177
  state_machine_register_handler src/StateMachine/state_machine.c:502-527
  CRABS_OP_LOCK/VERIFY/UNLOCK  src/CRABS/crabs.h:135-139
  crabs_tx_manager_memory      src/TxManager/tx_manager_memory.h:16
  data_item_create / state_add_item src/CRABS/data_model.h
maturity: all STABLE (executor + lock protocol + tx manager, tested)
test_ref: test/test_state_machine.cpp:196-352 (lock ceremony) + :1153-1211
  (atomic across resources) + test/test_tx_manager.cpp:225-243 (duplicate
  refused) + :269-295 (lamport backstop)

atomicity-in-three-layers note: (1) all-or-nothing preconditions — executor
  checks every named resource before the handler; a failure leaves no log
  entry, no version bump, no balance change (test/test_state_machine.cpp:1153-1211);
  (2) apply-once — duplicates recorded and refused (test/test_tx_manager.cpp:225-243),
  ordering backstop covering the post-restart window (:269-295);
  (3) recovery — a locked item snapshots its balance at acquisition and
  rollback restores exactly those bytes (state_machine.c:2296-2323)
node-binding refusal note: crabs-node has no custom-handler surface (api-map
  known difference #2), so handler-less custom ops go through the wildcard
  apply — which only acts on LOCKED resources (state_machine.c:1836-1851);
  the refusal is the gate, not a bug
serialization check: rollback "restores exactly the content (and digest) the
  lock captured" (state_machine.c:2182-2189) — a locked-and-reverted item
  hashes back to its pre-lock form; the snapshot is the recovery contract
-->