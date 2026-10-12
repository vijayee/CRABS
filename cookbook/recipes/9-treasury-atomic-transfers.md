---
number: 9
slug: treasury-atomic-transfers
title: A treasury with atomic transfers
section: Coordination
status: PARTIAL
maturity: STABLE
target: crabs-node
languages: c node
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
  CSPRNG bearer `lock_token` (`src/StateMachine/state_machine.c:310-322`),
  `lock_owner`, `lock_expiry`, extension count, and a `pre_lock_snapshot`
  for rollback. Lock state is runtime-only — it is *never serialized*
  (`data_model.h:126-131`); see the honesty section.
- An op names the items it touches: `Operation.addResource` (up to
  `CRABS_MAX_RESOURCES` = 8, `src/CRABS/crabs.h:19`; node wrapper
  `bindings/node/src/crabs_node.cc:638-679`). With each resource the op
  carries a `required_state`/`next_state` protocol pair — that pair is what
  lets the executor enforce timing, and (see the GAP blocks) it is the part
  JS cannot author.
- The executor's gates run in order *before any effect*: replay
  (signature, then per-signer ordering monotonicity,
  `src/StateMachine/state_machine.c:1248-1259`), required protocol state
  across **every** named resource
  (`_check_transitions`, `src/StateMachine/state_machine.c:845-857`,
  run at `:1260-1264`), presented lock claims
  (`:1266-1281`), dedup guard (`:1283+`), handler, and only then the
  wildcard apply — which for handler-less custom ops is restricted to
  LOCKED resources (`src/StateMachine/state_machine.c:1436-1464`). A gate
  that fails leaves *nothing*: no log entry, no version bump, no balance
  change (`test/test_state_machine.cpp:1153-1211`,
  `test/test_tx_manager.cpp:246-266`).
- The lock protocol is built-in op types — `__lock__`, `__extend__`,
  `__verify__`, `__rollback__`, `__unlock__`, `__force_unlock__`
  (`src/CRABS/crabs.h:135-140`) — moving the item through
  IDLE → LOCKED → MODIFIED → VERIFIED → IDLE
  (`src/StateMachine/state_machine.c:128-142`). A live lease refuses
  re-acquisition (`:1710`), expires on its own
  (`state_machine_lock_expired`, `:364-385`) and is pruned by the next
  execute (`:389-407`); a rollback is owner-checked
  (`:1890-1897`) and restores the pre-lock snapshot
  (`:1898-1917`), so a locked-and-reverted item hashes back to exactly what
  the lock captured.
- Replay protection is pluggable: a tx manager sits in front of the
  executor with `accept`/`commit`/`destroy`
  (`src/TxManager/tx_manager.h:19-41`) — memory-backed duplicates land as
  `CRABS_ERR_ALREADY_EXECUTED` (`src/CRABS/crabs.h:107`; wired and tested,
  `test/test_tx_manager.cpp:230-244`) — and even with *no* manager, the
  per-signer ordering backstop rejects a replayed op after a restart
  (`state_signer_has_replay`, `src/StateMachine/state_machine.c:585-611`,
  `test/test_tx_manager.cpp:268-291`).

This is the machine's contract. What surfaces can *drive* it is where this
recipe is PARTIAL: the pot minting and the lock drive work on crabs-node,
the full ceremony (claims, required states, extend/verify/rollback/unlock)
works only in C — the GAP blocks below are precise about each seam.

## What it guarantees / what it doesn't

Guaranteed, by the executor (all of it exercised by the snippets below):

- *Refused, not applied.* An op naming an un-locked RESOURCE is refused
  `protocol_violation` instead of half-applying; an op naming an unknown
  resource is refused `resource_not_found`. Preconditions run across every
  named resource before the handler, so one poisoned name voids the whole
  op with no partial apply (C snippet, Demo C;
  `test/test_state_machine.cpp:1153-1211`).
- *Apply at most once.* A committed op's uuid is recorded by the memory tx
  manager and a duplicate submission is `already_executed`
  (`test/test_tx_manager.cpp:230-244`); with no manager configured,
  ordering monotonicity still rejects a replayed op — the same signed op
  cannot land twice (`src/StateMachine/state_machine.c:585-611`,
  `:1248-1259`).
- *One live lease per pot.* A locked RESOURCE refuses acquisition until
  expiry (`state_machine.c:1710`); the lock token is a CSPRNG bearer
  credential (`:310-322`) and any claim an op presents on a
  locked/modified item is verified against it (`:1266-1281`), so a forged
  claim is `lock_token_mismatch`. A lock expires and is pruned; a rollback
  puts back the exact pre-lock balance.

Not guaranteed — say this before building on it:

- *The lock is machine-local, not a distributed lease.* Lock state is
  runtime-only and never serialized (`src/CRABS/data_model.h:126-131`,
  `:749`); two replicas do not negotiate a shared lease. The lock protocol
  coordinates *one machine's* operators — e.g. a validator process holding
  the treasury — while replica convergence is still CRDT merge after the
  fact. There is no cross-replica atomic commit here.
- *Claim discipline is cooperative at the op level.* The executor verifies
  the claims an op presents (`:1266-1281`) and refuses custom ops on a
  non-LOCKED resource (`:1440-1452`) — but the wildcard apply does not
  force a claim to be present, and a custom op with a registered handler
  owns its own protocol transitions entirely (`:1419-1433`). "Every treasury
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
  268-291`).
- *No JavaScript completion of the ceremony.* See the GAP blocks: claims,
  required-state authors, and the tx manager have no binding surface.

## Variations

- *Cross-item atomicity*: one op may name up to 8 resources
  (`src/CRABS/crabs.h:19`), and preconditions are checked across all of
  them before anything moves — that is the closest thing to a
  multi-item transaction here (`test/test_state_machine.cpp:1153-1211`).
- *Recovery instead of undo*: `__verify__` promotes MODIFIED → VERIFIED or
  drops the item to ERROR on a failed invariant
  (`state_machine.c:1858-1880`); `__rollback__` takes either MODIFIED or
  ERROR back to IDLE with the snapshot restored (`:1882-1920`).
- *Break-glass unblocking*: `__force_unlock__` releases an *expired but
  not-yet-pruned* lock to IDLE — it is not a lock steal: a live lease is
  refused with `CRABS_ERR_LOCK_NOT_EXPIRED` (`state_machine.c:1958-1970`,
  error at `src/CRABS/crabs.h:72`), and the whole op is refused with
  `force_unlock_disabled` unless `config.allow_force_unlock` is set
  (`src/CRABS/data_model.h:283`; typed string
  `bindings/node/src/crabs_node.cc:92`).
- *Vote-then-spend treasuries* compose Recipe 2's one-shot vote records
  with this item: the vote gate is the caller's, the spend serialization
  is this page's.
- *If you need "never twice" but not exclusivity*: Recipe 3's dedup guard
  is the lighter mechanism — a lock buys serialization you may not need.

## Recipe

### crabs-wasm (browser / Node / edge)

No full treasury demo exists on the wasm binding: the op half is real, the
item mint and the lock surface are not.

> [!WARNING] GAP
>
> **Prose describes:** the whole demo on crabs-wasm — minting a treasury
> pot in the browser, locking it, submitting a transfer with a lock claim,
> and seeing replay/precondition refusals.
>
> **Codebase status:** half of the seam exists on wasm. `Operation.
> addResource` is STABLE (`bindings/wasm/index.d.ts:33`, wrapper
> `bindings/wasm/bindings-core.js:352-358`) and the executor-side gates are
> the same C pipeline (`src/StateMachine/state_machine.c:1260-1281`) — but
> `Node.addResource`, the item mint (`DATA_TYPE_RESOURCE`), is **node-only**
> (`bindings/node/index.d.ts:199`, implemented
> `bindings/node/src/crabs_node.cc:1489-1513`); wasm declares no mint for
> a RESOURCE item, and no wasm surface sets required states or lock claims.
>
> **Divergence:** an op carrying a resource name on wasm either names an
> item that does not exist (`resource_not_found`) or — because `__lock__`
> also requires the item to exist and be IDLE — no lock can ever be taken
> on a pot wasm never minted. The recipe's demo needs `Node.addResource`;
> api-map §17 records the split: "Resources half is STABLE JS … Locks /
> transaction manager are **not JS-bound**" under R9's node-only note.
>
> **Tracking:** api-map §17, R9 (resources STABLE on node; locks/tx manager
> DESIGNED C-only). No wasm-side mint or lock build is scheduled.
>
> **Agent action:** code block omitted. Do not call
> `node.addResource('treasury')` on crabs-wasm — the wasm `Node` declares
> no such method. Drive the pot from crabs-node or from the C surface
> (below), and treat wasm as the reader half only.

### crabs-node (native Node.js)

The pot mint, the lock drive, and the executor's refusals are all real on
this binding — and one honest limit is demonstrated right in the snippet:
once the pot is locked, the op builder cannot author `required_state` or a
lock claim, so the locked pot is not spendable from JS at all.

```snippet:node/09-treasury.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  NodeStatic.new            bindings/node/index.d.ts:312
  KeyPair.generate          bindings/node/index.d.ts:14
  registerUser              bindings/node/index.d.ts:182
  grantRole                 bindings/node/index.d.ts:183
  Node.addResource          bindings/node/index.d.ts:199
  new Operation             bindings/node/index.d.ts:47
  Operation.addResource     bindings/node/index.d.ts:26
  Node.setPolicy            bindings/node/index.d.ts:249
  Node.sign                 bindings/node/index.d.ts:250
  Node.execute              bindings/node/index.d.ts:251
  Node.addCounter           bindings/node/index.d.ts:193
  (lock protocol op types)  src/CRABS/crabs.h:135-140
  (refusal: un-locked RESOURCE op) src/StateMachine/state_machine.c:1440-1452
  (refusal: re-acquire live lease) src/StateMachine/state_machine.c:1710
  (replay backstop)         src/StateMachine/state_machine.c:585-611
maturity: mint/drive/gates STABLE; claim + required-state authoring not bound
test_ref: bindings/node/test/test.js:36 (typed execute refusals) + test/test_tx_manager.cpp:230-291
-->

What the snippet could not do, and the machine cannot help with from this
binding — the ceremony tail:

> [!WARNING] GAP
>
> **Prose describes:** the part of the treasury protocol that makes the
> locked pot *useful* — carrying the live lock token as a claim into the
> transfer op, declaring `required_state: LOCKED` so the executor verifies
> the transfer ran under the lease, and driving `__verify__`/`__rollback__`/
> `__unlock__` (or the admin `__force_unlock__` escape) to completion.
>
> **Codebase status:** all of it works in C — claims are step 5 of the
> executor (`src/StateMachine/state_machine.c:1266-1281`), the required-
> state gate is step 4 (`:1260-1264`, helper `:845-857`), and the full
> lock-modify-verify-unlock ceremony is proven
> (`test/test_state_machine.cpp:196-352`). The executor is reached exactly
> as-is from the node binding (`bindings/node/src/crabs_node.cc:1774`).
>
> **Divergence:** no node symbol authors any of it.
> `bindings/node/index.d.ts` has no required-state setter, no lock-claim
> setter (`Operation.addResource` hard-codes both per-slot to
> `PROTOCOL_IDLE`, `bindings/node/src/crabs_node.cc:669-670`), and no claim-bearing op API —
> so from JS, a locked pot cannot be extended, verified, rolled back, or
> unlocked (each needs a `required_state` the op builder can't declare);
> it sits locked until the lease expires and the next execute prunes it
> (`state_machine.c:364-407`). The C tx manager
> (`src/TxManager/tx_manager.h:19-41`, memory impl
> `src/TxManager/tx_manager_memory.h:16`) is likewise not wired to any
> binding state — `state->tx_manager` (`src/CRABS/data_model.h:486`) is
> never assigned anywhere in `bindings/node/src/crabs_node.cc` (grep: zero
> matches), so the JS executor runs with no manager and relies on the
> ordering backstop.
>
> **Tracking:** api-map §17, R9 — "no lock API surface found in C headers
> or bindings"; map entries for locks marked DESIGNED. No binding work is
> scheduled.
>
> **Agent action:** the code block above is what exists — the pot, the
> gates, the lease, the replay backstop. For the ceremonial claims, do not
> invent `op.setRequiredState(...)`/`op.claim('treasury', token)`; drive
> the full protocol from C (next section) or design the binding surface
> first.

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
  state_machine_execute        src/StateMachine/state_machine.h
  state_machine_register_handler src/StateMachine/state_machine.c:500-524
  CRABS_OP_LOCK/VERIFY/UNLOCK  src/CRABS/crabs.h:135-139
  __lock__ contention refusal  src/StateMachine/state_machine.c:1710-1716
  lock token generation        src/StateMachine/state_machine.c:310-326
  expiry + pruning             src/StateMachine/state_machine.c:364-407
  wildcard apply gate          src/StateMachine/state_machine.c:1436-1464
  required-state check         src/StateMachine/state_machine.c:845-857
  rollback (owner check + snapshot restore) src/StateMachine/state_machine.c:1885-1917
  crabs_tx_manager_memory      src/TxManager/tx_manager_memory.h:16
  CRABS_ERR_ALREADY_EXECUTED   src/CRABS/crabs.h:107
  CRABS_ERR_LOCK_TOKEN_MISMATCH src/CRABS/crabs.h:69
  data_item_create / state_add_item src/CRABS/data_model.h
maturity: all STABLE (executor + lock protocol + tx manager, tested)
test_ref: test/test_state_machine.cpp:196-352 (lock ceremony) + :1153-1211 (atomic across resources) + test/test_tx_manager.cpp:230-244 (duplicate refused) + :268-291 (lamport backstop)
-->

## Notes

- *Where the "atomic" in this recipe's title actually lives.* Three
  different guarantees get called atomicity; the machine delivers all
  three, at different layers: (1) all-or-nothing *preconditions* — the
  executor checks every named resource before the handler runs and a
  failure leaves no log entry, no version bump, and no balance change
  (`test/test_state_machine.cpp:1153-1211`); (2) *apply-once* — duplicate
  submissions are recorded and refused (`test/test_tx_manager.cpp:
  230-244`), with the ordering backstop covering the post-restart window
  (`:268-291`); (3) *recovery* — a locked item snapshots its balance at
  acquisition and rollback restores exactly those bytes (`state_machine.c:
  1885-1917`), which is why the demo's treasury can end where it started.
- *Why the node binding refuses an un-locked spend at all*: crabs-node has
  no custom-handler surface (api-map §15 known difference #2), so
  handler-less custom ops go through the wildcard apply — and that path
  only acts on LOCKED resources (`state_machine.c:1440-1452`). The
  refusal is the gate, not a bug.
- *The lock is a lease, not an ownership transfer*: it has an expiry
  (`max_lock_duration_ms` per extension, `src/CRABS/data_model.h:281`) and
  re-acquisition stays refused while it is live regardless of who calls
  (`state_machine.c:1710-1716`) — the snippet's second `__lock__` from the
  same treasurer is refused exactly as a rival's would be.
- *Balance values on RESOURCE items are raw int64s* (`bindings/node/src/
  crabs_node.cc:1501-1510` — "the library contract — dedup mutations, the
  lock snapshot, and destroy all take the raw path"), which is why the
  lock snapshot captures 8 bytes for this item (`state_machine.c:1797-1806`)
  and the restore is the historical 8-byte form (`:1913-1920`).
- *Serialization check*: after a rollback, the content-only digest of a
  locked item hashes back to what the lock captured
  (`state_machine.c:1777-1779`) — the pre-lock snapshot is the recovery
  contract, not a courtesy.
- Related-but-different: sovereign write domains (Recipe 10) make a
  *leader's writes* verifiable and fork-detectable; they do nothing about
  concurrency on a shared balance. A deployment that wants both layers
  (single-writer accountability + item locking) composes them.