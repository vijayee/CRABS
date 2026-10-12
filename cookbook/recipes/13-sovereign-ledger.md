---
number: 13
slug: sovereign-ledger
title: A personal ledger no one can override
section: Composition
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
---
## Intent

A member keeps a *personal* ledger — a running balance, a private tally of
contributions — on a machine administered by someone else. The requirement
has a sharp edge the shared counters of Recipe 1 don't have:

- the ledger's *writer set is one person*: no other member — and not the
  machine's own admin — can add, amend, or rollback an entry;
- the writer's own entries are *ordered and tamper-evident*: each entry
  claims a position in a hash chain, and the engine refuses claims that
  don't extend the chain — a replay, or an attempt to claim the same
  position with different content;
- two members' ledgers on the same machine are independent: converging
  replicas merge each item's chain by its own rules, and nothing about
  bob's ledger is entangled with alice's.

## The naive version, and where it breaks

The naive version keeps each member's balance in an ordinary free-merge
item — a counter with a policy. A policy answers "may this signer run this
op type"; it cannot bind a *chain* of writes to one member's item, so the
balance is a merge race that any authorized member's increment enters. The
admin variant is subtler and worse: "only the admin edits balances on
behalf of members" — the machine's own authority, applied to everyone's
ledger. Now the admin is a single point of override (the one thing this
recipe forbids), the ledger's integrity story is "trust the operators,"
every audit is an audit of the admin, and there is no cryptographic chain
for a *member* to wave back — the member's own account history is only as
trustworthy as the operator's diligence.

The interesting gap between those two naive shapes is exactly the space a
sovereign item fills: writer-exclusive enforcement that is *stronger* than
policy (it binds the writer at the item, even when the policy would pass)
plus a signed, engine-enforced hash chain the item maintains itself.

## The shape

- *The mint*: each member's ledger is an item created with an explicit
  write domain and a fixed writer —
  `defineItem('ledger-alice', 'register', 'lww_reg', { domain: 'sovereign',
  writer: 'alice' })`. The domain is declared at mint and immutable on a
  live item; sovereign requires the writer (and forbids it elsewhere); the
  v1 legal shapes are counter and register (a register is what a
  *balance* wants — entries can subtract; an accumulate-only G-counter
  ledger is deposits-only), and every refusal is typed
  (`bindings/wasm/index.d.ts:235-236` + options `:181-188`,
  `bindings/node/index.d.ts:205-206` + `:122-130`; C creation rules
  `src/CRABS/data_model.h:645-660`).
- *The entry*: a custom op naming the ledger as its resource, carrying a
  **signed chain prefix** set before signing —
  `setSovereignPrefix(0, seq, digestHex)` — claiming the item's live chain
  head; the signing canonical form (v4) binds the prefix
  (`bindings/wasm/index.d.ts:40-41`, `bindings/node/index.d.ts:33`; C op
  fields `src/StateMachine/state_machine.h:110-120`, signed form wired at
  `src/Serialization/serialization.c:2908-2921`).
- *The gate*: DOMAIN_CHECK runs after authorization and before the handler
  (`src/StateMachine/state_machine.c:1047`): the writer is bound
  (`not_item_writer`, `:1096` — including the machine's genesis admin, the
  C snippet's admin-op case), a quarantined writer is refused
  (`quarantined`, `:1090`), the seq must equal the item's live head
  (`seq_mismatch`, `:1101`), and the same seq with a different digest is a
  fork refusal (`fork_detected`, `:1109`) before any mutation. On success
  the chain advances itself: seq +1 and a SHA-256 digest over the item's
  post-op content-only form
  (`_apply_sovereign_bookkeeping`, `src/StateMachine/state_machine.c:1142-1174`,
  driven at `:1471-1476`).
- *The public read*: `itemChainHead(name)` returns the live
  `{seq, digestHex}` to anyone — writer and auditor alike author their next
  prefix from it (`bindings/wasm/index.d.ts:244`,
  `bindings/node/index.d.ts:213`).
- *The accountability*: since each ledger is one item with one writer, all
  of Recipe 10's fork machinery applies — `reportEquivocation(item, opA,
  opB)` verifies two distinct writer-signed claims of the same head and
  quarantines the writer *on that item*, and false evidence is typed and
  inert (`state_machine.c:2562-2600`, handler `:2806`; evidence cap
  `src/CRABS/crabs.h:41,44`).

This recipe is COMPLETE: every claim below is executed by a snippet — on
wasm, node, and C.

## What it guarantees / what it doesn't

Guaranteed (everything below is executed by the snippets):

- *No one's override reaches another member's ledger.* Bob's and the admin's
  signed entry attempts on alice's ledger refuse `not_item_writer` even
  though the shared policy authorizes the op type for both
  (wasm + node + C snippets; `src/StateMachine/state_machine.c:1095-1097` —
  the writer check precedes the seq check, so a foreign writer learns
  nothing about the chain state).
- *Each ledger is one hash chain, engine-advanced.* Every accepted entry
  claimed the live `(seq, digest)` and moved the head; a replayed claim is
  `seq_mismatch`, the same seq with a foreign digest is `fork_detected` at
  the gate (both snippets + the C battery), and nothing partial applies.
- *Real content is covered by the chain.* The wasm and C demos register a
  handler that applies the entry's amount to the member's balance; the
  post-op digest is recomputed over that content, so the chain's head proves
  the *balance history*, not just the fact of writes
  (`src/StateMachine/state_machine.c:1121-1139` — the digest preimage
  deliberately excludes item_seq so no-op entries move a content-digest).
- *Forks are actionable.* Two distinct alice-signed claims to the same head
  are evidence; the report verifies and quarantines her on
  `ledger-alice` only — bob's ledger is untouched (wasm snippet's report +
  typed-failure battery). Chains and quarantine are per item.

Not guaranteed — the honesty behind "no one can override":

- *The ledger is tamper-evident, not tamper-proof-in-flight.* The gate
  refuses a forked claim — that is, no replica ever APPLIES both sides of a
  collision — but detection of a writer who signed two competing entries
  against *different replicas* requires evidence reaching a report: unless
  someone collects both payloads and files `reportEquivocation`, the
  conviction never happens. "No one can override" = no one can *apply* an
  override and no honest replica merges one; it does not mean the engine
  convicts by itself.
- *Replica convergence is not demoed here — deliberately.* Neither JS
  binding can load machine state (there is no `Node.deserialize`), so the
  snippets run one machine. The machinery that converges is the C engine's:
  sovereign items serialize with their chain head from wire version 14
  onward and the fork-writer set merges union-only
  (`src/CRABS/data_model.h:181-191`); Recipe 10's sovereign surface is the
  same engine.
- *The writer is fixed at mint.* A lost writer key means the ledger stops
  (the chain refuses everyone else by design); "changing the lead" means
  re-minting a new item under a new writer and importing, not editing the
  existing one — nothing in v1 replaces a writer on a live item.
- *The chain records THIS item only.* A member's cross-item story (ledger +
  profile + another ledger) has no machine-enforced total order — v1 ships
  no GROUP-ORDERED ordering modules (Recipe 14); ordering across a member's
  items is a protocol-author problem.

## Variations

- *Accumulate-only ledger*: a sovereign G-counter (`'counter'`,
  `'g_counter'`) accepts deposits-only: the C snippet's ledger handler feeds
  `g_counter_increment` (`src/CRDT/crdt_merge.h`), and negative deltas
  refuse. Balances that need withdrawals use the register shape as in the
  wasm snippet.
- *Ledgers inside subgroups*: a Blueprint may declare sovereign items in the
  charter — `blueprint_add_item_with_domain(..., CRABS_DOMAIN_SOVEREIGN,
  writer, 0)` lands the named writer and empty chain on the spawned child
  (`src/Lineage/lineage.h:147-153`;
  `test/test_lineage.cpp:1665-1712` — the spawn applies the domain and
  pre-first-op `item_seq == 0`). Recipe 11's machines + this recipe's
  domains compose: a subgroup's members keep ledgers its parent cannot touch.
- *Watch the ledger*: `on('change')` fires per entry — a UI can render the
  balance from the change stream without polling.
- *Equivocation caps*: fork evidence per item is capped
  (`CRABS_MAX_FORK_WRITERS = 16`, `src/CRABS/crabs.h:44`) and merges
  union-only, so a quarantined writer stays quarantined across convergence.

## Recipe

### crabs-wasm (browser / Node / edge)

Two members, two sovereign registers as personal ledgers, a handler applying
entries (deposits AND withdrawals) so the hash chain covers live balances,
then the refusal battery — admin and member refusals, replayed and
fork-claimed prefixes — plus the report/quarantine accountability loop, with
typed failures asserted.

```snippet:wasm/13-sovereign-ledger.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:372
  KeyPair.generate          bindings/wasm/index.d.ts:21
  registerUser/grantRole    bindings/wasm/index.d.ts:213-214
  Node.defineItem           bindings/wasm/index.d.ts:235-236
  DefineItemOptions         bindings/wasm/index.d.ts:181-188
  Node.setPolicy            bindings/wasm/index.d.ts:295
  Node.registerHandlerJs    bindings/wasm/index.d.ts:303
  HandlerState.getRegister/setRegister bindings/wasm/index.d.ts:120,112
  HandlerOperation.payload  bindings/wasm/index.d.ts:143-148
  Operation.setSovereignPrefix bindings/wasm/index.d.ts:40-41
  Node.sign/execute         bindings/wasm/index.d.ts:297,296
  Node.itemChainHead        bindings/wasm/index.d.ts:244
  Node.reportEquivocation   bindings/wasm/index.d.ts:251-252
  (DOMAIN_CHECK)            src/StateMachine/state_machine.c:1047-1129
  (chain advance)           src/StateMachine/state_machine.c:1142-1174
  (handler payload must be NUL-terminated) src/Util/wasm_helpers.c:1071-1080
maturity: all STABLE
test_ref: bindings/wasm/test/write-domains.js:12-149 + handlers per bindings/wasm/test/smoke.js:59-63 + registers per bindings/wasm/test/registers.js:83-100
-->

### crabs-node (native Node.js)

The same per-user ledgers and refusals on the native binding. The honest
difference (api-map §8 known difference #2): the node binding has no custom
handlers, so these entries advance the chain and live in the machine's op
log without mutating the balance in-process — the guarantees shown are the
writer-bound chain, the refusals, and the head reads.

```snippet:node/13-sovereign-ledger.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  NodeStatic.new            bindings/node/index.d.ts:312
  KeyPair.generate          bindings/node/index.d.ts:14
  registerUser/grantRole    bindings/node/index.d.ts:182-183
  Node.defineItem           bindings/node/index.d.ts:205-206
  Node.setPolicy            bindings/node/index.d.ts:249
  new Operation             bindings/node/index.d.ts:47
  Operation.setSovereignPrefix bindings/node/index.d.ts:33
  Node.sign/execute         bindings/node/index.d.ts:250,251
  Node.itemChainHead        bindings/node/index.d.ts:213
  (DOMAIN_CHECK)            src/StateMachine/state_machine.c:1047-1129
maturity: all STABLE
test_ref: bindings/node/test/test.js:385-540 (sovereign: chained writes, refusals, fork report)
-->

### C (native)

The engine in the raw: sovereign G-counter ledgers built through the tested
creation route (`data_item_create_with_options` + `state_add_item`), a
deposit handler, signed prefixes, and the full refusal battery — a member's
foreign-ledger op, the machine's own genesis-admin op
(`not_item_writer`), a replayed prefix (`seq_mismatch`), a same-seq
different-digest claim (`fork_detected`), each verified to move no chain.

```snippet:c/13-sovereign-ledger.c
```

<!-- PROVENANCE
target: native-c
verified: executed
symbols:
  data_item_create_with_options  src/CRABS/data_model.h:652-657
  state_add_item                 src/CRABS/data_model.h:719
  g_counter_increment/value      src/CRDT/crdt_merge.h
  operation_create               src/StateMachine/state_machine.h:243
  (sovereign prefix in signed form) src/Serialization/serialization.c:2908-2921
  (DOMAIN_CHECK + refusals)      src/StateMachine/state_machine.c:1090-1109
  (chain advance)                src/StateMachine/state_machine.c:1142-1174
maturity: all exercised by C tests
test_ref: test/test_state_machine.cpp:1238-1430 (handler-driven sovereign counters + refusal battery)
-->

## Notes

- *Why the register (not the counter) is the ledger's default shape here*:
  v1's sovereign-legal types are counters and registers; a G-counter can
  only grow (deposit-only), while a register holds the balance as a
  first-class int64 and lets the writer's signed entries carry withdrawals.
  The chain's digest covers either form content-only
  (`state_item_digest_compute`, `src/CRABS/data_model.h:752`).
- *The prefix is signed, and the order of enforcement matters for what an
  attacker learns*: quarantine → writer → seq → digest
  (`src/StateMachine/state_machine.c:1090-1109`). A foreign writer is
  refused before any chain-state information leaks; an out-of-order claim
  from THE writer reads as `seq_mismatch`, not as a fork.
- *The wasm handler payload contract*: `HandlerOperation.payload` reaches
  JS only when the op's payload is NUL-terminated
  (`crabs_wasm_handler_op_get_payload_str`,
  `src/Util/wasm_helpers.c:1071-1080`) — the snippet terminates the amount
  it encodes. Without the terminator the handler sees an empty payload.
- *Where the "no one" in the title is literally enforced*: the machine's own
  genesis admin is a user like any other at the item — role:admin
  authorizes nothing at the item (`src/StateMachine/state_machine.c:1095-1097`
  compares the signer against the item's `writer` field, not against roles).
  The one capability the admin DOES keep: minting the ledger in the first
  place (`defineItem` is a machine action) — and, with Recipe 11, the
  subgroup's charter is the place to pre-agree whose ledgers exist.
- *Recipe 10 is the deep dive on the accountability machinery* (prefixes,
  equivocation, quarantine): this page composes that surface into a
  per-member, multi-item configuration and focuses on the
  no-override property; the mechanics beneath are identical and cited
  there.