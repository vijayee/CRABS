---
number: 13
slug: sovereign-ledger
title: A personal ledger no one can override
section: Composition
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
teaches: append-only personal ledgers no admin can rewrite
---
## The problem

Alice keeps a contribution tally on a machine administered by someone else —
47 entries, one per shift, and the running balance is what she trades on.
The host is competent and cooperative; that is exactly why the demand is
sharp: she is not asking for better operators, she is asking that the
operator's *authority* stop at her ledger. No other member — and not the
machine's own admin — can add an entry, amend one, or roll hers back. Her
own entries stay ordered, so a replayed or rearranged entry can't sneak
in. And bob's ledger, kept on the same machine, is independent of hers —
converging replicas merge each item's chain by its own rules.

She is also *not* asking for secrecy. The tally's value being readable is
fine; the thing that must be impossible is an override that sticks.

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

## The idea

*Prevention* is the wrong frame for tamper resistance — any machine that
can write can also rewrite. What an append-only structure buys is
**evidence**: a rewrite ceases to be silent, because the structure makes
the legitimate history verifiable and competing histories impossible to
both be. Three mechanisms do the work:

- **Position.** Each entry claims a sequence number — the *next* slot in
  the chain, not "somewhere". An engine that accepts an entry only at the
  live head makes reordering and replay structurally inapplicable: a claim
  at any other position is refused, not reconciled.
- **Content coverage.** The chain digest covers the item's content — the
  *values*, not the fact that writes happened. So the chain is a promise
  about the balance history itself, not a write count.
- **Conflict as evidence.** One writer claiming the same position with two
  different contents — equivocation — is the one fault a chain cannot
  silently contain; competing claims at one position are mechanically
  detectable and collectable. If the surrounding machinery both detects the
  collision and lets the group act on collected evidence, "no one can
  override" becomes enforceable rather than aspirational.

Read that list as the honest boundary too: the chain makes tampering
*visible*, and enforcement (a conviction) happens when collected evidence
meets an act, not the instant the fork exists. Tamper-evident, actionable
on evidence — that is the property a ledger on someone else's machine can
actually have.

## How CRABS encodes it

- *The mint*: each member's ledger is an item created with an explicit
  write domain and a fixed writer — `defineItem('ledger-alice', 'register',
  'lww_reg', { domain: 'sovereign', writer: 'alice' })`. The domain is
  declared at mint and immutable on a live item; sovereign requires the
  writer (and forbids it elsewhere); the v1 legal shapes are counter and
  register (a register is what a *balance* wants — entries can subtract; an
  accumulate-only G-counter ledger is deposits-only), and every refusal is
  typed.
- *The entry*: a custom op naming the ledger as its resource, carrying a
  **signed chain prefix** set before signing —
  `setSovereignPrefix(0, seq, digestHex)` — claiming the item's live chain
  head; the signing canonical form (v4) binds the prefix (op format v6).
- *The gate*: DOMAIN_CHECK runs after authorization and before the handler:
  the writer is bound (`not_item_writer` — including the machine's genesis
  admin, the C snippet's admin-op case), a quarantined writer is refused
  (`quarantined`), the seq must equal the item's live head
  (`seq_mismatch`), and the same seq with a different digest is a fork
  refusal (`fork_detected`) before any mutation. On success the chain
  advances itself: seq +1 and a SHA-256 digest over the item's post-op
  content-only form.
- *The public read*: `itemChainHead(name)` returns the live
  `{seq, digestHex}` to anyone — writer and auditor alike author their next
  prefix from it.
- *The accountability*: since each ledger is one item with one writer, all
  of Recipe 10's fork machinery applies — `reportEquivocation(item, opA,
  opB)` verifies two distinct writer-signed claims of the same head and
  quarantines the writer *on that item*, and false evidence is typed and
  inert.

## Try it

### crabs-wasm (browser / Node / edge)

Two members, two sovereign registers as personal ledgers, a handler applying
entries (deposits AND withdrawals) so the hash chain covers live balances,
then the refusal battery — admin and member refusals, replayed and
fork-claimed prefixes — plus the report/quarantine accountability loop, with
typed failures asserted.

```snippet:wasm/13-sovereign-ledger.js
```

### crabs-node (native Node.js)

The same per-user ledgers and refusals on the native binding. The honest
difference (api-map known difference #2): the node binding has no custom
handlers, so these entries advance the chain and live in the machine's op
log without mutating the balance in-process — the guarantees shown are the
writer-bound chain, the refusals, and the head reads.

```snippet:node/13-sovereign-ledger.js
```

### C (native)

The engine in the raw: sovereign G-counter ledgers built through the tested
creation route (`data_item_create_with_options` + `state_add_item`), a
deposit handler, signed prefixes, and the full refusal battery — a member's
foreign-ledger op, the machine's own genesis-admin op
(`not_item_writer`), a replayed prefix (`seq_mismatch`), a same-seq
different-digest claim (`fork_detected`), each verified to move no chain.

```snippet:c/13-sovereign-ledger.c
```

## What it guarantees / what it doesn't

Guaranteed (everything below is executed by the snippets):

- *No one's override reaches another member's ledger.* Bob's and the
  admin's signed entry attempts on alice's ledger refuse
  `not_item_writer` even though the shared policy authorizes the op type
  for both.
- *Each ledger is one hash chain, engine-advanced.* Every accepted entry
  claimed the live `(seq, digest)` and moved the head; a replayed claim is
  `seq_mismatch`, a same-seq foreign-digest claim is `fork_detected`, both
  before any mutation, and nothing partial applies.
- *Real content is covered by the chain.* The wasm and C demos register a
  handler that applies the entry's amount to the member's balance; the
  post-op digest is recomputed over that content, so the chain's head
  proves the *balance history*, not just the fact of writes.
- *Forks are actionable.* Two distinct alice-signed claims to the same head
  are evidence; the report verifies and quarantines her on `ledger-alice`
  only — bob's ledger is untouched. Chains and quarantine are per item.

Not guaranteed — the honest reading of "no one can override":

- *Tamper-evident, not tamper-proof-in-flight.* The gate refuses a forked
  claim — no replica ever APPLIES both sides of a collision — but detection
  of a writer who signed two competing entries against *different replicas*
  requires evidence reaching a report: unless someone collects both
  payloads and files `reportEquivocation`, the conviction never happens.
  "No one can override" = no one can *apply* an override and no honest
  replica merges one; it does not mean the engine convicts by itself.
- *Replica convergence is not demoed here — deliberately.* Neither JS
  binding can load machine state (there is no `Node.deserialize`), so the
  snippets run one machine. The machinery that converges is the C engine's:
  sovereign items serialize with their chain head from wire version 14
  onward and the fork-writer set merges union-only; Recipe 10's sovereign
  surface is the same engine.
- *The writer is fixed at mint.* A lost writer key means the ledger stops
  (the chain refuses everyone else by design); "changing the lead" means
  re-minting a new item under a new writer and importing, not editing the
  existing one — nothing in v1 replaces a writer on a live item.
- *The chain records THIS item only.* A member's cross-item story (ledger +
  profile + another ledger) has no machine-enforced total order (Recipe 14
  is the group-ordered answer); ordering across a member's items is a
  protocol-author problem.

## Variations

- *Accumulate-only ledger*: for balances that only ever grow, a sovereign
  G-counter accepts deposits-only — the C snippet's ledger handler feeds
  `g_counter_increment`, and negative deltas refuse. Balances that need
  withdrawals use the register shape as in the wasm snippet.
- *Ledgers inside subgroups*: when the machine keeping ledgers is itself a
  subgroup, a Blueprint may declare sovereign items in the charter —
  `blueprint_add_item_with_domain(..., CRABS_DOMAIN_SOVEREIGN, writer, 0)`
  lands the named writer and empty chain on the spawned child. Recipe 11's
  machines + this recipe's domains compose: a subgroup's members keep
  ledgers its parent cannot touch.
- *Watch the ledger*: to render the balance from the change stream instead
  of polling, `on('change')` fires per entry.
- *Equivocation caps*: where many misbehaving writers are expected, fork
  evidence per item is capped (`CRABS_MAX_FORK_WRITERS = 16`) and merges
  union-only, so a quarantined writer stays quarantined across convergence.

## Verified against the code

<!-- PROVENANCE
target: all-bindings
mint + typing:
  defineItem sovereign rules — wasm bindings/wasm/index.d.ts:535-536 +
  DefineItemOptions :308-316, node :363-364 + :214-221; domain immutable on
  a live item; sovereign requires writer, forbidden elsewhere; typed
  refusals (sovereign-without-writer, writer-on-free, unknown domain,
  non-legal type); v1 legal shapes counter + register
  (bindings/wasm/test/write-domains.js:28-31 scope comment); C creation
  rules src/CRABS/data_model.h:645-660 (data_item_create_with_options
  :652-657, state_add_item :719)
entry + chain:
  Operation.setSovereignPrefix — wasm bindings/wasm/index.d.ts:75 (digest
  64 hex chars or 32 raw bytes; seq number|bigint), node :90 (number only);
  C op fields src/StateMachine/state_machine.h:110-120; signed form wired
  src/Serialization/serialization.c:3680-3693 (crabs_serialize_for_signing)
gate (DOMAIN_CHECK, after authorization, before the handler):
  src/StateMachine/state_machine.c:1047-1129; ordering of refusal matters:
  quarantine → writer → seq → digest :1090-1109 (a foreign writer is
  refused before any chain-state information leaks; an out-of-order claim
  from THE writer reads as seq_mismatch, not a fork); writer check
  :1095-1097 compares the signer against the item's `writer` field
  (data_model.h:169), not roles — role:admin authorizes nothing at the
  item; quarantined :1090 (CRABS_ERR_QUARANTINED); seq :1101
  (CRABS_ERR_SEQ_MISMATCH); fork :1109 (CRABS_ERR_FORK_DETECTED)
chain advance: _apply_sovereign_bookkeeping src/StateMachine/state_machine.c:1142-1174,
  driven at :1471-1476; digest = state_item_digest_compute over the
  content-only preimage (src/CRABS/data_model.h:752-756; the preimage
  deliberately excludes item_seq — a no-op entry moves a content-digest
  anyway, fixture note test/test_state_machine.cpp:1244-1247)
public read: itemChainHead wasm :544 / node :371
accountability: reportEquivocation (wasm :551-552, node :379) →
  __report_equivocation__; behavior state_machine.c:2562-2600 + handler
  :2806; evidence cap CRABS_MAX_FORK_WRITERS = 16 src/CRABS/crabs.h:41,44;
  per-item fork set, union-only merge, serialized from wire v14
  src/CRABS/data_model.h:181-195
convergence residual: neither JS binding has Node.deserialize — snippets
  run one machine; sovereign serialization from wire v14 onward
  (data_model.h:181-191)

target: crabs-wasm (snippet wasm/13-sovereign-ledger.js)
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:774
  KeyPair.generate          bindings/wasm/index.d.ts:44
  registerUser/grantRole    bindings/wasm/index.d.ts:480-481
  Node.defineItem           bindings/wasm/index.d.ts:535-536
  DefineItemOptions         bindings/wasm/index.d.ts:308-316
  Node.setPolicy            bindings/wasm/index.d.ts:638
  Node.registerHandlerJs    bindings/wasm/index.d.ts:683
  HandlerState.getRegister/setRegister bindings/wasm/index.d.ts:220 / :204
  HandlerOperation.payload  bindings/wasm/index.d.ts:265-279 (payload :269)
  Operation.setSovereignPrefix bindings/wasm/index.d.ts:75
  Node.sign/execute         bindings/wasm/index.d.ts:657 / :656
  Node.itemChainHead        bindings/wasm/index.d.ts:544
  Node.reportEquivocation   bindings/wasm/index.d.ts:551-552
  (DOMAIN_CHECK)            src/StateMachine/state_machine.c:1047-1129
  (chain advance)           src/StateMachine/state_machine.c:1142-1174
  (handler payload must be NUL-terminated) src/Util/wasm_helpers.c:1195-1201
maturity: all STABLE
test_ref: bindings/wasm/test/write-domains.js:12-149 + handlers per
  bindings/wasm/test/smoke.js:59-63 + registers per
  bindings/wasm/test/registers.js:83-100
wasm handler payload contract: HandlerOperation.payload reaches JS only
  when the op's payload is NUL-terminated (crabs_wasm_handler_op_get_payload_str,
  src/Util/wasm_helpers.c:1195-1201) — the snippet terminates the amount it
  encodes; without the terminator the handler sees an empty payload

target: crabs-node (snippet node/13-sovereign-ledger.js)
verified: executed
symbols:
  NodeStatic.new            bindings/node/index.d.ts:641-643
  KeyPair.generate          bindings/node/index.d.ts:71
  registerUser/grantRole    bindings/node/index.d.ts:304-305
  Node.defineItem           bindings/node/index.d.ts:363-364
  Node.setPolicy            bindings/node/index.d.ts:450
  new Operation             bindings/node/index.d.ts:138-140
  Operation.setSovereignPrefix bindings/node/index.d.ts:90
  Node.sign/execute         bindings/node/index.d.ts:463 / :464
  Node.itemChainHead        bindings/node/index.d.ts:371
  (DOMAIN_CHECK)            src/StateMachine/state_machine.c:1047-1129
maturity: all STABLE (no handler surface — entries advance the chain and
  live in the op log without mutating the balance in-process, api-map
  known difference #2; the guarantees shown are the writer-bound chain, the
  refusals, and the head reads)
test_ref: bindings/node/test/test.js:385-540 (sovereign: chained writes,
  refusals, fork report)

target: native-c (snippet c/13-sovereign-ledger.c)
verified: executed
symbols:
  data_item_create_with_options  src/CRABS/data_model.h:652-657
  state_add_item                 src/CRABS/data_model.h:719
  g_counter_increment/value      src/CRDT/crdt_merge.h
  operation_create               src/StateMachine/state_machine.h:243
  (sovereign prefix in signed form) src/Serialization/serialization.c:3680-3693
  (DOMAIN_CHECK + refusals)      src/StateMachine/state_machine.c:1090-1109
  (chain advance)                src/StateMachine/state_machine.c:1142-1174
maturity: all exercised by C tests
test_ref: test/test_state_machine.cpp:1238-1430 (handler-driven sovereign
  counters + refusal battery)
-->