---
number: 10
slug: private-but-accountable
title: Actions a leader takes that everyone can verify
section: Coordination
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: wasm node
---
## Intent

A leader — a coordinator, a chair, a lead maintainer — has to move things
the group cares about: a tally, a schedule, a roster, a ledger. The
requirement has a tension baked into it:

- the *action* should stay contained: one writer, no committee votes for
  every write, no merge race deciding whose edit wins;
- the *accountability* should stay collective: everyone can read where the
  chain is, every accepted op provably came from the writer, and if the
  writer signs two conflicting histories the group can not only detect that
  — they can *act* on it, evicting the writer from the item.

The leader must not need a quorum to write; the group must not need trust
to verify. That is the balance this recipe's machinery is built on.

## The naive version, and where it breaks

The naive version gives the leader a plain counter and says "only the leader
increments it". Nothing stops the leader but the *policy expression*, and a
policy answers "may this signer write this op type", not "may this signer
claim this item *history*". Take the leader's key to two replicas and sign
two different `adjust` ops — each replica happily applies both; merge them
and the group holds a tally that mixes both histories. Worse: there is no
way to *prove* the split, because nothing bound each op to a position —
the ops are independent signed statements, valid in any order, anywhere,
twice. A policy can even be fixed (only the leader holds `role:leader`)
and every problem above survives, because authorization over ops is not
authorization over a chain of them.

Hand-rolling the fix ("keep a sequence number in the payload") moves the
problem, not the solution: the number is only as trustworthy as the writer,
and the group still needs a mechanism to detect and punish a writer who
lies about it.

## The shape

- *The declaration at mint*: an item is created with an explicit write
  domain — `defineItem(name, type, crdt, { domain: 'sovereign',
  writer })`. The domain is immutable on a live item, the writer is
  mandatory for sovereign (and forbidden elsewhere), the legal types in v1
  are counter and register, and each refusal is typed
  (`invalid_param`, `type_mismatch`, unknown domain) —
  `bindings/wasm/index.d.ts:235-236` + options `:180-188`
  (`bindings/node/index.d.ts:205-206` + `:122-130`; C enum
  `src/CRABS/crabs.h:54-58`, item fields `src/CRABS/data_model.h:165-176`).
- *The signed chain prefix*: before signing, the op sets
  `setSovereignPrefix(index, seq, digest)` — the item_seq the writer
  believes is live and the 32-byte digest of the item at that sequence, as
  64 hex chars or (wasm) 32 raw bytes. The prefix is carried in op format
  v6 and **bound by the signature** (signing format v4) —
  `bindings/wasm/index.d.ts:40-41`, `bindings/node/index.d.ts:33`.
- *The gate*: DOMAIN_CHECK — step 6d of the executor pipeline
  (`_run_domain_check`, `src/StateMachine/state_machine.c:1047+`, invoked
  at `:1348` post-dedup and post-authorization, before the handler), which
  aligns every prefix with the op's sovereign resources, binds the writer,
  refuses a quarantined writer, and compares the claimed seq against the
  live head; a stale/duplicate claim is `CRABS_ERR_SEQ_MISMATCH`
  (`src/CRABS/crabs.h:126`), a non-writer's op is
  `CRABS_ERR_NOT_ITEM_WRITER` (`:125`), and the same seq claimed with a
  different digest is a gate-level fork refusal,
  `CRABS_ERR_FORK_DETECTED` (`state_machine.c:1103-1109`) — note the
  ordering of authority:
  the writer check beats the *policy*, so an op-authorized member is still
  refused. After the op applies, the chain advances: seq +1 and a SHA-256
  digest over the item's post-op content-only form
  (`_apply_sovereign_bookkeeping`, `state_machine.c:1142-1174`, driven at
  `:1471-1476`).
- *The accountability read*: `itemChainHead(name)` returns the live
  `{seq, digestHex}` to anyone — the next prefix is authored from it
  (`bindings/wasm/index.d.ts:244`, `bindings/node/index.d.ts:213`).
- *The enforcement*: two conflicting writer-signed claims of the same head
  are fork evidence; `reportEquivocation(item, opA, opB)` submits them as
  the `__report_equivocation__` op (`src/CRABS/crabs.h:175`; behavior spec
  `state_machine.c:2562-2600`, handler at `:2806`), which verifies the evidence itself (same op
  twice, a non-sovereign target, an unknown item, and a re-report are all
  typed refusals) and, only when the proof checks out, quarantines the
  writer *for that item*: every later write is `CRABS_ERR_QUARANTINED`.
  The conviction is machine state that merges union-only, never evicted
  (`src/CRABS/data_model.h:182-191`), under a per-item evidence cap
  (`src/CRABS/crabs.h:41,44`).

This recipe is COMPLETE: the whole surface above is bound on both JS
surfaces and exercised end-to-end —
`bindings/wasm/test/write-domains.js` and the sovereign sections of
`bindings/node/test/test.js`.

## What it guarantees / what it doesn't

Guaranteed (everything below is executed by the snippets):

- *No one writes the leader's item but the leader.* Writer identity is
  checked at the item, over and above the policy: an op-authorized member's
  write to the sovereign item is still refused `not_item_writer` (both
  snippets' rogue-op step; `write-domains.js:106`,
  `bindings/node/test/test.js:455-468`).
- *Every accepted op is chain-bound.* The signature covers `(seq, prev
  digest)`; the executor accepts a claim only at the live head — a stale
  seq is `seq_mismatch`, the same seq with a different digest is
  `fork_detected`, both before any mutation — then advances the head
  itself. A replica's accepted history is therefore one hash-chained
  sequence, and the head is readable by anyone (`itemChainHead`; both
  snippets re-read the head between writes and assert the seq/digest
  progression). A writer who *forks across replicas* is not stopped from
  signing the two histories — each replica just refuses the claim its own
  head can't satisfy — which is exactly what the evidence report is for
  (next bullet).
- *Forks are not just detectable — they are actionable.* A second
  leader-signed claim to an already-claimed head is evidence; the report
  op verifies the pair, quarantines the writer on that item, and the
  writer's very next op is refused `quarantined`. False evidence changes
  nothing (typed refusals); a re-report dedupes
  (`duplicate_operation`).

Not guaranteed — and this is the honesty this recipe owes its name:

- *"Private" here means contained, not confidential.* The mechanism on
  this page is identity + integrity: a named writer, a hash chain,
  equivocation evidence. Zero of it encrypts. The ops (including payload
  bytes) and the writer's identity live in the clear on every replica and
  the head digest is content-visible to anyone with the item name. For
  *confidentiality* — a group that can tally what was written without
  reading it — you need Recipe 6's mechanism: attribute-policy encryption
  (`Node.encrypt`, `bindings/wasm/index.d.ts:306`,
  `bindings/node/index.d.ts:257`). Sovereign chains and ABE policies
  compose; neither substitutes for the other.
- *Accountability needs the evidence.* The executor *refuses* a forked
  claim at the gate (`CRABS_ERR_FORK_DETECTED`, nothing applied —
  `state_machine.c:1103-1109`) but it does not *convict* on its own:
  quarantine happens only through the report op, which is policy-guarded
  (`__report_equivocation__` needs an authorizing policy, set in both
  snippets) and requires possession of the two conflicting op payloads —
  the group must actually collect them (that is what "reportEquivocation
  files the `__report_equivocation__` op" is for). The machine detects the
  claim conflict; it does not gossip the evidence by itself.
- *Chains are per item.* Each sovereign item sequences its own writer's
  ops; nothing orders a leader's actions *across* items, and v1 ships no
  GROUP-ORDERED ordering modules (`defineItem` refuses anything but 0 —
  `bindings/wasm/index.d.ts:186-187`), so a multi-item, machine-enforced
  total order for the leader's moves does not exist yet (api-map §17, R14).
- *v1's type ceiling*: sovereign items are counters and registers only
  (`write-domains.js:39-41` — other shapes `type_mismatch`). A "leader's
  list" (Recipe 8) cannot be made sovereign today.

## Variations

- *Equivocation caps*: fork evidence is stored inline per item, capped at
  `CRABS_MAX_FORK_WRITERS = 16` (`src/CRABS/crabs.h:44`) — union-only on
  merge, never evicted; past the cap the machine behavior (new evidence
  for an already-convicted writer vs. fresh writers) follows the cap, not
  unlimited growth.
- *Sovereign + rollback*: a `__rollback__` on a locked sovereign item
  restores content and digest (`state_machine.c:1790` — a rollback
  "restores exactly the content (and digest) the lock captured"), so
  Recipe 9's recovery protocol and Recipe 10's chain agree.
- *Mode B (anonymous) ops are not sovereign ops*: sovereignty binds the
  writer to a `user_id`, which requires an attributable signer — Mode A
  (`state_machine.c:1085-1124`).
- *Delegation with accountability*: a sub-machine spawned via Recipe 11's
  lineage can be its own admin, but the *item* writer is still one named
  user id — sovereignty does not delegate write rights to a committee.

## Recipe

### crabs-wasm (browser / Node / edge)

The full loop: declare the leader's item, write a chained op, read the
head anyone reads, refuse a non-writer, and — the accountability half —
submit fork evidence and watch the writer get quarantined.

```snippet:wasm/10-private-but-accountable.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:372
  KeyPair.generate          bindings/wasm/index.d.ts:21
  registerUser              bindings/wasm/index.d.ts:213
  grantRole                 bindings/wasm/index.d.ts:214
  Node.defineItem           bindings/wasm/index.d.ts:235-236
  DefineItemOptions         bindings/wasm/index.d.ts:180-188
  addCounter                bindings/wasm/index.d.ts:223
  Node.setPolicy            bindings/wasm/index.d.ts:295
  Operation.create          bindings/wasm/index.d.ts:52
  Operation.addResource     bindings/wasm/index.d.ts:33
  Operation.setSovereignPrefix bindings/wasm/index.d.ts:40-41
  Node.sign                 bindings/wasm/index.d.ts:297
  Node.execute              bindings/wasm/index.d.ts:296
  Node.itemChainHead        bindings/wasm/index.d.ts:244
  Node.reportEquivocation   bindings/wasm/index.d.ts:251-252
  Operation.destroy         bindings/wasm/index.d.ts:48
  Node.destroy              bindings/wasm/index.d.ts:368
  (DOMAIN_CHECK pipeline)   src/StateMachine/state_machine.c:978-1134, :1348
  (chain advance)           src/StateMachine/state_machine.c:1142-1174, :1471-1476
  (equivocation handler)    src/StateMachine/state_machine.c:2562-2600, :2806
  (op type word)            src/CRABS/crabs.h:175
maturity: all STABLE
test_ref: bindings/wasm/test/write-domains.js:68-104 (chained writes + head) + :106-107 (not_item_writer) + :113-146 (fork report, quarantine, typed failures)
-->

### crabs-node (native Node.js)

Same surface on the native binding, one mechanical difference in the demo:
node ops are built synchronously (`new Operation(...)`, `KeyPair.generate()`
sync), prefixes take numbers only, and reportEquivocation takes `Buffer`s.

```snippet:node/10-private-but-accountable.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  NodeStatic.new            bindings/node/index.d.ts:312
  KeyPair.generate          bindings/node/index.d.ts:14
  registerUser              bindings/node/index.d.ts:182
  grantRole                 bindings/node/index.d.ts:183
  Node.defineItem           bindings/node/index.d.ts:205-206
  DefineItemOptions         bindings/node/index.d.ts:122-130
  addCounter                bindings/node/index.d.ts:193
  Node.setPolicy            bindings/node/index.d.ts:249
  new Operation             bindings/node/index.d.ts:47
  Operation.addResource     bindings/node/index.d.ts:26
  Operation.setSovereignPrefix bindings/node/index.d.ts:33
  Node.sign                 bindings/node/index.d.ts:250
  Node.execute              bindings/node/index.d.ts:251
  Node.itemChainHead        bindings/node/index.d.ts:213
  Node.reportEquivocation   bindings/node/index.d.ts:221
maturity: all STABLE
test_ref: bindings/node/test/test.js:385-470 (chained writes + head) + :455-477 (not_item_writer) + :479-540 (fork report, quarantine, typed failures)
-->

### C (native)

No separate C demo — deliberately. The sovereign machinery is C *first*
(domain enum `src/CRABS/crabs.h:54-58`, item fields
`src/CRABS/data_model.h:165-195`, the DOMAIN_CHECK pipeline
`src/StateMachine/state_machine.c:978-1134`, the chain-advance
`:1142-1174` and the equivocation-report handler `:2585-2600`), and both
snippets above execute it through the same path — each binding translates
one JS call into one `state_machine_execute` call
(`bindings/node/src/crabs_node.cc:1774`; the wasm C glue,
`src/Util/wasm_helpers.c:420`). There is nothing the C
surface adds that this recipe could honestly demo beyond what those
snippets run — and nothing missing that a gap would need to document.

## Notes

- *Where the "privacy" in the title actually lives*: the leader's *item*
  is contained — a single named writer, no merge races, no concurrent
  writers to worry about — while the *accountability* is public structure:
  the head (`itemChainHead`) is readable by any member, every accepted op
  was verified against it, and equivocation is provable with the two
  offending payloads. What is *content-confidential* is nothing here;
  that is Recipe 6's `Node.encrypt` at a different layer (api-map §9),
  which this surface composes with but does not imply.
- *The prefix is signed, both ways it can be given*: 64-hex digest chars
  on both bindings, or 32 raw bytes on wasm (`bindings/wasm/index.d.ts:
  40-41`); on node the seq is `number`-only while wasm accepts
  `number | bigint` (api-map §15 known difference #5). Set it BEFORE
  signing — the signature binds it, and a post-signing edit fails the
  signature.
- *The head digest is not the digest you signed*: `itemChainHead` returns
  the digest recomputed over the item's post-op content-only form
  (`state_machine.c:1142-1174`); the all-zero digest only appears on a
  fresh item at seq 0, which is exactly what the snippets sign as their
  first link.
- *Quarantine is per item, and it sticks through merges*: the conviction
  lives in the item's inline fork set (`src/CRABS/data_model.h:182-195`),
  union-only on merge, so a quarantined leader stays quarantined on that
  item even after replica convergence (and it is serialized from wire
  version v14 onward, `data_model.h:187`).
- *False evidence is cheap to resist and typed at the door*: same op twice
  (`invalid_param`), free-merge target (`invalid_param`), unknown item
  (`resource_not_found`), a re-report (`duplicate_operation`) — a report
  that fails any of those changes nothing (`state_machine.c:2585-2600`,
  exercised in both snippets).
- *The writer is fixed at mint, and it is the item's truth about its
  leader*: the DOMAIN_CHECK compares the signer against the item's own
  `writer` field (`data_model.h:169`), not against any policy role, so
  "changing the lead" for a sovereign item means re-minting under a new
  writer — nothing in v1 replaces a writer on a live item.