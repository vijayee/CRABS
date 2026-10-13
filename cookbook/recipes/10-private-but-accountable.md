---
number: 10
slug: private-but-accountable
title: Actions a leader takes that everyone can verify
section: Coordination
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: wasm node
teaches: sovereign write domains — integrity without confidentiality
---
## The problem

A council of five keeps a running tally, and the chair is the only person
allowed to move it. During session the tally changes several times a minute,
so the group cannot stand behind the chair for every write — and nobody
wants a committee vote each time the number moves. But everyone does want to
be able to say two things afterward: that the number they are looking at is
the one the chair wrote and nothing has been altered since, and that if the
chair ever signed two conflicting histories of that tally, they could not
only detect it but *act* on it, removing the chair's ability to write the
tally again.

Now add the word "private" and everything gets muddled. What is private
here, exactly? Not the tally's value — the whole point is that anyone can
read it. The chair's *writes* being contained to the chair is the property
the group actually wants. That requirement — one writer, no quorum to write,
no merge race deciding whose edit wins, yet verification that needs no
trust — is the balance this page's machinery is built on.

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

## The idea

Two properties get called "accountability", and they are different things.
*Integrity + identity* say who produced a piece of content and that it is
unchanged since — proofs *about* content. *Confidentiality* says who may
*read* it. They are orthogonal: a tamper-evident ledger has the first and
none of the second; a sealed envelope can have the second and say nothing
about the author. Readers conflate them because the mechanisms look alike
(cryptography in both cases), but a chain of signatures over named content
never encrypts a byte, and a cipher never proves who wrote.

For a leader's actions, what the group needs is the first property —
attribution and alteration-detection — plus *teeth*: when the rule "one
history only" is broken, the breach should produce something the group can
present and act on. Two mechanisms deliver exactly that:

- A **hash chain per writer**: every accepted write covers the previous
  content in a digest and takes a sequence number, so the question "is this
  the real history?" has a mechanical answer — extend the chain or refuse.
- A **signed claim of position**: each write is signed not just as a
  statement but as a statement *at a position* — "entry N of this item, on
  top of this digest". Two valid statements claiming the same position with
  different content can no longer both be history. That is *equivocation*
  — the one failure mode a chain cannot silently absorb — and it is
  collectable evidence.

Neither mechanism restricts reading. That is not a shortfall to hide; it is
the design's point — the leader acts where the group can't watch the
*content being made*, and the group still ends up with a history anyone can
check.

## How CRABS encodes it

- *The declaration at mint*: an item is created with an explicit write
  domain — `defineItem(name, type, crdt, { domain: 'sovereign',
  writer })`. The domain is immutable on a live item, the writer is
  mandatory for sovereign (and forbidden elsewhere), the legal types in v1
  are counter and register, and each refusal is typed.
- *The signed chain prefix*: before signing, the op sets
  `setSovereignPrefix(index, seq, digest)` — the item_seq the writer
  believes is live and the 32-byte digest of the item at that sequence, as
  64 hex chars or (wasm) 32 raw bytes. The prefix is carried in op format
  v6 and **bound by the signature** (signing format v4).
- *The gate*: DOMAIN_CHECK — a step of the executor pipeline, run
  post-dedup and post-authorization and before the handler. It aligns
  every prefix with the op's sovereign resources, binds the writer, refuses
  a quarantined writer, and compares the claimed seq against the live
  head: a stale/duplicate claim is `CRABS_ERR_SEQ_MISMATCH`, a non-writer's
  op is `CRABS_ERR_NOT_ITEM_WRITER`, and the same seq claimed with a
  different digest is a gate-level fork refusal, `CRABS_ERR_FORK_DETECTED`.
  Note the ordering of authority: the writer check beats the *policy*, so
  an op-authorized member is still refused. After the op applies, the chain
  advances itself: seq +1 and a SHA-256 digest over the item's post-op
  content-only form.
- *The accountability read*: `itemChainHead(name)` returns the live
  `{seq, digestHex}` to anyone — the next prefix is authored from it.
- *The enforcement*: two conflicting writer-signed claims of the same head
  are fork evidence; `reportEquivocation(item, opA, opB)` submits them as
  the `__report_equivocation__` op, which verifies the evidence itself
  (same op twice, a non-sovereign target, an unknown item, and a re-report
  are all typed refusals) and, only when the proof checks out, quarantines
  the writer *for that item*: every later write is
  `CRABS_ERR_QUARANTINED`. The conviction is machine state that merges
  union-only, never evicted, under a per-item evidence cap.
- *The composition line*: confidentiality is a different mechanism —
  Recipe 6's attribute-policy encryption (`Node.encrypt`). Sovereign chains
  and ABE policies compose; neither substitutes for the other.

## Try it

### crabs-wasm (browser / Node / edge)

The full loop: declare the leader's item, write a chained op, read the
head anyone reads, refuse a non-writer, and — the accountability half —
submit fork evidence and watch the writer get quarantined.

```snippet:wasm/10-private-but-accountable.js
```

### crabs-node (native Node.js)

Same surface on the native binding, one mechanical difference in the demo:
node ops are built synchronously (`new Operation(...)`, `KeyPair.generate()`
sync), prefixes take numbers only, and reportEquivocation takes `Buffer`s.

```snippet:node/10-private-but-accountable.js
```

### C (native)

No separate C demo — deliberately. The sovereign machinery is C *first*,
and both snippets above execute it through the same path: each binding
translates one JS call into one `state_machine_execute` call. There is
nothing the C surface adds that this recipe could honestly demo beyond what
those snippets run — and nothing missing that a gap would need to document.

## What it guarantees / what it doesn't

Guaranteed (everything below is executed by the snippets):

- *No one writes the leader's item but the leader.* Writer identity is
  checked at the item, over and above the policy — an op-authorized
  member's write to the sovereign item is still refused `not_item_writer`.
- *Every accepted op is chain-bound.* The signature covers `(seq, prev
  digest)`; the executor accepts a claim only at the live head — a stale
  seq is `seq_mismatch`, the same seq with a different digest is
  `fork_detected`, both before any mutation — then advances the head
  itself. The head is readable by anyone (`itemChainHead`).
- *Forks are not just detectable — they are actionable.* Fork evidence is
  verified by the report op, the writer is quarantined on that item, and
  the writer's very next op is refused `quarantined`. False evidence
  changes nothing (typed refusals); a re-report dedupes
  (`duplicate_operation`).

Not guaranteed — this is where "private" stops:

- *None of this encrypts.* Zero of it encrypts. The mechanism is identity +
  integrity: a named writer, a hash chain, equivocation evidence. The ops
  (including payload bytes) and the writer's identity live in the clear on
  every replica and the head digest is content-visible to anyone with the
  item name. For *confidentiality* — a group that can tally what was
  written without reading it — you need Recipe 6's attribute-policy
  encryption. Sovereign chains and ABE policies compose; neither
  substitutes for the other.
- *Accountability needs the evidence.* The executor *refuses* a forked
  claim at the gate (nothing applied) but it does not *convict* on its own:
  quarantine happens only through the report op, which is policy-guarded
  and requires possession of the two conflicting op payloads — the group
  must actually collect them. The machine detects the claim conflict; it
  does not gossip the evidence by itself.
- *Chains are per item.* Each sovereign item sequences its own writer's
  ops; nothing orders a leader's actions *across* items. (Recipe 14 covers
  the group-ordered answer; v1's sovereign mint also has a type ceiling —
  counters and registers only, so a "leader's list" cannot be made
  sovereign today.)
- *The writer is fixed at mint.* The gate compares the signer against the
  item's own `writer` field, not against any policy role, so "changing the
  lead" means re-minting under a new writer — nothing in v1 replaces a
  writer on a live item.

## Variations

- *Equivocation caps*: when you expect many bad actors rather than one,
  fork evidence is stored inline per item, capped at
  `CRABS_MAX_FORK_WRITERS = 16` — union-only on merge, never evicted; past
  the cap machine behavior follows the cap, not unlimited growth.
- *Sovereign + rollback*: when Recipe 9's recovery protocol runs on a
  locked sovereign item, a `__rollback__` restores content *and* digest —
  the lock snapshot and the chain agree.
- *Mode B (anonymous) ops are not sovereign ops*: sovereignty binds the
  writer to a `user_id`, which requires an attributable signer.
- *Delegation with accountability*: a sub-machine spawned via Recipe 11's
  lineage can be its own admin, but the *item* writer is still one named
  user id — sovereignty does not delegate write rights to a committee.

## Verified against the code

<!-- PROVENANCE
target: all-bindings
declaration + mint typing:
  DefineItemOptions (domain: 'free'|'sovereign'|'group', sovereign writer
  mandatory, ordering_module refused non-zero) — wasm DefineItemOptions
  bindings/wasm/index.d.ts:308-316 + defineItem :535-536; node
  bindings/node/index.d.ts:214-221 + defineItem :363-364; DefineItemOptions
  typed refusals exercised bindings/wasm/test/write-domains.js:23-59, node
  test/test.js:353ff; C enum src/CRABS/crabs.h:54-58; item writer field
  src/CRABS/data_model.h:165-195
  v1 sovereign-legal types = counter + register (type_mismatch otherwise)
  bindings/wasm/test/write-domains.js:28-31 (scope comment)
signed prefix:
  Operation.setSovereignPrefix — wasm bindings/wasm/index.d.ts:75 (seq
  number|bigint; digest 64 hex chars or 32 raw bytes), node
  bindings/node/index.d.ts:90 (number only — api-map §15 known diff #5);
  signed in format v4, wire-carried in op format v6; set BEFORE signing
gate (DOMAIN_CHECK) — executor pipeline src/StateMachine/state_machine.c:
  _check_sovereign region :978-1134; writer bind :1095-1097 (compare vs
  item's `writer` field data_model.h:169 — writer check precedes the seq
  check, so a foreign writer learns nothing about chain state);
  quarantined writer refusal :1090; seq mismatch :1101
  (CRABS_ERR_SEQ_MISMATCH src/CRABS/crabs.h:126); fork refusal :1103-1109
  (CRABS_ERR_FORK_DETECTED); not_item_writer CRABS_ERR_NOT_ITEM_WRITER
  crabs.h:125; non-writer-op refusal also tested
  bindings/node/test/test.js:455-468; invoked in the pipeline at :1348
  (post-dedup, post-authorization, pre-handler); Mode-A-only
  attributable-signer requirement :1085-1124
chain advance: _apply_sovereign_bookkeeping src/StateMachine/state_machine.c:1142-1174,
  driven at :1471-1476 — seq +1 and SHA-256 over the post-op content-only
  form; itemChainHead read: wasm bindings/wasm/index.d.ts:544
  ({seq, digestHex} full 32-byte hex), node :371; resource_not_found on
  unknown item
accountability: reportEquivocation (wasm :551-552, node :379) files
  `__report_equivocation__` (src/CRABS/crabs.h:175); behavior spec
  state_machine.c:2562-2600 (verified refusals: same op twice invalid_param,
  non-sovereign target invalid_param, unknown item resource_not_found,
  re-report duplicate_operation) + handler :2806; conviction = item's
  inline fork set, union-only merge, never evicted, serialized from wire v14
  src/CRABS/data_model.h:182-195; cap CRABS_MAX_FORK_WRITERS = 16
  src/CRABS/crabs.h:41,44; quarantined writer's next op refused
  CRABS_ERR_QUARANTINED (write-domains.js:124-145, node test.js:493-540)
confidentiality counterpoint: Node.encrypt wasm bindings/wasm/index.d.ts:686,
  node :508 (api-map §9 — the ABE surface; the payload-privacy layer recipe 6 teaches)
binding plumbing: wasm glue src/Util/wasm_helpers.c:420; node impl
  bindings/node/src/crabs_node.cc:1774; C domain enum
  src/CRABS/crabs.h:54-58; C item fields src/CRABS/data_model.h:165-195;
  C chain-advance :1142-1174; C equivocation-report handler
  state_machine.c:2585-2600; rollback/digest agreement on locked sovereign
  items :1790 ("restores exactly the content (and digest) the lock captured")
head-digest note: itemChainHead returns the digest recomputed over the
  post-op content-only form (:1142-1174); the all-zero digest appears only
  on a fresh item at seq 0 — the first link the snippets sign

target: crabs-wasm (snippet wasm/10-private-but-accountable.js)
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:774
  KeyPair.generate          bindings/wasm/index.d.ts:44
  registerUser              bindings/wasm/index.d.ts:480
  grantRole                 bindings/wasm/index.d.ts:481
  Node.defineItem           bindings/wasm/index.d.ts:535-536
  DefineItemOptions         bindings/wasm/index.d.ts:308-316
  addCounter                bindings/wasm/index.d.ts:490
  Node.setPolicy            bindings/wasm/index.d.ts:638
  Operation.create          bindings/wasm/index.d.ts:122
  Operation.addResource     bindings/wasm/index.d.ts:68
  Operation.setSovereignPrefix bindings/wasm/index.d.ts:75
  Node.sign                 bindings/wasm/index.d.ts:657
  Node.execute              bindings/wasm/index.d.ts:656
  Node.itemChainHead        bindings/wasm/index.d.ts:544
  Node.reportEquivocation   bindings/wasm/index.d.ts:551-552
  Operation.destroy         bindings/wasm/index.d.ts:118
  Node.destroy              bindings/wasm/index.d.ts:770
  (DOMAIN_CHECK pipeline)   src/StateMachine/state_machine.c:978-1134, :1348
  (chain advance)           src/StateMachine/state_machine.c:1142-1174, :1471-1476
  (equivocation handler)    src/StateMachine/state_machine.c:2562-2600, :2806
  (op type word)            src/CRABS/crabs.h:175
maturity: all STABLE
test_ref: bindings/wasm/test/write-domains.js:68-104 (chained writes + head) + :106-107 (not_item_writer) + :113-146 (fork report, quarantine, typed failures)

target: crabs-node (snippet node/10-private-but-accountable.js)
verified: executed
symbols:
  NodeStatic.new            bindings/node/index.d.ts:641-643
  KeyPair.generate          bindings/node/index.d.ts:71
  registerUser              bindings/node/index.d.ts:304
  grantRole                 bindings/node/index.d.ts:305
  Node.defineItem           bindings/node/index.d.ts:363-364
  DefineItemOptions         bindings/node/index.d.ts:214-221
  addCounter                bindings/node/index.d.ts:315
  Node.setPolicy            bindings/node/index.d.ts:450
  new Operation             bindings/node/index.d.ts:138-140
  Operation.addResource     bindings/node/index.d.ts:83
  Operation.setSovereignPrefix bindings/node/index.d.ts:90
  Node.sign                 bindings/node/index.d.ts:463
  Node.execute              bindings/node/index.d.ts:464
  Node.itemChainHead        bindings/node/index.d.ts:371
  Node.reportEquivocation   bindings/node/index.d.ts:379
maturity: all STABLE
test_ref: bindings/node/test/test.js:385-470 (chained writes + head) + :455-477 (not_item_writer) + :479-540 (fork report, quarantine, typed failures)

target: native-c (no separate snippet — the snippets above run one
  state_machine_execute per JS call; wasm glue src/Util/wasm_helpers.c:420,
  node bindings/node/src/crabs_node.cc:1774)
-->