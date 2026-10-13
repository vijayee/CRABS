---
number: 1
slug: shared-count
title: A shared count that can't be double-counted
section: Basics
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
interactive: true
teaches: counting with replicas: why max-per-lane beats one integer
---
## The problem

Three laptops each count opens of the same document. They are offline half the
time. Each laptop starts its copy of the count at zero and adds 1 whenever its
user opens the document; when two laptops sync, whatever they send each other
has to add up.

Today the count is one integer on each laptop. Laptop A counts 5 opens, laptop
B counts 5 opens, and the two sync. `5` meets `5` — and neither copy can tell
whether that is the *same* five opens seen twice or *ten* different opens. The
number that arrives cannot say what happened to it. Whichever laptop's value
wins the sync, one of two things goes silently wrong for good: either an
increment disappears (the copies overwrite each other's), or an open nobody's
copy remembers is an open never counted. Retrying the sync changes
nothing, because no copy is missing information about the network — each copy
is missing information about *itself*. The problem is that `5` is the entire
state, and CRABS' counter is designed around exactly that failure.

## The naive version, and where it breaks

The naive version is an integer field on a shared record. Each replica holds
`count = 4`, two of them apply `count += 1` locally, and now you have `4`, `5`,
`5` — and at some point a replica holding `5` sends its state to a replica
holding `5`. Nothing you can do to the two `5`s recovers the fact that both
increments happened. An integer has no memory of what was added to it, only
the result of the last addition. The copies never converge back to `6`; two
replicas are now permanently showing different totals, and whichever one wins
the last write silently erases the other's increment.

It is worth seeing why the usual fixes don't patch it. Retrying delivery
doesn't help — re-sending `5` just re-runs the same overwrite, because the
problem is that `5` *is* the entire state, not that delivery is unreliable.
Logging every increment to an event log and re-summing on each side works, but
it requires a total order over events agreed by all nodes — you would be
building the coordination you were trying to avoid. The interesting thing is
that the correct representation is nearly free: keep a small table of
`node -> count seen from that node`, and merge by taking the larger value per
node. That table has no ordering requirement at all.

## The idea

Give each replica its own *lane*, and let the count live in the lanes instead
of a single cell. Three laptops produce three lanes: `A -> 4`, `B -> 3`,
`C -> 2`. A laptop only ever adds to its own lane, so lanes never fight over
the same slot. A sync merges lane tables by keeping the *larger* value per
lane:

| lane | laptop A | laptop B | merged |
|---|---|---|---|
| A | 4 | 2 | 4 |
| B | 3 | 1 | 3 |
| C | 2 | 0 | 2 |

Both sides can arrive at that table and both get the same answer — `max` is
deterministic, commutative, and idempotent. A lane only grows, so a value that
synced twice adds nothing, a late-arriving older snapshot loses to the newer
one, and no lane needs to know what order anything arrived in.

The trade is baked into the design: the counter counts *what each lane saw*,
not what happened in the world. Two laptops that both counted a genuinely
different open each grow their own lane — right. One laptop that counted the
same open twice grows its lane by 2 — the counter cannot object, because from
inside the lane both adds look alike. If "this specific event, exactly once"
is the requirement, the state needs a different shape (Recipe 3 takes it).

## How CRABS encodes it

- A counter is a named item on the machine: `addCounter('opens')` — a
  G-counter, the lane table above.
- Each increment names the node it came from:
  `incrementCounter('opens', 1, 'counter')`.
- A read, `getCounter('opens')`, sums the per-node table; merging two replicas
  keeps the larger value per node id, so replicas converge without
  double-counting an increment the same node recorded twice.
- Retries are safe for the same reason: re-applying an increment bumps the
  same lane toward its own max, so delivery replays cannot double-count.
  What a retry *can* do is record a real second event from the same node.
- The item lives in the free-merge domain — any authorized writer, CRDT
  merge semantics. This is the increments-only counter; for negative
  attribution there is a PN-counter family in the same surface.
- Counter values are `int64_t` in C and numbers in both JS bindings; keep
  deltas ordinary integers regardless.

## Try it

### crabs-wasm (browser / Node / edge)

```snippet:wasm/01-shared-count.js
```

<div class="interactive">

<iframe src="/cookbook/shared-count/interactive.html" style="width:100%;height:420px;border:none" title="Interactive demo — A shared count"></iframe>

</div>

### crabs-node (native Node.js)

```snippet:node/01-shared-count.js
```

### C (native)

```snippet:c/01-shared-count.c
```

## What it guarantees / what it doesn't

- Converges: under concurrent increments from many nodes, replicas end at
  the same total regardless of arrival order.
- No double-counting: an increment that arrives twice (or from two replicas
  that both saw it) merges into one per-node entry.
- Not a global ordered ledger: free-merge combines per-node deltas, so two
  nodes independently recording the same logical event count it twice.
  The C snippet's second half shows both edges: `node-1 -> 3` and
  `node-2 -> 2` merge to `max(3) + max(2) = 5` — convergence without a
  leader, attribution per node and not per event.
- If you need "this specific event, exactly once, from anywhere", that is
  dedup, and Recipe 3's problem, not the counter's.

## Variations

- Need decrements too? Swap `addCounter`/`incrementCounter` for the
  PN-counter family (`addPNCounter`/`incrementPNCounter`/`decrementPNCounter`)
  — the merge keeps the per-node maximum on each side of the entry, so
  decrements converge the same way. Decrement support is declared but not
  yet exercised by any test — the footer says where to look before relying
  on it.
- Same shape across process boundaries: attribution is by whatever node id
  string you pass, so two processes each with their own `Node` and distinct
  ids merge without coordination — nothing about the counter is per-machine.
- Watch instead of poll: the change event stream (`on('change')`) fires for
  counter mutations, so a UI can render the count without polling
  `getCounter`.

## Verified against the code

<!-- PROVENANCE
counter type: CRABS_DOMAIN_FREE_MERGE enum — src/CRABS/crabs.h:55
g_counter surface: g_counter_create src/CRDT/crdt_merge.h:27 · increment :29 (int64_t delta) · value :30 · merge :31 (per-node max) · destroy :28

target: crabs-wasm (snippet wasm/01-shared-count.js)
verified: executed
symbols:
  Node.create            bindings/wasm/index.d.ts:774
  KeyPair.generate       bindings/wasm/index.d.ts:44
  publicKeyHex           bindings/wasm/index.d.ts:38
  KeyPair.destroy        bindings/wasm/index.d.ts:40
  registerUser           bindings/wasm/index.d.ts:480
  addCounter             bindings/wasm/index.d.ts:490
  incrementCounter       bindings/wasm/index.d.ts:586
  getCounter             bindings/wasm/index.d.ts:554
  Node.destroy           bindings/wasm/index.d.ts:770
maturity: all STABLE
test_ref: bindings/wasm/test/smoke.js:6-28 (addCounter/incrementCounter/getCounter idiom) + smoke.js:135 (Node.destroy)

target: crabs-node (snippet node/01-shared-count.js)
verified: executed
symbols:
  NodeStatic.new         bindings/node/index.d.ts:642 (new Node)
  KeyPair.generate       bindings/node/index.d.ts:71
  publicKeyHex           bindings/node/index.d.ts:28
  registerUser           bindings/node/index.d.ts:304
  addCounter             bindings/node/index.d.ts:315
  incrementCounter       bindings/node/index.d.ts:396
  getCounter             bindings/node/index.d.ts:382
maturity: all STABLE
test_ref: bindings/node/test/test.js:31 (new Node + hlc) · test.js:66-78 (direct increments, getCounter readback)

target: native-c (snippet c/01-shared-count.c)
verified: executed
symbols:
  g_counter_create       src/CRDT/crdt_merge.h:27
  g_counter_destroy      src/CRDT/crdt_merge.h:28
  g_counter_increment    src/CRDT/crdt_merge.h:29
  g_counter_value        src/CRDT/crdt_merge.h:30
  g_counter_merge        src/CRDT/crdt_merge.h:31
  CRABS_SUCCESS          src/CRABS/crabs.h:65
maturity: all STABLE
test_ref: test/test_crdt.cpp:38 (TestMerge — max(5,0) + max(3,7) + max(0,2) = 14 over four node ids) · :61 (TestMergeSameNode — replayed increments stay max)

PN counters: addPNCounter wasm bindings/wasm/index.d.ts:491 · node bindings/node/index.d.ts:316 — STABLE (both test suites).
incrementPNCounter :587 / :397 — STABLE. decrementPNCounter :588 / :398 — PRESENT (declared; no test exercises it).
Counter reads fire 'change' events: Node.on wasm :485 · node :310 (bindings/wasm/test/change-events.js:44-52).
Counter values: int64_t deltas in C, numbers in both JS bindings (integer discipline on the int64-carrying register surface is recipe 5's; counter deltas stay plain integers).
-->