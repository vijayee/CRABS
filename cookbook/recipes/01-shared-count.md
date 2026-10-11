---
number: 1
slug: shared-count
title: A shared count that can't be double-counted
section: Basics
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
---
## Intent

You want a count — opens, likes, uses — that many nodes can increment at once,
while the records holding it stay divergent for a while and then agree. The
requirement has two halves: no increment is ever counted twice, and every node
ends up with the same total, no matter what order the increments arrived in
and no coordination step at the end.

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

## The shape

- A counter is a named item on the node: `addCounter('opens')` (G-counter).
- Each increment is attributed to a node id: `incrementCounter('opens', 1, 'counter')`.
- A read, `getCounter('opens')`, sums the per-node table; merging two replicas
  keeps the larger value per node id, so replicas converge without
  double-counting increments that the same node recorded (or re-recorded).
- The item lives in the free-merge domain — `CRABS_DOMAIN_FREE_MERGE`
  (`src/CRABS/crabs.h:55`), any authorized writer, CRDT merge semantics. This
  is the G-counter: increments only, counts up. PN counters (`addPNCounter` /
  `incrementPNCounter` / `decrementPNCounter`, api-map §4) exist for the case
  where decrements are needed, and give up a little guaranteed simplicity for it.

## What it guarantees / what it doesn't

Guaranteed: under concurrent increments from many nodes, the counter converges
to the same value everywhere, and no increment is double-counted — because
increments are attributed per node and merge takes the per-node maximum, an
increment that arrives twice (or from two replicas that both saw it) merges
into one entry. Nothing about arrival order matters.

Not guaranteed: strict per-event accounting. Free-merge combines per-node
deltas — it is not a global ordered ledger of individual opens. If two nodes
independently record the same logical event under different node ids, the
merged total is their sum, not one entry; if the same node records an event
twice, the merge cannot distinguish a retry from a second event on its own.
The C snippet's second half shows both edges of this: `node-1` saw 3 opens,
`node-2` saw 2, and the merge of the two is `max(3) + max(2) = 5` — converge
without a leader, but count attribution is per node, not per event. If you
need "this specific event, exactly once, from anywhere", that is dedup, and
it is Recipe 3's problem, not the counter's.

## Variations

- Need decrements too? Swap `addCounter`/`incrementCounter` for
  `addPNCounter`/`incrementPNCounter` and use `decrementPNCounter` to add
  negative attribution — the merge keeps the per-node maximum on each side of
  the entry, so decrements converge the same way. (Note the maturity split:
  `decrementPNCounter` is declared but not exercised by any test we found —
  see the Notes below.)
- Same shape across process boundaries: attribution is by whatever node id
  string you pass, so two processes each with their own `Node` and distinct
  ids merge without coordination — nothing about the counter is per-machine.
- Watch instead of poll: the change event stream (`on('change')`,
  `bindings/wasm/test/change-events.js`) fires for counter mutations, so a
  UI can render the count without polling `getCounter`.

## Recipe

### crabs-wasm (browser / Node / edge)

```snippet:wasm/01-shared-count.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create            bindings/wasm/index.d.ts:372
  KeyPair.generate       bindings/wasm/index.d.ts:21
  publicKeyHex           bindings/wasm/index.d.ts:15
  KeyPair.destroy        bindings/wasm/index.d.ts:17
  registerUser           bindings/wasm/index.d.ts:213
  addCounter             bindings/wasm/index.d.ts:223
  incrementCounter       bindings/wasm/index.d.ts:286
  getCounter             bindings/wasm/index.d.ts:254
  Node.destroy           bindings/wasm/index.d.ts:368
maturity: all STABLE
test_ref: bindings/wasm/test/smoke.js:1
-->

### crabs-node (native Node.js)

```snippet:node/01-shared-count.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  NodeStatic.new         bindings/node/index.d.ts:312
  KeyPair.generate       bindings/node/index.d.ts:14
  publicKeyHex           bindings/node/index.d.ts:8
  registerUser           bindings/node/index.d.ts:182
  addCounter             bindings/node/index.d.ts:193
  incrementCounter       bindings/node/index.d.ts:238
  getCounter             bindings/node/index.d.ts:224
maturity: all STABLE
test_ref: bindings/node/test/test.js:1
-->

### C (native)

```snippet:c/01-shared-count.c
```

<!-- PROVENANCE
target: native-c
verified: executed
symbols:
  g_counter_create       src/CRDT/crdt_merge.h:27
  g_counter_destroy      src/CRDT/crdt_merge.h:28
  g_counter_increment    src/CRDT/crdt_merge.h:29
  g_counter_value        src/CRDT/crdt_merge.h:30
  g_counter_merge        src/CRDT/crdt_merge.h:31
  CRABS_SUCCESS          src/CRABS/crabs.h:65
maturity: all STABLE
test_ref: test/test_crdt.cpp:38
-->

### Notes

- Counter values are `int64_t` in C (`src/CRDT/crdt_merge.h:29`) and numbers in
  both JS bindings; the JS-side integer discipline (fractions, NaN, and — on the
  node binding — BigInt are rejected on the int64-carrying register surface,
  `bindings/node/index.d.ts:227-234`) applies to registers, not to counter
  deltas, but keep deltas ordinary integers anyway.
- Need negative deltas? `addPNCounter` / `incrementPNCounter` (`wasm:224,287` /
  `node:194,239`) are STABLE; `decrementPNCounter` (`wasm:288, node:240`) is
  PRESENT — declared but not exercised by any test we found.
- The merge is per-node-max, not sum: the C snippet's two replicas hold
  `node-1 -> 3` and `node-2 -> 2` and merge to 5, and the C test suite asserts
  the same shape over four node ids (`test/test_crdt.cpp:38` — `max(5,0) +
  max(3,7) + max(0,2) = 14`).
- Retries are safe precisely because attribution is per node: re-applying
  `incrementCounter('opens', 1, 'counter')` to a replica that already counted
  that open bumps the same per-node entry toward its own max, so delivery
  retries and replay cannot double-count. What they *can* do is merge a real
  second event from the same node — the counter counts node-attribution, not
  events (see the guarantee discussion above).