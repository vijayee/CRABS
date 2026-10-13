'use strict';
// Recipe 8 — a reorderable list two people can edit at once (crabs-node).
// Mirror of the wasm snippet over the direct-C binding: the ordered* sugar
// composes, node-key-signs (this machine's admin, the reportEquivocation
// idiom) and executes a __execute_ot__ op through the machine, and
// getOrderedSet reads the materialized order, tombstones skipped.
//
// Scenarios: seeds keep their order, MOVE 0->2 re-derives [b,c,a], a
// replayed op id is a silent no-op, SWAP is a local value exchange, and two
// machines exchanging their ops (each carrying the causal deps the issuing
// replica had) converge on one identical order. The merge-level guarantees
// that live in crabs_ot_ordered_set_merge — merge commutativity by
// construction, conflicting-payload refusal — remain C-only (recipe 8 keeps
// that caveat).

const assert = require('assert');
const { Node } = require('../../../bindings/node');

const nodeA = new Node('node-a', { ordering: 'hlc' });
// The ordered* sugar signs under the machine's admin with the node key — the
// __execute_ot__ op type needs a policy first, or the executor refuses every
// op with unauthorized.
nodeA.setPolicy('__execute_ot__', 'role:admin');
nodeA.addOrderedSet('list');

const read = (machine, name) => machine.getOrderedSet(name).elements;

// ---- Three seed inserts; elements are addressed by op id + position ------
nodeA.orderedInsert('list', 'a', 0, { id: { node: 'node-a', seq: 1, ts: 1000 } });
nodeA.orderedInsert('list', 'b', 1, { id: { node: 'node-a', seq: 2, ts: 1000 } });
nodeA.orderedInsert('list', 'c', 2, { id: { node: 'node-a', seq: 3, ts: 1000 } });
assert.deepStrictEqual(read(nodeA, 'list'), ['a', 'b', 'c'],
  'seed inserts must keep their order');

// ---- MOVE 0->2: [a, b, c] -> [b, c, a] ------------------------------------
// Sequential local ops share this machine's op-id node: the executor skips
// same-node lower-sequence log ops as causally ordered, so the move applies
// at its raw position.
nodeA.orderedMove('list', 0, 2, { id: { node: 'node-a', seq: 4, ts: 1001 } });
assert.deepStrictEqual(read(nodeA, 'list'), ['b', 'c', 'a'], 'MOVE 0->2');

// ---- A replayed op id is a silent no-op -----------------------------------
nodeA.orderedMove('list', 0, 2, { id: { node: 'node-a', seq: 4, ts: 1001 } });
assert.deepStrictEqual(read(nodeA, 'list'), ['b', 'c', 'a'],
  'replayed op id is idempotent');

// ---- SWAP is a local value exchange of two positions ----------------------
// Not a placement op: the payloads trade, ids stay put
// (ot_ordered_set.c SwapElements) — demo it locally, exactly like the C
// snippet; recipe 8's placement caveat covers why this is local-only.
nodeA.orderedSwap('list', 0, 2, { id: { node: 'node-a', seq: 5, ts: 1002 } });
assert.deepStrictEqual(read(nodeA, 'list'), ['a', 'c', 'b'], 'SWAP 0<->2');
console.log('reorderable-list OK: local MOVE -> [b,c,a], replay no-op, SWAP -> [a,c,b]');

// ---- Two machines converge by exchanging ops, not arrays ------------------
// Both replicas execute the same seed ops (same op ids — replays of them are
// idempotent skips), then each issues ONE concurrent insert at the top.
// Replays carry the issuing replica's causal context in deps; the
// insert-insert transform tie-break (priority, then op-id node bytes) makes
// exactly one replica shift, so both converge deterministically.
const nodeB = new Node('node-b', { ordering: 'hlc' });
for (const machine of [nodeA, nodeB]) {
  machine.setPolicy('__execute_ot__', 'role:admin');
  machine.addOrderedSet('queue');
}
const seedDeps = [{ node: 'node-a2', seq: 1 }, { node: 'node-a2', seq: 2 }];
const insertOn = (machine, element, options) =>
  machine.orderedInsert('queue', element, 0, options);

for (const machine of [nodeA, nodeB]) {
  insertOn(machine, 'm', { id: { node: 'node-a2', seq: 1, ts: 2000 } });
  insertOn(machine, 'n', { id: { node: 'node-a2', seq: 2, ts: 2000 }, deps: seedDeps });
}
// Each machine's own concurrent top insert.
insertOn(nodeA, 'p', { id: { node: 'node-a2', seq: 4, ts: 4001 }, deps: [...seedDeps] });
insertOn(nodeB, 'q', { id: { node: 'node-b', seq: 1, ts: 4002 }, deps: [...seedDeps] });
// Cross-replay of the two divergent inserts.
insertOn(nodeA, 'q', { id: { node: 'node-b', seq: 1, ts: 4002 }, deps: [...seedDeps] });
insertOn(nodeB, 'p', { id: { node: 'node-a2', seq: 4, ts: 4001 }, deps: [...seedDeps] });

const orderA = read(nodeA, 'queue');
const orderB = read(nodeB, 'queue');
assert.strictEqual(orderA.join(','), orderB.join(','),
  `divergent orders must converge: [${orderA}] vs [${orderB}]`);
for (const wanted of ['p', 'q']) {
  assert.ok(orderA.includes(wanted),
    `concurrent insert ${wanted} was silently lost (got [${orderA}])`);
}
console.log(`reorderable-list OK: concurrent inserts both survive, both replicas converged -> [${orderA}]`);