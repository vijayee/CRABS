//
// ordered-set.js — OT_ORDERED_SET surface on crabs-node (recipe 8).
// Mirror of bindings/wasm/test/ordered-set.js over the direct-C binding:
// sequential inserts keep their order, MOVE 0->2 re-derives [b,c,a], SWAP is
// a local value exchange, DELETE tombstones in place, a replayed op id is a
// no-op, and two machines exchanging their ops (with the causal deps the C
// transform requires) converge on one identical order through the
// __execute_ot__ executor. Merge-level guarantees (conflicting-payload
// refusal, merge commutativity) stay C-only — see recipe 8's notes.
//

'use strict';

const assert = require('assert');
const { Node } = require('..');

const node = new Node('node-a', { ordering: 'hlc' });
node.setPolicy('__execute_ot__', 'role:admin');
node.addOrderedSet('list');

const read = (machine, name) => machine.getOrderedSet(name).elements;
const assertOrder = (machine, name, expected, what) => {
  assert.deepStrictEqual(read(machine, name), expected, `${what}: expected [${expected}]`);
};

// ---- Seed [a, b, c] and read it back --------------------------------------
node.orderedInsert('list', 'a', 0, { id: { node: 'node-a', seq: 1, ts: 1000 } });
node.orderedInsert('list', 'b', 1, { id: { node: 'node-a', seq: 2, ts: 1000 } });
node.orderedInsert('list', 'c', 2, { id: { node: 'node-a', seq: 3, ts: 1000 } });
assertOrder(node, 'list', ['a', 'b', 'c'], 'seed inserts must keep their order');

// ---- MOVE 0->2 ([a,b,c] -> [b,c,a]); sequential ops share the machine's id
node.orderedMove('list', 0, 2, { id: { node: 'node-a', seq: 4, ts: 1001 } });
assertOrder(node, 'list', ['b', 'c', 'a'], 'MOVE 0->2');

// ---- SWAP is a local value exchange of two positions ----------------------
node.orderedSwap('list', 0, 2, { id: { node: 'node-a', seq: 5, ts: 1002 } });
assertOrder(node, 'list', ['a', 'c', 'b'], 'SWAP 0<->2');

// ---- DELETE tombstones in place -------------------------------------------
node.orderedDelete('list', 1, { id: { node: 'node-a', seq: 6, ts: 1003 } });
assertOrder(node, 'list', ['a', 'b'], 'DELETE at 1');
node.orderedInsert('list', 'd', 2, { id: { node: 'node-a', seq: 7, ts: 1004 } });
assertOrder(node, 'list', ['a', 'b', 'd'], 'insert after delete');

// ---- Replaying the SAME op id is a silent no-op ---------------------------
node.orderedMove('list', 0, 2, { id: { node: 'node-a', seq: 4, ts: 1001 } });
assertOrder(node, 'list', ['a', 'b', 'd'], 'replayed op id is idempotent');

// ---- Argument guards -------------------------------------------------------
assert.throws(() => node.orderedSwap('list', 0, 1, null),
  /id is required/, 'swap without op id');
assert.throws(() => node.orderedInsert('list', 'x', 0, { id: {} }),
  /id\.node is required/, 'insert without id.node');
assert.throws(() => node.orderedInsert('list', 'x', 0, { id: { node: 'node-a' } }),
  /id\.seq is required/, 'insert without id.seq');
assert.throws(() => node.getOrderedSet('no-such-item'),
  /resource_not_found/, 'read unknown item');
assert.throws(() => node.orderedDelete('list', 99,
  { id: { node: 'node-a', seq: 9 } }),
  /ot_position_bounds|invalid_param/, 'delete past the end');

// ---- A machine without the op-type policy refuses the op ------------------
const unpoliced = new Node('node-plain', { ordering: 'hlc' });
unpoliced.addOrderedSet('list');
assert.throws(() => unpoliced.orderedInsert('list', 'a', 0,
  { id: { node: 'node-plain', seq: 1 } }),
  /unauthorized/, '__execute_ot__ without a policy');

// ---- Two machines converge by exchanging ops ------------------------------
const nodeA = new Node('node-a2', { ordering: 'hlc' });
const nodeB = new Node('node-b', { ordering: 'hlc' });
for (const machine of [nodeA, nodeB]) {
  machine.setPolicy('__execute_ot__', 'role:admin');
  machine.addOrderedSet('queue');
}
const seedDeps = [{ node: 'node-a', seq: 1 }, { node: 'node-a', seq: 2 }];
const insertOn = (machine, element, options) =>
  machine.orderedInsert('queue', element, 0, options);

for (const machine of [nodeA, nodeB]) {
  insertOn(machine, 'm', { id: { node: 'node-a', seq: 1, ts: 2000 } });
}
insertOn(nodeA, 'n', { id: { node: 'node-a', seq: 2, ts: 2000 }, deps: seedDeps });
insertOn(nodeB, 'n', { id: { node: 'node-a', seq: 2, ts: 2000 }, deps: seedDeps });

insertOn(nodeA, 'p', {
  id: { node: 'node-a', seq: 4, ts: 4001 }, deps: [...seedDeps]
});
insertOn(nodeB, 'q', {
  id: { node: 'node-b', seq: 1, ts: 4002 }, deps: [...seedDeps]
});

// Cross-replay of the two divergent inserts; deps are the causal context the
// ISSUER had at issue time — never the peer op being merged against.
insertOn(nodeA, 'q', {
  id: { node: 'node-b', seq: 1, ts: 4002 }, deps: [...seedDeps]
});
insertOn(nodeB, 'p', {
  id: { node: 'node-a', seq: 4, ts: 4001 }, deps: [...seedDeps]
});

const orderA = read(nodeA, 'queue');
const orderB = read(nodeB, 'queue');
assert.strictEqual(orderA.join(','), orderB.join(','),
  `convergence: [${orderA}] vs [${orderB}]`);
for (const wanted of ['p', 'q']) {
  assert.ok(orderA.includes(wanted),
    `convergence: ${wanted} was silently lost (got [${orderA}])`);
}
console.log(`ordered-set OK: concurrent inserts both survive and converge -> [${orderA}]`);

console.log('ordered-set OK: seed, move, swap, delete, idempotent replay, convergence');