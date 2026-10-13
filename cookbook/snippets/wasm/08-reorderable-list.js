'use strict';
// Recipe 8 — a reorderable list two people can edit at once (crabs-wasm, run
// in Node). The OT_ORDERED_SET surface drives the same op vocabulary the C
// snippet applies directly (INSERT / DELETE / MOVE / SWAP): each ordered*
// call composes, node-key-signs and executes a __execute_ot__ op through the
// machine, so every op is authorized (policy), deduplicated (op uuid) and
// journalled in the item's op log — and readbacks read the materialized
// order, tombstones skipped.
//
// What the executor-level demo shows here: sequential inserts keep their
// order, MOVE 0->2 re-derives [b,c,a], a replayed op id is a silent no-op,
// and two machines EXCHANGING their ops (each carrying the causal deps the
// issuing replica had) converge on one identical order through the transform
// tie-break. The merge-level guarantees that live in
// crabs_ot_ordered_set_merge — merge commutativity by construction,
// conflicting-payload refusal — remain C-only (recipe 8 keeps that caveat).

const assert = require('assert');
const { Node } = require('../../../bindings/wasm');

async function main() {
  const node = await Node.create('node-a', { ordering: 'hlc' });
  // The ordered* sugar signs as the machine's bootstrap admin via the node
  // key (the createTrigger idiom) — the __execute_ot__ op type needs a
  // policy first, or the executor refuses every op with unauthorized.
  node.setPolicy('__execute_ot__', 'role:admin');
  node.addOrderedSet('list');

  const read = (machine, name) => machine.getOrderedSet(name).elements;

  // ---- Three seed inserts; elements are addressed by op id + position ----
  node.orderedInsert('list', 'a', 0, { id: { node: 'node-a', seq: 1, ts: 1000 } });
  node.orderedInsert('list', 'b', 1, { id: { node: 'node-a', seq: 2, ts: 1000 } });
  node.orderedInsert('list', 'c', 2, { id: { node: 'node-a', seq: 3, ts: 1000 } });
  assert.deepStrictEqual(read(node, 'list'), ['a', 'b', 'c'],
    'seed inserts must keep their order');

  // ---- MOVE 0->2: [a, b, c] -> [b, c, a] -----------------------------------
  // Sequential locals ops share this machine's op-id node: the executor
  // skips same-node lower-sequence log ops as causally ordered, so the move
  // applies at its raw position.
  node.orderedMove('list', 0, 2, { id: { node: 'node-a', seq: 4, ts: 1001 } });
  assert.deepStrictEqual(read(node, 'list'), ['b', 'c', 'a'], 'MOVE 0->2');

  // ---- A replayed op id is a silent no-op ----------------------------------
  // The executor skips an op whose id is already in the item's op log
  // (ot_execution.c _op_already_applied) — no duplicate, no reshuffle.
  node.orderedMove('list', 0, 2, { id: { node: 'node-a', seq: 4, ts: 1001 } });
  assert.deepStrictEqual(read(node, 'list'), ['b', 'c', 'a'],
    'replayed op id is idempotent');

  // ---- SWAP is a local value exchange of two positions ---------------------
  // Not a placement op: the payloads trade, ids stay put
  // (ot_ordered_set.c SwapElements). It converges only as far as the recipe's
  // placement caveat says — demo it locally, exactly like the C snippet.
  node.orderedSwap('list', 0, 2, { id: { node: 'node-a', seq: 5, ts: 1002 } });
  assert.deepStrictEqual(read(node, 'list'), ['a', 'c', 'b'], 'SWAP 0<->2');
  console.log('reorderable-list OK: local MOVE -> [b,c,a], replay no-op, SWAP -> [a,c,b]');

  // ---- Two machines converge by exchanging ops, not arrays ----------------
  // Both replicas execute the same seed ops (same op ids — replays of them
  // are idempotent skips), then each issues ONE concurrent insert at the
  // top: A's 'p', B's 'q'. Replays carry the issuing replica's causal
  // context in deps — without them the transform would treat the seed ops
  // as concurrent and shift everything wrongly. Concurrent inserts at the
  // same position are resolved by the insert-insert tie-break (priority,
  // then op-id node bytes) — exactly one replica shifts, so both converge.
  const nodeA = await Node.create('node-a2', { ordering: 'hlc' });
  const nodeB = await Node.create('node-b', { ordering: 'hlc' });
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

  node.destroy();
  nodeA.destroy();
  nodeB.destroy();
}
main()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });