'use strict';

// Ordered set (OT_ORDERED_SET) surface from JS (recipe 8).
// Mirrors the C scenarios in test/test_ot_ordered_set.cpp and the C snippet
// cookbook/snippets/c/08-reorderable-list.c: sequential inserts keep their
// order, MOVE 0->2 re-derives [b,c,a] locally, SWAP is a local value
// exchange, DELETE tombstones in place, a replayed op id is a no-op, and two
// machines exchanging their ops (with the causal deps the C transform
// requires) converge on one identical order through plain __execute_ot__
// execution. Merge-level guarantees that live in crabs_ot_ordered_set_merge
// (conflicting-payload refusal, merge commutativity by construction) remain
// C-only — see recipe 8's notes.

const { Node } = require('..');

(async () => {
  // ---- Scenario 1: seed [a, b, c] and read it back ------------------------
  const node = await Node.create('node-a', { ordering: 'hlc' });
  node.setPolicy('__execute_ot__', 'role:admin');
  node.addOrderedSet('list');

  node.orderedInsert('list', 'a', 0, { id: { node: 'node-a', seq: 1, ts: 1000 } });
  node.orderedInsert('list', 'b', 1, { id: { node: 'node-a', seq: 2, ts: 1000 } });
  node.orderedInsert('list', 'c', 2, { id: { node: 'node-a', seq: 3, ts: 1000 } });

  const read = (machine, name) => machine.getOrderedSet(name).elements;
  const assertOrder = (machine, name, expected, what) => {
    const elements = read(machine, name);
    if (elements.join(',') !== expected.join(',')) {
      throw new Error(`${what}: expected [${expected}], got [${elements}]`);
    }
  };
  assertOrder(node, 'list', ['a', 'b', 'c'], 'seed inserts must keep their order');

  // ---- Scenario 2: MOVE 0->2 re-positions locally ([a,b,c] -> [b,c,a]) ----
  // Sequential ops from this machine share its op-id node ('node-a'): the
  // executor skips same-node lower-sequence log ops as causally ordered
  // (ot_transform.c), so the MOVE applies at its raw position. A cross-node
  // id here (a different author) would transform the move against the seeds
  // instead — that asymmetry is exactly why replays must carry deps.
  node.orderedMove('list', 0, 2, { id: { node: 'node-a', seq: 4, ts: 1001 } });
  assertOrder(node, 'list', ['b', 'c', 'a'], 'MOVE 0->2');

  // ---- Scenario 3: SWAP is a local value exchange of two positions --------
  node.orderedSwap('list', 0, 2, { id: { node: 'node-a', seq: 5, ts: 1002 } });
  assertOrder(node, 'list', ['a', 'c', 'b'], 'SWAP 0<->2');

  // ---- Scenario 4: DELETE tombstones in place ------------------------------
  node.orderedDelete('list', 1, { id: { node: 'node-a', seq: 6, ts: 1003 } });
  assertOrder(node, 'list', ['a', 'b'], 'DELETE at 1');
  node.orderedInsert('list', 'd', 2, { id: { node: 'node-a', seq: 7, ts: 1004 } });
  assertOrder(node, 'list', ['a', 'b', 'd'], 'insert after delete');

  // ---- Scenario 5: replaying the SAME op id is a silent no-op --------------
  // The executor skips an op whose id is already in the item's op log
  // (ot_execution.c _op_already_applied) — the replayed MOVE must not
  // duplicate or reshuffle anything.
  node.orderedMove('list', 0, 2, { id: { node: 'reorderer', seq: 4, ts: 1001 } });
  assertOrder(node, 'list', ['a', 'b', 'd'], 'replayed op id is idempotent');

  // ---- Argument guards ------------------------------------------------------
  const mustThrowWith = (invoke, fragment, label) => {
    let caught = null;
    try { invoke(); } catch (caughtError) { caught = caughtError; }
    if (!caught) throw new Error(`${label}: expected a throw`);
    if (!caught.message.includes(fragment)) {
      throw new Error(`${label}: expected "${fragment}", got "${caught.message}"`);
    }
  };

  // An op id is required — the C surface addresses elements by explicit
  // (node, seq) identity; there is no silent auto-id to collide behind us.
  mustThrowWith(() => node.orderedSwap('list', 0, 1, null),
    'id is required', 'swap without op id');
  mustThrowWith(() => node.orderedInsert('list', 'x', 0, { id: {} }),
    'id.node is required', 'insert without id.node');
  mustThrowWith(() => node.orderedInsert('list', 'x', 0,
    { id: { node: 'node-a' } }),
    'id.seq is required', 'insert without id.seq');
  mustThrowWith(() => node.orderedInsert('list', 'x'.repeat(4097), 0,
    { id: { node: 'node-a', seq: 6 } }),
    'element payload exceeds', 'oversize element');
  mustThrowWith(() => node.getOrderedSet('no-such-item'),
    'resource_not_found', 'read unknown item');
  mustThrowWith(() => node.orderedDelete('list', 99,
    { id: { node: 'node-a', seq: 7 } }),
    'ot_position_bounds', 'delete past the end');

  // ---- A machine without the op-type policy refuses the op ----------------
  const unpoliced = await Node.create('node-plain', { ordering: 'hlc' });
  unpoliced.addOrderedSet('list');
  mustThrowWith(() => unpoliced.orderedInsert('list', 'a', 0,
    { id: { node: 'node-plain', seq: 1 } }),
    'unauthorized', '__execute_ot__ without a policy');
  unpoliced.destroy();

  // ---- Deps are carried on the wire: a dep-declared replay skips the ------
  // transform for everything it names (ot_transform.c crabs_op_depends_on) —
  // the replayed insert applies at its RAW position (0 → head), not at the
  // transformed shifted one. Pin: x before m, not [m, x].
  const depNode = await Node.create('dep-check', { ordering: 'hlc' });
  depNode.setPolicy('__execute_ot__', 'role:admin');
  depNode.addOrderedSet('deps-list');
  depNode.orderedInsert('deps-list', 'm', 0, { id: { node: 'dep-check', seq: 1, ts: 2000 } });
  depNode.orderedInsert('deps-list', 'x', 0,
    { id: { node: 'remote-node', seq: 1, ts: 5 }, deps: [{ node: 'dep-check', seq: 1 }] });
  assertOrder(depNode, 'deps-list', ['x', 'm'],
    'dep-declared replay must skip the transform (deps travel the wire)');
  depNode.destroy();

  // ---- Scenario 6: two machines converge by exchanging ops -----------------
  // Each machine executes the same three seed ops (same op ids, so replays
  // of them are idempotent skips), then each issues ONE concurrent insert at
  // the top. Replays carry the issuing machine's causal context in `deps` —
  // without them the transform would treat the seed ops as concurrent and
  // shift positions wrongly (that is the executor contract; the merge-based
  // merge guarantees stay C-side). Both machines must materialize one
  // identical order containing both inserts.
  const nodeA = await Node.create('node-a2', { ordering: 'hlc' });
  const nodeB = await Node.create('node-b', { ordering: 'hlc' });
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

  // Each machine's own concurrent top insert (each causally after the seeds).
  insertOn(nodeA, 'p', {
    id: { node: 'node-a', seq: 4, ts: 4001 }, deps: [...seedDeps]
  });
  insertOn(nodeB, 'q', {
    id: { node: 'node-b', seq: 1, ts: 4002 }, deps: [...seedDeps]
  });

  // Cross-replay of the two divergent inserts. deps are the causal context
  // the ISSUER had at issue time — never the peer op being merged against
  // (declaring that a dependency would silently cancel the concurrency and
  // skip the tie-break transform). q's only causal context is the seeds it
  // was issued after on nodeB; p's is the same seed set.
  insertOn(nodeA, 'q', {
    id: { node: 'node-b', seq: 1, ts: 4002 }, deps: [...seedDeps]
  });
  insertOn(nodeB, 'p', {
    id: { node: 'node-a', seq: 4, ts: 4001 }, deps: [...seedDeps]
  });

  const orderA = read(nodeA, 'queue');
  const orderB = read(nodeB, 'queue');
  if (orderA.join(',') !== orderB.join(',')) {
    throw new Error(`convergence: [${orderA}] vs [${orderB}]`);
  }
  for (const wanted of ['p', 'q']) {
    if (!orderA.includes(wanted)) {
      throw new Error(`convergence: ${wanted} was silently lost (got [${orderA}])`);
    }
  }
  console.log(`ordered-set OK: concurrent inserts both survive and converge -> [${orderA}]`);

  node.destroy();
  nodeA.destroy();
  nodeB.destroy();

  console.log('ordered-set OK: seed, move, swap, delete, idempotent replay, convergence');
})()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });