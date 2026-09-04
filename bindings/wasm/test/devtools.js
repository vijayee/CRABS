//
// devtools.js — smoke test for the dev/prod artifact split.
//
// Production artifact must NOT expose devtools exports; dev artifact must,
// and drain + snapshot must return valid JSON.
//

'use strict';

const assert = require('assert');

async function main() {
  const prod = require('../index.js');
  const prodM = await prod.getModule();
  assert.strictEqual(typeof prodM._crabs_wasm_devtools_snapshot, 'undefined',
    'production artifact must not expose devtools exports');
  assert.strictEqual(typeof prodM._crabs_wasm_devtools_drain_events, 'undefined',
    'production artifact must not expose devtools exports');
  assert.strictEqual(typeof prodM._crabs_wasm_devtools_string_destroy, 'undefined',
    'production artifact must not expose devtools exports');
  console.log('prod artifact: devtools exports correctly absent');

  const dev = require('../dev.js');
  const devM = await dev.getModule();
  assert.strictEqual(typeof devM._crabs_wasm_devtools_snapshot, 'function',
    'dev artifact must expose devtools exports');
  assert.strictEqual(typeof devM._crabs_wasm_devtools_drain_events, 'function',
    'dev artifact must expose devtools exports');
  assert.strictEqual(typeof devM._crabs_wasm_devtools_string_destroy, 'function',
    'dev artifact must expose devtools exports');

  const drainPtr = devM._crabs_wasm_devtools_drain_events();
  const drained = devM.UTF8ToString(drainPtr);
  devM._crabs_wasm_devtools_string_destroy(drainPtr);
  assert.ok(Array.isArray(JSON.parse(drained)),
    'drain must return a JSON array string');
  console.log('dev artifact: devtools exports present, drain returns JSON');

  await testPerNodeDrain(dev, devM);
  console.log('dev artifact: filtered per-node drain isolates events');
}

// Two nodes share the global event ring: executing ops on node A and node B,
// a drain filtered to A's identity must return only A's events and preserve
// B's for a later B-filtered drain.
async function testPerNodeDrain(dev, module) {
  // The bootstrap admin id ('alice'/'bob') is the node's HLC identity: sign
  // stamps it into op->node_id, so the events are attributed per node by it.
  // The actors are regular users with distinct ids.
  const nodeA = await dev.Node.create('alice');
  const nodeB = await dev.Node.create('bob');
  const keyA = await dev.KeyPair.generate();
  const keyB = await dev.KeyPair.generate();
  for (const [node, adminId, actorId, key] of [
    [nodeA, 'alice', 'alice-actor', keyA],
    [nodeB, 'bob', 'bob-actor', keyB],
  ]) {
    node.registerUser(actorId, key.publicKeyHex(), 'adult');
    node.grantRole(actorId, 'role', 'member', adminId);
    node.addCounter('views');
    node.setPolicy('view', 'role:member');
  }

  // Any leftover events from earlier tests in this process must not leak
  // into the per-node assertions below.
  const clearPointer = module._crabs_wasm_devtools_drain_events();
  module._crabs_wasm_devtools_string_destroy(clearPointer);

  for (const [node, actorId, key] of [
    [nodeA, 'alice-actor', keyA],
    [nodeB, 'bob-actor', keyB],
  ]) {
    const operation = await dev.Operation.create('view');
    operation.signerId = actorId;
    node.sign(operation, key);
    node.execute(operation);
    operation.destroy();
  }

  const aliceBatch = drainFor(module, 'alice');
  assert.ok(aliceBatch.length >= 1, 'alice drain must return alice events');
  for (const event of aliceBatch) {
    assert.strictEqual(event.node, 'alice',
      'alice-filtered drain must only contain alice events');
  }

  const bobBatch = drainFor(module, 'bob');
  assert.ok(bobBatch.length >= 1, 'bob events must survive the alice drain');
  for (const event of bobBatch) {
    assert.strictEqual(event.node, 'bob',
      'bob-filtered drain must only contain bob events');
  }

  const leftoverBatch = drainFor(module, 'alice');
  assert.strictEqual(leftoverBatch.length, 0,
    'second alice drain must be empty');
}

function drainFor(module, nodeId) {
  // Exported WASM functions cannot take JS strings directly; route the node
  // id through ccall so it arrives as a heap-allocated C string.
  const pointer = module.ccall('crabs_wasm_devtools_drain_events_for', 'number',
                               ['string'], [nodeId]);
  const text = module.UTF8ToString(pointer);
  module._crabs_wasm_devtools_string_destroy(pointer);
  return JSON.parse(text);
}

main().then(
  () => console.log('devtools smoke test passed'),
  (error) => { console.error(error); process.exit(1); }
);