//
// schedules.js — smoke test for timed transactions through the WASM bindings.
//
// Schedules a signed op 60s out via node.schedule(); verifies pendingSchedules,
// processSchedules before/after due, and cancelSchedule.
//

'use strict';

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../dev.js');

async function main() {
  const node = await Node.create('admin', { ordering: 'hlc' });
  node.addCounter('tokens');
  const key = await KeyPair.generate();
  node.registerUser('alice', key.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'admin');
  node.setPolicy('mint', 'role:member');

  const inner = await Operation.create('mint');
  inner.signerId = 'alice';
  inner.nodeId = 'alice';
  node.sign(inner, key.privateKeyHex());

  const now = 1000000000000;
  const scheduleId = node.schedule(inner, now + 60000);
  assert.ok(scheduleId > 0n, 'schedule must return a positive id');
  assert.strictEqual(node.pendingSchedules().length, 1);
  assert.strictEqual(node.pendingSchedules()[0].submitter, 'alice');
  assert.strictEqual(node.pendingSchedules()[0].executeAt, BigInt(now + 60000));

  // Not due yet: nothing materializes.
  node.processSchedules(now);
  assert.strictEqual(node.pendingSchedules().length, 1);

  // Due: materializes.
  node.processSchedules(now + 60001);
  assert.strictEqual(node.pendingSchedules().length, 0);

  // Cancel path: schedule another and cancel it.
  const inner2 = await Operation.create('mint');
  inner2.signerId = 'alice';
  inner2.nodeId = 'alice';
  node.sign(inner2, key.privateKeyHex());
  const cancelId = node.schedule(inner2, now + 120000);
  node.cancelSchedule(cancelId);
  assert.strictEqual(node.pendingSchedules().length, 0);

  console.log('schedules smoke OK: id=' + scheduleId);
  process.exit(0);
}

main().catch(e => { console.error(e); process.exit(1); });