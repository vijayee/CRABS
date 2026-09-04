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
  node.registerHandlerJs('mint', (state) => {
    state.incrementCounter('tokens', 1, 'alice');
    return 0;
  });

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

  // Recurring: 3-fire series with 1s interval, driven by injected ticks.
  const recurring = await Operation.create('mint');
  recurring.signerId = 'alice';
  recurring.nodeId = 'alice';
  node.sign(recurring, key.privateKeyHex());
  const recurringId = node.scheduleRecurring(recurring, now + 1000, 1000, 3, 0);
  assert.ok(recurringId > 0n, 'scheduleRecurring must return a positive id');

  const recurringRow = node.pendingSchedules()[0];
  assert.strictEqual(recurringRow.intervalMs, 1000n);
  assert.strictEqual(recurringRow.repeatCount, 3n);
  assert.strictEqual(recurringRow.endAt, 0n);
  assert.strictEqual(recurringRow.executeAt, BigInt(now + 1000));

  // Not due yet: still pending, nothing materialized.
  node.processSchedules(now);
  assert.strictEqual(node.pendingSchedules().length, 1);

  // Catch-up: all 3 slots (1000/2000/3000) fire in order, then the
  // series is exhausted and the row disappears.
  node.processSchedules(now + 3500);
  assert.strictEqual(node.pendingSchedules().length, 0);

  // Occurrence budget: bounds the per-tick catch-up burst and carries the
  // deferred slots over to the next tick.
  const budgeted = await Operation.create('mint');
  budgeted.signerId = 'alice';
  budgeted.nodeId = 'alice';
  node.sign(budgeted, key.privateKeyHex());
  const budgetId = node.scheduleRecurring(budgeted, now + 1000, 1000, 3, 0);
  node.setScheduleOccurrenceBudget(2);
  assert.strictEqual(node.scheduleOccurrenceBudget(), 2);
  node.processSchedules(now + 3500);
  // Slots 1000 and 2000 fire; slot 3000 stays pending on its exact slot.
  assert.strictEqual(node.pendingSchedules().length, 1);
  assert.strictEqual(node.getCounter('tokens'), 6);  // 4 earlier fires + 2 budgeted
  node.setScheduleOccurrenceBudget(0);  // unlimited: the deferred slot fires now
  node.processSchedules(now + 3500);
  assert.strictEqual(node.pendingSchedules().length, 0);
  assert.strictEqual(node.getCounter('tokens'), 7);

  console.log('schedules smoke OK: id=' + scheduleId +
              ' recurring=' + recurringId);
  process.exit(0);
}

main().catch(e => { console.error(e); process.exit(1); });