'use strict';
// Recipe 7 — timed actions (crabs-wasm, run in Node).
// Schedules are a wasm-only surface (api-map §6): a signed op is queued with
// a due time; every tick materializes what's due — through the machine's full
// authorization (the embedded op was signed, so nothing is bypassed).
// Ticks are EXPLICIT in this demo: processSchedules(nowMs) is the machine's
// clock poke, mirroring bindings/wasm/test/schedules.js. A one-off mint,
// a cancel, a recurring 3-fire series, and the per-tick occurrence budget.

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../../../bindings/wasm');

async function main() {
  const node = await Node.create('admin', { ordering: 'hlc' });

  const aliceKey = await KeyPair.generate();
  node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'admin');

  // The timed effect: a 'mint' op incrementing a counter.
  node.addCounter('tokens');
  node.setPolicy('mint', 'role:member');
  node.registerHandlerJs('mint', (state) => {
    state.incrementCounter('tokens', 1, 'alice');
    return 0;
  });

  // The signing happens NOW, at submission; materialization replays the
  // signed bytes. A zero-payload sign with a stale/no policy would fail at
  // materialization (recorded, not propagated), so the op is fully
  // authorized here: signer + policy + handler.
  const scheduleMint = async (executeAtMs) => {
    const inner = await Operation.create('mint');
    inner.signerId = 'alice';
    inner.nodeId = 'alice';
    node.sign(inner, aliceKey.privateKeyHex());
    return node.schedule(inner, executeAtMs);
  };

  // Fixed demo clock — processSchedules takes nowMs explicitly, so the demo
  // never depends on the wall clock (schedules.js:30 idiom).
  const now = 1000000000000;

  // One-off: mint in +60s.
  const scheduleId = await scheduleMint(now + 60000);
  assert(scheduleId > 0n, 'schedule must return a positive id');
  assert.strictEqual(node.pendingSchedules().length, 1);
  assert.strictEqual(node.pendingSchedules()[0].submitter, 'alice');
  assert.strictEqual(node.pendingSchedules()[0].executeAt, BigInt(now + 60000));

  // Not due yet: nothing materializes.
  node.processSchedules(now);
  assert.strictEqual(node.pendingSchedules().length, 1);
  if (node.getCounter('tokens') !== 0) {
    throw new Error('nothing may materialize before the due time');
  }

  // Due: materializes exactly once.
  node.processSchedules(now + 60001);
  assert.strictEqual(node.pendingSchedules().length, 0);
  if (node.getCounter('tokens') !== 1) {
    throw new Error(`expected the mint to land once, got ${node.getCounter('tokens')}`);
  }
  // Idempotent: another tick re-materializes nothing.
  node.processSchedules(now + 60002);
  if (node.getCounter('tokens') !== 1) {
    throw new Error('a materialized op must not run twice');
  }

  // Cancel: a queued change of plans must be retrievable before due.
  const cancelId = await scheduleMint(now + 120000);
  node.cancelSchedule(cancelId);
  assert.strictEqual(node.pendingSchedules().length, 0);

  // Recurring: 3 fires at 1s intervals, driven by injected ticks. The whole
  // catch-up fires IN ORDER in one tick, then the series is exhausted.
  const recurringInner = await Operation.create('mint');
  recurringInner.signerId = 'alice';
  recurringInner.nodeId = 'alice';
  node.sign(recurringInner, aliceKey.privateKeyHex());
  const recurringId = node.scheduleRecurring(recurringInner, now + 1000, 1000, 3, 0);
  assert(recurringId > 0n, 'scheduleRecurring must return a positive id');
  const recurringRow = node.pendingSchedules()[0];
  assert.strictEqual(recurringRow.intervalMs, 1000n);
  assert.strictEqual(recurringRow.repeatCount, 3n);
  assert.strictEqual(recurringRow.endAt, 0n);
  assert.strictEqual(recurringRow.executeAt, BigInt(now + 1000));

  node.processSchedules(now);            // not due: still pending
  assert.strictEqual(node.pendingSchedules().length, 1);
  node.processSchedules(now + 3500);     // catch-up: all 3 slots
  assert.strictEqual(node.pendingSchedules().length, 0);
  if (node.getCounter('tokens') !== 4) {
    throw new Error(`expected 1 one-off + 3 recurring mints, got ${node.getCounter('tokens')}`);
  }

  // Occurrence budget: bounds the per-tick catch-up burst. Slots 1000 and
  // 2000 fire in the first tick; slot 3000 stays pending at its exact slot
  // until the budget is lifted (schedules.js:84-93).
  const budgetedInner = await Operation.create('mint');
  budgetedInner.signerId = 'alice';
  budgetedInner.nodeId = 'alice';
  node.sign(budgetedInner, aliceKey.privateKeyHex());
  const budgetedId = node.scheduleRecurring(budgetedInner, now + 1000, 1000, 3, 0);
  node.setScheduleOccurrenceBudget(2);
  assert.strictEqual(node.scheduleOccurrenceBudget(), 2);
  node.processSchedules(now + 3500);
  assert.strictEqual(node.pendingSchedules().length, 1);
  if (node.getCounter('tokens') !== 6) {  // 4 earlier fires + 2 budgeted
    throw new Error(`budget must cap the per-tick burst, got ${node.getCounter('tokens')}`);
  }
  node.setScheduleOccurrenceBudget(0);   // 0 = unlimited
  node.processSchedules(now + 3500);     // the deferred slot fires now
  assert.strictEqual(node.pendingSchedules().length, 0);
  if (node.getCounter('tokens') !== 7) {
    throw new Error(`deferred slot must fire once the budget lifts, got ${node.getCounter('tokens')}`);
  }

  console.log('timed-actions OK: one-off + cancel + recurring + budget ' +
              scheduleId.toString() + '/' + recurringId.toString() + '/' + budgetedId.toString());
  node.destroy();
  aliceKey.destroy();
}
main()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });