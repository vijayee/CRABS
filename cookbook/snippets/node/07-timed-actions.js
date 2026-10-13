'use strict';
// Recipe 7 — timed actions (crabs-node, run in Node).
// A signed op is queued with a due time; schedule() validates it AT
// SUBMISSION (policy + signature + key version, via
// state_machine_validate), so no signer needs to be online at fire time.
// A tick materializes what's due with the authorization step SKIPPED —
// fires re-run only the domain check and the engine's guards.
// crabs-node has no registerHandlerJs surface: the scheduled 'mint' op
// drives the machine's wildcard path (a policy-authorized type naming an
// existing resource), and each materialized slot is observable as a
// 'schedule'-kind change event — the fire ledger this demo asserts on
// (submission events say "scheduled at <ms>"; fire events say
// "scheduled <op> <resource>"). Ticks are EXPLICIT in this demo:
// processSchedules(nowMs) is the machine's clock poke; it never reads the
// wall clock. A one-off mint, a cancel, a recurring 3-fire series, and the
// per-tick occurrence budget — the same scenarios as the wasm demo.

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../../../bindings/node');

const node = new Node('admin', { ordering: 'hlc' });

const aliceKey = KeyPair.generate();
node.registerUser('alice', aliceKey.publicKeyHex(), '');
node.grantRole('alice', 'role', 'member', 'admin');

// The timed effect: a policy-authorized 'mint' op naming a real resource.
// Authorization happens NOW, at submission (the wrapper's
// state_machine_validate gate); materialization needs the op to still
// resolve through the engine, so the signer + policy + resource are all in
// place before scheduling.
node.addCounter('tokens');
node.setPolicy('mint', 'role:member');

const signMint = () => {
  const inner = new Operation('mint');
  inner.signerId = 'alice';
  inner.addResource('tokens');
  node.sign(inner, aliceKey);
  return inner;
};

// The fire ledger: every materialized slot (or durable failure) fires a
// kind-'schedule' change event. Submission events preview as
// "scheduled at <ms>"; a materialized slot previews as "scheduled <op>".
const fires = [];
let failures = 0;
node.on('change', (changeEvent) => {
  if (changeEvent.kind !== 'schedule') return;
  if (changeEvent.type === '__schedule_failed__') { failures += 1; return; }
  if (changeEvent.type === 'mint' &&
      !changeEvent.preview.startsWith('scheduled at ')) {
    fires.push(changeEvent);
  }
});

// Fixed demo clock — processSchedules takes nowMs explicitly, so the demo
// never depends on the wall clock (schedules.js:30 idiom).
const now = 1000000000000;

// One-off: mint in +60s.
const scheduleId = node.schedule(signMint(), now + 60000);
assert(scheduleId > 0n, 'schedule must return a positive id');
assert.strictEqual(node.pendingSchedules().length, 1);
assert.strictEqual(node.pendingSchedules()[0].submitter, 'alice');
assert.strictEqual(node.pendingSchedules()[0].executeAt, BigInt(now + 60000));

// Not due yet: nothing materializes.
node.processSchedules(now);
assert.strictEqual(node.pendingSchedules().length, 1);
assert.strictEqual(fires.length, 0, 'nothing may fire before the due time');

// Due: materializes exactly once.
node.processSchedules(now + 60001);
assert.strictEqual(node.pendingSchedules().length, 0);
assert.strictEqual(fires.length, 1, 'exactly one mint must land');
// Idempotent: another tick re-materializes nothing.
node.processSchedules(now + 60002);
assert.strictEqual(fires.length, 1, 'a materialized op must not run twice');

// Cancel: a queued change of plans must be retrievable before due.
const cancelId = node.schedule(signMint(), now + 120000);
node.cancelSchedule(cancelId);
assert.strictEqual(node.pendingSchedules().length, 0);
// And it must stay materialized-away: tick past the would-be due time.
node.processSchedules(now + 120001);
assert.strictEqual(fires.length, 1,
  'a cancelled schedule must never materialize');

// Recurring: 3 fires at 1s intervals, driven by injected ticks. The whole
// catch-up fires IN ORDER in one tick, then the series is exhausted.
const recurringId = node.scheduleRecurring(signMint(), now + 1000, 1000, 3, 0);
assert(recurringId > 0n, 'scheduleRecurring must return a positive id');
const recurringRow = node.pendingSchedules()[0];
assert.strictEqual(recurringRow.intervalMs, 1000n);
assert.strictEqual(recurringRow.repeatCount, 3n);
assert.strictEqual(recurringRow.endAt, 0n);
assert.strictEqual(recurringRow.executeAt, BigInt(now + 1000));

node.processSchedules(now);            // not due: still pending
assert.strictEqual(node.pendingSchedules().length, 1);
assert.strictEqual(fires.length, 1);
node.processSchedules(now + 3500);     // catch-up: all 3 slots in order
assert.strictEqual(node.pendingSchedules().length, 0);
assert.strictEqual(fires.length, 4,
  'expected 1 one-off + 3 recurring mints');
assert.strictEqual(failures, 0, 'every slot must fire cleanly');

// Occurrence budget: bounds the per-tick catch-up burst. Slots 1000 and
// 2000 fire in the first tick; slot 3000 stays pending at its exact slot
// until the budget is lifted (schedules.js:84-93).
node.scheduleRecurring(signMint(), now + 1000, 1000, 3, 0);
node.setScheduleOccurrenceBudget(2);
assert.strictEqual(node.scheduleOccurrenceBudget(), 2);
node.processSchedules(now + 3500);
assert.strictEqual(node.pendingSchedules().length, 1,
  'the budget must defer the third slot, keeping it pending');
assert.strictEqual(fires.length, 6,  // 4 earlier fires + 2 budgeted
  'budget must cap the per-tick burst');
node.setScheduleOccurrenceBudget(0);   // 0 = unlimited
node.processSchedules(now + 3500);     // the deferred slot fires now
assert.strictEqual(node.pendingSchedules().length, 0);
assert.strictEqual(fires.length, 7,
  'deferred slot must fire once the budget lifts');
assert.strictEqual(failures, 0);

console.log('timed-actions OK: one-off + cancel + recurring + budget ' +
            scheduleId + '/' + recurringId);