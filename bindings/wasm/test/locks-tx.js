'use strict';

// Recipe 9 — the treasury/lock/tx-manager surface from JS (wasm).
// Mirrors the C scenarios in cookbook/snippets/c/09-treasury.c and its gtest
// battery (test/test_state_machine.cpp:196-352 lock ceremony, :1153-1211
// atomic across resources; test/test_tx_manager.cpp:225-243 duplicate
// refused): a single live lease, a forged lock claim refused before any
// effect, the lock-modify-verify-unlock ceremony driven with per-slot
// required/next states and the live bearer token as the op's claim, a real
// debit/credit handler applied exactly once under an attached in-memory tx
// manager, and an op naming an unknown resource applying nothing.
//
// Pinned cooperative facts (recipe 9's honesty section): the executor
// verifies the claims an op PRESENTS but forces none — a claim-less custom
// op against a LOCKED resource still executes through the wildcard apply
// (driver discipline); the builtin protocol ops that MUTATE
// (`__extend__`/`__rollback__`/`__unlock__`) are owner-checked by their own
// handlers (R8-S-1).

const assert = require('assert');
const { Node, KeyPair, Operation } = require('..');

// Each executor step surfaces its typed code; assert on the message.
async function expectRefusal(runnable, expected, what) {
  try {
    await runnable();
  } catch (refusal) {
    assert(refusal.message.includes(expected),
      `${what}: expected "${expected}", got: ${refusal.message}`);
    return;
  }
  throw new Error(`${what}: expected a ${expected} refusal, got success`);
}

(async () => {
  // ---- Setup: one machine, a treasurer, the pot policies ------------------
  const node = await Node.create('treasury-node', { ordering: 'hlc' });
  const treasurerKey = await KeyPair.generate();
  node.registerUser('treasurer', treasurerKey.publicKeyHex(), '');
  node.grantRole('treasurer', 'role', 'treasurer', 'treasury-node');

  // NEW surface: wasm can finally mint a lock-capable RESOURCE item (the
  // recipe 9 flip: Node.addResource was node-only). The pot carries protocol
  // state, lock owner/token/expiry and a pre-lock snapshot
  // (src/CRABS/data_model.h:117-133). Seed balances are int64s (raw path —
  // the lock snapshot's 8-byte form).
  node.addResource('treasury', 1000);
  node.addResource('member_pot', 0);
  assert.strictEqual(node.getResource('treasury'), 1000, 'pot seed readback');
  assert.strictEqual(node.getResource('member_pot'), 0, 'member seed readback');

  for (const opType of ['__lock__', '__verify__', '__rollback__', '__unlock__',
                        'observe', 'transfer']) {
    node.setPolicy(opType, 'role:treasurer');
  }

  // The debit/credit: the handler owns the arithmetic (C snippet Demo B);
  // HandlerState.adjustResource mutates the raw int64 the machine guards
  // around, and HandlerOperation.resources names the op's resources.
  const AMOUNT = 100;
  node.registerHandlerJs('transfer', (state, op) => {
    if (op.resources.length !== 2) return 0x5003; // invalid_param
    const balance = state.getResource(op.resources[0]);
    if (balance === undefined) return 0x3002;     // resource_not_found
    if (balance < AMOUNT) return 0x1001;          // protocol_violation
    state.adjustResource(op.resources[0], -AMOUNT);
    state.adjustResource(op.resources[1], AMOUNT);
    return 0;
  });

  // ---- Scenario 1: a handler-less custom op on the IDLE pot is refused ----
  // The wildcard apply only acts on LOCKED resources (recipe 9's gate).
  await expectRefusal(async () => {
    const op = await Operation.create('observe');
    op.signerId = 'treasurer';
    op.addResource('treasury');
    node.sign(op, treasurerKey);
    node.execute(op);
  }, 'protocol_violation', 'un-coordinated observe on an IDLE pot');

  // ---- Scenario 2: exactly one live lease ---------------------------------
  const lock = (resource) => (async () => {
    const op = await Operation.create('__lock__');
    op.signerId = 'treasurer';
    op.addResource(resource);
    node.sign(op, treasurerKey);
    node.execute(op);
  })();
  await lock('treasury');

  const live = node.getLockState('treasury');
  assert.strictEqual(live.protocolState, 'locked', 'lease acquired');
  assert.strictEqual(live.lockOwner, 'treasurer', 'lease owner');
  assert.strictEqual(live.lockTokenHex.length, 64, 'bearer token is 32 bytes');
  assert.ok(live.lockExpiry > 0, 'lease carries an expiry');

  await expectRefusal(() => lock('treasury'), 'protocol_violation',
    're-acquisition of a live lease');

  // ---- Scenario 3: a forged claim is refused before any effect ------------
  await expectRefusal(async () => {
    const op = await Operation.create('observe');
    op.signerId = 'treasurer';
    op.addResource('treasury');
    op.setRequiredState(0, 'locked');
    op.setNextState(0, 'modified');
    op.addLockClaim('treasury', 'ff'.repeat(32));
    node.sign(op, treasurerKey);
    node.execute(op);
  }, 'lock_token_mismatch', 'forged bearer token');
  assert.strictEqual(node.getLockState('treasury').protocolState, 'locked',
    'a refused op must not move the protocol state');

  // ---- Scenario 4: the ceremony completes with the live token -------------
  // Lock → (claim-bearing apply) → Modified → Verified → Idle.
  const apply = await Operation.create('observe');
  apply.signerId = 'treasurer';
  apply.addResource('treasury');
  apply.setRequiredState(0, 'locked');
  apply.setNextState(0, 'modified');
  apply.addLockClaim('treasury', live.lockTokenHex);
  node.sign(apply, treasurerKey);
  node.execute(apply);
  assert.strictEqual(node.getLockState('treasury').protocolState, 'modified',
    'claim-bearing apply advances LOCKED->MODIFIED');

  const ceremony = async (opType, fromState) => {
    const op = await Operation.create(opType);
    op.signerId = 'treasurer';
    op.addResource('treasury');
    op.setRequiredState(0, fromState);
    op.addLockClaim('treasury', node.getLockState('treasury').lockTokenHex);
    node.sign(op, treasurerKey);
    node.execute(op);
  };
  await ceremony('__verify__', 'modified');
  assert.strictEqual(node.getLockState('treasury').protocolState, 'verified',
    '__verify__ promotes MODIFIED->VERIFIED');
  await ceremony('__unlock__', 'verified');
  assert.strictEqual(node.getLockState('treasury').protocolState, 'idle',
    '__unlock__ returns the pot to IDLE');
  assert.strictEqual(node.getLockState('treasury').lockTokenHex, '',
    'unlock clears the bearer token');

  // ---- Scenario 5: apply exactly once under the memory tx manager ---------
  // The manager (attachTxManager('memory')) records committed uuids and
  // refuses duplicates with already_executed; ordering monotonicity remains
  // the post-restart backstop.
  node.attachTxManager('memory');

  const transfer = async () => {
    const op = await Operation.create('transfer');
    op.signerId = 'treasurer';
    op.addResource('treasury');
    op.addResource('member_pot');
    op.setRequiredState(0, 'idle');
    op.setNextState(0, 'idle');
    op.setRequiredState(1, 'idle');
    op.setNextState(1, 'idle');
    node.sign(op, treasurerKey);
    node.execute(op);
    return op;
  };

  const applied = await transfer();
  assert.strictEqual(node.getResource('treasury'), 900, 'debit applied once');
  assert.strictEqual(node.getResource('member_pot'), 100, 'credit applied once');

  await expectRefusal(async () => {
    // Re-executing the SAME signed op bytes: the tx manager's accept step
    // (state_machine.c step 3b) refuses the duplicate uuid.
    node.execute(applied);
  }, 'already_executed', 'duplicate submission of the same signed transfer');
  assert.strictEqual(node.getResource('treasury'), 900, 'no second debit');
  assert.strictEqual(node.getResource('member_pot'), 100, 'no second credit');

  // ---- Scenario 6: all-or-nothing preconditions ---------------------------
  // A poisoned op (unknown second resource) is refused in the step-4
  // precondition pass BEFORE the handler runs: no debit, no credit.
  await expectRefusal(async () => {
    const op = await Operation.create('transfer');
    op.signerId = 'treasurer';
    op.addResource('treasury');
    op.addResource('ghost_treasury');
    op.setRequiredState(0, 'idle');
    op.setNextState(0, 'idle');
    op.setRequiredState(1, 'idle');
    op.setNextState(1, 'idle');
    node.sign(op, treasurerKey);
    node.execute(op);
  }, 'resource_not_found', 'poisoned transfer');
  assert.strictEqual(node.getResource('treasury'), 900, 'poisoned op left the pot');
  assert.strictEqual(node.getResource('member_pot'), 100, 'poisoned op left the member');

  // ---- Scenario 7: the executor's cooperative claim reality ---------------
  // The wildcard apply verifies whichever claims an op presents but forces
  // none: a claim-less custom op naming a LOCKED resource still executes
  // (LOCKED->MODIFIED) — claim discipline is the driver's, verified when
  // present (recipe 9's honesty note pin). The builtin mutating protocol
  // ops are owner-checked by their own handlers (pinned below).
  const claimLess = await Operation.create('observe');
  claimLess.signerId = 'treasurer';
  claimLess.addResource('treasury');
  claimLess.setRequiredState(0, 'locked');
  claimLess.setNextState(0, 'modified');
  await lock('treasury'); // a fresh live lease on the IDLE pot
  node.sign(claimLess, treasurerKey); // AFTER the lease: signing stamps the
  // machine's HLC / ordering time — an op signed before the lease landed
  // reads as "older than a logged op" and the ordering backstop refuses it
  // before any claim check would matter.
  node.execute(claimLess);

  // The builtin owner check: a NON-owner AUTHORIZED signer cannot roll the
  // pot back — op_rollback's own handler refuses lock_owner_mismatch
  // (R8-S-1; the step-5 claim check only runs over claims the op presents).
  // The outsider holds the treasurer role, so the policy passes and the
  // handler check is what stops them.
  const outsiderKey = await KeyPair.generate();
  node.registerUser('outsider', outsiderKey.publicKeyHex(), '');
  node.grantRole('outsider', 'role', 'treasurer', 'treasury-node');
  const sneak = await Operation.create('__rollback__');
  sneak.signerId = 'outsider';
  sneak.addResource('treasury');
  sneak.setRequiredState(0, 'modified');
  node.sign(sneak, outsiderKey);
  await expectRefusal(() => node.execute(sneak), 'lock_owner_mismatch',
    'non-owner cannot drive the builtin protocol');

  console.log('locks-tx OK: mint + readback, single lease, forged claim refused, ceremony completes, apply-once under tx manager, poisoned op applies nothing, cooperative wildcard pinned');
})().catch((err) => { console.error(err); process.exit(1); });