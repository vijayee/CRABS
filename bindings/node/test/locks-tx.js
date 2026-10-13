//
// locks-tx.js — Recipe 9's lock/tx-manager surface from JS (crabs-node).
//
// Mirrors the C scenarios in cookbook/snippets/c/09-treasury.c (single lease,
// forged claim refused, the lock-modify-verify-unlock ceremony, an attached
// in-memory tx manager refusing duplicate submissions, and an op naming an
// unknown resource applying nothing). crabs-node has no custom-handler
// surface (api-map known difference #2), so the debit/credit arithmetic
// cannot live in a machine handler here: the transfer demo uses the
// wildcard-apply path on a claim-bearing op (the machine guarantees at-most-
// once LOG application and the protocol state; values stay driver-owned —
// recipe 2/9 notes), while every executor gate runs exactly as in C.
//

'use strict';

const { Node, KeyPair, Operation } = require('..');

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) {
    passed++;
  } else {
    failed++;
    console.error('FAIL:', msg);
  }
}

function expectRefusal(runnable, expected, what) {
  try {
    runnable();
  } catch (refusal) {
    assert(refusal.message.includes(expected),
      `${what}: expected "${expected}", got: ${refusal.message}`);
    return;
  }
  assert(false, `${what}: expected a ${expected} refusal, got success`);
}

// Test 1: mint + readback. addResource seeds a raw int64 balance; getResource
// exposes it (previously machine-read only).
const node = new Node('treasury-node', { ordering: 'hlc' });
const treasurerKey = KeyPair.generate();
node.registerUser('treasurer', treasurerKey.publicKeyHex(), '');
node.grantRole('treasurer', 'role', 'treasurer', 'treasury-node');

node.addResource('treasury', 1000);
node.addResource('member_pot', 0);
assert(node.getResource('treasury') === 1000, 'pot seed readback');
assert(node.getResource('member_pot') === 0, 'member seed readback');

for (const opType of ['__lock__', '__verify__', '__unlock__', 'observe', 'record_transfer']) {
  node.setPolicy(opType, 'role:treasurer');
}

// Test 2: the un-coordinated op is refused (handler-less custom ops only act
// on LOCKED resources — the wildcard gate, state_machine.c).
const uncoordinated = new Operation('record_transfer');
uncoordinated.signerId = 'treasurer';
uncoordinated.addResource('treasury');
node.sign(uncoordinated, treasurerKey);
expectRefusal(() => node.execute(uncoordinated), 'protocol_violation',
  'op on un-locked RESOURCE');

// Test 3: exactly one live lease; re-acquisition refused even by the same
// signer (state_machine_op_lock).
const lock = () => {
  const op = new Operation('__lock__');
  op.signerId = 'treasurer';
  op.addResource('treasury');
  node.sign(op, treasurerKey);
  node.execute(op);
};
lock();
const live = node.getLockState('treasury');
assert(live.protocolState === 'locked', 'lease acquired');
assert(live.lockOwner === 'treasurer', 'lease owner');
assert(live.lockTokenHex.length === 64, 'bearer token is 32 bytes hex');

expectRefusal(lock, 'protocol_violation', 're-acquisition of a live lease');

// Test 4: a forged claim (wrong bearer token) is refused before any effect —
// the executor verifies the claims an op presents (state_machine.c step 5).
const forged = new Operation('record_transfer');
forged.signerId = 'treasurer';
forged.addResource('treasury');
forged.setRequiredState(0, 'locked');
forged.setNextState(0, 'modified');
forged.addLockClaim('treasury', 'ff'.repeat(32));
node.sign(forged, treasurerKey);
expectRefusal(() => node.execute(forged), 'lock_token_mismatch', 'forged claim');
assert(node.getLockState('treasury').protocolState === 'locked',
  'refused op leaves the protocol state');

// Test 5: the honest claim-bearing apply advances LOCKED -> MODIFIED, and the
// verify/unlock tail completes the ceremony. No handler owns 'record_transfer'
// on crabs-node, so the machine's wildcard apply carries the transition while
// the value arithmetic stays the driver's (recipe 9 note).
const apply = new Operation('record_transfer');
apply.signerId = 'treasurer';
apply.addResource('treasury');
apply.setRequiredState(0, 'locked');
apply.setNextState(0, 'modified');
apply.addLockClaim('treasury', live.lockTokenHex);
node.sign(apply, treasurerKey);
node.execute(apply);
assert(node.getLockState('treasury').protocolState === 'modified',
  'claim-bearing apply advances LOCKED->MODIFIED');

const ceremony = (opType, fromState) => {
  const op = new Operation(opType);
  op.signerId = 'treasurer';
  op.addResource('treasury');
  op.setRequiredState(0, fromState);
  op.addLockClaim('treasury', node.getLockState('treasury').lockTokenHex);
  node.sign(op, treasurerKey);
  node.execute(op);
};
ceremony('__verify__', 'modified');
assert(node.getLockState('treasury').protocolState === 'verified',
  '__verify__ promotes MODIFIED->VERIFIED');
ceremony('__unlock__', 'verified');
assert(node.getLockState('treasury').protocolState === 'idle',
  '__unlock__ returns the pot to IDLE');
assert(node.getLockState('treasury').lockTokenHex === '',
  'unlock clears the bearer token');

// Test 6: attach the memory tx manager; a duplicate submission of the same
// signed op is refused with already_executed (step 3b, before the ordering
// backstop at step 3c). The ledger counter is a non-RESOURCE item, so the
// op applies; the machine guarantees at-most-once log application.
node.attachTxManager('memory');
node.addCounter('transfer_ledger');
const record = () => {
  const op = new Operation('record_transfer');
  op.signerId = 'treasurer';
  op.addResource('transfer_ledger');
  op.setRequiredState(0, 'idle');
  op.setNextState(0, 'idle');
  node.sign(op, treasurerKey);
  node.execute(op);
  return op;
};
const applied = record();
expectRefusal(() => node.execute(applied), 'already_executed',
  'duplicate submission');

// Test 7: all-or-nothing preconditions — a poisoned op naming an unknown
// resource fails in the step-4 pass before any effect (the ledger counter
// records nothing; a subsequent fresh op still works).
expectRefusal(() => {
  const op = new Operation('record_transfer');
  op.signerId = 'treasurer';
  op.addResource('transfer_ledger');
  op.addResource('ghost_treasury');
  op.setRequiredState(0, 'idle');
  op.setNextState(0, 'idle');
  op.setRequiredState(1, 'idle');
  op.setNextState(1, 'idle');
  node.sign(op, treasurerKey);
  node.execute(op);
}, 'resource_not_found', 'poisoned op');

const afterPoison = record();
assert(afterPoison !== null, 'machine still accepts a fresh op after a poisoned one');

// Test 8: cooperative claim reality (recipe 9's honesty note): the executor
// verifies claims an op PRESENTS but forces none — the claim-less op on a
// LOCKED resource executes through the wildcard apply. The 'none' manager is
// the accept-everything deployment hook (crabs_tx_manager_none).
node.addResource('escrow');
node.setPolicy('observe', 'role:treasurer');
const claimLess = new Operation('record_transfer');
claimLess.signerId = 'treasurer';
claimLess.addResource('escrow');
claimLess.setRequiredState(0, 'locked');
claimLess.setNextState(0, 'modified');
const escrowLock = new Operation('__lock__');
escrowLock.signerId = 'treasurer';
escrowLock.addResource('escrow');
node.sign(escrowLock, treasurerKey);
node.execute(escrowLock);
node.attachTxManager('none');
node.sign(claimLess, treasurerKey);
node.execute(claimLess);
assert(node.getLockState('escrow').protocolState === 'modified',
  'wildcard apply advances a LOCKED resource with no claim presented');

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);