'use strict';
// Recipe 9 — a treasury with atomic transfers (crabs-node).
//
// What the machine itself guarantees on this binding, and what this snippet
// executes:
//   (1) a node mints the shared pot — a lock-capable DATA_TYPE_RESOURCE item
//       (`Node.addResource`, now with a seeded balance) and reads its raw
//       int64 balance back (`Node.getResource`);
//   (2) a signed op naming the pot is gated by the executor: a handler-less
//       custom op only acts on a LOCKED resource, so the un-coordinated
//       transfer is refused, never silently applied
//       (src/StateMachine/state_machine.c wildcard gate);
//   (3) the lease is acquirable — the built-in `__lock__` op type drives the
//       C lock protocol, a live pot refuses re-acquisition (single active
//       lease), and the 32-byte CSPRNG bearer token is read back live via
//       `Node.getLockState`;
//   (4) the full ceremony — a forged claim (wrong bearer token) is refused
//       lock_token_mismatch before any effect; the claim-bearing op declares
//       required/next protocol states per slot and advances
//       LOCKED -> MODIFIED; `__verify__` + `__unlock__` close it;
//   (5) an attached memory tx manager (`Node.attachTxManager('memory')`)
//       refuses a duplicate submission of the same signed op with
//       already_executed, and all-or-nothing preconditions leave a poisoned
//       op (unknown resource) with no partial apply.
// crabs-node still has NO custom-handler surface (api-map known difference
// #2): the debit/credit arithmetic cannot live in a machine handler here —
// the op-level guarantees (at-most-once log application, the protocol state,
// every gate) are machine-owned; the value arithmetic stays the driver's
// (recipe page notes). The handler-owned debit/credit runs on crabs-wasm
// and C (this recipe's other snippets). The lock is machine-local
// coordination (runtime-only lock state) and claim discipline is
// cooperative — the executor verifies the claims an op PRESENTS but forces
// none.

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../../../bindings/node');

const node = new Node('treasury-node', { ordering: 'hlc' });

const treasurerKey = KeyPair.generate();
node.registerUser('treasurer', treasurerKey.publicKeyHex(), '');
node.grantRole('treasurer', 'role', 'treasurer', 'treasury-node');

// The pot: `addResource` mints a DATA_TYPE_RESOURCE item — the item type
// that carries protocol state, lock owner/token/expiry and a pre-lock
// snapshot (src/CRABS/data_model.h:117-133). `initial` seeds the raw
// int64 balance; `getResource` is its readback.
node.addResource('treasury', 1000);
node.addResource('member_pot', 0);
assert.strictEqual(node.getResource('treasury'), 1000, 'pot seed');
assert.strictEqual(node.getResource('member_pot'), 0, 'member seed');

for (const opType of ['__lock__', '__verify__', '__rollback__', '__unlock__',
                      'observe', 'record_transfer']) {
  node.setPolicy(opType, 'role:treasurer');
}

// (2): the executor refuses an un-coordinated op against the pot. The op is
// authorized (policy passes), the pot exists and is IDLE — and the executor
// still refuses it: the wildcard apply of a handler-less custom op only
// acts on LOCKED resources (state_machine.c).
const uncoordinated = new Operation('record_transfer');
uncoordinated.signerId = 'treasurer';
uncoordinated.addResource('treasury');
node.sign(uncoordinated, treasurerKey);
try {
  node.execute(uncoordinated);
  throw new Error('an op against an un-locked RESOURCE must be refused');
} catch (refusal) {
  assert(refusal.message.includes('protocol_violation'),
    `expected protocol_violation, got: ${refusal.message}`);
}

// (3): acquire the lease on the pot through the built-in op type.
const lock = () => {
  const op = new Operation('__lock__');
  op.signerId = 'treasurer';
  op.addResource('treasury');
  node.sign(op, treasurerKey);
  node.execute(op);
};
lock();

const live = node.getLockState('treasury');
assert.strictEqual(live.protocolState, 'locked', 'lease acquired');
assert.strictEqual(live.lockOwner, 'treasurer', 'lease owner');
assert.strictEqual(live.lockTokenHex.length, 64,
  'bearer token: 32 bytes of CSPRNG hex');

// A live lease refuses re-acquisition: the pot is no longer IDLE, so a
// second `__lock__` — the same signer's, even — is refused
// (state_machine_op_lock's IDLE requirement).
try {
  lock();
  throw new Error('a live lease must refuse re-acquisition');
} catch (refusal) {
  assert(refusal.message.includes('protocol_violation'),
    `expected protocol_violation, got: ${refusal.message}`);
}

// (4): a forged claim — a wrong bearer token — is refused BEFORE any effect
// (executor step 5 verifies each presented claim against the live token).
const forged = new Operation('record_transfer');
forged.signerId = 'treasurer';
forged.addResource('treasury');
forged.setRequiredState(0, 'locked');
forged.setNextState(0, 'modified');
forged.addLockClaim('treasury', 'ff'.repeat(32));
node.sign(forged, treasurerKey);
try {
  node.execute(forged);
  throw new Error('a forged claim must be refused');
} catch (refusal) {
  assert(refusal.message.includes('lock_token_mismatch'),
    `expected lock_token_mismatch, got: ${refusal.message}`);
}
assert.strictEqual(node.getLockState('treasury').protocolState, 'locked',
  'a refused op never moves the protocol state');

// (4) cont.: the honest claim-bearing op — required/next states declared per
// slot, the LIVE token claimed — advances LOCKED -> MODIFIED through the
// wildcard apply (no handler owns 'record_transfer' on this binding, so the
// machine's wildcard carries the transition while the value arithmetic
// stays the driver's). Then `__verify__` and `__unlock__` close the
// ceremony.
const apply = new Operation('record_transfer');
apply.signerId = 'treasurer';
apply.addResource('treasury');
apply.setRequiredState(0, 'locked');
apply.setNextState(0, 'modified');
apply.addLockClaim('treasury', live.lockTokenHex);
node.sign(apply, treasurerKey);
node.execute(apply);
assert.strictEqual(node.getLockState('treasury').protocolState, 'modified',
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
assert.strictEqual(node.getLockState('treasury').protocolState, 'verified',
  '__verify__ promotes MODIFIED->VERIFIED');
ceremony('__unlock__', 'verified');
assert.strictEqual(node.getLockState('treasury').protocolState, 'idle',
  '__unlock__ returns the pot to IDLE');
assert.strictEqual(node.getLockState('treasury').lockTokenHex, '',
  'unlock clears the bearer token');

// (5): apply exactly once under the memory tx manager — the manager records
// committed op uuids and the executor's step 3b (after the signature check)
// refuses the duplicate with already_executed. Without a manager the
// ordering backstop (state_signer_has_replay) still rejects a replayed op;
// the manager covers uuids whose ordering state could not catch them.
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
try {
  node.execute(applied); // same signed op, re-submitted
  throw new Error('a duplicate submission must be refused');
} catch (replay) {
  assert(replay.message.includes('already_executed'),
    `expected already_executed, got: ${replay.message}`);
}

// All-or-nothing preconditions: one unknown item poisons the whole op — the
// transition check runs over EVERY named resource before anything moves, so
// nothing is logged. The pots' balances (driver arithmetic aside) are
// demonstrably untouched by refusals.
try {
  const poisoned = new Operation('record_transfer');
  poisoned.signerId = 'treasurer';
  poisoned.addResource('treasury');
  poisoned.addResource('ghost_treasury');
  poisoned.setRequiredState(0, 'idle');
  poisoned.setNextState(0, 'idle');
  poisoned.setRequiredState(1, 'idle');
  poisoned.setNextState(1, 'idle');
  node.sign(poisoned, treasurerKey);
  node.execute(poisoned);
  throw new Error('an op naming an unknown resource must be refused');
} catch (refusal) {
  assert(refusal.message.includes('resource_not_found'),
    `expected resource_not_found, got: ${refusal.message}`);
}
assert.strictEqual(node.getResource('treasury'), 1000, 'refusals left the pot');

console.log('treasury OK: pot minted + read, gate enforced, lease acquired + contested refused, forged claim refused, ceremony completes, duplicate refused under the tx manager, poisoned op applies nothing');
// Node/KeyPair expose no destroy() — native cleanup is process-exit driven.