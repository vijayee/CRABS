'use strict';
// Recipe 9 — a treasury with atomic transfers (crabs-wasm).
//
// The full protocol, driven from JS the way the C executor wants it — the
// same shape as cookbook/snippets/c/09-treasury.c:
//   (1) the pot exists: wasm gained Node.addResource (previously node-only),
//       minting a lock-capable RESOURCE item whose balance is a raw int64;
//   (2) only one holder of the live lease — a competing `__lock__` is
//       refused, an op naming an un-locked pot too;
//   (3) a forged lock claim (wrong bearer token) is refused
//       lock_token_mismatch BEFORE any effect;
//   (4) the lock-modify-verify-unlock ceremony completes with the live
//       token claimed and the required/next states declared per slot;
//   (5) a real debit/credit handler applied exactly once under an attached
//       memory tx manager — a duplicate submission of the same signed op is
//       already_executed, and all-or-nothing preconditions leave a poisoned
//       op with no partial apply.
// The lock is machine-local coordination (lock state is runtime only, never
// serialized) and claim discipline stays cooperative — the executor verifies
// the claims an op PRESENTS but forces none (the recipe page's honesty
// section); the demo pins both facts.

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../../../bindings/wasm');

const AMOUNT = 100;

async function main() {
  const node = await Node.create('treasury-node', { ordering: 'hlc' });

  const treasurerKey = await KeyPair.generate();
  node.registerUser('treasurer', treasurerKey.publicKeyHex(), '');
  node.grantRole('treasurer', 'role', 'treasurer', 'treasury-node');

  // (1): the pots — RESOURCE items whose balance is a raw int64 (the
  // library contract: dedup mutations, the lock snapshot, and destroy all
  // take the raw path for RESOURCE). The balances stay driver-read here:
  // getResource is the int64 readback; the machine guards everything
  // AROUND the value.
  node.addResource('treasury', 1000);
  node.addResource('member_pot', 0);
  assert.strictEqual(node.getResource('treasury'), 1000, 'pot seed');
  assert.strictEqual(node.getResource('member_pot'), 0, 'member seed');

  for (const opType of ['__lock__', '__verify__', '__rollback__', '__unlock__',
                        'observe', 'transfer']) {
    node.setPolicy(opType, 'role:treasurer');
  }

  // The treasury movement itself: the handler owns the arithmetic, the
  // machine owns everything around it. op.resources names the pots in
  // order; HandlerState.adjustResource does the overflow-checked int64
  // mutation (the same find-and-mutate the C transfer_handler performs).
  node.registerHandlerJs('transfer', (state, op) => {
    if (op.resources.length !== 2) return 0x5003; // invalid_param
    const balance = state.getResource(op.resources[0]);
    if (balance === undefined) return 0x3002;     // resource_not_found
    if (balance < AMOUNT) return 0x1001;          // protocol_violation
    state.adjustResource(op.resources[0], -AMOUNT);
    state.adjustResource(op.resources[1], AMOUNT);
    return 0;
  });

  const freshOp = async (type) => {
    const op = await Operation.create(type);
    op.signerId = 'treasurer';
    return op;
  };

  // (2): the un-coordinated op is refused — `observe` is a handler-less
  // custom op, and the wildcard apply only acts on LOCKED resources
  // (src/StateMachine/state_machine.c). The refusal is the gate, not a bug.
  const uncoordinated = await freshOp('observe');
  uncoordinated.addResource('treasury');
  node.sign(uncoordinated, treasurerKey);
  try {
    node.execute(uncoordinated);
    throw new Error('an op on an un-locked RESOURCE must be refused');
  } catch (refusal) {
    assert(refusal.message.includes('protocol_violation'),
      `expected protocol_violation, got: ${refusal.message}`);
  }

  // The lease: `__lock__` mints a CSPRNG bearer token; read it back live
  // (the executor consumes the lock response internally — the item's lock
  // state is the token's only observable home).
  const acquire = await freshOp('__lock__');
  acquire.addResource('treasury');
  node.sign(acquire, treasurerKey);
  node.execute(acquire);

  const live = node.getLockState('treasury');
  assert.strictEqual(live.protocolState, 'locked', 'lease acquired');
  assert.strictEqual(live.lockOwner, 'treasurer', 'lease owner');
  assert.strictEqual(live.lockTokenHex.length, 64, 'bearer token: 32 bytes');

  // (2) again: a live lease refuses re-acquisition — the pot is not
  // re-acquirable until expiry or release, even by the same treasurer.
  const reacquire = await freshOp('__lock__');
  reacquire.addResource('treasury');
  node.sign(reacquire, treasurerKey);
  try {
    node.execute(reacquire);
    throw new Error('a live lease must refuse re-acquisition');
  } catch (refusal) {
    assert(refusal.message.includes('protocol_violation'),
      `expected protocol_violation, got: ${refusal.message}`);
  }

  // (3): a forged claim — a wrong bearer token — is refused before any
  // effect, and the protocol state does not move.
  const forged = await freshOp('observe');
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

  // (4): the honest path — the claim-bearing op declares
  // required_state/next_state per slot and carries the LIVE token; the
  // wildcard apply advances LOCKED -> MODIFIED. Then `__verify__`
  // (MODIFIED -> VERIFIED) and `__unlock__` (VERIFIED -> IDLE) close the
  // ceremony — the protocol ops are owner-checked by their own handlers.
  const apply = await freshOp('observe');
  apply.addResource('treasury');
  apply.setRequiredState(0, 'locked');
  apply.setNextState(0, 'modified');
  apply.addLockClaim('treasury', live.lockTokenHex);
  node.sign(apply, treasurerKey);
  node.execute(apply);
  assert.strictEqual(node.getLockState('treasury').protocolState, 'modified',
    'claim-bearing apply advances LOCKED->MODIFIED');

  const ceremony = async (type, fromState) => {
    const op = await freshOp(type);
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

  // (5): apply exactly once under the memory tx manager. The manager
  // records committed op uuids; the executor's step 3b (after the signature
  // check — the processed-uuid oracle placement) refuses a duplicate
  // submission with already_executed. Ordering monotonicity remains the
  // post-restart backstop.
  node.attachTxManager('memory');

  const transfer = async () => {
    const op = await Operation.create('transfer');
    op.signerId = 'treasurer';
    op.addResource('treasury');
    op.addResource('member_pot');
    for (const slot of [0, 1]) {
      op.setRequiredState(slot, 'idle');
      op.setNextState(slot, 'idle');
    }
    node.sign(op, treasurerKey);
    node.execute(op);
    return op;
  };

  const applied = await transfer();
  assert.strictEqual(node.getResource('treasury'), 900, 'debit applied once');
  assert.strictEqual(node.getResource('member_pot'), 100, 'credit applied once');

  try {
    node.execute(applied); // the SAME signed op bytes, re-submitted
    throw new Error('a duplicate submission must be refused');
  } catch (replay) {
    assert(replay.message.includes('already_executed'),
      `expected already_executed, got: ${replay.message}`);
  }
  assert.strictEqual(node.getResource('treasury'), 900, 'no second debit');
  assert.strictEqual(node.getResource('member_pot'), 100, 'no second credit');

  // All-or-nothing preconditions: one unknown item poisons the whole op —
  // the transition check runs over EVERY named resource BEFORE the handler,
  // so nothing moves and nothing is logged.
  const poisoned = await freshOp('transfer');
  poisoned.addResource('treasury');
  poisoned.addResource('ghost_treasury');
  for (const slot of [0, 1]) {
    poisoned.setRequiredState(slot, 'idle');
    poisoned.setNextState(slot, 'idle');
  }
  node.sign(poisoned, treasurerKey);
  try {
    node.execute(poisoned);
    throw new Error('an op naming an unknown resource must be refused');
  } catch (refusal) {
    assert(refusal.message.includes('resource_not_found'),
      `expected resource_not_found, got: ${refusal.message}`);
  }
  assert.strictEqual(node.getResource('treasury'), 900, 'poisoned op left the pot');
  assert.strictEqual(node.getResource('member_pot'), 100, 'poisoned op left the member');

  console.log('treasury OK: pot minted, single lease, forged claim refused, ceremony completes, debit/credit applied once under the tx manager, poisoned op applies nothing');
  // Deterministic teardown is available: node.destroy() and keypair.destroy()
  // exist on crabs-wasm (the no-destroy note applies to the node binding —
  // see the node snippets, where native cleanup is process-exit driven).
}

main().catch((err) => { console.error(err); process.exit(1); });