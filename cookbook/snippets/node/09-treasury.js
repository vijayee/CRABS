'use strict';
// Recipe 9 — a treasury with atomic transfers (crabs-node).
//
// What the machine itself guarantees on this binding, and what this snippet
// executes:
//   (1) a node can mint the shared pot — a lock-capable DATA_TYPE_RESOURCE
//       item (node-only `Node.addResource`);
//   (2) a signed op that NAMES the pot is gated by the executor: a custom
//       op is only applied to a LOCKED resource, so the un-coordinated
//       transfer is refused, never silently applied;
//   (3) the lease is acquirable — the built-in `__lock__` op type drives
//       the C lock protocol, and a live pot refuses re-acquisition
//       (single active lease per RESOURCE item);
//   (4) a precondition failure (unknown resource) is typed and leaves
//       nothing behind;
//   (5) a replay of a previously executed signed op is refused by the
//       executor's ordering-monotonicity backstop, even without a
//       tx_manager wired on the JS node.
// What this binding CANNOT do (the recipe page's GAP blocks): present a
// lock-claim token, set an op's required protocol states, or drive the
// extend/verify/rollback/unlock tail of the ceremony — no d.ts symbol
// exists for any of it.

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../../../bindings/node');

const node = new Node('node-1', { ordering: 'hlc' });

const treasurerKey = KeyPair.generate();
node.registerUser('treasurer', treasurerKey.publicKeyHex(), '');
node.grantRole('treasurer', 'role', 'treasurer', 'node-1');

// The pot: node-only `addResource` mints a DATA_TYPE_RESOURCE item (a
// PN-counter with a raw int64 balance) — the item type that carries
// protocol state, lock owner/token/expiry and a pre-lock snapshot
// (src/CRABS/data_model.h:117-133). Its balance is machine-read only; the
// JS bindings expose no read for RESOURCE items.
node.addResource('treasury');
node.setPolicy('transfer', 'role:treasurer');
node.setPolicy('__lock__', 'role:treasurer');

// (1)+(2): the executor refuses an un-coordinated op against the pot. The
// op is authorized (policy passes), the pot exists and is in the IDLE
// state the op requires — and the executor still refuses it, because the
// wildcard apply of a custom op only acts on LOCKED resources
// (src/StateMachine/state_machine.c:1440-1452).
const uncoordinated = new Operation('transfer');
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
const acquire = new Operation('__lock__');
acquire.signerId = 'treasurer';
acquire.addResource('treasury');
node.sign(acquire, treasurerKey);
node.execute(acquire);

// The live lease refuses re-acquisition: the pot is no longer IDLE, so a
// second `__lock__` — the same signer's, even — is refused before any
// token is minted (state_machine_op_lock, src/StateMachine/state_machine.c:1710).
const reacquire = new Operation('__lock__');
reacquire.signerId = 'treasurer';
reacquire.addResource('treasury');
node.sign(reacquire, treasurerKey);
try {
  node.execute(reacquire);
  throw new Error('a live lease must refuse re-acquisition');
} catch (refusal) {
  assert(refusal.message.includes('protocol_violation'),
    `expected protocol_violation, got: ${refusal.message}`);
}

// The honest limit, demonstrated: once locked, a transfer op naming the
// pot fails the required-state check (the op builder cannot declare
// required_state PROTOCOL_LOCKED) — a JS-locked pot is not spendable by
// op at all, from anyone, until the lease expires and is pruned by the
// next execute (state_machine.c:364-407).
const whileLocked = new Operation('transfer');
whileLocked.signerId = 'treasurer';
whileLocked.addResource('treasury');
node.sign(whileLocked, treasurerKey);
try {
  node.execute(whileLocked);
  throw new Error('an op on a LOCKED pot must be refused here (no required_state)');
} catch (refusal) {
  assert(refusal.message.includes('protocol_violation'),
    `expected protocol_violation, got: ${refusal.message}`);
}

// (4): precondition checks are typed and leave nothing behind — an op
// naming a resource the machine never minted fails inside the same
// step-4 precondition pass that gates required states
// (state_machine.c:846-857), before any effect.
const ghostTransfer = new Operation('transfer');
ghostTransfer.signerId = 'treasurer';
ghostTransfer.addResource('ghost_treasury');
node.sign(ghostTransfer, treasurerKey);
try {
  node.execute(ghostTransfer);
  throw new Error('an op naming an unknown resource must be refused');
} catch (refusal) {
  assert(refusal.message.includes('resource_not_found'),
    `expected resource_not_found, got: ${refusal.message}`);
}

// (5): what a signed transfer CANNOT do: play twice. Mint an item the
// machine can actually apply (a counter — non-RESOURCE items skip the
// wildcard lock gate), apply one transfer op, then re-execute the SAME
// signed op bytes. The ordering-monotonicity backstop catches the replay
// (state_signer_has_replay, src/StateMachine/state_machine.c:585).
// The machine does not bump the counter — a custom op carries intent, the
// value arithmetic is the driver's (Recipe 2); what the machine guarantees
// is that the op is applied to the log at most once.
node.addCounter('transfer_ledger');
node.setPolicy('record_transfer', 'role:treasurer');

const firstTransfer = new Operation('record_transfer');
firstTransfer.signerId = 'treasurer';
firstTransfer.addResource('transfer_ledger');
node.sign(firstTransfer, treasurerKey);
node.execute(firstTransfer);

try {
  node.execute(firstTransfer); // same signed op, same ordering timestamp
  throw new Error('re-executing a recorded transfer op must be refused');
} catch (replay) {
  assert(replay.message.includes('already_executed'),
    `expected already_executed, got: ${replay.message}`);
}

console.log('treasury OK: gate enforced, lease acquired + re-acquisition refused, preconditions typed, replay refused');
// Node/KeyPair expose no destroy() — native cleanup is process-exit driven.