'use strict';
// Recipe 3 — execute once, ever (crabs-node, driven directly).
// The persisted outcome is a ONE_SHOT_FLAG: false -> true, exactly once.
// The once-rule is REGISTRED on the machine with defineOperationType (a
// node-key-signed '__define_operation_type__' op installs a DEDUP_GLOBAL
// spec), so the machine itself refuses every run after the first — from any
// signer, with no driver-side checking at all. The op names the flag as its
// resource and nothing else: the spec's guard + mutation are the whole
// behavior.

const { Node, KeyPair, Operation } = require('../../../bindings/node');

const node = new Node('node-1', { ordering: 'hlc' });

const keeperKey = KeyPair.generate();
node.registerUser('keeper', keeperKey.publicKeyHex(), '');
node.grantRole('keeper', 'role', 'member', 'node-1');

const closerKey = KeyPair.generate();
node.registerUser('closer', closerKey.publicKeyHex(), '');
node.grantRole('closer', 'role', 'member', 'node-1');

node.addOneShotFlag('closeout_done');
if (node.flagValue('closeout_done')) {
  throw new Error('a fresh one-shot flag must read false');
}

// Installing the spec is a signed op under the machine's admin; the
// closeout op type gets its own policy.
node.setPolicy('__define_operation_type__', 'role:admin');
node.setPolicy('closeout', 'role:member');

node.defineOperationType('closeout', {
  dedup: 'global',
  flagPath: 'closeout_done',
  rejectionMessage: 'already_executed',
});

const executeCloseout = (key, signer) => {
  const op = new Operation('closeout');
  op.signerId = signer;
  op.addResource('closeout_done');
  node.sign(op, key);
  node.execute(op);
};

executeCloseout(keeperKey, 'keeper');
if (!node.flagValue('closeout_done')) {
  throw new Error('the flag must be set by the executed op');
}

// A rerun — from the same signer or a different one — is refused by the
// registered spec before anything re-runs.
let rerunRejected = false;
try {
  executeCloseout(keeperKey, 'keeper');
} catch (rerunError) {
  rerunRejected = rerunError.message.includes('already_executed');
}
if (!rerunRejected) {
  throw new Error('a second closeout must be rejected');
}
let otherSignerRejected = false;
try {
  executeCloseout(closerKey, 'closer');
} catch (otherError) {
  otherSignerRejected = otherError.message.includes('already_executed');
}
if (!otherSignerRejected) {
  throw new Error('a GLOBAL spec refuses every signer after the first run');
}

console.log('execute-once OK: flag set by first run, rerun rejected');
// Node/KeyPair expose no destroy() — native cleanup is process-exit driven.