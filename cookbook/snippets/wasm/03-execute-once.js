'use strict';
// Recipe 3 — execute once, ever (crabs-wasm, run in Node).
// The persisted outcome is a ONE_SHOT_FLAG: false -> true, exactly once,
// and the guard is REGISTRED: defineOperationType installs a DEDUP_GLOBAL
// spec for the 'closeout' op type, so the machine itself refuses every run
// after the first — from any signer, with no handler or driver-side
// checking at all. The op names the flag item as its resource and nothing
// else: the spec's guard + mutation ARE the whole behavior.

const { Node, KeyPair, Operation } = require('../../../bindings/wasm');

async function main() {
  const node = await Node.create('admin', { ordering: 'hlc' });

  const keeperKey = await KeyPair.generate();
  node.registerUser('keeper', keeperKey.publicKeyHex(), '');
  node.grantRole('keeper', 'role', 'member', 'admin');

  const closerKey = await KeyPair.generate();
  node.registerUser('closer', closerKey.publicKeyHex(), '');
  node.grantRole('closer', 'role', 'member', 'admin');

  node.addOneShotFlag('closeout_done');
  // flagValue returns 0/1 numbers on crabs-wasm and real booleans on
  // crabs-node — compare truthiness, not identity.
  if (node.flagValue('closeout_done')) {
    throw new Error('a fresh one-shot flag must read false');
  }

  // Installing the spec is a signed '__define_operation_type__' op under
  // the machine's admin; the vote-type policy authorizes runners.
  node.setPolicy('__define_operation_type__', 'role:admin');
  node.setPolicy('closeout', 'role:member');

  node.defineOperationType('closeout', {
    dedup: 'global',
    flagPath: 'closeout_done',
    rejectionMessage: 'already_executed',
  });

  const executeCloseout = async (subjectKey, signer) => {
    const op = await Operation.create('closeout');
    op.signerId = signer;
    op.nodeId = signer;
    op.addResource('closeout_done');
    node.sign(op, subjectKey.privateKeyHex());
    node.execute(op);
    op.destroy();
  };

  await executeCloseout(keeperKey, 'keeper');
  if (!node.flagValue('closeout_done')) {
    throw new Error('the flag must be set by the executed op');
  }
  // Who/set-when are recorded in the C struct; a rerun — from the same
  // signer or a different one — is refused by the registered spec before
  // anything re-runs.
  let rerunRejected = false;
  try {
    await executeCloseout(keeperKey, 'keeper');
  } catch (rerunError) {
    rerunRejected = rerunError.message.includes('already_executed');
  }
  if (!rerunRejected) {
    throw new Error('a second closeout must be rejected');
  }
  let otherSignerRejected = false;
  try {
    await executeCloseout(closerKey, 'closer');
  } catch (otherError) {
    otherSignerRejected = otherError.message.includes('already_executed');
  }
  if (!otherSignerRejected) {
    throw new Error('a GLOBAL spec refuses every signer after the first run');
  }

  console.log('execute-once OK: flag set by first run, rerun rejected');
  node.destroy();
  keeperKey.destroy();
  closerKey.destroy();
}
main()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });