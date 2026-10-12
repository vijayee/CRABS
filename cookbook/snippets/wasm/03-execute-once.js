'use strict';
// Recipe 3 — execute once, ever (crabs-wasm, run in Node).
// The persisted outcome is a ONE_SHOT_FLAG: false -> true, exactly once,
// merge keeps the first setter. HandlerState has flagSet but no flagValue,
// so the in-machine guard reads a ONE_SHOT_SET sentinel that rides alongside
// the flag; the flag itself is read from the Node after execution.

const { Node, KeyPair, Operation } = require('../../../bindings/wasm');

const ALREADY_EXECUTED = 0x7002; // CRABS_ERR_ALREADY_EXECUTED (src/CRABS/crabs.h:107)

async function main() {
  const node = await Node.create('admin', { ordering: 'hlc' });

  const keeperKey = await KeyPair.generate();
  node.registerUser('keeper', keeperKey.publicKeyHex(), '');
  node.grantRole('keeper', 'role', 'member', 'admin');

  node.addOneShotFlag('closeout_done');
  // flagValue returns 0/1 numbers on crabs-wasm and real booleans on
  // crabs-node — compare truthiness, not identity.
  if (node.flagValue('closeout_done')) {
    throw new Error('a fresh one-shot flag must read false');
  }

  // In-machine guard: the first closeout op anywhere burns the sentinel.
  node.addOneShotSet('closeout_sentinel');
  node.setPolicy('closeout', 'role:member');
  node.registerHandlerJs('closeout', (state, op) => {
    if (state.setContains('closeout_sentinel', 'run')) {
      return ALREADY_EXECUTED;
    }
    state.setAdd('closeout_sentinel', 'run');
    state.flagSet('closeout_done', op.signerId);
    return 0;
  });

  const executeCloseout = async () => {
    const op = await Operation.create('closeout');
    op.signerId = 'keeper';
    op.nodeId = 'keeper';
    node.sign(op, keeperKey.privateKeyHex());
    node.execute(op);
    op.destroy();
  };

  await executeCloseout();
  if (!node.flagValue('closeout_done')) {
    throw new Error('the flag must be set by the executed op');
  }

  // The second attempt — a retry, a second device, an eager replica — is
  // rejected inside the machine, before any handler effect can re-run.
  let rerunRejected = false;
  try {
    await executeCloseout();
  } catch (rerunError) {
    rerunRejected = rerunError.message.includes('already_executed');
  }
  if (!rerunRejected) {
    throw new Error('a second closeout must be rejected');
  }

  console.log('execute-once OK: flag set by first run, rerun rejected');
  node.destroy();
  keeperKey.destroy();
}
main()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });