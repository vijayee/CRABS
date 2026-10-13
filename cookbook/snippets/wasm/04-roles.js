'use strict';
// Recipe 4 — roles and who-can-do-what (crabs-wasm, run in Node).
// Attributes carry the facts ('adult'), roles are privileges granted by the
// admin ('role:member'), policies are condition expressions over both, and
// every signed op is authorized against the policy inside the machine.

const { Node, KeyPair, Operation } = require('../../../bindings/wasm');

async function main() {
  const node = await Node.create('admin', { ordering: 'hlc' });

  // Privilege escalation is refused at the door: registering with a
  // privileged attribute name is invalid_param — roles are granted by the
  // admin path only (audit R7-08).
  const carolKey = await KeyPair.generate();
  let selfRoleRefused = false;
  try {
    node.registerUser('carol', carolKey.publicKeyHex(), 'role:member');
  } catch (roleGrab) {
    selfRoleRefused = roleGrab.message.includes('invalid_param');
  }
  if (!selfRoleRefused) {
    throw new Error('registerUser must reject privileged attribute names');
  }

  // Membership = an unprivileged fact ('adult') plus an admin-granted role.
  const aliceKey = await KeyPair.generate();
  node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'admin');

  const malloryKey = await KeyPair.generate();
  node.registerUser('mallory', malloryKey.publicKeyHex(), '');
  node.grantRole('mallory', 'role', 'member', 'admin'); // member but not adult

  const alice = node.getUser('alice');
  const aliceAttrs = alice.attributes.map((attribute) => attribute.value);
  if (!aliceAttrs.includes('role:member') || !aliceAttrs.includes('adult')) {
    throw new Error(`expected role:member and adult on alice, got ${aliceAttrs}`);
  }
  // UserInfo.attributes[].verifiedBy comes back populated on BOTH bindings —
  // the wasm getUser glue reads it back from the machine
  // (bindings/wasm/bindings-core.js:895-952), the node binding maps the same
  // field (bindings/node/src/crabs_node.cc:1588); the earlier empty-string
  // divergence is fixed and pinned by bindings/wasm/test/getuser-readback.js.

  node.addCounter('gposts');
  node.setPolicy('post', 'AND role:member adult');
  node.registerHandlerJs('post', (state, op) => {
    state.incrementCounter('gposts', 1, op.signerId);
    return 0;
  });

  const signedPost = async (key, member) => {
    const op = await Operation.create('post');
    op.signerId = member;
    op.nodeId = member;
    node.sign(op, key.privateKeyHex());
    node.execute(op);
    op.destroy();
  };

  await signedPost(aliceKey, 'alice'); // member + adult: passes
  if (node.getCounter('gposts') !== 1) {
    throw new Error(`expected gposts=1, got ${node.getCounter('gposts')}`);
  }

  // Mallory is a member but never asserted 'adult' — the policy's second
  // clause refuses the op. The verified error carries the canonical typed
  // name 'unauthorized' (a failed authorization also fires for a missing
  // policy or an invalid signature; the recipe cannot distinguish clauses
  // of one expression from the JS error alone).
  let malloryRefused = '';
  try {
    await signedPost(malloryKey, 'mallory');
  } catch (refusal) {
    malloryRefused = String(refusal.message);
  }
  if (!malloryRefused.includes('unauthorized')) {
    throw new Error(`an op missing a policy clause must be rejected, got "${malloryRefused}"`);
  }
  if (node.getCounter('gposts') !== 1) {
    throw new Error(`a refused op must not land, got gposts=${node.getCounter('gposts')}`);
  }

  console.log('roles OK: role granted + enforced, self-grant refused');
  node.destroy();
  aliceKey.destroy();
  malloryKey.destroy();
  carolKey.destroy();
}
main()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });