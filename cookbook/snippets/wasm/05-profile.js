'use strict';
// Recipe 5 — a member's own profile they control (crabs-wasm, run in Node).
// One LWW register per member carries the profile (UTF-8 bytes of a display
// name — crabs-wasm is the binding with the byte register API). Members
// update through a policy-gated op whose handler enforces self-ownership:
// you may write profile_<you> and no one else's.

const { Node, KeyPair, Operation } = require('../../../bindings/wasm');

const UNAUTHORIZED = 0x2001; // CRABS_ERR_UNAUTHORIZED (src/CRABS/crabs.h:77)
const encoder = new TextEncoder();
const decoder = new TextDecoder();

async function main() {
  const node = await Node.create('admin', { ordering: 'hlc' });

  const aliceKey = await KeyPair.generate();
  node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'admin');

  const bobKey = await KeyPair.generate();
  node.registerUser('bob', bobKey.publicKeyHex(), 'adult');
  node.grantRole('bob', 'role', 'member', 'admin');

  // One register per member. LWW: the newest write wins; the C struct also
  // keeps the writing node id (src/CRDT/crdt_merge.h:94-99).
  node.addRegister('profile_alice', 0);
  node.addRegister('profile_bob', 0);

  node.setPolicy('update_profile', 'role:member');
  node.registerHandlerJs('update_profile', (state, op) => {
    // Payload format: '<target>|<display name>' (NUL-terminated string
    // payloads reach handlers; see crabs_wasm_handler_op_get_payload_str).
    const separator = op.payload.indexOf('|');
    const target = op.payload.slice(0, separator);
    const displayName = op.payload.slice(separator + 1);
    if (target !== op.signerId) {
      return UNAUTHORIZED;
    }
    state.setRegisterBytes(`profile_${target}`, encoder.encode(displayName),
                           op.signerId);
    return 0;
  });

  const updateProfile = async (key, member, displayName) => {
    const op = await Operation.create('update_profile');
    op.signerId = member;
    op.nodeId = member;
    op.payload = `${member}|${displayName}\0`;
    node.sign(op, key.privateKeyHex());
    node.execute(op);
    op.destroy();
  };
  const readProfile = (member) => decoder.decode(node.getRegisterBytes(`profile_${member}`));

  await updateProfile(aliceKey, 'alice', 'Vic Morrow');
  if (readProfile('alice') !== 'Vic Morrow') {
    throw new Error(`profile must round-trip, got "${readProfile('alice')}"`);
  }
  // Key-version epochs are the JS-visible read (registration starts at 1,
  // each grant bumps): alice registered + one role grant => 2.
  if (node.getUser('alice').keyVersion !== 2) {
    throw new Error(`alice keyVersion must be 2 after one grant, got ` +
      `${node.getUser('alice').keyVersion}`);
  }

  // Bob may write his own profile...
  await updateProfile(bobKey, 'bob', 'B. Okafor');
  if (readProfile('bob') !== 'B. Okafor') {
    throw new Error(`bob profile must round-trip, got "${readProfile('bob')}"`);
  }
  // ...but not Alice's: the handler checks op.signerId against the target.
  let crossWriteRefused = '';
  try {
    await updateProfile(bobKey, 'alice', 'Bogus Name');
  } catch (crossWrite) {
    crossWriteRefused = String(crossWrite.message);
  }
  if (!crossWriteRefused.includes('unauthorized')) {
    throw new Error(`a cross-profile write must be refused, got "${crossWriteRefused}"`);
  }
  if (readProfile('alice') !== 'Vic Morrow') {
    throw new Error('a refused write must not touch the register');
  }

  // LWW: alice's second update supersedes the first.
  await updateProfile(aliceKey, 'alice', 'V. Morrow');
  if (readProfile('alice') !== 'V. Morrow') {
    throw new Error(`latest write must win, got "${readProfile('alice')}"`);
  }

  console.log('profile OK: alice+bob own and update their registers, cross-write refused');
  node.destroy();
  aliceKey.destroy();
  bobKey.destroy();
}
main()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });