'use strict';

// getUser readback (gap-fill A1): the wasm binding must surface the REAL
// machine state — keyVersion stamped by register/grant, user status, the
// registered 33-byte public key, and per-attribute verifiedBy — instead of
// the hardcoded stub (publicKeyHex '', keyVersion 0, status 'active').

const assert = require('assert');
const { Node, KeyPair } = require('..');

(async () => {
  const node = await Node.create('admin', { ordering: 'hlc' });
  const key = await KeyPair.generate();
  node.registerUser('alice', key.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'admin');

  const user = node.getUser('alice');
  assert.strictEqual(user.userId, 'alice');
  // register_user stamps key_version = 1 (attribute_machine.c:495); the
  // role grant increments it to 2 (attribute_machine.c:617).
  assert.strictEqual(user.keyVersion, 2);
  assert.strictEqual(user.status, 'active');
  assert.strictEqual(user.publicKeyHex.length, 66, '33-byte ECDSA key, hex');
  assert.strictEqual(user.publicKeyHex, key.publicKeyHex());

  // The machine stores the grant as the formatted 'role:value' token
  // (attribute_machine.c:611), which is what policy evaluation matches.
  const role = user.attributes.find((attribute) => attribute.value === 'role:member');
  assert.ok(role, 'role attribute missing');
  assert.strictEqual(role.verifiedBy, 'admin');

  // revoke_user flips the record's status; the readback must follow.
  node.revokeUser('alice', 'admin');
  assert.strictEqual(node.getUser('alice').status, 'revoked');

  console.log('getUser readback OK');
})().catch((e) => { console.error(e); process.exit(1); });