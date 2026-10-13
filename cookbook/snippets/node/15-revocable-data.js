'use strict';
// Recipe 15 — data that must be revocable (crabs-node, driven directly).
//
// Same real surface as the wasm binding (encrypt + abeKeygen/abeDecrypt +
// revokeUser + the fail-closed gate): crabs-node maps
// UserInfo.keyVersion and UserInfo.status DIRECTLY from the machine
// (bindings/node/src/crabs_node.cc GetUser), so revocation is observable as
// a status flip plus a keyVersion bump. Still missing here: the key-level
// lifecycle (suspend/activate/rotate, C-only).

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../../../bindings/node');

const node = new Node('admin', { ordering: 'hlc' });

const readerKey = KeyPair.generate();
node.registerUser('reader', readerKey.publicKeyHex(), 'vetted');

// The epoch observable — REAL on this binding: a user starts at keyVersion 1
// (src/Attribute/attribute_machine.c:495) and every attribute mutation bumps
// it (:617 grant, :1231 key suspend, :900 revoke).
const afterRegister = node.getUser('reader');
assert.strictEqual(afterRegister.keyVersion, 1,
  `register should mint key_version 1, got ${afterRegister.keyVersion}`);

node.grantRole('reader', 'role', 'member', 'admin');
const afterGrant = node.getUser('reader');
assert.strictEqual(afterGrant.keyVersion, 2,
  `the admin grant should bump key_version to 2, got ${afterGrant.keyVersion}`);
assert.strictEqual(afterGrant.attributes.some((attribute) => attribute.value === 'role:member'),
  true, 'the granted attribute must be readable with its provenance');

// The write gate: policy-gated custom op. crabs-node has no handler surface
// — the "op landed" observable is the op change event with result === 0
// (recipe 2's landed contract, node test.js:143-147).
node.setPolicy('adjust', 'role:member');
const adjustEvents = [];
const attributeEvents = [];
node.on('change', (event) => {
  if (event.kind === 'op' && event.type === 'adjust' && event.result === 0) {
    adjustEvents.push(event);
  }
  // Revocation streams as an attribute-kind change: the emitted actions are
  // the handler names ("revoke_user", src/Attribute/attribute_machine.c).
  if (event.kind === 'attribute' && event.type === 'revoke_user') {
    attributeEvents.push(event);
  }
});
const postAsReader = (who, whoKey) => {
  const op = new Operation('adjust');
  op.signerId = who;
  op.addResource('notes');
  node.sign(op, whoKey);
  node.execute(op);
};

node.defineItem('notes', 'counter', 'g_counter');
postAsReader('reader', readerKey);
if (adjustEvents.length !== 1) {
  throw new Error(`the member op must land exactly once, got ${adjustEvents.length} adjust events`);
}

// The payload: the same container layout as wasm — u16le policy byte length
// + policy bytes + u32le ciphertext length + ciphertext
// (bindings/node/index.d.ts:257 prose; recipe 6's seal).
const sealed = node.encrypt(Buffer.from('vault payload at epoch one'), 'member');
{
  const layoutView = new DataView(sealed.buffer, sealed.byteOffset, sealed.byteLength);
  const policyByteLength = layoutView.getUint16(0, true);
  const policyText = sealed.subarray(2, 2 + policyByteLength).toString('utf8');
  if (policyText !== 'member') {
    throw new Error(`policy must round-trip in the container, got "${policyText}"`);
  }
  const ciphertextLength = layoutView.getUint32(2 + policyByteLength, true);
  if (2 + policyByteLength + 4 + ciphertextLength !== sealed.byteLength) {
    throw new Error(`container length ${sealed.byteLength} must match header ${2 + policyByteLength + 4 + ciphertextLength}`);
  }
}

// REVOCATION: admin-gated, terminal (attribute_machine_revoke_user,
// src/Attribute/attribute_machine.c:885-907). crabs-node defaults the
// signer to the machine's admin id.
node.revokeUser('reader');

// The readback the browser binding cannot show: terminal status + the bump.
const afterRevoke = node.getUser('reader');
assert.strictEqual(afterRevoke.status, 'revoked',
  `revocation must flip the status readback, got ${afterRevoke.status}`);
assert.strictEqual(afterRevoke.keyVersion, 3,
  `revocation must bump key_version to 3, got ${afterRevoke.keyVersion}`);
if (attributeEvents.length !== 1) {
  throw new Error(`revocation must stream one revoke_user attribute event, got ${attributeEvents.length}`);
}

// The failure mode that DOES change on revocation: the revoked reader's
// next op refuses fail-closed (R7-14 collapse — src/Crypto/crypto.c:1395).
let refusal = '';
try {
  postAsReader('reader', readerKey);
} catch (caught) {
  refusal = String(caught.message);
}
if (!refusal.includes('unauthorized')) {
  throw new Error(`revoked reader's op must be refused unauthorized, got "${refusal}"`);
}
if (adjustEvents.length !== 1) {
  throw new Error('a refused op must not land');
}

// Re-granting is refused: the gate whitelists USER_ACTIVE only
// (attribute_machine.c:588 — audit R4-2), even for a revoked target.
let regrantRefusal = '';
try {
  node.grantRole('reader', 'role', 'member', 'admin');
} catch (caught) {
  regrantRefusal = String(caught.message);
}
if (!regrantRefusal.includes('user_suspended')) {
  throw new Error(`granting to a revoked target must be refused, got "${regrantRefusal}"`);
}

// The decrypt half (gap-fill A11) — and the BEARER-INSTRUMENT boundary,
// executed after the revocation: keygen consults no user record, and
// decrypt consults no user record either (crypto_abe_keygen /
// crypto_abe_decrypt). A reader key derived from 'member' — minted here for
// a user the machine just revoked, because the machine mints from its own
// authority — STILL opens the epoch-one payload.
const readerAbeKey = node.abeKeygen('member');
const opened = node.abeDecrypt(readerAbeKey, sealed);
assert.strictEqual(opened.toString('utf8'), 'vault payload at epoch one',
  'the policy-derived key still opens the epoch-one payload after revocation');

// What recalls access is RE-SEALING under the next epoch's policy: epoch
// two refuses the epoch-one key and opens for a fresh derivation
// (recipe-level re-key convention — the library has no re-encrypt).
const epochTwo = node.encrypt(Buffer.from('vault payload at epoch two'), 'epoch_2 and member');
let epochRefusal = '';
try {
  node.abeDecrypt(readerAbeKey, epochTwo);
} catch (caught) {
  epochRefusal = String(caught.message);
}
if (!epochRefusal.includes('unauthorized')) {
  throw new Error(`epoch-one key must not open epoch-two data, got "${epochRefusal}"`);
}
const epochTwoKey = node.abeKeygen('epoch_2,member');
assert.strictEqual(node.abeDecrypt(epochTwoKey, epochTwo).toString('utf8'),
  'vault payload at epoch two', 'a fresh epoch-two derivation opens the re-sealed payload');

// The negative from the other side: a key minted for an attribute the
// policy never asks for refuses the epoch-one payload too (typed
// 'unauthorized' — also the tamper path, GCM fail-closed).
const outsiderKey = node.abeKeygen('guest');
let outsiderRefusal = '';
try {
  node.abeDecrypt(outsiderKey, sealed);
} catch (caught) {
  outsiderRefusal = String(caught.message);
}
if (!outsiderRefusal.includes('unauthorized')) {
  throw new Error(`a policy-missing key must be refused, got "${outsiderRefusal}"`);
}

console.log('revocable-data OK: reader seeded (kv 1->2), op landed, revoked (kv 3, status revoked, event streamed), re-ops and re-grants refused, old-seal bearer key still opened (post-revoke keygen+decrypt), epoch-two re-seal refused the old key and opened for a fresh one, outsider refused');