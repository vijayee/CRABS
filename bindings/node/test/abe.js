'use strict';

// ABE keygen + decrypt from JS (gap-fill A11, crabs-node): the machine owns
// the CP-ABE master key — JS never sees the MSK. `abeKeygen(attrs)` derives a
// reader key from the machine's own authority and `abeDecrypt(key, sealed)`
// opens the container `encrypt` returned. Mirrors the wasm battery
// (bindings/wasm/test/abe-decrypt.js) and the C battery it both pin
// (test/test_crypto.cpp:163-301).
//
// Token mapping pinned end to end: keygen attrs are comma-separated CRABS
// tokens, ':' maps to '_' and ',' to '|' before OpenABE sees them
// (src/Crypto/crypto.c:98-111); the encrypt policy is passed through RAW, so
// the policy words must already be the mapped form.
//
// Container layout (bindings/node/src/crabs_node.cc Encrypt + the wasm smoke
// pin): u16le policy byte length + policy bytes + u32le ciphertext length +
// ciphertext.

const assert = require('assert');
const { Node, KeyPair } = require('..');

// Recipe 16's admin setup: register alice (member + moderator words minted
// by the machine's keygen) + bob (regular member, no moderator clause).
const ADMIN = 'admin';
const node = new Node(ADMIN, { ordering: 'hlc' });
const aliceKey = KeyPair.generate();
const bobKey = KeyPair.generate();
node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
node.grantRole('alice', 'role', 'member', ADMIN);
node.grantRole('alice', 'role', 'moderator', ADMIN);
node.registerUser('bob', bobKey.publicKeyHex(), 'adult');
node.grantRole('bob', 'role', 'member', ADMIN);

const policy = 'moderator and member';
const payload = Buffer.from('recipe-6 contact card', 'utf8');

// --- right-attrs key decrypts ---
const sealed = node.encrypt(payload, policy);
const readerKey = node.abeKeygen('moderator,member');
const opened = node.abeDecrypt(readerKey, sealed);
assert.ok(Buffer.isBuffer(opened), 'decrypt must return a Buffer');
assert.ok(opened.equals(payload), `round trip mismatch: ${opened.toString('utf8')}`);
readerKey.destroy();

// --- machine-derived key object follows the wrapper destroy convention ---
const onceKey = node.abeKeygen('moderator,member');
onceKey.destroy();
assert.throws(() => node.abeDecrypt(onceKey, sealed), KeyDestroyedError);
readerKeyReDestroyCheck(readerKey);

// --- missing clause refuses with the typed error word ---
const guestKey = node.abeKeygen('guest');
assert.throws(() => node.abeDecrypt(guestKey, sealed),
  (refusal) => refusal instanceof Error && /unauthorized/.test(refusal.message),
  'a policy-missing key must refuse with unauthorized');
guestKey.destroy();

// --- partial clause: bob holds member but sealed policy requires moderator too ---
const bobReaderKey = node.abeKeygen('member');
assert.throws(() => node.abeDecrypt(bobReaderKey, sealed),
  (refusal) => /unauthorized/.test(refusal.message),
  'an AND clause the key lacks must refuse');
bobReaderKey.destroy();

// --- colon-token map: ':' -> '_' in keygen attrs ---
const colonSealed = node.encrypt(payload, 'role_member and role_moderator');
const colonKey = node.abeKeygen('role:member,role:moderator');
assert.ok(node.abeDecrypt(colonKey, colonSealed).equals(payload),
  'colon tokens in keygen attrs must satisfy the mapped policy words');
const plainKey = node.abeKeygen('moderator,member');
assert.throws(() => node.abeDecrypt(plainKey, colonSealed),
  (refusal) => /unauthorized/.test(refusal.message));
colonKey.destroy();
plainKey.destroy();

// --- tampered ciphertext refuses (GCM fail-closed surfaces unauthorized) ---
const tampered = Buffer.from(sealed);
tampered[tampered.length - 1] ^= 0xff;
const tamperKey = node.abeKeygen('moderator,member');
assert.throws(() => node.abeDecrypt(tamperKey, tampered),
  (refusal) => /unauthorized/.test(refusal.message),
  'tampering must fail closed');
tamperKey.destroy();

// --- malformed containers refuse loudly at the binding boundary ---
const malformedKey = node.abeKeygen('moderator,member');
assert.throws(() => node.abeDecrypt(malformedKey, sealed.subarray(0, 2)),
  /container/);
assert.throws(() => node.abeDecrypt(malformedKey, sealed.subarray(0, sealed.length - 1)),
  /container/);
malformedKey.destroy();

console.log('abe OK: keygen/decrypt round trip, unauthorized refusals, token map, tamper fail-closed');

function KeyDestroyedError(refusal) {
  return refusal instanceof Error && /destroy/.test(refusal.message);
}

// .destroy() twice is a no-op (the wrapper nulls its pointer), matching
// KeyPair's contract on both bindings.
function readerKeyReDestroyCheck(key) {
  key.destroy();
  key.destroy();
}