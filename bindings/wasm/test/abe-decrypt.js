'use strict';

// ABE keygen + decrypt from JS (gap-fill A11): the machine owns the master
// key — JS never sees the MSK; `abeKeygen` derives a reader key from the
// machine's own authority and `abeDecrypt` opens `encrypt`'s container.
//
// Token mapping pinned end to end: keygen attrs are comma-separated CRABS
// tokens, ':' maps to '_' and ',' to '|' before OpenABE sees them
// (src/Crypto/crypto.c:98-111); the encrypt policy is passed through RAW, so
// the policy words must already be the mapped form. Both conventions are
// pinned below (plain words mirror test/test_crypto.cpp:163-301; colon
// tokens mirror the recipes' attribute words).
//
// Container layout (bindings/wasm/test/smoke.js:111-130): u16le policy byte
// length + policy bytes + u32le ciphertext length + ciphertext.

const assert = require('assert');
const { Node, KeyPair } = require('..');

async function main() {
  // Recipe 16's admin setup: register alice (role:member) + bob (regular).
  const node = await Node.create('admin', { ordering: 'hlc' });
  const aliceKey = await KeyPair.generate();
  const bobKey = await KeyPair.generate();
  node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'admin');
  node.grantRole('alice', 'role', 'moderator', 'admin');
  node.registerUser('bob', bobKey.publicKeyHex(), 'adult');
  node.grantRole('bob', 'role', 'member', 'admin');

  const plaintext = new TextEncoder().encode('recipe-6 contact card');
  const policy = 'moderator and member';

  // --- right-attrs key decrypts ---
  const sealed = node.encrypt(plaintext, policy);
  const readerKey = node.abeKeygen('moderator,member');
  const opened = node.abeDecrypt(readerKey, sealed);
  assert.ok(opened instanceof Uint8Array, 'decrypt must return a Uint8Array');
  assert.strictEqual(new TextDecoder().decode(opened), 'recipe-6 contact card');
  readerKey.destroy();

  // --- machine-derived key object behaves like KeyPair: destroy, then refuse ---
  const onceKey = node.abeKeygen('moderator,member');
  onceKey.destroy();
  assert.throws(() => node.abeDecrypt(onceKey, sealed), /destroy/);

  // --- missing clause refuses with the typed error word ---
  const guestKey = node.abeKeygen('guest');
  assert.throws(() => node.abeDecrypt(guestKey, sealed),
    (refusal) => refusal instanceof Error && /unauthorized/.test(refusal.message),
    'a policy-missing key must refuse with unauthorized');
  guestKey.destroy();

  // --- partial clause: member only, moderator required too ---
  const bobReaderKey = node.abeKeygen('member');
  assert.throws(() => node.abeDecrypt(bobReaderKey, sealed),
    (refusal) => /unauthorized/.test(refusal.message),
    'an AND clause the key lacks must refuse');
  bobReaderKey.destroy();

  // --- colon-token map: attrs 'role:member,role:moderator' become ABE words
  // role_member|role_moderator, so the policy must carry the mapped words.
  const colonSealed = node.encrypt(plaintext, 'role_member and role_moderator');
  const colonKey = node.abeKeygen('role:member,role:moderator');
  assert.strictEqual(
    new TextDecoder().decode(node.abeDecrypt(colonKey, colonSealed)),
    'recipe-6 contact card',
    'colon tokens in keygen attrs must satisfy the mapped policy words');
  // And the unmixed combination must NOT: plain 'member' does not satisfy
  // the mapped 'role_member' word.
  const plainKey = node.abeKeygen('moderator,member');
  assert.throws(() => node.abeDecrypt(plainKey, colonSealed),
    (refusal) => /unauthorized/.test(refusal.message));
  colonKey.destroy();
  plainKey.destroy();

  // --- tampered ciphertext refuses (GCM fail-closed surfaces unauthorized) ---
  const tampered = Uint8Array.from(sealed);
  tampered[tampered.length - 1] ^= 0xff;
  const tamperKey = node.abeKeygen('moderator,member');
  assert.throws(() => node.abeDecrypt(tamperKey, tampered),
    (refusal) => /unauthorized/.test(refusal.message),
    'tampering must fail closed');
  tamperKey.destroy();

  // --- malformed containers refuse loudly at the binding boundary ---
  const headerOnly = sealed.subarray(0, 2); // policy length with no lengths body
  const keyForMalformed = node.abeKeygen('moderator,member');
  assert.throws(() => node.abeDecrypt(keyForMalformed, headerOnly),
    /container/);
  const truncated = sealed.subarray(0, sealed.length - 1); // ct short of declared length
  assert.throws(() => node.abeDecrypt(keyForMalformed, truncated),
    /container/);
  keyForMalformed.destroy();

  console.log('abe-decrypt OK: keygen/decrypt round trip, unauthorized refusals, token map, tamper fail-closed');
  node.destroy();
  aliceKey.destroy();
  bobKey.destroy();
}

main()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });