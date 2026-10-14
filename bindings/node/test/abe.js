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

// ============================================================
// ABE key transport (parity-fill P4) — mirrors the wasm battery
// (bindings/wasm/test/key-transport.js) and pins the same C flows:
// user-key wire (crypto.c:872-899), the KeyEnvelope battery
// (test_crypto.cpp:963-1032), and the §11.5 master-key durability round
// trip (test_crypto.cpp:1199-1256). See the wasm file's header comment for
// the three transport shapes' trust posture: the user-key wire is a
// SELF-SUFFICIENT BEARER image (carries its own minting domain, no integrity
// check); the envelope is the authenticated transport; the master-key wire
// is the CROWN JEWEL backup.
// ============================================================

// --- 1. toWire / abeKeyFromWire round trip == same decrypt capability ---
const transportWire = readerWireSource();
const restoredWireKey = node.abeKeyFromWire(transportWire);
assert.ok(node.abeDecrypt(restoredWireKey, sealed).equals(payload),
  'the wire-restored key must decrypt exactly what the minted key decrypted');
restoredWireKey.destroy();

function readerWireSource() {
  const sourceKey = node.abeKeygen('moderator,member');
  const wire = sourceKey.toWire();
  assert.ok(Buffer.isBuffer(wire) && wire.length > 0,
    'toWire returns a non-empty Buffer');
  sourceKey.destroy();
  return wire;
}

// Wrapper conventions: idempotent destroy; a destroyed key refuses toWire.
const twiceKey = node.abeKeygen('moderator,member');
twiceKey.destroy();
twiceKey.destroy();
assert.throws(() => twiceKey.toWire(), KeyDestroyedError);

// Empty wire refuses loudly at the boundary (typed invalid_param).
assert.throws(() => node.abeKeyFromWire(Buffer.alloc(0)), /invalid_param/);

// Wrong-attrs wire: a 'guest' key wire restores but refuses the expected
// policy — capability does not travel with the wrong attribute set.
const guestWireKey = (function () {
  const guestKey = node.abeKeygen('guest');
  const wire = guestKey.toWire();
  guestKey.destroy();
  return node.abeKeyFromWire(wire);
})();
assert.throws(
  () => node.abeDecrypt(guestWireKey, sealed),
  (refusal) => refusal instanceof Error && /unauthorized/.test(refusal.message),
  'a wrong-attrs key wire must refuse the expected policy');
guestWireKey.destroy();

// Foreign-machine restore: the user-key wire is SELF-SUFFICIENT — restored
// on a stranger machine (its own fresh authority; the C deserialize takes
// mk only as a required param source), it opens EXACTLY what its minting
// authority sealed and refuses another machine's authority. The capability
// is the bearer wire's, not the importing machine's.
const stranger = new Node('stranger', { ordering: 'hlc' });
const strangerKey = stranger.abeKeyFromWire(transportWire);
assert.ok(stranger.abeDecrypt(strangerKey, sealed).equals(payload),
  'the wire carries its own minting domain capability across machines');
const strangerCt = stranger.encrypt(payload, 'moderator and member');
assert.throws(
  () => stranger.abeDecrypt(strangerKey, strangerCt),
  (refusal) => refusal instanceof Error && /unauthorized/.test(refusal.message),
  'the restored key refuses a ciphertext of a foreign authority');
strangerKey.destroy();

console.log('key-transport wire OK: round trip == capability, wrong-attrs refusal, bearer cross-machine semantics, destroy idempotent');

// --- 2. Key envelopes — the C KeyEnvelope battery's flow ---
// The envelope wraps a key for the user's CURRENT attribute string — a
// user record holds ONE value per attribute NAME (the role:member grant was
// overwritten by role:moderator above, keyVersion bumped), and the token
// map applies — so this envelope's key satisfies the role_moderator word.
const envelope = node.mintKeyEnvelope('alice');
assert.ok(Buffer.isBuffer(envelope) && envelope.length > 0,
  'mintKeyEnvelope returns the envelope wire');
const envelopeKey = node.decryptKeyEnvelope(envelope,
  { privateKeyHex: aliceKey.privateKeyHex() });
const moderatorSealed = node.encrypt(payload, 'role_moderator');
assert.ok(node.abeDecrypt(envelopeKey, moderatorSealed).equals(payload),
  'the envelope-restored key must be decrypt-capable');
envelopeKey.destroy();

// Wrong recipient private key → ECIES tag mismatch → typed unauthorized
// (the audit H-A regression shape).
assert.throws(
  () => node.decryptKeyEnvelope(envelope, { privateKeyHex: bobKey.privateKeyHex() }),
  (refusal) => refusal instanceof Error && /unauthorized/.test(refusal.message),
  'a wrong recipient key must refuse with unauthorized');

// Tampered envelope wire → the ECDSA signature fails → typed unauthorized.
const tamperedEnvelope = Buffer.from(envelope);
tamperedEnvelope[Math.floor(tamperedEnvelope.length / 2)] ^= 0xff;
assert.throws(
  () => node.decryptKeyEnvelope(tamperedEnvelope,
    { privateKeyHex: aliceKey.privateKeyHex() }),
  (refusal) => refusal instanceof Error && /unauthorized/.test(refusal.message),
  'a tampered envelope wire must fail closed');

// An envelope from ANOTHER machine refuses under this machine's own node key
// by default (fail-closed); passing the ISSUER's public key opens it — and
// the restored key works on THIS machine.
const otherNode = new Node('other', { ordering: 'hlc' });
const carolKey = KeyPair.generate();
otherNode.registerUser('carol', carolKey.publicKeyHex(), '');
otherNode.grantRole('carol', 'role', 'member', 'other');  // the machine's own admin
const foreignEnvelope = otherNode.mintKeyEnvelope('carol');
const foreignSealed = otherNode.encrypt(payload, 'member');
assert.throws(
  () => node.decryptKeyEnvelope(foreignEnvelope,
    { privateKeyHex: carolKey.privateKeyHex() }),
  (refusal) => refusal instanceof Error && /unauthorized/.test(refusal.message),
  'a foreign envelope must refuse under the wrong issuer key');
const imported = node.decryptKeyEnvelope(foreignEnvelope,
  { privateKeyHex: carolKey.privateKeyHex(),
    nodePublicKeyHex: otherNode.getNodeKey().publicKeyHex });
const foreignRoleSealed = otherNode.encrypt(payload, 'role_member');
assert.throws(
  () => node.abeDecrypt(imported, foreignSealed),
  (refusal) => refusal instanceof Error && /unauthorized/.test(refusal.message),
  'carol\'s registered-attribute key refuses the plain-word policy');
assert.ok(node.abeDecrypt(imported, foreignRoleSealed).equals(payload),
  'with the issuer key the foreign envelope opens AND the key works here');
imported.destroy();

// Typed gate refusals: malformed wire (invalid_param), unknown user
// (user_not_found), and the refresh-path ACTIVE gate (audit H-C):
// a suspended user refuses user_suspended.
assert.throws(
  () => node.decryptKeyEnvelope(Buffer.alloc(16),
    { privateKeyHex: aliceKey.privateKeyHex() }),
  (refusal) => /invalid_param/.test(refusal.message));
assert.throws(
  () => node.mintKeyEnvelope('nobody'),
  (refusal) => /user_not_found/.test(refusal.message));
node.suspendUser('alice', 'admin');
assert.throws(
  () => node.mintKeyEnvelope('alice'),
  (refusal) => /user_suspended/.test(refusal.message));
node.activateUser('alice', 'admin');

// Expiry is stamped into the envelope and still round-trips (enforcement is
// integrator-side in C).
const expiringKey = node.decryptKeyEnvelope(
  node.mintKeyEnvelope('alice', { expiresAt: 4102444800000 }),
  { privateKeyHex: aliceKey.privateKeyHex() });
expiringKey.destroy();

console.log('key-transport envelopes OK: mint/open round trip, wrong-recipient + tamper + foreign-issuer fail-closed, ACTIVE gate pinned');

// --- 3. Master-key durability (§11.5) — the CROWN JEWEL backup ---
const crownJewel = node.serializeMasterKey();
assert.ok(Buffer.isBuffer(crownJewel) && crownJewel.length > 0,
  'serializeMasterKey returns the authority wire');
const restorer = new Node('admin', { ordering: 'hlc' });
restorer.masterKeyFromWire(crownJewel);
const domainKey = restorer.abeKeygen('moderator,member');
assert.ok(restorer.abeDecrypt(domainKey, sealed).equals(payload),
  'the restored authority must mint keys in the SAME domain');
domainKey.destroy();

// Garbage / overrun-length wire refuses (the C battery's pins).
assert.throws(() => node.masterKeyFromWire(Buffer.alloc(16)), /invalid_param/);
const overrun = Buffer.alloc(11);
overrun.set([0x4D, 0x4B, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
assert.throws(() => node.masterKeyFromWire(overrun), /invalid_param/);

// Shape confusion refuses: a user-key wire is not authority wire.
assert.throws(() => node.masterKeyFromWire(transportWire), /invalid_param/);

console.log('key-transport master OK: durability round trip into a fresh machine, garbage + shape-confusion refusals');
