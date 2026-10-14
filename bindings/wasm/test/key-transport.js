'use strict';

// ABE key transport from JS (parity-fill P4). The C battery this pins:
//   - user-key wire:     crypto_abe_user_key_serialize/deserialize
//                        (src/Crypto/crypto.c:872-899)
//   - envelopes:         crypto_key_envelope_create/verify/decrypt_sk
//                        (test/test_crypto.cpp:963-1032 — the KeyEnvelope
//                        battery, incl. the audit H-A ECIES regression)
//   - master key:        TestDurability.MasterKeySerializeRoundTrip
//                        PreservesAuthority (test_crypto.cpp:1199-1238)
//                        + the garbage/overrun refusal pins (:1240-1256).
//
// The three transport shapes and their trust posture:
//   1. AbeKey.toWire() / node.abeKeyFromWire — the raw reader-key wire.
//      A SELF-SUFFICIENT BEARER image: it carries the key's own minting
//      domain (restored on any machine — even one holding a different
//      authority — it opens exactly what ITS minting authority sealed and
//      refuses others), with no integrity check of its own — carry it
//      authenticated.
//   2. mintKeyEnvelope / decryptKeyEnvelope — the authenticated transport:
//      node-ECDSA-signed canonical envelope, ABE key ECIES-wrapped to the
//      user's registered public key. Both tamper paths (wire tamper →
//      signature, recipient key / blob tamper → GCM tag) refuse with the
//      typed 'unauthorized'.
//   3. serializeMasterKey / masterKeyFromWire — the §11.5 CROWN JEWEL
//      backup: the restored authority is a FULL authority minting keys in
//      the same domain.

const assert = require('assert');
const { Node, KeyPair } = require('..');

(async () => {
  const node = await Node.create('admin', { ordering: 'hlc' });
  const aliceKey = await KeyPair.generate();
  const bobKey = await KeyPair.generate();
  node.registerUser('alice', aliceKey.publicKeyHex(), '');
  node.registerUser('bob', bobKey.publicKeyHex(), '');
  node.grantRole('alice', 'role', 'member', 'admin');
  node.grantRole('alice', 'role', 'moderator', 'admin');
  node.grantRole('bob', 'role', 'member', 'admin');

  const plaintext = new TextEncoder().encode('key-transport contact card');
  const policy = 'moderator and member';
  const sealed = node.encrypt(plaintext, policy);

  // ------------------------------------------------------------------
  // 1. toWire / abeKeyFromWire round trip == same decrypt capability.
  // ------------------------------------------------------------------
  const readerKey = node.abeKeygen('moderator,member');
  const wire = readerKey.toWire();
  assert.ok(wire instanceof Uint8Array && wire.length > 0,
    'toWire returns a non-empty Uint8Array');
  readerKey.destroy();

  const restored = node.abeKeyFromWire(wire);
  const opened = node.abeDecrypt(restored, sealed);
  assert.strictEqual(new TextDecoder().decode(opened), 'key-transport contact card',
    'the wire-restored key must decrypt exactly what the minted key decrypted');
  restored.destroy();

  // Wrapper conventions follow KeyPair: idempotent destroy; a destroyed key
  // refuses toWire and abeDecrypt.
  const repeatKey = node.abeKeygen('moderator,member');
  repeatKey.destroy();
  repeatKey.destroy();
  assert.throws(() => repeatKey.toWire(), /destroy/);
  assert.throws(() => node.abeDecrypt(repeatKey, sealed), /destroy/);

  // Malformed / empty wire refuses loudly at the boundary.
  assert.throws(() => node.abeKeyFromWire(new Uint8Array(0)), /wire/);

  // Wrong-attrs wire: capability does not survive the wrong attribute set —
  // a key wire minted for 'guest' restores on the same authority but decrypt
  // of the moderator+member policy refuses (fail-closed).
  const guestKey = node.abeKeygen('guest');
  const guestWire = guestKey.toWire();
  guestKey.destroy();
  const guestRestored = node.abeKeyFromWire(guestWire);
  assert.throws(
    () => node.abeDecrypt(guestRestored, sealed),
    (refusal) => /unauthorized/.test(refusal.message),
    'a wrong-attrs key wire must refuse the expected policy');
  guestRestored.destroy();

  // Foreign-machine restore: the user-key wire is SELF-SUFFICIENT — restored
  // on a stranger machine (its own fresh authority; the C deserialize takes
  // mk only as a required param source), it opens EXACTLY what its minting
  // authority sealed and refuses another machine's authority. The capability
  // is the bearer wire's, not the importing machine's.
  const stranger = await Node.create('stranger', { ordering: 'hlc' });
  const strangerKey = stranger.abeKeyFromWire(wire);
  const strangerOpen = stranger.abeDecrypt(strangerKey, sealed);
  assert.strictEqual(new TextDecoder().decode(strangerOpen), 'key-transport contact card',
    'the wire carries its own minting domain capability across machines');
  const strangerCt = stranger.encrypt(plaintext, 'moderator and member');
  assert.throws(
    () => stranger.abeDecrypt(strangerKey, strangerCt),
    (refusal) => /unauthorized/.test(refusal.message),
    'the restored key refuses a ciphertext of a foreign authority');
  strangerKey.destroy();
  stranger.destroy();

  // ------------------------------------------------------------------
  // 2. Key envelopes — the C KeyEnvelope battery's flow.
  // ------------------------------------------------------------------
  const envelope = node.mintKeyEnvelope('alice');
  assert.ok(envelope instanceof Uint8Array && envelope.length > 0,
    'mintKeyEnvelope returns the envelope wire');

  // The recipient (alice, whose public key is registered) opens it and gets
  // a decrypt-capable key back. The envelope wraps a key for the user's
  // CURRENT attribute string — a user record holds ONE value per attribute
  // NAME (the role:member grant is overwritten by role:moderator above,
  // keyVersion bumped), and the token map applies — so this envelope's key
  // satisfies the role_moderator word.
  const envelopeKey = node.decryptKeyEnvelope(envelope,
    { privateKeyHex: aliceKey.privateKeyHex() });
  const roleSealed = node.encrypt(plaintext, 'role_moderator');
  const envOpened = node.abeDecrypt(envelopeKey, roleSealed);
  assert.strictEqual(new TextDecoder().decode(envOpened), 'key-transport contact card',
    'the envelope-restored key must be decrypt-capable');
  envelopeKey.destroy();

  // A WRONG recipient private key refuses (ECIES GCM tag mismatch → the
  // typed unauthorized — the audit H-A regression shape).
  assert.throws(
    () => node.decryptKeyEnvelope(envelope, { privateKeyHex: bobKey.privateKeyHex() }),
    (refusal) => /unauthorized/.test(refusal.message),
    'a wrong recipient key must refuse with unauthorized');

  // A tampered envelope wire refuses (the ECDSA signature covers the
  // canonical envelope incl. the ECIES blob → typed unauthorized).
  const tamperedEnvelope = Uint8Array.from(envelope);
  tamperedEnvelope[Math.floor(tamperedEnvelope.length / 2)] ^= 0xff;
  assert.throws(
    () => node.decryptKeyEnvelope(tamperedEnvelope,
      { privateKeyHex: aliceKey.privateKeyHex() }),
    (refusal) => /unauthorized/.test(refusal.message),
    'a tampered envelope wire must fail closed');

  // An envelope from ANOTHER machine (different node key + authority)
  // refuses under this machine's own node key by default — the fail-closed
  // default. The explicit-issuer open exists on the C-shaped option
  // (nodePublicKeyHex) and is pinned on the node binding — wasm's getNodeKey
  // exposes NO node key material (by design, bindings/node returns it), so
  // the cross-machine open has no readback here; the option's happy path is
  // covered by the same C flow this binding shares.
  const otherNode = await Node.create('other', { ordering: 'hlc' });
  const carolKey = await KeyPair.generate();
  otherNode.registerUser('carol', carolKey.publicKeyHex(), '');
  otherNode.grantRole('carol', 'role', 'member', 'other');  // the machine's own admin
  const foreignEnvelope = otherNode.mintKeyEnvelope('carol');
  assert.throws(
    () => node.decryptKeyEnvelope(foreignEnvelope,
      { privateKeyHex: carolKey.privateKeyHex() }),
    (refusal) => /unauthorized/.test(refusal.message),
    'a foreign envelope must refuse under the wrong issuer key');

  // Malformed envelope wire refuses (typed invalid_param), unknown user
  // refuses (typed user_not_found).
  assert.throws(() => node.decryptKeyEnvelope(new Uint8Array(16), {
    privateKeyHex: aliceKey.privateKeyHex() }), /invalid_param/);
  assert.throws(() => node.mintKeyEnvelope('nobody'),
    (refusal) => /user_not_found/.test(refusal.message));

  // The refresh-path gates mirrored: a SUSPENDED user refuses
  // (audit H-C — only ACTIVE users receive envelopes).
  node.suspendUser('alice', 'admin');
  assert.throws(
    () => node.mintKeyEnvelope('alice'),
    (refusal) => /user_suspended/.test(refusal.message));
  node.activateUser('alice', 'admin');

  // Expiry is stamped (the C envelope carries it; enforcement is
  // integrator-side) — minting + decrypt with an expiry set still round-trips.
  // expiresAt accepts BigInt too (the shared number | bigint shape, capped
  // at MAX_SAFE_INTEGER).
  const expiringEnvelope = node.mintKeyEnvelope('alice', { expiresAt: 4102444800000 });
  const expiringKey = node.decryptKeyEnvelope(expiringEnvelope,
    { privateKeyHex: aliceKey.privateKeyHex() });
  expiringKey.destroy();
  const bigIntExpiringEnvelope = node.mintKeyEnvelope('alice',
    { expiresAt: 4102444800000n });
  const bigIntExpiringKey = node.decryptKeyEnvelope(bigIntExpiringEnvelope,
    { privateKeyHex: aliceKey.privateKeyHex() });
  bigIntExpiringKey.destroy();

  // Argument-shape refusals: bad option types throw before any staging.
  assert.throws(() => node.decryptKeyEnvelope(envelope,
    { privateKeyHex: 'zz' }), /privateKeyHex/);
  assert.throws(() => node.mintKeyEnvelope('alice', { expiresAt: -1 }), /expiresAt/);

  // ------------------------------------------------------------------
  // 3. Master-key durability (§11.5) — the CROWN JEWEL backup.
  // ------------------------------------------------------------------
  // A restorer starts with a FRESH authority, plants the backup, and mints
  // keys in the SAME domain — mirror of the C test's restore round trip.
  const restorer = await Node.create('admin', { ordering: 'hlc' });
  const crownJewel = node.serializeMasterKey();
  assert.ok(crownJewel instanceof Uint8Array && crownJewel.length > 0,
    'serializeMasterKey returns the authority wire');
  restorer.masterKeyFromWire(crownJewel);
  const restoredDomainKey = restorer.abeKeygen('moderator,member');
  const domainOpen = restorer.abeDecrypt(restoredDomainKey, sealed);
  assert.strictEqual(new TextDecoder().decode(domainOpen), 'key-transport contact card',
    'the restored authority must mint keys in the SAME domain');
  restoredDomainKey.destroy();

  // Garbage / truncated wire refuses (the C battery's pins): bad magic and
  // overrun-length length fields both fail closed with invalid_param.
  assert.throws(() => node.masterKeyFromWire(new Uint8Array(16)), /invalid_param/);
  const overrun = new Uint8Array(11);
  overrun.set([0x4D, 0x4B, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
  assert.throws(() => node.masterKeyFromWire(overrun), /invalid_param/);

  // A user-key wire is a bearer secret but NOT an authority: master wire
  // refuses on user-key input, user-key wire refuses on master wire input.
  assert.throws(() => node.masterKeyFromWire(wire), /invalid_param/);
  // Reverse shape confusion (P4 review): the 'MK' crown-jewel wire is an
  // AUTHORITY image, not a reader key — the reader-key import refuses it
  // typed (an authority image restores only through masterKeyFromWire).
  assert.throws(() => node.abeKeyFromWire(crownJewel), /invalid_param/);

  // ------------------------------------------------------------------
  // 4. Borrowed authority refuses the crown-jewel surface (P4 review).
  // ------------------------------------------------------------------
  // A SHARED_ROOT lineage child BORROWS the parent's live authority pointer.
  // The child may USE it (keygen/decrypt), but it is not entrusted with the
  // parent's MSK bytes at rest: serializeMasterKey refuses protocol_violation
  // (only the OWNING machine exports the 'MK' wire) and masterKeyFromWire
  // refuses to replace a borrowed authority (protocol_violation) — both
  // without mutating anything. The wrapper shape mirrors attestations.js:
  // the exported Node class wraps the borrowed pointer.
  const { Blueprint, TRUST_MODE, getModule } = require('..');
  const borrowBlueprint = await Blueprint.create('borrow-child',
    TRUST_MODE.SHARED_ROOT, 'borrow-admin', 3600000);
  const borrowChildPtr = node.lineageSpawn(borrowBlueprint);
  const moduleForChild = await getModule();
  const borrowChild = new Node(moduleForChild, borrowChildPtr);
  borrowChild.adminId = 'borrow-admin';
  assert.throws(
    () => borrowChild.serializeMasterKey(),
    (refusal) => /protocol_violation/.test(refusal.message),
    'a borrowed authority must refuse the crown-jewel export');
  assert.throws(
    () => borrowChild.masterKeyFromWire(crownJewel),
    (refusal) => /protocol_violation/.test(refusal.message),
    'a borrowed authority must refuse re-planting');
  // No either refusal mutated anything: the borrowed child still keys and
  // decrypts in the SHARED domain (a SHARED_ROOT child resolves the
  // parent's authority — same registry + same MSK).
  const stillMember = borrowChild.abeKeygen('moderator,member');
  borrowChild.abeDecrypt(stillMember, sealed);
  stillMember.destroy();
  borrowBlueprint.destroy();

  stranger.destroy();
  otherNode.destroy();
  console.log('key-transport OK: wire round trip == capability, wrong-attrs refusal, bearer cross-machine semantics, envelope flow + tamper fail-closed, master-key durability round trip, cross-wire + borrowed-authority refusals');
  node.destroy();
  aliceKey.destroy();
  bobKey.destroy();
})()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });