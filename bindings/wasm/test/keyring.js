'use strict';

// Keyring lifecycle (parity-fill P2):
//
// suspendKey / activateKey / rotateKey drive the user_t-scoped C keyring
// primitives (user_key_suspend / user_key_activate / user_key_rotate,
// src/Attribute/attribute_machine.h:219-221) through a RESOLVED user
// (`attribute_machine_find_user`) — the C keyring API is user_t-scoped and
// intentionally carries NO signer gate (the wire ops __suspend_key__ /
// __activate_key__ / __rotate_key__ own the policy story), so the wrapper's
// user-id surface is the honest shape.
//
// The tests seed the keyring through the machine's own self-service wire op
// (__register_key__ — the payload layout test/test_key_ops.cpp:118-141 pins),
// then pin:
//   - readback: listKeys/getDefaultKey + the keyVersion bump on suspend,
//     activate and rotate (getUser.keyVersion);
//   - rotation: old key REVOKED, new key ACTIVE with the predecessor chain,
//     label and scheme carried;
//   - typed refusals: resource_not_found (unknown user/key), key_not_active
//     (double suspend), key_revoked (activate after rotate),
//     duplicate_operation (rotate onto an existing id);
//   - R8-C-2 fail-closed: once a user HAS a keyring, the binding's
//     legacy-path signing (ops without a key_id) refuses with `unauthorized`
//     (src/Crypto/crypto.c:1349-1357) — exactly the C-integrator fact.
//
// NOT pinned here: a genuine `key_stale` replay — the executor's staleness
// gate (state_machine.c:884-891) runs AFTER signature verification, and a
// keyring-ed user refuses at verify first. The key_stale story is pinned by
// P3 (suspendUser bumps key_version on a keyring-less user).

const assert = require('assert');
const { Node, KeyPair, Operation } = require('..');

// Decode 66-hex-char public key text into the 33 wire bytes the
// __register_key__ payload carries after its NUL-terminated config string.
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

(async () => {
  const node = await Node.create('admin', { ordering: 'hlc' });
  const aliceKey = await KeyPair.generate();
  const bobKey = await KeyPair.generate();
  node.registerUser('alice', aliceKey.publicKeyHex(), '');
  node.registerUser('bob', bobKey.publicKeyHex(), '');
  // A fresh user stamps keyVersion 1 (attribute_machine.c:495).
  assert(node.getUser('alice').keyVersion === 1,
    'a fresh user stamps keyVersion 1');
  node.grantRole('alice', 'role', 'member', 'admin');
  node.grantRole('bob', 'role', 'member', 'admin');
  // The keyring seed rides the machine's own self-service wire op — the
  // executor fail-closes any op type without a registered policy (audit L-a),
  // so the seed op needs its policy line too (the C test env registers the
  // builtin policies under test_key_ops.cpp; the bindings register it here).
  node.setPolicy('__register_key__', 'role:member');

  // ------------------------------------------------------------------
  // Seed the keyring through the C-native self-service wire op
  // (payload: "key_id=<id>;scheme=<num>;public_key_len=<len>" + NUL + pk).
  // ------------------------------------------------------------------
  async function registerKeyWire(userId, keyPair, keyId) {
    const config = `key_id=${keyId};scheme=1;public_key_len=33`;
    const configBytes = Buffer.from(config, 'utf8');
    const payload = new Uint8Array(configBytes.length + 1 + 33);
    payload.set(configBytes, 0);
    payload[configBytes.length] = 0;
    payload.set(hexToBytes(keyPair.publicKeyHex()), configBytes.length + 1);
    const op = await Operation.create('__register_key__');
    op.signerId = userId;
    op.payload = payload;
    node.sign(op, keyPair);
    node.execute(op);
  }

  // The keyring-less signer rides the legacy path: both seeds execute.
  await registerKeyWire('bob', bobKey, 'b1');
  await registerKeyWire('alice', aliceKey, 'k1');

  // Registration does NOT bump key_version (user_key_register touches no
  // version counter — the grantRole bump above is the attribute layer) —
  // the first keyring key just becomes the default.
  const preSeedVersion = node.getUser('alice').keyVersion;
  assert(node.getDefaultKey('alice') === 'k1',
    'the first keyring key becomes the default');

  // R8-C-2 fail-closed (pinned, not regressed): now that alice HAS a keyring,
  // a further legacy-path op (a seed op for another id, exactly the shape
  // that succeeded for keyring-less bob above) refuses at verification.
  await assert.rejects(async () => {
    try {
      await registerKeyWire('alice', aliceKey, 'k1-legacy');
    } catch (refusal) {
      assert.match(refusal.message, /unauthorized/,
        `the refusal must be the fail-closed verify gate, got ${refusal.message}`);
      throw refusal;
    }
  });

  // ------------------------------------------------------------------
  // suspendKey: version bump + status readback.
  // ------------------------------------------------------------------
  const versionBeforeSuspend = node.getUser('alice').keyVersion;
  node.suspendKey('alice', 'k1');
  assert(node.getUser('alice').keyVersion === versionBeforeSuspend + 1,
    'suspending a key must bump the user keyVersion from its pre-seed value');
  assert.strictEqual(versionBeforeSuspend, preSeedVersion,
    'registering the first keyring key must not bump keyVersion');
  assert.deepStrictEqual(node.listKeys('alice'), [{
    keyId: 'k1',
    schemeId: 1,
    status: 'suspended',
    label: '',
    predecessorKeyId: '',
    publicKeyHex: aliceKey.publicKeyHex(),
  }], 'the suspended key reads back KEY_SUSPENDED');
  assert(node.listKeys('bob').length === 1 &&
         node.listKeys('bob')[0].keyId === 'b1' &&
         node.listKeys('bob')[0].status === 'active',
    'suspension touches only the target user');
  assert(node.getDefaultKey('alice') === '', 'the last active key suspends to no default');

  // Typed refusals mirror test_key_lifecycle.cpp.
  assert.throws(() => node.suspendKey('alice', 'k1'), /key_not_active/,
    'suspending a non-active key refuses key_not_active');
  assert.throws(() => node.suspendKey('alice', 'zz'), /resource_not_found/,
    'suspending an unknown key refuses resource_not_found');
  assert.throws(() => node.suspendKey('ghost', 'k1'), /user_not_found/,
    'suspending a key of an unknown user refuses user_not_found');

  // ------------------------------------------------------------------
  // activateKey: restore (idempotent when already active, per C).
  // ------------------------------------------------------------------
  node.activateKey('alice', 'k1');
  assert(node.listKeys('alice')[0].status === 'active',
    'the reactivated key reads back KEY_ACTIVE');
  assert(node.getUser('alice').keyVersion === versionBeforeSuspend + 2,
    'activating a key bumps keyVersion again (the suspension-era version dies)');
  // Activation does NOT restore a vacated default (user_key_activate touches
  // no default slot — attribute_machine.c:1254-1273); only rotate and the
  // register path move the default needle back.
  assert(node.getDefaultKey('alice') === '',
    'activating does not restore the vacated default (C fact)');
  assert(node.activateKey('alice', 'k1') === undefined &&
         node.listKeys('alice')[0].status === 'active',
    'activating an already-active key is idempotent (CRABS_SUCCESS)');

  // ------------------------------------------------------------------
  // rotateKey: explicit material, no auto-generation — the C rotate
  // signature takes (old, new, scheme, pk bytes, label) and the JS shape
  // carries them as named args.
  // ------------------------------------------------------------------
  const versionBeforeRotate = node.getUser('alice').keyVersion;
  node.rotateKey('alice', 'k1', 'k2', {
    scheme: 'ecdsa_secp256k1',
    publicKeyHex: bobKey.publicKeyHex(),  // alice's "new epoch" key material
    label: 'rotated primary',
  });
  assert(node.getUser('alice').keyVersion === versionBeforeRotate + 1,
    'rotation bumps keyVersion once (the old-key revocation)');
  const keys = node.listKeys('alice');
  assert.strictEqual(keys.length, 2, 'rotation registers the new key');
  const oldKey = keys.find((key) => key.keyId === 'k1');
  const newKey = keys.find((key) => key.keyId === 'k2');
  assert.strictEqual(oldKey.status, 'revoked',
    'the rotated-out key reads back KEY_REVOKED');
  assert.strictEqual(newKey.status, 'active', 'the new key reads back KEY_ACTIVE');
  assert.strictEqual(newKey.predecessorKeyId, 'k1',
    'the rotation links the predecessor chain');
  assert.strictEqual(newKey.label, 'rotated primary', 'the label carries');
  assert.strictEqual(newKey.publicKeyHex, bobKey.publicKeyHex(),
    'the declared material carries, not auto-generated');
  assert.strictEqual(newKey.schemeId, 1, 'the declared scheme carries');
  assert(node.listKeys('bob').length === 1 && node.listKeys('bob')[0].keyId === 'b1',
    'rotation touches only the target user');
  assert(node.getDefaultKey('alice') === 'k2', 'rotation transitions the default');

  // Rotate refusals (mirror test_key_lifecycle.cpp).
  assert.throws(() => node.rotateKey('alice', 'zz', 'k3',
    { scheme: 'ecdsa_secp256k1', publicKeyHex: aliceKey.publicKeyHex() }),
    /resource_not_found/,
    'rotating an unknown old key refuses resource_not_found');
  assert.throws(() => node.rotateKey('alice', 'k2', 'k2',
    { scheme: 'ecdsa_secp256k1', publicKeyHex: aliceKey.publicKeyHex() }),
    /duplicate_operation/,
    'rotating onto an existing key id refuses duplicate_operation');
  assert.throws(
    () => node.rotateKey('ghost', 'k2', 'k3',
      { scheme: 'ecdsa_secp256k1', publicKeyHex: aliceKey.publicKeyHex() }),
    /user_not_found/,
    'rotating for an unknown user refuses user_not_found');
  assert.throws(
    () => node.rotateKey('alice', 'k2', 'k3', { scheme: 'ecdsa_secp256k1' }),
    /publicKeyHex/,
    'rotation without material refuses at the wrapper');
  assert.throws(
    () => node.rotateKey('alice', 'k2', 'k3',
      { scheme: 'feudal', publicKeyHex: aliceKey.publicKeyHex() }),
    /scheme must be/,
    'an unknown scheme word refuses at the wrapper');
  assert.throws(
    () => node.rotateKey('alice', 'k1', 'k5',
      { scheme: 'ecdsa_secp256k1', publicKeyHex: aliceKey.publicKeyHex() }),
    /key_not_active/,
    'rotating a revoked old key refuses key_not_active');

  // ------------------------------------------------------------------
  // Activate-after-rotate refusal (ActivateRejectsRevokedKey pin).
  // ------------------------------------------------------------------
  assert.throws(() => node.activateKey('alice', 'k1'), /key_revoked/,
    'activating a revoked key refuses key_revoked');

  console.log('keyring.js: all keyring-lifecycle assertions passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});