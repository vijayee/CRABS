'use strict';

// Audit pass-3 D1: KeyPair.fromPrivateHex's DERIVE-failure path must reject
// cleanly. The fix cleanses the calloc'd ecdsa_keypair_t before free; the
// regression value of this test is pinning the rejection path itself so a
// refactor cannot skip the cleanse (or skip the rejection and hand out a
// keypair whose public key was never derived).
//
// Rejection semantics pinned from src/Crypto/crypto.c:_eckey_from_private
// (R8-C-7): a scalar is refused when it is zero, negative, or >= the
// secp256k1 group order n. So BOTH of these must throw:
//
//   - the all-zero scalar ('00' * 32)        — BN_is_zero
//   - 'ff' * 32                              — BN_cmp(bn, n) >= 0
//
// (the all-zero scalar IS rejected by derive — it is not merely a weak key;
// BN_is_zero gates it before EC_KEY_set_private_key ever runs).

const assert = require('assert');
const { KeyPair } = require('..');

// --- rejected scalars refuse with the typed context word ---
assert.throws(
  () => KeyPair.fromPrivateHex('00'.repeat(32)),
  (refusal) => refusal instanceof Error &&
    /KeyPair\.fromPrivateHex|cryptographic/i.test(refusal.message),
  'all-zero scalar must be rejected by fromPrivateHex');

assert.throws(
  () => KeyPair.fromPrivateHex('ff'.repeat(32)),
  (refusal) => refusal instanceof Error &&
    /KeyPair\.fromPrivateHex|cryptographic/i.test(refusal.message),
  'out-of-range (>= n) scalar must be rejected by fromPrivateHex');

// --- malformed hex still refuses on the decode path ---
assert.throws(
  () => KeyPair.fromPrivateHex('zz'),
  /Invalid private key hex/,
  'malformed hex must reject on decode');

// --- the happy path still derives and round-trips ---
const generated = KeyPair.generate();
const restored = KeyPair.fromPrivateHex(generated.privateKeyHex());
assert.strictEqual(restored.publicKeyHex(), generated.publicKeyHex(),
  'fromPrivateHex must derive the same compressed public key');
assert.strictEqual(restored.privateKeyHex(), generated.privateKeyHex(),
  'fromPrivateHex must keep the private key verbatim');

// Static derivePublicHex agrees with the object form on a valid scalar.
assert.strictEqual(KeyPair.derivePublicHex(generated.privateKeyHex()),
  generated.publicKeyHex(),
  'derivePublicHex must agree with the object derivation');

// KeyPair has no explicit destroy — the N-API finalizer runs
// crypto_ecdsa_keypair_destroy at GC. Let both wrappers go out of scope.

console.log('keypair-secret-lifecycle: ok');
process.exit(0);
