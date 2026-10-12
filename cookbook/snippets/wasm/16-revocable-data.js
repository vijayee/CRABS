'use strict';
// Recipe 16 — data that must be revocable (crabs-wasm, run in Node).
//
// What IS on this binding: policy-gated sealing (Node.encrypt), user-level
// revocation (revokeUser, admin-gated + terminal in C), and the fail-closed
// gate that refuses a revoked user's subsequent ops. What is NOT: decrypting
// the container (recipe 6's gap) and the key-level lifecycle (suspend /
// activate / rotate are C-only). The getUser readback of keyVersion/status
// is a wasm-side STUB (keyVersion: 0, status: 'active' hardcoded,
// bindings/wasm/bindings-core.js getUser) — demonstrated below, not hidden.

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../../../bindings/wasm');

async function main() {
  const node = await Node.create('admin', { ordering: 'hlc' });

  const readerKey = await KeyPair.generate();
  node.registerUser('reader', readerKey.publicKeyHex(), 'vetted');

  // The epoch observable exists in the machine (the user's key_version
  // bumps on every attribute mutation, src/Attribute/attribute_machine.c);
  // the wasm binding returns a STUB for it — pin the observed shape.
  const before = node.getUser('reader');
  assert.strictEqual(before.keyVersion, 0, 'wasm getUser readback is a stub (keyVersion hardcoded 0)');
  assert.strictEqual(before.status, 'active', 'wasm getUser readback is a stub (status hardcoded "active")');

  // Grant the reader what the policy will require. (The wasm readback
  // cannot show the bumps the machine made — see Notes on the page.)
  node.grantRole('reader', 'role', 'member', 'admin');

  // The write gate: a policy-gated custom op, written through the handler.
  node.addCounter('notes');
  node.setPolicy('adjust', 'role:member');
  node.registerHandlerJs('adjust', (state, op) => {
    state.incrementCounter('notes', 1, op.signerId);
    return 0;
  });
  const postAsReader = async () => {
    const op = await Operation.create('adjust');
    op.signerId = 'reader';
    op.nodeId = 'reader';
    node.sign(op, readerKey.privateKeyHex());
    try {
      node.execute(op);
      op.destroy();
      return 'executed';
    } catch (refusal) {
      op.destroy();
      return String(refusal.message);
    }
  };
  if ((await postAsReader()) !== 'executed') {
    throw new Error('the member op must land before revocation');
  }
  if (node.getCounter('notes') !== 1) {
    throw new Error(`expected notes=1, got ${node.getCounter('notes')}`);
  }

  // The payload: sealed under an attribute policy — the ABE-word form the
  // C key derivation produces for CRABS tokens (recipe 6's seal). Layout:
  // u16le policy byte length + policy bytes + u32le ciphertext length +
  // ciphertext (bindings/wasm/test/smoke.js:111-130 pins it).
  const sealed = node.encrypt('vault payload at epoch one', 'member');
  const view = new DataView(sealed.buffer, sealed.byteOffset, sealed.byteLength);
  const policyByteLength = view.getUint16(0, true);
  const policyText = new TextDecoder().decode(sealed.subarray(2, 2 + policyByteLength));
  if (policyText !== 'member') {
    throw new Error(`policy must round-trip in the container, got "${policyText}"`);
  }
  const ciphertextLength = view.getUint32(2 + policyByteLength, true);
  if (2 + policyByteLength + 4 + ciphertextLength !== sealed.byteLength) {
    throw new Error(`container length ${sealed.byteLength} must match header ${2 + policyByteLength + 4 + ciphertextLength}`);
  }

  // REVOCATION (the real, executable part): admin-gated, terminal in C
  // (attribute_machine_revoke_user — the signer must hold role:admin).
  node.revokeUser('reader', 'admin');

  // The failure mode the policy author should plan for... is the one that
  // DOES change: the revoked reader's next op is refused fail-closed —
  // (crypto_verify_operation_auth_v2 collapses to 'unauthorized' for a
  // non-ACTIVE signer, src/Crypto/crypto.c:1395-1403, R7-14).
  const afterRevoke = await postAsReader();
  if (!afterRevoke.includes('unauthorized')) {
    throw new Error(`revoked reader's op must be refused, got "${afterRevoke}"`);
  }
  if (node.getCounter('notes') !== 1) {
    throw new Error('a refused op must not land');
  }

  // Re-granting is refused too: the authorization gate whitelists
  // USER_ACTIVE only (attribute_machine.c:588 — audit R4-2), so a revoked
  // (or suspended) target cannot be silently re-armed with fresh attributes.
  let regrantRefusal = '';
  try {
    node.grantRole('reader', 'role', 'member', 'admin');
  } catch (refusal) {
    regrantRefusal = String(refusal.message);
  }
  if (!regrantRefusal.includes('user_suspended')) {
    throw new Error(`granting to a revoked target must be refused, got "${regrantRefusal}"`);
  }

  // Honest pin of the wasm-side readback stub: the machine revoked the user
  // (the refusals above are its consequence), but the browser CANNOT observe
  // it through getUser — keyVersion stays 0 and status stays 'active'.
  const stub = node.getUser('reader');
  assert.strictEqual(stub.keyVersion, 0, 'wasm getUser readback is a stub after revocation (keyVersion 0)');
  assert.strictEqual(stub.status, 'active', 'wasm getUser readback is a stub after revocation (status "active")');

  console.log('revocable-data OK: reader sealed+gated, revoked, re-ops refused, re-grant refused, wasm readback stub pinned');
  node.destroy();
  readerKey.destroy();
}
main()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });