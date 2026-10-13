'use strict';

// Recipe 12 — the attestation-consumption half of the federation surface
// from JS (wasm): a spawned child's `@parent/` endorsement policy resolved
// against an attestation-carrying op. Mirrors the C battery in
// cookbook/snippets/c/12-federation-between-machines.c (the JS-reachable
// subset: endorsed op authorized, tampered signature, wrong attested user,
// uncovered attributes, wrong child, expired window — forged-parent and
// unbound-machine stay C-only because the binding can only mint REAL
// parent attestations and only spawns BOUND children).
//
// The executor consumes op attestations during authorization
// (src/StateMachine/state_machine.c _verify_parent_endorsements); the
// binding side is Operation.addAttestation (struct fill, mirror of
// crabs_wasm_op_add_lock_claim).

const assert = require('assert');
const { Node, KeyPair, Operation, Blueprint, getModule,
        TRUST_MODE } = require('..');
const { setTimeout: sleep } = require('timers/promises');

const CRABS_SIG_SIZE = 64;

// Parse a parent-issued attestation wire image into the fields
// Operation.addAttestation consumes. Canonical layout (src/Lineage/lineage.c,
// _attestation_write_canonical_body): u32le total length (excluding the
// prefix itself) + u8 format_version + string16 parent/child/user/attributes
// + u64le not_before, expires_at, parent_key_version + 64-byte signature.
function parseAttestationWire(wire) {
  const view = new DataView(wire.buffer, wire.byteOffset, wire.byteLength);
  const total = view.getUint32(0, true);
  assert.strictEqual(total, wire.length - 4,
    'attestation length prefix must cover body + signature');
  let offset = 4;
  assert.strictEqual(wire[offset], 0x02, 'attestation body format must be v2');
  offset += 1;
  const readString16 = () => {
    const len = view.getUint16(offset, true); offset += 2;
    const text = new TextDecoder().decode(wire.subarray(offset, offset + len));
    offset += len;
    return text;
  };
  const parentId = readString16();
  const childId = readString16();
  const userId = readString16();
  const attributes = readString16();
  const notBefore = view.getBigUint64(offset, true); offset += 8;
  const expiresAt = view.getBigUint64(offset, true); offset += 8;
  const parentKeyVersion = view.getBigUint64(offset, true); offset += 8;
  const signatureBytes = wire.subarray(offset, offset + CRABS_SIG_SIZE);
  assert.strictEqual(signatureBytes.length, CRABS_SIG_SIZE,
    'attestation wire must end with the 64-byte signature');
  return { parentId, childId, userId, attributes, notBefore, expiresAt,
           parentKeyVersion,
           signatureHex: Buffer.from(signatureBytes).toString('hex') };
}

// Flip the first hex digit of a signature — a deterministically tampered
// ECDSA (r||s legitimately contains zero bytes; never flip on those).
const tamperedSignatureHex = (signatureHex) =>
  (signatureHex.startsWith('a') ? 'b' : 'a') + signatureHex.slice(1);

// Execute refusals surface their typed code in the message; assert on it.
async function expectRefusal(runnable, expected, what) {
  try {
    await runnable();
  } catch (refusal) {
    assert(refusal.message.includes(expected),
      `${what}: expected "${expected}", got: ${refusal.message}`);
    return;
  }
  throw new Error(`${what}: expected a ${expected} refusal, got success`);
}

(async () => {
  // ---- The federating machines ------------------------------------------
  // Parent (the signer of attestations) + a DELEGATED_COPY child whose
  // authorization for __check_dedup__ is a pure `@parent/` endorsement.
  const parent = await Node.create('federation-root', { ordering: 'hlc' });
  parent.setTime(Date.now());

  const blueprintB = await Blueprint.create('machine-b',
    TRUST_MODE.DELEGATED_COPY, 'b-admin', 3600000);
  blueprintB.addPolicy('__check_dedup__', '@parent/role:member');
  blueprintB.stampHash();
  const childBPtr = parent.lineageSpawn(blueprintB);
  assert(parent.lineageResidentChild('machine-b') === childBPtr,
    'spawned child not resident');

  // JS never owns the child pointer — the parent's resident registry in C
  // anchors its lifetime — but the exported Node class wraps the borrowed
  // pointer exactly like the node binding's native child wrapper does
  // (api-map §10 pointer-vs-wrapper divergence).
  const M = await getModule();
  const childB = new Node(M, childBPtr);
  childB.adminId = 'b-admin';

  // The signed op: alice's `__check_dedup__` on the child, alice registered
  // in the child's OWN registry (DELEGATED_COPY mints a fresh authority).
  const aliceKey = await KeyPair.generate();
  childB.registerUser('alice', aliceKey.publicKeyHex(), '');

  // ---- The end-to-end consume: attach the parent's vouch → executes ------
  const attested = parseAttestationWire(
    parent.attest('machine-b', 'alice', 'role:member'));
  assert.strictEqual(attested.parentId, 'federation-root',
    'attestation must bind the parent id');
  assert.strictEqual(attested.childId, 'machine-b',
    'attestation must bind the child id');
  assert.strictEqual(attested.parentKeyVersion, 1n,
    'fresh parent stamps the spawn generation');

  const endorsedOp = await Operation.create('__check_dedup__');
  endorsedOp.signerId = 'alice';
  endorsedOp.nodeId = 'alice';
  endorsedOp.addAttestation(attested);
  childB.sign(endorsedOp, aliceKey.privateKeyHex());
  childB.execute(endorsedOp);   // the endorsement resolved: no refusal
  endorsedOp.destroy();

  // ---- Fail-closed battery ----------------------------------------------
  const makeEndorsedOp = async (attestation) => {
    const op = await Operation.create('__check_dedup__');
    op.signerId = 'alice';
    op.nodeId = 'alice';
    op.addAttestation(attestation);
    childB.sign(op, aliceKey.privateKeyHex());
    return op;
  };

  // Tampered signature: one flipped byte in the carried ECDSA breaks the
  // canonical-body verification.
  const tamperedOp = await makeEndorsedOp({
    ...attested, signatureHex: tamperedSignatureHex(attested.signatureHex),
  });
  await expectRefusal(() => childB.execute(tamperedOp),
    'unauthorized', 'tampered attestation signature');
  tamperedOp.destroy();

  // Wrong attested user: the attestation must name the RESOLVED signer.
  const wrongUserOp = await makeEndorsedOp(parseAttestationWire(
    parent.attest('machine-b', 'bob', 'role:member')));
  await expectRefusal(() => childB.execute(wrongUserOp),
    'unauthorized', 'wrong-user attestation');
  wrongUserOp.destroy();

  // Uncovered attributes: coverage is EXACT membership in the list.
  const uncoveredOp = await makeEndorsedOp(parseAttestationWire(
    parent.attest('machine-b', 'alice', 'role:reader')));
  await expectRefusal(() => childB.execute(uncoveredOp),
    'unauthorized', 'uncovered attestation attributes');
  uncoveredOp.destroy();

  // Wrong child id: a vouch for a DIFFERENT child never matches this
  // machine's lineage_self_id, even though the parent and signer line up.
  const blueprintC = await Blueprint.create('machine-c',
    TRUST_MODE.DELEGATED_COPY, 'c-admin', 3600000);
  blueprintC.stampHash();
  parent.lineageSpawn(blueprintC);
  const wrongChildOp = await makeEndorsedOp(parseAttestationWire(
    parent.attest('machine-c', 'alice', 'role:member')));
  await expectRefusal(() => childB.execute(wrongChildOp),
    'unauthorized', 'wrong-child attestation');
  wrongChildOp.destroy();

  // ---- The TTL: a real, signature-INTACT expired attestation -------------
  // ttl 0 stamps expires_at = now at MINT; every later wall-clock read sits
  // past the instant-long window, so the pipeline's expiry gate refuses. A
  // JS caller cannot mint a fresh-signed expired vouch any other way: the
  // window is stamped at issue time, and hand-edits break the signature.
  const blueprintNow = await Blueprint.create('machine-now',
    TRUST_MODE.DELEGATED_COPY, 'n-admin', 0);
  blueprintNow.stampHash();
  parent.lineageSpawn(blueprintNow);
  const childNow = new Node(M, parent.lineageResidentChild('machine-now'));
  childNow.adminId = 'n-admin';
  childNow.registerUser('alice', aliceKey.publicKeyHex(), '');
  const expiredWire = parent.attest('machine-now', 'alice', 'role:member');
  await sleep(50);   // walk the wall clock past the single-instant window
  const expiredOp = await Operation.create('__check_dedup__');
  expiredOp.signerId = 'alice';
  expiredOp.nodeId = 'alice';
  expiredOp.addAttestation(parseAttestationWire(expiredWire));
  childNow.sign(expiredOp, aliceKey.privateKeyHex());
  await expectRefusal(() => childNow.execute(expiredOp),
    'unauthorized', 'expired attestation window');
  expiredOp.destroy();

  // ---- Attach-side validation (mirror of addLockClaim's loud discipline) -
  const badSignatureOp = await Operation.create('__check_dedup__');
  badSignatureOp.signerId = 'alice';
  badSignatureOp.nodeId = 'alice';
  assert.throws(() => badSignatureOp.addAttestation({
    ...attested, signatureHex: 'ff'.repeat(20),   // 20 bytes, not 64
  }), /addAttestation: signatureHex must be 128 hex chars \(64 bytes\)/,
    'short signatureHex must be refused loudly');
  badSignatureOp.destroy();

  // ---- Wire transport parity (wasm: Operation round trip) ----------------
  // Attestations ride op wire v5+ as TRANSPORT (u32le count + per-entry
  // attestation wire image, src/Serialization/serialization.c) while being
  // EXCLUDED from the canonical signing form (each attestation carries its
  // own parent ECDSA). The credential must survive a serialize ->
  // deserialize -> serialize round trip intact — the re-parsed op is
  // byte-identical. (The re-parsed op is not re-executed here: its
  // signature covers op uuid + ordering stamps, so a transported copy is a
  // distinct op only on a replica that kept the same machine id and has not
  // seen it — a surface a single resident machine cannot honestly
  // materialize; the executor's per-op attestation re-verification is
  // already pinned by the battery above.)
  const transportOp = await Operation.create('__check_dedup__');
  transportOp.signerId = 'alice';
  transportOp.nodeId = 'alice';
  transportOp.addAttestation(attested);
  childB.sign(transportOp, aliceKey.privateKeyHex());
  const opWire = transportOp.serialize();
  transportOp.destroy();

  const reloadedOp = await Operation.deserialize(opWire);
  assert.strictEqual(reloadedOp.type, '__check_dedup__',
    'deserialized op must carry its type');
  const reSerialized = reloadedOp.serialize();
  assert(Buffer.from(opWire).equals(Buffer.from(reSerialized)),
    're-serialized op must be byte-identical (attestation intact)');
  reloadedOp.destroy();

  console.log('attestations wasm OK: endorsed op authorized, tampered/' +
    'wrong-user/uncovered/wrong-child/expired refused, op-wire round trip' +
    ' kept the credential');
})().catch((failure) => {
  console.error('attestations wasm FAILED:', failure);
  process.exit(1);
});