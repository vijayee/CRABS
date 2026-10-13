// attestations.js — Recipe 12's attestation-consumption half from JS
// (crabs-node): a spawned child's `@parent/` endorsement policy resolved
// against an attestation-carrying op. Mirrors the C battery in
// cookbook/snippets/c/12-federation-between-machines.c (the JS-reachable
// subset: endorsed op authorized, tampered signature, wrong attested user,
// uncovered attributes, wrong child, expired window — forged-parent and
// unbound-machine stay C-only because the binding can only mint REAL parent
// attestations and only spawns BOUND children).
//
// Divergence pinned here (api-map §12): crabs-node has NO
// Operation.deserialize (wasm-only), so the op-wire transport round trip
// runs in the wasm battery only — the node demo exercises attach + execute,
// the consumption seam both bindings share.
//
// The executor consumes op attestations during authorization
// (src/StateMachine/state_machine.c _verify_parent_endorsements); the
// binding side is Operation.addAttestation (direct op_ fill, mirror of
// AddLockClaim's staging discipline).

'use strict';

const assert = require('assert');
const { setTimeout: sleep } = require('timers/promises');
const { Node, KeyPair, Operation, Blueprint, TRUST_MODE } = require('..');

const CRABS_SIG_SIZE = 64;

// Parse a parent-issued attestation wire image into the fields
// Operation.addAttestation consumes. Canonical layout (src/Lineage/lineage.c,
// _attestation_write_canonical_body): u32le total length (excluding the
// prefix itself) + u8 format_version + string16 parent/child/user/attributes
// + u64le not_before, expires_at, parent_key_version + 64-byte signature.
function parseAttestationWire(wire) {
  const total = wire.readUInt32LE(0);
  assert.strictEqual(total, wire.length - 4,
    'attestation length prefix must cover body + signature');
  let offset = 4;
  assert.strictEqual(wire[offset], 0x02, 'attestation body format must be v2');
  offset += 1;
  const readString16 = () => {
    const len = wire.readUInt16LE(offset); offset += 2;
    const text = wire.subarray(offset, offset + len).toString('utf8');
    offset += len;
    return text;
  };
  const parentId = readString16();
  const childId = readString16();
  const userId = readString16();
  const attributes = readString16();
  const notBefore = wire.readBigUInt64LE(offset); offset += 8;
  const expiresAt = wire.readBigUInt64LE(offset); offset += 8;
  const parentKeyVersion = wire.readBigUInt64LE(offset); offset += 8;
  const signatureBytes = wire.subarray(offset, offset + CRABS_SIG_SIZE);
  assert.strictEqual(signatureBytes.length, CRABS_SIG_SIZE,
    'attestation wire must end with the 64-byte signature');
  return { parentId, childId, userId, attributes,
           notBefore: Number(notBefore), expiresAt: Number(expiresAt),
           parentKeyVersion: Number(parentKeyVersion),
           signatureHex: signatureBytes.toString('hex') };
}

// Flip the first hex digit of a signature — a deterministically tampered
// ECDSA (r||s legitimately contains zero bytes; never flip on those).
const tamperedSignatureHex = (signatureHex) =>
  (signatureHex.startsWith('a') ? 'b' : 'a') + signatureHex.slice(1);

let passed = 0;
let failed = 0;

function check(condition, message) {
  if (condition) {
    passed++;
  } else {
    failed++;
    console.error('FAIL:', message);
  }
}

function expectRefusal(runnable, expected, what) {
  try {
    runnable();
  } catch (refusal) {
    check(refusal.message.includes(expected),
      `${what}: expected "${expected}", got: ${refusal.message}`);
    return;
  }
  check(false, `${what}: expected a ${expected} refusal, got success`);
}

async function main() {
  // ---- The federating machines ------------------------------------------
  // Parent (the signer of attestations) + a DELEGATED_COPY child whose
  // authorization for __check_dedup__ is a pure `@parent/` endorsement.
  const parent = new Node('federation-root', { ordering: 'hlc' });
  const blueprintB = Blueprint.create('machine-b', TRUST_MODE.DELEGATED_COPY,
                                      'b-admin', 3600000);
  blueprintB.addPolicy('__check_dedup__', '@parent/role:member');
  blueprintB.stampHash();
  const childB = parent.lineageSpawn(blueprintB);   // borrowed child wrapper
  check(parent.lineageResidentChild('machine-b') !== null,
    'spawned child not resident');

  // The signed op: alice's `__check_dedup__` on the child, alice registered
  // in the child's OWN registry (DELEGATED_COPY mints a fresh authority).
  const aliceKey = KeyPair.generate();
  childB.registerUser('alice', aliceKey.publicKeyHex(), '');

  // ---- The end-to-end consume: attach the parent's vouch → executes -------
  const attested = parseAttestationWire(
    parent.lineageAttest('machine-b', 'alice', 'role:member'));
  check(attested.parentId === 'federation-root',
    'attestation must bind the parent id');
  check(attested.childId === 'machine-b',
    'attestation must bind the child id');
  check(attested.parentKeyVersion === 1,
    'fresh parent stamps the spawn generation');

  const endorsedOp = new Operation('__check_dedup__');
  endorsedOp.signerId = 'alice';
  endorsedOp.nodeId = 'alice';
  endorsedOp.addAttestation(attested);
  childB.sign(endorsedOp, aliceKey.privateKeyHex());
  childB.execute(endorsedOp);   // the endorsement resolved: no refusal
  check(true, 'endorsed op executed');

  // ---- Fail-closed battery ------------------------------------------------
  const makeEndorsedOp = (attestation) => {
    const op = new Operation('__check_dedup__');
    op.signerId = 'alice';
    op.nodeId = 'alice';
    op.addAttestation(attestation);
    childB.sign(op, aliceKey.privateKeyHex());
    return op;
  };

  // Tampered signature: one flipped byte in the carried ECDSA breaks the
  // canonical-body verification.
  const tamperedOp = makeEndorsedOp({
    ...attested, signatureHex: tamperedSignatureHex(attested.signatureHex),
  });
  expectRefusal(() => childB.execute(tamperedOp),
    'unauthorized', 'tampered attestation signature');

  // Wrong attested user: the attestation must name the RESOLVED signer.
  const wrongUserOp = makeEndorsedOp(parseAttestationWire(
    parent.lineageAttest('machine-b', 'bob', 'role:member')));
  expectRefusal(() => childB.execute(wrongUserOp),
    'unauthorized', 'wrong-user attestation');

  // Uncovered attributes: coverage is EXACT membership in the list.
  const uncoveredOp = makeEndorsedOp(parseAttestationWire(
    parent.lineageAttest('machine-b', 'alice', 'role:reader')));
  expectRefusal(() => childB.execute(uncoveredOp),
    'unauthorized', 'uncovered attestation attributes');

  // Wrong child id: a vouch for a DIFFERENT child never matches this
  // machine's lineage_self_id, even though parent and signer line up.
  const blueprintC = Blueprint.create('machine-c', TRUST_MODE.DELEGATED_COPY,
                                      'c-admin', 3600000);
  blueprintC.stampHash();
  parent.lineageSpawn(blueprintC);
  const wrongChildOp = makeEndorsedOp(parseAttestationWire(
    parent.lineageAttest('machine-c', 'alice', 'role:member')));
  expectRefusal(() => childB.execute(wrongChildOp),
    'unauthorized', 'wrong-child attestation');

  // ---- The TTL: a real, signature-INTACT expired attestation --------------
  // ttl 0 stamps expires_at = now at MINT; every later wall-clock read sits
  // past the instant-long window, so the pipeline's expiry gate refuses. A
  // JS caller cannot mint a fresh-signed expired vouch any other way: the
  // window is stamped at issue time, and hand-edits break the signature.
  const blueprintNow = Blueprint.create('machine-now',
    TRUST_MODE.DELEGATED_COPY, 'n-admin', 0);
  blueprintNow.stampHash();
  parent.lineageSpawn(blueprintNow);
  const childNow = parent.lineageResidentChild('machine-now');
  childNow.registerUser('alice', aliceKey.publicKeyHex(), '');
  const expiredWire = parent.lineageAttest('machine-now', 'alice',
                                           'role:member');
  await sleep(50);   // walk the wall clock past the single-instant window
  const expiredOp = new Operation('__check_dedup__');
  expiredOp.signerId = 'alice';
  expiredOp.nodeId = 'alice';
  expiredOp.addAttestation(parseAttestationWire(expiredWire));
  childNow.sign(expiredOp, aliceKey.privateKeyHex());
  expectRefusal(() => childNow.execute(expiredOp),
    'unauthorized', 'expired attestation window');

  // ---- Attach-side validation (mirror of AddLockClaim's loud discipline) --
  const badSignatureOp = new Operation('__check_dedup__');
  badSignatureOp.signerId = 'alice';
  badSignatureOp.nodeId = 'alice';
  assert.throws(() => badSignatureOp.addAttestation({
    ...attested, signatureHex: 'ff'.repeat(20),   // 20 bytes, not 64 bytes
  }), /addAttestation: signatureHex must be 128 hex chars \(64 bytes\)/,
    'short signatureHex must be refused loudly');

  // ---- Wire transport divergence, pinned honestly -------------------------
  // crabs-node exposes no Operation.deserialize (wasm-only, api-map §12),
  // but op serialize() is real: an attestation-carrying op serializes under
  // op format v5+ with the credential in its transport section.
  const transportOp = new Operation('__check_dedup__');
  transportOp.signerId = 'alice';
  transportOp.nodeId = 'alice';
  transportOp.addAttestation(attested);
  childB.sign(transportOp, aliceKey.privateKeyHex());
  const opWire = transportOp.serialize();
  check(opWire !== null && opWire.length > 0,
    'attestation-carrying op serializes to non-empty wire');

  blueprintB.destroy();
  blueprintC.destroy();
  blueprintNow.destroy();

  check(passed + failed > 0, 'battery produced assertions');
  console.log(`attestations node OK: ${passed} passed, ${failed} failed` +
    ' — endorsed op authorized, tampered/wrong-user/uncovered/wrong-child/' +
    'expired refused');
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((failure) => {
  console.error('attestations node FAILED:', failure);
  process.exit(1);
});