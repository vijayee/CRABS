'use strict';
// Recipe 12 — federating two machines' machines via attestations (crabs-wasm).
//
// Machine A mints machine B (Recipe 11's flow); federation is A signing, on
// its own node key, TTL-bounded attribute vouches FOR B's members — the
// attestation wire a B-side endorsement policy resolves against. This
// snippet exercises the whole loop from JS: the ISSUANCE side plus the
// CONSUME side — a spawned child's `@parent/` endorsement policy resolving
// an attestation an op carries (Operation.addAttestation) — plus the
// federation lifecycle with two minted machines: the sever path (dissolve +
// signed tombstone) and the de-vouch path (revoke attestation — a one-way
// state whose dissolve door stays open; see the recipe notes). Mirrors the
// wasm lineage smoke (bindings/wasm/lineage_smoke.mjs) and the binding
// battery bindings/wasm/test/attestations.js.

const assert = require('assert');
const { Node, KeyPair, Operation, Blueprint, getModule,
        TRUST_MODE, DATA_TYPE, CRDT_TYPE } =
  require('../../../bindings/wasm');
const { setTimeout: sleep } = require('timers/promises');

const childId = 'machine-b';
const LINEAGE_DISSOLVED_TAG = 0x01;   // lineage_status_e LINEAGE_DISSOLVED
const CRABS_SIG_SIZE = 64;

// Parse a parent-issued attestation wire image into the fields
// Operation.addAttestation consumes. Canonical body layout (src/Lineage/
// lineage.c, _attestation_write_canonical_body): u32le total length
// (excluding the prefix itself) + u8 format_version + string16
// parent/child/user/attributes + u64le not_before, expires_at,
// parent_key_version + the 64-byte signature.
function parseAttestationWire(wire) {
  const view = new DataView(wire.buffer, wire.byteOffset, wire.byteLength);
  assert.strictEqual(view.getUint32(0, true), wire.length - 4,
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
  const childIdent = readString16();
  const userId = readString16();
  const attributes = readString16();
  const notBefore = view.getBigUint64(offset, true); offset += 8;
  const expiresAt = view.getBigUint64(offset, true); offset += 8;
  const parentKeyVersion = view.getBigUint64(offset, true); offset += 8;
  return { parentId, childId: childIdent, userId, attributes,
           notBefore, expiresAt, parentKeyVersion,
           signatureHex: Buffer.from(
             wire.subarray(offset, offset + CRABS_SIG_SIZE)).toString('hex') };
}

// Flip the first hex digit of a signature — a deterministically tampered
// ECDSA (r||s legitimately contains zero bytes; never flip on those).
const tamperedSignatureHex = (signatureHex) =>
  (signatureHex.startsWith('a') ? 'b' : 'a') + signatureHex.slice(1);

async function main() {
  // Machine A: the federating parent. attest() reads the machine's time
  // source to stamp the validity window — authenticate it first.
  const machineA = await Node.create('machine-a');
  machineA.setTime(Date.now());
  machineA.lineageInstall();

  // Machine B: minted by A, its own fresh authority, an attestation TTL.
  const blueprintB = await Blueprint.create(childId, TRUST_MODE.DELEGATED_COPY,
                                            'b-admin', 3600000);
  blueprintB.addItem('score', DATA_TYPE.COUNTER, CRDT_TYPE.G_COUNTER);
  blueprintB.stampHash();
  const spawnedPtr = machineA.lineageSpawn(blueprintB);
  assert(machineA.lineageResidentChild(childId) === spawnedPtr,
    'spawned child not resolvable in the resident registry');

  // ---- The vouch: A signs an attestation for alice IN B's domain -----------
  // Wire shape: u32le total length + canonical body + 64-byte parent ECDSA.
  // The body carries the parent's key-version stamp (A11-4) and the window
  // not_before <= now <= expires_at, from the TTL the blueprint recorded.
  const attestationWire = machineA.attest(childId, 'alice', 'role:member');
  assert(attestationWire.length > 0, 'attestation wire empty');
  const attestationView = new DataView(attestationWire.buffer,
                                       attestationWire.byteOffset);
  assert(attestationView.getUint32(0, true) === attestationWire.length - 4,
    'attestation length prefix must cover body + signature');
  assert(!attestationWire.subarray(attestationWire.length - CRABS_SIG_SIZE)
           .every(sigByte => sigByte === 0),
    'attestation signature is all zero bytes (not a real ECDSA)');

  // Vouches for a machine A does not manifest are refused up front.
  assert.throws(() => machineA.attest('machine-ghost', 'alice', 'role:member'),
    /attest/, 'attest for an unknown child must fail closed');

  // ---- The sever path: dissolve machine-b, then mint its tombstone --------
  const adminKey = await KeyPair.generate();
  machineA.registerUser('federation-admin', adminKey.publicKeyHex(), 'adult');
  machineA.grantRole('federation-admin', 'role', 'admin', 'machine-a');

  const dissolveOp = await Operation.create('__dissolve_machine__');
  dissolveOp.signerId = 'federation-admin';
  dissolveOp.nodeId = 'federation-admin';
  dissolveOp.payload = new TextEncoder().encode(childId);  // NUL-excluded
  machineA.sign(dissolveOp, adminKey.privateKeyHex());
  machineA.execute(dissolveOp);
  dissolveOp.destroy();

  assert(machineA.lineageResidentChild(childId) === null,
    'in-process severance must clear the resident registry slot');
  assert(machineA.childById(childId).status === 'dissolved',
    'manifest status after dissolve');

  // The tombstone: u8 tag LINEAGE_DISSOLVED + string16 child_id + u64le
  // parent_key_version (a fresh parent stamps its spawn generation, 1) +
  // the 64-byte parent ECDSA, no length prefix.
  const tombstone = machineA.lineageTombstone(childId);
  const expectedLength = 3 + childId.length + 8 + CRABS_SIG_SIZE;
  assert(tombstone.length === expectedLength,
    `tombstone length ${tombstone.length} != ${expectedLength}`);
  assert(tombstone[0] === LINEAGE_DISSOLVED_TAG, 'tombstone tag mismatch');
  const tombstoneView = new DataView(tombstone.buffer, tombstone.byteOffset);
  const tombstoneIdLength = tombstoneView.getUint16(1, true);
  assert(tombstoneIdLength === childId.length, 'tombstone id length');
  assert(new TextDecoder().decode(tombstone.subarray(3, 3 + tombstoneIdLength))
           === childId, 'tombstone id mismatch');
  assert(tombstoneView.getBigUint64(3 + tombstoneIdLength, true) === 1n,
    'fresh parent must stamp the spawn generation (key version 1)');
  assert(!tombstone.subarray(3 + tombstoneIdLength + 8)
           .every(sigByte => sigByte === 0),
    'tombstone signature is all zero bytes (not a real ECDSA)');

  // ---- The de-vouch path: machine-c keeps living, attestations stop -------
  // Minting a tombstone for it would be a lie — this machine is NOT dissolved.
  assert.throws(() => machineA.lineageTombstone('machine-c'), /tombstone/,
    'tombstone mint must fail closed for a non-dissolved child');

  // ---- The consume: B's endorsement policy resolves the carried vouch ----
  // The child's policy carries `@parent/<attribute>` tokens; the executor's
  // endorsement pipeline resolves op-carried attestations
  // (_verify_parent_endorsements, src/StateMachine/state_machine.c) when the
  // op executes with Operation.addAttestation having staged the credential.
  const blueprintD = await Blueprint.create('machine-d',
    TRUST_MODE.DELEGATED_COPY, 'd-admin', 3600000);
  blueprintD.addPolicy('__check_dedup__', '@parent/role:member');
  blueprintD.stampHash();
  // JS never owns child pointers — the parent's resident registry in C
  // anchors them — but the exported Node class wraps the borrowed pointer
  // (the node binding materializes this wrapper itself; api-map §10).
  const childD = new Node(await getModule(),
                          machineA.lineageSpawn(blueprintD));
  childD.adminId = 'd-admin';
  const aliceKey = await KeyPair.generate();
  childD.registerUser('alice', aliceKey.publicKeyHex(), '');

  // Mint the vouch, parse the wire, attach, sign, execute — the endorsement
  // resolves: the attestation verifies against the child's chain TIP,
  // names the child's parent, names the RESOLVED signer, and covers the
  // token exactly.
  const endorsed = parseAttestationWire(
    machineA.attest('machine-d', 'alice', 'role:member'));
  assert.strictEqual(endorsed.parentId, 'machine-a',
    'attestation must bind the parent id');
  assert.strictEqual(endorsed.childId, 'machine-d',
    'attestation must bind the child id');
  assert.strictEqual(endorsed.parentKeyVersion, 1n,
    'a fresh parent stamps the spawn generation');
  const endorsedOp = await Operation.create('__check_dedup__');
  endorsedOp.signerId = 'alice';
  endorsedOp.nodeId = 'alice';
  endorsedOp.addAttestation(endorsed);
  childD.sign(endorsedOp, aliceKey.privateKeyHex());
  childD.execute(endorsedOp);
  endorsedOp.destroy();

  const makeEndorsedOp = async (attestation) => {
    const op = await Operation.create('__check_dedup__');
    op.signerId = 'alice';
    op.nodeId = 'alice';
    op.addAttestation(attestation);
    childD.sign(op, aliceKey.privateKeyHex());
    return op;
  };

  // Tampered carried signature: one flipped byte breaks the canonical-body
  // ECDSA — refused `unauthorized` before any effect.
  const tamperedOp = await makeEndorsedOp({
    ...endorsed, signatureHex: tamperedSignatureHex(endorsed.signatureHex),
  });
  assert.throws(() => childD.execute(tamperedOp), /unauthorized/,
    'tampered attestation must fail closed');
  tamperedOp.destroy();

  // Wrong attested user: the vouch must name the op's RESOLVED signer.
  const wrongUserOp = await makeEndorsedOp(parseAttestationWire(
    machineA.attest('machine-d', 'bob', 'role:member')));
  assert.throws(() => childD.execute(wrongUserOp), /unauthorized/,
    'wrong-user attestation must fail closed');
  wrongUserOp.destroy();

  // The TTL: a signature-INTACT expired vouch — ttl 0 stamps expires_at =
  // now at mint, so every later wall-clock read is past the window. (A JS
  // caller cannot mint a fresh-signed expired vouch any other way: the
  // window is stamped at issue time, and hand-edits break the signature.)
  const blueprintE = await Blueprint.create('machine-e',
    TRUST_MODE.DELEGATED_COPY, 'e-admin', 0);
  blueprintE.stampHash();
  const childE = new Node(await getModule(),
                          machineA.lineageSpawn(blueprintE));
  childE.adminId = 'e-admin';
  childE.registerUser('alice', aliceKey.publicKeyHex(), '');
  const expiredWire = machineA.attest('machine-e', 'alice', 'role:member');
  await sleep(50);   // walk the wall clock past the single-instant window
  const expiredOp = await Operation.create('__check_dedup__');
  expiredOp.signerId = 'alice';
  expiredOp.nodeId = 'alice';
  expiredOp.addAttestation(parseAttestationWire(expiredWire));
  childE.sign(expiredOp, aliceKey.privateKeyHex());
  assert.throws(() => childE.execute(expiredOp), /unauthorized/,
    'expired attestation must fail closed');
  expiredOp.destroy();

  const blueprintC = await Blueprint.create('machine-c', TRUST_MODE.DELEGATED_COPY,
                                            'c-admin', 3600000);
  blueprintC.stampHash();
  machineA.lineageSpawn(blueprintC);
  machineA.attest('machine-c', 'carol', 'role:member');   // was vouching

  const revokeOp = await Operation.create('__revoke_attestation__');
  revokeOp.signerId = 'federation-admin';
  revokeOp.nodeId = 'federation-admin';
  revokeOp.payload = new TextEncoder().encode('machine-c');
  machineA.sign(revokeOp, adminKey.privateKeyHex());
  machineA.execute(revokeOp);
  revokeOp.destroy();

  const revokedEntry = machineA.childById('machine-c');
  assert(revokedEntry !== null && revokedEntry.status === 'attestation_revoked',
    `manifest status after revoke: ${JSON.stringify(revokedEntry)}`);
  assert(machineA.lineageResidentChild('machine-c') !== null,
    'a revoked child is NOT severed: the machine keeps living');
  assert.throws(() => machineA.attest('machine-c', 'dave', 'role:member'),
    /attest/, 'attest must refuse a revoked child');
  // The dissolve door stays open after revoke (src/Lineage/lineage.h:516-520
  // — "dissolution stays available"): the revoke only stopped FUTURE vouches,
  // so the late sever works — the manifest flips to dissolved and the
  // tombstone the honesty gate guards becomes mintable.
  const lateDissolve = await Operation.create('__dissolve_machine__');
  lateDissolve.signerId = 'federation-admin';
  lateDissolve.nodeId = 'federation-admin';
  lateDissolve.payload = new TextEncoder().encode('machine-c');
  machineA.sign(lateDissolve, adminKey.privateKeyHex());
  machineA.execute(lateDissolve);
  lateDissolve.destroy();
  const lateEntry = machineA.childById('machine-c');
  assert(lateEntry !== null && lateEntry.status === 'dissolved',
    `manifest status after dissolve-after-revoke: ${JSON.stringify(lateEntry)}`);
  assert(machineA.lineageResidentChild('machine-c') === null,
    'dissolve-after-revoke severs the resident child');
  machineA.lineageTombstone('machine-c');  // legal only once DISSOLVED

  // Idempotency gate preserved: dissolving the already-dissolved entry
  // refuses (a fresh, re-signed op — an executed op cannot be replayed).
  const reDissolve = await Operation.create('__dissolve_machine__');
  reDissolve.signerId = 'federation-admin';
  reDissolve.nodeId = 'federation-admin';
  reDissolve.payload = new TextEncoder().encode('machine-c');
  machineA.sign(reDissolve, adminKey.privateKeyHex());
  assert.throws(() => machineA.execute(reDissolve), /already_performed/,
    're-dissolving an already-DISSOLVED entry must refuse');
  reDissolve.destroy();

  blueprintB.destroy();
  blueprintC.destroy();
  blueprintD.destroy();
  blueprintE.destroy();
  adminKey.destroy();
  console.log('federation-between-machines wasm OK: attested and consumed' +
    ' (endorsed op authorized; tampered/wrong-user/expired refused),' +
    ' dissolved, tombstoned, revoked then dissolved (the late sever, with' +
    ' its tombstone)');
}

main().catch((failure) => {
  console.error('federation-between-machines wasm FAILED:', failure);
  process.exit(1);
});