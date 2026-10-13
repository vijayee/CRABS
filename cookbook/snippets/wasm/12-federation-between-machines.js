'use strict';
// Recipe 12 — federating two machines' machines via attestations (crabs-wasm).
//
// Machine A mints machine B (Recipe 11's flow); federation is A signing, on
// its own node key, TTL-bounded attribute vouches FOR B's members — the
// attestation wire a B-side endorsement policy resolves against. This
// snippet exercises the ISSUANCE side plus the federation lifecycle with two
// minted machines: the sever path (dissolve + signed tombstone) and the
// de-vouch path (revoke attestation — a one-way state whose dissolve door
// stays open; see the recipe notes). Mirrors the wasm lineage smoke
// (bindings/wasm/lineage_smoke.mjs).

const assert = require('assert');
const { Node, KeyPair, Operation, Blueprint, TRUST_MODE, DATA_TYPE, CRDT_TYPE } =
  require('../../../bindings/wasm');

const childId = 'machine-b';
const LINEAGE_DISSOLVED_TAG = 0x01;   // lineage_status_e LINEAGE_DISSOLVED
const CRABS_SIG_SIZE = 64;

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
  adminKey.destroy();
  console.log('federation-between-machines wasm OK: attested, dissolved,' +
    ' tombstoned, revoked then dissolved (the late sever, with its' +
    ' tombstone)');
}

main().catch((failure) => {
  console.error('federation-between-machines wasm FAILED:', failure);
  process.exit(1);
});