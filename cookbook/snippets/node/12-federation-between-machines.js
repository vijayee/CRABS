'use strict';
// Recipe 12 — federating two machines' machines via attestations (crabs-node).
//
// Same federation lifecycle as the wasm section, on the native binding —
// plus what the borrowed child wrapper makes demonstrable: the
// receive-dissolution delivery contract (the tombstone bytes are the exact
// payload the child consumes, and re-delivery is refused idempotently) and
// the attest/verify split honesty gate. Mirrors the node lineage smoke
// (bindings/node/lineage_smoke.mjs).

const assert = require('assert');
const { Node, KeyPair, Operation, Blueprint, TRUST_MODE, DATA_TYPE, CRDT_TYPE } =
  require('../../../bindings/node');

const childId = 'machine-b';
const LINEAGE_DISSOLVED_TAG = 0x01;   // lineage_status_e LINEAGE_DISSOLVED
const CRABS_SIG_SIZE = 64;

const machineA = new Node('machine-a', { ordering: 'hlc' });
machineA.setTime(Date.now());   // attest reads the machine's time source
machineA.lineageInstall();

// Machine B: minted by A, its own fresh authority, an attestation TTL.
const blueprintB = Blueprint.create(childId, TRUST_MODE.DELEGATED_COPY,
                                    'b-admin', 3600000);
blueprintB.addItem('score', DATA_TYPE.COUNTER, CRDT_TYPE.G_COUNTER);
blueprintB.stampHash();
const machineB = machineA.lineageSpawn(blueprintB);

// ---- The vouch: A signs an attestation for alice IN B's domain -----------
// Wire shape: u32le total length + canonical body + 64-byte parent ECDSA.
const attestationWire = machineA.lineageAttest(childId, 'alice', 'role:member');
assert(attestationWire.length > 0, 'attestation wire empty');
assert(attestationWire.readUInt32LE(0) === attestationWire.length - 4,
  'attestation length prefix must cover body + signature');
assert(!attestationWire.subarray(attestationWire.length - CRABS_SIG_SIZE)
         .every(sigByte => sigByte === 0),
  'attestation signature is all zero bytes (not a real ECDSA)');

// Vouches for a machine A does not manifest are refused up front.
assert.throws(() => machineA.lineageAttest('machine-ghost', 'alice',
                                           'role:member'),
  /unauthorized|resource_not_found/,
  'attest for an unknown child must fail closed');

// ---- The sever path: dissolve machine-b, then mint its tombstone --------
const adminKey = KeyPair.generate();
machineA.registerUser('federation-admin', adminKey.publicKeyHex(), 'adult');
machineA.grantRole('federation-admin', 'role', 'admin', 'machine-a');

const dissolveOp = new Operation('__dissolve_machine__');
dissolveOp.signerId = 'federation-admin';
dissolveOp.nodeId = 'federation-admin';
dissolveOp.payload = Buffer.from(childId);  // NUL-excluded
machineA.sign(dissolveOp, adminKey.privateKeyHex());
machineA.execute(dissolveOp);

assert(machineA.lineageResidentChild(childId) === null,
  'in-process severance must clear the resident registry slot');
assert(machineA.lineageChildren()[0].status === 'dissolved',
  'manifest status after dissolve');

// The tombstone: u8 tag LINEAGE_DISSOLVED + string16 child_id + u64le
// parent_key_version (a fresh parent stamps its spawn generation, 1) + the
// 64-byte parent ECDSA, no length prefix.
const tombstone = machineA.lineageTombstone(childId);
const expectedLength = 3 + childId.length + 8 + CRABS_SIG_SIZE;
assert(tombstone.length === expectedLength,
  `tombstone length ${tombstone.length} != ${expectedLength}`);
assert(tombstone[0] === LINEAGE_DISSOLVED_TAG, 'tombstone tag mismatch');
const tombstoneIdLength = tombstone.readUInt16LE(1);
assert(tombstoneIdLength === childId.length, 'tombstone id length');
assert(tombstone.subarray(3, 3 + tombstoneIdLength).toString('utf8')
         === childId, 'tombstone id mismatch');
assert(tombstone.readBigUInt64LE(3 + tombstoneIdLength) === 1n,
  'fresh parent must stamp the spawn generation (key version 1)');

// ---- The delivery: the child consumes the tombstone ----------------------
// The B-side contract of dissolution: a machine that receives the signed
// tombstone durably records that its parent severed the lineage. The
// machine-b wrapper is still resident here (severed but alive), so the
// delivery is refused with already_performed — the durable flag is the
// proof the severance reached the child. On a DISTANT child (restored from
// its genesis bytes in another process), the same op performs the flip.
machineB.lineageInstall();
const receiveOp = new Operation('__receive_dissolution__');
receiveOp.signerId = 'b-admin';
receiveOp.nodeId = 'b-admin';
receiveOp.payload = Buffer.from(tombstone);
// The child's bootstrap admin key IS the parent's node key at spawn (the
// parent vouches for its genesis admin with the minting machine's identity).
machineB.sign(receiveOp, machineA.getNodeKey().privateKeyHex);
try {
  machineB.execute(receiveOp);
  throw new Error('tombstone redelivery must be refused on a severed child');
} catch (redelivery) {
  assert(redelivery.message.includes('already_performed'),
    `expected already_performed, got: ${redelivery.message}`);
}

// ---- The de-vouch path: machine-c keeps living, attestations stop -------
const blueprintC = Blueprint.create('machine-c', TRUST_MODE.DELEGATED_COPY,
                                    'c-admin', 3600000);
blueprintC.stampHash();
const machineC = machineA.lineageSpawn(blueprintC);
machineA.lineageAttest('machine-c', 'carol', 'role:member');   // was vouching

const revokeOp = new Operation('__revoke_attestation__');
revokeOp.signerId = 'federation-admin';
revokeOp.nodeId = 'federation-admin';
revokeOp.payload = Buffer.from('machine-c');
machineA.sign(revokeOp, adminKey.privateKeyHex());
machineA.execute(revokeOp);

const revokedEntry = machineA.lineageChildren()[1];
assert(revokedEntry !== undefined &&
       revokedEntry.childId === 'machine-c' &&
       revokedEntry.status === 'attestation_revoked',
  `manifest status after revoke: ${JSON.stringify(revokedEntry)}`);
assert(machineA.lineageResidentChild('machine-c') !== null,
  'a revoked child is NOT severed: the machine keeps living');
assert.throws(() => machineA.lineageAttest('machine-c', 'dave', 'role:member'),
  /unauthorized/, 'attest must refuse a revoked child');

console.log('federation-between-machines OK: attested, dissolved, tombstone' +
  ' delivered (idempotent), revoked with the machine still living');
// Node exposes no destroy() — native cleanup is process-exit driven.