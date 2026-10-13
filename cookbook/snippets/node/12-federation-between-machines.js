'use strict';
// Recipe 12 — federating two machines' machines via attestations (crabs-node).
//
// Same federation lifecycle as the wasm section, on the native binding —
// plus what the borrowed child wrapper makes demonstrable: the
// receive-dissolution delivery contract (the tombstone bytes are the exact
// payload the child consumes, and re-delivery is refused idempotently), the
// attest/verify split honesty gate, and the CONSUME side — a spawned
// child's `@parent/` endorsement policy resolving an attestation an op
// carries (Operation.addAttestation). Mirrors the node lineage smoke
// (bindings/node/lineage_smoke.mjs) and the binding battery
// bindings/node/test/attestations.js.

const assert = require('assert');
const { Node, KeyPair, Operation, Blueprint, TRUST_MODE, DATA_TYPE, CRDT_TYPE } =
  require('../../../bindings/node');

const childId = 'machine-b';
const LINEAGE_DISSOLVED_TAG = 0x01;   // lineage_status_e LINEAGE_DISSOLVED
const CRABS_SIG_SIZE = 64;

// Sync 50 ms pause (the expired-window case just needs a LATER wall-clock
// read than the mint).
const pauseMs = (ms) =>
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

// Parse a parent-issued attestation wire image into the fields
// Operation.addAttestation consumes. Canonical body layout (src/Lineage/
// lineage.c, _attestation_write_canonical_body): u32le total length
// (excluding the prefix itself) + u8 format_version + string16
// parent/child/user/attributes + u64le not_before, expires_at,
// parent_key_version + the 64-byte signature.
function parseAttestationWire(wire) {
  assert.strictEqual(wire.readUInt32LE(0), wire.length - 4,
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
  const childIdent = readString16();
  const userId = readString16();
  const attributes = readString16();
  const notBefore = wire.readBigUInt64LE(offset); offset += 8;
  const expiresAt = wire.readBigUInt64LE(offset); offset += 8;
  const parentKeyVersion = wire.readBigUInt64LE(offset); offset += 8;
  return { parentId, childId: childIdent, userId, attributes,
           notBefore: Number(notBefore), expiresAt: Number(expiresAt),
           parentKeyVersion: Number(parentKeyVersion),
           signatureHex: wire.subarray(offset, offset + CRABS_SIG_SIZE)
                           .toString('hex') };
}

// Flip the first hex digit of a signature — a deterministically tampered
// ECDSA (r||s legitimately contains zero bytes; never flip on those).
const tamperedSignatureHex = (signatureHex) =>
  (signatureHex.startsWith('a') ? 'b' : 'a') + signatureHex.slice(1);

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

// ---- The consume: B's endorsement policy resolves the carried vouch ------
// The child's policy carries `@parent/<attribute>` tokens; the executor's
// endorsement pipeline resolves op-carried attestations
// (_verify_parent_endorsements, src/StateMachine/state_machine.c) when the
// op executes with Operation.addAttestation having staged the credential.
const blueprintD = Blueprint.create('machine-d', TRUST_MODE.DELEGATED_COPY,
                                    'd-admin', 3600000);
blueprintD.addPolicy('__check_dedup__', '@parent/role:member');
blueprintD.stampHash();
const machineD = machineA.lineageSpawn(blueprintD);   // borrowed child wrapper
const aliceKey = KeyPair.generate();
machineD.registerUser('alice', aliceKey.publicKeyHex(), '');

// Mint the vouch, parse the wire, attach, sign, execute — the endorsement
// resolves: the attestation verifies against the child's chain TIP, names
// the child's parent, names the RESOLVED signer, and covers the token
// exactly.
const endorsed = parseAttestationWire(
  machineA.lineageAttest('machine-d', 'alice', 'role:member'));
assert.strictEqual(endorsed.parentId, 'machine-a',
  'attestation must bind the parent id');
assert.strictEqual(endorsed.childId, 'machine-d',
  'attestation must bind the child id');
assert.strictEqual(endorsed.parentKeyVersion, 1,
  'a fresh parent stamps the spawn generation');
const endorsedOp = new Operation('__check_dedup__');
endorsedOp.signerId = 'alice';
endorsedOp.nodeId = 'alice';
endorsedOp.addAttestation(endorsed);
machineD.sign(endorsedOp, aliceKey.privateKeyHex());
machineD.execute(endorsedOp);

const makeEndorsedOp = (attestation) => {
  const op = new Operation('__check_dedup__');
  op.signerId = 'alice';
  op.nodeId = 'alice';
  op.addAttestation(attestation);
  machineD.sign(op, aliceKey.privateKeyHex());
  return op;
};

// Tampered carried signature: one flipped byte breaks the canonical-body
// ECDSA — refused unauthorized before any effect.
const tamperedOp = makeEndorsedOp({
  ...endorsed, signatureHex: tamperedSignatureHex(endorsed.signatureHex),
});
assert.throws(() => machineD.execute(tamperedOp), /unauthorized/,
  'tampered attestation must fail closed');

// Wrong attested user: the vouch must name the op's RESOLVED signer.
const wrongUserOp = makeEndorsedOp(parseAttestationWire(
  machineA.lineageAttest('machine-d', 'bob', 'role:member')));
assert.throws(() => machineD.execute(wrongUserOp), /unauthorized/,
  'wrong-user attestation must fail closed');

// The TTL: a signature-INTACT expired vouch — ttl 0 stamps expires_at = now
// at mint, so every later wall-clock read is past the window. (A JS caller
// cannot mint a fresh-signed expired vouch any other way: the window is
// stamped at issue time, and hand-edits break the signature.)
const blueprintE = Blueprint.create('machine-e', TRUST_MODE.DELEGATED_COPY,
                                    'e-admin', 0);
blueprintE.stampHash();
const machineE = machineA.lineageSpawn(blueprintE);
machineE.registerUser('alice', aliceKey.publicKeyHex(), '');
const expiredWire = machineA.lineageAttest('machine-e', 'alice',
                                           'role:member');
pauseMs(50);   // walk the wall clock past the single-instant window
const expiredOp = new Operation('__check_dedup__');
expiredOp.signerId = 'alice';
expiredOp.nodeId = 'alice';
expiredOp.addAttestation(parseAttestationWire(expiredWire));
machineE.sign(expiredOp, aliceKey.privateKeyHex());
assert.throws(() => machineE.execute(expiredOp), /unauthorized/,
  'expired attestation must fail closed');

blueprintB.destroy();
blueprintC.destroy();
blueprintD.destroy();
blueprintE.destroy();
console.log('federation-between-machines OK: attested AND consumed'
  + ' (endorsed op authorized; tampered/wrong-user/expired refused),'
  + ' dissolved, tombstone delivered (idempotent), revoked with the'
  + ' machine still living');
// Node exposes no destroy() — native cleanup is process-exit driven.