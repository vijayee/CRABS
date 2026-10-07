//
// lineage_smoke.mjs — node smoke test for the v1.7 N-API lineage surface.
//
// Requires the addon to be built first (from bindings/node):
//   npm run build
//
// Run:
//   node bindings/node/lineage_smoke.mjs
//
// Mirrors bindings/wasm/lineage_smoke.mjs: blueprint lifecycle/wire, spawn,
// children manifest, attestation issuance, dissolution through the OP
// PIPELINE (a registered role:admin user signs a __dissolve_machine__ op),
// the tombstone honesty gates, and the receive-dissolution contract on the
// borrowed child wrapper. It loads through require('./index.js') so it
// exercises the same addon paths the package ships.
//
// Deviation from the wasm smoke (noted there too): a TRUE first tombstone
// delivery needs a DISTANT (reloaded) child, which no binding surface can
// materialize (no state deserialization into a machine). What IS honestly
// exercised here is the receive-dissolution contract on the still-resident
// child: the in-process dissolve durably flags the child, so delivering the
// tombstone to it must be refused with already_performed — the re-delivery
// idempotency the C contract specifies.
//

import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
// Under `node --input-type=module -e "..."` import.meta.url is the CWD, so
// fall back to <cwd>/bindings/node when the script is piped in as text.
const bindingsDir = path.basename(scriptDir) === 'node' &&
                    path.basename(path.dirname(scriptDir)) === 'bindings'
  ? scriptDir
  : path.join(process.cwd(), 'bindings', 'node');

const { Node, KeyPair, Operation, Blueprint, TRUST_MODE, DATA_TYPE, CRDT_TYPE } =
  createRequire(path.join(bindingsDir, 'index.js'))('./index.js');

const childId = 'child-omega';
const LINEAGE_DISSOLVED_TAG = 0x01;   // lineage_status_e LINEAGE_DISSOLVED
const CRABS_SIG_SIZE = 64;

async function main() {
  // Parent node: full admin of its own machine.
  const parent = new Node('parent-admin');
  parent.setTime(Date.now());   // attest reads the machine's authenticated time source

  // The lineage ops become submitable through execute() after install.
  parent.lineageInstall();

  // Build a DELEGATED_COPY blueprint: a child with its own fresh authority.
  const blueprint = Blueprint.create(childId, TRUST_MODE.DELEGATED_COPY,
                                     'child-admin', 3600000);
  blueprint.addItem('score', DATA_TYPE.COUNTER, CRDT_TYPE.G_COUNTER);
  blueprint.addPolicy('view', 'role:member');
  blueprint.stampHash();

  // Blueprint wire round trip: serialize -> deserialize preserves identity.
  const wire = blueprint.serialize();
  const reloaded = Blueprint.deserialize(wire);   // throws on hash/structure mismatch
  if (wire.length === 0) throw new Error('blueprint serialize produced no bytes');

  // Honesty gate on tombstones: minting one for a LIVE child is a lie.
  const child = parent.lineageSpawn(blueprint);
  let liveTombstoneRefused = false;
  try {
    parent.lineageTombstone(childId);
  } catch (gateRefused) {
    liveTombstoneRefused = gateRefused.message.includes('unauthorized');
  }
  if (!liveTombstoneRefused) {
    throw new Error('tombstone mint must fail closed for a live child');
  }

  // Spawn: the JS child wrapper BORROWS the machine — the parent owns it
  // (destroyed when the parent is collected), mirroring the wasm binding's
  // resident-registry ownership statement. Resident lookups hand out fresh
  // wrappers over the same machine.
  const resident = parent.lineageResidentChild(childId);
  if (resident === null) {
    throw new Error('spawned child not resolvable in resident registry');
  }

  const childEntry = parent.lineageChildren()[0];
  if (childEntry === undefined) {
    throw new Error('child manifest entry missing after spawn');
  }
  if (childEntry.childId !== childId ||
      childEntry.mode !== 'delegated_copy' || childEntry.status !== 'active') {
    throw new Error(`unexpected manifest view: ${JSON.stringify(childEntry)}`);
  }
  if (childEntry.attestationTtlMs !== 3600000) {
    throw new Error(`unexpected ttl on manifest entry: ${childEntry.attestationTtlMs}`);
  }
  if (parent.lineageChildren().length !== 1) {
    throw new Error('expected exactly one child manifest entry');
  }

  // Attest: parent vouches for alice in the child's domain; the wire image
  // (u32le length + canonical body + signature) must be non-empty with a
  // nonzero trailing signature.
  const attestationWire = parent.lineageAttest(childId, 'alice', 'role:member');
  if (attestationWire.length === 0) throw new Error('attestation wire empty');
  if (attestationWire.subarray(attestationWire.length - CRABS_SIG_SIZE)
        .every(sigByte => sigByte === 0)) {
    throw new Error('attestation signature carries only zero bytes');
  }

  // ------------------------------------------------------------
  // Dissolve through the OP PIPELINE: role:admin must resolve against a
  // registered user (registerUser rejects privileged attrs, so the admin
  // grantRole path is the honest route — mirrors test/test.js).
  // ------------------------------------------------------------
  const dissolverKey = KeyPair.generate();
  parent.registerUser('dissolver', dissolverKey.publicKeyHex(), 'adult');
  parent.grantRole('dissolver', 'role', 'admin', 'parent-admin');

  // The child is RESIDENT (spawned in this process), so __dissolve_machine__
  // takes the in-process severance branch: it durably sets the child's
  // lineage_parent_dissolved flag (every @parent/ endorsement on the child
  // fails closed from that moment) and drops the registry slot. The
  // observable JS contract for that severance is the registry
  // (lineageResidentChild) plus the manifest status. The child wrapper itself
  // stays alive — the machine is parent-owned, not registry-owned.
  const dissolveOp = new Operation('__dissolve_machine__');
  dissolveOp.signerId = 'dissolver';
  dissolveOp.nodeId = 'dissolver';
  dissolveOp.payload = Buffer.from(childId);  // NUL-excluded, as the wasm smoke does
  parent.sign(dissolveOp, dissolverKey.privateKeyHex());
  parent.execute(dissolveOp);

  if (parent.lineageResidentChild(childId) !== null) {
    throw new Error('in-process severance must clear the resident registry slot');
  }
  const dissolvedEntry = parent.lineageChildren()[0];
  if (dissolvedEntry === undefined || dissolvedEntry.status !== 'dissolved') {
    throw new Error(`manifest status after dissolve: ${JSON.stringify(dissolvedEntry)}`);
  }

  // Attest now refuses: the entry is no longer ACTIVE (honesty gate).
  let postDissolveAttestRefused = false;
  try {
    parent.lineageAttest(childId, 'alice', 'role:member');
  } catch (attestRefused) {
    postDissolveAttestRefused = attestRefused.message.includes('unauthorized');
  }
  if (!postDissolveAttestRefused) {
    throw new Error('attest must fail closed for a dissolved child');
  }

  // Minting a tombstone for a non-dissolved child is a lie — refused.
  let tombstoneGateRefused = false;
  try {
    parent.lineageTombstone('not-spawned');
  } catch (gateRefused) {
    tombstoneGateRefused = gateRefused.message.includes('resource_not_found');
  }
  if (!tombstoneGateRefused) {
    throw new Error('tombstone mint must fail closed for a non-dissolved child');
  }

  // ------------------------------------------------------------
  // Tombstone mint: `u8 tag LINEAGE_DISSOLVED + string16 child_id` +
  // 64-byte parent ECDSA — NO length prefix (the exact bytes a
  // __receive_dissolution__ op transports). Structurally verified here.
  // ------------------------------------------------------------
  const tombstone = parent.lineageTombstone(childId);
  const expectedLength = 3 + childId.length + CRABS_SIG_SIZE;
  if (tombstone.length !== expectedLength) {
    throw new Error(`tombstone length ${tombstone.length} != ${expectedLength}`);
  }
  if (tombstone[0] !== LINEAGE_DISSOLVED_TAG) {
    throw new Error(`tombstone tag ${tombstone[0]} != LINEAGE_DISSOLVED(${LINEAGE_DISSOLVED_TAG})`);
  }
  const idLengthPrefix = tombstone.readUInt16LE(1);
  if (idLengthPrefix !== childId.length) {
    throw new Error(`tombstone id length ${idLengthPrefix} != ${childId.length}`);
  }
  if (tombstone.subarray(3, 3 + idLengthPrefix).toString('utf8') !== childId) {
    throw new Error(`tombstone id "${tombstone.subarray(3, 3 + idLengthPrefix).toString('utf8')}" != "${childId}"`);
  }
  // Deterministic structural check only: ECDSA r||s values legitimately
  // contain zero bytes (the wasm smoke's any-zero-byte assertion is
  // ~22%-of-runs flaky), so the honest check is "not a zeroed signature".
  if (tombstone.subarray(3 + idLengthPrefix).every(sigByte => sigByte === 0)) {
    throw new Error('tombstone signature is all zero bytes (not a real ECDSA)');
  }

  // ------------------------------------------------------------
  // Receive-dissolution on the borrowed child (see the header deviation
  // note): the in-process dissolve durably flagged the machine, so a
  // tombstone delivery — signed by its bootstrap admin (whose key is the
  // PARENT's node key at spawn) — must be refused with already_performed.
  // This is the re-delivery idempotency the C contract specifies, and the
  // proof that the severance reached the child durably.
  // ------------------------------------------------------------
  child.lineageInstall();
  const receiveOp = new Operation('__receive_dissolution__');
  receiveOp.signerId = 'child-admin';
  receiveOp.nodeId = 'child-admin';
  receiveOp.payload = tombstone;
  // The child's bootstrap admin key IS the parent's node key (spawn vouches
  // for its genesis admin with the minting machine's identity).
  child.sign(receiveOp, parent.getNodeKey().privateKeyHex);
  let redeliveryRefused = false;
  try {
    child.execute(receiveOp);
  } catch (redelivery) {
    redeliveryRefused = redelivery.message.includes('already_performed');
  }
  if (!redeliveryRefused) {
    throw new Error('tombstone delivery must already_performed-refuse on a flagged child');
  }

  // The borrowed wrapper still serves its machine after all lineage traffic:
  // a second receive (fresh op uuid) hits the same durable refusal.
  const receiveOpAgain = new Operation('__receive_dissolution__');
  receiveOpAgain.signerId = 'child-admin';
  receiveOpAgain.nodeId = 'child-admin';
  receiveOpAgain.payload = tombstone;
  child.sign(receiveOpAgain, parent.getNodeKey().privateKeyHex);
  let secondRefused = false;
  try {
    child.execute(receiveOpAgain);
  } catch (redeliveryAgain) {
    secondRefused = redeliveryAgain.message.includes('already_performed');
  }
  if (!secondRefused) {
    throw new Error('re-delivery must refuse on a flagged child');
  }

  console.log('SMOKE OK: entry=' + JSON.stringify(childEntry) +
              ', blueprint_bytes=' + wire.length +
              ', attestation_bytes=' + attestationWire.length +
              ', dissolved_status=' + dissolvedEntry.status +
              ', tombstone_bytes=' + tombstone.length);

  blueprint.destroy();
  reloaded.destroy();
}

main().catch(error => { console.error(error); process.exit(1); });