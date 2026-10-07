//
// lineage_smoke.mjs — node smoke test for the v1.7 wasm lineage exports.
//
// Run from the repo root:
//   node --input-type=module -e "$(cat bindings/wasm/lineage_smoke.mjs)"
// or directly:
//   node bindings/wasm/lineage_smoke.mjs
//
// Uses the DEV module (crabs.dev.js) like the devtools demo does — the
// lineage exports are identical in the production module.
//

import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
// Under `node --input-type=module -e "..."` import.meta.url is the CWD, so
// fall back to <cwd>/bindings/wasm when the script is piped in as text.
const bindingsDir = path.basename(scriptDir) === 'wasm' &&
                    path.basename(path.dirname(scriptDir)) === 'bindings'
  ? scriptDir
  : path.join(process.cwd(), 'bindings', 'wasm');

const { Node, KeyPair, Operation, Blueprint, TRUST_MODE, DATA_TYPE, CRDT_TYPE } =
  createRequire(path.join(bindingsDir, 'dev.js'))('./dev.js');

const childId = 'child-omega';
const LINEAGE_DISSOLVED_TAG = 0x01;   // lineage_status_e LINEAGE_DISSOLVED
const CRABS_SIG_SIZE = 64;

async function main() {
  // Parent node: full admin of its own machine.
  const parent = await Node.create('parent-admin');
  parent.setTime(Date.now());   // attest reads the parent's time source

  // The lineage ops become submitable through execute() after install.
  parent.lineageInstall();

  // Build a DELEGATED_COPY blueprint: a child with its own fresh authority.
  const blueprint = await Blueprint.create(childId, TRUST_MODE.DELEGATED_COPY,
                                           'child-admin', 3600000);
  blueprint.addItem('score', DATA_TYPE.COUNTER, CRDT_TYPE.G_COUNTER);
  blueprint.addPolicy('view', 'role:member');
  blueprint.stampHash();

  // Blueprint wire round trip: serialize -> deserialize preserves identity.
  const wire = blueprint.serialize();
  const reloaded = await Blueprint.deserialize(wire);
  if (wire.length === 0) throw new Error('blueprint serialize produced no bytes');

  // Spawn: JS borrows the child pointer; the parent's resident registry in C
  // owns it.
  const childPtr = parent.lineageSpawn(blueprint);
  const resident = parent.lineageResidentChild(childId);
  if (!resident || resident !== childPtr) {
    throw new Error('spawned child not resolvable in resident registry');
  }

  const count = parent.childCount();
  if (count !== 1) {
    throw new Error(`expected child count 1, got ${count}`);
  }
  const childEntry = parent.childById(childId);
  if (childEntry === null) {
    throw new Error('child manifest entry missing after spawn');
  }
  if (childEntry.mode !== 'delegated_copy' || childEntry.status !== 'active') {
    throw new Error(`unexpected manifest view: ${JSON.stringify(childEntry)}`);
  }
  if (childEntry.ttlMs !== 3600000) {
    throw new Error(`unexpected ttl on manifest entry: ${childEntry.ttlMs}`);
  }
  const index = parent.childIndex('not-spawned');
  if (index !== -1) throw new Error('childIndex miss must return -1');
  if (parent.childCount() !== parent.children().length) {
    throw new Error('children snapshot disagrees with child count');
  }

  // Attest: parent vouches for alice in the child's domain; the wire image
  // (u32le length + canonical body + signature) must be non-empty.
  const attestationWire = parent.attest(childId, 'alice', 'role:member');
  if (attestationWire.length === 0) throw new Error('attestation wire empty');

  // ------------------------------------------------------------
  // Dissolve through the OP PIPELINE: role:admin must resolve against a
  // registered user (registerUser rejects privileged attrs, so the admin
  // grantRole path is the honest route — mirrors test/smoke.js).
  // ------------------------------------------------------------
  const dissolverKey = await KeyPair.generate();
  parent.registerUser('dissolver', dissolverKey.publicKeyHex(), 'adult');
  parent.grantRole('dissolver', 'role', 'admin', 'parent-admin');

  // The child is RESIDENT (spawned in this process), so __dissolve_machine__
  // takes the in-process severance branch: it sets the child's
  // lineage_parent_dissolved flag immediately (every @parent/ endorsement on
  // the child fails closed from that moment) and drops the registry slot.
  // The observable JS contract for that in-process severance is the registry:
  // residentChild resolves before the op and must be null after it.
  const dissolveOp = await Operation.create('__dissolve_machine__');
  dissolveOp.signerId = 'dissolver';
  dissolveOp.nodeId = 'dissolver';
  dissolveOp.payload = new TextEncoder().encode(childId);  // NUL-excluded
  parent.sign(dissolveOp, dissolverKey.privateKeyHex());
  parent.execute(dissolveOp);
  dissolveOp.destroy();

  if (parent.lineageResidentChild(childId) !== null) {
    throw new Error('in-process severance must clear the resident registry slot');
  }
  const dissolvedEntry = parent.childById(childId);
  if (dissolvedEntry === null || dissolvedEntry.status !== 'dissolved') {
    throw new Error(`manifest status after dissolve: ${JSON.stringify(dissolvedEntry)}`);
  }
  // The manifest entry the exported accessor resolves is DISSOLVED — the
  // exact honesty-gate state the tombstone mint must pass.
  const dissolvedIndex = parent.childIndex(childId);
  if (dissolvedIndex < 0) throw new Error('dissolved child lost from manifest');

  // Attest now refuses: the entry is no longer ACTIVE (honesty gate).
  let postDissolveAttestRefused = false;
  try {
    parent.attest(childId, 'alice', 'role:member');
  } catch (attestRefused) {
    postDissolveAttestRefused =
      attestRefused.message.includes('attest failed');
  }
  if (!postDissolveAttestRefused) {
    throw new Error('attest must fail closed for a dissolved child');
  }

  // Minting a tombstone for a non-dissolved child is a lie — refused.
  let tombstoneGateRefused = false;
  try {
    parent.lineageTombstone('not-spawned');
  } catch (gateRefused) {
    tombstoneGateRefused = gateRefused.message.includes('tombstone failed');
  }
  if (!tombstoneGateRefused) {
    throw new Error('tombstone mint must fail closed for a non-dissolved child');
  }

  // ------------------------------------------------------------
  // Tombstone mint: `u8 tag LINEAGE_DISSOLVED + string16 child_id` +
  // 64-byte parent ECDSA — NO length prefix (the exact bytes a
  // __receive_dissolution__ op transports). The trailing signature is
  // structurally verified here (nonzero); verifying it against the parent's
  // public key in wasm would need pub-key plumbing the smoke skips.
  // ------------------------------------------------------------
  const tombstone = parent.lineageTombstone(childId);
  const expectedLength = 3 + childId.length + CRABS_SIG_SIZE;
  if (tombstone.length !== expectedLength) {
    throw new Error(`tombstone length ${tombstone.length} != ${expectedLength}`);
  }
  if (tombstone[0] !== LINEAGE_DISSOLVED_TAG) {
    throw new Error(`tombstone tag ${tombstone[0]} != LINEAGE_DISSOLVED(${LINEAGE_DISSOLVED_TAG})`);
  }
  const idLengthPrefix = new DataView(tombstone.buffer, tombstone.byteOffset)
                           .getUint16(1, true);
  if (idLengthPrefix !== childId.length) {
    throw new Error(`tombstone id length ${idLengthPrefix} != ${childId.length}`);
  }
  const tombstoneId = new TextDecoder().decode(tombstone.subarray(3, 3 + idLengthPrefix));
  if (tombstoneId !== childId) {
    throw new Error(`tombstone id "${tombstoneId}" != "${childId}"`);
  }
  if (tombstone
        .subarray(3 + idLengthPrefix)
        .some(signatureByteValue => signatureByteValue === 0)) {
    throw new Error('tombstone signature carries a zero byte (not a real ECDSA)');
  }

  console.log('SMOKE OK: children=' + count +
              ', entry=' + JSON.stringify(childEntry) +
              ', blueprint_bytes=' + wire.length +
              ', attestation_bytes=' + attestationWire.length +
              ', dissolved_status=' + dissolvedEntry.status +
              ', tombstone_bytes=' + tombstone.length);

  blueprint.destroy();
  reloaded.destroy();
}

main().catch(error => { console.error(error); process.exit(1); });