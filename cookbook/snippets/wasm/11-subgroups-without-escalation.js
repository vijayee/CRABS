'use strict';
// Recipe 11 — a group with subgroups that can't escalate (crabs-wasm).
//
// A parent group machine spawns a child machine (a "subgroup") from a
// Blueprint: item set, policy set and trust mode are the charter the parent
// signed. The subgroup gets its own fresh authority (DELEGATED_COPY), the
// parent tracks it in a child manifest, and the parent's lifecycle control
// is real: dissolving the child sever its endorsement authority instantly
// and mints a signed tombstone. Mirrors the wasm lineage smoke
// (bindings/wasm/lineage_smoke.mjs).

const assert = require('assert');
const { Node, KeyPair, Operation, Blueprint, TRUST_MODE, DATA_TYPE, CRDT_TYPE } =
  require('../../../bindings/wasm');

const childId = 'billing-team';
const LINEAGE_DISSOLVED_TAG = 0x01;   // lineage_status_e LINEAGE_DISSOLVED
const CRABS_SIG_SIZE = 64;

async function main() {
  // Machine A: the parent group machine, full admin of its own domain.
  const parent = await Node.create('parent-admin');
  parent.setTime(Date.now());   // attest reads the machine's time source
  parent.lineageInstall();

  // The subgroup's charter: a Blueprint a parent can serialize, ship, and
  // verify. DELEGATED_COPY mints the child its own fresh authority.
  const blueprint = await Blueprint.create(childId, TRUST_MODE.DELEGATED_COPY,
                                           'team-admin', 3600000);
  blueprint.addItem('score', DATA_TYPE.COUNTER, CRDT_TYPE.G_COUNTER);
  blueprint.addPolicy('view', 'role:member');
  blueprint.stampHash();

  // Wire round trip: serialize -> deserialize verifies the embedded hash and
  // re-validates the structure — the exact bytes a __spawn_machine__ op
  // carries as payload.
  const wire = blueprint.serialize();
  assert(wire.length > 0, 'blueprint serialize produced no bytes');
  const reloaded = await Blueprint.deserialize(wire);

  // Spawn: JS borrows the child pointer; the parent's resident registry in
  // C owns the machine.
  const childPtr = parent.lineageSpawn(blueprint);
  const resident = parent.lineageResidentChild(childId);
  assert(resident !== null && resident === childPtr,
    'spawned child not resolvable in the resident registry');

  // The manifest is the parent's durable track record of what it minted.
  const count = parent.childCount();
  assert(count === 1, `expected child count 1, got ${count}`);
  const entry = parent.childById(childId);
  assert(entry !== null, 'child manifest entry missing after spawn');
  assert(entry.mode === 'delegated_copy' && entry.status === 'active',
    `unexpected manifest view: ${JSON.stringify(entry)}`);
  assert(entry.ttlMs === 3600000, `unexpected ttl: ${entry.ttlMs}`);
  assert(parent.childIndex('not-spawned') === -1, 'childIndex miss must be -1');
  assert(parent.childCount() === parent.children().length,
    'children snapshot disagrees with child count');

  // No double-mint: the same child_id is refused even with identical
  // content — the manifest stays honest about what exists. (The wasm
  // wrapper surfaces the C error as the generic "lineageSpawn failed";
  // the typed name lives in the C error code, CRABS_ERR_DUPLICATE_OPERATION.)
  assert.throws(() => parent.lineageSpawn(reloaded), /lineageSpawn failed/,
    'spawning the same child_id twice must be refused');

  // ------------------------------------------------------------
  // Severance, through the op pipeline: role:admin must resolve against a
  // registered user (registerUser rejects privileged attribute names, so
  // grantRole is the honest admin route). __dissolve_machine__ on a RESIDENT
  // child flips the child's lineage_parent_dissolved flag durably — every
  // parent endorsement on the child fails closed from that moment — and
  // drops the registry slot.
  // ------------------------------------------------------------
  const dissolverKey = await KeyPair.generate();
  parent.registerUser('dissolver', dissolverKey.publicKeyHex(), 'adult');
  parent.grantRole('dissolver', 'role', 'admin', 'parent-admin');

  const dissolveOp = await Operation.create('__dissolve_machine__');
  dissolveOp.signerId = 'dissolver';
  dissolveOp.nodeId = 'dissolver';
  dissolveOp.payload = new TextEncoder().encode(childId);  // NUL-excluded
  parent.sign(dissolveOp, dissolverKey.privateKeyHex());
  parent.execute(dissolveOp);
  dissolveOp.destroy();

  assert(parent.lineageResidentChild(childId) === null,
    'in-process severance must clear the resident registry slot');
  const dissolvedEntry = parent.childById(childId);
  assert(dissolvedEntry !== null && dissolvedEntry.status === 'dissolved',
    `manifest status after dissolve: ${JSON.stringify(dissolvedEntry)}`);

  // The authority teeth: attest refuses for anything not ACTIVE.
  assert.throws(() => parent.attest(childId, 'alice', 'role:member'), /attest/,
    'attest must fail closed for a dissolved child');

  // Tombstones: minting one for a non-dissolved child is a lie — refused.
  assert.throws(() => parent.lineageTombstone('not-spawned'), /tombstone/,
    'tombstone mint must fail closed for a non-dissolved child');

  // The tombstone for the dissolved child: canonical body (u8 tag +
  // string16 child_id + u64le parent_key_version — a fresh parent stamps
  // its spawn generation, 1) + 64-byte parent ECDSA, no length prefix.
  const tombstone = parent.lineageTombstone(childId);
  const expectedLength = 3 + childId.length + 8 + CRABS_SIG_SIZE;
  assert(tombstone.length === expectedLength,
    `tombstone length ${tombstone.length} != ${expectedLength}`);
  assert(tombstone[0] === LINEAGE_DISSOLVED_TAG,
    `tombstone tag ${tombstone[0]} != LINEAGE_DISSOLVED`);
  const tombstoneView = new DataView(tombstone.buffer, tombstone.byteOffset);
  const idLengthPrefix = tombstoneView.getUint16(1, true);
  assert(idLengthPrefix === childId.length, 'tombstone id length mismatch');
  assert(new TextDecoder().decode(tombstone.subarray(3, 3 + idLengthPrefix))
           === childId, 'tombstone id mismatch');
  assert(tombstoneView.getBigUint64(3 + idLengthPrefix, true) === 1n,
    'fresh parent must stamp the spawn generation (key version 1)');
  assert(!tombstone.subarray(3 + idLengthPrefix + 8)
           .every(signatureByteValue => signatureByteValue === 0),
    'tombstone signature is all zero bytes (not a real ECDSA)');

  blueprint.destroy();
  reloaded.destroy();
  dissolverKey.destroy();
  console.log('subgroups-without-escalation wasm OK: spawned, manifested,' +
    ' duplicated refuse, dissolved, tombstoned');
}

main().catch((failure) => {
  console.error('subgroups-without-escalation wasm FAILED:', failure);
  process.exit(1);
});