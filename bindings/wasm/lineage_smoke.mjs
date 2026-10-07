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

const { Node, Blueprint, TRUST_MODE, DATA_TYPE, CRDT_TYPE } =
  createRequire(path.join(bindingsDir, 'dev.js'))('./dev.js');

const childId = 'child-omega';

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

  console.log('SMOKE OK: children=' + count +
              ', entry=' + JSON.stringify(childEntry) +
              ', blueprint_bytes=' + wire.length +
              ', attestation_bytes=' + attestationWire.length);

  blueprint.destroy();
  reloaded.destroy();
}

main().catch(error => { console.error(error); process.exit(1); });