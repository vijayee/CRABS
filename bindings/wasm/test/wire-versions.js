'use strict';

// wire-versions.js — consumption-fixes finding 5: wire-version diagnostics.
// Asserts the C-mirrored constants are exposed (no drift), frozen, and that
// Operation.getWireVersion() reports the active op format on fresh ops and
// the declared wire version on round-tripped ops.

const { Operation, wireVersions } = require('..');

(async () => {
  const versions = await wireVersions();

  // Constants are exposed and match the documented build values
  // (serialization.h CRABS_SERIAL_VERSION, state_machine.h
  // CRABS_OP_FORMAT_VERSION, serialization.h CRABS_SIGNING_FORMAT_VERSION).
  if (versions.state !== 15) {
    throw new Error(`wireVersions.state=${versions.state}, expected 15`);
  }
  if (versions.op !== 6) {
    throw new Error(`wireVersions.op=${versions.op}, expected 6`);
  }
  if (versions.signing !== 4) {
    throw new Error(`wireVersions.signing=${versions.signing}, expected 4`);
  }

  // The resolved object is frozen.
  if (!Object.isFrozen(versions)) {
    throw new Error('wireVersions result must be frozen');
  }
  try {
    versions.state = 0;  // silent no-op under freeze (sloppy mode)
  } catch (_) { /* strict-mode engines throw here — also acceptable */ }
  if (versions.state !== 15) {
    throw new Error('wireVersions was mutable');
  }

  // The promise is cached — repeated calls return the same object.
  const again = await wireVersions();
  if (again !== versions) {
    throw new Error('wireVersions must return a cached frozen object');
  }

  // A freshly created op carries the build's CRABS_OP_FORMAT_VERSION.
  const fresh = await Operation.create('probe');
  if (fresh.getWireVersion() !== versions.op) {
    throw new Error(
      `fresh op getWireVersion=${fresh.getWireVersion()}, expected ${versions.op}`);
  }

  // A round-tripped op preserves its op_version through serialization.
  const wire = fresh.serialize();
  fresh.destroy();
  const parsed = await Operation.deserialize(wire);
  if (parsed.getWireVersion() !== versions.op) {
    throw new Error(
      `deserialized op getWireVersion=${parsed.getWireVersion()}, expected ${versions.op}`);
  }
  parsed.destroy();

  console.log('wire-versions OK:', JSON.stringify(versions));
})().catch(e => { console.error(e); process.exit(1); });
