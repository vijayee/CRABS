'use strict';

// lineage-extras.js — P8 parity fill (wasm): the blueprint extras, the
// parent-key rotation chain, and the attestation wire parse surface.
//
//   1. Blueprint.addItem(name, type, {domain, writer}) — write-domains v1
//      declarations at MINT time (blueprint_add_item_with_domain,
//      lineage.h:147); the SOVEREIGN item a child spawns with is born
//      writer-bound and hash-chained from genesis (_spawn_apply_blueprint,
//      lineage.c:1366). Blueprint.addOpType(opType, spec) carries a dedup
//      spec into the spawned child's registry (blueprint_add_op_type_def,
//      lineage.h:157 → state_register_op_type_def at spawn), so a recipe-2
//      flow works on a child that never ran defineOperationType itself.
//      The blueprint wire format carries op-type defs natively
//      (lineage.c _blueprint_write_body: u32le op_type_def_count; per def:
//      string16 op_type + <dedup_spec>) and the v2 format-version byte
//      gates the per-item domain payload — pre-v2 bodies are rejected
//      outright at blueprint_deserialize (lineage.c:688), so both the
//      write-domain add and the carried specs serialize through the SAME
//      canonical body the hash covers; no separate wire gate exists for
//      op-type defs (they have been blueprint-wire citizens since v1) —
//      the gate is the whole-body v2 version byte, fail-closed.
//   2. node.lineageRotateKey(newKeyPair) — lineage_key_rotate
//      (lineage.h:285) + the paired state_set_node_key, returning the
//      signed transition record; child.lineageAcceptKeyTransition(record)
//      — lineage_child_accept_key_transition (lineage.h:318) with the C
//      test's pinned semantics (test/test_lineage.cpp KeyChain tests):
//      one record serves every child of the parent, re-delivery is
//      ALREADY_PERFORMED, endorsement verification is tip-only (A11-4) so
//      pre-rotation attestations refuse after the chain advances.
//   3. node.attestationFromWire(bytes) — attestation_deserialize
//      (lineage.h:666): parse-only (verification happens at op
//      attach/execution), producing exactly the field shape
//      Operation.addAttestation consumes; garbage refuses typed.

const assert = require('assert');
const { Node, KeyPair, Operation, Blueprint, getModule,
        TRUST_MODE, DATA_TYPE, CRDT_TYPE } = require('..');

// Execute refusals surface their typed code in the message; assert on it.
async function expectRefusal(runnable, expected, what) {
  try {
    await runnable();
  } catch (refusal) {
    assert(refusal.message.includes(expected),
      `${what}: expected "${expected}", got: ${refusal.message}`);
    return;
  }
  throw new Error(`${what}: expected a ${expected} refusal, got success`);
}

(async () => {
  const M = await getModule();

  // ============================================================
  // A: Blueprint extras — carried dedup spec + write-domain declarations
  // ============================================================
  {
    const parent = await Node.create('bp-root', { ordering: 'hlc' });
    parent.setTime(Date.now());

    const blueprint = await Blueprint.create('sub-a',
      TRUST_MODE.DELEGATED_COPY, 'a-admin', 3600000);
    // The tracker the carried spec will enforce — a genesis item of the
    // child, carried in the same blueprint.
    blueprint.addItem('ballot_voters', DATA_TYPE.ONE_SHOT_SET,
      CRDT_TYPE.ONE_SHOT_SET);
    blueprint.addPolicy('vote', 'role:member');
    blueprint.addOpType('vote', {
      dedup: 'per-user',
      trackerPath: 'ballot_voters',
      rejectionMessage: 'carried-spec-refusal',
    });

    // Write-domain declaration at mint: a SOVEREIGN counter with an
    // explicit writer (write-domains v1; COUNTER-only rule).
    blueprint.addItem('ledger', DATA_TYPE.COUNTER, CRDT_TYPE.G_COUNTER,
      { domain: 0x01 /* SOVEREIGN */, writer: 'ledger-writer' });

    // Authoring gates (blueprint_add_item_with_domain mirrors the
    // data_item_create_with_options rules, fail-early):
    assert.throws(() =>
        blueprint.addItem('bad-type', DATA_TYPE.SET, CRDT_TYPE.OR_SET,
          { domain: 0x01, writer: 'writer-x' }),
      /type_mismatch/, 'SOVEREIGN on a non-COUNTER/REGISTER type must refuse');
    assert.throws(() =>
        blueprint.addItem('bad-writer', DATA_TYPE.COUNTER,
          CRDT_TYPE.G_COUNTER, { writer: 'writer-x' }),
      /invalid_param/, 'a writer on a non-SOVEREIGN domain must refuse');

    parent.lineageSpawn(blueprint);
    const child = new Node(M, parent.lineageResidentChild('sub-a'));
    child.adminId = 'a-admin';

    // Recipe 2 on a child that never ran defineOperationType: the carried
    // spec enforces, and the rejection message travels with it.
    const voterKey = await KeyPair.generate();
    child.registerUser('voter', voterKey.publicKeyHex(), '');
    child.grantRole('voter', 'role', 'member', 'a-admin');

    const castVote = async () => {
      const vote = await Operation.create('vote');
      vote.signerId = 'voter';
      vote.nodeId = 'voter';
      vote.addResource('ballot_voters');
      child.sign(vote, voterKey.privateKeyHex());
      child.execute(vote);
      vote.destroy();
    };
    await castVote();
    // The executor surfaces the TYPED dedup refusal (recipe 2's own pin —
    // not the spec's metadata string).
    await expectRefusal(castVote, 'already_performed',
      'a double vote must refuse by the carried spec');
    blueprint.destroy();
  }

  // ============================================================
  // B: parent-key rotation → child transition accept → tip-only verify
  // ============================================================
  {
    const parent = await Node.create('rot-root', { ordering: 'hlc' });
    parent.setTime(Date.now());

    const blueprint = await Blueprint.create('rot-child',
      TRUST_MODE.DELEGATED_COPY, 'rc-admin', 3600000);
    blueprint.addPolicy('__check_dedup__', '@parent/role:member');
    blueprint.stampHash();
    parent.lineageSpawn(blueprint);
    const child = new Node(M, parent.lineageResidentChild('rot-child'));
    child.adminId = 'rc-admin';
    const signerKey = await KeyPair.generate();
    child.registerUser('alice', signerKey.publicKeyHex(), '');

    // Fresh parent stamps the spawn generation (version 1), and the parse
    // surface hands exactly the fields Operation.addAttestation consumes.
    const pre = child.attestationFromWire(
      parent.attest('rot-child', 'alice', 'role:member'));
    assert.strictEqual(pre.parentId, 'rot-root',
      'attestation must bind the parent id');
    assert.strictEqual(pre.childId, 'rot-child',
      'attestation must bind the child id');
    assert.strictEqual(pre.parentKeyVersion, 1n,
      'fresh parent stamps the spawn generation');

    const executeEndorsed = async (fields) => {
      const op = await Operation.create('__check_dedup__');
      op.signerId = 'alice';
      op.nodeId = 'alice';
      op.addAttestation(fields);
      child.sign(op, signerKey.privateKeyHex());
      child.execute(op);
      op.destroy();
    };
    await executeEndorsed(pre);   // the spawn-pin tip verifies version 1

    // The parent rotates: a signed transition record comes back (old_pk +
    // new_pk + 64-byte ECDSA; the wrapper installs the new node key too —
    // the C contract's rotate/set pairing is the binding's job).
    const newKey = await KeyPair.generate();
    const record = parent.lineageRotateKey(newKey);
    assert(record.byteLength > 64,
      'the transition record carries body + signature');

    // Parent attestations now mint under the NEW chain version.
    const post = child.attestationFromWire(
      parent.attest('rot-child', 'alice', 'role:member'));
    assert.strictEqual(post.parentKeyVersion, 2n,
      'rotation advances the parent lineage key version');

    // Pre-accept, the child's tip is still the spawn pin: the NEW
    // attestation (a version gap from the tip) refuses.
    await expectRefusal(() => executeEndorsed(post), 'unauthorized',
      'a new-key vouch must refuse while the child chain still pins spawn');
    // ...while the old-key vouch still verifies (tip == old key).
    await executeEndorsed(pre);

    // The child accepts the transition record.
    child.lineageAcceptKeyTransition(record);

    // Tip-only verification (A11-4): the retired-key vouch now refuses...
    await expectRefusal(() => executeEndorsed(pre), 'unauthorized',
      'a pre-rotation vouch must refuse once the chain advanced');
    // ...and the new-key vouch lands.
    await executeEndorsed(post);

    // Re-delivery of the SAME record is ALREADY_PERFORMED (A11-L5), and a
    // malformed image refuses without touching the chain.
    await expectRefusal(() => child.lineageAcceptKeyTransition(record),
      'already_performed', 'a replayed record must refuse already_performed');
    await expectRefusal(
      () => child.lineageAcceptKeyTransition(new Uint8Array(16).fill(0xAB)),
      'invalid_param', 'a garbage record must refuse invalid_param');
  }

  // ============================================================
  // C: attestationFromWire — parse-only, typed refusal on garbage
  // ============================================================
  {
    const parent = await Node.create('parse-root', { ordering: 'hlc' });
    parent.setTime(Date.now());
    const blueprint = await Blueprint.create('parse-child',
      TRUST_MODE.DELEGATED_COPY, 'p-admin', 3600000);
    blueprint.stampHash();
    parent.lineageSpawn(blueprint);
    const child = new Node(M, parent.lineageResidentChild('parse-child'));

    const fields = child.attestationFromWire(
      parent.attest('parse-child', 'carol', 'role:member'));
    assert.strictEqual(fields.parentId, 'parse-root');
    assert.strictEqual(fields.childId, 'parse-child');
    assert.strictEqual(fields.userId, 'carol');
    assert.strictEqual(fields.attributes, 'role:member');
    assert(typeof fields.notBefore === 'bigint' &&
           typeof fields.expiresAt === 'bigint' &&
           typeof fields.parentKeyVersion === 'bigint',
      'the stamps arrive as BigInt (the wasm u64 convention)');
    assert.strictEqual(fields.signatureHex.length, 128,
      'signatureHex must be 128 hex chars (64 bytes)');
    assert(/^[0-9a-f]+$/.test(fields.signatureHex),
      'signatureHex must be lowercase hex');
    // expiry = now + ttl (the manifest carried 3600000)
    assert(fields.expiresAt > fields.notBefore,
      'the ttl-bounded window must be non-degenerate');

    // Garbage refuses typed — truncated, wrong format byte, tampered body.
    assert.throws(() => child.attestationFromWire(new Uint8Array(12)),
      /malformed/, 'a truncated image must refuse');
    assert.throws(() => child.attestationFromWire(
        new Uint8Array(256).fill(0x5A)),
      /malformed/, 'structured garbage must refuse');
    const good = parent.attest('parse-child', 'carol', 'role:member');
    // Parse-only fact: a SIGNATURE-tampered image still parses — the parse
    // is structural; the executor's chain-TIP check at op attach/execution
    // is what refuses bad signatures. Only STRUCTURE refuses here.
    const tampered =
      Uint8Array.from(good, (byte, index) =>
        index >= good.length - 64 ? byte ^ 0xFF : byte);
    const tamperedFields = child.attestationFromWire(tampered);
    assert.strictEqual(tamperedFields.signatureHex.length, 128,
      'the tampered image parses field-wise, signature content untouched');
    assert.throws(() => child.attestationFromWire(
        good.subarray(0, good.length - 1)),
      /malformed/, 'one dropped trailing byte must refuse');
  }

  // ============================================================
  // D: lineageRotateKey key custody — heap-direct read (audit pass-3 M)
  // ============================================================
  {
    const node = await Node.create('custody-root', { ordering: 'hlc' });
    node.setTime(Date.now());

    // (a) The raw KeyPair form (fromPrivateHex; _raw = true) reads through
    // the SAME +0/+32 byte layout as the generated ecdsa_keypair_t form —
    // the fix reads both straight off this instance's heap with no hex
    // round-trip (a V8 string copy of the scalar would be unwipeable).
    const donor = await KeyPair.generate();
    const rawKey = await KeyPair.fromPrivateHex(donor.privateKeyHex());
    const record = node.lineageRotateKey(rawKey);
    assert(record instanceof Uint8Array && record.byteLength > 0,
      'rotation of a raw-form KeyPair must return the transition record bytes');
    rawKey.destroy();
    donor.destroy();

    // ...and the generated form keeps working (the layout parity the fix
    // rests on — both must read through the same staged 65-byte frame).
    const secondKey = await KeyPair.generate();
    const secondRecord = node.lineageRotateKey(secondKey);
    assert(secondRecord instanceof Uint8Array && secondRecord.byteLength > 0,
      'rotation of a generated KeyPair must return the transition record bytes');
    secondKey.destroy();

    // (b) A KeyPair minted by a DIFFERENT module instance (the dev bundle
    // loads its own wasm binary with its own linear memory) carries a
    // foreign-heap _ptr — reading it as if local would deref someone else's
    // memory. The machine must refuse instance-mismatched keys.
    const devBindings = require('../dev');
    const foreignKey = await devBindings.KeyPair.generate();
    assert.throws(() => node.lineageRotateKey(foreignKey),
      /expected a KeyPair minted by THIS module instance/,
      'a foreign-module KeyPair must refuse at lineageRotateKey');
    foreignKey.destroy();
  }

  console.log('lineage-extras wasm: OK');
})().catch((failure) => {
  console.error('lineage-extras wasm FAILED:', failure);
  process.exit(1);
});