// lineage-extras.js — P8 parity fill (crabs-node): the blueprint extras,
// the parent-key rotation chain, and the attestation wire parse surface.
// Mirrors bindings/wasm/test/lineage-extras.js surface-for-surface:
//   1. Blueprint.addItem(name, type, {domain, writer}) — write-domains v1
//      declarations at MINT time (blueprint_add_item_with_domain,
//      lineage.h:147); Blueprint.addOpType(opType, spec) carries a dedup
//      spec into the spawned child's registry (blueprint_add_op_type_def,
//      lineage.h:157 → state_register_op_type_def at spawn), so a recipe-2
//      flow works on a child that never ran defineOperationType itself.
//      The blueprint body's v2 format-version byte gates the per-item
//      domain payload; carried op-type defs ride the same canonical body
//      the stamped hash covers (no separate wire gate — the whole-body v2
//      gate rejects pre-v2 bodies outright, lineage.c:688).
//   2. node.lineageRotateKey(newKeyPair) — lineage_key_rotate
//      (lineage.h:285) + the paired state_set_node_key, returning the
//      signed transition record; child.lineageAcceptKeyTransition(record)
//      — lineage_child_accept_key_transition (lineage.h:318) with the C
//      battery's pinned semantics (test/test_lineage.cpp KeyChain tests):
//      re-delivery is ALREADY_PERFORMED, verification is tip-only (A11-4),
//      so pre-rotation attestations refuse once the chain advances.
//   3. node.attestationFromWire(bytes) — attestation_deserialize
//      (lineage.h:666): parse-only (verification happens at op
//      attach/execution), producing exactly the field shape
//      Operation.addAttestation consumes; garbage refuses typed.

'use strict';

const assert = require('assert');
const { Node, KeyPair, Operation, Blueprint, TRUST_MODE,
        DATA_TYPE, CRDT_TYPE } = require('..');

function expectRefusal(runnable, expected, what) {
  try {
    runnable();
  } catch (refusal) {
    assert(refusal.message.includes(expected),
      `${what}: expected "${expected}", got: ${refusal.message}`);
    return;
  }
  throw new Error(`${what}: expected a ${expected} refusal, got success`);
}

(async () => {
  // ============================================================
  // A: Blueprint extras — carried dedup spec + write-domain declarations
  // ============================================================
  {
    const parent = new Node('bp-root', { ordering: 'hlc' });

    const blueprint = Blueprint.create('sub-a', TRUST_MODE.DELEGATED_COPY,
                                       'a-admin', 3600000);
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
                      { domain: 'sovereign', writer: 'ledger-writer' });

    // Authoring gates (blueprint_add_item_with_domain mirrors the
    // data_item_create_with_options rules, fail-early):
    assert.throws(() =>
        blueprint.addItem('bad-type', DATA_TYPE.SET, CRDT_TYPE.OR_SET,
                          { domain: 'sovereign', writer: 'writer-x' }),
      /type_mismatch/, 'SOVEREIGN on a non-COUNTER/REGISTER type must refuse');
    assert.throws(() =>
        blueprint.addItem('bad-writer', DATA_TYPE.COUNTER,
                          CRDT_TYPE.G_COUNTER, { writer: 'writer-x' }),
      /invalid_param/, 'a writer on a non-SOVEREIGN domain must refuse');

    parent.lineageSpawn(blueprint);
    const child = parent.lineageResidentChild('sub-a');

    // Recipe 2 on a child that never ran defineOperationType: the carried
    // spec enforces, and the rejection message travels with it.
    const voterKey = KeyPair.generate();
    child.registerUser('voter', voterKey.publicKeyHex(), '');
    child.grantRole('voter', 'role', 'member', 'a-admin');

    const castVote = () => {
      const vote = new Operation('vote');
      vote.signerId = 'voter';
      vote.nodeId = 'voter';
      vote.addResource('ballot_voters');
      child.sign(vote, voterKey.privateKeyHex());
      child.execute(vote);
    };
    castVote();
    // The executor surfaces the TYPED dedup refusal (recipe 2's own pin —
    // node.setPolicy-level word, not the spec's metadata string).
    expectRefusal(castVote, 'already_performed',
      'a double vote must refuse by the carried spec');
    blueprint.destroy();
  }

  // ============================================================
  // B: parent-key rotation → child transition accept → tip-only verify
  // ============================================================
  {
    const parent = new Node('rot-root', { ordering: 'hlc' });
    const blueprint = Blueprint.create('rot-child',
      TRUST_MODE.DELEGATED_COPY, 'rc-admin', 3600000);
    blueprint.addPolicy('__check_dedup__', '@parent/role:member');
    blueprint.stampHash();
    parent.lineageSpawn(blueprint);
    const child = parent.lineageResidentChild('rot-child');
    const signerKey = KeyPair.generate();
    child.registerUser('alice', signerKey.publicKeyHex(), '');

    // Fresh parent stamps the spawn generation (version 1), and the parse
    // surface hands exactly the fields Operation.addAttestation consumes.
    const pre = child.attestationFromWire(
      parent.lineageAttest('rot-child', 'alice', 'role:member'));
    assert.strictEqual(pre.parentId, 'rot-root',
      'attestation must bind the parent id');
    assert.strictEqual(pre.childId, 'rot-child',
      'attestation must bind the child id');
    assert.strictEqual(pre.parentKeyVersion, 1,
      'fresh parent stamps the spawn generation');

    const executeEndorsed = (fields) => {
      const op = new Operation('__check_dedup__');
      op.signerId = 'alice';
      op.nodeId = 'alice';
      op.addAttestation(fields);
      child.sign(op, signerKey.privateKeyHex());
      child.execute(op);
    };
    executeEndorsed(pre);   // the spawn-pin tip verifies version 1

    // The parent rotates: a signed transition record comes back (old_pk +
    // new_pk + 64-byte ECDSA; the wrapper installs the new node key too —
    // the C contract's rotate/set pairing is the binding's job).
    const newKey = KeyPair.generate();
    const record = parent.lineageRotateKey(newKey);
    assert(record.length > 64,
      'the transition record carries body + signature');

    // Parent attestations now mint under the NEW chain version.
    const post = child.attestationFromWire(
      parent.lineageAttest('rot-child', 'alice', 'role:member'));
    assert.strictEqual(post.parentKeyVersion, 2,
      'rotation advances the parent lineage key version');

    // Pre-accept, the child's tip is still the spawn pin: the NEW
    // attestation (a version gap from the tip) refuses...
    expectRefusal(() => executeEndorsed(post), 'unauthorized',
      'a new-key vouch must refuse while the child chain still pins spawn');
    // ...while the old-key vouch still verifies (tip == old key).
    executeEndorsed(pre);

    // The child accepts the transition record.
    child.lineageAcceptKeyTransition(record);

    // Tip-only verification (A11-4): the retired-key vouch now refuses...
    expectRefusal(() => executeEndorsed(pre), 'unauthorized',
      'a pre-rotation vouch must refuse once the chain advanced');
    // ...and the new-key vouch lands.
    executeEndorsed(post);

    // Re-delivery of the SAME record is ALREADY_PERFORMED (A11-L5), and a
    // malformed image refuses without touching the chain.
    expectRefusal(() => child.lineageAcceptKeyTransition(record),
      'already_performed', 'a replayed record must refuse already_performed');
    expectRefusal(() => child.lineageAcceptKeyTransition(
        Buffer.alloc(16, 0xAB)),
      'invalid_param', 'a garbage record must refuse invalid_param');
  }

  // ============================================================
  // C: attestationFromWire — parse-only, typed refusal on garbage
  // ============================================================
  {
    const parent = new Node('parse-root', { ordering: 'hlc' });
    const blueprint = Blueprint.create('parse-child',
      TRUST_MODE.DELEGATED_COPY, 'p-admin', 3600000);
    blueprint.stampHash();
    parent.lineageSpawn(blueprint);
    const child = parent.lineageResidentChild('parse-child');

    const fields = child.attestationFromWire(
      parent.lineageAttest('parse-child', 'carol', 'role:member'));
    assert.strictEqual(fields.parentId, 'parse-root');
    assert.strictEqual(fields.childId, 'parse-child');
    assert.strictEqual(fields.userId, 'carol');
    assert.strictEqual(fields.attributes, 'role:member');
    assert(Number.isInteger(fields.notBefore) &&
           Number.isInteger(fields.expiresAt) &&
           Number.isInteger(fields.parentKeyVersion),
      'the stamps arrive as numbers (the node JS-safe-integer convention)');
    assert.strictEqual(fields.signatureHex.length, 128,
      'signatureHex must be 128 hex chars (64 bytes)');
    assert(/^[0-9a-f]+$/.test(fields.signatureHex),
      'signatureHex must be lowercase hex');
    assert(fields.expiresAt > fields.notBefore,
      'the ttl-bounded window must be non-degenerate');

    // Garbage refuses typed — truncated, structured garbage, tampered
    // signature byte, one dropped trailing byte.
    assert.throws(() => child.attestationFromWire(Buffer.alloc(12)),
      /malformed/, 'a truncated image must refuse');
    assert.throws(() => child.attestationFromWire(Buffer.alloc(256, 0x5A)),
      /malformed/, 'structured garbage must refuse');
    const good = parent.lineageAttest('parse-child', 'carol', 'role:member');
    // Parse-only fact: a SIGNATURE-tampered image still parses — the parse
    // is structural; the executor's chain-TIP check at op attach/execution
    // is what refuses bad signatures. Only STRUCTURE refuses here.
    const tampered = Buffer.from(good);
    for (let byteIndex = good.length - 64; byteIndex < good.length;
         byteIndex++) {
      tampered[byteIndex] ^= 0xFF;
    }
    const tamperedFields = child.attestationFromWire(tampered);
    assert.strictEqual(tamperedFields.signatureHex.length, 128,
      'the tampered image parses field-wise, signature content untouched');
    assert.throws(() =>
        child.attestationFromWire(good.subarray(0, good.length - 1)),
      /malformed/, 'one dropped trailing byte must refuse');
  }

  console.log('lineage-extras node: OK');
})().catch((failure) => {
  console.error('lineage-extras node FAILED:', failure);
  process.exit(1);
});