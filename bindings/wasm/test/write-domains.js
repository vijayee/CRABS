//
// write-domains.js — smoke test for the wasm write-domains v1 exports:
// defineItem (write-domain declaration), op.addResource +
// op.setSovereignPrefix (signed v6 chain prefixes), and
// node.reportEquivocation (evidence-verified fork quarantine).
//
'use strict';

const assert = require('assert');
const { Node, KeyPair, Operation } = require('..');

async function main() {
  const node = await Node.create('dom-admin');
  const aliceKey = await KeyPair.generate();
  node.registerUser('alice', aliceKey.publicKeyHex(), '');
  node.grantRole('alice', 'role', 'member', 'dom-admin');
  const malloryKey = await KeyPair.generate();
  node.registerUser('mallory', malloryKey.publicKeyHex(), '');
  node.grantRole('mallory', 'role', 'member', 'dom-admin');

  // defineItem with the sovereign domain; a plain free-merge counter stays
  // the default for the add* path.
  node.defineItem('score', 'counter', 'g_counter',
    { domain: 'sovereign', writer: 'alice' });
  node.addCounter('free-counter');
  node.setPolicy('bump', 'role:member');

  // defineItem refusals (v1 scope: counter/register only; sovereign needs a
  // writer; unknown domain words are TypeError-class errors at the wrapper).
  assert.throws(() => node.defineItem('orphan', 'counter', 'g_counter',
    { domain: 'sovereign' }), /invalid_param/,
    'sovereign without a writer should throw invalid_param');
  assert.throws(() => node.defineItem('mixed', 'counter', 'g_counter',
    { domain: 'free', writer: 'alice' }), /invalid_param/,
    'a writer on a free item should throw invalid_param');
  assert.throws(() => node.defineItem('odd', 'counter', 'g_counter',
    { domain: 'feudal' }), /domain must be/,
    'an unknown domain word should throw');
  assert.throws(() => node.defineItem('doc', 0x03, 0x03, { domain: 'free' }),
    /type_mismatch/,
    'a non-legal type number should throw type_mismatch from the C check');

  // setSovereignPrefix argument checking: the digest is exactly 64 hex
  // chars (or 32 raw bytes).
  const guardOp = await Operation.create('bump');
  guardOp.addResource('score');
  assert.throws(() => guardOp.setSovereignPrefix(0, 0, 'abcd'),
    /digest/, 'short digest hex should throw');
  assert.throws(() => guardOp.setSovereignPrefix(0, 0, 'z'.repeat(64)),
    /digest/, 'non-hex digest should throw');
  // A negative BigInt would wrap silently through the unsigned i64 wire;
  // fractional numbers fail BigInt() conversion. Refuse both loudly.
  for (const badSeq of [1.5, -2, -1n]) {
    assert.throws(() => guardOp.setSovereignPrefix(0, badSeq, '0'.repeat(64)),
      /seq must be/, `seq ${badSeq} should throw`);
  }
  // orderingModule narrowing: 256 would truncate to 0 (unset) at the C
  // export — the wrapper refuses instead.
  assert.throws(() => node.defineItem('mod', 'counter', 'g_counter',
    { domain: 'group', orderingModule: 256 }), /orderingModule/,
    'orderingModule 256 should throw a RangeError at the wrapper');
  guardOp.destroy();

  // The writer's first op on the fresh chain: seq 0 with the all-zero
  // initial digest. Signed by alice; the DOMAIN_CHECK matches the prefix
  // against the item and the wildcard apply accepts it.
  const ZERO_DIGEST = '0'.repeat(64);
  const writerOp = await Operation.create('bump');
  writerOp.signerId = 'alice';
  writerOp.addResource('score');
  writerOp.setSovereignPrefix(0, 0, ZERO_DIGEST);
  node.sign(writerOp, aliceKey);
  const opAWire = writerOp.serialize();
  node.execute(writerOp);
  writerOp.destroy();

  // The writer's SECOND op must claim the live chain head; itemChainHead is
  // the binding-side read for it (the devtools snapshot's digest head is
  // only 8 bytes — too short to sign with).
  const head = node.itemChainHead('score');
  assert.strictEqual(head.seq, 1, 'head seq should advance to 1');
  assert.match(head.digestHex, /^[0-9a-f]{64}$/,
    'head digest should be a full 32-byte hex string');
  assert.notStrictEqual(head.digestHex, ZERO_DIGEST,
    'head digest should be recomputed after the first op');
  assert.throws(() => node.itemChainHead('ghost'), /resource_not_found/,
    'itemChainHead on an unknown item should throw resource_not_found');

  const secondOp = await Operation.create('bump');
  secondOp.signerId = 'alice';
  secondOp.addResource('score');
  secondOp.setSovereignPrefix(0, head.seq, head.digestHex);
  node.sign(secondOp, aliceKey);
  node.execute(secondOp);
  secondOp.destroy();
  assert.strictEqual(node.itemChainHead('score').seq, 2,
    'head seq should advance to 2 after the second accepted write');

  // A non-writer op on the sovereign item is rejected with not_item_writer
  // even though mallory holds the authorizing role.
  const rogueOp = await Operation.create('bump');
  rogueOp.signerId = 'mallory';
  rogueOp.addResource('score');
  rogueOp.setSovereignPrefix(0, 1, ZERO_DIGEST);
  node.sign(rogueOp, malloryKey);
  assert.throws(() => node.execute(rogueOp), /not_item_writer/,
    'non-writer op on a sovereign item should throw not_item_writer');
  rogueOp.destroy();

  // A genuine fork: op_b is a second alice-signed claim to the same chain
  // head (seq 0, zero digest) that never executed here — minted fresh
  // (random uuid) so it is provably distinct from op_a's wire bytes.
  const forkOp = await Operation.create('bump');
  forkOp.signerId = 'alice';
  forkOp.addResource('score');
  forkOp.setSovereignPrefix(0, 0, ZERO_DIGEST);
  node.sign(forkOp, aliceKey);
  const opBWire = forkOp.serialize();
  forkOp.destroy();
  assert.notDeepStrictEqual(Buffer.from(opAWire), Buffer.from(opBWire),
    'fork evidence must be two distinct serialized ops');

  // The report quarantines alice on the item; her later op is rejected.
  node.setPolicy('__report_equivocation__', 'role:admin');
  node.reportEquivocation('score', opAWire, opBWire);

  const quarantinedOp = await Operation.create('bump');
  quarantinedOp.signerId = 'alice';
  quarantinedOp.addResource('score');
  quarantinedOp.setSovereignPrefix(0, 1, ZERO_DIGEST);
  node.sign(quarantinedOp, aliceKey);
  assert.throws(() => node.execute(quarantinedOp), /quarantined/,
    'quarantined writer op should throw quarantined');
  quarantinedOp.destroy();

  // Failure paths: same-op-twice is invalid evidence, a free-merge target
  // and an unknown item are refused up front, and a re-report of the same
  // conviction dedupes.
  assert.throws(() => node.reportEquivocation('score', opAWire, opAWire),
    /invalid_param/, 'same-op-twice report should throw invalid_param');
  assert.throws(() => node.reportEquivocation('free-counter', opAWire, opBWire),
    /invalid_param/, 'free-merge target should throw invalid_param');
  assert.throws(() => node.reportEquivocation('ghost', opAWire, opBWire),
    /resource_not_found/, 'unknown item should throw resource_not_found');
  assert.throws(() => node.reportEquivocation('score', opBWire, opAWire),
    /duplicate_operation/, 're-report should throw duplicate_operation');

  node.destroy();
  console.log('write-domains wasm smoke: OK');
}

main().catch((failure) => {
  console.error('write-domains wasm smoke FAILED:', failure);
  process.exit(1);
});
