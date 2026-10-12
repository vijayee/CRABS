'use strict';
// Recipe 10 — actions a leader takes that everyone can verify (crabs-wasm).
//
// Same shape as the crabs-node section, on the wasm surface: async static
// constructors, explicit destroy() on ops, prefixes taking seq as
// number | bigint, and the digest either as 64 hex chars or (wasm only) as
// 32 raw bytes. Mirrors bindings/wasm/test/write-domains.js:12-149.

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../../../bindings/wasm');

async function main() {
  const node = await Node.create('dom-admin');

  const leaderKey = await KeyPair.generate();
  node.registerUser('leader', leaderKey.publicKeyHex(), '');
  node.grantRole('leader', 'role', 'member', 'dom-admin');

  const memberKey = await KeyPair.generate();
  node.registerUser('member', memberKey.publicKeyHex(), '');
  node.grantRole('member', 'role', 'member', 'dom-admin');

  // The leader's ledger: single writer, hash-chained.
  node.defineItem('ledger', 'counter', 'g_counter',
    { domain: 'sovereign', writer: 'leader' });
  node.addCounter('free-counter');
  node.setPolicy('adjust', 'role:member');
  node.setPolicy('__report_equivocation__', 'role:admin');

  const ZERO_DIGEST = '0'.repeat(64);

  // Prefix guards, on wasm in particular: the seq is accepted as a number
  // or as a bigint — and both fractional seq and negative BigInts are
  // refused instead of silently wrapping through the unsigned i64 wire.
  const guardOp = await Operation.create('adjust');
  guardOp.addResource('ledger');
  assert.throws(() => guardOp.setSovereignPrefix(0, 0, 'abcd'), /digest/,
    'short digest hex should throw');
  for (const badSeq of [1.5, -2, -1n]) {
    assert.throws(() => guardOp.setSovereignPrefix(0, badSeq, '0'.repeat(64)),
      /seq must be/, `seq ${badSeq} should throw`);
  }
  guardOp.destroy();

  // Link 1: fresh chain, seq 0, all-zero digest — signed and executed. The
  // digest may also arrive as 32 raw bytes (wasm-only form).
  const firstAdjust = await Operation.create('adjust');
  firstAdjust.signerId = 'leader';
  firstAdjust.addResource('ledger');
  firstAdjust.setSovereignPrefix(0, 0n, ZERO_DIGEST);
  node.sign(firstAdjust, leaderKey);
  const firstWire = firstAdjust.serialize();
  node.execute(firstAdjust);
  firstAdjust.destroy();

  // Anyone can read the live head; the second link must claim it.
  const head = node.itemChainHead('ledger');
  assert(head.seq === 1n || head.seq === 1, 'head seq should advance to 1');
  assert.match(head.digestHex, /^[0-9a-f]{64}$/,
    'head digest should be a full 32-byte hex string');

  const secondAdjust = await Operation.create('adjust');
  secondAdjust.signerId = 'leader';
  secondAdjust.addResource('ledger');
  secondAdjust.setSovereignPrefix(0, head.seq, head.digestHex);
  node.sign(secondAdjust, leaderKey);
  node.execute(secondAdjust);
  secondAdjust.destroy();
  assert.strictEqual(node.itemChainHead('ledger').seq === 2n ? 2 : node.itemChainHead('ledger').seq, 2,
    'head seq should advance to 2 after the second link');

  // Sovereignty outranks policy: a role-authorized member is still refused.
  const rogue = await Operation.create('adjust');
  rogue.signerId = 'member';
  rogue.addResource('ledger');
  rogue.setSovereignPrefix(0, 1, ZERO_DIGEST);
  node.sign(rogue, memberKey);
  assert.throws(() => node.execute(rogue), /not_item_writer/,
    'a non-writer op on a sovereign item should throw not_item_writer');
  rogue.destroy();

  // Accountability: a genuine fork — a SECOND leader-signed claim to the
  // head the first op claimed, minted fresh (random uuid) so the wire bytes
  // are provably distinct. The report quarantines the leader.
  const fork = await Operation.create('adjust');
  fork.signerId = 'leader';
  fork.addResource('ledger');
  fork.setSovereignPrefix(0, 0n, ZERO_DIGEST);
  node.sign(fork, leaderKey);
  const forkWire = fork.serialize();
  fork.destroy();
  assert.notDeepStrictEqual(Buffer.from(firstWire), Buffer.from(forkWire),
    'fork evidence must be two distinct serialized ops');

  node.reportEquivocation('ledger', firstWire, forkWire);

  const afterQuarantine = await Operation.create('adjust');
  afterQuarantine.signerId = 'leader';
  afterQuarantine.addResource('ledger');
  afterQuarantine.setSovereignPrefix(0, 1, ZERO_DIGEST);
  node.sign(afterQuarantine, leaderKey);
  assert.throws(() => node.execute(afterQuarantine), /quarantined/,
    'a quarantined writer op should throw quarantined');
  afterQuarantine.destroy();

  // Failure paths are typed and set nothing.
  assert.throws(() => node.reportEquivocation('ledger', firstWire, firstWire),
    /invalid_param/, 'same-op-twice evidence is invalid');
  assert.throws(() => node.reportEquivocation('free-counter', firstWire, forkWire),
    /invalid_param/, 'a free-merge target is not a sovereign-chain item');
  assert.throws(() => node.reportEquivocation('ghost', firstWire, forkWire),
    /resource_not_found/, 'an unknown item is resource_not_found');
  assert.throws(() => node.reportEquivocation('ledger', forkWire, firstWire),
    /duplicate_operation/, 'a re-report of the same conviction dedupes');

  node.destroy();
  console.log('private-but-accountable wasm OK: chained leader ops, non-writer refused, fork quarantined');
}

main().catch((failure) => {
  console.error('private-but-accountable wasm FAILED:', failure);
  process.exit(1);
});