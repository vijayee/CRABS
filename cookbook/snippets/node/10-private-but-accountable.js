'use strict';
// Recipe 10 — actions a leader takes that everyone can verify (crabs-node).
//
// The ledger item is SOVEREIGN: one named writer, whose ops are signed with
// a chain prefix (item_seq + previous digest) that the signature binds. The
// writer must claim the live chain head to be accepted (seq_mismatch /
// stale prefixes fail), a non-writer is refused even when policy-authorized,
// and two conflicting signed claims of the same head are fork evidence:
// a report quarantines the writer. Mirrors the node write-domains test
// (bindings/node/test/test.js:380-540).

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../../../bindings/node');

const node = new Node('node-1', { ordering: 'hlc' });

const leaderKey = KeyPair.generate();
node.registerUser('leader', leaderKey.publicKeyHex(), '');
node.grantRole('leader', 'role', 'member', 'node-1');

const memberKey = KeyPair.generate();
node.registerUser('member', memberKey.publicKeyHex(), '');
node.grantRole('member', 'role', 'member', 'node-1');

// The leader's ledger: single writer, hash-chained. The domain is declared
// at mint and is immutable on a live item.
node.defineItem('ledger', 'counter', 'g_counter',
  { domain: 'sovereign', writer: 'leader' });
node.addCounter('free-counter');
node.setPolicy('adjust', 'role:member');

const ZERO_DIGEST = '0'.repeat(64);

// Link 1: a fresh chain starts at seq 0 with the all-zero digest; the
// signed prefix claims that head. Digest arguments are exactly 64 hex chars.
const firstAdjust = new Operation('adjust');
firstAdjust.signerId = 'leader';
firstAdjust.addResource('ledger');
firstAdjust.setSovereignPrefix(0, 0, ZERO_DIGEST);
node.sign(firstAdjust, leaderKey);
const firstWire = Buffer.from(firstAdjust.serialize());
node.execute(firstAdjust);

// Accountability read: anyone can see the live chain head. seq advanced to
// 1 and the digest is a full recomputed 32-byte hex string.
const head = node.itemChainHead('ledger');
assert(head.seq === 1, 'head seq should advance to 1 after the first link');
assert(/^[0-9a-f]{64}$/.test(head.digestHex), 'head digest should be 64 hex chars');
assert.notStrictEqual(head.digestHex, ZERO_DIGEST,
  'head digest should be recomputed after the first op');
assert.throws(() => node.itemChainHead('ghost'), /resource_not_found/,
  'itemChainHead on an unknown item should throw resource_not_found');

// Link 2: the writer must claim the LIVE head — stale/duplicate seq claims
// are refused with seq_mismatch by the DOMAIN_CHECK.
const secondAdjust = new Operation('adjust');
secondAdjust.signerId = 'leader';
secondAdjust.addResource('ledger');
secondAdjust.setSovereignPrefix(0, head.seq, head.digestHex);
node.sign(secondAdjust, leaderKey);
node.execute(secondAdjust);
assert(node.itemChainHead('ledger').seq === 2,
  'head seq should advance to 2 after the second link');

// Sovereignty outranks policy: the member holds the authorizing role but is
// not the item's writer — the op is refused with not_item_writer.
const rogue = new Operation('adjust');
rogue.signerId = 'member';
rogue.addResource('ledger');
rogue.setSovereignPrefix(0, 1, ZERO_DIGEST);
node.sign(rogue, memberKey);
try {
  node.execute(rogue);
  throw new Error('a non-writer op on a sovereign item must be refused');
} catch (refusal) {
  assert(refusal.message.includes('not_item_writer'),
    `expected not_item_writer, got: ${refusal.message}`);
}

// Accountability: a genuine fork. The fork op is a SECOND leader-signed
// claim to the head the first op claimed (seq 0, zero digest) that never
// executed here — newly minted (random uuid), so its wire bytes differ.
const fork = new Operation('adjust');
fork.signerId = 'leader';
fork.addResource('ledger');
fork.setSovereignPrefix(0, 0, ZERO_DIGEST);
node.sign(fork, leaderKey);
const forkWire = Buffer.from(fork.serialize());
assert(Buffer.compare(firstWire, forkWire) !== 0,
  'fork evidence must be two distinct serialized ops');

// A report quarantines the leader on the item. The report is a machine op
// (`__report_equivocation__`), submitted through the node's own sign path
// and policy-guarded.
node.setPolicy('__report_equivocation__', 'role:admin');
node.reportEquivocation('ledger', firstWire, forkWire);

// The quarantined writer's NEXT op is refused — even a fresh leader-signed
// claim carrying the item's own (now stale) head.
const afterQuarantine = new Operation('adjust');
afterQuarantine.signerId = 'leader';
afterQuarantine.addResource('ledger');
afterQuarantine.setSovereignPrefix(0, 1, ZERO_DIGEST);
node.sign(afterQuarantine, leaderKey);
try {
  node.execute(afterQuarantine);
  throw new Error('a quarantined writer op must be refused');
} catch (refusal) {
  assert(refusal.message.includes('quarantined'),
    `expected quarantined, got: ${refusal.message}`);
}

// Failure paths of a report are typed — and set nothing.
assert.throws(() => node.reportEquivocation('ledger', firstWire, firstWire),
  /invalid_param/, 'same-op-twice evidence is invalid');
assert.throws(() => node.reportEquivocation('free-counter', firstWire, forkWire),
  /invalid_param/, 'a free-merge target is not a sovereign-chain item');
assert.throws(() => node.reportEquivocation('ghost', firstWire, forkWire),
  /resource_not_found/, 'an unknown item is resource_not_found');
assert.throws(() => node.reportEquivocation('ledger', forkWire, firstWire),
  /duplicate_operation/, 'a re-report of the same conviction dedupes');

console.log('private-but-accountable OK: chained leader ops, non-writer refused, fork quarantined');
// Node/KeyPair expose no destroy() — native cleanup is process-exit driven.