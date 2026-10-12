'use strict';
// Recipe 13 — a personal ledger no one can override (crabs-node).
//
// Each member mints their own sovereign ledger item: one named writer, ops
// hash-chained through signed sovereign prefixes. Nobody else — not another
// member, NOT EVEN THE MACHINE'S OWN ADMIN, not a policy-authorized signer —
// can write someone else's ledger (not_item_writer); a stale prefix is
// seq_mismatch; the same seq claimed with a different digest is
// fork_detected at the gate, before anything is applied. Mirrors the
// sovereign sections of bindings/node/test/test.js:380-540.

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../../../bindings/node');

const node = new Node('machine-1', { ordering: 'hlc' });

// The members (and their keys) — the machine's admin is a separate party.
const aliceKey = KeyPair.generate();
node.registerUser('alice', aliceKey.publicKeyHex(), '');
node.grantRole('alice', 'role', 'member', 'machine-1');
const bobKey = KeyPair.generate();
node.registerUser('bob', bobKey.publicKeyHex(), '');
node.grantRole('bob', 'role', 'member', 'machine-1');

// ---- The mint: one sovereign ledger per member ----------------------------
// The domain is declared at mint and immutable on a live item; the writer is
// mandatory and fixed. (v1 legal sovereign shapes: counter and register.)
node.defineItem('ledger-alice', 'counter', 'g_counter',
  { domain: 'sovereign', writer: 'alice' });
node.defineItem('ledger-bob', 'counter', 'g_counter',
  { domain: 'sovereign', writer: 'bob' });
// Same policy authorizes the op type for everyone — sovereignty, not the
// policy, decides who may write WHICH item.
node.setPolicy('entry', 'role:member');

const ZERO_DIGEST = '0'.repeat(64);
const FORK_DIGEST = 'f'.repeat(64);   // a digest that is NOT the live head

// A member's chained deposit: claim the item's live chain head in a SIGNED
// prefix (the signature binds it), so every accepted entry is one position
// in one hash-chained sequence.
function depositAs(signerId, signerKey, ledgerName, seq, digestHex) {
  const entry = new Operation('entry');
  entry.signerId = signerId;
  entry.addResource(ledgerName);
  entry.setSovereignPrefix(0, seq, digestHex);
  node.sign(entry, signerKey);
  return entry;
}

// Alice's first two entries land: chain head advances per accepted op.
node.execute(depositAs('alice', aliceKey, 'ledger-alice', 0, ZERO_DIGEST));
let head = node.itemChainHead('ledger-alice');
assert(head.seq === 1, `head should advance to 1, got ${head.seq}`);
assert(/^[0-9a-f]{64}$/.test(head.digestHex),
  'head digest should be a full 32-byte hex string');

const secondEntry = depositAs('alice', aliceKey, 'ledger-alice',
                              head.seq, head.digestHex);
node.execute(secondEntry);
assert(node.itemChainHead('ledger-alice').seq === 2,
  'head should advance to 2');

// Bob's ledger is bob's: the same op shape lands on his item, chain
// independent of alice's.
node.execute(depositAs('bob', bobKey, 'ledger-bob', 0, ZERO_DIGEST));
assert(node.itemChainHead('ledger-bob').seq === 1, "bob's chain advances");
assert(node.itemChainHead('ledger-alice').seq === 2, "chains are per item");

// ---- Nobody else — including the machine's own admin — can write it ------
// The admin id is NOT alice and holds no item exception: a machine-signed
// admin attempt at alice's ledger is refused not_item_writer (sovereignty
// outranks policy: the policy would authorize the op type, the item decides
// the writer).
const adminKey = KeyPair.generate();
node.registerUser('admin', adminKey.publicKeyHex(), '');
node.grantRole('admin', 'role', 'member', 'machine-1');
try {
  node.execute(depositAs('admin', adminKey, 'ledger-alice', 2,
                         node.itemChainHead('ledger-alice').digestHex));
  throw new Error("the admin's op on alice's ledger must be refused");
} catch (refusal) {
  assert(refusal.message.includes('not_item_writer'),
    `expected not_item_writer, got: ${refusal.message}`);
}
assert(node.itemChainHead('ledger-alice').seq === 2,
  'a refused write moves no chain');

// The same holds bob→alice: membership is not a write right to a foreign
// ledger.
try {
  node.execute(depositAs('bob', bobKey, 'ledger-alice', 2,
                         node.itemChainHead('ledger-alice').digestHex));
  throw new Error("bob's op on alice's ledger must be refused");
} catch (refusal) {
  assert(refusal.message.includes('not_item_writer'),
    `expected not_item_writer, got: ${refusal.message}`);
}

// ---- The chain refuses stale and forked claims ---------------------------
// Stale: replaying alice's FIRST link (seq 0) when the chain is at 2.
try {
  node.execute(depositAs('alice', aliceKey, 'ledger-alice', 0, ZERO_DIGEST));
  throw new Error('a replayed prefix must be refused');
} catch (refusal) {
  assert(refusal.message.includes('seq_mismatch'),
    `expected seq_mismatch, got: ${refusal.message}`);
}

// Fork at the gate: the SAME seq alice is at, claimed with a DIFFERENT
// digest — the engine refuses before any mutation (nothing to quarantine
// yet: this is the gate-level refusal, the report path needs the two
// payloads).
try {
  node.execute(depositAs('alice', aliceKey, 'ledger-alice', 2, FORK_DIGEST));
  throw new Error('a same-seq different-digest claim must be refused');
} catch (refusal) {
  assert(refusal.message.includes('fork_detected'),
    `expected fork_detected, got: ${refusal.message}`);
}
assert(node.itemChainHead('ledger-alice').seq === 2,
  'a fork-refused write moves no chain');

// A member CAN rewrite their own ledger's future only by chaining the live
// head, the honest way — the third entry proves alice still writes hers.
node.execute(depositAs('alice', aliceKey, 'ledger-alice', 2,
                       node.itemChainHead('ledger-alice').digestHex));
assert(node.itemChainHead('ledger-alice').seq === 3,
  'the writer keeps chaining');

console.log('sovereign-ledger OK: per-user chains, admin and member' +
  ' refusals, stale and fork refusals');
// Node/KeyPair expose no destroy() — native cleanup is process-exit driven.