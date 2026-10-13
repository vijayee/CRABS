'use strict';
// Recipe 2 — one vote per member (crabs-node, driven directly).
// No custom-handler surface exists on crabs-node, but none is needed: the
// once-rule is REGISTRED on the machine with defineOperationType (a
// node-key-signed '__define_operation_type__' op installs a DedupSpec) and
// the executor resolves it for every signed 'vote' op. The vote op names
// the tracker as its resource; the spec's guard refuses a second vote from
// the same signer and the spec's own mutation records the vote — no
// driver-side check anywhere.

const { Node, KeyPair, Operation } = require('../../../bindings/node');

const node = new Node('node-1', { ordering: 'hlc' });

const aliceKey = KeyPair.generate();
node.registerUser('alice', aliceKey.publicKeyHex(), '');
node.grantRole('alice', 'role', 'member', 'node-1');

const bobKey = KeyPair.generate();
node.registerUser('bob', bobKey.publicKeyHex(), '');
node.grantRole('bob', 'role', 'member', 'node-1');

// The once-record. The tracker must exist BEFORE the spec is used — the
// executor validates the spec's target item before any handler.
node.addOneShotSet('proposal-42_voters');

// Installing the spec is a signed op under the machine's admin; the vote
// op type gets its own policy.
node.setPolicy('__define_operation_type__', 'role:admin');
node.setPolicy('vote', 'role:member');

node.defineOperationType('vote', {
  dedup: 'per-user',
  trackerPath: 'proposal-42_voters',
  rejectionMessage: 'already_performed',
});

const castVote = (key, voter) => {
  const op = new Operation('vote');
  op.signerId = voter;
  op.addResource('proposal-42_voters');  // the once-record the op touches
  node.sign(op, key);
  node.execute(op);
};

castVote(aliceKey, 'alice');
castVote(bobKey, 'bob');
if (!node.setContains('proposal-42_voters', 'alice') ||
    !node.setContains('proposal-42_voters', 'bob')) {
  throw new Error('the registered spec must record both members as voted');
}

// The same vote, replayed: refused inside the machine by the registered
// spec (the op itself carries no dedup spec — the registered spec wins over
// anything the wire could carry), so a stale client or a delivery retry
// cannot manufacture a second membership.
let doubleVoteRejected = false;
try {
  castVote(aliceKey, 'alice');
} catch (retryError) {
  doubleVoteRejected = retryError.message.includes('already_performed');
}
if (!doubleVoteRejected) {
  throw new Error('a second vote from the same signer must be rejected');
}
if (!node.setContains('proposal-42_voters', 'alice') ||
    node.setContains('proposal-42_voters', 'carol')) {
  throw new Error('the refused retry must not change membership');
}

console.log('one-vote OK: alice+bob recorded, alice retry rejected');
// Node/KeyPair expose no destroy() — native cleanup is process-exit driven.