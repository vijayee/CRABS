'use strict';
// Recipe 2 — one vote per member (crabs-node, driven directly).
// The node binding has no custom-handler surface, so there is no execute-time
// guard to attach to a "vote" op — the once-record is enforced by the caller,
// not by the machine. What the machine itself guarantees here is that the
// ONE_SHOT_SET absorbs re-attempts idempotently and cannot be un-voted.

const { Node, KeyPair } = require('../../../bindings/node');

const node = new Node('node-1', { ordering: 'hlc' });

const aliceKey = KeyPair.generate();
node.registerUser('alice', aliceKey.publicKeyHex(), '');
node.grantRole('alice', 'role', 'member', 'node-1');

const bobKey = KeyPair.generate();
node.registerUser('bob', bobKey.publicKeyHex(), '');
node.grantRole('bob', 'role', 'member', 'node-1');

node.addOneShotSet('proposal-42_voters');
node.addCounter('proposal-42_votes');

// cast() checks the once-record, records the member, then bumps the tally.
// On crabs-node this is driver discipline; the machine cannot review it.
const castVote = (voter) => {
  if (node.setContains('proposal-42_voters', voter)) {
    throw new Error(`${voter} already voted`);
  }
  node.setAdd('proposal-42_voters', voter);
  node.incrementCounter('proposal-42_votes', 1, voter);
};

castVote('alice');
castVote('bob');

if (!node.setContains('proposal-42_voters', 'alice') ||
    !node.setContains('proposal-42_voters', 'bob')) {
  throw new Error('both members must be recorded as voted');
}
if (node.getCounter('proposal-42_votes') !== 2) {
  throw new Error(`expected votes=2, got ${node.getCounter('proposal-42_votes')}`);
}

// A replayed cast() from the same member is absorbed: the set add is
// idempotent in C (one_shot_set_add), so a stale client or a delivery retry
// that reaches cast() again cannot manufacture a second membership.
const beforeVotes = node.getCounter('proposal-42_votes');
let replayRejected = false;
try {
  castVote('alice');
} catch (replayError) {
  replayRejected = replayError.message.includes('already voted');
}
if (!replayRejected) {
  throw new Error('the replay of a recorded vote must be refused by the check');
}
if (node.getCounter('proposal-42_votes') !== beforeVotes) {
  throw new Error('replay must not touch the tally');
}

console.log('one-vote OK: alice+bob recorded, replay refused');
// Node/KeyPair expose no destroy() — native cleanup is process-exit driven.