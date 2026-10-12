'use strict';
// Recipe 2 — one vote per member (crabs-wasm, run in Node).
// The once-record is a ONE_SHOT_SET item (additive, idempotent, cannot
// un-vote); the tallies are per-option G-counters. The guard runs inside the
// machine as a custom handler: a second vote op from the same signer is
// rejected before any mutation lands.

const { Node, KeyPair, Operation } = require('../../../bindings/wasm');

const ALREADY_PERFORMED = 0x7001; // CRABS_ERR_ALREADY_PERFORMED (src/CRABS/crabs.h:106)

async function main() {
  const node = await Node.create('admin', { ordering: 'hlc' });
  const adminId = 'admin';

  const aliceKey = await KeyPair.generate();
  node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', adminId);

  const bobKey = await KeyPair.generate();
  node.registerUser('bob', bobKey.publicKeyHex(), 'adult');
  node.grantRole('bob', 'role', 'member', adminId);

  // The once-record: who has voted.
  node.addOneShotSet('proposal-42_voters');
  // The tallies: one counter per option, attributed per voter by the handler.
  node.addCounter('proposal-42_voted_yea');
  node.addCounter('proposal-42_voted_nay');

  // Anyone who can sign and satisfies the policy may call the vote op.
  node.setPolicy('vote', 'role:member');
  // The handler reads the chosen option from the op payload. String payloads
  // are surfaced to handlers only when null-terminated (see
  // crabs_wasm_handler_op_get_payload_str), so the option travels with a NUL.
  node.registerHandlerJs('vote', (state, op) => {
    if (state.setContains('proposal-42_voters', op.signerId)) {
      return ALREADY_PERFORMED;
    }
    state.setAdd('proposal-42_voters', op.signerId);
    state.incrementCounter(`proposal-42_voted_${op.payload}`, 1, op.signerId);
    return 0;
  });

  const castVote = async (key, voter, option) => {
    const op = await Operation.create('vote');
    op.signerId = voter;
    op.nodeId = voter;
    op.payload = option + '\0';
    node.sign(op, key.privateKeyHex());
    node.execute(op);
    op.destroy();
  };

  await castVote(aliceKey, 'alice', 'yea');
  await castVote(bobKey, 'bob', 'nay');
  if (node.getCounter('proposal-42_voted_yea') !== 1) {
    throw new Error(`expected yea=1, got ${node.getCounter('proposal-42_voted_yea')}`);
  }
  if (node.getCounter('proposal-42_voted_nay') !== 1) {
    throw new Error(`expected nay=1, got ${node.getCounter('proposal-42_voted_nay')}`);
  }

  // The same vote, replayed (retry, refresh, or a second device operating on
  // a stale view): rejected inside the machine, tally untouched.
  let doubleVoteRejected = false;
  try {
    await castVote(aliceKey, 'alice', 'yea');
  } catch (retryError) {
    doubleVoteRejected = retryError.message.includes('already_performed');
  }
  if (!doubleVoteRejected) {
    throw new Error('a second vote from the same signer must be rejected');
  }
  if (node.getCounter('proposal-42_voted_yea') !== 1) {
    throw new Error(`retry must not change the tally, got ${node.getCounter('proposal-42_voted_yea')}`);
  }

  console.log('one-vote OK: yea=1, nay=1, alice retry rejected');
  node.destroy();
  aliceKey.destroy();
  bobKey.destroy();
}
main()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });