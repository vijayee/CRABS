'use strict';
// Recipe 2 — one vote per member (crabs-wasm, run in Node).
// The once-record is a ONE_SHOT_SET item (additive, idempotent, cannot
// un-vote); the tallies are per-option G-counters. The guard is REGISTERED on
// the machine: defineOperationType installs a DedupSpec for the 'vote' op
// type (state_register_op_type_def via a node-key-signed
// '__define_operation_type__' op) and the executor resolves it for every
// later vote op — registered specs win over anything the op carries on the
// wire, so no caller code can bypass or forget the rule.

const { Node, KeyPair, Operation } = require('../../../bindings/wasm');

async function main() {
  const node = await Node.create('admin', { ordering: 'hlc' });
  const adminId = 'admin';

  const aliceKey = await KeyPair.generate();
  node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', adminId);

  const bobKey = await KeyPair.generate();
  node.registerUser('bob', bobKey.publicKeyHex(), 'adult');
  node.grantRole('bob', 'role', 'member', adminId);

  // The once-record: who has voted. The tracker must exist BEFORE the spec
  // is used — the executor validates the spec's target item before any
  // handler runs (dedup_validate_mutation_spec).
  node.addOneShotSet('proposal-42_voters');
  // The tallies: one counter per option, attributed per voter by the handler.
  node.addCounter('proposal-42_voted_yea');
  node.addCounter('proposal-42_voted_nay');

  // Installing a registered spec is itself a signed op ('__define_operation_
  // type__') and needs its type's own policy — 'role:admin' puts the power
  // with the machine's bootstrap admin (the __create_trigger__ precedent).
  node.setPolicy('__define_operation_type__', 'role:admin');
  // Anyone who can sign and satisfies the policy may call the vote op.
  node.setPolicy('vote', 'role:member');

  node.defineOperationType('vote', {
    dedup: 'per-user',
    trackerPath: 'proposal-42_voters',
    rejectionMessage: 'already_performed',
  });

  // The handler only tallies. The GUARD is the machine's registered spec:
  // it runs before the handler, the spec's own mutation records membership
  // after a successful run, and a second vote from the same signer is
  // refused before any handler effect can land.
  node.registerHandlerJs('vote', (state, op) => {
    // String payloads are surfaced to handlers only when null-terminated
    // (see crabs_wasm_handler_op_get_payload_str), so the option travels
    // with a NUL.
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
  // The spec's own mutation recorded both votes in the tracker.
  if (!node.setContains('proposal-42_voters', 'alice') ||
      !node.setContains('proposal-42_voters', 'bob')) {
    throw new Error('the registered spec must record both voters');
  }

  // The same vote, replayed (retry, refresh, or a second device operating on
  // a stale view): refused inside the machine by the registered spec, tally
  // untouched.
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