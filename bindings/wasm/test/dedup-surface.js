'use strict';
// dedup-surface.js — the DedupSpec op-type registration surface
// (Node.defineOperationType) backed by the machine registry:
//   - C truth: state_machine_op_define_operation (src/StateMachine/
//     state_machine.c) copies op->dedup into the registry via
//     state_register_op_type_def (src/CRABS/data_model.c); the executor
//     resolves specs via state_find_op_type_def, so a registered spec
//     guards user ops regardless of what the op carries on the wire (F-2).
//   - The registry overwrite rule: re-defining the same op type REPLACES
//     its spec in place (data_model.c first-match update), including a
//     'none' redefinition that disables the guard.

const { Node, KeyPair, Operation } = require('..');

(async () => {
  const node = await Node.create('admin', { ordering: 'hlc' });
  const adminId = 'admin';

  // Signed-op installation needs the define type's own policy — the
  // bootstrap admin holds role:admin, mirroring the __create_trigger__
  // wiring (cookbook/snippets/wasm/06-moderation.js).
  node.setPolicy('__define_operation_type__', 'role:admin');

  // ---------- PER_USER: one vote per member ----------
  const aliceKey = await KeyPair.generate();
  node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', adminId);

  const bobKey = await KeyPair.generate();
  node.registerUser('bob', bobKey.publicKeyHex(), 'adult');
  node.grantRole('bob', 'role', 'member', adminId);

  // The once-record (tracker) and the tallies. The tracker must exist: the
  // executor validates the spec's mutation target BEFORE the handler runs
  // (dedup_validate_mutation_spec, R8-S-3), and dedup_check_guard_spec
  // reads it (tracker_not_found otherwise).
  node.addOneShotSet('proposal-42_voters');
  node.addCounter('proposal-42_voted_yea');
  node.addCounter('proposal-42_voted_nay');

  node.setPolicy('vote', 'role:member');
  // Real machine enforcement: the registered spec guards BEFORE the handler.
  // The handler only tallies — no handler-level setContains emulation.
  node.registerHandlerJs('vote', (state, op) => {
    state.incrementCounter(`proposal-42_voted_${op.payload}`, 1, op.signerId);
    return 0;
  });

  node.defineOperationType('vote', {
    dedup: 'per-user',
    trackerPath: 'proposal-42_voters',
    rejectionMessage: 'already_performed',
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

  // The op carries dedup=NONE (the F-2 bypass shape): the registered spec
  // wins over the wire.
  await castVote(aliceKey, 'alice', 'yea');
  await castVote(bobKey, 'bob', 'nay');
  if (node.getCounter('proposal-42_voted_yea') !== 1 ||
      node.getCounter('proposal-42_voted_nay') !== 1) {
    throw new Error('both first votes must land and tally');
  }

  // Alice's retry: refused inside the machine with the dedup domain error,
  // tally untouched.
  let doubleVoteRefused = false;
  try {
    await castVote(aliceKey, 'alice', 'yea');
  } catch (retryError) {
    doubleVoteRefused = retryError.message.includes('already_performed');
  }
  if (!doubleVoteRefused) {
    throw new Error('a second vote from the same signer must be refused');
  }
  if (node.getCounter('proposal-42_voted_yea') !== 1) {
    throw new Error('the refused retry must not touch the tally');
  }

  // ---------- GLOBAL: execute once, ever (recipe 3's real guard) ----------
  node.addOneShotFlag('closeout_done');
  node.setPolicy('closeout', 'role:member');
  // No handler at all: the GLOBAL spec's guard + apply ARE the whole
  // behavior — the op names the flag item as its resource so the executor
  // has something to resolve, and the post-handler mutation sets the flag.
  node.defineOperationType('closeout', {
    dedup: 'global',
    flagPath: 'closeout_done',
    rejectionMessage: 'already_executed',
  });

  const executeCloseout = async (subjectKey, signer) => {
    const op = await Operation.create('closeout');
    op.signerId = signer;
    op.nodeId = signer;
    op.addResource('closeout_done');
    node.sign(op, subjectKey.privateKeyHex());
    node.execute(op);
    op.destroy();
  };

  await executeCloseout(aliceKey, 'alice');
  if (!node.flagValue('closeout_done')) {
    throw new Error('the first closeout must set the flag');
  }
  let rerunRefused = false;
  try {
    await executeCloseout(aliceKey, 'alice');
  } catch (rerunError) {
    rerunRefused = rerunError.message.includes('already_executed');
  }
  if (!rerunRefused) {
    throw new Error('a second closeout must be refused');
  }
  let otherRerunRefused = false;
  try {
    await executeCloseout(bobKey, 'bob');
  } catch (otherError) {
    otherRerunRefused = otherError.message.includes('already_executed');
  }
  if (!otherRerunRefused) {
    throw new Error('a GLOBAL spec refuses every signer after the first run');
  }

  // ---------- NONE + registry overwrite semantics ----------
  node.addOneShotSet('boosters');
  node.setPolicy('boost', 'role:member');
  node.registerHandlerJs('boost', () => { return 0; });
  node.defineOperationType('boost', { dedup: 'per-user', trackerPath: 'boosters' });

  const castBoost = async (key, booster) => {
    const op = await Operation.create('boost');
    op.signerId = booster;
    op.nodeId = booster;
    node.sign(op, key.privateKeyHex());
    node.execute(op);
    op.destroy();
  };

  await castBoost(aliceKey, 'alice');
  let secondBoostRefused = false;
  try {
    await castBoost(aliceKey, 'alice');
  } catch (againError) {
    secondBoostRefused = againError.message.includes('already_performed');
  }
  if (!secondBoostRefused) {
    throw new Error('per-user boost must refuse the second call');
  }

  // Re-defining the same op type REPLACES its spec in place
  // (state_register_op_type_def first-match update): a 'none' definition
  // disables the guard. Carried specs are rejected when NO spec is
  // registered for the type, and ignored whenever ANY spec is registered —
  // including NONE (the seal) — so the executor never consults a
  // signer-authored spec.
  node.defineOperationType('boost', { dedup: 'none' });
  await castBoost(aliceKey, 'alice');  // the previously-refused second call now passes

  // Malformed registrations must fail closed at the binding surface.
  const badDedupWord = () => {
    try {
      node.defineOperationType('x1', { dedup: 'sometimes' });
    } catch (wordError) {
      return wordError.message.includes('dedup');
    }
    return false;
  };
  if (!badDedupWord()) {
    throw new Error('an unknown dedup word must be rejected');
  }
  const missingTracker = () => {
    try {
      node.defineOperationType('x2', { dedup: 'per-user' });
    } catch (pathError) {
      return pathError.message.includes('trackerPath');
    }
    return false;
  };
  if (!missingTracker()) {
    throw new Error("per-user without trackerPath must be rejected");
  }
  const customRefused = () => {
    try {
      node.defineOperationType('x3', { dedup: 'custom', condition: 'true' });
    } catch (customError) {
      return customError.message.includes('custom');
    }
    return false;
  };
  if (!customRefused()) {
    throw new Error("the 'custom' shape is not surfaceable from JS (mutation field is C-native); must be rejected");
  }

  console.log('dedup-surface OK: per-user/global specs enforced, registry overwrite + none seal verified');
  node.destroy();
  aliceKey.destroy();
  bobKey.destroy();
})()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });