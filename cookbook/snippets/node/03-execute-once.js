'use strict';
// Recipe 3 — execute once, ever (crabs-node, driven directly).
// No custom-handler surface on crabs-node, so an execute-time guard cannot
// be attached to an op. What the machine itself guarantees is the flag:
// false -> true exactly once, idempotent re-set, and (as the C core shows)
// merge keeps the FIRST setter — but the JS surface cannot read set_by.

const { Node, KeyPair, Operation } = require('../../../bindings/node');

const node = new Node('node-1', { ordering: 'hlc' });

const keeperKey = KeyPair.generate();
node.registerUser('keeper', keeperKey.publicKeyHex(), '');
node.grantRole('keeper', 'role', 'member', 'node-1');

node.addOneShotFlag('closeout_done');
if (node.flagValue('closeout_done')) {
  throw new Error('a fresh one-shot flag must read false');
}

// Raise the flag once...
node.flagSet('closeout_done', 'keeper', 1000);
if (!node.flagValue('closeout_done')) {
  throw new Error('flagSet must transition the flag to true');
}

// ...and set it again with a DIFFERENT setter and timestamp — the second
// set is a no-op in C (one_shot_flag_set exits early once the value is
// true, test/test_one_shot.cpp:186-201). The boolean cannot be re-fought
// over, and there is no un-set: flagSet has no false transition.
node.flagSet('closeout_done', 'later-comer', 2000);
if (!node.flagValue('closeout_done')) {
  throw new Error('a one-shot flag must not be unsettable');
}

// Who raised it is invisible from JS (the C struct carries set_by/set_at,
// src/CRDT/one_shot.h:37-41, but neither binding maps those reads) — which
// is why a policy-grade "executed once, by whom" story lives in the C snippet.
console.log('execute-once OK: flag transitions once, stays true');
// Node/KeyPair expose no destroy() — native cleanup is process-exit driven.