'use strict';
// Recipe 5 — a member's own profile, numeric half (crabs-node, driven directly).
// crabs-node maps registers as NUMBERS ONLY (bindings/node/index.d.ts:227-234
// — the full int64 range and the byte-register API live on crabs-wasm), so
// the profile half this binding can carry honestly is a signed integer field
// (karma, level, quota): one register per member, newest write wins.

const { Node, KeyPair } = require('../../../bindings/node');

const node = new Node('node-1', { ordering: 'hlc' });

const aliceKey = KeyPair.generate();
node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
node.grantRole('alice', 'role', 'member', 'node-1');

const bobKey = KeyPair.generate();
node.registerUser('bob', bobKey.publicKeyHex(), 'adult');
node.grantRole('bob', 'role', 'member', 'node-1');

// keyVersion: registration starts the key's epoch at 1
// (attribute_machine.c:495) and every role grant bumps it (the
// sign-path staleness gate R7-04 reads this number,
// src/Attribute/attribute_machine.c:597,617).
for (const member of ['alice', 'bob']) {
  if (node.getUser(member).keyVersion !== 2) {
    throw new Error(`${member} keyVersion must be 2 after one grant, got ${node.getUser(member).keyVersion}`);
  }
}

node.addRegister('profile_karma_alice', 0);
node.addRegister('profile_karma_bob', 0);

// Each member controls their own register; the key they registered with is
// the thing key_version will track when keys rotate (JS-visible on the user
// record, bindings/node/index.d.ts:53; rotation itself is C-only).
const setKarma = (member, karma) => {
  node.setRegister(`profile_karma_${member}`, karma, member);
};

setKarma('alice', 12);
setKarma('bob', 3);

if (node.getRegister('profile_karma_alice') !== 12) {
  throw new Error(`expected alice karma=12, got ${node.getRegister('profile_karma_alice')}`);
}
if (node.getRegister('profile_karma_bob') !== 3) {
  throw new Error(`expected bob karma=3, got ${node.getRegister('profile_karma_bob')}`);
}

// Registers are integer-only int64 slots: fractional, NaN, Infinity, and —
// on this binding — BigInt are refused BEFORE the C int64 can silently
// truncate (node d.ts:227-234; mirrors bindings/node/test/test.js:555-578).
const mustReject = (invoke, fragment, label) => {
  let refused = null;
  try { invoke(); } catch (refusal) { refused = String(refusal.message); }
  if (!refused || !refused.includes(fragment)) {
    throw new Error(`${label}: expected refusal containing "${fragment}", got "${refused}"`);
  }
};
mustReject(() => setKarma('alice', 1.5), 'registers are integer-only', 'fractional 1.5');
mustReject(() => setKarma('alice', NaN), 'registers are integer-only', 'NaN');

// LWW: the newest write wins...
setKarma('alice', 15);
if (node.getRegister('profile_karma_alice') !== 15) {
  throw new Error(`latest write must win, got ${node.getRegister('profile_karma_alice')}`);
}

// ...and the register stays inside the int64 the C struct carries
// (lww_register_t's payload, src/CRDT/crdt_merge.h:94-99).
setKarma('alice', Number.MAX_SAFE_INTEGER);
if (node.getRegister('profile_karma_alice') !== Number.MAX_SAFE_INTEGER) {
  throw new Error('MAX_SAFE_INTEGER must round-trip');
}

console.log('profile OK: per-member int64 registers round-trip, latest write wins');
// Node/KeyPair expose no destroy() — native cleanup is process-exit driven.