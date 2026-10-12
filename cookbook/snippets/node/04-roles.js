'use strict';
// Recipe 4 — roles and who-can-do-what (crabs-node, signed ops).
// crabs-node has no custom-handler surface, so a policy-gated custom op
// passes authorization and then fails closed with resource_not_found —
// which is exactly what lets us watch the authorization gate itself:
// member + adult -> authorization PASSES (resource_not_found, the next
// gate), member without adult -> refused with condition-side typed error.

const { Node, KeyPair, Operation } = require('../../../bindings/node');

const node = new Node('admin', { ordering: 'hlc' });

// Registering with a privileged attribute name is refused (audit R7-08);
// membership is an unprivileged fact plus an admin-granted role.
const aliceKey = KeyPair.generate();
node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
node.grantRole('alice', 'role', 'member', 'admin');

const malloryKey = KeyPair.generate();
node.registerUser('mallory', malloryKey.publicKeyHex(), '');
node.grantRole('mallory', 'role', 'member', 'admin'); // member but not adult

const alice = node.getUser('alice');
if (!alice.attributes.some((attribute) => attribute.value === 'role:member') ||
    !alice.attributes.some((attribute) => attribute.value === 'adult')) {
  throw new Error(`expected role:member and adult on alice, got ${JSON.stringify(alice.attributes)}`);
}
if (alice.attributes.find((attribute) => attribute.value === 'role:member').verifiedBy !== 'admin') {
  throw new Error('the role attribute must show admin provenance');
}

node.setPolicy('post', 'AND role:member adult');

// Alice satisfies every clause: the op gets THROUGH authorization. The
// next gate then refuses 'post' as resource_not_found (no handler is
// registered for it on this binding — see the wasm snippet for the
// handler-equipped version).
const aliceOp = new Operation('post');
aliceOp.signerId = 'alice';
node.sign(aliceOp, aliceKey);
let aliceAuthorized = false;
try {
  node.execute(aliceOp);
} catch (aliceRefusal) {
  aliceAuthorized = aliceRefusal.message.includes('resource_not_found');
}
if (!aliceAuthorized) {
  throw new Error('a member op must pass authorization (and then hit the no-handler gate)');
}

// Mallory fails authorization itself — a typed refusal ('unauthorized' is
// what this machine emits for a clause that does not hold; the dedicated
// condition_not_met code exists for trigger/dedup conditions) that precedes
// any effect.
const malloryOp = new Operation('post');
malloryOp.signerId = 'mallory';
node.sign(malloryOp, malloryKey);
let malloryRefused = '';
try {
  node.execute(malloryOp);
} catch (malloryError) {
  malloryRefused = String(malloryError.message);
}
if (!malloryRefused.includes('unauthorized')) {
  throw new Error(`an op missing a policy clause must be refused, got "${malloryRefused}"`);
}

// Privilege escalation over the self-assert channel is refused too.
node.selfAssert('nickname', 'Alice', 'alice');
const withNickname = node.getUser('alice');
if (!withNickname.attributes.some((attribute) => attribute.value === 'nickname:Alice')) {
  throw new Error('selfAssert must record the unprivileged nickname');
}
let selfRoleRefused = false;
try {
  node.selfAssert('role', 'admin', 'alice');
} catch (escalation) {
  selfRoleRefused = String(escalation.message).includes('unauthorized') ||
                    String(escalation.message).includes('invalid_param');
}
if (!selfRoleRefused) {
  throw new Error('selfAssert with a privileged attribute name must fail');
}

console.log('roles OK: member passes the gate, non-adult refused, self-grant refused');
// Node/KeyPair expose no destroy() — native cleanup is process-exit driven.