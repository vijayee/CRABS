'use strict';
// Recipe 6 — progressive disclosure moderation (crabs-node, driven directly).
// crabs-node has createTrigger + encrypt but NO custom-handler surface
// (api-map §7, §8 — deliberate). The counter is driver-written and the
// trigger's post-execute pass runs whenever a LANDING op executes — here a
// resource-carrying custom op whose wildcard path applies nothing. (Node
// also gained the DIRECT `evaluateTriggers()` tick in parity-fill P10 —
// this snippet pins the op-driven tick instead: both feed the same C pass.)

const { Node, KeyPair, Operation } = require('../../../bindings/node');

// The admin id is deliberately NOT 'admin': createTrigger signs with the
// machine's real admin identity (the id the node key is registered under),
// so any admin name works — this pins that property.
const ADMIN = 'chair';
const node = new Node(ADMIN, { ordering: 'hlc' });

const aliceKey = KeyPair.generate();
node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
node.grantRole('alice', 'role', 'member', ADMIN);

// Threshold item + gated action, as on crabs-wasm. The counter is written
// by the DRIVER here (no registerHandlerJs on this binding — the landed
// contract is the same one recipe 2's node half documents).
node.addCounter('abuse_reports');
node.addCounter('contact_reads');

// The trigger install is itself a signed '__create_trigger__' op — give the
// type its policy ('role:admin', the bootstrap admin holds it).
node.setPolicy('__create_trigger__', 'role:admin');

node.createTrigger({
  triggerId: 'clearance_gateway',
  condition: 'abuse_reports >= 3',
  description: 'issue verifier clearance when 3 abuse reports accumulated',
  effectType: 'issue_attribute',
  issueAttribute: 'clearance',
  targetRole: 'role',
  attributeValue: 'moderator',
  durationMs: 600000,
  oneShot: false,
  cooldownMs: 60000,
});

const triggerEvents = [];
const contactReadEvents = [];
node.on('change', (event) => {
  if (event.kind === 'trigger') triggerEvents.push(event);
  // Refused ops stream as op-kind events too (with a nonzero result), so
  // "the op landed" is read as result === 0 (node test.js:143-147).
  if (event.kind === 'op' && event.type === 'view_contact' && event.result === 0) {
    contactReadEvents.push(event);
  }
});

// The tick: any landing op runs the post-execute trigger pass
// (src/StateMachine/state_machine.c step 9). A landing op IS a legal tick —
// here a SIGN op of a resource-carrying custom type whose wildcard path
// applies nothing (the item is a counter, not a RESOURCE) but lands, logs,
// and ticks triggers. (`node.evaluateTriggers()` would run the same C pass
// directly now; this keeps the recipe's op-driven shape pinned.)
node.setPolicy('tick', 'role:admin');
const tickAs = (signerName, signerKey) => {
  const op = new Operation('tick');
  op.signerId = signerName;
  op.addResource('abuse_reports');
  node.sign(op, signerKey);
  node.execute(op);
};
tickAs(ADMIN, node.getNodeKey().privateKeyHex);

// Gated action: pre-threshold, the policy clause 'clearance:moderator'
// cannot be satisfied — refuse with the typed error.
node.setPolicy('view_contact', 'AND role:member clearance:moderator');
const viewContact = (who, whoKey) => {
  const op = new Operation('view_contact');
  op.signerId = who;
  op.addResource('contact_reads');
  node.sign(op, whoKey);
  node.execute(op);
};

let refused = '';
try {
  viewContact('alice', aliceKey);
} catch (preThresholdRefusal) {
  refused = String(preThresholdRefusal.message);
}
if (!refused.includes('unauthorized')) {
  throw new Error(`pre-threshold view_contact must be refused, got "${refused}"`);
}
if (contactReadEvents.length !== 0) {
  throw new Error(`a refused op must not land, got ${contactReadEvents.length} view_contact events`);
}

// The threshold is crossed by driver writes + landing-op ticks. Two ticks
// below threshold: nothing fires.
node.incrementCounter('abuse_reports', 1, 'alice');
tickAs(ADMIN, node.getNodeKey().privateKeyHex);
node.incrementCounter('abuse_reports', 1, 'alice');
tickAs(ADMIN, node.getNodeKey().privateKeyHex);
if (node.getCounter('abuse_reports') !== 2) {
  throw new Error(`expected 2 reports, got ${node.getCounter('abuse_reports')}`);
}
if (triggerEvents.length !== 0) {
  throw new Error('trigger must not fire below threshold');
}
let alicePre = node.getUser('alice');
if (alicePre.attributes.some((attribute) => attribute.temporary)) {
  throw new Error(`no temporary attribute before the threshold, got ${JSON.stringify(alicePre.attributes)}`);
}

// Third report: the next landing op's trigger pass fires — the temporary
// attribute is issued to every holder of an attribute NAMED 'role' and
// alice's keyVersion bumps with the grant.
node.incrementCounter('abuse_reports', 1, 'alice');
tickAs(ADMIN, node.getNodeKey().privateKeyHex);
if (node.getCounter('abuse_reports') !== 3) {
  throw new Error(`expected 3 reports, got ${node.getCounter('abuse_reports')}`);
}
if (triggerEvents.length !== 1) {
  throw new Error(`expected exactly 1 trigger event, got ${triggerEvents.length}`);
}
alicePre = node.getUser('alice');
if (alicePre.keyVersion !== 3) {
  throw new Error(`keyVersion must bump 2 -> 3 on the trigger grant, got ${alicePre.keyVersion}`);
}
const clearance = alicePre.attributes.find((attribute) => attribute.temporary);
if (!clearance) {
  throw new Error(`temporary clearance must be issued, got ${JSON.stringify(alicePre.attributes)}`);
}
// The temp attribute's value IS the plain 'name:value' token the C policy
// evaluator matches (crabs-node mapper: bindings/node/src/crabs_node.cc:1208,
// a.Set("value", temp->name); the wasm binding now matches this shape).
if (clearance.value !== 'clearance:moderator' ||
    clearance.verifiedBy !== 'trigger' ||
    !(clearance.expiresAt > 0)) {
  throw new Error(`unexpected temp attribute shape: ${JSON.stringify(clearance)}`);
}

// Disclosure: the gate passes now (the temp token participates in policy
// evaluation while unexpired, src/Crypto/crypto.c:1140-1165). The op lands;
// the observable is the 'op' change event it emits.
viewContact('alice', aliceKey);
if (contactReadEvents.length !== 1) {
  throw new Error(`the gated op must land exactly once, got ${contactReadEvents.length} view_contact events`);
}

// Cooldown: another tick with the condition still true must NOT re-fire
// while the 60s cooldown is in force.
tickAs(ADMIN, node.getNodeKey().privateKeyHex);
if (triggerEvents.length !== 1) {
  throw new Error(`cooldown must suppress the immediate re-fire, got ${triggerEvents.length} events`);
}

// The payload is sealed, not just gated: encrypt returns the same container
// layout (u16le policy byte length + policy bytes + u32le ciphertext length
// + ciphertext; bindings/node/index.d.ts:257 + smoke.js:111-130 layout).
const payload = Buffer.from('contact for verified viewers', 'utf8');
const sealed = node.encrypt(payload, 'moderator and member');
const policyByteLength = sealed.readUInt16LE(0);
if (sealed.subarray(2, 2 + policyByteLength).toString('utf8') !== 'moderator and member') {
  throw new Error('policy must round-trip in the container');
}
const ciphertextLength = sealed.readUInt32LE(2 + policyByteLength);
if (2 + policyByteLength + 4 + ciphertextLength !== sealed.length) {
  throw new Error(`container length ${sealed.length} must match header ${2 + policyByteLength + 4 + ciphertextLength}`);
}

console.log('moderation OK: trigger fired at threshold, gate opened, cooldown suppressed, payload sealed');

// The decrypt half (gap-fill A11): the machine derives a reader key from
// ITS OWN master authority — abeKeygen('moderator,member') mints a key
// carrying the ABE words the policy asks for, and abeDecrypt opens the
// container locally (the machine never exposes its master key; the derived
// key is JS-owned — destroy() it. Minting reader keys is the same trust
// position as encrypt: the machine's admin side names the attribute set).
const readerKey = node.abeKeygen('moderator,member');
const opened = node.abeDecrypt(readerKey, sealed);
if (opened.toString('utf8') !== 'contact for verified viewers') {
  throw new Error(`decrypted payload mismatch, got "${opened.toString('utf8')}"`);
}
readerKey.destroy();

// The negative: a key whose attributes lack a policy clause refuses with
// the typed error word — 'unauthorized' (crypto_abe_decrypt; also the
// tamper path, GCM fail-closed).
const guestKey = node.abeKeygen('guest');
let decryptRefusal = '';
try {
  node.abeDecrypt(guestKey, sealed);
} catch (refusal) {
  decryptRefusal = String(refusal.message);
}
if (!decryptRefusal.includes('unauthorized')) {
  throw new Error(`decrypt must refuse a policy-missing key, got "${decryptRefusal}"`);
}
guestKey.destroy();

console.log('decrypt OK: reader key opened the sealed payload, guest key refused unauthorized');
// Node/KeyPair expose no destroy() — native cleanup is process-exit driven.