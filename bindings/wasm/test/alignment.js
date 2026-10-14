'use strict';
//
// alignment.js — Parity-fill P10, wasm side: the node-only surfaces whose
// absence was honest noise, not design:
//   * selfAssert / verifyIdentity — the non-replicated attribute-writing
//     primitives (attribute_machine_self_assert :624 /
//     attribute_machine_verify_identity :697) — direct, no op, no policy.
//   * evaluateTriggers returning the fired count, driven by the C
//     trigger_process_all tick directly (the old 'noop-execute' shape was
//     unusable on a handlerless machine — a policy-less zero-resource op
//     refuses resource_not_found).
//   * getHLC unified on the read-only watermark with the node binding's
//     shape {seconds, nanos, logicalCounter, nodeId, formatted} — two
//     consecutive reads are IDENTICAL.

const { Node, KeyPair, Operation } = require('..');
const assert = require('assert');

(async () => {
  const node = await Node.create('admin', { ordering: 'hlc' });
  const aliceKey = await KeyPair.generate();
  await node.registerUser('alice', aliceKey.publicKeyHex(), '');
  node.grantRole('alice', 'role', 'member', 'admin');

  // ==========================================================
  // selfAssert
  // ==========================================================
  node.selfAssert('hometown', 'lisbon', 'alice');
  const afterSelf = node.getUser('alice');
  const selfAttr = afterSelf.attributes.find((a) => a.value === 'hometown:lisbon');
  assert.ok(selfAttr, 'self-asserted attribute recorded');
  assert.strictEqual(selfAttr.verifiedBy, '',
    'self-asserted attributes carry no verifier');

  // Privileged names refuse (the C-5 blocklist, fail closed).
  assert.throws(() => node.selfAssert('role', 'admin', 'alice'),
    /unauthorized/, 'self-assert of a privileged name refuses');

  // Unsafe charset names / comma-space values refuse invalid_param.
  assert.throws(() => node.selfAssert('hôme','x','alice'), /invalid_param/,
    'unsafe attribute name refuses');

  // A VERIFIED attribute may not be overwritten by a self-assert.
  node.verifyIdentity('alice', 'hometown', 'porto', 'admin');
  assert.throws(() => node.selfAssert('hometown', 'braga', 'alice'),
    /unauthorized/, 'self-assert over a verified attribute refuses');

  // ==========================================================
  // verifyIdentity
  // ==========================================================
  const verified = node.getUser('alice').attributes
    .find((a) => a.value === 'hometown:porto');
  assert.ok(verified, 'verified attribute recorded');
  assert.strictEqual(verified.verifiedBy, 'admin',
    'verified_by carries the verifying signer');

  // Non-admin verifier refuses.
  assert.throws(() => node.verifyIdentity('alice', 'hometown', 'faro', 'alice'),
    /unauthorized/, 'non-admin verifyIdentity refuses');

  // Unknown target user refuses.
  assert.throws(() => node.verifyIdentity('nobody', 'hometown', 'faro', 'admin'),
    /user_not_found/, 'unknown target user refuses');

  // ==========================================================
  // evaluateTriggers — explicit tick, fired-count return
  // ==========================================================
  const bobKey = await KeyPair.generate();
  await node.registerUser('bob', bobKey.publicKeyHex(), '');
  node.grantRole('bob', 'role', 'member', 'admin');
  node.addCounter('abuse_reports');
  node.setPolicy('__create_trigger__', 'role:admin');
  node.createTrigger({
    triggerId: 'clearance_gateway',
    condition: 'abuse_reports >= 1',
    description: 'Issue clearance:moderator when an abuse report lands',
    effectType: 'issue_attribute',
    issueAttribute: 'clearance',
    targetRole: 'role',
    attributeValue: 'moderator',
    durationMs: 3600000,
    oneShot: false,
    cooldownMs: 60000,
  });

  node.incrementCounter('abuse_reports', 1, 'admin');
  assert.ok(!node.getUser('bob').attributes
    .some((attribute) => attribute.temporary),
    'no temp attribute before the tick');

  const fired = node.evaluateTriggers();
  assert.ok(typeof fired === 'number' && fired >= 1,
    `evaluateTriggers reports the fired count (got ${fired})`);
  const clearance = node.getUser('bob').attributes
    .find((attribute) => attribute.temporary);
  assert.ok(clearance, 'the explicit tick fires the pending trigger');
  assert.strictEqual(clearance.value, 'clearance:moderator',
    'temp attribute carries the plain C-matched token');

  // A cooldown-suppressed tick re-runs the pass without re-firing
  // (fired drops; no duplicate grant).
  node.incrementCounter('abuse_reports', 1, 'admin');
  const firedSuppressed = node.evaluateTriggers();
  assert.strictEqual(firedSuppressed, 0,
    'a cooldown-suppressed tick reports 0 fired');
  assert.strictEqual(node.getUser('bob').attributes
    .filter((a) => a.temporary && a.value === 'clearance:moderator').length, 1,
    'no duplicate temp grant from the suppressed tick');

  // ==========================================================
  // getHLC — unified watermark readback, node shape
  // ==========================================================
  const hlo = node.getHLC();
  assert.ok(hlo, 'HLC machine reports its watermark');
  assert.ok(hlo.seconds > 0, `watermark seconds live (got ${hlo.seconds})`);
  assert.strictEqual(hlo.nodeId, 'admin', 'watermark carries the HLC identity');
  assert.ok(typeof hlo.formatted === 'string' && hlo.formatted.length > 0,
    'formatted stamp string present');
  assert.ok(Number.isFinite(hlo.nanos) && Number.isFinite(hlo.logicalCounter),
    'nanos + logicalCounter present');
  // READ-ONLY: two consecutive reads are identical — advancing happens only
  // when an op executes (the sign/execute paths issue crabs_hlc_next).
  assert.deepStrictEqual(JSON.parse(JSON.stringify(node.getHLC())),
    JSON.parse(JSON.stringify(hlo)),
    'getHLC is a read-only watermark read');

  console.log('alignment wasm OK');
})().catch((failure) => {
  console.error('alignment wasm FAILED:', failure);
  process.exit(1);
});