'use strict';

// getUser readback (gap-fill A1): the wasm binding must surface the REAL
// machine state — keyVersion stamped by register/grant, user status, the
// registered 33-byte public key, and per-attribute verifiedBy — instead of
// the hardcoded stub (publicKeyHex '', keyVersion 0, status 'active').
//
// Gap-fill A2 extends the same file to the TEMPORARY attribute readback:
// the binding must return the temp attribute's PLAIN token (name as stored,
// e.g. 'clearance:moderator') — exactly what node's mapper does
// (bindings/node/src/crabs_node.cc:1208-1211) and what the C policy
// evaluator matches (src/Crypto/crypto.c:1126-1158) — not a wasm-only
// 'name + ":" + value' doubling on top of the token.

const assert = require('assert');
const { Node, KeyPair, Operation } = require('..');

(async () => {
  const node = await Node.create('admin', { ordering: 'hlc' });
  const key = await KeyPair.generate();
  // Distinct keypair for the moderation flow below.
  const triggerUserKey = await KeyPair.generate();
  node.registerUser('alice', key.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'admin');

  const user = node.getUser('alice');
  assert.strictEqual(user.userId, 'alice');
  // register_user stamps key_version = 1 (attribute_machine.c:495); the
  // role grant increments it to 2 (attribute_machine.c:617).
  assert.strictEqual(user.keyVersion, 2);
  assert.strictEqual(user.status, 'active');
  assert.strictEqual(user.publicKeyHex.length, 66, '33-byte ECDSA key, hex');
  assert.strictEqual(user.publicKeyHex, key.publicKeyHex());

  // The machine stores the grant as the formatted 'role:value' token
  // (attribute_machine.c:611), which is what policy evaluation matches.
  const role = user.attributes.find((attribute) => attribute.value === 'role:member');
  assert.ok(role, 'role attribute missing');
  assert.strictEqual(role.verifiedBy, 'admin');

  // revoke_user flips the record's status; the readback must follow.
  node.revokeUser('alice', 'admin');
  assert.strictEqual(node.getUser('alice').status, 'revoked');

  // --- Temporary attribute readback (gap-fill A2) ---
  // Issue a temp attribute through the recipe idiom: a signed '__create_trigger__'
  // op installs the trigger (so its own policy gate applies), a signed report op
  // pushes the counter past the threshold, and the machine's post-execute
  // trigger pass issues the attribute (attribute_machine.c trigger pass).
  const bobKey = triggerUserKey;
  node.registerUser('bob', bobKey.publicKeyHex(), 'adult');
  node.grantRole('bob', 'role', 'member', 'admin');

  node.addCounter('abuse_reports');
  node.setPolicy('report_abuse', 'role:member');
  node.registerHandlerJs('report_abuse', (state, operation) => {
    state.incrementCounter('abuse_reports', 1, operation.signerId);
    return 0;
  });
  // Installing a trigger is an admin-gated op (mirrors
  // cookbook/snippets/wasm/06-moderation.js).
  node.setPolicy('__create_trigger__', 'role:admin');
  node.createTrigger({
    triggerId: 'clearance_gateway',
    condition: 'abuse_reports >= 1',
    description: 'Issue clearance:moderator when an abuse report lands',
    effectType: 'issue_attribute',
    issueAttribute: 'clearance',
    // targetRole is the audience attribute NAME (the fan-out matches
    // attribute names, not users — attribute_machine_issue_temporary).
    targetRole: 'role',
    attributeValue: 'moderator',
    durationMs: 3600000,
    oneShot: false,
    cooldownMs: 60000,
  });

  const reportOp = await Operation.create('report_abuse');
  reportOp.signerId = 'bob';
  reportOp.nodeId = 'bob';
  node.sign(reportOp, bobKey.privateKeyHex());
  node.execute(reportOp);
  reportOp.destroy();

  const bobAfterTrigger = node.getUser('bob');
  const clearance = bobAfterTrigger.attributes.find((attribute) => attribute.temporary);
  assert.ok(clearance, `temporary clearance must be issued, got ${JSON.stringify(bobAfterTrigger.attributes)}`);
  // The temp attr must read back as the PLAIN token the C evaluator matches
  // ('clearance:moderator', src/Crypto/crypto.c:1143) — not the wasm
  // doubling 'clearance:moderator:moderator'.
  assert.strictEqual(clearance.value, 'clearance:moderator');
  assert.strictEqual(clearance.verifiedBy, 'trigger');
  assert.ok(Number.isFinite(clearance.expiresAt) && clearance.expiresAt > Date.now(),
    `expiresAt must be a future timestamp, got ${clearance.expiresAt}`);

  console.log('getUser readback OK');
})().catch((e) => { console.error(e); process.exit(1); });
