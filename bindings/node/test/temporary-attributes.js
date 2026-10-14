// temporary-attributes.js — the node binding's DIRECT issuance path for
// `attribute_machine_issue_temporary(am, attribute, value, role, duration_ms)`
// (src/Attribute/attribute_machine.h:200, Amendment 1 §7.1). The trigger
// fan-out already issues temp attributes from JS (test.js pins the trigger
// shape); this file pins the issueTemporary surface:
//   - the grant fans out to EVERY ACTIVE holder of the audience attribute
//     NAME (the C role-match is a name match, attribute_machine.c:592), and
//     the readback is the canonical UserInfo temp shape: the name:value
//     token + temporary: true + expiresAt (issued_at + ttl);
//   - the blocklist (the privilege names, attribute_machine.c's
//     _PRIVILEGED_ATTR_NAMES) refuses unauthorized; comma/space values and
//     ttl 0 refuse invalid_param; a missing audienceRole is a wrapper error;
//   - issue bumps the holder's key_version (attribute_machine.c:1005);
//   - expiry is FAIL-CLOSED (crypto.c:1128-1177, R8-A-8): expired temp
//     attributes stop granting — pinned sleep-free via the direct prune the
//     execute pipeline itself runs before authorization
//     (state_machine.c's attribute-machine clock poke + prune).

'use strict';

const assert = require('assert');
const { Node, KeyPair, Operation } = require('..');

(async () => {
  // ---------- A: fan-out + readback on a poked test timeline ----------
  const node = new Node('admin', { ordering: 'hlc' });
  const aliceKey = KeyPair.generate();
  const bobKey = KeyPair.generate();
  const carolKey = KeyPair.generate();
  node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'admin');
  node.registerUser('bob', bobKey.publicKeyHex(), 'adult');
  node.grantRole('bob', 'role', 'member', 'admin');
  node.registerUser('carol', carolKey.publicKeyHex(), 'adult');

  const keyVersionBefore = node.getUser('alice').keyVersion;
  node.setTime(1000);
  node.issueTemporary('clearance', 'moderator', { audienceRole: 'role', ttlMs: 5000 });

  for (const [userId, granted] of [['alice', true], ['bob', true], ['carol', false]]) {
    const temp = (node.getUser(userId).attributes || [])
      .filter((attribute) => attribute.temporary)
      .find((attribute) => attribute.value === 'clearance:moderator');
    if (granted) {
      assert.ok(temp, `${userId} must hold the fan-out token`);
      assert.strictEqual(temp.expiresAt, 6000, `${userId} expiresAt = issued + ttl`);
    } else {
      assert.ok(!temp, 'carol holds no role attribute and must receive nothing');
    }
  }
  assert.strictEqual(node.getUser('alice').keyVersion, keyVersionBefore + 1,
    'every granted holder bumps key_version (attribute_machine.c:1005)');

  // ---------- B: typed refusals ----------
  assert.throws(
    () => node.issueTemporary('role', 'admin', { audienceRole: 'role', ttlMs: 60000 }),
    /unauthorized/, 'a privileged attribute name must refuse unauthorized');
  assert.throws(
    () => node.issueTemporary('clearance', 'secret,admin', { audienceRole: 'role', ttlMs: 60000 }),
    /invalid_param/, 'a comma in the value must refuse invalid_param');
  assert.throws(
    () => node.issueTemporary('clearance', 'secret admin', { audienceRole: 'role', ttlMs: 60000 }),
    /invalid_param/, 'a space in the value must refuse invalid_param');
  assert.throws(
    () => node.issueTemporary('clearance', 'moderator', { audienceRole: 'role', ttlMs: 0 }),
    /invalid_param/, 'ttl 0 must refuse invalid_param');
  assert.throws(
    () => node.issueTemporary('clearance', 'moderator', {}),
    /audienceRole/, 'a missing audienceRole is a wrapper-level error');

  // ---------- C: expiry is fail-closed ----------
  node.setTime(7000);
  // THREE tokens: alice, bob, AND the machine's bootstrap admin — the
  // §8.3 genesis admin holds role:admin, and the fan-out audience is a
  // NAME match on 'role' (attribute_machine.c:592), so the admin is in
  // every grant too.
  assert.strictEqual(node.pruneExpiredTempAttrs(), 3,
    'alice, bob, and the Genesis admin each held one expired token');
  assert.strictEqual(node.pruneExpiredTempAttrs(), 0, 'a second prune prunes nothing');
  for (const userId of ['alice', 'bob']) {
    const stillThere = (node.getUser(userId).attributes || [])
      .some((attribute) => attribute.temporary);
    assert.ok(!stillThere, `${userId} must read back no temp attribute after prune`);
  }

  // ---------- D: the policy-readback fail-closed fact ----------
  const policyNode = new Node('policy-admin', { ordering: 'hlc' });
  const danaKey = KeyPair.generate();
  policyNode.registerUser('dana', danaKey.publicKeyHex(), 'adult');
  policyNode.grantRole('dana', 'role', 'member', 'policy-admin');
  policyNode.addOneShotSet('reveal_log');
  policyNode.setPolicy('__check_dedup__', 'role:member');
  policyNode.setPolicy('reveal', 'clearance:moderator');

  // Positive pin: issued against a real, present clock, the token satisfies
  // the 'reveal' policy (the wildcard path executes the plain op).
  policyNode.setTime(Date.now());
  policyNode.issueTemporary('clearance', 'moderator', { audienceRole: 'role', ttlMs: 3600000 });
  const grantedOp = new Operation('reveal');
  grantedOp.signerId = 'dana';
  grantedOp.nodeId = 'dana';
  grantedOp.addResource('reveal_log');
  policyNode.sign(grantedOp, danaKey.privateKeyHex());
  policyNode.execute(grantedOp);

  // Negative pin: after the window closes (prune driven by a poked clock) the
  // same op shape refuses unauthorized — no fail-open residue.
  policyNode.setTime(Date.now() + 7200000);
  assert.strictEqual(policyNode.pruneExpiredTempAttrs(), 2,
    'dana AND the Genesis policy-admin held a token (the admin holds role:admin)');
  const expiredOp = new Operation('reveal');
  expiredOp.signerId = 'dana';
  expiredOp.nodeId = 'dana';
  expiredOp.addResource('reveal_log');
  policyNode.sign(expiredOp, danaKey.privateKeyHex());
  assert.throws(() => policyNode.execute(expiredOp),
    /unauthorized/, 'a policy satisfied only by the expired token must fail closed');

  console.log('temporary-attributes node: OK');
})().catch((failure) => {
  console.error('temporary-attributes node FAILED:', failure);
  process.exit(1);
});