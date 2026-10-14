'use strict';

// issueTemporary — the JS issuance path for Attribute/attribute_machine.h:200
// `attribute_machine_issue_temporary(am, attribute, value, role, duration_ms)`
// (Amendment 1 §7.1). The trigger fan-out already issues temp attributes from
// JS (getuser-readback.js pins that shape); this file pins the DIRECT
// issuance surface:
//   - the grant fans out to EVERY ACTIVE holder of the audience attribute
//     NAME (the C role-match is a name match, attribute_machine.c:592), and
//     the readback is the same UserInfo shape as the trigger path: the
//     name:value token + `temporary: true` + `expiresAt` (issued_at + ttl);
//   - the blocklist: a privileged attribute NAME (the 'role'/'admin' family,
//     attribute_machine.c's _PRIVILEGED_ATTR_NAMES) refuses `unauthorized`,
//     a comma- or space-carrying value refuses `invalid_param` (the
//     attribute-string token-injection guard), ttl 0 refuses `invalid_param`;
//   - issue bumps the holder's key_version (every holder's key_version++,
//     attribute_machine.c:1005);
//   - expiry is FAIL-CLOSED: the machine prunes expired temp attributes
//     before authorization (state_machine.c's attribute-machine clock poke +
//     prune, and crypto.c _build_attr_string drops expired in-list tokens),
//     so a policy written against the temp token refuses `unauthorized`
//     after the window — pinned here WITHOUT sleeping: the clock poke
//     (setTime) is only visible until the next execute(), so the negative
//     pin drives the direct prune path the execute pipeline itself calls.

const assert = require('assert');
const { Node, KeyPair, Operation } = require('..');

(async () => {
  // ---------- A: fan-out + readback on a poked test timeline ----------
  const node = await Node.create('admin', { ordering: 'hlc' });
  const aliceKey = await KeyPair.generate();
  const bobKey = await KeyPair.generate();
  const carolKey = await KeyPair.generate();
  node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'admin');
  node.registerUser('bob', bobKey.publicKeyHex(), 'adult');
  node.grantRole('bob', 'role', 'member', 'admin');
  node.registerUser('carol', carolKey.publicKeyHex(), 'adult');

  const keyVersionBefore = node.getUser('alice').keyVersion;
  node.setTime(1000);   // the attr-machine clock; issue stamps issued/expires
  node.issueTemporary('clearance', 'moderator', { audienceRole: 'role', ttlMs: 5000 });

  for (const [userId, granted] of [['alice', true], ['bob', true], ['carol', false]]) {
    const temp = (node.getUser(userId).attributes || [])
      .filter((attribute) => attribute.temporary)
      .find((attribute) => attribute.value === 'clearance:moderator');
    if (granted) {
      assert.ok(temp, `${userId} must hold the fan-out token`);
      // Amendment 1 §7.1: issued_at + duration; the clock was 1000.
      assert.strictEqual(temp.expiresAt, 6000, `${userId} expiresAt = issued + ttl`);
    } else {
      assert.ok(!temp, `carol holds no role attribute and must receive nothing`);
    }
  }
  assert.strictEqual(node.getUser('alice').keyVersion, keyVersionBefore + 1,
    'every granted holder bumps key_version (attribute_machine.c:1005)');

  // ---------- B: typed refusals ----------
  // The privileged-name blocklist covers the issue path (Audit N-1) —
  // minting `role:admin` via issueTemporary would forge the admin gate.
  assert.throws(() => node.issueTemporary('role', 'admin', { audienceRole: 'role', ttlMs: 60000 }),
    /unauthorized/, 'a privileged attribute name must refuse unauthorized');
  // Token-injection guard: comma/space values (de-wonk rule _is_safe_attr_value).
  assert.throws(() => node.issueTemporary('clearance', 'secret,admin', { audienceRole: 'role', ttlMs: 60000 }),
    /invalid_param/, 'a comma in the value must refuse invalid_param');
  assert.throws(() => node.issueTemporary('clearance', 'secret admin', { audienceRole: 'role', ttlMs: 60000 }),
    /invalid_param/, 'a space in the value must refuse invalid_param');
  assert.throws(() => node.issueTemporary('clearance', 'moderator', { audienceRole: 'role', ttlMs: 0 }),
    /invalid_param/, 'ttl 0 must refuse invalid_param');
  assert.throws(() => node.issueTemporary('clearance', 'moderator', {}),
    /audienceRole/, 'a missing audienceRole is a wrapper-level TypeError');

  // ---------- C: expiry is fail-closed ----------
  // Same test timeline: at 7000 the 6000 window is closed. The DIRECT prune
  // (the call the execute pipeline makes before authorization) reports the
  // count it removed.
  node.setTime(7000);
  const pruned = node.pruneExpiredTempAttrs();
  // THREE tokens: alice, bob, AND the machine's bootstrap admin — the
  // §8.3 genesis admin holds role:admin, and the fan-out audience is a
  // NAME match on 'role' (attribute_machine.c:592), so the admin is in
  // every grant too.
  assert.strictEqual(pruned, 3,
    'alice, bob, and the Genesis admin each held one expired token');
  assert.strictEqual(node.pruneExpiredTempAttrs(), 0, 'a second prune prunes nothing');
  for (const userId of ['alice', 'bob']) {
    const stillThere = (node.getUser(userId).attributes || [])
      .some((attribute) => attribute.temporary);
    assert.ok(!stillThere, `${userId} must read back no temp attribute after prune`);
  }

  // ---------- D: the policy-readback fail-closed fact (crypto.c:1128-1177) ----------
  // A policy written against the temp token is satisfied WHILE the window
  // holds and refuses `unauthorized` after it closes — the fail-closed
  // behaviour of _build_attr_string (R8-A-8) reached through __check_dedup__.
  const policyNode = await Node.create('policy-admin', { ordering: 'hlc' });
  const danaKey = await KeyPair.generate();
  policyNode.registerUser('dana', danaKey.publicKeyHex(), 'adult');
  policyNode.grantRole('dana', 'role', 'member', 'policy-admin');
  policyNode.addOneShotSet('reveal_log');
  policyNode.setPolicy('__check_dedup__', 'role:member');
  policyNode.setPolicy('reveal', 'clearance:moderator');

  // Positive pin: issue against the REAL pipeline clock (setTime(present) so
  // issued_at == the clock the execute pipeline feeds back in) with a window
  // that comfortably outlasts the harness run, then execute an op whose
  // policy the temp token satisfies. The wildcard path (a non-RESOURCE
  // resource, no handler) makes the plain non-builtin op executable.
  policyNode.setTime(Date.now());
  policyNode.issueTemporary('clearance', 'moderator', { audienceRole: 'role', ttlMs: 3600000 });
  const grantedOp = await Operation.create('reveal');
  grantedOp.signerId = 'dana';
  grantedOp.nodeId = 'dana';
  grantedOp.addResource('reveal_log');
  policyNode.sign(grantedOp, danaKey.privateKeyHex());
  policyNode.execute(grantedOp);
  grantedOp.destroy();

  // Negative pin: close the window (setTime, then the direct prune the
  // execute pipeline runs) — the same op shape now refuses `unauthorized`,
  // and there is no fail-open residue (the token is gone from the state).
  policyNode.setTime(Date.now() + 7200000);
  assert.strictEqual(policyNode.pruneExpiredTempAttrs(), 2,
    'dana AND the Genesis policy-admin held a token (the admin holds role:admin)');
  const expiredOp = await Operation.create('reveal');
  expiredOp.signerId = 'dana';
  expiredOp.nodeId = 'dana';
  expiredOp.addResource('reveal_log');
  policyNode.sign(expiredOp, danaKey.privateKeyHex());
  assert.throws(() => policyNode.execute(expiredOp),
    /unauthorized/, 'a policy satisfied only by the expired token must fail closed');
  expiredOp.destroy();

  console.log('temporary-attributes wasm: OK');
})().catch((failure) => {
  console.error('temporary-attributes wasm FAILED:', failure);
  process.exit(1);
});