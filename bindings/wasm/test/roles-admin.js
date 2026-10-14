'use strict';

// Admin demotion + user suspension from JS (parity-fill P3):
//
// revokeRole / suspendUser / activateUser drive the admin-gated C machine
// calls (attribute_machine_revoke_role / _suspend_user / _activate_user,
// src/Attribute/attribute_machine.h:145-171). The signer RESOLVES the gates
// (active + role:admin) and defaults to the node's bootstrap admin id, the
// same convention as revokeUser. Pinned from JS, mirroring the C tests:
//   - revokeRole strips ONE attribute (shifts the rest), works on
//     suspended/REVOKED targets by design (R4-4), and the op gate flips
//     fail-closed (pre-revoke execution reaches the handler; post-revoke
//     refuses `unauthorized` — the machine re-evaluates at execution);
//   - suspendUser bumps the epoch and the signed-op path refuses (the
//     non-ACTIVE signer verify gate, crypto.c:1395-1403);
//   - activateUser restores ACTIVE and bumps the epoch again (R8-A-5), so a
//     pre-suspension stamp replays into a genuine `key_stale` (the R7-04
//     staleness gate state_machine.c:884-891) — the P2 note's promise;
//   - typed refusals: resource_not_found (no such role), user_not_found,
//     invalid_param (activate on an ACTIVE or REVOKED target), unauthorized
//     (non-admin signer), user_suspended (a suspended signer).

const assert = require('assert');
const { Node, KeyPair, Operation } = require('..');

// Execute `op` (signed) and classify the refusal for gate-flip pinning.
async function refusedWord(node, op, signerKey) {
  try {
    node.execute(op);
  } catch (refusal) {
    return refusal.message.split(': ')[1] || refusal.message;
  }
  return '';
}

(async () => {
  // ------------------------------------------------------------------
  // 1. revokeRole: the fine demotion + the fail-closed gate flip.
  // ------------------------------------------------------------------
  {
    const node = await Node.create('admin', { ordering: 'hlc' });
    const aliceKey = await KeyPair.generate();
    node.registerUser('alice', aliceKey.publicKeyHex(), '');
    node.grantRole('alice', 'role', 'editor', 'admin');
    node.setPolicy('bump', 'role:editor');

    // Pre-revoke: alice's signed op AUTHORIZES (then hits the handlerless
    // op's own resource gate — resource_not_found, the node test's pinned
    // declared-but-unimplemented shape).
    const preOp = await Operation.create('bump');
    preOp.signerId = 'alice';
    node.sign(preOp, aliceKey);
    assert.strictEqual(await refusedWord(node, preOp), 'resource_not_found',
      "pre-revoke the op must pass authorization (land on resource_not_found)");

    // A wrong signer sees the authorization wall even pre-revoke.
    assert.deepStrictEqual(node.getUser('alice').attributes.map((a) => a.value),
      ['role:editor'], 'alice holds exactly the granted role before revoke');

    node.revokeRole('alice', 'role', 'admin');
    assert.deepStrictEqual(node.getUser('alice').attributes, [],
      'revokeRole strips the one role attribute');
    assert(!node.getUser('alice').attributes.some((a) => a.value === 'role:editor'),
      'the role attribute is gone');

    // Post-revoke: the same shape refuses at authorization — the policy gate
    // re-evaluates at EXECUTION time (fail closed, no caching).
    assert.throws(() => node.execute(preOp), /unauthorized/,
      'post-revoke the same op refuses unauthorized (the gate flipped)');

    // Typed refusals + target-status independence (audit R4-4).
    assert.throws(() => node.revokeRole('alice', 'role', 'admin'),
      /resource_not_found/, 'revoking an absent role refuses');
    assert.throws(() => node.revokeRole('ghost', 'role', 'admin'),
      /user_not_found/, 'revoking from an unknown user refuses');
    const bobKey = await KeyPair.generate();
    node.registerUser('bob', bobKey.publicKeyHex(), '');
    node.grantRole('bob', 'role', 'user', 'admin');
    assert.throws(() => node.revokeRole('alice', 'role', 'bob'),
      /unauthorized/, 'a non-admin signer cannot strip roles');
    // Works on a REVOKED target by design (the decommission path R4-4).
    node.revokeUser('bob', 'admin');
    assert(node.getUser('bob').status === 'revoked', 'bob revoked');
    node.revokeRole('bob', 'role', 'admin');  // must NOT throw
    assert.deepStrictEqual(node.getUser('bob').attributes, [],
      'revokeRole works on a revoked target (R4-4)');
  }

  // ------------------------------------------------------------------
  // 2. suspendUser + activateUser: suspension, restore and the stale replay.
  // ------------------------------------------------------------------
  {
    const node = await Node.create('admin', { ordering: 'hlc' });
    const aliceKey = await KeyPair.generate();
    node.registerUser('alice', aliceKey.publicKeyHex(), '');
    node.grantRole('alice', 'role', 'member', 'admin');
    node.setPolicy('bump', 'role:member');

    const preSuspendVersion = node.getUser('alice').keyVersion;
    // Sign a bump op BEFORE suspension: the stamp carries preSuspendVersion.
    const staleOp = await Operation.create('bump');
    staleOp.signerId = 'alice';
    node.sign(staleOp, aliceKey);

    node.suspendUser('alice', 'admin');
    assert(node.getUser('alice').status === 'suspended',
      'suspendUser reads back status suspended');
    assert(node.getUser('alice').keyVersion === preSuspendVersion + 1,
      'suspending a user bumps the epoch (attribute_machine.c:878)');

    // While suspended: a FRESH signed op refuses at verification (R7-14
    // non-ACTIVE signer gate), and the stale replay cannot sneak past it.
    const suspendedOp = await Operation.create('bump');
    suspendedOp.signerId = 'alice';
    node.sign(suspendedOp, aliceKey);
    assert.throws(() => node.execute(suspendedOp), /unauthorized/,
      'a suspended signer refuses at verification');
    assert.throws(() => node.execute(staleOp), /unauthorized/,
      'the pre-suspension replay refuses at verification while suspended');

    // Admin actions while suspended are gone too (the gate whitelists ACTIVE
    // signers): alice-as-signer now refuses with the signer's own word.
    assert.throws(() => node.revokeRole('admin', 'role', 'alice'),
      /user_suspended/, 'a suspended signer keeps no admin authority');

    // activateUser: restore + second epoch bump (R8-A-5).
    node.activateUser('alice', 'admin');
    assert(node.getUser('alice').status === 'active',
      'activateUser reads back status active');
    assert(node.getUser('alice').keyVersion === preSuspendVersion + 2,
      'activating a user bumps the epoch again (R8-A-5: suspension stamps die)');

    // NOW the pre-suspension stamp replays into the genuine `key_stale`:
    // verification passes (ACTIVE signer, no keyring, legacy path) and the
    // R7-04 staleness gate catches the superseded version.
    assert.throws(() => node.execute(staleOp), /key_stale/,
      'the pre-suspension replay refuses key_stale after reactivation');
    // A fresh stamp authorizes again (the role survives suspension).
    const freshOp = await Operation.create('bump');
    freshOp.signerId = 'alice';
    node.sign(freshOp, aliceKey);
    assert.strictEqual(await refusedWord(node, freshOp), 'resource_not_found',
      'a fresh post-activation op authorizes again');

    // Typed refusals (the C pins).
    assert.throws(() => node.activateUser('alice', 'admin'),
      /invalid_param/, 'activating an ACTIVE user is not a recovery state');
    assert.throws(() => node.suspendUser('ghost', 'admin'), /user_not_found/,
      'suspending an unknown user refuses');
    assert.throws(() => node.activateUser('ghost', 'admin'), /user_not_found/,
      'activating an unknown user refuses');
    const bobKey = await KeyPair.generate();
    node.registerUser('bob', bobKey.publicKeyHex(), '');
    assert.throws(() => node.suspendUser('alice', 'bob'), /unauthorized/,
      'a non-admin signer cannot suspend');
    assert.throws(() => node.activateUser('alice', 'bob'), /unauthorized/,
      'a non-admin signer cannot reactivate');
    // R8-C-4: suspension must not downgrade a REVOKED user.
    node.revokeUser('bob', 'admin');
    assert.throws(() => node.suspendUser('bob', 'admin'), /invalid_param/,
      'suspending a revoked user refuses (revocation is terminal, R8-C-4)');
    assert.throws(() => node.activateUser('bob', 'admin'), /invalid_param/,
      'activating a revoked user refuses (revocation is terminal)');
    assert(node.getUser('bob').status === 'revoked', 'bob stays revoked');
  }

  // ------------------------------------------------------------------
  // 3. The admin gate fails closed for the signer too: a SUSPENDED admin
  // keeps no authority (mirror test_attribute_machine.cpp:431-437's
  // self-lockout shape), and the default signer id honours revokeUser's
  // convention.
  // ------------------------------------------------------------------
  {
    const node = await Node.create('admin', { ordering: 'hlc' });
    const zoeKey = await KeyPair.generate();
    node.registerUser('zoe', zoeKey.publicKeyHex(), '');
    // signerId omitted → the node's bootstrap admin id (the revokeUser
    // convention this family shares).
    node.suspendUser('zoe');
    assert(node.getUser('zoe').status === 'suspended',
      'suspendUser defaults the signer to the node admin id');
    node.activateUser('zoe');
    assert(node.getUser('zoe').status === 'active',
      'activateUser defaults the signer to the node admin id');

    // The self-lockout: after the admin is suspended, an admin-signed call
    // refuses with the SIGNER's word (user_suspended, not unauthorized) —
    // and the refusal changes nothing on the target.
    node.suspendUser('admin', 'admin');
    assert.throws(() => node.suspendUser('zoe', 'admin'),
      /user_suspended/,
      'a suspended signer refuses with user_suspended (the gate whitelist)');
    assert(node.getUser('zoe').status === 'active',
      'the gate refusal changed nothing on the target');
  }

  console.log('roles-admin.js: all revoke/suspend/activate assertions passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});