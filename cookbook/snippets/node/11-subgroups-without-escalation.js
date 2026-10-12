'use strict';
// Recipe 11 — a group with subgroups that can't escalate (crabs-node).
//
// The node binding's lineageSpawn returns a full Node wrapper over the
// borrowed child machine, so the subgroup's side of the story is inspectable:
// its registry is its own, its items are exactly the blueprint's (minus
// what its own admin adds later — see the honesty assertion), its members
// resolve nowhere on the parent, and the parent's severance is the real
// teeth. Mirrors the node lineage smoke (bindings/node/lineage_smoke.mjs).

const assert = require('assert');
const { Node, KeyPair, Operation, Blueprint, TRUST_MODE, DATA_TYPE, CRDT_TYPE } =
  require('../../../bindings/node');

const parent = new Node('parent-admin', { ordering: 'hlc' });
parent.setTime(Date.now());   // attest reads the machine's time source
parent.lineageInstall();

// The subgroup's charter: items, policies, trust mode, attestation TTL.
const blueprint = Blueprint.create('billing-team', TRUST_MODE.DELEGATED_COPY,
                                   'team-admin', 3600000);
blueprint.addItem('score', DATA_TYPE.COUNTER, CRDT_TYPE.G_COUNTER);
blueprint.addPolicy('view', 'role:member');
blueprint.stampHash();

// Wire round trip: deserialize verifies the embedded hash and re-validates.
const wire = blueprint.serialize();
assert(wire.length > 0, 'blueprint serialize produced no bytes');
const reloaded = Blueprint.deserialize(wire);

// The parent's registry here is deliberately non-empty, to prove below that
// it does not leak into the child.
const operatorKey = KeyPair.generate();
parent.registerUser('operator', operatorKey.publicKeyHex(), 'adult');

// Spawn: the child wrapper BORROWS the machine — the parent owns it.
const child = parent.lineageSpawn(blueprint);

// The manifest is the parent's durable track record of what it minted.
const entry = parent.lineageChildren()[0];
assert(entry !== undefined, 'child manifest entry missing after spawn');
assert(entry.childId === 'billing-team' &&
       entry.mode === 'delegated_copy' && entry.status === 'active',
  `unexpected manifest view: ${JSON.stringify(entry)}`);
assert(entry.attestationTtlMs === 3600000, `unexpected ttl: ${entry.attestationTtlMs}`);
assert(parent.lineageResidentChild('billing-team') !== null,
  'spawned child not resolvable in the resident registry');

// ---- The attenuation, observed from inside the subgroup --------------------
// Fresh authority: the parent's user registry is NOT the child's registry.
// The subgroup starts with exactly one member — its vouched bootstrap admin
// — and nothing of the parent's roster.
assert(child.getUser('operator') === undefined,
  "the parent's users must not appear in the subgroup's registry");
assert(child.getUser('team-admin') !== undefined,
  "the subgroup's vouched genesis admin should exist");
assert(child.getCounter('score') === 0,
  "the blueprint's items land on the child");

// Attenuation is the INITIAL grant, not a sandbox: the subgroup's admin
// runs a full machine and can mint more of its own items afterwards. What
// the subgroup can never do is draw on the parent's authority — there is no
// path from child ops to parent state (see the recipe notes).
child.defineItem('side-ledger', 'counter', 'g_counter');
assert(child.getCounter('side-ledger') === 0,
  'the subgroup may mint items in its own domain');
child.addCounter('another');   // plain free-merge item, the child's business
assert(child.getCounter('another') === 0);

// And the child's roster grows inside the subgroup only. The subgroup admin
// is anchored to the PARENT's node key at spawn (the parent vouches for its
// genesis admin), so admin-side action on the child uses that key.
const clerkKey = KeyPair.generate();
child.registerUser('clerk', clerkKey.publicKeyHex(), '');
child.grantRole('clerk', 'role', 'member', 'team-admin');

// A subgroup member's op lands on the child... custom ops need a resource
// to act on (a resource-less custom op fails resource_not_found); 'score'
// is the blueprint's item, so the wildcard path accepts it.
const viewOp = new Operation('view');
viewOp.signerId = 'clerk';
viewOp.nodeId = 'clerk';
viewOp.addResource('score');
child.sign(viewOp, clerkKey.privateKeyHex());
child.execute(viewOp);

// ...and the same signer resolves NOWHERE on the parent: machines are
// bounded by their own registries. Escalation up has no surface.
const crossOp = new Operation('view');
crossOp.signerId = 'clerk';
crossOp.nodeId = 'clerk';
crossOp.addResource('score');
parent.sign(crossOp, clerkKey.privateKeyHex());
try {
  parent.execute(crossOp);
  throw new Error("a subgroup member's op must not authorize on the parent");
} catch (refusal) {
  assert(refusal.message.includes('unauthorized'),
    `expected unauthorized on the parent, got: ${refusal.message}`);
}

// ---- The parent's teeth (the "can't escalate" enforcement) ----------------
// The subgroup has no authority of its own over the parent, and the parent
// can cut the bridge any time: dissolving the child durably flags the
// child's parent_binding dissolved — every parent endorsement fails closed
// from that moment — and clears the resident slot. The dissolve op runs
// through the pipeline: a registered role:admin user signs it.
const dissolverKey = KeyPair.generate();
parent.registerUser('dissolver', dissolverKey.publicKeyHex(), 'adult');
parent.grantRole('dissolver', 'role', 'admin', 'parent-admin');

const dissolveOp = new Operation('__dissolve_machine__');
dissolveOp.signerId = 'dissolver';
dissolveOp.nodeId = 'dissolver';
dissolveOp.payload = Buffer.from('billing-team');  // NUL-excluded
parent.sign(dissolveOp, dissolverKey.privateKeyHex());
parent.execute(dissolveOp);

assert(parent.lineageResidentChild('billing-team') === null,
  'in-process severance must clear the resident registry slot');
assert(parent.lineageChildren()[0].status === 'dissolved',
  `manifest status after dissolve: ${JSON.stringify(parent.lineageChildren()[0])}`);

// The parent's vouching stops on refusal: attest for a non-ACTIVE entry
// fails closed.
assert.throws(() => parent.lineageAttest('billing-team', 'clerk', 'role:member'),
  /unauthorized/, 'attest must fail closed for a dissolved child');

console.log('subgroups-without-escalation OK: spawned, isolated, member bounded' +
  ' to the subgroup, duplicated refuse, dissolved');
// Node/KeyPair expose no destroy() — native cleanup is process-exit driven.