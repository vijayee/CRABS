'use strict';
//
// binding-alignment.js — Parity-fill P10: the node binding gains the
// wasm-side read/op surface whose absence was honest noise, not design:
//   * OR-set pagination (getSetSize/getSetElements/getSetTags) — the wasm
//     contract mirrored exactly (distinct-live counting, strcmp sort,
//     256-hard-cap, snapshot semantics).
//   * Byte registers (setRegisterBytes/getRegisterBytes) — opaque payload
//     storage beside the integer register API.
//   * BigInt-tolerant integer registers — wasm accepts Number|BigInt for
//     the full int64 range; node now does too (exact bytes pinned through
//     the byte register readback).
//   * evaluateTriggers — the explicit trigger tick (C trigger_process_all,
//     the same primitive the executor's post-execute pass runs).
//   * Operation.deserialize — the wasm round trip (JS adopts a wire op
//     object, the P1 state-restore precedent).
//

const { Node, Operation, KeyPair } = require('..');
const assert = require('assert');

(async () => {
  // ==========================================================
  // OR-set pagination
  // ==========================================================
  const node = new Node('admin', { ordering: 'hlc' });
  node.addORSet('crew');
  const elements = ['alpha', 'beta', 'gamma', 'delta', 'epsilon',
                    'lambda', 'mu', 'nu', 'omicron', 'zeta'];
  for (const element of elements) {
    node.setAdd('crew', element, `tag-${element}`);
  }
  // Post-Task-1 pair semantics: a second tag on the same element.
  node.setAdd('crew', 'alpha', 'tag-alpha-second');
  const sorted = [...elements].sort();

  // Size counts DISTINCT live elements (alpha-with-two-tags counts once).
  assert.strictEqual(node.getSetSize('crew'), 10,
    'getSetSize counts distinct live elements');

  // Pagination: two 5-element pages cover the set, sorted ascending (the
  // sort is byte-wise strcmp ascending, stable across replicas).
  assert.deepStrictEqual(node.getSetElements('crew', { offset: 0, limit: 5 }),
    sorted.slice(0, 5), 'page 1 sorted ascending');
  assert.deepStrictEqual(node.getSetElements('crew', { offset: 5, limit: 5 }),
    sorted.slice(5, 10), 'page 2 sorted ascending');
  // Default page still covers a small set wholesale.
  assert.deepStrictEqual(node.getSetElements('crew'), sorted,
    'default page covers the set');
  // Out-of-range offset returns an empty page (snapshot semantics).
  assert.deepStrictEqual(node.getSetElements('crew', { offset: 100, limit: 5 }),
    [], 'out-of-range offset returns an empty page');

  // Cap rejections BEFORE the C call, mirroring wasm's message word.
  assert.throws(() => node.getSetElements('crew', { limit: 257 }),
    /\[1, 256\]/, 'limit above the 256 cap refused');
  assert.throws(() => node.getSetElements('crew', { limit: 0 }),
    /\[1, 256\]/, 'limit 0 refused');

  // Tags of an element with MULTIPLE live tags, sorted ascending.
  assert.deepStrictEqual(node.getSetTags('crew', 'alpha'),
    ['tag-alpha', 'tag-alpha-second'].sort(), 'both live tags read back');
  assert.deepStrictEqual(node.getSetTags('crew', 'beta'), ['tag-beta'],
    'single-tag element');
  assert.deepStrictEqual(node.getSetTags('crew', 'does-not-exist'), [],
    'unknown element returns an empty tag list');

  // Unknown names and wrong types surface the same typed words as wasm.
  assert.strictEqual(node.getSetSize('no-such-set'), 0,
    'getSetSize of an unknown name is 0');
  assert.throws(() => node.getSetElements('no-such-set'),
    /resource_not_found/, 'getSetElements of an unknown name refuses');
  assert.throws(() => node.getSetTags('no-such-set', 'alpha'),
    /resource_not_found/, 'getSetTags of an unknown name refuses');

  node.addCounter('not-a-set');
  assert.strictEqual(node.getSetSize('not-a-set'), 0,
    'getSetSize of a non-set is 0');
  assert.throws(() => node.getSetElements('not-a-set'),
    /type_mismatch/, 'getSetElements of a non-set refuses');
  assert.throws(() => node.getSetTags('not-a-set', 'alpha'),
    /type_mismatch/, 'getSetTags of a non-OR-set refuses');

  // Tombstone filtering: removing alpha kills BOTH its tags and drops it
  // from size + pages.
  node.setRemove('crew', 'alpha');
  assert.strictEqual(node.getSetSize('crew'), 9, 'size drops on remove');
  assert.deepStrictEqual(node.getSetElements('crew'),
    sorted.filter((element) => element !== 'alpha'),
    'alpha removed from enumeration');
  assert.deepStrictEqual(node.getSetTags('crew', 'alpha'), [],
    'all of alpha\'s tags tombstoned');

  // ==========================================================
  // Byte registers
  // ==========================================================
  node.addRegister('blob', 0);
  const payload = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x42]);
  node.setRegisterBytes('blob', payload);
  assert.deepStrictEqual(Array.from(node.getRegisterBytes('blob')),
    Array.from(payload), 'getRegisterBytes round trip');

  // node_id override accepted (mirrors wasm setRegisterBytes). The byte
  // register is opaque — the integer view only reports registers carrying a
  // full int64 (1 byte < 8, so getRegister reports undefined exactly as it
  // does for any short register).
  node.setRegisterBytes('blob', Buffer.from([0x01]), 'worker');
  assert.deepStrictEqual(Array.from(node.getRegisterBytes('blob')), [0x01],
    'byte register rewrite');
  assert.strictEqual(node.getRegister('blob'), undefined,
    'register payload below int64 is not reported by the integer view');

  // An empty write stores zero bytes; the readback is an empty Buffer.
  node.setRegisterBytes('blob', Buffer.alloc(0));
  assert.ok(Buffer.isBuffer(node.getRegisterBytes('blob')) &&
    node.getRegisterBytes('blob').length === 0,
    'empty register readback is an empty Buffer');

  // Typed refusals mirror the wasm export exactly: unknown name OR a
  // non-register item → resource_not_found on the write path; unknown
  // name → resource_not_found and non-register → type_mismatch on the
  // read path.
  assert.throws(() => node.setRegisterBytes('no-such', payload),
    /resource_not_found/, 'setRegisterBytes of an unknown name refuses');
  assert.throws(() => node.setRegisterBytes('not-a-set', payload),
    /resource_not_found/, 'setRegisterBytes of a non-register refuses');
  assert.throws(() => node.getRegisterBytes('no-such'),
    /resource_not_found/, 'getRegisterBytes of an unknown name refuses');
  assert.throws(() => node.getRegisterBytes('not-a-set'),
    /type_mismatch/, 'getRegisterBytes of a non-register refuses');

  // ==========================================================
  // BigInt-tolerant integer registers
  // ==========================================================
  node.addRegister('big', 0);
  const beyondSafe = 2n ** 53n + 3n; // 9007199254740993 — unsafe as Number
  node.setRegister('big', beyondSafe);
  const bigBytes = node.getRegisterBytes('big');
  assert.ok(bigBytes.length === 8 && bigBytes.readBigUInt64LE(0) === beyondSafe,
    'BigInt register stores the exact int64 bytes');
  // A safe-range BigInt reads back through getRegister like a number write.
  node.setRegister('big', 12345n);
  assert.strictEqual(node.getRegister('big'), 12345,
    'safe-range BigInt reads back as a number');
  // Plain numbers keep working.
  node.setRegister('big', 12345);
  assert.strictEqual(node.getRegister('big'), 12345,
    'plain number still accepted');
  // Fractional numbers and i64-overflow BigInts refuse.
  assert.throws(() => node.setRegister('big', 1.5), /integer/,
    'fractional number refused');
  assert.throws(() => node.setRegister('big', 2n ** 64n),
    /int64|integer|BigInt/, 'out-of-i64 BigInt refused');

  // ==========================================================
  // evaluateTriggers — the explicit tick
  // ==========================================================
  // The tick pins: an installed ISSUE_ATTRIBUTE trigger fires on the
  // explicit tick exactly as it does after a real op's post-execute pass.
  node.registerUser('bob', KeyPair.generate().publicKeyHex(), '');
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

  // Before the tick: the condition holds, the trigger has NOT run yet.
  node.incrementCounter('abuse_reports', 1, 'admin');
  assert.ok(!node.getUser('bob').attributes
    .some((attribute) => attribute.temporary),
    'no temp attribute before the tick');
  // The executor's post-execute pass did not run it either (only
  // incrementCounter mutations happened, no executed op).

  node.evaluateTriggers();
  const clearance = node.getUser('bob').attributes
    .find((attribute) => attribute.temporary);
  assert.ok(clearance, 'evaluateTriggers fires the pending trigger');
  assert.strictEqual(clearance.value, 'clearance:moderator',
    'temp attribute carries the plain C-matched token');

  // A subsequent immediate tick is suppressed by the trigger's cooldown
  // (60s > the elapsed machine time) — no second temp grant rides on top.
  node.incrementCounter('abuse_reports', 1, 'admin');
  node.evaluateTriggers();
  const clearanceCount = node.getUser('bob').attributes
    .filter((attribute) => attribute.temporary &&
                           attribute.value === 'clearance:moderator').length;
  assert.strictEqual(clearanceCount, 1,
    'a cooldown-suppressed tick does not re-issue the attribute');

  // ==========================================================
  // Operation.deserialize — the wire round trip
  // ==========================================================
  const aliceKey = KeyPair.generate();
  const op = new Operation('report');
  op.signerId = 'alice';
  op.nodeId = 'alice';
  op.addResource('reports'); // a counter item name; see the fresh machine below
  // Sign through a machine context (node.sign, NOT op.sign) so the op
  // carries the R7-04 signer_key_version stamp — every real op rides one.
  const node1 = new Node('admin1', { ordering: 'hlc' });
  node1.registerUser('alice', aliceKey.publicKeyHex(), '');
  node1.sign(op, aliceKey);
  const opWire = op.serialize();

  const restored = Operation.deserialize(opWire);
  assert.strictEqual(restored.type, 'report', 'type rides the wire');
  assert.strictEqual(restored.signerId, 'alice', 'signerId rides the wire');
  assert.strictEqual(restored.nodeId, 'admin1',
    'nodeId rides the wire (node.sign stamps the machine\'s HLC identity)');
  assert.strictEqual(restored.getWireVersion(), op.getWireVersion(),
    'wire version preserved');
  // Re-serialization is byte-identical (canonical op form).
  assert.ok(Buffer.compare(opWire, restored.serialize()) === 0,
    're-serialization is byte-identical');
  // A malformed image refuses loudly, never silently.
  assert.throws(() => Operation.deserialize(Buffer.from([0x00, 0x01])),
    /malformed|failed|could not/i, 'garbage op wire refuses');
  // The restored op is not an alien blob — it executes like any adopted op
  // object on a compatible machine (the P1 state-restore precedent). alice's
  // registration carries the clearance through the initial-attribute path so
  // her key_version stays 0 — matching the op's unstamped signer version.
  const node2 = new Node('admin2', { ordering: 'hlc' });
  node2.registerUser('alice', aliceKey.publicKeyHex(), 'clearance:level1');
  node2.addCounter('reports');
  node2.setPolicy('report', 'clearance:level1');
  node2.execute(restored);
  console.log('binding-alignment OK');
})().catch((failure) => {
  console.error('binding-alignment FAILED:', failure);
  process.exit(1);
});