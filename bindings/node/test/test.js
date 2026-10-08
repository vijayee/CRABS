//
// test.js — Basic smoke test for the crabs-node bindings.
//

'use strict';

const { Node, KeyPair, Operation, Blueprint } = require('..');

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) {
    passed++;
  } else {
    failed++;
    console.error('FAIL:', msg);
  }
}

// Test 1: KeyPair generation
const kp = KeyPair.generate();
assert(kp.publicKeyHex().length === 66, 'Public key should be 66 hex chars');
assert(kp.privateKeyHex().length === 64, 'Private key should be 64 hex chars');

// Test 2: Derive public from private
const pubHex = KeyPair.derivePublicHex(kp.privateKeyHex());
assert(pubHex === kp.publicKeyHex(), 'Derived public key should match');

// Test 3: Node creation with HLC
const node = new Node('admin', { ordering: 'hlc' });
assert(node !== null, 'Node should be created');

// Test 4: Get node key
const nodeKey = node.getNodeKey();
assert(nodeKey.publicKeyHex.length === 66, 'Node public key should be 66 hex chars');

// Test 5: Register a user
// register_user rejects privileged (role:) initial attributes (audit R7-08),
// so the role is granted via the admin grantRole path after registration.
const aliceKey = KeyPair.generate();
node.registerUser('alice', aliceKey.publicKeyHex(), '');
node.grantRole('alice', 'role', 'member', 'admin');
const alice = node.getUser('alice');
assert(alice !== undefined, 'Alice should be found');
assert(alice.userId === 'alice', 'Alice userId should match');
assert(alice.status === 'active', 'Alice should be active');

// Test 6: Add data items
node.addCounter('views');
node.addPNCounter('likes');
node.addORSet('subscribers');
node.addOneShotSet('flaggers');
node.addOneShotFlag('flag_triggered');

// Test 7: Set policies
node.setPolicy('view', 'role:member');
node.setPolicy('like', 'role:member');
node.setPolicy('subscribe', 'role:member');

// Test 8: Execute a signed operation (use node.sign to stamp HLC before signing).
// Landed C contract (declared-but-unimplemented ops): a non-builtin op with
// a policy but NO handler and NO resources fails closed with
// resource_not_found — no successful empty operations are logged. The view
// effect is simulated directly with incrementCounter.
const viewOp = new Operation('view');
viewOp.signerId = 'alice';
node.sign(viewOp, aliceKey);
let handlerlessRefused = false;
try {
  node.execute(viewOp);
} catch (handlerlessRefusal) {
  handlerlessRefused = handlerlessRefusal.message.includes('resource_not_found');
}
assert(handlerlessRefused,
  'Handlerless view op should fail closed with resource_not_found');
node.incrementCounter('views', 1, 'alice');
assert(node.getCounter('views') === 1, 'Views should be 1 after one view');

// Test 9: HLC timestamp
const hlc = node.getHLC();
assert(hlc !== undefined, 'HLC should be available');
assert(hlc.nodeId === 'admin', 'HLC node ID should be admin');
assert(typeof hlc.formatted === 'string', 'HLC should have formatted string');

// Test 10: Direct set operations
node.setAdd('subscribers', 'alice', 'alice_sub_1');
assert(node.setContains('subscribers', 'alice') === true, 'Alice should be in subscribers');

// Test 11: Grant role
node.grantRole('alice', 'clearance', 'level3', 'admin');
const alice2 = node.getUser('alice');
const hasClearance = alice2.attributes.some(a => a.value === 'clearance:level3');
assert(hasClearance, 'Alice should have clearance:level3');

// Test 12: Self-assert
node.selfAssert('nickname', 'Alice', 'alice');
const alice3 = node.getUser('alice');
const hasNickname = alice3.attributes.some(a => a.value === 'nickname:Alice');
assert(hasNickname, 'Alice should have nickname:Alice');

// Test 13: Self-assert privileged name should fail
try {
  node.selfAssert('role', 'admin', 'alice');
  assert(false, 'Self-asserting role:admin should fail');
} catch (e) {
  assert(e.message.includes('unauthorized') || e.message.includes('invalid_param'),
    'Self-asserting role:admin should throw');
}

// Test 14: Flag set
node.flagSet('flag_triggered', 'alice', 1000);
assert(node.flagValue('flag_triggered') === true, 'Flag should be set');

// Test 15: Serialize
const serialized = node.serialize();
assert(Buffer.isBuffer(serialized), 'Serialize should return a Buffer');
assert(serialized.length > 0, 'Serialized state should not be empty');

// Test 16: change events fire on execute and registerUser; off() unsubscribes
const changeEvents = [];
const bobKey = KeyPair.generate();
const carolKey = KeyPair.generate();
const unsubscribeChange = node.on('change', (changeEvent) => changeEvents.push(changeEvent));

// Driver for the 'op'-kind event: a successful EXECUTE. The 'view' op fails
// closed per the landed declared-but-unimplemented contract (test 8), so the
// driver is a lineage op with a handler: __spawn_machine__ carrying a
// blueprint wire payload, signed/stamped via node.sign and executed by the
// node's admin (role:admin, the lineage default policy).
node.lineageInstall();
const spawnBlueprint = new Blueprint('test-child', 'delegated_copy', 'child-admin', 60000);
spawnBlueprint.addItem('flag_a', 'one_shot_flag', 'one_shot_flag');
const spawnOp = new Operation('__spawn_machine__');
spawnOp.signerId = 'admin';
spawnOp.nodeId = 'admin';
spawnOp.payload = spawnBlueprint.serialize();
node.sign(spawnOp, node.getNodeKey().privateKeyHex);
node.execute(spawnOp);
const opChangeEvent = changeEvents.find(
  (changeEvent) => changeEvent.kind === 'op' && changeEvent.type === '__spawn_machine__');
assert(opChangeEvent !== undefined, 'execute should fire an op change event');
assert(opChangeEvent.signer === 'admin', 'Op change event should name the signer');
assert(opChangeEvent.result === 0, 'Op change event should report success');

node.registerUser('bob', bobKey.publicKeyHex(), '');
assert(changeEvents.some((changeEvent) => changeEvent.kind === 'attribute'),
  'registerUser should fire an attribute change event');

const eventCountBeforeUnsubscribe = changeEvents.length;
unsubscribeChange();
node.registerUser('carol', carolKey.publicKeyHex(), '');
assert(changeEvents.length === eventCountBeforeUnsubscribe,
  'unsubscribed listener must not fire');
assert(node.getUser('carol') !== undefined,
  'Mutations after unsubscribe should still apply');

// Test 17: createTrigger with oversized fields must not corrupt the stack.
// Audit 9 A-1: the payload builder accumulated snprintf return values, which
// are the WOULD-BE length on truncation — unchecked, `pos` overruns the
// payload buffer and `sizeof(payload) - pos` underflows to a huge size_t.
// The id and condition below are far longer than the 4096-byte payload
// combined; the call must truncate (or error) but never write out of bounds.
try {
  node.createTrigger({
    triggerId: 'a'.repeat(3000),
    condition: 'b'.repeat(3000) + ' >= 1',
    effectType: 'issue_attribute',
    issueAttribute: 'c'.repeat(3000),
    targetRole: 'role',
    attributeValue: 'd'.repeat(3000),
  });
  assert(true, 'createTrigger with oversized fields should not crash');
} catch (e) {
  // A rejection is acceptable too — the point is no out-of-bounds write.
  assert(true, 'createTrigger with oversized fields rejected cleanly');
}

// Test 18: createTrigger on an adopted child wrapper must throw, not segfault.
// Audit 10 A10-M3: a spawned (borrowed) child Node wrapper carries no own node
// key (node_key_ == nullptr); CreateTrigger used to dereference it blindly.
// The spawn below happened in test 16 — grab the borrowed wrapper back from
// the resident registry and demand a typed refusal.
const adoptedChild = node.lineageResidentChild('test-child');
assert(adoptedChild !== null, 'spawned test-child should be resident');
let adoptedTriggerRefused = false;
try {
  adoptedChild.createTrigger({
    triggerId: 'adopted-trigger',
    condition: 'true',
    effectType: 'issue_attribute',
    issueAttribute: 'temp:x',
    targetRole: 'role',
    attributeValue: 'member',
  });
} catch (adoptedRefusal) {
  adoptedTriggerRefused = adoptedRefusal instanceof Error &&
    adoptedRefusal.message.includes('no own node key');
}
assert(adoptedTriggerRefused,
  'createTrigger on an adopted child wrapper must throw (no own node key)');

// Test 19: change listeners registering/unregistering mid-emit (A10-M4).
// A synchronous listener that calls node.on('change', …) pushes into the
// listener vector while EmitChange iterates it (reallocating the storage);
// dispatch must survive via the snapshot, and the new listener fires on the
// NEXT event, not the one that spawned it.
const lateEvents = [];
let registeredMidEmit = false;
let lateOff = null;
const registrarOff = node.on('change', () => {
  if (!registeredMidEmit) {
    registeredMidEmit = true;
    lateOff = node.on('change', (lateEvent) => lateEvents.push(lateEvent));
  }
});
node.registerUser('dave', KeyPair.generate().publicKeyHex(), '');
assert(lateEvents.length === 0,
  'listener registered mid-emit must not see the event that spawned it');
node.registerUser('erin', KeyPair.generate().publicKeyHex(), '');
assert(lateEvents.length > 0,
  'listener registered mid-emit must fire on the next event');
registrarOff();
lateOff();

// Test 20: a self-unregistering listener must not break the dispatch loop —
// every other listener still receives the event being delivered.
const survivorEvents = [];
let selfOffHandle = null;
selfOffHandle = node.on('change', () => { selfOffHandle(); });
const survivorOff = node.on('change',
  (survivorEvent) => survivorEvents.push(survivorEvent));
node.registerUser('frank', KeyPair.generate().publicKeyHex(), '');
assert(survivorEvents.length > 0,
  'listeners must still fire when an earlier listener unregisters itself');
survivorOff();

// Test 21: typed rejection of non-string arguments (A10-L12). Unguarded
// As<Napi::String>() conversions used to coerce or die untyped; every
// JS-controlled string boundary now throws a TypeError naming the field.
function expectTypeError(thunk, label) {
  try {
    thunk();
    assert(false, `${label} should throw a TypeError`);
  } catch (typeRejection) {
    assert(typeRejection instanceof TypeError &&
           typeRejection.message.includes('must be a string'),
      `${label} should throw a typed 'must be a string' error`);
  }
}
expectTypeError(() => node.addCounter(42), 'addCounter(number)');
expectTypeError(() => node.getUser(null), 'getUser(null)');
expectTypeError(() => node.revokeUser({}), 'revokeUser(object)');
expectTypeError(() => node.setPolicy('view', 7), 'setPolicy(number expr)');
expectTypeError(() => node.createTrigger({ triggerId: 1, condition: 'true',
                                           effectType: 'issue_attribute' }),
  'createTrigger(number triggerId)');
const typedOp = new Operation('typed');
expectTypeError(() => { typedOp.signerId = 42; }, 'Operation.signerId = number');

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);