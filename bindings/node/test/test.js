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

// Test 22: a fresh node defaults to the system clock — no authenticated
// source attached until setTimeSource says so.
const freshClock = node.getTimeSource();
assert(freshClock.mode === 'system',
  'fresh node getTimeSource should report mode system');

// Test 23: switch to the authenticated HTTPS time source. No fetch happens
// at attach time (the query runs lazily inside authenticated-time checks),
// so this must succeed with no network dependency. getTimeSource echoes the
// stored selection: default endpoint (url null) and the documented
// CRABS_TIME_SOURCE_DEFAULT_* numbers (30000/1000/5000).
node.setTimeSource({ mode: 'https' });
const httpsDefault = node.getTimeSource();
assert(httpsDefault.mode === 'https', 'https selection should report mode https');
assert(httpsDefault.url === null, 'default endpoint should surface as url null');
assert(httpsDefault.resyncMs === 30000 && httpsDefault.timeoutMs === 1000 &&
       httpsDefault.maxSkewMs === 5000,
  'omitted numbers should echo the documented defaults');
assert(httpsDefault.created === true, 'https ops object should be live');

// Test 24: custom url and numeric overrides are echoed; resync 0 is a real
// value (re-query every fetch), NOT a default request.
node.setTimeSource({ mode: 'https', url: 'https://time.example.com/trace',
                     resyncMs: 0, timeoutMs: 2000, maxSkewMs: 9000 });
const httpsCustom = node.getTimeSource();
assert(httpsCustom.url === 'https://time.example.com/trace',
  'configured url should be echoed');
assert(httpsCustom.resyncMs === 0 && httpsCustom.timeoutMs === 2000 &&
       httpsCustom.maxSkewMs === 9000,
  'numeric overrides should be echoed (resync 0 kept as 0)');
assert(httpsCustom.created === true, 'replacement ops object should be live');

// Test 25: back to the system clock — detaches and destroys the owned ops.
node.setTimeSource({ mode: 'system' });
assert(node.getTimeSource().mode === 'system',
  'system selection should report mode system');

// Test 26: typed rejections — bogus mode / missing mode / non-object arg.
function expectTimeSourceRejection(thunk, errorType, label) {
  try {
    thunk();
    assert(false, `${label} should throw ${errorType.name}`);
  } catch (rejection) {
    assert(rejection instanceof errorType &&
           rejection.message.includes('setTimeSource'),
      `${label} should throw a typed setTimeSource error`);
  }
}
expectTimeSourceRejection(() => node.setTimeSource({ mode: 'ntp' }),
  TypeError, 'setTimeSource({mode: ntp})');
expectTimeSourceRejection(() => node.setTimeSource({}),
  TypeError, 'setTimeSource({}) (missing mode)');
expectTimeSourceRejection(() => node.setTimeSource('https'),
  TypeError, 'setTimeSource(string)');
expectTimeSourceRejection(() => node.setTimeSource(),
  TypeError, 'setTimeSource() (no arg)');
expectTimeSourceRejection(() => node.setTimeSource({ mode: 'https',
                                                     timeoutMs: 'fast' }),
  TypeError, 'setTimeSource(string timeoutMs)');
expectTimeSourceRejection(() => node.setTimeSource({ mode: 'https',
                                                     resyncMs: -1 }),
  RangeError, 'setTimeSource(negative resyncMs)');
expectTimeSourceRejection(() => node.setTimeSource({ mode: 'https',
                                                     maxSkewMs: NaN }),
  RangeError, 'setTimeSource(NaN maxSkewMs)');

// Test 27: url validation mirrors the CLI checks — http://, empty host and
// over-long urls are RangeErrors and change NOTHING on the node.
expectTimeSourceRejection(() => node.setTimeSource({ mode: 'https',
                                                     url: 'http://example.com/t' }),
  RangeError, 'setTimeSource(http:// url)');
expectTimeSourceRejection(() => node.setTimeSource({ mode: 'https',
                                                     url: 'https://' }),
  RangeError, 'setTimeSource(empty host)');
expectTimeSourceRejection(() => node.setTimeSource({ mode: 'https',
                                                     url: 'https:///' }),
  RangeError, 'setTimeSource(slash host)');
expectTimeSourceRejection(() => node.setTimeSource({ mode: 'https',
    url: 'https://' + 'a'.repeat(256) }),
  RangeError, 'setTimeSource(url > 255 chars)');
assert(node.getTimeSource().mode === 'system',
  'rejected setTimeSource calls must leave the selection untouched');

// Test 28: write-domains v1 — defineItem with the sovereign domain, a
// writer op accepted through setSovereignPrefix, a non-writer op rejected
// with not_item_writer.
const domainNode = new Node('dom-admin');
const aliceDomKey = KeyPair.generate();
domainNode.registerUser('alice', aliceDomKey.publicKeyHex(), '');
domainNode.grantRole('alice', 'role', 'member', 'dom-admin');
const malloryDomKey = KeyPair.generate();
domainNode.registerUser('mallory', malloryDomKey.publicKeyHex(), '');
domainNode.grantRole('mallory', 'role', 'member', 'dom-admin');

domainNode.defineItem('score', 'counter', 'g_counter',
  { domain: 'sovereign', writer: 'alice' });
domainNode.addCounter('free-counter');  // untouched free-merge default
domainNode.setPolicy('bump', 'role:member');

// defineItem argument checking: sovereign without a writer, a writer on a
// non-sovereign domain, an unknown domain word, and a non-legal type are
// all refused before anything reaches state.
function expectDefineItemRejection(errorType, thunk, label) {
  try {
    thunk();
    assert(false, `${label} should throw`);
  } catch (defineRejection) {
    assert(defineRejection instanceof errorType,
      `${label} should throw ${errorType.name}, got ${defineRejection}`);
  }
}
expectDefineItemRejection(Error, () =>
  domainNode.defineItem('orphan', 'counter', 'g_counter',
    { domain: 'sovereign' }), 'sovereign without writer');
expectDefineItemRejection(Error, () =>
  domainNode.defineItem('mixed', 'counter', 'g_counter',
    { domain: 'free', writer: 'alice' }), 'writer on free item');
expectDefineItemRejection(TypeError, () =>
  domainNode.defineItem('odd', 'counter', 'g_counter',
    { domain: 'feudal' }), 'unknown domain word');
expectDefineItemRejection(Error, () =>
  domainNode.defineItem('doc', 'set', 'or_set',
    { domain: 'sovereign', writer: 'alice' }), 'sovereign on set (v1 type bound)');

// setSovereignPrefix argument checking: the digest is exactly 64 hex
// chars, the index is bounded by the op's resource capacity.
const guardOp = new Operation('bump');
guardOp.addResource('score');
try {
  guardOp.setSovereignPrefix(0, 0, 'abcd');
  assert(false, 'short digestHex should throw');
} catch (digestRejection) {
  assert(digestRejection instanceof RangeError,
    'short digestHex should throw a RangeError');
}
try {
  guardOp.setSovereignPrefix(0, 0, 'z'.repeat(64));
  assert(false, 'non-hex digestHex should throw');
} catch (digestRejection) {
  assert(digestRejection instanceof TypeError,
    'non-hex digestHex should throw a TypeError');
}
// A fractional seq or one past JS's exact-integer range would truncate
// silently on the double → uint64 conversion; refuse loudly instead.
for (const badSeq of [1.5, -2, Number.MAX_SAFE_INTEGER + 1]) {
  try {
    guardOp.setSovereignPrefix(0, badSeq, '0'.repeat(64));
    assert(false, `seq ${badSeq} should throw`);
  } catch (seqRejection) {
    assert(seqRejection instanceof RangeError,
      `seq ${badSeq} should throw a RangeError`);
  }
}

// The writer's first op on the fresh chain: seq 0 with the all-zero
// initial digest. Signed by alice; the DOMAIN_CHECK matches the prefix
// against the item and the wildcard apply accepts it (no handler needed).
const ZERO_DIGEST = '0'.repeat(64);
const writerOp = new Operation('bump');
writerOp.signerId = 'alice';
writerOp.addResource('score');
writerOp.setSovereignPrefix(0, 0, ZERO_DIGEST);
domainNode.sign(writerOp, aliceDomKey);
const opAWire = writerOp.serialize();
domainNode.execute(writerOp);

// A non-writer op on the sovereign item is rejected with not_item_writer
// even though mallory holds the authorizing role.
const rogueOp = new Operation('bump');
rogueOp.signerId = 'mallory';
rogueOp.addResource('score');
rogueOp.setSovereignPrefix(0, 1, ZERO_DIGEST);
domainNode.sign(rogueOp, malloryDomKey);
try {
  domainNode.execute(rogueOp);
  assert(false, 'non-writer op on a sovereign item should throw');
} catch (rogueRejection) {
  assert(rogueRejection.message.includes('not_item_writer'),
    'non-writer rejection should be typed not_item_writer, got: ' +
    rogueRejection.message);
}

// Test 29: write-domains v1 — a genuine fork reported through
// reportEquivocation quarantines the writer; false evidence sets nothing.
// The fork: op_b is a second alice-signed claim to the same chain head
// (seq 0, zero digest) that never executed here — minted fresh (random uuid)
// so it is provably distinct from op_a's wire bytes.
const forkOp = new Operation('bump');
forkOp.signerId = 'alice';
forkOp.addResource('score');
forkOp.setSovereignPrefix(0, 0, ZERO_DIGEST);
domainNode.sign(forkOp, aliceDomKey);
const opBWire = forkOp.serialize();
assert(Buffer.compare(Buffer.from(opAWire), Buffer.from(opBWire)) !== 0,
  'fork evidence must be two distinct serialized ops');

domainNode.setPolicy('__report_equivocation__', 'role:admin');
domainNode.reportEquivocation('score', opAWire, opBWire);

// The quarantined writer's later op is rejected with 'quarantined'.
const quarantinedOp = new Operation('bump');
quarantinedOp.signerId = 'alice';
quarantinedOp.addResource('score');
quarantinedOp.setSovereignPrefix(0, 1, ZERO_DIGEST);
domainNode.sign(quarantinedOp, aliceDomKey);
try {
  domainNode.execute(quarantinedOp);
  assert(false, 'quarantined writer op should throw');
} catch (quarantineRejection) {
  assert(quarantineRejection.message.includes('quarantined'),
    'quarantined writer rejection should be typed quarantined, got: ' +
    quarantineRejection.message);
}

// Failure paths: same-op-twice is invalid evidence (nothing changes), a
// non-sovereign target is refused up front, and an unknown item is
// resource_not_found.
try {
  domainNode.reportEquivocation('score', opAWire, opAWire);
  assert(false, 'same-op-twice report should throw');
} catch (sameEvidence) {
  assert(sameEvidence.message.includes('invalid_param'),
    'same-op-twice should be typed invalid_param, got: ' +
    sameEvidence.message);
}
try {
  domainNode.reportEquivocation('free-counter', opAWire, opBWire);
  assert(false, 'report against a free-merge item should throw');
} catch (nonSovereign) {
  assert(nonSovereign.message.includes('invalid_param'),
    'free-merge target should be typed invalid_param');
}
try {
  domainNode.reportEquivocation('ghost', opAWire, opBWire);
  assert(false, 'report against an unknown item should throw');
} catch (unknownItem) {
  assert(unknownItem.message.includes('resource_not_found'),
    'unknown item should be typed resource_not_found');
}

// A duplicate re-report is idempotently deduped (report ≠ a new fork).
try {
  domainNode.reportEquivocation('score', opBWire, opAWire);
  assert(false, 'swapped duplicate report should throw');
} catch (duplicateReport) {
  assert(duplicateReport.message.includes('duplicate_operation'),
    're-report should be typed duplicate_operation, got: ' +
    duplicateReport.message);
}


console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);