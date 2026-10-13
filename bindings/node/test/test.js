//
// test.js — Basic smoke test for the crabs-node bindings.
//

'use strict';

const { Node, KeyPair, Operation, Blueprint, wireVersions } = require('..');

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

// The writer's SECOND op must claim the live chain head; itemChainHead is
// the binding-side read for it. seq advances to 2 on accept.
const headAfterFirst = domainNode.itemChainHead('score');
assert(headAfterFirst.seq === 1,
  'head seq should advance to 1 after the first accepted write');
assert(/^[0-9a-f]{64}$/.test(headAfterFirst.digestHex),
  'head digest should be a full 32-byte hex string');
assert(headAfterFirst.digestHex !== ZERO_DIGEST,
  'head digest should be recomputed after the first op');
try {
  domainNode.itemChainHead('ghost');
  assert(false, 'itemChainHead on an unknown item should throw');
} catch (unknownItem) {
  assert(unknownItem.message.includes('resource_not_found'),
    'unknown-item head read should be typed resource_not_found, got: ' +
    unknownItem.message);
}
const secondWriterOp = new Operation('bump');
secondWriterOp.signerId = 'alice';
secondWriterOp.addResource('score');
secondWriterOp.setSovereignPrefix(0, headAfterFirst.seq,
                                  headAfterFirst.digestHex);
domainNode.sign(secondWriterOp, aliceDomKey);
domainNode.execute(secondWriterOp);
assert(domainNode.itemChainHead('score').seq === 2,
  'head seq should advance to 2 after the second accepted write');

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

// Test: setRegister is integer-only (consumption finding 1). NaN, Infinity,
// fractional values, and |value| > Number.MAX_SAFE_INTEGER reject BEFORE the
// C conversion can silently truncate. The node binding takes numbers only.
{
  node.addRegister('guard_slot', 0);
  const INTEGER_ONLY =
    'registers are integer-only; encode fractional values in register units (e.g. per-mille)';
  const SAFE_INTEGER =
    'registers are integer-only; |value| exceeds Number.MAX_SAFE_INTEGER';
  const mustThrowWith = (invoke, fragment, label) => {
    let caught = null;
    try { invoke(); } catch (caughtError) { caught = caughtError; }
    assert(caught !== null, `${label}: expected a throw`);
    assert(caught && caught.message.includes(fragment),
      `${label}: expected message containing "${fragment}", got "${caught && caught.message}"`);
  };

  mustThrowWith(() => node.setRegister('guard_slot', 1.5), INTEGER_ONLY, 'fractional 1.5');
  mustThrowWith(() => node.setRegister('guard_slot', -0.25), INTEGER_ONLY, 'fractional -0.25');
  mustThrowWith(() => node.setRegister('guard_slot', NaN), INTEGER_ONLY, 'NaN');
  mustThrowWith(() => node.setRegister('guard_slot', Infinity), INTEGER_ONLY, '+Infinity');
  mustThrowWith(() => node.setRegister('guard_slot', -Infinity), INTEGER_ONLY, '-Infinity');

  mustThrowWith(() => node.setRegister('guard_slot', Number.MAX_SAFE_INTEGER + 1),
    SAFE_INTEGER, 'MAX_SAFE_INTEGER + 1');
  mustThrowWith(() => node.setRegister('guard_slot', -(Number.MAX_SAFE_INTEGER + 1)),
    SAFE_INTEGER, '-(MAX_SAFE_INTEGER + 1)');
  mustThrowWith(() => node.setRegister('guard_slot', 2 ** 60),
    SAFE_INTEGER, '2^60');

  // Boundaries pass through verbatim.
  node.setRegister('guard_slot', Number.MAX_SAFE_INTEGER);
  assert(node.getRegister('guard_slot') === Number.MAX_SAFE_INTEGER,
    '+MAX_SAFE_INTEGER should round-trip');
  node.setRegister('guard_slot', -Number.MAX_SAFE_INTEGER);
  assert(node.getRegister('guard_slot') === -Number.MAX_SAFE_INTEGER,
    '-MAX_SAFE_INTEGER should round-trip');

  // Ordinary integers still set.
  node.setRegister('guard_slot', -7, 'alice');
  assert(node.getRegister('guard_slot') === -7, 'integer -7 should land');
}

// Wire-version diagnostics (consumption-fixes finding 5): the constants are
// exposed (no JS mirror drift), frozen, and match the documented build
// values. Operation.getWireVersion() reports the active op format on a
// fresh op.
{
  assert(wireVersions && typeof wireVersions === 'object',
    'wireVersions should be exposed');
  assert(wireVersions.state === 17,
    `wireVersions.state=${wireVersions.state}, expected 17`);
  assert(wireVersions.op === 6,
    `wireVersions.op=${wireVersions.op}, expected 6`);
  assert(wireVersions.signing === 4,
    `wireVersions.signing=${wireVersions.signing}, expected 4`);
  assert(Object.isFrozen(wireVersions), 'wireVersions must be frozen');

  const probe = new Operation('probe');
  assert(probe.getWireVersion() === wireVersions.op,
    `fresh op getWireVersion=${probe.getWireVersion()}, expected ${wireVersions.op}`);
}

// Test: createTrigger must sign with the machine's REAL admin identity, not
// a hardcoded 'admin' string. This machine's admin is deliberately 'chair' —
// the node key is registered under 'chair', so the install op must land with
// signer 'chair' (the old code stamped signer_id 'admin', which has no user
// record here and refuses with key_stale/unauthorized).
{
  const chairNode = new Node('chair', { ordering: 'hlc' });
  chairNode.addCounter('reports');
  const patientKey = KeyPair.generate();
  chairNode.registerUser('patient', patientKey.publicKeyHex(), '');
  chairNode.grantRole('patient', 'role', 'member', 'chair');
  chairNode.setPolicy('__create_trigger__', 'role:admin');
  chairNode.setPolicy('tick', 'role:admin');

  const installEvents = [];
  chairNode.on('change', (changeEvent) => {
    if (changeEvent.kind === 'op' &&
        changeEvent.type === '__create_trigger__') {
      installEvents.push(changeEvent);
    }
  });

  let installError = '';
  try {
    chairNode.createTrigger({
      triggerId: 'chair_flag',
      condition: 'reports >= 1',
      effectType: 'issue_attribute',
      issueAttribute: 'flagged',
      targetRole: 'role',
      attributeValue: 'member',
      durationMs: 600000,  // 0 would expire the grant instantly on readback
    });
  } catch (installRefusal) {
    installError = String(installRefusal.message);
  }
  assert(installError === '',
    `createTrigger under admin 'chair' must not throw, got "${installError}"`);
  assert(installEvents.length === 1 && installEvents[0].result === 0 &&
           installEvents[0].signer === 'chair',
    `createTrigger under admin 'chair' must land signed by 'chair', got ` +
    JSON.stringify(installEvents));

  // The trigger must actually install, not just not-throw: cross the
  // threshold and drive a landing op; the temporary attribute fires.
  chairNode.incrementCounter('reports', 1, 'chair');
  const tickOp = new Operation('tick');
  tickOp.signerId = 'chair';
  tickOp.addResource('reports');
  chairNode.sign(tickOp, chairNode.getNodeKey().privateKeyHex);
  chairNode.execute(tickOp);
  const patient = chairNode.getUser('patient');
  assert(patient !== undefined &&
           patient.attributes.some((attribute) =>
             attribute.temporary && attribute.value === 'flagged:member'),
    'trigger installed by non-\'admin\' admin must fire and grant the attribute');
}

// Test: defineOperationType — the DedupSpec op-type registration surface.
// A '__define_operation_type__' op signed with the node key registers a
// machine-enforced spec (state_register_op_type_def); the executor then
// resolves it for every later op of that type and refuses a second attempt
// from the same signer with the dedup domain error, no driver-side guard
// involved (state_machine_op_check_dedup / dedup_check_guard_spec).
{
  const voteNode = new Node('admin', { ordering: 'hlc' });
  const voterKey = KeyPair.generate();
  const memberKey = KeyPair.generate();
  voteNode.registerUser('alice', voterKey.publicKeyHex(), '');
  voteNode.registerUser('bob', memberKey.publicKeyHex(), '');
  voteNode.grantRole('alice', 'role', 'member', 'admin');
  voteNode.grantRole('bob', 'role', 'member', 'admin');

  // The tracker must exist: the executor validates the spec's tracker item
  // before the handler (dedup_validate_mutation_spec). The tracker IS the
  // record — no handler surface exists on crabs-node, and none is needed:
  // the applied spec mutation writes membership.
  voteNode.addOneShotSet('proposal-42_voters');
  voteNode.setPolicy('__define_operation_type__', 'role:admin');
  voteNode.setPolicy('vote', 'role:member');

  voteNode.defineOperationType('vote', {
    dedup: 'per-user',
    trackerPath: 'proposal-42_voters',
    rejectionMessage: 'already_performed',
  });

  // One vote per signer: the op carries no dedup spec at all (the F-2
  // bypass shape) — the registered spec is what enforces.
  const castVote = (key, voter) => {
    const op = new Operation('vote');
    op.signerId = voter;
    op.addResource('proposal-42_voters');  // the once-record the op touches
    voteNode.sign(op, key);
    voteNode.execute(op);
  };

  castVote(voterKey, 'alice');
  castVote(memberKey, 'bob');
  assert(voteNode.setContains('proposal-42_voters', 'alice') &&
           voteNode.setContains('proposal-42_voters', 'bob'),
    'the registered spec must record both voters in the tracker');

  let doubleVoteRefused = false;
  try {
    castVote(voterKey, 'alice');
  } catch (retryRefusal) {
    doubleVoteRefused = retryRefusal.message.includes('already_performed');
  }
  assert(doubleVoteRefused,
    "a second vote from the same signer must be refused with 'already_performed'");
  assert(!voteNode.setContains('proposal-42_voters', 'carol'),
    'the refused retry must not add new membership');
}

// Test: schedule surface — timed transactions on crabs-node (recipe 7).
// Mirrors bindings/wasm/test/schedules.js: a one-off mint, the not-due
// idempotent skip, due materializes exactly once, cancel + tick past ->
// never fires, a recurring 3-fire catch-up in order, and the per-tick
// occurrence budget. crabs-node has no registerHandlerJs surface, so the
// scheduled op drives the machine's wildcard path (a policy-authorized
// type naming an existing resource) and each materialized slot is
// observable as a 'schedule'-kind change event with a "scheduled <op>"
// preview — the submission event instead says "scheduled at <ms>" (the
// ChangeHookFiresPerMaterializedSlot shape in test/test_scheduler.cpp).
{
  const schedNode = new Node('admin', { ordering: 'hlc' });
  const mintKey = KeyPair.generate();
  schedNode.registerUser('alice', mintKey.publicKeyHex(), '');
  schedNode.grantRole('alice', 'role', 'member', 'admin');
  const outsiderKey = KeyPair.generate();
  schedNode.registerUser('mallory', outsiderKey.publicKeyHex(), '');
  schedNode.setPolicy('mint', 'role:member');
  schedNode.addCounter('tokens');

  const scheduleEvents = [];  // kind 'schedule', type 'mint'
  const failureEvents = [];   // kind 'schedule', type '__schedule_failed__'
  schedNode.on('change', (changeEvent) => {
    if (changeEvent.kind !== 'schedule') return;
    if (changeEvent.type === '__schedule_failed__') failureEvents.push(changeEvent);
    else if (changeEvent.type === 'mint') scheduleEvents.push(changeEvent);
  });
  const fireEvents = () => scheduleEvents.filter(
    (changeEvent) => !changeEvent.preview.startsWith('scheduled at '));

  const signMintOp = () => {
    const op = new Operation('mint');
    op.signerId = 'alice';
    op.addResource('tokens');
    schedNode.sign(op, mintKey);
    return op;
  };

  // Fixed demo clock, mirroring schedules.js:30 — never the wall clock.
  const now = 1000000000000;

  // Submission-time authorization: the wrapper must validate (policy +
  // signature + key version) BEFORE queueing, mirroring
  // crabs_wasm_schedule's state_machine_validate gate.
  const unauthorized = new Operation('mint');
  unauthorized.signerId = 'mallory';
  unauthorized.addResource('tokens');
  schedNode.sign(unauthorized, outsiderKey);
  let scheduleUnauthorizedRefused = false;
  try {
    schedNode.schedule(unauthorized, now + 5000);
  } catch (authorizationRefusal) {
    scheduleUnauthorizedRefused =
      authorizationRefusal.message.includes('unauthorized');
  }
  assert(scheduleUnauthorizedRefused,
    'schedule must refuse an op whose signer lacks the policy (unauthorized)');

  // One-off: mint in +60s.
  const scheduleId = schedNode.schedule(signMintOp(), now + 60000);
  assert(scheduleId > 0n && typeof scheduleId === 'bigint',
    `schedule must return a positive bigint id, got ${scheduleId}`);
  assert(schedNode.pendingSchedules().length === 1,
    `one scheduled op must be pending, got ${schedNode.pendingSchedules().length}`);
  assert(schedNode.pendingSchedules()[0].submitter === 'alice',
    'pending row must name the submitter');
  assert(schedNode.pendingSchedules()[0].executeAt === BigInt(now + 60000),
    'pending row must carry the due time');

  // Not due yet: nothing materializes.
  schedNode.processSchedules(now);
  assert(schedNode.pendingSchedules().length === 1,
    `a not-due tick must keep the op pending, got ${schedNode.pendingSchedules().length}`);
  assert(fireEvents().length === 0 && failureEvents.length === 0,
    'nothing may fire (or fail) before the due time');

  // Due: materializes exactly once.
  schedNode.processSchedules(now + 60001);
  assert(schedNode.pendingSchedules().length === 0,
    'a due one-shot must leave the pending queue');
  assert(fireEvents().length === 1,
    `expected one materialized fire, got ${fireEvents().length}`);
  assert(fireEvents()[0].result === 0 && fireEvents()[0].signer === 'alice',
    'the materialized mint must land successfully signed by alice');
  // Idempotent: another tick re-materializes nothing.
  schedNode.processSchedules(now + 60002);
  assert(fireEvents().length === 1,
    'a materialized op must not run twice');

  // Cancel: a queued change of plans must be retrievable before due.
  const cancelId = schedNode.schedule(signMintOp(), now + 120000);
  schedNode.cancelSchedule(cancelId);
  assert(schedNode.pendingSchedules().length === 0,
    'a cancelled schedule must leave the pending queue');
  // And it must stay materialized-away: tick past the would-be due time.
  schedNode.processSchedules(now + 120001);
  assert(fireEvents().length === 1,
    'a cancelled schedule must never materialize');
  // Cancellation is typed: an unknown id is resource_not_found.
  let unknownCancelTyped = false;
  try {
    schedNode.cancelSchedule(987654321n);
  } catch (cancelRefusal) {
    unknownCancelTyped = cancelRefusal.message.includes('resource_not_found');
  }
  assert(unknownCancelTyped,
    'cancelSchedule on an unknown id must be typed resource_not_found');

  // Recurring: 3 slots at 1s intervals, catch-up in one IN-ORDER pass, then
  // the series is exhausted. The row describes the series.
  const recurringId = schedNode.scheduleRecurring(signMintOp(), now + 1000, 1000, 3, 0);
  assert(recurringId > 0n, 'scheduleRecurring must return a positive id');
  const recurringRow = schedNode.pendingSchedules()[0];
  assert(recurringRow.intervalMs === 1000n,
    `recurring row must carry the interval, got ${recurringRow.intervalMs}`);
  assert(recurringRow.repeatCount === 3n,
    `recurring row must carry the fire count, got ${recurringRow.repeatCount}`);
  assert(recurringRow.endAt === 0n,
    `recurring row must carry the (unset) end, got ${recurringRow.endAt}`);
  assert(recurringRow.executeAt === BigInt(now + 1000),
    `recurring row must carry the first slot, got ${recurringRow.executeAt}`);
  schedNode.processSchedules(now);
  assert(schedNode.pendingSchedules().length === 1 &&
           fireEvents().length === 1,
    'a not-due recurring series must stay pending, unfired');
  schedNode.processSchedules(now + 3500);
  assert(schedNode.pendingSchedules().length === 0,
    'a fully caught-up series must leave the pending queue');
  assert(fireEvents().length === 4,
    `expected 1 one-off + 3 recurring fires, got ${fireEvents().length}`);
  assert(failureEvents.length === 0,
    `every slot must fire cleanly, got ${failureEvents.length} failure records`);

  // Occurrence budget: bounds the per-tick catch-up burst. Slots 1000 and
  // 2000 fire in the first tick; slot 3000 stays pending at its exact slot
  // until the budget is lifted, then fires.
  schedNode.scheduleRecurring(signMintOp(), now + 1000, 1000, 3, 0);
  schedNode.setScheduleOccurrenceBudget(2);
  assert(schedNode.scheduleOccurrenceBudget() === 2,
    'the budget setter must be reflected by the getter');
  schedNode.processSchedules(now + 3500);
  assert(schedNode.pendingSchedules().length === 1,
    'the budget must defer the third slot, keeping it pending');
  assert(fireEvents().length === 6,
    `budget must cap the burst (expected 6, got ${fireEvents().length})`);
  schedNode.setScheduleOccurrenceBudget(0);  // 0 = unlimited
  assert(schedNode.scheduleOccurrenceBudget() === 0,
    'budget 0 (unlimited) must read back as 0');
  schedNode.processSchedules(now + 3500);
  assert(schedNode.pendingSchedules().length === 0,
    'the deferred slot must fire once the budget lifts');
  assert(fireEvents().length === 7,
    `deferred slot must fire once the budget lifts (expected 7, got ${fireEvents().length})`);

  // Typed argument rejections mirroring the binding's other surfaces.
  function expectArgumentRejection(thunk, errorType, fragment, label) {
    try {
      thunk();
      assert(false, `${label} should throw`);
    } catch (rejection) {
      assert(rejection instanceof errorType &&
               rejection.message.includes(fragment),
        `${label} should throw ${errorType.name} with "${fragment}", got ` +
        `${rejection}`);
    }
  }
  expectArgumentRejection(() => schedNode.schedule('nope', now),
    TypeError, 'Operation', 'schedule(string)');
  expectArgumentRejection(() => schedNode.schedule(signMintOp(), -1),
    RangeError, 'executeAtMs', 'schedule(negative due)');
  expectArgumentRejection(() => schedNode.schedule(signMintOp()),
    TypeError, 'executeAtMs', 'schedule(missing due)');
  expectArgumentRejection(() =>
      schedNode.scheduleRecurring(signMintOp(), now, -1000, 3, 0),
    RangeError, 'intervalMs', 'scheduleRecurring(negative interval)');
  expectArgumentRejection(() =>
      schedNode.scheduleRecurring(signMintOp(), now, 1000, 3),
    TypeError, 'endAtMs', 'scheduleRecurring(missing endAt)');
  expectArgumentRejection(() => schedNode.cancelSchedule('x'),
    TypeError, 'cancelSchedule', 'cancelSchedule(string id)');
  expectArgumentRejection(() => schedNode.processSchedules('tomorrow'),
    TypeError, 'processSchedules', 'processSchedules(string)');

  // An op signed by NO registered user fails the same submission gate —
  // the policy evaluation fails closed on the unresolvable signer
  // (_verify_operation_authorization).
  const ghostOp = new Operation('mint');
  ghostOp.signerId = 'ghost';
  ghostOp.addResource('tokens');
  schedNode.sign(ghostOp, KeyPair.generate());
  expectArgumentRejection(() => schedNode.schedule(ghostOp, now + 5000),
    Error, 'unauthorized', 'schedule(unknown signer)');
}

// ============================================================
// P1 (parity fill): state restore + merge + sealed/signed snapshots.
//
// deserialize(wire, {sealKey?, verify?}) REPLACES the wrapper's machine with
// the restored state — the same wrapper stays usable — and returns the
// restore report {authorityRestored, mskSectionPresent}. mergeState(wire)
// merges a foreign snapshot through crdt_merge_state (counters max-per-node
// / sum-across-nodes, register LWW, OR-set union).
// ============================================================
(() => {
  function assert_raises(thunk, label, message) {
    let caught = null;
    try { thunk(); } catch (caughtError) { caught = caughtError; }
    assert(caught !== null, message + ` (${label} did not throw)`);
  }

  const SEAL_KEY_A = 'aa'.repeat(32);
  const SEAL_KEY_B = 'bb'.repeat(32);

  // Plain serialize -> deserialize round trip into a FRESH wrapper.
  const snapshotNode = new Node('m1', { ordering: 'hlc' });
  snapshotNode.addCounter('hits');
  snapshotNode.incrementCounter('hits', 5, 'm1');
  snapshotNode.addRegister('rank', 0);
  snapshotNode.setRegister('rank', 42, 'm1');
  snapshotNode.addORSet('tags');
  snapshotNode.setAdd('tags', 'crdt', 'writer-a');
  snapshotNode.setAdd('tags', 'abe', 'writer-b');
  const restoreKey = KeyPair.generate();
  snapshotNode.registerUser('restoree', restoreKey.publicKeyHex(), '');
  snapshotNode.grantRole('restoree', 'role', 'member', 'm1');
  const wire1 = snapshotNode.serialize();

  const restored = new Node('fresh', { ordering: 'hlc' });
  const plainReport = restored.deserialize(wire1);
  assert(plainReport.authorityRestored === false &&
         plainReport.mskSectionPresent === false,
    `plain snapshot report must be plain (got ${JSON.stringify(plainReport)})`);
  assert(restored.getCounter('hits') === 5, 'counter did not restore');
  assert(restored.getRegister('rank') === 42, 'register did not restore');
  assert(restored.setContains('tags', 'crdt') && restored.setContains('tags', 'abe'),
    'OR-set members did not restore');
  const restoree = restored.getUser('restoree');
  assert(restoree !== undefined && restoree.userId === 'restoree',
    'user registry did not restore');
  assert(restoree.attributes.some(attr => attr.value === 'role:member'),
    'restored user record lost the granted role');

  assert_raises(() => restored.deserialize(Buffer.from([0, 1, 2])),
    'deserialize', 'garbage wire must refuse deserialize');

  // mergeState: divergent machines converge on crdt_merge_state's rules.
  const mergerLeft = new Node('ml', { ordering: 'hlc' });
  mergerLeft.addCounter('hits');
  mergerLeft.incrementCounter('hits', 3, 'm-left');
  mergerLeft.addRegister('rank', 0);
  mergerLeft.setRegister('rank', 7, 'm-left');
  mergerLeft.addORSet('tags');
  mergerLeft.setAdd('tags', 'shared', 'left');
  const mergerRight = new Node('mr', { ordering: 'hlc' });
  mergerRight.addCounter('hits');
  mergerRight.incrementCounter('hits', 9, 'm-right');
  mergerRight.addRegister('rank', 0);
  mergerRight.setRegister('rank', 99, 'm-right');
  mergerRight.addORSet('tags');
  mergerRight.setAdd('tags', 'shared', 'right');
  mergerRight.setAdd('tags', 'extra', 'right');
  mergerLeft.mergeState(mergerRight.serialize());

  assert(mergerLeft.getCounter('hits') === 12,
    `merged counter: distinct node contributions sum (expected 12, got ${mergerLeft.getCounter('hits')})`);
  assert(mergerLeft.getRegister('rank') === 99,
    `merged register: later / higher-node-id LWW wins (expected 99, got ${mergerLeft.getRegister('rank')})`);
  assert(mergerLeft.setContains('tags', 'shared') &&
         mergerLeft.setContains('tags', 'extra'), 'merged OR-set lost elements');
  assert(mergerRight.getCounter('hits') === 9,
    'mergeState must not mutate the source machine');

  const beforeRefusedMerge = mergerLeft.getCounter('hits');
  assert_raises(() => mergerLeft.mergeState(Buffer.alloc(8)),
    'mergeState', 'garbage mergeState input must refuse');
  assert(mergerLeft.getCounter('hits') === beforeRefusedMerge,
    'refused merge must leave the machine untouched');

  // Sealed snapshot: same key restores authority, wrong key does not.
  const sealedWire = snapshotNode.serialize({ sealKey: SEAL_KEY_A });
  const unsealer = new Node('unsealer', { ordering: 'hlc' });
  const sealReport = unsealer.deserialize(sealedWire, { sealKey: SEAL_KEY_A });
  assert(sealReport.mskSectionPresent === true,
    'sealed snapshot must report the MSK section present');
  assert(sealReport.authorityRestored === true,
    'correct seal key must restore the machine authority');
  assert(unsealer.getCounter('hits') === 5, 'sealed snapshot content did not restore');

  const wrongKeyNode = new Node('wrongkey', { ordering: 'hlc' });
  const wrongReport = wrongKeyNode.deserialize(sealedWire, { sealKey: SEAL_KEY_B });
  assert(wrongReport.mskSectionPresent === true && wrongReport.authorityRestored === false,
    `wrong seal key must refuse the authority (got ${JSON.stringify(wrongReport)})`);
  assert(wrongKeyNode.getCounter('hits') === 5,
    'wrong-key restore must still load the substrate');

  // Signed snapshot: self-restore + tamper refusal.
  const signedWire = snapshotNode.serialize({ signed: true });
  const tampered = Buffer.from(signedWire);
  tampered[16] ^= 0xFF;  // flip one payload byte (signature must catch it)
  assert_raises(() => snapshotNode.deserialize(tampered, { verify: 'node-key' }),
    'deserialize', 'tampered signed snapshot must refuse');

  const signedReport = snapshotNode.deserialize(signedWire, { verify: 'node-key' });
  assert(snapshotNode.getCounter('hits') === 5 &&
         snapshotNode.getRegister('rank') === 42,
    'signed self-restore lost the snapshot content');
  assert(signedReport.authorityRestored === false &&
         signedReport.mskSectionPresent === false,
    'the plain body of a signed snapshot reports the plain path');

  const foreign = new Node('foreign', { ordering: 'hlc' });
  assert_raises(() => foreign.deserialize(signedWire, { verify: 'node-key' }),
    'deserialize', 'foreign node key must not verify a foreign signature');

  // Sealed + signed: both families compose from the wrapper.
  const sealedSignedWire =
      snapshotNode.serialize({ sealKey: SEAL_KEY_A, signed: true });
  const sealedSignedReport = snapshotNode.deserialize(
      sealedSignedWire, { sealKey: SEAL_KEY_A, verify: 'node-key' });
  assert(sealedSignedReport.authorityRestored === true &&
         sealedSignedReport.mskSectionPresent === true,
    `sealed+signed restore lost both guarantees (got ${JSON.stringify(sealedSignedReport)})`);
  assert(snapshotNode.getCounter('hits') === 5,
    'sealed+signed content did not restore');

  // The restored machine stays usable end to end.
  snapshotNode.setRegister('rank', 43, 'm1');
  assert(snapshotNode.getRegister('rank') === 43, 'restored machine must stay writable');

  // The N-API Node exposes no destroy() (borrowed-lifetime design): the
  // machines are reclaimed with GC.
})();

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);