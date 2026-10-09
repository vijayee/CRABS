'use strict';

// Handler-state read APIs (consumption findings 3-4).
//   * getSetSize / getSetElements — distinct live elements, sorted ascending,
//     hard-capped at 256 per call (pages via offset+limit).
//   * getSetTags — LIVE tags of a single element (post-Task-1 pair semantics
//     allow several tags per element).
//   * getRegisterBytes / setRegisterBytes — byte-exact round-trip available
//     on Node AND on the registerHandlerJs state proxy.

const { Node, KeyPair, Operation } = require('..');

const assertEquals = (actual, expected, label) => {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a !== b) throw new Error(`${label}: expected ${b}, got ${a}`);
};

(async () => {
  const node = await Node.create('admin', { ordering: 'hlc' });
  node.addORSet('crew');

  // Ten elements; "zeta" is the alphabetically-last name so page ordering is
  // exercised. Two tags on 'alpha' exercise post-Task-1 multi-tag retention.
  const elements = ['alpha', 'beta', 'gamma', 'delta', 'epsilon',
                    'lambda', 'mu', 'nu', 'omicron', 'zeta'];
  for (const element of elements) {
    node.setAdd('crew', element, `tag-${element}`);
  }
  // Same element, second tag — post-Task-1 both pairs are retained.
  node.setAdd('crew', 'alpha', 'tag-alpha-second');

  const sorted = [...elements].sort();

  // Size is DISTINCT live elements (alpha-with-two-tags counts once).
  assertEquals(node.getSetSize('crew'), 10, 'getSetSize distinct');

  // Pagination: two 5-element pages cover the whole set, sorted ascending.
  const page1 = node.getSetElements('crew', { offset: 0, limit: 5 });
  const page2 = node.getSetElements('crew', { offset: 5, limit: 5 });
  assertEquals(page1, sorted.slice(0, 5), 'page 1 sorted');
  assertEquals(page2, sorted.slice(5, 10), 'page 2 sorted');
  // Default limit covers the full small set.
  assertEquals(node.getSetElements('crew'), sorted, 'default page covers set');
  // An out-of-range offset returns an empty page.
  assertEquals(node.getSetElements('crew', { offset: 100, limit: 5 }), [],
               'out-of-range offset returns empty page');

  // Cap rejection: limit > 256 throws BEFORE the wasm round-trip.
  let capRejected = false;
  try { node.getSetElements('crew', { limit: 257 }); } catch (capError) {
    capRejected = capError.message.includes('[1, 256]');
  }
  if (!capRejected) {
    throw new Error('getSetElements must reject limit > 256');
  }
  // limit = 0 also rejected.
  let zeroRejected = false;
  try { node.getSetElements('crew', { limit: 0 }); } catch (zeroError) {
    zeroRejected = zeroError.message.includes('[1, 256]');
  }
  if (!zeroRejected) {
    throw new Error('getSetElements must reject limit === 0');
  }

  // Tags of an element with MULTIPLE tags (Task 1 pair semantics). Sorted
  // ascending so the two expected values line up deterministically.
  const alphaTags = node.getSetTags('crew', 'alpha');
  assertEquals(alphaTags, ['tag-alpha', 'tag-alpha-second'].sort(),
               'alpha has both tags');
  assertEquals(node.getSetTags('crew', 'beta'), ['tag-beta'],
               'beta has only its one tag');
  // Unknown element → empty list (element has no live tags).
  assertEquals(node.getSetTags('crew', 'does-not-exist'), [],
               'unknown element returns empty tags');

  // Tombstone filtering: alpha's tags both die with the remove, alpha drops
  // out of the size and the page.
  node.setRemove('crew', 'alpha');
  assertEquals(node.getSetSize('crew'), 9, 'size drops on remove');
  assertEquals(node.getSetElements('crew'), sorted.filter(e => e !== 'alpha'),
               'alpha removed from enumeration');
  assertEquals(node.getSetTags('crew', 'alpha'), [],
               'alpha tags all tombstoned');

  // Byte-register round trip on Node AND inside handler context.
  node.addRegister('blob', 0);
  const payload = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x42]);
  node.setRegisterBytes('blob', payload);
  const directRead = node.getRegisterBytes('blob');
  assertEquals(Array.from(directRead), Array.from(payload),
               'getRegisterBytes round trip (node)');

  // Register a worker + handler that reads 'blob' from handler state, flips
  // it, and writes back through state.setRegisterBytes.
  const workerKey = await KeyPair.generate();
  await node.registerUser('worker', workerKey.publicKeyHex(), '');
  node.grantRole('worker', 'role', 'member', 'admin');
  node.setPolicy('flip', 'role:member');

  let observedSize = 0;
  let observedTagsLength = 0;
  let observedFirstPageLength = 0;
  node.registerHandlerJs('flip', (state) => {
    const read = state.getRegisterBytes('blob');
    // Flip the first byte to prove we read what the node wrote.
    read[0] = read[0] ^ 0xFF;
    state.setRegisterBytes('blob', read, 'worker');
    // Exercise the handler-context reads while we're here.
    observedSize = state.getSetSize('crew');
    observedTagsLength = state.getSetTags('crew', 'beta').length;
    observedFirstPageLength = state.getSetElements('crew', { limit: 3 }).length;
    return 0;
  });
  const flipOp = await Operation.create('flip');
  flipOp.signerId = 'worker';
  flipOp.nodeId = 'worker';
  node.sign(flipOp, workerKey.privateKeyHex());
  node.execute(flipOp);
  flipOp.destroy();

  const flipped = node.getRegisterBytes('blob');
  const expectedFlipped = Array.from(payload);
  expectedFlipped[0] ^= 0xFF;
  assertEquals(Array.from(flipped), expectedFlipped,
               'handler setRegisterBytes round trip');
  if (observedSize !== 9) {
    throw new Error(`handler getSetSize returned ${observedSize}, expected 9`);
  }
  if (observedTagsLength !== 1) {
    throw new Error(`handler getSetTags('crew','beta') returned ${observedTagsLength} tags`);
  }
  if (observedFirstPageLength !== 3) {
    throw new Error(`handler getSetElements(limit 3) returned ${observedFirstPageLength}`);
  }

  // Handler-context cap rejection mirrors the Node contract.
  let handlerCapRejected = false;
  node.registerHandlerJs('probe', (state) => {
    try { state.getSetElements('crew', { limit: 999 }); } catch (probeError) {
      handlerCapRejected = probeError.message.includes('[1, 256]');
    }
    return 0;
  });
  node.setPolicy('probe', 'role:member');
  const probeOp = await Operation.create('probe');
  probeOp.signerId = 'worker';
  probeOp.nodeId = 'worker';
  node.sign(probeOp, workerKey.privateKeyHex());
  node.execute(probeOp);
  probeOp.destroy();
  if (!handlerCapRejected) {
    throw new Error('handler getSetElements must reject limit > 256');
  }

  workerKey.destroy();
  console.log('handler-reads OK: enumeration + tags + byte registers');
  node.destroy();
})().catch(e => { console.error(e); process.exit(1); });
