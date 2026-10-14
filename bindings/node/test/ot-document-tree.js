// ot-document-tree.js — OT_DOCUMENT + OT_TREE surfaces on crabs-node.
//
// Mirrors the wasm test of the same name (bindings/wasm/test/
// ot-document-tree.js). PRESENT maturity, EXPLICITLY UNBLESSED: the C
// machinery is implemented but unbenchmarked — do not build rich text on
// this until a benchmark exists (recipe 8's boundary note). The pinned
// facts are round-trip, determinism and the merge-held status — NOT
// performance or convergence-parity claims.

'use strict';

const assert = require('assert');
const { Node } = require('..');

// Throw if `invoke` fails to throw a typed-error message containing
// `fragment` (a refusal pin), naming the pin with `label`.
const mustThrowWith = (invoke, fragment, label) => {
  assert.throws(invoke, (caughtError) => String(caughtError.message).includes(fragment),
    `${label}: expected a typed error containing "${fragment}"`);
};

// ============================================================
// OT_DOCUMENT
// ============================================================

// ---- Document seed: sequential inserts keep their order -------------------
const node = new Node('ot-doc-a', { ordering: 'hlc' });
node.setPolicy('__execute_ot__', 'role:admin');
node.addOTDocument('doc');

node.otInsertText('doc', 0, 'Hello', { id: { node: 'ot-doc-a', seq: 1, ts: 1000 } });
node.otInsertText('doc', 5, ' world', { id: { node: 'ot-doc-a', seq: 2, ts: 1000 } });

const doc = node.getOTDocument('doc');
assert.strictEqual(doc.text, 'Hello world',
  `sequential inserts must concatenate in order (got "${doc.text}")`);
assert.strictEqual(doc.charCount, 11,
  `charCount must be the visible character count (got ${doc.charCount})`);
assert(Array.isArray(doc.spans) && doc.spans.length >= 1,
  `readback must expose the visible spans (got ${JSON.stringify(doc.spans)})`);

// ---- Two inserts at the SAME offset land deterministically ----------------
// The document op path inserts a same-position span at the head (pos == 0
// prepends — ot_document.c's no-position-map branch), so the later insert
// reads BEFORE the earlier one: 'B' then 'A'. Deterministic is the pin —
// whichever byte order, both replicas derive it from the same op log.
node.addOTDocument('same');
node.otInsertText('same', 0, 'A', { id: { node: 'ot-doc-a', seq: 10, ts: 1000 } });
node.otInsertText('same', 0, 'B', { id: { node: 'ot-doc-a', seq: 11, ts: 1000 } });
assert.strictEqual(node.getOTDocument('same').text, 'BA',
  'same-offset inserts must be deterministic (later insert prepends)');

// ---- Replay the SAME op id: silent no-op ----------------------------------
node.otInsertText('same', 2, 'AGAIN', { id: { node: 'ot-doc-a', seq: 11, ts: 1000 } });
assert.strictEqual(node.getOTDocument('same').text, 'BA',
  'a replayed op id must not duplicate or shift anything');

// ---- Style readback -------------------------------------------------------
node.addOTDocument('styled');
node.otInsertText('styled', 0, 'Hello', { id: { node: 'ot-doc-a', seq: 20, ts: 1000 } });
node.otApplyStyle('styled', 0, 1, { name: 'bold', value: 'true' },
  { id: { node: 'ot-doc-a', seq: 21, ts: 1000 } });
const styled = node.getOTDocument('styled');
assert.deepStrictEqual(styled.spans[0].styles, [{ name: 'bold', value: 'true' }],
  `the styled span must read back its style (got ${JSON.stringify(styled.spans[0])})`);

// ---- Delete range ---------------------------------------------------------
node.addOTDocument('trimmed');
node.otInsertText('trimmed', 0, 'Hello world',
  { id: { node: 'ot-doc-a', seq: 30, ts: 1000 } });
node.otDeleteRange('trimmed', 1, 5, { id: { node: 'ot-doc-a', seq: 31, ts: 1000 } });
assert.strictEqual(node.getOTDocument('trimmed').text, 'Hworld',
  'delete_range must remove the covered characters only');

// ---- Merge spans: VISIBLE ordinals, not tombstone-tail indexes ------------
// The merge_spans validator counts VISIBLE spans: three inserts make three
// spans, the middle one is tombstoned whole, and the survivors merge at
// visible ordinals 0+1. A span index past the visible tail (2 — only the
// tombstone tail would admit it) is REFUSED instead of signed as a logged
// no-op against the tombstone.
node.addOTDocument('merged');
node.otInsertText('merged', 0, 'AAA', { id: { node: 'ot-doc-a', seq: 40, ts: 1000 } });
node.otInsertText('merged', 3, 'BBB', { id: { node: 'ot-doc-a', seq: 41, ts: 1000 } });
node.otInsertText('merged', 6, 'CCC', { id: { node: 'ot-doc-a', seq: 42, ts: 1000 } });
node.otDeleteRange('merged', 3, 3, { id: { node: 'ot-doc-a', seq: 43, ts: 1000 } });
assert.strictEqual(node.getOTDocument('merged').text, 'AAACCC',
  'the tombstoned middle span must vanish');
mustThrowWith(() => node.otMergeSpans('merged', 1, 2,
    { id: { node: 'ot-doc-a', seq: 44, ts: 1000 } }),
  'ot_position_bounds', 'merge past the visible span tail');
node.otMergeSpans('merged', 0, 1, { id: { node: 'ot-doc-a', seq: 45, ts: 1000 } });
const mergedDoc = node.getOTDocument('merged');
assert.strictEqual(mergedDoc.text, 'AAACCC',
  'merging the survivors must fuse their text');
assert.strictEqual(mergedDoc.charCount, 6,
  'merging must not change the visible character count');
assert.strictEqual(mergedDoc.spans.length, 1,
  'merging the survivors must fuse them into ONE visible span');

// ---- Split: mid-span offsets split, boundaries are a TYPED refusal --------
// 'Hello' ('splitme', first insert) + ' world' are two spans: offset 5 is a
// span boundary (offset 0 within the next span) and offset 0 is the
// document start — both are null ops in the C core and must be refused
// before signing, not silently accepted; a mid-span offset splits.
node.addOTDocument('splitme');
node.otInsertText('splitme', 0, 'Hello', { id: { node: 'ot-doc-a', seq: 50, ts: 1000 } });
node.otInsertText('splitme', 5, ' world', { id: { node: 'ot-doc-a', seq: 51, ts: 1000 } });
mustThrowWith(() => node.otSplitSpan('splitme', 5,
    { id: { node: 'ot-doc-a', seq: 52, ts: 1000 } }),
  'ot_position_bounds', 'split at a span boundary');
mustThrowWith(() => node.otSplitSpan('splitme', 0,
    { id: { node: 'ot-doc-a', seq: 53, ts: 1000 } }),
  'ot_position_bounds', 'split at the document start');
node.otSplitSpan('splitme', 2, { id: { node: 'ot-doc-a', seq: 54, ts: 1000 } });
const splitDoc = node.getOTDocument('splitme');
assert.strictEqual(splitDoc.text, 'Hello world',
  'a mid-span split must not change the text');
assert.strictEqual(splitDoc.spans.length, 3,
  'a mid-span split must add a span');

// ---- Merge: an OT_DOCUMENT snapshot is HELD, not adopted ------------------
// OT_DOCUMENT has no merge machinery (crdt_merge.c): a fresh arrival is
// held — one __merge_held__ change event with CRABS_ERR_TYPE_MISMATCH
// (0x3004), the merge still returns SUCCESS, and the destination does NOT
// gain the item. The honest merge status of this type is held-on-merge.
const docHolder = new Node('ot-doc-holder', { ordering: 'hlc' });
const heldEvents = [];
docHolder.on('change', (event) => heldEvents.push(event));
docHolder.mergeState(node.serialize());
const docHeld = heldEvents.filter((event) => event.type === '__merge_held__');
assert(docHeld.length >= 1 && docHeld.some(
    (event) => event.target === 'doc' && event.result === 0x3004),
  `the document snapshot must be held (got ${JSON.stringify(heldEvents)})`);
assert.throws(() => docHolder.getOTDocument('doc'),
  'a held item must NOT be implanted: the holder gains no document item');

// ============================================================
// OT_TREE
// ============================================================

const treeNode = new Node('ot-tree-a', { ordering: 'hlc' });
treeNode.setPolicy('__execute_ot__', 'role:admin');
treeNode.addOTTree('t');

treeNode.otInsertNode('t', '', 0, 'r', 'root',
  { id: { node: 'ot-tree-a', seq: 1, ts: 1000 } });
treeNode.otInsertNode('t', 'r', 0, 'a', 'alpha',
  { id: { node: 'ot-tree-a', seq: 2, ts: 1000 } });
treeNode.otInsertNode('t', 'r', 1, 'b', 'beta',
  { id: { node: 'ot-tree-a', seq: 3, ts: 1000 } });
treeNode.otInsertNode('t', 'r', 2, 'c', 'gamma',
  { id: { node: 'ot-tree-a', seq: 4, ts: 1000 } });

const tree = treeNode.getOTTree('t');
const treeNodeIds = tree.nodes.map((entry) => entry.id);
assert.deepStrictEqual(treeNodeIds, ['r', 'a', 'b', 'c'],
  `seeded tree readback must be in materialized order (got [${treeNodeIds}])`);

// ---- Reparent: c moves under a (b, a stay under r) -------------------------
treeNode.otReparent('t', 'c', 'a', 0, { id: { node: 'ot-tree-a', seq: 5, ts: 1000 } });
const reparented = treeNode.getOTTree('t').nodes;
const byId = Object.fromEntries(reparented.map((entry) => [entry.id, entry]));
assert.strictEqual(byId.c.parentId, 'a', 'c must now parent under a');
assert.strictEqual(byId.a.parentId, 'r', 'a stays under r');
assert.deepStrictEqual(byId.r.childIds, ['a', 'b'], 'r keeps a then b');
assert.deepStrictEqual(byId.a.childIds, ['c'], 'a holds c as its only child');
assert.deepStrictEqual(byId.b.childIds, [], 'b has no children');

// ---- Replay idempotency on the tree ----------------------------------------
treeNode.otReparent('t', 'c', 'a', 0, { id: { node: 'ot-tree-a', seq: 5, ts: 1000 } });
assert.deepStrictEqual(
  treeNode.getOTTree('t').nodes.map((entry) => entry.id), ['r', 'a', 'c', 'b'],
  'a replayed tree op id must be a no-op');

// ---- Argument guards -------------------------------------------------------
assert.throws(() => treeNode.getOTTree('no-such-tree'),
  /resource_not_found/, 'read unknown tree');
assert.throws(() => treeNode.otInsertNode('t', 'ghost', 0, 'x', '',
    { id: { node: 'ot-tree-a', seq: 6 } }),
  /invalid_param/, 'insert under an unknown parent');
assert.throws(() => treeNode.otInsertNode('t', 'r', 0, 'r', '',
    { id: { node: 'ot-tree-a', seq: 7 } }),
  /invalid_param/, 'duplicate node id');

// ---- Root-level ordinals are HONORED ---------------------------------------
// A fresh root at ordinal 0 lands FIRST (the root-chain analogue of the
// nested path's position-0 prepend); the C core's root branches used to
// walk to the last root sibling and append regardless of the request.
treeNode.addOTTree('roots');
const rootInsert = (nodeId, position, seq, value) => treeNode.otInsertNode(
  'roots', '', position, nodeId, value,
  { id: { node: 'ot-tree-a', seq, ts: 1000 } });
rootInsert('r-first', 0, 8, 'one');
rootInsert('r-last', 1, 9, 'two');
rootInsert('r-prepended', 0, 10, 'zero');
const respectedRootOrder = ['r-prepended', 'r-first', 'r-last'];
assert.deepStrictEqual(
  treeNode.getOTTree('roots').nodes
    .filter((entry) => entry.parentId === '').map((entry) => entry.id),
  respectedRootOrder,
  'root ordinals must be honored: ordinal-0 insert lands first');

// Reparent to root at ordinal 1: r-kid lands BETWEEN r-first and r-last
// (the old root branch also appended reparented roots at the tail).
treeNode.otInsertNode('roots', 'r-first', 0, 'r-kid', 'kid',
  { id: { node: 'ot-tree-a', seq: 11, ts: 1000 } });
treeNode.otReparent('roots', 'r-kid', '', 1,
  { id: { node: 'ot-tree-a', seq: 12, ts: 1000 } });
assert.deepStrictEqual(
  treeNode.getOTTree('roots').nodes
    .filter((entry) => entry.parentId === '').map((entry) => entry.id),
  ['r-prepended', 'r-kid', 'r-first', 'r-last'],
  'reparent-to-root ordinal must be honored');

// ---- Unpoliced machine refuses the op --------------------------------------
const unpoliced = new Node('ot-doc-plain', { ordering: 'hlc' });
unpoliced.addOTDocument('doc');
assert.throws(() => unpoliced.otInsertText('doc', 0, 'nope',
    { id: { node: 'ot-doc-plain', seq: 1 } }),
  /unauthorized/, '__execute_ot__ without a policy');
// No Node.destroy on the node binding (borrow-lifetime — the documented
// binding asymmetry); the process exits and reclaims.

console.log('ok: ot-document-tree (node) — OT_DOCUMENT + OT_TREE surfaces (unblessed)');