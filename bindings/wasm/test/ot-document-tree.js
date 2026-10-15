// ot-document-tree.js — OT_DOCUMENT + OT_TREE surfaces from the wasm module.
//
// Mirror of bindings/node/test/ot-document-tree.js over the wasm surface.
// PRESENT maturity, EXPLICITLY UNBLESSED: the C machinery is implemented
// but unbenchmarked — do not build rich text on this until a benchmark
// exists (recipe 8's boundary note). The pinned facts are round-trip,
// determinism and the merge-held status — NOT performance or
// convergence-parity claims.
//
// FIXED PRE-EXISTING FLAKE (parity-fill P11 investigation, 2026-10-14).
// This test used to fail standalone on ~15/20 runs with
// `RuntimeError: memory access out of bounds` inside dlmalloc during a
// later ECDSA allocation. Root cause (full trail in
// src/Util/wasm_alloc_pad.c): OpenSSL 3.4.0's wasm EC-group construction
// (EC_KEY_new_by_curve_name → BN_MONT_CTX_set) overflows a few bytes past
// an allocation on effectively every ECDSA keygen/sign; with per-op
// signing the scribbles accumulate (monotonic failure gradient in op
// count), and once one of them hits a dlmalloc chunk header the next large
// malloc/free walks unmapped memory — which is why it looked random and
// why the native binding (glibc's allocator) never reproduced it.
// Mitigation shipped in build_wasm.sh: every allocation goes through
// src/Util/wasm_alloc_pad.c (-Wl,--wrap=malloc/calloc, +32-byte pad), so
// the overflow always lands in pad slack.
// UPGRADE EXPERIMENT (2026-10-15): rebuilding the wasm OpenSSL at 3.5.9
// LTS with the pad dropped did NOT fix the trap — same OOB at the same
// point (this test stayed clean; the full-chain canary flapped ~1-in-4 at
// state-restore.js on BOTH 3.4.0 and 3.5.9). The culprit is now tracked in
// the uninstrumented RELIC/OpenABE archives or toolchain UB — see the
// experiment note in src/Util/wasm_alloc_pad.c. Keep the shim.

'use strict';

const { Node } = require('..');

(async () => {
// Throw if `invoke` fails to throw a typed-error message containing
// `fragment` (a refusal pin), naming the pin with `label`.
const mustThrowWith = (invoke, fragment, label) => {
  let caught = null;
  try { invoke(); } catch (caughtError) { caught = caughtError; }
  if (!caught) throw new Error(`${label}: expected a throw`);
  if (!String(caught.message).includes(fragment)) {
    throw new Error(`${label}: expected "${fragment}", got "${caught.message}"`);
  }
};

// ============================================================
// OT_DOCUMENT
// ============================================================

// ---- Document seed: sequential inserts keep their order -------------------
const node = await Node.create('ot-doc-a', { ordering: 'hlc' });
node.setPolicy('__execute_ot__', 'role:admin');
node.addOTDocument('doc');

node.otInsertText('doc', 0, 'Hello', { id: { node: 'ot-doc-a', seq: 1, ts: 1000 } });
node.otInsertText('doc', 5, ' world', { id: { node: 'ot-doc-a', seq: 2, ts: 1000 } });

const doc = node.getOTDocument('doc');
if (doc.text !== 'Hello world') {
  throw new Error(`sequential inserts must concatenate in order (got "${doc.text}")`);
}
if (doc.charCount !== 11) {
  throw new Error(`charCount must be the visible character count (got ${doc.charCount})`);
}
if (!Array.isArray(doc.spans) || doc.spans.length < 1) {
  throw new Error(`readback must expose the visible spans (got ${JSON.stringify(doc.spans)})`);
}

// ---- Two inserts at the SAME offset land deterministically ----------------
// The document op path inserts a same-position span at the head (pos == 0
// prepends — ot_document.c's no-position-map branch), so the later insert
// reads BEFORE the earlier one: 'B' then 'A'. Deterministic is the pin —
// whichever byte order, both replicas derive it from the same op log.
node.addOTDocument('same');
node.otInsertText('same', 0, 'A', { id: { node: 'ot-doc-a', seq: 10, ts: 1000 } });
node.otInsertText('same', 0, 'B', { id: { node: 'ot-doc-a', seq: 11, ts: 1000 } });
if (node.getOTDocument('same').text !== 'BA') {
  throw new Error('same-offset inserts must be deterministic (later insert prepends)');
}

// ---- Replay the SAME op id: silent no-op ----------------------------------
node.otInsertText('same', 2, 'AGAIN', { id: { node: 'ot-doc-a', seq: 11, ts: 1000 } });
if (node.getOTDocument('same').text !== 'BA') {
  throw new Error('a replayed op id must not duplicate or shift anything');
}

// ---- Style readback -------------------------------------------------------
node.addOTDocument('styled');
node.otInsertText('styled', 0, 'Hello', { id: { node: 'ot-doc-a', seq: 20, ts: 1000 } });
node.otApplyStyle('styled', 0, 1, { name: 'bold', value: 'true' },
  { id: { node: 'ot-doc-a', seq: 21, ts: 1000 } });
const styled = node.getOTDocument('styled');
if (JSON.stringify(styled.spans[0].styles) !==
    JSON.stringify([{ name: 'bold', value: 'true' }])) {
  throw new Error(`the styled span must read back its style (got ${JSON.stringify(styled.spans[0])})`);
}

// ---- Delete range ---------------------------------------------------------
node.addOTDocument('trimmed');
node.otInsertText('trimmed', 0, 'Hello world',
  { id: { node: 'ot-doc-a', seq: 30, ts: 1000 } });
node.otDeleteRange('trimmed', 1, 5, { id: { node: 'ot-doc-a', seq: 31, ts: 1000 } });
if (node.getOTDocument('trimmed').text !== 'Hworld') {
  throw new Error('delete_range must remove the covered characters only');
}

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
if (node.getOTDocument('merged').text !== 'AAACCC') {
  throw new Error(`the tombstoned middle span must vanish (got "${node.getOTDocument('merged').text}")`);
}
mustThrowWith(() => node.otMergeSpans('merged', 1, 2,
    { id: { node: 'ot-doc-a', seq: 44, ts: 1000 } }),
  'ot_position_bounds', 'merge past the visible span tail');
node.otMergeSpans('merged', 0, 1, { id: { node: 'ot-doc-a', seq: 45, ts: 1000 } });
const mergedDoc = node.getOTDocument('merged');
if (mergedDoc.text !== 'AAACCC' || mergedDoc.charCount !== 6 ||
    mergedDoc.spans.length !== 1) {
  throw new Error(`merging the survivors must fuse them into ONE visible span (got ${JSON.stringify({ text: mergedDoc.text, charCount: mergedDoc.charCount, spans: mergedDoc.spans.length })})`);
}

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
if (splitDoc.text !== 'Hello world' || splitDoc.spans.length !== 3) {
  throw new Error(`a mid-span split must add a span without changing the text (got ${JSON.stringify({ text: splitDoc.text, spans: splitDoc.spans.length })})`);
}

// ---- Merge: an OT_DOCUMENT snapshot is HELD, not adopted ------------------
// OT_DOCUMENT has no merge machinery (crdt_merge.c): a fresh arrival is
// held — one __merge_held__ change event with CRABS_ERR_TYPE_MISMATCH
// (0x3004), the merge still returns SUCCESS, and the destination does NOT
// gain the item. The honest merge status of this type is held-on-merge.
const docHolder = await Node.create('ot-doc-holder', { ordering: 'hlc' });
const heldEvents = [];
docHolder.on('change', (event) => heldEvents.push(event));
docHolder.mergeState(node.serialize());
const docHeld = heldEvents.filter((event) => event.type === '__merge_held__');
if (docHeld.length < 1 || !docHeld.some(
    (event) => event.target === 'doc' && event.result === 0x3004)) {
  throw new Error(`the document snapshot must be held (got ${JSON.stringify(heldEvents)})`);
}
let heldReadThrew = null;
try { docHolder.getOTDocument('doc'); } catch (caught) { heldReadThrew = caught; }
if (heldReadThrew === null) {
  throw new Error('a held item must NOT be implanted: the holder gains no document item');
}

// ============================================================
// OT_TREE
// ============================================================

const treeNode = await Node.create('ot-tree-a', { ordering: 'hlc' });
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
if (treeNodeIds.join(',') !== 'r,a,b,c') {
  throw new Error(`seeded tree readback must be in materialized order (got [${treeNodeIds}])`);
}

// ---- Reparent: c moves under a (b stays sibling) ---------------------------
treeNode.otReparent('t', 'c', 'a', 0, { id: { node: 'ot-tree-a', seq: 5, ts: 1000 } });
const reparented = treeNode.getOTTree('t').nodes;
const byId = Object.fromEntries(reparented.map((entry) => [entry.id, entry]));
if (byId.c.parentId !== 'a') throw new Error('c must now parent under a');
if (byId.a.parentId !== 'r') throw new Error('a stays under r');
if (JSON.stringify(byId.r.childIds) !== JSON.stringify(['a', 'b'])) {
  throw new Error(`r keeps a then b (got ${JSON.stringify(byId.r.childIds)})`);
}
if (JSON.stringify(byId.a.childIds) !== JSON.stringify(['c'])) {
  throw new Error(`a holds c as its only child (got ${JSON.stringify(byId.a.childIds)})`);
}
if (JSON.stringify(byId.b.childIds) !== JSON.stringify([])) {
  throw new Error(`b has no children (got ${JSON.stringify(byId.b.childIds)})`);
}

// ---- Replay idempotency on the tree ----------------------------------------
treeNode.otReparent('t', 'c', 'a', 0, { id: { node: 'ot-tree-a', seq: 5, ts: 1000 } });
if (treeNode.getOTTree('t').nodes.map((entry) => entry.id).join(',') !== 'r,a,c,b') {
  throw new Error('a replayed tree op id must be a no-op');
}

// ---- Argument guards -------------------------------------------------------
mustThrowWith(() => treeNode.getOTTree('no-such-tree'),
  'resource_not_found', 'read unknown tree');
mustThrowWith(() => treeNode.otInsertNode('t', 'ghost', 0, 'x', '',
    { id: { node: 'ot-tree-a', seq: 6 } }),
  'invalid_param', 'insert under an unknown parent');
mustThrowWith(() => treeNode.otInsertNode('t', 'r', 0, 'r', '',
    { id: { node: 'ot-tree-a', seq: 7 } }),
  'invalid_param', 'duplicate node id');

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
const rootsReadback = treeNode.getOTTree('roots');
const respectedRootOrder = JSON.stringify(['r-prepended', 'r-first', 'r-last']);
if (JSON.stringify(rootsReadback.nodes
    .filter((entry) => entry.parentId === '').map((entry) => entry.id))
    !== respectedRootOrder) {
  throw new Error("root ordinals must be honored: ordinal-0 insert lands first");
}
// wasm-only convenience — documented in index.d.ts as absent from the node
// binding's readback: it must mirror the visible root order.
if (JSON.stringify(rootsReadback.rootIds) !== respectedRootOrder) {
  throw new Error(`wasm-only rootIds must mirror the visible root order (got ${JSON.stringify(rootsReadback.rootIds)})`);
}

// Reparent to root at ordinal 1: r-kid lands BETWEEN r-first and r-last
// (the old root branch also appended reparented roots at the tail).
treeNode.otInsertNode('roots', 'r-first', 0, 'r-kid', 'kid',
  { id: { node: 'ot-tree-a', seq: 11, ts: 1000 } });
treeNode.otReparent('roots', 'r-kid', '', 1,
  { id: { node: 'ot-tree-a', seq: 12, ts: 1000 } });
if (JSON.stringify(treeNode.getOTTree('roots').nodes
    .filter((entry) => entry.parentId === '').map((entry) => entry.id))
    !== JSON.stringify(['r-prepended', 'r-kid', 'r-first', 'r-last'])) {
  throw new Error('reparent-to-root ordinal must be honored');
}

// ---- Unpoliced machine refuses the op --------------------------------------
const unpoliced = await Node.create('ot-doc-plain', { ordering: 'hlc' });
unpoliced.addOTDocument('doc');
mustThrowWith(() => unpoliced.otInsertText('doc', 0, 'nope',
    { id: { node: 'ot-doc-plain', seq: 1 } }),
  'unauthorized', '__execute_ot__ without a policy');
unpoliced.destroy();

console.log('ok: ot-document-tree (wasm) — OT_DOCUMENT + OT_TREE surfaces (unblessed)');
})().catch((error) => { console.error(error); process.exit(1); });