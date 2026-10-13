---
number: 8
slug: reorderable-list
title: A reorderable list two people can edit at once
section: Convergence
status: PARTIAL
maturity: STABLE
target: native-c
languages: c wasm node
---
## Intent

You want a *ranked* thing — a priority queue, a playlist, a review queue, a
set of moderated submissions — where two members can each add items, remove
items and reorder what is there, while offline from each other, and both
replicas end up looking at the same list with nobody's edit erased. Insert
concurrently at the same slot: both items must land. Move and swap: the
movement must survive the merge as a deterministic order, not as whichever
write happened to arrive last.

This is the convergence problem for *order*, and it is strictly harder than
the counter in Recipe 1: a counter only has to agree on a number, a list has
to agree on a *sequence* while positions renumber under everyone's fingers.
It is also — deliberately — NOT a collaborative text editor: the page you
want for shared rich text is Recipe 8b, a separate and much more honest
page. The ordered list here is the project's blessed OT application
(api-map §17, R8).

## The naive version, and where it breaks

The naive version is an array the two clients overwrite wholesale: both hold
`["a","b","c"]`, member A moves `a` down to last, member B moves `b` to the
top, and the replicas exchange whole arrays — last writer wins. One member's
reorder silently vanishes, and worse, it vanishes *deterministically
invisibly*: nothing is thrown, nothing is flagged, the lost edit simply no
longer exists in either replica. The same overwriting applies per element if
you store the array in an LWW register.

And the "obvious" fixes don't help. Position-indexed element ops are broken
on their own: A deletes index `2` while B concurrently inserts at index `1`,
and now every index after `1` has shifted — applying both against raw
numbers corrupts positions that were never deleted. Locking the list during
edits reintroduces the coordination you are trying to avoid (and a lock
manager that is not even JS-bound — see api-map §17, R9). Renumbering on
merge requires a total-order coordinator: again coordination.

What actually works is changing what an element *is*: give every element a
stable op-id identity (not an index), track the order as per-element
placement metadata, keep the tombstones so concurrent positions never
renumber, and resolve conflicting placements with a deterministic priority
so both replicas compute the same sequence without talking.

## The shape

- Every element is identified by an op id — `(node_id, sequence, timestamp)`
  — and carries its order as placement metadata: an `anchor_id` (the element
  it sits after) plus a `placement_id` (the op that placed it), on
  `crabs_ordered_element_t` (`src/OT/ot_ordered_set.h:33-43`).
- Two coordinate spaces per list: internal (tombstones included) and visible
  (what users' positions reference), bridged by a BST position map —
  `crabs_xi` / `crabs_xi_inv` (`src/OT/position_map.h:49-52`; design:
  `docs/CRABS Extended.md` §4.2, :203).
- The op vocabulary is richer than a set's ADD/REMOVE:
  `CRABS_OT_OP_INSERT/ DELETE / UPDATE / MOVE / SWAP` (`src/OT/ot_types.h:22-28`)
  — an OR-set cannot express "move element from position 5 to position 2" at
  all (`docs/CRABS Extended.md` §4.1, :197-201).
- Concurrent position ops are resolved through a transform matrix — one
  transform function per op-type pair — and concurrent inserts at the same
  position are ordered by priority, which is intended to be
  `(timestamp << 48) | node_id_hash` (`docs/CRABS Extended.md` §4.3/:219 and
  §4.4/:244; in the implementation, a `priority` field on the op
  (`src/OT/ot_types.h:68`) and a 15x15 transform-function matrix on the item,
  `src/OT/ot_types.h:93-103`, populated by `crabs_transform_matrix_init`).
- The type itself: `crabs_ot_ordered_set_create / destroy / get / find /
  head / tail`, the five `apply_*` ops, and the CRDT merge —
  `crabs_ot_ordered_set_merge` + `crabs_ot_ordered_set_merge_position_maps`
  (`src/OT/ot_ordered_set.h:63-117`). The merge copies in src-only elements,
  takes the *larger* placement_id per element (with the op-id byte compare as
  the deterministic tie-break, `src/OT/ot_ordered_set.c:20-28`), wins
  deletions, and re-materializes one order.
- It is integrated as machine state: OT types register as real items
  (`crabs_register_ot_type`, `src/OT/ot_execution.h:69-72`) and the executor
  dispatches a `__execute_ot__` op through extract → transform → apply
  (`src/OT/ot_execution.h:38-54`; op type `src/CRABS/crabs.h:165`; executor
  branch `src/StateMachine/state_machine.c:1792-1794`). Both bindings bind
  this branch: item creation with the eager ordered-set wrapper
  (`crabs_wasm_add_ordered_set`, `src/Util/wasm_helpers.c:626`; node
  `AddOrderedSet`, `bindings/node/src/crabs_node.cc:1809`) and op application
  whose payload a wire encoder builds (`crabs_ot_ops_to_wire`,
  `src/OT/ot_execution.h:49-54` — the inverse of `crabs_extract_ot_ops`).

This is the *paper's* shape (`docs/CRABS Extended.md` §4). Two layers of it
are JS-bound today: the *op* layer — both bindings build ordered-set items
and apply INSERT/DELETE/MOVE/SWAP ops through the machine executor with
readback (the wasm/node snippets below) — and the *merge* layer, which is
still C-only: `crabs_ot_ordered_set_merge` has no JS map entry, so the
merge-preflight guarantees below are demonstrated in C and cited, not
re-run from JavaScript. That residual gap is stated per section.

## What it guarantees / what it doesn't

Guaranteed, on the surfaces exercised in the snippets: sequential ordered
ops land in issue order and read back materialized (tombstones skipped);
concurrent inserts at the same position are *both* kept — replica pairs
that exchange their ops with declared causal context converge on one
identical order through the transform tie-break (both binding snippets pin
the converged equality, and the C suite asserts the same property for
`merge` directly, `test/test_ot_ordered_set.cpp:347-375`); a duplicated op
id with the same payload is a no-op on replay (`_op_already_applied`,
`src/OT/ot_execution.c`). Still C-only — `crabs_ot_ordered_set_merge`'s
preflight guarantees: a duplicated op id whose *payload disagrees* refuses
to merge at all instead of pick-a-winner (`:377-393`), and a delete beats
a concurrent live element through the *merged position map*
(`:395-420`) — the executor path cannot observe either, because no binding
exposes `merge` (see the ledger note below). The reorder itself is also
deterministic: a MOVE re-stamps the placement of every element it knew
(`src/OT/ot_ordered_set.c:432-470`), and merged replicas re-derive the same
sequence from the merged placements.

Not guaranteed — and say this before building on it:

- *Placement is last-writer-wins by op-id compare.* Concurrent MOVE/SWAPs
  from two members do not interleave per item: because a MOVE re-stamps the
  whole order, the op id that sorts larger (node id bytes, then sequence,
  `src/OT/ot_ordered_set.c:20-28`) wins the *entire* placement, deterministically,
  and the other member's reorder is displaced rather than merged. Members
  who only insert and delete lose nothing; members who concurrently
  *reorder* get one converged order, not both reorderings.
- *The executor's transform is dep-driven, not merge-driven.* Replicas that
  exchange *ops* converge through the insert-insert tie-break (exactly one
  replica shifts; both snippets below pin one converged order from divergent
  machines), but an op replay carries its causal context *explicitly* —
  `options.deps` — because the C transform only skips log entries it can
  prove causally before or depended-on (`src/OT/ot_transform.c:32-63`).
  Replaying a peer op *without* its deps mis-shifts it (the binding tests pin
  the discriminating case, `bindings/*/test/ordered-set.js`). The
  merge-preflight refuses to reconcile replicas whose same-op-id elements
  carry different payloads — that check lives in `crabs_ot_ordered_set_merge`
  (`test_ot_ordered_set.cpp:377-393`) and no JS surface reaches it.
- *Rich-text/word-processing is a different and harder problem* (cursor
  stability, IME composition, styled spans) with its own unbenchmarked
  status: that is Recipe 8b's page, not this one.

## Variations

- Tree-shaped reordering: the same OT machinery ships an `OT_TREE` type
  (`DATA_TYPE_OT_TREE = 0x13`, `src/CRABS/data_model.h:35`) with
  `insert_node / delete_node / reparent / reorder` ops
  (`src/OT/ot_types.h:36-39`) — C-only: no binding creates or applies tree
  items (recipe 8b's document type likewise).
- Bigger lists: the op log behind a set is bounded
  (`CRABS_OT_OP_LOG_MAX`, `src/OT/ot_types.h:91`) and prunable
  (`crabs_prune_ot_log`, `src/OT/ot_execution.h:56-58`) — the log-pruning
  and compaction story is the design doc's stated mitigation for OT merge
  cost (`docs/CRABS Extended.md` §11.1, :585).
- Ordered map variant: `DATA_TYPE_OT_ORDERED_MAP = 0x14`
  (`src/CRABS/data_model.h:37`) exists as a type word, still without item
  machinery or bindings.
- Moderated review queues, i.e. ranked lists that a permission tree governs,
  compose this shape with Recipe 4's policies — the convergence machinery is
  independent of authorization; whoever may write applies the ops.

## Recipe

### crabs-wasm (browser / Node / edge)

The op layer is bound: `addOrderedSet` creates the item, the four
`ordered*` methods apply ops through the `__execute_ot__` executor (each call
composes, node-key-signs as the bootstrap admin and executes one
wire-encoded op — the createTrigger idiom: install the op type's policy
first with `setPolicy('__execute_ot__', 'role:admin')`), and `getOrderedSet`
reads the materialized order back (`bindings/wasm/index.d.ts:466-498`). Two
things to know before running it:

- every op's identity is caller-supplied (`options.id = {node, seq, ts?}`) —
  replaying the same id with the same payload is a silent no-op (the
  executor's `_op_already_applied` skip, `src/OT/ot_execution.c`);
- a *cross-replica replay* must carry the issuing replica's causal context in
  `options.deps` (max 16), or the transform treats the replica's earlier ops
  as concurrent and mis-shifts the position.

```snippet:wasm/08-reorderable-list.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.addOrderedSet         bindings/wasm/index.d.ts:466
  Node.getOrderedSet         bindings/wasm/index.d.ts:472
  Node.orderedInsert         bindings/wasm/index.d.ts:485
  Node.orderedDelete         bindings/wasm/index.d.ts:488
  Node.orderedMove           bindings/wasm/index.d.ts:491
  Node.orderedSwap           bindings/wasm/index.d.ts:497
  OrderedSetOpId/OrderedSetApplyOptions bindings/wasm/index.d.ts:103-122
  crabs_wasm_add_ordered_set src/Util/wasm_helpers.c:626
  crabs_wasm_ot_apply        src/Util/wasm_helpers.c:712
  crabs_wasm_ot_ordered_count/element src/Util/wasm_helpers.c:681/688
  crabs_ot_ops_to_wire       src/OT/ot_execution.h:49-54
  (__op_already_applied skip) src/OT/ot_execution.c
  (executor branch)          src/StateMachine/state_machine.c:1792-1794
maturity: all STABLE
test_ref: bindings/wasm/test/ordered-set.js (seed order, MOVE 0->2, SWAP, DELETE, idempotent replay, deps-carry pin, policy refusal, two-machine op-exchange convergence)
-->

### crabs-node (native Node.js)

The same surface direct-to-C (`bindings/node/index.d.ts:287-319`): the
sugar builds the op in-process, signs it under this machine's admin with
the node key (the reportEquivocation idiom) and runs the machine executor;
same policy requirement, same op-id and deps contract.

```snippet:node/08-reorderable-list.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  Node.addOrderedSet    bindings/node/index.d.ts:287
  Node.getOrderedSet    bindings/node/index.d.ts:293
  Node.orderedInsert    bindings/node/index.d.ts:306
  Node.orderedDelete    bindings/node/index.d.ts:309
  Node.orderedMove      bindings/node/index.d.ts:312
  Node.orderedSwap      bindings/node/index.d.ts:318
  OrderedSetOpId/OrderedSetApplyOptions bindings/node/index.d.ts:508-527
  AddOrderedSet         bindings/node/src/crabs_node.cc:1809
  GetOrderedSet         bindings/node/src/crabs_node.cc:1833
  OrderedSetApply       bindings/node/src/crabs_node.cc:1868
  (eager set + ot_data attach) src/OT/ot_execution.c (crabs_register_ot_type)
maturity: all STABLE
test_ref: bindings/node/test/ordered-set.js (same scenarios as the wasm block)
-->

### C (native)

```snippet:c/08-reorderable-list.c
```

<!-- PROVENANCE
target: native-c
verified: executed
symbols:
  crabs_ot_ordered_set_create     src/OT/ot_ordered_set.h:69
  crabs_ot_ordered_set_destroy    src/OT/ot_ordered_set.h:70
  crabs_ot_ordered_set_count      src/OT/ot_ordered_set.h:71
  crabs_ot_ordered_set_visible_count src/OT/ot_ordered_set.h:72
  crabs_ot_ordered_set_head       src/OT/ot_ordered_set.h:82
  crabs_ot_ordered_set_find       src/OT/ot_ordered_set.h:80
  crabs_ot_ordered_set_apply_insert src/OT/ot_ordered_set.h:91
  crabs_ot_ordered_set_apply_delete src/OT/ot_ordered_set.h:94
  crabs_ot_ordered_set_apply_move src/OT/ot_ordered_set.h:100
  crabs_ot_ordered_set_apply_swap src/OT/ot_ordered_set.h:103
  crabs_ot_ordered_set_merge      src/OT/ot_ordered_set.h:114
  crabs_ot_ordered_set_merge_position_maps src/OT/ot_ordered_set.h:117
  crabs_ot_op_id_init             src/OT/ot_types.h:109
  crabs_ot_operation_init         src/OT/ot_types.h:119
  crabs_ot_operation_set_payload  src/OT/ot_types.h:125
  crabs_ot_operation_t            src/OT/ot_types.h:61-72
  crabs_ordered_element_t         src/OT/ot_ordered_set.h:33-43
  CRABS_OT_OP_INSERT/DELETE/MOVE/SWAP src/OT/ot_types.h:22-28
  (placement tie-break: op-id compare) src/OT/ot_ordered_set.c:20-28
maturity: all STABLE
test_ref: test/test_ot_ordered_set.cpp:190-225 (MOVE) + :347-375 (merge commutative for concurrent singletons) + :377-393 (conflicting payload refuses to merge) + :395-420 (deletion wins)
-->

## Notes

- The snippet's merged replica re-derives its order from placement
  metadata, not from the arrival order of ops: `_materialize`
  (`src/OT/ot_ordered_set.c:293-350`) rebuilds the sequence from each
  element's anchor chain and placement priority, which is why both merge
  directions land on the same sequence in the concurrent-inserts demo.
- The deterministic reorder tie-break is *op-id* comparison
  (node id bytes, then sequence number — `src/OT/ot_ordered_set.c:20-28`),
  not the paper's timestamp-plus-hash priority formula
  (`docs/CRABS Extended.md` §4.4, :244). The convergence property is the
  same; the winning rule a reader should bank on is the one the code
  computes.
- The merge preflight (`_merge_preflight`, `src/OT/ot_ordered_set.c:197-257`)
  refuses to merge replicas whose same-op-id elements carry different
  payloads, or whose merged anchors would be invalid — merge returns `NULL`
  and the destination set is left untouched. That is the failure mode you
  *want* when two writers claim one element id: an error, not a silent
  overwrite.
- Position bookkeeping is the tombstone half of the story: deletes mark
  internal positions in the BST position map
  (`crabs_union_one` / `crabs_xi_one`, `src/OT/position_map.h:54-58`), and
  the maps merge through `crabs_bst_merge`, which copies src's deleted
  entries into dest (`src/OT/position_map.h:64-65`) — the snippet calls
  `crabs_ot_ordered_set_merge_position_maps` directly to show the seam.
- Status note (why the page stays PARTIAL with `languages: c wasm node`):
  the *op* layer is bound on both bindings and the snippets actually run;
  the *merge* layer — `crabs_ot_ordered_set_merge` +
  `merge_position_maps` (`src/OT/ot_ordered_set.h:114-118`, and the
  preflight/refusal/merge-commutativity tests cited above) — has no JS map
  entry, so a JS-only replica cannot merge a peer's serialized state; it
  converges by exchanging ops *with declared deps*, and the payload-conflict
  refusal plus merged position-map guarantees remain demonstrable only in C
  (`test/test_ot_ordered_set.cpp:377-420`). api-map §17 R8 tracks the row.
  Until a binding ships the merge, don't present op-exchange as full
  CRDT-merge parity: it is transform-based convergence, driven by the deps
  the issuer declares.
- A fallback for plain membership + rank (no order guarantees between
  members) is Recipe 2's OR-set with an integer rank held in the element's
  tags, plus Recipe 6-style triggers to promote items —
  last-writer-wins per element, weaker than this page's machinery, but
  reachable from day one. Do not present it as convergent reordering.
- The related JS-reachable primitives `itemChainHead` and
  `reportEquivocation` (api-map §11) give you tamper-evidence over writes to
  a replicated list, but they say nothing about *order*: order still needs
  this page's machinery.