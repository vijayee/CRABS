---
number: 8
slug: reorderable-list
title: A reorderable list two people can edit at once
section: Convergence
status: PARTIAL
maturity: STABLE
target: native-c
languages: c wasm node
teaches: concurrent edits to one ordered list via transform ops
---
## The problem

Two people manage one review queue: `["a", "b", "c"]`, and while they are
offline from each other, member A drags the top review `a` down to last
and member B drags `b` up to the top. Both come back online and sync.
Both edits must survive — one list, not A's list, not B's list, not
whichever sync got there last. Meanwhile a third member inserts two new
reviews "at the top", so every stored position shifts under everyone's
fingers mid-drag, and two of the members even insert into the same slot.

Insert concurrently at the same slot: both items must land. Move and
swap: the movement must survive the merge as a deterministic order, not
as whichever write happened to arrive last.

This is the convergence problem for *order*, and it is strictly harder
than the counter in Recipe 1: a counter only has to agree on a number, a
list has to agree on a *sequence* while positions renumber under
everyone's fingers. It is also — deliberately — NOT a collaborative text
editor: the page you want for shared rich text is Recipe 8b, a separate
and much more honest page. The ordered list here is the project's blessed
OT application.

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
edits reintroduces the coordination you are trying to avoid. Renumbering on
merge requires a total-order coordinator: again coordination.

What actually works is changing what an element *is*: give every element a
stable op-id identity (not an index), track the order as per-element
placement metadata, keep the tombstones so concurrent positions never
renumber, and resolve conflicting placements with a deterministic priority
so both replicas compute the same sequence without talking.

## The idea

**Identity and position are different things, and the naive version runs
them together.** A position is a fact about the whole list at an instant; an
identity is a fact about one element forever. Name elements — `(node,
sequence)` pairs minted by the op that created them — and they never get
renumbered or reused. The *order* becomes derived state: each element
carries placement metadata (the neighbour it anchors after, and the op that
placed it), and a list's visible order is computed by walking that chain.
Now B's "insert at top" cannot corrupt A's "delete position 2": both name
identities, not positions that were valid only in one replica's snapshot.

Two consequences of that split teach the whole design:

- **Positions get their own coordinate system.** Behind every visible
  slot sits an internal, tombstone-included position, and the two are
  bridged — delete something a peer never saw, and its *internal* slot
  still exists in the accounting, so every other element's coordinates
  stay stable while users see a gap-free list.
- **Concurrent ops are re-interpreted, not replayed.** When an op arrives
  at a replica that has seen other ops it didn't, an *operation
  transform* re-derives what the op should mean given the ops it missed —
  one transform function per op-type pair. Insert versus insert at the
  same slot needs a tie-break to decide which one shifts; the tie-break
  must be deterministic, or replicas that merge in different orders end
  up differently ordered — the very failure this page exists to prevent.

The asymmetry is worth teaching as clearly as the transforms. Concurrent
**inserts** interleave: both land, tie-break decides only their relative
order, nothing is lost. Concurrent **moves** do not interleave per row,
because a move is not "a change to one position" — it is a *re-stamp* of
the order it saw, every element's placement re-declared at once. Merging
two whole-order re-stamps picks one deterministic winner (the higher
op-id), and the other member's drag is displaced, not woven in. Members
who insert and delete lose nothing; members who drag concurrently get one
converged order, not both reorderings. Know that before you build drag
UX: re-ordering operations have whole-order granularity, even when the
UI shows row-level movement.

## How CRABS encodes it

- **Identity**: every element is identified by an op id —
  `(node_id, sequence, timestamp)` — and carries its order as placement
  metadata: an `anchor_id` (the element it sits after) plus a
  `placement_id` (the op that placed it) on `crabs_ordered_element_t`.
- **Coordinate spaces**: one internal (tombstones included), one visible
  (what users' positions reference), bridged by a BST position map
  (`crabs_xi` / `crabs_xi_inv`).
- **Vocabulary**: `CRABS_OT_OP_INSERT / DELETE / UPDATE / MOVE / SWAP` —
  an OR-set cannot express "move element from position 5 to position 2"
  at all.
- **Transform**: concurrent position ops resolve through a transform
  matrix — one transform function per op-type pair; concurrent inserts at
  the same position are ordered by priority. The design doc's formula is
  timestamp-and-hash; the *implemented* tie-break a reader should bank on
  is the op-id byte compare itself (node id bytes, then sequence).
- **The type**: `crabs_ot_ordered_set_create / destroy / get / find /
  head / tail`, the five `apply_*` ops, and the CRDT merge
  (`crabs_ot_ordered_set_merge` + `crabs_ot_ordered_set_merge_position_maps`)
  — the merge copies in src-only elements, takes the larger
  `placement_id` per element (op-id byte compare as tie-break), wins
  deletions, and re-materializes one order from placement metadata, not
  arrival order.
- **Machine state, not a library**: OT types register as real items and
  the executor dispatches a `__execute_ot__` op through extract →
  transform → apply. Both bindings bind the *op* layer: item creation
  (`addOrderedSet`) and op application whose payload a wire encoder
  builds.
- **Op identity is yours to manage**: every op's id is caller-supplied —
  replaying the same id with the same payload is a silent no-op (the
  executor's already-applied skip), and a *cross-replica* replay must
  carry the issuing replica's causal context in `options.deps` (max 16),
  or the transform treats the replica's earlier ops as concurrent and
  mis-shifts the position.
- **Install the policy first**: the sugar signs as the bootstrap admin —
  `setPolicy('__execute_ot__', 'role:admin')` — or the executor refuses
  every op with `unauthorized`.

## Try it

### crabs-wasm (browser / Node / edge)

```snippet:wasm/08-reorderable-list.js
```

### crabs-node (native Node.js)

```snippet:node/08-reorderable-list.js
```

### C (native)

```snippet:c/08-reorderable-list.c
```

## What it guarantees / what it doesn't

- Sequential ordered ops land in issue order and read back materialized
  (tombstones skipped).
- Concurrent inserts at the same position are *both* kept: replica pairs
  that exchange their ops with declared causal context converge on one
  identical order through the transform tie-break (both binding snippets
  pin the converged equality; the C suite asserts the same property for
  `merge` directly).
- A duplicated op id with the same payload is a no-op on replay; the same
  op id with a *different* payload refuses to merge at all instead of
  picking a winner — C merge property.
- Concurrent MOVE/SWAPs converge on one deterministic order — the op id
  that sorts larger wins the *entire* placement (whole-order re-stamp),
  so reordering is displaced rather than interleaved.
- A delete beats a concurrent live element through the merged position
  map — C merge property.
- The binding path converges by exchanging *ops*, and the op transform is
  dep-driven: it only skips log entries it can prove causally before or
  depended-on, so replays must carry `options.deps`. This is
  transform-based convergence, not full state-merge parity — a JS-only
  replica cannot absorb a peer's serialized state until a binding ships
  the merge.
- Rich-text/word-processing is a different and harder problem (cursor
  stability, IME composition, styled spans) with its own unbenchmarked
  status: that is Recipe 8b's page, not this one.

## Variations

- Tree-shaped reordering — when the list's elements have ancestry: the
  same OT machinery ships an `OT_TREE` type with
  `insert_node / delete_node / reparent / reorder` ops
  (src/OT/ot_types.h:36-39) — C-only: no
  binding creates or applies tree items (Recipe 8b's document type
  likewise).
- Bigger lists — when the op log's growth becomes the problem: the log
  behind a set is bounded and prunable, and log pruning + compaction is
  the design's stated mitigation for OT merge cost.
- Ordered map variant — when entries are keyed: `OT_ORDERED_MAP` exists
  as a type word, still without item machinery or bindings.
- Moderated review queues — when the queue ranks entries a permission
  tree governs: compose this shape with Recipe 4's policies; the
  convergence machinery is independent of authorization; whoever may
  write applies the ops.
- Tamper-evidence over the list's writes — when the threat is a rogue
  writer rather than concurrency: the related JS-reachable primitives
  `itemChainHead` and `reportEquivocation` give you sovereign-chain
  evidence over writes to a replicated list, but they say nothing about
  *order* — order still needs this page's machinery.
- Membership-plus-rank fallback — when plain membership with a weak rank
  beats the machinery: Recipe 2's OR-set with an integer rank held in the
  element's tags, plus Recipe 6-style triggers to promote items —
  last-writer-wins per element, reachable from day one. Do not present it
  as convergent reordering.

## Verified against the code

<!-- PROVENANCE
element identity: every element keyed by op id (node_id, sequence, timestamp) + anchor_id/placement_id placement metadata — crabs_ordered_element_t src/OT/ot_ordered_set.h:33-43.
coordinate spaces: internal(tombstones)/visible bridged by BST position map — crabs_xi/crabs_xi_inv src/OT/position_map.h:49-52 (+ union_one/xi_one :55-58); deletes mark internal positions (crabs_union_one/crabs_xi_one) and maps merge via crabs_bst_merge copying src deleted entries — position_map.h:64-65.
vocabulary: CRABS_OT_OP_INSERT/DELETE/UPDATE/MOVE/SWAP src/OT/ot_types.h:22-28 — an OR-set cannot express move (docs/CRABS Extended.md §4.1, :197-201).
transform: one function per op-type pair — 15x15 matrix on the item (src/OT/ot_types.h:93-102, init crabs_transform_matrix_init src/OT/ot_transform.c:317); insert-insert tie-break: skip rule src/OT/ot_transform.c:32-63 (replays carry deps; pinned by both binding ordered-set tests); design's priority formula (docs/CRABS Extended.md §4.3, :219 + §4.4, :244) is NOT the implemented rule — the bankable tie-break is the op-id byte compare (node id bytes, then sequence), src/OT/ot_ordered_set.c:20-28.
type surface: create/destroy/count/visible/get/find/head/tail + five apply_* + merge + merge_position_maps — src/OT/ot_ordered_set.h:69-117.
merge semantics: copies src-only elements, larger placement_id per element (op-id tie-break), deletions win, re-materialized order from placement metadata — src/OT/ot_ordered_set.c:514+ (_materialize :293-350 rebuilds from anchor chain + placement priority; the snippet's merged replica re-derives its order, not arrival order).
whole-order re-stamp: apply_move re-stamps every element's placement (src/OT/ot_ordered_set.c:432-478) — one deterministic winner per merged pair, not row-interleaved moves.
merge preflight: _merge_preflight (src/OT/ot_ordered_set.c:197-257) refuses same-op-id/different-payload or invalid-merged-anchor replicas — merge returns NULL, destination untouched (a failed merge is an error, not a silent overwrite).
status (why PARTIAL with languages: c wasm node): the op layer is JS-bound on BOTH bindings and the snippets execute; the merge layer — crabs_ot_ordered_set_merge + merge_position_maps, with the conflicting-payload refusal and merged-position-map guarantees — has no JS map entry (api-map §17 R8), so those properties are demonstrated in C: test/test_ot_ordered_set.cpp:347-375 (merge commutative for concurrent singletons) · :377-393 (conflicting payload refuses) · :395-420 (deletion wins).
paper vs code: the shape is the paper's (docs/CRABS Extended.md §4, :195-279); two layers JS-bound — the op layer (items + apply through the executor, both bindings) and the C-only merge layer. The convergence a JS replica observes is transform-based, driven by the deps the issuer declares — say that before building on it.
fallback note: recipe 2 OR-set + integer rank + recipe 6 triggers is LWW per element, weaker than this machinery.

target: crabs-wasm (snippet wasm/08-reorderable-list.js)
verified: executed
symbols:
  Node.addOrderedSet         bindings/wasm/index.d.ts:604
  Node.getOrderedSet         bindings/wasm/index.d.ts:610
  Node.orderedInsert         bindings/wasm/index.d.ts:623-624
  Node.orderedDelete         bindings/wasm/index.d.ts:626-627
  Node.orderedMove           bindings/wasm/index.d.ts:629-632
  Node.orderedSwap           bindings/wasm/index.d.ts:635-636
  OrderedSetOpId/OrderedSetApplyOptions bindings/wasm/index.d.ts:173-192
  crabs_wasm_add_ordered_set src/Util/wasm_helpers.c:917
  crabs_wasm_ot_apply        src/Util/wasm_helpers.c:1003
  crabs_wasm_ot_ordered_count/element src/Util/wasm_helpers.c:972/979
  crabs_ot_ops_to_wire       src/OT/ot_execution.h:52-54
  (__op_already_applied skip) src/OT/ot_execution.c:428, :605
  (executor branch)          src/StateMachine/state_machine.c:1799-1801
maturity: all STABLE
test_ref: bindings/wasm/test/ordered-set.js (seed order, MOVE 0->2, SWAP, DELETE, idempotent replay, deps-carry pin, policy refusal, two-machine op-exchange convergence)

target: crabs-node (snippet node/08-reorderable-list.js)
verified: executed
symbols:
  Node.addOrderedSet    bindings/node/index.d.ts:415
  Node.getOrderedSet    bindings/node/index.d.ts:421
  Node.orderedInsert    bindings/node/index.d.ts:434-435
  Node.orderedDelete    bindings/node/index.d.ts:437-438
  Node.orderedMove      bindings/node/index.d.ts:440-443
  Node.orderedSwap      bindings/node/index.d.ts:446-447
  OrderedSetOpId/OrderedSetApplyOptions bindings/node/index.d.ts:658-676
  AddOrderedSet         bindings/node/src/crabs_node.cc:2218
  GetOrderedSet         bindings/node/src/crabs_node.cc:2248
  OrderedSetApply       bindings/node/src/crabs_node.cc:2283
  (eager set + ot_data attach) src/OT/ot_execution.h:78-82 (crabs_register_ot_type)
maturity: all STABLE
test_ref: bindings/node/test/ordered-set.js (same scenarios as the wasm block)

target: native-c (snippet c/08-reorderable-list.c)
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
  (op type word)            src/CRABS/crabs.h:170
  (dispatch pipeline: extract → transform → apply) src/OT/ot_execution.h:43-64
maturity: all STABLE
test_ref: test/test_ot_ordered_set.cpp:190-225 (MOVE) + :347-375 (merge commutative for concurrent singletons) + :377-393 (conflicting payload refuses to merge) + :395-420 (deletion wins)
-->