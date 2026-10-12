---
number: 8
slug: reorderable-list
title: A reorderable list two people can edit at once
section: Convergence
status: PARTIAL
maturity: STABLE
target: native-c
languages: c
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
- It is integrated as machine state, C-side: OT types register as real items
  (`crabs_register_ot_type`, `src/OT/ot_execution.h:69-72`) and the executor
  dispatches a `__execute_ot__` op through extract → transform → apply
  (`src/OT/ot_execution.h:38-54`; op type `src/CRABS/crabs.h:165`; executor
  branch `src/StateMachine/state_machine.c:1401-1403`).

This is the *paper's* shape (`docs/CRABS Extended.md` §4). The part a recipe
can drive today is the C surface above — everything in it is implemented,
compiled into `libcrabs`, and tested. What no surface can do yet is call any
of it from JavaScript, which is exactly what the two GAP blocks below
document.

## What it guarantees / what it doesn't

Guaranteed, on the C surface exercised in the snippet: after two replicas
merge, they hold the same element set and the same materialized order;
concurrent inserts at the same position are *both* kept (nothing
silently vanishes — the merge adds src-only elements rather than
overwriting, and the C suite asserts merge is order-commutative for
concurrent singletons, `test/test_ot_ordered_set.cpp:347-375`); a
duplicated op id whose payload disagrees refuses to merge at all instead of
pick-a-winner (`:377-393`); and a delete beats a concurrent live element —
deletion wins (`:395-420`). The reorder itself is also deterministic: a MOVE
re-stamps the placement of every element it knew
(`src/OT/ot_ordered_set.c:432-470`), and both replicas re-derive the same
sequence from the merged placements.

Not guaranteed — and say this before building on it:

- *Placement is last-writer-wins by op-id compare.* Concurrent MOVE/SWAPs
  from two members do not interleave per item: because a MOVE re-stamps the
  whole order, the op id that sorts larger (node id bytes, then sequence,
  `src/OT/ot_ordered_set.c:20-28`) wins the *entire* placement, deterministically,
  and the other member's reorder is displaced rather than merged. Members
  who only insert and delete lose nothing; members who concurrently
  *reorder* get one converged order, not both reorderings.
- *SWAP is a value exchange, not a placement op* (`src/OT/ot_ordered_set.c:478-493`
  swaps the two positions' payloads): a swap that travels across replicas
  while the same element ids also diverge elsewhere is constrained by the
  merge's per-element payload preflight — the snippet therefore demonstrates
  swap locally, exactly as its test does (`test_ot_ordered_set.cpp:231-261`).
- *No JavaScript access, today.* Neither binding exposes an OT surface —
  see the GAP blocks below. Rich-text/word-processing is a different and
  harder problem (cursor stability, IME composition, styled spans) with its
  own unbenchmarked status: that is Recipe 8b's page, not this one.

## Variations

- Tree-shaped reordering: the same OT machinery ships an `OT_TREE` type
  (`DATA_TYPE_OT_TREE = 0x13`, `src/CRABS/data_model.h:35`) with
  `insert_node / delete_node / reparent / reorder` ops
  (`src/OT/ot_types.h:36-39`), C-only like everything in this recipe.
- Bigger lists: the op log behind a set is bounded
  (`CRABS_OT_OP_LOG_MAX`, `src/OT/ot_types.h:91`) and prunable
  (`crabs_prune_ot_log`, `src/OT/ot_execution.h:56-58`) — the log-pruning
  and compaction story is the design doc's stated mitigation for OT merge
  cost (`docs/CRABS Extended.md` §11.1, :585).
- Ordered map variant: `DATA_TYPE_OT_ORDERED_MAP = 0x14`
  (`src/CRABS/data_model.h:37`) exists as a type word, with the same
  JS-absence caveat as everything on this page.
- Moderated review queues, i.e. ranked lists that a permission tree governs,
  compose this shape with Recipe 4's policies — the convergence machinery is
  independent of authorization; whoever may write applies the ops.

## Recipe

### crabs-wasm (browser / Node / edge)

No reorderable-list surface exists on the wasm binding — nothing to drive.

> [!WARNING] GAP
>
> **Prose describes:** the Recipe's whole demo on crabs-wasm — building an
> ordered list, two browser members inserting/moving/swapping concurrently,
> and converging both replicas to one order through `merge`.
>
> **Codebase status:** the capability is implemented and tested — in C.
> `crabs_ot_ordered_set_create/destroy`, the five `apply_*` ops, and
> `crabs_ot_ordered_set_merge` + `crabs_ot_ordered_set_merge_position_maps`
> live at `src/OT/ot_ordered_set.h:63-117` behind 19 test cases
> (`test/test_ot_ordered_set.cpp`); the executor branch
> (`src/StateMachine/state_machine.c:1401-1403`) and item registration
> (`src/OT/ot_execution.h:69-72`) exist too, exercised by
> `test/test_ot_execution.cpp:37-136`.
>
> **Divergence:** none of that is reachable from this binding. Grepping
> `bindings/wasm/index.d.ts` for `ot`, `ordered`, `document`, `tree`
> (case-insensitive) returns zero OT exports — the module's `DATA_TYPE`
> const (`:63`) exposes only the non-OT types, and `Node` declares no
> `addOrderedSet`/`addDocument`-style item, no op builder for
> `__execute_ot__` (`src/CRABS/crabs.h:165`), and no OT read-back. api-map
> §17 records the gap: "R8 | OT ordered set surface — **Not JS-bound**".
>
> **Tracking:** api-map §17, R8. No JS-binding work is scheduled; the C
> surface is the only callable implementation today.
>
> **Agent action:** code block omitted. Do not invent
> `addOrderedSet(...)`/`item.move(...)` onto the wasm d.ts — call the C
> surface directly from native code (see the C section), or wait for a
> JS-bound OT surface before promising this behavior to a wasm consumer.

### crabs-node (native Node.js)

Same story one door over: the node binding even *parses* the type word, and
that parse leads nowhere a user can go.

> [!WARNING] GAP
>
> **Prose describes:** the same demo on crabs-node — a native Node process
> building an ordered list and merging a second member's concurrent
> reorder into it.
>
> **Codebase status:** identical C capability as above
> (`src/OT/ot_ordered_set.h:63-117`, 19 test cases). The node binding comes
> the closest of the two: its internal item-word parser accepts
> `'ot_ordered_set'` → `DATA_TYPE_OT_ORDERED_SET` = `0x10`
> (`bindings/node/src/crabs_node.cc:212`; constant
> `src/CRABS/data_model.h:33`) and the same for the wire number
> (`crabs_node.cc:193`).
>
> **Divergence:** the parse stops at the word. No `d.ts` export uses the
> type — `bindings/node/index.d.ts` has zero OT symbols (grep for
> `ot|ordered|document|tree` case-insensitive returns nothing binding-side),
> `DATA_TYPE` at `:326-335` lists only the non-OT types, and there is no op
> builder for `__execute_ot__` and no OT read surface. api-map §15 calls
> this honestly: "PRESENT (parsed, but see §17 — no OT item machinery is
> wired for v1 recipes)".
>
> **Tracking:** api-map §17, R8 (same gap as the wasm row).
>
> **Agent action:** code block omitted. Do not pass
> `'ot_ordered_set'` as a data-type word and expect an ordered list — the
> word is accepted, no item machinery answers it. Call the C surface from a
> native process (next section) or from a custom wasm handler that reaches
> a bound surface, once one exists.

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
- A real JS-facing story for ranked lists today is Recipe 2's OR-set with an
  integer rank held in the element's tags, plus Recipe 6-style triggers to
  promote items — last-writer-wins per element, weaker than this page's C
  merge, but reachable. Do not present it as convergent reordering.
- The related JS-reachable primitives `itemChainHead` and
  `reportEquivocation` (api-map §11) give you tamper-evidence over writes to
  a replicated list, but they say nothing about *order*: order still needs
  this page's machinery.