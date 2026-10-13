---
number: 8
slug: rich-text
title: Collaborative rich text (experimental)
section: Convergence
status: UNSUPPORTED
maturity: EXPERIMENTAL
target: native-c
teaches: why rich text is a different (unmeasured) order of hard
---
## The problem

Two members open one styled document. Member A types two sentences into
the middle of a paragraph while member B, offline from A, rewrites a
styled span at the end and bolds a name near the start. Each keystroke is
its own edit — a document is touched hundreds of times a minute, not a
few times a day — every character's location is defined against a text
the other member is changing under it, and when the replicas sync,
both members must be looking at the same document, with every caret
still parked where its owner left it and every style attached to the
text it was meant to attach to.

This page exists because the machinery that solved the *ordered list*
(Recipe 8) does not stretch to this, and pretending otherwise would be
the first lie a collaborative-text recipe could tell.

## The naive version, and where it breaks

The reachable shortcut is to say "text is just a list of characters" and
build on Recipe 8's ordered set. It breaks on three independent axes:

- **Positions are a continuum, elements are discrete.** In a list, an
  element is minted once by one op and identified forever. In text,
  "position 120" names a point *between* characters — and a keystroke
  redefines what 120 means for every concurrent op in flight. Position
  as identity is exactly the corrupting thing Recipe 8's element
  identity exists to avoid.
- **The ops are composites.** A "delete" in text deletes a range across
  span boundaries; a styled span is an interval overlapping other
  intervals. The list ops (insert/delete/move/swap of whole elements)
  say nothing about how two overlapping style intervals resolve, or what
  happens to a span when its middle is deleted.
- **The failure costs are quadratic.** Every keystroke is an op the
  transform machinery may re-interpret against every op it didn't see;
  concurrent edit volume, not list volume, is what grows.

## The idea

What shared rich text actually asks the state machine to do is to keep
*three different kinds of position state* coherent at once, and that
triple is what makes it a different order of hard from the ordered list:

- **Character positions are defined against a moving document.** "The
  caret sits after the 120th character" is a true statement only against
  one replica's snapshot; the moment another member's insert lands, the
  statement needs re-interpreting. Every keystroke from every member
  re-defines everyone else's coordinates — a list reorders a few times a
  day, a document redefines coordinates hundreds of times a minute.
- **A caret is state, not decoration.** It is a position someone's
  session depends on; a transform that moves the document under it
  without moving it *with* the document teleports the caret. CJK input
  commits in the middle of a composing session, and every transform in
  flight must respect the composing region — transforms must treat
  sessions, not just characters, as their subjects.
- **Style intervals are overlapping intents.** Two members bolding
  overlapping ranges is not insert-vs-insert; it is interval merge, and
  the answer determines what the reader sees. Nothing in the list
  vocabulary (Recipe 8) expresses it.

And the standard this machinery must be judged by is not "it passes its
unit tests" but "two replicas, each editing concurrently, converge at a
measurable cost" — convergence *measured*, not asserted, because the
cost profile of text (keystroke-sized ops, quadratic re-interpretation
potentially compounding per keystroke) is the part no sequential test
exercises.

## What a module must provide

To deliver the problem above, a rich-text module has to clear, at
minimum, four bars — each one a checkable artifact, not a sentence:

1. **A merge function for concurrent replicas** — the module's whole
   point: replicas exchange state and re-derive identical documents. For
   the ordered list this exists and is tested; for a *document* the
   project's own header declares lifecycle, ops and accessors — and no
   merge function anywhere in `src/OT/`.
2. **A wired insertion-order tie-break** — concurrent inserts at the same
   character position resolve by a deterministic priority; the generator
   for that priority exists in the C tree but has no production caller,
   so the mechanism the design names for exactly the
   insert-versus-insert case is not currently assembled into a pipeline.
3. **A binding surface** — a JS driver has to be able to create the item
   and drive the ops; today the bound OT path is the ordered set only
   (Recipe 8), and any `ot_document` type word a driver passes goes
   nowhere a document op can reach.
4. **A convergence benchmark** — concurrent multi-replica documents run
   against a reference implementation, reporting convergence and merge
   cost. Without one, "the O(N²) merge" is a design-table claim, not a
   measured property, and the cost differences between a list reordered
   a few times a day and a document edited hundreds of times a minute
   are unknown in both directions.

Absent any one of these, the honest status is UNSUPPORTED, not
PARTIAL — a half-bound module that has never converged two documents is
not deliverable behavior, it is a direction.

## What exists, precisely

The C machinery (`src/OT/ot_document.h`) is real and unit-tested, and it
is worth reading as the *shape* of a future module:

- A document is a list of spans — double-linked, each with text bytes and
  up to 8 style name/value pairs — plus a data item carrying the op log,
  priority counters and transform matrix.
- Ops: `insert_text`, `delete_range`, `apply_style`, `merge_spans`,
  `split_span` — the document op vocabulary.
- Lifecycle and accessors: create/destroy, span and character counts,
  `head`/`tail`.
- Unit tests: 21 cases — span create, insert, delete across spans, style
  application, span split, overflow guards on span merge.

What it does not contain — the load-bearing absence: **no function
anywhere in `src/OT/` merges two documents.** Concurrent *single-*document
ops are tested; a concurrent *multi-replica* document — the entire point
of collaborative text — has no tested path at all.

## Do this instead

Deliverable today, on every surface this project binds: the ordered list
of [Recipe 8 — a reorderable list two people can edit at
once](/cookbook/reorderable-list/) — playlists, ranked lists,
prioritized queues — where insert
concurrency resolves with a deterministic tie-break and the whole-order
re-stamp semantics are documented in one converged direction. For plain
membership plus a weak rank (no convergence promises on order), Recipe 2
plus Recipe 6 gets reachable-from-day-one behavior. A text editor wants
Recipe 8b's gap closed first; when a convergence benchmark exists for the
document type, one runnable per language is the flip to PARTIAL.

> [!WARNING] GAP
>
> **Prose describes:** collaborative editing that never loses intent — two
> or more members editing one rich-text document concurrently, with styled
> spans, stable cursors, and convergence on every replica.
>
> **Codebase status:** `OT_DOCUMENT` implemented in C — document
> lifecycle, `insert_text`, `delete_range`, `apply_style`, `merge_spans`,
> `split_span` (`src/OT/ot_document.h:87-119`), 21 unit tests in
> `test/test_ot_document.cpp` (span create, insert, delete across spans,
> style, split, overflow guards — :248, :279), executor dispatch via
> `__execute_ot__` (`src/StateMachine/state_machine.c:1799-1801`), type
> word carried by the node binding's item-word parser
> (`bindings/node/src/crabs_node.cc:291`). But: no multi-replica merge
> function exists anywhere in `src/OT/` (`src/OT/ot_document.h:87-119` —
> no merge row, unlike the ordered set's `src/OT/ot_ordered_set.h:114`)
> and no benchmark measures the design-table costs; the bound OT path is
> the ordered set only (`crabs_wasm_ot_apply` refuses non-ordered-set
> items, `src/Util/wasm_helpers.c:1026`).
>
> **Divergence:** the design (`docs/CRABS Extended.md` §4, :195-279)
> promises "collaborative editing" as the OT_DOCUMENT use case; the code
> implements single-replica document ops that were never assembled into a
> converging, bound, measured whole. A JS consumer cannot reach any
> document op, so a snippet here would be fabrication rather than
> omission.
>
> **Tracking:** none found — no tracking doc, benchmark, remediation
> item, or plan entry for a document convergence benchmark; until one
> exists this recipe page is the tracking (status flips to PARTIAL the
> day a C snippet and a benchmark do).
>
> **Agent action:** no code block — for this page the omission *is* the
> body. Do not write a rich-text recipe against `ot_document.h` symbols,
> do not pass `'ot_document'` where a data-type word is accepted (the
> parse succeeds and binds no document path), and do not present the
> O(N²) statement as a measured cost — it is a design-table claim.

## Verified against the code

<!-- PROVENANCE
what exists: span list, ≤8 styles per span (crabs_span_t src/OT/ot_document.h:41-61) + ot_data item (op log, priority counters, transform matrix, :67-73); ops crabs_ot_document_insert_text :96 · delete_range :101 · apply_style :104 · merge_spans :108 · split_span :111; lifecycle/accessors create :87 / destroy :88 / head :118 / tail :119.
op vocabulary: CRABS_OT_OP_INSERT_TEXT/DELETE_RANGE/STYLE/MERGE_SPANS/SPLIT_SPAN — src/OT/ot_types.h:30-34; type words DATA_TYPE_OT_ORDERED_SET/DOCUMENT/TREE/ORDERED_MAP src/CRABS/data_model.h:33-37.
executor: __execute_ot__ dispatch — src/CRABS/crabs.h:170 (word), src/StateMachine/state_machine.c:1799-1801 (branch); node item-word parse of 'ot_document' bindings/node/src/crabs_node.cc:291; the bound apply refuses non-ordered-set items — src/Util/wasm_helpers.c:1026 (CRABS_ERR_NOT_OT_TYPE) — so no JS path reaches a document op.
no merge: src/OT/ot_document.h:87-119 declares lifecycle/ops/accessors and no crabs_ot_document_merge; the ordered set's merge row is the contrast — src/OT/ot_ordered_set.h:114.
insertion-order tie-break: priority generator crabs_ot_data_item_next_priority — declared src/OT/ot_types.h:141, defined src/OT/ot_types.c:180-207 (op-log count high 32 bits, FNV-1a node-id hash low 32, (priority, node_id) tie-break backstop) — but has NO caller in src/ (grep-verified; only its own unit tests touch it) and the transform matrix's INSERT/INSERT entry resolves ties by design priority (docs/CRABS Extended.md §4.3, :219) with the op-id compare as the implemented backstop (src/OT/ot_ordered_set.c:20-28).
design-table cost claims, NOT measured: "OT transform complexity — O(N²) merge for concurrent operations" + "Tombstone growth — linear with edit count", mitigations log pruning / unified compaction — docs/CRABS Extended.md §11.1, :585-586; nothing in docs/ measures N against either (grep: no benchmark file).
unsurveyed product requirements: cursor stability, IME composition, concurrent span attribution — no relevant hits in docs/ (design + protocol do not address them); unspecified + unmeasured is why the status is UNSUPPORTED rather than PARTIAL.
tracking status: no tracking doc/benchmark/remediation item exists for document convergence; when one does, keep it where recipes can cite (the consumption-findings precedent, docs/CONSUMPTION_FINDINGS_2026-10-09.md).
tests (single-replica only): 21 TESTs test/test_ot_document.cpp — SpanCreateDestroy :23 · InsertSingleSpan :67 · InsertMultipleSpans :78 · DeletePartial/AcrossSpans :129/:159 · ApplyStyle :189 · MergeSpans :216 · SplitSpan :311 · overflow guards :248 (u32), :279 (over-cap).

target: native-c (no snippet — see GAP Agent action)
verified: not applicable (no runnable surface)
symbols:
  crabs_span_t                  src/OT/ot_document.h:41-61
  crabs_ot_document_t           src/OT/ot_document.h:67-73
  crabs_ot_document_create      src/OT/ot_document.h:87
  crabs_ot_document_destroy     src/OT/ot_document.h:88
  crabs_ot_document_insert_text src/OT/ot_document.h:96
  crabs_ot_document_delete_range src/OT/ot_document.h:101
  crabs_ot_document_apply_style src/OT/ot_document.h:104
  crabs_ot_document_merge_spans src/OT/ot_document.h:108
  crabs_ot_document_split_span  src/OT/ot_document.h:111
  crabs_ot_document_head/tail   src/OT/ot_document.h:118-119
  CRABS_OT_OP_INSERT_TEXT/DELETE_RANGE/STYLE/MERGE_SPANS/SPLIT_SPAN src/OT/ot_types.h:30-34
  DATA_TYPE_OT_DOCUMENT         src/CRABS/data_model.h:34
  (ordered-set merge contrast)  src/OT/ot_ordered_set.h:114
maturity: EXPERIMENTAL (C-only, unbound, unmeasured — UNSUPPORTED is the binding status, not the code's)
test_ref: test/test_ot_document.cpp (21 single-replica unit tests) + test/test_ot_types.cpp:442-450 (priority generator, its only callers)
-->