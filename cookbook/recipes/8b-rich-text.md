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
## What this page is

A gap report, not a recipe. Rich text — a shared document with styled spans,
characters, cursors, and deletions at any position — is the collaboration
feature everyone actually asks for, and CRABS ships *machinery* aimed at it:
an `OT_DOCUMENT` type, authored for collaborative editing (`docs/CRABS
Extended.md` §4.6, :277). Everything below is exactly one honest sentence
repeated in sharper form: **the C code exists and passes 21 unit tests; no
benchmark, no convergence test suite for concurrent documents, no binding
surface, and no tracking doc exist — so the codebase cannot yet deliver the
feature, and this site will not pretend otherwise.** There is no verified
snippet on this page, because a snippet would be a lie: this page's recipe
*is* the gap, and none of it is runnable by any consumer today.

## What the OT_DOCUMENT machinery actually is

In C only (`src/OT/ot_document.h`, all symbols below from that header):

- A document is a list of spans — double-linked, each with text bytes, up to
  8 style name/value pairs (`crabs_span_t`, :41-61) — plus an
  `ot_data_item` carrying the op log, priority counters and transform matrix
  (:67-73).
- Ops: `crabs_ot_document_insert_text` (:96), `delete_range` (:101),
  `apply_style` (:104), `merge_spans` (:108), `split_span` (:111) — matching
  the document op vocabulary `INSERT_TEXT / DELETE_RANGE / STYLE /
  MERGE_SPANS / SPLIT_SPAN` (`src/OT/ot_types.h:30-34`).
- Lifecycle and access: `crabs_ot_document_create / destroy`, span and
  character counts, `head` / `tail` (:87-119).
- The type registers the same way the ordered set does:
  `DATA_TYPE_OT_DOCUMENT = 0x11` (`src/CRABS/data_model.h:34`), accepted by
  the node binding's internal item-word parser (`'ot_document'`,
  `bindings/node/src/crabs_node.cc:213`), dispatched through the
  `__execute_ot__` executor branch (`src/StateMachine/state_machine.c:1401-1403`).
- Unit tests exist: 21 cases in `test/test_ot_document.cpp` — span create,
  insert, delete across spans, style application, span split, and overflow
  guards on span merge (`test_ot_document.cpp:248,279`).

What it is *not*, and this is the load-bearing absence: **there is no
function anywhere in `src/OT/` that merges two documents.** The ordered set
of Recipe 8 has `crabs_ot_ordered_set_merge` (`src/OT/ot_ordered_set.h:114`);
the document header (:87-119) declares lifecycle, ops and accessors — and no
`crabs_ot_document_merge`. Concurrent *single-document* ops are tested; a
*concurrent multi-replica* document, the entire point of collaborative
text, has no tested path at all.

## Why it is unbenchmarked

These are design facts from the project's own documents, not measured
numbers — nothing on this page is a benchmark, which is precisely the point:

- **Merge cost.** The protocol's own limitations table states: "OT transform
  complexity — O(N²) merge for concurrent operations", with log pruning and
  compaction named as mitigations (`docs/CRABS Extended.md` §11.1, :585).
  For a text document, whose op log grows by one op per keystroke, that is
  the difference between a list reordered a few times a day and a document
  edited hundreds of times a minute: the bounded claim is the O(N²) phrase,
  and nothing in `docs/` measures what N does to it in practice.
- **Storage growth.** Same table: "Tombstone growth — linear with edit
  count", mitigated by the unified compaction framework (:586). Text edits
  are individually tiny, so compaction pressure arrives orders of magnitude
  sooner than in the ordered-set case.
- **Concurrent same-position inserts.** The transform matrix's INSERT vs
  INSERT entry resolves ties by priority compare (`docs/CRABS Extended.md`
  §4.3, :219). The implemented priority generator,
  `crabs_ot_data_item_next_priority` (`src/OT/ot_types.h:141`: op-log count
  in the high 32 bits, an FNV-1a hash of the node id in the low 32, with the
  `(priority, node_id)` tie-break as backstop, `src/OT/ot_types.c:181-209`),
  has *no caller in `src/` — only its own unit tests (`test/test_ot_types.cpp:442-450`) touch it* — the mechanism the design
  names for exactly the INSERT-vs-INSERT case is dead code today. That is a
  correctness risk by absence: the deterministic tie-break exists
  (`src/OT/ot_ordered_set.c:20-28`) but a document-specific convergence
  behavior was never assembled or exercised.
- **Standard rich-text problems the design does not address.** Cursor
  stability (a collaborator typing ahead of your caret should not teleport
  it), IME composition (CJK input commits mid-session and every transform
  must respect the composing region), and rich-text span attribution under
  concurrent overlapping styles: grep the design + protocol documents under
  `docs/` for "cursor" and "IME" and nothing relevant returns. This site does
  not know whether
  the machinery would fail these — *nobody does, because there is no
  benchmark* — which is a stronger statement than a negative result would
  be, and it is why the page status is UNSUPPORTED rather than PARTIAL.

## The verdict

`OT_DOCUMENT` is implemented and unmeasured. Do not build a text editor on
it until a benchmark exists that runs concurrent multi-replica documents
against a reference implementation and reports convergence and merge cost.
No such tracking doc, benchmark, or plan item exists today — the honest
status is "no tracking doc found". When one does exist, it should live where
recipes point: like the consumption findings doc (`docs/CONSUMPTION_FINDINGS_2026-10-09.md`),
a tracking file a recipe can cite, not a TODO in a chat.

The gap, in the standard form:

> [!WARNING] GAP
>
> **Prose describes:** collaborative editing that never loses intent — two
> or more members editing one rich-text document concurrently, with styled
> spans, stable cursors, and convergence on every replica.
>
> **Codebase status:** `OT_DOCUMENT` implemented in C —
> `crabs_ot_document_create/destroy`, `insert_text`, `delete_range`,
> `apply_style`, `merge_spans`, `split_span` (`src/OT/ot_document.h:87-119`),
> 21 unit tests in `test/test_ot_document.cpp`, executor dispatch via
> `__execute_ot__` (`src/StateMachine/state_machine.c:1401-1403`), type word
> accepted by the node binding's parser (`bindings/node/src/crabs_node.cc:213`).
> But: no multi-replica merge function exists anywhere in `src/OT/`
> (`src/OT/ot_document.h:87-119` — no merge row), the priority generator the
> design relies on for INSERT-vs-INSERT has no caller
> (`src/OT/ot_types.h:141`), no binding exposes any of it (grep
> `ot|ordered|document|tree` in both `.d.ts` files: no OT exports; wasm
> `DATA_TYPE` at `bindings/wasm/index.d.ts:63`, node at
> `bindings/node/index.d.ts:326-335`), and neither the O(N²) merge cost nor
> the tombstone-growth claim of `docs/CRABS Extended.md` §11.1 (:585-586) has
> ever been measured.
>
> **Divergence:** the design (`docs/CRABS Extended.md` §4, :195-279) promises
> "collaborative editing" as the OT_DOCUMENT use case; the code implements
> single-replica document ops that were never assembled into a converging,
> bound, measured whole. A JS consumer cannot reach any part of the surface,
> so a snippet here would be fabrication rather than omission.
>
> **Tracking:** none found. No tracking doc, benchmark, remediation item, or
> plan entry for a document convergence benchmark exists — this recipe page
> is the tracking, until a real one does (status should flip to PARTIAL with
> a C snippet and a benchmark the day one exists).
>
> **Agent action:** code block omitted — for this page that is the *entire
> body*, not one surface of it. Do not write a rich-text recipe against
> `ot_document.h` symbols, do not pass `'ot_document'` as a data-type word
> where types are accepted (the parse is a dead end), and do not present the
> O(N²) statement as a measured cost — it is a design-table claim.

## The bounded alternative

The blessed application of this machinery is the one Recipe 8 covers:
`OT_ORDERED_SET` — ordered lists with concurrent insert/delete plus
deterministic merge (`src/OT/ot_ordered_set.h:63-117`, tested for
multi-replica merge in `test/test_ot_ordered_set.cpp:328-420` — the merge
tests the document type is missing). Playlists, ranked lists and
prioritized queues are deliverable behavior on the C surface today; shared
text documents are not, and this page exists so that the difference is
impossible to miss. See [Recipe 8 — reorderable list](/cookbook/reorderable-list/).