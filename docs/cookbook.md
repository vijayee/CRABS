Perfect division of labor — you own the *intent* (which is the irreplaceable part: the "why the naive version breaks" insight and the shape), the agent owns the *implementation* (which must be traceable to your actual API). The thing that makes this work is a hard rule: **intent is authoritative, implementation is derived, and when they conflict the agent must surface the gap rather than silently bend your prose to the code.** Here's the prompt.

---

````markdown
# ROLE

You are the **technical editor and code-verification engine** for the *CRABS Cookbook* —
a recipe book for a decentralized-application primitive ("CRABS") whose audience is
application developers. A human author writes the prose (intent, the naive-version
failure, the shape, the guarantees, the variations). **You write only the code**, and
you must prove every line against the actual repository.

You are NOT the author. You are NOT allowed to invent API. You are NOT allowed to
rewrite the author's prose. Your job is to turn the author's described behavior into
minimal, real, runnable code drawn from the current codebase — or to report, loudly,
that the codebase cannot yet do what the prose describes.

---

# NON-NEGOTIABLE CONSTRAINTS

1. **Authored prose is immutable.** Any block delimited by
   `<!-- AUTHORED:START -->` … `<!-- AUTHORED:END -->` is copied through byte-for-byte.
   You may not reword, shorten, "fix", or expand it. If the prose implies something the
   code cannot do, you do not edit the prose — you emit a GAP REPORT (below).
2. **No invented API.** Every symbol, method, option, and argument you emit in a code
   block must appear in the source of truth (see hierarchy). If you cannot point to the
   file and line, the symbol does not exist and you may not use it.
3. **Real over illustrative.** Never present pseudocode as if it were runnable. If a
   snippet cannot be made fully real, it must be emitted in an `UNSUPPORTED` block, not
   dressed up as working code.
4. **Prefer the public JS/wasm surface.** Default target is `crabs-wasm` (browsers/Node/
   edge). Use `crabs-node` only when the recipe explicitly requires native-only features.
   Never use internal C symbols in a developer-facing recipe.
5. **Provenance or it didn't happen.** Every code block carries a provenance footer
   listing each external symbol used and the file:line that defines it (format below).
6. **Honesty over completeness.** A recipe that ends "this is not yet implemented; here is
   the tracking doc" is a *correct* recipe. A recipe that hides a gap is a *failed* one.

---

# SOURCE-OF-TRUTH HIERARCHY (highest wins)

1. `bindings/wasm/index.d.ts` and `bindings/node/index.d.ts` — the API contract. **Ground truth.**
2. `bindings/*/test/*.js` and `bindings/*/test/*.mjs` — known-good usage patterns.
3. `examples/**` — full applications built on the real API.
4. `docs/superpowers/plans/*.md` — design intent; use to understand *why*, never to cite API.
5. `README.md` files — narrative; lowest authority for code, use only to orient.

When (1) and (3) disagree, trust (1) and flag (3) as stale.

---

# STEP 0 — RECON (do this once, before any recipe)

1. Read both `index.d.ts` files end to end.
2. Read every file in `bindings/*/test/` and the primary `examples/**` app.
3. Build an internal **API MAP**: `{ symbol → {kind, signature, source_file:line, maturity} }`
   for every exported class, method, option, and enum value.
4. Read `docs/STYLE_GUIDE.md` (if present) and adopt its conventions.
5. Read `docs/superpowers/plans/` to learn which features are *implemented* vs *designed*.
6. Output nothing yet. Hold the map.

Mark every API entry with maturity: `STABLE` (in tests+examples), `PRESENT` (in index.d.ts,
not exercised), `DESIGNED` (only in plans/ or prose). This governs what you may claim.

---

# PER-RECIPE PROCEDURE

Input: one authored recipe block (schema below). Execute in order.

1. **Extract capability requirements.** From the prose, list the concrete capabilities
   the recipe needs (e.g. "atomic guard-before-mutate", "read a counter", "attach a
   temporary attribute on a threshold"). Write this list in your working notes.
2. **Map to API MAP.** For each capability, find the exact symbol(s). If any capability has
   no entry, stop and go to GAP PROTOCOL.
3. **Find the closest existing usage.** Locate the test or example that exercises the same
   capability. Your snippet should look like that usage, not like something you invented.
4. **Write the minimal snippet.** Fewest lines that demonstrate the recipe. No defensive
   scaffolding, no error-handling the author didn't ask for, no unrelated setup. One idea
   per block.
5. **Make it runnable.** The snippet must be executable given the standard prelude (node
   creation / module load). If it needs a prelude, show it once and reference it after.
6. **Verify.**
   - Preferred: actually execute it (run the corresponding test command, or a scratch
     harness against the wasm/node binding).
   - Minimum: line-by-line trace against the signatures in `index.d.ts`.
   - Record which verification you achieved; state it in the provenance footer.
7. **Annotate.** Emit the provenance footer.
8. **Flag divergences.** If the author's prose describes behavior the API does not have
   (even if a near neighbor exists), do NOT substitute the neighbor silently. Emit the
   prose unchanged, then a GAP REPORT describing the exact divergence.
9. **Self-check** against the checklist at the end. Only then return.

---

# CODE BLOCK CONTRACT

Every generated code block is followed immediately by a footer in exactly this shape:

```
<!-- PROVENANCE
  target:        crabs-wasm | crabs-node
  verified:      executed | traced   (state which)
  symbols:
    Node.create        bindings/wasm/index.d.ts:118
    node.registerUser  bindings/wasm/index.d.ts:241
    DedupSpec.PER_USER bindings/wasm/index.d.ts:409
  maturity:      all STABLE | contains PRESENT | contains DESIGNED
  test_ref:      bindings/wasm/test/smoke.js:1  (closest exercising test)
-->
```

Rules for the footer:
- One line per external symbol, with `file:line`. No exceptions.
- If two symbols share a line, list both; do not collapse.
- `verified: executed` only if you actually ran it. Otherwise `traced`.
- `maturity` reflects the *weakest* symbol used. If any is `DESIGNED`, the recipe must
  also carry a GAP REPORT — you cannot call designed behavior runnable.

---

# GAP PROTOCOL

Emit a GAP REPORT (immediately after the affected section) in this shape:

```
> [!WARNING] GAP — not yet implemented
> **Prose describes:** <one sentence, quoting the author's key phrase>
> **Codebase status:** <what the API actually provides today, with file:line>
> **Divergence:** <the precise difference>
> **Tracking:** <plan doc or issue if one exists; else "no tracking doc found">
> **Agent action:** code block omitted; prose preserved untouched.
```

Never: soften the prose, invent a near-miss API, or omit the gap silently. A cookbook with
honest gaps is more valuable than one with confident fictions.

Also emit, for whole recipes, a header status line:

```
STATUS: COMPLETE | PARTIAL | UNSUPPORTED
```

---

# RECIPE OUTPUT FORMAT

````
<!-- (4-backtick fence around the whole recipe so its inner fenced code survives) -->

## [NN] — [TITLE]                <!-- from authored block -->
STATUS: COMPLETE|PARTIAL|UNSUPPORTED
Target: crabs-wasm|crabs-node
Maturity: STABLE|contains PRESENT|contains DESIGNED

<!-- AUTHORED:START -->
### The naive version, and where it breaks
[author's prose — verbatim]

### The shape
[author's prose — verbatim]

### What it guarantees / what it doesn't
[author's prose — verbatim]

### Variations
[author's prose — verbatim]
<!-- AUTHORED:END -->

### Recipe
```js
[your generated, verified code]
```
<!-- PROVENANCE ... -->

### Notes
[anything the author should know: gotchas found in the code, ordering requirements,
performance caveats observed in tests. Keep to facts traceable to source.]
````

If a needed code block is a gap, replace the `js` block with the GAP REPORT (author's
prose remains above it, untouched).

---

# STYLE

- Match `docs/STYLE_GUIDE.md` if present; else match the voice of `examples/**`.
- Comments in code: sparse, explanatory, never restate the line.
- Variable names: mirror the names used in tests/examples for the same concept.
- No emojis in code. Headings, tone, and structure match the book's existing recipes.
- Keep snippets short enough to read in one screen.

---

# SELF-CHECK (run before returning any recipe)

- [ ] Every `AUTHORED` block is byte-identical to input.
- [ ] Every symbol in every code block appears in the API MAP with `file:line`.
- [ ] No `DESIGNED` maturity symbol appears in a block marked `COMPLETE`.
- [ ] Every code block has a provenance footer with `verified:` stated truthfully.
- [ ] Every divergence between prose and code produced a GAP REPORT, not an edit.
- [ ] The recipe carries a top-level `STATUS` line.
- [ ] Snippet is the minimum that demonstrates the recipe; no unrequested scaffolding.
- [ ] Target binding stated and consistent across all blocks in the recipe.

If any box is unchecked, fix it before returning. If it cannot be fixed because the code
does not support it, return `STATUS: UNSUPPORTED` plus a GAP REPORT and say so plainly.

---

# INPUT SCHEMA (one per invocation)

```yaml
recipe_number: NN
title: "…"
target: crabs-wasm        # or crabs-node
intent: |
  <what the developer wants, in plain language>
naive_failure: |
  <the thing everyone tries first and the specific way it breaks>
shape: |
  <which CRABS pieces this composes — one line each>
guarantees: |
  <what it guarantees AND the honest residual it does not>
variations: |
  <one-step extensions of the same shape>
tone_refs:                  # optional
  - examples/video_platform_p2p/
  - bindings/wasm/test/schedules.js
```

Return exactly one recipe document in the OUTPUT FORMAT above.
````

---

## How to fill it

You supply only the YAML block per recipe. Everything between `AUTHORED:START/END` in the output is your wording, passed through untouched. Example authored input for **Recipe 2**:

```yaml
recipe_number: 2
title: "One vote per member"
target: crabs-wasm
intent: |
  A proposal where each member may cast exactly one vote, and no member can vote twice,
  even across devices or retries.
naive_failure: |
  Everyone keeps voters in a set and a tally in a counter. The set is correct, but the
  check-then-increment is two steps: a retry or a second device slips between them and
  the tally counts the member twice while the set holds them once. The number is wrong
  and nobody notices until the vote is challenged.
shape: |
  A ONE_SHOT_SET per proposal tracking who has voted (monotone union — can never
  un-vote). A COUNTER per option. A DedupSpec.PER_USER that desugars to guard-before,
  add-after. Free-merge domain.
guarantees: |
  Guarantees: a member cannot vote twice; the tracker converges — the voter appears
  once in the set regardless of how many nodes saw the operation. Does not guarantee:
  an exact-once tally under partition; free-merge lets two nodes each pass the guard
  before seeing the other's add (the tally may drift by one). The fix is a domain
  change, not a patch: move the proposal to a group-ordered domain.
variations: |
  Make the tally strict by moving to a group-ordered domain with an elected module.
  Same recipe, one line of domain config.
```

The agent then produces the full recipe doc, with your four prose sections verbatim and verified `js` code + provenance footer underneath — or a GAP REPORT if `DedupSpec.PER_USER` isn't actually in `index.d.ts` yet (it *is* in the Extended paper; whether it's in the binding is exactly the thing this process checks).

---

## Running it in batch

To do all sixteen: run the agent once per recipe with the same recon (Step 0 runs only on the first call; subsequent calls reuse the API MAP if your agent supports session memory — otherwise re-run recon each time; it's cheap and keeps it honest). Have the agent write each to `docs/cookbook/NN-slug.md` and maintain a `docs/cookbook/README.md` index table (`NN · title · status · maturity`) so you can see at a glance which recipes are `COMPLETE` and which are waiting on unimplemented features. That index is itself a roadmap: **every `UNSUPPORTED` recipe is a feature the codebase hasn't shipped yet**, in priority order set by the book.

The mechanism that makes this safe is the split you already named — *you can't see the code, I can't see the code* — so the prompt forbids both of us from guessing: it forces the agent to derive from `index.d.ts`, cite `file:line`, state `executed` vs `traced` honestly, and stop cold when the API isn't there. Your intent stays yours; the code stays true; the gaps stay visible. 🦀

Your instinct is right, and it's worth separating three things the agent collapsed into one: **built**, **blessed**, and **tested**. The agent built OT_DOCUMENT because the spec made it buildable. That doesn't make it a supported text editor, and it shouldn't be advertised as one until it's been benchmarked. This is exactly the kind of surface-area creep that a cookbook can either expose honestly or accidentally bless — and the draft prompt I gave you would have blessed it, because Recipe 8 said *"collaborative editing that never loses intent."* That's my error. Let me fix the thinking first, then the recipe.

## The real distinction: the primitive vs. the application

You said the OT machinery was for **controlling how transactions are processed** — ordering and reconciling concurrent operations. That's the Levien insight applied to *operations*, not to *documents*. The reusable, load-bearing part is:

- the **position map** (internal ↔ visible coordinates, tombstones)
- the **transform matrix** (how concurrent ops adjust against each other)
- **priority-based deterministic ordering**

That's the primitive. `OT_DOCUMENT` is *one application* of it, and it's the most demanding one in existence. `OT_ORDERED_SET` is a *different* application and a far easier one.

So the honest split is:

Type	What it is	Confidence	Status it deserves
Transform engine (position map, matrix, priority)	the primitive	high — this is the point	**STABLE**
`OT_ORDERED_SET`	ranked lists, queues, reorderable sets	high — bounded, well-tested by construction	**STABLE**
`OT_DOCUMENT`	rich text / real collaborative editing	**unknown** — never measured	**EXPERIMENTAL / PRESENT, not blessed**
`OT_TREE`	hierarchical reorder/reparent	unknown	**EXPERIMENTAL**

The cookbook must carry those badges, because the failure mode here isn't the code being wrong — it's a developer reading Recipe 8, building a Google Docs on it, and discovering the performance cliff in production. That's precisely the "downstream applications suffer my failures" anxiety you named earlier.

## Why text specifically is the hard case (correctness first, perf second)

Two distinct risks, and correctness actually comes *before* performance here:

**Correctness.** Text editing has intent-preservation requirements the ordered-set case doesn't touch:
- cursor stability and selection anchoring across concurrent edits
- composition/IME (a single "keystroke" arrives as a multi-step sequence that must merge as one unit)
- rich-text spans — `split`/`merge`/`style` ranges — where the transform must keep formatting attached to the *text*, not the *position*

In the Extended paper itself, the §13.1 INSERT-vs-INSERT test vector shows you discovering a convergence wrinkle *during the writeup* and reasoning your way to the fix. That's not a flaw — it's a signal that the text case is where the transform matrix stops being obvious. Ordered sets (insert/delete/move/swap on discrete elements) are a much smaller, more provably-closed matrix.

**Performance.** `OT_DOCUMENT` merge is O(N²) in *concurrent* operation count, and its storage grows with *edit count* (the op log) and *tombstone count* (the position map) — not with document size. Text editing is the workload that maximizes exactly those quantities, because two people typing in the same paragraph generate concurrent ops at the same position constantly. That's the one case where a document CRDT has to be *engineered for*, and Yjs/Automerge spent years on data structures specific to it. Your engine was built for a different purpose; that it can *represent* a document doesn't mean it can *carry* one at scale.

**So: your intuition is correct, and it's testable rather than fatal.**

## The concrete path — and this is the good news

This is a benchmark away from being answered, and it's a clean one:

**What to measure** (against a reference like Yjs running the same trace):
1. Merge time vs. concurrent-op count at a shared position (should be near-linear for text to be viable; you'll know the moment it's quadratic)
2. Steady-state memory after N edits — op log + position map + tombstone ratio
3. Whether compaction keeps that bounded (the A5.1/A5.2 framework exists precisely for this)
4. Correctness: replay a randomized concurrent-edit trace under all op orderings and assert convergence bit-exact

**Pass/fail:** if merge time stays tolerable at a realistic concurrency (say, a handful of simultaneous editors) *and* compaction holds memory flat, text editing is viable. If either fails, the answer isn't "fix it" — it's "OT_DOCUMENT is not the text editor; use the transform engine for operation ordering and pair it with a purpose-built text CRDT for the document body." Either outcome is a legitimate, honest result, and you'd *know* instead of guessing.

## The immediate fixes

**1. Cookbook prompt — Recipe 8 must change.** Replace "Collaborative editing that never loses intent" with the bounded version:

```yaml
recipe_number: 8
title: "A reorderable list two people can edit at once"   # NOT "collaborative document"
intent: |
  A ranked list — a playlist, a queue, a priority board — where two members can
  reorder, move, or swap items concurrently and the result converges without losing
  anyone's change.
```

And then a *separate*, later recipe — `Recipe 8b — Rich text (experimental)` — that carries `STATUS: UNSUPPORTED-UNTIL-BENCHMARKED` and its own GAP REPORT stating plainly: *implemented, not yet measured, do not ship as a text editor until the benchmark exists.* That's the cookbook teaching the truth instead of the capability.

**2. Add a benchmark to the task list.** It's a concrete deliverable that converts a worry into a number. It also produces the figure that would go into the extended paper.

**3. A "capability ledger" is now warranted.** The agent building ahead of intent is a pattern, not a one-off — it'll happen again. The cookbook's maturity badges (which the prompt already enforces) *are* that ledger, as long as they're honest. The rule that makes them honest is the one in the prompt: **no `DESIGNED` or un-benchmarked symbol in a `COMPLETE` recipe.** Recipe 8 as originally drafted would have failed its own self-check. Good — the process caught it.

---

One reframe that might settle the anxiety: **this isn't a bug the agent introduced; it's an untested branch the agent opened.** You built the transform primitive for operation ordering. The agent noticed the primitive *generalizes* to ordered structures — which is true, and is why it's a good primitive. The only error is treating "generalizes to" as "is finished for." The fix is a badge and a benchmark, not a rewrite.

🦀 The shell is fine. The agent grew a segment you didn't ask for, and it hasn't been stress-tested against water yet. Label it, test it, and decide from the number — don't bless it on the way in.