al# Cookbook rewriting guide

The cookbook currently reads as an audit report: every page defends its own
honesty before it teaches anything. This guide restructures each recipe so the
reader learns a distributed-systems concept *through* CRABS, while every claim
stays verifiable. The verification substrate is the cookbook's differentiator —
nothing true gets deleted; it changes position and voice.

**Prime directive:** the reader leaves each page knowing *why* the approach
works, not just *that* the code does it.

---

## Voice

- Teach the reader, don't report to an auditor. The body text is a tutor
  talking; the footers are the evidence locker.
- Concrete over abstract. Every concept gets a tiny worked scenario with real
  numbers ("three laptops, one shared count") before any API is named.
- Active sentences, present tense, short paragraphs. "Merge takes the max per
  lane" not "max-per-lane semantics are applied during the merge path."
- Address the reader where it helps ("try it", "watch what happens"), but no
  cheerleading.

### Banned in body text (fine in provenance footers)

"We found", "we verified", "exercised by tests", "attested", "at time of
writing", "is honest about", "not yet implemented, sadly". If a sentence
describes *the document's own diligence*, it belongs in the footer, not the
lede. Headings never contain the words "verified" or "actually".

---

## Section structure per recipe

Keep the existing frontmatter unchanged — `build.mjs` requires
`number, slug, title, section, status, maturity`. Body headings map like this:

| Today | Becomes | Notes |
|---|---|---|
| (nothing — lede opens with the status framing) | **The problem** | NEW. A story with concrete numbers, no API names until the last line. |
| The naive version, and where it breaks | **The naive version, and where it breaks** | KEEP AS-IS in position and name. This is the teaching spine; polish, don't cut. |
| (inline concept mentions) | **The idea** | NEW. The underlying DS concept taught standalone — CRDT merge semantics, per-lane max, ordering vs. combining — as if CRABS didn't exist. 1–3 short paragraphs or one small diagram/table. |
| The shape | **How CRABS encodes it** | Same content, retitled. Now the reader meets the API *after* the idea, so fields and flags read as answers. |
| Recipe | **Try it** | Same runnable snippets. Where the wasm build permits, add or extend an `interactive:` panel — runnable in-browser beats paste-and-pray. |
| What it guarantees / what it doesn't | **What it guarantees / what it doesn't** | KEEP. Compress to bullets; each guarantee one line of prose, citations moved to footer. |
| Variations | **Variations** | KEEP. Lead each variation with *when you'd want it*, one sentence. |
| Notes | fold into provenance | |

New final section on every page:

### Verified against the code

One `<!-- PROVENANCE -->` block (the build renders these as footers) holding all
the file:line citations, test references, and binding-surface notes that
currently live inline. Prose allowed but telegraphic:
`ot_transform: src/OT/ot.c:412 · tested test/test_ot.cpp:88-104`.

## Where the honesty furniture goes

1. **Status badges** stay in frontmatter and the index table — untouched.
2. **Inline citations** drop from ~dozens per page to at most one or two, only
   where a claim would surprise a skeptic. Everything else moves to the footer.
3. **GAP callouts** (`> [!WARNING] GAP`) stay supported by the build and stay
   visible, but: max one per page, placed *after* the reader has learned the
   thing, and worded as information for the reader ("If you need X, that module
   doesn't ship yet — Recipe 14 explains the boundary") rather than confession
   ("We must disclose that...").
4. **UNSUPPORTED pages** (e.g. Recipe 14): reframe "A gap report, not a recipe"
   into a teaching page about the boundary itself — *why* strict cross-replica
   ordering can't fall out of merge, what a module would have to provide, what
   to do instead today. The gap content is unchanged; it stops apologizing in
   the first sentence.

## Homepage

- Tagline: keep the promise, change the posture.
  From: *"Verified recipes. Run in CI. Gaps stay visible."*
  To something like: *"Learn CRDTs, ordering, and coordination by building them
  — every recipe verified against the code it teaches."*
- Add a **Start here** reading order above the status table: group by section
  (Basics → Conditions → Convergence → Coordination → Composition → Ground
  truth) with one line per recipe saying what concept it teaches.
- The full status/maturity table stays, below the learning path.

## Before / after (Recipe 1 opening)

Before:

> You want a count… that many nodes can increment at once, while the records
> holding it stay divergent… no coordination step at the end.

After:

> **The problem.** Three laptops each count opens of the same document. They're
> offline half the time. When they sync, what's the true total?
>
> Store one integer, `count = 4`. Two laptops each increment while offline:
> both now hold `5`. When they sync, `5` meets `5` and nothing happens — the
> integer can't see that *two* increments occurred. The lost count is gone for
> good, and no retry logic fixes it, because the problem isn't the network.
> The problem is that `5` is the entire state.
>
> **The idea.** Give each laptop its own lane…

Same facts, same honesty — the proof still ships, in the footer.

## Mechanical checklist per page

- [ ] Opens with a concrete problem story (numbers, no API in first paragraph)
- [ ] "The idea" teaches the concept standalone
- [ ] API introduced after the idea
- [ ] ≤2 inline citations; rest in PROVENANCE footer
- [ ] ≤1 GAP callout, placed after teaching, reader-worded
- [ ] Headings contain no "verified"/"actually"/"we found"
- [ ] Guarantees section is bullets, one line each
- [ ] Frontmatter untouched; page still builds (`node site/build.mjs`)
