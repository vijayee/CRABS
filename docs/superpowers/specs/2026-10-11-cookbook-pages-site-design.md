# CRABS Cookbook GitHub Pages Site — Design

Date: 2026-10-11
Status: approved in conversation, pending spec review

## Purpose

A GitHub Pages site for the CRABS library whose flagship section is a **CRABS
Cookbook**: verified, runnable recipes for decentralized-application patterns.
The site is structured so future sections can be added alongside the cookbook.

## Decisions locked in conversation

- **Recipe set**: the 16-recipe catalog from `docs/cookbook.md` (simple →
  compositional: Basics, Conditions, Convergence, Coordination, Composition,
  Ground truth). Full cookbook protocol: authored prose, provenance footers
  citing `file:line` per symbol, maturity badges (STABLE / PRESENT / DESIGNED),
  STATUS lines, and GAP REPORTs wherever the API cannot deliver what the prose
  describes. No invented API, ever.
- **Languages per recipe**: C (native `src/` API), JS via `crabs-wasm` (browser +
  Node), JS via `crabs-node` (N-API). These are the only real language surfaces;
  recipes for a surface that cannot implement the recipe carry a GAP REPORT for
  that surface (e.g. `crabs-node` lacks HandlerState/BigInt registers).
- **Snippet testing**: approach A — *runnable source of truth*. Every code block
  shown on the site exists as a real executable file that a harness runs.
  Site pages get the snippet text injected at build time; snippets live nowhere
  else, so the site cannot drift from the tests.
- **Deployment**: in-repo sources + GitHub Actions workflow deploying to GitHub
  Pages from `master`.
- **Site generator**: hand-rolled static site (no MkDocs/Jekyll/11ty).
- **In-browser examples**: JS-wasm recipes may embed live demo panels using the
  dev wasm bundle (pattern exists: `examples/devtools_demo`,
  `examples/video_platform_p2p`).

## Site architecture

```
cookbook/
  recipes/NN-slug.md            recipe prose + structure; snippets injected at build
  snippets/c/NN-slug.c          the exact C blocks shown on the site
  snippets/wasm/NN-slug.js
  snippets/node/NN-slug.js
  prelude/c/prelude.h           tiny shared C scaffold (node create, setup)
  tests/run-snippets.mjs        runs every node+wasm snippet (pass = exit 0)
  tests/run-c.sh                cmake build + compile/run each C snippet
  tests/browser.spec.js         Playwright checks for interactive pages
  site/build.mjs                renders recipe markdown → HTML; injects snippet
                                file contents; runs → site/dist/
  site/assets/style.css         locked palette
  site/dist/                    built output (gitignored)
.github/workflows/deploy.yml    snippets tests → site build → Pages deploy
.github/workflows/site-ci.yml   test-only workflow for PRs (may merge with deploy)
```

### Pages

- **`/` — landing page** (new requirement): hero with Encryptstacean, one-paragraph
  CRABS summary, links to sections. The cookbook is the first section; future
  sections (paper, specs, audits) can be added as siblings later.
- **`/cookbook/` — cookbook hub**: the 16-recipe index table
  (`NN · title · status · maturity · languages`), styled per palette; Unlockster
  anchors the trust/guarantees callout.
- **`/cookbook/NN-slug/` — recipe pages**: sticky left sidebar (numbered recipe
  index with status badges), main column, right "on this page" outline.
- **`/cookbook/NN-slug/interactive.html`-style panels**: live in-browser wasm
  demos embedded in the recipes that support them (light theme, baby-blue
  panels), with Playwright tests asserting a live node/merge flow works.

## Palette (locked)

| Token | Value | Use |
|---|---|---|
| `--bg` | `#F5CE89` | page background (warm tan) |
| `--ink` | `#3A3325` | body text on tan |
| `--crab` | `#E0901F` | links, headings, active nav, status badges |
| `--steel` | `#76A5E6` | code block border, secondary accents, TOC |
| `--baby` | `#BBD9EE` | code block background (black text), callouts, panels |
| code text | near-black `#111111` | always black on blue blocks |

Code blocks use the blue scheme (baby-blue ground, steel-blue frame, black text).
Both mascots (`Encryptstacean.png`, `Unlockster.png`) are used in the site:
Encryptstacean = hero/encryption flavor; Unlockster = trust/guarantee flavor.
Theme is light-only (no dark mode styling).

## Recipe content contract

Follows `docs/cookbook.md` verbatim for the code-verification engine rules:
byte-identical authored sections, per-block provenance footers, honest
`verified: executed | traced`, maturity discipline (`no DESIGNED symbol in a
COMPLETE recipe`), GAP REPORT shape, per-page STATUS line. Page format adapted
for HTML per the layout above; the contract is unchanged.

The 16 recipes map to the catalog table in `docs/cookbook.md`:
1 shared count · 2 one vote per member · 3 execute once · 4 roles/policies ·
5 registrable profile · 6 progressive-disclosure moderation · 7 timed actions ·
8 reorderable list (bounded claim; rich text as 8b marked
UNSUPPORTED-UNTIL-BENCHMARKED) · 9 treasury atomic transfers · 10 private-but-
accountable actions · 11 subgroups without escalation · 12 federation via
attestations · 13 sovereign ledger · 14 strict market ordering ·
15 hardware-attested policy · 16 revocable data.

Each recipe carries its snippet in all three languages **or** a per-language
GAP REPORT stating exactly why that surface cannot deliver the recipe yet.

## Testing

- `node cookbook/tests/run-snippets.mjs` — executes every `snippets/node/*.js`
  and `snippets/wasm/*.js` under Node against the committed wasm artifacts;
  any failure fails CI.
- `cookbook/tests/run-c.sh` — CMake build of the library, then compile + run
  each C snippet against `prelude/c/prelude.h`; embedded asserts; any failure
  fails CI.
- Playwright (`cookbook/tests/browser.spec.js`) — loads interactive demo pages
  headlessly, drives a small node/merge flow, asserts visible state change.
- `.github/workflows/deploy.yml` — runs all three harnesses on `master`,
  then `site/build.mjs`, then deploys `site/dist/` to GitHub Pages. A red
  harness blocks deployment.

## Explicitly out of scope

- Rich-text collaborative editing claims (Recipe 8b stays unsupported-until-
  benchmarked per the excerpt's guidance).
- Search, dark mode, i18n.
- Bindings for languages that do not exist.
- Any new library capability to make a recipe work (gaps stay gaps, tracked.
  Recipe pages link to the tracking doc or say "no tracking doc found").