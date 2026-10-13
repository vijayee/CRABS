# Cookbook Gap-Fill + Teaching-Restyle — Design

Date: 2026-10-13
Status: approved in conversation, pending spec review

## Purpose

Two sequenced phases, one branch each landing on master:

- **Phase A — fill the gaps the cookbook documents.** Make the JS bindings and
  library deliver everything the recipes honestly flagged as missing, correct
  the cookbook's one stale finding (ordering module), remove the
  hardware-attestation recipe, and re-bless affected pages with real executed
  snippets.
- **Phase B — restyle the cookbook per `cookbook/STYLE.md`.** Every page
  restructured from audit-report voice into problem → idea → encoding → try-it
  teaching prose, citations consolidated into one "Verified against the code"
  footer, homepage retagged with a learning path.

Phase B starts only after Phase A's final review passes, so no page is
styled twice.

## Phase A — gap fill

### Scope of each task (dependency order)

**A1. wasm `getUser` readback fix.** `bindings/wasm/bindings-core.js` hardcodes
`publicKeyHex: ''`, `keyVersion: 0`, `status: 'active'` (and empty
`verifiedBy`). Map the real machine state the way crabs-node does
(`bindings/node/src/crabs_node.cc:1139-1157`). Node-side behavior is already
correct and must not regress.

**A2. DedupSpec JS surface** (recipes 2/3). The C surface exists
(`src/Dedup/dedup.h`; `state_register_op_type_def` at
`src/CRABS/data_model.h:757`; `__define_operation_type__` at
`src/CRABS/crabs.h:161` carries dedup data). Both bindings gain an
op-type-definition path that attaches `DEDUP_PER_USER` / `DEDUP_GLOBAL`
/ registered-free specs. Shape: a `Node.defineOperationType(type, options)`
-style API (exact naming decided in implementation, cited in spec-review)
built as a serialized `__define_operation_type__` op — the dedup spec rides
in the op payload (`tracker_path` / `flag_path` fields,
`data_model.h:364-374`).

**A3. Schedules on crabs-node** (recipe 7). Port the wasm schedule surface to
the node binding via `src/Scheduler/scheduler.h`: schedule one-off + recurring,
cancel, process-due tick with explicit clock, pending reads, occurrence
budget. The wasm surface (`bindings/wasm/index.d.ts:324-334`) is the shape
reference.

**A4. OT ordered set JS** (recipe 8). The node binding already parses the
`ot_ordered_set` data-type word (`bindings/node/src/crabs_node.cc:212`) with no
item machinery behind it. Trace where dead-ends; finish the path so both
bindings can create ordered-set items, insert/move/delete elements, and read
the converged order. C reference: `src/OT/ot_ordered_set.h`, usage in
`test/test_ot_ordered_set.cpp`.

**A5. Locks / tx-manager ceremony JS** (recipe 9). Three pieces: `Node.addResource`
on wasm (node already has it, `bindings/node/index.d.ts:199`); claim /
`requiredState` setters surfacing through op payloads (`state_machine.c`
token-check path); a node-visible tx-manager attachment (node binding uses
`crabs_tx_manager_none` today; wire `crabs_tx_manager_memory` selectable).
The machine-local/cooperative caveats in recipe 9 stay true and stay
documented.

**A6. Attestation consumption JS** (recipe 12). Op-level `attestations` attach
(wire structure per `attestation_deserialize`/`src/Lineage/lineage.h`), the
`@parent/` endorsement resolution path, and deserialize/verify accessors —
issuance already exists on both bindings; consumption is C-only
(`state_machine.c:700-756`).

**A7. ABE decrypt JS** (recipes 6/16). Expose the round trip
(`crypto_abe_setup` / `keygen` / `encrypt` / `decrypt` from
`src/Crypto/crypto.h:96-131`) to both bindings. Master-key ownership: the
machine owns the MSK generation material under its admin attribute state
(same trust story the C tests use — `test/test_crypto.cpp:163-301`); the
binding surface decides whether setup returns a portable master handle or the
machine holds it internally. Decision: the machine owns the master
key-gen material internally (matching how the C tests derive keys) and the
bindings expose decrypt-through-the-machine; no portable MSK handle ships.

**A8. Documented divergences** (from recipes 4/6/12/16 notes):
- wasm temp-attribute string doubling (`clearance:moderator:moderator`,
  `bindings-core.js:686-696`) vs node's plain token — adopt node's plain token
  as canonical; update wasm consumers + tests.
- node `createTrigger` stamps the signer as literally `'admin'`
  (`crabs_node.cc:1846-1862`) — sign with the actual caller identity.
- dissolve one-way door: the handler refuses already-REVOKED entries
  (`lineage.c:1787-1790`) while `lineage.h:516-520` promises "dissolution stays
  available" — code is truth; reconcile whichever the implementer judges to be
  the intended semantic (preference: honor the header, allow dissolving
  revoked entries, since the tombstone pipeline already gates on DISSOLVED).
- recipe 16's grammar pitfall (one-clause `'AND role:member'` mis-parses) —
  either fix the parser's single-prefix case or document as a lint-able rule;
  decide by size (fix if the change is genuinely one guard in
  `src/Crypto/crypto.c:676+`, else document).

**A9. Cookbook corrections.**
- Recipe 14: the Raft ordering module exists and is node-bound
  (`src/Raft/raft_module.h`; `bindings/node/index.d.ts:311+`; `createRaftHost`
  reference loop in `bindings/node/index.js`). Rewrite recipe 14 as a runnable
  single-host (or multi-peer-loop) market demo; api-map R14 row rewritten from
  source.
- Recipe 15 (hardware attestation) deleted entirely; recipe 16 becomes recipe
  15 (`number: 15`, slug unchanged `revocable-data`; cross-references in other
  pages updated; api-map R15 row deleted).
- api-map regenerated against current d.ts + sources; the R2/R3/R7/R8/R9/R12/R16
  ledger rows flip to STABLE-with-citations as each gap closes.
- Wasm artifacts regenerated (`build_wasm.sh`) and committed so the wasm
  snippets exercise the new surfaces; node binding rebuilt in CI (workflow
  already does).

**A10. Recipe re-blessing.** Every page whose GAP block this ladder filled
gets: GAP callout removed, real snippet(s) added for the previously-gapped
language, frontmatter `status: COMPLETE` and `languages` updated to the full
delivered set, provenance footers regenerated with real citations, all
snippets executed green by the harnesses. Gap pages that survive (8b rich
text) keep their single GAP callout.

### Testing (Phase A)

Same discipline as the site build: C additions get gtest coverage in `test/`;
binding additions get coverage in `bindings/*/test/` (plain `node` assert
scripts) plus the cookbook snippet harnesses. The recipes' new snippets ARE
executed by `cookbook/tests/run-snippets.mjs` and `run-c.sh`; the browser
check keeps the interactive panel green. Existing tests must not regress; the
temp-attr and createTrigger fixes may require updating existing wasm/node
tests that encode the old behavior.

## Phase B — STYLE.md restyle

### Per-page restructure (16 remaining recipe pages: 15 runnable + 8b)

Mapping (from `cookbook/STYLE.md`, binding on implementation):

- NEW **The problem** — concrete story with numbers, no API in first paragraph.
- **The naive version, and where it breaks** — kept, position and name; polish.
- NEW **The idea** — the DS concept standalone (1-3 short paragraphs or a small
  table), no CRABS API names.
- **How CRABS encodes it** — current "The shape" retitled; API after the idea.
- **Try it** — current "Recipe" retitled; same snippet fences (build stays
  snippet-file-driven). One optional extension: an `interactive:` panel on one
  more recipe (member-profile) — stretch goal, not blocking.
- **What it guarantees / what it doesn't** — kept, compressed to bullets
  (one line each), citations moved to the footer.
- **Variations** — kept; each leads with when you'd want it.
- **Notes** — folded into the new final section.
- NEW final **Verified against the code** — one PROVENANCE page block holding
  all file:line citations + test refs moved inline (`ot_transform:
  src/OT/ot.c:412 · tested test/test_ot.cpp:88-104` style).

Honesty furniture per STYLE: ≤2 inline citations per page (only where a claim
would surprise a skeptic); ≤1 GAP callout, placed after teaching, reader-worded
(runner-up wording: "If you need X, the JS binding doesn't ship it yet — see
the footer"); headings never say "verified"/"actually"/"we found"/"we
verified"; status badges stay in frontmatter/hub untouched.

8b (rich text) becomes a boundary-teaching page per STYLE §4: why strict
cross-replica ordering can't fall out of merge, what a module must provide,
what to use today — same facts, no apologizing.

### Homepage / hub (build.mjs)

- Sidebar tagline: "Learn by building — every recipe verified against the code
  it teaches." (or close to STYLE's suggestion).
- Hub gains a **Start here** learning path above the status table: grouped by
  section (Basics → Conditions → Convergence → Coordination → Composition →
  Ground truth), one line per recipe saying what concept it teaches. Each
  recipe gains an optional `teaches:` frontmatter line (additive; the required
  frontmatter set is unchanged) consumed by the hub builder. Status/maturity
  table stays below the path.
- Landing page card copy updated to the new posture (no "audit" voice).

### Testing (Phase B)

- `node cookbook/site/build.mjs` must stay green with the restructured pages;
  the mechanical checklist from STYLE.md is the reviewer's per-page rubric.
- Snippet content is unaffected (fences reference the same files); harnesses
  re-run green unchanged.
- Final gate: full harness suite + a Phase-B reviewer pass applying the
  checklist to all 16 pages + hub.

## Explicitly out of scope

- Multi-node Raft deployment UX (recipe 14 demos the host loop on the
  reference transport only).
- Any new hardware-attestation work (removed from the book).
- Dark mode, search, i18n.
- New library capabilities not listed above.

## Sequencing

One branch per phase, merged after review: `gap-fill` (Phase A), then
`cookbook-restyle` (Phase B). Both follow the established per-task
implementer/spec-review/quality-review loop; subagent-driven execution.