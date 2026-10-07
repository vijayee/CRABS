# Lineage Surfaces (CLI + Wasm + Devtools) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the landed lineage core to operators and tooling: a `machine` CLI command group (blueprint authoring, spawn via the op pipeline, children/attest/dissolve/withdraw), wasm exports for lineage (spawn/query/attest/blueprint) registered in the export lists, and a Devtools Lineage section (C snapshot + JS keyed view + layer colors).

**Architecture:** Three independent surface layers over the landed `src/Lineage/` core (blueprint wire format with hash verification, `lineage_spawn_machine`, `lineage_query_children/query_resident_child`, `crabs_issue_attestation`, the four lineage ops + `lineage_install`). CLI builds blueprints as node-resident context and drives lifecycle through `state_machine_execute` (op pipeline — authorization applies); wasm exposes borrowed-pointer patterns like the existing handler registry (`crabs_wasm_handler_get_am`); devtools adds ONE snapshot section writer + one keyed JS view entry + two layer-color keys. No core changes except where a surface exposes an missing accessor (Task 4's child manifest id accessor).

**Tech Stack:** C11, emscripten (`EMSCRIPTEN_KEEPALIVE` + `build_wasm.sh` export JSON lists), vanilla-JS custom element (`<crabs-devtools>` shadow DOM), N-API (node bindings compile lineage.c via GLOB_RECURSE automatically).

**Spec:** docs/superpowers/specs/2026-10-06-machine-minting-design.md (§Exposure surfaces)
**Prerequisites (landed):** Plan 1 + Plan 2 (see docs/superpowers/plans/2026-10-06-lineage-core.md for the exact landed API list — the lineage module section of its File Structure).

**Style:** docs/STYLE_GUIDE.md; CRABS_ERR_* real names; no single-letter variable names; no Co-Authored-By. Build/test: `cmake --build build -j && ctest --test-dir build/test --output-on-failure` (~1525 green, 1 env skip). Wasm: `./build_wasm.sh` then recompile the example JS as needed.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/CLI/cli.h` / `cli.c` (Modify) | `machine` command group: blueprint context on cli_node_t, build/save/validate/spawn/children/dissolve/withdraw/attest; usage + mutation-warning table |
| `src/Lineage/lineage.h` / `.c` (Modify) | ONLY: `child_manifest_entry_t* lineage_find_manifest_entry(const state_t*, const char* child_id);` accessor needed by CLI + wasm (borrowed) |
| `bindings/wasm/…` via `src/Util/wasm_helpers.c` (Modify) | `crabs_wasm_lineage_*` exports + `build_wasm.sh` export-list entries + JS wrapper additions in `bindings/wasm/index.js`/`bindings-core.js` (follow the file's real structure) |
| `src/Devtools/devtools.c` (Modify) | `_write_lineage_json` section in `devtools_snapshot_json` |
| `bindings/devtools/devtools-api.js` (Modify) | `children: keyBy(snapshot.children, 'child_id')` in `deriveView` |
| `bindings/devtools/crabs-devtools.js` (Modify) | Lineage section in `renderStateTree`; `LAYER_COLORS` entries for `spawn` + `lineage` (currently gray via fallback) |
| `test/test_cli.cpp` (Append) | CLI machine-group tests |
| `test/test_devtools.cpp` (Append) | Snapshot section test (children render) |
| `test/test_lineage.cpp` (Append) | accessor test |
| `bindings/devtools/demo wiring` (examples/devtools_demo/index.html) | cache-bust version bump only |

Light-mode UI per project rule (no dark styling; match BADGE_COLORS/LAYER_COLORS light-theme palette).

---

### Task 1: Manifest accessor

**Files:** `src/Lineage/lineage.h`/`.c`, Test: `test/test_lineage.cpp`

- [ ] **Step 1: Failing test**

```cpp
TEST(TestLineage, FindManifestEntryResolvesById) {
  attribute_machine_t* parent = make_parent_machine();   // existing helper
  machine_blueprint_t* blueprint = make_valid_blueprint();
  memcpy(blueprint->child_id, "child-x", sizeof("child-x") - 1);
  attribute_machine_t* child = NULL;
  ASSERT_EQ(lineage_spawn_machine(parent_machine_state(parent), blueprint, &child),
            CRABS_SUCCESS);
  // hit
  const child_manifest_entry_t* entry =
      lineage_find_manifest_entry(parent_machine_state(parent), "child-x");
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->mode, blueprint->trust_mode);
  // miss
  EXPECT_EQ(lineage_find_manifest_entry(parent_machine_state(parent), "nope"),
            nullptr);
  // null-safe
  EXPECT_EQ(lineage_find_manifest_entry(nullptr, "child-x"), nullptr);
  attribute_machine_destroy(child);
  machine_blueprint_destroy(blueprint);
  <free parent per the existing helper's pattern>;
}
```
(Adapt to the real helper names/parent plumbing in test_lineage.cpp; keep the
three assertions: hit asserts content, miss, NULL-safety.)

- [ ] **Step 2: Implement** — lineage.h:
```c
// Borrowed pointer to the manifest entry for child_id, or NULL. O(n) over the
// (small, capped) manifest. Returns NULL on NULL inputs.
child_manifest_entry_t* lineage_find_manifest_entry(const state_t* state,
                                                      const char* child_id);
```
Implementation: linear scan over `state->children` matching `child_id`
(strcmp, entry NOT dissolved-withdrawn-only semantics — return whatever is in
the manifest, statuses included; readers interpret status).

- [ ] **Step 3: Green + commit** — `feat: lineage manifest entry accessor`

---

### Task 2: CLI `machine` blueprint authoring + save/validate

**Files:** `src/CLI/cli.h`/`cli.c`, Test: `test/test_cli.cpp`

**Design (v1 UX, no placeholders):** `cli_node_t` gains a machine-blueprint
draft: `machine_blueprint_t* blueprint_draft;` (NULL until `machine blueprint
new`). Subcommands:

- `machine blueprint new <child_id> <shared|delegated|sovereign> <bootstrap_admin> <attestation_ttl_ms>` — destroy any existing draft; create fresh; stamps the base fields. Mode words map to the enum (exactly this table in code).
- `machine blueprint item <name> <type> <crdt_type>` — appends to draft.
- `machine blueprint policy <op_type> <expression>` — appends to draft.
- `machine blueprint dedup <op_type> <dedup_type> [tracker_path|flag_path|condition] [rejection_message]` — appends an op_type_def with the DEDUP_* enum mapping (PER_USER→tracker_path, GLOBAL→flag_path, CUSTOM→condition; NONE → no extra arg).
- `machine blueprint save <file.cbp>` — validate → `blueprint_serialize` → write bytes to file (binary, fwrite).
- `machine blueprint validate <file.cbp>` — read file → `blueprint_deserialize` → `lineage_blueprint_validate` → print `Valid: <child_id> (mode <n>, <item_count> items, <policy_count> policies)` or the failure.
- `machine blueprint drop` — destroy draft (no output).

Error contract: arg parse → CLI_ERR_ARGS; blueprint errors map via
`cli_error_string(cli_...)` — NOTE cli_error_string takes crabs_error_e;
blueprint API returns crabs_error_e directly.

CLI output conventions: follow cli_cmd_user_list formatting.

- [ ] **Step 1: Failing tests** (test/test_cli.cpp):
  - `MachineBlueprintBuildCycle`: dispatch-level — `machine blueprint new child-red delegated child-admin 3600000` → items/policies via dispatch args (build `char** argv` arrays — follow how existing dispatch tests in test_cli.cpp invoke cli_dispatch) → `blueprint save` to /tmp/crabs-bp.cbp → fresh `machine blueprint validate` on a NEW node reads it back (ids round trip).
  - `MachineBlueprintSaveRefusesInvalidState`: policy with `@parent/` inside parens (malformed per landed validator) → save fails, draft intact.
- [ ] **Step 2: See fail. Implement. See pass.** — follow the dispatch-table
  idiom: add `"machine"` to the known-command gate's accept chain, insert the
  group AFTER the `state` block (cli.c, before `user`), write
  `_print_machine_usage`, register in `cli_print_usage`.
- [ ] **Step 3: Full suite green; commit** — `feat: CLI machine blueprint authoring`

---

### Task 3: CLI `machine` lifecycle commands

**Files:** `src/CLI/cli.h`/`cli.c`, Test: `test/test_cli.cpp`

- [ ] **Step 1: Commands** (each an actual op through the pipeline EXCEPT children query):
  - `machine spawn <file.cbp>` — read blueprint file → build `operation_create("__spawn_machine__")` → payload = serialized blueprint bytes → sign via the node's admin keyring path — follow `cli_cmd_op_submit`'s (cli.c ~1011) signing/payload idiom EXACTLY (hex payload path or direct bytes; reuse whatever it does) → `state_machine_execute` on the machine. Print child manifest count after success.
  - `machine children` — `lineage_query_children` + `lineage_query_resident_child` per entry; print `child_id  mode  status  resident  ttl_ms` lines (human strings for mode/status via small static helpers — add `_lineage_mode_name`/`_lineage_status_name` to lineage.{h,c} as public `lineage_mode_name`/`lineage_status_name` so wasm/devtools reuse them instead of triplicating).
  - `machine dissolve <child_id>` / `machine withdraw <child_id>` / `machine revoke-attestation <child_id>` — op pipeline like spawn (payload = child_id bytes; handlers in lineage accept the payload format — VERIFY the payload format lineage_op_dissolve consumes (Task 8 chose a format; read lineage.c `lineage_op_dissolve`'s payload parsing and construct matching bytes)).
  - `machine attest <child_id> <user_id> <attrs>` — `crabs_issue_attestation(now_ms from state_get_time_ms)` → hex-print the attestation wire for transport.
- [ ] **Step 2: Failing tests**:
  - `MachineSpawnThroughCliLifecycle`: blueprint build → spawn → `machine children` asserts the printed entry exists (capture stdout? follow the existing cli test capturing convention — check how test_cli.cpp asserts print output; if it only checks return codes, assert via `lineage_query_children` after the dispatch);
    dissolve → status flips; attest returns CLI_OK and the wire re-verifies via `attestation_deserialize` + `attestation_verify` with the node pub.
  - `MachineSovereignDissolveFailsThroughCli`: delegated spawn then dissolve OK; sovereign spawn → dissolve → nonzero result.
- [ ] **Step 3: Mutation-warning table**: add the three mutating lineage commands
  to `_warn_first_unauthenticated_mutation`'s table (cli.c ~1278-1306).
- [ ] **Step 4: Full suite green; commit** — `feat: CLI machine lifecycle — spawn, children, attest, dissolve, withdraw, revoke-attestation`

---

### Task 4: Wasm exports

**Files:** `src/Util/wasm_helpers.c`, `build_wasm.sh`, JS wrapper (`bindings/wasm/index.js` / `bindings-core.js` — follow the file's actual export-binding structure), Test: `test/test_devtools.cpp` NOT applicable — wasm has no C test; VERIFY via `./build_wasm.sh` + node smoke (see step 3).

- [ ] **Step 1: Exports** (follow crabs_wasm_handler_* idiom for pointer/child handling):
  - `crabs_wasm_lineage_blueprint_new(am, child_id, mode_int, bootstrap_admin, ttl_u64) → machine_blueprint_t*` (+ destroy), `_blueprint_add_item(name, type_int, crdt_int)`, `_blueprint_add_policy(op, expr)`, `_blueprint_serialize(bp) → serialized_buffer_t*`, `_blueprint_deserialize(bytes,len) → bp*`.
  - `crabs_wasm_lineage_spawn(am, bp) → attribute_machine_t*` — the spawned child pointer must reach JS: wasm helpers keep a small runtime array mirroring resident_children (borrowed; per-process); return an index/handle like the handler/am pattern (read how `crabs_wasm_handler_get_am` solves exactly this and mirror it), plus `_lineage_resident_child(am, child_id) → am*` for re-lookup.
  - `crabs_wasm_lineage_children(am) → serialized_buffer_t*` (borrowed entries copied into a flat buffer — serialize via the existing v11 manifest layout writer? Simplest honest: serialize the manifest the same way the state blob's section does — reuse by writing a tiny local flat format: count + entries' fields, documented in the helper).
  - `crabs_wasm_lineage_attest(am, child_id, user_id, attrs) → serialized_buffer_t*` (attestation wire) + `_attestation_verify(pub, child_id, bytes, len, now_u64) → bool`.
- [ ] **Step 2: `build_wasm.sh`** — add every new export to BOTH variants' export arrays (prod + dev; lineage is core, so prod gets it — verify against the script's current split).
- [ ] **Step 3: Verify**: `./build_wasm.sh` succeeds; smoke-test in node with the emscripten module (bindings/wasm has a test/smoke path — check README bindings docs; if a JS-test harness exists in bindings/wasm/, add a smoke test there; otherwise demonstrate via a manual `node -e` script committed as `bindings/wasm/lineage_smoke.mjs` and print its output in the report).
- [ ] **Step 4: Commit** — `feat: wasm lineage exports — blueprint, spawn, children, attest` (the .wasm artifacts are tracked: per repo convention the two packaging files bindings/wasm/crabs.wasm + crabs.dev.wasm ARE staged in this commit — they are the shipped artifacts, and `git status` currently shows them dirty from Plan 2's devtools enum work; confirm with `git log --oneline -- bindings/wasm/*.wasm | head -3` that committing them here is the established pattern, then stage ONLY those two binaries plus the source/JS files).

---

### Task 5: Devtools C snapshot section

**Files:** `src/Devtools/devtools.c`, Test: `test/test_devtools.cpp`

- [ ] **Step 1: Failing test** — snapshot JSON contains a `children` array when the state has manifest entries:
```cpp
TEST(TestDevtools, SnapshotCarriesLineageSection) {
  // build attr machine + spawn one child (lineage_spawn_machine)
  // json = devtools_snapshot_json(machine state)
  // assert json contains "\"children\":" and the child_id string
  // assert lineage-neutral machine (no children) renders "children":[]
}
```
(Adapt to real devtools test helper names in test_devtools.cpp — it builds
states directly; follow its fixture idiom.)
- [ ] **Step 2: Implement** — `_write_lineage_json(json_writer_t*, const state_t* state)` after `_write_schedules_json`: per entry `{child_id, mode (name via lineage_mode_name), status (lineage_status_name), spawned_at, attestation_ttl_ms}` + top-level count. Wire into `devtools_snapshot_json` after schedules. Lineage data is CORE (not devtools-gated): lineage.h include is fine already since devtools.c compiles CRABS_ENABLE_DEVTOOLS-guarded.
- [ ] **Step 3: Green; commit** — `feat: devtools snapshot lineage section`

---

### Task 6: Devtools JS — keyed view + light-theme lineage UI

**Files:** `bindings/devtools/devtools-api.js`, `bindings/devtools/crabs-devtools.js`, examples/devtools_demo/index.html (cache-bust)

- [ ] **Step 1 (devtools-api.js):** `deriveView` gains `children: keyBy(snapshot.children ?? [], 'child_id')`.
- [ ] **Step 2 (crabs-devtools.js):**
  - `LAYER_COLORS` gains `lineage` + `spawn` entries — LIGHT-THEME visible hues distinct from the existing four (pick from the file's palette family; e.g. a violet for `spawn`, a teal for `lineage` — match the existing hex formats), keeping `LAYER_FALLBACK` behavior for unknowns.
  - `renderStateTree` gains a **Lineage** section rendering the keyed `children`: rows with `child_id`, mode/status pills (reuse the badge span idiom at lines 177-186), `ttl_ms`, `resident` marker (`●`/`○` text, no emoji per project rules — use text `[resident]`/`[off-process]`).
  - Timeline layer toggle list picks up the two new layers automatically from LAYER_COLORS keys — verify by reading the `visibleLayers` init (line ~272) and confirm no hardcoded array elsewhere (grep `['op', 'schedule'` in the file — update if hardcoded).
- [ ] **Step 3: Verify in browser**: run `examples/devtools_demo/index.html` (serve it, e.g. `python3 -m http.server 8123 -d examples/devtools_demo` then open) — the panel must render the lineage section, badges in the light theme, layers toggling; bump the script cache-bust version (index.html ~43-48). Report what you SAW (you must actually load the page; if the demo cannot spawn a machine, wire a demo-only inline `machine blueprint`+spawn sequence in the demo page's script block — read the page first; it drives the wasm module). If browser automation isn't possible in this environment, verify the JS with a DOM smoke (jsdom? follow repo precedent — check how previous devtools work was verified) and state so in the report.
- [ ] **Step 4: Commit** — `feat: devtools lineage section — keyed view, layer colors, demo wiring`

---

### Task 7: End-to-end + de-wonk gate

**Files:** Test: `test/test_durability.cpp` (append), plus everything above.

- [ ] **Step 1: The full-surface integration test** (test_durability.cpp): CLI dispatch — blueprint cycle → `machine spawn` op → `machine children` → `machine attest` → restart (save/load-sealed both machines) → `machine children` post-restart → dissolve → de-wonk.
- [ ] **Step 2: Full de-wonk** over the Plan 3 span (all five categories, all touched files, loop to zero).
- [ ] **Step 3: Commit** — `test: lineage surfaces end-to-end; de-wonk pass`
- [ ] **Step 4: README** — append the CLI command table under the existing Trust Boundaries section's commands (or wherever the intro documents usage — README.md): the `machine` group commands with one-line descriptions + the wasm export names. Commit as `docs: document machine minting CLI + wasm surface`.

## Sequencing

1 → 2 → 3 (CLI chain: accessor → authoring → lifecycle); 4 (wasm) independent of 2-3 but after 1; 5 → 6 (devtools chain);
7 last (integration + de-wonk + docs). Tasks 4 and 5 can run in sequence with the CLI tail.

## Known Constraints Carried Forward

- The wasm child-pointer handle pattern MUST mirror `crabs_wasm_handler_get_am` — JS never owns machine pointers.
- Devtools is entirely `#ifdef CRABS_ENABLE_DEVTOOLS`; the .dev wasm variant is the only one that ships devtools strings — exports live in BOTH variants though lineage is core (build_wasm.sh split: confirm before editing).
- Light theme only (project standing rule); text glyphs over emoji.
- Node bindings need NO plan work — lineage.c compiles in via GLOB_RECURSE and the change-kind stringifiers were updated in Plan 2 (verify `CRABS_CHANGE_LINEAGE` arm exists in `_change_kind_name_napi` as a Task 7 check).
- .wasm packaging binaries ARE tracked artifacts — the wasm task's commit includes exactly the two .wasm files when regenerated.