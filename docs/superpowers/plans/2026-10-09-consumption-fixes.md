# Consumption-Findings Remediation Plan (docs/CONSUMPTION_FINDINGS_2026-10-09.md)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Remediate all six validated consumer findings: §2 is a correctness bug (OR-set tag collision silently drops unrelated elements), §1/§5/§6 are ergonomics/documentation, §3/§4 are missing capability (handler read APIs).

**Baseline:** master (d22f204), ctest 1694/1694, node 80, wasm npm chain, parity smoke. Worktree-based.

---

### Task 1: §2 — OR-set `(element, tag)` semantics

**Files:** `src/CRDT/crdt_merge.c:263` (`or_set_add`), tests (`test/test_crdt*.cpp`), `docs/CONSUMPTION_FINDINGS_2026-10-09.md` (status pointer later).
- [x] TDD (RED-first): same tag, different element → BOTH retained (entry count grows; setContains true for both; getSetTags-style read reflects both — after Task 3's read APIs land, this test asserts them); same (element, tag) re-add → idempotent (no growth — H-J invariant preserved); tombstone interplay: tag tombstoned via element A's remove → B add with same tag → ALLOWED? Semantics: tombstoned tag means that (element,tag) pair was removed — B's add with a tombstoned tag: STANDARD OR-set says the tag is dead (observed-remove: tag tombstone kills any element carried by that tag) → B's add rejected/silently-ignored — DECIDE: keep tombstone-blocked (observed-remove correctness) but fail LOUD: return `CRABS_ERR_DUPLICATE_OPERATION`? No — merges call or_set_add liberally; error-throwing breaks merge. Keep tombstone behavior as-is (CRABS_SUCCESS no-op) but DOCUMENT in the set README section. Silent-drop removal applies ONLY to the live-set collision case. *(As landed: tombstones are pair-scoped, so a DIFFERENT element under a tombstoned tag adds normally; same-pair re-add of a tombstoned pair is the documented CRABS_SUCCESS no-op. Tests in test_crdt.cpp; the wasm handler-reads test asserts two tags on one element.)*
- [x] Implement: dedupe check becomes `strcmp(tag)==0 && strcmp(element)==0`; the LIVE-set tag-only check changes to pair-check. Sweep every or_set_add caller for semantic assumptions (crdt_merge.c:331, crdt_compaction.c:58/75, serialization.c:853, wasm 802): none should depend on tag-global uniqueness (verify by reading each). *(As landed: tombstone dedupe + contains + compaction visibility count/extract also went pair-scoped; all callers just pass (element, tag) through.)*
- [x] Cap consideration: distinct (elem,tag) growth bounded by CRABS_MAX_* if a set cap exists (grep or_set caps); if none, add a cap consistent with sibling set caps (check one_shot cap constants). *(As landed: no OR-set or one-shot-set cap constants exist — siblings are also uncapped — so the set stays uncapped, consistent; the handler-read encoder rejects u16-overflow lists instead of mis-encoding.)*
- [x] Commit: `fix: OR-set add dedupes by (element, tag) pair — no silent drop on shared tags`. *(ba17e66)*

### Task 2: §1 + §2 — wrapper guards + docs

**Files:** `bindings/wasm/bindings-core.js`, `bindings/node/src/crabs_node.cc` (setRegister number-path), `bindings/node/index.d.ts`, `bindings/wasm/index.d.ts`, `bindings/wasm/README.md`, wasm tests, node test.js.
- [x] Guard (both wrappers + node binding): `setRegister(name, value, …)` — reject non-integer BEFORE the C call: `Number.isInteger(value)` (also NaN/Infinity reject); BigInt callers pass through. Descriptive error: "setRegister: registers are integer-only; encode fractional values in register units (e.g. per-mille)". *(As landed: wasm also rejects |n| > MAX_SAFE_INTEGER with a BigInt hint; node binding accepts numbers only (safe-integer range), per index.d.ts.)*
- [x] `index.d.ts` JSDoc on the setRegister family: integer-only contract + BigInt acceptance.
- [x] wasm README: registers section (integer-only; per-mille pattern) + OR-set section (add semantics: same tag + same element idempotent; two elements sharing a tag are BOTH retained; remove-by-element tombstones the element's tags; re-add under a tombstoned tag is a no-op). *(As landed: the no-op clause is scoped to the SAME pair; a different element under a tombstoned tag adds normally, and both clauses are stated.)*
- [x] Tests both wrappers: float rejected with descriptive message; integer passes; NaN/Infinity rejected. Commit: `feat: integer-only register guards and set/register contract docs (consumer findings 1-2)`. *(4e1c801; wasm test/registers.js also covers the handler-context guard path.)*

### Task 3: §3 + §4 — handler read APIs

**Files:** `src/Util/wasm_helpers.c`, `bindings/wasm/bindings-core.js`, `bindings/wasm/index.d.ts` (+node `crabs_node.cc` if handlers exist there — the consumer is wasm; scope wasm unless node has an equivalent handler surface).
- [x] C helpers (pattern-match the existing `_crabs_wasm_handler_*` / `_callSetContainsFromAm` shape): `getSetElements(name, offset, limit)` → array of element strings, bounded enumerator (default limit e.g. 256, error beyond cap — mirror the `maxVoteCheck` discipline; total count query `getSetSize(name)` for pagination); `getSetTags(name, element)` → tag array; `getRegisterBytes(name)` → byte array; `setRegisterBytes(name, bytes)` (mirroring the Node-side existing C helper). *(As landed: page cap is 256 both sides; enumeration is DISTINCT live elements sorted ascending for cross-replica stability; node binding has no registerHandlerJs surface so scope stayed wasm, with getRegisterBytes also mirrored onto wasm Node.)*
- [x] Expose on `HandlerState` (bindings-core 1174-1239 block) with the same throw discipline. *(As landed: also exposed on wasm Node — getSetSize/getSetElements/getSetTags/getRegisterBytes — same helpers, node am.)*
- [x] Tests (wasm test file or new): enumerate a set (page + cap), tags of an element (after Task 1: two tags per element), getRegisterBytes/setRegisterBytes round-trip reachable from handler context. *(As landed: bindings/wasm/test/handler-reads.js exercises the registerHandlerJs + execute path — the handler context, not just top-level node.)*
- [x] Commit: `feat: handler-state read APIs — set enumeration, tags, byte registers (findings 3-4)`. *(08f72f0)*

### Task 4: §5 — wire-version diagnostics

**Files:** `src/Util/wasm_helpers.c` (or constants exposure), `bindings/wasm/bindings-core.js` + `bindings/node/src/crabs_node.cc` + index.d.ts both.
- [x] Expose constants: `CRABS.wireVersions = { state: CRABS_SERIAL_VERSION, op: CRABS_OP_FORMAT_VERSION, signing: <the signing canonical version 4> }` (export the three C constants or hardcode+mirror with a ctest that asserts the JS mirror matches C — prefer exposure via an export to avoid drift). *(As landed: exposure via exports, no JS mirror — wasm `wireVersions()` (async, cached, frozen) reads the C constants through `_crabs_wasm_wire_versions`; node exposes a frozen `wireVersions` object built from the same macros; signing byte promoted to named `CRABS_SIGNING_FORMAT_VERSION`.)*
- [x] `Operation.getWireVersion()` → the op's parsed op_version (C accessor). *(Both bindings.)*
- [x] Tests: accessor + constants non-drift. Commit: `feat: wire-version diagnostics — constants exposure and operation version accessor (finding 5)`. *(4b4e515; wasm test/wire-versions.js + node test.js cover fresh + round-tripped ops.)*

### Task 5: §6 — wrapper-generation compatibility matrix

**Files:** `bindings/wasm/README.md`, `docs/CONSUMPTION_FINDINGS_2026-10-09.md` (status section).
- [x] One-line compat matrix in the wasm README: the shipped wrapper generation ↔ crabs.wasm build pairing + rule: ALWAYS ship bindings-core.js and crabs.wasm from the same regen commit (they already are); future work: generated-TS single-source wrapper (documented as such, no stub). *(As landed: "Wrapper/WASM compatibility" README section + runtime `wireVersions()` check hook.)*
- [x] Commit: `docs: wrapper generation compatibility matrix (finding 6)`. *(89a42a1)*

### Task 6: Final verification
- [x] Full suites (ctest/node/wasm/parity); regen wasm artifacts (C changed in Tasks 1/3/4): `chore: regenerate wasm artifacts`; de-wonk two rounds; update `CONSUMPTION_FINDINGS` doc with a short REMEDIATION status block mirroring the audit-doc style. Commit closure. *(As landed: ctest 1698/1698, node 105/105, wasm npm chain green, parity byte-identical. De-wonk follow-ups: f05738c (encoder u16-overflow hardening + naming), a24dac2 (status-block re-key + docs accuracy), 002c37d (wasm regen — required rebuilding the wasm openssl at linux-generic32; the generic64 BN path traps under emscripten).)*