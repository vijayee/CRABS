# Write Domains v1 Implementation Plan (SOVEREIGN + FREE-MERGE full, GROUP-ORDERED seam)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Spec:** `docs/superpowers/specs/2026-10-08-write-domains-design.md` (revised against current code). **v1 scope (approved):** SOVEREIGN + FREE-MERGE fully; GROUP-ORDERED = data model + DOMAIN_CHECK seam + read-only behavior until a module is registered — no reference module, no merge-prefix machinery beyond holding divergences.

**Baseline:** ctest 1615/1615 (1 skip); node 59 + smoke; wasm smokes green; fork 153/153. All work in a worktree.

**Wire/version moves (all in one release):** state v13→**14** (per-item domain fields), `CRABS_OP_FORMAT_VERSION` 5→**6** (per-resource sovereign prefix), signing format v3→**4** (prefixes are signed), blueprint format bump (domain fields are hash-stamped). Pre-version data fails closed per established posture.

---

### Task 1: Data model + item creation surface (no wire yet)

**Files:** `src/CRABS/crabs.h` (enum + error codes), `src/CRABS/data_model.{c,h}` (item fields + fork set + creation params), `test/test_data_model.cpp`.
- [ ] Enum `crabs_write_domain_e` (FREE_MERGE=0, SOVEREIGN=1, GROUP_ORDERED=2); error codes `CRABS_ERR_NOT_ITEM_WRITER/_SEQ_MISMATCH/_FORK_DETECTED/_ORDERING_PATH/_QUARANTINED` (next free codes; unique).
- [ ] `data_item_t` fields per spec: `write_domain`, `writer[64]`, `item_seq`, `item_digest[32]`, `ordering_module`, capped `fork_writers`/`fork_evidence_digests`/`fork_count` (`#define CRABS_MAX_FORK_WRITERS 16`).
- [ ] `state_add_item` gains an options struct (all-optional; NULL/zeroed → today's behavior: FREE_MERGE, empty writer) — check the existing creation API shape and EXTEND rather than fork; new items default FREE_MERGE; SOVEREIGN requires non-empty `writer` + registered active user + (v1) item type among counter/register/set (hash-chain digest over serialization must be defined for the type — restrict allowed types in v1 to DATA_TYPE_COUNTER and DATA_TYPE_REGISTER; document).
- [ ] Item digest init + `state_item_domain()` accessor. Destroy/free paths updated.
- [ ] Tests (RED-first): creation with domain+writer; SOVEREIGN without writer rejected; default FREE_MERGE unchanged; fork-set capped append helper rejects beyond cap. Commit: `feat: write-domain data model and item creation options (SOVEREIGN/FREE-MERGE)`.

### Task 2: Serialization v14 — per-item domain fields

**Files:** `src/Serialization/serialization.{h,c}`, `test/test_serialization.cpp`.
- [x] Bump `CRABS_SERIAL_VERSION` 14 (comment). Writer: per item, emit domain fields ONLY for non-default: `u8 write_domain`; SOVEREIGN → `string16 writer` + `u64 item_seq` + `bytes32 item_digest`; fork set (`u8 count` + per-entry string16 writer + bytes32 evidence); GROUP_ORDERED → `u8 module`. Default (FREE_MERGE, no writer) = single `0x00` byte per item (keeps blob sizes for existing items at +1 byte). (As landed: the fork block lives inside the SOVEREIGN arm with an ALWAYS-present count byte so the reader needs no presence signal; entries exist only when count > 0.)
- [x] Reader gated `version >= 14`: same optional layout; **enum whitelist** (`write_domain ≤ 2`); writer bounds; count cap `CRABS_MAX_FORK_WRITERS` + remaining-bytes bound; SOVEREIGN requires non-empty writer + `item_seq ≥ 1` consistency (`item_seq==0 ⇒ digest all-zero`); full-consumption check unchanged (len-32).
- [x] Pre-v14 loads: all items FREE_MERGE (assert in a test with a v13 fixture — reuse the existing version-surgery test pattern).
- [x] Tests: round-trip with a sovereign item + fork entry; corrupt domain enum → reject; corrupt fork count → reject. Commit: `feat: v14 state format — per-item write domains and fork evidence`.

### Task 3: Blueprint wiring (domains are declared at mint)

**Files:** `src/Lineage/lineage.{c,h}`, `test/test_lineage.cpp`.
- [x] `data_item_blueprint_t` gains `write_domain`/`writer`/`ordering_module`; blueprint wire version bumps; the blueprint hash-stamp naturally covers the new fields (verify the hash covers the serialized body — it does). (As landed: the struct is `blueprint_item_t`; the body previously had NO version byte, so this step INTRODUCES `CRABS_BLUEPRINT_FORMAT_VERSION` = 0x02 as a leading body byte, gated exactly — pre-v2 unversioned bodies fail closed. New `blueprint_add_item_with_domain` authoring helper; `blueprint_add_item` is now a FREE_MERGE shorthand.)
- [x] Deserialize: enum whitelists (`write_domain`) mirroring the A10-L2 pattern — before offset advance; SOVEREIGN blueprint item requires writer. `lineage_blueprint_validate` checks domain/writer legality (writer must be the spawned child's bootstrap admin or a declared user id — v1 rule: any registered id string; validate field-safety).
- [x] Spawn passes item options → child items carry domains. Tests: blueprint round-trip with a sovereign item; tampered domain byte (restamped hash) → rejected. Commit: `feat: blueprint-declared write domains (v1: sovereign/free; group reads-only pre-module)`.

### Task 4: Sovereign op prefix + signing v4 + op v6

**Files:** `src/StateMachine/state_machine.{c,h}`, `src/Serialization/serialization.{c,h}`, `test/test_serialization.cpp`.
- [ ] `operation_t` gains `crabs_sovereign_op_prefix_t sovereign_prefixes[CRABS_MAX_RES_COUNT];` (check the actual per-resource array capacity name/size) + `sovereign_prefix_count` (0 = not a sovereign op).
- [ ] Wire: op serializer v6 section — `u8 prefix_count` + per-entry u64+bytes32, AFTER resources, aligned to the v5 attestation section style; deserializer bounds + full consumption. Ops with a prefix whose items aren't SOVEREIGN at execute: prefix ignored-but-logged? NO — fail closed: mismatch → `CRABS_ERR_SEQ_MISMATCH` per DOMAIN_CHECK (T5).
- [ ] Signing: canonical form v4 (`_write_uint8(buf, 0x04)`), prefixes appended as signed field (after resources, before co-sig fields — check current field order and append at the END with the version byte isolating the change). Verification goes through the same builder — single function (as established in the v3 change).
- [ ] `CRABS_OP_FORMAT_VERSION` 6: writer gates the new section on `op->op_version >= 6`; reader accepts 1..6 and gated-reads; ops declaring <6 with prefix content → serialize refuses (existing refuse-vs-truncate discipline).
- [ ] Tests: prefix round-trip; signing binds prefixes (same-prefix-different-seq signatures differ, cross-verification fails); low-version op carrying prefixes refused at serialize. Commit: `feat: sovereign op sequence prefix — signing format v4, op format v6`.

### Task 5: DOMAIN_CHECK in the execution pipeline

**Files:** `src/StateMachine/state_machine.c`, `test/test_state_machine.cpp`.
- [ ] New step after the dedup gate, before the handler dispatch (~ locate the step order: auth → tx → HLC → replay → transitions → lock claims → dedup → KEY/scheme gates → handler): insert DOMAIN_CHECK before handler. Logic per spec's algorithm (quarantine check FIRST — cheap — then writer, then seq, then digest; GROUP_ORDERED: `ordering_module == 0` → `CRABS_ERR_ORDERING_PATH` since NO module can exist in v1).
- [ ] On handler success, post-op bookkeeping for sovereign items (increment `item_seq`, recompute `item_digest` over the item's serialized post-state) — place after the same success point where OTHER per-item bookkeeping runs (find where the lock/protocol bookkeeping commits; keep atomic-with-the-op; must NOT run on error paths).
- [ ] Wire the prefixes ↔ items consistency: prefix count must equal the count of sovereign resources (exact; mismatch → SEQ_MISMATCH).
- [ ] Tests (RED-first where behavior changes): non-writer rejected; wrong seq rejected; digest mismatch → FORK_DETECTED (and NOT applied); quarantined writer rejected before crypto; FREE_MERGE unchanged (existing suite green); GROUP_ORDERED item write via normal path → ORDERING_PATH in v1. Commit: `feat: DOMAIN_CHECK pipeline step + sovereign chain bookkeeping`.

### Task 6: Equivocation report + quarantine op

**Files:** `src/StateMachine/state_machine.c` (op type + handler), `test/test_state_machine.cpp` (+ trigger tests if touching protected list).
- [ ] `CRABS_OP_REPORT_EQUIVOCATION` `"__report_equivocation__"`: registered op type (no dedup def initially — dedup via the item fork-set idempotence itself); handler verifies evidence payload: two serialized ops (a,b), both sigs verify against... the WRITER's key resolved via the ATTRIBUTE MACHINE keyring or the item's writer binding — v1: resolve via attribute machine `attribute_machine_find_user` + active key logic (the same machinery crypto_verify_operation_auth uses; resolve the writer's current key) + seq equality + digest fields differ → append to a sovereign item's fork set (item named in payload must exist and be SOVEREIGN — if the op's writer_id != the fork... anyone may report); quarantined state only blocks WRITES by the fork writer (reports still allowed).
- [ ] Handler on failure: flag NOT set (plan invariant); on success: dedup-mutation appends evidence + change event; later writer ops → QUARANTINED (from T5).
- [ ] Add the op to `operation_is_protected`.
- [ ] Tests: genuine fork → flag set, subsequent writer ops rejected; false report → not set; forged evidence → handler fails; cap behavior. Commit: `feat: __report_equivocation__ op — evidence-verified fork quarantine`.

### Task 7: crdt_merge domain dispatch

**Files:** `src/CRDT/crdt_merge.c`, `test/test_crdt_merge.cpp` (find the right test file name).
- [ ] Per-item dispatch before type merge: FREE_MERGE → unchanged; SOVEREIGN → chains continue cleanly (item_b ahead, same writer) → accept item_b; chain fork (same seq, different digest) → do NOT apply, monotone-union the fork sets, surface a change event; GROUP_ORDERED (v1, no modules) → keep local item_a, emit a held-divergence change event (module-less prefix logic is future work — document in the function).
- [ ] Tests per branch. Commit: `feat: domain-aware crdt_merge dispatch (sovereign chain accept/fork; group holds)`.

### Task 8: Surfaces — CLI, bindings, devtools, docs

**Files:** `src/CLI/cli.c` (+tests), `bindings/node/src/crabs_node.cc` + test.js + index.d.ts, `bindings/wasm/bindings-core.js` + index.d.ts + test file, `src/Util/wasm_helpers.c`, README.md, spec doc.
- [ ] CLI: `item info <name>` shows domain/writer/seq/module; blueprint authoring accepts the fields (matching the blueprint-file format Task 3 landed) — check the existing `machine blueprint item` arm for how fields parse.
- [ ] node binding: `defineItem(..., opts)` domain/writer passthrough; `reportEquivocation(itemName, bytes)`; op builders gain `setSovereignPrefix(resourceIndex, seq, digestHex)`; snapshot/pending rows gain additive `domain`.
- [ ] wasm: `crabs_wasm_*` exports for the same + wrapper + d.ts; artifacts REGEN (wire v6 changed bytes).
- [ ] devtools: additive `domain` + `writer`/`seq` display IF the snapshot JSON flows from C (it does; render-only change in crabs-devtools.js — keep all strings via textContent, existing XSS discipline).
- [ ] README: the four trust caveats from the spec's README section, verbatim-adapted. Spec doc: append "as implemented" notes (v1 scope, module seam).
- [ ] Cross-binding smoke: extend one lineage smoke-style script — sovereign item minted, writer op accepted, non-writer rejected, fork reported; identical in crabs-node && crabs-wasm (per the spec's testing section; extend CROSS_PLATFORM_AUDIT.md only if the file exists and matches).
- Commits (each isolated): `feat: CLI write-domain surfaces`; `feat: node bindings write-domain + sovereign prefix surface`; `feat: wasm write-domain surfaces + regenerated artifacts`; `feat: devtools domain pill and forks section (snapshot fields)`; `docs: write-domains trust caveats and as-implemented notes`.

### Task 9: Final verification

- [ ] Full suites (ctest/node/wasm/node-smoke); the guarantee-regression test from the spec (A4 §13.6 race under FREE_MERGE vs strict under SOVEREIGN); de-wonk (two rounds); audit-style self-review of the whole feature diff; `docs: write-domains v1 complete` if any doc closure needed.