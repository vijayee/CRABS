# JS↔C Binding Parity Fill (Round 2) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reach full JS↔C capability parity: state restore/merge, keyring lifecycle, admin demotion/suspension, ABE key transport, OT ordered-set merge, unblessed OT document/tree surfaces, temporary-attribute issuance, lineage extras, raft membership on node — then align the binding-to-binding divergences that are honest noise.

**Architecture:** One branch (`parity-fill`) off master, tasks P1-P10 in the order below (P1 first — it unblocks P5/P8's merge consumers; P10's alignment last since earlier tasks change the surfaces it aligns). Every task: failing binding test → C export/wrapper (wasm via `crabs_wasm_*` in `src/Util/wasm_helpers.c` + `bindings/wasm/bindings-core.js`; node via direct C in `bindings/node/src/crabs_node.cc`) → green → d.ts in the same commit → cookbook/api-map re-anchor as claims flip. Per-task spec + quality review with adversarial passes on every secret-carrying surface (P4, P1's sealed states).

**Tech Stack:** C11 (CMake/gtest), Emscripten regen, node-addon-api (cmake-js), plain-node assert scripts, cookbook pipeline.

**Spec:** `docs/superpowers/specs/2026-10-13-binding-parity-fill-design.md`

---

## Ground rules (same as round 1)

Worktree branch `parity-fill`; conventional commits, no Co-Authored-By; verify every file:line you cite by reading it; read 3 neighboring exports/wrappers before writing one; secrets (key bytes, seal keys, tokens) stage cleansed and destroys idempotent; full battery (`ctest --test-dir build`, both `npm test` chains, `node cookbook/tests/run-snippets.mjs`, `bash cookbook/tests/run-c.sh`, `node cookbook/tests/browser.js`, site build) green per task; wasm artifacts regenerated at the phase end (Task P11) — tasks may regen locally for their own tests (repo precedent), artifacts committed then.

## File structure

```
src/Util/wasm_helpers.c                 new exports (state restore/merge/sealed, keyring, roles, envelopes, OT doc/tree, issueTemporary, lineage extras, raft members)
bindings/wasm/bindings-core.js          consume + sugar (Node.* methods)
bindings/wasm/index.d.ts                surface (same commit as code)
bindings/node/src/crabs_node.cc         node counterparts, direct C
bindings/node/index.d.ts                surface (same commit as code)
src/Raft/raft_module.h/.c               P9 (node moduleHandle + changeMembership)
test/test_*.cpp                         gtest for genuinely-new C (P1 sealed round trips, P4 envelopes)
cookbook/recipes/8-reorderable-list.md  P5 → COMPLETE flip
cookbook/recipes/15-revocable-data.md   P2/P4 residual narrowing
cookbook/api-map.md                     ledger + rows as each lands
```

---

### Task P1: state restore + merge + sealed/signed serialization

**Files:**
- Modify: `src/Util/wasm_helpers.c` (new exports near `crabs_wasm_serialize_state` :1706)
- Modify: `bindings/wasm/bindings-core.js` + `index.d.ts`; `bindings/node/src/crabs_node.cc` + `index.d.ts`
- Test: `bindings/wasm/test/state-restore.js` (new) + node addition in `test/test.js`

- [x] **Step 1: C API verified.** `crabs_deserialize_state` (serialization.h:41), `crdt_merge_state(dst, src)` (crdt_merge.h:131), sealed/signed families (serialization.h:55-90 — READ the whole block; note `crabs_serialize_state_sealed` requires `state->abe_mk`, `_sealed_signed` returns NULL without node key/live MSK, and `crabs_deserialize_state_keys_reported` reports `authority_restored`/`msk_section_present`).
- [x] **Step 2: Failing JS test** (both bindings, mirror the wasm `serialize` shape at bindings-core's existing Node.serialize wrapper): machine builds state (counter + register + item), `wire1 = node.serialize()`, second machine `node2.deserialize(wire1)` (wasm: Node.create a second wrapper over the RESTORED state — READ how the binding wraps machine state; the restore likely REPLACES the wrapper's state or spawns a new wrapper — the C side returns a new `state_t*`; decide the binding shape: `Node.deserialize(bytes)` replaces the wrapper's machine → returns undefined; document the lifetime), asserts merged readback + op-log/seq preserved; then `node3.mergeState(wire2)` — divergent counters converge per `crdt_merge_state` (mirror `test_crdt` merge facts); sealed round trip: `node.serialize({sealKey: '64-hex'})` → deserialize with the SAME key restores (assert `msk_section_present`, per `_keys_reported`); signed variant + a TAMPERED blob refuses (verify error).
- [x] **Step 3: Implement** — wasm exports: `crabs_wasm_deserialize_state(am, data, len)`, `crabs_wasm_merge_state(am, data, len)`, `crabs_wasm_serialize_state_sealed/_signed/_sealed_signed`, `crabs_wasm_deserialize_state_keys/_signed` (+ reported out-params as a 4-byte result struct). Merge semantics: `crdt_merge_state(dst, src)` requires src built — build src via `crabs_deserialize_state` in the export (deserialize → merge → destroy temp state). Sealed/signed key inputs: 32/33-byte hex strings from JS; staging cleansed. Node: same, direct C. d.ts both.
  - (Decided shape: `deserialize` REPLACES the wrapper's machine and returns the keys-reported report `{authorityRestored, mskSectionPresent}` — always the keys-reported core, NULL seal key on the plain path; the signed compose (`crabs_deserialize_state_signed` never parses sealed bodies) is wrapper-level: ECDSA verify of the whole blob, then the `_keys_reported` parse of the 64-byte-trailer-stripped body. Wasm restores via one C helper (`crabs_wasm_deserialize_state`) that adopts shell-or-bare and rewires node key/hook/time source/raft module; node drives the same adoption in C++ and destroys the previous machine unless adopted.)
- [x] **Step 4:** green; ctest (add a gtest ONLY if you change .c beyond wrappers — `test/test_serialization.cpp` already covers the C serialize/deserialize family — verify); battery green.
- [x] **Step 5: Commit** `feat: state restore, merge and sealed/signed snapshots from JS`.

### Task P2: keyring lifecycle

**Files:** wrappers only; Test: both bindings.
- [x] **Step 1: Failing tests:** `node.suspendKey('alice', keyId)` where the C test (`test/test_key_lifecycle.cpp:96-140` READ it for the key id shape + who calls: user_t-based) — mirror: suspended user's ops refuse; `activateKey` restores; `rotateKey` bumps key version + old stamps refuse `key_stale` (mirror the C test's asserts).
  - (Landed reality: the C keyring API is user_t-scoped and gate-free — the
    binding surface resolves the user id (`attribute_machine_find_user`) and
    drives the primitives; seeding rides the C-native `__register_key__` wire
    op because the bindings expose no registerKey. A genuine `key_stale`
    replay is NOT pinnable here — a keyring-ed user refuses at verify
    (unauthorized, R8-C-2) BEFORE the staleness gate (state_machine.c:884) —
    so keyring.js pins the R8-C-2 fail-closed word and the staleness story
    moves to P3 (suspendUser on a keyring-less user); rotateKey carries the
    C material explicitly; `listKeys`/`getDefaultKey` are the readback.)
- [x] **Step 2:** implement wasm exports + node direct C (`user_key_suspend`/`activate_user_key`-named variants — grep the real function names at attribute_machine.h:219-221), d.ts both.
- [x] **Step 3:** green + battery. **Commit** `feat: key suspend/activate/rotate from JS`.

### Task P3: revokeRole / suspendUser / activateUser
Same TDD pattern; C: attribute_machine.h:147/149/168 (read the real signatures — `revoke_role(am, target_user, role, value?, signer?)`); policies re-eval fail-closed after revoke (pinned); battery. **Commit** `feat: revokeRole, suspendUser and activateUser from JS`.

### Task P4: ABE key transport envelopes (SECURITY-CRITICAL — adversarial review mandatory)

**Files:** `src/Util/wasm_helpers.c`, `bindings/wasm/bindings-core.js`, d.ts ×2; gtest if C changes.
- [ ] **Step 1: Read the C transport block:** crypto.h:140-160 (`user_key_serialize/deserialize`, `master_key_serialize/deserialize`) + crypto.h:271-304 (`crypto_key_envelope_*` — READ all of it: what the envelope wraps, key derivation, how refresh_key materializes responses, state_machine.c:2797's refresh path).
- [ ] **Step 2: Failing tests:** wasm + node: `abeKey.toWire() -> Buffer`; `node.abeKeyFromWire(bytes) -> AbeKey` (destroy idempotent); `node.mintKeyEnvelope(attrs..., recipientContext)` / `node.decryptKeyEnvelope(envelope)` — mirror the C envelope flow the tests use (grep envelope in test/). Round trip == same capability; tampered envelope refuses cleansed.
- [ ] **Step 3:** implement; master-key serialize/deserialize EXPOSED ONLY as `Node.masterKeyToWire()/fromWire()` — document the trust step (the MSK at rest is the machine's crown jewel; the d.ts prose says exactly that), OR omit master key transport from the surface if the envelope flow covers recovery — DECIDE by the C tests' actual usage and the spec's intent (machine-owned MSK in v1: prefer envelope-only; if the C tests exercise master serialize for backup, surface it as PRESENT).
- [ ] **Step 4:** green + battery + adversarial review (staging cleanse, GCM/tag checks, no MSK pointer escape). **Commit** `feat: ABE key envelopes and key transport from JS`.

### Task P5: OT ordered-set merge layer (recipe 8 → COMPLETE)

**Files:** merge rides P1's `mergeState` (verify: does `crdt_merge_state` dispatch OT items via `crabs_ot_ordered_set_merge`? read crdt_merge.c's group/OT item branch — RE-VERIFY the merge case for DATA_TYPE_OT_ORDERED_SET exists: round-1's review said "merge layer C-only, no binding map entry" but the C fn exists at ot_ordered_set.h:114-117; crdt_merge_state's item dispatch must call it — read and confirm; if it does NOT dispatch OT items, add it + gtest).
- [ ] **Step 1: Failing test:** two machines build divergent ordered sets WITH DIFFERENT OP LOGS (same element ids), mergeState, converged order == the C test's merge result (`test/test_ot_ordered_set.cpp:347-420` scenarios mirrored: copies src-only elements, larger placement_id per element, deletions win via merged position maps, conflicting payload → merge NULL = dst untouched — the executor's merge returns the error; pin BOTH the refusal case (dst unchanged) and the converge case).
- [ ] **Step 2:** implement whatever is missing (C dispatch or export only); recipe 8: PARTIAL → COMPLETE (the merge layer now demos from JS via state-merge), the footer + status flip with re-anchored cites.
- [ ] **Step 3:** battery + **Commit** `feat: ordered-set merge reachable from JS (state-merge dispatch)` + `docs(cookbook): recipe 8 COMPLETE`.

### Task P6: OT document + tree — PRESENT, UNBLESSED

**Files:** wasm_helpers.c exports (`crabs_wasm_add_ot_document/tree`, `crabs_wasm_ot_document_apply/read`, `crabs_wasm_ot_tree_apply/read` — shape mirrors round-1's ordered-set exports), bindings-core + node + d.ts ×2.
- [ ] **Step 1: Read the C surfaces:** ot_document.h:79-119 (RGA: insert_text/delete_range/apply_style/merge_spans; read what item creation needs — DATA_TYPE_OT_DOCUMENT + value_repr), ot_tree.h:71-115 (insert_node/delete_node/reparent/reorder).
- [ ] **Step 2: Failing tests (both bindings):** document: create + insert_text at offset → read text back; two insertions at same offset → deterministic (pin the actual transform); tree: insert 3 nodes + reparent → read hierarchy. Everything asserts PRESENT-tier facts (round trip, determinism) — NOT performance/convergence-parity claims. d.ts docblocks carry the UNBLESSED caveat in BOTH bindings: "implemented, unbenchmarked — do not build rich text on this until a benchmark exists".
- [ ] **Step 3:** implement; register the OT_DOCUMENT/OT_TREE words in both define paths (node's parser accepts the words already; wasm's adders get new entries — mirror addOrderedSet); battery.
- [ ] **Step 4:** api-map rows (PRESENT); recipe 8's variations updated (the document/tree "same story" line becomes "bound, unblessed — see P6 row"); **Commit** `feat: OT document and tree surfaces from JS (unblessed, unbenchmarked)`.

### Task P7: issueTemporary
TDD: `node.issueTemporary('clearance', 'moderator', { audienceRole: 'member', ttlMs: 60000 })` mirroring `attribute_machine_issue_temporary` (attribute_machine.h:200 — read the real signature: attribute, value, audience, ttl) — expiry fail-closed in policy readback (crypto.c:1128-1177 — the existing C fact, pinned here from JS); wasm + node; battery. **Commit** `feat: temporary attribute issuance from JS`.

### Task P8: lineage extras
- Blueprint: `Blueprint.addItem(name, type, {domain|...})` domain opt + `Blueprint.addOpType(dedupSpecOpts)` (blueprint_add_item_with_domain :147, blueprint_add_op_type_def :157 — carried specs on spawned children, pinned via a spawned machine's registered dedup).
- Parent-key rotation: `node.lineageRotate(parentKeyId...)` driving `lineage_key_rotate` (:285) + child accept (:318) — mirror test usage (grep test_lineage.cpp for key_rotate).
- `node.attestationFromWire(bytes)` (attestation_deserialize :666) → fields object (parsed, NOT verified).
- TDD per piece; battery; **Commit** `feat: blueprint domains/carried specs, lineage key rotation and attestation wire parsing from JS`.

### Task P9: raft membership on node
- node gets the module handle surface: `changeMembership(joint)` + `jointMembers()/committedMembers()` (raft_module.h:222,269-271; wasm's raw exports exist — read `crabs_wasm_raft_change_membership` for the arg shape). Failing test first (mirror wasm's change-membership test if one exists — grep); battery; **Commit** `feat: raft membership change on the node binding`.

### Task P10: binding-to-binding alignment
- node gains: `getSetSize/getSetElements/getSetTags` (wasm_helpers.c:1421-1428 region — re-verify current lines), `setRegisterBytes/getRegisterBytes`, `evaluateTriggers`, `Operation.deserialize`, BigInt-tolerant register ints (d.ts note "Number or BigInt").
- wasm gains: `selfAssert`, `verifyIdentity`, `getHLC`.
- NOT aligned (documented): node's borrow-lifetime (no Node.destroy), wasm's Node.off, wasm-only handler surface (registerHandlerJs/HandlerState — node's design statement, noted in d.ts as intentional).
- TDD mirrors; battery; **Commit** `feat: binding parity align — pagination, byte registers, evaluateTriggers, op deserialize, selfAssert/getHLC on wasm`.

### Task P11: artifact regen + cookbook re-bless + verification
- [ ] wasm artifacts regenerated + committed (`chore: regenerate wasm artifacts (parity fill)`).
- [ ] api-map final sweep: every PRESENT/DESIGNED row re-checked against the new reality (the §17 ledger + body rows for keyring/roles/ABE-transport/OT-doc-tree/issueTemporary/lineage-extras/raft-membership/state-restore); recipe residual prose re-anchored (15's C-only-keyring note narrows or goes; 8's COMPLETE).
- [ ] Full battery; **Phase final review** (spec + adversarial quality on P4/P1; per-task reviews already ran) → merge `parity-fill` to master; push on user go-ahead.
- [ ] De-wonk audit over the branch's changed code (the skill) before the final review.