# Deferred-Items Remediation Plan (write-domains follow-ups)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fix the four deferred findings from the write-domains v1 final review: value-representation canonicalization (prerequisite), invariant_check mis-evaluation, lock snapshot/rollback deep restore (UAF class), data_item_destroy shallow free, and the merge-adopt digest recompute hardening. Plus the deferred p2p-demo sovereign item.

**Baseline:** ctest 1679/1679 (1 skip) in the write-domains worktree (branch worktree-write-domains, tip acb9ab6).

---

### Task A: Value-representation canonicalization (`data_item_t.value_repr`)

**Files:** `src/CRABS/data_model.{c,h}`, all producer/consumer sites, tests.

- [x] `data_item_t` gains runtime-only `data_value_repr_t value_repr;` NOT in the wire format: `RAW_INT64` (plain value; legacy pre-v15 loads, plain adders) vs `CRDT_STRUCT` (g_counter/pn/lww-backed). Helper accessors: `data_item_has_struct_value(item)`.
- [x] Producer sites set it: wasm adders (g_counter_create callers), crdt_merge_value, compaction, v15 deserializer (struct path) → STRUCT; legacy deserializer path (< v15) → RAW_INT64; explicit int64 setters (grep `item->value = ` in src/ — tests excluded) → RAW_INT64. Where an item is created and value assigned later, repr follows the assignment (documented invariant; grep-test asserts nothing in src/ assigns without repr).
- [x] `data_item_destroy`: STRUCT repr → dispatch through `crdt_value_destroy(item->crdt_type, item->value)` (the proven pattern); RAW_INT64 → free(value). Removes the shallow-free leak.
- [x] `invariant_check` (state_machine.c:~328): crdt-aware logical read — struct counter → SUM of the counter's entries (g_counter value semantics); struct lww register → its current value; RAW → int64. Only v1-allowed types matter (COUNTER/REGISTER) but make the function total over the reprs.
- [x] Lock snapshot/rollback (state_machine.c ~:1766-1863): snapshot = the deterministic LOGICAL content bytes (reuse `crabs_serialize_data_item_chain_preimage`); restore = rebuild the struct from those bytes via a shared reconstruction helper (factor the v15 deserializer's value-reconstruction into a public `data_item_restore_value_from_logical_bytes(item, bytes, len)` used by BOTH the state deserializer and lock rollback); RAW repr → existing 8-byte snapshot path. This kills the freed-pointer UAF for struct-backed locks.
- [x] Demote the NOTE added to data_item_destroy (acb9ab6) once fixed.
- [x] Tests: invariant on struct-backed counter (sum semantics); lock+extend+rollback on struct-backed counter (rollback restores content, digest chain consistent, no UAF — ASAN if available else discipline); legacy raw repr still works (invariant + lock + destroy); repr round-trips through save/load. Commit: `fix: canonicalize item value representations — invariants, lock rollback, destroy`.

### Task B: Merge adopt recomputes the chain head

**Files:** `src/CRDT/crdt_merge.c`, tests.
- [x] `_merge_sovereign_item`: when adopting ahead item_b, recompute `state_item_digest_compute` over the ADOPTED content and use the COMPUTED digest as the merged head (carried digest is advisory); if computed ≠ carried → that's a tampered/divergent snapshot: hold (keep dst), emit the existing merge divergence event, union evidence — fail closed rather than planting a mismatched head.
- [x] Also recompute the equal-seq comparison path's heads from content, not carried fields.
- [x] Canonical (type, crdt) pairing table (`data_item_canonical_crdt_for_type` next to CRABS_BUILTIN_TYPES) — fail-closed in `data_item_create_with_options`, checked explicitly in `crabs_wasm_define_item` and the node defineItem binding (the reviewed wasm define_item miscast hole, folded in).
- [x] Tests: tampered carried digest on an ahead snapshot → held + event, dst chain intact; honest ahead snapshot → adopted with computed digest == carried; equal-seq content-equal + corrupted carried → converges, no conviction; pairing rejection C tests. Commit: `fix: merge recomputes adopted sovereign chain heads from content`.

### Task C: p2p demo — sovereign item + domain pills

**Files:** `examples/video_platform_p2p/*` (client JS), `bindings/devtools/crabs-devtools.js` render additions if not already live.
- [x] Explore the demo's client structure; add ONE sovereign item (per-user counter signed only by its owner — `node.defineItem({... domain:'sovereign', writer})` on the local node) alongside the free-merge items; op flow via `setSovereignPrefix` + submit; non-writer attempt surfaces the error visibly.
- [x] Devtools pills: confirm the earlier render change surfaces in the demo (two tabs: both pills visible). (Fixed first: deriveView keys items by name, so the pill regex never matched item rows.)
- [x] Run the demo's own smoke/playwright suite if present (`package.json` test script — read it); keep it green. (Playwright 5/5 + server smoke; the demo needed un-breaking against R7-08/R7-04 and the fail-closed handler-less-op executor first.)
- [x] Commit: `feat: video platform demo gains a sovereign item — domain pills in both tabs`.

### Task D: Final verification
- [x] Full suites: ctest, node build+tests+smoke, wasm regen (only if wasm C changed — Task A/B are C-level: YES regen needed + `chore: regenerate wasm artifacts` commit), npm test, parity smoke, de-wonk two rounds over `acb9ab6..HEAD`. (As landed: ctest 1694/1694 (1 skip); node 80/80 + lineage_smoke OK; wasm `npm test` all pass; parity byte-identical across node and wasm; wasm regen folded into `010c095` so no separate regen commit was needed; de-wonk rounds 1+2 clean across the five categories.)
- [x] `docs: deferred remedies complete` if doc closure needed. (This file's Task D ticks + the README "group-ordered until a module is registered" wording — v1 ships no registration API, so the sentence now states that directly.)