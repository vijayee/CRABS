# Lineage Deferred Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the deferred residuals: (1) post-restart dissolve tombstone delivery — persist the dissolved flag (v12) + a `__receive_dissolution__` op on the child + CLI commands to hand the tombstone between operators; (2) the engine-level silent no-op for handler-less RESOURCE-LESS custom ops; (3) attestation-count writer cap; (4) regenerate wasm artifacts.

**Architecture:** The dissolved state becomes DURABLE data: serialization v12 adds a `u8 parent_dissolved` tail to the parent-binding block (v11 position), consumed by `_verify_parent_endorsements` (which already fail-closes on the runtime flag). Delivery is an ordinary op on the child whose payload carries the parent's `lineage_sign_dissolution` tombstone — authenticity by the parent ECDSA signature that op already produces. The engine fix is surgical: handler-less + non-builtin + ZERO-resource ops return `CRABS_ERR_RESOURCE_NOT_FOUND`-family error instead of logging success (resource-bearing ops keep the LOCKED→MODIFIED wildcard design unchanged).

**Prerequisites (landed):** Plans 1-3 complete + merged to master + pushed (5d2671d).

**Style:** docs/STYLE_GUIDE.md; CRABS_ERR_* real names; no single-letter variables; no Co-Authored-By. Build/test: `cmake --build build -j && ctest --test-dir build/test --output-on-failure` (~1537 green, 1 env skip).

---

### Task 1: Persist the dissolve state (v12)

**Files:** `src/Serialization/serialization.h`/`.c`, Test: `test/test_serialization.cpp`

- [ ] **Step 1: Failing test** — round trip a bound state with `lineage_parent_dissolved = true`; assert it survives serialize/deserialize; a v11-layout blob (no flag) reads as false.

- [ ] **Step 2: Implement** — `CRABS_SERIAL_VERSION` 12; the parent-binding block becomes `u8 bound; if 1: string16 parent_id + 33B pubkey + string16 lineage_self_id + u8 parent_dissolved` (appended AT THE END of the block, so a v11 reader... readers are gated `version >= 11` as one block — v12 reader reads the flag only when `>= 12`; v11 blobs parse exactly as before). Writer emits the flag always when bound. Keep the byte-stability test green.

- [ ] **Step 3: Green; commit** — `feat: persist lineage dissolution state (v12)`

---

### Task 2: `__receive_dissolution__` op on the child

**Files:** `src/Lineage/lineage.h`/`.c`, Test: `test/test_lineage.cpp`

- [ ] **Step 1: Failing test** — child machine (bound), op `__receive_dissolution__` payload = tombstone wire produced by `lineage_sign_dissolution(parent, child_id, sig)` — read lineage.c:1477+ for the EXACT canonical/tombstone bytes and reuse the same writer so delivery bytes == signing bytes. Assert: valid tombstone → `lineage_parent_dissolved == true` + persists through a save/reload round trip; wrong signature / wrong child_id / unbound machine → refused.

- [ ] **Step 2: Implement** — `lineage_op_receive_dissolution(state, op)`: verify op NOT NULL + payload present; the machine must be `lineage_parent_bound` (else refuse); parse tombstone: child_id must equal `state->lineage_self_id`; verify ECDSA against `state->lineage_parent_public_key`; set `state->lineage_parent_dissolved = true`; `state_notify_change(state, CRABS_CHANGE_LINEAGE, ...)` ("dissolution received"). `lineage_install` registers it as the FIFTH op + "role:admin" policy (a child admin submits the delivery). Idempotency: re-delivery returns CRABS_ERR_ALREADY_PERFORMED-family (check the real name). Update lineage_install's idempotency test (counts stay 5).

- [ ] **Step 3: Green; commit** — `feat: dissolution tombstone delivery op`

---

### Task 3: CLI tombstone hand-off + end-to-end delivery proof

**Files:** `src/CLI/cli.h`/`cli.c`, Test: `test/test_cli.cpp` (+ `test/test_durability.cpp`)

- [ ] **Step 1: Commands** — parent side: `machine tombstone <child_id>` = the manifest entry must be DISSOLVED → `lineage_sign_dissolution` → hex-print the tombstone wire (transport material, like attest). Child side: `machine accept-tombstone <file>` — no wait, transport is text: accept the HEX via file (`accept-tombstone` reads a file of 128-hex — mirror `seal-key import`'s file-reading idiom) → build `__receive_dissolution__` op (payload = the tombstone BYTES — payload vs hex: the op pipeline payload for this op is the raw tombstone bytes; the CLI decodes hex → bytes → op) → `_op_sign_and_execute` path as child admin.
- [ ] **Step 2: E2E test** (test_durability.cpp): the Plan 3 end-to-end flow EXTENDED — dissolve parent-side → tombstone hex captured → reload the child file → apply tombstone (op pipeline) → save child → destroy → RELOAD again → `lineage_parent_dissolved` persisted TRUE → `@parent/` endorsements still fail after restart. This is the whole deferred item closed.
- [ ] **Step 3: usage/warning-table/README** — add both commands to `_print_machine_usage`, `cli_print_usage`, the mutation-warning table, and the README's machine table.
- [ ] **Step 4: Green; commit** — `feat: CLI tombstone hand-off between parent and child operators`

---

### Task 4: Engine — remove the resource-less silent no-op

**Files:** `src/StateMachine/state_machine.c`, Test: `test/test_state_machine.cpp`

- [ ] **Step 1: Failing tests** (a) a DECLARED custom op (policy registered) with NO handler and NO resources → `state_machine_execute` returns the not-found error and does NOT append a log entry; (b) the SAME op WITH a resource-bearing LOCKED item → STILL succeeds via the wildcard (regression guard: the legitimate pattern is preserved); (c) lineage ops installed → dissolve still works (regression guard from Task 3 wiring).

- [ ] **Step 2: Implement** — in the dispatch else-chain (state_machine.c ~1164): `custom_handler == NULL && !operation_is_builtin(op->type) && op->resource_count == 0 → return CRABS_ERR_RESOURCE_NOT_FOUND` (the nearest real error for "no implementation to run"). Comment: distinguishes declared-but-unimplemented ops from the resource-wildcard workflow ops, which keep CRABS_SUCCESS semantics. Check the auth pipeline doesn't pre-reject this (auth passes first by design — the engine error is what surfaces).

- [ ] **Step 3: Full suite green; commit** — `fix: resource-less custom ops without handlers fail loudly instead of logging a no-op`

---

### Task 5: Attestation writer cap + wasm regeneration

**Files:** `src/Serialization/serialization.c` (writer-side count guard at CRABS_MAX_OP_ATTESTATIONS), Test: `test/test_serialization.cpp` (append), then wasm artifacts.

- [ ] **Step 1: Failing test** — build an op with 9 attestations → `crabs_serialize_operation` refuses (returns NULL / 0 per its real contract). Implement the writer guard; reader already caps at 8.
- [ ] **Step 2: `./build_wasm.sh` with `OPENSSL_SRC=~/Workspace/src/github.com/vijayee/openssl`** — regenerate; commit the two `.wasm` + regenerated `crabs.js`/`crabs.dev.js` glue per the established pattern (`chore: regenerate wasm artifacts...`); rerun `node bindings/wasm/lineage_smoke.mjs` + the devtools JS tests against the new binaries.
- [ ] **Step 3: Green; commit** — writer guard first (`fix: operation writer enforces the attestation count cap`), artifacts second.

---

### Task 6: De-wonk gate

**Files:** all touched above.

- [ ] **Step 1: De-wonk** the fix span (five categories; loop to zero; suite green).
- [ ] **Step 2: Update** the Plan docs' follow-up sections — mark the now-closed residuals in docs/superpowers/plans/2026-10-07-lineage-surfaces.md (and the Plan 1 doc where relevant); the SHARED_ROOT-reload stance stays documented as-design (one shared registry is an in-process invariant; cross-process is a Plan-4+ concern, stated plainly). Commit `docs: close lineage follow-ups — tombstone delivery shipped`.

## Sequencing

1 → 2 → 3 are a strict chain (persist → op → CLI/e2e). Task 4 independent of 1-3 (run after, any order). Task 5 last-ish; Task 6 final.