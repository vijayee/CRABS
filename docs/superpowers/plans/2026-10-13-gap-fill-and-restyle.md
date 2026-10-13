# CRABS Cookbook Gap-Fill + Teaching-Restyle — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill every gap the cookbook documents (dedup JS, node schedules, OT ordered set JS, locks/tx-manager JS, attestation consumption, ABE decrypt + wasm getUser stub, documented divergences), correct the cookbook's stale ordering-module finding, remove the hardware-attestation recipe, then restyle all 16 recipe pages per `cookbook/STYLE.md`.

**Architecture:** Phase A works from the C truth outward — new C exports and struct-field wrappers in `src/Util/wasm_helpers.c` + `bindings/wasm/bindings-core.js`, direct C calls in `bindings/node/src/crabs_node.cc`, gtest + `bindings/*/test/` coverage, then wasm artifact regeneration. Phase B is markdown-only except a `build.mjs` hub change, gated on Phase A's review. Two branches from master: `gap-fill`, then `cookbook-restyle`.

**Tech Stack:** C11 (CMake + gtest), Emscripten (regen via `build_wasm.sh`), node-addon-api (cmake-js), plain `node` assert scripts, the cookbook site pipeline (`cookbook/site/build.mjs`).

**Spec:** `docs/superpowers/specs/2026-10-13-gap-fill-and-restyle-design.md`

---

## Ground rules for every task

- Work from a worktree branch `gap-fill` off master (created at execution time via the worktree skill). Conventional commits, no Co-Authored-By.
- Every new C export follows the existing `crabs_wasm_*` pattern in `src/Util/wasm_helpers.c` (read 3 neighbors before writing). Every binding change keeps both `bindings/wasm/index.d.ts` and `bindings/node/index.d.ts` updated IN THE SAME COMMIT as the code.
- Tests first where a harness exists: gtest (`ctest --test-dir build` for C changes), plain-node scripts (`node bindings/wasm/test/<file>.js`) for bindings. The cookbook snippet harnesses (`cd cookbook && node tests/run-snippets.mjs && bash cookbook/tests/run-c.sh`) must be green at the end of every task that touches surfaces the snippets use.
- `bash cookbook/tests/run-c.sh` builds the whole library; it doubles as the fast build check. Full gtest suite: `ctest --test-dir build`.
- No invented API: before citing any symbol in prose/footers, open the file at that line.

## File structure (Phase A)

```
src/Util/wasm_helpers.c            new C exports: user fields, dedup define-op, OT ops, claims, ABE keygen/decrypt
bindings/wasm/bindings-core.js     consume new exports; getUser real readback; temp-attr fix; JS API
bindings/wasm/index.d.ts           surface updates
bindings/wasm/src/ (glue)          regenerated via build_wasm.sh at Phase A end
bindings/node/src/crabs_node.cc    node counterparts: schedules, defineOperationType, OT, claims, attestations, ABE, createTrigger signer
bindings/node/index.d.ts           surface updates
src/Lineage/lineage.c              dissolve-after-revoke reconciliation (A8)
src/Crypto/crypto.c                single-clause parser guard decision (A8)
test/test_*.cpp                    gtest for new C behavior
bindings/wasm/test/*.js            binding test updates
cookbook/recipes/*.md              A9/A10 corrections and re-blessing
cookbook/api-map.md                regenerated
bindings/wasm/crabs.js|.wasm etc.  regenerated artifacts (committed)
```

Phase B adds: `cookbook/site/build.mjs` (hub learning path), recipe restructures, `cookbook/site/index.html` copy.

---

## PHASE A

### Task A1: wasm getUser real readback

**Files:**
- Modify: `src/Util/wasm_helpers.c` (new exports next to `crabs_wasm_user_attr_value` at :986)
- Modify: `bindings/wasm/bindings-core.js:672-706`
- Modify: `bindings/wasm/index.d.ts` (if UserInfo doc lines change)
- Test: `bindings/wasm/test/getuser-readback.js` (new)

- [ ] **Step 1: Failing JS test** — new `bindings/wasm/test/getuser-readback.js` (mirror `smoke.js` prelude: `Node.create('admin', {ordering:'hlc'})`, `KeyPair.generate`, `registerUser('alice', key.publicKeyHex(), 'adult')`), asserting after `grantRole('alice','role','member','admin')`:
```js
const user = node.getUser('alice');
assert.strictEqual(user.keyVersion, 1);          // stamped at grant (attribute_machine.c:597,617)
assert.strictEqual(user.status, 'active');
assert.ok(user.publicKeyHex.length === 66);      // 33 bytes hex
const role = user.attributes.find(a => a.value === 'member');
assert.strictEqual(role.verifiedBy, 'admin');
```
- [ ] **Step 2: Run** `node bindings/wasm/test/getuser-readback.js` — expect FAIL (`keyVersion` is hardcode-0, `publicKeyHex` empty).
- [ ] **Step 3: Add C exports** in `wasm_helpers.c` following the `crabs_wasm_user_attr_*` idiom (:981-997 read the same `user_t*`; `attribute_machine.h:81-98` has `public_key[33]`, `status`, `key_version`; attr entries carry `verified_by`):
```c
int64_t  crabs_wasm_user_key_version(void* user);
int32_t  crabs_wasm_user_status(void* user);
int32_t  crabs_wasm_user_public_key(void* user, uint8_t* out);  /* copies 33 bytes, returns length */
const char* crabs_wasm_user_attr_verified_by(void* user, int32_t index);
uint64_t crabs_wasm_user_attr_expires_at(void* user, int32_t index);
```
Add matching declarations to `wasm_init.c`'s EXPORT list (grep how `crabs_wasm_user_attr_value` is registered there and follow).
- [ ] **Step 4: Map in bindings-core.js** — replace the stubbed return (:699-706 fragment) using the existing `readString`/hex idiom used elsewhere in that file; the status switch mirrors `crabs_node.cc:1183-1187` (`active`/`suspended`/`revoked`).
- [ ] **Step 5: Test green** + run `node bindings/wasm/test/smoke.js` (no regression) + `bash cookbook/tests/run-c.sh | tail -1`.
- [ ] **Step 6: Commit** `fix: wasm getUser returns real keyVersion, status, publicKey, verifiedBy`.

### Task A2: temp-attr representation — node's plain token wins

**Files:**
- Modify: `bindings/wasm/bindings-core.js:686-696` (drop the `name + ':' + value` doubling)
- Test: `bindings/wasm/test/06-moderation` semantics — `cookbook/snippets/wasm/06-moderation.js` currently asserts the doubled string; policy `'AND role:member clearance:moderator'` must still match via the plain token path (`src/Crypto/crypto.c:1126-1163` evaluates `temp->name` + value as two tokens).

- [x] **Step 1: Update bindings-core.js** — done in commit 8751aa9: `value` now reads back the plain token `'clearance:moderator'` (the plan's `'moderator'` shorthand was loose; node's mapper returns `temp->name`, the full `name:value` token, crabs_node.cc:1208).
- [x] **Step 2: Run the recipe snippet** `node cookbook/snippets/wasm/06-moderation.js` — expect FAIL where it pins the doubled string.
- [x] **Step 3: Update the snippet assertions** (and the recipe prose that explains the doubling — recipe 6 "How CRABS encodes it" section) to the plain token; re-run green. Also grep `bindings/wasm/test/` for other doubled-string reliance (`grep -rn "moderator:moderator" bindings/`) and fix.
- [x] **Step 4: Full suites**: `node bindings/wasm/test/smoke.js && node bindings/wasm/test/schedules.js && cd cookbook && node tests/run-snippets.mjs`.
- [x] **Step 5: Commit** `fix: unify wasm temp attributes on the plain token representation`.

### Task A3: node createTrigger signs with the real caller identity

**Files:**
- Modify: `bindings/node/src/crabs_node.cc:1846-1862` (replace hardcoded sign-block keyed to `'admin'` with the machine's admin identity used by every other node op path — read `crabs_node.cc` `DefineItem`/`Execute` to see what id the wrapper normally stamps; the bug is ONLY if the node wrapper fabricates `'admin'` when the machine's admin is named otherwise).
- Test: add to `bindings/node/test/test.js` (follow existing style) — machine created with admin id `'chair'` (NOT `'admin'`), then `node.createTrigger(...)` must succeed (it failed/signed-as-'admin' before) and the trigger grant's `verifiedBy`/signer is `chair` (assert whatever field the machine exposes).
- [ ] **Step 1: Failing test** (admin named `'chair'`; createTrigger → expect success where the old code produced `key_stale`/wrong-signer behavior). [ ] **Step 2:** run → FAIL. [ ] **Step 3:** fix the signer stamping. [ ] **Step 4:** green + `node cookbook/snippets/node/06-moderation.js` (that snippet has the "machine must be created with admin id `'admin'`" workaround note — update the snippet + recipe 6 note once the constraint is gone). [ ] **Step 5: Commit** `fix: crabs-node createTrigger signs with the machine's real admin identity`.

### Task A4: dissolve-after-revoke reconciliation

**Files:**
- Modify: `src/Lineage/lineage.c:1787-1790` (the dissolve handler's ACTIVE gate)
- Test: gtest near `test/test_lineage.cpp` dissolve tests — add `DissolveAfterRevoke`: revoke a manifest entry, then dissolve it → expect success (per `lineage.h:516-520`'s contract), tombstone mint then legal.
- [x] **Step 1: Failing gtest** asserting dissolve-after-revoke returns `CRABS_SUCCESS` and the tombstone is produced. ([x] **Step 2:** run `ctest --test-dir build -R Dissolve` → FAIL.) [x] **Step 3:** allow dissolving a revoked (non-DISSOLVED) entry — keep refusing re-dissolve of an already-DISSOLVED entry (idempotency gate stays). [x] **Step 4:** ctest green (whole suite) — plus recipe 12's wasm snippet, prose, and the wasm binary re-synced to the settled semantic (`run-snippets.mjs` green). [x] **Step 5: Commit** `fix: lineage dissolve works on revoked entries (header contract honored)`.

### Task A5: policy parser single-clause guard (decision by size)

**Files:** possibly `src/Crypto/crypto.c:676-696`; Test: gtest addition near `test/test_crypto.cpp` policy tests.
- [x] **Step 1:** Fix implemented (recipe 16, not 15, is the revocable-data doc): a pre-parse guard in the `_eval_policy_expr` prefix-AND branch — the collapse applies only when the text after `AND` is a single term running to end-of-string (no further operator/paren/comma), and only if the operand parse consumes it fully. Every other dangling shape (bare `AND`, compound `AND role:member AND`, parenthesized form, infix trailing `<term> AND` — ambiguous at recursion depth) keeps the fail-closed refusal. gtest `SingleClauseAndPolicyIsTheClause` added; red confirmed on the eval assertions only, green after the fix.
- [x] **Step 2:** crypto section (12/12 `TestAbe*`) + whole `ctest` suite 1742/1742 green; `run-c.sh` all snippets green after rewriting 16's pitfall pin (singleton now lands as `'role:member'`, plus a new fail-closed pin for `'AND role:member AND'`); `run-snippets.mjs` 24/24 green. Recipe 16 prose updated to the post-fix grammar rule.
- [x] **Step 3: Commit** `fix: 'AND x' single-clause policy parses as x`.

### Task A6: DedupSpec JS surface (recipes 2/3)

**Files:**
- Modify: `src/Util/wasm_helpers.c` (new `crabs_wasm_define_operation_type(am, op_type, dedup_type, tracker_path, flag_path, condition, rejection_message)`) — builds a `__define_operation_type__` op with `resources[0] = op_type`, sets `op.dedup` (`state_machine_op_define_operation` at `state_machine.c:2895-2911` copies op->dedup into the registry via `state_register_op_type_def`), signs as the admin, executes through the machine. Wire layout reference: `_serialize_dedup_spec` (`serialization.c:1842-1856`).
- Modify: `bindings/wasm/bindings-core.js` + `index.d.ts`: `Node.defineOperationType(opType, { dedup: 'per-user' | 'global' | 'none', trackerPath?, flagPath?, condition?, rejectionMessage? })`.
- Modify: `bindings/node/src/crabs_node.cc` + `index.d.ts`: `DefineOperationType` following the `DefineItem` C-direct pattern (`crabs_node.cc:1243-1326`): `operation_create(CRABS_OP_DEFINE_OPERATION)`, `operation_add_resource(op, op_type)`, set `op_->dedup` (fields per `data_model.h:363-374`), sign, `state_machine_execute`.
- Test: gtest addition in `test/test_dedup.cpp` is already the C truth (registered specs enforced, F-2) — binding tests instead: `bindings/wasm/test/dedup-surface.js`: define a `vote` op with `DEDUP_PER_USER`, trackerPath a one-shot set name; register handler; submit two alice votes → second refuses (`already_performed`, pin the error string from `crabs.h:106`/`bindings-core.js` ERROR_MESSAGES); plus `bindings/node/test/` equivalent via `node.defineOperationType`.
- [x] Steps: TDD wiring (new binding test → FAIL → implement export + API → PASS: wasm RED at `Node.defineOperationType is not a function`, then GREEN; node mirror block GREEN), run `ctest -R Dedup` — plus ONE C change found by the TDD loop: `__define_operation_type__` could not pass the full executor's pre-handler gates at all (the item-transition gate resolved resources[0] as an item; the A10 carried-spec gate rejected the op's own dedup registration payload) — fixed with narrow define-op exemptions + `DefineOperationTypeExecutesThroughMachine` gtest (commit `fix: __define_operation_type__ executes through the machine`). Cookbook snippets 2/3 (wasm + node) rewritten to install real specs (recipes 2/3 COMPLETE, GAP blocks removed, api-map R2/R3 rows updated); recipe 3 needs no handler at all (the GLOBAL spec's guard+apply are the whole behavior). `run-snippets.mjs` + `run-c.sh` green, full wasm `npm test` (13/13 incl. dedup-surface.js) + node `npm test` green. [x] **Commit**s `feat: defineOperationType in wasm binding (DedupSpec registration)` / `feat: defineOperationType in node binding (DedupSpec registration)` / `docs(cookbook): recipes 2-3 use registered dedup specs` (+ audit refinements commit).

### Task A7: schedules on crabs-node (recipe 7)

**Files:**
- Modify: `bindings/node/src/crabs_node.cc` + `index.d.ts`: port the surface implied by the wasm exports (`wasm_helpers.c:1383-1438`, listed: `schedule`, recurring, `cancelSchedule`, process-due tick with explicit `nowMs`, count/first/next pending reads, `scheduler_set_max_occurrences_per_tick`). Node wraps the SAME C scheduler functions (`src/Scheduler/scheduler.h:20-58`); the due-mint materialization must route through the full machine executor like wasm does (read wasm's `crabs_wasm_process_schedules` :1416 implementation and mirror its execute path).
- Test: `bindings/node/test/test.js` addition (mirror `bindings/wasm/test/schedules.js`): one-off mint at fixed clock, not-due idempotent, cancel + tick past → never fires, recurring 3 fires in order. Reminder from the cookbook: materializes at submission-time authorization (scheduler.c:337 comment is the fact).
- [x] Steps: test → FAIL → port → PASS. Node block mirrors `bindings/wasm/test/schedules.js` scenarios with node-native observability (no `registerHandlerJs`: the scheduled `mint` op runs the executor's wildcard path, fires observed as kind-`schedule` change events; also pins the submission-time authorization refusal (unauthorized) and typed argument rejections). RED at `schedNode.schedule is not a function` → GREEN (`148 passed, 0 failed`, node; `ctest -R Scheduler` 37/37 unchanged). Implement: `crabs_node.cc` — `require_u64_numeric` helper (number|bigint, 2^53 exact-range bound) + `Schedule` / `ScheduleRecurring` (5-arg wasm shape) / `CancelSchedule` / `ProcessSchedules` (wall-clock default mirroring the wasm wrapper's `Date.now()`) / budget setter+getter / `PendingSchedules` (same row shape), all behind the `state_machine_validate` wrapper gate — surface names EXACTLY match `bindings/wasm/index.d.ts:501-511`; node d.ts `:294-331` in the same commit. Cookbook: recipe 7 node GAP block deleted → node section + `cookbook/snippets/node/07-timed-actions.js` (same scenarios: one-off exactly-once, cancel pin, recurring 3-fire catch-up, budget defer+lift; explicit clock pokes only); frontmatter `languages: c wasm node`, status COMPLETE, wasm/node cites re-anchored; api-map §6 schedule rows + §17 R7 + difference-list item 3 updated (wasm-only → both bindings). `run-snippets.mjs` 25/25 + `run-c.sh` green. [x] **Commit** `feat: schedule surface on crabs-node bindings`.

### Task A8: OT ordered set JS (recipe 8)

**Files:**
- Modify: `src/Util/wasm_helpers.c`: `crabs_wasm_define_item` (:529-549) gains the `DATA_TYPE_OT_ORDERED_SET` + `CRDT_CUSTOM` branch (allocate `crabs_ot_ordered_set_create()` into the item's `value_repr` struct — mirror how `data_model.c:192-193` destroys OT items to see the expected repr); new exports `crabs_wasm_ot_apply(am, item_name, ot_wire)` (wrap a `crabs_ot_operation_t` in a `CRABS_OP_EXECUTE_OT` op per `src/OT/ot_execution.c:471`) and `crabs_wasm_ot_read(am, item_name)` returning the converged order list (`crabs_ot_ordered_set_get/head/count`, `ot_ordered_set.h:69-75`).
- Modify: `bindings/wasm/bindings-core.js` + `index.d.ts`: `Node.addOrderedSet(name)` + `node.otInsert(name, opId, element, afterElement | null)` / `otMove` / `otDelete` + `getOrderedSet(name) -> string[]` (naming follows task; keep consistent across surfaces).
- Modify: `bindings/node/src/crabs_node.cc` + `index.d.ts`: same surface direct-to-C (creation already unblocked per recon: `state_add_item` does no type dispatch).
- Test: gtest already covers C (`test/test_ot_ordered_set.cpp`); binding tests mirror its MERGE scenario: two JS nodes, item created via defineItem `('board', 'ot_ordered_set', ...)`, concurrent inserts on both, merge (`Node.merge` — check its existing name in d.ts, e.g. how recipe 1's C demo merges; if bindings only expose op-exchange, exchange ops exactly as `test/test_ot_ordered_set.cpp:347-375` does), assert one converged order containing both.
- [x] Steps: TDD each export/API (wasm RED at `node.addOrderedSet is not a function` → GREEN; node RED the same → GREEN). Implemented with one executor-contract discovery: ordered* sugar takes POSITIONS (the C apply ops are position-based; the plan's `afterElement` anchoring is internal placement metadata, not a surface param) and an options bag `{ id: {node,seq,ts?}, deps? }` because cross-replica op-exchange REPLAYS need declared causal deps — replaying a peer op without its deps mis-shifts it (transform treats the replica's unknown ops as concurrent); both binding tests pin the discriminating deps-carry case, and a wasm marshal bug found by it (deps {ptr,len} wrapper passed instead of the pointer) is fixed. Item creation is a DEDICATED adder (`addOrderedSet` mirroring addORSet / `crabs_register_ot_type`), NOT the defineItem guard: define_item is the SOVEREIGN-legal surface (counter/register canonical serializations back the hash-chain digest) and OT items can never be sovereign-legal. Recipe 8's GAP blocks replaced with `wasm/08-reorderable-list.js` + `node/08-reorderable-list.js`; status stays **PARTIAL** with `languages: c wasm node` — the merge layer (`crabs_ot_ordered_set_merge` preflight: conflicting-payload refusal, merged position-map delete-wins) has no JS map entry; the snippets demo op-exchange convergence (insert-insert tie-break, deps declared) plus idempotent replay. C additions: `crabs_ot_ops_to_wire` (ot_execution.c, round-trip + executor gtests in test_ot_execution.cpp → 23/23 OTExecution, full suite 1746/1746), `crabs_wasm_add_ordered_set`/`crabs_wasm_ot_apply`/read exports in wasm_helpers.c. api-map §15 + §17 R8 rewritten with live cites. [x] `run-snippets.mjs` 27/27, `run-c.sh` green, browser.js green, both bindings npm test green. [x] **Commits** `feat: ordered-set items from JS (wasm binding)` / `(node binding)` + 2 marshalling/validation fixes + `docs(cookbook): recipe 8 — ordered set from JS`.

### Task A9: locks / tx-manager ceremony JS (recipe 9)

**Files:**
- Modify: `src/Util/wasm_helpers.c`: `crabs_wasm_add_resource(am, ...)` (mint a `RESOURCE` item — mirror node's `Node.addResource` at `crabs_node.cc:1499-1516`); `crabs_wasm_lock_claims(am, op, ...)` setters for the lock-claim fields the executor token-checks (`state_machine.c:1266-1281`; find the `operation_t` claim fields via `grep -n "claim" src/CRABS/data_model.h src/StateMachine/state_machine.h`).
- Modify: `bindings/wasm/bindings-core.js` + `index.d.ts`; `bindings/node/src/crabs_node.cc` + `index.d.ts`: tx-manager attachment — node: option at `new Node(...)` or `node.attachTxManager('memory')` calling `crabs_tx_manager_memory()` (`src/TxManager/tx_manager.h`); wasm: same via export `crabs_wasm_attach_tx_manager`.
- Test: keep recipe 9's honest caveats: binding test mirrors its C ceremony (lease, forged-claim refusal, apply-once via replay backstop with a REAL tx manager attached), gtest for the node binding's C-level changes if any.
- [ ] Steps: TDD; cookbook: replace recipe 9's wasm GAP block and node ceremony GAP block with snippets exercising claims + attached tx manager; keep the machine-local/cooperative caveats prose; status COMPLETE, `languages: c wasm node`. [ ] Harnesses green. [ ] **Commit** `feat: lock claims and attachable tx manager from JS`.

### Task A10: attestation consumption JS (recipe 12)

**Files:**
- Modify: both bindings' `Operation` class (`bindings/wasm/index.d.ts:26-45` / node :19+): `addAttestation(fields)` where fields = `attestation_t` (`lineage.h:96-104`: parent/child/user ids, attributes, notBefore, expiresAt, parentKeyVersion, signature hex). Wasm: new export copying the struct onto `op->attestations` (alloc count + fill — mirror how resources are attached); node: direct `op_->attestations` fill.
- Verify the executor path needs nothing new: `state_machine.c:700-756` already consumes `op->attestations` (the C snippet in recipe 12 proves it).
- Test: extend `bindings/*/test/` lineage tests: child machine op carrying a REAL attestation (minted by the same parent machinery in-test) passes `@parent/` endorsement; a tampered signature refuses — mirroring C battery `lineage.c:700-756`.
- [ ] Steps: TDD; cookbook: replace recipe 12's consumption GAP block with a wasm + node snippet; status COMPLETE. [ ] **Commit** `feat: op attestation attach from JS`.

### Task A11: ABE decrypt through the machine (recipes 6/16)

**Files:**
- Modify: `src/Util/wasm_helpers.c`: `crabs_wasm_abe_keygen(am, attrs)` returning the serialized user key (`crypto_abe_keygen` on `state->abe_mk` + `crypto_abe_user_key_serialize`, `crypto.h:131`); `crabs_wasm_abe_decrypt(am, key_serialized, ct)` = `crypto_abe_user_key_deserialize` (check exact name in crypto.h :120-131) + `crypto_abe_decrypt`.
- Modify: `bindings/wasm/bindings-core.js`: `node.abeKeygen(attrs) -> object` and `node.abeDecrypt(key, encrypted)` (shape parallels the existing `encrypt` pipeline at :1050-1081). Node binding: same two methods via `crabs_node.cc`.
- Note: the machine-owned-MSK decision means the ADMIN (anyone controlling the machine) derives keys — the recipes frame this as "the machine derives a reader key for the reader's attribute set".
- Test: `bindings/wasm/test/` + node: full round trip encrypt→keygen→decrypt==plaintext + wrong-attrs keygen refuses decrypt (mirrors `test_crypto.cpp:249-301`).
- [ ] Steps: TDD; cookbook: recipe 6's ABE GAP block replaced with round-trip snippet; recipe 16's decrypt gap likewise; both statuses COMPLETE where the rest of their surfaces are real. [ ] **Commit** `feat: ABE keygen and decrypt from JS with machine-held master key`.

### Task A12: cookbook corrections — recipe 14 runnable, recipe 15 deleted

**Files:**
- Modify: `cookbook/recipes/14-strict-ordering-market.md` → rewrite as runnable: frontmatter `status: COMPLETE`, `maturity: STABLE`, `languages: wasm node` (node binding is raft-bound per `bindings/node/index.d.ts:311+`; check wasm attachRaft parity FIRST — if wasm lacks the raft surface, `languages: node` with an honest "wasm recovery seam exists, propose path is node-only" note and citation to `b5b2b56`). Content: `createRaftHost` reference loop (`bindings/node/index.js` — read it) driving a single-host or two-peer-loop market with strict ordering via `attachRaft` + `defineItem` with the module; keep the naive-version/idea prose; the GAP callout is removed. api-map R14 row rewritten from `src/Raft/raft_module.h` + d.ts lines.
- Delete: `cookbook/recipes/15-hardware-attested-policy.md`; `git rm cookbook/snippets/c/15*` if any exists (there is none — verify with `ls cookbook/snippets/*/ | grep 15`).
- Rename: `cookbook/recipes/16-revocable-data.md` → `number: 15` (git mv to `15-revocable-data.md`); grep `recipes/` + `api-map.md` for `Recipe 16`/`recipe 16`/`R16` cross-refs and update (recipe 1's "Recipe 3" dedup pointer unaffected; recipe 6's pointer to "Recipe 6" unaffected).
- api-map: delete R15 row, renumber R16→R15, update R2/R3/R7/R8/R9/R12 rows to reflect the new bindings (each with real file:line from this phase's code).
- [ ] Steps: rebuild (`node cookbook/site/build.mjs` → "Built 16 recipe pages"), hub rows correct, snippets harness green. [ ] **Commit** `docs(cookbook): ordering module is real (recipe 14 runnable); drop hw attestation; renumber`.

### Task A13: wasm artifact regeneration + full Phase A verification

**Files:** `bindings/wasm/crabs.js`, `crabs.wasm`, `crabs.dev.js`, `crabs.dev.wasm` (committed artifacts).
- [ ] **Step 1: Regenerate:** `OPENSSL_SRC=/tmp/openssl-3.4.0 bash build_wasm.sh` (per `bindings/wasm/package.json` build script; if `/tmp/openssl-3.4.0` is absent locally, follow the openabe-c fork build path the repo committed before — the last artifact commit shows the exact flow; report the flag set used).
- [ ] **Step 2:** rerun EVERYTHING: `node bindings/wasm/test/smoke.js` + full wasm test chain (`package.json` test script), cookbook harnesses, `bash cookbook/tests/run-c.sh`, CMake + `ctest --test-dir build`, `node cookbook/tests/browser.js`.
- [ ] **Step 3: Commit** `chore: regenerate wasm artifacts (dedup, schedules-parity, OT, claims, ABE decrypt, trigger signer)`.
- [ ] **Step 4: Final Phase A review** — spec compliance + quality reviewer passes over the branch, then merge `gap-fill` to master (finishing-a-development-branch flow). Phase B starts from the merged master.---

## PHASE B (branch `cookbook-restyle` off merged master; starts only after A13's review merges)

### Task B1: hub learning path + tagline (build.mjs)

**Files:**
- Modify: `cookbook/site/build.mjs` (sidebarFor + hub mainHtml) and every recipe frontmatter (additive `teaches:` line)
- Test: `node cookbook/site/build.mjs` + `curl` the dist hub

- [ ] **Step 1: Add `teaches:`** to all 16 recipe frontmatters — one line each, concept-first. Final content per recipe (paste verbatim):
```yaml
# 01 shared-count:        teaches: counting with replicas: why max-per-lane beats one integer
# 02 one-vote-per-member: teaches: one-person-one-vote as a monotone set plus dedup guarding
# 03 execute-once:        teaches: exactly-once semantics vs. monotone flags
# 04 roles-and-policies:  teaches: authorization as state — attributes deciding what runs
# 05 member-profile:      teaches: last-writer-wins registers and per-member data
# 06 progressive-disclosure-moderation: teaches: triggers, thresholds and attribute-gated payloads
# 07 timed-actions:       teaches: clocks, schedules and the submission/fire boundary
# 08 reorderable-list:    teaches: concurrent edits to one ordered list via transform ops
# 8b rich-text:           teaches: why rich text is a different (unmeasured) order of hard
# 09 treasury:            teaches: resource locking — what machines can and cannot promise
# 10 private-but-accountable: teaches: sovereign write domains — integrity without confidentiality
# 11 subgroups:           teaches: attenuating authority down a machine tree
# 12 federation:          teaches: attestations — vouches that cross machines and expire
# 13 sovereign-ledger:    teaches: append-only personal ledgers no admin can rewrite
# 14 market:              teaches: strict ordering from an elected leader (raft module)
# 15 revocable-data:      teaches: revocation, key versions and epoch re-encryption
```
- [ ] **Step 2: build.mjs hub block** — render `Start here` above the status table:
```js
const SECTION_ORDER = ['Basics', 'Conditions', 'Convergence', 'Coordination', 'Composition', 'Ground truth'];
const learningPath = SECTION_ORDER.map(section => {
  const rows = pages.filter(page => page.meta.section === section);
  if (!rows.length) return '';
  return `<h2>${escapeHtml(section)}</h2>` + rows.map(page =>
    `<p><a href="/cookbook/${escapeHtml(page.meta.slug)}/">${escapeHtml(page.meta.title)}</a><br>
     <span class="teaches">${escapeHtml(page.meta.teaches || '')}</span></p>`).join('');
}).join('');
```
insert `learningPath` into the hub `mainHtml` before the index table. Add `.teaches` to `style.css`: `color: #6b5a3e; font-size: 13px;`.
- [ ] **Step 3: Taglines.** `sidebarFor()`: replace `Verified recipes.<br>Run in CI. Gaps stay visible.` with `Learn by building.<br>Every recipe verified against<br>the code it teaches.` Landing page card: reword per STYLE ("Learn CRDTs, ordering, and coordination by building them — every recipe verified against the code it teaches."), keep "Coming soon" cards as-is.
- [ ] **Step 4: Verify** hub renders the path above the table; `node cookbook/tests/browser.js` still green (recipe page unchanged). [ ] **Commit** `feat(cookbook): start-here learning path and teaching taglines`.

### Task B2: restructure Basics pages (recipes 01-05)

Per-page procedure (identical for every page in B2/B3/B4; the per-page concept notes below are the NEW material):

- The section map and rewriting rules come from `cookbook/STYLE.md` (read it first). Every page ends with `## Verified against the code` containing ONE PROVENANCE block consolidating all citations moved inline (the existing per-language footers disappear INTO it — the per-snippet PROVENANCE comments are deleted; keep symbols/test_ref/verified fields, telegraphic prose allowed). Guarantees become one-line bullets. Inline citations drop to ≤2 per page. GAP callouts: ≤1, reader-worded, after teaching (most Phase-A-complete pages end with none). Headings contain no "verified/actually/we found". Snippet fences stay byte-identical (no code churn). Build + harnesses green after each page. One commit per page.

Concrete concept-notes per page (the new "The problem"/"The idea" seeds — expand, don't invent facts):
- 01 shared-count: problem = three offline laptops, `5 meets 5`; idea = lanes/own-state + max merge (the per-node max table).
- 02 one-vote-per-member: problem = the two-device double vote; idea = append-only sets + the check-then-take race that dedup specs close in one machine step.
- 03 execute-once: problem = double-applied webhooks; idea = monotone flags and why "skip if seen" needs the seen-set to be part of the state.
- 04 roles-and-policies: problem = who may close the merge request; idea = authorization inputs are state transitions, not config.
- 05 member-profile: problem = two tabs editing one profile; idea = LWW and why tie-break needs order, not timestamps alone.
- [ ] Pages 01-05 restructured per procedure, builds green, commits `docs(cookbook): restructure recipe 0N into teaching form`.

### Task B3: restructure Conditions + Convergence (06, 07, 8, 8b)

- 06: problem = the spam wave; idea = threshold → consequence, as a state transition (triggers), with the payload privacy split (policy gate vs ABE seal).
- 07: problem = the token that must not count until T; idea = time as an input to state transitions, and WHY authorization lives at submission (scheduler.c:337 fact — keep citations in footer).
- 08: problem = two people drag different rows; idea = positions vs identity (op-id elements), the transform idea taught standalone; now with real JS snippets from A8, so this page flips PARTIAL → COMPLETE.
- 8b: boundary-teaching per STYLE §4 — WHY rich text ≠ ordered set (continuum vs discrete elements; cursor/IME/span risks; O(N²) shared-position merge), what a module must provide, do-this-instead pointer to 8. Same facts, no apology.
- [ ] Same procedure/gates/commits.

### Task B4: restructure Coordination + Composition + Ground truth (09-15)

- 09 treasury: idea = claiming vs locking, machine-local reality ("the lock lives in one machine's runtime") taught as the concept, not a confession.
- 10 private-but-accountable: idea = identity+integrity vs confidentiality — two different properties readers conflate.
- 11 subgroups: idea = attenuating authority; can't-reach-up ≠ sandbox (both halves taught).
- 12 federation: idea = vouches with expiry; clock honesty as a concept (TTL is advice without an authenticated clock).
- 13 sovereign-ledger: idea = append-only per writer; hash chains make tampering evidence, not prevention.
- 14 market (now runnable from A12): idea = strict total order needs ONE authority per item; the raft host loop shown.
- 15 revocable-data: idea = revocation of capability vs. revocation of instruments (bearer keys), epoch re-encryption as the recipe pattern.
- [ ] Same procedure; commits per page.

### Task B5: final gate

- [ ] Run the STYLE.md mechanical checklist per page (16 pages) — self-check, then a reviewer applies it independently with the build + harnesses; fix anything it finds (loop).
- [ ] Full suites: build, 3 harnesses, browser check, hub + landing eyeball at `/cookbook/` and `/`.
- [ ] De-wonk audit (the skill) over build.mjs + the changed pages.
- [ ] Merge `cookbook-restyle` to master; push (user go-ahead); verify the Pages run. 