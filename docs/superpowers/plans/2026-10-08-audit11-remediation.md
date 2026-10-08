# Audit-11 Remediation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fix all Audit-11 findings (docs/SECURITY_AUDIT_11.md): two in the openabe-c fork (push + submodule bump), the rest in CRABS on master.

**Baseline:** ctest 1604/1604 (1 network skip); fork tests 148/148 via `LD_LIBRARY_PATH=build:deps/lib:deps/relic/build/lib make test` (fork repo /home/victor/Workspace/src/github.com/vijayee/openabe-to-c/openabe-c; tests/ is git-ignored there — source commits only).

---

### Task F1: A11-1 (+A11-L9 in touched files) — fork `oabe_params_deserialize` bounds

**Files (fork only):** `src/keys/oabe_key.c` (`oabe_params_deserialize`, ~:555-735), `tests/test_abe.cpp` (untracked).

- [ ] TDD: crafted params blob test — valid envelope header then first length prefix oversized (0xFFFFFFF0) with short body → must return an error (never succeed/crash); also a mid-blob oversized later field.
- [ ] Add `if (index + X_len > oabe_bytestring_get_size(input)) { rc = OABE_ERROR_DESERIALIZATION_FAILED; goto error/-return; }` before EVERY `X_len > 0` copy block (g1/g2/gt/g1_alpha/egg_alpha/g1_a/g2_a/key_data). Use the subtraction form (`X_len > size - index`, matching CRABS's "overflow-safe" idiom) in the touched functions per A11-L9.
- [ ] Sweep: grep the whole fork src/ for remaining `new_from_data(ptr + index` / `unpack32`+copy patterns lacking bounds — fix any sibling found; report the sweep result.
- [ ] Fork full suite green. Commit: `fix: bounds-check every length prefix in oabe_params_deserialize (audit 11 A11-1)` — push origin master.

### Task F2: A11-3(+A11-L9) — fork zero-length MSK scalars fail open

**Files (fork):** `src/keys/oabe_key.c` (~:956, 979), `src/abe/oabe_context.c` (`oabe_context_cp_keygen` defensive check ~:790), tests.

- [ ] TDD: deserialize an MSK envelope with alpha_len==0 → must return error (not SUCCESS with NULL alpha); same for beta_len==0.
- [ ] Implement: reject `alpha_len == 0 || beta_len == 0` (INVALID_KEY) before/at reconstruction. Use subtraction-form bounds per A11-L9 in this function.
- [ ] Defensive: `oabe_context_cp_keygen` returns OABE_ERROR_INVALID_KEY if `secret_key->alpha/beta == NULL` (guards all other restore paths) — with a comment.
- [ ] Full fork suite green. Commit: `fix: reject zero-length MSK scalars; keygen refuses NULL scalars (A11-3)` — push; then CRABS: `cd deps/openabe-c && git checkout <sha>` + commit `chore: bump openabe-c — audit-11 fork fixes`.

### Task C1: A11-2 — REPL quoting + policy-add truncation

**Files:** `src/CLI/cli.c` (cli_shell_execute_line ~:2594-2620; policy arm ~:2650), `test/test_cli.cpp`.

- [ ] TDD (test_cli.cpp): (a) `policy add myop "role:admin OR role:member"` through `cli_shell_execute_line` installs the FULL expression (quotes stripped; assert via state_get_policy equivalent used by sibling tests); (b) `policy add myop role:admin OR role:member` (unquoted, surplus argv) → error, NOT a silently-truncated install; (c) unbalanced quote → error; (d) quotes with spaces inside still split outer tokens (`item add "my item" counter` style usage); empty quoted string `""` → empty-token refusal? (decide: refuse, document).
- [ ] Implement tokenizer upgrade in cli_shell_execute_line: whitespace + quote awareness (double AND single quotes; a quote toggles no-split between its pair; quotes stripped; >32 tokens refusal kept; unbalanced/empty-quote → CLI_ERR_ARGS). Then the `policy add` arm additionally REJECTS argc > 6 with a message instructing quoting (defense in depth for single-shot users who might also pass unquoted).
- [ ] Full ctest green. Commit: `fix: REPL quote-aware tokenizer; reject surplus policy add args (A11-2)`.

### Task C2: A11-5 — wedge detection in lineage_key_rotate

**Files:** `src/Lineage/lineage.c` (~:1960-2046), `test/test_lineage.cpp`.

- [ ] TDD: rotate K1→K2, do NOT state_set_node_key, then rotate again → SECOND rotate must FAIL (clear error `CRABS_ERR_INVALID_PARAM`, message via event/error semantics consistent with the API) and leave state untouched; a comment documents that recovery requires installing the pending key first. Also verify the normal rotate→install→rotate flow still succeeds and rotate-without-prior-records (first rotation) still works when node key != any record (no prior record → allowed).
- [ ] Implement: before building a record, if `lineage_last_key_transition != NULL` → parse its new_pk and compare with `state->node_public_key`; mismatch → refuse (the previous rotation was never installed).
- [ ] Full ctest green. Commit: `fix: refuse lineage_key_rotate while the previous rotation is uninstalled (A11-5)`.

### Task C3: A11-4 — retired-key authority: README truth + tip policy for FRESH attestations

**Files:** README.md (~:223), src/Lineage/lineage.c (`attestation_verify_by_lineage_key` / `lineage_verify_by_parent_key` — DESIGN: keep any-key verify for tombstones [backward compat, no time anchor]; for ATTESTATIONS with a validity window, verification MUST try the tip key FIRST and only accept a retired-chain key for attestations whose window STARTED before the tip version existed — we have no per-attestation key-version stamp, so the honest implementable rule is: keep any-key for attestations but STATE the residual in README; a fresh-window-requires-tip rule needs a wire change. **DECISION (controller): docs-only this round** — implement precisely: README paragraph states retired keys retain LIVE authority (fresh attestations + tombstones) until the chain refuses; recommend rotating children's trust by keeping retired keys only as long as needed and re-issuing; also A11-L1's stash/catch-up precondition documented in lineage.h (one sentence).
- [ ] Commit: `docs: state retired-key live authority + stash precondition honestly (A11-4, A11-L1)`.

### Task C4: LOW batch

Separate small commits:
- **A11-L2:** cap-check the `created_at` write in `_lineage_key_transition_write_body` (reject cap too small uniformly, fix the doc comment) — `fix: cap-check created_at write in key transition body (A11-L2)`.
- **A11-L3:** `strnlen(parent_id, CRABS_MAX_USER_ID)` discipline in the body writer — `fix: bound parent_id length reads in transition body writer (A11-L3)`.
- **A11-L5:** duplicate key-update delivery → `CRABS_ERR_ALREADY_PERFORMED` (match sibling lineage ops; check the enumerator exists — grep ALREADY_PERFORMED) + test — `fix: already-performed error for duplicate key-update delivery (A11-L5)`.
- **A11-L7:** cleanse at the hex-decode failure throws in crabs_node.cc (`:634-635`, `:1364-1365`) — `fix: cleanse on decode-failure throws in binding sign paths (A11-L7)`.
- **A11-L8:** rewrite the `_cli_apply_time_source` create-failure comment to state actual behavior (system fallback retained; honest revert happens at the caller) — `docs: correct time-source apply comment (A11-L8)`.
- **A11-L10:** extend the operation_is_protected regression test loop to include `__parent_key_update__` — `test: cover parent key update op in protected-op guards (A11-L10)`.
- **A11-L6:** binding README + index.d.ts note on cross-wrapper detach semantics — `docs: note cross-wrapper time-source detach in node binding docs (A11-L6)`.

### Task C5: final verification

- [ ] ctest 1604+/full green; node tests + smoke; wasm npm test; de-wonk over the change set; SECURITY_AUDIT_11.md remediation status updated with commit refs. Commit: `docs: mark audit-11 remediation complete`.