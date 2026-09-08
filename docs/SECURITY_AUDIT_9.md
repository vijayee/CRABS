# CRABS Security & Correctness Audit 9

**Date:** 2026-09-08
**Scope:** Full codebase at `feature/devtools-state-inspector` (master + ordered-set convergence repair + change-notification/devtools work). Emphasis on code changed since Audit 8.
**Method:** Five parallel identification agents (crypto/key-lifecycle; authorization/state machine; serialization/CLI; CRDT/OT/scheduler; JS bindings/devtools; HLC/time/conditions/triggers), then three adversarial false-positive filter agents over every raw finding. Findings below kept at filter-adjusted confidence; refuted findings listed at the end. Prior audits: `docs/SECURITY_AUDIT*.md` (8 rounds).

## High (confidence >= 8, fix recommended)

### A-1. Stack-buffer overflow in `CreateTrigger` (N-API binding) — HIGH, conf 9
`bindings/node/src/crabs_node.cc` (~956-970). `pos += snprintf(payload + pos, sizeof(payload) - pos, …)`: on truncation `snprintf` returns the *would-be* length, so `pos` can exceed `sizeof(payload)`; the subsequent write uses `sizeof(payload) - pos`, which underflows to a huge `size_t` → out-of-bounds stack write. Attacker-controlled via long `triggerId`/`condition`/`description` JS args. Fix: clamp `pos` to `sizeof(payload) - 1` after each `snprintf`.

### A-2. Change-hook re-entrancy → use-after-free in `trigger_process_all` — HIGH, conf 8
`src/Trigger/trigger.c` (~184-225 loop; notify at ~104-107) fires the change hook **inside** the trigger loop and **before** `last_triggered_at` is written. A hook that executes synchronously (JS listener via the WASM trampoline — installed unconditionally since the change-events feature — or an N-API listener) running `__create_trigger__` reallocs `state->triggers` while the outer loop still holds the old pointer → UAF on `trigger->last_triggered_at`; nested `trigger_process_all` (no guard, unlike `scheduler_ticking`) can also double-fire a trigger. Fix: add a `trigger_ticking` re-entrancy guard and/or defer effect notification until after bookkeeping.

### A-3. Serialized state silently drops all triggers — HIGH (correctness), conf 8
`src/Serialization/serialization.c` `_serialize_state`/`_deserialize_state` never read or write `state->triggers`/`trigger_count`. A save/load cycle discards every trigger; a restored node silently runs without its triggers (authorization-relevant mutations lost). Fix: add a triggers section (version-gated, v9) or document as known limitation with an explicit loader warning.

## Medium (confirmed; fix when convenient)

### A-4. Wire HLC is never validated — MEDIUM, conf 8
`crabs_hlc_receive` (src/HLC/hlc.c:353) has zero callers outside tests: BOUNDED/STRICT/TRUSTED skew strategies and counter validation never run on received ops. Wire HLC (`serialization.c:1890-1893`) is deserialized without `physical_nanos < 1e9` or skew checks and flows into ordering, the R7-11 replay backstop, and the chain hash. Impact: a signer can advance its own watermark arbitrarily far (self-DoS, R8-S-10 class) and unvalidated nanos would freeze `crabs_hlc_next` if receive is ever wired. Fix: validate received op HLC (nanos bound + strategy skew) at deserialization or execute time.

### A-5. `log_count` missing the sibling remaining-buffer bound — MEDIUM, conf 5
`serialization.c:1455-1459` caps `log_count` at 1M but — unlike every sibling counter fixed under R7-H/R8 — applies no remaining-bytes bound before `get_clear_memory(log_count * sizeof(log_entry_t))` (~276 B/entry). `get_clear_memory` aborts on failure. Crafted ~30-byte blobs (SHA-256 is integrity, not auth) request ~276 MB; on overcommit Linux this is mostly virtual, on strict-allocation systems a hard abort. Fix: `log_count > (buf.len - buf.offset) / 64`-style bound like `pc_count` (:2108).

### A-6. Trigger engine lacks a re-entrancy guard (double-fire) — MEDIUM, conf 8 (same root as A-2)
Nested `trigger_process_all` invocations (op → trigger effect → hook → execute) fire the same trigger twice before bookkeeping: duplicate temporary attributes, duplicate CHANGE_POLICY. Fix: guard flag mirroring `scheduler_ticking`.

## Confirmed, lower confidence (worth tracking)

- **Mode B ops skip `min_key_version` and key-staleness checks** (conf 6): `state_machine.c:593,652,686` resolve the signer via `find_user(op->signer_id)` which is NULL for `signer_id=""`; a lagging keyholder can sign anonymously and bypass the forced-rotation floor. Fix: enforce against the keyring-resolved signer.
- **Key-expiry config is dead** (conf 5): `key_expiry_enabled`/`default_key_ttl_ms`/`max_key_age_ms` have zero enforcement readers; `key->expires_at` is hard-coded 0 (`attribute_machine.c:1071`). R8-S-12 assumed these were enforced. (`key_rotation_enabled` IS enforced.)
- **Condition path-prefix fallback** (conf 6): `condition.c:905-924` resolves missing `tenant.quota` to item `tenant` — an attacker-controlled sibling item can satisfy conditions on nonexistent sub-paths.
- **Chain hash is never verified** (conf 6): computed, persisted, displayed — no verifier anywhere; log tampering is currently undetectable. Design gap, not exploit.
- **CLI loads unsigned state on a warning** (conf 6): unsigned blobs load with `state_sig_pending=false`; subsequent direct mutations operate on attacker-supplied state and `save` re-signs it with the operator's node key (after `key import`). Suggest gating mutations/save on provenance confirmation.
- **Scheduler submission change-event carries `node_id = NULL`** (conf 3): `scheduler.c:76-81` — the JSON `"node":""` never matches any per-node listener filter, so panels don't refresh on schedule submission. Failure sites were already fixed; submission was missed.
- **Scheduler idempotent-skip path ignores the occurrence budget** (conf 7, DoS-only): skipped slots (uuid already in log) neither fire nor count against the budget, so a sub-second series over a long replicated gap runs unbounded catch-up work per tick.
- **OT ordered-set (all latent — `crabs_ot_ordered_set_merge` has no production callers):** `apply_update` stamps no LWW so concurrent value updates permanently break future merges (conf 6); compaction and v6/v7 restore produce anchors that preflight rejects against non-compacted peers (conf 6); `apply_move` leaves the position map stale (conf 6); v8 deserializer accepts duplicate element ids (conf 6) and dangling/cyclic anchors (conf 5); `crdt_merge_state` type-confusion on crafted snapshots is dead code (conf 4); position-map BST is unvalidated (conf 5).
- **Change-event JSON drops events with non-UTF-8 bytes** (conf 5): the escaper passes bytes ≥ 0x80 raw; `JSON.parse` fails and the event is silently dropped (audit-visibility gap).
- **Trigger config `strtol`/`strtoull` lack `endptr`** (conf 4); **ECDSA high-S/low-S handling skipped on OOM** (conf 4); **time plausibility gate skipped when the local clock is invalid** (conf 4, chained preconditions); **`registerHandlerJs` returning `undefined` counts as success** (conf 5); **N-API `off()` closure can outlive the Node** (conf 6); **`node.adminId` reassignment orphans listeners** (conf 6); **unfiltered global drain steals other panels' ring events** (conf 3, footgun).

## Refuted (dropped)

- `op->node_id` spoofing for event misattribution — node_id is covered by the signature (`crabs_serialize_for_signing` field 13); same-page delivery semantics are by-design.
- `registerHandlerJs` exception escape corrupting WASM state — nothing heap-allocated is live at the dispatch site; helpers free before throwing.
- `__cancel_schedule__` submitter check — documented by-design (README: policy-gated, not submitter-bound).
- Trigger delete/disable/enable ownership — policy-gate trust model is by-design (`created_by` is informational).
- `crabs_wasm_sign_with_node_key` as a trust-boundary breach — same-origin script already controls the module; `getNodeKey()` ergonomics note only.
- Lock-expiry multiply overflow — `max_lock_duration_ms` (≤ 24h) and `max_lock_extensions` (≤ 1024) are clamped by audit M-B.
- Backward-clock trigger stall — self-heals when the clock recovers; self-DoS only.
- `state_get_time_ms` wrap — unreachable without an already-compromised time source.
- Envelope `attributes_hash` excluding temp attributes — deliberate per R8-A-8 comment.
- Chain-hash change breaking persisted states — nothing verifies hashes, so no upgrade false positives.

## Verified clean this round

Sig-scheme registry (no shadowing path; builtin always occupies a slot; unregistered schemes fail closed); dedup spec authorization (op-carried specs rejected); lock-token CSPRNG + `CRYPTO_memcmp`; ECIES envelope validation both directions; signed CLI blobs verify before parse; v7→v8 ordered-set reconstruction; change-event JSON buffer math and control-char escaping; devtools `layer` JSON field (enum-only, not injectable); **no XSS in crabs-devtools.js** (all event/snapshot strings render via `textContent`, `focusItem` uses `CSS.escape`); scheduler budget carry-over, mid-loop cancel re-finds, `scheduler_ticking` guard; `_merge_preflight` catches cycles/self-anchors/dangling anchors; `_materialize` emission is deterministic.

## Remediation status (2026-09-08, same day as the audit)

Fixed on `feature/devtools-state-inspector`:
- **A-1** snprintf clamp (`48b3b13`); **A-2/A-6** trigger re-find + `trigger_ticking` guard (`cd7b99a`)
- **A-3** triggers persisted (serialization v9), **A-5** `log_count` remaining-bytes bound, duplicate OT element ids rejected (`a0e5fd5`)
- **A-4** wire HLC validated (probe-copy strategy check at execute, `physical_nanos < 1e9` bound at op and log-entry deserialization; scheduled materialization exempt — embedded ops validated at submission) (`0d0e675`)
- Scheduler submission events now carry the node identity (`7fd80b9`)
- **Mode B** key-version gates enforced against the keyring-resolved signer (`605bdfd`)
- **Condition** multi-segment paths resolve fully (prefix fallback removed) (`e3b2580`)
- **CLI** save gated on `state accept-unverified` acknowledgment after unsigned loads (`77950d4`)

Deferred (tracked, not fixed — see the lower-confidence list): key-expiry config enforcement (feature-sized),
chain-hash verification (needs a version-aware recompute design), latent OT/CRDT merge-path items
(apply_update LWW stamping, compaction anchor scheme, position-map refresh, crdt_merge type guard) — fix before
the state-merge path gains production callers — and the minor JS polish items (off() lifetime, adminId
reassignment, global-drain footgun, undefined-handler success, non-UTF-8 event drops).