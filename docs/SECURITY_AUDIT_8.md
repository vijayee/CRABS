# CRABS Security & Correctness Audit — Round 8

**Date:** 2026-08-15
**Scope:** Full source tree (`src/`), WASM glue, and committed artifacts.
**Method:** Parallel deep-read of every subsystem by independent auditors, followed by manual spot-verification of the highest-severity findings against the code. The R7 fixes (R7-01..R7-18, R7-L-1..L-15) were re-verified for correctness and completeness.
**Baseline:** 1287 tests passing, 1 network test skipped.

**Relationship to prior audits:** Builds on `SECURITY_AUDIT_7.md` (R7-xx). This round found no CRITICAL issues. It found 5 HIGH, ~30 MEDIUM, and a number of LOW/INFO items. Several are **gaps in the R7 fixes** (R7-04 legacy-key bypass, R7-01 fail-open clock, R7-06/R7-07 revocation invariants) and several are **latent** (no current callers) but would cause data loss or divergence if the code paths are ever exercised.

---

## 1. HIGH

| ID | File:line | Finding |
|----|-----------|---------|
| R8-CL-1 | `condition.c:1208-1217` | **Pre-auth infinite-loop DoS.** `_resolve_user_id_placeholder` replaces `{user_id}` with `signer_id`. When `signer_id == "{user_id}"` (9 chars, equal to placeholder length), the `slen <= plen` branch is a no-op and `strstr` re-finds the placeholder forever. Reachable from `state_machine_execute` (state_machine.c:476) **before** signature verification, so an unauthenticated attacker can submit an op with `signer_id="{user_id}"` against any op type whose policy contains `{user_id}`, hanging the node. **Verified.** Fix: skip when `memcmp(pos, signer_id, slen)==0`, or bound iterations. |
| R8-A-1 | `attribute_machine.c:578-632` | **Privilege escalation in `verify_identity`.** Unlike `self_assert`/`issue_temporary`, it never calls `_is_privileged_attr_name`, so a caller can mint a verified `role:admin` (or `admin`, `owner`, …) attribute on any target. It also never checks that `signer_id` is an authorized verifier. **Verified** — no in-tree callers, so it is a public-API risk rather than wire-reachable, but the API is documented and exported. |
| R8-T-1 | `state_machine.c:252` | **HLC lock expiry uses the unauthenticated system clock.** `state_machine_lock_expired` calls `crabs_hlc_get_system_time(NULL)` (hlc.c:248, `platform_get_time`) when `ordering_system == HLC`, discarding the authenticated `now_ms` passed in. A browser attacker (WASM `Date.now()` is page-overridable) can freeze lock expiry. Reachable from `state_machine_prune_expired` and the lock-check/trigger paths. **Verified.** |
| R8-O-1 | `ot_ordered_set.c:305-320` | **Non-commutative merge.** `crabs_ot_ordered_set_merge` appends src-unique elements to dest's tail, so `merge(A,B)` and `merge(B,A)` yield different element orders → divergent replicas. **Latent** (no current callers), but it is the state-sync merge path. |
| R8-O-2 | `crdt_merge.c:524-529,641-644` | **`crdt_merge_state` breaks OT items.** It deep-copies `CRDT_CUSTOM` (OT) items via `crdt_merge_value`, which returns NULL for `CRDT_CUSTOM`; merged OT items get `value=NULL`/`ot_data=NULL`. **Latent** (no callers), but data loss if used. |

---

## 2. MEDIUM

### 2.1 State machine / protocol

| ID | File:line | Finding |
|----|-----------|---------|
| R8-S-1 | `state_machine.c:916-1024` | **Lock ownership is not enforced.** The Step-5 lock-claim check (state_machine.c:555-570) only verifies claims the op actually carries; an op with `lock_claim_count == 0` skips token/owner verification entirely, and the EXTEND/ROLLBACK/UNLOCK/FORCE_UNLOCK handlers (916, 958, 985, 1002) never check owner or token themselves. Any signer authorized for these op types can extend/roll back/release another user's resource. **Verified.** |
| R8-S-2 | `state_machine.c:1054-1127` | **CHANGE_CONFIG applies pairs incrementally.** A later failure (the `allow_force_unlock` ratchet at 1085, or `co_sign_threshold=0` at 1104) returns an error after earlier pairs were already applied, and the op is not logged. An authorized user can set `max_lock_duration_ms=1` then trigger a failure, permanently shortening all lock durations. |
| R8-S-3 | `state_machine.c:763-768` | **Dedup mutation runs after the handler/protocol transition have committed.** If `dedup_apply_mutation_spec` fails (e.g. one_shot_set full → OOM, or tracker missing), the op returns an error but the handler's effects and protocol-state change persist, and the op is neither logged nor committed — partial application. |
| R8-S-4 | `state_machine.c:330-331` | **`append_log` silently returns on realloc failure**, yet `state->version++` and the tx_manager commit still run. The audit chain gains a gap and the R7-11 lamport backstop loses the entry; a replay with a new UUID and the same lamport_time passes both the tx_manager and lamport checks. |
| R8-S-5 | `state_machine.c:799-801` | A time-source failure during trigger processing returns `CRYPTOGRAPHIC_ERROR` after the op was already applied, logged, and committed — the caller sees failure for a committed op. |
| R8-S-6 | `state_machine.c:763-768` | The dedup mutation applies to every op with a non-NONE `effective_dedup`, including CHECK_DEDUP, whose handler is read-only. A CHECK_DEDUP op carrying a dedup spec consumes the slot. |
| R8-S-7 | `state_machine.c:1084,1100,1109,1121,1124` | Boolean config values are parsed with `strcmp` on the full value including any subsequent `key=value` pairs, so `allow_force_unlock=true;max_lock_extensions=5` parses as false and trips the ratchet → UNAUTHORIZED. |
| R8-S-8 | `state_machine.c:860` | `state_machine_op_lock` writes `response->lock_tokens[i]` (array sized `CRABS_MAX_RESOURCES=8`) for `i < resource_count`. Not wire-reachable (deserializer bounds `resource_count`), but a programmatic caller can overflow the stack response buffer. |
| R8-S-9 | `state_machine.c:410-416` | **R7-01 fail-closed is weak.** `crabs_hlc_get_physical_time` falls back to the system clock for every time source (hlc.c:277-287), so the fail-closed path only triggers when the platform clock itself is unavailable; an attacker controlling the local clock still controls expiry. |
| R8-S-10 | `state_machine.c:539-543` | R7-11 is sound (lamport_time and signer_id are both signed) but per-signer and log-based: a signer can permanently DoS itself by submitting `lamport_time=UINT64_MAX`, and out-of-order ops from the same signer are rejected. |
| R8-S-11 | `state_machine.c:1454` | `refresh_key` bumps `user->key_version` before envelope creation/serialization; a failed refresh leaves the version advanced, invalidating ops signed with the old version. |
| R8-S-12 | `state_machine.c:1112-1116` | `max_key_age_ms`/`default_key_ttl_ms` are unbounded; an authorized CHANGE_CONFIG can set `max_key_age_ms=0` (all keys stale) or huge (expiry disabled). |
| R8-S-13 | `state_machine.c:763-768` | The registered dedup spec's mutation is not covered by the op's signature (only the op-carried dedup is signed); a DEFINE_OPERATION-authorized user can register a spec whose mutation runs on any authorized op of that type. |
| R8-S-14 | `state_machine.c:1523` | `state_machine_auto_compact` returns `uint32_t` but returns the negative `CRABS_ERR_CRYPTOGRAPHIC_ERROR`; the caller ignores the value (no functional impact). |

### 2.2 Crypto

| ID | File:line | Finding |
|----|-----------|---------|
| R8-C-1 | `crypto.c:42-46` | **`_ensure_oabe_init` race.** The atomic state conflates "initializing" and "ready": the CAS sets state to 1 *before* `oabe_init()` completes, so a concurrent thread that loses the CAS sees state==1 and proceeds to use OpenABE before it is initialized. |
| R8-C-2 | `crypto.c:1055,1083,1285-1288` | **R7-04 gap.** The v1 Mode A/B paths and the v2 Mode B legacy fallback verify against `user->public_key` directly, bypassing the keyring check in `_verify_user_signature` (crypto.c:1142-1149). A user with a keyring whose legacy `public_key` is compromised can still authorize via these paths; `user_key_register`/`user_key_rotate` never invalidate `user->public_key`. **Verified.** |
| R8-C-3 | `crypto.c:1793-1803` | **R7-06 gap.** `crypto_revoke_and_rotate` validates the new key up front but still mutates the user (suspend + overwrite `public_key`) *before* `crypto_key_envelope_create`. If envelope creation fails (OOM, ABE keygen failure), the user is left SUSPENDED with a new key and no envelope. |
| R8-C-4 | `crypto.c:1793` + `attribute_machine.c:675` | **Revocation is not terminal.** `attribute_machine_suspend_user` unconditionally sets `USER_SUSPENDED`, so `crypto_revoke_and_rotate` on a REVOKED user downgrades them to SUSPENDED, and R7-07 `activate_user` (which only requires status==SUSPENDED) can resurrect them. |
| R8-C-5 | `crypto.c:627-663` | R7-09 grammar has inconsistent precedence: infix parsing is right-associative, so `a AND b OR c` evaluates as `a AND (b OR c)` while `a OR b AND c` evaluates as `a OR (b AND c)`. The AND-then-OR case denies legitimate users rather than bypassing, but the grammar is ambiguous. |
| R8-C-6 | `crypto.c:1325-1328` | `crypto_verify_co_signature` returns `CRABS_ERR_USER_NOT_FOUND`/`CRABS_ERR_USER_SUSPENDED`, leaking user existence/status, unlike the R7-14 collapse in Mode A. |
| R8-C-7 | `crypto.c:185-227` | `_eckey_from_private` does not validate the private key is in [1, n-1]; a zero/out-of-range key yields a point-at-infinity public key silently. |
| R8-C-8 | `crypto.c:768-771` | In `crypto_abe_keygen`, if `oabe_context_cp_export_key` fails, the key remains in the authority keystore (unbounded leak). |
| R8-C-9 | `crypto.c:1677` | `crypto_key_envelope_deserialize` copies `user_id` as 64 raw bytes; if the source lacks a NUL, `env->user_id` is unterminated (any downstream `str*` over-reads). |

### 2.3 Serialization

| ID | File:line | Finding |
|----|-----------|---------|
| R8-SER-1 | `serialization.c:553-557` | In `_deserialize_ot_type_state` TREE case, if `_read_uint32_le(&bst_count)` fails or `_deserialize_bst_recursive` returns NULL, the `node` created at line 545 is neither linked nor freed — a heap leak reachable by a crafted blob. |
| R8-SER-2 | `serialization.c:534-536` | The duplicate-id check scans the whole pool for each node: O(n²). With `node_count` up to `CRABS_DESER_MAX_LOG` (1M), a ~15MB blob forces ~5×10¹¹ `strcmp` calls — a multi-minute CPU DoS. The SHA-256 checksum is not authentication, so this is reachable from untrusted input. |
| R8-SER-3 | `serialization.c:595-616,624-638` | The parent lookup and cycle-detection walks are also O(n²) over the pool, compounding the TREE deserialization DoS. |
| R8-SER-4 | `serialization.c:624` | Cycle detection is gated on `tree->root != NULL`. If `root_id` is non-empty but matches no node, `tree->root` stays NULL while the linking phase still creates parent links; a crafted blob with a parent cycle (A→B, B→A) passes deserialization and can hang downstream parent-chain walkers. |
| R8-SER-5 | `serialization.c:1973-2086` | The canonical signing form omits `co_signer_count`/`co_signers` (present in the wire format). An attacker can strip or alter co-signatures without invalidating the primary signature. |
| R8-SER-6 | `serialization.c:1191` | `_deserialize_log_entry` reads the ordering byte only if `buf->offset < buf->len`, but the serializer always writes it; a crafted blob omitting the byte reads it from the trailing SHA-256 hash bytes (format ambiguity, not practically exploitable). |
| R8-SER-7 | `serialization.c:974-975` | `msg_lens_arr = (uint16_t*)(msg_lens + inv_count)` is a misaligned `uint16_t*` (UB on strict-alignment platforms); the array is never read (dead code). |
| R8-SER-8 | `serialization.c:1768-1782,1801-1832,1897-1968` | `crabs_deserialize_ot_op`, `_ot_op_log`, and `_ot_data` do not require full buffer consumption (unlike `crabs_deserialize_operation`); trailing bytes are silently ignored. |
| R8-SER-9 | `serialization.c:711,718,736,743,755` | `_deserialize_crdt_value` counts (ec/tc/ac/rc2) are unbounded (only bounded by input size); the `or_set_add` dedup scan is O(n²) within the value blob. |
| R8-SER-10 | `serialization.c:250,269` | `_deserialize_ot_op` accepts arbitrary `op_type`/`transform_fn_id` without validation; semantic validation is deferred downstream. |
| R8-SER-11 | `serialization.c:1911` | `crabs_deserialize_ot_data` reads the blob's `ot_type_id` but never validates it matches the passed `ot_type_id` parameter. |
| R8-SER-12 | `serialization.c:1431 vs 1973-2086` | The wire-format version byte (1-4) is not covered by the canonical form; a v4 blob with `dedup.type=DEDUP_NONE` and LAMPORT ordering can be downgraded to v1 without invalidating the signature (semantically identical op, no practical impact). |

### 2.4 Time source / HLC

| ID | File:line | Finding |
|----|-----------|---------|
| R8-T-2 | `wasm_time_library.js:43-54` | The Node child-process script never checks `res.statusCode`; a 404/500 page body containing `ts=`/`unixtime` is parsed as valid time. R7-17 (2xx enforcement) is applied on the native and browser paths but not the Node path. |
| R8-T-3 | `time_source.c:122-123` | `(int64_t)fetched.seconds * 1000` is signed-overflow UB for seconds > ~9.2e15. The parser accepts 19-digit values, which wrap unpredictably; the wrapped value can land within `max_skew_ms` of local time, letting a compromised server push the anchor arbitrarily forward — the exact attack R7-18 was meant to block. Use saturating arithmetic. |
| R8-T-4 | `time_source.c:309` | `getaddrinfo()` is not bounded by `timeout_ms`. Since `_get_time` runs synchronously inside `state_machine_execute`, a blackholed DNS server blocks the entire authorization path indefinitely (availability DoS). |
| R8-H-1 | `hlc.c:277-287` | **Fail-open time source.** `crabs_hlc_get_physical_time` falls back to the unauthenticated system clock for every `time_source` value (including `HTTPS_AUTH`) when `time_source_ops` is NULL. A caller configuring `HTTPS_AUTH` without attaching ops silently gets the attacker-controlled clock. **Verified.** |
| R8-T-5 | `time_source.c:387` | The `ts=` anchor requires `p[-1] == '\n'`; a server emitting `\r\n` line endings never matches, so the trace format silently fails (fails closed, but brittle against the default Cloudflare endpoint). |
| R8-T-6 | `time_source.c:134-140` | The monotonicity check compares the fetched time to the last anchor, not the last returned time (anchor + elapsed); a fetched time between anchor and anchor+elapsed is accepted yet is a backward jump of up to `resync_interval_ms` (30s) from the caller's perspective. |
| R8-T-7 | `time_source.c:172` | `platform_strdup(url)` result is not NULL-checked; on OOM the time source silently never works (fails closed, but `_create` returns a plausible ops). |
| R8-T-8 | `wasm_time_library.js:31` | The synchronous XHR remains unbounded (the spec forbids `timeout` on sync requests); a hanging server freezes the page. R7-05's scheme check was applied, but the DoS was not addressed. |
| R8-H-2 | `hlc.c:313-320` | `crabs_hlc_next` falls back to `state->last` + counter when the time source is invalid; timestamps freeze at stale time. Combined with R8-T-1, locks acquired before an outage never expire while the source is down. |
| R8-H-3 | `hlc.c:443-455` | Step 3 of `crabs_hlc_receive` re-fetches local time without checking `local.valid`; a TOCTOU where the source goes invalid between Step 1 and Step 3 uses `local={0,0}` and the max rule advances the HLC to the received time. Only reachable in NAIVE mode. |
| R8-H-4 | `hlc.c:116` | `(time_t)hlc->physical_seconds` is implementation-defined for values > INT64_MAX; `gmtime_r` returns NULL for out-of-range so `crabs_hlc_format` fails closed. |

### 2.5 Attribute machine

| ID | File:line | Finding |
|----|-----------|---------|
| R8-A-2 | `attribute_machine.c:448-505` | `grant_role` stores `signer_id` in `verified_by` but never checks the signer holds admin status, so any caller can grant `role:admin` to anyone. Inconsistent with `activate_user` (R7-07), which does verify the signer. |
| R8-A-3 | `attribute_machine.c:247-254` | `_is_safe_attr_value` rejects only comma/space, allowing `|`. `_crabs_attrs_to_oabe` (crypto.c:86-97) preserves `|` as the OABE attribute separator, so a self-asserted value like `x|role_admin` injects `role_admin` as a separate attribute into the user's CP-ABE key, enabling decryption of content encrypted for attributes the user doesn't legitimately hold. |
| R8-A-4 | `attribute_machine.c:51-63` | `_is_safe_user_id` checks charset/keywords but not length; `register_user` truncates to 63 bytes. Two distinct long user_ids sharing a 63-byte prefix both pass the full-string uniqueness check but collide after truncation, creating shadowed/duplicate users. |
| R8-A-5 | `attribute_machine.c:693-723` | **R7-07 gap.** `activate_user` does not bump `key_version` and does not verify a key rotation occurred. The staleness check only rejects ops whose version differs from the current one; signatures made during suspension at that version remain valid after reactivation if the compromised key was not rotated. |
| R8-A-6 | `attribute_machine.c:1016-1019` | `user_key_revoke` unconditionally sets `USER_SUSPENDED` when the last active key is revoked, downgrading a `USER_REVOKED` user to the recoverable SUSPENDED state — violating the "revocation is terminal" invariant and making a revoked user reactivatable via `activate_user`. |
| R8-A-7 | `attribute_machine.c:260-314` | `attribute_machine_create` does not validate `admin_pk` with `crypto_ecdsa_validate_public_key` nor `admin_id` with `_is_safe_user_id`. An invalid bootstrap admin key defeats envelope confidentiality for the most privileged user. |
| R8-A-8 | `attribute_machine.c:872` | Temp-attribute expiry is fail-open when the clock is 0: `prune_expired_temporary` requires `expires_at <= now`, so with `now==0` nothing is pruned, and `_build_attr_string` includes expired temp attributes. Direct calls to `crypto_verify_operation_auth(_v2)` accept expired temp attributes. Inconsistent with R7-10's fail-closed key expiry. |
| R8-A-9 | `attribute_machine.c:787-857` | `issue_temporary` has no authorization check; any caller can mint temp attributes for any role group. Impact is limited (non-privileged, self-assertable), but it should be admin/trigger-gated. |
| R8-A-10 | `attribute_machine.c:198-201` | `_PRIVILEGED_ATTR_NAMES` is not exhaustive: `role_admin`, `administrator`, `superadmin`, `sysadmin`, `moderator`, `operator` are not blocked. Defense-in-depth only (CRABS-side matching is exact-token). |
| R8-A-11 | `attribute_machine.c:675-739` | `suspend_user`/`revoke_user` have no signer parameter or authorization check; any caller can suspend/revoke any user. Relies entirely on the caller. |
| R8-A-12 | `condition.c:1203-1231` | `_resolve_user_id_placeholder` infinite-loops if `signer_id` contains `{user_id}` (in-place replacement, `slen==plen`). Protected upstream by `_is_safe_user_id`, but `preprocess_policy` is a public API. (Same root cause as R8-CL-1.) |
| R8-A-13 | — | R7-10, R7-L-7, R7-08 are correctly implemented. No memory-safety issues found in user/attribute/key management. |

### 2.6 OT / CRDT / Compaction

| ID | File:line | Finding |
|----|-----------|---------|
| R8-O-3 | `ot_execution.c:232-243` | When the wire runs out mid-deps, `dep_count` is truncated and the op is still accepted. Dropped deps make `crabs_op_depends_on` miss causal predecessors, so the transform runs against causally-preceding ops → divergence. Fail-open. |
| R8-O-4 | `ot_ordered_set.c:175-176` | No-position-map insert: if `visible_pos-1` is beyond the list, `get()` returns NULL and `_insert_after(set,NULL,elem)` inserts at HEAD instead of appending. Reachable via a wire INSERT op. |
| R8-O-5 | `ot_document.c:196-199` | `insert_text` at a span boundary (offset==0) inserts AFTER the found span instead of BEFORE it; e.g. "ab"+"cd", insert at 2 → "abcdX" not "abXcd". |
| R8-O-6 | `ot_document.c:339-356` | `merge_spans` merges any two spans regardless of adjacency; a non-adjacent merge reorders text. |
| R8-O-7 | `ot_tree.c:165-247` | `insert_node` has no duplicate-id check (comment at :530 claims it is enforced); duplicate ids make `find()` ambiguous and merge attach to the wrong node. |
| R8-O-8 | `ot_tree.c:282-310,312-386,388-429` | delete_node/reparent/reorder never update the affected parents' `child_position_map` → stale maps, wrong `xi_inv` coordinates. |
| R8-O-9 | `ot_ordered_set.c:223-259` | `apply_move` ignores the position map and re-inserts relative to the raw list (deleted elements included), so the destination is wrong once tombstones exist. |
| R8-O-10 | `vector_clock.c:148` | QUORUM safety returns true when `peer_vc->count==0` ("no peers to wait for"); an empty peer VC bypasses the quorum gate (fail-open). |
| R8-O-11 | `vector_clock.c:160-168` | TIMESTAMP safety returns true whenever `state->version>0` (or interval==0), regardless of peer acknowledgment; the TIME_BASED default uses this, so concurrent remote ops can be compacted away. |
| R8-O-12 | `ot_document.c:149-164` | The document position-map path treats `pos` (a character index) as a span index via `xi_inv`, then walks spans; once a map exists (post-merge) inserts land at the wrong span. |
| R8-O-13 | `ot_execution.c:237` | R7-L-13 gap: `deps[d].node_id` is memcpy'd without NUL termination (only `id.node_id` is fixed). Currently only used with bounded `strncmp`, but any strcmp/strlen consumer would over-read. |
| R8-O-14 | `ot_transform.c:238` | swap_swap tie-break uses `>=` (not antisymmetric); converges for the symmetric two-op case but is fragile for multi-op logs. |
| R8-O-15 | `ot_document.c:310-315` | `apply_style` can loop forever on a zero-size span (`remaining -= 0`); currently unreachable (no zero-size spans are created). |
| R8-O-16 | `ot_execution.c:85-96` | `register_ot_type` caps `desired_cap` at 1048576, but `sizeof(op)≈1.4KB` → ~1.4GB realloc from config; DoS if config is attacker-influenced. |
| R8-O-17 | `ot_tree.c:549-559` | Cycle-break trail write `trail[tlen++]` can write `trail[cnt]` (one past a cnt-sized array) when `tlen==cnt`; unreachable because a cycle is always detected first, but fragile. |
| R8-O-18 | `ot_execution.c:465-550` | The same `ot_ops` are transformed in place per resource; `resource_count>1` double-transforms the op for the second resource. |
| R8-O-19 | `ot_execution.c:282` | The transform depth cap (64) stops mid-log; the op is applied with partial transforms → potential divergence (documented trade-off). |
| R8-O-20 | `ot_execution.c:505` | Only `visible_pos` is bounds-checked; `visible_pos_2` (MOVE/SWAP/DELETE_RANGE length) is not. |
| R8-O-21 | `compaction_engine.c:238-246` | The emergency threshold uses the registry tombstone count, which is 0 for OT types (no vtable), so emergency compaction never triggers for OT items. |
| R8-O-22 | `ot_execution.c:531-539` | The OOM branch leaves `log_entry->payload` dangling (double-free), but `get_memory()` aborts, so it is dead code; misleading. |

### 2.7 Condition / Trigger / CLI / WASM

| ID | File:line | Finding |
|----|-----------|---------|
| R8-CL-2 | `condition.c:211` | `atoll` on a >19-digit literal overflows to LLONG_MAX with no error. A policy `x < 999…9` becomes `x < LLONG_MAX` (always true); `x > 999…9` always false. Use `strtoll` with errno/range check. |
| R8-CL-3 | `condition.c:1174-1178` | Path-to-path comparisons in policies are fail-open. `_ast_to_string` emits `a > b`; the ABE evaluator parses `b` as a numeric literal (`atoll("b")=0`), so `a > b` grants whenever attribute `a > 0`, ignoring `b`. |
| R8-CL-4 | `condition.c:1151-1170` | BETWEEN and IN policies always deny: `_ast_to_string` emits `x BETWEEN a AND b` / `x IN (...)`, which the ABE evaluator rejects as trailing garbage. Fail-closed, but both features are broken in policies (they work only in trigger conditions via `condition_evaluate`). |
| R8-CL-5 | `condition.c:860-890` | `condition_resolve_path` returns 0 for missing items, so a trigger condition `x == 0` / `x <= 0` fires when item `x` is absent (fail-open). The ABE policy path is fail-closed here; only trigger conditions are affected. |
| R8-CL-6 | `condition.c:338-343` | A dotted path exceeding the buffer is silently truncated, so a long path can resolve to a different, shorter item. |
| R8-CL-7 | `condition.c:498-509` | BETWEEN with a path/string bound leaves the bound at 0 (only PRIMARY_NUMBER is stored), so `x BETWEEN 0 AND y` evaluates as `x <= 0`. |
| R8-CL-8 | `condition.c:885` | `*(int64_t*)reg->value` is an unaligned read that also reinterprets string register values as integers. |
| R8-TR-1 | `trigger.c:90-105` | ISSUE_ATTRIBUTE bypasses `grant_role` authorization: any user authorized to create a trigger can mint any non-privileged temporary attribute for holders of a target role. The privileged-name blocklist in `issue_temporary` blocks `role:admin` but not other policy-gating attributes. |
| R8-TR-2 | `trigger.c:107-133` | CHANGE_POLICY can rewrite any non-builtin op's policy. Guards block empty expressions and builtin ops, but a trigger creator can still set an arbitrary non-empty policy for a custom op without a signed policy-change op. |
| R8-TR-3 | `trigger.c:155-211` | `trigger_process_all` trusts caller-supplied `now_ms`; a value of 0 never satisfies `expires_at`, and a stale clock bypasses cooldown/one-shot logic. |
| R8-W-1 | `wasm_helpers.c:318-321` | `crabs_wasm_set_register` frees `reg->value` without NULLing it; on malloc failure the dangling pointer (with stale `value_size`) is returned and `get_register` reads freed memory. |
| R8-W-2 | `wasm_helpers.c:59-66` | `crabs_wasm_node_destroy` is a documented no-op (leak). |
| R8-CLI-1 | `cli.c:227-237` | `cli_node_load` loses the user registry (`users=NULL`) and ABE master key: the deserializer never sets `base_state.abe_mk`, and `node->abe_mk` is never assigned to it, so every op on a loaded node fails with CRYPTOGRAPHIC_ERROR. Fail-closed but the load/save round-trip is broken. |
| R8-CLI-2 | `cli.c:133,141` | `cli_node_init` creates two distinct ABE master keys (`node->abe_mk` and `base_state.abe_mk` from `attribute_machine_create`). `cli_cmd_key_revoke` issues keys under `node->abe_mk` while authorization verifies under `base_state.abe_mk`, so rotated keys never work. |
| R8-CLI-3 | `cli.c:903` | `cli_cmd_compact` passes `node->state`, which is never set (only `attr_machine` is), so compact always returns CRABS_ERR_INVALID_PARAM. |
| R8-CLI-4 | `cli.c:252` | `cli_node_load_key` takes the private key as a CLI argument, visible in `/proc/<pid>/cmdline`. |
| R8-DM-1 | `condition.c:742` | `condition_parse` caps paren nesting at 64 but not AND/OR chain length; a caller passing a multi-KB `a AND a AND …` string builds a left-deep tree whose `condition_node_destroy` recursion can overflow the stack. Not reachable via the audited capped paths. |

---

## 3. LOW / INFO

- **R8-C-9 (INFO)** — `crypto_key_envelope_deserialize` copies `user_id` as 64 raw bytes; unterminated if source lacks NUL.
- **R8-S-12 (INFO)** — `max_key_age_ms`/`default_key_ttl_ms` unbounded via CHANGE_CONFIG.
- **R8-S-13 (INFO)** — registered dedup spec's mutation not covered by the op signature.
- **R8-S-14 (INFO)** — `state_machine_auto_compact` returns negative error as uint32_t; caller ignores it.
- **R8-SER-6..SER-12 (LOW/INFO)** — see §2.3.
- **R8-H-4 (INFO)** — `(time_t)` cast implementation-defined for huge physical_seconds; `crabs_hlc_format` fails closed.
- **R8-O-13..O-22 (LOW/INFO)** — see §2.6.
- **R8-CL-6..CL-8, R8-TR-3, R8-W-1/W-2, R8-CLI-3/CLI-4, R8-DM-1 (LOW/INFO)** — see §2.7.

---

## 4. Verified Correct This Round

- **R7 fixes re-verified:** R7-01/R7-02 (fail-closed `_get_time` on fetch failure; `state_machine_execute` fails closed via `state_get_time_ms` — except the R8-T-1/R8-H-1 clock fallbacks), R7-03 (signed snapshots, verify-before-parse, low-S), R7-04 (key-version + scheme allowlist enforced unconditionally — except the R8-C-2 legacy-key bypass), R7-05 (JS https scheme check), R7-06 (validate-before-mutate — except R8-C-3), R7-07 (activate_user — except R8-A-5), R7-08 (privileged-attr rejection), R7-09 (prefix form parses correctly), R7-10 (fail-closed key expiry), R7-11 (signed lamport/signer, correct ordering), R7-12 (in-bounds str_space), R7-13 (guard-before/mutation-after), R7-14 (Mode A collapse), R7-15 (v4 wire fields), R7-16/17/18 (anchored ts=, 2xx, plausibility+monotonicity — except R8-T-2/T-3/T-6), R7-L-3 (eph_pub validation), R7-L-4 (accept after auth), R7-L-5/6/7/12/13/14/15.
- **Crypto primitives:** ECDSA low-S normalization on sign and verify is consistent; ECIES uses fresh ephemeral keys + random 12-byte IVs with a domain-separated KDF; no nonce reuse or constant-time issues found; `_build_attr_string` emits full `name:value` tokens.
- **CRDT merges:** g_counter, pn_counter, or_set, two_p_set, lww_register, one_shot_* are commutative/associative/idempotent. position_map BST insert/delete/xi/xi_inv are correct.
- **TxManager:** none/memory/avl_uuid are clean — correct AVL rotations, no leaks or double-frees, idempotent commit.
- **Allocator / platform / data_model:** clean; `state_destroy` cleanses `node_private_key`; `data_item_destroy` avoids OT double-free.

---

## 5. Recommended Remediation Order

1. **R8-CL-1** — pre-auth infinite-loop DoS. Fix `_resolve_user_id_placeholder` (skip when replacement equals placeholder, or bound iterations). Highest priority: unauthenticated, hangs the node.
2. **R8-S-1** — enforce lock ownership/token in EXTEND/ROLLBACK/UNLOCK/FORCE_UNLOCK (require a valid lock claim, or check owner in the handlers). Authorization alone is not enough to protect another user's lock.
3. **R8-T-1 + R8-H-1** — stop using the unauthenticated system clock for HLC lock expiry and for the `HTTPS_AUTH` fallback; fail closed when the configured source is unavailable.
4. **R8-C-2** — close the R7-04 legacy-key bypass: the v1 Mode A/B paths and v2 Mode B legacy fallback must reject a user with a keyring (route through `_verify_user_signature`).
5. **R8-A-1** — add `_is_privileged_attr_name` + signer-authorization checks to `verify_identity`.
6. **R8-C-4 / R8-A-6** — preserve the terminal-revocation invariant: `suspend_user`/`user_key_revoke` must not downgrade a REVOKED user to SUSPENDED.
7. **R8-S-2 / R8-S-3 / R8-S-4** — make CHANGE_CONFIG and dedup-mutation atomic; make `append_log` failure fail the op.
8. **R8-SER-1..SER-4** — bound the TREE deserializer (leak, O(n²) DoS, cycle-detection gap).
9. **R8-T-2 / R8-T-3 / R8-T-4** — Node 2xx check, saturating time arithmetic, bounded DNS.
10. Remaining MEDIUM/LOW items and the two carried-forward compaction fixes (R7-CF-1/CF-2).
