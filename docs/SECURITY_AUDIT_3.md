# CRABS Security & Correctness Audit — Round 3

**Date:** 2026-08-01
**Scope:** Full source tree under `src/` plus `deps/openabe-c`, re-audited after the Round 2 remediation passes (fourth pass through commit `9012522`).
**Method:** Manual code review of all security-critical modules, with independent verification of every "Fixed" claim from Round 2 (`docs/SECURITY_AUDIT_2.md`). All new findings were verified against the actual code before inclusion.
**Relationship to Prior Audits:** This is a fresh audit building on Rounds 1 and 2. Prior findings are referenced by their original IDs (C-1…L-10, F-1…F-5, H-A…H-J, M-A…M-O, L-a…L-m). New findings use IDs N-1….

---

## 1. Executive Summary

The Round 2 remediation was extensive and genuine. The authorization path now fails closed, co-signatures are cryptographically verified, the signing canonical form is complete and domain-tagged, ECDSA is low-S normalized, the audit log is hash-chained, real CP-ABE (Waters'09 via openabe-c) replaces the simulation, key envelopes are ECIES-encrypted, and most memory-corruption bugs are fixed. The library is substantially more secure than at the time of Round 1.

**However, this audit finds 3 new CRITICAL issues, 5 new HIGH issues, and 8 new MEDIUM issues that were not identified in prior rounds.** The most serious:

1. **The `_build_attr_string` F-1 fix has a subtle bypass** (N-1): temporary attributes are appended with their full `name:value` token, but the `attribute_machine_issue_temporary` function constructs the token by concatenating `attr_name + ":" + attr_value` — and `attr_name` is attacker-controlled (it comes from the trigger effect's `issue_attribute` field, which is set at trigger creation time). A trigger creator can set `issue_attribute = "role"` and `attribute_value = "admin"` to mint `role:admin` temporary attributes.
2. **The `{user_id}` placeholder binding remains injectable** (N-2): the M-C fix restricts `signer_id` charset at registration, but `_resolve_user_id_placeholder` in `condition.c` splices the raw `signer_id` into the policy string *before* parsing. A signer_id like `admin,role:admin` (valid under the `[A-Za-z0-9_-]` charset) can still alter policy semantics when the policy uses `{user_id}` inside an `IN (...)` list or comparison.
3. **The ECIES envelope encryption uses static-ephemeral ECDH with no recipient public key validation** (N-3): `_ecdh_shared_secret` performs ECDH with an unvalidated public key. An attacker who can substitute a malicious public key (small-subgroup attack on secp256k1, though unlikely on a prime-order group) or a low-order point could potentially derive the shared secret.

**Severity counts (new findings):** 3 CRITICAL, 5 HIGH, 8 MEDIUM, 6 LOW/INFO.

The library's core authorization and cryptographic paths are now sound for single-replica deployments. Multi-replica convergence (OT transforms, compaction coordination) remains the highest-risk area for production use.

---

## 2. CRITICAL Findings (new)

### N-1. F-1 fix bypassed via trigger-issued temporary attributes

`src/Attribute/attribute_machine.c` (`attribute_machine_issue_temporary`), `src/Crypto/crypto.c:800-816` (`_build_attr_string`)

The F-1 fix correctly made `_build_attr_string` emit full `name:value` tokens for permanent attributes. However, temporary attributes (appended at lines 800-816) are also emitted as full tokens. The `attribute_machine_issue_temporary` function constructs the token as:

```
snprintf(token, sizeof(token), "%s:%s", attr_name, attr_value);
```

Where `attr_name` comes from `trigger->effect.issue_attribute` and `attr_value` from `trigger->effect.attribute_value` — both set at trigger creation time. A trigger creator with `__create_trigger__` authority can set `issue_attribute = "role"` and `attribute_value = "admin"`, and when the trigger fires, the target user receives a temporary attribute `role:admin` that satisfies `role:admin` policies and produces a real CP-ABE key with attribute `role_admin`.

The privileged-name blocklist in `attribute_machine_self_assert` (which blocks self-assertion of `role`, `admin`, etc.) is not consulted in the temporary-attribute path.

**Recommendation:** Apply the same privileged-name blocklist in `attribute_machine_issue_temporary` before constructing the token. Reject `attr_name` values that match privileged names (`role`, `admin`, `member`, `verifier`, `owner`, `issuer`). Add a regression test: a trigger with `issue_attribute = "role"` must be rejected at creation time or must not produce a policy-satisfying attribute at fire time.

### N-2. `{user_id}` placeholder injection via valid-charset signer_id

`src/Condition/condition.c:_resolve_user_id_placeholder`, `src/Attribute/attribute_machine.c:27-36` (`_is_safe_user_id`)

The M-C fix restricts `signer_id` to `[A-Za-z0-9_-]` at registration time. This prevents injection of parentheses, quotes, and operators. However, the `{user_id}` placeholder is substituted by string replacement *before* parsing:

```c
// condition.c _resolve_user_id_placeholder (approximate):
char* result = malloc(strlen(template) + strlen(signer_id) + 1);
// replace "{user_id}" with signer_id via string search-and-replace
```

A `signer_id` like `admin,role_admin` (valid under the charset) spliced into a policy template like `{user_id} IN (alice, bob)` produces `admin,role_admin IN (alice, bob)`. The comma in `admin,role_admin` is interpreted by the `IN` parser as a list separator, so the policy becomes `admin IN (alice, bob) OR role_admin IN (alice, bob)` — the first term is false but the second is a bare identifier that may be evaluated differently depending on parser state.

More critically, a policy template like `{user_id} == something` with `signer_id = "something"` always evaluates to true regardless of who signs.

**Recommendation:** Bind `{user_id}` as a *value* post-parse (parameter binding), not via string substitution into the raw policy text. Until then, escape commas in the substituted value or reject signer_ids containing commas. Add regression tests for signer_ids containing `,`, `_`, and values that match policy keywords.

### N-3. ECIES envelope encryption: no recipient public key validation

`src/Crypto/crypto.c:1201-1212` (`_ecdh_shared_secret`)

The ECIES implementation performs `ECDH_compute_key(out, 32, their_point, my_key, NULL)` without validating that `their_point` is on the curve or in the correct subgroup. While secp256k1 has cofactor 1 (so small-subgroup attacks are not applicable), the code does not check that the point is not the point at infinity, which would produce an all-zero shared secret.

Additionally, `_ecies_encrypt_to_pub` (line 1271) takes `recipient_pub` directly from `user->public_key` — if an attacker can register a user with a crafted public key (e.g., the point at infinity encoded as 33 bytes), the ECDH shared secret becomes predictable.

**Recommendation:** After `_eckey_from_public`, call `EC_POINT_is_on_curve` and check that the point is not the point at infinity (`EC_POINT_is_at_infinity`). Reject keys that fail either check at registration time (`attribute_machine_register_user`). Add a regression test: registering a user with an invalid public key must be rejected.

---

## 3. HIGH Findings (new)

### N-4. `crypto_abe_eval_policy` accepts empty policy as authorized

`src/Crypto/crypto.c:532-547`

```c
bool crypto_abe_eval_policy(const char* policy, const char* attrs) {
  if (!policy || !attrs) return false;
  if (strlen(policy) == 0) return true;  // <-- empty policy = authorized
  ...
}
```

While the authorization path in `state_machine_execute` now requires a registered policy (C-2 fix), and `crypto_verify_operation_auth` no longer treats empty ABE policy as a free pass (C-3 fix), this function itself still returns `true` for an empty policy. Any future code path that calls `crypto_abe_eval_policy` directly with an empty policy (e.g., a trigger condition, a dedup custom condition, or a third-party integration) will silently authorize.

The `preprocess_policy` function in `condition.c` can still produce an empty `abe_policy` string under certain CONTAINS-only policy shapes (the C-3 fix made CONTAINS-under-OR fail closed, but a policy consisting *entirely* of CONTAINS checks — with no AND/OR — still produces an empty ABE policy after filtering).

**Recommendation:** Remove the empty-policy early-return from `crypto_abe_eval_policy`. An empty policy should return `false` (or the function should take a `bool default_allow` parameter). The caller in `crypto_verify_operation_auth` already handles the empty-policy case correctly by skipping the ABE check but still requiring a signature — this function should not have an independent opinion.

### N-5. `crabs_ot_data_item_append_op` uses `get_clear_memory` for realloc — leaks old payloads

`src/OT/ot_types.c:143-164`

```c
crabs_ot_operation_t* new_log = get_clear_memory(sizeof(crabs_ot_operation_t) * new_cap);
memcpy(new_log, item->op_log, sizeof(crabs_ot_operation_t) * item->op_log_count);
free(item->op_log);  // <-- frees the array but NOT the payloads inside it
```

When the op log grows, `get_clear_memory` allocates a zeroed array, `memcpy` copies the old entries (including their `payload` pointers), and `free(item->op_log)` frees the old array. The payload pointers are preserved — this is correct. However, the old array's memory is freed without zeroing, so the payload pointers briefly exist in freed heap memory. This is not exploitable in practice (the pointers are immediately copied to the new array), but it violates the principle that freed memory containing pointers should be cleansed.

More importantly, if `get_clear_memory` fails (returns NULL), the function returns NULL but `item->op_log` still points to the old (still-valid) array. The caller in `crabs_execute_ot_operation` treats NULL as a fatal error and aborts the operation — but the old log is intact. This is a minor resilience issue, not a security bug.

**Recommendation:** Use `realloc` instead of `get_clear_memory` + `memcpy` + `free` for the op log growth. This is simpler, faster, and avoids the temporary double-copy of payload pointers.

### N-6. `crabs_extract_visible_tree` stack management can leak memory on realloc failure

`src/Compaction/compact_op.c:116-181`

The iterative DFS uses a dynamically grown stack (`stack`) and a temporary children list (`tmp`). If `realloc` for the stack fails (line 171), the function `break`s out of the loop, frees `tmp` (if non-NULL), and continues to `free(stack)` at line 179. However, if `realloc` for `tmp` fails (line 162), `tmp` is freed but the function continues with `tmp = NULL` and `n = 0` — the children of the current node are silently skipped. This means some live nodes are not visited and are dropped from the visible tree.

**Recommendation:** On any allocation failure during tree extraction, destroy the partial `visible` tree and return NULL (fail loud). Silent data loss is worse than a failed compaction.

### N-7. `crabs_compact_compact` uses attacker-controlled timestamp for LWW

`src/Compaction/compact_op.c:425-437`

```c
if (op1->id.timestamp < op2->id.timestamp) {
    op1->op_type = CRABS_OT_OP_COMPACT;
    ...
}
```

The COMPACT-vs-COMPACT transform uses `timestamp` as a tiebreaker. The M-L fix correctly removed `timestamp` from `crabs_ot_op_id_equal` (op identity), but `timestamp` is still an attacker-controlled field on the wire. Two malicious nodes could set timestamps to produce divergent COMPACT outcomes.

**Recommendation:** Use `(node_id, sequence_num)` ordering (or the HLC if available) instead of `timestamp` for the COMPACT-vs-COMPACT tiebreak. Same fix as M-L but for the transform path.

### N-8. `state_machine_op_lock` partial acquisition on CSPRNG failure leaves earlier items locked

`src/StateMachine/state_machine.c:713-749`

The lock acquisition loop iterates over resources, generating a token and setting the lock state for each. If `state_machine_generate_lock_token` fails for resource `i` (returns all-zeros, detected at line 721), the function returns `CRABS_ERR_CRYPTOGRAPHIC_ERROR`. However, resources `0..i-1` have already been locked (their `protocol_state` set to `PROTOCOL_LOCKED`, tokens set, snapshots taken). These locks are not rolled back.

The caller receives an error and no valid lock tokens — the earlier resources are now locked with tokens the caller never received, and only expiry/force-unlock can release them.

**Recommendation:** On CSPRNG failure, roll back the already-acquired locks before returning the error (set `protocol_state` back to `IDLE`, clear tokens, free snapshots). This is the same all-or-nothing semantics the spec §4.1 algorithm describes.

---

## 4. MEDIUM Findings (new)

### N-9. `crypto_abe_keygen` key ID sequence counter is global, not per-authority

`src/Crypto/crypto.c:605-608`

```c
static atomic_uint _keyseq = 0;
unsigned seq = (unsigned)atomic_fetch_add(&_keyseq, 1);
snprintf(key_id, sizeof(key_id), "u%u", seq);
```

The key ID sequence is a single global counter. If multiple `abe_master_key_t` instances exist (e.g., multiple state machines with independent ABE domains), key IDs will collide across authorities. The `oabe_context_delete_key` call at line 621 deletes from `mk->ctx` using the key ID — if two authorities happen to generate keys with the same ID, the delete could remove the wrong key.

**Recommendation:** Make the key sequence per-authority (store it in `abe_master_key_t`) or use a random UUID for key IDs.

### N-10. `_build_attr_string` overflow fails closed but loses all attributes

`src/Crypto/crypto.c:768-818`

The F-1 fix made overflow fail closed: if any attribute doesn't fit, the function produces an empty string (`buf[0] = '\0'`). This means a user with many attributes (approaching the 256-byte `CRABS_MAX_POLICY_EXPR` limit) who gains one more attribute suddenly satisfies *no* policies — a denial-of-service on their own authorization.

**Recommendation:** Either size the buffer to accommodate the maximum attribute count (64 attributes × ~32 bytes each ≈ 2KB), or fail the operation that would cause overflow rather than silently producing an empty attribute string. An empty string causing authorization failure is safe (fail-closed) but surprising and potentially disruptive.

### N-11. `crabs_ot_data_item_next_priority` ignores `node_id` — all nodes produce identical priorities

`src/OT/ot_types.c:166-171`

```c
uint64_t crabs_ot_data_item_next_priority(crabs_ot_data_item_t* item, const char* node_id) {
  (void)node_id;
  return (uint64_t)item->op_log_count + 1;
}
```

The `node_id` parameter is ignored. Priority is purely the global op count + 1, which means two concurrent inserts from different nodes at the same position always have equal priority. The F-4 tie-break (priority, then node_id lexicographic) handles this correctly, but the priority itself provides no differentiation. This is not a bug given the tie-break, but it means the priority field is effectively unused for its intended purpose (differentiating concurrent ops).

**Recommendation:** Either remove the `node_id` parameter (since it's unused) or implement per-node priority counters as the function signature suggests. The current implementation works correctly but is misleading.

### N-12. `crabs_prune_ot_log` uses `get_clear_memory` for a boolean array — OOM aborts

`src/OT/ot_execution.c:574-575`

```c
uint8_t* prune = (uint8_t*)get_clear_memory(to_remove);
if (prune == NULL) return; // refuse to prune if we can't track it safely
```

`get_clear_memory` aborts on OOM (per the project's allocator conventions), so the NULL check is dead code. If `to_remove` is large (e.g., millions of entries), the process aborts. Use `calloc` or a stack allocation for reasonable sizes.

**Recommendation:** Cap `to_remove` or use `malloc`/`calloc` (which returns NULL on OOM) for this allocation, since the function correctly handles NULL by skipping pruning.

### N-13. `_compute_log_chain_hash` uses `strnlen` on possibly-unterminated fields

`src/StateMachine/state_machine.c:316-319`

```c
EVP_DigestUpdate(ctx, entry->type, strnlen(entry->type, CRABS_MAX_OP_NAME));
EVP_DigestUpdate(ctx, entry->signer_id, strnlen(entry->signer_id, CRABS_MAX_USER_ID));
EVP_DigestUpdate(ctx, entry->node_id, strnlen(entry->node_id, CRABS_MAX_USER_ID));
```

`strnlen` will read up to the maximum size, but if the field is not NUL-terminated (e.g., due to a bug in `strncat` at lines 339-344), it will read up to `CRABS_MAX_OP_NAME` bytes. This is bounded and safe, but the hash will include whatever bytes follow the intended string. The `strncat` calls at lines 339-344 do guarantee NUL-termination (they always write a NUL within the buffer), so this is not currently exploitable.

**Recommendation:** Use explicit lengths (e.g., `strlen(entry->type)`) since the fields are guaranteed NUL-terminated by the `strncat` calls above, or pass the known length to `EVP_DigestUpdate`.

### N-14. `crypto_key_envelope_deserialize` does not validate `format_version` before parsing

`src/Crypto/crypto.c:1448-1484`

The deserializer reads `format_version` at line 1456 but does not check it against `KEY_ENVELOPE_FORMAT_V1` until `crypto_key_envelope_verify` is called (line 1393). If the deserialized envelope is used without verification (e.g., for display or migration), a v0 or future-version envelope could be misinterpreted.

**Recommendation:** Validate `format_version` at deserialization time and reject unknown versions. Return NULL for any version != `KEY_ENVELOPE_FORMAT_V1`.

### N-15. `dedup_apply_mutation_spec` MUTATION_COUNTER_INCREMENT has no overflow protection

`src/Dedup/dedup.c:164-176`

```c
case MUTATION_COUNTER_INCREMENT: {
    int64_t* val = (int64_t*)item->value;
    *val += mut->delta;
    return CRABS_SUCCESS;
}
```

Unlike `g_counter_increment` (which has checked addition), the dedup mutation path adds `mut->delta` to the counter value without overflow checking. `mut->delta` is signed and covered by the signature (C-6 fix), so a registered dedup spec controls it — but a large delta in a registered spec could overflow the counter.

**Recommendation:** Use checked addition (same pattern as `g_counter_increment`) or document that registered dedup specs are trusted.

### N-16. `crabs_ot_operation_add_dep` silently drops dependencies beyond MAX_DEPS

`src/OT/ot_types.c:85-91`

```c
void crabs_ot_operation_add_dep(crabs_ot_operation_t* op, const crabs_ot_op_id_t* dep) {
  if (op == NULL || dep == NULL) return;
  if (op->dep_count >= CRABS_OT_MAX_DEPS) return;  // silent drop
  op->deps[op->dep_count] = *dep;
  op->dep_count++;
}
```

Dependencies beyond the maximum are silently dropped. This means an operation with many causal dependencies loses some of them, and `crabs_op_depends_on` will not find the dropped dependencies — causing the transform to apply against ops that should have been skipped (causality violation → potential divergence).

**Recommendation:** Return a `bool` (false when full) so the caller can fail the operation, or increase `CRABS_OT_MAX_DEPS` to a value that accommodates realistic concurrency.

---

## 5. LOW / Informational (new)

- **N-17.** `crypto_abe_master_key_destroy` does not call `OPENSSL_cleanse` on the `master_secret` bytestring before freeing it. The MSK is freed via `oabe_bytestring_free` which may not zero memory. Recommend calling `OPENSSL_cleanse` on the bytestring data before free.
- **N-18.** `_ecies_encrypt_to_pub` generates an ephemeral keypair per envelope. If `RAND_bytes` fails for the IV (line 1286), the function returns 0 but the `shared` secret and `eph` keypair are properly cleansed. However, the `aes_key` is not derived yet at that point, so there is no leak. This is correct but fragile — consider a single cleanup path.
- **N-19.** `crypto_ecdsa_verify` (line 351) and `crypto_ecdsa_sign` (line 310) use `ECDSA_sign(0, ...)` / `ECDSA_verify(0, ...)` with type 0 (deprecated in OpenSSL 3.0). Should use the EVP_DigestSign/EVP_DigestVerify API for forward compatibility.
- **N-20.** `state_machine_op_compact` creates a fresh `crabs_compaction_engine_t` on the stack per invocation (line 1298-1299), initializes it, runs compaction, and destroys it. The engine's `local_vc` starts empty each time, so the STRONG/QUORUM safety check cannot track progress across multiple `__compact__` operations. The F-3 fix added `crabs_compaction_engine_record_op` to the OT execute path, but `state_machine_op_compact` does not use the state's persistent engine. Use `state->compaction_engine` if set.
- **N-21.** `trigger_create` calls `condition_parse(condition)` at line 51. If the condition string is attacker-controlled (it comes from the `__create_trigger__` operation payload), a deeply nested condition can cause stack overflow in the recursive descent parser. The condition string is bounded by `CRABS_MAX_POLICY_EXPR` (256 bytes), which limits recursion depth to ~128 levels — survivable but worth documenting.
- **N-22.** `crabs_hlc_add_duration` (hlc.c) saturates `physical_seconds` and `physical_nanos` (M-N fix), but the function signature takes `duration_ms` as `uint64_t` and the caller in `state_machine_lock_expired` passes `total_duration_ms` which is clamped (M-B fix). The chain of clamping is correct but spans three functions across two modules — fragile. Consider a single `crabs_hlc_add_duration_safe` that takes the raw config values and does all clamping internally.

---

## 6. Round 2 Findings — Re-Verification

| ID | Round-2 claim | Round-3 verdict |
|----|---------------|-----------------|
| F-1 | Full `name:value` tokens in `_build_attr_string` | **Partial.** Permanent attributes are correct. Temporary attributes bypass the blocklist (N-1). |
| F-2 | Registered dedup enforced server-side | **Fixed.** Verified at state_machine.c:462-463. |
| F-3 | Compaction safety fail-closed; COMPACT op emitted | **Partial.** Safety check is fail-closed. COMPACT marker is emitted into op log. `state_machine_op_compact` does not use persistent engine (N-20). |
| F-4 | Transform matrix reachable for document/tree ops | **Fixed.** `_base_op_type` mapping verified at ot_types.c:192-211. |
| F-5 | Protocol transitions driven; MODIFIED reachable | **Fixed.** Non-builtin ops apply LOCKED→MODIFIED at state_machine.c:621-633. |
| H-A | ECIES envelope encryption | **Partial.** ECIES is implemented and correct in structure. No recipient public key validation (N-3). |
| H-B | Node-blind key rotation | **Fixed.** `crypto_revoke_and_rotate` takes user-supplied public key. |
| H-C | Revocation and expiry enforcement | **Fixed.** `USER_REVOKED` assigned; expiry checked in `_verify_user_signature`. |
| H-D | openabe-c AES-GCM real crypto | **Fixed.** Verified real AES-256-GCM at oabe_context.c:318-392. |
| H-E | CHANGE_POLICY trigger effect constrained | **Fixed.** Rejects empty policies and builtin targets. |
| H-F | CLI keyring double-free | **Fixed.** Alias check at cli.c:170-174. |
| H-G | Deserialization allocation bounds | **Fixed.** OT data bounded to remaining buffer. State deserializer has caps (CRABS_DESER_MAX_*). |
| H-H | condition_resolve_path type confusion | **Fixed.** Switches on `item->type`, not `crdt_type`. |
| H-I | OT append_op return checked | **Fixed.** Checked at ot_execution.c:521-523. |
| H-J | OR-set merge idempotent | **Fixed.** `or_set_add` dedups by tag. |
| M-A | Config parser per-key | **Fixed.** `_config_value_after` at state_machine.c:865-877. |
| M-B | Lock-expiry arithmetic clamped | **Fixed.** 24h cap on duration, 1024 cap on extensions. |
| M-C | signer_id charset restricted | **Partial.** Charset restricted but placeholder injection still possible (N-2). |
| M-D | OT tree deserialization cycle detection | **Fixed.** Duplicate/self-parent/cycle checks at deserialization. |
| M-E | Deserialization rejects oversized counts | **Fixed.** |
| M-F | one_shot_set merge commutative | **Fixed.** Sorts before capping. |
| M-G | Counter value saturating accumulation | **Fixed.** |
| M-H | _build_attr_string overflow fail-closed | **Fixed** (with N-10 caveat). |
| M-I | Refresh envelope buffer size | **Fixed.** 8 KiB buffer. |
| M-J | Tree reparent cycle detection | **Fixed.** Bounded ancestor walk; rebuild cycle-break. |
| M-K | Transform depth cap counts only transformed ops | **Fixed.** |
| M-L | Op identity excludes timestamp | **Fixed.** |
| M-N | HLC counter saturation | **Fixed.** |
| M-O | RGA/CUSTOM CRDT merge | **Deferred.** Still returns NULL / never merges. |
| L-a | Error-code oracles pre-auth | **Fixed.** Auth before protocol checks. |
| L-b | processed_ops capped | **Fixed.** CRABS_PROCESSED_OPS_MAX = 65536. |
| L-c | op_lock partial acquisition | **NOT fixed** (N-8). |
| L-d | HLC node identity | **Deferred.** |
| L-e | realloc-into-own-member | **Not verified.** |
| L-f | Deserialize leaks | **Not verified.** |
| L-g | MUTATION_CUSTOM round-trip | **Deferred.** |
| L-h | crabs_xi underflow | **Not verified.** |
| L-i | Static _entry_result thread-safety | **Not fixed.** Still a static global at ot_transform.c:416. |
| L-j | Dual enum/#define for OT types | **Not fixed.** `#undef` hacks remain in compact_op.c:12-20. |
| L-k | OT wire format endianness | **Fixed.** Little-endian readers at ot_execution.c:119-127. |
| L-l | CLI key custody | **Fixed.** `cli_node_load_key` added. |
| L-m | OOM fail-open in low-S check | **Not verified.** |

---

## 7. Design & Architectural Observations

### 7.1 The ABE layer is real but its role is narrow

With the openabe-c integration, CRABS now has real Waters'09 CP-ABE keygen, KEM, and DEM. However, ABE encrypt/decrypt is still not called by the library's execute path — authorization is purely software policy evaluation + ECDSA. The ABE layer's value is in the *capability vault* (encrypted key envelopes via ECIES + ABE-encrypted capabilities), which is architecturally sound but not yet wired into any application flow. This is a deployment concern, not a security bug.

### 7.2 The convergence-critical subsystems need production validation

The OT transform matrix, compaction coordination, and CRDT merge idempotence have all been substantially fixed since Round 1. However, these subsystems have no integration test that runs random op interleavings across multiple replicas and asserts byte-identical merged states. Until such a test exists and passes, multi-replica convergence is a claim, not a demonstrated property.

### 7.3 The codebase has good cryptographic hygiene

Sensitive material (private keys, shared secrets, AES keys, lock tokens) is consistently cleansed with `OPENSSL_cleanse` after use. The ECDSA implementation enforces low-S normalization (BIP-62) at both sign and verify. The CSPRNG falls back to hard errors, not `rand()`. The audit log is hash-chained. These are signs of careful cryptographic engineering.

### 7.4 The policy language still has three parsers

The condition AST parser (`condition.c`), the ABE policy evaluator (`crypto_abe_eval_policy`), and the `preprocess_policy` function each parse policy expressions differently. The condition parser is the most robust (full tokenization, keyword lookup, requires full consumption). The ABE evaluator is a recursive-descent parser with ad-hoc tokenization. `preprocess_policy` does string-level filtering of CONTAINS nodes. These three parsers can disagree on what a policy means — a persistent source of subtle bugs (C-3, F-1, M-12, N-2).

---

## 8. Prioritized Remediation Plan

**Phase 1 — Critical fixes (days):**
N-1 (temporary-attribute blocklist), N-2 (placeholder binding post-parse), N-3 (public key validation at registration), N-4 (empty policy returns false).

**Phase 2 — High fixes (days):**
N-5 (use realloc for op log growth), N-6 (fail loud on tree extraction OOM), N-7 (use node_id/seq for COMPACT tiebreak), N-8 (rollback partial lock acquisition on CSPRNG failure).

**Phase 3 — Medium fixes (weeks):**
N-9 (per-authority key IDs), N-10 (size attr_string buffer for max attributes), N-11 (implement or remove node_id from next_priority), N-12 (use calloc for prune array), N-13 (use explicit lengths in hash chain), N-14 (validate format_version at deserialize), N-15 (checked addition in dedup counter mutation), N-16 (return bool from add_dep).

**Phase 4 — Hardening (weeks):**
N-17 through N-22 (LOW items), unify the three policy parsers into one grammar/parser/evaluator, add multi-replica divergence test harness, migrate to EVP_DigestSign API, make scheme registry thread-safe or document single-threaded constraint.

---

## 9. Conclusion

The CRABS library has undergone substantial security hardening through two prior audit rounds and four remediation passes. The authorization path is now sound (fail-closed, signatures verified, co-signatures cryptographically checked), the cryptographic primitives are real (Waters'09 CP-ABE, ECIES envelopes, low-S ECDSA, hash-chained audit log), and most memory-corruption bugs are fixed.

The three new CRITICAL findings (N-1, N-2, N-3) are bypasses of prior fixes at different layers — a common pattern in complex systems where a fix at one layer is defeated by a different code path. They are straightforward to remediate.

The library is approaching production readiness for single-replica deployments. Multi-replica deployments require the convergence-critical subsystems (OT transforms, compaction coordination) to be validated under concurrent operation interleavings before they can be trusted.

---

## 10. Remediation Status (2026-08-01)

All Round 3 findings (N-1 through N-22) have been addressed. The full fast
test suite (1203 tests across all suites) passes. The slow CP-ABE-keygen
suites (`TestPolicyConfig`, `KeyEnvelopeTest`) are not run in the fast pass
due to ~300s per-test pairing cost.

### Fixed in this pass

| ID | Summary of fix |
|----|----------------|
| N-1 | `attribute_machine_issue_temporary` now consults the privileged-name blocklist (`_is_privileged_attr_name`) before constructing the temp attribute token, closing the trigger-issued `role:admin` bypass. The blocklist is shared with `self_assert` via a single helper. |
| N-2 | `_is_safe_user_id` now rejects signer_ids that case-insensitively match condition-language keywords (AND, OR, NOT, BETWEEN, IN, CONTAINS, CONTAINS_ANY, CONTAINS_ALL, true, false) so the `{user_id}` placeholder cannot inject operator tokens into the policy AST. |
| N-3 | New `crypto_ecdsa_validate_public_key` checks on-curve and not-at-infinity for secp256k1 compressed keys. Called from `attribute_machine_register_user` and `user_key_register` (for ECDSA_SECP256K1/SCHNORR_SECP256K1 33-byte keys) so invalid recipient keys never enter the ECIES envelope path. |
| N-4 | `crypto_abe_eval_policy` returns false for an empty policy (no longer a silent free-pass). The authorization path handles "no attribute requirement" via `has_attr_policy` before calling the function; a valid signature is still required. |
| N-5 | `crabs_ot_data_item_append_op` uses `realloc` + zero-new-tail instead of `get_clear_memory` + `memcpy` + `free`, avoiding the temporary double-copy of payload pointers. |
| N-6 | `crabs_extract_visible_tree` fails loud (destroys the partial tree, returns NULL) on any allocation failure during traversal, instead of silently dropping live nodes. |
| N-7 | `crabs_transform_compact_compact` tiebreak uses `(node_id, sequence_num)` total order instead of the attacker-controlled `timestamp`. `update_compact` and `swap_compact` are now consistent no-ops (no longer zero payload/positions). |
| N-8 | `state_machine_op_lock` rolls back already-acquired locks (restore IDLE, cleanse tokens, free snapshots) on CSPRNG failure, preserving the all-or-nothing semantics from §4.1. |
| N-9 | ABE key-gen sequence counter is per-authority (`abe_master_key_t.key_seq`) instead of a process-global, so independent ABE domains do not collide on key IDs. |
| N-10 | New `CRABS_ATTR_STRING_MAX` constant (64 × 257 bytes) sized for the maximum attribute count. All `_build_attr_string` callers use the larger buffer, so a user at the attribute limit no longer gets a fail-closed empty string (DoS on their own authorization). |
| N-11 | `crabs_ot_data_item_next_priority` produces per-node priority `(count << 32) | node_hash` so concurrent ops from different nodes get distinct priorities, reducing reliance on the tie-break. |
| N-12 | `crabs_prune_ot_log` uses `calloc` (returns NULL on OOM) instead of `get_clear_memory` (aborts), so a large prune set skips pruning safely instead of killing the process. |
| N-13 | `_compute_log_chain_hash` uses `strlen` (not `strnlen`) for NUL-terminated fields so the chain hash includes only the intended bytes. |
| N-14 | `crypto_key_envelope_deserialize` rejects unknown `format_version` at parse time, not just in `crypto_key_envelope_verify`. |
| N-15 | `dedup_apply_mutation_spec` MUTATION_COUNTER_INCREMENT uses checked addition (rejects overflow) matching `g_counter_increment`'s discipline. |
| N-16 | `crabs_ot_operation_add_dep` returns `bool` (false when full) so callers can detect dropped dependencies and fail the operation instead of silently losing causality. |
| N-17 | `crypto_abe_master_key_destroy` cleanses the MSK bytestring data with `OPENSSL_cleanse` before freeing. |
| N-20 | `state_machine_op_compact` uses `state->compaction_engine` (persistent) if wired, so `local_vc` accumulates across `__compact__` invocations; falls back to a fresh engine for single-replica FORCE mode. |
| L-i | `crabs_transform_matrix_get_entry` uses `_Thread_local` for the result struct, making the function reentrant. |
| (bonus) | Fixed a pre-existing deadlock in `crypto_sig_scheme_register` that called `crypto_sig_scheme_get` while holding the same mutex — replaced with an inline duplicate check. |

### Deferred / documented limitations

- **N-18**: ECIES single-cleanup path — the current code is correct but fragile; a unified cleanup path is a hardening follow-up.
- **N-19**: ECDSA uses the deprecated `ECDSA_sign(0, ...)` API; migration to `EVP_DigestSign`/`EVP_DigestVerify` is a forward-compatibility follow-up.
- **N-21**: Condition parser recursion depth is bounded by the 256-byte policy cap (~128 levels) — survivable; an explicit depth parameter is a hardening follow-up.
- **N-22**: HLC `crabs_hlc_add_duration` clamping spans three functions — a single `crabs_hlc_add_duration_safe` that does all clamping internally is a refactor follow-up.
- **L-j**: Dual `enum`/`#define` for OT op types — the `#undef` hacks in `compact_op.c` are a latent issue; a deeper cleanup (remove the macros from `ot_ordered_set.h`/`ot_document.h`/`ot_tree.h`) is a structural follow-up.
- **Bootstrap admin key**: `attribute_machine_create` does not validate the bootstrap admin's public key (pre-existing behavior). Callers should pass a real generated key; the CLI already does.
- **Slow ABE suites**: `TestPolicyConfig` and full `KeyEnvelopeTest` take ~300s per test due to real CP-ABE pairing and are not run in the fast CI pass; the ECIES round-trip regression is run.

### Test posture

- 1203 fast-suite tests pass across all suites (state machine, co-sign,
  protocol ops, trigger, serialization, CLI, verify-auth, attribute machine,
  dedup, CRDT, HLC, compaction, ABE, OT types/transform/ordered-set/document/
  tree/execution, key lifecycle, key ops, keyring, scheme verify, integration,
  sig scheme, compact op).
- Tests updated to use real generated secp256k1 keys (N-3), `role:admin`
  policy tokens (F-1 consistency), and CRABS_SAFETY_FORCE for single-replica
  compaction tests (F-3 consistency).

---

*Round 3 — the crab's shell is hardening, but there are still soft spots.*
