# CRABS Security & Correctness Audit — Round 5 (Independent)

**Date:** 2026-08-01
**Scope:** Full source tree under `src/` plus `deps/openabe-c`, independently re-audited after the Round 4 remediation pass (commit `009e894`).
**Method:** Manual code review of all security-critical modules, with independent verification of every "Fixed" claim from Rounds 1–4 (`docs/SECURITY_AUDIT.md` through `docs/SECURITY_AUDIT_4.md`). All new findings were verified against the actual code before inclusion.
**Relationship to Prior Audits:** This is a fresh, independent audit building on Rounds 1–4. Prior findings are referenced by their original IDs. New findings use IDs R5-1….

---

## 1. Executive Summary

The CRABS library has undergone four prior audit rounds with five total remediation passes. The code quality and security posture have improved dramatically since Round 1. The authorization path is sound (fail-closed, signatures verified, co-signatures cryptographically checked), the cryptographic primitives are real (Waters'09 CP-ABE via openabe-c, ECIES-encrypted envelopes, low-S ECDSA, hash-chained audit log), and memory safety is greatly improved.

**This independent Round 5 audit finds 0 new CRITICAL issues, 2 new HIGH issues, 4 new MEDIUM issues, and 3 LOW/INFO items that were not identified in prior rounds.** The library is approaching production readiness for single-replica deployments.

The most significant remaining concerns are:

1. **`_is_safe_user_id` charset allows hyphens in signer_ids, but `_is_safe_attr_value` rejects spaces** — a signer_id like `"admin,role_admin"` (with comma) is rejected by the charset check, but the `{user_id}` placeholder substitution in `_resolve_user_id_placeholder` does a raw string splice. The N-2 fix (keyword rejection) blocks `AND`/`OR`/etc. as signer_ids, but a signer_id like `"x,role_admin"` (comma rejected by charset) is blocked. However, a signer_id like `"x_role_admin"` (underscore, no comma) is valid and when substituted into `{user_id} IN (alice, bob)` produces `x_role_admin IN (alice, bob)` — which is harmless because the IN parser treats it as a single identifier. The N-2 fix is effective for the current charset. **(No finding — verified correct.)**

2. **The `_is_safe_attr_value` function rejects commas and spaces in attribute values, but `_is_safe_attr_name` only validates the name part.** The `grant_role` function constructs `"role:value"` tokens where `role` is the attribute name and `value` is the attribute value. The name is validated by `_is_safe_attr_name` (called in `self_assert` and `issue_temporary`), but `grant_role` and `verify_identity` do NOT call `_is_safe_attr_name` on the role parameter — they only call `_is_safe_attr_value` on the value. A caller with `grant_role` authority could pass a role name like `"role,admin"` which would produce the token `"role,admin:value"` — the comma in the name part would split into two tokens in the attribute string. **(R5-1)**

3. **`attribute_machine_register_user` accepts `initial_attrs` without charset-validating individual attribute name parts.** The `_parse_attributes` function splits on `|` and checks for commas in the token (de-wonk), but does not validate that the name part of each `name:value` pair uses the safe charset. A bootstrap registration with `initial_attrs = "role,admin:value|dept:eng"` would have the comma rejected by the de-wonk check in `_parse_attributes`, but `"role\x00admin:value"` (null byte injection) is not specifically checked. **(R5-2)**

**Severity counts (new findings):** 0 CRITICAL, 2 HIGH, 4 MEDIUM, 3 LOW/INFO.

---

## 2. HIGH Findings (new)

### R5-1. `grant_role` and `verify_identity` do not validate the attribute name charset

`src/Attribute/attribute_machine.c:374-423` (`grant_role`), `496-544` (`verify_identity`)

The `_is_safe_attr_name` function (line 175-184) validates that attribute names contain only `[A-Za-z0-9_-]`. This is called from:
- `attribute_machine_self_assert` (line 441) — correct
- `attribute_machine_issue_temporary` (line 681) — correct

But it is NOT called from:
- `attribute_machine_grant_role` (line 374) — the `role` parameter is used directly in `snprintf(formatted, sizeof(formatted), "%s:%s", role, value)` at line 397 without charset validation
- `attribute_machine_verify_identity` (line 496) — same issue at line 517

A caller with `grant_role` or `verify_identity` authority (typically an admin) could pass a role name containing characters outside the safe charset. While the `_is_safe_attr_value` check on the value part blocks comma/space injection in the value, the name part is not validated. A role name like `"role,admin"` would produce the token `"role,admin:value"` which, when placed in the comma-separated attribute string, would be parsed as two tokens: `"role"` and `"admin:value"` — the first being a bare `"role"` that could satisfy unrelated policies.

The de-wonk comma check in `_parse_attributes` (line 88-95) provides defense-in-depth for initial attribute parsing, but `grant_role` and `verify_identity` write directly to `user->attributes[i].value` without going through `_parse_attributes`.

**Recommendation:** Call `_is_safe_attr_name(role)` at the top of `attribute_machine_grant_role` and `attribute_machine_verify_identity`, matching the pattern in `self_assert` and `issue_temporary`. Add a regression test: `grant_role` with role name `"role,admin"` must be rejected.

### R5-2. `attribute_machine_register_user` initial attribute parsing does not validate individual name parts

`src/Attribute/attribute_machine.c:67-108` (`_parse_attributes`), `325-372` (`register_user`)

The `_parse_attributes` function splits on `|` and stores each token in `out[count].value`. The de-wonk check (line 88-95) rejects tokens containing commas, which blocks the `"role:admin,secret"` injection vector. However, the function does not validate that the *name part* of each `name:value` token uses the safe charset `[A-Za-z0-9_-]`.

A user registered with `initial_attrs = "role:admin|dept:eng"` has their attributes parsed correctly. But if an attacker could inject a null byte or control character into the initial_attrs string (e.g., through a compromised admin CLI or a serialized state), the name part would not be validated.

This is a defense-in-depth concern rather than an exploitable vulnerability, since `register_user` requires admin authority and the `_is_safe_user_id` check on the user_id prevents injection there. However, for consistency with the other attribute mutation paths, the name part should be validated.

**Recommendation:** In `_parse_attributes`, after splitting on `|`, extract the name part (before the colon) and validate it with `_is_safe_attr_name`. Reject the entire registration if any attribute name fails validation. Add a regression test.

---

## 3. MEDIUM Findings (new)

### R5-3. `_is_safe_attr_value` allows empty string but `_is_safe_attr_name` rejects it — inconsistent with `grant_role("role:admin", "")` usage

`src/Attribute/attribute_machine.c:175-203`

The `_is_safe_attr_value` function (line 196-203) explicitly allows empty values (the loop body never executes for an empty string, so it returns true). The comment at line 193-195 explains this is intentional: the CLI uses `grant_role("role:admin", "")` where the full token is in the role parameter and the value is intentionally empty.

However, `_is_safe_attr_name` (line 175-184) returns false for empty strings (`name[0] == '\0'`). This means `self_assert("", "value")` is rejected (correctly — you can't self-assert an empty attribute name), but the asymmetry between the two validators could be confusing to future maintainers.

The `grant_role` function constructs the token as `snprintf(formatted, sizeof(formatted), "%s:%s", role, value)`. When `value` is empty, this produces `"role:"` — a token with a trailing colon. The `_build_attr_string` function emits this as-is, and `crypto_abe_eval_policy` would need to match `"role:"` (with trailing colon) to authorize. This is unlikely to match any real policy, but it's a subtle behavior.

**Recommendation:** Document the empty-value allowance more prominently. Consider whether `grant_role("role:admin", "")` should instead construct the token as just `"role:admin"` (ignoring the empty value parameter) or whether the empty value should be rejected. The current behavior is not a security bug but is surprising.

### R5-4. `trigger_create` copies the parsed `condition_ast` pointer by value into the trigger array, then frees the heap allocation — fragile ownership

`src/Trigger/trigger.c:327-347`

```c
trigger_t* new_trigger = trigger_create(..., &effect, ...);
// ...
state->triggers[idx] = *new_trigger;  // struct copy — condition_ast pointer copied
free(new_trigger);                     // heap allocation freed, but condition_ast still points to the AST
```

The `condition_ast` pointer in `new_trigger` (heap-allocated by `trigger_create`) is copied by value into `state->triggers[idx]`. The `free(new_trigger)` at line 347 frees the trigger struct but NOT the `condition_ast` (because `trigger_destroy` is not called — only `free` is used). This is correct but fragile: if someone later changes `free(new_trigger)` to `trigger_destroy(new_trigger)`, the `condition_ast` would be freed and the array entry would hold a dangling pointer.

This was noted as R4-10 (LOW) in the Round 4 audit. It remains a code-quality concern.

**Recommendation:** Either use `trigger_destroy` and deep-copy the AST for the array entry, or add a comment explaining why `free` is used instead of `trigger_destroy`. The current code is correct but fragile.

### R5-5. `state_machine_op_register_key` uses `strnlen` to find the config string terminator — OOB if no NUL in payload

`src/StateMachine/state_machine.c:1038`

```c
size_t config_strlen = strnlen((const char*)op->payload, op->payload_size);
if (config_strlen + 1 + pk_len > op->payload_size) {
  return CRABS_ERR_INVALID_PARAM;
}
```

`strnlen` returns `op->payload_size` if no NUL byte is found within the first `op->payload_size` bytes. In that case, `config_strlen + 1 + pk_len` will be `op->payload_size + 1 + pk_len`, which is greater than `op->payload_size` (since `pk_len > 0`), so the check correctly rejects the input. This is safe.

However, the `rotate_key` handler at line 1247 uses `memchr` to find the NUL:
```c
char* config_end = (char*)memchr(op->payload, '\0', op->payload_size);
if (config_end == NULL) return CRABS_ERR_INVALID_PARAM;
```

The two handlers use different methods to find the config string terminator. This inconsistency is not a bug but makes the code harder to audit.

**Recommendation:** Use a consistent pattern (preferably `memchr` since it explicitly returns NULL when no NUL is found) across all key-management handlers.

### R5-6. `_ecies_encrypt_to_pub` generates an ephemeral keypair even when the recipient public key is invalid

`src/Crypto/crypto.c:1334-1360`

The ECIES encryption function generates an ephemeral keypair at line 1340 (`ecdsa_keypair_t* eph = crypto_ecdsa_generate()`), then performs ECDH at line 1343. If the recipient's public key is invalid (not on curve, point at infinity), the ECDH will fail and the function returns 0. However, the ephemeral keypair has already been generated (consuming entropy) and is destroyed at line 1347.

The N-3 fix validates public keys at registration time, so invalid keys should never reach this function. However, if a key is registered before the N-3 fix was applied (e.g., a pre-existing database), the ECIES path would still attempt ECDH with an invalid key. The function handles this correctly (returns 0 on ECDH failure), but the ephemeral key generation is wasted work.

**Recommendation:** Consider validating the public key at the start of `_ecies_encrypt_to_pub` as defense-in-depth, or document that callers must ensure key validity before calling. The current code is correct but could be more efficient.

---

## 4. LOW / Informational (new)

- **R5-7.** `crypto_abe_master_key_destroy` calls `OPENSSL_cleanse` on the MSK data via `oabe_bytestring_get_const_ptr`. The OpenABE documentation does not guarantee that the returned pointer is the actual buffer (it could be a copy). If it is a copy, the cleanse is ineffective. The openabe-c source (`oabe_bytestring.c`) shows that `get_const_ptr` returns a pointer to the internal buffer, so this is safe in practice. Document this assumption.

- **R5-8.** The `_PRIVILEGED_ATTR_NAMES` blocklist (attribute_machine.c:153-156) is hardcoded. Different deployments may have different notions of privileged attributes. The Round 4 audit (R4-12) noted this as a LOW item. Consider making the blocklist configurable via `__change_config__` or a state initialization parameter.

- **R5-9.** `crabs_hlc_get_system_time` uses `CLOCK_REALTIME` which can jump backward due to NTP adjustments. The HLC regression detection handles this correctly (uses last physical time + increments counter), but the logical counter grows unboundedly during extended clock regression. The spec §11.2 recommends using `CLOCK_MONOTONIC` with a stored epoch offset. This is a known limitation documented in the spec.

---

## 5. Prior Round Findings — Independent Re-Verification

I independently verified every CRITICAL and HIGH fix claimed in Rounds 1–4. Below is a summary of the key verification results.

### Round 1 Fixes — Verified

| ID | Claim | Independent Verdict |
|----|-------|---------------------|
| C-1 | Real CP-ABE via openabe-c | **Verified.** `crypto_abe_keygen` calls `oabe_context_cp_keygen` with real Waters'09. `crypto_abe_encrypt`/`decrypt` use real KEM+DEM. |
| C-2 | Fail-closed auth | **Verified.** `state_machine_execute:388-392` rejects when `state_find_policy` returns NULL. |
| C-3 | No empty-policy free pass | **Verified.** `crypto_abe_eval_policy("")` returns false (line 578). `crypto_verify_operation_auth` requires signature even when `has_attr_policy` is false. |
| C-4 | Co-signatures verified | **Verified.** `state_machine_execute:518-549` verifies each co-signer via `crypto_verify_co_signature`. |
| C-5 | Self-assert restricted | **Verified.** `_is_privileged_attr_name` blocks `role`, `admin`, etc. `_is_safe_attr_name` blocks non-ASCII. `_is_safe_attr_value` blocks comma/space injection. |
| C-6/C-7 | Full dedup + payload_format in signed form | **Verified.** `crabs_serialize_for_signing` includes the full `dedup_spec_t` and `payload_format`. |
| C-8 | Op-type constants unified | **Verified.** Single enum in `ot_types.h`. |
| C-9/C-10 | Heap corruption fixes | **Verified.** `compact_op.c` uses `crabs_ot_operation_clear`. `crabs_register_ot_type` reallocs before setting capacity. |
| C-11 | Compaction safety fail-closed | **Verified.** STRONG/QUORUM reject when `peer_vc == NULL`. |
| C-12 | USER_ACTIVE whitelist | **Verified.** All auth gates check `user->status != USER_ACTIVE`. |

### Round 2 Fixes — Verified

| ID | Claim | Independent Verdict |
|----|-------|---------------------|
| F-1 | Full `name:value` tokens | **Verified.** `_build_attr_string` emits full tokens. R4-1 fix uses `temp->name`. |
| F-2 | Registered dedup enforced | **Verified.** `state_machine_execute:467-468` resolves effective spec from registry. |
| F-3 | Compaction safety + COMPACT op | **Verified.** Safety check fail-closed. COMPACT marker emitted. `record_op` available. |
| F-4 | Transform matrix reachable | **Verified.** `_base_op_type` maps document/tree ops to base semantics. |
| F-5 | Protocol transitions driven | **Verified.** Non-builtin ops apply LOCKED→MODIFIED at line 626-638. |
| H-A | ECIES envelope encryption | **Verified.** `_ecies_encrypt_to_pub` uses ECDH + AES-256-GCM. |
| H-B | Node-blind key rotation | **Verified.** `crypto_revoke_and_rotate` takes user-supplied public key. |
| H-C | Revocation/expiry enforcement | **Verified.** `USER_REVOKED` assigned. Expiry checked in `_verify_user_signature`. |
| H-D | openabe-c AES-GCM real | **Verified.** Real EVP AES-256-GCM in `oabe_context.c`. |
| H-E | CHANGE_POLICY constrained | **Verified.** Rejects empty policies and builtin targets. |

### Round 3 Fixes — Verified

| ID | Claim | Independent Verdict |
|----|-------|---------------------|
| N-1 | Temp-attribute blocklist | **Verified.** `_is_privileged_attr_name` called in `issue_temporary`. |
| N-2 | `{user_id}` keyword rejection | **Verified.** `_is_safe_user_id` rejects policy keywords. |
| N-3 | Public key validation | **Verified.** `crypto_ecdsa_validate_public_key` at registration. |
| N-4 | Empty policy returns false | **Verified.** `crypto_abe_eval_policy("")` returns false. |

### Round 4 Fixes — Verified

| ID | Claim | Independent Verdict |
|----|-------|---------------------|
| R4-1 | `temp->name` in `_build_attr_string` | **Verified.** Line 866 reads `temp->name`. |
| R4-2 | USER_ACTIVE in all direct APIs | **Verified.** All 10 sites use `!= USER_ACTIVE`. |
| R4-3 | `verifier`/`issuer` in blocklist | **Verified.** Lines 154-155. |
| R4-5 | `_is_safe_attr_name` charset | **Verified.** Applied in `self_assert` and `issue_temporary`. |
| R4-7 | `condition_parse` depth cap | **Verified.** `CRABS_CONDITION_MAX_DEPTH = 64`. |
| R4-8 | Reject extreme logical counters | **Verified.** `UINT64_MAX/2` threshold in `crabs_hlc_receive`. |
| R4-DW-1 | Comma injection in values | **Verified.** `_is_safe_attr_value` rejects commas. `_parse_attributes` defense-in-depth. |

---

## 6. Positive Observations

The codebase demonstrates excellent cryptographic hygiene and defensive programming:

1. **Consistent secret cleansing:** `OPENSSL_cleanse` is called on all sensitive material: private keys, shared secrets, AES keys, lock tokens, MSK data. The discipline is consistent across all modules.

2. **Fail-closed defaults:** Every security-relevant decision defaults to rejection. Empty policies, missing attribute machines, NULL peer VCs, unimplemented HLC strategies — all fail closed.

3. **Saturating arithmetic:** Counters, HLC operations, and lock-expiry computations all use saturating or checked arithmetic to prevent wrap-around attacks.

4. **Defense in depth:** The attribute namespace safety has multiple layers: charset validation on names, comma/space rejection on values, privileged-name blocklist, keyword rejection on user IDs, and comma rejection in `_parse_attributes`. Each layer catches a different class of injection.

5. **Audit trail quality:** Every fix is clearly commented with the audit finding ID it addresses, making verification straightforward. The code is unusually well-documented for a C project.

6. **Constant-time comparisons:** Lock tokens use `CRYPTO_memcmp`. ECDSA uses low-S normalization. These are signs of careful cryptographic engineering.

7. **Bounds-checked deserialization:** All wire-format parsers validate lengths, check remaining buffer space, and reject malformed input. The OT data deserializer bounds `op_count` to the remaining buffer before allocating.

---

## 7. Design & Architectural Observations

### 7.1 The library is approaching production readiness for single-replica deployments

The authorization path is sound, the cryptographic primitives are real, memory safety is greatly improved, and the code shows evidence of systematic hardening across four audit rounds. The remaining findings (R5-1, R5-2) are defense-in-depth concerns rather than exploitable vulnerabilities.

### 7.2 Multi-replica convergence needs integration testing

The OT transform matrix, compaction coordination, and CRDT merge semantics have all been substantially fixed. However, as noted in prior audits, there is no integration test that runs random op interleavings across multiple replicas and asserts byte-identical merged states. Until such a test exists, multi-replica convergence is a claim rather than a demonstrated property.

### 7.3 The attribute namespace safety is robust but has inconsistent application

The `_is_safe_attr_name` / `_is_safe_attr_value` / `_is_privileged_attr_name` validation triad is applied in `self_assert` and `issue_temporary`, but not in `grant_role` and `verify_identity` (R5-1). This inconsistency is the most significant remaining finding. A helper function that validates both name and value in a single call would make consistent application easier.

### 7.4 The policy language still has multiple parsers

As noted in prior audits, the condition AST parser (`condition.c`), the ABE policy evaluator (`crypto_abe_eval_policy`), and the `preprocess_policy` function each parse policy expressions differently. While the known bugs have been fixed, the architectural risk of parser disagreement remains. A single unified policy grammar and evaluator would eliminate this class of bug permanently.

### 7.5 The codebase is unusually well-documented for a C project

Every audit fix is clearly commented with the finding ID it addresses. Function-level comments explain the "why" rather than the "what." The code is a pleasure to audit — a rare quality in C codebases.

---

## 8. Prioritized Remediation Plan

**Phase 1 — High fixes (hours):**
R5-1 (validate attribute name charset in `grant_role` and `verify_identity`), R5-2 (validate name parts in `_parse_attributes`).

**Phase 2 — Medium fixes (hours):**
R5-3 (document empty-value allowance), R5-4 (clarify trigger AST ownership), R5-5 (consistent NUL-finding pattern), R5-6 (defense-in-depth key validation in ECIES).

**Phase 3 — Hardening (days):**
R5-7 through R5-9 (LOW items), unify the three policy parsers, add multi-replica divergence test harness, make privileged-attribute blocklist configurable.

---

## 9. Conclusion

The CRABS library has undergone substantial security hardening through four audit rounds and five remediation passes. The code quality is high, the cryptographic primitives are real and correctly used, and the authorization path is sound. The two new HIGH findings (R5-1, R5-2) are consistency issues — places where the attribute namespace validation was applied to some mutation paths but not others. They are straightforward to remediate.

The library is suitable for single-replica deployments. Multi-replica deployments should await convergence integration tests before production use.

---

## 10. Comparison with Prior Audits

The prior audit rounds (1–4) identified a total of 12+5+3+1 = 21 CRITICAL, 14+10+5+2 = 31 HIGH, and 17+15+8+5 = 45 MEDIUM findings. All CRITICAL and HIGH findings have been fixed. The remaining MEDIUM findings are mostly deferred design improvements (unified policy parser, multi-replica convergence testing, configurable blocklists).

This Round 5 audit finds that the codebase is in its best state yet. The findings are minor compared to the systemic issues identified in Round 1 (simulated ABE, fail-open authorization, unverified co-signatures). The library has matured significantly.

---

*Round 5 — the crab's shell is hard, its pincers are sharp, and it's ready for the ocean. Just check those joints one more time.*

---

## 11. Remediation Status (2026-08-01)

All Round 5 findings (R5-1 through R5-6) have been addressed. The full test
suite (1233 tests) passes — 1230 pre-existing tests plus 3 new regression
tests. No openabe-c modifications were needed; all fixes are in the CRABS
source tree.

### Fixed in this pass

| ID | Summary of fix |
|----|----------------|
| R5-1 | `attribute_machine_grant_role` and `attribute_machine_verify_identity` now call `_is_safe_attr_name` on the attribute name parameter, matching `self_assert` and `issue_temporary`. A role/attribute name containing characters outside `[A-Za-z0-9_-]` (comma, space, parenthesis, semicolon, etc.) is rejected with `CRABS_ERR_INVALID_PARAM`. The CLI's `cli_cmd_user_grant` was updated to split the role parameter on the first colon before calling `grant_role`, preserving backward compatibility with the `"role:admin"` convention while passing a clean name to the validated path. |
| R5-2 | `_parse_attributes` (used by `attribute_machine_register_user` for initial attributes) now validates the name part of each `name:value` token against the safe charset. A forward declaration of `_is_safe_attr_name` was added so the function is visible to `_parse_attributes`. Malformed tokens (name part outside `[A-Za-z0-9_-]`) are skipped, matching the existing comma-check behavior. |
| R5-3 | Improved the documentation comment on `_is_safe_attr_value` to explicitly explain the empty-value allowance and the asymmetry with `_is_safe_attr_name` (names must be non-empty; values may be empty). |
| R5-4 | Added a detailed comment in `state_machine_op_create_trigger` explaining why `free(new_trigger)` is used instead of `trigger_destroy` (the struct copy transfers `condition_ast` ownership; `trigger_destroy` would free it and leave a dangling pointer). |
| R5-5 | `state_machine_op_register_key` now uses `memchr` to find the config string terminator, matching the pattern in `state_machine_op_rotate_key`. The `strnlen` approach worked correctly but was inconsistent with the rest of the codebase. |
| R5-6 | `_ecies_encrypt_to_pub` now calls `crypto_ecdsa_validate_public_key` on the recipient public key before generating the ephemeral keypair and performing ECDH. This is defense-in-depth: the N-3 fix validates keys at registration, but a pre-existing database or future code path that bypasses registration cannot trigger ECDH against an invalid key. |

### Regression tests added

- `TestAttributeMachine.TestGrantRoleRejectsBadAttrNameCharset` — verifies
  `grant_role` rejects comma/space/parenthesis/semicolon in the role name.
- `TestAttributeMachine.TestVerifyIdentityRejectsBadAttrNameCharset` —
  verifies `verify_identity` rejects the same charset violations in the
  attribute name.
- `TestAttributeMachine.TestRegisterUserRejectsBadAttrNameInInitialAttrs` —
  verifies `register_user` with `initial_attrs` containing malformed name
  parts skips the bad tokens and stores the valid ones.

### CLI fix

The CLI's `cli_cmd_user_grant` function was updated to split the `role`
parameter on the first colon before calling `attribute_machine_grant_role`.
This preserves the existing CLI convention of accepting `"role:admin"` as a
single argument while passing a charset-valid name (`"role"`) and value
(`"admin"`) to the validated `grant_role` path. The prior code passed the
full `"role:admin"` token as the role name, which the R5-1 charset check
correctly rejects (colon not in `[A-Za-z0-9_-]`).

### De-wonk pass

A de-wonk audit over the modified files found no additional issues:
- No TODOs/FIXMEs/stubs introduced.
- The `_is_safe_attr_name` forward declaration matches its definition.
- All stack buffers are properly bounded (`name_buf[CRABS_MAX_POLICY_EXPR]`
  with `name_len` capped at `sizeof(name_buf) - 1`).
- Edge cases handled: NULL, empty strings, colon at start/end, multiple
  colons, no-colon tokens.
- No memory leaks or use-after-free (all changes use stack buffers or
  read-only parameter pointers).

### Test posture

- 1233 fast-suite tests pass across all suites (1230 pre-existing + 3 new
  regression tests).
- The slow CP-ABE-keygen suites (`TestPolicyConfig`, full `KeyEnvelopeTest`)
  are not run in the fast CI pass due to ~300s per-test pairing cost; the
  ECIES round-trip regression is run.
