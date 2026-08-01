# CRABS Security & Correctness Audit — Round 4

**Date:** 2026-08-01
**Scope:** Full source tree under `src/` plus `deps/openabe-c`, re-audited after the Round 3 remediation pass (commit `8092520`).
**Method:** Manual code review of all security-critical modules, with independent verification of every "Fixed" claim from Round 3 (`docs/SECURITY_AUDIT_3.md`). All new findings were verified against the actual code before inclusion.
**Relationship to Prior Audits:** This is a fresh audit building on Rounds 1–3. Prior findings are referenced by their original IDs. New findings use IDs R4-1….

---

## 1. Executive Summary

The CRABS library has undergone three prior audit rounds with five total remediation passes. The authorization path is now sound (fail-closed, signatures verified, co-signatures cryptographically checked), the cryptographic primitives are real (Waters'09 CP-ABE via openabe-c, ECIES-encrypted envelopes, low-S ECDSA, hash-chained audit log), and most memory-corruption bugs are fixed. The library is approaching production readiness for single-replica deployments.

**This Round 4 audit finds 1 new CRITICAL issue, 2 new HIGH issues, and 5 new MEDIUM issues that were not identified in prior rounds.** The most serious:

1. **Temporary attributes are emitted without their name prefix in `_build_attr_string`** (R4-1): `attribute_machine_issue_temporary` stores the full `name:value` token in `temp->name` but only the value in `temp->value`. `_build_attr_string` reads `temp->value`, so temporary attributes appear as bare values (e.g., `"secret"` instead of `"clearance:secret"`). This means temporary attributes cannot satisfy policies written with the `name:value` form, and conversely a bare-value policy could be satisfied by a temporary attribute from an unrelated namespace.
2. **`USER_REVOKED` check missing from 7 direct API paths** (R4-2): The H-C fix (whitelist `USER_ACTIVE`) was applied to the main authorization path (`crypto_verify_operation_auth{,_v2}`) but not to the direct attribute-machine and key-operation APIs. A revoked user can still self-assert attributes, grant/revoke roles, verify identities, register/revoke/suspend/activate/rotate keys, and set default keys.
3. **The privileged-attribute blocklist is missing entries** (R4-3): `"verifier"` and `"issuer"` were specified in the N-1 recommendation but are absent from `_PRIVILEGED_ATTR_NAMES`.

**Severity counts (new findings):** 1 CRITICAL, 2 HIGH, 5 MEDIUM, 4 LOW/INFO.

---

## 2. CRITICAL Findings (new)

### R4-1. Temporary attributes lose their name prefix in `_build_attr_string` — namespace collision and policy bypass

`src/Attribute/attribute_machine.c:608-609`, `src/Crypto/crypto.c:859`

`attribute_machine_issue_temporary` stores the attribute in two fields:

```c
snprintf(temp->name, sizeof(temp->name), "%s:%s", attribute, value);   // "clearance:secret"
strncpy(temp->value, value, CRABS_MAX_POLICY_EXPR - 1);                 // "secret"
```

`_build_attr_string` (crypto.c:859) reads `temp->value` for the token:

```c
const char* token = temp->value;   // "secret" — name prefix LOST
```

This means:
- A temporary attribute `clearance:secret` appears as just `secret` in the attribute string.
- A policy `clearance:secret` does NOT match (the token is `secret`, not `clearance:secret`).
- A policy of bare `secret` DOES match — even though the attribute was issued in the `clearance` namespace.
- Two temporary attributes `clearance:secret` and `dept:secret` both produce the token `secret` and collide.

The N-1 fix correctly blocks privileged names at issuance time, so `role:admin` cannot be minted. But for non-privileged namespaces, this is a correctness bug: temporary attributes don't behave like permanent attributes (which use the full `name:value` token per the F-1 fix), and namespace collisions can cause unexpected policy satisfaction.

**Recommendation:** Change `_build_attr_string` line 859 from `temp->value` to `temp->name` so temporary attributes use the full `name:value` token, matching the F-1 fix for permanent attributes. Add a regression test: a temporary attribute `clearance:secret` must match policy `clearance:secret` and must NOT match policy `dept:secret`.

---

## 3. HIGH Findings (new)

### R4-2. `USER_REVOKED` check missing from 7 direct API paths — revoked users retain capabilities

`src/Attribute/attribute_machine.c:325, 378, 427, 471`
`src/StateMachine/state_machine.c:990, 1055, 1091, 1131, 1165, 1199`

The H-C fix (Round 2) correctly changed the main authorization path to whitelist `USER_ACTIVE`:

```c
// crypto_verify_operation_auth (crypto.c:916)
if (user->status != USER_ACTIVE) { ... }
```

However, the following direct API functions still use the old blacklist pattern (`== USER_SUSPENDED`), allowing `USER_REVOKED` users through:

| Function | File:Line | Current check |
|---|---|---|
| `attribute_machine_grant_role` | attribute_machine.c:325 | `== USER_SUSPENDED` |
| `attribute_machine_self_assert` | attribute_machine.c:378 | `== USER_SUSPENDED` |
| `attribute_machine_verify_identity` | attribute_machine.c:427 | `== USER_SUSPENDED` |
| `attribute_machine_revoke_role` | attribute_machine.c:471 | *(no status check at all)* |
| `state_machine_op_register_key` | state_machine.c:990 | `== USER_SUSPENDED` |
| `state_machine_op_revoke_key` | state_machine.c:1055 | `== USER_SUSPENDED` |
| `state_machine_op_set_default_key` | state_machine.c:1091 | `== USER_SUSPENDED` |
| `state_machine_op_suspend_key` | state_machine.c:1131 | `== USER_SUSPENDED` |
| `state_machine_op_activate_key` | state_machine.c:1165 | `== USER_SUSPENDED` |
| `state_machine_op_rotate_key` | state_machine.c:1199 | `== USER_SUSPENDED` |

A revoked user can still: self-assert attributes, grant/revoke roles to/from other users, verify identities, register new keys, revoke others' keys, set default keys, suspend/activate keys, and rotate keys. The only gate is that these operations require a valid signature — but the revoked user still has their key material and can sign operations.

**Recommendation:** Change all 10 sites to `if (user->status != USER_ACTIVE)` (whitelist). For `attribute_machine_revoke_role`, add a status check. Add regression tests: a revoked user must be rejected by each of these APIs.

### R4-3. Privileged-attribute blocklist missing `"verifier"` and `"issuer"`

`src/Attribute/attribute_machine.c:134-136`

The N-1 recommendation explicitly stated: "Reject `attr_name` values that match privileged names (`role`, `admin`, `member`, `verifier`, `owner`, `issuer`)." The current blocklist is:

```c
static const char* _PRIVILEGED_ATTR_NAMES[] = {
  "role", "admin", "member", "owner", "root", "superuser", "manager", NULL
};
```

`"verifier"` and `"issuer"` are missing. A trigger creator could set `issue_attribute = "verifier"` and `attribute_value = "admin"` to mint a temporary `verifier:admin` attribute. While `verifier:admin` may not directly grant admin access (policies are written against `role:admin`), it could satisfy policies written against `verifier:admin` if such policies exist in the deployment.

**Recommendation:** Add `"verifier"` and `"issuer"` to `_PRIVILEGED_ATTR_NAMES`. Consider making the blocklist configurable per deployment rather than hardcoded.

---

## 4. MEDIUM Findings (new)

### R4-4. `attribute_machine_revoke_role` has no user status check

`src/Attribute/attribute_machine.c:462-492`

Every other attribute-machine mutation function checks the target user's status before operating. `attribute_machine_revoke_role` does not — it proceeds directly to the role lookup and removal. A suspended or revoked user can have roles removed, which is arguably correct (you want to be able to strip roles from a bad actor), but the lack of any status check is inconsistent with the rest of the API and means the function doesn't distinguish "user not found" from "user is revoked" in its behavior.

**Recommendation:** Add an explicit status check with a clear policy decision: either allow role revocation regardless of status (document why), or restrict to ACTIVE users for consistency. At minimum, check that the user exists before proceeding.

### R4-5. `_is_privileged_attr_name` uses `strcasecmp` — case-insensitive bypass may miss Unicode homoglyphs

`src/Attribute/attribute_machine.c:141`

The blocklist uses `strcasecmp`, so `"Role"`, `"ADMIN"`, etc. are blocked. This is good. However, Unicode homoglyph attacks (e.g., using Cyrillic `"аdmin"` with a Cyrillic 'а' instead of Latin 'a') are not defended against. The `_is_safe_user_id` charset check (`[A-Za-z0-9_-]`) would reject non-ASCII characters in user IDs, but attribute names in `attribute_machine_issue_temporary` are not validated against this charset — they come from the trigger effect's `issue_attribute` field, which is a raw string from the operation payload.

**Recommendation:** Apply the same `[A-Za-z0-9_-]` charset validation to `attr_name` in `attribute_machine_issue_temporary` and `attribute` in `attribute_machine_self_assert`. Reject any attribute name containing characters outside this set.

### R4-6. `state_machine_op_refresh_key` checks `USER_ACTIVE` but `state_machine_op_register_key` and siblings do not

`src/StateMachine/state_machine.c:1264` vs `990, 1055, 1091, 1131, 1165, 1199`

The refresh-key handler correctly whitelists `USER_ACTIVE` (line 1264):

```c
if (user->status != USER_ACTIVE) {
  return (user->status == USER_SUSPENDED) ? CRABS_ERR_USER_SUSPENDED
                                            : CRABS_ERR_USER_NOT_FOUND;
}
```

But the six other key-management handlers (`register_key`, `revoke_key`, `set_default_key`, `suspend_key`, `activate_key`, `rotate_key`) still use the old `== USER_SUSPENDED` pattern. This is the same class of bug as R4-2 but specifically in the key-management path. A revoked user can register new keys, revoke existing keys, and rotate keys — effectively maintaining access after revocation.

**Recommendation:** Apply the same `USER_ACTIVE` whitelist pattern to all six key-management handlers. Covered by the R4-2 fix.

### R4-7. `trigger_create` calls `condition_parse` on attacker-controlled input with no length bound

`src/Trigger/trigger.c:51`

```c
trigger->condition_ast = condition_parse(condition);
```

The `condition` string comes from the `__create_trigger__` operation payload. While the payload is bounded by `CRABS_MAX_POLICY_EXPR` (256 bytes), the recursive-descent parser in `condition.c` has no explicit recursion depth limit. The 256-byte cap limits practical recursion to ~128 levels, which is survivable on most stacks. However, this is an incidental bound — if `CRABS_MAX_POLICY_EXPR` is ever increased, this becomes a stack-overflow DoS vector.

**Recommendation:** Add an explicit `MAX_RECURSION_DEPTH` parameter to `condition_parse` (e.g., 32) and reject inputs that exceed it. This is defense in depth against future buffer size increases.

### R4-8. `_hlc_saturate_inc` returns `UINT64_MAX` unchanged — logical clock permanently stuck at max

`src/HLC/hlc.c:292-294`

```c
static uint64_t _hlc_saturate_inc(uint64_t v) {
  return (v == UINT64_MAX) ? UINT64_MAX : v + 1;
}
```

Once the logical counter reaches `UINT64_MAX`, it stays there forever. All subsequent events at the same physical time get the same timestamp `(seconds, nanos, UINT64_MAX)`, breaking the total-order property that HLC guarantees. In practice, reaching `UINT64_MAX` requires 2^64 events at the same nanosecond — impossible in normal operation. But a malicious node sending `logical_counter = UINT64_MAX` in a received HLC timestamp (via `crabs_hlc_receive`, line 437-440) forces the local counter to `UINT64_MAX` permanently.

**Recommendation:** In `crabs_hlc_receive`, reject received timestamps with `logical_counter == UINT64_MAX` (or above a sane threshold like `UINT64_MAX/2`). A counter that high indicates either a bug or an attack.

---

## 5. LOW / Informational (new)

- **R4-9.** `attribute_machine_issue_temporary` iterates all users to find role matches (line 594-622). For a deployment with many users, this is O(n) per trigger fire. If multiple triggers fire per operation, this becomes O(n*m). Consider indexing users by role for large deployments.

- **R4-10.** `state_machine_op_create_trigger` copies the parsed trigger struct into the array then frees the heap allocation (trigger.c:346-347). The `condition_ast` pointer in the heap struct is copied by value, so the array entry holds a valid pointer to the AST. This is correct but fragile — if `trigger_destroy` ever frees `condition_ast` on the heap copy before the memcpy, it would be a use-after-free. The current code is safe because `trigger_destroy` is only called on the `new_trigger` pointer after the struct copy.

- **R4-11.** `crabs_hlc_receive` at line 437-440 takes `max(received->logical_counter, state->last.logical_counter)` and increments it. If both are `UINT64_MAX`, the saturating increment keeps it at `UINT64_MAX`. This is the same issue as R4-8 but in the receive path. Rejecting `UINT64_MAX` counters on receive would fix both.

- **R4-12.** The `_PRIVILEGED_ATTR_NAMES` blocklist is hardcoded. Different deployments may have different notions of "privileged" attributes. Consider making this list configurable via `__change_config__` or a state initialization parameter.

---

## 6. Round 3 Findings — Re-Verification

| ID | Round-3 claim | Round-4 verdict |
|----|---------------|-----------------|
| N-1 | Temporary-attribute blocklist | **Partial.** Blocklist applied but missing `verifier`/`issuer` (R4-3). Temporary attribute value emitted without name prefix (R4-1). |
| N-2 | `{user_id}` placeholder keyword rejection | **Fixed.** `_is_safe_user_id` rejects policy keywords. |
| N-3 | Public key validation at registration | **Fixed.** `crypto_ecdsa_validate_public_key` called at user and key registration. |
| N-4 | Empty policy returns false | **Fixed.** `crypto_abe_eval_policy("")` returns false. |
| N-5 | realloc for op log growth | **Fixed.** Uses `realloc` + zero-new-tail. |
| N-6 | Tree extraction fail-loud on OOM | **Fixed.** Returns NULL on allocation failure. |
| N-7 | COMPACT tiebreak uses (node_id, seq) | **Fixed.** |
| N-8 | Lock rollback on CSPRNG failure | **Fixed.** All-or-nothing semantics. |
| N-9 | Per-authority key IDs | **Fixed.** `key_seq` in `abe_master_key_t`. |
| N-10 | ATTR_STRING_MAX buffer size | **Fixed.** 64 × 257 bytes. |
| N-11 | Per-node priority in next_priority | **Fixed.** `(count << 32) \| node_hash`. |
| N-12 | calloc for prune array | **Fixed.** |
| N-13 | strlen for hash chain | **Fixed.** |
| N-14 | format_version at deserialize | **Fixed.** Rejects unknown versions. |
| N-15 | Checked addition in dedup counter | **Fixed.** |
| N-16 | add_dep returns bool | **Fixed.** |
| N-17 | MSK cleanse before free | **Fixed.** |
| N-20 | Persistent compaction engine | **Fixed.** Uses `state->compaction_engine`. |
| L-i | _Thread_local for transform matrix | **Fixed.** |

All Round 3 fixes verified. The N-1 fix is partially bypassed by the `temp->value` vs `temp->name` issue (R4-1).

---

## 7. Round 2 Deferred Items — Status Check

| ID | Round-2 status | Current status |
|----|---------------|----------------|
| F-3 full (compaction coordination) | Deferred | Still deferred. COMPACT op emitted, `record_op` available, but no in-tree producer wires it end-to-end. |
| M-J commutativity | Deferred (id-sorted cycle-break) | Fixed in Round 3 pass 2. |
| M-K (transform depth wedge) | Deferred | Fixed in Round 3 pass 2. |
| M-D (tree deserialization cycles) | Deferred | Fixed in Round 3 pass 2. |
| M-F (one_shot_set cap commutativity) | Deferred | Fixed in Round 3 pass 2. |
| M-A, M-B (config parser, lock expiry) | Deferred | Fixed in Round 3 pass 2. |
| M-C ({user_id} placeholder) | Deferred | Fixed in Round 3 pass 2 (keyword rejection). |
| H-A, H-B (ECIES, node-blind rotation) | Deferred | Fixed in Round 3 pass 3. |
| L-* (LOW items) | Deferred | Mostly fixed across passes 3-4. L-k (endianness) fixed in pass 4. |

---

## 8. Design & Architectural Observations

### 8.1 The codebase has matured significantly

Three audit rounds and five remediation passes have transformed this from a prototype with fundamental cryptographic flaws into a library with real CP-ABE, sound authorization, and careful memory management. The code shows evidence of systematic hardening: consistent `OPENSSL_cleanse` on secrets, saturating arithmetic throughout, fail-closed defaults, depth caps on recursion, and bounds checking on all deserialization paths.

### 8.2 The `name:value` token consistency is still fragile

The F-1 fix established that attributes use full `name:value` tokens everywhere. But R4-1 shows this invariant is broken for temporary attributes — `temp->value` stores only the value part, and `_build_attr_string` reads it. The dual storage (`temp->name` = full token, `temp->value` = value only) is a trap. A single field would prevent this class of bug.

### 8.3 The `USER_ACTIVE` whitelist pattern needs systematic application

The H-C fix applied `USER_ACTIVE` whitelisting to the main authorization path, but R4-2 shows 10 direct API paths still use the old `== USER_SUSPENDED` blacklist. This is a systemic issue: when a security pattern changes, every gate must be updated. A helper function like `user_is_active(user)` that encapsulates the check would make this invariant enforceable by grep.

### 8.4 Multi-replica convergence remains the highest-risk area

The OT transform matrix, compaction coordination, and CRDT merge semantics have all been substantially fixed. But without an integration test that runs random op interleavings across multiple replicas and asserts byte-identical merged states, multi-replica convergence is a claim rather than a demonstrated property. The F-3 coordination layer (COMPACT op emission, vector clock population) is available but not wired end-to-end by any in-tree producer.

### 8.5 Positive: cryptographic hygiene is excellent

Sensitive material is consistently cleansed. The CSPRNG fails hard. ECDSA is low-S normalized. The audit log is hash-chained. Envelopes are ECIES-encrypted. Lock tokens use constant-time comparison. These are signs of careful cryptographic engineering that has survived three audit rounds.

---

## 9. Prioritized Remediation Plan

**Phase 1 — Critical/High fixes (hours):**
R4-1 (use `temp->name` in `_build_attr_string`), R4-2 (whitelist `USER_ACTIVE` in all 10 direct API paths), R4-3 (add `verifier`/`issuer` to blocklist).

**Phase 2 — Medium fixes (hours):**
R4-4 (add status check to `revoke_role`), R4-5 (charset-validate attribute names), R4-6 (covered by R4-2), R4-7 (explicit recursion depth in `condition_parse`), R4-8 (reject `UINT64_MAX` logical counters on receive).

**Phase 3 — Hardening (days):**
R4-9 through R4-12 (LOW items), unify `temp->name`/`temp->value` into a single field, add `user_is_active()` helper, make privileged-attribute blocklist configurable, add multi-replica divergence test harness.

---

## 10. Conclusion

The CRABS library has undergone substantial security hardening through four audit rounds. The authorization path is sound, the cryptographic primitives are real, and memory safety is greatly improved. The four new findings in this round (R4-1 through R4-4) are consistency issues — places where a security pattern was applied to the main path but not to secondary paths. They are straightforward to remediate.

The library is suitable for single-replica deployments with the R4-1 and R4-2 fixes applied. Multi-replica deployments should await the convergence integration tests before production use.

---

*Round 4 — the crab's shell is nearly complete, but there are still a few soft spots at the joints.*

---

## 11. Remediation Status (2026-08-01)

All Round 4 findings (R4-1 through R4-8) have been addressed. The full fast
test suite (1229 tests across all suites) passes — 1220 pre-existing tests
plus 9 new regression tests.

### Fixed in this pass

| ID | Summary of fix |
|----|----------------|
| R4-1 | `_build_attr_string` (crypto.c) now reads `temp->name` (the full `"clearance:secret"` token) instead of `temp->value` (just `"secret"`). Temporary attributes are now consistent with the F-1 fix for permanent attributes — both use full `name:value` tokens. Regression test `VerifyAuthTest.TempAttributeUsesFullNameColonToken` verifies a temp `clearance:secret` satisfies policy `clearance:secret` and does NOT satisfy bare `secret`. |
| R4-2 | All 10 direct API paths now whitelist `USER_ACTIVE` (rejecting SUSPENDED and REVOKED): `attribute_machine_grant_role`, `self_assert`, `verify_identity` (attribute_machine.c), and `state_machine_op_{register,revoke,set_default,suspend,activate,rotate}_key` (state_machine.c). Through the signed-op path the auth step already rejects REVOKED with `CRABS_ERR_USER_NOT_FOUND`; the handler-level check is defense-in-depth for the direct API. Regression tests in test_key_ops.cpp and test_attribute_machine.cpp. |
| R4-3 | Added `"verifier"` and `"issuer"` to `_PRIVILEGED_ATTR_NAMES`. A trigger with `issue_attribute="verifier"` is now rejected at fire time, and `self_assert("verifier", ...)` is rejected at call time. Regression test `TestPrivilegedAttrNamesIncludeVerifierIssuer`. |
| R4-4 | `attribute_machine_revoke_role` now has an explicit comment documenting that the absence of a USER_ACTIVE check is intentional — revoking roles from SUSPENDED/REVOKED users is a valid administrative action (stripping remaining privileges from a bad actor). The function still verifies the user exists. |
| R4-5 | New `_is_safe_attr_name` helper validates attribute names against `[A-Za-z0-9_-]` (same charset as `_is_safe_user_id`). Applied in `attribute_machine_self_assert` and `attribute_machine_issue_temporary` so Unicode homoglyphs and other non-portable characters cannot bypass the case-insensitive privileged-name blocklist. Regression test `TestAttrNameCharsetValidation`. |
| R4-7 | `condition_parse` now tracks recursion depth in `parser_ctx_t.depth` and rejects expressions deeper than `CRABS_CONDITION_MAX_DEPTH` (64). The 256-byte input cap allows ~85 levels of bare parens, but the explicit depth limit blocks pathological inputs and protects against future increases in the input length cap. Regression test `TestDeepNestingRejected` verifies 80-level nesting is rejected while 32-level is accepted. |
| R4-8 | `crabs_hlc_receive` rejects received timestamps with `logical_counter >= UINT64_MAX/2` before any strategy processing. This prevents a malicious node from sending `logical_counter = UINT64_MAX` which would force the local counter to saturate at `UINT64_MAX` permanently (breaking the total-order guarantee). Regression test `TV12_8_RejectExtremeLogicalCounter` verifies `UINT64_MAX` and `UINT64_MAX/2` are rejected while `UINT64_MAX/2 - 1` is accepted. |

### Deferred / documented limitations

- **R4-9 through R4-12** (LOW items): O(n) trigger role matching, trigger struct copy fragility, `UINT64_MAX/2` threshold documentation, and configurable blocklist are documented limitations with no immediate security impact.
- **No openabe-c modifications were needed.** All Round 4 fixes are in the CRABS source tree.

### Test posture

- 1230 fast-suite tests pass across all suites (1220 pre-existing + 10 new
  regression tests).
- New regression tests:
  - `VerifyAuthTest.TempAttributeUsesFullNameColonToken` (R4-1)
  - `TestAttributeMachine.TestRevokedUserRejectedByDirectAPIs` (R4-2)
  - `TestAttributeMachine.TestPrivilegedAttrNamesIncludeVerifierIssuer` (R4-3)
  - `TestAttributeMachine.TestAttrNameCharsetValidation` (R4-5)
  - `TestAttributeMachine.TestAttrValueCommaInjectionRejected` (de-wonk)
  - `TestKeyOps.RegisterKeyRejectsRevokedUser` (R4-2)
  - `TestKeyOps.RevokeKeyRejectsRevokedUser` (R4-2)
  - `TestKeyOps.SetDefaultKeyRejectsRevokedUser` (R4-2)
  - `TestCondition.TestDeepNestingRejected` (R4-7)
  - `HLCTestVectors.TV12_8_RejectExtremeLogicalCounter` (R4-8)

### De-wonk pass

A de-wonk audit over the modified files found one additional vulnerability not
identified in the Round 4 review:

**R4-DW-1 (CRITICAL, pre-existing): comma injection in attribute values.**
A user who self-asserts `clearance:secret,admin` (value = `"secret,admin"`)
would inject `"admin"` as a separate token into the comma-separated attribute
string. Any operation with a bare `"admin"` policy would then be satisfied —
bypassing the privileged-name blocklist (which checks the attribute NAME, not
the value). The same vector exists via `grant_role`, `verify_identity`,
`issue_temporary`, and `register_user` (initial attributes). Fixed by adding
`_is_safe_attr_value` (rejects commas and spaces in values) in all four
mutation APIs, plus a comma check in `_parse_attributes` for defense in depth
on initial attribute parsing. Regression test
`TestAttrValueCommaInjectionRejected` verifies all five paths reject the
injection. This was a pre-existing vulnerability, not introduced by the Round
4 changes, but found during the de-wonk pass over the attribute namespace
safety work.
