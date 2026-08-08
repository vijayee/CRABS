# CRABS Security Audit Report

**Date:** 2026-08-07
**Scope:** Full codebase — cryptographic primitives, state machine authorization, key management, HLC, triggers, conditions, dedup, CRDTs, compaction, serialization
**Methodology:** Manual source code review of all `src/` modules

---

## Overall Assessment

The codebase demonstrates strong security awareness with multiple layers of defense-in-depth. Authorization is correctly ordered (verify before mutate), lock tokens use CSPRNG, the canonical signing format is deterministic, deserialization has appropriate bounds checks, and the attribute machine has robust input validation. No critical-severity vulnerabilities were found.

---

## Findings by Severity

### HIGH (4)

#### H-1: ECDSA_sign buffer size initialized to 0 instead of buffer capacity
**File:** `src/Crypto/crypto.c:376-378`
**Domain:** Cryptographic primitives

```c
unsigned char der_sig[128];
unsigned int der_sig_len = 0;  // BUG: should be sizeof(der_sig)
if (ECDSA_sign(0, digest, CRABS_HASH_SIZE, der_sig, &der_sig_len, eckey) != 1) {
```

The `siglen` parameter of `ECDSA_sign` is an in/out parameter. On input it must be set to the output buffer size. Initializing it to 0 tells OpenSSL the buffer is 0 bytes. In OpenSSL 1.1.x this happens to work because the internal `i2d_ECDSA_SIG` writes without checking the input length. In OpenSSL 3.x the behavior is less clearly defined. An ECDSA DER signature for secp256k1 is typically 70-72 bytes, so 128 bytes is safe, but the API contract violation is a latent risk.

**Fix:** Initialize `der_sig_len = sizeof(der_sig)`.

#### H-2: Missing key material cleanse in crypto_abe_user_key_destroy
**File:** `src/Crypto/crypto.c:701-706`
**Domain:** Cryptographic primitives

```c
void crypto_abe_user_key_destroy(abe_user_key_t* sk) {
  if (sk) {
    if (sk->key_bytes) oabe_bytestring_free(sk->key_bytes);  // no cleanse
    if (sk->public_params) oabe_bytestring_free(sk->public_params);
    free(sk);
  }
}
```

The ABE user secret key is freed via `oabe_bytestring_free` without first calling `OPENSSL_cleanse`. The codebase itself documents at line 637 that "oabe_bytestring_free does not zero the buffer." The master key destroy function (`crypto_abe_master_key_destroy`) correctly cleanses the master secret before freeing, but the user key destroy does not. An attacker with heap read access could recover user keys from freed allocations.

**Fix:** Call `OPENSSL_cleanse(sk->key_bytes->data, sk->key_bytes->size)` before `oabe_bytestring_free`.

#### H-3: 2P-Set compaction discards remove_set, allowing re-addition of removed elements
**File:** `src/Compaction/crdt_compaction.c:152-176`
**Domain:** CRDT correctness

The code explicitly warns (lines 173-174): "After compaction, previously removed elements CAN be re-added because the remove_set is discarded." This is a semantic violation of the 2P-Set CRDT. If a 2P-Set is used to track revoked permissions, compaction would allow re-granting previously revoked permissions.

**Fix:** Either document this as an irreversible compaction choice that callers must opt into, or preserve the remove_set in a compressed form.

#### H-4: PN-Counter compaction discards neg counter, allowing re-increment from zero
**File:** `src/Compaction/crdt_compaction.c:384-411`
**Domain:** CRDT correctness

Similarly warns (lines 408-409): "After compaction, neg counter is discarded. Previously decremented values can be re-incremented from zero." This breaks PN-Counter semantics. If counters are used for rate limiting or quota enforcement, compaction could allow bypassing limits.

**Fix:** Same approach as H-3 — require explicit opt-in or preserve the negative component.

---

### MEDIUM (16)

#### M-1: Integer overflow in envelope deserialization bounds check
**File:** `src/Crypto/crypto.c:1576`
**Domain:** Cryptographic primitives

```c
if (pos + sk_len + CRABS_SIG_SIZE > len) {
```

On 32-bit platforms, `pos + sk_len` could overflow if `sk_len` is near `UINT32_MAX`, bypassing the bounds check. On 64-bit platforms this is not exploitable.

**Fix:** Check each addition separately: `if (pos > len || sk_len > len - pos || CRABS_SIG_SIZE > len - pos - sk_len)`.

#### M-2: crypto_sig_scheme_init releases lock before registering built-in vtable
**File:** `src/Crypto/sig_scheme.c:210-216`
**Domain:** Thread safety

The function sets `_registry_initialized = true` and releases the mutex before calling `crypto_sig_scheme_register`. Another thread could see `_registry_initialized == true` and return before the ECDSA vtable is registered.

**Fix:** Register the vtable before setting the flag, or hold the lock through registration.

#### M-3: crypto_sig_scheme_list and crypto_sig_scheme_count lack mutex synchronization
**File:** `src/Crypto/sig_scheme.c:101-114`
**Domain:** Thread safety

Neither function acquires `_registry_lock`. A concurrent registration or cleanup could cause a data race. On WASM (single-threaded) this is harmless, but on POSIX/Windows it is undefined behavior.

**Fix:** Acquire `_registry_lock` in both functions.

#### M-4: Public operation handlers lack independent authorization checks
**File:** `src/StateMachine/state_machine.h:101-130`, `src/StateMachine/state_machine.c:756-955`
**Domain:** Authorization

All built-in operation handlers are declared as public functions and perform no internal authorization checks — they rely entirely on `state_machine_execute` having already verified the signature and policy. If any caller invokes these handlers directly, all authorization is skipped.

**Fix:** Either make handlers `static` (file-scope only) or add an authorization guard at the top of each handler.

#### M-5: Transition table has conflicting entries; ERROR entry is unreachable
**File:** `src/StateMachine/state_machine.c:38,45`
**Domain:** Protocol state machine

```c
{PROTOCOL_MODIFIED, CRABS_OP_VERIFY, PROTOCOL_VERIFIED},   // line 38
{PROTOCOL_MODIFIED, CRABS_OP_VERIFY, PROTOCOL_ERROR},      // line 45
```

Both entries map `(MODIFIED, __verify__)` to different next states. The lookup returns `true` on the first match (VERIFIED), so the ERROR entry is unreachable. However, `state_machine_op_verify` can set either VERIFIED or ERROR depending on invariant checks. The table is inconsistent with actual behavior.

**Fix:** Remove the unreachable ERROR entry or restructure the table to reflect that verify can produce two outcomes.

#### M-6: Key activation can auto-reactivate a suspended user
**File:** `src/Attribute/attribute_machine.c:1034-1049`
**Domain:** Key lifecycle

When a suspended key is activated, the code checks if the user has at least one active key and, if so, sets `user->status = USER_ACTIVE`. This means activating a key can automatically reactivate a suspended user. An admin with `__activate_key__` authority could inadvertently reactivate a user they intended to keep suspended.

**Fix:** Require an explicit administrative action to change user status from SUSPENDED to ACTIVE.

#### M-7: state_machine_op_change_config can disable force_unlock (permanent DoS)
**File:** `src/StateMachine/state_machine.c:1014-1016`
**Domain:** Configuration security

An attacker with `__change_config__` authorization can set `allow_force_unlock = false`, permanently preventing force-unlock. A resource stuck in LOCKED state could never be released without another `__change_config__` call.

**Fix:** Consider a time-bound or quorum-based restriction on disabling force_unlock.

#### M-8: state_machine_op_change_config can set co_sign_threshold to 0
**File:** `src/StateMachine/state_machine.c:1029-1033`
**Domain:** Configuration security

Setting `co_sign_threshold = 0` disables the co-signature requirement globally. An attacker with `__change_config__` authorization could remove co-signature enforcement.

**Fix:** Consider making co_sign_threshold only increasable, or requiring co-signatures to change it.

#### M-9: Trigger payload truncation could cause policy manipulation
**File:** `src/Trigger/trigger.c:257-260`
**Domain:** Trigger system

The payload is truncated to 4095 bytes. Critical fields like `policy_expression` could be truncated mid-value, causing the parser to interpret a truncated policy differently than intended. The `condition` field is truncated at 256 bytes during `strncpy`, but the original payload could have been up to 4095 bytes.

**Fix:** Reject payloads that exceed the expected field sizes rather than silently truncating.

#### M-10: atoi/atoll undefined behavior on overflow in trigger parsing
**File:** `src/Trigger/trigger.c:285-291`
**Domain:** Trigger system

```c
effect_type = (trigger_effect_type_e)atoi(value);
cooldown_ms = (uint64_t)atoll(value);
```

`atoi` and `atoll` have undefined behavior on overflow. The `effect_type` cast from `atoi` result to enum is particularly dangerous — an out-of-range value could produce an unexpected effect type.

**Fix:** Use `strtol`/`strtoull` with proper error checking (errno, endptr).

#### M-11: No restrictions on ISSUE_ATTRIBUTE trigger effect target/attribute
**File:** `src/Trigger/trigger.c:88-103`
**Domain:** Trigger system

The `ISSUE_ATTRIBUTE` effect has no validation of the attribute name, value, or target. A trigger could issue `"role:admin"` to any user. Security depends entirely on the authorization policy governing who can create triggers.

**Fix:** Apply the same privileged attribute name blocklist used in `attribute_machine_issue_temporary` and `attribute_machine_self_assert`.

#### M-12: Unsafe int64_t* cast for LWW_REG in condition_resolve_path
**File:** `src/Condition/condition.c:886-888`
**Domain:** Condition evaluator

```c
if (item->crdt_type == CRDT_LWW_REG || item->type == DATA_TYPE_REGISTER) {
    return *(int64_t*)item->value;
}
```

This reads 8 bytes from `item->value` regardless of the actual stored size. If the register stores fewer than 8 bytes, this reads out-of-bounds.

**Fix:** Check the register's value size before casting, or store registers with a known size field.

#### M-13: _ast_to_string potential buffer overflow via strncat underflow
**File:** `src/Condition/condition.c:1134-1184`
**Domain:** Condition parser

The function uses `strncat(buf, tmp, bufsize - strlen(buf) - 1)`. If `strlen(buf) >= bufsize`, the size calculation underflows to a huge value, and `strncat` writes past the buffer.

**Fix:** Check that `strlen(buf) < bufsize` before each `strncat` call.

#### M-14: TOCTOU between dedup guard check and mutation (documented)
**File:** `src/Dedup/dedup.c:33-38`
**Domain:** Dedup system

The code documents that `dedup_check_guard` and `dedup_apply_mutation` are two separate steps with a TOCTOU window. Currently benign because execution is single-threaded. If concurrency is ever introduced, two operations could both pass the guard before either applies the mutation.

**Fix:** Combine guard check and mutation into an atomic operation if concurrency is added.

#### M-15: Vector clock increment has no overflow protection
**File:** `src/Compaction/vector_clock.c:56-70`
**Domain:** Compaction

```c
vc->entries[i].sequence++;
```

If `sequence` reaches `UINT64_MAX`, incrementing wraps to 0, making the vector clock appear to regress. The HLC has saturating increment for its logical counter, but the vector clock does not.

**Fix:** Use saturating increment (cap at `UINT64_MAX`) consistent with HLC.

#### M-16: NTP/TPM time sources silently fall back to system clock
**File:** `src/HLC/hlc.c:277-287`
**Domain:** HLC

All non-system time sources fall back to `crabs_hlc_get_system_time(NULL)` with no indication to the caller. A deployment configured with `CRABS_TIME_SOURCE_TPM` expecting hardware-rooted time would silently get system clock time.

**Fix:** Either implement the time sources or return an error when an unimplemented source is configured.

---

### LOW (25)

#### L-1: No RAND_status() check before CSPRNG use
**File:** `src/Crypto/crypto.c:500`
On embedded systems or during early boot, the entropy pool may not be fully seeded. `RAND_bytes` will fail (return 0), and the code checks the return value, so this is not a silent failure. A `RAND_status()` check at startup would provide early warning.

#### L-2: Non-constant-time low-S normalization
**File:** `src/Crypto/crypto.c:120-138, 416-434`
The low-S normalization uses `BN_cmp`, which is not constant-time. Since signatures are public values, this is not a confidentiality concern, but it deviates from best practices.

#### L-3: ECIES KDF uses single SHA-256 instead of HKDF
**File:** `src/Crypto/crypto.c:1304-1319`
The ad-hoc KDF `SHA-256(shared_secret || eph_pub || label)` is not vulnerable to length-extension attacks (shared secret is fixed-length), but HKDF (RFC 5869) would be the standard choice.

#### L-4: AES-256-GCM encryption uses no AAD
**File:** `src/Crypto/crypto.c:1321-1337`
Without AAD, the ciphertext is not cryptographically bound to envelope context. The envelope signature prevents undetected tampering, so this is not exploitable, but AAD would be a stronger design.

#### L-5: WASM oabe_init has race condition
**File:** `src/Crypto/crypto.c:35-38`
The check-then-set on `_oabe_init_state` is not atomic. WASM is single-threaded by default, so not exploitable, but if compiled with `-pthread` and SharedArrayBuffer, two threads could both call `oabe_init()` concurrently.

#### L-6: WASM oabe_init retries forever on failure
**File:** `src/Crypto/crypto.c:35-38`
If `oabe_init()` fails in the WASM path, `_oabe_init_state` remains 0, and every subsequent call retries. The non-WASM path records the failure. Inconsistent behavior.

#### L-7: crypto_ecdsa_keypair_destroy does not cleanse public key
**File:** `src/Crypto/crypto.c:345-350`
Only the private key is cleansed. Public keys are not secret, so this is not a vulnerability, but cleansing the entire structure would be defense-in-depth.

#### L-8: crypto_revoke_and_rotate stores user-supplied public key without validation
**File:** `src/Crypto/crypto.c:1670`
No defense-in-depth validation of the new public key. The ECIES encryption path does validate before use, but the invalid key persists in the attribute machine.

#### L-9: ABE decrypt output buffer sizing heuristic
**File:** `src/Crypto/crypto.c:813`
The output buffer is sized as ciphertext length + 64 bytes. If OpenABE ever produces a larger plaintext, this would overflow.

#### L-10: Integer truncation in crypto_random_bytes
**File:** `src/Crypto/crypto.c:500`
`size_t len` is cast to `int`. On 32-bit platforms, requesting more than `INT_MAX` bytes would silently truncate. Callers request small buffers in practice.

#### L-11: state_machine_is_valid_transition is dead code for enforcement
**File:** `src/StateMachine/state_machine.c:97-107`
The function is declared in the header and implements the transition table, but is never called inside `state_machine_execute`. The actual enforcement compares `item->protocol_state != op->required_state[i]`.

#### L-12: {user_id} placeholder resolution uses raw string substitution
**File:** `src/Condition/condition.c:1188-1216`
The defense relies on `_is_safe_user_id` rejecting signer_ids containing policy delimiters at registration time. The substitution itself has no contextual escaping.

#### L-13: Lock expiry uses time(NULL) for wall-clock fallback
**File:** `src/StateMachine/state_machine.c:770`
System time can be manipulated via NTP adjustment or clock skew. HLC support mitigates this when configured, but the fallback path uses wall-clock time.

#### L-14: Log entry appended AFTER state mutation
**File:** `src/StateMachine/state_machine.c:728-735`
If the system crashes between state mutation and log append, the audit trail is missing an entry while state has been mutated.

#### L-15: Log chain hash uses strlen on attacker-controlled fields
**File:** `src/StateMachine/state_machine.c:322-325`
The hash computation uses `strlen(entry->type)`, `strlen(entry->signer_id)`, and `strlen(entry->node_id)`. These are guaranteed NUL-terminated by `strncat` in `append_log`, but the pattern is fragile.

#### L-16: Idempotency check happens before authorization
**File:** `src/StateMachine/state_machine.c:433-436`
A duplicate operation returns `CRABS_SUCCESS` without signature verification. This prevents replay attacks from consuming verification resources, but an unauthenticated observer can probe whether a specific UUID has been processed.

#### L-17: OOM during record_processed_op silently drops idempotency
**File:** `src/StateMachine/state_machine.c:282-295`
If `realloc` fails or the 65536-entry cap is reached, the operation UUID is not recorded, creating a replay risk.

#### L-18: user_key_rotate rollback does not restore default key
**File:** `src/Attribute/attribute_machine.c:1089-1120`
If `user_key_revoke` fails after registering the new key, the rollback removes the new key but does not restore the previous default key state.

#### L-19: user_key_find_active returns first key, not default
**File:** `src/Attribute/attribute_machine.c:850-858`
When no `key_id` is specified but a scheme is, the first active key for that scheme is returned, which may not be the user's intended default.

#### L-20: Key timestamps not set (registered_at, revoked_at, suspended_at)
**File:** `src/Attribute/attribute_machine.c:906,929,997`
Key lifecycle timestamps are left at 0 with a "Caller should set if needed" comment, but no caller sets them. Key age tracking is non-functional.

#### L-21: KEY_EXPIRED status never set
**File:** `src/Attribute/attribute_machine.h:51`
The `KEY_EXPIRED` status is defined but no code transitions a key to this state. Expiry is only checked at verification time, so expired keys still show as `KEY_ACTIVE`.

#### L-22: crabs_hlc_lock_expired mutates HLC state as a side effect
**File:** `src/HLC/hlc.c:188-197`
Calling `crabs_hlc_next(state)` to get the current time advances the HLC state. Frequent lock expiry checks would artificially inflate the logical counter.

#### L-23: HLC logical counter saturation causes total-order collapse
**File:** `src/HLC/hlc.c:297-299`
Once the logical counter saturates at `UINT64_MAX`, all subsequent events at the same physical time share the same timestamp. The receive path rejects remote saturation, but local saturation is theoretically possible.

#### L-24: CRDT merge OOM handling can resurrect tombstoned elements
**File:** `src/CRDT/crdt_merge.c:334-348`
If `realloc` fails during OR-Set tombstone collection, the code does `continue`, silently skipping that tombstone. Under memory pressure, deleted elements could reappear.

#### L-25: Deserialization allocates attacker-controlled size for payloads
**File:** `src/Serialization/serialization.c:177-190`
`_read_bytes32` allocates `len` bytes where `len` is a uint32 from the wire. The only bound is the remaining input buffer size. An attacker could cause large allocations.

---

## Positive Findings

The codebase demonstrates several strong security practices:

1. **Authorization ordering is correct** — signature/policy verification (Step 3) precedes all state mutation (Steps 7-14). An unauthenticated caller receives only `CRABS_ERR_UNAUTHORIZED`, preventing information leakage through distinct error codes.

2. **Low-S normalization (BIP-62)** — both signing and verification enforce low-S values, eliminating ECDSA signature malleability.

3. **Public key validation** — `crypto_ecdsa_validate_public_key` checks that keys are on the curve and not the point at infinity, preventing ECDH with invalid keys.

4. **Defense-in-depth ECIES** — the `_ecies_encrypt_to_pub` function re-validates the recipient public key even though it should have been validated at registration.

5. **Key material cleansing** — most sensitive key material paths use `OPENSSL_cleanse` before `free` (private keys, shared secrets, AES keys, plaintext ABE keys, master secrets). The notable exception is H-2.

6. **Lock tokens use CSPRNG** — `RAND_bytes` with proper error handling (zero-on-failure + rollback), explicitly documented to never fall back to `rand()`.

7. **Constant-time lock token comparison** — uses OpenSSL's `CRYPTO_memcmp`.

8. **Canonical signing format is deterministic** — domain-separation tag, length-prefixed strings, fixed field order, version byte. Separate from wire format.

9. **Deserialization has appropriate bounds** — `CRABS_DESER_MAX_ITEMS` (100k), `CRABS_DESER_MAX_POLICIES` (10k), `CRABS_DESER_MAX_LOG` (1M), BST depth limit (256), OT tree cycle detection.

10. **Hash-chained audit log** — each log entry chains to the previous via SHA-256, creating a tamper-evident sequence.

11. **Privileged attribute name blocklist** — prevents self-assertion and temporary-attribute issuance of admin/root/superuser role names, with charset validation preventing homoglyph attacks.

12. **Policy keyword blocklist for signer_ids** — prevents users named "AND", "OR", "CONTAINS", etc. from injecting policy structure via `{user_id}` substitution.

13. **Real CP-ABE** — uses OpenABE's Waters '09 CP-ABE with ABE-KEM+DEM (AES-256-GCM), not a simulated/derivable scheme.

14. **Node-blind key rotation** — `crypto_revoke_and_rotate` never generates or learns the user's new private key.

15. **Fail-closed defaults** — unimplemented HLC strategies reject all timestamps, oversized deserialization counts are rejected (not clamped), unknown envelope versions are rejected.

---

## Remediation Priority

| Priority | ID | Finding | File |
|----------|----|---------|------|
| 1 | H-1 | ECDSA_sign buffer size = 0 | `crypto.c:376` |
| 2 | H-2 | Missing key cleanse in user_key_destroy | `crypto.c:701` |
| 3 | H-3 | 2P-Set compaction discards remove_set | `crdt_compaction.c:152` |
| 4 | H-4 | PN-Counter compaction discards neg counter | `crdt_compaction.c:384` |
| 5 | M-1 | Integer overflow in deserialize bounds check | `crypto.c:1576` |
| 6 | M-2 | Init lock released before registration | `sig_scheme.c:214` |
| 7 | M-3 | list/count lack mutex synchronization | `sig_scheme.c:101` |
| 8 | M-4 | Public handlers lack independent auth | `state_machine.c:756` |
| 9 | M-9 | Trigger payload truncation | `trigger.c:257` |
| 10 | M-10 | atoi/atoll overflow in trigger parsing | `trigger.c:285` |
| 11 | M-11 | No restrictions on ISSUE_ATTRIBUTE effect | `trigger.c:88` |
| 12 | M-13 | _ast_to_string strncat underflow | `condition.c:1134` |
| 13 | M-15 | Vector clock increment overflow | `vector_clock.c:56` |
| 14 | M-16 | NTP/TPM time sources silently fall back | `hlc.c:277` |
