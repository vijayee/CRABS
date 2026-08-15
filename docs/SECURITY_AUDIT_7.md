# CRABS Cryptographic Security & Correctness Audit — Round 7

**Date:** 2026-08-15
**Scope:** Full source tree under `src/` plus `bindings/` and the WASM build glue (`deps/openabe-c` reviewed where it interfaces with CRABS). Focus: cryptographic primitives, authorization paths, untrusted-input handling, entropy, time security, and protocol correctness.
**Method:** Four parallel deep-review passes (signature/ABE, serialization/op-processing, RNG/time/WASM, prior-audit delta) against Rounds 1–6 and the 2026-08-07 audit. Every finding reproduced below was re-verified against the current code before inclusion.
**Relationship to Prior Audits:** Builds on `SECURITY_AUDIT.md` … `SECURITY_AUDIT_6.md` (IDs R6-x) and `security-audit-2026-08-07.md`. That 08-07 audit has no fix-status section; this round spot-verified its crypto findings and records which are closed. New findings use IDs R7-N.

---

## 1. Executive Summary

The core cryptographic constructions are in good shape: ECDSA over secp256k1 with BIP-62 low-S enforcement on **both** sign and verify, defense-in-depth public-key validation, a correctly constructed ECIES envelope (fresh ephemeral key + fresh IV per encryption, domain-separated KDF, GCM tag verified on decrypt), consistent key zeroization on destroy paths, fail-closed authorization ordering in `state_machine_execute`, and CSPRNG-only randomness on both native and WASM builds. Spot-checks confirm the two HIGH crypto findings of the 2026-08-07 audit (ECDSA_sign buffer size, ABE user-key cleanse) are fixed.

The dominant theme of this round is **time trust**: every security-relevant expiry decision (temporary attributes, key expiry, lock expiry, trigger cooldowns) is driven by the unauthenticated local wall clock — `time(NULL)` natively and `Date.now()` (page-controllable) in WASM — while the HTTPS time source that was built to anchor them is never wired in, and falls back to the local clock on any failure anyway. A browser attacker can therefore keep expired attributes, keys, and locks alive indefinitely.

The second theme is **key-lifecycle correctness gaps**: keyring rotation never invalidates the legacy bootstrap key, the §11.4 recovery path corrupts user state on failure, and two guard conditions (`signer_key_version > 0`, `sig_scheme != SCHEME_UNSPECIFIED`) are bypassable by an attacker crafting the op.

**Severity counts (new):** 2 CRITICAL, 3 HIGH, 13 MEDIUM, 15 LOW, 3 INFO. Two HIGH-severity items from the 08-07 audit (CRDT compaction semantics, R7-CF-1/CF-2) remain open and are carried forward.

---

## 2. CRITICAL

### R7-01. All security-relevant expiry decisions use the unauthenticated local wall clock; the HTTPS time source is never wired in

**Files:** `src/StateMachine/state_machine.c:409,418` (`time(NULL)` → `attribute_machine_set_time`), `src/HLC/hlc.c:34` (`time_source_ops = NULL`), `src/HLC/hlc.c:271-274` (the only consumer), `src/Crypto/crypto.c:1071,1087` (key expiry), `src/Attribute/attribute_machine.c:806-816` (temp-attribute pruning), `src/StateMachine/state_machine.c:723,742,749,840,917,1353,1428` (trigger/lock expiry)

`state_machine_execute` sets the attribute machine's clock from `(uint64_t)time(NULL) * 1000` immediately before authorization. That clock gates temporary-attribute pruning, keyring key expiry (`key->expires_at <= now_ms`), and lock/trigger expiry. The HTTPS time source built for exactly this purpose is dead code: `crabs_time_source_ops_t` is created only by `crabs_time_source_https_create*`, and nothing anywhere assigns it to `hlc_state.time_source_ops` — `hlc.c:34` initializes it NULL and no other write exists. `hlc.c:271-274` would honor it, but is never reached with a non-NULL vtable.

In the WASM build, Emscripten implements `time()` as `Date.now()`, which any script in the page can override.

**Exploit scenario:** A browser client whose temporary attribute (e.g. a 5-minute `clearance:secret` grant) has expired overrides `Date` to a past epoch before loading the module. Every `state_machine_execute` then prunes nothing, the stale attribute keeps satisfying policies, and the user can mint ABE decrypt keys for data they should no longer read. The same trick freezes lock expiry and keyring expiry.

**Fix:** Wire the time source end-to-end: assign `state->hlc_state.time_source_ops` at node creation, and in `state_machine_execute` replace `time(NULL)` with `crabs_hlc_get_physical_time(&state->hlc_state)`, treating "no authenticated time" as fail-closed for expiry decisions. Until then, document that expiry semantics are only as trustworthy as the host clock.

### R7-02. Time source fails open to the local clock on any fetch failure

**File:** `src/TimeSource/time_source.c:109-124` (also `:91-93`)

```c
log_warn("time source unreachable; using system clock");
return crabs_hlc_get_system_time(NULL);
```

Any DNS/TLS/timeout/parse failure silently degrades to the local wall clock — the same attacker-controlled clock the time source exists to distrust. The unit test `FailedFetchFallsBackToSystemClock` (`test/test_time_source.cpp:103-122`) explicitly blesses this, and `_is_available` is never consulted by any caller. Even after R7-01 is fixed, an attacker who merely blocks the time server (or keeps the page offline) falls through to the local clock.

**Fix:** On failure return `valid = false` and make security callers fail closed; never substitute the unauthenticated local clock for authenticated time in expiry decisions.

---

## 3. HIGH

### R7-03. State snapshot is integrity-checked but not authenticated — snapshot load trusts the file completely (carried forward: 08-07 M-1 lineage)

**Files:** `src/Serialization/serialization.c:1246-1281` (`crabs_serialize_state` appends a bare SHA-256; deserialize verifies only that), `src/Serialization/serialization.c:1092` (Vault auth token serialized in plaintext), `src/CLI/cli.c:221` (`cli_node_load`)

The appended SHA-256 is an unkeyed corruption check; the code comment itself admits it. An attacker who can write the state file — or a malicious peer if snapshots are ever used for resync — can recompute the hash over a crafted blob, yielding arbitrary data items, policies, config, and log entries on load, plus plaintext recovery of the Vault auth token embedded in the blob. The attribute machine is rebuilt empty on load (cli.c:233-236), so this cannot directly mint authorized ops, but it corrupts all replica state and exfiltrates a credential.

**Fix:** Authenticate the blob with HMAC-SHA256 under a node-held key or an ECDSA signature from the node key; verify before parsing. Track as the outstanding follow-up from prior audit M-1.

### R7-04. Keyring rotation never invalidates the legacy bootstrap key; guard conditions are bypassable

**Files:** `src/Attribute/attribute_machine.c:1047-1122` (`user_key_rotate` touches only the keyring), `src/Crypto/crypto.c:1054-1060` (legacy `user->public_key` path taken when `sig_scheme == SCHEME_UNSPECIFIED` and `key_id` empty), `src/StateMachine/state_machine.c:531` (`if (op->signer_key_version > 0 && …)`), `src/StateMachine/state_machine.c:539` (`if (op->sig_scheme != SCHEME_UNSPECIFIED && …)`)

`user_key_rotate` revokes the old keyring entry but never clears or updates `user->public_key` — the legacy bootstrap ECDSA key remains a valid signing key for the user. An op that omits `key_id` and declares `sig_scheme = SCHEME_UNSPECIFIED` routes to that legacy key, and setting `signer_key_version = 0` skips the staleness check entirely. So a user who rotates precisely because their key was compromised still accepts ops signed with the compromised key, provided the attacker crafts the fields above. (Note: the §11.4 `crypto_revoke_and_rotate` path *does* replace `user->public_key`; the ordinary §9 rotation path does not.)

**Fix:** (a) On keyring rotation, clear or replace the legacy `user->public_key`, or reject the legacy verification path once a keyring exists. (b) Make `signer_key_version` mandatory (reject 0) when the signer has a nonzero `key_version`. (c) Enforce the scheme allowlist against the key actually used, including the legacy path.

### R7-05. WASM time shim does not enforce the https scheme; sync XHR is unbounded

**File:** `src/TimeSource/wasm_time_library.js:27` (`xhr.open('GET', url, false)`)

The native transport enforces `https://` in `_parse_url` (`time_source.c:201`); the JS glue passes the configured URL straight to the browser XHR with no scheme check. A deployment config (or any code path influencing it) pointing at `http://` fetches time over cleartext, fully MITM-able. Additionally, the synchronous XHR cannot be bound by a timeout (the spec throws on `timeout` for sync requests), so a hanging server freezes the page. The Node path spawns a synchronous child process with a similar gap in scheme enforcement (`https.get` itself restricts to TLS, but nothing rejects non-https input explicitly).

**Severity note:** Currently latent because of R7-01 — but fixing R7-01 without this makes an `http://` config a live timestamp-forgery channel.

**Fix:** Reject non-`https://` URLs in `_wasm_fetch_server_time` and in the JS glue; move the browser path to async `fetch()` with `AbortController`.

---

## 4. MEDIUM

### R7-06. `crypto_revoke_and_rotate` mutates user state before validating the new key

**File:** `src/Crypto/crypto.c:1666-1682`

The function suspends the user and `memcpy`s `new_public_key` into `user->public_key` *before* any validation. If the key is invalid, `crypto_key_envelope_create` fails (via the R5-6 validation in `_ecies_encrypt_to_pub`) and the function returns NULL — but the user record now holds an invalid public key and is suspended, with no rollback and (see R7-07) no reactivation path. The user is permanently bricked.

**Fix:** Call `crypto_ecdsa_validate_public_key(new_public_key)` at entry and return before any mutation; move the suspend after successful envelope creation, or roll back both mutations on failure.

### R7-07. `crypto_revoke_and_rotate` suspends the user with no reactivation path

**Files:** `src/Crypto/crypto.c:1672`, `src/Attribute/attribute_machine.c:662` (`USER_SUSPENDED`)

There is no `attribute_machine_activate_user` anywhere in the tree; `USER_ACTIVE` is only ever set at bootstrap-admin creation and initial registration, and re-registration is rejected as a duplicate. After a §11.4 recovery the user can never authorize again — the "recovery" is a permanent lockout unless an out-of-band admin tool edits state. The test at `test/test_crypto.cpp:908` asserts the suspension, so this is intended-but-incomplete design.

**Fix:** Add an admin-authorized reactivation op, or have rotation revoke the old key without suspending the user.

### R7-08. `register_user` does not apply the privileged-attribute blocklist to `initial_attrs`

**File:** `src/Attribute/attribute_machine.c:418`

`_parse_attributes` validates charsets but never calls `_is_privileged_attr_name` (compare :512 in `self_assert` and :758 in `issue_temporary`). A caller passing `initial_attrs = "role:admin"` mints that attribute, which satisfies `role:admin` policies and yields a real CP-ABE key. The only in-tree caller passes `""`, so it is not reachable today — a latent privilege escalation in a public API.

**Fix:** Reject privileged names inside `_parse_attributes`.

### R7-09. Policy notation mismatch: the evaluator expects prefix form, the preprocessor emits/passes infix — compound and comparison policies always deny

**Files:** `src/Crypto/crypto.c:534-575` (`_eval_policy_expr`, prefix `AND <l> <r>`), `src/Crypto/crypto.c:597-598` (trailing-garbage rejection), `src/Condition/condition.c:1133-1195` (`_ast_to_string`, infix `left AND right`, `(l) OR (r)`, `a >= 5`), `src/Condition/condition.c:1243-1256` (raw fallback when `condition_parse` fails — which it always does for `name:value` tokens, since `:` is a lexer error)

A policy registered in the natural infix form `"role:admin AND dept:eng"` evaluates `role:admin`, hits the trailing-garbage check, and returns false — always, regardless of attributes. Numeric comparisons (`"views >= 5"`) similarly always deny: the comparison is never evaluated, only the first token is matched. This is fail-closed (no privilege escalation) but silently breaks the documented AND/OR and comparison policy features; tests only exercise the prefix form, so the mismatch is uncaught.

**Fix:** Unify on one grammar: either emit prefix from `_ast_to_string` and require prefix in stored policies, or teach `crypto_abe_eval_policy` the infix grammar. Add round-trip tests for compound and comparison policies.

### R7-10. Key expiry is skipped when the platform clock is 0 (fail-open)

**Files:** `src/Crypto/crypto.c:1071,1087` (`key->expires_at != 0 && now_ms != 0 && …`), `bindings/wasm/index.js:572` (`setTime`), `bindings/node/index.d.ts:134`

Both verification paths read `attr_machine->current_time_ms` directly and skip expiry enforcement when it is 0 ("platform has not injected a clock"). `state_machine_execute` injects the clock, but any direct caller of `crypto_verify_co_signature` / `crypto_verify_operation_auth_v2` that forgets to set the time disables key expiry entirely; a binding caller can also `setTime(0)`. Fail-open by design.

**Fix:** Treat `now_ms == 0` as "expiry unknown" and reject, or require explicit clock injection before any time-gated check.

### R7-11. Replay protection is not durable across restarts

**Files:** `src/TxManager/tx_manager_memory.c:24-39` (in-memory AVL of processed op UUIDs, never persisted), `src/StateMachine/state_machine.c:426-432,708-714`

The comment at `crabs.h:33` claims cross-session replay protection "relies on Lamport clocks and signatures," but no Lamport monotonicity check exists in the execute path. After a restart, a validly signed op can be replayed and re-applied — double-counting counters, corrupting lock sequences. Ops carrying dedup specs survive (the tracker lives in state); plain ops do not.

**Fix:** Persist the processed-UUID set (or tx manager), or enforce `op->lamport_time` strictly greater than the last logged time per signer.

### R7-12. Memory-amplification DoS in invariant deserialization

**File:** `src/Serialization/serialization.c:960-1007`

In the first pass, `str_space += msg_len + 1` (line 974) accumulates unconditionally, while the in-bounds guard (line 975) only gates offset advancement. With `inv_count` up to 255 and `msg_len` up to 65535, ~2.8 KB of input forces a ~16.7 MB allocation per item; with `item_count` up to `CRABS_DESER_MAX_ITEMS` (100000) a ~280 MB blob forces ~1.6 TB of cumulative allocation. `get_clear_memory` aborts on OOM (`allocator.c:8-24`) → remote crash. (Writes remain bounds-checked; this is allocation amplification, not corruption.)

**Fix:** Only accumulate `str_space` when the message is actually in bounds (mirror the second pass) and/or cap total `str_space`.

### R7-13. Dedup mutation is applied before the handler — failing ops burn dedup slots

**File:** `src/StateMachine/state_machine.c:516-528`

`dedup_check_and_apply_spec` runs before the handler; if the handler fails, the tracker mutation (e.g. the signer added to a ONE_SHOT_SET) persists. An authorized signer can thus permanently consume their "vote once" slot with an op that fails, denying the legitimate action. Requires an authorized signer, so this is a protocol-DoS, not an auth bypass.

**Fix:** Apply the dedup mutation only after the handler succeeds, or roll it back on handler failure.

### R7-14. Mode A verification leaks user existence and status through distinct error codes

**Files:** `src/Crypto/crypto.c:948-960, 1130-1139`, `src/StateMachine/state_machine.c:485-487` (propagated verbatim)

Nonexistent user → `CRABS_ERR_USER_NOT_FOUND`; suspended → `CRABS_ERR_USER_SUSPENDED`; active with bad signature → `CRABS_ERR_UNAUTHORIZED`. An unauthenticated caller can enumerate user IDs and their status. This contradicts the stated intent of the Round-2 L-a fix ("an unauthenticated caller gets a single CRABS_ERR_UNAUTHORIZED").

**Fix:** Collapse Mode A failures to a single error at the trust boundary.

### R7-15. Canonical signing form and wire format disagree on `ordering_system`/HLC — HLC-ordered ops cannot verify after gossip, and HLC timestamps are unauthenticated

**Files:** `src/Serialization/serialization.c:1974-1984` (canonical form includes `ordering_system` + four HLC fields) vs `:1365-1475` (wire format writes neither); workaround at `src/Util/wasm_helpers.c:147-155`

A deserialized op always has `ordering_system == CRABS_ORDERING_LAMPORT` (zero-init). Any caller that sets HLC ordering signs bytes the wire drops; the verifier's re-serialization differs and verification fails forever. The HLC timestamp is not covered by any signature. Currently latent — the WASM binding deliberately signs as LAMPORT to dodge the bug — but the documented HLC feature is broken on the wire.

**Fix:** Make wire and canonical formats cover the same field set (add HLC fields to the wire format with a version bump, or remove them from the canonical form).

### R7-16. Time-response parsing is unanchored; WASM cast of huge values is UB

**Files:** `src/TimeSource/time_source.c:347` (`strstr(response, "ts=")`), `src/TimeSource/wasm_time_library.js:65` (`/ts=(\d+)(?:\.(\d+))?/` — unbounded digits), `src/TimeSource/time_source.c:522-523` (`(uint64_t)server_time` from a JS double)

`ts=` is matched anywhere in the body — an error page or unrelated JSON field containing `ts=` is accepted. On the WASM path a huge digit string becomes a double ≥ 2^64 and the cast to `uint64_t` is undefined behavior. Native parsing is bounded (8 KiB buffer, 19-digit cap); the JS path is not.

**Fix:** Anchor parsing to the trace format (line-start `ts=` digits), bound digit count in the JS regex (`\d{1,19}`), and range-check before casting.

### R7-17. Native HTTPS transport ignores the HTTP status code

**File:** `src/TimeSource/time_source.c:468-501`

The body is parsed for `ts=`/`unixtime` regardless of the status line; a 404/500 page containing `ts=` yields a "valid" time. Requires a misbehaving/compromised time server (the channel is TLS-authenticated), but combined with R7-16 it widens the forgery surface. (The browser path does check 2xx.)

**Fix:** Require `200 OK` before parsing the body.

### R7-18. No plausibility bound or monotonicity on fetched time

**File:** `src/TimeSource/time_source.c:109-121`

A fetched timestamp is accepted and cached for the resync interval with no sanity check against the local clock and no monotonicity enforcement across resyncs. A compromised time server (or CA compromise with valid cert) can push time far forward and extend all expiries. The integration test asserts ±5 s; production code does not.

**Fix:** Reject fetches outside a configurable bound of the local clock and never accept an anchor earlier than the current one.

**Severity note:** R7-16 through R7-18 are latent while R7-01 stands (the transport is never called), but become live the moment the time source is wired in.

---

## 5. Carried Forward (previously reported, verified STILL OPEN)

### R7-CF-1. 2P-set compaction discards `remove_set` — removed elements can be re-added

**File:** `src/Compaction/crdt_compaction.c:152-176` — originally reported 2026-08-07 (H-3). Still open; the in-code warning comment remains. If a 2P-set backs a revocation/deny list, compaction silently re-enables revoked entries. **Fix:** do not register a compaction vtable for 2P-set, or preserve the remove_set.

### R7-CF-2. PN-counter compaction discards the neg counter — replica divergence

**File:** `src/Compaction/crdt_compaction.c:384-411` — originally reported 2026-08-07 (H-4). Still open. A compacted replica (pos=net, neg=0) and a non-compacted replica diverge after later decrements. **Fix:** restrict to STRONG/QUORUM safety with full peer acknowledgement, or keep the neg counter.

---

## 6. LOW

| ID | File:line | Finding |
|----|-----------|---------|
| R7-L-1 | `state_machine.c:531` | `signer_key_version > 0` guard — a crafted op with 0 skips the staleness check (compounds R7-04). |
| R7-L-2 | `state_machine.c:539` | `sig_scheme != SCHEME_UNSPECIFIED` guard — declaring UNSPECIFIED skips the per-policy scheme allowlist (compounds R7-04). |
| R7-L-3 | `crypto.c:1617`, `crypto.c:1296-1307` | Decrypt-side ECDH uses attacker-controlled `eph_pub` from the unauthenticated blob without `crypto_ecdsa_validate_public_key`; `_eckey_from_public`/`ECDH_compute_key` do no on-curve check. The encrypt side validates (R5-6); the decrypt side should too. No exploitable output oracle exists (GCM tag check), so this is hardening. |
| R7-L-4 | `state_machine.c:426-432` | tx_manager accept runs before signature verification: `CRABS_ERR_ALREADY_EXECUTED` vs `CRABS_ERR_UNAUTHORIZED` is a processed-UUID existence oracle. |
| R7-L-5 | `serialization.c:164-175` | `_read_string16` truncates over-long strings instead of rejecting; the offset still advances by the full length, so malformed ops fail verification instead of being rejected at parse. Reject instead. |
| R7-L-6 | `serialization.c:1477-1657` | `crabs_deserialize_operation` accepts trailing bytes; arbitrary data can be appended to a signed op without invalidating it (canonicalization laxity, not a bypass). Require full consumption. |
| R7-L-7 | `condition.c:1216-1223` | `_resolve_user_id_placeholder` overflow path `memcpy`s the full placeholder length from a shorter `signer_id`, reading past its NUL and splicing garbage into the policy. Fails closed, but the over-read is a defect. Fail preprocessing instead of truncating. |
| R7-L-8 | `crypto.c:966-978, 1144-1160` | Mode A verifies signature before policy and returns early on bad signature — a timing side channel distinguishes bad-signature from bad-policy. Evaluate both and return a combined result. |
| R7-L-9 | `crypto.c:1215-1237` | Co-signers are checked only for active status + valid signature, not for satisfying the op's ABE policy. A threshold-2 "role:admin" policy is met by one admin plus any active user. If co-signers are meant as approvers, this is a policy bypass; if witnesses, document it. |
| R7-L-10 | `build_wasm.sh:50` (`-DOPENSSL_NO_SECURE_HEAP`), `Util/allocator.c` | WASM linear memory is readable by any in-page JS; `free()` does not zero. Explicit `OPENSSL_cleanse` coverage in `crypto.c` is good, but OpenSSL-internal key buffers are unprotected in this build. Defense-in-depth gap. |
| R7-L-11 | `bindings/wasm/crabs.js` | Committed WASM artifact (Aug 8) predates the time-shim commits and contains no `js_fetch_server_time`; `build-wasm/crabs.js` (Aug 15) does. Rebuild before release. |
| R7-L-12 | `crdt_merge.c:490-501` | `_data_item_deep_copy` shallow-copies `lock_state` including the `pre_lock_snapshot` pointer — a latent use-after-free/double-free if `crdt_merge_state` ever gains callers (currently none). |
| R7-L-13 | `ot_execution.c:166` | OT op `node_id` memcpy of 64 bytes without forcing NUL; consumers `strcmp`/`strlen` (compaction_engine.c:61, ot_types.c:189-193) can read past the buffer on a wire-crafted 64-byte ID (bounded, ~8 bytes). |
| R7-L-14 | `serialization.c:1728-1736, 1836-1841` | Failed `_deserialize_ot_op` leaks the current op's payload (error path frees `j < i` only). Bounded leak per malformed blob. |
| R7-L-15 | `serialization.c:1456` vs `:1965-1972` | Canonical form always writes all 7 dedup mutation fields; wire format drops them for `MUTATION_CUSTOM` — same inconsistent-field-set class as R7-15; ops carrying such fields fail verification after gossip. |

---

## 7. INFO

- **R7-I-1.** `mk` (ABE master key) is unused in both `crypto_verify_operation_auth` and `_v2` (`crypto.c:916-1020, 1099-1209`): "ABE-gated" authorization is the string-based policy evaluator only; real CP-ABE is never consulted on the auth path. Matches the documented design, but the attribute check is exactly as strong as the string matcher — policy grammar bugs (R7-09) directly shape authorization.
- **R7-I-2.** Mode B's comment says "trial ABE decryption" (`crypto.c:985`); the code does trial ECDSA verification against each active user. Cosmetic.
- **R7-I-3.** `crypto_abe_encrypt` takes OpenABE policy syntax (`"admin and editor"`), distinct from both the prefix evaluator and the infix preprocessor — three policy dialects coexist (also flagged at the end of Round 6 as "three policy parsers un-unified").

---

## 8. Prior-Audit Delta (spot-verified)

**Confirmed fixed since 2026-08-07 audit:**
- H-1 `ECDSA_sign` buffer size: `der_sig_len = sizeof(der_sig)` (crypto.c:377). Fixed.
- H-2 ABE user-key destroy cleanse: `OPENSSL_cleanse` before `oabe_bytestring_free` (crypto.c:704-709). Fixed.

**Confirmed still open:** 08-07 H-3/H-4 (carried as R7-CF-1/CF-2); the unkeyed state checksum (M-1 lineage) is R7-03.

## 9. Verified Correct This Round (no action needed)

- ECDSA low-S normalization on sign (`crypto.c:117-138`) and enforcement on verify (`crypto.c:415-434`) — consistent round trip, malleability closed.
- Public-key validation (`crypto.c:322-340`) rejects infinity/off-curve points; enforced at registration, key registration, and ECIES encrypt (`crypto.c:1379`).
- ECIES envelope: fresh ephemeral key + fresh 12-byte IV per encryption (no IV reuse possible — the key is bound to the ephemeral pub), domain-separated KDF (SHA-256 over shared‖eph_pub‖label), GCM tag checked on decrypt, shared/aes/plain cleansed.
- Envelope canonical form is unambiguous (fixed-width + length-prefixed fields) and the signature covers all fields including the ciphertext (`crypto.c:1258-1284`); deserialize is bounds-checked with unknown-version rejection (`crypto.c:1551-1597`).
- `state_machine_execute` authorization ordering: signature + ABE policy verified before any mutation; compaction/snapshot/resync do not bypass the op gate (with the snapshot-authentication caveat of R7-03).
- Deserialization bounds checks are consistent (`_read_uint*_le`, `_read_bytes`, `_read_bytes32`); oversized counts rejected not clamped; BST depth-limited; tree cycle detection present; OT op_log/priority allocations bounded by remaining buffer.
- CRDT merges (g_counter, or_set, two_p_set, lww_register, one_shot_*) are commutative/associative/idempotent; compaction safety fails closed on NULL peer VC.
- Entropy: `RAND_bytes` with return checks everywhere; WASM chain resolves through Emscripten `/dev/urandom` device to `crypto.getRandomValues`/`nodeCrypto.randomFillSync`; RELIC's HASHD DRBG seeded from `/dev/urandom`; no `rand()`/`Math.random` anywhere in `src/` or `bindings/`.
- Native TLS verification for the time source is correct: `SSL_VERIFY_PEER` + default verify paths + `SSL_set1_host` + `X509_V_OK` check (`time_source.c:435-466`).
- Key zeroization: private keys, shared secrets, AES keys, ABE master secret, user keys, and envelope plaintext are all `OPENSSL_cleanse`d on the paths reviewed.
- Co-signature distinctness and threshold enforcement (`state_machine.c:582-609`); registered dedup spec wins over op-carried spec (`state_machine.c:521-522`); config clamps prevent expiry-arithmetic wrap (`state_machine.c:962,982,990`).

---

## 10. Recommended Remediation Order

1. **R7-01 + R7-02 together** — wire the authenticated time source into `state_machine_execute` and fail closed on unavailability; this is the only way expiry semantics mean anything, especially in WASM.
2. **R7-04** — close the legacy-key survival on rotation and the two guard bypasses; this is the weakest point in key-compromise recovery.
3. **R7-05, R7-16, R7-17, R7-18** — harden the time transport *before* enabling R7-01's wiring.
4. **R7-06/R7-07** — make §11.4 recovery transactional and provide a reactivation path.
5. **R7-09** — unify the policy grammar (and add round-trip tests); compound policies silently deny today.
6. **R7-03** — authenticate the state snapshot.
7. **R7-11, R7-12, R7-13** — durable replay protection, allocation cap, dedup ordering.
8. Remaining MEDIUM/LOW items and the two carried-forward compaction fixes.

---

## 11. Fix Status (2026-08-15)

All MEDIUM findings and all code-fixable LOW findings are fixed and covered by
regression tests (1287 passing, 1 network test skipped). The two carried-forward
compaction findings (R7-CF-1/CF-2) remain open.

**MEDIUM — fixed:**
- R7-01/R7-02 — authenticated time source wired into `state_machine_execute`, fail-closed on unavailability.
- R7-03 — authenticated state snapshots (`crabs_serialize_state_signed` / `crabs_deserialize_state_signed`).
- R7-04 — legacy-key invalidation on rotation + mandatory key-version and scheme-allowlist checks.
- R7-05 — WASM JS glue rejects non-`https://` URLs (`wasm_time_library.js`).
- R7-06/R7-07 — `crypto_revoke_and_rotate` validates before mutating; `attribute_machine_activate_user` reactivation path.
- R7-08 — `register_user` rejects privileged attribute names in `initial_attrs`.
- R7-09 — policy grammar unified (prefix + infix + comparisons).
- R7-10 — key expiry fail-closed when the platform clock is 0.
- R7-11 — per-signer Lamport monotonicity check in `state_machine_execute` (durable replay protection).
- R7-12 — invariant deserialization accumulates `str_space` only for in-bounds messages.
- R7-13 — dedup mutation applied only after the handler succeeds.
- R7-14 — Mode A collapses user-existence/status/signature/policy failures to a single `CRABS_ERR_UNAUTHORIZED`.
- R7-15 — wire format v4 carries `ordering_system` + HLC fields.
- R7-16/R7-17/R7-18 — anchored `ts=` parsing, 2xx status enforcement, plausibility + monotonicity bounds.

**LOW — fixed:**
- R7-L-1/R7-L-2 (via R7-04), R7-L-3, R7-L-4 (tx_manager accept after authorization), R7-L-5, R7-L-6, R7-L-7, R7-L-8 (Mode A evaluates signature + policy together), R7-L-9 (co-signers must satisfy the op's ABE policy), R7-L-11 (committed WASM artifact rebuilt), R7-L-12, R7-L-13, R7-L-14, R7-L-15.
- R7-L-10 — the `-DOPENSSL_NO_SECURE_HEAP` flag is no longer in `build_wasm.sh`; the remaining `free()`-does-not-zero gap is documented defense-in-depth (crypto paths already `OPENSSL_cleanse`).

**Open:** R7-CF-1/CF-2 (carried-forward compaction fixes).
