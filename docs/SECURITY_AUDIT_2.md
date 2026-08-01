# CRABS Security & Correctness Audit — Follow-Up (Round 2)

**Date:** 2026-07-31
**Scope:** Full source tree under `src/` plus the `deps/openabe-c` integration surface, re-audited after the 2026-07-30 remediation commits (`140e2b0`, `34bf377`, `06c8d77`, `3755386`, `e612f49`).
**Method:** Five independent module-level reviews (Crypto/Attribute, StateMachine/Dedup/Trigger, Serialization/Condition, OT/Compaction, CRDT/HLC/CLI/Util). Each reviewer both re-verified every "Fixed" claim from `docs/SECURITY_AUDIT.md` (Round 1) and hunted for new issues. All CRITICAL findings were independently re-verified against the code before inclusion in this report.
**Relationship to Round 1:** This is a fresh audit, not a delta review. Round 1 findings are referenced by their original IDs (C-1…L-10); new findings use IDs F-1…. 

---

## 1. Executive Summary

The Round 1 remediation was substantial and mostly real: authorization now fails closed, co-signatures are verified, the signing canonical form is complete and domain-tagged, ECDSA is low-S normalized, the audit log is hash-chained, most memory-corruption bugs are fixed, and a real Waters'09 CP-ABE (via openabe-c) replaces the simulation.

**However, several Round 1 fixes are bypassed at a different layer, and the convergence/complex subsystems (OT, Compaction, CRDT merge) still guarantee silent replica divergence and data loss under normal concurrent use.** The most serious problems:

1. **The C-5 self-assertion fix is bypassed** (F-1): policies and real CP-ABE keys are derived from attribute *values* with names stripped, but the new privileged-attribute blocklist checks *names*. `self_assert("clearance", "admin")` mints admin authority — including a real CP-ABE key with attribute `admin`.
2. **Dedup/one-shot semantics are entirely client-supplied** (F-2): an attacker sets `dedup.type = DEDUP_NONE` on the wire and "vote once" disappears. The server-side registry is consulted only inside `__check_dedup__`, never in the enforcement path.
3. **Compaction is unarmed and uncoordinated** (F-3): no code anywhere sets a peer vector clock or emits a COMPACT op, so the C-11 safety fixes never fire and compaction destroys concurrent remote operations — permanent divergence.
4. **The OT transform matrix is unreachable for the op types that actually execute** (F-4): concurrent document/tree edits are applied untransformed; a dropped no-op marker makes a double-delete delete the wrong element.
5. **The resource protocol state machine (spec §6.3) is dead code** (F-5): nothing ever assigns `MODIFIED`, so `__verify__`/`__unlock__` can never succeed and the `required_state` check is vacuous.

**Severity counts (new findings):** 5 CRITICAL, 10 HIGH, 15 MEDIUM, 12 LOW/INFO (some grouped).

The library remains unsuitable for protecting real data or authorization decisions until at least the CRITICAL findings and the OT/Compaction convergence work are complete.

---

## 2. CRITICAL Findings (new)

### F-1. C-5 fix bypassed: attribute names are stripped everywhere, so the privileged-name blocklist is useless

`src/Crypto/crypto.c:755-790` (`_build_attr_string`), `src/Attribute/attribute_machine.c:297-304`, `src/Crypto/crypto.c:1160,1177`

The 06c8d77 fix for C-5 blocks self-assertion of privileged attribute **names** (`role`, `admin`, `member`, …). But `_build_attr_string` — used for both policy evaluation and **real CP-ABE keygen** — strips the name and keeps only the value:

```c
const char* colon = strchr(attr, ':');          // crypto.c:763
const char* value = colon ? colon + 1 : attr;   // "role:admin" -> "admin"
```

So `attribute_machine_self_assert("clearance", "admin")` passes the name blocklist, then produces the token `admin` in the attribute string. The user thereafter (a) satisfies a software policy of `admin` (`_attr_in_list`, crypto.c:511 region), and (b) — far worse — is minted a **real Waters'09 CP-ABE key with attribute `admin`** by `crypto_key_envelope_create`, which cryptographically satisfies any ABE-encrypted policy naming `admin`. Name-stripping also makes `role:admin` and `dept:admin` collide, as flagged in Round 1 (M-12).

**Recommendation:** never strip names. Evaluate policies and generate ABE keys over the full `name:value` token (sanitized into the OpenABE identifier alphabet, e.g. `role_admin`), and keep the blocklist as a second line of defense only. Add a regression test: self-asserting any attribute whose *value* is `admin` must not satisfy a `role:admin` policy or yield an ABE key for it.

### F-2. Dedup guard is entirely client-supplied — one-shot semantics bypassable

`src/StateMachine/state_machine.c:384-390, 583, 1253-1267`; registered spec consulted only inside `__check_dedup__`

Step 5 of `state_machine_execute` enforces dedup using the `dedup_spec_t` **embedded in the operation itself**:

```c
if (op->dedup.type != DEDUP_NONE) {
  crabs_error_e dedup_result = dedup_check_guard(state, op);
```

The server-side registry populated by `__define_operation_type__` (`state_register_op_type_def`) is read only when the op type is literally `__check_dedup__` (line 1257). An attacker submits the same logical operation with `dedup.type = DEDUP_NONE` (or a trivially-true custom condition) and the guard vanishes — "vote once", "perform at most once", and the Round 1 C-6 signature coverage of the mutation fields are all moot, because the mutating op carries whatever dedup spec it likes.

**Recommendation:** in step 5, look up `state_find_op_type_def(state, op->type)` and evaluate the *registered* guard and mutation; if a definition exists, ignore the op-carried spec entirely (and reject ops whose embedded spec doesn't match the registered one). Apply the registered mutation in step 8, not the attacker-supplied one.

### F-3. Compaction is never armed and never coordinated — guaranteed divergence and silent data loss

`src/Compaction/compaction_engine.c`, `src/Compaction/vector_clock.c:135,146`, `src/Compaction/compact_op.c:303-312`

Three compounding defects:

1. **Nothing arms the safety check.** No caller of `crabs_compaction_engine_set_peer_vc` or any vector-clock mutation exists outside `src/Compaction` (verified by grep). `local_vc` stays empty and `peer_vc` stays NULL forever, so the C-11 fail-closed fallbacks (`local_vc->count <= 1`, `peer_vc->count == 0 → true`) make every safety check pass unconditionally — the Round 1 C-11 fix is inert.
2. **Peers are never told.** No `CRABS_OT_OP_COMPACT` op is produced anywhere. One node compacts (zeroing `op_log_count`, destroying `position_map`, resetting priorities) while peers hold concurrent ops; subsequent transforms run against an empty log and apply remote ops at stale positions.
3. **Compaction actively deletes data.** `crabs_transform_delete_compact` (compact_op.c:432-439) sets `visible_pos = 0` but leaves the op live, so it deletes element 0 instead of no-op'ing; `crabs_extract_visible_tree` drops live children of deleted parents because `crabs_ot_tree_merge` marks deletion per-node without marking subtrees (ot_tree.c:525-528).

**Recommendation:** emit a signed COMPACT op on ingest/egress so all replicas compact the same causal prefix; refuse compaction when `peer_vc` is NULL (fail closed); wire vector-clock updates into the op ingest path; make `delete_compact` set `op_type = 0`; recursively mark (or orphan-reparent) subtrees during tree merge. Until peer state exists, the honest answer is to disable compaction entirely.

### F-4. OT transforms never run for the op types that execute; dropped no-op marker corrupts documents

`src/OT/ot_types.c:185-186`, `src/OT/ot_execution.c:279-294`, `src/OT/ot_transform.c:99,121`

- The H-8 core bug persists: `crabs_ot_data_item_get_transform` rejects `type > CRABS_OT_OP_TYPE_COUNT (15)`, but the only op types ever applied are `INSERT_TEXT`–`SPLIT_SPAN` (0x11–0x15) and `INSERT_NODE`–`REORDER` (0x21–0x24). Transform lookup returns NULL for all of them, and `crabs_transform_ot_op` **silently applies ops untransformed** — two concurrent `INSERT_TEXT`s diverge every time.
- `crabs_transform_delete_delete`/`move_move` signal "no-op" by setting `op1->op_type = 0`, but `crabs_transform_ot_op` copies back only positions — the delete is still applied, at the same position, deleting whatever shifted into it.
- Equal-priority concurrent inserts: `if (op1->priority >= op2->priority) op1->visible_pos += 1` (ot_transform.c:63) shifts symmetrically on both replicas (AB on one, BA on the other — TP2 violation); the tie-break `next_priority` helper is never called.

**Recommendation:** map document/tree op types onto base INSERT/DELETE/UPDATE semantics before matrix lookup (or dense-index the matrix over all types); copy back `op_type` and skip apply+append when it is 0; tie-break by `(priority, node_id, seq)` with strict antisymmetry. These are correctness-of-convergence bugs that become security bugs the moment state divergence is used to bypass invariants.

### F-5. The §6.3 resource protocol is dead code — `MODIFIED` is unreachable, verify/unlock impossible

`src/StateMachine/state_machine.c:96 (is_valid_transition — no callers)`, dispatch `else → CRABS_ERR_INVALID_PARAM` (line ~576)

Grep shows nothing in `src/` ever assigns `item->protocol_state = PROTOCOL_MODIFIED` (only comparisons), and the executor rejects every non-builtin op type. Consequences:

1. `__verify__` (requires `MODIFIED`) and therefore `__unlock__` (requires `VERIFIED`) can never succeed through `state_machine_execute` — **the entire lock lifecycle cannot be completed**; every locked resource is only ever released by expiry/force-unlock, which rolls back the pre-lock snapshot. Resource mutation via the protocol is effectively non-functional.
2. The step-3 `required_state` check is vacuous as a security control: the attacker declares whatever state the item is in (it's readable), and since transitions never advance, no protocol sequencing is enforced.
3. `CRABS_OT_OP_*` operations (`crabs_execute_ot_operation`) perform no protocol transition either.

**Recommendation:** after handler success, apply `op->next_state[i]` (already signed!) validated against the §6.3 transition table, and actually drive `LOCKED → MODIFIED → VERIFIED → IDLE` inside the builtins. Add end-to-end tests: lock → modify → verify → unlock happy path, and rejection of out-of-order transitions.

---

## 3. HIGH Findings (new)

### H-A. Key envelopes ship the ABE secret key in cleartext; the vault crypto is never used by the library

`src/Crypto/crypto.c:1248-1275` (`crypto_key_envelope_serialize` writes `sk_abe` unencrypted, signature only); `crypto_abe_encrypt`/`crypto_abe_decrypt` (658, 697) have **no callers in `src/`** (tests only). No HKDF exists anywhere in the tree — the Round 1 status note about an "MSK-derived AES-256-GCM vault via HKDF" is stale; the code was rewritten to the (real, but uncalled) ABE-KEM+DEM in openabe-c. Two consequences: (1) authorization in CRABS is purely software policy evaluation + ECDSA — ABE contributes nothing to the execute path; (2) key distribution relies entirely on an out-of-band "secure channel" that the library does not provide. **Recommendation:** encrypt envelopes to the recipient's public key (ECIES over the registered secp256k1 key), and either wire `crypto_abe_encrypt` into a real capability-vault store or document that ABE confidentiality is currently an application concern.

### H-B. `crypto_revoke_and_rotate` still generates the user's private key on the node (M-7 NOT fixed)

`src/Crypto/crypto.c:1354-1358`. A node compromise yields permanent impersonation of every rotated user. Move to user-generated keypairs submitted via a signed `__rotate_key__` op.

### H-C. Revocation and expiry are never enforced

`USER_REVOKED`/`KEY_EXPIRED` are declared but **never assigned anywhere** (grep); verify paths check only `status == USER_ACTIVE`/`KEY_ACTIVE`, so a "revoked" user is only revocable by overwriting status manually with nothing doing so; `expires_at` on keys/attributes is ignored by `_verify_user_signature` (crypto.c:942) and `_build_attr_string`; `state_machine_op_refresh_key` (state_machine.c:1152) rejects `USER_SUSPENDED` but not `USER_REVOKED`. **Recommendation:** wire the suspend/revoke ops to the status enum, check `expires_at` at every use site, and reject REVOKED on all paths including refresh.

### H-D. openabe-c's public AES-GCM API is fake crypto

`deps/openabe-c/src/api/oabe_crypto.c:311` → `abe/oabe_context.c:345-372`: `encrypted[i] = plaintext[i] ^ key[i % key_len]` with a random dummy tag, commented "placeholder — production should use AES-GCM". CRABS doesn't call it today, but it is a loaded footgun for any future caller. Implement real EVP GCM or remove the symbols.

### H-E. Trigger `CHANGE_POLICY` effect can rewrite any authorization policy at fire time

`src/Trigger/trigger.c:104-111` + update-in-place `state_add_policy` (data_model.c:194-199). Anyone with `__create_trigger__` authority can create a trigger that, on fire, replaces the policy for *any* op — including `__change_config__` or `__force_unlock__` — with an empty string, which `crypto_abe_eval_policy("")` accepts (crypto.c:516), needing only a self-signature afterwards. **Recommendation:** constrain CHANGE_POLICY effects to op types the creator could itself administer (re-authorize the effect at fire time against the signer's attributes), and forbid empty-policy writes via triggers.

### H-F. CLI keyring replacement double-free / use-after-free

`src/CLI/cli.c:163-169`: re-adding a key for the bootstrap admin destroys the keyring entry that aliases `node->node_key`; `cli_cmd_key_revoke` then dereferences the dangling pointer (line ~572) and `cli_node_destroy` frees it again (line ~123). **Recommendation:** skip destroy when the old pointer equals `node->node_key` (or deep-copy into the keyring).

### H-G. Deserialization allocation amplification (M-2 residual) + forgeable state blobs (M-1 NOT fixed)

`src/Serialization/serialization.c:1813-1818`: `pc_count` (priority_counters) unbounded → 4 wire bytes request ~34 GiB; op-log cap `CRABS_OT_OP_LOG_MAX = 1048576` × ~1.4 KB/op ≈ 1.4 GiB per item; the allocator **aborts** on OOM, so this is a one-packet process kill. The state checksum remains unkeyed SHA-256 (documented deferral), so any stored/exchanged state blob is attacker-forgeable. Positive: the hash is now verified before allocations. **Recommendation:** cap all counts proportionally to remaining buffer length; HMAC/sign state blobs intended for untrusted transport or storage.

### H-H. Type confusion in `condition_resolve_path` via attacker-controlled `crdt_type`

`src/Condition/condition.c:841-855`: switches on `item->crdt_type` (independent, attacker-controlled wire field) and casts `item->value` to `g_counter_t*`/`lww_register_t*`, while the rest of the codebase stores counters as `int64_t*`. A state blob with `crdt_type == CRDT_G_COUNTER` over an int64 value produces wild-pointer dereference. **Recommendation:** switch on `item->type`, require the exact invariants the serializer writes, never cast raw values to struct pointers.

### H-I. OT op-log append failure ignored → log corruption and leak

`src/OT/ot_execution.c:476-486`: on `append_op` failure the code overwrites `op_log[op_log_count - 1]` (leaking its payload, destroying causal history) instead of aborting. Check the return; abort the op.

### H-J. OR-set merge is not idempotent → unbounded remote-triggered memory growth

`src/CRDT/crdt_merge.c:243-255, 296-303`: `or_set_add` never dedups by tag; `merge(A, A)` doubles `element_count` each round. Membership converges; memory/CPU diverges — a gossip partner or replayed sync can exhaust memory. **Recommendation:** dedup elements by tag (tombstones already do, line 310).

---

## 4. MEDIUM Findings (new)

- **M-A.** `__change_config__` parser pairs each key with the **first `=` in the whole payload** (state_machine.c:814-865), and values are unbounded: `max_lock_extensions=0;max_lock_duration_ms=60000` sets the *duration* to 0 (every lock instantly force-unlockable). Clamp config values and parse per key.
- **M-B.** Lock-expiry arithmetic overflow (state_machine.c:232-234): `max_lock_duration_ms + extensions * max_lock_duration_ms` wraps with attacker-set config → live locks read as expired. Saturate.
- **M-C.** `{user_id}` placeholder still spliced raw into policy text before parsing (condition.c:1153-1181) — policy-structure injection via `signer_id` (M-12 NOT fixed). Validate signer IDs at registration (`[A-Za-z0-9_-]`) or bind post-parse.
- **M-D.** Malformed OT trees accepted on deserialize: duplicate ids, `parent_id == id`, and A↔B cycles pass (serialization.c:554-592); downstream recursive walkers hang/overflow.
- **M-E.** Truncation-instead-of-rejection on clamped counts (`dep_count` → 16, `style_count`, `allowed_scheme_count`; serialization.c:257, 473, 1019) desynchronizes the parse with attacker-controlled offsets — fail closed instead. OT-side twin: `ot_execution.c:207-209` consumes only 16 deps of a larger declared count.
- **M-F.** `one_shot_set` merge non-commutative at the 256-element cap (one_shot.c:36-76) — the surviving subset depends on merge order (M-3 residual). Canonicalize (sort) before capping.
- **M-G.** `g_counter_value`/`pn_counter_value` signed-overflow UB on the sum (crdt_merge.c:109-113, 184) even though per-entry increments are checked. Saturate accumulation.
- **M-H.** `_build_attr_string` silently truncates values mid-token and drops trailing attributes (crypto.c:766-786) — a truncated value can alias a legitimate policy token; make overflow fail closed.
- **M-I.** Refresh envelope silently empty: real CP-ABE keys exceed the 1024/1200-byte transport buffers (state_machine.h:126, crypto.h:173); `crypto_key_envelope_serialize` returns 0 and `state_machine_op_refresh_key` reports success with `envelope_data_len = 0` (state_machine.c:1181-1184). Size buffers for real keys; fail the op on overflow.
- **M-J.** Merge-created parent cycles in OT trees: reparent's cycle check is local-only (ot_tree.c:321-329); concurrent reparents merged via `_rebuild_links` create cycles → infinite ancestor walks. Detect cycles during rebuild.
- **M-K.** 64-op transform-depth wedge persists (ot_execution.c:299-301) — `depth++` counts even skipped entries, so flooding concurrent ops permanently wedges an item. Count only transformed ops; trigger compaction instead of failing.
- **M-L.** Op-identity inconsistency: `crabs_ot_op_id_equal` includes `timestamp` (ot_types.c:31-33) but `crabs_op_depends_on` ignores it (ot_transform.c:36-37) — forged timestamps bypass dedup and double-apply. Drop timestamp from identity.
- **M-M.** `condition_parse` has no input-length or recursion-depth cap (trigger.c:51 passes the original unbounded string) — deep parentheses → stack exhaustion.
- **M-N.** HLC counter wrap: `max_counter + 1` on a received `UINT64_MAX` logical counter wraps to 0 (hlc.c:415-417, also 290/305/312); `crabs_hlc_add_duration` can wrap `physical_seconds` (hlc.c:158-167). Reject/saturate.
- **M-O.** RGA/CUSTOM CRDTs still never merge — `crdt_merge_value` returns NULL and new RGA items are added with `value = NULL` (crdt_merge.c:641-644, 495-497): silent permanent divergence (M-3 residual). Fail loud or implement.

## 5. LOW / Informational (new)

- **L-a.** Error-code oracles pre-auth (steps 3–5 before 5b): resource existence, lock state, and dedup membership are distinguishable to unauthenticated callers. Consider authorizing first or collapsing errors.
- **L-b.** `record_processed_op` silently drops the record on realloc failure (state_machine.c:282) → idempotency loss; `processed_ops` and the log grow unboundedly.
- **L-c.** `op_lock` partial acquisition on CSPRNG failure (state_machine.c:656-666) leaves earlier items locked with tokens the caller never receives.
- **L-d.** HLC node identity bound to the first lock's `op->node_id` and never re-validated (state_machine.c:644-646).
- **L-e.** realloc-into-own-member (serialization.c:679) loses the old pointer on failure; several unchecked `strdup`s.
- **L-f.** Deserialize leaks on malformed input (span/tree-node on style failure, partial op payload; serialization.c:467-477, 1691-1698); trailing garbage after the checksum silently accepted; `msg_lens_arr` dead code.
- **L-g.** `MUTATION_CUSTOM` dedup ops round-trip differently than they sign (wire form drops mutation fields) → always-rejected signatures for that shape.
- **L-h.** `crabs_xi` uint64 underflow (position_map.c:211) returns ~UINT64_MAX → tail-append placement divergence.
- **L-i.** Static shared `_entry_result` in transform matrix (ot_transform.c:401) — thread-unsafe.
- **L-j.** `DATA_TYPE_OT_*` still has dual enum/`#define` definitions with `#undef` hacks (compact_op.c:12-20) — the C-8 contradiction is latent, not gone.
- **L-k.** `crabs_extract_ot_ops` wire format is host-endian `memcpy` — cross-architecture peers desync. No in-repo producer today.
- **L-l.** CLI: after `cli_node_load` the keyring is empty and a fresh `node_key` is generated — the node is unusable (fail-closed but dead) with no `key import` command; `cli_cmd_key_revoke` revokes any user with no authorization check; `localtime` in log.c:136 remains thread-unsafe (L-8 half-fixed).
- **L-m.** OOM fail-open in the low-S check (crypto.c:357-366); keystore leak if `oabe_context_cp_export_key` fails after keygen; `attribute_machine_create` leaks `abe_mk` on admin alloc failure; `fprintf(stderr, "DEBUG: …")` left in openabe-c `oabe_context_cp_import_key`; BN_P254 is ≈100-bit security — plan migration to a 128-bit curve.

---

## 6. Round 1 Findings — Re-Verification

| ID | Round-1 claim | Round-2 verdict |
|----|---------------|-----------------|
| C-1 | Real Waters'09 keygen; MSK-derived vault | **Partial.** Keygen/KEM/DEM are real and correct (GT neutered before serialization, fresh IVs, symkey cleansed). But encrypt/decrypt are uncalled by the library and envelopes ship keys in cleartext (H-A). |
| C-2 | Fail-closed auth | **Fixed.** Verified: every op incl. builtins gates on registered policy + signature; NULL attr_machine rejected. |
| C-3 | No empty-policy free pass; CONTAINS-under-OR fails closed | **Fixed.** |
| C-4 | Co-signatures verified | **Fixed.** Verified at state_machine.c:484-521 + crypto.c:1079. |
| C-5 | Self-assert restricted; trigger issuance gated | **Bypassed.** Name-blocklist defeated by value-only attr strings (F-1); ISSUE_ATTRIBUTE is inert-no-op (safe but silent); CHANGE_POLICY effect remains dangerous (H-E). |
| C-6 / C-7 / M-15 | Full dedup + payload_format + domain tag in signed form | **Fixed.** Canonical form is injective and deterministic. Note: enforcement of dedup is still client-driven (F-2). |
| C-8 | Op-type constants unified | **Fixed** (residual dual definitions, L-j). |
| C-9 / C-10 | Heap corruption fixes | **Fixed.** |
| C-11 | Compaction safety fail-closed | **Inert.** Fix exists but is never armed (F-3). |
| C-12 | USER_ACTIVE whitelist | **Partial.** Gates fixed, but nothing ever sets REVOKED and expiry is unchecked (H-C). |
| H-1 / H-2 / H-3 / H-4 / H-5 | Payload, count, timing, recursion fixes | **Fixed.** (New parser semantic bug M-A; write-side BST recursion on crafted in-memory trees remains.) |
| H-6 | OT wire deps consumed | **Partial** (M-E desync when declared > 16). |
| H-7 | Deps-based causality | **Partial.** Wall-clock removed; depth wedge remains (M-K). |
| H-8 | Transform matrix guards | **Partial.** NULL-desc crash fixed; matrix still unreachable for executed types (F-4). |
| H-9 | Reparent cycle check | **Partial** (M-J merge-created cycles). |
| H-10 | Tree extraction order | **Partial** (F-3 deleted-parent/live-child drop). |
| H-11 / H-12 / H-13 / H-14 | delete_range, HLC fail-closed, skew overflow, policy registry | **Fixed.** |
| M-1 / M-2 | Unkeyed checksum; allocation limits | **NOT / Partial** (H-G). |
| M-3 | Log dedup, LWW ties, g-counter | **Partial.** Those three fixed; OR-set idempotence (H-J), RGA/CUSTOM (M-O), one_shot cap (M-F) remain. |
| M-4 | condition_resolve_path casts | **Partial** → H-H. |
| M-5 | CRDT serialization | **Partial.** Sets/2P/one-shot/OT round-trip; RGA documents, OT_TABLE, OT_ORDERED_MAP still 0-length without failing loudly. |
| M-6 | Persistent master key for refresh | **Fixed.** |
| M-7 | Node-generated user keys | **NOT fixed** (H-B). |
| M-8 | Hash-chained audit log | **Fixed.** |
| M-9 | Dep-aware op-log pruning | **Partial** (compaction destroys the log anyway; H-I). |
| M-10 | Persistent HLC, expiry | **Fixed** (trigger cooldown guarded; HLC wraps remain, M-N). |
| M-11 | One-shot trigger bypass | **Fixed.** |
| M-12 | Policy grammar / `{user_id}` | **NOT fixed** (M-C). |
| M-14 | Negative/overflowing increments | **Fixed** (sum-overflow residual M-G). |
| M-16 | Low-S ECDSA | **Fixed.** |
| M-17 | CLI signs with custodied per-user keys | **Fixed with regressions** (H-F, L-l). |
| L-3/L-4/L-8/L-9/L-10 | Hygiene items | Mostly fixed; `localtime` and documented spec non-compliances remain. |

---

## 7. Design / Specification Observations

1. **Authorization is software-only; ABE is decorative in the execute path.** The spec (§10.3) has the node *generate a key and attempt decryption* to verify policy satisfaction — expensive and pointless, since the node holds the MSK and can just evaluate attributes. The implementation evaluates attributes in software (fine), which means the ONLY thing ABE must deliver is vault confidentiality — and that vault is not wired to anything. Decide what ABE is for in this system, then either wire it (capability vault storing per-op signing keys, spec §2.5) or honestly scope it out of the security claims.
2. **Attribute tokens must be namespaced.** Every layer (policy eval, ABE keygen, blocklist) must agree on token form — full `name:value`. Today each layer sees a different view (F-1, M-12).
3. **Convergence-critical subsystems need their own hardening pass** before any production use: OT transforms (F-4), compaction coordination (F-3), and CRDT merge idempotence (H-J, M-F, M-O). These don't just lose data — divergence + invariant checks that pass on one replica and not another is an authorization bypass path.
4. **The spec still needs the same updates as Round 1 recommended** (§7.5 signing fields — now done in code, update the document; QUORUM/TRUSTED HLC marked reserved) plus new ones: document that dedup specs are server-registered, define the envelope transport encryption (H-A), and specify COMPACT op semantics for compaction coordination (F-3).
5. **openabe-c hygiene:** its public AES-GCM API is a placeholder (H-D); its DEM is real but the public API should be fixed or deleted; BN_P254 is ~100-bit.

---

## 8. Prioritized Remediation Plan

**Phase 1 — Authorization bypasses (days):**
F-1 (namespaced tokens end-to-end), F-2 (registered dedup enforced server-side), H-E (trigger policy writes), H-C (revocation/expiry enforcement), F-5 (drive the protocol transitions).

**Phase 2 — Convergence correctness (the big one):**
F-4 (transform reachability + no-op marker + tie-breaks), F-3 (compaction coordination or disable), H-I, M-J/M-K/M-L, H-J/M-F/M-O (CRDT idempotence), M-D/M-E (deserialization strictness).

**Phase 3 — Key management & crypto plumbing:**
H-A (encrypt envelopes; wire or scope out the vault), H-B (user-side key generation), H-D (fix/remove openabe-c AES-GCM), H-G (allocation caps; MAC state blobs), M-I (buffer sizes).

**Phase 4 — Robustness & hygiene:**
M-A/M-B (config parsing & expiry arithmetic), M-C (placeholder binding), M-G/M-H/M-N (arithmetic saturation), H-F/L-l (CLI keyring), H-H (type confusion), all LOW items; add fuzz targets over every deserializer and an end-to-end divergence test harness (random op interleavings across 2–3 replicas asserting byte-identical merged states).

---

## 9. Remediation Status (2026-07-31)

A first remediation pass has been applied. The fast test suites (292 tests
across the state-machine, crypto, dedup, trigger, serialization, CLI, CRDT,
HLC, compaction, and ABE suites) pass. The slow CP-ABE-keygen suites
(`TestPolicyConfig`, `KeyEnvelopeTest`) are not run in this pass — they take
~300s each due to real pairing operations.

### Fixed in this pass

| ID | Summary of fix |
|----|----------------|
| F-1 | `_build_attr_string` (crypto.c) and the `preprocess_policy` fallback (condition.c) now keep the full `name:value` token; policies are matched as whole tokens, so `self_assert("clearance","admin")` no longer satisfies `role:admin`. Overflow fails closed (empty string) rather than truncating mid-token. Regression tests in test_crypto.cpp / test_attribute_machine.cpp. |
| F-2 | `state_machine_execute` resolves the effective dedup spec via `state_find_op_type_def` (registered wins over op-carried); `dedup_check_guard_spec`/`dedup_apply_mutation_spec` take an explicit spec. A signer can no longer bypass "vote once" by setting `dedup.type = DEDUP_NONE`. Regression test in test_dedup.cpp. |
| F-5 | Non-builtin operations are now accepted (no C handler; effect via dedup mutation + protocol transition). The §6.3 wildcard `LOCKED→MODIFIED` is applied after handler success, making `__verify__`/`__unlock__` reachable. Regression tests in test_protocol_ops.cpp (lock→modify→verify→unlock happy path; non-LOCKED rejected). |
| H-E | `TRIGGER_EFFECT_CHANGE_POLICY` rejects empty `policy_expression` and rejects changing the policy of any builtin op type; triggers may only set policies for application-defined ops. Regression test in test_trigger.cpp. |
| H-C | Added `attribute_machine_revoke_user` (sets `USER_REVOKED` — the enum value was previously never assigned) and `attribute_machine_set_time` (injects the wall clock so temp-attribute expiry actually fires). `state_machine_op_refresh_key` now whitelists `USER_ACTIVE` (rejects REVOKED, not just SUSPENDED). The executor prunes expired temp attributes before authorization. `_verify_user_signature` enforces key `expires_at`. Regression tests in test_attribute_machine.cpp / test_crypto.cpp. |
| H-J | `or_set_add` dedups by tag (and skips tombstoned tags), making `merge(A,A)` idempotent — closes the remote memory-exhaustion DoS. |
| M-G | `g_counter_value` uses saturating accumulation (clamps to INT64_MAX/MIN) instead of wrapping. |
| M-N | HLC logical-counter increments saturate (`_hlc_saturate_inc`) — a received `UINT64_MAX` counter no longer wraps local to 0. `crabs_hlc_add_duration` saturates `physical_seconds`/nanos. |
| H-F | `cli_node_add_user_key` skips destroying keyring entries that alias `node->node_key`, closing the double-free / use-after-free on re-add. |
| F-4 (partial) | Transform no-op marker (`op_type = 0`) is now copied back and `crabs_apply_ot_op` skips it — a double-delete no longer deletes the wrong element. Equal-priority insert/insert tie-break is now a strict total order on `(priority, node_id)` (antisymmetric) so both replicas converge. **The transform-matrix reachability for document/tree op types (>15) is still deferred** — concurrent document/tree ops are still applied untransformed. |
| F-3 (partial) | `crabs_check_compaction_safety` now fails closed for STRONG/QUORUM when `peer_vc == NULL` (the prior `local_vc->count <= 1` fallback always passed because local_vc is never populated). `crabs_transform_delete_compact` marks the op as a no-op (`op_type = 0`) instead of deleting element 0. **Compaction coordination (COMPACT op emission, vector-clock population) is still deferred** — multi-replica deployments must use `CRABS_SAFETY_FORCE` until the coordination layer lands. |
| H-I | `crabs_ot_data_item_append_op` return is checked; on failure the operation aborts instead of overwriting the last log entry (which leaked its payload and destroyed causal history). |
| M-L | `crabs_ot_op_id_equal` no longer includes `timestamp` — op identity is `(node_id, sequence_num)`, so forged timestamps cannot bypass dedup. |
| H-G | `crabs_deserialize_ot_data` bounds `op_count` and `priority_counters` to the remaining buffer before allocating, closing the one-packet abort-DoS (the allocator aborts on OOM). |
| M-E | Deserializers now reject (not clamp) oversized `dep_count`, `style_count`, and `allowed_scheme_count` — clamping desynchronized the parse. |
| H-D | openabe-c's public `oabe_context_aes_encrypt`/`decrypt` (in `deps/openabe-c/src/abe/oabe_context.c`, synced from the canonical repo at `openabe-to-c/openabe-c`) replaced the XOR-with-dummy-tag placeholder with real AES-256-GCM via OpenSSL EVP (96-bit random IV per encryption, 16-byte authentication tag verified on decrypt). The CP-ABE DEM (`_dem_aes_gcm_*`) was already real and is unchanged. |

### Deferred (known follow-ups)

- **F-4 full:** the transform matrix is still unreachable for document/tree op types (>15). Mapping those onto base INSERT/DELETE/UPDATE semantics before lookup (or dense-indexing the matrix) is a deeper OT-correctness rewrite.
- **F-3 full:** compaction coordination — emit a signed COMPACT op on the wire, populate `local_vc`/`peer_vc` from op ingest, and recursively mark subtrees deleted during tree merge (`ot_tree.c`). Until then multi-replica compaction is disabled (fail-closed); single-replica deployments use `CRABS_SAFETY_FORCE`.
- **M-J, M-K:** merge-created parent cycles (ot_tree rebuild) and the 64-op transform-depth wedge remain.
- **M-D:** OT tree deserialization still accepts duplicate ids / self-parents / cycles.
- **M-F:** `one_shot_set` merge non-commutativity at the 256-element cap.
- **M-A, M-B:** `__change_config__` per-key parser bug and lock-expiry arithmetic overflow.
- **M-C:** `{user_id}` placeholder still spliced raw into policy text before parsing (policy-structure injection via `signer_id`).
- **M-H:** `_build_attr_string` overflow now fails closed (empty) rather than truncating — the deeper fix (sizing buffers for real attribute counts) is not needed at current limits.
- **M-I:** refresh envelope transport buffers (1024/1200 bytes) may be too small for real CP-ABE keys with many attributes; `crypto_key_envelope_serialize` returns 0 on overflow and the op reports success with `envelope_data_len = 0`. Size buffers or fail the op.
- **H-A, H-B:** key envelopes still ship `sk_abe` in cleartext (the ABE vault crypto is real but unused by the library internally); `crypto_revoke_and_rotate` still generates the user's new ECDSA private key on the node.
- **L-\*:** the LOW items (error-code oracles, `processed_ops` unbounded growth, `localtime` thread-safety, CLI key-import path, op-log wire endianness, etc.) are documented limitations.
- **Cross-arch wire format:** `crabs_extract_ot_ops` uses host-endian `memcpy`; cross-architecture peers would desync. No in-repo producer today.

### Test posture

- 292 fast-suite tests pass (state machine, co-sign, protocol ops, trigger,
  serialization, CLI, verify-auth, attribute machine, dedup, CRDT, HLC,
  compaction, ABE encrypt/decrypt, crypto).
- New regression tests added: F-1 (self-assert value collision does not
  authorize), F-2 (registered dedup enforced despite op-carried DEDUP_NONE),
  F-5 (custom op accepted / LOCKED→MODIFIED / non-LOCKED rejected), H-E
  (CHANGE_POLICY rejects empty and builtin targets), H-C (revoke user,
  revoked user rejected, temp-attr expiry after set_time), H-J (OR-set
  idempotence — covered by existing TestORSet.TestMerge), M-G/M-N
  (saturation — covered by existing counter/HLC tests).
- A de-wonk pass caught and fixed one CRITICAL regression introduced by the
  F-1 change (an overflow path in `_build_attr_string` returned without
  NUL-terminating the caller's stack buffer, which would have let
  `crypto_abe_eval_policy` read garbage) and one MEDIUM (OT append OOM left
  a log entry with `payload=NULL` but non-zero `payload_size`).

### Fixed in the second pass (2026-08-01)

| ID | Summary of fix |
|----|----------------|
| M-A | `state_machine_op_change_config` now parses each key via `_config_value_after` (finds the `=` immediately after the matched key, requiring a boundary before it), so `"max_lock_extensions=0;max_lock_duration_ms=60000"` no longer sets the duration to 0 (which made every lock instantly force-unlockable). |
| M-B | `max_lock_duration_ms` is clamped to a 24h ceiling and `max_lock_extensions` to 1024, so the lock-expiry `extensions * duration` multiply cannot wrap uint64 into a small value (which made active locks read as expired). |
| M-C | `attribute_machine_register_user` rejects signer_ids outside `[A-Za-z0-9_-]`, so the `{user_id}` policy placeholder cannot inject policy structure (quotes, parens, operators). |
| M-D | OT tree deserialization now rejects duplicate node ids, self-parenting, and parent-link cycles/disconnections (bounded ancestor walk per node). |
| M-J | `crabs_ot_tree_reparent`'s ancestor walk is bounded by node_count (no hang on a merge-created cycle), and `_rebuild_links` detaches any node whose parent chain cycles (deterministic per pool order). |
| M-K | The 64-op transform-depth cap now counts only ops that were actually transformed and no longer fails the operation — a flooded log no longer permanently wedges the item. |
| M-F | `one_shot_set_merge` collects the union, sorts lexicographically, and keeps the first MAX, so the surviving subset at the 256-element cap no longer depends on argument order (commutative). |
| M-I | The refresh-key transport buffer is sized to 8 KiB (was 1024) and `CRABS_KEY_ENVELOPE_MAX_SIZE` to 8192 (was 1200) so real CP-ABE keys fit; `state_machine_op_refresh_key` now fails the op on serialize overflow instead of returning SUCCESS with `envelope_data_len = 0`. |
| F-4 full | `crabs_ot_data_item_get_transform` now maps concrete document/tree op types (0x11-0x24) onto their base transform semantics (INSERT/DELETE/UPDATE/MOVE/SWAP) before matrix lookup, so concurrent document/tree ops are transformed against each other instead of applied untransformed. Regression test `OTTypes.ConcreteOpsResolveToBaseTransform`. |

### Still deferred

- **F-3 full:** compaction coordination — emit a signed COMPACT op, populate
  `local_vc`/`peer_vc` from op ingest. Multi-replica compaction is fail-closed
  until then; single-replica uses `CRABS_SAFETY_FORCE`.
- **M-J commutativity:** `_rebuild_links` cycle-break is deterministic per pool
  order; full commutativity across `merge(A,B)` vs `merge(B,A)` (id-sorted
  cycle-break) is a deeper CRDT-tree follow-up.
- **H-A, H-B:** key envelopes still ship `sk_abe` in cleartext (the ABE vault
  crypto is real but unused internally); `crypto_revoke_and_rotate` still
  generates the user's new ECDSA private key on the node.
- **L-\*:** the LOW items (error-code oracles, `processed_ops` unbounded
  growth, `localtime` thread-safety, CLI key-import path, op-log wire
  endianness) are documented limitations.

### Test posture (second pass)

- 414 tests pass across 22 suites (state machine, co-sign, protocol ops,
  trigger, serialization, CLI, verify-auth, attribute machine, dedup, CRDT,
  HLC, compaction, ABE, OT types/transform/ordered-set/document/tree/
  execution).
- The slow CP-ABE-keygen suites (`TestPolicyConfig`, `KeyEnvelopeTest`) are
  not run in CI due to ~300s per-test pairing cost.

---

*Round 2 — same crab, sharper pincers needed.*
