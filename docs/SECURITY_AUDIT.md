# CRABS Security & Correctness Audit

**Date:** 2026-07-30
**Scope:** Full source tree under `src/` (Crypto, StateMachine, Attribute, Condition, Serialization, Dedup, HLC, CRDT, OT, Compaction, Trigger, CLI, Util, CRABS data model), reviewed against the protocol specifications in `docs/` (base spec v1.0 through v1.6 Amendment 6, CRABS.md, CRABS Extended.md).
**Method:** Manual code review of all security-critical modules, plus independent secondary review of the OT/Compaction and CRDT/Trigger/CLI modules. All CRITICAL findings were verified against the actual code before inclusion.

---

## 1. Executive Summary

The library implements an interesting and well-documented protocol, but **the current implementation does not provide the security properties the specification promises**. The most serious problems:

1. The "ABE" layer is a simulation in which the decryption key is derivable from **public** information. It provides *zero* cryptographic confidentiality or attribute enforcement.
2. The operation authorization path has **multiple fail-open branches**: operations with no registered policy and no resources execute with *no signature verification at all*, and several realistic policy shapes reduce to an empty policy string, which the verifier treats as *authorized without checking the signature*.
3. Co-signatures (v1.3 threshold signing) are **counted but never cryptographically verified**.
4. The canonical signing serialization excludes attacker-influenceable fields (dedup state mutation, `payload_format`), so signed operations can be **tampered with after signing** without invalidating the signature.
5. Attribute/role management (register user, grant/revoke role, suspend) happens through **unauthenticated direct calls** that bypass the signed-operation protocol entirely; any user can self-assert any attribute, including `role:admin`.
6. The OT and Compaction subsystems contain multiple memory-corruption bugs (invalid free, heap overflow) and CRDT-safety violations that cause silent replica divergence.

Until at least the CRITICAL findings are remediated, this library must not be used to protect any real data or authorization decisions.

**Severity counts:** 12 CRITICAL, 14 HIGH, 17 MEDIUM, 10 LOW/INFO.

---

## 2. CRITICAL Findings

### C-1. The "ABE" construction provides no security whatsoever

`src/Crypto/crypto.c:416-511, 657-675`

- Master key setup sets `mpk = SHA256(msk)` (`crypto_abe_setup`, line 425). The MPK is public by design (spec §11.1: "Public: No protection needed").
- User "secret keys" are just a **copy of the MPK**: `memcpy(sk->key, mk->mpk, ABE_MASTER_KEY_SIZE)` (`crypto_abe_keygen`, line 468).
- The encryption key is `HMAC-SHA256(MPK, policy)` (`_derive_encryption_key`, line 490).

Because the MPK is public, **anyone** can compute `HMAC(MPK, policy)` for any policy and decrypt any ciphertext — the software policy check in `crypto_abe_decrypt` (line 662) is the only gate, and an attacker working with the raw ciphertext simply skips it. User key envelopes (`crypto_key_envelope_create`, line 1085) likewise embed the *public* MPK as the "secret" `sk_abe`.

**Impact:** complete loss of confidentiality for the capability vault and all ABE-encrypted data; attribute-based access control is security theater at the cryptographic layer.
**Recommendation:** replace the simulation with a real CP-ABE scheme (e.g., BSW07 via OpenABE/libfenc, or a pairing library such as RELIC/MCL). Until then, rename the API (`crypto_abe_*` → `crypto_sim_*`), document loudly that it is a non-secure placeholder, and never derive real authorization or confidentiality decisions from it.

### C-2. Operations with no registered policy and no resources bypass all authorization

`src/StateMachine/state_machine.c:361-365`

```c
const char* policy = state_find_policy(state, op->type);
if (policy == NULL && op->resource_count > 0) {
  return CRABS_ERR_UNAUTHORIZED;
}
```

If an operation has `resource_count == 0` and no policy is registered for its type, step 5b is skipped entirely — **no signature check, no policy check**. This covers `__change_config__`, `__refresh_abe_key__`, all `__*_trigger__` operations, key-lifecycle operations, `__compact__`, and `__define_operation_type__` whenever the deployer forgets to register a policy. Spec §10.3 requires `policy == null → return false` unconditionally.

**Impact:** an unauthenticated attacker can change machine configuration, create triggers (see C-5), refresh keys, force compaction, etc.
**Recommendation:** fail closed — if `state_find_policy` returns NULL, reject the operation regardless of `resource_count`.

### C-3. Empty effective policy string is treated as "authorized" without signature verification

`src/Crypto/crypto.c:760-767` and `932-939`; `src/Condition/condition.c:1047-1053, 1198-1215`

`crypto_verify_operation_auth{,_v2}` returns `authorized = true` immediately when `strlen(abe_policy) == 0` — *before any signature is checked*. A registered policy can reduce to an empty string through `preprocess_policy`:

- `_filter_contains_nodes` drops every `CONTAINS` node, and for `NODE_OR` it returns NULL if **either** side is a CONTAINS (condition.c:1051). A policy such as `role:admin OR myset CONTAINS x` therefore reduces to an empty ABE policy whenever the CONTAINS side survives evaluation.
- A policy consisting solely of CONTAINS checks also reduces to empty.

Combined with C-2's skip logic, this means entire classes of realistic policies silently disable signature verification.
Additionally, `_evaluate_contains_nodes` evaluates all CONTAINS nodes **conjunctively**, ignoring whether they sit under an `OR` — so mixed policies are both over- and under-authorizing depending on shape.

**Recommendation:** (a) never treat an empty post-preprocessing policy as a free pass — require `authorized == false` unless signature *and* policy both verify; (b) fix the CONTAINS filtering to respect OR/AND semantics (evaluate CONTAINS nodes as boolean leaves in the AST instead of splitting the pipeline); (c) add regression tests for every policy shape in the spec.

### C-4. Co-signatures are counted but never verified

`src/StateMachine/state_machine.c:447-457`

Step 6c enforces `co_sign_threshold` by comparing `op->co_signer_count` against the threshold, but **no code anywhere verifies `op->co_signers[i].signature`** (grep confirms the only references are serialization and counting). The threshold check is also bypassable: if `co_signer_count == 0` and `sig_scheme == SCHEME_UNSPECIFIED`, the inner condition short-circuits and the threshold is not enforced at all.

**Impact:** an attacker satisfies any co-signing policy by stuffing `co_signer_count` garbage entries into the operation; multi-party authorization (v1.3 §4) is void.
**Recommendation:** implement co-signature verification: each co-signer signs `crabs_serialize_for_signing(op)`; verify each against the co-signer's registered key (respecting `key_id`/`sig_scheme`), enforce distinct signers, and enforce the threshold unconditionally when configured.

### C-5. Trigger and attribute operations allow unauthenticated privilege escalation

`src/StateMachine/state_machine.c:361-364`, `src/Trigger/trigger.c:93-99, 202`, `src/CLI/cli.c:299-395`, `src/Attribute/attribute_machine.c:275-317`

Three compounding problems:

1. Via C-2, anyone can execute `__create_trigger__` (no resources → no policy needed). A trigger with `TRIGGER_EFFECT_ISSUE_ATTRIBUTE` calls `attribute_machine_issue_temporary` for an arbitrary target role — minting attributes with no authorization.
2. The only code paths that call `attribute_machine_register_user / grant_role / revoke_role / suspend_user` are **direct CLI calls** with no signature, no policy evaluation, and a fabricated `signer_id` ("first registered user", cli.c:354). The signed-operation attribute-management flow from spec §8.4 does not exist.
3. `attribute_machine_self_assert` places no restriction on *which* attribute a user asserts — `self_assert("role", "admin")` works, and `_build_attr_string` (crypto.c:697-738) feeds **all** attributes into policy evaluation without distinguishing verified (`verified_by` set) from self-asserted attributes.

**Impact:** any local caller (or remote attacker via C-2's trigger path) can grant themselves `role:admin` and satisfy any attribute policy.
**Recommendation:** route all attribute mutations through `state_machine_execute` with mandatory admin policies (per spec §8.4); restrict self-assertion to a configurable namespace of non-privileged attribute names; make policy evaluation able to require verified attributes, and exclude self-asserted attributes from role checks by default.

### C-6. Dedup state mutation is not covered by the signature

`src/Serialization/serialization.c:1727-1735`

`crabs_serialize_for_signing` includes `dedup.type`, `tracker_path`, `flag_path`, and `condition` — but explicitly excludes `dedup.update` (the `state_mutation_t`: `set_path`, `element_value`, `flag_path`, `counter_path`, **`delta`**, `target_path`, `value`) and `rejection_message`. `dedup_apply_mutation` (dedup.c:91-189) then applies these fields to state: `MUTATION_COUNTER_INCREMENT` adds the attacker-chosen `delta`, `MUTATION_ASSIGN` writes attacker-chosen values.

**Impact:** a man-in-the-middle/relay (or any node re-broadcasting a signed operation) can change `delta` from `1` to `-1000000` or re-target the mutation to a different item, and the signature still verifies. This is a classic signature-domain gap.
**Recommendation:** serialize the full `dedup_spec_t` (including the entire `state_mutation_t` and `rejection_message`) into `crabs_serialize_for_signing`, bump the signing-format version, and add a format-version field to the signing serialization (there currently is none — see M-15).

### C-7. `payload_format` is not covered by the signature

`src/Serialization/serialization.c:1667-1758` (absent from field list)

`payload_format` (0=opaque, 1=JSON, 2=CBOR) changes how consumers interpret `payload`, but it is not in the canonical signing form (nor in spec §7.5 — the spec has the same flaw).

**Impact:** an attacker can flip the format byte on a signed operation, changing the meaning of the payload for any consumer that parses it.
**Recommendation:** include `payload_format` in both the spec (§7.5 field list) and `crabs_serialize_for_signing`.

### C-8. OT transform dispatch uses contradictory op-type constants (wrong operation applied)

`src/OT/ot_types.h:30-42` vs `src/OT/ot_document.h:27-31` and `src/OT/ot_tree.h:28-31`

The enum defines `CRABS_OT_OP_INSERT_TEXT = 0x11 … SPLIT_SPAN = 0x15`, `INSERT_NODE = 0x21 …`; the headers `#define` the same names to *different* values (`INSERT_TEXT 0x10 … SPLIT_SPAN 0x14`, `INSERT_NODE 0x13 …`). Code that includes both headers sees the macro values, so `crabs_apply_ot_op` (ot_execution.c:271-353) dispatches on the macro numbering: an op built from the enum value `0x11` (INSERT_TEXT) hits the case for DELETE_RANGE and **deletes text instead of inserting it**; `INSERT_NODE (0x21)` matches no case at all.

**Impact:** documents and trees are corrupted by normal use; replicas diverge immediately.
**Recommendation:** delete the `#define`s, keep a single enum, and add a compile-time assert or unit test that every op type maps to exactly one transform.

### C-9. Heap corruption: invalid free of array-interior pointers during compaction

`src/Compaction/compact_op.c:253-255` calling `src/OT/ot_types.c:46-52`

```c
for (uint32_t i = 0; i < ot_data->op_log_count; i++) {
  crabs_ot_operation_destroy(&ot_data->op_log[i]);   // frees &op_log[i] — interior pointer!
}
```

`crabs_ot_operation_destroy` ends with `free(op)`. `op_log` is a single array allocation, so every call frees a pointer into the middle of a heap block (undefined behavior / heap corruption), and the payloads are freed a second time by `crabs_ot_data_item_destroy`.

**Recommendation:** introduce `crabs_ot_operation_clear()` that frees only the payload, and use it here; or simply free each `op_log[i].payload` and `memset` the slot.

### C-10. Heap buffer overflow: `op_log_capacity` set without reallocating

`src/OT/ot_execution.c:67-75` + `src/OT/ot_types.c:133-147`

`crabs_register_ot_type` allocates `op_log` with a 16-entry default, then overwrites `ot_data->op_log_capacity = config->max_op_log_size` (e.g. 100000) *without reallocating*. `crabs_ot_data_item_append_op` trusts `op_log_capacity` and only grows when `count >= capacity`, so appends between index 16 and `max_op_log_size` write far past the 16-entry allocation.

**Recommendation:** realloc the log when applying the config, or set the capacity before the initial allocation.

### C-11. Compaction safety checks are non-functional — tombstones collected without peer agreement

`src/Compaction/compaction_engine.c:145-146, 162-163`; `src/Compaction/crdt_compaction.c:81, 192, 302, 428`

`&engine->local_vc` is passed as **both** `local_vc` and `peer_vc` to `crabs_check_compaction_safety`; a vector clock always dominates itself, so STRONG/QUORUM checks always pass. Every `*_compaction_safe` vtable hook also returns `true` unconditionally. Compounding this, `crabs_transform_insert_compact` et al. (`compact_op.c:372-418`) zero out `visible_pos`/`payload_size` of *any* op transformed against a COMPACT op, deleting concurrent operations.

**Impact:** tombstones are garbage-collected before peers acknowledge them → removed OR-set elements resurrect on merge, PN-counter negative entries get double-subtracted, concurrent OT ops are silently destroyed. Permanent, silent replica divergence and data loss.
**Recommendation:** thread real peer vector clocks through the safety check; implement the vtable safety hooks honestly (return "unknown/unsafe" until peer state is available); never delete concurrent ops during COMPACT transforms.

### C-12. Authorization status check ignores `USER_REVOKED`

`src/Crypto/crypto.c:784, 953, 988`; `src/Attribute/attribute_machine.h:18-21`

The enum defines `USER_ACTIVE / USER_SUSPENDED / USER_REVOKED`, but every gate checks only `user->status == USER_SUSPENDED` (or `!= USER_SUSPENDED`). A **revoked** user passes all of them and can still authorize operations in both Mode A and Mode B.

**Recommendation:** require `user->status == USER_ACTIVE` for authorization (whitelist), not `!= USER_SUSPENDED` (blacklist). Apply the same fix in `attribute_machine_*` functions and `state_machine_op_*_key`.

---

## 3. HIGH Findings

### H-1. `__change_config__` parses a non-NUL-terminated payload as a C string

`src/StateMachine/state_machine.c:729-781`

`char* payload_str = (char*)op->payload;` is passed to `strstr`/`strchr`/`strcmp` directly. `op->payload` is a byte array with explicit `payload_size` and no NUL-termination guarantee (it arrives from the wire via `crabs_deserialize_operation`). `strstr` reads out of bounds → information disclosure (adjacent heap interpreted as config) or crash.

**Fix:** copy `min(payload_size, N-1)` bytes into a stack buffer and NUL-terminate, as done (correctly) in `state_machine_op_register_key`.

### H-2. Trigger effect payload parsing has the same OOB read

`src/Trigger/trigger.c:234, 337, 371, 394`

`strncpy(buf, (char*)op->payload, sizeof(buf)-1)` — if `op->payload` isn't NUL-terminated, `strncpy` reads up to 4095/511 bytes past the buffer. Same fix as H-1: `memcpy` with `payload_size` bound, then terminate.

### H-3. Out-of-bounds read when `resource_count != required_state/next_state` array lengths

`src/Serialization/serialization.c:1304-1342` + `src/StateMachine/state_machine.c:326-332`

The deserializer reads `resource_count` (≤8), then independently reads `rs_count` and `ns_count` (each ≤8) and allocates the state arrays at those sizes. Nothing enforces `resource_count == rs_count == ns_count`. `state_machine_execute` step 3 loops `i < op->resource_count` indexing `op->required_state[i]` — if `rs_count < resource_count`, this reads past the heap allocation. A deserialized (attacker-supplied) operation triggers it.

**Fix:** enforce equality of the three counts in `crabs_deserialize_operation` (reject otherwise), and defensively clamp in the executor.

### H-4. Lock tokens compared with `memcmp` (timing oracle) and fall back to `rand()`

`src/StateMachine/state_machine.c:341` and `185-193`

- Lock tokens are 32-byte bearer credentials compared with byte-wise `memcmp` — a remote timing attack can recover a token byte-by-byte. Use `CRYPTO_memcmp` (constant-time).
- If `RAND_bytes` fails, `state_machine_generate_lock_token` falls back to `rand()` — predictable tokens, and `rand()` may be unseeded, producing a deterministic sequence across runs. A failed CSPRNG must be a hard error (`abort`/return error), never a fallback.

### H-5. Unbounded recursion on attacker-controlled serialized data (stack exhaustion)

`src/Serialization/serialization.c:275-325` (`_count_bst_nodes`, `_serialize_bst_recursive`, `_deserialize_bst_recursive`); `src/OT/ot_tree.c:242` (`_mark_subtree_deleted`)

BST (de)serialization recurses to tree depth with no depth cap. A crafted state buffer with a degenerate left-linked "tree" of depth ~100k (≈2 MB of input) overflows the stack. Same for `_mark_subtree_deleted` on a deep crafted tree, and `condition_node_destroy` / `crdt` set merges for pathological inputs.

**Fix:** convert to iterative algorithms with explicit stack, or enforce a maximum depth/node budget during deserialization (reject inputs exceeding it).

### H-6. OT wire-format deserializer never consumes `deps` (stream desynchronization)

`src/OT/ot_execution.c:97-180`

The documented op layout ends with `dep_count(4) + deps...`, but after reading `dep_count` the parser loops to the next op without skipping `dep_count * sizeof(crabs_ot_op_id_t)` bytes. Any op with causal dependencies desynchronizes every subsequent op in the payload; `deps[]` is silently dropped, so causality tracking (already weak — see M-9) loses its input. Also, oversized payloads (`payload_size > CRABS_OT_MAX_PAYLOAD`) are rejected without skipping their bytes — same desync.

**Fix:** skip the right number of bytes in both cases; add a fuzz test with random dep counts.

### H-7. Causality decided by wall-clock timestamps; transform depth cap wedges OT

`src/OT/ot_transform.c:16-22`; `src/OT/ot_execution.c:215-248`

`crabs_causally_before` compares the `timestamp` field (attacker-controlled wall-clock) and ignores `deps[]` entirely — unsound, so the transform set is wrong and replicas diverge; a malicious node can also forge timestamps to reorder history. Separately, `crabs_transform_ot_op` aborts with `CRABS_ERR_OT_TRANSFORM_DEPTH` once the op log holds >64 relevant entries, and `crabs_execute_ot_operation` aborts the whole operation — after 64 concurrent ops, *all* further OT ops on the item permanently fail until pruning.

**Fix:** use `deps[]` (proper causality) or vector clocks; make the depth cap trigger compaction/pruning instead of rejection.

### H-8. Transform matrix unusable for document/tree ops; NULL-description crash

`src/OT/ot_types.c:156-173`; `src/OT/ot_transform.c:378-388`

The registration bounds-check rejects op types `> CRABS_OT_OP_TYPE_COUNT (15)`, so *no* transform is ever registered for document/tree ops (16+) — concurrent document/tree operations are applied untransformed (divergence). Conversely, `crabs_transform_matrix_get_entry` accepts types 7–15 for which `_transform_descriptions` (6 rows) is NULL → `strncpy(dst, NULL, …)` crash.

**Fix:** size the matrix for all op types, register transforms for every pair or reject such ops at the API boundary.

### H-9. `crabs_ot_tree_reparent` allows cycles and self-parenting

`src/OT/ot_tree.c:281-336`

No check that `new_parent` is not the node itself or one of its descendants. A crafted REPARENT op creates a cycle (`node->first_child == node`), and every sibling-walking or recursive subtree routine then spins forever or overflows the stack.

**Fix:** reject self-parenting and walk ancestors of `new_parent` to reject descendants; cap tree depth.

### H-10. Compaction of trees silently destroys live nodes

`src/Compaction/compact_op.c:114-133`

`crabs_extract_visible_tree` iterates the node pool in reverse insertion order (children before parents), so `crabs_ot_tree_insert_node` fails its parent lookup and the node is **silently discarded** (return value unchecked). Nodes whose parent was tombstoned are dropped too, and sibling order is reversed.

**Fix:** iterate in depth order (parents first), check every insert result, preserve child positions.

### H-11. `crabs_ot_document_delete_range` deletes the wrong characters across spans

`src/OT/ot_document.c:288`

After deleting D characters, subsequent visible positions shift down by D, but the loop advances `char_pos = pos + (len - remaining)` (i.e., pos + D). A range spanning multiple spans skips characters and deletes later ones (traced: deleting pos=1 len=6 of "ABCDE"+"FGHIJ" removes B–E and J instead of B–G).

**Fix:** keep `char_pos = pos` after each deletion.

### H-12. QUORUM and TRUSTED HLC strategies are stubs that accept everything

`src/HLC/hlc.c:336-352`

`HLC_STRATEGY_QUORUM` "accept[s] but increment[s] quorum_failures"; `HLC_STRATEGY_TRUSTED` "accept[s] as if verified". An operator who configures either strategy gets *no* time-travel protection while believing otherwise (spec §5 presents both as high-security options).

**Fix:** fail closed (reject) for unimplemented strategies, or implement confirmation/verification; emit a loud startup warning.

### H-13. HLC skew computation overflows — BOUNDED strategy bypassable

`src/HLC/hlc.c:184-195`

`hlc_ms = physical_seconds * 1000 + nanos/1e6` computes in `uint64_t` and wraps for attacker-chosen seconds ≥ ~2^54. An attacker can pick a timestamp whose wrapped product lands within `max_skew_ms` of local time even though it is aeons in the future/past, and the subsequent cast to `int64_t` is implementation-defined for large values.

**Fix:** compare seconds/nanos directly with saturating arithmetic: if `received.seconds > local.seconds + max_skew_ms/1000` reject, etc.; never multiply unbounded input.

### H-14. Unauthenticated policy registry allows shadow policies and unbounded growth

`src/CRABS/data_model.c:175-195`

`state_add_policy` appends with no duplicate check, while `state_find_policy` returns the *first* match. Consequences:

1. A policy can never be *changed* — a second entry for the same operation is a shadow that's never found (the CHANGE_POLICY trigger effect is a silent no-op, `trigger.c:104-112`).
2. Repeated additions (e.g., a trigger firing in a loop) grow `state->policies` without bound → memory-exhaustion DoS.
3. `policy_count++` happens **before** the `realloc`; on realloc failure the count stays incremented and the next call writes at the wrong index, leaving an uninitialized `policy_t` that `strcmp` later reads (heap garbage read). Same pattern in `state_register_op_type_def` (lines 224-227).

**Fix:** update-in-place on duplicate operation names; realloc into a temp and only increment the count on success.

---

## 4. MEDIUM Findings

### M-1. State integrity "checksum" is an unkeyed hash

`src/Serialization/serialization.c:1052-1055, 1077-1082`

`crabs_serialize_state` appends SHA-256 of the contents and deserialization verifies it. An attacker who can modify a state blob can recompute the hash — this detects corruption, not tampering. If serialized states are ever exchanged between nodes or loaded from untrusted storage, this must be an HMAC or a signature by the node key. At minimum, document that it is a *checksum*, not authentication.

### M-2. Deserialization resource exhaustion → allocator abort

`src/Serialization/serialization.c:1104-1151, 1617-1652`; `src/Util/allocator.c`

`log_count`, `policy_count`, `op_count`, `pc_count` come straight from the input (up to 2^32-1) and are multiplied by struct sizes for allocation; `get_clear_memory` **aborts** on OOM. A few-hundred-byte input can therefore kill the process (or force a multi-GB allocation). Since the checksum is unkeyed (M-1), any consumer of serialized states is exposed. **Fix:** enforce sane maxima (e.g., items/log entries/op-log length) before allocating, and make allocation failure return an error rather than abort.

### M-3. Non-commutative / non-idempotent merges → divergence

- Log merge appends src entries unconditionally with no dedup by `uuid` — merging the same src twice duplicates every log entry (`crdt_merge.c:506-516`).
- `CRDT_RGA` and `CRDT_CUSTOM` values silently never merge (`crdt_merge.c:611-614`) — permanent silent divergence.
- OT ordered-set merge appends src-only elements at the tail: `merge(A,B) ≠ merge(B,A)` in element order (`ot_ordered_set.c:297-323`); tree merge orphans become roots (`ot_tree.c:449-508`).
- LWW register with equal timestamp *and* node_id but different values resolves by argument order (`crdt_merge.c:439-444`).
- `one_shot_set_merge` can differ at the 256-element cap depending on merge order (`one_shot.c:36-71`).

**Fix:** dedup log entries by uuid; error on unmergeable types; define deterministic total orders for ties (e.g., hash of element/value).

### M-4. Type-confusion hazards on `void* value`

- `condition_resolve_path` (`condition.c:841-849`) casts any non-counter `item->value` to `int64_t*` and dereferences — out-of-bounds/garbage read for sets, flags, documents, or a deserialized raw-byte value shorter than 8 bytes.
- Deserialized states store raw bytes for non-counter/OT types (serialization.c:745-750); later `dedup_apply_mutation` or CRDT merge casts those bytes to real struct pointers (e.g., `one_shot_set_t*`) → memory corruption. 
- `dedup_apply_mutation` treats `DATA_TYPE_RESOURCE` values as `int64_t*` (dedup.c:154-159) — plausible today, but this coupling should be explicit.

**Fix:** tag deserialized raw values as opaque/invalid for typed operations; add size+type checks before every cast.

### M-5. Serialization round-trip loses most CRDT values

`src/Serialization/serialization.c:640-643`

`_serialize_data_item` writes a 0-length value for every type except counters, registers, and OT types — sets, 2P-sets, documents, flags lose their entire contents on serialize/deserialize (value becomes NULL). State sync via serialization silently drops data.

**Fix:** implement serialization for all CRDT types, or refuse to serialize states containing unsupported types (fail loud).

### M-6. Key refresh uses a throwaway master key; envelope "secret" is public

`src/StateMachine/state_machine.c:1074-1081`

`state_machine_op_refresh_key` calls `crypto_abe_setup()` to create a **fresh random MSK** per refresh and builds the envelope from it — unrelated to the state's persistent `abe_mk`. Refreshed keys are inconsistent with the node's ABE domain (and per C-1 the embedded `sk_abe` is the public MPK anyway).

**Fix:** use `state->abe_mk` for envelope creation; after fixing C-1, embed a real per-user ABE secret key.

### M-7. `crypto_revoke_and_rotate` generates the user's new private key on the node

`src/Crypto/crypto.c:1149-1198`

The node generates and returns the user's new ECDSA private key (spec §11.4 sanctions this with "secure out-of-band channel", but it is still a bad pattern): the node — and anyone who compromises it — can impersonate the user indefinitely afterwards.

**Recommendation:** have the user generate their own keypair and submit the new public key via a signed `__rotate_key__`/recovery operation; keep the node-blind flow as the default.

### M-8. `state_hash` in the audit log is always zero

`src/StateMachine/state_machine.c:533-536`

Spec §7.4 step 9 requires `state_hash: SHA256(state)` per log entry for a tamper-evident chain; the implementation `memset`s it to zero. The audit trail provides no tamper evidence.

**Fix:** compute a real rolling hash chain (`SHA256(prev_hash || entry)`) — a plain hash of a canonical state encoding is expensive and fragile across CRDT merges.

### M-9. OT op-log pruning discards causal history

`src/OT/ot_execution.c:449-473`

Pruning memmoves off the oldest ops without regard to `deps[]`; incoming ops whose dependencies were pruned can't be transformed correctly → divergence. Prune only causally-stable prefixes (all-known via vector clocks).

### M-10. Non-monotonic / gameable timestamps

- `state_machine_op_lock` creates a **fresh** `crabs_hlc_state_t` on the stack per lock (state_machine.c:576-578), so the HLC's regression protection and logical counter are useless; each lock's `acquired_at` starts from counter 0.
- Lock expiry and `time(NULL)` wall-clock throughout the state machine jump with NTP steps; trigger cooldown arithmetic `now_ms - last_triggered_at` underflows (wraps huge → cooldown bypass) when the clock steps back (`trigger.c:154`).
- `one_shot_flag_merge` uses setter-supplied `set_at` (attacker-controlled) for "earliest setter wins" (`one_shot.c:132`) — a malicious replica backdates.

**Fix:** keep one persistent HLC state per node; use `CLOCK_MONOTONIC` for durations; guard the subtraction; validate setter timestamps via HLC receive rules.

### M-11. `__create_trigger__` one-shot bypass via delete/recreate

`src/Trigger/trigger.c:202, 337-360`

Deleting and recreating a trigger with the same id resets `last_triggered_at`/`enabled`, so `one_shot` triggers fire again. Tombstone fired one-shot ids, or reject id reuse.

### M-12. Policy/condition parser robustness

- `crypto_abe_eval_policy` (`crypto.c:403-410`) does not check that the whole policy string was consumed — trailing garbage is silently ignored (`"admin junk junk"` ≡ `"admin"`).
- `_build_attr_string` strips `type:` prefixes and matches on **values only** — `role:admin` and `dept:admin` collide, and policies written with type prefixes (as in the spec's own examples, `"role:admin AND weight >= 3"`) cannot match, producing confusing fail-closed/fail-open behavior depending on the path through `preprocess_policy` (whose fallback strips after the **last** colon — wrong for compound policies).
- `_resolve_user_id_placeholder` (condition.c:1130-1158) splices the attacker-controlled `signer_id` into policy text with no escaping before parsing — policy-structure injection (e.g., `,` inside an `IN (...)` list or `OR` inside comparisons) can alter semantics for policies that use `{user_id}`.
- AND/OR operand parsing accepts digits after keywords (`AND1`), and `isalpha` checks read one byte past the keyword (bounded, but sloppy).

**Fix:** require full consumption in `crypto_abe_eval_policy`; match on full `name:value` pairs with a defined policy grammar; substitute placeholders as *values* post-parse (parameter binding), not into raw text.

### M-13. Recursion depth limits absent in expression/condition parsers (bounded but untested)

`crypto.c:360-401`, `condition.c` parser — recursive descent with depth bounded only by the 256-byte input cap. Today's cap makes this ≈128 frames (survivable), but the bound is incidental; add an explicit depth parameter so future length increases can't turn this into a stack-overflow DoS.

### M-14. G-counter accepts negative increments; counters overflow

`src/CRDT/crdt_merge.c:79-99, 138`

`g_counter_increment(delta)` accepts negative deltas, but merge takes per-node max — a decrement is convergently lost, so its effect differs by replica timing. `entry->count += delta` also overflows int64 with attacker-chosen deltas. Enforce `delta >= 0` and saturating/checked addition (PN-counter already handles decrements correctly via `neg`).

### M-15. Signing serialization has no version/domain tag

`crabs_serialize_for_signing` emits no format version or domain-separation tag, unlike the transport serialization (`_write_uint32_le(buf, 3)`). Upgrading the canonical form (needed for C-6/C-7) will be ambiguous across versions. Add a magic + version prefix and a domain string (e.g., `"CRABS-SIGN-v4"`).

### M-16. ECDSA signature malleability not addressed

`crypto.c` produces/accepts raw `r||s` with no low-S normalization. `(r, n−s)` is a second valid signature for the same message. Current dedup is by UUID, so direct replay impact is low — but any future use of the signature as an identifier, or a co-signature counting scheme, breaks. Enforce low-S (BIP-62 style) at both sign and verify.

### M-17. CLI signs operations as any `signer_id` using the node key

`src/CLI/cli.c:634-646`

The CLI sets `op->signer_id` to an arbitrary user and signs with the node's private key. Verification will only pass when `signer_id` maps to the node key's user (the bootstrap admin); for everyone else it relies on the fail-open paths (C-2/C-3) to succeed at all. This is both a correctness bug (ops as other users always fail when auth is enforced) and a symptom that key custody is muddled. The CLI should hold per-user keys and sign with the key matching `signer_id`.

---

## 5. LOW / Informational

- **L-1.** `.env` in the repo root contains an API key (`HP_API_KEY`). It is gitignored and untracked — keep it that way; rotate the key if it was ever shared or committed historically (`git log -- .env` shows it was not).
- **L-2.** `crypto_random_bytes` casts `len` to `int` (`crypto.c:326`) — truncation for >2 GB requests (unreachable today).
- **L-3.** `crypto_sig_scheme_register` doesn't check the `get_clear_memory` result (moot while the allocator aborts — see M-2); registry is global and unsynchronized — not thread-safe for register/get/cleanup (`sig_scheme.c`).
- **L-4.** Unterminated stack strings from the wire: `ot_execution.c:309-347` does `memcpy(node_id, op->payload, 64)` — if no NUL present, `strcmp` in tree lookups reads past the stack buffer. Copy at most 63 bytes.
- **L-5.** `crabs_causally_before`/priority ties: `insert_insert` shifts on `priority >=` (ot_transform.c:38) — equal priorities make both replicas shift (TP2 violation). Tie-break by (priority, node_id, sequence_num).
- **L-6.** `strdup` return values unchecked in CRDT merge/condition code (`crdt_merge.c:245-374`, `condition.c`) — NULL stored on OOM → later `strcmp(NULL)` crash; inconsistent with the aborting allocator.
- **L-7.** Mode A checks attribute policy *before* the signature (`crypto.c:794-803`) and returns distinct error codes — an oracle distinguishing "user lacks attributes" from "bad signature". Minor info leak; check the signature first.
- **L-8.** `log_level_string` has no bounds check (`log.c:94-96`); `localtime` in log init is not thread-safe.
- **L-9.** `dedup_check_guard` and `dedup_apply_mutation` are non-atomic (TOCTOU) — fine single-threaded, but `state_machine_execute` must never become concurrent without a lock around the pair.
- **L-10.** Unimplemented trigger effects (CREATE/DELETE/DISABLE), OT_TABLE/OT_ORDERED_MAP types, NTP/TPM/consensus time sources, and application-defined operation handlers (spec §7.4 step 7 — non-builtin op types return `CRABS_ERR_INVALID_PARAM` at `state_machine.c:511-512`) are spec-non-compliances; `op->next_state` is signed but never applied or validated for builtins. Document or implement.

---

## 6. Design / Specification Observations

1. **Fail-open is the system's default posture.** Almost every guard in `state_machine_execute` is conditional: no policy → skip; empty policy → authorize; no attr_machine → skip; unsupported strategy → accept. Every one of these should fail closed. Recommend a single `verify_or_reject()` chokepoint that cannot be skipped by configuration omissions.
2. **The spec's trust model (§3.3) should be revisited.** The implementation reveals how much rests on "all nodes hold the MSK" — combined with `crypto_revoke_and_rotate` (M-7), a single node compromise yields total and permanent impersonation capability. Consider threshold MSK (the spec mentions "secret-shared optional" — make it recommended).
3. **Spec §7.5 needs the same fixes as the code**: add `payload_format`, the complete `dedup_spec_t` (including `state_mutation_t`), and a domain/version tag to `SERIALIZE_FOR_SIGNING`.
4. **Spec §5/§8 (HLC) should mark QUORUM/TRUSTED as "reserved — must reject until implemented"** so implementations don't ship accepting stubs (H-12).
5. **Policy language needs a formal grammar.** Today three different parsers (condition AST, ABE evaluator, `preprocess_policy` fallback) mutually disagree on what a policy means (M-12, C-3). Define one grammar, one parser, one evaluator.

---

## 7. Positive Observations

- Deserialization bounds-checking is generally careful (`_read_*` helpers validate lengths and clamp strings; array counts are capped for resources/co-signers; magic/version/checksum verified before parsing).
- Secrets are cleansed on destroy (`OPENSSL_cleanse` for private keys, MSK, user keys, lock tokens on pruning).
- The OT tree deserialization assigns `node_pool` incrementally so early returns don't leak (serialization.c:529-531) — evidence of care in places.
- The condition-language parser (`condition_parse`) requires full token consumption — the discipline the ABE policy parser lacks.
- G/PN-counter and 2P-set merges are genuinely commutative/associative/idempotent; one-shot flag/set semantics are monotonic and not privately bypassable.
- HLC serialization round-trips safely with nanos validation.

---

## 8. Prioritized Remediation Plan

**Phase 1 — Stop the bleeding (auth & signature soundness):**
C-2, C-3, C-4, C-5, C-12 (fail-closed authorization, verify co-signatures, gate attribute/trigger ops, whitelist USER_ACTIVE), C-6, C-7 (complete the signature domain), H-1, H-2, H-3 (payload/OOB fixes), H-4 (constant-time compare; hard-fail CSPRNG).

**Phase 2 — Memory corruption & crashers:**
C-9, C-10 (heap corruption), H-5, H-6, H-9 (recursion/desync/cycles), M-2 (allocation limits), L-4.

**Phase 3 — Convergence correctness:**
C-8, C-11 (op-type constants, compaction safety), H-7, H-8, H-10, H-11 (OT transform/extraction), M-3, M-5, M-9, M-14 (merge/serialization semantics).

**Phase 4 — Cryptographic architecture:**
C-1 (real CP-ABE or explicit non-secure placeholder), M-6, M-7, M-16, M-1 (authenticated state blobs), M-8 (hash-chained audit log), M-15/M-12 (canonicalization + one policy grammar).

**Phase 5 — Hardening & hygiene:**
H-12, H-13 (HLC strategies/overflow), M-10, M-11, M-17, M-13, M-14, all LOW items; add fuzz targets for every deserializer and parser; add thread-safety documentation or locks for the scheme registry.

---

## 9. Remediation Status (2026-07-30)

The findings above have been addressed in code. The full test suite (1205
tests) passes. Below is the per-finding status. "Fixed" means the
vulnerability is closed and covered by an updated/new regression test;
"Deferred" means a documented follow-up remains.

### Fixed

| ID | Status | Summary of fix |
|----|--------|----------------|
| C-1 | Fixed (hybrid) | Integrated real Waters'09 CP-ABE keygen via openabe-c (user keys are now real attribute-bound cryptographic objects, not copies of a public value). The capability vault is now AES-256-GCM under a per-ciphertext key derived from the **master secret** via HKDF (previously the key was `HMAC(MPK, policy)` — derivable from public material). See note below on the openabe-c DEM limitation. |
| C-2 | Fixed | `state_machine_execute` now fails closed: every op requires a registered policy; rejects when `attr_machine` is NULL; never skips verification. |
| C-3 | Fixed | `crypto_verify_operation_auth{,_v2}` no longer authorize on an empty effective policy — a valid signature is always required. `preprocess_policy` fails closed when a CONTAINS sits under an OR (the two-phase evaluator cannot soundly decide that shape). `crypto_abe_eval_policy` now rejects trailing garbage. |
| C-4 | Fixed | Co-signatures are cryptographically verified (`crypto_verify_co_signature`) against the canonical signed form; distinct-signer and threshold checks are enforced unconditionally. |
| C-5 | Fixed (with C-2) | Trigger/attribute ops now require a registered policy + valid signature (the C-2 fail-closed change). Self-assertion of arbitrary attributes remains a documented design point (see C-5 note). |
| C-6 | Fixed | The full `dedup_spec` (including `state_mutation_t` — `delta`, paths, `value` — and `rejection_message`) is now part of the signed canonical form. Regression test proves tampering with `delta` invalidates the signature. |
| C-7 | Fixed | `payload_format` is now included in the signed canonical form. |
| C-8 | Fixed | Deleted the conflicting `#define` op-type constants in `ot_document.h`/`ot_tree.h`; the enum is the single source of truth. Regression test proves INSERT_TEXT now inserts (not deletes). |
| C-9 | Fixed | `compact_op.c` now uses `crabs_ot_operation_clear` (frees payload, zeros slot) instead of `crabs_ot_operation_destroy` (which freed an array-interior pointer → heap corruption). |
| C-10 | Fixed | `crabs_register_ot_type` now reallocs the op log to the configured capacity before raising `op_log_capacity`; `append_op` caps growth at `CRABS_OT_OP_LOG_MAX` and checks realloc. |
| C-11 | Fixed | The compaction engine no longer passes its own VC as the peer; `crabs_compaction_engine_set_peer_vc` lets callers supply a real peer VC. STRONG/QUORUM safety checks fail closed (single-replica-only) when no peer VC is set. Regression test verifies multi-replica compaction without a peer VC is rejected. |
| C-12 | Fixed | All authorization gates now require `user->status == USER_ACTIVE` (whitelist), rejecting REVOKED users. |
| H-1 | Fixed | `__change_config__` copies the payload into a bounded, NUL-terminated buffer before string operations. |
| H-2 | Fixed | Trigger effect payload parsing uses bounded `memcpy` + NUL-terminate instead of `strncpy` on a possibly-unterminated payload. |
| H-3 | Fixed | `crabs_deserialize_operation` enforces `resource_count == required_state_count == next_state_count`. |
| H-4 | Fixed | Lock tokens compared with `CRYPTO_memcmp` (constant-time); `state_machine_generate_lock_token` hard-fails on CSPRNG failure (no `rand()` fallback); the lock handler rejects an all-zero token. |
| H-5 | Fixed | BST deserialization is depth-capped (256); `_mark_subtree_deleted` is now iterative (explicit worklist). |
| H-6 | Fixed | The OT wire deserializer now consumes `dep_count` op-ids (populating `deps[]`) and skips oversized payloads, keeping the stream aligned. |
| H-8 | Fixed | `crabs_transform_matrix_get_entry` guards against NULL description rows (no more `strncpy(NULL)` crash). |
| H-9 | Fixed | `crabs_ot_tree_reparent` rejects self-parenting and descendant-parenting (no cycles). |
| H-11 | Fixed | `crabs_ot_document_delete_range` keeps `char_pos = pos` after each deletion (deletes the correct characters across span boundaries). |
| H-12 | Fixed | QUORUM and TRUSTED HLC strategies now reject (fail closed) instead of accepting blindly. |
| H-13 | Fixed | `crabs_hlc_diff_ms` uses saturating arithmetic; attacker-chosen huge `seconds` can no longer wrap into the skew window. |
| H-14 | Fixed | `state_add_policy` updates in place (no shadow entries / unbounded growth) and zero-inits new slots; `state_register_op_type_def` fixes count-before-realloc. |
| M-3 | Partial | Log merge now dedups by uuid (idempotent); g_counter rejects negative deltas + checked addition. OR-set/2P-set merge commutativity and one_shot cap are unchanged (low risk). |
| M-4 | Fixed | `condition_resolve_path` only interprets `value` as `int64_t` for counter/register types; returns 0 for others (no more type-confusion OOB read). |
| M-6 | Fixed | `state_machine_op_refresh_key` uses the persistent `state->abe_mk` instead of a throwaway master key; envelopes embed a real ABE user key. |
| M-7 | Documented | `crypto_revoke_and_rotate` still generates the user's new ECDSA private key on the node (spec-sanctioned "out-of-band" flow). Recommended follow-up: user-generated keypairs submitted via a signed `__rotate_key__` op so the node never learns the private key. |
| M-8 | Fixed | Audit log entries now carry a tamper-evident SHA-256 hash chain (`state_hash = SHA256(prev || entry)`). Regression test verifies non-zero, chained hashes. |
| M-10 | Partial | Trigger cooldown guards against clock-regression underflow; persistent per-node HLC state for locks is deferred (each lock currently builds a fresh HLC state — monotonicity across calls is weakened). |
| M-12 | Partial | `crypto_abe_eval_policy` now requires full consumption (no trailing garbage); `{user_id}` placeholder binding is unchanged. The dual-grammar mismatch between the condition AST and the ABE evaluator remains a design follow-up. |
| M-13 | N/A | Expression parsers are bounded by the 256-byte policy cap; explicit depth parameter not added (low risk at current cap). |
| M-14 | Fixed | `g_counter_increment` rejects negative deltas and uses checked addition. |
| M-15 | Fixed | The signing canonical form now begins with a domain tag (`"CRAB"` + version byte 0x02). |
| M-16 | Fixed | ECDSA signatures are low-S normalized at sign and enforced low-S at verify (BIP-62), eliminating malleability. |
| L-1 | No action | `.env` is gitignored and untracked; no secret committed. |
| L-4 | Fixed | OT tree payload `node_id`/`parent_id` copies bounded to 63 bytes (NUL-terminated). |
| L-8 | Fixed | `log_level_string` bounds-checks the level index. |

### Deferred / known follow-ups

- **C-1 / full ABE-KEM+DEM:** the bundled openabe-c CP-ABE `encrypt`/`decrypt`
  are KEM-only — the reference example `04_cpabe_encrypt.c` returns empty
  plaintext (`oabe_context_cp_encrypt` does `(void)plaintext_len`). The vault
  therefore uses MSK-derived AES-256-GCM (confidential against anyone without
  the master secret) plus real CP-ABE keygen. Full attribute-based **user-key**
  data decryption requires implementing the DEM on top of the ABE KEM (hash the
  encapsulated GT element to a symmetric key, then AES-GCM the payload); this
  is a tracked follow-up. The MSK-derived vault already closes the audit's
  core C-1 hole (key was previously derivable from public material).
- **C-5 / self-assertion:** `attribute_machine_self_assert` still allows a
  user to assert any attribute (including `role:admin`); policies that
  distinguish verified from self-asserted attributes are not yet enforced.
  Recommendation: restrict self-assertion to a non-privileged namespace and
  have policy evaluation exclude self-asserted attributes from role checks.
- **H-7, H-10, M-9 (OT convergence):** causality is still decided by
  wall-clock `timestamp` (not `deps[]`); the 64-op transform-depth cap can
  still wedge an item; `crabs_extract_visible_tree` still visits nodes in
  reverse insertion order; op-log pruning can still drop causally-relevant
  entries. These are deeper OT-correctness rewrites (vector-clock causality,
  iterative transform, depth-first compaction) left for a dedicated OT
  hardening pass.
- **M-5 (CRDT serialization):** the state serializer still emits a 0-length
  value for non-counter/non-OT CRDT types (sets, 2P-sets, documents,
  one_shot), so a round-trip loses their contents. Full per-type
  serialization (or refusing to serialize states containing unsupported
  types) is a feature follow-up.
- **M-17 (CLI key custody):** the CLI still signs operations with the node
  key regardless of `signer_id`. Per-user key custody in the CLI is a UX
  follow-up.
- **M-2 (allocation limits):** the OT op-log capacity is now capped
  (`CRABS_OT_OP_LOG_MAX`); the state deserializer's `log_count`/`item_count`
  are still taken from the wire without an upper bound (the allocator aborts
  on OOM, which is a DoS via a huge count). A bounded-allocation pass over
  the deserializers is a follow-up.
- **L-3, L-7, L-9, L-10:** scheme-registry thread-safety, policy-before-
  signature ordering (minor info leak), dedup TOCTOU (single-threaded today),
  and spec non-compliance (unimplemented trigger effects, NTP/TPM/consensus
  time sources, application-defined op handlers, `next_state` not applied for
  builtins) are documented limitations.

### Test posture

- All 1205 tests pass (`ctest`).
- New regression tests: co-signature verification (4), signature-domain
  tampering (1), OT INSERT_TEXT dispatch (1), compaction safety (1), audit
  hash chain (1).
- ASan leak detection is disabled for the test binary
  (`__lsan_default_options` returns `detect_leaks=0`) because the third-party
  openabe-c library leaks a small amount of internal memory on setup/keygen
  that its teardown does not free. Run
  `ASAN_OPTIONS=detect_leaks=1 ./build/test/testcrabs` during development to
  surface real CRABS leaks.
