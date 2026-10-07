# Lineage Core (Machine Minting) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Machines mint machines: a `__spawn_machine__` op instantiates child machines from fully-serializable blueprints under three trust modes, bridged by parent-signed cross-domain attestations, with full parent-side lineage ops (revoke attestation, dissolve, withdraw genesis).

**Architecture:** New `src/Lineage/` module. The parent keeps a `child_manifest[]` in its `state_t` (serialized). Child machines are real `attribute_machine_t` + `state_t` units created from a `machine_blueprint_t`; trust profile per blueprint (SHARED_ROOT / DELEGATED_COPY / SOVEREIGN). Cross-domain endorsement is an ABE-policy token (`@parent/attr`) resolved only against parent-signed, TTL-bounded attestations carried in the op. Serialization bumps to **v11** to carry the real manifest content + the child's parent binding (v10's booked position was a 0-count placeholder).

**Tech Stack:** C11, OpenSSL (ECDSA/SHA-256), OpenABE/relic (CP-ABE authority for DELEGATED_COPY), GoogleTest.

**Spec:** `docs/superpowers/specs/2026-10-06-machine-minting-design.md`
**Prerequisite (landed):** Plan 1 durability kernel — commits up to `3c96f53` (v10 sections, `crabs_serialize_state_sealed`, `crypto_master_key_*`, `crypto_seal/unseal`, CLI seal-key custody, `state migrate`).

**Style:** docs/STYLE_GUIDE.md — `_t` types, `module_action()` names, NO single-letter variable names, minimal comments. No Co-Authored-By. Build/test: `cmake --build build -j && ctest --test-dir build/test --output-on-failure` (suite ~1460; 1 known env-dependent skip `TimeSourceIntegration.JsonTimeApi`).

**Real repo names to use (verified):** `CRABS_ERR_INVALID_PARAM` / `CRABS_ERR_UNAUTHORIZED` / `CRABS_ERR_CRYPTOGRAPHIC_ERROR` (crabs.h — there is NO CRABS_ERR_ARGS/ERR_EXEC); `ECDSA_SECP256K1` (sig_scheme.h:17); `state_register_op_type_def` / `state_find_op_type_def` → `const dedup_spec_t*`; `attribute_machine_user_has_role(user, "role")` matches the NAME part before ':'; policy grammar for `crypto_abe_eval_policy` is UPPERCASE infix `AND`/`OR`; ABE policies for `crypto_abe_encrypt` must be OpenABE-grammar (`role_admin`, not `role:admin`); privileged attribute names (`role:*`) are blocked from `register_user` initial_attrs (R7-08). Policy grammar error → `CRABS_ERR_UNAUTHORIZED`; op auth pipeline: state_machine.c `_verify_operation_authorization` (617-673) → `preprocess_policy` (condition.c:1296) → `crypto_verify_operation_auth[_v2]`.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/Lineage/lineage.h` / `.c` (Create) | Blueprint type + validation, child manifest, trust-mode spawn, lineage ops, attestation issuance/verification |
| `src/Condition/condition.c` (Modify) | `preprocess_policy` recognizes and strips `@parent/...` endorsement tokens into the result struct |
| `src/Condition/condition.h` (Modify) | `policy_preprocess_result_t` gains parent-endorsement list |
| `src/StateMachine/state_machine.c` (Modify) | Auth pipeline consumes attestations; `operation_t` gains attestation fields (state_machine.h) |
| `src/Serialization/serialization.h` / `.c` (Modify) | v11: manifest content + parent binding; sealed+signed centralization; authority-restoration reporting |
| `src/CRABS/data_model.h` / `data_model.c` (Modify) | `state_t` gains manifest + parent binding; change kinds SPAWN/LINEAGE; destroy wiring |
| `src/CLI/cli.h` / `cli.c` (Modify) | Only the load-time authority-restoration warning (the CLI surfaces land in Plan 3) |
| `test/test_lineage.cpp` (Create) | Blueprint, spawn modes, attestations, lifecycle — registered in `test/CMakeLists.txt` |

---

### Task 1: Authority-restoration reporting (Plan-1 follow-up #1)

**Files:**
- Modify: `src/Serialization/serialization.h` (API block after `crabs_deserialize_state_keys`)
- Modify: `src/Serialization/serialization.c` (`_deserialize_state_internal`)
- Modify: `src/CLI/cli.c` (load warnings; cli_node_load + cli_node_load_sealed)
- Test: `test/test_serialization.cpp` (append)

- [ ] **Step 1: Failing test** — the sealed file loaded with a WRONG key must be distinguishable from a file with no MSK section:

```cpp
TEST(TestSerialization, AuthorityRestorationIsReportable) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  uint8_t seal_key[32];
  ASSERT_EQ(crypto_random_bytes(seal_key, sizeof(seal_key)), CRABS_SUCCESS);

  serialized_buffer_t* buf = crabs_serialize_state_sealed(state, seal_key);
  ASSERT_NE(buf, nullptr);

  uint8_t wrong_key[32];
  memcpy(wrong_key, seal_key, 32);
  wrong_key[0] ^= 0xFF;

  bool authority_restored = true;
  bool msk_section_present = false;
  state_t* wrong = crabs_deserialize_state_keys_reported(
      buf->data, buf->len, wrong_key, &authority_restored, &msk_section_present);
  ASSERT_NE(wrong, nullptr);
  EXPECT_FALSE(authority_restored);
  EXPECT_TRUE(msk_section_present);

  authority_restored = false;
  state_t* correct = crabs_deserialize_state_keys_reported(
      buf->data, buf->len, seal_key, &authority_restored, &msk_section_present);
  ASSERT_NE(correct, nullptr);
  EXPECT_TRUE(authority_restored);
  EXPECT_TRUE(msk_section_present);
  state_destroy(correct);
  state_destroy(wrong);
  serialized_buffer_destroy(buf);
  state_destroy(state);
}
```

- [ ] **Step 2: Verify failure** — `cmake --build build -j` → undeclared `crabs_deserialize_state_keys_reported`.

- [ ] **Step 3: Implement** — in serialization.h:

```c
// v10+ load with restoration reporting: *authority_restored is true only when
// a sealed MSK section was present AND unsealed with the provided key;
// *msk_section_present reports whether the authority section existed at all.
// Either out-param may be NULL. Returns a state with a LIVE (restored or
// fresh) MSK in every case — see the base function's contract.
state_t* crabs_deserialize_state_keys_reported(const uint8_t* data, size_t len,
                                                 const uint8_t seal_key[32],
                                                 bool* authority_restored,
                                                 bool* msk_section_present);
```

Refactor `_deserialize_state_internal` to accept the two trailing out-params
(`bool* authority_restored, bool* msk_section_present`; both nullable, default
false/false) — the MSK section block sets `*msk_section_present = true` on the
sealed path and `*authority_restored = true` only when
`crypto_master_key_deserialize` succeeded (the existing unseal-then-restore
logic — keep it; just thread the reporting). The plain
`crabs_deserialize_state` / `crabs_deserialize_state_keys` remain thin
wrappers passing NULL/NULL.

In cli.c, both deserialize call sites switch to the reported variant and warn:

```c
    bool authority_restored = false;
    bool msk_section_present = false;
    state_t* loaded = crabs_deserialize_state_keys_reported(
        data, payload_len,
        node->seal_key_valid ? node->seal_key : NULL,
        &authority_restored, &msk_section_present);
    if (msk_section_present && !authority_restored) {
      fprintf(stderr,
              "WARNING: this snapshot's master secret key could NOT be "
              "restored (wrong or missing seal key) — a FRESH authority was "
              "created; re-enroll via 'state migrate' instead of trusting "
              "signatures against this authority\n");
    }
```
(apply to BOTH the signed-parse and unsigned-parse call sites)

- [ ] **Step 4: Green** — targeted + full suite.
- [ ] **Step 5: Commit** — `feat: report authority restoration on sealed loads`

---

### Task 2: Sealed+signed serialization centralization (Plan-1 follow-up #2)

**Files:** `src/Serialization/serialization.h`/`.c`, `src/CLI/cli.c`, Test: `test/test_cli.cpp` (append)

- [ ] **Step 1: Failing test**

```cpp
TEST(TestSerialization, SealedSignedBlobComposesSealAndSignature) {
  cli_node_t* node = cli_node_create();
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  ASSERT_TRUE(_apply_test_seal_key(node));
  ASSERT_EQ(cli_node_save(node, "/tmp/crabs-sealed-signed.crabs"), CLI_OK);
  cli_node_destroy(node);

  cli_node_t* reloaded = cli_node_create();
  const uint8_t test_seal_key[32] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
  };
  char seal_hex[65];
  cli_bytes_to_hex(test_seal_key, 32, seal_hex);
  seal_hex[64] = '\0';
  // The sealed file loads through the EXISTING cli_node_load path (signed
  // parse first) and the import verifies the signature — proving the
  // composition produces the same wire shape the signed loader expects.
  ASSERT_EQ(cli_node_load(reloaded, "/tmp/crabs-sealed-signed.crabs"), CLI_OK);
  ASSERT_TRUE(reloaded->state_sig_pending);   // signature present + pending
  cli_node_destroy(reloaded);
  remove("/tmp/crabs-sealed-signed.crabs");
}
```

(This test PASSES today — it is the characterization test for the new
centralized API; write it FIRST, then the API.)

- [ ] **Step 2: Implement** — serialization.h:

```c
// Sealed + node-key-signed full snapshot: _serialize_state_internal with
// seal_key, then the ECDSA trailer from state->node_private_key. Returns NULL
// when the state has no valid node key or no MSK.
serialized_buffer_t* crabs_serialize_state_sealed_signed(const state_t* state,
                                                           const uint8_t seal_key[32]);
```

Extract the trailer-appending logic from `crabs_serialize_state_signed`
(serialization.c ~2027) into `static serialized_buffer_t* _append_state_signature(serialized_buffer_t* blob, const state_t* state)` returning NULL when
`!state->node_key_valid`; both signed variants (`crabs_serialize_state_signed`
and the new sealed_signed) call it. Replace cli_node_save's inline composition
(cli.c ~465-490) with a single call to `crabs_serialize_state_sealed_signed`.

- [ ] **Step 3: Suite green; commit** — `refactor: centralize sealed+signed snapshot composition`

---

### Task 3: Lineage data model — manifest, parent binding, blueprint types

**Files:**
- Create: `src/Lineage/lineage.h`, `src/Lineage/lineage.c`
- Modify: `src/CRABS/data_model.h` (state_t), `data_model.c` ( destroy)
- Test: `test/test_lineage.cpp` (Create) + `test/CMakeLists.txt` (register)

- [ ] **Step 1: Types in lineage.h** (spec §Architecture + §Blueprint payload):

```c
typedef enum {
  LINEAGE_SHARED_ROOT    = 0x01,
  LINEAGE_DELEGATED_COPY = 0x02,
  LINEAGE_SOVEREIGN      = 0x03
} lineage_trust_mode_e;

typedef enum {
  LINEAGE_ACTIVE    = 0x00,
  LINEAGE_DISSOLVED = 0x01,
  LINEAGE_WITHDRAWN = 0x02
} lineage_status_e;

typedef struct {
  char                 child_id[CRABS_MAX_USER_ID];
  lineage_trust_mode_e mode;
  uint8_t              genesis_snapshot_hash[CRABS_HASH_SIZE];
  uint8_t              genesis_attestation_signature[CRABS_SIG_SIZE];
  uint64_t             attestation_ttl_ms;
  uint64_t             spawned_at;
  lineage_status_e     status;
} child_manifest_entry_t;

#define CRABS_MAX_CHILD_MACHINES 64

// Cross-domain endorsement (spec §attestation bridge). Format version 0x01
// — independent of key_envelope_t's 0x03.
#define CRABS_ATTESTATION_FORMAT_VERSION 0x01

typedef struct {
  uint8_t  format_version;
  char     parent_id[CRABS_MAX_USER_ID];
  char     child_id[CRABS_MAX_USER_ID];
  char     user_id[CRABS_MAX_USER_ID];
  char     attributes[CRABS_MAX_POLICY_EXPR];   // comma-separated name:value pairs
  uint64_t not_before;
  uint64_t expires_at;                            // not_before + ttl <= expires_at
  uint8_t  signature[CRABS_SIG_SIZE];             // parent ECDSA over canonical body
} attestation_t;

// Blueprint: fully serializable machine definition (spec §Blueprint payload).
typedef struct {
  char                 child_id[CRABS_MAX_USER_ID];
  lineage_trust_mode_e trust_mode;
  char                 bootstrap_admin[CRABS_MAX_USER_ID];
  uint64_t             attestation_ttl_ms;
  // Items: name + type + crdt type + optional initial value
  struct {
    char        name[CRABS_MAX_USER_ID];
    data_type_e type;
    crdt_type_e crdt_type;
  }* items;
  uint32_t              item_count;
  struct {
    char               operation[CRABS_MAX_OP_NAME];
    char               expression[CRABS_MAX_POLICY_EXPR];
  }* policies;
  uint32_t              policy_count;
  struct {
    char         op_type[CRABS_MAX_OP_NAME];
    dedup_spec_t dedup;
  }* op_type_defs;
  uint32_t              op_type_def_count;
  uint8_t               blueprint_hash[CRABS_HASH_SIZE];  // stamped at build
} machine_blueprint_t;
```

data_model.h `state_t` additions (place after `op_handler_count`):

```c
  // Lineage (v1.7 §machines-mint-machines): children this machine spawned.
  child_manifest_entry_t* children;      // requires lineage.h inclusion — put
                                          // the TYPE in data_model.h instead
                                          // to avoid a cycle (move the struct)
  uint32_t                child_count;
  // This machine's parent binding (present only for spawned children):
  char    lineage_parent_id[CRABS_MAX_USER_ID];
  uint8_t lineage_parent_public_key[33];
  bool    lineage_parent_bound;
```

(Resolve the header-cycle: `child_manifest_entry_t` lives in data_model.h and
lineage.h includes data_model.h — the enum + entry struct are DATA MODEL types.
Attestation/blueprint stay in lineage.h.)

- [ ] **Step 2: Blueprint validation** in lineage.c — `crabs_error_e lineage_blueprint_validate(const machine_blueprint_t* blueprint);`:
  checks: child_id non-empty, safe charset (`_is_safe_user_id` idiom — copy the
  predicate into lineage.c or expose it from attribute_machine as
  `attribute_machine_is_safe_user_id(const char*)`; prefer exposing), lengths,
  policy parseability (`condition_parse` on each policy expression), item names
  safe + unique, counts within config caps, trust_mode within enum, and for
  DELEGATED_COPY/SOVEREIGN bootstrap_admin safe. Error family:
  `CRABS_ERR_INVALID_POLICY`-style — use existing nearest real enumerators.

- [ ] **Step 3: Tests** (test/test_lineage.cpp, registered in test/CMakeLists.txt
  before test_sig_scheme.cpp): valid blueprint builds; rejects empty id, unsafe
  id (`"AND"`, `"a<b"`, over-long), malformed policy (lowercase `or`),
  duplicate item names, unknown trust mode. Include parent-binding round trip
  through serialization? — deferred to Task 6 (v11).

- [ ] **Step 4: Suite green; commit** — `feat: lineage data model, blueprint validation`

---

### Task 4: Attestation issue/verify/serialize

**Files:** `src/Lineage/lineage.h`/`.c`, Test: `test/test_lineage.cpp`

- [ ] **Step 1: Failing tests**

```cpp
TEST(TestLineage, AttestationSignVerifyRoundTrip) {
  state_t* parent = state_create();     // needs a node key to sign
  // node key via state_set_node_key with a generated ecdsa keypair
  ecdsa_keypair_t* parent_key = crypto_ecdsa_generate();
  ASSERT_NE(parent_key, nullptr);
  ASSERT_EQ(state_set_node_key(parent, parent_key->private_key,
            parent_key->public_key), CRABS_SUCCESS);

  uint64_t now = 1'700'000'000'000;      // fixed test epoch, ms
  attestation_t attestation = {0};
  TEST_ASSERT(attestation_create(parent, &attestation,
      "parent-root", "child-red", "alice",
      "role:writer,dept:red", now, now + 60000) == CRABS_SUCCESS);

  // Positive: correct parent key, correct child, inside window.
  EXPECT_TRUE(attestation_verify(parent_key->public_key, "child-red",
                                 &attestation, now));
  // Negative: wrong child id.
  EXPECT_FALSE(attestation_verify(parent_key->public_key, "child-blue",
                                  &attestation, now));
  // Negative: expired.
  EXPECT_FALSE(attestation_verify(parent_key->public_key, "child-red",
                                  &attestation, now + 120000));
  // Negative: tampered attributes.
  attestation.attributes[6] ^= 0x01;
  EXPECT_FALSE(attestation_verify(parent_key->public_key, "child-red",
                                  &attestation, now));
  attestation.attributes[6] ^= 0x01;

  // Byte transport.
  uint8_t wire[2048];
  size_t wire_len = attestation_serialize(&attestation, wire, sizeof(wire));
  ASSERT_GT(wire_len, (size_t)0);
  attestation_t* restored = attestation_deserialize(wire, wire_len);
  ASSERT_NE(restored, nullptr);
  EXPECT_TRUE(attestation_verify(parent_key->public_key, "child-red",
                                 restored, now));
  attestation_destroy(restored);
  crypto_ecdsa_keypair_destroy(parent_key);
  state_destroy(parent);
}
```

- [ ] **Step 2: Implement** — canonical signing body is
  `format_version + parent_id + child_id + user_id + attributes + not_before +
  expires_at` (fixed-width fields, string16-style length-prefixed), signed with
  `crypto_ecdsa_sign(state->node_private_key, ...)`. Wire format mirrors it
  with a `u32` total-length prefix. `attestation_verify(pub, child_id,
  attestation, now)`: format check, child_id exact match, `not_before <= now
  <= expires_at`, `crypto_ecdsa_verify`. Names per style guide
  (`attestation_create` takes `state_t*` for the signer key; document that).

- [ ] **Step 3: Suite green; commit** — `feat: cross-domain attribute attestations`

---

### Task 5: Policy token `@parent/...` + auth pipeline integration

**Files:**
- Modify: `src/Condition/condition.h` (`policy_preprocess_result_t`), `condition.c` (`preprocess_policy`)
- Modify: `src/StateMachine/state_machine.h` (`operation_t` fields), `state_machine.c` (`_verify_operation_authorization`)
- Test: `test/test_durability.cpp` (append — it already has the full-stack CLI harness) or `test/test_lineage.cpp`

- [ ] **Step 1: Design point (read this before coding).** Policies are ABE
  expression strings evaluated by `crypto_abe_eval_policy(policy, attrs)`.
  Endorsement tokens MUST be resolved out of the ABE string (OpenABE grammar
  cannot carry them) and checked in the auth pipeline where the op's
  attestations are available:

  `policy_preprocess_result_t` gains `char parent_endorsements[8][CRABS_MAX_POLICY_EXPR]; uint32_t parent_endorsement_count;` —
  `preprocess_policy` extracts every `@parent/<attr>` token (e.g.
  `@parent/role:writer`) into that list and removes it from `abe_policy`
  (whitespace collapse). Parse errors on `@parent/` (empty attr, nested
  `@`) → `resolved_ok = false`.

  In `_verify_operation_authorization` (state_machine.c:617-673), AFTER
  signature verification succeeds: for each `parent_endorsement`, require the
  op to carry a matching attestation
  (`op->attestations`/`op->attestation_count` — new `operation_t` fields, placed
  after `co_signature_count`; serialized as a v12 OPERATION format field, see
  below) verified against the machine's lineage parent binding
  (`state->lineage_parent_bound`, pubkey) — child_id must equal this machine's
  own id. The attested USER must be the resolved signer. Collect verified
  attested attribute strings and evaluate the endorsements themself via
  direct string membership (attribute `dept:red` attested ⇔ endorsement
  `@parent/dept:red` satisfied by ANY verified attestation covering the signer).
  Missing attestation → `CRABS_ERR_UNAUTHORIZED` (no fail-open).

  Restraint: endorsements are checked EXACTLY as written; no boolean
  composition in v1 (an endorsement list is AND-ed with the local ABE policy,
  which is fine for v1 semantics; the policy can express OR locally).

- [ ] **Step 2: `operation_t` wire bump**: operation serialization gains
  attestation count + bodies; `CRABS_OP_SERIAL_VERSION` bumps one level — find
  the actual constant in serialization.c (`crabs_serialize_operation`) and
  follow its version-gating idiom EXACTLY (same pattern as the state format).

- [ ] **Step 3: Tests** — attestation-granted op authorization on a spawned
  delegated child is Task 7's scope; HERE: unit tests on preprocess_policy
  (`@parent/role:writer OR role:admin` preprocesses to endorsement +
  `role:admin`; three `@parent/` tokens → count 3; malformed → resolved_ok
  false) and an operation round-trip carrying attestations through
  `crabs_serialize_operation`.

- [ ] **Step 4: Suite green; commit** — `feat: @parent endorsement policy tokens with attested op verification`

---

### Task 6: Manifest + parent binding serialization (v11)

**Files:** `src/Serialization/serialization.h`/`.c`, Test: `test/test_serialization.cpp`

- [ ] **Step 1: Failing test** — round trip a state with 2 manifest entries +
  parent binding; assert ids/mode/status/hash/ttl survive; a manifest entry with
  garbage mode fails the load.

- [ ] **Step 2: Implement** — `CRABS_SERIAL_VERSION` 11: the child-manifest
  position (booked in v10 as u32 child_count) becomes `u32 child_count + entries
  { string16 child_id; u8 mode; 32B hash; 64B signature; u64 ttl; u64 spawned_at;
  u8 status }` followed by the parent-binding block
  `u8 bound; if 1: string16 parent_id + 33B pubkey` — v11 reader accepts v10
  blobs by gating both blocks on `version >= 11`. Reader caps:
  `count > CRABS_MAX_CHILD_MACHINES` → fail; mode values outside the enum →
  fail; bound flag > 1 → fail. data_model.c `state_destroy` frees
  `state->children` (array free) — check it is a heap array, keep single-owner.

- [ ] **Step 3: Suite green; commit** — `feat: lineage manifest + parent binding persisted (v11)`

---

### Task 7: Spawn — the three trust modes

**Files:** `src/Lineage/lineage.h`/`.c`, Test: `test/test_lineage.cpp`

- [ ] **Step 1: Failing tests** — IN-PROCESS spawn per mode:

```cpp
TEST(TestLineage, SpawnSharedRootSharesParentAuthority) {
  // parent: attr machine + node key + admin; user with role:admin
  // blueprint: SHARED_ROOT, items "counter"
  // lineage_spawn_machine(parent, &blueprint, &child) → CRABS_SUCCESS
  // child->attr_machine == parent->attr_machine (SAME pointer)
  // parent manifest gains entry (child_id, mode, ACTIVE)
  // genesis snapshot hash in manifest == sha256 of child's serialized genesis
  // policy for child op "increment" requires "custody:child-red"
  // op executed by a parent-registered user WITHOUT custody attr → denied
  // parent grants custody:red → op passes
}
TEST(TestLineage, SpawnDelegatedCopyMintsFreshAuthority) {
  // child->attr_machine != parent->attr_machine; child->base_state.abe_mk != NULL
  // and != parent MSK; genesis manifest entry present; child bootstrap admin exists
}
TEST(TestLineage, SpawnSovereignGeneratesOwnMsk) {
  // same assertions as delegated; PLUS parent manifest has no live authority:
  // genesis attestation signature present but child is self-minted
}
TEST(TestLineage, SpawnRejectsOverLimitChildren) {
  // spawn CRABS_MAX_CHILD_MACHINES then one more → error, no partial manifest
}
```

- [ ] **Step 2: Implement** — `crabs_error_e lineage_spawn_machine(
  state_t* parent, const machine_blueprint_t* blueprint, attribute_machine_t** child_out);`

  Order of operations (fail-safe, no partial residue):
  1. validate blueprint; check parent admin-gate is the CALLER's job (spawn is
     invoked through the op handler, which is behind the op's policy).
  2. child_id uniqueness within `parent->children` (and ≠ parent's own id).
  3. Build child per mode:
     - SHARED_ROOT: child shell = heap attribute_machine_t; base_state fields
       set from blueprint items/policies/op_type_defs; `base_state.attr_machine
       = parent->attr_machine` (SHARE the pointer — one authority);
       bootstrap admin entry created IN THE SHARED registry ONLY as a
       user-reference (no duplicate user) — child machine's config.bootstrap_admin
       records the id; the custody attribute namespacing
       (`custody:<child_id>`) is enforced by the child's op policies (blueprint
       authors write them; spawn validates each child policy contains at least
       one `custody:` guard? NO — that policy choice belongs to protocol
       authors; spawn does NOT impose it. Document in spawn's header comment.)
     - DELEGATED_COPY: fresh `crypto_abe_setup()` authority for the child;
       child gets its own attr machine with bootstrap admin from the blueprint
       (register + genesis-equivalent role:admin write — the SAME two-step
       genesis construction proven in Plan 1's migrate task).
     - SOVEREIGN: same as DELEGATED_COPY but the spawn marks that the parent
       may only withdraw, never dissolve (mode recorded in manifest).
  4. Genesis snapshot: `crabs_serialize_state_sealed_signed`-style but WITHOUT
     the seal (genesis is empty authority: use `crabs_serialize_state_signed`
     on the child's base_state with the PARENT's node key — so the manifest
     signature is over the actual bytes); SHA-256 the genesis blob into
     `genesis_snapshot_hash`; store parent signature in the manifest entry.
  5. Parent binding on the child: `lineage_parent_bound = true`,
     `lineage_parent_id = parent.config.bootstrap_admin`(or machine id — same
     string), `lineage_parent_public_key = parent node pub`.
  6. Manifest append LAST; change-hook event: new kind
     `CRABS_CHANGE_SPAWN` (data_model.h enum + all switch/comment updates —
     grep `CRABS_CHANGE_ATTRIBUTE` for every touchpoint).

- [ ] **Step 3: Suite green; commit** — `feat: lineage spawn with three trust modes`

---

### Task 8: Lineage ops + spawn op wiring

**Files:** `src/Lineage/lineage.h`/`.c`, `src/StateMachine/state_machine.c` (handler registry integration), Test: `test/test_lineage.cpp`

- [ ] **Step 1: Failing tests**

  - `spawn_via_op`: register `__spawn_machine__` handler + policy
    ("role:admin") on a parent; op payload = serialized blueprint (u32-prefixed
    blueprint serialization — Task 3 omitted blueprint wire format; HERE:
    `blueprint_serialize`/`blueprint_deserialize` mirroring state sections,
    with the blueprint_hash field computed over the canonical body before the
    hash field); execute as admin → child exists + manifest entry. Dedup spec
    on the spawn op registered via `state_register_op_type_def` (per-child id
    guard optional — leave to protocol authors; test with DEDUP_NONE).
  - `revoke_attestation_via_op`: `__revoke_attestation__` flips the entry's
    issuing status; subsequent `crabs_issue_attestation` for that child fails
    (`CRABS_ERR_NOT_PERMITTED`-family — nearest existing error).
  - `dissolve_via_op`: `__dissolve_machine__` on SHARED_ROOT/DELEGATED_COPY →
    status DISSOLVED + tombstone serialized into the manifest entry; sovereign →
    CRABS_ERR_NOT_PERMITTED.
  - `withdraw_genesis_via_op`: sovereign only; others → CRABS_ERR_NOT_PERMITTED;
    status → WITHDRAWN.

- [ ] **Step 2: Implement** — public functions
  `lineage_op_spawn/lineage_op_revoke_attestation/lineage_op_dissolve/
  lineage_op_withdraw_genesis` (op-handler signature
  `crabs_error_e (*)(state_t*, operation_t*)`), plus the convenience installer
  `void lineage_install(state_t* state)` that registers all four handlers +
  `__spawn_machine__`/`__revoke_attestation__`/`__dissolve_machine__`/
  `__withdraw_genesis__` policies ("role:admin AND role:custodian" for spawn,
  "role:admin" for the rest) — a protocol may override policies afterwards;
  installer re-registers nothing that exists. All four flow through
  `state_machine_register_handler`; no builtin-chain changes.

- [ ] **Step 3: End-to-end revocation-timing test** (the custody payoff):

```cpp
TEST(TestLineage, DelegatedChildLosesEndorsementAfterAttestationExpiry) {
  // parent + delegated child + parent-endorsement policy `@parent/role:writer`
  // on child op "render"; attestation issued with ttl; op authorized inside
  // window; clock advances past expiry (attribute_machine_set_time +
  // state_get_time_ms idiom from test_time_source / existing expiry tests) →
  // op FAILS CRABS_ERR_UNAUTHORIZED without re-issued attestation.
}
TEST(TestLineage, SharedRootChildStopsInstantlyOnParentRevoke) {
  // attribute_machine_revoke_role(am, "alice", "custody") on the parent →
  // child op denied immediately (no attestations involved).
}
```

- [ ] **Step 4: Suite green; commit** — `feat: lineage ops — spawn/revoke/dissolve/withdraw via operation pipeline`

---

### Task 9: Persistence end-to-end + de-wonk gate

**Files:** Test: `test/test_lineage.cpp` (+ any fixes the test surfaces)

- [ ] **Step 1: The restart proof** — spawn (delegated) → save BOTH machines
  (parent: `crabs_serialize_state_sealed_signed` + child state file) → destroy
  → reload parent (verify manifest signature over genesis hash intact) →
  reload child (`crabs_deserialize_state_keys_reported`, authority_restored) →
  child op still authorized; `lineage_query_children(parent)` returns the entry
  (API: `uint32_t lineage_query_children(const state_t* state,
  const child_manifest_entry_t** out_entries);` — out points at the internal
  array; borrowed, not owned).

- [ ] **Step 2: De-wonk the lineage module** — every changed/new file; the five
  categories; fix CRITICAL/HIGH; loop round 2.

- [ ] **Step 3: Commit** — `test: lineage survives restart; parent manifest signature verified`

---

## Sequencing Notes

- Tasks build on each other: 1-2 are Plan-1 follow-ups (standalone); 3→4→5→6→7→8
  are strictly ordered (types → attestations → policy/token → v11 → spawn →
  ops); 9 closes with the restart proof + the de-wonk gate.
- Plan 3 (CLI/wasm/devtools) is authored after this plan executes.
- Spawn handlers are CUSTOM ops on the parent behind admin policies — the
  state machine's builtin chain stays untouched (matches spec §Spawn interface).

## Known Constraints Carried From Plan 1/Spec

- `attribute_machine_register_user` cannot mint `role:*` via initial_attrs
  (R7-08); genesis-equivalent two-step (register empty + direct write) is the
  established, reviewed pattern (Plan 1 Task 5).
- `crypto_abe_keygen` attrs must be CRABS-form (`role:writer`); encryption
  policies must be OpenABE-form (`role_writer`) — the two grammars differ by
  design (`_crabs_attrs_to_oabe`).
- The `@parent/` token is AND-composed with the local ABE policy in v1; boolean
  compositions over endorsements are out of scope (spec v1).
- Attestation revocation is TTL-bounded by design (spec §attestation bridge);
  the dissolve tombstone voids outstanding attestations immediately for
  non-sovereign children (enforced at child auth: manifest status of the
  parent binding is checked via the CHILD's stored binding + its DISSOLVED
  receipt — the tombstone delivery is an op on the child carrying the parent's
  manifest-tombstone signature).