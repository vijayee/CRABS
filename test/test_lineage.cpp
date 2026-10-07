//
// Lineage data model tests: machine blueprints, blueprint validation,
// child manifest entries, and the state_t lineage fields (parent binding).
//

#include <gtest/gtest.h>
#include <cstdlib>
#include <cstring>
#include <string>

extern "C" {
#include "../src/Lineage/lineage.h"
#include "../src/CRABS/data_model.h"
#include "../src/CRABS/crabs.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/crypto.h"
}

// ============================================================
// Helpers
// ============================================================

// A blueprint that satisfies every validation rule: shared-root trust,
// one item, one policy, one op type definition.
static machine_blueprint_t* make_valid_blueprint() {
  machine_blueprint_t* blueprint = machine_blueprint_create();
  EXPECT_NE(blueprint, nullptr);
  strncpy(blueprint->child_id, "child-red", sizeof(blueprint->child_id) - 1);
  blueprint->trust_mode = LINEAGE_SHARED_ROOT;
  strncpy(blueprint->bootstrap_admin, "parent-admin",
          sizeof(blueprint->bootstrap_admin) - 1);
  blueprint->attestation_ttl_ms = 60000;

  EXPECT_EQ(blueprint_add_item(blueprint, "counter", DATA_TYPE_COUNTER,
                               CRDT_G_COUNTER), CRABS_SUCCESS);
  EXPECT_EQ(blueprint_add_policy(blueprint, "increment",
                                 "custody:child-red"), CRABS_SUCCESS);

  dedup_spec_t dedup;
  memset(&dedup, 0, sizeof(dedup));
  dedup.type = DEDUP_NONE;
  EXPECT_EQ(blueprint_add_op_type_def(blueprint, "increment", &dedup),
            CRABS_SUCCESS);

  EXPECT_EQ(lineage_blueprint_validate(blueprint), CRABS_SUCCESS);
  return blueprint;
}

// ============================================================
// Blueprint lifecycle + validation
// ============================================================

TEST(TestLineage, ValidBlueprintPassesValidation) {
  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);
  EXPECT_EQ(blueprint->item_count, 1u);
  EXPECT_EQ(blueprint->policy_count, 1u);
  EXPECT_EQ(blueprint->op_type_def_count, 1u);
  machine_blueprint_destroy(blueprint);
}

TEST(TestLineage, NullBlueprintIsRejected) {
  EXPECT_EQ(lineage_blueprint_validate(nullptr), CRABS_ERR_INVALID_PARAM);
  machine_blueprint_destroy(nullptr);  // no-crash
}

TEST(TestLineage, RejectsEmptyChildId) {
  machine_blueprint_t* blueprint = machine_blueprint_create();
  ASSERT_NE(blueprint, nullptr);
  blueprint->child_id[0] = '\0';
  blueprint->trust_mode = LINEAGE_SHARED_ROOT;
  EXPECT_EQ(lineage_blueprint_validate(blueprint), CRABS_ERR_INVALID_PARAM);
  machine_blueprint_destroy(blueprint);
}

TEST(TestLineage, RejectsUnsafeChildIds) {
  // "AND" is a condition-language keyword; "a<b" is outside the safe charset;
  // an id filling the whole CRABS_MAX_USER_ID field has no room for its NUL
  // (register_user truncates to 63, so such ids would collide after
  // truncation) and is rejected by the unterminated-field guard.
  const char* unsafe_charset_ids[] = {"AND", "a<b"};
  for (const char* unsafe_id : unsafe_charset_ids) {
    machine_blueprint_t* blueprint = machine_blueprint_create();
    ASSERT_NE(blueprint, nullptr);
    strncpy(blueprint->child_id, unsafe_id, sizeof(blueprint->child_id) - 1);
    blueprint->trust_mode = LINEAGE_SHARED_ROOT;
    EXPECT_EQ(lineage_blueprint_validate(blueprint),
              CRABS_ERR_INVALID_PARAM) << unsafe_id;
    machine_blueprint_destroy(blueprint);
  }

  machine_blueprint_t* overlong = machine_blueprint_create();
  ASSERT_NE(overlong, nullptr);
  memset(overlong->child_id, 'a', sizeof(overlong->child_id));
  overlong->trust_mode = LINEAGE_SHARED_ROOT;
  EXPECT_EQ(lineage_blueprint_validate(overlong), CRABS_ERR_INVALID_PARAM);
  machine_blueprint_destroy(overlong);
}

TEST(TestLineage, RejectsUnknownTrustMode) {
  machine_blueprint_t* blueprint = machine_blueprint_create();
  ASSERT_NE(blueprint, nullptr);
  strncpy(blueprint->child_id, "child-red", sizeof(blueprint->child_id) - 1);
  blueprint->trust_mode = (lineage_trust_mode_e)0x7F;
  EXPECT_EQ(lineage_blueprint_validate(blueprint), CRABS_ERR_INVALID_PARAM);
  machine_blueprint_destroy(blueprint);
}

TEST(TestLineage, RejectsMalformedPolicy) {
  // The ABE policy grammar demands UPPERCASE operators; a lowercase "or"
  // cannot act as a boolean separator once the expression reaches the ABE
  // evaluator. A dangling operator and a quoted operand are malformed too.
  // blueprint_add_policy guards at insertion time, so each expression is
  // written into the array in place to target the validator itself.
  const char* malformed[] = {
    "custody:child-red or custody:child-blue",  // lowercase operator
    "custody:child-red AND",                     // dangling operator
    "custody:child-red AND (custody:child-blue", // unbalanced parens
    "custody:\"child-red\""                      // quoted operand
  };
  for (const char* expression : malformed) {
    machine_blueprint_t* blueprint = make_valid_blueprint();
    ASSERT_NE(blueprint, nullptr);
    memset(blueprint->policies[0].expression, 0,
           sizeof(blueprint->policies[0].expression));
    strncpy(blueprint->policies[0].expression, expression,
            sizeof(blueprint->policies[0].expression) - 1);
    EXPECT_EQ(lineage_blueprint_validate(blueprint),
              CRABS_ERR_UNAUTHORIZED) << expression;
    machine_blueprint_destroy(blueprint);
  }
}

TEST(TestLineage, DuplicateItemNamesAreRejected) {
  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);

  // Add path: item names must be unique.
  EXPECT_NE(blueprint_add_item(blueprint, "counter", DATA_TYPE_COUNTER,
                               CRDT_G_COUNTER), CRABS_SUCCESS);

  // Validation path: force a duplicate into the array directly to prove the
  // validator (not just the add helper) catches it.
  strncpy(blueprint->items[0].name, "counter",
          sizeof(blueprint->items[0].name) - 1);
  ASSERT_EQ(blueprint_add_item(blueprint, "gauge", DATA_TYPE_PN_COUNTER,
                               CRDT_PN_COUNTER), CRABS_SUCCESS);
  strncpy(blueprint->items[1].name, "counter",
          sizeof(blueprint->items[1].name) - 1);
  EXPECT_EQ(lineage_blueprint_validate(blueprint),
            CRABS_ERR_DUPLICATE_OPERATION);

  // Restore and confirm only the duplicate was wrong.
  strncpy(blueprint->items[1].name, "gauge",
          sizeof(blueprint->items[1].name) - 1);
  EXPECT_EQ(lineage_blueprint_validate(blueprint), CRABS_SUCCESS);
  machine_blueprint_destroy(blueprint);
}

TEST(TestLineage, BlueprintCountsRespectConfigCaps) {
  // Items and policies are capped at 64 (CRABS_MAX_BLUEPRINT_ITEMS /
  // CRABS_MAX_BLUEPRINT_POLICIES); op type definitions are capped at 32 —
  // the state registry's CRABS_MAX_OP_TYPE_DEFS is the tighter bound, and a
  // blueprint exceeding it could never be applied.
  std::string long_op_suffix(40, 'x');

  machine_blueprint_t* blueprint = machine_blueprint_create();
  ASSERT_NE(blueprint, nullptr);
  strncpy(blueprint->child_id, "child-red", sizeof(blueprint->child_id) - 1);
  blueprint->trust_mode = LINEAGE_SHARED_ROOT;
  for (int item_index = 0; item_index < CRABS_MAX_BLUEPRINT_ITEMS;
       item_index++) {
    std::string name = "item_" + std::to_string(item_index) + long_op_suffix;
    EXPECT_EQ(blueprint_add_item(blueprint, name.c_str(), DATA_TYPE_COUNTER,
                                 CRDT_G_COUNTER), CRABS_SUCCESS);
  }
  EXPECT_EQ(blueprint->item_count, (uint32_t)CRABS_MAX_BLUEPRINT_ITEMS);
  EXPECT_EQ(blueprint_add_item(blueprint, "one_too_many", DATA_TYPE_COUNTER,
                               CRDT_G_COUNTER), CRABS_ERR_INVALID_PARAM);

  for (int policy_index = 0; policy_index < CRABS_MAX_BLUEPRINT_POLICIES;
       policy_index++) {
    std::string operation =
        "op_" + std::to_string(policy_index) + long_op_suffix;
    EXPECT_EQ(blueprint_add_policy(blueprint, operation.c_str(),
                                   "custody:child-red"), CRABS_SUCCESS);
  }
  EXPECT_EQ(blueprint->policy_count, (uint32_t)CRABS_MAX_BLUEPRINT_POLICIES);
  EXPECT_EQ(blueprint_add_policy(blueprint, "one_too_many", "custody:red"),
            CRABS_ERR_INVALID_PARAM);

  dedup_spec_t dedup;
  memset(&dedup, 0, sizeof(dedup));
  dedup.type = DEDUP_NONE;
  for (int def_index = 0; def_index < CRABS_MAX_BLUEPRINT_OP_TYPE_DEFS;
       def_index++) {
    std::string operation =
        "op_" + std::to_string(def_index) + long_op_suffix;
    EXPECT_EQ(blueprint_add_op_type_def(blueprint, operation.c_str(), &dedup),
              CRABS_SUCCESS);
  }
  EXPECT_EQ(blueprint->op_type_def_count,
            (uint32_t)CRABS_MAX_BLUEPRINT_OP_TYPE_DEFS);
  EXPECT_EQ(blueprint_add_op_type_def(blueprint, "one_too_many", &dedup),
            CRABS_ERR_INVALID_PARAM);

  EXPECT_EQ(lineage_blueprint_validate(blueprint), CRABS_SUCCESS);
  machine_blueprint_destroy(blueprint);
}

TEST(TestLineage, AddHelpersRejectBadArguments) {
  machine_blueprint_t* blueprint = machine_blueprint_create();
  ASSERT_NE(blueprint, nullptr);

  EXPECT_EQ(blueprint_add_item(nullptr, "counter", DATA_TYPE_COUNTER,
                               CRDT_G_COUNTER), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(blueprint_add_item(blueprint, NULL, DATA_TYPE_COUNTER,
                               CRDT_G_COUNTER), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(blueprint_add_item(blueprint, "a<b", DATA_TYPE_COUNTER,
                               CRDT_G_COUNTER), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(blueprint_add_item(blueprint, "AND", DATA_TYPE_COUNTER,
                               CRDT_G_COUNTER), CRABS_ERR_INVALID_PARAM);

  EXPECT_EQ(blueprint_add_policy(nullptr, "grant_write", "custody:red"),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(blueprint_add_policy(blueprint, NULL, "custody:red"),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(blueprint_add_policy(blueprint, "", "custody:red"),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(blueprint_add_policy(blueprint, "grant_write",
                                 "custody:red or custody:blue"),
            CRABS_ERR_UNAUTHORIZED);

  dedup_spec_t dedup;
  memset(&dedup, 0, sizeof(dedup));
  dedup.type = DEDUP_NONE;
  EXPECT_EQ(blueprint_add_op_type_def(nullptr, "grant_write", &dedup),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(blueprint_add_op_type_def(blueprint, "grant_write", NULL),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(blueprint_add_op_type_def(blueprint, "", &dedup),
            CRABS_ERR_INVALID_PARAM);

  machine_blueprint_destroy(blueprint);
}

TEST(TestLineage, DelegatedAndSovereignRequireBootstrapAdmin) {
  const lineage_trust_mode_e modes[] = {LINEAGE_DELEGATED_COPY,
                                        LINEAGE_SOVEREIGN};
  for (lineage_trust_mode_e mode : modes) {
    // Empty bootstrap admin: a fresh authority has nobody to mint roles.
    machine_blueprint_t* empty_admin = machine_blueprint_create();
    ASSERT_NE(empty_admin, nullptr);
    strncpy(empty_admin->child_id, "child-red",
            sizeof(empty_admin->child_id) - 1);
    empty_admin->trust_mode = mode;
    empty_admin->bootstrap_admin[0] = '\0';
    EXPECT_EQ(lineage_blueprint_validate(empty_admin),
              CRABS_ERR_INVALID_PARAM) << (int)mode;

    // Unsafe bootstrap admin.
    machine_blueprint_t* bad_admin = machine_blueprint_create();
    ASSERT_NE(bad_admin, nullptr);
    strncpy(bad_admin->child_id, "child-red", sizeof(bad_admin->child_id) - 1);
    bad_admin->trust_mode = mode;
    strncpy(bad_admin->bootstrap_admin, "a<b",
            sizeof(bad_admin->bootstrap_admin) - 1);
    EXPECT_EQ(lineage_blueprint_validate(bad_admin),
              CRABS_ERR_INVALID_PARAM) << (int)mode;
    machine_blueprint_destroy(empty_admin);
    machine_blueprint_destroy(bad_admin);
  }

  // Shared-root children borrow the parent authority — an empty bootstrap
  // admin is acceptable there.
  machine_blueprint_t* shared_root = machine_blueprint_create();
  ASSERT_NE(shared_root, nullptr);
  strncpy(shared_root->child_id, "child-red",
          sizeof(shared_root->child_id) - 1);
  shared_root->trust_mode = LINEAGE_SHARED_ROOT;
  shared_root->bootstrap_admin[0] = '\0';
  EXPECT_EQ(lineage_blueprint_validate(shared_root), CRABS_SUCCESS);
  machine_blueprint_destroy(shared_root);
}

// ============================================================
// Safe user id predicate exposure
// ============================================================

TEST(TestLineage, SafeUserIdPredicateIsPublic) {
  EXPECT_TRUE(attribute_machine_is_safe_user_id("alice"));
  EXPECT_TRUE(attribute_machine_is_safe_user_id("a-B_1"));
  EXPECT_FALSE(attribute_machine_is_safe_user_id(NULL));
  EXPECT_FALSE(attribute_machine_is_safe_user_id(""));
  EXPECT_FALSE(attribute_machine_is_safe_user_id("AND"));
  EXPECT_FALSE(attribute_machine_is_safe_user_id("a<b"));
  EXPECT_FALSE(
      attribute_machine_is_safe_user_id(std::string(64, 'a').c_str()));
}

// ============================================================
// state_t lineage fields
// ============================================================

TEST(TestLineage, StateLineageFieldsStartEmpty) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  EXPECT_EQ(state->children, nullptr);
  EXPECT_EQ(state->child_count, 0u);
  EXPECT_FALSE(state->lineage_parent_bound);
  EXPECT_EQ(state->lineage_parent_id[0], '\0');
  for (int byte_index = 0; byte_index < 33; byte_index++) {
    EXPECT_EQ(state->lineage_parent_public_key[byte_index], 0);
  }
  state_destroy(state);
  state_destroy(NULL);  // no-crash
}

TEST(TestLineage, StateDestroyReleasesChildrenArray) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  state->children = (child_manifest_entry_t*)malloc(
      sizeof(child_manifest_entry_t) * 2);
  ASSERT_NE(state->children, nullptr);
  memset(state->children, 0, sizeof(child_manifest_entry_t) * 2);
  state->child_count = 2;
  state_destroy(state);
}

// ============================================================
// Attestations
// ============================================================

// A parent state with a valid ECDSA node key — the signer for attestations.
static state_t* make_parent_state(ecdsa_keypair_t** parent_key_out) {
  state_t* parent = state_create();
  EXPECT_NE(parent, nullptr);
  ecdsa_keypair_t* parent_key = crypto_ecdsa_generate();
  EXPECT_NE(parent_key, nullptr);
  if (parent != nullptr && parent_key != nullptr) {
    EXPECT_EQ(state_set_node_key(parent, parent_key->private_key,
                                 parent_key->public_key), CRABS_SUCCESS);
  }
  *parent_key_out = parent_key;
  return parent;
}

TEST(TestLineage, AttestationSignVerifyRoundTrip) {
  ecdsa_keypair_t* parent_key = nullptr;
  state_t* parent = make_parent_state(&parent_key);
  ASSERT_NE(parent, nullptr);
  ASSERT_NE(parent_key, nullptr);

  const uint64_t now = 1700000000000ULL;  // fixed test epoch, ms
  attestation_t attestation = {0};
  ASSERT_EQ(attestation_create(parent, &attestation,
      "parent-root", "child-red", "alice",
      "role:writer,dept:red", now, now + 60000), CRABS_SUCCESS);
  EXPECT_EQ(attestation.format_version, CRABS_ATTESTATION_FORMAT_VERSION);

  // Positive: correct parent key, correct child, inside window.
  EXPECT_TRUE(attestation_verify(parent_key->public_key, "child-red",
                                 &attestation, now));
  // Negative: wrong child id.
  EXPECT_FALSE(attestation_verify(parent_key->public_key, "child-blue",
                                  &attestation, now));
  // Negative: expired.
  EXPECT_FALSE(attestation_verify(parent_key->public_key, "child-red",
                                  &attestation, now + 120000));
  // Negative: tampered attributes (flip the first attribute character).
  attestation.attributes[0] ^= 0x01;
  EXPECT_FALSE(attestation_verify(parent_key->public_key, "child-red",
                                  &attestation, now));
  attestation.attributes[0] ^= 0x01;
  EXPECT_TRUE(attestation_verify(parent_key->public_key, "child-red",
                                 &attestation, now));

  // Byte transport round trip re-verifies.
  uint8_t wire[2048];
  size_t wire_len = attestation_serialize(&attestation, wire, sizeof(wire));
  ASSERT_GT(wire_len, 0u);
  attestation_t* restored = attestation_deserialize(wire, wire_len);
  ASSERT_NE(restored, nullptr);
  EXPECT_TRUE(attestation_verify(parent_key->public_key, "child-red",
                                 restored, now));
  attestation_destroy(restored);

  crypto_ecdsa_keypair_destroy(parent_key);
  state_destroy(parent);
}

TEST(TestLineage, AttestationCreateRejectsBadInputs) {
  ecdsa_keypair_t* parent_key = nullptr;
  state_t* parent = make_parent_state(&parent_key);
  ASSERT_NE(parent, nullptr);
  ASSERT_NE(parent_key, nullptr);

  const uint64_t now = 1700000000000ULL;
  attestation_t attestation = {0};
  EXPECT_EQ(attestation_create(nullptr, &attestation, "parent-root",
              "child-red", "alice", "role:writer", now, now + 60000),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attestation_create(parent, nullptr, "parent-root",
              "child-red", "alice", "role:writer", now, now + 60000),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attestation_create(parent, &attestation, "",
              "child-red", "alice", "role:writer", now, now + 60000),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attestation_create(parent, &attestation, "parent-root",
              "a<b", "alice", "role:writer", now, now + 60000),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attestation_create(parent, &attestation, "parent-root",
              "child-red", "alice", "role:writer", now, now - 1),
            CRABS_ERR_INVALID_PARAM);

  // A state with no node key cannot sign.
  state_t* keyless = state_create();
  ASSERT_NE(keyless, nullptr);
  EXPECT_EQ(attestation_create(keyless, &attestation, "parent-root",
              "child-red", "alice", "role:writer", now, now + 60000),
            CRABS_ERR_CRYPTOGRAPHIC_ERROR);
  state_destroy(keyless);

  crypto_ecdsa_keypair_destroy(parent_key);
  state_destroy(parent);
}

TEST(TestLineage, AttestationDeserializeRejectsGarbage) {
  EXPECT_EQ(attestation_deserialize(nullptr, 100), nullptr);
  EXPECT_EQ(attestation_deserialize(nullptr, 0), nullptr);

  // Four junk bytes cannot form a length prefix + body + signature.
  const uint8_t junk[4] = {0xDE, 0xAD, 0xBE, 0xEF};
  EXPECT_EQ(attestation_deserialize(junk, sizeof(junk)), nullptr);

  // A valid wire image truncated by one byte must be rejected, not silently
  // recovered from the length prefix.
  ecdsa_keypair_t* parent_key = nullptr;
  state_t* parent = make_parent_state(&parent_key);
  ASSERT_NE(parent, nullptr);
  ASSERT_NE(parent_key, nullptr);
  const uint64_t now = 1700000000000ULL;
  attestation_t attestation = {0};
  ASSERT_EQ(attestation_create(parent, &attestation, "parent-root",
              "child-red", "alice", "role:writer", now, now + 60000),
            CRABS_SUCCESS);
  uint8_t wire[2048];
  size_t wire_len = attestation_serialize(&attestation, wire, sizeof(wire));
  ASSERT_GT(wire_len, 0u);
  EXPECT_EQ(attestation_deserialize(wire, wire_len - 1), nullptr);

  // A length prefix claiming MORE bytes than the buffer holds is rejected.
  uint8_t lying[128];
  memset(lying, 0, sizeof(lying));
  lying[0] = 0xFF;  // u32le total length 0x000000FF > 124 usable bytes
  EXPECT_EQ(attestation_deserialize(lying, sizeof(lying)), nullptr);

  crypto_ecdsa_keypair_destroy(parent_key);
  state_destroy(parent);
}

TEST(TestLineage, ManifestEntryTypeLayout) {
  child_manifest_entry_t entry;
  memset(&entry, 0, sizeof(entry));
  strncpy(entry.child_id, "child-red", sizeof(entry.child_id) - 1);
  entry.mode = LINEAGE_DELEGATED_COPY;
  entry.status = LINEAGE_ACTIVE;
  entry.attestation_ttl_ms = 60000;
  entry.spawned_at = 42;
  EXPECT_STREQ(entry.child_id, "child-red");
  EXPECT_EQ(entry.mode, LINEAGE_DELEGATED_COPY);
  EXPECT_EQ(entry.status, LINEAGE_ACTIVE);
}