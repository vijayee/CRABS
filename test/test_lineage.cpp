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
#include "../src/StateMachine/state_machine.h"
#include "../src/Serialization/serialization.h"
#include "test_helpers.h"
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

TEST(TestLineage, EndorsementPolicyExpressionsValidate) {
  // v1.7 §attestation bridge: blueprint policies may carry @parent/<attr>
  // endorsement tokens (spawned children resolve them against their parent
  // binding). The validator mirrors preprocess_policy's grammar: the token
  // must be well-formed and sit at parenthesis depth 0.
  machine_blueprint_t* valid = make_valid_blueprint();
  ASSERT_NE(valid, nullptr);
  memset(valid->policies[0].expression, 0,
         sizeof(valid->policies[0].expression));
  strncpy(valid->policies[0].expression, "@parent/role:writer",
          sizeof(valid->policies[0].expression) - 1);
  EXPECT_EQ(lineage_blueprint_validate(valid), CRABS_SUCCESS);

  strncpy(valid->policies[0].expression, "@parent/role:writer AND custody:child-red",
          sizeof(valid->policies[0].expression) - 1);
  EXPECT_EQ(lineage_blueprint_validate(valid), CRABS_SUCCESS);
  machine_blueprint_destroy(valid);

  machine_blueprint_t* malformed = make_valid_blueprint();
  ASSERT_NE(malformed, nullptr);
  memset(malformed->policies[0].expression, 0,
         sizeof(malformed->policies[0].expression));
  const char* bad_expressions[] = {
    "@parent/",                              // empty attribute
    "@parent/ro@le:writer",                  // nested '@'
    "@parent/a:1 AND @parent/",              // empty attribute mid-policy
    "(role:admin OR @parent/a:1)"            // endorsement inside parens —
                                             // composition out of scope in v1
  };
  for (const char* expression : bad_expressions) {
    strncpy(malformed->policies[0].expression, expression,
            sizeof(malformed->policies[0].expression) - 1);
    EXPECT_EQ(lineage_blueprint_validate(malformed),
              CRABS_ERR_UNAUTHORIZED) << expression;
  }
  machine_blueprint_destroy(malformed);
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
// ============================================================
// Authorization pipeline: @parent/ endorsement enforcement
// ============================================================

#include <ctime>

// A child machine (NOT spawned — spawn lands later) with:
//   - an attribute machine whose user "alice" has a legacy ECDSA key;
//   - the policy "@parent/role:writer" on __check_dedup__ (auth-only op:
//     state_machine_validate exercises the full authorization pipeline).
// The correct parent key and an impostor key are pre-generated so each test
// can bind/fabricate attestations independently.
typedef struct {
  state_t*            child_state;
  attribute_machine_t* am;
  ecdsa_keypair_t*    alice_key;
  ecdsa_keypair_t*    parent_key;
  ecdsa_keypair_t*    impostor_key;
} endorsement_harness_t;

static void endorsement_harness_setup(endorsement_harness_t* harness) {
  memset(harness, 0, sizeof(*harness));
  harness->child_state = state_create();
  ASSERT_NE(harness->child_state, nullptr);
  harness->alice_key = crypto_ecdsa_generate();
  ASSERT_NE(harness->alice_key, nullptr);
  uint8_t admin_pk[33];
  memset(admin_pk, 0xAA, 33);
  admin_pk[0] = 0x02;
  harness->am = attribute_machine_create("admin", admin_pk);
  ASSERT_NE(harness->am, nullptr);
  ASSERT_EQ(crabs_test_register_user_with_role(
      harness->am, "alice", harness->alice_key->public_key, "role", "admin"),
      CRABS_SUCCESS);
  harness->child_state->attr_machine = harness->am;
  ASSERT_EQ(state_add_policy(harness->child_state, CRABS_OP_CHECK_DEDUP,
                             "@parent/role:writer"), CRABS_SUCCESS);
  harness->parent_key = crypto_ecdsa_generate();
  ASSERT_NE(harness->parent_key, nullptr);
  harness->impostor_key = crypto_ecdsa_generate();
  ASSERT_NE(harness->impostor_key, nullptr);
}

static void endorsement_harness_destroy(endorsement_harness_t* harness) {
  harness->child_state->attr_machine = NULL;
  state_destroy(harness->child_state);
  attribute_machine_destroy(harness->am);
  crypto_ecdsa_keypair_destroy(harness->alice_key);
  crypto_ecdsa_keypair_destroy(harness->parent_key);
  crypto_ecdsa_keypair_destroy(harness->impostor_key);
}

// Bind the child state to a parent: public key + self id + bound flag. This
// is the in-memory shape spawn will produce (spawn itself is a later task).
static void bind_child_to_parent(state_t* child_state,
                                 const ecdsa_keypair_t* parent_key,
                                 const char* parent_id,
                                 const char* child_id) {
  memcpy(child_state->lineage_parent_public_key, parent_key->public_key, 33);
  strncpy(child_state->lineage_parent_id, parent_id,
          sizeof(child_state->lineage_parent_id) - 1);
  strncpy(child_state->lineage_self_id, child_id,
          sizeof(child_state->lineage_self_id) - 1);
  child_state->lineage_parent_bound = true;
}

// Attestation signed by whatever key the harness state carries.
static void issue_attestation(ecdsa_keypair_t* signing_key,
                              const char* child_id, const char* user_id,
                              const char* attributes,
                              attestation_t* attestation_out) {
  state_t* signing_state = state_create();
  ASSERT_NE(signing_state, nullptr);
  ASSERT_EQ(state_set_node_key(signing_state, signing_key->private_key,
                               signing_key->public_key), CRABS_SUCCESS);
  // The pipeline reads the machine's own authenticated clock; with no time
  // source configured it falls back to the system clock — use a wide,
  // system-anchored window so the test does not depend on clock granularity.
  uint64_t now_ms = (uint64_t)time(NULL) * 1000ULL;
  ASSERT_EQ(attestation_create(signing_state, attestation_out, "parent-root",
                               child_id, user_id, attributes,
                               now_ms - 60000, now_ms + 3600000),
            CRABS_SUCCESS);
  state_destroy(signing_state);
}

static operation_t* make_signed_dedup_check_op(endorsement_harness_t* harness) {
  operation_t* op = operation_create(CRABS_OP_CHECK_DEDUP);
  memset(op->uuid, 0x42, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  user_t* signer = attribute_machine_find_user(harness->am, "alice");
  if (signer != NULL) op->signer_key_version = signer->key_version;
  op->lamport_time = 1;
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  EXPECT_NE(ser, nullptr);
  if (ser == NULL) {
    operation_destroy(op);
    return NULL;
  }
  EXPECT_EQ(crypto_sign_operation(harness->alice_key->private_key,
                                  ser->data, ser->len, op->signature),
            CRABS_SUCCESS);
  serialized_buffer_destroy(ser);
  return op;
}

static void attach_attestation(operation_t* op, const attestation_t* att) {
  op->attestations = (attestation_t*)malloc(sizeof(attestation_t));
  ASSERT_NE(op->attestations, nullptr);
  op->attestations[0] = *att;
  op->attestation_count = 1;
}

TEST(TestLineage, UnboundMachineFailsClosedOnEndorsementPolicy) {
  // A machine that was never spawned has no parent binding — an endorsement
  // policy can neither fail open nor be satisfied by any attestation.
  endorsement_harness_t harness;
  endorsement_harness_setup(&harness);
  operation_t* op = make_signed_dedup_check_op(&harness);
  attestation_t attestation;
  issue_attestation(harness.parent_key, "child-red", "alice",
                    "role:writer", &attestation);
  attach_attestation(op, &attestation);

  EXPECT_EQ(state_machine_validate(harness.child_state, op),
            CRABS_ERR_UNAUTHORIZED);

  operation_destroy(op);
  endorsement_harness_destroy(&harness);
}

TEST(TestLineage, AttestationSignedByWrongParentFailsClosed) {
  endorsement_harness_t harness;
  endorsement_harness_setup(&harness);
  bind_child_to_parent(harness.child_state, harness.parent_key,
                       "parent-root", "child-red");
  operation_t* op = make_signed_dedup_check_op(&harness);

  // Fabricated: signed by a key that is NOT the machine's parent.
  attestation_t forged;
  issue_attestation(harness.impostor_key, "child-red", "alice",
                    "role:writer", &forged);
  attach_attestation(op, &forged);
  EXPECT_EQ(state_machine_validate(harness.child_state, op),
            CRABS_ERR_UNAUTHORIZED);

  // Right parent key but naming a DIFFERENT child.
  operation_t* wrong_child_op = make_signed_dedup_check_op(&harness);
  attestation_t wrong_child;
  issue_attestation(harness.parent_key, "child-blue", "alice",
                    "role:writer", &wrong_child);
  attach_attestation(wrong_child_op, &wrong_child);
  EXPECT_EQ(state_machine_validate(harness.child_state, wrong_child_op),
            CRABS_ERR_UNAUTHORIZED);

  operation_destroy(op);
  operation_destroy(wrong_child_op);
  endorsement_harness_destroy(&harness);
}

TEST(TestLineage, AttestationForWrongUserOrAttributesFailsClosed) {
  endorsement_harness_t harness;
  endorsement_harness_setup(&harness);
  bind_child_to_parent(harness.child_state, harness.parent_key,
                       "parent-root", "child-red");

  // Attestation names a different user than the op's signer.
  operation_t* wrong_user_op = make_signed_dedup_check_op(&harness);
  attestation_t wrong_user;
  issue_attestation(harness.parent_key, "child-red", "bob", "role:writer",
                    &wrong_user);
  attach_attestation(wrong_user_op, &wrong_user);
  EXPECT_EQ(state_machine_validate(harness.child_state, wrong_user_op),
            CRABS_ERR_UNAUTHORIZED);
  operation_destroy(wrong_user_op);

  // Attestation for the right user but an attribute list that does not
  // cover the endorsement.
  operation_t* unrelated_attrs_op = make_signed_dedup_check_op(&harness);
  attestation_t unrelated_attrs;
  issue_attestation(harness.parent_key, "child-red", "alice", "role:reader",
                    &unrelated_attrs);
  attach_attestation(unrelated_attrs_op, &unrelated_attrs);
  EXPECT_EQ(state_machine_validate(harness.child_state, unrelated_attrs_op),
            CRABS_ERR_UNAUTHORIZED);
  operation_destroy(unrelated_attrs_op);

  // No attestation at all.
  operation_t* no_attestation_op = make_signed_dedup_check_op(&harness);
  EXPECT_EQ(state_machine_validate(harness.child_state, no_attestation_op),
            CRABS_ERR_UNAUTHORIZED);
  operation_destroy(no_attestation_op);

  endorsement_harness_destroy(&harness);
}

TEST(TestLineage, MatchingAttestationAuthorizesEndorsementPolicy) {
  endorsement_harness_t harness;
  endorsement_harness_setup(&harness);
  bind_child_to_parent(harness.child_state, harness.parent_key,
                       "parent-root", "child-red");
  operation_t* op = make_signed_dedup_check_op(&harness);

  attestation_t attestation;
  issue_attestation(harness.parent_key, "child-red", "alice", "role:writer",
                    &attestation);
  attach_attestation(op, &attestation);
  EXPECT_EQ(state_machine_validate(harness.child_state, op), CRABS_SUCCESS);

  // A comma-separated attribute list covers the endorsement when it
  // CONTAINS the exact attribute among several.
  operation_t* covered_among_many = make_signed_dedup_check_op(&harness);
  attestation_t multi;
  issue_attestation(harness.parent_key, "child-red", "alice",
                    "dept:red,role:writer,custody:video", &multi);
  attach_attestation(covered_among_many, &multi);
  EXPECT_EQ(state_machine_validate(harness.child_state, covered_among_many),
            CRABS_SUCCESS);

  operation_destroy(op);
  operation_destroy(covered_among_many);
  endorsement_harness_destroy(&harness);
}

TEST(TestLineage, UnsignedModeBOpRejectedOnEndorsementPolicy) {
  // Mode B (anonymous op, empty signer_id) cannot resolve an attested user:
  // trial verification only identifies the signers of registered users, and
  // the endorsement pipeline requires an attestation naming the resolved
  // signer. Fail closed BEFORE any signature work.
  endorsement_harness_t harness;
  endorsement_harness_setup(&harness);
  bind_child_to_parent(harness.child_state, harness.parent_key,
                       "parent-root", "child-red");

  operation_t* op = operation_create(CRABS_OP_CHECK_DEDUP);
  memset(op->uuid, 0x42, CRABS_UUID_SIZE);
  ASSERT_NE(op, nullptr);
  attestation_t attestation;
  issue_attestation(harness.parent_key, "child-red", "alice", "role:writer",
                    &attestation);
  attach_attestation(op, &attestation);
  EXPECT_EQ(state_machine_validate(harness.child_state, op),
            CRABS_ERR_UNAUTHORIZED);

  operation_destroy(op);
  endorsement_harness_destroy(&harness);
}
