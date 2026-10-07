//
// Lineage data model tests: machine blueprints, blueprint validation,
// child manifest entries, and the state_t lineage fields (parent binding).
//

#include <gtest/gtest.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <openssl/sha.h>

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

// ============================================================
// Spawn: the three trust modes
// ============================================================

// A parent machine shaped the way the CLI wires its nodes: a heap attribute
// machine whose genesis admin holds the node key's public key, the node key
// set on the embedded state, and the state's attr_machine self-reference.
typedef struct {
  attribute_machine_t* am;
  ecdsa_keypair_t*     parent_key;
  ecdsa_keypair_t*     alice_key;
} spawn_parent_harness_t;

static void spawn_parent_setup(spawn_parent_harness_t* harness) {
  memset(harness, 0, sizeof(*harness));
  harness->parent_key = crypto_ecdsa_generate();
  ASSERT_NE(harness->parent_key, nullptr);
  harness->am = attribute_machine_create("parent-root",
                                         harness->parent_key->public_key);
  ASSERT_NE(harness->am, nullptr);
  ASSERT_EQ(state_set_node_key(&harness->am->base_state,
                               harness->parent_key->private_key,
                               harness->parent_key->public_key),
            CRABS_SUCCESS);
  harness->am->base_state.attr_machine = harness->am;
  harness->alice_key = crypto_ecdsa_generate();
  ASSERT_NE(harness->alice_key, nullptr);
  // Registered with NO attributes: the deny-then-grant shared-root test needs
  // a signer that initially lacks the custody attribute the child policy
  // demands.
  ASSERT_EQ(attribute_machine_register_user(harness->am, "alice",
                                            harness->alice_key->public_key, ""),
            CRABS_SUCCESS);
}

static void spawn_parent_destroy(spawn_parent_harness_t* harness) {
  if (harness->am != NULL) attribute_machine_destroy(harness->am);
  crypto_ecdsa_keypair_destroy(harness->parent_key);
  crypto_ecdsa_keypair_destroy(harness->alice_key);
}

// A delegated/sovereign blueprint: fresh authority, bootstrap admin
// "child-admin", op "increment" under "role:admin" — the child's own genesis
// admin must be able to authorize it.
static machine_blueprint_t* make_fresh_authority_blueprint(
    const char* child_id, lineage_trust_mode_e mode) {
  machine_blueprint_t* blueprint = machine_blueprint_create();
  EXPECT_NE(blueprint, nullptr);
  strncpy(blueprint->child_id, child_id, sizeof(blueprint->child_id) - 1);
  blueprint->trust_mode = mode;
  strncpy(blueprint->bootstrap_admin, "child-admin",
          sizeof(blueprint->bootstrap_admin) - 1);
  blueprint->attestation_ttl_ms = 60000;
  EXPECT_EQ(blueprint_add_item(blueprint, "counter", DATA_TYPE_COUNTER,
                               CRDT_G_COUNTER), CRABS_SUCCESS);
  EXPECT_EQ(blueprint_add_policy(blueprint, "increment", "role:admin"),
            CRABS_SUCCESS);
  dedup_spec_t dedup;
  memset(&dedup, 0, sizeof(dedup));
  dedup.type = DEDUP_NONE;
  EXPECT_EQ(blueprint_add_op_type_def(blueprint, "increment", &dedup),
            CRABS_SUCCESS);
  EXPECT_EQ(lineage_blueprint_validate(blueprint), CRABS_SUCCESS);
  return blueprint;
}

static operation_t* make_signed_increment_op(attribute_machine_t* registry,
                                             ecdsa_keypair_t* signer_key,
                                             const char* signer_id) {
  operation_t* op = operation_create("increment");
  EXPECT_NE(op, nullptr);
  if (op == NULL) return NULL;
  strncpy(op->signer_id, signer_id, CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(registry, signer_key, op);
  return op;
}

TEST(TestLineage, SpawnSharedRootSharesParentAuthority) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);

  // Capture the spawn change event.
  static crabs_change_event_t captured_events[4];
  static uint32_t captured_event_count;
  captured_event_count = 0;
  state_set_change_hook(parent, [](state_t*, const crabs_change_event_t* event,
                                   void*) {
    if (captured_event_count < 4) captured_events[captured_event_count++] = *event;
  }, nullptr);

  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  ASSERT_NE(child, nullptr);

  // Same authority: attribute machine pointer AND the live MSK.
  EXPECT_EQ(child->base_state.attr_machine, harness.am);
  EXPECT_EQ(child->base_state.abe_mk, harness.am->base_state.abe_mk);
  EXPECT_TRUE(child->base_state.abe_mk_borrowed);
  // Nothing was re-enrolled: the child owns no registry of its own.
  EXPECT_EQ(child->user_count, 0u);

  // Blueprint applied to the child state.
  EXPECT_NE(state_find_item(&child->base_state, "counter"), nullptr);
  EXPECT_STREQ(state_find_policy(&child->base_state, "increment"),
               "custody:child-red");
  EXPECT_NE(state_find_op_type_def(&child->base_state, "increment"), nullptr);
  EXPECT_STRNE(child->base_state.config.bootstrap_admin, "");

  // Parent binding + identity.
  EXPECT_TRUE(child->base_state.lineage_parent_bound);
  EXPECT_STREQ(child->base_state.lineage_parent_id, "parent-root");
  EXPECT_STREQ(child->base_state.lineage_self_id, "child-red");
  EXPECT_EQ(memcmp(child->base_state.lineage_parent_public_key,
                   harness.parent_key->public_key, 33), 0);

  // Manifest entry appended: child_id, mode, ACTIVE, ttl, spawned_at.
  state_t* parent_state = parent;
  ASSERT_EQ(parent_state->child_count, 1u);
  const child_manifest_entry_t* manifest_entry = &parent_state->children[0];
  EXPECT_STREQ(manifest_entry->child_id, "child-red");
  EXPECT_EQ(manifest_entry->mode, LINEAGE_SHARED_ROOT);
  EXPECT_EQ(manifest_entry->status, LINEAGE_ACTIVE);
  EXPECT_EQ(manifest_entry->attestation_ttl_ms, 60000u);
  EXPECT_GT(manifest_entry->spawned_at, 0u);

  // Genesis snapshot: the manifest hash is the SHA-256 of the child's
  // unkeyed serialization (recomputed here), signed by the parent's node key.
  serialized_buffer_t* genesis = crabs_serialize_state(&child->base_state);
  ASSERT_NE(genesis, nullptr);
  uint8_t recomputed_hash[CRABS_HASH_SIZE];
  ASSERT_EQ(crypto_sha256(genesis->data, genesis->len, recomputed_hash),
            CRABS_SUCCESS);
  EXPECT_EQ(memcmp(recomputed_hash, manifest_entry->genesis_snapshot_hash,
                   CRABS_HASH_SIZE), 0);
  EXPECT_TRUE(crypto_ecdsa_verify(harness.parent_key->public_key,
                                  genesis->data, genesis->len,
                                  manifest_entry->genesis_attestation_signature));
  serialized_buffer_destroy(genesis);

  // Change event: kind SPAWN, type __spawn_machine__, no uuid/signer.
  ASSERT_EQ(captured_event_count, 1u);
  EXPECT_EQ(captured_events[0].kind, CRABS_CHANGE_SPAWN);
  EXPECT_STREQ(captured_events[0].type, "__spawn_machine__");
  EXPECT_EQ(captured_events[0].uuid, nullptr);
  EXPECT_EQ(captured_events[0].signer_id, nullptr);
  EXPECT_STREQ(captured_events[0].target, "child-red");
  EXPECT_EQ(captured_events[0].result, CRABS_SUCCESS);

  // Deny-then-grant: alice (parent registry, shared authority) has no
  // custody attribute — the child op is denied.
  operation_t* denied = make_signed_increment_op(harness.am,
                                                 harness.alice_key, "alice");
  ASSERT_NE(denied, nullptr);
  EXPECT_EQ(state_machine_execute(&child->base_state, denied),
            CRABS_ERR_UNAUTHORIZED);
  operation_destroy(denied);

  // The parent grants custody:child-red ON THE SHARED registry — the op
  // now authorizes through the child's policy.
  EXPECT_EQ(attribute_machine_grant_role(harness.am, "alice", "custody",
                                         "child-red", "parent-root"),
            CRABS_SUCCESS);
  operation_t* granted = make_signed_increment_op(harness.am,
                                                  harness.alice_key, "alice");
  ASSERT_NE(granted, nullptr);
  EXPECT_EQ(state_machine_execute(&child->base_state, granted), CRABS_SUCCESS);
  operation_destroy(granted);

  attribute_machine_destroy(child);
  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, SpawnDelegatedCopyMintsFreshAuthority) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  machine_blueprint_t* blueprint =
      make_fresh_authority_blueprint("child-delegated", LINEAGE_DELEGATED_COPY);
  ASSERT_NE(blueprint, nullptr);

  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  ASSERT_NE(child, nullptr);

  // Fresh authority: own attribute machine AND own MSK.
  EXPECT_NE(child->base_state.attr_machine, harness.am);
  EXPECT_EQ(child->base_state.attr_machine, child);
  ASSERT_NE(child->base_state.abe_mk, nullptr);
  EXPECT_NE(child->base_state.abe_mk, harness.am->base_state.abe_mk);
  EXPECT_FALSE(child->base_state.abe_mk_borrowed);

  // The child's genesis admin exists IN THE CHILD's registry with role:admin.
  EXPECT_EQ(child->user_count, 1u);
  user_t* child_admin =
      attribute_machine_find_user(child, "child-admin");
  ASSERT_NE(child_admin, nullptr);
  EXPECT_TRUE(attribute_machine_user_has_role(child_admin, "role"));
  EXPECT_STREQ(child->base_state.config.bootstrap_admin, "child-admin");

  // Manifest entry present, mode recorded.
  ASSERT_EQ(parent->child_count, 1u);
  EXPECT_EQ(parent->children[0].mode, LINEAGE_DELEGATED_COPY);
  EXPECT_EQ(parent->children[0].status, LINEAGE_ACTIVE);
  EXPECT_TRUE(child->base_state.lineage_parent_bound);

  // The fresh domain works: the child's OWN genesis admin authorizes a child
  // op (policy "role:admin"). The genesis admin's registered key is the
  // parent's node public key — the machine that minted the child vouches for
  // its bootstrap admin.
  operation_t* op = make_signed_increment_op(child, harness.parent_key,
                                             "child-admin");
  ASSERT_NE(op, nullptr);
  EXPECT_EQ(state_machine_execute(&child->base_state, op), CRABS_SUCCESS);
  operation_destroy(op);

  attribute_machine_destroy(child);
  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, SpawnSovereignGeneratesOwnMsk) {
  // Sovereign children are constructed exactly like delegated copies — the
  // difference lives in the manifest mode, which Task 8's dissolve op will
  // reject (parent may only WITHDRAW a sovereign child, never dissolve it).
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  machine_blueprint_t* blueprint =
      make_fresh_authority_blueprint("child-sov", LINEAGE_SOVEREIGN);
  ASSERT_NE(blueprint, nullptr);

  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  ASSERT_NE(child, nullptr);

  EXPECT_NE(child->base_state.attr_machine, harness.am);
  ASSERT_NE(child->base_state.abe_mk, nullptr);
  EXPECT_NE(child->base_state.abe_mk, harness.am->base_state.abe_mk);
  user_t* child_admin = attribute_machine_find_user(child, "child-admin");
  ASSERT_NE(child_admin, nullptr);
  EXPECT_TRUE(attribute_machine_user_has_role(child_admin, "role"));

  ASSERT_EQ(parent->child_count, 1u);
  EXPECT_EQ(parent->children[0].mode, LINEAGE_SOVEREIGN);
  EXPECT_EQ(parent->children[0].status, LINEAGE_ACTIVE);

  operation_t* op = make_signed_increment_op(child, harness.parent_key,
                                             "child-admin");
  ASSERT_NE(op, nullptr);
  EXPECT_EQ(state_machine_execute(&child->base_state, op), CRABS_SUCCESS);
  operation_destroy(op);

  attribute_machine_destroy(child);
  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, SpawnRejectsOverLimitChildren) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;

  for (uint32_t child_index = 0; child_index < CRABS_MAX_CHILD_MACHINES;
       child_index++) {
    char child_name[CRABS_MAX_USER_ID];
    snprintf(child_name, sizeof(child_name), "child-%02u", child_index);
    machine_blueprint_t* blueprint = make_valid_blueprint();
    ASSERT_NE(blueprint, nullptr) << child_name;
    strncpy(blueprint->child_id, child_name, sizeof(blueprint->child_id) - 1);
    attribute_machine_t* child = nullptr;
    ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child),
              CRABS_SUCCESS) << child_name;
    attribute_machine_destroy(child);
    machine_blueprint_destroy(blueprint);
  }
  ASSERT_EQ(parent->child_count, (uint32_t)CRABS_MAX_CHILD_MACHINES);

  // One more than the ceiling: rejected, no partial manifest residue.
  machine_blueprint_t* overflow = make_valid_blueprint();
  ASSERT_NE(overflow, nullptr);
  strncpy(overflow->child_id, "child-overflow", sizeof(overflow->child_id) - 1);
  attribute_machine_t* rejected_child = nullptr;
  EXPECT_EQ(lineage_spawn_machine(parent, overflow, &rejected_child),
            CRABS_ERR_OOM);
  EXPECT_EQ(rejected_child, nullptr);
  EXPECT_EQ(parent->child_count, (uint32_t)CRABS_MAX_CHILD_MACHINES);
  machine_blueprint_destroy(overflow);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, SpawnRejectsDuplicateChildId) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);

  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  ASSERT_NE(child, nullptr);
  ASSERT_EQ(parent->child_count, 1u);

  // The same child_id again is rejected — even with identical content.
  attribute_machine_t* duplicate = nullptr;
  EXPECT_EQ(lineage_spawn_machine(parent, blueprint, &duplicate),
            CRABS_ERR_DUPLICATE_OPERATION);
  EXPECT_EQ(duplicate, nullptr);
  EXPECT_EQ(parent->child_count, 1u);

  // A ROOT parent's own machine id is its config.bootstrap_admin — a child
  // may not take the parent's identity name either.
  machine_blueprint_t* parent_aliased = make_valid_blueprint();
  ASSERT_NE(parent_aliased, nullptr);
  strncpy(parent_aliased->child_id, "parent-root",
          sizeof(parent_aliased->child_id) - 1);
  attribute_machine_t* aliased = nullptr;
  EXPECT_EQ(lineage_spawn_machine(parent, parent_aliased, &aliased),
            CRABS_ERR_DUPLICATE_OPERATION);
  EXPECT_EQ(aliased, nullptr);
  EXPECT_EQ(parent->child_count, 1u);
  machine_blueprint_destroy(parent_aliased);

  // The spawned child may itself mint — its own lineage_self_id occupies the
  // same machine-name space, so a grandchild must not reuse it.
  ecdsa_keypair_t* child_key = crypto_ecdsa_generate();
  ASSERT_NE(child_key, nullptr);
  ASSERT_EQ(state_set_node_key(&child->base_state, child_key->private_key,
                               child_key->public_key), CRABS_SUCCESS);
  machine_blueprint_t* grandchild = make_valid_blueprint();
  ASSERT_NE(grandchild, nullptr);
  strncpy(grandchild->child_id, "child-red",
          sizeof(grandchild->child_id) - 1);
  attribute_machine_t* rejected = nullptr;
  EXPECT_EQ(lineage_spawn_machine(&child->base_state, grandchild, &rejected),
            CRABS_ERR_DUPLICATE_OPERATION);
  EXPECT_EQ(rejected, nullptr);
  EXPECT_EQ(child->base_state.child_count, 0u);

  crypto_ecdsa_keypair_destroy(child_key);
  machine_blueprint_destroy(grandchild);
  machine_blueprint_destroy(blueprint);
  attribute_machine_destroy(child);
  spawn_parent_destroy(&harness);
}

// ============================================================
// Blueprint wire format
// ============================================================

TEST(TestLineage, BlueprintSerializeDeserializeRoundTrip) {
  machine_blueprint_t* blueprint = machine_blueprint_create();
  ASSERT_NE(blueprint, nullptr);
  strncpy(blueprint->child_id, "child-blue", sizeof(blueprint->child_id) - 1);
  blueprint->trust_mode = LINEAGE_DELEGATED_COPY;
  strncpy(blueprint->bootstrap_admin, "child-admin",
          sizeof(blueprint->bootstrap_admin) - 1);
  blueprint->attestation_ttl_ms = 120000;

  EXPECT_EQ(blueprint_add_item(blueprint, "counter", DATA_TYPE_COUNTER,
                               CRDT_G_COUNTER), CRABS_SUCCESS);
  EXPECT_EQ(blueprint_add_item(blueprint, "doc", DATA_TYPE_REGISTER,
                               CRDT_LWW_REG), CRABS_SUCCESS);
  EXPECT_EQ(blueprint_add_policy(blueprint, "render",
                                 "@parent/role:writer"), CRABS_SUCCESS);
  EXPECT_EQ(blueprint_add_policy(blueprint, "increment",
                                 "custody:child-blue"), CRABS_SUCCESS);

  dedup_spec_t dedup;
  memset(&dedup, 0, sizeof(dedup));
  dedup.type = DEDUP_NONE;
  EXPECT_EQ(blueprint_add_op_type_def(blueprint, "increment", &dedup),
            CRABS_SUCCESS);
  EXPECT_EQ(lineage_blueprint_validate(blueprint), CRABS_SUCCESS);

  // The stamp is a public entry point but serialize calls it internally,
  // so the hash on the wire image always matches the serialized body.
  uint8_t wire[CRABS_BLUEPRINT_WIRE_MAX];
  size_t wire_len = blueprint_serialize(blueprint, wire, sizeof(wire));
  ASSERT_GT(wire_len, 0u);
  for (int byte_index = 0; byte_index < CRABS_HASH_SIZE; byte_index++) {
    EXPECT_NE(blueprint->blueprint_hash[byte_index], 0);
  }

  machine_blueprint_t* restored = blueprint_deserialize(wire, wire_len);
  ASSERT_NE(restored, nullptr);
  EXPECT_STREQ(restored->child_id, "child-blue");
  EXPECT_EQ(restored->trust_mode, LINEAGE_DELEGATED_COPY);
  EXPECT_STREQ(restored->bootstrap_admin, "child-admin");
  EXPECT_EQ(restored->attestation_ttl_ms, 120000u);
  ASSERT_EQ(restored->item_count, 2u);
  EXPECT_STREQ(restored->items[0].name, "counter");
  EXPECT_EQ(restored->items[0].type, DATA_TYPE_COUNTER);
  EXPECT_EQ(restored->items[0].crdt_type, CRDT_G_COUNTER);
  EXPECT_STREQ(restored->items[1].name, "doc");
  EXPECT_EQ(restored->items[1].type, DATA_TYPE_REGISTER);
  EXPECT_EQ(restored->items[1].crdt_type, CRDT_LWW_REG);
  ASSERT_EQ(restored->policy_count, 2u);
  EXPECT_STREQ(restored->policies[0].operation, "render");
  EXPECT_STREQ(restored->policies[0].expression, "@parent/role:writer");
  EXPECT_STREQ(restored->policies[1].operation, "increment");
  EXPECT_STREQ(restored->policies[1].expression, "custody:child-blue");
  ASSERT_EQ(restored->op_type_def_count, 1u);
  EXPECT_STREQ(restored->op_type_defs[0].op_type, "increment");
  EXPECT_EQ(restored->op_type_defs[0].dedup.type, DEDUP_NONE);
  // The restored blueprint validates and re-serializes BYTE-IDENTICALLY —
  // the canonical body writer is the single source of layout truth.
  EXPECT_EQ(lineage_blueprint_validate(restored), CRABS_SUCCESS);
  uint8_t wire_again[CRABS_BLUEPRINT_WIRE_MAX];
  size_t wire_again_len = blueprint_serialize(restored, wire_again,
                                              sizeof(wire_again));
  ASSERT_EQ(wire_again_len, wire_len);
  EXPECT_EQ(memcmp(wire_again, wire, wire_len), 0);

  machine_blueprint_destroy(restored);
  machine_blueprint_destroy(blueprint);
}

TEST(TestLineage, BlueprintDeserializeRejectsHashMismatch) {
  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);

  uint8_t wire[CRABS_BLUEPRINT_WIRE_MAX];
  size_t wire_len = blueprint_serialize(blueprint, wire, sizeof(wire));
  ASSERT_GT(wire_len, 0u);

  // Flip a byte INSIDE the body (child_id field, offset 4 prefix + 1 mode + 2
  // string16 length) without touching the stored hash — deserialize must
  // reject, not silently accept a tampered body.
  wire[7] ^= 0x01;
  EXPECT_EQ(blueprint_deserialize(wire, wire_len), nullptr);

  // A wire image truncated by one byte is malformed too.
  wire[7] ^= 0x01;
  EXPECT_EQ(blueprint_deserialize(wire, wire_len - 1), nullptr);

  // NULL/zero-size arguments never parse.
  EXPECT_EQ(blueprint_deserialize(nullptr, wire_len), nullptr);
  EXPECT_EQ(blueprint_deserialize(wire, 0), nullptr);

  machine_blueprint_destroy(blueprint);
}

TEST(TestLineage, BlueprintStampHashRejectsInvalidStruct) {
  EXPECT_EQ(machine_blueprint_stamp_hash(nullptr), CRABS_ERR_INVALID_PARAM);

  // A hand-built struct with a capacity-full (unterminated) child_id field
  // has no reproducible canonical body — the stamp fails closed.
  machine_blueprint_t* unterminated = machine_blueprint_create();
  ASSERT_NE(unterminated, nullptr);
  memset(unterminated->child_id, 'a', sizeof(unterminated->child_id));
  EXPECT_EQ(machine_blueprint_stamp_hash(unterminated),
            CRABS_ERR_INVALID_PARAM);
  machine_blueprint_destroy(unterminated);
}

TEST(TestLineage, SpawnRejectsInvalidBlueprint) {
  // Rejects: nullptr arguments, an invalid blueprint, a keyless parent — and
  // every rejection leaves NO manifest residue and no child allocation.
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);

  attribute_machine_t* child = nullptr;
  EXPECT_EQ(lineage_spawn_machine(nullptr, blueprint, &child),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(lineage_spawn_machine(parent, nullptr, &child),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(lineage_spawn_machine(parent, blueprint, nullptr),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(parent->child_count, 0u);

  blueprint->trust_mode = (lineage_trust_mode_e)0x7F;
  EXPECT_EQ(lineage_spawn_machine(parent, blueprint, &child),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(child, nullptr);
  EXPECT_EQ(parent->child_count, 0u);
  blueprint->trust_mode = LINEAGE_SHARED_ROOT;

  // A parent machine that cannot sign genesis provenance cannot mint.
  uint8_t phantom_pk[33];
  memset(phantom_pk, 0xAB, sizeof(phantom_pk));
  phantom_pk[0] = 0x02;
  attribute_machine_t* keyless = attribute_machine_create("keyless-root",
                                                          phantom_pk);
  ASSERT_NE(keyless, nullptr);
  keyless->base_state.attr_machine = keyless;
  EXPECT_FALSE(keyless->base_state.node_key_valid);
  EXPECT_EQ(lineage_spawn_machine(&keyless->base_state, blueprint, &child),
            CRABS_ERR_CRYPTOGRAPHIC_ERROR);
  EXPECT_EQ(child, nullptr);
  EXPECT_EQ(keyless->base_state.child_count, 0u);
  attribute_machine_destroy(keyless);

  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}

// ============================================================
// Lineage status wire: enum extension stays v11-compatible
// ============================================================

// Direct-field fixture (same shape as test_serialization.cpp's
// append_manifest_entry): the children array is owned by the state.
static void append_manifest_entry_fixture(state_t* state, const char* child_id,
                                          lineage_trust_mode_e mode,
                                          lineage_status_e status) {
  child_manifest_entry_t* grown = (child_manifest_entry_t*)realloc(
      state->children,
      (state->child_count + 1) * sizeof(child_manifest_entry_t));
  ASSERT_NE(grown, nullptr);
  state->children = grown;
  child_manifest_entry_t* entry = &state->children[state->child_count];
  memset(entry, 0, sizeof(*entry));
  strncpy(entry->child_id, child_id, CRABS_MAX_USER_ID - 1);
  entry->mode = mode;
  entry->status = status;
  entry->attestation_ttl_ms = 60000;
  entry->spawned_at = 1700000000000;
  state->child_count++;
}

TEST(TestLineage, ManifestStatusExtensionRoundTrips) {
  // ATTESTATION_REVOKED was added to the u8 status wire WITHOUT a format
  // bump — every status round trips through the v11 reader.
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  append_manifest_entry_fixture(state, "child-a", LINEAGE_SHARED_ROOT,
                                LINEAGE_ACTIVE);
  append_manifest_entry_fixture(state, "child-b", LINEAGE_DELEGATED_COPY,
                                LINEAGE_DISSOLVED);
  append_manifest_entry_fixture(state, "child-c", LINEAGE_DELEGATED_COPY,
                                LINEAGE_ATTESTATION_REVOKED);
  append_manifest_entry_fixture(state, "child-d", LINEAGE_SOVEREIGN,
                                LINEAGE_WITHDRAWN);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);
  ASSERT_EQ(restored->child_count, 4u);
  EXPECT_EQ(restored->children[0].status, LINEAGE_ACTIVE);
  EXPECT_EQ(restored->children[1].status, LINEAGE_DISSOLVED);
  EXPECT_EQ(restored->children[2].status, LINEAGE_ATTESTATION_REVOKED);
  EXPECT_EQ(restored->children[3].status, LINEAGE_WITHDRAWN);
  EXPECT_FALSE(restored->lineage_parent_dissolved);
  EXPECT_EQ(restored->resident_children, nullptr);

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

TEST(TestLineage, ManifestStatusOutOfRangeRejected) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  append_manifest_entry_fixture(state, "child-red", LINEAGE_SHARED_ROOT,
                                LINEAGE_ACTIVE);
  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  state_destroy(state);

  // Status sits at needle + 125 in the v11 entry image (11-byte id needle;
  // mode at +11, 32B hash, 64B sig, ttl, spawned_at, status).
  const uint8_t needle[11] = {0x09, 0x00, 'c', 'h', 'i', 'l', 'd', '-', 'r', 'e', 'd'};
  bool found = false;
  for (size_t index = 0; index + 11 <= buf->len - CRABS_HASH_SIZE; index++) {
    if (memcmp(buf->data + index, needle, 11) == 0) {
      buf->data[index + 125] = 0x7F;
      found = true;
      break;
    }
  }
  ASSERT_TRUE(found);
  uint8_t recomputed_hash[CRABS_HASH_SIZE];
  SHA256(buf->data, buf->len - CRABS_HASH_SIZE, recomputed_hash);
  memcpy(buf->data + buf->len - CRABS_HASH_SIZE, recomputed_hash,
         CRABS_HASH_SIZE);
  EXPECT_EQ(crabs_deserialize_state(buf->data, buf->len), nullptr);

  serialized_buffer_destroy(buf);
}

// ============================================================
// Lineage ops: spawn / revoke / dissolve / withdraw via the pipeline
// ============================================================

// Sign a lineage op carrying a raw payload (blueprint wire image or child_id
// string). The payload is owned by the op (operation_destroy frees it).
static operation_t* make_signed_lineage_op(attribute_machine_t* registry,
                                           ecdsa_keypair_t* signer_key,
                                           const char* signer_id,
                                           const char* op_type,
                                           const void* payload,
                                           size_t payload_size) {
  operation_t* op = operation_create(op_type);
  EXPECT_NE(op, nullptr);
  if (op == NULL) return NULL;
  op->payload = (uint8_t*)malloc(payload_size);
  EXPECT_NE(op->payload, nullptr);
  if (op->payload == NULL) {
    operation_destroy(op);
    return NULL;
  }
  memcpy(op->payload, payload, payload_size);
  op->payload_size = (uint32_t)payload_size;
  strncpy(op->signer_id, signer_id, CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(registry, signer_key, op);
  return op;
}

TEST(TestLineage, SpawnViaOp) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  ASSERT_EQ(attribute_machine_grant_role(harness.am, "alice", "role", "admin",
                                         "parent-root"), CRABS_SUCCESS);

  // Idempotent installer: a second call registers nothing new.
  lineage_install(parent);
  EXPECT_EQ(parent->op_handler_count, 4u);
  lineage_install(parent);
  EXPECT_EQ(parent->op_handler_count, 4u);
  EXPECT_EQ(parent->op_type_def_count, 4u);
  EXPECT_NE(state_find_policy(parent, CRABS_LINEAGE_OP_SPAWN), nullptr);

  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);
  uint8_t wire[CRABS_BLUEPRINT_WIRE_MAX];
  size_t wire_len = blueprint_serialize(blueprint, wire, sizeof(wire));
  ASSERT_GT(wire_len, 0u);

  operation_t* op = make_signed_lineage_op(harness.am, harness.alice_key,
                                           "alice", CRABS_LINEAGE_OP_SPAWN,
                                           wire, wire_len);
  ASSERT_NE(op, nullptr);
  EXPECT_EQ(state_machine_execute(parent, op), CRABS_SUCCESS);

  // The child exists: manifest entry + runtime resident registry.
  ASSERT_EQ(parent->child_count, 1u);
  EXPECT_STREQ(parent->children[0].child_id, "child-red");
  EXPECT_EQ(parent->children[0].status, LINEAGE_ACTIVE);
  ASSERT_EQ(parent->resident_child_count, 1u);
  EXPECT_NE(parent->resident_children[0], nullptr);
  EXPECT_STREQ(parent->resident_children[0]->base_state.lineage_self_id,
               "child-red");

  operation_destroy(op);

  // Without role:admin the same blueprint is denied at authorization.
  spawn_parent_harness_t outsider;
  memset(&outsider, 0, sizeof(outsider));
  outsider.parent_key = crypto_ecdsa_generate();
  ASSERT_NE(outsider.parent_key, nullptr);
  outsider.am = attribute_machine_create("parent-root-2",
                                         outsider.parent_key->public_key);
  ASSERT_NE(outsider.am, nullptr);
  outsider.am->base_state.attr_machine = outsider.am;
  ASSERT_EQ(state_set_node_key(&outsider.am->base_state,
                               outsider.parent_key->private_key,
                               outsider.parent_key->public_key),
            CRABS_SUCCESS);
  outsider.alice_key = crypto_ecdsa_generate();
  ASSERT_NE(outsider.alice_key, nullptr);
  ASSERT_EQ(attribute_machine_register_user(outsider.am, "alice",
                                            outsider.alice_key->public_key, ""),
            CRABS_SUCCESS);
  lineage_install(&outsider.am->base_state);
  machine_blueprint_t* blueprint2 = make_valid_blueprint();
  ASSERT_NE(blueprint2, nullptr);
  uint8_t wire2[CRABS_BLUEPRINT_WIRE_MAX];
  size_t wire2_len = blueprint_serialize(blueprint2, wire2, sizeof(wire2));
  ASSERT_GT(wire2_len, 0u);
  operation_t* denied = make_signed_lineage_op(
      outsider.am, outsider.alice_key, "alice", CRABS_LINEAGE_OP_SPAWN,
      wire2, wire2_len);
  ASSERT_NE(denied, nullptr);
  EXPECT_EQ(state_machine_execute(&outsider.am->base_state, denied),
            CRABS_ERR_UNAUTHORIZED);
  EXPECT_EQ(outsider.am->base_state.child_count, 0u);

  operation_destroy(denied);
  machine_blueprint_destroy(blueprint2);
  crypto_ecdsa_keypair_destroy(outsider.parent_key);
  crypto_ecdsa_keypair_destroy(outsider.alice_key);
  attribute_machine_destroy(outsider.am);
  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, RevokeAttestationViaOp) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  ASSERT_EQ(attribute_machine_grant_role(harness.am, "alice", "role", "admin",
                                         "parent-root"), CRABS_SUCCESS);
  lineage_install(parent);

  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  attribute_machine_destroy(child);

  // Revoke the child's attestation authority via the op.
  operation_t* revoke = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice",
      CRABS_LINEAGE_OP_REVOKE_ATTESTATION, "child-red", strlen("child-red"));
  ASSERT_NE(revoke, nullptr);
  EXPECT_EQ(state_machine_execute(parent, revoke), CRABS_SUCCESS);
  EXPECT_EQ(parent->children[0].status, LINEAGE_ATTESTATION_REVOKED);
  operation_destroy(revoke);

  // Revoking twice is idempotent-rejected, not a re-write.
  operation_t* again = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice",
      CRABS_LINEAGE_OP_REVOKE_ATTESTATION, "child-red", strlen("child-red"));
  ASSERT_NE(again, nullptr);
  EXPECT_EQ(state_machine_execute(parent, again),
            CRABS_ERR_ALREADY_PERFORMED);
  operation_destroy(again);

  // Unknown child.
  operation_t* unknown = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice",
      CRABS_LINEAGE_OP_REVOKE_ATTESTATION, "child-ghost",
      strlen("child-ghost"));
  ASSERT_NE(unknown, nullptr);
  EXPECT_EQ(state_machine_execute(parent, unknown),
            CRABS_ERR_RESOURCE_NOT_FOUND);
  operation_destroy(unknown);

  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, DissolveViaOpSeversResidentChildImmediately) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  ASSERT_EQ(attribute_machine_grant_role(harness.am, "alice", "role", "admin",
                                         "parent-root"), CRABS_SUCCESS);
  lineage_install(parent);

  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  ASSERT_NE(child, nullptr);
  EXPECT_FALSE(child->base_state.lineage_parent_dissolved);

  operation_t* dissolve = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice", CRABS_LINEAGE_OP_DISSOLVE,
      "child-red", strlen("child-red"));
  ASSERT_NE(dissolve, nullptr);
  EXPECT_EQ(state_machine_execute(parent, dissolve), CRABS_SUCCESS);
  operation_destroy(dissolve);

  // Manifest DISSOLVED; the resident child is severed INSTANTLY (its
  // endorsement gate fails closed) and dropped from the registry (the
  // pointer array keeps its size — the slot is NULL, the child object
  // outlives the dissolve under its owner's control).
  ASSERT_EQ(parent->child_count, 1u);
  EXPECT_EQ(parent->children[0].status, LINEAGE_DISSOLVED);
  EXPECT_TRUE(child->base_state.lineage_parent_dissolved);
  ASSERT_EQ(parent->resident_child_count, 1u);
  EXPECT_EQ(parent->resident_children[0], nullptr);

  // Already dissolved.
  operation_t* again = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice", CRABS_LINEAGE_OP_DISSOLVE,
      "child-red", strlen("child-red"));
  ASSERT_NE(again, nullptr);
  EXPECT_EQ(state_machine_execute(parent, again),
            CRABS_ERR_ALREADY_PERFORMED);
  operation_destroy(again);

  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, SovereignDissolveRefusedWithdrawSovereignOnly) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  ASSERT_EQ(attribute_machine_grant_role(harness.am, "alice", "role", "admin",
                                         "parent-root"), CRABS_SUCCESS);
  lineage_install(parent);

  // Sovereign child.
  machine_blueprint_t* sovereign = make_fresh_authority_blueprint(
      "child-sov", LINEAGE_SOVEREIGN);
  ASSERT_NE(sovereign, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, sovereign, &child), CRABS_SUCCESS);

  // Dissolve is refused for sovereigns; the status stays ACTIVE.
  operation_t* dissolve = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice", CRABS_LINEAGE_OP_DISSOLVE,
      "child-sov", strlen("child-sov"));
  ASSERT_NE(dissolve, nullptr);
  EXPECT_EQ(state_machine_execute(parent, dissolve),
            CRABS_ERR_UNAUTHORIZED);
  operation_destroy(dissolve);
  EXPECT_EQ(parent->children[0].status, LINEAGE_ACTIVE);

  // Withdraw belongs to sovereigns: it succeeds here.
  operation_t* withdraw = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice",
      CRABS_LINEAGE_OP_WITHDRAW_GENESIS, "child-sov", strlen("child-sov"));
  ASSERT_NE(withdraw, nullptr);
  EXPECT_EQ(state_machine_execute(parent, withdraw), CRABS_SUCCESS);
  operation_destroy(withdraw);
  EXPECT_EQ(parent->children[0].status, LINEAGE_WITHDRAWN);

  // ...but a second withdraw is already-performed.
  operation_t* again = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice",
      CRABS_LINEAGE_OP_WITHDRAW_GENESIS, "child-sov", strlen("child-sov"));
  ASSERT_NE(again, nullptr);
  EXPECT_EQ(state_machine_execute(parent, again),
            CRABS_ERR_ALREADY_PERFORMED);
  operation_destroy(again);

  // A non-sovereign child cannot be withdrawn — dissolve is a different op.
  machine_blueprint_t* shared = make_valid_blueprint();
  ASSERT_NE(shared, nullptr);
  strncpy(shared->child_id, "child-shared", sizeof(shared->child_id) - 1);
  attribute_machine_t* shared_child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, shared, &shared_child),
            CRABS_SUCCESS);
  operation_t* withdraw_shared = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice",
      CRABS_LINEAGE_OP_WITHDRAW_GENESIS, "child-shared",
      strlen("child-shared"));
  ASSERT_NE(withdraw_shared, nullptr);
  EXPECT_EQ(state_machine_execute(parent, withdraw_shared),
            CRABS_ERR_UNAUTHORIZED);
  operation_destroy(withdraw_shared);
  EXPECT_EQ(parent->children[1].status, LINEAGE_ACTIVE);

  machine_blueprint_destroy(sovereign);
  machine_blueprint_destroy(shared);
  attribute_machine_destroy(child);
  attribute_machine_destroy(shared_child);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, DissolutionTombstoneSignsOnlyAfterDissolve) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;

  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);

  // A child that is not dissolved cannot be signed away — the tombstone
  // would be a lie.
  uint8_t tombstone[CRABS_SIG_SIZE];
  EXPECT_EQ(lineage_sign_dissolution(parent, "child-red", tombstone),
            CRABS_ERR_UNAUTHORIZED);
  EXPECT_EQ(lineage_sign_dissolution(parent, "child-ghost", tombstone),
            CRABS_ERR_RESOURCE_NOT_FOUND);
  EXPECT_EQ(lineage_sign_dissolution(parent, "a<b", tombstone),
            CRABS_ERR_INVALID_PARAM);

  // Dissolve directly through the handler (it runs post-authorization, so
  // an unsigned op shell is enough for a direct call), then the tombstone
  // signs and verifies against the parent's node public key over the
  // canonical tombstone bytes `u8 tag + string16 child_id`.
  operation_t* dissolve_op = operation_create(CRABS_LINEAGE_OP_DISSOLVE);
  ASSERT_NE(dissolve_op, nullptr);
  EXPECT_EQ(lineage_op_dissolve(parent, dissolve_op),
            CRABS_ERR_INVALID_PARAM);  // no payload
  dissolve_op->payload = (uint8_t*)"child-red";
  dissolve_op->payload_size = (uint32_t)strlen("child-red");
  EXPECT_EQ(lineage_op_dissolve(parent, dissolve_op), CRABS_SUCCESS);
  EXPECT_EQ(parent->children[0].status, LINEAGE_DISSOLVED);
  EXPECT_TRUE(child->base_state.lineage_parent_dissolved);
  dissolve_op->payload = NULL;
  operation_destroy(dissolve_op);

  EXPECT_EQ(lineage_sign_dissolution(parent, "child-red", tombstone),
            CRABS_SUCCESS);
  uint8_t canonical_tombstone[1 + 2 + 9];
  canonical_tombstone[0] = (uint8_t)LINEAGE_DISSOLVED;
  canonical_tombstone[1] = 9;
  canonical_tombstone[2] = 0;
  memcpy(canonical_tombstone + 3, "child-red", 9);
  EXPECT_TRUE(crypto_ecdsa_verify(harness.parent_key->public_key,
                                  canonical_tombstone,
                                  sizeof(canonical_tombstone), tombstone));

  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}
