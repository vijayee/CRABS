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
// Test-only shim (test_lineage_body_writer.c): direct access to the static
// canonical key-transition body writer for its cap-refusal unit test.
size_t crabs_test_lineage_key_transition_write_body(
    uint64_t new_key_version, const uint8_t new_pk[33],
    const uint8_t old_pk[33], const char* parent_id, uint64_t created_at,
    uint8_t* out, size_t cap);
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

// Bind the child state to a parent: public key + self id + bound flag +
// chain[0] = the spawn pin (the in-memory shape spawn produces — spawn stamps
// the chain at binding time so chain-aware verification works from genesis).
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
  child_state->lineage_key_chain = (lineage_key_chain_entry_t*)calloc(
      1, sizeof(lineage_key_chain_entry_t));
  ASSERT_NE(child_state->lineage_key_chain, nullptr);
  child_state->lineage_key_chain[0].key_version =
      CRABS_LINEAGE_KEY_VERSION_START;
  memcpy(child_state->lineage_key_chain[0].public_key,
         parent_key->public_key, 33);
  child_state->lineage_key_chain_count = 1;
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

// Engine change: a zero-resource custom op whose policy authorizes it but
// that has no registered handler fails CRABS_ERR_RESOURCE_NOT_FOUND instead
// of silently succeeding. The child fixtures' zero-resource ops ("increment",
// "render") exist only to exercise the authorization and endorsement gates,
// so each spawned child that executes them gets this real (trivial) op body.
// The gates the tests assert on all run in the execute pipeline BEFORE the
// handler is reached, so denial paths are unaffected.
static crabs_error_e increment_no_op_handler(state_t* state, operation_t* op) {
  (void)state;
  (void)op;
  return CRABS_SUCCESS;
}

static crabs_error_e render_no_op_handler(state_t* state, operation_t* op) {
  (void)state;
  (void)op;
  return CRABS_SUCCESS;
}

static void register_child_increment_handler(attribute_machine_t* child) {
  ASSERT_EQ(state_machine_register_handler(&child->base_state, "increment",
            increment_no_op_handler), CRABS_SUCCESS);
}

static void register_child_render_handler(attribute_machine_t* child) {
  ASSERT_EQ(state_machine_register_handler(&child->base_state, "render",
            render_no_op_handler), CRABS_SUCCESS);
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
  register_child_increment_handler(child);

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
  ASSERT_EQ(parent->child_count, 1u);
  const child_manifest_entry_t* manifest_entry = &parent->children[0];
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

  // Change event: kind SPAWN, type __spawn_machine__, no uuid/signer, but
  // attributed to the parent's node identity (per-node devtools drains and
  // node.on('change') dispatch both filter on the node field).
  ASSERT_EQ(captured_event_count, 1u);
  EXPECT_EQ(captured_events[0].kind, CRABS_CHANGE_SPAWN);
  EXPECT_STREQ(captured_events[0].type, "__spawn_machine__");
  EXPECT_EQ(captured_events[0].uuid, nullptr);
  EXPECT_EQ(captured_events[0].signer_id, nullptr);
  EXPECT_NE(captured_events[0].node_id, nullptr);
  // The harness's parent state has no HLC initializer, so the node identity
  // falls back to the bootstrap admin.
  EXPECT_STREQ(captured_events[0].node_id, "parent-root");
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
  register_child_increment_handler(child);

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
  register_child_increment_handler(child);

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

// Locate the offset JUST PAST the last occurrence of a string16-carried
// ASCII blob in a serialized blueprint wire image (the u16le length prefix
// immediately precedes the text). Returns SIZE_MAX when not found.
static size_t blueprint_wire_find_string_end(uint8_t* wire, size_t wire_len,
                                             const char* text) {
  size_t text_len = strlen(text);
  size_t found = SIZE_MAX;
  for (size_t search = 0; search + 2 + text_len <= wire_len; search++) {
    if (wire[search] == (uint8_t)(text_len & 0xFF) &&
        wire[search + 1] == (uint8_t)(text_len >> 8) &&
        memcmp(wire + search + 2, text, text_len) == 0) {
      found = search + 2 + text_len;
    }
  }
  return found;
}

// Recompute the blueprint body-hash trailer after patching wire bytes, so the
// ONLY thing a deserializer can reject is the patched field itself (the hash
// is an integrity stamp, not an authenticity check — it is re-stampable).
static void blueprint_wire_restamp_hash(uint8_t* wire, size_t wire_len) {
  size_t body_len = wire_len - 4 - CRABS_HASH_SIZE;
  ASSERT_EQ(crypto_sha256(wire + 4, body_len, wire + 4 + body_len),
            CRABS_SUCCESS);
}

// A blueprint wire image whose item type byte is outside data_type_e must be
// rejected at load (A10-L2), hash re-stamped so only the enum byte differs.
TEST(TestLineage, BlueprintDeserializeRejectsOutOfRangeItemType) {
  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);

  uint8_t wire[CRABS_BLUEPRINT_WIRE_MAX];
  size_t wire_len = blueprint_serialize(blueprint, wire, sizeof(wire));
  ASSERT_GT(wire_len, 0u);

  size_t item_end = blueprint_wire_find_string_end(wire, wire_len, "counter");
  ASSERT_NE(item_end, SIZE_MAX);
  ASSERT_LT(item_end + 1, wire_len);
  // 0x0A sits in the gap between the classic types (0x01-0x09) and the OT
  // family (0x10-0x14); the original bytes are 0x01 (COUNTER) / 0x01 (G_COUNT).
  ASSERT_EQ(wire[item_end], (uint8_t)DATA_TYPE_COUNTER);
  ASSERT_EQ(wire[item_end + 1], (uint8_t)CRDT_G_COUNTER);

  wire[item_end] = 0x0A;
  blueprint_wire_restamp_hash(wire, wire_len);
  EXPECT_EQ(blueprint_deserialize(wire, wire_len), nullptr);

  wire[item_end] = (uint8_t)DATA_TYPE_COUNTER;
  wire[item_end + 1] = 0x07;  // no such crdt_type_e (0x01-0x06, 0x08, 0x09, 0xFF)
  blueprint_wire_restamp_hash(wire, wire_len);
  EXPECT_EQ(blueprint_deserialize(wire, wire_len), nullptr);

  machine_blueprint_destroy(blueprint);
}

// Same for the dedup spec bytes inside an op type definition: dedup_type and
// mutation_type are whitelisted at load too.
TEST(TestLineage, BlueprintDeserializeRejectsOutOfRangeDedupType) {
  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);

  uint8_t wire[CRABS_BLUEPRINT_WIRE_MAX];
  size_t wire_len = blueprint_serialize(blueprint, wire, sizeof(wire));
  ASSERT_GT(wire_len, 0u);

  // The LAST "increment" string16 is the op type definition's name (the
  // policy operation earlier in the image shares the same text); the dedup
  // spec begins immediately after it with the dedup_type byte.
  size_t spec_start = blueprint_wire_find_string_end(wire, wire_len,
                                                     "increment");
  ASSERT_NE(spec_start, SIZE_MAX);
  // Layout: u8 dedup_type | 3 X string16 (empty => 2 bytes each) | u8 mutation.
  size_t dedup_type_offset = spec_start;
  size_t mutation_type_offset = spec_start + 1 + 3 * 2;
  ASSERT_LT(mutation_type_offset, wire_len);
  ASSERT_EQ(wire[dedup_type_offset], (uint8_t)DEDUP_NONE);
  ASSERT_EQ(wire[mutation_type_offset], 0x00);

  wire[dedup_type_offset] = 0x7F;
  blueprint_wire_restamp_hash(wire, wire_len);
  EXPECT_EQ(blueprint_deserialize(wire, wire_len), nullptr);

  // update.type is whitelisted under DEDUP_CUSTOM (its only consumer);
  // mutation_type_e runs 0x01-0x04, 0xFF — 0x05 is out of range.
  wire[dedup_type_offset] = (uint8_t)DEDUP_CUSTOM;
  wire[mutation_type_offset] = 0x05;
  blueprint_wire_restamp_hash(wire, wire_len);
  EXPECT_EQ(blueprint_deserialize(wire, wire_len), nullptr);

  machine_blueprint_destroy(blueprint);
}

// Defense in depth: struct-level validation rejects out-of-range enums too,
// so a hand-built blueprint cannot reach spawn with them (A10-L2).
TEST(TestLineage, BlueprintValidateRejectsOutOfRangeCrdtType) {
  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);

  machine_blueprint_t* bad_crdt = make_valid_blueprint();
  ASSERT_NE(bad_crdt, nullptr);
  bad_crdt->items[0].crdt_type = (crdt_type_e)0x07;
  EXPECT_EQ(lineage_blueprint_validate(bad_crdt), CRABS_ERR_INVALID_PARAM);
  machine_blueprint_destroy(bad_crdt);

  machine_blueprint_t* bad_item = make_valid_blueprint();
  ASSERT_NE(bad_item, nullptr);
  bad_item->items[0].type = (data_type_e)0x0A;
  EXPECT_EQ(lineage_blueprint_validate(bad_item), CRABS_ERR_INVALID_PARAM);
  machine_blueprint_destroy(bad_item);

  machine_blueprint_t* bad_dedup = make_valid_blueprint();
  ASSERT_NE(bad_dedup, nullptr);
  bad_dedup->op_type_defs[0].dedup.type = (dedup_type_e)0x7F;
  EXPECT_EQ(lineage_blueprint_validate(bad_dedup), CRABS_ERR_INVALID_PARAM);
  machine_blueprint_destroy(bad_dedup);

  machine_blueprint_t* bad_mutation = make_valid_blueprint();
  ASSERT_NE(bad_mutation, nullptr);
  // update.type is checked only under DEDUP_CUSTOM (its sole consumer).
  bad_mutation->op_type_defs[0].dedup.type = DEDUP_CUSTOM;
  bad_mutation->op_type_defs[0].dedup.update.type = (mutation_type_e)0x05;
  EXPECT_EQ(lineage_blueprint_validate(bad_mutation), CRABS_ERR_INVALID_PARAM);
  machine_blueprint_destroy(bad_mutation);

  // Sanity: the untouched fixture still validates.
  EXPECT_EQ(lineage_blueprint_validate(blueprint), CRABS_SUCCESS);
  machine_blueprint_destroy(blueprint);
}

// A hand-built struct with count>0 but a NULL section array must be rejected
// by lineage_blueprint_validate, not dereferenced (de-wonk follow-up: the
// deserializer can never produce this shape, only a direct caller can).
TEST(TestLineage, BlueprintValidateRejectsCountWithoutArray) {
  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);

  blueprint->items = nullptr;  // count stays 1 from the fixture
  EXPECT_EQ(lineage_blueprint_validate(blueprint), CRABS_ERR_INVALID_PARAM);
  machine_blueprint_destroy(blueprint);

  machine_blueprint_t* blueprint2 = make_valid_blueprint();
  ASSERT_NE(blueprint2, nullptr);
  blueprint2->policies = nullptr;
  blueprint2->op_type_defs = nullptr;
  EXPECT_EQ(lineage_blueprint_validate(blueprint2), CRABS_ERR_INVALID_PARAM);
  machine_blueprint_destroy(blueprint2);
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

  // Garbage counts / count-without-array on a hand-built struct fail closed
  // instead of dereferencing (the writer never trusts the counts).
  machine_blueprint_t* garbage = machine_blueprint_create();
  ASSERT_NE(garbage, nullptr);
  garbage->item_count = 0xFFFFFFFF;
  EXPECT_EQ(machine_blueprint_stamp_hash(garbage), CRABS_ERR_INVALID_PARAM);
  garbage->item_count = 0;
  garbage->policy_count = 3;
  EXPECT_EQ(machine_blueprint_stamp_hash(garbage), CRABS_ERR_INVALID_PARAM);
  machine_blueprint_destroy(garbage);
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
// Lineage status wire: enum extension needs no format bump (the manifest
// entry layout is unchanged from v11 through v12)
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
  // ATTESTATION_REVOKED was added to the u8 status wire WITHOUT a layout
  // bump — every status round trips (readers gate the manifest section on
  // version >= 11, and v12 changed only the parent-binding tail).
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

  // Status sits at needle + 125 in the manifest entry image (layout
  // unchanged since v11; 11-byte id needle;
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

  // Idempotent installer: a second call registers nothing new (six lineage
  // ops since __parent_key_update__ joined).
  lineage_install(parent);
  EXPECT_EQ(parent->op_handler_count, 6u);
  lineage_install(parent);
  EXPECT_EQ(parent->op_handler_count, 6u);
  EXPECT_EQ(parent->op_type_def_count, 6u);
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

TEST(TestLineage, QueryResidentChildAccessor) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  ASSERT_EQ(attribute_machine_grant_role(harness.am, "alice", "role", "admin",
                                         "parent-root"), CRABS_SUCCESS);
  lineage_install(parent);

  // Direct spawn path: the accessor agrees EXACTLY with the pointer the
  // caller already owns.
  machine_blueprint_t* direct = make_valid_blueprint();
  ASSERT_NE(direct, nullptr);
  attribute_machine_t* child_direct = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, direct, &child_direct),
            CRABS_SUCCESS);
  ASSERT_NE(child_direct, nullptr);
  EXPECT_EQ(lineage_query_resident_child(parent, "child-red"), child_direct);

  // Op-spawned second child: the op pipeline never returns the pointer, so
  // the accessor is the only way back to the resident child.
  machine_blueprint_t* op_blueprint = make_valid_blueprint();
  ASSERT_NE(op_blueprint, nullptr);
  strncpy(op_blueprint->child_id, "child-blue",
          sizeof(op_blueprint->child_id) - 1);
  uint8_t wire[CRABS_BLUEPRINT_WIRE_MAX];
  size_t wire_len = blueprint_serialize(op_blueprint, wire, sizeof(wire));
  ASSERT_GT(wire_len, 0u);
  operation_t* op = make_signed_lineage_op(harness.am, harness.alice_key,
                                           "alice", CRABS_LINEAGE_OP_SPAWN,
                                           wire, wire_len);
  ASSERT_NE(op, nullptr);
  EXPECT_EQ(state_machine_execute(parent, op), CRABS_SUCCESS);
  operation_destroy(op);

  ASSERT_EQ(parent->resident_child_count, 2u);
  attribute_machine_t* child_op = lineage_query_resident_child(parent,
                                                               "child-blue");
  ASSERT_NE(child_op, nullptr);
  EXPECT_EQ(child_op, parent->resident_children[1]);
  EXPECT_STREQ(child_op->base_state.lineage_self_id, "child-blue");

  // Unknown id answers NULL.
  EXPECT_EQ(lineage_query_resident_child(parent, "child-ghost"), nullptr);

  // Dissolve clears the registry slot: a subsequent query answers NULL.
  operation_t* dissolve = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice", CRABS_LINEAGE_OP_DISSOLVE,
      "child-blue", strlen("child-blue"));
  ASSERT_NE(dissolve, nullptr);
  EXPECT_EQ(state_machine_execute(parent, dissolve), CRABS_SUCCESS);
  operation_destroy(dissolve);
  EXPECT_EQ(lineage_query_resident_child(parent, "child-blue"), nullptr);
  // The direct-path child was never dissolved: still resolvable.
  EXPECT_EQ(lineage_query_resident_child(parent, "child-red"), child_direct);

  attribute_machine_destroy(child_direct);
  attribute_machine_destroy(child_op);
  machine_blueprint_destroy(direct);
  machine_blueprint_destroy(op_blueprint);
  spawn_parent_destroy(&harness);
}

// ============================================================
// A10-5: the resident registry is NOT index-aligned with the manifest
// after a restart (the manifest is persisted; the registry starts empty)
// ============================================================

// Simulate a restart: the manifest is persisted (left untouched) while the
// runtime resident-children registry starts EMPTY on reload. This helper
// only frees the registry pointer array; the callers destroy the pre-restart
// machines themselves FIRST (each attribute_machine_destroy runs the A10-6
// hook, which drops then-NULL's the machine's slot — what remains is exactly
// the hole array a state load leaves behind).
static void simulate_restart_clears_registry(state_t* parent) {
  free(parent->resident_children);
  parent->resident_children = NULL;
  parent->resident_child_count = 0;
}

TEST(TestLineage, RegistrySurvivesRestartReindexing) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  ASSERT_EQ(attribute_machine_grant_role(harness.am, "alice", "role", "admin",
                                         "parent-root"), CRABS_SUCCESS);
  lineage_install(parent);

  // Pre-restart children A and B occupy manifest entries 0/1 AND registry
  // slots 0/1 — the alignment holds only until the process exits.
  machine_blueprint_t* blueprint_a = make_valid_blueprint();
  ASSERT_NE(blueprint_a, nullptr);
  strncpy(blueprint_a->child_id, "child-aaa",
          sizeof(blueprint_a->child_id) - 1);
  attribute_machine_t* child_a = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint_a, &child_a),
            CRABS_SUCCESS);
  machine_blueprint_t* blueprint_b = make_valid_blueprint();
  ASSERT_NE(blueprint_b, nullptr);
  strncpy(blueprint_b->child_id, "child-bbb",
          sizeof(blueprint_b->child_id) - 1);
  attribute_machine_t* child_b = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint_b, &child_b),
            CRABS_SUCCESS);
  ASSERT_EQ(parent->child_count, 2u);
  ASSERT_EQ(parent->resident_child_count, 2u);

  // Restart: A and B are destroyed with the old process; the manifest
  // (persisted) still lists them, the registry is empty.
  attribute_machine_destroy(child_a);
  attribute_machine_destroy(child_b);
  simulate_restart_clears_registry(parent);

  // Post-restart spawn: C lands in registry slot 0 — the slot a positional
  // lookup would (wrongly) resolve for manifest entry 0 ("child-aaa").
  machine_blueprint_t* blueprint_c = make_valid_blueprint();
  ASSERT_NE(blueprint_c, nullptr);
  strncpy(blueprint_c->child_id, "child-ccc",
          sizeof(blueprint_c->child_id) - 1);
  attribute_machine_t* child_c = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint_c, &child_c),
            CRABS_SUCCESS);
  ASSERT_EQ(parent->child_count, 3u);
  ASSERT_EQ(parent->resident_child_count, 1u);
  EXPECT_EQ(parent->resident_children[0], child_c);

  // Dissolving pre-restart A succeeds on the manifest and must NOT reach C:
  // C stays resident and un-severed (no wrong-machine severance).
  operation_t* dissolve_a = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice", CRABS_LINEAGE_OP_DISSOLVE,
      "child-aaa", strlen("child-aaa"));
  ASSERT_NE(dissolve_a, nullptr);
  EXPECT_EQ(state_machine_execute(parent, dissolve_a), CRABS_SUCCESS);
  operation_destroy(dissolve_a);
  EXPECT_EQ(parent->children[0].status, LINEAGE_DISSOLVED);
  EXPECT_FALSE(child_c->base_state.lineage_parent_dissolved);
  EXPECT_EQ(lineage_query_resident_child(parent, "child-ccc"), child_c);

  // Dissolve B likewise: manifest-only, no fallout on the resident C.
  operation_t* dissolve_b = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice", CRABS_LINEAGE_OP_DISSOLVE,
      "child-bbb", strlen("child-bbb"));
  ASSERT_NE(dissolve_b, nullptr);
  EXPECT_EQ(state_machine_execute(parent, dissolve_b), CRABS_SUCCESS);
  operation_destroy(dissolve_b);
  EXPECT_EQ(parent->children[1].status, LINEAGE_DISSOLVED);
  EXPECT_FALSE(child_c->base_state.lineage_parent_dissolved);
  EXPECT_EQ(lineage_query_resident_child(parent, "child-ccc"), child_c);

  // Dissolving C itself severs C in-process and drops it from the registry —
  // the positional lookup would miss it entirely (manifest index 2 is out of
  // bounds for a one-slot registry).
  operation_t* dissolve_c = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice", CRABS_LINEAGE_OP_DISSOLVE,
      "child-ccc", strlen("child-ccc"));
  ASSERT_NE(dissolve_c, nullptr);
  EXPECT_EQ(state_machine_execute(parent, dissolve_c), CRABS_SUCCESS);
  operation_destroy(dissolve_c);
  EXPECT_EQ(parent->children[2].status, LINEAGE_DISSOLVED);
  EXPECT_TRUE(child_c->base_state.lineage_parent_dissolved);
  EXPECT_EQ(lineage_query_resident_child(parent, "child-ccc"), nullptr);

  attribute_machine_destroy(child_c);
  machine_blueprint_destroy(blueprint_a);
  machine_blueprint_destroy(blueprint_b);
  machine_blueprint_destroy(blueprint_c);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, QueryKeyedByIdNotIndex) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;

  // Same restart shape: A and B persist only in the manifest.
  machine_blueprint_t* blueprint_a = make_valid_blueprint();
  ASSERT_NE(blueprint_a, nullptr);
  strncpy(blueprint_a->child_id, "child-aaa",
          sizeof(blueprint_a->child_id) - 1);
  attribute_machine_t* child_a = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint_a, &child_a),
            CRABS_SUCCESS);
  machine_blueprint_t* blueprint_b = make_valid_blueprint();
  ASSERT_NE(blueprint_b, nullptr);
  strncpy(blueprint_b->child_id, "child-bbb",
          sizeof(blueprint_b->child_id) - 1);
  attribute_machine_t* child_b = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint_b, &child_b),
            CRABS_SUCCESS);
  attribute_machine_destroy(child_a);
  attribute_machine_destroy(child_b);
  simulate_restart_clears_registry(parent);

  machine_blueprint_t* blueprint_c = make_valid_blueprint();
  ASSERT_NE(blueprint_c, nullptr);
  strncpy(blueprint_c->child_id, "child-ccc",
          sizeof(blueprint_c->child_id) - 1);
  attribute_machine_t* child_c = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint_c, &child_c),
            CRABS_SUCCESS);

  // Pre-restart ids resolve to NULL (their slots are gone — the manifest
  // entry existing does NOT make the machine resident); C resolves to its
  // machine regardless of sitting in slot 0 under manifest index 2.
  EXPECT_EQ(lineage_query_resident_child(parent, "child-aaa"), nullptr);
  EXPECT_EQ(lineage_query_resident_child(parent, "child-bbb"), nullptr);
  EXPECT_EQ(lineage_query_resident_child(parent, "child-ccc"), child_c);
  EXPECT_EQ(lineage_query_resident_child(parent, "child-ghost"), nullptr);

  attribute_machine_destroy(child_c);
  machine_blueprint_destroy(blueprint_a);
  machine_blueprint_destroy(blueprint_b);
  machine_blueprint_destroy(blueprint_c);
  spawn_parent_destroy(&harness);
}

// ============================================================
// A10-6: out-of-band destroy of a resident child must not leave a dangling
// registry slot for __dissolve_machine__ (or any find-by-id) to touch.
// ============================================================

TEST(TestLineage, OutOfBandChildDestroyIsSafeForDissolve) {
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

  // Sanity: pre-destroy the child IS resident and resolves.
  EXPECT_EQ(lineage_query_resident_child(parent, "child-red"), child);

  // Out-of-band destroy — the exact pattern the spawn caller is entitled to
  // (lineage.h: the spawn caller owns the child and destroys it via
  // attribute_machine_destroy; the node bindings' destructor does precisely
  // this for spawned_machines_).
  attribute_machine_destroy(child);

  // A10-6: the destroy hook must have dropped the registry slot — a query
  // answers NULL instead of strcmp'ing through a dangling pointer.
  EXPECT_EQ(lineage_query_resident_child(parent, "child-red"), nullptr);

  // Dissolve for the destroyed child still flips the manifest and must not
  // reach through freed memory (pre-fix this WRITES
  // resident->base_state.lineage_parent_dissolved on the freed child).
  operation_t* dissolve = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice", CRABS_LINEAGE_OP_DISSOLVE,
      "child-red", strlen("child-red"));
  ASSERT_NE(dissolve, nullptr);
  EXPECT_EQ(state_machine_execute(parent, dissolve), CRABS_SUCCESS);
  EXPECT_EQ(parent->children[0].status, LINEAGE_DISSOLVED);
  operation_destroy(dissolve);

  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}

// The reverse death order: the registry OWNER dies while a spawned child is
// still alive. This is exactly the node bindings' destructor order
// (~CrabsNode destroys am_ first, then spawned_machines_). state_destroy /
// attribute_machine_destroy must NULL the surviving children's weak
// lineage_owner_state back-pointers, or the child's later destroy would walk
// a dangling owner pointer (write-after-free on the dead parent).
TEST(TestLineage, ParentDestroyDetachesResidentChildren) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;

  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  ASSERT_NE(child, nullptr);
  EXPECT_EQ(child->lineage_owner_state, parent);

  // Parent machine dies with the child still resident (registry ownership
  // lives in the parent's base_state; the child must be detached BEFORE its
  // back-pointer becomes dangling).
  attribute_machine_destroy(harness.am);
  harness.am = nullptr;  // spawn_parent_destroy guards on NULL
  EXPECT_EQ(child->lineage_owner_state, nullptr);

  // Must be a no-op: no walk into the freed parent's registry.
  attribute_machine_destroy(child);

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

  // Capture the lineage op's change event. The OP event that wraps every
  // executed op is ignored here — only LINEAGE-kind events are captured.
  // Event strings are borrowed only for the hook call, so the target is
  // copied (the op handler's child_id is a stack buffer).
  static crabs_change_event_t captured_events[4];
  static char captured_targets[4][CRABS_MAX_USER_ID];
  static uint32_t captured_event_count;
  captured_event_count = 0;
  state_set_change_hook(parent, [](state_t*, const crabs_change_event_t* event,
                                   void*) {
    if (event->kind != CRABS_CHANGE_LINEAGE) return;
    if (captured_event_count >= 4) return;
    captured_events[captured_event_count] = *event;
    strncpy(captured_targets[captured_event_count],
            event->target ? event->target : "", CRABS_MAX_USER_ID - 1);
    captured_events[captured_event_count].target =
        captured_targets[captured_event_count];
    captured_event_count += 1;
  }, nullptr);

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
  // Change event: kind LINEAGE, the revoke op type, target = child, and
  // attributed to the executing op (signer/node/uuid) — per-node devtools
  // drains and node.on('change') dispatch both filter on the node field.
  ASSERT_EQ(captured_event_count, 1u);
  EXPECT_EQ(captured_events[0].kind, CRABS_CHANGE_LINEAGE);
  EXPECT_STREQ(captured_events[0].type, "__revoke_attestation__");
  EXPECT_NE(captured_events[0].uuid, nullptr);
  EXPECT_STREQ(captured_events[0].target, "child-red");
  EXPECT_STREQ(captured_events[0].preview, "attestation issuing revoked");
  EXPECT_EQ(captured_events[0].result, CRABS_SUCCESS);
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

  // Capture the lineage op's change event. The OP event that wraps every
  // executed op is ignored here — only LINEAGE-kind events are captured.
  // Event strings are borrowed only for the hook call, so the target is
  // copied (the op handler's child_id is a stack buffer).
  static crabs_change_event_t captured_events[4];
  static char captured_targets[4][CRABS_MAX_USER_ID];
  static uint32_t captured_event_count;
  captured_event_count = 0;
  state_set_change_hook(parent, [](state_t*, const crabs_change_event_t* event,
                                   void*) {
    if (event->kind != CRABS_CHANGE_LINEAGE) return;
    if (captured_event_count >= 4) return;
    captured_events[captured_event_count] = *event;
    strncpy(captured_targets[captured_event_count],
            event->target ? event->target : "", CRABS_MAX_USER_ID - 1);
    captured_events[captured_event_count].target =
        captured_targets[captured_event_count];
    captured_event_count += 1;
  }, nullptr);

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
  // Change event: kind LINEAGE, the dissolve op type, target = child, and
  // attributed to the executing op (signer/node/uuid) — per-node devtools
  // drains and node.on('change') dispatch both filter on the node field.
  ASSERT_EQ(captured_event_count, 1u);
  EXPECT_EQ(captured_events[0].kind, CRABS_CHANGE_LINEAGE);
  EXPECT_STREQ(captured_events[0].type, "__dissolve_machine__");
  EXPECT_NE(captured_events[0].uuid, nullptr);
  EXPECT_STREQ(captured_events[0].target, "child-red");
  EXPECT_STREQ(captured_events[0].preview, "dissolved");
  EXPECT_EQ(captured_events[0].result, CRABS_SUCCESS);
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

  // Capture the lineage op's change event. The OP event that wraps every
  // executed op is ignored here — only LINEAGE-kind events are captured
  // (a refused dissolve emits none; only the successful withdraw fires).
  // Event strings are borrowed only for the hook call, so the target is
  // copied (the op handler's child_id is a stack buffer).
  static crabs_change_event_t captured_events[4];
  static char captured_targets[4][CRABS_MAX_USER_ID];
  static uint32_t captured_event_count;
  captured_event_count = 0;
  state_set_change_hook(parent, [](state_t*, const crabs_change_event_t* event,
                                   void*) {
    if (event->kind != CRABS_CHANGE_LINEAGE) return;
    if (captured_event_count >= 4) return;
    captured_events[captured_event_count] = *event;
    strncpy(captured_targets[captured_event_count],
            event->target ? event->target : "", CRABS_MAX_USER_ID - 1);
    captured_events[captured_event_count].target =
        captured_targets[captured_event_count];
    captured_event_count += 1;
  }, nullptr);

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
  // Change event: kind LINEAGE, the withdraw op type, target = child, and
  // attributed to the executing op (signer/node/uuid) — per-node devtools
  // drains and node.on('change') dispatch both filter on the node field.
  ASSERT_EQ(captured_event_count, 1u);
  EXPECT_EQ(captured_events[0].kind, CRABS_CHANGE_LINEAGE);
  EXPECT_STREQ(captured_events[0].type, "__withdraw_genesis__");
  EXPECT_NE(captured_events[0].uuid, nullptr);
  EXPECT_STREQ(captured_events[0].target, "child-sov");
  EXPECT_STREQ(captured_events[0].preview, "genesis attested chain withdrawn");
  EXPECT_EQ(captured_events[0].result, CRABS_SUCCESS);
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

// ============================================================
// Dissolution tombstone delivery: __receive_dissolution__ on the child
// ============================================================

// Attach a stack tombstone wire to an op shell for DIRECT handler calls.
// Handlers run post-authorization, so an unsigned shell is enough (same
// idiom as DissolutionTombstoneSignsOnlyAfterDissolve); the payload pointer
// is cleared before destroy so operation_destroy never frees test-owned
// memory.
static operation_t* make_handler_shell_op(const char* op_type,
                                          const uint8_t* payload,
                                          size_t payload_size) {
  operation_t* op = operation_create(op_type);
  EXPECT_NE(op, nullptr);
  if (op == NULL) return NULL;
  op->payload = (uint8_t*)payload;
  op->payload_size = (uint32_t)payload_size;
  return op;
}

static void release_handler_shell_op(operation_t* op) {
  if (op == NULL) return;
  op->payload = NULL;
  op->payload_size = 0;
  operation_destroy(op);
}

TEST(TestLineage, TombstoneDeliveryOpSetsAndPersistsDissolveState) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;

  // Delegated child: its genesis admin ("child-admin", registered with the
  // parent's node public key) is the child-side operator who will carry the
  // tombstone in through the op pipeline.
  machine_blueprint_t* blueprint =
      make_fresh_authority_blueprint("child-delegated", LINEAGE_DELEGATED_COPY);
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  ASSERT_NE(child, nullptr);

  // Parent side: the dissolve op runs under the installer's role:admin gated
  // __dissolve_machine__.
  lineage_install(parent);

  // The child machine holds its own node key; the seal key seals the state's
  // ABE master key across the persistence round trip.
  ecdsa_keypair_t* child_key = crypto_ecdsa_generate();
  ASSERT_NE(child_key, nullptr);
  ASSERT_EQ(state_set_node_key(&child->base_state, child_key->private_key,
                               child_key->public_key), CRABS_SUCCESS);
  uint8_t seal_key[32];
  ASSERT_EQ(crypto_random_bytes(seal_key, sizeof(seal_key)), CRABS_SUCCESS);

  // The installer on the CHILD registers the delivery op: six lineage ops,
  // the delivery op gated "role:admin" like its five siblings. The blueprint
  // already contributed one op type definition ("increment").
  lineage_install(&child->base_state);
  EXPECT_EQ(child->base_state.op_handler_count, 6u);
  EXPECT_EQ(child->base_state.op_type_def_count, 7u);
  EXPECT_NE(state_find_policy(&child->base_state,
                              CRABS_LINEAGE_OP_RECEIVE_DISSOLUTION), nullptr);
  EXPECT_NE(state_find_op_type_def(&child->base_state,
                                   CRABS_LINEAGE_OP_RECEIVE_DISSOLUTION),
            nullptr);
  EXPECT_FALSE(child->base_state.lineage_parent_dissolved);

  // Dissolve the child parent-side through the pipeline (alice is admin).
  ASSERT_EQ(attribute_machine_grant_role(harness.am, "alice", "role", "admin",
                                         "parent-root"), CRABS_SUCCESS);
  operation_t* dissolve = make_signed_lineage_op(
      harness.am, harness.alice_key, "alice", CRABS_LINEAGE_OP_DISSOLVE,
      "child-delegated", strlen("child-delegated"));
  ASSERT_NE(dissolve, nullptr);
  EXPECT_EQ(state_machine_execute(parent, dissolve), CRABS_SUCCESS);
  operation_destroy(dissolve);
  EXPECT_EQ(parent->children[0].status, LINEAGE_DISSOLVED);
  // In-process severance already flipped the resident child's flag.
  EXPECT_TRUE(child->base_state.lineage_parent_dissolved);

  // Simulate the child OPERATOR'S node, which never saw the parent's
  // in-process severance (cross-process by design): the tombstone op is the
  // ONLY channel that carries the parent's decision there.
  child->base_state.lineage_parent_dissolved = false;

  // Tombstone wire: the shared writer produces the exact bytes
  // `lineage_sign_dissolution` signs over — canonical body + signature.
  uint8_t tombstone[CRABS_DISSOLUTION_WIRE_MAX];
  size_t tombstone_len = 0;
  ASSERT_EQ(lineage_dissolution_serialize(parent, "child-delegated", tombstone,
                                          sizeof(tombstone), &tombstone_len),
            CRABS_SUCCESS);
  ASSERT_EQ(tombstone_len,
            (size_t)(3 + strlen("child-delegated") + CRABS_SIG_SIZE));
  // Wire layout: u8 tag + u16le string length + child_id + 64B signature.
  EXPECT_EQ(tombstone[0], (uint8_t)LINEAGE_DISSOLVED);
  EXPECT_EQ(tombstone[1], (uint8_t)strlen("child-delegated"));
  EXPECT_EQ(tombstone[2], 0x00);
  EXPECT_EQ(memcmp(tombstone + 3, "child-delegated",
                   strlen("child-delegated")), 0);
  EXPECT_TRUE(crypto_ecdsa_verify(harness.parent_key->public_key, tombstone,
                                  tombstone_len - CRABS_SIG_SIZE,
                                  tombstone + tombstone_len - CRABS_SIG_SIZE));

  // Capture the delivered change event.
  static crabs_change_event_t captured_events[4];
  static char captured_targets[4][CRABS_MAX_USER_ID];
  static uint32_t captured_event_count;
  captured_event_count = 0;
  state_set_change_hook(&child->base_state,
                        [](state_t*, const crabs_change_event_t* event, void*) {
    if (event->kind != CRABS_CHANGE_LINEAGE) return;
    if (captured_event_count >= 4) return;
    captured_events[captured_event_count] = *event;
    strncpy(captured_targets[captured_event_count],
            event->target ? event->target : "", CRABS_MAX_USER_ID - 1);
    captured_events[captured_event_count].target =
        captured_targets[captured_event_count];
    captured_event_count += 1;
  }, nullptr);

  // Deliver as the CHILD ADMIN through the full pipeline.
  operation_t* delivery = make_signed_lineage_op(
      child, harness.parent_key, "child-admin",
      CRABS_LINEAGE_OP_RECEIVE_DISSOLUTION, tombstone, tombstone_len);
  ASSERT_NE(delivery, nullptr);
  EXPECT_EQ(state_machine_execute(&child->base_state, delivery),
            CRABS_SUCCESS);
  operation_destroy(delivery);
  EXPECT_TRUE(child->base_state.lineage_parent_dissolved);

  // Change event: kind LINEAGE, delivery op type, target = this machine,
  // attributed to the executing op.
  ASSERT_EQ(captured_event_count, 1u);
  EXPECT_EQ(captured_events[0].kind, CRABS_CHANGE_LINEAGE);
  EXPECT_STREQ(captured_events[0].type, "__receive_dissolution__");
  EXPECT_STREQ(captured_events[0].target, "child-delegated");
  EXPECT_STREQ(captured_events[0].preview, "dissolution received");
  EXPECT_EQ(captured_events[0].result, CRABS_SUCCESS);

  // Re-delivery is already-performed, not a re-severance.
  operation_t* redelivery = make_signed_lineage_op(
      child, harness.parent_key, "child-admin",
      CRABS_LINEAGE_OP_RECEIVE_DISSOLUTION, tombstone, tombstone_len);
  ASSERT_NE(redelivery, nullptr);
  EXPECT_EQ(state_machine_execute(&child->base_state, redelivery),
            CRABS_ERR_ALREADY_PERFORMED);
  operation_destroy(redelivery);

  // Persistence: the delivered dissolution survives the sealed round trip
  // (Task 1's v12 binding-tail byte consumed through the real save/load).
  serialized_buffer_t* snapshot =
      crabs_serialize_state_sealed(&child->base_state, seal_key);
  ASSERT_NE(snapshot, nullptr);
  bool authority_restored = false;
  bool msk_section_present = false;
  state_t* restored = crabs_deserialize_state_keys_reported(
      snapshot->data, snapshot->len, seal_key, &authority_restored,
      &msk_section_present);
  ASSERT_NE(restored, nullptr);
  EXPECT_TRUE(authority_restored);
  EXPECT_TRUE(msk_section_present);
  EXPECT_TRUE(restored->lineage_parent_dissolved);
  EXPECT_TRUE(restored->lineage_parent_bound);
  EXPECT_STREQ(restored->lineage_self_id, "child-delegated");

  serialized_buffer_destroy(snapshot);
  state_destroy(restored);
  crypto_ecdsa_keypair_destroy(child_key);
  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, TombstoneDeliveryRefusesForgedMisaddressedAndUnbound) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;

  // The receiver child stays LIVE through this test: a tombstone for a
  // non-dissolved child can never exist, so its refusals must come from
  // structural/authenticity failures, not the already-dissolved guard. A
  // second child provides a genuinely dissolved, honestly-signed tombstone
  // that is misaddressed to the receiver.
  machine_blueprint_t* receiver_blueprint =
      make_fresh_authority_blueprint("child-delegated", LINEAGE_DELEGATED_COPY);
  ASSERT_NE(receiver_blueprint, nullptr);
  attribute_machine_t* receiver = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, receiver_blueprint, &receiver),
            CRABS_SUCCESS);
  ASSERT_NE(receiver, nullptr);
  machine_blueprint_t* other_blueprint =
      make_fresh_authority_blueprint("child-other", LINEAGE_DELEGATED_COPY);
  ASSERT_NE(other_blueprint, nullptr);
  attribute_machine_t* other = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, other_blueprint, &other),
            CRABS_SUCCESS);
  ASSERT_NE(other, nullptr);
  EXPECT_EQ(parent->child_count, 2u);

  // Dissolve both through the direct handler (post-auth idiom).
  operation_t* dissolve_receiver = make_handler_shell_op(
      CRABS_LINEAGE_OP_DISSOLVE,
      (const uint8_t*)"child-delegated", strlen("child-delegated"));
  ASSERT_NE(dissolve_receiver, nullptr);
  EXPECT_EQ(lineage_op_dissolve(parent, dissolve_receiver), CRABS_SUCCESS);
  release_handler_shell_op(dissolve_receiver);
  operation_t* dissolve_other = make_handler_shell_op(
      CRABS_LINEAGE_OP_DISSOLVE, (const uint8_t*)"child-other",
      strlen("child-other"));
  ASSERT_NE(dissolve_other, nullptr);
  EXPECT_EQ(lineage_op_dissolve(parent, dissolve_other), CRABS_SUCCESS);
  release_handler_shell_op(dissolve_other);

  // Honestly-signed tombstones for both children.
  uint8_t self_tombstone[CRABS_DISSOLUTION_WIRE_MAX];
  size_t self_tombstone_len = 0;
  ASSERT_EQ(lineage_dissolution_serialize(parent, "child-delegated",
                                          self_tombstone,
                                          sizeof(self_tombstone),
                                          &self_tombstone_len), CRABS_SUCCESS);
  uint8_t other_tombstone[CRABS_DISSOLUTION_WIRE_MAX];
  size_t other_tombstone_len = 0;
  ASSERT_EQ(lineage_dissolution_serialize(parent, "child-other",
                                          other_tombstone,
                                          sizeof(other_tombstone),
                                          &other_tombstone_len), CRABS_SUCCESS);

  // Simulate the child operator's node again: the in-process severance is
  // not observable there, so the receiver accepts delivery candidates.
  receiver->base_state.lineage_parent_dissolved = false;

  // (1) Tampered signature: one flipped signature bit and the parent's
  // proof is gone — refused, flag stays false.
  uint8_t tampered[CRABS_DISSOLUTION_WIRE_MAX];
  memcpy(tampered, self_tombstone, self_tombstone_len);
  tampered[self_tombstone_len - 1] ^= 0x01;
  operation_t* forged = make_handler_shell_op(
      CRABS_LINEAGE_OP_RECEIVE_DISSOLUTION, tampered, self_tombstone_len);
  ASSERT_NE(forged, nullptr);
  EXPECT_EQ(lineage_op_receive_dissolution(&receiver->base_state, forged),
            CRABS_ERR_CRYPTOGRAPHIC_ERROR);
  release_handler_shell_op(forged);
  EXPECT_FALSE(receiver->base_state.lineage_parent_dissolved);

  // (2) Misaddressed tombstone: honestly signed by the parent, but it names
  // a different machine — refused before any state changes.
  operation_t* misaddressed = make_handler_shell_op(
      CRABS_LINEAGE_OP_RECEIVE_DISSOLUTION, other_tombstone,
      other_tombstone_len);
  ASSERT_NE(misaddressed, nullptr);
  EXPECT_EQ(lineage_op_receive_dissolution(&receiver->base_state,
                                           misaddressed),
            CRABS_ERR_INVALID_PARAM);
  release_handler_shell_op(misaddressed);
  EXPECT_FALSE(receiver->base_state.lineage_parent_dissolved);

  // (3) Unbound machine: never spawned, so it carries no parent public key
  // — nothing can be verified against, delivery refused outright.
  ecdsa_keypair_t* stray_key = crypto_ecdsa_generate();
  ASSERT_NE(stray_key, nullptr);
  attribute_machine_t* stray =
      attribute_machine_create("stray-root", stray_key->public_key);
  ASSERT_NE(stray, nullptr);
  stray->base_state.attr_machine = stray;
  lineage_install(&stray->base_state);
  operation_t* to_stray = make_handler_shell_op(
      CRABS_LINEAGE_OP_RECEIVE_DISSOLUTION, self_tombstone,
      self_tombstone_len);
  ASSERT_NE(to_stray, nullptr);
  EXPECT_EQ(lineage_op_receive_dissolution(&stray->base_state, to_stray),
            CRABS_ERR_UNAUTHORIZED);
  release_handler_shell_op(to_stray);
  EXPECT_FALSE(stray->base_state.lineage_parent_dissolved);

  // (4) Re-delivery pinned order: on an ALREADY-dissolved machine a
  // wrong-machine tombstone stops at the dissolved guard — the refusal is
  // the re-delivery (CRABS_ERR_ALREADY_PERFORMED), not the misaddressing
  // (CRABS_ERR_INVALID_PARAM). The documented refusal ladder checks
  // idempotency BEFORE the tombstone's child_id, so a re-delivery never
  // spends parse work on tombstones it will refuse anyway.
  receiver->base_state.lineage_parent_dissolved = true;
  operation_t* redelivered_wrong = make_handler_shell_op(
      CRABS_LINEAGE_OP_RECEIVE_DISSOLUTION, other_tombstone,
      other_tombstone_len);
  ASSERT_NE(redelivered_wrong, nullptr);
  EXPECT_EQ(lineage_op_receive_dissolution(&receiver->base_state,
                                           redelivered_wrong),
            CRABS_ERR_ALREADY_PERFORMED);
  release_handler_shell_op(redelivered_wrong);
  EXPECT_TRUE(receiver->base_state.lineage_parent_dissolved);

  crypto_ecdsa_keypair_destroy(stray_key);
  attribute_machine_destroy(stray);
  attribute_machine_destroy(receiver);
  attribute_machine_destroy(other);
  machine_blueprint_destroy(receiver_blueprint);
  machine_blueprint_destroy(other_blueprint);
  spawn_parent_destroy(&harness);
}

// ============================================================
// Revocation timing: the custody payoff
// ============================================================

// Controllable machine clock (state_set_time_source + state_get_time_ms
// read through it) shared by every state in a test so issuance and expiry
// verification run on the SAME timeline.
static uint64_t g_test_clock_ms;
static crabs_physical_time_t test_clock_get_time(void* context) {
  (void)context;
  crabs_physical_time_t physical;
  physical.seconds = g_test_clock_ms / 1000;
  physical.nanos = (g_test_clock_ms % 1000) * 1000000ULL;
  physical.valid = true;
  return physical;
}
static bool test_clock_is_available(void* context) {
  (void)context;
  return true;
}
static crabs_time_source_ops_t g_test_clock_ops = {
  test_clock_get_time, test_clock_is_available, NULL
};

// A delegated blueprint whose child op "render" resolves ONLY through a
// parent endorsement: `@parent/role:writer`. The endorsement is AND-composed
// with the (empty) local remainder — this is the strongest v1 coupling.
static machine_blueprint_t* make_endorsed_delegated_blueprint(
    const char* child_id) {
  machine_blueprint_t* blueprint = machine_blueprint_create();
  EXPECT_NE(blueprint, nullptr);
  strncpy(blueprint->child_id, child_id, sizeof(blueprint->child_id) - 1);
  blueprint->trust_mode = LINEAGE_DELEGATED_COPY;
  strncpy(blueprint->bootstrap_admin, "child-admin",
          sizeof(blueprint->bootstrap_admin) - 1);
  blueprint->attestation_ttl_ms = 60000;
  EXPECT_EQ(blueprint_add_item(blueprint, "canvas", DATA_TYPE_REGISTER,
                               CRDT_LWW_REG), CRABS_SUCCESS);
  EXPECT_EQ(blueprint_add_policy(blueprint, "render",
                                 "@parent/role:writer"), CRABS_SUCCESS);
  dedup_spec_t dedup;
  memset(&dedup, 0, sizeof(dedup));
  dedup.type = DEDUP_NONE;
  EXPECT_EQ(blueprint_add_op_type_def(blueprint, "render", &dedup),
            CRABS_SUCCESS);
  EXPECT_EQ(lineage_blueprint_validate(blueprint), CRABS_SUCCESS);
  return blueprint;
}

TEST(TestLineage, DelegatedChildLosesEndorsementAfterAttestationExpiry) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  g_test_clock_ms = 1700000000000ULL;  // fixed test epoch T0
  state_set_time_source(parent, &g_test_clock_ops);

  machine_blueprint_t* blueprint =
      make_endorsed_delegated_blueprint("child-delegated");
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  state_set_time_source(&child->base_state, &g_test_clock_ops);
  register_child_render_handler(child);

  // The manifest ttl flows into the wrapper's expiry: expires = T0 + 60000.
  attestation_t attestation;
  ASSERT_EQ(crabs_issue_attestation(parent, &attestation, "child-delegated",
                                    "child-admin", "role:writer",
                                    g_test_clock_ms), CRABS_SUCCESS);
  EXPECT_EQ(attestation.expires_at, g_test_clock_ms + 60000u);

  // Inside the window: the endorsement resolves and the op authorizes. The
  // child-admin's registered key is the parent's node public key, so the
  // parent keypair signs; the op carries the attestation AFTER signing (the
  // signing image excludes attestations — Task 7's established idiom).
  operation_t* op = operation_create("render");
  ASSERT_NE(op, nullptr);
  strncpy(op->signer_id, "child-admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(child, harness.parent_key, op);
  attach_attestation(op, &attestation);
  EXPECT_EQ(state_machine_execute(&child->base_state, op), CRABS_SUCCESS);

  // Advance the machine clock one millisecond past expiry: SAME op,
  // SAME signature, SAME attestation — the endorsement no longer resolves.
  g_test_clock_ms += 60001;
  EXPECT_EQ(state_machine_execute(&child->base_state, op),
            CRABS_ERR_UNAUTHORIZED);

  // Re-issue on the advanced clock (a fresh, still-live window) — the
  // endorsement authorizes again.
  attestation_t renewed;
  ASSERT_EQ(crabs_issue_attestation(parent, &renewed, "child-delegated",
                                    "child-admin", "role:writer",
                                    g_test_clock_ms), CRABS_SUCCESS);
  operation_t* op2 = operation_create("render");
  ASSERT_NE(op2, nullptr);
  strncpy(op2->signer_id, "child-admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(child, harness.parent_key, op2);
  attach_attestation(op2, &renewed);
  EXPECT_EQ(state_machine_execute(&child->base_state, op2), CRABS_SUCCESS);

  operation_destroy(op);
  operation_destroy(op2);
  machine_blueprint_destroy(blueprint);
  attribute_machine_destroy(child);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, SharedRootChildStopsInstantlyOnParentRevoke) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;  // shared registry authority

  machine_blueprint_t* blueprint = make_valid_blueprint();  // custody:child-red
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  register_child_increment_handler(child);

  // No custodial attribute yet — denied.
  operation_t* denied = make_signed_increment_op(harness.am,
                                                 harness.alice_key, "alice");
  ASSERT_NE(denied, nullptr);
  EXPECT_EQ(state_machine_execute(&child->base_state, denied),
            CRABS_ERR_UNAUTHORIZED);

  // The parent grants (and then REVOKES) custody — no attestation is
  // involved anywhere: the shared registry is the single source of truth.
  ASSERT_EQ(attribute_machine_grant_role(harness.am, "alice", "custody",
                                         "child-red", "parent-root"),
            CRABS_SUCCESS);
  operation_t* granted = make_signed_increment_op(harness.am,
                                                  harness.alice_key, "alice");
  ASSERT_NE(granted, nullptr);
  EXPECT_EQ(state_machine_execute(&child->base_state, granted),
            CRABS_SUCCESS);

  ASSERT_EQ(attribute_machine_revoke_role(harness.am, "alice", "custody",
                                          "parent-root"), CRABS_SUCCESS);
  // SAME op, signed seconds earlier: denied IMMEDIATELY on revoke.
  EXPECT_EQ(state_machine_execute(&child->base_state, granted),
            CRABS_ERR_UNAUTHORIZED);

  operation_destroy(denied);
  operation_destroy(granted);
  machine_blueprint_destroy(blueprint);
  attribute_machine_destroy(child);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, DissolveVoidsEndorsementsImmediately) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  g_test_clock_ms = 1700000000000ULL;
  state_set_time_source(parent, &g_test_clock_ops);

  machine_blueprint_t* blueprint =
      make_endorsed_delegated_blueprint("child-delegated");
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  state_set_time_source(&child->base_state, &g_test_clock_ops);
  register_child_render_handler(child);

  attestation_t attestation;
  ASSERT_EQ(crabs_issue_attestation(parent, &attestation, "child-delegated",
                                    "child-admin", "role:writer",
                                    g_test_clock_ms), CRABS_SUCCESS);
  operation_t* op = operation_create("render");
  ASSERT_NE(op, nullptr);
  strncpy(op->signer_id, "child-admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(child, harness.parent_key, op);
  attach_attestation(op, &attestation);
  EXPECT_EQ(state_machine_execute(&child->base_state, op), CRABS_SUCCESS);

  // Dissolve THROUGH the handler: the child (resident in-process) is
  // severed, and the endorsement gate fails closed from that moment.
  operation_t* dissolve_op = operation_create(CRABS_LINEAGE_OP_DISSOLVE);
  ASSERT_NE(dissolve_op, nullptr);
  dissolve_op->payload = (uint8_t*)"child-delegated";
  dissolve_op->payload_size = (uint32_t)strlen("child-delegated");
  EXPECT_EQ(lineage_op_dissolve(parent, dissolve_op), CRABS_SUCCESS);
  EXPECT_TRUE(child->base_state.lineage_parent_dissolved);
  dissolve_op->payload = NULL;
  operation_destroy(dissolve_op);

  // A VALID, unexpired attestation (issued BEFORE the dissolve) still
  // cannot cross the severed lineage — dissolution voids endorsements
  // outright. New attestations cannot even be minted: the wrapper refuses a
  // non-ACTIVE lineage.
  attestation_t renewed;
  EXPECT_EQ(crabs_issue_attestation(parent, &renewed, "child-delegated",
                                    "child-admin", "role:writer",
                                    g_test_clock_ms),
            CRABS_ERR_UNAUTHORIZED);
  operation_t* op2 = operation_create("render");
  ASSERT_NE(op2, nullptr);
  strncpy(op2->signer_id, "child-admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(child, harness.parent_key, op2);
  attach_attestation(op2, &attestation);
  EXPECT_EQ(state_machine_execute(&child->base_state, op2),
            CRABS_ERR_UNAUTHORIZED);

  operation_destroy(op);
  operation_destroy(op2);
  machine_blueprint_destroy(blueprint);
  attribute_machine_destroy(child);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, RevokedChildCannotReceiveNewAttestations) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;

  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);

  // ACTIVE: the wrapper issues with the manifest ttl.
  g_test_clock_ms = 1700000000000ULL;
  attestation_t attestation;
  ASSERT_EQ(crabs_issue_attestation(parent, &attestation, "child-red",
                                    "alice", "custody:child-red",
                                    g_test_clock_ms), CRABS_SUCCESS);
  EXPECT_STREQ(attestation.parent_id, "parent-root");
  EXPECT_EQ(attestation.expires_at, g_test_clock_ms + 60000u);

  // Unknown child.
  EXPECT_EQ(crabs_issue_attestation(parent, &attestation, "child-ghost",
                                    "alice", "custody:child-red",
                                    g_test_clock_ms),
            CRABS_ERR_RESOURCE_NOT_FOUND);

  // After the parent revokes the child's attestation authority, new
  // attestations are refused without dissolving the lineage.
  operation_t* revoke_op = operation_create(CRABS_LINEAGE_OP_REVOKE_ATTESTATION);
  ASSERT_NE(revoke_op, nullptr);
  revoke_op->payload = (uint8_t*)"child-red";
  revoke_op->payload_size = (uint32_t)strlen("child-red");
  EXPECT_EQ(lineage_op_revoke_attestation(parent, revoke_op), CRABS_SUCCESS);
  EXPECT_EQ(parent->children[0].status, LINEAGE_ATTESTATION_REVOKED);
  revoke_op->payload = NULL;
  operation_destroy(revoke_op);

  EXPECT_EQ(crabs_issue_attestation(parent, &attestation, "child-red",
                                    "alice", "custody:child-red",
                                    g_test_clock_ms),
            CRABS_ERR_UNAUTHORIZED);

  // The issued-before-revoke attestation still verifies inside its window —
  // revocation stops ISSUING, it does not forge-void what was signed.
  EXPECT_TRUE(attestation_verify(parent->node_public_key, "child-red",
                                 &attestation, g_test_clock_ms));

  machine_blueprint_destroy(blueprint);
  attribute_machine_destroy(child);
  spawn_parent_destroy(&harness);
}

// ============================================================
// Manifest entry accessor
// ============================================================

TEST(TestLineage, FindManifestEntryResolvesById) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);

  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  ASSERT_NE(child, nullptr);

  // Hit: the entry resolves by id and carries the mode the blueprint named.
  child_manifest_entry_t* entry =
      lineage_find_manifest_entry(parent, "child-red");
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->mode, blueprint->trust_mode);
  EXPECT_STREQ(entry->child_id, "child-red");

  // Miss: an id absent from the manifest yields NULL, not garbage.
  EXPECT_EQ(lineage_find_manifest_entry(parent, "child-ghost"), nullptr);

  // Null-safe: a NULL state (and NULL id) returns NULL, no crash.
  EXPECT_EQ(lineage_find_manifest_entry(nullptr, "child-red"), nullptr);
  EXPECT_EQ(lineage_find_manifest_entry(parent, nullptr), nullptr);

  attribute_machine_destroy(child);
  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}

// ============================================================
// Enum name helpers (single source for CLI / wasm / devtools)
// ============================================================

TEST(TestLineage, ModeNameCoversEveryEnumValue) {
  EXPECT_STREQ(lineage_mode_name(LINEAGE_SHARED_ROOT), "shared_root");
  EXPECT_STREQ(lineage_mode_name(LINEAGE_DELEGATED_COPY), "delegated_copy");
  EXPECT_STREQ(lineage_mode_name(LINEAGE_SOVEREIGN), "sovereign");
  EXPECT_STREQ(lineage_mode_name((lineage_trust_mode_e)0x42), "unknown");
}

TEST(TestLineage, StatusNameCoversEveryEnumValue) {
  EXPECT_STREQ(lineage_status_name(LINEAGE_ACTIVE), "active");
  EXPECT_STREQ(lineage_status_name(LINEAGE_DISSOLVED), "dissolved");
  EXPECT_STREQ(lineage_status_name(LINEAGE_WITHDRAWN), "withdrawn");
  EXPECT_STREQ(lineage_status_name(LINEAGE_ATTESTATION_REVOKED),
               "attestation_revoked");
  EXPECT_STREQ(lineage_status_name((lineage_status_e)0x2A), "unknown");
}

// ============================================================
// Parent key chain (A10-M6): rotate / accept / verify
// ============================================================
//
// The transition record's string16 names the PARENT machine (parent_id). The
// rotate API emits the rotating machine's lineage_self_id when set, else its
// v1 root identity (config.bootstrap_admin — the same string attestations
// carry and children persist as lineage_parent_id). Acceptance compares the
// field against the receiving machine's lineage_parent_id, so ONE record
// serves every child of that parent (replay across children is the feature;
// per-child idempotency comes from the version-forward-only + pk-already-
// known gates). The API-level fixtures below wire the rotating parent to
// "parent-red" and bind children to that id (spawn stamps the real chain in
// the v13 wire task).

typedef struct {
  state_t*         parent_state;   // rotating machine (signer), node key k1
  state_t*         child_state;    // bound child, chain [(1, k1.public)]
  ecdsa_keypair_t* k1;
  ecdsa_keypair_t* k2;
  ecdsa_keypair_t* foreign;
} keychain_harness_t;

// Build a bound child state with chain[0] = {CRABS_LINEAGE_KEY_VERSION_START,
// spawn_pin_public_key} by hand (spawn will stamp this at spawn time in the
// wire-format task; the API-level tests only need the chain shape). The
// child's parent_id ("parent-red") is what the rotate record names — the
// accept gate compares the record's string16 against lineage_parent_id.
static void keychain_bind_child(state_t* child_state,
                                const uint8_t spawn_pin_public_key[33]) {
  memcpy(child_state->lineage_parent_public_key, spawn_pin_public_key, 33);
  strncpy(child_state->lineage_parent_id, "parent-red",
          sizeof(child_state->lineage_parent_id) - 1);
  strncpy(child_state->lineage_self_id, "child-red",
          sizeof(child_state->lineage_self_id) - 1);
  child_state->lineage_parent_bound = true;
  child_state->lineage_key_chain = (lineage_key_chain_entry_t*)calloc(
      1, sizeof(lineage_key_chain_entry_t));
  ASSERT_NE(child_state->lineage_key_chain, nullptr);
  child_state->lineage_key_chain[0].key_version =
      CRABS_LINEAGE_KEY_VERSION_START;
  memcpy(child_state->lineage_key_chain[0].public_key, spawn_pin_public_key,
         33);
  child_state->lineage_key_chain_count = 1;
}

static void keychain_harness_setup(keychain_harness_t* harness) {
  memset(harness, 0, sizeof(*harness));
  harness->k1 = crypto_ecdsa_generate();
  harness->k2 = crypto_ecdsa_generate();
  harness->foreign = crypto_ecdsa_generate();
  ASSERT_NE(harness->k1, nullptr);
  ASSERT_NE(harness->k2, nullptr);
  ASSERT_NE(harness->foreign, nullptr);

  harness->parent_state = state_create();
  ASSERT_NE(harness->parent_state, nullptr);
  ASSERT_EQ(state_set_node_key(harness->parent_state,
                               harness->k1->private_key,
                               harness->k1->public_key), CRABS_SUCCESS);
  // A root parent has no lineage_self_id, so the rotate record falls back to
  // its bootstrap_admin (the same id children persist as lineage_parent_id).
  strncpy(harness->parent_state->config.bootstrap_admin, "parent-red",
          sizeof(harness->parent_state->config.bootstrap_admin) - 1);

  harness->child_state = state_create();
  ASSERT_NE(harness->child_state, nullptr);
  keychain_bind_child(harness->child_state, harness->k1->public_key);
}

static void keychain_harness_destroy(keychain_harness_t* harness) {
  state_destroy(harness->parent_state);
  state_destroy(harness->child_state);
  crypto_ecdsa_keypair_destroy(harness->k1);
  crypto_ecdsa_keypair_destroy(harness->k2);
  crypto_ecdsa_keypair_destroy(harness->foreign);
}

// Hand-craft a key transition record (wire image: canonical body + a
// signature over the body made with signing_private_key). Lets the rejection
// tests produce structurally valid-but-wrong records the rotate API could
// never emit (bad version continuity, wrong parent_id, forged signer).
// created_at is written as 0 — the accept gates never read it.
static size_t keychain_make_record(uint64_t new_key_version,
                                   const uint8_t new_public_key[33],
                                   const uint8_t old_public_key[33],
                                   const char* parent_id,
                                   const uint8_t signing_private_key[32],
                                   uint8_t* out, size_t out_capacity) {
  size_t offset = 0;
  out[offset++] = 'P';
  out[offset++] = 'K';
  out[offset++] = 'T';
  for (int byte_index = 0; byte_index < 8; byte_index++) {
    out[offset + byte_index] = (uint8_t)(new_key_version >> (byte_index * 8));
  }
  offset += 8;
  memcpy(out + offset, new_public_key, 33);
  offset += 33;
  memcpy(out + offset, old_public_key, 33);
  offset += 33;
  uint16_t id_len = (uint16_t)strlen(parent_id);
  out[offset++] = (uint8_t)(id_len & 0xFF);
  out[offset++] = (uint8_t)(id_len >> 8);
  memcpy(out + offset, parent_id, id_len);
  offset += id_len;
  for (int byte_index = 0; byte_index < 8; byte_index++) {
    out[offset + byte_index] = 0;  // created_at = 0 (informational)
  }
  offset += 8;
  EXPECT_LE(offset + CRABS_SIG_SIZE, out_capacity);
  EXPECT_EQ(crypto_ecdsa_sign(signing_private_key, out, offset, out + offset),
            CRABS_SUCCESS);
  return offset + CRABS_SIG_SIZE;
}

TEST(TestLineage, KeyChainStateFieldsStartEmpty) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  EXPECT_EQ(state->lineage_key_chain, nullptr);
  EXPECT_EQ(state->lineage_key_chain_count, 0u);
  EXPECT_EQ(state->lineage_key_version, 0u);
  EXPECT_EQ(state->lineage_last_key_transition, nullptr);
  EXPECT_EQ(state->lineage_last_key_transition_len, 0u);
  state_destroy(state);
}

TEST(TestLineage, KeyChainStateDestroyReleasesChainFields) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  state->lineage_key_chain = (lineage_key_chain_entry_t*)calloc(
      2, sizeof(lineage_key_chain_entry_t));
  state->lineage_key_chain_count = 2;
  state->lineage_last_key_transition =
      (uint8_t*)calloc(1, LINEAGE_KEY_TRANSITION_WIRE_MAX);
  state->lineage_last_key_transition_len = 12;
  state_destroy(state);  // no leak / no crash
}

TEST(TestLineage, KeyChainRotateAppendsAndStashes) {
  keychain_harness_t harness;
  keychain_harness_setup(&harness);

  uint8_t* record = nullptr;
  size_t record_len = 0;
  ASSERT_EQ(lineage_key_rotate(harness.parent_state,
                               harness.k2->private_key, harness.k2->public_key,
                               1700000000000ULL, &record, &record_len),
            CRABS_SUCCESS);
  ASSERT_NE(record, nullptr);
  ASSERT_GT(record_len, (size_t)CRABS_SIG_SIZE);
  EXPECT_LE(record_len, (size_t)LINEAGE_KEY_TRANSITION_WIRE_MAX);

  // Parent-side state: the version bumped past the (implicit) spawn
  // generation and the signed record is stashed for re-emission.
  EXPECT_EQ(harness.parent_state->lineage_key_version,
            (uint64_t)CRABS_LINEAGE_KEY_VERSION_START + 1);
  ASSERT_EQ(harness.parent_state->lineage_last_key_transition_len,
            (uint32_t)record_len);
  ASSERT_NE(harness.parent_state->lineage_last_key_transition, nullptr);
  EXPECT_EQ(memcmp(harness.parent_state->lineage_last_key_transition, record,
                   record_len), 0);

  // The recorded old_pk is the pre-rotation node key, and the record's own
  // signature verifies under it over the record's body prefix.
  const size_t body_len = record_len - CRABS_SIG_SIZE;
  const uint8_t* old_pk = record + 3 + 8 + 33;
  EXPECT_EQ(memcmp(old_pk, harness.k1->public_key, 33), 0);
  EXPECT_TRUE(crypto_ecdsa_verify(old_pk, record, body_len,
                                  record + body_len));

  // Child accepts: the chain advances forward-only to versions {1, 2} and
  // entry [0] stays the spawn pin.
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                record_len),
            CRABS_SUCCESS);
  ASSERT_EQ(harness.child_state->lineage_key_chain_count, 2u);
  EXPECT_EQ(harness.child_state->lineage_key_chain[0].key_version,
            (uint64_t)CRABS_LINEAGE_KEY_VERSION_START);
  EXPECT_EQ(memcmp(harness.child_state->lineage_key_chain[0].public_key,
                   harness.k1->public_key, 33), 0);
  EXPECT_EQ(harness.child_state->lineage_key_chain[1].key_version, 2u);
  EXPECT_EQ(memcmp(harness.child_state->lineage_key_chain[1].public_key,
                   harness.k2->public_key, 33), 0);

  free(record);
  keychain_harness_destroy(&harness);
}

// Replay-across-children: ONE record minted by the parent is honored by EVERY
// child bound to that parent_id. Per-child idempotency then refuses a second
// delivery of the SAME record (version-forward-only gate).
TEST(TestLineage, KeyChainRecordServesAllChildrenOfOneParent) {
  keychain_harness_t harness;
  keychain_harness_setup(&harness);

  // A second child bound to the SAME parent (same lineage_parent_id, same
  // spawn pin) — distinct lineage_self_id is irrelevant to the accept gate.
  state_t* second_child = state_create();
  ASSERT_NE(second_child, nullptr);
  keychain_bind_child(second_child, harness.k1->public_key);
  strncpy(second_child->lineage_self_id, "child-blue",
          sizeof(second_child->lineage_self_id) - 1);

  // The parent mints ONE record.
  uint8_t* record = nullptr;
  size_t record_len = 0;
  ASSERT_EQ(lineage_key_rotate(harness.parent_state,
                               harness.k2->private_key, harness.k2->public_key,
                               1700000000000ULL, &record, &record_len),
            CRABS_SUCCESS);

  // created_at is bound into the body (informational; never validated).
  const size_t body_len = record_len - CRABS_SIG_SIZE;
  uint64_t recorded_at = 0;
  for (int byte_index = 0; byte_index < 8; byte_index++) {
    recorded_at |= ((uint64_t)record[body_len - 8 + byte_index])
                   << (byte_index * 8);
  }
  EXPECT_EQ(recorded_at, 1700000000000ULL);

  // BOTH children accept the SAME record — this is the broadcast feature.
  ASSERT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                record_len),
            CRABS_SUCCESS);
  ASSERT_EQ(lineage_child_accept_key_transition(second_child, record,
                                                record_len),
            CRABS_SUCCESS);
  EXPECT_EQ(harness.child_state->lineage_key_chain_count, 2u);
  EXPECT_EQ(second_child->lineage_key_chain_count, 2u);

  // Re-acceptance on EITHER child is refused (per-child idempotency): the
  // version is no longer max+1 and the public key is already in the chain.
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                record_len),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(lineage_child_accept_key_transition(second_child, record,
                                                record_len),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(harness.child_state->lineage_key_chain_count, 2u);
  EXPECT_EQ(second_child->lineage_key_chain_count, 2u);

  // A machine bound to a DIFFERENT parent refuses the record outright: its
  // lineage_parent_id fails the strcmp gate before any verification.
  state_t* foreign_child = state_create();
  ASSERT_NE(foreign_child, nullptr);
  memcpy(foreign_child->lineage_parent_public_key, harness.k1->public_key, 33);
  strncpy(foreign_child->lineage_parent_id, "someone-else",
          sizeof(foreign_child->lineage_parent_id) - 1);
  strncpy(foreign_child->lineage_self_id, "child-green",
          sizeof(foreign_child->lineage_self_id) - 1);
  foreign_child->lineage_parent_bound = true;
  foreign_child->lineage_key_chain = (lineage_key_chain_entry_t*)calloc(
      1, sizeof(lineage_key_chain_entry_t));
  ASSERT_NE(foreign_child->lineage_key_chain, nullptr);
  foreign_child->lineage_key_chain[0].key_version =
      CRABS_LINEAGE_KEY_VERSION_START;
  memcpy(foreign_child->lineage_key_chain[0].public_key,
         harness.k1->public_key, 33);
  foreign_child->lineage_key_chain_count = 1;
  EXPECT_EQ(lineage_child_accept_key_transition(foreign_child, record,
                                                record_len),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(foreign_child->lineage_key_chain_count, 1u);

  free(record);
  state_destroy(foreign_child);
  state_destroy(second_child);
  keychain_harness_destroy(&harness);
}

// A spawned parent names its OWN lineage_self_id (NOT a child's, NOT its
// bootstrap_admin) in the transition record. Only children bound to that id
// accept; children who still carry the pre-spawn bootstrap id refuse.
TEST(TestLineage, KeyChainRotatePrefersLineageSelfIdOverBootstrap) {
  keychain_harness_t harness;
  keychain_harness_setup(&harness);

  // Mark the rotating machine as itself a spawned child upstream.
  strncpy(harness.parent_state->lineage_self_id, "self-red",
          sizeof(harness.parent_state->lineage_self_id) - 1);

  uint8_t* record = nullptr;
  size_t record_len = 0;
  ASSERT_EQ(lineage_key_rotate(harness.parent_state,
                               harness.k2->private_key, harness.k2->public_key,
                               0, &record, &record_len),
            CRABS_SUCCESS);

  // A child bound to the SELF id accepts the record.
  state_t* bound_to_self = state_create();
  ASSERT_NE(bound_to_self, nullptr);
  memcpy(bound_to_self->lineage_parent_public_key, harness.k1->public_key, 33);
  strncpy(bound_to_self->lineage_parent_id, "self-red",
          sizeof(bound_to_self->lineage_parent_id) - 1);
  bound_to_self->lineage_parent_bound = true;
  bound_to_self->lineage_key_chain = (lineage_key_chain_entry_t*)calloc(
      1, sizeof(lineage_key_chain_entry_t));
  ASSERT_NE(bound_to_self->lineage_key_chain, nullptr);
  bound_to_self->lineage_key_chain[0].key_version =
      CRABS_LINEAGE_KEY_VERSION_START;
  memcpy(bound_to_self->lineage_key_chain[0].public_key,
         harness.k1->public_key, 33);
  bound_to_self->lineage_key_chain_count = 1;
  EXPECT_EQ(lineage_child_accept_key_transition(bound_to_self, record,
                                                record_len),
            CRABS_SUCCESS);

  // The harness's default child (still bound to the bootstrap admin id
  // "parent-red") refuses — its lineage_parent_id no longer matches.
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                record_len),
            CRABS_ERR_INVALID_PARAM);

  free(record);
  state_destroy(bound_to_self);
  keychain_harness_destroy(&harness);
}

TEST(TestLineage, KeyChainRotateRefusesBadInputs) {
  keychain_harness_t harness;
  keychain_harness_setup(&harness);

  uint8_t* record = nullptr;
  size_t record_len = 0;
  EXPECT_EQ(lineage_key_rotate(nullptr, harness.k2->private_key,
                               harness.k2->public_key, 0, &record, &record_len),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(lineage_key_rotate(harness.parent_state, nullptr,
                               harness.k2->public_key, 0, &record, &record_len),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(lineage_key_rotate(harness.parent_state, harness.k2->private_key,
                               nullptr, 0, &record, &record_len),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(lineage_key_rotate(harness.parent_state, harness.k2->private_key,
                               harness.k2->public_key, 0, nullptr,
                               &record_len),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(lineage_key_rotate(harness.parent_state, harness.k2->private_key,
                               harness.k2->public_key, 0, &record, nullptr),
            CRABS_ERR_INVALID_PARAM);

  // A keyless machine cannot sign a transition.
  state_t* keyless = state_create();
  ASSERT_NE(keyless, nullptr);
  EXPECT_EQ(lineage_key_rotate(keyless, harness.k2->private_key,
                               harness.k2->public_key, 0, &record, &record_len),
            CRABS_ERR_CRYPTOGRAPHIC_ERROR);
  state_destroy(keyless);

  // private/public mismatch: recording a key the caller cannot wield would
  // brick later transitions, so rotate fails before any mutation.
  EXPECT_EQ(lineage_key_rotate(harness.parent_state, harness.k1->private_key,
                               harness.k2->public_key, 0, &record, &record_len),
            CRABS_ERR_INVALID_PARAM);
  // Rotating to the CURRENT key is not a rotation (forward-only).
  EXPECT_EQ(lineage_key_rotate(harness.parent_state, harness.k1->private_key,
                               harness.k1->public_key, 0, &record, &record_len),
            CRABS_ERR_INVALID_PARAM);

  // Every refusal above left the parent untouched.
  EXPECT_EQ(harness.parent_state->lineage_key_version, 0u);
  EXPECT_EQ(harness.parent_state->lineage_last_key_transition, nullptr);
  EXPECT_EQ(record, nullptr);
  keychain_harness_destroy(&harness);
}

// A11-5: rotating twice without installing the first rotation's key wedges
// every child's chain — the second record's old_pk is the still-installed
// ORIGINAL key while children who accepted the first record sit at tip=v2,
// and the tip-gate plus version-gap rejections are permanent in-band. rotate
// must REFUSE to mint a new transition while the previous rotation's key was
// never installed via state_set_node_key.
TEST(TestLineage, KeyChainRotateRefusesUninstalledPriorRotation) {
  keychain_harness_t harness;
  keychain_harness_setup(&harness);

  ecdsa_keypair_t* k3 = crypto_ecdsa_generate();
  ASSERT_NE(k3, nullptr);

  // Positive control B: a fresh parent's FIRST rotation is always allowed —
  // no prior transition exists yet, so no wedge is possible.
  state_t* fresh_parent = state_create();
  ASSERT_NE(fresh_parent, nullptr);
  ecdsa_keypair_t* fresh_key = crypto_ecdsa_generate();
  ASSERT_NE(fresh_key, nullptr);
  ASSERT_EQ(state_set_node_key(fresh_parent, fresh_key->private_key,
                               fresh_key->public_key),
            CRABS_SUCCESS);
  uint8_t* first_record = nullptr;
  size_t first_len = 0;
  EXPECT_EQ(lineage_key_rotate(fresh_parent, harness.k2->private_key,
                               harness.k2->public_key, 0, &first_record,
                               &first_len),
            CRABS_SUCCESS);
  free(first_record);
  crypto_ecdsa_keypair_destroy(fresh_key);
  state_destroy(fresh_parent);

  // Scenario 1: rotate K1 -> K2 succeeds, but the caller never installs K2.
  uint8_t* record = nullptr;
  size_t record_len = 0;
  ASSERT_EQ(lineage_key_rotate(harness.parent_state,
                               harness.k2->private_key, harness.k2->public_key,
                               1700000000000ULL, &record, &record_len),
            CRABS_SUCCESS);
  free(record);

  // A second rotation while K2 is uninstalled must be REFUSED — no version
  // bump, no stash swap, no output record.
  const uint64_t version_before = harness.parent_state->lineage_key_version;
  const uint8_t* stash_before =
      harness.parent_state->lineage_last_key_transition;
  const uint32_t stash_len_before =
      harness.parent_state->lineage_last_key_transition_len;
  record = nullptr;
  record_len = 0;
  EXPECT_EQ(lineage_key_rotate(harness.parent_state, k3->private_key,
                               k3->public_key, 1700000000001ULL, &record,
                               &record_len),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(harness.parent_state->lineage_key_version, version_before);
  EXPECT_EQ(harness.parent_state->lineage_last_key_transition, stash_before);
  EXPECT_EQ(harness.parent_state->lineage_last_key_transition_len,
            stash_len_before);
  EXPECT_EQ(record, nullptr);
  EXPECT_EQ(record_len, 0u);

  // Positive control A: installing the rotated key (the pairing the header
  // documents) un-gates the next rotation — the normal flow is unaffected.
  ASSERT_EQ(state_set_node_key(harness.parent_state, harness.k2->private_key,
                               harness.k2->public_key),
            CRABS_SUCCESS);
  EXPECT_EQ(lineage_key_rotate(harness.parent_state, k3->private_key,
                               k3->public_key, 1700000000002ULL, &record,
                               &record_len),
            CRABS_SUCCESS);
  EXPECT_EQ(harness.parent_state->lineage_key_version, version_before + 1);
  free(record);

  crypto_ecdsa_keypair_destroy(k3);
  keychain_harness_destroy(&harness);
}

TEST(TestLineage, KeyChainRollbackAndGapRejected) {
  keychain_harness_t harness;
  keychain_harness_setup(&harness);

  ecdsa_keypair_t* k3 = crypto_ecdsa_generate();
  ASSERT_NE(k3, nullptr);
  uint8_t record[LINEAGE_KEY_TRANSITION_WIRE_MAX];

  // Replay: the spawn pin's own generation is already the chain maximum.
  size_t replay_len = keychain_make_record(
      CRABS_LINEAGE_KEY_VERSION_START, k3->public_key,
      harness.k1->public_key, "parent-red", harness.k1->private_key,
      record, sizeof(record));
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                replay_len),
            CRABS_ERR_INVALID_PARAM);

  // Gap: version 3 when the chain maximum is 1 (versions must advance by
  // exactly one).
  size_t gap_len = keychain_make_record(3, k3->public_key,
                                        harness.k1->public_key, "parent-red",
                                        harness.k1->private_key,
                                        record, sizeof(record));
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                gap_len),
            CRABS_ERR_INVALID_PARAM);

  // Key already known: a fresh version naming an existing chain key.
  size_t known_len = keychain_make_record(2, harness.k1->public_key,
                                          harness.k1->public_key, "parent-red",
                                          harness.k1->private_key,
                                          record, sizeof(record));
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                known_len),
            CRABS_ERR_INVALID_PARAM);

  // Wrong parent: a record minted by parent P but DELIVERED to a machine
  // whose lineage_parent_id is "someone-else" — refused as targeting a
  // different parent identity.
  size_t wrong_parent_len = keychain_make_record(
      2, harness.k2->public_key, harness.k1->public_key, "someone-else",
      harness.k1->private_key, record, sizeof(record));
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                wrong_parent_len),
            CRABS_ERR_INVALID_PARAM);

  // Wrong tag.
  size_t bad_tag_len = keychain_make_record(
      2, harness.k2->public_key, harness.k1->public_key, "parent-red",
      harness.k1->private_key, record, sizeof(record));
  record[0] = 'X';
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                bad_tag_len),
            CRABS_ERR_INVALID_PARAM);
  record[0] = 'P';

  // Continuity proof: old_pk is not the chain tip (it matches no chain entry
  // at all), so it fails the tip gate before any signature work.
  size_t forged_len = keychain_make_record(
      2, harness.k2->public_key, harness.foreign->public_key, "parent-red",
      harness.foreign->private_key, record, sizeof(record));
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                forged_len),
            CRABS_ERR_CRYPTOGRAPHIC_ERROR);

  // A genuine record signed by the chain key is accepted — establishing that
  // the refusals above were about the record, not the machinery.
  size_t good_len = keychain_make_record(
      2, harness.k2->public_key, harness.k1->public_key, "parent-red",
      harness.k1->private_key, record, sizeof(record));
  ASSERT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                good_len),
            CRABS_SUCCESS);
  ASSERT_EQ(harness.child_state->lineage_key_chain_count, 2u);

  // Re-delivery of the same record is a rollback (version 2 == max now).
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                good_len),
            CRABS_ERR_INVALID_PARAM);

  crypto_ecdsa_keypair_destroy(k3);
  keychain_harness_destroy(&harness);
}

// Continuity-proof forgery path: the record's old_pk field names the chain
// TIP (k1.public — the tip gate passes), but the signature was made by a
// foreign/never-registered private key. Verification against the pinned
// k1.public fails, refusing the record with CRABS_ERR_CRYPTOGRAPHIC_ERROR
// and leaving the chain byte-identical.
// (The sibling cases — old_pk is not the tip:
// KeyChainRollbackAndGapRejected exercises a never-chained key,
// KeyChainTipOnlyTransitionAccepted exercises a RETIRED chain key; this one
// isolates the verify-under-known-tip failure.)
TEST(TestLineage, KeyChainForgedSignatureUnderKnownOldKey) {
  keychain_harness_t harness;
  keychain_harness_setup(&harness);

  uint8_t record[LINEAGE_KEY_TRANSITION_WIRE_MAX];
  size_t forged_len = keychain_make_record(
      2, harness.k2->public_key, harness.k1->public_key, "parent-red",
      harness.foreign->private_key, record, sizeof(record));

  // Snapshot the chain so the refusal can be proven to be mutation-free.
  const uint32_t chain_count_before =
      harness.child_state->lineage_key_chain_count;
  ASSERT_EQ(chain_count_before, 1u);
  lineage_key_chain_entry_t chain_before[CRABS_MAX_LINEAGE_KEY_CHAIN];
  memcpy(chain_before, harness.child_state->lineage_key_chain,
         chain_count_before * sizeof(lineage_key_chain_entry_t));

  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                forged_len),
            CRABS_ERR_CRYPTOGRAPHIC_ERROR);

  EXPECT_EQ(harness.child_state->lineage_key_chain_count, chain_count_before);
  EXPECT_EQ(memcmp(harness.child_state->lineage_key_chain, chain_before,
                   chain_count_before * sizeof(lineage_key_chain_entry_t)),
            0);

  keychain_harness_destroy(&harness);
}

// Tip-only admission: a transition's old_pk must be the chain TIP — a record
// signed by a RETIRED (but still chained) key must NOT advance the chain,
// even when its signature is perfectly valid. Chain [(1,k1),(2,k2)]: the
// record retiring k1 is refused; the record retiring k2 (the tip) succeeds.
TEST(TestLineage, KeyChainTipOnlyTransitionAccepted) {
  keychain_harness_t harness;
  keychain_harness_setup(&harness);

  // Advance the child to chain [(1,k1),(2,k2)] via a legitimate rotation.
  uint8_t* record = nullptr;
  size_t record_len = 0;
  ASSERT_EQ(lineage_key_rotate(harness.parent_state,
                               harness.k2->private_key, harness.k2->public_key,
                               0, &record, &record_len),
            CRABS_SUCCESS);
  ASSERT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                record_len),
            CRABS_SUCCESS);
  ASSERT_EQ(harness.child_state->lineage_key_chain_count, 2u);
  free(record);

  ecdsa_keypair_t* k3 = crypto_ecdsa_generate();
  ASSERT_NE(k3, nullptr);

  // Snapshot the chain so the refusal can be proven mutation-free.
  lineage_key_chain_entry_t chain_before[CRABS_MAX_LINEAGE_KEY_CHAIN];
  memcpy(chain_before, harness.child_state->lineage_key_chain,
         2 * sizeof(lineage_key_chain_entry_t));

  // A compromised RETIRED key: old_pk = k1, signed VALIDLY by k1's private
  // half, correct version continuity (3) and a fresh new_pk — still refused.
  uint8_t forged[LINEAGE_KEY_TRANSITION_WIRE_MAX];
  size_t forged_len = keychain_make_record(
      3, k3->public_key, harness.k1->public_key, "parent-red",
      harness.k1->private_key, forged, sizeof(forged));
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, forged,
                                                forged_len),
            CRABS_ERR_CRYPTOGRAPHIC_ERROR);
  EXPECT_EQ(harness.child_state->lineage_key_chain_count, 2u);
  EXPECT_EQ(memcmp(harness.child_state->lineage_key_chain, chain_before,
                   2 * sizeof(lineage_key_chain_entry_t)), 0);

  // The tip key (k2) may still advance the chain.
  size_t tip_len = keychain_make_record(
      3, k3->public_key, harness.k2->public_key, "parent-red",
      harness.k2->private_key, forged, sizeof(forged));
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, forged,
                                                tip_len),
            CRABS_SUCCESS);
  ASSERT_EQ(harness.child_state->lineage_key_chain_count, 3u);
  EXPECT_EQ(harness.child_state->lineage_key_chain[2].key_version, 3u);
  EXPECT_EQ(memcmp(harness.child_state->lineage_key_chain[2].public_key,
                   k3->public_key, 33), 0);

  crypto_ecdsa_keypair_destroy(k3);
  keychain_harness_destroy(&harness);
}

TEST(TestLineage, KeyChainAcceptRefusesUnboundOrDissolvedChild) {
  keychain_harness_t harness;
  keychain_harness_setup(&harness);

  uint8_t record[LINEAGE_KEY_TRANSITION_WIRE_MAX];
  size_t record_len = keychain_make_record(
      2, harness.k2->public_key, harness.k1->public_key, "parent-red",
      harness.k1->private_key, record, sizeof(record));

  // Unbound: no chain exists to advance.
  state_t* unbound = state_create();
  ASSERT_NE(unbound, nullptr);
  EXPECT_EQ(lineage_child_accept_key_transition(unbound, record, record_len),
            CRABS_ERR_UNAUTHORIZED);
  state_destroy(unbound);

  // Dissolved: the lineage is severed — no new parent key may rotate in.
  harness.child_state->lineage_parent_dissolved = true;
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                record_len),
            CRABS_ERR_UNAUTHORIZED);
  harness.child_state->lineage_parent_dissolved = false;

  // Malformed sizes and NULLs refuse without touching the chain.
  EXPECT_EQ(lineage_child_accept_key_transition(nullptr, record, record_len),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, nullptr,
                                                record_len),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                16),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(lineage_child_accept_key_transition(
                harness.child_state, record,
                LINEAGE_KEY_TRANSITION_WIRE_MAX + 1),
            CRABS_ERR_INVALID_PARAM);
  ASSERT_EQ(harness.child_state->lineage_key_chain_count, 1u);

  keychain_harness_destroy(&harness);
}

TEST(TestLineage, KeyChainCapacityRefusesNinthEntry) {
  state_t* parent = state_create();
  ASSERT_NE(parent, nullptr);
  state_t* child = state_create();
  ASSERT_NE(child, nullptr);

  ecdsa_keypair_t* keys[CRABS_MAX_LINEAGE_KEY_CHAIN + 1] = {nullptr};
  for (size_t key_index = 0;
       key_index <= (size_t)CRABS_MAX_LINEAGE_KEY_CHAIN; key_index++) {
    keys[key_index] = crypto_ecdsa_generate();
    ASSERT_NE(keys[key_index], nullptr);
  }

  // chain[0] = the spawn pin under k1.
  ASSERT_EQ(state_set_node_key(parent, keys[0]->private_key,
                             keys[0]->public_key), CRABS_SUCCESS);
  strncpy(parent->config.bootstrap_admin, "parent-red",
          sizeof(parent->config.bootstrap_admin) - 1);
  keychain_bind_child(child, keys[0]->public_key);

  // Rotations 1..7 fill the chain to its cap (entries: k1..k8).
  for (size_t rotation = 1; rotation < (size_t)CRABS_MAX_LINEAGE_KEY_CHAIN;
       rotation++) {
    uint8_t* record = nullptr;
    size_t record_len = 0;
    ASSERT_EQ(lineage_key_rotate(parent, keys[rotation]->private_key,
                                 keys[rotation]->public_key, 0, &record,
                                 &record_len),
              CRABS_SUCCESS) << rotation;
    ASSERT_EQ(lineage_child_accept_key_transition(child, record, record_len),
              CRABS_SUCCESS) << rotation;
    free(record);
    // Rotate never installs the new key — the caller pairs it (mirrors the
    // documented caller contract).
    ASSERT_EQ(state_set_node_key(parent, keys[rotation]->private_key,
                                 keys[rotation]->public_key), CRABS_SUCCESS);
  }
  ASSERT_EQ(child->lineage_key_chain_count,
            (uint32_t)CRABS_MAX_LINEAGE_KEY_CHAIN);
  EXPECT_EQ(parent->lineage_key_version,
            (uint64_t)CRABS_MAX_LINEAGE_KEY_CHAIN);

  // The 8th rotation (a 9th chain entry) overflows the bounded history — the
  // child refuses rather than truncating the spawn pin. keys[8] has never
  // entered the chain, so the record itself is otherwise fully valid.
  uint8_t* record = nullptr;
  size_t record_len = 0;
  ASSERT_EQ(lineage_key_rotate(parent,
                               keys[CRABS_MAX_LINEAGE_KEY_CHAIN]->private_key,
                               keys[CRABS_MAX_LINEAGE_KEY_CHAIN]->public_key,
                               0, &record, &record_len),
            CRABS_SUCCESS);
  EXPECT_EQ(lineage_child_accept_key_transition(child, record, record_len),
            CRABS_ERR_OOM);

  // The refusal mutated nothing: the chain still ends at k8 / version 8.
  EXPECT_EQ(child->lineage_key_chain_count,
            (uint32_t)CRABS_MAX_LINEAGE_KEY_CHAIN);
  EXPECT_EQ(child->lineage_key_chain[CRABS_MAX_LINEAGE_KEY_CHAIN - 1]
                .key_version,
            (uint64_t)CRABS_MAX_LINEAGE_KEY_CHAIN);
  EXPECT_EQ(memcmp(child->lineage_key_chain[CRABS_MAX_LINEAGE_KEY_CHAIN - 1]
                       .public_key,
                   keys[CRABS_MAX_LINEAGE_KEY_CHAIN - 1]->public_key, 33), 0);

  free(record);
  for (size_t key_index = 0;
       key_index <= (size_t)CRABS_MAX_LINEAGE_KEY_CHAIN; key_index++) {
    crypto_ecdsa_keypair_destroy(keys[key_index]);
  }
  state_destroy(child);
  state_destroy(parent);
}

// Regression for audit A11-L2: the canonical key-transition body writer's
// trailing created_at write must be cap-checked — an undersized buffer must
// yield a 0 refusal, not an out-of-bounds write. The writer is static; the
// test shim (test_lineage_body_writer.c) recompiles lineage.c into the test
// binary so this test can construct the call directly. A one-character
// parent_id with cap == BODY_MIN: the string16 fits (offset 77 -> 80) but the
// 8-byte created_at would land one byte past the buffer — the old code wrote
// it anyway and returned 88 (> cap); the fixed code refuses with 0. (An empty
// parent_id at cap == BODY_MIN lands EXACTLY on the boundary, so it does not
// exercise the gap.)
TEST(TestLineage, KeyTransitionBodyWriterRefusesUndersizedCap) {
  uint8_t new_pk[33] = {0};
  uint8_t old_pk[33] = {0};
  uint8_t out[LINEAGE_KEY_TRANSITION_BODY_MIN] = {0};
  size_t written = crabs_test_lineage_key_transition_write_body(
      CRABS_LINEAGE_KEY_VERSION_START + 1, new_pk, old_pk, "x", 0, out,
      sizeof(out));
  EXPECT_EQ(written, 0u);
}

TEST(TestLineage, KeyChainVerifyByAnyChainKey) {
  keychain_harness_t harness;
  keychain_harness_setup(&harness);

  const char* message = "tombstone or endorsement material";
  uint8_t signature_by_k1[CRABS_SIG_SIZE];
  uint8_t signature_by_k2[CRABS_SIG_SIZE];
  uint8_t signature_by_foreign[CRABS_SIG_SIZE];
  ASSERT_EQ(crypto_ecdsa_sign(harness.k1->private_key,
                              (const uint8_t*)message, strlen(message),
                              signature_by_k1), CRABS_SUCCESS);
  ASSERT_EQ(crypto_ecdsa_sign(harness.k2->private_key,
                              (const uint8_t*)message, strlen(message),
                              signature_by_k2), CRABS_SUCCESS);
  ASSERT_EQ(crypto_ecdsa_sign(harness.foreign->private_key,
                              (const uint8_t*)message, strlen(message),
                              signature_by_foreign), CRABS_SUCCESS);

  // Chain holds only k1 for now: k1 verifies, k2 and foreign do not.
  EXPECT_TRUE(lineage_verify_by_parent_key(harness.child_state,
                                           (const uint8_t*)message,
                                           strlen(message), signature_by_k1));
  EXPECT_FALSE(lineage_verify_by_parent_key(harness.child_state,
                                            (const uint8_t*)message,
                                            strlen(message), signature_by_k2));

  // Advance the chain: both the spawn pin and the rotated key verify — old
  // attestations keep working, new ones land.
  uint8_t record[LINEAGE_KEY_TRANSITION_WIRE_MAX];
  size_t record_len = keychain_make_record(
      2, harness.k2->public_key, harness.k1->public_key, "parent-red",
      harness.k1->private_key, record, sizeof(record));
  ASSERT_EQ(lineage_child_accept_key_transition(harness.child_state, record,
                                                record_len),
            CRABS_SUCCESS);
  EXPECT_TRUE(lineage_verify_by_parent_key(harness.child_state,
                                           (const uint8_t*)message,
                                           strlen(message), signature_by_k1));
  EXPECT_TRUE(lineage_verify_by_parent_key(harness.child_state,
                                           (const uint8_t*)message,
                                           strlen(message), signature_by_k2));
  EXPECT_FALSE(lineage_verify_by_parent_key(harness.child_state,
                                            (const uint8_t*)message,
                                            strlen(message),
                                            signature_by_foreign));

  // A never-bound machine carries no chain and fails closed.
  state_t* unbound = state_create();
  ASSERT_NE(unbound, nullptr);
  EXPECT_FALSE(lineage_verify_by_parent_key(unbound, (const uint8_t*)message,
                                            strlen(message),
                                            signature_by_k1));
  state_destroy(unbound);

  // NULL-safety.
  EXPECT_FALSE(lineage_verify_by_parent_key(nullptr, (const uint8_t*)message,
                                            strlen(message),
                                            signature_by_k1));
  EXPECT_FALSE(lineage_verify_by_parent_key(harness.child_state, nullptr,
                                            strlen(message),
                                            signature_by_k1));
  EXPECT_FALSE(lineage_verify_by_parent_key(harness.child_state,
                                            (const uint8_t*)message,
                                            strlen(message), nullptr));

  keychain_harness_destroy(&harness);
}

// ============================================================
// __parent_key_update__: the op pipeline path into the key chain (A10-M6)
// ============================================================

// Deliver a key transition record to a child machine through its own auth
// pipeline: the signer is the child's genesis admin "child-admin" — registered
// at spawn with the parent's PRE-rotation node public key, so the ORIGINAL
// parent keypair carries the op — under the installer's "role:admin" policy.
// Carriage (the op signature) and content (the parent-signed record inside)
// are the same two independent proofs as __receive_dissolution__.
static crabs_error_e deliver_key_update(attribute_machine_t* child,
                                        ecdsa_keypair_t* carrier_key,
                                        const uint8_t* record,
                                        size_t record_len) {
  operation_t* op = make_signed_lineage_op(child, carrier_key, "child-admin",
                                           CRABS_LINEAGE_OP_PARENT_KEY_UPDATE,
                                           record, record_len);
  EXPECT_NE(op, nullptr);
  if (op == NULL) return CRABS_ERR_INVALID_PARAM;
  crabs_error_e status = state_machine_execute(&child->base_state, op);
  operation_destroy(op);
  return status;
}

TEST(TestLineage, ParentKeyUpdateEndToEnd) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;

  // Two resident delegated children: spawn stamps each chain at
  // [(CRABS_LINEAGE_KEY_VERSION_START, parent node key)] alongside the
  // lineage_parent_public_key pin.
  machine_blueprint_t* red_blueprint =
      make_fresh_authority_blueprint("child-red", LINEAGE_DELEGATED_COPY);
  ASSERT_NE(red_blueprint, nullptr);
  attribute_machine_t* child_red = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, red_blueprint, &child_red),
            CRABS_SUCCESS);
  machine_blueprint_t* blue_blueprint =
      make_fresh_authority_blueprint("child-blue", LINEAGE_DELEGATED_COPY);
  ASSERT_NE(blue_blueprint, nullptr);
  attribute_machine_t* child_blue = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blue_blueprint, &child_blue),
            CRABS_SUCCESS);
  attribute_machine_t* children[2] = {child_red, child_blue};
  for (int child_index = 0; child_index < 2; child_index++) {
    state_t* child_state = &children[child_index]->base_state;
    lineage_install(child_state);
    ASSERT_EQ(child_state->lineage_key_chain_count, 1u);
    EXPECT_EQ(child_state->lineage_key_chain[0].key_version,
              (uint64_t)CRABS_LINEAGE_KEY_VERSION_START);
    EXPECT_EQ(memcmp(child_state->lineage_key_chain[0].public_key,
                     harness.parent_key->public_key, 33), 0);
  }

  // Parent rotates k1 -> k2: the record is signed by k1 and stashed for
  // re-emission; k2 becomes the parent's live node key.
  ecdsa_keypair_t* k2 = crypto_ecdsa_generate();
  ASSERT_NE(k2, nullptr);
  uint8_t* record = nullptr;
  size_t record_len = 0;
  ASSERT_EQ(lineage_key_rotate(parent, k2->private_key, k2->public_key,
                               1700000000000ULL, &record, &record_len),
            CRABS_SUCCESS);
  ASSERT_EQ(state_set_node_key(parent, k2->private_key, k2->public_key),
            CRABS_SUCCESS);
  EXPECT_EQ(parent->lineage_key_version,
            (uint64_t)CRABS_LINEAGE_KEY_VERSION_START + 1);

  // Capture the first child's change event for the update op.
  static crabs_change_event_t captured_events[4];
  static uint32_t captured_event_count;
  captured_event_count = 0;
  state_set_change_hook(&child_red->base_state,
                        [](state_t*, const crabs_change_event_t* event,
                           void*) {
    if (event->kind != CRABS_CHANGE_LINEAGE) return;
    if (captured_event_count < 4) {
      captured_events[captured_event_count++] = *event;
    }
  }, nullptr);

  // ONE record (bound to the parent_id, not a child) serves BOTH children —
  // delivered through each child's own op pipeline.
  for (int child_index = 0; child_index < 2; child_index++) {
    EXPECT_EQ(deliver_key_update(children[child_index], harness.parent_key,
                                 record, record_len),
              CRABS_SUCCESS);
    state_t* child_state = &children[child_index]->base_state;
    ASSERT_EQ(child_state->lineage_key_chain_count, 2u);
    EXPECT_EQ(child_state->lineage_key_chain[0].key_version,
              (uint64_t)CRABS_LINEAGE_KEY_VERSION_START);
    EXPECT_EQ(memcmp(child_state->lineage_key_chain[0].public_key,
                     harness.parent_key->public_key, 33), 0);
    EXPECT_EQ(child_state->lineage_key_chain[1].key_version,
              (uint64_t)CRABS_LINEAGE_KEY_VERSION_START + 1);
    EXPECT_EQ(memcmp(child_state->lineage_key_chain[1].public_key,
                     k2->public_key, 33), 0);
  }

  // Change event: lineage kind, the update op type, attributed to the op,
  // targeting THIS machine (the __receive_dissolution__ precedent for
  // child-side ops names the mutated machine) — the preview carries that the
  // PARENT's key was accepted.
  ASSERT_EQ(captured_event_count, 1u);
  EXPECT_EQ(captured_events[0].kind, CRABS_CHANGE_LINEAGE);
  EXPECT_STREQ(captured_events[0].type, "__parent_key_update__");
  EXPECT_STREQ(captured_events[0].target, "child-red");
  EXPECT_STREQ(captured_events[0].preview, "parent key accepted");
  EXPECT_EQ(captured_events[0].result, CRABS_SUCCESS);

  free(record);
  crypto_ecdsa_keypair_destroy(k2);
  attribute_machine_destroy(child_red);
  attribute_machine_destroy(child_blue);
  machine_blueprint_destroy(red_blueprint);
  machine_blueprint_destroy(blue_blueprint);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, ParentKeyUpdateNewKeyEndorsementSatisfies) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  g_test_clock_ms = 1700000000000ULL;  // fixed test epoch T0
  state_set_time_source(parent, &g_test_clock_ops);

  machine_blueprint_t* blueprint =
      make_endorsed_delegated_blueprint("child-delegated");
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  state_set_time_source(&child->base_state, &g_test_clock_ops);
  register_child_render_handler(child);
  lineage_install(&child->base_state);

  // Rotate k1 -> k2 BEFORE the child learns of it: the parent's issuances
  // are now k2-signed while the child still holds only the spawn pin.
  ecdsa_keypair_t* k2 = crypto_ecdsa_generate();
  ASSERT_NE(k2, nullptr);
  uint8_t* record = nullptr;
  size_t record_len = 0;
  ASSERT_EQ(lineage_key_rotate(parent, k2->private_key, k2->public_key,
                               g_test_clock_ms, &record, &record_len),
            CRABS_SUCCESS);
  ASSERT_EQ(state_set_node_key(parent, k2->private_key, k2->public_key),
            CRABS_SUCCESS);

  // Endorsement attestation signed with k2 (the parent's CURRENT node key).
  attestation_t attestation;
  ASSERT_EQ(crabs_issue_attestation(parent, &attestation, "child-delegated",
                                    "child-admin", "role:writer",
                                    g_test_clock_ms), CRABS_SUCCESS);

  // The child-admin carries the endorsed op; its registry key is the
  // pre-rotation parent public key, so the ORIGINAL parent keypair signs
  // (the attestation attaches AFTER signing — the signing image excludes
  // attestations, per the established idiom).
  operation_t* op = operation_create("render");
  ASSERT_NE(op, nullptr);
  strncpy(op->signer_id, "child-admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(child, harness.parent_key, op);
  attach_attestation(op, &attestation);

  // Before the update: k2 is not an accepted parent key — the endorsement
  // fails closed even though the attestation is honestly signed.
  EXPECT_EQ(state_machine_execute(&child->base_state, op),
            CRABS_ERR_UNAUTHORIZED);
  operation_destroy(op);

  // Deliver the transition through the pipeline.
  ASSERT_EQ(deliver_key_update(child, harness.parent_key, record, record_len),
            CRABS_SUCCESS);

  // The SAME signer, SAME k2-signed attestation now authorizes via the
  // chain. (A fresh op shell — lamport monotonicity refuses a literal
  // re-execution, unrelated to the endorsement gate.)
  operation_t* op2 = operation_create("render");
  ASSERT_NE(op2, nullptr);
  strncpy(op2->signer_id, "child-admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(child, harness.parent_key, op2);
  attach_attestation(op2, &attestation);
  EXPECT_EQ(state_machine_execute(&child->base_state, op2), CRABS_SUCCESS);

  operation_destroy(op2);
  free(record);
  crypto_ecdsa_keypair_destroy(k2);
  attribute_machine_destroy(child);
  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}

TEST(TestLineage, ParentKeyUpdateRejectsTamperedRecord) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;

  machine_blueprint_t* blueprint =
      make_fresh_authority_blueprint("child-red", LINEAGE_DELEGATED_COPY);
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  lineage_install(&child->base_state);

  ecdsa_keypair_t* k2 = crypto_ecdsa_generate();
  ASSERT_NE(k2, nullptr);
  uint8_t* record = nullptr;
  size_t record_len = 0;
  ASSERT_EQ(lineage_key_rotate(parent, k2->private_key, k2->public_key,
                               1700000000000ULL, &record, &record_len),
            CRABS_SUCCESS);

  // Tamper INSIDE the signed body (created_at — informational, so every
  // structural gate still parses and the failure is pure signature
  // verification): the handler surfaces the accept gate's cryptographic
  // refusal and the chain is untouched.
  const size_t body_len = record_len - CRABS_SIG_SIZE;
  uint8_t tampered[LINEAGE_KEY_TRANSITION_WIRE_MAX];
  memcpy(tampered, record, record_len);
  tampered[body_len - 1] ^= 0xFF;
  EXPECT_EQ(deliver_key_update(child, harness.parent_key, tampered,
                               record_len),
            CRABS_ERR_CRYPTOGRAPHIC_ERROR);
  EXPECT_EQ(child->base_state.lineage_key_chain_count, 1u);
  EXPECT_EQ(memcmp(child->base_state.lineage_key_chain[0].public_key,
                   harness.parent_key->public_key, 33), 0);

  // Tampering the trailing signature fails closed the same way.
  memcpy(tampered, record, record_len);
  tampered[record_len - 1] ^= 0x01;
  EXPECT_EQ(deliver_key_update(child, harness.parent_key, tampered,
                               record_len),
            CRABS_ERR_CRYPTOGRAPHIC_ERROR);
  EXPECT_EQ(child->base_state.lineage_key_chain_count, 1u);

  free(record);
  crypto_ecdsa_keypair_destroy(k2);
  attribute_machine_destroy(child);
  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}

// ============================================================
// Genesis provenance verification (A10-L1)
// ============================================================
//
// lineage_spawn_machine signs the child's canonical unkeyed genesis
// serialization with the parent's node key and persists the blob's SHA-256
// (genesis_snapshot_hash) plus the signature (genesis_attestation_signature)
// in the manifest, but NOT the blob itself. Because crypto_ecdsa_sign signs
// SHA-256(body) directly as the 32-byte ECDSA digest, the stored hash IS the
// digest, so lineage_verify_child_provenance can fully check the manifest:
// the signature must verify under the parent's current node public key over
// digest genesis_snapshot_hash.

TEST(GenesisProvenance, VerifiesFreshSpawnSuccess) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;

  // Shared-root spawn.
  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  ASSERT_NE(child, nullptr);
  EXPECT_EQ(lineage_verify_child_provenance(parent, "child-red"),
            CRABS_SUCCESS);

  // Delegated spawn: provenance is digest-bound, so the fresh random
  // authority minted here changes nothing about verifiability.
  machine_blueprint_t* delegated_blueprint =
      make_fresh_authority_blueprint("child-del", LINEAGE_DELEGATED_COPY);
  ASSERT_NE(delegated_blueprint, nullptr);
  attribute_machine_t* delegated_child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, delegated_blueprint,
                                  &delegated_child),
            CRABS_SUCCESS);
  ASSERT_NE(delegated_child, nullptr);
  EXPECT_EQ(lineage_verify_child_provenance(parent, "child-del"),
            CRABS_SUCCESS);

  attribute_machine_destroy(delegated_child);
  attribute_machine_destroy(child);
  machine_blueprint_destroy(delegated_blueprint);
  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}

TEST(GenesisProvenance, FailsOnTamperedManifest) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  ASSERT_NE(child, nullptr);

  child_manifest_entry_t* manifest_entry =
      lineage_find_manifest_entry(parent, "child-red");
  ASSERT_NE(manifest_entry, nullptr);
  const uint8_t original_hash_byte = manifest_entry->genesis_snapshot_hash[0];
  const uint8_t original_sig_byte =
      manifest_entry->genesis_attestation_signature[CRABS_SIG_SIZE - 1];

  // A corrupted stored hash no longer matches the digest the signature
  // covers → cryptographic failure.
  manifest_entry->genesis_snapshot_hash[0] ^= 0xFF;
  EXPECT_EQ(lineage_verify_child_provenance(parent, "child-red"),
            CRABS_ERR_CRYPTOGRAPHIC_ERROR);
  manifest_entry->genesis_snapshot_hash[0] = original_hash_byte;
  EXPECT_EQ(lineage_verify_child_provenance(parent, "child-red"),
            CRABS_SUCCESS);

  // A corrupted attestation signature fails the same way.
  manifest_entry->genesis_attestation_signature[CRABS_SIG_SIZE - 1] ^= 0xFF;
  EXPECT_EQ(lineage_verify_child_provenance(parent, "child-red"),
            CRABS_ERR_CRYPTOGRAPHIC_ERROR);
  manifest_entry->genesis_attestation_signature[CRABS_SIG_SIZE - 1] =
      original_sig_byte;
  EXPECT_EQ(lineage_verify_child_provenance(parent, "child-red"),
            CRABS_SUCCESS);

  attribute_machine_destroy(child);
  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}

TEST(GenesisProvenance, UnknownChildNotFound) {
  spawn_parent_harness_t harness;
  spawn_parent_setup(&harness);
  state_t* parent = &harness.am->base_state;
  machine_blueprint_t* blueprint = make_valid_blueprint();
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent, blueprint, &child), CRABS_SUCCESS);
  ASSERT_NE(child, nullptr);

  // An id no manifest entry carries is a lookup miss, not a proof failure.
  EXPECT_EQ(lineage_verify_child_provenance(parent, "no-such-child"),
            CRABS_ERR_RESOURCE_NOT_FOUND);

  // Bad inputs fail at the gate.
  EXPECT_EQ(lineage_verify_child_provenance(NULL, "child-red"),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(lineage_verify_child_provenance(parent, NULL),
            CRABS_ERR_INVALID_PARAM);

  attribute_machine_destroy(child);
  machine_blueprint_destroy(blueprint);
  spawn_parent_destroy(&harness);
}
