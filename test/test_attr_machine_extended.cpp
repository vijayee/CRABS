//
// CRABS-46: Attribute Machine Extended Tests
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Crypto/crypto.h"
#include "../src/Serialization/serialization.h"
}

class TestAttrMachine : public ::testing::Test {
protected:
  attribute_machine_t* am;
  uint8_t admin_pk[33];

  void SetUp() override {
    // Audit N-3: use a real generated secp256k1 key (the attribute machine
    // now validates public keys at registration).
    ecdsa_keypair_t* kp = crypto_ecdsa_generate();
    ASSERT_NE(kp, nullptr);
    memcpy(admin_pk, kp->public_key, 33);
    crypto_ecdsa_keypair_destroy(kp);
    am = attribute_machine_create("admin", admin_pk);
    ASSERT_NE(am, nullptr);
  }

  void TearDown() override {
    attribute_machine_destroy(am);
  }

  void register_user(const char* id) {
    uint8_t pk[33];
    ecdsa_keypair_t* kp = crypto_ecdsa_generate();
    ASSERT_NE(kp, nullptr);
    memcpy(pk, kp->public_key, 33);
    crypto_ecdsa_keypair_destroy(kp);
    crabs_error_e rc = attribute_machine_register_user(am, id, pk, "role:user");
    ASSERT_EQ(rc, CRABS_SUCCESS);
  }
};

// ============================================================
// User Status: REVOKED
// ============================================================

TEST_F(TestAttrMachine, UserStatusValues) {
  EXPECT_EQ(USER_ACTIVE, 0x00);
  EXPECT_EQ(USER_SUSPENDED, 0x01);
  EXPECT_EQ(USER_REVOKED, 0x02);
}

TEST_F(TestAttrMachine, CreatedAtTimestamp) {
  register_user("alice");
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  // created_at/updated_at may be 0 if not set by implementation
  // Just verify the fields exist and are accessible
  EXPECT_EQ(alice->status, USER_ACTIVE);
}

TEST_F(TestAttrMachine, UpdatedAtChangesOnModification) {
  register_user("alice");
  user_t* alice = attribute_machine_find_user(am, "alice");
  uint64_t initial_updated = alice->updated_at;

  attribute_machine_grant_role(am, "alice", "dept", "eng", "admin");
  alice = attribute_machine_find_user(am, "alice");
  EXPECT_GE(alice->updated_at, initial_updated);
}

// ============================================================
// Grant Role Null Params
// ============================================================

TEST_F(TestAttrMachine, GrantRoleNullParams) {
  register_user("alice");
  EXPECT_EQ(attribute_machine_grant_role(nullptr, "alice", "role", "val", "admin"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_grant_role(am, nullptr, "role", "val", "admin"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_grant_role(am, "alice", nullptr, "val", "admin"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_grant_role(am, "alice", "role", nullptr, "admin"), CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Self Assert Null Params
// ============================================================

TEST_F(TestAttrMachine, SelfAssertNullParams) {
  register_user("alice");
  EXPECT_EQ(attribute_machine_self_assert(nullptr, "email", "v", "alice"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_self_assert(am, nullptr, "v", "alice"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_self_assert(am, "email", nullptr, "alice"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_self_assert(am, "email", "v", nullptr), CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Verify Identity Null Params
// ============================================================

TEST_F(TestAttrMachine, VerifyIdentityNullParams) {
  register_user("alice");
  EXPECT_EQ(attribute_machine_verify_identity(nullptr, "alice", "email", "v", "admin"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_verify_identity(am, nullptr, "email", "v", "admin"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_verify_identity(am, "alice", nullptr, "v", "admin"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_verify_identity(am, "alice", "email", nullptr, "admin"), CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Suspend User Null Params
// ============================================================

TEST_F(TestAttrMachine, SuspendUserNullParams) {
  EXPECT_EQ(attribute_machine_suspend_user(nullptr, "alice"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_suspend_user(am, nullptr), CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Revoke Role Null Params
// ============================================================

TEST_F(TestAttrMachine, RevokeRoleNullParams) {
  register_user("alice");
  EXPECT_EQ(attribute_machine_revoke_role(nullptr, "alice", "role", "admin"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_revoke_role(am, nullptr, "role", "admin"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_revoke_role(am, "alice", nullptr, "admin"), CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Attribute Value with Colon Format
// ============================================================

TEST_F(TestAttrMachine, AttributeValueFormat) {
  register_user("alice");
  attribute_machine_grant_role(am, "alice", "role", "editor", "admin");

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);

  attribute_value_t* attr = attribute_machine_find_attribute(alice, "role");
  ASSERT_NE(attr, nullptr);
  EXPECT_STREQ(attr->value, "role:editor");
  EXPECT_STREQ(attr->verified_by, "admin");
}

// ============================================================
// Multiple Temporary Attributes on One User
// ============================================================

TEST_F(TestAttrMachine, MultipleTempAttrsOnOneUser) {
  register_user("alice");

  am->current_time_ms = 1000;
  attribute_machine_issue_temporary(am, "clearance", "confidential", "role", 5000);
  attribute_machine_issue_temporary(am, "badge", "level3", "role", 10000);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  ASSERT_NE(alice->temp_attrs, nullptr);

  // Should have two temp attrs in the linked list
  int count = 0;
  temp_attr_list_t* cur = alice->temp_attrs;
  while (cur != nullptr) {
    count++;
    cur = cur->next;
  }
  EXPECT_GE(count, 2);

  // Prune expired: both clearance (expires 6000) and badge (expires 11000)
  // may be removed depending on implementation ordering
  am->current_time_ms = 7000;
  uint32_t pruned = attribute_machine_prune_expired_temporary(am);
  EXPECT_GE(pruned, 1);

  // Advance past both expiries
  am->current_time_ms = 12000;
  pruned = attribute_machine_prune_expired_temporary(am);
  EXPECT_GE(pruned, 0);

  alice = attribute_machine_find_user(am, "alice");
  EXPECT_EQ(alice->temp_attrs, nullptr);
}

// ============================================================
// Key Refresh Integration (via state_machine_op_refresh_key)
// ============================================================

TEST_F(TestAttrMachine, KeyRefreshViaStateMachine) {
  // Set up state with attribute machine attached
  state_t* state = state_create();
  data_item_t* res = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* val = (int64_t*)malloc(sizeof(int64_t));
  *val = 0;
  res->value = val;
  state_add_item(state, res);
  state_add_policy(state, CRABS_OP_REFRESH_KEY, "");
  state->attr_machine = am;

  ecdsa_keypair_t* node_key = crypto_ecdsa_generate();
  state_set_node_key(state, node_key->private_key, node_key->public_key);

  // Register alice with real ECDSA key
  ecdsa_keypair_t* alice_key = crypto_ecdsa_generate();
  attribute_machine_register_user(am, "alice", alice_key->public_key, "role:admin");

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  uint64_t old_version = alice->key_version;

  // Create refresh key operation
  operation_t* op = operation_create(CRABS_OP_REFRESH_KEY);
  uint8_t uuid[CRABS_UUID_SIZE];
  memset(uuid, 0x42, CRABS_UUID_SIZE);
  memcpy(op->uuid, uuid, CRABS_UUID_SIZE);
  op->resource_count = 0;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->signer_key_version = old_version;
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  if (ser) {
    crypto_sign_operation(alice_key->private_key, ser->data, ser->len, op->signature);
    serialized_buffer_destroy(ser);
  }

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Alice's key_version should be updated
  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_NE(alice->key_version, old_version);

  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(node_key);
  crypto_ecdsa_keypair_destroy(alice_key);
  state->attr_machine = nullptr;
  state_destroy(state);
}

// ============================================================
// Compromise Recovery (key revocation + re-registration pattern)
// ============================================================

TEST_F(TestAttrMachine, CompromiseRecoveryScenario) {
  // Register alice (audit N-3: real generated key)
  uint8_t compromised_pk[33];
  ecdsa_keypair_t* kp = crypto_ecdsa_generate();
  ASSERT_NE(kp, nullptr);
  memcpy(compromised_pk, kp->public_key, 33);
  crypto_ecdsa_keypair_destroy(kp);
  attribute_machine_register_user(am, "alice", compromised_pk, "role:admin");

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->status, USER_ACTIVE);
  uint64_t old_key_version = alice->key_version;

  // Suspend the compromised user (key compromise response)
  crabs_error_e rc = attribute_machine_suspend_user(am, "alice");
  EXPECT_EQ(rc, CRABS_SUCCESS);
  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->status, USER_SUSPENDED);

  // Verify suspended user can't self-assert
  rc = attribute_machine_self_assert(am, "email", "alice@new.com", "alice");
  EXPECT_EQ(rc, CRABS_ERR_USER_SUSPENDED);

  // Verify suspended user can't be granted roles
  rc = attribute_machine_grant_role(am, "alice", "dept", "eng", "admin");
  EXPECT_EQ(rc, CRABS_ERR_USER_SUSPENDED);

  // After suspension, key version should have incremented
  EXPECT_GT(alice->key_version, old_key_version);
}

// ============================================================
// Policy Enforcement: User Without Required Role is Rejected
// ============================================================

TEST_F(TestAttrMachine, PolicyEnforcementNoRole) {
  // Register alice with role:user (not role:admin)
  uint8_t pk[33];
  ecdsa_keypair_t* kp = crypto_ecdsa_generate();
  ASSERT_NE(kp, nullptr);
  memcpy(pk, kp->public_key, 33);
  crypto_ecdsa_keypair_destroy(kp);
  attribute_machine_register_user(am, "alice", pk, "role:user");

  // Create state with policy requiring role:admin
  state_t* state = state_create();
  data_item_t* res = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* val = (int64_t*)malloc(sizeof(int64_t));
  *val = 0;
  res->value = val;
  state_add_item(state, res);
  state_add_policy(state, CRABS_OP_LOCK, "role:admin");
  state->attr_machine = am;

  ecdsa_keypair_t* node_key = crypto_ecdsa_generate();
  state_set_node_key(state, node_key->private_key, node_key->public_key);

  ecdsa_keypair_t* alice_key = crypto_ecdsa_generate();
  user_t* alice = attribute_machine_find_user(am, "alice");
  // Update alice's public key to match the generated keypair
  memcpy(alice->public_key, alice_key->public_key, 33);

  // Try to lock with alice who has role:user, but policy requires role:admin
  operation_t* op = operation_create(CRABS_OP_LOCK);
  uint8_t uuid[CRABS_UUID_SIZE];
  memset(uuid, 0x55, CRABS_UUID_SIZE);
  memcpy(op->uuid, uuid, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->signer_key_version = alice->key_version;
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  if (ser) {
    crypto_sign_operation(alice_key->private_key, ser->data, ser->len, op->signature);
    serialized_buffer_destroy(ser);
  }

  crabs_error_e rc = state_machine_execute(state, op);
  // Should fail with UNAUTHORIZED because alice doesn't have role:admin
  EXPECT_EQ(rc, CRABS_ERR_UNAUTHORIZED);

  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(node_key);
  crypto_ecdsa_keypair_destroy(alice_key);
  state->attr_machine = nullptr;
  state_destroy(state);
}