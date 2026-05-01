#include <gtest/gtest.h>
extern "C" {
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/crypto.h"
#include "../src/Serialization/serialization.h"
}

class TestStateMachine : public ::testing::Test {
protected:
  state_t* state;
  uint8_t test_uuid[CRABS_UUID_SIZE];
  attribute_machine_t* am;
  ecdsa_keypair_t* alice_key;

  void SetUp() override {
    state = state_create();

    // Add a resource item to the state
    data_item_t* res = data_item_create("test_resource", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
    int64_t* val = (int64_t*)malloc(sizeof(int64_t));
    *val = 0;
    res->value = val;
    state_add_item(state, res);

    // Add policies for lock operations
    state_add_policy(state, CRABS_OP_LOCK, "role:admin");
    state_add_policy(state, CRABS_OP_EXTEND, "role:admin");
    state_add_policy(state, CRABS_OP_VERIFY, "role:admin");
    state_add_policy(state, CRABS_OP_ROLLBACK, "role:admin");
    state_add_policy(state, CRABS_OP_UNLOCK, "role:admin");
    state_add_policy(state, CRABS_OP_FORCE_UNLOCK, "role:admin");
    state_add_policy(state, CRABS_OP_REFRESH_KEY, "role:admin");

    // Set a known UUID for testing
    memset(test_uuid, 0x42, CRABS_UUID_SIZE);

    // Generate ECDSA keypair for alice
    alice_key = crypto_ecdsa_generate();
    ASSERT_NE(alice_key, nullptr);

    // Create attribute machine and register alice with role:admin
    uint8_t admin_pk[33];
    memset(admin_pk, 0xAA, 33);
    admin_pk[0] = 0x02;
    am = attribute_machine_create("admin", admin_pk);
    ASSERT_NE(am, nullptr);

    crabs_error_e rc = attribute_machine_register_user(
        am, "alice", alice_key->public_key, "role:admin");
    ASSERT_EQ(rc, CRABS_SUCCESS);

    // Attach attribute machine to state so ABE verification is enforced
    state->attr_machine = am;

    // Generate and set node key for envelope signing (§11)
    ecdsa_keypair_t* node_key = crypto_ecdsa_generate();
    ASSERT_NE(node_key, nullptr);
    state_set_node_key(state, node_key->private_key, node_key->public_key);
    crypto_ecdsa_keypair_destroy(node_key);
  }

  void TearDown() override {
    state->attr_machine = NULL;
    state_destroy(state);
    attribute_machine_destroy(am);
    crypto_ecdsa_keypair_destroy(alice_key);
  }

  operation_t* make_lock_op() {
    operation_t* op = operation_create(CRABS_OP_LOCK);
    memcpy(op->uuid, test_uuid, CRABS_UUID_SIZE);
    op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
    strncpy(op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
    op->resource_count = 1;
    op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
    op->required_state[0] = PROTOCOL_IDLE;
    op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
    op->next_state[0] = PROTOCOL_LOCKED;
    strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
    sign_operation(op);
    return op;
  }

  void sign_operation(operation_t* op) {
    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
    if (ser != NULL) {
      crypto_sign_operation(alice_key->private_key, ser->data, ser->len, op->signature);
      serialized_buffer_destroy(ser);
    }
  }
};

TEST_F(TestStateMachine, TestValidTransition) {
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_IDLE, CRABS_OP_LOCK));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_LOCKED, CRABS_OP_EXTEND));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_MODIFIED, CRABS_OP_VERIFY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_MODIFIED, CRABS_OP_ROLLBACK));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_VERIFIED, CRABS_OP_UNLOCK));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_LOCKED, CRABS_OP_FORCE_UNLOCK));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_ERROR, CRABS_OP_ROLLBACK));
  // Invalid transitions
  EXPECT_FALSE(state_machine_is_valid_transition(PROTOCOL_IDLE, CRABS_OP_UNLOCK));
  EXPECT_FALSE(state_machine_is_valid_transition(PROTOCOL_IDLE, CRABS_OP_VERIFY));
  // LOCKED→* is valid (any user op transitions to MODIFIED)
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_LOCKED, CRABS_OP_LOCK));
}

TEST_F(TestStateMachine, TestLockOperation) {
  operation_t* op = make_lock_op();
  crabs_error_e result = state_machine_execute(state, op);
  EXPECT_EQ(result, CRABS_SUCCESS);

  data_item_t* item = state_find_item(state, "test_resource");
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->protocol_state, PROTOCOL_LOCKED);
  EXPECT_TRUE(item->lock_state.lock_token_valid);
  EXPECT_STREQ(item->lock_state.lock_owner, "alice");
  EXPECT_EQ(state->version, 1);

  operation_destroy(op);
}

TEST_F(TestStateMachine, TestLockThenExtend) {
  // Lock first
  operation_t* lock_op = make_lock_op();
  EXPECT_EQ(state_machine_execute(state, lock_op), CRABS_SUCCESS);
  operation_destroy(lock_op);

  // Now extend
  operation_t* extend_op = operation_create(CRABS_OP_EXTEND);
  memset(extend_op->uuid, 0x43, CRABS_UUID_SIZE);
  extend_op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(extend_op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  extend_op->resource_count = 1;
  extend_op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  extend_op->required_state[0] = PROTOCOL_LOCKED;
  extend_op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  extend_op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(extend_op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_operation(extend_op);

  crabs_error_e result = state_machine_execute(state, extend_op);
  EXPECT_EQ(result, CRABS_SUCCESS);

  data_item_t* item = state_find_item(state, "test_resource");
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->protocol_state, PROTOCOL_LOCKED);
  EXPECT_EQ(item->lock_state.lock_extensions, 1);

  operation_destroy(extend_op);
}

TEST_F(TestStateMachine, TestLockVerifyUnlockCycle) {
  // Lock
  operation_t* lock_op = make_lock_op();
  EXPECT_EQ(state_machine_execute(state, lock_op), CRABS_SUCCESS);
  operation_destroy(lock_op);

  // Get lock token from state
  data_item_t* item = state_find_item(state, "test_resource");
  ASSERT_NE(item, nullptr);

  // Set to modified state (simulate a user modifying the resource)
  item->protocol_state = PROTOCOL_MODIFIED;

  // Verify
  operation_t* verify_op = operation_create(CRABS_OP_VERIFY);
  memset(verify_op->uuid, 0x44, CRABS_UUID_SIZE);
  verify_op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(verify_op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  verify_op->resource_count = 1;
  verify_op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  verify_op->required_state[0] = PROTOCOL_MODIFIED;
  verify_op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  verify_op->next_state[0] = PROTOCOL_VERIFIED;
  verify_op->lock_claims = (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(verify_op->lock_claims[0].resource, "test_resource", CRABS_MAX_USER_ID - 1);
  memcpy(verify_op->lock_claims[0].lock_token, item->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE);
  verify_op->lock_claim_count = 1;
  strncpy(verify_op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_operation(verify_op);

  EXPECT_EQ(state_machine_execute(state, verify_op), CRABS_SUCCESS);
  EXPECT_EQ(item->protocol_state, PROTOCOL_VERIFIED);
  operation_destroy(verify_op);

  // Unlock
  operation_t* unlock_op = operation_create(CRABS_OP_UNLOCK);
  memset(unlock_op->uuid, 0x45, CRABS_UUID_SIZE);
  unlock_op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(unlock_op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  unlock_op->resource_count = 1;
  unlock_op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  unlock_op->required_state[0] = PROTOCOL_VERIFIED;
  unlock_op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  unlock_op->next_state[0] = PROTOCOL_IDLE;
  unlock_op->lock_claims = (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(unlock_op->lock_claims[0].resource, "test_resource", CRABS_MAX_USER_ID - 1);
  memcpy(unlock_op->lock_claims[0].lock_token, item->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE);
  unlock_op->lock_claim_count = 1;
  strncpy(unlock_op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_operation(unlock_op);

  EXPECT_EQ(state_machine_execute(state, unlock_op), CRABS_SUCCESS);
  EXPECT_EQ(item->protocol_state, PROTOCOL_IDLE);
  EXPECT_FALSE(item->lock_state.lock_token_valid);
  operation_destroy(unlock_op);
}

TEST_F(TestStateMachine, TestLockTokenMismatch) {
  operation_t* op = make_lock_op();
  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);

  data_item_t* item = state_find_item(state, "test_resource");
  item->protocol_state = PROTOCOL_MODIFIED;

  // Try with wrong lock token
  operation_t* bad_op = operation_create(CRABS_OP_VERIFY);
  memset(bad_op->uuid, 0x46, CRABS_UUID_SIZE);
  bad_op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(bad_op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  bad_op->resource_count = 1;
  bad_op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  bad_op->required_state[0] = PROTOCOL_MODIFIED;
  bad_op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  bad_op->next_state[0] = PROTOCOL_VERIFIED;
  bad_op->lock_claims = (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(bad_op->lock_claims[0].resource, "test_resource", CRABS_MAX_USER_ID - 1);
  memset(bad_op->lock_claims[0].lock_token, 0xFF, CRABS_LOCK_TOKEN_SIZE); // wrong token
  bad_op->lock_claim_count = 1;
  strncpy(bad_op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_operation(bad_op);

  EXPECT_EQ(state_machine_execute(state, bad_op), CRABS_ERR_LOCK_TOKEN_MISMATCH);
  operation_destroy(bad_op);
}

TEST_F(TestStateMachine, TestRollback) {
  operation_t* lock_op = make_lock_op();
  EXPECT_EQ(state_machine_execute(state, lock_op), CRABS_SUCCESS);
  operation_destroy(lock_op);

  data_item_t* item = state_find_item(state, "test_resource");
  item->protocol_state = PROTOCOL_MODIFIED;

  operation_t* rollback_op = operation_create(CRABS_OP_ROLLBACK);
  memset(rollback_op->uuid, 0x47, CRABS_UUID_SIZE);
  rollback_op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(rollback_op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  rollback_op->resource_count = 1;
  rollback_op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  rollback_op->required_state[0] = PROTOCOL_MODIFIED;
  rollback_op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  rollback_op->next_state[0] = PROTOCOL_IDLE;
  rollback_op->lock_claims = (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(rollback_op->lock_claims[0].resource, "test_resource", CRABS_MAX_USER_ID - 1);
  memcpy(rollback_op->lock_claims[0].lock_token, item->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE);
  rollback_op->lock_claim_count = 1;
  strncpy(rollback_op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_operation(rollback_op);

  EXPECT_EQ(state_machine_execute(state, rollback_op), CRABS_SUCCESS);
  EXPECT_EQ(item->protocol_state, PROTOCOL_IDLE);
  EXPECT_FALSE(item->lock_state.lock_token_valid);
  operation_destroy(rollback_op);
}

TEST_F(TestStateMachine, TestIdempotency) {
  operation_t* op = make_lock_op();
  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  // Same UUID again should succeed (idempotent)
  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  EXPECT_EQ(state->version, 1); // Version should not increment
  operation_destroy(op);
}

TEST_F(TestStateMachine, TestResourceNotFound) {
  operation_t* op = operation_create(CRABS_OP_LOCK);
  memset(op->uuid, 0x48, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "nonexistent", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_operation(op);

  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_RESOURCE_NOT_FOUND);
  operation_destroy(op);
}

TEST_F(TestStateMachine, TestDuplicateAddItem) {
  data_item_t* item = data_item_create("test_resource", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  EXPECT_EQ(state_add_item(state, item), CRABS_ERR_DUPLICATE_OPERATION);
  data_item_destroy(item);
}

TEST_F(TestStateMachine, TestOperationIsBuiltin) {
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_LOCK));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_EXTEND));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_UNLOCK));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_VERIFY));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_ROLLBACK));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_FORCE_UNLOCK));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_CHANGE_CONFIG));
  EXPECT_FALSE(operation_is_builtin("custom_transfer"));
}

TEST_F(TestStateMachine, TestLockTokenEntropy) {
  operation_t* op = make_lock_op();
  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  data_item_t* item = state_find_item(state, "test_resource");
  ASSERT_NE(item, nullptr);

  uint8_t token1[CRABS_LOCK_TOKEN_SIZE];
  memcpy(token1, item->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE);
  operation_destroy(op);

  // Reset state and lock again - tokens must differ
  item->protocol_state = PROTOCOL_IDLE;
  item->lock_state.lock_token_valid = false;

  operation_t* op2 = operation_create(CRABS_OP_LOCK);
  memset(op2->uuid, 0x55, CRABS_UUID_SIZE);
  op2->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op2->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  op2->resource_count = 1;
  op2->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op2->required_state[0] = PROTOCOL_IDLE;
  op2->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op2->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op2->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_operation(op2);
  EXPECT_EQ(state_machine_execute(state, op2), CRABS_SUCCESS);

  // Tokens should differ (with overwhelming probability if CSPRNG)
  EXPECT_NE(memcmp(token1, item->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE), 0);
  operation_destroy(op2);
}

TEST_F(TestStateMachine, TestRollbackRestoresOriginalValue) {
  data_item_t* item = state_find_item(state, "test_resource");
  ASSERT_NE(item, nullptr);
  int64_t original_value = *(int64_t*)item->value;

  // Lock
  operation_t* lock_op = make_lock_op();
  EXPECT_EQ(state_machine_execute(state, lock_op), CRABS_SUCCESS);
  operation_destroy(lock_op);

  // Get fresh pointer after lock
  item = state_find_item(state, "test_resource");
  ASSERT_NE(item, nullptr);

  // Modify value
  *(int64_t*)item->value = original_value + 100;
  item->protocol_state = PROTOCOL_MODIFIED;

  // Rollback should restore original value
  operation_t* rollback_op = operation_create(CRABS_OP_ROLLBACK);
  memset(rollback_op->uuid, 0x50, CRABS_UUID_SIZE);
  rollback_op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(rollback_op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  rollback_op->resource_count = 1;
  rollback_op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  rollback_op->required_state[0] = PROTOCOL_MODIFIED;
  rollback_op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  rollback_op->next_state[0] = PROTOCOL_IDLE;
  rollback_op->lock_claims = (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(rollback_op->lock_claims[0].resource, "test_resource", CRABS_MAX_USER_ID - 1);
  memcpy(rollback_op->lock_claims[0].lock_token, item->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE);
  rollback_op->lock_claim_count = 1;
  strncpy(rollback_op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_operation(rollback_op);

  EXPECT_EQ(state_machine_execute(state, rollback_op), CRABS_SUCCESS);
  EXPECT_EQ(*(int64_t*)item->value, original_value);
  operation_destroy(rollback_op);
}

TEST_F(TestStateMachine, TestChangeConfig) {
  const char* payload_str = "max_lock_duration_ms=10000";
  operation_t* op = operation_create(CRABS_OP_CHANGE_CONFIG);
  memset(op->uuid, 0x49, CRABS_UUID_SIZE);
  op->payload = (uint8_t*)strdup(payload_str);
  op->payload_size = strlen(payload_str);
  op->resource_count = 0;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_operation(op);

  state_add_policy(state, CRABS_OP_CHANGE_CONFIG, "role:admin");
  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  EXPECT_EQ(state->config.max_lock_duration_ms, 10000);
  operation_destroy(op);
}

TEST_F(TestStateMachine, TestKeyVersionVerification_StaleKey) {
  // Set user's key_version to 2
  user_t* user = attribute_machine_find_user(am, "alice");
  ASSERT_NE(user, nullptr);
  user->key_version = 2;

  // Create a lock operation with stale key_version=1 (must set before signing)
  operation_t* op = operation_create(CRABS_OP_LOCK);
  memcpy(op->uuid, test_uuid, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->signer_key_version = 1;  // Stale — user is on version 2
  sign_operation(op);

  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_KEY_STALE);
  operation_destroy(op);

  // Now with matching key_version=2 — should succeed
  operation_t* op2 = operation_create(CRABS_OP_LOCK);
  memset(op2->uuid, 0x99, CRABS_UUID_SIZE);
  op2->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op2->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  op2->resource_count = 1;
  op2->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op2->required_state[0] = PROTOCOL_IDLE;
  op2->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op2->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op2->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op2->signer_key_version = 2;
  sign_operation(op2);

  EXPECT_EQ(state_machine_execute(state, op2), CRABS_SUCCESS);
  operation_destroy(op2);
}

TEST_F(TestStateMachine, TestKeyVersionVerification_NoAttrMachine) {
  // Without attr_machine, key version check should be skipped
  state->attr_machine = NULL;

  operation_t* op = operation_create(CRABS_OP_LOCK);
  memset(op->uuid, 0x48, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->signer_key_version = 99;  // Would be stale if attr_machine existed

  // Without attr_machine, step 5 ABE verification is skipped entirely
  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);

  // Restore attr_machine for TearDown
  state->attr_machine = am;
}

TEST_F(TestStateMachine, TestKeyVersionVerification_ZeroKeyVersion) {
  // Set user's key_version to 5
  user_t* user = attribute_machine_find_user(am, "alice");
  ASSERT_NE(user, nullptr);
  user->key_version = 5;

  // signer_key_version = 0 means "skip version check" (per spec §10.4)
  operation_t* op = make_lock_op();
  op->signer_key_version = 0;

  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);
}

TEST_F(TestStateMachine, TestRefreshKey) {
  // Record alice's key_version before refresh
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  uint64_t old_version = alice->key_version;

  // Create a refresh key operation (no resources needed)
  operation_t* op = operation_create(CRABS_OP_REFRESH_KEY);
  memcpy(op->uuid, test_uuid, CRABS_UUID_SIZE);
  op->resource_count = 0;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->signer_key_version = old_version;
  sign_operation(op);

  crabs_error_e result = state_machine_execute(state, op);
  EXPECT_EQ(result, CRABS_SUCCESS);

  // Alice's key_version should be updated to match state version
  EXPECT_NE(alice->key_version, old_version);

  // Envelope should be stored in state for caller retrieval
  EXPECT_NE(state->last_refresh_envelope, nullptr);
  key_envelope_t* env = (key_envelope_t*)state->last_refresh_envelope;
  EXPECT_EQ(env->format_version, KEY_ENVELOPE_FORMAT_V1);
  EXPECT_STREQ(env->user_id, "alice");

  // Envelope should be verifiable with node's public key
  EXPECT_TRUE(crypto_key_envelope_verify(state->node_public_key, env));

  operation_destroy(op);
}

TEST_F(TestStateMachine, TestRefreshKeyNoNodeKey) {
  // Create a state without node key
  state_t* no_key_state = state_create();
  no_key_state->attr_machine = am;

  operation_t* op = operation_create(CRABS_OP_REFRESH_KEY);
  memcpy(op->uuid, test_uuid, CRABS_UUID_SIZE);
  op->resource_count = 0;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_operation(op);

  crabs_error_e result = state_machine_execute(no_key_state, op);
  EXPECT_EQ(result, CRABS_ERR_CRYPTOGRAPHIC_ERROR);

  operation_destroy(op);
  no_key_state->attr_machine = NULL;
  state_destroy(no_key_state);
}