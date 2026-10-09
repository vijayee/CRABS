#include <gtest/gtest.h>
extern "C" {
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/crypto.h"
#include "../src/Serialization/serialization.h"
#include "../src/TxManager/tx_manager_memory.h"
#include "../src/CRDT/crdt_merge.h"
}
#include "test_helpers.h"

class TestStateMachine : public ::testing::Test {
protected:
  state_t* state;
  uint8_t test_uuid[CRABS_UUID_SIZE];
  attribute_machine_t* am;
  ecdsa_keypair_t* alice_key;
  // R7-11: Lamport monotonicity is enforced per signer, so each op must carry
  // a strictly increasing lamport_time. Stamped in sign_operation.
  uint64_t lamport_counter = 0;

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

    crabs_error_e rc = crabs_test_register_user_with_role(
        am, "alice", alice_key->public_key, "role", "admin");
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
    // R7-04: the key-version check is now mandatory, so ops must carry the
    // signer's current key_version.
    user_t* signer = attribute_machine_find_user(am, "alice");
    if (signer != NULL) op->signer_key_version = signer->key_version;
    sign_operation(op);
    return op;
  }

  // R7-04: ops must carry the signer's current key_version before signing.
  void set_signer_key_version(operation_t* op) {
    user_t* signer = attribute_machine_find_user(am, "alice");
    if (signer != NULL) op->signer_key_version = signer->key_version;
  }

  void sign_operation(operation_t* op) {
    op->lamport_time = ++lamport_counter;
    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
    if (ser != NULL) {
      crypto_sign_operation(alice_key->private_key, ser->data, ser->len, op->signature);
      serialized_buffer_destroy(ser);
    }
  }

  // Audit: a Mode B (anonymous) operation leaves signer_id empty and is
  // signed with the caller's own key — the verifier must resolve the signer
  // from the keyring. The key-version gates must run against that RESOLVED
  // signer, not against the empty op->signer_id.
  operation_t* make_anonymous_lock_op() {
    operation_t* op = operation_create(CRABS_OP_LOCK);
    memcpy(op->uuid, test_uuid, CRABS_UUID_SIZE);
    op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
    strncpy(op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
    op->resource_count = 1;
    op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
    op->required_state[0] = PROTOCOL_IDLE;
    op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
    op->next_state[0] = PROTOCOL_LOCKED;
    // signer_id intentionally left empty (Mode B).
    user_t* signer = attribute_machine_find_user(am, "alice");
    if (signer != NULL) op->signer_key_version = signer->key_version;
    sign_operation(op);
    return op;
  }

  policy_t* find_lock_policy() {
    for (uint32_t policy_index = 0; policy_index < state->policy_count; policy_index++) {
      if (strcmp(state->policies[policy_index].operation, CRABS_OP_LOCK) == 0) {
        return &state->policies[policy_index];
      }
    }
    return NULL;
  }
};

// Audit: an op-carried dedup spec is signer-authored (condition, target and
// delta are all covered only by the op's own signature). When no spec is
// registered for the op type via __define_operation_type__, the executor must
// reject the op instead of falling back to the op-carried spec — otherwise the
// spec's MUTATION section is an unauthorized mutation primitive on any state
// item.
TEST_F(TestStateMachine, OpCarriedDedupSpecRejectedWithoutRegistration) {
  // The mutation target: a g-counter the op does not own and that no
  // registered spec covers.
  data_item_t* counter_item =
      data_item_create("smuggled_target", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* counter_value = g_counter_create();
  ASSERT_EQ(g_counter_increment(counter_value, "admin", 10), CRABS_SUCCESS);
  counter_item->value = counter_value;
  ASSERT_EQ(state_add_item(state, counter_item), CRABS_SUCCESS);

  operation_t* op = make_lock_op();
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "true", CRABS_MAX_POLICY_EXPR - 1);
  op->dedup.update.type = MUTATION_COUNTER_INCREMENT;
  strncpy(op->dedup.update.counter_path, "smuggled_target", CRABS_MAX_DEDUP_PATH - 1);
  op->dedup.update.delta = 1000;
  sign_operation(op);  // re-sign after attaching the spec

  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_UNAUTHORIZED);

  // Neither the smuggled mutation nor the handler may have run.
  data_item_t* target = state_find_item(state, "smuggled_target");
  ASSERT_NE(target, nullptr);
  EXPECT_EQ(g_counter_value((g_counter_t*)target->value), 10);
  data_item_t* resource = state_find_item(state, "test_resource");
  ASSERT_NE(resource, nullptr);
  EXPECT_EQ(resource->protocol_state, PROTOCOL_IDLE);

  operation_destroy(op);
}

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

// R7-01: when an authenticated time source is configured but unavailable,
// state_machine_execute must fail closed rather than fall back to the
// attacker-controlled local clock for expiry decisions.
TEST_F(TestStateMachine, TestUnavailableTimeSourceFailsClosed) {
  static crabs_time_source_ops_t unavailable_ops;
  unavailable_ops.get_time = [](void* ctx) -> crabs_physical_time_t {
    (void)ctx;
    crabs_physical_time_t t = {0, 0, false};
    return t;
  };
  unavailable_ops.is_available = [](void* ctx) -> bool {
    (void)ctx;
    return false;
  };
  unavailable_ops.ctx = NULL;

  state_set_time_source(state, &unavailable_ops);

  operation_t* op = make_lock_op();
  crabs_error_e result = state_machine_execute(state, op);
  EXPECT_EQ(result, CRABS_ERR_CRYPTOGRAPHIC_ERROR);
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
  set_signer_key_version(extend_op);
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
  set_signer_key_version(verify_op);
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
  set_signer_key_version(unlock_op);
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
  set_signer_key_version(rollback_op);
  sign_operation(rollback_op);

  EXPECT_EQ(state_machine_execute(state, rollback_op), CRABS_SUCCESS);
  EXPECT_EQ(item->protocol_state, PROTOCOL_IDLE);
  EXPECT_FALSE(item->lock_state.lock_token_valid);
  operation_destroy(rollback_op);
}

TEST_F(TestStateMachine, TestIdempotency) {
  // Install a memory tx_manager so duplicate UUIDs are rejected
  state->tx_manager = crabs_tx_manager_memory(64);
  operation_t* op = make_lock_op();
  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  // Same UUID again should succeed (idempotent via tx_manager)
  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_ALREADY_EXECUTED);
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
  user_t* signer = attribute_machine_find_user(am, "alice");
  if (signer != NULL) op->signer_key_version = signer->key_version;
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
  user_t* signer = attribute_machine_find_user(am, "alice");
  if (signer != NULL) op2->signer_key_version = signer->key_version;
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
  set_signer_key_version(rollback_op);
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
  user_t* signer = attribute_machine_find_user(am, "alice");
  if (signer != NULL) op->signer_key_version = signer->key_version;
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
  // Fail-closed: without attr_machine, authorization cannot be verified,
  // so execution must be rejected.
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

  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_UNAUTHORIZED);
  operation_destroy(op);

  // Restore attr_machine for TearDown
  state->attr_machine = am;
}

TEST_F(TestStateMachine, TestKeyVersionVerification_ZeroKeyVersion) {
  // Set user's key_version to 5
  user_t* user = attribute_machine_find_user(am, "alice");
  ASSERT_NE(user, nullptr);
  user->key_version = 5;

  // R7-04: signer_key_version = 0 must NOT skip the staleness check when the
  // signer has a nonzero key_version — otherwise a replayed op signed with a
  // rotated-out key is accepted. The op must carry the matching version.
  // Build the op manually so signer_key_version=0 is set BEFORE signing.
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
  op->signer_key_version = 0;
  sign_operation(op);

  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_KEY_STALE);
  operation_destroy(op);
}

// R7-04: a policy that restricts allowed schemes must reject an op declaring
// SCHEME_UNSPECIFIED — otherwise the allowlist is bypassed by declaring the
// legacy path.
TEST_F(TestStateMachine, SchemeConstraintRejectsUnspecified) {
  // Restrict __lock__ to ECDSA_SECP256K1 only.
  policy_t* policy = NULL;
  for (uint32_t i = 0; i < state->policy_count; i++) {
    if (strcmp(state->policies[i].operation, CRABS_OP_LOCK) == 0) {
      policy = &state->policies[i];
      break;
    }
  }
  ASSERT_NE(policy, nullptr);
  policy->allowed_schemes[0] = ECDSA_SECP256K1;
  policy->allowed_scheme_count = 1;

  // make_lock_op signs with alice's legacy key and leaves sig_scheme
  // UNSPECIFIED (zero-init). The allowlist must reject it.
  operation_t* op = make_lock_op();
  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_UNAUTHORIZED);
  operation_destroy(op);
}

// ============================================================
// Audit: Mode B (anonymous-signer) operations must not skip the
// key-version gates. The staleness check and the policy min_key_version
// floor previously resolved the signer via op->signer_id, which is empty
// for Mode B, so a lagging keyholder could sign anonymously and bypass a
// forced-rotation floor with a still-ACTIVE key.
// ============================================================

TEST_F(TestStateMachine, ModeBOperationEnforcesMinKeyVersionFloor) {
  // Alice is ACTIVE on key_version 1; the policy forces rotation to >= 5.
  policy_t* policy = find_lock_policy();
  ASSERT_NE(policy, nullptr);
  policy->min_key_version = 5;

  operation_t* op = make_anonymous_lock_op();
  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_KEY_STALE);
  operation_destroy(op);
}

TEST_F(TestStateMachine, ModeBOperationEnforcesKeyStalenessCheck) {
  // The anonymous op declares a key_version that no longer matches the
  // resolved signer's current version — the staleness gate must fire.
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  alice->key_version = 3;

  operation_t* op = make_anonymous_lock_op();
  op->signer_key_version = 1;  // Stale relative to alice's current version.
  sign_operation(op);
  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_KEY_STALE);
  operation_destroy(op);
}

TEST_F(TestStateMachine, ModeBKeyringSignedOperationEnforcesMinKeyVersionFloor) {
  crypto_sig_scheme_init();
  const signature_vtable_t* scheme_vtable = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(scheme_vtable, nullptr);
  uint8_t public_key[33];
  uint32_t public_key_len = sizeof(public_key);
  uint8_t private_key[32];
  uint32_t private_key_len = sizeof(private_key);
  ASSERT_EQ(scheme_vtable->generate_keypair(public_key, &public_key_len,
                                            private_key, &private_key_len),
            CRABS_SUCCESS);

  // The lagging keyholder registers their still-ACTIVE keyring key.
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  ASSERT_EQ(user_key_register(alice, "lagging-key", ECDSA_SECP256K1,
                              public_key, public_key_len, "primary"),
            CRABS_SUCCESS);

  policy_t* policy = find_lock_policy();
  ASSERT_NE(policy, nullptr);
  policy->min_key_version = 5;

  operation_t* op = operation_create(CRABS_OP_LOCK);
  memcpy(op->uuid, test_uuid, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  // Mode B: signer_id empty; the op carries the key identity that verifies.
  op->sig_scheme = ECDSA_SECP256K1;
  strncpy(op->key_id, "lagging-key", CRABS_MAX_KEY_ID - 1);
  op->signer_key_version = alice->key_version;
  op->lamport_time = ++lamport_counter;
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  ASSERT_NE(ser, nullptr);
  uint8_t signature[CRABS_SIG_SIZE];
  uint32_t signature_len = sizeof(signature);
  ASSERT_EQ(scheme_vtable->sign(private_key, private_key_len,
                                ser->data, ser->len, signature, &signature_len),
            CRABS_SUCCESS);
  memcpy(op->signature, signature, CRABS_SIG_SIZE);
  serialized_buffer_destroy(ser);

  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_KEY_STALE);
  operation_destroy(op);
  crypto_sig_scheme_cleanup();
}

// Mode A behavior must be preserved: a signer whose user record is below
// the policy min_key_version floor is rejected even with a matching
// declared key_version.
TEST_F(TestStateMachine, ModeAOperationEnforcesMinKeyVersionFloor) {
  policy_t* policy = find_lock_policy();
  ASSERT_NE(policy, nullptr);
  policy->min_key_version = 5;

  operation_t* op = make_lock_op();
  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_KEY_STALE);
  operation_destroy(op);
}

// Audit A10-M2: In Mode B (anonymous signer) the primary signer leaves
// op->signer_id empty and is resolved by the authorization step into the
// keyring-matched user. Per v1.3 §4.2 co-signers must be distinct from the
// primary signer, so the resolved signer must not also occupy a co-signer
// slot — otherwise one party satisfies a threshold of 2 alone.
TEST_F(TestStateMachine, ModeBPrimarySignerCannotDoubleAsCoSigner) {
  state->config.sig_config.co_sign_threshold = 2;

  // Register a second, genuinely distinct admin (bob) with a real key.
  ecdsa_keypair_t* bob_key = crypto_ecdsa_generate();
  ASSERT_NE(bob_key, nullptr);
  ASSERT_EQ(crabs_test_register_user_with_role(am, "bob", bob_key->public_key,
                                               "role", "admin"),
            CRABS_SUCCESS);

  // Mode B: signer_id empty, signed by alice — she is the resolved primary
  // signer after step 3's trial verification.
  operation_t* op = make_anonymous_lock_op();

  // Co-signer slot 0: alice again, doubling her resolved primary role.
  // Co-signer slot 1: bob, a valid second signer.
  op->co_signers = (co_signature_t*)calloc(2, sizeof(co_signature_t));
  ASSERT_NE(op->co_signers, nullptr);
  serialized_buffer_t* co_ser = crabs_serialize_for_signing(op);
  ASSERT_NE(co_ser, nullptr);
  strncpy(op->co_signers[0].signer_id, "alice", CRABS_MAX_USER_ID - 1);
  ASSERT_EQ(crypto_ecdsa_sign(alice_key->private_key, co_ser->data, co_ser->len,
                              op->co_signers[0].signature),
            CRABS_SUCCESS);
  op->co_signers[0].signature_len = CRABS_SIG_SIZE;
  strncpy(op->co_signers[1].signer_id, "bob", CRABS_MAX_USER_ID - 1);
  ASSERT_EQ(crypto_ecdsa_sign(bob_key->private_key, co_ser->data, co_ser->len,
                              op->co_signers[1].signature),
            CRABS_SUCCESS);
  op->co_signers[1].signature_len = CRABS_SIG_SIZE;
  serialized_buffer_destroy(co_ser);
  op->co_signer_count = 2;

  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_DUPLICATE_OPERATION);

  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(bob_key);
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
  // Register the refresh-key policy so execution reaches the node-key check
  // (fail-closed authorization requires a registered policy).
  state_add_policy(no_key_state, CRABS_OP_REFRESH_KEY, "role:admin");

  operation_t* op = operation_create(CRABS_OP_REFRESH_KEY);
  memcpy(op->uuid, test_uuid, CRABS_UUID_SIZE);
  op->resource_count = 0;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  user_t* signer = attribute_machine_find_user(am, "alice");
  if (signer != NULL) op->signer_key_version = signer->key_version;
  sign_operation(op);

  crabs_error_e result = state_machine_execute(no_key_state, op);
  EXPECT_EQ(result, CRABS_ERR_CRYPTOGRAPHIC_ERROR);

  operation_destroy(op);
  no_key_state->attr_machine = NULL;
  state_destroy(no_key_state);
}
// Regression for audit M-8: the audit log must carry a tamper-evident hash
// chain, not all-zero state_hash values.
TEST_F(TestStateMachine, AuditLogHashChainIsNonZeroAndChained) {
  operation_t* op1 = make_lock_op();
  for (int i = 0; i < CRABS_UUID_SIZE; i++) op1->uuid[i] = (uint8_t)(i + 1);
  sign_operation(op1);
  ASSERT_EQ(state_machine_execute(state, op1), CRABS_SUCCESS);
  operation_destroy(op1);

  ASSERT_GT(state->log_count, 0u);
  // First entry's state_hash must be non-zero (previously it was always zero).
  bool nonzero = false;
  for (int i = 0; i < CRABS_HASH_SIZE; i++) {
    if (state->log[state->log_count - 1].state_hash[i] != 0) { nonzero = true; break; }
  }
  EXPECT_TRUE(nonzero);

  // A second op (extend, valid on a locked resource) produces a different
  // chain hash — it mixes in the prior entry's hash.
  uint8_t first[CRABS_HASH_SIZE];
  memcpy(first, state->log[state->log_count - 1].state_hash, CRABS_HASH_SIZE);

  operation_t* op2 = operation_create(CRABS_OP_EXTEND);
  for (int i = 0; i < CRABS_UUID_SIZE; i++) op2->uuid[i] = (uint8_t)(i + 2);
  op2->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op2->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  op2->resource_count = 1;
  op2->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op2->required_state[0] = PROTOCOL_LOCKED;
  op2->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op2->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op2->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  user_t* signer = attribute_machine_find_user(am, "alice");
  if (signer != NULL) op2->signer_key_version = signer->key_version;
  sign_operation(op2);
  ASSERT_EQ(state_machine_execute(state, op2), CRABS_SUCCESS);
  operation_destroy(op2);

  EXPECT_NE(memcmp(first, state->log[state->log_count - 1].state_hash, CRABS_HASH_SIZE), 0);
}

// ============================================================
// State Change Notification (devtools change events core)
// ============================================================

// Stateless sink: a captureless lambda cannot reach local variables, so the
// hook tests use a static struct. The event is borrowed only for the
// duration of the hook call, so the hook copies it into static storage.
// Place ABOVE the first test that uses it.
struct ChangeSink {
  static crabs_change_event_t last_event_storage;
  static bool has_event;
  static int call_count;
  // The event's strings are borrowed and only valid for the duration of the
  // hook call — copy the ones tests inspect after the call returns.
  static char type_storage[CRABS_MAX_OP_NAME];
  static char target_storage[CRABS_MAX_USER_ID];
  static char preview_storage[256];
  static void hook(state_t*, const crabs_change_event_t* event, void* user_data) {
    (void)user_data;
    ChangeSink::last_event_storage = *event;
    if (event->type != nullptr) {
      strncpy(type_storage, event->type, CRABS_MAX_OP_NAME - 1);
      type_storage[CRABS_MAX_OP_NAME - 1] = '\0';
      ChangeSink::last_event_storage.type = type_storage;
    }
    if (event->target != nullptr) {
      strncpy(target_storage, event->target, CRABS_MAX_USER_ID - 1);
      target_storage[CRABS_MAX_USER_ID - 1] = '\0';
      ChangeSink::last_event_storage.target = target_storage;
    }
    if (event->preview != nullptr) {
      strncpy(preview_storage, event->preview, sizeof(preview_storage) - 1);
      preview_storage[sizeof(preview_storage) - 1] = '\0';
      ChangeSink::last_event_storage.preview = preview_storage;
    }
    ChangeSink::has_event = true;
    ChangeSink::call_count++;
  }
};
crabs_change_event_t ChangeSink::last_event_storage;
bool ChangeSink::has_event = false;
int ChangeSink::call_count = 0;
char ChangeSink::type_storage[CRABS_MAX_OP_NAME];
char ChangeSink::target_storage[CRABS_MAX_USER_ID];
char ChangeSink::preview_storage[256];

TEST_F(TestStateMachine, ChangeHookFiresOnExecuteSuccess) {
  state_set_change_hook(state, ChangeSink::hook, nullptr);
  ChangeSink::call_count = 0;
  ChangeSink::has_event = false;

  operation_t* op = make_lock_op();
  ASSERT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);

  EXPECT_EQ(ChangeSink::call_count, 1);
  ASSERT_TRUE(ChangeSink::has_event);
  EXPECT_STREQ(ChangeSink::last_event_storage.type, "__lock__");
  EXPECT_EQ(ChangeSink::last_event_storage.kind, CRABS_CHANGE_OP);
  EXPECT_EQ(ChangeSink::last_event_storage.result, CRABS_SUCCESS);
  state_set_change_hook(state, nullptr, nullptr);
}

TEST_F(TestStateMachine, ChangeHookFiresOnExecuteFailure) {
  state_set_change_hook(state, ChangeSink::hook, nullptr);
  ChangeSink::call_count = 0;
  ChangeSink::has_event = false;

  // Corrupt signature -> cryptographic failure; no state mutation, but the
  // event still fires (devtools parity with the old recorder).
  operation_t* op = make_lock_op();
  op->signature[0] = (uint8_t)(op->signature[0] ^ 0xFF);
  EXPECT_NE(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);

  EXPECT_EQ(ChangeSink::call_count, 1);
  EXPECT_NE(ChangeSink::last_event_storage.result, CRABS_SUCCESS);
  state_set_change_hook(state, nullptr, nullptr);
}

TEST_F(TestStateMachine, ChangeHookIdempotentSkipFiresNothing) {
  state_set_change_hook(state, ChangeSink::hook, nullptr);
  ChangeSink::call_count = 0;
  ChangeSink::has_event = false;

  operation_t* op = make_lock_op();
  ASSERT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  crabs_error_e replay = state_machine_execute(state, op);
  operation_destroy(op);

  // CRABS_ERR_ALREADY_EXECUTED is an idempotent skip: no mutation, no event.
  EXPECT_EQ(replay, CRABS_ERR_ALREADY_EXECUTED);
  EXPECT_EQ(ChangeSink::call_count, 1);
  state_set_change_hook(state, nullptr, nullptr);
}

TEST_F(TestStateMachine, ChangeHookNullIsNoOp) {
  state_set_change_hook(state, nullptr, nullptr);  // must not crash
  ChangeSink::call_count = 0;
  ChangeSink::has_event = false;
  operation_t* op = make_lock_op();
  ASSERT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);
}

TEST_F(TestStateMachine, ChangeHookIsRuntimeStateNotSerialized) {
  state_set_change_hook(state, ChangeSink::hook, nullptr);
  ChangeSink::call_count = 0;
  ChangeSink::has_event = false;

  serialized_buffer_t* blob = crabs_serialize_state(state);
  ASSERT_NE(blob, nullptr);
  state_t* restored = crabs_deserialize_state(blob->data, blob->len);
  serialized_buffer_destroy(blob);
  ASSERT_NE(restored, nullptr);
  // attr_machine is runtime state too (like the hook): production re-attaches
  // it after loading, so mirror that here — otherwise authorization fails
  // closed with CRABS_ERR_UNAUTHORIZED and the hook assertions are unreachable.
  restored->attr_machine = am;
  operation_t* op = make_lock_op();
  ASSERT_EQ(state_machine_execute(restored, op), CRABS_SUCCESS);
  operation_destroy(op);
  EXPECT_EQ(ChangeSink::call_count, 0);
  EXPECT_EQ(restored->change_hook, nullptr);
  state_destroy(restored);
  state_set_change_hook(state, nullptr, nullptr);
}

// state_notify_change_for_op propagates every operation field, and a
// non-NULL preview_override replaces the default.
TEST_F(TestStateMachine, ChangeHookForOpPropagation) {
  state_set_change_hook(state, ChangeSink::hook, nullptr);
  ChangeSink::call_count = 0;
  ChangeSink::has_event = false;

  operation_t* op = make_lock_op();
  state_notify_change_for_op(state, CRABS_CHANGE_OP, op, "preview text",
                             CRABS_ERR_UNAUTHORIZED);

  ASSERT_TRUE(ChangeSink::has_event);
  EXPECT_EQ(ChangeSink::last_event_storage.kind, CRABS_CHANGE_OP);
  EXPECT_STREQ(ChangeSink::last_event_storage.type, "__lock__");
  EXPECT_EQ(ChangeSink::last_event_storage.uuid, op->uuid);
  EXPECT_STREQ(ChangeSink::last_event_storage.signer_id, "alice");
  EXPECT_STREQ(ChangeSink::last_event_storage.target, "test_resource");
  EXPECT_STREQ(ChangeSink::last_event_storage.preview, "preview text");
  EXPECT_EQ(ChangeSink::last_event_storage.result, CRABS_ERR_UNAUTHORIZED);
  operation_destroy(op);
  state_set_change_hook(state, nullptr, nullptr);
}

// state_notify_change with no hook registered is a no-op (direct call).
TEST_F(TestStateMachine, ChangeNotifyWithoutHookIsNoOp) {
  state_set_change_hook(state, nullptr, nullptr);
  ChangeSink::call_count = 0;
  ChangeSink::has_event = false;
  state_notify_change(state, CRABS_CHANGE_OP, "lock", nullptr, "alice",
                      "alice", "test_resource", "preview", CRABS_SUCCESS);
  EXPECT_EQ(ChangeSink::call_count, 0);
}

// The preview carried by the hook from state_machine_execute is
// "<type> <first resource>" — it must mention both.
TEST_F(TestStateMachine, ChangeHookPreviewCarriesTypeAndTarget) {
  state_set_change_hook(state, ChangeSink::hook, nullptr);
  ChangeSink::call_count = 0;
  ChangeSink::has_event = false;

  operation_t* op = make_lock_op();
  ASSERT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);

  ASSERT_TRUE(ChangeSink::has_event);
  EXPECT_NE(strstr(ChangeSink::last_event_storage.preview, "__lock__"), nullptr);
  EXPECT_NE(strstr(ChangeSink::last_event_storage.preview, "test_resource"), nullptr);
  state_set_change_hook(state, nullptr, nullptr);
}

// ============================================================
// Resource-less custom ops without handlers fail loudly
// ============================================================

static int g_zero_resource_handler_calls = 0;

static crabs_error_e counting_zero_resource_handler(state_t* op_state,
                                                    operation_t* op) {
  (void)op_state;
  (void)op;
  g_zero_resource_handler_calls++;
  return CRABS_SUCCESS;
}

// A DECLARED custom op (a policy authorizes its type) with NO registered
// handler and NO resources used to fall through the dispatch chain as a
// silent CRABS_SUCCESS and was logged as a successful empty operation.
// Declared is not implemented: with no handler and no resources there is no
// wildcard work either, so the op must fail instead of logging a no-op.
TEST_F(TestStateMachine, ResourcelessCustomOpWithoutHandlerFailsLoudly) {
  state_add_policy(state, "audit_ping", "role:admin");

  operation_t* op = operation_create("audit_ping");
  memcpy(op->uuid, test_uuid, CRABS_UUID_SIZE);
  op->resource_count = 0;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  set_signer_key_version(op);
  sign_operation(op);

  uint64_t version_before = state->version;
  uint64_t log_count_before = state->log_count;

  state_set_change_hook(state, ChangeSink::hook, nullptr);
  ChangeSink::call_count = 0;
  ChangeSink::has_event = false;

  crabs_error_e result = state_machine_execute(state, op);
  operation_destroy(op);

  EXPECT_EQ(result, CRABS_ERR_RESOURCE_NOT_FOUND);

  // The failed op is a no-op: no log entry, no version bump.
  EXPECT_EQ(state->version, version_before);
  EXPECT_EQ(state->log_count, log_count_before);

  // The failure still surfaces through the change-hook contract ("failed ops
  // surface result").
  EXPECT_EQ(ChangeSink::call_count, 1);
  ASSERT_TRUE(ChangeSink::has_event);
  EXPECT_EQ(ChangeSink::last_event_storage.result, CRABS_ERR_RESOURCE_NOT_FOUND);
  EXPECT_STREQ(ChangeSink::last_event_storage.type, "audit_ping");
  state_set_change_hook(state, nullptr, nullptr);
}

// Regression guard: the same handler-less op WITH a resource on a LOCKED
// item keeps the legitimate pure-lock workflow — the LOCKED→MODIFIED
// wildcard runs and the op logs as successful.
TEST_F(TestStateMachine, ResourceCarryingCustomOpWithoutHandlerStillAppliesWildcard) {
  state_add_policy(state, "apply_patch", "role:admin");

  // Lock the resource first: the wildcard workflow only acts on LOCKED items.
  operation_t* lock_op = make_lock_op();
  ASSERT_EQ(state_machine_execute(state, lock_op), CRABS_SUCCESS);
  operation_destroy(lock_op);

  operation_t* patch_op = operation_create("apply_patch");
  for (int uuid_byte = 0; uuid_byte < CRABS_UUID_SIZE; uuid_byte++) {
    patch_op->uuid[uuid_byte] = (uint8_t)(uuid_byte + 2);
  }
  patch_op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(patch_op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  patch_op->resource_count = 1;
  patch_op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  patch_op->required_state[0] = PROTOCOL_LOCKED;
  patch_op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  patch_op->next_state[0] = PROTOCOL_MODIFIED;
  strncpy(patch_op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  set_signer_key_version(patch_op);
  sign_operation(patch_op);

  uint64_t log_count_before = state->log_count;
  crabs_error_e result = state_machine_execute(state, patch_op);
  operation_destroy(patch_op);

  EXPECT_EQ(result, CRABS_SUCCESS);
  data_item_t* item = state_find_item(state, "test_resource");
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->protocol_state, PROTOCOL_MODIFIED);
  EXPECT_EQ(state->log_count, log_count_before + 1);
}

// Regression guard (audit A10-L11): the wildcard LOCKED→MODIFIED protocol
// transition for a handler-less custom op must be ATOMIC across resources.
// The original single-pass loop flipped earlier LOCKED resources to MODIFIED
// before hitting a later non-LOCKED resource and returning
// CRABS_ERR_PROTOCOL_VIOLATION — a mutation with no log entry, no version
// bump, and a replayable uuid. The op must validate every resource BEFORE
// mutating any, so a failure leaves all resources untouched.
TEST_F(TestStateMachine, ProtocolTransitionIsAtomicAcrossResources) {
  state_add_policy(state, "apply_patch", "role:admin");

  // Add a second resource that stays IDLE (never locked).
  data_item_t* second_res = data_item_create("second_resource", DATA_TYPE_RESOURCE,
                                             CRDT_PN_COUNTER);
  int64_t* second_val = (int64_t*)malloc(sizeof(int64_t));
  *second_val = 0;
  second_res->value = second_val;
  state_add_item(state, second_res);

  // Lock the first resource: the wildcard workflow only acts on LOCKED items.
  operation_t* lock_op = make_lock_op();
  ASSERT_EQ(state_machine_execute(state, lock_op), CRABS_SUCCESS);
  operation_destroy(lock_op);

  // Multi-resource custom op listing {test_resource (LOCKED),
  // second_resource (IDLE)} — the later resource fails the wildcard.
  operation_t* patch_op = operation_create("apply_patch");
  for (int uuid_byte = 0; uuid_byte < CRABS_UUID_SIZE; uuid_byte++) {
    patch_op->uuid[uuid_byte] = (uint8_t)(uuid_byte + 3);
  }
  patch_op->resources =
      (char(*)[CRABS_MAX_USER_ID])malloc(2 * sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(patch_op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  strncpy(patch_op->resources[1], "second_resource", CRABS_MAX_USER_ID - 1);
  patch_op->resource_count = 2;
  patch_op->required_state =
      (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  patch_op->required_state[0] = PROTOCOL_LOCKED;
  patch_op->required_state[1] = PROTOCOL_IDLE;
  patch_op->next_state = (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  patch_op->next_state[0] = PROTOCOL_MODIFIED;
  patch_op->next_state[1] = PROTOCOL_MODIFIED;
  strncpy(patch_op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  set_signer_key_version(patch_op);
  sign_operation(patch_op);

  uint64_t version_before = state->version;
  uint64_t log_count_before = state->log_count;

  crabs_error_e result = state_machine_execute(state, patch_op);
  operation_destroy(patch_op);

  EXPECT_EQ(result, CRABS_ERR_PROTOCOL_VIOLATION);

  // The failing op must leave NO partial apply: the earlier LOCKED resource
  // is untouched, and there is no log entry or version bump.
  data_item_t* first_item = state_find_item(state, "test_resource");
  ASSERT_NE(first_item, nullptr);
  EXPECT_EQ(first_item->protocol_state, PROTOCOL_LOCKED);
  data_item_t* second_item = state_find_item(state, "second_resource");
  ASSERT_NE(second_item, nullptr);
  EXPECT_EQ(second_item->protocol_state, PROTOCOL_IDLE);
  EXPECT_EQ(state->version, version_before);
  EXPECT_EQ(state->log_count, log_count_before);
}

// Regression guard: a registered-handler custom op with zero resources is a
// real implementation and still succeeds (with its log entry).
TEST_F(TestStateMachine, RegisteredHandlerCustomOpWithZeroResourcesSucceeds) {
  state_add_policy(state, "heartbeat_ping", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "heartbeat_ping",
                                           counting_zero_resource_handler),
            CRABS_SUCCESS);
  g_zero_resource_handler_calls = 0;

  operation_t* op = operation_create("heartbeat_ping");
  memcpy(op->uuid, test_uuid, CRABS_UUID_SIZE);
  op->resource_count = 0;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  set_signer_key_version(op);
  sign_operation(op);

  uint64_t log_count_before = state->log_count;
  crabs_error_e result = state_machine_execute(state, op);
  operation_destroy(op);

  EXPECT_EQ(result, CRABS_SUCCESS);
  EXPECT_EQ(g_zero_resource_handler_calls, 1);
  EXPECT_EQ(state->log_count, log_count_before + 1);
}

// ============================================================
// Write domains v1: DOMAIN_CHECK pipeline step (spec 2026-10-08,
// §Execution pipeline change) and the post-handler sovereign chain
// bookkeeping (item_seq advance + item_digest recompute).
// ============================================================

// Handler that bumps a G_COUNTER item — gives a sovereign op a real content
// mutation so the post-op chain digest actually changes (the digest preimage
// deliberately excludes item_seq, so a no-op op would not move it).
static crabs_error_e sov_bump_handler(state_t* handler_state, operation_t* op) {
  if (op->resource_count == 0) return CRABS_ERR_RESOURCE_NOT_FOUND;
  data_item_t* item = state_find_item(handler_state, op->resources[0]);
  if (item == NULL || item->type != DATA_TYPE_COUNTER) {
    return CRABS_ERR_RESOURCE_NOT_FOUND;
  }
  return g_counter_increment((g_counter_t*)item->value, op->signer_id, 1);
}

// Add a SOVEREIGN G_COUNTER item to the state. Returns the state's item
// pointer (state owns it after state_add_item).
static data_item_t* add_sovereign_counter(state_t* target_state,
                                          const char* name,
                                          const char* writer) {
  data_item_options_t options = {};
  options.write_domain = CRABS_DOMAIN_SOVEREIGN;
  options.writer = writer;
  data_item_t* item = nullptr;
  if (data_item_create_with_options(name, DATA_TYPE_COUNTER, CRDT_G_COUNTER,
                                    &options, &item) != CRABS_SUCCESS) {
    return nullptr;
  }
  item->value = g_counter_create();
  if (state_add_item(target_state, item) != CRABS_SUCCESS) {
    data_item_destroy(item);
    return nullptr;
  }
  return state_find_item(target_state, name);
}

// Build a one-resource custom op of `op_type` touching `resource_name`
// (PROTOCOL_IDLE expectations match a fresh item). uuid is fixed-pattern.
// signer_id defaults to alice (the fixture's sign_operation signs with her
// key); sign_as overwrites it for other signers, and the Mode B test clears
// it explicitly.
static operation_t* make_domain_op(const char* op_type, const char* resource_name,
                                   uint8_t uuid_seed) {
  operation_t* op = operation_create(op_type);
  memset(op->uuid, uuid_seed, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], resource_name, CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_IDLE;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  return op;
}

// Sign `op` with `key` as `signer_id`, stamping the R7-11/R7-04 fields the
// gates require (per-signer monotone lamport, current key_version). Set
// op->sovereign_prefixes before calling: the signed canonical form (v4)
// binds them.
static void sign_as(operation_t* op, attribute_machine_t* signing_am,
                    ecdsa_keypair_t* key, const char* signer_id,
                    uint64_t* signer_lamport) {
  strncpy(op->signer_id, signer_id, CRABS_MAX_USER_ID - 1);
  user_t* signer = attribute_machine_find_user(signing_am, signer_id);
  if (signer != NULL) op->signer_key_version = signer->key_version;
  op->lamport_time = ++(*signer_lamport);
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  if (ser != NULL) {
    crypto_sign_operation(key->private_key, ser->data, ser->len, op->signature);
    serialized_buffer_destroy(ser);
  }
}

// A non-writer's validly-signed op on a SOVEREIGN item is rejected at
// DOMAIN_CHECK with NOT_ITEM_WRITER and changes nothing.
TEST_F(TestStateMachine, DomainCheckSovereignWriterOnly) {
  state_add_policy(state, "sov_bump", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "sov_bump", sov_bump_handler),
            CRABS_SUCCESS);
  data_item_t* item = add_sovereign_counter(state, "sov_counter", "alice");
  ASSERT_NE(item, nullptr);

  ecdsa_keypair_t* bob_key = crypto_ecdsa_generate();
  ASSERT_NE(bob_key, nullptr);
  ASSERT_EQ(crabs_test_register_user_with_role(am, "bob", bob_key->public_key,
                                               "role", "admin"),
            CRABS_SUCCESS);

  operation_t* op = make_domain_op("sov_bump", "sov_counter", 0x31);
  // Correct prefix for a fresh item (seq 0, zero digest) — only the WRITER is
  // wrong, so any rejection must be the attribution check.
  op->sovereign_prefix_count = 1;
  op->sovereign_prefixes[0].item_seq = 0;
  memset(op->sovereign_prefixes[0].prev_item_digest, 0, CRABS_HASH_SIZE);
  uint64_t bob_lamport = 0;
  sign_as(op, am, bob_key, "bob", &bob_lamport);

  uint64_t version_before = state->version;
  uint64_t log_count_before = state->log_count;
  EXPECT_EQ(state_machine_validate(state, op), CRABS_ERR_NOT_ITEM_WRITER);
  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_NOT_ITEM_WRITER);
  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(bob_key);

  EXPECT_EQ(state->version, version_before);
  EXPECT_EQ(state->log_count, log_count_before);
  EXPECT_EQ(item->item_seq, (uint64_t)0);
}

// The prefix's item_seq must equal the item's current seq: ahead-of-current
// is rejected; current is accepted and the post-op bookkeeping advances the
// chain (seq + 1, digest recomputed over the post-op serialized form).
TEST_F(TestStateMachine, DomainCheckSeqMustBeCurrent) {
  state_add_policy(state, "sov_bump", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "sov_bump", sov_bump_handler),
            CRABS_SUCCESS);
  data_item_t* item = add_sovereign_counter(state, "sov_counter", "alice");
  ASSERT_NE(item, nullptr);

  // Stale/ahead seq: item_seq 1 while the item is at 0.
  operation_t* ahead_op = make_domain_op("sov_bump", "sov_counter", 0x32);
  ahead_op->sovereign_prefix_count = 1;
  ahead_op->sovereign_prefixes[0].item_seq = 1;
  memset(ahead_op->sovereign_prefixes[0].prev_item_digest, 0, CRABS_HASH_SIZE);
  set_signer_key_version(ahead_op);
  sign_operation(ahead_op);
  EXPECT_EQ(state_machine_execute(state, ahead_op), CRABS_ERR_SEQ_MISMATCH);
  operation_destroy(ahead_op);
  EXPECT_EQ(item->item_seq, (uint64_t)0);

  // Current seq accepted; bookkeeping advances the chain.
  uint8_t old_digest[CRABS_HASH_SIZE];
  memcpy(old_digest, item->item_digest, CRABS_HASH_SIZE);
  operation_t* good_op = make_domain_op("sov_bump", "sov_counter", 0x33);
  good_op->sovereign_prefix_count = 1;
  good_op->sovereign_prefixes[0].item_seq = 0;
  memset(good_op->sovereign_prefixes[0].prev_item_digest, 0, CRABS_HASH_SIZE);
  set_signer_key_version(good_op);
  sign_operation(good_op);
  EXPECT_EQ(state_machine_validate(state, good_op), CRABS_SUCCESS);
  EXPECT_EQ(state_machine_execute(state, good_op), CRABS_SUCCESS);
  operation_destroy(good_op);

  EXPECT_EQ(item->item_seq, (uint64_t)1);
  EXPECT_NE(memcmp(item->item_digest, old_digest, CRABS_HASH_SIZE), 0);
  uint8_t recomputed[CRABS_HASH_SIZE];
  ASSERT_EQ(state_item_digest_compute(item, recomputed), CRABS_SUCCESS);
  EXPECT_EQ(memcmp(item->item_digest, recomputed, CRABS_HASH_SIZE), 0);

  // Replaying the accepted prefix is stale now (seq moved): SEQ_MISMATCH.
  operation_t* replay_op = make_domain_op("sov_bump", "sov_counter", 0x34);
  replay_op->sovereign_prefix_count = 1;
  replay_op->sovereign_prefixes[0].item_seq = 0;
  memset(replay_op->sovereign_prefixes[0].prev_item_digest, 0, CRABS_HASH_SIZE);
  set_signer_key_version(replay_op);
  sign_operation(replay_op);
  EXPECT_EQ(state_machine_execute(state, replay_op), CRABS_ERR_SEQ_MISMATCH);
  operation_destroy(replay_op);
  EXPECT_EQ(item->item_seq, (uint64_t)1);
}

// Same seq, wrong digest: the writer equivocated. FORK_DETECTED, and nothing
// is applied (no log entry, no version bump, chain untouched). The report
// path that would quarantine this writer is Task 6; here we only detect.
TEST_F(TestStateMachine, DomainCheckDigestMismatchForks) {
  state_add_policy(state, "sov_bump", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "sov_bump", sov_bump_handler),
            CRABS_SUCCESS);
  data_item_t* item = add_sovereign_counter(state, "sov_counter", "alice");
  ASSERT_NE(item, nullptr);

  operation_t* good_op = make_domain_op("sov_bump", "sov_counter", 0x35);
  good_op->sovereign_prefix_count = 1;
  good_op->sovereign_prefixes[0].item_seq = 0;
  memset(good_op->sovereign_prefixes[0].prev_item_digest, 0, CRABS_HASH_SIZE);
  set_signer_key_version(good_op);
  sign_operation(good_op);
  ASSERT_EQ(state_machine_execute(state, good_op), CRABS_SUCCESS);
  operation_destroy(good_op);
  ASSERT_EQ(item->item_seq, (uint64_t)1);

  uint64_t version_before = state->version;
  uint64_t log_count_before = state->log_count;
  uint8_t chain_digest[CRABS_HASH_SIZE];
  memcpy(chain_digest, item->item_digest, CRABS_HASH_SIZE);

  operation_t* fork_op = make_domain_op("sov_bump", "sov_counter", 0x36);
  fork_op->sovereign_prefix_count = 1;
  fork_op->sovereign_prefixes[0].item_seq = 1;  // current seq passes...
  memset(fork_op->sovereign_prefixes[0].prev_item_digest, 0xFF,
         CRABS_HASH_SIZE);                       // ...but the digest lies
  set_signer_key_version(fork_op);
  sign_operation(fork_op);
  EXPECT_EQ(state_machine_validate(state, fork_op), CRABS_ERR_FORK_DETECTED);
  EXPECT_EQ(state_machine_execute(state, fork_op), CRABS_ERR_FORK_DETECTED);
  operation_destroy(fork_op);

  EXPECT_EQ(state->version, version_before);
  EXPECT_EQ(state->log_count, log_count_before);
  EXPECT_EQ(item->item_seq, (uint64_t)1);
  EXPECT_EQ(memcmp(item->item_digest, chain_digest, CRABS_HASH_SIZE), 0);
}

// The prefix slots are indexed per SOVEREIGN resource in resource order —
// the count must match exactly. Too few, too many, or prefixes on an op
// whose resources are all FREE_MERGE are fail-closed SEQ_MISMATCH.
TEST_F(TestStateMachine, DomainCheckPrefixCountMustMatchSovereignResources) {
  state_add_policy(state, "sov_bump", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "sov_bump", sov_bump_handler),
            CRABS_SUCCESS);
  data_item_t* item = add_sovereign_counter(state, "sov_counter", "alice");
  ASSERT_NE(item, nullptr);

  // Missing prefix for the one sovereign resource.
  operation_t* missing_op = make_domain_op("sov_bump", "sov_counter", 0x37);
  set_signer_key_version(missing_op);
  sign_operation(missing_op);
  EXPECT_EQ(state_machine_execute(state, missing_op),
            CRABS_ERR_SEQ_MISMATCH);
  operation_destroy(missing_op);

  // Extra prefix beyond the sovereign resources present.
  operation_t* extra_op = make_domain_op("sov_bump", "sov_counter", 0x38);
  extra_op->sovereign_prefix_count = 2;
  extra_op->sovereign_prefixes[0].item_seq = 0;
  extra_op->sovereign_prefixes[1].item_seq = 0;
  set_signer_key_version(extra_op);
  sign_operation(extra_op);
  EXPECT_EQ(state_machine_execute(state, extra_op), CRABS_ERR_SEQ_MISMATCH);
  operation_destroy(extra_op);

  // Prefixes on an all-FREE_MERGE op: no slot to assign them to.
  data_item_t* free_item =
      data_item_create("free_counter", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  free_item->value = g_counter_create();
  ASSERT_EQ(state_add_item(state, free_item), CRABS_SUCCESS);
  operation_t* free_op = make_domain_op("sov_bump", "free_counter", 0x39);
  free_op->sovereign_prefix_count = 1;
  free_op->sovereign_prefixes[0].item_seq = 0;
  set_signer_key_version(free_op);
  sign_operation(free_op);
  EXPECT_EQ(state_machine_execute(state, free_op), CRABS_ERR_SEQ_MISMATCH);
  operation_destroy(free_op);

  EXPECT_EQ(item->item_seq, (uint64_t)0);
}

// A quarantined writer's VALID-signature op is rejected QUARANTINED. The op
// is authentically signed (authorization passes first — the rejection is the
// domain step, not the crypto), and the deliberately wrong seq pins the
// check order: quarantine is examined before the chain prefix.
TEST_F(TestStateMachine, DomainCheckQuarantinedWriterRejected) {
  state_add_policy(state, "sov_bump", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "sov_bump", sov_bump_handler),
            CRABS_SUCCESS);
  data_item_t* item = add_sovereign_counter(state, "sov_counter", "alice");
  ASSERT_NE(item, nullptr);

  uint8_t evidence[CRABS_HASH_SIZE];
  memset(evidence, 0x5A, CRABS_HASH_SIZE);
  ASSERT_EQ(state_append_fork_evidence(item, "alice", evidence), CRABS_SUCCESS);
  ASSERT_TRUE(state_item_is_quarantined(item, "alice"));

  operation_t* op = make_domain_op("sov_bump", "sov_counter", 0x3A);
  op->sovereign_prefix_count = 1;
  op->sovereign_prefixes[0].item_seq = 7;  // wrong on purpose
  memset(op->sovereign_prefixes[0].prev_item_digest, 0, CRABS_HASH_SIZE);
  set_signer_key_version(op);
  sign_operation(op);
  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_QUARANTINED);
  operation_destroy(op);

  EXPECT_EQ(item->item_seq, (uint64_t)0);
}

// FREE_MERGE items (the default) are untouched by the new step: an
// authorized op with no prefixes succeeds exactly as before and no chain
// fields move.
TEST_F(TestStateMachine, DomainCheckFreeMergeUnchanged) {
  state_add_policy(state, "sov_bump", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "sov_bump", sov_bump_handler),
            CRABS_SUCCESS);
  data_item_t* free_item =
      data_item_create("free_counter", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  free_item->value = g_counter_create();
  ASSERT_EQ(state_add_item(state, free_item), CRABS_SUCCESS);

  operation_t* op = make_domain_op("sov_bump", "free_counter", 0x3B);
  set_signer_key_version(op);
  sign_operation(op);
  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);

  data_item_t* item = state_find_item(state, "free_counter");
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->write_domain, CRABS_DOMAIN_FREE_MERGE);
  EXPECT_EQ(item->item_seq, (uint64_t)0);
  uint8_t zero_digest[CRABS_HASH_SIZE];
  memset(zero_digest, 0, CRABS_HASH_SIZE);
  EXPECT_EQ(memcmp(item->item_digest, zero_digest, CRABS_HASH_SIZE), 0);
}

// v1 seam: GROUP_ORDERED items exist but no ordering module can be
// registered, so every direct write is off-path (fail closed).
TEST_F(TestStateMachine, DomainCheckGroupOrderedV1ReadOnly) {
  state_add_policy(state, "sov_bump", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "sov_bump", sov_bump_handler),
            CRABS_SUCCESS);
  data_item_options_t options = {};
  options.write_domain = CRABS_DOMAIN_GROUP_ORDERED;
  data_item_t* group_item = nullptr;
  ASSERT_EQ(data_item_create_with_options("group_counter", DATA_TYPE_COUNTER,
                                          CRDT_G_COUNTER, &options, &group_item),
            CRABS_SUCCESS);
  group_item->value = g_counter_create();
  ASSERT_EQ(state_add_item(state, group_item), CRABS_SUCCESS);

  operation_t* op = make_domain_op("sov_bump", "group_counter", 0x3C);
  set_signer_key_version(op);
  sign_operation(op);
  EXPECT_EQ(state_machine_validate(state, op), CRABS_ERR_ORDERING_PATH);
  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_ORDERING_PATH);
  operation_destroy(op);
}

// Mode B (signer omitted, resolved via the keyring) is incompatible with the
// sovereignty check by definition: the writer must be attributable, so an
// anonymous op touching a SOVEREIGN item is NOT_ITEM_WRITER even when the
// key IS the writer's.
TEST_F(TestStateMachine, DomainCheckModeBSovereignRejected) {
  state_add_policy(state, "sov_bump", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "sov_bump", sov_bump_handler),
            CRABS_SUCCESS);
  data_item_t* item = add_sovereign_counter(state, "sov_counter", "alice");
  ASSERT_NE(item, nullptr);

  operation_t* op = make_domain_op("sov_bump", "sov_counter", 0x3D);
  op->sovereign_prefix_count = 1;
  op->sovereign_prefixes[0].item_seq = 0;
  memset(op->sovereign_prefixes[0].prev_item_digest, 0, CRABS_HASH_SIZE);
  // Anonymous: signer_id left empty; signed with alice's key so the keyring
  // resolves the signer (Mode B) — still rejected at the domain step.
  op->signer_id[0] = '\0';
  user_t* signer = attribute_machine_find_user(am, "alice");
  if (signer != NULL) op->signer_key_version = signer->key_version;
  op->lamport_time = ++lamport_counter;
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  ASSERT_NE(ser, nullptr);
  crypto_sign_operation(alice_key->private_key, ser->data, ser->len,
                        op->signature);
  serialized_buffer_destroy(ser);

  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_NOT_ITEM_WRITER);
  operation_destroy(op);
  EXPECT_EQ(item->item_seq, (uint64_t)0);
}

// ============================================================
// Write domains v1: __report_equivocation__ op (Task 6, spec
// 2026-10-08 §Equivocation detection and quarantine) and the carried
// dedup-mutation-target rule for sovereign bookkeeping.
// ============================================================
// Fork-fact definition (as implemented; spec doc amended in Task 8): two
// DISTINCT serialized ops from the same writer, both naming the same
// SOVEREIGN item with the same item_seq AND the same prev_item_digest in
// their signed prefixes — two signed claims to be the one continuation of
// the same chain head at the same sequence number. Both signatures must
// verify under the writer's CURRENT keys (evidence minted under the
// current key era; rotated-away-key eras are out of v1 scope).

// Payload wire layout for __report_equivocation__ (v1):
//   u8      format version (0x01)
//   string16 item_name    (u16le length + bytes)
//   string16 writer_id    (u16le length + bytes)
//   bytes32  op_a         (u32le length + serialized op bytes)
//   bytes32  op_b         (u32le length + serialized op bytes)
// Full consumption required.
static uint8_t* build_report_payload(const char* item_name, const char* writer,
                                     const uint8_t* op_a_bytes, uint32_t op_a_len,
                                     const uint8_t* op_b_bytes, uint32_t op_b_len,
                                     uint32_t* out_len) {
  uint32_t item_len = (uint32_t)strlen(item_name);
  uint32_t writer_len = (uint32_t)strlen(writer);
  *out_len = 1u + 2u + item_len + 2u + writer_len + 4u + op_a_len + 4u + op_b_len;
  uint8_t* payload = (uint8_t*)malloc(*out_len);
  if (payload == nullptr) return nullptr;
  uint32_t offset = 0;
  payload[offset++] = 0x01;
  payload[offset++] = (uint8_t)(item_len & 0xFF);
  payload[offset++] = (uint8_t)((item_len >> 8) & 0xFF);
  memcpy(payload + offset, item_name, item_len); offset += item_len;
  payload[offset++] = (uint8_t)(writer_len & 0xFF);
  payload[offset++] = (uint8_t)((writer_len >> 8) & 0xFF);
  memcpy(payload + offset, writer, writer_len); offset += writer_len;
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    payload[offset++] = (uint8_t)((op_a_len >> (8 * byte_index)) & 0xFF);
  }
  memcpy(payload + offset, op_a_bytes, op_a_len); offset += op_a_len;
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    payload[offset++] = (uint8_t)((op_b_len >> (8 * byte_index)) & 0xFF);
  }
  memcpy(payload + offset, op_b_bytes, op_b_len); offset += op_b_len;
  EXPECT_EQ(offset, *out_len);
  return payload;
}

// Build a sovereign op SIGNED AS ALICE with `signing_key` (stamped by
// sign_as) on `resource_name` claiming (seq, prev_digest all zero), and hand
// back its WIRE bytes — the (T'-style) evidence candidate. The in-memory op
// is destroyed; only the serialized form survives.
static void make_serialized_sovereign_op(attribute_machine_t* signing_am,
                                         ecdsa_keypair_t* signing_key,
                                         uint64_t* signing_lamport,
                                         const char* op_type,
                                         const char* resource_name,
                                         uint8_t uuid_seed, uint64_t seq,
                                         uint8_t** out_bytes,
                                         uint32_t* out_len) {
  operation_t* op = make_domain_op(op_type, resource_name, uuid_seed);
  op->sovereign_prefix_count = 1;
  op->sovereign_prefixes[0].item_seq = seq;
  memset(op->sovereign_prefixes[0].prev_item_digest, 0, CRABS_HASH_SIZE);
  sign_as(op, signing_am, signing_key, "alice", signing_lamport);
  serialized_buffer_t* serialized = crabs_serialize_operation(op);
  ASSERT_NE(serialized, nullptr);
  *out_len = (uint32_t)serialized->len;
  *out_bytes = (uint8_t*)malloc(*out_len);
  ASSERT_NE(*out_bytes, nullptr);
  memcpy(*out_bytes, serialized->data, *out_len);
  serialized_buffer_destroy(serialized);
  operation_destroy(op);
}

// Assemble a __report_equivocation__ op carrying the given evidence bytes;
// the reporter's signer_id is set but signing is the caller's job (sign_as
// with the reporter's key + lamport state).
static operation_t* make_report_op(const char* item_name,
                                   const char* writer_id,
                                   const char* reporter_id,
                                   const uint8_t* op_a_bytes, uint32_t op_a_len,
                                   const uint8_t* op_b_bytes, uint32_t op_b_len,
                                   uint8_t uuid_seed) {
  operation_t* op = operation_create(CRABS_OP_REPORT_EQUIVOCATION);
  memset(op->uuid, uuid_seed, CRABS_UUID_SIZE);
  op->payload = build_report_payload(item_name, writer_id,
                                     op_a_bytes, op_a_len,
                                     op_b_bytes, op_b_len,
                                     &op->payload_size);
  EXPECT_NE(op->payload, nullptr);
  strncpy(op->signer_id, reporter_id, CRABS_MAX_USER_ID - 1);
  return op;
}

// A genuine fork: alice signed two DISTINCT ops claiming the same (item,
// seq 0, zero prev-digest) continuation. The first executed (chain now at
// seq 1); the sibling never did. A reporter submits both as evidence; the
// handler convicts and quarantines alice on the item.
TEST_F(TestStateMachine, ReportEquivocationGenuineForkQuarantines) {
  state_add_policy(state, "sov_bump", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "sov_bump", sov_bump_handler),
            CRABS_SUCCESS);
  state_add_policy(state, CRABS_OP_REPORT_EQUIVOCATION, "role:admin");
  data_item_t* item = add_sovereign_counter(state, "sov_counter", "alice");
  ASSERT_NE(item, nullptr);

  const char* reporter_user = "bob";
  uint64_t reporter_lamport = 0;
  ecdsa_keypair_t* reporter_key = crypto_ecdsa_generate();
  ASSERT_NE(reporter_key, nullptr);
  ASSERT_EQ(crabs_test_register_user_with_role(am, reporter_user,
                                               reporter_key->public_key,
                                               "role", "admin"),
            CRABS_SUCCESS);

  // op_a: signed, and accepted — the honest chain head advance.
  uint8_t* op_a_bytes = nullptr; uint32_t op_a_len = 0;
  ASSERT_NO_FATAL_FAILURE(make_serialized_sovereign_op(
      am, alice_key, &lamport_counter, "sov_bump", "sov_counter", 0x41, 0, &op_a_bytes, &op_a_len));
  operation_t* op_a = crabs_deserialize_operation(op_a_bytes, op_a_len);
  ASSERT_NE(op_a, nullptr);
  ASSERT_EQ(state_machine_execute(state, op_a), CRABS_SUCCESS);
  operation_destroy(op_a);
  ASSERT_EQ(item->item_seq, (uint64_t)1);

  // op_b: the sibling fork op — same seq (0), same zero prev digest, signed
  // by alice after op_a (lamport advanced), never executed here.
  uint8_t* op_b_bytes = nullptr; uint32_t op_b_len = 0;
  ASSERT_NO_FATAL_FAILURE(make_serialized_sovereign_op(
      am, alice_key, &lamport_counter, "sov_bump", "sov_counter", 0x42, 0, &op_b_bytes, &op_b_len));
  ASSERT_NE(op_a_len == op_b_len &&
            memcmp(op_a_bytes, op_b_bytes, op_a_len) == 0, true);

  uint64_t version_before = state->version;
  operation_t* report = make_report_op("sov_counter", "alice", reporter_user,
                                                      op_a_bytes, op_a_len,
                                       op_b_bytes, op_b_len, 0x51);
  sign_as(report, am, reporter_key, reporter_user, &reporter_lamport);
  EXPECT_EQ(state_machine_execute(state, report), CRABS_SUCCESS);
  operation_destroy(report);

  EXPECT_EQ(item->fork_count, 1u);
  EXPECT_TRUE(state_item_is_quarantined(item, "alice"));
  EXPECT_GT(state->version, version_before);

  // The quarantined writer's later op on the item is rejected (Task 5
  // interplay), while the reporter — report ≠ quarantine — can still act:
  // a duplicate re-report reaches the handler and is deduped, not
  // QUARANTINED-rejected.
  operation_t* writer_op = make_domain_op("sov_bump", "sov_counter", 0x43);
  writer_op->sovereign_prefix_count = 1;
  writer_op->sovereign_prefixes[0].item_seq = 1;
  {
    uint8_t digest_copy[CRABS_HASH_SIZE];
    memcpy(digest_copy, item->item_digest, CRABS_HASH_SIZE);
    memcpy(writer_op->sovereign_prefixes[0].prev_item_digest, digest_copy,
           CRABS_HASH_SIZE);
  }
  set_signer_key_version(writer_op);
  sign_operation(writer_op);
  EXPECT_EQ(state_machine_execute(state, writer_op), CRABS_ERR_QUARANTINED);
  operation_destroy(writer_op);

  operation_t* duplicate_report = make_report_op("sov_counter", "alice", reporter_user,
                                                                op_b_bytes, op_b_len,
                                                 op_a_bytes, op_a_len, 0x52);
  sign_as(duplicate_report, am, reporter_key, reporter_user, &reporter_lamport);
  EXPECT_EQ(state_machine_execute(state, duplicate_report),
            CRABS_ERR_DUPLICATE_OPERATION);
  operation_destroy(duplicate_report);
  EXPECT_EQ(item->fork_count, 1u);

  free(op_a_bytes);
  free(op_b_bytes);
  crypto_ecdsa_keypair_destroy(reporter_key);
}

// False evidence must never set the flag: broken signature, mismatched seq,
// mismatched prev digest, and same-op-twice are all rejected with no state
// change.
TEST_F(TestStateMachine, ReportEquivocationFalseEvidenceRejected) {
  state_add_policy(state, "sov_bump", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "sov_bump", sov_bump_handler),
            CRABS_SUCCESS);
  state_add_policy(state, CRABS_OP_REPORT_EQUIVOCATION, "role:admin");
  data_item_t* item = add_sovereign_counter(state, "sov_counter", "alice");
  ASSERT_NE(item, nullptr);

  const char* reporter_user = "bob";
  uint64_t reporter_lamport = 0;
  ecdsa_keypair_t* reporter_key = crypto_ecdsa_generate();
  ASSERT_NE(reporter_key, nullptr);
  ASSERT_EQ(crabs_test_register_user_with_role(am, reporter_user,
                                               reporter_key->public_key,
                                               "role", "admin"),
            CRABS_SUCCESS);

  uint8_t* op_a_bytes = nullptr; uint32_t op_a_len = 0;
  ASSERT_NO_FATAL_FAILURE(make_serialized_sovereign_op(
      am, alice_key, &lamport_counter, "sov_bump", "sov_counter", 0x44, 0, &op_a_bytes, &op_a_len));
  uint8_t* op_b_bytes = nullptr; uint32_t op_b_len = 0;
  ASSERT_NO_FATAL_FAILURE(make_serialized_sovereign_op(
      am, alice_key, &lamport_counter, "sov_bump", "sov_counter", 0x45, 0, &op_b_bytes, &op_b_len));

  // (a) op_b with a broken signature → UNAUTHORIZED, flag not set.
  {
    operation_t* broken = crabs_deserialize_operation(op_b_bytes, op_b_len);
    ASSERT_NE(broken, nullptr);
    broken->signature[0] ^= 0xFF;
    serialized_buffer_t* broken_ser = crabs_serialize_operation(broken);
    operation_destroy(broken);
    ASSERT_NE(broken_ser, nullptr);
    uint64_t version_before = state->version;
    operation_t* report = make_report_op("sov_counter", "alice", reporter_user,
                                                        op_a_bytes, op_a_len,
                                         (const uint8_t*)broken_ser->data,
                                         (uint32_t)broken_ser->len, 0x53);
    sign_as(report, am, reporter_key, reporter_user, &reporter_lamport);
    EXPECT_EQ(state_machine_execute(state, report), CRABS_ERR_UNAUTHORIZED);
    operation_destroy(report);
    serialized_buffer_destroy(broken_ser);
    EXPECT_EQ(item->fork_count, 0u);
    EXPECT_EQ(state->version, version_before);
  }

  // (b) seq differs between the two ops → not a fork claim about one slot.
  {
    uint8_t* op_c_bytes = nullptr; uint32_t op_c_len = 0;
    ASSERT_NO_FATAL_FAILURE(make_serialized_sovereign_op(
        am, alice_key, &lamport_counter,
        "sov_bump", "sov_counter", 0x46, 1, &op_c_bytes, &op_c_len));
    uint64_t version_before = state->version;
    operation_t* report = make_report_op("sov_counter", "alice", reporter_user,
                                                        op_a_bytes, op_a_len,
                                         op_c_bytes, op_c_len, 0x54);
    sign_as(report, am, reporter_key, reporter_user, &reporter_lamport);
    EXPECT_EQ(state_machine_execute(state, report), CRABS_ERR_INVALID_PARAM);
    operation_destroy(report);
    EXPECT_EQ(item->fork_count, 0u);
    EXPECT_EQ(state->version, version_before);
    free(op_c_bytes);
  }

  // (c) prev digest differs: the two ops do not claim the same chain head.
  {
    operation_t* divergent = make_domain_op("sov_bump", "sov_counter", 0x47);
    divergent->sovereign_prefix_count = 1;
    divergent->sovereign_prefixes[0].item_seq = 0;
    memset(divergent->sovereign_prefixes[0].prev_item_digest, 0x11,
           CRABS_HASH_SIZE);
    set_signer_key_version(divergent);
    sign_operation(divergent);
    serialized_buffer_t* divergent_ser = crabs_serialize_operation(divergent);
    operation_destroy(divergent);
    ASSERT_NE(divergent_ser, nullptr);
    uint64_t version_before = state->version;
    operation_t* report = make_report_op("sov_counter", "alice", reporter_user,
                                                        op_a_bytes, op_a_len,
                                         (const uint8_t*)divergent_ser->data,
                                         (uint32_t)divergent_ser->len, 0x55);
    sign_as(report, am, reporter_key, reporter_user, &reporter_lamport);
    EXPECT_EQ(state_machine_execute(state, report), CRABS_ERR_INVALID_PARAM);
    operation_destroy(report);
    serialized_buffer_destroy(divergent_ser);
    EXPECT_EQ(item->fork_count, 0u);
    EXPECT_EQ(state->version, version_before);
  }

  // (d) the same op twice is one claim, not a fork.
  {
    uint64_t version_before = state->version;
    operation_t* report = make_report_op("sov_counter", "alice", reporter_user,
                                                        op_a_bytes, op_a_len,
                                         op_a_bytes, op_a_len, 0x56);
    sign_as(report, am, reporter_key, reporter_user, &reporter_lamport);
    EXPECT_EQ(state_machine_execute(state, report), CRABS_ERR_INVALID_PARAM);
    operation_destroy(report);
    EXPECT_EQ(item->fork_count, 0u);
    EXPECT_EQ(state->version, version_before);
  }

  free(op_a_bytes);
  free(op_b_bytes);
  crypto_ecdsa_keypair_destroy(reporter_key);
}

// The report target must be an existing SOVEREIGN item owned by the named
// writer; FREE_MERGE targets and missing items reject without setting flags.
TEST_F(TestStateMachine, ReportEquivocationTargetGuards) {
  state_add_policy(state, "sov_bump", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "sov_bump", sov_bump_handler),
            CRABS_SUCCESS);
  state_add_policy(state, CRABS_OP_REPORT_EQUIVOCATION, "role:admin");
  data_item_t* free_item =
      data_item_create("free_counter", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  free_item->value = g_counter_create();
  ASSERT_EQ(state_add_item(state, free_item), CRABS_SUCCESS);
  data_item_t* item = add_sovereign_counter(state, "sov_counter", "alice");
  ASSERT_NE(item, nullptr);

  const char* reporter_user = "bob";
  uint64_t reporter_lamport = 0;
  ecdsa_keypair_t* reporter_key = crypto_ecdsa_generate();
  ASSERT_NE(reporter_key, nullptr);
  ASSERT_EQ(crabs_test_register_user_with_role(am, reporter_user,
                                               reporter_key->public_key,
                                               "role", "admin"),
            CRABS_SUCCESS);

  uint8_t* op_a_bytes = nullptr; uint32_t op_a_len = 0;
  ASSERT_NO_FATAL_FAILURE(make_serialized_sovereign_op(
      am, alice_key, &lamport_counter, "sov_bump", "sov_counter", 0x48, 0, &op_a_bytes, &op_a_len));
  uint8_t* op_b_bytes = nullptr; uint32_t op_b_len = 0;
  ASSERT_NO_FATAL_FAILURE(make_serialized_sovereign_op(
      am, alice_key, &lamport_counter, "sov_bump", "sov_counter", 0x49, 0, &op_b_bytes, &op_b_len));

  // FREE_MERGE target: INVALID_PARAM.
  operation_t* free_target = make_report_op("free_counter", "alice", reporter_user,
                                                           op_a_bytes, op_a_len,
                                            op_b_bytes, op_b_len, 0x57);
  sign_as(free_target, am, reporter_key, reporter_user, &reporter_lamport);
  EXPECT_EQ(state_machine_execute(state, free_target), CRABS_ERR_INVALID_PARAM);
  operation_destroy(free_target);

  // Missing item: RESOURCE_NOT_FOUND.
  operation_t* missing_target = make_report_op("no_such_item", "alice", reporter_user,
                                                              op_a_bytes, op_a_len,
                                               op_b_bytes, op_b_len, 0x58);
  sign_as(missing_target, am, reporter_key, reporter_user, &reporter_lamport);
  EXPECT_EQ(state_machine_execute(state, missing_target),
            CRABS_ERR_RESOURCE_NOT_FOUND);
  operation_destroy(missing_target);

  // Payload writer ≠ item writer: INVALID_PARAM.
  operation_t* wrong_writer = make_report_op("sov_counter", "bob", reporter_user,
                                                            op_a_bytes, op_a_len,
                                             op_b_bytes, op_b_len, 0x59);
  sign_as(wrong_writer, am, reporter_key, reporter_user, &reporter_lamport);
  EXPECT_EQ(state_machine_execute(state, wrong_writer), CRABS_ERR_INVALID_PARAM);
  operation_destroy(wrong_writer);

  EXPECT_EQ(item->fork_count, 0u);
  free(op_a_bytes);
  free(op_b_bytes);
  crypto_ecdsa_keypair_destroy(reporter_key);
}

// The report op type is builtin + protected: not re-definable via
// __define_operation_type__ (the A10-M1 guard covers it).
TEST_F(TestStateMachine, ReportEquivocationIsBuiltinAndProtected) {
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_REPORT_EQUIVOCATION));
  EXPECT_TRUE(operation_is_protected(CRABS_OP_REPORT_EQUIVOCATION));

  // Direct handler invocation, mirroring the lineage protected-guard
  // regression test (the handler's protected check precedes any spec work).
  operation_t* define = operation_create(CRABS_OP_DEFINE_OPERATION);
  memset(define->uuid, 0x5A, CRABS_UUID_SIZE);
  define->resources = (char(*)[CRABS_MAX_USER_ID])malloc(CRABS_MAX_USER_ID);
  strncpy(define->resources[0], CRABS_OP_REPORT_EQUIVOCATION,
          CRABS_MAX_USER_ID - 1);
  define->resource_count = 1;
  define->dedup.type = DEDUP_PER_USER;
  strncpy(define->dedup.tracker_path, "voters", CRABS_MAX_DEDUP_PATH - 1);
  EXPECT_EQ(state_machine_op_define_operation(state, define),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state_find_op_type_def(state, CRABS_OP_REPORT_EQUIVOCATION),
            nullptr);
  operation_destroy(define);
}

// Carried Task-5 gap: a dedup mutation targeting a SOVEREIGN item that is
// NOT among op->resources would mutate the item without advancing its hash
// chain (stale digest vs content). v1 rule: DOMAIN_CHECK requires every
// non-FREE_MERGE dedup mutation target to be a named resource (so its
// prefix is carried and verified); otherwise the op is SEQ_MISMATCH. When
// the target IS a resource, the post-handler bookkeeping recomputes the
// digest over the post-MUTATION state.
TEST_F(TestStateMachine, DedupMutationSovereignTargetMustBeResource) {
  state_add_policy(state, "vote_bump", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "vote_bump",
                                           sov_bump_handler),
            CRABS_SUCCESS);
  data_item_t* item = add_sovereign_counter(state, "sov_counter", "alice");
  ASSERT_NE(item, nullptr);

  // Register a dedup spec on "vote_bump" whose mutation increments the
  // sovereign counter — the target chain the op's claims must cover.
  dedup_spec_t spec;
  memset(&spec, 0, sizeof(spec));
  spec.type = DEDUP_CUSTOM;
  strncpy(spec.condition, "free_counter >= 0", CRABS_MAX_POLICY_EXPR - 1);
  spec.update.type = MUTATION_COUNTER_INCREMENT;
  strncpy(spec.update.counter_path, "sov_counter", CRABS_MAX_DEDUP_PATH - 1);
  spec.update.delta = 1;
  ASSERT_EQ(state_register_op_type_def(state, "vote_bump", &spec),
            CRABS_SUCCESS);

  // The handler requires resources[0] to exist; use a separate free-merge
  // item as the handler's target so the op can run WITHOUT naming the
  // sovereign counter at all.
  data_item_t* free_item =
      data_item_create("free_counter", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  free_item->value = g_counter_create();
  ASSERT_EQ(state_add_item(state, free_item), CRABS_SUCCESS);

  // (1) Target NOT in resources: the mutation would advance the counter
  // without a chain step. Fail closed.
  operation_t* uncovered = make_domain_op("vote_bump", "free_counter", 0x61);
  set_signer_key_version(uncovered);
  sign_operation(uncovered);
  EXPECT_EQ(state_machine_validate(state, uncovered), CRABS_ERR_SEQ_MISMATCH);
  EXPECT_EQ(state_machine_execute(state, uncovered), CRABS_ERR_SEQ_MISMATCH);
  operation_destroy(uncovered);
  EXPECT_EQ(g_counter_value((g_counter_t*)item->value), 0);
  EXPECT_EQ(item->item_seq, (uint64_t)0);

  // (2) Target IS in resources with a correct prefix: accepted, and the
  // chain bookkeeping covers the dedup mutation (digest recomputed over
  // the post-increment state).
  operation_t* covered = operation_create("vote_bump");
  memset(covered->uuid, 0x62, CRABS_UUID_SIZE);
  covered->resources =
      (char(*)[CRABS_MAX_USER_ID])malloc(2 * sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(covered->resources[0], "free_counter", CRABS_MAX_USER_ID - 1);
  strncpy(covered->resources[1], "sov_counter", CRABS_MAX_USER_ID - 1);
  covered->resource_count = 2;
  covered->required_state =
      (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  covered->next_state = (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  covered->required_state[0] = PROTOCOL_IDLE;
  covered->next_state[0] = PROTOCOL_IDLE;
  covered->required_state[1] = PROTOCOL_IDLE;
  covered->next_state[1] = PROTOCOL_IDLE;
  covered->sovereign_prefix_count = 1;
  covered->sovereign_prefixes[0].item_seq = 0;
  memset(covered->sovereign_prefixes[0].prev_item_digest, 0, CRABS_HASH_SIZE);
  covered->dedup = spec;  // op-carried value is ignored; the registered spec wins
  strncpy(covered->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  set_signer_key_version(covered);
  sign_operation(covered);
  EXPECT_EQ(state_machine_execute(state, covered), CRABS_SUCCESS);
  operation_destroy(covered);

  // The handler bumped free_counter once; the dedup mutation bumped the
  // sovereign counter once; the chain advanced exactly once and the stored
  // digest matches the item's current content.
  EXPECT_EQ(g_counter_value((g_counter_t*)item->value), 1);
  EXPECT_EQ(item->item_seq, (uint64_t)1);
  uint8_t recomputed[CRABS_HASH_SIZE];
  ASSERT_EQ(state_item_digest_compute(item, recomputed), CRABS_SUCCESS);
  EXPECT_EQ(memcmp(item->item_digest, recomputed, CRABS_HASH_SIZE), 0);
}

// Same carried-gap rule for a GROUP_ORDERED dedup mutation target outside
// the resource list: v1 has no module to order through, so it fails closed
// (SEQ_MISMATCH) rather than silently mutating an off-path item.
TEST_F(TestStateMachine, DedupMutationGroupOrderedTargetMustBeResource) {
  state_add_policy(state, "vote_bump", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "vote_bump",
                                           sov_bump_handler),
            CRABS_SUCCESS);
  data_item_options_t options = {};
  options.write_domain = CRABS_DOMAIN_GROUP_ORDERED;
  data_item_t* group_item = nullptr;
  ASSERT_EQ(data_item_create_with_options("group_counter", DATA_TYPE_COUNTER,
                                          CRDT_G_COUNTER, &options, &group_item),
            CRABS_SUCCESS);
  group_item->value = g_counter_create();
  ASSERT_EQ(state_add_item(state, group_item), CRABS_SUCCESS);

  data_item_t* free_item =
      data_item_create("free_counter", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  free_item->value = g_counter_create();
  ASSERT_EQ(state_add_item(state, free_item), CRABS_SUCCESS);

  dedup_spec_t spec;
  memset(&spec, 0, sizeof(spec));
  spec.type = DEDUP_CUSTOM;
  strncpy(spec.condition, "free_counter >= 0", CRABS_MAX_POLICY_EXPR - 1);
  spec.update.type = MUTATION_COUNTER_INCREMENT;
  strncpy(spec.update.counter_path, "group_counter", CRABS_MAX_DEDUP_PATH - 1);
  spec.update.delta = 1;
  ASSERT_EQ(state_register_op_type_def(state, "vote_bump", &spec),
            CRABS_SUCCESS);

  operation_t* uncovered = make_domain_op("vote_bump", "free_counter", 0x63);
  set_signer_key_version(uncovered);
  sign_operation(uncovered);
  EXPECT_EQ(state_machine_execute(state, uncovered), CRABS_ERR_SEQ_MISMATCH);
  operation_destroy(uncovered);
  EXPECT_EQ(g_counter_value((g_counter_t*)group_item->value), 0);
}

// ============================================================
// Guarantee-regression test (spec 2026-10-08 §Testing — "Guarantee
// regression test", Amendment 4 §13.6): the same concurrent same-writer
// write race must produce DIFFERENT outcomes per domain class. Under
// FREE_MERGE the race is silently absorbed at merge (eventual — A4 §11.2
// stands). Under SOVEREIGN the same race is signed equivocation: both
// writer ops claim the same chain head with divergent results, so merge
// convicts the writer and DOMAIN_CHECK blocks further writes (strict).
// A class that behaved identically in both races would be the other class
// renamed — the divergent outcome is what demonstrates the taxonomy is
// real. (GROUP_ORDERED's arm is trivial in v1: every direct write is
// ORDERING_PATH — see DomainCheckGroupOrderedV1ReadOnly.)
// ============================================================

// Handler: assign the op's payload bytes into the REGISTER resource (LWW
// semantics mirroring crabs_wasm_set_register). The payload is what makes
// two concurrent writer ops diverge on the same item.
static crabs_error_e tag_assign_handler(state_t* handler_state,
                                        operation_t* op) {
  if (op->resource_count == 0) return CRABS_ERR_RESOURCE_NOT_FOUND;
  data_item_t* item = state_find_item(handler_state, op->resources[0]);
  if (item == NULL || item->type != DATA_TYPE_REGISTER) {
    return CRABS_ERR_RESOURCE_NOT_FOUND;
  }
  lww_register_t* register_value = (lww_register_t*)item->value;
  uint8_t* new_payload = (uint8_t*)malloc(op->payload_size);
  if (new_payload == NULL) return CRABS_ERR_OOM;
  memcpy(new_payload, op->payload, op->payload_size);
  free(register_value->value);
  register_value->value = new_payload;
  register_value->value_size = (uint32_t)op->payload_size;
  register_value->timestamp = handler_state->version + 1;
  strncpy(register_value->node_id, op->signer_id, CRABS_MAX_USER_ID - 1);
  register_value->node_id[CRABS_MAX_USER_ID - 1] = '\0';
  return CRABS_SUCCESS;
}

// A second replica sharing the fixture's alice identity: own state, own
// attribute machine (alice registered under the same public key), own node
// key, "tag_assign" policy + handler, and one REGISTER item named "slot"
// with the requested write domain.
typedef struct {
  state_t* state;
  attribute_machine_t* am;
} writer_replica_t;

static writer_replica_t make_writer_replica(ecdsa_keypair_t* alice_key,
                                            crabs_write_domain_e domain,
                                            crabs_error_e* out_status) {
  writer_replica_t replica = {NULL, NULL};
  *out_status = CRABS_SUCCESS;
  replica.state = state_create();
  uint8_t admin_pk[33];
  memset(admin_pk, 0xAA, 33);
  admin_pk[0] = 0x02;
  replica.am = attribute_machine_create("admin", admin_pk);
  if (replica.state == NULL || replica.am == NULL) {
    *out_status = CRABS_ERR_OOM;
    return replica;
  }
  if (crabs_test_register_user_with_role(replica.am, "alice",
                                         alice_key->public_key, "role",
                                         "admin") != CRABS_SUCCESS) {
    *out_status = CRABS_ERR_CRYPTOGRAPHIC_ERROR;
    return replica;
  }
  replica.state->attr_machine = replica.am;
  ecdsa_keypair_t* node_key = crypto_ecdsa_generate();
  if (node_key == NULL) { *out_status = CRABS_ERR_OOM; return replica; }
  state_set_node_key(replica.state, node_key->private_key,
                     node_key->public_key);
  crypto_ecdsa_keypair_destroy(node_key);
  state_add_policy(replica.state, "tag_assign", "role:admin");
  if (state_machine_register_handler(replica.state, "tag_assign",
                                     tag_assign_handler) != CRABS_SUCCESS) {
    *out_status = CRABS_ERR_PROTOCOL_VIOLATION;
    return replica;
  }

  data_item_options_t options = {};
  options.write_domain = domain;
  const char writer_alice[] = "alice";
  if (domain == CRABS_DOMAIN_SOVEREIGN) options.writer = writer_alice;
  data_item_t* item = NULL;
  *out_status = data_item_create_with_options("slot", DATA_TYPE_REGISTER,
                                              CRDT_LWW_REG, &options, &item);
  if (*out_status != CRABS_SUCCESS) return replica;
  static const uint8_t initial_payload[] = "init";
  item->value = lww_register_create(initial_payload,
                                    sizeof(initial_payload) - 1, 0, "system");
  if (item->value == NULL) { *out_status = CRABS_ERR_OOM; return replica; }
  *out_status = state_add_item(replica.state, item);
  return replica;
}

static void destroy_writer_replica(writer_replica_t* replica) {
  replica->state->attr_machine = NULL;
  state_destroy(replica->state);
  attribute_machine_destroy(replica->am);
}

// Build an alice-signed "tag_assign" op on resource "slot" carrying `tag`
// as its payload. `replica_am` resolves the signer key_version; the lamport
// counter is the caller's (must stay strictly increasing per signer). For
// sovereign items the caller sets op->sovereign_prefixes BEFORE this signs.
static operation_t* make_tag_op(const char* tag, uint8_t uuid_seed,
                                attribute_machine_t* replica_am,
                                ecdsa_keypair_t* alice_key,
                                uint64_t* signer_lamport) {
  operation_t* op = make_domain_op("tag_assign", "slot", uuid_seed);
  op->payload_size = strlen(tag);
  op->payload = (uint8_t*)malloc(op->payload_size);
  memcpy(op->payload, tag, op->payload_size);
  sign_as(op, replica_am, alice_key, "alice", signer_lamport);
  return op;
}

TEST_F(TestStateMachine, ConcurrentSameWriterRaceOutcomeDiffersByDomain) {
  crabs_error_e build_status = CRABS_SUCCESS;

  // ---------- FREE_MERGE arm: the race is absorbed (A4 §11.2) ----------
  writer_replica_t free_a =
      make_writer_replica(alice_key, CRABS_DOMAIN_FREE_MERGE, &build_status);
  ASSERT_EQ(build_status, CRABS_SUCCESS);
  writer_replica_t free_b =
      make_writer_replica(alice_key, CRABS_DOMAIN_FREE_MERGE, &build_status);
  ASSERT_EQ(build_status, CRABS_SUCCESS);

  operation_t* free_op_red = make_tag_op("red", 0x71, free_a.am, alice_key,
                                         &lamport_counter);
  EXPECT_EQ(state_machine_execute(free_a.state, free_op_red), CRABS_SUCCESS);
  operation_destroy(free_op_red);
  operation_t* free_op_blue = make_tag_op("blue", 0x72, free_b.am,
                                          alice_key, &lamport_counter);
  EXPECT_EQ(state_machine_execute(free_b.state, free_op_blue),
            CRABS_SUCCESS);
  operation_destroy(free_op_blue);

  // Merge: the concurrent writes converge silently. Equal timestamp and
  // node_id tie-break in dst's favor, so the absorbed value is "red".
  EXPECT_EQ(crdt_merge_state(free_a.state, free_b.state), CRABS_SUCCESS);
  data_item_t* free_slot = state_find_item(free_a.state, "slot");
  ASSERT_NE(free_slot, nullptr);
  lww_register_t* free_reg = (lww_register_t*)free_slot->value;
  ASSERT_NE(free_reg, nullptr);
  EXPECT_EQ(free_reg->value_size, strlen("red"));
  EXPECT_EQ(memcmp(free_reg->value, "red", free_reg->value_size), 0);

  // Eventual means nothing is blocked: a further write lands without any
  // chain check.
  operation_t* free_op_green = make_tag_op("green", 0x73, free_a.am,
                                           alice_key, &lamport_counter);
  EXPECT_EQ(state_machine_execute(free_a.state, free_op_green),
            CRABS_SUCCESS);
  operation_destroy(free_op_green);
  destroy_writer_replica(&free_a);
  destroy_writer_replica(&free_b);

  // ---------- SOVEREIGN arm: the race convicts the writer ----------
  writer_replica_t sov_a =
      make_writer_replica(alice_key, CRABS_DOMAIN_SOVEREIGN, &build_status);
  ASSERT_EQ(build_status, CRABS_SUCCESS);
  writer_replica_t sov_b =
      make_writer_replica(alice_key, CRABS_DOMAIN_SOVEREIGN, &build_status);
  ASSERT_EQ(build_status, CRABS_SUCCESS);

  // Alice signs two DISTINCT ops both claiming chain head (seq 0, zero
  // digest) — the same concurrent-write race as the free arm, but under
  // sovereignty it is signed equivocation by construction.
  operation_t* sov_op_red = make_domain_op("tag_assign", "slot", 0x81);
  sov_op_red->payload_size = strlen("red");
  sov_op_red->payload = (uint8_t*)malloc(sov_op_red->payload_size);
  memcpy(sov_op_red->payload, "red", sov_op_red->payload_size);
  sov_op_red->sovereign_prefix_count = 1;
  sov_op_red->sovereign_prefixes[0].item_seq = 0;
  memset(sov_op_red->sovereign_prefixes[0].prev_item_digest, 0,
         CRABS_HASH_SIZE);
  sign_as(sov_op_red, sov_a.am, alice_key, "alice", &lamport_counter);
  EXPECT_EQ(state_machine_execute(sov_a.state, sov_op_red), CRABS_SUCCESS);
  operation_destroy(sov_op_red);

  operation_t* sov_op_blue = make_domain_op("tag_assign", "slot", 0x82);
  sov_op_blue->payload_size = strlen("blue");
  sov_op_blue->payload = (uint8_t*)malloc(sov_op_blue->payload_size);
  memcpy(sov_op_blue->payload, "blue", sov_op_blue->payload_size);
  sov_op_blue->sovereign_prefix_count = 1;
  sov_op_blue->sovereign_prefixes[0].item_seq = 0;
  memset(sov_op_blue->sovereign_prefixes[0].prev_item_digest, 0,
         CRABS_HASH_SIZE);
  sign_as(sov_op_blue, sov_b.am, alice_key, "alice", &lamport_counter);
  EXPECT_EQ(state_machine_execute(sov_b.state, sov_op_blue), CRABS_SUCCESS);
  operation_destroy(sov_op_blue);

  data_item_t* slot_a = state_find_item(sov_a.state, "slot");
  data_item_t* slot_b = state_find_item(sov_b.state, "slot");
  ASSERT_NE(slot_a, nullptr);
  ASSERT_NE(slot_b, nullptr);
  ASSERT_EQ(slot_a->item_seq, (uint64_t)1);
  ASSERT_EQ(slot_b->item_seq, (uint64_t)1);
  // Divergent post-op content ⇒ divergent chain heads on the same seq.
  ASSERT_NE(memcmp(slot_a->item_digest, slot_b->item_digest,
                   CRABS_HASH_SIZE),
            0);

  // Merge: equal seq + different digest = fork. Item_a's content is kept
  // (quarantine semantics — the race must NOT merge), and alice is
  // convicted on the receiving replica.
  EXPECT_EQ(crdt_merge_state(sov_a.state, sov_b.state), CRABS_SUCCESS);
  lww_register_t* sov_reg = (lww_register_t*)slot_a->value;
  ASSERT_NE(sov_reg, nullptr);
  EXPECT_EQ(sov_reg->value_size, strlen("red"));
  EXPECT_EQ(memcmp(sov_reg->value, "red", sov_reg->value_size), 0);
  EXPECT_TRUE(state_item_is_quarantined(slot_a, "alice"));

  // Strict means blocked: the convicted writer's next op — even with the
  // current, honest chain prefix — is rejected at DOMAIN_CHECK.
  operation_t* sov_op_next = make_domain_op("tag_assign", "slot", 0x83);
  sov_op_next->payload_size = strlen("late");
  sov_op_next->payload = (uint8_t*)malloc(sov_op_next->payload_size);
  memcpy(sov_op_next->payload, "late", sov_op_next->payload_size);
  sov_op_next->sovereign_prefix_count = 1;
  sov_op_next->sovereign_prefixes[0].item_seq = slot_a->item_seq;
  memcpy(sov_op_next->sovereign_prefixes[0].prev_item_digest,
         slot_a->item_digest, CRABS_HASH_SIZE);
  sign_as(sov_op_next, sov_a.am, alice_key, "alice", &lamport_counter);
  EXPECT_EQ(state_machine_validate(sov_a.state, sov_op_next),
            CRABS_ERR_QUARANTINED);
  EXPECT_EQ(state_machine_execute(sov_a.state, sov_op_next),
            CRABS_ERR_QUARANTINED);
  operation_destroy(sov_op_next);
  EXPECT_EQ(slot_a->item_seq, (uint64_t)1);
  destroy_writer_replica(&sov_a);
  destroy_writer_replica(&sov_b);
}
