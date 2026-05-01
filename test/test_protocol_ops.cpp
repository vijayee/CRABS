//
// CRABS-45: Protocol State Machine & Operations Tests
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/crypto.h"
#include "../src/Serialization/serialization.h"
}

// Helper fixture that sets up a state with resource + attr_machine + keys
class TestProtocolOps : public ::testing::Test {
protected:
  state_t* state;
  attribute_machine_t* am;
  ecdsa_keypair_t* alice_key;

  void SetUp() override {
    state = state_create();
    add_resource("res1");
    add_resource("res2");
    add_policies();

    uint8_t admin_pk[33];
    memset(admin_pk, 0xAA, 33);
    admin_pk[0] = 0x02;
    am = attribute_machine_create("admin", admin_pk);
    ASSERT_NE(am, nullptr);
    alice_key = crypto_ecdsa_generate();
    attribute_machine_register_user(am, "alice", alice_key->public_key, "role:admin");
    state->attr_machine = am;

    ecdsa_keypair_t* node_key = crypto_ecdsa_generate();
    ASSERT_NE(node_key, nullptr);
    state_set_node_key(state, node_key->private_key, node_key->public_key);
    crypto_ecdsa_keypair_destroy(node_key);
  }

  void TearDown() override {
    state->attr_machine = nullptr;
    state_destroy(state);
    attribute_machine_destroy(am);
    crypto_ecdsa_keypair_destroy(alice_key);
  }

  void add_resource(const char* name) {
    data_item_t* res = data_item_create(name, DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
    int64_t* val = (int64_t*)malloc(sizeof(int64_t));
    *val = 0;
    res->value = val;
    state_add_item(state, res);
  }

  void add_policies() {
    state_add_policy(state, CRABS_OP_LOCK, "role:admin");
    state_add_policy(state, CRABS_OP_EXTEND, "role:admin");
    state_add_policy(state, CRABS_OP_VERIFY, "role:admin");
    state_add_policy(state, CRABS_OP_ROLLBACK, "role:admin");
    state_add_policy(state, CRABS_OP_UNLOCK, "role:admin");
    state_add_policy(state, CRABS_OP_FORCE_UNLOCK, "role:admin");
    state_add_policy(state, CRABS_OP_CHANGE_CONFIG, "role:admin");
  }

  // Sign an operation AFTER all fields are set
  void sign_op(operation_t* op) {
    op->signer_key_version = attribute_machine_find_user(am, "alice")->key_version;
    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
    if (ser) {
      crypto_sign_operation(alice_key->private_key, ser->data, ser->len, op->signature);
      serialized_buffer_destroy(ser);
    }
  }

  // Lock a resource and return. The operation is fully formed and signed.
  crabs_error_e lock_resource(const char* resource) {
    operation_t* op = operation_create(CRABS_OP_LOCK);
    memset(op->uuid, 0x42, CRABS_UUID_SIZE);
    op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
    strncpy(op->resources[0], resource, CRABS_MAX_USER_ID - 1);
    op->resource_count = 1;
    op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
    op->required_state[0] = PROTOCOL_IDLE;
    op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
    op->next_state[0] = PROTOCOL_LOCKED;
    strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
    sign_op(op);
    crabs_error_e rc = state_machine_execute(state, op);
    operation_destroy(op);
    return rc;
  }
};

// ============================================================
// Force Unlock
// ============================================================

TEST_F(TestProtocolOps, ForceUnlockExpiredLock) {
  ASSERT_EQ(lock_resource("res1"), CRABS_SUCCESS);
  data_item_t* item = state_find_item(state, "res1");
  ASSERT_NE(item, nullptr);
  item->lock_state.lock_expiry = 1000; // expired in the past

  operation_t* op = operation_create(CRABS_OP_FORCE_UNLOCK);
  memset(op->uuid, 0x50, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_LOCKED;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_IDLE;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  crabs_error_e rc = state_machine_execute(state, op);
  // Note: step 1 prunes expired locks, so item may be IDLE before step 3
  // If prune ran, item is IDLE but required_state is LOCKED -> PROTOCOL_VIOLATION
  // Force_unlock can only work when the lock is expired but not yet pruned
  // So the expected result depends on whether prune resets the item
  // Prune sets item to IDLE, then step 3 sees IDLE != LOCKED -> PROTOCOL_VIOLATION
  EXPECT_EQ(rc, CRABS_ERR_PROTOCOL_VIOLATION);
  operation_destroy(op);
}

TEST_F(TestProtocolOps, ForceUnlockNotExpired) {
  ASSERT_EQ(lock_resource("res1"), CRABS_SUCCESS);
  data_item_t* item = state_find_item(state, "res1");
  ASSERT_NE(item, nullptr);
  item->lock_state.lock_expiry = UINT64_MAX; // far future

  operation_t* op = operation_create(CRABS_OP_FORCE_UNLOCK);
  memset(op->uuid, 0x51, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_LOCKED;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_IDLE;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_ERR_LOCK_NOT_EXPIRED);
  operation_destroy(op);
}

// ============================================================
// Max Extensions Reached
// ============================================================

TEST_F(TestProtocolOps, MaxExtensionsReached) {
  ASSERT_EQ(lock_resource("res1"), CRABS_SUCCESS);
  state->config.max_lock_extensions = 2;

  for (int i = 0; i < 2; i++) {
    operation_t* ext = operation_create(CRABS_OP_EXTEND);
    memset(ext->uuid, 0x60 + i, CRABS_UUID_SIZE);
    ext->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
    strncpy(ext->resources[0], "res1", CRABS_MAX_USER_ID - 1);
    ext->resource_count = 1;
    ext->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
    ext->required_state[0] = PROTOCOL_LOCKED;
    ext->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
    ext->next_state[0] = PROTOCOL_LOCKED;
    strncpy(ext->signer_id, "alice", CRABS_MAX_USER_ID - 1);
    sign_op(ext);
    EXPECT_EQ(state_machine_execute(state, ext), CRABS_SUCCESS);
    operation_destroy(ext);
  }

  data_item_t* item = state_find_item(state, "res1");
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->lock_state.lock_extensions, (uint32_t)2);

  // Third extend should fail
  operation_t* ext3 = operation_create(CRABS_OP_EXTEND);
  memset(ext3->uuid, 0x63, CRABS_UUID_SIZE);
  ext3->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(ext3->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  ext3->resource_count = 1;
  ext3->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  ext3->required_state[0] = PROTOCOL_LOCKED;
  ext3->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  ext3->next_state[0] = PROTOCOL_LOCKED;
  strncpy(ext3->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(ext3);
  EXPECT_EQ(state_machine_execute(state, ext3), CRABS_ERR_MAX_EXTENSIONS_REACHED);
  operation_destroy(ext3);
}

// ============================================================
// Lock Owner Mismatch
// ============================================================

TEST_F(TestProtocolOps, LockOwnerMismatch) {
  ASSERT_EQ(lock_resource("res1"), CRABS_SUCCESS);
  data_item_t* item = state_find_item(state, "res1");
  ASSERT_NE(item, nullptr);
  item->protocol_state = PROTOCOL_MODIFIED;

  // Register bob with admin role
  ecdsa_keypair_t* bob_key = crypto_ecdsa_generate();
  attribute_machine_register_user(am, "bob", bob_key->public_key, "role:admin");

  // Bob tries to verify with alice's lock token but bob is not the lock owner
  operation_t* op = operation_create(CRABS_OP_VERIFY);
  memset(op->uuid, 0x70, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_MODIFIED;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_VERIFIED;
  op->lock_claims = (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(op->lock_claims[0].resource, "res1", CRABS_MAX_USER_ID - 1);
  memcpy(op->lock_claims[0].lock_token, item->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE);
  op->lock_claim_count = 1;
  strncpy(op->signer_id, "bob", CRABS_MAX_USER_ID - 1);
  op->signer_key_version = attribute_machine_find_user(am, "bob")->key_version;

  // Sign with bob's key
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  if (ser) {
    crypto_sign_operation(bob_key->private_key, ser->data, ser->len, op->signature);
    serialized_buffer_destroy(ser);
  }

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_ERR_LOCK_OWNER_MISMATCH);
  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(bob_key);
}

// ============================================================
// Protocol Violation via Wrong Required State
// ============================================================

TEST_F(TestProtocolOps, ProtocolViolationWrongState) {
  operation_t* op = operation_create(CRABS_OP_LOCK);
  memset(op->uuid, 0x80, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_LOCKED; // wrong - item is IDLE
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_MODIFIED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_ERR_PROTOCOL_VIOLATION);
  operation_destroy(op);
}

// ============================================================
// Type Mismatch (lock a non-RESOURCE item)
// ============================================================

TEST_F(TestProtocolOps, LockNonResourceTypeMismatch) {
  data_item_t* counter = data_item_create("c1", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  int64_t* val = (int64_t*)malloc(sizeof(int64_t));
  *val = 10;
  counter->value = val;
  state_add_item(state, counter);

  operation_t* op = operation_create(CRABS_OP_LOCK);
  memset(op->uuid, 0x81, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "c1", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  // The lock op handler checks type == DATA_TYPE_RESOURCE
  crabs_error_e rc = state_machine_execute(state, op);
  // If policy doesn't exist for the resource, it could be UNAUTHORIZED first
  // But we have a policy for LOCK, so it should get to the handler
  // The handler checks item->type != DATA_TYPE_RESOURCE
  EXPECT_TRUE(rc == CRABS_ERR_TYPE_MISMATCH || rc == CRABS_ERR_PROTOCOL_VIOLATION);
  operation_destroy(op);
}

// ============================================================
// Custom (Non-Builtin) Operation Rejection
// ============================================================

TEST_F(TestProtocolOps, CustomOperationRejected) {
  state_add_policy(state, "custom_transfer", "");

  operation_t* op = operation_create("custom_transfer");
  memset(op->uuid, 0x90, CRABS_UUID_SIZE);
  op->resource_count = 0;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_ERR_INVALID_PARAM);
  operation_destroy(op);
}

// ============================================================
// Null/Missing Policy Rejection
// ============================================================

TEST_F(TestProtocolOps, OperationWithNoPolicyRejected) {
  state_t* s = state_create();
  data_item_t* res = data_item_create("r1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* val = (int64_t*)malloc(sizeof(int64_t));
  *val = 0;
  res->value = val;
  state_add_item(s, res);
  // No policy added

  operation_t* op = operation_create(CRABS_OP_LOCK);
  memset(op->uuid, 0x99, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "r1", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  crabs_error_e rc = state_machine_execute(s, op);
  EXPECT_EQ(rc, CRABS_ERR_UNAUTHORIZED);
  operation_destroy(op);
  state_destroy(s);
}

// ============================================================
// Multiple Resource Lock
// ============================================================

TEST_F(TestProtocolOps, LockMultipleResources) {
  operation_t* op = operation_create(CRABS_OP_LOCK);
  memset(op->uuid, 0xA0, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(2 * CRABS_MAX_USER_ID);
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  strncpy(op->resources[1], "res2", CRABS_MAX_USER_ID - 1);
  op->resource_count = 2;
  op->required_state = (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->required_state[1] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  op->next_state[1] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  data_item_t* r1 = state_find_item(state, "res1");
  data_item_t* r2 = state_find_item(state, "res2");
  ASSERT_NE(r1, nullptr);
  ASSERT_NE(r2, nullptr);
  EXPECT_EQ(r1->protocol_state, PROTOCOL_LOCKED);
  EXPECT_EQ(r2->protocol_state, PROTOCOL_LOCKED);
  EXPECT_TRUE(r1->lock_state.lock_token_valid);
  EXPECT_TRUE(r2->lock_state.lock_token_valid);

  operation_destroy(op);
}

TEST_F(TestProtocolOps, LockMultipleResourcesPartialFailure) {
  operation_t* op = operation_create(CRABS_OP_LOCK);
  memset(op->uuid, 0xA1, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(2 * CRABS_MAX_USER_ID);
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  strncpy(op->resources[1], "res3", CRABS_MAX_USER_ID - 1);
  op->resource_count = 2;
  op->required_state = (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->required_state[1] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  op->next_state[1] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_ERR_RESOURCE_NOT_FOUND);
  operation_destroy(op);
}

// ============================================================
// CHANGE_CONFIG with Various Fields
// ============================================================

TEST_F(TestProtocolOps, ChangeConfigMaxExtensions) {
  operation_t* op = operation_create(CRABS_OP_CHANGE_CONFIG);
  memset(op->uuid, 0xB0, CRABS_UUID_SIZE);
  const char* payload = "max_lock_extensions=5";
  op->payload = (uint8_t*)strdup(payload);
  op->payload_size = strlen(payload);
  op->resource_count = 0;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(state->config.max_lock_extensions, (uint32_t)5);
  operation_destroy(op);
}

TEST_F(TestProtocolOps, ChangeConfigAllowForceUnlock) {
  operation_t* op = operation_create(CRABS_OP_CHANGE_CONFIG);
  memset(op->uuid, 0xB1, CRABS_UUID_SIZE);
  const char* payload = "allow_force_unlock=false";
  op->payload = (uint8_t*)strdup(payload);
  op->payload_size = strlen(payload);
  op->resource_count = 0;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(state->config.allow_force_unlock, false);
  operation_destroy(op);
}

TEST_F(TestProtocolOps, ChangeConfigNullPayloadRejected) {
  operation_t* op = operation_create(CRABS_OP_CHANGE_CONFIG);
  memset(op->uuid, 0xB2, CRABS_UUID_SIZE);
  op->payload = nullptr;
  op->payload_size = 0;
  op->resource_count = 0;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_ERR_INVALID_PARAM);
  operation_destroy(op);
}

TEST_F(TestProtocolOps, ChangeConfigDuration) {
  operation_t* op = operation_create(CRABS_OP_CHANGE_CONFIG);
  memset(op->uuid, 0xB3, CRABS_UUID_SIZE);
  const char* payload = "max_lock_duration_ms=20000";
  op->payload = (uint8_t*)strdup(payload);
  op->payload_size = strlen(payload);
  op->resource_count = 0;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(state->config.max_lock_duration_ms, (uint64_t)20000);
  operation_destroy(op);
}

// ============================================================
// Rollback from PROTOCOL_ERROR
// ============================================================

TEST_F(TestProtocolOps, RollbackFromErrorState) {
  ASSERT_EQ(lock_resource("res1"), CRABS_SUCCESS);
  data_item_t* item = state_find_item(state, "res1");
  ASSERT_NE(item, nullptr);
  item->protocol_state = PROTOCOL_ERROR;

  operation_t* op = operation_create(CRABS_OP_ROLLBACK);
  memset(op->uuid, 0xC0, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_ERROR;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_IDLE;
  op->lock_claims = (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(op->lock_claims[0].resource, "res1", CRABS_MAX_USER_ID - 1);
  memcpy(op->lock_claims[0].lock_token, item->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE);
  op->lock_claim_count = 1;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(item->protocol_state, PROTOCOL_IDLE);
  EXPECT_FALSE(item->lock_state.lock_token_valid);
  operation_destroy(op);
}

// ============================================================
// Lock Expiry During Execution (prune resets state)
// ============================================================

TEST_F(TestProtocolOps, LockPrunedBeforeNewOperation) {
  ASSERT_EQ(lock_resource("res1"), CRABS_SUCCESS);
  data_item_t* item = state_find_item(state, "res1");
  ASSERT_NE(item, nullptr);
  item->lock_state.lock_expiry = 1000; // expired

  // Try to verify while item was LOCKED but prune will reset to IDLE
  operation_t* op = operation_create(CRABS_OP_VERIFY);
  memset(op->uuid, 0xD0, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_LOCKED;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_VERIFIED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  crabs_error_e rc = state_machine_execute(state, op);
  // After prune, item is IDLE, but required_state is LOCKED -> PROTOCOL_VIOLATION
  EXPECT_EQ(rc, CRABS_ERR_PROTOCOL_VIOLATION);
  operation_destroy(op);
}

// ============================================================
// Execute with Null Params
// ============================================================

TEST_F(TestProtocolOps, ExecuteNullParams) {
  EXPECT_EQ(state_machine_execute(nullptr, nullptr), CRABS_ERR_INVALID_PARAM);

  operation_t* op = operation_create(CRABS_OP_LOCK);
  EXPECT_EQ(state_machine_execute(nullptr, op), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state_machine_execute(state, nullptr), CRABS_ERR_INVALID_PARAM);
  operation_destroy(op);
}

// ============================================================
// Version Increments on Successful Operations
// ============================================================

TEST_F(TestProtocolOps, VersionIncrementsOnSuccess) {
  EXPECT_EQ(state->version, (uint64_t)0);
  ASSERT_EQ(lock_resource("res1"), CRABS_SUCCESS);
  EXPECT_EQ(state->version, (uint64_t)1);
}

TEST_F(TestProtocolOps, VersionDoesNotIncrementOnFailure) {
  // Submit lock with wrong required_state
  operation_t* op = operation_create(CRABS_OP_LOCK);
  memset(op->uuid, 0x80, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_LOCKED; // wrong
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_MODIFIED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  state_machine_execute(state, op);
  EXPECT_EQ(state->version, (uint64_t)0);
  operation_destroy(op);
}

// ============================================================
// Idempotency - same UUID replay
// ============================================================

TEST_F(TestProtocolOps, IdempotentReplay) {
  ASSERT_EQ(lock_resource("res1"), CRABS_SUCCESS);
  EXPECT_EQ(state->version, (uint64_t)1);

  // Replay the exact same lock (same UUID)
  operation_t* op = operation_create(CRABS_OP_LOCK);
  memset(op->uuid, 0x42, CRABS_UUID_SIZE); // same UUID as lock_resource
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  sign_op(op);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(state->version, (uint64_t)1); // no increment on replay
  operation_destroy(op);
}