//
// CRABS-51: Built-in Key Operations Tests
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/StateMachine/state_machine.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/sig_scheme.h"
#include "../src/Crypto/crypto.h"
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/Util/allocator.h"
}

// ============================================================
// Helper: Create a state with an attribute machine
// ============================================================

static state_t* create_test_state_with_attr() {
  state_t* state = (state_t*)get_clear_memory(sizeof(state_t));
  state->version = 1;
  state->config.max_lock_duration_ms = CRABS_DEFAULT_LOCK_MS;
  state->config.max_lock_extensions = CRABS_MAX_LOCK_EXTENDS;
  state->config.allow_force_unlock = true;

  uint8_t admin_pk[33] = {0x02};
  memset(admin_pk + 1, 0xAA, 32);
  attribute_machine_t* am = attribute_machine_create("admin", admin_pk);
  state->attr_machine = am;
  return state;
}

static void destroy_test_state(state_t* state) {
  if (state == NULL) return;
  attribute_machine_destroy(state->attr_machine);
  data_item_t* item = state->items;
  while (item != NULL) {
    data_item_t* next = item->next;
    data_item_destroy(item);
    item = next;
  }
  if (state->policies != NULL) free(state->policies);
  if (state->log != NULL) free(state->log);
  if (state->processed_ops != NULL) free(state->processed_ops);
  if (state->last_refresh_envelope != NULL) {
    crypto_key_envelope_destroy((key_envelope_t*)state->last_refresh_envelope);
  }
  free(state);
}

static void fill_uuid(uint8_t* uuid) {
  for (int i = 0; i < CRABS_UUID_SIZE; i++) uuid[i] = (uint8_t)i;
}

// ============================================================
// operation_is_builtin includes key operations
// ============================================================

TEST(TestKeyOps, IsBuiltinRecognizesKeyOperations) {
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_REGISTER_KEY));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_REVOKE_KEY));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_SET_DEFAULT_KEY));
}

// ============================================================
// Register Key via state machine
// ============================================================

TEST(TestKeyOps, RegisterKeyBasic) {
  state_t* state = create_test_state_with_attr();

  // Prepare payload: "key_id=testkey;scheme=1;public_key_len=33" + 33 bytes of key data
  const char* config = "key_id=testkey;scheme=1;public_key_len=33";
  size_t config_len = strlen(config) + 1;  // include null terminator
  size_t payload_size = config_len + 33;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  ASSERT_NE(payload, nullptr);
  memcpy(payload, config, config_len);
  // Fill public key data after the config string
  payload[config_len] = 0x03;  // compressed point prefix
  memset(payload + config_len + 1, 0xBB, 32);

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Verify key was registered
  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
  ASSERT_NE(admin, nullptr);
  EXPECT_EQ(admin->key_count, 1u);
  user_key_t* key = user_key_find(admin, "testkey");
  ASSERT_NE(key, nullptr);
  EXPECT_EQ(key->scheme, ECDSA_SECP256K1);
  EXPECT_TRUE(key->is_active);

  operation_destroy(op);
  destroy_test_state(state);
}

TEST(TestKeyOps, RegisterKeyRejectsNoAttrMachine) {
  state_t* state = (state_t*)get_clear_memory(sizeof(state_t));
  state->version = 1;

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_ERR_UNAUTHORIZED);

  operation_destroy(op);
  free(state);
}

TEST(TestKeyOps, RegisterKeyRejectsUnknownUser) {
  state_t* state = create_test_state_with_attr();

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "nonexistent", CRABS_MAX_USER_ID - 1);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_ERR_USER_NOT_FOUND);

  operation_destroy(op);
  destroy_test_state(state);
}

TEST(TestKeyOps, RegisterKeyRejectsSuspendedUser) {
  state_t* state = create_test_state_with_attr();

  // Suspend admin
  attribute_machine_suspend_user(state->attr_machine, "admin");

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_ERR_USER_SUSPENDED);

  operation_destroy(op);
  destroy_test_state(state);
}

TEST(TestKeyOps, RegisterKeyRejectsNullPayload) {
  state_t* state = create_test_state_with_attr();

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_ERR_INVALID_PARAM);

  operation_destroy(op);
  destroy_test_state(state);
}

// ============================================================
// Revoke Key via state machine
// ============================================================

TEST(TestKeyOps, RevokeKeyBasic) {
  state_t* state = create_test_state_with_attr();

  // First register a key
  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "mykey", ECDSA_SECP256K1, pk, 33, "test"), CRABS_SUCCESS);

  // Now revoke via state machine
  const char* config = "key_id=mykey";
  size_t payload_size = strlen(config) + 1;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, payload_size);

  operation_t* op = operation_create(CRABS_OP_REVOKE_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Verify key is now inactive
  user_key_t* key = user_key_find(admin, "mykey");
  ASSERT_NE(key, nullptr);
  EXPECT_FALSE(key->is_active);

  operation_destroy(op);
  destroy_test_state(state);
}

TEST(TestKeyOps, RevokeKeyRejectsUnknownKeyId) {
  state_t* state = create_test_state_with_attr();

  const char* config = "key_id=nonexistent";
  size_t payload_size = strlen(config) + 1;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, payload_size);

  operation_t* op = operation_create(CRABS_OP_REVOKE_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_ERR_RESOURCE_NOT_FOUND);

  operation_destroy(op);
  destroy_test_state(state);
}

// ============================================================
// Set Default Key via state machine
// ============================================================

TEST(TestKeyOps, SetDefaultKeyBasic) {
  state_t* state = create_test_state_with_attr();

  // Register two keys
  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
  uint8_t pk1[33] = {0x03};
  memset(pk1 + 1, 0xBB, 32);
  uint8_t pk2[33] = {0x02};
  memset(pk2 + 1, 0xCC, 32);
  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk1, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_register(admin, "key2", ECDSA_SECP256K1, pk2, 33, "secondary"), CRABS_SUCCESS);
  EXPECT_STREQ(admin->default_key_id, "key1");

  // Set key2 as default via state machine
  const char* config = "key_id=key2";
  size_t payload_size = strlen(config) + 1;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, payload_size);

  operation_t* op = operation_create(CRABS_OP_SET_DEFAULT_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_STREQ(admin->default_key_id, "key2");

  operation_destroy(op);
  destroy_test_state(state);
}

TEST(TestKeyOps, SetDefaultKeyRejectsInactiveKey) {
  state_t* state = create_test_state_with_attr();

  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
  uint8_t pk1[33] = {0x03};
  memset(pk1 + 1, 0xBB, 32);
  uint8_t pk2[33] = {0x02};
  memset(pk2 + 1, 0xCC, 32);
  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk1, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_register(admin, "key2", ECDSA_SECP256K1, pk2, 33, "secondary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_revoke(admin, "key2"), CRABS_SUCCESS);

  const char* config = "key_id=key2";
  size_t payload_size = strlen(config) + 1;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, payload_size);

  operation_t* op = operation_create(CRABS_OP_SET_DEFAULT_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_ERR_INVALID_PARAM);

  operation_destroy(op);
  destroy_test_state(state);
}

// ============================================================
// Direct handler tests (without full execute pipeline)
// ============================================================

TEST(TestKeyOps, RegisterKeyDirectHandler) {
  state_t* state = create_test_state_with_attr();

  const char* config = "key_id=directkey;scheme=1;public_key_len=33";
  size_t config_len = strlen(config) + 1;
  size_t payload_size = config_len + 33;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, config_len);
  payload[config_len] = 0x03;
  memset(payload + config_len + 1, 0xCC, 32);

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  crabs_error_e rc = state_machine_op_register_key(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
  user_key_t* key = user_key_find(admin, "directkey");
  ASSERT_NE(key, nullptr);
  EXPECT_EQ(key->scheme, ECDSA_SECP256K1);

  operation_destroy(op);
  destroy_test_state(state);
}

TEST(TestKeyOps, RevokeKeyDirectHandler) {
  state_t* state = create_test_state_with_attr();

  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "revme", ECDSA_SECP256K1, pk, 33, "test"), CRABS_SUCCESS);

  const char* config = "key_id=revme";
  size_t payload_size = strlen(config) + 1;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, payload_size);

  operation_t* op = operation_create(CRABS_OP_REVOKE_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  crabs_error_e rc = state_machine_op_revoke_key(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_FALSE(user_key_find(admin, "revme")->is_active);

  operation_destroy(op);
  destroy_test_state(state);
}

TEST(TestKeyOps, SetDefaultKeyDirectHandler) {
  state_t* state = create_test_state_with_attr();

  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
  uint8_t pk1[33] = {0x03};
  memset(pk1 + 1, 0xBB, 32);
  uint8_t pk2[33] = {0x02};
  memset(pk2 + 1, 0xCC, 32);
  ASSERT_EQ(user_key_register(admin, "k1", ECDSA_SECP256K1, pk1, 33, "a"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_register(admin, "k2", ECDSA_SECP256K1, pk2, 33, "b"), CRABS_SUCCESS);

  const char* config = "key_id=k2";
  size_t payload_size = strlen(config) + 1;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, payload_size);

  operation_t* op = operation_create(CRABS_OP_SET_DEFAULT_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  crabs_error_e rc = state_machine_op_set_default_key(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_STREQ(admin->default_key_id, "k2");

  operation_destroy(op);
  destroy_test_state(state);
}

// ============================================================
// Null param guards
// ============================================================

TEST(TestKeyOps, RegisterKeyNullParams) {
  crabs_error_e rc = state_machine_op_register_key(NULL, NULL);
  EXPECT_EQ(rc, CRABS_ERR_INVALID_PARAM);
}

TEST(TestKeyOps, RevokeKeyNullParams) {
  crabs_error_e rc = state_machine_op_revoke_key(NULL, NULL);
  EXPECT_EQ(rc, CRABS_ERR_INVALID_PARAM);
}

TEST(TestKeyOps, SetDefaultKeyNullParams) {
  crabs_error_e rc = state_machine_op_set_default_key(NULL, NULL);
  EXPECT_EQ(rc, CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Register key with label
// ============================================================

TEST(TestKeyOps, RegisterKeyWithLabel) {
  state_t* state = create_test_state_with_attr();

  const char* config = "key_id=labeled;scheme=1;public_key_len=33;label=my signing key";
  size_t config_len = strlen(config) + 1;
  size_t payload_size = config_len + 33;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, config_len);
  payload[config_len] = 0x03;
  memset(payload + config_len + 1, 0xDD, 32);

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
  user_key_t* key = user_key_find(admin, "labeled");
  ASSERT_NE(key, nullptr);
  EXPECT_STREQ(key->label, "my signing key");

  operation_destroy(op);
  destroy_test_state(state);
}

// ============================================================
// Key operations by non-admin user
// ============================================================

TEST(TestKeyOps, RegisterKeyOnNonAdminUser) {
  state_t* state = create_test_state_with_attr();

  // Register a regular user
  uint8_t user_pk[33] = {0x02};
  memset(user_pk + 1, 0xDD, 32);
  attribute_machine_register_user(state->attr_machine, "alice", user_pk, "role:user");

  // Alice registers her own key
  const char* config = "key_id=alice-ecdsa;scheme=1;public_key_len=33";
  size_t config_len = strlen(config) + 1;
  size_t payload_size = config_len + 33;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, config_len);
  payload[config_len] = 0x03;
  memset(payload + config_len + 1, 0xEE, 32);

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(state->attr_machine, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->key_count, 1u);
  EXPECT_STREQ(alice->default_key_id, "alice-ecdsa");

  operation_destroy(op);
  destroy_test_state(state);
}

// ============================================================
// Transition validation for key operations
// ============================================================

TEST(TestKeyOps, KeyOpsAreValidTransitionsInAllStates) {
  // Key operations should be valid in every protocol state
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_IDLE, CRABS_OP_REGISTER_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_IDLE, CRABS_OP_REVOKE_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_IDLE, CRABS_OP_SET_DEFAULT_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_LOCKED, CRABS_OP_REGISTER_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_LOCKED, CRABS_OP_REVOKE_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_LOCKED, CRABS_OP_SET_DEFAULT_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_MODIFIED, CRABS_OP_REGISTER_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_MODIFIED, CRABS_OP_REVOKE_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_MODIFIED, CRABS_OP_SET_DEFAULT_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_VERIFIED, CRABS_OP_REGISTER_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_VERIFIED, CRABS_OP_REVOKE_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_VERIFIED, CRABS_OP_SET_DEFAULT_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_ERROR, CRABS_OP_REGISTER_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_ERROR, CRABS_OP_REVOKE_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_ERROR, CRABS_OP_SET_DEFAULT_KEY));
}

// ============================================================
// Scheme validation
// ============================================================

TEST(TestKeyOps, RegisterKeyRejectsUnspecifiedScheme) {
  state_t* state = create_test_state_with_attr();

  // scheme=0 is SCHEME_UNSPECIFIED, should be rejected
  const char* config = "key_id=badscheme;scheme=0;public_key_len=33";
  size_t config_len = strlen(config) + 1;
  size_t payload_size = config_len + 33;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, config_len);
  payload[config_len] = 0x03;
  memset(payload + config_len + 1, 0xBB, 32);

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_ERR_INVALID_PARAM);

  operation_destroy(op);
  destroy_test_state(state);
}

// ============================================================
// Revoke key suspends user when all keys revoked
// ============================================================

TEST(TestKeyOps, RevokeLastKeySuspendsUserViaStateMachine) {
  state_t* state = create_test_state_with_attr();

  // Register a single key for admin
  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "onlykey", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);
  EXPECT_EQ(admin->status, USER_ACTIVE);

  // Revoke it via state machine
  const char* config = "key_id=onlykey";
  size_t payload_size = strlen(config) + 1;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, payload_size);

  operation_t* op = operation_create(CRABS_OP_REVOKE_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(admin->status, USER_SUSPENDED);

  operation_destroy(op);
  destroy_test_state(state);
}

// ============================================================
// Duplicate key registration via state machine
// ============================================================

TEST(TestKeyOps, RegisterKeyRejectsDuplicateKeyId) {
  state_t* state = create_test_state_with_attr();

  // Register first key
  const char* config = "key_id=dupkey;scheme=1;public_key_len=33";
  size_t config_len = strlen(config) + 1;
  size_t payload_size = config_len + 33;

  // First registration
  uint8_t* payload1 = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload1, config, config_len);
  payload1[config_len] = 0x03;
  memset(payload1 + config_len + 1, 0xBB, 32);

  operation_t* op1 = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op1->uuid);
  strncpy(op1->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op1->payload = payload1;
  op1->payload_size = (uint32_t)payload_size;

  crabs_error_e rc = state_machine_execute(state, op1);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  operation_destroy(op1);

  // Duplicate registration — use a different UUID to avoid idempotency check
  uint8_t* payload2 = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload2, config, config_len);
  payload2[config_len] = 0x03;
  memset(payload2 + config_len + 1, 0xCC, 32);

  operation_t* op2 = operation_create(CRABS_OP_REGISTER_KEY);
  // Use a different UUID
  for (int i = 0; i < CRABS_UUID_SIZE; i++) op2->uuid[i] = (uint8_t)(i + 0x80);
  strncpy(op2->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op2->payload = payload2;
  op2->payload_size = (uint32_t)payload_size;

  rc = state_machine_execute(state, op2);
  EXPECT_EQ(rc, CRABS_ERR_DUPLICATE_OPERATION);
  operation_destroy(op2);

  destroy_test_state(state);
}