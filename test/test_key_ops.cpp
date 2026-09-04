//
// CRABS-51: Built-in Key Operations Tests
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/StateMachine/state_machine.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/sig_scheme.h"
#include "../src/Crypto/crypto.h"
#include "../src/Serialization/serialization.h"
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/Util/allocator.h"
#include "test_helpers.h"
}

// Internal handlers not in public header — exposed for testing only.
extern "C" {
crabs_error_e state_machine_op_register_key(state_t* state, operation_t* op);
crabs_error_e state_machine_op_revoke_key(state_t* state, operation_t* op);
crabs_error_e state_machine_op_set_default_key(state_t* state, operation_t* op);
}

// ============================================================
// Helper: Create a state with an attribute machine backed by a real
// ECDSA admin keypair, with policies registered for all built-in ops.
// ============================================================

static crabs_test_env_t g_env;
static bool g_env_initialized = false;

static state_t* create_test_state_with_attr() {
  crypto_sig_scheme_init();
  crabs_test_env_init(&g_env);
  g_env_initialized = true;
  return g_env.state;
}

// Audit N-3: user_key_register now validates secp256k1 public keys, so tests
// must use real generated keys (not 0xBB/0xCC fill).
static void _gen_pk_ops(uint8_t out[33]) {
  ecdsa_keypair_t* kp = crypto_ecdsa_generate();
  ASSERT_NE(kp, nullptr);
  memcpy(out, kp->public_key, 33);
  crypto_ecdsa_keypair_destroy(kp);
}

static ecdsa_keypair_t* test_admin_key() {
  return g_env.admin_key;
}

static void destroy_test_state(state_t* state) {
  (void)state;
  if (g_env_initialized) {
    crabs_test_env_destroy(&g_env);
    g_env_initialized = false;
  }
  crypto_sig_scheme_cleanup();
}

// R7-11: Lamport monotonicity is enforced per signer, so each op must carry a
// strictly increasing lamport_time.
static uint64_t g_key_ops_lamport = 0;

static void sign_as_admin(operation_t* op) {
  op->lamport_time = ++g_key_ops_lamport;
  crabs_test_sign_op_with(g_env.am, test_admin_key(), op);
}

// R8-C-2: once a keyring exists, the legacy bootstrap key is rejected, so ops
// must be signed with a keyring key. These helpers register a key with a known
// keypair and sign with it.
static void register_admin_key(const char* key_id, const char* label, ecdsa_keypair_t** out) {
  ecdsa_keypair_t* kp = crypto_ecdsa_generate();
  ASSERT_NE(kp, nullptr);
  user_t* admin = attribute_machine_find_user(g_env.am, "admin");
  ASSERT_NE(admin, nullptr);
  ASSERT_EQ(user_key_register(admin, key_id, ECDSA_SECP256K1, kp->public_key, 33, label),
            CRABS_SUCCESS);
  *out = kp;
}

static void sign_as_admin_with_key(operation_t* op, const char* key_id, ecdsa_keypair_t* key) {
  op->lamport_time = ++g_key_ops_lamport;
  strncpy(op->key_id, key_id, CRABS_MAX_KEY_ID - 1);
  op->sig_scheme = ECDSA_SECP256K1;
  op->signer_key_version = attribute_machine_find_user(g_env.am, "admin")->key_version;
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  crypto_sign_operation(key->private_key, ser->data, ser->len, op->signature);
  serialized_buffer_destroy(ser);
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
  // Audit N-3: use a real generated secp256k1 public key (not 0xBB fill).
  uint8_t _real_pk[33];
  _gen_pk_ops(_real_pk);
  memcpy(payload + config_len, _real_pk, 33);

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  sign_as_admin(op);
  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Verify key was registered
  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
  ASSERT_NE(admin, nullptr);
  EXPECT_EQ(admin->key_count, 1u);
  user_key_t* key = user_key_find(admin, "testkey");
  ASSERT_NE(key, nullptr);
  EXPECT_EQ(key->scheme, ECDSA_SECP256K1);
  EXPECT_EQ(key->status, KEY_ACTIVE);

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

  sign_as_admin(op);
  crabs_error_e rc = state_machine_execute(state, op);
  // R7-14: user existence must not leak through a distinct error code.
  EXPECT_EQ(rc, CRABS_ERR_UNAUTHORIZED);

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

  sign_as_admin(op);
  crabs_error_e rc = state_machine_execute(state, op);
  // R7-14: user status must not leak through a distinct error code.
  EXPECT_EQ(rc, CRABS_ERR_UNAUTHORIZED);

  operation_destroy(op);
  destroy_test_state(state);
}

TEST(TestKeyOps, RegisterKeyRejectsNullPayload) {
  state_t* state = create_test_state_with_attr();

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);

  sign_as_admin(op);
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

  // First register a key with a known keypair so we can sign with it (R8-C-2).
  ecdsa_keypair_t* kp = nullptr;
  register_admin_key("mykey", "test", &kp);
  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");

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

  sign_as_admin_with_key(op, "mykey", kp);
  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Verify key is now inactive
  user_key_t* key = user_key_find(admin, "mykey");
  ASSERT_NE(key, nullptr);
  EXPECT_EQ(key->status, KEY_REVOKED);

  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(kp);
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

  sign_as_admin(op);
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

  // Register two keys with known keypairs (R8-C-2).
  ecdsa_keypair_t* kp1 = nullptr;
  ecdsa_keypair_t* kp2 = nullptr;
  register_admin_key("key1", "primary", &kp1);
  register_admin_key("key2", "secondary", &kp2);
  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
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

  sign_as_admin_with_key(op, "key1", kp1);
  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_STREQ(admin->default_key_id, "key2");

  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(kp1);
  crypto_ecdsa_keypair_destroy(kp2);
  destroy_test_state(state);
}

TEST(TestKeyOps, SetDefaultKeyRejectsInactiveKey) {
  state_t* state = create_test_state_with_attr();

  ecdsa_keypair_t* kp1 = nullptr;
  ecdsa_keypair_t* kp2 = nullptr;
  register_admin_key("key1", "primary", &kp1);
  register_admin_key("key2", "secondary", &kp2);
  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
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

  sign_as_admin_with_key(op, "key1", kp1);
  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_ERR_KEY_NOT_ACTIVE);

  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(kp1);
  crypto_ecdsa_keypair_destroy(kp2);
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
  { uint8_t _pk[33]; _gen_pk_ops(_pk); memcpy(payload + config_len, _pk, 33); }

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
  uint8_t pk[33];
  _gen_pk_ops(pk);
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
  EXPECT_EQ(user_key_find(admin, "revme")->status, KEY_REVOKED);

  operation_destroy(op);
  destroy_test_state(state);
}

TEST(TestKeyOps, SetDefaultKeyDirectHandler) {
  state_t* state = create_test_state_with_attr();

  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
  uint8_t pk1[33];
  _gen_pk_ops(pk1);
  uint8_t pk2[33];
  _gen_pk_ops(pk2);
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
  { uint8_t _pk[33]; _gen_pk_ops(_pk); memcpy(payload + config_len, _pk, 33); }

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  sign_as_admin(op);
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

  // Register a regular user with a real ECDSA keypair so she can sign.
  ecdsa_keypair_t* alice_key = crypto_ecdsa_generate();
  ASSERT_NE(alice_key, nullptr);
  crabs_test_register_user_with_role(state->attr_machine, "alice",
                                    alice_key->public_key, "role", "user");

  // Alice registers her own key
  const char* config = "key_id=alice-ecdsa;scheme=1;public_key_len=33";
  size_t config_len = strlen(config) + 1;
  size_t payload_size = config_len + 33;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, config_len);
  { uint8_t _pk[33]; _gen_pk_ops(_pk); memcpy(payload + config_len, _pk, 33); }

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  crabs_test_sign_op_with(state->attr_machine, alice_key, op);
  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(state->attr_machine, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->key_count, 1u);
  EXPECT_STREQ(alice->default_key_id, "alice-ecdsa");

  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(alice_key);
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
  { uint8_t _pk[33]; _gen_pk_ops(_pk); memcpy(payload + config_len, _pk, 33); }

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  sign_as_admin(op);
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

  // Register a single key for admin with a known keypair (R8-C-2).
  ecdsa_keypair_t* kp = nullptr;
  register_admin_key("onlykey", "primary", &kp);
  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
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

  sign_as_admin_with_key(op, "onlykey", kp);
  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(admin->status, USER_SUSPENDED);

  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(kp);
  destroy_test_state(state);
}

// ============================================================
// Duplicate key registration via state machine
// ============================================================

TEST(TestKeyOps, RegisterKeyRejectsDuplicateKeyId) {
  state_t* state = create_test_state_with_attr();

  // Register first key with a known keypair so the duplicate op can be signed
  // with it (R8-C-2: once a keyring exists, the legacy key is rejected).
  ecdsa_keypair_t* kp = crypto_ecdsa_generate();
  ASSERT_NE(kp, nullptr);
  const char* config = "key_id=dupkey;scheme=1;public_key_len=33";
  size_t config_len = strlen(config) + 1;
  size_t payload_size = config_len + 33;

  // First registration
  uint8_t* payload1 = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload1, config, config_len);
  memcpy(payload1 + config_len, kp->public_key, 33);

  operation_t* op1 = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op1->uuid);
  strncpy(op1->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op1->payload = payload1;
  op1->payload_size = (uint32_t)payload_size;

  sign_as_admin(op1);
  crabs_error_e rc = state_machine_execute(state, op1);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  operation_destroy(op1);

  // Duplicate registration — use a different UUID to avoid idempotency check
  uint8_t* payload2 = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload2, config, config_len);
  { uint8_t _pk[33]; _gen_pk_ops(_pk); memcpy(payload2 + config_len, _pk, 33); }

  operation_t* op2 = operation_create(CRABS_OP_REGISTER_KEY);
  // Use a different UUID
  for (int i = 0; i < CRABS_UUID_SIZE; i++) op2->uuid[i] = (uint8_t)(i + 0x80);
  strncpy(op2->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op2->payload = payload2;
  op2->payload_size = (uint32_t)payload_size;

  sign_as_admin_with_key(op2, "dupkey", kp);
  rc = state_machine_execute(state, op2);
  EXPECT_EQ(rc, CRABS_ERR_DUPLICATE_OPERATION);
  operation_destroy(op2);

  crypto_ecdsa_keypair_destroy(kp);
  destroy_test_state(state);
}

// ============================================================
// Round 4 audit regression: R4-2 — a REVOKED user must be rejected by the
// key-management handlers. Previously they checked == USER_SUSPENDED, so a
// revoked user could still register/revoke/set-default/suspend/activate/
// rotate keys. Now they whitelist USER_ACTIVE.
//
// Through the signed-operation path, the revoked user is first rejected by
// the authorization step (crypto_verify_operation_auth whitelists
// USER_ACTIVE per the H-C fix), which returns CRABS_ERR_UNAUTHORIZED for
// REVOKED users (R7-14: no status leak). The handler-level != USER_ACTIVE
// check is defense-in-depth for the direct API path (tested in
// test_attribute_machine.cpp).
// ============================================================
TEST(TestKeyOps, RegisterKeyRejectsRevokedUser) {
  state_t* state = create_test_state_with_attr();

  // Revoke admin
  attribute_machine_revoke_user(state->attr_machine, "admin");

  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);

  sign_as_admin(op);
  crabs_error_e rc = state_machine_execute(state, op);
  // Auth step rejects REVOKED with UNAUTHORIZED (H-C whitelist, R7-14).
  EXPECT_EQ(rc, CRABS_ERR_UNAUTHORIZED);

  operation_destroy(op);
  destroy_test_state(state);
}

TEST(TestKeyOps, RevokeKeyRejectsRevokedUser) {
  state_t* state = create_test_state_with_attr();

  // First register a key (admin is still active)
  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");
  uint8_t pk[33];
  _gen_pk_ops(pk);
  ASSERT_EQ(user_key_register(admin, "mykey", ECDSA_SECP256K1, pk, 33, "test"), CRABS_SUCCESS);

  // Revoke admin
  attribute_machine_revoke_user(state->attr_machine, "admin");

  // Now try to revoke the key — must be rejected by auth step
  const char* config = "key_id=mykey";
  size_t payload_size = strlen(config) + 1;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, payload_size);

  operation_t* op = operation_create(CRABS_OP_REVOKE_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  sign_as_admin(op);
  crabs_error_e rc = state_machine_execute(state, op);
  // R7-14: status must not leak through a distinct error code.
  EXPECT_EQ(rc, CRABS_ERR_UNAUTHORIZED);

  operation_destroy(op);
  destroy_test_state(state);
}

TEST(TestKeyOps, SetDefaultKeyRejectsRevokedUser) {
  state_t* state = create_test_state_with_attr();

  // Revoke admin
  attribute_machine_revoke_user(state->attr_machine, "admin");

  const char* config = "key_id=somekey";
  size_t payload_size = strlen(config) + 1;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, payload_size);

  operation_t* op = operation_create(CRABS_OP_SET_DEFAULT_KEY);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload = payload;
  op->payload_size = (uint32_t)payload_size;

  sign_as_admin(op);
  crabs_error_e rc = state_machine_execute(state, op);
  // R7-14: status must not leak through a distinct error code.
  EXPECT_EQ(rc, CRABS_ERR_UNAUTHORIZED);

  operation_destroy(op);
  destroy_test_state(state);
}
// ============================================================
// Lazy Signature Scheme Registry (v1.3 keyring verification)
// ============================================================
// Regression: builds that never call crypto_sig_scheme_init() (WASM, CLI,
// native library consumers — only the Node binding initializes the registry)
// got NULL from crypto_sig_scheme_get for every scheme, so every keyring
// (v1.3) signature verification failed closed with
// CRABS_ERR_CRYPTOGRAPHIC_ERROR. The same keyring-signed op was accepted by a
// Node replica and rejected by WASM replicas. The accessors now lazily install
// the built-in ECDSA secp256k1 scheme, so verification must succeed without a
// manual init call.
TEST(TestKeyOps, VerifyKeyringOpWithoutExplicitRegistryInit) {
  // Force the registry empty to prove the lazy path runs; test execution
  // order must not matter. Deliberately NO crypto_sig_scheme_init() here.
  crypto_sig_scheme_cleanup();

  crabs_test_env_init(&g_env);
  g_env_initialized = true;

  // Register a keyring key for admin with a non-UNSPECIFIED scheme
  // (user_key_register rejects SCHEME_UNSPECIFIED, so every keyring key has
  // one — meaning every keyring verification routes through the registry).
  ecdsa_keypair_t* keyring_kp = crypto_ecdsa_generate();
  ASSERT_NE(keyring_kp, nullptr);
  user_t* admin = attribute_machine_find_user(g_env.am, "admin");
  ASSERT_NE(admin, nullptr);
  ASSERT_EQ(user_key_register(admin, "lazy-key", ECDSA_SECP256K1,
                              keyring_kp->public_key, 33, "lazy init regression"),
            CRABS_SUCCESS);

  // Sign an operation with the keyring key.
  const char* payload_text = "keyring-signed operation";
  operation_t* op = operation_create(CRABS_OP_LOCK);
  ASSERT_NE(op, nullptr);
  fill_uuid(op->uuid);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->lamport_time = ++g_key_ops_lamport;
  op->signer_key_version = admin->key_version;
  size_t payload_size = strlen(payload_text) + 1;
  op->payload = (uint8_t*)calloc(payload_size, 1);
  ASSERT_NE(op->payload, nullptr);
  memcpy(op->payload, payload_text, payload_size);
  op->payload_size = (uint32_t)payload_size;

  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  ASSERT_NE(ser, nullptr);
  ASSERT_EQ(crypto_sign_operation(keyring_kp->private_key, ser->data, ser->len,
                                  op->signature),
            CRABS_SUCCESS);
  serialized_buffer_destroy(ser);

  // Verify through the crypto layer — this lookup must lazy-init the registry.
  abe_master_key_t* master_key = crypto_abe_setup();
  ASSERT_NE(master_key, nullptr);
  serialized_buffer_t* ser_for_verify = crabs_serialize_for_signing(op);
  ASSERT_NE(ser_for_verify, nullptr);
  verify_result_t result = crypto_verify_operation_auth_v2(
      master_key, "", g_env.am,
      ser_for_verify->data, ser_for_verify->len,
      op->signature, CRABS_SIG_SIZE,
      "admin", "lazy-key", ECDSA_SECP256K1, VERIFY_MODE_A);
  EXPECT_TRUE(result.authorized);
  EXPECT_EQ(result.error, CRABS_SUCCESS);
  serialized_buffer_destroy(ser_for_verify);

  crypto_abe_master_key_destroy(master_key);
  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(keyring_kp);
  destroy_test_state(g_env.state);
}
