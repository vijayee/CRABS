//
// CRABS-54: Key Lifecycle & Vault Integration Tests
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/Attribute/attribute_machine.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Crypto/sig_scheme.h"
#include "../src/Crypto/crypto.h"
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/Util/allocator.h"
#include "test_helpers.h"
}

// ============================================================
// Helper: create attribute machine with admin user
// ============================================================

static attribute_machine_t* create_am_lifecycle() {
  uint8_t admin_pk[33] = {0x02};
  memset(admin_pk + 1, 0xAA, 32);
  return attribute_machine_create("admin", admin_pk);
}

// ============================================================
// key_status_e enum
// ============================================================

TEST(TestKeyLifecycle, KeyStatusEnumValues) {
  EXPECT_EQ(KEY_ACTIVE, 0x00);
  EXPECT_EQ(KEY_SUSPENDED, 0x01);
  EXPECT_EQ(KEY_REVOKED, 0x02);
  EXPECT_EQ(KEY_EXPIRED, 0x03);
}

TEST(TestKeyLifecycle, KeyStatusNameFunc) {
  EXPECT_STREQ(user_key_status_name(KEY_ACTIVE), "active");
  EXPECT_STREQ(user_key_status_name(KEY_SUSPENDED), "suspended");
  EXPECT_STREQ(user_key_status_name(KEY_REVOKED), "revoked");
  EXPECT_STREQ(user_key_status_name(KEY_EXPIRED), "expired");
  EXPECT_STREQ(user_key_status_name((key_status_e)99), "unknown");
}

// ============================================================
// user_key_t new fields
// ============================================================

TEST(TestKeyLifecycle, RegisteredKeyHasActiveStatus) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "k1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);

  user_key_t* key = user_key_find(admin, "k1");
  ASSERT_NE(key, nullptr);
  EXPECT_EQ(key->status, KEY_ACTIVE);
  EXPECT_EQ(key->expires_at, 0u);
  EXPECT_EQ(key->suspended_at, 0u);
  EXPECT_EQ(key->revoked_at, 0u);
  EXPECT_STREQ(key->predecessor_key_id, "");

  attribute_machine_destroy(am);
}

// ============================================================
// user_key_suspend
// ============================================================

TEST(TestKeyLifecycle, SuspendActiveKey) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "k1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);

  crabs_error_e rc = user_key_suspend(admin, "k1");
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(user_key_find(admin, "k1")->status, KEY_SUSPENDED);

  attribute_machine_destroy(am);
}

TEST(TestKeyLifecycle, SuspendRejectsNullParams) {
  EXPECT_EQ(user_key_suspend(nullptr, "k1"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(user_key_suspend(nullptr, nullptr), CRABS_ERR_INVALID_PARAM);
}

TEST(TestKeyLifecycle, SuspendRejectsUnknownKey) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  EXPECT_EQ(user_key_suspend(admin, "nonexistent"), CRABS_ERR_RESOURCE_NOT_FOUND);

  attribute_machine_destroy(am);
}

TEST(TestKeyLifecycle, SuspendRejectsNonActiveKey) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "k1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_revoke(admin, "k1"), CRABS_SUCCESS);

  // Can't suspend a revoked key
  EXPECT_EQ(user_key_suspend(admin, "k1"), CRABS_ERR_KEY_NOT_ACTIVE);

  attribute_machine_destroy(am);
}

TEST(TestKeyLifecycle, SuspendDefaultKeyTransitionsDefault) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk1[33] = {0x03};
  memset(pk1 + 1, 0xBB, 32);
  uint8_t pk2[33] = {0x02};
  memset(pk2 + 1, 0xCC, 32);

  ASSERT_EQ(user_key_register(admin, "k1", ECDSA_SECP256K1, pk1, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_register(admin, "k2", ECDSA_SECP256K1, pk2, 33, "secondary"), CRABS_SUCCESS);
  EXPECT_STREQ(admin->default_key_id, "k1");

  // Suspend the default key
  ASSERT_EQ(user_key_suspend(admin, "k1"), CRABS_SUCCESS);
  EXPECT_STREQ(admin->default_key_id, "k2");

  attribute_machine_destroy(am);
}

TEST(TestKeyLifecycle, SuspendKeyNotInFindActive) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "k1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_suspend(admin, "k1"), CRABS_SUCCESS);

  // Suspended key should not appear in find_active
  EXPECT_EQ(user_key_find_active(admin, ECDSA_SECP256K1), nullptr);

  attribute_machine_destroy(am);
}

// ============================================================
// user_key_activate
// ============================================================

TEST(TestKeyLifecycle, ActivateSuspendedKey) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "k1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_suspend(admin, "k1"), CRABS_SUCCESS);

  crabs_error_e rc = user_key_activate(admin, "k1");
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(user_key_find(admin, "k1")->status, KEY_ACTIVE);

  attribute_machine_destroy(am);
}

TEST(TestKeyLifecycle, ActivateActiveKeyIsIdempotent) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "k1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);

  // Activating an already active key should succeed (idempotent)
  EXPECT_EQ(user_key_activate(admin, "k1"), CRABS_SUCCESS);
  EXPECT_EQ(user_key_find(admin, "k1")->status, KEY_ACTIVE);

  attribute_machine_destroy(am);
}

TEST(TestKeyLifecycle, ActivateRejectsRevokedKey) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "k1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_revoke(admin, "k1"), CRABS_SUCCESS);

  EXPECT_EQ(user_key_activate(admin, "k1"), CRABS_ERR_KEY_REVOKED);

  attribute_machine_destroy(am);
}

TEST(TestKeyLifecycle, ActivateRejectsExpiredKey) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "k1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);

  // Manually set key to expired state
  user_key_find(admin, "k1")->status = KEY_EXPIRED;

  EXPECT_EQ(user_key_activate(admin, "k1"), CRABS_ERR_KEY_EXPIRED);

  attribute_machine_destroy(am);
}

TEST(TestKeyLifecycle, ActivateReactivatesSuspendedUser) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "k1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);

  // Revoke the only key, which suspends the user
  ASSERT_EQ(user_key_revoke(admin, "k1"), CRABS_SUCCESS);
  EXPECT_EQ(admin->status, USER_SUSPENDED);

  // Register a new key (admin is suspended but we bypass check here)
  user_key_t* new_key = user_key_find(admin, "k1");
  // Actually, we can't register a new key on a suspended user through
  // the state machine. But we can directly activate a key if one existed.
  // Let's test the scenario where a key is suspended but not revoked:
  attribute_machine_destroy(am);

  // Better test: register two keys, suspend one, revoke the other (user suspended),
  // then activate the suspended key
  am = create_am_lifecycle();
  admin = attribute_machine_find_user(am, "admin");
  uint8_t pk1[33] = {0x03}; memset(pk1 + 1, 0xBB, 32);
  uint8_t pk2[33] = {0x02}; memset(pk2 + 1, 0xCC, 32);
  ASSERT_EQ(user_key_register(admin, "k1", ECDSA_SECP256K1, pk1, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_register(admin, "k2", ECDSA_SECP256K1, pk2, 33, "secondary"), CRABS_SUCCESS);

  // Suspend k1, revoke k2
  ASSERT_EQ(user_key_suspend(admin, "k1"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_revoke(admin, "k2"), CRABS_SUCCESS);
  // k1 is suspended (not active), k2 is revoked, no active keys -> user suspended
  EXPECT_EQ(admin->status, USER_SUSPENDED);

  // Activate k1
  ASSERT_EQ(user_key_activate(admin, "k1"), CRABS_SUCCESS);
  EXPECT_EQ(admin->status, USER_ACTIVE);

  attribute_machine_destroy(am);
}

// ============================================================
// user_key_rotate
// ============================================================

TEST(TestKeyLifecycle, RotateKeyBasic) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t old_pk[33] = {0x03};
  memset(old_pk + 1, 0xBB, 32);
  uint8_t new_pk[33] = {0x02};
  memset(new_pk + 1, 0xDD, 32);

  ASSERT_EQ(user_key_register(admin, "old-key", ECDSA_SECP256K1, old_pk, 33, "primary"), CRABS_SUCCESS);

  crabs_error_e rc = user_key_rotate(admin, "old-key", "new-key", ECDSA_SECP256K1, new_pk, 33, "rotated primary");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Old key should be revoked
  user_key_t* old_key = user_key_find(admin, "old-key");
  ASSERT_NE(old_key, nullptr);
  EXPECT_EQ(old_key->status, KEY_REVOKED);

  // New key should be active
  user_key_t* new_key = user_key_find(admin, "new-key");
  ASSERT_NE(new_key, nullptr);
  EXPECT_EQ(new_key->status, KEY_ACTIVE);
  EXPECT_STREQ(new_key->predecessor_key_id, "old-key");

  // New key should be default
  EXPECT_STREQ(admin->default_key_id, "new-key");

  attribute_machine_destroy(am);
}

TEST(TestKeyLifecycle, RotateRejectsNullParams) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");
  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);

  EXPECT_EQ(user_key_rotate(nullptr, "old", "new", ECDSA_SECP256K1, pk, 33, "l"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(user_key_rotate(admin, nullptr, "new", ECDSA_SECP256K1, pk, 33, "l"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(user_key_rotate(admin, "old", nullptr, ECDSA_SECP256K1, pk, 33, "l"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(user_key_rotate(admin, "old", "new", ECDSA_SECP256K1, nullptr, 33, "l"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(user_key_rotate(admin, "old", "new", ECDSA_SECP256K1, pk, 0, "l"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(user_key_rotate(admin, "old", "new", SCHEME_UNSPECIFIED, pk, 33, "l"), CRABS_ERR_INVALID_PARAM);

  attribute_machine_destroy(am);
}

TEST(TestKeyLifecycle, RotateRejectsUnknownOldKey) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");
  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);

  EXPECT_EQ(user_key_rotate(admin, "nonexistent", "new-key", ECDSA_SECP256K1, pk, 33, "l"), CRABS_ERR_RESOURCE_NOT_FOUND);

  attribute_machine_destroy(am);
}

TEST(TestKeyLifecycle, RotateRejectsNonActiveOldKey) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "old-key", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_revoke(admin, "old-key"), CRABS_SUCCESS);

  uint8_t new_pk[33] = {0x02};
  memset(new_pk + 1, 0xDD, 32);
  EXPECT_EQ(user_key_rotate(admin, "old-key", "new-key", ECDSA_SECP256K1, new_pk, 33, "l"), CRABS_ERR_KEY_NOT_ACTIVE);

  attribute_machine_destroy(am);
}

TEST(TestKeyLifecycle, RotateRejectsDuplicateNewKeyId) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);

  // Try to rotate key1 to key1 (same id)
  EXPECT_EQ(user_key_rotate(admin, "key1", "key1", ECDSA_SECP256K1, pk, 33, "l"), CRABS_ERR_DUPLICATE_OPERATION);

  attribute_machine_destroy(am);
}

TEST(TestKeyLifecycle, RotateChainMultiple) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk1[33] = {0x03}; memset(pk1 + 1, 0x11, 32);
  uint8_t pk2[33] = {0x02}; memset(pk2 + 1, 0x22, 32);
  uint8_t pk3[33] = {0x03}; memset(pk3 + 1, 0x33, 32);

  ASSERT_EQ(user_key_register(admin, "v1", ECDSA_SECP256K1, pk1, 33, "v1"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_rotate(admin, "v1", "v2", ECDSA_SECP256K1, pk2, 33, "v2"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_rotate(admin, "v2", "v3", ECDSA_SECP256K1, pk3, 33, "v3"), CRABS_SUCCESS);

  // Check rotation chain
  EXPECT_STREQ(user_key_find(admin, "v3")->predecessor_key_id, "v2");
  EXPECT_STREQ(user_key_find(admin, "v2")->predecessor_key_id, "v1");
  EXPECT_STREQ(user_key_find(admin, "v1")->predecessor_key_id, "");

  // v1 and v2 should be revoked, v3 active
  EXPECT_EQ(user_key_find(admin, "v1")->status, KEY_REVOKED);
  EXPECT_EQ(user_key_find(admin, "v2")->status, KEY_REVOKED);
  EXPECT_EQ(user_key_find(admin, "v3")->status, KEY_ACTIVE);

  attribute_machine_destroy(am);
}

// ============================================================
// Error codes for key lifecycle
// ============================================================

TEST(TestKeyLifecycle, KeyErrorCodes) {
  EXPECT_EQ(CRABS_ERR_KEY_SUSPENDED, 0x6001);
  EXPECT_EQ(CRABS_ERR_KEY_REVOKED, 0x6002);
  EXPECT_EQ(CRABS_ERR_KEY_EXPIRED, 0x6003);
  EXPECT_EQ(CRABS_ERR_KEY_NOT_ACTIVE, 0x6004);
  EXPECT_EQ(CRABS_ERR_VAULT_UNAVAILABLE, 0x6005);
}

// ============================================================
// Operation names for key lifecycle
// ============================================================

TEST(TestKeyLifecycle, KeyLifecycleOperationNames) {
  EXPECT_STREQ(CRABS_OP_SUSPEND_KEY, "__suspend_key__");
  EXPECT_STREQ(CRABS_OP_ACTIVATE_KEY, "__activate_key__");
  EXPECT_STREQ(CRABS_OP_ROTATE_KEY, "__rotate_key__");
}

TEST(TestKeyLifecycle, IsBuiltinRecognizesKeyLifecycleOps) {
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_SUSPEND_KEY));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_ACTIVATE_KEY));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_ROTATE_KEY));
}

// ============================================================
// Transition table for key lifecycle ops
// ============================================================

TEST(TestKeyLifecycle, KeyLifecycleOpsValidInAllProtocolStates) {
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_IDLE, CRABS_OP_SUSPEND_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_LOCKED, CRABS_OP_SUSPEND_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_MODIFIED, CRABS_OP_SUSPEND_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_VERIFIED, CRABS_OP_SUSPEND_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_ERROR, CRABS_OP_SUSPEND_KEY));

  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_IDLE, CRABS_OP_ACTIVATE_KEY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_IDLE, CRABS_OP_ROTATE_KEY));
}

// ============================================================
// Vault config
// ============================================================

TEST(TestKeyLifecycle, VaultConfigDefaults) {
  state_t* state = (state_t*)get_clear_memory(sizeof(state_t));
  state->version = 1;

  // Zero-initialized vault config
  EXPECT_EQ(state->config.vault_config.provider, VAULT_NONE);
  EXPECT_FALSE(state->config.vault_config.signing_delegated);
  EXPECT_FALSE(state->config.vault_config.rotation_delegated);

  free(state);
}

TEST(TestKeyLifecycle, VaultProviderEnum) {
  EXPECT_EQ(VAULT_NONE, 0x00);
  EXPECT_EQ(VAULT_HASHICORP, 0x01);
  EXPECT_EQ(VAULT_AWS_KMS, 0x02);
  EXPECT_EQ(VAULT_HSM, 0x03);
  EXPECT_EQ(VAULT_CUSTOM, 0xFF);
}

TEST(TestKeyLifecycle, SignatureConfigKeyExpiryFields) {
  state_t* state = (state_t*)get_clear_memory(sizeof(state_t));
  state->version = 1;

  EXPECT_FALSE(state->config.sig_config.key_expiry_enabled);
  EXPECT_EQ(state->config.sig_config.default_key_ttl_ms, 0u);
  EXPECT_EQ(state->config.sig_config.max_key_age_ms, 0u);

  free(state);
}

TEST(TestKeyLifecycle, ChangeConfigKeyExpiryFields) {
  state_t* state = (state_t*)get_clear_memory(sizeof(state_t));
  state->version = 1;

  // Change key_expiry_enabled
  const char* p1 = "key_expiry_enabled=true";
  operation_t* op1 = operation_create(CRABS_OP_CHANGE_CONFIG);
  op1->payload = (uint8_t*)strdup(p1);
  op1->payload_size = (uint32_t)strlen(p1) + 1;
  memcpy(op1->uuid, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10", 16);
  EXPECT_EQ(state_machine_op_change_config(state, op1), CRABS_SUCCESS);
  EXPECT_TRUE(state->config.sig_config.key_expiry_enabled);
  operation_destroy(op1);

  // Change default_key_ttl_ms
  const char* p2 = "default_key_ttl_ms=86400000";
  operation_t* op2 = operation_create(CRABS_OP_CHANGE_CONFIG);
  op2->payload = (uint8_t*)strdup(p2);
  op2->payload_size = (uint32_t)strlen(p2) + 1;
  memcpy(op2->uuid, "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20", 16);
  EXPECT_EQ(state_machine_op_change_config(state, op2), CRABS_SUCCESS);
  EXPECT_EQ(state->config.sig_config.default_key_ttl_ms, 86400000u);
  operation_destroy(op2);

  // Change max_key_age_ms
  const char* p3 = "max_key_age_ms=31536000000";
  operation_t* op3 = operation_create(CRABS_OP_CHANGE_CONFIG);
  op3->payload = (uint8_t*)strdup(p3);
  op3->payload_size = (uint32_t)strlen(p3) + 1;
  memcpy(op3->uuid, "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30", 16);
  EXPECT_EQ(state_machine_op_change_config(state, op3), CRABS_SUCCESS);
  EXPECT_EQ(state->config.sig_config.max_key_age_ms, 31536000000u);
  operation_destroy(op3);

  free(state);
}

TEST(TestKeyLifecycle, ChangeConfigVaultFields) {
  state_t* state = (state_t*)get_clear_memory(sizeof(state_t));
  state->version = 1;

  const char* p1 = "vault_provider=1";
  operation_t* op1 = operation_create(CRABS_OP_CHANGE_CONFIG);
  op1->payload = (uint8_t*)strdup(p1);
  op1->payload_size = (uint32_t)strlen(p1) + 1;
  memcpy(op1->uuid, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10", 16);
  EXPECT_EQ(state_machine_op_change_config(state, op1), CRABS_SUCCESS);
  EXPECT_EQ(state->config.vault_config.provider, VAULT_HASHICORP);
  operation_destroy(op1);

  const char* p2 = "vault_signing_delegated=true";
  operation_t* op2 = operation_create(CRABS_OP_CHANGE_CONFIG);
  op2->payload = (uint8_t*)strdup(p2);
  op2->payload_size = (uint32_t)strlen(p2) + 1;
  memcpy(op2->uuid, "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20", 16);
  EXPECT_EQ(state_machine_op_change_config(state, op2), CRABS_SUCCESS);
  EXPECT_TRUE(state->config.vault_config.signing_delegated);
  operation_destroy(op2);

  const char* p3 = "vault_rotation_delegated=true";
  operation_t* op3 = operation_create(CRABS_OP_CHANGE_CONFIG);
  op3->payload = (uint8_t*)strdup(p3);
  op3->payload_size = (uint32_t)strlen(p3) + 1;
  memcpy(op3->uuid, "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30", 16);
  EXPECT_EQ(state_machine_op_change_config(state, op3), CRABS_SUCCESS);
  EXPECT_TRUE(state->config.vault_config.rotation_delegated);
  operation_destroy(op3);

  free(state);
}

// ============================================================
// State machine operations for key lifecycle
// ============================================================

static crabs_test_env_t g_env;
static bool g_env_initialized = false;

static state_t* create_state_with_am_for_lifecycle() {
  crabs_test_env_init(&g_env);
  g_env_initialized = true;
  g_env.state->config.sig_config.key_rotation_enabled = true;
  return g_env.state;
}

static ecdsa_keypair_t* lifecycle_admin_key() {
  return g_env.admin_key;
}

static void destroy_lifecycle_state(state_t* state) {
  (void)state;
  if (g_env_initialized) {
    crabs_test_env_destroy(&g_env);
    g_env_initialized = false;
  }
}

static void sign_lifecycle_op(operation_t* op) {
  crabs_test_sign_op_with(lifecycle_admin_key(), op);
}

TEST(TestKeyLifecycle, StateMachineSuspendKey) {
  crypto_sig_scheme_init();
  state_t* state = create_state_with_am_for_lifecycle();
  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");

  // Register a key first
  const char* config = "key_id=suskey;scheme=1;public_key_len=33";
  size_t config_len = strlen(config) + 1;
  size_t payload_size = config_len + 33;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, config_len);
  payload[config_len] = 0x03;
  memset(payload + config_len + 1, 0xBB, 32);

  operation_t* reg_op = operation_create(CRABS_OP_REGISTER_KEY);
  memcpy(reg_op->uuid, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10", 16);
  strncpy(reg_op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  reg_op->payload = payload;
  reg_op->payload_size = (uint32_t)payload_size;
  sign_lifecycle_op(reg_op);
  ASSERT_EQ(state_machine_execute(state, reg_op), CRABS_SUCCESS);
  operation_destroy(reg_op);

  // Now suspend the key
  const char* suspend_payload = "key_id=suskey";
  operation_t* sus_op = operation_create(CRABS_OP_SUSPEND_KEY);
  memcpy(sus_op->uuid, "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20", 16);
  strncpy(sus_op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  sus_op->payload = (uint8_t*)strdup(suspend_payload);
  sus_op->payload_size = (uint32_t)strlen(suspend_payload) + 1;

  sign_lifecycle_op(sus_op);
  crabs_error_e rc = state_machine_execute(state, sus_op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(user_key_find(admin, "suskey")->status, KEY_SUSPENDED);

  operation_destroy(sus_op);
  destroy_lifecycle_state(state);
  crypto_sig_scheme_cleanup();
}

TEST(TestKeyLifecycle, StateMachineActivateKey) {
  crypto_sig_scheme_init();
  state_t* state = create_state_with_am_for_lifecycle();
  user_t* admin = attribute_machine_find_user(state->attr_machine, "admin");

  // Register a key, then suspend it
  const char* config = "key_id=actkey;scheme=1;public_key_len=33";
  size_t config_len = strlen(config) + 1;
  size_t payload_size = config_len + 33;
  uint8_t* payload = (uint8_t*)calloc(payload_size, 1);
  memcpy(payload, config, config_len);
  payload[config_len] = 0x03;
  memset(payload + config_len + 1, 0xBB, 32);

  operation_t* reg_op = operation_create(CRABS_OP_REGISTER_KEY);
  memcpy(reg_op->uuid, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10", 16);
  strncpy(reg_op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  reg_op->payload = payload;
  reg_op->payload_size = (uint32_t)payload_size;
  sign_lifecycle_op(reg_op);
  ASSERT_EQ(state_machine_execute(state, reg_op), CRABS_SUCCESS);
  operation_destroy(reg_op);

  // Suspend
  const char* suspend_payload = "key_id=actkey";
  operation_t* sus_op = operation_create(CRABS_OP_SUSPEND_KEY);
  memcpy(sus_op->uuid, "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20", 16);
  strncpy(sus_op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  sus_op->payload = (uint8_t*)strdup(suspend_payload);
  sus_op->payload_size = (uint32_t)strlen(suspend_payload) + 1;
  sign_lifecycle_op(sus_op);
  ASSERT_EQ(state_machine_execute(state, sus_op), CRABS_SUCCESS);
  operation_destroy(sus_op);

  // Activate
  const char* activate_payload = "key_id=actkey";
  operation_t* act_op = operation_create(CRABS_OP_ACTIVATE_KEY);
  memcpy(act_op->uuid, "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30", 16);
  strncpy(act_op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  act_op->payload = (uint8_t*)strdup(activate_payload);
  act_op->payload_size = (uint32_t)strlen(activate_payload) + 1;

  sign_lifecycle_op(act_op);
  crabs_error_e rc = state_machine_execute(state, act_op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(user_key_find(admin, "actkey")->status, KEY_ACTIVE);

  operation_destroy(act_op);
  destroy_lifecycle_state(state);
  crypto_sig_scheme_cleanup();
}

TEST(TestKeyLifecycle, StateMachineRotateKeyRequiresRotationEnabled) {
  crypto_sig_scheme_init();
  state_t* state = create_state_with_am_for_lifecycle();

  // Disable rotation
  state->config.sig_config.key_rotation_enabled = false;

  const char* rot_payload = "old_key_id=k1;new_key_id=k2;scheme=1;public_key_len=33";
  operation_t* rot_op = operation_create(CRABS_OP_ROTATE_KEY);
  memcpy(rot_op->uuid, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10", 16);
  strncpy(rot_op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  rot_op->payload = (uint8_t*)strdup(rot_payload);
  rot_op->payload_size = (uint32_t)strlen(rot_payload) + 1;

  sign_lifecycle_op(rot_op);
  crabs_error_e rc = state_machine_execute(state, rot_op);
  EXPECT_EQ(rc, CRABS_ERR_PROTOCOL_VIOLATION);

  operation_destroy(rot_op);
  destroy_lifecycle_state(state);
  crypto_sig_scheme_cleanup();
}

// ============================================================
// Key expiry field access
// ============================================================

TEST(TestKeyLifecycle, KeyExpiryFieldAccess) {
  attribute_machine_t* am = create_am_lifecycle();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "expkey", ECDSA_SECP256K1, pk, 33, "expirable"), CRABS_SUCCESS);

  user_key_t* key = user_key_find(admin, "expkey");
  ASSERT_NE(key, nullptr);

  // Set expires_at manually (no built-in setter yet — config drives TTL)
  key->expires_at = 86400000;
  EXPECT_EQ(key->expires_at, 86400000u);

  // Mark as expired
  key->status = KEY_EXPIRED;
  EXPECT_EQ(key->status, KEY_EXPIRED);
  EXPECT_STREQ(user_key_status_name(key->status), "expired");

  attribute_machine_destroy(am);
}