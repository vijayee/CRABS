//
// CRABS-50: Multi-Key User Support & Operation Updates Tests
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/Attribute/attribute_machine.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Crypto/sig_scheme.h"
#include "../src/CRABS/crabs.h"
}

// ============================================================
// Helper: create a basic attribute machine with admin user
// ============================================================

static attribute_machine_t* create_test_am() {
  uint8_t admin_pk[33] = {0x02};
  memset(admin_pk + 1, 0xAA, 32);
  return attribute_machine_create("admin", admin_pk);
}

// ============================================================
// user_key_find
// ============================================================

TEST(TestKeyRing, FindReturnsNullOnEmptyKeyring) {
  attribute_machine_t* am = create_test_am();
  ASSERT_NE(am, nullptr);
  user_t* admin = attribute_machine_find_user(am, "admin");
  ASSERT_NE(admin, nullptr);

  EXPECT_EQ(user_key_find(admin, "key1"), nullptr);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, FindReturnsNullOnNullParams) {
  uint8_t admin_pk[33] = {0x02};
  memset(admin_pk + 1, 0xAA, 32);
  attribute_machine_t* am = attribute_machine_create("admin", admin_pk);
  user_t* admin = attribute_machine_find_user(am, "admin");

  EXPECT_EQ(user_key_find(nullptr, "key1"), nullptr);
  EXPECT_EQ(user_key_find(admin, nullptr), nullptr);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, FindReturnsKeyAfterRegister) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  crabs_error_e rc = user_key_register(admin, "key1", ECDSA_SECP256K1, pk, 33, "primary");
  ASSERT_EQ(rc, CRABS_SUCCESS);

  user_key_t* found = user_key_find(admin, "key1");
  ASSERT_NE(found, nullptr);
  EXPECT_STREQ(found->key_id, "key1");
  EXPECT_EQ(found->scheme, ECDSA_SECP256K1);
  EXPECT_EQ(found->public_key_len, 33u);
  EXPECT_TRUE(found->is_active);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, FindReturnsNullForUnknownKey) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);

  EXPECT_EQ(user_key_find(admin, "nonexistent"), nullptr);

  attribute_machine_destroy(am);
}

// ============================================================
// user_key_find_active
// ============================================================

TEST(TestKeyRing, FindActiveReturnsNullOnEmptyKeyring) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  EXPECT_EQ(user_key_find_active(admin, ECDSA_SECP256K1), nullptr);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, FindActiveReturnsNullOnNullUser) {
  EXPECT_EQ(user_key_find_active(nullptr, ECDSA_SECP256K1), nullptr);
}

TEST(TestKeyRing, FindActiveReturnsMatchingActiveKey) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "ecdsa-key", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);

  user_key_t* found = user_key_find_active(admin, ECDSA_SECP256K1);
  ASSERT_NE(found, nullptr);
  EXPECT_STREQ(found->key_id, "ecdsa-key");

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, FindActiveSkipsInactiveKeys) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "ecdsa-key", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);

  // Revoke the key (marks inactive)
  ASSERT_EQ(user_key_revoke(admin, "ecdsa-key"), CRABS_SUCCESS);

  // No active ECDSA keys remain
  EXPECT_EQ(user_key_find_active(admin, ECDSA_SECP256K1), nullptr);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, FindActiveSkipsWrongScheme) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "ecdsa-key", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);

  // Looking for ED25519 — no match
  EXPECT_EQ(user_key_find_active(admin, ED25519), nullptr);

  attribute_machine_destroy(am);
}

// ============================================================
// user_key_register
// ============================================================

TEST(TestKeyRing, RegisterBasicKey) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  crabs_error_e rc = user_key_register(admin, "key1", ECDSA_SECP256K1, pk, 33, "primary key");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  user_key_t* key = user_key_find(admin, "key1");
  ASSERT_NE(key, nullptr);
  EXPECT_STREQ(key->key_id, "key1");
  EXPECT_EQ(key->scheme, ECDSA_SECP256K1);
  EXPECT_EQ(key->public_key_len, 33u);
  EXPECT_STREQ(key->label, "primary key");
  EXPECT_TRUE(key->is_active);
  EXPECT_EQ(admin->key_count, 1u);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, RegisterSetsDefaultOnFirstKey) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  // Default key should be empty initially (user has legacy pk, no keyring keys)
  EXPECT_STREQ(admin->default_key_id, "");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);

  // First registered key should become default
  EXPECT_STREQ(admin->default_key_id, "key1");

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, RegisterDoesNotOverrideDefault) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk1[33] = {0x03};
  memset(pk1 + 1, 0xBB, 32);
  uint8_t pk2[33] = {0x02};
  memset(pk2 + 1, 0xCC, 32);

  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk1, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_register(admin, "key2", ECDSA_SECP256K1, pk2, 33, "secondary"), CRABS_SUCCESS);

  // Second key should NOT become default — first one stays
  EXPECT_STREQ(admin->default_key_id, "key1");

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, RegisterRejectsNullParams) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");
  uint8_t pk[33] = {};

  EXPECT_EQ(user_key_register(nullptr, "key1", ECDSA_SECP256K1, pk, 33, "label"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(user_key_register(admin, nullptr, ECDSA_SECP256K1, pk, 33, "label"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, nullptr, 33, "label"), CRABS_ERR_INVALID_PARAM);
}

TEST(TestKeyRing, RegisterRejectsOversizedPublicKey) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");
  uint8_t big_pk[CRABS_MAX_PUBLIC_KEY + 1] = {};

  EXPECT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, big_pk, CRABS_MAX_PUBLIC_KEY + 1, "label"),
            CRABS_ERR_INVALID_PARAM);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, RegisterRejectsZeroLengthPublicKey) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");
  uint8_t pk[33] = {0x03};

  EXPECT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk, 0, "label"),
            CRABS_ERR_INVALID_PARAM);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, RegisterRejectsUnspecifiedScheme) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");
  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);

  EXPECT_EQ(user_key_register(admin, "key1", SCHEME_UNSPECIFIED, pk, 33, "label"),
            CRABS_ERR_INVALID_PARAM);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, RegisterRejectsDuplicateKeyId) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");
  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);

  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);
  EXPECT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk, 33, "duplicate"),
            CRABS_ERR_DUPLICATE_OPERATION);
}

TEST(TestKeyRing, RegisterRejectsAtMaxKeys) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  // Register up to CRABS_MAX_KEYS_PER_USER keys
  for (uint32_t i = 0; i < CRABS_MAX_KEYS_PER_USER; i++) {
    char key_id[CRABS_MAX_KEY_ID];
    snprintf(key_id, sizeof(key_id), "key%u", i);
    uint8_t pk[33] = {0x03};
    memset(pk + 1, (uint8_t)i, 32);
    ASSERT_EQ(user_key_register(admin, key_id, ECDSA_SECP256K1, pk, 33, nullptr), CRABS_SUCCESS);
  }

  // Next one should fail
  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xFF, 32);
  EXPECT_EQ(user_key_register(admin, "overflow", ECDSA_SECP256K1, pk, 33, nullptr),
            CRABS_ERR_INVALID_PARAM);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, RegisterWithNullLabel) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  crabs_error_e rc = user_key_register(admin, "key1", ECDSA_SECP256K1, pk, 33, nullptr);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  user_key_t* key = user_key_find(admin, "key1");
  ASSERT_NE(key, nullptr);
  EXPECT_STREQ(key->label, "");  // Null label should result in empty string

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, RegisterMultipleKeys) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk1[33] = {0x03};
  memset(pk1 + 1, 0xBB, 32);
  uint8_t pk2[33] = {0x02};
  memset(pk2 + 1, 0xCC, 32);

  ASSERT_EQ(user_key_register(admin, "ecdsa-key", ECDSA_SECP256K1, pk1, 33, "ecdsa primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_register(admin, "ed25519-key", ED25519, pk2, 33, "ed25519 primary"), CRABS_SUCCESS);

  EXPECT_EQ(admin->key_count, 2u);

  user_key_t* ecdsa = user_key_find(admin, "ecdsa-key");
  ASSERT_NE(ecdsa, nullptr);
  EXPECT_EQ(ecdsa->scheme, ECDSA_SECP256K1);

  user_key_t* ed25519 = user_key_find(admin, "ed25519-key");
  ASSERT_NE(ed25519, nullptr);
  EXPECT_EQ(ed25519->scheme, ED25519);

  // Find active should return matching scheme
  user_key_t* active_ecdsa = user_key_find_active(admin, ECDSA_SECP256K1);
  ASSERT_NE(active_ecdsa, nullptr);
  EXPECT_EQ(active_ecdsa->scheme, ECDSA_SECP256K1);

  user_key_t* active_ed = user_key_find_active(admin, ED25519);
  ASSERT_NE(active_ed, nullptr);
  EXPECT_EQ(active_ed->scheme, ED25519);

  attribute_machine_destroy(am);
}

// ============================================================
// user_key_revoke
// ============================================================

TEST(TestKeyRing, RevokeMarksKeyInactive) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);

  crabs_error_e rc = user_key_revoke(admin, "key1");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  user_key_t* key = user_key_find(admin, "key1");
  ASSERT_NE(key, nullptr);
  EXPECT_FALSE(key->is_active);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, RevokeIncrementsKeyVersion) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");
  uint64_t version_before = admin->key_version;

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);

  // Register doesn't change key_version (only revoke does per spec)
  uint64_t version_after_register = admin->key_version;

  ASSERT_EQ(user_key_revoke(admin, "key1"), CRABS_SUCCESS);
  EXPECT_GT(admin->key_version, version_after_register);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, RevokeRejectsNullParams) {
  EXPECT_EQ(user_key_revoke(nullptr, "key1"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(user_key_revoke(nullptr, nullptr), CRABS_ERR_INVALID_PARAM);
}

TEST(TestKeyRing, RevokeRejectsUnknownKeyId) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  EXPECT_EQ(user_key_revoke(admin, "nonexistent"), CRABS_ERR_RESOURCE_NOT_FOUND);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, RevokeDefaultKeyTransitionsDefault) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk1[33] = {0x03};
  memset(pk1 + 1, 0xBB, 32);
  uint8_t pk2[33] = {0x02};
  memset(pk2 + 1, 0xCC, 32);

  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk1, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_register(admin, "key2", ECDSA_SECP256K1, pk2, 33, "secondary"), CRABS_SUCCESS);

  EXPECT_STREQ(admin->default_key_id, "key1");

  // Revoke the default key — should transition to another active key
  ASSERT_EQ(user_key_revoke(admin, "key1"), CRABS_SUCCESS);
  EXPECT_STREQ(admin->default_key_id, "key2");

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, RevokeOnlyKeyClearsDefault) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);
  EXPECT_STREQ(admin->default_key_id, "key1");

  ASSERT_EQ(user_key_revoke(admin, "key1"), CRABS_SUCCESS);

  // No active keys remain, default should be cleared
  EXPECT_STREQ(admin->default_key_id, "");

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, RevokeAllKeysSuspendsUser) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");
  EXPECT_EQ(admin->status, USER_ACTIVE);

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);

  ASSERT_EQ(user_key_revoke(admin, "key1"), CRABS_SUCCESS);

  // All keys revoked, user should be suspended
  EXPECT_EQ(admin->status, USER_SUSPENDED);

  attribute_machine_destroy(am);
}

// ============================================================
// user_key_set_default
// ============================================================

TEST(TestKeyRing, SetDefaultChangesDefault) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk1[33] = {0x03};
  memset(pk1 + 1, 0xBB, 32);
  uint8_t pk2[33] = {0x02};
  memset(pk2 + 1, 0xCC, 32);

  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk1, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_register(admin, "key2", ECDSA_SECP256K1, pk2, 33, "secondary"), CRABS_SUCCESS);

  EXPECT_STREQ(admin->default_key_id, "key1");

  crabs_error_e rc = user_key_set_default(admin, "key2");
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_STREQ(admin->default_key_id, "key2");

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, SetDefaultRejectsNullParams) {
  EXPECT_EQ(user_key_set_default(nullptr, "key1"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(user_key_set_default(nullptr, nullptr), CRABS_ERR_INVALID_PARAM);
}

TEST(TestKeyRing, SetDefaultRejectsUnknownKeyId) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  EXPECT_EQ(user_key_set_default(admin, "nonexistent"), CRABS_ERR_RESOURCE_NOT_FOUND);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, SetDefaultRejectsInactiveKey) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk1[33] = {0x03};
  memset(pk1 + 1, 0xBB, 32);
  uint8_t pk2[33] = {0x02};
  memset(pk2 + 1, 0xCC, 32);

  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk1, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_register(admin, "key2", ECDSA_SECP256K1, pk2, 33, "secondary"), CRABS_SUCCESS);

  // Revoke key2
  ASSERT_EQ(user_key_revoke(admin, "key2"), CRABS_SUCCESS);

  // Setting revoked key as default should fail
  EXPECT_EQ(user_key_set_default(admin, "key2"), CRABS_ERR_INVALID_PARAM);

  attribute_machine_destroy(am);
}

// ============================================================
// user_key_destroy_all
// ============================================================

TEST(TestKeyRing, DestroyAllClearsKeyring) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk1[33] = {0x03};
  memset(pk1 + 1, 0xBB, 32);
  uint8_t pk2[33] = {0x02};
  memset(pk2 + 1, 0xCC, 32);

  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk1, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_register(admin, "key2", ECDSA_SECP256K1, pk2, 33, "secondary"), CRABS_SUCCESS);
  EXPECT_EQ(admin->key_count, 2u);

  user_key_destroy_all(admin);

  EXPECT_EQ(admin->key_count, 0u);
  EXPECT_EQ(admin->keys, nullptr);
  EXPECT_STREQ(admin->default_key_id, "");
  EXPECT_EQ(user_key_find(admin, "key1"), nullptr);
  EXPECT_EQ(user_key_find(admin, "key2"), nullptr);

  attribute_machine_destroy(am);
}

TEST(TestKeyRing, DestroyAllOnNullUserIsSafe) {
  user_key_destroy_all(nullptr);  // Should not crash
}

TEST(TestKeyRing, DestroyAllOnEmptyKeyringIsSafe) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  // No keys registered — destroy_all should be a no-op
  user_key_destroy_all(admin);
  EXPECT_EQ(admin->key_count, 0u);
  EXPECT_EQ(admin->keys, nullptr);

  attribute_machine_destroy(am);
}

// ============================================================
// Co-signature data structure (operation_t fields)
// ============================================================

TEST(TestKeyRing, OperationCoSignatureFields) {
  operation_t* op = operation_create("__test_op__");
  ASSERT_NE(op, nullptr);

  // Verify new fields exist and are initialized
  EXPECT_EQ(op->sig_scheme, SCHEME_UNSPECIFIED);
  EXPECT_STREQ(op->key_id, "");
  EXPECT_EQ(op->co_signer_count, 0u);
  EXPECT_EQ(op->co_signers, nullptr);

  operation_destroy(op);
}

TEST(TestKeyRing, CoSignatureStructLayout) {
  co_signature_t cosig = {};
  EXPECT_STREQ(cosig.signer_id, "");
  EXPECT_STREQ(cosig.key_id, "");
  EXPECT_EQ(cosig.sig_scheme, SCHEME_UNSPECIFIED);
  EXPECT_EQ(cosig.signature_len, 0u);
}

// ============================================================
// Integration: Destroy machine with registered keys
// ============================================================

TEST(TestKeyRing, DestroyMachineWithKeysNoLeak) {
  attribute_machine_t* am = create_test_am();
  user_t* admin = attribute_machine_find_user(am, "admin");

  uint8_t pk[33] = {0x03};
  memset(pk + 1, 0xBB, 32);
  ASSERT_EQ(user_key_register(admin, "key1", ECDSA_SECP256K1, pk, 33, "primary"), CRABS_SUCCESS);
  ASSERT_EQ(user_key_register(admin, "key2", ED25519, pk, 33, "ed25519"), CRABS_SUCCESS);

  // Destroy should free all keys without leak
  attribute_machine_destroy(am);
}

// ============================================================
// Key ring operations on non-admin user
// ============================================================

TEST(TestKeyRing, RegisterKeyOnNonAdminUser) {
  attribute_machine_t* am = create_test_am();

  uint8_t user_pk[33] = {0x02};
  memset(user_pk + 1, 0xDD, 32);
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, "role:user"), CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);

  uint8_t key_pk[33] = {0x03};
  memset(key_pk + 1, 0xEE, 32);
  crabs_error_e rc = user_key_register(alice, "alice-key1", ECDSA_SECP256K1, key_pk, 33, "alice primary");
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(alice->key_count, 1u);
  EXPECT_STREQ(alice->default_key_id, "alice-key1");

  attribute_machine_destroy(am);
}