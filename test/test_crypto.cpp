#include <gtest/gtest.h>
#include <cstring>
extern "C" {
#include "../src/Crypto/crypto.h"
#include "../src/Attribute/attribute_machine.h"
}

TEST(TestCrypto, TestEcdsaGenerate) {
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);

  // Private key should not be all zeros (extremely unlikely for valid key)
  bool all_zero_priv = true;
  for (int i = 0; i < 32; i++) {
    if (keypair->private_key[i] != 0) {
      all_zero_priv = false;
      break;
    }
  }
  EXPECT_FALSE(all_zero_priv);

  // Public key should start with 0x02 or 0x03 (compressed point prefix)
  EXPECT_TRUE(keypair->public_key[0] == 0x02 || keypair->public_key[0] == 0x03);

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST(TestCrypto, TestEcdsaSignVerify) {
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);

  const uint8_t message[] = "Hello, CRABS protocol!";
  uint8_t signature[CRABS_SIG_SIZE];

  crabs_error_e rc = crypto_ecdsa_sign(
    keypair->private_key, message, sizeof(message), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Verify with the correct public key
  bool valid = crypto_ecdsa_verify(
    keypair->public_key, message, sizeof(message), signature);
  EXPECT_TRUE(valid);

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST(TestCrypto, TestEcdsaWrongKey) {
  ecdsa_keypair_t* keypair1 = crypto_ecdsa_generate();
  ecdsa_keypair_t* keypair2 = crypto_ecdsa_generate();
  ASSERT_NE(keypair1, nullptr);
  ASSERT_NE(keypair2, nullptr);

  const uint8_t message[] = "Message signed by keypair1";
  uint8_t signature[CRABS_SIG_SIZE];

  crabs_error_e rc = crypto_ecdsa_sign(
    keypair1->private_key, message, sizeof(message), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Verify with the wrong public key should fail
  bool valid = crypto_ecdsa_verify(
    keypair2->public_key, message, sizeof(message), signature);
  EXPECT_FALSE(valid);

  // Verify with the correct public key should succeed
  valid = crypto_ecdsa_verify(
    keypair1->public_key, message, sizeof(message), signature);
  EXPECT_TRUE(valid);

  crypto_ecdsa_keypair_destroy(keypair1);
  crypto_ecdsa_keypair_destroy(keypair2);
}

TEST(TestCrypto, TestSha256) {
  const uint8_t data[] = "CRABS protocol test data";
  uint8_t hash1[CRABS_HASH_SIZE];
  uint8_t hash2[CRABS_HASH_SIZE];

  crabs_error_e rc = crypto_sha256(data, sizeof(data), hash1);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Same input should produce same hash
  rc = crypto_sha256(data, sizeof(data), hash2);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(memcmp(hash1, hash2, CRABS_HASH_SIZE), 0);
}

TEST(TestCrypto, TestSha256Consistency) {
  const uint8_t data1[] = "First message";
  const uint8_t data2[] = "Second message";
  uint8_t hash1[CRABS_HASH_SIZE];
  uint8_t hash2[CRABS_HASH_SIZE];

  crabs_error_e rc = crypto_sha256(data1, sizeof(data1), hash1);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  rc = crypto_sha256(data2, sizeof(data2), hash2);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Different inputs should produce different hashes
  EXPECT_NE(memcmp(hash1, hash2, CRABS_HASH_SIZE), 0);
}

TEST(TestCrypto, TestRandomBytes) {
  uint8_t buf1[32];
  uint8_t buf2[32];

  crabs_error_e rc = crypto_random_bytes(buf1, sizeof(buf1));
  EXPECT_EQ(rc, CRABS_SUCCESS);

  rc = crypto_random_bytes(buf2, sizeof(buf2));
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Two random buffers should not be identical (extremely unlikely)
  EXPECT_NE(memcmp(buf1, buf2, 32), 0);
}

TEST(TestCrypto, TestAbeNullParams) {
  // Keygen with null master key should return NULL
  abe_user_key_t* sk = crypto_abe_keygen(nullptr, "attr1,attr2");
  EXPECT_EQ(sk, nullptr);

  // Encrypt with null master key should return NULL
  const uint8_t msg[] = "test message";
  abe_ciphertext_t* ct = crypto_abe_encrypt(nullptr, msg, sizeof(msg), "policy");
  EXPECT_EQ(ct, nullptr);

  // Decrypt with null params should return INVALID_PARAM
  uint8_t* out = nullptr;
  size_t out_len = 0;
  crabs_error_e dec_rc = crypto_abe_decrypt(nullptr, nullptr, &out, &out_len);
  EXPECT_EQ(dec_rc, CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// ABE Functional Tests
// ============================================================

TEST(TestAbe, TestSetup) {
  abe_master_key_t* mk = crypto_abe_setup();
  ASSERT_NE(mk, nullptr);

  // MSK should not be all zeros
  bool msk_nonzero = false;
  for (int i = 0; i < ABE_MASTER_KEY_SIZE; i++) {
    if (mk->msk[i] != 0) { msk_nonzero = true; break; }
  }
  EXPECT_TRUE(msk_nonzero);

  // MPK should not be all zeros
  bool mpk_nonzero = false;
  for (int i = 0; i < ABE_MASTER_KEY_SIZE; i++) {
    if (mk->mpk[i] != 0) { mpk_nonzero = true; break; }
  }
  EXPECT_TRUE(mpk_nonzero);

  // MSK and MPK should differ (MSK is random, MPK is SHA-256 of MSK)
  EXPECT_NE(memcmp(mk->msk, mk->mpk, ABE_MASTER_KEY_SIZE), 0);

  crypto_abe_master_key_destroy(mk);
}

TEST(TestAbe, TestKeygen) {
  abe_master_key_t* mk = crypto_abe_setup();
  ASSERT_NE(mk, nullptr);

  const char* attrs = "admin,editor,auditor";
  abe_user_key_t* sk = crypto_abe_keygen(mk, attrs);
  ASSERT_NE(sk, nullptr);

  // Attributes should be stored
  EXPECT_STREQ(sk->attrs, attrs);
  EXPECT_EQ(sk->attr_count, 3u);

  // Key should not be all zeros (contains MPK)
  bool key_nonzero = false;
  for (int i = 0; i < ABE_MASTER_KEY_SIZE; i++) {
    if (sk->key[i] != 0) { key_nonzero = true; break; }
  }
  EXPECT_TRUE(key_nonzero);

  // Same master key should produce same user key (stores MPK)
  abe_user_key_t* sk2 = crypto_abe_keygen(mk, "admin,viewer");
  ASSERT_NE(sk2, nullptr);
  EXPECT_EQ(memcmp(sk->key, sk2->key, ABE_MASTER_KEY_SIZE), 0);

  // Different master key should produce different user key
  abe_master_key_t* mk2 = crypto_abe_setup();
  ASSERT_NE(mk2, nullptr);
  abe_user_key_t* sk3 = crypto_abe_keygen(mk2, attrs);
  ASSERT_NE(sk3, nullptr);
  EXPECT_NE(memcmp(sk->key, sk3->key, ABE_MASTER_KEY_SIZE), 0);

  crypto_abe_user_key_destroy(sk);
  crypto_abe_user_key_destroy(sk2);
  crypto_abe_user_key_destroy(sk3);
  crypto_abe_master_key_destroy(mk);
  crypto_abe_master_key_destroy(mk2);
}

TEST(TestAbe, TestKeygenNullParams) {
  abe_user_key_t* sk = crypto_abe_keygen(nullptr, "admin");
  EXPECT_EQ(sk, nullptr);

  abe_master_key_t* mk = crypto_abe_setup();
  ASSERT_NE(mk, nullptr);
  sk = crypto_abe_keygen(mk, nullptr);
  EXPECT_EQ(sk, nullptr);

  crypto_abe_master_key_destroy(mk);
}

TEST(TestAbe, TestEncryptDecrypt) {
  abe_master_key_t* mk = crypto_abe_setup();
  ASSERT_NE(mk, nullptr);

  const char* policy = "admin";
  const uint8_t msg[] = "Hello, ABE world!";
  size_t msg_len = sizeof(msg);

  // Encrypt
  abe_ciphertext_t* ct = crypto_abe_encrypt(mk, msg, msg_len, policy);
  ASSERT_NE(ct, nullptr);
  EXPECT_STREQ(ct->policy, policy);
  EXPECT_GT(ct->ct_len, 0u);
  EXPECT_NE(ct->ciphertext, nullptr);

  // Decrypt with matching attributes
  abe_user_key_t* sk = crypto_abe_keygen(mk, "admin,editor");
  ASSERT_NE(sk, nullptr);

  uint8_t* out = nullptr;
  size_t out_len = 0;
  crabs_error_e rc = crypto_abe_decrypt(sk, ct, &out, &out_len);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  ASSERT_NE(out, nullptr);
  EXPECT_EQ(out_len, msg_len);
  EXPECT_EQ(memcmp(out, msg, msg_len), 0);

  free(out);
  crypto_abe_user_key_destroy(sk);
  crypto_abe_ciphertext_destroy(ct);
  crypto_abe_master_key_destroy(mk);
}

TEST(TestAbe, TestDecryptPolicyNotSatisfied) {
  abe_master_key_t* mk = crypto_abe_setup();
  ASSERT_NE(mk, nullptr);

  const char* policy = "admin";
  const uint8_t msg[] = "Secret data";
  size_t msg_len = sizeof(msg);

  abe_ciphertext_t* ct = crypto_abe_encrypt(mk, msg, msg_len, policy);
  ASSERT_NE(ct, nullptr);

  // Decrypt with non-matching attributes should fail with UNAUTHORIZED
  abe_user_key_t* sk = crypto_abe_keygen(mk, "viewer,editor");
  ASSERT_NE(sk, nullptr);

  uint8_t* out = nullptr;
  size_t out_len = 0;
  crabs_error_e rc = crypto_abe_decrypt(sk, ct, &out, &out_len);
  EXPECT_EQ(rc, CRABS_ERR_UNAUTHORIZED);

  crypto_abe_user_key_destroy(sk);
  crypto_abe_ciphertext_destroy(ct);
  crypto_abe_master_key_destroy(mk);
}

TEST(TestAbe, TestPolicyAnd) {
  abe_master_key_t* mk = crypto_abe_setup();
  ASSERT_NE(mk, nullptr);

  const char* policy = "AND admin editor";
  const uint8_t msg[] = "AND policy test";
  size_t msg_len = sizeof(msg);

  abe_ciphertext_t* ct = crypto_abe_encrypt(mk, msg, msg_len, policy);
  ASSERT_NE(ct, nullptr);

  // User with both attributes should decrypt
  abe_user_key_t* sk_both = crypto_abe_keygen(mk, "admin,editor");
  ASSERT_NE(sk_both, nullptr);
  uint8_t* out = nullptr;
  size_t out_len = 0;
  crabs_error_e rc = crypto_abe_decrypt(sk_both, ct, &out, &out_len);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(memcmp(out, msg, msg_len), 0);
  free(out);

  // User with only one attribute should fail
  abe_user_key_t* sk_one = crypto_abe_keygen(mk, "admin,viewer");
  ASSERT_NE(sk_one, nullptr);
  out = nullptr;
  out_len = 0;
  rc = crypto_abe_decrypt(sk_one, ct, &out, &out_len);
  EXPECT_EQ(rc, CRABS_ERR_UNAUTHORIZED);

  crypto_abe_user_key_destroy(sk_both);
  crypto_abe_user_key_destroy(sk_one);
  crypto_abe_ciphertext_destroy(ct);
  crypto_abe_master_key_destroy(mk);
}

TEST(TestAbe, TestPolicyOr) {
  abe_master_key_t* mk = crypto_abe_setup();
  ASSERT_NE(mk, nullptr);

  const char* policy = "OR admin manager";
  const uint8_t msg[] = "OR policy test";
  size_t msg_len = sizeof(msg);

  abe_ciphertext_t* ct = crypto_abe_encrypt(mk, msg, msg_len, policy);
  ASSERT_NE(ct, nullptr);

  // User with first attribute should decrypt
  abe_user_key_t* sk1 = crypto_abe_keygen(mk, "admin,viewer");
  ASSERT_NE(sk1, nullptr);
  uint8_t* out = nullptr;
  size_t out_len = 0;
  crabs_error_e rc = crypto_abe_decrypt(sk1, ct, &out, &out_len);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(memcmp(out, msg, msg_len), 0);
  free(out);

  // User with second attribute should decrypt
  abe_user_key_t* sk2 = crypto_abe_keygen(mk, "manager,viewer");
  ASSERT_NE(sk2, nullptr);
  out = nullptr;
  out_len = 0;
  rc = crypto_abe_decrypt(sk2, ct, &out, &out_len);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(memcmp(out, msg, msg_len), 0);
  free(out);

  // User with neither attribute should fail
  abe_user_key_t* sk3 = crypto_abe_keygen(mk, "viewer,auditor");
  ASSERT_NE(sk3, nullptr);
  out = nullptr;
  out_len = 0;
  rc = crypto_abe_decrypt(sk3, ct, &out, &out_len);
  EXPECT_EQ(rc, CRABS_ERR_UNAUTHORIZED);

  crypto_abe_user_key_destroy(sk1);
  crypto_abe_user_key_destroy(sk2);
  crypto_abe_user_key_destroy(sk3);
  crypto_abe_ciphertext_destroy(ct);
  crypto_abe_master_key_destroy(mk);
}

TEST(TestAbe, TestPolicyEvalSimple) {
  // Single attribute
  EXPECT_TRUE(crypto_abe_eval_policy("admin", "admin,editor"));
  EXPECT_FALSE(crypto_abe_eval_policy("admin", "viewer,editor"));
  EXPECT_TRUE(crypto_abe_eval_policy("editor", "admin,editor,viewer"));

  // Empty policy always passes
  EXPECT_TRUE(crypto_abe_eval_policy("", "admin"));
}

TEST(TestAbe, TestPolicyEvalAndOr) {
  // AND: both required
  EXPECT_TRUE(crypto_abe_eval_policy("AND admin editor", "admin,editor"));
  EXPECT_FALSE(crypto_abe_eval_policy("AND admin editor", "admin,viewer"));

  // OR: either sufficient
  EXPECT_TRUE(crypto_abe_eval_policy("OR admin manager", "admin,viewer"));
  EXPECT_TRUE(crypto_abe_eval_policy("OR admin manager", "manager,viewer"));
  EXPECT_FALSE(crypto_abe_eval_policy("OR admin manager", "viewer,editor"));
}

TEST(TestAbe, TestEncryptNullParams) {
  abe_master_key_t* mk = crypto_abe_setup();
  ASSERT_NE(mk, nullptr);

  const uint8_t msg[] = "test";
  EXPECT_EQ(crypto_abe_encrypt(nullptr, msg, sizeof(msg), "admin"), nullptr);
  EXPECT_EQ(crypto_abe_encrypt(mk, nullptr, sizeof(msg), "admin"), nullptr);
  EXPECT_EQ(crypto_abe_encrypt(mk, msg, sizeof(msg), nullptr), nullptr);

  crypto_abe_master_key_destroy(mk);
}

TEST(TestCrypto, TestSignOperation) {
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);

  const uint8_t serialized_op[] = {0x01, 0x02, 0x03, 0x04};
  uint8_t signature[CRABS_SIG_SIZE];

  crabs_error_e rc = crypto_sign_operation(
    keypair->private_key, serialized_op, sizeof(serialized_op), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  bool valid = crypto_verify_operation(
    keypair->public_key, serialized_op, sizeof(serialized_op), signature);
  EXPECT_TRUE(valid);

  crypto_ecdsa_keypair_destroy(keypair);
}

// ============================================================
// ABE-Gated Verification Tests (§10.3)
// ============================================================

class VerifyAuthTest : public ::testing::Test {
protected:
  void SetUp() override {
    mk = crypto_abe_setup();
    ASSERT_NE(mk, nullptr);
    am = attribute_machine_create("admin", admin_pk);
    ASSERT_NE(am, nullptr);
  }

  void TearDown() override {
    attribute_machine_destroy(am);
    crypto_abe_master_key_destroy(mk);
  }

  abe_master_key_t* mk = nullptr;
  attribute_machine_t* am = nullptr;
  uint8_t admin_pk[33] = {0x02};  // Compressed point prefix
};

TEST_F(VerifyAuthTest, ModeA_AuthorizedUser) {
  // Register a user with admin role
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);

  // Register alice with role:admin and department:engineering
  crabs_error_e rc = attribute_machine_register_user(am, "alice", keypair->public_key, "role:admin|department:engineering");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Sign an operation
  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  rc = crypto_sign_operation(keypair->private_key, op_data, sizeof(op_data), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Mode A: Verify alice is authorized with policy "admin"
  verify_result_t vr = crypto_verify_operation_auth(
      mk, "admin", am, op_data, sizeof(op_data),
      signature, "alice", VERIFY_MODE_A);
  EXPECT_TRUE(vr.authorized);
  EXPECT_EQ(vr.error, CRABS_SUCCESS);
  EXPECT_STREQ(vr.signer_id, "alice");

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST_F(VerifyAuthTest, ModeA_UnauthorizedUser) {
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);

  // Register alice with only "viewer" role
  crabs_error_e rc = attribute_machine_register_user(am, "alice", keypair->public_key, "role:viewer");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  rc = crypto_sign_operation(keypair->private_key, op_data, sizeof(op_data), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Policy requires "admin" but alice only has "viewer"
  verify_result_t vr = crypto_verify_operation_auth(
      mk, "admin", am, op_data, sizeof(op_data),
      signature, "alice", VERIFY_MODE_A);
  EXPECT_FALSE(vr.authorized);
  EXPECT_EQ(vr.error, CRABS_ERR_UNAUTHORIZED);

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST_F(VerifyAuthTest, ModeA_UserNotFound) {
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);

  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  crabs_error_e rc = crypto_sign_operation(keypair->private_key, op_data, sizeof(op_data), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  verify_result_t vr = crypto_verify_operation_auth(
      mk, "admin", am, op_data, sizeof(op_data),
      signature, "nonexistent", VERIFY_MODE_A);
  EXPECT_FALSE(vr.authorized);
  EXPECT_EQ(vr.error, CRABS_ERR_USER_NOT_FOUND);

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST_F(VerifyAuthTest, ModeB_AuthorizedUser) {
  ecdsa_keypair_t* keypair1 = crypto_ecdsa_generate();
  ecdsa_keypair_t* keypair2 = crypto_ecdsa_generate();
  ASSERT_NE(keypair1, nullptr);
  ASSERT_NE(keypair2, nullptr);

  // Register two users
  crabs_error_e rc = attribute_machine_register_user(am, "alice", keypair1->public_key, "role:admin");
  EXPECT_EQ(rc, CRABS_SUCCESS);
  rc = attribute_machine_register_user(am, "bob", keypair2->public_key, "role:viewer");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Sign with alice's key
  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  rc = crypto_sign_operation(keypair1->private_key, op_data, sizeof(op_data), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Mode B: Find any user matching policy "admin" with valid signature
  verify_result_t vr = crypto_verify_operation_auth(
      mk, "admin", am, op_data, sizeof(op_data),
      signature, nullptr, VERIFY_MODE_B);
  EXPECT_TRUE(vr.authorized);
  EXPECT_EQ(vr.error, CRABS_SUCCESS);
  EXPECT_STREQ(vr.signer_id, "alice");

  crypto_ecdsa_keypair_destroy(keypair1);
  crypto_ecdsa_keypair_destroy(keypair2);
}

TEST_F(VerifyAuthTest, ModeB_NoMatchingUser) {
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);

  crabs_error_e rc = attribute_machine_register_user(am, "charlie", keypair->public_key, "role:viewer");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  rc = crypto_sign_operation(keypair->private_key, op_data, sizeof(op_data), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // No user has "admin" attribute
  verify_result_t vr = crypto_verify_operation_auth(
      mk, "admin", am, op_data, sizeof(op_data),
      signature, nullptr, VERIFY_MODE_B);
  EXPECT_FALSE(vr.authorized);
  EXPECT_EQ(vr.error, CRABS_ERR_UNAUTHORIZED);

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST_F(VerifyAuthTest, EmptyPolicyAllowsAll) {
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);

  crabs_error_e rc = attribute_machine_register_user(am, "alice", keypair->public_key, "role:admin");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  rc = crypto_sign_operation(keypair->private_key, op_data, sizeof(op_data), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  verify_result_t vr = crypto_verify_operation_auth(
      mk, "", am, op_data, sizeof(op_data),
      signature, "alice", VERIFY_MODE_A);
  EXPECT_TRUE(vr.authorized);
  EXPECT_EQ(vr.error, CRABS_SUCCESS);

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST_F(VerifyAuthTest, AndPolicy) {
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);

  // Register alice with role:admin AND department:engineering
  crabs_error_e rc = attribute_machine_register_user(am, "alice", keypair->public_key, "role:admin|department:engineering");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  rc = crypto_sign_operation(keypair->private_key, op_data, sizeof(op_data), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // alice has both admin and engineering
  verify_result_t vr = crypto_verify_operation_auth(
      mk, "AND admin engineering", am, op_data, sizeof(op_data),
      signature, "alice", VERIFY_MODE_A);
  EXPECT_TRUE(vr.authorized);
  EXPECT_EQ(vr.error, CRABS_SUCCESS);

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST_F(VerifyAuthTest, NullParams) {
  const uint8_t op_data[] = {0x01};
  uint8_t sig[CRABS_SIG_SIZE] = {0};

  verify_result_t vr = crypto_verify_operation_auth(
      nullptr, "admin", am, op_data, sizeof(op_data), sig, "alice", VERIFY_MODE_A);
  EXPECT_FALSE(vr.authorized);
  EXPECT_EQ(vr.error, CRABS_ERR_INVALID_PARAM);

  vr = crypto_verify_operation_auth(
      mk, nullptr, am, op_data, sizeof(op_data), sig, "alice", VERIFY_MODE_A);
  EXPECT_FALSE(vr.authorized);
  EXPECT_EQ(vr.error, CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Key Envelope Tests (§11.2)
// ============================================================

class KeyEnvelopeTest : public ::testing::Test {
protected:
  void SetUp() override {
    mk = crypto_abe_setup();
    ASSERT_NE(mk, nullptr);
    node_key = crypto_ecdsa_generate();
    ASSERT_NE(node_key, nullptr);
    am = attribute_machine_create("admin", admin_pk);
    ASSERT_NE(am, nullptr);

    // Register alice with role:admin
    alice_key = crypto_ecdsa_generate();
    ASSERT_NE(alice_key, nullptr);
    crabs_error_e rc = attribute_machine_register_user(
        am, "alice", alice_key->public_key, "role:admin");
    EXPECT_EQ(rc, CRABS_SUCCESS);
  }

  void TearDown() override {
    crypto_ecdsa_keypair_destroy(alice_key);
    attribute_machine_destroy(am);
    crypto_ecdsa_keypair_destroy(node_key);
    crypto_abe_master_key_destroy(mk);
  }

  abe_master_key_t* mk = nullptr;
  ecdsa_keypair_t* node_key = nullptr;
  attribute_machine_t* am = nullptr;
  ecdsa_keypair_t* alice_key = nullptr;
  uint8_t admin_pk[33] = {0x02};
};

TEST_F(KeyEnvelopeTest, CreateAndVerify) {
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);

  // Compute attributes hash
  uint8_t attr_hash[CRABS_HASH_SIZE];
  crabs_error_e rc = crypto_compute_attributes_hash(alice, attr_hash);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Create envelope
  uint64_t now_ms = 1000000;
  key_envelope_t* env = crypto_key_envelope_create(
      mk, node_key->private_key, "alice", 42, attr_hash, now_ms, 0);
  ASSERT_NE(env, nullptr);

  // Check envelope fields
  EXPECT_EQ(env->format_version, KEY_ENVELOPE_FORMAT_V1);
  EXPECT_STREQ(env->user_id, "alice");
  EXPECT_EQ(env->state_version, 42u);
  EXPECT_EQ(memcmp(env->attributes_hash, attr_hash, CRABS_HASH_SIZE), 0);
  EXPECT_EQ(env->issued_at, now_ms);
  EXPECT_EQ(env->expires_at, 0u);

  // Verify with node's public key
  bool valid = crypto_key_envelope_verify(node_key->public_key, env);
  EXPECT_TRUE(valid);

  // Verify with wrong key should fail
  ecdsa_keypair_t* wrong_key = crypto_ecdsa_generate();
  ASSERT_NE(wrong_key, nullptr);
  valid = crypto_key_envelope_verify(wrong_key->public_key, env);
  EXPECT_FALSE(valid);

  crypto_ecdsa_keypair_destroy(wrong_key);
  crypto_key_envelope_destroy(env);
}

TEST_F(KeyEnvelopeTest, CreateWithExpiry) {
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);

  uint8_t attr_hash[CRABS_HASH_SIZE];
  crypto_compute_attributes_hash(alice, attr_hash);

  key_envelope_t* env = crypto_key_envelope_create(
      mk, node_key->private_key, "alice", 10, attr_hash, 1000, 5000);
  ASSERT_NE(env, nullptr);

  EXPECT_EQ(env->expires_at, 5000u);
  EXPECT_TRUE(crypto_key_envelope_verify(node_key->public_key, env));

  crypto_key_envelope_destroy(env);
}

TEST_F(KeyEnvelopeTest, NullParams) {
  uint8_t dummy_hash[CRABS_HASH_SIZE] = {0};

  EXPECT_EQ(crypto_key_envelope_create(nullptr, node_key->private_key, "alice", 1, dummy_hash, 0, 0), nullptr);
  EXPECT_EQ(crypto_key_envelope_create(mk, nullptr, "alice", 1, dummy_hash, 0, 0), nullptr);
  EXPECT_EQ(crypto_key_envelope_create(mk, node_key->private_key, nullptr, 1, dummy_hash, 0, 0), nullptr);
  EXPECT_EQ(crypto_key_envelope_create(mk, node_key->private_key, "alice", 1, nullptr, 0, 0), nullptr);
}

TEST_F(KeyEnvelopeTest, VerifyNullParams) {
  EXPECT_FALSE(crypto_key_envelope_verify(nullptr, nullptr));
  EXPECT_FALSE(crypto_key_envelope_verify(node_key->public_key, nullptr));
}

TEST_F(KeyEnvelopeTest, VerifyWrongFormatVersion) {
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);

  uint8_t attr_hash[CRABS_HASH_SIZE];
  crypto_compute_attributes_hash(alice, attr_hash);

  key_envelope_t* env = crypto_key_envelope_create(
      mk, node_key->private_key, "alice", 1, attr_hash, 0, 0);
  ASSERT_NE(env, nullptr);

  // Tamper with format version
  env->format_version = 0x99;
  EXPECT_FALSE(crypto_key_envelope_verify(node_key->public_key, env));

  crypto_key_envelope_destroy(env);
}

TEST_F(KeyEnvelopeTest, AttributesHash) {
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);

  // Same user should produce same hash
  uint8_t hash1[CRABS_HASH_SIZE];
  uint8_t hash2[CRABS_HASH_SIZE];
  crabs_error_e rc = crypto_compute_attributes_hash(alice, hash1);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  rc = crypto_compute_attributes_hash(alice, hash2);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(memcmp(hash1, hash2, CRABS_HASH_SIZE), 0);

  // Register bob with different attributes
  ecdsa_keypair_t* bob_key = crypto_ecdsa_generate();
  ASSERT_NE(bob_key, nullptr);
  rc = attribute_machine_register_user(am, "bob", bob_key->public_key, "role:viewer");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  user_t* bob = attribute_machine_find_user(am, "bob");
  ASSERT_NE(bob, nullptr);

  uint8_t bob_hash[CRABS_HASH_SIZE];
  rc = crypto_compute_attributes_hash(bob, bob_hash);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  // Different attributes should produce different hashes
  EXPECT_NE(memcmp(hash1, bob_hash, CRABS_HASH_SIZE), 0);

  crypto_ecdsa_keypair_destroy(bob_key);
}

TEST_F(KeyEnvelopeTest, AttributesHashNullParams) {
  uint8_t hash[CRABS_HASH_SIZE];
  EXPECT_EQ(crypto_compute_attributes_hash(nullptr, hash), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(crypto_compute_attributes_hash(nullptr, nullptr), CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Key Compromise Recovery Tests (§11.4)
// ============================================================

TEST_F(KeyEnvelopeTest, RevokeAndRotate) {
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  uint64_t orig_version = alice->key_version;

  recovery_result_t* result = crypto_revoke_and_rotate(
      mk, node_key->private_key, am, "alice", 1, 1000);
  ASSERT_NE(result, nullptr);
  ASSERT_NE(result->new_ecdsa_key, nullptr);
  ASSERT_NE(result->new_envelope, nullptr);

  // User should be suspended
  EXPECT_EQ(alice->status, USER_SUSPENDED);

  // Key version should be incremented
  EXPECT_EQ(alice->key_version, orig_version + 1);

  // Public key should be updated to new key
  EXPECT_EQ(memcmp(alice->public_key, result->new_ecdsa_key->public_key, 33), 0);

  // Envelope should be verifiable with node key
  EXPECT_TRUE(crypto_key_envelope_verify(node_key->public_key, result->new_envelope));

  crypto_recovery_result_destroy(result);
}

TEST_F(KeyEnvelopeTest, RevokeAndRotateUserNotFound) {
  recovery_result_t* result = crypto_revoke_and_rotate(
      mk, node_key->private_key, am, "nonexistent", 1, 1000);
  EXPECT_EQ(result, nullptr);
}

TEST_F(KeyEnvelopeTest, RevokeAndRotateNullParams) {
  EXPECT_EQ(crypto_revoke_and_rotate(nullptr, node_key->private_key, am, "alice", 1, 1000), nullptr);
  EXPECT_EQ(crypto_revoke_and_rotate(mk, nullptr, am, "alice", 1, 1000), nullptr);
  EXPECT_EQ(crypto_revoke_and_rotate(mk, node_key->private_key, nullptr, "alice", 1, 1000), nullptr);
  EXPECT_EQ(crypto_revoke_and_rotate(mk, node_key->private_key, am, nullptr, 1, 1000), nullptr);
}