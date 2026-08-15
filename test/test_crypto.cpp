#include <gtest/gtest.h>
#include <cstring>
extern "C" {
#include "../src/Crypto/crypto.h"
#include "../src/Attribute/attribute_machine.h"
}
#include "test_helpers.h"

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
  crypto_abe_master_key_destroy(mk);
}

TEST(TestAbe, TestKeygen) {
  abe_master_key_t* mk = crypto_abe_setup();
  ASSERT_NE(mk, nullptr);

  abe_user_key_t* sk = crypto_abe_keygen(mk, "admin,editor,auditor");
  ASSERT_NE(sk, nullptr);

  // A key from a different master must not decrypt this master's ciphertext
  // (the key is bound to the master's public params). Verify via a round-trip.
  abe_master_key_t* mk2 = crypto_abe_setup();
  ASSERT_NE(mk2, nullptr);
  abe_user_key_t* sk2 = crypto_abe_keygen(mk2, "admin");
  ASSERT_NE(sk2, nullptr);

  const uint8_t msg[] = "probe";
  abe_ciphertext_t* ct = crypto_abe_encrypt(mk, msg, sizeof(msg), "admin");
  ASSERT_NE(ct, nullptr);
  uint8_t* out = nullptr;
  size_t out_len = 0;
  // sk (from mk) can decrypt mk's ciphertext.
  EXPECT_EQ(crypto_abe_decrypt(sk, ct, &out, &out_len), CRABS_SUCCESS);
  if (out) { free(out); out = nullptr; }
  // sk2 (from mk2) cannot decrypt mk's ciphertext (different domain).
  EXPECT_NE(crypto_abe_decrypt(sk2, ct, &out, &out_len), CRABS_SUCCESS);
  if (out) { free(out); out = nullptr; }

  crypto_abe_user_key_destroy(sk);
  crypto_abe_user_key_destroy(sk2);
  crypto_abe_ciphertext_destroy(ct);
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

  // OpenABE policy grammar: lowercase "and"/"or" with parentheses.
  const char* policy = "admin and editor";
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

  const char* policy = "admin or manager";
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

  // Audit N-4: an empty policy is NOT authorized by this function. The
  // authorization path handles the "no attribute requirement" case separately
  // (it still requires a valid signature); this function returns false for
  // an empty policy so a bare call cannot be a silent free-pass.
  EXPECT_FALSE(crypto_abe_eval_policy("", "admin"));
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

// R7-09: the ABE evaluator expected prefix form but the preprocessor emitted
// infix, so compound and comparison policies always denied. Both grammars must
// evaluate correctly.
TEST(TestAbe, TestPolicyInfixAndComparison) {
  // Infix AND (as emitted by the preprocessor's _ast_to_string).
  EXPECT_TRUE(crypto_abe_eval_policy("role:admin AND dept:eng", "role:admin,dept:eng"));
  EXPECT_FALSE(crypto_abe_eval_policy("role:admin AND dept:eng", "role:admin,dept:sales"));

  // Infix OR.
  EXPECT_TRUE(crypto_abe_eval_policy("role:admin OR role:viewer", "role:viewer"));
  EXPECT_FALSE(crypto_abe_eval_policy("role:admin OR role:viewer", "role:guest"));

  // Numeric comparison against the attribute value.
  EXPECT_TRUE(crypto_abe_eval_policy("views >= 5", "views:10"));
  EXPECT_FALSE(crypto_abe_eval_policy("views >= 5", "views:3"));
  EXPECT_TRUE(crypto_abe_eval_policy("views < 5", "views:3"));
  EXPECT_FALSE(crypto_abe_eval_policy("views < 5", "views:10"));
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
  crabs_error_e rc = attribute_machine_register_user(am, "alice", keypair->public_key, "department:engineering");
  ASSERT_EQ(rc, CRABS_SUCCESS);
  rc = attribute_machine_grant_role(am, "alice", "role", "admin", "admin");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Sign an operation
  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  rc = crypto_sign_operation(keypair->private_key, op_data, sizeof(op_data), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Mode A: Verify alice is authorized with policy "role:admin" (F-1:
  // policies and attributes are matched as whole "name:value" tokens, so a
  // user with "role:admin" satisfies "role:admin" but not bare "admin").
  verify_result_t vr = crypto_verify_operation_auth(
      mk, "role:admin", am, op_data, sizeof(op_data),
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
  crabs_error_e rc = crabs_test_register_user_with_role(am, "alice", keypair->public_key, "role", "viewer");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  rc = crypto_sign_operation(keypair->private_key, op_data, sizeof(op_data), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Policy requires "role:admin" but alice only has "role:viewer"
  verify_result_t vr = crypto_verify_operation_auth(
      mk, "role:admin", am, op_data, sizeof(op_data),
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
      mk, "role:admin", am, op_data, sizeof(op_data),
      signature, "nonexistent", VERIFY_MODE_A);
  EXPECT_FALSE(vr.authorized);
  // R7-14: user existence must not leak through a distinct error code.
  EXPECT_EQ(vr.error, CRABS_ERR_UNAUTHORIZED);

  crypto_ecdsa_keypair_destroy(keypair);
}

// R7-14: Mode A must not leak user existence or status through distinct error
// codes. Nonexistent, suspended, and revoked users all yield a single
// CRABS_ERR_UNAUTHORIZED at the trust boundary.
TEST_F(VerifyAuthTest, ModeA_CollapsesUserExistenceAndStatus) {
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);
  ASSERT_EQ(crabs_test_register_user_with_role(am, "alice", keypair->public_key,
                                              "role", "admin"), CRABS_SUCCESS);

  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  ASSERT_EQ(crypto_sign_operation(keypair->private_key, op_data, sizeof(op_data),
                                    signature), CRABS_SUCCESS);

  // Nonexistent user → UNAUTHORIZED, not USER_NOT_FOUND.
  verify_result_t vr = crypto_verify_operation_auth(
      mk, "role:admin", am, op_data, sizeof(op_data),
      signature, "nonexistent", VERIFY_MODE_A);
  EXPECT_FALSE(vr.authorized);
  EXPECT_EQ(vr.error, CRABS_ERR_UNAUTHORIZED);

  // Suspended user → UNAUTHORIZED, not USER_SUSPENDED.
  ASSERT_EQ(attribute_machine_suspend_user(am, "alice"), CRABS_SUCCESS);
  vr = crypto_verify_operation_auth(
      mk, "role:admin", am, op_data, sizeof(op_data),
      signature, "alice", VERIFY_MODE_A);
  EXPECT_FALSE(vr.authorized);
  EXPECT_EQ(vr.error, CRABS_ERR_UNAUTHORIZED);

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST_F(VerifyAuthTest, ModeB_AuthorizedUser) {
  ecdsa_keypair_t* keypair1 = crypto_ecdsa_generate();
  ecdsa_keypair_t* keypair2 = crypto_ecdsa_generate();
  ASSERT_NE(keypair1, nullptr);
  ASSERT_NE(keypair2, nullptr);

  // Register two users
  crabs_error_e rc = crabs_test_register_user_with_role(am, "alice", keypair1->public_key, "role", "admin");
  EXPECT_EQ(rc, CRABS_SUCCESS);
  rc = crabs_test_register_user_with_role(am, "bob", keypair2->public_key, "role", "viewer");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Sign with alice's key
  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  rc = crypto_sign_operation(keypair1->private_key, op_data, sizeof(op_data), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Mode B: Find any user matching policy "role:admin" with valid signature
  verify_result_t vr = crypto_verify_operation_auth(
      mk, "role:admin", am, op_data, sizeof(op_data),
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

  crabs_error_e rc = crabs_test_register_user_with_role(am, "charlie", keypair->public_key, "role", "viewer");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  rc = crypto_sign_operation(keypair->private_key, op_data, sizeof(op_data), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // No user has "role:admin" attribute
  verify_result_t vr = crypto_verify_operation_auth(
      mk, "role:admin", am, op_data, sizeof(op_data),
      signature, nullptr, VERIFY_MODE_B);
  EXPECT_FALSE(vr.authorized);
  EXPECT_EQ(vr.error, CRABS_ERR_UNAUTHORIZED);

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST_F(VerifyAuthTest, EmptyPolicyAllowsAll) {
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);

  crabs_error_e rc = crabs_test_register_user_with_role(am, "alice", keypair->public_key, "role", "admin");
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
  crabs_error_e rc = attribute_machine_register_user(am, "alice", keypair->public_key, "department:engineering");
  ASSERT_EQ(rc, CRABS_SUCCESS);
  rc = attribute_machine_grant_role(am, "alice", "role", "admin", "admin");
  EXPECT_EQ(rc, CRABS_SUCCESS);

  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  rc = crypto_sign_operation(keypair->private_key, op_data, sizeof(op_data), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // alice has both role:admin and department:engineering (F-1: whole-token match)
  verify_result_t vr = crypto_verify_operation_auth(
      mk, "AND role:admin department:engineering", am, op_data, sizeof(op_data),
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

// Regression for audit F-1: a user who self-asserts "clearance:admin" (a
// non-privileged name with a privileged value) must NOT satisfy a "role:admin"
// policy. Policies and attribute strings are matched as whole "name:value"
// tokens, so "clearance:admin" != "role:admin". The prior code stripped the
// name, producing token "admin", which matched a bare "admin" policy and was
// minted a real CP-ABE key for attribute "admin".
TEST_F(VerifyAuthTest, SelfAssertValueDoesNotAuthorize) {
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);

  // alice is a regular member (no role:admin).
  ASSERT_EQ(crabs_test_register_user_with_role(am, "alice", keypair->public_key,
                                              "role", "member"), CRABS_SUCCESS);
  // Self-assert a non-privileged attribute whose value is "admin".
  ASSERT_EQ(attribute_machine_self_assert(am, "clearance", "admin", "alice"),
            CRABS_SUCCESS);

  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  ASSERT_EQ(crypto_sign_operation(keypair->private_key, op_data, sizeof(op_data),
                                    signature), CRABS_SUCCESS);

  // Namespaced policy: "role:admin" must NOT match "clearance:admin".
  verify_result_t vr = crypto_verify_operation_auth(
      mk, "role:admin", am, op_data, sizeof(op_data),
      signature, "alice", VERIFY_MODE_A);
  EXPECT_FALSE(vr.authorized);
  EXPECT_EQ(vr.error, CRABS_ERR_UNAUTHORIZED);

  // And a bare "admin" policy must also NOT match (token is "clearance:admin",
  // not "admin"). This is the defense-in-depth guarantee: even careless
  // bare-value policies cannot be satisfied by self-asserted values.
  vr = crypto_verify_operation_auth(
      mk, "admin", am, op_data, sizeof(op_data),
      signature, "alice", VERIFY_MODE_A);
  EXPECT_FALSE(vr.authorized);
  EXPECT_EQ(vr.error, CRABS_ERR_UNAUTHORIZED);

  crypto_ecdsa_keypair_destroy(keypair);
}

// Regression for audit H-C: a REVOKED user must not authorize even with a
// valid signature. All gates check status == USER_ACTIVE (whitelist), so
// REVOKED is rejected. (Previously gates checked != SUSPENDED, and REVOKED
// — which was never assigned — would have passed.)
TEST_F(VerifyAuthTest, RevokedUserRejected) {
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);
  ASSERT_EQ(crabs_test_register_user_with_role(am, "alice", keypair->public_key,
                                              "role", "admin"), CRABS_SUCCESS);

  ASSERT_EQ(attribute_machine_revoke_user(am, "alice"), CRABS_SUCCESS);

  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  ASSERT_EQ(crypto_sign_operation(keypair->private_key, op_data, sizeof(op_data),
                                    signature), CRABS_SUCCESS);

  verify_result_t vr = crypto_verify_operation_auth(
      mk, "role:admin", am, op_data, sizeof(op_data),
      signature, "alice", VERIFY_MODE_A);
  EXPECT_FALSE(vr.authorized);
  // R7-14: status must not leak through a distinct error code.
  EXPECT_EQ(vr.error, CRABS_ERR_UNAUTHORIZED);

  // Mode B must also reject a revoked user (no user satisfies the policy).
  vr = crypto_verify_operation_auth(
      mk, "role:admin", am, op_data, sizeof(op_data),
      signature, nullptr, VERIFY_MODE_B);
  EXPECT_FALSE(vr.authorized);

  crypto_ecdsa_keypair_destroy(keypair);
}

// Regression for audit R4-1: temporary attributes must use the full
// "name:value" token in the attribute string (not just the value part).
// Before the fix, _build_attr_string read temp->value ("secret") instead of
// temp->name ("clearance:secret"), so a temporary "clearance:secret" attribute
// could not satisfy a "clearance:secret" policy but could satisfy a bare
// "secret" policy — a namespace collision. Now it matches the namespaced
// policy and does not match the bare-value policy.
TEST_F(VerifyAuthTest, TempAttributeUsesFullNameColonToken) {
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);
  ASSERT_EQ(crabs_test_register_user_with_role(am, "alice", keypair->public_key,
                                              "role", "member"), CRABS_SUCCESS);

  // Issue a temporary attribute clearance:secret to alice (who has role:member).
  // The role parameter matches the attribute NAME ("role"), not the full
  // "role:member" token.
  attribute_machine_set_time(am, 1000);
  ASSERT_EQ(attribute_machine_issue_temporary(am, "clearance", "secret",
                                                 "role", 60000),
            CRABS_SUCCESS);

  const uint8_t op_data[] = {0x01, 0x02, 0x03};
  uint8_t signature[CRABS_SIG_SIZE];
  ASSERT_EQ(crypto_sign_operation(keypair->private_key, op_data, sizeof(op_data),
                                    signature), CRABS_SUCCESS);

  // The namespaced policy "clearance:secret" MUST be satisfied (the temp
  // attribute token is now "clearance:secret", not just "secret").
  verify_result_t vr = crypto_verify_operation_auth(
      mk, "clearance:secret", am, op_data, sizeof(op_data),
      signature, "alice", VERIFY_MODE_A);
  EXPECT_TRUE(vr.authorized);

  // A bare "secret" policy must NOT be satisfied — the token is
  // "clearance:secret", not "secret", so there is no namespace collision.
  vr = crypto_verify_operation_auth(
      mk, "secret", am, op_data, sizeof(op_data),
      signature, "alice", VERIFY_MODE_A);
  EXPECT_FALSE(vr.authorized);

  crypto_ecdsa_keypair_destroy(keypair);
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
    crabs_error_e rc = crabs_test_register_user_with_role(
        am, "alice", alice_key->public_key, "role", "admin");
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

  // Create envelope
  uint64_t now_ms = 1000000;
  key_envelope_t* env = crypto_key_envelope_create(
      mk, node_key->private_key, alice, 42, now_ms, 0);
  ASSERT_NE(env, nullptr);

  // Check envelope fields
  EXPECT_EQ(env->format_version, KEY_ENVELOPE_FORMAT_V1);
  EXPECT_STREQ(env->user_id, "alice");
  EXPECT_EQ(env->state_version, 42u);
  EXPECT_EQ(env->issued_at, now_ms);
  EXPECT_EQ(env->expires_at, 0u);
  EXPECT_GT(env->sk_abe_len, 0u);
  EXPECT_NE(env->sk_abe, nullptr);

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

// Regression for audit H-A: the ABE user key in the envelope is ECIES-encrypted
// to the recipient's public key, so the envelope is not shipped in cleartext.
// Decrypting with the recipient's private key recovers the ABE key; a wrong
// private key is rejected (tag mismatch).
TEST_F(KeyEnvelopeTest, EciesDecryptRoundTrip) {
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);

  key_envelope_t* env = crypto_key_envelope_create(
      mk, node_key->private_key, alice, 42, 1000, 0);
  ASSERT_NE(env, nullptr);
  ASSERT_GT(env->sk_abe_len, 33u + 12u + 16u);  // ECIES blob layout

  // Decrypt with alice's private key → recovers the ABE key.
  uint8_t plain[4096];
  size_t plain_len = 0;
  crabs_error_e rc = crypto_key_envelope_decrypt_sk(
      env, alice_key->private_key, plain, sizeof(plain), &plain_len);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_GT(plain_len, 0u);

  // The recovered plaintext should round-trip into an ABE user key (deserialize).
  abe_user_key_t* recovered = crypto_abe_user_key_deserialize(mk, plain, plain_len);
  EXPECT_NE(recovered, nullptr);
  if (recovered) crypto_abe_user_key_destroy(recovered);
  memset(plain, 0, plain_len);

  // A wrong private key must be rejected (tag mismatch → UNAUTHORIZED).
  ecdsa_keypair_t* wrong_key = crypto_ecdsa_generate();
  ASSERT_NE(wrong_key, nullptr);
  rc = crypto_key_envelope_decrypt_sk(
      env, wrong_key->private_key, plain, sizeof(plain), &plain_len);
  EXPECT_EQ(rc, CRABS_ERR_UNAUTHORIZED);
  crypto_ecdsa_keypair_destroy(wrong_key);

  crypto_key_envelope_destroy(env);
}

TEST_F(KeyEnvelopeTest, CreateWithExpiry) {
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);

  key_envelope_t* env = crypto_key_envelope_create(
      mk, node_key->private_key, alice, 10, 1000, 5000);
  ASSERT_NE(env, nullptr);

  EXPECT_EQ(env->expires_at, 5000u);
  EXPECT_TRUE(crypto_key_envelope_verify(node_key->public_key, env));

  crypto_key_envelope_destroy(env);
}

TEST_F(KeyEnvelopeTest, NullParams) {
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);

  EXPECT_EQ(crypto_key_envelope_create(nullptr, node_key->private_key, alice, 1, 0, 0), nullptr);
  EXPECT_EQ(crypto_key_envelope_create(mk, nullptr, alice, 1, 0, 0), nullptr);
  EXPECT_EQ(crypto_key_envelope_create(mk, node_key->private_key, nullptr, 1, 0, 0), nullptr);
}

TEST_F(KeyEnvelopeTest, VerifyNullParams) {
  EXPECT_FALSE(crypto_key_envelope_verify(nullptr, nullptr));
  EXPECT_FALSE(crypto_key_envelope_verify(node_key->public_key, nullptr));
}

TEST_F(KeyEnvelopeTest, VerifyWrongFormatVersion) {
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);

  key_envelope_t* env = crypto_key_envelope_create(
      mk, node_key->private_key, alice, 1, 0, 0);
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
  rc = crabs_test_register_user_with_role(am, "bob", bob_key->public_key, "role", "viewer");
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

  // Audit H-B: node-blind rotation — the caller supplies the user's new
  // public key; the node records it and issues an envelope but never learns
  // the private key.
  ecdsa_keypair_t* user_new_key = crypto_ecdsa_generate();
  ASSERT_NE(user_new_key, nullptr);

  recovery_result_t* result = crypto_revoke_and_rotate(
      mk, node_key->private_key, am, "alice", user_new_key->public_key, 1, 1000);
  ASSERT_NE(result, nullptr);
  ASSERT_NE(result->new_envelope, nullptr);

  // User should be suspended
  EXPECT_EQ(alice->status, USER_SUSPENDED);

  // Key version should be incremented
  EXPECT_EQ(alice->key_version, orig_version + 1);

  // Public key should be updated to the user-supplied key
  EXPECT_EQ(memcmp(alice->public_key, user_new_key->public_key, 33), 0);
  EXPECT_EQ(memcmp(alice->public_key, result->new_public_key, 33), 0);

  // Envelope should be verifiable with node key
  EXPECT_TRUE(crypto_key_envelope_verify(node_key->public_key, result->new_envelope));

  crypto_recovery_result_destroy(result);
  crypto_ecdsa_keypair_destroy(user_new_key);
}

TEST_F(KeyEnvelopeTest, RevokeAndRotateUserNotFound) {
  ecdsa_keypair_t* user_new_key = crypto_ecdsa_generate();
  recovery_result_t* result = crypto_revoke_and_rotate(
      mk, node_key->private_key, am, "nonexistent", user_new_key->public_key, 1, 1000);
  EXPECT_EQ(result, nullptr);
  crypto_ecdsa_keypair_destroy(user_new_key);
}

TEST_F(KeyEnvelopeTest, RevokeAndRotateNullParams) {
  ecdsa_keypair_t* user_new_key = crypto_ecdsa_generate();
  EXPECT_EQ(crypto_revoke_and_rotate(nullptr, node_key->private_key, am, "alice", user_new_key->public_key, 1, 1000), nullptr);
  EXPECT_EQ(crypto_revoke_and_rotate(mk, nullptr, am, "alice", user_new_key->public_key, 1, 1000), nullptr);
  EXPECT_EQ(crypto_revoke_and_rotate(mk, node_key->private_key, nullptr, "alice", user_new_key->public_key, 1, 1000), nullptr);
  EXPECT_EQ(crypto_revoke_and_rotate(mk, node_key->private_key, am, nullptr, user_new_key->public_key, 1, 1000), nullptr);
  EXPECT_EQ(crypto_revoke_and_rotate(mk, node_key->private_key, am, "alice", nullptr, 1, 1000), nullptr);
  crypto_ecdsa_keypair_destroy(user_new_key);
}

// R7-06: an invalid new public key must be rejected BEFORE any state mutation.
// The prior code suspended the user and overwrote user->public_key first, then
// failed envelope creation — permanently bricking the user record.
TEST_F(KeyEnvelopeTest, RevokeAndRotateInvalidKeyLeavesUserIntact) {
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  uint8_t orig_pk[33];
  memcpy(orig_pk, alice->public_key, 33);
  uint64_t orig_version = alice->key_version;

  // Not a valid compressed secp256k1 point (all zeros).
  uint8_t invalid_pk[33];
  memset(invalid_pk, 0, 33);

  recovery_result_t* result = crypto_revoke_and_rotate(
      mk, node_key->private_key, am, "alice", invalid_pk, 1, 1000);
  EXPECT_EQ(result, nullptr);

  // User must be untouched: still active, key unchanged, version unchanged.
  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->status, USER_ACTIVE);
  EXPECT_EQ(memcmp(alice->public_key, orig_pk, 33), 0);
  EXPECT_EQ(alice->key_version, orig_version);
}