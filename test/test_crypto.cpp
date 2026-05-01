#include <gtest/gtest.h>
#include <cstring>
extern "C" {
#include "../src/Crypto/crypto.h"
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

TEST(TestCrypto, TestAbeStubs) {
  // Setup should return NULL (stub)
  abe_key_t* msk = crypto_abe_setup();
  EXPECT_EQ(msk, nullptr);

  // Keygen should return NULL (stub)
  abe_key_t* sk = crypto_abe_keygen(nullptr, nullptr, "attr1,attr2");
  EXPECT_EQ(sk, nullptr);

  // Encrypt should return NULL (stub)
  const uint8_t msg[] = "test message";
  abe_ciphertext_t* ct = crypto_abe_encrypt(nullptr, msg, sizeof(msg), "policy");
  EXPECT_EQ(ct, nullptr);

  // Decrypt should return -1 (stub)
  uint8_t* out = nullptr;
  size_t out_len = 0;
  int dec_rc = crypto_abe_decrypt(nullptr, nullptr, &out, &out_len);
  EXPECT_EQ(dec_rc, -1);
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