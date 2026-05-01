//
// CRABS-49: Signature VTable & Registry Tests
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/Crypto/sig_scheme.h"
#include "../src/Crypto/crypto.h"
#include "../src/CRABS/crabs.h"
}

// ============================================================
// Scheme Enum Values
// ============================================================

TEST(TestSigScheme, EnumValues) {
  EXPECT_EQ(SCHEME_UNSPECIFIED, 0x00);
  EXPECT_EQ(ECDSA_SECP256K1, 0x01);
  EXPECT_EQ(ED25519, 0x03);
  EXPECT_EQ(DILITHIUM_3, 0x09);
  EXPECT_EQ(SCHEME_CUSTOM, 0xFF);
}

// ============================================================
// Registry: Initialization & Lookup
// ============================================================

TEST(TestSigScheme, InitRegistersECDSA) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);
  EXPECT_EQ(vt->scheme_id, ECDSA_SECP256K1);
  EXPECT_STREQ(vt->name, "ECDSA secp256k1");
}

TEST(TestSigScheme, GetUnregisteredReturnsNull) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ED25519);
  EXPECT_EQ(vt, nullptr);
}

TEST(TestSigScheme, GetUnspecifiedReturnsNull) {
  const signature_vtable_t* vt = crypto_sig_scheme_get(SCHEME_UNSPECIFIED);
  EXPECT_EQ(vt, nullptr);
}

// ============================================================
// Registry: List & Count
// ============================================================

TEST(TestSigScheme, CountAfterInit) {
  crypto_sig_scheme_init();
  EXPECT_EQ(crypto_sig_scheme_count(), 1u);
}

TEST(TestSigScheme, ListSchemes) {
  crypto_sig_scheme_init();
  signature_scheme_e schemes[32];
  uint32_t count = crypto_sig_scheme_list(schemes, 32);
  EXPECT_EQ(count, 1u);
  EXPECT_EQ(schemes[0], ECDSA_SECP256K1);
}

TEST(TestSigScheme, ListWithSmallBuffer) {
  crypto_sig_scheme_init();
  signature_scheme_e schemes[1];
  uint32_t count = crypto_sig_scheme_list(schemes, 1);
  EXPECT_EQ(count, 1u);
}

// ============================================================
// Registry: Duplicate Registration
// ============================================================

TEST(TestSigScheme, RegisterDuplicateFails) {
  crypto_sig_scheme_init();
  signature_vtable_t dup = {};
  dup.scheme_id = ECDSA_SECP256K1;
  dup.generate_keypair = (sig_generate_keypair_fn)1;
  dup.sign = (sig_sign_fn)1;
  dup.verify = (sig_verify_fn)1;
  crabs_error_e rc = crypto_sig_scheme_register(&dup);
  EXPECT_EQ(rc, CRABS_ERR_SCHEME_ALREADY_REGISTERED);
}

// ============================================================
// Registry: Null Param Guards
// ============================================================

TEST(TestSigScheme, RegisterNullVtable) {
  EXPECT_EQ(crypto_sig_scheme_register(nullptr), CRABS_ERR_INVALID_PARAM);
}

TEST(TestSigScheme, RegisterNullRequiredFn) {
  signature_vtable_t vt = {};
  vt.scheme_id = (signature_scheme_e)0xF1;
  // generate_keypair is NULL
  vt.sign = (sig_sign_fn)1;
  vt.verify = (sig_verify_fn)1;
  EXPECT_EQ(crypto_sig_scheme_register(&vt), CRABS_ERR_INVALID_PARAM);

  vt.scheme_id = (signature_scheme_e)0xF2;
  vt.generate_keypair = (sig_generate_keypair_fn)1;
  vt.sign = nullptr;
  EXPECT_EQ(crypto_sig_scheme_register(&vt), CRABS_ERR_INVALID_PARAM);

  vt.scheme_id = (signature_scheme_e)0xF3;
  vt.sign = (sig_sign_fn)1;
  vt.verify = nullptr;
  EXPECT_EQ(crypto_sig_scheme_register(&vt), CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Scheme Properties
// ============================================================

TEST(TestSigScheme, ECDSAProperties) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  const scheme_properties_t* p = &vt->properties;
  EXPECT_EQ(p->scheme_id, ECDSA_SECP256K1);
  EXPECT_EQ(p->security_level, 2);
  EXPECT_FALSE(p->is_post_quantum);
  EXPECT_EQ(p->public_key_size, 33u);
  EXPECT_EQ(p->secret_key_size, 32u);
  EXPECT_EQ(p->signature_size, 64u);
  EXPECT_FALSE(p->supports_batch_verification);
  EXPECT_FALSE(p->supports_aggregation);
  EXPECT_FALSE(p->supports_threshold);
}

// ============================================================
// ECDSA VTable Round-Trip: Keypair → Sign → Verify
// ============================================================

TEST(TestSigScheme, ECDSAGenerateKeypair) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  uint8_t pk[33];
  uint32_t pk_len = sizeof(pk);
  uint8_t sk[32];
  uint32_t sk_len = sizeof(sk);

  crabs_error_e rc = vt->generate_keypair(pk, &pk_len, sk, &sk_len);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(pk_len, 33u);
  EXPECT_EQ(sk_len, 32u);
  EXPECT_TRUE(pk[0] == 0x02 || pk[0] == 0x03);
}

TEST(TestSigScheme, ECDSASignVerifyRoundTrip) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  uint8_t pk[33]; uint32_t pk_len = sizeof(pk);
  uint8_t sk[32]; uint32_t sk_len = sizeof(sk);
  ASSERT_EQ(vt->generate_keypair(pk, &pk_len, sk, &sk_len), CRABS_SUCCESS);

  const uint8_t msg[] = "hello CRABS v1.3 sig scheme";
  uint8_t sig[CRABS_SIG_SIZE]; uint32_t sig_len = sizeof(sig);
  crabs_error_e rc = vt->sign(sk, sk_len, msg, sizeof(msg), sig, &sig_len);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(sig_len, (uint32_t)CRABS_SIG_SIZE);

  rc = vt->verify(pk, pk_len, msg, sizeof(msg), sig, sig_len);
  EXPECT_EQ(rc, CRABS_SUCCESS);
}

TEST(TestSigScheme, ECDSAVerifyWrongMessageFails) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  uint8_t pk[33]; uint32_t pk_len = sizeof(pk);
  uint8_t sk[32]; uint32_t sk_len = sizeof(sk);
  ASSERT_EQ(vt->generate_keypair(pk, &pk_len, sk, &sk_len), CRABS_SUCCESS);

  const uint8_t msg[] = "correct message";
  uint8_t sig[CRABS_SIG_SIZE]; uint32_t sig_len = sizeof(sig);
  ASSERT_EQ(vt->sign(sk, sk_len, msg, sizeof(msg), sig, &sig_len), CRABS_SUCCESS);

  const uint8_t wrong_msg[] = "wrong message";
  crabs_error_e rc = vt->verify(pk, pk_len, wrong_msg, sizeof(wrong_msg), sig, sig_len);
  EXPECT_EQ(rc, CRABS_ERR_CRYPTOGRAPHIC_ERROR);
}

TEST(TestSigScheme, ECDSAVerifyWrongKeyFails) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  uint8_t pk1[33]; uint32_t pk1_len = sizeof(pk1);
  uint8_t sk1[32]; uint32_t sk1_len = sizeof(sk1);
  ASSERT_EQ(vt->generate_keypair(pk1, &pk1_len, sk1, &sk1_len), CRABS_SUCCESS);

  uint8_t pk2[33]; uint32_t pk2_len = sizeof(pk2);
  uint8_t sk2[32]; uint32_t sk2_len = sizeof(sk2);
  ASSERT_EQ(vt->generate_keypair(pk2, &pk2_len, sk2, &sk2_len), CRABS_SUCCESS);

  const uint8_t msg[] = "test message";
  uint8_t sig[CRABS_SIG_SIZE]; uint32_t sig_len = sizeof(sig);
  ASSERT_EQ(vt->sign(sk1, sk1_len, msg, sizeof(msg), sig, &sig_len), CRABS_SUCCESS);

  crabs_error_e rc = vt->verify(pk2, pk2_len, msg, sizeof(msg), sig, sig_len);
  EXPECT_EQ(rc, CRABS_ERR_CRYPTOGRAPHIC_ERROR);
}

// ============================================================
// Null Param Guards for VTable Operations
// ============================================================

TEST(TestSigScheme, ECDSAGenerateKeypairNullParams) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  uint8_t buf[33]; uint32_t len = sizeof(buf);
  EXPECT_EQ(vt->generate_keypair(nullptr, &len, buf, &len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->generate_keypair(buf, nullptr, buf, &len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->generate_keypair(buf, &len, nullptr, &len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->generate_keypair(buf, &len, buf, nullptr), CRABS_ERR_INVALID_PARAM);
}

TEST(TestSigScheme, ECDSASignNullParams) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  uint8_t sk[32]; uint32_t sk_len = 32;
  uint8_t msg[] = "test"; uint32_t msg_len = 4;
  uint8_t sig[64]; uint32_t sig_len = 64;

  EXPECT_EQ(vt->sign(nullptr, sk_len, msg, msg_len, sig, &sig_len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->sign(sk, sk_len, nullptr, msg_len, sig, &sig_len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->sign(sk, sk_len, msg, msg_len, nullptr, &sig_len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->sign(sk, sk_len, msg, msg_len, sig, nullptr), CRABS_ERR_INVALID_PARAM);
}

TEST(TestSigScheme, ECDSAVerifyNullParams) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  uint8_t pk[33]; uint32_t pk_len = 33;
  uint8_t msg[] = "test"; uint32_t msg_len = 4;
  uint8_t sig[64]; uint32_t sig_len = 64;

  EXPECT_EQ(vt->verify(nullptr, pk_len, msg, msg_len, sig, sig_len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->verify(pk, pk_len, nullptr, msg_len, sig, sig_len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->verify(pk, pk_len, msg, msg_len, nullptr, sig_len), CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Optional VTable Functions Are NULL for ECDSA
// ============================================================

TEST(TestSigScheme, ECDSAOptionalFunctionsNull) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);
  EXPECT_EQ(vt->verify_batch, nullptr);
  EXPECT_EQ(vt->aggregate_signatures, nullptr);
  EXPECT_EQ(vt->export_public_key, nullptr);
  EXPECT_EQ(vt->export_secret_key, nullptr);
  EXPECT_EQ(vt->import_public_key, nullptr);
  EXPECT_EQ(vt->import_secret_key, nullptr);
}