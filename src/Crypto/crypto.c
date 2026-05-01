//
// Created by victor on 4/30/25.
//

#include "crypto.h"
#include "../Util/allocator.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <string.h>

// ============================================================
// Internal: Convert OpenSSL DER signature to raw r||s format
// ============================================================
static int _der_to_raw(const uint8_t* der, size_t der_len,
                        uint8_t raw[CRABS_SIG_SIZE]) {
  ECDSA_SIG* sig = ECDSA_SIG_new();
  if (!sig) return -1;

  const unsigned char* p = der;
  if (d2i_ECDSA_SIG(&sig, &p, (long)der_len) == NULL) {
    ECDSA_SIG_free(sig);
    return -1;
  }

  const BIGNUM* r = NULL;
  const BIGNUM* s = NULL;
  ECDSA_SIG_get0(sig, &r, &s);

  memset(raw, 0, CRABS_SIG_SIZE);
  BN_bn2binpad(r, raw, 32);
  BN_bn2binpad(s, raw + 32, 32);

  ECDSA_SIG_free(sig);
  return 0;
}

// ============================================================
// Internal: Convert raw r||s signature to OpenSSL DER format
// ============================================================
static int _raw_to_der(const uint8_t raw[CRABS_SIG_SIZE],
                        uint8_t** der, size_t* der_len) {
  BIGNUM* r = BN_bin2bn(raw, 32, NULL);
  BIGNUM* s = BN_bin2bn(raw + 32, 32, NULL);
  if (!r || !s) {
    BN_free(r);
    BN_free(s);
    return -1;
  }

  ECDSA_SIG* sig = ECDSA_SIG_new();
  if (!sig) {
    BN_free(r);
    BN_free(s);
    return -1;
  }

  ECDSA_SIG_set0(sig, r, s); // sig takes ownership of r, s

  unsigned char* buf = NULL;
  int len = i2d_ECDSA_SIG(sig, &buf);
  ECDSA_SIG_free(sig);

  if (len < 0) return -1;

  *der = buf;
  *der_len = (size_t)len;
  return 0;
}

// ============================================================
// Internal: Create EC_KEY from raw private key bytes
// ============================================================
static EC_KEY* _eckey_from_private(const uint8_t private_key[32]) {
  EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
  if (!eckey) return NULL;

  BIGNUM* bn_priv = BN_bin2bn(private_key, 32, NULL);
  if (!bn_priv) {
    EC_KEY_free(eckey);
    return NULL;
  }

  if (EC_KEY_set_private_key(eckey, bn_priv) != 1) {
    BN_free(bn_priv);
    EC_KEY_free(eckey);
    return NULL;
  }

  // Derive public key from private key
  const EC_GROUP* group = EC_KEY_get0_group(eckey);
  EC_POINT* pub_point = EC_POINT_new(group);
  if (!pub_point) {
    BN_free(bn_priv);
    EC_KEY_free(eckey);
    return NULL;
  }

  if (EC_POINT_mul(group, pub_point, bn_priv, NULL, NULL, NULL) != 1) {
    EC_POINT_free(pub_point);
    BN_free(bn_priv);
    EC_KEY_free(eckey);
    return NULL;
  }

  if (EC_KEY_set_public_key(eckey, pub_point) != 1) {
    EC_POINT_free(pub_point);
    BN_free(bn_priv);
    EC_KEY_free(eckey);
    return NULL;
  }

  EC_POINT_free(pub_point);
  BN_free(bn_priv);
  return eckey;
}

// ============================================================
// Internal: Create EC_KEY from raw compressed public key bytes
// ============================================================
static EC_KEY* _eckey_from_public(const uint8_t public_key[33]) {
  EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
  if (!eckey) return NULL;

  const unsigned char* p = public_key;
  if (o2i_ECPublicKey(&eckey, &p, 33) == NULL) {
    EC_KEY_free(eckey);
    return NULL;
  }

  return eckey;
}

// ============================================================
// ECDSA Key Pair Generation
// ============================================================
ecdsa_keypair_t* crypto_ecdsa_generate(void) {
  EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
  if (!eckey) return NULL;

  if (EC_KEY_generate_key(eckey) != 1) {
    EC_KEY_free(eckey);
    return NULL;
  }

  ecdsa_keypair_t* keypair = get_clear_memory(sizeof(ecdsa_keypair_t));
  if (!keypair) {
    EC_KEY_free(eckey);
    return NULL;
  }

  // Extract private key
  const BIGNUM* bn_priv = EC_KEY_get0_private_key(eckey);
  if (BN_num_bytes(bn_priv) > 32) {
    EC_KEY_free(eckey);
    free(keypair);
    return NULL;
  }
  BN_bn2binpad(bn_priv, keypair->private_key, 32);

  // Extract compressed public key
  point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;
  size_t pub_len = EC_POINT_point2oct(
    EC_KEY_get0_group(eckey),
    EC_KEY_get0_public_key(eckey),
    form,
    NULL, 0, NULL);
  if (pub_len != 33) {
    EC_KEY_free(eckey);
    free(keypair);
    return NULL;
  }

  EC_POINT_point2oct(
    EC_KEY_get0_group(eckey),
    EC_KEY_get0_public_key(eckey),
    form,
    keypair->public_key, 33, NULL);

  EC_KEY_free(eckey);
  return keypair;
}

// ============================================================
// ECDSA Keypair Destroy
// ============================================================
void crypto_ecdsa_keypair_destroy(ecdsa_keypair_t* keypair) {
  if (keypair) {
    free(keypair);
  }
}

// ============================================================
// ECDSA Signing
// ============================================================
crabs_error_e crypto_ecdsa_sign(const uint8_t private_key[32],
                                 const uint8_t* message, size_t message_len,
                                 uint8_t signature[CRABS_SIG_SIZE]) {
  if (!private_key || !message || !signature) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Hash the message with SHA-256
  uint8_t digest[CRABS_HASH_SIZE];
  crabs_error_e hash_rc = crypto_sha256(message, message_len, digest);
  if (hash_rc != CRABS_SUCCESS) {
    return hash_rc;
  }

  // Create EC_KEY from private key
  EC_KEY* eckey = _eckey_from_private(private_key);
  if (!eckey) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  // Sign the digest (OpenSSL produces DER-encoded signature)
  unsigned char der_sig[128];
  unsigned int der_sig_len = 0;
  if (ECDSA_sign(0, digest, CRABS_HASH_SIZE, der_sig, &der_sig_len, eckey) != 1) {
    EC_KEY_free(eckey);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  // Convert DER to raw r||s format
  if (_der_to_raw(der_sig, der_sig_len, signature) != 0) {
    EC_KEY_free(eckey);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  EC_KEY_free(eckey);
  return CRABS_SUCCESS;
}

// ============================================================
// ECDSA Verification
// ============================================================
bool crypto_ecdsa_verify(const uint8_t public_key[33],
                          const uint8_t* message, size_t message_len,
                          const uint8_t signature[CRABS_SIG_SIZE]) {
  if (!public_key || !message || !signature) {
    return false;
  }

  // Hash the message with SHA-256
  uint8_t digest[CRABS_HASH_SIZE];
  if (crypto_sha256(message, message_len, digest) != CRABS_SUCCESS) {
    return false;
  }

  // Create EC_KEY from public key
  EC_KEY* eckey = _eckey_from_public(public_key);
  if (!eckey) {
    return false;
  }

  // Convert raw r||s to DER format for verification
  uint8_t* der_sig = NULL;
  size_t der_sig_len = 0;
  if (_raw_to_der(signature, &der_sig, &der_sig_len) != 0) {
    EC_KEY_free(eckey);
    return false;
  }

  // Verify the signature
  int rc = ECDSA_verify(0, digest, CRABS_HASH_SIZE,
                         der_sig, (int)der_sig_len, eckey);

  OPENSSL_free(der_sig);
  EC_KEY_free(eckey);
  return rc == 1;
}

// ============================================================
// SHA-256 Hash
// ============================================================
crabs_error_e crypto_sha256(const uint8_t* data, size_t len,
                             uint8_t hash[CRABS_HASH_SIZE]) {
  if (!data || !hash) {
    return CRABS_ERR_INVALID_PARAM;
  }

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
    EVP_MD_CTX_free(ctx);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  if (EVP_DigestUpdate(ctx, data, len) != 1) {
    EVP_MD_CTX_free(ctx);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  unsigned int hash_len = 0;
  if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
    EVP_MD_CTX_free(ctx);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  EVP_MD_CTX_free(ctx);

  if (hash_len != CRABS_HASH_SIZE) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  return CRABS_SUCCESS;
}

// ============================================================
// CSPRNG
// ============================================================
crabs_error_e crypto_random_bytes(uint8_t* buf, size_t len) {
  if (!buf) {
    return CRABS_ERR_INVALID_PARAM;
  }

  if (RAND_bytes(buf, (int)len) != 1) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  return CRABS_SUCCESS;
}

// ============================================================
// ABE Stub Implementations
// ============================================================

abe_key_t* crypto_abe_setup(void) {
  // Stub: not yet implemented
  return NULL;
}

void crypto_abe_key_destroy(abe_key_t* key) {
  if (key) {
    free(key->data);
    free(key);
  }
}

abe_key_t* crypto_abe_keygen(const abe_key_t* msk, const abe_key_t* mpk, const char* attrs) {
  // Stub: not yet implemented
  (void)msk;
  (void)mpk;
  (void)attrs;
  return NULL;
}

abe_ciphertext_t* crypto_abe_encrypt(const abe_key_t* mpk, const uint8_t* msg, size_t msg_len, const char* policy) {
  // Stub: not yet implemented
  (void)mpk;
  (void)msg;
  (void)msg_len;
  (void)policy;
  return NULL;
}

void crypto_abe_ciphertext_destroy(abe_ciphertext_t* ct) {
  if (ct) {
    free(ct->data);
    free(ct);
  }
}

int crypto_abe_decrypt(const abe_key_t* sk, const abe_ciphertext_t* ct, uint8_t** out, size_t* out_len) {
  // Stub: not yet implemented
  (void)sk;
  (void)ct;
  (void)out;
  (void)out_len;
  return -1;
}

// ============================================================
// Operation Signing (§10.2.1 + §7.5)
// ============================================================

crabs_error_e crypto_sign_operation(const uint8_t private_key[32],
                                     const uint8_t* serialized_op, size_t op_len,
                                     uint8_t signature[CRABS_SIG_SIZE]) {
  return crypto_ecdsa_sign(private_key, serialized_op, op_len, signature);
}

bool crypto_verify_operation(const uint8_t public_key[33],
                              const uint8_t* serialized_op, size_t op_len,
                              const uint8_t signature[CRABS_SIG_SIZE]) {
  return crypto_ecdsa_verify(public_key, serialized_op, op_len, signature);
}