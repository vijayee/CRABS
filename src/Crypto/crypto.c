//
// Created by victor on 4/30/25.
//

#include "crypto.h"
#include "sig_scheme.h"
#include "../Util/allocator.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/hmac.h>
#include <string.h>
#include <ctype.h>

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
    OPENSSL_cleanse(keypair->private_key, 32);
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
// ABE Policy Evaluation (§10.1) — AND/OR/attribute matching
// ============================================================

static bool _attr_in_list(const char* attr, const char* attr_list) {
  if (!attr || !attr_list) return false;

  size_t attr_len = strlen(attr);
  const char* p = attr_list;

  while (*p) {
    while (*p == ' ' || *p == ',') p++;
    if (*p == '\0') break;

    const char* start = p;
    while (*p && *p != ',') p++;
    size_t tok_len = (size_t)(p - start);

    while (tok_len > 0 && start[tok_len - 1] == ' ') tok_len--;

    if (tok_len == attr_len && strncmp(start, attr, attr_len) == 0) {
      return true;
    }
  }
  return false;
}

static bool _eval_policy_expr(const char** pp, const char* attrs) {
  while (**pp == ' ') (*pp)++;

  if (strncmp(*pp, "AND", 3) == 0 && !isalpha((unsigned char)(*pp)[3])) {
    // AND node: (left right) — both must match
    *pp += 3;
    while (**pp == ' ') (*pp)++;
    bool left = _eval_policy_expr(pp, attrs);
    bool right = _eval_policy_expr(pp, attrs);
    return left && right;
  }

  if (strncmp(*pp, "OR", 2) == 0 && !isalpha((unsigned char)(*pp)[2])) {
    // OR node: either must match
    *pp += 2;
    while (**pp == ' ') (*pp)++;
    bool left = _eval_policy_expr(pp, attrs);
    bool right = _eval_policy_expr(pp, attrs);
    return left || right;
  }

  if (**pp == '(') {
    (*pp)++;
    bool result = _eval_policy_expr(pp, attrs);
    while (**pp == ' ') (*pp)++;
    if (**pp == ')') (*pp)++;
    return result;
  }

  // Parse attribute token
  const char* start = *pp;
  while (**pp && **pp != ' ' && **pp != ')' && **pp != ',') (*pp)++;
  size_t len = (size_t)(*pp - start);
  if (len == 0) return false;

  char attr[CRABS_MAX_POLICY_EXPR];
  if (len >= sizeof(attr)) len = sizeof(attr) - 1;
  memcpy(attr, start, len);
  attr[len] = '\0';

  return _attr_in_list(attr, attrs);
}

bool crypto_abe_eval_policy(const char* policy, const char* attrs) {
  if (!policy || !attrs) return false;
  if (strlen(policy) == 0) return true;

  const char* p = policy;
  bool result = _eval_policy_expr(&p, attrs);
  return result;
}

// ============================================================
// ABE Setup — Generate MSK and derive MPK (§10.1)
// ============================================================

abe_master_key_t* crypto_abe_setup(void) {
  abe_master_key_t* mk = get_clear_memory(sizeof(abe_master_key_t));
  if (!mk) return NULL;

  if (crypto_random_bytes(mk->msk, ABE_MASTER_KEY_SIZE) != CRABS_SUCCESS) {
    free(mk);
    return NULL;
  }

  if (crypto_sha256(mk->msk, ABE_MASTER_KEY_SIZE, mk->mpk) != CRABS_SUCCESS) {
    OPENSSL_cleanse(mk->msk, ABE_MASTER_KEY_SIZE);
    free(mk);
    return NULL;
  }

  return mk;
}

void crypto_abe_master_key_destroy(abe_master_key_t* mk) {
  if (mk) {
    OPENSSL_cleanse(mk->msk, ABE_MASTER_KEY_SIZE);
    free(mk);
  }
}

// ============================================================
// ABE Keygen — Derive user secret key from MSK + attrs (§10.1)
// ============================================================

static uint32_t _count_attrs(const char* attrs) {
  if (!attrs || *attrs == '\0') return 0;
  uint32_t count = 1;
  const char* p = attrs;
  while (*p) {
    if (*p == ',') count++;
    p++;
  }
  return count;
}

abe_user_key_t* crypto_abe_keygen(const abe_master_key_t* mk, const char* attrs) {
  if (!mk || !attrs) return NULL;

  abe_user_key_t* sk = get_clear_memory(sizeof(abe_user_key_t));
  if (!sk) return NULL;

  strncpy(sk->attrs, attrs, CRABS_MAX_POLICY_EXPR - 1);
  sk->attrs[CRABS_MAX_POLICY_EXPR - 1] = '\0';
  sk->attr_count = _count_attrs(sk->attrs);

  // Store MPK in user key for simulated ABE key derivation
  // In production CP-ABE, this would be a proper attribute-based secret key
  memcpy(sk->key, mk->mpk, ABE_MASTER_KEY_SIZE);

  return sk;
}

void crypto_abe_user_key_destroy(abe_user_key_t* sk) {
  if (sk) {
    OPENSSL_cleanse(sk->key, ABE_MASTER_KEY_SIZE);
    free(sk);
  }
}

// ============================================================
// ABE Encrypt — AES-256-GCM with policy-derived key (§10.1)
// ============================================================

static crabs_error_e _derive_encryption_key(const abe_master_key_t* mk,
                                              const char* policy,
                                              uint8_t key[32]) {
  // Key = HMAC-SHA256(MPK, policy)
  // Both encrypt and decrypt can derive this if they have MPK
  unsigned int hmac_len = 32;
  if (!HMAC(EVP_sha256(), mk->mpk, ABE_MASTER_KEY_SIZE,
             (const unsigned char*)policy, strlen(policy),
             key, &hmac_len)) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  return CRABS_SUCCESS;
}

static crabs_error_e _derive_decryption_key(const abe_user_key_t* sk,
                                              const char* policy,
                                              uint8_t key[32]) {
  // Same derivation: HMAC-SHA256(MPK, policy)
  // We embed MPK in the user key for simulation purposes
  // In production ABE, this would use bilinear pairings
  unsigned int hmac_len = 32;
  if (!HMAC(EVP_sha256(), sk->key, ABE_MASTER_KEY_SIZE,
             (const unsigned char*)policy, strlen(policy),
             key, &hmac_len)) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  return CRABS_SUCCESS;
}

static crabs_error_e _aes_gcm_encrypt(const uint8_t key[32],
                                        const uint8_t* msg, size_t msg_len,
                                        uint8_t nonce[ABE_NONCE_SIZE],
                                        uint8_t tag[ABE_TAG_SIZE],
                                        uint8_t** ct_out, size_t* ct_len) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;

  if (crypto_random_bytes(nonce, ABE_NONCE_SIZE) != CRABS_SUCCESS) {
    EVP_CIPHER_CTX_free(ctx);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ABE_NONCE_SIZE, NULL) != 1 ||
      EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  *ct_out = get_clear_memory(msg_len + 16);
  if (!*ct_out) {
    EVP_CIPHER_CTX_free(ctx);
    return CRABS_ERR_OOM;
  }

  int out_len = 0;
  if (EVP_EncryptUpdate(ctx, *ct_out, &out_len, msg, (int)msg_len) != 1) {
    free(*ct_out);
    *ct_out = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  *ct_len = (size_t)out_len;

  int final_len = 0;
  if (EVP_EncryptFinal_ex(ctx, *ct_out + out_len, &final_len) != 1) {
    free(*ct_out);
    *ct_out = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  *ct_len += (size_t)final_len;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ABE_TAG_SIZE, tag) != 1) {
    free(*ct_out);
    *ct_out = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  EVP_CIPHER_CTX_free(ctx);
  return CRABS_SUCCESS;
}

abe_ciphertext_t* crypto_abe_encrypt(const abe_master_key_t* mk,
                                       const uint8_t* msg, size_t msg_len,
                                       const char* policy) {
  if (!mk || !msg || !policy) return NULL;

  uint8_t enc_key[32];
  if (_derive_encryption_key(mk, policy, enc_key) != CRABS_SUCCESS) {
    return NULL;
  }

  abe_ciphertext_t* ct = get_clear_memory(sizeof(abe_ciphertext_t));
  if (!ct) {
    OPENSSL_cleanse(enc_key, sizeof(enc_key));
    return NULL;
  }

  strncpy(ct->policy, policy, CRABS_MAX_POLICY_EXPR - 1);
  ct->policy[CRABS_MAX_POLICY_EXPR - 1] = '\0';

  crabs_error_e rc = _aes_gcm_encrypt(enc_key, msg, msg_len,
                                        ct->nonce, ct->tag,
                                        &ct->ciphertext, &ct->ct_len);
  if (rc != CRABS_SUCCESS) {
    OPENSSL_cleanse(enc_key, sizeof(enc_key));
    free(ct);
    return NULL;
  }

  OPENSSL_cleanse(enc_key, sizeof(enc_key));
  return ct;
}

void crypto_abe_ciphertext_destroy(abe_ciphertext_t* ct) {
  if (ct) {
    if (ct->ciphertext) {
      OPENSSL_cleanse(ct->ciphertext, ct->ct_len);
      free(ct->ciphertext);
    }
    free(ct);
  }
}

// ============================================================
// ABE Decrypt — Check policy + AES-256-GCM decrypt (§10.1)
// ============================================================

static crabs_error_e _aes_gcm_decrypt(const uint8_t key[32],
                              const abe_ciphertext_t* ct,
                              uint8_t** out, size_t* out_len) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ABE_NONCE_SIZE, NULL) != 1 ||
      EVP_DecryptInit_ex(ctx, NULL, NULL, key, ct->nonce) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ABE_TAG_SIZE, (void*)ct->tag) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  *out = get_clear_memory(ct->ct_len + 16);
  if (!*out) {
    EVP_CIPHER_CTX_free(ctx);
    return CRABS_ERR_OOM;
  }

  int dec_len = 0;
  if (EVP_DecryptUpdate(ctx, *out, &dec_len, ct->ciphertext, (int)ct->ct_len) != 1) {
    OPENSSL_cleanse(*out, ct->ct_len);
    free(*out);
    *out = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  int final_len = 0;
  if (EVP_DecryptFinal_ex(ctx, *out + dec_len, &final_len) != 1) {
    OPENSSL_cleanse(*out, ct->ct_len);
    free(*out);
    *out = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  *out_len = (size_t)(dec_len + final_len);

  EVP_CIPHER_CTX_free(ctx);
  return CRABS_SUCCESS;
}

crabs_error_e crypto_abe_decrypt(const abe_user_key_t* sk, const abe_ciphertext_t* ct,
                         uint8_t** out, size_t* out_len) {
  if (!sk || !ct || !out || !out_len) return CRABS_ERR_INVALID_PARAM;

  // Check if user attributes satisfy the policy
  if (!crypto_abe_eval_policy(ct->policy, sk->attrs)) {
    return CRABS_ERR_UNAUTHORIZED;
  }

  // Derive the same encryption key: HMAC-SHA256(user_key, policy)
  uint8_t enc_key[32];
  if (_derive_decryption_key(sk, ct->policy, enc_key) != CRABS_SUCCESS) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  crabs_error_e rc = _aes_gcm_decrypt(enc_key, ct, out, out_len);
  OPENSSL_cleanse(enc_key, sizeof(enc_key));
  return rc;
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

// ============================================================
// ABE-Gated Signature Verification (§10.3)
// ============================================================

static void _build_attr_string(const user_t* user, char* buf, size_t buf_len) {
  if (!user || !buf || buf_len == 0) {
    if (buf) buf[0] = '\0';
    return;
  }

  size_t pos = 0;
  for (uint32_t i = 0; i < user->attribute_count && pos < buf_len - 1; i++) {
    if (pos > 0 && pos < buf_len - 1) {
      buf[pos++] = ',';
    }
    // Extract the value portion after the colon from "type:value" format
    const char* attr = user->attributes[i].value;
    const char* colon = strchr(attr, ':');
    const char* value = colon ? colon + 1 : attr;
    size_t val_len = strlen(value);
    if (pos + val_len >= buf_len - 1) {
      val_len = buf_len - pos - 1;
    }
    memcpy(buf + pos, value, val_len);
    pos += val_len;
  }

  // Append temporary attribute values
  temp_attr_list_t* temp = user->temp_attrs;
  while (temp != NULL && pos < buf_len - 1) {
    if (pos > 0 && pos < buf_len - 1) {
      buf[pos++] = ',';
    }
    // Use the value portion of temp attrs
    const char* value = temp->value;
    size_t val_len = strlen(value);
    if (pos + val_len >= buf_len - 1) {
      val_len = buf_len - pos - 1;
    }
    memcpy(buf + pos, value, val_len);
    pos += val_len;
    temp = temp->next;
  }

  buf[pos] = '\0';
}

verify_result_t crypto_verify_operation_auth(
    const abe_master_key_t* mk,
    const char* abe_policy,
    const attribute_machine_t* attr_machine,
    const uint8_t* serialized_op, size_t op_len,
    const uint8_t signature[CRABS_SIG_SIZE],
    const char* signer_id,
    verify_mode_e mode) {
  verify_result_t result = {
    .authorized = false,
    .error = CRABS_ERR_UNAUTHORIZED,
    .signer_id = {'\0'}
  };

  if (!mk || !abe_policy || !serialized_op || op_len == 0) {
    result.error = CRABS_ERR_INVALID_PARAM;
    return result;
  }

  // Empty policy means no authorization required
  if (strlen(abe_policy) == 0) {
    result.authorized = true;
    result.error = CRABS_SUCCESS;
    if (signer_id) {
      strncpy(result.signer_id, signer_id, CRABS_MAX_USER_ID - 1);
    }
    return result;
  }

  if (mode == VERIFY_MODE_A) {
    // Mode A: Verify specific user via ECDSA + ABE policy check
    if (!signer_id || !attr_machine) {
      result.error = CRABS_ERR_INVALID_PARAM;
      return result;
    }

    // Find the user in the attribute machine
    user_t* user = attribute_machine_find_user((attribute_machine_t*)attr_machine, signer_id);
    if (!user) {
      result.error = CRABS_ERR_USER_NOT_FOUND;
      return result;
    }

    // Check user is not suspended
    if (user->status == USER_SUSPENDED) {
      result.error = CRABS_ERR_USER_SUSPENDED;
      return result;
    }

    // Build attribute string from user's attributes
    char attr_string[CRABS_MAX_POLICY_EXPR];
    _build_attr_string(user, attr_string, sizeof(attr_string));

    // Check if user's attributes satisfy the ABE policy
    if (!crypto_abe_eval_policy(abe_policy, attr_string)) {
      result.error = CRABS_ERR_UNAUTHORIZED;
      return result;
    }

    // Verify ECDSA signature
    if (!crypto_ecdsa_verify(user->public_key, serialized_op, op_len, signature)) {
      result.error = CRABS_ERR_CRYPTOGRAPHIC_ERROR;
      return result;
    }

    result.authorized = true;
    result.error = CRABS_SUCCESS;
    strncpy(result.signer_id, signer_id, CRABS_MAX_USER_ID - 1);

  } else {
    // Mode B: Verify against all registered users via trial policy check
    if (!attr_machine) {
      result.error = CRABS_ERR_INVALID_PARAM;
      return result;
    }

    // Iterate all users, check if any satisfy the policy and have a valid signature
    user_t* user = ((attribute_machine_t*)attr_machine)->users;
    while (user != NULL) {
      if (user->status != USER_SUSPENDED) {
        char attr_string[CRABS_MAX_POLICY_EXPR];
        _build_attr_string(user, attr_string, sizeof(attr_string));

        if (crypto_abe_eval_policy(abe_policy, attr_string)) {
          // Check signature if provided
          if (signature != NULL) {
            if (crypto_ecdsa_verify(user->public_key, serialized_op, op_len, signature)) {
              result.authorized = true;
              result.error = CRABS_SUCCESS;
              strncpy(result.signer_id, user->user_id, CRABS_MAX_USER_ID - 1);
              return result;
            }
          }
        }
      }
      user = user->next;
    }

    result.error = CRABS_ERR_UNAUTHORIZED;
  }

  return result;
}

// ============================================================
// Scheme-Aware Signature Verification (v1.3 §6)
// ============================================================

static crabs_error_e _verify_sig_with_scheme(
    signature_scheme_e scheme,
    const uint8_t* pk, uint32_t pk_len,
    const uint8_t* msg, uint32_t msg_len,
    const uint8_t* sig, uint32_t sig_len) {
  if (scheme == SCHEME_UNSPECIFIED) {
    // Legacy ECDSA path: fixed 33-byte public key, 64-byte signature
    if (pk_len != 33 || sig_len != CRABS_SIG_SIZE) {
      return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
    }
    return crypto_ecdsa_verify(pk, msg, msg_len, sig) ? CRABS_SUCCESS : CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  // Dispatch through vtable registry
  const signature_vtable_t* vt = crypto_sig_scheme_get(scheme);
  if (vt == NULL || vt->verify == NULL) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  return vt->verify(pk, pk_len, msg, msg_len, sig, sig_len);
}

static crabs_error_e _verify_user_signature(
    const user_t* user,
    const char* key_id,
    signature_scheme_e sig_scheme,
    const uint8_t* serialized_op, size_t op_len,
    const uint8_t* signature, uint32_t signature_len) {
  if (sig_scheme == SCHEME_UNSPECIFIED && (key_id == NULL || key_id[0] == '\0')) {
    // Legacy path: use user's default ECDSA key
    return _verify_sig_with_scheme(SCHEME_UNSPECIFIED,
                                    user->public_key, 33,
                                    serialized_op, (uint32_t)op_len,
                                    signature, signature_len);
  }

  // v1.3 path: resolve key from user's keyring
  if (key_id != NULL && key_id[0] != '\0') {
    user_key_t* key = user_key_find((user_t*)user, key_id);
    if (key == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    if (!key->is_active) return CRABS_ERR_UNAUTHORIZED;
    if (sig_scheme != SCHEME_UNSPECIFIED && key->scheme != sig_scheme) {
      return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
    }
    return _verify_sig_with_scheme(key->scheme,
                                    key->public_key, key->public_key_len,
                                    serialized_op, (uint32_t)op_len,
                                    signature, signature_len);
  }

  // No key_id but scheme specified: find user's default active key for that scheme
  if (sig_scheme != SCHEME_UNSPECIFIED) {
    user_key_t* key = user_key_find_active((user_t*)user, sig_scheme);
    if (key == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    return _verify_sig_with_scheme(key->scheme,
                                    key->public_key, key->public_key_len,
                                    serialized_op, (uint32_t)op_len,
                                    signature, signature_len);
  }

  return CRABS_ERR_INVALID_PARAM;
}

verify_result_t crypto_verify_operation_auth_v2(
    const abe_master_key_t* mk,
    const char* abe_policy,
    const attribute_machine_t* attr_machine,
    const uint8_t* serialized_op, size_t op_len,
    const uint8_t* signature, uint32_t signature_len,
    const char* signer_id,
    const char* key_id,
    signature_scheme_e sig_scheme,
    verify_mode_e mode) {
  verify_result_t result = {
    .authorized = false,
    .error = CRABS_ERR_UNAUTHORIZED,
    .signer_id = {'\0'}
  };

  if (!mk || !abe_policy || !serialized_op || op_len == 0) {
    result.error = CRABS_ERR_INVALID_PARAM;
    return result;
  }

  // Empty policy means no authorization required
  if (strlen(abe_policy) == 0) {
    result.authorized = true;
    result.error = CRABS_SUCCESS;
    if (signer_id) {
      strncpy(result.signer_id, signer_id, CRABS_MAX_USER_ID - 1);
    }
    return result;
  }

  if (mode == VERIFY_MODE_A) {
    // Mode A: Verify specific user
    if (!signer_id || !attr_machine) {
      result.error = CRABS_ERR_INVALID_PARAM;
      return result;
    }

    user_t* user = attribute_machine_find_user((attribute_machine_t*)attr_machine, signer_id);
    if (!user) {
      result.error = CRABS_ERR_USER_NOT_FOUND;
      return result;
    }
    if (user->status == USER_SUSPENDED) {
      result.error = CRABS_ERR_USER_SUSPENDED;
      return result;
    }

    // ABE policy check
    char attr_string[CRABS_MAX_POLICY_EXPR];
    _build_attr_string(user, attr_string, sizeof(attr_string));
    if (!crypto_abe_eval_policy(abe_policy, attr_string)) {
      result.error = CRABS_ERR_UNAUTHORIZED;
      return result;
    }

    // Scheme-aware signature verification
    crabs_error_e sig_rc = _verify_user_signature(user, key_id, sig_scheme,
                                                    serialized_op, op_len,
                                                    signature, signature_len);
    if (sig_rc != CRABS_SUCCESS) {
      result.error = sig_rc;
      return result;
    }

    result.authorized = true;
    result.error = CRABS_SUCCESS;
    strncpy(result.signer_id, signer_id, CRABS_MAX_USER_ID - 1);

  } else {
    // Mode B: Verify against all registered users
    if (!attr_machine) {
      result.error = CRABS_ERR_INVALID_PARAM;
      return result;
    }

    user_t* user = ((attribute_machine_t*)attr_machine)->users;
    while (user != NULL) {
      if (user->status != USER_SUSPENDED) {
        char attr_string[CRABS_MAX_POLICY_EXPR];
        _build_attr_string(user, attr_string, sizeof(attr_string));

        if (crypto_abe_eval_policy(abe_policy, attr_string)) {
          // Try verification with this user
          crabs_error_e sig_rc;
          if (sig_scheme != SCHEME_UNSPECIFIED || (key_id != NULL && key_id[0] != '\0')) {
            sig_rc = _verify_user_signature(user, key_id, sig_scheme,
                                             serialized_op, op_len,
                                             signature, signature_len);
          } else {
            // No scheme or key_id specified: try legacy ECDSA
            sig_rc = _verify_sig_with_scheme(SCHEME_UNSPECIFIED,
                                              user->public_key, 33,
                                              serialized_op, (uint32_t)op_len,
                                              signature, signature_len);
          }
          if (sig_rc == CRABS_SUCCESS) {
            result.authorized = true;
            result.error = CRABS_SUCCESS;
            strncpy(result.signer_id, user->user_id, CRABS_MAX_USER_ID - 1);
            return result;
          }
        }
      }
      user = user->next;
    }

    result.error = CRABS_ERR_UNAUTHORIZED;
  }

  return result;
}

// ============================================================
// Key Envelope (§11.2)
// ============================================================

// Canonical envelope data size for signing:
// format_version(1) + user_id(64) + state_version(8) + attributes_hash(32)
// + issued_at(8) + expires_at(8) + sk_abe(32) = 153
#define _ENVELOPE_SIGN_DATA_SIZE (1 + CRABS_MAX_USER_ID + 8 + CRABS_HASH_SIZE + 8 + 8 + ABE_MASTER_KEY_SIZE)

static void _pack_u64_le(uint8_t* buf, uint64_t val) {
  for (int i = 0; i < 8; i++) {
    buf[i] = (uint8_t)(val & 0xFF);
    val >>= 8;
  }
}

static size_t _envelope_sign_data(const key_envelope_t* env, uint8_t* buf, size_t buf_len) {
  if (!env || !buf || buf_len < _ENVELOPE_SIGN_DATA_SIZE) return 0;

  size_t pos = 0;
  buf[pos++] = env->format_version;
  memcpy(buf + pos, env->user_id, CRABS_MAX_USER_ID);
  pos += CRABS_MAX_USER_ID;
  _pack_u64_le(buf + pos, env->state_version);
  pos += 8;
  memcpy(buf + pos, env->attributes_hash, CRABS_HASH_SIZE);
  pos += CRABS_HASH_SIZE;
  _pack_u64_le(buf + pos, env->issued_at);
  pos += 8;
  _pack_u64_le(buf + pos, env->expires_at);
  pos += 8;
  memcpy(buf + pos, env->sk_abe, ABE_MASTER_KEY_SIZE);
  pos += ABE_MASTER_KEY_SIZE;

  return pos;
}

key_envelope_t* crypto_key_envelope_create(
    const abe_master_key_t* mk,
    const uint8_t node_private_key[32],
    const char* user_id,
    uint64_t state_version,
    const uint8_t attributes_hash[CRABS_HASH_SIZE],
    uint64_t issued_at,
    uint64_t expires_at) {
  if (!mk || !node_private_key || !user_id || !attributes_hash) return NULL;

  key_envelope_t* env = get_clear_memory(sizeof(key_envelope_t));
  if (!env) return NULL;

  env->format_version = KEY_ENVELOPE_FORMAT_V1;
  strncpy(env->user_id, user_id, CRABS_MAX_USER_ID - 1);
  env->state_version = state_version;
  memcpy(env->attributes_hash, attributes_hash, CRABS_HASH_SIZE);
  env->issued_at = issued_at;
  env->expires_at = expires_at;

  // Generate ABE key for the user's current attributes
  // We need to reconstruct the attribute string from the hash context,
  // but since the hash is one-way, we generate a generic ABE key
  // and the actual attribute string is used during policy evaluation.
  // For the simulated ABE, the key is just MPK, which is already in mk.
  memcpy(env->sk_abe, mk->mpk, ABE_MASTER_KEY_SIZE);

  // Sign the envelope data with the node's ECDSA private key
  uint8_t sign_data[_ENVELOPE_SIGN_DATA_SIZE];
  size_t sign_len = _envelope_sign_data(env, sign_data, sizeof(sign_data));
  if (sign_len == 0) {
    OPENSSL_cleanse(env->sk_abe, ABE_MASTER_KEY_SIZE);
    free(env);
    return NULL;
  }

  crabs_error_e rc = crypto_ecdsa_sign(node_private_key, sign_data, sign_len, env->signature);
  if (rc != CRABS_SUCCESS) {
    OPENSSL_cleanse(env->sk_abe, ABE_MASTER_KEY_SIZE);
    free(env);
    return NULL;
  }

  return env;
}

bool crypto_key_envelope_verify(
    const uint8_t node_public_key[33],
    const key_envelope_t* envelope) {
  if (!node_public_key || !envelope) return false;
  if (envelope->format_version != KEY_ENVELOPE_FORMAT_V1) return false;

  uint8_t sign_data[_ENVELOPE_SIGN_DATA_SIZE];
  size_t sign_len = _envelope_sign_data(envelope, sign_data, sizeof(sign_data));
  if (sign_len == 0) return false;

  return crypto_ecdsa_verify(node_public_key, sign_data, sign_len, envelope->signature);
}

void crypto_key_envelope_destroy(key_envelope_t* envelope) {
  if (envelope) {
    OPENSSL_cleanse(envelope->sk_abe, ABE_MASTER_KEY_SIZE);
    free(envelope);
  }
}

// ============================================================
// Attributes Hash (§11.2)
// ============================================================

crabs_error_e crypto_compute_attributes_hash(const user_t* user, uint8_t hash[CRABS_HASH_SIZE]) {
  if (!user || !hash) return CRABS_ERR_INVALID_PARAM;

  char attr_string[CRABS_MAX_POLICY_EXPR];
  _build_attr_string(user, attr_string, sizeof(attr_string));

  if (strlen(attr_string) == 0) {
    // Empty attributes - hash a single zero byte
    uint8_t zero = 0;
    return crypto_sha256(&zero, 1, hash);
  }

  return crypto_sha256((const uint8_t*)attr_string, strlen(attr_string), hash);
}

// ============================================================
// Key Compromise Recovery (§11.4)
// ============================================================

recovery_result_t* crypto_revoke_and_rotate(
    const abe_master_key_t* mk,
    const uint8_t node_private_key[32],
    attribute_machine_t* attr_machine,
    const char* user_id,
    uint64_t state_version,
    uint64_t issued_at) {
  if (!mk || !node_private_key || !attr_machine || !user_id) return NULL;

  // Step 1: Suspend compromised user (also increments key_version per §8.4)
  user_t* user = attribute_machine_find_user(attr_machine, user_id);
  if (!user) return NULL;

  attribute_machine_suspend_user(attr_machine, user_id);

  // Step 3: Generate new ECDSA keypair
  ecdsa_keypair_t* new_key = crypto_ecdsa_generate();
  if (!new_key) return NULL;

  // Step 4: Update user's public key
  memcpy(user->public_key, new_key->public_key, 33);

  // Step 5: Compute attributes hash and generate new ABE key envelope
  uint8_t attr_hash[CRABS_HASH_SIZE];
  crabs_error_e rc = crypto_compute_attributes_hash(user, attr_hash);
  if (rc != CRABS_SUCCESS) {
    crypto_ecdsa_keypair_destroy(new_key);
    return NULL;
  }

  key_envelope_t* envelope = crypto_key_envelope_create(
      mk, node_private_key, user_id, state_version, attr_hash, issued_at, 0);
  if (!envelope) {
    crypto_ecdsa_keypair_destroy(new_key);
    return NULL;
  }

  // Step 6: Build result
  recovery_result_t* result = get_clear_memory(sizeof(recovery_result_t));
  if (!result) {
    crypto_ecdsa_keypair_destroy(new_key);
    crypto_key_envelope_destroy(envelope);
    return NULL;
  }

  result->new_ecdsa_key = new_key;
  result->new_envelope = envelope;

  return result;
}

void crypto_recovery_result_destroy(recovery_result_t* result) {
  if (result) {
    if (result->new_ecdsa_key) crypto_ecdsa_keypair_destroy(result->new_ecdsa_key);
    if (result->new_envelope) crypto_key_envelope_destroy(result->new_envelope);
    free(result);
  }
}