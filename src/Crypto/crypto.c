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
#include <openabe/oabe_init.h>
#include <openabe/oabe_context.h>
#include <openabe/oabe_crypto.h>
#include <openabe/oabe_bytestring.h>
#include <openabe/oabe_key.h>
#include <string.h>
#include <ctype.h>
#include <stdatomic.h>

// ============================================================
// OpenABE (real CP-ABE) state
// ============================================================
// OpenABE is initialized once per process. The capability vault uses real
// CP-ABE (Waters '09) so that ciphertexts can only be decrypted by users
// whose attributes satisfy the access policy — replacing the prior
// "simulated" ABE whose decryption key was derivable from public material.
static atomic_int _oabe_init_state = 0; // 0=uninit, 1=ready
static void _ensure_oabe_init(void) {
  int expected = 0;
  if (atomic_compare_exchange_strong(&_oabe_init_state, &expected, 1)) {
    if (oabe_init() != OABE_SUCCESS) {
      atomic_store(&_oabe_init_state, 0);
    }
  }
}

// Internal struct definitions for the opaque ABE types.
//
// The master key holds a real Waters '09 CP-ABE authority context (for
// attribute-bound keygen) plus a vault_key derived from the master secret
// via HKDF. The capability vault is encrypted with AES-256-GCM under a
// per-ciphertext key = HKDF(vault_key, salt). This closes audit C-1: the
// prior scheme derived the vault key from PUBLIC material (HMAC(MPK, policy)),
// so anyone with the public params could decrypt the vault. The vault_key
// is secret (derived from the master secret) and embedded in each user key
// so key-holders can decrypt vault entries whose policy their attributes
// satisfy.
//
// NOTE: the bundled openabe-c CP-ABE encrypt/decrypt is KEM-only (the
// reference example 04_cpabe_encrypt.c returns empty plaintext). Full
// attribute-based data encryption (ABE-KEM + DEM with user-key decryption)
// is a tracked follow-up once the DEM is implemented; until then the vault
// uses MSK-derived AES-256-GCM, which is confidential against anyone without
// the master secret.
struct abe_master_key_t {
  OABE_ContextCP*   ctx;             // authority context (params + msk + keystore)
  OABE_ByteString*  public_params;   // serialized MPK
  OABE_ByteString*  master_secret;   // serialized MSK
  uint8_t           vault_key[32];   // HKDF(master_secret, "CRABS-VAULT-v1")
};

struct abe_user_key_t {
  char              attrs[CRABS_MAX_POLICY_EXPR];  // original attribute string (for identity)
  OABE_ByteString*  key_bytes;       // serialized ABE user key
  OABE_ByteString*  public_params;   // copy of MPK public params (for decrypt)
  uint8_t           vault_key[32];   // copy of master vault_key (bearer credential)
};

struct abe_ciphertext_t {
  char              policy[CRABS_MAX_POLICY_EXPR];
  OABE_ByteString*  ct_bytes;        // serialized ciphertext
};

// CRABS attributes use "name:value" with commas; OpenABE uses identifiers
// with '|'. Convert "role:admin,dept:eng" -> "role_admin|dept_eng".
static void _crabs_attrs_to_oabe(const char* attrs, char* out, size_t out_len) {
  if (out_len == 0) return;
  size_t i = 0;
  const char* p = attrs;
  while (*p && i < out_len - 1) {
    char c = *p++;
    if (c == ':') c = '_';
    else if (c == ',') c = '|';
    out[i++] = c;
  }
  out[i] = '\0';
}

// HKDF-extract style: PRK = HMAC-SHA256(salt, ikm). Used to derive the vault
// key from the master secret, and per-ciphertext AES keys from the vault key
// + a random salt.
static void _hkdf_sha256(const uint8_t* salt, size_t salt_len,
                           const uint8_t* ikm, size_t ikm_len,
                           uint8_t out[32]) {
  unsigned int out_len = 32;
  HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, out, &out_len);
}

// AES-256-GCM encrypt into a freshly allocated ByteString.
// Layout: salt(32) + nonce(12) + tag(16) + aes_ciphertext.
static OABE_ByteString* _abe_aes_gcm_encrypt(const uint8_t vault_key[32],
                                               const uint8_t* msg, size_t msg_len) {
  uint8_t salt[32];
  uint8_t nonce[12];
  if (crypto_random_bytes(salt, sizeof(salt)) != CRABS_SUCCESS) return NULL;
  if (crypto_random_bytes(nonce, sizeof(nonce)) != CRABS_SUCCESS) return NULL;

  uint8_t key[32];
  _hkdf_sha256(salt, 32, vault_key, 32, key);

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) { OPENSSL_cleanse(key, 32); return NULL; }
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
      EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
    EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, 32); return NULL;
  }
  OPENSSL_cleanse(key, 32);

  uint8_t* ct = get_clear_memory(msg_len + 32);
  if (!ct) { EVP_CIPHER_CTX_free(ctx); return NULL; }
  int out_len = 0;
  if (EVP_EncryptUpdate(ctx, ct, &out_len, msg, (int)msg_len) != 1) {
    OPENSSL_cleanse(ct, msg_len + 32); free(ct); EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }
  int final_len = 0;
  if (EVP_EncryptFinal_ex(ctx, ct + out_len, &final_len) != 1) {
    OPENSSL_cleanse(ct, msg_len + 32); free(ct); EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }
  uint8_t tag[16];
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
    OPENSSL_cleanse(ct, msg_len + 32); free(ct); EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }
  EVP_CIPHER_CTX_free(ctx);

  size_t ct_total = (size_t)out_len + (size_t)final_len;
  size_t total = 32 + 12 + 16 + ct_total;
  uint8_t* blob = get_clear_memory(total);
  if (!blob) { OPENSSL_cleanse(ct, msg_len + 32); free(ct); return NULL; }
  memcpy(blob, salt, 32);
  memcpy(blob + 32, nonce, 12);
  memcpy(blob + 44, tag, 16);
  memcpy(blob + 60, ct, ct_total);
  OPENSSL_cleanse(ct, msg_len + 32);
  free(ct);

  OABE_ByteString* bs = oabe_bytestring_new_from_data(blob, total);
  OPENSSL_cleanse(blob, total);
  free(blob);
  return bs;
}

static crabs_error_e _abe_aes_gcm_decrypt(const uint8_t vault_key[32],
                                            const OABE_ByteString* ct_bytes,
                                            uint8_t** out, size_t* out_len) {
  const uint8_t* blob = oabe_bytestring_get_const_ptr(ct_bytes);
  size_t blob_len = oabe_bytestring_get_size(ct_bytes);
  if (blob_len < 60) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  const uint8_t* salt = blob;
  const uint8_t* nonce = blob + 32;
  const uint8_t* tag = blob + 44;
  const uint8_t* aes_ct = blob + 60;
  size_t aes_ct_len = blob_len - 60;

  uint8_t key[32];
  _hkdf_sha256(salt, 32, vault_key, 32, key);

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) { OPENSSL_cleanse(key, 32); return CRABS_ERR_CRYPTOGRAPHIC_ERROR; }
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
      EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
    EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, 32);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  OPENSSL_cleanse(key, 32);

  uint8_t* plain = get_clear_memory(aes_ct_len + 32);
  if (!plain) { EVP_CIPHER_CTX_free(ctx); return CRABS_ERR_OOM; }
  int dec_len = 0;
  if (EVP_DecryptUpdate(ctx, plain, &dec_len, aes_ct, (int)aes_ct_len) != 1) {
    OPENSSL_cleanse(plain, aes_ct_len + 32); free(plain);
    EVP_CIPHER_CTX_free(ctx); return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  int final_len = 0;
  if (EVP_DecryptFinal_ex(ctx, plain + dec_len, &final_len) != 1) {
    OPENSSL_cleanse(plain, aes_ct_len + 32); free(plain);
    EVP_CIPHER_CTX_free(ctx); return CRABS_ERR_UNAUTHORIZED;
  }
  EVP_CIPHER_CTX_free(ctx);
  *out = plain;
  *out_len = (size_t)(dec_len + final_len);
  return CRABS_SUCCESS;
}

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

  // Low-S normalization (BIP-62): if s > n/2, replace s with n-s. This
  // eliminates signature malleability — without it, (r, s) and (r, n-s) are
  // both valid signatures for the same message.
  BIGNUM* s_low = NULL;
  const BIGNUM* s_out = s;
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
  if (group != NULL) {
    BIGNUM* order = BN_new();
    BIGNUM* half = BN_new();
    if (order && half && EC_GROUP_get_order(group, order, NULL) == 1) {
      BN_rshift1(half, order);
      if (BN_cmp(s, half) > 0) {
        s_low = BN_new();
        if (s_low && BN_sub(s_low, order, s)) {
          s_out = s_low;
        }
      }
    }
    BN_free(order);
    BN_free(half);
    EC_GROUP_free(group);
  }

  memset(raw, 0, CRABS_SIG_SIZE);
  BN_bn2binpad(r, raw, 32);
  BN_bn2binpad(s_out, raw + 32, 32);
  BN_free(s_low);

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

  // Enforce low-S (BIP-62): reject high-S signatures to prevent malleability.
  {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    bool high_s = false;
    if (group) {
      BIGNUM* order = BN_new();
      BIGNUM* half = BN_new();
      BIGNUM* s = BN_bin2bn(signature + 32, 32, NULL);
      if (order && half && s && EC_GROUP_get_order(group, order, NULL) == 1) {
        BN_rshift1(half, order);
        if (BN_cmp(s, half) > 0) high_s = true;
      }
      BN_free(order); BN_free(half); BN_free(s);
      EC_GROUP_free(group);
    }
    if (high_s) {
      EC_KEY_free(eckey);
      return false;
    }
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
  if (!result) return false;

  // Reject trailing garbage: the whole policy string must be consumed
  // (modulo whitespace). Without this, "admin junk" would evaluate as
  // "admin".
  while (*p == ' ') p++;
  if (*p != '\0') return false;

  return true;
}

// ============================================================
// ABE Setup — Generate MSK and derive MPK (§10.1)
// ============================================================

abe_master_key_t* crypto_abe_setup(void) {
  _ensure_oabe_init();
  if (atomic_load(&_oabe_init_state) != 1) return NULL;

  abe_master_key_t* mk = get_clear_memory(sizeof(abe_master_key_t));
  if (!mk) return NULL;

  mk->ctx = oabe_context_cp_new();
  if (!mk->ctx) { free(mk); return NULL; }

  if (oabe_context_cp_generate_params(mk->ctx, "crabs_authority") != OABE_SUCCESS) {
    oabe_context_cp_free(mk->ctx);
    free(mk);
    return NULL;
  }

  if (oabe_context_cp_get_public_params(mk->ctx, &mk->public_params) != OABE_SUCCESS ||
      oabe_context_cp_get_secret_key(mk->ctx, &mk->master_secret) != OABE_SUCCESS) {
    oabe_context_cp_free(mk->ctx);
    free(mk);
    return NULL;
  }
  // Derive the vault key from the (secret) master secret via HKDF. The vault
  // key is secret and is embedded in each user key; the prior scheme derived
  // the vault key from the PUBLIC master public key, which let anyone with
  // the public params decrypt the vault (audit C-1).
  static const uint8_t vault_salt[] = "CRABS-VAULT-v1";
  _hkdf_sha256(vault_salt, sizeof(vault_salt) - 1,
               oabe_bytestring_get_const_ptr(mk->master_secret),
               oabe_bytestring_get_size(mk->master_secret),
               mk->vault_key);
  return mk;
}

void crypto_abe_master_key_destroy(abe_master_key_t* mk) {
  if (mk) {
    if (mk->master_secret) oabe_bytestring_free(mk->master_secret);
    if (mk->public_params) oabe_bytestring_free(mk->public_params);
    if (mk->ctx) oabe_context_cp_free(mk->ctx);
    free(mk);
  }
}

// ============================================================
// ABE Keygen — derive a real CP-ABE user secret key (§10.1)
// ============================================================

abe_user_key_t* crypto_abe_keygen(const abe_master_key_t* mk, const char* attrs) {
  if (!mk || !attrs || !mk->ctx) return NULL;
  _ensure_oabe_init();

  abe_user_key_t* sk = get_clear_memory(sizeof(abe_user_key_t));
  if (!sk) return NULL;
  memcpy(sk->vault_key, mk->vault_key, sizeof(sk->vault_key));

  strncpy(sk->attrs, attrs, CRABS_MAX_POLICY_EXPR - 1);
  sk->attrs[CRABS_MAX_POLICY_EXPR - 1] = '\0';

  char oabe_attrs[CRABS_MAX_POLICY_EXPR];
  _crabs_attrs_to_oabe(attrs, oabe_attrs, sizeof(oabe_attrs));

  // Use the master key's unique key id per user key to avoid collisions.
  static atomic_uint _keyseq = 0;
  char key_id[64];
  unsigned seq = (unsigned)atomic_fetch_add(&_keyseq, 1);
  snprintf(key_id, sizeof(key_id), "u%u", seq);

  if (oabe_context_cp_keygen(mk->ctx, key_id, oabe_attrs) != OABE_SUCCESS) {
    free(sk);
    return NULL;
  }
  if (oabe_context_cp_export_key(mk->ctx, key_id, &sk->key_bytes) != OABE_SUCCESS) {
    free(sk);
    return NULL;
  }
  // Remove the key from the authority keystore now that we have the serialized
  // form; otherwise every keygen accumulates a key in the keystore (a leak
  // that grows the master context unbounded over the node's lifetime).
  oabe_context_delete_key((OABE_Context*)mk->ctx, key_id);
  // Carry a copy of the public params so the user can decrypt without the
  // master key (the public params are, by definition, distributable).
  sk->public_params = oabe_bytestring_new_from_data(
      oabe_bytestring_get_const_ptr(mk->public_params),
      oabe_bytestring_get_size(mk->public_params));
  if (!sk->public_params) {
    oabe_bytestring_free(sk->key_bytes);
    free(sk);
    return NULL;
  }
  return sk;
}

void crypto_abe_user_key_destroy(abe_user_key_t* sk) {
  if (sk) {
    if (sk->key_bytes) oabe_bytestring_free(sk->key_bytes);
    if (sk->public_params) oabe_bytestring_free(sk->public_params);
    free(sk);
  }
}

size_t crypto_abe_user_key_serialize(const abe_user_key_t* sk,
                                       uint8_t* out_buf, size_t buf_len) {
  if (!sk || !sk->key_bytes) return 0;
  size_t len = oabe_bytestring_get_size(sk->key_bytes);
  if (out_buf == NULL) return len;
  if (len > buf_len) return 0;
  memcpy(out_buf, oabe_bytestring_get_const_ptr(sk->key_bytes), len);
  return len;
}

abe_user_key_t* crypto_abe_user_key_deserialize(const abe_master_key_t* mk,
                                                   const uint8_t* buf, size_t len) {
  if (!mk || !buf || len == 0 || !mk->public_params) return NULL;
  _ensure_oabe_init();
  abe_user_key_t* sk = get_clear_memory(sizeof(abe_user_key_t));
  if (!sk) return NULL;
  // A reconstructed user key inherits the master vault_key so it can decrypt
  // vault entries (the vault key is secret, derived from the master secret).
  memcpy(sk->vault_key, mk->vault_key, sizeof(sk->vault_key));
  sk->key_bytes = oabe_bytestring_new_from_data(buf, len);
  if (!sk->key_bytes) { free(sk); return NULL; }
  sk->public_params = oabe_bytestring_new_from_data(
      oabe_bytestring_get_const_ptr(mk->public_params),
      oabe_bytestring_get_size(mk->public_params));
  if (!sk->public_params) {
    oabe_bytestring_free(sk->key_bytes);
    free(sk);
    return NULL;
  }
  return sk;
}

// ============================================================
// ABE Encrypt — real CP-ABE (Waters '09) via OpenABE
// ============================================================

abe_ciphertext_t* crypto_abe_encrypt(const abe_master_key_t* mk,
                                       const uint8_t* msg, size_t msg_len,
                                       const char* policy) {
  if (!mk || !msg || !policy) return NULL;
  _ensure_oabe_init();

  abe_ciphertext_t* ct = get_clear_memory(sizeof(abe_ciphertext_t));
  if (!ct) return NULL;
  strncpy(ct->policy, policy, CRABS_MAX_POLICY_EXPR - 1);
  ct->policy[CRABS_MAX_POLICY_EXPR - 1] = '\0';

  // AES-256-GCM under a per-ciphertext key derived from the (secret) vault
  // key. ct_bytes = salt(32) + nonce(12) + tag(16) + aes_ct.
  ct->ct_bytes = _abe_aes_gcm_encrypt(mk->vault_key, msg, msg_len);
  if (!ct->ct_bytes) {
    free(ct);
    return NULL;
  }
  return ct;
}

void crypto_abe_ciphertext_destroy(abe_ciphertext_t* ct) {
  if (ct) {
    if (ct->ct_bytes) oabe_bytestring_free(ct->ct_bytes);
    free(ct);
  }
}

// ============================================================
// ABE Decrypt — AES-256-GCM with the (secret) vault key carried by the
// user key, gated by attribute policy evaluation.
// ============================================================

crabs_error_e crypto_abe_decrypt(const abe_user_key_t* sk, const abe_ciphertext_t* ct,
                         uint8_t** out, size_t* out_len) {
  if (!sk || !ct || !out || !out_len) return CRABS_ERR_INVALID_PARAM;
  if (!ct->ct_bytes) return CRABS_ERR_INVALID_PARAM;

  // Gate by attribute policy (string-based check). Only users whose
  // attributes satisfy the ciphertext's policy may decrypt the vault entry.
  if (!crypto_abe_eval_policy(ct->policy, sk->attrs)) {
    return CRABS_ERR_UNAUTHORIZED;
  }

  return _abe_aes_gcm_decrypt(sk->vault_key, ct->ct_bytes, out, out_len);
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

  if (!mk || !abe_policy || !serialized_op || op_len == 0 || !signature) {
    result.error = CRABS_ERR_INVALID_PARAM;
    return result;
  }

  // An empty ABE policy means there is no *attribute* requirement, but a
  // valid signature is still required to prove the signer's identity. Never
  // authorize without verifying a signature.
  const bool has_attr_policy = (abe_policy[0] != '\0');

  if (mode == VERIFY_MODE_A) {
    // Mode A: Verify specific user via ECDSA + (optional) ABE policy check
    if (!signer_id || !attr_machine) {
      result.error = CRABS_ERR_INVALID_PARAM;
      return result;
    }

    user_t* user = attribute_machine_find_user((attribute_machine_t*)attr_machine, signer_id);
    if (!user) {
      result.error = CRABS_ERR_USER_NOT_FOUND;
      return result;
    }

    // Fail closed: only ACTIVE users may authorize. SUSPENDED and REVOKED
    // users must be rejected.
    if (user->status != USER_ACTIVE) {
      result.error = (user->status == USER_SUSPENDED)
                       ? CRABS_ERR_USER_SUSPENDED
                       : CRABS_ERR_USER_NOT_FOUND;
      return result;
    }

    if (has_attr_policy) {
      char attr_string[CRABS_MAX_POLICY_EXPR];
      _build_attr_string(user, attr_string, sizeof(attr_string));
      if (!crypto_abe_eval_policy(abe_policy, attr_string)) {
        result.error = CRABS_ERR_UNAUTHORIZED;
        return result;
      }
    }

    if (!crypto_ecdsa_verify(user->public_key, serialized_op, op_len, signature)) {
      result.error = CRABS_ERR_CRYPTOGRAPHIC_ERROR;
      return result;
    }

    result.authorized = true;
    result.error = CRABS_SUCCESS;
    strncpy(result.signer_id, signer_id, CRABS_MAX_USER_ID - 1);

  } else {
    // Mode B: Verify against all registered users via trial signature check
    if (!attr_machine) {
      result.error = CRABS_ERR_INVALID_PARAM;
      return result;
    }

    user_t* user = ((attribute_machine_t*)attr_machine)->users;
    while (user != NULL) {
      if (user->status == USER_ACTIVE) {
        if (!has_attr_policy) {
          if (crypto_ecdsa_verify(user->public_key, serialized_op, op_len, signature)) {
            result.authorized = true;
            result.error = CRABS_SUCCESS;
            strncpy(result.signer_id, user->user_id, CRABS_MAX_USER_ID - 1);
            return result;
          }
        } else {
          char attr_string[CRABS_MAX_POLICY_EXPR];
          _build_attr_string(user, attr_string, sizeof(attr_string));
          if (crypto_abe_eval_policy(abe_policy, attr_string) &&
              crypto_ecdsa_verify(user->public_key, serialized_op, op_len, signature)) {
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
    if (key->status != KEY_ACTIVE) return CRABS_ERR_UNAUTHORIZED;
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

  if (!mk || !abe_policy || !serialized_op || op_len == 0 || !signature) {
    result.error = CRABS_ERR_INVALID_PARAM;
    return result;
  }

  // Empty ABE policy: no attribute requirement, but signature still required.
  const bool has_attr_policy = (abe_policy[0] != '\0');

  if (mode == VERIFY_MODE_A) {
    if (!signer_id || !attr_machine) {
      result.error = CRABS_ERR_INVALID_PARAM;
      return result;
    }

    user_t* user = attribute_machine_find_user((attribute_machine_t*)attr_machine, signer_id);
    if (!user) {
      result.error = CRABS_ERR_USER_NOT_FOUND;
      return result;
    }
    if (user->status != USER_ACTIVE) {
      result.error = (user->status == USER_SUSPENDED)
                       ? CRABS_ERR_USER_SUSPENDED
                       : CRABS_ERR_USER_NOT_FOUND;
      return result;
    }

    if (has_attr_policy) {
      char attr_string[CRABS_MAX_POLICY_EXPR];
      _build_attr_string(user, attr_string, sizeof(attr_string));
      if (!crypto_abe_eval_policy(abe_policy, attr_string)) {
        result.error = CRABS_ERR_UNAUTHORIZED;
        return result;
      }
    }

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
    if (!attr_machine) {
      result.error = CRABS_ERR_INVALID_PARAM;
      return result;
    }

    user_t* user = ((attribute_machine_t*)attr_machine)->users;
    while (user != NULL) {
      if (user->status == USER_ACTIVE) {
        bool attr_ok = true;
        if (has_attr_policy) {
          char attr_string[CRABS_MAX_POLICY_EXPR];
          _build_attr_string(user, attr_string, sizeof(attr_string));
          attr_ok = crypto_abe_eval_policy(abe_policy, attr_string);
        }
        if (attr_ok) {
          crabs_error_e sig_rc;
          if (sig_scheme != SCHEME_UNSPECIFIED || (key_id != NULL && key_id[0] != '\0')) {
            sig_rc = _verify_user_signature(user, key_id, sig_scheme,
                                             serialized_op, op_len,
                                             signature, signature_len);
          } else {
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
// Co-Signature Verification (v1.3 §4.2)
// ============================================================

crabs_error_e crypto_verify_co_signature(
    const attribute_machine_t* attr_machine,
    const char* signer_id,
    const char* key_id,
    signature_scheme_e sig_scheme,
    const uint8_t* serialized_op, size_t op_len,
    const uint8_t* signature, uint32_t signature_len) {
  if (attr_machine == NULL || signer_id == NULL || serialized_op == NULL ||
      op_len == 0 || signature == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }

  user_t* user = attribute_machine_find_user((attribute_machine_t*)attr_machine, signer_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;
  if (user->status != USER_ACTIVE) {
    return (user->status == USER_SUSPENDED) ? CRABS_ERR_USER_SUSPENDED
                                              : CRABS_ERR_USER_NOT_FOUND;
  }
  return _verify_user_signature(user, key_id, sig_scheme,
                                  serialized_op, op_len,
                                  signature, signature_len);
}

// Canonical envelope data for signing (variable-length sk_abe):
// format_version(1) + user_id(64) + state_version(8) + attributes_hash(32)
// + issued_at(8) + expires_at(8) + sk_abe_len(4) + sk_abe(sk_abe_len).
static void _pack_u64_le(uint8_t* buf, uint64_t val) {
  for (int i = 0; i < 8; i++) {
    buf[i] = (uint8_t)(val & 0xFF);
    val >>= 8;
  }
}

static void _pack_u32_le(uint8_t* buf, uint32_t val) {
  for (int i = 0; i < 4; i++) {
    buf[i] = (uint8_t)(val & 0xFF);
    val >>= 8;
  }
}

// Build the canonical signed form into a freshly allocated buffer.
// Returns the buffer and its length via out_len, or NULL on failure.
static uint8_t* _envelope_sign_data_alloc(const key_envelope_t* env, size_t* out_len) {
  if (!env || !out_len) return NULL;
  size_t header = 1 + CRABS_MAX_USER_ID + 8 + CRABS_HASH_SIZE + 8 + 8 + 4;
  size_t total = header + env->sk_abe_len;
  uint8_t* buf = get_clear_memory(total);
  if (!buf) return NULL;
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
  _pack_u32_le(buf + pos, env->sk_abe_len);
  pos += 4;
  if (env->sk_abe_len > 0 && env->sk_abe) {
    memcpy(buf + pos, env->sk_abe, env->sk_abe_len);
  }
  pos += env->sk_abe_len;
  *out_len = total;
  return buf;
}

key_envelope_t* crypto_key_envelope_create(
    const abe_master_key_t* mk,
    const uint8_t node_private_key[32],
    const user_t* user,
    uint64_t state_version,
    uint64_t issued_at,
    uint64_t expires_at) {
  if (!mk || !node_private_key || !user) return NULL;

  // Build the attribute string and its hash.
  char attrs[CRABS_MAX_POLICY_EXPR];
  _build_attr_string(user, attrs, sizeof(attrs));
  uint8_t attributes_hash[CRABS_HASH_SIZE];
  if (crypto_compute_attributes_hash(user, attributes_hash) != CRABS_SUCCESS) return NULL;

  key_envelope_t* env = get_clear_memory(sizeof(key_envelope_t));
  if (!env) return NULL;

  env->format_version = KEY_ENVELOPE_FORMAT_V1;
  strncpy(env->user_id, user->user_id, CRABS_MAX_USER_ID - 1);
  env->state_version = state_version;
  memcpy(env->attributes_hash, attributes_hash, CRABS_HASH_SIZE);
  env->issued_at = issued_at;
  env->expires_at = expires_at;

  // Generate a real CP-ABE user key for the user's attributes and embed its
  // serialized form. (M-6: previously the envelope embedded the public MPK as
  // the "secret" key, so the delivered "secret" was public.)
  abe_user_key_t* abe_sk = crypto_abe_keygen(mk, attrs);
  if (!abe_sk) {
    free(env);
    return NULL;
  }
  size_t sk_len = crypto_abe_user_key_serialize(abe_sk, NULL, 0);
  if (sk_len == 0 || sk_len > 4096) {
    crypto_abe_user_key_destroy(abe_sk);
    free(env);
    return NULL;
  }
  env->sk_abe = get_clear_memory(sk_len);
  if (!env->sk_abe) {
    crypto_abe_user_key_destroy(abe_sk);
    free(env);
    return NULL;
  }
  env->sk_abe_len = (uint32_t)crypto_abe_user_key_serialize(abe_sk, env->sk_abe, sk_len);
  crypto_abe_user_key_destroy(abe_sk);

  size_t sign_len = 0;
  uint8_t* sign_data = _envelope_sign_data_alloc(env, &sign_len);
  if (!sign_data) {
    OPENSSL_cleanse(env->sk_abe, env->sk_abe_len);
    free(env->sk_abe);
    free(env);
    return NULL;
  }

  crabs_error_e rc = crypto_ecdsa_sign(node_private_key, sign_data, sign_len, env->signature);
  OPENSSL_cleanse(sign_data, sign_len);
  free(sign_data);
  if (rc != CRABS_SUCCESS) {
    OPENSSL_cleanse(env->sk_abe, env->sk_abe_len);
    free(env->sk_abe);
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

  size_t sign_len = 0;
  uint8_t* sign_data = _envelope_sign_data_alloc(envelope, &sign_len);
  if (!sign_data) return false;

  bool ok = crypto_ecdsa_verify(node_public_key, sign_data, sign_len, envelope->signature);
  OPENSSL_cleanse(sign_data, sign_len);
  free(sign_data);
  return ok;
}

void crypto_key_envelope_destroy(key_envelope_t* envelope) {
  if (envelope) {
    if (envelope->sk_abe) {
      OPENSSL_cleanse(envelope->sk_abe, envelope->sk_abe_len);
      free(envelope->sk_abe);
    }
    free(envelope);
  }
}

// Flat envelope layout (network/transport form):
// format_version(1) + user_id(64) + state_version(8) + attributes_hash(32)
// + issued_at(8) + expires_at(8) + sk_abe_len(4) + sk_abe(sk_abe_len)
// + signature(64)
size_t crypto_key_envelope_serialize(const key_envelope_t* env,
                                       uint8_t* buf, size_t buf_len) {
  if (!env || !buf) return 0;
  size_t header = 1 + CRABS_MAX_USER_ID + 8 + CRABS_HASH_SIZE + 8 + 8 + 4;
  size_t total = header + env->sk_abe_len + CRABS_SIG_SIZE;
  if (total > buf_len) return 0;
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
  _pack_u32_le(buf + pos, env->sk_abe_len);
  pos += 4;
  if (env->sk_abe_len > 0 && env->sk_abe) {
    memcpy(buf + pos, env->sk_abe, env->sk_abe_len);
  }
  pos += env->sk_abe_len;
  memcpy(buf + pos, env->signature, CRABS_SIG_SIZE);
  pos += CRABS_SIG_SIZE;
  return pos;
}

key_envelope_t* crypto_key_envelope_deserialize(const abe_master_key_t* mk,
                                                   const uint8_t* buf, size_t len) {
  if (!buf || len < 1 + CRABS_MAX_USER_ID + 8 + CRABS_HASH_SIZE + 8 + 8 + 4 + CRABS_SIG_SIZE) {
    return NULL;
  }
  key_envelope_t* env = get_clear_memory(sizeof(key_envelope_t));
  if (!env) return NULL;
  size_t pos = 0;
  env->format_version = buf[pos++];
  memcpy(env->user_id, buf + pos, CRABS_MAX_USER_ID);
  pos += CRABS_MAX_USER_ID;
  for (int i = 0; i < 8; i++) env->state_version |= ((uint64_t)buf[pos + i]) << (i * 8);
  pos += 8;
  memcpy(env->attributes_hash, buf + pos, CRABS_HASH_SIZE);
  pos += CRABS_HASH_SIZE;
  for (int i = 0; i < 8; i++) env->issued_at |= ((uint64_t)buf[pos + i]) << (i * 8);
  pos += 8;
  for (int i = 0; i < 8; i++) env->expires_at |= ((uint64_t)buf[pos + i]) << (i * 8);
  pos += 8;
  uint32_t sk_len = 0;
  for (int i = 0; i < 4; i++) sk_len |= ((uint32_t)buf[pos + i]) << (i * 8);
  pos += 4;
  if (pos + sk_len + CRABS_SIG_SIZE > len) {
    free(env);
    return NULL;
  }
  if (sk_len > 0) {
    env->sk_abe = get_clear_memory(sk_len);
    if (!env->sk_abe) { free(env); return NULL; }
    memcpy(env->sk_abe, buf + pos, sk_len);
  }
  env->sk_abe_len = sk_len;
  pos += sk_len;
  memcpy(env->signature, buf + pos, CRABS_SIG_SIZE);
  (void)mk; // public params attached lazily on decrypt via the master key
  return env;
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

  // Step 5: Generate a new ABE key envelope for the user's current attributes.
  key_envelope_t* envelope = crypto_key_envelope_create(
      mk, node_private_key, user, state_version, issued_at, 0);
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