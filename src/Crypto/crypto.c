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
static atomic_int _oabe_init_state = 0; // 0=uninit, 1=initializing, 2=ready
static void _ensure_oabe_init(void) {
#ifdef __EMSCRIPTEN__
  // WASM is single-threaded — C11 atomics may not be available without
  // the -pthread flag. Use a simple flag instead.
  if (_oabe_init_state == 0) {
    if (oabe_init() == OABE_SUCCESS) {
      _oabe_init_state = 2;
    }
  }
#else
  // R8-C-1: distinguish "initializing" from "ready". The prior code set the
  // state to 1 before oabe_init() completed, so a concurrent thread that lost
  // the CAS saw state==1 and used OpenABE before it was initialized.
  for (;;) {
    int expected = 0;
    if (atomic_compare_exchange_strong(&_oabe_init_state, &expected, 1)) {
      // This thread owns initialization.
      if (oabe_init() == OABE_SUCCESS) {
        atomic_store(&_oabe_init_state, 2);
      } else {
        atomic_store(&_oabe_init_state, 0);
      }
      return;
    }
    if (atomic_load(&_oabe_init_state) == 2) return; // already ready
    // state == 1: another thread is initializing. Spin until it finishes,
    // then loop back (retry if it failed, return if it succeeded).
    while (atomic_load(&_oabe_init_state) == 1) {
    }
  }
#endif
}

// Internal struct definitions for the opaque ABE types.
//
// The master key holds a real Waters '09 CP-ABE authority context (for
// attribute-bound keygen). The capability vault is encrypted with real
// CP-ABE (ABE-KEM + DEM): the encapsulated GT element is hashed to a
// symmetric key and the payload is AES-256-GCM encrypted, so only a user key
// whose attributes satisfy the access policy can recover the symmetric key
// and decrypt. This closes audit C-1: the prior scheme derived the vault
// key from PUBLIC material (HMAC(MPK, policy)), so anyone with the public
// params could decrypt the vault. (The DEM was added to openabe-c itself
// — see oabe_context.c.)
struct abe_master_key_t {
  OABE_ContextCP*   ctx;             // authority context (params + msk + keystore)
  OABE_ByteString*  public_params;   // serialized MPK
  OABE_ByteString*  master_secret;   // serialized MSK
  // Audit N-9: per-authority key-ID sequence. The prior global counter meant
  // multiple abe_master_key_t instances (e.g. independent state machines with
  // independent ABE domains) would generate colliding key IDs, and the
  // oabe_context_delete_key call could remove the wrong key. Scoping the
  // sequence to the authority keeps key IDs unique within an authority.
  atomic_uint        key_seq;
};

struct abe_user_key_t {
  char              attrs[CRABS_MAX_POLICY_EXPR];  // original attribute string (for identity)
  OABE_ByteString*  key_bytes;       // serialized CP-ABE user key
  OABE_ByteString*  public_params;   // copy of MPK public params (for decrypt)
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

  // R8-C-7: validate the private key is in [1, n-1]. A zero or out-of-range
  // key yields a point-at-infinity public key silently.
  const EC_GROUP* group = EC_KEY_get0_group(eckey);
  BIGNUM* order = BN_new();
  if (!order || EC_GROUP_get_order(group, order, NULL) != 1) {
    BN_free(order);
    BN_free(bn_priv);
    EC_KEY_free(eckey);
    return NULL;
  }
  if (BN_is_zero(bn_priv) || BN_is_negative(bn_priv) || BN_cmp(bn_priv, order) >= 0) {
    BN_free(order);
    BN_free(bn_priv);
    EC_KEY_free(eckey);
    return NULL;
  }
  BN_free(order);

  if (EC_KEY_set_private_key(eckey, bn_priv) != 1) {
    BN_free(bn_priv);
    EC_KEY_free(eckey);
    return NULL;
  }

  // Derive public key from private key
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

// Derive the compressed public key (33 bytes) from a 32-byte private key.
// Used by the CLI to restore node-key custody after loading a serialized
// state (audit L-l): the operator persists the private key out-of-band and
// re-custodies it via cli_node_load_key.
crabs_error_e crypto_ecdsa_derive_public_key(const uint8_t private_key[32],
                                                uint8_t public_key[33]) {
  if (private_key == NULL || public_key == NULL) return CRABS_ERR_INVALID_PARAM;
  EC_KEY* eckey = _eckey_from_private(private_key);
  if (eckey == NULL) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;
  size_t pub_len = EC_POINT_point2oct(
    EC_KEY_get0_group(eckey),
    EC_KEY_get0_public_key(eckey),
    form, public_key, 33, NULL);
  EC_KEY_free(eckey);
  return (pub_len == 33) ? CRABS_SUCCESS : CRABS_ERR_CRYPTOGRAPHIC_ERROR;
}

// Audit N-3: validate that a compressed secp256k1 public key decodes to a
// point that is on the curve and is not the point at infinity. The ECIES
// envelope encryption (_ecdh_shared_secret) performs ECDH with an unvalidated
// recipient public key; a key that decodes to the point at infinity would
// produce an all-zero shared secret (predictable AES key → envelope
// confidentiality defeated). secp256k1 has cofactor 1 so small-subgroup
// attacks do not apply, but the infinity check is still required. This is
// called at user registration and key registration so invalid keys never
// enter the attribute machine or the keyring.
bool crypto_ecdsa_validate_public_key(const uint8_t public_key[33]) {
  if (public_key == NULL) return false;
  EC_KEY* eckey = _eckey_from_public(public_key);
  if (eckey == NULL) return false;
  const EC_GROUP* group = EC_KEY_get0_group(eckey);
  const EC_POINT* point = EC_KEY_get0_public_key(eckey);
  bool valid = false;
  if (group != NULL && point != NULL) {
    // Must not be the point at infinity (ECDH with infinity yields zero).
    if (!EC_POINT_is_at_infinity(group, point)) {
      // Must lie on the curve (o2i_ECPublicKey already checks group membership
      // in most OpenSSL builds, but verify explicitly for defense in depth).
      int on_curve = EC_POINT_is_on_curve(group, point, NULL);
      valid = (on_curve == 1);
    }
  }
  EC_KEY_free(eckey);
  return valid;
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
  unsigned int der_sig_len = sizeof(der_sig);
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

static bool _eval_policy_expr(const char** pp, const char* attrs);

// R7-09: evaluate a numeric comparison "name op value" against the attribute
// string (comma-separated "name:value" tokens). The right operand is parsed as
// a numeric literal; a non-numeric operand yields 0 (best-effort).
static bool _eval_comparison(const char* name, const char* op, const char* value,
                             const char* attrs) {
  size_t name_len = strlen(name);
  const char* p = attrs;
  long long attr_val = 0;
  bool found = false;
  while (*p) {
    while (*p == ' ' || *p == ',') p++;
    const char* tok_start = p;
    while (*p && *p != ',') p++;
    size_t tok_len = (size_t)(p - tok_start);
    if (tok_len > name_len + 1 &&
        strncmp(tok_start, name, name_len) == 0 && tok_start[name_len] == ':') {
      char val_buf[64];
      size_t val_len = tok_len - name_len - 1;
      if (val_len >= sizeof(val_buf)) val_len = sizeof(val_buf) - 1;
      memcpy(val_buf, tok_start + name_len + 1, val_len);
      val_buf[val_len] = '\0';
      attr_val = atoll(val_buf);
      found = true;
      break;
    }
  }
  if (!found) return false;

  long long cmp_val = atoll(value);
  if (strcmp(op, ">=") == 0) return attr_val >= cmp_val;
  if (strcmp(op, "<=") == 0) return attr_val <= cmp_val;
  if (strcmp(op, ">") == 0) return attr_val > cmp_val;
  if (strcmp(op, "<") == 0) return attr_val < cmp_val;
  if (strcmp(op, "==") == 0) return attr_val == cmp_val;
  if (strcmp(op, "!=") == 0) return attr_val != cmp_val;
  return false;
}

// Parse a primary policy term: an attribute token, a numeric comparison, or a
// parenthesized expression. Advances *pp past the term.
static bool _eval_policy_term(const char** pp, const char* attrs) {
  while (**pp == ' ') (*pp)++;

  if (**pp == '(') {
    (*pp)++;
    bool result = _eval_policy_expr(pp, attrs);
    while (**pp == ' ') (*pp)++;
    if (**pp == ')') (*pp)++;
    return result;
  }

  // Parse the left token (attribute name or name:value).
  const char* start = *pp;
  while (**pp && **pp != ' ' && **pp != ')' && **pp != ',') (*pp)++;
  size_t len = (size_t)(*pp - start);
  if (len == 0) return false;

  char left[CRABS_MAX_POLICY_EXPR];
  if (len >= sizeof(left)) len = sizeof(left) - 1;
  memcpy(left, start, len);
  left[len] = '\0';

  // Check for a comparison operator after the left token.
  const char* save = *pp;
  while (**pp == ' ') (*pp)++;
  const char* op = NULL;
  if (strncmp(*pp, ">=", 2) == 0) { op = ">="; *pp += 2; }
  else if (strncmp(*pp, "<=", 2) == 0) { op = "<="; *pp += 2; }
  else if (strncmp(*pp, "==", 2) == 0) { op = "=="; *pp += 2; }
  else if (strncmp(*pp, "!=", 2) == 0) { op = "!="; *pp += 2; }
  else if (**pp == '>') { op = ">"; *pp += 1; }
  else if (**pp == '<') { op = "<"; *pp += 1; }

  if (op != NULL) {
    while (**pp == ' ') (*pp)++;
    const char* rstart = *pp;
    while (**pp && **pp != ' ' && **pp != ')' && **pp != ',') (*pp)++;
    size_t rlen = (size_t)(*pp - rstart);
    if (rlen == 0) return false;
    char right[CRABS_MAX_POLICY_EXPR];
    if (rlen >= sizeof(right)) rlen = sizeof(right) - 1;
    memcpy(right, rstart, rlen);
    right[rlen] = '\0';
    return _eval_comparison(left, op, right, attrs);
  }

  // No comparison — restore the pointer and treat as a bare attribute token.
  *pp = save;
  return _attr_in_list(left, attrs);
}

static bool _eval_policy_expr(const char** pp, const char* attrs) {
  while (**pp == ' ') (*pp)++;

  // Prefix operators (legacy form): AND <l> <r>, OR <l> <r>.
  if (strncmp(*pp, "AND", 3) == 0 && !isalpha((unsigned char)(*pp)[3])) {
    *pp += 3;
    while (**pp == ' ') (*pp)++;
    bool left = _eval_policy_expr(pp, attrs);
    bool right = _eval_policy_expr(pp, attrs);
    return left && right;
  }

  if (strncmp(*pp, "OR", 2) == 0 && !isalpha((unsigned char)(*pp)[2])) {
    *pp += 2;
    while (**pp == ' ') (*pp)++;
    bool left = _eval_policy_expr(pp, attrs);
    bool right = _eval_policy_expr(pp, attrs);
    return left || right;
  }

  // Parse a primary term, then handle infix operators (R7-09: the
  // preprocessor emits "left AND right" / "left OR right").
  bool left = _eval_policy_term(pp, attrs);

  while (**pp == ' ') (*pp)++;
  if (strncmp(*pp, "AND", 3) == 0 && !isalpha((unsigned char)(*pp)[3])) {
    *pp += 3;
    bool right = _eval_policy_expr(pp, attrs);
    return left && right;
  }
  if (strncmp(*pp, "OR", 2) == 0 && !isalpha((unsigned char)(*pp)[2])) {
    *pp += 2;
    bool right = _eval_policy_expr(pp, attrs);
    return left || right;
  }
  return left;
}

bool crypto_abe_eval_policy(const char* policy, const char* attrs) {
  if (!policy || !attrs) return false;
  // Audit N-4: an empty policy means "no attribute requirement" — but this
  // function evaluates the ABE attribute policy in isolation, and an empty
  // policy should NOT be treated as satisfied (that made the function a
  // silent free-pass for any future caller that calls it directly). The
  // authorization path in crypto_verify_operation_auth handles the
  // "no attribute requirement" case separately by checking has_attr_policy
  // before calling this function; it still requires a valid signature. Here,
  // an empty policy returns false so a bare attribute policy must always
  // name at least one attribute to match.
  if (strlen(policy) == 0) return false;

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
  if (atomic_load(&_oabe_init_state) != 2) return NULL;

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
  return mk;
}

void crypto_abe_master_key_destroy(abe_master_key_t* mk) {
  if (mk) {
    // Audit N-17: cleanse the master secret before freeing it. The MSK is the
    // root trust material — anyone who recovers it from freed heap memory can
    // forge any attribute. oabe_bytestring_free does not zero the buffer, so
    // OPENSSL_cleanse the data first. (Public params are non-secret.)
    if (mk->master_secret) {
      const uint8_t* ms_data = oabe_bytestring_get_const_ptr(mk->master_secret);
      size_t ms_len = oabe_bytestring_get_size(mk->master_secret);
      if (ms_data != NULL && ms_len > 0) {
        OPENSSL_cleanse((void*)ms_data, ms_len);
      }
      oabe_bytestring_free(mk->master_secret);
    }
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

  strncpy(sk->attrs, attrs, CRABS_MAX_POLICY_EXPR - 1);
  sk->attrs[CRABS_MAX_POLICY_EXPR - 1] = '\0';

  char oabe_attrs[CRABS_MAX_POLICY_EXPR];
  _crabs_attrs_to_oabe(attrs, oabe_attrs, sizeof(oabe_attrs));

  // Use the master key's unique key id per user key to avoid collisions.
  // Audit N-9: the sequence is per-authority (stored in abe_master_key_t) so
  // multiple independent ABE domains do not generate colliding key IDs.
  char key_id[64];
  unsigned seq = (unsigned)atomic_fetch_add(&((abe_master_key_t*)mk)->key_seq, 1);
  snprintf(key_id, sizeof(key_id), "u%u", seq);

  if (oabe_context_cp_keygen(mk->ctx, key_id, oabe_attrs) != OABE_SUCCESS) {
    free(sk);
    return NULL;
  }
  if (oabe_context_cp_export_key(mk->ctx, key_id, &sk->key_bytes) != OABE_SUCCESS) {
    // R8-C-8: remove the key from the authority keystore on export failure,
    // otherwise every failed keygen leaks a key in the keystore.
    oabe_context_delete_key((OABE_Context*)mk->ctx, key_id);
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
    if (sk->key_bytes) {
      const uint8_t* key_data = oabe_bytestring_get_const_ptr(sk->key_bytes);
      size_t key_len = oabe_bytestring_get_size(sk->key_bytes);
      if (key_data != NULL && key_len > 0) {
        OPENSSL_cleanse((void*)key_data, key_len);
      }
      oabe_bytestring_free(sk->key_bytes);
    }
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
// Master Key Durability (§11.5)
// ============================================================

// oabe-c's oabe_secret_key_deserialize parses the MSK envelope but leaves the
// alpha/beta master scalars unset (see the "placeholder" note in oabe_key.c),
// which would leave a restored authority minting garbage keys. The scalars are
// present in the serialized MSK (key_type + scheme bytes, then two packed ZP
// elements), so parse them back out here and attach them to the restored
// context's secret key.
static bool _restore_msk_scalars(OABE_ContextCP* ctx, const OABE_ByteString* msk) {
  if (!ctx || !msk || !ctx->secret_key) return false;
  size_t offset = 2;                     // key_type byte + scheme byte
  uint32_t alpha_len = 0;
  uint32_t beta_len = 0;
  if (oabe_bytestring_unpack32(msk, &offset, &alpha_len) != OABE_SUCCESS ||
      offset + alpha_len + 4 > oabe_bytestring_get_size(msk)) {
    return false;
  }
  offset += alpha_len;                   // skip the alpha element bytes
  if (oabe_bytestring_unpack32(msk, &offset, &beta_len) != OABE_SUCCESS) {
    return false;
  }
  const uint8_t* msk_data = oabe_bytestring_get_const_ptr(msk);
  size_t header_len = 2 + 4 + alpha_len + 4;
  if (header_len + beta_len > oabe_bytestring_get_size(msk)) return false;

  OABE_ByteString* alpha_bytes = oabe_bytestring_new_from_data(msk_data + 6, alpha_len);
  OABE_ByteString* beta_bytes = oabe_bytestring_new_from_data(msk_data + header_len, beta_len);
  OABE_ZP* alpha_scalar = NULL;
  OABE_ZP* beta_scalar = NULL;
  if (!alpha_bytes || !beta_bytes ||
      oabe_zp_deserialize(ctx->base.group, alpha_bytes, &alpha_scalar) != OABE_SUCCESS ||
      oabe_zp_deserialize(ctx->base.group, beta_bytes, &beta_scalar) != OABE_SUCCESS) {
    if (alpha_scalar) oabe_zp_free(alpha_scalar);
    if (beta_scalar) oabe_zp_free(beta_scalar);
    // Same rationale as Audit N-17: cleanse the master scalars before the
    // transient buffers holding them are freed.
    if (alpha_bytes) {
      const uint8_t* alpha_data = oabe_bytestring_get_const_ptr(alpha_bytes);
      size_t alpha_data_len = oabe_bytestring_get_size(alpha_bytes);
      if (alpha_data != NULL && alpha_data_len > 0) {
        OPENSSL_cleanse((void*)alpha_data, alpha_data_len);
      }
      oabe_bytestring_free(alpha_bytes);
    }
    if (beta_bytes) {
      const uint8_t* beta_data = oabe_bytestring_get_const_ptr(beta_bytes);
      size_t beta_data_len = oabe_bytestring_get_size(beta_bytes);
      if (beta_data != NULL && beta_data_len > 0) {
        OPENSSL_cleanse((void*)beta_data, beta_data_len);
      }
      oabe_bytestring_free(beta_bytes);
    }
    return false;
  }
  // Cleanse the transient master-scalar copies before freeing.
  const uint8_t* alpha_data = oabe_bytestring_get_const_ptr(alpha_bytes);
  size_t alpha_data_len = oabe_bytestring_get_size(alpha_bytes);
  if (alpha_data != NULL && alpha_data_len > 0) {
    OPENSSL_cleanse((void*)alpha_data, alpha_data_len);
  }
  const uint8_t* beta_data = oabe_bytestring_get_const_ptr(beta_bytes);
  size_t beta_data_len = oabe_bytestring_get_size(beta_bytes);
  if (beta_data != NULL && beta_data_len > 0) {
    OPENSSL_cleanse((void*)beta_data, beta_data_len);
  }
  oabe_bytestring_free(alpha_bytes);
  oabe_bytestring_free(beta_bytes);
  ctx->secret_key->alpha = alpha_scalar;
  ctx->secret_key->beta = beta_scalar;
  return true;
}

size_t crypto_master_key_serialize(const abe_master_key_t* mk,
                                     uint8_t* buf, size_t buf_len) {
  if (!mk || !mk->public_params || !mk->master_secret) return 0;
  size_t pp_len = oabe_bytestring_get_size(mk->public_params);
  size_t ms_len = oabe_bytestring_get_size(mk->master_secret);
  size_t total = 2 + 1 + 4 + pp_len + 4 + ms_len;
  if (!buf) return total;               // size probe
  if (buf_len < total) return 0;

  size_t offset = 0;
  buf[offset++] = 0x4D;                    // 'M'
  buf[offset++] = 0x4B;                    // 'K'
  buf[offset++] = CRABS_MSK_FORMAT_VERSION;
  uint32_t pp_len32 = (uint32_t)pp_len;
  uint32_t ms_len32 = (uint32_t)ms_len;
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    buf[offset++] = (uint8_t)(pp_len32 >> (8 * byte_index));
  }
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    buf[offset++] = (uint8_t)(ms_len32 >> (8 * byte_index));
  }
  memcpy(buf + offset, oabe_bytestring_get_const_ptr(mk->public_params), pp_len);
  offset += pp_len;
  memcpy(buf + offset, oabe_bytestring_get_const_ptr(mk->master_secret), ms_len);
  offset += ms_len;
  return offset;
}

abe_master_key_t* crypto_master_key_deserialize(const uint8_t* buf, size_t len) {
  if (!buf || len < 2 + 1 + 4 + 4) return NULL;
  if (buf[0] != 0x4D || buf[1] != 0x4B || buf[2] != CRABS_MSK_FORMAT_VERSION) return NULL;
  _ensure_oabe_init();
  if (atomic_load(&_oabe_init_state) != 2) return NULL;

  size_t offset = 3;
  uint32_t pp_len = 0;
  uint32_t ms_len = 0;
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    pp_len |= (uint32_t)buf[offset++] << (8 * byte_index);
  }
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    ms_len |= (uint32_t)buf[offset++] << (8 * byte_index);
  }
  // Overflow-safe bounds: at this point len >= 11 and offset == 11, so both
  // subtractions below are well-defined.
  if ((size_t)pp_len > len - offset) return NULL;
  if ((size_t)ms_len > len - offset - pp_len) return NULL;

  abe_master_key_t* mk = get_clear_memory(sizeof(abe_master_key_t));
  if (!mk) return NULL;
  mk->ctx = oabe_context_cp_new();
  if (!mk->ctx) { free(mk); return NULL; }

  OABE_ByteString* params = oabe_bytestring_new_from_data(buf + offset, pp_len);
  OABE_ByteString* secret = oabe_bytestring_new_from_data(buf + offset + pp_len, ms_len);
  if (!params || !secret ||
      oabe_context_cp_set_public_params(mk->ctx, params) != OABE_SUCCESS ||
      oabe_context_cp_set_secret_key(mk->ctx, secret) != OABE_SUCCESS) {
    if (params) oabe_bytestring_free(params);
    if (secret) {
      // Same rationale as Audit N-17: the MSK is root trust material, and
      // oabe_bytestring_free does not zero the buffer.
      const uint8_t* secret_data = oabe_bytestring_get_const_ptr(secret);
      size_t secret_data_len = oabe_bytestring_get_size(secret);
      if (secret_data != NULL && secret_data_len > 0) {
        OPENSSL_cleanse((void*)secret_data, secret_data_len);
      }
      oabe_bytestring_free(secret);
    }
    oabe_context_cp_free(mk->ctx);
    free(mk);
    return NULL;
  }
  oabe_bytestring_free(params);
  if (!_restore_msk_scalars(mk->ctx, secret)) {
    const uint8_t* secret_data = oabe_bytestring_get_const_ptr(secret);
    size_t secret_data_len = oabe_bytestring_get_size(secret);
    if (secret_data != NULL && secret_data_len > 0) {
      OPENSSL_cleanse((void*)secret_data, secret_data_len);
    }
    oabe_bytestring_free(secret);
    oabe_context_cp_free(mk->ctx);
    free(mk);
    return NULL;
  }
  {
    const uint8_t* secret_data = oabe_bytestring_get_const_ptr(secret);
    size_t secret_data_len = oabe_bytestring_get_size(secret);
    if (secret_data != NULL && secret_data_len > 0) {
      OPENSSL_cleanse((void*)secret_data, secret_data_len);
    }
    oabe_bytestring_free(secret);
  }
  if (oabe_context_cp_get_public_params(mk->ctx, &mk->public_params) != OABE_SUCCESS ||
      oabe_context_cp_get_secret_key(mk->ctx, &mk->master_secret) != OABE_SUCCESS) {
    crypto_abe_master_key_destroy(mk);
    return NULL;
  }
  return mk;
}

// ============================================================
// ABE Encrypt — real CP-ABE (Waters '09) via OpenABE
// ============================================================

abe_ciphertext_t* crypto_abe_encrypt(const abe_master_key_t* mk,
                                       const uint8_t* msg, size_t msg_len,
                                       const char* policy) {
  if (!mk || !msg || !policy || !mk->public_params) return NULL;
  _ensure_oabe_init();

  abe_ciphertext_t* ct = get_clear_memory(sizeof(abe_ciphertext_t));
  if (!ct) return NULL;
  strncpy(ct->policy, policy, CRABS_MAX_POLICY_EXPR - 1);
  ct->policy[CRABS_MAX_POLICY_EXPR - 1] = '\0';

  // Real CP-ABE: build an encryptor context with only the public params and
  // encrypt under the access policy. The OpenABE context performs the
  // ABE-KEM and the DEM (hashes the encapsulated GT element to a symmetric
  // key and AES-256-GCM encrypts the plaintext), so the resulting ciphertext
  // is only recoverable by a user key whose attributes satisfy the policy.
  OABE_ContextCP* enc_ctx = oabe_context_cp_new();
  if (!enc_ctx) { free(ct); return NULL; }
  if (oabe_context_cp_set_public_params(enc_ctx, mk->public_params) != OABE_SUCCESS) {
    oabe_context_cp_free(enc_ctx); free(ct); return NULL;
  }
  if (oabe_context_cp_encrypt(enc_ctx, policy, msg, msg_len, &ct->ct_bytes) != OABE_SUCCESS) {
    oabe_context_cp_free(enc_ctx); free(ct); return NULL;
  }
  oabe_context_cp_free(enc_ctx);
  return ct;
}

void crypto_abe_ciphertext_destroy(abe_ciphertext_t* ct) {
  if (ct) {
    if (ct->ct_bytes) oabe_bytestring_free(ct->ct_bytes);
    free(ct);
  }
}

// Accessors for opaque ciphertext (used by language bindings).
const char* crypto_abe_ciphertext_get_policy(const abe_ciphertext_t* ct) {
  if (!ct) return NULL;
  return ct->policy;
}

const uint8_t* crypto_abe_ciphertext_get_data(const abe_ciphertext_t* ct, size_t* len) {
  if (!ct || !ct->ct_bytes) {
    if (len) *len = 0;
    return NULL;
  }
  if (len) *len = oabe_bytestring_get_size(ct->ct_bytes);
  return (const uint8_t*)oabe_bytestring_get_const_ptr(ct->ct_bytes);
}

// ============================================================
// ABE Decrypt — real CP-ABE user-key decryption (ABE-KEM + DEM).
// ============================================================

crabs_error_e crypto_abe_decrypt(const abe_user_key_t* sk, const abe_ciphertext_t* ct,
                         uint8_t** out, size_t* out_len) {
  if (!sk || !ct || !out || !out_len) return CRABS_ERR_INVALID_PARAM;
  if (!sk->key_bytes || !sk->public_params || !ct->ct_bytes) {
    return CRABS_ERR_INVALID_PARAM;
  }
  _ensure_oabe_init();

  OABE_ContextCP* dec_ctx = oabe_context_cp_new();
  if (!dec_ctx) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  if (oabe_context_cp_set_public_params(dec_ctx, sk->public_params) != OABE_SUCCESS) {
    oabe_context_cp_free(dec_ctx); return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  if (oabe_context_cp_import_key(dec_ctx, "dec_key", sk->key_bytes) != OABE_SUCCESS) {
    oabe_context_cp_free(dec_ctx); return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  size_t cap = oabe_bytestring_get_size(ct->ct_bytes) + 64;
  uint8_t* plain = get_clear_memory(cap);
  if (!plain) { oabe_context_cp_free(dec_ctx); return CRABS_ERR_OOM; }
  size_t plain_len = cap;
  OABE_ERROR orc = oabe_context_cp_decrypt(dec_ctx, "dec_key", ct->ct_bytes,
                                             plain, &plain_len);
  oabe_context_cp_free(dec_ctx);
  if (orc != OABE_SUCCESS) {
    OPENSSL_cleanse(plain, cap); free(plain);
    return CRABS_ERR_UNAUTHORIZED; // attributes don't satisfy the policy, or tampering
  }
  *out = plain;
  *out_len = plain_len;
  return CRABS_SUCCESS;
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

static void _build_attr_string(const user_t* user, char* buf, size_t buf_len, uint64_t now_ms) {
  if (!user || !buf || buf_len == 0) {
    if (buf) buf[0] = '\0';
    return;
  }

  // Audit F-1: emit the full "name:value" token (do NOT strip the name).
  // Policies are matched as whole tokens by crypto_abe_eval_policy, so a
  // policy "role:admin" matches only an attribute "role:admin" — a user
  // who self-asserts "clearance:admin" cannot satisfy "role:admin". The
  // prior code stripped the name, making "role:admin" and "dept:admin"
  // collide and letting self_assert("clearance","admin") satisfy "admin".
  // Fail closed on overflow rather than truncating mid-token: a truncated
  // "role:admi" token could alias a different legitimate token.
  size_t pos = 0;
  for (uint32_t i = 0; i < user->attribute_count; i++) {
    const char* token = user->attributes[i].value;
    size_t tok_len = strlen(token);
    if (tok_len == 0) continue;
    size_t need = (pos > 0 ? 1 : 0) + tok_len + 1;
    if (need > buf_len - pos) {
      // Overflow — fail closed: produce an empty string so the caller's
      // (typically uninitialized) buffer is NUL-terminated and policy
      // evaluation rejects rather than reading garbage.
      buf[0] = '\0';
      return;
    }
    if (pos > 0) buf[pos++] = ',';
    memcpy(buf + pos, token, tok_len);
    pos += tok_len;
  }

  // Append temporary attribute tokens. Audit R4-1: use temp->name which holds
  // the full "name:value" token (e.g. "clearance:secret"), NOT temp->value
  // which holds only the value part ("secret"). The prior code emitted bare
  // values, so a temporary "clearance:secret" appeared as just "secret" in the
  // attribute string — failing to match "clearance:secret" policies while
  // colliding with bare "secret" policies from unrelated namespaces. Using
  // temp->name makes temporary attributes consistent with the F-1 fix for
  // permanent attributes (full name:value tokens everywhere).
  temp_attr_list_t* temp = user->temp_attrs;
  while (temp != NULL) {
    // R8-A-8: skip expired temporary attributes (fail-closed). When the clock
    // is 0 (uninitialized), treat any temp attribute with an expiry as expired
    // rather than including it and granting access the user should not have.
    if (temp->expires_at > 0 && (now_ms == 0 || temp->expires_at <= now_ms)) {
      temp = temp->next;
      continue;
    }
    const char* token = temp->name;
    size_t tok_len = strlen(token);
    if (tok_len > 0) {
      size_t need = (pos > 0 ? 1 : 0) + tok_len + 1;
      if (need > buf_len - pos) {
        buf[0] = '\0';
        return;
      }
      if (pos > 0) buf[pos++] = ',';
      memcpy(buf + pos, token, tok_len);
      pos += tok_len;
    }
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
      // R7-14: collapse to a single UNAUTHORIZED so an unauthenticated caller
      // cannot enumerate user IDs. The prior USER_NOT_FOUND leaked existence.
      result.error = CRABS_ERR_UNAUTHORIZED;
      return result;
    }

    // Fail closed: only ACTIVE users may authorize. SUSPENDED and REVOKED
    // users must be rejected. R7-14: collapse to a single UNAUTHORIZED so a
    // caller cannot learn a user's status.
    if (user->status != USER_ACTIVE) {
      result.error = CRABS_ERR_UNAUTHORIZED;
      return result;
    }

    // R7-L-8: evaluate BOTH the signature and the policy, then combine, so a
    // caller cannot distinguish "bad signature" from "bad policy" by timing.
    // The prior code returned early on a bad signature, skipping the policy
    // evaluation and leaking which check failed through response latency.
    // R8-C-2: once a user has a keyring, the legacy bootstrap key is rejected
    // (same rule as _verify_user_signature). Otherwise a rotated-away legacy
    // key would keep authorizing via this path.
    const bool sig_ok = (user->keys == NULL) &&
                        crypto_ecdsa_verify(user->public_key, serialized_op, op_len, signature);
    bool policy_ok = true;
    if (has_attr_policy) {
      char attr_string[CRABS_ATTR_STRING_MAX];
      _build_attr_string(user, attr_string, sizeof(attr_string), attr_machine->current_time_ms);
      policy_ok = crypto_abe_eval_policy(abe_policy, attr_string);
    }

    if (!sig_ok || !policy_ok) {
      result.error = CRABS_ERR_UNAUTHORIZED;
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
        // R8-C-2: skip users with a keyring on the legacy path (see Mode A).
        if (!has_attr_policy) {
          if (user->keys == NULL &&
              crypto_ecdsa_verify(user->public_key, serialized_op, op_len, signature)) {
            result.authorized = true;
            result.error = CRABS_SUCCESS;
            strncpy(result.signer_id, user->user_id, CRABS_MAX_USER_ID - 1);
            return result;
          }
        } else {
          char attr_string[CRABS_ATTR_STRING_MAX];
          _build_attr_string(user, attr_string, sizeof(attr_string), attr_machine->current_time_ms);
          if (crypto_abe_eval_policy(abe_policy, attr_string) &&
              user->keys == NULL &&
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
    uint64_t now_ms,
    const uint8_t* serialized_op, size_t op_len,
    const uint8_t* signature, uint32_t signature_len) {
  if (sig_scheme == SCHEME_UNSPECIFIED && (key_id == NULL || key_id[0] == '\0')) {
    // R7-04: once a user has a keyring, the legacy user->public_key path is
    // rejected. Otherwise a rotated-away legacy key would keep signing
    // operations as the user. Users with a keyring must identify the key
    // explicitly (key_id and/or sig_scheme).
    if (user->keys != NULL) {
      return CRABS_ERR_UNAUTHORIZED;
    }
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
    // Audit H-C: enforce key expiry. A key with expires_at set and past is
    // rejected. R7-10: now_ms == 0 means the platform has not injected a clock
    // yet — treat that as "expiry unknown" and fail closed rather than
    // silently accepting an expired key.
    if (key->expires_at != 0 && (now_ms == 0 || key->expires_at <= now_ms)) {
      return CRABS_ERR_UNAUTHORIZED;
    }
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
    if (key->expires_at != 0 && (now_ms == 0 || key->expires_at <= now_ms)) {
      return CRABS_ERR_UNAUTHORIZED;
    }
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
      // R7-14: collapse to a single UNAUTHORIZED so an unauthenticated caller
      // cannot enumerate user IDs. The prior USER_NOT_FOUND leaked existence.
      result.error = CRABS_ERR_UNAUTHORIZED;
      return result;
    }
    if (user->status != USER_ACTIVE) {
      // R7-14: collapse to a single UNAUTHORIZED so a caller cannot learn a
      // user's status (SUSPENDED vs REVOKED).
      result.error = CRABS_ERR_UNAUTHORIZED;
      return result;
    }

    // R7-L-8: evaluate BOTH the signature and the policy, then combine, so a
    // caller cannot distinguish "bad signature" from "bad policy" by timing.
    // The prior code returned early on a bad signature, skipping the policy
    // evaluation and leaking which check failed through response latency.
    crabs_error_e sig_rc = _verify_user_signature(user, key_id, sig_scheme,
                                                    attr_machine->current_time_ms,
                                                    serialized_op, op_len,
                                                    signature, signature_len);
    bool policy_ok = true;
    if (has_attr_policy) {
      char attr_string[CRABS_ATTR_STRING_MAX];
      _build_attr_string(user, attr_string, sizeof(attr_string), attr_machine->current_time_ms);
      policy_ok = crypto_abe_eval_policy(abe_policy, attr_string);
    }

    if (sig_rc != CRABS_SUCCESS || !policy_ok) {
      result.error = CRABS_ERR_UNAUTHORIZED;
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
          char attr_string[CRABS_ATTR_STRING_MAX];
          _build_attr_string(user, attr_string, sizeof(attr_string), attr_machine->current_time_ms);
          attr_ok = crypto_abe_eval_policy(abe_policy, attr_string);
        }
        if (attr_ok) {
          crabs_error_e sig_rc;
          if (sig_scheme != SCHEME_UNSPECIFIED || (key_id != NULL && key_id[0] != '\0')) {
            sig_rc = _verify_user_signature(user, key_id, sig_scheme,
                                             attr_machine->current_time_ms,
                                             serialized_op, op_len,
                                             signature, signature_len);
          } else {
            // R8-C-2: route the legacy path through _verify_user_signature so
            // a user with a keyring cannot authorize with the rotated-away
            // bootstrap key.
            sig_rc = _verify_user_signature(user, NULL, SCHEME_UNSPECIFIED,
                                             attr_machine->current_time_ms,
                                             serialized_op, op_len,
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
    const char* abe_policy,
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
  // R8-C-6: collapse user-not-found / suspended to UNAUTHORIZED so a caller
  // cannot probe for user existence or status (matching the R7-14 collapse in
  // Mode A).
  if (user == NULL) return CRABS_ERR_UNAUTHORIZED;
  if (user->status != USER_ACTIVE) return CRABS_ERR_UNAUTHORIZED;
  // R7-L-9: a co-signer is an approver and must satisfy the op's ABE policy,
  // not merely be an active user with a valid signature. Otherwise a
  // threshold-2 "role:admin" policy is met by one admin plus any active user.
  if (abe_policy != NULL && abe_policy[0] != '\0') {
    char attr_string[CRABS_ATTR_STRING_MAX];
    _build_attr_string(user, attr_string, sizeof(attr_string), attr_machine->current_time_ms);
    if (!crypto_abe_eval_policy(abe_policy, attr_string)) {
      return CRABS_ERR_UNAUTHORIZED;
    }
  }
  return _verify_user_signature(user, key_id, sig_scheme,
                                  attr_machine->current_time_ms,
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

// ============================================================
// Audit H-A: ECIES envelope transport encryption
// The ABE user key (sk_abe) is encrypted to the recipient's registered
// secp256k1 public key so the envelope is not shipped in cleartext. Layout
// of the encrypted sk_abe blob: eph_pub(33) + iv(12) + ct(pt_len) + tag(16).
// The symmetric key is SHA256(shared_secret || eph_pub || label) where
// shared_secret = ECDH(eph_priv, recipient_pub). The recipient recovers it
// with ECDH(user_priv, eph_pub).
// ============================================================

static int _ecdh_shared_secret(const uint8_t priv[32], const uint8_t pub[33],
                                 uint8_t out[32]) {
  EC_KEY* my_key = _eckey_from_private(priv);
  if (!my_key) return -1;
  EC_KEY* their_key = _eckey_from_public(pub);
  if (!their_key) { EC_KEY_free(my_key); return -1; }
  const EC_POINT* their_point = EC_KEY_get0_public_key(their_key);
  int rc = ECDH_compute_key(out, 32, their_point, my_key, NULL);
  EC_KEY_free(my_key);
  EC_KEY_free(their_key);
  return (rc == 32) ? 0 : -1;
}

static const char _ENVELOPE_ECIES_LABEL[] = "CRABS-ENVELOPE-ECIES-V1";

static int _ecies_derive_key(const uint8_t shared[32], const uint8_t eph_pub[33],
                                uint8_t aes_key[32]) {
  EVP_MD_CTX* md = EVP_MD_CTX_new();
  if (!md) return -1;
  int ok = -1;
  unsigned int hlen = 0;
  if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
      EVP_DigestUpdate(md, shared, 32) == 1 &&
      EVP_DigestUpdate(md, eph_pub, 33) == 1 &&
      EVP_DigestUpdate(md, _ENVELOPE_ECIES_LABEL, sizeof(_ENVELOPE_ECIES_LABEL) - 1) == 1 &&
      EVP_DigestFinal_ex(md, aes_key, &hlen) == 1 && hlen == 32) {
    ok = 0;
  }
  EVP_MD_CTX_free(md);
  return ok;
}

static int _aes256_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12],
                                 const uint8_t* pt, size_t pt_len,
                                 uint8_t* ct, uint8_t tag[16]) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return -1;
  int rc = -1, outl = 0, finall = 0;
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
      EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto done;
  if (EVP_EncryptUpdate(ctx, ct, &outl, pt, (int)pt_len) != 1) goto done;
  if (EVP_EncryptFinal_ex(ctx, ct + outl, &finall) != 1) goto done;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto done;
  rc = 0;
done:
  EVP_CIPHER_CTX_free(ctx);
  return rc;
}

static int _aes256_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12],
                                 const uint8_t* ct, size_t ct_len,
                                 const uint8_t tag[16], uint8_t* pt) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return -1;
  int rc = -1, outl = 0, finall = 0;
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
      EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto done;
  if (EVP_DecryptUpdate(ctx, pt, &outl, ct, (int)ct_len) != 1) goto done;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) goto done;
  if (EVP_DecryptFinal_ex(ctx, pt + outl, &finall) != 1) goto done; // fails on tag mismatch
  rc = 0;
done:
  EVP_CIPHER_CTX_free(ctx);
  return rc;
}

// ============================================================
// At-Rest Sealing (§11.5): AES-256-GCM envelope for durable
// secrets (MSK at rest). Sealed layout: IV(12) + ciphertext + tag(16).
// ============================================================

crabs_error_e crypto_seal(const uint8_t key[32],
                            const uint8_t* plain, size_t plain_len,
                            uint8_t* sealed, size_t* sealed_len) {
  if (!key || (!plain && plain_len != 0) || !sealed || !sealed_len)
    return CRABS_ERR_INVALID_PARAM;
  if (plain_len > SIZE_MAX - CRABS_SEAL_OVERHEAD)
    return CRABS_ERR_INVALID_PARAM;
  if (*sealed_len < plain_len + CRABS_SEAL_OVERHEAD)
    return CRABS_ERR_INVALID_PARAM;

  uint8_t initialization_vector[12];
  crabs_error_e random_error = crypto_random_bytes(initialization_vector,
                                                     sizeof(initialization_vector));
  if (random_error != CRABS_SUCCESS) return random_error;

  memcpy(sealed, initialization_vector, 12);
  uint8_t* ciphertext = sealed + 12;
  uint8_t* tag = sealed + 12 + plain_len;
  if (_aes256_gcm_encrypt(key, initialization_vector, plain, plain_len,
                          ciphertext, tag) != 0)
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  *sealed_len = plain_len + 12 + 16;
  return CRABS_SUCCESS;
}

crabs_error_e crypto_unseal(const uint8_t key[32],
                              const uint8_t* sealed, size_t sealed_len,
                              uint8_t* plain, size_t plain_cap,
                              size_t* plain_len) {
  if (!key || !sealed || !plain || !plain_len)
    return CRABS_ERR_INVALID_PARAM;
  if (sealed_len < CRABS_SEAL_OVERHEAD)
    return CRABS_ERR_INVALID_PARAM;
  size_t cipher_len = sealed_len - 12 - 16;
  if (cipher_len > plain_cap)
    return CRABS_ERR_INVALID_PARAM;

  const uint8_t* initialization_vector = sealed;
  const uint8_t* ciphertext = sealed + 12;
  const uint8_t* tag = sealed + 12 + cipher_len;
  // DecryptFinal_ex fails on tag mismatch, so a wrong key or tampered blob
  // never yields usable plaintext.
  if (_aes256_gcm_decrypt(key, initialization_vector, ciphertext, cipher_len,
                          tag, plain) != 0)
    return CRABS_ERR_UNAUTHORIZED;
  *plain_len = cipher_len;
  return CRABS_SUCCESS;
}

// ECIES encrypt: out = eph_pub(33) + iv(12) + ct(pt_len) + tag(16). Returns
// total length, or 0 on failure.
static size_t _ecies_encrypt_to_pub(const uint8_t recipient_pub[33],
                                       const uint8_t* pt, size_t pt_len,
                                       uint8_t* out, size_t out_cap) {
  if (pt_len == 0) return 0;
  size_t need = 33 + 12 + pt_len + 16;
  if (out == NULL || out_cap < need) return 0;
  // Audit R5-6: defense-in-depth. The N-3 fix validates recipient public keys
  // at registration (attribute_machine_register_user / user_key_register), so
  // invalid keys should never reach this function. Validate again here so a
  // pre-existing database (populated before N-3) or any future code path that
  // bypasses registration cannot trigger ECDH against an invalid key — which
  // would produce a predictable shared secret and defeat envelope
  // confidentiality. The cost is negligible (one EC_POINT_is_on_curve check).
  if (!crypto_ecdsa_validate_public_key(recipient_pub)) return 0;
  ecdsa_keypair_t* eph = crypto_ecdsa_generate();
  if (!eph) return 0;
  uint8_t shared[32];
  if (_ecdh_shared_secret(eph->private_key, recipient_pub, shared) != 0) {
    crypto_ecdsa_keypair_destroy(eph); return 0;
  }
  memcpy(out, eph->public_key, 33);  // eph_pub
  crypto_ecdsa_keypair_destroy(eph);
  uint8_t* iv = out + 33;
  if (RAND_bytes(iv, 12) != 1) { OPENSSL_cleanse(shared, 32); return 0; }
  uint8_t aes_key[32];
  if (_ecies_derive_key(shared, out, aes_key) != 0) {
    OPENSSL_cleanse(shared, 32); return 0;
  }
  uint8_t* ct = out + 45;
  uint8_t* tag = out + 45 + pt_len;
  int enc_rc = _aes256_gcm_encrypt(aes_key, iv, pt, pt_len, ct, tag);
  OPENSSL_cleanse(shared, 32);
  OPENSSL_cleanse(aes_key, 32);
  return (enc_rc == 0) ? need : 0;
}

key_envelope_t* crypto_key_envelope_create(
    const abe_master_key_t* mk,
    const uint8_t node_private_key[32],
    const user_t* user,
    uint64_t state_version,
    uint64_t issued_at,
    uint64_t expires_at) {
  if (!mk || !node_private_key || !user) return NULL;

  // Build the attribute string and its hash. The envelope is issued at
  // issued_at, so temporary attributes are evaluated against that clock.
  char attrs[CRABS_ATTR_STRING_MAX];
  _build_attr_string(user, attrs, sizeof(attrs), issued_at);
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

  // Generate a real CP-ABE user key for the user's attributes and serialize
  // it to a temporary buffer.
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
  uint8_t* plain_sk = get_clear_memory(sk_len);
  if (!plain_sk) {
    crypto_abe_user_key_destroy(abe_sk);
    free(env);
    return NULL;
  }
  crypto_abe_user_key_serialize(abe_sk, plain_sk, sk_len);
  crypto_abe_user_key_destroy(abe_sk);

  // Audit H-A: ECIES-encrypt the serialized ABE key to the user's registered
  // public key so the envelope is not shipped in cleartext. The encrypted blob
  // layout is eph_pub(33) + iv(12) + ct(sk_len) + tag(16).
  size_t enc_cap = 33 + 12 + sk_len + 16;
  env->sk_abe = get_clear_memory(enc_cap);
  if (!env->sk_abe) {
    OPENSSL_cleanse(plain_sk, sk_len); free(plain_sk);
    free(env);
    return NULL;
  }
  size_t enc_len = _ecies_encrypt_to_pub(user->public_key, plain_sk, sk_len,
                                           env->sk_abe, enc_cap);
  OPENSSL_cleanse(plain_sk, sk_len);
  free(plain_sk);
  if (enc_len == 0) {
    OPENSSL_cleanse(env->sk_abe, enc_cap);
    free(env->sk_abe);
    free(env);
    return NULL;
  }
  env->sk_abe_len = (uint32_t)enc_len;

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
  // Audit N-14: reject unknown envelope versions at deserialize time. The
  // prior code accepted any version byte and only rejected v2 cleartext
  // envelopes in crypto_key_envelope_verify — but if the envelope was used
  // without verification (e.g. for display/migration), a v0 or future-version
  // envelope could be misinterpreted. Reject anything that is not the
  // current format.
  if (env->format_version != KEY_ENVELOPE_FORMAT_V1) {
    free(env);
    return NULL;
  }
  memcpy(env->user_id, buf + pos, CRABS_MAX_USER_ID);
  // R8-C-9: force NUL termination. The wire format carries CRABS_MAX_USER_ID
  // raw bytes; a crafted blob without a NUL would leave env->user_id
  // unterminated and any downstream str* would over-read.
  env->user_id[CRABS_MAX_USER_ID - 1] = '\0';
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
  if (pos > len || sk_len > len - pos || CRABS_SIG_SIZE > len - pos - sk_len) {
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

// Audit H-A: decrypt the ECIES-encrypted sk_abe using the recipient's private
// key. The blob layout is eph_pub(33) + iv(12) + ct(ct_len) + tag(16). Returns
// the plaintext ABE key bytes in `out`; the caller must cleanse `out` after
// importing the key.
crabs_error_e crypto_key_envelope_decrypt_sk(const key_envelope_t* env,
                                                const uint8_t user_private_key[32],
                                                uint8_t* out, size_t out_cap,
                                                size_t* out_len) {
  if (!env || !user_private_key || !out || !out_len) return CRABS_ERR_INVALID_PARAM;
  // Minimum: eph_pub(33) + iv(12) + tag(16) = 61 (no ciphertext)
  if (env->sk_abe_len < 33 + 12 + 16) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  const uint8_t* eph_pub = env->sk_abe;
  // R7-L-3: validate the attacker-controlled ephemeral public key before ECDH.
  // The encrypt side validates (R5-6); the decrypt side must too — an
  // off-curve point would otherwise feed ECDH_compute_key unchecked.
  if (!crypto_ecdsa_validate_public_key(eph_pub)) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  const uint8_t* iv = env->sk_abe + 33;
  size_t ct_len = (size_t)env->sk_abe_len - 33 - 12 - 16;
  const uint8_t* ct = env->sk_abe + 45;
  const uint8_t* tag = env->sk_abe + 45 + ct_len;
  if (out_cap < ct_len) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  uint8_t shared[32];
  if (_ecdh_shared_secret(user_private_key, eph_pub, shared) != 0) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  uint8_t aes_key[32];
  if (_ecies_derive_key(shared, eph_pub, aes_key) != 0) {
    OPENSSL_cleanse(shared, 32); return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  int dec_rc = _aes256_gcm_decrypt(aes_key, iv, ct, ct_len, tag, out);
  OPENSSL_cleanse(shared, 32);
  OPENSSL_cleanse(aes_key, 32);
  if (dec_rc != 0) {
    // Tag mismatch = wrong recipient or tampering.
    return CRABS_ERR_UNAUTHORIZED;
  }
  *out_len = ct_len;
  return CRABS_SUCCESS;
}

// ============================================================
// Attributes Hash (§11.2)
// ============================================================

crabs_error_e crypto_compute_attributes_hash(const user_t* user, uint8_t hash[CRABS_HASH_SIZE]) {
  if (!user || !hash) return CRABS_ERR_INVALID_PARAM;

  char attr_string[CRABS_ATTR_STRING_MAX];
  // No clock is in scope here, so pass 0 — per R8-A-8 that fail-closed
  // excludes temporary attributes with an expiry from the hash.
  _build_attr_string(user, attr_string, sizeof(attr_string), 0);

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
    const uint8_t new_public_key[33],
    uint64_t state_version,
    uint64_t issued_at) {
  if (!mk || !node_private_key || !attr_machine || !user_id || !new_public_key) return NULL;

  // R7-06: validate the user-supplied public key BEFORE any state mutation.
  // The prior code suspended the user and overwrote user->public_key first,
  // then failed envelope creation (via the R5-6 validation in
  // _ecies_encrypt_to_pub) — leaving the user suspended with an invalid key
  // and no recovery path. Reject invalid keys up front so a failed rotation
  // leaves the user record untouched.
  if (!crypto_ecdsa_validate_public_key(new_public_key)) return NULL;

  // Step 1: Find the user.
  user_t* user = attribute_machine_find_user(attr_machine, user_id);
  if (!user) return NULL;

  // R8-C-3: build the envelope BEFORE mutating the user, so a failed envelope
  // creation leaves the user record untouched. The envelope is encrypted to
  // the new public key, so temporarily swap it in and restore on any failure.
  uint8_t old_public_key[33];
  memcpy(old_public_key, user->public_key, 33);
  memcpy(user->public_key, new_public_key, 33);

  key_envelope_t* envelope = crypto_key_envelope_create(
      mk, node_private_key, user, state_version, issued_at, 0);
  if (!envelope) {
    memcpy(user->public_key, old_public_key, 33);
    return NULL;
  }

  // Envelope succeeded. Suspend the user (increments key_version). If the
  // user is REVOKED (terminal), suspend fails and we must roll back.
  // System-internal path: the NODE suspends the user during key rotation;
  // no signing admin is behind this action.
  if (attribute_machine_suspend_user_internal(attr_machine, user_id,
      "key-rotation suspension") != CRABS_SUCCESS) {
    memcpy(user->public_key, old_public_key, 33);
    crypto_key_envelope_destroy(envelope);
    return NULL;
  }
  // public_key stays as new_public_key (already set above).

  // Step 6: Build result (envelope only; no private key on the node)
  recovery_result_t* result = get_clear_memory(sizeof(recovery_result_t));
  if (!result) {
    crypto_key_envelope_destroy(envelope);
    return NULL;
  }
  memcpy(result->new_public_key, new_public_key, 33);
  result->new_envelope = envelope;

  return result;
}

void crypto_recovery_result_destroy(recovery_result_t* result) {
  if (result) {
    if (result->new_envelope) crypto_key_envelope_destroy(result->new_envelope);
    free(result);
  }
}