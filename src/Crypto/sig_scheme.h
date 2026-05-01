//
// CRABS v1.3: Signature Scheme Registry & VTable (Amendment 3, §2-3)
//

#ifndef CRABS_SIG_SCHEME_H
#define CRABS_SIG_SCHEME_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"

// ============================================================
// Signature Scheme Identifiers (§2.1)
// ============================================================
typedef enum {
  SCHEME_UNSPECIFIED    = 0x00,
  ECDSA_SECP256K1       = 0x01,
  ECDSA_P256            = 0x02,
  ED25519               = 0x03,
  SCHNORR_SECP256K1     = 0x04,
  BLS_BLS12_381         = 0x05,
  RSA_2048              = 0x06,
  RSA_4096              = 0x07,
  DILITHIUM_2           = 0x08,
  DILITHIUM_3           = 0x09,
  DILITHIUM_5           = 0x0A,
  FALCON_512            = 0x0B,
  FALCON_1024           = 0x0C,
  SPHINCS_PLUS_128S     = 0x0D,
  CUSTOM_BASE           = 0xF0,
  CUSTOM_MAX            = 0xFE,
  SCHEME_CUSTOM         = 0xFF
} signature_scheme_e;

// ============================================================
// Scheme Properties (§2.2)
// ============================================================
#define CRABS_MAX_SCHEME_NAME  64

typedef struct {
  signature_scheme_e scheme_id;
  char               name[CRABS_MAX_SCHEME_NAME];
  uint8_t            security_level;
  bool               is_post_quantum;

  uint16_t           public_key_size;
  uint16_t           secret_key_size;
  uint16_t           signature_size;

  bool               supports_batch_verification;
  bool               supports_aggregation;
  bool               supports_threshold;

  uint8_t            sign_speed;
  uint8_t            verify_speed;
  uint8_t            keygen_speed;
} scheme_properties_t;

// ============================================================
// Signature VTable (§3.1)
// ============================================================
typedef crabs_error_e (*sig_generate_keypair_fn)(
    uint8_t* pk, uint32_t* pk_len,
    uint8_t* sk, uint32_t* sk_len);

typedef crabs_error_e (*sig_sign_fn)(
    const uint8_t* sk, uint32_t sk_len,
    const uint8_t* msg, uint32_t msg_len,
    uint8_t* sig, uint32_t* sig_len);

typedef crabs_error_e (*sig_verify_fn)(
    const uint8_t* pk, uint32_t pk_len,
    const uint8_t* msg, uint32_t msg_len,
    const uint8_t* sig, uint32_t sig_len);

typedef crabs_error_e (*sig_verify_batch_fn)(
    const uint8_t** pks, const uint32_t* pk_lens,
    const uint8_t** msgs, const uint32_t* msg_lens,
    const uint8_t** sigs, const uint32_t* sig_lens,
    uint32_t count);

typedef crabs_error_e (*sig_aggregate_fn)(
    const uint8_t** sigs, const uint32_t* sig_lens,
    uint32_t count,
    uint8_t* aggregated, uint32_t* aggregated_len);

typedef crabs_error_e (*sig_export_key_fn)(
    const uint8_t* key, uint32_t key_len,
    uint8_t* buf, uint32_t* buf_len);

typedef crabs_error_e (*sig_import_key_fn)(
    const uint8_t* buf, uint32_t buf_len,
    uint8_t* key, uint32_t* key_len);

typedef struct {
  signature_scheme_e      scheme_id;
  char                    name[CRABS_MAX_SCHEME_NAME];
  scheme_properties_t     properties;

  sig_generate_keypair_fn generate_keypair;
  sig_sign_fn             sign;
  sig_verify_fn           verify;

  sig_verify_batch_fn     verify_batch;
  sig_aggregate_fn        aggregate_signatures;
  sig_export_key_fn       export_public_key;
  sig_export_key_fn       export_secret_key;
  sig_import_key_fn       import_public_key;
  sig_import_key_fn       import_secret_key;
} signature_vtable_t;

// ============================================================
// Registry API (§3.2)
// ============================================================
#define CRABS_MAX_REGISTERED_SCHEMES  32

crabs_error_e  crypto_sig_scheme_register(const signature_vtable_t* vtable);
const signature_vtable_t* crypto_sig_scheme_get(signature_scheme_e scheme_id);
uint32_t       crypto_sig_scheme_list(signature_scheme_e* out, uint32_t max_count);
uint32_t       crypto_sig_scheme_count(void);
void           crypto_sig_scheme_init(void);

#endif // CRABS_SIG_SCHEME_H