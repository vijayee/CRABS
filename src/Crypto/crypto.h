//
// Created by victor on 4/30/25.
//

#ifndef CRABS_CRYPTO_H
#define CRABS_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"

// ============================================================
// ECDSA Key Pair (§10.2)
// ============================================================
typedef struct {
  uint8_t private_key[32];   // ECDSA private key (secp256k1)
  uint8_t public_key[33];    // ECDSA compressed public key
} ecdsa_keypair_t;

ecdsa_keypair_t* crypto_ecdsa_generate(void);
void             crypto_ecdsa_keypair_destroy(ecdsa_keypair_t* keypair);

// ============================================================
// ECDSA Signing (§10.2.1)
// ============================================================
crabs_error_e crypto_ecdsa_sign(const uint8_t private_key[32],
                                 const uint8_t* message, size_t message_len,
                                 uint8_t signature[CRABS_SIG_SIZE]);

// ============================================================
// ECDSA Verification (§10.2.2)
// ============================================================
bool crypto_ecdsa_verify(const uint8_t public_key[33],
                          const uint8_t* message, size_t message_len,
                          const uint8_t signature[CRABS_SIG_SIZE]);

// ============================================================
// SHA-256 Hash
// ============================================================
crabs_error_e crypto_sha256(const uint8_t* data, size_t len,
                             uint8_t hash[CRABS_HASH_SIZE]);

// ============================================================
// CSPRNG (§14.2)
// ============================================================
crabs_error_e crypto_random_bytes(uint8_t* buf, size_t len);

// ============================================================
// ABE Stub Interface (§10.1)
// ============================================================
typedef struct {
  uint8_t* data;
  size_t   len;
} abe_key_t;

typedef struct {
  uint8_t* data;
  size_t   len;
} abe_ciphertext_t;

// ABE operations are stubs for future integration with openabe-c
abe_key_t*        crypto_abe_setup(void);
void              crypto_abe_key_destroy(abe_key_t* key);
abe_key_t*        crypto_abe_keygen(const abe_key_t* msk, const abe_key_t* mpk, const char* attrs);
abe_ciphertext_t* crypto_abe_encrypt(const abe_key_t* mpk, const uint8_t* msg, size_t msg_len, const char* policy);
void              crypto_abe_ciphertext_destroy(abe_ciphertext_t* ct);
int               crypto_abe_decrypt(const abe_key_t* sk, const abe_ciphertext_t* ct, uint8_t** out, size_t* out_len);

// ============================================================
// Operation Signing (§10.2.1 + §7.5)
// ============================================================
crabs_error_e crypto_sign_operation(const uint8_t private_key[32],
                                     const uint8_t* serialized_op, size_t op_len,
                                     uint8_t signature[CRABS_SIG_SIZE]);
bool crypto_verify_operation(const uint8_t public_key[33],
                              const uint8_t* serialized_op, size_t op_len,
                              const uint8_t signature[CRABS_SIG_SIZE]);

#endif // CRABS_CRYPTO_H