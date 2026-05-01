//
// Created by victor on 4/30/25.
//

#ifndef CRABS_CRYPTO_H
#define CRABS_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../Attribute/attribute_machine.h"

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
// ABE Interface (§10.1) — Simulated CP-ABE with AES-256-GCM
// ============================================================
// ABE_MASTER_KEY_SIZE: 32 bytes (MSK + MPK each)
#define ABE_MASTER_KEY_SIZE  32
#define ABE_NONCE_SIZE       12   // AES-GCM nonce
#define ABE_TAG_SIZE         16   // AES-GCM auth tag

typedef struct {
  uint8_t msk[ABE_MASTER_KEY_SIZE];  // Master Secret Key
  uint8_t mpk[ABE_MASTER_KEY_SIZE];  // Master Public Key (SHA-256 of MSK)
} abe_master_key_t;

typedef struct {
  uint8_t  key[ABE_MASTER_KEY_SIZE];          // MPK copy (for simulated ABE key derivation)
  char     attrs[CRABS_MAX_POLICY_EXPR];      // Comma-separated attribute string
  uint32_t attr_count;                        // Number of parsed attributes
} abe_user_key_t;

typedef struct {
  char     policy[CRABS_MAX_POLICY_EXPR];     // Access policy expression
  uint8_t  nonce[ABE_NONCE_SIZE];             // AES-GCM nonce
  uint8_t  tag[ABE_TAG_SIZE];                 // AES-GCM auth tag
  uint8_t* ciphertext;                         // Encrypted data
  size_t   ct_len;                            // Length of ciphertext
} abe_ciphertext_t;

abe_master_key_t*  crypto_abe_setup(void);
void               crypto_abe_master_key_destroy(abe_master_key_t* mk);
abe_user_key_t*    crypto_abe_keygen(const abe_master_key_t* mk, const char* attrs);
void               crypto_abe_user_key_destroy(abe_user_key_t* sk);
abe_ciphertext_t*  crypto_abe_encrypt(const abe_master_key_t* mk, const uint8_t* msg, size_t msg_len, const char* policy);
void               crypto_abe_ciphertext_destroy(abe_ciphertext_t* ct);
crabs_error_e      crypto_abe_decrypt(const abe_user_key_t* sk, const abe_ciphertext_t* ct, uint8_t** out, size_t* out_len);

// Policy evaluation (AND/OR/attribute matching)
bool crypto_abe_eval_policy(const char* policy, const char* attrs);

// ============================================================
// Operation Signing (§10.2.1 + §7.5)
// ============================================================
crabs_error_e crypto_sign_operation(const uint8_t private_key[32],
                                     const uint8_t* serialized_op, size_t op_len,
                                     uint8_t signature[CRABS_SIG_SIZE]);
bool crypto_verify_operation(const uint8_t public_key[33],
                              const uint8_t* serialized_op, size_t op_len,
                              const uint8_t signature[CRABS_SIG_SIZE]);

// ============================================================
// ABE-Gated Signature Verification (§10.3)
// ============================================================
typedef enum {
  VERIFY_MODE_A = 0x01,  // Verify specific user (ECDSA + ABE policy check)
  VERIFY_MODE_B = 0x02   // Verify any authorized user (trial ABE decryption)
} verify_mode_e;

typedef struct {
  bool            authorized;
  crabs_error_e   error;
  char            signer_id[CRABS_MAX_USER_ID];  // Matched user (Mode B)
} verify_result_t;

// Verify operation authorization using ABE-gated signature verification
// Mode A: verify specific signer (ECDSA signature + ABE policy check)
// Mode B: verify against all registered users (trial decryption)
verify_result_t crypto_verify_operation_auth(
    const abe_master_key_t* mk,
    const char* abe_policy,
    const attribute_machine_t* attr_machine,
    const uint8_t* serialized_op, size_t op_len,
    const uint8_t signature[CRABS_SIG_SIZE],
    const char* signer_id,
    verify_mode_e mode);

#endif // CRABS_CRYPTO_H