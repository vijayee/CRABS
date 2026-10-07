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

// Derive the compressed public key (33 bytes) from a 32-byte private key.
crabs_error_e crypto_ecdsa_derive_public_key(const uint8_t private_key[32],
                                                uint8_t public_key[33]);

// Audit N-3: validate a compressed secp256k1 public key — decodes to a point
// on the curve and is not the point at infinity. Called at user/key
// registration so the ECIES envelope encryption never performs ECDH against
// an invalid recipient key (which could yield a predictable shared secret).
bool crypto_ecdsa_validate_public_key(const uint8_t public_key[33]);

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

// A10-L1: verify a signature against a PRE-COMPUTED 32-byte SHA-256 digest
// instead of the message. crypto_ecdsa_sign signs SHA-256(message) directly
// as the ECDSA digest, so a caller that retains the message's hash but not
// the message itself (lineage genesis provenance, where the manifest stores
// genesis_snapshot_hash == SHA-256(genesis blob) but not the blob) can still
// verify the attestation: the signature binds to exactly that hash. Does NOT
// prove the digest's preimage is any particular body — only that the key
// signed a message whose SHA-256 is this digest. Same low-S enforcement as
// crypto_ecdsa_verify.
bool crypto_ecdsa_verify_digest(const uint8_t public_key[33],
                                 const uint8_t digest[CRABS_HASH_SIZE],
                                 const uint8_t signature[CRABS_SIG_SIZE]);

// ============================================================
// SHA-256 Hash
// ============================================================
crabs_error_e crypto_sha256(const uint8_t* data, size_t len,
                             uint8_t hash[CRABS_HASH_SIZE]);

// ============================================================
// At-Rest Sealing (§11.5): AES-256-GCM envelope for durable
// secrets (MSK at rest). Sealed layout: IV(12) + ciphertext + tag(16).
// ============================================================
#define CRABS_SEAL_OVERHEAD 28   // 12-byte IV + 16-byte GCM tag

// In: *sealed_len = buffer capacity. Out: *sealed_len = sealed blob length.
crabs_error_e crypto_seal(const uint8_t key[32],
                            const uint8_t* plain, size_t plain_len,
                            uint8_t* sealed, size_t* sealed_len);
// In: plain_cap = plaintext capacity. Out: *plain_len = written length.
crabs_error_e crypto_unseal(const uint8_t key[32],
                              const uint8_t* sealed, size_t sealed_len,
                              uint8_t* plain, size_t plain_cap,
                              size_t* plain_len);

// ============================================================
// CSPRNG (§14.2)
// ============================================================
crabs_error_e crypto_random_bytes(uint8_t* buf, size_t len);

// ============================================================
// ABE Interface (§10.1) — CP-ABE via OpenABE (Waters '09)
// ============================================================
// The master key, user keys, and ciphertexts are opaque; their internal
// representation (OpenABE contexts and serialized byte strings) is private to
// crypto.c. This replaces the prior "simulated" ABE whose decryption key was
// derivable from public material (audit C-1).

typedef struct abe_master_key_t abe_master_key_t;
typedef struct abe_user_key_t   abe_user_key_t;
typedef struct abe_ciphertext_t abe_ciphertext_t;

// Generate a CP-ABE authority: public parameters (MPK) + master secret key.
abe_master_key_t*  crypto_abe_setup(void);
void               crypto_abe_master_key_destroy(abe_master_key_t* mk);

// Derive a CP-ABE user secret key for the given pipe- or comma-separated
// attribute list. The key can decrypt ciphertexts whose policy is satisfied
// by the attributes.
abe_user_key_t*    crypto_abe_keygen(const abe_master_key_t* mk, const char* attrs);
void               crypto_abe_user_key_destroy(abe_user_key_t* sk);

// Encrypt msg under the given access policy (ABE boolean expression, e.g.
// "admin and member"). Returns NULL on failure.
abe_ciphertext_t*  crypto_abe_encrypt(const abe_master_key_t* mk,
                                        const uint8_t* msg, size_t msg_len,
                                        const char* policy);
void               crypto_abe_ciphertext_destroy(abe_ciphertext_t* ct);

// Accessors for opaque ciphertext (used by language bindings that can't
// access the internal struct). Get the policy string and the raw encrypted
// data + its length.
const char*        crypto_abe_ciphertext_get_policy(const abe_ciphertext_t* ct);
const uint8_t*     crypto_abe_ciphertext_get_data(const abe_ciphertext_t* ct, size_t* len);

// Decrypt with a user key. Succeeds only if the key's attributes satisfy the
// ciphertext's policy. Caller frees *out.
crabs_error_e      crypto_abe_decrypt(const abe_user_key_t* sk,
                                        const abe_ciphertext_t* ct,
                                        uint8_t** out, size_t* out_len);

// Serialize a user key for storage/transmission (e.g. into a key envelope).
// Returns the byte length written into out_buf, or 0 on overflow/error.
size_t crypto_abe_user_key_serialize(const abe_user_key_t* sk,
                                       uint8_t* out_buf, size_t buf_len);
// Deserialize a user key from bytes (the master key provides the public params
// needed to reconstruct a decrypt-capable context). Returns NULL on failure.
abe_user_key_t* crypto_abe_user_key_deserialize(const abe_master_key_t* mk,
                                                   const uint8_t* buf, size_t len);

// ============================================================
// Master Key Durability (§11.5): serialize + restore the CP-ABE
// authority (MPK + MSK) so a machine's authority survives restart.
// Wire format: 'M','K' magic (2 bytes) + format_version 0x01 +
// u32le public_params_len + public_params + u32le master_secret_len
// + master_secret (lengths little-endian).
// ============================================================
#define CRABS_MSK_FORMAT_VERSION 0x01

size_t crypto_master_key_serialize(const abe_master_key_t* mk,
                                     uint8_t* buf, size_t buf_len);
// Reconstruct a full authority (context + params + secret) from bytes.
// Returns NULL on malformed input.
abe_master_key_t* crypto_master_key_deserialize(const uint8_t* buf, size_t len);

// Policy evaluation (AND/OR/attribute matching) — a lightweight string-based
// check used by the authorization path; NOT a confidentiality mechanism.
// Real attribute enforcement for the capability vault is provided by
// crypto_abe_encrypt/decrypt above.
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

// ============================================================
// Scheme-Aware Signature Verification (v1.3 §6)
// ============================================================
verify_result_t crypto_verify_operation_auth_v2(
    const abe_master_key_t* mk,
    const char* abe_policy,
    const attribute_machine_t* attr_machine,
    const uint8_t* serialized_op, size_t op_len,
    const uint8_t* signature, uint32_t signature_len,
    const char* signer_id,
    const char* key_id,
    signature_scheme_e sig_scheme,
    verify_mode_e mode);

// ============================================================
// Co-Signature Verification (v1.3 §4.2)
// ============================================================
// Verify a single co-signature against the serialized canonical form of the
// operation. Resolves the co-signer's key via the attribute machine keyring
// (key_id/sig_scheme) or the bootstrap public key (legacy). Returns
// CRABS_SUCCESS only if the signature is valid, the co-signer is an active
// user, and (R7-L-9) the co-signer's attributes satisfy the operation's ABE
// policy — a co-signer is an approver, not merely a witness.
crabs_error_e crypto_verify_co_signature(
    const attribute_machine_t* attr_machine,
    const char* abe_policy,
    const char* signer_id,
    const char* key_id,
    signature_scheme_e sig_scheme,
    const uint8_t* serialized_op, size_t op_len,
    const uint8_t* signature, uint32_t signature_len);

// ============================================================
// Key Envelope (§11.2)
// ============================================================
// Audit H-A: v3 wraps the ABE user key in ECIES (ECDH + AES-256-GCM) to the
// recipient's registered public key, so the envelope is no longer shipped in
// cleartext. v2 (cleartext sk_abe) is rejected by crypto_key_envelope_verify.
#define KEY_ENVELOPE_FORMAT_V1  0x03

// Maximum serialized size of a key envelope (used for transport buffers).
// format_version(1) + user_id(64) + state_version(8) + attributes_hash(32)
// + issued_at(8) + expires_at(8) + sk_abe_len(4) + sk_abe(<=1024) + signature(64)
// Audit M-I: real Waters'09 CP-ABE user keys with several attributes
// exceed the prior 1200-byte ceiling, so crypto_key_envelope_serialize
// returned 0 and the refresh op reported SUCCESS with envelope_data_len=0
// (an unusable, empty envelope). 8 KiB comfortably fits a key at the 4096-byte
// keygen cap plus the envelope header and signature.
#define CRABS_KEY_ENVELOPE_MAX_SIZE 8192

typedef struct key_envelope_t {
  uint8_t  format_version;                       // 0x02
  char     user_id[CRABS_MAX_USER_ID];           // User identifier
  uint64_t state_version;                        // State version when issued
  uint8_t  attributes_hash[CRABS_HASH_SIZE];     // SHA-256 of attribute string
  uint64_t issued_at;                            // Unix timestamp ms
  uint64_t expires_at;                           // Expiry (0 = no expiry)
  // Variable-length serialized ABE user key (crypto_abe_user_key_serialize).
  uint8_t* sk_abe;
  uint32_t sk_abe_len;
  uint8_t  signature[CRABS_SIG_SIZE];            // Node ECDSA signature over the canonical form
} key_envelope_t;

// Create a key envelope: generates a real CP-ABE user key for the user's
// attributes, embeds its serialized form, and signs the canonical envelope
// with the node's ECDSA private key. The user's attribute string and its
// SHA-256 hash are computed internally.
key_envelope_t* crypto_key_envelope_create(
    const abe_master_key_t* mk,
    const uint8_t node_private_key[32],
    const user_t* user,
    uint64_t state_version,
    uint64_t issued_at,
    uint64_t expires_at);

// Verify the node signature on a key envelope
bool crypto_key_envelope_verify(
    const uint8_t node_public_key[33],
    const key_envelope_t* envelope);

// Serialize an envelope into a flat byte buffer (format_version + user_id +
// state_version + attributes_hash + issued_at + expires_at + sk_abe_len +
// sk_abe + signature). Returns bytes written, or 0 on overflow/error.
size_t crypto_key_envelope_serialize(const key_envelope_t* env,
                                       uint8_t* buf, size_t buf_len);
// Deserialize an envelope from bytes. Returns NULL on failure. The master key
// is needed to attach public params to the reconstructed ABE user key.
key_envelope_t* crypto_key_envelope_deserialize(const abe_master_key_t* mk,
                                                   const uint8_t* buf, size_t len);

// Audit H-A: decrypt the ECIES-wrapped ABE user key with the recipient's
// private key. On success, writes the plaintext ABE key to `out` (caller
// must OPENSSL_cleanse it after importing). Returns CRABS_ERR_UNAUTHORIZED on
// tag mismatch (wrong recipient or tampering).
crabs_error_e crypto_key_envelope_decrypt_sk(const key_envelope_t* env,
                                                const uint8_t user_private_key[32],
                                                uint8_t* out, size_t out_cap,
                                                size_t* out_len);

// Secure cleanup
void crypto_key_envelope_destroy(key_envelope_t* envelope);

// Compute SHA-256 hash of a user's attribute string
crabs_error_e crypto_compute_attributes_hash(
    const user_t* user,
    uint8_t hash[CRABS_HASH_SIZE]);

// ============================================================
// Key Compromise Recovery (§11.4)
// ============================================================
typedef struct {
  uint8_t new_public_key[33];   // Echoed: the user's new public key
  key_envelope_t*  new_envelope;     // New ABE key envelope
} recovery_result_t;

// Audit H-B: node-blind key rotation. The node never generates or learns the
// user's new ECDSA private key. The user generates their own keypair
// out-of-band and submits the new public key; the node records it, suspends
// the compromised key, and issues a new ABE envelope bound to the user's
// current attributes. The envelope is returned for out-of-band delivery.
recovery_result_t* crypto_revoke_and_rotate(
    const abe_master_key_t* mk,
    const uint8_t node_private_key[32],
    attribute_machine_t* attr_machine,
    const char* user_id,
    const uint8_t new_public_key[33],
    uint64_t state_version,
    uint64_t issued_at);

// Secure cleanup
void crypto_recovery_result_destroy(recovery_result_t* result);

#endif // CRABS_CRYPTO_H