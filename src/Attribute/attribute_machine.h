//
// Created by victor on 4/30/25.
//

#ifndef CRABS_ATTRIBUTE_MACHINE_H
#define CRABS_ATTRIBUTE_MACHINE_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "../Crypto/sig_scheme.h"

// ============================================================
// User Status (§8.2)
// ============================================================
typedef enum {
  USER_ACTIVE    = 0x00,
  USER_SUSPENDED = 0x01,
  USER_REVOKED   = 0x02
} user_status_e;

// ============================================================
// Attribute Value (§8.2)
// ============================================================
typedef struct {
  char     value[CRABS_MAX_POLICY_EXPR];
  char     verified_by[CRABS_MAX_USER_ID];
  uint64_t verified_at;
  uint64_t expires_at;  // 0 = no expiry
} attribute_value_t;

// ============================================================
// Temporary Attribute (Amendment 1, §7.1)
// ============================================================
typedef struct temp_attr_list_t {
  char     name[CRABS_MAX_POLICY_EXPR];
  char     value[CRABS_MAX_POLICY_EXPR];
  uint64_t issued_at;
  uint64_t expires_at;
  struct temp_attr_list_t* next;
} temp_attr_list_t;

// ============================================================
// Key Lifecycle States (v1.3 §9)
// ============================================================
typedef enum {
  KEY_ACTIVE    = 0x00,
  KEY_SUSPENDED = 0x01,
  KEY_REVOKED   = 0x02,
  KEY_EXPIRED   = 0x03
} key_status_e;

// ============================================================
// User Key (v1.3 Amendment 3, §4.1 + §9 Key Lifecycle)
// ============================================================
#define CRABS_MAX_KEY_ID       64
#define CRABS_MAX_KEY_LABEL    128
#define CRABS_MAX_PUBLIC_KEY   512   // Max public key size across all schemes
#define CRABS_MAX_KEYS_PER_USER 8

typedef struct user_key_t {
  char                  key_id[CRABS_MAX_KEY_ID];
  signature_scheme_e    scheme;
  uint8_t               public_key[CRABS_MAX_PUBLIC_KEY];
  uint32_t              public_key_len;
  char                  label[CRABS_MAX_KEY_LABEL];
  uint64_t              registered_at;
  uint64_t              last_used_at;
  key_status_e          status;               // v1.3 §9: key lifecycle state
  uint64_t              expires_at;           // 0 = no expiry
  uint64_t              suspended_at;         // 0 = never suspended
  uint64_t              revoked_at;           // 0 = never revoked
  char                  predecessor_key_id[CRABS_MAX_KEY_ID]; // Key rotation chain
  struct user_key_t*    next;
} user_key_t;

// ============================================================
// User Record (§8.2 + v1.3 §4.1)
// ============================================================
typedef struct user_t {
  char               user_id[CRABS_MAX_USER_ID];
  attribute_value_t  attributes[CRABS_MAX_ATTRIBUTES];
  uint32_t           attribute_count;
  uint8_t            public_key[33];  // Legacy ECDSA key (backward compat)
  user_status_e      status;
  uint64_t           key_version;
  uint64_t           created_at;
  uint64_t           updated_at;
  temp_attr_list_t*  temp_attrs;
  // v1.3: Multi-key support
  user_key_t*        keys;                    // Linked list of registered keys
  char               default_key_id[CRABS_MAX_KEY_ID]; // Default signing key
  uint32_t           key_count;
  struct user_t*     next;
} user_t;

// ============================================================
// Attribute Machine (inherits state_t)
// ============================================================
typedef struct attribute_machine_t {
  state_t   base_state;
  user_t*   users;
  uint32_t  user_count;
  uint64_t  current_time_ms;  // Platform-injected time for temp attr expiry
} attribute_machine_t;

// ============================================================
// Attribute Machine Lifecycle
// ============================================================
attribute_machine_t* attribute_machine_create(const char* admin_id, const uint8_t admin_pk[33]);
void                  attribute_machine_destroy(attribute_machine_t* am);

// ============================================================
// User Operations (§8.4)
// ============================================================
crabs_error_e attribute_machine_register_user(attribute_machine_t* am, const char* user_id,
                                               const uint8_t public_key[33],
                                               const char* initial_attrs);
crabs_error_e attribute_machine_grant_role(attribute_machine_t* am, const char* target_user,
                                            const char* role, const char* value,
                                            const char* signer_id);
crabs_error_e attribute_machine_self_assert(attribute_machine_t* am, const char* attribute,
                                              const char* value, const char* signer_id);
crabs_error_e attribute_machine_verify_identity(attribute_machine_t* am, const char* target_user,
                                                  const char* attribute, const char* value,
                                                  const char* signer_id);
crabs_error_e attribute_machine_revoke_role(attribute_machine_t* am, const char* target_user,
                                              const char* role, const char* signer_id);
crabs_error_e attribute_machine_suspend_user(attribute_machine_t* am, const char* user_id);

// R7-07: reactivate a SUSPENDED user after key-compromise recovery
// (crypto_revoke_and_rotate). Admin-authorized: the signer must be an active
// user holding the role:admin attribute. REVOKED users are terminal and cannot
// be reactivated. Does not bump key_version — the suspension during recovery
// already invalidated the old key, and the user's new key is bound to the
// current version.
crabs_error_e attribute_machine_activate_user(attribute_machine_t* am, const char* target_user,
                                               const char* signer_id);

// Audit H-C: revoke a user. Unlike suspend (recoverable), revocation is the
// terminal state — a revoked user cannot authorize, refresh, or be reactivated
// without re-registration. Sets user->status = USER_REVOKED.
crabs_error_e attribute_machine_revoke_user(attribute_machine_t* am, const char* user_id);

// Audit H-C: inject the platform wall clock (ms) used for temporary-attribute
// expiry and key expiry. Without this, current_time_ms stays 0 and expired
// temp attributes are never pruned (they grant authority indefinitely).
// Platforms MUST call this before processing operations that depend on expiry.
void attribute_machine_set_time(attribute_machine_t* am, uint64_t now_ms);

// ============================================================
// Query Functions
// ============================================================
user_t*        attribute_machine_find_user(attribute_machine_t* am, const char* user_id);
bool           attribute_machine_user_has_role(user_t* user, const char* role);
attribute_value_t* attribute_machine_find_attribute(user_t* user, const char* name);

// ============================================================
// Temporary Attributes (Amendment 1, §7.1)
// ============================================================
crabs_error_e attribute_machine_issue_temporary(attribute_machine_t* am, const char* attribute,
                                                  const char* value, const char* role,
                                                  uint64_t duration_ms);
uint32_t      attribute_machine_prune_expired_temporary(attribute_machine_t* am);

// ============================================================
// Key Ring Operations (v1.3 Amendment 3, §4.1 + §9 Key Lifecycle)
// ============================================================
user_key_t*   user_key_find(user_t* user, const char* key_id);
user_key_t*   user_key_find_active(user_t* user, signature_scheme_e scheme);
crabs_error_e user_key_register(user_t* user, const char* key_id,
                                 signature_scheme_e scheme,
                                 const uint8_t* public_key, uint32_t public_key_len,
                                 const char* label);
crabs_error_e user_key_revoke(user_t* user, const char* key_id);
crabs_error_e user_key_set_default(user_t* user, const char* key_id);
void          user_key_destroy_all(user_t* user);

// Key lifecycle operations (v1.3 §9)
crabs_error_e user_key_suspend(user_t* user, const char* key_id);
crabs_error_e user_key_activate(user_t* user, const char* key_id);
crabs_error_e user_key_rotate(user_t* user, const char* old_key_id,
                               const char* new_key_id, signature_scheme_e new_scheme,
                               const uint8_t* new_public_key, uint32_t new_public_key_len,
                               const char* new_label);
const char*   user_key_status_name(key_status_e status);

#endif // CRABS_ATTRIBUTE_MACHINE_H