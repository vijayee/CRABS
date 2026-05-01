//
// Created by victor on 4/30/25.
//

#ifndef CRABS_ATTRIBUTE_MACHINE_H
#define CRABS_ATTRIBUTE_MACHINE_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"

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
// User Record (§8.2)
// ============================================================
typedef struct user_t {
  char               user_id[CRABS_MAX_USER_ID];
  attribute_value_t  attributes[CRABS_MAX_ATTRIBUTES];
  uint32_t           attribute_count;
  uint8_t            public_key[33];  // ECDSA compressed public key
  user_status_e      status;
  uint64_t           key_version;
  uint64_t           created_at;
  uint64_t           updated_at;
  temp_attr_list_t*  temp_attrs;  // Linked list of temporary attributes
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

#endif // CRABS_ATTRIBUTE_MACHINE_H