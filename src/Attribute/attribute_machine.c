//
// Created by victor on 4/30/25.
//

#include "attribute_machine.h"
#include "../Util/allocator.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// ============================================================
// Internal helpers
// ============================================================

// Parse pipe-separated attribute string like "role:admin|dept:eng"
// into attribute_value_t entries. Each entry's value field stores
// "name:value" so the attribute name is recoverable.
// Returns number of attributes parsed.
static uint32_t _parse_attributes(const char* attrs, attribute_value_t* out, uint32_t max_count) {
  if (attrs == NULL || attrs[0] == '\0') return 0;

  uint32_t count = 0;
  char buf[CRABS_MAX_POLICY_EXPR * 4];
  strncpy(buf, attrs, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';

  char* saveptr = NULL;
  char* token = strtok_r(buf, "|", &saveptr);

  while (token != NULL && count < max_count) {
    // Trim leading spaces
    while (*token == ' ') token++;

    strncpy(out[count].value, token, CRABS_MAX_POLICY_EXPR - 1);
    out[count].value[CRABS_MAX_POLICY_EXPR - 1] = '\0';
    out[count].verified_by[0] = '\0';
    out[count].verified_at = 0;
    out[count].expires_at = 0;
    count++;

    token = strtok_r(NULL, "|", &saveptr);
  }

  return count;
}

// Extract the "name" part from "name:value" format
static void _extract_name(const char* pair, char* name_out, size_t name_size) {
  const char* colon = strchr(pair, ':');
  if (colon != NULL) {
    size_t len = (size_t)(colon - pair);
    if (len >= name_size) len = name_size - 1;
    memcpy(name_out, pair, len);
    name_out[len] = '\0';
  } else {
    strncpy(name_out, pair, name_size - 1);
    name_out[name_size - 1] = '\0';
  }
}

// Extract the "value" part from "name:value" format
static void _extract_value(const char* pair, char* value_out, size_t value_size) {
  const char* colon = strchr(pair, ':');
  if (colon != NULL) {
    strncpy(value_out, colon + 1, value_size - 1);
    value_out[value_size - 1] = '\0';
  } else {
    value_out[0] = '\0';
  }
}

// Check if an attribute matches a given name (from "name:value" format)
static bool _attribute_matches_name(const attribute_value_t* attr, const char* name) {
  char attr_name[CRABS_MAX_POLICY_EXPR];
  _extract_name(attr->value, attr_name, sizeof(attr_name));
  return strcmp(attr_name, name) == 0;
}

// ============================================================
// Attribute Machine Lifecycle
// ============================================================

attribute_machine_t* attribute_machine_create(const char* admin_id, const uint8_t admin_pk[33]) {
  if (admin_id == NULL || admin_pk == NULL) return NULL;

  attribute_machine_t* am = get_clear_memory(sizeof(attribute_machine_t));
  if (am == NULL) return NULL;

  // Initialize base state
  am->base_state.version = 0;
  am->base_state.config.max_lock_duration_ms = CRABS_DEFAULT_LOCK_MS;
  am->base_state.config.max_lock_extensions = CRABS_MAX_LOCK_EXTENDS;
  am->base_state.config.allow_force_unlock = true;
  strncpy(am->base_state.config.bootstrap_admin, admin_id, CRABS_MAX_USER_ID - 1);

  am->users = NULL;
  am->user_count = 0;
  am->current_time_ms = 0;

  // Create bootstrap admin user (§8.3 Genesis)
  user_t* admin = get_clear_memory(sizeof(user_t));
  if (admin == NULL) {
    free(am);
    return NULL;
  }

  strncpy(admin->user_id, admin_id, CRABS_MAX_USER_ID - 1);
  memcpy(admin->public_key, admin_pk, 33);
  admin->status = USER_ACTIVE;
  admin->key_version = 1;
  admin->created_at = 0;
  admin->updated_at = 0;
  admin->temp_attrs = NULL;
  admin->next = NULL;

  // Grant admin role to bootstrap user
  strncpy(admin->attributes[0].value, "role:admin", CRABS_MAX_POLICY_EXPR - 1);
  strncpy(admin->attributes[0].verified_by, admin_id, CRABS_MAX_USER_ID - 1);
  admin->attributes[0].verified_at = 0;
  admin->attributes[0].expires_at = 0;
  admin->attribute_count = 1;

  am->users = admin;
  am->user_count = 1;
  am->base_state.version = 1;

  return am;
}

void attribute_machine_destroy(attribute_machine_t* am) {
  if (am == NULL) return;

  user_t* user = am->users;
  while (user != NULL) {
    user_t* next_user = user->next;

    // Free temporary attributes linked list
    temp_attr_list_t* temp = user->temp_attrs;
    while (temp != NULL) {
      temp_attr_list_t* next_temp = temp->next;
      free(temp);
      temp = next_temp;
    }

    free(user);
    user = next_user;
  }

  // Destroy base state items
  data_item_t* item = am->base_state.items;
  while (item != NULL) {
    data_item_t* next = item->next;
    data_item_destroy(item);
    item = next;
  }

  if (am->base_state.policies != NULL) free(am->base_state.policies);
  if (am->base_state.log != NULL) free(am->base_state.log);
  if (am->base_state.processed_ops != NULL) free(am->base_state.processed_ops);

  free(am);
}

// ============================================================
// User Operations (§8.4)
// ============================================================

crabs_error_e attribute_machine_register_user(attribute_machine_t* am, const char* user_id,
                                               const uint8_t public_key[33],
                                               const char* initial_attrs) {
  if (am == NULL || user_id == NULL || public_key == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Verify user_id is unique (§8.4.1)
  if (attribute_machine_find_user(am, user_id) != NULL) {
    return CRABS_ERR_DUPLICATE_OPERATION;
  }

  // Create user entry
  user_t* user = get_clear_memory(sizeof(user_t));
  if (user == NULL) return CRABS_ERR_OOM;

  strncpy(user->user_id, user_id, CRABS_MAX_USER_ID - 1);
  memcpy(user->public_key, public_key, 33);
  user->status = USER_ACTIVE;
  user->key_version = 1;
  user->created_at = am->current_time_ms;
  user->updated_at = am->current_time_ms;
  user->temp_attrs = NULL;

  // Parse initial attributes
  user->attribute_count = _parse_attributes(initial_attrs, user->attributes, CRABS_MAX_ATTRIBUTES);

  // Prepend to linked list
  user->next = am->users;
  am->users = user;
  am->user_count++;
  am->base_state.version++;

  return CRABS_SUCCESS;
}

crabs_error_e attribute_machine_grant_role(attribute_machine_t* am, const char* target_user,
                                            const char* role, const char* value,
                                            const char* signer_id) {
  if (am == NULL || target_user == NULL || role == NULL || value == NULL || signer_id == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }

  user_t* user = attribute_machine_find_user(am, target_user);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;

  if (user->status == USER_SUSPENDED) return CRABS_ERR_USER_SUSPENDED;

  // Check if role already exists — update it (§8.4.2)
  for (uint32_t i = 0; i < user->attribute_count; i++) {
    if (_attribute_matches_name(&user->attributes[i], role)) {
      char formatted[CRABS_MAX_POLICY_EXPR];
      snprintf(formatted, sizeof(formatted), "%s:%s", role, value);
      strncpy(user->attributes[i].value, formatted, CRABS_MAX_POLICY_EXPR - 1);
      strncpy(user->attributes[i].verified_by, signer_id, CRABS_MAX_USER_ID - 1);
      user->key_version++;
      am->base_state.version++;
      return CRABS_SUCCESS;
    }
  }

  // Add new role attribute
  if (user->attribute_count >= CRABS_MAX_ATTRIBUTES) {
    return CRABS_ERR_INVARIANT_VIOLATED;
  }

  uint32_t idx = user->attribute_count;
  char formatted[CRABS_MAX_POLICY_EXPR];
  snprintf(formatted, sizeof(formatted), "%s:%s", role, value);
  strncpy(user->attributes[idx].value, formatted, CRABS_MAX_POLICY_EXPR - 1);
  strncpy(user->attributes[idx].verified_by, signer_id, CRABS_MAX_USER_ID - 1);
  user->attributes[idx].verified_at = 0;
  user->attributes[idx].expires_at = 0;
  user->attribute_count++;
  user->key_version++;
  am->base_state.version++;

  return CRABS_SUCCESS;
}

crabs_error_e attribute_machine_self_assert(attribute_machine_t* am, const char* attribute,
                                              const char* value, const char* signer_id) {
  if (am == NULL || attribute == NULL || value == NULL || signer_id == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }

  user_t* user = attribute_machine_find_user(am, signer_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;

  if (user->status == USER_SUSPENDED) return CRABS_ERR_USER_SUSPENDED;

  // Check if attribute already exists (§8.4.3)
  for (uint32_t i = 0; i < user->attribute_count; i++) {
    if (_attribute_matches_name(&user->attributes[i], attribute)) {
      char formatted[CRABS_MAX_POLICY_EXPR];
      snprintf(formatted, sizeof(formatted), "%s:%s", attribute, value);
      strncpy(user->attributes[i].value, formatted, CRABS_MAX_POLICY_EXPR - 1);
      // Self-asserted: verified_by is empty
      user->attributes[i].verified_by[0] = '\0';
      user->key_version++;
      am->base_state.version++;
      return CRABS_SUCCESS;
    }
  }

  // Add new self-asserted attribute
  if (user->attribute_count >= CRABS_MAX_ATTRIBUTES) {
    return CRABS_ERR_INVARIANT_VIOLATED;
  }

  uint32_t idx = user->attribute_count;
  char formatted[CRABS_MAX_POLICY_EXPR];
  snprintf(formatted, sizeof(formatted), "%s:%s", attribute, value);
  strncpy(user->attributes[idx].value, formatted, CRABS_MAX_POLICY_EXPR - 1);
  user->attributes[idx].verified_by[0] = '\0';
  user->attributes[idx].verified_at = 0;
  user->attributes[idx].expires_at = 0;
  user->attribute_count++;
  user->key_version++;
  am->base_state.version++;

  return CRABS_SUCCESS;
}

crabs_error_e attribute_machine_verify_identity(attribute_machine_t* am, const char* target_user,
                                                  const char* attribute, const char* value,
                                                  const char* signer_id) {
  if (am == NULL || target_user == NULL || attribute == NULL || value == NULL || signer_id == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }

  user_t* user = attribute_machine_find_user(am, target_user);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;

  if (user->status == USER_SUSPENDED) return CRABS_ERR_USER_SUSPENDED;

  // Check if attribute already exists — set verified_by (§8.4.4)
  for (uint32_t i = 0; i < user->attribute_count; i++) {
    if (_attribute_matches_name(&user->attributes[i], attribute)) {
      char formatted[CRABS_MAX_POLICY_EXPR];
      snprintf(formatted, sizeof(formatted), "%s:%s", attribute, value);
      strncpy(user->attributes[i].value, formatted, CRABS_MAX_POLICY_EXPR - 1);
      strncpy(user->attributes[i].verified_by, signer_id, CRABS_MAX_USER_ID - 1);
      user->attributes[i].verified_at = am->current_time_ms;
      user->key_version++;
      am->base_state.version++;
      return CRABS_SUCCESS;
    }
  }

  // Add new verified attribute
  if (user->attribute_count >= CRABS_MAX_ATTRIBUTES) {
    return CRABS_ERR_INVARIANT_VIOLATED;
  }

  uint32_t idx = user->attribute_count;
  char formatted[CRABS_MAX_POLICY_EXPR];
  snprintf(formatted, sizeof(formatted), "%s:%s", attribute, value);
  strncpy(user->attributes[idx].value, formatted, CRABS_MAX_POLICY_EXPR - 1);
  strncpy(user->attributes[idx].verified_by, signer_id, CRABS_MAX_USER_ID - 1);
  user->attributes[idx].verified_at = am->current_time_ms;
  user->attributes[idx].expires_at = 0;
  user->attribute_count++;
  user->key_version++;
  am->base_state.version++;

  return CRABS_SUCCESS;
}

crabs_error_e attribute_machine_revoke_role(attribute_machine_t* am, const char* target_user,
                                              const char* role, const char* signer_id) {
  if (am == NULL || target_user == NULL || role == NULL || signer_id == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }

  user_t* user = attribute_machine_find_user(am, target_user);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;

  // Find and remove the role attribute (§8.4.5)
  bool found = false;
  for (uint32_t i = 0; i < user->attribute_count; i++) {
    if (_attribute_matches_name(&user->attributes[i], role)) {
      // Shift remaining attributes down
      for (uint32_t j = i; j < user->attribute_count - 1; j++) {
        user->attributes[j] = user->attributes[j + 1];
      }
      user->attribute_count--;
      // Clear the last slot
      memset(&user->attributes[user->attribute_count], 0, sizeof(attribute_value_t));
      found = true;
      break;
    }
  }

  if (!found) return CRABS_ERR_RESOURCE_NOT_FOUND;

  user->key_version++;
  am->base_state.version++;
  return CRABS_SUCCESS;
}

crabs_error_e attribute_machine_suspend_user(attribute_machine_t* am, const char* user_id) {
  if (am == NULL || user_id == NULL) return CRABS_ERR_INVALID_PARAM;

  user_t* user = attribute_machine_find_user(am, user_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;

  user->status = USER_SUSPENDED;
  user->key_version++;
  am->base_state.version++;

  return CRABS_SUCCESS;
}

// ============================================================
// Query Functions
// ============================================================

user_t* attribute_machine_find_user(attribute_machine_t* am, const char* user_id) {
  if (am == NULL || user_id == NULL) return NULL;

  user_t* user = am->users;
  while (user != NULL) {
    if (strcmp(user->user_id, user_id) == 0) return user;
    user = user->next;
  }
  return NULL;
}

bool attribute_machine_user_has_role(user_t* user, const char* role) {
  if (user == NULL || role == NULL) return false;

  for (uint32_t i = 0; i < user->attribute_count; i++) {
    if (_attribute_matches_name(&user->attributes[i], role)) {
      return true;
    }
  }
  return false;
}

attribute_value_t* attribute_machine_find_attribute(user_t* user, const char* name) {
  if (user == NULL || name == NULL) return NULL;

  for (uint32_t i = 0; i < user->attribute_count; i++) {
    if (_attribute_matches_name(&user->attributes[i], name)) {
      return &user->attributes[i];
    }
  }
  return NULL;
}

// ============================================================
// Temporary Attributes (Amendment 1, §7.1)
// ============================================================

crabs_error_e attribute_machine_issue_temporary(attribute_machine_t* am, const char* attribute,
                                                  const char* value, const char* role,
                                                  uint64_t duration_ms) {
  if (am == NULL || attribute == NULL || value == NULL || role == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }

  if (duration_ms == 0) return CRABS_ERR_INVALID_PARAM;

  uint64_t now = am->current_time_ms;
  uint64_t expires = now + duration_ms;

  // Iterate all users, find those matching the role (Amendment 1 §5.4)
  user_t* user = am->users;
  uint32_t granted = 0;

  while (user != NULL) {
    if (user->status != USER_ACTIVE) {
      user = user->next;
      continue;
    }

    if (attribute_machine_user_has_role(user, role)) {
      // Create temporary attribute
      temp_attr_list_t* temp = get_clear_memory(sizeof(temp_attr_list_t));
      if (temp == NULL) return CRABS_ERR_OOM;

      snprintf(temp->name, sizeof(temp->name), "%s:%s", attribute, value);
      strncpy(temp->value, value, CRABS_MAX_POLICY_EXPR - 1);
      temp->issued_at = now;
      temp->expires_at = expires;
      temp->next = NULL;

      // Prepend to user's temp_attrs linked list
      temp->next = user->temp_attrs;
      user->temp_attrs = temp;

      user->key_version++;
      granted++;
    }
    user = user->next;
  }

  if (granted > 0) {
    am->base_state.version++;
  }

  return CRABS_SUCCESS;
}

uint32_t attribute_machine_prune_expired_temporary(attribute_machine_t* am) {
  if (am == NULL) return 0;

  uint64_t now = am->current_time_ms;
  uint32_t total_pruned = 0;

  user_t* user = am->users;
  while (user != NULL) {
    temp_attr_list_t** indirect = &user->temp_attrs;
    uint32_t pruned_for_user = 0;

    while (*indirect != NULL) {
      temp_attr_list_t* current = *indirect;
      if (current->expires_at > 0 && current->expires_at <= now) {
        // Expired — remove it
        *indirect = current->next;
        free(current);
        total_pruned++;
        pruned_for_user++;
      } else {
        indirect = &current->next;
      }
    }

    if (pruned_for_user > 0) {
      user->key_version++;
    }

    user = user->next;
  }

  if (total_pruned > 0) {
    am->base_state.version++;
  }

  return total_pruned;
}