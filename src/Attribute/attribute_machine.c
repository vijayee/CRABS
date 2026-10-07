//
// Created by victor on 4/30/25.
//

#include "attribute_machine.h"
#include "../Lineage/lineage.h"
#include "../Util/platform.h"
#include "../StateMachine/state_machine.h"
#include "../Trigger/trigger.h"
#include "../Scheduler/scheduler.h"
#include "../Crypto/crypto.h"
#include "../Condition/condition.h"
#include "../Util/allocator.h"
#include "../CRDT/crdt_merge.h"
#include "../TxManager/tx_manager.h"
#include <openssl/crypto.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>

// ============================================================
// Internal helpers
// ============================================================

// Audit M-C: a signer_id is spliced raw into policy text via the {user_id}
// placeholder (condition.c _resolve_user_id_placeholder) before parsing.
// A signer_id containing '"', '(', ')', ',', or operator keywords could
// alter the policy's structure (policy-structure injection). Restrict
// signer_ids to a safe charset at registration so substitution cannot
// break out of the intended context.
//
// Audit N-2: the safe charset [A-Za-z0-9_-] already excludes delimiters, but
// it still allows the condition-language keywords (AND, OR, NOT, BETWEEN, IN,
// CONTAINS, CONTAINS_ANY, CONTAINS_ALL, true, false). A user who registers
// with user_id = "AND" or "OR" can alter a policy template's structure when
// {user_id} is substituted: e.g. policy "{user_id} IN (alice, bob)" with
// signer_id "AND" becomes "AND IN (alice, bob)" — the parser sees the AND
// keyword, not an identifier. Reject signer_ids that case-insensitively
// match a policy keyword so the substituted text is always a bare identifier.
static const char* _POLICY_KEYWORDS[] = {
  "and", "or", "not", "between", "in", "contains",
  "contains_any", "contains_all", "true", "false", NULL
};

static bool _is_policy_keyword(const char* id) {
  if (id == NULL) return false;
  for (int i = 0; _POLICY_KEYWORDS[i] != NULL; i++) {
    if (strcasecmp(id, _POLICY_KEYWORDS[i]) == 0) return true;
  }
  return false;
}

// Public safe-id predicate (see attribute_machine.h). The static wrapper
// keeps the audit-era call sites unchanged.
bool attribute_machine_is_safe_user_id(const char* id) {
  if (id == NULL || id[0] == '\0') return false;
  // R8-A-4: reject over-long ids. register_user truncates to 63 bytes, so two
  // distinct long ids sharing a 63-byte prefix would collide after truncation.
  if (strlen(id) >= CRABS_MAX_USER_ID) return false;
  for (const char* p = id; *p != '\0'; p++) {
    char c = *p;
    bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-';
    if (!ok) return false;
  }
  // Reject policy keywords so the {user_id} placeholder cannot inject
  // operator tokens into the condition AST.
  if (_is_policy_keyword(id)) return false;
  return true;
}

static bool _is_safe_user_id(const char* id) {
  return attribute_machine_is_safe_user_id(id);
}

// Audit R5-2 / R6-2: forward declarations so _parse_attributes can validate
// attribute name and value parts against the safe charset. The full
// definitions appear below (after _PRIVILEGED_ATTR_NAMES, which they do not
// depend on).
static bool _is_safe_attr_name(const char* name);
static bool _is_safe_attr_value(const char* value);

// Forward declaration: fires the state change hook for an attribute mutation
// (defined after _check_signer_is_active_admin, below).
static void _notify_attribute_change(attribute_machine_t* am, const char* action,
                                     const char* target_user, const char* preview);

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
  char* token = platform_strtok_r(buf, "|", &saveptr);

  while (token != NULL && count < max_count) {
    // Trim leading spaces
    while (*token == ' ') token++;

    // De-wonk: reject tokens containing commas. The attribute string is
    // comma-separated, so a comma in a token (e.g. "role:admin,secret")
    // would inject "secret" as a separate token — letting a user registered
    // with "role:admin,secret|dept:eng" satisfy a bare "secret" policy. Skip
    // the malformed token rather than storing it. This is defense in depth
    // alongside the _is_safe_attr_value check below.
    bool has_comma = false;
    for (const char* p = token; *p != '\0'; p++) {
      if (*p == ',') { has_comma = true; break; }
    }
    if (has_comma) {
      token = platform_strtok_r(NULL, "|", &saveptr);
      continue;
    }

    // Audit R5-2: validate the attribute NAME part against the safe charset.
    // Audit R6-2: validate the attribute VALUE part against the safe charset
    // too (reject commas and spaces), matching the _is_safe_attr_value check
    // in all mutation APIs (grant_role, self_assert, verify_identity,
    // issue_temporary). Without this, a space in the value part (e.g.
    // "role:admin secret") would pass through _parse_attributes even though
    // the mutation APIs reject it — an inconsistency in defense-in-depth.
    // Extract the name (before the colon) and value (after the colon) and
    // reject the token if either fails validation.
    {
      char name_buf[CRABS_MAX_POLICY_EXPR];
      char value_buf[CRABS_MAX_POLICY_EXPR];
      const char* colon = strchr(token, ':');
      size_t name_len = (colon != NULL) ? (size_t)(colon - token) : strlen(token);
      if (name_len >= sizeof(name_buf)) name_len = sizeof(name_buf) - 1;
      memcpy(name_buf, token, name_len);
      name_buf[name_len] = '\0';
      if (!_is_safe_attr_name(name_buf)) {
        token = platform_strtok_r(NULL, "|", &saveptr);
        continue;
      }
      // Validate the value part (after the colon). An empty value is allowed
      // (the mutation APIs allow it too — see _is_safe_attr_value comment).
      if (colon != NULL) {
        const char* value = colon + 1;
        size_t value_len = strlen(value);
        if (value_len >= sizeof(value_buf)) value_len = sizeof(value_buf) - 1;
        memcpy(value_buf, value, value_len);
        value_buf[value_len] = '\0';
        if (!_is_safe_attr_value(value_buf)) {
          token = platform_strtok_r(NULL, "|", &saveptr);
          continue;
        }
      }
    }

    strncpy(out[count].value, token, CRABS_MAX_POLICY_EXPR - 1);
    out[count].value[CRABS_MAX_POLICY_EXPR - 1] = '\0';
    out[count].verified_by[0] = '\0';
    out[count].verified_at = 0;
    out[count].expires_at = 0;
    count++;

    token = platform_strtok_r(NULL, "|", &saveptr);
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

// Audit N-1 / R4-3: the set of privileged attribute names that must never be
// mintable via self-assertion OR via trigger-issued temporary attributes. A
// trigger creator with __create_trigger__ authority could otherwise set
// issue_attribute="role" and attribute_value="admin", and when the trigger
// fires the target user receives a temporary "role:admin" attribute that
// satisfies role:admin policies and produces a real CP-ABE key with attribute
// role_admin (the F-1 blocklist in self_assert did not cover this path).
// Audit R4-3: "verifier" and "issuer" were specified in the N-1 recommendation
// but were missing from the blocklist. A trigger could mint "verifier:admin"
// which, while not matching "role:admin" directly, could satisfy policies
// written against the verifier namespace. Add them now.
static const char* _PRIVILEGED_ATTR_NAMES[] = {
  "role", "admin", "member", "owner", "root", "superuser", "manager",
  "verifier", "issuer",
  // R8-A-10: defense-in-depth — block additional privileged-looking names.
  "role_admin", "administrator", "superadmin", "sysadmin", "moderator",
  "operator", NULL
};

static bool _is_privileged_attr_name(const char* name) {
  if (name == NULL || name[0] == '\0') return false;
  for (int i = 0; _PRIVILEGED_ATTR_NAMES[i] != NULL; i++) {
    if (strcasecmp(name, _PRIVILEGED_ATTR_NAMES[i]) == 0) return true;
  }
  return false;
}

// Audit R4-5: attribute names arrive from attacker-controlled operation
// payloads (trigger effect issue_attribute, self_assert attribute argument).
// The privileged-name blocklist uses strcasecmp, so it blocks "Role"/"ADMIN"
// etc., but it does NOT defend against Unicode homoglyph attacks (e.g. a
// Cyrillic 'а' in "аdmin"). The user_id charset check (_is_safe_user_id)
// rejects non-ASCII, but attribute names were never validated against the
// same charset. Reject attribute names containing characters outside
// [A-Za-z0-9_-] so homoglyphs and other non-portable characters cannot enter
// the attribute namespace.
static bool _is_safe_attr_name(const char* name) {
  if (name == NULL || name[0] == '\0') return false;
  for (const char* p = name; *p != '\0'; p++) {
    char c = *p;
    bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-';
    if (!ok) return false;
  }
  return true;
}

// De-wonk: reject attribute values containing comma or space. The attribute
// string is comma-separated and the policy tokenizer splits on commas and
// spaces, so a value like "secret,admin" would inject "admin" as a separate
// token into the attribute string — letting a user who self-asserts
// clearance:secret,admin satisfy a bare "admin" policy. This is a
// pre-existing injection vector, not introduced by the Round 4 changes, but
// found during the de-wonk pass over the attribute namespace safety work.
//
// Audit R5-3: empty values ARE allowed (the loop body never executes for an
// empty string, so the function returns true). This is intentional: the CLI
// uses grant_role("role:admin", "") where the full token is in the role
// parameter and the value is intentionally empty, producing "role:". This
// asymmetry with _is_safe_attr_name (which rejects empty names) is by design
// — an attribute must have a name but may have an empty value. A "role:"
// token with trailing colon is unlikely to match any real policy, but is
// harmless.
static bool _is_safe_attr_value(const char* value) {
  if (value == NULL) return false;
  for (const char* p = value; *p != '\0'; p++) {
    char c = *p;
    // R8-A-3: also reject '|', which _crabs_attrs_to_oabe preserves as the
    // OABE attribute separator. A self-asserted value like "x|role_admin"
    // would inject "role_admin" as a separate attribute into the CP-ABE key.
    if (c == ',' || c == ' ' || c == '|') return false;
  }
  return true;
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
  // The embedded base_state is zero-cleared (get_clear_memory), so it never
  // runs state_create's defaults — the per-tick occurrence budget must be
  // seeded here too or the scheduler runs unbounded in bindings (the default
  // field value 0 reads as "unlimited").
  am->base_state.max_occurrences_per_tick =
      CRABS_SCHEDULER_DEFAULT_MAX_OCCURRENCES_PER_TICK;

  am->users = NULL;
  am->user_count = 0;
  am->current_time_ms = 0;

  // Every machine needs an ABE master key for attribute-based verification
  // (signature verification consults the attribute machine; the ABE master
  // key is required for real CP-ABE attribute checks).
  am->base_state.abe_mk = crypto_abe_setup();
  if (am->base_state.abe_mk == NULL) {
    free(am);
    return NULL;
  }

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

// Teardown for a single user record: temporary attributes, keyring, record.
// Shared by attribute_users_destroy_all and the v10 deserializer's per-entry
// failure cleanup.
void user_destroy(user_t* user) {
  if (user == NULL) return;

  // Free temporary attributes linked list
  temp_attr_list_t* temp = user->temp_attrs;
  while (temp != NULL) {
    temp_attr_list_t* next_temp = temp->next;
    free(temp);
    temp = next_temp;
  }

  // Free keyring linked list
  user_key_destroy_all(user);

  free(user);
}

// Shared teardown for the user registry (v10 durability): frees every user
// along the linked list together with its keyring and temporary attributes,
// then clears am->users and am->user_count so the machine reports an empty
// registry after the call — the machine is typically about to be destroyed.
void attribute_users_destroy_all(attribute_machine_t* am) {
  if (am == NULL) return;

  user_t* user = am->users;
  while (user != NULL) {
    user_t* next_user = user->next;
    user_destroy(user);
    user = next_user;
  }
  am->users = NULL;
  am->user_count = 0;
}

void attribute_machine_destroy(attribute_machine_t* am) {
  if (am == NULL) return;

  // A10-6 FIRST, while every field is still valid: if this machine is a
  // resident lineage child of some parent state, drop its registry slot in
  // the owner and detach the weak back-pointer. Skipping this left the
  // parent's registry holding a dangling pointer that __dissolve_machine__
  // wrote through (heap write-after-free).
  lineage_resident_child_destroyed(am);

  attribute_users_destroy_all(am);

  // Destroy base state items — clean up CRDT values before data_item_destroy
  // since data_item_destroy uses free() which doesn't clean up CRDT struct internals
  data_item_t* item = am->base_state.items;
  while (item != NULL) {
    data_item_t* next = item->next;
    if (item->value != NULL) {
      crdt_value_destroy(item->crdt_type, item->value);
      item->value = NULL;
    }
    data_item_destroy(item);
    item = next;
  }

  if (am->base_state.policies != NULL) free(am->base_state.policies);
  if (am->base_state.log != NULL) free(am->base_state.log);
  // Scheduler entries (pending timed transactions) are state-owned heap
  // records; v10 snapshots restore them, so this teardown must mirror
  // state_destroy's lifecycle or every loaded-and-destroyed CLI node leaks
  // its restored schedules.
  scheduler_destroy_all(&am->base_state);
  if (am->base_state.op_type_defs != NULL) free(am->base_state.op_type_defs);
  if (am->base_state.op_handlers != NULL) free(am->base_state.op_handlers);
  // Lineage child manifest: heap array owned by the state — mirror
  // state_destroy's teardown so independently owned machines (this path)
  // release it too.
  if (am->base_state.children != NULL) free(am->base_state.children);
  // A10-M6 parent key chain + stashed last transition: state-owned heap —
  // mirror state_destroy's teardown.
  if (am->base_state.lineage_key_chain != NULL) {
    free(am->base_state.lineage_key_chain);
  }
  if (am->base_state.lineage_last_key_transition != NULL) {
    free(am->base_state.lineage_last_key_transition);
  }
  // Lineage resident-child registry: runtime-only UNOWNED views (each child
  // is owned by whoever spawned/holds it) — free the pointer array only.
  // A10-6: this machine is the registry OWNER and is dying FIRST — NULL each
  // resident child's weak lineage_owner_state back-pointer before the array
  // is freed, or a child that outlives its parent would walk a dangling owner
  // pointer in its own destroy hook.
  lineage_detach_resident_children(&am->base_state);
  if (am->base_state.resident_children != NULL) {
    free(am->base_state.resident_children);
  }
  if (am->base_state.tx_manager != NULL) {
    crabs_tx_manager_t* tx = (crabs_tx_manager_t*)am->base_state.tx_manager;
    if (tx->vtable.destroy != NULL) tx->vtable.destroy(tx);
  }
  // Borrowed MSK (spawned shared-root child): the parent's live authority
  // stays owned by the parent — skip the destroy here.
  if (am->base_state.abe_mk != NULL && !am->base_state.abe_mk_borrowed) {
    crypto_abe_master_key_destroy(am->base_state.abe_mk);
  }
  if (am->base_state.node_key_valid) OPENSSL_cleanse(am->base_state.node_private_key, 32);
  if (am->base_state.triggers != NULL) {
    for (uint32_t i = 0; i < am->base_state.trigger_count; i++) {
      if (am->base_state.triggers[i].condition_ast != NULL) {
        condition_node_destroy(am->base_state.triggers[i].condition_ast);
      }
    }
    free(am->base_state.triggers);
  }
  if (am->base_state.last_refresh_envelope != NULL) {
    crypto_key_envelope_destroy(am->base_state.last_refresh_envelope);
  }

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
  // Audit M-C: reject signer_ids outside the safe charset so the {user_id}
  // policy placeholder cannot inject policy structure.
  if (!_is_safe_user_id(user_id)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // Audit N-3: reject invalid public keys at registration. A key that does
  // not decode to a point on secp256k1 (or decodes to the point at infinity)
  // would make ECDH in the ECIES envelope encryption produce a predictable
  // shared secret, defeating envelope confidentiality. Validate before the
  // user is ever stored.
  if (!crypto_ecdsa_validate_public_key(public_key)) {
    return CRABS_ERR_INVALID_PARAM;
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

  // R7-08: register_user must not mint privileged attributes (role, admin,
  // owner, ...) from initial_attrs. Privileged attributes are granted only via
  // the admin grant_role path; a public register_user call must not be able to
  // create a role:admin user. Reject the whole registration if any parsed
  // attribute name is privileged.
  for (uint32_t i = 0; i < user->attribute_count; i++) {
    const char* colon = strchr(user->attributes[i].value, ':');
    size_t name_len = (colon != NULL) ? (size_t)(colon - user->attributes[i].value)
                                      : strlen(user->attributes[i].value);
    char name_buf[CRABS_MAX_POLICY_EXPR];
    if (name_len >= sizeof(name_buf)) name_len = sizeof(name_buf) - 1;
    memcpy(name_buf, user->attributes[i].value, name_len);
    name_buf[name_len] = '\0';
    if (_is_privileged_attr_name(name_buf)) {
      free(user);
      return CRABS_ERR_INVALID_PARAM;
    }
  }

  // Prepend to linked list
  user->next = am->users;
  am->users = user;
  am->user_count++;
  am->base_state.version++;

  _notify_attribute_change(am, "register_user", user_id, "user registered");
  return CRABS_SUCCESS;
}

// Shared admin gate (audit follow-up: module-level gates). Every
// user-mutating operation requires the signer to be an ACTIVE user holding
// the role:admin attribute.
static crabs_error_e _check_signer_is_active_admin(attribute_machine_t* am,
                                                     const char* signer_id) {
  user_t* signer = attribute_machine_find_user(am, signer_id);
  if (signer == NULL) return CRABS_ERR_USER_NOT_FOUND;
  if (signer->status != USER_ACTIVE) return CRABS_ERR_USER_SUSPENDED;
  for (uint32_t i = 0; i < signer->attribute_count; i++) {
    if (strcmp(signer->attributes[i].value, "role:admin") == 0) {
      return CRABS_SUCCESS;
    }
  }
  return CRABS_ERR_UNAUTHORIZED;
}

// Fire the state change hook (devtools change events) for an attribute
// mutation. am->base_state carries the hook; preview is a short summary.
static void _notify_attribute_change(attribute_machine_t* am, const char* action,
                                     const char* target_user, const char* preview) {
  state_notify_change(&am->base_state, CRABS_CHANGE_ATTRIBUTE, action, NULL,
                      NULL, am->base_state.config.bootstrap_admin, target_user,
                      preview, CRABS_SUCCESS);
}

crabs_error_e attribute_machine_grant_role(attribute_machine_t* am, const char* target_user,
                                            const char* role, const char* value,
                                            const char* signer_id) {
  if (am == NULL || target_user == NULL || role == NULL || value == NULL || signer_id == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Audit R5-1: validate the attribute NAME charset. self_assert and
  // issue_temporary call _is_safe_attr_name, but grant_role previously did not
  // — a caller with grant authority could pass a role name like "role,admin"
  // which produces the token "role,admin:value", and the comma splits into two
  // tokens in the attribute string ("role" and "admin:value"), letting a bare
  // "role" token satisfy unrelated policies. The value check alone does not
  // defend against name-part injection.
  if (!_is_safe_attr_name(role)) return CRABS_ERR_INVALID_PARAM;
  // De-wonk: reject values containing comma/space to prevent attribute-string
  // token injection (see _is_safe_attr_value).
  if (!_is_safe_attr_value(value)) return CRABS_ERR_INVALID_PARAM;

  // R8-A-2: the signer must be an active user holding role:admin. The prior
  // code stored signer_id in verified_by without checking authorization, so
  // any caller could grant role:admin to anyone.
  crabs_error_e signer_rc = _check_signer_is_active_admin(am, signer_id);
  if (signer_rc != CRABS_SUCCESS) return signer_rc;

  user_t* user = attribute_machine_find_user(am, target_user);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;

  // Audit R4-2: whitelist USER_ACTIVE. The prior == USER_SUSPENDED check let
  // a REVOKED user through (REVOKED != SUSPENDED), so a revoked user could
  // still grant roles to other users. Only ACTIVE users may mutate roles.
  if (user->status != USER_ACTIVE) return CRABS_ERR_USER_SUSPENDED;

  // Check if role already exists — update it (§8.4.2)
  for (uint32_t i = 0; i < user->attribute_count; i++) {
    if (_attribute_matches_name(&user->attributes[i], role)) {
      char formatted[CRABS_MAX_POLICY_EXPR];
      snprintf(formatted, sizeof(formatted), "%s:%s", role, value);
      strncpy(user->attributes[i].value, formatted, CRABS_MAX_POLICY_EXPR - 1);
      strncpy(user->attributes[i].verified_by, signer_id, CRABS_MAX_USER_ID - 1);
      user->key_version++;
      am->base_state.version++;
      _notify_attribute_change(am, "grant_role", target_user, formatted);
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

  _notify_attribute_change(am, "grant_role", target_user, formatted);
  return CRABS_SUCCESS;
}

crabs_error_e attribute_machine_self_assert(attribute_machine_t* am, const char* attribute,
                                              const char* value, const char* signer_id) {
  if (am == NULL || attribute == NULL || value == NULL || signer_id == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Self-assertion is for non-privileged, user-owned attributes only. A user
  // must not be able to grant themselves authorization-bearing attributes
  // (role:admin, admin, member, owner, etc.) — those require an admin
  // grant via attribute_machine_grant_role. Without this restriction a user
  // could self-assert role:admin and satisfy any role policy (audit C-5).
  if (attribute == NULL || attribute[0] == '\0') return CRABS_ERR_INVALID_PARAM;
  // Audit R4-5: reject attribute names outside the safe charset so Unicode
  // homoglyphs and other non-portable characters cannot bypass the
  // privileged-name blocklist (which uses strcasecmp and would not catch
  // a Cyrillic 'а' in "аdmin").
  if (!_is_safe_attr_name(attribute)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // De-wonk: reject values containing comma/space to prevent attribute-string
  // token injection (see _is_safe_attr_value).
  if (!_is_safe_attr_value(value)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (_is_privileged_attr_name(attribute)) {
    return CRABS_ERR_UNAUTHORIZED;
  }

  user_t* user = attribute_machine_find_user(am, signer_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;

  // Audit R4-2: whitelist USER_ACTIVE (rejects SUSPENDED and REVOKED).
  if (user->status != USER_ACTIVE) return CRABS_ERR_USER_SUSPENDED;

  // Check if attribute already exists (§8.4.3)
  for (uint32_t i = 0; i < user->attribute_count; i++) {
    if (_attribute_matches_name(&user->attributes[i], attribute)) {
      // An existing verified attribute may not be overwritten by a self-assert.
      if (user->attributes[i].verified_by[0] != '\0') {
        return CRABS_ERR_UNAUTHORIZED;
      }
      char formatted[CRABS_MAX_POLICY_EXPR];
      snprintf(formatted, sizeof(formatted), "%s:%s", attribute, value);
      strncpy(user->attributes[i].value, formatted, CRABS_MAX_POLICY_EXPR - 1);
      // Self-asserted: verified_by is empty
      user->attributes[i].verified_by[0] = '\0';
      user->key_version++;
      am->base_state.version++;
      _notify_attribute_change(am, "self_assert", signer_id, attribute);
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

  _notify_attribute_change(am, "self_assert", signer_id, attribute);
  return CRABS_SUCCESS;
}

crabs_error_e attribute_machine_verify_identity(attribute_machine_t* am, const char* target_user,
                                                  const char* attribute, const char* value,
                                                  const char* signer_id) {
  if (am == NULL || target_user == NULL || attribute == NULL || value == NULL || signer_id == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Audit R5-1: validate the attribute NAME charset, matching grant_role /
  // self_assert / issue_temporary. Without this, a verifier could pass an
  // attribute name like "email,admin" which produces the token
  // "email,admin:value" — the comma splits into two tokens in the attribute
  // string, letting a bare "email" token satisfy unrelated policies.
  if (!_is_safe_attr_name(attribute)) return CRABS_ERR_INVALID_PARAM;
  // De-wonk: reject values containing comma/space to prevent attribute-string
  // token injection (see _is_safe_attr_value).
  if (!_is_safe_attr_value(value)) return CRABS_ERR_INVALID_PARAM;
  // R8-A-1: verify_identity must not mint privileged attributes (role:admin,
  // owner, ...). Only grant_role may issue those. Without this, any caller
  // could mint a verified role:admin on any target.
  if (_is_privileged_attr_name(attribute)) return CRABS_ERR_UNAUTHORIZED;

  // R8-A-1: the signer must be an authorized verifier (holds role:admin).
  user_t* signer = attribute_machine_find_user(am, signer_id);
  if (signer == NULL) return CRABS_ERR_USER_NOT_FOUND;
  if (signer->status != USER_ACTIVE) return CRABS_ERR_USER_SUSPENDED;
  bool signer_is_admin = false;
  for (uint32_t i = 0; i < signer->attribute_count; i++) {
    if (strcmp(signer->attributes[i].value, "role:admin") == 0) {
      signer_is_admin = true;
      break;
    }
  }
  if (!signer_is_admin) return CRABS_ERR_UNAUTHORIZED;

  user_t* user = attribute_machine_find_user(am, target_user);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;

  // Audit R4-2: whitelist USER_ACTIVE (rejects SUSPENDED and REVOKED).
  if (user->status != USER_ACTIVE) return CRABS_ERR_USER_SUSPENDED;

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
      _notify_attribute_change(am, "verify_identity", target_user, attribute);
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

  _notify_attribute_change(am, "verify_identity", target_user, attribute);
  return CRABS_SUCCESS;
}

crabs_error_e attribute_machine_revoke_role(attribute_machine_t* am, const char* target_user,
                                              const char* role, const char* signer_id) {
  if (am == NULL || target_user == NULL || role == NULL || signer_id == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Audit follow-up: admin gate. Stripping roles is exactly the privilege
  // that must not be available to a non-admin caller — revoking role:admin
  // from the real admins would hand the machine to whoever calls next.
  crabs_error_e signer_rc = _check_signer_is_active_admin(am, signer_id);
  if (signer_rc != CRABS_SUCCESS) return signer_rc;

  user_t* user = attribute_machine_find_user(am, target_user);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;

  // Audit R4-4: intentionally no USER_ACTIVE status check here. Revoking a
  // role from a SUSPENDED or REVOKED user is a valid administrative action
  // (stripping remaining privileges from a bad actor). The other
  // attribute_machine mutations (grant_role, self_assert, verify_identity)
  // restrict to ACTIVE targets because adding/modifying attributes on a
  // revoked user is pointless at best and confusing at worst. Role
  // revocation is the one mutation that must work regardless of target
  // status — otherwise an admin cannot fully decommission a revoked user.

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
  _notify_attribute_change(am, "revoke_role", target_user, role);
  return CRABS_SUCCESS;
}

crabs_error_e attribute_machine_suspend_user(attribute_machine_t* am, const char* user_id,
                                               const char* signer_id) {
  if (am == NULL || user_id == NULL || signer_id == NULL) return CRABS_ERR_INVALID_PARAM;

  // Audit follow-up: admin gate. Suspension denies a user every
  // authorization gate, so an ungated suspend was a full account-takeover
  // primitive.
  crabs_error_e signer_rc = _check_signer_is_active_admin(am, signer_id);
  if (signer_rc != CRABS_SUCCESS) return signer_rc;

  return attribute_machine_suspend_user_internal(am, user_id, "user suspended");
}

crabs_error_e attribute_machine_suspend_user_internal(attribute_machine_t* am,
                                                        const char* user_id,
                                                        const char* preview) {
  if (am == NULL || user_id == NULL || preview == NULL) return CRABS_ERR_INVALID_PARAM;

  user_t* user = attribute_machine_find_user(am, user_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;

  // R8-C-4: revocation is terminal. Suspending a REVOKED user would downgrade
  // them to the recoverable SUSPENDED state, letting activate_user resurrect
  // a revoked user. Refuse instead.
  if (user->status == USER_REVOKED) return CRABS_ERR_INVALID_PARAM;

  user->status = USER_SUSPENDED;
  user->key_version++;
  am->base_state.version++;

  _notify_attribute_change(am, "suspend_user", user_id, preview);
  return CRABS_SUCCESS;
}

// R7-07: reactivate a SUSPENDED user after key-compromise recovery. The
// signer must be an active user holding the role:admin attribute. REVOKED
// users are terminal (audit H-C) and cannot be reactivated.
// R8-A-5: key_version IS bumped on activation. The prior code left it
// unchanged, so signatures made during suspension at that version remained
// valid after reactivation if the compromised key was not rotated.
crabs_error_e attribute_machine_activate_user(attribute_machine_t* am, const char* target_user,
                                               const char* signer_id) {
  if (am == NULL || target_user == NULL || signer_id == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Admin authorization: the signer must be an active user holding the
  // role:admin attribute.
  crabs_error_e signer_rc = _check_signer_is_active_admin(am, signer_id);
  if (signer_rc != CRABS_SUCCESS) return signer_rc;

  user_t* user = attribute_machine_find_user(am, target_user);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;

  // Only SUSPENDED users are recoverable; REVOKED is terminal.
  if (user->status != USER_SUSPENDED) return CRABS_ERR_INVALID_PARAM;

  user->status = USER_ACTIVE;
  user->key_version++;
  am->base_state.version++;

  _notify_attribute_change(am, "activate_user", target_user, "user activated");
  return CRABS_SUCCESS;
}

// Audit H-C: revocation is terminal. A revoked user is rejected by every
// authorization gate (all gates check status == USER_ACTIVE, a whitelist),
// and may not refresh keys. Re-registration is required to restore access.
crabs_error_e attribute_machine_revoke_user(attribute_machine_t* am, const char* user_id,
                                              const char* signer_id) {
  if (am == NULL || user_id == NULL || signer_id == NULL) return CRABS_ERR_INVALID_PARAM;

  // Audit follow-up: admin gate. Revocation is terminal — an ungated call
  // permanently destroyed any account with no recovery path.
  crabs_error_e signer_rc = _check_signer_is_active_admin(am, signer_id);
  if (signer_rc != CRABS_SUCCESS) return signer_rc;

  user_t* user = attribute_machine_find_user(am, user_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;

  user->status = USER_REVOKED;
  user->key_version++;
  am->base_state.version++;

  _notify_attribute_change(am, "revoke_user", user_id, "user revoked");
  return CRABS_SUCCESS;
}

void attribute_machine_set_time(attribute_machine_t* am, uint64_t now_ms) {
  if (am == NULL) return;
  am->current_time_ms = now_ms;
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

  // Audit N-1: a trigger creator can set the issue_attribute field at trigger
  // creation time. If the privileged-name blocklist is not consulted here, a
  // trigger with issue_attribute="role" and attribute_value="admin" mints a
  // temporary "role:admin" attribute on fire — satisfying role:admin policies
  // and producing a real CP-ABE key with attribute role_admin. The F-1 fix
  // blocked self-assertion of privileged names but not trigger-issued temp
  // attributes. Reject privileged names here so the blocklist covers both
  // paths.
  // Audit R4-5: also reject attribute names outside the safe charset so
  // Unicode homoglyphs cannot bypass the case-insensitive blocklist.
  if (!_is_safe_attr_name(attribute)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // De-wonk: reject values containing comma/space to prevent attribute-string
  // token injection (see _is_safe_attr_value).
  if (!_is_safe_attr_value(value)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (_is_privileged_attr_name(attribute)) {
    return CRABS_ERR_UNAUTHORIZED;
  }

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

  // No single target user: the grant fans out to every active holder of
  // `role`, so the role identifies the audience in the event's target field.
  _notify_attribute_change(am, "issue_temporary", role, attribute);
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

// ============================================================
// Key Ring Operations (v1.3 Amendment 3, §4.1)
// ============================================================

user_key_t* user_key_find(user_t* user, const char* key_id) {
  if (user == NULL || key_id == NULL) return NULL;
  user_key_t* key = user->keys;
  while (key != NULL) {
    if (strcmp(key->key_id, key_id) == 0) return key;
    key = key->next;
  }
  return NULL;
}

user_key_t* user_key_find_active(user_t* user, signature_scheme_e scheme) {
  if (user == NULL) return NULL;
  user_key_t* key = user->keys;
  while (key != NULL) {
    if (key->status == KEY_ACTIVE && key->scheme == scheme) return key;
    key = key->next;
  }
  return NULL;
}

crabs_error_e user_key_register(user_t* user, const char* key_id,
                                 signature_scheme_e scheme,
                                 const uint8_t* public_key, uint32_t public_key_len,
                                 const char* label) {
  if (user == NULL || key_id == NULL || public_key == NULL || public_key_len == 0) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (public_key_len > CRABS_MAX_PUBLIC_KEY) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (scheme == SCHEME_UNSPECIFIED) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (user->key_count >= CRABS_MAX_KEYS_PER_USER) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // Audit N-3: validate secp256k1 compressed public keys (33 bytes) at
  // registration so the ECIES envelope encryption never performs ECDH against
  // an invalid recipient key. Other schemes (Ed25519, BLS, Dilithium, etc.)
  // have their own key formats and are validated by their vtable on use.
  if (public_key_len == 33 &&
      (scheme == ECDSA_SECP256K1 || scheme == SCHNORR_SECP256K1)) {
    if (!crypto_ecdsa_validate_public_key(public_key)) {
      return CRABS_ERR_INVALID_PARAM;
    }
  }
  // Check for duplicate key_id
  if (user_key_find(user, key_id) != NULL) {
    return CRABS_ERR_DUPLICATE_OPERATION;
  }

  user_key_t* key = get_clear_memory(sizeof(user_key_t));
  if (key == NULL) return CRABS_ERR_OOM;

  strncpy(key->key_id, key_id, CRABS_MAX_KEY_ID - 1);
  key->scheme = scheme;
  memcpy(key->public_key, public_key, public_key_len);
  key->public_key_len = public_key_len;
  if (label != NULL) {
    strncpy(key->label, label, CRABS_MAX_KEY_LABEL - 1);
  }
  key->status = KEY_ACTIVE;
  key->expires_at = 0;
  key->suspended_at = 0;
  key->revoked_at = 0;
  key->predecessor_key_id[0] = '\0';
  key->registered_at = 0;  // Caller should set if needed
  key->last_used_at = 0;

  // Prepend to linked list
  key->next = user->keys;
  user->keys = key;
  user->key_count++;

  // Set as default if this is the first key
  if (user->default_key_id[0] == '\0') {
    strncpy(user->default_key_id, key_id, CRABS_MAX_KEY_ID - 1);
  }

  return CRABS_SUCCESS;
}

crabs_error_e user_key_revoke(user_t* user, const char* key_id) {
  if (user == NULL || key_id == NULL) return CRABS_ERR_INVALID_PARAM;
  user_key_t* key = user_key_find(user, key_id);
  if (key == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
  if (key->status == KEY_REVOKED) return CRABS_ERR_KEY_REVOKED;

  key->status = KEY_REVOKED;
  key->revoked_at = 0;  // Caller should set if needed
  user->key_version++;

  // Count remaining active keys and find a replacement default if needed
  uint32_t active_count = 0;
  user_key_t* replacement = NULL;
  user_key_t* iter = user->keys;
  while (iter != NULL) {
    if (iter->status == KEY_ACTIVE) {
      active_count++;
      if (replacement == NULL && strcmp(iter->key_id, key_id) != 0) {
        replacement = iter;
      }
    }
    iter = iter->next;
  }

  // If this was the default key, transition to a replacement
  if (strcmp(user->default_key_id, key_id) == 0) {
    if (replacement != NULL) {
      strncpy(user->default_key_id, replacement->key_id, CRABS_MAX_KEY_ID - 1);
    } else {
      user->default_key_id[0] = '\0';
    }
  }

  // If no active keys remain, suspend the user. R8-A-6: revocation is
  // terminal — never downgrade a REVOKED user to the recoverable SUSPENDED
  // state, or activate_user could resurrect them.
  if (active_count == 0 && user->status != USER_REVOKED) {
    user->status = USER_SUSPENDED;
  }

  return CRABS_SUCCESS;
}

crabs_error_e user_key_set_default(user_t* user, const char* key_id) {
  if (user == NULL || key_id == NULL) return CRABS_ERR_INVALID_PARAM;
  user_key_t* key = user_key_find(user, key_id);
  if (key == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
  if (key->status != KEY_ACTIVE) return CRABS_ERR_KEY_NOT_ACTIVE;

  strncpy(user->default_key_id, key_id, CRABS_MAX_KEY_ID - 1);
  return CRABS_SUCCESS;
}

void user_key_destroy_all(user_t* user) {
  if (user == NULL) return;
  user_key_t* key = user->keys;
  while (key != NULL) {
    user_key_t* next = key->next;
    free(key);
    key = next;
  }
  user->keys = NULL;
  user->key_count = 0;
  user->default_key_id[0] = '\0';
}

// ============================================================
// Key Lifecycle Operations (v1.3 §9)
// ============================================================

crabs_error_e user_key_suspend(user_t* user, const char* key_id) {
  if (user == NULL || key_id == NULL) return CRABS_ERR_INVALID_PARAM;
  user_key_t* key = user_key_find(user, key_id);
  if (key == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
  if (key->status != KEY_ACTIVE) return CRABS_ERR_KEY_NOT_ACTIVE;

  key->status = KEY_SUSPENDED;
  key->suspended_at = 0;  // Caller should set if needed
  user->key_version++;

  // If this was the default key, find a replacement
  if (strcmp(user->default_key_id, key_id) == 0) {
    user_key_t* replacement = NULL;
    user_key_t* iter = user->keys;
    while (iter != NULL) {
      if (iter->status == KEY_ACTIVE && strcmp(iter->key_id, key_id) != 0) {
        replacement = iter;
        break;
      }
      iter = iter->next;
    }
    if (replacement != NULL) {
      strncpy(user->default_key_id, replacement->key_id, CRABS_MAX_KEY_ID - 1);
    } else {
      user->default_key_id[0] = '\0';
    }
  }

  return CRABS_SUCCESS;
}

crabs_error_e user_key_activate(user_t* user, const char* key_id) {
  if (user == NULL || key_id == NULL) return CRABS_ERR_INVALID_PARAM;
  user_key_t* key = user_key_find(user, key_id);
  if (key == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
  // Can only activate suspended keys (not revoked or expired)
  if (key->status == KEY_REVOKED) return CRABS_ERR_KEY_REVOKED;
  if (key->status == KEY_EXPIRED) return CRABS_ERR_KEY_EXPIRED;
  if (key->status == KEY_ACTIVE) return CRABS_SUCCESS;  // Already active, idempotent

  key->status = KEY_ACTIVE;
  key->suspended_at = 0;
  user->key_version++;

  // User status is NOT auto-reactivated here. A suspended user stays
  // suspended even if a key is activated — reactivation requires an
  // explicit administrative action. This prevents key activation from
  // being used as a backdoor to unsuspend users.

  return CRABS_SUCCESS;
}

crabs_error_e user_key_rotate(user_t* user, const char* old_key_id,
                               const char* new_key_id, signature_scheme_e new_scheme,
                               const uint8_t* new_public_key, uint32_t new_public_key_len,
                               const char* new_label) {
  if (user == NULL || old_key_id == NULL || new_key_id == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (new_public_key == NULL || new_public_key_len == 0) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (new_scheme == SCHEME_UNSPECIFIED) {
    return CRABS_ERR_INVALID_PARAM;
  }

  user_key_t* old_key = user_key_find(user, old_key_id);
  if (old_key == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
  if (old_key->status != KEY_ACTIVE) return CRABS_ERR_KEY_NOT_ACTIVE;

  // Check max key limit before adding new key
  uint32_t active_count = 0;
  user_key_t* iter = user->keys;
  while (iter != NULL) {
    if (iter->status == KEY_ACTIVE) active_count++;
    iter = iter->next;
  }
  if (active_count >= CRABS_MAX_KEYS_PER_USER) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Check for duplicate new key_id
  if (user_key_find(user, new_key_id) != NULL) {
    return CRABS_ERR_DUPLICATE_OPERATION;
  }

  // Register the new key
  crabs_error_e rc = user_key_register(user, new_key_id, new_scheme,
                                        new_public_key, new_public_key_len, new_label);
  if (rc != CRABS_SUCCESS) return rc;

  // Link the new key to the old key via predecessor
  user_key_t* new_key = user_key_find(user, new_key_id);
  if (new_key != NULL) {
    strncpy(new_key->predecessor_key_id, old_key_id, CRABS_MAX_KEY_ID - 1);
  }

  // Revoke the old key
  rc = user_key_revoke(user, old_key_id);
  if (rc != CRABS_SUCCESS) {
    // Rollback: remove the newly registered key
    user_key_t* prev = NULL;
    user_key_t* cur = user->keys;
    while (cur != NULL) {
      if (strcmp(cur->key_id, new_key_id) == 0) {
        if (prev == NULL) {
          user->keys = cur->next;
        } else {
          prev->next = cur->next;
        }
        free(cur);
        user->key_count--;
        break;
      }
      prev = cur;
      cur = cur->next;
    }
    return rc;
  }

  // If the old key was the default, set the new key as default
  if (strcmp(user->default_key_id, old_key_id) == 0 ||
      user->default_key_id[0] == '\0') {
    strncpy(user->default_key_id, new_key_id, CRABS_MAX_KEY_ID - 1);
  }

  return CRABS_SUCCESS;
}

const char* user_key_status_name(key_status_e status) {
  switch (status) {
    case KEY_ACTIVE:    return "active";
    case KEY_SUSPENDED: return "suspended";
    case KEY_REVOKED:   return "revoked";
    case KEY_EXPIRED:   return "expired";
    default:            return "unknown";
  }
}
