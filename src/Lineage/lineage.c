//
// Lineage (v1.7: machines mint machines) — blueprint data layer:
// create/destroy, append helpers, and full structural validation.
//
// Error mapping (crabs.h has no policy-specific enumerator, so the nearest
// real ones carry the semantics):
//   structural garbage           → CRABS_ERR_INVALID_PARAM
//   unparseable policy expression→ CRABS_ERR_UNAUTHORIZED (policy grammar)
//   duplicate item name          → CRABS_ERR_DUPLICATE_OPERATION
//                                   (mirrors state_add_item)
//

#include "lineage.h"
#include "../Attribute/attribute_machine.h"
#include "../Condition/condition.h"
#include "../Util/allocator.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward declaration: defined below (Policy expression parsing checks).
static bool _lineage_policy_expression_is_valid(const char* expression);

// ============================================================
// Lifecycle
// ============================================================

machine_blueprint_t* machine_blueprint_create(void) {
  return get_clear_memory(sizeof(machine_blueprint_t));
}

void machine_blueprint_destroy(machine_blueprint_t* blueprint) {
  if (blueprint == NULL) return;
  if (blueprint->items != NULL) free(blueprint->items);
  if (blueprint->policies != NULL) free(blueprint->policies);
  if (blueprint->op_type_defs != NULL) free(blueprint->op_type_defs);
  free(blueprint);
}

// ============================================================
// Append helpers
// ============================================================

// Operation names follow the same rules as user ids — non-empty, safe
// charset, NUL-terminated within their fixed capacity — so a hand-built
// struct cannot smuggle an unterminated string or an operator keyword.
static bool _blueprint_op_name_is_valid(const char* op_name) {
  return attribute_machine_is_safe_user_id(op_name) &&
         strlen(op_name) < CRABS_MAX_OP_NAME;
}

static crabs_error_e _blueprint_array_append(void** array_slot,
                                             uint32_t* count_slot,
                                             uint32_t max_count,
                                             size_t element_size) {
  if (*count_slot >= max_count) return CRABS_ERR_INVALID_PARAM;
  void* grown = realloc(*array_slot, (*count_slot + 1) * element_size);
  if (grown == NULL) return CRABS_ERR_OOM;
  *array_slot = grown;
  // Zero-init the new slot so fixed-capacity string fields stay terminated
  // (realloc does not zero-fill the grown region).
  memset((uint8_t*)*array_slot + *count_slot * element_size, 0, element_size);
  *count_slot += 1;
  return CRABS_SUCCESS;
}

crabs_error_e blueprint_add_item(machine_blueprint_t* blueprint,
                                 const char* name, data_type_e type,
                                 crdt_type_e crdt_type) {
  if (blueprint == NULL || !attribute_machine_is_safe_user_id(name)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  for (uint32_t item_index = 0; item_index < blueprint->item_count;
       item_index++) {
    if (strcmp(blueprint->items[item_index].name, name) == 0) {
      return CRABS_ERR_DUPLICATE_OPERATION;
    }
  }
  crabs_error_e status = _blueprint_array_append(
      (void**)&blueprint->items, &blueprint->item_count,
      CRABS_MAX_BLUEPRINT_ITEMS, sizeof(blueprint_item_t));
  if (status != CRABS_SUCCESS) return status;

  blueprint_item_t* appended = &blueprint->items[blueprint->item_count - 1];
  strncpy(appended->name, name, sizeof(appended->name) - 1);
  appended->type = type;
  appended->crdt_type = crdt_type;
  return CRABS_SUCCESS;
}

crabs_error_e blueprint_add_policy(machine_blueprint_t* blueprint,
                                   const char* operation,
                                   const char* expression) {
  if (blueprint == NULL || !_blueprint_op_name_is_valid(operation) ||
      expression == NULL || strlen(expression) >= CRABS_MAX_POLICY_EXPR) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (!_lineage_policy_expression_is_valid(expression)) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  crabs_error_e status = _blueprint_array_append(
      (void**)&blueprint->policies, &blueprint->policy_count,
      CRABS_MAX_BLUEPRINT_POLICIES, sizeof(blueprint_policy_t));
  if (status != CRABS_SUCCESS) return status;

  blueprint_policy_t* appended = &blueprint->policies[blueprint->policy_count - 1];
  strncpy(appended->operation, operation, sizeof(appended->operation) - 1);
  strncpy(appended->expression, expression, sizeof(appended->expression) - 1);
  return CRABS_SUCCESS;
}

crabs_error_e blueprint_add_op_type_def(machine_blueprint_t* blueprint,
                                        const char* op_type,
                                        const dedup_spec_t* dedup) {
  if (blueprint == NULL || !_blueprint_op_name_is_valid(op_type) ||
      dedup == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  crabs_error_e status = _blueprint_array_append(
      (void**)&blueprint->op_type_defs, &blueprint->op_type_def_count,
      CRABS_MAX_BLUEPRINT_OP_TYPE_DEFS, sizeof(blueprint_op_type_def_t));
  if (status != CRABS_SUCCESS) return status;

  blueprint_op_type_def_t* appended =
      &blueprint->op_type_defs[blueprint->op_type_def_count - 1];
  strncpy(appended->op_type, op_type, sizeof(appended->op_type) - 1);
  appended->dedup = *dedup;
  return CRABS_SUCCESS;
}

// ============================================================
// Policy expression parsing checks
// ============================================================

static bool _char_starts_identifier(char c) {
  return isalnum((unsigned char)c) || c == '_' || c == '-';
}

static bool _char_in_identifier(char c) {
  return isalnum((unsigned char)c) || c == '_' || c == '-' || c == ':' ||
         c == '.';
}

static bool _is_boolean_operator_word(const char* word, const char* canonical) {
  // The condition scanner (condition.c _lookup_keyword) matches keywords
  // case-INSENSITIVELY, but the ABE policy evaluator only honors UPPERCASE
  // operators — so the canonical form must be the exact spelling.
  return strcasecmp(word, canonical) == 0 && strcmp(word, canonical) != 0;
}

// Reject boolean operator words that are not exactly the uppercase canonical
// form ("or", "And", "oR"). The condition grammar would still parse them,
// but downstream the expression only reaches the ABE evaluator as a verbatim
// token — a non-canonical operator cannot act as a boolean separator there.
static bool _has_non_canonical_boolean_operator(const char* expression) {
  const char* cursor = expression;
  while (*cursor != '\0') {
    if (_char_starts_identifier(*cursor)) {
      const char* word_start = cursor;
      while (_char_in_identifier(*cursor)) cursor++;
      size_t word_len = (size_t)(cursor - word_start);
      char word[CRABS_MAX_POLICY_EXPR];
      if (word_len >= sizeof(word)) return false;
      memcpy(word, word_start, word_len);
      word[word_len] = '\0';
      if (_is_boolean_operator_word(word, "AND") ||
          _is_boolean_operator_word(word, "OR") ||
          _is_boolean_operator_word(word, "NOT")) {
        return true;
      }
      continue;
    }
    cursor++;
  }
  return false;
}

// A fixed-capacity field copied from a hand-built struct may be filled to
// capacity with no NUL terminator — strlen would read past the field. Check
// termination within capacity first, then apply the safe-id rules.
static bool _blueprint_id_field_is_safe(const char* field, size_t capacity) {
  if (field == NULL || strnlen(field, capacity) >= capacity) return false;
  return attribute_machine_is_safe_user_id(field);
}

// Structural validity shared by blueprint_add_policy and
// lineage_blueprint_validate. The authorization pipeline (condition.c
// preprocess_policy) accepts two expression families:
//   1. full condition grammar expressions (AND/OR/NOT/CONTAINS/comparisons);
//   2. bare attribute tokens — the "name:value" family condition_parse
//      rejects because ':' is not in the condition identifier charset, and
//      which preprocess_policy then passes through verbatim as the ABE
//      policy.
// To validate the boolean structure of BOTH with one call, every bare
// attribute token is rewritten into a placeholder comparison "aN == aN"
// before condition_parse. Quoted operands are rejected up front, mirroring
// preprocess_policy's fail-closed rule. An empty expression is valid (an op
// with no auth requirement — state_add_policy accepts the same).
static bool _lineage_policy_expression_is_valid(const char* expression) {
  if (expression == NULL) return false;
  if (expression[0] == '\0') return true;
  if (strchr(expression, '"') != NULL) return false;
  if (_has_non_canonical_boolean_operator(expression)) return false;

  char transformed[CRABS_MAX_POLICY_EXPR * 4];
  size_t write_pos = 0;
  int token_index = 0;
  const char* cursor = expression;
  while (*cursor != '\0') {
    if (_char_starts_identifier(*cursor)) {
      const char* run_start = cursor;
      bool has_colon = false;
      while (_char_in_identifier(*cursor)) {
        if (*cursor == ':') has_colon = true;
        cursor++;
      }
      if (has_colon) {
        int written = snprintf(transformed + write_pos,
                               sizeof(transformed) - write_pos,
                               "attr%d == attr%d ", token_index, token_index);
        if (written < 0 || (size_t)written >= sizeof(transformed) - write_pos) {
          return false;
        }
        write_pos += (size_t)written;
        token_index++;
      } else {
        size_t run_len = (size_t)(cursor - run_start);
        if (run_len >= sizeof(transformed) - write_pos) return false;
        memcpy(transformed + write_pos, run_start, run_len);
        write_pos += run_len;
      }
      continue;
    }
    if (write_pos + 1 >= sizeof(transformed)) return false;
    transformed[write_pos++] = *cursor++;
  }
  transformed[write_pos] = '\0';

  condition_node_t* ast = condition_parse(transformed);
  if (ast == NULL) return false;
  condition_node_destroy(ast);
  return true;
}

// ============================================================
// Blueprint validation
// ============================================================

crabs_error_e lineage_blueprint_validate(const machine_blueprint_t* blueprint) {
  if (blueprint == NULL) return CRABS_ERR_INVALID_PARAM;

  if (!_blueprint_id_field_is_safe(blueprint->child_id,
                                   sizeof(blueprint->child_id))) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (blueprint->trust_mode != LINEAGE_SHARED_ROOT &&
      blueprint->trust_mode != LINEAGE_DELEGATED_COPY &&
      blueprint->trust_mode != LINEAGE_SOVEREIGN) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // A fresh authority (DELEGATED_COPY / SOVEREIGN) has nobody to mint its
  // first roles until a bootstrap admin exists; a shared-root child borrows
  // the parent authority, so an empty bootstrap admin is acceptable there.
  bool bootstrap_admin_required =
      blueprint->trust_mode == LINEAGE_DELEGATED_COPY ||
      blueprint->trust_mode == LINEAGE_SOVEREIGN;
  if (bootstrap_admin_required && blueprint->bootstrap_admin[0] == '\0') {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (blueprint->bootstrap_admin[0] != '\0' &&
      !_blueprint_id_field_is_safe(blueprint->bootstrap_admin,
                                   sizeof(blueprint->bootstrap_admin))) {
    return CRABS_ERR_INVALID_PARAM;
  }

  if (blueprint->item_count > CRABS_MAX_BLUEPRINT_ITEMS ||
      blueprint->policy_count > CRABS_MAX_BLUEPRINT_POLICIES ||
      blueprint->op_type_def_count > CRABS_MAX_BLUEPRINT_OP_TYPE_DEFS) {
    return CRABS_ERR_INVALID_PARAM;
  }
  for (uint32_t item_index = 0; item_index < blueprint->item_count;
       item_index++) {
    if (!_blueprint_id_field_is_safe(blueprint->items[item_index].name,
                                     sizeof(blueprint->items[item_index].name))) {
      return CRABS_ERR_INVALID_PARAM;
    }
    for (uint32_t earlier_index = 0; earlier_index < item_index;
         earlier_index++) {
      if (strcmp(blueprint->items[item_index].name,
                 blueprint->items[earlier_index].name) == 0) {
        return CRABS_ERR_DUPLICATE_OPERATION;
      }
    }
  }
  for (uint32_t policy_index = 0; policy_index < blueprint->policy_count;
       policy_index++) {
    // A hand-built struct may have a capacity-full (unterminated) expression
    // field — strlen inside the predicate would read past it.
    if (memchr(blueprint->policies[policy_index].expression, '\0',
               CRABS_MAX_POLICY_EXPR) == NULL) {
      return CRABS_ERR_UNAUTHORIZED;
    }
    if (!_blueprint_id_field_is_safe(blueprint->policies[policy_index].operation,
                                     sizeof(blueprint->policies[policy_index].operation)) ||
        !_lineage_policy_expression_is_valid(
            blueprint->policies[policy_index].expression)) {
      return CRABS_ERR_UNAUTHORIZED;
    }
  }
  for (uint32_t def_index = 0; def_index < blueprint->op_type_def_count;
       def_index++) {
    if (!_blueprint_id_field_is_safe(blueprint->op_type_defs[def_index].op_type,
                                     sizeof(blueprint->op_type_defs[def_index].op_type))) {
      return CRABS_ERR_INVALID_PARAM;
    }
  }
  return CRABS_SUCCESS;
}