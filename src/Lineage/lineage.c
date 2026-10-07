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
#include "../Crypto/crypto.h"
#include "../Util/allocator.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

// Forward declaration: defined below (Policy expression parsing checks).
static bool _lineage_policy_expression_is_valid(const char* expression);

// ============================================================
// Attestations: issue / verify / wire transport
// ============================================================

// Canonical signing body (EXACT layout, shared by create/sign, verify, and
// serialize so the three can never drift):
//   u8 format_version; string16 parent_id; string16 child_id;
//   string16 user_id; string16 attributes; u64le not_before; u64le expires_at
// string16 = u16le byte length + bytes WITHOUT the trailing NUL.
// Worst case: 1 + 2*(63+1)*3 + 2*(255+1) + 8 + 8 = 470 bytes.
#define CRABS_ATTESTATION_BODY_MAX 512

static bool _lineage_field_is_safe(const char* field, size_t capacity) {
  if (field == NULL || strnlen(field, capacity) >= capacity) return false;
  return attribute_machine_is_safe_user_id(field);
}

static void _lineage_u16le_write(uint8_t* out, uint16_t value) {
  out[0] = (uint8_t)(value & 0xFF);
  out[1] = (uint8_t)(value >> 8);
}

static void _lineage_u32le_write(uint8_t* out, uint32_t value) {
  _lineage_u16le_write(out, (uint16_t)(value & 0xFFFF));
  _lineage_u16le_write(out + 2, (uint16_t)(value >> 16));
}

static void _lineage_u64le_write(uint8_t* out, uint64_t value) {
  for (size_t byte_index = 0; byte_index < 8; byte_index++) {
    out[byte_index] = (uint8_t)(value >> (byte_index * 8));
  }
}

static bool _lineage_u32le_read(const uint8_t* buf, size_t len,
                                size_t* offset, uint32_t* out) {
  if (*offset + 4 > len) return false;
  *out = (uint32_t)buf[*offset] |
         ((uint32_t)buf[*offset + 1] << 8) |
         ((uint32_t)buf[*offset + 2] << 16) |
         ((uint32_t)buf[*offset + 3] << 24);
  *offset += 4;
  return true;
}

static bool _lineage_u64le_read(const uint8_t* buf, size_t len,
                                size_t* offset, uint64_t* out) {
  if (*offset + 8 > len) return false;
  *out = 0;
  for (size_t byte_index = 0; byte_index < 8; byte_index++) {
    *out |= ((uint64_t)buf[*offset + byte_index]) << (byte_index * 8);
  }
  *offset += 8;
  return true;
}

// string16 write: a capacity-full (unterminated) field is a caller bug and
// fails closed — the canonical body could not be reproduced by a verifier.
static bool _lineage_string16_write(uint8_t* out, size_t cap, size_t* offset,
                                    const char* field, size_t field_capacity) {
  size_t field_len = strnlen(field, field_capacity);
  if (field_len >= field_capacity) return false;
  if (*offset + 2 + field_len > cap) return false;
  _lineage_u16le_write(out + *offset, (uint16_t)field_len);
  memcpy(out + *offset + 2, field, field_len);
  *offset += 2 + field_len;
  return true;
}

static bool _lineage_string16_read(const uint8_t* buf, size_t len,
                                   size_t* offset, char* out,
                                   size_t out_capacity) {
  if (*offset + 2 > len) return false;
  uint16_t str_len = (uint16_t)(buf[*offset] | (buf[*offset + 1] << 8));
  *offset += 2;
  // Reject over-long strings instead of truncating — a truncated string could
  // alias a different legitimate value.
  if (str_len >= out_capacity || *offset + str_len > len) return false;
  memcpy(out, buf + *offset, str_len);
  out[str_len] = '\0';
  *offset += str_len;
  return true;
}

// Single shared canonical-body writer behind signing, verification, and wire
// serialization. Returns bytes written, or 0 when a struct field is
// unterminated or `cap` is too small.
static size_t _attestation_write_canonical_body(const attestation_t* attestation,
                                                uint8_t* out, size_t cap) {
  size_t offset = 0;
  if (cap < 1) return 0;
  out[offset++] = attestation->format_version;
  if (!_lineage_string16_write(out, cap, &offset, attestation->parent_id,
                               sizeof(attestation->parent_id)) ||
      !_lineage_string16_write(out, cap, &offset, attestation->child_id,
                               sizeof(attestation->child_id)) ||
      !_lineage_string16_write(out, cap, &offset, attestation->user_id,
                               sizeof(attestation->user_id)) ||
      !_lineage_string16_write(out, cap, &offset, attestation->attributes,
                               sizeof(attestation->attributes))) {
    return 0;
  }
  if (offset + 16 > cap) return 0;
  _lineage_u64le_write(out + offset, attestation->not_before);
  _lineage_u64le_write(out + offset + 8, attestation->expires_at);
  offset += 16;
  return offset;
}

crabs_error_e attestation_create(state_t* parent,
                                 attestation_t* attestation_out,
                                 const char* parent_id, const char* child_id,
                                 const char* user_id, const char* attributes,
                                 uint64_t now_ms, uint64_t expires_at) {
  if (parent == NULL || attestation_out == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (!_lineage_field_is_safe(parent_id, sizeof(attestation_out->parent_id)) ||
      !_lineage_field_is_safe(child_id, sizeof(attestation_out->child_id)) ||
      !_lineage_field_is_safe(user_id, sizeof(attestation_out->user_id))) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (attributes == NULL || strnlen(attributes, CRABS_MAX_POLICY_EXPR) >=
                                CRABS_MAX_POLICY_EXPR) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (expires_at < now_ms) return CRABS_ERR_INVALID_PARAM;

  if (!parent->node_key_valid ||
      !crypto_ecdsa_validate_public_key(parent->node_public_key)) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  memset(attestation_out, 0, sizeof(*attestation_out));
  attestation_out->format_version = CRABS_ATTESTATION_FORMAT_VERSION;
  strncpy(attestation_out->parent_id, parent_id,
          sizeof(attestation_out->parent_id) - 1);
  strncpy(attestation_out->child_id, child_id,
          sizeof(attestation_out->child_id) - 1);
  strncpy(attestation_out->user_id, user_id,
          sizeof(attestation_out->user_id) - 1);
  strncpy(attestation_out->attributes, attributes,
          sizeof(attestation_out->attributes) - 1);
  attestation_out->not_before = now_ms;
  attestation_out->expires_at = expires_at;

  uint8_t canonical_body[CRABS_ATTESTATION_BODY_MAX];
  size_t body_len = _attestation_write_canonical_body(
      attestation_out, canonical_body, sizeof(canonical_body));
  if (body_len == 0) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  if (crypto_ecdsa_sign(parent->node_private_key, canonical_body, body_len,
                        attestation_out->signature) != CRABS_SUCCESS) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  return CRABS_SUCCESS;
}

bool attestation_verify(const uint8_t parent_public_key[33],
                        const char* child_id,
                        const attestation_t* attestation, uint64_t now_ms) {
  if (parent_public_key == NULL || child_id == NULL || attestation == NULL) {
    return false;
  }
  if (attestation->format_version != CRABS_ATTESTATION_FORMAT_VERSION) {
    return false;
  }
  if (attestation->not_before > now_ms || now_ms > attestation->expires_at) {
    return false;
  }
  // The signature covers child_id, so it must match the challenger exactly.
  if (strnlen(attestation->child_id, sizeof(attestation->child_id)) >=
          sizeof(attestation->child_id) ||
      strcmp(attestation->child_id, child_id) != 0) {
    return false;
  }
  uint8_t canonical_body[CRABS_ATTESTATION_BODY_MAX];
  size_t body_len = _attestation_write_canonical_body(
      attestation, canonical_body, sizeof(canonical_body));
  if (body_len == 0) return false;
  return crypto_ecdsa_verify(parent_public_key, canonical_body, body_len,
                             attestation->signature);
}

size_t attestation_serialize(const attestation_t* attestation,
                             uint8_t* out_buf, size_t buf_len) {
  if (attestation == NULL || out_buf == NULL) return 0;
  uint8_t canonical_body[CRABS_ATTESTATION_BODY_MAX];
  size_t body_len = _attestation_write_canonical_body(
      attestation, canonical_body, sizeof(canonical_body));
  if (body_len == 0) return 0;
  // u32le total length of everything that follows the prefix.
  uint32_t total_len = (uint32_t)(body_len + CRABS_SIG_SIZE);
  if (buf_len < 4 + total_len) return 0;
  _lineage_u32le_write(out_buf, total_len);
  memcpy(out_buf + 4, canonical_body, body_len);
  memcpy(out_buf + 4 + body_len, attestation->signature, CRABS_SIG_SIZE);
  return 4 + total_len;
}

attestation_t* attestation_deserialize(const uint8_t* buf, size_t len) {
  if (buf == NULL) return NULL;
  size_t offset = 0;
  uint32_t total_len;
  // The prefix must claim exactly the bytes that follow it.
  if (!_lineage_u32le_read(buf, len, &offset, &total_len) ||
      total_len != len - 4 ||
      total_len < CRABS_SIG_SIZE + 1 + 16) {
    return NULL;
  }
  uint8_t format_version;
  if (offset + 1 > len) return NULL;
  format_version = buf[offset++];
  if (format_version != CRABS_ATTESTATION_FORMAT_VERSION) return NULL;

  attestation_t* attestation = get_clear_memory(sizeof(*attestation));
  attestation->format_version = format_version;
  bool parsed =
      _lineage_string16_read(buf, len, &offset, attestation->parent_id,
                             sizeof(attestation->parent_id)) &&
      _lineage_string16_read(buf, len, &offset, attestation->child_id,
                             sizeof(attestation->child_id)) &&
      _lineage_string16_read(buf, len, &offset, attestation->user_id,
                             sizeof(attestation->user_id)) &&
      _lineage_string16_read(buf, len, &offset, attestation->attributes,
                             sizeof(attestation->attributes)) &&
      _lineage_u64le_read(buf, len, &offset, &attestation->not_before) &&
      _lineage_u64le_read(buf, len, &offset, &attestation->expires_at) &&
      offset + CRABS_SIG_SIZE == len;
  if (parsed) {
    memcpy(attestation->signature, buf + offset, CRABS_SIG_SIZE);
    return attestation;
  }
  free(attestation);
  return NULL;
}

void attestation_destroy(attestation_t* attestation) {
  if (attestation == NULL) return;
  free(attestation);
}

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

  // Worst case: a 3-char "a:b" token plus a one-char separator expands to
  // "attrNN == attrNN " (~17 chars per 4 input) — the x8 margin stays safe
  // for a fully colon-dense expression; snprintf guards remain fail-closed.
  char transformed[CRABS_MAX_POLICY_EXPR * 8];
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