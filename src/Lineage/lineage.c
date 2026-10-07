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
#include "../Serialization/serialization.h"
#include "../StateMachine/state_machine.h"
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
// Worst case: 1 + (2+63)*3 + (2+255) + 8 + 8 = 469 bytes; the cap lives in
// lineage.h (CRABS_ATTESTATION_BODY_MAX) next to the wire cap that layers on
// top of it.

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
// Blueprint wire format: stamp / serialize / deserialize
// ============================================================

// Canonical blueprint body (EXACT layout, shared by hash stamping,
// serialization, and deserialization so the three can never drift):
//   u8 trust_mode; string16 child_id; string16 bootstrap_admin;
//   u64le attestation_ttl_ms;
//   u32le item_count;  per item: string16 name; u8 type; u8 crdt_type;
//   u32le policy_count;  per policy: string16 operation; string16 expression;
//   u32le op_type_def_count;  per def: string16 op_type; <dedup_spec>
// <dedup_spec> (mirrors serialization.c _serialize_dedup_spec):
//   u8 dedup type; string16 tracker_path; string16 flag_path;
//   string16 condition; u8 update type; string16 update.set_path;
//   string16 update.element_value; string16 update.flag_path;
//   string16 update.counter_path; i64le update.delta;
//   string16 update.target_path; string16 update.value;
//   string16 rejection_message
// The blueprint hash stamped on the wire is SHA-256 over EXACTLY these bytes.
// Worst case 77271 bytes; the cap lives in lineage.h
// (CRABS_BLUEPRINT_BODY_MAX) next to the wire cap layered on top of it.

// Fixed-capacity structured fields (dedup paths, rejection message) copied
// from hand-built structs may be filled to capacity with no NUL terminator —
// that has no reproducible canonical image and fails closed, mirroring the
// attestation body writer.
static bool _blueprint_dedup_field_write(uint8_t* out, size_t cap,
                                         size_t* offset, const char* field,
                                         size_t field_capacity) {
  if (strnlen(field, field_capacity) >= field_capacity) return false;
  return _lineage_string16_write(out, cap, offset, field, field_capacity);
}

static bool _blueprint_dedup_spec_write(uint8_t* out, size_t cap,
                                        size_t* offset,
                                        const dedup_spec_t* spec) {
  if (cap < *offset + 2) return false;
  out[(*offset)++] = (uint8_t)spec->type;
  bool written =
      _blueprint_dedup_field_write(out, cap, offset, spec->tracker_path,
                                   sizeof(spec->tracker_path)) &&
      _blueprint_dedup_field_write(out, cap, offset, spec->flag_path,
                                   sizeof(spec->flag_path)) &&
      _blueprint_dedup_field_write(out, cap, offset, spec->condition,
                                   sizeof(spec->condition));
  if (!written) return false;
  if (cap < *offset + 1) return false;
  out[(*offset)++] = (uint8_t)spec->update.type;
  written =
      _blueprint_dedup_field_write(out, cap, offset, spec->update.set_path,
                                   sizeof(spec->update.set_path)) &&
      _blueprint_dedup_field_write(out, cap, offset, spec->update.element_value,
                                   sizeof(spec->update.element_value)) &&
      _blueprint_dedup_field_write(out, cap, offset, spec->update.flag_path,
                                   sizeof(spec->update.flag_path)) &&
      _blueprint_dedup_field_write(out, cap, offset, spec->update.counter_path,
                                   sizeof(spec->update.counter_path));
  if (!written) return false;
  if (cap < *offset + 8) return false;
  _lineage_u64le_write(out + *offset, (uint64_t)spec->update.delta);
  *offset += 8;
  written =
      _blueprint_dedup_field_write(out, cap, offset, spec->update.target_path,
                                   sizeof(spec->update.target_path)) &&
      _blueprint_dedup_field_write(out, cap, offset, spec->update.value,
                                   sizeof(spec->update.value)) &&
      _blueprint_dedup_field_write(out, cap, offset, spec->rejection_message,
                                   sizeof(spec->rejection_message));
  return written;
}

static size_t _blueprint_write_body(const machine_blueprint_t* blueprint,
                                    uint8_t* out, size_t cap) {
  size_t offset = 0;
  if (cap < 1) return 0;
  // A hand-built struct may carry an out-of-range count or a NULL array —
  // the writer fails closed instead of dereferencing them.
  if (blueprint->item_count > CRABS_MAX_BLUEPRINT_ITEMS ||
      blueprint->policy_count > CRABS_MAX_BLUEPRINT_POLICIES ||
      blueprint->op_type_def_count > CRABS_MAX_BLUEPRINT_OP_TYPE_DEFS) {
    return 0;
  }
  if ((blueprint->item_count > 0 && blueprint->items == NULL) ||
      (blueprint->policy_count > 0 && blueprint->policies == NULL) ||
      (blueprint->op_type_def_count > 0 && blueprint->op_type_defs == NULL)) {
    return 0;
  }
  out[offset++] = (uint8_t)blueprint->trust_mode;
  if (!_lineage_string16_write(out, cap, &offset, blueprint->child_id,
                               sizeof(blueprint->child_id)) ||
      !_lineage_string16_write(out, cap, &offset, blueprint->bootstrap_admin,
                               sizeof(blueprint->bootstrap_admin))) {
    return 0;
  }
  if (cap < offset + 8) return 0;
  _lineage_u64le_write(out + offset, blueprint->attestation_ttl_ms);
  offset += 8;

  if (cap < offset + 4) return 0;
  _lineage_u32le_write(out + offset, blueprint->item_count);
  offset += 4;
  for (uint32_t item_index = 0; item_index < blueprint->item_count;
       item_index++) {
    const blueprint_item_t* item = &blueprint->items[item_index];
    if (!_lineage_string16_write(out, cap, &offset, item->name,
                                 sizeof(item->name))) {
      return 0;
    }
    if (cap < offset + 2) return 0;
    out[offset++] = (uint8_t)item->type;
    out[offset++] = (uint8_t)item->crdt_type;
  }

  if (cap < offset + 4) return 0;
  _lineage_u32le_write(out + offset, blueprint->policy_count);
  offset += 4;
  for (uint32_t policy_index = 0; policy_index < blueprint->policy_count;
       policy_index++) {
    const blueprint_policy_t* policy = &blueprint->policies[policy_index];
    if (!_lineage_string16_write(out, cap, &offset, policy->operation,
                                 sizeof(policy->operation)) ||
        !_lineage_string16_write(out, cap, &offset, policy->expression,
                                 sizeof(policy->expression))) {
      return 0;
    }
  }

  if (cap < offset + 4) return 0;
  _lineage_u32le_write(out + offset, blueprint->op_type_def_count);
  offset += 4;
  for (uint32_t def_index = 0; def_index < blueprint->op_type_def_count;
       def_index++) {
    const blueprint_op_type_def_t* definition =
        &blueprint->op_type_defs[def_index];
    if (!_lineage_string16_write(out, cap, &offset, definition->op_type,
                                 sizeof(definition->op_type)) ||
        !_blueprint_dedup_spec_write(out, cap, &offset, &definition->dedup)) {
      return 0;
    }
  }
  return offset;
}

crabs_error_e machine_blueprint_stamp_hash(machine_blueprint_t* blueprint) {
  if (blueprint == NULL) return CRABS_ERR_INVALID_PARAM;
  uint8_t body[CRABS_BLUEPRINT_BODY_MAX];
  size_t body_len = _blueprint_write_body(blueprint, body, sizeof(body));
  if (body_len == 0) return CRABS_ERR_INVALID_PARAM;
  return crypto_sha256(body, body_len, blueprint->blueprint_hash);
}

size_t blueprint_serialize(machine_blueprint_t* blueprint,
                           uint8_t* out_buf, size_t buf_len) {
  if (blueprint == NULL || out_buf == NULL) return 0;
  uint8_t body[CRABS_BLUEPRINT_BODY_MAX];
  size_t body_len = _blueprint_write_body(blueprint, body, sizeof(body));
  if (body_len == 0) return 0;
  // One body write serves both the image and the stamped hash — the hash is
  // always over the exact bytes serialized.
  if (crypto_sha256(body, body_len, blueprint->blueprint_hash) !=
      CRABS_SUCCESS) {
    return 0;
  }
  uint32_t total_len = (uint32_t)(body_len + CRABS_HASH_SIZE);
  if (buf_len < 4 + total_len) return 0;
  _lineage_u32le_write(out_buf, total_len);
  memcpy(out_buf + 4, body, body_len);
  memcpy(out_buf + 4 + body_len, blueprint->blueprint_hash, CRABS_HASH_SIZE);
  return 4 + total_len;
}

static bool _blueprint_dedup_field_read(const uint8_t* buf, size_t len,
                                        size_t* offset, char* out,
                                        size_t out_capacity) {
  return _lineage_string16_read(buf, len, offset, out, out_capacity);
}

static bool _blueprint_dedup_spec_read(const uint8_t* buf, size_t len,
                                       size_t* offset, dedup_spec_t* spec) {
  uint8_t raw_dedup_type;
  uint8_t raw_mutation_type;
  uint64_t raw_delta;
  bool strings_ok;
  if (*offset + 1 > len) return false;
  raw_dedup_type = buf[(*offset)++];
  strings_ok =
      _blueprint_dedup_field_read(buf, len, offset, spec->tracker_path,
                                  sizeof(spec->tracker_path)) &&
      _blueprint_dedup_field_read(buf, len, offset, spec->flag_path,
                                  sizeof(spec->flag_path)) &&
      _blueprint_dedup_field_read(buf, len, offset, spec->condition,
                                  sizeof(spec->condition));
  if (!strings_ok) return false;
  if (*offset + 1 > len) return false;
  raw_mutation_type = buf[(*offset)++];
  strings_ok =
      _blueprint_dedup_field_read(buf, len, offset, spec->update.set_path,
                                  sizeof(spec->update.set_path)) &&
      _blueprint_dedup_field_read(buf, len, offset, spec->update.element_value,
                                  sizeof(spec->update.element_value)) &&
      _blueprint_dedup_field_read(buf, len, offset, spec->update.flag_path,
                                  sizeof(spec->update.flag_path)) &&
      _blueprint_dedup_field_read(buf, len, offset, spec->update.counter_path,
                                  sizeof(spec->update.counter_path));
  if (!strings_ok) return false;
  if (!_lineage_u64le_read(buf, len, offset, &raw_delta)) return false;
  spec->update.delta = (int64_t)raw_delta;
  strings_ok =
      _blueprint_dedup_field_read(buf, len, offset, spec->update.target_path,
                                  sizeof(spec->update.target_path)) &&
      _blueprint_dedup_field_read(buf, len, offset, spec->update.value,
                                  sizeof(spec->update.value)) &&
      _blueprint_dedup_field_read(buf, len, offset, spec->rejection_message,
                                  sizeof(spec->rejection_message));
  if (!strings_ok) return false;
  spec->type = (dedup_type_e)raw_dedup_type;
  spec->update.type = (mutation_type_e)raw_mutation_type;
  return true;
}

machine_blueprint_t* blueprint_deserialize(const uint8_t* buf, size_t len) {
  if (buf == NULL) return NULL;
  size_t offset = 0;
  uint32_t total_len;
  uint32_t item_count = 0;
  uint32_t policy_count = 0;
  uint32_t def_count = 0;
  size_t body_len;
  machine_blueprint_t* blueprint = NULL;
  bool parsed;
  uint8_t stored_hash[CRABS_HASH_SIZE];
  uint8_t recomputed_hash[CRABS_HASH_SIZE];

  // The prefix must claim exactly the bytes that follow it, and the smallest
  // possible body (trust mode + two empty strings16 + ttl + three zero
  // counts) is 24 bytes before the hash.
  if (!_lineage_u32le_read(buf, len, &offset, &total_len) ||
      total_len != len - 4 ||
      total_len < 24 + CRABS_HASH_SIZE) {
    return NULL;
  }
  body_len = total_len - CRABS_HASH_SIZE;

  blueprint = get_clear_memory(sizeof(*blueprint));
  parsed = offset + 1 <= len;
  if (parsed) {
    blueprint->trust_mode = (lineage_trust_mode_e)buf[offset++];
    parsed = blueprint->trust_mode == LINEAGE_SHARED_ROOT ||
             blueprint->trust_mode == LINEAGE_DELEGATED_COPY ||
             blueprint->trust_mode == LINEAGE_SOVEREIGN;
  }
  parsed = parsed &&
      _lineage_string16_read(buf, len, &offset, blueprint->child_id,
                             sizeof(blueprint->child_id)) &&
      _lineage_string16_read(buf, len, &offset, blueprint->bootstrap_admin,
                             sizeof(blueprint->bootstrap_admin)) &&
      _lineage_u64le_read(buf, len, &offset, &blueprint->attestation_ttl_ms);

  parsed = parsed &&
      _lineage_u32le_read(buf, len, &offset, &item_count) &&
      item_count <= CRABS_MAX_BLUEPRINT_ITEMS;
  if (parsed && item_count > 0) {
    // get_clear_memory aborts on exhaustion — allocation never fails here.
    blueprint->items = get_clear_memory(
        (size_t)item_count * sizeof(blueprint_item_t));
    blueprint->item_count = item_count;
  }

  // The ITEM section (its count was just consumed).
  for (uint32_t item_index = 0; parsed && item_index < item_count;
       item_index++) {
    blueprint_item_t* item = &blueprint->items[item_index];
    uint8_t raw_item_type;
    uint8_t raw_crdt_type;
    parsed = _lineage_string16_read(buf, len, &offset, item->name,
                                    sizeof(item->name)) &&
             offset + 2 <= len;
    if (parsed) {
      raw_item_type = buf[offset++];
      raw_crdt_type = buf[offset++];
      item->type = (data_type_e)raw_item_type;
      item->crdt_type = (crdt_type_e)raw_crdt_type;
    }
  }

  parsed = parsed &&
      _lineage_u32le_read(buf, len, &offset, &policy_count) &&
      policy_count <= CRABS_MAX_BLUEPRINT_POLICIES;
  if (parsed && policy_count > 0) {
    blueprint->policies = get_clear_memory(
        (size_t)policy_count * sizeof(blueprint_policy_t));
    blueprint->policy_count = policy_count;
  }

  // The POLICY section (its count was just consumed).
  for (uint32_t policy_index = 0; parsed && policy_index < policy_count;
       policy_index++) {
    blueprint_policy_t* policy = &blueprint->policies[policy_index];
    parsed =
        _lineage_string16_read(buf, len, &offset, policy->operation,
                               sizeof(policy->operation)) &&
        _lineage_string16_read(buf, len, &offset, policy->expression,
                               sizeof(policy->expression));
  }

  parsed = parsed &&
      _lineage_u32le_read(buf, len, &offset, &def_count) &&
      def_count <= CRABS_MAX_BLUEPRINT_OP_TYPE_DEFS;
  if (parsed && def_count > 0) {
    blueprint->op_type_defs = get_clear_memory(
        (size_t)def_count * sizeof(blueprint_op_type_def_t));
    blueprint->op_type_def_count = def_count;
  }
  for (uint32_t def_index = 0; parsed && def_index < def_count; def_index++) {
    blueprint_op_type_def_t* definition = &blueprint->op_type_defs[def_index];
    parsed =
        _lineage_string16_read(buf, len, &offset, definition->op_type,
                               sizeof(definition->op_type)) &&
        _blueprint_dedup_spec_read(buf, len, &offset, &definition->dedup);
  }

  // Every field consumed EXACTLY the body; the hash closes the image.
  parsed = parsed && offset == body_len + 4;
  if (parsed) {
    memcpy(stored_hash, buf + offset, CRABS_HASH_SIZE);
    // Verify over the body ALONE — a tampered body can never reproduce the
    // stored hash, so any mismatch rejects the whole image.
    parsed = crypto_sha256(buf + 4, body_len, recomputed_hash) ==
                 CRABS_SUCCESS &&
             memcmp(recomputed_hash, stored_hash, CRABS_HASH_SIZE) == 0;
  }
  if (parsed) {
    memcpy(blueprint->blueprint_hash, stored_hash, CRABS_HASH_SIZE);
    return blueprint;
  }
  machine_blueprint_destroy(blueprint);
  return NULL;
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
// preprocess_policy) accepts three expression families:
//   1. full condition grammar expressions (AND/OR/NOT/CONTAINS/comparisons);
//   2. bare attribute tokens — the "name:value" family condition_parse
//      rejects because ':' is not in the condition identifier charset, and
//      which preprocess_policy then passes through verbatim as the ABE
//      policy;
//   3. `@parent/<attr>` endorsement tokens (v1.7 §attestation bridge) —
//      resolved out of the expression by preprocess_policy and verified in
//      the auth pipeline against the op's attestations. Valid only at
//      parenthesis depth 0 and with a well-formed attribute part, mirroring
//      preprocess_policy's fail-closed rules.
// To validate the boolean structure of ALL with one call, every bare
// attribute token — and every well-formed endorsement token — is rewritten
// into a placeholder comparison "aN == aN" before condition_parse. Quoted
// operands are rejected up front, mirroring preprocess_policy's fail-closed
// rule. An empty expression is valid (an op with no auth requirement —
// state_add_policy accepts the same).
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
  int paren_depth = 0;
  const char* cursor = expression;
  while (*cursor != '\0') {
    if (*cursor == '(') {
      paren_depth++;
    } else if (*cursor == ')') {
      if (paren_depth > 0) paren_depth--;
    }
    // Endorsement token: literal "@parent/" prefix at depth 0, non-empty
    // attribute run of the bare-attribute charset, no nested '@'. Rewritten
    // into the same placeholder comparison a colon token becomes, so the
    // boolean structure around it is still checked by condition_parse.
    if (*cursor == '@') {
      // An '@' glued to a preceding word is malformed (bare attribute tokens
      // never contain '@') — mirrors preprocess_policy's rule.
      if (paren_depth > 0 ||
          (cursor != expression && _char_in_identifier(cursor[-1]))) {
        return false;
      }
      if (strncmp(cursor, "@parent/", 8) != 0) return false;
      const char* attr_start = cursor + 8;
      const char* attr_end = attr_start;
      // The run stops at any non-identifier char; '@' is not one, so a
      // nested '@' terminates the run and is rejected below.
      while (_char_in_identifier(*attr_end)) {
        attr_end++;
      }
      if (attr_end == attr_start || *attr_end == '@') return false;
      int written = snprintf(transformed + write_pos,
                             sizeof(transformed) - write_pos,
                             "attr%d == attr%d ", token_index, token_index);
      if (written < 0 || (size_t)written >= sizeof(transformed) - write_pos) {
        return false;
      }
      write_pos += (size_t)written;
      token_index++;
      cursor = attr_end;
      continue;
    }
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

// ============================================================
// Spawn: the three trust modes
// ============================================================

// Runtime resident-child registry (state_t fields, UNOWNED views). Slots are
// index-ALIGNED with the manifest (both arrays only ever append at the tail
// and dissolve merely NULLs the slot), so a lookup resolves child_id through
// the manifest entry — the only owned data — and never dereferences a
// pointer slot that could dangle (a child destroyed by its owner out-of-band
// without a dissolve).

static attribute_machine_t* _lineage_find_resident_child(
    state_t* parent, const char* child_id) {
  for (uint32_t child_index = 0; child_index < parent->child_count;
       child_index++) {
    if (strcmp(parent->children[child_index].child_id, child_id) == 0 &&
        child_index < parent->resident_child_count) {
      return parent->resident_children[child_index];
    }
  }
  return NULL;
}

static void _lineage_drop_resident_child(state_t* parent,
                                         const char* child_id) {
  for (uint32_t child_index = 0;
       child_index < parent->child_count &&
       child_index < parent->resident_child_count;
       child_index++) {
    if (strcmp(parent->children[child_index].child_id, child_id) == 0) {
      parent->resident_children[child_index] = NULL;
      return;
    }
  }
}

// Spawn appends both arrays at the tail in the same order — manifest entry
// at child_count, registry slot at resident_child_count — keeping the index
// alignment the lookups above rely on.
static crabs_error_e _lineage_register_resident_child(
    state_t* parent, attribute_machine_t* child) {
  attribute_machine_t** grown = realloc(
      parent->resident_children,
      (size_t)(parent->resident_child_count + 1) * sizeof(attribute_machine_t*));
  if (grown == NULL) return CRABS_ERR_OOM;
  parent->resident_children = grown;
  parent->resident_children[parent->resident_child_count] = child;
  parent->resident_child_count += 1;
  return CRABS_SUCCESS;
}

// Apply the blueprint's items, policies, and op type definitions to the
// freshly built child state. Validation ran BEFORE any child allocation, so
// the only realistic failure here is a registry cap: the state's op type
// registry is the blueprint cap's own floor (CRABS_MAX_BLUEPRINT_OP_TYPE_DEFS
// <= CRABS_MAX_OP_TYPE_DEFS) and duplicate item names were checked across the
// whole blueprint — the child starts empty.
static crabs_error_e _spawn_apply_blueprint(state_t* child_state,
                                            const machine_blueprint_t* blueprint) {
  for (uint32_t item_index = 0; item_index < blueprint->item_count;
       item_index++) {
    const blueprint_item_t* item = &blueprint->items[item_index];
    // Genesis items are valueless shells: the blueprint carries name, type,
    // and CRDT strategy only (initial value is the empty CRDT, materialized
    // by the first authorized mutation).
    data_item_t* created = data_item_create(item->name, item->type,
                                            item->crdt_type);
    if (created == NULL) return CRABS_ERR_OOM;
    crabs_error_e status = state_add_item(child_state, created);
    if (status != CRABS_SUCCESS) {
      data_item_destroy(created);
      return status;
    }
  }
  for (uint32_t policy_index = 0; policy_index < blueprint->policy_count;
       policy_index++) {
    const blueprint_policy_t* policy = &blueprint->policies[policy_index];
    crabs_error_e status = state_add_policy(child_state, policy->operation,
                                            policy->expression);
    if (status != CRABS_SUCCESS) return status;
  }
  for (uint32_t def_index = 0; def_index < blueprint->op_type_def_count;
       def_index++) {
    const blueprint_op_type_def_t* definition =
        &blueprint->op_type_defs[def_index];
    crabs_error_e status = state_register_op_type_def(
        child_state, definition->op_type, &definition->dedup);
    if (status != CRABS_SUCCESS) return status;
  }
  return CRABS_SUCCESS;
}

crabs_error_e lineage_spawn_machine(state_t* parent,
                                    const machine_blueprint_t* blueprint,
                                    attribute_machine_t** child_out) {
  if (parent == NULL || blueprint == NULL || child_out == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  *child_out = NULL;

  crabs_error_e status = lineage_blueprint_validate(blueprint);
  if (status != CRABS_SUCCESS) return status;

  // Genesis provenance is a parent ECDSA signature — a machine that cannot
  // sign cannot mint.
  if (!parent->node_key_valid) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  // The manifest ceiling bounds the serialized manifest and the spawn
  // lookup cost. crabs.h carries no dedicated limit enumerator; CRABS_ERR_OOM
  // follows the per-state registry precedent (state_machine_register_handler
  // returns CRABS_ERR_OOM at CRABS_MAX_OP_HANDLERS).
  if (parent->child_count >= CRABS_MAX_CHILD_MACHINES) {
    return CRABS_ERR_OOM;
  }

  // child_id uniqueness: among the parent's live children AND against the
  // parent's OWN machine id (a child may itself mint — its lineage_self_id
  // occupies the same machine-name space; a machine that was never spawned
  // has no lineage_self_id yet, and its identity is the root machine's id,
  // config.bootstrap_admin).
  for (uint32_t child_index = 0; child_index < parent->child_count;
       child_index++) {
    if (strcmp(parent->children[child_index].child_id,
               blueprint->child_id) == 0) {
      return CRABS_ERR_DUPLICATE_OPERATION;
    }
  }
  if ((parent->lineage_self_id[0] != '\0' &&
       strcmp(parent->lineage_self_id, blueprint->child_id) == 0) ||
      (parent->config.bootstrap_admin[0] != '\0' &&
       strcmp(parent->config.bootstrap_admin, blueprint->child_id) == 0)) {
    return CRABS_ERR_DUPLICATE_OPERATION;
  }

  attribute_machine_t* child;
  state_t* child_state;
  if (blueprint->trust_mode == LINEAGE_SHARED_ROOT) {
    // Shared root: the child BORROWS the parent's authority — one attribute
    // machine (one user registry) and one MSK serve both states. Nothing is
    // re-enrolled; the genesis-equivalent step would be meaningless here.
    if (parent->attr_machine == NULL || parent->abe_mk == NULL) {
      return CRABS_ERR_INVALID_PARAM;
    }
    child = get_clear_memory(sizeof(*child));
    child_state = &child->base_state;
    // Embedded base_state never runs state_create's defaults — seed the
    // same defaults attribute_machine_create seeds for its machines.
    child_state->config.max_lock_duration_ms = CRABS_DEFAULT_LOCK_MS;
    child_state->config.max_lock_extensions = CRABS_MAX_LOCK_EXTENDS;
    child_state->config.allow_force_unlock = true;
    child_state->max_occurrences_per_tick =
        CRABS_SCHEDULER_DEFAULT_MAX_OCCURRENCES_PER_TICK;
    strncpy(child_state->config.bootstrap_admin, blueprint->bootstrap_admin,
            CRABS_MAX_USER_ID - 1);
    child_state->attr_machine = parent->attr_machine;
    child_state->abe_mk = parent->abe_mk;
    child_state->abe_mk_borrowed = true;
  } else {
    // DELEGATED_COPY / SOVEREIGN: a fresh authority is minted via the
    // genesis-equivalent construction (§8.3 — attribute_machine_create
    // registers the bootstrap admin with role:admin under `admin_pk`). The
    // admin's key is the PARENT's node public key: the machine that mints
    // the child vouches for its genesis admin, and only it holds the
    // matching private key at this point (the child's own node key is set
    // later, by whoever loads it).
    child = attribute_machine_create(blueprint->bootstrap_admin,
                                     parent->node_public_key);
    if (child == NULL) return CRABS_ERR_OOM;
    child_state = &child->base_state;
    // The child's auth pipeline resolves users through ITS OWN registry.
    child_state->attr_machine = child;
  }

  // Genesis bytes must carry the parent binding (v11 persists it in the same
  // parent-binding block), so the binding is stamped BEFORE the snapshot.
  child_state->lineage_parent_bound = true;
  strncpy(child_state->lineage_parent_id, parent->config.bootstrap_admin,
          CRABS_MAX_USER_ID - 1);
  memcpy(child_state->lineage_parent_public_key, parent->node_public_key, 33);
  strncpy(child_state->lineage_self_id, blueprint->child_id,
          CRABS_MAX_USER_ID - 1);

  status = _spawn_apply_blueprint(child_state, blueprint);
  if (status == CRABS_SUCCESS) {
    // Genesis snapshot: the canonical UNKEYED serialization (no sealed MSK
    // section — provenance is not authority-at-rest). The serializer embeds
    // the user registry the child's authority resolves through — for a
    // shared-root child that is the SHARED registry image, for a delegated
    // child the fresh genesis admin. Signed EXPLICITLY with the parent's
    // node key: the child shell has no node key of its own, so the
    // signed-serializer would fail closed.
    serialized_buffer_t* genesis_blob = crabs_serialize_state(child_state);
    if (genesis_blob == NULL) {
      status = CRABS_ERR_SERIALIZATION_ERROR;
    } else {
      uint8_t genesis_hash[CRABS_HASH_SIZE];
      uint8_t genesis_signature[CRABS_SIG_SIZE];
      status = crypto_sha256(genesis_blob->data, genesis_blob->len,
                             genesis_hash);
      if (status == CRABS_SUCCESS) {
        status = crypto_ecdsa_sign(parent->node_private_key,
                                   genesis_blob->data, genesis_blob->len,
                                   genesis_signature);
      }
      if (status == CRABS_SUCCESS) {
        // Runtime resident-child registry FIRST (fail-safe): a registry
        // failure here leaves the manifest unwritten and the child destroyed
        // below — no residue. UNOWNED pointer: the registry holds nothing
        // the caller does not own (see state_t.resident_children).
        status = _lineage_register_resident_child(parent, child);
      }
      if (status == CRABS_SUCCESS) {
        // Manifest append LAST — every earlier failure destroyed the child
        // and left the parent untouched (no partial residue).
        child_manifest_entry_t* grown = realloc(
            parent->children,
            (size_t)(parent->child_count + 1) * sizeof(child_manifest_entry_t));
        if (grown == NULL) {
          status = CRABS_ERR_OOM;
          // Roll back the registry slot appended just above — the child is
          // destroyed below and no residue may survive either array.
          parent->resident_child_count -= 1;
          parent->resident_children[parent->resident_child_count] = NULL;
        } else {
          parent->children = grown;
          child_manifest_entry_t* manifest_entry =
              &parent->children[parent->child_count];
          memset(manifest_entry, 0, sizeof(*manifest_entry));
          strncpy(manifest_entry->child_id, blueprint->child_id,
                  CRABS_MAX_USER_ID - 1);
          manifest_entry->mode = blueprint->trust_mode;
          memcpy(manifest_entry->genesis_snapshot_hash, genesis_hash,
                 CRABS_HASH_SIZE);
          memcpy(manifest_entry->genesis_attestation_signature,
                 genesis_signature, CRABS_SIG_SIZE);
          manifest_entry->attestation_ttl_ms = blueprint->attestation_ttl_ms;
          // The parent never reads the wall clock itself — spawn stamps the
          // manifest with the parent's HLC time source (state_get_time_ms;
          // 0 when the source reports no valid time — the default SYSTEM_
          // CLOCK source backs this with the unauthenticated platform clock,
          // so protocol authors needing authenticated spawn times configure
          // an authenticated source).
          if (!state_get_time_ms(parent, &manifest_entry->spawned_at)) {
            manifest_entry->spawned_at = 0;
          }
          manifest_entry->status = LINEAGE_ACTIVE;
          parent->child_count += 1;

          state_notify_change(parent, CRABS_CHANGE_SPAWN,
                              CRABS_LINEAGE_OP_SPAWN, NULL, NULL, NULL,
                              blueprint->child_id, "machine spawned", CRABS_SUCCESS);
          *child_out = child;
        }
      }
      serialized_buffer_destroy(genesis_blob);
    }
  }
  if (status != CRABS_SUCCESS) {
    attribute_machine_destroy(child);
  }
  return status;
}

// ============================================================
// Lineage ops: spawn / revoke attestation / dissolve / withdraw
// ============================================================

// Handlers run POST-authorization (dispatched by state_machine_execute after
// the op's signature + policy check passed) — they re-verify nothing about
// the caller. The parent manifest / trust-mode refusals use
// CRABS_ERR_UNAUTHORIZED and CRABS_ERR_ALREADY_PERFORMED: crabs.h has no
// dedicated NOT_PERMITTED enumerator (see lineage.h).

// Revoke / dissolve / withdraw carry the same payload shape: the raw
// child_id string (NUL-terminated, safe id charset). A payload that cannot
// be a safe id is structural garbage → CRABS_ERR_INVALID_PARAM.
static crabs_error_e _lineage_child_id_from_payload(const operation_t* op,
                                                    char* child_id_out,
                                                    size_t out_capacity) {
  if (op == NULL || op->payload == NULL ||
      out_capacity > CRABS_MAX_USER_ID) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // payload_size < out_capacity so the copy leaves room for the NUL.
  if (op->payload_size == 0 || op->payload_size >= out_capacity) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (memchr(op->payload, '\0', op->payload_size) != NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  memcpy(child_id_out, op->payload, op->payload_size);
  child_id_out[op->payload_size] = '\0';
  if (!attribute_machine_is_safe_user_id(child_id_out)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  return CRABS_SUCCESS;
}

attribute_machine_t* lineage_query_resident_child(const state_t* state,
                                                  const char* child_id) {
  if (state == NULL || child_id == NULL) return NULL;
  // Resolve the child_id through the manifest entry — the only owned data.
  // The registry slots are index-ALIGNED with the manifest (see the spawn
  // helpers above), so the winning manifest index addresses the registry
  // slot directly; a NULL slot means the child dissolved (or was dropped by
  // its owner out-of-band) and answers NULL.
  for (uint32_t child_index = 0; child_index < state->child_count;
       child_index++) {
    if (strcmp(state->children[child_index].child_id, child_id) != 0) {
      continue;
    }
    if (child_index >= state->resident_child_count ||
        state->resident_children == NULL) {
      return NULL;
    }
    return state->resident_children[child_index];
  }
  return NULL;
}

uint32_t lineage_query_children(const state_t* state,
                                const child_manifest_entry_t** out_entries) {
  if (state == NULL || out_entries == NULL) return 0;
  // Borrowed view: the state owns the array (state_destroy frees it); the
  // caller never gets ownership. NULL when the machine never spawned.
  *out_entries = state->children;
  return state->child_count;
}

child_manifest_entry_t* lineage_find_manifest_entry(const state_t* state,
                                                    const char* child_id) {
  if (state == NULL || child_id == NULL) return NULL;
  // Borrowed pointer into the state-owned manifest array; entries of every
  // status resolve — the caller interprets the status byte.
  for (uint32_t child_index = 0; child_index < state->child_count;
       child_index++) {
    if (strcmp(state->children[child_index].child_id, child_id) == 0) {
      return &state->children[child_index];
    }
  }
  return NULL;
}

// ============================================================
// Enum name helpers (single source for CLI / wasm / devtools)
// ============================================================

const char* lineage_mode_name(lineage_trust_mode_e mode) {
  switch (mode) {
    case LINEAGE_SHARED_ROOT:    return "shared_root";
    case LINEAGE_DELEGATED_COPY: return "delegated_copy";
    case LINEAGE_SOVEREIGN:      return "sovereign";
    default:                     return "unknown";
  }
}

const char* lineage_status_name(lineage_status_e status) {
  switch (status) {
    case LINEAGE_ACTIVE:              return "active";
    case LINEAGE_DISSOLVED:           return "dissolved";
    case LINEAGE_WITHDRAWN:           return "withdrawn";
    case LINEAGE_ATTESTATION_REVOKED: return "attestation_revoked";
    default:                          return "unknown";
  }
}

crabs_error_e lineage_op_spawn(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL || op->payload == NULL ||
      op->payload_size == 0) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // Malformed wire image or hash mismatch → the blueprint never parsed.
  machine_blueprint_t* blueprint =
      blueprint_deserialize(op->payload, op->payload_size);
  if (blueprint == NULL) return CRABS_ERR_INVALID_PARAM;
  attribute_machine_t* child = NULL;
  crabs_error_e status = lineage_spawn_machine(state, blueprint, &child);
  machine_blueprint_destroy(blueprint);
  // Ownership note: the caller of the OP pipeline never sees `child` — spawn
  // registered it in the runtime resident-children registry so a later
  // dissolve can reach it (and protocol code may hold the pointer itself).
  return status;
}

crabs_error_e lineage_op_revoke_attestation(state_t* state, operation_t* op) {
  char child_id[CRABS_MAX_USER_ID];
  crabs_error_e status = _lineage_child_id_from_payload(
      op, child_id, sizeof(child_id));
  if (status != CRABS_SUCCESS) return status;
  if (state == NULL) return CRABS_ERR_INVALID_PARAM;

  child_manifest_entry_t* manifest_entry =
      lineage_find_manifest_entry(state, child_id);
  if (manifest_entry == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
  if (manifest_entry->status == LINEAGE_ATTESTATION_REVOKED) {
    return CRABS_ERR_ALREADY_PERFORMED;
  }
  // Only an ACTIVE child has live attestations to stop issuing.
  if (manifest_entry->status != LINEAGE_ACTIVE) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  manifest_entry->status = LINEAGE_ATTESTATION_REVOKED;
  state_notify_change(state, CRABS_CHANGE_LINEAGE,
                      CRABS_LINEAGE_OP_REVOKE_ATTESTATION, NULL, NULL, NULL,
                      child_id, "attestation issuing revoked", CRABS_SUCCESS);
  return CRABS_SUCCESS;
}

crabs_error_e lineage_op_dissolve(state_t* state, operation_t* op) {
  char child_id[CRABS_MAX_USER_ID];
  crabs_error_e status = _lineage_child_id_from_payload(
      op, child_id, sizeof(child_id));
  if (status != CRABS_SUCCESS) return status;
  if (state == NULL) return CRABS_ERR_INVALID_PARAM;

  child_manifest_entry_t* manifest_entry =
      lineage_find_manifest_entry(state, child_id);
  if (manifest_entry == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
  if (manifest_entry->status == LINEAGE_DISSOLVED) {
    return CRABS_ERR_ALREADY_PERFORMED;
  }
  // Sovereign children cannot be dissolved — the parent may only withdraw
  // its genesis stake. Any non-ACTIVE entry is past its lifecycle too.
  if (manifest_entry->mode == LINEAGE_SOVEREIGN ||
      manifest_entry->status != LINEAGE_ACTIVE) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  manifest_entry->status = LINEAGE_DISSOLVED;

  // In-process severance: the resident child (if any) loses every @parent/
  // endorsement IMMEDIATELY — its auth pipeline fails closed on
  // lineage_parent_dissolved — and it leaves the registry (the child itself
  // is NOT destroyed; it outlives the dissolution).
  attribute_machine_t* resident = _lineage_find_resident_child(state, child_id);
  if (resident != NULL) {
    resident->base_state.lineage_parent_dissolved = true;
  }
  _lineage_drop_resident_child(state, child_id);
  state_notify_change(state, CRABS_CHANGE_LINEAGE, CRABS_LINEAGE_OP_DISSOLVE,
                      NULL, NULL, NULL, child_id, "dissolved", CRABS_SUCCESS);
  return CRABS_SUCCESS;
}

crabs_error_e lineage_op_withdraw_genesis(state_t* state, operation_t* op) {
  char child_id[CRABS_MAX_USER_ID];
  crabs_error_e status = _lineage_child_id_from_payload(
      op, child_id, sizeof(child_id));
  if (status != CRABS_SUCCESS) return status;
  if (state == NULL) return CRABS_ERR_INVALID_PARAM;

  child_manifest_entry_t* manifest_entry =
      lineage_find_manifest_entry(state, child_id);
  if (manifest_entry == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
  // Sovereign ONLY: the genesis stake recoverable by withdrawal exists only
  // where the child self-mints (LINEAGE_SOVEREIGN). Non-sovereign children
  // end through lineage_op_dissolve instead.
  if (manifest_entry->mode != LINEAGE_SOVEREIGN) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  if (manifest_entry->status == LINEAGE_WITHDRAWN) {
    return CRABS_ERR_ALREADY_PERFORMED;
  }
  if (manifest_entry->status != LINEAGE_ACTIVE) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  manifest_entry->status = LINEAGE_WITHDRAWN;
  state_notify_change(state, CRABS_CHANGE_LINEAGE,
                      CRABS_LINEAGE_OP_WITHDRAW_GENESIS, NULL, NULL, NULL,
                      child_id, "genesis attested chain withdrawn",
                      CRABS_SUCCESS);
  return CRABS_SUCCESS;
}

void lineage_install(state_t* state) {
  if (state == NULL) return;
  dedup_spec_t no_dedup;
  memset(&no_dedup, 0, sizeof(no_dedup));
  no_dedup.type = DEDUP_NONE;

  // Idempotent by construction: every registration path updates in place
  // when the name already exists (state_register_op_type_def /
  // state_add_policy / state_machine_register_handler all do). Return values
  // are deliberately ignored — registration only fails at the registry caps
  // (CRABS_MAX_OP_HANDLERS / CRABS_MAX_OP_TYPE_DEFS), where a silently
  // missing lineage handler simply makes the op unauthorized, and a
  // protocol wanting hard guarantees registers the pieces itself.
  state_register_op_type_def(state, CRABS_LINEAGE_OP_SPAWN, &no_dedup);
  state_register_op_type_def(state, CRABS_LINEAGE_OP_REVOKE_ATTESTATION,
                             &no_dedup);
  state_register_op_type_def(state, CRABS_LINEAGE_OP_DISSOLVE, &no_dedup);
  state_register_op_type_def(state, CRABS_LINEAGE_OP_WITHDRAW_GENESIS,
                             &no_dedup);
  state_add_policy(state, CRABS_LINEAGE_OP_SPAWN, "role:admin");
  state_add_policy(state, CRABS_LINEAGE_OP_REVOKE_ATTESTATION, "role:admin");
  state_add_policy(state, CRABS_LINEAGE_OP_DISSOLVE, "role:admin");
  state_add_policy(state, CRABS_LINEAGE_OP_WITHDRAW_GENESIS, "role:admin");
  state_machine_register_handler(state, CRABS_LINEAGE_OP_SPAWN,
                                 lineage_op_spawn);
  state_machine_register_handler(state, CRABS_LINEAGE_OP_REVOKE_ATTESTATION,
                                 lineage_op_revoke_attestation);
  state_machine_register_handler(state, CRABS_LINEAGE_OP_DISSOLVE,
                                 lineage_op_dissolve);
  state_machine_register_handler(state, CRABS_LINEAGE_OP_WITHDRAW_GENESIS,
                                 lineage_op_withdraw_genesis);
}

// Off-chain dissolution proof: ECDSA over the canonical tombstone
// `u8 tag (= LINEAGE_DISSOLVED) + string16 child_id`. Verifiable by any
// third party holding the parent's node public key — no manifest needed.
// Worst case 1 + 2 + CRABS_MAX_USER_ID = 67 bytes.
crabs_error_e lineage_sign_dissolution(state_t* parent, const char* child_id,
                                       uint8_t signature_out[CRABS_SIG_SIZE]) {
  if (parent == NULL || child_id == NULL || signature_out == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (!attribute_machine_is_safe_user_id(child_id)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  const child_manifest_entry_t* manifest_entry =
      lineage_find_manifest_entry(parent, child_id);
  if (manifest_entry == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
  // Honesty gate: a tombstone proves a dissolution — never sign one for a
  // child that is not dissolved.
  if (manifest_entry->status != LINEAGE_DISSOLVED) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  if (!parent->node_key_valid) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;

  uint8_t tombstone[1 + 2 + CRABS_MAX_USER_ID];
  size_t offset = 0;
  tombstone[offset++] = (uint8_t)LINEAGE_DISSOLVED;
  if (!_lineage_string16_write(tombstone, sizeof(tombstone), &offset,
                               child_id, strlen(child_id) + 1)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (crypto_ecdsa_sign(parent->node_private_key, tombstone, offset,
                        signature_out) != CRABS_SUCCESS) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  return CRABS_SUCCESS;
}

// Manifest-backed attestation issuance convenience (see lineage.h).
crabs_error_e crabs_issue_attestation(state_t* parent,
                                      attestation_t* attestation_out,
                                      const char* child_id,
                                      const char* user_id,
                                      const char* attributes,
                                      uint64_t now_ms) {
  if (parent == NULL || attestation_out == NULL) return CRABS_ERR_INVALID_PARAM;
  const child_manifest_entry_t* manifest_entry =
      lineage_find_manifest_entry(parent, child_id);
  if (manifest_entry == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
  // Only an ACTIVE child carries live attestation authority — a revoked,
  // dissolved, or withdrawn lineage stops issuing (existing attestations
  // from before the change run out their remaining TTL on their own).
  if (manifest_entry->status != LINEAGE_ACTIVE) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  // Saturate-check the ttl addition: a wrap would mint an attestation with
  // a PAST expiry (silent zero-window) instead of failing.
  if (manifest_entry->attestation_ttl_ms > UINT64_MAX - now_ms) {
    return CRABS_ERR_INVALID_PARAM;
  }
  return attestation_create(parent, attestation_out,
                            parent->config.bootstrap_admin, child_id,
                            user_id, attributes, now_ms,
                            now_ms + manifest_entry->attestation_ttl_ms);
}
