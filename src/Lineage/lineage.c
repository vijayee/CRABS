//
// Lineage (v1.7: machines mint machines) — blueprint data layer:
// create/destroy, append helpers, and full structural validation, plus the
// lineage ops (__spawn_machine__ / __revoke_attestation__ /
// __dissolve_machine__ / __withdraw_genesis__ / __receive_dissolution__ /
// __parent_key_update__) registered on a machine by lineage_install.
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

bool attestation_verify_by_lineage_key(const state_t* child_state,
                                       const attestation_t* attestation,
                                       uint64_t now_ms) {
  if (child_state == NULL || attestation == NULL) return false;
  // Unbound or never-chain-stamped: no accepted parent authority exists, so
  // nothing can verify (fail closed — mirrors lineage_verify_by_parent_key).
  if (!child_state->lineage_parent_bound) return false;
  // The canonical check's child_id is THIS machine's lineage identity: any
  // chain entry may have signed, but the attestation must still name this
  // machine (attestation_verify's strcmp gate).
  for (uint32_t chain_index = 0;
       chain_index < child_state->lineage_key_chain_count; chain_index++) {
    if (attestation_verify(child_state->lineage_key_chain[chain_index]
                               .public_key,
                           child_state->lineage_self_id, attestation,
                           now_ms)) {
      return true;
    }
  }
  return false;
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

// Wire enum whitelists (A10-L2). Raw bytes arriving over the wire (or from a
// hand-built struct) are cast to enum types in a handful of places; anything
// outside the enum's defined range must be rejected BEFORE the cast, or an
// admin-signed __spawn_machine__ blueprint could plant an unrecognized enum
// in a child's state. Both the deserializer below and the struct-level
// lineage_blueprint_validate fail closed against these lists.
static bool _lineage_enum_valid_data_type(uint8_t raw) {
  switch ((data_type_e)raw) {
    case DATA_TYPE_COUNTER:
    case DATA_TYPE_PN_COUNTER:
    case DATA_TYPE_SET:
    case DATA_TYPE_2P_SET:
    case DATA_TYPE_REGISTER:
    case DATA_TYPE_DOCUMENT:
    case DATA_TYPE_RESOURCE:
    case DATA_TYPE_ONE_SHOT_SET:
    case DATA_TYPE_ONE_SHOT_FLAG:
    case DATA_TYPE_OT_ORDERED_SET:
    case DATA_TYPE_OT_DOCUMENT:
    case DATA_TYPE_OT_TABLE:
    case DATA_TYPE_OT_TREE:
    case DATA_TYPE_OT_ORDERED_MAP:
    case DATA_TYPE_CUSTOM:
      return true;
    default:
      return false;
  }
}

static bool _lineage_enum_valid_crdt_type(uint8_t raw) {
  switch ((crdt_type_e)raw) {
    case CRDT_G_COUNTER:
    case CRDT_PN_COUNTER:
    case CRDT_OR_SET:
    case CRDT_2P_SET:
    case CRDT_LWW_REG:
    case CRDT_RGA:
    case CRDT_ONE_SHOT_SET:
    case CRDT_ONE_SHOT_FLAG:
    case CRDT_CUSTOM:
      return true;
    default:
      return false;
  }
}

static bool _lineage_enum_valid_dedup_type(uint8_t raw) {
  switch ((dedup_type_e)raw) {
    case DEDUP_NONE:
    case DEDUP_PER_USER:
    case DEDUP_GLOBAL:
    case DEDUP_CUSTOM:
      return true;
    default:
      return false;
  }
}

static bool _lineage_enum_valid_mutation_type(uint8_t raw) {
  switch ((mutation_type_e)raw) {
    case MUTATION_SET_ADD:
    case MUTATION_FLAG_SET:
    case MUTATION_COUNTER_INCREMENT:
    case MUTATION_ASSIGN:
    case MUTATION_CUSTOM:
      return true;
    default:
      return false;
  }
}

// Returns false on ANY malformed input (truncated fields, capacity overflow,
// out-of-range enum bytes). No dedicated error channel: the sole caller
// (blueprint_deserialize) folds the failure into its `parsed` flag and
// destroys the partially filled blueprint, so no partial state escapes.
static bool _blueprint_dedup_spec_read(const uint8_t* buf, size_t len,
                                       size_t* offset, dedup_spec_t* spec) {
  uint8_t raw_dedup_type;
  uint8_t raw_mutation_type;
  uint64_t raw_delta;
  bool strings_ok;
  if (*offset + 1 > len) return false;
  raw_dedup_type = buf[(*offset)++];
  if (!_lineage_enum_valid_dedup_type(raw_dedup_type)) return false;
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
  // update.type is consumed ONLY under DEDUP_CUSTOM (dedup.c switches on the
  // dedup type first and never reaches the mutation switch otherwise), so the
  // byte is inert for DEDUP_NONE/PER_USER/GLOBAL — existing images carry a
  // memset 0x00 there and must keep loading. The whitelist is therefore
  // enforced exactly where the value would reach a mutation switch.
  if ((dedup_type_e)raw_dedup_type == DEDUP_CUSTOM &&
      !_lineage_enum_valid_mutation_type(raw_mutation_type)) {
    return false;
  }
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
    // The two enum bytes are whitelisted BEFORE the offset advances past them
    // or the type fields are cast/assigned — and any earlier stop on a bad
    // byte leaves parsed=false, so the partially read blueprint is destroyed
    // below with no partial state escaping (A10-L2).
    parsed = _lineage_string16_read(buf, len, &offset, item->name,
                                    sizeof(item->name)) &&
             offset + 2 <= len &&
             _lineage_enum_valid_data_type(buf[offset]) &&
             _lineage_enum_valid_crdt_type(buf[offset + 1]);
    if (parsed) {
      item->type = (data_type_e)buf[offset++];
      item->crdt_type = (crdt_type_e)buf[offset++];
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
    // NOTE: the hash is an integrity check recomputed at serialize time; a
    // deliberate tamperer can re-stamp it. Provenance/authenticity comes from
    // the signed __spawn_machine__ op, not from this hash.
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
  // A hand-built struct with count>0 but a NULL section array must fail
  // closed here rather than dereference below — the deserializer can never
  // produce this shape; only a direct caller can (mirrors the writer's
  // guard in _blueprint_write_body).
  if ((blueprint->item_count > 0 && blueprint->items == NULL) ||
      (blueprint->policy_count > 0 && blueprint->policies == NULL) ||
      (blueprint->op_type_def_count > 0 && blueprint->op_type_defs == NULL)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  for (uint32_t item_index = 0; item_index < blueprint->item_count;
       item_index++) {
    const blueprint_item_t* item = &blueprint->items[item_index];
    if (!_blueprint_id_field_is_safe(item->name, sizeof(item->name))) {
      return CRABS_ERR_INVALID_PARAM;
    }
    // Enum whitelists (A10-L2): hand-built structs reach spawn without ever
    // touching the deserializer, so the same range checks run here too.
    if (!_lineage_enum_valid_data_type((uint8_t)item->type) ||
        !_lineage_enum_valid_crdt_type((uint8_t)item->crdt_type)) {
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
    const blueprint_op_type_def_t* definition =
        &blueprint->op_type_defs[def_index];
    if (!_blueprint_id_field_is_safe(definition->op_type,
                                     sizeof(definition->op_type))) {
      return CRABS_ERR_INVALID_PARAM;
    }
    // Enum whitelists (A10-L2): same defense-in-depth as the item checks.
    // update.type is enforced only under DEDUP_CUSTOM (the sole consumer —
    // mirrors the deserializer); elsewhere the byte is inert.
    if (!_lineage_enum_valid_dedup_type((uint8_t)definition->dedup.type) ||
        (definition->dedup.type == DEDUP_CUSTOM &&
         !_lineage_enum_valid_mutation_type(
             (uint8_t)definition->dedup.update.type))) {
      return CRABS_ERR_INVALID_PARAM;
    }
  }
  return CRABS_SUCCESS;
}

// ============================================================
// Spawn: the three trust modes
// ============================================================

// Runtime resident-child registry (state_t fields, UNOWNED views). A10-5:
// registry entries are matched by the child's lineage_self_id, NOT by
// manifest position — the manifest is persisted across a restart while the
// runtime registry starts empty, so positional alignment between the two
// arrays is a fiction (a post-restart spawn lands in registry slot 0 while
// its manifest entry sits at whatever index the reload left). NULL slots
// are holes (dissolved children) and are skipped. The manifest index is
// only used to find the manifest ENTRY (status etc.) — never to index the
// registry.
//
// A10-6 liveness invariant: every NON-NULL slot points at a LIVE machine.
// The child's weak lineage_owner_state back-pointer and its registry slot
// are paired: registration sets both, and EVERY removal path clears both —
// __dissolve_machine__ (severance), lineage_resident_child_destroyed (the
// attribute_machine_destroy hook, when the child dies first), and
// lineage_detach_resident_children (when the owner state dies first). The
// strcmp lookups below can therefore never read freed memory.

static attribute_machine_t* _lineage_find_resident_child(
    const state_t* parent, const char* child_id) {
  if (parent == NULL || child_id == NULL || parent->resident_children == NULL) {
    return NULL;
  }
  for (uint32_t slot_index = 0; slot_index < parent->resident_child_count;
       slot_index++) {
    attribute_machine_t* child = parent->resident_children[slot_index];
    if (child == NULL) continue;
    if (strcmp(child->base_state.lineage_self_id, child_id) == 0) {
      return child;
    }
  }
  return NULL;
}

static void _lineage_drop_resident_child(state_t* parent,
                                         const char* child_id) {
  if (parent == NULL || child_id == NULL ||
      parent->resident_children == NULL) {
    return;
  }
  for (uint32_t slot_index = 0; slot_index < parent->resident_child_count;
       slot_index++) {
    attribute_machine_t* child = parent->resident_children[slot_index];
    if (child == NULL) continue;
    if (strcmp(child->base_state.lineage_self_id, child_id) == 0) {
      parent->resident_children[slot_index] = NULL;
      return;
    }
  }
}

// Spawn appends the registry at the tail (slot resident_child_count). No
// positional relationship with the manifest entry is required or relied on —
// the lookups above key off lineage_self_id. A10-6: registration also sets
// the child's weak lineage_owner_state back-pointer (paired with the slot);
// a machine already resident somewhere else is a double-registration bug —
// refuse it rather than leak the old owner's slot as a dangling entry.
static crabs_error_e _lineage_register_resident_child(
    state_t* parent, attribute_machine_t* child) {
  if (child->lineage_owner_state != NULL) return CRABS_ERR_INVALID_PARAM;
  attribute_machine_t** grown = realloc(
      parent->resident_children,
      (size_t)(parent->resident_child_count + 1) * sizeof(attribute_machine_t*));
  if (grown == NULL) return CRABS_ERR_OOM;
  parent->resident_children = grown;
  parent->resident_children[parent->resident_child_count] = child;
  parent->resident_child_count += 1;
  child->lineage_owner_state = parent;
  return CRABS_SUCCESS;
}

void lineage_resident_child_destroyed(attribute_machine_t* child) {
  if (child == NULL || child->lineage_owner_state == NULL) return;
  state_t* owner = child->lineage_owner_state;
  // NULL the back-pointer FIRST: the machine is provably detached before the
  // owner's registry is touched, and a slot drop that (hypothetically)
  // re-entered this hook on the same machine would terminate instead of
  // looping.
  child->lineage_owner_state = NULL;
  _lineage_drop_resident_child(owner, child->base_state.lineage_self_id);
}

void lineage_detach_resident_children(state_t* owner) {
  if (owner == NULL || owner->resident_children == NULL) return;
  // The owner state is dying: NULL every resident child's back-pointer. The
  // caller frees the pointer array right after this returns; any child that
  // outlives the owner must not carry a dangling reference into the dead
  // parent's registry (its later destroy would otherwise write-after-free).
  for (uint32_t slot_index = 0; slot_index < owner->resident_child_count;
       slot_index++) {
    attribute_machine_t* child = owner->resident_children[slot_index];
    if (child != NULL) child->lineage_owner_state = NULL;
  }
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
  // A10-M6: chain entry [0] is the spawn pin — the parent's CURRENT node key
  // is the first accepted parent authority. Stamped at binding time so the
  // chain-aware verification surfaces (endorsements, tombstones) work from
  // genesis; __parent_key_update__ advances it forward-only from here. The
  // v12 genesis serialization predates the chain (v13 persists it), so this
  // allocation affects no signed bytes.
  child_state->lineage_key_chain =
      get_clear_memory(sizeof(lineage_key_chain_entry_t));
  if (child_state->lineage_key_chain == NULL) {
    // No manifest/registry residue exists yet — destroying the child is the
    // whole cleanup (same failure shape as _spawn_apply_blueprint failures).
    attribute_machine_destroy(child);
    return CRABS_ERR_OOM;
  }
  child_state->lineage_key_chain[0].key_version =
      CRABS_LINEAGE_KEY_VERSION_START;
  memcpy(child_state->lineage_key_chain[0].public_key,
         parent->node_public_key, 33);
  child_state->lineage_key_chain_count = 1;

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
          // destroyed below and no residue may survive either array. Also
          // detach the back-pointer: the child destroy below runs the A10-6
          // hook, which would scan for an id whose slot just popped (a waste,
          // though harmless, while the back-pointer still names this parent).
          parent->resident_child_count -= 1;
          parent->resident_children[parent->resident_child_count] = NULL;
          child->lineage_owner_state = NULL;
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

          // Attribute the spawn to the parent's node identity (same HLC-id
          // idiom as the scheduler's change events): per-node devtools
          // drains and node.on('change') dispatch both filter by the node
          // field, so an un-attributed spawn event reaches no observer.
          const char* parent_node_id = parent->hlc_state_initialized
              ? parent->hlc_state.last.node_id
              : parent->config.bootstrap_admin;
          state_notify_change(parent, CRABS_CHANGE_SPAWN,
                              CRABS_LINEAGE_OP_SPAWN, NULL, NULL,
                              parent_node_id, blueprint->child_id,
                              "machine spawned", CRABS_SUCCESS);
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
// Lineage ops: spawn / revoke attestation / dissolve / withdraw /
// receive dissolution
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
  // A10-5: keyed by lineage_self_id over the registry, never by manifest
  // position — after a restart the manifest persists while the registry
  // starts empty, so only ids spawned in THIS process resolve.
  return _lineage_find_resident_child(state, child_id);
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

crabs_error_e lineage_verify_child_provenance(const state_t* parent_state,
                                              const char* child_id) {
  if (parent_state == NULL || child_id == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  const child_manifest_entry_t* manifest_entry =
      lineage_find_manifest_entry(parent_state, child_id);
  if (manifest_entry == NULL) {
    return CRABS_ERR_RESOURCE_NOT_FOUND;
  }
  // A parent without a node key never spawned — a manifest entry it cannot
  // have authored is treated as corrupt, not merely unverifiable (spawn
  // itself refuses keyless parents, so reaching this means the key material
  // or the entry was tampered after the fact).
  if (!parent_state->node_key_valid) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  // The stored hash IS the ECDSA digest (see the header contract): the
  // digest-level verify proves the parent's node key attested exactly this
  // genesis hash at spawn, without needing the (unrecoverable) blob.
  return crypto_ecdsa_verify_digest(
             parent_state->node_public_key,
             manifest_entry->genesis_snapshot_hash,
             manifest_entry->genesis_attestation_signature)
             ? CRABS_SUCCESS
             : CRABS_ERR_CRYPTOGRAPHIC_ERROR;
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
  // Attribute via the op (signer/node/uuid) like the other lineage lifecycle
  // events — per-node devtools drains and node.on('change') dispatch both
  // filter by the node field.
  state_notify_change(state, CRABS_CHANGE_LINEAGE,
                      CRABS_LINEAGE_OP_REVOKE_ATTESTATION, op->uuid,
                      op->signer_id, op->node_id, child_id,
                      "attestation issuing revoked", CRABS_SUCCESS);
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
    // A10-6: detach the back-pointer BEFORE dropping the slot — the child
    // may outlive this machine, and its post-dissolution destroy must not
    // walk back into the (possibly dead) parent's registry. Slot + back-
    // pointer are cleared as a pair (the registry liveness invariant).
    resident->lineage_owner_state = NULL;
    _lineage_drop_resident_child(state, child_id);
  }
  state_notify_change(state, CRABS_CHANGE_LINEAGE, CRABS_LINEAGE_OP_DISSOLVE,
                      op->uuid, op->signer_id, op->node_id, child_id,
                      "dissolved", CRABS_SUCCESS);
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
                      CRABS_LINEAGE_OP_WITHDRAW_GENESIS, op->uuid,
                      op->signer_id, op->node_id, child_id,
                      "genesis attested chain withdrawn",
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
  state_register_op_type_def(state, CRABS_LINEAGE_OP_RECEIVE_DISSOLUTION,
                             &no_dedup);
  state_register_op_type_def(state, CRABS_LINEAGE_OP_PARENT_KEY_UPDATE,
                             &no_dedup);
  state_add_policy(state, CRABS_LINEAGE_OP_SPAWN, "role:admin");
  state_add_policy(state, CRABS_LINEAGE_OP_REVOKE_ATTESTATION, "role:admin");
  state_add_policy(state, CRABS_LINEAGE_OP_DISSOLVE, "role:admin");
  state_add_policy(state, CRABS_LINEAGE_OP_WITHDRAW_GENESIS, "role:admin");
  state_add_policy(state, CRABS_LINEAGE_OP_RECEIVE_DISSOLUTION, "role:admin");
  state_add_policy(state, CRABS_LINEAGE_OP_PARENT_KEY_UPDATE, "role:admin");
  state_machine_register_handler(state, CRABS_LINEAGE_OP_SPAWN,
                                 lineage_op_spawn);
  state_machine_register_handler(state, CRABS_LINEAGE_OP_REVOKE_ATTESTATION,
                                 lineage_op_revoke_attestation);
  state_machine_register_handler(state, CRABS_LINEAGE_OP_DISSOLVE,
                                 lineage_op_dissolve);
  state_machine_register_handler(state, CRABS_LINEAGE_OP_WITHDRAW_GENESIS,
                                 lineage_op_withdraw_genesis);
  state_machine_register_handler(state, CRABS_LINEAGE_OP_RECEIVE_DISSOLUTION,
                                 lineage_op_receive_dissolution);
  state_machine_register_handler(state, CRABS_LINEAGE_OP_PARENT_KEY_UPDATE,
                                 lineage_op_parent_key_update);
}

// Canonical tombstone body: `u8 tag (= LINEAGE_DISSOLVED) + string16
// child_id` (string length EXCLUDES the NUL). Sole writer for the signing
// surfaces — lineage_sign_dissolution signs it and
// lineage_dissolution_serialize appends the signature to it; the delivery
// op lineage_op_receive_dissolution only PARSES the same layout (it never
// writes), so delivery bytes can never drift from signing bytes. Worst
// case 3 + (CRABS_MAX_USER_ID - 1) = 66 bytes.
static bool _lineage_tombstone_write_body(uint8_t* out, size_t cap,
                                          size_t* offset_out,
                                          const char* child_id) {
  size_t offset = 0;
  if (cap < 1) return false;
  out[offset++] = (uint8_t)LINEAGE_DISSOLVED;
  // strlen + 1 is the string's real capacity here — the writer asserts the
  // field is NUL-terminated within it; the emitted length excludes the NUL.
  if (!_lineage_string16_write(out, cap, &offset, child_id,
                               strlen(child_id) + 1)) {
    return false;
  }
  *offset_out = offset;
  return true;
}

// Honest-tombstone gate shared by the signing surfaces: resolve the manifest
// entry, enforce the honesty gate (a tombstone proves a dissolution — never
// sign one for a child that is not dissolved), and require a usable node key.
static crabs_error_e _lineage_dissolved_entry(state_t* parent,
                                              const char* child_id) {
  if (!attribute_machine_is_safe_user_id(child_id)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  const child_manifest_entry_t* manifest_entry =
      lineage_find_manifest_entry(parent, child_id);
  if (manifest_entry == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
  if (manifest_entry->status != LINEAGE_DISSOLVED) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  if (!parent->node_key_valid) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  return CRABS_SUCCESS;
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
  crabs_error_e status = _lineage_dissolved_entry(parent, child_id);
  if (status != CRABS_SUCCESS) return status;

  uint8_t tombstone[1 + 2 + CRABS_MAX_USER_ID];
  size_t tombstone_len = 0;
  if (!_lineage_tombstone_write_body(tombstone, sizeof(tombstone),
                                     &tombstone_len, child_id)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (crypto_ecdsa_sign(parent->node_private_key, tombstone, tombstone_len,
                        signature_out) != CRABS_SUCCESS) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  return CRABS_SUCCESS;
}

// Tombstone wire image for transport (see lineage.h): canonical body +
// signature appended, no length prefix.
crabs_error_e lineage_dissolution_serialize(state_t* parent,
                                            const char* child_id,
                                            uint8_t* out_buf, size_t buf_len,
                                            size_t* out_len) {
  if (parent == NULL || child_id == NULL || out_buf == NULL ||
      out_len == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  crabs_error_e status = _lineage_dissolved_entry(parent, child_id);
  if (status != CRABS_SUCCESS) return status;

  size_t body_len = 0;
  if (!_lineage_tombstone_write_body(out_buf, buf_len, &body_len, child_id) ||
      buf_len - body_len < CRABS_SIG_SIZE) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (crypto_ecdsa_sign(parent->node_private_key, out_buf, body_len,
                        out_buf + body_len) != CRABS_SUCCESS) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  *out_len = body_len + CRABS_SIG_SIZE;
  return CRABS_SUCCESS;
}

// Tombstone delivery on the child (see lineage.h for the authenticity model
// and the full refusal table). The payload is the wire image the parent's
// lineage_dissolution_serialize produced; the trailing CRABS_SIG_SIZE bytes
// are the signature over the body prefix.
crabs_error_e lineage_op_receive_dissolution(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL || op->payload == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // Size window: a 1-character id is the smallest honest tombstone
  // (3 + 1 + CRABS_SIG_SIZE); a safe id tops out at CRABS_MAX_USER_ID - 1
  // characters (it must keep room for its NUL).
  size_t tombstone_min = 3 + 1 + CRABS_SIG_SIZE;
  size_t tombstone_max = 3 + (CRABS_MAX_USER_ID - 1) + CRABS_SIG_SIZE;
  if (op->payload_size < tombstone_min || op->payload_size > tombstone_max) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // An unbound machine carries no parent binding — and therefore no parent
  // public key to verify the tombstone against. Refuse outright.
  if (!state->lineage_parent_bound) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  // Idempotency: a re-delivery cannot re-sever or undo anything.
  if (state->lineage_parent_dissolved) {
    return CRABS_ERR_ALREADY_PERFORMED;
  }

  size_t body_len = op->payload_size - CRABS_SIG_SIZE;
  const uint8_t* signature = op->payload + body_len;

  // Parse the tombstone's subject before spending verification work: the tag
  // must name a dissolution and the child_id must name THIS machine.
  if (op->payload[0] != (uint8_t)LINEAGE_DISSOLVED) {
    return CRABS_ERR_INVALID_PARAM;
  }
  size_t offset = 1;
  char tombstone_child_id[CRABS_MAX_USER_ID];
  if (!_lineage_string16_read(op->payload, body_len, &offset,
                              tombstone_child_id, sizeof(tombstone_child_id)) ||
      offset != body_len) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (strcmp(tombstone_child_id, state->lineage_self_id) != 0) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Authenticity rests on the tombstone's own parent signature — NOT on the
  // op's signature or attestations: the pipeline already authorized the
  // child admin (carriage), this ECDSA proves the parent decided (content).
  // Chain-aware (A10-M6): a tombstone signed by ANY accepted parent key —
  // the spawn pin or an accepted rotation — is authoritative.
  if (!lineage_verify_by_parent_key(state, op->payload, body_len,
                                    signature)) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  state->lineage_parent_dissolved = true;
  state_notify_change(state, CRABS_CHANGE_LINEAGE,
                      CRABS_LINEAGE_OP_RECEIVE_DISSOLUTION, op->uuid,
                      op->signer_id, op->node_id, tombstone_child_id,
                      "dissolution received", CRABS_SUCCESS);
  return CRABS_SUCCESS;
}

crabs_error_e lineage_op_parent_key_update(state_t* state, operation_t* op) {
  // Belt-and-braces payload cap alongside the accept gate's own size window:
  // an oversized payload is structural garbage before it is a record.
  if (state == NULL || op == NULL || op->payload == NULL ||
      op->payload_size > LINEAGE_KEY_TRANSITION_WIRE_MAX) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // The record's embedded parent signature is the authority — the accept
  // gate validates structure, continuity, version, and the signature, and
  // appends ONLY on full admission (no partial mutation).
  crabs_error_e status =
      lineage_child_accept_key_transition(state, op->payload,
                                          op->payload_size);
  if (status != CRABS_SUCCESS) return status;
  // Attribute via the op (signer/node/uuid) like the other lineage lifecycle
  // events; the target is THIS machine (the mutated subject) — the
  // __receive_dissolution__ precedent for child-side ops.
  state_notify_change(state, CRABS_CHANGE_LINEAGE,
                      CRABS_LINEAGE_OP_PARENT_KEY_UPDATE, op->uuid,
                      op->signer_id, op->node_id, state->lineage_self_id,
                      "parent key accepted", CRABS_SUCCESS);
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

// ============================================================
// Parent key chain (A10-M6): rotate / accept / chain-wide verify
// ============================================================

// Canonical key transition body writer — the SINGLE writer shared by signing
// (lineage_key_rotate) and verification re-canonicalization, so signed bytes
// and verified bytes can never drift (lineage.h documents the layout):
//   'P','K','T' + u64le new_key_version + new_pk(33) + old_pk(33)
//   + string16 parent_id + u64le created_at
// Returns bytes written, or 0 when cap is too small or parent_id is not
// NUL-terminated (strlen + 1 fails closed like the tombstone writer).
static size_t _lineage_key_transition_write_body(uint64_t new_key_version,
                                                 const uint8_t new_pk[33],
                                                 const uint8_t old_pk[33],
                                                 const char* parent_id,
                                                 uint64_t created_at,
                                                 uint8_t* out, size_t cap) {
  size_t offset = 0;
  if (cap < LINEAGE_KEY_TRANSITION_BODY_MIN) return 0;
  out[offset++] = 'P';
  out[offset++] = 'K';
  out[offset++] = 'T';
  _lineage_u64le_write(out + offset, new_key_version);
  offset += 8;
  memcpy(out + offset, new_pk, 33);
  offset += 33;
  memcpy(out + offset, old_pk, 33);
  offset += 33;
  if (!_lineage_string16_write(out, cap, &offset, parent_id,
                               strlen(parent_id) + 1)) {
    return 0;
  }
  _lineage_u64le_write(out + offset, created_at);
  offset += 8;
  return offset;
}

crabs_error_e lineage_key_rotate(state_t* parent_state,
                                 const uint8_t new_private_key[32],
                                 const uint8_t new_public_key[33],
                                 uint64_t now_ms,
                                 uint8_t** transition_out,
                                 size_t* transition_len) {
  if (parent_state == NULL || new_private_key == NULL ||
      new_public_key == NULL || transition_out == NULL ||
      transition_len == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  *transition_out = NULL;
  *transition_len = 0;

  // Validate first, mutate LAST: every refusal below leaves the lineage
  // version and the stashed transition untouched.
  if (!parent_state->node_key_valid ||
      !crypto_ecdsa_validate_public_key(parent_state->node_public_key)) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  if (!crypto_ecdsa_validate_public_key(new_public_key)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // The private half must match the advertised new public key — stashing a
  // transition toward a key the caller cannot wield would brick the next
  // rotation and every tombstone the new key should have signed.
  uint8_t derived_public_key[33];
  if (crypto_ecdsa_derive_public_key(new_private_key, derived_public_key)
          != CRABS_SUCCESS ||
      memcmp(derived_public_key, new_public_key, 33) != 0) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // Forward-only: "rotating" to the CURRENT key is not a rotation (the chain
  // side would refuse it as a known key anyway; refuse before signing).
  if (memcmp(new_public_key, parent_state->node_public_key, 33) == 0) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Version semantics: an unversioned machine key IS the spawn generation
  // (CRABS_LINEAGE_KEY_VERSION_START) — chain entry [0] on every child —
  // so the first rotation lands at START + 1.
  uint64_t current_key_version = parent_state->lineage_key_version != 0
      ? parent_state->lineage_key_version
      : (uint64_t)CRABS_LINEAGE_KEY_VERSION_START;
  if (current_key_version == UINT64_MAX) return CRABS_ERR_INVALID_PARAM;
  uint64_t new_key_version = current_key_version + 1;

  // The record names the PARENT machine in the lineage namespace. A spawned
  // parent carries its own lineage_self_id; a root machine falls back to its
  // v1 bootstrap_admin identity (the same string attestations carry).
  const char* parent_id = parent_state->lineage_self_id[0] != '\0'
      ? parent_state->lineage_self_id
      : parent_state->config.bootstrap_admin;
  uint8_t body[LINEAGE_KEY_TRANSITION_BODY_MAX];
  size_t body_len = _lineage_key_transition_write_body(
      new_key_version, new_public_key, parent_state->node_public_key,
      parent_id, now_ms, body, sizeof(body));
  if (body_len == 0) return CRABS_ERR_INVALID_PARAM;

  size_t record_len = body_len + CRABS_SIG_SIZE;
  uint8_t* record = get_clear_memory(record_len);
  if (record == NULL) return CRABS_ERR_OOM;
  memcpy(record, body, body_len);
  if (crypto_sign_operation(parent_state->node_private_key, body, body_len,
                            record + body_len) != CRABS_SUCCESS) {
    free(record);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  // Stash a second copy for re-emission; the stash swap and the version bump
  // are the ONLY mutations, and both fallible steps above (allocation,
  // signing) preceded them.
  uint8_t* stashed = get_clear_memory(record_len);
  if (stashed == NULL) {
    free(record);
    return CRABS_ERR_OOM;
  }
  memcpy(stashed, record, record_len);
  if (parent_state->lineage_last_key_transition != NULL) {
    free(parent_state->lineage_last_key_transition);
  }
  parent_state->lineage_last_key_transition = stashed;
  parent_state->lineage_last_key_transition_len = (uint32_t)record_len;
  parent_state->lineage_key_version = new_key_version;
  *transition_out = record;
  *transition_len = record_len;
  return CRABS_SUCCESS;
}

crabs_error_e lineage_child_accept_key_transition(state_t* child_state,
                                                  const uint8_t* record,
                                                  size_t record_len) {
  if (child_state == NULL || record == NULL) return CRABS_ERR_INVALID_PARAM;
  // Size window: the smallest honest record carries an empty parent_id and a
  // zero created_at (LINEAGE_KEY_TRANSITION_BODY_MIN body) plus the signature;
  // the cap keeps a hostile payload from making the parser walk unbounded
  // bytes.
  if (record_len < LINEAGE_KEY_TRANSITION_BODY_MIN + CRABS_SIG_SIZE ||
      record_len > LINEAGE_KEY_TRANSITION_WIRE_MAX) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // Lifecycle gates (cheapest first): an unbound machine has no chain to
  // advance, and a dissolved lineage accepts NO new parent key — severance
  // must not be quietly re-armed by a later rotation.
  if (!child_state->lineage_parent_bound) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  if (child_state->lineage_parent_dissolved) {
    return CRABS_ERR_UNAUTHORIZED;
  }

  size_t body_len = record_len - CRABS_SIG_SIZE;
  const uint8_t* signature = record + body_len;
  if (record[0] != 'P' || record[1] != 'K' || record[2] != 'T') {
    return CRABS_ERR_INVALID_PARAM;
  }
  size_t offset = 3;
  uint64_t new_key_version = 0;
  if (!_lineage_u64le_read(record, body_len, &offset, &new_key_version)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  const uint8_t* new_public_key = record + offset;
  offset += 33;
  const uint8_t* old_public_key = record + offset;
  offset += 33;
  char record_parent_id[CRABS_MAX_USER_ID];
  uint64_t created_at = 0;
  // Full-consumption parse: trailing garbage could smuggle aliasing bytes
  // past the signature surface. The trailing created_at is informational
  // only (never fed into the accept gates — the version is the ordering
  // authority); it lands here so a future surface can read it without
  // re-canonicalizing.
  if (!_lineage_string16_read(record, body_len, &offset, record_parent_id,
                              sizeof(record_parent_id)) ||
      !_lineage_u64le_read(record, body_len, &offset, &created_at) ||
      offset != body_len) {
    return CRABS_ERR_INVALID_PARAM;
  }
  (void)created_at;
  // The record names the PARENT this machine is bound to — refuse records
  // minted by/for a different parent before spending verification work
  // (mirrors the tombstone child_id gate). One record serves every child of
  // the named parent, so this is an identity check, not a per-record target.
  if (strcmp(record_parent_id, child_state->lineage_parent_id) != 0) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // Never install an off-curve key into the verification surface.
  if (!crypto_ecdsa_validate_public_key(new_public_key)) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Forward-only, gapless version continuity: new == (max chain version) + 1.
  // A zero version can never satisfy it (also catches the UINT64_MAX wrap).
  uint64_t max_key_version = (uint64_t)CRABS_LINEAGE_KEY_VERSION_START - 1;
  for (uint32_t chain_index = 0;
       chain_index < child_state->lineage_key_chain_count; chain_index++) {
    if (child_state->lineage_key_chain[chain_index].key_version >
        max_key_version) {
      max_key_version =
          child_state->lineage_key_chain[chain_index].key_version;
    }
  }
  if (new_key_version == 0 || new_key_version != max_key_version + 1) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // The incoming key must be NEW — no chain key may appear twice (a replay
  // with a bumped version would otherwise alias an existing signer).
  for (uint32_t chain_index = 0;
       chain_index < child_state->lineage_key_chain_count; chain_index++) {
    if (memcmp(child_state->lineage_key_chain[chain_index].public_key,
               new_public_key, 33) == 0) {
      return CRABS_ERR_INVALID_PARAM;
    }
  }
  // Bounded history: refuse overflow instead of truncating the spawn pin.
  if (child_state->lineage_key_chain_count >= CRABS_MAX_LINEAGE_KEY_CHAIN) {
    return CRABS_ERR_OOM;
  }

  // Continuity proof: the transition is authorized by the private half of
  // the chain TIP it retires. Tip-only admission is deliberate hardening:
  // every honest record (rotation signed with the current node key ==
  // chain tip; re-emission re-delivers that same record) names the tip, so
  // refusing retired-key records closes the "compromised retired key can
  // still advance the chain" hole with zero legitimate-traffic cost. Key
  // rotation retires the tip (version-bump authority moves to the new key),
  // but chain-wide verification (lineage_verify_by_parent_key) keeps prior
  // entries accepted for historical attestations/tombstones.
  // Guard the tip index rather than assume it: a bound state SHOULD always
  // carry chain_count >= 1 (spawn stamps the pin; the deserializer
  // synthesizes one), but a hand-built state could reach here with no
  // chain — fail closed instead of underflowing.
  if (child_state->lineage_key_chain_count == 0) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  const lineage_key_chain_entry_t* retired_entry =
      &child_state->lineage_key_chain[
          child_state->lineage_key_chain_count - 1];
  if (memcmp(retired_entry->public_key, old_public_key, 33) != 0) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  if (!crypto_verify_operation(retired_entry->public_key, record, body_len,
                               signature)) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  // Append with realloc semantics: on failure the old array is untouched and
  // still owned by the state (no rollback needed — this is the only mutation).
  lineage_key_chain_entry_t* grown = realloc(
      child_state->lineage_key_chain,
      (size_t)(child_state->lineage_key_chain_count + 1) *
          sizeof(lineage_key_chain_entry_t));
  if (grown == NULL) return CRABS_ERR_OOM;
  grown[child_state->lineage_key_chain_count].key_version = new_key_version;
  memcpy(grown[child_state->lineage_key_chain_count].public_key,
         new_public_key, 33);
  child_state->lineage_key_chain = grown;
  child_state->lineage_key_chain_count += 1;
  return CRABS_SUCCESS;
}

bool lineage_verify_by_parent_key(const state_t* state, const uint8_t* msg,
                                  size_t msg_len,
                                  const uint8_t sig[CRABS_SIG_SIZE]) {
  if (state == NULL || msg == NULL || sig == NULL) return false;
  // Any current chain entry is an accepted parent authority — the spawn pin
  // keeps verifying old attestations after a rotation, and each rotated key
  // joins the surface. An empty chain (never bound) fails closed.
  for (uint32_t chain_index = 0;
       chain_index < state->lineage_key_chain_count; chain_index++) {
    if (crypto_ecdsa_verify(state->lineage_key_chain[chain_index].public_key,
                            msg, msg_len, sig)) {
      return true;
    }
  }
  return false;
}
