//
// Created by victor on 9/1/25.
//
// Devtools: observer-only instrumentation for the WASM devtools panel.
// Compiled to real code only when CRABS_ENABLE_DEVTOOLS is defined, so
// production WASM binaries contain no devtools code.

#ifdef CRABS_ENABLE_DEVTOOLS

#include "devtools.h"
#include "../Attribute/attribute_machine.h"
#include "../CRDT/crdt_merge.h"
#include "../CRDT/one_shot.h"
#include "../HLC/hlc.h"
#include "../Trigger/trigger.h"
#include "../Util/allocator.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================
// Ring buffer
// ============================================================

typedef struct {
  uint64_t      seq;
  char          op_type[CRABS_MAX_OP_NAME];
  char          uuid_hex[CRABS_UUID_SIZE * 2 + 1];
  char          signer_id[CRABS_MAX_USER_ID];
  char          node_id[CRABS_MAX_USER_ID];
  uint64_t      lamport_time;
  bool          has_hlc;
  crabs_hlc_t   hlc;
  char          target[CRABS_MAX_USER_ID];
  crabs_error_e result;
} devtools_event_t;

static devtools_event_t devtools_ring[CRABS_DEVTOOLS_RING_SIZE];
static uint32_t devtools_ring_head = 0;   // next write slot
static uint32_t devtools_ring_used = 0;
static uint64_t devtools_event_seq = 0;

uint32_t devtools_ring_count(void) {
  return devtools_ring_used;
}

static void _hex_encode_uuid(char* out, const uint8_t* uuid) {
  for (uint32_t byte_index = 0; byte_index < CRABS_UUID_SIZE; byte_index++) {
    snprintf(out + byte_index * 2, 3, "%02x", uuid[byte_index]);
  }
}

void devtools_record_event(state_t* state, const operation_t* op, crabs_error_e result) {
  if (!op) return;

  devtools_event_t* event = &devtools_ring[devtools_ring_head];
  memset(event, 0, sizeof(*event));
  event->seq = ++devtools_event_seq;
  strncpy(event->op_type, op->type, CRABS_MAX_OP_NAME - 1);
  _hex_encode_uuid(event->uuid_hex, op->uuid);
  strncpy(event->signer_id, op->signer_id, CRABS_MAX_USER_ID - 1);
  strncpy(event->node_id, op->node_id, CRABS_MAX_USER_ID - 1);
  event->lamport_time = op->lamport_time;
  if (op->ordering_system == CRABS_ORDERING_HLC) {
    event->has_hlc = true;
    event->hlc = op->hlc;
  }
  if (op->resource_count > 0 && op->resources) {
    strncpy(event->target, op->resources[0], CRABS_MAX_USER_ID - 1);
  }
  event->result = result;

  devtools_ring_head = (devtools_ring_head + 1) % CRABS_DEVTOOLS_RING_SIZE;
  if (devtools_ring_used < CRABS_DEVTOOLS_RING_SIZE) {
    devtools_ring_used++;
  }
  (void)state;
}

// ============================================================
// JSON writer (grow-on-append string builder)
// ============================================================

typedef struct {
  char*  data;
  size_t len;
  size_t capacity;
} json_writer_t;

static void _json_writer_init(json_writer_t* writer) {
  writer->capacity = 256;
  writer->len = 0;
  writer->data = get_clear_memory(writer->capacity);
}

static void _json_writer_reserve(json_writer_t* writer, size_t extra) {
  if (writer->len + extra + 1 <= writer->capacity) return;
  size_t new_capacity = writer->capacity;
  while (new_capacity < writer->len + extra + 1) new_capacity *= 2;
  char* grown = get_clear_memory(new_capacity);
  memcpy(grown, writer->data, writer->len);
  free(writer->data);
  writer->data = grown;
  writer->capacity = new_capacity;
}

static void _json_writer_raw(json_writer_t* writer, const char* text) {
  size_t text_len = strlen(text);
  _json_writer_reserve(writer, text_len);
  memcpy(writer->data + writer->len, text, text_len);
  writer->len += text_len;
  writer->data[writer->len] = '\0';
}

static void _json_writer_uint(json_writer_t* writer, uint64_t value) {
  char scratch[24];
  snprintf(scratch, sizeof(scratch), "%llu", (unsigned long long)value);
  _json_writer_raw(writer, scratch);
}

static void _json_writer_string(json_writer_t* writer, const char* text) {
  _json_writer_raw(writer, "\"");
  for (const char* cursor = text ? text : ""; *cursor; cursor++) {
    char character = *cursor;
    switch (character) {
      case '"':  _json_writer_raw(writer, "\\\""); break;
      case '\\': _json_writer_raw(writer, "\\\\"); break;
      case '\n': _json_writer_raw(writer, "\\n"); break;
      case '\r': _json_writer_raw(writer, "\\r"); break;
      case '\t': _json_writer_raw(writer, "\\t"); break;
      default:
        if ((unsigned char)character < 0x20) {
          char escape[8];
          snprintf(escape, sizeof(escape), "\\u%04x", (unsigned char)character);
          _json_writer_raw(writer, escape);
        } else {
          _json_writer_reserve(writer, 1);
          writer->data[writer->len++] = character;
          writer->data[writer->len] = '\0';
        }
    }
  }
  _json_writer_raw(writer, "\"");
}

static void _json_writer_key(json_writer_t* writer, const char* key) {
  _json_writer_string(writer, key);
  _json_writer_raw(writer, ":");
}

static void _json_writer_hlc(json_writer_t* writer, const crabs_hlc_t* hlc) {
  _json_writer_raw(writer, "{\"physical\":");
  _json_writer_uint(writer, hlc->physical_seconds);
  _json_writer_raw(writer, ",\"nanos\":");
  _json_writer_uint(writer, hlc->physical_nanos);
  _json_writer_raw(writer, ",\"logical\":");
  _json_writer_uint(writer, hlc->logical_counter);
  _json_writer_raw(writer, ",\"node\":");
  _json_writer_string(writer, hlc->node_id);
  _json_writer_raw(writer, "}");
}

static const char* _error_name(crabs_error_e result) {
  switch (result) {
    case CRABS_SUCCESS:                  return "success";
    case CRABS_ERR_UNAUTHORIZED:         return "unauthorized";
    case CRABS_ERR_PROTOCOL_VIOLATION:   return "protocol_violation";
    case CRABS_ERR_DUPLICATE_OPERATION:  return "duplicate_operation";
    case CRABS_ERR_INVARIANT_VIOLATED:   return "invariant_violated";
    case CRABS_ERR_CONDITION_NOT_MET:    return "condition_not_met";
    case CRABS_ERR_ALREADY_EXECUTED:     return "already_executed";
    case CRABS_ERR_ALREADY_PERFORMED:    return "already_performed";
    case CRABS_ERR_RESOURCE_NOT_FOUND:   return "resource_not_found";
    case CRABS_ERR_TYPE_MISMATCH:        return "type_mismatch";
    default:                             return "error";
  }
}

// ============================================================
// Events drain
// ============================================================

static void _write_event_json(json_writer_t* writer, const devtools_event_t* event) {
  _json_writer_raw(writer, "{\"seq\":");
  _json_writer_uint(writer, event->seq);
  _json_writer_raw(writer, ",\"op_type\":");
  _json_writer_string(writer, event->op_type);
  _json_writer_raw(writer, ",\"uuid_hex\":");
  _json_writer_string(writer, event->uuid_hex);
  _json_writer_raw(writer, ",\"signer\":");
  _json_writer_string(writer, event->signer_id);
  _json_writer_raw(writer, ",\"node\":");
  _json_writer_string(writer, event->node_id);
  _json_writer_raw(writer, ",\"lamport\":");
  _json_writer_uint(writer, event->lamport_time);
  _json_writer_raw(writer, ",\"hlc\":");
  if (event->has_hlc) {
    _json_writer_hlc(writer, &event->hlc);
  } else {
    _json_writer_raw(writer, "null");
  }
  _json_writer_raw(writer, ",\"target\":");
  _json_writer_string(writer, event->target);
  _json_writer_raw(writer, ",\"result\":");
  _json_writer_string(writer, event->result == CRABS_SUCCESS ? "accepted" : "rejected");
  _json_writer_raw(writer, ",\"error_code\":");
  _json_writer_uint(writer, (uint64_t)event->result);
  _json_writer_raw(writer, ",\"error\":");
  _json_writer_string(writer, _error_name(event->result));
  _json_writer_raw(writer, "}");
}

char* devtools_events_json(void) {
  json_writer_t writer;
  _json_writer_init(&writer);
  _json_writer_raw(&writer, "[");

  uint32_t oldest = (devtools_ring_head + CRABS_DEVTOOLS_RING_SIZE - devtools_ring_used)
                    % CRABS_DEVTOOLS_RING_SIZE;
  for (uint32_t event_index = 0; event_index < devtools_ring_used; event_index++) {
    if (event_index > 0) _json_writer_raw(&writer, ",");
    uint32_t slot = (oldest + event_index) % CRABS_DEVTOOLS_RING_SIZE;
    _write_event_json(&writer, &devtools_ring[slot]);
  }
  _json_writer_raw(&writer, "]");

  devtools_ring_head = 0;
  devtools_ring_used = 0;
  return writer.data;
}

// ============================================================
// Snapshot
// ============================================================

static const char* _crdt_type_name(crdt_type_e crdt_type) {
  switch (crdt_type) {
    case CRDT_G_COUNTER:    return "g_counter";
    case CRDT_PN_COUNTER:   return "pn_counter";
    case CRDT_OR_SET:       return "or_set";
    case CRDT_2P_SET:       return "2p_set";
    case CRDT_LWW_REG:      return "lww_register";
    case CRDT_RGA:          return "rga";
    case CRDT_ONE_SHOT_SET: return "one_shot_set";
    case CRDT_ONE_SHOT_FLAG:return "one_shot_flag";
    default:                return "custom";
  }
}

static const char* _protocol_state_name(protocol_state_e protocol_state) {
  switch (protocol_state) {
    case PROTOCOL_IDLE:     return "idle";
    case PROTOCOL_LOCKED:   return "locked";
    case PROTOCOL_MODIFIED: return "modified";
    case PROTOCOL_VERIFIED: return "verified";
    case PROTOCOL_ERROR:    return "error";
    default:                return "unknown";
  }
}

static void _write_g_counter_json(json_writer_t* writer, const g_counter_t* counter) {
  _json_writer_raw(writer, "{");
  for (uint32_t entry_index = 0; entry_index < counter->entry_count; entry_index++) {
    if (entry_index > 0) _json_writer_raw(writer, ",");
    _json_writer_string(writer, counter->entries[entry_index].node_id);
    _json_writer_raw(writer, ":");
    _json_writer_uint(writer, (uint64_t)counter->entries[entry_index].count);
  }
  _json_writer_raw(writer, "}");
}

static void _write_item_value_json(json_writer_t* writer, const data_item_t* item) {
  if (!item->value) {
    _json_writer_raw(writer, "null");
    return;
  }
  switch (item->crdt_type) {
    case CRDT_G_COUNTER:
      _write_g_counter_json(writer, (const g_counter_t*)item->value);
      break;
    case CRDT_PN_COUNTER: {
      const pn_counter_t* counter = (const pn_counter_t*)item->value;
      _json_writer_raw(writer, "{\"pos\":");
      _write_g_counter_json(writer, &counter->pos);
      _json_writer_raw(writer, ",\"neg\":");
      _write_g_counter_json(writer, &counter->neg);
      _json_writer_raw(writer, ",\"value\":");
      _json_writer_uint(writer, (uint64_t)pn_counter_value(counter));
      _json_writer_raw(writer, "}");
      break;
    }
    case CRDT_OR_SET: {
      const or_set_t* set = (const or_set_t*)item->value;
      _json_writer_raw(writer, "{\"elements\":[");
      for (uint32_t entry_index = 0; entry_index < set->element_count; entry_index++) {
        if (entry_index > 0) _json_writer_raw(writer, ",");
        _json_writer_string(writer, set->elements[entry_index].element);
      }
      _json_writer_raw(writer, "],\"tombstones\":");
      _json_writer_uint(writer, set->tombstone_count);
      _json_writer_raw(writer, "}");
      break;
    }
    case CRDT_2P_SET: {
      const two_p_set_t* set = (const two_p_set_t*)item->value;
      _json_writer_raw(writer, "{\"adds\":[");
      for (uint32_t entry_index = 0; entry_index < set->add_count; entry_index++) {
        if (entry_index > 0) _json_writer_raw(writer, ",");
        _json_writer_string(writer, set->add_set[entry_index]);
      }
      _json_writer_raw(writer, "],\"removes\":[");
      for (uint32_t entry_index = 0; entry_index < set->remove_count; entry_index++) {
        if (entry_index > 0) _json_writer_raw(writer, ",");
        _json_writer_string(writer, set->remove_set[entry_index]);
      }
      _json_writer_raw(writer, "]}");
      break;
    }
    case CRDT_LWW_REG: {
      const lww_register_t* reg = (const lww_register_t*)item->value;
      _json_writer_raw(writer, "{\"value\":");
      if (reg->value && reg->value_size >= sizeof(int64_t)) {
        int64_t register_value;
        memcpy(&register_value, reg->value, sizeof(int64_t));
        _json_writer_uint(writer, (uint64_t)register_value);
      } else {
        _json_writer_raw(writer, "null");
      }
      _json_writer_raw(writer, ",\"timestamp\":");
      _json_writer_uint(writer, reg->timestamp);
      _json_writer_raw(writer, ",\"writer\":");
      _json_writer_string(writer, reg->node_id);
      _json_writer_raw(writer, "}");
      break;
    }
    case CRDT_ONE_SHOT_SET: {
      const one_shot_set_t* set = (const one_shot_set_t*)item->value;
      _json_writer_raw(writer, "{\"elements\":[");
      for (uint32_t entry_index = 0; entry_index < set->element_count; entry_index++) {
        if (entry_index > 0) _json_writer_raw(writer, ",");
        _json_writer_string(writer, set->elements[entry_index]);
      }
      _json_writer_raw(writer, "]}");
      break;
    }
    case CRDT_ONE_SHOT_FLAG: {
      const one_shot_flag_t* flag = (const one_shot_flag_t*)item->value;
      _json_writer_raw(writer, "{\"value\":");
      _json_writer_raw(writer, flag->value ? "true" : "false");
      _json_writer_raw(writer, ",\"set_by\":");
      _json_writer_string(writer, flag->set_by);
      _json_writer_raw(writer, ",\"set_at\":");
      _json_writer_uint(writer, flag->set_at);
      _json_writer_raw(writer, "}");
      break;
    }
    default:
      _json_writer_raw(writer, "null");
  }
}

static void _write_hlc_field(json_writer_t* writer, const char* key, const crabs_hlc_t* hlc) {
  _json_writer_key(writer, key);
  _json_writer_hlc(writer, hlc);
}

static void _write_invariants_json(json_writer_t* writer, const data_item_t* item) {
  _json_writer_raw(writer, "\"invariants\":[");
  for (uint32_t invariant_index = 0; invariant_index < item->invariant_count; invariant_index++) {
    if (invariant_index > 0) _json_writer_raw(writer, ",");
    const invariant_t* invariant = &item->invariants[invariant_index];
    _json_writer_raw(writer, "{\"type\":");
    _json_writer_uint(writer, (uint64_t)invariant->type);
    _json_writer_raw(writer, ",\"param\":");
    _json_writer_uint(writer, (uint64_t)invariant->param);
    _json_writer_raw(writer, ",\"message\":");
    _json_writer_string(writer, invariant->error_message);
    _json_writer_raw(writer, "}");
  }
  _json_writer_raw(writer, "]");
}

static void _write_lock_state_json(json_writer_t* writer, const data_item_t* item) {
  _json_writer_raw(writer, "\"lock_state\":{\"locked\":");
  _json_writer_raw(writer, item->lock_state.lock_token_valid ? "true" : "false");
  _json_writer_raw(writer, ",\"owner\":");
  _json_writer_string(writer, item->lock_state.lock_owner);
  _json_writer_raw(writer, ",\"expiry\":");
  _json_writer_uint(writer, item->lock_state.lock_expiry);
  _json_writer_raw(writer, "}");
}

static void _write_item_json(json_writer_t* writer, const data_item_t* item) {
  _json_writer_raw(writer, "{\"name\":");
  _json_writer_string(writer, item->name);
  _json_writer_raw(writer, ",\"crdt_type\":");
  _json_writer_string(writer, _crdt_type_name(item->crdt_type));
  _json_writer_raw(writer, ",\"protocol_state\":");
  _json_writer_string(writer, _protocol_state_name(item->protocol_state));
  _json_writer_raw(writer, ",\"value\":");
  _write_item_value_json(writer, item);
  _json_writer_raw(writer, ",");
  _write_invariants_json(writer, item);
  _json_writer_raw(writer, ",");
  _write_lock_state_json(writer, item);
  _json_writer_raw(writer, "}");
}

static void _write_policies_json(json_writer_t* writer, const state_t* state) {
  _json_writer_raw(writer, "\"policies\":[");
  for (uint32_t policy_index = 0; policy_index < state->policy_count; policy_index++) {
    if (policy_index > 0) _json_writer_raw(writer, ",");
    _json_writer_raw(writer, "{\"operation\":");
    _json_writer_string(writer, state->policies[policy_index].operation);
    _json_writer_raw(writer, ",\"expression\":");
    _json_writer_string(writer, state->policies[policy_index].expression);
    _json_writer_raw(writer, "}");
  }
  _json_writer_raw(writer, "]");
}

static void _write_trigger_effect_json(json_writer_t* writer, const trigger_effect_t* effect) {
  if (effect->type == TRIGGER_EFFECT_ISSUE_ATTRIBUTE) {
    _json_writer_string(writer, effect->issue_attribute);
  } else if (effect->type == TRIGGER_EFFECT_CHANGE_POLICY) {
    _json_writer_string(writer, effect->policy_operation);
  } else {
    _json_writer_string(writer, "custom");
  }
}

static void _write_triggers_json(json_writer_t* writer, const state_t* state) {
  _json_writer_raw(writer, "\"triggers\":[");
  for (uint32_t trigger_index = 0; trigger_index < state->trigger_count; trigger_index++) {
    if (trigger_index > 0) _json_writer_raw(writer, ",");
    const trigger_t* trigger = &state->triggers[trigger_index];
    _json_writer_raw(writer, "{\"id\":");
    _json_writer_string(writer, trigger->trigger_id);
    _json_writer_raw(writer, ",\"description\":");
    _json_writer_string(writer, trigger->description);
    _json_writer_raw(writer, ",\"condition\":");
    _json_writer_string(writer, trigger->condition);
    _json_writer_raw(writer, ",\"enabled\":");
    _json_writer_raw(writer, trigger->enabled ? "true" : "false");
    _json_writer_raw(writer, ",\"fired\":");
    _json_writer_raw(writer, trigger->last_triggered_at > 0 ? "true" : "false");
    _json_writer_raw(writer, ",\"effect\":");
    _write_trigger_effect_json(writer, &trigger->effect);
    _json_writer_raw(writer, "}");
  }
  _json_writer_raw(writer, "]");
}

static void _write_users_json(json_writer_t* writer, const state_t* state) {
  _json_writer_raw(writer, "\"users\":[");
  if (state->attr_machine && state->attr_machine->users) {
    const user_t* user = state->attr_machine->users;
    bool first_user = true;
    while (user) {
      if (!first_user) _json_writer_raw(writer, ",");
      first_user = false;
      _json_writer_raw(writer, "{\"id\":");
      _json_writer_string(writer, user->user_id);
      _json_writer_raw(writer, ",\"status\":");
      _json_writer_uint(writer, (uint64_t)user->status);
      _json_writer_raw(writer, ",\"keys\":");
      _json_writer_uint(writer, user->key_count);
      _json_writer_raw(writer, ",\"attrs\":[");
      for (uint32_t attribute_index = 0; attribute_index < user->attribute_count; attribute_index++) {
        if (attribute_index > 0) _json_writer_raw(writer, ",");
        _json_writer_string(writer, user->attributes[attribute_index].value);
      }
      _json_writer_raw(writer, "]}");
      user = user->next;
    }
  }
  _json_writer_raw(writer, "]");
}

static void _write_log_head_json(json_writer_t* writer, const state_t* state) {
  _json_writer_raw(writer, "\"log_head\":{\"entries\":");
  _json_writer_uint(writer, state->log_count);
  _json_writer_raw(writer, ",\"state_hash\":");
  if (state->log_count > 0 && state->log) {
    const log_entry_t* head = &state->log[state->log_count - 1];
    char hash_hex[CRABS_HASH_SIZE * 2 + 1];
    for (uint32_t byte_index = 0; byte_index < CRABS_HASH_SIZE; byte_index++) {
      snprintf(hash_hex + byte_index * 2, 3, "%02x", head->state_hash[byte_index]);
    }
    _json_writer_string(writer, hash_hex);
  } else {
    _json_writer_string(writer, "");
  }
  _json_writer_raw(writer, "}");
}

char* devtools_snapshot_json(const state_t* state) {
  if (!state) return NULL;

  json_writer_t writer;
  _json_writer_init(&writer);
  _json_writer_raw(&writer, "{\"node_id\":");
  if (state->hlc_state_initialized) {
    _json_writer_string(&writer, state->hlc_state.last.node_id);
  } else {
    _json_writer_string(&writer, state->config.bootstrap_admin);
  }
  _json_writer_raw(&writer, ",\"version\":");
  _json_writer_uint(&writer, state->version);
  _json_writer_raw(&writer, ",");
  if (state->hlc_state_initialized) {
    _write_hlc_field(&writer, "hlc", &state->hlc_state.last);
  } else {
    _json_writer_raw(&writer, "\"hlc\":null");
  }
  _json_writer_raw(&writer, ",\"items\":[");

  bool first_item = true;
  for (const data_item_t* item = state->items; item; item = item->next) {
    if (!first_item) _json_writer_raw(&writer, ",");
    first_item = false;
    _write_item_json(&writer, item);
  }

  _json_writer_raw(&writer, "],");
  _write_policies_json(&writer, state);
  _json_writer_raw(&writer, ",");
  _write_triggers_json(&writer, state);
  _json_writer_raw(&writer, ",");
  _write_users_json(&writer, state);
  _json_writer_raw(&writer, ",");
  _write_log_head_json(&writer, state);
  _json_writer_raw(&writer, "}");
  return writer.data;
}

void devtools_string_destroy(char* str) {
  free(str);
}

#endif // CRABS_ENABLE_DEVTOOLS
