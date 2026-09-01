//
// Created by victor on 9/1/25.
//
// Devtools: observer-only instrumentation for the WASM devtools panel.
// Compiled to real code only when CRABS_ENABLE_DEVTOOLS is defined, so
// production WASM binaries contain no devtools code.

#ifdef CRABS_ENABLE_DEVTOOLS

#include "devtools.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../Util/allocator.h"
#include "../HLC/hlc.h"
#include "../CRDT/crdt_merge.h"
#include "../CRDT/one_shot.h"

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
// Snapshot — implemented in Task 2
// ============================================================

char* devtools_snapshot_json(const state_t* state) {
  (void)state;
  return NULL;
}

void devtools_string_destroy(char* str) {
  free(str);
}

#endif // CRABS_ENABLE_DEVTOOLS