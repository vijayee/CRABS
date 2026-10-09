//
// wasm_helpers.c — Emscripten-only helpers for the crabs-wasm JS wrapper.
//
// These functions expose safe accessors/setters so the JS wrapper does not
// need to hardcode struct offsets or pointer sizes.
//

#ifdef __EMSCRIPTEN__

#include <emscripten.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "../Attribute/attribute_machine.h"
#include "../StateMachine/state_machine.h"
#include "../Serialization/serialization.h"
#include "../Crypto/crypto.h"
#include "../HLC/hlc.h"
#include "../CRDT/crdt_merge.h"
#include "../CRDT/one_shot.h"
#include "../Scheduler/scheduler.h"
#include "../Lineage/lineage.h"
#include "../TimeSource/time_source.h"

#ifdef CRABS_ENABLE_DEVTOOLS
#include "../Devtools/devtools.h"
#endif

// ============================================================
// Change-event forwarding to JS
// ============================================================
// A single module-wide JS trampoline receives one JSON string per change
// event. Registered once per module by any Node via
// crabs_wasm_set_change_trampoline. The per-node hook forwards to the
// devtools ring (dev builds) and to JS (all builds).

static void (*s_js_change_trampoline)(const char* json) = NULL;

// Fixed literal overhead of the change-event JSON envelope: all the keys,
// quotes, and the result field beyond the escaped string bodies (measured
// ~68 bytes; margin included for kind-name growth).
#define JSON_FIXED_OVERHEAD 160

// Serialize a string as a JSON string body (without quotes), escaping
// backslashes, double quotes, and control characters (<0x20). Truncates to
// fit; output is always NUL-terminated.
static void _json_escape_into(const char* src, char* out, size_t out_size) {
  size_t out_index = 0;
  for (const char* cursor = (src != NULL) ? src : ""; *cursor != '\0'; cursor++) {
    char escaped_pair[3];
    switch (*cursor) {
      case '"':  escaped_pair[0] = '\\'; escaped_pair[1] = '"';  break;
      case '\\': escaped_pair[0] = '\\'; escaped_pair[1] = '\\'; break;
      case '\n': escaped_pair[0] = '\\'; escaped_pair[1] = 'n';  break;
      case '\r': escaped_pair[0] = '\\'; escaped_pair[1] = 'r';  break;
      case '\t': escaped_pair[0] = '\\'; escaped_pair[1] = 't';  break;
      default:
        if ((unsigned char)*cursor < 0x20) {
          // Other control chars: \u00XX (4 hex digits after a backslash-u).
          if (out_index + 6 >= out_size) goto done;
          static const char hex_chars[] = "0123456789abcdef";
          out[out_index++] = '\\';
          out[out_index++] = 'u';
          out[out_index++] = '0';
          out[out_index++] = '0';
          out[out_index++] = hex_chars[((unsigned char)*cursor) >> 4];
          out[out_index++] = hex_chars[((unsigned char)*cursor) & 0x0F];
          continue;
        }
        escaped_pair[0] = *cursor; escaped_pair[1] = '\0'; break;
    }
    if (out_index + 3 >= out_size) break;
    out[out_index++] = escaped_pair[0];
    if (escaped_pair[1] != '\0') out[out_index++] = escaped_pair[1];
  }
done:
  out[out_index] = '\0';
}

// Serialize a change event as a JSON object string (malloc'd; caller frees).
static char* _change_event_json(const crabs_change_event_t* event) {
  char type_buf[CRABS_MAX_OP_NAME + 8];
  char signer_buf[CRABS_MAX_USER_ID + 8];
  char node_buf[CRABS_MAX_USER_ID + 8];
  char target_buf[CRABS_MAX_USER_ID + 8];
  char preview_buf[128];
  _json_escape_into(event->type, type_buf, sizeof(type_buf));
  _json_escape_into(event->signer_id, signer_buf, sizeof(signer_buf));
  _json_escape_into(event->node_id, node_buf, sizeof(node_buf));
  _json_escape_into(event->target, target_buf, sizeof(target_buf));
  _json_escape_into(event->preview, preview_buf, sizeof(preview_buf));

  char uuid_hex[CRABS_UUID_SIZE * 2 + 1];
  uuid_hex[0] = '\0';
  if (event->uuid != NULL) {
    static const char hex_chars[] = "0123456789abcdef";
    for (uint32_t uuid_byte_index = 0; uuid_byte_index < CRABS_UUID_SIZE;
         uuid_byte_index++) {
      uuid_hex[uuid_byte_index * 2] = hex_chars[event->uuid[uuid_byte_index] >> 4];
      uuid_hex[uuid_byte_index * 2 + 1] =
          hex_chars[event->uuid[uuid_byte_index] & 0x0F];
    }
    uuid_hex[CRABS_UUID_SIZE * 2] = '\0';
  }

  const char* kind_name = "op";
  switch (event->kind) {
    case CRABS_CHANGE_SCHEDULE:  kind_name = "schedule"; break;
    case CRABS_CHANGE_TRIGGER:   kind_name = "trigger"; break;
    case CRABS_CHANGE_ATTRIBUTE: kind_name = "attribute"; break;
    case CRABS_CHANGE_SPAWN:     kind_name = "spawn"; break;
    case CRABS_CHANGE_LINEAGE:   kind_name = "lineage"; break;
    default: break;
  }

  size_t needed = strlen(type_buf) + strlen(signer_buf) + strlen(node_buf) +
                  strlen(target_buf) + strlen(preview_buf) + JSON_FIXED_OVERHEAD;
  char* json = (char*)malloc(needed);
  if (json == NULL) return NULL;
  snprintf(json, needed,
           "{\"kind\":\"%s\",\"type\":\"%s\",\"uuid\":\"%s\","
           "\"signer\":\"%s\",\"node\":\"%s\",\"target\":\"%s\","
           "\"preview\":\"%s\",\"result\":%u}",
           kind_name, type_buf, uuid_hex, signer_buf, node_buf, target_buf,
           preview_buf, (unsigned)event->result);
  return json;
}

static void _forward_change_to_js(state_t* state,
                                  const crabs_change_event_t* event,
                                  void* user_data) {
  (void)state; (void)user_data;
  if (s_js_change_trampoline == NULL || event == NULL) return;
  char* json = _change_event_json(event);
  if (json == NULL) return;
  s_js_change_trampoline(json);
  free(json);
}

// Per-node hook registered on every node's base state: every mutation the
// state reports (executes, schedules, triggers, attribute changes) is
// recorded into the devtools ring (dev builds) and forwarded to JS.
static void _node_change_hook(state_t* state,
                              const crabs_change_event_t* event,
                              void* user_data) {
  (void)state;
#ifdef CRABS_ENABLE_DEVTOOLS
  devtools_record_change(state, event);
#endif
  _forward_change_to_js(state, event, user_data);
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_set_change_trampoline(void (*trampoline)(const char* json)) {
  s_js_change_trampoline = trampoline;
}

// ============================================================
// Authenticated time source (module-scoped owned slot)
// ============================================================
// A wasm module instance owns ONE time source: every machine that selects
// mode=https attaches to the same owned ops object (per-module, not
// per-machine). crabs_wasm_set_time_source manages the slot:
//   - set-https replaces the slot: the fresh ops is attached to every
//     machine in the attached-set PLUS the target machine, and only THEN is
//     the previous ops destroyed (attach-before-retire, so no machine ever
//     observes a dangling ops pointer).
//   - set-system detaches the target machine and drops it from the
//     attached-set; when the last attached machine leaves, the owned ops is
//     destroyed (registry empty = nothing references it).
// The attached-set holds raw machine pointers. In the wasm build machines
// are never truly freed (crabs_wasm_node_destroy intentionally leaks — see
// its comment), so these pointers stay valid for the module's lifetime; the
// destroy path still detaches the machine state and drops its registry
// entry so the shared ops can be retired before a leaked (but destroyed)
// machine could observe it dangling.

#define CRABS_WASM_TIME_SOURCE_URL_MAX 255
#define CRABS_WASM_TIME_SOURCE_SYSTEM  0
#define CRABS_WASM_TIME_SOURCE_HTTPS   1

static crabs_time_source_ops_t* s_time_source_ops = NULL;
static attribute_machine_t** s_time_source_machines = NULL;
static uint32_t s_time_source_machine_count = 0;
static uint32_t s_time_source_machine_capacity = 0;

static uint32_t _time_source_machine_index(attribute_machine_t* am) {
  for (uint32_t index = 0; index < s_time_source_machine_count; index++) {
    if (s_time_source_machines[index] == am) return index;
  }
  return UINT32_MAX;
}

static crabs_error_e _time_source_register_machine(attribute_machine_t* am) {
  if (_time_source_machine_index(am) != UINT32_MAX) return CRABS_SUCCESS;
  if (s_time_source_machine_count == s_time_source_machine_capacity) {
    uint32_t fresh_capacity = s_time_source_machine_capacity == 0
        ? 4 : s_time_source_machine_capacity * 2;
    attribute_machine_t** fresh_registry = (attribute_machine_t**)realloc(
        s_time_source_machines, fresh_capacity * sizeof(attribute_machine_t*));
    if (fresh_registry == NULL) return CRABS_ERR_OOM;
    s_time_source_machines = fresh_registry;
    s_time_source_machine_capacity = fresh_capacity;
  }
  s_time_source_machines[s_time_source_machine_count++] = am;
  return CRABS_SUCCESS;
}

// Drop a machine from the attached-set. The caller detaches the machine's
// state FIRST; once the last attached machine leaves, the owned ops has no
// remaining references and is destroyed.
static void _time_source_unregister_machine(attribute_machine_t* am) {
  uint32_t index = _time_source_machine_index(am);
  if (index == UINT32_MAX) return;
  s_time_source_machines[index] =
      s_time_source_machines[s_time_source_machine_count - 1];
  s_time_source_machine_count--;
  if (s_time_source_machine_count == 0 && s_time_source_ops != NULL) {
    crabs_time_source_destroy(s_time_source_ops);
    s_time_source_ops = NULL;
  }
}

// ============================================================
// Node lifecycle (HLC-enabled)
// ============================================================

EMSCRIPTEN_KEEPALIVE
attribute_machine_t* crabs_wasm_node_create(const char* admin_id) {
  ecdsa_keypair_t* node_key = crypto_ecdsa_generate();
  if (!node_key) return NULL;

  attribute_machine_t* am = attribute_machine_create(admin_id, node_key->public_key);
  if (!am) {
    crypto_ecdsa_keypair_destroy(node_key);
    return NULL;
  }

  am->base_state.attr_machine = am;
  state_set_node_key(&am->base_state, node_key->private_key, node_key->public_key);

  crabs_ordering_config_t* ordering_config = (crabs_ordering_config_t*)malloc(sizeof(crabs_ordering_config_t));
  if (!ordering_config) {
    crypto_ecdsa_keypair_destroy(node_key);
    attribute_machine_destroy(am);
    return NULL;
  }
  crabs_ordering_config_init_hlc(ordering_config, HLC_STRATEGY_BOUNDED);
  state_set_ordering_config(&am->base_state, ordering_config);

  crabs_hlc_state_init(&am->base_state.hlc_state, admin_id);
  am->base_state.hlc_state_initialized = true;

  state_set_change_hook(&am->base_state, _node_change_hook, am);

  crypto_ecdsa_keypair_destroy(node_key);
  return am;
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_node_destroy(attribute_machine_t* am) {
  // Intentional near-no-op. Full C teardown (attribute_machine_destroy)
  // triggers a memory-access crash in the Emscripten build during
  // ABE/OpenABE cleanup. The browser demo creates one Node per page load;
  // leaking it is harmless because the process ends on navigation. A future
  // fix can safely tear down the ABE context first.
  //
  // The machine IS released from the module time-source attached-set even
  // though its memory leaks: detaching keeps the shared ops honest about who
  // references it (so set-system on the last live machine can retire it) and
  // guarantees a hypothetical future full teardown cannot leave a dangling
  // ops pointer behind.
  if (am == NULL) return;
  state_set_time_source(&am->base_state, NULL);
  _time_source_unregister_machine(am);
}

// ============================================================
// Operation field accessors
// ============================================================

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_op_set_type(operation_t* op, const char* type) {
  if (!op || !type) return;
  strncpy(op->type, type, CRABS_MAX_OP_NAME - 1);
  op->type[CRABS_MAX_OP_NAME - 1] = '\0';
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_op_set_signer(operation_t* op, const char* signer) {
  if (!op || !signer) return;
  strncpy(op->signer_id, signer, CRABS_MAX_USER_ID - 1);
  op->signer_id[CRABS_MAX_USER_ID - 1] = '\0';
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_op_set_node(operation_t* op, const char* node) {
  if (!op || !node) return;
  strncpy(op->node_id, node, CRABS_MAX_USER_ID - 1);
  op->node_id[CRABS_MAX_USER_ID - 1] = '\0';
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_op_set_payload(operation_t* op, const uint8_t* data, uint32_t len) {
  if (!op) return;
  if (op->payload) { free(op->payload); op->payload = NULL; }
  op->payload_size = 0;
  if (!data || len == 0) return;
  op->payload = (uint8_t*)malloc(len);
  if (op->payload) {
    memcpy(op->payload, data, len);
    op->payload_size = len;
  }
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_op_get_type(operation_t* op) {
  return op ? op->type : NULL;
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_op_get_signer(operation_t* op) {
  return op ? op->signer_id : NULL;
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_op_get_node(operation_t* op) {
  return op ? op->node_id : NULL;
}

EMSCRIPTEN_KEEPALIVE
uint32_t crabs_wasm_op_get_payload_size(operation_t* op) {
  return op ? op->payload_size : 0;
}

EMSCRIPTEN_KEEPALIVE
const uint8_t* crabs_wasm_op_get_payload(operation_t* op) {
  return op ? op->payload : NULL;
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_op_init_uuid(operation_t* op) {
  if (!op) return;
  crypto_random_bytes(op->uuid, CRABS_UUID_SIZE);
}

// ============================================================
// Signing
// ============================================================

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_sign_operation(attribute_machine_t* am, operation_t* op,
                                       const uint8_t* private_key) {
  if (!am || !op || !private_key) return CRABS_ERR_INVALID_PARAM;

  if (am->base_state.hlc_state_initialized) {
    // R7-15: the wire format now preserves HLC fields, so sign with HLC
    // ordering directly instead of the Lamport workaround.
    op->hlc = crabs_hlc_next(&am->base_state.hlc_state);
    op->ordering_system = CRABS_ORDERING_HLC;
    strncpy(op->node_id, am->base_state.hlc_state.last.node_id, CRABS_MAX_USER_ID - 1);
    op->node_id[CRABS_MAX_USER_ID - 1] = '\0';
  }

  // R7-04: the execute path's key-staleness check is mandatory — the op must
  // declare the signer's current key version or it is rejected as stale. The
  // signer signs with their current key, so stamp it from their user record.
  user_t* signer = attribute_machine_find_user(am, op->signer_id);
  if (signer != NULL) {
    op->signer_key_version = signer->key_version;
  }

  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  if (!ser) return CRABS_ERR_SERIALIZATION_ERROR;
  crabs_error_e rc = crypto_ecdsa_sign(private_key, ser->data, ser->len, op->signature);
  serialized_buffer_destroy(ser);
  return rc;
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_sign_with_node_key(attribute_machine_t* am, operation_t* op) {
  if (!am || !op) return CRABS_ERR_INVALID_PARAM;
  return crabs_wasm_sign_operation(am, op, am->base_state.node_private_key);
}

// ============================================================
// Execution
// ============================================================

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_execute(attribute_machine_t* am, operation_t* op) {
  if (!am || !op) return CRABS_ERR_INVALID_PARAM;
  return state_machine_execute(&am->base_state, op);
}

// ============================================================
// Serialization helpers
// ============================================================

EMSCRIPTEN_KEEPALIVE
serialized_buffer_t* crabs_wasm_serialize_operation(const operation_t* op) {
  return crabs_serialize_operation(op);
}

EMSCRIPTEN_KEEPALIVE
operation_t* crabs_wasm_deserialize_operation(const uint8_t* data, uint32_t len) {
  return crabs_deserialize_operation(data, len);
}

EMSCRIPTEN_KEEPALIVE
uint32_t crabs_wasm_buffer_len(serialized_buffer_t* buf) {
  return buf ? (uint32_t)buf->len : 0;
}

EMSCRIPTEN_KEEPALIVE
const uint8_t* crabs_wasm_buffer_data(serialized_buffer_t* buf) {
  return buf ? buf->data : NULL;
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_buffer_destroy(serialized_buffer_t* buf) {
  if (buf) serialized_buffer_destroy(buf);
}

// ============================================================
// State helpers
// ============================================================

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_add_counter(attribute_machine_t* am, const char* name) {
  data_item_t* item = data_item_create(name, DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  if (!item) return CRABS_ERR_OOM;
  item->value = g_counter_create();
  // Struct-backed value (g_counter_t) — release via crdt_value_destroy.
  item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;
  return state_add_item(&am->base_state, item);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_add_pn_counter(attribute_machine_t* am, const char* name) {
  data_item_t* item = data_item_create(name, DATA_TYPE_PN_COUNTER, CRDT_PN_COUNTER);
  if (!item) return CRABS_ERR_OOM;
  item->value = pn_counter_create();
  // Struct-backed value (pn_counter_t) — release via crdt_value_destroy.
  item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;
  return state_add_item(&am->base_state, item);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_add_or_set(attribute_machine_t* am, const char* name) {
  data_item_t* item = data_item_create(name, DATA_TYPE_SET, CRDT_OR_SET);
  if (!item) return CRABS_ERR_OOM;
  item->value = or_set_create();
  // Struct-backed value (or_set_t) — release via crdt_value_destroy.
  item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;
  return state_add_item(&am->base_state, item);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_add_one_shot_set(attribute_machine_t* am, const char* name) {
  data_item_t* item = data_item_create(name, DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  if (!item) return CRABS_ERR_OOM;
  item->value = one_shot_set_create();
  // Struct-backed value (one_shot_set_t) — release via crdt_value_destroy.
  item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;
  return state_add_item(&am->base_state, item);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_add_one_shot_flag(attribute_machine_t* am, const char* name) {
  data_item_t* item = data_item_create(name, DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
  if (!item) return CRABS_ERR_OOM;
  item->value = one_shot_flag_create();
  // Struct-backed value (one_shot_flag_t) — release via crdt_value_destroy.
  item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;
  return state_add_item(&am->base_state, item);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_add_register(attribute_machine_t* am, const char* name, int64_t initial) {
  data_item_t* item = data_item_create(name, DATA_TYPE_REGISTER, CRDT_LWW_REG);
  if (!item) return CRABS_ERR_OOM;
  item->value = lww_register_create((const uint8_t*)&initial, sizeof(int64_t), 0, "system");
  // Struct-backed value (lww_register_t) — release via crdt_value_destroy.
  item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;
  return state_add_item(&am->base_state, item);
}

// ============================================================
// Write-domains v1 surfaces
// ============================================================

// Item creation with an explicit write-domain declaration. The options
// mirror data_item_options_t as scalars: write_domain is the
// crabs_write_domain_e wire number (0 free / 1 sovereign / 2 group), writer
// is NULL-or-empty for none, ordering_module 0 for unset. v1 restricts this
// surface to COUNTER/REGISTER — the SOVEREIGN-legal types (their canonical
// serializations back the hash-chain digest); other shapes keep their
// dedicated add exports. On failure the item is destroyed, not leaked.
EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_define_item(attribute_machine_t* am,
                                     const char* name, int data_type,
                                     int crdt_type, int write_domain,
                                     const char* writer,
                                     int ordering_module) {
  if (!am || !name) return CRABS_ERR_INVALID_PARAM;
  if (data_type != DATA_TYPE_COUNTER && data_type != DATA_TYPE_REGISTER) {
    return CRABS_ERR_TYPE_MISMATCH;
  }
  // Final-review fix: the JS caller picks the crdt_type word freely, and the
  // value install below keys on data_type ALONE — COUNTER + CRDT_PN_COUNTER
  // minted a g_counter value tagged CRDT_PN_COUNTER, which destroy (and
  // every other repr/crdt-dispatched consumer) miscast as pn_counter_t.
  // Refuse any non-canonical (data_type, crdt_type) pair BEFORE allocating;
  // data_item_create_with_options enforces the same pairing as the
  // fail-closed backstop for every other caller.
  if (!data_item_type_crdt_pair_canonical((data_type_e)data_type,
                                          (crdt_type_e)crdt_type)) {
    return CRABS_ERR_TYPE_MISMATCH;
  }
  data_item_options_t options;
  memset(&options, 0, sizeof(options));
  options.write_domain = (crabs_write_domain_e)write_domain;
  options.writer = (writer != NULL && writer[0] != '\0') ? writer : NULL;
  options.ordering_module = (uint8_t)ordering_module;
  data_item_t* item = NULL;
  crabs_error_e rc = data_item_create_with_options(
      name, (data_type_e)data_type, (crdt_type_e)crdt_type, &options, &item);
  if (rc != CRABS_SUCCESS) return rc;
  if (data_type == DATA_TYPE_COUNTER) {
    item->value = g_counter_create();
  } else {
    int64_t initial = 0;
    item->value = lww_register_create((const uint8_t*)&initial,
                                      sizeof(int64_t), 0, "system");
  }
  // Struct-backed value (g_counter_t / lww_register_t) — release via
  // crdt_value_destroy.
  item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;
  rc = state_add_item(&am->base_state, item);
  if (rc != CRABS_SUCCESS) data_item_destroy(item);
  return rc;
}

// Append a resource name to an op, growing the three per-resource arrays
// (resources / required_state / next_state) in lockstep — the signing
// canonical form and the executor index them all up to resource_count.
// Zeroed states = PROTOCOL_IDLE, matching the deserializer's default.
EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_op_add_resource(operation_t* op, const char* name) {
  if (!op || !name || name[0] == '\0' || strlen(name) >= CRABS_MAX_USER_ID) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (op->resource_count >= CRABS_MAX_RESOURCES) return CRABS_ERR_OOM;
  uint32_t grown_count = op->resource_count + 1;
  char (*grown_resources)[CRABS_MAX_USER_ID] = realloc(
      op->resources, grown_count * CRABS_MAX_USER_ID);
  if (grown_resources == NULL) return CRABS_ERR_OOM;
  op->resources = grown_resources;
  protocol_state_e* grown_required = realloc(
      op->required_state, grown_count * sizeof(protocol_state_e));
  if (grown_required == NULL) return CRABS_ERR_OOM;
  op->required_state = grown_required;
  protocol_state_e* grown_next = realloc(
      op->next_state, grown_count * sizeof(protocol_state_e));
  if (grown_next == NULL) return CRABS_ERR_OOM;
  op->next_state = grown_next;
  memset(op->resources[op->resource_count], 0, CRABS_MAX_USER_ID);
  strncpy(op->resources[op->resource_count], name, CRABS_MAX_USER_ID - 1);
  op->required_state[op->resource_count] = PROTOCOL_IDLE;
  op->next_state[op->resource_count] = PROTOCOL_IDLE;
  op->resource_count = grown_count;
  return CRABS_SUCCESS;
}

// Set the sovereign chain prefix at `prefix_index` (item_seq + 32-byte
// prev_item_digest). The prefix array is parallel to the op's sovereign
// resources in declaration order; setting index i grows the count to i + 1.
// Sign AFTER setting — signing format v4 binds the prefixes.
EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_op_set_sovereign_prefix(operation_t* op,
                                                 uint32_t prefix_index,
                                                 uint64_t item_seq,
                                                 const uint8_t* digest) {
  if (!op || !digest) return CRABS_ERR_INVALID_PARAM;
  if (prefix_index >= CRABS_MAX_RESOURCES) return CRABS_ERR_INVALID_PARAM;
  op->sovereign_prefixes[prefix_index].item_seq = item_seq;
  memcpy(op->sovereign_prefixes[prefix_index].prev_item_digest, digest,
         CRABS_HASH_SIZE);
  if (op->sovereign_prefix_count < prefix_index + 1) {
    op->sovereign_prefix_count = prefix_index + 1;
  }
  return CRABS_SUCCESS;
}

// Chain-head read pair for SOVEREIGN writers composing their next op: a
// signed prefix must claim the item's CURRENT item_seq and item_digest
// (DOMAIN_CHECK compares both). The devtools snapshot ships only the first
// 8 digest bytes (an eyeball head), so the full 32 bytes come from here.
// crabs_wasm_item_chain_seq returns -1 for an unknown item (the digest
// getter reports the failure as CRABS_ERR_RESOURCE_NOT_FOUND).
EMSCRIPTEN_KEEPALIVE
int64_t crabs_wasm_item_chain_seq(attribute_machine_t* am, const char* name) {
  if (!am || !name) return -1;
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item) return -1;
  return (int64_t)item->item_seq;
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_item_chain_digest(attribute_machine_t* am,
                                           const char* name,
                                           uint8_t* out_digest) {
  if (!am || !name || !out_digest) return CRABS_ERR_INVALID_PARAM;
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item) return CRABS_ERR_RESOURCE_NOT_FOUND;
  memcpy(out_digest, item->item_digest, CRABS_HASH_SIZE);
  return CRABS_SUCCESS;
}

// Fill a caller-created __report_equivocation__ op with the evidence
// payload for `item_name`: u8 version + string16 item + string16 writer
// (read from the item — a forged writer field can never parse) + bytes32
// op_a + bytes32 op_b, plus a fresh uuid. The caller then sets the signer,
// signs (crabs_wasm_sign_with_node_key or a KeyPair) and executes — the
// same compose/sign/execute idiom as every other wasm op.
EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_report_equivocation(attribute_machine_t* am,
                                             operation_t* op,
                                             const char* item_name,
                                             const uint8_t* op_a,
                                             uint32_t op_a_len,
                                             const uint8_t* op_b,
                                             uint32_t op_b_len) {
  if (!am || !op || !item_name || !op_a || !op_b) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (op_a_len == 0 || op_b_len == 0) return CRABS_ERR_INVALID_PARAM;
  data_item_t* item = state_find_item(&am->base_state, item_name);
  if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
  if (item->write_domain != CRABS_DOMAIN_SOVEREIGN ||
      item->writer[0] == '\0') {
    return CRABS_ERR_INVALID_PARAM;
  }

  uint32_t item_len = (uint32_t)strlen(item_name);
  uint32_t writer_len = (uint32_t)strlen(item->writer);
  if (item_len == 0 || item_len > UINT16_MAX || writer_len > UINT16_MAX) {
    return CRABS_ERR_INVALID_PARAM;
  }
  uint64_t payload_len64 = 1ull + 2 + item_len + 2 + writer_len +
                           4 + op_a_len + 4 + op_b_len;
  if (payload_len64 > UINT32_MAX) return CRABS_ERR_OOM;
  uint32_t payload_len = (uint32_t)payload_len64;
  uint8_t* payload = (uint8_t*)malloc(payload_len);
  if (payload == NULL) return CRABS_ERR_OOM;
  uint32_t offset = 0;
  payload[offset++] = 0x01;
  payload[offset++] = (uint8_t)(item_len & 0xFF);
  payload[offset++] = (uint8_t)((item_len >> 8) & 0xFF);
  memcpy(payload + offset, item_name, item_len);
  offset += item_len;
  payload[offset++] = (uint8_t)(writer_len & 0xFF);
  payload[offset++] = (uint8_t)((writer_len >> 8) & 0xFF);
  memcpy(payload + offset, item->writer, writer_len);
  offset += writer_len;
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    payload[offset++] = (uint8_t)((op_a_len >> (8 * byte_index)) & 0xFF);
  }
  memcpy(payload + offset, op_a, op_a_len);
  offset += op_a_len;
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    payload[offset++] = (uint8_t)((op_b_len >> (8 * byte_index)) & 0xFF);
  }
  memcpy(payload + offset, op_b, op_b_len);
  offset += op_b_len;

  crypto_random_bytes(op->uuid, CRABS_UUID_SIZE);
  if (op->payload != NULL) free(op->payload);
  op->payload = payload;
  op->payload_size = payload_len;
  return CRABS_SUCCESS;
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_set_policy(attribute_machine_t* am, const char* op_type, const char* expr) {
  return state_add_policy(&am->base_state, op_type, expr);
}

EMSCRIPTEN_KEEPALIVE
int64_t crabs_wasm_get_counter(attribute_machine_t* am, const char* name) {
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item || item->crdt_type != CRDT_G_COUNTER) return 0;
  return g_counter_value((g_counter_t*)item->value);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_increment_counter(attribute_machine_t* am, const char* name,
                                           int64_t delta, const char* node_id) {
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item || item->crdt_type != CRDT_G_COUNTER) return CRABS_ERR_RESOURCE_NOT_FOUND;
  return g_counter_increment((g_counter_t*)item->value, node_id, delta);
}

EMSCRIPTEN_KEEPALIVE
int64_t crabs_wasm_get_pn_counter(attribute_machine_t* am, const char* name) {
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item || item->crdt_type != CRDT_PN_COUNTER) return 0;
  return pn_counter_value((pn_counter_t*)item->value);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_increment_pn_counter(attribute_machine_t* am, const char* name,
                                              int64_t delta, const char* node_id) {
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item || item->crdt_type != CRDT_PN_COUNTER) return CRABS_ERR_RESOURCE_NOT_FOUND;
  return pn_counter_increment((pn_counter_t*)item->value, node_id, delta);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_decrement_pn_counter(attribute_machine_t* am, const char* name,
                                              int64_t delta, const char* node_id) {
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item || item->crdt_type != CRDT_PN_COUNTER) return CRABS_ERR_RESOURCE_NOT_FOUND;
  return pn_counter_decrement((pn_counter_t*)item->value, node_id, delta);
}

EMSCRIPTEN_KEEPALIVE
int64_t crabs_wasm_get_register(attribute_machine_t* am, const char* name) {
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item || item->crdt_type != CRDT_LWW_REG) return 0;
  lww_register_t* reg = (lww_register_t*)item->value;
  if (!reg || !reg->value || reg->value_size < sizeof(int64_t)) return 0;
  return *(int64_t*)reg->value;
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_set_register(attribute_machine_t* am, const char* name,
                                      int64_t value, const char* node_id) {
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item || item->crdt_type != CRDT_LWW_REG) return CRABS_ERR_RESOURCE_NOT_FOUND;
  lww_register_t* reg = (lww_register_t*)item->value;
  if (!reg) return CRABS_ERR_INTERNAL;
  if (reg->value) free(reg->value);
  reg->value = (uint8_t*)malloc(sizeof(int64_t));
  if (!reg->value) return CRABS_ERR_OOM;
  memcpy(reg->value, &value, sizeof(int64_t));
  reg->value_size = sizeof(int64_t);
  reg->timestamp = am->base_state.version + 1;
  strncpy(reg->node_id, node_id, CRABS_MAX_USER_ID - 1);
  reg->node_id[CRABS_MAX_USER_ID - 1] = '\0';
  am->base_state.version++;
  return CRABS_SUCCESS;
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_set_register_bytes(attribute_machine_t* am, const char* name,
                                            const uint8_t* data, uint32_t len,
                                            const char* node_id) {
  if (len > 0 && !data) return CRABS_ERR_INTERNAL;
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item || item->crdt_type != CRDT_LWW_REG) return CRABS_ERR_RESOURCE_NOT_FOUND;
  lww_register_t* reg = (lww_register_t*)item->value;
  if (!reg) return CRABS_ERR_INTERNAL;
  uint8_t* copy = NULL;
  if (len > 0) {
    copy = (uint8_t*)malloc(len);
    if (!copy) return CRABS_ERR_OOM;
    memcpy(copy, data, len);
  }
  if (reg->value) free(reg->value);
  reg->value = copy;
  reg->value_size = len;
  reg->timestamp = am->base_state.version + 1;
  strncpy(reg->node_id, node_id, CRABS_MAX_USER_ID - 1);
  reg->node_id[CRABS_MAX_USER_ID - 1] = '\0';
  am->base_state.version++;
  return CRABS_SUCCESS;
}

EMSCRIPTEN_KEEPALIVE
bool crabs_wasm_set_contains(attribute_machine_t* am, const char* name, const char* element) {
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item) return false;
  if (item->crdt_type == CRDT_OR_SET)
    return or_set_contains((or_set_t*)item->value, element);
  if (item->crdt_type == CRDT_ONE_SHOT_SET)
    return one_shot_set_contains((one_shot_set_t*)item->value, element);
  return false;
}


EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_set_add(attribute_machine_t* am, const char* name,
                                 const char* element, const char* tag) {
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item) return CRABS_ERR_RESOURCE_NOT_FOUND;
  if (item->crdt_type == CRDT_OR_SET)
    return or_set_add((or_set_t*)item->value, element, tag ? tag : element);
  if (item->crdt_type == CRDT_ONE_SHOT_SET)
    return one_shot_set_add((one_shot_set_t*)item->value, element);
  return CRABS_ERR_TYPE_MISMATCH;
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_set_remove(attribute_machine_t* am, const char* name, const char* element) {
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item) return CRABS_ERR_RESOURCE_NOT_FOUND;
  if (item->crdt_type == CRDT_OR_SET)
    or_set_remove((or_set_t*)item->value, element);
  return CRABS_SUCCESS;
}

EMSCRIPTEN_KEEPALIVE
bool crabs_wasm_one_shot_flag_value(attribute_machine_t* am, const char* name) {
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item || item->crdt_type != CRDT_ONE_SHOT_FLAG) return false;
  return one_shot_flag_value((one_shot_flag_t*)item->value);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_one_shot_flag_set(attribute_machine_t* am, const char* name,
                                           const char* set_by, uint64_t set_at) {
  data_item_t* item = state_find_item(&am->base_state, name);
  if (!item || item->crdt_type != CRDT_ONE_SHOT_FLAG) return CRABS_ERR_RESOURCE_NOT_FOUND;
  one_shot_flag_set((one_shot_flag_t*)item->value, set_by, set_at);
  return CRABS_SUCCESS;
}

// ============================================================
// Time / temp attrs
// ============================================================

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_set_time(attribute_machine_t* am, uint64_t now_ms) {
  if (am) attribute_machine_set_time(am, now_ms);
}

EMSCRIPTEN_KEEPALIVE
uint32_t crabs_wasm_prune_expired_temp_attrs(attribute_machine_t* am) {
  if (!am) return 0;
  return attribute_machine_prune_expired_temporary(am);
}

// Select the time source for this machine (mirrors the CLI's
// `time-source https [url]` / `time-source system` and the node binding's
// setTimeSource). `mode` is CRABS_WASM_TIME_SOURCE_SYSTEM or
// CRABS_WASM_TIME_SOURCE_HTTPS; anything else changes nothing. `url` is a
// (pointer, length) byte pair — a NULL pointer or zero length selects the
// default endpoint (the JS wrapper passes UTF-8 bytes without a NUL, so the
// string is bounded-copied into a local buffer before use).
//
// The u64 scalars are passed through AS-IS: a NON-NULL config's values have
// no defaults applied by crabs_time_source_https_create (resync 0 = re-query
// every fetch; max_skew 0 disables the plausibility bound), so the JS
// wrapper spells CRABS_TIME_SOURCE_DEFAULT_* out for omitted options. See
// the module-scoped slot contract in the section comment above
// _time_source_register_machine. No fetch happens at attach time; the first
// query runs lazily inside authenticated-time checks, and a fetch failure
// fails closed (R7-02) — a machine with an unreachable source reports
// invalid time, never local-clock fallback.
EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_set_time_source(attribute_machine_t* am, int mode,
                                         const uint8_t* url, uint32_t url_len,
                                         uint64_t resync_ms,
                                         uint64_t timeout_ms,
                                         uint64_t max_skew_ms) {
  if (am == NULL) return CRABS_ERR_INVALID_PARAM;

  if (mode == CRABS_WASM_TIME_SOURCE_SYSTEM) {
    state_set_time_source(&am->base_state, NULL);
    _time_source_unregister_machine(am);
    return CRABS_SUCCESS;
  }
  if (mode != CRABS_WASM_TIME_SOURCE_HTTPS) return CRABS_ERR_INVALID_PARAM;

  // Defensive URL validation: the JS wrapper already rejects bad URLs before
  // calling in, but a rejected call must change NOTHING (mirrors the CLI's
  // reject-before-mutating contract) so the shape check is repeated here —
  // https scheme, non-empty host, bounded length. The native transport's
  // _parse_url is not compiled into the wasm build, so the checks must live
  // in this helper (the JS glue's js_fetch_server_time also enforces
  // https:// as the last line of defense).
  char url_buffer[CRABS_WASM_TIME_SOURCE_URL_MAX + 1];
  const char* configured_url = NULL;
  if (url != NULL && url_len > 0) {
    if (url_len > CRABS_WASM_TIME_SOURCE_URL_MAX) return CRABS_ERR_INVALID_PARAM;
    memcpy(url_buffer, url, url_len);
    url_buffer[url_len] = '\0';
    if (strncmp(url_buffer, "https://", 8) != 0 || url_buffer[8] == '\0' ||
        url_buffer[8] == '/' || url_buffer[8] == ':') {
      return CRABS_ERR_INVALID_PARAM;
    }
    configured_url = url_buffer;
  }

  crabs_time_source_config_t config;
  config.server_url = configured_url;  // create() copies it before returning
  config.resync_interval_ms = resync_ms;
  config.timeout_ms = timeout_ms;
  config.max_skew_ms = max_skew_ms;
  crabs_time_source_ops_t* fresh = crabs_time_source_https_create(&config);
  if (fresh == NULL) {
    // Allocation failure: leave the target machine on NO source rather than
    // silently falling back to the system clock (fail closed, R7-02).
    // Machines that were already attached keep the existing module ops.
    state_set_time_source(&am->base_state, NULL);
    _time_source_unregister_machine(am);
    return CRABS_ERR_OOM;
  }
  crabs_error_e registered = _time_source_register_machine(am);
  if (registered != CRABS_SUCCESS) {
    crabs_time_source_destroy(fresh);
    state_set_time_source(&am->base_state, NULL);
    _time_source_unregister_machine(am);
    return registered;
  }
  // Attach the fresh ops to the whole attached-set (the target machine is in
  // it now), THEN retire the previous module-owned ops.
  for (uint32_t index = 0; index < s_time_source_machine_count; index++) {
    state_set_time_source(&s_time_source_machines[index]->base_state, fresh);
  }
  if (s_time_source_ops != NULL) {
    crabs_time_source_destroy(s_time_source_ops);
  }
  s_time_source_ops = fresh;
  return CRABS_SUCCESS;
}

// Honest per-machine view for the JS getTimeSource echo: whether this
// machine's HLC state currently has a time source attached (in the wasm
// build that source is always the module-owned ops).
EMSCRIPTEN_KEEPALIVE
bool crabs_wasm_time_source_attached(attribute_machine_t* am) {
  return am != NULL && am->base_state.hlc_state.time_source_ops != NULL;
}

// ============================================================
// User queries
// ============================================================

EMSCRIPTEN_KEEPALIVE
user_t* crabs_wasm_find_user(attribute_machine_t* am, const char* user_id) {
  return am ? attribute_machine_find_user(am, user_id) : NULL;
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_user_id(user_t* user) {
  return user ? user->user_id : NULL;
}

EMSCRIPTEN_KEEPALIVE
uint32_t crabs_wasm_user_attr_count(user_t* user) {
  return user ? user->attribute_count : 0;
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_user_attr_value(user_t* user, uint32_t i) {
  if (!user || i >= user->attribute_count) return NULL;
  return user->attributes[i].value;
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_user_temp_attr_name(user_t* user) {
  return (user && user->temp_attrs) ? user->temp_attrs->name : NULL;
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_user_temp_attr_value(user_t* user) {
  return (user && user->temp_attrs) ? user->temp_attrs->value : NULL;
}

// ============================================================
// ABE helpers
// ============================================================

EMSCRIPTEN_KEEPALIVE
abe_ciphertext_t* crabs_wasm_abe_encrypt(attribute_machine_t* am,
                                         const uint8_t* data, uint32_t len,
                                         const char* policy) {
  if (!am || !data || !policy) return NULL;
  return crypto_abe_encrypt((abe_master_key_t*)am->base_state.abe_mk, data, len, policy);
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_abe_ciphertext_policy(abe_ciphertext_t* ct) {
  return crypto_abe_ciphertext_get_policy(ct);
}

EMSCRIPTEN_KEEPALIVE
const uint8_t* crabs_wasm_abe_ciphertext_data(abe_ciphertext_t* ct, uint32_t* out_len) {
  size_t len = 0;
  const uint8_t* data = crypto_abe_ciphertext_get_data(ct, &len);
  if (out_len) *out_len = (uint32_t)len;
  return data;
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_abe_ciphertext_destroy(abe_ciphertext_t* ct) {
  if (ct) crypto_abe_ciphertext_destroy(ct);
}

// ============================================================
// State serialization (for future catch-up; not required for v1)
// ============================================================

EMSCRIPTEN_KEEPALIVE
serialized_buffer_t* crabs_wasm_serialize_state(attribute_machine_t* am) {
  return am ? crabs_serialize_state(&am->base_state) : NULL;
}

// ============================================================
// User-defined operation handler registry
// ============================================================

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_register_handler(attribute_machine_t* am,
                                           const char* op_type,
                                           op_handler_fn handler) {
  if (am == NULL || op_type == NULL || handler == NULL) return CRABS_ERR_INVALID_PARAM;
  return state_machine_register_handler(&am->base_state, op_type, handler);
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_unregister_handler(attribute_machine_t* am, const char* op_type) {
  if (am == NULL || op_type == NULL) return;
  state_machine_unregister_handler(&am->base_state, op_type);
}

// ============================================================
// Handler context helpers
//
// User-defined handlers receive (state_t*, operation_t*). The state helpers
// below let a JS handler obtain the attribute_machine_t* needed by the
// name-based mutation helpers and read the operation fields.
// ============================================================

EMSCRIPTEN_KEEPALIVE
attribute_machine_t* crabs_wasm_handler_get_am(state_t* state) {
  return state ? state->attr_machine : NULL;
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_handler_op_get_payload_str(operation_t* op) {
  if (op == NULL || op->payload == NULL || op->payload_size == 0) return NULL;
  // Ensure null termination for JSON/string payloads. The operation payload
  // is a byte buffer; if it is not null-terminated we cannot safely expose it
  // as a C string. Demo payloads are null-terminated JSON strings.
  if (op->payload[op->payload_size - 1] != '\0') return NULL;
  return (const char*)op->payload;
}

// ============================================================
// Timed transactions (v1)
// ============================================================

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_schedule(attribute_machine_t* am, operation_t* inner_op,
                             uint64_t execute_at_ms) {
  if (!am || !inner_op) return 0;
  // Submission-time authorization: the op must already be signed by an
  // authorized signer (mirrors the __schedule__ op path). Read-only checks.
  if (state_machine_validate(&am->base_state, inner_op) != CRABS_SUCCESS) {
    return 0;
  }
  return scheduler_schedule(&am->base_state, execute_at_ms,
                            inner_op->signer_id, inner_op);
}

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_schedule_recurring(attribute_machine_t* am, operation_t* inner_op,
                                       uint64_t start_at_ms, uint64_t interval_ms,
                                       uint64_t repeat_count, uint64_t end_at_ms) {
  if (!am || !inner_op) return 0;
  // Submission-time authorization (mirrors crabs_wasm_schedule). Read-only.
  if (state_machine_validate(&am->base_state, inner_op) != CRABS_SUCCESS) {
    return 0;
  }
  return scheduler_schedule_recurring(&am->base_state, start_at_ms, interval_ms,
                                      repeat_count, end_at_ms,
                                      inner_op->signer_id, inner_op);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_cancel_schedule(attribute_machine_t* am, uint64_t schedule_id) {
  if (!am) return CRABS_ERR_INVALID_PARAM;
  return scheduler_cancel(&am->base_state, schedule_id);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_process_schedules(attribute_machine_t* am, uint64_t now_ms) {
  if (!am) return CRABS_ERR_INVALID_PARAM;
  return scheduler_process_due(&am->base_state, now_ms);
}

EMSCRIPTEN_KEEPALIVE
uint32_t crabs_wasm_schedule_count(attribute_machine_t* am) {
  return am ? scheduler_count(&am->base_state) : 0;
}

EMSCRIPTEN_KEEPALIVE
const scheduled_operation_t* crabs_wasm_schedule_first(attribute_machine_t* am) {
  return am ? scheduler_first(&am->base_state) : NULL;
}

EMSCRIPTEN_KEEPALIVE
const scheduled_operation_t* crabs_wasm_schedule_next(const scheduled_operation_t* entry) {
  return entry ? entry->next : NULL;
}

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_schedule_id(const scheduled_operation_t* entry) {
  return entry ? entry->schedule_id : 0;
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_set_schedule_occurrence_budget(attribute_machine_t* am,
                                               uint32_t max_occurrences) {
  if (!am) return;
  scheduler_set_max_occurrences_per_tick(&am->base_state, max_occurrences);
}

EMSCRIPTEN_KEEPALIVE
uint32_t crabs_wasm_schedule_occurrence_budget(attribute_machine_t* am) {
  return am ? am->base_state.max_occurrences_per_tick : 0;
}

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_schedule_execute_at(const scheduled_operation_t* entry) {
  return entry ? entry->execute_at_ms : 0;
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_schedule_submitter(const scheduled_operation_t* entry) {
  return entry ? entry->submitter : NULL;
}

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_schedule_interval(const scheduled_operation_t* entry) {
  return entry ? entry->interval_ms : 0;
}

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_schedule_repeat_count(const scheduled_operation_t* entry) {
  return entry ? entry->repeat_count : 0;
}

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_schedule_end_at(const scheduled_operation_t* entry) {
  return entry ? entry->end_at_ms : 0;
}

// ============================================================
// Lineage (v1.7: machines mint machines)
// ============================================================
// Blueprint authoring, spawn, child-manifest accessors, and attestation
// issuance for the JS wrapper. Lineage is CORE data — none of the exports
// below are devtools-gated and both wasm build variants carry them.
//
// Pointer ownership across the JS boundary:
//   - machine_blueprint_t*       — owned by the JS Blueprint wrapper, which
//                                  releases it via ..._blueprint_destroy.
//   - attribute_machine_t*       — never owned by JS. Every spawned child
//                                  stays in the PARENT's resident-children
//                                  registry (lineage_spawn_machine registers
//                                  it); the returned pointer is borrowed for
//                                  immediate use and the registry is the
//                                  lifetime anchor — re-resolve through
//                                  crabs_wasm_lineage_query_resident_child
//                                  instead of stashing pointers.
//   - child manifest strings     — owned by the parent state; borrow within
//                                  the call that obtained the index.
//
// Int-valued enums (trust mode, data type, CRDT strategy) are ints on the
// wire to keep the JS side free of C enum tables; the same numeric values
// the header comments document (e.g. LINEAGE_DELEGATED_COPY = 0x02) apply.

EMSCRIPTEN_KEEPALIVE
machine_blueprint_t* crabs_wasm_lineage_blueprint_new(
    attribute_machine_t* am, const char* child_id, int trust_mode,
    const char* bootstrap_admin, uint64_t attestation_ttl_ms) {
  // `am` is accepted for call-site symmetry with the other lineage exports
  // (spawn / attest), which do take the parent machine; blueprint authoring
  // is a standalone object build and does not read the parent.
  (void)am;
  if (child_id == NULL || bootstrap_admin == NULL) return NULL;
  machine_blueprint_t* blueprint = machine_blueprint_create();
  if (blueprint == NULL) return NULL;
  strncpy(blueprint->child_id, child_id, CRABS_MAX_USER_ID - 1);
  blueprint->child_id[CRABS_MAX_USER_ID - 1] = '\0';
  blueprint->trust_mode = (lineage_trust_mode_e)trust_mode;
  strncpy(blueprint->bootstrap_admin, bootstrap_admin, CRABS_MAX_USER_ID - 1);
  blueprint->bootstrap_admin[CRABS_MAX_USER_ID - 1] = '\0';
  blueprint->attestation_ttl_ms = attestation_ttl_ms;
  return blueprint;
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_lineage_blueprint_destroy(machine_blueprint_t* blueprint) {
  if (blueprint) machine_blueprint_destroy(blueprint);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_lineage_blueprint_add_item(
    machine_blueprint_t* blueprint, const char* name, int data_type,
    int crdt_type) {
  if (!blueprint || !name) return CRABS_ERR_INVALID_PARAM;
  return blueprint_add_item(blueprint, name, (data_type_e)data_type,
                            (crdt_type_e)crdt_type);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_lineage_blueprint_add_policy(
    machine_blueprint_t* blueprint, const char* operation,
    const char* expression) {
  if (!blueprint || !operation || !expression) return CRABS_ERR_INVALID_PARAM;
  return blueprint_add_policy(blueprint, operation, expression);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_lineage_blueprint_stamp_hash(
    machine_blueprint_t* blueprint) {
  if (!blueprint) return CRABS_ERR_INVALID_PARAM;
  return machine_blueprint_stamp_hash(blueprint);
}

EMSCRIPTEN_KEEPALIVE
serialized_buffer_t* crabs_wasm_lineage_blueprint_serialize(
    machine_blueprint_t* blueprint) {
  if (!blueprint) return NULL;
  serialized_buffer_t* buffer = serialized_buffer_create(CRABS_BLUEPRINT_WIRE_MAX);
  if (buffer == NULL) return NULL;
  size_t written = blueprint_serialize(blueprint, buffer->data,
                                       CRABS_BLUEPRINT_WIRE_MAX);
  if (written == 0) {
    serialized_buffer_destroy(buffer);
    return NULL;
  }
  buffer->len = written;
  return buffer;
}

EMSCRIPTEN_KEEPALIVE
machine_blueprint_t* crabs_wasm_lineage_blueprint_deserialize(
    const uint8_t* data, uint32_t len) {
  if (data == NULL || len == 0) return NULL;
  return blueprint_deserialize(data, (size_t)len);
}

EMSCRIPTEN_KEEPALIVE
attribute_machine_t* crabs_wasm_lineage_spawn(attribute_machine_t* am,
                                             machine_blueprint_t* blueprint) {
  if (am == NULL || blueprint == NULL) return NULL;
  attribute_machine_t* child = NULL;
  if (lineage_spawn_machine(&am->base_state, blueprint, &child) !=
      CRABS_SUCCESS) {
    return NULL;
  }
  // Child ownership stays in the parent's resident-children registry (the
  // lifetime anchor); JS borrows the pointer from the registry via
  // crabs_wasm_lineage_query_resident_child instead of stashing it.
  return child;
}

EMSCRIPTEN_KEEPALIVE
attribute_machine_t* crabs_wasm_lineage_query_resident_child(
    attribute_machine_t* am, const char* child_id) {
  if (am == NULL || child_id == NULL) return NULL;
  return lineage_query_resident_child(&am->base_state, child_id);
}

// Borrowed entry accessor for the flat index accessors below. Returns the
// manifest entry at `index`, or NULL when the index is out of range.
static const child_manifest_entry_t* _lineage_children_at(
    attribute_machine_t* am, uint32_t index) {
  if (am == NULL) return NULL;
  const child_manifest_entry_t* entries = NULL;
  const uint32_t count = lineage_query_children(&am->base_state, &entries);
  if (entries == NULL || index >= count) return NULL;
  return &entries[index];
}

EMSCRIPTEN_KEEPALIVE
uint32_t crabs_wasm_lineage_children_count(attribute_machine_t* am) {
  if (am == NULL) return 0;
  const child_manifest_entry_t* entries = NULL;
  return lineage_query_children(&am->base_state, &entries);
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_lineage_children_get_id(attribute_machine_t* am,
                                              uint32_t index) {
  const child_manifest_entry_t* entry = _lineage_children_at(am, index);
  return entry ? entry->child_id : NULL;
}

// Mode / status are rendered through lineage_mode_name / lineage_status_name
// (the single human-name source shared with the CLI and devtools); values
// outside the enums render as "unknown".

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_lineage_children_get_mode(attribute_machine_t* am,
                                                uint32_t index) {
  const child_manifest_entry_t* entry = _lineage_children_at(am, index);
  return entry ? lineage_mode_name(entry->mode) : NULL;
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_lineage_children_get_status(attribute_machine_t* am,
                                                  uint32_t index) {
  const child_manifest_entry_t* entry = _lineage_children_at(am, index);
  return entry ? lineage_status_name(entry->status) : NULL;
}

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_lineage_children_get_ttl_ms(attribute_machine_t* am,
                                               uint32_t index) {
  const child_manifest_entry_t* entry = _lineage_children_at(am, index);
  return entry ? entry->attestation_ttl_ms : 0;
}

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_lineage_children_get_spawned_at(attribute_machine_t* am,
                                                   uint32_t index) {
  const child_manifest_entry_t* entry = _lineage_children_at(am, index);
  return entry ? entry->spawned_at : 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t crabs_wasm_lineage_find_manifest_entry(attribute_machine_t* am,
                                              const char* child_id) {
  if (am == NULL || child_id == NULL) return -1;
  // The manifest scan is the landed accessor's job (single source, shared
  // with the CLI); the export only translates the borrowed entry pointer
  // into the flat index the JS surface accesses entries through.
  const child_manifest_entry_t* matched =
      lineage_find_manifest_entry(&am->base_state, child_id);
  if (matched == NULL) return -1;
  const child_manifest_entry_t* entries = NULL;
  const uint32_t count = lineage_query_children(&am->base_state, &entries);
  if (entries == NULL || count == 0) return -1;
  return (int32_t)(matched - entries);
}

// Issue a parent-signed attestation for an ACTIVE manifest child and return
// its wire image (u32le length + canonical body + signature) as a
// serialized_buffer_t. now_ms comes from the parent's time source
// (state_get_time_ms); when no source reports a valid time the attestation is
// minted with now_ms = 0, so its window starts at epoch 0 and ends at
// now + ttl — usable for local testing, but consumers needing an
// authenticated window must configure a time source on the node first.
EMSCRIPTEN_KEEPALIVE
serialized_buffer_t* crabs_wasm_lineage_attest(attribute_machine_t* am,
                                              const char* child_id,
                                              const char* user_id,
                                              const char* attributes) {
  if (am == NULL || child_id == NULL || user_id == NULL ||
      attributes == NULL) {
    return NULL;
  }
  uint64_t now_ms = 0;
  (void)state_get_time_ms(&am->base_state, &now_ms);
  attestation_t attestation;
  if (crabs_issue_attestation(&am->base_state, &attestation, child_id, user_id,
                              attributes, now_ms) != CRABS_SUCCESS) {
    return NULL;
  }
  serialized_buffer_t* buffer = serialized_buffer_create(CRABS_ATTESTATION_WIRE_MAX);
  if (buffer == NULL) return NULL;
  size_t written = attestation_serialize(&attestation, buffer->data,
                                         CRABS_ATTESTATION_WIRE_MAX);
  if (written == 0) {
    serialized_buffer_destroy(buffer);
    return NULL;
  }
  buffer->len = written;
  return buffer;
}

// Mint a dissolution tombstone for a DISSOLVED manifest child and return its
// wire image (canonical body `u8 tag LINEAGE_DISSOLVED + string16 child_id +
// u64le parent_key_version` + the 64-byte parent ECDSA signature, NO length
// prefix) as a
// serialized_buffer_t. There is deliberately no JS-visible honesty precheck:
// resolving the manifest entry and refusing anything but DISSOLVED is the C
// gate inside lineage_dissolution_serialize, so a non-dissolved child simply
// yields NULL (JS throws) exactly like the attest refusal does.
EMSCRIPTEN_KEEPALIVE
serialized_buffer_t* crabs_wasm_lineage_tombstone(attribute_machine_t* am,
                                                 const char* child_id) {
  if (am == NULL || child_id == NULL) {
    return NULL;
  }
  serialized_buffer_t* buffer =
      serialized_buffer_create(CRABS_DISSOLUTION_WIRE_MAX);
  if (buffer == NULL) return NULL;
  size_t written = 0;
  if (lineage_dissolution_serialize(&am->base_state, child_id, buffer->data,
                                    CRABS_DISSOLUTION_WIRE_MAX,
                                    &written) != CRABS_SUCCESS) {
    serialized_buffer_destroy(buffer);
    return NULL;
  }
  buffer->len = written;
  return buffer;
}

// Register the four lineage ops (__spawn_machine__ / __revoke_attestation__ /
// __dissolve_machine__ / __withdraw_genesis__) + their default admin policies
// on this machine. After this, JS submits those ops through the ordinary
// crabs_wasm_execute path, composing __spawn_machine__ ops by stamping
// crabs_wasm_lineage_blueprint_serialize bytes into the op payload.
EMSCRIPTEN_KEEPALIVE
void crabs_wasm_register_lineage_ops(attribute_machine_t* am) {
  if (am == NULL) return;
  lineage_install(&am->base_state);
}

// ============================================================
// Devtools (only present in builds with CRABS_ENABLE_DEVTOOLS)
// ============================================================

#ifdef CRABS_ENABLE_DEVTOOLS

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_devtools_snapshot(attribute_machine_t* am) {
  if (!am) return NULL;
  return devtools_snapshot_json(&am->base_state);
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_devtools_drain_events(void) {
  return devtools_events_json();
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_devtools_drain_events_for(const char* node_id) {
  return devtools_events_json_for(node_id);
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_devtools_string_destroy(const char* str) {
  free((void*)str);
}

#endif // CRABS_ENABLE_DEVTOOLS

#endif /* __EMSCRIPTEN__ */
