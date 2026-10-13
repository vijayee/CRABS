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
#include "../Raft/raft_module.h"

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

// The op format version this op carries. Freshly created ops report the
// build's CRABS_OP_FORMAT_VERSION; deserialized ops report the version they
// declared on the wire (validated 1..CRABS_OP_FORMAT_VERSION at parse time).
EMSCRIPTEN_KEEPALIVE
uint32_t crabs_wasm_op_get_wire_version(const operation_t* op) {
  return op ? op->op_version : 0;
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_op_init_uuid(operation_t* op) {
  if (!op) return;
  crypto_random_bytes(op->uuid, CRABS_UUID_SIZE);
}

// ============================================================
// Wire-version diagnostics (consumption-fixes finding 5)
// ============================================================
// Mirrors the C-side constants into JS without a handwritten drift-prone
// copy: state wire version (CRABS_SERIAL_VERSION), op format version
// (CRABS_OP_FORMAT_VERSION), signing canonical-form version
// (CRABS_SIGNING_FORMAT_VERSION). Caller passes a 3×u32 buffer; out[0]=state,
// out[1]=op, out[2]=signing.
EMSCRIPTEN_KEEPALIVE
void crabs_wasm_wire_versions(uint32_t* out_versions) {
  if (!out_versions) return;
  out_versions[0] = (uint32_t)CRABS_SERIAL_VERSION;
  out_versions[1] = (uint32_t)CRABS_OP_FORMAT_VERSION;
  out_versions[2] = (uint32_t)CRABS_SIGNING_FORMAT_VERSION;
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

// Forward declaration: the op type registration below reuses the shared
// resources-array growth helper (defined lower, with the write-domains
// surfaces).
crabs_error_e crabs_wasm_op_add_resource(operation_t* op, const char* name);

// ============================================================
// DedupSpec op-type registration (v1.4 §7)
// ============================================================
// Compose, sign and execute a __define_operation_type__ op in one call:
// resources[0] carries the op-type name being registered, op->dedup carries
// the spec (state_machine_op_define_operation copies it into the machine
// registry via state_register_op_type_def). Signing uses the machine's node
// key with the bootstrap admin as the signer — the same
// __create_trigger__/__report_equivocation__ admin-op idiom; the caller
// installs the type's own policy first (setPolicy('__define_operation_type__',
// 'role:admin')) or the executor refuses the op with unauthorized.
//
// Exposed dedup types are the machine-enforceable ones (per-user tracker /
// global flag registrations whose guard+mutation are C-native) plus a 'none'
// registration, which is the documented way to replace (unregister the guard
// of) a previously defined spec — state_register_op_type_def updates the
// entry in place. DEDUP_CUSTOM is deliberately NOT surfaceable from JS: a
// custom spec is guarded AND mutated through the C condition evaluator and
// the spec's state_mutation_t update field, whose targets are C-native
// surfaces (the JS binding would mint specs whose post-handler mutation it
// cannot reason about).
EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_define_operation_type(attribute_machine_t* am,
                                               const char* op_type,
                                               int32_t dedup_type,
                                               const char* tracker_path,
                                               const char* flag_path,
                                               const char* condition,
                                               const char* rejection_message) {
  if (!am || !op_type || op_type[0] == '\0') return CRABS_ERR_INVALID_PARAM;
  dedup_type_e type = (dedup_type_e)dedup_type;
  if (type != DEDUP_NONE && type != DEDUP_PER_USER && type != DEDUP_GLOBAL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (type == DEDUP_PER_USER &&
      (!tracker_path || tracker_path[0] == '\0')) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (type == DEDUP_GLOBAL && (!flag_path || flag_path[0] == '\0')) {
    return CRABS_ERR_INVALID_PARAM;
  }

  operation_t* op = operation_create(CRABS_OP_DEFINE_OPERATION);
  if (!op) return CRABS_ERR_OOM;
  crabs_error_e rc = crabs_wasm_op_add_resource(op, op_type);
  if (rc != CRABS_SUCCESS) {
    operation_destroy(op);
    return rc;
  }
  op->dedup.type = type;
  if (type == DEDUP_PER_USER) {
    strncpy(op->dedup.tracker_path, tracker_path, CRABS_MAX_DEDUP_PATH - 1);
    op->dedup.tracker_path[CRABS_MAX_DEDUP_PATH - 1] = '\0';
  } else if (type == DEDUP_GLOBAL) {
    strncpy(op->dedup.flag_path, flag_path, CRABS_MAX_DEDUP_PATH - 1);
    op->dedup.flag_path[CRABS_MAX_DEDUP_PATH - 1] = '\0';
  }
  // rejection_message is metadata carried on the spec (serialized with it);
  // the enforcement error itself is still the type's domain error.
  if (rejection_message != NULL && rejection_message[0] != '\0') {
    strncpy(op->dedup.rejection_message, rejection_message,
            CRABS_MAX_DEDUP_MESSAGE - 1);
    op->dedup.rejection_message[CRABS_MAX_DEDUP_MESSAGE - 1] = '\0';
  }
  // The state_mutation_t update field stays zeroed: for the surfaceable
  // types the mutation is built-in (tracker membership / flag set) and is
  // applied by dedup_apply_mutation_spec regardless of the update field.

  // Sign with the node key under the bootstrap admin's identity — the
  // admin-op idiom shared with createTrigger/reportEquivocation. Signing
  // stamps HLC and the signer's key_version (crabs_wasm_sign_operation).
  const char* admin_id = am->base_state.config.bootstrap_admin;
  op->signer_id[0] = '\0';
  op->node_id[0] = '\0';
  if (admin_id != NULL && admin_id[0] != '\0') {
    strncpy(op->signer_id, admin_id, CRABS_MAX_USER_ID - 1);
    strncpy(op->node_id, admin_id, CRABS_MAX_USER_ID - 1);
  }
  rc = crabs_wasm_sign_with_node_key(am, op);
  if (rc != CRABS_SUCCESS) {
    operation_destroy(op);
    return rc;
  }
  rc = state_machine_execute(&am->base_state, op);
  operation_destroy(op);
  return rc;
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

EMSCRIPTEN_KEEPALIVE
int64_t crabs_wasm_user_key_version(user_t* user) {
  return user ? (int64_t)user->key_version : 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t crabs_wasm_user_status(user_t* user) {
  return user ? (int32_t)user->status : 0;
}

// Copies the user's legacy 33-byte ECDSA public key into out (the caller
// allocates 33 bytes). Returns the byte count copied, 0 on failure.
EMSCRIPTEN_KEEPALIVE
int32_t crabs_wasm_user_public_key(user_t* user, uint8_t* out) {
  if (!user || !out) return 0;
  memcpy(out, user->public_key, 33);
  return 33;
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_user_attr_verified_by(user_t* user, uint32_t i) {
  if (!user || i >= user->attribute_count) return NULL;
  return user->attributes[i].verified_by;
}

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_user_temp_attr_expires_at(user_t* user) {
  return (user && user->temp_attrs) ? user->temp_attrs->expires_at : 0;
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
// Handler-state read APIs (consumption findings 3-4)
//
// Bounded, paged enumerators for OR-sets / one-shot sets from handler
// context, plus byte-register access. The C helpers hand results back
// through the existing serialized_buffer_t idiom so the JS side can reuse
// _crabs_wasm_buffer_data/_crabs_wasm_buffer_len/_crabs_wasm_buffer_destroy
// verbatim.
//
// String-list wire protocol (used by _set_elements and _set_tags):
//   u16le  count
//   then `count` entries of: u16le byte_length + raw bytes (no NUL).
// Both u16 fields bound the payload: lists longer than 65535 entries and
// strings longer than 65535 bytes are REJECTED by the encoder
// (_handler_encode_string_list returns NULL and the caller surfaces an
// error) rather than silently truncated or mis-decoded JS-side. Strings
// arriving over the wire are already u16-bounded by _write_string16.
//
// Visibility: an OR-set (element, tag) pair is LIVE iff it is not present
// in the set's tombstone list. Enumeration is at the ELEMENT level — i.e.
// DISTINCT visible elements, sorted ascending by byte-wise strcmp for
// cross-replica pagination stability (OR-set insertion order is per-replica
// and is NOT stable under merge). `getSetSize` is the total of that
// distinct-visible-element list, for pagination math.
// ============================================================

#define CRABS_WASM_HANDLER_SET_PAGE_CAP 256u

// One-shot sets already store unique elements; OR-sets may carry the same
// element under several tags (post-Task-1 pair semantics), so the
// distinct-element pass dedupes by element string after tombstone filtering.
static uint32_t _handler_set_live_distinct(const data_item_t* item,
                                           const char*** out_elements) {
  *out_elements = NULL;
  if (item == NULL) return 0;

  uint32_t capacity = 0;
  if (item->crdt_type == CRDT_OR_SET) {
    capacity = ((or_set_t*)item->value)->element_count;
  } else if (item->crdt_type == CRDT_ONE_SHOT_SET) {
    capacity = ((one_shot_set_t*)item->value)->element_count;
  } else {
    return 0;
  }
  if (capacity == 0) return 0;

  const char** elements = (const char**)malloc(capacity * sizeof(const char*));
  if (elements == NULL) return 0;
  uint32_t count = 0;

  if (item->crdt_type == CRDT_OR_SET) {
    const or_set_t* set = (const or_set_t*)item->value;
    for (uint32_t entry_index = 0; entry_index < set->element_count; entry_index++) {
      const char* element = set->elements[entry_index].element;
      const char* tag = set->elements[entry_index].tag;
      // Pair-tombstoned entries are invisible.
      bool tombstoned = false;
      for (uint32_t tombstone_index = 0; tombstone_index < set->tombstone_count;
           tombstone_index++) {
        if (strcmp(set->tombstones[tombstone_index].element, element) == 0 &&
            strcmp(set->tombstones[tombstone_index].tag, tag) == 0) {
          tombstoned = true;
          break;
        }
      }
      if (tombstoned) continue;
      bool seen = false;
      for (uint32_t seen_index = 0; seen_index < count; seen_index++) {
        if (strcmp(elements[seen_index], element) == 0) { seen = true; break; }
      }
      if (!seen) elements[count++] = element;
    }
  } else { // CRDT_ONE_SHOT_SET
    const one_shot_set_t* set = (const one_shot_set_t*)item->value;
    for (uint32_t entry_index = 0; entry_index < set->element_count; entry_index++) {
      bool seen = false;
      for (uint32_t seen_index = 0; seen_index < count; seen_index++) {
        if (strcmp(elements[seen_index], set->elements[entry_index]) == 0) {
          seen = true;
          break;
        }
      }
      if (!seen) elements[count++] = set->elements[entry_index];
    }
  }

  if (count == 0) {
    free(elements);
    return 0;
  }
  *out_elements = elements;
  return count;
}

static int _handler_cstr_cmp(const void* a, const void* b) {
  return strcmp(*(const char* const*)a, *(const char* const*)b);
}

// Encode a string list using the u16-count prefix + u16-length-prefixed
// entries protocol documented above. Returns NULL on failure with *out_rc
// set: CRABS_ERR_SERIALIZATION_ERROR on u16 overflow (count > 65535, any
// string longer than 65535 bytes — overflowing the u16 fields would produce
// a list the JS decoder mis-parses, so oversize is a hard failure, not a
// truncation) or CRABS_ERR_OOM on allocation failure.
static serialized_buffer_t* _handler_encode_string_list(const char** strings,
                                                        uint32_t count,
                                                        uint32_t* out_rc) {
  if (count > 0xFFFF) {
    *out_rc = CRABS_ERR_SERIALIZATION_ERROR;
    return NULL;
  }
  size_t total = 2;
  for (uint32_t entry_index = 0; entry_index < count; entry_index++) {
    const size_t length = strlen(strings[entry_index]);
    if (length > 0xFFFF) {
      *out_rc = CRABS_ERR_SERIALIZATION_ERROR;
      return NULL;
    }
    total += 2 + length;
  }
  serialized_buffer_t* buffer = serialized_buffer_create(total);
  if (buffer == NULL) {
    *out_rc = CRABS_ERR_OOM;
    return NULL;
  }
  uint8_t* cursor = (uint8_t*)buffer->data;
  cursor[0] = (uint8_t)(count & 0xFF);
  cursor[1] = (uint8_t)((count >> 8) & 0xFF);
  cursor += 2;
  for (uint32_t entry_index = 0; entry_index < count; entry_index++) {
    const size_t length = strlen(strings[entry_index]);
    cursor[0] = (uint8_t)(length & 0xFF);
    cursor[1] = (uint8_t)((length >> 8) & 0xFF);
    cursor += 2;
    memcpy(cursor, strings[entry_index], length);
    cursor += length;
  }
  buffer->len = total;
  return buffer;
}

EMSCRIPTEN_KEEPALIVE
uint32_t crabs_wasm_handler_set_size(attribute_machine_t* am, const char* name) {
  if (am == NULL || name == NULL) return 0;
  data_item_t* item = state_find_item(&am->base_state, name);
  if (item == NULL) return 0;
  const char** elements = NULL;
  const uint32_t count = _handler_set_live_distinct(item, &elements);
  if (elements != NULL) free(elements);
  return count;
}

EMSCRIPTEN_KEEPALIVE
serialized_buffer_t* crabs_wasm_handler_set_elements(attribute_machine_t* am,
                                                     const char* name,
                                                     uint32_t offset,
                                                     uint32_t limit,
                                                     uint32_t* out_rc) {
  if (out_rc == NULL) return NULL;
  *out_rc = CRABS_ERR_INTERNAL;
  if (am == NULL || name == NULL) {
    *out_rc = CRABS_ERR_INVALID_PARAM;
    return NULL;
  }
  if (limit == 0 || limit > CRABS_WASM_HANDLER_SET_PAGE_CAP) {
    *out_rc = CRABS_ERR_INVALID_PARAM;
    return NULL;
  }
  data_item_t* item = state_find_item(&am->base_state, name);
  if (item == NULL) {
    *out_rc = CRABS_ERR_RESOURCE_NOT_FOUND;
    return NULL;
  }
  if (item->crdt_type != CRDT_OR_SET && item->crdt_type != CRDT_ONE_SHOT_SET) {
    *out_rc = CRABS_ERR_TYPE_MISMATCH;
    return NULL;
  }

  const char** elements = NULL;
  const uint32_t total = _handler_set_live_distinct(item, &elements);
  if (total == 0) {
    // Empty (or unallocatable) set — encode an empty page.
    return _handler_encode_string_list(NULL, 0, out_rc);
  }
  qsort(elements, total, sizeof(const char*), _handler_cstr_cmp);

  const uint32_t start = offset < total ? offset : total;
  const uint32_t remaining = total - start;
  const uint32_t page_count = remaining < limit ? remaining : limit;

  serialized_buffer_t* buffer =
      _handler_encode_string_list(elements + start, page_count, out_rc);
  free(elements);
  if (buffer == NULL) return NULL;
  *out_rc = CRABS_SUCCESS;
  return buffer;
}

EMSCRIPTEN_KEEPALIVE
serialized_buffer_t* crabs_wasm_handler_set_tags(attribute_machine_t* am,
                                                 const char* name,
                                                 const char* element,
                                                 uint32_t* out_rc) {
  if (out_rc == NULL) return NULL;
  *out_rc = CRABS_ERR_INTERNAL;
  if (am == NULL || name == NULL || element == NULL) {
    *out_rc = CRABS_ERR_INVALID_PARAM;
    return NULL;
  }
  data_item_t* item = state_find_item(&am->base_state, name);
  if (item == NULL) {
    *out_rc = CRABS_ERR_RESOURCE_NOT_FOUND;
    return NULL;
  }
  if (item->crdt_type != CRDT_OR_SET) {
    // Tags are pair-semantics data: only OR-sets carry them. A one-shot set
    // has an element list but no tag axis, so the call is a type mismatch.
    *out_rc = CRABS_ERR_TYPE_MISMATCH;
    return NULL;
  }
  const or_set_t* set = (const or_set_t*)item->value;

  const char** tags = (const char**)malloc(
      (set->element_count ? set->element_count : 1) * sizeof(const char*));
  if (tags == NULL) {
    *out_rc = CRABS_ERR_OOM;
    return NULL;
  }
  uint32_t count = 0;
  for (uint32_t entry_index = 0; entry_index < set->element_count; entry_index++) {
    if (strcmp(set->elements[entry_index].element, element) != 0) continue;
    const char* tag = set->elements[entry_index].tag;
    bool tombstoned = false;
    for (uint32_t tombstone_index = 0; tombstone_index < set->tombstone_count;
         tombstone_index++) {
      if (strcmp(set->tombstones[tombstone_index].element, element) == 0 &&
          strcmp(set->tombstones[tombstone_index].tag, tag) == 0) {
        tombstoned = true;
        break;
      }
    }
    if (tombstoned) continue;
    tags[count++] = tag;
  }
  // Sort ascending so a JS consumer can compare tag lists across replicas
  // without depending on insertion order.
  if (count > 1) qsort(tags, count, sizeof(const char*), _handler_cstr_cmp);
  serialized_buffer_t* buffer = _handler_encode_string_list(tags, count, out_rc);
  free(tags);
  if (buffer == NULL) return NULL;
  *out_rc = CRABS_SUCCESS;
  return buffer;
}

EMSCRIPTEN_KEEPALIVE
serialized_buffer_t* crabs_wasm_handler_get_register_bytes(
    attribute_machine_t* am, const char* name, uint32_t* out_rc) {
  if (out_rc == NULL) return NULL;
  *out_rc = CRABS_ERR_INTERNAL;
  if (am == NULL || name == NULL) {
    *out_rc = CRABS_ERR_INVALID_PARAM;
    return NULL;
  }
  data_item_t* item = state_find_item(&am->base_state, name);
  if (item == NULL) {
    *out_rc = CRABS_ERR_RESOURCE_NOT_FOUND;
    return NULL;
  }
  if (item->crdt_type != CRDT_LWW_REG) {
    *out_rc = CRABS_ERR_TYPE_MISMATCH;
    return NULL;
  }
  const lww_register_t* reg = (const lww_register_t*)item->value;
  if (reg == NULL) {
    *out_rc = CRABS_ERR_INTERNAL;
    return NULL;
  }
  if (reg->value_size == 0) {
    serialized_buffer_t* empty = serialized_buffer_create(0);
    if (empty == NULL) {
      *out_rc = CRABS_ERR_OOM;
      return NULL;
    }
    *out_rc = CRABS_SUCCESS;
    return empty;
  }
  serialized_buffer_t* buffer = serialized_buffer_create(reg->value_size);
  if (buffer == NULL) {
    *out_rc = CRABS_ERR_OOM;
    return NULL;
  }
  memcpy(buffer->data, reg->value, reg->value_size);
  buffer->len = reg->value_size;
  *out_rc = CRABS_SUCCESS;
  return buffer;
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
// Raft ordering module surface
// ============================================================
// The module is a pure reactor (Raft/raft_module.h): the wasm host (the
// bindings-core reference host, or the embedding app replacing its seams)
// drives tick/inbound/propose/persist_complete and drains the outbound
// queues here. Export/import of the module's durable state is NOT a raw
// struct transfer to JS — the state serializer already carries the module's
// state in the v16 machine section (crabs_serialize_state), and attaching a
// fresh module via crabs_raft_create re-imports it through
// state_attach_raft_module. crabs_wasm_raft_recover_from_persist covers the
// remaining restart duty: replaying the host's stored persist batches.
//
// Drain disposal conventions (mirroring raft_module.h):
//   - poll_outbound / poll_notification TRANSFER a copy: the returned
//     envelope buffer is JS-owned, freed with _crabs_wasm_buffer_destroy,
//     and the next poll moves to the next event (drain until NULL).
//   - poll_persist reports a copy of the OUTSTANDING window — the handle
//     stays un-resolved on the module until persist_complete(handle, ok),
//     and the same handle is re-reported while pending. JS must poll ONE
//     window per async storage round and never drain-loop this queue.
//
// Module registry: exports address modules by pointer (this file's idiom —
// raw C object pointers, no integer handles). The registry only remembers
// the machine each module was created for so crabs_raft_destroy can detach
// it from the state before teardown (the state never owns the module
// object).

typedef struct {
  crabs_raft_module_t* module;
  attribute_machine_t* machine;
} raft_module_registry_entry_t;

static raft_module_registry_entry_t* s_raft_modules = NULL;
static uint32_t s_raft_module_count = 0;
static uint32_t s_raft_module_capacity = 0;

static uint32_t _raft_module_index(crabs_raft_module_t* module) {
  for (uint32_t index = 0; index < s_raft_module_count; index++) {
    if (s_raft_modules[index].module == module) return index;
  }
  return UINT32_MAX;
}

static crabs_error_e _raft_module_registry_add(crabs_raft_module_t* module,
                                               attribute_machine_t* am) {
  if (s_raft_module_count == s_raft_module_capacity) {
    uint32_t fresh_capacity = s_raft_module_capacity == 0
        ? 4 : s_raft_module_capacity * 2;
    raft_module_registry_entry_t* fresh_registry =
        (raft_module_registry_entry_t*)realloc(
            s_raft_modules,
            fresh_capacity * sizeof(raft_module_registry_entry_t));
    if (fresh_registry == NULL) return CRABS_ERR_OOM;
    s_raft_modules = fresh_registry;
    s_raft_module_capacity = fresh_capacity;
  }
  s_raft_modules[s_raft_module_count].module = module;
  s_raft_modules[s_raft_module_count].machine = am;
  s_raft_module_count++;
  return CRABS_SUCCESS;
}

static void _raft_module_registry_remove(crabs_raft_module_t* module) {
  uint32_t index = _raft_module_index(module);
  if (index == UINT32_MAX) return;
  s_raft_modules[index] = s_raft_modules[s_raft_module_count - 1];
  s_raft_module_count--;
}

// Copy the peer id pointer array out of wasm linear memory has already
// happened on the JS side: peer_ids arrives as a C array of char* built by
// the JS wrapper (a malloc'd block of u32 pointers, each a wasm string).
// The module copies the id strings itself, so nothing here needs to retain
// the array.
static void _raft_config_fill(crabs_raft_config_t* config, const char* node_id,
                              const char* const* peer_ids,
                              uint32_t peer_count) {
  crabs_raft_config_defaults(config);
  strncpy(config->node_id, node_id != NULL ? node_id : "",
          CRABS_MAX_USER_ID - 1);
  config->node_id[CRABS_MAX_USER_ID - 1] = '\0';
  // The export already validated peer_count <= CRABS_RAFT_MAX_PEERS, so no
  // clamping — an over-cap config is refused, never silently truncated.
  config->peer_count = peer_count;
  for (uint32_t peer_index = 0; peer_index < peer_count; peer_index++) {
    const char* peer_id = peer_ids[peer_index];
    strncpy(config->peer_ids[peer_index],
            peer_id != NULL ? peer_id : "", CRABS_MAX_USER_ID - 1);
    config->peer_ids[peer_index][CRABS_MAX_USER_ID - 1] = '\0';
  }
}

// Create a raft module for the machine and attach it to the node's state
// (the pipeline seam: group-item writes route through the module's
// two-phase path only while the module is attached). Attaching also
// imports any v16 module snapshot the state carried from a deserialize.
// The timers in the config arrive from JS with C defaults pre-filled
// (crabs_raft_config_defaults ran inside _raft_config_fill), so the JS
// reference host passes 0 only when it has not filled its own values.
EMSCRIPTEN_KEEPALIVE
crabs_raft_module_t* crabs_wasm_raft_create(
    attribute_machine_t* am, const char* node_id,
    const char* const* peer_ids, uint32_t peer_count,
    uint64_t election_timeout_min_ms, uint64_t election_timeout_max_ms,
    uint64_t heartbeat_interval_ms, uint64_t seed, uint8_t module_id) {
  if (am == NULL || node_id == NULL ||
      (peer_ids == NULL && peer_count > 0) ||
      peer_count > CRABS_RAFT_MAX_PEERS) {
    return NULL;
  }
  // One module per machine (the state's module pointer is single-slot): a
  // second create would silently orphan the previous module in the registry.
  if (state_raft_module(&am->base_state) != NULL) return NULL;
  crabs_raft_config_t config;
  _raft_config_fill(&config, node_id, peer_ids, peer_count);
  if (election_timeout_min_ms > 0) config.election_timeout_min_ms = election_timeout_min_ms;
  if (election_timeout_max_ms > 0) config.election_timeout_max_ms = election_timeout_max_ms;
  if (heartbeat_interval_ms > 0)  config.heartbeat_interval_ms = heartbeat_interval_ms;
  config.seed = seed;
  config.module_id = module_id;

  crabs_raft_module_t* module = crabs_raft_module_create(&config);
  if (module == NULL) return NULL;
  crabs_error_e attach_rc = state_attach_raft_module(&am->base_state, module);
  if (attach_rc != CRABS_SUCCESS) {
    crabs_raft_module_destroy(module);
    return NULL;
  }
  if (_raft_module_registry_add(module, am) != CRABS_SUCCESS) {
    state_attach_raft_module(&am->base_state, NULL);
    crabs_raft_module_destroy(module);
    return NULL;
  }
  return module;
}

// Detach the module from its machine's state and destroy it. The node
// object itself stays alive (see crabs_wasm_node_destroy's leak note).
EMSCRIPTEN_KEEPALIVE
void crabs_wasm_raft_destroy(crabs_raft_module_t* module) {
  if (module == NULL) return;
  uint32_t index = _raft_module_index(module);
  if (index != UINT32_MAX) {
    state_attach_raft_module(&s_raft_modules[index].machine->base_state, NULL);
  }
  _raft_module_registry_remove(module);
  crabs_raft_module_destroy(module);
}

// Inbound events. All return a crabs_error_e.
EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_raft_tick(crabs_raft_module_t* module,
                                   uint64_t now_ms) {
  if (module == NULL) return CRABS_ERR_INVALID_PARAM;
  return crabs_raft_module_tick(module, now_ms);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_raft_inbound(crabs_raft_module_t* module,
                                      const char* peer_id,
                                      const uint8_t* blob, uint32_t len,
                                      uint64_t now_ms) {
  if (module == NULL || peer_id == NULL || blob == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  return crabs_raft_module_inbound(module, peer_id, blob, (size_t)len, now_ms);
}

// Propose a (pre-validated) op directly on the module handle — the raw
// reactor path used by hosts that drive the module WITHOUT the state
// pipeline. The assigned proposal id (log index) lands in *out_proposal_id.
EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_raft_propose(crabs_raft_module_t* module,
                                      operation_t* op, uint64_t* out_proposal_id) {
  if (module == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  return crabs_raft_module_propose(module, op, out_proposal_id);
}

// Joint-consensus membership change on the module's own config log.
EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_raft_change_membership(
    crabs_raft_module_t* module, const char* const* new_member_ids,
    uint32_t member_count, uint64_t* out_proposal_id) {
  if (module == NULL) return CRABS_ERR_INVALID_PARAM;
  return crabs_raft_module_change_membership(module, new_member_ids,
                                             member_count, out_proposal_id);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_raft_persist_complete(crabs_raft_module_t* module,
                                               uint64_t handle, uint32_t ok) {
  if (module == NULL) return CRABS_ERR_INVALID_PARAM;
  return crabs_raft_module_persist_complete(module, handle, ok != 0);
}

// Crash recovery: replay one stored persist batch into the module's
// durable state (the host's storage outlived the instance).
EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_raft_recover_from_persist(
    crabs_raft_module_t* module, const uint8_t* batch, uint32_t batch_len) {
  if (module == NULL || batch == NULL) return CRABS_ERR_INVALID_PARAM;
  return crabs_raft_module_recover_from_persist(module, batch,
                                                (size_t)batch_len);
}

// Materialize the module's committed notifications through the state's
// pipeline (state_raft_process_notifications_at): deserializes each
// COMMITTED_OP, executes it (change events fire through the module-wide
// change hook), and shelves ordered retries. Leadership-change
// notifications are consumed here — hosts observe leadership through the
// query exports below.
EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_raft_pump(attribute_machine_t* am,
                                   uint64_t now_ms) {
  if (am == NULL) return CRABS_ERR_INVALID_PARAM;
  return state_raft_process_notifications_at(&am->base_state, now_ms);
}

// Wrap one outbound event as a JS-owned wire envelope:
//   message:     [u32 kind][u16 to_peer_len][to_peer][u32 blob_len][blob]
//   notification:[u32 kind][u16 peer_len][peer][u64 proposal_id][u64
//                 commit_index][u32 op_len][op_bytes]
//   persist view:[u64 handle][u32 blob_len][blob]  (copied; handle stays
//                 module-open until crabs_wasm_raft_persist_complete)
// Returns a serialized_buffer_t (the file's list-encode idiom) that the JS
// wrapper reads once and frees with _crabs_wasm_buffer_destroy.
static serialized_buffer_t* _raft_envelope(size_t body_len,
                                           const uint8_t* body) {
  serialized_buffer_t* buffer =
      (serialized_buffer_t*)malloc(sizeof(serialized_buffer_t));
  if (buffer == NULL) return NULL;
  buffer->data = (uint8_t*)malloc(body_len);
  if (buffer->data == NULL) {
    free(buffer);
    return NULL;
  }
  memcpy(buffer->data, body, body_len);
  buffer->len = body_len;
  return buffer;
}

static serialized_buffer_t* _raft_message_envelope(
    const crabs_raft_outbound_message_t* message) {
  size_t peer_len = strlen(message->to_peer);
  if (peer_len > 0xFFFF) peer_len = 0xFFFF;
  size_t body_len = 4 + 2 + peer_len + 4 + message->len;
  uint8_t* body = (uint8_t*)malloc(body_len);
  if (body == NULL) return NULL;
  size_t cursor = 0;
  uint32_t kind = (uint32_t)message->kind;
  memcpy(body + cursor, &kind, 4); cursor += 4;
  uint16_t len16 = (uint16_t)peer_len;
  memcpy(body + cursor, &len16, 2); cursor += 2;
  memcpy(body + cursor, message->to_peer, peer_len); cursor += peer_len;
  uint32_t blob_len = (uint32_t)message->len;
  memcpy(body + cursor, &blob_len, 4); cursor += 4;
  if (message->len > 0) {
    memcpy(body + cursor, message->bytes, message->len);
  }
  serialized_buffer_t* buffer = _raft_envelope(body_len, body);
  free(body);
  return buffer;
}

static serialized_buffer_t* _raft_notification_envelope(
    const crabs_raft_notification_t* notification) {
  size_t peer_len = strlen(notification->peer_id);
  if (peer_len > 0xFFFF) peer_len = 0xFFFF;
  size_t op_len = notification->op_len > 0 ? notification->op_len : 0;
  size_t body_len = 4 + 2 + peer_len + 8 + 8 + 4 + op_len;
  uint8_t* body = (uint8_t*)malloc(body_len);
  if (body == NULL) return NULL;
  size_t cursor = 0;
  uint32_t kind = (uint32_t)notification->kind;
  memcpy(body + cursor, &kind, 4); cursor += 4;
  uint16_t len16 = (uint16_t)peer_len;
  memcpy(body + cursor, &len16, 2); cursor += 2;
  memcpy(body + cursor, notification->peer_id, peer_len); cursor += peer_len;
  uint64_t proposal_id = notification->proposal_id;
  memcpy(body + cursor, &proposal_id, 8); cursor += 8;
  uint64_t commit_index = notification->commit_index;
  memcpy(body + cursor, &commit_index, 8); cursor += 8;
  uint32_t op_len32 = (uint32_t)op_len;
  memcpy(body + cursor, &op_len32, 4); cursor += 4;
  if (op_len > 0) {
    memcpy(body + cursor, notification->op_bytes, op_len);
  }
  serialized_buffer_t* buffer = _raft_envelope(body_len, body);
  free(body);
  return buffer;
}

static serialized_buffer_t* _raft_persist_view_envelope(
    const crabs_raft_persist_request_t* request) {
  size_t body_len = 8 + 4 + request->len;
  uint8_t* body = (uint8_t*)malloc(body_len);
  if (body == NULL) return NULL;
  size_t cursor = 0;
  uint64_t handle = request->handle;
  memcpy(body + cursor, &handle, 8); cursor += 8;
  uint32_t blob_len = (uint32_t)request->len;
  memcpy(body + cursor, &blob_len, 4); cursor += 4;
  if (request->len > 0) {
    memcpy(body + cursor, request->bytes, request->len);
  }
  serialized_buffer_t* buffer = _raft_envelope(body_len, body);
  free(body);
  return buffer;
}

// Drain one outbound message; returns NULL when the queue is empty. Each
// call moves the head out (ownership transfer semantics): the module hands
// the blob over, so this copies it into the self-contained envelope for JS
// and releases the transferred bytes.
EMSCRIPTEN_KEEPALIVE
serialized_buffer_t* crabs_wasm_raft_poll_outbound(
    crabs_raft_module_t* module) {
  if (module == NULL) return NULL;
  crabs_raft_outbound_message_t message;
  if (!crabs_raft_module_poll_outbound(module, &message)) return NULL;
  serialized_buffer_t* envelope = _raft_message_envelope(&message);
  free((void*)message.bytes);   // poll transferred ownership; envelope owns the copy
  return envelope;
}

// Report the CURRENT outstanding persist window (a copy). Re-reports the
// same handle while it is unresolved — see the section header for the
// disposal convention.
EMSCRIPTEN_KEEPALIVE
serialized_buffer_t* crabs_wasm_raft_poll_persist_request(
    crabs_raft_module_t* module) {
  if (module == NULL) return NULL;
  crabs_raft_persist_request_t request;
  if (!crabs_raft_module_poll_persist(module, &request)) return NULL;
  return _raft_persist_view_envelope(&request);
}

// Raw notification drain — ONLY for hosts driving the module without the
// state pipeline; the state-attached reference host uses
// crabs_wasm_raft_pump (which consumes this queue itself) and must never
// poll here.
EMSCRIPTEN_KEEPALIVE
serialized_buffer_t* crabs_wasm_raft_poll_notification(
    crabs_raft_module_t* module) {
  if (module == NULL) return NULL;
  crabs_raft_notification_t notification;
  if (!crabs_raft_module_poll_notification(module, &notification)) return NULL;
  return _raft_notification_envelope(&notification);
}

// Queries for the host loop and diagnostics.
EMSCRIPTEN_KEEPALIVE
uint32_t crabs_wasm_raft_is_leader(crabs_raft_module_t* module) {
  return module != NULL && crabs_raft_module_is_leader(module) ? 1u : 0u;
}

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_raft_committed_tip(crabs_raft_module_t* module) {
  return module != NULL ? crabs_raft_module_committed_tip(module) : 0;
}

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_raft_current_term(crabs_raft_module_t* module) {
  return module != NULL ? crabs_raft_module_current_term(module) : 0;
}

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_raft_log_length(crabs_raft_module_t* module) {
  return module != NULL ? crabs_raft_module_log_length(module) : 0;
}

EMSCRIPTEN_KEEPALIVE
uint32_t crabs_wasm_raft_config_change_pending(crabs_raft_module_t* module) {
  return module != NULL &&
         crabs_raft_module_config_change_pending(module) ? 1u : 0u;
}

EMSCRIPTEN_KEEPALIVE
uint32_t crabs_wasm_raft_rejected_message_count(
    crabs_raft_module_t* module) {
  return module != NULL ? crabs_raft_module_rejected_message_count(module) : 0;
}

// Committed-config member ids into a flat wasm buffer: u32 count +
// count × [u16 len][id bytes], max CRABS_RAFT_MAX_PEERS entries.
EMSCRIPTEN_KEEPALIVE
serialized_buffer_t* crabs_wasm_raft_committed_members(
    crabs_raft_module_t* module) {
  if (module == NULL) return NULL;
  char ids[CRABS_RAFT_MAX_PEERS][CRABS_MAX_USER_ID];
  uint32_t count = crabs_raft_module_committed_members(module, ids);
  size_t body_len = 4;
  for (uint32_t index = 0; index < count; index++) {
    body_len += 2 + strlen(ids[index]);
  }
  uint8_t* body = (uint8_t*)malloc(body_len);
  if (body == NULL) return NULL;
  memcpy(body, &count, 4);
  size_t cursor = 4;
  for (uint32_t index = 0; index < count; index++) {
    uint16_t len16 = (uint16_t)strlen(ids[index]);
    memcpy(body + cursor, &len16, 2); cursor += 2;
    memcpy(body + cursor, ids[index], len16); cursor += len16;
  }
  serialized_buffer_t* buffer = _raft_envelope(body_len, body);
  free(body);
  return buffer;
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
