//
// wasm_helpers.c — Emscripten-only helpers for the crabs-wasm JS wrapper.
//
// These functions expose safe accessors/setters so the JS wrapper does not
// need to hardcode struct offsets or pointer sizes.
//

#ifdef __EMSCRIPTEN__

#include <emscripten.h>
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

#ifdef CRABS_ENABLE_DEVTOOLS
#include "../Devtools/devtools.h"
#endif

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

  crypto_ecdsa_keypair_destroy(node_key);
  return am;
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_node_destroy(attribute_machine_t* am) {
  // Intentional no-op. Full C teardown (attribute_machine_destroy) triggers a
  // memory-access crash in the Emscripten build during ABE/OpenABE cleanup.
  // The browser demo creates one Node per page load; leaking it is harmless
  // because the process ends on navigation. A future fix can safely tear down
  // the ABE context first.
  (void)am;
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
  crabs_error_e result = state_machine_execute(&am->base_state, op);
#ifdef CRABS_ENABLE_DEVTOOLS
  devtools_record_event(&am->base_state, op, result);
#endif
  return result;
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
  return state_add_item(&am->base_state, item);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_add_pn_counter(attribute_machine_t* am, const char* name) {
  data_item_t* item = data_item_create(name, DATA_TYPE_PN_COUNTER, CRDT_PN_COUNTER);
  if (!item) return CRABS_ERR_OOM;
  item->value = pn_counter_create();
  return state_add_item(&am->base_state, item);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_add_or_set(attribute_machine_t* am, const char* name) {
  data_item_t* item = data_item_create(name, DATA_TYPE_SET, CRDT_OR_SET);
  if (!item) return CRABS_ERR_OOM;
  item->value = or_set_create();
  return state_add_item(&am->base_state, item);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_add_one_shot_set(attribute_machine_t* am, const char* name) {
  data_item_t* item = data_item_create(name, DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  if (!item) return CRABS_ERR_OOM;
  item->value = one_shot_set_create();
  return state_add_item(&am->base_state, item);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_add_one_shot_flag(attribute_machine_t* am, const char* name) {
  data_item_t* item = data_item_create(name, DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
  if (!item) return CRABS_ERR_OOM;
  item->value = one_shot_flag_create();
  return state_add_item(&am->base_state, item);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_add_register(attribute_machine_t* am, const char* name, int64_t initial) {
  data_item_t* item = data_item_create(name, DATA_TYPE_REGISTER, CRDT_LWW_REG);
  if (!item) return CRABS_ERR_OOM;
  item->value = lww_register_create((const uint8_t*)&initial, sizeof(int64_t), 0, "system");
  return state_add_item(&am->base_state, item);
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
void crabs_wasm_devtools_string_destroy(const char* str) {
  free((void*)str);
}

#endif // CRABS_ENABLE_DEVTOOLS

#endif /* __EMSCRIPTEN__ */
