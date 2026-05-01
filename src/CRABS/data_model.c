//
// Created by victor on 3/30/25.
//

#include "data_model.h"
#include "../Util/allocator.h"
#include <string.h>
#include <stdlib.h>

const data_type_definition_t CRABS_BUILTIN_TYPES[8] = {
  {0x01, "COUNTER",    false},
  {0x02, "PN_COUNTER", true},
  {0x03, "SET",        false},
  {0x04, "2P_SET",     false},
  {0x05, "REGISTER",   false},
  {0x06, "DOCUMENT",   false},
  {0x07, "RESOURCE",   true},
  {0xFF, "CUSTOM",     false},
};

data_item_t* data_item_create(const char* name, data_type_e type, crdt_type_e crdt_type) {
  data_item_t* item = get_clear_memory(sizeof(data_item_t));
  if (name != NULL) {
    strncpy(item->name, name, CRABS_MAX_USER_ID - 1);
  }
  item->type = type;
  item->crdt_type = crdt_type;
  item->protocol_state = PROTOCOL_IDLE;
  item->invariants = NULL;
  item->invariant_count = 0;
  item->value = NULL;
  item->next = NULL;
  return item;
}

void data_item_destroy(data_item_t* item) {
  if (item == NULL) return;
  if (item->invariants != NULL) free(item->invariants);
  if (item->lock_state.pre_lock_snapshot != NULL) free(item->lock_state.pre_lock_snapshot);
  if (item->value != NULL) free(item->value);
  free(item);
}

state_t* state_create(void) {
  state_t* state = get_clear_memory(sizeof(state_t));
  state->version = 0;
  state->items = NULL;
  state->policies = NULL;
  state->policy_count = 0;
  state->log = NULL;
  state->log_count = 0;
  state->processed_ops = NULL;
  state->processed_op_count = 0;
  state->config.max_lock_duration_ms = CRABS_DEFAULT_LOCK_MS;
  state->config.max_lock_extensions = CRABS_MAX_LOCK_EXTENDS;
  state->config.allow_force_unlock = true;
  state->config.bootstrap_admin[0] = '\0';
  return state;
}

void state_destroy(state_t* state) {
  if (state == NULL) return;
  data_item_t* item = state->items;
  while (item != NULL) {
    data_item_t* next = item->next;
    data_item_destroy(item);
    item = next;
  }
  if (state->policies != NULL) free(state->policies);
  if (state->log != NULL) free(state->log);
  if (state->processed_ops != NULL) free(state->processed_ops);
  free(state);
}

// ============================================================
// State query helpers
// ============================================================
data_item_t* state_find_item(state_t* state, const char* name) {
  data_item_t* item = state->items;
  while (item != NULL) {
    if (strcmp(item->name, name) == 0) return item;
    item = item->next;
  }
  return NULL;
}

crabs_error_e state_add_item(state_t* state, data_item_t* item) {
  if (state == NULL || item == NULL) return CRABS_ERR_INVALID_PARAM;
  // Check for duplicate name
  if (state_find_item(state, item->name) != NULL) return CRABS_ERR_DUPLICATE_OPERATION;
  item->next = state->items;
  state->items = item;
  return CRABS_SUCCESS;
}

crabs_error_e state_add_policy(state_t* state, const char* operation, const char* expression) {
  if (state == NULL || operation == NULL || expression == NULL) return CRABS_ERR_INVALID_PARAM;
  uint32_t idx = state->policy_count;
  state->policy_count++;
  policy_t* new_policies = realloc(state->policies, state->policy_count * sizeof(policy_t));
  if (new_policies == NULL) return CRABS_ERR_OOM;
  state->policies = new_policies;
  strncpy(state->policies[idx].operation, operation, CRABS_MAX_OP_NAME - 1);
  strncpy(state->policies[idx].expression, expression, CRABS_MAX_POLICY_EXPR - 1);
  return CRABS_SUCCESS;
}

const char* state_find_policy(state_t* state, const char* operation) {
  if (state == NULL || operation == NULL) return NULL;
  for (uint32_t i = 0; i < state->policy_count; i++) {
    if (strcmp(state->policies[i].operation, operation) == 0) {
      return state->policies[i].expression;
    }
  }
  return NULL;
}
