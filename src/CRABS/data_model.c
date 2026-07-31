//
// Created by victor on 3/30/25.
//

#include "data_model.h"
#include "../Trigger/trigger.h"
#include "../Crypto/crypto.h"
#include "../OT/ot_ordered_set.h"
#include "../OT/ot_document.h"
#include "../OT/ot_tree.h"
#include "../CRDT/crdt_merge.h"
#include "../CRDT/one_shot.h"
#include "../Util/allocator.h"
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>

const data_type_definition_t CRABS_BUILTIN_TYPES[10] = {
  {0x01, "COUNTER",        false},
  {0x02, "PN_COUNTER",     true},
  {0x03, "SET",            false},
  {0x04, "2P_SET",         false},
  {0x05, "REGISTER",       false},
  {0x06, "DOCUMENT",       false},
  {0x07, "RESOURCE",       true},
  {0x08, "ONE_SHOT_SET",   false},
  {0x09, "ONE_SHOT_FLAG",  false},
  {0xFF, "CUSTOM",         false},
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
  // OT types need special cleanup — destroy functions handle ot_data
  if (item->value != NULL) {
    switch (item->type) {
      case DATA_TYPE_OT_ORDERED_SET:
        crabs_ot_ordered_set_destroy((crabs_ot_ordered_set_t*)item->value);
        item->ot_data = NULL; // Destroyed by set destroy
        break;
      case DATA_TYPE_OT_DOCUMENT:
        crabs_ot_document_destroy((crabs_ot_document_t*)item->value);
        item->ot_data = NULL;
        break;
      case DATA_TYPE_OT_TREE:
        crabs_ot_tree_destroy((crabs_ot_tree_t*)item->value);
        item->ot_data = NULL;
        break;
      case DATA_TYPE_SET:
        or_set_destroy((or_set_t*)item->value);
        break;
      case DATA_TYPE_2P_SET:
        two_p_set_destroy((two_p_set_t*)item->value);
        break;
      case DATA_TYPE_ONE_SHOT_SET:
        one_shot_set_destroy((one_shot_set_t*)item->value);
        break;
      case DATA_TYPE_ONE_SHOT_FLAG:
        one_shot_flag_destroy((one_shot_flag_t*)item->value);
        break;
      default:
        free(item->value);
        break;
    }
  }
  if (item->ot_data != NULL) {
    crabs_ot_data_item_destroy((crabs_ot_data_item_t*)item->ot_data);
  }
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
  state->triggers = NULL;
  state->trigger_count = 0;
  state->attr_machine = NULL;
  state->config.max_lock_duration_ms = CRABS_DEFAULT_LOCK_MS;
  state->config.max_lock_extensions = CRABS_MAX_LOCK_EXTENDS;
  state->config.allow_force_unlock = true;
  state->config.bootstrap_admin[0] = '\0';
  state->abe_mk = crypto_abe_setup();
  return state;
}

void state_destroy(state_t* state) {
  if (state == NULL) return;
  if (state->node_key_valid) {
    OPENSSL_cleanse(state->node_private_key, 32);
  }
  if (state->last_refresh_envelope != NULL) {
    crypto_key_envelope_destroy(state->last_refresh_envelope);
  }
  if (state->abe_mk != NULL) {
    crypto_abe_master_key_destroy(state->abe_mk);
  }
  data_item_t* item = state->items;
  while (item != NULL) {
    data_item_t* next = item->next;
    data_item_destroy(item);
    item = next;
  }
  if (state->policies != NULL) free(state->policies);
  if (state->log != NULL) free(state->log);
  if (state->processed_ops != NULL) free(state->processed_ops);
  if (state->op_type_defs != NULL) free(state->op_type_defs);
  if (state->triggers != NULL) {
    for (uint32_t i = 0; i < state->trigger_count; i++) {
      if (state->triggers[i].condition_ast != NULL) {
        condition_node_destroy(state->triggers[i].condition_ast);
      }
    }
    free(state->triggers);
  }
  free(state);
}

crabs_error_e state_set_node_key(state_t* state,
                                  const uint8_t private_key[32],
                                  const uint8_t public_key[33]) {
  if (state == NULL || private_key == NULL || public_key == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  memcpy(state->node_private_key, private_key, 32);
  memcpy(state->node_public_key, public_key, 33);
  state->node_key_valid = true;
  return CRABS_SUCCESS;
}

void state_set_compaction_config(state_t* state, void* config) {
  if (state == NULL) return;
  state->compaction_config = config;
}

void state_set_ordering_config(state_t* state, crabs_ordering_config_t* config) {
  if (state == NULL) return;
  state->ordering_config = config;
}

crabs_ordering_config_t* state_get_ordering_config(state_t* state) {
  if (state == NULL) return NULL;
  return (crabs_ordering_config_t*)state->ordering_config;
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
  // Update-in-place if a policy for this operation already exists, so the
  // first-registered policy (returned by state_find_policy) reflects the
  // latest expression. Otherwise append a new entry.
  for (uint32_t i = 0; i < state->policy_count; i++) {
    if (strcmp(state->policies[i].operation, operation) == 0) {
      strncpy(state->policies[i].expression, expression, CRABS_MAX_POLICY_EXPR - 1);
      state->policies[i].expression[CRABS_MAX_POLICY_EXPR - 1] = '\0';
      return CRABS_SUCCESS;
    }
  }
  uint32_t new_count = state->policy_count + 1;
  policy_t* new_policies = realloc(state->policies, new_count * sizeof(policy_t));
  if (new_policies == NULL) return CRABS_ERR_OOM;
  state->policies = new_policies;
  // Zero-init the new slot so allowed_scheme_count / min_key_version are
  // not left as garbage (realloc does not zero-fill the grown region).
  memset(&state->policies[state->policy_count], 0, sizeof(policy_t));
  uint32_t idx = state->policy_count;
  state->policy_count = new_count;
  strncpy(state->policies[idx].operation, operation, CRABS_MAX_OP_NAME - 1);
  state->policies[idx].operation[CRABS_MAX_OP_NAME - 1] = '\0';
  strncpy(state->policies[idx].expression, expression, CRABS_MAX_POLICY_EXPR - 1);
  state->policies[idx].expression[CRABS_MAX_POLICY_EXPR - 1] = '\0';
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

// ============================================================
// Operation type definition registry (v1.4 §7)
// ============================================================
const dedup_spec_t* state_find_op_type_def(const state_t* state, const char* op_type) {
  if (state == NULL || op_type == NULL) return NULL;
  for (uint32_t i = 0; i < state->op_type_def_count; i++) {
    if (strcmp(state->op_type_defs[i].op_type, op_type) == 0) {
      return &state->op_type_defs[i].dedup;
    }
  }
  return NULL;
}

crabs_error_e state_register_op_type_def(state_t* state, const char* op_type, const dedup_spec_t* dedup) {
  if (state == NULL || op_type == NULL || dedup == NULL) return CRABS_ERR_INVALID_PARAM;

  // Check if already registered — update if so
  for (uint32_t i = 0; i < state->op_type_def_count; i++) {
    if (strcmp(state->op_type_defs[i].op_type, op_type) == 0) {
      state->op_type_defs[i].dedup = *dedup;
      return CRABS_SUCCESS;
    }
  }

  // Check capacity
  if (state->op_type_def_count >= CRABS_MAX_OP_TYPE_DEFS) return CRABS_ERR_OOM;

  uint32_t new_count = state->op_type_def_count + 1;
  op_type_def_t* new_defs = realloc(state->op_type_defs, new_count * sizeof(op_type_def_t));
  if (new_defs == NULL) return CRABS_ERR_OOM;
  state->op_type_defs = new_defs;
  uint32_t idx = state->op_type_def_count;
  state->op_type_def_count = new_count;
  memset(&state->op_type_defs[idx], 0, sizeof(op_type_def_t));

  strncpy(state->op_type_defs[idx].op_type, op_type, CRABS_MAX_OP_NAME - 1);
  state->op_type_defs[idx].op_type[CRABS_MAX_OP_NAME - 1] = '\0';
  state->op_type_defs[idx].dedup = *dedup;
  return CRABS_SUCCESS;
}
