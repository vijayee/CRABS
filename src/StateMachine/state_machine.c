//
// Created by victor on 4/30/25.
//

#include "state_machine.h"
#include "../Trigger/trigger.h"
#include "../Crypto/crypto.h"
#include "../Attribute/attribute_machine.h"
#include "../Condition/condition.h"
#include "../Serialization/serialization.h"
#include "../Util/allocator.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/rand.h>

// ============================================================
// Transition Table (§6.3)
// ============================================================
typedef struct {
  protocol_state_e current;
  const char*      op_type;
  protocol_state_e next;
} transition_t;

static const transition_t TRANSITIONS[] = {
  {PROTOCOL_IDLE,     CRABS_OP_LOCK,          PROTOCOL_LOCKED},
  {PROTOCOL_LOCKED,   CRABS_OP_EXTEND,        PROTOCOL_LOCKED},
  {PROTOCOL_LOCKED,   "*",                    PROTOCOL_MODIFIED},
  {PROTOCOL_MODIFIED, CRABS_OP_VERIFY,        PROTOCOL_VERIFIED},
  {PROTOCOL_MODIFIED, CRABS_OP_ROLLBACK,      PROTOCOL_IDLE},
  {PROTOCOL_MODIFIED, CRABS_OP_FORCE_UNLOCK,  PROTOCOL_IDLE},
  {PROTOCOL_VERIFIED, CRABS_OP_UNLOCK,        PROTOCOL_IDLE},
  {PROTOCOL_LOCKED,   CRABS_OP_FORCE_UNLOCK,  PROTOCOL_IDLE},
  {PROTOCOL_ERROR,    CRABS_OP_ROLLBACK,      PROTOCOL_IDLE},
  {PROTOCOL_ERROR,    CRABS_OP_FORCE_UNLOCK,  PROTOCOL_IDLE},
  {PROTOCOL_MODIFIED, CRABS_OP_VERIFY,        PROTOCOL_ERROR},
};

bool state_machine_is_valid_transition(protocol_state_e current, const char* op_type) {
  for (size_t i = 0; i < sizeof(TRANSITIONS) / sizeof(TRANSITIONS[0]); i++) {
    if (TRANSITIONS[i].current == current) {
      if (strcmp(TRANSITIONS[i].op_type, "*") == 0 ||
          strcmp(TRANSITIONS[i].op_type, op_type) == 0) {
        return true;
      }
    }
  }
  return false;
}

// ============================================================
// Operation Helpers
// ============================================================
bool operation_is_builtin(const char* type) {
  return (strcmp(type, CRABS_OP_LOCK) == 0 ||
          strcmp(type, CRABS_OP_EXTEND) == 0 ||
          strcmp(type, CRABS_OP_VERIFY) == 0 ||
          strcmp(type, CRABS_OP_ROLLBACK) == 0 ||
          strcmp(type, CRABS_OP_UNLOCK) == 0 ||
          strcmp(type, CRABS_OP_FORCE_UNLOCK) == 0 ||
          strcmp(type, CRABS_OP_REFRESH_KEY) == 0 ||
          strcmp(type, CRABS_OP_CHANGE_CONFIG) == 0 ||
          strcmp(type, CRABS_OP_CREATE_TRIGGER) == 0 ||
          strcmp(type, CRABS_OP_DELETE_TRIGGER) == 0 ||
          strcmp(type, CRABS_OP_DISABLE_TRIGGER) == 0 ||
          strcmp(type, CRABS_OP_ENABLE_TRIGGER) == 0);
}

operation_t* operation_create(const char* type) {
  operation_t* op = get_clear_memory(sizeof(operation_t));
  strncpy(op->type, type, CRABS_MAX_OP_NAME - 1);
  return op;
}

void operation_destroy(operation_t* op) {
  if (op == NULL) return;
  if (op->payload != NULL) free(op->payload);
  if (op->resources != NULL) free(op->resources);
  if (op->required_state != NULL) free(op->required_state);
  if (op->next_state != NULL) free(op->next_state);
  if (op->lock_claims != NULL) free(op->lock_claims);
  free(op);
}

// ============================================================
// Lock Token Generation
// ============================================================
void state_machine_generate_lock_token(uint8_t token[CRABS_LOCK_TOKEN_SIZE]) {
  if (RAND_bytes(token, CRABS_LOCK_TOKEN_SIZE) != 1) {
    // Fallback: if RAND_bytes fails, fill with random as last resort
    // but this should be treated as a serious error in production
    for (int i = 0; i < CRABS_LOCK_TOKEN_SIZE; i++) {
      token[i] = (uint8_t)(rand() & 0xFF);
    }
  }
}

// ============================================================
// Invariant Checking
// ============================================================
bool invariant_check(invariant_t* inv, void* value, data_type_e type) {
  if (inv == NULL || value == NULL) return false;

  int64_t val = 0;
  if (type == DATA_TYPE_COUNTER || type == DATA_TYPE_PN_COUNTER) {
    val = *(int64_t*)value;
  } else {
    return true;
  }

  switch (inv->type) {
    case INVARIANT_GREATER_THAN: return val > inv->param;
    case INVARIANT_LESS_THAN:    return val < inv->param;
    case INVARIANT_EQUAL_TO:     return val == inv->param;
    case INVARIANT_NOT_EQUAL:    return val != inv->param;
    case INVARIANT_DIVISIBLE_BY: return inv->param != 0 && (val % inv->param) == 0;
    case INVARIANT_NON_NEGATIVE: return val >= 0;
    default:                     return true;
  }
}

// ============================================================
// Lock Pruning (§7.4 step 1)
// ============================================================
uint32_t state_machine_prune_expired(state_t* state, uint64_t now_ms) {
  uint32_t pruned = 0;
  data_item_t* item = state->items;
  while (item != NULL) {
    if (item->type == DATA_TYPE_RESOURCE && item->protocol_state != PROTOCOL_IDLE) {
      if (now_ms >= item->lock_state.lock_expiry) {
        item->protocol_state = PROTOCOL_IDLE;
        item->lock_state.lock_token_valid = false;
        memset(item->lock_state.lock_owner, 0, CRABS_MAX_USER_ID);
        if (item->lock_state.pre_lock_snapshot != NULL) {
          free(item->lock_state.pre_lock_snapshot);
          item->lock_state.pre_lock_snapshot = NULL;
        }
        item->lock_state.lock_extensions = 0;
        pruned++;
      }
    }
    item = item->next;
  }
  return pruned;
}

// ============================================================
// Duplicate operation check
// ============================================================
static bool is_duplicate_op(state_t* state, const uint8_t uuid[CRABS_UUID_SIZE]) {
  for (uint64_t i = 0; i < state->processed_op_count; i++) {
    if (memcmp(state->processed_ops[i], uuid, CRABS_UUID_SIZE) == 0) {
      return true;
    }
  }
  return false;
}

static void record_processed_op(state_t* state, const uint8_t uuid[CRABS_UUID_SIZE]) {
  state->processed_op_count++;
  state->processed_ops = realloc(state->processed_ops,
    state->processed_op_count * CRABS_UUID_SIZE);
  if (state->processed_ops != NULL) {
    memcpy(state->processed_ops[state->processed_op_count - 1], uuid, CRABS_UUID_SIZE);
  }
}

// ============================================================
// Log helper
// ============================================================
static void append_log(state_t* state, const uint8_t uuid[CRABS_UUID_SIZE],
                       const char* type, const char* signer_id,
                       uint64_t lamport_time, const char* node_id,
                       const uint8_t state_hash[CRABS_HASH_SIZE]) {
  state->log_count++;
  state->log = realloc(state->log, state->log_count * sizeof(log_entry_t));
  if (state->log == NULL) return;
  log_entry_t* entry = &state->log[state->log_count - 1];
  entry->version = state->version;
  memcpy(entry->uuid, uuid, CRABS_UUID_SIZE);
  strncpy(entry->type, type, CRABS_MAX_OP_NAME - 1);
  strncpy(entry->signer_id, signer_id, CRABS_MAX_USER_ID - 1);
  entry->lamport_time = lamport_time;
  strncpy(entry->node_id, node_id, CRABS_MAX_USER_ID - 1);
  memcpy(entry->state_hash, state_hash, CRABS_HASH_SIZE);
}

// ============================================================
// Main Execution Algorithm (§7.4)
// ============================================================
crabs_error_e state_machine_execute(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;

  // Step 1: Prune expired locks
  uint64_t now_ms = (uint64_t)time(NULL) * 1000;
  state_machine_prune_expired(state, now_ms);

  // Step 2: Idempotency check
  if (is_duplicate_op(state, op->uuid)) {
    return CRABS_SUCCESS;
  }

  // Step 3: Verify protocol state transitions
  for (uint32_t i = 0; i < op->resource_count; i++) {
    data_item_t* item = state_find_item(state, op->resources[i]);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    if (item->protocol_state != op->required_state[i]) {
      return CRABS_ERR_PROTOCOL_VIOLATION;
    }
  }

  // Step 4: Verify lock claims
  for (uint32_t i = 0; i < op->lock_claim_count; i++) {
    data_item_t* item = state_find_item(state, op->lock_claims[i].resource);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    if (item->protocol_state == PROTOCOL_LOCKED ||
        item->protocol_state == PROTOCOL_MODIFIED) {
      if (!item->lock_state.lock_token_valid ||
          memcmp(item->lock_state.lock_token, op->lock_claims[i].lock_token,
                 CRABS_LOCK_TOKEN_SIZE) != 0) {
        return CRABS_ERR_LOCK_TOKEN_MISMATCH;
      }
      if (strlen(op->signer_id) > 0 &&
          strcmp(item->lock_state.lock_owner, op->signer_id) != 0) {
        return CRABS_ERR_LOCK_OWNER_MISMATCH;
      }
    }
  }

  // Step 5: ABE-gated policy verification (§10.3)
  const char* policy = state_find_policy(state, op->type);
  if (policy == NULL && op->resource_count > 0) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  if (policy != NULL && strlen(policy) > 0 && state->attr_machine != NULL) {
    // Resolve CONTAINS operators in the policy
    policy_preprocess_result_t pp = preprocess_policy(policy, state, op->signer_id);
    if (!pp.resolved_ok) {
      return CRABS_ERR_UNAUTHORIZED;
    }

    // Determine verification mode from the operation
    verify_mode_e mode = (op->signer_id[0] != '\0') ? VERIFY_MODE_A : VERIFY_MODE_B;

    // Serialize operation for signature verification
    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
    if (ser == NULL) {
      return CRABS_ERR_SERIALIZATION_ERROR;
    }

    // Use a temporary master key for policy-only verification
    // In production, this would be provided by the key management system
    abe_master_key_t* mk = crypto_abe_setup();
    if (mk == NULL) {
      serialized_buffer_destroy(ser);
      return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
    }

    verify_result_t vr = crypto_verify_operation_auth(
        mk, pp.abe_policy, state->attr_machine,
        ser->data, ser->len,
        op->signature, op->signer_id, mode);

    crypto_abe_master_key_destroy(mk);
    serialized_buffer_destroy(ser);

    if (!vr.authorized) {
      return vr.error;
    }
  }

  // Step 6: Key version verification (§10.4)
  if (op->signer_key_version > 0 && state->attr_machine != NULL) {
    user_t* signer = attribute_machine_find_user(state->attr_machine, op->signer_id);
    if (signer != NULL && signer->key_version != op->signer_key_version) {
      return CRABS_ERR_KEY_STALE;
    }
  }

  // Step 7: Execute operation handler
  crabs_error_e result;
  if (strcmp(op->type, CRABS_OP_LOCK) == 0) {
    lock_response_t lock_resp;
    memset(&lock_resp, 0, sizeof(lock_resp));
    result = state_machine_op_lock(state, op, &lock_resp);
  } else if (strcmp(op->type, CRABS_OP_EXTEND) == 0) {
    result = state_machine_op_extend(state, op);
  } else if (strcmp(op->type, CRABS_OP_VERIFY) == 0) {
    result = state_machine_op_verify(state, op);
  } else if (strcmp(op->type, CRABS_OP_ROLLBACK) == 0) {
    result = state_machine_op_rollback(state, op);
  } else if (strcmp(op->type, CRABS_OP_UNLOCK) == 0) {
    result = state_machine_op_unlock(state, op);
  } else if (strcmp(op->type, CRABS_OP_FORCE_UNLOCK) == 0) {
    result = state_machine_op_force_unlock(state, op);
  } else if (strcmp(op->type, CRABS_OP_CHANGE_CONFIG) == 0) {
    result = state_machine_op_change_config(state, op);
  } else if (strcmp(op->type, CRABS_OP_CREATE_TRIGGER) == 0) {
    result = state_machine_op_create_trigger(state, op);
  } else if (strcmp(op->type, CRABS_OP_DELETE_TRIGGER) == 0) {
    result = state_machine_op_delete_trigger(state, op);
  } else if (strcmp(op->type, CRABS_OP_DISABLE_TRIGGER) == 0) {
    result = state_machine_op_disable_trigger(state, op);
  } else if (strcmp(op->type, CRABS_OP_ENABLE_TRIGGER) == 0) {
    result = state_machine_op_enable_trigger(state, op);
  } else if (strcmp(op->type, CRABS_OP_REFRESH_KEY) == 0) {
    refresh_key_response_t refresh_resp;
    memset(&refresh_resp, 0, sizeof(refresh_resp));
    result = state_machine_op_refresh_key(state, op, &refresh_resp);
  } else {
    result = CRABS_ERR_INVALID_PARAM;
  }

  if (result != CRABS_SUCCESS) return result;

  // Step 8: Transition protocol states (handled by built-in ops)
  // Step 9: Log operation
  uint8_t state_hash[CRABS_HASH_SIZE];
  memset(state_hash, 0, CRABS_HASH_SIZE);
  append_log(state, op->uuid, op->type, op->signer_id,
             op->lamport_time, op->node_id, state_hash);
  state->version++;

  // Record for idempotency
  record_processed_op(state, op->uuid);

  // Step 9: Process triggers (Amendment 1, §5.2)
  if (state->triggers != NULL && state->trigger_count > 0) {
    uint64_t trigger_now_ms = (uint64_t)time(NULL) * 1000;
    trigger_process_all(state, state->triggers, state->trigger_count, NULL, trigger_now_ms);
  }

  return CRABS_SUCCESS;
}

// ============================================================
// Built-in Operations (§7.3)
// ============================================================

crabs_error_e state_machine_op_lock(state_t* state, operation_t* op, lock_response_t* response) {
  for (uint32_t i = 0; i < op->resource_count; i++) {
    data_item_t* item = state_find_item(state, op->resources[i]);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    if (item->type != DATA_TYPE_RESOURCE) return CRABS_ERR_TYPE_MISMATCH;
    if (item->protocol_state != PROTOCOL_IDLE) return CRABS_ERR_PROTOCOL_VIOLATION;
    if (item->lock_state.lock_token_valid) {
      uint64_t now_ms = (uint64_t)time(NULL) * 1000;
      if (now_ms < item->lock_state.lock_expiry) {
        return CRABS_ERR_LOCK_OWNER_MISMATCH;
      }
    }
  }

  uint64_t now_ms = (uint64_t)time(NULL) * 1000;
  uint64_t expiry = now_ms + state->config.max_lock_duration_ms;

  response->success = true;
  response->token_count = op->resource_count;
  response->expiry = expiry;

  for (uint32_t i = 0; i < op->resource_count; i++) {
    data_item_t* item = state_find_item(state, op->resources[i]);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;

    state_machine_generate_lock_token(response->lock_tokens[i]);
    memcpy(item->lock_state.lock_token, response->lock_tokens[i], CRABS_LOCK_TOKEN_SIZE);
    item->lock_state.lock_token_valid = true;
    strncpy(item->lock_state.lock_owner, op->signer_id, CRABS_MAX_USER_ID - 1);
    item->lock_state.lock_expiry = expiry;
    item->lock_state.lock_extensions = 0;

    if (item->value != NULL) {
      size_t value_size = 0;
      if (item->type == DATA_TYPE_COUNTER || item->type == DATA_TYPE_PN_COUNTER ||
          item->type == DATA_TYPE_RESOURCE) {
        value_size = sizeof(int64_t);
      } else if (item->type == DATA_TYPE_REGISTER) {
        value_size = sizeof(int64_t);
      }
      if (value_size > 0) {
        item->lock_state.pre_lock_snapshot = get_memory(value_size);
        memcpy(item->lock_state.pre_lock_snapshot, item->value, value_size);
      }
    }

    item->protocol_state = PROTOCOL_LOCKED;
  }

  return CRABS_SUCCESS;
}

crabs_error_e state_machine_op_extend(state_t* state, operation_t* op) {
  for (uint32_t i = 0; i < op->resource_count; i++) {
    data_item_t* item = state_find_item(state, op->resources[i]);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    if (item->protocol_state != PROTOCOL_LOCKED) return CRABS_ERR_PROTOCOL_VIOLATION;
    if (item->lock_state.lock_extensions >= state->config.max_lock_extensions) {
      return CRABS_ERR_MAX_EXTENSIONS_REACHED;
    }
    uint64_t now_ms = (uint64_t)time(NULL) * 1000;
    item->lock_state.lock_expiry = now_ms + state->config.max_lock_duration_ms;
    item->lock_state.lock_extensions++;
  }
  return CRABS_SUCCESS;
}

crabs_error_e state_machine_op_verify(state_t* state, operation_t* op) {
  for (uint32_t i = 0; i < op->resource_count; i++) {
    data_item_t* item = state_find_item(state, op->resources[i]);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    if (item->protocol_state != PROTOCOL_MODIFIED) return CRABS_ERR_PROTOCOL_VIOLATION;

    bool all_pass = true;
    for (uint32_t j = 0; j < item->invariant_count; j++) {
      if (!invariant_check(&item->invariants[j], item->value, item->type)) {
        all_pass = false;
        break;
      }
    }

    if (all_pass) {
      item->protocol_state = PROTOCOL_VERIFIED;
    } else {
      item->protocol_state = PROTOCOL_ERROR;
      return CRABS_ERR_INVARIANT_VIOLATED;
    }
  }
  return CRABS_SUCCESS;
}

crabs_error_e state_machine_op_rollback(state_t* state, operation_t* op) {
  for (uint32_t i = 0; i < op->resource_count; i++) {
    data_item_t* item = state_find_item(state, op->resources[i]);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    if (item->protocol_state != PROTOCOL_MODIFIED &&
        item->protocol_state != PROTOCOL_ERROR) {
      return CRABS_ERR_PROTOCOL_VIOLATION;
    }
    if (item->lock_state.pre_lock_snapshot != NULL && item->value != NULL) {
      size_t value_size = 0;
      if (item->type == DATA_TYPE_COUNTER || item->type == DATA_TYPE_PN_COUNTER ||
          item->type == DATA_TYPE_RESOURCE) {
        value_size = sizeof(int64_t);
      } else if (item->type == DATA_TYPE_REGISTER) {
        value_size = sizeof(int64_t);
      }
      if (value_size > 0) {
        memcpy(item->value, item->lock_state.pre_lock_snapshot, value_size);
      }
    }
    item->protocol_state = PROTOCOL_IDLE;
    item->lock_state.lock_token_valid = false;
    memset(item->lock_state.lock_owner, 0, CRABS_MAX_USER_ID);
  }
  return CRABS_SUCCESS;
}

crabs_error_e state_machine_op_unlock(state_t* state, operation_t* op) {
  for (uint32_t i = 0; i < op->resource_count; i++) {
    data_item_t* item = state_find_item(state, op->resources[i]);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    if (item->protocol_state != PROTOCOL_VERIFIED) return CRABS_ERR_PROTOCOL_VIOLATION;
    item->protocol_state = PROTOCOL_IDLE;
    item->lock_state.lock_token_valid = false;
    memset(item->lock_state.lock_owner, 0, CRABS_MAX_USER_ID);
    if (item->lock_state.pre_lock_snapshot != NULL) {
      free(item->lock_state.pre_lock_snapshot);
      item->lock_state.pre_lock_snapshot = NULL;
    }
    item->lock_state.lock_extensions = 0;
  }
  return CRABS_SUCCESS;
}

crabs_error_e state_machine_op_force_unlock(state_t* state, operation_t* op) {
  uint64_t now_ms = (uint64_t)time(NULL) * 1000;
  for (uint32_t i = 0; i < op->resource_count; i++) {
    data_item_t* item = state_find_item(state, op->resources[i]);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    if (now_ms < item->lock_state.lock_expiry) {
      return CRABS_ERR_LOCK_NOT_EXPIRED;
    }
    item->protocol_state = PROTOCOL_IDLE;
    item->lock_state.lock_token_valid = false;
    memset(item->lock_state.lock_owner, 0, CRABS_MAX_USER_ID);
    if (item->lock_state.pre_lock_snapshot != NULL) {
      free(item->lock_state.pre_lock_snapshot);
      item->lock_state.pre_lock_snapshot = NULL;
    }
    item->lock_state.lock_extensions = 0;
  }
  return CRABS_SUCCESS;
}

crabs_error_e state_machine_op_change_config(state_t* state, operation_t* op) {
  if (op->payload == NULL || op->payload_size == 0) {
    return CRABS_ERR_INVALID_PARAM;
  }
  char* payload_str = (char*)op->payload;
  if (strstr(payload_str, "max_lock_duration_ms") != NULL) {
    char* eq = strchr(payload_str, '=');
    if (eq != NULL) state->config.max_lock_duration_ms = (uint64_t)atoll(eq + 1);
  }
  if (strstr(payload_str, "max_lock_extensions") != NULL) {
    char* eq = strchr(payload_str, '=');
    if (eq != NULL) state->config.max_lock_extensions = (uint32_t)atol(eq + 1);
  }
  if (strstr(payload_str, "allow_force_unlock") != NULL) {
    char* eq = strchr(payload_str, '=');
    if (eq != NULL) state->config.allow_force_unlock = (strcmp(eq + 1, "true") == 0);
  }
  return CRABS_SUCCESS;
}

// ============================================================
// Key Refresh (§11.3, §8.5)
// ============================================================
crabs_error_e state_machine_op_refresh_key(state_t* state, operation_t* op,
                                            refresh_key_response_t* response) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (state->attr_machine == NULL) return CRABS_ERR_UNAUTHORIZED;
  if (!state->node_key_valid) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;

  // Find the requesting user
  user_t* user = attribute_machine_find_user(state->attr_machine, op->signer_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;
  if (user->status == USER_SUSPENDED) return CRABS_ERR_USER_SUSPENDED;

  // Compute attributes hash for current attribute set
  uint8_t attr_hash[CRABS_HASH_SIZE];
  crabs_error_e rc = crypto_compute_attributes_hash(user, attr_hash);
  if (rc != CRABS_SUCCESS) return rc;

  // Generate ABE master key for envelope creation
  abe_master_key_t* mk = crypto_abe_setup();
  if (mk == NULL) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;

  // Create key envelope
  uint64_t now_ms = (uint64_t)time(NULL) * 1000;
  key_envelope_t* envelope = crypto_key_envelope_create(
      mk, state->node_private_key, op->signer_id,
      state->version, attr_hash, now_ms, 0);

  crypto_abe_master_key_destroy(mk);

  if (envelope == NULL) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;

  // Update user key_version to match state version (§8.5)
  user->key_version = state->version;

  // Store envelope in state for caller retrieval
  if (state->last_refresh_envelope != NULL) {
    crypto_key_envelope_destroy((key_envelope_t*)state->last_refresh_envelope);
  }
  state->last_refresh_envelope = envelope;

  // Copy envelope to response (flat serialization)
  if (response != NULL) {
    size_t copy_size = sizeof(key_envelope_t);
    if (copy_size > sizeof(response->envelope_data)) {
      copy_size = sizeof(response->envelope_data);
    }
    memcpy(response->envelope_data, envelope, copy_size);
    response->envelope_data_len = (uint32_t)copy_size;
  }

  return CRABS_SUCCESS;
}
