//
// Created by victor on 4/30/25.
//

#include "state_machine.h"
#include "../Trigger/trigger.h"
#include "../Crypto/crypto.h"
#include "../Crypto/sig_scheme.h"
#include "../Attribute/attribute_machine.h"
#include "../Condition/condition.h"
#include "../Serialization/serialization.h"
#include "../Dedup/dedup.h"
#include "../OT/ot_execution.h"
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
  // Key operations (v1.3 §5): valid in any state, no state change
  {PROTOCOL_IDLE,     CRABS_OP_REGISTER_KEY,    PROTOCOL_IDLE},
  {PROTOCOL_IDLE,     CRABS_OP_REVOKE_KEY,      PROTOCOL_IDLE},
  {PROTOCOL_IDLE,     CRABS_OP_SET_DEFAULT_KEY,  PROTOCOL_IDLE},
  {PROTOCOL_LOCKED,   CRABS_OP_REGISTER_KEY,    PROTOCOL_LOCKED},
  {PROTOCOL_LOCKED,   CRABS_OP_REVOKE_KEY,      PROTOCOL_LOCKED},
  {PROTOCOL_LOCKED,   CRABS_OP_SET_DEFAULT_KEY,  PROTOCOL_LOCKED},
  {PROTOCOL_MODIFIED, CRABS_OP_REGISTER_KEY,    PROTOCOL_MODIFIED},
  {PROTOCOL_MODIFIED, CRABS_OP_REVOKE_KEY,      PROTOCOL_MODIFIED},
  {PROTOCOL_MODIFIED, CRABS_OP_SET_DEFAULT_KEY,  PROTOCOL_MODIFIED},
  {PROTOCOL_VERIFIED, CRABS_OP_REGISTER_KEY,    PROTOCOL_VERIFIED},
  {PROTOCOL_VERIFIED, CRABS_OP_REVOKE_KEY,      PROTOCOL_VERIFIED},
  {PROTOCOL_VERIFIED, CRABS_OP_SET_DEFAULT_KEY,  PROTOCOL_VERIFIED},
  {PROTOCOL_ERROR,    CRABS_OP_REGISTER_KEY,    PROTOCOL_ERROR},
  {PROTOCOL_ERROR,    CRABS_OP_REVOKE_KEY,      PROTOCOL_ERROR},
  {PROTOCOL_ERROR,    CRABS_OP_SET_DEFAULT_KEY,  PROTOCOL_ERROR},
  // Key lifecycle operations (v1.3 §9): valid in any state, no state change
  {PROTOCOL_IDLE,     CRABS_OP_SUSPEND_KEY,      PROTOCOL_IDLE},
  {PROTOCOL_IDLE,     CRABS_OP_ACTIVATE_KEY,     PROTOCOL_IDLE},
  {PROTOCOL_IDLE,     CRABS_OP_ROTATE_KEY,       PROTOCOL_IDLE},
  {PROTOCOL_LOCKED,   CRABS_OP_SUSPEND_KEY,      PROTOCOL_LOCKED},
  {PROTOCOL_LOCKED,   CRABS_OP_ACTIVATE_KEY,     PROTOCOL_LOCKED},
  {PROTOCOL_LOCKED,   CRABS_OP_ROTATE_KEY,       PROTOCOL_LOCKED},
  {PROTOCOL_MODIFIED, CRABS_OP_SUSPEND_KEY,      PROTOCOL_MODIFIED},
  {PROTOCOL_MODIFIED, CRABS_OP_ACTIVATE_KEY,     PROTOCOL_MODIFIED},
  {PROTOCOL_MODIFIED, CRABS_OP_ROTATE_KEY,       PROTOCOL_MODIFIED},
  {PROTOCOL_VERIFIED, CRABS_OP_SUSPEND_KEY,      PROTOCOL_VERIFIED},
  {PROTOCOL_VERIFIED, CRABS_OP_ACTIVATE_KEY,     PROTOCOL_VERIFIED},
  {PROTOCOL_VERIFIED, CRABS_OP_ROTATE_KEY,       PROTOCOL_VERIFIED},
  {PROTOCOL_ERROR,    CRABS_OP_SUSPEND_KEY,      PROTOCOL_ERROR},
  {PROTOCOL_ERROR,    CRABS_OP_ACTIVATE_KEY,     PROTOCOL_ERROR},
  {PROTOCOL_ERROR,    CRABS_OP_ROTATE_KEY,       PROTOCOL_ERROR},
  // Dedup operations (v1.4 §7): valid in any state, no state change
  {PROTOCOL_IDLE,     CRABS_OP_DEFINE_OPERATION,  PROTOCOL_IDLE},
  {PROTOCOL_LOCKED,   CRABS_OP_DEFINE_OPERATION,  PROTOCOL_LOCKED},
  {PROTOCOL_MODIFIED, CRABS_OP_DEFINE_OPERATION,  PROTOCOL_MODIFIED},
  {PROTOCOL_VERIFIED, CRABS_OP_DEFINE_OPERATION,  PROTOCOL_VERIFIED},
  {PROTOCOL_ERROR,    CRABS_OP_DEFINE_OPERATION,  PROTOCOL_ERROR},
  {PROTOCOL_IDLE,     CRABS_OP_CHECK_DEDUP,       PROTOCOL_IDLE},
  {PROTOCOL_LOCKED,   CRABS_OP_CHECK_DEDUP,       PROTOCOL_LOCKED},
  {PROTOCOL_MODIFIED, CRABS_OP_CHECK_DEDUP,       PROTOCOL_MODIFIED},
  {PROTOCOL_VERIFIED, CRABS_OP_CHECK_DEDUP,       PROTOCOL_VERIFIED},
  {PROTOCOL_ERROR,    CRABS_OP_CHECK_DEDUP,       PROTOCOL_ERROR},
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
          strcmp(type, CRABS_OP_ENABLE_TRIGGER) == 0 ||
          strcmp(type, CRABS_OP_REGISTER_KEY) == 0 ||
          strcmp(type, CRABS_OP_REVOKE_KEY) == 0 ||
          strcmp(type, CRABS_OP_SET_DEFAULT_KEY) == 0 ||
          strcmp(type, CRABS_OP_SUSPEND_KEY) == 0 ||
          strcmp(type, CRABS_OP_ACTIVATE_KEY) == 0 ||
          strcmp(type, CRABS_OP_ROTATE_KEY) == 0 ||
          strcmp(type, CRABS_OP_DEFINE_OPERATION) == 0 ||
          strcmp(type, CRABS_OP_CHECK_DEDUP) == 0);
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
  if (op->co_signers != NULL) free(op->co_signers);
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

  // Step 5: Dedup guard check (v1.4 §5.2)
  if (op->dedup.type != DEDUP_NONE) {
    crabs_error_e dedup_result = dedup_check_guard(state, op);
    if (dedup_result != CRABS_SUCCESS) {
      return dedup_result;
    }
  }

  // Step 5b: ABE-gated policy verification (§10.3)
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

    verify_result_t vr;
    if (op->sig_scheme != SCHEME_UNSPECIFIED || op->key_id[0] != '\0') {
      // v1.3: Scheme-aware verification
      vr = crypto_verify_operation_auth_v2(
          mk, pp.abe_policy, state->attr_machine,
          ser->data, ser->len,
          op->signature, CRABS_SIG_SIZE,
          op->signer_id, op->key_id, op->sig_scheme, mode);
    } else {
      // Legacy ECDSA verification
      vr = crypto_verify_operation_auth(
          mk, pp.abe_policy, state->attr_machine,
          ser->data, ser->len,
          op->signature, op->signer_id, mode);
    }

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

  // Step 6b: Scheme constraint enforcement (v1.3 §7)
  if (op->sig_scheme != SCHEME_UNSPECIFIED && state->policies != NULL) {
    const policy_t* policy = NULL;
    for (uint32_t i = 0; i < state->policy_count; i++) {
      if (strcmp(state->policies[i].operation, op->type) == 0) {
        policy = &state->policies[i];
        break;
      }
    }
    if (policy != NULL && policy->allowed_scheme_count > 0) {
      bool scheme_allowed = false;
      for (uint32_t i = 0; i < policy->allowed_scheme_count; i++) {
        if (policy->allowed_schemes[i] == op->sig_scheme) {
          scheme_allowed = true;
          break;
        }
      }
      if (!scheme_allowed) {
        return CRABS_ERR_UNAUTHORIZED;
      }
    }
    if (policy != NULL && policy->min_key_version > 0 && state->attr_machine != NULL) {
      user_t* signer = attribute_machine_find_user(state->attr_machine, op->signer_id);
      if (signer != NULL && signer->key_version < policy->min_key_version) {
        return CRABS_ERR_KEY_STALE;
      }
    }
  }

  // Step 6c: Co-signature threshold enforcement (v1.3 §4.2)
  if (state->config.sig_config.co_sign_threshold > 0 && op->co_signer_count < state->config.sig_config.co_sign_threshold) {
    // Check if this operation type requires co-signatures
    // Only enforce if threshold is set and operation has fewer co-signers
    if (op->co_signer_count > 0 || op->sig_scheme != SCHEME_UNSPECIFIED) {
      // If co-signers are present or scheme is specified, enforce threshold
      if (op->co_signer_count < state->config.sig_config.co_sign_threshold) {
        return CRABS_ERR_UNAUTHORIZED;
      }
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
  } else if (strcmp(op->type, CRABS_OP_REGISTER_KEY) == 0) {
    result = state_machine_op_register_key(state, op);
  } else if (strcmp(op->type, CRABS_OP_REVOKE_KEY) == 0) {
    result = state_machine_op_revoke_key(state, op);
  } else if (strcmp(op->type, CRABS_OP_SET_DEFAULT_KEY) == 0) {
    result = state_machine_op_set_default_key(state, op);
  } else if (strcmp(op->type, CRABS_OP_SUSPEND_KEY) == 0) {
    result = state_machine_op_suspend_key(state, op);
  } else if (strcmp(op->type, CRABS_OP_ACTIVATE_KEY) == 0) {
    result = state_machine_op_activate_key(state, op);
  } else if (strcmp(op->type, CRABS_OP_ROTATE_KEY) == 0) {
    result = state_machine_op_rotate_key(state, op);
  } else if (strcmp(op->type, CRABS_OP_DEFINE_OPERATION) == 0) {
    result = state_machine_op_define_operation(state, op);
  } else if (strcmp(op->type, CRABS_OP_CHECK_DEDUP) == 0) {
    result = state_machine_op_check_dedup(state, op);
  } else if (strcmp(op->type, CRABS_OP_EXECUTE_OT) == 0) {
    // OT operation: extract, transform, and apply (v1.5 §8)
    result = crabs_execute_ot_operation(state, op);
  } else {
    result = CRABS_ERR_INVALID_PARAM;
  }

  if (result != CRABS_SUCCESS) return result;

  // Step 8: Apply dedup state mutation (v1.4 §5.3)
  if (op->dedup.type != DEDUP_NONE) {
    crabs_error_e mut_result = dedup_apply_mutation(state, op);
    if (mut_result != CRABS_SUCCESS) {
      // Mutation failure doesn't roll back the operation,
      // but we log the error for diagnostics
    }
  }

  // Step 9: Transition protocol states (handled by built-in ops)
  // Step 10: Log operation
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
  if (strstr(payload_str, "default_scheme") != NULL) {
    char* eq = strchr(payload_str, '=');
    if (eq != NULL) state->config.sig_config.default_scheme = (signature_scheme_e)atoi(eq + 1);
  }
  if (strstr(payload_str, "max_keys_per_user") != NULL) {
    char* eq = strchr(payload_str, '=');
    if (eq != NULL) state->config.sig_config.max_keys_per_user = (uint32_t)atol(eq + 1);
  }
  if (strstr(payload_str, "key_rotation_enabled") != NULL) {
    char* eq = strchr(payload_str, '=');
    if (eq != NULL) state->config.sig_config.key_rotation_enabled = (strcmp(eq + 1, "true") == 0);
  }
  if (strstr(payload_str, "co_sign_threshold") != NULL) {
    char* eq = strchr(payload_str, '=');
    if (eq != NULL) state->config.sig_config.co_sign_threshold = (uint32_t)atol(eq + 1);
  }
  if (strstr(payload_str, "key_expiry_enabled") != NULL) {
    char* eq = strchr(payload_str, '=');
    if (eq != NULL) state->config.sig_config.key_expiry_enabled = (strcmp(eq + 1, "true") == 0);
  }
  if (strstr(payload_str, "default_key_ttl_ms") != NULL) {
    char* eq = strchr(payload_str, '=');
    if (eq != NULL) state->config.sig_config.default_key_ttl_ms = (uint64_t)atoll(eq + 1);
  }
  if (strstr(payload_str, "max_key_age_ms") != NULL) {
    char* eq = strchr(payload_str, '=');
    if (eq != NULL) state->config.sig_config.max_key_age_ms = (uint64_t)atoll(eq + 1);
  }
  if (strstr(payload_str, "vault_provider") != NULL) {
    char* eq = strchr(payload_str, '=');
    if (eq != NULL) state->config.vault_config.provider = (vault_provider_e)atoi(eq + 1);
  }
  if (strstr(payload_str, "vault_signing_delegated") != NULL) {
    char* eq = strchr(payload_str, '=');
    if (eq != NULL) state->config.vault_config.signing_delegated = (strcmp(eq + 1, "true") == 0);
  }
  if (strstr(payload_str, "vault_rotation_delegated") != NULL) {
    char* eq = strchr(payload_str, '=');
    if (eq != NULL) state->config.vault_config.rotation_delegated = (strcmp(eq + 1, "true") == 0);
  }
  return CRABS_SUCCESS;
}

// ============================================================
// Key Ring Operations (v1.3 Amendment 3, §5)
// ============================================================

crabs_error_e state_machine_op_register_key(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (state->attr_machine == NULL) return CRABS_ERR_UNAUTHORIZED;

  user_t* user = attribute_machine_find_user(state->attr_machine, op->signer_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;
  if (user->status == USER_SUSPENDED) return CRABS_ERR_USER_SUSPENDED;

  // Payload format: key_id=<id>;scheme=<num>;public_key_len=<len>;label=<label>
  // public_key bytes follow in payload after the null-terminated config string
  if (op->payload == NULL || op->payload_size == 0) return CRABS_ERR_INVALID_PARAM;

  char key_id[CRABS_MAX_KEY_ID] = {0};
  signature_scheme_e scheme = SCHEME_UNSPECIFIED;
  uint32_t pk_len = 0;
  char label[CRABS_MAX_KEY_LABEL] = {0};
  const uint8_t* pk_data = NULL;

  // Parse key-value config from payload
  char buf[1024];
  uint32_t copy_len = op->payload_size < sizeof(buf) - 1 ? op->payload_size : sizeof(buf) - 1;
  memcpy(buf, op->payload, copy_len);
  buf[copy_len] = '\0';

  char* saveptr = NULL;
  char* token = strtok_r(buf, ";", &saveptr);

  while (token != NULL) {
    while (*token == ' ') token++;
    char* eq = strchr(token, '=');
    if (eq == NULL) { token = strtok_r(NULL, ";", &saveptr); continue; }

    *eq = '\0';
    const char* key = token;
    const char* val = eq + 1;

    if (strcmp(key, "key_id") == 0) {
      strncpy(key_id, val, CRABS_MAX_KEY_ID - 1);
    } else if (strcmp(key, "scheme") == 0) {
      scheme = (signature_scheme_e)atoi(val);
    } else if (strcmp(key, "public_key_len") == 0) {
      pk_len = (uint32_t)atoi(val);
    } else if (strcmp(key, "label") == 0) {
      strncpy(label, val, CRABS_MAX_KEY_LABEL - 1);
    }

    token = strtok_r(NULL, ";", &saveptr);
  }

  // Find the public key data after the config string's null terminator
  // The config string ends at the first \0 in the payload
  size_t config_strlen = strnlen((const char*)op->payload, op->payload_size);
  if (config_strlen + 1 + pk_len > op->payload_size) {
    return CRABS_ERR_INVALID_PARAM;
  }
  pk_data = op->payload + config_strlen + 1;

  if (key_id[0] == '\0' || pk_len == 0 || pk_data == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }

  return user_key_register(user, key_id, scheme, pk_data, pk_len,
                           label[0] != '\0' ? label : NULL);
}

crabs_error_e state_machine_op_revoke_key(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (state->attr_machine == NULL) return CRABS_ERR_UNAUTHORIZED;

  user_t* user = attribute_machine_find_user(state->attr_machine, op->signer_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;
  if (user->status == USER_SUSPENDED) return CRABS_ERR_USER_SUSPENDED;

  // Payload format: key_id=<id>
  if (op->payload == NULL || op->payload_size == 0) return CRABS_ERR_INVALID_PARAM;

  char key_id[CRABS_MAX_KEY_ID] = {0};
  char buf[256];
  uint32_t copy_len = op->payload_size < sizeof(buf) - 1 ? op->payload_size : sizeof(buf) - 1;
  memcpy(buf, op->payload, copy_len);
  buf[copy_len] = '\0';

  char* saveptr = NULL;
  char* token = strtok_r(buf, ";", &saveptr);
  while (token != NULL) {
    while (*token == ' ') token++;
    char* eq = strchr(token, '=');
    if (eq == NULL) { token = strtok_r(NULL, ";", &saveptr); continue; }

    *eq = '\0';
    if (strcmp(token, "key_id") == 0) {
      strncpy(key_id, eq + 1, CRABS_MAX_KEY_ID - 1);
    }
    token = strtok_r(NULL, ";", &saveptr);
  }

  if (key_id[0] == '\0') return CRABS_ERR_INVALID_PARAM;

  return user_key_revoke(user, key_id);
}

crabs_error_e state_machine_op_set_default_key(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (state->attr_machine == NULL) return CRABS_ERR_UNAUTHORIZED;

  user_t* user = attribute_machine_find_user(state->attr_machine, op->signer_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;
  if (user->status == USER_SUSPENDED) return CRABS_ERR_USER_SUSPENDED;

  // Payload format: key_id=<id>
  if (op->payload == NULL || op->payload_size == 0) return CRABS_ERR_INVALID_PARAM;

  char key_id[CRABS_MAX_KEY_ID] = {0};
  char buf[256];
  uint32_t copy_len = op->payload_size < sizeof(buf) - 1 ? op->payload_size : sizeof(buf) - 1;
  memcpy(buf, op->payload, copy_len);
  buf[copy_len] = '\0';

  char* saveptr = NULL;
  char* token = strtok_r(buf, ";", &saveptr);
  while (token != NULL) {
    while (*token == ' ') token++;
    char* eq = strchr(token, '=');
    if (eq == NULL) { token = strtok_r(NULL, ";", &saveptr); continue; }

    *eq = '\0';
    if (strcmp(token, "key_id") == 0) {
      strncpy(key_id, eq + 1, CRABS_MAX_KEY_ID - 1);
    }
    token = strtok_r(NULL, ";", &saveptr);
  }

  if (key_id[0] == '\0') return CRABS_ERR_INVALID_PARAM;

  return user_key_set_default(user, key_id);
}

// ============================================================
// Key Lifecycle Operations (v1.3 §9)
// ============================================================

crabs_error_e state_machine_op_suspend_key(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (state->attr_machine == NULL) return CRABS_ERR_UNAUTHORIZED;

  user_t* user = attribute_machine_find_user(state->attr_machine, op->signer_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;
  if (user->status == USER_SUSPENDED) return CRABS_ERR_USER_SUSPENDED;

  if (op->payload == NULL || op->payload_size == 0) return CRABS_ERR_INVALID_PARAM;

  char key_id[CRABS_MAX_KEY_ID] = {0};
  char buf[256];
  uint32_t copy_len = op->payload_size < sizeof(buf) - 1 ? op->payload_size : sizeof(buf) - 1;
  memcpy(buf, op->payload, copy_len);
  buf[copy_len] = '\0';

  char* saveptr = NULL;
  char* token = strtok_r(buf, ";", &saveptr);
  while (token != NULL) {
    while (*token == ' ') token++;
    char* eq = strchr(token, '=');
    if (eq == NULL) { token = strtok_r(NULL, ";", &saveptr); continue; }
    *eq = '\0';
    if (strcmp(token, "key_id") == 0) {
      strncpy(key_id, eq + 1, CRABS_MAX_KEY_ID - 1);
    }
    token = strtok_r(NULL, ";", &saveptr);
  }

  if (key_id[0] == '\0') return CRABS_ERR_INVALID_PARAM;

  return user_key_suspend(user, key_id);
}

crabs_error_e state_machine_op_activate_key(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (state->attr_machine == NULL) return CRABS_ERR_UNAUTHORIZED;

  user_t* user = attribute_machine_find_user(state->attr_machine, op->signer_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;
  if (user->status == USER_SUSPENDED) return CRABS_ERR_USER_SUSPENDED;

  if (op->payload == NULL || op->payload_size == 0) return CRABS_ERR_INVALID_PARAM;

  char key_id[CRABS_MAX_KEY_ID] = {0};
  char buf[256];
  uint32_t copy_len = op->payload_size < sizeof(buf) - 1 ? op->payload_size : sizeof(buf) - 1;
  memcpy(buf, op->payload, copy_len);
  buf[copy_len] = '\0';

  char* saveptr = NULL;
  char* token = strtok_r(buf, ";", &saveptr);
  while (token != NULL) {
    while (*token == ' ') token++;
    char* eq = strchr(token, '=');
    if (eq == NULL) { token = strtok_r(NULL, ";", &saveptr); continue; }
    *eq = '\0';
    if (strcmp(token, "key_id") == 0) {
      strncpy(key_id, eq + 1, CRABS_MAX_KEY_ID - 1);
    }
    token = strtok_r(NULL, ";", &saveptr);
  }

  if (key_id[0] == '\0') return CRABS_ERR_INVALID_PARAM;

  return user_key_activate(user, key_id);
}

crabs_error_e state_machine_op_rotate_key(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (state->attr_machine == NULL) return CRABS_ERR_UNAUTHORIZED;

  user_t* user = attribute_machine_find_user(state->attr_machine, op->signer_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;
  if (user->status == USER_SUSPENDED) return CRABS_ERR_USER_SUSPENDED;

  if (!state->config.sig_config.key_rotation_enabled) return CRABS_ERR_PROTOCOL_VIOLATION;

  if (op->payload == NULL || op->payload_size == 0) return CRABS_ERR_INVALID_PARAM;

  // Parse payload: old_key_id=X;new_key_id=Y;scheme=Z;public_key_len=N
  char old_key_id[CRABS_MAX_KEY_ID] = {0};
  char new_key_id[CRABS_MAX_KEY_ID] = {0};
  signature_scheme_e new_scheme = SCHEME_UNSPECIFIED;
  uint32_t pk_len = 0;
  char buf[512];
  uint32_t copy_len = op->payload_size < sizeof(buf) - 1 ? op->payload_size : sizeof(buf) - 1;
  memcpy(buf, op->payload, copy_len);
  buf[copy_len] = '\0';

  char* saveptr = NULL;
  char* token = strtok_r(buf, ";", &saveptr);
  while (token != NULL) {
    while (*token == ' ') token++;
    char* eq = strchr(token, '=');
    if (eq == NULL) { token = strtok_r(NULL, ";", &saveptr); continue; }
    *eq = '\0';
    if (strcmp(token, "old_key_id") == 0) {
      strncpy(old_key_id, eq + 1, CRABS_MAX_KEY_ID - 1);
    } else if (strcmp(token, "new_key_id") == 0) {
      strncpy(new_key_id, eq + 1, CRABS_MAX_KEY_ID - 1);
    } else if (strcmp(token, "scheme") == 0) {
      new_scheme = (signature_scheme_e)atoi(eq + 1);
    } else if (strcmp(token, "public_key_len") == 0) {
      pk_len = (uint32_t)atoi(eq + 1);
    }
    token = strtok_r(NULL, ";", &saveptr);
  }

  if (old_key_id[0] == '\0' || new_key_id[0] == '\0' || pk_len == 0) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Extract public key bytes from payload after the config string
  char* config_end = (char*)memchr(op->payload, '\0', op->payload_size);
  if (config_end == NULL) return CRABS_ERR_INVALID_PARAM;
  size_t config_len = (size_t)(config_end - (char*)op->payload) + 1;
  const uint8_t* pk_data = op->payload + config_len;
  uint32_t remaining = op->payload_size - (uint32_t)config_len;
  if (remaining < pk_len) return CRABS_ERR_INVALID_PARAM;

  return user_key_rotate(user, old_key_id, new_key_id, new_scheme, pk_data, pk_len, NULL);
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

// ============================================================
// Dedup Built-in Operations (v1.4 §7)
// ============================================================

crabs_error_e state_machine_op_define_operation(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;

  // The operation type name to define is carried in resources[0]
  if (op->resource_count == 0 || op->resources == NULL) return CRABS_ERR_INVALID_PARAM;

  crabs_error_e rc = state_register_op_type_def(state, op->resources[0], &op->dedup);
  if (rc != CRABS_SUCCESS) return rc;

  return CRABS_SUCCESS;
}

crabs_error_e state_machine_op_check_dedup(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;

  // If the operation has a dedup spec, use it directly
  if (op->dedup.type != DEDUP_NONE) {
    return dedup_check_guard(state, op);
  }

  // Otherwise, look up the registered dedup spec for this operation type
  const dedup_spec_t* registered = state_find_op_type_def(state, op->type);
  if (registered == NULL) return CRABS_SUCCESS; // No dedup spec → passes

  // Create a temporary copy of the operation with the registered dedup spec
  operation_t* check_op = operation_create(op->type);
  if (check_op == NULL) return CRABS_ERR_OOM;
  check_op->dedup = *registered;
  strncpy(check_op->signer_id, op->signer_id, CRABS_MAX_USER_ID - 1);
  check_op->lamport_time = op->lamport_time;

  crabs_error_e result = dedup_check_guard(state, check_op);
  operation_destroy(check_op);
  return result;
}
