//
// Created by victor on 4/30/25.
//

#include "state_machine.h"
#include "../Util/platform.h"
#include "../Trigger/trigger.h"
#include "../Crypto/crypto.h"
#include "../Crypto/sig_scheme.h"
#include "../Attribute/attribute_machine.h"
#include "../Condition/condition.h"
#include "../Serialization/serialization.h"
#include "../Dedup/dedup.h"
#include "../OT/ot_execution.h"
#include "../Compaction/compaction_engine.h"
#include "../Compaction/crdt_compaction.h"
#include "../Util/allocator.h"
#include "../TxManager/tx_manager.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

// Forward declarations for handlers defined later in this file.
// These are not in the public header — reachable only via state_machine_execute.
crabs_error_e state_machine_op_lock(state_t* s, operation_t* o, lock_response_t* r);
crabs_error_e state_machine_op_extend(state_t* s, operation_t* o);
crabs_error_e state_machine_op_verify(state_t* s, operation_t* o);
crabs_error_e state_machine_op_rollback(state_t* s, operation_t* o);
crabs_error_e state_machine_op_unlock(state_t* s, operation_t* o);
crabs_error_e state_machine_op_force_unlock(state_t* s, operation_t* o);
crabs_error_e state_machine_op_change_config(state_t* s, operation_t* o);
crabs_error_e state_machine_op_register_key(state_t* s, operation_t* o);
crabs_error_e state_machine_op_revoke_key(state_t* s, operation_t* o);
crabs_error_e state_machine_op_set_default_key(state_t* s, operation_t* o);
crabs_error_e state_machine_op_suspend_key(state_t* s, operation_t* o);
crabs_error_e state_machine_op_activate_key(state_t* s, operation_t* o);
crabs_error_e state_machine_op_rotate_key(state_t* s, operation_t* o);
crabs_error_e state_machine_op_compact(state_t* s, operation_t* o);

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
  // Note: __verify__ on MODIFIED can transition to either VERIFIED or ERROR
  // depending on invariant checks. The table records the primary (success)
  // transition; the handler sets ERROR when invariants fail.
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
  // Compaction operation (v1.5.2 §4.3): valid in any state, no state change
  {PROTOCOL_IDLE,     CRABS_OP_COMPACT,            PROTOCOL_IDLE},
  {PROTOCOL_LOCKED,   CRABS_OP_COMPACT,            PROTOCOL_LOCKED},
  {PROTOCOL_MODIFIED, CRABS_OP_COMPACT,            PROTOCOL_MODIFIED},
  {PROTOCOL_VERIFIED, CRABS_OP_COMPACT,            PROTOCOL_VERIFIED},
  {PROTOCOL_ERROR,    CRABS_OP_COMPACT,            PROTOCOL_ERROR},
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
          strcmp(type, CRABS_OP_CHECK_DEDUP) == 0 ||
          strcmp(type, CRABS_OP_EXECUTE_OT) == 0 ||
          strcmp(type, CRABS_OP_COMPACT) == 0);
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
// Cross-System Operation Ordering (v1.6 Amd6 §10.2)
// ============================================================

int crabs_operation_compare(const operation_t* a, const operation_t* b) {
  if (a == NULL && b == NULL) return 0;
  if (a == NULL) return -1;
  if (b == NULL) return 1;

  // Cross-system ordering: Lamport operations sort before HLC operations
  if (a->ordering_system == CRABS_ORDERING_LAMPORT &&
      b->ordering_system == CRABS_ORDERING_HLC) {
    return -1;  // Lamport before HLC
  }
  if (a->ordering_system == CRABS_ORDERING_HLC &&
      b->ordering_system == CRABS_ORDERING_LAMPORT) {
    return 1;  // HLC after Lamport
  }

  // Same ordering system: use system-specific ordering
  if (a->ordering_system == CRABS_ORDERING_HLC) {
    // HLC ordering: compare by (physical_seconds, physical_nanos,
    // logical_counter, node_id)
    return crabs_hlc_compare(&a->hlc, &b->hlc);
  }

  // Lamport ordering: compare by (lamport_time, node_id)
  if (a->lamport_time < b->lamport_time) return -1;
  if (a->lamport_time > b->lamport_time) return 1;
  return strcmp(a->node_id, b->node_id);
}

// ============================================================
// Lock Token Generation
// ============================================================
void state_machine_generate_lock_token(uint8_t token[CRABS_LOCK_TOKEN_SIZE]) {
  // Lock tokens are bearer credentials — they MUST come from a CSPRNG.
  // A failure here is a fatal error; we must never fall back to rand(),
  // which is unseeded and predictable. The caller treats an all-zero token
  // as "generation failed" and must abort the lock acquisition.
  if (RAND_bytes(token, CRABS_LOCK_TOKEN_SIZE) != 1) {
    memset(token, 0, CRABS_LOCK_TOKEN_SIZE);
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
// HLC-aware Lock Expiry (v1.6 Amd6 §8)
// ============================================================
bool state_machine_lock_expired(state_t* state, const lock_state_t* lock, uint64_t now_ms) {
  if (state == NULL || lock == NULL) return true;

  crabs_ordering_config_t* config = state_get_ordering_config(state);
  if (config != NULL && config->ordering_system == CRABS_ORDERING_HLC) {
    // R8-T-1: use the authenticated now_ms passed in, NOT the unauthenticated
    // system clock. The prior code called crabs_hlc_get_system_time(NULL),
    // letting a browser attacker (WASM Date.now is page-overridable) freeze
    // lock expiry. now_ms is milliseconds since epoch; convert to s/ns.
    uint64_t now_seconds = now_ms / 1000;
    uint64_t now_nanos = (now_ms % 1000) * 1000000;
    uint64_t total_duration_ms = state->config.max_lock_duration_ms +
      (uint64_t)lock->lock_extensions * state->config.max_lock_duration_ms;
    crabs_hlc_t expiry = crabs_hlc_add_duration(lock->lock_acquired_at, total_duration_ms);
    return (now_seconds > expiry.physical_seconds) ||
           (now_seconds == expiry.physical_seconds && now_nanos > expiry.physical_nanos);
  }

  // Fallback: wall-clock millisecond comparison
  return now_ms >= lock->lock_expiry;
}

// Lock Pruning (§7.4 step 1)
// ============================================================
uint32_t state_machine_prune_expired(state_t* state, uint64_t now_ms) {
  uint32_t pruned = 0;
  data_item_t* item = state->items;
  while (item != NULL) {
    if (item->type == DATA_TYPE_RESOURCE && item->protocol_state != PROTOCOL_IDLE) {
      if (state_machine_lock_expired(state, &item->lock_state, now_ms)) {
        item->protocol_state = PROTOCOL_IDLE;
        item->lock_state.lock_token_valid = false;
        OPENSSL_cleanse(item->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE);
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
// Log helper
// ============================================================
// Compute a tamper-evident hash-chain entry: state_hash = SHA256(prev_hash ||
// version || uuid || type || signer_id || lamport_time || node_id). The
// previous entry's state_hash (or an all-zero seed for the first entry) is
// mixed in so that altering or removing any historical entry breaks the
// chain (audit M-8: previously state_hash was always zero).
static void _compute_log_chain_hash(state_t* state, log_entry_t* entry) {
  uint8_t prev[CRABS_HASH_SIZE];
  memset(prev, 0, CRABS_HASH_SIZE);
  if (state->log_count > 1) {
    memcpy(prev, state->log[state->log_count - 2].state_hash, CRABS_HASH_SIZE);
  }
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) { memset(entry->state_hash, 0, CRABS_HASH_SIZE); return; }
  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(ctx, prev, CRABS_HASH_SIZE);
  EVP_DigestUpdate(ctx, &entry->version, sizeof(entry->version));
  EVP_DigestUpdate(ctx, entry->uuid, CRABS_UUID_SIZE);
  // Audit N-13: use strlen (not strnlen) since the fields are guaranteed
  // NUL-terminated by the strncat calls in append_log above. strnlen would
  // read up to the max buffer size even when the string is shorter, hashing
  // whatever bytes follow the intended string — bounded and safe, but
  // include only the intended bytes for a stable, well-defined chain hash.
  EVP_DigestUpdate(ctx, entry->type, strlen(entry->type));
  EVP_DigestUpdate(ctx, entry->signer_id, strlen(entry->signer_id));
  EVP_DigestUpdate(ctx, &entry->lamport_time, sizeof(entry->lamport_time));
  EVP_DigestUpdate(ctx, entry->node_id, strlen(entry->node_id));
  unsigned int hlen = 0;
  EVP_DigestFinal_ex(ctx, entry->state_hash, &hlen);
  EVP_MD_CTX_free(ctx);
}

// R8-S-4: returns false on realloc failure so the caller can fail the op
// instead of silently continuing (which would leave a gap in the audit chain
// and skip the R7-11 lamport backstop entry).
static bool append_log(state_t* state, const uint8_t uuid[CRABS_UUID_SIZE],
                       const char* type, const char* signer_id,
                       uint64_t lamport_time, const char* node_id,
                       crabs_ordering_system_e ordering_system,
                       const crabs_hlc_t* hlc,
                       const uint8_t state_hash[CRABS_HASH_SIZE]) {
  (void)state_hash; // the chain hash is computed below; the caller's value is ignored
  uint64_t new_count = state->log_count + 1;
  log_entry_t* new_log = realloc(state->log, new_count * sizeof(log_entry_t));
  if (new_log == NULL) return false;
  state->log = new_log;
  state->log_count = new_count;
  log_entry_t* entry = &state->log[state->log_count - 1];
  entry->version = state->version;
  // v1.6 Amd6: record the ordering system and HLC so the R7-11 replay
  // backstop can compare HLC-ordered ops by HLC. Zero the HLC for lamport
  // ops so log entries never carry uninitialized bytes.
  entry->ordering_system = ordering_system;
  if (ordering_system == CRABS_ORDERING_HLC && hlc != NULL) {
    entry->hlc = *hlc;
  } else {
    memset(&entry->hlc, 0, sizeof(entry->hlc));
  }
  memcpy(entry->uuid, uuid, CRABS_UUID_SIZE);
  entry->type[0] = '\0';
  strncat(entry->type, type, CRABS_MAX_OP_NAME - 1);
  entry->signer_id[0] = '\0';
  strncat(entry->signer_id, signer_id, CRABS_MAX_USER_ID - 1);
  entry->lamport_time = lamport_time;
  entry->node_id[0] = '\0';
  strncat(entry->node_id, node_id, CRABS_MAX_USER_ID - 1);
  _compute_log_chain_hash(state, entry);
  return true;
}

// ============================================================
// User-Defined Operation Handler Registry
// ============================================================

crabs_error_e state_machine_register_handler(state_t* state, const char* op_type,
                                              op_handler_fn handler) {
  if (state == NULL || op_type == NULL || handler == NULL) return CRABS_ERR_INVALID_PARAM;

  for (uint32_t i = 0; i < state->op_handler_count; i++) {
    if (strcmp(state->op_handlers[i].op_type, op_type) == 0) {
      state->op_handlers[i].handler = handler;
      return CRABS_SUCCESS;
    }
  }

  if (state->op_handler_count >= CRABS_MAX_OP_HANDLERS) return CRABS_ERR_OOM;

  uint32_t new_count = state->op_handler_count + 1;
  op_handler_entry_t* new_handlers = realloc(state->op_handlers,
      new_count * sizeof(op_handler_entry_t));
  if (new_handlers == NULL) return CRABS_ERR_OOM;
  state->op_handlers = new_handlers;
  uint32_t idx = state->op_handler_count;
  state->op_handler_count = new_count;
  memset(&state->op_handlers[idx], 0, sizeof(op_handler_entry_t));
  strncpy(state->op_handlers[idx].op_type, op_type, CRABS_MAX_OP_NAME - 1);
  state->op_handlers[idx].op_type[CRABS_MAX_OP_NAME - 1] = '\0';
  state->op_handlers[idx].handler = handler;
  return CRABS_SUCCESS;
}

void state_machine_unregister_handler(state_t* state, const char* op_type) {
  if (state == NULL || op_type == NULL) return;
  for (uint32_t i = 0; i < state->op_handler_count; i++) {
    if (strcmp(state->op_handlers[i].op_type, op_type) == 0) {
      if (i < state->op_handler_count - 1) {
        memmove(&state->op_handlers[i], &state->op_handlers[i + 1],
                (state->op_handler_count - i - 1) * sizeof(op_handler_entry_t));
      }
      state->op_handler_count--;
      return;
    }
  }
}

op_handler_fn state_machine_find_handler(const state_t* state, const char* op_type) {
  if (state == NULL || op_type == NULL) return NULL;
  for (uint32_t i = 0; i < state->op_handler_count; i++) {
    if (strcmp(state->op_handlers[i].op_type, op_type) == 0) {
      return state->op_handlers[i].handler;
    }
  }
  return NULL;
}

// ============================================================
// Main Execution Algorithm (§7.4)
// ============================================================

// R7-01: get the current physical time in ms from the state's HLC time source.
// Returns false when no authenticated time is available (fail-closed for
// expiry decisions). When no time source is configured, falls back to the
// system clock (backward compatible).
static bool state_get_time_ms(const state_t* state, uint64_t* now_ms) {
  if (state == NULL || now_ms == NULL) return false;
  crabs_physical_time_t phys = crabs_hlc_get_physical_time(&((state_t*)state)->hlc_state);
  if (!phys.valid) return false;
  *now_ms = phys.seconds * 1000 + phys.nanos / 1000000;
  return true;
}

// R7-11: the most recent log entry for a signer. Returns false if the
// signer has no logged ops (so a first op is never rejected). Scans the log
// from the tail (a signer's latest op is near the end). Used to enforce
// ordering monotonicity so a replayed op — which carries the same ordering
// timestamp as the original — is rejected even after a restart, when the
// in-memory tx_manager has been reset.
static bool state_last_log_entry_for_signer(const state_t* state, const char* signer_id,
                                            const log_entry_t** out) {
  if (state == NULL || signer_id == NULL || out == NULL) return false;
  for (uint64_t entry_index = state->log_count; entry_index > 0; entry_index--) {
    const log_entry_t* entry = &state->log[entry_index - 1];
    if (strcmp(entry->signer_id, signer_id) == 0) {
      *out = entry;
      return true;
    }
  }
  return false;
}

crabs_error_e state_machine_execute(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;

  // Step 1: Prune expired locks
  uint64_t now_ms;
  if (!state_get_time_ms(state, &now_ms)) {
    // R7-01: no authenticated time — fail closed rather than use the
    // attacker-controlled local clock for expiry decisions.
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  state_machine_prune_expired(state, now_ms);

  // Audit H-C: inject the wall clock into the attribute machine and prune
  // expired temporary attributes BEFORE authorization. Without this, an
  // expired temporary attribute (issued via attribute_machine_issue_temporary)
  // would continue to satisfy policies indefinitely — current_time_ms stays 0
  // and prune_expired_temporary never removes anything.
  if (state->attr_machine != NULL) {
    attribute_machine_set_time(state->attr_machine, now_ms);
    attribute_machine_prune_expired_temporary(state->attr_machine);
  }

  // Step 3: Authorization (§10.3) — fail closed. Every operation requires a
  // registered policy and a valid signature.
  // Audit L-a: authorize BEFORE the protocol/lock/dedup checks (steps 4-6)
  // so an unauthenticated caller cannot learn resource existence, lock
  // state, or dedup-tracker membership from distinct error codes. An
  // unauthenticated caller gets a single CRABS_ERR_UNAUTHORIZED; an
  // authenticated caller still receives the specific protocol error below.
  if (state->attr_machine == NULL) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  const char* policy = state_find_policy(state, op->type);
  if (policy == NULL) {
    // No policy registered for this operation type — reject.
    return CRABS_ERR_UNAUTHORIZED;
  }

  // Resolve CONTAINS operators and {user_id} placeholders in the policy.
  policy_preprocess_result_t pp = preprocess_policy(policy, state, op->signer_id);
  if (!pp.resolved_ok) {
    return CRABS_ERR_UNAUTHORIZED;
  }

  verify_mode_e mode = (op->signer_id[0] != '\0') ? VERIFY_MODE_A : VERIFY_MODE_B;

  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  if (ser == NULL) {
    return CRABS_ERR_SERIALIZATION_ERROR;
  }
  if (state->abe_mk == NULL) {
    serialized_buffer_destroy(ser);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  verify_result_t vr;
  if (op->sig_scheme != SCHEME_UNSPECIFIED || op->key_id[0] != '\0') {
    // v1.3: Scheme-aware verification
    vr = crypto_verify_operation_auth_v2(
        state->abe_mk, pp.abe_policy, state->attr_machine,
        ser->data, ser->len,
        op->signature, CRABS_SIG_SIZE,
        op->signer_id, op->key_id, op->sig_scheme, mode);
  } else {
    // Legacy ECDSA verification
    vr = crypto_verify_operation_auth(
        state->abe_mk, pp.abe_policy, state->attr_machine,
        ser->data, ser->len,
        op->signature, op->signer_id, mode);
  }

  serialized_buffer_destroy(ser);

  if (!vr.authorized) {
    return vr.error;
  }

  // Step 3b: Transaction manager accept (replay protection).
  // R7-L-4: this runs AFTER signature verification but BEFORE the protocol
  // state / lock / dedup checks. The prior placement at the top of execute()
  // let an attacker probe whether a UUID was already processed by sending an
  // op with a bad signature and observing ALREADY_EXECUTED vs UNAUTHORIZED — a
  // processed-UUID existence oracle. Placing it after authorization closes
  // the oracle while still detecting a replayed op as a duplicate before any
  // state-dependent check (e.g. a replayed LOCK whose resource is now LOCKED)
  // can misreport it as a protocol violation. Delegates to the pluggable
  // tx_manager — may be a no-op, an in-memory hash set, or a persistent store.
  // Returns CRABS_ERR_ALREADY_EXECUTED for duplicates (caller treats as
  // idempotent success).
  if (state->tx_manager != NULL) {
    crabs_tx_manager_t* tx = (crabs_tx_manager_t*)state->tx_manager;
    if (tx->vtable.accept != NULL) {
      crabs_error_e tx_result = tx->vtable.accept(tx, state, op);
      if (tx_result != CRABS_SUCCESS) return tx_result;
    }
  }

  // Step 3c: Ordering monotonicity (R7-11 + v1.6 Amd6). A replayed op
  // carries the same ordering timestamp as the original, so require the op
  // to be strictly newer than the signer's last logged op. HLC-ordered ops
  // are compared by HLC (they may legitimately carry lamport_time 0);
  // lamport-ordered ops by lamport_time. Cross-system: lamport ops sort
  // before HLC ops, so an HLC op is always newer than a lamport-logged one.
  // This survives restarts when the log is durable, closing the
  // cross-session replay gap for plain (non-dedup) ops that the in-memory
  // tx_manager cannot cover after a reset.
  const log_entry_t* last_signer_entry = NULL;
  if (state_last_log_entry_for_signer(state, op->signer_id, &last_signer_entry)) {
    bool is_replay = false;
    if (op->ordering_system == CRABS_ORDERING_HLC) {
      if (last_signer_entry->ordering_system == CRABS_ORDERING_HLC) {
        is_replay = crabs_hlc_compare(&op->hlc, &last_signer_entry->hlc) <= 0;
      }
      // Last entry was lamport-ordered: any HLC op is newer by the
      // cross-system ordering rule (lamport sorts before HLC).
    } else {
      is_replay = op->lamport_time <= last_signer_entry->lamport_time;
    }
    if (is_replay) {
      return CRABS_ERR_ALREADY_EXECUTED;
    }
  }

  // Step 4: Verify protocol state transitions
  for (uint32_t i = 0; i < op->resource_count; i++) {
    data_item_t* item = state_find_item(state, op->resources[i]);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    if (item->protocol_state != op->required_state[i]) {
      return CRABS_ERR_PROTOCOL_VIOLATION;
    }
  }

  // Step 5: Verify lock claims
  for (uint32_t i = 0; i < op->lock_claim_count; i++) {
    data_item_t* item = state_find_item(state, op->lock_claims[i].resource);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    if (item->protocol_state == PROTOCOL_LOCKED ||
        item->protocol_state == PROTOCOL_MODIFIED) {
      if (!item->lock_state.lock_token_valid ||
          CRYPTO_memcmp(item->lock_state.lock_token, op->lock_claims[i].lock_token,
                        CRABS_LOCK_TOKEN_SIZE) != 0) {
        return CRABS_ERR_LOCK_TOKEN_MISMATCH;
      }
      if (strlen(op->signer_id) > 0 &&
          strcmp(item->lock_state.lock_owner, op->signer_id) != 0) {
        return CRABS_ERR_LOCK_OWNER_MISMATCH;
      }
    }
  }

  // Step 6: Dedup guard check (v1.4 §5.2-5.3)
  // R7-13: check the guard BEFORE the handler but apply the mutation only
  // AFTER the handler succeeds. The prior check-and-apply burned the dedup
  // slot (e.g. a ONE_SHOT_SET membership) even when the handler failed,
  // letting an authorized signer permanently consume a "vote once" slot.
  // The registered spec always wins over the op-carried spec.
  const dedup_spec_t* registered_dedup = state_find_op_type_def(state, op->type);
  const dedup_spec_t* effective_dedup = registered_dedup ? registered_dedup : &op->dedup;
  if (effective_dedup->type != DEDUP_NONE) {
    crabs_error_e dedup_result = dedup_check_guard_spec(state, effective_dedup, op);
    if (dedup_result != CRABS_SUCCESS) {
      return dedup_result;
    }
    // R8-S-3: validate the mutation BEFORE the handler runs. The mutation is
    // applied after the handler (R7-13, so a failing op does not burn its
    // dedup slot); validating first ensures a mutation that would fail is
    // rejected before the handler's effects are applied, avoiding partial
    // application.
    dedup_result = dedup_validate_mutation_spec(state, effective_dedup, op);
    if (dedup_result != CRABS_SUCCESS) {
      return dedup_result;
    }
  }

  // Step 6: Key version verification (§10.4)
  // R7-04: the check is mandatory when the signer has a nonzero key_version.
  // The prior `op->signer_key_version > 0` guard let a crafted op with
  // signer_key_version = 0 skip the staleness check entirely, so a replayed op
  // signed with a rotated-out key was accepted.
  if (state->attr_machine != NULL) {
    user_t* signer = attribute_machine_find_user(state->attr_machine, op->signer_id);
    if (signer != NULL && signer->key_version > 0 &&
        signer->key_version != op->signer_key_version) {
      return CRABS_ERR_KEY_STALE;
    }
  }

  // Step 6b: Scheme constraint enforcement (v1.3 §7)
  // R7-04: the allowlist is enforced regardless of the op's declared scheme.
  // The prior `op->sig_scheme != SCHEME_UNSPECIFIED` guard let an op bypass
  // the allowlist by declaring the legacy path.
  if (state->policies != NULL) {
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

  // Step 6c: Co-signature verification and threshold enforcement (v1.3 §4.2).
  // Every co-signature is cryptographically verified against the canonical
  // signed form; co-signers must be distinct from each other and from the
  // primary signer. When a threshold is configured, it is enforced
  // unconditionally (no fail-open bypass).
  if (op->co_signer_count > 0) {
    serialized_buffer_t* co_ser = crabs_serialize_for_signing(op);
    if (co_ser == NULL) return CRABS_ERR_SERIALIZATION_ERROR;

    for (uint32_t i = 0; i < op->co_signer_count; i++) {
      const co_signature_t* cs = &op->co_signers[i];
      if (cs->signer_id[0] == '\0') {
        serialized_buffer_destroy(co_ser);
        return CRABS_ERR_INVALID_PARAM;
      }
      // Distinctness: no co-signer may duplicate another or the primary signer.
      if (strcmp(cs->signer_id, op->signer_id) == 0) {
        serialized_buffer_destroy(co_ser);
        return CRABS_ERR_DUPLICATE_OPERATION;
      }
      for (uint32_t j = 0; j < i; j++) {
        if (strcmp(cs->signer_id, op->co_signers[j].signer_id) == 0) {
          serialized_buffer_destroy(co_ser);
          return CRABS_ERR_DUPLICATE_OPERATION;
        }
      }
      crabs_error_e cs_rc = crypto_verify_co_signature(
          state->attr_machine,
          pp.abe_policy,
          cs->signer_id, cs->key_id, cs->sig_scheme,
          co_ser->data, co_ser->len,
          cs->signature, cs->signature_len);
      if (cs_rc != CRABS_SUCCESS) {
        serialized_buffer_destroy(co_ser);
        return CRABS_ERR_UNAUTHORIZED;
      }
    }
    serialized_buffer_destroy(co_ser);
  }

  if (state->config.sig_config.co_sign_threshold > 0 &&
      op->co_signer_count < state->config.sig_config.co_sign_threshold) {
    return CRABS_ERR_UNAUTHORIZED;
  }

  // Step 7: Execute operation handler
  crabs_error_e result;
  op_handler_fn custom_handler = NULL;
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
  } else if (strcmp(op->type, CRABS_OP_COMPACT) == 0) {
    // Compaction operation (v1.5.2 §4.3)
    result = state_machine_op_compact(state, op);
  } else {
    // Check user-defined handler registry for non-builtin operation types
    custom_handler = state_machine_find_handler(state, op->type);
    if (custom_handler != NULL) {
      result = custom_handler(state, op);
    } else {
      result = CRABS_SUCCESS;
    }
  }

  if (result != CRABS_SUCCESS) return result;

  // Step 7b: Apply protocol state transitions for non-builtin operations
  // (§6.3 wildcard: LOCKED → MODIFIED). Builtin operations manage their own
  // protocol state in their handlers. Skip when a custom handler was invoked
  // — the handler owns its own protocol state transitions.
  if (!operation_is_builtin(op->type) && custom_handler == NULL) {
    for (uint32_t i = 0; i < op->resource_count; i++) {
      data_item_t* item = state_find_item(state, op->resources[i]);
      if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
      if (item->type != DATA_TYPE_RESOURCE) continue; // only RESOURCE has protocol state
      if (item->protocol_state == PROTOCOL_LOCKED) {
        item->protocol_state = PROTOCOL_MODIFIED;
      } else {
        // A user operation may only be applied to a LOCKED resource (the
        // wildcard transition). Other states require a builtin transition.
        return CRABS_ERR_PROTOCOL_VIOLATION;
      }
    }
  }

  // R7-13: apply the dedup mutation only after the handler (and protocol
  // transition) succeeded, so a failing op does not burn its dedup slot.
  if (effective_dedup->type != DEDUP_NONE) {
    crabs_error_e dedup_result = dedup_apply_mutation_spec(state, effective_dedup, op);
    if (dedup_result != CRABS_SUCCESS) {
      return dedup_result;
    }
  }

  // Step 8: Auto-compaction check after OT operations (v1.5.2 §4)
  if (state->compaction_config != NULL &&
      strcmp(op->type, CRABS_OP_EXECUTE_OT) == 0) {
    state_machine_auto_compact(state);
  }

  // Step 9: Transition protocol states and log operation
  uint8_t state_hash[CRABS_HASH_SIZE];
  memset(state_hash, 0, CRABS_HASH_SIZE);
  // R8-S-4: a failed append_log must fail the op BEFORE version++ and the
  // tx_manager commit, so the audit chain and the R7-11 lamport backstop stay
  // consistent (no gap, no missing entry).
  if (!append_log(state, op->uuid, op->type, op->signer_id,
                  op->lamport_time, op->node_id, op->ordering_system, &op->hlc,
                  state_hash)) {
    return CRABS_ERR_OOM;
  }
  state->version++;

  // Step 8c: Commit to transaction manager (replay protection).
  if (state->tx_manager != NULL) {
    crabs_tx_manager_t* tx = (crabs_tx_manager_t*)state->tx_manager;
    if (tx->vtable.commit != NULL) {
      tx->vtable.commit(tx, state, op);
    }
  }

  // Step 9: Process triggers (Amendment 1, §5.2)
  // Pass the attribute machine so trigger effects (e.g. ISSUE_ATTRIBUTE) can
  // actually issue attributes. The prior code passed NULL here, which made
  // _execute_trigger_effect silently skip ISSUE_ATTRIBUTE effects (the
  // function checks `if (am == NULL) return CRABS_SUCCESS;`). This meant
  // threshold triggers never issued attributes — a functional bug.
  if (state->triggers != NULL && state->trigger_count > 0) {
    uint64_t trigger_now_ms;
    if (!state_get_time_ms(state, &trigger_now_ms)) {
      return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
    }
    trigger_process_all(state, state->triggers, state->trigger_count,
                        (attribute_machine_t*)state->attr_machine, trigger_now_ms);
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
      uint64_t lock_check_ms;
      if (!state_get_time_ms(state, &lock_check_ms)) {
        return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
      }
      if (!state_machine_lock_expired(state, &item->lock_state, lock_check_ms)) {
        return CRABS_ERR_LOCK_OWNER_MISMATCH;
      }
    }
  }

  uint64_t now_ms;
  if (!state_get_time_ms(state, &now_ms)) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  uint64_t expiry = now_ms + state->config.max_lock_duration_ms;

  // v1.6 Amd6 §8: Set HLC acquired_at if using HLC ordering. Reuse the
  // persistent per-node HLC state on the state so the logical counter
  // advances and clock-regression protection holds across lock acquisitions
  // (audit M-10: previously each lock built a fresh HLC state, resetting the
  // counter).
  crabs_hlc_t acquired_at = {0, 0, 0, {'\0'}};
  crabs_ordering_config_t* config = state_get_ordering_config(state);
  if (config != NULL && config->ordering_system == CRABS_ORDERING_HLC) {
    if (!state->hlc_state_initialized) {
      crabs_hlc_state_init(&state->hlc_state, op->node_id);
      state->hlc_state_initialized = true;
    }
    acquired_at = crabs_hlc_next(&state->hlc_state);
  }

  response->success = true;
  response->token_count = op->resource_count;
  response->expiry = expiry;
  response->acquired_at = acquired_at;

  for (uint32_t i = 0; i < op->resource_count; i++) {
    data_item_t* item = state_find_item(state, op->resources[i]);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;

    state_machine_generate_lock_token(response->lock_tokens[i]);
    // If CSPRNG generation failed, the token is all-zeros. Lock tokens are
    // bearer credentials — never store a predictable token.
    static const uint8_t zero_token[CRABS_LOCK_TOKEN_SIZE] = {0};
    if (memcmp(response->lock_tokens[i], zero_token, CRABS_LOCK_TOKEN_SIZE) == 0) {
      // Audit N-8: roll back already-acquired locks before failing. The prior
      // code returned the error here, leaving resources 0..i-1 in LOCKED with
      // tokens the caller never received — only expiry/force-unlock could
      // release them (a denial-of-service on those resources). Restore each
      // already-locked item to IDLE, clear its token, and free its snapshot
      // so the all-or-nothing semantics from §4.1 hold.
      for (uint32_t j = 0; j < i; j++) {
        data_item_t* locked = state_find_item(state, op->resources[j]);
        if (locked == NULL) continue;
        locked->protocol_state = PROTOCOL_IDLE;
        locked->lock_state.lock_token_valid = false;
        OPENSSL_cleanse(locked->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE);
        memset(locked->lock_state.lock_owner, 0, CRABS_MAX_USER_ID);
        if (locked->lock_state.pre_lock_snapshot != NULL) {
          free(locked->lock_state.pre_lock_snapshot);
          locked->lock_state.pre_lock_snapshot = NULL;
        }
        locked->lock_state.lock_extensions = 0;
      }
      return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
    }
    memcpy(item->lock_state.lock_token, response->lock_tokens[i], CRABS_LOCK_TOKEN_SIZE);
    item->lock_state.lock_token_valid = true;
    strncpy(item->lock_state.lock_owner, op->signer_id, CRABS_MAX_USER_ID - 1);
    item->lock_state.lock_expiry = expiry;
    item->lock_state.lock_extensions = 0;
    item->lock_state.lock_acquired_at = acquired_at;

    if (item->value != NULL) {
      size_t value_size = 0;
      if (item->type == DATA_TYPE_COUNTER || item->type == DATA_TYPE_PN_COUNTER ||
          item->type == DATA_TYPE_RESOURCE) {
        value_size = sizeof(int64_t);
      } else if (item->type == DATA_TYPE_REGISTER) {
        value_size = sizeof(int64_t);
      }
      if (value_size > 0) {
        if (item->lock_state.pre_lock_snapshot != NULL) {
          free(item->lock_state.pre_lock_snapshot);
        }
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
    // R8-S-1: only the lock owner may extend. The Step-5 lock-claim check only
    // runs when the op carries claims; an op without claims must still be
    // rejected if the signer is not the owner.
    if (!item->lock_state.lock_token_valid ||
        strcmp(item->lock_state.lock_owner, op->signer_id) != 0) {
      return CRABS_ERR_LOCK_OWNER_MISMATCH;
    }
    if (item->lock_state.lock_extensions >= state->config.max_lock_extensions) {
      return CRABS_ERR_MAX_EXTENSIONS_REACHED;
    }
    uint64_t now_ms;
    if (!state_get_time_ms(state, &now_ms)) {
      return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
    }
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
    // R8-S-1: only the lock owner may roll back. The Step-5 lock-claim check
    // only runs when the op carries claims; an op without claims must still be
    // rejected if the signer is not the owner.
    if (!item->lock_state.lock_token_valid ||
        strcmp(item->lock_state.lock_owner, op->signer_id) != 0) {
      return CRABS_ERR_LOCK_OWNER_MISMATCH;
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
    // R8-S-1: only the lock owner may unlock. The Step-5 lock-claim check only
    // runs when the op carries claims; an op without claims must still be
    // rejected if the signer is not the owner.
    if (!item->lock_state.lock_token_valid ||
        strcmp(item->lock_state.lock_owner, op->signer_id) != 0) {
      return CRABS_ERR_LOCK_OWNER_MISMATCH;
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

crabs_error_e state_machine_op_force_unlock(state_t* state, operation_t* op) {
  if (!state->config.allow_force_unlock) return CRABS_ERR_FORCE_UNLOCK_DISABLED;
  uint64_t now_ms;
  if (!state_get_time_ms(state, &now_ms)) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  for (uint32_t i = 0; i < op->resource_count; i++) {
    data_item_t* item = state_find_item(state, op->resources[i]);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    if (!state_machine_lock_expired(state, &item->lock_state, now_ms)) {
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

// Audit M-A: find the value portion after "key=" in the config payload. The
// prior code paired each strstr(KEY) with strchr(payload, '=') which found the
// FIRST '=' in the whole payload, so "max_lock_extensions=0;max_lock_duration_ms=60000"
// parsed the duration from "0;..." → 0, making every lock instantly expire
// (force-unlock hijack). This helper finds the '=' immediately after the
// matched key and requires the key to start at the buffer or after a ';'
// separator, so "x_max_lock_duration_ms=" cannot match "max_lock_duration_ms=".
static char* _config_value_after(char* payload, const char* key) {
  if (payload == NULL || key == NULL) return NULL;
  size_t klen = strlen(key);
  char* p = payload;
  while ((p = strstr(p, key)) != NULL) {
    bool at_boundary = (p == payload) || (p[-1] == ';') || (p[-1] == ' ');
    if (at_boundary && p[klen] == '=') {
      return p + klen + 1;
    }
    p += klen;
  }
  return NULL;
}

// Upper bound on max_lock_duration_ms. Audit M-B: the lock-expiry computation
// `max_lock_duration_ms + extensions * max_lock_duration_ms` wraps uint64 for
// attacker-set huge values, which can make an active lock read as expired
// (force-unlock hijack). Clamping here keeps the arithmetic in range; the
// default is 5s and a 24h ceiling is generous.
#define CRABS_MAX_LOCK_DURATION_MS_CAP 86400000ULL

crabs_error_e state_machine_op_change_config(state_t* state, operation_t* op) {
  if (op->payload == NULL || op->payload_size == 0) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // op->payload is a byte array with explicit payload_size and no NUL
  // termination guarantee. Copy into a bounded buffer and NUL-terminate
  // before any string operations to avoid an out-of-bounds read.
  char payload_buf[1024];
  uint32_t copy_len = op->payload_size < sizeof(payload_buf) - 1
                        ? op->payload_size : (uint32_t)sizeof(payload_buf) - 1;
  memcpy(payload_buf, op->payload, copy_len);
  payload_buf[copy_len] = '\0';
  char* payload_str = payload_buf;

  // R8-S-2: validate every pair BEFORE applying any, so a later failing pair
  // cannot leave earlier pairs applied (partial config mutation). The prior
  // code applied pairs incrementally and returned on the first failure, so an
  // authorized user could set max_lock_duration_ms=1 then trigger a failure,
  // permanently shortening all lock durations.
  char* v;
  if ((v = _config_value_after(payload_str, "allow_force_unlock")) != NULL) {
    bool requested = (strcmp(v, "true") == 0);
    if (!requested && state->config.allow_force_unlock) {
      return CRABS_ERR_UNAUTHORIZED;
    }
  }
  if ((v = _config_value_after(payload_str, "co_sign_threshold")) != NULL) {
    uint32_t val = (uint32_t)atol(v);
    if (val == 0) return CRABS_ERR_UNAUTHORIZED;
  }

  // Apply pass — cannot fail after the validation pass above.
  if ((v = _config_value_after(payload_str, "max_lock_duration_ms")) != NULL) {
    uint64_t val = (uint64_t)atoll(v);
    // Audit M-B: clamp to a sane ceiling so the expiry arithmetic cannot wrap.
    if (val > CRABS_MAX_LOCK_DURATION_MS_CAP) val = CRABS_MAX_LOCK_DURATION_MS_CAP;
    state->config.max_lock_duration_ms = val;
  }
  if ((v = _config_value_after(payload_str, "max_lock_extensions")) != NULL) {
    uint32_t val = (uint32_t)atol(v);
    // Audit M-B: with max_lock_duration_ms capped at 24h, extensions up to
    // ~2^43 still cannot overflow the `extensions * duration` multiply.
    // 1024 is far above any legitimate use and keeps the arithmetic safe.
    if (val > 1024) val = 1024;
    state->config.max_lock_extensions = val;
  }
  if ((v = _config_value_after(payload_str, "allow_force_unlock")) != NULL) {
    bool requested = (strcmp(v, "true") == 0);
    if (!requested && state->config.allow_force_unlock) {
      return CRABS_ERR_UNAUTHORIZED;
    }
    state->config.allow_force_unlock = requested;
  }
  if ((v = _config_value_after(payload_str, "default_scheme")) != NULL) {
    state->config.sig_config.default_scheme = (signature_scheme_e)atoi(v);
  }
  if ((v = _config_value_after(payload_str, "max_keys_per_user")) != NULL) {
    uint32_t val = (uint32_t)atol(v);
    if (val == 0) val = 1; // must allow at least one key
    if (val > 64) val = 64;
    state->config.sig_config.max_keys_per_user = val;
  }
  if ((v = _config_value_after(payload_str, "key_rotation_enabled")) != NULL) {
    state->config.sig_config.key_rotation_enabled = (strcmp(v, "true") == 0);
  }
  if ((v = _config_value_after(payload_str, "co_sign_threshold")) != NULL) {
    uint32_t val = (uint32_t)atol(v);
    if (val == 0) return CRABS_ERR_UNAUTHORIZED;
    if (val > 32) val = 32;
    state->config.sig_config.co_sign_threshold = val;
  }
  if ((v = _config_value_after(payload_str, "key_expiry_enabled")) != NULL) {
    state->config.sig_config.key_expiry_enabled = (strcmp(v, "true") == 0);
  }
  if ((v = _config_value_after(payload_str, "default_key_ttl_ms")) != NULL) {
    state->config.sig_config.default_key_ttl_ms = (uint64_t)atoll(v);
  }
  if ((v = _config_value_after(payload_str, "max_key_age_ms")) != NULL) {
    state->config.sig_config.max_key_age_ms = (uint64_t)atoll(v);
  }
  if ((v = _config_value_after(payload_str, "vault_provider")) != NULL) {
    state->config.vault_config.provider = (vault_provider_e)atoi(v);
  }
  if ((v = _config_value_after(payload_str, "vault_signing_delegated")) != NULL) {
    state->config.vault_config.signing_delegated = (strcmp(v, "true") == 0);
  }
  if ((v = _config_value_after(payload_str, "vault_rotation_delegated")) != NULL) {
    state->config.vault_config.rotation_delegated = (strcmp(v, "true") == 0);
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
  // Audit R4-2: whitelist USER_ACTIVE. The prior == USER_SUSPENDED check let a
  // REVOKED user register keys (REVOKED != SUSPENDED). Only ACTIVE users may
  // manage keys.
  if (user->status != USER_ACTIVE) return CRABS_ERR_USER_SUSPENDED;

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
  char* token = platform_strtok_r(buf, ";", &saveptr);

  while (token != NULL) {
    while (*token == ' ') token++;
    char* eq = strchr(token, '=');
    if (eq == NULL) { token = platform_strtok_r(NULL, ";", &saveptr); continue; }

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

    token = platform_strtok_r(NULL, ";", &saveptr);
  }

  // Find the public key data after the config string's null terminator.
  // Audit R5-5: use memchr (matching rotate_key's pattern) rather than
  // strnlen. strnlen returns payload_size when no NUL is present, which
  // happens to be caught by the bounds check below, but memchr makes the
  // "no NUL found" case explicit by returning NULL — easier to audit and
  // consistent with the rotate_key handler.
  char* config_end = (char*)memchr(op->payload, '\0', op->payload_size);
  if (config_end == NULL) return CRABS_ERR_INVALID_PARAM;
  size_t config_len = (size_t)(config_end - (char*)op->payload) + 1;
  if (config_len + pk_len > op->payload_size) {
    return CRABS_ERR_INVALID_PARAM;
  }
  pk_data = op->payload + config_len;

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
  // Audit R4-2: whitelist USER_ACTIVE (rejects SUSPENDED and REVOKED).
  if (user->status != USER_ACTIVE) return CRABS_ERR_USER_SUSPENDED;

  // Payload format: key_id=<id>
  if (op->payload == NULL || op->payload_size == 0) return CRABS_ERR_INVALID_PARAM;

  char key_id[CRABS_MAX_KEY_ID] = {0};
  char buf[256];
  uint32_t copy_len = op->payload_size < sizeof(buf) - 1 ? op->payload_size : sizeof(buf) - 1;
  memcpy(buf, op->payload, copy_len);
  buf[copy_len] = '\0';

  char* saveptr = NULL;
  char* token = platform_strtok_r(buf, ";", &saveptr);
  while (token != NULL) {
    while (*token == ' ') token++;
    char* eq = strchr(token, '=');
    if (eq == NULL) { token = platform_strtok_r(NULL, ";", &saveptr); continue; }

    *eq = '\0';
    if (strcmp(token, "key_id") == 0) {
      strncpy(key_id, eq + 1, CRABS_MAX_KEY_ID - 1);
    }
    token = platform_strtok_r(NULL, ";", &saveptr);
  }

  if (key_id[0] == '\0') return CRABS_ERR_INVALID_PARAM;

  return user_key_revoke(user, key_id);
}

crabs_error_e state_machine_op_set_default_key(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (state->attr_machine == NULL) return CRABS_ERR_UNAUTHORIZED;

  user_t* user = attribute_machine_find_user(state->attr_machine, op->signer_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;
  // Audit R4-2: whitelist USER_ACTIVE (rejects SUSPENDED and REVOKED).
  if (user->status != USER_ACTIVE) return CRABS_ERR_USER_SUSPENDED;

  // Payload format: key_id=<id>
  if (op->payload == NULL || op->payload_size == 0) return CRABS_ERR_INVALID_PARAM;

  char key_id[CRABS_MAX_KEY_ID] = {0};
  char buf[256];
  uint32_t copy_len = op->payload_size < sizeof(buf) - 1 ? op->payload_size : sizeof(buf) - 1;
  memcpy(buf, op->payload, copy_len);
  buf[copy_len] = '\0';

  char* saveptr = NULL;
  char* token = platform_strtok_r(buf, ";", &saveptr);
  while (token != NULL) {
    while (*token == ' ') token++;
    char* eq = strchr(token, '=');
    if (eq == NULL) { token = platform_strtok_r(NULL, ";", &saveptr); continue; }

    *eq = '\0';
    if (strcmp(token, "key_id") == 0) {
      strncpy(key_id, eq + 1, CRABS_MAX_KEY_ID - 1);
    }
    token = platform_strtok_r(NULL, ";", &saveptr);
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
  // Audit R4-2: whitelist USER_ACTIVE (rejects SUSPENDED and REVOKED).
  if (user->status != USER_ACTIVE) return CRABS_ERR_USER_SUSPENDED;

  if (op->payload == NULL || op->payload_size == 0) return CRABS_ERR_INVALID_PARAM;

  char key_id[CRABS_MAX_KEY_ID] = {0};
  char buf[256];
  uint32_t copy_len = op->payload_size < sizeof(buf) - 1 ? op->payload_size : sizeof(buf) - 1;
  memcpy(buf, op->payload, copy_len);
  buf[copy_len] = '\0';

  char* saveptr = NULL;
  char* token = platform_strtok_r(buf, ";", &saveptr);
  while (token != NULL) {
    while (*token == ' ') token++;
    char* eq = strchr(token, '=');
    if (eq == NULL) { token = platform_strtok_r(NULL, ";", &saveptr); continue; }
    *eq = '\0';
    if (strcmp(token, "key_id") == 0) {
      strncpy(key_id, eq + 1, CRABS_MAX_KEY_ID - 1);
    }
    token = platform_strtok_r(NULL, ";", &saveptr);
  }

  if (key_id[0] == '\0') return CRABS_ERR_INVALID_PARAM;

  return user_key_suspend(user, key_id);
}

crabs_error_e state_machine_op_activate_key(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (state->attr_machine == NULL) return CRABS_ERR_UNAUTHORIZED;

  user_t* user = attribute_machine_find_user(state->attr_machine, op->signer_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;
  // Audit R4-2: whitelist USER_ACTIVE (rejects SUSPENDED and REVOKED).
  if (user->status != USER_ACTIVE) return CRABS_ERR_USER_SUSPENDED;

  if (op->payload == NULL || op->payload_size == 0) return CRABS_ERR_INVALID_PARAM;

  char key_id[CRABS_MAX_KEY_ID] = {0};
  char buf[256];
  uint32_t copy_len = op->payload_size < sizeof(buf) - 1 ? op->payload_size : sizeof(buf) - 1;
  memcpy(buf, op->payload, copy_len);
  buf[copy_len] = '\0';

  char* saveptr = NULL;
  char* token = platform_strtok_r(buf, ";", &saveptr);
  while (token != NULL) {
    while (*token == ' ') token++;
    char* eq = strchr(token, '=');
    if (eq == NULL) { token = platform_strtok_r(NULL, ";", &saveptr); continue; }
    *eq = '\0';
    if (strcmp(token, "key_id") == 0) {
      strncpy(key_id, eq + 1, CRABS_MAX_KEY_ID - 1);
    }
    token = platform_strtok_r(NULL, ";", &saveptr);
  }

  if (key_id[0] == '\0') return CRABS_ERR_INVALID_PARAM;

  return user_key_activate(user, key_id);
}

crabs_error_e state_machine_op_rotate_key(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (state->attr_machine == NULL) return CRABS_ERR_UNAUTHORIZED;

  user_t* user = attribute_machine_find_user(state->attr_machine, op->signer_id);
  if (user == NULL) return CRABS_ERR_USER_NOT_FOUND;
  // Audit R4-2: whitelist USER_ACTIVE (rejects SUSPENDED and REVOKED).
  if (user->status != USER_ACTIVE) return CRABS_ERR_USER_SUSPENDED;

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
  char* token = platform_strtok_r(buf, ";", &saveptr);
  while (token != NULL) {
    while (*token == ' ') token++;
    char* eq = strchr(token, '=');
    if (eq == NULL) { token = platform_strtok_r(NULL, ";", &saveptr); continue; }
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
    token = platform_strtok_r(NULL, ";", &saveptr);
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
  // Audit H-C: whitelist the status — only ACTIVE users may refresh. SUSPENDED
  // and REVOKED are both rejected (previously only SUSPENDED was checked, so a
  // revoked user could still obtain a fresh ABE key envelope).
  if (user->status != USER_ACTIVE) {
    return (user->status == USER_SUSPENDED) ? CRABS_ERR_USER_SUSPENDED
                                              : CRABS_ERR_USER_NOT_FOUND;
  }

  // Compute attributes hash for current attribute set
  uint8_t attr_hash[CRABS_HASH_SIZE];
  crabs_error_e rc = crypto_compute_attributes_hash(user, attr_hash);
  if (rc != CRABS_SUCCESS) return rc;

  // Use the persistent ABE master key bound to this state (M-6: previously
  // a throwaway master key was generated per refresh, producing envelopes
  // whose ABE key was unrelated to the node's domain).
  if (state->abe_mk == NULL) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;

  // Create key envelope
  uint64_t now_ms;
  if (!state_get_time_ms(state, &now_ms)) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  key_envelope_t* envelope = crypto_key_envelope_create(
      (abe_master_key_t*)state->abe_mk, state->node_private_key, user,
      state->version, now_ms, 0);

  if (envelope == NULL) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;

  // Update user key_version to match state version (§8.5)
  user->key_version = state->version;

  // Store envelope in state for caller retrieval
  if (state->last_refresh_envelope != NULL) {
    crypto_key_envelope_destroy((key_envelope_t*)state->last_refresh_envelope);
  }
  state->last_refresh_envelope = envelope;

  // Serialize the envelope into the response buffer (flat transport form).
  if (response != NULL) {
    size_t n = crypto_key_envelope_serialize(envelope,
        response->envelope_data, sizeof(response->envelope_data));
    // Audit M-I: fail the op if the envelope does not fit (previously the
    // op returned SUCCESS with envelope_data_len = 0, delivering an
    // unusable empty envelope).
    if (n == 0) {
      crypto_key_envelope_destroy(envelope);
      state->last_refresh_envelope = NULL;
      response->envelope_data_len = 0;
      return CRABS_ERR_SERIALIZATION_ERROR;
    }
    response->envelope_data_len = (uint32_t)n;
  }

  return CRABS_SUCCESS;
}

// ============================================================
// Compaction Built-in Operation (v1.5.2 §4.3)
// ============================================================

crabs_error_e state_machine_op_compact(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;

  // Audit N-20: use the state's persistent compaction engine if one is wired
  // so the local_vc accumulated from the OT execute path (via
  // crabs_compaction_engine_record_op) is preserved across __compact__
  // invocations. The prior code created a fresh engine on the stack each
  // time, so local_vc started empty and the STRONG/QUORUM safety check could
  // never be armed. If no persistent engine is set, fall back to a fresh
  // one (single-replica CRABS_SAFETY_FORCE mode).
  if (state->compaction_engine != NULL) {
    return crabs_op_compact_now((crabs_compaction_engine_t*)state->compaction_engine,
                                state);
  }

  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, NULL);
  crabs_register_crdt_vtables(&engine.registry);

  crabs_error_e err = crabs_op_compact_now(&engine, state);
  crabs_compaction_engine_destroy(&engine);

  return err;
}

// Auto-compaction check for items that need compaction (v1.5.2 §4)
// Called internally after OT operations if compaction_config is set on state.
uint32_t state_machine_auto_compact(state_t* state) {
  if (state == NULL || state->compaction_config == NULL) return 0;

  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t* config =
    (crabs_tombstone_config_t*)state->compaction_config;
  crabs_compaction_engine_init(&engine, config);
  crabs_register_crdt_vtables(&engine.registry);

  uint64_t now_ms;
  if (!state_get_time_ms(state, &now_ms)) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }
  uint32_t compacted = 0;
  data_item_t* item = state->items;
  while (item != NULL) {
    if (crabs_needs_compaction(config, &engine.registry, item)) {
      crabs_compaction_result_e r = crabs_compact_item(&engine, state, item, now_ms);
      if (r == CRABS_COMPACTION_OK) compacted++;
    }
    item = item->next;
  }

  crabs_compaction_engine_destroy(&engine);
  return compacted;
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
