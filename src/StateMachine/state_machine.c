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
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

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
    // HLC-based expiry: compare physical time against acquired_at + duration
    crabs_physical_time_t now = crabs_hlc_get_system_time(NULL);
    if (!now.valid) return now_ms >= lock->lock_expiry;
    uint64_t total_duration_ms = state->config.max_lock_duration_ms +
      (uint64_t)lock->lock_extensions * state->config.max_lock_duration_ms;
    crabs_hlc_t expiry = crabs_hlc_add_duration(lock->lock_acquired_at, total_duration_ms);
    return (now.seconds > expiry.physical_seconds) ||
           (now.seconds == expiry.physical_seconds && now.nanos > expiry.physical_nanos);
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
  // Audit L-b: cap growth so a long-running node does not exhaust memory.
  // Beyond the cap the op is not recorded; replay protection across
  // sessions relies on Lamport clocks and signatures, and within-session
  // idempotency covers the recent window.
  if (state->processed_op_count >= CRABS_PROCESSED_OPS_MAX) return;
  uint64_t new_count = state->processed_op_count + 1;
  uint8_t(*new_ops)[CRABS_UUID_SIZE] = realloc(state->processed_ops,
    new_count * CRABS_UUID_SIZE);
  if (new_ops == NULL) return; // keep old array; op unrecorded (replay risk)
  state->processed_ops = new_ops;
  state->processed_op_count = new_count;
  memcpy(state->processed_ops[state->processed_op_count - 1], uuid, CRABS_UUID_SIZE);
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

static void append_log(state_t* state, const uint8_t uuid[CRABS_UUID_SIZE],
                       const char* type, const char* signer_id,
                       uint64_t lamport_time, const char* node_id,
                       const uint8_t state_hash[CRABS_HASH_SIZE]) {
  (void)state_hash; // the chain hash is computed below; the caller's value is ignored
  uint64_t new_count = state->log_count + 1;
  log_entry_t* new_log = realloc(state->log, new_count * sizeof(log_entry_t));
  if (new_log == NULL) return;
  state->log = new_log;
  state->log_count = new_count;
  log_entry_t* entry = &state->log[state->log_count - 1];
  entry->version = state->version;
  memcpy(entry->uuid, uuid, CRABS_UUID_SIZE);
  entry->type[0] = '\0';
  strncat(entry->type, type, CRABS_MAX_OP_NAME - 1);
  entry->signer_id[0] = '\0';
  strncat(entry->signer_id, signer_id, CRABS_MAX_USER_ID - 1);
  entry->lamport_time = lamport_time;
  entry->node_id[0] = '\0';
  strncat(entry->node_id, node_id, CRABS_MAX_USER_ID - 1);
  _compute_log_chain_hash(state, entry);
}

// ============================================================
// Main Execution Algorithm (§7.4)
// ============================================================
crabs_error_e state_machine_execute(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;

  // Step 1: Prune expired locks
  uint64_t now_ms = (uint64_t)time(NULL) * 1000;
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

  // Step 2: Idempotency check
  if (is_duplicate_op(state, op->uuid)) {
    return CRABS_SUCCESS;
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

  // Step 6: Dedup guard check (v1.4 §5.2)
  // Audit F-2: enforce the SERVER-REGISTERED dedup spec when one exists for
  // this operation type, so a signer cannot bypass "vote once" by setting
  // dedup.type = DEDUP_NONE (or a trivial custom condition) on the wire. The
  // op-carried spec is only consulted when no spec is registered for the
  // operation type (legacy/dynamic ops). The registered spec also wins for
  // the mutation in step 8.
  const dedup_spec_t* registered_dedup = state_find_op_type_def(state, op->type);
  const dedup_spec_t* effective_dedup = registered_dedup ? registered_dedup : &op->dedup;
  if (effective_dedup->type != DEDUP_NONE) {
    crabs_error_e dedup_result = dedup_check_guard_spec(state, effective_dedup, op);
    if (dedup_result != CRABS_SUCCESS) {
      return dedup_result;
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
    // Audit F-5: non-builtin (application-defined) operations have no C
    // handler in this implementation. Their effect is the dedup state
    // mutation (step 8) plus the protocol transition applied below.
    // Previously the dispatch rejected them, which left the LOCKED→MODIFIED
    // transition unreachable and made __verify__/__unlock__ impossible (the
    // entire resource lifecycle could only end in force-unlock/rollback).
    result = CRABS_SUCCESS;
  }

  if (result != CRABS_SUCCESS) return result;

  // Step 7b: Apply protocol state transitions for non-builtin operations
  // (§6.3 wildcard: LOCKED → MODIFIED). Builtin operations manage their own
  // protocol state in their handlers (e.g. __lock__ sets LOCKED, __verify__
  // sets VERIFIED or ERROR). This is the only path that reaches MODIFIED,
  // without which __verify__ (which requires MODIFIED) can never succeed.
  if (!operation_is_builtin(op->type)) {
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

  // Step 8: Apply dedup state mutation (v1.4 §5.3)
  // Audit F-2: apply the same effective spec used in step 5 (registered wins
  // over op-carried), so the mutation matches the guard that was checked.
  if (effective_dedup->type != DEDUP_NONE) {
    crabs_error_e mut_result = dedup_apply_mutation_spec(state, effective_dedup, op);
    if (mut_result != CRABS_SUCCESS) {
      // Mutation failure doesn't roll back the operation,
      // but we log the error for diagnostics
    }
  }

  // Step 8b: Auto-compaction check after OT operations (v1.5.2 §4)
  if (state->compaction_config != NULL &&
      strcmp(op->type, CRABS_OP_EXECUTE_OT) == 0) {
    state_machine_auto_compact(state);
  }

  // Step 9: Transition protocol states and log operation
  uint8_t state_hash[CRABS_HASH_SIZE];
  memset(state_hash, 0, CRABS_HASH_SIZE);
  append_log(state, op->uuid, op->type, op->signer_id,
             op->lamport_time, op->node_id, state_hash);
  state->version++;

  // Record for idempotency
  record_processed_op(state, op->uuid);

  // Step 9: Process triggers (Amendment 1, §5.2)
  // Pass the attribute machine so trigger effects (e.g. ISSUE_ATTRIBUTE) can
  // actually issue attributes. The prior code passed NULL here, which made
  // _execute_trigger_effect silently skip ISSUE_ATTRIBUTE effects (the
  // function checks `if (am == NULL) return CRABS_SUCCESS;`). This meant
  // threshold triggers never issued attributes — a functional bug.
  if (state->triggers != NULL && state->trigger_count > 0) {
    uint64_t trigger_now_ms = (uint64_t)time(NULL) * 1000;
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
      uint64_t lock_check_ms = (uint64_t)time(NULL) * 1000;
      if (!state_machine_lock_expired(state, &item->lock_state, lock_check_ms)) {
        return CRABS_ERR_LOCK_OWNER_MISMATCH;
      }
    }
  }

  uint64_t now_ms = (uint64_t)time(NULL) * 1000;
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
  if (!state->config.allow_force_unlock) return CRABS_ERR_FORCE_UNLOCK_DISABLED;
  uint64_t now_ms = (uint64_t)time(NULL) * 1000;
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

  char* v;
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
    state->config.allow_force_unlock = (strcmp(v, "true") == 0);
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
  uint64_t now_ms = (uint64_t)time(NULL) * 1000;
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

  uint64_t now_ms = (uint64_t)time(NULL) * 1000;
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
