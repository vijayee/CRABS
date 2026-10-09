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
#include "../Lineage/lineage.h"
#include "../Serialization/serialization.h"
#include "../CRDT/crdt_merge.h"
#include "../Dedup/dedup.h"
#include "../OT/ot_execution.h"
#include "../Compaction/compaction_engine.h"
#include "../Compaction/crdt_compaction.h"
#include "../Util/allocator.h"
#include "../TxManager/tx_manager.h"
#include "../Scheduler/scheduler.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

// ============================================================
// State Change Notification
// ============================================================

void state_set_change_hook(state_t* state, crabs_change_hook_fn hook,
                           void* user_data) {
  if (state == NULL) return;
  state->change_hook = hook;
  state->change_hook_user_data = user_data;
}

void state_notify_change(state_t* state, crabs_change_kind_e kind,
                         const char* type, const uint8_t* uuid,
                         const char* signer_id, const char* node_id,
                         const char* target, const char* preview,
                         crabs_error_e result) {
  if (state == NULL || state->change_hook == NULL) return;
  crabs_change_event_t event;
  memset(&event, 0, sizeof(event));
  event.kind = kind;
  event.type = type;
  event.uuid = uuid;
  event.signer_id = signer_id;
  event.node_id = node_id;
  event.target = target;
  event.preview = preview;
  event.result = result;
  // Contract: the hook never mutates state and never fails the op. The
  // borrowed strings are valid only for the duration of the call.
  state->change_hook(state, &event, state->change_hook_user_data);
}

void state_notify_change_for_op(state_t* state, crabs_change_kind_e kind,
                                const operation_t* op,
                                const char* preview_override,
                                crabs_error_e result) {
  if (state == NULL || state->change_hook == NULL || op == NULL) return;
  const char* target = NULL;
  if (op->resource_count > 0 && op->resources != NULL) {
    target = op->resources[0];
  }
  crabs_change_event_t event;
  memset(&event, 0, sizeof(event));
  event.kind = kind;
  event.type = op->type;
  event.uuid = op->uuid;
  event.signer_id = op->signer_id;
  event.node_id = op->node_id;
  event.target = target;
  event.preview = preview_override;
  event.result = result;
  event.lamport_time = op->lamport_time;
  if (op->ordering_system == CRABS_ORDERING_HLC) {
    event.has_hlc = true;
    event.hlc = op->hlc;
  }
  // Contract: the hook never mutates state and never fails the op. The
  // borrowed strings are valid only for the duration of the call.
  state->change_hook(state, &event, state->change_hook_user_data);
}

// Human-readable "<type> <first resource>" for change events. Empty target
// renders as just the type.
static void _op_preview(const operation_t* op, char* out, size_t out_size) {
  if (op == NULL) { out[0] = '\0'; return; }
  const char* target = (op->resource_count > 0 && op->resources != NULL)
                           ? op->resources[0] : "";
  snprintf(out, out_size, "%s%s%s", op->type, target[0] != '\0' ? " " : "",
           target);
}

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
crabs_error_e state_machine_op_schedule(state_t* s, operation_t* o);
crabs_error_e state_machine_op_cancel_schedule(state_t* s, operation_t* o);
crabs_error_e state_machine_op_report_equivocation(state_t* s, operation_t* o);

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
          strcmp(type, CRABS_OP_COMPACT) == 0 ||
          strcmp(type, CRABS_OP_SCHEDULE) == 0 ||
          strcmp(type, CRABS_OP_CANCEL_SCHEDULE) == 0 ||
          strcmp(type, CRABS_OP_REPORT_EQUIVOCATION) == 0);
}

// v1.7: lineage operations are handler-registered custom types, but the
// lineage lifecycle must not be rewritable by triggers or re-definable by
// __define_operation_type__ (audit A10-M1). Protected = builtin ∪ lineage.
// Callers that depend on strict builtin/custom semantics (the step-7b
// protocol-transition skip, the CLI) keep using operation_is_builtin.
bool operation_is_protected(const char* type) {
  if (operation_is_builtin(type)) return true;
  return (strcmp(type, CRABS_LINEAGE_OP_SPAWN) == 0 ||
          strcmp(type, CRABS_LINEAGE_OP_REVOKE_ATTESTATION) == 0 ||
          strcmp(type, CRABS_LINEAGE_OP_DISSOLVE) == 0 ||
          strcmp(type, CRABS_LINEAGE_OP_WITHDRAW_GENESIS) == 0 ||
          strcmp(type, CRABS_LINEAGE_OP_RECEIVE_DISSOLUTION) == 0 ||
          strcmp(type, CRABS_LINEAGE_OP_PARENT_KEY_UPDATE) == 0);
}

operation_t* operation_create(const char* type) {
  operation_t* op = get_clear_memory(sizeof(operation_t));
  strncpy(op->type, type, CRABS_MAX_OP_NAME - 1);
  // A10-L7: new in-memory ops are authored at the current wire version; the
  // deserializer overwrites this with the parsed version.
  op->op_version = CRABS_OP_FORMAT_VERSION;
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
  if (op->attestations != NULL) free(op->attestations);
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
// The comparison itself, given the item's logical numeric value.
static bool _invariant_eval(const invariant_t* inv, int64_t val) {
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

bool invariant_check(invariant_t* inv, void* value, data_type_e type) {
  if (inv == NULL || value == NULL) return false;

  int64_t val = 0;
  if (type == DATA_TYPE_COUNTER || type == DATA_TYPE_PN_COUNTER) {
    val = *(int64_t*)value;
  } else {
    return true;
  }

  return _invariant_eval(inv, val);
}

bool invariant_check_item(invariant_t* inv, const data_item_t* item) {
  if (inv == NULL || item == NULL || item->value == NULL) return false;

  int64_t val = 0;
  if (data_item_logical_value(item, &val) != CRABS_SUCCESS) {
    // No numeric logical value (sets/documents/OT): invariants don't apply —
    // the historical behavior for non-counter types.
    return true;
  }
  return _invariant_eval(inv, val);
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
          item->lock_state.pre_lock_snapshot_len = 0;
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
  // Audit follow-up: fold in the ordering fields so two replicas applying
  // the same ops in DIFFERENT orders produce different chain hashes —
  // without these, the hash could not distinguish divergent orderings.
  // Lamport entries carry a zeroed HLC (append_log guarantees it), so the
  // digest is deterministic for them too. hlc.node_id is NUL-terminated by
  // every creation path (crabs_hlc emit and the v1.6 serializer's
  // _read_string16), and crabs_hlc_compare already relies on that.
  EVP_DigestUpdate(ctx, &entry->ordering_system, sizeof(entry->ordering_system));
  EVP_DigestUpdate(ctx, &entry->hlc.physical_seconds, sizeof(entry->hlc.physical_seconds));
  EVP_DigestUpdate(ctx, &entry->hlc.physical_nanos, sizeof(entry->hlc.physical_nanos));
  EVP_DigestUpdate(ctx, &entry->hlc.logical_counter, sizeof(entry->hlc.logical_counter));
  EVP_DigestUpdate(ctx, entry->hlc.node_id, strlen(entry->hlc.node_id));
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

// R7-01: get the current physical time in ms from the state's HLC time
// source. The default SYSTEM_CLOCK source backs reads with the
// UNAUTHENTICATED platform clock (R8-H-1, crabs_hlc_get_physical_time);
// every other source requires attached ops and fails closed — returns
// false — when it reports no valid time. Public since v1.7 — lineage spawn
// stamps the manifest's spawned_at from the parent's time source (0 when
// unavailable; spawn consumers needing authentication must configure an
// authenticated source).
bool state_get_time_ms(const state_t* state, uint64_t* now_ms) {
  if (state == NULL || now_ms == NULL) return false;
  crabs_physical_time_t phys = crabs_hlc_get_physical_time(&((state_t*)state)->hlc_state);
  if (!phys.valid) return false;
  *now_ms = phys.seconds * 1000 + phys.nanos / 1000000;
  return true;
}

// R7-11 replay backstop: true when the signer's log already contains an op
// that is NOT strictly older than `op`. Uses the MAXIMUM ordering timestamp
// across the signer's entries (not the tail-most) so late-logged materialized
// schedules and lamport-0 __schedule_failed__ records cannot regress the
// watermark. __schedule_failed__ entries are system records and are skipped
// entirely. Used to enforce ordering monotonicity so a replayed op — which
// carries the same ordering timestamp as the original — is rejected even
// after a restart, when the in-memory tx_manager has been reset.
//
// The scan covers the whole log with no tail-most-first early exit — that
// early exit was removed deliberately (correctness over speed): the tail-most
// entry can be older than an earlier one once materialized schedules and
// failure records interleave. O(n) per op; a per-signer watermark cache is
// the future optimization.
static bool state_signer_has_replay(const state_t* state, const operation_t* op) {
  if (state == NULL || op == NULL) return false;
  for (uint64_t entry_index = state->log_count; entry_index > 0; entry_index--) {
    const log_entry_t* entry = &state->log[entry_index - 1];
    if (strcmp(entry->signer_id, op->signer_id) != 0) continue;
    if (strcmp(entry->type, "__schedule_failed__") == 0) continue;

    if (op->ordering_system == CRABS_ORDERING_HLC) {
      if (entry->ordering_system == CRABS_ORDERING_HLC &&
          crabs_hlc_compare(&op->hlc, &entry->hlc) <= 0) {
        return true;
      }
      // Lamport-ordered entry vs HLC op: lamport sorts before HLC, so this
      // entry can never make the op a replay.
    } else {
      if (entry->ordering_system == CRABS_ORDERING_LAMPORT &&
          op->lamport_time <= entry->lamport_time) {
        return true;
      }
      // HLC-ordered entry vs lamport op: the op is older by the cross-system
      // rule, but the previous behavior compared lamport values only (an HLC
      // entry carries lamport 0 and never rejects) — preserve that: HLC
      // entries do not reject lamport ops.
    }
  }
  return false;
}

// Audit A-4: validate a received op's wire HLC against the local clock per
// the node's receive strategy, BEFORE any ordering comparison consumes it.
// Without this, crabs_hlc_receive (the BOUNDED/STRICT/TRUSTED skew strategies
// and the R4-8 counter bound) never ran on received ops: wire HLC flowed
// straight into ordering comparisons, the R7-11 replay backstop and the chain
// hash, letting a signer stamp physical_seconds arbitrarily far in the future
// (self-DoS of its own watermark) or push the node's logical counter toward
// saturation.
//
// Probe copy: crabs_hlc_receive mutates its state argument, so validate
// against a copy — the real clock adopts nothing from ops. Strategy, skew
// bound and strict mode come from the node's ordering config (hlc_state
// itself carries BOUNDED defaults regardless of the configured strategy).
// Rejections (BOUNDED out-of-window, QUORUM/TRUSTED fail-closed, R4-8
// counter) fail the op; ACCEPTED_STRICT counts as acceptance — STRICT orders
// by the received timestamp but never adopts it. When the node has no
// initialized local clock (lamport-only node receiving an HLC op) there is
// nothing to compare against and validation is skipped.
static crabs_error_e _validate_received_hlc(state_t* state, const operation_t* op) {
  crabs_ordering_config_t* config = state_get_ordering_config(state);
  if (op->ordering_system != CRABS_ORDERING_HLC ||
      !state->hlc_state_initialized ||
      config == NULL || config->ordering_system != CRABS_ORDERING_HLC) {
    return CRABS_SUCCESS;
  }

  crabs_hlc_state_t probe_state = state->hlc_state;
  probe_state.receive_strategy = config->hlc.receive_strategy;
  probe_state.max_skew_ms = config->hlc.max_skew_ms;
  probe_state.strict_mode = config->hlc.strict_mode;
  crabs_hlc_receive_result_e receive_rc = crabs_hlc_receive(&probe_state, &op->hlc);
  if (receive_rc == CRABS_HLC_ACCEPTED || receive_rc == CRABS_HLC_ACCEPTED_STRICT) {
    return CRABS_SUCCESS;
  }
  return CRABS_ERR_PROTOCOL_VIOLATION;
}

// v1.7 §attestation bridge: does the attestation's comma-separated
// attributes list contain the endorsement attribute EXACTLY? Direct string
// membership only — v1 evaluates no boolean logic over attested attributes
// (attribute "dept:red" attested ⇔ endorsement "@parent/dept:red" matched).
static bool _attestation_covers(const attestation_t* attestation,
                                const char* endorsement) {
  if (attestation == NULL || endorsement[0] == '\0') return false;
  size_t endorsement_len = strlen(endorsement);

  const char* list_cursor = attestation->attributes;
  while (*list_cursor != '\0') {
    const char* element_end = strchr(list_cursor, ',');
    size_t element_len = (element_end != NULL)
        ? (size_t)(element_end - list_cursor) : strlen(list_cursor);
    // Trim the element's surrounding whitespace before comparing.
    while (element_len > 0 && isspace((unsigned char)list_cursor[0])) {
      list_cursor++;
      element_len--;
    }
    while (element_len > 0 &&
           isspace((unsigned char)list_cursor[element_len - 1])) {
      element_len--;
    }
    if (element_len == endorsement_len &&
        strncmp(list_cursor, endorsement, element_len) == 0) {
      return true;
    }
    if (element_end == NULL) break;
    list_cursor = element_end + 1;
  }
  return false;
}

// v1.7 §attestation bridge: resolve the @parent/ endorsements extracted
// from the policy against the attestations the op carries. Runs only AFTER
// the op's own signature verified (the signer is resolved). Fail closed:
//   - a machine with no parent binding (never spawned) cannot satisfy ANY
//     endorsement — endorsement policies deny on an unbound machine even
//     when the op carries attestations;
//   - each endorsement needs ONE attestation that verifies against the
//     machine's accepted parent key chain (A10-M6: the spawn pin plus every
//     key admitted by __parent_key_update__), names THIS machine
//     (child_id == lineage_self_id), sits inside its validity window, names
//     the RESOLVED signer as its attested user, and whose attested
//     attributes cover the endorsement exactly;
//   - Mode B (anonymous ops, empty signer_id) never gets this far: trial
//     verification cannot bind an attestation to a resolved user, so an
//     endorsement-bearing policy is rejected before signature work.
// Every missing/invalid/unverified condition collapses to
// CRABS_ERR_UNAUTHORIZED — no fail-open path.
static crabs_error_e _verify_parent_endorsements(
    state_t* state, const operation_t* op,
    const policy_preprocess_result_t* pp, const char* resolved_signer) {
  if (!state->lineage_parent_bound) {
    return CRABS_ERR_UNAUTHORIZED;
  }

  // Dissolution severs the parent's endorsement authority INSTANTLY — every
  // @parent/ endorsement fails closed even with a valid, unexpired
  // attestation (lineage_op_dissolve sets this flag on the resident child).
  if (state->lineage_parent_dissolved) {
    return CRABS_ERR_UNAUTHORIZED;
  }

  uint64_t now_ms;
  if (!state_get_time_ms(state, &now_ms)) {
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  for (uint32_t endorsement_index = 0;
       endorsement_index < pp->parent_endorsement_count; endorsement_index++) {
    const char* endorsement =
        pp->parent_endorsements[endorsement_index];
    bool satisfied = false;
    for (uint32_t attestation_index = 0;
         attestation_index < op->attestation_count; attestation_index++) {
      const attestation_t* attestation =
          &op->attestations[attestation_index];
      if (!attestation_verify_by_lineage_key(state, attestation, now_ms)) {
        continue;
      }
      // Identity anchor: the attestation must name THIS machine's bound
      // parent. The signature check verifies the attestation against the
      // chain TIP key (tip-only, A11-4) but cannot see WHO the attestation
      // names — a different parent's attestation (validly signed by its own
      // key that happens to be bound here) must not satisfy an endorsement.
      if (strcmp(attestation->parent_id, state->lineage_parent_id) != 0) {
        continue;
      }
      if (strcmp(attestation->user_id, resolved_signer) != 0) {
        continue;
      }
      if (!_attestation_covers(attestation, endorsement)) {
        continue;
      }
      satisfied = true;
      break;
    }
    if (!satisfied) {
      return CRABS_ERR_UNAUTHORIZED;
    }
  }
  return CRABS_SUCCESS;
}

// Step 3 helper: Authorization (§10.3) — fail closed. Every operation
// requires a registered policy and a valid signature.
// Audit L-a: authorize BEFORE the protocol/lock/dedup checks (steps 4-6)
// so an unauthenticated caller cannot learn resource existence, lock
// state, or dedup-tracker membership from distinct error codes. An
// unauthenticated caller gets a single CRABS_ERR_UNAUTHORIZED; an
// authenticated caller still receives the specific protocol error below.
// On success, *pp_out receives the preprocessed policy result (needed by
// the co-signature check in step 6c) and *resolved_signer_out receives the
// signer whose key actually verified. For Mode A that is op->signer_id; for
// Mode B (anonymous ops) it is the user the trial verification matched —
// the key-version gates in steps 6/6b must run against this resolved
// signer, because op->signer_id is empty there.
static crabs_error_e _verify_operation_authorization(state_t* state, const operation_t* op,
                                                     policy_preprocess_result_t* pp_out,
                                                     char* resolved_signer_out) {
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

  // v1.7 §attestation bridge: endorsement-bearing policies REQUIRE an
  // explicit signer. Mode B resolves the user only by trial-verification
  // against every registered user, while an attestation names a fixed
  // user_id — the two can never be soundly matched, so an anonymous op on
  // an endorsement policy is rejected here, before any signature work.
  if (pp.parent_endorsement_count > 0 && op->signer_id[0] == '\0') {
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

  strncpy(resolved_signer_out, vr.signer_id, CRABS_MAX_USER_ID - 1);
  resolved_signer_out[CRABS_MAX_USER_ID - 1] = '\0';

  // v1.7 §attestation bridge: every @parent/ endorsement extracted from the
  // policy must be covered by a verified op attestation.
  if (pp.parent_endorsement_count > 0) {
    crabs_error_e endorsement_rc = _verify_parent_endorsements(
        state, op, &pp, resolved_signer_out);
    if (endorsement_rc != CRABS_SUCCESS) {
      return endorsement_rc;
    }
  }

  *pp_out = pp;
  return CRABS_SUCCESS;
}

// Step 4 helper: Verify protocol state transitions (§7.4 step 4).
static crabs_error_e _check_transitions(state_t* state, const operation_t* op) {
  for (uint32_t resource_index = 0; resource_index < op->resource_count;
       resource_index++) {
    data_item_t* item = state_find_item(state, op->resources[resource_index]);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    if (item->protocol_state != op->required_state[resource_index]) {
      return CRABS_ERR_PROTOCOL_VIOLATION;
    }
  }
  return CRABS_SUCCESS;
}

// Step 6 helper: Key version verification (§10.4).
// `signer_id` is the signer RESOLVED by step 3's verification (op->signer_id
// for Mode A, the keyring-matched user for anonymous Mode B ops — audit:
// resolving via op->signer_id silently skipped both gates for Mode B).
static crabs_error_e _check_key_version(state_t* state, const operation_t* op,
                                        const char* signer_id) {
  // R7-04: the check is mandatory when the signer has a nonzero key_version.
  // The prior `op->signer_key_version > 0` guard let a crafted op with
  // signer_key_version = 0 skip the staleness check entirely, so a replayed op
  // signed with a rotated-out key was accepted.
  if (state->attr_machine != NULL) {
    user_t* signer = attribute_machine_find_user(state->attr_machine, signer_id);
    if (signer != NULL && signer->key_version > 0 &&
        signer->key_version != op->signer_key_version) {
      return CRABS_ERR_KEY_STALE;
    }
  }
  return CRABS_SUCCESS;
}

// Step 6b helper: Scheme constraint enforcement (v1.3 §7).
// `signer_id` is the signer RESOLVED by step 3's verification (see
// _check_key_version) so the min_key_version floor also applies to
// anonymous Mode B operations.
static crabs_error_e _check_scheme_constraints(state_t* state, const operation_t* op,
                                               const char* signer_id) {
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
      user_t* signer = attribute_machine_find_user(state->attr_machine, signer_id);
      if (signer != NULL && signer->key_version < policy->min_key_version) {
        return CRABS_ERR_KEY_STALE;
      }
    }
  }
  return CRABS_SUCCESS;
}

// Step 6c helper: Co-signature verification and threshold enforcement
// (v1.3 §4.2). Every co-signature is cryptographically verified against the
// canonical signed form; co-signers must be distinct from each other and from
// the primary signer. When a threshold is configured, it is enforced
// unconditionally (no fail-open bypass). `pp` is the preprocessed policy from
// step 3 — co-signatures verify against the same ABE policy as the primary
// signer. `resolved_signer` is the signer RESOLVED by step 3 (op->signer_id
// for Mode A, the keyring-matched user for anonymous Mode B ops) — audit
// A10-M2: without it, a Mode B proposer could also occupy a co-signer slot,
// defeating the threshold.
static crabs_error_e _verify_co_signatures(state_t* state, const operation_t* op,
                                           const policy_preprocess_result_t* pp,
                                           const char* resolved_signer) {
  if (op->co_signer_count > 0) {
    serialized_buffer_t* co_ser = crabs_serialize_for_signing(op);
    if (co_ser == NULL) return CRABS_ERR_SERIALIZATION_ERROR;

    for (uint32_t i = 0; i < op->co_signer_count; i++) {
      const co_signature_t* cs = &op->co_signers[i];
      if (cs->signer_id[0] == '\0') {
        serialized_buffer_destroy(co_ser);
        return CRABS_ERR_INVALID_PARAM;
      }
      // Distinctness: no co-signer may duplicate another or the primary
      // signer. The primary signer is checked under both names: op->signer_id
      // (Mode A) and the resolved keyring match (Mode B, where op->signer_id
      // is empty).
      if (strcmp(cs->signer_id, op->signer_id) == 0 ||
          (resolved_signer != NULL && resolved_signer[0] != '\0' &&
           strcmp(cs->signer_id, resolved_signer) == 0)) {
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
          pp->abe_policy,
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

  return CRABS_SUCCESS;
}

// Step 6d: DOMAIN_CHECK (write-domains v1, spec 2026-10-08 §Execution
// pipeline change). Runs post-dedup/post-key-scheme-co-sig/pre-handler —
// after authorization has made op->signer_id authoritative, before any
// mutation. Only EXISTING items are examined: a missing resource is reported
// by the step-7b/handler convention (CRABS_ERR_RESOURCE_NOT_FOUND), not by
// this check.
//
// Prefix alignment: op->sovereign_prefixes walks the op's SOVEREIGN
// resources in resource order (non-sovereign resources consume no slot), so
// the count must match EXACTLY the number of sovereign resources present —
// a prefix silently assigned to the wrong item would compare against the
// wrong chain head. Fail closed (CRABS_ERR_SEQ_MISMATCH) on any mismatch.
//
// Dedup mutation targets: the registered spec's MUTATION section mutates its
// path-named item post-handler, so non-FREE_MERGE targets must be named
// resources of the op (riding its signed chain claims) — enforced below.

// The mutation target path of a dedup spec, or NULL when the spec carries
// no resolvable mutation target (DEDUP_NONE, or DEDUP_CUSTOM with a
// MUTATION_CUSTOM update, which has no path fields).
static const char* _dedup_mutation_target_path(const dedup_spec_t* spec) {
  switch (spec->type) {
    case DEDUP_PER_USER: return spec->tracker_path;
    case DEDUP_GLOBAL:   return spec->flag_path;
    case DEDUP_CUSTOM:
      switch (spec->update.type) {
        case MUTATION_SET_ADD:           return spec->update.set_path;
        case MUTATION_FLAG_SET:          return spec->update.flag_path;
        case MUTATION_COUNTER_INCREMENT: return spec->update.counter_path;
        case MUTATION_ASSIGN:            return spec->update.target_path;
        default:                         return NULL;
      }
    default: return NULL;
  }
}

// Dedup mutation targets obey the same domain rules as named resources.
// The registered spec's MUTATION section runs post-handler (R7-13) on
// whatever item its path names — including a SOVEREIGN/GROUP_ORDERED item
// absent from op->resources, which the post-op bookkeeping
// (_apply_sovereign_bookkeeping) would then fail to chain-advance: the
// item's content moves while its stored digest goes stale. v1 rule: every
// existing, non-FREE_MERGE mutation target must be a NAMED resource of the
// op, so the SOVEREIGN arm below (writer binding + signed chain prefix) and
// the GROUP_ORDERED arm (v1 read-only) cover mutation targets too. Fail
// closed with CRABS_ERR_SEQ_MISMATCH: the op's chain claims are incomplete
// for the items it mutates. (SOVEREIGN targets cannot be ONE_SHOT types in
// v1 — creation restricts SOVEREIGN to COUNTER/REGISTER — so only the
// COUNTER_INCREMENT/ASSIGN arms of DEDUP_CUSTOM can actually resolve to one;
// the check is uniform regardless.)
static crabs_error_e _check_mutation_target_in_resources(state_t* state,
                                                         const dedup_spec_t* spec,
                                                         const operation_t* op) {
  const char* target_path = _dedup_mutation_target_path(spec);
  if (target_path == NULL || target_path[0] == '\0') return CRABS_SUCCESS;
  // A missing target fails earlier: dedup_validate_mutation_spec runs before
  // this step and reports TRACKER_NOT_FOUND/FLAG_NOT_FOUND/NOT_FOUND.
  const data_item_t* target_item = state_find_item(state, target_path);
  if (target_item == NULL) return CRABS_SUCCESS;
  if (target_item->write_domain == CRABS_DOMAIN_FREE_MERGE) return CRABS_SUCCESS;
  for (uint32_t resource_index = 0; resource_index < op->resource_count;
       resource_index++) {
    if (strcmp(op->resources[resource_index], target_path) == 0) {
      return CRABS_SUCCESS;
    }
  }
  return CRABS_ERR_SEQ_MISMATCH;
}

static crabs_error_e _run_domain_check(state_t* state, const operation_t* op) {
  uint32_t sovereign_count = 0;
  for (uint32_t resource_index = 0; resource_index < op->resource_count;
       resource_index++) {
    const data_item_t* item = state_find_item(state, op->resources[resource_index]);
    if (item != NULL && item->write_domain == CRABS_DOMAIN_SOVEREIGN) {
      sovereign_count++;
    }
  }
  if (op->sovereign_prefix_count != sovereign_count) {
    return CRABS_ERR_SEQ_MISMATCH;
  }

  // Registered dedup specs only (never the op-carried, signer-authored one —
  // the pipeline rejects those for op types without a registered def before
  // this step): the mutation target must ride the op's chain claims.
  const dedup_spec_t* registered_spec = state_find_op_type_def(state, op->type);
  if (registered_spec != NULL) {
    crabs_error_e target_rc =
        _check_mutation_target_in_resources(state, registered_spec, op);
    if (target_rc != CRABS_SUCCESS) {
      return target_rc;
    }
  }

  uint32_t prefix_index = 0;
  for (uint32_t resource_index = 0; resource_index < op->resource_count;
       resource_index++) {
    const data_item_t* item = state_find_item(state, op->resources[resource_index]);
    if (item == NULL) continue;
    switch (item->write_domain) {
      case CRABS_DOMAIN_GROUP_ORDERED:
        // v1 seam: no ordering module can be registered (creation refuses a
        // nonzero ordering_module, so it is always 0), and writes are only
        // legal through a module's propose path — every direct write is
        // off-path.
        return CRABS_ERR_ORDERING_PATH;
      case CRABS_DOMAIN_SOVEREIGN: {
        // Cheap checks first: quarantine set membership, then writer
        // attribution, then the chain prefix. The Task 6
        // __report_equivocation__ handler populates the fork set with
        // re-verified evidence; here we only consult it.
        if (state_item_is_quarantined(item, op->signer_id)) {
          return CRABS_ERR_QUARANTINED;
        }
        // Mode B (empty signer_id) is unattributable by definition — the
        // writer binding is to a user_id, so sovereignty requires Mode A.
        if (op->signer_id[0] == '\0' ||
            strcmp(op->signer_id, item->writer) != 0) {
          return CRABS_ERR_NOT_ITEM_WRITER;
        }
        const crabs_sovereign_op_prefix_t* prefix =
            &op->sovereign_prefixes[prefix_index++];
        if (prefix->item_seq != item->item_seq) {
          return CRABS_ERR_SEQ_MISMATCH;
        }
        if (CRYPTO_memcmp(prefix->prev_item_digest, item->item_digest,
                          CRABS_HASH_SIZE) != 0) {
          // Same seq, different digest: the writer equivocated. Nothing is
          // applied (this return precedes every mutation); the Task 6 report
          // path constructs the __report_equivocation__ evidence from the
          // two conflicting log entries.
          return CRABS_ERR_FORK_DETECTED;
        }
        break;
      }
      case CRABS_DOMAIN_FREE_MERGE:
      default:
        break;
    }
  }
  return CRABS_SUCCESS;
}

// Post-handler sovereign chain bookkeeping: advance each touched SOVEREIGN
// item (item_seq + 1) and recompute item_digest over the item's post-op
// content-only form (state_item_digest_compute — protocol_state excluded;
// runtime lock state is replica-local and must not change the digest).
// Runs only on the success path, after the handler
// / step-7b transitions / dedup mutation and BEFORE append_log — the same
// placement as the other per-op in-memory bookkeeping (R8-S-4 context):
// there is no rollback machinery for op mutations, and an append_log failure
// (OOM) already leaves the handler's own mutations committed while failing
// the op before version++/tx-commit. Advancing the chain alongside those
// mutations keeps it in lockstep with the op's other effects; advancing it
// only AFTER append_log would expose the opposite inconsistency (a log entry
// whose chain never moved) if the digest computation failed.
//
// Coverage: walking op->resources is EXHAUSTIVE for sovereign mutations
// because (a) DOMAIN_CHECK requires every non-FREE_MERGE dedup mutation
// target to be a named resource (_check_mutation_target_in_resources) — the
// dedup mutation runs immediately above and is the only other mutation the
// pipeline applies — and (b) trigger effects that would touch sovereign
// items are rejected at install time (spec §Triggers). Handler-internal
// mutations are the writer's own and land on the named resources.
static crabs_error_e _apply_sovereign_bookkeeping(state_t* state,
                                                  const operation_t* op) {
  for (uint32_t resource_index = 0; resource_index < op->resource_count;
       resource_index++) {
    data_item_t* item = state_find_item(state, op->resources[resource_index]);
    if (item == NULL || item->write_domain != CRABS_DOMAIN_SOVEREIGN) {
      continue;
    }
    // An op may name the same item in two resource slots; the chain advance
    // must still be exactly-once per op (a duplicate slot consumed a second
    // prefix in DOMAIN_CHECK, but must not bump seq twice — a seq jump is a
    // gap another honest op's prefix can't span).
    bool already_advanced = false;
    for (uint32_t earlier_index = 0; earlier_index < resource_index;
         earlier_index++) {
      if (strcmp(op->resources[earlier_index],
                 op->resources[resource_index]) == 0) {
        already_advanced = true;
        break;
      }
    }
    if (already_advanced) {
      continue;
    }
    item->item_seq += 1;
    crabs_error_e digest_rc = state_item_digest_compute(item, item->item_digest);
    if (digest_rc != CRABS_SUCCESS) {
      return digest_rc;
    }
  }
  return CRABS_SUCCESS;
}

static crabs_error_e state_machine_execute_internal(state_t* state, operation_t* op,
                                                    bool skip_authorization,
                                                    bool process_schedules) {
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

  // Step 3: Authorization — skipped for scheduled materialization, where
  // authorization was already enforced at submission time
  // (state_machine_validate). Declared unconditionally so the co-signature
  // helper can take its address in either mode.
  policy_preprocess_result_t pp = {0};
  char resolved_signer[CRABS_MAX_USER_ID];
  resolved_signer[0] = '\0';
  if (!skip_authorization) {
    crabs_error_e auth_rc = _verify_operation_authorization(state, op, &pp, resolved_signer);
    if (auth_rc != CRABS_SUCCESS) {
      return auth_rc;
    }
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

  // Audit A-4: wire HLC skew/counter validation (see _validate_received_hlc).
  // Runs BEFORE the ordering comparisons below consume op->hlc. Scheduled
  // materializations skip it: their embedded ops were validated against the
  // scheduling node's clock at submission time (state_machine_validate), and
  // a recurring slot materialized later must not be judged against a moved
  // clock.
  if (!skip_authorization) {
    crabs_error_e hlc_rc = _validate_received_hlc(state, op);
    if (hlc_rc != CRABS_SUCCESS) {
      return hlc_rc;
    }
  }

  // Step 3c: Ordering monotonicity (R7-11 + v1.6 Amd6). Rejects the op when
  // any of the signer's logged ops is NOT strictly older than it (see
  // state_signer_has_replay for why the maximum across all entries is used
  // instead of the tail-most entry). The R7-11 ordering check does not apply
  // to scheduled materializations — it is replaced by the scheduler's
  // idempotency guard (pending-list removal + uuid presence in the log,
  // enforced in scheduler_process_due), and the scheduled executor must not
  // reject a materialized op that a later submission advanced past.
  if (!skip_authorization) {
    if (state_signer_has_replay(state, op)) {
      return CRABS_ERR_ALREADY_EXECUTED;
    }
  }

  // Step 4: Verify protocol state transitions
  crabs_error_e transition_rc = _check_transitions(state, op);
  if (transition_rc != CRABS_SUCCESS) {
    return transition_rc;
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
  // Audit: an op-carried dedup spec is signer-authored — its condition,
  // mutation target and delta are covered only by the op's own signature.
  // Its MUTATION section would be applied post-handler with no authorization
  // on the target item, making it an unauthorized mutation primitive. Only
  // specs registered through __define_operation_type__ may guard or mutate
  // state; an op that carries a non-NONE spec for an op type with no
  // registered spec is rejected outright.
  const dedup_spec_t* registered_dedup = state_find_op_type_def(state, op->type);
  if (registered_dedup == NULL && op->dedup.type != DEDUP_NONE) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  const dedup_spec_t* effective_dedup = registered_dedup;
  if (effective_dedup != NULL && effective_dedup->type != DEDUP_NONE) {
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

  // Steps 6, 6b, 6c: key staleness, scheme constraints, co-signatures.
  // Skipped for scheduled materialization — all three were enforced at
  // submission time via state_machine_validate, against the same signer and
  // key state the scheduled op carries.
  if (!skip_authorization) {
    crabs_error_e key_version_rc = _check_key_version(state, op, resolved_signer);
    if (key_version_rc != CRABS_SUCCESS) {
      return key_version_rc;
    }

    crabs_error_e scheme_rc = _check_scheme_constraints(state, op, resolved_signer);
    if (scheme_rc != CRABS_SUCCESS) {
      return scheme_rc;
    }

    crabs_error_e co_signature_rc = _verify_co_signatures(state, op, &pp,
                                                          resolved_signer);
    if (co_signature_rc != CRABS_SUCCESS) {
      return co_signature_rc;
    }
  }

  // Step 6d: DOMAIN_CHECK (write-domains v1). Placement: post-dedup and
  // post-authorization (op->signer_id is authoritative; for scheduled
  // materializations it was authorized at submission), pre-handler (no
  // mutation has happened yet). Runs unconditionally — including for
  // skip_authorization materializations, whose chain prefixes must still be
  // current at fire time: the item's chain may have advanced since
  // submission, and applying a stale prefix silently would corrupt the
  // chain (a failing materialization is recorded as __schedule_failed__).
  crabs_error_e domain_rc = _run_domain_check(state, op);
  if (domain_rc != CRABS_SUCCESS) {
    return domain_rc;
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
  } else if (strcmp(op->type, CRABS_OP_SCHEDULE) == 0) {
    // Timed transactions (v1)
    result = state_machine_op_schedule(state, op);
  } else if (strcmp(op->type, CRABS_OP_CANCEL_SCHEDULE) == 0) {
    result = state_machine_op_cancel_schedule(state, op);
  } else if (strcmp(op->type, CRABS_OP_REPORT_EQUIVOCATION) == 0) {
    // Write domains v1: evidence-verified equivocation report
    result = state_machine_op_report_equivocation(state, op);
  } else {
    // Check user-defined handler registry for non-builtin operation types
    custom_handler = state_machine_find_handler(state, op->type);
    if (custom_handler != NULL) {
      result = custom_handler(state, op);
    } else if (op->resource_count == 0) {
      // Declared-but-unimplemented: a policy authorizes the op type (auth
      // passed) but no handler was registered and there are no resources for
      // the wildcard workflow below to act on. Failing so it does not log a
      // successful empty operation — the NOT_FOUND error, also returned by
      // the wildcard loop for unknown resources, applies to both cases.
      result = CRABS_ERR_RESOURCE_NOT_FOUND;
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
    // Pre-validate every resource BEFORE mutating any, so a later failure
    // cannot leave a partial apply (audit A10-L11: a mutation without a log
    // entry must never happen — the op would carry no version bump, no tx
    // commit, and its uuid could be replayed).
    for (uint32_t resource_index = 0; resource_index < op->resource_count;
         resource_index++) {
      data_item_t* item = state_find_item(state, op->resources[resource_index]);
      if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
      if (item->type != DATA_TYPE_RESOURCE) continue; // only RESOURCE has protocol state
      // A user operation may only be applied to a LOCKED resource (the
      // wildcard transition). Other states require a builtin transition.
      if (item->protocol_state != PROTOCOL_LOCKED) {
        return CRABS_ERR_PROTOCOL_VIOLATION;
      }
    }
    for (uint32_t resource_index = 0; resource_index < op->resource_count;
         resource_index++) {
      data_item_t* item = state_find_item(state, op->resources[resource_index]);
      if (item == NULL) continue; // unreachable: validated above
      if (item->type != DATA_TYPE_RESOURCE) continue;
      item->protocol_state = PROTOCOL_MODIFIED;
    }
  }

  // R7-13: apply the dedup mutation only after the handler (and protocol
  // transition) succeeded, so a failing op does not burn its dedup slot.
  if (effective_dedup != NULL && effective_dedup->type != DEDUP_NONE) {
    crabs_error_e dedup_result = dedup_apply_mutation_spec(state, effective_dedup, op);
    if (dedup_result != CRABS_SUCCESS) {
      return dedup_result;
    }
  }

  // Write domains v1: advance the sovereign hash chain for every SOVEREIGN
  // resource this op touched. Success-only and exactly-once (this runs after
  // the handler's success return above and cannot run twice for one op);
  // placement alongside the other per-op bookkeeping, before append_log, is
  // documented on _apply_sovereign_bookkeeping.
  crabs_error_e chain_rc = _apply_sovereign_bookkeeping(state, op);
  if (chain_rc != CRABS_SUCCESS) {
    return chain_rc;
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

  // Step 9b: Materialize due scheduled operations (timed transactions v1).
  // Failures are recorded as __schedule_failed__ log entries, never
  // propagated to this op.
  if (process_schedules) {
    scheduler_process_due(state, now_ms);
  }

  return CRABS_SUCCESS;
}

crabs_error_e state_machine_execute(state_t* state, operation_t* op) {
  char preview[CRABS_MAX_OP_NAME + CRABS_MAX_USER_ID + 2];
  _op_preview(op, preview, sizeof(preview));
  crabs_error_e rc = state_machine_execute_internal(state, op, false, true);
  // CRABS_ERR_ALREADY_EXECUTED is an idempotent skip: no mutation, no event.
  if (rc != CRABS_ERR_ALREADY_EXECUTED) {
    state_notify_change_for_op(state, CRABS_CHANGE_OP, op, preview, rc);
  }
  return rc;
}

crabs_error_e state_machine_execute_scheduled(state_t* state, operation_t* op) {
  char preview[CRABS_MAX_OP_NAME + CRABS_MAX_USER_ID + 16];
  memcpy(preview, "scheduled ", strlen("scheduled "));
  _op_preview(op, preview + strlen("scheduled "),
              sizeof(preview) - strlen("scheduled "));
  crabs_error_e rc = state_machine_execute_internal(state, op, true, false);
  if (rc != CRABS_ERR_ALREADY_EXECUTED) {
    state_notify_change_for_op(state, CRABS_CHANGE_SCHEDULE, op, preview, rc);
  }
  return rc;
}

crabs_error_e state_machine_validate(state_t* state, const operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;

  uint64_t now_ms;
  if (!state_get_time_ms(state, &now_ms)) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  state_machine_prune_expired(state, now_ms);
  if (state->attr_machine != NULL) {
    attribute_machine_set_time(state->attr_machine, now_ms);
    attribute_machine_prune_expired_temporary(state->attr_machine);
  }

  policy_preprocess_result_t pp = {0};
  char resolved_signer[CRABS_MAX_USER_ID];
  resolved_signer[0] = '\0';
  crabs_error_e rc = _verify_operation_authorization(state, op, &pp, resolved_signer);
  if (rc != CRABS_SUCCESS) return rc;
  // Audit A-4: validate a scheduled embedded op's HLC at submission time,
  // against the scheduling node's clock — this is the only chance, because
  // materialization re-runs without validation (execute_scheduled skips the
  // skew check; a slot fired later must not be judged against a moved clock).
  rc = _validate_received_hlc(state, op);
  if (rc != CRABS_SUCCESS) return rc;
  rc = _check_transitions(state, op);
  if (rc != CRABS_SUCCESS) return rc;
  rc = _check_key_version(state, op, resolved_signer);
  if (rc != CRABS_SUCCESS) return rc;
  rc = _check_scheme_constraints(state, op, resolved_signer);
  if (rc != CRABS_SUCCESS) return rc;
  rc = _verify_co_signatures(state, op, &pp, resolved_signer);
  if (rc != CRABS_SUCCESS) return rc;
  // DOMAIN_CHECK runs here too (write-domains v1): this pass mirrors the
  // execute path's pre-handler gates so a scheduled submission whose
  // sovereign prefix / writer binding / quarantine state would be rejected
  // at fire time fails BEFORE anyone co-signs or schedules it. Read-only —
  // the check never mutates items, and the chain is re-checked at
  // materialization (stale prefixes fail there too).
  rc = _run_domain_check(state, op);
  if (rc != CRABS_SUCCESS) return rc;
  return CRABS_SUCCESS;
}

// ============================================================
// Timed Transactions (v1)
// ============================================================

// The codebase avoids <endian.h>; payloads are little-endian by spec
// (mirrors serialization.c's _read_uint64_le logic).
static uint64_t _load_u64_le(const uint8_t* bytes) {
  uint64_t value = 0;
  for (int byte_index = 0; byte_index < 8; byte_index++) {
    value |= ((uint64_t)bytes[byte_index]) << (byte_index * 8);
  }
  return value;
}

static uint32_t _load_u32_le(const uint8_t* bytes) {
  uint32_t value = 0;
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    value |= ((uint32_t)bytes[byte_index]) << (byte_index * 8);
  }
  return value;
}

static uint16_t _load_u16_le(const uint8_t* bytes) {
  return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

// Record a failed scheduled materialization as a durable, LAMPORT-ordered log
// entry so all nodes agree the schedule resolved as failed. Never fails the
// caller's op: an OOM while appending simply drops the record (the tick must
// not crash), and a NULL/invalid input is ignored.
void state_machine_log_schedule_failure(state_t* state,
                                        const uint8_t uuid[CRABS_UUID_SIZE],
                                        const char* signer_id) {
  if (state == NULL || uuid == NULL || signer_id == NULL) return;
  uint8_t state_hash[CRABS_HASH_SIZE];
  memset(state_hash, 0, CRABS_HASH_SIZE);
  crabs_hlc_t zero_hlc;
  memset(&zero_hlc, 0, sizeof(zero_hlc));
  if (!append_log(state, uuid, "__schedule_failed__", signer_id,
                  0, state->hlc_state_initialized
                         ? state->hlc_state.last.node_id : "",
                  CRABS_ORDERING_LAMPORT, &zero_hlc, state_hash)) {
    return;  // OOM appending a failure record must not crash the tick
  }
  state->version++;
}

crabs_error_e state_machine_op_schedule(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL || op->payload == NULL ||
      op->payload_size < 12) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Payload layout: [u64 execute_at_ms LE][u32 op_len LE][op_bytes].
  uint64_t execute_at_ms = _load_u64_le(op->payload);
  uint32_t inner_len = _load_u32_le(op->payload + 8);
  // 12 + inner_len wraps mod 2^32 for huge inner_len, but any overflowed sum
  // is < 12 while payload_size >= 12 was already verified, so the equality
  // below can never match an overflowed value.
  if (inner_len == 0 || op->payload_size != 12 + inner_len) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Cheap check first: reject past (or exactly-now) execution times before
  // paying for deserialization and full pipeline validation.
  uint64_t now_ms;
  if (!state_get_time_ms(state, &now_ms)) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  if (execute_at_ms <= now_ms) return CRABS_ERR_INVALID_PARAM;

  operation_t* embedded = crabs_deserialize_operation(op->payload + 12, inner_len);
  if (embedded == NULL) return CRABS_ERR_INVALID_PARAM;

  // No nesting: a scheduled operation cannot itself be a schedule, so
  // deferred execution can never recursively defer.
  if (strcmp(embedded->type, CRABS_OP_SCHEDULE) == 0) {
    operation_destroy(embedded);
    return CRABS_ERR_INVALID_PARAM;
  }

  // Authorize the embedded operation NOW (full pipeline checks, nothing
  // applied). The embedded op carries its own signer_id and signature, and
  // validate checks them independently of the __schedule__ submitter. A
  // failing embedded op rejects the whole __schedule__ so nothing is stored.
  crabs_error_e validation = state_machine_validate(state, embedded);
  if (validation != CRABS_SUCCESS) {
    operation_destroy(embedded);
    return CRABS_ERR_SCHEDULE_INVALID;
  }

  uint64_t schedule_id = scheduler_schedule(state, execute_at_ms, op->signer_id, embedded);
  operation_destroy(embedded);
  if (schedule_id == 0) return CRABS_ERR_OOM;
  return CRABS_SUCCESS;
}

crabs_error_e state_machine_op_cancel_schedule(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL || op->payload == NULL ||
      op->payload_size != 8) {
    return CRABS_ERR_INVALID_PARAM;
  }
  uint64_t schedule_id = _load_u64_le(op->payload);
  return scheduler_cancel(state, schedule_id);
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
          locked->lock_state.pre_lock_snapshot_len = 0;
        }
        locked->lock_state.lock_extensions = 0;
      }
      return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
    }

    // Capture the pre-lock snapshot BEFORE mutating lock fields: a capture
    // failure must not hand out a token for a resource we could not roll
    // back (fail closed, item untouched).
    //
    // Repr-aware: a CRDT_STRUCT value's first bytes are a heap ADDRESS —
    // snapshotting them raw and memcpy-restoring after a post-lock entry
    // realloc revives a freed pointer (the old UAF). Struct values snapshot
    // their serialized LOGICAL content instead; rollback rebuilds the
    // struct from those bytes (data_item_restore_value_from_logical_bytes).
    // The sovereign chain digest is content-only over these same bytes, so
    // a rollback restores exactly the content (and digest) the lock
    // captured. RAW_INT64 values keep the historical 8-byte form.
    uint8_t* new_snapshot = NULL;
    size_t new_snapshot_len = 0;
    if (item->value != NULL) {
      if (item->value_repr == DATA_VALUE_REPR_CRDT_STRUCT) {
        crabs_error_e snapshot_rc =
          crabs_serialize_item_value_logical(item, &new_snapshot, &new_snapshot_len);
        if (snapshot_rc != CRABS_SUCCESS) return snapshot_rc;
      } else {
        size_t value_size = 0;
        if (item->type == DATA_TYPE_COUNTER || item->type == DATA_TYPE_PN_COUNTER ||
            item->type == DATA_TYPE_RESOURCE) {
          value_size = sizeof(int64_t);
        } else if (item->type == DATA_TYPE_REGISTER) {
          value_size = sizeof(int64_t);
        }
        if (value_size > 0) {
          new_snapshot = get_memory(value_size);
          new_snapshot_len = value_size;
          memcpy(new_snapshot, item->value, value_size);
        }
      }
    }
    if (item->lock_state.pre_lock_snapshot != NULL) {
      free(item->lock_state.pre_lock_snapshot);
    }
    item->lock_state.pre_lock_snapshot = new_snapshot;
    item->lock_state.pre_lock_snapshot_len = new_snapshot_len;

    memcpy(item->lock_state.lock_token, response->lock_tokens[i], CRABS_LOCK_TOKEN_SIZE);
    item->lock_state.lock_token_valid = true;
    strncpy(item->lock_state.lock_owner, op->signer_id, CRABS_MAX_USER_ID - 1);
    item->lock_state.lock_expiry = expiry;
    item->lock_state.lock_extensions = 0;
    item->lock_state.lock_acquired_at = acquired_at;

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
      if (!invariant_check_item(&item->invariants[j], item)) {
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
      if (item->value_repr == DATA_VALUE_REPR_CRDT_STRUCT) {
        // Deep restore: rebuild the struct from the snapshot's serialized
        // logical content (the bytes op_lock captured). Rebuild FIRST and
        // swap only on success — a malformed snapshot must not leave the
        // locked item value-less. content-only digest ⇒ the restored item
        // hashes back to exactly what the lock captured.
        void* previous_value = item->value;
        crabs_error_e restore_rc = data_item_restore_value_from_logical_bytes(
            item, item->lock_state.pre_lock_snapshot,
            item->lock_state.pre_lock_snapshot_len);
        if (restore_rc != CRABS_SUCCESS) {
          return restore_rc;
        }
        crdt_value_destroy(item->crdt_type, previous_value);
      } else {
        // RAW_INT64 items keep the historical 8-byte restore.
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
      item->lock_state.pre_lock_snapshot_len = 0;
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
      item->lock_state.pre_lock_snapshot_len = 0;
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

  // Audit: protected operation types (built-in ∪ lineage, A10-M1) have
  // their own handlers and protocol transitions; a registered dedup spec on
  // one would stack a signer-chosen guard/mutation on top of them. The
  // define operation may only register specs for user-defined operation
  // types.
  if (operation_is_protected(op->resources[0])) return CRABS_ERR_INVALID_PARAM;

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

// ============================================================
// Equivocation Report Built-in Operation (write-domains v1, spec
// 2026-10-08 §Equivocation detection and quarantine)
// ============================================================
// __report_equivocation__ convicts a SOVEREIGN item's writer of forking
// their own chain. The payload carries the evidence itself; the handler
// re-verifies everything, so no trust in the reporter is required and the
// quarantine flag is only ever set when the proof checks out.
//
// Payload wire layout (v1; bounded by the op's own u32 payload size):
//   u8       format version (0x01)
//   string16 item_name     (u16le length + bytes; the SOVEREIGN item)
//   string16 writer_id     (u16le length + bytes; must equal item.writer)
//   bytes32  op_a          (u32le length + serialized op bytes)
//   bytes32  op_b          (u32le length + serialized op bytes)
// Full consumption required; every length is checked against the bytes
// actually remaining before it is consumed.
//
// Fork fact (as implemented — the spec's "different resulting digests" is
// derivable by applying the ops; the signed fork FACT is the duplicate
// claim): op_a and op_b are two DISTINCT serialized ops that both
//   - are signed by `writer_id` (Mode A: signer_id == writer_id, and the
//     signature verifies under the writer's CURRENT keyring — v1 scope:
//     evidence must be minted under the writer's current key era; a fork
//     committed under a since-rotated key does not verify), and
//   - name `item_name` among their resources with a signed sovereign prefix
//     whose (item_seq, prev_item_digest) are EQUAL in both —
// i.e. two signed claims to be the one continuation of the same chain head
// at the same sequence number. Exactly one such continuation can exist.
//
// On success: { writer_id : SHA256(min(a,b) ‖ max(a,b)) } (lexicographic
// order, so (a,b) and (b,a) dedupe to the same entry) is appended to the
// item's capped fork-evidence set; DOMAIN_CHECK then rejects the writer's
// later ops on the item (CRABS_ERR_QUARANTINED). A duplicate report returns
// CRABS_ERR_DUPLICATE_OPERATION from state_append_fork_evidence. On ANY
// failed check nothing is set. The report op deliberately names NO
// resources — anyone with a policy for the op type may report, and the
// quarantine check (which gates only ops naming sovereign resources) never
// blocks a report.

// Bounded cursor read over the report payload: fail when fewer than `count`
// bytes remain. The cursor never exceeds payload_size, so the subtraction
// cannot underflow.
static bool _report_cursor_read(const uint8_t* payload, uint32_t payload_size,
                                uint32_t* cursor, uint32_t count,
                                const uint8_t** out_bytes) {
  if (count > payload_size - *cursor) return false;
  *out_bytes = payload + *cursor;
  *cursor += count;
  return true;
}

static crabs_error_e _report_payload_parse(const uint8_t* payload,
                                           uint32_t payload_size,
                                           char item_name[CRABS_MAX_USER_ID],
                                           char writer_id[CRABS_MAX_USER_ID],
                                           const uint8_t** op_a_bytes,
                                           uint32_t* op_a_len,
                                           const uint8_t** op_b_bytes,
                                           uint32_t* op_b_len) {
  if (payload == NULL) return CRABS_ERR_INVALID_PARAM;
  uint32_t cursor = 0;
  const uint8_t* field = NULL;
  if (!_report_cursor_read(payload, payload_size, &cursor, 1, &field)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (field[0] != 0x01) return CRABS_ERR_INVALID_PARAM;  // payload version

  // string16 item_name, string16 writer_id
  for (int name_index = 0; name_index < 2; name_index++) {
    char* name_out = (name_index == 0) ? item_name : writer_id;
    if (!_report_cursor_read(payload, payload_size, &cursor, 2, &field)) {
      return CRABS_ERR_INVALID_PARAM;
    }
    uint16_t name_len = _load_u16_le(field);
    if (name_len == 0 || name_len >= CRABS_MAX_USER_ID) {
      return CRABS_ERR_INVALID_PARAM;
    }
    if (!_report_cursor_read(payload, payload_size, &cursor, name_len,
                             &field)) {
      return CRABS_ERR_INVALID_PARAM;
    }
    memcpy(name_out, field, name_len);
    name_out[name_len] = '\0';
  }

  // bytes32 op_a, bytes32 op_b (each length bounded by the bytes remaining)
  for (int op_index = 0; op_index < 2; op_index++) {
    const uint8_t** bytes_out = (op_index == 0) ? op_a_bytes : op_b_bytes;
    uint32_t* len_out = (op_index == 0) ? op_a_len : op_b_len;
    if (!_report_cursor_read(payload, payload_size, &cursor, 4, &field)) {
      return CRABS_ERR_INVALID_PARAM;
    }
    uint32_t blob_len = _load_u32_le(field);
    if (blob_len == 0 || blob_len > payload_size - cursor) {
      return CRABS_ERR_INVALID_PARAM;
    }
    if (!_report_cursor_read(payload, payload_size, &cursor, blob_len,
                             &field)) {
      return CRABS_ERR_INVALID_PARAM;
    }
    *bytes_out = field;
    *len_out = blob_len;
  }

  // Full consumption: trailing bytes mean a malformed or padded payload.
  if (cursor != payload_size) return CRABS_ERR_INVALID_PARAM;
  return CRABS_SUCCESS;
}

// Locate the signed sovereign prefix an evidence op carries for
// `item_name`. Slot assignment mirrors DOMAIN_CHECK exactly: resources are
// walked in order and every resource that resolves to an existing SOVEREIGN
// item consumes one prefix slot. The op is well-formed for this machine
// only when its prefix count equals the number of its sovereign resources —
// the same exactness DOMAIN_CHECK would have enforced when the evidence op
// executed; anything else is structurally invalid evidence.
static crabs_error_e _evidence_prefix_for_item(state_t* state,
                                               const operation_t* evidence_op,
                                               const char* item_name,
                                               const crabs_sovereign_op_prefix_t** out_prefix) {
  uint32_t sovereign_total = 0;
  for (uint32_t resource_index = 0;
       resource_index < evidence_op->resource_count; resource_index++) {
    const data_item_t* resource_item =
        state_find_item(state, evidence_op->resources[resource_index]);
    if (resource_item != NULL &&
        resource_item->write_domain == CRABS_DOMAIN_SOVEREIGN) {
      sovereign_total++;
    }
  }
  if (evidence_op->sovereign_prefix_count != sovereign_total) {
    return CRABS_ERR_INVALID_PARAM;
  }
  uint32_t prefix_slot = 0;
  for (uint32_t resource_index = 0;
       resource_index < evidence_op->resource_count; resource_index++) {
    const data_item_t* resource_item =
        state_find_item(state, evidence_op->resources[resource_index]);
    if (resource_item == NULL ||
        resource_item->write_domain != CRABS_DOMAIN_SOVEREIGN) {
      continue;
    }
    if (strcmp(evidence_op->resources[resource_index], item_name) == 0) {
      *out_prefix = &evidence_op->sovereign_prefixes[prefix_slot];
      return CRABS_SUCCESS;
    }
    prefix_slot++;
  }
  return CRABS_ERR_INVALID_PARAM;
}

// Verify an evidence op's signature under the writer's CURRENT keyring —
// the same resolution op authorization uses (keyring key_id/scheme aware;
// R8-C-2 keeps rotated-away bootstrap keys from authorizing). The policy
// argument is empty on purpose: the writer binding IS the requirement, no
// attribute expression is re-evaluated against evidence.
static crabs_error_e _verify_evidence_signature(state_t* state,
                                                const operation_t* evidence_op,
                                                const char* writer_id) {
  serialized_buffer_t* canonical = crabs_serialize_for_signing(evidence_op);
  if (canonical == NULL) return CRABS_ERR_SERIALIZATION_ERROR;
  verify_result_t verify_result = crypto_verify_operation_auth_v2(
      state->abe_mk, "", state->attr_machine,
      canonical->data, canonical->len,
      evidence_op->signature, CRABS_SIG_SIZE,
      writer_id, evidence_op->key_id, evidence_op->sig_scheme,
      VERIFY_MODE_A);
  serialized_buffer_destroy(canonical);
  return verify_result.authorized ? CRABS_SUCCESS : verify_result.error;
}

// Conviction step: both evidence ops already parsed, the item already
// resolved to an existing SOVEREIGN item owned by writer_id. Checks the
// structural fork fact, re-verifies both signatures, and on success appends
// the canonical evidence digest to the item's fork set. Owns nothing;
// the byte strings and ops are borrowed from the caller.
static crabs_error_e _convict_if_fork(state_t* state, data_item_t* item,
                                      const char* writer_id,
                                      const operation_t* op_a,
                                      const operation_t* op_b,
                                      const uint8_t* op_a_bytes,
                                      uint32_t op_a_len,
                                      const uint8_t* op_b_bytes,
                                      uint32_t op_b_len) {
  // Structural fork fact: both halves are Mode A ops from the named writer…
  if (strcmp(op_a->signer_id, writer_id) != 0 ||
      strcmp(op_b->signer_id, writer_id) != 0) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // …both carrying a well-formed signed prefix for the item…
  const crabs_sovereign_op_prefix_t* prefix_a = NULL;
  const crabs_sovereign_op_prefix_t* prefix_b = NULL;
  if (_evidence_prefix_for_item(state, op_a, item->name, &prefix_a) !=
          CRABS_SUCCESS ||
      _evidence_prefix_for_item(state, op_b, item->name, &prefix_b) !=
          CRABS_SUCCESS) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // …claiming the SAME chain slot: equal seq, equal prev head digest.
  if (prefix_a->item_seq != prefix_b->item_seq ||
      CRYPTO_memcmp(prefix_a->prev_item_digest, prefix_b->prev_item_digest,
                    CRABS_HASH_SIZE) != 0) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Both signatures must verify under the writer's current keyring. The
  // cheap structural checks run first; signature failure maps to the
  // verifier's code (UNAUTHORIZED), still setting nothing.
  crabs_error_e verify_rc = _verify_evidence_signature(state, op_a, writer_id);
  if (verify_rc != CRABS_SUCCESS) return verify_rc;
  verify_rc = _verify_evidence_signature(state, op_b, writer_id);
  if (verify_rc != CRABS_SUCCESS) return verify_rc;

  // Canonical, direction-independent evidence digest: SHA256 over the
  // lexicographically ordered concatenation of the two serialized ops, so
  // re-reports swapping (a, b) dedupe to the same entry.
  const uint8_t* first_bytes = op_a_bytes;
  const uint8_t* second_bytes = op_b_bytes;
  uint32_t first_len = op_a_len;
  uint32_t second_len = op_b_len;
  int order = (op_a_len == op_b_len)
      ? memcmp(op_a_bytes, op_b_bytes, op_a_len)
      : (op_a_len < op_b_len ? -1 : 1);
  if (order > 0) {
    first_bytes = op_b_bytes;
    first_len = op_b_len;
    second_bytes = op_a_bytes;
    second_len = op_a_len;
  }
  uint8_t* joined = get_memory((size_t)first_len + (size_t)second_len);
  memcpy(joined, first_bytes, first_len);
  memcpy(joined + first_len, second_bytes, second_len);
  uint8_t evidence_digest[CRABS_HASH_SIZE];
  crabs_error_e hash_rc = crypto_sha256(joined,
                                        (size_t)first_len + (size_t)second_len,
                                        evidence_digest);
  free(joined);
  if (hash_rc != CRABS_SUCCESS) return hash_rc;

  // Monotone, capped union; DUPLICATE_OPERATION on re-delivery, OOM past the
  // cap — both surfaced to the reporter, flag untouched either way (domain
  // check honors what is present; the audit log keeps the rest).
  return state_append_fork_evidence(item, writer_id, evidence_digest);
}

crabs_error_e state_machine_op_report_equivocation(state_t* state,
                                                   operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;

  char item_name[CRABS_MAX_USER_ID];
  char writer_id[CRABS_MAX_USER_ID];
  const uint8_t* op_a_bytes = NULL;
  const uint8_t* op_b_bytes = NULL;
  uint32_t op_a_len = 0;
  uint32_t op_b_len = 0;
  crabs_error_e parse_rc =
      _report_payload_parse(op->payload, op->payload_size,
                            item_name, writer_id,
                            &op_a_bytes, &op_a_len, &op_b_bytes, &op_b_len);
  if (parse_rc != CRABS_SUCCESS) return parse_rc;

  // The target must exist, must be SOVEREIGN, and the payload must name its
  // bound writer — the fork set is per-item evidence about THAT writer.
  data_item_t* item = state_find_item(state, item_name);
  if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
  if (item->write_domain != CRABS_DOMAIN_SOVEREIGN ||
      strcmp(writer_id, item->writer) != 0) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Identical bytes are one op delivered twice, not two conflicting claims.
  if (op_a_len == op_b_len &&
      CRYPTO_memcmp(op_a_bytes, op_b_bytes, op_a_len) == 0) {
    return CRABS_ERR_INVALID_PARAM;
  }

  operation_t* op_a = crabs_deserialize_operation(op_a_bytes, op_a_len);
  operation_t* op_b = crabs_deserialize_operation(op_b_bytes, op_b_len);
  if (op_a == NULL || op_b == NULL) {
    if (op_a != NULL) operation_destroy(op_a);
    if (op_b != NULL) operation_destroy(op_b);
    return CRABS_ERR_SERIALIZATION_ERROR;
  }

  crabs_error_e result = _convict_if_fork(state, item, writer_id,
                                          op_a, op_b,
                                          op_a_bytes, op_a_len,
                                          op_b_bytes, op_b_len);
  operation_destroy(op_a);
  operation_destroy(op_b);
  return result;
}
