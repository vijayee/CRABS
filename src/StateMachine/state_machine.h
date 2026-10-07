//
// Created by victor on 4/30/25.
//

#ifndef CRABS_STATE_MACHINE_H
#define CRABS_STATE_MACHINE_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "../Trigger/trigger.h"
#include "../Crypto/sig_scheme.h"
#include "../HLC/hlc.h"
#include "../Lineage/lineage.h"

// ============================================================
// Lock Claim (§7.2)
// ============================================================
typedef struct {
  char    resource[CRABS_MAX_USER_ID];
  uint8_t lock_token[CRABS_LOCK_TOKEN_SIZE];
} lock_claim_t;

// ============================================================
// Co-Signature (v1.3 Amendment 3, §4.2)
// ============================================================
#define CRABS_MAX_CO_SIGNERS  8

// Parent attestations an operation may carry (v1.7 §attestation bridge).
// Matches the per-policy endorsement slot cap in condition.h — a policy
// cannot name more endorsements than CRABS_MAX_PARENT_ENDORSEMENTS, so an
// op never needs more attestations than that either.
#define CRABS_MAX_OP_ATTESTATIONS  CRABS_MAX_PARENT_ENDORSEMENTS

typedef struct {
  char               signer_id[CRABS_MAX_USER_ID];
  char               key_id[CRABS_MAX_KEY_ID];
  signature_scheme_e  sig_scheme;
  uint8_t            signature[CRABS_SIG_SIZE];
  uint32_t           signature_len;
} co_signature_t;

// ============================================================
// Operation (§7.1 + v1.3 §4.2)
// ============================================================
// Current operation wire format version (the u32le heading every serialized
// op). v3: dedup_spec; v4: ordering_system + HLC; v5: parent attestations.
#define CRABS_OP_FORMAT_VERSION  5

// Tagged so lineage.h can forward-declare the name for its op handlers
// (those declarations land before this header's own definition of the type).
typedef struct crabs_operation {
  char     type[CRABS_MAX_OP_NAME];
  uint8_t  uuid[CRABS_UUID_SIZE];
  uint8_t* payload;
  uint32_t payload_size;
  uint8_t  payload_format;
  char(*resources)[CRABS_MAX_USER_ID];
  uint32_t resource_count;
  protocol_state_e* required_state;
  protocol_state_e* next_state;
  lock_claim_t* lock_claims;
  uint32_t      lock_claim_count;
  char     policy[CRABS_MAX_POLICY_EXPR];
  uint8_t  signature[CRABS_SIG_SIZE];
  char     signer_id[CRABS_MAX_USER_ID];
  uint64_t signer_key_version;
  uint64_t lamport_time;
  char     node_id[CRABS_MAX_USER_ID];
  // v1.3: Scheme-aware signing
  signature_scheme_e sig_scheme;
  char               key_id[CRABS_MAX_KEY_ID];
  co_signature_t*    co_signers;
  uint32_t           co_signer_count;
  // v1.7 lineage: parent attestations carried by the op (§attestation
  // bridge). Verified in the authorization pipeline against the machine's
  // lineage parent binding; on the wire each entry reuses the attestation
  // wire format. Single-owner heap array like co_signers: allocated by the
  // deserializer, freed by operation_destroy; value copies of the struct
  // only borrow the pointer.
  attestation_t*     attestations;
  uint32_t           attestation_count;
  // v1.4: Dedup specification
  dedup_spec_t       dedup;
  // v1.6 Amd6: Ordering system support
  crabs_ordering_system_e ordering_system;  // LAMPORT (default) or HLC
  crabs_hlc_t        hlc;                   // HLC timestamp (used when ordering_system == HLC)
  // A10-L7: wire format version this op was parsed from / will be emitted as.
  // The deserializer validates 1..CRABS_OP_FORMAT_VERSION and stores it here
  // (previously discarded); operation_create stamps the current version.
  // Included in the signed canonical form (signing format v3) so a relay
  // cannot strip the attestation/dedup/HLC tail by downgrading the version
  // byte — the rewritten op re-serializes to different signed bytes.
  uint32_t           op_version;
} operation_t;

// ============================================================
// User-Defined Operation Handler Registry
// ============================================================
#define CRABS_MAX_OP_HANDLERS  32

typedef crabs_error_e (*op_handler_fn)(state_t* state, operation_t* op);

typedef struct op_handler_entry_t {
  char           op_type[CRABS_MAX_OP_NAME];
  op_handler_fn  handler;
} op_handler_entry_t;

// ============================================================
// State Change Notification (core; not devtools-gated)
// ============================================================
// Register a callback fired after every state-mutating completion: direct
// execution (kind OP), scheduled materialization (kind SCHEDULE), trigger
// effects (kind TRIGGER), attribute-machine mutations (kind ATTRIBUTE).
// Idempotent skips (CRABS_ERR_ALREADY_EXECUTED) do NOT fire. The hook must
// not mutate state. Pass NULL to clear. Runtime state; not serialized.
void state_set_change_hook(state_t* state, crabs_change_hook_fn hook,
                           void* user_data);

// Fire a change event manually (used by the attribute machine and trigger
// engine, which mutate without going through state_machine_execute). Does
// nothing when no hook is registered. All strings are borrowed for the
// duration of the hook call only.
void state_notify_change(state_t* state, crabs_change_kind_e kind,
                         const char* type, const uint8_t* uuid,
                         const char* signer_id, const char* node_id,
                         const char* target, const char* preview,
                         crabs_error_e result);

// Convenience: build the event from an operation's fields. preview_override
// replaces the default (NULL) preview when non-NULL.
void state_notify_change_for_op(state_t* state, crabs_change_kind_e kind,
                                const operation_t* op,
                                const char* preview_override,
                                crabs_error_e result);

// ============================================================
// Lock Response (§7.3.1)
// ============================================================
typedef struct {
  bool      success;
  uint8_t   lock_tokens[CRABS_MAX_RESOURCES][CRABS_LOCK_TOKEN_SIZE];
  uint32_t  token_count;
  uint64_t  expiry;
  crabs_hlc_t acquired_at;  // v1.6 Amd6 §8: HLC timestamp when lock was acquired
} lock_response_t;

// ============================================================
// State Machine Functions
// ============================================================
bool           state_machine_is_valid_transition(protocol_state_e current, const char* op_type);
crabs_error_e  state_machine_execute(state_t* state, operation_t* op);

// Authorization-only pipeline: signature + policy + key staleness + scheme +
// co-signatures + transition feasibility, applied to nothing. Used by the
// scheduler to authorize a scheduled operation at submission time.
crabs_error_e  state_machine_validate(state_t* state, const operation_t* op);

// Internal executor for scheduled materialization: transitions, dedup,
// handlers, and logging apply; user-facing authorization is skipped. The
// R7-11 ordering check does not apply to scheduled materializations — it is
// replaced by the scheduler's idempotency guard (pending-list removal + uuid
// presence in the log, enforced in scheduler_process_due).
crabs_error_e  state_machine_execute_scheduled(state_t* state, operation_t* op);

// Record a failed scheduled materialization in the audit log (system entry,
// no signature, lamport 0 / LAMPORT ordering). Used by the scheduler; never
// fails the caller's op.
void state_machine_log_schedule_failure(state_t* state,
                                        const uint8_t uuid[CRABS_UUID_SIZE],
                                        const char* signer_id);

uint32_t       state_machine_prune_expired(state_t* state, uint64_t now_ms);

// Built-in trigger operations (Amendment 1, §4) — defined in trigger.c
crabs_error_e  state_machine_op_create_trigger(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_delete_trigger(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_disable_trigger(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_enable_trigger(state_t* state, operation_t* op);

// These handlers are called from CLI and must remain public. All other
// built-in operation handlers are static in state_machine.c — they can
// only be reached through state_machine_execute, which enforces auth.
crabs_error_e  state_machine_op_define_operation(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_check_dedup(state_t* state, operation_t* op);

// Timed transactions (v1): __schedule__ stores a validated pending entry;
// __cancel_schedule__ removes one by id. Both are dispatched from
// state_machine_execute's builtin chain.
crabs_error_e  state_machine_op_schedule(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_cancel_schedule(state_t* state, operation_t* op);

// Auto-compact items that need compaction (v1.5.2 §4)
// Returns count of items compacted. Requires compaction_config on state.
uint32_t       state_machine_auto_compact(state_t* state);

// Key refresh operation (§11.3)
typedef struct {
  // Audit M-I: sized large enough for a real Waters'09 CP-ABE user key
  // (up to ~4096 bytes) plus the envelope header and signature. The prior
  // 1024-byte buffer overflowed in crypto_key_envelope_serialize, which
  // returned 0 and left the op reporting SUCCESS with an unusable empty
  // envelope. Must stay >= CRABS_KEY_ENVELOPE_MAX_SIZE (crypto.h).
  uint8_t         envelope_data[8192];
  uint32_t        envelope_data_len;
} refresh_key_response_t;

crabs_error_e  state_machine_op_refresh_key(state_t* state, operation_t* op,
                                             refresh_key_response_t* response);

// User-defined operation handler registry
crabs_error_e  state_machine_register_handler(state_t* state, const char* op_type,
                                               op_handler_fn handler);
void           state_machine_unregister_handler(state_t* state, const char* op_type);
op_handler_fn  state_machine_find_handler(const state_t* state, const char* op_type);

// Operation lifecycle
operation_t*   operation_create(const char* type);
void           operation_destroy(operation_t* op);
bool           operation_is_builtin(const char* type);
// Superset of operation_is_builtin that also covers the lineage op types
// (handler-registered custom ops that must not be re-policyable by triggers
// or re-definable by __define_operation_type__ — audit A10-M1).
bool           operation_is_protected(const char* type);

// Cross-system operation ordering (v1.6 Amd6 §10.2)
// Compares two operations by their ordering system (Lamport or HLC).
// Returns: -1 if a < b, 0 if equal, 1 if a > b
// Rule: Lamport operations always sort before HLC operations.
int            crabs_operation_compare(const operation_t* a, const operation_t* b);

// HLC-aware lock expiry check (v1.6 Amd6 §8)
// When ordering_config is HLC, uses crabs_hlc_lock_expired for expiry check.
// Otherwise falls back to wall-clock millisecond comparison using now_ms.
bool           state_machine_lock_expired(state_t* state, const lock_state_t* lock, uint64_t now_ms);

// Current time in ms from the state's HLC time source. The default
// SYSTEM_CLOCK source backs reads with the UNAUTHENTICATED platform clock
// (R8-H-1); every other source requires attached ops and fails closed —
// returns false — when it reports no valid time. Callers that treat time as
// an authorization input (attestation windows, expiry) must run on an
// authenticated source; on a false return they treat time as unavailable
// rather than reading the wall clock themselves. Lineage spawn stamps the
// manifest's spawned_at through this helper (0 when unavailable).
bool           state_get_time_ms(const state_t* state, uint64_t* now_ms);

// Misc
void           state_machine_generate_lock_token(uint8_t token[CRABS_LOCK_TOKEN_SIZE]);
bool           invariant_check(invariant_t* inv, void* value, data_type_e type);

#endif // CRABS_STATE_MACHINE_H
