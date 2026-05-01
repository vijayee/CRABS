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
typedef struct {
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
  // v1.4: Dedup specification
  dedup_spec_t       dedup;
} operation_t;

// ============================================================
// Lock Response (§7.3.1)
// ============================================================
typedef struct {
  bool      success;
  uint8_t   lock_tokens[CRABS_MAX_RESOURCES][CRABS_LOCK_TOKEN_SIZE];
  uint32_t  token_count;
  uint64_t  expiry;
} lock_response_t;

// ============================================================
// State Machine Functions
// ============================================================
bool           state_machine_is_valid_transition(protocol_state_e current, const char* op_type);
crabs_error_e  state_machine_execute(state_t* state, operation_t* op);
uint32_t       state_machine_prune_expired(state_t* state, uint64_t now_ms);

// Built-in operations
crabs_error_e  state_machine_op_lock(state_t* state, operation_t* op, lock_response_t* response);
crabs_error_e  state_machine_op_extend(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_verify(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_rollback(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_unlock(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_force_unlock(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_change_config(state_t* state, operation_t* op);

// Built-in trigger operations (Amendment 1, §4)
crabs_error_e  state_machine_op_create_trigger(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_delete_trigger(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_disable_trigger(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_enable_trigger(state_t* state, operation_t* op);

// Built-in key operations (v1.3 Amendment 3, §5)
crabs_error_e  state_machine_op_register_key(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_revoke_key(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_set_default_key(state_t* state, operation_t* op);

// Key lifecycle operations (v1.3 §9)
crabs_error_e  state_machine_op_suspend_key(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_activate_key(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_rotate_key(state_t* state, operation_t* op);

// Dedup built-in operations (v1.4 §7)
crabs_error_e  state_machine_op_define_operation(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_check_dedup(state_t* state, operation_t* op);

// Key refresh operation (§11.3)
typedef struct {
  uint8_t         envelope_data[1024];  // Serialized key envelope for transport
  uint32_t        envelope_data_len;
} refresh_key_response_t;

crabs_error_e  state_machine_op_refresh_key(state_t* state, operation_t* op,
                                             refresh_key_response_t* response);

// Operation lifecycle
operation_t*   operation_create(const char* type);
void           operation_destroy(operation_t* op);
bool           operation_is_builtin(const char* type);

// Misc
void           state_machine_generate_lock_token(uint8_t token[CRABS_LOCK_TOKEN_SIZE]);
bool           invariant_check(invariant_t* inv, void* value, data_type_e type);

#endif // CRABS_STATE_MACHINE_H
