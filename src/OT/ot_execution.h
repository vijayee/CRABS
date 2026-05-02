//
// Created by victor on 5/1/25.
//
// OT Execution Integration (v1.5 §8)
// Integrates OT operations into the CRABS state machine pipeline.
// Steps 6-7 of EXECUTE_OT_OPERATION: extract, transform, apply.
//

#ifndef CRABS_OT_EXECUTION_H
#define CRABS_OT_EXECUTION_H

#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "../StateMachine/state_machine.h"
#include "ot_types.h"
#include "ot_transform.h"

// ============================================================
// OT Config (v1.5 §8.1)
// ============================================================

#define CRABS_OT_MAX_OP_LOG_DEFAULT  1000
#define CRABS_OT_MAX_TRANSFORM_DEPTH 64

typedef struct {
  uint32_t max_op_log_size;
  char     priority_node_id[CRABS_MAX_USER_ID];
  bool     allow_move;
  bool     allow_swap;
} crabs_ot_config_t;

// ============================================================
// OT Execution Functions (v1.5 §8.2)
// ============================================================

// Execute OT operation on a data item
// Returns CRABS_SUCCESS on success, error code on failure
crabs_error_e crabs_execute_ot_operation(state_t* state, operation_t* op);

// Extract OT operations from an operation payload
// Returns number of extracted ops (0 = NO_OT_OPS)
// Caller must free the returned array with crabs_ot_ops_free()
uint32_t crabs_extract_ot_ops(const uint8_t* payload, uint32_t payload_size,
                              crabs_ot_operation_t** ops_out);

// Transform an OT operation against concurrent operations in the op log
// Applies both forward and reverse transforms per spec §8.2 step 7
crabs_error_e crabs_transform_ot_op(crabs_ot_operation_t* op,
                                     crabs_ot_data_item_t* item,
                                     const char* local_node_id,
                                     uint32_t max_depth);

// Apply a transformed OT operation to the appropriate data item value
crabs_error_e crabs_apply_ot_op(data_item_t* item, crabs_ot_operation_t* op);

// Prune the operation log, keeping recent operations plus any
// referenced by causal dependencies
void crabs_prune_ot_log(crabs_ot_data_item_t* item, uint32_t max_size);

// Free an array of OT operations extracted by crabs_extract_ot_ops
void crabs_ot_ops_free(crabs_ot_operation_t* ops, uint32_t count);

// ============================================================
// Type Registration (v1.5 §8.1)
// ============================================================

// Register an OT data type on the state, creating the data item
// with ot_data initialized for the specified OT type
data_item_t* crabs_register_ot_type(state_t* state,
                                     const char* name,
                                     uint32_t ot_type,
                                     const crabs_ot_config_t* config);

// Check if a data type is an OT type (0x10-0x1F range)
bool crabs_is_ot_type(uint32_t type);

// Get the apply function for an OT type
// Returns NULL for non-OT types
typedef void* (*crabs_ot_apply_fn)(void* data, const crabs_ot_operation_t* op);
crabs_ot_apply_fn crabs_ot_get_apply_fn(data_type_e type);

#endif // CRABS_OT_EXECUTION_H