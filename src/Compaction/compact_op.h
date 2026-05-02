//
// Created by victor on 5/1/25.
//
// COMPACT Operation & Algorithm (v1.6 §3)
// Tombstone compaction as an OT operation that extracts visible values,
// rebuilds data items with empty position maps, and handles transform rules.
//

#ifndef CRABS_COMPACT_OP_H
#define CRABS_COMPACT_OP_H

#include <stdint.h>
#include <stdbool.h>
#include "../OT/ot_types.h"
#include "../CRABS/data_model.h"
#include "compaction.h"
#include "vector_clock.h"

// ============================================================
// Compaction ID Generation (v1.6 §3)
// ============================================================

void crabs_compact_id_init(crabs_ot_op_id_t* id, const char* node_id,
                            uint64_t sequence_num, uint64_t timestamp);

// ============================================================
// Extract Visible Value (v1.6 §3.3)
// ============================================================

// Generic extract visible: dispatches by data type.
// Returns a newly allocated value of the appropriate type.
// Caller is responsible for freeing the returned value.
void* crabs_extract_visible(data_type_e type, const void* value);

// ============================================================
// COMPACT Operation (v1.6 §3)
// ============================================================

// Execute a COMPACT operation on a data item.
crabs_error_e crabs_compact_ot_item(
  state_t* state,
  data_item_t* item,
  const crabs_tombstone_config_t* config,
  const crabs_compaction_registry_t* registry,
  const crabs_vector_clock_t* local_vc,
  const crabs_vector_clock_t* peer_vc);

// ============================================================
// COMPACT Transform Rules (v1.6 §3.4)
// ============================================================

// COMPACT absorbs all preceding operations
crabs_ot_operation_t* crabs_transform_compact_insert(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);
crabs_ot_operation_t* crabs_transform_compact_delete(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);
crabs_ot_operation_t* crabs_transform_compact_move(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);
crabs_ot_operation_t* crabs_transform_compact_update(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);
crabs_ot_operation_t* crabs_transform_compact_swap(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// COMPACT vs COMPACT: last-writer-wins by timestamp
crabs_ot_operation_t* crabs_transform_compact_compact(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// Preceding operations vs COMPACT: absorbed by compacted state
crabs_ot_operation_t* crabs_transform_insert_compact(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);
crabs_ot_operation_t* crabs_transform_delete_compact(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);
crabs_ot_operation_t* crabs_transform_move_compact(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);
crabs_ot_operation_t* crabs_transform_update_compact(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);
crabs_ot_operation_t* crabs_transform_swap_compact(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

#endif // CRABS_COMPACT_OP_H