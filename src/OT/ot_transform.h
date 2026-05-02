//
// Created by victor on 5/1/25.
//
// OT Transform Functions & Matrix (v1.5 §4)
// Operational transform functions for the 5x5 transform matrix
// used in ordered structure collaboration.
//

#ifndef CRABS_OT_TRANSFORM_H
#define CRABS_OT_TRANSFORM_H

#include <stdint.h>
#include <stdbool.h>
#include "ot_types.h"

// ============================================================
// Causal Ordering (v1.5 §4.1)
// ============================================================

bool crabs_causally_before(const crabs_ot_op_id_t* a, const crabs_ot_op_id_t* b);

// ============================================================
// Transform Entry (v1.5 §4)
// ============================================================

#define CRABS_TRANSFORM_DESC_MAX 64

typedef struct {
  crabs_ot_transform_fn fn;
  char description[CRABS_TRANSFORM_DESC_MAX];
} crabs_transform_entry_t;

// ============================================================
// Transform Functions (v1.5 §4.2)
// ============================================================

// T1: INSERT vs INSERT — right-side insertion shifts by +1 if same position
crabs_ot_operation_t* crabs_transform_insert_insert(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// T2: DELETE vs INSERT — insertion after deletion site doesn't shift
crabs_ot_operation_t* crabs_transform_delete_insert(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// T3: INSERT vs DELETE — deletion before insertion shifts insert back by -1
crabs_ot_operation_t* crabs_transform_insert_delete(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// T4: DELETE vs DELETE — if same position, second becomes no-op
crabs_ot_operation_t* crabs_transform_delete_delete(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// T5: MOVE vs MOVE — composite: delete at src then insert at dst
crabs_ot_operation_t* crabs_transform_move_move(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// T6: SWAP vs INSERT — insertion before swap positions shifts both by +1
crabs_ot_operation_t* crabs_transform_swap_insert(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// T7: SWAP vs DELETE — deletion before swap shifts both back by -1
crabs_ot_operation_t* crabs_transform_swap_delete(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// MOVE vs INSERT
crabs_ot_operation_t* crabs_transform_move_insert(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// MOVE vs DELETE
crabs_ot_operation_t* crabs_transform_move_delete(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// INSERT vs MOVE
crabs_ot_operation_t* crabs_transform_insert_move(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// DELETE vs MOVE
crabs_ot_operation_t* crabs_transform_delete_move(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// SWAP vs SWAP
crabs_ot_operation_t* crabs_transform_swap_swap(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// SWAP vs MOVE
crabs_ot_operation_t* crabs_transform_swap_move(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// MOVE vs SWAP
crabs_ot_operation_t* crabs_transform_move_swap(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// DELETE vs SWAP
crabs_ot_operation_t* crabs_transform_delete_swap(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// INSERT vs SWAP
crabs_ot_operation_t* crabs_transform_insert_swap(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// Identity transform (no change)
crabs_ot_operation_t* crabs_transform_identity(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2);

// ============================================================
// Transform Matrix (v1.5 §4)
// ============================================================

void crabs_transform_matrix_init(crabs_ot_data_item_t* item);
crabs_transform_entry_t* crabs_transform_matrix_get_entry(
  crabs_ot_data_item_t* item, crabs_ot_op_type_e type1, crabs_ot_op_type_e type2);

#endif // CRABS_OT_TRANSFORM_H