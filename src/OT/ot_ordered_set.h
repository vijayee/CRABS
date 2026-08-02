//
// Created by victor on 5/1/25.
//
// OT_ORDERED_SET Data Type (v1.5 §5)
// Ordered list with OT/CRDT hybrid conflict resolution.
// Type ID: 0x10
//

#ifndef CRABS_OT_ORDERED_SET_H
#define CRABS_OT_ORDERED_SET_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "ot_types.h"
#include "ot_transform.h"

// ============================================================
// Type ID
// ============================================================
// Audit R6-1: DATA_TYPE_OT_ORDERED_SET is defined as an enum constant in
// data_model.h (value 0x10). Do NOT re-#define it here — the dual
// definition required #undef hacks in compact_op.c and risked redefinition
// conflicts if include order changed. The CRABS_OT_ORDERED_SET macro is
// retained as the numeric type ID for crabs_ot_data_item_create() calls
// in the .c file (it does not collide with any enum identifier).
#define CRABS_OT_ORDERED_SET    0x10

// ============================================================
// Ordered Element (v1.5 §5.1)
// ============================================================

typedef struct crabs_ordered_element {
  crabs_ot_op_id_t            id;
  uint8_t*                    value;
  uint32_t                    value_size;
  bool                        deleted;
  struct crabs_ordered_element* prev;
  struct crabs_ordered_element* next;
} crabs_ordered_element_t;

// ============================================================
// OT Ordered Set (v1.5 §5)
// ============================================================

typedef struct {
  crabs_ordered_element_t* head;
  crabs_ordered_element_t* tail;
  uint32_t                 count;
  uint32_t                 visible_count;
  crabs_ot_data_item_t*    ot_data;
} crabs_ot_ordered_set_t;

// ============================================================
// Element Lifecycle
// ============================================================

crabs_ordered_element_t* crabs_ordered_element_create(
  const crabs_ot_op_id_t* id, const uint8_t* value, uint32_t value_size);
void crabs_ordered_element_destroy(crabs_ordered_element_t* elem);

// ============================================================
// Ordered Set Lifecycle
// ============================================================

crabs_ot_ordered_set_t* crabs_ot_ordered_set_create(void);
void crabs_ot_ordered_set_destroy(crabs_ot_ordered_set_t* set);
uint32_t crabs_ot_ordered_set_count(const crabs_ot_ordered_set_t* set);
uint32_t crabs_ot_ordered_set_visible_count(const crabs_ot_ordered_set_t* set);

// ============================================================
// Ordered Set Access
// ============================================================

crabs_ordered_element_t* crabs_ot_ordered_set_get(
  const crabs_ot_ordered_set_t* set, uint64_t visible_pos);
crabs_ordered_element_t* crabs_ot_ordered_set_find(
  const crabs_ot_ordered_set_t* set, const crabs_ot_op_id_t* id);
crabs_ordered_element_t* crabs_ot_ordered_set_head(
  const crabs_ot_ordered_set_t* set);
crabs_ordered_element_t* crabs_ot_ordered_set_tail(
  const crabs_ot_ordered_set_t* set);

// ============================================================
// Apply Operations (v1.5 §5.2)
// ============================================================

crabs_ordered_element_t* crabs_ot_ordered_set_apply_insert(
  crabs_ot_ordered_set_t* set, const crabs_ot_operation_t* op);

crabs_ordered_element_t* crabs_ot_ordered_set_apply_delete(
  crabs_ot_ordered_set_t* set, const crabs_ot_operation_t* op);

crabs_ordered_element_t* crabs_ot_ordered_set_apply_update(
  crabs_ot_ordered_set_t* set, const crabs_ot_operation_t* op);

crabs_ordered_element_t* crabs_ot_ordered_set_apply_move(
  crabs_ot_ordered_set_t* set, const crabs_ot_operation_t* op);

crabs_ordered_element_t* crabs_ot_ordered_set_apply_swap(
  crabs_ot_ordered_set_t* set, const crabs_ot_operation_t* op);

// Apply any operation by type
crabs_ordered_element_t* crabs_ot_ordered_set_apply(
  crabs_ot_ordered_set_t* set, const crabs_ot_operation_t* op);

// ============================================================
// CRDT Merge (v1.5 §5.3)
// ============================================================

crabs_ot_ordered_set_t* crabs_ot_ordered_set_merge(
  crabs_ot_ordered_set_t* dest, const crabs_ot_ordered_set_t* src);

void crabs_ot_ordered_set_merge_position_maps(
  crabs_ot_ordered_set_t* dest, const crabs_ot_ordered_set_t* src);

#endif // CRABS_OT_ORDERED_SET_H