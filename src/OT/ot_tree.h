//
// Created by victor on 5/1/25.
//
// OT_TREE Data Type (v1.5 §7)
// Tree-structured data with per-parent position maps.
// Type ID: 0x13
//

#ifndef CRABS_OT_TREE_H
#define CRABS_OT_TREE_H

#include <stdint.h>
#include <stdbool.h>
#include "ot_types.h"
#include "position_map.h"

// ============================================================
// Type ID
// ============================================================
// Audit R6-1: DATA_TYPE_OT_TREE is defined as an enum constant in
// data_model.h (value 0x13). Do NOT re-#define it here — the dual
// definition required #undef hacks in compact_op.c. The CRABS_OT_TREE
// macro is retained as the numeric type ID for crabs_ot_data_item_create().
#define CRABS_OT_TREE     0x13

// ============================================================
// Tree Operation Types (extends crabs_ot_op_type_e)
// ============================================================
// These identifiers are enum constants in ot_types.h (CRABS_OT_OP_INSERT_NODE
// etc.). Do NOT redefine them here as macros — a prior #define version used
// different numeric values than the enum, which made the wire format and the
// dispatch disagree.

// ============================================================
// Tree Node (v1.5 §7.1)
// ============================================================

#define CRABS_TREE_NODE_ID_MAX 64
#define CRABS_TREE_MAX_CHILDREN 256

typedef struct crabs_tree_node {
  char                  id[CRABS_TREE_NODE_ID_MAX];
  char                  parent_id[CRABS_TREE_NODE_ID_MAX];
  uint8_t*              value;
  uint32_t              value_size;
  bool                  deleted;
  crabs_bst_node_t*     child_position_map;
  struct crabs_tree_node* first_child;
  struct crabs_tree_node* next_sibling;
  struct crabs_tree_node* prev_sibling;
  struct crabs_tree_node* parent;
  struct crabs_tree_node* pool_next;  // Node pool linkage for iteration
} crabs_tree_node_t;

// ============================================================
// OT Tree (v1.5 §7)
// ============================================================

typedef struct {
  crabs_tree_node_t*   root;
  crabs_tree_node_t*   node_pool;  // Linked list of all nodes for iteration
  uint32_t             node_count;
  uint32_t             visible_count;
  crabs_ot_data_item_t* ot_data;
} crabs_ot_tree_t;

// ============================================================
// Tree Node Lifecycle
// ============================================================

crabs_tree_node_t* crabs_tree_node_create(const char* id, const char* parent_id,
                                            const uint8_t* value, uint32_t value_size);
void crabs_tree_node_destroy(crabs_tree_node_t* node);

// ============================================================
// Tree Lifecycle
// ============================================================

crabs_ot_tree_t* crabs_ot_tree_create(void);
void crabs_ot_tree_destroy(crabs_ot_tree_t* tree);
uint32_t crabs_ot_tree_node_count(const crabs_ot_tree_t* tree);
uint32_t crabs_ot_tree_visible_count(const crabs_ot_tree_t* tree);

// ============================================================
// Tree Operations (v1.5 §7.2)
// ============================================================

crabs_tree_node_t* crabs_ot_tree_insert_node(
  crabs_ot_tree_t* tree, const char* parent_id, uint64_t pos,
  const char* node_id, const uint8_t* value, uint32_t value_size);

crabs_tree_node_t* crabs_ot_tree_delete_node(
  crabs_ot_tree_t* tree, const char* node_id);

crabs_tree_node_t* crabs_ot_tree_reparent(
  crabs_ot_tree_t* tree, const char* node_id,
  const char* new_parent_id, uint64_t new_pos);

crabs_tree_node_t* crabs_ot_tree_reorder(
  crabs_ot_tree_t* tree, const char* node_id, uint64_t new_pos);

// ============================================================
// Tree Access
// ============================================================

crabs_tree_node_t* crabs_ot_tree_find(
  const crabs_ot_tree_t* tree, const char* node_id);
crabs_tree_node_t* crabs_ot_tree_root(const crabs_ot_tree_t* tree);
uint32_t crabs_ot_tree_child_count(const crabs_tree_node_t* parent);

// ============================================================
// CRDT Merge (v1.5 §7.3)
// ============================================================

crabs_ot_tree_t* crabs_ot_tree_merge(
  crabs_ot_tree_t* dest, const crabs_ot_tree_t* src);

#endif // CRABS_OT_TREE_H