//
// Created by victor on 5/1/25.
//
// Position Map BST & Coordinate Mapping (v1.5 §3.3, §12.1)
// Size-balanced BST (AVL tree) for OT/CRDT hybrid type position tracking.
//

#ifndef CRABS_POSITION_MAP_H
#define CRABS_POSITION_MAP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ============================================================
// BST Node (v1.5 §12.1)
// ============================================================
typedef struct crabs_bst_node {
  struct crabs_bst_node* left;
  struct crabs_bst_node* right;
  uint64_t value;       // Internal position
  uint32_t size;        // Subtree node count
  uint32_t height;      // For AVL balancing
  bool deleted;         // Whether this position is deleted
} crabs_bst_node_t;

// ============================================================
// BST Lifecycle
// ============================================================
crabs_bst_node_t* crabs_bst_create(uint64_t value);
void              crabs_bst_destroy(crabs_bst_node_t* root);

// ============================================================
// BST Operations
// ============================================================
crabs_bst_node_t* crabs_bst_insert(crabs_bst_node_t* root, uint64_t value);
crabs_bst_node_t* crabs_bst_delete_node(crabs_bst_node_t* root, uint64_t value);
crabs_bst_node_t* crabs_bst_find(const crabs_bst_node_t* root, uint64_t value);
uint32_t          crabs_bst_size(const crabs_bst_node_t* root);
bool              crabs_bst_contains(const crabs_bst_node_t* root, uint64_t value);
void              crabs_bst_mark_deleted(crabs_bst_node_t* root, uint64_t value);

// ============================================================
// Coordinate Mapping (v1.5 §3.3, §12.1)
// ============================================================

// xi: internal position -> visible position
uint64_t crabs_xi(const crabs_bst_node_t* tree, uint64_t internal_pos);

// xi_inv: visible position -> internal position
uint64_t crabs_xi_inv(const crabs_bst_node_t* tree, uint64_t visible_pos);

// union_one: mark an internal position as deleted, insert if not present
crabs_bst_node_t* crabs_union_one(crabs_bst_node_t* root, uint64_t internal_pos);

// xi_one: shift all positions >= internal_pos by +1 (for insert)
crabs_bst_node_t* crabs_xi_one(crabs_bst_node_t* root, uint64_t internal_pos);

// ============================================================
// BST Merge
// ============================================================

// Merge two position maps: copy deleted entries from source into dest
crabs_bst_node_t* crabs_bst_merge(crabs_bst_node_t* dest, const crabs_bst_node_t* src);

#endif // CRABS_POSITION_MAP_H