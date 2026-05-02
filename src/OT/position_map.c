//
// Created by victor on 5/1/25.
//
// Position Map BST & Coordinate Mapping (v1.5 §3.3, §12.1)
// Size-balanced BST (AVL tree) for OT/CRDT hybrid type position tracking.
//

#include "position_map.h"
#include "../Util/allocator.h"
#include <stdlib.h>
#include <string.h>

// ============================================================
// AVL Helper Functions
// ============================================================

static uint32_t _height(const crabs_bst_node_t* node) {
  return node ? node->height : 0;
}

static uint32_t _size(const crabs_bst_node_t* node) {
  return node ? node->size : 0;
}

static int64_t _balance_factor(const crabs_bst_node_t* node) {
  return node ? (int64_t)_height(node->left) - (int64_t)_height(node->right) : 0;
}

static void _update(crabs_bst_node_t* node) {
  if (node == NULL) return;
  node->height = 1 + (_height(node->left) > _height(node->right)
                           ? _height(node->left) : _height(node->right));
  node->size = 1 + _size(node->left) + _size(node->right);
}

// ============================================================
// AVL Rotations
// ============================================================

static crabs_bst_node_t* _rotate_right(crabs_bst_node_t* y) {
  crabs_bst_node_t* x = y->left;
  y->left = x->right;
  x->right = y;
  _update(y);
  _update(x);
  return x;
}

static crabs_bst_node_t* _rotate_left(crabs_bst_node_t* x) {
  crabs_bst_node_t* y = x->right;
  x->right = y->left;
  y->left = x;
  _update(x);
  _update(y);
  return y;
}

static crabs_bst_node_t* _rebalance(crabs_bst_node_t* node) {
  if (node == NULL) return NULL;
  _update(node);

  int64_t bf = _balance_factor(node);

  // Left-heavy
  if (bf > 1) {
    if (_balance_factor(node->left) < 0) {
      node->left = _rotate_left(node->left);
    }
    return _rotate_right(node);
  }

  // Right-heavy
  if (bf < -1) {
    if (_balance_factor(node->right) > 0) {
      node->right = _rotate_right(node->right);
    }
    return _rotate_left(node);
  }

  return node;
}

// ============================================================
// BST Lifecycle
// ============================================================

crabs_bst_node_t* crabs_bst_create(uint64_t value) {
  crabs_bst_node_t* node = get_clear_memory(sizeof(crabs_bst_node_t));
  if (node == NULL) return NULL;
  node->value = value;
  node->size = 1;
  node->height = 1;
  node->deleted = false;
  return node;
}

void crabs_bst_destroy(crabs_bst_node_t* root) {
  if (root == NULL) return;
  crabs_bst_destroy(root->left);
  crabs_bst_destroy(root->right);
  free(root);
}

// ============================================================
// BST Operations
// ============================================================

crabs_bst_node_t* crabs_bst_insert(crabs_bst_node_t* root, uint64_t value) {
  if (root == NULL) {
    return crabs_bst_create(value);
  }

  if (value < root->value) {
    root->left = crabs_bst_insert(root->left, value);
  } else if (value > root->value) {
    root->right = crabs_bst_insert(root->right, value);
  } else {
    // Value already exists; don't insert duplicate
    return root;
  }

  return _rebalance(root);
}

static crabs_bst_node_t* _min_value_node(crabs_bst_node_t* node) {
  crabs_bst_node_t* current = node;
  while (current && current->left != NULL) {
    current = current->left;
  }
  return current;
}

crabs_bst_node_t* crabs_bst_delete_node(crabs_bst_node_t* root, uint64_t value) {
  if (root == NULL) return NULL;

  if (value < root->value) {
    root->left = crabs_bst_delete_node(root->left, value);
  } else if (value > root->value) {
    root->right = crabs_bst_delete_node(root->right, value);
  } else {
    // Node found
    if (root->left == NULL) {
      crabs_bst_node_t* temp = root->right;
      free(root);
      return temp;
    } else if (root->right == NULL) {
      crabs_bst_node_t* temp = root->left;
      free(root);
      return temp;
    }

    // Two children: get inorder successor
    crabs_bst_node_t* successor = _min_value_node(root->right);
    root->value = successor->value;
    root->deleted = successor->deleted;
    root->right = crabs_bst_delete_node(root->right, successor->value);
  }

  return _rebalance(root);
}

crabs_bst_node_t* crabs_bst_find(const crabs_bst_node_t* root, uint64_t value) {
  if (root == NULL) return NULL;
  if (value == root->value) return (crabs_bst_node_t*)root;
  if (value < root->value) return crabs_bst_find(root->left, value);
  return crabs_bst_find(root->right, value);
}

uint32_t crabs_bst_size(const crabs_bst_node_t* root) {
  return _size(root);
}

bool crabs_bst_contains(const crabs_bst_node_t* root, uint64_t value) {
  return crabs_bst_find(root, value) != NULL;
}

void crabs_bst_mark_deleted(crabs_bst_node_t* root, uint64_t value) {
  crabs_bst_node_t* node = crabs_bst_find(root, value);
  if (node != NULL) {
    node->deleted = true;
  }
}

// ============================================================
// Coordinate Mapping (v1.5 §12.1)
// ============================================================

uint64_t crabs_xi(const crabs_bst_node_t* tree, uint64_t internal_pos) {
  // Count deletions at or before internal_pos, subtract from internal_pos
  uint64_t offset = 0;
  while (tree != NULL) {
    if (internal_pos < tree->value) {
      tree = tree->left;
    } else {
      offset += 1 + _size(tree->left);
      tree = tree->right;
    }
  }
  return internal_pos - offset;
}

uint64_t crabs_xi_inv(const crabs_bst_node_t* tree, uint64_t visible_pos) {
  // Fixed-point: internal_pos = visible_pos + count_deletions_at_or_before(internal_pos)
  uint64_t internal_pos = visible_pos;
  while (true) {
    uint64_t count = 0;
    const crabs_bst_node_t* node = tree;
    while (node != NULL) {
      if (internal_pos < node->value) {
        node = node->left;
      } else {
        count += 1 + _size(node->left);
        node = node->right;
      }
    }
    uint64_t new_pos = visible_pos + count;
    if (new_pos == internal_pos) break;
    internal_pos = new_pos;
  }
  return internal_pos;
}

// ============================================================
// union_one: mark position as deleted, insert if needed
// ============================================================

crabs_bst_node_t* crabs_union_one(crabs_bst_node_t* root, uint64_t internal_pos) {
  crabs_bst_node_t* existing = crabs_bst_find(root, internal_pos);
  if (existing != NULL) {
    // Already in tree, just mark deleted
    existing->deleted = true;
    return root;
  }
  // Insert and mark deleted
  root = crabs_bst_insert(root, internal_pos);
  crabs_bst_mark_deleted(root, internal_pos);
  return root;
}

// ============================================================
// xi_one: shift all positions >= internal_pos by +1
// ============================================================

// Helper: recursively shift values >= threshold by +1
static void _shift_values(crabs_bst_node_t* root, uint64_t threshold) {
  if (root == NULL) return;
  if (root->value >= threshold) {
    root->value += 1;
    // All right children are >= root->value (now shifted), need to shift them too
    // Left children < root->value, but some might be >= threshold
  }
  // Always recurse both sides since values might be distributed
  _shift_values(root->left, threshold);
  _shift_values(root->right, threshold);
}

crabs_bst_node_t* crabs_xi_one(crabs_bst_node_t* root, uint64_t internal_pos) {
  // Shift all node values >= internal_pos by +1
  _shift_values(root, internal_pos);
  return root;
}

// ============================================================
// BST Merge
// ============================================================

// In-order traversal to collect deleted entries from source
static crabs_bst_node_t* _merge_deleted(crabs_bst_node_t* dest, const crabs_bst_node_t* src) {
  if (src == NULL) return dest;
  dest = _merge_deleted(dest, src->left);
  if (src->deleted) {
    dest = crabs_union_one(dest, src->value);
  }
  dest = _merge_deleted(dest, src->right);
  return dest;
}

crabs_bst_node_t* crabs_bst_merge(crabs_bst_node_t* dest, const crabs_bst_node_t* src) {
  if (src == NULL) return dest;
  return _merge_deleted(dest, src);
}