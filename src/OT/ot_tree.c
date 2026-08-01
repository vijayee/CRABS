//
// Created by victor on 5/1/25.
//
// OT_TREE Data Type (v1.5 §7)
// Tree-structured data with per-parent position maps.
// Type ID: 0x13
//

#include "ot_tree.h"
#include "ot_transform.h"
#include "../Util/allocator.h"
#include <stdlib.h>
#include <string.h>

// Audit M-J: comparator for qsort over tree-node pointers by id. Used to
// make the merge cycle-break commutative (process nodes in id order).
static int _node_id_cmp(const void* x, const void* y) {
  const crabs_tree_node_t* const* a = (const crabs_tree_node_t* const*)x;
  const crabs_tree_node_t* const* b = (const crabs_tree_node_t* const*)y;
  return strcmp((*a)->id, (*b)->id);
}

// ============================================================
// Tree Node Lifecycle
// ============================================================

crabs_tree_node_t* crabs_tree_node_create(const char* id, const char* parent_id,
                                             const uint8_t* value, uint32_t value_size) {
  crabs_tree_node_t* node = get_clear_memory(sizeof(crabs_tree_node_t));
  if (id != NULL) {
    strncpy(node->id, id, CRABS_TREE_NODE_ID_MAX - 1);
    node->id[CRABS_TREE_NODE_ID_MAX - 1] = '\0';
  }
  if (parent_id != NULL) {
    strncpy(node->parent_id, parent_id, CRABS_TREE_NODE_ID_MAX - 1);
    node->parent_id[CRABS_TREE_NODE_ID_MAX - 1] = '\0';
  }
  if (value != NULL && value_size > 0) {
    node->value = get_memory(value_size);
    memcpy(node->value, value, value_size);
    node->value_size = value_size;
  }
  return node;
}

void crabs_tree_node_destroy(crabs_tree_node_t* node) {
  if (node == NULL) return;
  if (node->value != NULL) {
    free(node->value);
  }
  if (node->child_position_map != NULL) {
    crabs_bst_destroy(node->child_position_map);
  }
  free(node);
}

// ============================================================
// Tree Lifecycle
// ============================================================

crabs_ot_tree_t* crabs_ot_tree_create(void) {
  crabs_ot_tree_t* tree = get_clear_memory(sizeof(crabs_ot_tree_t));
  tree->ot_data = crabs_ot_data_item_create(CRABS_OT_TREE);
  crabs_transform_matrix_init(tree->ot_data);
  return tree;
}

void crabs_ot_tree_destroy(crabs_ot_tree_t* tree) {
  if (tree == NULL) return;
  crabs_tree_node_t* node = tree->node_pool;
  while (node != NULL) {
    crabs_tree_node_t* next = node->pool_next;
    crabs_tree_node_destroy(node);
    node = next;
  }
  crabs_ot_data_item_destroy(tree->ot_data);
  free(tree);
}

uint32_t crabs_ot_tree_node_count(const crabs_ot_tree_t* tree) {
  return tree == NULL ? 0 : tree->node_count;
}

uint32_t crabs_ot_tree_visible_count(const crabs_ot_tree_t* tree) {
  return tree == NULL ? 0 : tree->visible_count;
}

// ============================================================
// Helpers
// ============================================================

// Add node to the pool linked list
static void _add_to_pool(crabs_ot_tree_t* tree, crabs_tree_node_t* node) {
  node->pool_next = tree->node_pool;
  tree->node_pool = node;
  tree->node_count++;
  if (!node->deleted) tree->visible_count++;
}

// Find child by visible position (skip deleted)
static crabs_tree_node_t* _get_child_at_visible(crabs_tree_node_t* parent, uint64_t visible_pos) {
  if (parent == NULL) return NULL;
  uint64_t idx = 0;
  for (crabs_tree_node_t* c = parent->first_child; c != NULL; c = c->next_sibling) {
    if (c->deleted) continue;
    if (idx == visible_pos) return c;
    idx++;
  }
  return NULL;
}

// Link child as last child of parent
static void _link_child_last(crabs_tree_node_t* parent, crabs_tree_node_t* child) {
  child->parent = parent;
  child->next_sibling = NULL;
  child->prev_sibling = NULL;

  if (parent->first_child == NULL) {
    parent->first_child = child;
  } else {
    crabs_tree_node_t* last = parent->first_child;
    while (last->next_sibling != NULL) {
      last = last->next_sibling;
    }
    last->next_sibling = child;
    child->prev_sibling = last;
  }
}

// Unlink child from parent's child list (doesn't free)
static void _unlink_child(crabs_ot_tree_t* tree, crabs_tree_node_t* child) {
  if (child->prev_sibling != NULL) {
    child->prev_sibling->next_sibling = child->next_sibling;
  } else if (child->parent != NULL) {
    child->parent->first_child = child->next_sibling;
  } else if (tree != NULL && child == tree->root) {
    // Unlinking the root node
    tree->root = child->next_sibling;
    if (tree->root != NULL) {
      tree->root->prev_sibling = NULL;
    }
  }
  if (child->next_sibling != NULL) {
    child->next_sibling->prev_sibling = child->prev_sibling;
  }
  child->prev_sibling = NULL;
  child->next_sibling = NULL;
  child->parent = NULL;
}

// Count visible children
static uint32_t _visible_child_count(crabs_tree_node_t* parent) {
  uint32_t count = 0;
  if (parent == NULL) return 0;
  for (crabs_tree_node_t* c = parent->first_child; c != NULL; c = c->next_sibling) {
    if (!c->deleted) count++;
  }
  return count;
}

// ============================================================
// Tree Operations (v1.5 §7.2)
// ============================================================

crabs_tree_node_t* crabs_ot_tree_insert_node(
    crabs_ot_tree_t* tree, const char* parent_id, uint64_t pos,
    const char* node_id, const uint8_t* value, uint32_t value_size) {
  if (tree == NULL || node_id == NULL) return NULL;

  crabs_tree_node_t* node = crabs_tree_node_create(node_id, parent_id, value, value_size);
  if (node == NULL) return NULL;

  crabs_tree_node_t* parent = NULL;
  if (parent_id != NULL && parent_id[0] != '\0') {
    parent = crabs_ot_tree_find(tree, parent_id);
    if (parent == NULL) {
      // Parent not found — cannot insert
      crabs_tree_node_destroy(node);
      return NULL;
    }
  }

  if (parent != NULL) {
    strncpy(node->parent_id, parent_id, CRABS_TREE_NODE_ID_MAX - 1);
    node->parent_id[CRABS_TREE_NODE_ID_MAX - 1] = '\0';
    node->parent = parent;

    // Use position map for child ordering if available
    if (parent->child_position_map != NULL) {
      uint64_t internal_pos = crabs_xi_inv(parent->child_position_map, pos);
      if (internal_pos == 0 || parent->first_child == NULL) {
        node->next_sibling = parent->first_child;
        if (parent->first_child != NULL) parent->first_child->prev_sibling = node;
        parent->first_child = node;
      } else {
        uint64_t idx = 0;
        crabs_tree_node_t* at = NULL;
        for (crabs_tree_node_t* c = parent->first_child; c != NULL; c = c->next_sibling) {
          if (idx == internal_pos - 1) { at = c; break; }
          idx++;
        }
        if (at != NULL) {
          node->prev_sibling = at;
          node->next_sibling = at->next_sibling;
          if (at->next_sibling) at->next_sibling->prev_sibling = node;
          at->next_sibling = node;
        } else {
          _link_child_last(parent, node);
        }
      }
      parent->child_position_map = crabs_xi_one(parent->child_position_map, internal_pos);
    } else {
      // No position map: insert at visible position
      if (pos == 0 || parent->first_child == NULL) {
        node->next_sibling = parent->first_child;
        if (parent->first_child != NULL) parent->first_child->prev_sibling = node;
        parent->first_child = node;
      } else {
        crabs_tree_node_t* after = _get_child_at_visible(parent, pos - 1);
        if (after != NULL) {
          node->prev_sibling = after;
          node->next_sibling = after->next_sibling;
          if (after->next_sibling) after->next_sibling->prev_sibling = node;
          after->next_sibling = node;
        } else {
          _link_child_last(parent, node);
        }
      }
    }
  } else {
    // No parent — this is a root node
    if (tree->root == NULL) {
      tree->root = node;
    } else {
      // Multiple roots: add as sibling of current root
      crabs_tree_node_t* last = tree->root;
      while (last->next_sibling != NULL) {
        last = last->next_sibling;
      }
      last->next_sibling = node;
      node->prev_sibling = last;
    }
  }

  _add_to_pool(tree, node);
  return node;
}

// Helper: mark a subtree as deleted using an explicit worklist (iterative)
// to avoid unbounded recursion on a deep or attacker-shaped tree.
static void _mark_subtree_deleted(crabs_ot_tree_t* tree, crabs_tree_node_t* node) {
  if (node == NULL || node->deleted) return;
  crabs_tree_node_t** stack = NULL;
  uint32_t cap = 0;
  uint32_t top = 0;

  // Push the root of the subtree.
  stack = (crabs_tree_node_t**)realloc(stack, sizeof(crabs_tree_node_t*) * 16);
  if (stack == NULL) return;
  cap = 16;
  stack[top++] = node;

  while (top > 0) {
    crabs_tree_node_t* n = stack[--top];
    if (n == NULL || n->deleted) continue;
    n->deleted = true;
    tree->visible_count--;
    for (crabs_tree_node_t* c = n->first_child; c != NULL; c = c->next_sibling) {
      if (top == cap) {
        uint32_t new_cap = cap * 2;
        crabs_tree_node_t** ns = (crabs_tree_node_t**)realloc(stack, sizeof(crabs_tree_node_t*) * new_cap);
        if (ns == NULL) { free(stack); return; }
        stack = ns;
        cap = new_cap;
      }
      stack[top++] = c;
    }
  }
  free(stack);
}

crabs_tree_node_t* crabs_ot_tree_delete_node(
    crabs_ot_tree_t* tree, const char* node_id) {
  if (tree == NULL || node_id == NULL) return NULL;

  crabs_tree_node_t* node = crabs_ot_tree_find(tree, node_id);
  if (node == NULL) return NULL;
  if (node->deleted) return node;

  // Mark all descendants as deleted
  for (crabs_tree_node_t* c = node->first_child; c != NULL; c = c->next_sibling) {
    _mark_subtree_deleted(tree, c);
  }

  node->deleted = true;
  tree->visible_count--;

  // Update parent's position map
  if (node->parent != NULL && node->parent->child_position_map != NULL) {
    uint64_t child_pos = 0;
    for (crabs_tree_node_t* c = node->parent->first_child; c != NULL; c = c->next_sibling) {
      if (c == node) break;
      child_pos++;
    }
    node->parent->child_position_map = crabs_union_one(
      node->parent->child_position_map, child_pos);
  }

  return node;
}

crabs_tree_node_t* crabs_ot_tree_reparent(
    crabs_ot_tree_t* tree, const char* node_id,
    const char* new_parent_id, uint64_t new_pos) {
  if (tree == NULL || node_id == NULL) return NULL;

  crabs_tree_node_t* node = crabs_ot_tree_find(tree, node_id);
  if (node == NULL) return NULL;

  crabs_tree_node_t* new_parent = NULL;
  if (new_parent_id != NULL && new_parent_id[0] != '\0') {
    new_parent = crabs_ot_tree_find(tree, new_parent_id);
  }

  // Reject cycles: new_parent must not be `node` itself or one of its
  // descendants. Allowing self/descendant parenting creates a cycle that
  // makes every sibling-walking or subtree routine spin forever or overflow
  // the stack.
  if (new_parent != NULL) {
    if (new_parent == node) return NULL;
    // Walk ancestors of new_parent; if we reach `node`, it's a descendant.
    // Audit M-J: bound the walk by node_count — a merge-created parent
    // cycle (e.g. concurrent X→Y and Y→X) would otherwise spin forever.
    uint32_t steps = 0;
    crabs_tree_node_t* p = new_parent->parent;
    while (p != NULL && steps <= tree->node_count) {
      if (p == node) return NULL;
      p = p->parent;
      steps++;
    }
    if (p != NULL) return NULL; // cycle detected — refuse to reparent
  }

  // Unlink from current parent
  _unlink_child(tree, node);

  // Update parent reference
  if (new_parent != NULL) {
    strncpy(node->parent_id, new_parent_id, CRABS_TREE_NODE_ID_MAX - 1);
    node->parent_id[CRABS_TREE_NODE_ID_MAX - 1] = '\0';
  } else {
    node->parent_id[0] = '\0';
  }
  node->parent = new_parent;

  // Insert at new position
  if (new_parent != NULL) {
    if (new_pos == 0 || new_parent->first_child == NULL) {
      node->next_sibling = new_parent->first_child;
      if (new_parent->first_child) new_parent->first_child->prev_sibling = node;
      new_parent->first_child = node;
    } else {
      crabs_tree_node_t* after = _get_child_at_visible(new_parent, new_pos - 1);
      if (after != NULL) {
        node->prev_sibling = after;
        node->next_sibling = after->next_sibling;
        if (after->next_sibling) after->next_sibling->prev_sibling = node;
        after->next_sibling = node;
      } else {
        _link_child_last(new_parent, node);
      }
    }
  } else {
    // Becomes root
    if (tree->root == NULL) {
      tree->root = node;
    } else {
      crabs_tree_node_t* last = tree->root;
      while (last->next_sibling != NULL) last = last->next_sibling;
      last->next_sibling = node;
      node->prev_sibling = last;
    }
  }

  return node;
}

crabs_tree_node_t* crabs_ot_tree_reorder(
    crabs_ot_tree_t* tree, const char* node_id, uint64_t new_pos) {
  if (tree == NULL || node_id == NULL) return NULL;

  crabs_tree_node_t* node = crabs_ot_tree_find(tree, node_id);
  if (node == NULL) return NULL;
  if (node->parent == NULL) return NULL;

  crabs_tree_node_t* parent = node->parent;

  // Get old visible position among siblings
  uint64_t old_pos = 0;
  for (crabs_tree_node_t* c = parent->first_child; c != NULL; c = c->next_sibling) {
    if (c == node) break;
    if (!c->deleted) old_pos++;
  }

  if (old_pos == new_pos) return node;

  // Unlink from current position
  _unlink_child(tree, node);

  // Re-insert at new position
  if (new_pos == 0 || parent->first_child == NULL) {
    node->next_sibling = parent->first_child;
    if (parent->first_child) parent->first_child->prev_sibling = node;
    parent->first_child = node;
  } else {
    crabs_tree_node_t* after = _get_child_at_visible(parent, new_pos - 1);
    if (after != NULL) {
      node->prev_sibling = after;
      node->next_sibling = after->next_sibling;
      if (after->next_sibling) after->next_sibling->prev_sibling = node;
      after->next_sibling = node;
    } else {
      _link_child_last(parent, node);
    }
  }
  node->parent = parent;

  return node;
}

// ============================================================
// Tree Access
// ============================================================

crabs_tree_node_t* crabs_ot_tree_find(
    const crabs_ot_tree_t* tree, const char* node_id) {
  if (tree == NULL || node_id == NULL) return NULL;
  for (crabs_tree_node_t* n = tree->node_pool; n != NULL; n = n->pool_next) {
    if (strcmp(n->id, node_id) == 0) return n;
  }
  return NULL;
}

crabs_tree_node_t* crabs_ot_tree_root(const crabs_ot_tree_t* tree) {
  return tree == NULL ? NULL : tree->root;
}

uint32_t crabs_ot_tree_child_count(const crabs_tree_node_t* parent) {
  return _visible_child_count((crabs_tree_node_t*)parent);
}

// ============================================================
// CRDT Merge (v1.5 §7.3)
// ============================================================

// Helper: rebuild parent/child links from parent_id fields
static void _rebuild_links(crabs_ot_tree_t* tree) {
  // Clear all child links
  for (crabs_tree_node_t* n = tree->node_pool; n != NULL; n = n->pool_next) {
    n->first_child = NULL;
    n->parent = NULL;
    n->prev_sibling = NULL;
    n->next_sibling = NULL;
  }

  // Reset root
  tree->root = NULL;

  // Re-establish parent/child links
  for (crabs_tree_node_t* n = tree->node_pool; n != NULL; n = n->pool_next) {
    if (n->deleted) continue;

    if (n->parent_id[0] == '\0') {
      // Root node
      if (tree->root == NULL) {
        tree->root = n;
      } else {
        // Multiple roots — add as sibling
        crabs_tree_node_t* last = tree->root;
        while (last->next_sibling != NULL) last = last->next_sibling;
        last->next_sibling = n;
        n->prev_sibling = last;
      }
      continue;
    }

    crabs_tree_node_t* parent = crabs_ot_tree_find(tree, n->parent_id);
    if (parent != NULL) {
      n->parent = parent;
      // Append as last child
      if (parent->first_child == NULL) {
        parent->first_child = n;
      } else {
        crabs_tree_node_t* last = parent->first_child;
        while (last->next_sibling != NULL) last = last->next_sibling;
        last->next_sibling = n;
        n->prev_sibling = last;
      }
    } else {
      // Parent not found yet — treat as root
      if (tree->root == NULL) {
        tree->root = n;
      } else {
        crabs_tree_node_t* last = tree->root;
        while (last->next_sibling != NULL) last = last->next_sibling;
        last->next_sibling = n;
        n->prev_sibling = last;
      }
    }
  }

  // Audit M-J: concurrent reparents merged here can create parent cycles
  // (e.g. dest has X→Y, src has Y→X). Break every cycle so downstream ancestor
  // walks don't spin. To be COMMUTATIVE across merge(A,B) vs merge(B,A),
  // process nodes in id-sorted order and, for each cycle encountered,
  // detach the edge from the cycle's lexicographically-largest-id node.
  // Both replicas see the same node set and the same max-id, so they break
  // the same edge and converge.
  if (tree->node_count > 0) {
    // Collect the pool into an array.
    crabs_tree_node_t** arr = (crabs_tree_node_t**)get_clear_memory(
        sizeof(crabs_tree_node_t*) * tree->node_count);
    if (arr != NULL) {
      uint32_t cnt = 0;
      for (crabs_tree_node_t* n = tree->node_pool; n != NULL && cnt < tree->node_count; n = n->pool_next) {
        arr[cnt++] = n;
      }
      // Sort by id (strcmp). qsort is not stable, but the cycle-break only
      // depends on the order being a deterministic total order, which strcmp
      // provides (ids are unique — enforced at deserialize and at insert).
      // Comparator uses a thread-safe-ish static; ids are unique so ties don't
      // occur.
      qsort(arr, cnt, sizeof(crabs_tree_node_t*), _node_id_cmp);

      // Heap-allocated scratch chain for cycle detection, sized to the node
      // count (de-wonk: a fixed 256-entry stack trail could miss cycles in
      // larger trees).
      crabs_tree_node_t** trail = (crabs_tree_node_t**)get_clear_memory(
          sizeof(crabs_tree_node_t*) * (cnt > 0 ? cnt : 1));
      if (trail != NULL) {
        for (uint32_t i = 0; i < cnt; i++) {
          crabs_tree_node_t* n = arr[i];
          // Walk n's parent chain collecting into the trail; detect a repeat
          // (cycle). Bounded by cnt+1.
          uint32_t tlen = 0;
          crabs_tree_node_t* p = n->parent;
          bool cycle_found = false;
          uint32_t cycle_start = 0;
          while (p != NULL && tlen <= cnt) {
            for (uint32_t j = 0; j < tlen; j++) {
              if (trail[j] == p) {
                cycle_found = true;
                cycle_start = j;
                break;
              }
            }
            if (cycle_found) break;
            trail[tlen++] = p;
            p = p->parent;
          }
          if (cycle_found) {
            // The cycle is trail[cycle_start .. tlen-1]. Find the max-id node
            // in it and detach its parent edge (commutative: both replicas
            // pick the same max-id).
            crabs_tree_node_t* max_node = trail[cycle_start];
            for (uint32_t j = cycle_start + 1; j < tlen; j++) {
              if (strcmp(trail[j]->id, max_node->id) > 0) max_node = trail[j];
            }
            if (max_node->parent != NULL) {
              _unlink_child(tree, max_node);
              max_node->parent = NULL;
              max_node->parent_id[0] = '\0';
            }
          }
        }
        free(trail);
      }
      free(arr);
    }
  }
}

crabs_ot_tree_t* crabs_ot_tree_merge(
    crabs_ot_tree_t* dest, const crabs_ot_tree_t* src) {
  if (dest == NULL || src == NULL) return dest;

  // Merge position maps
  if (dest->ot_data != NULL && src->ot_data != NULL) {
    dest->ot_data->position_map = crabs_bst_merge(
      dest->ot_data->position_map, src->ot_data->position_map);
  }

  // Merge nodes: add nodes from src that don't exist in dest
  for (crabs_tree_node_t* n = src->node_pool; n != NULL; n = n->pool_next) {
    crabs_tree_node_t* found = crabs_ot_tree_find(dest, n->id);
    if (found == NULL) {
      // New node — add to dest
      crabs_tree_node_t* new_node = crabs_tree_node_create(
        n->id, n->parent_id, n->value, n->value_size);
      new_node->deleted = n->deleted;
      // Copy child position map
      if (n->child_position_map != NULL) {
        new_node->child_position_map = crabs_bst_copy(n->child_position_map);
      }
      _add_to_pool(dest, new_node);
    } else {
      // Existing node — merge deletion state (deleted wins)
      if (n->deleted && !found->deleted) {
        found->deleted = true;
        dest->visible_count--;
      }
      // Merge child position maps
      if (n->child_position_map != NULL) {
        if (found->child_position_map == NULL) {
          found->child_position_map = crabs_bst_copy(n->child_position_map);
        } else {
          found->child_position_map = crabs_bst_merge(
            found->child_position_map, n->child_position_map);
        }
      }
    }
  }

  // Rebuild parent/child links
  _rebuild_links(dest);

  // Audit F-3: propagate deletion downward. When a node is marked deleted on
  // merge, all of its descendants must also be deleted; otherwise compaction
  // (crabs_extract_visible_tree) drops live children of a deleted parent
  // (silent data loss). Iterate to a fixpoint: any node whose parent is
  // deleted becomes deleted.
  bool changed = true;
  while (changed) {
    changed = false;
    for (crabs_tree_node_t* n = dest->node_pool; n != NULL; n = n->pool_next) {
      if (!n->deleted && n->parent != NULL && n->parent->deleted) {
        n->deleted = true;
        if (dest->visible_count > 0) dest->visible_count--;
        changed = true;
      }
    }
  }

  return dest;
}