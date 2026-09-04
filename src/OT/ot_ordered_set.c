//
// Created by victor on 5/1/25.
//
// OT_ORDERED_SET Data Type (v1.5 §5)
// Implementation of ordered list with OT/CRDT hybrid conflict resolution.
//

#include "ot_ordered_set.h"
#include "../Util/allocator.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
  crabs_ot_op_id_t id;
  bool has_anchor;
  crabs_ot_op_id_t anchor_id;
  crabs_ot_op_id_t placement_id;
} crabs_ordered_placement_t;

static int _op_id_compare(const crabs_ot_op_id_t* a,
                          const crabs_ot_op_id_t* b) {
  int node = memcmp(a->node_id, b->node_id, CRABS_MAX_USER_ID);
  if (node != 0) return node < 0 ? -1 : 1;
  if (a->sequence_num < b->sequence_num) return -1;
  if (a->sequence_num > b->sequence_num) return 1;
  return 0;
}

static void _set_placement(crabs_ordered_element_t* elem,
                           const crabs_ordered_element_t* anchor,
                           const crabs_ot_op_id_t* placement_id) {
  elem->has_anchor = anchor != NULL;
  if (anchor != NULL) elem->anchor_id = anchor->id;
  else memset(&elem->anchor_id, 0, sizeof(elem->anchor_id));
  elem->placement_id = *placement_id;
}

// ============================================================
// Element Lifecycle
// ============================================================

crabs_ordered_element_t* crabs_ordered_element_create(
    const crabs_ot_op_id_t* id, const uint8_t* value, uint32_t value_size) {
  crabs_ordered_element_t* elem = get_clear_memory(sizeof(crabs_ordered_element_t));
  if (id != NULL) {
    elem->id = *id;
    elem->placement_id = *id;
  }
  if (value != NULL && value_size > 0) {
    elem->value = get_memory(value_size);
    memcpy(elem->value, value, value_size);
    elem->value_size = value_size;
  }
  return elem;
}

void crabs_ordered_element_destroy(crabs_ordered_element_t* elem) {
  if (elem == NULL) return;
  if (elem->value != NULL) {
    free(elem->value);
  }
  free(elem);
}

// ============================================================
// Ordered Set Lifecycle
// ============================================================

crabs_ot_ordered_set_t* crabs_ot_ordered_set_create(void) {
  crabs_ot_ordered_set_t* set = get_clear_memory(sizeof(crabs_ot_ordered_set_t));
  set->ot_data = crabs_ot_data_item_create(CRABS_OT_ORDERED_SET);
  crabs_transform_matrix_init(set->ot_data);
  return set;
}

void crabs_ot_ordered_set_destroy(crabs_ot_ordered_set_t* set) {
  if (set == NULL) return;
  crabs_ordered_element_t* elem = set->head;
  while (elem != NULL) {
    crabs_ordered_element_t* next = elem->next;
    crabs_ordered_element_destroy(elem);
    elem = next;
  }
  crabs_ot_data_item_destroy(set->ot_data);
  free(set);
}

uint32_t crabs_ot_ordered_set_count(const crabs_ot_ordered_set_t* set) {
  return set == NULL ? 0 : set->count;
}

uint32_t crabs_ot_ordered_set_visible_count(const crabs_ot_ordered_set_t* set) {
  return set == NULL ? 0 : set->visible_count;
}

// ============================================================
// Ordered Set Access
// ============================================================

crabs_ordered_element_t* crabs_ot_ordered_set_get(
    const crabs_ot_ordered_set_t* set, uint64_t visible_pos) {
  if (set == NULL) return NULL;
  uint64_t idx = 0;
  for (crabs_ordered_element_t* e = set->head; e != NULL; e = e->next) {
    if (e->deleted) continue;
    if (idx == visible_pos) return e;
    idx++;
  }
  return NULL;
}

crabs_ordered_element_t* crabs_ot_ordered_set_find(
    const crabs_ot_ordered_set_t* set, const crabs_ot_op_id_t* id) {
  if (set == NULL || id == NULL) return NULL;
  for (crabs_ordered_element_t* e = set->head; e != NULL; e = e->next) {
    if (crabs_ot_op_id_equal(&e->id, id)) return e;
  }
  return NULL;
}

crabs_ordered_element_t* crabs_ot_ordered_set_head(
    const crabs_ot_ordered_set_t* set) {
  return set == NULL ? NULL : set->head;
}

crabs_ordered_element_t* crabs_ot_ordered_set_tail(
    const crabs_ot_ordered_set_t* set) {
  return set == NULL ? NULL : set->tail;
}

// Helper: get element at internal position (including deleted)
static crabs_ordered_element_t* _get_at_internal(
    const crabs_ot_ordered_set_t* set, uint64_t internal_pos) {
  if (set == NULL) return NULL;
  uint64_t idx = 0;
  for (crabs_ordered_element_t* e = set->head; e != NULL; e = e->next) {
    if (idx == internal_pos) return e;
    idx++;
  }
  return NULL;
}

// Helper: insert element after a specific element
static void _insert_after(crabs_ot_ordered_set_t* set,
                          crabs_ordered_element_t* after,
                          crabs_ordered_element_t* elem) {
  if (after == NULL) {
    // Insert at head
    elem->next = set->head;
    if (set->head != NULL) set->head->prev = elem;
    set->head = elem;
    if (set->tail == NULL) set->tail = elem;
  } else {
    elem->prev = after;
    elem->next = after->next;
    if (after->next != NULL) after->next->prev = elem;
    after->next = elem;
    if (after == set->tail) set->tail = elem;
  }
  set->count++;
  if (!elem->deleted) set->visible_count++;
}

// Helper: unlink element (doesn't free)
static int _placement_index(const crabs_ordered_placement_t* placements,
                            uint32_t count, const crabs_ot_op_id_t* id) {
  for (uint32_t i = 0; i < count; i++) {
    if (crabs_ot_op_id_equal(&placements[i].id, id)) return (int)i;
  }
  return -1;
}

static bool _placements_valid(const crabs_ordered_placement_t* placements,
                              uint32_t count) {
  if (count == 0) return true;
  uint32_t* visits = get_clear_memory(count * sizeof(uint32_t));
  for (uint32_t start = 0; start < count; start++) {
    int current = (int)start;
    while (placements[current].has_anchor) {
      if (visits[current] == start + 1) {
        free(visits);
        return false;
      }
      visits[current] = start + 1;
      current = _placement_index(placements, count,
                                 &placements[current].anchor_id);
      if (current < 0) {
        free(visits);
        return false;
      }
    }
  }
  free(visits);
  return true;
}

static bool _merge_preflight(const crabs_ot_ordered_set_t* dest,
                             const crabs_ot_ordered_set_t* src) {
  if (src->count > UINT32_MAX - dest->count) return false;
  uint32_t capacity = dest->count + src->count;
  if (capacity == 0) return true;
  crabs_ordered_placement_t* placements =
    get_clear_memory(capacity * sizeof(crabs_ordered_placement_t));
  uint32_t count = 0;

  for (const crabs_ordered_element_t* e = dest->head; e != NULL; e = e->next) {
    placements[count++] = (crabs_ordered_placement_t){
      .id = e->id,
      .has_anchor = e->has_anchor,
      .anchor_id = e->anchor_id,
      .placement_id = e->placement_id,
    };
  }

  for (const crabs_ordered_element_t* e = src->head; e != NULL; e = e->next) {
    int index = _placement_index(placements, count, &e->id);
    if (index >= 0) {
      const crabs_ordered_element_t* existing =
        crabs_ot_ordered_set_find(dest, &e->id);
      if (existing != NULL &&
          (existing->value_size != e->value_size ||
           (e->value_size > 0 &&
            memcmp(existing->value, e->value, e->value_size) != 0))) {
        free(placements);
        return false;
      }
      int placement_order = _op_id_compare(
        &e->placement_id, &placements[index].placement_id);
      if (placement_order == 0 &&
          (e->has_anchor != placements[index].has_anchor ||
           (e->has_anchor &&
            !crabs_ot_op_id_equal(&e->anchor_id,
                                  &placements[index].anchor_id)))) {
        free(placements);
        return false;
      }
      if (placement_order > 0) {
        placements[index].has_anchor = e->has_anchor;
        placements[index].anchor_id = e->anchor_id;
        placements[index].placement_id = e->placement_id;
      }
    } else {
      placements[count++] = (crabs_ordered_placement_t){
        .id = e->id,
        .has_anchor = e->has_anchor,
        .anchor_id = e->anchor_id,
        .placement_id = e->placement_id,
      };
    }
  }

  bool valid = _placements_valid(placements, count);
  free(placements);
  return valid;
}

static int _element_order_compare(const crabs_ordered_element_t* a,
                                  const crabs_ordered_element_t* b) {
  int placement = _op_id_compare(&a->placement_id, &b->placement_id);
  if (placement != 0) return placement;
  return _op_id_compare(&a->id, &b->id);
}

static int _next_child(crabs_ordered_element_t** nodes, uint32_t count,
                       const bool* emitted,
                       const crabs_ordered_element_t* parent) {
  int selected = -1;
  for (uint32_t i = 0; i < count; i++) {
    if (emitted[i]) continue;
    bool child = parent == NULL
      ? !nodes[i]->has_anchor
      : nodes[i]->has_anchor &&
        crabs_ot_op_id_equal(&nodes[i]->anchor_id, &parent->id);
    if (!child) continue;
    if (selected < 0 || _element_order_compare(nodes[i], nodes[selected]) > 0) {
      selected = (int)i;
    }
  }
  return selected;
}

static void _append_materialized(crabs_ot_ordered_set_t* set,
                                 crabs_ordered_element_t* elem) {
  elem->prev = set->tail;
  elem->next = NULL;
  if (set->tail != NULL) set->tail->next = elem;
  else set->head = elem;
  set->tail = elem;
  set->count++;
  if (!elem->deleted) set->visible_count++;
}

static bool _materialize(crabs_ot_ordered_set_t* set) {
  uint32_t count = set->count;
  if (count == 0) return true;
  crabs_ordered_element_t** nodes =
    get_memory(count * sizeof(crabs_ordered_element_t*));
  bool* emitted = get_clear_memory(count * sizeof(bool));
  int* stack = get_memory(count * sizeof(int));
  crabs_ordered_placement_t* placements =
    get_memory(count * sizeof(crabs_ordered_placement_t));

  uint32_t index = 0;
  for (crabs_ordered_element_t* e = set->head; e != NULL; e = e->next) {
    nodes[index] = e;
    placements[index] = (crabs_ordered_placement_t){
      .id = e->id,
      .has_anchor = e->has_anchor,
      .anchor_id = e->anchor_id,
      .placement_id = e->placement_id,
    };
    index++;
  }
  if (index != count || !_placements_valid(placements, count)) {
    free(placements); free(stack); free(emitted); free(nodes);
    return false;
  }

  set->head = NULL;
  set->tail = NULL;
  set->count = 0;
  set->visible_count = 0;
  uint32_t emitted_count = 0;

  while (emitted_count < count) {
    int root = _next_child(nodes, count, emitted, NULL);
    if (root < 0) break;
    int depth = 0;
    emitted[root] = true;
    emitted_count++;
    _append_materialized(set, nodes[root]);
    stack[depth++] = root;
    while (depth > 0) {
      int parent = stack[depth - 1];
      int child = _next_child(nodes, count, emitted, nodes[parent]);
      if (child < 0) {
        depth--;
        continue;
      }
      emitted[child] = true;
      emitted_count++;
      _append_materialized(set, nodes[child]);
      stack[depth++] = child;
    }
  }

  free(placements); free(stack); free(emitted); free(nodes);
  return emitted_count == count;
}

// ============================================================
// Apply Operations (v1.5 §5.2)
// ============================================================

crabs_ordered_element_t* crabs_ot_ordered_set_apply_insert(
    crabs_ot_ordered_set_t* set, const crabs_ot_operation_t* op) {
  if (set == NULL || op == NULL) return NULL;

  crabs_ordered_element_t* elem = crabs_ordered_element_create(
    &op->id, op->payload, op->payload_size);
  if (elem == NULL) return NULL;

  crabs_ordered_element_t* after = NULL;
  // Use position map to find insertion point
  if (set->ot_data != NULL && set->ot_data->position_map != NULL) {
    uint64_t internal_pos = crabs_xi_inv(set->ot_data->position_map, op->visible_pos);
    crabs_ordered_element_t* at = _get_at_internal(set, internal_pos);
    if (at != NULL) {
      after = at->prev;
    } else {
      after = set->tail;
    }
    _set_placement(elem, after, &op->id);
    _insert_after(set, after, elem);
    set->ot_data->position_map = crabs_xi_one(set->ot_data->position_map, internal_pos);
  } else {
    // No position map: insert at visible position
    if (op->visible_pos == 0 || set->head == NULL) {
      _set_placement(elem, NULL, &op->id);
      _insert_after(set, NULL, elem);
    } else {
      after = crabs_ot_ordered_set_get(set, op->visible_pos - 1);
      if (after == NULL) after = set->tail;
      _set_placement(elem, after, &op->id);
      _insert_after(set, after, elem);
    }
  }

  return elem;
}

crabs_ordered_element_t* crabs_ot_ordered_set_apply_delete(
    crabs_ot_ordered_set_t* set, const crabs_ot_operation_t* op) {
  if (set == NULL || op == NULL) return NULL;

  crabs_ordered_element_t* elem = crabs_ot_ordered_set_get(set, op->visible_pos);
  if (elem == NULL) return NULL;

  if (!elem->deleted) {
    elem->deleted = true;
    set->visible_count--;

    // Update position map
    if (set->ot_data != NULL) {
      uint64_t internal_pos = crabs_xi_inv(set->ot_data->position_map, op->visible_pos);
      set->ot_data->position_map = crabs_union_one(set->ot_data->position_map, internal_pos);
    }
  }

  return elem;
}

crabs_ordered_element_t* crabs_ot_ordered_set_apply_update(
    crabs_ot_ordered_set_t* set, const crabs_ot_operation_t* op) {
  if (set == NULL || op == NULL) return NULL;

  crabs_ordered_element_t* elem = crabs_ot_ordered_set_get(set, op->visible_pos);
  if (elem == NULL) return NULL;

  if (op->payload != NULL && op->payload_size > 0) {
    if (elem->value != NULL) {
      free(elem->value);
    }
    elem->value = get_memory(op->payload_size);
    memcpy(elem->value, op->payload, op->payload_size);
    elem->value_size = op->payload_size;
  }

  return elem;
}

crabs_ordered_element_t* crabs_ot_ordered_set_apply_move(
    crabs_ot_ordered_set_t* set, const crabs_ot_operation_t* op) {
  if (set == NULL || op == NULL) return NULL;
  if (op->visible_pos == op->visible_pos_2) return crabs_ot_ordered_set_get(set, op->visible_pos);

  // MOVE = DELETE at src + INSERT at dst
  crabs_ordered_element_t* elem = crabs_ot_ordered_set_get(set, op->visible_pos);
  if (elem == NULL) return NULL;

  // Unlink without count adjustment
  if (elem->prev != NULL) elem->prev->next = elem->next;
  else set->head = elem->next;
  if (elem->next != NULL) elem->next->prev = elem->prev;
  else set->tail = elem->prev;
  set->count--;

  // Re-insert at destination (coordinates in the list after source removal)
  uint64_t dst = op->visible_pos_2;
  if (dst == 0 || set->head == NULL) {
    elem->prev = NULL;
    elem->next = set->head;
    if (set->head != NULL) set->head->prev = elem;
    set->head = elem;
    if (set->tail == NULL) set->tail = elem;
  } else {
    crabs_ordered_element_t* after = crabs_ot_ordered_set_get(set, dst - 1);
    if (after == NULL) after = set->tail;
    elem->prev = after;
    elem->next = after->next;
    if (after->next != NULL) after->next->prev = elem;
    after->next = elem;
    if (after == set->tail) set->tail = elem;
  }
  set->count++;

  // A MOVE is a last-writer-wins update of the complete order known here.
  crabs_ordered_element_t* anchor = NULL;
  for (crabs_ordered_element_t* current = set->head;
       current != NULL; current = current->next) {
    _set_placement(current, anchor, &op->id);
    anchor = current;
  }

  return elem;
}

crabs_ordered_element_t* crabs_ot_ordered_set_apply_swap(
    crabs_ot_ordered_set_t* set, const crabs_ot_operation_t* op) {
  if (set == NULL || op == NULL) return NULL;

  crabs_ordered_element_t* a = crabs_ot_ordered_set_get(set, op->visible_pos);
  crabs_ordered_element_t* b = crabs_ot_ordered_set_get(set, op->visible_pos_2);
  if (a == NULL || b == NULL) return NULL;

  // Swap values
  uint8_t* tmp_val = a->value;
  uint32_t tmp_size = a->value_size;
  a->value = b->value;
  a->value_size = b->value_size;
  b->value = tmp_val;
  b->value_size = tmp_size;

  return a;
}

crabs_ordered_element_t* crabs_ot_ordered_set_apply(
    crabs_ot_ordered_set_t* set, const crabs_ot_operation_t* op) {
  if (set == NULL || op == NULL) return NULL;
  switch (op->op_type) {
    case CRABS_OT_OP_INSERT: return crabs_ot_ordered_set_apply_insert(set, op);
    case CRABS_OT_OP_DELETE: return crabs_ot_ordered_set_apply_delete(set, op);
    case CRABS_OT_OP_UPDATE: return crabs_ot_ordered_set_apply_update(set, op);
    case CRABS_OT_OP_MOVE:   return crabs_ot_ordered_set_apply_move(set, op);
    case CRABS_OT_OP_SWAP:   return crabs_ot_ordered_set_apply_swap(set, op);
    default: return NULL;
  }
}

// ============================================================
// CRDT Merge (v1.5 §5.3)
// ============================================================

crabs_ot_ordered_set_t* crabs_ot_ordered_set_merge(
    crabs_ot_ordered_set_t* dest, const crabs_ot_ordered_set_t* src) {
  if (dest == NULL || src == NULL) return dest;

  if (!_merge_preflight(dest, src)) return NULL;

  // Merge position maps
  crabs_ot_ordered_set_merge_position_maps(dest, src);

  // Merge elements: add elements from src that don't exist in dest
  for (crabs_ordered_element_t* e = src->head; e != NULL; e = e->next) {
    crabs_ordered_element_t* found = crabs_ot_ordered_set_find(dest, &e->id);
    if (found == NULL) {
      // New element — add to dest
      crabs_ordered_element_t* new_elem = crabs_ordered_element_create(
        &e->id, e->value, e->value_size);
      new_elem->deleted = e->deleted;
      new_elem->has_anchor = e->has_anchor;
      new_elem->anchor_id = e->anchor_id;
      new_elem->placement_id = e->placement_id;
      _insert_after(dest, dest->tail, new_elem);
    } else {
      // Existing element — merge deletion state (deleted wins)
      if (e->deleted && !found->deleted) {
        found->deleted = true;
        dest->visible_count--;
      }
      if (_op_id_compare(&e->placement_id, &found->placement_id) > 0) {
        found->has_anchor = e->has_anchor;
        found->anchor_id = e->anchor_id;
        found->placement_id = e->placement_id;
      }
    }
  }

  return _materialize(dest) ? dest : NULL;
}

void crabs_ot_ordered_set_merge_position_maps(
    crabs_ot_ordered_set_t* dest, const crabs_ot_ordered_set_t* src) {
  if (dest == NULL || src == NULL) return;
  if (dest->ot_data != NULL && src->ot_data != NULL) {
    dest->ot_data->position_map = crabs_bst_merge(
      dest->ot_data->position_map, src->ot_data->position_map);
  }
}
