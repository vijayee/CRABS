//
// Created by victor on 5/1/25.
//
// COMPACT Operation & Algorithm (v1.6 §3)
// Tombstone compaction as an OT operation.
//

#include "compact_op.h"

// Undefine OT type macros that conflict with data_type_e enum values
// in data_model.h. These headers define the same constants as macros.
#ifdef DATA_TYPE_OT_ORDERED_SET
#undef DATA_TYPE_OT_ORDERED_SET
#endif
#ifdef DATA_TYPE_OT_DOCUMENT
#undef DATA_TYPE_OT_DOCUMENT
#endif
#ifdef DATA_TYPE_OT_TREE
#undef DATA_TYPE_OT_TREE
#endif

#include "../OT/ot_ordered_set.h"
#include "../OT/ot_document.h"
#include "../OT/ot_tree.h"
#include <string.h>

// ============================================================
// Compaction ID Generation (v1.6 §3)
// ============================================================

void crabs_compact_id_init(crabs_ot_op_id_t* id, const char* node_id,
                            uint64_t sequence_num, uint64_t timestamp) {
  if (id == NULL) return;
  crabs_ot_op_id_init(id, node_id, sequence_num, timestamp);
}

// ============================================================
// Extract Visible Value (v1.6 §3.3)
// ============================================================

crabs_ot_ordered_set_t* crabs_extract_visible_ordered_set(
  const crabs_ot_ordered_set_t* set) {
  if (set == NULL) return NULL;

  crabs_ot_ordered_set_t* visible = crabs_ot_ordered_set_create();
  if (visible == NULL) return NULL;

  crabs_ordered_element_t* elem = set->head;
  while (elem != NULL) {
    if (!elem->deleted) {
      crabs_ordered_element_t* new_elem = crabs_ordered_element_create(
        &elem->id, elem->value, elem->value_size);
      if (new_elem == NULL) {
        crabs_ot_ordered_set_destroy(visible);
        return NULL;
      }
      // Append to tail
      new_elem->prev = visible->tail;
      new_elem->next = NULL;
      if (visible->tail != NULL) {
        visible->tail->next = new_elem;
      } else {
        visible->head = new_elem;
      }
      visible->tail = new_elem;
      visible->count++;
      visible->visible_count++;
    }
    elem = elem->next;
  }

  return visible;
}

crabs_ot_document_t* crabs_extract_visible_document(
  const crabs_ot_document_t* doc) {
  if (doc == NULL) return NULL;

  crabs_ot_document_t* visible = crabs_ot_document_create();
  if (visible == NULL) return NULL;

  crabs_span_t* span = doc->head;
  while (span != NULL) {
    if (!span->deleted) {
      crabs_span_t* new_span = crabs_span_create(&span->id,
        span->text, span->text_size);
      if (new_span == NULL) {
        crabs_ot_document_destroy(visible);
        return NULL;
      }
      // Copy styles
      for (uint32_t i = 0; i < span->style_count && i < CRABS_SPAN_MAX_STYLES; i++) {
        new_span->styles[i] = span->styles[i];
      }
      new_span->style_count = span->style_count;
      // Append to tail
      new_span->prev = visible->tail;
      new_span->next = NULL;
      if (visible->tail != NULL) {
        visible->tail->next = new_span;
      } else {
        visible->head = new_span;
      }
      visible->tail = new_span;
      visible->span_count++;
      visible->visible_char_count += new_span->text_size;
    }
    span = span->next;
  }

  return visible;
}

crabs_ot_tree_t* crabs_extract_visible_tree(
  const crabs_ot_tree_t* tree) {
  if (tree == NULL) return NULL;

  crabs_ot_tree_t* visible = crabs_ot_tree_create();
  if (visible == NULL) return NULL;

  // Walk the node pool linked list
  crabs_tree_node_t* node = tree->node_pool;
  while (node != NULL) {
    if (!node->deleted) {
      crabs_ot_tree_insert_node(visible, node->parent_id,
        0, node->id,
        node->value, node->value_size);
    }
    node = node->pool_next;
  }

  return visible;
}

void* crabs_extract_visible(data_type_e type, const void* value) {
  if (value == NULL) return NULL;

  switch (type) {
    case DATA_TYPE_OT_ORDERED_SET:
      return crabs_extract_visible_ordered_set(
        (const crabs_ot_ordered_set_t*)value);
    case DATA_TYPE_OT_DOCUMENT:
      return crabs_extract_visible_document(
        (const crabs_ot_document_t*)value);
    case DATA_TYPE_OT_TREE:
      return crabs_extract_visible_tree(
        (const crabs_ot_tree_t*)value);
    default:
      return NULL;
  }
}

// ============================================================
// COMPACT Operation (v1.6 §3)
// ============================================================

// ============================================================
// OT Type Tombstone Counting (v1.5.2 §4)
// ============================================================

uint64_t crabs_ot_tombstone_count(data_type_e type, const void* value) {
  if (value == NULL) return 0;

  switch (type) {
    case DATA_TYPE_OT_ORDERED_SET: {
      const crabs_ot_ordered_set_t* set = (const crabs_ot_ordered_set_t*)value;
      return (uint64_t)(set->count - set->visible_count);
    }
    case DATA_TYPE_OT_DOCUMENT: {
      const crabs_ot_document_t* doc = (const crabs_ot_document_t*)value;
      // Count spans marked deleted
      uint64_t deleted = 0;
      const crabs_span_t* span = doc->head;
      while (span != NULL) {
        if (span->deleted) deleted++;
        span = span->next;
      }
      return deleted;
    }
    case DATA_TYPE_OT_TREE: {
      const crabs_ot_tree_t* tree = (const crabs_ot_tree_t*)value;
      return (uint64_t)(tree->node_count - tree->visible_count);
    }
    default:
      return 0;
  }
}

uint64_t crabs_ot_visible_count(data_type_e type, const void* value) {
  if (value == NULL) return 0;

  switch (type) {
    case DATA_TYPE_OT_ORDERED_SET: {
      const crabs_ot_ordered_set_t* set = (const crabs_ot_ordered_set_t*)value;
      return (uint64_t)set->visible_count;
    }
    case DATA_TYPE_OT_DOCUMENT: {
      const crabs_ot_document_t* doc = (const crabs_ot_document_t*)value;
      // Count spans not deleted
      uint64_t visible = 0;
      const crabs_span_t* span = doc->head;
      while (span != NULL) {
        if (!span->deleted) visible++;
        span = span->next;
      }
      return visible;
    }
    case DATA_TYPE_OT_TREE: {
      const crabs_ot_tree_t* tree = (const crabs_ot_tree_t*)value;
      return (uint64_t)tree->visible_count;
    }
    default:
      return 0;
  }
}

// ============================================================
// COMPACT Operation (v1.6 §3)
// ============================================================

crabs_error_e crabs_compact_ot_item(
  state_t* state,
  data_item_t* item,
  const crabs_tombstone_config_t* config,
  const crabs_compaction_registry_t* registry,
  const crabs_vector_clock_t* local_vc,
  const crabs_vector_clock_t* peer_vc) {
  if (state == NULL || item == NULL || config == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Step 1: Check compaction safety
  if (!crabs_check_compaction_safety(config, state, item, local_vc, peer_vc)) {
    return CRABS_ERR_PROTOCOL_VIOLATION;
  }

  // Step 2: Check if compaction is needed
  if (!crabs_needs_compaction(config, registry, item)) {
    return CRABS_SUCCESS;  // No compaction needed
  }

  // Step 3: Extract visible value
  void* visible = crabs_extract_visible(item->type, item->value);
  if (visible == NULL) {
    return CRABS_ERR_INTERNAL;
  }

  // Step 4: For OT types, reset the position map and op log
  if (item->ot_data != NULL) {
    crabs_ot_data_item_t* ot_data = (crabs_ot_data_item_t*)item->ot_data;

    // Destroy all ops in the log
    for (uint32_t i = 0; i < ot_data->op_log_count; i++) {
      crabs_ot_operation_destroy(&ot_data->op_log[i]);
    }
    ot_data->op_log_count = 0;

    // Reset position map (destroy and null out)
    if (ot_data->position_map != NULL) {
      crabs_bst_destroy(ot_data->position_map);
      ot_data->position_map = NULL;
    }

    // Reset priority counters
    if (ot_data->priority_counters != NULL) {
      memset(ot_data->priority_counters, 0,
        sizeof(uint64_t) * ot_data->priority_counter_count);
    }
  }

  // Step 5: Replace the item's value with the visible-only version
  switch (item->type) {
    case DATA_TYPE_OT_ORDERED_SET: {
      crabs_ot_ordered_set_t* old_set = (crabs_ot_ordered_set_t*)item->value;
      crabs_ot_ordered_set_t* new_set = (crabs_ot_ordered_set_t*)visible;
      // Destroy the new set's ot_data (created by extract_visible)
      // before transferring the old set's ot_data
      if (new_set->ot_data != NULL) {
        crabs_ot_data_item_destroy(new_set->ot_data);
        new_set->ot_data = NULL;
      }
      new_set->ot_data = old_set->ot_data;
      old_set->ot_data = NULL;  // Prevent double-free
      crabs_ot_ordered_set_destroy(old_set);
      item->value = new_set;
      break;
    }
    case DATA_TYPE_OT_DOCUMENT: {
      crabs_ot_document_t* old_doc = (crabs_ot_document_t*)item->value;
      crabs_ot_document_t* new_doc = (crabs_ot_document_t*)visible;
      if (new_doc->ot_data != NULL) {
        crabs_ot_data_item_destroy(new_doc->ot_data);
        new_doc->ot_data = NULL;
      }
      new_doc->ot_data = old_doc->ot_data;
      old_doc->ot_data = NULL;
      crabs_ot_document_destroy(old_doc);
      item->value = visible;
      break;
    }
    case DATA_TYPE_OT_TREE: {
      crabs_ot_tree_t* old_tree = (crabs_ot_tree_t*)item->value;
      crabs_ot_tree_t* new_tree = (crabs_ot_tree_t*)visible;
      if (new_tree->ot_data != NULL) {
        crabs_ot_data_item_destroy(new_tree->ot_data);
        new_tree->ot_data = NULL;
      }
      new_tree->ot_data = old_tree->ot_data;
      old_tree->ot_data = NULL;
      crabs_ot_tree_destroy(old_tree);
      item->value = visible;
      break;
    }
    default:
      // Non-OT type: free the visible value we extracted
      // We don't know how to free it generically, so this is an error
      // For ordered_set/document/tree, we should have matched above
      return CRABS_ERR_TYPE_MISMATCH;
  }

  return CRABS_SUCCESS;
}

// ============================================================
// COMPACT Transform Rules (v1.6 §3.4)
// ============================================================

crabs_ot_operation_t* crabs_transform_compact_insert(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  (void)op2;
  return op1;
}

crabs_ot_operation_t* crabs_transform_compact_delete(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  (void)op2;
  return op1;
}

crabs_ot_operation_t* crabs_transform_compact_move(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  (void)op2;
  return op1;
}

crabs_ot_operation_t* crabs_transform_compact_update(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  (void)op2;
  return op1;
}

crabs_ot_operation_t* crabs_transform_compact_swap(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  (void)op2;
  return op1;
}

crabs_ot_operation_t* crabs_transform_compact_compact(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;

  // Last-writer-wins: earlier timestamp is absorbed
  if (op1->id.timestamp < op2->id.timestamp) {
    op1->op_type = CRABS_OT_OP_COMPACT;
    op1->visible_pos = 0;
    return op1;
  }

  return op1;
}

crabs_ot_operation_t* crabs_transform_insert_compact(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  (void)op2;
  if (op1 != NULL) {
    op1->visible_pos = 0;
    op1->payload_size = 0;
  }
  return op1;
}

crabs_ot_operation_t* crabs_transform_delete_compact(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  (void)op2;
  if (op1 != NULL) {
    op1->visible_pos = 0;
  }
  return op1;
}

crabs_ot_operation_t* crabs_transform_move_compact(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  (void)op2;
  if (op1 != NULL) {
    op1->visible_pos = 0;
    op1->visible_pos_2 = 0;
  }
  return op1;
}

crabs_ot_operation_t* crabs_transform_update_compact(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  (void)op2;
  if (op1 != NULL) {
    op1->payload_size = 0;
  }
  return op1;
}

crabs_ot_operation_t* crabs_transform_swap_compact(
  crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  (void)op2;
  if (op1 != NULL) {
    op1->visible_pos = 0;
    op1->visible_pos_2 = 0;
  }
  return op1;
}