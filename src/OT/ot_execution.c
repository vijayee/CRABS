//
// Created by victor on 5/1/25.
//
// OT Execution Integration (v1.5 §8)
// Integrates OT operations into the CRABS state machine pipeline.
//

#include "ot_execution.h"
#include "ot_ordered_set.h"
#include "ot_document.h"
#include "ot_tree.h"
#include "../CRABS/data_model.h"
#include "../StateMachine/state_machine.h"
#include "../Compaction/compaction_engine.h"
#include "../Util/allocator.h"
#include <stdlib.h>
#include <string.h>

// ============================================================
// Type Registration (v1.5 §8.1)
// ============================================================

bool crabs_is_ot_type(uint32_t type) {
  return (type >= 0x10 && type <= 0x1F);
}

data_item_t* crabs_register_ot_type(state_t* state,
                                     const char* name,
                                     uint32_t ot_type,
                                     const crabs_ot_config_t* config) {
  if (state == NULL || name == NULL) return NULL;
  if (!crabs_is_ot_type(ot_type)) return NULL;

  // Create the data item
  data_item_t* item = data_item_create(name, ot_type, CRDT_CUSTOM);
  if (item == NULL) return NULL;

  // Create the appropriate CRDT value — these create their own ot_data
  switch (ot_type) {
    case DATA_TYPE_OT_ORDERED_SET: {
      crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
      item->value = set;
      if (set != NULL) item->ot_data = set->ot_data;
      break;
    }
    case DATA_TYPE_OT_DOCUMENT: {
      crabs_ot_document_t* doc = crabs_ot_document_create();
      item->value = doc;
      if (doc != NULL) item->ot_data = doc->ot_data;
      break;
    }
    case DATA_TYPE_OT_TREE: {
      crabs_ot_tree_t* tree = crabs_ot_tree_create();
      item->value = tree;
      if (tree != NULL) item->ot_data = tree->ot_data;
      break;
    }
    default:
      // OT_TABLE and OT_ORDERED_MAP not yet implemented
      break;
  }

  if (item->value == NULL) {
    data_item_destroy(item);
    return NULL;
  }
  // OT items hold crabs_ot_*_t heap structs — repr CRDT_STRUCT (symmetry;
  // data_item_destroy dispatches OT destruction by type).
  item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;

  // Apply config to the ot_data
  if (item->ot_data != NULL) {
    crabs_ot_data_item_t* ot_data = (crabs_ot_data_item_t*)item->ot_data;
    uint32_t desired_cap;
    if (config != NULL && config->max_op_log_size > 0) {
      desired_cap = config->max_op_log_size;
    } else {
      desired_cap = CRABS_OT_MAX_OP_LOG_DEFAULT;
    }
    // Cap to a sane maximum to avoid a huge allocation from untrusted config.
    if (desired_cap > CRABS_OT_OP_LOG_MAX) {
      desired_cap = CRABS_OT_OP_LOG_MAX;
    }
    // The op_log was allocated with the initial capacity by
    // crabs_ot_data_item_create. Setting op_log_capacity above the actual
    // allocation would let append_op write past the end of the buffer
    // (heap overflow), so realloc to the desired capacity first.
    if (desired_cap > ot_data->op_log_capacity) {
      crabs_ot_operation_t* new_log = realloc(
          ot_data->op_log,
          sizeof(crabs_ot_operation_t) * desired_cap);
      if (new_log == NULL) {
        data_item_destroy(item);
        return NULL;
      }
      memset(new_log + ot_data->op_log_capacity, 0,
             sizeof(crabs_ot_operation_t) * (desired_cap - ot_data->op_log_capacity));
      ot_data->op_log = new_log;
      ot_data->op_log_capacity = desired_cap;
    } else {
      ot_data->op_log_capacity = desired_cap;
    }
  }

  // Add to state
  crabs_error_e err = state_add_item(state, item);
  if (err != CRABS_SUCCESS) {
    data_item_destroy(item);
    return NULL;
  }

  return item;
}

// ============================================================
// OT Operation Extraction (v1.5 §8.2 step 6)
// ============================================================

// Audit L-k: explicit little-endian readers so the OT op-log wire format is
// cross-architecture safe (the prior memcpy reads were host-endian, which
// desyncs big-endian peers). The format is defined as little-endian.
static uint32_t _rd_u32_le(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t _rd_u64_le(const uint8_t* p) {
  return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
         ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
         ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

// Payload format for OT operations:
// [4 bytes: count] [count * crabs_ot_operation_t binary layout]
// Each op: [op_type(4) + id.node_id(64) + id.sequence_num(8) + id.timestamp(8)
//          + visible_pos(8) + visible_pos_2(8) + priority(8)
//          + payload_size(4) + payload(payload_size) + dep_count(4) + deps...]

uint32_t crabs_extract_ot_ops(const uint8_t* payload, uint32_t payload_size,
                              crabs_ot_operation_t** ops_out) {
  if (payload == NULL || payload_size < 4 || ops_out == NULL) {
    *ops_out = NULL;
    return 0;
  }

  // Read op count from first 4 bytes (little-endian).
  uint32_t count = _rd_u32_le(payload);

  if (count == 0 || count > 1024) {
    *ops_out = NULL;
    return 0;
  }

  crabs_ot_operation_t* ops = get_clear_memory(sizeof(crabs_ot_operation_t) * count);
  if (ops == NULL) {
    *ops_out = NULL;
    return 0;
  }

  uint32_t offset = 4;
  uint32_t parsed = 0;
  for (uint32_t i = 0; i < count; i++) {
    crabs_ot_operation_init(&ops[i]);

    if (offset + 4 > payload_size) break;
    ops[i].op_type = _rd_u32_le(payload + offset);
    offset += 4;

    if (offset + CRABS_MAX_USER_ID > payload_size) break;
    memcpy(ops[i].id.node_id, payload + offset, CRABS_MAX_USER_ID);
    // R7-L-13: force NUL termination so strcmp/strlen consumers cannot read
    // past the buffer on a wire-crafted 64-byte ID.
    ops[i].id.node_id[CRABS_MAX_USER_ID - 1] = '\0';
    offset += CRABS_MAX_USER_ID;

    if (offset + 8 > payload_size) break;
    ops[i].id.sequence_num = _rd_u64_le(payload + offset);
    offset += 8;

    if (offset + 8 > payload_size) break;
    ops[i].id.timestamp = _rd_u64_le(payload + offset);
    offset += 8;

    if (offset + 8 > payload_size) break;
    ops[i].visible_pos = _rd_u64_le(payload + offset);
    offset += 8;

    if (offset + 8 > payload_size) break;
    ops[i].visible_pos_2 = _rd_u64_le(payload + offset);
    offset += 8;

    if (offset + 8 > payload_size) break;
    ops[i].priority = _rd_u64_le(payload + offset);
    offset += 8;

    if (offset + 4 > payload_size) {
      // Partial op: free payload if already allocated
      if (ops[i].payload != NULL) { free(ops[i].payload); ops[i].payload = NULL; }
      break;
    }
    ops[i].payload_size = _rd_u32_le(payload + offset);
    offset += 4;

    if (ops[i].payload_size > 0 && ops[i].payload_size <= CRABS_OT_MAX_PAYLOAD) {
      if (offset + ops[i].payload_size > payload_size) {
        if (ops[i].payload != NULL) { free(ops[i].payload); ops[i].payload = NULL; }
        break;
      }
      crabs_ot_operation_set_payload(&ops[i], payload + offset, ops[i].payload_size);
      offset += ops[i].payload_size;
    } else if (ops[i].payload_size > CRABS_OT_MAX_PAYLOAD) {
      // Oversized payload: skip its bytes so the stream stays aligned for
      // subsequent ops, but reject this op (don't store the payload).
      if (offset + ops[i].payload_size > payload_size) {
        if (ops[i].payload != NULL) { free(ops[i].payload); ops[i].payload = NULL; }
        break;
      }
      offset += ops[i].payload_size;
    }

    if (offset + 4 > payload_size) {
      if (ops[i].payload != NULL) { free(ops[i].payload); ops[i].payload = NULL; }
      break;
    }
    ops[i].dep_count = _rd_u32_le(payload + offset);
    offset += 4;
    // Audit M-E/L-k: reject (do not clamp) oversized dep_count — clamping
    // desynchronizes the parse (the wire carries dep_count deps but we'd
    // consume only MAX). Stop parsing on a malformed op.
    if (ops[i].dep_count > CRABS_OT_MAX_DEPS) {
      ops[i].dep_count = 0;
      break;
    }

    // Consume dep_count op-ids from the wire (little-endian).
    for (uint32_t d = 0; d < ops[i].dep_count; d++) {
      if (offset + CRABS_MAX_USER_ID + 8 + 8 > payload_size) {
        ops[i].dep_count = d; // truncated
        goto done_op;
      }
      memcpy(ops[i].deps[d].node_id, payload + offset, CRABS_MAX_USER_ID);
      offset += CRABS_MAX_USER_ID;
      ops[i].deps[d].sequence_num = _rd_u64_le(payload + offset);
      offset += 8;
      ops[i].deps[d].timestamp = _rd_u64_le(payload + offset);
      offset += 8;
    }
done_op:;

    parsed++;
  }

  // If we couldn't parse any ops, free and return nothing
  if (parsed == 0) {
    free(ops);
    *ops_out = NULL;
    return 0;
  }

  *ops_out = ops;
  return parsed;
}

void crabs_ot_ops_free(crabs_ot_operation_t* ops, uint32_t count) {
  if (ops == NULL) return;
  for (uint32_t i = 0; i < count; i++) {
    if (ops[i].payload != NULL) {
      free(ops[i].payload);
    }
  }
  free(ops);
}

// ============================================================
// OT Transform (v1.5 §8.2 step 7)
// ============================================================

crabs_error_e crabs_transform_ot_op(crabs_ot_operation_t* op,
                                     crabs_ot_data_item_t* item,
                                     const char* local_node_id,
                                     uint32_t max_depth) {
  if (op == NULL || item == NULL) return CRABS_ERR_INVALID_PARAM;
  if (max_depth == 0) max_depth = CRABS_OT_MAX_TRANSFORM_DEPTH;

  uint32_t depth = 0;
  for (uint32_t i = 0; i < item->op_log_count && depth < max_depth; i++) {
    crabs_ot_operation_t* log_op = &item->op_log[i];

    // Skip if same operation (dedup)
    if (crabs_ot_op_id_equal(&op->id, &log_op->id)) continue;

    // Check causal ordering: only transform against concurrent ops. A log op
    // that the incoming op causally depends on (or that precedes it on the
    // same node) is already accounted for and must be skipped. This uses the
    // dependency set (sound) rather than the prior wall-clock comparison.
    if (crabs_causally_before(&log_op->id, &op->id)) continue;
    if (crabs_op_depends_on(op, &log_op->id)) continue;

    // Look up the transform function for this op type pair
    crabs_ot_transform_fn transform_fn = crabs_ot_data_item_get_transform(
      item, (crabs_ot_op_type_e)op->op_type, (crabs_ot_op_type_e)log_op->op_type);

    if (transform_fn != NULL) {
      // Apply forward transform: op' = T(op, log_op)
      crabs_ot_operation_t* transformed = transform_fn(op, log_op);
      if (transformed != NULL) {
        // Copy transformed fields back to op. Audit F-4: copy back op_type
        // too — transform functions signal "no-op" by setting op_type = 0
        // (e.g. delete_delete at the same position). Without copying it back,
        // the delete was still applied at the same position, deleting
        // whatever element shifted into it (wrong element deleted).
        op->visible_pos = transformed->visible_pos;
        op->visible_pos_2 = transformed->visible_pos_2;
        op->op_type = transformed->op_type;
        // Free the returned operation (it's a heap copy)
        if (transformed != op) {
          crabs_ot_operation_destroy(transformed);
        }
      }
      // Audit M-K: only count ops that were actually transformed. The prior
      // code incremented depth for every iterated log entry (including ones
      // with no registered transform), so a flooded log permanently wedged
      // the item at the 64-entry cap.
      depth++;
    }
  }

  // Audit M-K: do not fail when the cap is reached — returning an error
  // wedged all further OT ops on this item. The op is applied with the
  // transforms completed so far; the proper fix for divergent partial
  // transforms is compaction/pruning of the log (F-3 full, deferred).
  return CRABS_SUCCESS;
}

// Audit finding (conf 8): replay protection. Returns true when an op with
// the same id (node_id, sequence_num) is already recorded in the item's op
// log — i.e. this exact op was applied before and must be skipped ENTIRELY:
// transforming it against a log that already contains its own effects, and
// re-applying it, would duplicate its effect (e.g. a doubled INSERT_TEXT).
static bool _op_already_applied(const crabs_ot_data_item_t* ot_data,
                                const crabs_ot_op_id_t* op_id) {
  for (uint32_t log_index = 0; log_index < ot_data->op_log_count; log_index++) {
    if (crabs_ot_op_id_equal(&ot_data->op_log[log_index].id, op_id)) {
      return true;
    }
  }
  return false;
}

// ============================================================
// Apply OT Operation (v1.5 §8.2 step 7)
// ============================================================

crabs_error_e crabs_apply_ot_op(data_item_t* item, crabs_ot_operation_t* op) {
  if (item == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (!crabs_is_ot_type((uint32_t)item->type)) return CRABS_ERR_NOT_OT_TYPE;

  // Audit F-4: a transform may mark the op as a no-op by setting op_type = 0
  // (e.g. delete_delete at the same position, or move_move with the same
  // source). Skip applying it entirely — applying a no-op'd delete would
  // delete whatever element shifted into the position (wrong element).
  if (op->op_type == 0) {
    return CRABS_SUCCESS;
  }

  switch (item->type) {
    case DATA_TYPE_OT_ORDERED_SET: {
      crabs_ot_ordered_set_t* set = (crabs_ot_ordered_set_t*)item->value;
      if (set == NULL) return CRABS_ERR_INTERNAL;
      crabs_ot_ordered_set_apply(set, op);
      break;
    }
    case DATA_TYPE_OT_DOCUMENT: {
      crabs_ot_document_t* doc = (crabs_ot_document_t*)item->value;
      if (doc == NULL) return CRABS_ERR_INTERNAL;
      switch (op->op_type) {
        case CRABS_OT_OP_INSERT_TEXT: {
          crabs_ot_op_id_t id = op->id;
          crabs_ot_document_insert_text(doc, op->visible_pos,
            op->payload, op->payload_size, &id);
          break;
        }
        case CRABS_OT_OP_DELETE_RANGE:
          crabs_ot_document_delete_range(doc, op->visible_pos, op->visible_pos_2);
          break;
        case CRABS_OT_OP_STYLE: {
          if (op->payload == NULL || op->payload_size < sizeof(crabs_style_t)) {
            return CRABS_ERR_INVALID_PARAM;
          }
          crabs_style_t* style = (crabs_style_t*)op->payload;
          crabs_ot_document_apply_style(doc, op->visible_pos, op->visible_pos_2, style);
          break;
        }
        case CRABS_OT_OP_MERGE_SPANS:
          crabs_ot_document_merge_spans(doc, op->visible_pos, op->visible_pos_2);
          break;
        case CRABS_OT_OP_SPLIT_SPAN:
          crabs_ot_document_split_span(doc, op->visible_pos);
          break;
        default:
          break;
      }
      break;
    }
    case DATA_TYPE_OT_TREE: {
      crabs_ot_tree_t* tree = (crabs_ot_tree_t*)item->value;
      if (tree == NULL) return CRABS_ERR_INTERNAL;
      switch (op->op_type) {
        case CRABS_OT_OP_INSERT_NODE: {
          // Payload format: parent_id[64] + node_id[64] + value
          if (op->payload == NULL || op->payload_size < 128) {
            return CRABS_ERR_INVALID_PARAM;
          }
          char parent_id[64] = {0};
          char node_id[64] = {0};
          memcpy(parent_id, op->payload, 63);
          memcpy(node_id, op->payload + 64, 63);
          crabs_ot_tree_insert_node(tree,
            parent_id[0] ? parent_id : NULL,
            op->visible_pos, node_id,
            op->payload + 128, op->payload_size - 128);
          break;
        }
        case CRABS_OT_OP_DELETE_NODE: {
          if (op->payload == NULL || op->payload_size < 64) {
            return CRABS_ERR_INVALID_PARAM;
          }
          char node_id[64] = {0};
          memcpy(node_id, op->payload, 63);
          crabs_ot_tree_delete_node(tree, node_id);
          break;
        }
        case CRABS_OT_OP_REPARENT: {
          // Payload format: node_id[64] + new_parent_id[64]
          if (op->payload == NULL || op->payload_size < 128) {
            return CRABS_ERR_INVALID_PARAM;
          }
          char node_id[64] = {0};
          char new_parent_id[64] = {0};
          memcpy(node_id, op->payload, 63);
          memcpy(new_parent_id, op->payload + 64, 63);
          crabs_ot_tree_reparent(tree, node_id,
            new_parent_id[0] ? new_parent_id : "",
            op->visible_pos);
          break;
        }
        case CRABS_OT_OP_REORDER: {
          if (op->payload == NULL || op->payload_size < 64) {
            return CRABS_ERR_INVALID_PARAM;
          }
          char node_id[64] = {0};
          memcpy(node_id, op->payload, 63);
          crabs_ot_tree_reorder(tree, node_id, op->visible_pos);
          break;
        }
        default:
          break;
      }
      break;
    }
    default:
      return CRABS_ERR_NOT_OT_TYPE;
  }

  return CRABS_SUCCESS;
}

// ============================================================
// Execute OT Operation (v1.5 §8.2)
// ============================================================

crabs_error_e crabs_execute_ot_operation(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;

  // Step 6: Extract OT operations from payload
  crabs_ot_operation_t* ot_ops = NULL;
  uint32_t ot_op_count = crabs_extract_ot_ops(op->payload, op->payload_size, &ot_ops);

  if (ot_op_count == 0 || ot_ops == NULL) {
    return CRABS_ERR_NO_OT_OPS;
  }

  // For each resource, apply the OT operations
  for (uint32_t res = 0; res < op->resource_count; res++) {
    data_item_t* item = state_find_item(state, op->resources[res]);
    if (item == NULL) {
      crabs_ot_ops_free(ot_ops, ot_op_count);
      return CRABS_ERR_RESOURCE_NOT_FOUND;
    }

    if (!crabs_is_ot_type(item->type)) {
      crabs_ot_ops_free(ot_ops, ot_op_count);
      return CRABS_ERR_NOT_OT_TYPE;
    }

    crabs_ot_data_item_t* ot_data = (crabs_ot_data_item_t*)item->ot_data;
    if (ot_data == NULL) {
      crabs_ot_ops_free(ot_ops, ot_op_count);
      return CRABS_ERR_INTERNAL;
    }

    // Step 7: Transform and apply each OT operation
    for (uint32_t i = 0; i < ot_op_count; i++) {
      // Audit F-3: record this ingested OT op in the compaction engine's
      // local vector clock (if an engine is wired on the state) so the
      // STRONG/QUORUM compaction safety check can compare local progress
      // against a peer VC.
      if (state->compaction_engine != NULL) {
        crabs_compaction_engine_record_op(
            (crabs_compaction_engine_t*)state->compaction_engine,
            ot_ops[i].id.node_id, ot_ops[i].id.sequence_num);
      }

      // Audit finding (conf 8): idempotent-apply. An op whose id is already
      // in the log has already been applied — skip it entirely (no transform,
      // no re-apply) but still count it as processed.
      if (_op_already_applied(ot_data, &ot_ops[i].id)) {
        continue;
      }

      // Transform against concurrent operations in the op log
      crabs_error_e transform_err = crabs_transform_ot_op(
        &ot_ops[i], ot_data, op->node_id, CRABS_OT_MAX_TRANSFORM_DEPTH);

      if (transform_err != CRABS_SUCCESS) {
        crabs_ot_ops_free(ot_ops, ot_op_count);
        return transform_err;
      }

      // Position bounds checking
      if (ot_ops[i].visible_pos > 100000) {
        // Basic sanity check for position values
        crabs_ot_ops_free(ot_ops, ot_op_count);
        return CRABS_ERR_OT_POSITION_BOUNDS;
      }

      // Apply the transformed operation
      crabs_error_e apply_err = crabs_apply_ot_op(item, &ot_ops[i]);
      if (apply_err != CRABS_SUCCESS) {
        crabs_ot_ops_free(ot_ops, ot_op_count);
        return apply_err;
      }

      // Append a fresh slot to the op log. Audit H-I: check the return — on
      // failure (capacity cap reached or OOM) append_op does NOT increment
      // op_log_count, and the prior code then overwrote the last existing
      // log entry (leaking its payload and destroying causal history). Abort
      // the whole operation instead.
      crabs_ot_operation_t* log_entry = crabs_ot_data_item_append_op(ot_data);
      if (log_entry == NULL) {
        crabs_ot_ops_free(ot_ops, ot_op_count);
        return CRABS_ERR_OOM;
      }
      // Copy the transformed op into the log
      *log_entry = ot_ops[i];
      // Payload was allocated for the log entry, need to copy
      if (ot_ops[i].payload != NULL && ot_ops[i].payload_size > 0) {
        log_entry->payload = get_memory(ot_ops[i].payload_size);
        if (log_entry->payload == NULL) {
          // Keep the log entry self-consistent (NULL payload, 0 size) so a
          // later transform reading it doesn't dereference NULL.
          log_entry->payload_size = 0;
          crabs_ot_ops_free(ot_ops, ot_op_count);
          return CRABS_ERR_OOM;
        }
        memcpy(log_entry->payload, ot_ops[i].payload, ot_ops[i].payload_size);
        log_entry->payload_size = ot_ops[i].payload_size;
      } else {
        log_entry->payload = NULL;
        log_entry->payload_size = 0;
      }

      // Prune log if it exceeds max size
      crabs_prune_ot_log(ot_data, CRABS_OT_MAX_OP_LOG_DEFAULT);
    }
  }

  crabs_ot_ops_free(ot_ops, ot_op_count);
  return CRABS_SUCCESS;
}

// ============================================================
// Operation Log Pruning (v1.5 §8.3)
// ============================================================

void crabs_prune_ot_log(crabs_ot_data_item_t* item, uint32_t max_size) {
  if (item == NULL || item->op_log == NULL) return;
  if (item->op_log_count <= max_size) return;

  // Keep a margin of 100 ops beyond max_size
  uint32_t keep_count = max_size + 100;
  if (keep_count >= item->op_log_count) return;

  // Candidates to prune are the oldest ops (indices 0..to_remove-1). But an
  // op may only be pruned if NO retained op declares a causal dependency on
  // it — otherwise a future transform against a retained op could need the
  // pruned op's context and diverge (audit M-9: the prior code shifted the
  // oldest ops out blindly, dropping causally-relevant history).
  uint32_t to_remove = item->op_log_count - keep_count;
  if (to_remove == 0) return;

  // For each candidate, check whether any retained op depends on it.
  // Audit N-12: use calloc (returns NULL on OOM) instead of get_clear_memory
  // (which aborts the process). The NULL check below then skips pruning
  // safely; the prior call would abort the node on a large prune set.
  uint8_t* prune = (uint8_t*)calloc(to_remove, 1);
  if (prune == NULL) return; // refuse to prune if we can't track it safely
  for (uint32_t i = 0; i < to_remove; i++) {
    const crabs_ot_op_id_t* cid = &item->op_log[i].id;
    bool needed = false;
    for (uint32_t j = to_remove; j < item->op_log_count && !needed; j++) {
      const crabs_ot_operation_t* k = &item->op_log[j];
      for (uint32_t d = 0; d < k->dep_count && d < CRABS_OT_MAX_DEPS; d++) {
        if (strncmp(k->deps[d].node_id, cid->node_id, CRABS_MAX_USER_ID) == 0 &&
            k->deps[d].sequence_num == cid->sequence_num) {
          needed = true;
          break;
        }
      }
    }
    prune[i] = needed ? 0 : 1; // 1 = prune
  }

  // Compact in place: free pruned payloads, move retained ops to the front.
  uint32_t write = 0;
  for (uint32_t i = 0; i < item->op_log_count; i++) {
    if (i < to_remove && prune[i]) {
      if (item->op_log[i].payload != NULL) {
        free(item->op_log[i].payload);
        item->op_log[i].payload = NULL;
      }
      continue; // drop
    }
    if (write != i) {
      item->op_log[write] = item->op_log[i];
    }
    write++;
  }
  item->op_log_count = write;
  free(prune);
}

// ============================================================
// Apply Function Registry (v1.5 §8.1)
// ============================================================

crabs_ot_apply_fn crabs_ot_get_apply_fn(data_type_e type) {
  switch (type) {
    case DATA_TYPE_OT_ORDERED_SET:
      return (crabs_ot_apply_fn)crabs_ot_ordered_set_apply;
    case DATA_TYPE_OT_DOCUMENT:
    case DATA_TYPE_OT_TREE:
    case DATA_TYPE_OT_TABLE:
    case DATA_TYPE_OT_ORDERED_MAP:
      // Document and Tree use crabs_apply_ot_op dispatch, not a single apply fn
      return NULL;
    default:
      return NULL;
  }
}