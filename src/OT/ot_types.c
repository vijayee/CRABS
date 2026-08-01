//
// Created by victor on 5/1/25.
//
// OT Operation Types & Core Structs (v1.5 §3.2, §3.4)
// Implementation of core OT data structures and lifecycle functions.
//

#include "ot_types.h"
#include "../Util/allocator.h"
#include <stdlib.h>
#include <string.h>

// ============================================================
// OT Op ID Functions
// ============================================================

void crabs_ot_op_id_init(crabs_ot_op_id_t* id, const char* node_id,
                         uint64_t sequence_num, uint64_t timestamp) {
  if (id == NULL) return;
  memset(id, 0, sizeof(crabs_ot_op_id_t));
  if (node_id != NULL) {
    strncpy(id->node_id, node_id, CRABS_MAX_USER_ID - 1);
    id->node_id[CRABS_MAX_USER_ID - 1] = '\0';
  }
  id->sequence_num = sequence_num;
  id->timestamp = timestamp;
}

bool crabs_ot_op_id_equal(const crabs_ot_op_id_t* a, const crabs_ot_op_id_t* b) {
  if (a == NULL || b == NULL) return a == b;
  // Audit M-L: an op id is (node_id, sequence_num) — the timestamp is not part
  // of the identity. Including it here meant a forged timestamp could make the
  // same logical op appear distinct, bypassing dedup and double-applying.
  return a->sequence_num == b->sequence_num &&
         strncmp(a->node_id, b->node_id, CRABS_MAX_USER_ID) == 0;
}

// ============================================================
// OT Operation Functions
// ============================================================

crabs_ot_operation_t* crabs_ot_operation_create(void) {
  crabs_ot_operation_t* op = get_clear_memory(sizeof(crabs_ot_operation_t));
  crabs_ot_operation_init(op);
  return op;
}

void crabs_ot_operation_destroy(crabs_ot_operation_t* op) {
  if (op == NULL) return;
  if (op->payload != NULL) {
    free(op->payload);
  }
  free(op);
}

void crabs_ot_operation_clear(crabs_ot_operation_t* op) {
  if (op == NULL) return;
  if (op->payload != NULL) {
    free(op->payload);
  }
  memset(op, 0, sizeof(crabs_ot_operation_t));
}

void crabs_ot_operation_init(crabs_ot_operation_t* op) {
  if (op == NULL) return;
  memset(op, 0, sizeof(crabs_ot_operation_t));
}

bool crabs_ot_operation_set_payload(crabs_ot_operation_t* op,
                                    const uint8_t* data, uint32_t size) {
  if (op == NULL || size > CRABS_OT_MAX_PAYLOAD) return false;
  if (op->payload != NULL) {
    free(op->payload);
    op->payload = NULL;
    op->payload_size = 0;
  }
  if (data != NULL && size > 0) {
    op->payload = get_memory(size);
    memcpy(op->payload, data, size);
    op->payload_size = size;
  }
  return true;
}

// Audit N-16: return a bool so the caller can detect a dropped dependency
// and fail the operation instead of silently losing causality. The prior
// void return meant an op with more than CRABS_OT_MAX_DEPS dependencies
// silently dropped the overflow, and crabs_op_depends_on would not find the
// dropped deps — causing the transform to apply against ops that should have
// been skipped (causality violation → potential divergence).
bool crabs_ot_operation_add_dep(crabs_ot_operation_t* op,
                                const crabs_ot_op_id_t* dep) {
  if (op == NULL || dep == NULL) return false;
  if (op->dep_count >= CRABS_OT_MAX_DEPS) return false; // full — caller must fail
  op->deps[op->dep_count] = *dep;
  op->dep_count++;
  return true;
}

const char* crabs_ot_op_type_name(crabs_ot_op_type_e type) {
  switch (type) {
    case CRABS_OT_OP_INSERT:  return "INSERT";
    case CRABS_OT_OP_DELETE:  return "DELETE";
    case CRABS_OT_OP_UPDATE:  return "UPDATE";
    case CRABS_OT_OP_MOVE:    return "MOVE";
    case CRABS_OT_OP_SWAP:    return "SWAP";
    case CRABS_OT_OP_COMPACT: return "COMPACT";
    case CRABS_OT_OP_INSERT_TEXT:  return "INSERT_TEXT";
    case CRABS_OT_OP_DELETE_RANGE: return "DELETE_RANGE";
    case CRABS_OT_OP_STYLE:        return "STYLE";
    case CRABS_OT_OP_MERGE_SPANS:  return "MERGE_SPANS";
    case CRABS_OT_OP_SPLIT_SPAN:   return "SPLIT_SPAN";
    case CRABS_OT_OP_INSERT_NODE:  return "INSERT_NODE";
    case CRABS_OT_OP_DELETE_NODE:  return "DELETE_NODE";
    case CRABS_OT_OP_REPARENT:     return "REPARENT";
    case CRABS_OT_OP_REORDER:      return "REORDER";
    default:                       return "UNKNOWN";
  }
}

// ============================================================
// OT Data Item Functions
// ============================================================

crabs_ot_data_item_t* crabs_ot_data_item_create(uint32_t ot_type_id) {
  crabs_ot_data_item_t* item = get_clear_memory(sizeof(crabs_ot_data_item_t));
  item->ot_type_id = ot_type_id;
  item->op_log_capacity = CRABS_OT_OP_LOG_INITIAL;
  item->op_log = get_clear_memory(sizeof(crabs_ot_operation_t) * item->op_log_capacity);
  return item;
}

void crabs_ot_data_item_destroy(crabs_ot_data_item_t* item) {
  if (item == NULL) return;
  crabs_bst_destroy(item->position_map);
  if (item->op_log != NULL) {
    for (uint32_t i = 0; i < item->op_log_count; i++) {
      if (item->op_log[i].payload != NULL) {
        free(item->op_log[i].payload);
      }
    }
    free(item->op_log);
  }
  if (item->priority_counters != NULL) {
    free(item->priority_counters);
  }
  free(item);
}

crabs_ot_operation_t* crabs_ot_data_item_append_op(crabs_ot_data_item_t* item) {
  if (item == NULL) return NULL;
  if (item->op_log_count >= item->op_log_capacity) {
    if (item->op_log_capacity == 0) return NULL;
    uint64_t new_cap64 = (uint64_t)item->op_log_capacity * 2;
    if (new_cap64 > CRABS_OT_OP_LOG_MAX) {
      new_cap64 = CRABS_OT_OP_LOG_MAX;
    }
    uint32_t new_cap = (uint32_t)new_cap64;
    if (new_cap <= item->op_log_capacity) return NULL; // cap reached
    // Audit N-5: use realloc instead of get_clear_memory+memcpy+free. The
    // prior path allocated a zeroed array, memcpy'd the old entries (which
    // include payload pointers), then freed the old array — leaving the
    // payload pointers briefly in freed heap memory. realloc preserves the
    // entries in place and only zeroes the new tail, avoiding the temporary
    // double-copy of payload pointers.
    crabs_ot_operation_t* new_log = realloc(
        item->op_log, sizeof(crabs_ot_operation_t) * new_cap);
    if (new_log == NULL) return NULL;
    // Zero the new slots only (realloc does not zero the grown region).
    memset(new_log + item->op_log_capacity, 0,
           sizeof(crabs_ot_operation_t) * (new_cap - item->op_log_capacity));
    item->op_log = new_log;
    item->op_log_capacity = new_cap;
  }
  crabs_ot_operation_t* op = &item->op_log[item->op_log_count];
  crabs_ot_operation_init(op);
  item->op_log_count++;
  return op;
}

// Audit N-11: produce a per-node priority so concurrent ops from different
// nodes at the same insertion count get distinct priorities, reducing
// reliance on the (priority, node_id) tie-break in insert_insert. The high
// 32 bits are the global op count (preserving same-node insertion order);
// the low 32 bits are a hash of the node_id (differentiating concurrent
// nodes). The tie-break still handles the rare case of two ops from the
// same node at the same count (should not happen — sequence_num is unique
// per node).
static uint32_t _node_id_hash(const char* node_id) {
  if (node_id == NULL) return 0;
  // FNV-1a 32-bit
  uint32_t h = 0x811c9dc5u;
  for (const char* p = node_id; *p != '\0'; p++) {
    h ^= (uint8_t)*p;
    h *= 0x01000193u;
  }
  return h;
}

uint64_t crabs_ot_data_item_next_priority(crabs_ot_data_item_t* item,
                                           const char* node_id) {
  if (item == NULL || node_id == NULL) return 0;
  uint64_t count = (uint64_t)item->op_log_count + 1;
  uint64_t hash = _node_id_hash(node_id);
  return (count << 32) | (hash & 0xFFFFFFFFu);
}

void crabs_ot_data_item_set_transform(crabs_ot_data_item_t* item,
                                      crabs_ot_op_type_e type1,
                                      crabs_ot_op_type_e type2,
                                      crabs_ot_transform_fn fn) {
  if (item == NULL) return;
  if (type1 < 1 || type1 > CRABS_OT_OP_TYPE_COUNT) return;
  if (type2 < 1 || type2 > CRABS_OT_OP_TYPE_COUNT) return;
  item->transform_matrix[type1 - 1][type2 - 1] = fn;
}

// Audit F-4: map a concrete op type (document/tree) onto its base transform
// semantics so the transform matrix — which is indexed by the base types
// (INSERT/DELETE/UPDATE/MOVE/SWAP/COMPACT, 1..6) — can be consulted. Without
// this, document/tree op types (0x11-0x24) all exceeded CRABS_OT_OP_TYPE_COUNT,
// the lookup returned NULL, and concurrent ops were applied untransformed
// (divergent documents). The mapping:
//   INSERT_TEXT/INSERT_NODE -> INSERT, DELETE_RANGE/DELETE_NODE -> DELETE,
//   STYLE/MERGE_SPANS/SPLIT_SPAN -> UPDATE, REPARENT -> MOVE,
//   REORDER -> SWAP. Unknown types fall back to themselves (base lookup).
static crabs_ot_op_type_e _base_op_type(crabs_ot_op_type_e t) {
  switch (t) {
    case CRABS_OT_OP_INSERT_TEXT:
    case CRABS_OT_OP_INSERT_NODE:
      return CRABS_OT_OP_INSERT;
    case CRABS_OT_OP_DELETE_RANGE:
    case CRABS_OT_OP_DELETE_NODE:
      return CRABS_OT_OP_DELETE;
    case CRABS_OT_OP_STYLE:
    case CRABS_OT_OP_MERGE_SPANS:
    case CRABS_OT_OP_SPLIT_SPAN:
      return CRABS_OT_OP_UPDATE;
    case CRABS_OT_OP_REPARENT:
      return CRABS_OT_OP_MOVE;
    case CRABS_OT_OP_REORDER:
      return CRABS_OT_OP_SWAP;
    default:
      return t; // base types (1..6) and COMPACT pass through
  }
}

crabs_ot_transform_fn crabs_ot_data_item_get_transform(const crabs_ot_data_item_t* item,
                                                        crabs_ot_op_type_e type1,
                                                        crabs_ot_op_type_e type2) {
  if (item == NULL) return NULL;
  // Map concrete op types onto base transform semantics before lookup.
  crabs_ot_op_type_e b1 = _base_op_type(type1);
  crabs_ot_op_type_e b2 = _base_op_type(type2);
  if (b1 < 1 || b1 > CRABS_OT_OP_TYPE_COUNT) return NULL;
  if (b2 < 1 || b2 > CRABS_OT_OP_TYPE_COUNT) return NULL;
  return item->transform_matrix[b1 - 1][b2 - 1];
}