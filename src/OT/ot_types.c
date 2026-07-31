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
  return a->sequence_num == b->sequence_num &&
         a->timestamp == b->timestamp &&
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

void crabs_ot_operation_add_dep(crabs_ot_operation_t* op,
                                const crabs_ot_op_id_t* dep) {
  if (op == NULL || dep == NULL) return;
  if (op->dep_count >= CRABS_OT_MAX_DEPS) return;
  op->deps[op->dep_count] = *dep;
  op->dep_count++;
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
    crabs_ot_operation_t* new_log = get_clear_memory(sizeof(crabs_ot_operation_t) * new_cap);
    if (new_log == NULL) return NULL;
    memcpy(new_log, item->op_log, sizeof(crabs_ot_operation_t) * item->op_log_count);
    free(item->op_log);
    item->op_log = new_log;
    item->op_log_capacity = new_cap;
  }
  crabs_ot_operation_t* op = &item->op_log[item->op_log_count];
  crabs_ot_operation_init(op);
  item->op_log_count++;
  return op;
}

uint64_t crabs_ot_data_item_next_priority(crabs_ot_data_item_t* item,
                                           const char* node_id) {
  if (item == NULL || node_id == NULL) return 0;
  // Priority is the total op count + 1 (operations are ordered by insertion)
  return (uint64_t)item->op_log_count + 1;
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

crabs_ot_transform_fn crabs_ot_data_item_get_transform(const crabs_ot_data_item_t* item,
                                                        crabs_ot_op_type_e type1,
                                                        crabs_ot_op_type_e type2) {
  if (item == NULL) return NULL;
  if (type1 < 1 || type1 > CRABS_OT_OP_TYPE_COUNT) return NULL;
  if (type2 < 1 || type2 > CRABS_OT_OP_TYPE_COUNT) return NULL;
  return item->transform_matrix[type1 - 1][type2 - 1];
}