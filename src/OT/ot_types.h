//
// Created by victor on 5/1/25.
//
// OT Operation Types & Core Structs (v1.5 §3.2, §3.4)
// Defines the core data structures for Operational Transform operations
// in the OT/CRDT hybrid type system.
//

#ifndef CRABS_OT_TYPES_H
#define CRABS_OT_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../CRABS/crabs.h"
#include "position_map.h"

// ============================================================
// OT Operation Types (v1.5 §3.2)
// ============================================================

typedef enum {
  CRABS_OT_OP_INSERT  = 0x01,
  CRABS_OT_OP_DELETE  = 0x02,
  CRABS_OT_OP_UPDATE  = 0x03,
  CRABS_OT_OP_MOVE    = 0x04,
  CRABS_OT_OP_SWAP    = 0x05,
  CRABS_OT_OP_COMPACT = 0x06,  // v1.6 §3: Tombstone compaction operation
  // Document type-specific operations
  CRABS_OT_OP_INSERT_TEXT  = 0x11,
  CRABS_OT_OP_DELETE_RANGE = 0x12,
  CRABS_OT_OP_STYLE        = 0x13,
  CRABS_OT_OP_MERGE_SPANS  = 0x14,
  CRABS_OT_OP_SPLIT_SPAN   = 0x15,
  // Tree type-specific operations
  CRABS_OT_OP_INSERT_NODE  = 0x21,
  CRABS_OT_OP_DELETE_NODE  = 0x22,
  CRABS_OT_OP_REPARENT     = 0x23,
  CRABS_OT_OP_REORDER      = 0x24,
} crabs_ot_op_type_e;

#define CRABS_OT_OP_TYPE_COUNT 15

// ============================================================
// OT Operation ID (v1.5 §3.2)
// ============================================================

typedef struct {
  char     node_id[CRABS_MAX_USER_ID];
  uint64_t sequence_num;
  uint64_t timestamp;
} crabs_ot_op_id_t;

// ============================================================
// OT Operation (v1.5 §3.4)
// ============================================================

#define CRABS_OT_MAX_DEPS 16
#define CRABS_OT_MAX_PAYLOAD 4096

typedef struct crabs_ot_operation {
  crabs_ot_op_id_t  id;
  crabs_ot_op_type_e op_type;
  uint64_t visible_pos;
  uint64_t visible_pos_2;    // Second position for MOVE/SWAP
  uint8_t* payload;
  uint32_t payload_size;
  uint64_t priority;
  crabs_ot_op_id_t deps[CRABS_OT_MAX_DEPS];
  uint32_t dep_count;
  uint32_t transform_fn_id;
} crabs_ot_operation_t;

// ============================================================
// Transform Function (v1.5 §3.4)
// ============================================================

typedef crabs_ot_operation_t* (*crabs_ot_transform_fn)(
  crabs_ot_operation_t* op1,
  crabs_ot_operation_t* op2);

#define CRABS_OT_TRANSFORM_MATRIX_SIZE CRABS_OT_OP_TYPE_COUNT

// ============================================================
// OT Data Item (v1.5 §3.4)
// ============================================================

#define CRABS_OT_OP_LOG_INITIAL 16
// Hard cap on the op-log capacity to avoid a huge allocation from untrusted
// config (e.g. a malicious __change_config__ setting max_op_log_size to 1e9).
#define CRABS_OT_OP_LOG_MAX 1048576

typedef struct {
  uint32_t              ot_type_id;
  crabs_bst_node_t*     position_map;
  crabs_ot_operation_t* op_log;
  uint32_t              op_log_count;
  uint32_t              op_log_capacity;
  uint64_t*             priority_counters;
  uint32_t              priority_counter_count;
  crabs_ot_transform_fn transform_matrix[CRABS_OT_TRANSFORM_MATRIX_SIZE]
                                         [CRABS_OT_TRANSFORM_MATRIX_SIZE];
} crabs_ot_data_item_t;

// ============================================================
// OT Op ID Functions
// ============================================================

void crabs_ot_op_id_init(crabs_ot_op_id_t* id, const char* node_id,
                         uint64_t sequence_num, uint64_t timestamp);
bool crabs_ot_op_id_equal(const crabs_ot_op_id_t* a, const crabs_ot_op_id_t* b);

// ============================================================
// OT Operation Functions
// ============================================================

crabs_ot_operation_t* crabs_ot_operation_create(void);
void crabs_ot_operation_destroy(crabs_ot_operation_t* op);
void crabs_ot_operation_init(crabs_ot_operation_t* op);
// Free only an op's owned payload and zero the slot, WITHOUT freeing the op
// struct itself. Use this for ops that live inside an array allocation (e.g.
// ot_data->op_log[]) — calling crabs_ot_operation_destroy on such entries
// would free an interior pointer (heap corruption).
void crabs_ot_operation_clear(crabs_ot_operation_t* op);
bool crabs_ot_operation_set_payload(crabs_ot_operation_t* op,
                                    const uint8_t* data, uint32_t size);
// Audit N-16: returns true if the dependency was added, false if the dep
// array is full (CRABS_OT_MAX_DEPS). The caller must fail the operation on
// false to avoid silently dropping causality.
bool crabs_ot_operation_add_dep(crabs_ot_operation_t* op,
                                const crabs_ot_op_id_t* dep);
const char* crabs_ot_op_type_name(crabs_ot_op_type_e type);

// ============================================================
// OT Data Item Functions
// ============================================================

crabs_ot_data_item_t* crabs_ot_data_item_create(uint32_t ot_type_id);
void crabs_ot_data_item_destroy(crabs_ot_data_item_t* item);
crabs_ot_operation_t* crabs_ot_data_item_append_op(crabs_ot_data_item_t* item);
uint64_t crabs_ot_data_item_next_priority(crabs_ot_data_item_t* item,
                                          const char* node_id);
void crabs_ot_data_item_set_transform(crabs_ot_data_item_t* item,
                                      crabs_ot_op_type_e type1,
                                      crabs_ot_op_type_e type2,
                                      crabs_ot_transform_fn fn);
crabs_ot_transform_fn crabs_ot_data_item_get_transform(const crabs_ot_data_item_t* item,
                                                        crabs_ot_op_type_e type1,
                                                        crabs_ot_op_type_e type2);

#endif // CRABS_OT_TYPES_H