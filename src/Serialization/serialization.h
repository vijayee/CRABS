//
// Created by victor on 4/30/25.
//

#ifndef CRABS_SERIALIZATION_H
#define CRABS_SERIALIZATION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "../StateMachine/state_machine.h"
#include "../OT/ot_types.h"
#include "../OT/position_map.h"

// ============================================================
// Magic bytes and format version (§13.1)
// ============================================================
#define CRABS_SERIAL_MAGIC      0x42415243  // "CRAB" in little-endian
#define CRABS_SERIAL_VERSION    4           // v4: adds OT data item serialization

// ============================================================
// Serialized buffer
// ============================================================
typedef struct {
  uint8_t* data;
  size_t   len;
} serialized_buffer_t;

// ============================================================
// State serialization (§13.1)
// ============================================================
serialized_buffer_t* crabs_serialize_state(const state_t* state);
state_t*             crabs_deserialize_state(const uint8_t* data, size_t len);

// ============================================================
// Operation serialization (§7.5)
// ============================================================
serialized_buffer_t* crabs_serialize_operation(const operation_t* op);
operation_t*         crabs_deserialize_operation(const uint8_t* data, size_t len);

// ============================================================
// Canonical encoding for signing (§7.5)
// ============================================================
serialized_buffer_t* crabs_serialize_for_signing(const operation_t* op);

// ============================================================
// Buffer helpers
// ============================================================
serialized_buffer_t* serialized_buffer_create(size_t len);
void                 serialized_buffer_destroy(serialized_buffer_t* buf);

// ============================================================
// OT Serialization (v1.5 §9)
// ============================================================

// Serialize/deserialize an OT operation
serialized_buffer_t* crabs_serialize_ot_op(const crabs_ot_operation_t* op);
crabs_ot_operation_t* crabs_deserialize_ot_op(const uint8_t* data, size_t len);

// Serialize/deserialize an OT operation log (array of ops)
serialized_buffer_t* crabs_serialize_ot_op_log(const crabs_ot_operation_t* ops, uint32_t count);
uint32_t crabs_deserialize_ot_op_log(const uint8_t* data, size_t len,
                                      crabs_ot_operation_t** ops_out);

// Serialize/deserialize a BST position map
serialized_buffer_t* crabs_serialize_bst(const crabs_bst_node_t* root);
crabs_bst_node_t*    crabs_deserialize_bst(const uint8_t* data, size_t len);

// Serialize/deserialize an OT data item (op_log, position_map, priority_counters)
serialized_buffer_t* crabs_serialize_ot_data(const crabs_ot_data_item_t* item);
crabs_ot_data_item_t* crabs_deserialize_ot_data(const uint8_t* data, size_t len, uint32_t ot_type_id);

#endif // CRABS_SERIALIZATION_H