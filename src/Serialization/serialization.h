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

// ============================================================
// Magic bytes and format version (§13.1)
// ============================================================
#define CRABS_SERIAL_MAGIC      0x42415243  // "CRAB" in little-endian
#define CRABS_SERIAL_VERSION    1

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

#endif // CRABS_SERIALIZATION_H