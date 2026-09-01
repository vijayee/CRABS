//
// Created by victor on 9/1/25.
//

#ifndef CRABS_DEVTOOLS_H
#define CRABS_DEVTOOLS_H

#include <stdint.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "../StateMachine/state_machine.h"

#define CRABS_DEVTOOLS_RING_SIZE 1024

// Record one execute outcome into the global devtools ring buffer.
// No-op unless the build defines CRABS_ENABLE_DEVTOOLS.
void     devtools_record_event(state_t* state, const operation_t* op, crabs_error_e result);

// Drain the ring buffer as a JSON array string, oldest first. The buffer is
// emptied. Caller owns the returned string.
char*    devtools_events_json(void);

// Render the full state as a JSON document string. Caller owns the string.
char*    devtools_snapshot_json(const state_t* state);

// Free a string returned by devtools_events_json or devtools_snapshot_json.
void     devtools_string_destroy(char* str);

// Number of events currently held in the ring buffer.
uint32_t devtools_ring_count(void);

#endif // CRABS_DEVTOOLS_H
