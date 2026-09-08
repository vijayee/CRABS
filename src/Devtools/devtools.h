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

// Record a state change into the devtools ring. Layered recorder for the
// state change hook (dev builds only).
void     devtools_record_change(state_t* state, const crabs_change_event_t* event);

// Drain the ring buffer as a JSON array string, oldest first. The buffer is
// emptied. Caller owns the returned string.
char*    devtools_events_json(void);

// Drain only the events whose node_id equals the given id; events belonging
// to other nodes are preserved in the ring (in order) for their owner's later
// drain. A NULL node_id matches every event (equivalent to
// devtools_events_json). Caller owns the returned string, which is NULL when
// the internal copy cannot be allocated (the ring is left intact).
char*    devtools_events_json_for(const char* node_id);

// Render the full state as a JSON document string. Caller owns the string.
char*    devtools_snapshot_json(const state_t* state);

// Free a string returned by devtools_events_json or devtools_snapshot_json.
void     devtools_string_destroy(char* str);

// Number of events currently held in the ring buffer.
uint32_t devtools_ring_count(void);

#endif // CRABS_DEVTOOLS_H
