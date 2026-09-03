//
// Created by victor on 9/3/25.
//

#ifndef CRABS_SCHEDULER_H
#define CRABS_SCHEDULER_H

#include <stdint.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "../StateMachine/state_machine.h"

#define CRABS_SCHEDULER_MAX_DUE_PER_TICK 64

// Add a pending scheduled operation. `op` is the embedded operation (already
// fully signed by its authorizer); it is serialized with
// crabs_serialize_operation and stored. Returns the new schedule_id, or 0 on
// invalid input (NULL state/op, empty submitter) or serialization failure.
// The caller keeps ownership of `op`.
uint64_t scheduler_schedule(state_t* state, uint64_t execute_at_ms,
                            const char* submitter, const operation_t* op);

// Remove a pending schedule by id. CRABS_ERR_RESOURCE_NOT_FOUND when absent.
crabs_error_e scheduler_cancel(state_t* state, uint64_t schedule_id);

// Number of pending schedules.
uint32_t scheduler_count(const state_t* state);

// Head of the pending list in submission order (also after restore).
// NULL when empty.
const scheduled_operation_t* scheduler_first(const state_t* state);

// Materialize every pending schedule whose execute_at_ms <= now_ms.
// Failures are recorded as __schedule_failed__ log entries and never
// propagated. Returns CRABS_SUCCESS.
crabs_error_e scheduler_process_due(state_t* state, uint64_t now_ms);

// Free the entire pending list (called from state_destroy).
void scheduler_destroy_all(state_t* state);

#endif // CRABS_SCHEDULER_H
