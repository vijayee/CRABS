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

// Default ceiling on scheduled occurrences materialized per tick. Bounds the
// work a single tick does when catching up after a long offline window; the
// remainder carries over to subsequent ticks (nothing is dropped). Node-local
// runtime policy — override with scheduler_set_max_occurrences_per_tick, 0 =
// unlimited. Not part of the serialized state.
#define CRABS_SCHEDULER_DEFAULT_MAX_OCCURRENCES_PER_TICK 64

// Add a pending scheduled operation. `op` is the embedded operation (already
// fully signed by its authorizer); it is serialized with
// crabs_serialize_operation and stored. Returns the new schedule_id, or 0 on
// invalid input (NULL state/op, empty submitter) or serialization failure.
// The caller keeps ownership of `op`.
uint64_t scheduler_schedule(state_t* state, uint64_t execute_at_ms,
                            const char* submitter, const operation_t* op);

// Add a recurring pending schedule: fires at start_at_ms, then every
// interval_ms, until repeat_count fires have happened (0 = infinite) or
// execute_at passes end_at_ms (0 = none), whichever comes first. Same
// ownership/return semantics as scheduler_schedule (0 on invalid input).
uint64_t scheduler_schedule_recurring(state_t* state, uint64_t start_at_ms,
                                      uint64_t interval_ms, uint64_t repeat_count,
                                      uint64_t end_at_ms, const char* submitter,
                                      const operation_t* op);

// Remove a pending schedule by id. CRABS_ERR_RESOURCE_NOT_FOUND when absent.
crabs_error_e scheduler_cancel(state_t* state, uint64_t schedule_id);

// Number of pending schedules.
uint32_t scheduler_count(const state_t* state);

// Head of the pending list in submission order (also after restore).
// NULL when empty.
const scheduled_operation_t* scheduler_first(const state_t* state);

// Materialize every pending schedule whose execute_at_ms <= now_ms.
// Failures are recorded as __schedule_failed__ log entries and never
// propagated; CRABS_ERR_ALREADY_EXECUTED from the materialized op is treated
// as an idempotent skip. Re-entrant calls (a materialized handler invoking
// state_machine_execute, which ticks) are deferred to the enclosing tick.
// At most state->max_occurrences_per_tick occurrences materialize per tick;
// the rest carry over (entries stay pending, cadence keeps its position).
// Returns CRABS_SUCCESS.
crabs_error_e scheduler_process_due(state_t* state, uint64_t now_ms);

// Override the per-tick occurrence ceiling (node-local runtime policy; not
// serialized, so a restored state reverts to
// CRABS_SCHEDULER_DEFAULT_MAX_OCCURRENCES_PER_TICK). 0 = unlimited.
void scheduler_set_max_occurrences_per_tick(state_t* state, uint32_t max_occurrences);

// Free the entire pending list (called from state_destroy).
void scheduler_destroy_all(state_t* state);

#endif // CRABS_SCHEDULER_H
