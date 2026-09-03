//
// Created by victor on 9/3/25.
//
// Scheduler: timed transactions. Pending operations are stored durably in
// the state (serialized with crabs_serialize_state) and materialized when a
// node's authenticated clock passes the scheduled time.
//

#include "scheduler.h"
#include <stdlib.h>
#include <string.h>
#include "../Util/allocator.h"
#include "../Serialization/serialization.h"
#include "../StateMachine/state_machine.h"

uint32_t scheduler_count(const state_t* state) {
  if (state == NULL) return 0;
  uint32_t count = 0;
  for (const scheduled_operation_t* entry = state->scheduled_operations;
       entry != NULL; entry = entry->next) {
    count++;
  }
  return count;
}

const scheduled_operation_t* scheduler_first(const state_t* state) {
  return state ? state->scheduled_operations : NULL;
}

uint64_t scheduler_schedule(state_t* state, uint64_t execute_at_ms,
                            const char* submitter, const operation_t* op) {
  if (state == NULL || op == NULL || submitter == NULL || submitter[0] == '\0') {
    return 0;
  }

  serialized_buffer_t* serialized = crabs_serialize_operation(op);
  if (serialized == NULL) return 0;

  scheduled_operation_t* entry =
      (scheduled_operation_t*)get_clear_memory(sizeof(scheduled_operation_t));
  entry->schedule_id = ++state->schedule_seq;
  entry->execute_at_ms = execute_at_ms;
  strncpy(entry->submitter, submitter, CRABS_MAX_USER_ID - 1);
  entry->op_len = serialized->len;
  entry->op_bytes = (uint8_t*)get_clear_memory(serialized->len);
  memcpy(entry->op_bytes, serialized->data, serialized->len);
  serialized_buffer_destroy(serialized);

  // Append at the tail so the list follows submission order; due entries
  // are materialized in list order by scheduler_process_due.
  if (state->scheduled_operations == NULL) {
    state->scheduled_operations = entry;
  } else {
    scheduled_operation_t* tail = state->scheduled_operations;
    while (tail->next != NULL) tail = tail->next;
    tail->next = entry;
  }
  return entry->schedule_id;
}

crabs_error_e scheduler_cancel(state_t* state, uint64_t schedule_id) {
  if (state == NULL) return CRABS_ERR_INVALID_PARAM;
  scheduled_operation_t** link = &state->scheduled_operations;
  while (*link != NULL) {
    if ((*link)->schedule_id == schedule_id) {
      scheduled_operation_t* removed = *link;
      *link = removed->next;
      free(removed->op_bytes);
      free(removed);
      return CRABS_SUCCESS;
    }
    link = &(*link)->next;
  }
  return CRABS_ERR_RESOURCE_NOT_FOUND;
}

void scheduler_destroy_all(state_t* state) {
  if (state == NULL) return;
  scheduled_operation_t* entry = state->scheduled_operations;
  while (entry != NULL) {
    scheduled_operation_t* next_entry = entry->next;
    free(entry->op_bytes);
    free(entry);
    entry = next_entry;
  }
  state->scheduled_operations = NULL;
}

static bool _uuid_in_log(const state_t* state, const uint8_t uuid[CRABS_UUID_SIZE]) {
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (memcmp(state->log[entry_index].uuid, uuid, CRABS_UUID_SIZE) == 0) {
      return true;
    }
  }
  return false;
}

crabs_error_e scheduler_process_due(state_t* state, uint64_t now_ms) {
  if (state == NULL) return CRABS_ERR_INVALID_PARAM;

  // Snapshot the due ids first so cancellation during materialization
  // cannot skip or double-process entries. At most
  // CRABS_SCHEDULER_MAX_DUE_PER_TICK entries materialize per tick; anything
  // beyond the cap simply stays pending until the next tick.
  uint64_t due_ids[CRABS_SCHEDULER_MAX_DUE_PER_TICK];
  uint32_t due_count = 0;
  for (const scheduled_operation_t* entry = state->scheduled_operations;
       entry != NULL && due_count < CRABS_SCHEDULER_MAX_DUE_PER_TICK;
       entry = entry->next) {
    if (entry->execute_at_ms <= now_ms) {
      due_ids[due_count++] = entry->schedule_id;
    }
  }

  for (uint32_t due_index = 0; due_index < due_count; due_index++) {
    uint64_t schedule_id = due_ids[due_index];
    scheduled_operation_t** link = &state->scheduled_operations;
    scheduled_operation_t* entry = NULL;
    while (*link != NULL) {
      if ((*link)->schedule_id == schedule_id) {
        entry = *link;
        break;
      }
      link = &(*link)->next;
    }
    if (entry == NULL) continue;  // cancelled during this tick

    // Remove from the pending list FIRST (idempotency guard — replaces the
    // R7-11 ordering check for scheduled materializations).
    *link = entry->next;

    operation_t* embedded = crabs_deserialize_operation(entry->op_bytes, entry->op_len);
    if (embedded == NULL) {
      // Undecodable bytes: record with a zero uuid (the op identity is not
      // recoverable) and the submitter as the log signer.
      uint8_t zero_uuid[CRABS_UUID_SIZE];
      memset(zero_uuid, 0, sizeof(zero_uuid));
      state_machine_log_schedule_failure(state, zero_uuid, entry->submitter);
      free(entry->op_bytes);
      free(entry);
      continue;
    }

    // Already applied via replication? Idempotent skip.
    if (_uuid_in_log(state, embedded->uuid)) {
      operation_destroy(embedded);
      free(entry->op_bytes);
      free(entry);
      continue;
    }

    // Internal execution: authorization was enforced at submission.
    // state_machine_execute_scheduled passes process_schedules=false, so the
    // tick inside the materialized op's execute pipeline does NOT re-enter
    // scheduler_process_due — no recursion while materializing.
    crabs_error_e materialize_rc =
        state_machine_execute_scheduled(state, embedded);
    if (materialize_rc != CRABS_SUCCESS) {
      // Durable failure record keyed by the embedded op's uuid, so all nodes
      // agree the schedule resolved as failed and the devtools Timeline can
      // show it. The record is LAMPORT-ordered with lamport 0, so it never
      // blocks the signer's later ops (HLC sorts after lamport; lamport
      // signers already need lamport > their signed value).
      state_machine_log_schedule_failure(state, embedded->uuid, embedded->signer_id);
    }
    operation_destroy(embedded);
    free(entry->op_bytes);
    free(entry);
  }
  return CRABS_SUCCESS;
}
