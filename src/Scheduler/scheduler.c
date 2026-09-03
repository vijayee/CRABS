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
  if (entry == NULL) {
    serialized_buffer_destroy(serialized);
    return 0;
  }
  entry->schedule_id = ++state->schedule_seq;
  entry->execute_at_ms = execute_at_ms;
  strncpy(entry->submitter, submitter, CRABS_MAX_USER_ID - 1);
  entry->op_len = serialized->len;
  entry->op_bytes = (uint8_t*)get_clear_memory(serialized->len);
  if (entry->op_bytes == NULL) {
    serialized_buffer_destroy(serialized);
    free(entry);
    return 0;
  }
  memcpy(entry->op_bytes, serialized->data, serialized->len);
  serialized_buffer_destroy(serialized);

  // Append at the tail so the list follows submission order; due entries
  // are materialized in execute_at order by scheduler_process_due.
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

crabs_error_e scheduler_process_due(state_t* state, uint64_t now_ms) {
  (void)state;
  (void)now_ms;
  return CRABS_SUCCESS;  // implemented in Task 4
}
