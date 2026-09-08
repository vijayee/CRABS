//
// Created by victor on 9/3/25.
//
// Scheduler: timed transactions. Pending operations are stored durably in
// the state (serialized with crabs_serialize_state) and materialized when a
// node's authenticated clock passes the scheduled time.
//

#include "scheduler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../Util/allocator.h"
#include "../Crypto/crypto.h"
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

void scheduler_set_max_occurrences_per_tick(state_t* state, uint32_t max_occurrences) {
  if (state == NULL) return;
  state->max_occurrences_per_tick = max_occurrences;
}

// Shared tail of scheduler_schedule / scheduler_schedule_recurring: serialize
// the op, allocate the entry, append at the tail. interval/repeat/end are the
// cadence fields (one-shot callers pass interval 0, repeat 1, end 0).
static uint64_t _append_schedule(state_t* state, uint64_t execute_at_ms,
                                 const char* submitter, const operation_t* op,
                                 uint64_t interval_ms, uint64_t repeat_count,
                                 uint64_t end_at_ms) {
  serialized_buffer_t* serialized = crabs_serialize_operation(op);
  if (serialized == NULL) return 0;

  scheduled_operation_t* entry =
      (scheduled_operation_t*)get_clear_memory(sizeof(scheduled_operation_t));
  entry->schedule_id = ++state->schedule_seq;
  entry->execute_at_ms = execute_at_ms;
  entry->interval_ms = interval_ms;
  entry->repeat_count = repeat_count;
  entry->end_at_ms = end_at_ms;
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

  // Submission mutates the durable pending set, so it reports a change like
  // every other mutation path; the devtools Timeline shows the entry as soon
  // as it is queued, before any slot materializes.
  char schedule_preview[96];
  snprintf(schedule_preview, sizeof(schedule_preview), "scheduled at %llu",
           (unsigned long long)execute_at_ms);
  state_notify_change(state, CRABS_CHANGE_SCHEDULE, op->type, op->uuid,
                      submitter, NULL,
                      op->resource_count > 0 && op->resources
                          ? op->resources[0]
                          : NULL,
                      schedule_preview, CRABS_SUCCESS);
  return entry->schedule_id;
}

uint64_t scheduler_schedule(state_t* state, uint64_t execute_at_ms,
                            const char* submitter, const operation_t* op) {
  if (state == NULL || op == NULL || submitter == NULL || submitter[0] == '\0') {
    return 0;
  }
  return _append_schedule(state, execute_at_ms, submitter, op, 0, 1, 0);
}

uint64_t scheduler_schedule_recurring(state_t* state, uint64_t start_at_ms,
                                      uint64_t interval_ms, uint64_t repeat_count,
                                      uint64_t end_at_ms, const char* submitter,
                                      const operation_t* op) {
  if (state == NULL || op == NULL || submitter == NULL || submitter[0] == '\0') {
    return 0;
  }
  if (interval_ms == 0) return 0;                       // recurring requires a cadence
  if (end_at_ms != 0 && end_at_ms <= start_at_ms) return 0;
  return _append_schedule(state, start_at_ms, submitter, op,
                          interval_ms, repeat_count, end_at_ms);
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

// Re-find a pending entry by schedule_id. Returns the link slot that holds
// the entry (usable for unlinking) and sets *found_entry, or NULL when the
// id is absent (cancelled). Matching by id — never by node pointer — is what
// makes this safe against a cancel-then-reschedule during materialization:
// schedule ids are monotonically increasing and never reused, so a freshly
// allocated entry can never collide with a cancelled one's id.
static scheduled_operation_t** _find_schedule_link(
    state_t* state, uint64_t schedule_id, scheduled_operation_t** found_entry) {
  scheduled_operation_t** link_slot = &state->scheduled_operations;
  while (*link_slot != NULL) {
    if ((*link_slot)->schedule_id == schedule_id) {
      *found_entry = *link_slot;
      return link_slot;
    }
    link_slot = &(*link_slot)->next;
  }
  return NULL;
}

crabs_error_e scheduler_process_due(state_t* state, uint64_t now_ms) {
  if (state == NULL) return CRABS_ERR_INVALID_PARAM;

  if (state->scheduler_ticking) {
    // A materialized handler re-entered the tick — defer to the enclosing
    // tick instead of recursing (bounds stack depth; due work still runs
    // because the outer tick keeps processing its snapshot).
    return CRABS_SUCCESS;
  }
  state->scheduler_ticking = true;

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

  // Occurrence budget (audit follow-up: unbounded catch-up burst). A node
  // returning online after a long gap would otherwise materialize every
  // missed slot in a single tick. The budget caps FIRES per tick (one-shots
  // and recurring slots alike); deferred work carries over because deferred
  // entries stay pending with their cadence position intact. 0 = unlimited.
  uint32_t fires_this_tick = 0;

  for (uint32_t due_index = 0; due_index < due_count; due_index++) {
    if (state->max_occurrences_per_tick != 0 &&
        fires_this_tick >= state->max_occurrences_per_tick) {
      break;  // budget exhausted: remaining due entries stay pending
    }
    uint64_t schedule_id = due_ids[due_index];
    scheduled_operation_t* entry = NULL;
    scheduled_operation_t** link =
        _find_schedule_link(state, schedule_id, &entry);
    if (link == NULL) continue;  // cancelled during this tick

    if (entry->interval_ms == 0) {
      // ---- one-shot: remove from the pending list FIRST (idempotency guard
      // ---- — replaces the R7-11 ordering check for scheduled
      // ---- materializations), then materialize exactly once.
      *link = entry->next;

      operation_t* embedded =
          crabs_deserialize_operation(entry->op_bytes, entry->op_len);
      if (embedded == NULL) {
        // Undecodable bytes: the op identity is not recoverable, so record
        // with a RANDOM uuid and the submitter as the log signer. A random
        // uuid prevents a permanent collision with any later all-zero-uuid op.
        uint8_t failure_uuid[CRABS_UUID_SIZE];
        if (crypto_random_bytes(failure_uuid, CRABS_UUID_SIZE) != CRABS_SUCCESS) {
          memset(failure_uuid, 0, sizeof(failure_uuid));  // best effort only
        }
        state_machine_log_schedule_failure(state, failure_uuid, entry->submitter);
        state_notify_change(state, CRABS_CHANGE_SCHEDULE, "__schedule_failed__",
                            failure_uuid, entry->submitter, NULL, NULL,
                            "schedule failed; durable failure recorded",
                            CRABS_ERR_INTERNAL);
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
      // scheduler_process_due — no recursion while materializing. (Custom
      // handlers can still re-enter via state_machine_execute; the
      // scheduler_ticking guard above defers those to this tick.)
      crabs_error_e materialize_rc =
          state_machine_execute_scheduled(state, embedded);
      fires_this_tick++;
      if (materialize_rc == CRABS_ERR_ALREADY_EXECUTED) {
        // The tx_manager accepted the uuid elsewhere (persistent store case):
        // treat as idempotent success, not a failure.
        operation_destroy(embedded);
        free(entry->op_bytes);
        free(entry);
        continue;
      }
      if (materialize_rc != CRABS_SUCCESS) {
        // Durable failure record keyed by the embedded op's uuid, so all nodes
        // agree the schedule resolved as failed and the devtools Timeline can
        // show it. The record is LAMPORT-ordered with lamport 0, so it never
        // blocks the signer's later ops (HLC sorts after lamport; lamport
        // signers already need lamport > their signed value).
        state_machine_log_schedule_failure(state, embedded->uuid, embedded->signer_id);
        state_notify_change(state, CRABS_CHANGE_SCHEDULE, "__schedule_failed__",
                            embedded->uuid, embedded->signer_id, NULL, NULL,
                            "schedule failed; durable failure recorded",
                            CRABS_ERR_INTERNAL);
      }
      operation_destroy(embedded);
      free(entry->op_bytes);
      free(entry);
      continue;
    }

    // ---- recurring: fire ALL due slots in order; the entry stays resident
    // ---- until the series terminates (count exhausted, past end_at, or the
    // ---- embedded bytes prove undecodable). repeat_count is "remaining
    // ---- fires" where 0 = INFINITE (never decremented when 0); a finite
    // ---- series counts down and is removed the instant its count hits 0
    // ---- after a fire.
    bool bytes_corrupt = false;
    bool series_exhausted = false;
    while (entry->execute_at_ms <= now_ms) {
      if (entry->end_at_ms != 0 && entry->execute_at_ms > entry->end_at_ms) break;

      // Budget check BEFORE the fire: breaking here leaves execute_at_ms on
      // the not-yet-fired slot, so the series resumes exactly where it left
      // off on the next tick (no slot skipped, no slot double-fired).
      if (state->max_occurrences_per_tick != 0 &&
          fires_this_tick >= state->max_occurrences_per_tick) {
        break;
      }

      // Overflow guard: execute_at += interval must not wrap (a hostile
      // UINT64_MAX interval would wrap to a small value and re-fire).
      if (entry->interval_ms > UINT64_MAX - entry->execute_at_ms) break;

      operation_t* occurrence =
          crabs_deserialize_operation(entry->op_bytes, entry->op_len);
      if (occurrence == NULL) {
        // Undecodable bytes: the op identity is not recoverable, so record
        // with a RANDOM uuid and the submitter as the log signer (same
        // reasoning as the one-shot path). Undecodable bytes would re-fail
        // on every slot forever, so the series terminates here.
        uint8_t failure_uuid[CRABS_UUID_SIZE];
        if (crypto_random_bytes(failure_uuid, CRABS_UUID_SIZE) != CRABS_SUCCESS) {
          memset(failure_uuid, 0, sizeof(failure_uuid));  // best effort only
        }
        state_machine_log_schedule_failure(state, failure_uuid, entry->submitter);
        state_notify_change(state, CRABS_CHANGE_SCHEDULE, "__schedule_failed__",
                            failure_uuid, entry->submitter, NULL, NULL,
                            "schedule failed; durable failure recorded",
                            CRABS_ERR_INTERNAL);
        bytes_corrupt = true;
        break;
      }
      // Occurrence identity: the embedded uuid XORed with this slot's
      // execute_at_ms (little-endian, into the first 8 bytes). Distinct per
      // slot AND stable across ticks — keying the bare embedded uuid would
      // collide with the log entry an earlier tick's fire wrote (the per-tick
      // fire index resets, so only a multi-fire catch-up tick got fresh
      // identities) and skip every later slot of the series. Injective per
      // entry: XOR with the strictly increasing execute_at values maps the
      // same embedded uuid to distinct uuids. SAFE: materialization skips
      // signature verification — authorization happened at submission, so a
      // derived uuid cannot break any signature check.
      for (uint32_t uuid_byte_index = 0; uuid_byte_index < 8; uuid_byte_index++) {
        occurrence->uuid[uuid_byte_index] ^=
            (uint8_t)(entry->execute_at_ms >> (8 * uuid_byte_index));
      }
      if (_uuid_in_log(state, occurrence->uuid)) {
        // Already applied via replication? Idempotent skip (still advances
        // the cadence below).
        operation_destroy(occurrence);
      } else {
        crabs_error_e fire_rc = state_machine_execute_scheduled(state, occurrence);
        if (fire_rc != CRABS_SUCCESS && fire_rc != CRABS_ERR_ALREADY_EXECUTED) {
          // A failed slot does NOT terminate the series: durable failure
          // record keyed by the occurrence's uuid, cadence keeps advancing.
          state_machine_log_schedule_failure(state, occurrence->uuid,
                                             occurrence->signer_id);
          state_notify_change(state, CRABS_CHANGE_SCHEDULE, "__schedule_failed__",
                              occurrence->uuid, occurrence->signer_id, NULL,
                              NULL, "schedule failed; durable failure recorded",
                              CRABS_ERR_INTERNAL);
        }
        operation_destroy(occurrence);
        fires_this_tick++;
      }

      // A handler may have cancelled the entry during the fire — re-find by
      // id BEFORE touching it again (scheduler_cancel unlinks AND frees the
      // entry, so the cadence fields below would read freed memory). Breaking
      // here (instead of returning) keeps the single function exit, so the
      // re-entrancy guard is always cleared; the termination re-find after
      // the loop then observes the unlink and moves on to the next due id.
      scheduled_operation_t* recheck_entry = NULL;
      scheduled_operation_t** mid_link =
          _find_schedule_link(state, schedule_id, &recheck_entry);
      if (mid_link == NULL) break;  // cancelled mid-series: entry already freed
      entry = recheck_entry;

      // Advance cadence + bookkeeping (safe: the re-find above confirmed the
      // entry is still linked). Decrement ONLY finite counts (0 stays 0 =
      // INFINITE forever).
      entry->execute_at_ms += entry->interval_ms;
      if (entry->repeat_count != 0) {
        entry->repeat_count--;
        if (entry->repeat_count == 0) {
          series_exhausted = true;  // last allowed fire consumed
          break;
        }
      }
      if (entry->end_at_ms != 0 && entry->execute_at_ms > entry->end_at_ms) break;

      // No second re-find here: nothing runs between this point and the loop
      // condition that could free the entry.
    }

    // Termination removal: re-find by schedule id first (a handler may have
    // cancelled the entry, unlinking and freeing it).
    scheduled_operation_t** recheck =
        _find_schedule_link(state, schedule_id, &entry);
    if (recheck == NULL) continue;

    bool past_end = (entry->end_at_ms != 0 && entry->execute_at_ms > entry->end_at_ms);
    if (series_exhausted || past_end || bytes_corrupt) {
      // `recheck` points at the exact link slot that holds `entry`, so
      // unlinking through it is safe even if OTHER entries were removed while
      // handlers ran.
      *recheck = entry->next;
      free(entry->op_bytes);
      free(entry);
    }
  }

  state->scheduler_ticking = false;
  return CRABS_SUCCESS;
}
