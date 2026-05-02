//
// Created by victor on 5/2/25.
//
// Unified Compaction Engine & Scheduler (v1.5.2 §4)
// COMPACT_ITEM algorithm, periodic scheduler, per-type overrides.
//

#include "compaction_engine.h"
#include "compact_op.h"
#include <string.h>

// ============================================================
// Engine Init/Destroy
// ============================================================

void crabs_compaction_engine_init(crabs_compaction_engine_t* engine,
                                   const crabs_tombstone_config_t* config) {
  if (engine == NULL) return;
  memset(engine, 0, sizeof(crabs_compaction_engine_t));

  if (config != NULL) {
    engine->global_config = *config;
  } else {
    crabs_tombstone_config_init(&engine->global_config);
  }

  crabs_compaction_registry_init(&engine->registry);
  crabs_vector_clock_init(&engine->local_vc);
  engine->last_run_time_ms = 0;
  engine->compaction_count = 0;
  engine->skipped_count = 0;
  engine->unsafe_count = 0;
}

void crabs_compaction_engine_destroy(crabs_compaction_engine_t* engine) {
  if (engine == NULL) return;
  // No heap allocations in the engine itself
}

// ============================================================
// Per-Type Config Overrides
// ============================================================

crabs_error_e crabs_engine_set_type_override(crabs_compaction_engine_t* engine,
                                             uint32_t type_id,
                                             const crabs_tombstone_config_t* config) {
  if (engine == NULL || config == NULL) return CRABS_ERR_INVALID_PARAM;

  // Check for existing override
  for (uint32_t i = 0; i < engine->type_overrides.count; i++) {
    if (engine->type_overrides.overrides[i].type_id == type_id) {
      engine->type_overrides.overrides[i].config = *config;
      return CRABS_SUCCESS;
    }
  }

  // Add new override
  if (engine->type_overrides.count >= CRABS_MAX_TYPE_OVERRIDES) {
    return CRABS_ERR_OOM;
  }

  engine->type_overrides.overrides[engine->type_overrides.count].type_id = type_id;
  engine->type_overrides.overrides[engine->type_overrides.count].config = *config;
  engine->type_overrides.count++;
  return CRABS_SUCCESS;
}

const crabs_tombstone_config_t* crabs_engine_get_config(
  const crabs_compaction_engine_t* engine, const data_item_t* item) {
  if (engine == NULL || item == NULL) return NULL;

  // Check for type-specific override
  for (uint32_t i = 0; i < engine->type_overrides.count; i++) {
    if (engine->type_overrides.overrides[i].type_id == (uint32_t)item->type) {
      return &engine->type_overrides.overrides[i].config;
    }
  }

  return &engine->global_config;
}

// ============================================================
// COMPACT_ITEM Algorithm (v1.5.2 §4)
// ============================================================

crabs_compaction_result_e crabs_compact_item(
  crabs_compaction_engine_t* engine,
  state_t* state,
  data_item_t* item,
  uint64_t current_time_ms) {
  if (engine == NULL || state == NULL || item == NULL) {
    return CRABS_COMPACTION_ERROR;
  }

  const crabs_tombstone_config_t* config = crabs_engine_get_config(engine, item);
  if (config == NULL) return CRABS_COMPACTION_ERROR;

  // Step 1: Check if type supports compaction
  if (!crabs_type_supports_compaction(&engine->registry, (uint32_t)item->type) &&
      item->ot_data == NULL) {
    return CRABS_COMPACTION_UNSUPPORTED;
  }

  // Step 2: Check compaction safety
  if (!crabs_check_compaction_safety(config, state, item,
                                      &engine->local_vc, &engine->local_vc)) {
    engine->unsafe_count++;
    return CRABS_COMPACTION_UNSAFE;
  }

  // Step 3: Check if compaction is needed
  if (!crabs_needs_compaction(config, &engine->registry, item)) {
    engine->skipped_count++;
    return CRABS_COMPACTION_SKIPPED;
  }

  // Step 4: Perform compaction based on type
  crabs_error_e err = CRABS_SUCCESS;

  if (item->ot_data != NULL) {
    // OT type: use the existing crabs_compact_ot_item
    err = crabs_compact_ot_item(state, item, config, &engine->registry,
                                &engine->local_vc, &engine->local_vc);
  } else {
    // CRDT type: use vtable dispatch
    const crabs_compaction_vtable_t* vtable =
      crabs_compaction_get_vtable(&engine->registry, (uint32_t)item->type);
    if (vtable == NULL) return CRABS_COMPACTION_UNSUPPORTED;

    void* visible = vtable->extract_visible(item->value);
    if (visible == NULL) return CRABS_COMPACTION_ERROR;

    // Use the visible value directly as the compacted result.
    // extract_visible already creates a clean copy with no tombstones.
    // The original item->value is replaced; callers should ensure
    // the old value is freed if needed (or add a destroy_value vtable fn).
    item->value = visible;
  }

  if (err != CRABS_SUCCESS) {
    return CRABS_COMPACTION_ERROR;
  }

  // Update compaction tracking
  item->last_compaction_time = current_time_ms;
  engine->compaction_count++;

  return CRABS_COMPACTION_OK;
}

// ============================================================
// Periodic Compaction (v1.5.2 §4.2)
// ============================================================

bool crabs_engine_should_compact(const crabs_compaction_engine_t* engine,
                                  uint64_t current_time_ms) {
  if (engine == NULL) return false;

  uint64_t interval = engine->global_config.auto_compact_interval_ms;
  if (interval == 0) return false;

  if (engine->last_run_time_ms == 0) return true;

  return (current_time_ms - engine->last_run_time_ms) >= interval;
}

uint32_t crabs_engine_run_compaction(crabs_compaction_engine_t* engine,
                                      state_t* state,
                                      uint64_t current_time_ms) {
  if (engine == NULL || state == NULL) return 0;

  uint32_t compacted = 0;
  data_item_t* item = state->items;

  while (item != NULL) {
    // Check emergency threshold first
    uint64_t tombstones = crabs_tombstone_count(&engine->registry, item);
    if (engine->global_config.emergency_tombstone_count > 0 &&
        tombstones >= engine->global_config.emergency_tombstone_count) {
      // Emergency compaction regardless of timer
      crabs_compaction_result_e result = crabs_compact_item(engine, state, item, current_time_ms);
      if (result == CRABS_COMPACTION_OK) compacted++;
      item = item->next;
      continue;
    }

    // Check time-based trigger
    if (engine->global_config.strategy == CRABS_COMPACT_TIME_BASED ||
        engine->global_config.strategy == CRABS_COMPACT_HYBRID) {
      if (!crabs_engine_should_compact(engine, current_time_ms)) {
        item = item->next;
        continue;
      }
    }

    // Try compaction
    crabs_compaction_result_e result = crabs_compact_item(engine, state, item, current_time_ms);
    if (result == CRABS_COMPACTION_OK) compacted++;

    item = item->next;
  }

  engine->last_run_time_ms = current_time_ms;
  return compacted;
}

// ============================================================
// __compact__ Built-in Operation (v1.5.2 §4.3)
// ============================================================

crabs_error_e crabs_op_compact(crabs_compaction_engine_t* engine,
                                state_t* state) {
  if (engine == NULL || state == NULL) return CRABS_ERR_INVALID_PARAM;

  data_item_t* item = state->items;
  while (item != NULL) {
    crabs_compact_item(engine, state, item, 0);
    item = item->next;
  }

  return CRABS_SUCCESS;
}

// ============================================================
// Engine Statistics
// ============================================================

uint64_t crabs_engine_compaction_count(const crabs_compaction_engine_t* engine) {
  return engine ? engine->compaction_count : 0;
}

uint64_t crabs_engine_skipped_count(const crabs_compaction_engine_t* engine) {
  return engine ? engine->skipped_count : 0;
}

uint64_t crabs_engine_unsafe_count(const crabs_compaction_engine_t* engine) {
  return engine ? engine->unsafe_count : 0;
}