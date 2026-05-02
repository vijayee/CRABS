//
// Created by victor on 5/2/25.
//
// Unified Compaction Engine & Scheduler (v1.5.2 §4)
// COMPACT_ITEM algorithm, periodic scheduler, per-type overrides.
//

#ifndef CRABS_COMPACTION_ENGINE_H
#define CRABS_COMPACTION_ENGINE_H

#include <stdint.h>
#include <stdbool.h>
#include "compaction.h"
#include "vector_clock.h"
#include "../CRABS/data_model.h"

// Get current wall-clock time in milliseconds (since epoch)
uint64_t crabs_engine_get_time_ms(void);

// ============================================================
// Compaction Result (v1.5.2 §4)
// ============================================================

typedef enum {
  CRABS_COMPACTION_OK          = 0,  // Compaction succeeded
  CRABS_COMPACTION_SKIPPED     = 1,  // Item doesn't need compaction
  CRABS_COMPACTION_UNSAFE      = 2,  // Safety check failed
  CRABS_COMPACTION_UNSUPPORTED = 3,  // No vtable registered for this type
  CRABS_COMPACTION_ERROR       = 4,  // Generic error
  CRABS_COMPACTION_RATE_LIMITED = 5, // Rate limit exceeded (v1.5.2 §4.4)
  CRABS_COMPACTION_INTERVAL    = 6, // Minimum interval not elapsed (v1.5.2 §4.4)
} crabs_compaction_result_e;

// ============================================================
// Per-Type Config Override (v1.5.2 §4.1)
// ============================================================

#define CRABS_MAX_TYPE_OVERRIDES 16

typedef struct {
  uint32_t type_id;
  crabs_tombstone_config_t config;
} crabs_type_override_t;

typedef struct {
  crabs_type_override_t overrides[CRABS_MAX_TYPE_OVERRIDES];
  uint32_t count;
} crabs_type_overrides_t;

// ============================================================
// Compaction Engine (v1.5.2 §4)
// ============================================================

typedef struct {
  crabs_tombstone_config_t     global_config;
  crabs_compaction_registry_t  registry;
  crabs_type_overrides_t       type_overrides;
  crabs_vector_clock_t         local_vc;
  uint64_t                     last_run_time_ms;
  uint64_t                     compaction_count;
  uint64_t                     skipped_count;
  uint64_t                     unsafe_count;
  // Rate limiting (v1.5.2 §4.4)
  uint64_t                     rate_window_start_ms;  // Start of current rate window
  uint32_t                     rate_window_count;     // Compactions in current window
} crabs_compaction_engine_t;

// Initialize compaction engine with global config
void crabs_compaction_engine_init(crabs_compaction_engine_t* engine,
                                   const crabs_tombstone_config_t* config);

// Destroy compaction engine (does not free registry items)
void crabs_compaction_engine_destroy(crabs_compaction_engine_t* engine);

// Register a per-type config override
crabs_error_e crabs_engine_set_type_override(crabs_compaction_engine_t* engine,
                                              uint32_t type_id,
                                              const crabs_tombstone_config_t* config);

// Get the effective config for a data item (type override or global)
const crabs_tombstone_config_t* crabs_engine_get_config(
  const crabs_compaction_engine_t* engine, const data_item_t* item);

// ============================================================
// COMPACT_ITEM Algorithm (v1.5.2 §4)
// ============================================================

// Compact a single data item using vtable dispatch.
// Handles both OT types (via extract_visible) and CRDT types (via vtable).
// current_time_ms is used to set last_compaction_time on the item.
crabs_compaction_result_e crabs_compact_item(
  crabs_compaction_engine_t* engine,
  state_t* state,
  data_item_t* item,
  uint64_t current_time_ms);

// ============================================================
// Periodic Compaction (v1.5.2 §4.2)
// ============================================================

// Check if periodic compaction should run based on elapsed time
bool crabs_engine_should_compact(const crabs_compaction_engine_t* engine,
                                  uint64_t current_time_ms);

// Run compaction on all items in state that need it.
// Returns the number of items compacted.
uint32_t crabs_engine_run_compaction(crabs_compaction_engine_t* engine,
                                      state_t* state,
                                      uint64_t current_time_ms);

// ============================================================
// __compact__ Built-in Operation (v1.5.2 §4.3)
// ============================================================

// Execute the __compact__ built-in operation on the state machine.
// Compacts all items that need compaction according to engine config.
// Uses the provided current_time_ms for last_compaction_time tracking.
crabs_error_e crabs_op_compact(crabs_compaction_engine_t* engine,
                                state_t* state,
                                uint64_t current_time_ms);

// Convenience wrapper that uses current wall-clock time.
crabs_error_e crabs_op_compact_now(crabs_compaction_engine_t* engine,
                                    state_t* state);

// ============================================================
// Periodic Compaction Entry Point (v1.5.2 §4.2)
// ============================================================

// Check if periodic compaction should run, and if so, run it.
// Returns the number of items compacted (0 if skipped).
// This is the primary entry point for timer-based compaction.
uint32_t crabs_engine_periodic_compaction(crabs_compaction_engine_t* engine,
                                            state_t* state,
                                            uint64_t current_time_ms);

// ============================================================
// Engine Statistics
// ============================================================

// Get the number of items compacted since engine init
uint64_t crabs_engine_compaction_count(const crabs_compaction_engine_t* engine);

// Get the number of items skipped (no compaction needed)
uint64_t crabs_engine_skipped_count(const crabs_compaction_engine_t* engine);

// Get the number of items that failed safety checks
uint64_t crabs_engine_unsafe_count(const crabs_compaction_engine_t* engine);

#endif // CRABS_COMPACTION_ENGINE_H