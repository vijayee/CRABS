//
// Created by victor on 5/1/25.
//
// Tombstone Management & State Compaction (v1.6 §6, §8)
// Unified framework for managing tombstone growth across CRDT types.
//

#ifndef CRABS_COMPACTION_H
#define CRABS_COMPACTION_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"

// ============================================================
// Compaction Strategy (v1.6 §6)
// ============================================================

typedef enum {
  CRABS_COMPACT_NONE       = 0x00,  // No automatic compaction
  CRABS_COMPACT_TIME_BASED = 0x01,  // Compact on time interval
  CRABS_COMPACT_SIZE_BASED = 0x02,  // Compact when tombstone ratio exceeds threshold
  CRABS_COMPACT_QUORUM     = 0x03,  // Compact only with peer quorum acknowledgment
  CRABS_COMPACT_HYBRID     = 0x04,  // Combine time-based and size-based triggers
} crabs_compaction_strategy_e;

// ============================================================
// Compaction Safety Level (v1.6 §8.4)
// ============================================================

typedef enum {
  CRABS_SAFETY_STRONG   = 0,  // All peers must have acknowledged
  CRABS_SAFETY_QUORUM   = 1,  // Majority of peers acknowledged
  CRABS_SAFETY_TIMESTAMP = 2, // Compaction point older than threshold
  CRABS_SAFETY_FORCE     = 3,  // Force compaction regardless of safety
} crabs_safety_level_e;

// ============================================================
// TombstoneConfig (v1.6 §6)
// ============================================================

#define CRABS_DEFAULT_MAX_TOMBSTONE_RATIO      0.5   // 50% tombstones before compaction
#define CRABS_DEFAULT_COMPACTION_INTERVAL_MS   60000  // 60 seconds
#define CRABS_DEFAULT_EMERGENCY_TOMBSTONE_COUNT 10000
#define CRABS_DEFAULT_AUTO_COMPACT_INTERVAL_MS  300000 // 5 minutes
#define CRABS_DEFAULT_MIN_COMPACTION_INTERVAL_MS 10000 // 10 seconds minimum between compactions
#define CRABS_DEFAULT_MAX_COMPACTIONS_PER_WINDOW 5      // Max 5 compactions per rate window
#define CRABS_DEFAULT_COMPACTION_RATE_WINDOW_MS  60000 // 1-minute rate window

typedef struct {
  crabs_compaction_strategy_e strategy;
  double   max_tombstone_ratio;        // 0.0-1.0, ratio of tombstones to total entries
  uint64_t compaction_interval_ms;     // How often to check for compaction
  uint32_t quorum_threshold;            // Minimum peer acknowledgments for quorum safety
  uint32_t emergency_tombstone_count;   // Force compaction at this tombstone count
  bool     allow_force;                // Allow force compaction (bypass safety checks)
  uint64_t auto_compact_interval_ms;   // Interval for automatic periodic compaction
  uint8_t  log_level;                  // 0=none, 1=errors, 2=info, 3=debug
  crabs_safety_level_e safety_level;   // Safety level for compaction
  // Security mitigations (v1.5.2 §4.4)
  uint64_t min_compaction_interval_ms; // Minimum time between compactions on the same item
  uint32_t max_compactions_per_window; // Max compaction operations per rate window
  uint64_t compaction_rate_window_ms;  // Rate window duration in ms
} crabs_tombstone_config_t;

// ============================================================
// CompactionVTable (v1.6 §8.2)
// ============================================================

typedef struct {
  uint64_t (*count_tombstones)(const void* item);
  uint64_t (*count_visible)(const void* item);
  void*    (*extract_visible)(const void* item);
  void*    (*rebuild_from_visible)(const void* visible);
  bool     (*compaction_safe)(const void* item, const state_t* state);
  // v1.5.2 §2: Extended vtable functions
  double   (*estimated_savings)(const void* item);   // Estimated savings ratio (0.0-1.0)
  void     (*describe_tombstones)(const void* item, char* buf, uint32_t buf_size);  // Human-readable description
} crabs_compaction_vtable_t;

// ============================================================
// Compaction Registry
// ============================================================

#define CRABS_MAX_COMPACTION_VTABLES 16

typedef struct {
  uint32_t type_id;
  crabs_compaction_vtable_t vtable;
} crabs_compaction_entry_t;

typedef struct {
  crabs_compaction_entry_t entries[CRABS_MAX_COMPACTION_VTABLES];
  uint32_t count;
} crabs_compaction_registry_t;

// ============================================================
// Compaction Functions
// ============================================================

// Initialize TombstoneConfig with default values
void crabs_tombstone_config_init(crabs_tombstone_config_t* config);

// Initialize with a specific strategy profile
void crabs_tombstone_config_init_strategy(crabs_tombstone_config_t* config,
                                           crabs_compaction_strategy_e strategy);

// Initialize the global compaction registry
void crabs_compaction_registry_init(crabs_compaction_registry_t* registry);

// Register a compaction vtable for a type
crabs_error_e crabs_compaction_register(crabs_compaction_registry_t* registry,
                                         uint32_t type_id,
                                         const crabs_compaction_vtable_t* vtable);

// Look up a compaction vtable by type
const crabs_compaction_vtable_t* crabs_compaction_get_vtable(
  const crabs_compaction_registry_t* registry, uint32_t type_id);

// Count tombstones for a data item using its registered vtable
uint64_t crabs_tombstone_count(const crabs_compaction_registry_t* registry,
                               const data_item_t* item);

// Count visible entries for a data item using its registered vtable
uint64_t crabs_visible_size(const crabs_compaction_registry_t* registry,
                            const data_item_t* item);

// Check if compaction is safe for a data item
bool crabs_compaction_is_safe(const crabs_compaction_registry_t* registry,
                               const data_item_t* item, const state_t* state);

// Check if a data item needs compaction based on its config
bool crabs_needs_compaction(const crabs_tombstone_config_t* config,
                             const crabs_compaction_registry_t* registry,
                             const data_item_t* item);

// Get strategy name string
const char* crabs_compaction_strategy_name(crabs_compaction_strategy_e strategy);

// Get safety level name string
const char* crabs_safety_level_name(crabs_safety_level_e level);

// Check if a data type supports compaction (has a registered vtable)
bool crabs_type_supports_compaction(const crabs_compaction_registry_t* registry,
                                    uint32_t type_id);

// Estimate savings ratio for a data item (0.0-1.0)
double crabs_estimated_savings(const crabs_compaction_registry_t* registry,
                               const data_item_t* item);

// Get human-readable description of tombstones for a data item
void crabs_describe_tombstones(const crabs_compaction_registry_t* registry,
                                const data_item_t* item,
                                char* buf, uint32_t buf_size);

#endif // CRABS_COMPACTION_H