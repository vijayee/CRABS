//
// Created by victor on 5/1/25.
//
// Tombstone Management & State Compaction (v1.6 §6, §8)
// Unified framework for managing tombstone growth across CRDT types.
//

#include "compaction.h"
#include <stdio.h>
#include <string.h>

// ============================================================
// Default Config Profiles (v1.6 §6)
// ============================================================

void crabs_tombstone_config_init(crabs_tombstone_config_t* config) {
  if (config == NULL) return;
  memset(config, 0, sizeof(crabs_tombstone_config_t));
  config->strategy = CRABS_COMPACT_HYBRID;
  config->max_tombstone_ratio = CRABS_DEFAULT_MAX_TOMBSTONE_RATIO;
  config->compaction_interval_ms = CRABS_DEFAULT_COMPACTION_INTERVAL_MS;
  config->quorum_threshold = 2;
  config->emergency_tombstone_count = CRABS_DEFAULT_EMERGENCY_TOMBSTONE_COUNT;
  config->allow_force = false;
  config->auto_compact_interval_ms = CRABS_DEFAULT_AUTO_COMPACT_INTERVAL_MS;
  config->log_level = 1;  // errors only
  config->safety_level = CRABS_SAFETY_QUORUM;
  config->min_compaction_interval_ms = CRABS_DEFAULT_MIN_COMPACTION_INTERVAL_MS;
  config->max_compactions_per_window = CRABS_DEFAULT_MAX_COMPACTIONS_PER_WINDOW;
  config->compaction_rate_window_ms = CRABS_DEFAULT_COMPACTION_RATE_WINDOW_MS;
}

void crabs_tombstone_config_init_strategy(crabs_tombstone_config_t* config,
                                           crabs_compaction_strategy_e strategy) {
  crabs_tombstone_config_init(config);
  config->strategy = strategy;

  switch (strategy) {
    case CRABS_COMPACT_NONE:
      config->max_tombstone_ratio = 1.0;  // Never compact
      config->auto_compact_interval_ms = 0;
      config->safety_level = CRABS_SAFETY_FORCE;
      config->allow_force = true;         // FORCE allowed for manual compaction
      break;
    case CRABS_COMPACT_TIME_BASED:
      config->compaction_interval_ms = 30000;  // 30 seconds
      config->auto_compact_interval_ms = 60000;
      config->safety_level = CRABS_SAFETY_TIMESTAMP;
      break;
    case CRABS_COMPACT_SIZE_BASED:
      config->max_tombstone_ratio = 0.4;  // Compact at 40%
      config->emergency_tombstone_count = 5000;
      config->safety_level = CRABS_SAFETY_QUORUM;
      break;
    case CRABS_COMPACT_QUORUM:
      config->quorum_threshold = 3;
      config->safety_level = CRABS_SAFETY_QUORUM;
      config->max_tombstone_ratio = 0.6;
      break;
    case CRABS_COMPACT_HYBRID:
      // Defaults from crabs_tombstone_config_init are already hybrid
      break;
  }
}

// ============================================================
// Compaction Registry
// ============================================================

void crabs_compaction_registry_init(crabs_compaction_registry_t* registry) {
  if (registry == NULL) return;
  memset(registry, 0, sizeof(crabs_compaction_registry_t));
}

crabs_error_e crabs_compaction_register(crabs_compaction_registry_t* registry,
                                         uint32_t type_id,
                                         const crabs_compaction_vtable_t* vtable) {
  if (registry == NULL || vtable == NULL) return CRABS_ERR_INVALID_PARAM;

  // Check for duplicate
  for (uint32_t i = 0; i < registry->count; i++) {
    if (registry->entries[i].type_id == type_id) {
      // Update existing entry
      registry->entries[i].vtable = *vtable;
      return CRABS_SUCCESS;
    }
  }

  // Add new entry
  if (registry->count >= CRABS_MAX_COMPACTION_VTABLES) {
    return CRABS_ERR_OOM;
  }

  registry->entries[registry->count].type_id = type_id;
  registry->entries[registry->count].vtable = *vtable;
  registry->count++;

  return CRABS_SUCCESS;
}

const crabs_compaction_vtable_t* crabs_compaction_get_vtable(
  const crabs_compaction_registry_t* registry, uint32_t type_id) {
  if (registry == NULL) return NULL;
  for (uint32_t i = 0; i < registry->count; i++) {
    if (registry->entries[i].type_id == type_id) {
      return &registry->entries[i].vtable;
    }
  }
  return NULL;
}

// ============================================================
// Helper Functions
// ============================================================

uint64_t crabs_tombstone_count(const crabs_compaction_registry_t* registry,
                               const data_item_t* item) {
  if (registry == NULL || item == NULL) return 0;
  const crabs_compaction_vtable_t* vtable =
    crabs_compaction_get_vtable(registry, (uint32_t)item->type);
  if (vtable == NULL || vtable->count_tombstones == NULL) return 0;
  return vtable->count_tombstones(item->value);
}

uint64_t crabs_visible_size(const crabs_compaction_registry_t* registry,
                            const data_item_t* item) {
  if (registry == NULL || item == NULL) return 0;
  const crabs_compaction_vtable_t* vtable =
    crabs_compaction_get_vtable(registry, (uint32_t)item->type);
  if (vtable == NULL || vtable->count_visible == NULL) return 0;
  return vtable->count_visible(item->value);
}

bool crabs_compaction_is_safe(const crabs_compaction_registry_t* registry,
                               const data_item_t* item, const state_t* state) {
  if (registry == NULL || item == NULL || state == NULL) return false;
  const crabs_compaction_vtable_t* vtable =
    crabs_compaction_get_vtable(registry, (uint32_t)item->type);
  if (vtable == NULL || vtable->compaction_safe == NULL) return false;
  return vtable->compaction_safe(item->value, state);
}

bool crabs_needs_compaction(const crabs_tombstone_config_t* config,
                             const crabs_compaction_registry_t* registry,
                             const data_item_t* item) {
  if (config == NULL || registry == NULL || item == NULL) return false;
  if (config->strategy == CRABS_COMPACT_NONE) return false;

  uint64_t tombstones = crabs_tombstone_count(registry, item);
  uint64_t visible = crabs_visible_size(registry, item);

  // Emergency threshold: always compact regardless of ratio
  if (config->emergency_tombstone_count > 0 &&
      tombstones >= config->emergency_tombstone_count) {
    return true;
  }

  // Size-based check: tombstone ratio exceeds threshold
  uint64_t total = tombstones + visible;
  if (total > 0) {
    double ratio = (double)tombstones / (double)total;
    if (ratio >= config->max_tombstone_ratio) {
      return true;
    }
  }

  return false;
}

const char* crabs_compaction_strategy_name(crabs_compaction_strategy_e strategy) {
  switch (strategy) {
    case CRABS_COMPACT_NONE:       return "NONE";
    case CRABS_COMPACT_TIME_BASED: return "TIME_BASED";
    case CRABS_COMPACT_SIZE_BASED: return "SIZE_BASED";
    case CRABS_COMPACT_QUORUM:     return "QUORUM";
    case CRABS_COMPACT_HYBRID:     return "HYBRID";
    default:                       return "UNKNOWN";
  }
}

const char* crabs_safety_level_name(crabs_safety_level_e level) {
  switch (level) {
    case CRABS_SAFETY_STRONG:    return "STRONG";
    case CRABS_SAFETY_QUORUM:    return "QUORUM";
    case CRABS_SAFETY_TIMESTAMP: return "TIMESTAMP";
    case CRABS_SAFETY_FORCE:    return "FORCE";
    default:                     return "UNKNOWN";
  }
}

bool crabs_type_supports_compaction(const crabs_compaction_registry_t* registry,
                                     uint32_t type_id) {
  return crabs_compaction_get_vtable(registry, type_id) != NULL;
}

double crabs_estimated_savings(const crabs_compaction_registry_t* registry,
                               const data_item_t* item) {
  if (registry == NULL || item == NULL) return 0.0;
  const crabs_compaction_vtable_t* vtable =
    crabs_compaction_get_vtable(registry, (uint32_t)item->type);
  if (vtable == NULL || vtable->estimated_savings == NULL) {
    // Fall back to ratio calculation
    uint64_t tombstones = crabs_tombstone_count(registry, item);
    uint64_t visible = crabs_visible_size(registry, item);
    uint64_t total = tombstones + visible;
    if (total == 0) return 0.0;
    return (double)tombstones / (double)total;
  }
  return vtable->estimated_savings(item->value);
}

void crabs_describe_tombstones(const crabs_compaction_registry_t* registry,
                                const data_item_t* item,
                                char* buf, uint32_t buf_size) {
  if (buf == NULL || buf_size == 0) return;
  buf[0] = '\0';

  if (registry == NULL || item == NULL) {
    snprintf(buf, buf_size, "no item");
    return;
  }

  const crabs_compaction_vtable_t* vtable =
    crabs_compaction_get_vtable(registry, (uint32_t)item->type);
  if (vtable == NULL || vtable->describe_tombstones == NULL) {
    uint64_t tombstones = crabs_tombstone_count(registry, item);
    uint64_t visible = crabs_visible_size(registry, item);
    snprintf(buf, buf_size, "tombstones=%lu visible=%lu",
             (unsigned long)tombstones, (unsigned long)visible);
    return;
  }
  vtable->describe_tombstones(item->value, buf, buf_size);
}