//
// Created by victor on 5/1/25.
//
// Tests for TombstoneConfig & CompactionStrategy (CRABS-69)
//

#include <gtest/gtest.h>
#include <cmath>
extern "C" {
#include "../src/Compaction/compaction.h"
#include "../src/CRABS/data_model.h"
}

// ============================================================
// Config Initialization Tests
// ============================================================

TEST(Compaction, ConfigInitDefaults) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);

  EXPECT_EQ(config.strategy, CRABS_COMPACT_HYBRID);
  EXPECT_DOUBLE_EQ(config.max_tombstone_ratio, CRABS_DEFAULT_MAX_TOMBSTONE_RATIO);
  EXPECT_EQ(config.compaction_interval_ms, CRABS_DEFAULT_COMPACTION_INTERVAL_MS);
  EXPECT_EQ(config.quorum_threshold, 2u);
  EXPECT_EQ(config.emergency_tombstone_count, CRABS_DEFAULT_EMERGENCY_TOMBSTONE_COUNT);
  EXPECT_FALSE(config.allow_force);
  EXPECT_EQ(config.auto_compact_interval_ms, CRABS_DEFAULT_AUTO_COMPACT_INTERVAL_MS);
  EXPECT_EQ(config.log_level, 1u);
  EXPECT_EQ(config.safety_level, CRABS_SAFETY_QUORUM);
}

TEST(Compaction, ConfigInitNull) {
  crabs_tombstone_config_init(nullptr);
  // Should not crash
}

TEST(Compaction, ConfigInitStrategyNone) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init_strategy(&config, CRABS_COMPACT_NONE);

  EXPECT_EQ(config.strategy, CRABS_COMPACT_NONE);
  EXPECT_DOUBLE_EQ(config.max_tombstone_ratio, 1.0);
  EXPECT_EQ(config.auto_compact_interval_ms, 0u);
  EXPECT_EQ(config.safety_level, CRABS_SAFETY_FORCE);
}

TEST(Compaction, ConfigInitStrategyTimeBased) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init_strategy(&config, CRABS_COMPACT_TIME_BASED);

  EXPECT_EQ(config.strategy, CRABS_COMPACT_TIME_BASED);
  EXPECT_EQ(config.compaction_interval_ms, 30000u);
  EXPECT_EQ(config.auto_compact_interval_ms, 60000u);
  EXPECT_EQ(config.safety_level, CRABS_SAFETY_TIMESTAMP);
}

TEST(Compaction, ConfigInitStrategySizeBased) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init_strategy(&config, CRABS_COMPACT_SIZE_BASED);

  EXPECT_EQ(config.strategy, CRABS_COMPACT_SIZE_BASED);
  EXPECT_DOUBLE_EQ(config.max_tombstone_ratio, 0.4);
  EXPECT_EQ(config.emergency_tombstone_count, 5000u);
  EXPECT_EQ(config.safety_level, CRABS_SAFETY_QUORUM);
}

TEST(Compaction, ConfigInitStrategyQuorum) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init_strategy(&config, CRABS_COMPACT_QUORUM);

  EXPECT_EQ(config.strategy, CRABS_COMPACT_QUORUM);
  EXPECT_EQ(config.quorum_threshold, 3u);
  EXPECT_DOUBLE_EQ(config.max_tombstone_ratio, 0.6);
}

TEST(Compaction, ConfigInitStrategyHybrid) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init_strategy(&config, CRABS_COMPACT_HYBRID);

  EXPECT_EQ(config.strategy, CRABS_COMPACT_HYBRID);
  // Hybrid uses defaults from crabs_tombstone_config_init
  EXPECT_DOUBLE_EQ(config.max_tombstone_ratio, CRABS_DEFAULT_MAX_TOMBSTONE_RATIO);
}

// ============================================================
// Strategy & Safety Level Names
// ============================================================

TEST(Compaction, StrategyNames) {
  EXPECT_STREQ(crabs_compaction_strategy_name(CRABS_COMPACT_NONE), "NONE");
  EXPECT_STREQ(crabs_compaction_strategy_name(CRABS_COMPACT_TIME_BASED), "TIME_BASED");
  EXPECT_STREQ(crabs_compaction_strategy_name(CRABS_COMPACT_SIZE_BASED), "SIZE_BASED");
  EXPECT_STREQ(crabs_compaction_strategy_name(CRABS_COMPACT_QUORUM), "QUORUM");
  EXPECT_STREQ(crabs_compaction_strategy_name(CRABS_COMPACT_HYBRID), "HYBRID");
  EXPECT_STREQ(crabs_compaction_strategy_name((crabs_compaction_strategy_e)99), "UNKNOWN");
}

TEST(Compaction, SafetyLevelNames) {
  EXPECT_STREQ(crabs_safety_level_name(CRABS_SAFETY_STRONG), "STRONG");
  EXPECT_STREQ(crabs_safety_level_name(CRABS_SAFETY_QUORUM), "QUORUM");
  EXPECT_STREQ(crabs_safety_level_name(CRABS_SAFETY_TIMESTAMP), "TIMESTAMP");
  EXPECT_STREQ(crabs_safety_level_name(CRABS_SAFETY_FORCE), "FORCE");
  EXPECT_STREQ(crabs_safety_level_name((crabs_safety_level_e)99), "UNKNOWN");
}

// ============================================================
// Registry Tests
// ============================================================

TEST(Compaction, RegistryInit) {
  crabs_compaction_registry_t registry;
  crabs_compaction_registry_init(&registry);
  EXPECT_EQ(registry.count, 0u);
}

TEST(Compaction, RegistryInitNull) {
  crabs_compaction_registry_init(nullptr);
  // Should not crash
}

static uint64_t mock_count_tombstones(const void* item) {
  (void)item;
  return 10;
}

static uint64_t mock_count_visible(const void* item) {
  (void)item;
  return 20;
}

static void* mock_extract_visible(const void* item) {
  return (void*)item;
}

static void* mock_rebuild_from_visible(const void* visible) {
  return (void*)visible;
}

static bool mock_compaction_safe(const void* item, const state_t* state) {
  (void)item;
  (void)state;
  return true;
}

TEST(Compaction, RegistryRegisterAndLookup) {
  crabs_compaction_registry_t registry;
  crabs_compaction_registry_init(&registry);

  crabs_compaction_vtable_t vtable = {
    .count_tombstones = mock_count_tombstones,
    .count_visible = mock_count_visible,
    .extract_visible = mock_extract_visible,
    .rebuild_from_visible = mock_rebuild_from_visible,
    .compaction_safe = mock_compaction_safe,
  };

  crabs_error_e err = crabs_compaction_register(&registry, DATA_TYPE_OT_ORDERED_SET, &vtable);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(registry.count, 1u);

  const crabs_compaction_vtable_t* found =
    crabs_compaction_get_vtable(&registry, DATA_TYPE_OT_ORDERED_SET);
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->count_tombstones, mock_count_tombstones);
  EXPECT_EQ(found->count_visible, mock_count_visible);
}

TEST(Compaction, RegistryLookupNotFound) {
  crabs_compaction_registry_t registry;
  crabs_compaction_registry_init(&registry);

  const crabs_compaction_vtable_t* found =
    crabs_compaction_get_vtable(&registry, DATA_TYPE_COUNTER);
  EXPECT_EQ(found, nullptr);
}

TEST(Compaction, RegistryRegisterNull) {
  crabs_compaction_registry_t registry;
  crabs_compaction_registry_init(&registry);

  crabs_compaction_vtable_t vtable = {};
  EXPECT_EQ(crabs_compaction_register(nullptr, DATA_TYPE_COUNTER, &vtable), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(crabs_compaction_register(&registry, DATA_TYPE_COUNTER, nullptr), CRABS_ERR_INVALID_PARAM);
}

TEST(Compaction, RegistryUpdateExisting) {
  crabs_compaction_registry_t registry;
  crabs_compaction_registry_init(&registry);

  crabs_compaction_vtable_t vtable1 = {
    .count_tombstones = mock_count_tombstones,
  };
  crabs_compaction_vtable_t vtable2 = {
    .count_tombstones = nullptr,
  };

  crabs_compaction_register(&registry, DATA_TYPE_COUNTER, &vtable1);
  EXPECT_EQ(registry.count, 1u);

  crabs_compaction_register(&registry, DATA_TYPE_COUNTER, &vtable2);
  EXPECT_EQ(registry.count, 1u);  // Updated, not added

  const crabs_compaction_vtable_t* found =
    crabs_compaction_get_vtable(&registry, DATA_TYPE_COUNTER);
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->count_tombstones, nullptr);  // Updated to vtable2
}

// ============================================================
// Needs Compaction Tests
// ============================================================

TEST(Compaction, NeedsCompactionNone) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init_strategy(&config, CRABS_COMPACT_NONE);

  crabs_compaction_registry_t registry;
  crabs_compaction_registry_init(&registry);

  data_item_t* item = data_item_create("test", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  EXPECT_FALSE(crabs_needs_compaction(&config, &registry, item));
  data_item_destroy(item);
}

TEST(Compaction, NeedsCompactionNulls) {
  EXPECT_FALSE(crabs_needs_compaction(nullptr, nullptr, nullptr));
}

// ============================================================
// Enum Value Tests
// ============================================================

TEST(Compaction, StrategyValues) {
  EXPECT_EQ(CRABS_COMPACT_NONE, 0x00);
  EXPECT_EQ(CRABS_COMPACT_TIME_BASED, 0x01);
  EXPECT_EQ(CRABS_COMPACT_SIZE_BASED, 0x02);
  EXPECT_EQ(CRABS_COMPACT_QUORUM, 0x03);
  EXPECT_EQ(CRABS_COMPACT_HYBRID, 0x04);
}

TEST(Compaction, SafetyLevelValues) {
  EXPECT_EQ(CRABS_SAFETY_STRONG, 0);
  EXPECT_EQ(CRABS_SAFETY_QUORUM, 1);
  EXPECT_EQ(CRABS_SAFETY_TIMESTAMP, 2);
  EXPECT_EQ(CRABS_SAFETY_FORCE, 3);
}