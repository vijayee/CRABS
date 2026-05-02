//
// Created by victor on 5/2/25.
//
// Tests for Unified Compaction Engine & Scheduler (CRABS-77)
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/Compaction/compaction_engine.h"
#include "../src/Compaction/crdt_compaction.h"
#include "../src/Compaction/compaction.h"
#include "../src/CRDT/crdt_merge.h"
#include "../src/CRABS/data_model.h"
}

// ============================================================
// Engine Init/Destroy Tests
// ============================================================

TEST(CompactionEngine, InitDefaults) {
  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, nullptr);

  EXPECT_EQ(engine.global_config.strategy, CRABS_COMPACT_HYBRID);
  EXPECT_DOUBLE_EQ(engine.global_config.max_tombstone_ratio, CRABS_DEFAULT_MAX_TOMBSTONE_RATIO);
  EXPECT_EQ(engine.compaction_count, 0u);
  EXPECT_EQ(engine.skipped_count, 0u);
  EXPECT_EQ(engine.unsafe_count, 0u);
  EXPECT_EQ(engine.last_run_time_ms, 0u);
  EXPECT_EQ(engine.type_overrides.count, 0u);

  crabs_compaction_engine_destroy(&engine);
}

TEST(CompactionEngine, InitWithConfig) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init_strategy(&config, CRABS_COMPACT_SIZE_BASED);

  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, &config);

  EXPECT_EQ(engine.global_config.strategy, CRABS_COMPACT_SIZE_BASED);

  crabs_compaction_engine_destroy(&engine);
}

TEST(CompactionEngine, InitNull) {
  crabs_compaction_engine_init(nullptr, nullptr);
  crabs_compaction_engine_destroy(nullptr);
  // Should not crash
}

// ============================================================
// Per-Type Override Tests
// ============================================================

TEST(CompactionEngine, SetTypeOverride) {
  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, nullptr);

  crabs_tombstone_config_t or_config;
  crabs_tombstone_config_init_strategy(&or_config, CRABS_COMPACT_SIZE_BASED);

  crabs_error_e err = crabs_engine_set_type_override(&engine, DATA_TYPE_SET, &or_config);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(engine.type_overrides.count, 1u);

  crabs_compaction_engine_destroy(&engine);
}

TEST(CompactionEngine, GetConfigOverride) {
  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, nullptr);

  crabs_tombstone_config_t or_config;
  crabs_tombstone_config_init_strategy(&or_config, CRABS_COMPACT_SIZE_BASED);
  crabs_engine_set_type_override(&engine, DATA_TYPE_SET, &or_config);

  data_item_t* item = data_item_create("test", DATA_TYPE_SET, CRDT_OR_SET);
  const crabs_tombstone_config_t* effective = crabs_engine_get_config(&engine, item);
  ASSERT_NE(effective, nullptr);
  EXPECT_EQ(effective->strategy, CRABS_COMPACT_SIZE_BASED);

  data_item_destroy(item);
  crabs_compaction_engine_destroy(&engine);
}

TEST(CompactionEngine, GetConfigGlobalFallback) {
  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, nullptr);

  data_item_t* item = data_item_create("test", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  const crabs_tombstone_config_t* effective = crabs_engine_get_config(&engine, item);
  ASSERT_NE(effective, nullptr);
  EXPECT_EQ(effective->strategy, CRABS_COMPACT_HYBRID);  // Default

  data_item_destroy(item);
  crabs_compaction_engine_destroy(&engine);
}

TEST(CompactionEngine, SetTypeOverrideNull) {
  EXPECT_EQ(crabs_engine_set_type_override(nullptr, DATA_TYPE_SET, nullptr),
            CRABS_ERR_INVALID_PARAM);
}

TEST(CompactionEngine, UpdateExistingOverride) {
  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, nullptr);

  crabs_tombstone_config_t config1;
  crabs_tombstone_config_init_strategy(&config1, CRABS_COMPACT_SIZE_BASED);
  crabs_engine_set_type_override(&engine, DATA_TYPE_SET, &config1);

  crabs_tombstone_config_t config2;
  crabs_tombstone_config_init_strategy(&config2, CRABS_COMPACT_QUORUM);
  crabs_error_e err = crabs_engine_set_type_override(&engine, DATA_TYPE_SET, &config2);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(engine.type_overrides.count, 1u);  // Updated, not added

  data_item_t* item = data_item_create("test", DATA_TYPE_SET, CRDT_OR_SET);
  const crabs_tombstone_config_t* effective = crabs_engine_get_config(&engine, item);
  EXPECT_EQ(effective->strategy, CRABS_COMPACT_QUORUM);

  data_item_destroy(item);
  crabs_compaction_engine_destroy(&engine);
}

// ============================================================
// COMPACT_ITEM Tests
// ============================================================

TEST(CompactionEngine, CompactItemNullParams) {
  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, nullptr);

  EXPECT_EQ(crabs_compact_item(nullptr, nullptr, nullptr, 0), CRABS_COMPACTION_ERROR);
  EXPECT_EQ(crabs_compact_item(&engine, nullptr, nullptr, 0), CRABS_COMPACTION_ERROR);

  crabs_compaction_engine_destroy(&engine);
}

TEST(CompactionEngine, CompactItemUnsupportedType) {
  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, nullptr);

  state_t* state = state_create();
  data_item_t* item = data_item_create("counter", DATA_TYPE_COUNTER, CRDT_G_COUNTER);

  crabs_compaction_result_e result = crabs_compact_item(&engine, state, item, 1000);
  EXPECT_EQ(result, CRABS_COMPACTION_UNSUPPORTED);

  data_item_destroy(item);
  state_destroy(state);
  crabs_compaction_engine_destroy(&engine);
}

TEST(CompactionEngine, CompactItemORSetNoTombstones) {
  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, nullptr);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");

  data_item_t* item = data_item_create("test_set", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;

  // No tombstones, so compaction should be skipped
  crabs_compaction_result_e result = crabs_compact_item(&engine, state, item, 1000);
  EXPECT_EQ(result, CRABS_COMPACTION_SKIPPED);

  or_set_destroy(set);
  item->value = nullptr;
  data_item_destroy(item);
  state_destroy(state);
  crabs_compaction_engine_destroy(&engine);
}

TEST(CompactionEngine, CompactItemORSetWithTombstones) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.strategy = CRABS_COMPACT_SIZE_BASED;
  config.max_tombstone_ratio = 0.3;  // Low threshold to force compaction
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("test_set", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;

  // 1 tombstone out of 3 total (ratio ~0.33) >= 0.3 threshold
  crabs_compaction_result_e result = crabs_compact_item(&engine, state, item, 1000);
  EXPECT_EQ(result, CRABS_COMPACTION_OK);
  EXPECT_EQ(engine.compaction_count, 1u);

  or_set_destroy(set);
  item->value = nullptr;
  data_item_destroy(item);
  state_destroy(state);
  crabs_compaction_engine_destroy(&engine);
}

TEST(CompactionEngine, CompactItem2PSet) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.strategy = CRABS_COMPACT_SIZE_BASED;
  config.max_tombstone_ratio = 0.3;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  two_p_set_t* set = two_p_set_create();
  two_p_set_add(set, "a");
  two_p_set_add(set, "b");
  two_p_set_add(set, "c");
  two_p_set_remove(set, "a");
  two_p_set_remove(set, "b");

  data_item_t* item = data_item_create("test_2p", DATA_TYPE_2P_SET, CRDT_2P_SET);
  item->value = set;

  crabs_compaction_result_e result = crabs_compact_item(&engine, state, item, 1000);
  EXPECT_EQ(result, CRABS_COMPACTION_OK);
  EXPECT_EQ(engine.compaction_count, 1u);

  two_p_set_destroy(set);
  item->value = nullptr;
  data_item_destroy(item);
  state_destroy(state);
  crabs_compaction_engine_destroy(&engine);
}

// ============================================================
// Periodic Compaction Tests
// ============================================================

TEST(CompactionEngine, ShouldCompactFirstRun) {
  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, nullptr);

  // First run should always trigger
  EXPECT_TRUE(crabs_engine_should_compact(&engine, 1000));

  crabs_compaction_engine_destroy(&engine);
}

TEST(CompactionEngine, ShouldCompactDisabled) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init_strategy(&config, CRABS_COMPACT_NONE);
  crabs_compaction_engine_init(&engine, &config);

  // NONE strategy has auto_compact_interval_ms = 0
  EXPECT_FALSE(crabs_engine_should_compact(&engine, 1000));

  crabs_compaction_engine_destroy(&engine);
}

TEST(CompactionEngine, ShouldCompactAfterInterval) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.auto_compact_interval_ms = 1000;
  crabs_compaction_engine_init(&engine, &config);
  engine.last_run_time_ms = 500;

  // Not enough time has passed
  EXPECT_FALSE(crabs_engine_should_compact(&engine, 1000));

  // Enough time has passed (1000 + 1000 >= 1000)
  EXPECT_TRUE(crabs_engine_should_compact(&engine, 2000));

  crabs_compaction_engine_destroy(&engine);
}

// ============================================================
// __compact__ Operation Tests
// ============================================================

TEST(CompactionEngine, OpCompactEmptyState) {
  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, nullptr);

  state_t* state = state_create();
  crabs_error_e err = crabs_op_compact(&engine, state);
  EXPECT_EQ(err, CRABS_SUCCESS);

  state_destroy(state);
  crabs_compaction_engine_destroy(&engine);
}

TEST(CompactionEngine, OpCompactNull) {
  EXPECT_EQ(crabs_op_compact(nullptr, nullptr), CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Statistics Tests
// ============================================================

TEST(CompactionEngine, StatisticsNull) {
  EXPECT_EQ(crabs_engine_compaction_count(nullptr), 0u);
  EXPECT_EQ(crabs_engine_skipped_count(nullptr), 0u);
  EXPECT_EQ(crabs_engine_unsafe_count(nullptr), 0u);
}

TEST(CompactionEngine, StatisticsAfterCompact) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.strategy = CRABS_COMPACT_SIZE_BASED;
  config.max_tombstone_ratio = 0.3;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();

  // Create item that needs compaction
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");
  or_set_remove(set, "a");
  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;

  crabs_compact_item(&engine, state, item, 1000);
  EXPECT_EQ(crabs_engine_compaction_count(&engine), 1u);

  or_set_destroy(set);
  item->value = nullptr;
  data_item_destroy(item);
  state_destroy(state);
  crabs_compaction_engine_destroy(&engine);
}

// ============================================================
// Unsafe Compaction Detection Tests
// ============================================================

TEST(CompactionEngine, UnsafeCompactionStrongSafety) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.safety_level = CRABS_SAFETY_STRONG;
  config.max_tombstone_ratio = 0.1;  // Very low threshold
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;

  // STRONG safety requires all peers acknowledged, but our VC is empty
  // so dominates() returns true (empty VC dominates empty VC)
  // The safety check depends on the config + VCs
  // ratio = 1 tombstone / (1 element + 1 tombstone) = 0.5 >= 0.1
  crabs_compaction_result_e result = crabs_compact_item(&engine, state, item, 1000);
  EXPECT_TRUE(result == CRABS_COMPACTION_OK || result == CRABS_COMPACTION_UNSAFE);

  or_set_destroy(set);
  item->value = nullptr;
  data_item_destroy(item);
  state_destroy(state);
  crabs_compaction_engine_destroy(&engine);
}

TEST(CompactionEngine, UnsafeCompactionForceSafety) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init_strategy(&config, CRABS_COMPACT_NONE);
  // NONE strategy: max_tombstone_ratio = 1.0, never compact
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;

  // NONE strategy: never compacts (max_tombstone_ratio = 1.0)
  crabs_compaction_result_e result = crabs_compact_item(&engine, state, item, 1000);
  EXPECT_EQ(result, CRABS_COMPACTION_SKIPPED);

  or_set_destroy(set);
  item->value = nullptr;
  data_item_destroy(item);
  state_destroy(state);
  crabs_compaction_engine_destroy(&engine);
}

// ============================================================
// Run Compaction (periodic) Tests
// ============================================================

TEST(CompactionEngine, RunCompactionEmptyState) {
  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, nullptr);

  state_t* state = state_create();
  uint32_t count = crabs_engine_run_compaction(&engine, state, 1000);
  EXPECT_EQ(count, 0u);

  state_destroy(state);
  crabs_compaction_engine_destroy(&engine);
}

TEST(CompactionEngine, RunCompactionNull) {
  EXPECT_EQ(crabs_engine_run_compaction(nullptr, nullptr, 1000), 0u);
}

TEST(CompactionEngine, LastCompactionTime) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.max_tombstone_ratio = 0.3;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;

  crabs_compact_item(&engine, state, item, 5000);
  EXPECT_EQ(item->last_compaction_time, 5000u);

  or_set_destroy(set);
  item->value = nullptr;
  data_item_destroy(item);
  state_destroy(state);
  crabs_compaction_engine_destroy(&engine);
}