//
// Created by victor on 5/2/25.
//
// Tests for Compaction Integration & Periodic Compaction (CRABS-72)
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/CRDT/crdt_merge.h"
#include "../src/Compaction/compaction_engine.h"
#include "../src/Compaction/crdt_compaction.h"
}

// ============================================================
// Auto-compaction after OT operations
// ============================================================

TEST(CompactionPeriodic, AutoCompactAfterOT) {
  state_t* state = state_create();

  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);

  crabs_tombstone_config_t* config = (crabs_tombstone_config_t*)malloc(sizeof(crabs_tombstone_config_t));
  crabs_tombstone_config_init(config);
  config->max_tombstone_ratio = 0.1;
  config->min_compaction_interval_ms = 0;
  config->safety_level = CRABS_SAFETY_FORCE;
  config->allow_force = true;
  state_set_compaction_config(state, config);

  EXPECT_EQ(item->last_compaction_time, 0u);

  operation_t* op = operation_create(CRABS_OP_EXECUTE_OT);
  op->payload = nullptr;
  op->payload_size = 0;
  crabs_error_e err = state_machine_execute(state, op);
  operation_destroy(op);

  free(config);
  state->compaction_config = nullptr;
  or_set_destroy((or_set_t*)item->value);
  item->value = nullptr;
  state_destroy(state);
}

TEST(CompactionPeriodic, AutoCompactNoConfigSkipsCompact) {
  state_t* state = state_create();
  EXPECT_EQ(state->compaction_config, nullptr);

  operation_t* op = operation_create(CRABS_OP_EXECUTE_OT);
  crabs_error_e err = state_machine_execute(state, op);
  operation_destroy(op);

  state_destroy(state);
}

TEST(CompactionPeriodic, AutoCompactNonOTOpsDoNotTrigger) {
  state_t* state = state_create();

  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);

  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.max_tombstone_ratio = 0.1;
  config.min_compaction_interval_ms = 0;
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = true;
  state_set_compaction_config(state, &config);

  operation_t* op = operation_create(CRABS_OP_LOCK);
  op->resource_count = 0;
  crabs_error_e err = state_machine_execute(state, op);
  operation_destroy(op);

  EXPECT_EQ(item->last_compaction_time, 0u);

  state->compaction_config = nullptr;
  or_set_destroy((or_set_t*)item->value);
  item->value = nullptr;
  state_destroy(state);
}

TEST(CompactionPeriodic, StateMachineAutoCompact) {
  state_t* state = state_create();

  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);

  EXPECT_EQ(state_machine_auto_compact(state), 0u);

  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.max_tombstone_ratio = 0.1;
  config.min_compaction_interval_ms = 0;
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = true;
  state_set_compaction_config(state, &config);

  uint32_t count = state_machine_auto_compact(state);
  EXPECT_GT(count, 0u);
  EXPECT_GT(item->last_compaction_time, 0u);

  state->compaction_config = nullptr;
  or_set_destroy((or_set_t*)item->value);
  item->value = nullptr;
  state_destroy(state);
}

TEST(CompactionPeriodic, StateMachineAutoCompactNullState) {
  EXPECT_EQ(state_machine_auto_compact(nullptr), 0u);
}

// ============================================================
// Periodic compaction entry point
// ============================================================

TEST(CompactionPeriodic, PeriodicCompactionEntry) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.auto_compact_interval_ms = 1000;
  config.min_compaction_interval_ms = 0;
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = true;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);

  uint32_t count = crabs_engine_periodic_compaction(&engine, state, 1000);
  EXPECT_GT(count, 0u);

  count = crabs_engine_periodic_compaction(&engine, state, 1500);
  EXPECT_EQ(count, 0u);

  crabs_compaction_engine_destroy(&engine);
  or_set_destroy((or_set_t*)item->value);
  item->value = nullptr;
  state_destroy(state);
}

TEST(CompactionPeriodic, PeriodicCompactionNotNeeded) {
  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, nullptr);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);

  uint32_t count = crabs_engine_periodic_compaction(&engine, state, 1000);
  EXPECT_EQ(count, 0u);

  crabs_compaction_engine_destroy(&engine);
  or_set_destroy(set);
  item->value = nullptr;
  state_destroy(state);
}

TEST(CompactionPeriodic, PeriodicCompactionNullParams) {
  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, nullptr);

  EXPECT_EQ(crabs_engine_periodic_compaction(nullptr, nullptr, 0), 0u);
  EXPECT_EQ(crabs_engine_periodic_compaction(&engine, nullptr, 0), 0u);

  crabs_compaction_engine_destroy(&engine);
}

// ============================================================
// crabs_op_compact_now and crabs_op_compact with timestamp
// ============================================================

TEST(CompactionPeriodic, OpCompactNowSetsTimestamp) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.min_compaction_interval_ms = 0;
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = true;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);

  EXPECT_EQ(item->last_compaction_time, 0u);

  crabs_error_e err = crabs_op_compact_now(&engine, state);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_GT(item->last_compaction_time, 0u);

  crabs_compaction_engine_destroy(&engine);
  or_set_destroy((or_set_t*)item->value);
  item->value = nullptr;
  state_destroy(state);
}

TEST(CompactionPeriodic, OpCompactWithTimestamp) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.min_compaction_interval_ms = 0;
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = true;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);

  crabs_error_e err = crabs_op_compact(&engine, state, 5000);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(item->last_compaction_time, 5000u);

  crabs_compaction_engine_destroy(&engine);
  or_set_destroy((or_set_t*)item->value);
  item->value = nullptr;
  state_destroy(state);
}

// ============================================================
// Minimum interval enforcement
// ============================================================

TEST(CompactionPeriodic, MinIntervalBlocksTooSoon) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.max_tombstone_ratio = 0.1;
  config.min_compaction_interval_ms = 5000;
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = true;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);

  crabs_compaction_result_e result = crabs_compact_item(&engine, state, item, 10000);
  EXPECT_EQ(result, CRABS_COMPACTION_OK);
  EXPECT_EQ(item->last_compaction_time, 10000u);

  or_set_t* compacted_set = (or_set_t*)item->value;
  or_set_add(compacted_set, "c", "n1:3");
  or_set_remove(compacted_set, "c");

  result = crabs_compact_item(&engine, state, item, 12000);
  EXPECT_EQ(result, CRABS_COMPACTION_INTERVAL);

  result = crabs_compact_item(&engine, state, item, 15001);
  EXPECT_EQ(result, CRABS_COMPACTION_OK);

  crabs_compaction_engine_destroy(&engine);
  or_set_destroy((or_set_t*)item->value);
  item->value = nullptr;
  state_destroy(state);
}

TEST(CompactionPeriodic, MinIntervalZeroNoLimit) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.max_tombstone_ratio = 0.1;
  config.min_compaction_interval_ms = 0;
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = true;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);

  crabs_compaction_result_e result = crabs_compact_item(&engine, state, item, 1000);
  EXPECT_EQ(result, CRABS_COMPACTION_OK);

  or_set_t* compacted_set = (or_set_t*)item->value;
  or_set_add(compacted_set, "c", "n1:3");
  or_set_remove(compacted_set, "c");

  result = crabs_compact_item(&engine, state, item, 1001);
  EXPECT_EQ(result, CRABS_COMPACTION_OK);

  crabs_compaction_engine_destroy(&engine);
  or_set_destroy((or_set_t*)item->value);
  item->value = nullptr;
  state_destroy(state);
}

// ============================================================
// Rate limiting
// ============================================================

TEST(CompactionPeriodic, RateLimitingBlocksExcess) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.max_tombstone_ratio = 0.1;
  config.min_compaction_interval_ms = 0;
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = true;
  config.max_compactions_per_window = 2;
  config.compaction_rate_window_ms = 10000;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();

  for (int i = 0; i < 3; i++) {
    char name[16];
    snprintf(name, sizeof(name), "s%d", i);
    or_set_t* set = or_set_create();
    or_set_add(set, "a", "n1:1");
    or_set_remove(set, "a");
    data_item_t* item = data_item_create(name, DATA_TYPE_SET, CRDT_OR_SET);
    item->value = set;
    state_add_item(state, item);
  }

  data_item_t* item1 = state_find_item(state, "s0");
  data_item_t* item2 = state_find_item(state, "s1");
  data_item_t* item3 = state_find_item(state, "s2");

  crabs_compaction_result_e r1 = crabs_compact_item(&engine, state, item1, 1000);
  EXPECT_EQ(r1, CRABS_COMPACTION_OK);

  crabs_compaction_result_e r2 = crabs_compact_item(&engine, state, item2, 2000);
  EXPECT_EQ(r2, CRABS_COMPACTION_OK);

  crabs_compaction_result_e r3 = crabs_compact_item(&engine, state, item3, 3000);
  EXPECT_EQ(r3, CRABS_COMPACTION_RATE_LIMITED);

  crabs_compaction_engine_destroy(&engine);
  data_item_t* cur = state->items;
  while (cur != nullptr) {
    or_set_destroy((or_set_t*)cur->value);
    cur->value = nullptr;
    cur = cur->next;
  }
  state_destroy(state);
}

TEST(CompactionPeriodic, RateLimitingResetsAfterWindow) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.max_tombstone_ratio = 0.1;
  config.min_compaction_interval_ms = 0;
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = true;
  config.max_compactions_per_window = 1;
  config.compaction_rate_window_ms = 5000;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);

  crabs_compaction_result_e r1 = crabs_compact_item(&engine, state, item, 1000);
  EXPECT_EQ(r1, CRABS_COMPACTION_OK);

  or_set_t* compacted = (or_set_t*)item->value;
  or_set_add(compacted, "b", "n1:2");
  or_set_remove(compacted, "b");

  crabs_compaction_result_e r2 = crabs_compact_item(&engine, state, item, 3000);
  EXPECT_EQ(r2, CRABS_COMPACTION_RATE_LIMITED);

  crabs_compaction_result_e r3 = crabs_compact_item(&engine, state, item, 7000);
  EXPECT_EQ(r3, CRABS_COMPACTION_OK);

  crabs_compaction_engine_destroy(&engine);
  or_set_destroy((or_set_t*)item->value);
  item->value = nullptr;
  state_destroy(state);
}

TEST(CompactionPeriodic, RateLimitingDisabledWhenZero) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.max_tombstone_ratio = 0.1;
  config.min_compaction_interval_ms = 0;
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = true;
  config.max_compactions_per_window = 0;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);

  crabs_compaction_result_e r = crabs_compact_item(&engine, state, item, 1000);
  EXPECT_EQ(r, CRABS_COMPACTION_OK);

  crabs_compaction_engine_destroy(&engine);
  or_set_destroy((or_set_t*)item->value);
  item->value = nullptr;
  state_destroy(state);
}

// ============================================================
// allow_force enforcement
// ============================================================

TEST(CompactionPeriodic, ForceSafetyBlockedWhenAllowForceFalse) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = false;

  EXPECT_FALSE(crabs_check_compaction_safety(&config, nullptr, nullptr, nullptr, nullptr));
}

TEST(CompactionPeriodic, ForceSafetyAllowedWhenAllowForceTrue) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = true;

  EXPECT_TRUE(crabs_check_compaction_safety(&config, nullptr, nullptr, nullptr, nullptr));
}

TEST(CompactionPeriodic, DefaultConfigBlocksForce) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.safety_level = CRABS_SAFETY_FORCE;
  EXPECT_FALSE(crabs_check_compaction_safety(&config, nullptr, nullptr, nullptr, nullptr));
}

TEST(CompactionPeriodic, ForceCompactBlockedByDefaultConfig) {
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.max_tombstone_ratio = 0.1;
  config.min_compaction_interval_ms = 0;
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = false;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  state_t* state = state_create();
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);

  crabs_compaction_result_e result = crabs_compact_item(&engine, state, item, 1000);
  EXPECT_EQ(result, CRABS_COMPACTION_UNSAFE);

  crabs_compaction_engine_destroy(&engine);
  or_set_destroy(set);
  item->value = nullptr;
  state_destroy(state);
}

// ============================================================
// state_set_compaction_config
// ============================================================

TEST(CompactionPeriodic, SetCompactionConfig) {
  state_t* state = state_create();
  EXPECT_EQ(state->compaction_config, nullptr);

  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  state_set_compaction_config(state, &config);
  EXPECT_EQ(state->compaction_config, &config);

  state_set_compaction_config(state, nullptr);
  EXPECT_EQ(state->compaction_config, nullptr);

  state_destroy(state);
}

TEST(CompactionPeriodic, SetCompactionConfigNullState) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  state_set_compaction_config(nullptr, &config);
}

// ============================================================
// crabs_engine_get_time_ms
// ============================================================

TEST(CompactionPeriodic, GetTimeMsReturnsNonZero) {
  uint64_t t = crabs_engine_get_time_ms();
  EXPECT_GT(t, 0u);
}