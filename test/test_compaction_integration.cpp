//
// Created by victor on 5/2/25.
//
// Tests for Compaction Serialization & Integration (CRABS-78)
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/CRDT/crdt_merge.h"
#include "../src/Compaction/compaction_engine.h"
#include "../src/Compaction/crdt_compaction.h"
#include "../src/Serialization/serialization.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/crypto.h"
#include "test_helpers.h"
}

// Internal handlers not in public header — exposed for testing only.
extern "C" {
crabs_error_e state_machine_op_compact(state_t* state, operation_t* op);
}

// ============================================================
// CRABS_OP_COMPACT constant
// ============================================================

TEST(CompactionIntegration, OpCompactDefined) {
  EXPECT_STREQ(CRABS_OP_COMPACT, "__compact__");
}

// ============================================================
// operation_is_builtin includes compact
// ============================================================

TEST(CompactionIntegration, OperationIsBuiltinCompact) {
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_COMPACT));
}

// ============================================================
// Transition table includes compact
// ============================================================

TEST(CompactionIntegration, TransitionValidForCompact) {
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_IDLE, CRABS_OP_COMPACT));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_LOCKED, CRABS_OP_COMPACT));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_MODIFIED, CRABS_OP_COMPACT));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_VERIFIED, CRABS_OP_COMPACT));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_ERROR, CRABS_OP_COMPACT));
}

// ============================================================
// state_machine_op_compact dispatch
// ============================================================

TEST(CompactionIntegration, StateMachineCompactDispatch) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  state_t* state = env.state;

  // Create an OR-Set with tombstones
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("test_set", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);

  operation_t* op = operation_create(CRABS_OP_COMPACT);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op(&env, op);
  crabs_error_e err = state_machine_execute(state, op);
  EXPECT_EQ(err, CRABS_SUCCESS);

  operation_destroy(op);

  // Clean up — the compaction may have replaced item->value
  or_set_destroy((or_set_t*)item->value);
  item->value = nullptr;
  crabs_test_env_destroy(&env);
}

TEST(CompactionIntegration, StateMachineCompactNullParams) {
  state_t* state = state_create();
  operation_t* op = operation_create(CRABS_OP_COMPACT);

  crabs_error_e err = state_machine_op_compact(nullptr, op);
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);

  err = state_machine_op_compact(state, nullptr);
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);

  operation_destroy(op);
  state_destroy(state);
}

TEST(CompactionIntegration, StateMachineCompactEmptyState) {
  state_t* state = state_create();

  operation_t* op = operation_create(CRABS_OP_COMPACT);
  crabs_error_e err = state_machine_op_compact(state, op);
  EXPECT_EQ(err, CRABS_SUCCESS);

  operation_destroy(op);
  state_destroy(state);
}

// ============================================================
// Serialization: last_compaction_time round-trip
// ============================================================

TEST(CompactionIntegration, SerializeLastCompactionTime) {
  state_t* state = state_create();

  data_item_t* item = data_item_create("counter", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* counter = g_counter_create();
  ASSERT_EQ(g_counter_increment(counter, "node1", 42), CRABS_SUCCESS);
  item->value = counter;
  item->last_compaction_time = 12345;
  state_add_item(state, item);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  data_item_t* restored_item = state_find_item(restored, "counter");
  ASSERT_NE(restored_item, nullptr);
  EXPECT_EQ(restored_item->last_compaction_time, 12345u);

  serialized_buffer_destroy(buf);
  state_destroy(restored);
  state_destroy(state);
}

TEST(CompactionIntegration, SerializeZeroCompactionTime) {
  state_t* state = state_create();

  data_item_t* item = data_item_create("reg", DATA_TYPE_REGISTER, CRDT_LWW_REG);
  item->value = nullptr;
  item->last_compaction_time = 0;  // Never compacted
  state_add_item(state, item);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  data_item_t* restored_item = state_find_item(restored, "reg");
  ASSERT_NE(restored_item, nullptr);
  EXPECT_EQ(restored_item->last_compaction_time, 0u);

  serialized_buffer_destroy(buf);
  state_destroy(restored);
  state_destroy(state);
}

TEST(CompactionIntegration, SerializeNullState) {
  serialized_buffer_t* buf = crabs_serialize_state(nullptr);
  EXPECT_EQ(buf, nullptr);
}

TEST(CompactionIntegration, DeserializeNullData) {
  state_t* s = crabs_deserialize_state(nullptr, 0);
  EXPECT_EQ(s, nullptr);
}

// ============================================================
// Compaction sets last_compaction_time
// ============================================================

TEST(CompactionIntegration, CompactSetsLastCompactionTime) {
  state_t* state = state_create();

  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);

  EXPECT_EQ(item->last_compaction_time, 0u);

  // Run compaction through state machine. Audit F-3: compaction without a
  // peer vector clock is now rejected for STRONG/QUORUM safety (the prior
  // fallback always passed because local_vc was never populated, so
  // compaction destroyed concurrent remote operations). This is a single-
  // replica test, so use FORCE mode.
  crabs_compaction_engine_t engine;
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.max_tombstone_ratio = 0.3;
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = true;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);

  crabs_compact_item(&engine, state, item, 5000);
  EXPECT_EQ(item->last_compaction_time, 5000u);

  crabs_compaction_engine_destroy(&engine);
  or_set_destroy((or_set_t*)item->value);
  item->value = nullptr;
  state_destroy(state);
}

// ============================================================
// Audit pass-3 LOW (E6): __compact__ clock routing
// ============================================================
// The __compact__ op path must drive the compaction rate window and
// timestamp comparisons from the state's AUTHENTICATED time source
// (R8-T-1 discipline), not from time(NULL). Pre-fix, the op handler called
// crabs_op_compact_now → crabs_engine_get_time_ms (wall clock); a host that
// steers the wall clock accelerates compaction and dodges rate limits.

namespace {

// Mutable fixed clock: get_time returns ctx->now_ms as a valid physical
// time, letting the test move "now" without touching the wall clock.
struct compact_fixed_clock_t {
  uint64_t now_ms;
};

crabs_time_source_ops_t* compact_make_fixed_clock(compact_fixed_clock_t* clock) {
  static crabs_time_source_ops_t fixed_ops;
  fixed_ops.get_time = [](void* ctx) -> crabs_physical_time_t {
    compact_fixed_clock_t* clk = (compact_fixed_clock_t*)ctx;
    crabs_physical_time_t phys;
    phys.seconds = clk->now_ms / 1000;
    phys.nanos = (clk->now_ms % 1000) * 1000000ull;
    phys.valid = true;
    return phys;
  };
  fixed_ops.is_available = [](void* ctx) -> bool {
    (void)ctx;
    return true;
  };
  fixed_ops.ctx = clock;
  return &fixed_ops;
}

// Unavailable clock: reports no valid time, so state_get_time_ms fails and
// the op handler must fall back to the engine wall clock.
crabs_time_source_ops_t* compact_make_unavailable_clock() {
  static crabs_time_source_ops_t unavailable_ops;
  unavailable_ops.get_time = [](void* ctx) -> crabs_physical_time_t {
    (void)ctx;
    crabs_physical_time_t phys = {0, 0, false};
    return phys;
  };
  unavailable_ops.is_available = [](void* ctx) -> bool {
    (void)ctx;
    return false;
  };
  unavailable_ops.ctx = nullptr;
  return &unavailable_ops;
}

data_item_t* compact_add_tombstoned_set(state_t* state, const char* name) {
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create(name, DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;
  state_add_item(state, item);
  return item;
}

crabs_error_e compact_fire(state_t* state) {
  operation_t* op = operation_create(CRABS_OP_COMPACT);
  crabs_error_e err = state_machine_op_compact(state, op);
  operation_destroy(op);
  return err;
}

} // namespace

TEST(CompactionOpClock, CompactFollowsInjectedTimeSourceNotWallClock) {
  // Injected epoch deliberately far from wall-clock now (~1.7e12 ms): any
  // read of the wall clock diverges catastrophically from the injected
  // clock, so every timestamp assertion below discriminates the two.
  const uint64_t injected_epoch_ms = 1000000;
  const uint64_t rate_window_ms = 60000;

  state_t* state = state_create();

  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.max_tombstone_ratio = 0.3;
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = true;
  config.min_compaction_interval_ms = 0;  // isolate the rate-window gate
  config.max_compactions_per_window = 1;
  config.compaction_rate_window_ms = rate_window_ms;

  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);
  state_set_compaction_engine(state, &engine);

  // Three items, each individually compactable: one pass compacts at most
  // one of them per rate window (max 1/window).
  data_item_t* item_one = compact_add_tombstoned_set(state, "set_one");
  data_item_t* item_two = compact_add_tombstoned_set(state, "set_two");
  data_item_t* item_three = compact_add_tombstoned_set(state, "set_three");

  compact_fixed_clock_t clock = {injected_epoch_ms};
  state_set_time_source(state, compact_make_fixed_clock(&clock));

  // Pass 1 inside the window: exactly one item compacts (list order is
  // insertion-reversed) and must be stamped with the INJECTED time; the
  // same-window budget refuses the other two. Pre-fix (wall clock) the
  // stamp reads ~now*1000 and fails outright.
  EXPECT_EQ(compact_fire(state), CRABS_SUCCESS);
  uint32_t compacted_first_pass = 0;
  const data_item_t* pass_items[3] = {item_one, item_two, item_three};
  for (uint32_t item_index = 0; item_index < 3; item_index++) {
    uint64_t stamp = pass_items[item_index]->last_compaction_time;
    if (stamp == 0) continue;
    EXPECT_EQ(stamp, injected_epoch_ms);
    compacted_first_pass++;
  }
  EXPECT_EQ(compacted_first_pass, 1u);

  // Advance the INJECTED clock past the rate window. The wall clock has not
  // moved by a window's worth, so a wall-clock-driven gate still refuses;
  // the authenticated-clock gate must reset. The pass-1 item no longer
  // needs compaction (tombstones collected), so a second item advances to
  // the new stamp and the third stays refused.
  clock.now_ms = injected_epoch_ms + rate_window_ms + 1000;
  EXPECT_EQ(compact_fire(state), CRABS_SUCCESS);
  uint32_t stamped_epoch = 0, stamped_advanced = 0, stamped_never = 0;
  for (uint32_t item_index = 0; item_index < 3; item_index++) {
    uint64_t stamp = pass_items[item_index]->last_compaction_time;
    if (stamp == injected_epoch_ms) stamped_epoch++;
    else if (stamp == clock.now_ms) stamped_advanced++;
    else if (stamp == 0) stamped_never++;
    else ADD_FAILURE() << "unexpected stamp " << stamp;
  }
  EXPECT_EQ(stamped_epoch, 1u);
  EXPECT_EQ(stamped_advanced, 1u);
  EXPECT_EQ(stamped_never, 1u);

  state_set_time_source(state, nullptr);
  state_set_compaction_engine(state, nullptr);
  crabs_compaction_engine_destroy(&engine);
  or_set_destroy((or_set_t*)item_one->value);
  item_one->value = nullptr;
  or_set_destroy((or_set_t*)item_two->value);
  item_two->value = nullptr;
  or_set_destroy((or_set_t*)item_three->value);
  item_three->value = nullptr;
  state_destroy(state);
}

TEST(CompactionOpClock, CompactFallsBackToWallClockWithoutTimeSource) {
  // Clock-less host contract (mirrors the pump's clock-untrusted
  // convention): with no usable authenticated time source, the op resolves
  // via the engine wall clock — behavior identical to the pre-fix path.
  state_t* state = state_create();

  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.max_tombstone_ratio = 0.3;
  config.safety_level = CRABS_SAFETY_FORCE;
  config.allow_force = true;
  config.min_compaction_interval_ms = 0;

  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, &config);
  crabs_register_crdt_vtables(&engine.registry);
  state_set_compaction_engine(state, &engine);

  data_item_t* item = compact_add_tombstoned_set(state, "set_wall");

  state_set_time_source(state, compact_make_unavailable_clock());

  EXPECT_EQ(compact_fire(state), CRABS_SUCCESS);
  // Wall-clock-derived stamp: any modern epoch reading (2026 era, ~1.7e12
  // ms) clears this bound; an injected/zero stamp would not.
  EXPECT_GT(item->last_compaction_time, 1000000000000ull);

  state_set_time_source(state, nullptr);
  state_set_compaction_engine(state, nullptr);
  crabs_compaction_engine_destroy(&engine);
  or_set_destroy((or_set_t*)item->value);
  item->value = nullptr;
  state_destroy(state);
}