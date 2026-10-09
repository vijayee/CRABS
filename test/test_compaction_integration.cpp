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