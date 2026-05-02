//
// Created by victor on 5/1/25.
//
// Tests for OT Execution Integration (v1.5 §8)
//

#include <gtest/gtest.h>
#include <cstdlib>
extern "C" {
#include "../src/OT/ot_execution.h"
#include "../src/OT/ot_ordered_set.h"
#include "../src/OT/ot_tree.h"
#include "../src/StateMachine/state_machine.h"
}

static crabs_ot_op_id_t make_id(const char* node, uint64_t seq, uint64_t ts) {
  crabs_ot_op_id_t id;
  crabs_ot_op_id_init(&id, node, seq, ts);
  return id;
}

// ============================================================
// Type Registration Tests
// ============================================================

TEST(OTExecution, IsOtType) {
  EXPECT_TRUE(crabs_is_ot_type(DATA_TYPE_OT_ORDERED_SET));
  EXPECT_TRUE(crabs_is_ot_type(DATA_TYPE_OT_DOCUMENT));
  EXPECT_TRUE(crabs_is_ot_type(DATA_TYPE_OT_TREE));
  EXPECT_FALSE(crabs_is_ot_type(DATA_TYPE_COUNTER));
  EXPECT_FALSE(crabs_is_ot_type(DATA_TYPE_CUSTOM));
}

TEST(OTExecution, RegisterOrderedSet) {
  state_t* state = state_create();
  crabs_ot_config_t config;
  memset(&config, 0, sizeof(config));
  config.max_op_log_size = 100;
  config.allow_move = true;
  config.allow_swap = true;
  strncpy(config.priority_node_id, "node1", CRABS_MAX_USER_ID - 1);

  data_item_t* item = crabs_register_ot_type(state, "playlist",
    DATA_TYPE_OT_ORDERED_SET, &config);
  ASSERT_NE(item, nullptr);
  EXPECT_NE(item->ot_data, nullptr);
  EXPECT_NE(item->value, nullptr);

  state_destroy(state);
}

TEST(OTExecution, RegisterTree) {
  state_t* state = state_create();
  crabs_ot_config_t config;
  memset(&config, 0, sizeof(config));
  config.max_op_log_size = 50;

  data_item_t* item = crabs_register_ot_type(state, "tree1",
    DATA_TYPE_OT_TREE, &config);
  ASSERT_NE(item, nullptr);
  EXPECT_NE(item->ot_data, nullptr);
  EXPECT_NE(item->value, nullptr);

  state_destroy(state);
}

TEST(OTExecution, RegisterNullState) {
  crabs_ot_config_t config;
  memset(&config, 0, sizeof(config));
  EXPECT_EQ(crabs_register_ot_type(nullptr, "test", DATA_TYPE_OT_ORDERED_SET, &config), nullptr);
}

TEST(OTExecution, RegisterNonOtType) {
  state_t* state = state_create();
  crabs_ot_config_t config;
  memset(&config, 0, sizeof(config));
  EXPECT_EQ(crabs_register_ot_type(state, "counter", DATA_TYPE_COUNTER, &config), nullptr);
  state_destroy(state);
}

// ============================================================
// Extract OT Ops Tests
// ============================================================

TEST(OTExecution, ExtractNullPayload) {
  crabs_ot_operation_t* ops = nullptr;
  uint32_t count = crabs_extract_ot_ops(nullptr, 0, &ops);
  EXPECT_EQ(count, 0u);
  EXPECT_EQ(ops, nullptr);
}

TEST(OTExecution, ExtractEmptyOps) {
  uint8_t payload[4] = {0, 0, 0, 0}; // count = 0
  crabs_ot_operation_t* ops = nullptr;
  uint32_t count = crabs_extract_ot_ops(payload, 4, &ops);
  EXPECT_EQ(count, 0u);
}

TEST(OTExecution, FreeNullOps) {
  crabs_ot_ops_free(nullptr, 0);
}

// ============================================================
// Apply OT Op Tests
// ============================================================

TEST(OTExecution, ApplyOrderedSetOp) {
  state_t* state = state_create();
  data_item_t* item = crabs_register_ot_type(state, "list",
    DATA_TYPE_OT_ORDERED_SET, nullptr);
  ASSERT_NE(item, nullptr);

  crabs_ot_operation_t op;
  crabs_ot_operation_init(&op);
  op.op_type = CRABS_OT_OP_INSERT;
  op.visible_pos = 0;
  crabs_ot_op_id_init(&op.id, "n1", 1, 100);
  uint8_t data[] = {0x01};
  crabs_ot_operation_set_payload(&op, data, 1);

  crabs_error_e err = crabs_apply_ot_op(item, &op);
  EXPECT_EQ(err, CRABS_SUCCESS);

  crabs_ot_ordered_set_t* set = (crabs_ot_ordered_set_t*)item->value;
  EXPECT_EQ(crabs_ot_ordered_set_count(set), 1u);
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 1u);

  // Free payload only (op is stack-allocated, don't free the struct)
  if (op.payload) { free(op.payload); op.payload = nullptr; }
  state_destroy(state);
}

TEST(OTExecution, ApplyTreeOp) {
  state_t* state = state_create();
  data_item_t* item = crabs_register_ot_type(state, "tree",
    DATA_TYPE_OT_TREE, nullptr);
  ASSERT_NE(item, nullptr);

  crabs_ot_operation_t op;
  crabs_ot_operation_init(&op);
  op.op_type = (crabs_ot_op_type_e)CRABS_OT_OP_INSERT_NODE;
  op.visible_pos = 0;
  crabs_ot_op_id_init(&op.id, "n1", 1, 100);
  // Payload: parent_id[64] + node_id[64]
  uint8_t payload[128];
  memset(payload, 0, sizeof(payload));
  // root node: empty parent_id, node_id = "root"
  memcpy(payload + 64, "root", 4);
  crabs_ot_operation_set_payload(&op, payload, 128);

  crabs_error_e err = crabs_apply_ot_op(item, &op);
  EXPECT_EQ(err, CRABS_SUCCESS);

  crabs_ot_tree_t* tree = (crabs_ot_tree_t*)item->value;
  EXPECT_EQ(crabs_ot_tree_node_count(tree), 1u);

  // Free payload only (op is stack-allocated)
  if (op.payload) { free(op.payload); op.payload = nullptr; }
  state_destroy(state);
}

TEST(OTExecution, ApplyNotOtType) {
  state_t* state = state_create();
  data_item_t* item = data_item_create("counter", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  ASSERT_NE(item, nullptr);
  state_add_item(state, item);

  crabs_ot_operation_t op;
  crabs_ot_operation_init(&op);

  crabs_error_e err = crabs_apply_ot_op(item, &op);
  EXPECT_EQ(err, CRABS_ERR_NOT_OT_TYPE);

  state_destroy(state);
}

TEST(OTExecution, ApplyNullItem) {
  crabs_ot_operation_t op;
  crabs_ot_operation_init(&op);
  EXPECT_EQ(crabs_apply_ot_op(nullptr, &op), CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Transform OT Op Tests
// ============================================================

TEST(OTExecution, TransformWithEmptyLog) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(DATA_TYPE_OT_ORDERED_SET);
  crabs_transform_matrix_init(item);

  crabs_ot_operation_t op;
  crabs_ot_operation_init(&op);
  op.op_type = CRABS_OT_OP_INSERT;
  op.visible_pos = 0;
  crabs_ot_op_id_init(&op.id, "n1", 1, 100);

  crabs_error_e err = crabs_transform_ot_op(&op, item, "n1", 64);
  EXPECT_EQ(err, CRABS_SUCCESS);
  // With empty log, position should be unchanged
  EXPECT_EQ(op.visible_pos, 0u);

  crabs_ot_data_item_destroy(item);
}

TEST(OTExecution, TransformDepthLimit) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(DATA_TYPE_OT_ORDERED_SET);
  crabs_transform_matrix_init(item);

  crabs_ot_operation_t op;
  crabs_ot_operation_init(&op);
  op.op_type = CRABS_OT_OP_INSERT;
  op.visible_pos = 0;
  crabs_ot_op_id_init(&op.id, "n1", 1, 100);

  // Should not exceed max depth
  crabs_error_e err = crabs_transform_ot_op(&op, item, "n1", 2);
  EXPECT_EQ(err, CRABS_SUCCESS);

  crabs_ot_data_item_destroy(item);
}

// ============================================================
// Execute OT Operation through State Machine Tests
// ============================================================

TEST(OTExecution, ExecuteOtOpInvalidParam) {
  state_t* state = state_create();
  operation_t op;
  memset(&op, 0, sizeof(op));

  crabs_error_e err = crabs_execute_ot_operation(nullptr, &op);
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);

  err = crabs_execute_ot_operation(state, nullptr);
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);

  state_destroy(state);
}

TEST(OTExecution, ExecuteOtOpNoOps) {
  state_t* state = state_create();
  data_item_t* item = crabs_register_ot_type(state, "list",
    DATA_TYPE_OT_ORDERED_SET, nullptr);
  ASSERT_NE(item, nullptr);

  operation_t op;
  memset(&op, 0, sizeof(op));
  strncpy(op.type, CRABS_OP_EXECUTE_OT, CRABS_MAX_OP_NAME);
  // No payload = no OT ops

  crabs_error_e err = crabs_execute_ot_operation(state, &op);
  EXPECT_EQ(err, CRABS_ERR_NO_OT_OPS);

  state_destroy(state);
}

// ============================================================
// Log Pruning Tests
// ============================================================

TEST(OTExecution, PruneLog) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(DATA_TYPE_OT_ORDERED_SET);
  crabs_transform_matrix_init(item);

  // Add some ops to the log
  for (uint32_t i = 0; i < 10; i++) {
    crabs_ot_data_item_append_op(item);
    if (item->op_log != nullptr) {
      crabs_ot_operation_init(&item->op_log[item->op_log_count - 1]);
      item->op_log[item->op_log_count - 1].op_type = CRABS_OT_OP_INSERT;
      item->op_log[item->op_log_count - 1].visible_pos = i;
      crabs_ot_op_id_init(&item->op_log[item->op_log_count - 1].id, "n1", i, 100 + i);
    }
  }
  EXPECT_EQ(item->op_log_count, 10u);

  // Prune with max_size = 5 (plus 100 margin = keep 105, so no pruning)
  crabs_prune_ot_log(item, 5);
  EXPECT_EQ(item->op_log_count, 10u); // Not pruned yet

  // Prune with max_size much smaller
  // Need more ops for pruning to kick in
  for (uint32_t i = 10; i < 210; i++) {
    crabs_ot_data_item_append_op(item);
    if (item->op_log != nullptr && item->op_log_count > 0) {
      crabs_ot_operation_init(&item->op_log[item->op_log_count - 1]);
      item->op_log[item->op_log_count - 1].op_type = CRABS_OT_OP_INSERT;
      item->op_log[item->op_log_count - 1].visible_pos = i;
      crabs_ot_op_id_init(&item->op_log[item->op_log_count - 1].id, "n1", i, 100 + i);
    }
  }

  // Now prune
  crabs_prune_ot_log(item, 5);

  crabs_ot_data_item_destroy(item);
}

TEST(OTExecution, PruneNullItem) {
  crabs_prune_ot_log(nullptr, 100);
}