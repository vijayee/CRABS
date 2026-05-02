//
// Created by victor on 5/1/25.
//
// Tests for OT Operation Types & Core Structs (v1.5 §3.2, §3.4)
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/OT/ot_types.h"
}

// ============================================================
// OT Op Type Enum Tests
// ============================================================

TEST(OTTypes, OpTypeEnumValues) {
  EXPECT_EQ(CRABS_OT_OP_INSERT, 0x01);
  EXPECT_EQ(CRABS_OT_OP_DELETE, 0x02);
  EXPECT_EQ(CRABS_OT_OP_UPDATE, 0x03);
  EXPECT_EQ(CRABS_OT_OP_MOVE,   0x04);
  EXPECT_EQ(CRABS_OT_OP_SWAP,   0x05);
  EXPECT_EQ(CRABS_OT_OP_COMPACT, 0x06);
  EXPECT_EQ(CRABS_OT_OP_INSERT_TEXT, 0x11);
  EXPECT_EQ(CRABS_OT_OP_INSERT_NODE, 0x21);
  EXPECT_EQ(CRABS_OT_OP_TYPE_COUNT, 15);
}

TEST(OTTypes, OpTypeName) {
  EXPECT_STREQ(crabs_ot_op_type_name(CRABS_OT_OP_INSERT), "INSERT");
  EXPECT_STREQ(crabs_ot_op_type_name(CRABS_OT_OP_DELETE), "DELETE");
  EXPECT_STREQ(crabs_ot_op_type_name(CRABS_OT_OP_UPDATE), "UPDATE");
  EXPECT_STREQ(crabs_ot_op_type_name(CRABS_OT_OP_MOVE),   "MOVE");
  EXPECT_STREQ(crabs_ot_op_type_name(CRABS_OT_OP_SWAP),   "SWAP");
  EXPECT_STREQ(crabs_ot_op_type_name(CRABS_OT_OP_COMPACT), "COMPACT");
  EXPECT_STREQ(crabs_ot_op_type_name((crabs_ot_op_type_e)99), "UNKNOWN");
}

// ============================================================
// OT Op ID Tests
// ============================================================

TEST(OTTypes, OpIdInit) {
  crabs_ot_op_id_t id;
  crabs_ot_op_id_init(&id, "node1", 42, 1000);
  EXPECT_STREQ(id.node_id, "node1");
  EXPECT_EQ(id.sequence_num, 42u);
  EXPECT_EQ(id.timestamp, 1000u);
}

TEST(OTTypes, OpIdInitNull) {
  crabs_ot_op_id_t id;
  crabs_ot_op_id_init(NULL, "node1", 1, 1);
  crabs_ot_op_id_init(&id, NULL, 0, 0);
  EXPECT_EQ(id.node_id[0], '\0');
  EXPECT_EQ(id.sequence_num, 0u);
  EXPECT_EQ(id.timestamp, 0u);
}

TEST(OTTypes, OpIdInitLongNodeId) {
  crabs_ot_op_id_t id;
  char long_id[128];
  memset(long_id, 'A', 127);
  long_id[127] = '\0';
  crabs_ot_op_id_init(&id, long_id, 1, 1);
  EXPECT_EQ(strnlen(id.node_id, CRABS_MAX_USER_ID), CRABS_MAX_USER_ID - 1);
}

TEST(OTTypes, OpIdEqual) {
  crabs_ot_op_id_t a, b;
  crabs_ot_op_id_init(&a, "node1", 42, 1000);
  crabs_ot_op_id_init(&b, "node1", 42, 1000);
  EXPECT_TRUE(crabs_ot_op_id_equal(&a, &b));
}

TEST(OTTypes, OpIdNotEqualNodeId) {
  crabs_ot_op_id_t a, b;
  crabs_ot_op_id_init(&a, "node1", 42, 1000);
  crabs_ot_op_id_init(&b, "node2", 42, 1000);
  EXPECT_FALSE(crabs_ot_op_id_equal(&a, &b));
}

TEST(OTTypes, OpIdNotEqualSeqNum) {
  crabs_ot_op_id_t a, b;
  crabs_ot_op_id_init(&a, "node1", 42, 1000);
  crabs_ot_op_id_init(&b, "node1", 43, 1000);
  EXPECT_FALSE(crabs_ot_op_id_equal(&a, &b));
}

TEST(OTTypes, OpIdNotEqualTimestamp) {
  crabs_ot_op_id_t a, b;
  crabs_ot_op_id_init(&a, "node1", 42, 1000);
  crabs_ot_op_id_init(&b, "node1", 42, 2000);
  EXPECT_FALSE(crabs_ot_op_id_equal(&a, &b));
}

TEST(OTTypes, OpIdEqualNull) {
  EXPECT_TRUE(crabs_ot_op_id_equal(NULL, NULL));
  EXPECT_FALSE(crabs_ot_op_id_equal(NULL, (crabs_ot_op_id_t*)1));
  EXPECT_FALSE(crabs_ot_op_id_equal((crabs_ot_op_id_t*)1, NULL));
}

// ============================================================
// OT Operation Lifecycle Tests
// ============================================================

TEST(OTTypes, OperationCreateDestroy) {
  crabs_ot_operation_t* op = crabs_ot_operation_create();
  ASSERT_NE(op, nullptr);
  EXPECT_EQ(op->op_type, 0);
  EXPECT_EQ(op->visible_pos, 0u);
  EXPECT_EQ(op->visible_pos_2, 0u);
  EXPECT_EQ(op->payload, nullptr);
  EXPECT_EQ(op->payload_size, 0u);
  EXPECT_EQ(op->priority, 0u);
  EXPECT_EQ(op->dep_count, 0u);
  EXPECT_EQ(op->transform_fn_id, 0u);
  crabs_ot_operation_destroy(op);
}

TEST(OTTypes, OperationDestroyNull) {
  crabs_ot_operation_destroy(NULL);
}

TEST(OTTypes, OperationInit) {
  crabs_ot_operation_t op;
  op.op_type = CRABS_OT_OP_INSERT;
  op.visible_pos = 99;
  crabs_ot_operation_init(&op);
  EXPECT_EQ(op.op_type, 0);
  EXPECT_EQ(op.visible_pos, 0u);
}

TEST(OTTypes, OperationInitNull) {
  crabs_ot_operation_init(NULL);
}

// ============================================================
// OT Operation Payload Tests
// ============================================================

TEST(OTTypes, OperationSetPayload) {
  crabs_ot_operation_t* op = crabs_ot_operation_create();
  uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
  EXPECT_TRUE(crabs_ot_operation_set_payload(op, data, 4));
  ASSERT_NE(op->payload, nullptr);
  EXPECT_EQ(op->payload_size, 4u);
  EXPECT_EQ(op->payload[0], 0x01);
  EXPECT_EQ(op->payload[3], 0x04);
  crabs_ot_operation_destroy(op);
}

TEST(OTTypes, OperationSetPayloadReplaces) {
  crabs_ot_operation_t* op = crabs_ot_operation_create();
  uint8_t data1[] = {0xAA, 0xBB};
  uint8_t data2[] = {0xCC, 0xDD, 0xEE};
  crabs_ot_operation_set_payload(op, data1, 2);
  crabs_ot_operation_set_payload(op, data2, 3);
  EXPECT_EQ(op->payload_size, 3u);
  EXPECT_EQ(op->payload[0], 0xCC);
  crabs_ot_operation_destroy(op);
}

TEST(OTTypes, OperationSetPayloadNull) {
  crabs_ot_operation_t* op = crabs_ot_operation_create();
  uint8_t data[] = {0x01};
  crabs_ot_operation_set_payload(op, data, 1);
  EXPECT_TRUE(crabs_ot_operation_set_payload(op, NULL, 0));
  EXPECT_EQ(op->payload, nullptr);
  EXPECT_EQ(op->payload_size, 0u);
  crabs_ot_operation_destroy(op);
}

TEST(OTTypes, OperationSetPayloadTooLarge) {
  crabs_ot_operation_t* op = crabs_ot_operation_create();
  EXPECT_FALSE(crabs_ot_operation_set_payload(op, NULL, CRABS_OT_MAX_PAYLOAD + 1));
  crabs_ot_operation_destroy(op);
}

TEST(OTTypes, OperationSetPayloadNullOp) {
  uint8_t data[] = {0x01};
  EXPECT_FALSE(crabs_ot_operation_set_payload(NULL, data, 1));
}

// ============================================================
// OT Operation Dependency Tests
// ============================================================

TEST(OTTypes, OperationAddDep) {
  crabs_ot_operation_t* op = crabs_ot_operation_create();
  crabs_ot_op_id_t dep;
  crabs_ot_op_id_init(&dep, "node1", 10, 100);
  crabs_ot_operation_add_dep(op, &dep);
  EXPECT_EQ(op->dep_count, 1u);
  EXPECT_TRUE(crabs_ot_op_id_equal(&op->deps[0], &dep));
  crabs_ot_operation_destroy(op);
}

TEST(OTTypes, OperationAddMultipleDeps) {
  crabs_ot_operation_t* op = crabs_ot_operation_create();
  crabs_ot_op_id_t dep1, dep2, dep3;
  crabs_ot_op_id_init(&dep1, "n1", 1, 100);
  crabs_ot_op_id_init(&dep2, "n2", 2, 200);
  crabs_ot_op_id_init(&dep3, "n3", 3, 300);
  crabs_ot_operation_add_dep(op, &dep1);
  crabs_ot_operation_add_dep(op, &dep2);
  crabs_ot_operation_add_dep(op, &dep3);
  EXPECT_EQ(op->dep_count, 3u);
  EXPECT_TRUE(crabs_ot_op_id_equal(&op->deps[0], &dep1));
  EXPECT_TRUE(crabs_ot_op_id_equal(&op->deps[2], &dep3));
  crabs_ot_operation_destroy(op);
}

TEST(OTTypes, OperationAddDepOverflow) {
  crabs_ot_operation_t* op = crabs_ot_operation_create();
  crabs_ot_op_id_t dep;
  crabs_ot_op_id_init(&dep, "n", 1, 1);
  for (int i = 0; i < CRABS_OT_MAX_DEPS + 5; i++) {
    crabs_ot_operation_add_dep(op, &dep);
  }
  EXPECT_EQ(op->dep_count, (uint32_t)CRABS_OT_MAX_DEPS);
  crabs_ot_operation_destroy(op);
}

TEST(OTTypes, OperationAddDepNull) {
  crabs_ot_operation_t* op = crabs_ot_operation_create();
  crabs_ot_operation_add_dep(op, NULL);
  EXPECT_EQ(op->dep_count, 0u);
  crabs_ot_operation_add_dep(NULL, (crabs_ot_op_id_t*)1);
  crabs_ot_operation_destroy(op);
}

// ============================================================
// OT Operation Field Access Tests
// ============================================================

TEST(OTTypes, OperationFieldAccess) {
  crabs_ot_operation_t* op = crabs_ot_operation_create();
  crabs_ot_op_id_init(&op->id, "node42", 7, 3000);
  op->op_type = CRABS_OT_OP_INSERT;
  op->visible_pos = 5;
  op->visible_pos_2 = 0;
  op->priority = 10;
  op->transform_fn_id = 3;

  EXPECT_STREQ(op->id.node_id, "node42");
  EXPECT_EQ(op->id.sequence_num, 7u);
  EXPECT_EQ(op->id.timestamp, 3000u);
  EXPECT_EQ(op->op_type, CRABS_OT_OP_INSERT);
  EXPECT_EQ(op->visible_pos, 5u);
  EXPECT_EQ(op->visible_pos_2, 0u);
  EXPECT_EQ(op->priority, 10u);
  EXPECT_EQ(op->transform_fn_id, 3u);

  crabs_ot_operation_destroy(op);
}

TEST(OTTypes, OperationMoveFieldAccess) {
  crabs_ot_operation_t* op = crabs_ot_operation_create();
  op->op_type = CRABS_OT_OP_MOVE;
  op->visible_pos = 3;
  op->visible_pos_2 = 7;
  EXPECT_EQ(op->op_type, CRABS_OT_OP_MOVE);
  EXPECT_EQ(op->visible_pos, 3u);
  EXPECT_EQ(op->visible_pos_2, 7u);
  crabs_ot_operation_destroy(op);
}

// ============================================================
// OT Data Item Lifecycle Tests
// ============================================================

TEST(OTTypes, DataItemCreateDestroy) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(1);
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->ot_type_id, 1u);
  EXPECT_EQ(item->position_map, nullptr);
  ASSERT_NE(item->op_log, nullptr);
  EXPECT_EQ(item->op_log_count, 0u);
  EXPECT_EQ(item->op_log_capacity, (uint32_t)CRABS_OT_OP_LOG_INITIAL);
  EXPECT_EQ(item->priority_counters, nullptr);
  EXPECT_EQ(item->priority_counter_count, 0u);
  crabs_ot_data_item_destroy(item);
}

TEST(OTTypes, DataItemDestroyNull) {
  crabs_ot_data_item_destroy(NULL);
}

// ============================================================
// OT Data Item Op Log Tests
// ============================================================

TEST(OTTypes, DataItemAppendOp) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(1);
  crabs_ot_operation_t* op = crabs_ot_data_item_append_op(item);
  ASSERT_NE(op, nullptr);
  EXPECT_EQ(item->op_log_count, 1u);

  crabs_ot_op_id_init(&op->id, "node1", 1, 100);
  op->op_type = CRABS_OT_OP_INSERT;
  op->visible_pos = 0;

  EXPECT_EQ(item->op_log[0].op_type, CRABS_OT_OP_INSERT);
  crabs_ot_data_item_destroy(item);
}

TEST(OTTypes, DataItemAppendMultipleOps) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(1);
  for (int i = 0; i < 20; i++) {
    crabs_ot_operation_t* op = crabs_ot_data_item_append_op(item);
    ASSERT_NE(op, nullptr);
    op->op_type = CRABS_OT_OP_INSERT;
    crabs_ot_op_id_init(&op->id, "node1", (uint64_t)i, 100);
  }
  EXPECT_EQ(item->op_log_count, 20u);
  EXPECT_GE(item->op_log_capacity, 20u);
  crabs_ot_data_item_destroy(item);
}

TEST(OTTypes, DataItemAppendOpNull) {
  EXPECT_EQ(crabs_ot_data_item_append_op(NULL), nullptr);
}

// ============================================================
// OT Data Item Position Map Tests
// ============================================================

TEST(OTTypes, DataItemPositionMap) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(1);
  EXPECT_EQ(item->position_map, nullptr);

  item->position_map = crabs_bst_insert(NULL, 5);
  item->position_map = crabs_union_one(item->position_map, 3);

  EXPECT_NE(item->position_map, nullptr);
  EXPECT_EQ(crabs_bst_size(item->position_map), 2u);

  crabs_ot_data_item_destroy(item);
}

// ============================================================
// OT Data Item Transform Matrix Tests
// ============================================================

static crabs_ot_operation_t* test_transform_insert_delete(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  (void)op2;
  return op1;
}

TEST(OTTypes, DataItemSetGetTransform) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(1);

  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_INSERT, CRABS_OT_OP_DELETE,
                                    test_transform_insert_delete);
  crabs_ot_transform_fn fn = crabs_ot_data_item_get_transform(item,
    CRABS_OT_OP_INSERT, CRABS_OT_OP_DELETE);
  EXPECT_EQ(fn, test_transform_insert_delete);

  crabs_ot_data_item_destroy(item);
}

TEST(OTTypes, DataItemTransformDefaultNull) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(1);
  crabs_ot_transform_fn fn = crabs_ot_data_item_get_transform(item,
    CRABS_OT_OP_INSERT, CRABS_OT_OP_DELETE);
  EXPECT_EQ(fn, nullptr);
  crabs_ot_data_item_destroy(item);
}

TEST(OTTypes, DataItemSetTransformInvalidType) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(1);
  crabs_ot_data_item_set_transform(item, (crabs_ot_op_type_e)0, CRABS_OT_OP_DELETE,
                                    test_transform_insert_delete);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_INSERT, (crabs_ot_op_type_e)99,
                                    test_transform_insert_delete);
  crabs_ot_transform_fn fn = crabs_ot_data_item_get_transform(item,
    CRABS_OT_OP_INSERT, CRABS_OT_OP_DELETE);
  EXPECT_EQ(fn, nullptr);
  crabs_ot_data_item_destroy(item);
}

TEST(OTTypes, DataItemSetTransformNull) {
  crabs_ot_data_item_set_transform(NULL, CRABS_OT_OP_INSERT, CRABS_OT_OP_DELETE,
                                    test_transform_insert_delete);
  EXPECT_EQ(crabs_ot_data_item_get_transform(NULL,
    CRABS_OT_OP_INSERT, CRABS_OT_OP_DELETE), nullptr);
}

// ============================================================
// OT Data Item Priority Tests
// ============================================================

TEST(OTTypes, DataItemNextPriority) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(1);
  uint64_t p = crabs_ot_data_item_next_priority(item, "node1");
  EXPECT_GT(p, 0u);
  crabs_ot_data_item_destroy(item);
}

TEST(OTTypes, DataItemNextPriorityNull) {
  EXPECT_EQ(crabs_ot_data_item_next_priority(NULL, "node1"), 0u);
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(1);
  EXPECT_EQ(crabs_ot_data_item_next_priority(item, NULL), 0u);
  crabs_ot_data_item_destroy(item);
}