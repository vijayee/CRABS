//
// Created by victor on 5/1/25.
//
// Tests for OT Transform Functions & Matrix (v1.5 §4)
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/OT/ot_transform.h"
}

// Helper: create an operation on the stack
static crabs_ot_operation_t make_op(crabs_ot_op_type_e type, uint64_t pos,
                                     uint64_t pos2 = 0, uint64_t priority = 1) {
  crabs_ot_operation_t op;
  crabs_ot_operation_init(&op);
  op.op_type = type;
  op.visible_pos = pos;
  op.visible_pos_2 = pos2;
  op.priority = priority;
  crabs_ot_op_id_init(&op.id, "node", 1, 1000);
  return op;
}

// ============================================================
// Causal Ordering Tests
// ============================================================

TEST(OTTransform, CausallyBeforeSameNode) {
  crabs_ot_op_id_t a, b;
  crabs_ot_op_id_init(&a, "node1", 1, 1000);
  crabs_ot_op_id_init(&b, "node1", 2, 1000);
  EXPECT_TRUE(crabs_causally_before(&a, &b));
  EXPECT_FALSE(crabs_causally_before(&b, &a));
}

TEST(OTTransform, CausallyBeforeDiffNode) {
  // Cross-node IDs alone carry no causal information (wall-clock comparison
  // is unsound). Causality across nodes is decided by the dependency set.
  crabs_ot_op_id_t a, b;
  crabs_ot_op_id_init(&a, "node1", 5, 1000);
  crabs_ot_op_id_init(&b, "node2", 1, 2000);
  EXPECT_FALSE(crabs_causally_before(&a, &b));
  EXPECT_FALSE(crabs_causally_before(&b, &a));
}

TEST(OTTransform, CausallyBeforeNull) {
  crabs_ot_op_id_t a;
  crabs_ot_op_id_init(&a, "node1", 1, 1000);
  EXPECT_FALSE(crabs_causally_before(NULL, &a));
  EXPECT_FALSE(crabs_causally_before(&a, NULL));
  EXPECT_FALSE(crabs_causally_before(NULL, NULL));
}

// ============================================================
// T1: INSERT vs INSERT
// ============================================================

TEST(OTTransform, InsertInsertDifferentPositions) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_INSERT, 5);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_INSERT, 3);
  crabs_transform_insert_insert(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 6u);
}

TEST(OTTransform, InsertInsertSamePositionLowerPriority) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_INSERT, 3, 0, 2);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_INSERT, 3, 0, 1);
  crabs_transform_insert_insert(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 4u);
}

TEST(OTTransform, InsertInsertSamePositionHigherPriority) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_INSERT, 3, 0, 1);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_INSERT, 3, 0, 2);
  crabs_transform_insert_insert(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 3u);
}

TEST(OTTransform, InsertInsertBeforeOther) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_INSERT, 3);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_INSERT, 5);
  crabs_transform_insert_insert(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 3u);
}

// ============================================================
// T2: DELETE vs INSERT
// ============================================================

TEST(OTTransform, DeleteInsertAfter) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_DELETE, 5);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_INSERT, 3);
  crabs_transform_delete_insert(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 6u);
}

TEST(OTTransform, DeleteInsertBefore) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_DELETE, 3);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_INSERT, 5);
  crabs_transform_delete_insert(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 3u);
}

// ============================================================
// T3: INSERT vs DELETE
// ============================================================

TEST(OTTransform, InsertDeleteBeforeInsert) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_INSERT, 5);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_DELETE, 3);
  crabs_transform_insert_delete(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 4u);
}

TEST(OTTransform, InsertDeleteAfterInsert) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_INSERT, 3);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_DELETE, 5);
  crabs_transform_insert_delete(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 3u);
}

// ============================================================
// T4: DELETE vs DELETE
// ============================================================

TEST(OTTransform, DeleteDeleteDifferentPositions) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_DELETE, 5);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_DELETE, 3);
  crabs_transform_delete_delete(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 4u);
}

TEST(OTTransform, DeleteDeleteSamePosition) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_DELETE, 3);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_DELETE, 3);
  crabs_transform_delete_delete(&op1, &op2);
  EXPECT_EQ(op1.op_type, 0);
}

// ============================================================
// T5: MOVE vs MOVE
// ============================================================

TEST(OTTransform, MoveMoveSameSource) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_MOVE, 3, 7);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_MOVE, 3, 9);
  crabs_transform_move_move(&op1, &op2);
  EXPECT_EQ(op1.op_type, 0);
}

TEST(OTTransform, MoveMoveDifferentSource) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_MOVE, 5, 10);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_MOVE, 2, 8);
  crabs_transform_move_move(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 4u);
  EXPECT_EQ(op1.visible_pos_2, 11u);
}

// ============================================================
// T6: SWAP vs INSERT
// ============================================================

TEST(OTTransform, SwapInsertBefore) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_SWAP, 3, 7);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_INSERT, 2);
  crabs_transform_swap_insert(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 4u);
  EXPECT_EQ(op1.visible_pos_2, 8u);
}

TEST(OTTransform, SwapInsertAfter) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_SWAP, 3, 7);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_INSERT, 10);
  crabs_transform_swap_insert(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 3u);
  EXPECT_EQ(op1.visible_pos_2, 7u);
}

// ============================================================
// T7: SWAP vs DELETE
// ============================================================

TEST(OTTransform, SwapDeleteBefore) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_SWAP, 4, 8);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_DELETE, 2);
  crabs_transform_swap_delete(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 3u);
  EXPECT_EQ(op1.visible_pos_2, 7u);
}

TEST(OTTransform, SwapDeleteAfter) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_SWAP, 3, 7);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_DELETE, 10);
  crabs_transform_swap_delete(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 3u);
  EXPECT_EQ(op1.visible_pos_2, 7u);
}

// ============================================================
// Null Safety Tests
// ============================================================

TEST(OTTransform, NullSafety) {
  crabs_ot_operation_t op = make_op(CRABS_OT_OP_INSERT, 3);
  EXPECT_EQ(crabs_transform_insert_insert(NULL, &op), nullptr);
  EXPECT_EQ(crabs_transform_insert_insert(&op, nullptr), &op);
  EXPECT_EQ(crabs_transform_delete_insert(NULL, &op), nullptr);
  EXPECT_EQ(crabs_transform_insert_delete(NULL, &op), nullptr);
  EXPECT_EQ(crabs_transform_delete_delete(NULL, &op), nullptr);
  EXPECT_EQ(crabs_transform_move_move(NULL, &op), nullptr);
  EXPECT_EQ(crabs_transform_swap_insert(NULL, &op), nullptr);
  EXPECT_EQ(crabs_transform_swap_delete(NULL, &op), nullptr);
}

// ============================================================
// Identity Transform Tests
// ============================================================

TEST(OTTransform, IdentityNoChange) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_UPDATE, 5);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_INSERT, 3);
  crabs_transform_identity(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 5u);
}

// ============================================================
// Matrix Initialization Tests
// ============================================================

TEST(OTTransform, MatrixInit) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(1);
  crabs_transform_matrix_init(item);

  // Verify INSERT vs INSERT is set
  crabs_ot_transform_fn fn = crabs_ot_data_item_get_transform(item,
    CRABS_OT_OP_INSERT, CRABS_OT_OP_INSERT);
  EXPECT_EQ(fn, crabs_transform_insert_insert);

  // Verify DELETE vs DELETE is set
  fn = crabs_ot_data_item_get_transform(item, CRABS_OT_OP_DELETE, CRABS_OT_OP_DELETE);
  EXPECT_EQ(fn, crabs_transform_delete_delete);

  // Verify UPDATE vs UPDATE is identity
  fn = crabs_ot_data_item_get_transform(item, CRABS_OT_OP_UPDATE, CRABS_OT_OP_UPDATE);
  EXPECT_EQ(fn, crabs_transform_identity);

  crabs_ot_data_item_destroy(item);
}

TEST(OTTransform, MatrixAllEntriesSet) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(1);
  crabs_transform_matrix_init(item);

  crabs_ot_op_type_e types[] = {
    CRABS_OT_OP_INSERT, CRABS_OT_OP_DELETE, CRABS_OT_OP_UPDATE,
    CRABS_OT_OP_MOVE, CRABS_OT_OP_SWAP
  };

  for (int i = 0; i < 5; i++) {
    for (int j = 0; j < 5; j++) {
      crabs_ot_transform_fn fn = crabs_ot_data_item_get_transform(item, types[i], types[j]);
      EXPECT_NE(fn, nullptr) << "Missing transform for " << i << " vs " << j;
    }
  }
  crabs_ot_data_item_destroy(item);
}

// ============================================================
// Transform Entry Lookup Tests
// ============================================================

TEST(OTTransform, MatrixEntryLookup) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(1);
  crabs_transform_matrix_init(item);

  crabs_transform_entry_t* entry = crabs_transform_matrix_get_entry(
    item, CRABS_OT_OP_INSERT, CRABS_OT_OP_INSERT);
  ASSERT_NE(entry, nullptr);
  EXPECT_NE(entry->fn, nullptr);
  EXPECT_NE(entry->description[0], '\0');

  crabs_ot_data_item_destroy(item);
}

TEST(OTTransform, MatrixEntryInvalidType) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(1);
  EXPECT_EQ(crabs_transform_matrix_get_entry(item, (crabs_ot_op_type_e)0, CRABS_OT_OP_INSERT), nullptr);
  EXPECT_EQ(crabs_transform_matrix_get_entry(item, CRABS_OT_OP_INSERT, (crabs_ot_op_type_e)99), nullptr);
  crabs_ot_data_item_destroy(item);
}

// ============================================================
// Integration: Transform through Matrix
// ============================================================

TEST(OTTransform, TransformThroughMatrix) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(1);
  crabs_transform_matrix_init(item);

  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_INSERT, 5);
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_DELETE, 3);

  crabs_ot_transform_fn fn = crabs_ot_data_item_get_transform(item,
    op1.op_type, op2.op_type);
  ASSERT_NE(fn, nullptr);
  fn(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 4u);

  crabs_ot_data_item_destroy(item);
}