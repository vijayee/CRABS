//
// Created by victor on 5/1/25.
//
// Tests for OT_ORDERED_SET Data Type (v1.5 §5)
//

#include <gtest/gtest.h>
#include <cstdlib>
extern "C" {
#include "../src/OT/ot_ordered_set.h"
}

static crabs_ot_op_id_t make_id(const char* node, uint64_t seq, uint64_t ts) {
  crabs_ot_op_id_t id;
  crabs_ot_op_id_init(&id, node, seq, ts);
  return id;
}

// Free payload from a stack-allocated operation (doesn't free the op struct itself)
static void op_payload_free(crabs_ot_operation_t* op) {
  if (op && op->payload) {
    free(op->payload);
    op->payload = nullptr;
    op->payload_size = 0;
  }
}

static crabs_ot_operation_t make_insert_op(uint64_t pos, const char* node,
    uint64_t seq, const uint8_t* payload = nullptr, uint32_t payload_size = 0) {
  crabs_ot_operation_t op;
  crabs_ot_operation_init(&op);
  op.op_type = CRABS_OT_OP_INSERT;
  op.visible_pos = pos;
  crabs_ot_op_id_init(&op.id, node, seq, 1000);
  if (payload && payload_size > 0) {
    crabs_ot_operation_set_payload(&op, payload, payload_size);
  }
  return op;
}

// ============================================================
// Element Lifecycle Tests
// ============================================================

TEST(OTOrderedSet, ElementCreateDestroy) {
  crabs_ot_op_id_t id = make_id("n1", 1, 100);
  uint8_t data[] = {0xAA, 0xBB};
  crabs_ordered_element_t* elem = crabs_ordered_element_create(&id, data, 2);
  ASSERT_NE(elem, nullptr);
  EXPECT_TRUE(crabs_ot_op_id_equal(&elem->id, &id));
  ASSERT_NE(elem->value, nullptr);
  EXPECT_EQ(elem->value_size, 2u);
  EXPECT_EQ(elem->value[0], 0xAA);
  EXPECT_FALSE(elem->deleted);
  crabs_ordered_element_destroy(elem);
}

TEST(OTOrderedSet, ElementCreateNull) {
  crabs_ordered_element_t* elem = crabs_ordered_element_create(NULL, NULL, 0);
  ASSERT_NE(elem, nullptr);
  EXPECT_EQ(elem->value, nullptr);
  EXPECT_EQ(elem->value_size, 0u);
  crabs_ordered_element_destroy(elem);
  crabs_ordered_element_destroy(NULL);
}

// ============================================================
// Ordered Set Lifecycle Tests
// ============================================================

TEST(OTOrderedSet, CreateDestroy) {
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  ASSERT_NE(set, nullptr);
  EXPECT_EQ(crabs_ot_ordered_set_count(set), 0u);
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 0u);
  EXPECT_NE(set->ot_data, nullptr);
  crabs_ot_ordered_set_destroy(set);
}

TEST(OTOrderedSet, DestroyNull) {
  crabs_ot_ordered_set_destroy(NULL);
}

// ============================================================
// INSERT Tests
// ============================================================

TEST(OTOrderedSet, InsertSingle) {
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  uint8_t data[] = {0x01};
  crabs_ot_operation_t op = make_insert_op(0, "n1", 1, data, 1);
  crabs_ordered_element_t* elem = crabs_ot_ordered_set_apply_insert(set, &op);
  ASSERT_NE(elem, nullptr);
  EXPECT_EQ(crabs_ot_ordered_set_count(set), 1u);
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 1u);
  op_payload_free(&op);
  crabs_ot_ordered_set_destroy(set);
}

TEST(OTOrderedSet, InsertMultiple) {
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  uint8_t d1[] = {0x01}, d2[] = {0x02}, d3[] = {0x03};
  crabs_ot_operation_t op1 = make_insert_op(0, "n1", 1, d1, 1);
  crabs_ot_operation_t op2 = make_insert_op(1, "n1", 2, d2, 1);
  crabs_ot_operation_t op3 = make_insert_op(2, "n1", 3, d3, 1);

  crabs_ot_ordered_set_apply_insert(set, &op1);
  crabs_ot_ordered_set_apply_insert(set, &op2);
  crabs_ot_ordered_set_apply_insert(set, &op3);

  EXPECT_EQ(crabs_ot_ordered_set_count(set), 3u);
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 3u);

  crabs_ordered_element_t* head = crabs_ot_ordered_set_head(set);
  ASSERT_NE(head, nullptr);
  EXPECT_EQ(head->value[0], 0x01);

  crabs_ordered_element_t* tail = crabs_ot_ordered_set_tail(set);
  ASSERT_NE(tail, nullptr);
  EXPECT_EQ(tail->value[0], 0x03);

  op_payload_free(&op1);
  op_payload_free(&op2);
  op_payload_free(&op3);
  crabs_ot_ordered_set_destroy(set);
}

// ============================================================
// DELETE Tests
// ============================================================

TEST(OTOrderedSet, DeleteElement) {
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  uint8_t d1[] = {0x01}, d2[] = {0x02}, d3[] = {0x03};
  crabs_ot_operation_t op1 = make_insert_op(0, "n1", 1, d1, 1);
  crabs_ot_operation_t op2 = make_insert_op(1, "n1", 2, d2, 1);
  crabs_ot_operation_t op3 = make_insert_op(2, "n1", 3, d3, 1);
  crabs_ot_ordered_set_apply_insert(set, &op1);
  crabs_ot_ordered_set_apply_insert(set, &op2);
  crabs_ot_ordered_set_apply_insert(set, &op3);

  // Delete at visible position 1 (middle element)
  crabs_ot_operation_t del_op;
  crabs_ot_operation_init(&del_op);
  del_op.op_type = CRABS_OT_OP_DELETE;
  del_op.visible_pos = 1;
  crabs_ordered_element_t* deleted = crabs_ot_ordered_set_apply_delete(set, &del_op);
  ASSERT_NE(deleted, nullptr);
  EXPECT_TRUE(deleted->deleted);
  EXPECT_EQ(crabs_ot_ordered_set_count(set), 3u);
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 2u);

  op_payload_free(&op1);
  op_payload_free(&op2);
  op_payload_free(&op3);
  crabs_ot_ordered_set_destroy(set);
}

// ============================================================
// UPDATE Tests
// ============================================================

TEST(OTOrderedSet, UpdateElement) {
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  uint8_t d1[] = {0x01};
  crabs_ot_operation_t op1 = make_insert_op(0, "n1", 1, d1, 1);
  crabs_ot_ordered_set_apply_insert(set, &op1);

  uint8_t new_val[] = {0xFF, 0xFE};
  crabs_ot_operation_t upd_op;
  crabs_ot_operation_init(&upd_op);
  upd_op.op_type = CRABS_OT_OP_UPDATE;
  upd_op.visible_pos = 0;
  crabs_ot_operation_set_payload(&upd_op, new_val, 2);

  crabs_ordered_element_t* updated = crabs_ot_ordered_set_apply_update(set, &upd_op);
  ASSERT_NE(updated, nullptr);
  EXPECT_EQ(updated->value_size, 2u);
  EXPECT_EQ(updated->value[0], 0xFF);

  op_payload_free(&op1);
  op_payload_free(&upd_op);
  crabs_ot_ordered_set_destroy(set);
}

// ============================================================
// MOVE Tests
// ============================================================

TEST(OTOrderedSet, MoveElement) {
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  uint8_t d1[] = {0x01}, d2[] = {0x02}, d3[] = {0x03};
  crabs_ot_operation_t op1 = make_insert_op(0, "n1", 1, d1, 1);
  crabs_ot_operation_t op2 = make_insert_op(1, "n1", 2, d2, 1);
  crabs_ot_operation_t op3 = make_insert_op(2, "n1", 3, d3, 1);
  crabs_ot_ordered_set_apply_insert(set, &op1);
  crabs_ot_ordered_set_apply_insert(set, &op2);
  crabs_ot_ordered_set_apply_insert(set, &op3);

  // Move element at pos 0 to pos 2
  crabs_ot_operation_t move_op;
  crabs_ot_operation_init(&move_op);
  move_op.op_type = CRABS_OT_OP_MOVE;
  move_op.visible_pos = 0;
  move_op.visible_pos_2 = 2;
  crabs_ot_op_id_init(&move_op.id, "n1", 4, 1001);
  crabs_ot_ordered_set_apply_move(set, &move_op);

  EXPECT_EQ(crabs_ot_ordered_set_count(set), 3u);
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 3u);

  // After moving [A, B, C] -> [B, C, A]
  crabs_ordered_element_t* head = crabs_ot_ordered_set_get(set, 0);
  ASSERT_NE(head, nullptr);
  EXPECT_EQ(head->value[0], 0x02);

  crabs_ordered_element_t* tail = crabs_ot_ordered_set_get(set, 2);
  ASSERT_NE(tail, nullptr);
  EXPECT_EQ(tail->value[0], 0x01);

  op_payload_free(&op1);
  op_payload_free(&op2);
  op_payload_free(&op3);
  crabs_ot_ordered_set_destroy(set);
}

// ============================================================
// SWAP Tests
// ============================================================

TEST(OTOrderedSet, SwapElements) {
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  uint8_t d1[] = {0x01}, d2[] = {0x02}, d3[] = {0x03};
  crabs_ot_operation_t op1 = make_insert_op(0, "n1", 1, d1, 1);
  crabs_ot_operation_t op2 = make_insert_op(1, "n1", 2, d2, 1);
  crabs_ot_operation_t op3 = make_insert_op(2, "n1", 3, d3, 1);
  crabs_ot_ordered_set_apply_insert(set, &op1);
  crabs_ot_ordered_set_apply_insert(set, &op2);
  crabs_ot_ordered_set_apply_insert(set, &op3);

  // Swap positions 0 and 2
  crabs_ot_operation_t swap_op;
  crabs_ot_operation_init(&swap_op);
  swap_op.op_type = CRABS_OT_OP_SWAP;
  swap_op.visible_pos = 0;
  swap_op.visible_pos_2 = 2;
  crabs_ot_ordered_set_apply_swap(set, &swap_op);

  crabs_ordered_element_t* first = crabs_ot_ordered_set_get(set, 0);
  ASSERT_NE(first, nullptr);
  EXPECT_EQ(first->value[0], 0x03);

  crabs_ordered_element_t* last = crabs_ot_ordered_set_get(set, 2);
  ASSERT_NE(last, nullptr);
  EXPECT_EQ(last->value[0], 0x01);

  op_payload_free(&op1);
  op_payload_free(&op2);
  op_payload_free(&op3);
  crabs_ot_ordered_set_destroy(set);
}

// ============================================================
// Apply Dispatch Tests
// ============================================================

TEST(OTOrderedSet, ApplyDispatch) {
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  uint8_t d1[] = {0x01};
  crabs_ot_operation_t op = make_insert_op(0, "n1", 1, d1, 1);
  crabs_ordered_element_t* elem = crabs_ot_ordered_set_apply(set, &op);
  ASSERT_NE(elem, nullptr);
  EXPECT_EQ(crabs_ot_ordered_set_count(set), 1u);

  crabs_ot_operation_t del_op;
  crabs_ot_operation_init(&del_op);
  del_op.op_type = CRABS_OT_OP_DELETE;
  del_op.visible_pos = 0;
  crabs_ot_ordered_set_apply(set, &del_op);
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 0u);

  op_payload_free(&op);
  crabs_ot_ordered_set_destroy(set);
}

TEST(OTOrderedSet, ApplyNull) {
  EXPECT_EQ(crabs_ot_ordered_set_apply(NULL, NULL), nullptr);
}

// ============================================================
// Access Tests
// ============================================================

TEST(OTOrderedSet, GetOutOfBounds) {
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  EXPECT_EQ(crabs_ot_ordered_set_get(set, 0), nullptr);
  uint8_t d[] = {0x01};
  crabs_ot_operation_t op = make_insert_op(0, "n1", 1, d, 1);
  crabs_ot_ordered_set_apply_insert(set, &op);
  EXPECT_EQ(crabs_ot_ordered_set_get(set, 99), nullptr);
  op_payload_free(&op);
  crabs_ot_ordered_set_destroy(set);
}

TEST(OTOrderedSet, FindById) {
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  uint8_t d[] = {0x01};
  crabs_ot_operation_t op = make_insert_op(0, "n1", 1, d, 1);
  crabs_ot_ordered_set_apply_insert(set, &op);

  crabs_ot_op_id_t id = make_id("n1", 1, 1000);
  crabs_ordered_element_t* found = crabs_ot_ordered_set_find(set, &id);
  ASSERT_NE(found, nullptr);

  crabs_ot_op_id_t missing = make_id("n2", 99, 9999);
  EXPECT_EQ(crabs_ot_ordered_set_find(set, &missing), nullptr);
  EXPECT_EQ(crabs_ot_ordered_set_find(NULL, &id), nullptr);
  EXPECT_EQ(crabs_ot_ordered_set_find(set, NULL), nullptr);

  op_payload_free(&op);
  crabs_ot_ordered_set_destroy(set);
}

// ============================================================
// CRDT Merge Tests
// ============================================================

TEST(OTOrderedSet, MergeAddsElements) {
  crabs_ot_ordered_set_t* dest = crabs_ot_ordered_set_create();
  crabs_ot_ordered_set_t* src = crabs_ot_ordered_set_create();

  uint8_t d1[] = {0x01}, d2[] = {0x02};
  crabs_ot_operation_t op1 = make_insert_op(0, "n1", 1, d1, 1);
  crabs_ot_operation_t op2 = make_insert_op(0, "n2", 1, d2, 1);
  crabs_ot_ordered_set_apply_insert(dest, &op1);
  crabs_ot_ordered_set_apply_insert(src, &op2);

  crabs_ot_ordered_set_merge(dest, src);
  EXPECT_EQ(crabs_ot_ordered_set_count(dest), 2u);

  op_payload_free(&op1);
  op_payload_free(&op2);
  crabs_ot_ordered_set_destroy(dest);
  crabs_ot_ordered_set_destroy(src);
}

TEST(OTOrderedSet, MergeIsCommutativeForDistinctSingletons) {
  crabs_ot_ordered_set_t* ab = crabs_ot_ordered_set_create();
  crabs_ot_ordered_set_t* ba = crabs_ot_ordered_set_create();
  crabs_ot_ordered_set_t* a = crabs_ot_ordered_set_create();
  crabs_ot_ordered_set_t* b = crabs_ot_ordered_set_create();
  uint8_t av[] = {0x01}, bv[] = {0x02};
  crabs_ot_operation_t a1 = make_insert_op(0, "A", 1, av, 1);
  crabs_ot_operation_t a2 = make_insert_op(0, "A", 1, av, 1);
  crabs_ot_operation_t b1 = make_insert_op(0, "B", 1, bv, 1);
  crabs_ot_operation_t b2 = make_insert_op(0, "B", 1, bv, 1);
  crabs_ot_ordered_set_apply_insert(ab, &a1);
  crabs_ot_ordered_set_apply_insert(a, &a2);
  crabs_ot_ordered_set_apply_insert(ba, &b1);
  crabs_ot_ordered_set_apply_insert(b, &b2);

  ASSERT_EQ(crabs_ot_ordered_set_merge(ab, b), ab);
  ASSERT_EQ(crabs_ot_ordered_set_merge(ba, a), ba);
  ASSERT_NE(ab->head, nullptr);
  ASSERT_NE(ba->head, nullptr);
  ASSERT_NE(ab->head->next, nullptr);
  ASSERT_NE(ba->head->next, nullptr);
  EXPECT_TRUE(crabs_ot_op_id_equal(&ab->head->id, &ba->head->id));
  EXPECT_TRUE(crabs_ot_op_id_equal(&ab->head->next->id, &ba->head->next->id));

  op_payload_free(&a1); op_payload_free(&a2);
  op_payload_free(&b1); op_payload_free(&b2);
  crabs_ot_ordered_set_destroy(ab); crabs_ot_ordered_set_destroy(ba);
  crabs_ot_ordered_set_destroy(a); crabs_ot_ordered_set_destroy(b);
}

TEST(OTOrderedSet, MergeRejectsConflictingPayloadWithoutMutation) {
  crabs_ot_ordered_set_t* dest = crabs_ot_ordered_set_create();
  crabs_ot_ordered_set_t* src = crabs_ot_ordered_set_create();
  uint8_t one[] = {0x01}, two[] = {0x02};
  crabs_ot_operation_t left = make_insert_op(0, "A", 1, one, 1);
  crabs_ot_operation_t right = make_insert_op(0, "A", 1, two, 1);
  crabs_ot_ordered_set_apply_insert(dest, &left);
  crabs_ot_ordered_set_apply_insert(src, &right);

  EXPECT_EQ(crabs_ot_ordered_set_merge(dest, src), nullptr);
  ASSERT_NE(dest->head, nullptr);
  EXPECT_EQ(dest->count, 1u);
  EXPECT_EQ(dest->head->value[0], 0x01);

  op_payload_free(&left); op_payload_free(&right);
  crabs_ot_ordered_set_destroy(dest); crabs_ot_ordered_set_destroy(src);
}

TEST(OTOrderedSet, MergeDeletionWins) {
  crabs_ot_ordered_set_t* dest = crabs_ot_ordered_set_create();
  crabs_ot_ordered_set_t* src = crabs_ot_ordered_set_create();

  uint8_t d1[] = {0x01};
  crabs_ot_operation_t op1 = make_insert_op(0, "n1", 1, d1, 1);
  crabs_ot_ordered_set_apply_insert(dest, &op1);
  crabs_ot_ordered_set_apply_insert(src, &op1);

  // Delete in src
  crabs_ot_operation_t del_op;
  crabs_ot_operation_init(&del_op);
  del_op.op_type = CRABS_OT_OP_DELETE;
  del_op.visible_pos = 0;
  crabs_ot_ordered_set_apply_delete(src, &del_op);

  crabs_ot_ordered_set_merge(dest, src);
  crabs_ordered_element_t* elem = crabs_ot_ordered_set_find(dest, &op1.id);
  ASSERT_NE(elem, nullptr);
  EXPECT_TRUE(elem->deleted);
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(dest), 0u);

  op_payload_free(&op1);
  crabs_ot_ordered_set_destroy(dest);
  crabs_ot_ordered_set_destroy(src);
}

TEST(OTOrderedSet, MergeNull) {
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  EXPECT_EQ(crabs_ot_ordered_set_merge(set, NULL), set);
  EXPECT_EQ(crabs_ot_ordered_set_merge(NULL, set), nullptr);
  crabs_ot_ordered_set_destroy(set);
}
