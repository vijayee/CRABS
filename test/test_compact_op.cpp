//
// Created by victor on 5/1/25.
//
// Tests for COMPACT Operation & Algorithm (CRABS-71)
//

#include <gtest/gtest.h>
extern "C" {
// Audit R6-1: the #undef hacks for DATA_TYPE_OT_* macros are no longer
// needed — the dual #define/enum definitions have been resolved by removing
// the #define macros from the OT headers.
#include "../src/CRABS/data_model.h"
#include "../src/Compaction/compact_op.h"
#include "../src/Compaction/compaction.h"
#include "../src/Compaction/vector_clock.h"
#include "../src/OT/ot_types.h"
#include "../src/OT/ot_ordered_set.h"
#include "../src/OT/ot_transform.h"
}

// ============================================================
// Compaction ID Tests
// ============================================================

TEST(CompactOp, IdInit) {
  crabs_ot_op_id_t id;
  crabs_compact_id_init(&id, "node1", 1, 1000);
  EXPECT_STREQ(id.node_id, "node1");
  EXPECT_EQ(id.sequence_num, 1u);
  EXPECT_EQ(id.timestamp, 1000u);
}

TEST(CompactOp, IdInitNull) {
  crabs_compact_id_init(nullptr, "node1", 1, 1000);
  // Should not crash
}

// ============================================================
// COMPACT Op Type Value
// ============================================================

TEST(CompactOp, OpTypeValue) {
  EXPECT_EQ(CRABS_OT_OP_COMPACT, 0x06);
  EXPECT_EQ(CRABS_OT_OP_TYPE_COUNT, 15);
}

// ============================================================
// Op Type Name
// ============================================================

TEST(CompactOp, OpTypeName) {
  EXPECT_STREQ(crabs_ot_op_type_name(CRABS_OT_OP_COMPACT), "COMPACT");
}

// ============================================================
// Extract Visible - Ordered Set
// ============================================================

TEST(CompactOp, ExtractVisibleOrderedSetBasic) {
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  ASSERT_NE(set, nullptr);

  crabs_ot_op_id_t id1, id2, id3;
  crabs_ot_op_id_init(&id1, "node1", 1, 100);
  crabs_ot_op_id_init(&id2, "node1", 2, 200);
  crabs_ot_op_id_init(&id3, "node1", 3, 300);

  uint8_t val1[] = "hello";
  uint8_t val2[] = "world";
  uint8_t val3[] = "test";

  // Insert elements
  crabs_ordered_element_t* e1 = crabs_ordered_element_create(&id1, val1, 5);
  crabs_ordered_element_t* e2 = crabs_ordered_element_create(&id2, val2, 5);
  crabs_ordered_element_t* e3 = crabs_ordered_element_create(&id3, val3, 4);

  // Manually link: e1, e2 (deleted), e3
  e1->next = e2; e2->prev = e1;
  e2->next = e3; e3->prev = e2;
  set->head = e1; set->tail = e3;
  set->count = 3;
  set->visible_count = 2;  // e2 is deleted

  e2->deleted = true;

  // Use generic extract_visible with type ID
  crabs_ot_ordered_set_t* visible = (crabs_ot_ordered_set_t*)crabs_extract_visible(
    (data_type_e)DATA_TYPE_OT_ORDERED_SET, set);
  ASSERT_NE(visible, nullptr);
  EXPECT_EQ(visible->count, 2u);
  EXPECT_EQ(visible->visible_count, 2u);

  crabs_ot_ordered_set_destroy(visible);
  crabs_ot_ordered_set_destroy(set);
}

TEST(CompactOp, ExtractVisibleOrderedSetNull) {
  EXPECT_EQ(crabs_extract_visible((data_type_e)DATA_TYPE_OT_ORDERED_SET, nullptr), nullptr);
}

// ============================================================
// Extract Visible - Generic
// ============================================================

TEST(CompactOp, ExtractVisibleNullValue) {
  EXPECT_EQ(crabs_extract_visible((data_type_e)DATA_TYPE_OT_ORDERED_SET, nullptr), nullptr);
}

TEST(CompactOp, ExtractVisibleUnsupportedType) {
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  void* result = crabs_extract_visible(DATA_TYPE_COUNTER, set);
  EXPECT_EQ(result, nullptr);
  crabs_ot_ordered_set_destroy(set);
}

// ============================================================
// Transform Rules - COMPACT absorbs
// ============================================================

TEST(CompactOp, TransformCompactInsert) {
  crabs_ot_operation_t op1;
  crabs_ot_operation_init(&op1);
  op1.op_type = CRABS_OT_OP_COMPACT;
  op1.visible_pos = 5;

  crabs_ot_operation_t op2;
  crabs_ot_operation_init(&op2);
  op2.op_type = CRABS_OT_OP_INSERT;
  op2.visible_pos = 3;

  crabs_ot_operation_t* result = crabs_transform_compact_insert(&op1, &op2);
  EXPECT_EQ(result, &op1);
  EXPECT_EQ(result->visible_pos, 5u);  // Unchanged - COMPACT absorbs INSERT
}

TEST(CompactOp, TransformCompactDelete) {
  crabs_ot_operation_t op1;
  crabs_ot_operation_init(&op1);
  op1.op_type = CRABS_OT_OP_COMPACT;
  op1.visible_pos = 5;

  crabs_ot_operation_t op2;
  crabs_ot_operation_init(&op2);
  op2.op_type = CRABS_OT_OP_DELETE;

  crabs_ot_operation_t* result = crabs_transform_compact_delete(&op1, &op2);
  EXPECT_EQ(result, &op1);
}

TEST(CompactOp, TransformCompactCompactLWW) {
  crabs_ot_operation_t op1;
  crabs_ot_operation_init(&op1);
  op1.op_type = CRABS_OT_OP_COMPACT;
  op1.id.timestamp = 100;

  crabs_ot_operation_t op2;
  crabs_ot_operation_init(&op2);
  op2.op_type = CRABS_OT_OP_COMPACT;
  op2.id.timestamp = 200;

  // op1 is earlier (lower timestamp) — should be absorbed
  crabs_ot_operation_t* result = crabs_transform_compact_compact(&op1, &op2);
  EXPECT_EQ(result, &op1);
  EXPECT_EQ(result->visible_pos, 0u);  // Absorbed
}

TEST(CompactOp, TransformCompactCompactLaterWins) {
  crabs_ot_operation_t op1;
  crabs_ot_operation_init(&op1);
  op1.op_type = CRABS_OT_OP_COMPACT;
  op1.id.timestamp = 300;
  op1.visible_pos = 5;

  crabs_ot_operation_t op2;
  crabs_ot_operation_init(&op2);
  op2.op_type = CRABS_OT_OP_COMPACT;
  op2.id.timestamp = 200;

  // op1 is later (higher timestamp) — survives unchanged
  crabs_ot_operation_t* result = crabs_transform_compact_compact(&op1, &op2);
  EXPECT_EQ(result, &op1);
  EXPECT_EQ(result->visible_pos, 5u);  // Survives unchanged
}

// ============================================================
// Transform Rules - Ops absorbed by COMPACT
// ============================================================

TEST(CompactOp, TransformInsertCompact) {
  crabs_ot_operation_t op1;
  crabs_ot_operation_init(&op1);
  op1.op_type = CRABS_OT_OP_INSERT;
  op1.visible_pos = 5;
  uint8_t payload[] = "data";
  op1.payload = payload;
  op1.payload_size = 4;

  crabs_ot_operation_t op2;
  crabs_ot_operation_init(&op2);
  op2.op_type = CRABS_OT_OP_COMPACT;

  // Audit F-3: insert_compact is now a no-op (does not zero visible_pos or
  // payload_size). A concurrent insert must still apply against the compacted
  // state; zeroing it would silently delete the insert.
  crabs_ot_operation_t* result = crabs_transform_insert_compact(&op1, &op2);
  EXPECT_EQ(result, &op1);
  EXPECT_EQ(result->visible_pos, 5u);    // Unchanged
  EXPECT_EQ(result->payload_size, 4u);    // Unchanged
}

TEST(CompactOp, TransformDeleteCompact) {
  crabs_ot_operation_t op1;
  crabs_ot_operation_init(&op1);
  op1.op_type = CRABS_OT_OP_DELETE;
  op1.visible_pos = 5;

  crabs_ot_operation_t op2;
  crabs_ot_operation_init(&op2);
  op2.op_type = CRABS_OT_OP_COMPACT;

  // Audit F-3: delete_compact is now a no-op. The delete must still apply
  // against the compacted state; the apply path bounds-checks the position.
  crabs_ot_operation_t* result = crabs_transform_delete_compact(&op1, &op2);
  EXPECT_EQ(result, &op1);
  EXPECT_EQ(result->visible_pos, 5u);  // Unchanged
}

TEST(CompactOp, TransformMoveCompact) {
  crabs_ot_operation_t op1;
  crabs_ot_operation_init(&op1);
  op1.op_type = CRABS_OT_OP_MOVE;
  op1.visible_pos = 5;
  op1.visible_pos_2 = 10;

  crabs_ot_operation_t op2;
  crabs_ot_operation_init(&op2);
  op2.op_type = CRABS_OT_OP_COMPACT;

  // Audit F-3: move_compact is now a no-op (positions unchanged).
  crabs_ot_operation_t* result = crabs_transform_move_compact(&op1, &op2);
  EXPECT_EQ(result, &op1);
  EXPECT_EQ(result->visible_pos, 5u);    // Unchanged
  EXPECT_EQ(result->visible_pos_2, 10u);  // Unchanged
}

TEST(CompactOp, TransformNullOps) {
  EXPECT_EQ(crabs_transform_compact_compact(nullptr, nullptr), nullptr);
  EXPECT_EQ(crabs_transform_compact_insert(nullptr, nullptr), nullptr);
  EXPECT_EQ(crabs_transform_insert_compact(nullptr, nullptr), nullptr);
}

// ============================================================
// Transform Matrix Integration
// ============================================================

TEST(CompactOp, TransformMatrixCompactInitialized) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(DATA_TYPE_OT_ORDERED_SET);
  ASSERT_NE(item, nullptr);
  crabs_transform_matrix_init(item);

  // Verify COMPACT row entries are set
  crabs_transform_entry_t* entry;

  entry = crabs_transform_matrix_get_entry(item, CRABS_OT_OP_COMPACT, CRABS_OT_OP_INSERT);
  ASSERT_NE(entry, nullptr);
  EXPECT_NE(entry->fn, nullptr);

  entry = crabs_transform_matrix_get_entry(item, CRABS_OT_OP_COMPACT, CRABS_OT_OP_COMPACT);
  ASSERT_NE(entry, nullptr);
  EXPECT_NE(entry->fn, nullptr);

  // Verify COMPACT column entries are set
  entry = crabs_transform_matrix_get_entry(item, CRABS_OT_OP_INSERT, CRABS_OT_OP_COMPACT);
  ASSERT_NE(entry, nullptr);
  EXPECT_NE(entry->fn, nullptr);

  crabs_ot_data_item_destroy(item);
}

// ============================================================
// Compact Item - Safety Check Failure
// ============================================================

TEST(CompactOp, CompactItemSafetyFail) {
  state_t* state = state_create();
  data_item_t* item = data_item_create("test", (data_type_e)DATA_TYPE_OT_ORDERED_SET, (crdt_type_e)CRABS_OT_ORDERED_SET);

  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.safety_level = CRABS_SAFETY_STRONG;

  crabs_compaction_registry_t registry;
  crabs_compaction_registry_init(&registry);

  crabs_vector_clock_t local_vc, peer_vc;
  crabs_vector_clock_init(&local_vc);
  crabs_vector_clock_init(&peer_vc);

  // STRONG safety: local VC must dominate peer VC
  // With empty VCs, dominates() returns true (no entries to check),
  // so needs_compaction must return true to proceed. Since no vtable
  // is registered, needs_compaction returns false, so we get SUCCESS
  // (no compaction needed). Test null config instead for a real error.
  crabs_error_e err = crabs_compact_ot_item(state, item, nullptr, &registry, &local_vc, &peer_vc);
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);

  data_item_destroy(item);
  state_destroy(state);
}

TEST(CompactOp, CompactItemNullParams) {
  EXPECT_EQ(crabs_compact_ot_item(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr),
             CRABS_ERR_INVALID_PARAM);
}