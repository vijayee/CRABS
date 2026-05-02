//
// Created by victor on 5/1/25.
//
// Tests for OT Serialization (v1.5 §9)
//

#include <gtest/gtest.h>
#include <cstdlib>
extern "C" {
#include "../src/Serialization/serialization.h"
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/OT/ot_types.h"
#include "../src/OT/ot_ordered_set.h"
#include "../src/OT/ot_document.h"
#include "../src/OT/ot_tree.h"
#include "../src/OT/ot_execution.h"
#include "../src/OT/position_map.h"
#include "../src/OT/ot_transform.h"
}

// ============================================================
// OT Operation Serialization Tests
// ============================================================

TEST(OTSerialization, OtOpRoundTrip) {
  crabs_ot_operation_t op;
  crabs_ot_operation_init(&op);
  op.op_type = CRABS_OT_OP_INSERT;
  op.visible_pos = 5;
  op.visible_pos_2 = 0;
  op.priority = 42;
  crabs_ot_op_id_init(&op.id, "node1", 1, 1000);
  uint8_t payload[] = {0x01, 0x02, 0x03};
  crabs_ot_operation_set_payload(&op, payload, 3);
  op.dep_count = 1;
  op.deps[0] = op.id;
  op.transform_fn_id = 7;

  serialized_buffer_t* buf = crabs_serialize_ot_op(&op);
  ASSERT_NE(buf, nullptr);
  EXPECT_GT(buf->len, (size_t)0);

  crabs_ot_operation_t* restored = crabs_deserialize_ot_op(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->op_type, CRABS_OT_OP_INSERT);
  EXPECT_EQ(restored->visible_pos, 5u);
  EXPECT_EQ(restored->visible_pos_2, 0u);
  EXPECT_EQ(restored->priority, 42u);
  EXPECT_EQ(memcmp(restored->id.node_id, "node1", 5), 0);
  EXPECT_EQ(restored->id.sequence_num, 1u);
  EXPECT_EQ(restored->id.timestamp, 1000u);
  EXPECT_NE(restored->payload, nullptr);
  EXPECT_EQ(restored->payload_size, 3u);
  EXPECT_EQ(restored->dep_count, 1u);
  EXPECT_EQ(restored->transform_fn_id, 7u);

  crabs_ot_operation_destroy(restored);
  serialized_buffer_destroy(buf);
  if (op.payload) { free(op.payload); op.payload = nullptr; }
}

TEST(OTSerialization, OtOpNullInput) {
  EXPECT_EQ(crabs_serialize_ot_op(nullptr), nullptr);
  EXPECT_EQ(crabs_deserialize_ot_op(nullptr, 0), nullptr);
  EXPECT_EQ(crabs_deserialize_ot_op(nullptr, 100), nullptr);
}

TEST(OTSerialization, OtOpLogRoundTrip) {
  crabs_ot_operation_t ops[3];
  for (int i = 0; i < 3; i++) {
    crabs_ot_operation_init(&ops[i]);
    ops[i].op_type = (i == 0) ? CRABS_OT_OP_INSERT :
                     (i == 1) ? CRABS_OT_OP_DELETE : CRABS_OT_OP_UPDATE;
    ops[i].visible_pos = i * 10;
    ops[i].priority = i + 1;
    crabs_ot_op_id_init(&ops[i].id, "node1", i + 1, 1000 + i);
  }

  serialized_buffer_t* buf = crabs_serialize_ot_op_log(ops, 3);
  ASSERT_NE(buf, nullptr);

  crabs_ot_operation_t* restored = nullptr;
  uint32_t count = crabs_deserialize_ot_op_log(buf->data, buf->len, &restored);
  ASSERT_NE(restored, nullptr);
  EXPECT_EQ(count, 3u);
  EXPECT_EQ(restored[0].op_type, CRABS_OT_OP_INSERT);
  EXPECT_EQ(restored[0].visible_pos, 0u);
  EXPECT_EQ(restored[1].op_type, CRABS_OT_OP_DELETE);
  EXPECT_EQ(restored[1].visible_pos, 10u);
  EXPECT_EQ(restored[2].op_type, CRABS_OT_OP_UPDATE);
  EXPECT_EQ(restored[2].visible_pos, 20u);

  crabs_ot_ops_free(restored, count);
  serialized_buffer_destroy(buf);
}

TEST(OTSerialization, OtOpLogEmpty) {
  EXPECT_EQ(crabs_serialize_ot_op_log(nullptr, 0), nullptr);
}

// ============================================================
// BST Position Map Serialization Tests
// ============================================================

TEST(OTSerialization, BstRoundTrip) {
  crabs_bst_node_t* root = crabs_bst_create(50);
  root = crabs_bst_insert(root, 25);
  root = crabs_bst_insert(root, 75);
  root = crabs_bst_insert(root, 10);
  root = crabs_bst_insert(root, 60);

  serialized_buffer_t* buf = crabs_serialize_bst(root);
  ASSERT_NE(buf, nullptr);
  EXPECT_GT(buf->len, (size_t)0);

  crabs_bst_node_t* restored = crabs_deserialize_bst(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_TRUE(crabs_bst_contains(restored, 50));
  EXPECT_TRUE(crabs_bst_contains(restored, 25));
  EXPECT_TRUE(crabs_bst_contains(restored, 75));
  EXPECT_TRUE(crabs_bst_contains(restored, 10));
  EXPECT_TRUE(crabs_bst_contains(restored, 60));
  EXPECT_FALSE(crabs_bst_contains(restored, 99));
  EXPECT_EQ(crabs_bst_size(restored), 5u);

  crabs_bst_destroy(restored);
  crabs_bst_destroy(root);
  serialized_buffer_destroy(buf);
}

TEST(OTSerialization, BstWithDeleted) {
  crabs_bst_node_t* root = crabs_bst_create(100);
  root = crabs_bst_insert(root, 50);
  root = crabs_bst_insert(root, 150);
  crabs_bst_mark_deleted(root, 50);

  serialized_buffer_t* buf = crabs_serialize_bst(root);
  ASSERT_NE(buf, nullptr);

  crabs_bst_node_t* restored = crabs_deserialize_bst(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_TRUE(crabs_bst_contains(restored, 100));
  EXPECT_TRUE(crabs_bst_contains(restored, 50));
  EXPECT_TRUE(crabs_bst_contains(restored, 150));

  // Check that deleted status is preserved
  crabs_bst_node_t* node50 = crabs_bst_find(restored, 50);
  ASSERT_NE(node50, nullptr);
  EXPECT_TRUE(node50->deleted);

  crabs_bst_destroy(restored);
  crabs_bst_destroy(root);
  serialized_buffer_destroy(buf);
}

TEST(OTSerialization, BstNull) {
  EXPECT_EQ(crabs_deserialize_bst(nullptr, 0), nullptr);
}

// ============================================================
// OT Data Item Serialization Tests
// ============================================================

TEST(OTSerialization, OtDataItemRoundTrip) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(DATA_TYPE_OT_ORDERED_SET);
  ASSERT_NE(item, nullptr);
  crabs_transform_matrix_init(item);

  // Add some ops to the log
  for (uint32_t i = 0; i < 3; i++) {
    crabs_ot_data_item_append_op(item);
    if (item->op_log != nullptr && i < item->op_log_count) {
      crabs_ot_operation_init(&item->op_log[i]);
      item->op_log[i].op_type = CRABS_OT_OP_INSERT;
      item->op_log[i].visible_pos = i * 5;
      crabs_ot_op_id_init(&item->op_log[i].id, "n1", i + 1, 1000 + i);
    }
  }

  // Add position map entries
  item->position_map = crabs_bst_create(100);
  item->position_map = crabs_bst_insert(item->position_map, 50);

  serialized_buffer_t* buf = crabs_serialize_ot_data(item);
  ASSERT_NE(buf, nullptr);

  crabs_ot_data_item_t* restored = crabs_deserialize_ot_data(buf->data, buf->len, DATA_TYPE_OT_ORDERED_SET);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->ot_type_id, DATA_TYPE_OT_ORDERED_SET);
  EXPECT_EQ(restored->op_log_count, 3u);
  EXPECT_EQ(restored->op_log[0].visible_pos, 0u);
  EXPECT_EQ(restored->op_log[1].visible_pos, 5u);
  EXPECT_EQ(restored->op_log[2].visible_pos, 10u);
  EXPECT_NE(restored->position_map, nullptr);
  EXPECT_TRUE(crabs_bst_contains(restored->position_map, 100));
  EXPECT_TRUE(crabs_bst_contains(restored->position_map, 50));

  crabs_ot_data_item_destroy(restored);
  crabs_ot_data_item_destroy(item);
  serialized_buffer_destroy(buf);
}

// ============================================================
// State with OT Types Serialization Tests
// ============================================================

TEST(OTSerialization, StateWithOrderedSetRoundTrip) {
  state_t* original = state_create();
  original->version = 100;

  // Register an OT ordered set
  crabs_ot_config_t config;
  memset(&config, 0, sizeof(config));
  config.max_op_log_size = 50;
  strncpy(config.priority_node_id, "node1", CRABS_MAX_USER_ID - 1);
  data_item_t* item = crabs_register_ot_type(original, "playlist",
    DATA_TYPE_OT_ORDERED_SET, &config);
  ASSERT_NE(item, nullptr);

  // Add an element via apply
  crabs_ot_ordered_set_t* set = (crabs_ot_ordered_set_t*)item->value;
  crabs_ot_operation_t op;
  crabs_ot_operation_init(&op);
  op.op_type = CRABS_OT_OP_INSERT;
  op.visible_pos = 0;
  crabs_ot_op_id_init(&op.id, "n1", 1, 100);
  uint8_t val[] = {0xAA, 0xBB};
  crabs_ot_operation_set_payload(&op, val, 2);
  crabs_ot_ordered_set_apply(set, &op);
  if (op.payload) { free(op.payload); op.payload = nullptr; }

  // Serialize
  serialized_buffer_t* buf = crabs_serialize_state(original);
  ASSERT_NE(buf, nullptr);

  // Deserialize
  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  // Verify state
  EXPECT_EQ(restored->version, 100u);
  data_item_t* r_item = state_find_item(restored, "playlist");
  ASSERT_NE(r_item, nullptr);
  EXPECT_EQ(r_item->type, DATA_TYPE_OT_ORDERED_SET);
  EXPECT_NE(r_item->value, nullptr);
  EXPECT_NE(r_item->ot_data, nullptr);

  crabs_ot_ordered_set_t* r_set = (crabs_ot_ordered_set_t*)r_item->value;
  EXPECT_EQ(crabs_ot_ordered_set_count(r_set), 1u);

  state_destroy(restored);
  state_destroy(original);
  serialized_buffer_destroy(buf);
}

TEST(OTSerialization, StateWithDocumentRoundTrip) {
  state_t* original = state_create();
  original->version = 200;

  data_item_t* item = crabs_register_ot_type(original, "doc1",
    DATA_TYPE_OT_DOCUMENT, nullptr);
  ASSERT_NE(item, nullptr);

  // Add a text span
  crabs_ot_document_t* doc = (crabs_ot_document_t*)item->value;
  crabs_ot_op_id_t id;
  crabs_ot_op_id_init(&id, "n1", 1, 100);
  crabs_ot_document_insert_text(doc, 0, (const uint8_t*)"hello", 5, &id);

  serialized_buffer_t* buf = crabs_serialize_state(original);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  data_item_t* r_item = state_find_item(restored, "doc1");
  ASSERT_NE(r_item, nullptr);
  EXPECT_EQ(r_item->type, DATA_TYPE_OT_DOCUMENT);

  crabs_ot_document_t* r_doc = (crabs_ot_document_t*)r_item->value;
  EXPECT_EQ(r_doc->span_count, 1u);
  EXPECT_EQ(r_doc->visible_char_count, 5u);

  state_destroy(restored);
  state_destroy(original);
  serialized_buffer_destroy(buf);
}

TEST(OTSerialization, StateWithTreeRoundTrip) {
  state_t* original = state_create();
  original->version = 300;

  data_item_t* item = crabs_register_ot_type(original, "tree1",
    DATA_TYPE_OT_TREE, nullptr);
  ASSERT_NE(item, nullptr);

  // Add root and child nodes
  crabs_ot_tree_t* tree = (crabs_ot_tree_t*)item->value;
  crabs_ot_tree_insert_node(tree, nullptr, 0, "root", nullptr, 0);
  crabs_ot_tree_insert_node(tree, "root", 0, "child1", nullptr, 0);

  serialized_buffer_t* buf = crabs_serialize_state(original);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  data_item_t* r_item = state_find_item(restored, "tree1");
  ASSERT_NE(r_item, nullptr);
  EXPECT_EQ(r_item->type, DATA_TYPE_OT_TREE);

  crabs_ot_tree_t* r_tree = (crabs_ot_tree_t*)r_item->value;
  EXPECT_EQ(crabs_ot_tree_node_count(r_tree), 2u);

  state_destroy(restored);
  state_destroy(original);
  serialized_buffer_destroy(buf);
}

// ============================================================
// Backward Compatibility Test
// ============================================================

TEST(OTSerialization, BackwardCompatibilityV3) {
  // v3 serialized data (without OT fields) should still deserialize correctly
  state_t* original = state_create();
  original->version = 42;

  // Create a simple counter item (non-OT type)
  data_item_t* item = data_item_create("counter1", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  int64_t* val = (int64_t*)malloc(sizeof(int64_t));
  *val = 12345;
  item->value = val;
  state_add_item(original, item);

  serialized_buffer_t* buf = crabs_serialize_state(original);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->version, 42u);
  data_item_t* r_item = state_find_item(restored, "counter1");
  ASSERT_NE(r_item, nullptr);
  EXPECT_EQ(r_item->type, DATA_TYPE_COUNTER);
  EXPECT_NE(r_item->value, nullptr);
  EXPECT_EQ(*(int64_t*)r_item->value, 12345);

  state_destroy(restored);
  state_destroy(original);
  serialized_buffer_destroy(buf);
}

// ============================================================
// Null/Error Handling Tests
// ============================================================

TEST(OTSerialization, OtDataNullInput) {
  EXPECT_EQ(crabs_serialize_ot_data(nullptr), nullptr);
  EXPECT_EQ(crabs_deserialize_ot_data(nullptr, 0, DATA_TYPE_OT_ORDERED_SET), nullptr);
  EXPECT_EQ(crabs_deserialize_ot_data(nullptr, 100, DATA_TYPE_OT_ORDERED_SET), nullptr);
}

TEST(OTSerialization, OtDataEmptyItem) {
  crabs_ot_data_item_t* item = crabs_ot_data_item_create(DATA_TYPE_OT_ORDERED_SET);
  ASSERT_NE(item, nullptr);
  crabs_transform_matrix_init(item);

  serialized_buffer_t* buf = crabs_serialize_ot_data(item);
  ASSERT_NE(buf, nullptr);

  crabs_ot_data_item_t* restored = crabs_deserialize_ot_data(buf->data, buf->len, DATA_TYPE_OT_ORDERED_SET);
  ASSERT_NE(restored, nullptr);
  EXPECT_EQ(restored->op_log_count, 0u);
  EXPECT_EQ(restored->priority_counter_count, 0u);

  crabs_ot_data_item_destroy(restored);
  crabs_ot_data_item_destroy(item);
  serialized_buffer_destroy(buf);
}