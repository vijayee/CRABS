//
// Created by victor on 5/1/25.
//
// Tests for OT Execution Integration (v1.5 §8)
//

#include <gtest/gtest.h>
#include <cstdlib>
#include <vector>
extern "C" {
#include "../src/OT/ot_execution.h"
#include "../src/OT/ot_ordered_set.h"
#include "../src/OT/ot_tree.h"
#include "../src/OT/ot_document.h"
#include "../src/OT/ot_types.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Util/allocator.h"
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
// Execute Idempotency Tests
// ============================================================

// Build a wire-format payload carrying a single INSERT_TEXT op, matching the
// layout parsed by crabs_extract_ot_ops.
static uint32_t build_insert_text_payload(uint8_t* buffer,
                                          uint32_t buffer_capacity,
                                          const char* node_id,
                                          uint64_t sequence_num,
                                          uint64_t timestamp,
                                          uint64_t insert_pos,
                                          const uint8_t* text,
                                          uint32_t text_size) {
  uint32_t offset = 0;
  const uint32_t op_count = 1;
  const uint32_t op_type = (uint32_t)CRABS_OT_OP_INSERT_TEXT;
  const uint32_t dep_count = 0;

  auto write_u32 = [&](uint32_t value) {
    buffer[offset++] = (uint8_t)(value & 0xFF);
    buffer[offset++] = (uint8_t)((value >> 8) & 0xFF);
    buffer[offset++] = (uint8_t)((value >> 16) & 0xFF);
    buffer[offset++] = (uint8_t)((value >> 24) & 0xFF);
  };
  auto write_u64 = [&](uint64_t value) {
    for (uint32_t byte_index = 0; byte_index < 8; byte_index++) {
      buffer[offset++] = (uint8_t)((value >> (8 * byte_index)) & 0xFF);
    }
  };

  uint32_t needed = 4 + 4 + CRABS_MAX_USER_ID + 8 * 5 + 4 + text_size + 4;
  if (buffer_capacity < needed) return 0;

  write_u32(op_count);
  write_u32(op_type);
  memset(buffer + offset, 0, CRABS_MAX_USER_ID);
  strncpy((char*)(buffer + offset), node_id, CRABS_MAX_USER_ID - 1);
  offset += CRABS_MAX_USER_ID;
  write_u64(sequence_num);
  write_u64(timestamp);
  write_u64(insert_pos);   // visible_pos
  write_u64(0);            // visible_pos_2
  write_u64(0);            // priority
  write_u32(text_size);    // payload_size
  memcpy(buffer + offset, text, text_size);
  offset += text_size;
  write_u32(dep_count);
  return offset;
}

// Audit finding (conf 8): replaying the same OT op batch applied every op a
// second time — the executor never checked whether op.id already existed in
// the item's op log, so a duplicated INSERT_TEXT message duplicated the text.
TEST(OTExecution, ReplayedOperationIsIdempotent) {
  state_t* state = state_create();
  data_item_t* item = crabs_register_ot_type(state, "doc",
    DATA_TYPE_OT_DOCUMENT, nullptr);
  ASSERT_NE(item, nullptr);

  const uint8_t text[] = {'A', 'B'};
  uint8_t wire[512];
  uint32_t wire_size = build_insert_text_payload(
    wire, sizeof(wire), "n1", 1, 100, 0, text, sizeof(text));
  ASSERT_GT(wire_size, 0u);

  operation_t op;
  memset(&op, 0, sizeof(op));
  strncpy(op.type, CRABS_OP_EXECUTE_OT, CRABS_MAX_OP_NAME - 1);
  op.payload = wire;
  op.payload_size = wire_size;
  op.resources = (char(*)[CRABS_MAX_USER_ID])get_clear_memory(CRABS_MAX_USER_ID);
  ASSERT_NE(op.resources, nullptr);
  strncpy(op.resources[0], "doc", CRABS_MAX_USER_ID - 1);
  op.resource_count = 1;

  crabs_error_e err = crabs_execute_ot_operation(state, &op);
  EXPECT_EQ(err, CRABS_SUCCESS);

  crabs_ot_document_t* doc = (crabs_ot_document_t*)item->value;
  ASSERT_NE(doc, nullptr);
  EXPECT_EQ(crabs_ot_document_char_count(doc), 2u);
  EXPECT_EQ(crabs_ot_document_span_count(doc), 1u);
  ASSERT_NE(item->ot_data, nullptr);
  crabs_ot_data_item_t* ot_data = (crabs_ot_data_item_t*)item->ot_data;
  EXPECT_EQ(ot_data->op_log_count, 1u);

  // Replay the exact same op bytes.
  err = crabs_execute_ot_operation(state, &op);
  EXPECT_EQ(err, CRABS_SUCCESS);

  // Document text unchanged (no duplicate span), op log unchanged.
  EXPECT_EQ(crabs_ot_document_char_count(doc), 2u);
  EXPECT_EQ(crabs_ot_document_span_count(doc), 1u);
  EXPECT_EQ(ot_data->op_log_count, 1u);

  free(op.resources);
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
// Regression for audit C-8: the document op-type constants were #defined in
// ot_document.h with different values than the enum in ot_types.h, so an op
// built with the enum value for INSERT_TEXT (0x11) was dispatched as
// DELETE_RANGE (macro 0x11) and deleted text instead of inserting. After the
// fix, INSERT_TEXT inserts.
TEST(OTExecution, ApplyDocumentInsertTextDispatchMatchesEnum) {
  state_t* state = state_create();
  data_item_t* item = crabs_register_ot_type(state, "doc",
    DATA_TYPE_OT_DOCUMENT, nullptr);
  ASSERT_NE(item, nullptr);

  crabs_ot_operation_t op;
  crabs_ot_operation_init(&op);
  op.op_type = CRABS_OT_OP_INSERT_TEXT; // enum value 0x11
  op.visible_pos = 0;
  crabs_ot_op_id_init(&op.id, "n1", 1, 100);
  uint8_t text[] = {'A', 'B'};
  crabs_ot_operation_set_payload(&op, text, 2);

  crabs_error_e err = crabs_apply_ot_op(item, &op);
  EXPECT_EQ(err, CRABS_SUCCESS);

  crabs_ot_document_t* doc = (crabs_ot_document_t*)item->value;
  ASSERT_NE(doc, nullptr);
  // Before the fix this would have been 0 (dispatched as DELETE_RANGE).
  EXPECT_EQ(crabs_ot_document_char_count(doc), 2u);

  if (op.payload) { free(op.payload); op.payload = nullptr; }
  state_destroy(state);
}

// ============================================================
// OT Op Wire Encoding Tests (A8: ordered set from JS)
// ============================================================

TEST(OTExecution, OtOpsToWireRoundTrip) {
  // One INSERT with a payload and two deps: encode with
  // crabs_ot_ops_to_wire, decode with crabs_extract_ot_ops, compare fields.
  crabs_ot_operation_t op;
  crabs_ot_operation_init(&op);
  op.op_type = CRABS_OT_OP_INSERT;
  op.visible_pos = 3;
  op.visible_pos_2 = 0;
  op.priority = 7;
  crabs_ot_op_id_init(&op.id, "n1", 4, 1000);
  const uint8_t element = 0x42;
  ASSERT_TRUE(crabs_ot_operation_set_payload(&op, &element, 1));
  crabs_ot_op_id_t dep1 = make_id("peer", 1, 50);
  crabs_ot_op_id_t dep2 = make_id("peer", 2, 51);
  ASSERT_TRUE(crabs_ot_operation_add_dep(&op, &dep1));
  ASSERT_TRUE(crabs_ot_operation_add_dep(&op, &dep2));

  std::vector<uint8_t> wire(4 + 4 + CRABS_MAX_USER_ID + 8 * 5 + 4 + 1 + 4 +
                             2 * (CRABS_MAX_USER_ID + 8 + 8));
  uint32_t wire_size = crabs_ot_ops_to_wire(&op, 1, wire.data(),
                                            (uint32_t)wire.size());
  ASSERT_GT(wire_size, 0u);
  ASSERT_LE(wire_size, (uint32_t)wire.size());

  crabs_ot_operation_t* decoded = nullptr;
  uint32_t decoded_count = crabs_extract_ot_ops(wire.data(), wire_size,
                                                &decoded);
  ASSERT_EQ(decoded_count, 1u);
  ASSERT_NE(decoded, nullptr);
  EXPECT_EQ(decoded[0].op_type, CRABS_OT_OP_INSERT);
  EXPECT_TRUE(crabs_ot_op_id_equal(&decoded[0].id, &op.id));
  EXPECT_EQ(decoded[0].visible_pos, 3u);
  EXPECT_EQ(decoded[0].visible_pos_2, 0u);
  EXPECT_EQ(decoded[0].priority, 7u);
  ASSERT_NE(decoded[0].payload, nullptr);
  EXPECT_EQ(decoded[0].payload_size, 1u);
  EXPECT_EQ(decoded[0].payload[0], 0x42);
  EXPECT_EQ(decoded[0].dep_count, 2u);
  EXPECT_TRUE(crabs_ot_op_id_equal(&decoded[0].deps[0], &dep1));
  EXPECT_TRUE(crabs_ot_op_id_equal(&decoded[0].deps[1], &dep2));

  crabs_ot_ops_free(decoded, decoded_count);
  free(op.payload);
}

TEST(OTExecution, OtOpsToWireRejects) {
  crabs_ot_operation_t op;
  crabs_ot_operation_init(&op);
  op.op_type = CRABS_OT_OP_INSERT;
  crabs_ot_op_id_init(&op.id, "n1", 1, 100);

  uint8_t tiny[3];
  EXPECT_EQ(crabs_ot_ops_to_wire(&op, 1, tiny, sizeof(tiny)), 0u);
  EXPECT_EQ(crabs_ot_ops_to_wire(nullptr, 1, tiny, sizeof(tiny)), 0u);
  static uint8_t small[256];
  EXPECT_EQ(crabs_ot_ops_to_wire(&op, 0, small, sizeof(small)), 0u);
  // An op with a payload larger than CRABS_OT_MAX_PAYLOAD must never be
  // emitted — the extractor would silently mis-align on those bytes.
  uint8_t oversized[] = {0x01, 0x02};
  op.payload = oversized;
  op.payload_size = CRABS_OT_MAX_PAYLOAD + 1;
  EXPECT_EQ(crabs_ot_ops_to_wire(&op, 1, small, sizeof(small)), 0u);
  op.payload = nullptr;
  op.payload_size = 0;
}

TEST(OTExecution, ExecuteOtOrderedSetThroughExecutor) {
  // The bindings route ordered-set ops through a CRABS_OP_EXECUTE_OT op
  // whose payload crabs_ot_ops_to_wire built: register an ordered set,
  // execute three INSERT ops through crabs_execute_ot_operation, then a
  // MOVE — the materialized order must read [b, c, a] from item->value.
  state_t* state = state_create();
  data_item_t* item = crabs_register_ot_type(state, "list",
    DATA_TYPE_OT_ORDERED_SET, nullptr);
  ASSERT_NE(item, nullptr);

  struct execute_step {
    crabs_ot_op_type_e op_type;
    uint64_t position;
    uint64_t position_2;
    const char* author;
    uint64_t sequence;
    uint8_t element;
  };
  const execute_step steps[] = {
    { CRABS_OT_OP_INSERT, 0, 0, "n1", 1, 'a' },
    { CRABS_OT_OP_INSERT, 1, 0, "n1", 2, 'b' },
    { CRABS_OT_OP_INSERT, 2, 0, "n1", 3, 'c' },
    { CRABS_OT_OP_MOVE,   0, 2, "n1", 4, 0   },
  };
  for (const execute_step& step : steps) {
    crabs_ot_operation_t ot_op;
    crabs_ot_operation_init(&ot_op);
    ot_op.op_type = step.op_type;
    ot_op.visible_pos = step.position;
    ot_op.visible_pos_2 = step.position_2;
    crabs_ot_op_id_init(&ot_op.id, step.author, step.sequence, 1000);
    if (step.op_type == CRABS_OT_OP_INSERT) {
      ASSERT_TRUE(crabs_ot_operation_set_payload(&ot_op, &step.element, 1));
    }

    uint8_t wire[256];
    uint32_t wire_size = crabs_ot_ops_to_wire(&ot_op, 1, wire, sizeof(wire));
    ASSERT_GT(wire_size, 0u);

    operation_t op;
    memset(&op, 0, sizeof(op));
    strncpy(op.type, CRABS_OP_EXECUTE_OT, CRABS_MAX_OP_NAME - 1);
    op.payload = wire;
    op.payload_size = wire_size;
    op.resources = (char(*)[CRABS_MAX_USER_ID])get_clear_memory(
      CRABS_MAX_USER_ID);
    ASSERT_NE(op.resources, nullptr);
    strncpy(op.resources[0], "list", CRABS_MAX_USER_ID - 1);
    op.resource_count = 1;

    EXPECT_EQ(crabs_execute_ot_operation(state, &op), CRABS_SUCCESS);
    free(op.resources);
    free(ot_op.payload);
  }

  crabs_ot_ordered_set_t* set = (crabs_ot_ordered_set_t*)item->value;
  ASSERT_NE(set, nullptr);
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 3u);
  const char* order = "bca";
  for (uint32_t position = 0; position < 3; position++) {
    crabs_ordered_element_t* element = crabs_ot_ordered_set_get(set, position);
    ASSERT_NE(element, nullptr);
    ASSERT_NE(element->value, nullptr);
    // The MOVE re-stamps placement; the materialized order is the moved one.
    EXPECT_EQ((char)element->value[0], order[position]) << "position "
      << position;
  }
  ASSERT_NE(item->ot_data, nullptr);
  crabs_ot_data_item_t* ot_data = (crabs_ot_data_item_t*)item->ot_data;
  EXPECT_EQ(ot_data->op_log_count, 4u);
  state_destroy(state);
}

// ============================================================
// Causal Admission Tests (audit pass-3 M)
// ============================================================

// Encode one OT op to wire format and run it through the executor against a
// single resource. Mirrors the bindings' delivery path.
static crabs_error_e execute_one_ot_op(state_t* state, const char* resource,
                                       crabs_ot_operation_t* ot_op) {
  uint8_t wire[512];
  uint32_t wire_size = crabs_ot_ops_to_wire(ot_op, 1, wire, sizeof(wire));
  EXPECT_GT(wire_size, 0u);
  if (wire_size == 0u) return CRABS_ERR_INTERNAL;

  operation_t op;
  memset(&op, 0, sizeof(op));
  strncpy(op.type, CRABS_OP_EXECUTE_OT, CRABS_MAX_OP_NAME - 1);
  op.payload = wire;
  op.payload_size = wire_size;
  op.resources = (char(*)[CRABS_MAX_USER_ID])get_clear_memory(
    CRABS_MAX_USER_ID);
  if (op.resources == nullptr) return CRABS_ERR_INTERNAL;
  strncpy(op.resources[0], resource, CRABS_MAX_USER_ID - 1);
  op.resource_count = 1;

  crabs_error_e err = crabs_execute_ot_operation(state, &op);
  free(op.resources);
  return err;
}

// An op whose declared causal dependency is absent from the item's op log
// must be deferred, NOT transformed against partial history and applied —
// replicas holding different partial logs would transform it differently and
// diverge permanently.
TEST(OTExecution, OpWithMissingDependencyIsDeferredNotApplied) {
  state_t* state = state_create();
  data_item_t* item = crabs_register_ot_type(state, "list",
    DATA_TYPE_OT_ORDERED_SET, nullptr);
  ASSERT_NE(item, nullptr);
  crabs_ot_data_item_t* ot_data = (crabs_ot_data_item_t*)item->ot_data;
  ASSERT_NE(ot_data, nullptr);
  crabs_ot_ordered_set_t* set = (crabs_ot_ordered_set_t*)item->value;
  ASSERT_NE(set, nullptr);

  // A dependent op: INSERT 'b' authored by n2, causally after n1's seq-1 op,
  // which has NOT arrived at this replica.
  crabs_ot_operation_t dependent;
  crabs_ot_operation_init(&dependent);
  dependent.op_type = CRABS_OT_OP_INSERT;
  dependent.visible_pos = 0;
  crabs_ot_op_id_init(&dependent.id, "n2", 1, 2000);
  crabs_ot_op_id_t missing_dep = make_id("n1", 1, 1000);
  ASSERT_TRUE(crabs_ot_operation_add_dep(&dependent, &missing_dep));
  const uint8_t element_b = 'b';
  ASSERT_TRUE(crabs_ot_operation_set_payload(&dependent, &element_b, 1));

  // Deferral is a normal outcome, not an error, while the cause is in flight.
  EXPECT_EQ(execute_one_ot_op(state, "list", &dependent), CRABS_SUCCESS);

  // Not applied (element invisible), not logged (no transform history for it).
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 0u);
  EXPECT_EQ(ot_data->op_log_count, 0u);

  // The missing cause arrives. Applying it must flush the parked dependent op.
  crabs_ot_operation_t cause;
  crabs_ot_operation_init(&cause);
  cause.op_type = CRABS_OT_OP_INSERT;
  cause.visible_pos = 0;
  crabs_ot_op_id_init(&cause.id, "n1", 1, 1000);
  const uint8_t element_a = 'a';
  ASSERT_TRUE(crabs_ot_operation_set_payload(&cause, &element_a, 1));

  EXPECT_EQ(execute_one_ot_op(state, "list", &cause), CRABS_SUCCESS);

  // Both ops are now visible and logged: the cause applied directly, the
  // dependent op applied via the flush pass against complete history.
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 2u);
  EXPECT_EQ(ot_data->op_log_count, 2u);

  free(dependent.payload);
  free(cause.payload);
  state_destroy(state);
}

// An op whose dependency never arrives stays parked; re-delivering the same
// op must not queue duplicates, and destroying the state must free the parked
// payload (the sanitizer build catches a leak here).
TEST(OTExecution, OpWithPermanentlyMissingDepStaysParkedWithoutDuplicates) {
  state_t* state = state_create();
  data_item_t* item = crabs_register_ot_type(state, "list",
    DATA_TYPE_OT_ORDERED_SET, nullptr);
  ASSERT_NE(item, nullptr);
  crabs_ot_data_item_t* ot_data = (crabs_ot_data_item_t*)item->ot_data;
  ASSERT_NE(ot_data, nullptr);
  crabs_ot_ordered_set_t* set = (crabs_ot_ordered_set_t*)item->value;
  ASSERT_NE(set, nullptr);

  crabs_ot_operation_t stranded;
  crabs_ot_operation_init(&stranded);
  stranded.op_type = CRABS_OT_OP_INSERT;
  stranded.visible_pos = 0;
  crabs_ot_op_id_init(&stranded.id, "n2", 5, 3000);
  crabs_ot_op_id_t never_arrives = make_id("ghost", 9, 9999);
  ASSERT_TRUE(crabs_ot_operation_add_dep(&stranded, &never_arrives));
  const uint8_t element = 'z';
  ASSERT_TRUE(crabs_ot_operation_set_payload(&stranded, &element, 1));

  // Deliver the same op repeatedly (state-sync re-delivery). Each delivery is
  // a success but the op never applies and is parked at most once.
  for (uint32_t delivery = 0; delivery < 3; delivery++) {
    EXPECT_EQ(execute_one_ot_op(state, "list", &stranded), CRABS_SUCCESS);
    EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 0u);
    EXPECT_EQ(ot_data->op_log_count, 0u);
  }

  free(stranded.payload);
  state_destroy(state);
}

// A parked op can be the cause of another parked op: op B depends on op A,
// and A depends on op C. While C is missing both A and B park. When C lands,
// the flush loop applies A (round against the refreshed log) and then B —
// the pending set drains completely instead of only one hop per delivery.
TEST(OTExecution, ChainedParkedOpsFlushInOrder) {
  state_t* state = state_create();
  data_item_t* item = crabs_register_ot_type(state, "list",
    DATA_TYPE_OT_ORDERED_SET, nullptr);
  ASSERT_NE(item, nullptr);
  crabs_ot_data_item_t* ot_data = (crabs_ot_data_item_t*)item->ot_data;
  ASSERT_NE(ot_data, nullptr);
  crabs_ot_ordered_set_t* set = (crabs_ot_ordered_set_t*)item->value;
  ASSERT_NE(set, nullptr);

  // Op A: depends on the (not-yet-arrived) cause C (n1 seq 1).
  crabs_ot_operation_t op_a;
  crabs_ot_operation_init(&op_a);
  op_a.op_type = CRABS_OT_OP_INSERT;
  op_a.visible_pos = 0;
  crabs_ot_op_id_init(&op_a.id, "n2", 1, 2000);
  crabs_ot_op_id_t cause_id = make_id("n1", 1, 1000);
  ASSERT_TRUE(crabs_ot_operation_add_dep(&op_a, &cause_id));
  const uint8_t element_a = 'a';
  ASSERT_TRUE(crabs_ot_operation_set_payload(&op_a, &element_a, 1));

  // Op B: depends on op A (n2 seq 1) — also not yet in the log.
  crabs_ot_operation_t op_b;
  crabs_ot_operation_init(&op_b);
  op_b.op_type = CRABS_OT_OP_INSERT;
  op_b.visible_pos = 0;
  crabs_ot_op_id_init(&op_b.id, "n2", 2, 3000);
  crabs_ot_op_id_t op_a_id = make_id("n2", 1, 2000);
  ASSERT_TRUE(crabs_ot_operation_add_dep(&op_b, &op_a_id));
  const uint8_t element_b = 'b';
  ASSERT_TRUE(crabs_ot_operation_set_payload(&op_b, &element_b, 1));

  // B arrives first and parks on A; A arrives and parks on C.
  EXPECT_EQ(execute_one_ot_op(state, "list", &op_b), CRABS_SUCCESS);
  EXPECT_EQ(execute_one_ot_op(state, "list", &op_a), CRABS_SUCCESS);
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 0u);
  EXPECT_EQ(ot_data->op_log_count, 0u);
  EXPECT_EQ(ot_data->pending_count, 2u);

  // C lands: applies directly; the flush pass applies A and then B.
  crabs_ot_operation_t cause;
  crabs_ot_operation_init(&cause);
  cause.op_type = CRABS_OT_OP_INSERT;
  cause.visible_pos = 0;
  crabs_ot_op_id_init(&cause.id, "n1", 1, 1000);
  const uint8_t element_c = 'c';
  ASSERT_TRUE(crabs_ot_operation_set_payload(&cause, &element_c, 1));

  EXPECT_EQ(execute_one_ot_op(state, "list", &cause), CRABS_SUCCESS);

  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 3u);
  EXPECT_EQ(ot_data->op_log_count, 3u);
  EXPECT_EQ(ot_data->pending_count, 0u);

  free(op_a.payload);
  free(op_b.payload);
  free(cause.payload);
  state_destroy(state);
}

// The pending-set cap (CRABS_OT_MAX_PENDING_OPS) bounds a Byzantine peer's
// forever-pending garbage: the 513th distinct dep-blocked op must be refused
// with an error rather than parked.
TEST(OTExecution, PendingSetCapRejectsOverflow) {
  state_t* state = state_create();
  data_item_t* item = crabs_register_ot_type(state, "list",
    DATA_TYPE_OT_ORDERED_SET, nullptr);
  ASSERT_NE(item, nullptr);
  crabs_ot_data_item_t* ot_data = (crabs_ot_data_item_t*)item->ot_data;
  ASSERT_NE(ot_data, nullptr);

  crabs_ot_op_id_t ghost_dep = make_id("ghost", 1, 9999);
  const uint8_t element = 'x';

  // Park the cap's worth of distinct dep-blocked ops — every deferral is a
  // normal success while the cause is nominally in flight.
  for (uint32_t sequence = 1; sequence <= CRABS_OT_MAX_PENDING_OPS;
       sequence++) {
    crabs_ot_operation_t parked_op;
    crabs_ot_operation_init(&parked_op);
    parked_op.op_type = CRABS_OT_OP_INSERT;
    parked_op.visible_pos = 0;
    crabs_ot_op_id_init(&parked_op.id, "n2", sequence, 1000);
    ASSERT_TRUE(crabs_ot_operation_add_dep(&parked_op, &ghost_dep));
    ASSERT_TRUE(crabs_ot_operation_set_payload(&parked_op, &element, 1));
    EXPECT_EQ(execute_one_ot_op(state, "list", &parked_op), CRABS_SUCCESS)
      << "sequence " << sequence;
    free(parked_op.payload);
  }
  EXPECT_EQ(ot_data->pending_count, (uint32_t)CRABS_OT_MAX_PENDING_OPS);

  // The next distinct deferral overflows the cap: the executor fails closed.
  crabs_ot_operation_t overflow_op;
  crabs_ot_operation_init(&overflow_op);
  overflow_op.op_type = CRABS_OT_OP_INSERT;
  overflow_op.visible_pos = 0;
  crabs_ot_op_id_init(&overflow_op.id, "n2", CRABS_OT_MAX_PENDING_OPS + 1,
                      1000);
  ASSERT_TRUE(crabs_ot_operation_add_dep(&overflow_op, &ghost_dep));
  ASSERT_TRUE(crabs_ot_operation_set_payload(&overflow_op, &element, 1));
  EXPECT_EQ(execute_one_ot_op(state, "list", &overflow_op),
            CRABS_ERR_INTERNAL);
  EXPECT_EQ(ot_data->pending_count, (uint32_t)CRABS_OT_MAX_PENDING_OPS);

  free(overflow_op.payload);
  state_destroy(state);
}

// ============================================================
// Position Cap Determinism Tests (audit pass-3 M)
// ============================================================

// The 100000-position cap must gate the WIRE-CARRIED position, before the op
// is transformed against the local log. A post-transform check makes the
// accept/reject verdict depend on the replica's own log length (a longer log
// can push the same op over the cap) — replicas diverge. An op arriving at
// 200000 is over the wire cap regardless of what the local log holds.
TEST(OTExecution, PositionCapRejectsWirePositionRegardlessOfLog) {
  // Case 1: empty log.
  state_t* state_short = state_create();
  data_item_t* item_short = crabs_register_ot_type(state_short, "list",
    DATA_TYPE_OT_ORDERED_SET, nullptr);
  ASSERT_NE(item_short, nullptr);

  crabs_ot_operation_t over_cap;
  crabs_ot_operation_init(&over_cap);
  over_cap.op_type = CRABS_OT_OP_INSERT;
  over_cap.visible_pos = 200000;
  crabs_ot_op_id_init(&over_cap.id, "n2", 1, 2000);
  const uint8_t element_x = 'x';
  ASSERT_TRUE(crabs_ot_operation_set_payload(&over_cap, &element_x, 1));

  EXPECT_EQ(execute_one_ot_op(state_short, "list", &over_cap),
            CRABS_ERR_OT_POSITION_BOUNDS);
  free(over_cap.payload);
  state_destroy(state_short);

  // Case 2: a longer log of lower inserts. The verdict must be identical —
  // content-determined, not log-determined.
  state_t* state_long = state_create();
  data_item_t* item_long = crabs_register_ot_type(state_long, "list",
    DATA_TYPE_OT_ORDERED_SET, nullptr);
  ASSERT_NE(item_long, nullptr);

  for (uint64_t sequence = 1; sequence <= 2; sequence++) {
    crabs_ot_operation_t filler;
    crabs_ot_operation_init(&filler);
    filler.op_type = CRABS_OT_OP_INSERT;
    filler.visible_pos = 0;
    crabs_ot_op_id_init(&filler.id, "n1", sequence, 1000);
    const uint8_t element_f = 'a' + (uint8_t)(sequence - 1);
    ASSERT_TRUE(crabs_ot_operation_set_payload(&filler, &element_f, 1));
    ASSERT_EQ(execute_one_ot_op(state_long, "list", &filler), CRABS_SUCCESS);
    free(filler.payload);
  }

  crabs_ot_operation_t over_cap_long;
  crabs_ot_operation_init(&over_cap_long);
  over_cap_long.op_type = CRABS_OT_OP_INSERT;
  over_cap_long.visible_pos = 200000;
  crabs_ot_op_id_init(&over_cap_long.id, "n2", 1, 2000);
  ASSERT_TRUE(crabs_ot_operation_set_payload(&over_cap_long, &element_x, 1));

  EXPECT_EQ(execute_one_ot_op(state_long, "list", &over_cap_long),
            CRABS_ERR_OT_POSITION_BOUNDS);
  free(over_cap_long.payload);
  state_destroy(state_long);
}

// The complement: a large-but-legitimate wire position (99999) must be ADMITTED
// by the cap pre-gate even when the local log would transform it beyond the cap
// (two logged inserts below it shift it to 100001 during transform). The
// transformed position is guarded by the apply path's own content-derived
// bounds (the ordered-set insert clamps to content), so the op applies and the
// verdict is the same with an empty log and with the shifting log — no
// CRABS_ERR_OT_POSITION_BOUNDS in either case.
TEST(OTExecution, PositionCapAdmitsOpBelowCapRegardlessOfLogShift) {
  // Case 1: empty log — no transform, wire position stands.
  state_t* state_short = state_create();
  data_item_t* item_short = crabs_register_ot_type(state_short, "list",
    DATA_TYPE_OT_ORDERED_SET, nullptr);
  ASSERT_NE(item_short, nullptr);
  crabs_ot_ordered_set_t* set_short = (crabs_ot_ordered_set_t*)item_short->value;
  ASSERT_NE(set_short, nullptr);

  crabs_ot_operation_t below_cap;
  crabs_ot_operation_init(&below_cap);
  below_cap.op_type = CRABS_OT_OP_INSERT;
  below_cap.visible_pos = 99999;
  crabs_ot_op_id_init(&below_cap.id, "n2", 1, 2000);
  const uint8_t element_x = 'x';
  ASSERT_TRUE(crabs_ot_operation_set_payload(&below_cap, &element_x, 1));

  crabs_error_e err_short = execute_one_ot_op(state_short, "list", &below_cap);
  EXPECT_NE(err_short, CRABS_ERR_OT_POSITION_BOUNDS);
  EXPECT_EQ(err_short, CRABS_SUCCESS);
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set_short), 1u);
  free(below_cap.payload);
  state_destroy(state_short);

  // Case 2: a 2-insert log whose transform would push the same op to
  // 100001 (> cap). Pre-gate admits on the wire position; apply clamps.
  state_t* state_long = state_create();
  data_item_t* item_long = crabs_register_ot_type(state_long, "list",
    DATA_TYPE_OT_ORDERED_SET, nullptr);
  ASSERT_NE(item_long, nullptr);
  crabs_ot_ordered_set_t* set_long = (crabs_ot_ordered_set_t*)item_long->value;
  ASSERT_NE(set_long, nullptr);

  for (uint64_t sequence = 1; sequence <= 2; sequence++) {
    crabs_ot_operation_t filler;
    crabs_ot_operation_init(&filler);
    filler.op_type = CRABS_OT_OP_INSERT;
    filler.visible_pos = 0;
    crabs_ot_op_id_init(&filler.id, "n1", sequence, 1000);
    const uint8_t element_f = 'a' + (uint8_t)(sequence - 1);
    ASSERT_TRUE(crabs_ot_operation_set_payload(&filler, &element_f, 1));
    ASSERT_EQ(execute_one_ot_op(state_long, "list", &filler), CRABS_SUCCESS);
    free(filler.payload);
  }

  crabs_ot_operation_t below_cap_long;
  crabs_ot_operation_init(&below_cap_long);
  below_cap_long.op_type = CRABS_OT_OP_INSERT;
  below_cap_long.visible_pos = 99999;
  crabs_ot_op_id_init(&below_cap_long.id, "n2", 1, 2000);
  ASSERT_TRUE(crabs_ot_operation_set_payload(&below_cap_long, &element_x, 1));

  crabs_error_e err_long = execute_one_ot_op(state_long, "list",
                                             &below_cap_long);
  EXPECT_NE(err_long, CRABS_ERR_OT_POSITION_BOUNDS);
  EXPECT_EQ(err_long, CRABS_SUCCESS);
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set_long), 3u);
  free(below_cap_long.payload);
  state_destroy(state_long);
}

// visible_pos == CRABS_OT_MAX_VISIBLE_POSITION on an empty item is at the cap
// boundary: admitted by the pre-gate, and the apply clamps the position to the
// tail of the (empty) ordered set. The op must apply successfully.
TEST(OTExecution, PositionCapBoundaryExactlyMaxAdmitted) {
  state_t* state = state_create();
  data_item_t* item = crabs_register_ot_type(state, "list",
    DATA_TYPE_OT_ORDERED_SET, nullptr);
  ASSERT_NE(item, nullptr);
  crabs_ot_ordered_set_t* set = (crabs_ot_ordered_set_t*)item->value;
  ASSERT_NE(set, nullptr);

  crabs_ot_operation_t at_cap;
  crabs_ot_operation_init(&at_cap);
  at_cap.op_type = CRABS_OT_OP_INSERT;
  at_cap.visible_pos = CRABS_OT_MAX_VISIBLE_POSITION;
  crabs_ot_op_id_init(&at_cap.id, "n2", 1, 2000);
  const uint8_t element_x = 'x';
  ASSERT_TRUE(crabs_ot_operation_set_payload(&at_cap, &element_x, 1));

  crabs_error_e err = execute_one_ot_op(state, "list", &at_cap);
  EXPECT_NE(err, CRABS_ERR_OT_POSITION_BOUNDS);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 1u);
  free(at_cap.payload);
  state_destroy(state);
}

// visible_pos == CRABS_OT_MAX_VISIBLE_POSITION + 1 is one past the cap:
// rejected with CRABS_ERR_OT_POSITION_BOUNDS before any transform or apply.
TEST(OTExecution, PositionCapBoundaryOneBeyondRejected) {
  state_t* state = state_create();
  data_item_t* item = crabs_register_ot_type(state, "list",
    DATA_TYPE_OT_ORDERED_SET, nullptr);
  ASSERT_NE(item, nullptr);
  crabs_ot_ordered_set_t* set = (crabs_ot_ordered_set_t*)item->value;
  ASSERT_NE(set, nullptr);

  crabs_ot_operation_t over_cap;
  crabs_ot_operation_init(&over_cap);
  over_cap.op_type = CRABS_OT_OP_INSERT;
  over_cap.visible_pos = CRABS_OT_MAX_VISIBLE_POSITION + 1;
  crabs_ot_op_id_init(&over_cap.id, "n2", 1, 2000);
  const uint8_t element_x = 'x';
  ASSERT_TRUE(crabs_ot_operation_set_payload(&over_cap, &element_x, 1));

  EXPECT_EQ(execute_one_ot_op(state, "list", &over_cap),
            CRABS_ERR_OT_POSITION_BOUNDS);
  EXPECT_EQ(crabs_ot_ordered_set_visible_count(set), 0u);
  free(over_cap.payload);
  state_destroy(state);
}
