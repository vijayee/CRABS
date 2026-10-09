//
// CRABS-47: CRDT Merge & Serialization Extended Tests
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/CRDT/crdt_merge.h"
#include "../src/Serialization/serialization.h"
}

// ============================================================
// G-Counter Extended Tests
// ============================================================

TEST(TestCRDTExtended, GCounterZeroDelta) {
  g_counter_t* c = g_counter_create();
  crabs_error_e err = g_counter_increment(c, "nodeA", 0);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(g_counter_value(c), 0);
  g_counter_destroy(c);
}

TEST(TestCRDTExtended, GCounterNegativeDelta) {
  g_counter_t* c = g_counter_create();
  // A G-Counter only grows; a negative delta is convergently lost on merge
  // (merge takes per-node max). Reject negative deltas — use a PN-Counter
  // for decrementing counters.
  crabs_error_e err = g_counter_increment(c, "nodeA", -5);
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(g_counter_value(c), 0);
  g_counter_destroy(c);
}

TEST(TestCRDTExtended, GCounterLargeValues) {
  g_counter_t* c = g_counter_create();
  g_counter_increment(c, "nodeA", 1000000000);
  EXPECT_EQ(g_counter_value(c), 1000000000);
  g_counter_destroy(c);
}

TEST(TestCRDTExtended, GCounterMergeIdempotent) {
  g_counter_t* a = g_counter_create();
  g_counter_increment(a, "nodeA", 5);
  g_counter_t* merged = g_counter_merge(a, a);
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(g_counter_value(merged), 5);
  g_counter_destroy(a);
  g_counter_destroy(merged);
}

TEST(TestCRDTExtended, GCounterMergeCommutative) {
  g_counter_t* a = g_counter_create();
  g_counter_t* b = g_counter_create();
  g_counter_increment(a, "nodeA", 3);
  g_counter_increment(b, "nodeB", 7);

  g_counter_t* ab = g_counter_merge(a, b);
  g_counter_t* ba = g_counter_merge(b, a);
  ASSERT_NE(ab, nullptr);
  ASSERT_NE(ba, nullptr);
  EXPECT_EQ(g_counter_value(ab), g_counter_value(ba));

  g_counter_destroy(a);
  g_counter_destroy(b);
  g_counter_destroy(ab);
  g_counter_destroy(ba);
}

// ============================================================
// PN-Counter Extended Tests
// ============================================================

TEST(TestCRDTExtended, PNCounterNegativeValue) {
  pn_counter_t* c = pn_counter_create();
  pn_counter_decrement(c, "nodeA", 10);
  EXPECT_EQ(pn_counter_value(c), -10);
  pn_counter_destroy(c);
}

TEST(TestCRDTExtended, PNCounterMergeCommutative) {
  pn_counter_t* a = pn_counter_create();
  pn_counter_t* b = pn_counter_create();
  pn_counter_increment(a, "nodeA", 10);
  pn_counter_decrement(a, "nodeA", 3);
  pn_counter_increment(b, "nodeB", 5);

  pn_counter_t* ab = pn_counter_merge(a, b);
  pn_counter_t* ba = pn_counter_merge(b, a);
  ASSERT_NE(ab, nullptr);
  ASSERT_NE(ba, nullptr);
  EXPECT_EQ(pn_counter_value(ab), pn_counter_value(ba));

  pn_counter_destroy(a);
  pn_counter_destroy(b);
  pn_counter_destroy(ab);
  pn_counter_destroy(ba);
}

// ============================================================
// OR-Set Extended Tests
// ============================================================

TEST(TestCRDTExtended, ORSetAddDuplicateElement) {
  or_set_t* set = or_set_create();
  or_set_add(set, "apple", "nodeA:1");
  or_set_add(set, "apple", "nodeA:2");
  EXPECT_TRUE(or_set_contains(set, "apple"));
  or_set_destroy(set);
}

TEST(TestCRDTExtended, ORSetRemoveNonExistent) {
  or_set_t* set = or_set_create();
  crabs_error_e err = or_set_remove(set, "nonexistent");
  EXPECT_EQ(err, CRABS_SUCCESS);
  or_set_destroy(set);
}

TEST(TestCRDTExtended, ORSetMergeCommutative) {
  or_set_t* a = or_set_create();
  or_set_t* b = or_set_create();
  or_set_add(a, "apple", "nodeA:1");
  or_set_add(b, "banana", "nodeB:1");

  or_set_t* ab = or_set_merge(a, b);
  or_set_t* ba = or_set_merge(b, a);
  ASSERT_NE(ab, nullptr);
  ASSERT_NE(ba, nullptr);
  EXPECT_TRUE(or_set_contains(ab, "apple"));
  EXPECT_TRUE(or_set_contains(ab, "banana"));
  EXPECT_TRUE(or_set_contains(ba, "apple"));
  EXPECT_TRUE(or_set_contains(ba, "banana"));

  or_set_destroy(a);
  or_set_destroy(b);
  or_set_destroy(ab);
  or_set_destroy(ba);
}

// ============================================================
// 2P-Set Extended Tests
// ============================================================

TEST(TestCRDTExtended, TwoPSetRemoveNonExistent) {
  two_p_set_t* set = two_p_set_create();
  crabs_error_e err = two_p_set_remove(set, "nonexistent");
  EXPECT_EQ(err, CRABS_SUCCESS);
  two_p_set_destroy(set);
}

TEST(TestCRDTExtended, TwoPSetMergeCommutative) {
  two_p_set_t* a = two_p_set_create();
  two_p_set_t* b = two_p_set_create();
  two_p_set_add(a, "apple");
  two_p_set_add(b, "banana");

  two_p_set_t* ab = two_p_set_merge(a, b);
  two_p_set_t* ba = two_p_set_merge(b, a);
  ASSERT_NE(ab, nullptr);
  ASSERT_NE(ba, nullptr);
  EXPECT_TRUE(two_p_set_contains(ab, "apple"));
  EXPECT_TRUE(two_p_set_contains(ab, "banana"));
  EXPECT_TRUE(two_p_set_contains(ba, "apple"));
  EXPECT_TRUE(two_p_set_contains(ba, "banana"));

  two_p_set_destroy(a);
  two_p_set_destroy(b);
  two_p_set_destroy(ab);
  two_p_set_destroy(ba);
}

// ============================================================
// LWW-Register Extended Tests
// ============================================================

TEST(TestCRDTExtended, LWWRegisterMergeSameTimestamp) {
  uint8_t data_a[] = {0x01};
  uint8_t data_b[] = {0x02};
  lww_register_t* a = lww_register_create(data_a, 1, 1000, "nodeA");
  lww_register_t* b = lww_register_create(data_b, 1, 1000, "nodeB");

  lww_register_t* merged = lww_register_merge(a, b);
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(merged->value[0], 0x02);
  lww_register_destroy(a);
  lww_register_destroy(b);
  lww_register_destroy(merged);
}

TEST(TestCRDTExtended, LWWRegisterMergeOlderWins) {
  uint8_t data_a[] = {0x01};
  uint8_t data_b[] = {0x02};
  lww_register_t* a = lww_register_create(data_a, 1, 2000, "nodeA");
  lww_register_t* b = lww_register_create(data_b, 1, 1000, "nodeB");

  lww_register_t* merged = lww_register_merge(a, b);
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(merged->timestamp, (uint64_t)2000);
  EXPECT_EQ(merged->value[0], 0x01);
  lww_register_destroy(a);
  lww_register_destroy(b);
  lww_register_destroy(merged);
}

// ============================================================
// State-Level Merge Extended Tests
// ============================================================

TEST(TestCRDTExtended, StateMergeWithDifferentItems) {
  state_t* dst = state_create();
  state_t* src = state_create();

  data_item_t* d1 = data_item_create("item_dst", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc1 = g_counter_create();
  g_counter_increment(gc1, "nodeA", 10);
  d1->value = gc1;
  state_add_item(dst, d1);

  data_item_t* s1 = data_item_create("item_src", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc2 = g_counter_create();
  g_counter_increment(gc2, "nodeB", 20);
  s1->value = gc2;
  state_add_item(src, s1);

  src->version = 5;

  crabs_error_e err = crdt_merge_state(dst, src);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(dst->version, (uint64_t)5);

  EXPECT_NE(state_find_item(dst, "item_dst"), nullptr);
  EXPECT_NE(state_find_item(dst, "item_src"), nullptr);

  // Clean up CRDT values before state_destroy (data_item_destroy uses free()
  // which doesn't clean up CRDT struct internals)
  for (data_item_t* it = dst->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  for (data_item_t* it = src->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(dst);
  state_destroy(src);
}

TEST(TestCRDTExtended, StateMergeWithPNCounter) {
  state_t* dst = state_create();
  state_t* src = state_create();

  data_item_t* d1 = data_item_create("pn1", DATA_TYPE_PN_COUNTER, CRDT_PN_COUNTER);
  pn_counter_t* pnc1 = pn_counter_create();
  pn_counter_increment(pnc1, "nodeA", 10);
  d1->value = pnc1;
  state_add_item(dst, d1);

  data_item_t* s1 = data_item_create("pn1", DATA_TYPE_PN_COUNTER, CRDT_PN_COUNTER);
  pn_counter_t* pnc2 = pn_counter_create();
  pn_counter_increment(pnc2, "nodeB", 5);
  pn_counter_decrement(pnc2, "nodeB", 2);
  s1->value = pnc2;
  state_add_item(src, s1);

  crabs_error_e err = crdt_merge_state(dst, src);
  EXPECT_EQ(err, CRABS_SUCCESS);

  data_item_t* merged = state_find_item(dst, "pn1");
  ASSERT_NE(merged, nullptr);
  pn_counter_t* pnc = (pn_counter_t*)merged->value;
  EXPECT_EQ(pn_counter_value(pnc), 13);

  for (data_item_t* it = dst->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  for (data_item_t* it = src->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(dst);
  state_destroy(src);
}

// ============================================================
// Serialization Extended Tests
// (v15: struct-backed counter/register values serialize their LOGICAL
// content — a node-sorted entry map for counters, payload+timestamp+node
// for registers — and the deserializer reconstructs the struct. A bare
// int64 tagged with a CRDT counter/register type is no longer a valid
// serialization fixture; RESOURCE items still carry a raw int64.)
// ============================================================

TEST(TestCRDTExtended, SerializeStateWithPNCounterInt64) {
  state_t* state = state_create();
  data_item_t* item = data_item_create("pn1", DATA_TYPE_PN_COUNTER, CRDT_PN_COUNTER);
  pn_counter_t* pn = pn_counter_create();
  ASSERT_EQ(pn_counter_increment(pn, "node1", 100), CRABS_SUCCESS);
  ASSERT_EQ(pn_counter_decrement(pn, "node1", 30), CRABS_SUCCESS);
  item->value = pn;
  state_add_item(state, item);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  data_item_t* r = state_find_item(restored, "pn1");
  ASSERT_NE(r, nullptr);
  EXPECT_EQ(r->type, DATA_TYPE_PN_COUNTER);
  ASSERT_NE(r->value, nullptr);
  EXPECT_EQ(pn_counter_value((pn_counter_t*)r->value), 70);
  // The restored struct is functional: further mutation works post-load.
  ASSERT_EQ(pn_counter_increment((pn_counter_t*)r->value, "node2", 5),
            CRABS_SUCCESS);
  EXPECT_EQ(pn_counter_value((pn_counter_t*)r->value), 75);

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

TEST(TestCRDTExtended, SerializeStateWithSetType) {
  state_t* state = state_create();
  data_item_t* item = data_item_create("set1", DATA_TYPE_SET, CRDT_OR_SET);
  // Serializer stores 0-length value for unsupported CRDT types
  item->value = nullptr;
  state_add_item(state, item);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  data_item_t* r = state_find_item(restored, "set1");
  ASSERT_NE(r, nullptr);
  EXPECT_EQ(r->type, DATA_TYPE_SET);

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

TEST(TestCRDTExtended, SerializeStateWithRegisterInt64) {
  state_t* state = state_create();
  data_item_t* item = data_item_create("reg1", DATA_TYPE_REGISTER, CRDT_LWW_REG);
  int64_t register_content = 0xDEADBEEF;
  item->value = lww_register_create((const uint8_t*)&register_content,
                                    sizeof(int64_t), 12, "writer1");
  ASSERT_NE(item->value, nullptr);
  state_add_item(state, item);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  data_item_t* r = state_find_item(restored, "reg1");
  ASSERT_NE(r, nullptr);
  EXPECT_EQ(r->type, DATA_TYPE_REGISTER);
  ASSERT_NE(r->value, nullptr);
  lww_register_t* restored_reg = (lww_register_t*)r->value;
  ASSERT_EQ(restored_reg->value_size, (uint32_t)sizeof(int64_t));
  int64_t restored_content = 0;
  memcpy(&restored_content, restored_reg->value, sizeof(int64_t));
  EXPECT_EQ(restored_content, (int64_t)0xDEADBEEF);
  EXPECT_EQ(restored_reg->timestamp, (uint64_t)12);
  EXPECT_STREQ(restored_reg->node_id, "writer1");

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

TEST(TestCRDTExtended, SerializeMultipleItemsRoundTrip) {
  state_t* state = state_create();
  state->version = 42;

  // Counter (struct-backed per the production representation)
  data_item_t* c = data_item_create("c1", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* counter = g_counter_create();
  ASSERT_EQ(g_counter_increment(counter, "node1", 7), CRABS_SUCCESS);
  c->value = counter;
  state_add_item(state, c);

  // Resource as int64_t
  data_item_t* r = data_item_create("r1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* rv = (int64_t*)malloc(sizeof(int64_t));
  *rv = 42;
  r->value = rv;
  state_add_item(state, r);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);
  EXPECT_EQ(restored->version, (uint64_t)42);

  data_item_t* rc = state_find_item(restored, "c1");
  ASSERT_NE(rc, nullptr);
  EXPECT_EQ(rc->type, DATA_TYPE_COUNTER);
  ASSERT_NE(rc->value, nullptr);
  EXPECT_EQ(g_counter_value((g_counter_t*)rc->value), 7);

  data_item_t* rr = state_find_item(restored, "r1");
  ASSERT_NE(rr, nullptr);
  EXPECT_EQ(rr->type, DATA_TYPE_RESOURCE);
  ASSERT_NE(rr->value, nullptr);
  EXPECT_EQ(*(int64_t*)rr->value, 42);

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

TEST(TestCRDTExtended, MergeValueUnsupportedTypes) {
  void* result = crdt_merge_value(DATA_TYPE_DOCUMENT, CRDT_RGA, nullptr, nullptr, "a", "b");
  EXPECT_EQ(result, nullptr);

  result = crdt_merge_value(DATA_TYPE_CUSTOM, CRDT_CUSTOM, nullptr, nullptr, "a", "b");
  EXPECT_EQ(result, nullptr);
}

// ============================================================
// Per-Value Merge Dispatch for Sets
// ============================================================

TEST(TestCRDTExtended, MergeValueORSet) {
  or_set_t* a = or_set_create();
  or_set_t* b = or_set_create();
  or_set_add(a, "x", "n1:1");
  or_set_add(b, "y", "n2:1");

  void* merged = crdt_merge_value(DATA_TYPE_SET, CRDT_OR_SET, a, b, "n1", "n2");
  ASSERT_NE(merged, nullptr);
  or_set_t* ms = (or_set_t*)merged;
  EXPECT_TRUE(or_set_contains(ms, "x"));
  EXPECT_TRUE(or_set_contains(ms, "y"));

  or_set_destroy(a);
  or_set_destroy(b);
  or_set_destroy(ms);
}

TEST(TestCRDTExtended, MergeValue2PSet) {
  two_p_set_t* a = two_p_set_create();
  two_p_set_t* b = two_p_set_create();
  two_p_set_add(a, "x");
  two_p_set_add(b, "y");
  two_p_set_remove(a, "x");

  void* merged = crdt_merge_value(DATA_TYPE_2P_SET, CRDT_2P_SET, a, b, "n1", "n2");
  ASSERT_NE(merged, nullptr);
  two_p_set_t* ms = (two_p_set_t*)merged;
  EXPECT_FALSE(two_p_set_contains(ms, "x"));
  EXPECT_TRUE(two_p_set_contains(ms, "y"));

  two_p_set_destroy(a);
  two_p_set_destroy(b);
  two_p_set_destroy(ms);
}