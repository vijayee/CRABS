#include <gtest/gtest.h>
extern "C" {
#include "../src/CRDT/crdt_merge.h"
}

// ============================================================
// G-Counter tests
// ============================================================

TEST(TestGCounter, TestCreateAndValue) {
  g_counter_t* counter = g_counter_create();
  ASSERT_NE(counter, nullptr);
  EXPECT_EQ(g_counter_value(counter), 0);
  g_counter_destroy(counter);
}

TEST(TestGCounter, TestIncrement) {
  g_counter_t* counter = g_counter_create();
  ASSERT_NE(counter, nullptr);

  crabs_error_e err = g_counter_increment(counter, "nodeA", 5);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(g_counter_value(counter), 5);

  err = g_counter_increment(counter, "nodeB", 3);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(g_counter_value(counter), 8);

  // Increment existing node
  err = g_counter_increment(counter, "nodeA", 2);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(g_counter_value(counter), 10);

  g_counter_destroy(counter);
}

TEST(TestGCounter, TestMerge) {
  g_counter_t* a = g_counter_create();
  g_counter_t* b = g_counter_create();

  g_counter_increment(a, "nodeA", 5);
  g_counter_increment(a, "nodeB", 3);
  g_counter_increment(b, "nodeB", 7);
  g_counter_increment(b, "nodeC", 2);

  g_counter_t* merged = g_counter_merge(a, b);
  ASSERT_NE(merged, nullptr);

  // nodeA: max(5, 0) = 5
  // nodeB: max(3, 7) = 7
  // nodeC: max(0, 2) = 2
  // Total: 5 + 7 + 2 = 14
  EXPECT_EQ(g_counter_value(merged), 14);

  g_counter_destroy(a);
  g_counter_destroy(b);
  g_counter_destroy(merged);
}

TEST(TestGCounter, TestMergeSameNode) {
  g_counter_t* a = g_counter_create();
  g_counter_t* b = g_counter_create();

  g_counter_increment(a, "nodeA", 3);
  g_counter_increment(b, "nodeA", 7);

  g_counter_t* merged = g_counter_merge(a, b);
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(g_counter_value(merged), 7);

  g_counter_destroy(a);
  g_counter_destroy(b);
  g_counter_destroy(merged);
}

TEST(TestGCounter, TestMergeNullInputs) {
  g_counter_t* a = g_counter_create();
  g_counter_increment(a, "nodeA", 10);

  g_counter_t* merged1 = g_counter_merge(a, nullptr);
  ASSERT_NE(merged1, nullptr);
  EXPECT_EQ(g_counter_value(merged1), 10);

  g_counter_t* merged2 = g_counter_merge(nullptr, a);
  ASSERT_NE(merged2, nullptr);
  EXPECT_EQ(g_counter_value(merged2), 10);

  g_counter_t* merged3 = g_counter_merge(nullptr, nullptr);
  EXPECT_EQ(merged3, nullptr);

  g_counter_destroy(a);
  g_counter_destroy(merged1);
  g_counter_destroy(merged2);
}

TEST(TestGCounter, TestInvalidParams) {
  crabs_error_e err = g_counter_increment(nullptr, "nodeA", 5);
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);

  g_counter_t* counter = g_counter_create();
  err = g_counter_increment(counter, nullptr, 5);
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);

  EXPECT_EQ(g_counter_value(nullptr), 0);
  g_counter_destroy(counter);
  g_counter_destroy(nullptr); // Should not crash
}

// ============================================================
// PN-Counter tests
// ============================================================

TEST(TestPNCounter, TestCreateAndValue) {
  pn_counter_t* counter = pn_counter_create();
  ASSERT_NE(counter, nullptr);
  EXPECT_EQ(pn_counter_value(counter), 0);
  pn_counter_destroy(counter);
}

TEST(TestPNCounter, TestIncrementDecrement) {
  pn_counter_t* counter = pn_counter_create();
  ASSERT_NE(counter, nullptr);

  pn_counter_increment(counter, "nodeA", 10);
  EXPECT_EQ(pn_counter_value(counter), 10);

  pn_counter_decrement(counter, "nodeA", 3);
  EXPECT_EQ(pn_counter_value(counter), 7);

  pn_counter_increment(counter, "nodeB", 5);
  EXPECT_EQ(pn_counter_value(counter), 12);

  pn_counter_decrement(counter, "nodeB", 2);
  EXPECT_EQ(pn_counter_value(counter), 10);

  pn_counter_destroy(counter);
}

TEST(TestPNCounter, TestMerge) {
  pn_counter_t* a = pn_counter_create();
  pn_counter_t* b = pn_counter_create();

  pn_counter_increment(a, "nodeA", 5);
  pn_counter_decrement(a, "nodeA", 2);
  EXPECT_EQ(pn_counter_value(a), 3);

  pn_counter_increment(b, "nodeB", 10);
  pn_counter_decrement(b, "nodeB", 4);
  EXPECT_EQ(pn_counter_value(b), 6);

  pn_counter_t* merged = pn_counter_merge(a, b);
  ASSERT_NE(merged, nullptr);
  // pos: nodeA=5, nodeB=10 => total=15
  // neg: nodeA=2, nodeB=4 => total=6
  // value: 15 - 6 = 9
  EXPECT_EQ(pn_counter_value(merged), 9);

  pn_counter_destroy(a);
  pn_counter_destroy(b);
  pn_counter_destroy(merged);
}

TEST(TestPNCounter, TestMergeNullInputs) {
  pn_counter_t* a = pn_counter_create();
  pn_counter_increment(a, "nodeA", 7);

  pn_counter_t* merged = pn_counter_merge(a, nullptr);
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(pn_counter_value(merged), 7);

  pn_counter_destroy(a);
  pn_counter_destroy(merged);
}

TEST(TestPNCounter, TestInvalidParams) {
  crabs_error_e err = pn_counter_increment(nullptr, "nodeA", 5);
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);

  err = pn_counter_decrement(nullptr, "nodeA", 5);
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);

  EXPECT_EQ(pn_counter_value(nullptr), 0);
  pn_counter_destroy(nullptr); // Should not crash
}

// ============================================================
// OR-Set tests
// ============================================================

TEST(TestORSet, TestCreateAndAdd) {
  or_set_t* set = or_set_create();
  ASSERT_NE(set, nullptr);
  EXPECT_EQ(set->element_count, 0u);
  EXPECT_EQ(set->tombstone_count, 0u);

  crabs_error_e err = or_set_add(set, "apple", "nodeA:1");
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_TRUE(or_set_contains(set, "apple"));
  EXPECT_FALSE(or_set_contains(set, "banana"));

  or_set_destroy(set);
}

TEST(TestORSet, TestAddRemoveContains) {
  or_set_t* set = or_set_create();
  ASSERT_NE(set, nullptr);

  or_set_add(set, "apple", "nodeA:1");
  or_set_add(set, "banana", "nodeA:2");

  EXPECT_TRUE(or_set_contains(set, "apple"));
  EXPECT_TRUE(or_set_contains(set, "banana"));

  // Remove apple
  crabs_error_e err = or_set_remove(set, "apple");
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_FALSE(or_set_contains(set, "apple"));
  EXPECT_TRUE(or_set_contains(set, "banana"));

  or_set_destroy(set);
}

TEST(TestORSet, TestMerge) {
  or_set_t* a = or_set_create();
  or_set_t* b = or_set_create();

  or_set_add(a, "apple", "nodeA:1");
  or_set_add(a, "banana", "nodeA:2");
  or_set_remove(a, "apple"); // Remove apple in set a

  or_set_add(b, "apple", "nodeA:1"); // Same tag as a
  or_set_add(b, "cherry", "nodeB:1");

  or_set_t* merged = or_set_merge(a, b);
  ASSERT_NE(merged, nullptr);

  // apple was removed in a (tombstoned), and the same tag is in b
  // After merge: tombstones from a apply, so "apple" with tag "nodeA:1" is tombstoned
  EXPECT_FALSE(or_set_contains(merged, "apple"));
  EXPECT_TRUE(or_set_contains(merged, "banana"));
  EXPECT_TRUE(or_set_contains(merged, "cherry"));

  or_set_destroy(a);
  or_set_destroy(b);
  or_set_destroy(merged);
}

TEST(TestORSet, TestMergeNullInputs) {
  or_set_t* a = or_set_create();
  or_set_add(a, "apple", "nodeA:1");

  or_set_t* merged = or_set_merge(a, nullptr);
  ASSERT_NE(merged, nullptr);
  EXPECT_TRUE(or_set_contains(merged, "apple"));

  or_set_destroy(a);
  or_set_destroy(merged);

  or_set_t* merged2 = or_set_merge(nullptr, nullptr);
  EXPECT_EQ(merged2, nullptr);
}

TEST(TestORSet, TestInvalidParams) {
  crabs_error_e err = or_set_add(nullptr, "apple", "tag");
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);

  err = or_set_remove(nullptr, "apple");
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);

  EXPECT_FALSE(or_set_contains(nullptr, "apple"));
  or_set_destroy(nullptr); // Should not crash
}

// ============================================================
// 2P-Set tests
// ============================================================

TEST(TestTwoPSet, TestCreateAndAdd) {
  two_p_set_t* set = two_p_set_create();
  ASSERT_NE(set, nullptr);
  EXPECT_EQ(set->add_count, 0u);
  EXPECT_EQ(set->remove_count, 0u);

  crabs_error_e err = two_p_set_add(set, "apple");
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_TRUE(two_p_set_contains(set, "apple"));

  or_set_destroy(nullptr); // Just to cover destroy-noop
  two_p_set_destroy(set);
}

TEST(TestTwoPSet, TestAddRemoveContains) {
  two_p_set_t* set = two_p_set_create();
  ASSERT_NE(set, nullptr);

  two_p_set_add(set, "apple");
  two_p_set_add(set, "banana");
  EXPECT_TRUE(two_p_set_contains(set, "apple"));
  EXPECT_TRUE(two_p_set_contains(set, "banana"));
  EXPECT_FALSE(two_p_set_contains(set, "cherry"));

  two_p_set_remove(set, "apple");
  EXPECT_FALSE(two_p_set_contains(set, "apple"));
  EXPECT_TRUE(two_p_set_contains(set, "banana"));

  two_p_set_destroy(set);
}

TEST(TestTwoPSet, TestMerge) {
  two_p_set_t* a = two_p_set_create();
  two_p_set_t* b = two_p_set_create();

  two_p_set_add(a, "apple");
  two_p_set_add(a, "banana");
  two_p_set_remove(a, "apple");

  two_p_set_add(b, "cherry");
  two_p_set_remove(b, "banana");

  two_p_set_t* merged = two_p_set_merge(a, b);
  ASSERT_NE(merged, nullptr);

  // apple: in add, in remove => not visible
  EXPECT_FALSE(two_p_set_contains(merged, "apple"));
  // banana: in add, in remove => not visible
  EXPECT_FALSE(two_p_set_contains(merged, "banana"));
  // cherry: in add, not in remove => visible
  EXPECT_TRUE(two_p_set_contains(merged, "cherry"));

  two_p_set_destroy(a);
  two_p_set_destroy(b);
  two_p_set_destroy(merged);
}

TEST(TestTwoPSet, TestCannotReaddAfterRemove) {
  two_p_set_t* set = two_p_set_create();
  ASSERT_NE(set, nullptr);

  two_p_set_add(set, "apple");
  EXPECT_TRUE(two_p_set_contains(set, "apple"));

  two_p_set_remove(set, "apple");
  EXPECT_FALSE(two_p_set_contains(set, "apple"));

  // Re-adding to add_set does not make it visible again
  two_p_set_add(set, "apple");
  EXPECT_FALSE(two_p_set_contains(set, "apple"));

  two_p_set_destroy(set);
}

TEST(TestTwoPSet, TestMergeNullInputs) {
  two_p_set_t* a = two_p_set_create();
  two_p_set_add(a, "apple");

  two_p_set_t* merged = two_p_set_merge(a, nullptr);
  ASSERT_NE(merged, nullptr);
  EXPECT_TRUE(two_p_set_contains(merged, "apple"));

  two_p_set_destroy(a);
  two_p_set_destroy(merged);

  two_p_set_t* merged2 = two_p_set_merge(nullptr, nullptr);
  EXPECT_EQ(merged2, nullptr);
}

// ============================================================
// LWW-Register tests
// ============================================================

TEST(TestLWWRegister, TestCreate) {
  uint8_t data[] = {0x01, 0x02, 0x03};
  lww_register_t* reg = lww_register_create(data, 3, 1000, "nodeA");
  ASSERT_NE(reg, nullptr);
  EXPECT_EQ(reg->value_size, 3u);
  EXPECT_EQ(reg->timestamp, 1000u);
  EXPECT_STREQ(reg->node_id, "nodeA");
  EXPECT_EQ(memcmp(reg->value, data, 3), 0);

  lww_register_destroy(reg);
}

TEST(TestLWWRegister, TestMergeNewerWins) {
  uint8_t data_a[] = {0x01};
  uint8_t data_b[] = {0x02};

  lww_register_t* a = lww_register_create(data_a, 1, 1000, "nodeA");
  lww_register_t* b = lww_register_create(data_b, 1, 2000, "nodeB");

  lww_register_t* merged = lww_register_merge(a, b);
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(merged->timestamp, 2000u);
  EXPECT_EQ(merged->value[0], 0x02);

  lww_register_destroy(a);
  lww_register_destroy(b);
  lww_register_destroy(merged);
}

TEST(TestLWWRegister, TestMergeTieBreakerNodeId) {
  uint8_t data_a[] = {0x01};
  uint8_t data_b[] = {0x02};

  // Same timestamp, nodeB > nodeA lexicographically, so nodeB wins
  lww_register_t* a = lww_register_create(data_a, 1, 1000, "nodeA");
  lww_register_t* b = lww_register_create(data_b, 1, 1000, "nodeB");

  lww_register_t* merged = lww_register_merge(a, b);
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(merged->timestamp, 1000u);
  EXPECT_EQ(merged->value[0], 0x02); // nodeB wins
  EXPECT_STREQ(merged->node_id, "nodeB");

  lww_register_destroy(a);
  lww_register_destroy(b);
  lww_register_destroy(merged);
}

TEST(TestLWWRegister, TestMergeNullInputs) {
  uint8_t data[] = {0x01};
  lww_register_t* a = lww_register_create(data, 1, 500, "nodeA");

  lww_register_t* merged1 = lww_register_merge(a, nullptr);
  ASSERT_NE(merged1, nullptr);
  EXPECT_EQ(merged1->timestamp, 500u);

  lww_register_t* merged2 = lww_register_merge(nullptr, a);
  ASSERT_NE(merged2, nullptr);
  EXPECT_EQ(merged2->timestamp, 500u);

  lww_register_t* merged3 = lww_register_merge(nullptr, nullptr);
  EXPECT_EQ(merged3, nullptr);

  lww_register_destroy(a);
  lww_register_destroy(merged1);
  lww_register_destroy(merged2);
}

// ============================================================
// Per-value merge dispatch tests
// ============================================================

TEST(TestCRDTMerge, TestMergeValueGCounter) {
  g_counter_t* a = g_counter_create();
  g_counter_t* b = g_counter_create();
  g_counter_increment(a, "nodeA", 5);
  g_counter_increment(b, "nodeA", 7);

  void* merged = crdt_merge_value(DATA_TYPE_COUNTER, CRDT_G_COUNTER, a, b, "nodeA", "nodeB");
  ASSERT_NE(merged, nullptr);
  g_counter_t* gc = (g_counter_t*)merged;
  EXPECT_EQ(g_counter_value(gc), 7);

  g_counter_destroy(a);
  g_counter_destroy(b);
  g_counter_destroy(gc);
}

TEST(TestCRDTMerge, TestMergeValuePNCounter) {
  pn_counter_t* a = pn_counter_create();
  pn_counter_t* b = pn_counter_create();
  pn_counter_increment(a, "nodeA", 5);
  pn_counter_decrement(a, "nodeA", 2);
  pn_counter_increment(b, "nodeB", 10);

  void* merged = crdt_merge_value(DATA_TYPE_PN_COUNTER, CRDT_PN_COUNTER, a, b, "nodeA", "nodeB");
  ASSERT_NE(merged, nullptr);
  pn_counter_t* pnc = (pn_counter_t*)merged;
  EXPECT_EQ(pn_counter_value(pnc), 13); // (5+10) - 2 = 13

  pn_counter_destroy(a);
  pn_counter_destroy(b);
  pn_counter_destroy(pnc);
}

TEST(TestCRDTMerge, TestMergeValueLWWReg) {
  uint8_t data_a[] = {0xAA};
  uint8_t data_b[] = {0xBB};

  lww_register_t* a = lww_register_create(data_a, 1, 100, "nodeA");
  lww_register_t* b = lww_register_create(data_b, 1, 200, "nodeB");

  void* merged = crdt_merge_value(DATA_TYPE_REGISTER, CRDT_LWW_REG, a, b, "nodeA", "nodeB");
  ASSERT_NE(merged, nullptr);
  lww_register_t* reg = (lww_register_t*)merged;
  EXPECT_EQ(reg->timestamp, 200u);

  lww_register_destroy(a);
  lww_register_destroy(b);
  lww_register_destroy(reg);
}

TEST(TestCRDTMerge, TestMergeValueUnsupportedType) {
  void* result = crdt_merge_value(DATA_TYPE_DOCUMENT, CRDT_RGA, NULL, NULL, "a", "b");
  EXPECT_EQ(result, nullptr);

  result = crdt_merge_value(DATA_TYPE_CUSTOM, CRDT_CUSTOM, NULL, NULL, "a", "b");
  EXPECT_EQ(result, nullptr);
}

// ============================================================
// State merge tests
// ============================================================

TEST(TestCRDTMerge, TestStateMergeBasic) {
  state_t* dst = state_create();
  state_t* src = state_create();

  // Create items in dst
  data_item_t* dst_item = data_item_create("counter1", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* dst_gc = g_counter_create();
  g_counter_increment(dst_gc, "nodeA", 5);
  dst_item->value = dst_gc;
  state_add_item(dst, dst_item);

  // Create items in src
  data_item_t* src_item = data_item_create("counter1", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* src_gc = g_counter_create();
  g_counter_increment(src_gc, "nodeA", 7);
  src_item->value = src_gc;
  state_add_item(src, src_item);

  // Add an item only in src
  data_item_t* src_item2 = data_item_create("counter2", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* src_gc2 = g_counter_create();
  g_counter_increment(src_gc2, "nodeB", 3);
  src_item2->value = src_gc2;
  state_add_item(src, src_item2);

  src->version = 10;

  crabs_error_e err = crdt_merge_state(dst, src);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(dst->version, 10u);

  // counter1 should be merged: max(5, 7) = 7
  data_item_t* merged_item = state_find_item(dst, "counter1");
  ASSERT_NE(merged_item, nullptr);
  g_counter_t* merged_gc = (g_counter_t*)merged_item->value;
  EXPECT_EQ(g_counter_value(merged_gc), 7);

  // counter2 should be added
  data_item_t* new_item = state_find_item(dst, "counter2");
  ASSERT_NE(new_item, nullptr);

  for (data_item_t* it = dst->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  for (data_item_t* it = src->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(dst);
  state_destroy(src);
}

TEST(TestCRDTMerge, TestStateMergeVersionMax) {
  state_t* dst = state_create();
  state_t* src = state_create();

  dst->version = 20;
  src->version = 15;

  crabs_error_e err = crdt_merge_state(dst, src);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(dst->version, 20u); // max(20, 15)

  state_destroy(dst);
  state_destroy(src);
}

TEST(TestCRDTMerge, TestStateMergeInvalidParams) {
  crabs_error_e err = crdt_merge_state(nullptr, nullptr);
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);

  state_t* s = state_create();
  err = crdt_merge_state(s, nullptr);
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);
  err = crdt_merge_state(nullptr, s);
  EXPECT_EQ(err, CRABS_ERR_INVALID_PARAM);
  state_destroy(s);
}