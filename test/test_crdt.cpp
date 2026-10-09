#include <gtest/gtest.h>
extern "C" {
#include "../src/CRDT/crdt_merge.h"
#include "../src/StateMachine/state_machine.h"
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

// ============================================================
// Write-domain merge dispatch tests (write-domains v1)
// ============================================================

// Build a sovereign counter item directly (writer/seq stamped, digest
// COMPUTED from content the same way the post-op bookkeeping stamps it —
// state_item_digest_compute), so an honest snapshot's carried head always
// matches its content. The merge dispatch treats the carried digest as
// advisory and reasons over content-derived heads (write-domains deferred
// Task B), so tests that need a forged head corrupt item->item_digest AFTER
// creation instead of seeding one here.
static data_item_t* _make_sovereign_counter(const char* name, const char* writer,
                                            uint64_t item_seq,
                                            int64_t increments) {
  data_item_options_t options;
  memset(&options, 0, sizeof(options));
  options.write_domain = CRABS_DOMAIN_SOVEREIGN;
  options.writer = writer;
  data_item_t* item = nullptr;
  crabs_error_e create_err =
      data_item_create_with_options(name, DATA_TYPE_COUNTER, CRDT_G_COUNTER,
                                    &options, &item);
  EXPECT_EQ(create_err, CRABS_SUCCESS);
  if (item == nullptr) return nullptr;
  g_counter_t* counter = g_counter_create();
  if (increments > 0) {
    g_counter_increment(counter, writer, increments);
  }
  item->value = counter;
  item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  item->item_seq = item_seq;
  EXPECT_EQ(state_item_digest_compute(item, item->item_digest), CRABS_SUCCESS);
  return item;
}

static data_item_t* _make_group_register(const char* name,
                                         const char* register_value) {
  data_item_options_t options;
  memset(&options, 0, sizeof(options));
  options.write_domain = CRABS_DOMAIN_GROUP_ORDERED;
  data_item_t* item = nullptr;
  crabs_error_e create_err =
      data_item_create_with_options(name, DATA_TYPE_REGISTER, CRDT_LWW_REG,
                                    &options, &item);
  EXPECT_EQ(create_err, CRABS_SUCCESS);
  if (item == nullptr) return nullptr;
  if (register_value != nullptr) {
    item->value = lww_register_create((const uint8_t*)register_value,
                                      (uint32_t)strlen(register_value), 1, "nodeA");
    item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  }
  return item;
}

// Capture of the last change event emitted during a merge.
typedef struct {
  int                 calls;
  crabs_change_kind_e kind;
  char                type[CRABS_MAX_USER_ID];
  char                target[CRABS_MAX_USER_ID];
  crabs_error_e       result;
} merge_event_capture_t;

static void _merge_event_hook(state_t* state, const crabs_change_event_t* event,
                              void* user_data) {
  (void)state;
  merge_event_capture_t* capture = (merge_event_capture_t*)user_data;
  capture->calls++;
  capture->kind = event->kind;
  memset(capture->type, 0, sizeof(capture->type));
  if (event->type != NULL) {
    strncpy(capture->type, event->type, sizeof(capture->type) - 1);
  }
  memset(capture->target, 0, sizeof(capture->target));
  if (event->target != NULL) {
    strncpy(capture->target, event->target, sizeof(capture->target) - 1);
  }
  capture->result = event->result;
}

// Free every item value of a state via crdt_value_destroy (data_item_destroy's
// default arm only frees the wrapper for counter/register types).
static void _destroy_state_values(state_t* state) {
  for (data_item_t* item = state->items; item != NULL; item = item->next) {
    if (item->value != NULL) {
      crdt_value_destroy(item->crdt_type, item->value);
      item->value = NULL;
    }
  }
}

// Carried Task-1 review fix: the merge deep-copy path must propagate the
// write-domain fields — a sovereign item new to dst must arrive whole.
TEST(TestCRDTMerge, TestMergeDeepCopyPropagatesDomainFields) {
  state_t* dst = state_create();
  state_t* src = state_create();

  data_item_t* src_item = _make_sovereign_counter("vault", "alice", 7, 9);
  ASSERT_NE(src_item, nullptr);
  uint8_t src_digest[CRABS_HASH_SIZE];
  memcpy(src_digest, src_item->item_digest, CRABS_HASH_SIZE);
  uint8_t fork_evidence[CRABS_HASH_SIZE];
  memset(fork_evidence, 0xF0, sizeof(fork_evidence));
  EXPECT_EQ(state_append_fork_evidence(src_item, "mallory", fork_evidence),
            CRABS_SUCCESS);
  state_add_item(src, src_item);

  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);

  data_item_t* dst_item = state_find_item(dst, "vault");
  ASSERT_NE(dst_item, nullptr);
  EXPECT_EQ(dst_item->write_domain, CRABS_DOMAIN_SOVEREIGN);
  EXPECT_STREQ(dst_item->writer, "alice");
  EXPECT_EQ(dst_item->item_seq, 7u);
  EXPECT_EQ(memcmp(dst_item->item_digest, src_digest, CRABS_HASH_SIZE), 0);
  EXPECT_EQ(dst_item->ordering_module, 0);
  ASSERT_EQ(dst_item->fork_count, 1u);
  EXPECT_STREQ(dst_item->fork_writers[0], "mallory");
  EXPECT_EQ(memcmp(dst_item->fork_evidence_digests[0], fork_evidence,
                   CRABS_HASH_SIZE), 0);
  // content carried too
  EXPECT_EQ(g_counter_value((g_counter_t*)dst_item->value), 9);

  _destroy_state_values(dst);
  _destroy_state_values(src);
  state_destroy(dst);
  state_destroy(src);
}

// SOVEREIGN: the remote chain head is ahead with the same writer — accept it.
// Adopt sets the merged head to the RECOMPUTED digest of the adopted content;
// for an honest snapshot carried == computed (sanity half of the recompute
// rule — the tampered half is TestSovereignMergeTamperedCarriedDigestHeld).
TEST(TestCRDTMerge, TestSovereignMergeAcceptsAheadSnapshot) {
  state_t* dst = state_create();
  state_t* src = state_create();
  merge_event_capture_t capture = {};
  state_set_change_hook(dst, _merge_event_hook, &capture);

  data_item_t* dst_item = _make_sovereign_counter("vault", "alice", 3, 2);
  data_item_t* src_item = _make_sovereign_counter("vault", "alice", 5, 9);
  ASSERT_NE(dst_item, nullptr);
  ASSERT_NE(src_item, nullptr);
  uint8_t src_digest[CRABS_HASH_SIZE];
  memcpy(src_digest, src_item->item_digest, CRABS_HASH_SIZE);
  state_add_item(dst, dst_item);
  state_add_item(src, src_item);

  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);

  data_item_t* merged = state_find_item(dst, "vault");
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(g_counter_value((g_counter_t*)merged->value), 9);
  EXPECT_EQ(merged->item_seq, 5u);
  EXPECT_EQ(memcmp(merged->item_digest, src_digest, CRABS_HASH_SIZE), 0);
  EXPECT_STREQ(merged->writer, "alice");
  // The adopted head is exactly the digest of the adopted content — the merge
  // recomputed it rather than trusting src's carried field.
  uint8_t recomputed[CRABS_HASH_SIZE];
  ASSERT_EQ(state_item_digest_compute(merged, recomputed), CRABS_SUCCESS);
  EXPECT_EQ(memcmp(recomputed, src_digest, CRABS_HASH_SIZE), 0);
  // a clean continuation is silent
  EXPECT_EQ(capture.calls, 0);

  _destroy_state_values(dst);
  _destroy_state_values(src);
  state_destroy(dst);
  state_destroy(src);
}

// SOVEREIGN: an ahead snapshot whose CARRIED digest disagrees with its own
// content (in-flight tamper — the content is honest, the chain head is
// fabricated). The digest preimage is content-only, so the recompute cannot
// reproduce the forged head: fail closed — keep dst's content AND chain head
// whole, surface a held divergence, and do NOT convict the writer (a relay
// forging a head carries no equivocation evidence).
TEST(TestCRDTMerge, TestSovereignMergeTamperedCarriedDigestHeld) {
  state_t* dst = state_create();
  state_t* src = state_create();
  merge_event_capture_t capture = {};
  state_set_change_hook(dst, _merge_event_hook, &capture);

  data_item_t* dst_item = _make_sovereign_counter("vault", "alice", 3, 2);
  data_item_t* src_item = _make_sovereign_counter("vault", "alice", 5, 9);
  ASSERT_NE(dst_item, nullptr);
  ASSERT_NE(src_item, nullptr);
  src_item->item_digest[0] ^= 0xFF;  // forge the carried head, keep content
  uint8_t dst_digest[CRABS_HASH_SIZE];
  memcpy(dst_digest, dst_item->item_digest, CRABS_HASH_SIZE);
  state_add_item(dst, dst_item);
  state_add_item(src, src_item);

  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);

  data_item_t* merged = state_find_item(dst, "vault");
  ASSERT_NE(merged, nullptr);
  // Nothing adopted: content, seq, and the stored head all stay item_a's.
  EXPECT_EQ(g_counter_value((g_counter_t*)merged->value), 2);
  EXPECT_EQ(merged->item_seq, 3u);
  EXPECT_EQ(memcmp(merged->item_digest, dst_digest, CRABS_HASH_SIZE), 0);
  EXPECT_EQ(merged->fork_count, 0u);
  EXPECT_FALSE(state_item_is_quarantined(merged, "alice"));
  ASSERT_EQ(capture.calls, 1);
  EXPECT_EQ(capture.kind, CRABS_CHANGE_MERGE);
  EXPECT_STREQ(capture.type, "__merge_held__");
  EXPECT_STREQ(capture.target, "vault");
  EXPECT_EQ(capture.result, CRABS_ERR_PROTOCOL_VIOLATION);

  _destroy_state_values(dst);
  _destroy_state_values(src);
  state_destroy(dst);
  state_destroy(src);
}

// SOVEREIGN: the local chain head is ahead — keep it, ignore the stale tail.
TEST(TestCRDTMerge, TestSovereignMergeKeepsLocalWhenAhead) {
  state_t* dst = state_create();
  state_t* src = state_create();
  merge_event_capture_t capture = {};
  state_set_change_hook(dst, _merge_event_hook, &capture);

  data_item_t* dst_item = _make_sovereign_counter("vault", "alice", 6, 4);
  data_item_t* src_item = _make_sovereign_counter("vault", "alice", 2, 100);
  ASSERT_NE(dst_item, nullptr);
  ASSERT_NE(src_item, nullptr);
  state_add_item(dst, dst_item);
  state_add_item(src, src_item);

  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);

  data_item_t* merged = state_find_item(dst, "vault");
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(g_counter_value((g_counter_t*)merged->value), 4);
  EXPECT_EQ(merged->item_seq, 6u);
  EXPECT_EQ(capture.calls, 0);

  _destroy_state_values(dst);
  _destroy_state_values(src);
  state_destroy(dst);
  state_destroy(src);
}

// SOVEREIGN: equal seq + equal digest is an identical head — no-op, and the
// local value object is left untouched.
// SOVEREIGN: equal seq + equal digest is an identical head — no-op, and the
// local value object is left untouched.
TEST(TestCRDTMerge, TestSovereignMergeIdenticalHeadIsNoOp) {
  state_t* dst = state_create();
  state_t* src = state_create();
  merge_event_capture_t capture = {};
  state_set_change_hook(dst, _merge_event_hook, &capture);

  data_item_t* dst_item = _make_sovereign_counter("vault", "alice", 4, 3);
  data_item_t* src_item = _make_sovereign_counter("vault", "alice", 4, 3);
  ASSERT_NE(dst_item, nullptr);
  ASSERT_NE(src_item, nullptr);
  state_add_item(dst, dst_item);
  state_add_item(src, src_item);
  void* original_value = dst_item->value;

  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);

  data_item_t* merged = state_find_item(dst, "vault");
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(merged->value, original_value);
  EXPECT_EQ(merged->item_seq, 4u);
  EXPECT_EQ(capture.calls, 0);

  _destroy_state_values(dst);
  _destroy_state_values(src);
  state_destroy(dst);
  state_destroy(src);
}

// SOVEREIGN: equal seq + CONTENT-equal snapshots CONVERGE even when one
// replica's carried digest was corrupted in flight. The fork judgment keys on
// content-derived heads, so a forged carried field can neither convict an
// honest writer nor plant fork evidence (pre-fix behavior: the carried-field
// comparison convicted alice and quarantined her on a content-identical
// snapshot — a false conviction a relay could manufacture).
TEST(TestCRDTMerge, TestSovereignMergeEqualSeqCorruptedCarriedDigestConverges) {
  state_t* dst = state_create();
  state_t* src = state_create();
  merge_event_capture_t capture = {};
  state_set_change_hook(dst, _merge_event_hook, &capture);

  data_item_t* dst_item = _make_sovereign_counter("vault", "alice", 4, 3);
  data_item_t* src_item = _make_sovereign_counter("vault", "alice", 4, 3);
  ASSERT_NE(dst_item, nullptr);
  ASSERT_NE(src_item, nullptr);
  src_item->item_digest[0] ^= 0xFF;  // corrupt the carried head only
  uint8_t dst_digest[CRABS_HASH_SIZE];
  memcpy(dst_digest, dst_item->item_digest, CRABS_HASH_SIZE);
  state_add_item(dst, dst_item);
  state_add_item(src, src_item);
  void* original_value = dst_item->value;

  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);

  data_item_t* merged = state_find_item(dst, "vault");
  ASSERT_NE(merged, nullptr);
  // Convergence, not fork: identical content is the identical-head no-op arm.
  EXPECT_EQ(merged->value, original_value);
  EXPECT_EQ(merged->item_seq, 4u);
  EXPECT_EQ(memcmp(merged->item_digest, dst_digest, CRABS_HASH_SIZE), 0);
  EXPECT_EQ(merged->fork_count, 0u);
  EXPECT_FALSE(state_item_is_quarantined(merged, "alice"));
  EXPECT_EQ(capture.calls, 0)
      << "a corrupted carried digest must NOT fork-convict an honest writer";

  _destroy_state_values(dst);
  _destroy_state_values(src);
  state_destroy(dst);
  state_destroy(src);
}

// SOVEREIGN: equal seq + equal content with DIVERGENT protocol_state on the two
// replicas must NOT convict. The chain digest is content-only, so runtime lock
// state on a single replica reads as an identical head — no fork evidence, no
// event. Pre-fix the preimage included protocol_state, so a lock taken on one
// replica alone produced false fork evidence against an honest writer.
TEST(TestCRDTMerge, TestSovereignMergeProtocolStateDivergenceIsNotFork) {
  state_t* dst = state_create();
  state_t* src = state_create();
  merge_event_capture_t capture = {};
  state_set_change_hook(dst, _merge_event_hook, &capture);

  // A struct-backed LWW register — the chain serializer now emits the
  // register's logical content (payload + timestamp + node), so the same
  // content pins identical digests when protocol_state is excluded from the
  // preimage. Identical content, identical chain position, same writer; the
  // digest cache is stamped by the same path the state machine uses post-op
  // (state_item_digest_compute), so the test reproduces the merge-time
  // (seq, digest) comparison exactly.
  auto make_sovereign_register = [](const char* writer, uint64_t item_seq,
                                    int64_t register_value) {
    data_item_options_t options;
    memset(&options, 0, sizeof(options));
    options.write_domain = CRABS_DOMAIN_SOVEREIGN;
    options.writer = writer;
    data_item_t* item = nullptr;
    EXPECT_EQ(data_item_create_with_options("vault", DATA_TYPE_REGISTER,
                                            CRDT_LWW_REG, &options, &item),
              CRABS_SUCCESS);
    if (item == nullptr) return (data_item_t*)nullptr;
    item->value = lww_register_create((const uint8_t*)&register_value,
                                      sizeof(int64_t), 0, writer);
    item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
    EXPECT_NE(item->value, nullptr);
    if (item->value == nullptr) { data_item_destroy(item); return (data_item_t*)nullptr; }
    item->item_seq = item_seq;
    return item;
  };

  data_item_t* dst_item = make_sovereign_register("alice", 4, 7);
  data_item_t* src_item = make_sovereign_register("alice", 4, 7);
  ASSERT_NE(dst_item, nullptr);
  ASSERT_NE(src_item, nullptr);
  // One replica holds a runtime lock; the other doesn't.
  dst_item->protocol_state = PROTOCOL_LOCKED;
  src_item->protocol_state = PROTOCOL_IDLE;
  ASSERT_EQ(state_item_digest_compute(dst_item, dst_item->item_digest),
            CRABS_SUCCESS);
  ASSERT_EQ(state_item_digest_compute(src_item, src_item->item_digest),
            CRABS_SUCCESS);
  state_add_item(dst, dst_item);
  state_add_item(src, src_item);

  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);

  data_item_t* merged = state_find_item(dst, "vault");
  ASSERT_NE(merged, nullptr);
  // No fork evidence, no quarantine conviction, no merge events.
  EXPECT_EQ(merged->fork_count, 0u);
  EXPECT_FALSE(state_item_is_quarantined(merged, "alice"));
  EXPECT_EQ(capture.calls, 0)
      << "protocol-state divergence must NOT fork-convict a legitimate writer";

  // The registers are lww_register_t-backed here, and data_item_destroy's
  // default arm would free only the struct shell (pre-existing destroy gap —
  // no register case). Destroy the values explicitly, then the states.
  lww_register_t* dst_reg = (lww_register_t*)state_find_item(dst, "vault")->value;
  state_find_item(dst, "vault")->value = nullptr;
  lww_register_destroy(dst_reg);
  lww_register_t* src_reg = (lww_register_t*)state_find_item(src, "vault")->value;
  state_find_item(src, "vault")->value = nullptr;
  lww_register_destroy(src_reg);
  state_destroy(dst);
  state_destroy(src);
}

// SOVEREIGN: equal seq + different content (hence different content-derived
// head) is a fork — neither side's content applies, the fork sets union
// monotonically, the writer is convicted, and a merge change event surfaces
// the divergence.
TEST(TestCRDTMerge, TestSovereignMergeForkUnionsEvidenceWithoutOverwriting) {
  state_t* dst = state_create();
  state_t* src = state_create();
  merge_event_capture_t capture = {};
  state_set_change_hook(dst, _merge_event_hook, &capture);

  data_item_t* dst_item = _make_sovereign_counter("vault", "alice", 4, 3);
  data_item_t* src_item = _make_sovereign_counter("vault", "alice", 4, 99);
  ASSERT_NE(dst_item, nullptr);
  ASSERT_NE(src_item, nullptr);
  uint8_t dst_digest[CRABS_HASH_SIZE];
  memcpy(dst_digest, dst_item->item_digest, CRABS_HASH_SIZE);
  // src carries prior quarantine evidence for another writer — unioned in.
  uint8_t prior_evidence[CRABS_HASH_SIZE];
  memset(prior_evidence, 0xE1, sizeof(prior_evidence));
  EXPECT_EQ(state_append_fork_evidence(src_item, "mallory", prior_evidence),
            CRABS_SUCCESS);
  state_add_item(dst, dst_item);
  state_add_item(src, src_item);

  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);

  data_item_t* merged = state_find_item(dst, "vault");
  ASSERT_NE(merged, nullptr);
  // content NOT overwritten by the forking side
  EXPECT_EQ(g_counter_value((g_counter_t*)merged->value), 3);
  EXPECT_EQ(merged->item_seq, 4u);
  EXPECT_EQ(memcmp(merged->item_digest, dst_digest, CRABS_HASH_SIZE), 0);
  // fork set: the forking writer convicted + src's prior evidence unioned
  EXPECT_TRUE(state_item_is_quarantined(merged, "alice"));
  EXPECT_TRUE(state_item_is_quarantined(merged, "mallory"));
  EXPECT_EQ(merged->fork_count, 2u);
  // event surfaced the divergence
  ASSERT_EQ(capture.calls, 1);
  EXPECT_EQ(capture.kind, CRABS_CHANGE_MERGE);
  EXPECT_STREQ(capture.type, "__merge_fork__");
  EXPECT_STREQ(capture.target, "vault");
  EXPECT_EQ(capture.result, CRABS_ERR_FORK_DETECTED);

  // re-merging the same src is idempotent in evidence (no fork-set growth)
  // but surfaces the fork event again — the divergence persists until the
  // application resolves it, so every merge with the forking replica fires.
  merge_event_capture_t second_capture = {};
  state_set_change_hook(dst, _merge_event_hook, &second_capture);
  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);
  merged = state_find_item(dst, "vault");
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(merged->fork_count, 2u);
  EXPECT_EQ(g_counter_value((g_counter_t*)merged->value), 3);
  ASSERT_EQ(second_capture.calls, 1);
  EXPECT_EQ(second_capture.result, CRABS_ERR_FORK_DETECTED);

  _destroy_state_values(dst);
  _destroy_state_values(src);
  state_destroy(dst);
  state_destroy(src);
}

// SOVEREIGN: the same item name with a different writer is creation-immutable
// lineage corruption — keep item_a's content and surface an event.
TEST(TestCRDTMerge, TestSovereignMergeWriterMismatchHeld) {
  state_t* dst = state_create();
  state_t* src = state_create();
  merge_event_capture_t capture = {};
  state_set_change_hook(dst, _merge_event_hook, &capture);

  data_item_t* dst_item = _make_sovereign_counter("vault", "alice", 1, 5);
  data_item_t* src_item = _make_sovereign_counter("vault", "eve", 9, 50);
  ASSERT_NE(dst_item, nullptr);
  ASSERT_NE(src_item, nullptr);
  state_add_item(dst, dst_item);
  state_add_item(src, src_item);

  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);

  data_item_t* merged = state_find_item(dst, "vault");
  ASSERT_NE(merged, nullptr);
  EXPECT_STREQ(merged->writer, "alice");
  EXPECT_EQ(g_counter_value((g_counter_t*)merged->value), 5);
  EXPECT_EQ(merged->item_seq, 1u);
  ASSERT_EQ(capture.calls, 1);
  EXPECT_EQ(capture.kind, CRABS_CHANGE_MERGE);
  EXPECT_STREQ(capture.type, "__merge_writer_mismatch__");
  EXPECT_EQ(capture.result, CRABS_ERR_PROTOCOL_VIOLATION);

  _destroy_state_values(dst);
  _destroy_state_values(src);
  state_destroy(dst);
  state_destroy(src);
}

// SOVEREIGN: an ahead snapshot whose value cannot be deep-copied (unsupported
// CRDT type) must NOT split content from chain head: item_a is kept whole and
// a hold event fires. The items are hand-built wire-shapes: the validating
// creation path (data_item_create_with_options) now rejects a non-canonical
// (type, crdt_type) pair outright, so REGISTER tagged CRDT_RGA can only
// arrive off the wire. The carried digests are opaque seeds — this branch
// holds on the value deep-copy failure BEFORE any digest comparison, so the
// heads never enter the rule.
TEST(TestCRDTMerge, TestSovereignMergeAheadWithUndigestableValueHeld) {
  state_t* dst = state_create();
  state_t* src = state_create();
  merge_event_capture_t capture = {};
  state_set_change_hook(dst, _merge_event_hook, &capture);

  data_item_t* dst_item = data_item_create("vault", DATA_TYPE_REGISTER, CRDT_RGA);
  ASSERT_NE(dst_item, nullptr);
  dst_item->write_domain = CRABS_DOMAIN_SOVEREIGN;
  strncpy(dst_item->writer, "alice", CRABS_MAX_USER_ID - 1);
  // Values with NULL payloads: crdt_value_destroy's default arm only frees
  // the wrapper for CRDT_RGA, so keep them payload-less to avoid a leak.
  dst_item->value = lww_register_create(nullptr, 0, 1, "nodeA");
  dst_item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  dst_item->item_seq = 2;
  memset(dst_item->item_digest, 0x02, CRABS_HASH_SIZE);
  ASSERT_EQ(state_add_item(dst, dst_item), CRABS_SUCCESS);

  data_item_t* src_item = data_item_create("vault", DATA_TYPE_REGISTER, CRDT_RGA);
  ASSERT_NE(src_item, nullptr);
  src_item->write_domain = CRABS_DOMAIN_SOVEREIGN;
  strncpy(src_item->writer, "alice", CRABS_MAX_USER_ID - 1);
  src_item->value = lww_register_create(nullptr, 0, 2, "nodeA");
  src_item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  src_item->item_seq = 5;
  memset(src_item->item_digest, 0x05, CRABS_HASH_SIZE);
  ASSERT_EQ(state_add_item(src, src_item), CRABS_SUCCESS);

  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);

  data_item_t* merged = state_find_item(dst, "vault");
  ASSERT_NE(merged, nullptr);
  // head NOT adopted: seq/digest/value all stay item_a's
  EXPECT_EQ(merged->item_seq, 2u);
  lww_register_t* merged_reg = (lww_register_t*)merged->value;
  ASSERT_NE(merged_reg, nullptr);
  EXPECT_EQ(merged_reg->timestamp, 1u);
  ASSERT_EQ(capture.calls, 1);
  EXPECT_EQ(capture.kind, CRABS_CHANGE_MERGE);
  EXPECT_STREQ(capture.type, "__merge_held__");
  EXPECT_EQ(capture.result, CRABS_ERR_PROTOCOL_VIOLATION);

  _destroy_state_values(dst);
  _destroy_state_values(src);
  state_destroy(dst);
  state_destroy(src);
}

// SOVEREIGN: a same-named item of a different type/crdt_type is corrupted
// lineage — merging values across shapes would cast across incompatible
// structs, so item_a is held whole and an event fires.
TEST(TestCRDTMerge, TestSovereignMergeTypeMismatchHeld) {
  state_t* dst = state_create();
  state_t* src = state_create();
  merge_event_capture_t capture = {};
  state_set_change_hook(dst, _merge_event_hook, &capture);

  data_item_t* dst_item = _make_sovereign_counter("vault", "alice", 2, 7);
  ASSERT_NE(dst_item, nullptr);
  state_add_item(dst, dst_item);

  // Same name, same domain, same writer — but a register, not a counter.
  data_item_options_t src_options;
  memset(&src_options, 0, sizeof(src_options));
  src_options.write_domain = CRABS_DOMAIN_SOVEREIGN;
  src_options.writer = "alice";
  data_item_t* src_item = nullptr;
  ASSERT_EQ(data_item_create_with_options("vault", DATA_TYPE_REGISTER,
                                          CRDT_LWW_REG, &src_options,
                                          &src_item),
            CRABS_SUCCESS);
  src_item->item_seq = 9;
  state_add_item(src, src_item);

  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);

  data_item_t* merged = state_find_item(dst, "vault");
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(merged->item_seq, 2u);
  EXPECT_EQ(g_counter_value((g_counter_t*)merged->value), 7);
  ASSERT_EQ(capture.calls, 1);
  EXPECT_EQ(capture.kind, CRABS_CHANGE_MERGE);
  EXPECT_STREQ(capture.type, "__merge_type_mismatch__");
  EXPECT_EQ(capture.result, CRABS_ERR_PROTOCOL_VIOLATION);

  _destroy_state_values(dst);
  _destroy_state_values(src);
  state_destroy(dst);
  state_destroy(src);
}

// GROUP_ORDERED (v1, no modules): any content divergence is held — keep
// item_a and surface a held-divergence event; identical items are a no-op.
TEST(TestCRDTMerge, TestGroupOrderedMergeHoldsDivergence) {
  state_t* dst = state_create();
  state_t* src = state_create();
  merge_event_capture_t capture = {};
  state_set_change_hook(dst, _merge_event_hook, &capture);

  data_item_t* dst_item = _make_group_register("council", "alpha");
  data_item_t* src_item = _make_group_register("council", "beta");
  ASSERT_NE(dst_item, nullptr);
  ASSERT_NE(src_item, nullptr);
  state_add_item(dst, dst_item);
  state_add_item(src, src_item);

  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);

  data_item_t* merged = state_find_item(dst, "council");
  ASSERT_NE(merged, nullptr);
  // item_a's content kept; the held side did not overwrite
  lww_register_t* merged_reg = (lww_register_t*)merged->value;
  ASSERT_NE(merged_reg, nullptr);
  EXPECT_EQ(memcmp(merged_reg->value, "alpha", 5), 0);
  ASSERT_EQ(capture.calls, 1);
  EXPECT_EQ(capture.kind, CRABS_CHANGE_MERGE);
  EXPECT_STREQ(capture.type, "__merge_held__");
  EXPECT_STREQ(capture.target, "council");
  EXPECT_EQ(capture.result, CRABS_ERR_ORDERING_PATH);

  _destroy_state_values(dst);
  _destroy_state_values(src);
  state_destroy(dst);
  state_destroy(src);
}

TEST(TestCRDTMerge, TestGroupOrderedMergeIdenticalNoOp) {
  state_t* dst = state_create();
  state_t* src = state_create();
  merge_event_capture_t capture = {};
  state_set_change_hook(dst, _merge_event_hook, &capture);

  data_item_t* dst_item = _make_group_register("council", nullptr);
  data_item_t* src_item = _make_group_register("council", nullptr);
  ASSERT_NE(dst_item, nullptr);
  ASSERT_NE(src_item, nullptr);
  state_add_item(dst, dst_item);
  state_add_item(src, src_item);

  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);

  data_item_t* merged = state_find_item(dst, "council");
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(merged->value, nullptr);
  EXPECT_EQ(capture.calls, 0);

  _destroy_state_values(dst);
  _destroy_state_values(src);
  state_destroy(dst);
  state_destroy(src);
}