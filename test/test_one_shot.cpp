#include <gtest/gtest.h>
extern "C" {
#include "../src/CRDT/one_shot.h"
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/CRDT/crdt_merge.h"
}

// ============================================================
// ONE_SHOT_SET tests
// ============================================================

TEST(OneShotSet, CreateDestroy) {
  one_shot_set_t* set = one_shot_set_create();
  ASSERT_NE(set, nullptr);
  EXPECT_EQ(set->element_count, (uint32_t)0);
  EXPECT_EQ(set->elements, nullptr);
  one_shot_set_destroy(set);
}

TEST(OneShotSet, CreateDestroyNull) {
  one_shot_set_destroy(NULL);
}

TEST(OneShotSet, AddAndContains) {
  one_shot_set_t* set = one_shot_set_create();
  ASSERT_NE(set, nullptr);

  EXPECT_EQ(one_shot_set_add(set, "alice"), CRABS_SUCCESS);
  EXPECT_EQ(one_shot_set_add(set, "bob"), CRABS_SUCCESS);
  EXPECT_EQ(one_shot_set_add(set, "charlie"), CRABS_SUCCESS);

  EXPECT_TRUE(one_shot_set_contains(set, "alice"));
  EXPECT_TRUE(one_shot_set_contains(set, "bob"));
  EXPECT_TRUE(one_shot_set_contains(set, "charlie"));
  EXPECT_FALSE(one_shot_set_contains(set, "dave"));

  EXPECT_EQ(one_shot_set_count(set), (uint32_t)3);

  one_shot_set_destroy(set);
}

TEST(OneShotSet, AddIsIdempotent) {
  one_shot_set_t* set = one_shot_set_create();
  ASSERT_NE(set, nullptr);

  EXPECT_EQ(one_shot_set_add(set, "alice"), CRABS_SUCCESS);
  EXPECT_EQ(one_shot_set_count(set), (uint32_t)1);

  // Adding same element again is idempotent
  EXPECT_EQ(one_shot_set_add(set, "alice"), CRABS_SUCCESS);
  EXPECT_EQ(one_shot_set_count(set), (uint32_t)1);

  one_shot_set_destroy(set);
}

TEST(OneShotSet, AddNullParams) {
  one_shot_set_t* set = one_shot_set_create();
  EXPECT_EQ(one_shot_set_add(NULL, "alice"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(one_shot_set_add(set, NULL), CRABS_ERR_INVALID_PARAM);
  one_shot_set_destroy(set);
}

TEST(OneShotSet, ContainsNullParams) {
  EXPECT_FALSE(one_shot_set_contains(NULL, "alice"));
  one_shot_set_t* set = one_shot_set_create();
  EXPECT_FALSE(one_shot_set_contains(set, NULL));
  one_shot_set_destroy(set);
}

TEST(OneShotSet, CountNull) {
  EXPECT_EQ(one_shot_set_count(NULL), (uint32_t)0);
}

TEST(OneShotSet, MergeBothNonNull) {
  one_shot_set_t* a = one_shot_set_create();
  one_shot_set_t* b = one_shot_set_create();

  one_shot_set_add(a, "alice");
  one_shot_set_add(a, "bob");

  one_shot_set_add(b, "bob");
  one_shot_set_add(b, "charlie");

  one_shot_set_t* merged = one_shot_set_merge(a, b);
  ASSERT_NE(merged, nullptr);

  // Union: alice, bob, charlie
  EXPECT_TRUE(one_shot_set_contains(merged, "alice"));
  EXPECT_TRUE(one_shot_set_contains(merged, "bob"));
  EXPECT_TRUE(one_shot_set_contains(merged, "charlie"));
  EXPECT_EQ(one_shot_set_count(merged), (uint32_t)3);

  one_shot_set_destroy(a);
  one_shot_set_destroy(b);
  one_shot_set_destroy(merged);
}

TEST(OneShotSet, MergeWithNull) {
  one_shot_set_t* a = one_shot_set_create();
  one_shot_set_add(a, "alice");

  one_shot_set_t* merged1 = one_shot_set_merge(a, NULL);
  ASSERT_NE(merged1, nullptr);
  EXPECT_TRUE(one_shot_set_contains(merged1, "alice"));
  EXPECT_EQ(one_shot_set_count(merged1), (uint32_t)1);

  one_shot_set_t* merged2 = one_shot_set_merge(NULL, a);
  ASSERT_NE(merged2, nullptr);
  EXPECT_TRUE(one_shot_set_contains(merged2, "alice"));

  one_shot_set_t* merged3 = one_shot_set_merge(NULL, NULL);
  EXPECT_EQ(merged3, nullptr);

  one_shot_set_destroy(a);
  one_shot_set_destroy(merged1);
  one_shot_set_destroy(merged2);
}

TEST(OneShotSet, MergeEmptySets) {
  one_shot_set_t* a = one_shot_set_create();
  one_shot_set_t* b = one_shot_set_create();

  one_shot_set_t* merged = one_shot_set_merge(a, b);
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(one_shot_set_count(merged), (uint32_t)0);

  one_shot_set_destroy(a);
  one_shot_set_destroy(b);
  one_shot_set_destroy(merged);
}

TEST(OneShotSet, MergeIsCommutative) {
  one_shot_set_t* a = one_shot_set_create();
  one_shot_set_t* b = one_shot_set_create();

  one_shot_set_add(a, "alice");
  one_shot_set_add(b, "bob");

  one_shot_set_t* ab = one_shot_set_merge(a, b);
  one_shot_set_t* ba = one_shot_set_merge(b, a);

  EXPECT_EQ(one_shot_set_count(ab), one_shot_set_count(ba));
  EXPECT_TRUE(one_shot_set_contains(ab, "alice"));
  EXPECT_TRUE(one_shot_set_contains(ab, "bob"));
  EXPECT_TRUE(one_shot_set_contains(ba, "alice"));
  EXPECT_TRUE(one_shot_set_contains(ba, "bob"));

  one_shot_set_destroy(a);
  one_shot_set_destroy(b);
  one_shot_set_destroy(ab);
  one_shot_set_destroy(ba);
}

// ============================================================
// ONE_SHOT_FLAG tests
// ============================================================

TEST(OneShotFlag, CreateDestroy) {
  one_shot_flag_t* flag = one_shot_flag_create();
  ASSERT_NE(flag, nullptr);
  EXPECT_FALSE(flag->value);
  EXPECT_EQ(flag->set_by[0], '\0');
  EXPECT_EQ(flag->set_at, (uint64_t)0);
  one_shot_flag_destroy(flag);
}

TEST(OneShotFlag, CreateDestroyNull) {
  one_shot_flag_destroy(NULL);
}

TEST(OneShotFlag, SetTransitionsToTrue) {
  one_shot_flag_t* flag = one_shot_flag_create();
  ASSERT_NE(flag, nullptr);

  EXPECT_FALSE(one_shot_flag_value(flag));

  EXPECT_EQ(one_shot_flag_set(flag, "alice", 1000), CRABS_SUCCESS);
  EXPECT_TRUE(one_shot_flag_value(flag));
  EXPECT_STREQ(flag->set_by, "alice");
  EXPECT_EQ(flag->set_at, (uint64_t)1000);

  one_shot_flag_destroy(flag);
}

TEST(OneShotFlag, SetIsIdempotent) {
  one_shot_flag_t* flag = one_shot_flag_create();
  ASSERT_NE(flag, nullptr);

  EXPECT_EQ(one_shot_flag_set(flag, "alice", 1000), CRABS_SUCCESS);
  EXPECT_TRUE(one_shot_flag_value(flag));

  // Second set should be no-op (already true)
  EXPECT_EQ(one_shot_flag_set(flag, "bob", 2000), CRABS_SUCCESS);
  EXPECT_TRUE(one_shot_flag_value(flag));
  // Original setter and timestamp should remain
  EXPECT_STREQ(flag->set_by, "alice");
  EXPECT_EQ(flag->set_at, (uint64_t)1000);

  one_shot_flag_destroy(flag);
}

TEST(OneShotFlag, SetNullParams) {
  one_shot_flag_t* flag = one_shot_flag_create();
  EXPECT_EQ(one_shot_flag_set(NULL, "alice", 1000), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(one_shot_flag_set(flag, NULL, 1000), CRABS_ERR_INVALID_PARAM);
  one_shot_flag_destroy(flag);
}

TEST(OneShotFlag, ValueNullFlag) {
  EXPECT_FALSE(one_shot_flag_value(NULL));
}

TEST(OneShotFlag, MergeBothFalse) {
  one_shot_flag_t* a = one_shot_flag_create();
  one_shot_flag_t* b = one_shot_flag_create();

  one_shot_flag_t* merged = one_shot_flag_merge(a, b);
  ASSERT_NE(merged, nullptr);
  EXPECT_FALSE(one_shot_flag_value(merged));

  one_shot_flag_destroy(a);
  one_shot_flag_destroy(b);
  one_shot_flag_destroy(merged);
}

TEST(OneShotFlag, MergeOneTrue) {
  one_shot_flag_t* a = one_shot_flag_create();
  one_shot_flag_t* b = one_shot_flag_create();
  one_shot_flag_set(a, "alice", 1000);

  // a=true, b=false
  one_shot_flag_t* merged1 = one_shot_flag_merge(a, b);
  ASSERT_NE(merged1, nullptr);
  EXPECT_TRUE(one_shot_flag_value(merged1));
  EXPECT_STREQ(merged1->set_by, "alice");
  EXPECT_EQ(merged1->set_at, (uint64_t)1000);

  // a=false, b=true
  one_shot_flag_t* c = one_shot_flag_create();
  one_shot_flag_t* d = one_shot_flag_create();
  one_shot_flag_set(d, "bob", 2000);

  one_shot_flag_t* merged2 = one_shot_flag_merge(c, d);
  ASSERT_NE(merged2, nullptr);
  EXPECT_TRUE(one_shot_flag_value(merged2));
  EXPECT_STREQ(merged2->set_by, "bob");
  EXPECT_EQ(merged2->set_at, (uint64_t)2000);

  one_shot_flag_destroy(a);
  one_shot_flag_destroy(b);
  one_shot_flag_destroy(c);
  one_shot_flag_destroy(d);
  one_shot_flag_destroy(merged1);
  one_shot_flag_destroy(merged2);
}

TEST(OneShotFlag, MergeBothTrueEarlierWins) {
  one_shot_flag_t* a = one_shot_flag_create();
  one_shot_flag_t* b = one_shot_flag_create();
  one_shot_flag_set(a, "alice", 1000);
  one_shot_flag_set(b, "bob", 2000);

  one_shot_flag_t* merged = one_shot_flag_merge(a, b);
  ASSERT_NE(merged, nullptr);
  EXPECT_TRUE(one_shot_flag_value(merged));
  // Earlier timestamp wins
  EXPECT_STREQ(merged->set_by, "alice");
  EXPECT_EQ(merged->set_at, (uint64_t)1000);

  one_shot_flag_destroy(a);
  one_shot_flag_destroy(b);
  one_shot_flag_destroy(merged);
}

TEST(OneShotFlag, MergeBothTrueSameTimestampLexicographic) {
  one_shot_flag_t* a = one_shot_flag_create();
  one_shot_flag_t* b = one_shot_flag_create();
  one_shot_flag_set(a, "bob", 1000);
  one_shot_flag_set(b, "alice", 1000);

  one_shot_flag_t* merged = one_shot_flag_merge(a, b);
  ASSERT_NE(merged, nullptr);
  EXPECT_TRUE(one_shot_flag_value(merged));
  // Same timestamp: lexicographic comparison, "alice" < "bob"
  EXPECT_STREQ(merged->set_by, "alice");
  EXPECT_EQ(merged->set_at, (uint64_t)1000);

  one_shot_flag_destroy(a);
  one_shot_flag_destroy(b);
  one_shot_flag_destroy(merged);
}

TEST(OneShotFlag, MergeWithNull) {
  one_shot_flag_t* a = one_shot_flag_create();
  one_shot_flag_set(a, "alice", 1000);

  one_shot_flag_t* merged1 = one_shot_flag_merge(a, NULL);
  ASSERT_NE(merged1, nullptr);
  EXPECT_TRUE(one_shot_flag_value(merged1));

  one_shot_flag_t* merged2 = one_shot_flag_merge(NULL, a);
  ASSERT_NE(merged2, nullptr);
  EXPECT_TRUE(one_shot_flag_value(merged2));

  one_shot_flag_t* merged3 = one_shot_flag_merge(NULL, NULL);
  EXPECT_EQ(merged3, nullptr);

  one_shot_flag_destroy(a);
  one_shot_flag_destroy(merged1);
  one_shot_flag_destroy(merged2);
}

// ============================================================
// CRDT merge dispatch tests
// ============================================================

TEST(OneShotCRDTDispatch, MergeValueOneShotSet) {
  one_shot_set_t* a = one_shot_set_create();
  one_shot_set_t* b = one_shot_set_create();
  one_shot_set_add(a, "alice");
  one_shot_set_add(b, "bob");

  void* result = crdt_merge_value(DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET,
                                   a, b, "node_a", "node_b");
  ASSERT_NE(result, nullptr);
  one_shot_set_t* merged = (one_shot_set_t*)result;
  EXPECT_TRUE(one_shot_set_contains(merged, "alice"));
  EXPECT_TRUE(one_shot_set_contains(merged, "bob"));
  EXPECT_EQ(one_shot_set_count(merged), (uint32_t)2);

  one_shot_set_destroy(a);
  one_shot_set_destroy(b);
  one_shot_set_destroy(merged);
}

TEST(OneShotCRDTDispatch, MergeValueOneShotFlag) {
  one_shot_flag_t* a = one_shot_flag_create();
  one_shot_flag_t* b = one_shot_flag_create();
  one_shot_flag_set(a, "alice", 1000);

  void* result = crdt_merge_value(DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG,
                                   a, b, "node_a", "node_b");
  ASSERT_NE(result, nullptr);
  one_shot_flag_t* merged = (one_shot_flag_t*)result;
  EXPECT_TRUE(one_shot_flag_value(merged));
  EXPECT_STREQ(merged->set_by, "alice");

  one_shot_flag_destroy(a);
  one_shot_flag_destroy(b);
  one_shot_flag_destroy(merged);
}

TEST(OneShotCRDTDispatch, MergeValueOneShotSetNull) {
  one_shot_set_t* a = one_shot_set_create();
  one_shot_set_add(a, "alice");

  void* result = crdt_merge_value(DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET,
                                   NULL, a, NULL, "node_b");
  ASSERT_NE(result, nullptr);
  one_shot_set_t* merged = (one_shot_set_t*)result;
  EXPECT_TRUE(one_shot_set_contains(merged, "alice"));

  one_shot_set_destroy(a);
  one_shot_set_destroy(merged);
}

TEST(OneShotCRDTDispatch, MergeValueBothNull) {
  void* result = crdt_merge_value(DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET,
                                   NULL, NULL, NULL, NULL);
  EXPECT_EQ(result, nullptr);

  result = crdt_merge_value(DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG,
                            NULL, NULL, NULL, NULL);
  EXPECT_EQ(result, nullptr);
}