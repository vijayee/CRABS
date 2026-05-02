#include <gtest/gtest.h>
extern "C" {
#include "../src/Condition/condition.h"
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/CRDT/crdt_merge.h"
}

// ============================================================
// Test Fixture
// ============================================================
class TestCondition : public ::testing::Test {
protected:
  state_t* state;

  void SetUp() override {
    state = state_create();

    // Add a counter item "video_abc" with value 10
    data_item_t* flags = data_item_create("video_abc", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
    g_counter_t* gc = g_counter_create();
    g_counter_increment(gc, "nodeA", 10);
    flags->value = gc;
    state_add_item(state, flags);

    // Add a counter item "views" with value 1000
    data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
    g_counter_t* views_gc = g_counter_create();
    g_counter_increment(views_gc, "nodeA", 1000);
    views->value = views_gc;
    state_add_item(state, views);

    // Add a PN-counter item "user_alice" with value -50
    data_item_t* rep = data_item_create("user_alice", DATA_TYPE_PN_COUNTER, CRDT_PN_COUNTER);
    pn_counter_t* pnc = pn_counter_create();
    pn_counter_increment(pnc, "nodeA", 10);
    pn_counter_decrement(pnc, "nodeA", 60);
    rep->value = pnc;
    state_add_item(state, rep);

    // Add an OR-Set item "course_enrolled" with {"alice", "bob"}
    data_item_t* enrolled = data_item_create("course_enrolled", DATA_TYPE_SET, CRDT_OR_SET);
    or_set_t* enrolled_set = or_set_create();
    or_set_add(enrolled_set, "alice", "nodeA:1");
    or_set_add(enrolled_set, "bob", "nodeA:2");
    enrolled->value = enrolled_set;
    state_add_item(state, enrolled);

    // Add a 2P-Set item "mod_queue" with {"video_abc", "video_def"}
    data_item_t* mod_queue = data_item_create("mod_queue", DATA_TYPE_SET, CRDT_2P_SET);
    two_p_set_t* mq_set = two_p_set_create();
    two_p_set_add(mq_set, "video_abc");
    two_p_set_add(mq_set, "video_def");
    mod_queue->value = mq_set;
    state_add_item(state, mod_queue);

    // Add a counter for BETWEEN tests
    data_item_t* likes = data_item_create("likes", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
    g_counter_t* likes_gc = g_counter_create();
    g_counter_increment(likes_gc, "nodeA", 500);
    likes->value = likes_gc;
    state_add_item(state, likes);
  }

  void TearDown() override {
    // Free CRDT struct values manually since data_item_destroy uses free()
    // which doesn't clean up internal CRDT allocations
    for (data_item_t* item = state->items; item != NULL; item = item->next) {
      if (item->value != NULL) {
        crdt_value_destroy(item->crdt_type, item->value);
        item->value = NULL;
      }
    }
    state_destroy(state);
  }
};

// ============================================================
// Parser Tests
// ============================================================

TEST_F(TestCondition, TestParseSimpleComparison) {
  condition_node_t* node = condition_parse("video_abc >= 10");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_COMPARISON);
  EXPECT_STREQ(node->left_path, "video_abc");
  EXPECT_EQ(node->cmp_operator, CMP_GE);
  EXPECT_EQ(node->right_literal, 10);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseLessThan) {
  condition_node_t* node = condition_parse("video_abc < 5");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_COMPARISON);
  EXPECT_EQ(node->cmp_operator, CMP_LT);
  EXPECT_EQ(node->right_literal, 5);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseEqual) {
  condition_node_t* node = condition_parse("video_abc == 10");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_COMPARISON);
  EXPECT_EQ(node->cmp_operator, CMP_EQ);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseNotEqual) {
  condition_node_t* node = condition_parse("video_abc != 10");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_COMPARISON);
  EXPECT_EQ(node->cmp_operator, CMP_NE);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseLessEqual) {
  condition_node_t* node = condition_parse("video_abc <= 10");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_COMPARISON);
  EXPECT_EQ(node->cmp_operator, CMP_LE);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseNegativeNumber) {
  condition_node_t* node = condition_parse("user_alice < -50");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_COMPARISON);
  EXPECT_EQ(node->cmp_operator, CMP_LT);
  EXPECT_EQ(node->right_literal, -50);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseAndCondition) {
  condition_node_t* node = condition_parse("video_abc >= 10 AND views >= 1000");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_AND);
  EXPECT_NE(node->left, nullptr);
  EXPECT_NE(node->right, nullptr);
  EXPECT_EQ(node->left->type, NODE_COMPARISON);
  EXPECT_EQ(node->right->type, NODE_COMPARISON);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseOrCondition) {
  condition_node_t* node = condition_parse("video_abc >= 10 OR views >= 1000");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_OR);
  EXPECT_NE(node->left, nullptr);
  EXPECT_NE(node->right, nullptr);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseParenthesizedCondition) {
  condition_node_t* node = condition_parse("(video_abc >= 10 OR views >= 1000) AND user_alice < 0");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_AND);
  EXPECT_NE(node->left, nullptr);
  EXPECT_NE(node->right, nullptr);
  EXPECT_EQ(node->left->type, NODE_OR);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseBetween) {
  condition_node_t* node = condition_parse("likes BETWEEN 100 AND 1000");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_COMPARISON);
  EXPECT_EQ(node->cmp_operator, CMP_BETWEEN);
  EXPECT_EQ(node->right_literal, 100);
  EXPECT_EQ(node->right_literal_2, 1000);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseInList) {
  condition_node_t* node = condition_parse("video_abc IN (10, 20, 30)");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_COMPARISON);
  EXPECT_EQ(node->cmp_operator, CMP_IN);
  EXPECT_EQ(node->element_count, 3u);
  EXPECT_STREQ(node->element_values[0], "10");
  EXPECT_STREQ(node->element_values[1], "20");
  EXPECT_STREQ(node->element_values[2], "30");
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseContains) {
  condition_node_t* node = condition_parse("course_enrolled CONTAINS alice");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_CONTAINS);
  EXPECT_STREQ(node->set_path, "course_enrolled");
  EXPECT_EQ(node->contains_type, CONTAINS_SINGLE);
  EXPECT_EQ(node->negated, false);
  EXPECT_EQ(node->element_count, 1u);
  EXPECT_STREQ(node->element_values[0], "alice");
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseContainsAny) {
  condition_node_t* node = condition_parse("mod_queue CONTAINS_ANY (video_abc, video_ghi)");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_CONTAINS);
  EXPECT_EQ(node->contains_type, CONTAINS_ANY);
  EXPECT_EQ(node->element_count, 2u);
  EXPECT_STREQ(node->element_values[0], "video_abc");
  EXPECT_STREQ(node->element_values[1], "video_ghi");
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseContainsAll) {
  condition_node_t* node = condition_parse("course_enrolled CONTAINS_ALL (alice, bob)");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_CONTAINS);
  EXPECT_EQ(node->contains_type, CONTAINS_ALL);
  EXPECT_EQ(node->element_count, 2u);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseNegatedContains) {
  condition_node_t* node = condition_parse("course_enrolled NOT CONTAINS carol");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_CONTAINS);
  EXPECT_EQ(node->contains_type, CONTAINS_SINGLE);
  EXPECT_EQ(node->negated, true);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseNegatedContainsAny) {
  condition_node_t* node = condition_parse("mod_queue NOT CONTAINS_ANY (video_abc, video_def)");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_CONTAINS);
  EXPECT_EQ(node->contains_type, CONTAINS_ANY);
  EXPECT_EQ(node->negated, true);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseNegatedContainsAll) {
  condition_node_t* node = condition_parse("course_enrolled NOT CONTAINS_ALL (alice, dave)");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_CONTAINS);
  EXPECT_EQ(node->contains_type, CONTAINS_ALL);
  EXPECT_EQ(node->negated, true);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseValueInPath) {
  // "alice IN course_enrolled" → CONTAINS node
  condition_node_t* node = condition_parse("alice IN course_enrolled");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_CONTAINS);
  EXPECT_STREQ(node->set_path, "course_enrolled");
  EXPECT_EQ(node->contains_type, CONTAINS_SINGLE);
  EXPECT_EQ(node->negated, false);
  EXPECT_EQ(node->element_count, 1u);
  EXPECT_STREQ(node->element_values[0], "alice");
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseValueNotInPath) {
  // "alice NOT IN course_enrolled" → negated CONTAINS node
  condition_node_t* node = condition_parse("alice NOT IN course_enrolled");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_CONTAINS);
  EXPECT_EQ(node->contains_type, CONTAINS_SINGLE);
  EXPECT_EQ(node->negated, true);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseStringLiteral) {
  condition_node_t* node = condition_parse("video_abc >= 10");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_COMPARISON);
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseQuotedString) {
  condition_node_t* node = condition_parse("course_enrolled CONTAINS \"alice\"");
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_CONTAINS);
  EXPECT_STREQ(node->element_values[0], "alice");
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestParseInvalidExpression) {
  condition_node_t* node = condition_parse("");
  EXPECT_EQ(node, nullptr);

  node = condition_parse(NULL);
  EXPECT_EQ(node, nullptr);
}

TEST_F(TestCondition, TestParseComplexExpression) {
  condition_node_t* node = condition_parse(
    "video_abc >= 10 AND (course_enrolled CONTAINS alice OR mod_queue CONTAINS_ANY (video_abc, video_def))"
  );
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->type, NODE_AND);
  EXPECT_NE(node->left, nullptr);
  EXPECT_NE(node->right, nullptr);
  condition_node_destroy(node);
}

// ============================================================
// Evaluation Tests
// ============================================================

TEST_F(TestCondition, TestEvaluateComparisonTrue) {
  condition_node_t* node = condition_parse("video_abc >= 10");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateComparisonFalse) {
  condition_node_t* node = condition_parse("video_abc >= 20");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateEqual) {
  condition_node_t* node = condition_parse("video_abc == 10");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateNotEqual) {
  condition_node_t* node = condition_parse("video_abc != 5");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateLessThan) {
  condition_node_t* node = condition_parse("video_abc < 20");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  node = condition_parse("video_abc < 5");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateLessEqual) {
  condition_node_t* node = condition_parse("video_abc <= 10");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  node = condition_parse("video_abc <= 5");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateGreaterThan) {
  condition_node_t* node = condition_parse("video_abc > 5");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateAndCondition) {
  condition_node_t* node = condition_parse("video_abc >= 10 AND views >= 1000");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  node = condition_parse("video_abc >= 10 AND views >= 2000");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateOrCondition) {
  condition_node_t* node = condition_parse("video_abc >= 20 OR views >= 1000");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  node = condition_parse("video_abc >= 20 OR views >= 2000");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateBetween) {
  condition_node_t* node = condition_parse("likes BETWEEN 100 AND 1000");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  // likes = 500, should be outside [600, 1000]
  node = condition_parse("likes BETWEEN 600 AND 1000");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateBetweenInclusive) {
  // likes = 500, test that BETWEEN is inclusive on both ends
  condition_node_t* node = condition_parse("likes BETWEEN 500 AND 500");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateInList) {
  condition_node_t* node = condition_parse("video_abc IN (5, 10, 15)");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  node = condition_parse("video_abc IN (1, 2, 3)");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateContainsORSet) {
  condition_node_t* node = condition_parse("course_enrolled CONTAINS alice");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  node = condition_parse("course_enrolled CONTAINS carol");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateContains2PSet) {
  condition_node_t* node = condition_parse("mod_queue CONTAINS video_abc");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  node = condition_parse("mod_queue CONTAINS video_ghi");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateContainsAny) {
  condition_node_t* node = condition_parse("mod_queue CONTAINS_ANY (video_abc, video_ghi)");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  node = condition_parse("mod_queue CONTAINS_ANY (video_ghi, video_jkl)");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateContainsAll) {
  condition_node_t* node = condition_parse("course_enrolled CONTAINS_ALL (alice, bob)");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  node = condition_parse("course_enrolled CONTAINS_ALL (alice, dave)");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateNegatedContains) {
  condition_node_t* node = condition_parse("course_enrolled NOT CONTAINS carol");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  node = condition_parse("course_enrolled NOT CONTAINS alice");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateNegatedContainsAny) {
  condition_node_t* node = condition_parse("mod_queue NOT CONTAINS_ANY (video_ghi, video_jkl)");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  node = condition_parse("mod_queue NOT CONTAINS_ANY (video_abc, video_ghi)");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateNegatedContainsAll) {
  condition_node_t* node = condition_parse("course_enrolled NOT CONTAINS_ALL (alice, dave)");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateValueInPath) {
  // "alice IN course_enrolled" → CONTAINS node
  condition_node_t* node = condition_parse("alice IN course_enrolled");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateValueNotInPath) {
  condition_node_t* node = condition_parse("carol IN course_enrolled");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluateValueNotInPathNegated) {
  condition_node_t* node = condition_parse("carol NOT IN course_enrolled");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  node = condition_parse("alice NOT IN course_enrolled");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

// ============================================================
// Path Resolution Tests
// ============================================================

TEST_F(TestCondition, TestResolvePath) {
  int64_t value = condition_resolve_path(state, "video_abc");
  EXPECT_EQ(value, 10);

  value = condition_resolve_path(state, "views");
  EXPECT_EQ(value, 1000);

  value = condition_resolve_path(state, "user_alice");
  EXPECT_EQ(value, -50);

  value = condition_resolve_path(state, "nonexistent");
  EXPECT_EQ(value, 0);
}

TEST_F(TestCondition, TestResolvePathNull) {
  int64_t value = condition_resolve_path(NULL, "video_abc");
  EXPECT_EQ(value, 0);

  value = condition_resolve_path(state, NULL);
  EXPECT_EQ(value, 0);
}

// ============================================================
// Node Creation/Destroy Tests
// ============================================================

TEST_F(TestCondition, TestNodeCreateDestroy) {
  condition_node_t* cmp = condition_node_create_comparison("test_path", CMP_GE, 42);
  ASSERT_NE(cmp, nullptr);
  EXPECT_EQ(cmp->type, NODE_COMPARISON);
  EXPECT_STREQ(cmp->left_path, "test_path");
  EXPECT_EQ(cmp->cmp_operator, CMP_GE);
  EXPECT_EQ(cmp->right_literal, 42);
  condition_node_destroy(cmp);

  condition_node_t* left = condition_node_create_comparison("a", CMP_GT, 0);
  condition_node_t* right = condition_node_create_comparison("b", CMP_LT, 0);
  condition_node_t* and_node = condition_node_create_and(left, right);
  ASSERT_NE(and_node, nullptr);
  EXPECT_EQ(and_node->type, NODE_AND);
  EXPECT_EQ(and_node->left, left);
  EXPECT_EQ(and_node->right, right);
  condition_node_destroy(and_node);

  left = condition_node_create_comparison("a", CMP_GT, 0);
  right = condition_node_create_comparison("b", CMP_LT, 0);
  condition_node_t* or_node = condition_node_create_or(left, right);
  ASSERT_NE(or_node, nullptr);
  EXPECT_EQ(or_node->type, NODE_OR);
  condition_node_destroy(or_node);

  char* values[] = {(char*)"alice", (char*)"bob"};
  condition_node_t* contains = condition_node_create_contains("course_enrolled", CONTAINS_ALL, false, values, 2);
  ASSERT_NE(contains, nullptr);
  EXPECT_EQ(contains->type, NODE_CONTAINS);
  EXPECT_STREQ(contains->set_path, "course_enrolled");
  EXPECT_EQ(contains->contains_type, CONTAINS_ALL);
  EXPECT_EQ(contains->negated, false);
  EXPECT_EQ(contains->element_count, 2u);
  condition_node_destroy(contains);
}

TEST_F(TestCondition, TestNodeDestroyNull) {
  condition_node_destroy(nullptr);
  // Should not crash
}

// ============================================================
// Combined Condition Tests
// ============================================================

TEST_F(TestCondition, TestEvaluateCombinedContainsAndComparison) {
  // course_enrolled CONTAINS alice AND video_abc >= 10
  condition_node_t* node = condition_parse("course_enrolled CONTAINS alice AND video_abc >= 10");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  // course_enrolled CONTAINS alice AND video_abc < 5
  node = condition_parse("course_enrolled CONTAINS alice AND video_abc < 5");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

TEST_F(TestCondition, TestEvaluatePNCounter) {
  condition_node_t* node = condition_parse("user_alice < -40");
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(condition_evaluate(node, state));
  condition_node_destroy(node);

  node = condition_parse("user_alice < -60");
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(condition_evaluate(node, state));
  condition_node_destroy(node);
}

// ============================================================
// Policy Pre-processing Tests (Amendment 2 §5)
// ============================================================

TEST_F(TestCondition, TestPreprocessPolicyNoContains) {
  auto result = preprocess_policy("video_abc >= 5", state, "alice");
  EXPECT_TRUE(result.resolved_ok);
  EXPECT_STRNE(result.abe_policy, "");
}

TEST_F(TestCondition, TestPreprocessPolicyContainsOnly) {
  auto result = preprocess_policy("course_enrolled CONTAINS alice", state, "alice");
  EXPECT_TRUE(result.resolved_ok);
  EXPECT_STREQ(result.abe_policy, "");
}

TEST_F(TestCondition, TestPreprocessPolicyContainsAndABE) {
  auto result = preprocess_policy("course_enrolled CONTAINS alice AND video_abc >= 5", state, "alice");
  EXPECT_TRUE(result.resolved_ok);
  EXPECT_STRNE(result.abe_policy, "");
}

TEST_F(TestCondition, TestPreprocessPolicyContainsFails) {
  auto result = preprocess_policy("course_enrolled CONTAINS carol AND video_abc >= 5", state, "alice");
  EXPECT_FALSE(result.resolved_ok);
}

TEST_F(TestCondition, TestPreprocessPolicyUserIdPlaceholder) {
  // {user_id} placeholder is resolved before evaluation
  auto result = preprocess_policy("course_enrolled CONTAINS alice", state, "alice");
  EXPECT_TRUE(result.resolved_ok);

  // Test that placeholder resolves correctly
  auto result2 = preprocess_policy("mod_queue CONTAINS video_abc", state, "alice");
  EXPECT_TRUE(result2.resolved_ok);
}

TEST_F(TestCondition, TestPreprocessPolicyNullInput) {
  auto result = preprocess_policy(NULL, state, "alice");
  EXPECT_TRUE(result.resolved_ok);
  EXPECT_STREQ(result.abe_policy, "");

  result = preprocess_policy("", state, "alice");
  EXPECT_TRUE(result.resolved_ok);
  EXPECT_STREQ(result.abe_policy, "");
}

TEST_F(TestCondition, TestPreprocessPolicyContainsNot) {
  auto result = preprocess_policy("course_enrolled NOT CONTAINS carol", state, "alice");
  EXPECT_TRUE(result.resolved_ok);
}