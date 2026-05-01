#include <gtest/gtest.h>
extern "C" {
#include "../src/Dedup/dedup.h"
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/CRDT/one_shot.h"
}

// ============================================================
// DedupSpec enum tests
// ============================================================

TEST(DedupSpec, DedupTypeEnumValues) {
  EXPECT_EQ(DEDUP_NONE, (int)0x00);
  EXPECT_EQ(DEDUP_PER_USER, (int)0x01);
  EXPECT_EQ(DEDUP_GLOBAL, (int)0x02);
  EXPECT_EQ(DEDUP_CUSTOM, (int)0xFF);
}

TEST(DedupSpec, MutationTypeEnumValues) {
  EXPECT_EQ(MUTATION_SET_ADD, (int)0x01);
  EXPECT_EQ(MUTATION_FLAG_SET, (int)0x02);
  EXPECT_EQ(MUTATION_COUNTER_INCREMENT, (int)0x03);
  EXPECT_EQ(MUTATION_ASSIGN, (int)0x04);
  EXPECT_EQ(MUTATION_CUSTOM, (int)0xFF);
}

TEST(DedupSpec, ErrorCodes) {
  EXPECT_EQ(CRABS_ERR_ALREADY_PERFORMED, (int)0x7001);
  EXPECT_EQ(CRABS_ERR_ALREADY_EXECUTED, (int)0x7002);
  EXPECT_EQ(CRABS_ERR_CONDITION_NOT_MET, (int)0x7003);
  EXPECT_EQ(CRABS_ERR_TRACKER_NOT_FOUND, (int)0x7004);
  EXPECT_EQ(CRABS_ERR_FLAG_NOT_FOUND, (int)0x7005);
}

TEST(DedupSpec, OperationNames) {
  EXPECT_STREQ(CRABS_OP_DEFINE_OPERATION, "__define_operation_type__");
  EXPECT_STREQ(CRABS_OP_CHECK_DEDUP, "__check_dedup__");
}

// ============================================================
// DedupSpec struct tests
// ============================================================

TEST(DedupSpec, DefaultDedupIsNone) {
  operation_t* op = operation_create("vote");
  ASSERT_NE(op, nullptr);
  EXPECT_EQ(op->dedup.type, DEDUP_NONE);
  operation_destroy(op);
}

TEST(DedupSpec, SetPerUserDedup) {
  operation_t* op = operation_create("vote");
  op->dedup.type = DEDUP_PER_USER;
  strncpy(op->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->dedup.rejection_message, "You have already voted", CRABS_MAX_DEDUP_MESSAGE - 1);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(op->dedup.type, DEDUP_PER_USER);
  EXPECT_STREQ(op->dedup.tracker_path, "proposal_42_voters");
  EXPECT_STREQ(op->dedup.rejection_message, "You have already voted");

  operation_destroy(op);
}

TEST(DedupSpec, SetGlobalDedup) {
  operation_t* op = operation_create("execute");
  op->dedup.type = DEDUP_GLOBAL;
  strncpy(op->dedup.flag_path, "proposal_42_executed", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->dedup.rejection_message, "Already executed", CRABS_MAX_DEDUP_MESSAGE - 1);

  EXPECT_EQ(op->dedup.type, DEDUP_GLOBAL);
  EXPECT_STREQ(op->dedup.flag_path, "proposal_42_executed");

  operation_destroy(op);
}

// ============================================================
// Dedup guard check tests
// ============================================================

class DedupGuardTest : public ::testing::Test {
protected:
  void SetUp() override {
    state = state_create();
    // Create a ONE_SHOT_SET item for tracking voters
    data_item_t* voters = data_item_create("proposal_42_voters", DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
    voters->value = one_shot_set_create();
    state_add_item(state, voters);

    // Create a ONE_SHOT_FLAG item for tracking execution
    data_item_t* executed = data_item_create("proposal_42_executed", DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
    executed->value = one_shot_flag_create();
    state_add_item(state, executed);
  }

  void TearDown() override {
    state_destroy(state);
  }

  state_t* state;
};

TEST_F(DedupGuardTest, NoneDedupAlwaysPasses) {
  operation_t* op = operation_create("any_op");
  op->dedup.type = DEDUP_NONE;

  EXPECT_EQ(dedup_check_guard(state, op), CRABS_SUCCESS);

  operation_destroy(op);
}

TEST_F(DedupGuardTest, PerUserDedupPassesWhenNotVoted) {
  operation_t* op = operation_create("vote");
  op->dedup.type = DEDUP_PER_USER;
  strncpy(op->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_check_guard(state, op), CRABS_SUCCESS);

  operation_destroy(op);
}

TEST_F(DedupGuardTest, PerUserDedupFailsAfterVoting) {
  // First, add alice to the voters set
  data_item_t* voters = state_find_item(state, "proposal_42_voters");
  one_shot_set_add((one_shot_set_t*)voters->value, "alice");

  operation_t* op = operation_create("vote");
  op->dedup.type = DEDUP_PER_USER;
  strncpy(op->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_check_guard(state, op), CRABS_ERR_ALREADY_PERFORMED);

  operation_destroy(op);
}

TEST_F(DedupGuardTest, PerUserDifferentUserCanVote) {
  // Add alice to voters
  data_item_t* voters = state_find_item(state, "proposal_42_voters");
  one_shot_set_add((one_shot_set_t*)voters->value, "alice");

  // Bob should still be able to vote
  operation_t* op = operation_create("vote");
  op->dedup.type = DEDUP_PER_USER;
  strncpy(op->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->signer_id, "bob", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_check_guard(state, op), CRABS_SUCCESS);

  operation_destroy(op);
}

TEST_F(DedupGuardTest, GlobalDedupPassesWhenNotExecuted) {
  operation_t* op = operation_create("execute");
  op->dedup.type = DEDUP_GLOBAL;
  strncpy(op->dedup.flag_path, "proposal_42_executed", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->signer_id, "carol", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_check_guard(state, op), CRABS_SUCCESS);

  operation_destroy(op);
}

TEST_F(DedupGuardTest, GlobalDedupFailsAfterExecution) {
  // Set the flag to true
  data_item_t* flag_item = state_find_item(state, "proposal_42_executed");
  one_shot_flag_set((one_shot_flag_t*)flag_item->value, "carol", 1000);

  operation_t* op = operation_create("execute");
  op->dedup.type = DEDUP_GLOBAL;
  strncpy(op->dedup.flag_path, "proposal_42_executed", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->signer_id, "dave", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_check_guard(state, op), CRABS_ERR_ALREADY_EXECUTED);

  operation_destroy(op);
}

TEST_F(DedupGuardTest, PerUserTrackerNotFound) {
  operation_t* op = operation_create("vote");
  op->dedup.type = DEDUP_PER_USER;
  strncpy(op->dedup.tracker_path, "nonexistent_tracker", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_check_guard(state, op), CRABS_ERR_TRACKER_NOT_FOUND);

  operation_destroy(op);
}

TEST_F(DedupGuardTest, GlobalFlagNotFound) {
  operation_t* op = operation_create("execute");
  op->dedup.type = DEDUP_GLOBAL;
  strncpy(op->dedup.flag_path, "nonexistent_flag", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_check_guard(state, op), CRABS_ERR_FLAG_NOT_FOUND);

  operation_destroy(op);
}

// ============================================================
// Dedup state mutation tests
// ============================================================

class DedupMutationTest : public ::testing::Test {
protected:
  void SetUp() override {
    state = state_create();
    voters = data_item_create("proposal_42_voters", DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
    voters->value = one_shot_set_create();
    state_add_item(state, voters);

    executed = data_item_create("proposal_42_executed", DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
    executed->value = one_shot_flag_create();
    state_add_item(state, executed);

    counter = data_item_create("balance", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
    int64_t* val = (int64_t*)malloc(sizeof(int64_t));
    *val = 1000;
    counter->value = val;
    state_add_item(state, counter);
  }

  void TearDown() override {
    state_destroy(state);
  }

  state_t* state;
  data_item_t* voters;
  data_item_t* executed;
  data_item_t* counter;
};

TEST_F(DedupMutationTest, NoneDedupNoMutation) {
  operation_t* op = operation_create("any_op");
  op->dedup.type = DEDUP_NONE;

  EXPECT_EQ(dedup_apply_mutation(state, op), CRABS_SUCCESS);

  // No changes should occur
  one_shot_set_t* set = (one_shot_set_t*)voters->value;
  EXPECT_EQ(one_shot_set_count(set), (uint32_t)0);

  operation_destroy(op);
}

TEST_F(DedupMutationTest, PerUserAddsSignerToTracker) {
  operation_t* op = operation_create("vote");
  op->dedup.type = DEDUP_PER_USER;
  strncpy(op->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_apply_mutation(state, op), CRABS_SUCCESS);

  one_shot_set_t* set = (one_shot_set_t*)voters->value;
  EXPECT_TRUE(one_shot_set_contains(set, "alice"));
  EXPECT_EQ(one_shot_set_count(set), (uint32_t)1);

  operation_destroy(op);
}

TEST_F(DedupMutationTest, PerUserSecondAddIsIdempotent) {
  // Add alice
  operation_t* op1 = operation_create("vote");
  op1->dedup.type = DEDUP_PER_USER;
  strncpy(op1->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op1->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  dedup_apply_mutation(state, op1);

  // Try again
  operation_t* op2 = operation_create("vote");
  op2->dedup.type = DEDUP_PER_USER;
  strncpy(op2->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op2->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  EXPECT_EQ(dedup_apply_mutation(state, op2), CRABS_SUCCESS);

  one_shot_set_t* set = (one_shot_set_t*)voters->value;
  EXPECT_EQ(one_shot_set_count(set), (uint32_t)1); // Still 1

  operation_destroy(op1);
  operation_destroy(op2);
}

TEST_F(DedupMutationTest, GlobalSetsFlag) {
  operation_t* op = operation_create("execute");
  op->dedup.type = DEDUP_GLOBAL;
  strncpy(op->dedup.flag_path, "proposal_42_executed", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->signer_id, "carol", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 1000;

  EXPECT_EQ(dedup_apply_mutation(state, op), CRABS_SUCCESS);

  one_shot_flag_t* flag = (one_shot_flag_t*)executed->value;
  EXPECT_TRUE(one_shot_flag_value(flag));
  EXPECT_STREQ(flag->set_by, "carol");
  EXPECT_EQ(flag->set_at, (uint64_t)1000);

  operation_destroy(op);
}

TEST_F(DedupMutationTest, CustomSetAddMutation) {
  operation_t* op = operation_create("custom_op");
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "true", CRABS_MAX_POLICY_EXPR - 1);
  op->dedup.update.type = MUTATION_SET_ADD;
  strncpy(op->dedup.update.set_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->dedup.update.element_value, "bob", CRABS_MAX_USER_ID - 1);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_apply_mutation(state, op), CRABS_SUCCESS);

  one_shot_set_t* set = (one_shot_set_t*)voters->value;
  EXPECT_TRUE(one_shot_set_contains(set, "bob"));

  operation_destroy(op);
}

TEST_F(DedupMutationTest, CustomCounterIncrementMutation) {
  operation_t* op = operation_create("spend");
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "balance >= 100", CRABS_MAX_POLICY_EXPR - 1);
  op->dedup.update.type = MUTATION_COUNTER_INCREMENT;
  strncpy(op->dedup.update.counter_path, "balance", CRABS_MAX_DEDUP_PATH - 1);
  op->dedup.update.delta = -100;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_apply_mutation(state, op), CRABS_SUCCESS);

  int64_t* val = (int64_t*)counter->value;
  EXPECT_EQ(*val, (int64_t)900);

  operation_destroy(op);
}

// ============================================================
// Desugaring tests
// ============================================================

TEST(DedupDesugaring, PerUserPolicyGuard) {
  dedup_spec_t dedup;
  memset(&dedup, 0, sizeof(dedup));
  dedup.type = DEDUP_PER_USER;
  strncpy(dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);

  char* guard = dedup_build_policy_guard(&dedup, "alice");
  ASSERT_NE(guard, nullptr);
  EXPECT_STREQ(guard, "proposal_42_voters NOT CONTAINS alice");
  free(guard);
}

TEST(DedupDesugaring, GlobalPolicyGuard) {
  dedup_spec_t dedup;
  memset(&dedup, 0, sizeof(dedup));
  dedup.type = DEDUP_GLOBAL;
  strncpy(dedup.flag_path, "proposal_42_executed", CRABS_MAX_DEDUP_PATH - 1);

  char* guard = dedup_build_policy_guard(&dedup, "carol");
  ASSERT_NE(guard, nullptr);
  EXPECT_STREQ(guard, "proposal_42_executed == false");
  free(guard);
}

TEST(DedupDesugaring, CustomPolicyGuard) {
  dedup_spec_t dedup;
  memset(&dedup, 0, sizeof(dedup));
  dedup.type = DEDUP_CUSTOM;
  strncpy(dedup.condition, "treasury.balance >= 100", CRABS_MAX_POLICY_EXPR - 1);

  char* guard = dedup_build_policy_guard(&dedup, "alice");
  ASSERT_NE(guard, nullptr);
  EXPECT_STREQ(guard, "treasury.balance >= 100");
  free(guard);
}

TEST(DedupDesugaring, NoneDedupReturnsNull) {
  dedup_spec_t dedup;
  memset(&dedup, 0, sizeof(dedup));
  dedup.type = DEDUP_NONE;

  char* guard = dedup_build_policy_guard(&dedup, "alice");
  EXPECT_EQ(guard, nullptr);
}

TEST(DedupDesugaring, NullDedupReturnsNull) {
  char* guard = dedup_build_policy_guard(NULL, "alice");
  EXPECT_EQ(guard, nullptr);
}

// ============================================================
// Full lifecycle: guard check + mutation round-trip
// ============================================================

TEST(DedupLifecycle, PerUserVoteOnceLifecycle) {
  state_t* state = state_create();
  data_item_t* voters = data_item_create("voters", DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  voters->value = one_shot_set_create();
  state_add_item(state, voters);

  // Alice tries to vote - should pass
  operation_t* op1 = operation_create("vote");
  op1->dedup.type = DEDUP_PER_USER;
  strncpy(op1->dedup.tracker_path, "voters", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op1->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_check_guard(state, op1), CRABS_SUCCESS);
  EXPECT_EQ(dedup_apply_mutation(state, op1), CRABS_SUCCESS);

  // Alice tries again - should fail
  operation_t* op2 = operation_create("vote");
  op2->dedup.type = DEDUP_PER_USER;
  strncpy(op2->dedup.tracker_path, "voters", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op2->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_check_guard(state, op2), CRABS_ERR_ALREADY_PERFORMED);

  // Bob tries to vote - should pass
  operation_t* op3 = operation_create("vote");
  op3->dedup.type = DEDUP_PER_USER;
  strncpy(op3->dedup.tracker_path, "voters", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op3->signer_id, "bob", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_check_guard(state, op3), CRABS_SUCCESS);
  EXPECT_EQ(dedup_apply_mutation(state, op3), CRABS_SUCCESS);

  one_shot_set_t* set = (one_shot_set_t*)voters->value;
  EXPECT_EQ(one_shot_set_count(set), (uint32_t)2);

  operation_destroy(op1);
  operation_destroy(op2);
  operation_destroy(op3);
  state_destroy(state);
}

TEST(DedupLifecycle, GlobalExecutionOnceLifecycle) {
  state_t* state = state_create();
  data_item_t* flag_item = data_item_create("executed", DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
  flag_item->value = one_shot_flag_create();
  state_add_item(state, flag_item);

  // Carol executes - should pass
  operation_t* op1 = operation_create("execute");
  op1->dedup.type = DEDUP_GLOBAL;
  strncpy(op1->dedup.flag_path, "executed", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op1->signer_id, "carol", CRABS_MAX_USER_ID - 1);
  op1->lamport_time = 1000;

  EXPECT_EQ(dedup_check_guard(state, op1), CRABS_SUCCESS);
  EXPECT_EQ(dedup_apply_mutation(state, op1), CRABS_SUCCESS);

  // Dave tries to execute - should fail
  operation_t* op2 = operation_create("execute");
  op2->dedup.type = DEDUP_GLOBAL;
  strncpy(op2->dedup.flag_path, "executed", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op2->signer_id, "dave", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_check_guard(state, op2), CRABS_ERR_ALREADY_EXECUTED);

  one_shot_flag_t* flag = (one_shot_flag_t*)flag_item->value;
  EXPECT_TRUE(one_shot_flag_value(flag));
  EXPECT_STREQ(flag->set_by, "carol");

  operation_destroy(op1);
  operation_destroy(op2);
  state_destroy(state);
}