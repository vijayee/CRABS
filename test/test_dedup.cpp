#include <gtest/gtest.h>
extern "C" {
#include "../src/Dedup/dedup.h"
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/CRDT/one_shot.h"
#include "../src/CRDT/crdt_merge.h"
}

// Internal handlers not in public header — exposed for testing only.
extern "C" {
crabs_error_e state_machine_op_lock(state_t* state, operation_t* op, lock_response_t* response);
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
    voters->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
    state_add_item(state, voters);

    // Create a ONE_SHOT_FLAG item for tracking execution
    data_item_t* executed = data_item_create("proposal_42_executed", DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
    executed->value = one_shot_flag_create();
    executed->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
    state_add_item(state, executed);
  }

  void TearDown() override {
    // Free CRDT struct values manually (predates the repr-aware
    // data_item_destroy; harmless with the values NULLed after).
    for (data_item_t* item = state->items; item != NULL; item = item->next) {
      if (item->value != NULL) {
        crdt_value_destroy(item->crdt_type, item->value);
        item->value = NULL;
      }
    }
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

// Regression for audit F-2: when a dedup spec is REGISTERED for an operation
// type, the server must enforce THAT spec regardless of what dedup the op
// carries on the wire. A signer cannot bypass "vote once" by setting
// dedup.type = DEDUP_NONE on their operation. The executor resolves the
// effective spec via state_find_op_type_def and calls dedup_check_guard_spec
// with it; this test exercises that exact path.
TEST_F(DedupGuardTest, RegisteredSpecEnforcedEvenWhenOpCarriesNone) {
  // Register a PER_USER dedup spec for the "vote" op type.
  dedup_spec_t spec;
  memset(&spec, 0, sizeof(spec));
  spec.type = DEDUP_PER_USER;
  strncpy(spec.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);
  ASSERT_EQ(state_register_op_type_def(state, "vote", &spec), CRABS_SUCCESS);

  // Alice has already voted.
  data_item_t* voters = state_find_item(state, "proposal_42_voters");
  ASSERT_EQ(one_shot_set_add((one_shot_set_t*)voters->value, "alice"), CRABS_SUCCESS);

  // Attacker submits a "vote" op with dedup.type = DEDUP_NONE to bypass.
  operation_t* op = operation_create("vote");
  op->dedup.type = DEDUP_NONE;  // bypass attempt
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  // The executor's resolution: registered wins over op-carried.
  const dedup_spec_t* registered = state_find_op_type_def(state, "vote");
  ASSERT_NE(registered, nullptr);
  const dedup_spec_t* effective = registered;
  EXPECT_EQ(effective->type, DEDUP_PER_USER);

  // Guard with the EFFECTIVE (registered) spec must reject alice.
  EXPECT_EQ(dedup_check_guard_spec(state, effective, op), CRABS_ERR_ALREADY_PERFORMED);

  // Sanity: the op-carried spec alone (DEDUP_NONE) would have passed —
  // confirming the bypass would work without the F-2 fix.
  EXPECT_EQ(dedup_check_guard(state, op), CRABS_SUCCESS);

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
    voters->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
    state_add_item(state, voters);

    executed = data_item_create("proposal_42_executed", DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
    executed->value = one_shot_flag_create();
    executed->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
    state_add_item(state, executed);

    // Audit: counter items created the way wasm/CRDT helpers create them hold
    // a g_counter_t* (not a raw int64_t*). The dedup mutation dispatch must
    // route through g_counter_increment for these.
    counter = data_item_create("balance", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
    g_counter_t* seeded_counter = g_counter_create();
    EXPECT_EQ(g_counter_increment(seeded_counter, "node1", 1000), CRABS_SUCCESS);
    counter->value = seeded_counter;
    counter->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
    state_add_item(state, counter);
  }

  void TearDown() override {
    // Free CRDT struct values manually (predates the repr-aware
    // data_item_destroy; harmless with the values NULLed after).
    for (data_item_t* item = state->items; item != NULL; item = item->next) {
      if (item->value != NULL) {
        switch (item->crdt_type) {
          case CRDT_G_COUNTER:
          case CRDT_PN_COUNTER:
          case CRDT_OR_SET:
          case CRDT_2P_SET:
          case CRDT_LWW_REG:
          case CRDT_ONE_SHOT_SET:
          case CRDT_ONE_SHOT_FLAG:
            crdt_value_destroy(item->crdt_type, item->value);
            item->value = NULL;
            break;
          default:
            break;
        }
      }
    }
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
  operation_t* op = operation_create("credit");
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "balance >= 100", CRABS_MAX_POLICY_EXPR - 1);
  op->dedup.update.type = MUTATION_COUNTER_INCREMENT;
  strncpy(op->dedup.update.counter_path, "balance", CRABS_MAX_DEDUP_PATH - 1);
  // A G-Counter only grows, so the mutation applies a positive delta through
  // g_counter_increment (the item's actual value representation).
  op->dedup.update.delta = 100;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_apply_mutation(state, op), CRABS_SUCCESS);

  g_counter_t* counter_value = (g_counter_t*)counter->value;
  EXPECT_EQ(g_counter_value(counter_value), (int64_t)1100);

  operation_destroy(op);
}

// R8-S-3: the dedup mutation must be validated BEFORE the handler runs, so a
// failing mutation cannot leave the handler's effects applied. These tests
// exercise dedup_validate_mutation_spec, which state_machine_execute calls
// before dispatching to the handler.
TEST_F(DedupMutationTest, ValidateRejectsMissingSetPath) {
  operation_t* op = operation_create("custom_op");
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "true", CRABS_MAX_POLICY_EXPR - 1);
  op->dedup.update.type = MUTATION_SET_ADD;
  strncpy(op->dedup.update.set_path, "nonexistent_set", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->dedup.update.element_value, "bob", CRABS_MAX_USER_ID - 1);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_validate_mutation_spec(state, &op->dedup, op), CRABS_ERR_TRACKER_NOT_FOUND);

  operation_destroy(op);
}

TEST_F(DedupMutationTest, ValidateRejectsCounterOverflow) {
  operation_t* op = operation_create("spend");
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "true", CRABS_MAX_POLICY_EXPR - 1);
  op->dedup.update.type = MUTATION_COUNTER_INCREMENT;
  strncpy(op->dedup.update.counter_path, "balance", CRABS_MAX_DEDUP_PATH - 1);
  op->dedup.update.delta = INT64_MAX;  // balance=1000, adding INT64_MAX overflows
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_validate_mutation_spec(state, &op->dedup, op), CRABS_ERR_INVALID_PARAM);

  operation_destroy(op);
}

TEST_F(DedupMutationTest, ValidateRejectsFullPerUserSet) {
  // Fill the voters set to capacity so a PER_USER add would fail with OOM.
  one_shot_set_t* set = (one_shot_set_t*)voters->value;
  for (uint32_t i = 0; i < CRABS_ONE_SHOT_SET_MAX; i++) {
    char id[32];
    snprintf(id, sizeof(id), "user%u", i);
    ASSERT_EQ(one_shot_set_add(set, id), CRABS_SUCCESS);
  }

  operation_t* op = operation_create("vote");
  op->dedup.type = DEDUP_PER_USER;
  strncpy(op->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_validate_mutation_spec(state, &op->dedup, op), CRABS_ERR_OOM);

  operation_destroy(op);
}

// ============================================================
// Audit: mutation dispatch must match the item's actual value representation
// ============================================================
// Items created by the wasm/CRDT helpers hold real CRDT structs (g_counter_t*,
// pn_counter_t*, lww_register_t*). The old counter/assign mutations blind-cast
// item->value to int64_t*, corrupting the struct. These tests pin the dispatch.

TEST_F(DedupMutationTest, CounterIncrementOnGCounterRoutesThroughCounterStruct) {
  g_counter_t* counter_value = (g_counter_t*)counter->value;
  g_counter_entry_t* entries_before = counter_value->entries;

  operation_t* op = operation_create("credit");
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "true", CRABS_MAX_POLICY_EXPR - 1);
  op->dedup.update.type = MUTATION_COUNTER_INCREMENT;
  strncpy(op->dedup.update.counter_path, "balance", CRABS_MAX_DEDUP_PATH - 1);
  op->dedup.update.delta = 5;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  // The counter was seeded for node "node1"; mutating as the same node keeps
  // the entries array in place, so the pointer-stability assertion below is
  // an exact check that no struct memory was corrupted.
  strncpy(op->node_id, "node1", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_validate_mutation_spec(state, &op->dedup, op), CRABS_SUCCESS);
  EXPECT_EQ(dedup_apply_mutation_spec(state, &op->dedup, op), CRABS_SUCCESS);

  // No pointer corruption: the counter struct and its entries array are the
  // same allocations as before, and the value moved by exactly the delta.
  EXPECT_EQ(counter->value, counter_value);
  EXPECT_EQ(counter_value->entries, entries_before);
  EXPECT_EQ(g_counter_value(counter_value), (int64_t)1005);
  EXPECT_EQ(g_counter_value((g_counter_t*)counter->value), (int64_t)1005);

  operation_destroy(op);
}

TEST_F(DedupMutationTest, ValidateRejectsNegativeDeltaOnGCounter) {
  operation_t* op = operation_create("spend");
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "true", CRABS_MAX_POLICY_EXPR - 1);
  op->dedup.update.type = MUTATION_COUNTER_INCREMENT;
  strncpy(op->dedup.update.counter_path, "balance", CRABS_MAX_DEDUP_PATH - 1);
  // g_counter_increment rejects negative deltas (a G-Counter only grows), so
  // the pre-handler validation must reject them too.
  op->dedup.update.delta = -1;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_validate_mutation_spec(state, &op->dedup, op), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(g_counter_value((g_counter_t*)counter->value), (int64_t)1000);

  operation_destroy(op);
}

TEST_F(DedupMutationTest, CounterIncrementOnPnCounterRoutesThroughCounterStruct) {
  data_item_t* pn_item = data_item_create("pn_balance", DATA_TYPE_PN_COUNTER, CRDT_PN_COUNTER);
  pn_counter_t* pn_value = pn_counter_create();
  EXPECT_EQ(pn_counter_increment(pn_value, "node1", 50), CRABS_SUCCESS);
  pn_item->value = pn_value;
  pn_item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  state_add_item(state, pn_item);

  operation_t* op = operation_create("spend");
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "true", CRABS_MAX_POLICY_EXPR - 1);
  op->dedup.update.type = MUTATION_COUNTER_INCREMENT;
  strncpy(op->dedup.update.counter_path, "pn_balance", CRABS_MAX_DEDUP_PATH - 1);
  op->dedup.update.delta = -30;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_validate_mutation_spec(state, &op->dedup, op), CRABS_SUCCESS);
  EXPECT_EQ(dedup_apply_mutation_spec(state, &op->dedup, op), CRABS_SUCCESS);

  EXPECT_EQ(pn_item->value, pn_value);
  EXPECT_EQ(pn_counter_value(pn_value), (int64_t)20);

  operation_destroy(op);
}

TEST_F(DedupMutationTest, AssignOnLwwRegisterUsesRegisterSemantics) {
  data_item_t* register_item = data_item_create("config_level", DATA_TYPE_REGISTER, CRDT_LWW_REG);
  int64_t initial_value = 1;
  register_item->value =
      lww_register_create((const uint8_t*)&initial_value, sizeof(int64_t), 0, "system");
  register_item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  state_add_item(state, register_item);

  operation_t* op = operation_create("set_level");
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "true", CRABS_MAX_POLICY_EXPR - 1);
  op->dedup.update.type = MUTATION_ASSIGN;
  strncpy(op->dedup.update.target_path, "config_level", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->dedup.update.value, "777", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_validate_mutation_spec(state, &op->dedup, op), CRABS_SUCCESS);
  EXPECT_EQ(dedup_apply_mutation_spec(state, &op->dedup, op), CRABS_SUCCESS);

  // The register struct must still be intact and readable via the same path
  // crabs_wasm_get_register uses (value pointer + 8-byte int payload).
  lww_register_t* register_value = (lww_register_t*)register_item->value;
  ASSERT_NE(register_value, nullptr);
  ASSERT_NE(register_value->value, nullptr);
  ASSERT_GE(register_value->value_size, sizeof(int64_t));
  EXPECT_EQ(*(int64_t*)register_value->value, (int64_t)777);
  EXPECT_GT(register_value->timestamp, (uint64_t)0);

  operation_destroy(op);
}

TEST_F(DedupMutationTest, SetAddRejectsOrSetTarget) {
  data_item_t* or_set_item = data_item_create("or_members", DATA_TYPE_SET, CRDT_OR_SET);
  or_set_t* set_value = or_set_create();
  or_set_item->value = set_value;
  or_set_item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  state_add_item(state, or_set_item);

  operation_t* op = operation_create("join");
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "true", CRABS_MAX_POLICY_EXPR - 1);
  op->dedup.update.type = MUTATION_SET_ADD;
  strncpy(op->dedup.update.set_path, "or_members", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->dedup.update.element_value, "mallory", CRABS_MAX_USER_ID - 1);
  strncpy(op->signer_id, "mallory", CRABS_MAX_USER_ID - 1);

  // Casting an or_set_t to one_shot_set_t and calling one_shot_set_add is
  // memory corruption; both validate and apply must reject with TYPE_MISMATCH.
  EXPECT_EQ(dedup_validate_mutation_spec(state, &op->dedup, op), CRABS_ERR_TYPE_MISMATCH);
  EXPECT_EQ(dedup_apply_mutation_spec(state, &op->dedup, op), CRABS_ERR_TYPE_MISMATCH);

  // The OR-set is untouched.
  EXPECT_EQ(set_value->element_count, (uint32_t)0);

  operation_destroy(op);
}

TEST_F(DedupMutationTest, CheckAndApplyCounterIncrementOnGCounter) {
  operation_t* op = operation_create("credit");
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "balance >= 100", CRABS_MAX_POLICY_EXPR - 1);
  op->dedup.update.type = MUTATION_COUNTER_INCREMENT;
  strncpy(op->dedup.update.counter_path, "balance", CRABS_MAX_DEDUP_PATH - 1);
  op->dedup.update.delta = 7;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_check_and_apply_spec(state, &op->dedup, op), CRABS_SUCCESS);
  EXPECT_EQ(g_counter_value((g_counter_t*)counter->value), (int64_t)1007);

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
  voters->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
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
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

TEST(DedupLifecycle, GlobalExecutionOnceLifecycle) {
  state_t* state = state_create();
  data_item_t* flag_item = data_item_create("executed", DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
  flag_item->value = one_shot_flag_create();
  flag_item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
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
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

// ============================================================
// State machine integration tests
// ============================================================

TEST(DedupIntegration, StateMachineRejectsPerUserDuplicate) {
  state_t* state = state_create();
  data_item_t* voters = data_item_create("proposal_42_voters", DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  voters->value = one_shot_set_create();
  voters->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  state_add_item(state, voters);
  state_add_policy(state, CRABS_OP_LOCK, "role:admin");

  // First vote via state_machine_execute should succeed (dedup check passes)
  operation_t* op1 = operation_create(CRABS_OP_LOCK);
  memset(op1->uuid, 0x01, CRABS_UUID_SIZE);
  strncpy(op1->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op1->lamport_time = 1000;
  op1->dedup.type = DEDUP_PER_USER;
  strncpy(op1->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);
  op1->resource_count = 1;
  op1->resources = (char(*)[CRABS_MAX_USER_ID])malloc(CRABS_MAX_USER_ID);
  strncpy(op1->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  op1->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op1->required_state[0] = PROTOCOL_IDLE;
  op1->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op1->next_state[0] = PROTOCOL_LOCKED;
  op1->lock_claim_count = 1;
  op1->lock_claims = (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(op1->lock_claims[0].resource, "res1", CRABS_MAX_USER_ID - 1);
  memset(op1->lock_claims[0].lock_token, 0x01, CRABS_LOCK_TOKEN_SIZE);
  strncpy(op1->policy, "role:admin", CRABS_MAX_POLICY_EXPR - 1);
  memset(op1->signature, 0, CRABS_SIG_SIZE);

  // The dedup guard should pass (alice hasn't voted yet)
  crabs_error_e guard_result = dedup_check_guard(state, op1);
  EXPECT_EQ(guard_result, CRABS_SUCCESS);

  // After adding alice to the set
  one_shot_set_add((one_shot_set_t*)voters->value, "alice");

  // Second attempt should fail
  crabs_error_e guard_result2 = dedup_check_guard(state, op1);
  EXPECT_EQ(guard_result2, CRABS_ERR_ALREADY_PERFORMED);

  operation_destroy(op1);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

TEST(DedupIntegration, StateMachineRejectsGlobalDuplicate) {
  state_t* state = state_create();
  data_item_t* executed = data_item_create("proposal_42_executed", DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
  executed->value = one_shot_flag_create();
  executed->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  state_add_item(state, executed);

  operation_t* op = operation_create("custom_op");
  memset(op->uuid, 0x02, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "carol", CRABS_MAX_USER_ID - 1);
  op->dedup.type = DEDUP_GLOBAL;
  strncpy(op->dedup.flag_path, "proposal_42_executed", CRABS_MAX_DEDUP_PATH - 1);

  // Guard should pass (flag not set)
  EXPECT_EQ(dedup_check_guard(state, op), CRABS_SUCCESS);

  // Set the flag
  one_shot_flag_set((one_shot_flag_t*)executed->value, "carol", 1000);

  // Guard should now fail
  EXPECT_EQ(dedup_check_guard(state, op), CRABS_ERR_ALREADY_EXECUTED);

  operation_destroy(op);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

TEST(DedupIntegration, NoneDedupOperationExecutes) {
  state_t* state = state_create();
  state_add_policy(state, CRABS_OP_LOCK, "role:admin");

  operation_t* op = operation_create(CRABS_OP_LOCK);
  memset(op->uuid, 0x03, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 1;
  // dedup.type defaults to DEDUP_NONE
  EXPECT_EQ(op->dedup.type, DEDUP_NONE);

  lock_response_t resp;
  memset(&resp, 0, sizeof(resp));
  // This should work without any dedup interference
  crabs_error_e result = state_machine_op_lock(state, op, &resp);
  EXPECT_EQ(result, CRABS_SUCCESS);

  operation_destroy(op);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

TEST(DedupIntegration, CheckDedupOperationIsBuiltin) {
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_DEFINE_OPERATION));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_CHECK_DEDUP));
}

// ============================================================
// DEDUP_CUSTOM condition evaluation tests (v1.4 §6)
// ============================================================

class DedupCustomTest : public ::testing::Test {
protected:
  void SetUp() override {
    state = state_create();
    // Create a G-Counter for condition evaluation
    data_item_t* counter = data_item_create("vote_count", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
    g_counter_t* gc = g_counter_create();
    g_counter_increment(gc, "node1", 5);
    counter->value = gc;
    counter->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
    state_add_item(state, counter);

    // Create a set for CONTAINS evaluation
    data_item_t* voters = data_item_create("proposal_voters", DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
    voters->value = one_shot_set_create();
    voters->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
    state_add_item(state, voters);
  }

  void TearDown() override {
    // Free CRDT struct values manually since data_item_destroy uses free()
    for (data_item_t* item = state->items; item != NULL; item = item->next) {
      if (item->value != NULL) {
        crdt_value_destroy(item->crdt_type, item->value);
        item->value = NULL;
      }
    }
    state_destroy(state);
  }

  state_t* state;
};

TEST_F(DedupCustomTest, CustomConditionPasses) {
  operation_t* op = operation_create("spend");
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "vote_count >= 3", CRABS_MAX_POLICY_EXPR - 1);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_check_guard(state, op), CRABS_SUCCESS);

  operation_destroy(op);
}

TEST_F(DedupCustomTest, CustomConditionFails) {
  operation_t* op = operation_create("spend");
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "vote_count >= 100", CRABS_MAX_POLICY_EXPR - 1);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(dedup_check_guard(state, op), CRABS_ERR_CONDITION_NOT_MET);

  operation_destroy(op);
}

TEST_F(DedupCustomTest, CustomEmptyConditionFails) {
  operation_t* op = operation_create("spend");
  op->dedup.type = DEDUP_CUSTOM;
  // Empty condition string → should fail
  op->dedup.condition[0] = '\0';

  EXPECT_EQ(dedup_check_guard(state, op), CRABS_ERR_CONDITION_NOT_MET);

  operation_destroy(op);
}

TEST_F(DedupCustomTest, CustomConditionTrueLiteral) {
  operation_t* op = operation_create("any_op");
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "vote_count >= 1", CRABS_MAX_POLICY_EXPR - 1);

  EXPECT_EQ(dedup_check_guard(state, op), CRABS_SUCCESS);

  operation_destroy(op);
}

// ============================================================
// Operation type definition registry tests (v1.4 §7)
// ============================================================

TEST(OpTypeDef, RegisterAndFind) {
  state_t* state = state_create();

  dedup_spec_t spec;
  memset(&spec, 0, sizeof(spec));
  spec.type = DEDUP_PER_USER;
  strncpy(spec.tracker_path, "voters", CRABS_MAX_DEDUP_PATH - 1);

  crabs_error_e rc = state_register_op_type_def(state, "vote", &spec);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  const dedup_spec_t* found = state_find_op_type_def(state, "vote");
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->type, DEDUP_PER_USER);
  EXPECT_STREQ(found->tracker_path, "voters");

  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

TEST(OpTypeDef, FindNonexistent) {
  state_t* state = state_create();

  const dedup_spec_t* found = state_find_op_type_def(state, "nonexistent");
  EXPECT_EQ(found, nullptr);

  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

TEST(OpTypeDef, UpdateExisting) {
  state_t* state = state_create();

  dedup_spec_t spec1;
  memset(&spec1, 0, sizeof(spec1));
  spec1.type = DEDUP_PER_USER;
  strncpy(spec1.tracker_path, "voters", CRABS_MAX_DEDUP_PATH - 1);

  crabs_error_e rc = state_register_op_type_def(state, "vote", &spec1);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Update with global dedup
  dedup_spec_t spec2;
  memset(&spec2, 0, sizeof(spec2));
  spec2.type = DEDUP_GLOBAL;
  strncpy(spec2.flag_path, "vote_executed", CRABS_MAX_DEDUP_PATH - 1);

  rc = state_register_op_type_def(state, "vote", &spec2);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  const dedup_spec_t* found = state_find_op_type_def(state, "vote");
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->type, DEDUP_GLOBAL);
  EXPECT_STREQ(found->flag_path, "vote_executed");

  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

TEST(OpTypeDef, NullParams) {
  crabs_error_e rc = state_register_op_type_def(NULL, "vote", NULL);
  EXPECT_EQ(rc, CRABS_ERR_INVALID_PARAM);

  state_t* state = state_create();
  dedup_spec_t spec;
  memset(&spec, 0, sizeof(spec));
  rc = state_register_op_type_def(state, NULL, &spec);
  EXPECT_EQ(rc, CRABS_ERR_INVALID_PARAM);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

// ============================================================
// Built-in operation handler tests (v1.4 §7)
// ============================================================

TEST(DedupBuiltinOp, DefineOperationRegistersType) {
  state_t* state = state_create();

  operation_t* op = operation_create(CRABS_OP_DEFINE_OPERATION);
  memset(op->uuid, 0x01, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 1;
  // The operation type name being defined is carried in resources[0]
  op->resource_count = 1;
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(CRABS_MAX_USER_ID);
  strncpy(op->resources[0], "vote", CRABS_MAX_USER_ID - 1);
  op->dedup.type = DEDUP_PER_USER;
  strncpy(op->dedup.tracker_path, "voters", CRABS_MAX_DEDUP_PATH - 1);

  crabs_error_e result = state_machine_op_define_operation(state, op);
  EXPECT_EQ(result, CRABS_SUCCESS);

  // Look up the registered type for "vote"
  const dedup_spec_t* found = state_find_op_type_def(state, "vote");
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->type, DEDUP_PER_USER);
  EXPECT_STREQ(found->tracker_path, "voters");

  operation_destroy(op);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

// Audit: __define_operation_type__ must not be able to attach a dedup spec to
// a built-in operation type (e.g. __lock__) — builtin handlers own their own
// authorization and a registered spec would only add an unauthorized
// mutation/guard surface on top of them.
TEST(DedupBuiltinOp, DefineOperationRejectsBuiltinTarget) {
  state_t* state = state_create();

  operation_t* op = operation_create(CRABS_OP_DEFINE_OPERATION);
  memset(op->uuid, 0x01, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 1;
  op->resource_count = 1;
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(CRABS_MAX_USER_ID);
  strncpy(op->resources[0], CRABS_OP_LOCK, CRABS_MAX_USER_ID - 1);
  op->dedup.type = DEDUP_PER_USER;
  strncpy(op->dedup.tracker_path, "voters", CRABS_MAX_DEDUP_PATH - 1);

  EXPECT_EQ(state_machine_op_define_operation(state, op), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state_find_op_type_def(state, CRABS_OP_LOCK), nullptr);

  operation_destroy(op);
  state_destroy(state);
}

TEST(DedupBuiltinOp, CheckDedupWithRegisteredSpec) {
  state_t* state = state_create();

  // Register a "vote" operation type with PER_USER dedup
  dedup_spec_t vote_spec;
  memset(&vote_spec, 0, sizeof(vote_spec));
  vote_spec.type = DEDUP_PER_USER;
  strncpy(vote_spec.tracker_path, "voters", CRABS_MAX_DEDUP_PATH - 1);
  state_register_op_type_def(state, "vote", &vote_spec);

  // Create the tracking set
  data_item_t* voters = data_item_create("voters", DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  voters->value = one_shot_set_create();
  voters->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  state_add_item(state, voters);

  // Check dedup using the registered spec - should pass for new user
  operation_t* op = operation_create(CRABS_OP_CHECK_DEDUP);
  memset(op->uuid, 0x01, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 1;
  // Use the "vote" type for lookup - the check_dedup handler looks up the registered spec
  strncpy(op->type, "vote", CRABS_MAX_OP_NAME - 1);

  crabs_error_e result = state_machine_op_check_dedup(state, op);
  EXPECT_EQ(result, CRABS_SUCCESS);

  operation_destroy(op);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

TEST(DedupBuiltinOp, CheckDedupRejectsWithRegisteredSpec) {
  state_t* state = state_create();

  // Register a "vote" operation type with PER_USER dedup
  dedup_spec_t vote_spec;
  memset(&vote_spec, 0, sizeof(vote_spec));
  vote_spec.type = DEDUP_PER_USER;
  strncpy(vote_spec.tracker_path, "voters", CRABS_MAX_DEDUP_PATH - 1);
  state_register_op_type_def(state, "vote", &vote_spec);

  // Create the tracking set with alice already in it
  data_item_t* voters = data_item_create("voters", DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  voters->value = one_shot_set_create();
  voters->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  one_shot_set_add((one_shot_set_t*)voters->value, "alice");
  state_add_item(state, voters);

  // Check dedup - should fail for alice
  operation_t* op = operation_create("vote");
  memset(op->uuid, 0x01, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 1;

  crabs_error_e result = state_machine_op_check_dedup(state, op);
  EXPECT_EQ(result, CRABS_ERR_ALREADY_PERFORMED);

  operation_destroy(op);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

TEST(DedupBuiltinOp, CheckDedupNoSpecPasses) {
  state_t* state = state_create();

  // No registered spec for "unknown_op"
  operation_t* op = operation_create("unknown_op");
  memset(op->uuid, 0x01, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 1;

  crabs_error_e result = state_machine_op_check_dedup(state, op);
  EXPECT_EQ(result, CRABS_SUCCESS);

  operation_destroy(op);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

TEST(DedupBuiltinOp, CheckDedupInlineSpecOverridesRegistered) {
  state_t* state = state_create();

  // Register a "vote" operation type with PER_USER dedup
  dedup_spec_t vote_spec;
  memset(&vote_spec, 0, sizeof(vote_spec));
  vote_spec.type = DEDUP_PER_USER;
  strncpy(vote_spec.tracker_path, "voters", CRABS_MAX_DEDUP_PATH - 1);
  state_register_op_type_def(state, "vote", &vote_spec);

  // Create the tracking set with alice already in it
  data_item_t* voters = data_item_create("voters", DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  voters->value = one_shot_set_create();
  voters->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  one_shot_set_add((one_shot_set_t*)voters->value, "alice");
  state_add_item(state, voters);

  // Operation with DEDUP_NONE inline (default zero value) — check_dedup looks up
  // the registered spec for "vote" since inline is DEDUP_NONE
  operation_t* op = operation_create("vote");
  memset(op->uuid, 0x01, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 1;
  // dedup.type defaults to DEDUP_NONE — check_dedup uses registered spec

  // alice is already in the voters set, so the registered PER_USER spec should reject
  crabs_error_e result = state_machine_op_check_dedup(state, op);
  EXPECT_EQ(result, CRABS_ERR_ALREADY_PERFORMED);

  operation_destroy(op);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

TEST(DedupBuiltinOp, DefineOperationNoResourcesFails) {
  state_t* state = state_create();

  operation_t* op = operation_create(CRABS_OP_DEFINE_OPERATION);
  memset(op->uuid, 0x01, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 1;
  // No resources — should fail
  op->resource_count = 0;
  op->resources = NULL;
  op->dedup.type = DEDUP_PER_USER;

  crabs_error_e result = state_machine_op_define_operation(state, op);
  EXPECT_EQ(result, CRABS_ERR_INVALID_PARAM);

  operation_destroy(op);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

// ============================================================
// v1.4 §13 Test Vectors: Dedup Idempotency Scenarios
// ============================================================

// §13.1 PER_USER — First Vote Succeeds
TEST(TestVectorV14, PerUserFirstVoteSucceeds) {
  // Setup: proposal_42.voters = ONE_SHOT_SET({})
  state_t* state = state_create();
  data_item_t* voters = data_item_create("proposal_42_voters",
                                          DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  ASSERT_NE(voters, nullptr);
  voters->value = one_shot_set_create();
  voters->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  ASSERT_NE(voters->value, nullptr);
  state_add_item(state, voters);

  // Operation 1: type="vote", signer_id="alice", dedup={PER_USER, tracker_path="proposal_42_voters"}
  operation_t* op = operation_create("vote");
  ASSERT_NE(op, nullptr);
  memset(op->uuid, 0x01, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 1;
  op->dedup.type = DEDUP_PER_USER;
  strncpy(op->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);

  // Guard check: voters NOT CONTAINS alice? YES (empty)
  crabs_error_e guard = dedup_check_guard(state, op);
  EXPECT_EQ(guard, CRABS_SUCCESS);

  // Mutation: voters.add("alice")
  crabs_error_e mut = dedup_apply_mutation(state, op);
  EXPECT_EQ(mut, CRABS_SUCCESS);

  // Result: SUCCESS, voters = {"alice"}
  EXPECT_TRUE(one_shot_set_contains((one_shot_set_t*)voters->value, "alice"));
  EXPECT_EQ(one_shot_set_count((one_shot_set_t*)voters->value), 1u);

  operation_destroy(op);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

// §13.2 PER_USER — Second Vote Rejected
TEST(TestVectorV14, PerUserSecondVoteRejected) {
  // Setup: proposal_42.voters = ONE_SHOT_SET({"alice"})
  state_t* state = state_create();
  data_item_t* voters = data_item_create("proposal_42_voters",
                                          DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  ASSERT_NE(voters, nullptr);
  voters->value = one_shot_set_create();
  voters->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  ASSERT_NE(voters->value, nullptr);
  one_shot_set_add((one_shot_set_t*)voters->value, "alice");
  state_add_item(state, voters);

  // Operation 2: type="vote", signer_id="alice", dedup={PER_USER, tracker_path="proposal_42_voters"}
  operation_t* op = operation_create("vote");
  ASSERT_NE(op, nullptr);
  memset(op->uuid, 0x02, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 2;
  op->dedup.type = DEDUP_PER_USER;
  strncpy(op->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);

  // Guard check: voters NOT CONTAINS alice? NO (already in set)
  crabs_error_e guard = dedup_check_guard(state, op);
  EXPECT_EQ(guard, CRABS_ERR_ALREADY_PERFORMED);

  // Result: ALREADY_PERFORMED, voters = {"alice"} (unchanged)
  EXPECT_EQ(one_shot_set_count((one_shot_set_t*)voters->value), 1u);

  operation_destroy(op);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

// §13.3 PER_USER — Different User Can Vote
TEST(TestVectorV14, PerUserDifferentUserCanVote) {
  // Setup: proposal_42.voters = ONE_SHOT_SET({"alice"})
  state_t* state = state_create();
  data_item_t* voters = data_item_create("proposal_42_voters",
                                          DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  ASSERT_NE(voters, nullptr);
  voters->value = one_shot_set_create();
  voters->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  ASSERT_NE(voters->value, nullptr);
  one_shot_set_add((one_shot_set_t*)voters->value, "alice");
  state_add_item(state, voters);

  // Operation 3: type="vote", signer_id="bob", dedup={PER_USER, tracker_path="proposal_42_voters"}
  operation_t* op = operation_create("vote");
  ASSERT_NE(op, nullptr);
  memset(op->uuid, 0x03, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "bob", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 3;
  op->dedup.type = DEDUP_PER_USER;
  strncpy(op->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);

  // Guard check: voters NOT CONTAINS bob? YES
  crabs_error_e guard = dedup_check_guard(state, op);
  EXPECT_EQ(guard, CRABS_SUCCESS);

  // Mutation: voters.add("bob")
  crabs_error_e mut = dedup_apply_mutation(state, op);
  EXPECT_EQ(mut, CRABS_SUCCESS);

  // Result: SUCCESS, voters = {"alice", "bob"}
  EXPECT_TRUE(one_shot_set_contains((one_shot_set_t*)voters->value, "alice"));
  EXPECT_TRUE(one_shot_set_contains((one_shot_set_t*)voters->value, "bob"));
  EXPECT_EQ(one_shot_set_count((one_shot_set_t*)voters->value), 2u);

  operation_destroy(op);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

// §13.4 GLOBAL — First Execution Succeeds
TEST(TestVectorV14, GlobalFirstExecutionSucceeds) {
  // Setup: proposal_42.executed = ONE_SHOT_FLAG({value: false})
  state_t* state = state_create();
  data_item_t* flag = data_item_create("proposal_42_executed",
                                        DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
  ASSERT_NE(flag, nullptr);
  flag->value = one_shot_flag_create();
  flag->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  ASSERT_NE(flag->value, nullptr);
  state_add_item(state, flag);

  // Operation 1: type="execute_proposal", signer_id="carol", dedup={GLOBAL, flag_path="proposal_42_executed"}
  operation_t* op = operation_create("execute_proposal");
  ASSERT_NE(op, nullptr);
  memset(op->uuid, 0x04, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "carol", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 4;
  op->dedup.type = DEDUP_GLOBAL;
  strncpy(op->dedup.flag_path, "proposal_42_executed", CRABS_MAX_DEDUP_PATH - 1);

  // Guard check: executed == false? YES
  crabs_error_e guard = dedup_check_guard(state, op);
  EXPECT_EQ(guard, CRABS_SUCCESS);

  // Mutation: executed.set("carol")
  crabs_error_e mut = dedup_apply_mutation(state, op);
  EXPECT_EQ(mut, CRABS_SUCCESS);

  // Result: SUCCESS, executed = {value: true, set_by: "carol"}
  EXPECT_TRUE(one_shot_flag_value((one_shot_flag_t*)flag->value));
  EXPECT_STREQ(((one_shot_flag_t*)flag->value)->set_by, "carol");

  operation_destroy(op);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

// §13.5 GLOBAL — Second Execution Rejected
TEST(TestVectorV14, GlobalSecondExecutionRejected) {
  // Setup: proposal_42.executed = ONE_SHOT_FLAG({value: true, set_by: "carol"})
  state_t* state = state_create();
  data_item_t* flag = data_item_create("proposal_42_executed",
                                        DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
  ASSERT_NE(flag, nullptr);
  flag->value = one_shot_flag_create();
  flag->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  ASSERT_NE(flag->value, nullptr);
  one_shot_flag_set((one_shot_flag_t*)flag->value, "carol", 1);
  state_add_item(state, flag);

  // Operation 2: type="execute_proposal", signer_id="dave", dedup={GLOBAL, flag_path="proposal_42_executed"}
  operation_t* op = operation_create("execute_proposal");
  ASSERT_NE(op, nullptr);
  memset(op->uuid, 0x05, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "dave", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 5;
  op->dedup.type = DEDUP_GLOBAL;
  strncpy(op->dedup.flag_path, "proposal_42_executed", CRABS_MAX_DEDUP_PATH - 1);

  // Guard check: executed == false? NO (already true)
  crabs_error_e guard = dedup_check_guard(state, op);
  EXPECT_EQ(guard, CRABS_ERR_ALREADY_EXECUTED);

  // Result: ALREADY_EXECUTED, executed = {value: true, set_by: "carol"} (unchanged)
  EXPECT_TRUE(one_shot_flag_value((one_shot_flag_t*)flag->value));
  EXPECT_STREQ(((one_shot_flag_t*)flag->value)->set_by, "carol");

  operation_destroy(op);
  // Clean up CRDT values before state_destroy
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

// §13.6 CRDT Merge — Concurrent Votes
TEST(TestVectorV14, CrdtMergeConcurrentVotes) {
  // Setup: proposal_42.voters = ONE_SHOT_SET({})
  // Node A and Node B both receive Alice's vote concurrently

  // Create two independent states
  state_t* state_a = state_create();
  data_item_t* voters_a = data_item_create("proposal_42_voters",
                                            DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  ASSERT_NE(voters_a, nullptr);
  voters_a->value = one_shot_set_create();
  voters_a->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  ASSERT_NE(voters_a->value, nullptr);
  state_add_item(state_a, voters_a);

  state_t* state_b = state_create();
  data_item_t* voters_b = data_item_create("proposal_42_voters",
                                            DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  ASSERT_NE(voters_b, nullptr);
  voters_b->value = one_shot_set_create();
  voters_b->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  ASSERT_NE(voters_b->value, nullptr);
  state_add_item(state_b, voters_b);

  // Node A: alice votes — guard passes, mutation adds alice
  operation_t* op_a = operation_create("vote");
  ASSERT_NE(op_a, nullptr);
  memset(op_a->uuid, 0x0A, CRABS_UUID_SIZE);
  strncpy(op_a->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op_a->lamport_time = 10;
  op_a->dedup.type = DEDUP_PER_USER;
  strncpy(op_a->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);

  crabs_error_e guard_a = dedup_check_guard(state_a, op_a);
  EXPECT_EQ(guard_a, CRABS_SUCCESS);
  dedup_apply_mutation(state_a, op_a);
  // State A: voters = {"alice"}, count = 1

  // Node B: same operation from alice — guard passes (empty set)
  crabs_error_e guard_b = dedup_check_guard(state_b, op_a);
  EXPECT_EQ(guard_b, CRABS_SUCCESS);
  dedup_apply_mutation(state_b, op_a);
  // State B: voters = {"alice"}, count = 1

  // Merge: voters_a ∪ voters_b = {"alice"}
  one_shot_set_t* merged = one_shot_set_merge((one_shot_set_t*)voters_a->value,
                                               (one_shot_set_t*)voters_b->value);
  ASSERT_NE(merged, nullptr);

  // Result: Alice's vote counted ONCE
  EXPECT_TRUE(one_shot_set_contains(merged, "alice"));
  EXPECT_EQ(one_shot_set_count(merged), 1u);

  one_shot_set_destroy(merged);
  operation_destroy(op_a);
  for (data_item_t* it = state_a->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  for (data_item_t* it = state_b->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state_a);
  state_destroy(state_b);
}

// §13.7 CRDT Merge — Concurrent Different Users
TEST(TestVectorV14, CrdtMergeConcurrentDifferentUsers) {
  // Setup: proposal_42.voters = ONE_SHOT_SET({})

  // Create two independent states
  state_t* state_a = state_create();
  data_item_t* voters_a = data_item_create("proposal_42_voters",
                                            DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  ASSERT_NE(voters_a, nullptr);
  voters_a->value = one_shot_set_create();
  voters_a->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  ASSERT_NE(voters_a->value, nullptr);
  state_add_item(state_a, voters_a);

  state_t* state_b = state_create();
  data_item_t* voters_b = data_item_create("proposal_42_voters",
                                            DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  ASSERT_NE(voters_b, nullptr);
  voters_b->value = one_shot_set_create();
  voters_b->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  ASSERT_NE(voters_b->value, nullptr);
  state_add_item(state_b, voters_b);

  // Node A receives Alice's vote
  operation_t* op_alice = operation_create("vote");
  ASSERT_NE(op_alice, nullptr);
  memset(op_alice->uuid, 0x0B, CRABS_UUID_SIZE);
  strncpy(op_alice->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op_alice->lamport_time = 11;
  op_alice->dedup.type = DEDUP_PER_USER;
  strncpy(op_alice->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);

  dedup_check_guard(state_a, op_alice);
  dedup_apply_mutation(state_a, op_alice);
  // State A: voters = {"alice"}

  // Node B receives Bob's vote
  operation_t* op_bob = operation_create("vote");
  ASSERT_NE(op_bob, nullptr);
  memset(op_bob->uuid, 0x0C, CRABS_UUID_SIZE);
  strncpy(op_bob->signer_id, "bob", CRABS_MAX_USER_ID - 1);
  op_bob->lamport_time = 12;
  op_bob->dedup.type = DEDUP_PER_USER;
  strncpy(op_bob->dedup.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);

  dedup_check_guard(state_b, op_bob);
  dedup_apply_mutation(state_b, op_bob);
  // State B: voters = {"bob"}

  // Merge: {"alice"} ∪ {"bob"} = {"alice", "bob"}
  one_shot_set_t* merged = one_shot_set_merge((one_shot_set_t*)voters_a->value,
                                               (one_shot_set_t*)voters_b->value);
  ASSERT_NE(merged, nullptr);

  // Result: Both votes counted
  EXPECT_TRUE(one_shot_set_contains(merged, "alice"));
  EXPECT_TRUE(one_shot_set_contains(merged, "bob"));
  EXPECT_EQ(one_shot_set_count(merged), 2u);

  one_shot_set_destroy(merged);
  operation_destroy(op_alice);
  operation_destroy(op_bob);
  for (data_item_t* it = state_a->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  for (data_item_t* it = state_b->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state_a);
  state_destroy(state_b);
}