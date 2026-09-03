//
// Scheduler (timed transactions) tests.
//

#include <gtest/gtest.h>
#include <cstring>
#include <string>

extern "C" {
#include "Scheduler/scheduler.h"
#include "CRABS/data_model.h"
#include "StateMachine/state_machine.h"
#include "Serialization/serialization.h"
#include "Crypto/crypto.h"
#include "test_helpers.h"
}

static operation_t* make_counter_op(const char* op_type, const char* signer) {
  operation_t* op = operation_create(op_type);
  strncpy(op->signer_id, signer, CRABS_MAX_USER_ID - 1);
  return op;
}

TEST(SchedulerList, ScheduleStoresPendingEntry) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");

  uint64_t schedule_id = scheduler_schedule(env.state, 9999999, "admin", op);

  EXPECT_NE(schedule_id, 0u);
  EXPECT_EQ(scheduler_count(env.state), 1u);
  const scheduled_operation_t* pending = scheduler_first(env.state);
  ASSERT_NE(pending, nullptr);
  EXPECT_EQ(pending->schedule_id, schedule_id);
  EXPECT_EQ(pending->execute_at_ms, 9999999u);
  EXPECT_STREQ(pending->submitter, "admin");
  EXPECT_GT(pending->op_len, 0u);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerList, ScheduleRejectsInvalidInput) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");

  EXPECT_EQ(scheduler_schedule(env.state, 1000, NULL, op), 0u);
  EXPECT_EQ(scheduler_schedule(env.state, 1000, "", op), 0u);
  EXPECT_EQ(scheduler_schedule(env.state, 1000, "admin", NULL), 0u);
  EXPECT_EQ(scheduler_schedule(NULL, 1000, "admin", op), 0u);
  EXPECT_EQ(scheduler_count(env.state), 0u);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerList, ScheduleIdsAreMonotonic) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* first_op = make_counter_op("mint", "admin");
  operation_t* second_op = make_counter_op("mint", "admin");

  uint64_t first_id = scheduler_schedule(env.state, 1000, "admin", first_op);
  uint64_t second_id = scheduler_schedule(env.state, 2000, "admin", second_op);
  EXPECT_GT(second_id, first_id);
  EXPECT_EQ(scheduler_count(env.state), 2u);

  operation_destroy(first_op);
  operation_destroy(second_op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerList, CancelRemovesPendingEntry) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");

  uint64_t keep_id = scheduler_schedule(env.state, 1000, "admin", op);
  uint64_t drop_id = scheduler_schedule(env.state, 2000, "admin", op);
  EXPECT_EQ(scheduler_cancel(env.state, keep_id), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(env.state), 1u);
  EXPECT_EQ(scheduler_first(env.state)->schedule_id, drop_id);

  EXPECT_EQ(scheduler_cancel(env.state, 424242), CRABS_ERR_RESOURCE_NOT_FOUND);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerSerialization, PendingSetSurvivesRoundtrip) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");
  uint64_t schedule_id = scheduler_schedule(env.state, 1234567, "admin", op);
  operation_destroy(op);

  serialized_buffer_t* blob = crabs_serialize_state(env.state);
  ASSERT_NE(blob, nullptr);
  state_t* restored = crabs_deserialize_state(blob->data, blob->len);
  serialized_buffer_destroy(blob);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(scheduler_count(restored), 1u);
  const scheduled_operation_t* pending = scheduler_first(restored);
  ASSERT_NE(pending, nullptr);
  EXPECT_EQ(pending->schedule_id, schedule_id);
  EXPECT_EQ(pending->execute_at_ms, 1234567u);
  EXPECT_STREQ(pending->submitter, "admin");
  EXPECT_GT(pending->op_len, 0u);
  state_destroy(restored);

  crabs_test_env_destroy(&env);
}