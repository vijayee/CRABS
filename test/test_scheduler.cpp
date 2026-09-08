//
// Scheduler (timed transactions) tests.
//

#include <gtest/gtest.h>
#include <cstdint>
#include <cstring>
#include <string>

extern "C" {
#include "Scheduler/scheduler.h"
#include "CRABS/data_model.h"
#include "StateMachine/state_machine.h"
#include "Serialization/serialization.h"
#include "Crypto/crypto.h"
#include "Util/allocator.h"
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

TEST(SchedulerList, CancelMiddleEntryPreservesRest) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");
  uint64_t first_id = scheduler_schedule(env.state, 1000, "admin", op);
  uint64_t middle_id = scheduler_schedule(env.state, 2000, "admin", op);
  uint64_t last_id = scheduler_schedule(env.state, 3000, "admin", op);

  EXPECT_EQ(scheduler_cancel(env.state, middle_id), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(env.state), 2u);
  EXPECT_EQ(scheduler_first(env.state)->schedule_id, first_id);
  EXPECT_EQ(scheduler_cancel(env.state, middle_id), CRABS_ERR_RESOURCE_NOT_FOUND);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerSerialization, PendingSetSurvivesRoundtrip) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");
  uint64_t first_id = scheduler_schedule(env.state, 1000, "admin", op);
  uint64_t second_id = scheduler_schedule(env.state, 2000, "admin", op);
  uint64_t third_id = scheduler_schedule(env.state, 3000, "admin", op);
  operation_destroy(op);

  serialized_buffer_t* blob = crabs_serialize_state(env.state);
  ASSERT_NE(blob, nullptr);
  state_t* restored = crabs_deserialize_state(blob->data, blob->len);
  serialized_buffer_destroy(blob);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(scheduler_count(restored), 3u);
  // Submission order must be preserved across the roundtrip: the first entry
  // after restore is the earliest-scheduled one.
  const scheduled_operation_t* pending = scheduler_first(restored);
  ASSERT_NE(pending, nullptr);
  EXPECT_EQ(pending->schedule_id, first_id);
  EXPECT_EQ(pending->execute_at_ms, 1000u);
  EXPECT_STREQ(pending->submitter, "admin");
  EXPECT_GT(pending->op_len, 0u);
  pending = pending->next;
  ASSERT_NE(pending, nullptr);
  EXPECT_EQ(pending->schedule_id, second_id);
  EXPECT_EQ(pending->execute_at_ms, 2000u);
  pending = pending->next;
  ASSERT_NE(pending, nullptr);
  EXPECT_EQ(pending->schedule_id, third_id);
  EXPECT_EQ(pending->execute_at_ms, 3000u);
  state_destroy(restored);

  crabs_test_env_destroy(&env);
}

// Build a signed operation of the given type. "verify" is used because the
// test env registers a role:admin policy for it and the bootstrap admin
// satisfies that policy.
static operation_t* make_signed_view_op(crabs_test_env_t* env, const char* op_type) {
  operation_t* op = operation_create(op_type);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(env->state->attr_machine, env->admin_key, op);
  return op;
}

TEST(SchedulerValidate, ValidOpPassesWithoutApplying) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_signed_view_op(&env, CRABS_OP_VERIFY);
  uint64_t version_before = env.state->version;

  EXPECT_EQ(state_machine_validate(env.state, op), CRABS_SUCCESS);
  // Nothing applied: no log entry, version unchanged.
  EXPECT_EQ(env.state->log_count, 0u);
  EXPECT_EQ(env.state->version, version_before);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerValidate, BadSignatureRejectedWithoutApplying) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_signed_view_op(&env, CRABS_OP_VERIFY);
  op->signature[0] ^= 0xFF;

  EXPECT_EQ(state_machine_validate(env.state, op), CRABS_ERR_UNAUTHORIZED);
  EXPECT_EQ(env.state->log_count, 0u);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerValidate, MissingPolicyRejectedWithoutApplying) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_signed_view_op(&env, CRABS_OP_VERIFY);
  strncpy(op->type, "nosuchop", CRABS_MAX_OP_NAME - 1);
  memset(op->signature, 0, CRABS_SIG_SIZE);

  EXPECT_EQ(state_machine_validate(env.state, op), CRABS_ERR_UNAUTHORIZED);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerSerialization, ScheduleIdsContinueAfterRestore) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* first = make_counter_op("mint", "admin");
  uint64_t first_id = scheduler_schedule(env.state, 1000, "admin", first);
  operation_destroy(first);

  serialized_buffer_t* blob = crabs_serialize_state(env.state);
  ASSERT_NE(blob, nullptr);
  state_t* restored = crabs_deserialize_state(blob->data, blob->len);
  serialized_buffer_destroy(blob);
  ASSERT_NE(restored, nullptr);

  operation_t* second = make_counter_op("mint", "admin");
  uint64_t second_id = scheduler_schedule(restored, 2000, "admin", second);
  EXPECT_GT(second_id, first_id);  // must not collide with the restored entry's id
  // Also verify cancel targets the right entry: cancel the new id must not
  // remove the restored pending entry.
  EXPECT_EQ(scheduler_cancel(restored, second_id), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(restored), 1u);
  EXPECT_EQ(scheduler_first(restored)->schedule_id, first_id);
  operation_destroy(second);
  state_destroy(restored);
  crabs_test_env_destroy(&env);
}

// ============================================================
// Timed Transactions (v1): __schedule__ / __cancel_schedule__
// ============================================================

// The test env's state falls back to the unauthenticated system clock, so
// "future" must be a fixed epoch far enough ahead to stay stable on any
// machine (4000000000000 ms is roughly year 2096). "Past" is 1 ms.
static const uint64_t SCHEDULE_FUTURE_MS = 4000000000000ull;

// The env registers policies only for the builtin ops it knows about; the
// schedule ops and the custom embedded op type used below need explicit
// policies so the fail-closed authorization step passes for admin.
static void register_schedule_test_policies(crabs_test_env_t* env) {
  state_add_policy(env->state, CRABS_OP_SCHEDULE, "role:admin");
  state_add_policy(env->state, CRABS_OP_CANCEL_SCHEDULE, "role:admin");
  state_add_policy(env->state, "mint", "role:admin");
}

static void store_u64_le(uint8_t* out, uint64_t value) {
  for (int byte_index = 0; byte_index < 8; byte_index++) {
    out[byte_index] = (uint8_t)((value >> (byte_index * 8)) & 0xFF);
  }
}

static void store_u32_le(uint8_t* out, uint32_t value) {
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    out[byte_index] = (uint8_t)((value >> (byte_index * 8)) & 0xFF);
  }
}

// Payload layout for __schedule__: [u64 execute_at_ms LE][u32 op_len LE][op_bytes].
static void set_schedule_payload(operation_t* op, uint64_t execute_at_ms,
                                 const operation_t* embedded) {
  serialized_buffer_t* inner = crabs_serialize_operation(embedded);
  ASSERT_NE(inner, nullptr);
  uint32_t payload_len = 8 + 4 + (uint32_t)inner->len;
  uint8_t* payload = (uint8_t*)get_clear_memory(payload_len);
  store_u64_le(payload, execute_at_ms);
  store_u32_le(payload + 8, (uint32_t)inner->len);
  memcpy(payload + 12, inner->data, inner->len);
  serialized_buffer_destroy(inner);
  op->payload = payload;
  op->payload_size = payload_len;
}

// operation_create leaves the uuid all-zero, and the production entry points
// (CLI, wasm bindings) stamp random uuids that the test helpers skip. The
// materialization idempotency guard keys on the uuid, so every op below gets
// a distinct nonzero uuid or the guard matches the zero-uuid __schedule__ log
// entry and silently skips real materializations.
static uint64_t g_sched_uuid_counter = 0;

static void stamp_unique_uuid(operation_t* op) {
  g_sched_uuid_counter++;
  store_u64_le(op->uuid, g_sched_uuid_counter);
  memset(op->uuid + 8, 0xA7, CRABS_UUID_SIZE - 8);
}

static operation_t* make_schedule_op(crabs_test_env_t* env, uint64_t execute_at_ms,
                                     operation_t* embedded) {
  operation_t* op = operation_create(CRABS_OP_SCHEDULE);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  // The uuid is covered by the signature, so it must be stamped before
  // signing — a zero uuid would let the materialization guard (and later
  // replay checks) match the all-zero sentinel.
  stamp_unique_uuid(op);
  set_schedule_payload(op, execute_at_ms, embedded);
  crabs_test_sign_op_with(env->state->attr_machine, env->admin_key, op);
  return op;
}

TEST(SchedulerOps, ScheduleStoresPendingEntryAndLogs) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  operation_t* embedded = make_counter_op("mint", "admin");
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, embedded);

  operation_t* schedule_op = make_schedule_op(&env, SCHEDULE_FUTURE_MS, embedded);
  EXPECT_EQ(state_machine_execute(env.state, schedule_op), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(env.state), 1u);
  EXPECT_STREQ(scheduler_first(env.state)->submitter, "admin");
  EXPECT_GT(scheduler_first(env.state)->op_len, 0u);

  operation_destroy(schedule_op);
  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerOps, ScheduleInPastRejected) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  operation_t* embedded = make_counter_op("mint", "admin");
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, embedded);

  operation_t* schedule_op = make_schedule_op(&env, 1, embedded);
  EXPECT_EQ(state_machine_execute(env.state, schedule_op), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(scheduler_count(env.state), 0u);

  operation_destroy(schedule_op);
  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerOps, NestedScheduleRejected) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  operation_t* inner_schedule = operation_create(CRABS_OP_SCHEDULE);
  strncpy(inner_schedule->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, inner_schedule);

  operation_t* schedule_op = make_schedule_op(&env, SCHEDULE_FUTURE_MS, inner_schedule);
  EXPECT_EQ(state_machine_execute(env.state, schedule_op), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(scheduler_count(env.state), 0u);

  operation_destroy(schedule_op);
  operation_destroy(inner_schedule);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerOps, ScheduleWithInvalidEmbeddedOpRejected) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  operation_t* embedded = operation_create("nosuchop");
  strncpy(embedded->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, embedded);

  operation_t* schedule_op = make_schedule_op(&env, SCHEDULE_FUTURE_MS, embedded);
  EXPECT_EQ(state_machine_execute(env.state, schedule_op), CRABS_ERR_SCHEDULE_INVALID);
  EXPECT_EQ(scheduler_count(env.state), 0u);

  operation_destroy(schedule_op);
  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerOps, CancelScheduleRemovesPendingEntry) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  operation_t* embedded = make_counter_op("mint", "admin");
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, embedded);

  operation_t* schedule_op = make_schedule_op(&env, SCHEDULE_FUTURE_MS, embedded);
  ASSERT_EQ(state_machine_execute(env.state, schedule_op), CRABS_SUCCESS);
  uint64_t schedule_id = scheduler_first(env.state)->schedule_id;
  operation_destroy(schedule_op);

  // Cancel via a signed __cancel_schedule__ op carrying the 8-byte id.
  operation_t* cancel_op = operation_create(CRABS_OP_CANCEL_SCHEDULE);
  strncpy(cancel_op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  uint8_t* payload = (uint8_t*)get_clear_memory(8);
  store_u64_le(payload, schedule_id);
  cancel_op->payload = payload;
  cancel_op->payload_size = 8;
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, cancel_op);

  EXPECT_EQ(state_machine_execute(env.state, cancel_op), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(env.state), 0u);

  operation_destroy(cancel_op);
  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerOps, PendingEntryPreservesEmbeddedOpBytes) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  operation_t* embedded = make_counter_op("mint", "admin");
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, embedded);

  operation_t* schedule_op = make_schedule_op(&env, SCHEDULE_FUTURE_MS, embedded);
  ASSERT_EQ(state_machine_execute(env.state, schedule_op), CRABS_SUCCESS);

  serialized_buffer_t* expected = crabs_serialize_operation(embedded);
  ASSERT_NE(expected, nullptr);
  const scheduled_operation_t* pending = scheduler_first(env.state);
  ASSERT_EQ(pending->op_len, expected->len);
  EXPECT_EQ(memcmp(pending->op_bytes, expected->data, expected->len), 0);
  serialized_buffer_destroy(expected);

  operation_destroy(schedule_op);
  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerValidate, TransitionMismatchRejectedWithoutApplying) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  // A __lock__ op whose resource is in a non-IDLE state fails the
  // transition-feasibility branch of state_machine_validate. The lock must be
  // valid and unexpired — validate prunes expired locks first, which would
  // otherwise reset the resource to IDLE before the transition check runs.
  data_item_t* resource = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  ASSERT_EQ(state_add_item(env.state, resource), CRABS_SUCCESS);
  resource->protocol_state = PROTOCOL_LOCKED;  // op requires IDLE
  resource->lock_state.lock_token_valid = true;
  resource->lock_state.lock_expiry = UINT64_MAX;

  operation_t* op = operation_create(CRABS_OP_LOCK);
  op->resources =
      (char(*)[CRABS_MAX_USER_ID])get_clear_memory(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)get_clear_memory(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)get_clear_memory(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, op);

  EXPECT_EQ(state_machine_validate(env.state, op), CRABS_ERR_PROTOCOL_VIOLATION);
  EXPECT_EQ(env.state->log_count, 0u);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

// ============================================================
// Timed Transactions (v1): materialization (scheduler_process_due)
// ============================================================

// Mock time source so tests control the authenticated clock: with these ops
// installed, state_get_time_ms returns seconds*1000 + nanos/1e6.
static crabs_physical_time_t g_sched_mock_time = {0, 0, false};

static crabs_physical_time_t sched_mock_get_time(void* ctx) {
  (void)ctx;
  return g_sched_mock_time;
}

static bool sched_mock_is_available(void* ctx) {
  (void)ctx;
  return g_sched_mock_time.valid;
}

static crabs_time_source_ops_t g_sched_mock_ops = {
  sched_mock_get_time, sched_mock_is_available, NULL
};

TEST(SchedulerMaterialize, DueOpMaterializedExactlyOnce) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);

  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);

  // execute_at just past the mock's 1000000000 ms so __schedule__ accepts it
  // AND the due tick finds it.
  operation_t* schedule_op = make_schedule_op(&env, 1000005000, embedded);
  ASSERT_EQ(state_machine_execute(state, schedule_op), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 1u);

  // Not due yet.
  ASSERT_EQ(scheduler_process_due(state, 1000004999u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 1u);

  // Due: materializes.
  ASSERT_EQ(scheduler_process_due(state, 1000005000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 0u);

  // Idempotent: a second tick is a no-op.
  ASSERT_EQ(scheduler_process_due(state, 1000006000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 0u);

  // The embedded op's uuid appears in the log exactly once.
  uint32_t uuid_matches = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (memcmp(state->log[entry_index].uuid, embedded->uuid, CRABS_UUID_SIZE) == 0) {
      uuid_matches++;
    }
  }
  EXPECT_EQ(uuid_matches, 1u);

  operation_destroy(embedded);
  operation_destroy(schedule_op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerMaterialize, SignerSubsequentOpsNotBlockedByReplayGuard) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
  operation_t* schedule_op = make_schedule_op(&env, 1000005000, embedded);
  ASSERT_EQ(state_machine_execute(state, schedule_op), CRABS_SUCCESS);

  // Signer does a normal op NOW (after scheduling, before materialization).
  operation_t* direct = make_counter_op("mint", "admin");
  stamp_unique_uuid(direct);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, direct);
  ASSERT_EQ(state_machine_execute(state, direct), CRABS_SUCCESS);
  operation_destroy(direct);

  // Materialize: must not trip any replay guard.
  g_sched_mock_time.seconds = 1000005;
  EXPECT_EQ(scheduler_process_due(state, 1000005000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 0u);

  operation_destroy(embedded);
  operation_destroy(schedule_op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerMaterialize, FailedMaterializationRecordedNotPropagated) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  data_item_t* resource = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* value = (int64_t*)get_clear_memory(sizeof(int64_t));
  *value = 5;
  resource->value = value;
  ASSERT_EQ(state_add_item(state, resource), CRABS_SUCCESS);

  // Signed __lock__ op on "res1" (IDLE → LOCKED), mirroring
  // test/test_co_sign.cpp's make_lock_op_signed.
  operation_t* embedded = operation_create(CRABS_OP_LOCK);
  embedded->resources =
      (char(*)[CRABS_MAX_USER_ID])get_clear_memory(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(embedded->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  embedded->resource_count = 1;
  embedded->required_state = (protocol_state_e*)get_clear_memory(sizeof(protocol_state_e));
  embedded->required_state[0] = PROTOCOL_IDLE;
  embedded->next_state = (protocol_state_e*)get_clear_memory(sizeof(protocol_state_e));
  embedded->next_state[0] = PROTOCOL_LOCKED;
  strncpy(embedded->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);

  operation_t* schedule_op = make_schedule_op(&env, 1000005000, embedded);
  ASSERT_EQ(state_machine_execute(state, schedule_op), CRABS_SUCCESS);

  // State drift: lock the resource directly before materialization. The lock
  // must look valid and unexpired so state_machine_prune_expired (which runs
  // inside the tick) does not reset the item to IDLE — otherwise the
  // scheduled __lock__ would succeed instead of failing. The test env has no
  // ordering config, so state_machine_lock_expired falls back to
  // now_ms >= lock_expiry and UINT64_MAX holds through both prunes.
  resource->protocol_state = PROTOCOL_LOCKED;
  resource->lock_state.lock_token_valid = true;
  memset(resource->lock_state.lock_token, 0xAB, CRABS_LOCK_TOKEN_SIZE);
  resource->lock_state.lock_expiry = UINT64_MAX;

  // A normal user op executes at the same tick (the tick runs at the end of
  // its execute pipeline) and MUST still succeed even though the scheduled
  // materialization fails.
  g_sched_mock_time.seconds = 1000005;
  operation_t* unrelated = make_counter_op("mint", "admin");
  stamp_unique_uuid(unrelated);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, unrelated);
  EXPECT_EQ(state_machine_execute(state, unrelated), CRABS_SUCCESS);

  // The failure is recorded: exactly one __schedule_failed__ log entry whose
  // uuid matches the embedded op, and the pending entry is consumed.
  uint32_t failure_records = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "__schedule_failed__") == 0 &&
        memcmp(state->log[entry_index].uuid, embedded->uuid, CRABS_UUID_SIZE) == 0) {
      failure_records++;
    }
  }
  EXPECT_EQ(failure_records, 1u);
  EXPECT_EQ(scheduler_count(state), 0u);

  operation_destroy(unrelated);
  operation_destroy(embedded);
  operation_destroy(schedule_op);
  crabs_test_env_destroy(&env);
}

// R7-11: a __schedule_failed__ record is LAMPORT-ordered with lamport 0 and
// lands at the tail of the log. The replay watermark must consider ALL of the
// signer's entries and skip system records, so a failed materialization never
// lets the signer replay an op that is already in the log.
TEST(SchedulerMaterialize, FailureRecordDoesNotRegressReplayWatermark) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  // Signer executes a normal op (lamport stamped by the test helper, entry
  // logged). Replaying this exact op later must be rejected.
  operation_t* first = make_counter_op("mint", "admin");
  stamp_unique_uuid(first);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, first);
  ASSERT_EQ(state_machine_execute(state, first), CRABS_SUCCESS);

  // A scheduled op by the same signer fails at materialization: a signed
  // __lock__ on "res1" (IDLE → LOCKED), mirroring
  // FailedMaterializationRecordedNotPropagated's drift pattern.
  data_item_t* resource = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  ASSERT_EQ(state_add_item(state, resource), CRABS_SUCCESS);
  operation_t* doomed = operation_create(CRABS_OP_LOCK);
  doomed->resources =
      (char(*)[CRABS_MAX_USER_ID])get_clear_memory(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(doomed->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  doomed->resource_count = 1;
  doomed->required_state = (protocol_state_e*)get_clear_memory(sizeof(protocol_state_e));
  doomed->required_state[0] = PROTOCOL_IDLE;
  doomed->next_state = (protocol_state_e*)get_clear_memory(sizeof(protocol_state_e));
  doomed->next_state[0] = PROTOCOL_LOCKED;
  strncpy(doomed->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  stamp_unique_uuid(doomed);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, doomed);

  operation_t* schedule_op = make_schedule_op(&env, 1000005000, doomed);
  ASSERT_EQ(state_machine_execute(state, schedule_op), CRABS_SUCCESS);

  // State drift: "res1" is already locked by someone else with a valid,
  // unexpired lock, so the scheduled __lock__ fails the transition check
  // (op requires IDLE). The lock must look valid and unexpired so
  // state_machine_prune_expired does not reset the item to IDLE.
  resource->protocol_state = PROTOCOL_LOCKED;
  resource->lock_state.lock_token_valid = true;
  memset(resource->lock_state.lock_token, 0xAB, CRABS_LOCK_TOKEN_SIZE);
  resource->lock_state.lock_expiry = UINT64_MAX;

  // Tick: materialization fails and a __schedule_failed__ record (lamport 0,
  // signer "admin") lands at the tail of the log.
  ASSERT_EQ(scheduler_process_due(state, 1000005000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 0u);
  bool failure_recorded = false;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "__schedule_failed__") == 0 &&
        memcmp(state->log[entry_index].uuid, doomed->uuid, CRABS_UUID_SIZE) == 0) {
      failure_recorded = true;
    }
  }
  ASSERT_TRUE(failure_recorded);

  // Replay `first` (same op object, so the same uuid and lamport): the
  // tail-most signer entry is now the lamport-0 failure record, but the
  // signer's own earlier entry still makes this op a replay. The in-memory
  // test env has no tx_manager, so the ordering check is the only guard.
  EXPECT_EQ(state_machine_execute(state, first), CRABS_ERR_ALREADY_EXECUTED);

  operation_destroy(first);
  operation_destroy(doomed);
  operation_destroy(schedule_op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerMaterialize, AlreadyAppliedOpSkipsIdempotently) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);

  // Execute the embedded op normally FIRST (uuid lands in the log).
  ASSERT_EQ(state_machine_execute(state, embedded), CRABS_SUCCESS);

  // Schedule the SAME op for the future.
  operation_t* schedule_op = make_schedule_op(&env, 1000005000, embedded);
  ASSERT_EQ(state_machine_execute(state, schedule_op), CRABS_SUCCESS);

  // Tick: the uuid is already in the log → idempotent skip, no failure record.
  g_sched_mock_time.seconds = 1000005;
  ASSERT_EQ(scheduler_process_due(state, 1000005000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 0u);

  uint32_t uuid_matches = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (memcmp(state->log[entry_index].uuid, embedded->uuid, CRABS_UUID_SIZE) == 0) {
      uuid_matches++;
    }
  }
  EXPECT_EQ(uuid_matches, 1u);  // the direct execution only

  operation_destroy(embedded);
  operation_destroy(schedule_op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerOps, MalformedSchedulePayloadsRejected) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);

  // payload_size == 12 with no embedded op bytes
  operation_t* op = operation_create(CRABS_OP_SCHEDULE);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  uint8_t* payload = (uint8_t*)get_clear_memory(12);
  store_u64_le(payload, SCHEDULE_FUTURE_MS);
  store_u32_le(payload + 8, 0);
  op->payload = payload;
  op->payload_size = 12;
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, op);
  EXPECT_EQ(state_machine_execute(env.state, op), CRABS_ERR_INVALID_PARAM);
  operation_destroy(op);

  // inner_len lies: claims 4 bytes, payload carries 8
  op = operation_create(CRABS_OP_SCHEDULE);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  payload = (uint8_t*)get_clear_memory(20);
  store_u64_le(payload, SCHEDULE_FUTURE_MS);
  store_u32_le(payload + 8, 4);
  memset(payload + 12, 0xAB, 8);
  op->payload = payload;
  op->payload_size = 20;
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, op);
  EXPECT_EQ(state_machine_execute(env.state, op), CRABS_ERR_INVALID_PARAM);
  operation_destroy(op);

  // huge inner_len targeting the uint32 wrap in 12 + inner_len
  op = operation_create(CRABS_OP_SCHEDULE);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  payload = (uint8_t*)get_clear_memory(16);
  store_u64_le(payload, SCHEDULE_FUTURE_MS);
  store_u32_le(payload + 8, 0xFFFFFFF4u);
  memset(payload + 12, 0xAB, 4);
  op->payload = payload;
  op->payload_size = 16;
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, op);
  EXPECT_EQ(state_machine_execute(env.state, op), CRABS_ERR_INVALID_PARAM);
  operation_destroy(op);

  // wrong-size __cancel_schedule__ payload
  op = operation_create(CRABS_OP_CANCEL_SCHEDULE);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  payload = (uint8_t*)get_clear_memory(4);
  memset(payload, 0, 4);
  op->payload = payload;
  op->payload_size = 4;
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, op);
  EXPECT_EQ(state_machine_execute(env.state, op), CRABS_ERR_INVALID_PARAM);
  operation_destroy(op);

  EXPECT_EQ(scheduler_count(env.state), 0u);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerRecurring, ScheduleRecurringStoresCadence) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");

  uint64_t schedule_id = scheduler_schedule_recurring(
      env.state, 1000000000, 60000, 5, 0, "admin", op);

  EXPECT_NE(schedule_id, 0u);
  const scheduled_operation_t* pending = scheduler_first(env.state);
  ASSERT_NE(pending, nullptr);
  EXPECT_EQ(pending->schedule_id, schedule_id);
  EXPECT_EQ(pending->execute_at_ms, 1000000000u);
  EXPECT_EQ(pending->interval_ms, 60000u);
  EXPECT_EQ(pending->repeat_count, 5u);
  EXPECT_EQ(pending->end_at_ms, 0u);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerRecurring, RecurringValidationRejections) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");

  // interval 0 is meaningless
  EXPECT_EQ(scheduler_schedule_recurring(env.state, 1000, 0, 5, 0, "admin", op), 0u);
  // end_at must be strictly after start_at (or 0 = none)
  EXPECT_EQ(scheduler_schedule_recurring(env.state, 1000000000, 60000, 5,
                                         999999, "admin", op), 0u);
  EXPECT_EQ(scheduler_schedule_recurring(env.state, 1000000000, 60000, 5,
                                         1000000000, "admin", op), 0u);
  // plain invalid-input guards still apply
  EXPECT_EQ(scheduler_schedule_recurring(NULL, 1000, 60000, 5, 0, "admin", op), 0u);
  EXPECT_EQ(scheduler_schedule_recurring(env.state, 1000, 60000, 5, 0, NULL, op), 0u);
  EXPECT_EQ(scheduler_count(env.state), 0u);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerSerialization, RecurringFieldsSurviveRoundtrip) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");
  uint64_t schedule_id = scheduler_schedule_recurring(
      env.state, 1000000000, 60000, 5, 2000000000, "admin", op);
  operation_destroy(op);

  serialized_buffer_t* blob = crabs_serialize_state(env.state);
  ASSERT_NE(blob, nullptr);
  state_t* restored = crabs_deserialize_state(blob->data, blob->len);
  serialized_buffer_destroy(blob);
  ASSERT_NE(restored, nullptr);

  const scheduled_operation_t* pending = scheduler_first(restored);
  ASSERT_NE(pending, nullptr);
  EXPECT_EQ(pending->schedule_id, schedule_id);
  EXPECT_EQ(pending->interval_ms, 60000u);
  EXPECT_EQ(pending->repeat_count, 5u);
  EXPECT_EQ(pending->end_at_ms, 2000000000u);
  state_destroy(restored);

  crabs_test_env_destroy(&env);
}

TEST(SchedulerRecurring, FiresOnCadenceUntilCountExhausted) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
  uint64_t schedule_id = scheduler_schedule_recurring(
      state, 1000001000, 1000, 3, 0, "admin", embedded);
  ASSERT_NE(schedule_id, 0u);

  // One tick fires all three slots (1000001000, 2000, 3000) in order; the
  // series is exhausted after the third fire and the entry is removed.
  ASSERT_EQ(scheduler_process_due(state, 1000003000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 0u);

  uint32_t mint_entries = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "mint") == 0) mint_entries++;
  }
  EXPECT_EQ(mint_entries, 3u);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

// Regression: each occurrence needs an identity distinct from every earlier
// fire, even across separate ticks. Deriving occurrences from the bare
// embedded uuid made every tick's first occurrence collide with the log
// entry a previous tick's fire wrote, so only the first slot ever applied.
TEST(SchedulerRecurring, FiresAcrossSeparateTicksWithDistinctIdentity) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
  uint64_t schedule_id = scheduler_schedule_recurring(
      state, 1000001000, 1000, 3, 0, "admin", embedded);
  ASSERT_NE(schedule_id, 0u);

  // One tick per slot (no catch-up): each tick must apply its slot, not skip
  // it as already-in-log.
  ASSERT_EQ(scheduler_process_due(state, 1000001000u), CRABS_SUCCESS);
  ASSERT_EQ(scheduler_count(state), 1u);
  ASSERT_EQ(scheduler_process_due(state, 1000002000u), CRABS_SUCCESS);
  ASSERT_EQ(scheduler_count(state), 1u);
  ASSERT_EQ(scheduler_process_due(state, 1000003000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 0u);

  uint32_t mint_entries = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "mint") == 0) mint_entries++;
  }
  EXPECT_EQ(mint_entries, 3u);

  // Every occurrence carries a distinct uuid.
  uint32_t duplicate_uuids = 0;
  for (uint64_t entry_a = 0; entry_a < state->log_count; entry_a++) {
    for (uint64_t entry_b = entry_a + 1; entry_b < state->log_count; entry_b++) {
      if (memcmp(state->log[entry_a].uuid, state->log[entry_b].uuid,
                 CRABS_UUID_SIZE) == 0) {
        duplicate_uuids++;
      }
    }
  }
  EXPECT_EQ(duplicate_uuids, 0u);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerRecurring, EndAtTerminatesBeforeNextFire) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
  ASSERT_NE(scheduler_schedule_recurring(
      state, 1000001000, 1000, 0, 1000002000, "admin", embedded), 0u);

  // Slots 1000001000 and 1000002000 fire (both <= end_at); the next slot
  // (1000003000) is past end_at → entry removed, no third fire.
  ASSERT_EQ(scheduler_process_due(state, 1000003000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 0u);

  uint32_t mint_entries = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "mint") == 0) mint_entries++;
  }
  EXPECT_EQ(mint_entries, 2u);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerRecurring, CatchUpFiresAllMissedSlotsInOrder) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
  ASSERT_NE(scheduler_schedule_recurring(
      state, 1000001000, 1000, 0, 0, "admin", embedded), 0u);

  // Tick BETWEEN slots (1000005500) so slots 1000001000..5000 fire (5 fires)
  // and slot 1000006000 stays future.
  ASSERT_EQ(scheduler_process_due(state, 1000005500u), CRABS_SUCCESS);
  uint32_t mint_entries = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "mint") == 0) mint_entries++;
  }
  EXPECT_EQ(mint_entries, 5u);

  // Infinite series stays resident with execute_at advanced to the next slot.
  ASSERT_EQ(scheduler_count(state), 1u);
  EXPECT_EQ(scheduler_first(state)->execute_at_ms, 1000006000u);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

// Audit follow-up: an unbounded catch-up burst. With a budget of 2, a tick
// that would fire 5 missed slots fires exactly 2 and leaves the series
// resident on the NEXT unfired slot; a later tick resumes exactly where it
// stopped (no slot skipped, no slot double-fired).
TEST(SchedulerRecurring, BudgetLimitsCatchUpWithCarryOver) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
  ASSERT_NE(scheduler_schedule_recurring(
      state, 1000001000, 1000, 0, 0, "admin", embedded), 0u);

  scheduler_set_max_occurrences_per_tick(state, 2);

  // First tick: slots 1000001000 and 1000002000 fire; slot 1000003000 is the
  // next unfired slot the entry now rests on.
  ASSERT_EQ(scheduler_process_due(state, 1000005500u), CRABS_SUCCESS);
  uint32_t mint_entries = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "mint") == 0) mint_entries++;
  }
  EXPECT_EQ(mint_entries, 2u);
  ASSERT_EQ(scheduler_count(state), 1u);
  EXPECT_EQ(scheduler_first(state)->execute_at_ms, 1000003000u);

  // Second tick at the SAME time: budget applies per tick, so the next two
  // slots fire and the entry carries over again.
  ASSERT_EQ(scheduler_process_due(state, 1000005500u), CRABS_SUCCESS);
  mint_entries = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "mint") == 0) mint_entries++;
  }
  EXPECT_EQ(mint_entries, 4u);
  EXPECT_EQ(scheduler_first(state)->execute_at_ms, 1000005000u);

  // Unlimited budget (0): the remaining slot fires immediately.
  scheduler_set_max_occurrences_per_tick(state, 0);
  ASSERT_EQ(scheduler_process_due(state, 1000005500u), CRABS_SUCCESS);
  mint_entries = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "mint") == 0) mint_entries++;
  }
  EXPECT_EQ(mint_entries, 5u);
  EXPECT_EQ(scheduler_first(state)->execute_at_ms, 1000006000u);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

// Budget 0 is the explicit unlimited escape hatch: a long catch-up fires
// every missed slot in a single tick, exactly as before the budget existed.
TEST(SchedulerRecurring, ZeroBudgetMeansUnlimited) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
  ASSERT_NE(scheduler_schedule_recurring(
      state, 1000001000, 1000, 0, 0, "admin", embedded), 0u);

  scheduler_set_max_occurrences_per_tick(state, 0);

  ASSERT_EQ(scheduler_process_due(state, 1000005500u), CRABS_SUCCESS);
  uint32_t mint_entries = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "mint") == 0) mint_entries++;
  }
  EXPECT_EQ(mint_entries, 5u);
  EXPECT_EQ(scheduler_first(state)->execute_at_ms, 1000006000u);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

// The budget also caps one-shot schedules: with 3 due one-shots and a budget
// of 2, only 2 materialize this tick and the third stays pending.
TEST(SchedulerRecurring, BudgetLimitsOneShotFires) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  for (uint32_t op_index = 0; op_index < 3; op_index++) {
    operation_t* embedded = make_counter_op("mint", "admin");
    stamp_unique_uuid(embedded);
    crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
    ASSERT_NE(scheduler_schedule(
        state, 1000001000 + op_index, "admin", embedded), 0u);
    operation_destroy(embedded);
  }

  scheduler_set_max_occurrences_per_tick(state, 2);

  ASSERT_EQ(scheduler_process_due(state, 1000001100u), CRABS_SUCCESS);
  uint32_t mint_entries = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "mint") == 0) mint_entries++;
  }
  EXPECT_EQ(mint_entries, 2u);
  ASSERT_EQ(scheduler_count(state), 1u);

  // Next tick materializes the deferred one-shot.
  ASSERT_EQ(scheduler_process_due(state, 1000001100u), CRABS_SUCCESS);
  mint_entries = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "mint") == 0) mint_entries++;
  }
  EXPECT_EQ(mint_entries, 3u);
  EXPECT_EQ(scheduler_count(state), 0u);

  crabs_test_env_destroy(&env);
}

// ============================================================
// UAF regression: a handler cancels the recurring series it is
// materialized from, while the tick loop is advancing the cadence.
// ============================================================

// The handler below must cancel the series' own schedule id, captured after
// scheduling (ids are assigned by the scheduler, so the test reads it back).
static uint64_t g_cancel_schedule_id = 0;

// A handler for 'mint' that cancels the recurring schedule mid-fire. The
// scheduler unlinks AND frees the entry inside this call, so the tick loop
// must re-find the entry before touching it again.
static crabs_error_e cancel_own_series_handler(state_t* state, operation_t* op) {
  (void)op;
  return scheduler_cancel(state, g_cancel_schedule_id);
}

TEST(SchedulerRecurring, HandlerCancelDuringFireIsSafe) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);

  // Infinite series (repeat_count 0) with 1000 ms cadence so several slots
  // are due within one tick: the first fire's handler cancels the entry.
  uint64_t schedule_id = scheduler_schedule_recurring(
      state, 1000001000, 1000, 0, 0, "admin", embedded);
  ASSERT_NE(schedule_id, 0u);
  g_cancel_schedule_id = schedule_id;

  // Re-register 'mint' so the materialized occurrence cancels its own series.
  ASSERT_EQ(state_machine_register_handler(state, "mint",
                                           cancel_own_series_handler),
            CRABS_SUCCESS);

  // Two slots are due (1000001000, 1000002000). The first fire's handler
  // cancels the series: the loop must stop cleanly without touching the
  // freed entry, and the function must return success with the re-entrancy
  // flag cleared.
  ASSERT_EQ(scheduler_process_due(state, 1000002500u), CRABS_SUCCESS);

  EXPECT_EQ(scheduler_count(state), 0u);
  EXPECT_FALSE(state->scheduler_ticking);

  // Exactly one fire happened (the second slot never fires after the cancel).
  uint32_t mint_entries = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "mint") == 0) mint_entries++;
  }
  EXPECT_EQ(mint_entries, 1u);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerRecurring, FailureDoesNotTerminateSeries) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  // Signed __lock__ op on "res1" that will fail at materialization
  // (resource re-locked with a valid unexpired lock so prune keeps it LOCKED).
  data_item_t* resource = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* value = (int64_t*)get_clear_memory(sizeof(int64_t));
  *value = 5;
  resource->value = value;
  ASSERT_EQ(state_add_item(state, resource), CRABS_SUCCESS);

  operation_t* embedded = operation_create(CRABS_OP_LOCK);
  embedded->resources =
      (char(*)[CRABS_MAX_USER_ID])get_clear_memory(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(embedded->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  embedded->resource_count = 1;
  embedded->required_state = (protocol_state_e*)get_clear_memory(sizeof(protocol_state_e));
  embedded->required_state[0] = PROTOCOL_IDLE;
  embedded->next_state = (protocol_state_e*)get_clear_memory(sizeof(protocol_state_e));
  embedded->next_state[0] = PROTOCOL_LOCKED;
  strncpy(embedded->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);

  ASSERT_NE(scheduler_schedule_recurring(state, 1000001000, 1000, 0, 0,
                                         "admin", embedded), 0u);

  // Drift: lock the resource (valid unexpired lock survives pruning).
  resource->protocol_state = PROTOCOL_LOCKED;
  resource->lock_state.lock_token_valid = true;
  memset(resource->lock_state.lock_token, 0xAB, CRABS_LOCK_TOKEN_SIZE);
  resource->lock_state.lock_expiry = UINT64_MAX;

  // Two due slots fire, both fail; the series CONTINUES (2 failure records,
  // entry still resident, cadence advanced).
  ASSERT_EQ(scheduler_process_due(state, 1000002500u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 1u);
  EXPECT_EQ(scheduler_first(state)->execute_at_ms, 1000003000u);

  uint32_t failure_records = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "__schedule_failed__") == 0) {
      failure_records++;
    }
  }
  EXPECT_EQ(failure_records, 2u);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

// Change notification: the submission itself fires one SCHEDULE event, then
// each materialized slot fires another; budget-deferred slots fire nothing
// until they actually fire.
TEST(SchedulerRecurring, ChangeHookFiresPerMaterializedSlot) {
  static int schedule_event_count;
  schedule_event_count = 0;

  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  scheduler_set_max_occurrences_per_tick(state, 2);
  state_set_change_hook(state, [](state_t* hook_state,
                                  const crabs_change_event_t* event,
                                  void* user_data) {
    (void)hook_state; (void)user_data;
    if (event->kind == CRABS_CHANGE_SCHEDULE) schedule_event_count++;
  }, nullptr);

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
  ASSERT_NE(scheduler_schedule_recurring(
      state, 1000001000, 1000, 3, 0, "admin", embedded), 0u);
  operation_destroy(embedded);

  ASSERT_EQ(scheduler_process_due(state, 1000003000u), CRABS_SUCCESS);
  // One event from the submission, one per materialized slot (the per-tick
  // cap of 2 leaves the third slot for a later tick).
  EXPECT_EQ(schedule_event_count, 3);
  state_set_change_hook(state, nullptr, nullptr);
  crabs_test_env_destroy(&env);
}

// Audit finding: the schedule SUBMISSION change event passed node_id NULL,
// so it rendered as "node":"" and never matched any per-node listener filter
// (and the per-node ring drain). The event must carry the same attribution
// the scheduler's failure sites use: the node's HLC node id, or the
// bootstrap admin on lamport-only nodes.
TEST(SchedulerList, SubmissionChangeEventCarriesNodeId) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  state_t* state = env.state;

  // HLC-initialized node: the submission event must carry the HLC node id.
  crabs_hlc_state_init(&state->hlc_state, "admin-node");
  state->hlc_state_initialized = true;

  static char captured_node[CRABS_MAX_USER_ID];
  static bool submission_event_seen;
  captured_node[0] = '\0';
  submission_event_seen = false;
  state_set_change_hook(state, [](state_t* hook_state,
                                  const crabs_change_event_t* event,
                                  void* user_data) {
    (void)hook_state; (void)user_data;
    if (event->kind == CRABS_CHANGE_SCHEDULE && !submission_event_seen) {
      submission_event_seen = true;
      if (event->node_id != NULL) {
        strncpy(captured_node, event->node_id, CRABS_MAX_USER_ID - 1);
        captured_node[CRABS_MAX_USER_ID - 1] = '\0';
      }
    }
  }, nullptr);

  operation_t* op = make_counter_op("mint", "admin");
  ASSERT_NE(scheduler_schedule(state, 9999999, "admin", op), 0u);
  operation_destroy(op);

  state_set_change_hook(state, nullptr, nullptr);

  // The FIRST SCHEDULE-kind event is the submission (materialization events
  // only fire on a later tick) — it must carry the node id, never NULL.
  EXPECT_TRUE(submission_event_seen);
  EXPECT_STREQ(captured_node, "admin-node");

  crabs_test_env_destroy(&env);
}
