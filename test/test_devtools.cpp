//
// Devtools tests: event ring buffer, drain JSON, snapshot JSON.
//

#include <gtest/gtest.h>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>

extern "C" {
#include "Devtools/devtools.h"
#include "Lineage/lineage.h"
#include "CRABS/data_model.h"
#include "StateMachine/state_machine.h"
#include "Trigger/trigger.h"
#include "CRDT/crdt_merge.h"
#include "CRDT/one_shot.h"
#include "Scheduler/scheduler.h"
#include "test_helpers.h"
}

static state_t* make_state_with_g_counter(void) {
  state_t* state = state_create();
  data_item_t* item = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  item->value = g_counter_create();
  g_counter_increment((g_counter_t*)item->value, "alice", 12);
  state_add_item(state, item);
  return state;
}

static operation_t* make_operation(const char* type, const char* signer) {
  operation_t* op = operation_create(type);
  strncpy(op->signer_id, signer, CRABS_MAX_USER_ID - 1);
  op->lamport_time = 87;
  return op;
}

// Build the change event a state-mutating completion would carry and record
// it through the layered recorder (the shape crabs_wasm_execute's hook sees).
static void record_op_event(state_t* state, const operation_t* op,
                            crabs_error_e result) {
  crabs_change_event_t event;
  memset(&event, 0, sizeof(event));
  event.kind = CRABS_CHANGE_OP;
  event.type = op->type;
  event.uuid = op->uuid;
  event.signer_id = op->signer_id;
  event.node_id = op->node_id;
  if (op->resource_count > 0 && op->resources != NULL) {
    event.target = op->resources[0];
  }
  event.result = result;
  event.lamport_time = op->lamport_time;
  if (op->ordering_system == CRABS_ORDERING_HLC) {
    event.has_hlc = true;
    event.hlc = op->hlc;
  }
  devtools_record_change(state, &event);
}

// Registration shape crabs_wasm_node_create uses: every mutation the state
// reports lands in the devtools ring.
static void test_devtools_change_hook(state_t* state,
                                      const crabs_change_event_t* event,
                                      void* user_data) {
  (void)user_data;
  devtools_record_change(state, event);
}

TEST(DevtoolsEvents, RecordThenDrainProducesJsonArray) {
  state_t* state = make_state_with_g_counter();
  operation_t* op = make_operation("increment", "bob");

  record_op_event(state, op, CRABS_SUCCESS);

  char* json = devtools_events_json();
  ASSERT_NE(json, nullptr);
  std::string text = json;
  devtools_string_destroy(json);

  EXPECT_NE(text.find("\"op_type\":\"increment\""), std::string::npos);
  EXPECT_NE(text.find("\"signer\":\"bob\""), std::string::npos);
  EXPECT_NE(text.find("\"result\":\"accepted\""), std::string::npos);
  EXPECT_NE(text.find("\"lamport\":87"), std::string::npos);
  EXPECT_EQ(text.front(), '[');
  EXPECT_EQ(text.back(), ']');

  operation_destroy(op);
  state_destroy(state);
}

TEST(DevtoolsEvents, DrainEmptiesBuffer) {
  state_t* state = make_state_with_g_counter();
  operation_t* op = make_operation("increment", "bob");
  record_op_event(state, op, CRABS_SUCCESS);

  char* first = devtools_events_json();
  devtools_string_destroy(first);

  char* second = devtools_events_json();
  ASSERT_NE(second, nullptr);
  EXPECT_STREQ(second, "[]");
  devtools_string_destroy(second);

  operation_destroy(op);
  state_destroy(state);
}

TEST(DevtoolsEvents, RejectedOperationRecordsError) {
  state_t* state = make_state_with_g_counter();
  operation_t* op = make_operation("decrement", "mallory");

  record_op_event(state, op, CRABS_ERR_UNAUTHORIZED);

  char* json = devtools_events_json();
  std::string text = json;
  devtools_string_destroy(json);

  EXPECT_NE(text.find("\"result\":\"rejected\""), std::string::npos);
  EXPECT_NE(text.find("\"error\":\"unauthorized\""), std::string::npos);
  EXPECT_NE(text.find("\"error_code\":8193"), std::string::npos);

  operation_destroy(op);
  state_destroy(state);
}

TEST(DevtoolsEvents, RingWraparoundDropsOldest) {
  state_t* state = make_state_with_g_counter();

  operation_t* marker_op = make_operation("increment", "alice");
  record_op_event(state, marker_op, CRABS_SUCCESS);
  operation_destroy(marker_op);

  char* marker_json = devtools_events_json();
  ASSERT_NE(marker_json, nullptr);
  std::string marker_text = marker_json;
  devtools_string_destroy(marker_json);

  size_t marker_seq_position = marker_text.rfind("\"seq\":");
  ASSERT_NE(marker_seq_position, std::string::npos);
  uint64_t marker_seq = strtoull(marker_text.c_str() + marker_seq_position + strlen("\"seq\":"), nullptr, 10);

  for (uint32_t op_index = 0; op_index < CRABS_DEVTOOLS_RING_SIZE + 5; op_index++) {
    operation_t* op = make_operation("increment", "alice");
    record_op_event(state, op, CRABS_SUCCESS);
    operation_destroy(op);
  }

  char* json = devtools_events_json();
  std::string text = json;
  devtools_string_destroy(json);

  uint32_t object_count = 0;
  uint64_t minimum_seq = UINT64_MAX;
  size_t search_position = 0;
  while ((search_position = text.find("\"seq\":", search_position)) != std::string::npos) {
    object_count++;
    uint64_t seq_value = strtoull(text.c_str() + search_position + strlen("\"seq\":"), nullptr, 10);
    if (seq_value < minimum_seq) minimum_seq = seq_value;
    search_position += strlen("\"seq\":");
  }
  EXPECT_EQ(object_count, (uint32_t)CRABS_DEVTOOLS_RING_SIZE);
  EXPECT_EQ(minimum_seq, marker_seq + 6u);
}

TEST(DevtoolsEvents, NullOperationIsIgnored) {
  state_t* state = make_state_with_g_counter();
  devtools_record_change(state, nullptr);
  char* json = devtools_events_json();
  EXPECT_STREQ(json, "[]");
  devtools_string_destroy(json);
  state_destroy(state);
}

TEST(DevtoolsEvents, HlcEventEmitsHlcObject) {
  state_t* state = make_state_with_g_counter();
  operation_t* op = make_operation("increment", "bob");
  op->ordering_system = CRABS_ORDERING_HLC;
  op->hlc = {1, 2, 3, "node-b"};

  record_op_event(state, op, CRABS_SUCCESS);

  char* json = devtools_events_json();
  std::string text = json;
  devtools_string_destroy(json);

  EXPECT_NE(text.find("\"hlc\":{\"physical\":1,\"nanos\":2,\"logical\":3,\"node\":\"node-b\"}"),
            std::string::npos);

  operation_destroy(op);
  state_destroy(state);
}

TEST(DevtoolsEvents, RingCountTracksUsedSlots) {
  state_t* state = make_state_with_g_counter();
  operation_t* first = make_operation("increment", "bob");
  operation_t* second = make_operation("increment", "carol");
  operation_t* third = make_operation("increment", "dave");

  EXPECT_EQ(devtools_ring_count(), 0u);
  record_op_event(state, first, CRABS_SUCCESS);
  record_op_event(state, second, CRABS_SUCCESS);
  record_op_event(state, third, CRABS_SUCCESS);
  EXPECT_EQ(devtools_ring_count(), 3u);

  char* json = devtools_events_json();
  devtools_string_destroy(json);
  EXPECT_EQ(devtools_ring_count(), 0u);

  operation_destroy(first);
  operation_destroy(second);
  operation_destroy(third);
  state_destroy(state);
}

// The recorder runs from the change hook: attribute mutations, which no
// direct call site ever recorded, now land in the ring.
TEST(DevtoolsEvents, RecordsAttributeMutationsViaChangeHook) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  // Attribute mutations fire on the attribute machine's own base_state, so
  // the hook must be registered there (crabs_wasm_node_create registers it
  // on the state the node actually uses). env.state gets it too so the
  // execute/schedule paths fire in the same wiring.
  state_set_change_hook(&env.am->base_state, test_devtools_change_hook, NULL);
  state_set_change_hook(env.state, test_devtools_change_hook, NULL);

  // Registration validates the key on secp256k1, so use a generated key.
  ecdsa_keypair_t* user_key = crypto_ecdsa_generate();
  ASSERT_NE(user_key, nullptr);
  ASSERT_EQ(attribute_machine_register_user(env.am, "alice", user_key->public_key, NULL),
            CRABS_SUCCESS);
  crypto_ecdsa_keypair_destroy(user_key);

  char* json = devtools_events_json();
  ASSERT_NE(json, nullptr);
  std::string text = json;
  devtools_string_destroy(json);

  EXPECT_NE(text.find("\"layer\":\"attribute\""), std::string::npos);
  EXPECT_NE(text.find("\"op_type\":\"register_user\""), std::string::npos);
  EXPECT_NE(text.find("\"preview\":\"user registered\""), std::string::npos);

  crabs_test_env_destroy(&env);
}

TEST(DevtoolsEvents, RecordsScheduledFireWithScheduleLayer) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  state_set_change_hook(env.state, test_devtools_change_hook, NULL);

  operation_t* embedded = operation_create("increment");
  strncpy(embedded->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  uint64_t schedule_id = scheduler_schedule(env.state, 1000, "admin", embedded);
  ASSERT_NE(schedule_id, 0u);

  scheduler_process_due(env.state, 2000);

  char* json = devtools_events_json();
  ASSERT_NE(json, nullptr);
  std::string text = json;
  devtools_string_destroy(json);

  EXPECT_NE(text.find("\"layer\":\"schedule\""), std::string::npos);
  EXPECT_NE(text.find("\"preview\":\"scheduled increment\""),
            std::string::npos);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

static bool contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

TEST(DevtoolsSnapshot, ItemsAndGCounterValue) {
  state_t* state = make_state_with_g_counter();

  char* json = devtools_snapshot_json(state);
  ASSERT_NE(json, nullptr);
  std::string text = json;
  devtools_string_destroy(json);
  state_destroy(state);

  EXPECT_TRUE(contains(text, "\"node_id\":"));
  EXPECT_TRUE(contains(text, "\"name\":\"views\""));
  EXPECT_TRUE(contains(text, "\"crdt_type\":\"g_counter\""));
  EXPECT_TRUE(contains(text, "\"protocol_state\":\"idle\""));
  EXPECT_TRUE(contains(text, "\"alice\":12"));
}

TEST(DevtoolsSnapshot, NullStateReturnsNull) {
  EXPECT_EQ(devtools_snapshot_json(nullptr), nullptr);
}

TEST(DevtoolsSnapshot, AllValueTypes) {
  state_t* state = state_create();

  data_item_t* pn = data_item_create("likes", DATA_TYPE_PN_COUNTER, CRDT_PN_COUNTER);
  pn->value = pn_counter_create();
  pn_counter_increment((pn_counter_t*)pn->value, "bob", 3);
  pn_counter_decrement((pn_counter_t*)pn->value, "bob", 5);
  state_add_item(state, pn);

  data_item_t* set = data_item_create("subscribers", DATA_TYPE_SET, CRDT_OR_SET);
  set->value = or_set_create();
  or_set_add((or_set_t*)set->value, "carol", "carol:1");
  state_add_item(state, set);

  data_item_t* reg = data_item_create("contact", DATA_TYPE_REGISTER, CRDT_LWW_REG);
  reg->value = lww_register_create((const uint8_t*)"x", 1, 5, "alice");
  state_add_item(state, reg);

  // Exactly-8-byte payloads follow the int64 register convention and must
  // keep rendering as numbers (not as the opaque marker).
  data_item_t* int64_reg = data_item_create("score", DATA_TYPE_REGISTER, CRDT_LWW_REG);
  const int64_t score_value = -42;
  int64_reg->value = lww_register_create((const uint8_t*)&score_value,
                                         sizeof(score_value), 7, "bob");
  state_add_item(state, int64_reg);

  data_item_t* one_shot_item = data_item_create("flaggers", DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  one_shot_set_t* one_shot = one_shot_set_create();
  one_shot_set_add(one_shot, "dave");
  one_shot_set_add(one_shot, "eve");
  one_shot_set_add(one_shot, "frank");
  one_shot_item->value = one_shot;
  state_add_item(state, one_shot_item);

  data_item_t* flag = data_item_create("tos_flag", DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
  flag->value = one_shot_flag_create();
  one_shot_flag_set((one_shot_flag_t*)flag->value, "alice", 42);
  state_add_item(state, flag);

  char* json = devtools_snapshot_json(state);
  ASSERT_NE(json, nullptr);
  std::string text = json;
  devtools_string_destroy(json);
  state_destroy(state);

  EXPECT_TRUE(contains(text, "\"pos\":{"));
  EXPECT_TRUE(contains(text, "\"neg\":{"));
  EXPECT_TRUE(contains(text, "\"bob\":3"));
  EXPECT_TRUE(contains(text, "\"value\":-2"));
  EXPECT_TRUE(contains(text, "\"elements\":[\"carol\"]"));
  EXPECT_TRUE(contains(text, "[encrypted: 1 bytes]"));
  EXPECT_TRUE(contains(text, "\"value\":-42"));
  EXPECT_TRUE(contains(text, "\"timestamp\":5"));
  EXPECT_TRUE(contains(text, "\"set_by\":\"alice\""));
  EXPECT_TRUE(contains(text, "\"set_at\":42"));
}

TEST(DevtoolsSnapshot, PoliciesTriggersUsersLogHead) {
  state_t* state = make_state_with_g_counter();
  ASSERT_EQ(state_add_policy(state, "increment", "role:member"), CRABS_SUCCESS);

  trigger_effect_t* effect = trigger_effect_create_issue_attribute(
      "role:investigator", "member", 0, "");
  trigger_t* trigger = trigger_create("tos_threshold", "Too many flags",
                                      "flag_count >= 3", effect, 0, false, "admin");
  state->triggers = trigger;
  state->trigger_count = 1;

  char* json = devtools_snapshot_json(state);
  ASSERT_NE(json, nullptr);
  std::string text = json;
  devtools_string_destroy(json);
  state_destroy(state);

  EXPECT_TRUE(contains(text, "\"operation\":\"increment\""));
  EXPECT_TRUE(contains(text, "\"expression\":\"role:member\""));
  EXPECT_TRUE(contains(text, "\"id\":\"tos_threshold\""));
  EXPECT_TRUE(contains(text, "\"condition\":\"flag_count >= 3\""));
  EXPECT_TRUE(contains(text, "\"fired\":false"));
  EXPECT_TRUE(contains(text, "\"entries\":0"));
}

TEST(DevtoolsSnapshot, SchedulesSection) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* embedded = operation_create("mint");
  strncpy(embedded->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  uint64_t schedule_id = scheduler_schedule(env.state, 5555555, "admin", embedded);

  char* json = devtools_snapshot_json(env.state);
  ASSERT_NE(json, nullptr);
  std::string text = json;
  devtools_string_destroy(json);

  EXPECT_NE(text.find("\"schedules\":["), std::string::npos);
  EXPECT_NE(text.find("\"id\":" + std::to_string(schedule_id)), std::string::npos);
  EXPECT_NE(text.find("\"execute_at\":5555555"), std::string::npos);
  EXPECT_NE(text.find("\"submitter\":\"admin\""), std::string::npos);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(DevtoolsSnapshot, RecurringSchedulesSection) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* embedded = operation_create("mint");
  strncpy(embedded->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  uint64_t schedule_id = scheduler_schedule_recurring(
      env.state, 1000000, 15000, 3, 0, "admin", embedded);

  char* json = devtools_snapshot_json(env.state);
  ASSERT_NE(json, nullptr);
  std::string text = json;
  devtools_string_destroy(json);

  EXPECT_NE(text.find("\"schedules\":["), std::string::npos);
  EXPECT_NE(text.find("\"id\":" + std::to_string(schedule_id)), std::string::npos);
  EXPECT_NE(text.find("\"execute_at\":1000000"), std::string::npos);
  EXPECT_NE(text.find("\"interval\":15000"), std::string::npos);
  EXPECT_NE(text.find("\"repeat\":3"), std::string::npos);
  EXPECT_NE(text.find("\"end_at\":0"), std::string::npos);
  EXPECT_NE(text.find("\"submitter\":\"admin\""), std::string::npos);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

// ============================================================
// DevtoolsSnapshot: lineage (children manifest) section
// ============================================================

// A shared-root blueprint that satisfies every validation rule (same shape as
// test_lineage.cpp's make_valid_blueprint).
static machine_blueprint_t* make_shared_root_blueprint(void) {
  machine_blueprint_t* blueprint = machine_blueprint_create();
  EXPECT_NE(blueprint, nullptr);
  strncpy(blueprint->child_id, "child-red", sizeof(blueprint->child_id) - 1);
  blueprint->trust_mode = LINEAGE_SHARED_ROOT;
  strncpy(blueprint->bootstrap_admin, "parent-admin",
          sizeof(blueprint->bootstrap_admin) - 1);
  blueprint->attestation_ttl_ms = 60000;

  EXPECT_EQ(blueprint_add_item(blueprint, "counter", DATA_TYPE_COUNTER,
                               CRDT_G_COUNTER), CRABS_SUCCESS);
  EXPECT_EQ(blueprint_add_policy(blueprint, "increment",
                                 "custody:child-red"), CRABS_SUCCESS);

  dedup_spec_t dedup;
  memset(&dedup, 0, sizeof(dedup));
  dedup.type = DEDUP_NONE;
  EXPECT_EQ(blueprint_add_op_type_def(blueprint, "increment", &dedup),
            CRABS_SUCCESS);

  EXPECT_EQ(lineage_blueprint_validate(blueprint), CRABS_SUCCESS);
  return blueprint;
}

TEST(DevtoolsSnapshot, SnapshotCarriesLineageSection) {
  // Spawn parent wired the way test_lineage.cpp's spawn_parent_setup does it:
  // heap attribute machine, node key on the embedded state, self-reference.
  ecdsa_keypair_t* parent_key = crypto_ecdsa_generate();
  ASSERT_NE(parent_key, nullptr);
  attribute_machine_t* parent_machine =
      attribute_machine_create("parent-root", parent_key->public_key);
  ASSERT_NE(parent_machine, nullptr);
  ASSERT_EQ(state_set_node_key(&parent_machine->base_state,
                               parent_key->private_key,
                               parent_key->public_key), CRABS_SUCCESS);
  parent_machine->base_state.attr_machine = parent_machine;

  machine_blueprint_t* blueprint = make_shared_root_blueprint();
  ASSERT_NE(blueprint, nullptr);
  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(&parent_machine->base_state, blueprint,
                                  &child), CRABS_SUCCESS);
  ASSERT_NE(child, nullptr);

  char* json = devtools_snapshot_json(&parent_machine->base_state);
  ASSERT_NE(json, nullptr);
  std::string text = json;
  devtools_string_destroy(json);

  EXPECT_TRUE(contains(text, "\"children\":"));
  EXPECT_TRUE(contains(text, "\"child_id\":\"child-red\""));
  EXPECT_TRUE(contains(text, "\"mode\":\"shared_root\""));
  EXPECT_TRUE(contains(text, "\"status\":\"active\""));
  EXPECT_TRUE(contains(text, "\"spawned_at\":"));
  EXPECT_TRUE(contains(text, "\"attestation_ttl_ms\":60000"));
  // The child spawned in-process is still held by the parent's
  // resident-children registry, so the snapshot marks it resident.
  EXPECT_TRUE(contains(text, "\"resident\":true"));

  // A machine with an empty manifest renders an empty array (here: the just
  // spawned child, which has spawned nothing of its own).
  char* child_json = devtools_snapshot_json(&child->base_state);
  ASSERT_NE(child_json, nullptr);
  std::string child_text = child_json;
  devtools_string_destroy(child_json);
  EXPECT_TRUE(contains(child_text, "\"children\":[]"));

  attribute_machine_destroy(child);
  machine_blueprint_destroy(blueprint);
  attribute_machine_destroy(parent_machine);
  crypto_ecdsa_keypair_destroy(parent_key);
}
