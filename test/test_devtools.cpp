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
#include "CRABS/data_model.h"
#include "StateMachine/state_machine.h"
#include "Trigger/trigger.h"
#include "CRDT/crdt_merge.h"
#include "CRDT/one_shot.h"
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

TEST(DevtoolsEvents, RecordThenDrainProducesJsonArray) {
  state_t* state = make_state_with_g_counter();
  operation_t* op = make_operation("increment", "bob");

  devtools_record_event(state, op, CRABS_SUCCESS);

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
  devtools_record_event(state, op, CRABS_SUCCESS);

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

  devtools_record_event(state, op, CRABS_ERR_UNAUTHORIZED);

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
  devtools_record_event(state, marker_op, CRABS_SUCCESS);
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
    devtools_record_event(state, op, CRABS_SUCCESS);
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
  devtools_record_event(state, nullptr, CRABS_SUCCESS);
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

  devtools_record_event(state, op, CRABS_SUCCESS);

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
  devtools_record_event(state, first, CRABS_SUCCESS);
  devtools_record_event(state, second, CRABS_SUCCESS);
  devtools_record_event(state, third, CRABS_SUCCESS);
  EXPECT_EQ(devtools_ring_count(), 3u);

  char* json = devtools_events_json();
  devtools_string_destroy(json);
  EXPECT_EQ(devtools_ring_count(), 0u);

  operation_destroy(first);
  operation_destroy(second);
  operation_destroy(third);
  state_destroy(state);
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
