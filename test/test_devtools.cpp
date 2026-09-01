//
// Devtools tests: event ring buffer, drain JSON, snapshot JSON.
//

#include <gtest/gtest.h>
#include <cstring>
#include <string>

extern "C" {
#include "Devtools/devtools.h"
#include "CRABS/data_model.h"
#include "StateMachine/state_machine.h"
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
  for (uint32_t op_index = 0; op_index < CRABS_DEVTOOLS_RING_SIZE + 5; op_index++) {
    operation_t* op = make_operation("increment", "alice");
    devtools_record_event(state, op, CRABS_SUCCESS);
    operation_destroy(op);
  }

  char* json = devtools_events_json();
  std::string text = json;
  devtools_string_destroy(json);

  uint32_t comma_count = 0;
  for (char character : text) {
    if (character == '{') comma_count++;
  }
  EXPECT_EQ(comma_count, (uint32_t)CRABS_DEVTOOLS_RING_SIZE);
}

TEST(DevtoolsEvents, NullOperationIsIgnored) {
  state_t* state = make_state_with_g_counter();
  devtools_record_event(state, nullptr, CRABS_SUCCESS);
  char* json = devtools_events_json();
  EXPECT_STREQ(json, "[]");
  devtools_string_destroy(json);
  state_destroy(state);
}