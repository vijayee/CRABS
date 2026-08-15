#include <gtest/gtest.h>
extern "C" {
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/crypto.h"
#include "../src/Serialization/serialization.h"
#include "../src/CRDT/crdt_merge.h"
}
#include "test_helpers.h"

// ============================================================
// Registry CRUD tests
// ============================================================

static crabs_error_e test_handler_null(state_t* state, operation_t* op) {
  (void)state;
  (void)op;
  return CRABS_SUCCESS;
}

static crabs_error_e test_handler_error(state_t* state, operation_t* op) {
  (void)state;
  (void)op;
  return CRABS_ERR_INVALID_PARAM;
}

TEST(HandlerRegistry, RegisterAndFind) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  crabs_error_e rc = state_machine_register_handler(state, "transfer", test_handler_null);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(state->op_handler_count, (uint32_t)1);

  op_handler_fn found = state_machine_find_handler(state, "transfer");
  EXPECT_EQ(found, test_handler_null);

  state_destroy(state);
}

TEST(HandlerRegistry, FindNonexistentReturnsNull) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  op_handler_fn found = state_machine_find_handler(state, "nonexistent");
  EXPECT_EQ(found, nullptr);

  state_destroy(state);
}

TEST(HandlerRegistry, RegisterReplacesExisting) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  state_machine_register_handler(state, "transfer", test_handler_null);
  state_machine_register_handler(state, "transfer", test_handler_error);

  EXPECT_EQ(state->op_handler_count, (uint32_t)1);
  op_handler_fn found = state_machine_find_handler(state, "transfer");
  EXPECT_EQ(found, test_handler_error);

  state_destroy(state);
}

TEST(HandlerRegistry, UnregisterRemovesHandler) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  state_machine_register_handler(state, "transfer", test_handler_null);
  EXPECT_EQ(state->op_handler_count, (uint32_t)1);

  state_machine_unregister_handler(state, "transfer");
  EXPECT_EQ(state->op_handler_count, (uint32_t)0);
  EXPECT_EQ(state_machine_find_handler(state, "transfer"), nullptr);

  state_destroy(state);
}

TEST(HandlerRegistry, UnregisterNonexistentIsNoop) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  state_machine_unregister_handler(state, "nonexistent");
  EXPECT_EQ(state->op_handler_count, (uint32_t)0);

  state_destroy(state);
}

TEST(HandlerRegistry, UnregisterShiftsRemainingEntries) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  state_machine_register_handler(state, "op_a", test_handler_null);
  state_machine_register_handler(state, "op_b", test_handler_error);
  state_machine_register_handler(state, "op_c", test_handler_null);
  EXPECT_EQ(state->op_handler_count, (uint32_t)3);

  state_machine_unregister_handler(state, "op_b");
  EXPECT_EQ(state->op_handler_count, (uint32_t)2);
  EXPECT_EQ(state_machine_find_handler(state, "op_a"), test_handler_null);
  EXPECT_EQ(state_machine_find_handler(state, "op_b"), nullptr);
  EXPECT_EQ(state_machine_find_handler(state, "op_c"), test_handler_null);

  state_destroy(state);
}

TEST(HandlerRegistry, CapacityLimit) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  char op_name[64];
  for (int i = 0; i < CRABS_MAX_OP_HANDLERS; i++) {
    snprintf(op_name, sizeof(op_name), "op_%d", i);
    EXPECT_EQ(state_machine_register_handler(state, op_name, test_handler_null), CRABS_SUCCESS);
  }
  EXPECT_EQ(state->op_handler_count, (uint32_t)CRABS_MAX_OP_HANDLERS);

  crabs_error_e rc = state_machine_register_handler(state, "one_too_many", test_handler_null);
  EXPECT_EQ(rc, CRABS_ERR_OOM);

  state_destroy(state);
}

TEST(HandlerRegistry, NullParamsReturnError) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  EXPECT_EQ(state_machine_register_handler(NULL, "transfer", test_handler_null), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state_machine_register_handler(state, NULL, test_handler_null), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state_machine_register_handler(state, "transfer", NULL), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state_machine_find_handler(NULL, "transfer"), nullptr);
  EXPECT_EQ(state_machine_find_handler(state, NULL), nullptr);

  state_destroy(state);
}

// ============================================================
// Integration tests: handler invocation via state_machine_execute
// ============================================================

class HandlerRegistryIntegration : public ::testing::Test {
protected:
  state_t* state;
  attribute_machine_t* am;
  ecdsa_keypair_t* alice_key;

  void SetUp() override {
    state = state_create();

    data_item_t* res = data_item_create("test_resource", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
    int64_t* val = (int64_t*)malloc(sizeof(int64_t));
    *val = 0;
    res->value = val;
    state_add_item(state, res);

    state_add_policy(state, "transfer", "role:admin");

    alice_key = crypto_ecdsa_generate();
    ASSERT_NE(alice_key, nullptr);

    uint8_t admin_pk[33];
    memset(admin_pk, 0xAA, 33);
    admin_pk[0] = 0x02;
    am = attribute_machine_create("admin", admin_pk);
    ASSERT_NE(am, nullptr);

    crabs_error_e rc = crabs_test_register_user_with_role(
        am, "alice", alice_key->public_key, "role", "admin");
    ASSERT_EQ(rc, CRABS_SUCCESS);

    state->attr_machine = am;

    ecdsa_keypair_t* node_key = crypto_ecdsa_generate();
    ASSERT_NE(node_key, nullptr);
    state_set_node_key(state, node_key->private_key, node_key->public_key);
    crypto_ecdsa_keypair_destroy(node_key);
  }

  void TearDown() override {
    crypto_ecdsa_keypair_destroy(alice_key);
    attribute_machine_destroy(am);
    state_destroy(state);
  }

  operation_t* create_signed_op(const char* type) {
    operation_t* op = operation_create(type);
    strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
    strncpy(op->node_id, "node1", CRABS_MAX_USER_ID - 1);
    op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
    strncpy(op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
    op->resource_count = 1;
    op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
    op->required_state[0] = PROTOCOL_IDLE;
    op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
    op->next_state[0] = PROTOCOL_IDLE;
    op->lamport_time = 1;

    user_t* signer = attribute_machine_find_user(am, "alice");
    if (signer != NULL) op->signer_key_version = signer->key_version;
    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
    crypto_sign_operation(alice_key->private_key, ser->data, ser->len, op->signature);
    serialized_buffer_destroy(ser);
    return op;
  }
};

static int g_handler_call_count = 0;

static crabs_error_e counting_handler(state_t* state, operation_t* op) {
  (void)state;
  (void)op;
  g_handler_call_count++;
  return CRABS_SUCCESS;
}

TEST_F(HandlerRegistryIntegration, CustomHandlerInvokedOnExecute) {
  g_handler_call_count = 0;
  state_machine_register_handler(state, "transfer", counting_handler);

  operation_t* op = create_signed_op("transfer");
  crabs_error_e result = state_machine_execute(state, op);
  EXPECT_EQ(result, CRABS_SUCCESS);
  EXPECT_EQ(g_handler_call_count, 1);

  operation_destroy(op);
}

TEST_F(HandlerRegistryIntegration, NoHandlerFallsBackToDefault) {
  // The default path for non-builtin ops applies the LOCKED->MODIFIED
  // transition. When the resource is IDLE (not LOCKED), it returns
  // CRABS_ERR_PROTOCOL_VIOLATION because only LOCKED->MODIFIED is valid.
  operation_t* op = create_signed_op("transfer");
  crabs_error_e result = state_machine_execute(state, op);
  EXPECT_EQ(result, CRABS_ERR_PROTOCOL_VIOLATION);

  operation_destroy(op);
}

TEST_F(HandlerRegistryIntegration, HandlerErrorPropagates) {
  state_machine_register_handler(state, "transfer", test_handler_error);

  operation_t* op = create_signed_op("transfer");
  crabs_error_e result = state_machine_execute(state, op);
  EXPECT_EQ(result, CRABS_ERR_INVALID_PARAM);

  operation_destroy(op);
}

// R7-13: the dedup mutation was applied before the handler, so a failing op
// burned the dedup slot (e.g. a ONE_SHOT_SET membership). The mutation must
// only be applied after the handler succeeds.
TEST_F(HandlerRegistryIntegration, FailingHandlerDoesNotBurnDedupSlot) {
  data_item_t* voters = data_item_create("proposal_voters", DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  voters->value = one_shot_set_create();
  state_add_item(state, voters);

  dedup_spec_t spec;
  memset(&spec, 0, sizeof(spec));
  spec.type = DEDUP_PER_USER;
  strncpy(spec.tracker_path, "proposal_voters", CRABS_MAX_DEDUP_PATH - 1);
  ASSERT_EQ(state_register_op_type_def(state, "transfer", &spec), CRABS_SUCCESS);

  state_machine_register_handler(state, "transfer", test_handler_error);

  operation_t* op = create_signed_op("transfer");
  crabs_error_e result = state_machine_execute(state, op);
  EXPECT_EQ(result, CRABS_ERR_INVALID_PARAM);

  // The signer must NOT be in the tracker — the failed op did not burn the slot.
  one_shot_set_t* set = (one_shot_set_t*)voters->value;
  EXPECT_FALSE(one_shot_set_contains(set, "alice"));
  EXPECT_EQ(one_shot_set_count(set), (uint32_t)0);

  operation_destroy(op);
}

TEST_F(HandlerRegistryIntegration, UnauthorizedOpRejectedBeforeHandler) {
  g_handler_call_count = 0;
  state_machine_register_handler(state, "transfer", counting_handler);

  operation_t* op = operation_create("transfer");
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  strncpy(op->node_id, "node1", CRABS_MAX_USER_ID - 1);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_IDLE;
  op->lamport_time = 1;
  // Deliberately skip signing — signature is all zeros

  crabs_error_e result = state_machine_execute(state, op);
  EXPECT_NE(result, CRABS_SUCCESS);
  EXPECT_EQ(g_handler_call_count, 0);

  operation_destroy(op);
}

TEST_F(HandlerRegistryIntegration, BuiltinOpsNotDispatchedToCustomHandler) {
  g_handler_call_count = 0;
  state_machine_register_handler(state, CRABS_OP_LOCK, counting_handler);

  operation_t* op = create_signed_op(CRABS_OP_LOCK);
  crabs_error_e result = state_machine_execute(state, op);
  // The builtin __lock__ handler runs, not our custom one
  EXPECT_EQ(g_handler_call_count, 0);

  operation_destroy(op);
}

static crabs_error_e protocol_mutating_handler(state_t* state, operation_t* op) {
  for (uint32_t i = 0; i < op->resource_count; i++) {
    data_item_t* item = state_find_item(state, op->resources[i]);
    if (item != NULL && item->type == DATA_TYPE_RESOURCE) {
      item->protocol_state = PROTOCOL_VERIFIED;
    }
  }
  return CRABS_SUCCESS;
}

TEST_F(HandlerRegistryIntegration, CustomHandlerOwnsProtocolTransitions) {
  state_machine_register_handler(state, "transfer", protocol_mutating_handler);

  operation_t* op = create_signed_op("transfer");
  crabs_error_e result = state_machine_execute(state, op);
  EXPECT_EQ(result, CRABS_SUCCESS);

  data_item_t* item = state_find_item(state, "test_resource");
  ASSERT_NE(item, nullptr);
  // Handler set VERIFIED; default LOCKED->MODIFIED was skipped
  EXPECT_EQ(item->protocol_state, PROTOCOL_VERIFIED);

  operation_destroy(op);
}
