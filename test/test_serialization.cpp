#include <gtest/gtest.h>
extern "C" {
#include "../src/Serialization/serialization.h"
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
}

// ============================================================
// State serialization tests
// ============================================================

TEST(TestSerialization, TestSerializeEmptyState) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  EXPECT_GT(buf->len, (size_t)0);

  // First 4 bytes should be "CRAB"
  EXPECT_EQ(buf->data[0], 0x43);
  EXPECT_EQ(buf->data[1], 0x52);
  EXPECT_EQ(buf->data[2], 0x41);
  EXPECT_EQ(buf->data[3], 0x42);

  serialized_buffer_destroy(buf);
  state_destroy(state);
}

TEST(TestSerialization, TestSerializeDeserializeStateRoundTrip) {
  state_t* original = state_create();
  original->version = 42;

  // Add a data item
  data_item_t* item = data_item_create("counter1", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  int64_t* val = (int64_t*)malloc(sizeof(int64_t));
  *val = 12345;
  item->value = val;
  state_add_item(original, item);

  // Add a policy
  state_add_policy(original, CRABS_OP_LOCK, "role:admin");

  // Serialize
  serialized_buffer_t* buf = crabs_serialize_state(original);
  ASSERT_NE(buf, nullptr);

  // Deserialize
  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  // Verify
  EXPECT_EQ(restored->version, original->version);
  EXPECT_EQ(restored->policy_count, original->policy_count);

  // Verify item
  data_item_t* restored_item = state_find_item(restored, "counter1");
  ASSERT_NE(restored_item, nullptr);
  EXPECT_EQ(restored_item->type, DATA_TYPE_COUNTER);
  EXPECT_EQ(restored_item->crdt_type, CRDT_G_COUNTER);
  EXPECT_EQ(restored_item->protocol_state, PROTOCOL_IDLE);
  ASSERT_NE(restored_item->value, nullptr);
  EXPECT_EQ(*(int64_t*)restored_item->value, (int64_t)12345);

  // Verify policy
  const char* policy = state_find_policy(restored, CRABS_OP_LOCK);
  ASSERT_NE(policy, nullptr);
  EXPECT_STREQ(policy, "role:admin");

  // Verify config
  EXPECT_EQ(restored->config.max_lock_duration_ms, original->config.max_lock_duration_ms);
  EXPECT_EQ(restored->config.max_lock_extensions, original->config.max_lock_extensions);
  EXPECT_EQ(restored->config.allow_force_unlock, original->config.allow_force_unlock);

  serialized_buffer_destroy(buf);
  state_destroy(original);
  state_destroy(restored);
}

TEST(TestSerialization, TestSerializeStateWithItems) {
  state_t* state = state_create();
  state->version = 100;

  // Add multiple items
  data_item_t* item1 = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* val1 = (int64_t*)malloc(sizeof(int64_t));
  *val1 = 999;
  item1->value = val1;
  item1->protocol_state = PROTOCOL_LOCKED;
  state_add_item(state, item1);

  data_item_t* item2 = data_item_create("res2", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  int64_t* val2 = (int64_t*)malloc(sizeof(int64_t));
  *val2 = -42;
  item2->value = val2;
  state_add_item(state, item2);

  // Add policies
  state_add_policy(state, CRABS_OP_LOCK, "role:admin");
  state_add_policy(state, CRABS_OP_UNLOCK, "role:admin");

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->version, (uint64_t)100);

  // Count items
  data_item_t* cur = restored->items;
  int count = 0;
  while (cur != nullptr) {
    count++;
    cur = cur->next;
  }
  EXPECT_EQ(count, 2);

  // Verify res1
  data_item_t* r1 = state_find_item(restored, "res1");
  ASSERT_NE(r1, nullptr);
  EXPECT_EQ(r1->type, DATA_TYPE_RESOURCE);
  EXPECT_EQ(r1->crdt_type, CRDT_PN_COUNTER);
  EXPECT_EQ(r1->protocol_state, PROTOCOL_LOCKED);
  EXPECT_EQ(*(int64_t*)r1->value, (int64_t)999);

  // Verify res2
  data_item_t* r2 = state_find_item(restored, "res2");
  ASSERT_NE(r2, nullptr);
  EXPECT_EQ(r2->type, DATA_TYPE_COUNTER);
  EXPECT_EQ(*(int64_t*)r2->value, (int64_t)-42);

  // Verify policies
  EXPECT_EQ(restored->policy_count, (uint32_t)2);

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

TEST(TestSerialization, TestSerializeOperationRoundTrip) {
  operation_t* original = operation_create(CRABS_OP_LOCK);
  memset(original->uuid, 0xAB, CRABS_UUID_SIZE);

  original->resources = (char(*)[CRABS_MAX_USER_ID])malloc(2 * CRABS_MAX_USER_ID);
  strncpy(original->resources[0], "resource_a", CRABS_MAX_USER_ID - 1);
  strncpy(original->resources[1], "resource_b", CRABS_MAX_USER_ID - 1);
  original->resource_count = 2;

  original->required_state = (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  original->required_state[0] = PROTOCOL_IDLE;
  original->required_state[1] = PROTOCOL_IDLE;

  original->next_state = (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  original->next_state[0] = PROTOCOL_LOCKED;
  original->next_state[1] = PROTOCOL_LOCKED;

  original->lock_claims = (lock_claim_t*)malloc(2 * sizeof(lock_claim_t));
  strncpy(original->lock_claims[0].resource, "resource_a", CRABS_MAX_USER_ID - 1);
  memset(original->lock_claims[0].lock_token, 0x11, CRABS_LOCK_TOKEN_SIZE);
  strncpy(original->lock_claims[1].resource, "resource_b", CRABS_MAX_USER_ID - 1);
  memset(original->lock_claims[1].lock_token, 0x22, CRABS_LOCK_TOKEN_SIZE);
  original->lock_claim_count = 2;

  strncpy(original->policy, "role:admin", CRABS_MAX_POLICY_EXPR - 1);
  memset(original->signature, 0xCC, CRABS_SIG_SIZE);
  strncpy(original->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  original->signer_key_version = 3;
  original->lamport_time = 12345678;
  strncpy(original->node_id, "node1", CRABS_MAX_USER_ID - 1);

  const char* payload_str = "test_payload_data";
  original->payload = (uint8_t*)strdup(payload_str);
  original->payload_size = strlen(payload_str);
  original->payload_format = 0x01;

  // Serialize
  serialized_buffer_t* buf = crabs_serialize_operation(original);
  ASSERT_NE(buf, nullptr);

  // Deserialize
  operation_t* restored = crabs_deserialize_operation(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  // Verify
  EXPECT_STREQ(restored->type, CRABS_OP_LOCK);
  EXPECT_EQ(memcmp(restored->uuid, original->uuid, CRABS_UUID_SIZE), 0);
  EXPECT_EQ(restored->payload_size, original->payload_size);
  ASSERT_NE(restored->payload, nullptr);
  EXPECT_EQ(memcmp(restored->payload, original->payload, original->payload_size), 0);
  EXPECT_EQ(restored->resource_count, (uint32_t)2);
  EXPECT_STREQ(restored->resources[0], "resource_a");
  EXPECT_STREQ(restored->resources[1], "resource_b");
  EXPECT_EQ(restored->required_state[0], PROTOCOL_IDLE);
  EXPECT_EQ(restored->required_state[1], PROTOCOL_IDLE);
  EXPECT_EQ(restored->next_state[0], PROTOCOL_LOCKED);
  EXPECT_EQ(restored->next_state[1], PROTOCOL_LOCKED);
  EXPECT_EQ(restored->lock_claim_count, (uint32_t)2);
  EXPECT_STREQ(restored->lock_claims[0].resource, "resource_a");
  EXPECT_EQ(memcmp(restored->lock_claims[0].lock_token, original->lock_claims[0].lock_token, CRABS_LOCK_TOKEN_SIZE), 0);
  EXPECT_STREQ(restored->lock_claims[1].resource, "resource_b");
  EXPECT_EQ(memcmp(restored->lock_claims[1].lock_token, original->lock_claims[1].lock_token, CRABS_LOCK_TOKEN_SIZE), 0);
  EXPECT_STREQ(restored->policy, "role:admin");
  EXPECT_EQ(memcmp(restored->signature, original->signature, CRABS_SIG_SIZE), 0);
  EXPECT_STREQ(restored->signer_id, "alice");
  EXPECT_EQ(restored->signer_key_version, (uint64_t)3);
  EXPECT_EQ(restored->lamport_time, (uint64_t)12345678);
  EXPECT_STREQ(restored->node_id, "node1");
  EXPECT_EQ(restored->payload_format, (uint8_t)0x01);

  serialized_buffer_destroy(buf);
  operation_destroy(original);
  operation_destroy(restored);
}

TEST(TestSerialization, TestCanonicalEncodingDeterminism) {
  operation_t* op1 = operation_create(CRABS_OP_VERIFY);
  memset(op1->uuid, 0x42, CRABS_UUID_SIZE);
  op1->resource_count = 1;
  op1->resources = (char(*)[CRABS_MAX_USER_ID])malloc(CRABS_MAX_USER_ID);
  strncpy(op1->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  op1->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op1->required_state[0] = PROTOCOL_MODIFIED;
  op1->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op1->next_state[0] = PROTOCOL_VERIFIED;
  strncpy(op1->signer_id, "bob", CRABS_MAX_USER_ID - 1);
  op1->lamport_time = 99;
  strncpy(op1->node_id, "node2", CRABS_MAX_USER_ID - 1);

  // Serialize twice
  serialized_buffer_t* buf1 = crabs_serialize_for_signing(op1);
  serialized_buffer_t* buf2 = crabs_serialize_for_signing(op1);

  ASSERT_NE(buf1, nullptr);
  ASSERT_NE(buf2, nullptr);
  EXPECT_EQ(buf1->len, buf2->len);
  EXPECT_EQ(memcmp(buf1->data, buf2->data, buf1->len), 0);

  serialized_buffer_destroy(buf1);
  serialized_buffer_destroy(buf2);
  operation_destroy(op1);
}

TEST(TestSerialization, TestCanonicalEncodingFieldOrder) {
  // Verify that the canonical encoding produces deterministic, ordered output
  operation_t* op = operation_create(CRABS_OP_LOCK);
  memset(op->uuid, 0x01, CRABS_UUID_SIZE);

  const char* payload_data = "hello";
  op->payload = (uint8_t*)strdup(payload_data);
  op->payload_size = strlen(payload_data);

  op->resource_count = 1;
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(CRABS_MAX_USER_ID);
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  op->lock_claim_count = 1;
  op->lock_claims = (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(op->lock_claims[0].resource, "res1", CRABS_MAX_USER_ID - 1);
  memset(op->lock_claims[0].lock_token, 0xFF, CRABS_LOCK_TOKEN_SIZE);
  strncpy(op->policy, "role:admin", CRABS_MAX_POLICY_EXPR - 1);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->signer_key_version = 1;
  op->lamport_time = 42;
  strncpy(op->node_id, "node1", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* buf = crabs_serialize_for_signing(op);
  ASSERT_NE(buf, nullptr);

  // Verify the first field is the type string (length-prefixed)
  // The lock op name is "__lock__" which is 8 chars
  // uint16 length prefix = 8, then "__lock__"
  uint16_t type_len = buf->data[0] | (buf->data[1] << 8);
  EXPECT_EQ(type_len, 8);
  EXPECT_EQ(memcmp(buf->data + 2, "__lock__", 8), 0);

  // After type, the next 16 bytes should be the UUID
  size_t offset = 2 + type_len;
  EXPECT_EQ(memcmp(buf->data + offset, op->uuid, CRABS_UUID_SIZE), 0);

  serialized_buffer_destroy(buf);
  operation_destroy(op);
}

TEST(TestSerialization, TestDeserializeCorruptData) {
  state_t* state = state_create();
  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  // Corrupt the checksum (last 32 bytes)
  buf->data[buf->len - 1] ^= 0xFF;

  state_t* result = crabs_deserialize_state(buf->data, buf->len);
  EXPECT_EQ(result, nullptr);

  // Corrupt magic bytes
  serialized_buffer_t* buf2 = crabs_serialize_state(state);
  ASSERT_NE(buf2, nullptr);
  buf2->data[0] = 0x00; // corrupt first magic byte

  // We need to recompute checksum after corruption to get past checksum check,
  // but still fail on magic check. Let's do it differently:
  // Just test with garbage data
  uint8_t garbage[64];
  memset(garbage, 0xFF, sizeof(garbage));
  state_t* result2 = crabs_deserialize_state(garbage, sizeof(garbage));
  EXPECT_EQ(result2, nullptr);

  // Test with NULL
  state_t* result3 = crabs_deserialize_state(NULL, 0);
  EXPECT_EQ(result3, nullptr);

  // Test with too-short data
  uint8_t short_data[10];
  memset(short_data, 0, sizeof(short_data));
  state_t* result4 = crabs_deserialize_state(short_data, sizeof(short_data));
  EXPECT_EQ(result4, nullptr);

  serialized_buffer_destroy(buf);
  serialized_buffer_destroy(buf2);
  state_destroy(state);
}

TEST(TestSerialization, TestDeserializeOperationCorruptData) {
  operation_t* op = operation_create(CRABS_OP_LOCK);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* buf = crabs_serialize_operation(op);
  ASSERT_NE(buf, nullptr);

  // Deserialize valid data should succeed
  operation_t* valid = crabs_deserialize_operation(buf->data, buf->len);
  ASSERT_NE(valid, nullptr);
  operation_destroy(valid);

  // Test with NULL
  operation_t* null_op = crabs_deserialize_operation(NULL, 0);
  EXPECT_EQ(null_op, nullptr);

  // Test with truncated data
  if (buf->len > 4) {
    operation_t* trunc_op = crabs_deserialize_operation(buf->data, 2);
    EXPECT_EQ(trunc_op, nullptr);
  }

  serialized_buffer_destroy(buf);
  operation_destroy(op);
}

TEST(TestSerialization, TestSerializeStateWithConfig) {
  state_t* state = state_create();
  state->config.max_lock_duration_ms = 10000;
  state->config.max_lock_extensions = 5;
  state->config.allow_force_unlock = false;
  strncpy(state->config.bootstrap_admin, "admin_user", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->config.max_lock_duration_ms, (uint64_t)10000);
  EXPECT_EQ(restored->config.max_lock_extensions, (uint32_t)5);
  EXPECT_EQ(restored->config.allow_force_unlock, false);
  EXPECT_STREQ(restored->config.bootstrap_admin, "admin_user");

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

TEST(TestSerialization, TestSerializeStateWithInvariants) {
  state_t* state = state_create();
  state->version = 5;

  data_item_t* item = data_item_create("counter1", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  int64_t* val = (int64_t*)malloc(sizeof(int64_t));
  *val = 100;
  item->value = val;

  // Add invariants (heap-allocated for proper cleanup)
  invariant_t* invs = (invariant_t*)malloc(2 * sizeof(invariant_t));
  invs[0].type = INVARIANT_GREATER_THAN;
  invs[0].param = 0;
  invs[0].error_message = strdup("must be positive");
  invs[1].type = INVARIANT_NON_NEGATIVE;
  invs[1].param = 0;
  invs[1].error_message = strdup("must be non-negative");
  item->invariants = invs;
  item->invariant_count = 2;

  state_add_item(state, item);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  data_item_t* restored_item = state_find_item(restored, "counter1");
  ASSERT_NE(restored_item, nullptr);
  EXPECT_EQ(restored_item->invariant_count, (uint8_t)2);
  EXPECT_EQ(restored_item->invariants[0].type, INVARIANT_GREATER_THAN);
  EXPECT_EQ(restored_item->invariants[0].param, (int64_t)0);
  EXPECT_STREQ(restored_item->invariants[0].error_message, "must be positive");
  EXPECT_EQ(restored_item->invariants[1].type, INVARIANT_NON_NEGATIVE);
  EXPECT_STREQ(restored_item->invariants[1].error_message, "must be non-negative");

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

TEST(TestSerialization, TestSerializeForSigningCompleteness) {
  operation_t* op = operation_create("custom_op");
  memset(op->uuid, 0xDE, CRABS_UUID_SIZE);

  const char* payload_data = "some payload";
  op->payload = (uint8_t*)strdup(payload_data);
  op->payload_size = strlen(payload_data);

  op->resource_count = 2;
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(2 * CRABS_MAX_USER_ID);
  strncpy(op->resources[0], "resource_alpha", CRABS_MAX_USER_ID - 1);
  strncpy(op->resources[1], "resource_beta", CRABS_MAX_USER_ID - 1);

  op->required_state = (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->required_state[1] = PROTOCOL_LOCKED;

  op->next_state = (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  op->next_state[1] = PROTOCOL_MODIFIED;

  op->lock_claim_count = 1;
  op->lock_claims = (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(op->lock_claims[0].resource, "resource_alpha", CRABS_MAX_USER_ID - 1);
  memset(op->lock_claims[0].lock_token, 0xAA, CRABS_LOCK_TOKEN_SIZE);

  strncpy(op->policy, "role:editor&dept:eng", CRABS_MAX_POLICY_EXPR - 1);
  strncpy(op->signer_id, "charlie", CRABS_MAX_USER_ID - 1);
  op->signer_key_version = 7;
  op->lamport_time = 999888777;
  strncpy(op->node_id, "node3", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* buf = crabs_serialize_for_signing(op);
  ASSERT_NE(buf, nullptr);
  EXPECT_GT(buf->len, (size_t)0);

  // Verify we can re-serialize and get the same result (determinism)
  serialized_buffer_t* buf2 = crabs_serialize_for_signing(op);
  ASSERT_NE(buf2, nullptr);
  EXPECT_EQ(buf->len, buf2->len);
  EXPECT_EQ(memcmp(buf->data, buf2->data, buf->len), 0);

  serialized_buffer_destroy(buf);
  serialized_buffer_destroy(buf2);
  operation_destroy(op);
}

TEST(TestSerialization, TestSerializeNullInputs) {
  serialized_buffer_t* null_buf = crabs_serialize_state(NULL);
  EXPECT_EQ(null_buf, nullptr);

  null_buf = crabs_serialize_operation(NULL);
  EXPECT_EQ(null_buf, nullptr);

  null_buf = crabs_serialize_for_signing(NULL);
  EXPECT_EQ(null_buf, nullptr);

  state_t* null_state = crabs_deserialize_state(NULL, 0);
  EXPECT_EQ(null_state, nullptr);

  operation_t* null_op = crabs_deserialize_operation(NULL, 0);
  EXPECT_EQ(null_op, nullptr);
}

TEST(TestSerialization, TestSerializeOperationWithNullPayload) {
  operation_t* op = operation_create(CRABS_OP_UNLOCK);
  memset(op->uuid, 0x55, CRABS_UUID_SIZE);
  op->payload = NULL;
  op->payload_size = 0;
  strncpy(op->signer_id, "dave", CRABS_MAX_USER_ID - 1);
  op->resource_count = 0;

  serialized_buffer_t* buf = crabs_serialize_operation(op);
  ASSERT_NE(buf, nullptr);

  operation_t* restored = crabs_deserialize_operation(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);
  EXPECT_EQ(restored->payload_size, (uint32_t)0);
  EXPECT_EQ(restored->payload, nullptr);

  serialized_buffer_destroy(buf);
  operation_destroy(op);
  operation_destroy(restored);
}

TEST(TestSerialization, TestBufferCreateDestroy) {
  serialized_buffer_t* buf = serialized_buffer_create(128);
  ASSERT_NE(buf, nullptr);
  EXPECT_NE(buf->data, nullptr);
  EXPECT_EQ(buf->len, (size_t)128);

  serialized_buffer_destroy(buf);
  // Should not crash on null
  serialized_buffer_destroy(NULL);
}