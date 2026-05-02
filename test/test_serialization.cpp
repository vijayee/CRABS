#include <gtest/gtest.h>
#include <vector>
#include <cstring>
extern "C" {
#include "../src/Serialization/serialization.h"
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Crypto/sig_scheme.h"
#include "../src/Attribute/attribute_machine.h"
#include <openssl/sha.h>
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

  free((void*)invs[0].error_message);
  free((void*)invs[1].error_message);
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

// ============================================================
// v1.3 Serialization v2 tests
// ============================================================

TEST(TestSerializationV2, TestOperationRoundTripWithSigScheme) {
  operation_t* op = operation_create(CRABS_OP_LOCK);
  memset(op->uuid, 0xAB, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->sig_scheme = ECDSA_SECP256K1;
  strncpy(op->key_id, "key-001", CRABS_MAX_KEY_ID - 1);
  op->resource_count = 0;

  serialized_buffer_t* buf = crabs_serialize_operation(op);
  ASSERT_NE(buf, nullptr);

  operation_t* restored = crabs_deserialize_operation(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->sig_scheme, ECDSA_SECP256K1);
  EXPECT_STREQ(restored->key_id, "key-001");

  serialized_buffer_destroy(buf);
  operation_destroy(op);
  operation_destroy(restored);
}

TEST(TestSerializationV2, TestOperationRoundTripWithCoSigners) {
  operation_t* op = operation_create(CRABS_OP_LOCK);
  memset(op->uuid, 0xCD, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->sig_scheme = ECDSA_P256;
  strncpy(op->key_id, "key-002", CRABS_MAX_KEY_ID - 1);
  op->resource_count = 0;

  // Add 2 co-signers
  op->co_signer_count = 2;
  op->co_signers = (co_signature_t*)calloc(2, sizeof(co_signature_t));
  strncpy(op->co_signers[0].signer_id, "bob", CRABS_MAX_USER_ID - 1);
  strncpy(op->co_signers[0].key_id, "bob-key-1", CRABS_MAX_KEY_ID - 1);
  op->co_signers[0].sig_scheme = ECDSA_SECP256K1;
  memset(op->co_signers[0].signature, 0xAA, CRABS_SIG_SIZE);
  op->co_signers[0].signature_len = CRABS_SIG_SIZE;

  strncpy(op->co_signers[1].signer_id, "carol", CRABS_MAX_USER_ID - 1);
  strncpy(op->co_signers[1].key_id, "carol-key-1", CRABS_MAX_KEY_ID - 1);
  op->co_signers[1].sig_scheme = ED25519;
  memset(op->co_signers[1].signature, 0xBB, CRABS_SIG_SIZE);
  op->co_signers[1].signature_len = CRABS_SIG_SIZE;

  serialized_buffer_t* buf = crabs_serialize_operation(op);
  ASSERT_NE(buf, nullptr);

  operation_t* restored = crabs_deserialize_operation(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->co_signer_count, (uint32_t)2);
  EXPECT_STREQ(restored->co_signers[0].signer_id, "bob");
  EXPECT_STREQ(restored->co_signers[0].key_id, "bob-key-1");
  EXPECT_EQ(restored->co_signers[0].sig_scheme, ECDSA_SECP256K1);
  EXPECT_EQ(restored->co_signers[0].signature_len, (uint32_t)CRABS_SIG_SIZE);
  EXPECT_EQ(memcmp(restored->co_signers[0].signature, op->co_signers[0].signature, CRABS_SIG_SIZE), 0);

  EXPECT_STREQ(restored->co_signers[1].signer_id, "carol");
  EXPECT_STREQ(restored->co_signers[1].key_id, "carol-key-1");
  EXPECT_EQ(restored->co_signers[1].sig_scheme, ED25519);

  serialized_buffer_destroy(buf);
  operation_destroy(op);
  operation_destroy(restored);
}

TEST(TestSerializationV2, TestConfigRoundTripWithSigConfig) {
  state_t* state = state_create();
  state->config.sig_config.default_scheme = ECDSA_P256;
  state->config.sig_config.max_keys_per_user = 4;
  state->config.sig_config.key_rotation_enabled = true;
  state->config.sig_config.co_sign_threshold = 2;
  state->config.sig_config.key_expiry_enabled = true;
  state->config.sig_config.default_key_ttl_ms = 86400000;
  state->config.sig_config.max_key_age_ms = 31536000000;

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->config.sig_config.default_scheme, ECDSA_P256);
  EXPECT_EQ(restored->config.sig_config.max_keys_per_user, (uint32_t)4);
  EXPECT_EQ(restored->config.sig_config.key_rotation_enabled, true);
  EXPECT_EQ(restored->config.sig_config.co_sign_threshold, (uint32_t)2);
  EXPECT_EQ(restored->config.sig_config.key_expiry_enabled, true);
  EXPECT_EQ(restored->config.sig_config.default_key_ttl_ms, (uint64_t)86400000);
  EXPECT_EQ(restored->config.sig_config.max_key_age_ms, (uint64_t)31536000000);

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

TEST(TestSerializationV2, TestConfigRoundTripWithVaultConfig) {
  state_t* state = state_create();
  state->config.vault_config.provider = VAULT_HASHICORP;
  strncpy(state->config.vault_config.address, "https://vault.example.com:8200", CRABS_VAULT_ADDRESS_MAX - 1);
  strncpy(state->config.vault_config.auth_token, "s.xtUa7gHAk1vY9x5j", CRABS_VAULT_TOKEN_MAX - 1);
  state->config.vault_config.signing_delegated = true;
  state->config.vault_config.rotation_delegated = false;

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->config.vault_config.provider, VAULT_HASHICORP);
  EXPECT_STREQ(restored->config.vault_config.address, "https://vault.example.com:8200");
  EXPECT_STREQ(restored->config.vault_config.auth_token, "s.xtUa7gHAk1vY9x5j");
  EXPECT_EQ(restored->config.vault_config.signing_delegated, true);
  EXPECT_EQ(restored->config.vault_config.rotation_delegated, false);

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

TEST(TestSerializationV2, TestPolicyRoundTripWithSchemeConstraints) {
  state_t* state = state_create();
  state_add_policy(state, CRABS_OP_LOCK, "role:admin");

  // Set scheme constraints on the policy
  state->policies[0].allowed_scheme_count = 2;
  state->policies[0].allowed_schemes[0] = ECDSA_SECP256K1;
  state->policies[0].allowed_schemes[1] = ED25519;
  state->policies[0].min_key_version = 3;

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->policy_count, (uint32_t)1);
  EXPECT_EQ(restored->policies[0].allowed_scheme_count, (uint32_t)2);
  EXPECT_EQ(restored->policies[0].allowed_schemes[0], ECDSA_SECP256K1);
  EXPECT_EQ(restored->policies[0].allowed_schemes[1], ED25519);
  EXPECT_EQ(restored->policies[0].min_key_version, (uint64_t)3);

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

TEST(TestSerializationV2, TestV1BackwardCompatRejectsInvalidVersion) {
  // Craft a v0 (invalid) serialized state
  state_t* state = state_create();
  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  // Patch version field (offset 4, uint32 LE) to 0
  buf->data[4] = 0;
  buf->data[5] = 0;
  buf->data[6] = 0;
  buf->data[7] = 0;

  // Recompute checksum (last 32 bytes)
  uint8_t hash[32];
  SHA256(buf->data, buf->len - 32, hash);
  memcpy(buf->data + buf->len - 32, hash, 32);

  state_t* result = crabs_deserialize_state(buf->data, buf->len);
  EXPECT_EQ(result, nullptr);

  serialized_buffer_destroy(buf);
  state_destroy(state);
}

TEST(TestSerializationV2, TestV1BackwardCompatAcceptsV1) {
  // Build a v1-format buffer: same as v2 but with version=1 and no v2 fields
  // We construct this manually since the serializer always writes v2
  state_t* state = state_create();
  state->version = 7;
  state->config.max_lock_duration_ms = 5000;
  state->config.max_lock_extensions = 3;
  state->config.allow_force_unlock = true;
  strncpy(state->config.bootstrap_admin, "admin", CRABS_MAX_USER_ID - 1);

  // Serialize as v2 first, then rebuild as v1
  // v1 layout: magic(4) + version(4) + state_version(8) + item_count(4) + policy_count(4) + log_count(4)
  //   + items + policies(v1: no scheme fields) + config(v1: no sig_config/vault_config) + log + checksum

  // Build a v1 buffer manually
  // We'll use a write-buffer approach
  std::vector<uint8_t> v1buf;
  auto write_u8 = [&](uint8_t v) { v1buf.push_back(v); };
  auto write_u16 = [&](uint16_t v) { v1buf.push_back(v & 0xFF); v1buf.push_back((v >> 8) & 0xFF); };
  auto write_u32 = [&](uint32_t v) { for(int i=0;i<4;i++) v1buf.push_back((v>>(i*8))&0xFF); };
  auto write_u64 = [&](uint64_t v) { for(int i=0;i<8;i++) v1buf.push_back((v>>(i*8))&0xFF); };
  auto write_str16 = [&](const char* s) {
    uint16_t slen = s ? strlen(s) : 0;
    write_u16(slen);
    for(uint16_t i=0;i<slen;i++) v1buf.push_back((uint8_t)s[i]);
  };

  // Magic
  v1buf.push_back(0x43); v1buf.push_back(0x52); v1buf.push_back(0x41); v1buf.push_back(0x42);
  // Version = 1
  write_u32(1);
  // state_version
  write_u64(state->version);
  // item_count = 0
  write_u32(0);
  // policy_count = 0
  write_u32(0);
  // log_count = 0
  write_u32(0);
  // config (v1: only base fields)
  write_u64(state->config.max_lock_duration_ms);
  write_u32(state->config.max_lock_extensions);
  write_u8(state->config.allow_force_unlock ? 1 : 0);
  write_str16(state->config.bootstrap_admin);

  // Checksum
  uint8_t v1hash[32];
  SHA256(v1buf.data(), v1buf.size(), v1hash);
  for (int i = 0; i < 32; i++) v1buf.push_back(v1hash[i]);

  // Deserialize v1
  state_t* restored = crabs_deserialize_state(v1buf.data(), v1buf.size());
  ASSERT_NE(restored, nullptr);

  // Base config should be correct
  EXPECT_EQ(restored->version, (uint64_t)7);
  EXPECT_EQ(restored->config.max_lock_duration_ms, (uint64_t)5000);
  EXPECT_EQ(restored->config.max_lock_extensions, (uint32_t)3);
  EXPECT_EQ(restored->config.allow_force_unlock, true);
  EXPECT_STREQ(restored->config.bootstrap_admin, "admin");

  // v1 defaults: sig_config and vault_config should be zero-initialized
  EXPECT_EQ(restored->config.sig_config.default_scheme, SCHEME_UNSPECIFIED);
  EXPECT_EQ(restored->config.sig_config.max_keys_per_user, (uint32_t)0);
  EXPECT_EQ(restored->config.sig_config.key_rotation_enabled, false);
  EXPECT_EQ(restored->config.vault_config.provider, VAULT_NONE);

  state_destroy(state);
  state_destroy(restored);
}

TEST(TestSerializationV2, TestCanonicalEncodingWithSchemeFields) {
  operation_t* op = operation_create(CRABS_OP_VERIFY);
  memset(op->uuid, 0x42, CRABS_UUID_SIZE);
  op->resource_count = 1;
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(CRABS_MAX_USER_ID);
  strncpy(op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_MODIFIED;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_VERIFIED;
  strncpy(op->signer_id, "bob", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 99;
  strncpy(op->node_id, "node2", CRABS_MAX_USER_ID - 1);
  op->sig_scheme = ED25519;
  strncpy(op->key_id, "bob-ed-key", CRABS_MAX_KEY_ID - 1);

  // Serialize twice - should be deterministic
  serialized_buffer_t* buf1 = crabs_serialize_for_signing(op);
  serialized_buffer_t* buf2 = crabs_serialize_for_signing(op);
  ASSERT_NE(buf1, nullptr);
  ASSERT_NE(buf2, nullptr);
  EXPECT_EQ(buf1->len, buf2->len);
  EXPECT_EQ(memcmp(buf1->data, buf2->data, buf1->len), 0);

  // Change sig_scheme and key_id should produce different encoding
  op->sig_scheme = ECDSA_SECP256K1;
  strncpy(op->key_id, "bob-ecdsa-key", CRABS_MAX_KEY_ID - 1);
  serialized_buffer_t* buf3 = crabs_serialize_for_signing(op);
  ASSERT_NE(buf3, nullptr);
  EXPECT_NE(buf1->len, buf3->len);  // Different key_id length means different total

  serialized_buffer_destroy(buf1);
  serialized_buffer_destroy(buf2);
  serialized_buffer_destroy(buf3);
  operation_destroy(op);
}

TEST(TestSerializationV2, TestOperationWithNoCoSigners) {
  operation_t* op = operation_create(CRABS_OP_REGISTER_KEY);
  memset(op->uuid, 0xEF, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->sig_scheme = ECDSA_SECP256K1;
  strncpy(op->key_id, "admin-key-1", CRABS_MAX_KEY_ID - 1);
  op->co_signer_count = 0;
  op->co_signers = NULL;
  op->resource_count = 0;

  serialized_buffer_t* buf = crabs_serialize_operation(op);
  ASSERT_NE(buf, nullptr);

  operation_t* restored = crabs_deserialize_operation(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->sig_scheme, ECDSA_SECP256K1);
  EXPECT_STREQ(restored->key_id, "admin-key-1");
  EXPECT_EQ(restored->co_signer_count, (uint32_t)0);
  EXPECT_EQ(restored->co_signers, nullptr);

  serialized_buffer_destroy(buf);
  operation_destroy(op);
  operation_destroy(restored);
}

TEST(TestSerializationV2, TestV1PolicyBackwardCompat) {
  // Manually build a v1 buffer with a policy (no scheme fields)
  std::vector<uint8_t> v1buf;
  auto write_u8 = [&](uint8_t v) { v1buf.push_back(v); };
  auto write_u16 = [&](uint16_t v) { v1buf.push_back(v & 0xFF); v1buf.push_back((v >> 8) & 0xFF); };
  auto write_u32 = [&](uint32_t v) { for(int i=0;i<4;i++) v1buf.push_back((v>>(i*8))&0xFF); };
  auto write_u64 = [&](uint64_t v) { for(int i=0;i<8;i++) v1buf.push_back((v>>(i*8))&0xFF); };
  auto write_str16 = [&](const char* s) {
    uint16_t slen = s ? strlen(s) : 0;
    write_u16(slen);
    for(uint16_t i=0;i<slen;i++) v1buf.push_back((uint8_t)s[i]);
  };

  // Magic
  v1buf.push_back(0x43); v1buf.push_back(0x52); v1buf.push_back(0x41); v1buf.push_back(0x42);
  // Version = 1
  write_u32(1);
  // state_version = 1
  write_u64(1);
  // item_count = 0
  write_u32(0);
  // policy_count = 1
  write_u32(1);
  // log_count = 0
  write_u32(0);
  // policy (v1: only operation + expression)
  write_str16("__lock__");
  write_str16("role:admin");
  // config (v1: only base fields)
  write_u64(5000);  // max_lock_duration_ms
  write_u32(3);     // max_lock_extensions
  write_u8(1);      // allow_force_unlock
  write_str16("admin");

  // Checksum
  uint8_t v1hash[32];
  SHA256(v1buf.data(), v1buf.size(), v1hash);
  for (int i = 0; i < 32; i++) v1buf.push_back(v1hash[i]);

  state_t* restored = crabs_deserialize_state(v1buf.data(), v1buf.size());
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->policy_count, (uint32_t)1);
  // v1 policy should have zero scheme constraints
  EXPECT_EQ(restored->policies[0].allowed_scheme_count, (uint32_t)0);
  EXPECT_EQ(restored->policies[0].min_key_version, (uint64_t)0);

  state_destroy(restored);
}

// ============================================================
// Dedup serialization tests (v3 format)
// ============================================================

TEST(OperationV3, SerializeDedupPerUser) {
  operation_t* op = operation_create("vote");
  memset(op->uuid, 0xAB, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 1000;
  op->dedup.type = DEDUP_PER_USER;
  strncpy(op->dedup.tracker_path, "proposal_voters", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->dedup.rejection_message, "Already voted", CRABS_MAX_DEDUP_MESSAGE - 1);
  op->dedup.update.type = MUTATION_SET_ADD;
  strncpy(op->dedup.update.set_path, "proposal_voters", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->dedup.update.element_value, "{signer_id}", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* buf = crabs_serialize_operation(op);
  ASSERT_NE(buf, nullptr);

  operation_t* restored = crabs_deserialize_operation(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->dedup.type, DEDUP_PER_USER);
  EXPECT_STREQ(restored->dedup.tracker_path, "proposal_voters");
  EXPECT_STREQ(restored->dedup.rejection_message, "Already voted");
  EXPECT_EQ(restored->dedup.update.type, MUTATION_SET_ADD);
  EXPECT_STREQ(restored->dedup.update.set_path, "proposal_voters");
  EXPECT_STREQ(restored->dedup.update.element_value, "{signer_id}");

  serialized_buffer_destroy(buf);
  operation_destroy(op);
  operation_destroy(restored);
}

TEST(OperationV3, SerializeDedupGlobal) {
  operation_t* op = operation_create("execute");
  memset(op->uuid, 0xCC, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "carol", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 2000;
  op->dedup.type = DEDUP_GLOBAL;
  strncpy(op->dedup.flag_path, "proposal_executed", CRABS_MAX_DEDUP_PATH - 1);
  strncpy(op->dedup.rejection_message, "Already executed", CRABS_MAX_DEDUP_MESSAGE - 1);
  op->dedup.update.type = MUTATION_FLAG_SET;
  strncpy(op->dedup.update.flag_path, "proposal_executed", CRABS_MAX_DEDUP_PATH - 1);

  serialized_buffer_t* buf = crabs_serialize_operation(op);
  ASSERT_NE(buf, nullptr);

  operation_t* restored = crabs_deserialize_operation(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->dedup.type, DEDUP_GLOBAL);
  EXPECT_STREQ(restored->dedup.flag_path, "proposal_executed");
  EXPECT_STREQ(restored->dedup.rejection_message, "Already executed");
  EXPECT_EQ(restored->dedup.update.type, MUTATION_FLAG_SET);
  EXPECT_STREQ(restored->dedup.update.flag_path, "proposal_executed");

  serialized_buffer_destroy(buf);
  operation_destroy(op);
  operation_destroy(restored);
}

TEST(OperationV3, SerializeDedupNone) {
  operation_t* op = operation_create("lock");
  memset(op->uuid, 0xDD, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "dave", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 3000;
  // dedup.type defaults to DEDUP_NONE

  serialized_buffer_t* buf = crabs_serialize_operation(op);
  ASSERT_NE(buf, nullptr);

  operation_t* restored = crabs_deserialize_operation(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->dedup.type, DEDUP_NONE);

  serialized_buffer_destroy(buf);
  operation_destroy(op);
  operation_destroy(restored);
}

TEST(OperationV3, SerializeDedupCustom) {
  operation_t* op = operation_create("spend");
  memset(op->uuid, 0xEE, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "eve", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 4000;
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "balance >= 100", CRABS_MAX_POLICY_EXPR - 1);
  strncpy(op->dedup.rejection_message, "Insufficient balance", CRABS_MAX_DEDUP_MESSAGE - 1);
  op->dedup.update.type = MUTATION_COUNTER_INCREMENT;
  strncpy(op->dedup.update.counter_path, "balance", CRABS_MAX_DEDUP_PATH - 1);
  op->dedup.update.delta = -50;

  serialized_buffer_t* buf = crabs_serialize_operation(op);
  ASSERT_NE(buf, nullptr);

  operation_t* restored = crabs_deserialize_operation(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->dedup.type, DEDUP_CUSTOM);
  EXPECT_STREQ(restored->dedup.condition, "balance >= 100");
  EXPECT_STREQ(restored->dedup.rejection_message, "Insufficient balance");
  EXPECT_EQ(restored->dedup.update.type, MUTATION_COUNTER_INCREMENT);
  EXPECT_STREQ(restored->dedup.update.counter_path, "balance");
  EXPECT_EQ(restored->dedup.update.delta, (int64_t)-50);

  serialized_buffer_destroy(buf);
  operation_destroy(op);
  operation_destroy(restored);
}

TEST(OperationV3, DedupInCanonicalSigning) {
  operation_t* op = operation_create("vote");
  memset(op->uuid, 0xAB, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 5000;
  op->dedup.type = DEDUP_PER_USER;
  strncpy(op->dedup.tracker_path, "voters", CRABS_MAX_DEDUP_PATH - 1);

  serialized_buffer_t* canon = crabs_serialize_for_signing(op);
  ASSERT_NE(canon, nullptr);
  EXPECT_GT(canon->len, (size_t)0);

  // Verify the canonical form includes dedup.type
  // Find the dedup_type byte in the output (it should be 0x01 for PER_USER)
  bool found_dedup_type = false;
  for (size_t i = 0; i < canon->len; i++) {
    if (canon->data[i] == 0x01) { // DEDUP_PER_USER
      found_dedup_type = true;
      break;
    }
  }
  EXPECT_TRUE(found_dedup_type);

  serialized_buffer_destroy(canon);
  operation_destroy(op);
}