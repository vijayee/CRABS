#include <gtest/gtest.h>
#include <vector>
#include <cstring>
#include <cstdio>
extern "C" {
#include "../src/Serialization/serialization.h"
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Lineage/lineage.h"
#include "../src/Scheduler/scheduler.h"
#include "../src/Crypto/sig_scheme.h"
#include "../src/Crypto/crypto.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/CRDT/crdt_merge.h"
#include "../src/Trigger/trigger.h"
#include "../src/OT/ot_ordered_set.h"
#include "../src/Util/allocator.h"
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
  g_counter_t* counter = g_counter_create();
  ASSERT_EQ(g_counter_increment(counter, "node1", 12345), CRABS_SUCCESS);
  item->value = counter;
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
  EXPECT_EQ(g_counter_value((g_counter_t*)restored_item->value), (int64_t)12345);

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

// Struct-backed counter items must survive a state save/load: pre-fix the
// serializer wrote the first 8 bytes of the g_counter struct (the entries
// heap pointer) and the deserializer rebuilt a bare int64 from them, so a
// restored counter was a dangling-pointer-as-int that the first
// g_counter_increment dereferenced as a g_counter — heap corruption. The
// chain digest also hashed those pointer bytes, so it was unstable across a
// restart even for unchanged content.
TEST(TestSerialization, StructBackedCounterSurvivesStateRoundTrip) {
  state_t* original = state_create();
  data_item_t* item = data_item_create("gc", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* counter = g_counter_create();
  ASSERT_EQ(g_counter_increment(counter, "node1", 5), CRABS_SUCCESS);
  ASSERT_EQ(g_counter_increment(counter, "node2", 7), CRABS_SUCCESS);
  item->value = counter;
  state_add_item(original, item);

  uint8_t digest_before[CRABS_HASH_SIZE];
  ASSERT_EQ(state_item_digest_compute(item, digest_before), CRABS_SUCCESS);

  serialized_buffer_t* buf = crabs_serialize_state(original);
  ASSERT_NE(buf, nullptr);
  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  data_item_t* restored_item = state_find_item(restored, "gc");
  ASSERT_NE(restored_item, nullptr);
  ASSERT_EQ(restored_item->crdt_type, CRDT_G_COUNTER);
  // Logical content survived: value readable through the g-counter API...
  EXPECT_EQ(g_counter_value((g_counter_t*)restored_item->value), (int64_t)12);
  // ...and further increments on the restored replica keep working.
  ASSERT_EQ(g_counter_increment((g_counter_t*)restored_item->value, "node1", 3),
            CRABS_SUCCESS);
  EXPECT_EQ(g_counter_value((g_counter_t*)restored_item->value), (int64_t)15);

  // Restart with unchanged content must NOT move the chain digest.
  state_t* restored2 = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored2, nullptr);
  data_item_t* restored_item2 = state_find_item(restored2, "gc");
  ASSERT_NE(restored_item2, nullptr);
  uint8_t digest_after[CRABS_HASH_SIZE];
  ASSERT_EQ(state_item_digest_compute(restored_item2, digest_after), CRABS_SUCCESS);
  EXPECT_EQ(memcmp(digest_before, digest_after, CRABS_HASH_SIZE), 0)
      << "chain digest must be stable across a save/load restart";

  // Struct-backed values: release properly (data_item_destroy's default arm
  // frees only the g_counter shell — pre-existing destroy gap).
  g_counter_destroy((g_counter_t*)state_find_item(original, "gc")->value);
  state_find_item(original, "gc")->value = nullptr;
  g_counter_destroy((g_counter_t*)restored_item->value);
  restored_item->value = nullptr;
  g_counter_destroy((g_counter_t*)restored_item2->value);
  restored_item2->value = nullptr;
  serialized_buffer_destroy(buf);
  state_destroy(original);
  state_destroy(restored);
  state_destroy(restored2);
}

// Struct-backed LWW register items must likewise survive a state round-trip
// with their (value, timestamp, node) content intact.
TEST(TestSerialization, StructBackedRegisterSurvivesStateRoundTrip) {
  state_t* original = state_create();
  data_item_t* item = data_item_create("reg", DATA_TYPE_REGISTER, CRDT_LWW_REG);
  int64_t stored = 0x1234;
  item->value = lww_register_create((const uint8_t*)&stored, sizeof(int64_t),
                                    77, "writer1");
  ASSERT_NE(item->value, nullptr);
  state_add_item(original, item);

  uint8_t digest_before[CRABS_HASH_SIZE];
  ASSERT_EQ(state_item_digest_compute(item, digest_before), CRABS_SUCCESS);

  serialized_buffer_t* buf = crabs_serialize_state(original);
  ASSERT_NE(buf, nullptr);
  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  data_item_t* restored_item = state_find_item(restored, "reg");
  ASSERT_NE(restored_item, nullptr);
  ASSERT_EQ(restored_item->crdt_type, CRDT_LWW_REG);
  lww_register_t* reg = (lww_register_t*)restored_item->value;
  ASSERT_NE(reg, nullptr);
  ASSERT_EQ(reg->value_size, (uint32_t)sizeof(int64_t));
  int64_t round_value = 0;
  memcpy(&round_value, reg->value, sizeof(int64_t));
  EXPECT_EQ(round_value, (int64_t)0x1234);
  EXPECT_EQ(reg->timestamp, (uint64_t)77);
  EXPECT_STREQ(reg->node_id, "writer1");

  uint8_t digest_after[CRABS_HASH_SIZE];
  ASSERT_EQ(state_item_digest_compute(restored_item, digest_after), CRABS_SUCCESS);
  EXPECT_EQ(memcmp(digest_before, digest_after, CRABS_HASH_SIZE), 0)
      << "register chain digest must be stable across a save/load restart";

  lww_register_destroy((lww_register_t*)state_find_item(original, "reg")->value);
  state_find_item(original, "reg")->value = nullptr;
  lww_register_destroy((lww_register_t*)reg);
  restored_item->value = nullptr;
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
  g_counter_t* counter2 = g_counter_create();
  ASSERT_EQ(g_counter_increment(counter2, "node1", 42), CRABS_SUCCESS);
  item2->value = counter2;
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
  EXPECT_EQ(g_counter_value((g_counter_t*)r2->value), (int64_t)42);

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

// R7-15: the wire format dropped ordering_system + HLC fields that the
// canonical signing form includes, so an HLC-ordered op could not verify after
// gossip (the deserialized op re-serialized to different bytes). The wire
// format must preserve the same field set.
TEST(TestSerialization, TestHlcOrderingSurvivesWireRoundTrip) {
  operation_t* original = operation_create(CRABS_OP_LOCK);
  memset(original->uuid, 0x77, CRABS_UUID_SIZE);
  original->ordering_system = CRABS_ORDERING_HLC;
  original->hlc.physical_seconds = 1234567890;
  original->hlc.physical_nanos = 42;
  original->hlc.logical_counter = 7;
  strncpy(original->hlc.node_id, "node-hlc", CRABS_HLC_NODE_ID_SIZE - 1);
  strncpy(original->node_id, "node-hlc", CRABS_MAX_USER_ID - 1);
  original->lamport_time = 0;

  serialized_buffer_t* wire = crabs_serialize_operation(original);
  ASSERT_NE(wire, nullptr);

  operation_t* restored = crabs_deserialize_operation(wire->data, wire->len);
  ASSERT_NE(restored, nullptr);

  // The HLC ordering and fields must survive the wire round-trip.
  EXPECT_EQ(restored->ordering_system, CRABS_ORDERING_HLC);
  EXPECT_EQ(restored->hlc.physical_seconds, (uint64_t)1234567890);
  EXPECT_EQ(restored->hlc.physical_nanos, (uint64_t)42);
  EXPECT_EQ(restored->hlc.logical_counter, (uint64_t)7);
  EXPECT_STREQ(restored->hlc.node_id, "node-hlc");

  // The canonical signing form must be identical before and after gossip.
  serialized_buffer_t* sig1 = crabs_serialize_for_signing(original);
  serialized_buffer_t* sig2 = crabs_serialize_for_signing(restored);
  ASSERT_NE(sig1, nullptr);
  ASSERT_NE(sig2, nullptr);
  EXPECT_EQ(sig1->len, sig2->len);
  EXPECT_EQ(memcmp(sig1->data, sig2->data, sig1->len), 0);

  serialized_buffer_destroy(sig1);
  serialized_buffer_destroy(sig2);
  serialized_buffer_destroy(wire);
  operation_destroy(original);
  operation_destroy(restored);
}

// v1.7 §attestation bridge: operations carry parent attestations on the
// wire. Each entry reuses the attestation wire format, and the deserializer
// owns the heap array exactly like co_signers.
TEST(TestSerialization, TestOperationCarriesAttestationsOnWire) {
  operation_t* original = operation_create(CRABS_OP_CHECK_DEDUP);
  memset(original->uuid, 0x55, CRABS_UUID_SIZE);
  strncpy(original->policy, "@parent/role:writer", CRABS_MAX_POLICY_EXPR - 1);
  memset(original->signature, 0xDD, CRABS_SIG_SIZE);
  strncpy(original->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  original->lamport_time = 42;
  strncpy(original->node_id, "node1", CRABS_MAX_USER_ID - 1);

  // Hand-built attestations: this test covers transport only (opaque
  // signature bytes; semantic verify lives in test_lineage.cpp).
  const uint64_t not_before = 1700000000000ULL;
  attestation_t first_attestation;
  memset(&first_attestation, 0, sizeof(first_attestation));
  first_attestation.format_version = CRABS_ATTESTATION_FORMAT_VERSION;
  strncpy(first_attestation.parent_id, "parent-root",
          sizeof(first_attestation.parent_id) - 1);
  strncpy(first_attestation.child_id, "child-red",
          sizeof(first_attestation.child_id) - 1);
  strncpy(first_attestation.user_id, "alice",
          sizeof(first_attestation.user_id) - 1);
  strncpy(first_attestation.attributes, "role:writer,dept:red",
          sizeof(first_attestation.attributes) - 1);
  first_attestation.not_before = not_before;
  first_attestation.expires_at = not_before + 60000;
  memset(first_attestation.signature, 0x44, CRABS_SIG_SIZE);

  attestation_t second_attestation;
  memset(&second_attestation, 0, sizeof(second_attestation));
  second_attestation.format_version = CRABS_ATTESTATION_FORMAT_VERSION;
  strncpy(second_attestation.parent_id, "parent-root",
          sizeof(second_attestation.parent_id) - 1);
  strncpy(second_attestation.child_id, "child-red",
          sizeof(second_attestation.child_id) - 1);
  strncpy(second_attestation.user_id, "bob",
          sizeof(second_attestation.user_id) - 1);
  strncpy(second_attestation.attributes, "custody:video",
          sizeof(second_attestation.attributes) - 1);
  second_attestation.not_before = not_before;
  second_attestation.expires_at = not_before + 120000;
  memset(second_attestation.signature, 0x66, CRABS_SIG_SIZE);

  original->attestations = (attestation_t*)malloc(2 * sizeof(attestation_t));
  ASSERT_NE(original->attestations, nullptr);
  original->attestations[0] = first_attestation;
  original->attestations[1] = second_attestation;
  original->attestation_count = 2;

  serialized_buffer_t* wire = crabs_serialize_operation(original);
  ASSERT_NE(wire, nullptr);

  operation_t* restored = crabs_deserialize_operation(wire->data, wire->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->attestation_count, 2u);
  ASSERT_NE(restored->attestations, nullptr);
  EXPECT_EQ(restored->attestations[0].format_version,
            CRABS_ATTESTATION_FORMAT_VERSION);
  EXPECT_STREQ(restored->attestations[0].parent_id, "parent-root");
  EXPECT_STREQ(restored->attestations[0].child_id, "child-red");
  EXPECT_STREQ(restored->attestations[0].user_id, "alice");
  EXPECT_STREQ(restored->attestations[0].attributes, "role:writer,dept:red");
  EXPECT_EQ(restored->attestations[0].not_before, not_before);
  EXPECT_EQ(restored->attestations[0].expires_at, not_before + 60000);
  EXPECT_EQ(memcmp(restored->attestations[0].signature,
                   first_attestation.signature, CRABS_SIG_SIZE), 0);
  EXPECT_STREQ(restored->attestations[1].user_id, "bob");
  EXPECT_STREQ(restored->attestations[1].attributes, "custody:video");
  EXPECT_EQ(memcmp(restored->attestations[1].signature,
                   second_attestation.signature, CRABS_SIG_SIZE), 0);

  // The canonical signing form excludes attestations (each carries its own
  // parent signature), so signing bytes are stable across the round trip.
  serialized_buffer_t* sig1 = crabs_serialize_for_signing(original);
  serialized_buffer_t* sig2 = crabs_serialize_for_signing(restored);
  ASSERT_NE(sig1, nullptr);
  ASSERT_NE(sig2, nullptr);
  EXPECT_EQ(sig1->len, sig2->len);
  EXPECT_EQ(memcmp(sig1->data, sig2->data, sig1->len), 0);

  serialized_buffer_destroy(sig1);
  serialized_buffer_destroy(sig2);
  serialized_buffer_destroy(wire);
  operation_destroy(original);
  operation_destroy(restored);
}

TEST(TestSerialization, TestOperationAttestationCountBoundAndTruncation) {
  // An op serialized WITHOUT attestations still deserializes (count 0).
  operation_t* plain = operation_create(CRABS_OP_CHECK_DEDUP);
  memset(plain->uuid, 0x55, CRABS_UUID_SIZE);
  strncpy(plain->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  serialized_buffer_t* plain_wire = crabs_serialize_operation(plain);
  ASSERT_NE(plain_wire, nullptr);
  operation_t* plain_restored =
      crabs_deserialize_operation(plain_wire->data, plain_wire->len);
  ASSERT_NE(plain_restored, nullptr);
  EXPECT_EQ(plain_restored->attestation_count, 0u);
  EXPECT_EQ(plain_restored->attestations, nullptr);
  serialized_buffer_destroy(plain_wire);
  operation_destroy(plain);
  operation_destroy(plain_restored);

  // A serialized op carrying one attestation, truncated to a fraction of its
  // final byte, must fail closed.
  operation_t* original = operation_create(CRABS_OP_CHECK_DEDUP);
  memset(original->uuid, 0x55, CRABS_UUID_SIZE);
  strncpy(original->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  attestation_t attestation;
  memset(&attestation, 0, sizeof(attestation));
  attestation.format_version = CRABS_ATTESTATION_FORMAT_VERSION;
  strncpy(attestation.parent_id, "parent-root",
          sizeof(attestation.parent_id) - 1);
  strncpy(attestation.child_id, "child-red",
          sizeof(attestation.child_id) - 1);
  strncpy(attestation.user_id, "alice", sizeof(attestation.user_id) - 1);
  strncpy(attestation.attributes, "role:writer",
          sizeof(attestation.attributes) - 1);
  attestation.not_before = 1700000000000ULL;
  attestation.expires_at = 1700000060000ULL;
  memset(attestation.signature, 0x44, CRABS_SIG_SIZE);
  original->attestations = (attestation_t*)malloc(sizeof(attestation_t));
  ASSERT_NE(original->attestations, nullptr);
  original->attestations[0] = attestation;
  original->attestation_count = 1;

  serialized_buffer_t* wire = crabs_serialize_operation(original);
  ASSERT_NE(wire, nullptr);

  // Locate the per-entry length prefix (u32le, directly before the blob it
  // describes). The v6 sovereign-prefix section (a single u8 count, 0 here)
  // trails the attestation section on the wire, so walk back past it too.
  uint8_t scratch[CRABS_ATTESTATION_WIRE_MAX];
  size_t attestation_wire_len =
      attestation_serialize(&attestation, scratch, sizeof(scratch));
  ASSERT_GT(attestation_wire_len, 0u);
  ASSERT_EQ(wire->data[wire->len - 1], 0u); // sovereign_prefix_count == 0
  uint8_t* length_prefix =
      wire->data + wire->len - 1 - attestation_wire_len - 4;
  // Sanity: the blob the prefix describes re-parses on its own.
  attestation_t* direct = attestation_deserialize(length_prefix + 4,
                                                  attestation_wire_len);
  ASSERT_NE(direct, nullptr);
  attestation_destroy(direct);
  memset(length_prefix, 0xFF, 4);

  EXPECT_EQ(crabs_deserialize_operation(wire->data, wire->len), nullptr);

  // Truncation: chop anything after the attestation entry.
  EXPECT_EQ(crabs_deserialize_operation(wire->data, wire->len - 8), nullptr);

  serialized_buffer_destroy(wire);
  operation_destroy(original);
}

// Symmetry with the reader: the deserializer already fail-closes on
// attestation_count > CRABS_MAX_OP_ATTESTATIONS, so the writer must refuse
// to emit such a blob rather than produce wire that can never be read back.
TEST(TestSerialization, TestOperationWriterEnforcesAttestationCap) {
  operation_t* original = operation_create(CRABS_OP_CHECK_DEDUP);
  memset(original->uuid, 0x55, CRABS_UUID_SIZE);
  strncpy(original->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  attestation_t* entries = (attestation_t*)malloc(
      (CRABS_MAX_OP_ATTESTATIONS + 1) * sizeof(attestation_t));
  ASSERT_NE(entries, nullptr);
  for (uint32_t attestation_index = 0;
       attestation_index <= CRABS_MAX_OP_ATTESTATIONS; attestation_index++) {
    attestation_t* entry = &entries[attestation_index];
    memset(entry, 0, sizeof(*entry));
    entry->format_version = CRABS_ATTESTATION_FORMAT_VERSION;
    strncpy(entry->parent_id, "parent-root", sizeof(entry->parent_id) - 1);
    strncpy(entry->child_id, "child-red", sizeof(entry->child_id) - 1);
    strncpy(entry->user_id, "alice", sizeof(entry->user_id) - 1);
    strncpy(entry->attributes, "role:writer", sizeof(entry->attributes) - 1);
    entry->not_before = 1700000000000ULL;
    entry->expires_at = 1700000060000ULL;
    memset(entry->signature, 0x44, CRABS_SIG_SIZE);
  }
  original->attestations = entries;

  // At the cap the op still serializes; one over it the writer refuses.
  original->attestation_count = CRABS_MAX_OP_ATTESTATIONS;
  serialized_buffer_t* wire = crabs_serialize_operation(original);
  ASSERT_NE(wire, nullptr);
  serialized_buffer_destroy(wire);
  wire = NULL;

  original->attestation_count = CRABS_MAX_OP_ATTESTATIONS + 1;
  EXPECT_EQ(crabs_serialize_operation(original), nullptr);

  operation_destroy(original);
}

// R7-03: state snapshots must be authenticated with the node key, not just
// SHA-256 checksummed. A tampered blob or a wrong verification key must be
// rejected before parsing.
TEST(TestSerialization, TestSignedStateRoundTrip) {
  state_t* state = state_create();
  state->version = 5;

  data_item_t* item = data_item_create("counter1", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* counter = g_counter_create();
  ASSERT_EQ(g_counter_increment(counter, "node1", 100), CRABS_SUCCESS);
  item->value = counter;
  state_add_item(state, item);

  ecdsa_keypair_t* node_key = crypto_ecdsa_generate();
  ASSERT_NE(node_key, nullptr);
  ASSERT_EQ(state_set_node_key(state, node_key->private_key, node_key->public_key),
            CRABS_SUCCESS);

  serialized_buffer_t* buf = crabs_serialize_state_signed(state);
  ASSERT_NE(buf, nullptr);

  // Correct key → loads.
  state_t* restored = crabs_deserialize_state_signed(buf->data, buf->len, node_key->public_key);
  ASSERT_NE(restored, nullptr);
  data_item_t* restored_item = state_find_item(restored, "counter1");
  ASSERT_NE(restored_item, nullptr);
  EXPECT_EQ(g_counter_value((g_counter_t*)restored_item->value), (int64_t)100);
  state_destroy(restored);

  // Wrong key → rejected.
  ecdsa_keypair_t* other_key = crypto_ecdsa_generate();
  ASSERT_NE(other_key, nullptr);
  EXPECT_EQ(crabs_deserialize_state_signed(buf->data, buf->len, other_key->public_key), nullptr);

  // Tampered blob → rejected.
  uint8_t* tampered = (uint8_t*)malloc(buf->len);
  memcpy(tampered, buf->data, buf->len);
  tampered[0] ^= 0xFF;  // flip a magic byte
  EXPECT_EQ(crabs_deserialize_state_signed(tampered, buf->len, node_key->public_key), nullptr);
  free(tampered);

  serialized_buffer_destroy(buf);
  crypto_ecdsa_keypair_destroy(node_key);
  crypto_ecdsa_keypair_destroy(other_key);
  state_destroy(state);
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

  // The canonical form begins with a 5-byte domain tag: "CRAB" + version.
  ASSERT_GE(buf->len, 5);
  EXPECT_EQ(buf->data[0], 0x43);
  EXPECT_EQ(buf->data[1], 0x52);
  EXPECT_EQ(buf->data[2], 0x41);
  EXPECT_EQ(buf->data[3], 0x42);
  EXPECT_EQ(buf->data[4], 0x04); // signing-format version 4 (write domains)

  // After the domain tag, the first field is the type string (length-prefixed).
  // "__lock__" is 8 chars → uint16 length prefix = 8, then the bytes.
  size_t base = 5;
  uint16_t type_len = buf->data[base] | (buf->data[base + 1] << 8);
  EXPECT_EQ(type_len, 8);
  EXPECT_EQ(memcmp(buf->data + base + 2, "__lock__", 8), 0);

  // A10-L7: after type comes op_version as a u32le (signing format v3).
  size_t op_version_offset = base + 2 + type_len;
  uint32_t canonical_version =
      (uint32_t)buf->data[op_version_offset] |
      ((uint32_t)buf->data[op_version_offset + 1] << 8) |
      ((uint32_t)buf->data[op_version_offset + 2] << 16) |
      ((uint32_t)buf->data[op_version_offset + 3] << 24);
  EXPECT_EQ(canonical_version, (uint32_t)CRABS_OP_FORMAT_VERSION);

  // After op_version, the next 16 bytes should be the UUID
  size_t offset = op_version_offset + 4;
  EXPECT_EQ(memcmp(buf->data + offset, op->uuid, CRABS_UUID_SIZE), 0);

  serialized_buffer_destroy(buf);
  operation_destroy(op);
}

// A10-L7: op_version is part of the signed canonical form (signing format
// v3). Two ops identical except op_version must serialize to DIFFERENT
// signing bytes, and a signature minted over the version-5 canonical form
// must NOT verify when the op is re-serialized as version 1 — this is the
// strip attack: a relay downgrades the wire version byte to truncate the
// attestation/dedup/HLC tail; pre-fix the signature still verified because
// op_version never entered the canonical form.
TEST(TestSerialization, TestCanonicalSigningBindsOpVersion) {
  operation_t* op_current = operation_create(CRABS_OP_LOCK);
  ASSERT_NE(op_current, nullptr);
  memset(op_current->uuid, 0x11, CRABS_UUID_SIZE);
  strncpy(op_current->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op_current->signer_key_version = 1;
  op_current->lamport_time = 7;
  strncpy(op_current->node_id, "node1", CRABS_MAX_USER_ID - 1);
  ASSERT_EQ(op_current->op_version, (uint32_t)CRABS_OP_FORMAT_VERSION);

  // Twin op: identical field-for-field, differing only in op_version —
  // exactly what the stripped/re-parsed op looks like to a verifier.
  operation_t op_v1 = *op_current;
  op_v1.op_version = 1;

  serialized_buffer_t* buf_current = crabs_serialize_for_signing(op_current);
  serialized_buffer_t* buf_v1 = crabs_serialize_for_signing(&op_v1);
  ASSERT_NE(buf_current, nullptr);
  ASSERT_NE(buf_v1, nullptr);

  // Canonical forms must differ.
  bool identical = (buf_current->len == buf_v1->len) &&
                   (memcmp(buf_current->data, buf_v1->data, buf_current->len) == 0);
  EXPECT_FALSE(identical)
      << "op_version is not bound into the signed canonical form: a "
         "version-downgrade strip keeps the signature valid (A10-L7)";

  // A signature over the current-version canonical form verifies there, and
  // MUST NOT verify against the version-1 canonical form.
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);
  uint8_t signature[CRABS_SIG_SIZE];
  ASSERT_EQ(crypto_ecdsa_sign(keypair->private_key, buf_current->data,
                              buf_current->len, signature),
            CRABS_SUCCESS);
  EXPECT_TRUE(crypto_ecdsa_verify(keypair->public_key, buf_current->data,
                                  buf_current->len, signature));
  EXPECT_FALSE(crypto_ecdsa_verify(keypair->public_key, buf_v1->data,
                                   buf_v1->len, signature))
      << "signature minted at the current op_version still verifies after "
         "a downgrade to op_version 1 (A10-L7)";

  crypto_ecdsa_keypair_destroy(keypair);
  serialized_buffer_destroy(buf_current);
  serialized_buffer_destroy(buf_v1);
  operation_destroy(op_current);
}

// A10-L7: the wire round-trip preserves op_version. The serializer emits the
// op's declared version (not a hardcoded current version), the deserializer
// stores it back on the op, and the canonical signing form matches across
// the round-trip — required for scheduled ops (serialized into the state
// blob, deserialized and verified on fire) to keep verifying.
TEST(TestSerialization, TestOpVersionRoundTrip) {
  operation_t* op = operation_create(CRABS_OP_LOCK);
  ASSERT_NE(op, nullptr);
  memset(op->uuid, 0x22, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "bob", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 11;
  op->ordering_system = CRABS_ORDERING_HLC;
  op->hlc.physical_seconds = 100;
  op->hlc.physical_nanos = 5;
  op->hlc.logical_counter = 3;
  strncpy(op->hlc.node_id, "node1", CRABS_HLC_NODE_ID_SIZE - 1);

  serialized_buffer_t* wire = crabs_serialize_operation(op);
  ASSERT_NE(wire, nullptr);
  ASSERT_GE(wire->len, 4u);
  uint32_t wire_version = (uint32_t)wire->data[0] |
                          ((uint32_t)wire->data[1] << 8) |
                          ((uint32_t)wire->data[2] << 16) |
                          ((uint32_t)wire->data[3] << 24);
  EXPECT_EQ(wire_version, (uint32_t)CRABS_OP_FORMAT_VERSION);

  operation_t* restored = crabs_deserialize_operation(wire->data, wire->len);
  ASSERT_NE(restored, nullptr);
  EXPECT_EQ(restored->op_version, (uint32_t)CRABS_OP_FORMAT_VERSION);

  serialized_buffer_t* canon_original = crabs_serialize_for_signing(op);
  serialized_buffer_t* canon_restored = crabs_serialize_for_signing(restored);
  ASSERT_NE(canon_original, nullptr);
  ASSERT_NE(canon_restored, nullptr);
  ASSERT_EQ(canon_original->len, canon_restored->len);
  EXPECT_EQ(memcmp(canon_original->data, canon_restored->data,
                   canon_original->len), 0);

  serialized_buffer_destroy(canon_original);
  serialized_buffer_destroy(canon_restored);
  operation_destroy(restored);
  serialized_buffer_destroy(wire);
  operation_destroy(op);
}

// Write domains (op format v6): per-resource sovereign chain prefixes
// round-trip through the op serializer/deserializer with every field exact,
// and the canonical signing form is identical before and after the wire —
// required for a gossiped sovereign op to still verify.
TEST(TestSerialization, SovereignPrefixRoundTrip) {
  operation_t* original = operation_create(CRABS_OP_LOCK);
  memset(original->uuid, 0x66, CRABS_UUID_SIZE);
  strncpy(original->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  original->lamport_time = 17;

  original->resource_count = 2;
  original->resources = (char(*)[CRABS_MAX_USER_ID])malloc(2 * CRABS_MAX_USER_ID);
  strncpy(original->resources[0], "tally", CRABS_MAX_USER_ID - 1);
  strncpy(original->resources[1], "profile", CRABS_MAX_USER_ID - 1);
  original->required_state = (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  original->required_state[0] = PROTOCOL_IDLE;
  original->required_state[1] = PROTOCOL_IDLE;
  original->next_state = (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  original->next_state[0] = PROTOCOL_LOCKED;
  original->next_state[1] = PROTOCOL_LOCKED;

  original->sovereign_prefix_count = 2;
  original->sovereign_prefixes[0].item_seq = 7;
  for (uint32_t byte_index = 0; byte_index < CRABS_HASH_SIZE; byte_index++) {
    original->sovereign_prefixes[0].prev_item_digest[byte_index] =
        (uint8_t)(0xA0 + byte_index);
  }
  original->sovereign_prefixes[1].item_seq = 42;
  for (uint32_t byte_index = 0; byte_index < CRABS_HASH_SIZE; byte_index++) {
    original->sovereign_prefixes[1].prev_item_digest[byte_index] =
        (uint8_t)(0xB0 + byte_index);
  }

  serialized_buffer_t* wire = crabs_serialize_operation(original);
  ASSERT_NE(wire, nullptr);

  operation_t* restored = crabs_deserialize_operation(wire->data, wire->len);
  ASSERT_NE(restored, nullptr);
  EXPECT_EQ(restored->op_version, (uint32_t)CRABS_OP_FORMAT_VERSION);
  ASSERT_EQ(restored->sovereign_prefix_count, (uint32_t)2);
  EXPECT_EQ(restored->sovereign_prefixes[0].item_seq, (uint64_t)7);
  EXPECT_EQ(memcmp(restored->sovereign_prefixes[0].prev_item_digest,
                   original->sovereign_prefixes[0].prev_item_digest,
                   CRABS_HASH_SIZE), 0);
  EXPECT_EQ(restored->sovereign_prefixes[1].item_seq, (uint64_t)42);
  EXPECT_EQ(memcmp(restored->sovereign_prefixes[1].prev_item_digest,
                   original->sovereign_prefixes[1].prev_item_digest,
                   CRABS_HASH_SIZE), 0);

  // The canonical signing form must be identical before and after gossip.
  serialized_buffer_t* sig1 = crabs_serialize_for_signing(original);
  serialized_buffer_t* sig2 = crabs_serialize_for_signing(restored);
  ASSERT_NE(sig1, nullptr);
  ASSERT_NE(sig2, nullptr);
  EXPECT_EQ(sig1->len, sig2->len);
  EXPECT_EQ(memcmp(sig1->data, sig2->data, sig1->len), 0);

  serialized_buffer_destroy(sig1);
  serialized_buffer_destroy(sig2);
  serialized_buffer_destroy(wire);
  operation_destroy(original);
  operation_destroy(restored);
}

// Write domains (signing format v4): the sovereign prefixes are part of the
// signed canonical form. Two ops identical except one prefix's item_seq must
// serialize to different signing bytes, and a signature over one must NOT
// verify against the other's form — otherwise a relay could rewire the chain
// prefix a writer signed (the rewind class the v3 bump closed for op_version).
TEST(TestSerialization, SigningBindsSovereignPrefix) {
  operation_t* op_seq7 = operation_create(CRABS_OP_LOCK);
  ASSERT_NE(op_seq7, nullptr);
  memset(op_seq7->uuid, 0x33, CRABS_UUID_SIZE);
  strncpy(op_seq7->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op_seq7->signer_key_version = 1;
  op_seq7->lamport_time = 9;
  strncpy(op_seq7->node_id, "node1", CRABS_MAX_USER_ID - 1);
  op_seq7->sovereign_prefix_count = 1;
  op_seq7->sovereign_prefixes[0].item_seq = 7;
  memset(op_seq7->sovereign_prefixes[0].prev_item_digest, 0x5A,
         CRABS_HASH_SIZE);

  // Twin op: identical field-for-field, differing only in the prefix's
  // item_seq — exactly what a rewired sovereign op looks like to a verifier.
  operation_t op_seq8 = *op_seq7;
  op_seq8.sovereign_prefixes[0].item_seq = 8;

  serialized_buffer_t* buf_seq7 = crabs_serialize_for_signing(op_seq7);
  serialized_buffer_t* buf_seq8 = crabs_serialize_for_signing(&op_seq8);
  ASSERT_NE(buf_seq7, nullptr);
  ASSERT_NE(buf_seq8, nullptr);

  // Canonical forms must differ.
  bool identical = (buf_seq7->len == buf_seq8->len) &&
                   (memcmp(buf_seq7->data, buf_seq8->data, buf_seq7->len) == 0);
  EXPECT_FALSE(identical)
      << "sovereign prefixes are not bound into the signed canonical form: "
         "a relay can rewire a signed op's item_seq prefix without "
         "invalidating the signature";

  // A signature over the seq-7 canonical form verifies there, and MUST NOT
  // verify against the seq-8 canonical form.
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);
  uint8_t signature[CRABS_SIG_SIZE];
  ASSERT_EQ(crypto_ecdsa_sign(keypair->private_key, buf_seq7->data,
                              buf_seq7->len, signature),
            CRABS_SUCCESS);
  EXPECT_TRUE(crypto_ecdsa_verify(keypair->public_key, buf_seq7->data,
                                  buf_seq7->len, signature));
  EXPECT_FALSE(crypto_ecdsa_verify(keypair->public_key, buf_seq8->data,
                                   buf_seq8->len, signature))
      << "signature over one sovereign prefix still verifies after the "
         "prefix's item_seq is rewired";

  crypto_ecdsa_keypair_destroy(keypair);
  serialized_buffer_destroy(buf_seq7);
  serialized_buffer_destroy(buf_seq8);
  operation_destroy(op_seq7);
}

// Refuse discipline (op format v6): an op declaring op_version < 6 cannot
// represent sovereign prefixes on the wire — the reader of that version
// would not parse the section, so the serializer must refuse rather than
// silently truncate signed content. The canonical signing form still covers
// the prefixes regardless of op_version (they are part of the op's
// identity), so a low-version op is simply unsendable, never mis-signed.
TEST(TestSerialization, LowVersionOpWithPrefixesRefusedOnWire) {
  operation_t* op = operation_create(CRABS_OP_LOCK);
  ASSERT_NE(op, nullptr);
  memset(op->uuid, 0x44, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op->sovereign_prefix_count = 1;
  op->sovereign_prefixes[0].item_seq = 3;
  memset(op->sovereign_prefixes[0].prev_item_digest, 0x77, CRABS_HASH_SIZE);

  // At the default (current) version the op serializes...
  serialized_buffer_t* wire = crabs_serialize_operation(op);
  ASSERT_NE(wire, nullptr);
  serialized_buffer_destroy(wire);

  // ...but downgraded to v5 the wire serializer must refuse.
  op->op_version = 5;
  EXPECT_EQ(crabs_serialize_operation(op), nullptr);

  // The signing form still includes the prefix content at any op_version.
  operation_t no_prefix = *op;
  no_prefix.sovereign_prefix_count = 0;
  serialized_buffer_t* sig_with = crabs_serialize_for_signing(op);
  serialized_buffer_t* sig_without = crabs_serialize_for_signing(&no_prefix);
  ASSERT_NE(sig_with, nullptr);
  ASSERT_NE(sig_without, nullptr);
  EXPECT_GT(sig_with->len, sig_without->len);
  serialized_buffer_destroy(sig_with);
  serialized_buffer_destroy(sig_without);

  operation_destroy(op);
}

// Symmetry with the reader (op format v6): the writer refuses
// sovereign_prefix_count beyond CRABS_MAX_RESOURCES (such wire could never
// parse back), and the reader rejects an inflated or truncated prefix
// section.
TEST(TestSerialization, SovereignPrefixCountBoundAndTruncation) {
  operation_t* op = operation_create(CRABS_OP_LOCK);
  ASSERT_NE(op, nullptr);
  memset(op->uuid, 0x88, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  // At the cap the op still serializes; one over it the writer refuses
  // (the cap check precedes the entry loop, so the over-cap write attempt
  // never reads past the inline array).
  op->sovereign_prefix_count = CRABS_MAX_RESOURCES;
  serialized_buffer_t* wire = crabs_serialize_operation(op);
  ASSERT_NE(wire, nullptr);
  serialized_buffer_destroy(wire);
  wire = NULL;

  op->sovereign_prefix_count = CRABS_MAX_RESOURCES + 1;
  EXPECT_EQ(crabs_serialize_operation(op), nullptr);

  // A single-prefix op: the v6 section is the LAST section on the wire —
  // u8 count followed by 8 + CRABS_HASH_SIZE bytes per entry.
  op->sovereign_prefix_count = 1;
  op->sovereign_prefixes[0].item_seq = 5;
  memset(op->sovereign_prefixes[0].prev_item_digest, 0x99, CRABS_HASH_SIZE);
  wire = crabs_serialize_operation(op);
  ASSERT_NE(wire, nullptr);
  const size_t entry_size = sizeof(uint64_t) + CRABS_HASH_SIZE;
  ASSERT_GT(wire->len, entry_size + 1);

  // Inflated count byte → rejected.
  uint8_t* count_byte = wire->data + wire->len - entry_size - 1;
  ASSERT_EQ(*count_byte, 1u);
  *count_byte = 0xFF;
  EXPECT_EQ(crabs_deserialize_operation(wire->data, wire->len), nullptr);

  // Restore the count; truncation of the section tail → rejected.
  *count_byte = 1;
  EXPECT_EQ(crabs_deserialize_operation(wire->data, wire->len - 1), nullptr);

  // Sanity: the unmodified wire still parses.
  operation_t* restored = crabs_deserialize_operation(wire->data, wire->len);
  ASSERT_NE(restored, nullptr);
  EXPECT_EQ(restored->sovereign_prefix_count, (uint32_t)1);
  operation_destroy(restored);

  serialized_buffer_destroy(wire);
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

// A10-L6: the state deserializer must reject blobs whose payload carries
// trailing un-consumed bytes after the last parsed section and before the
// checksum (a crafted blob could otherwise satisfy a dual parse). The op
// deserializer already enforces full consumption (R7-L-6).
TEST(StateDeserialize, RejectsTrailingBytes) {
  state_t* state = state_create();
  state->version = 42;

  data_item_t* item = data_item_create("counter1", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* counter_tmp = g_counter_create();
  ASSERT_EQ(g_counter_increment(counter_tmp, "node1", 12345), CRABS_SUCCESS);
  item->value = counter_tmp;
  state_add_item(state, item);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  // Sanity: the unmodified blob round-trips.
  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);
  state_destroy(restored);

  // The checksum is the final CRABS_HASH_SIZE bytes over everything before it.
  const size_t payload_len = buf->len - CRABS_HASH_SIZE;

  // Payload-level trailing bytes: 16 junk bytes inserted between the last
  // section and the checksum, with the checksum recomputed so the blob is
  // otherwise self-consistent. Must be rejected.
  {
    std::vector<uint8_t> crafted(buf->len + 16);
    memcpy(crafted.data(), buf->data, payload_len);
    memset(crafted.data() + payload_len, 0xA5, 16);
    uint8_t recomputed_hash[CRABS_HASH_SIZE];
    SHA256(crafted.data(), payload_len + 16, recomputed_hash);
    memcpy(crafted.data() + payload_len + 16, recomputed_hash, CRABS_HASH_SIZE);

    state_t* result = crabs_deserialize_state(crafted.data(), crafted.size());
    EXPECT_EQ(result, nullptr);
    if (result != nullptr) state_destroy(result);
  }

  // Junk appended after the checksum: the checksum region no longer matches,
  // so this is rejected at checksum verification (belt-and-braces check).
  {
    std::vector<uint8_t> crafted(buf->len + 16);
    memcpy(crafted.data(), buf->data, buf->len);
    memset(crafted.data() + buf->len, 0xA5, 16);

    state_t* result = crabs_deserialize_state(crafted.data(), crafted.size());
    EXPECT_EQ(result, nullptr);
    if (result != nullptr) state_destroy(result);
  }

  serialized_buffer_destroy(buf);
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
  g_counter_t* counter_tmp = g_counter_create();
  ASSERT_EQ(g_counter_increment(counter_tmp, "node1", 100), CRABS_SUCCESS);
  item->value = counter_tmp;

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

// R7-12: the invariant first pass accumulated str_space for out-of-bounds
// messages, amplifying a ~2.8 KB input into a ~16.7 MB allocation per item
// (get_clear_memory aborts on OOM → remote crash). Craft a buffer where an
// invariant's msg_len is huge and out of bounds; deserialization must fail
// cleanly without crashing.
TEST(TestSerialization, TestDeserializeInvariantOutOfBoundsMsgLenNoCrash) {
  state_t* state = state_create();
  state->version = 5;

  data_item_t* item = data_item_create("counter1", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* counter_tmp = g_counter_create();
  ASSERT_EQ(g_counter_increment(counter_tmp, "node1", 100), CRABS_SUCCESS);
  item->value = counter_tmp;

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

  // Locate the second invariant's message and corrupt the 2-byte msg_len that
  // precedes it to 0xFFFF (out of bounds), then truncate so the message bytes
  // are gone — the deserializer must reject cleanly, not allocate 64 KB.
  const char* needle = "must be non-negative";
  size_t needle_len = strlen(needle);
  size_t msg_offset = SIZE_MAX;
  for (size_t i = 0; i + needle_len <= buf->len; i++) {
    if (memcmp(buf->data + i, needle, needle_len) == 0) {
      msg_offset = i;
      break;
    }
  }
  ASSERT_NE(msg_offset, SIZE_MAX);
  ASSERT_GE(msg_offset, 2u);
  buf->data[msg_offset - 2] = 0xFF;
  buf->data[msg_offset - 1] = 0xFF;

  state_t* restored = crabs_deserialize_state(buf->data, msg_offset);
  // No crash is the primary assertion; a clean failure (NULL) is expected.
  if (restored != NULL) {
    state_destroy(restored);
  }

  free((void*)invs[0].error_message);
  free((void*)invs[1].error_message);
  serialized_buffer_destroy(buf);
  state_destroy(state);
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

// v6 introduced the pending-schedules section but carried no recurring
// cadence fields (v7 added interval/repeat/end right after execute_at_ms).
// A v7 reader must accept a v6 blob and restore the schedule with one-shot
// cadence semantics (interval/repeat/end all zero).
TEST(TestSerializationV2, TestV6BackwardCompatAcceptsV6WithSchedule) {
  std::vector<uint8_t> v6buf;
  auto write_u8 = [&](uint8_t v) { v6buf.push_back(v); };
  auto write_u32 = [&](uint32_t v) { for (uint32_t b = 0; b < 4; b++) v6buf.push_back((uint8_t)((v >> (b * 8)) & 0xFF)); };
  auto write_u64 = [&](uint64_t v) { for (uint32_t b = 0; b < 8; b++) v6buf.push_back((uint8_t)((v >> (b * 8)) & 0xFF)); };
  auto write_str16 = [&](const char* s) {
    uint16_t slen = s ? (uint16_t)strlen(s) : 0;
    v6buf.push_back((uint8_t)(slen & 0xFF));
    v6buf.push_back((uint8_t)((slen >> 8) & 0xFF));
    for (uint16_t ch = 0; ch < slen; ch++) v6buf.push_back((uint8_t)s[ch]);
  };
  auto write_fixed = [&](const char* s, size_t len) {
    size_t str_len = s ? strlen(s) : 0;
    for (size_t ch = 0; ch < len; ch++) {
      v6buf.push_back(ch < str_len ? (uint8_t)s[ch] : 0);
    }
  };

  // Magic "CRAB" + version 6
  v6buf.push_back(0x43); v6buf.push_back(0x52);
  v6buf.push_back(0x41); v6buf.push_back(0x42);
  write_u32(6);
  write_u64(7);       // state_version
  write_u32(0);       // item_count
  write_u32(0);       // policy_count
  write_u32(0);       // log_count

  // config: base fields + sig_config + vault_config (layout stable since v2)
  write_u64(5000);    // max_lock_duration_ms
  write_u32(3);       // max_lock_extensions
  write_u8(1);        // allow_force_unlock
  write_str16("admin");
  write_u8(1);        // sig_config.default_scheme = ECDSA_SECP256K1
  write_u32(4);       // sig_config.max_keys_per_user
  write_u8(0);        // sig_config.key_rotation_enabled
  write_u32(1);       // sig_config.co_sign_threshold
  write_u8(0);        // sig_config.key_expiry_enabled
  write_u64(0);       // sig_config.default_key_ttl_ms
  write_u64(0);       // sig_config.max_key_age_ms
  write_u8(0);        // vault_config.provider = VAULT_NONE
  write_str16("");    // vault_config.address
  write_str16("");    // vault_config.auth_token
  write_u8(0);        // vault_config.signing_delegated
  write_u8(0);        // vault_config.rotation_delegated

  // schedules (v6 layout: no cadence fields)
  write_u64(42);      // schedule_seq
  write_u32(1);       // schedule_count
  write_u64(42);      // schedule_id
  write_u64(1000001000);  // execute_at_ms
  write_fixed("admin", 64);  // submitter (fixed CRABS_MAX_USER_ID bytes)
  write_u32(4);       // op_len
  v6buf.push_back(0xAA); v6buf.push_back(0xBB);
  v6buf.push_back(0xCC); v6buf.push_back(0xDD);  // op_bytes (not decoded on load)

  uint8_t v6hash[32];
  SHA256(v6buf.data(), v6buf.size(), v6hash);
  for (int i = 0; i < 32; i++) v6buf.push_back(v6hash[i]);

  state_t* restored = crabs_deserialize_state(v6buf.data(), v6buf.size());
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->version, (uint64_t)7);
  EXPECT_EQ(restored->config.max_lock_duration_ms, (uint64_t)5000);
  EXPECT_STREQ(restored->config.bootstrap_admin, "admin");

  // The pending schedule survived, as a one-shot (v6 has no cadence fields).
  EXPECT_EQ(restored->schedule_seq, 42u);
  const scheduled_operation_t* pending = scheduler_first(restored);
  ASSERT_NE(pending, nullptr);
  EXPECT_EQ(pending->schedule_id, 42u);
  EXPECT_EQ(pending->execute_at_ms, 1000001000u);
  EXPECT_EQ(pending->interval_ms, 0u);
  EXPECT_EQ(pending->repeat_count, 0u);
  EXPECT_EQ(pending->end_at_ms, 0u);
  EXPECT_STREQ(pending->submitter, "admin");
  EXPECT_EQ(pending->op_len, 4u);

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
// Regression: the canonical signing form MUST cover the dedup state_mutation
// (audit C-6) and payload_format (C-7). Tampering with either field after
// signing must invalidate the signature.
TEST(TestSerialization, SigningCoversDedupMutationAndPayloadFormat) {
  ecdsa_keypair_t* kp = crypto_ecdsa_generate();
  ASSERT_NE(kp, nullptr);

  operation_t* op = operation_create("vote");
  for (int i = 0; i < CRABS_UUID_SIZE; i++) op->uuid[i] = (uint8_t)(i + 1);
  op->payload = (uint8_t*)strdup("yes");
  op->payload_size = 3;
  op->payload_format = 1; // JSON
  op->dedup.type = DEDUP_CUSTOM;
  strncpy(op->dedup.condition, "voted == false", CRABS_MAX_POLICY_EXPR - 1);
  op->dedup.update.type = MUTATION_COUNTER_INCREMENT;
  strncpy(op->dedup.update.counter_path, "tally", CRABS_MAX_DEDUP_PATH - 1);
  op->dedup.update.delta = 1;

  serialized_buffer_t* s1 = crabs_serialize_for_signing(op);
  ASSERT_NE(s1, nullptr);
  uint8_t sig[CRABS_SIG_SIZE];
  ASSERT_EQ(crypto_ecdsa_sign(kp->private_key, s1->data, s1->len, sig), CRABS_SUCCESS);
  EXPECT_TRUE(crypto_ecdsa_verify(kp->public_key, s1->data, s1->len, sig));
  serialized_buffer_destroy(s1);

  // Tamper with the dedup delta (1 -> 999999). The signature must no longer verify.
  op->dedup.update.delta = 999999;
  serialized_buffer_t* s2 = crabs_serialize_for_signing(op);
  ASSERT_NE(s2, nullptr);
  EXPECT_FALSE(crypto_ecdsa_verify(kp->public_key, s2->data, s2->len, sig));
  serialized_buffer_destroy(s2);

  // Tamper with payload_format (1 -> 2). Must also invalidate.
  op->dedup.update.delta = 1; // restore
  op->payload_format = 2;
  serialized_buffer_t* s3 = crabs_serialize_for_signing(op);
  ASSERT_NE(s3, nullptr);
  EXPECT_FALSE(crypto_ecdsa_verify(kp->public_key, s3->data, s3->len, sig));
  serialized_buffer_destroy(s3);

  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(kp);
}

// Regression for audit M-5: OR-set / 2P-set / one-shot set/flag contents must
// survive a serialize/deserialize round-trip (previously the serializer wrote
// a 0-length value and the set came back empty).
TEST(TestSerialization, RoundTripPreservesORSet) {
  state_t* state = state_create();
  data_item_t* item = data_item_create("s1", DATA_TYPE_SET, CRDT_OR_SET);
  or_set_t* set = or_set_create();
  or_set_add(set, "apple", "n1:1");
  or_set_add(set, "banana", "n1:2");
  or_set_remove(set, "apple");
  item->value = set;
  state_add_item(state, item);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  data_item_t* r = state_find_item(restored, "s1");
  ASSERT_NE(r, nullptr);
  ASSERT_NE(r->value, nullptr);
  or_set_t* rs = (or_set_t*)r->value;
  EXPECT_FALSE(or_set_contains(rs, "apple"));  // removed
  EXPECT_TRUE(or_set_contains(rs, "banana")); // survived
  EXPECT_GT(rs->element_count, 0u);

  serialized_buffer_destroy(buf);
  state_destroy(restored);
  state_destroy(state);
}

// Audit A-3 (HIGH): triggers were never serialized — save/load silently
// dropped every trigger definition. v9 persists them; round-trip must
// preserve every field of trigger_t (condition_ast is re-derived from the
// condition string on load).
TEST(TestSerialization, TriggerStateRoundTripPreservesAllFields) {
  state_t* state = state_create();

  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_ISSUE_ATTRIBUTE;
  strncpy(effect.issue_attribute, "role", CRABS_MAX_POLICY_EXPR - 1);
  strncpy(effect.target_role, "moderator", CRABS_MAX_USER_ID - 1);
  effect.duration_ms = 5000;
  strncpy(effect.attribute_value, "elevated", CRABS_MAX_POLICY_EXPR - 1);
  strncpy(effect.policy_operation, "__read__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect.policy_expression, "role >= moderator", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("high_views", "Fires when views >= 50",
                                      "views >= 50", &effect, 60000, true, "admin");
  ASSERT_NE(trigger, nullptr);
  ASSERT_NE(trigger->condition_ast, nullptr);

  // Production shape: state-owned trigger array (see test_trigger.cpp setup)
  state->trigger_count = 1;
  state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
  ASSERT_NE(state->triggers, nullptr);
  state->triggers[0] = *trigger;
  free(trigger);
  // Runtime-mutated fields that must also survive
  state->triggers[0].last_triggered_at = 9999;
  state->triggers[0].expires_at = 123456;
  state->triggers[0].created_at = 777;
  state->triggers[0].enabled = false;

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);
  ASSERT_EQ(restored->trigger_count, 1u);

  const trigger_t* restored_trigger = &restored->triggers[0];
  EXPECT_STREQ(restored_trigger->trigger_id, "high_views");
  EXPECT_STREQ(restored_trigger->description, "Fires when views >= 50");
  EXPECT_STREQ(restored_trigger->condition, "views >= 50");
  EXPECT_EQ(restored_trigger->effect.type, TRIGGER_EFFECT_ISSUE_ATTRIBUTE);
  EXPECT_STREQ(restored_trigger->effect.issue_attribute, "role");
  EXPECT_STREQ(restored_trigger->effect.target_role, "moderator");
  EXPECT_EQ(restored_trigger->effect.duration_ms, (uint64_t)5000);
  EXPECT_STREQ(restored_trigger->effect.attribute_value, "elevated");
  EXPECT_STREQ(restored_trigger->effect.policy_operation, "__read__");
  EXPECT_STREQ(restored_trigger->effect.policy_expression, "role >= moderator");
  EXPECT_EQ(restored_trigger->cooldown_ms, (uint64_t)60000);
  EXPECT_EQ(restored_trigger->last_triggered_at, (uint64_t)9999);
  EXPECT_TRUE(restored_trigger->one_shot);
  EXPECT_FALSE(restored_trigger->enabled);
  EXPECT_EQ(restored_trigger->expires_at, (uint64_t)123456);
  EXPECT_EQ(restored_trigger->created_at, (uint64_t)777);
  EXPECT_STREQ(restored_trigger->created_by, "admin");
  // The AST must be re-derived so the restored trigger can actually fire
  EXPECT_NE(restored_trigger->condition_ast, nullptr);

  serialized_buffer_destroy(buf);
  state_destroy(restored);
  state_destroy(state);
}

// v8 blobs predate the triggers section. The v9 reader must accept a v8 blob
// and restore a state with zero triggers (no phantom entries, no parse drift).
TEST(TestSerializationV2, TestV8BlobWithoutTriggerSectionRestoresZeroTriggers) {
  std::vector<uint8_t> v8buf;
  auto write_u8 = [&](uint8_t v) { v8buf.push_back(v); };
  auto write_u32 = [&](uint32_t v) { for (uint32_t b = 0; b < 4; b++) v8buf.push_back((uint8_t)((v >> (b * 8)) & 0xFF)); };
  auto write_u64 = [&](uint64_t v) { for (uint32_t b = 0; b < 8; b++) v8buf.push_back((uint8_t)((v >> (b * 8)) & 0xFF)); };
  auto write_str16 = [&](const char* s) {
    uint16_t slen = s ? (uint16_t)strlen(s) : 0;
    v8buf.push_back((uint8_t)(slen & 0xFF));
    v8buf.push_back((uint8_t)((slen >> 8) & 0xFF));
    for (uint16_t ch = 0; ch < slen; ch++) v8buf.push_back((uint8_t)s[ch]);
  };

  // Magic "CRAB" + version 8
  v8buf.push_back(0x43); v8buf.push_back(0x52);
  v8buf.push_back(0x41); v8buf.push_back(0x42);
  write_u32(8);
  write_u64(3);   // state_version
  write_u32(0);   // item_count
  write_u32(0);   // policy_count
  write_u32(0);   // log_count
  // config (v2+ layout)
  write_u64(5000);          // max_lock_duration_ms
  write_u32(3);             // max_lock_extensions
  write_u8(1);              // allow_force_unlock
  write_str16("admin");     // bootstrap_admin
  write_u8(0);              // sig_config.default_scheme
  write_u32(0);             // sig_config.max_keys_per_user
  write_u8(0);              // sig_config.key_rotation_enabled
  write_u32(0);             // sig_config.co_sign_threshold
  write_u8(0);              // sig_config.key_expiry_enabled
  write_u64(0);             // sig_config.default_key_ttl_ms
  write_u64(0);             // sig_config.max_key_age_ms
  write_u8(0);              // vault_config.provider
  write_str16("");          // vault_config.address
  write_str16("");          // vault_config.auth_token
  write_u8(0);              // vault_config.signing_delegated
  write_u8(0);              // vault_config.rotation_delegated
  // schedules (v6+)
  write_u64(0);   // schedule_seq
  write_u32(0);   // schedule_count
  // v8 ends here — no triggers section

  uint8_t v8hash[32];
  SHA256(v8buf.data(), v8buf.size(), v8hash);
  for (int i = 0; i < 32; i++) v8buf.push_back(v8hash[i]);

  state_t* restored = crabs_deserialize_state(v8buf.data(), v8buf.size());
  ASSERT_NE(restored, nullptr);
  EXPECT_EQ(restored->version, (uint64_t)3);
  EXPECT_EQ(restored->trigger_count, 0u);
  EXPECT_EQ(restored->triggers, nullptr);

  state_destroy(restored);
}

// Audit A-5 (MEDIUM): log_count had no remaining-bytes bound before the
// log_count * sizeof(log_entry_t) allocation. The count is chosen just under
// the CRABS_DESER_MAX_LOG cap so the remaining-bytes bound is what rejects
// the blob (a count above the cap is already caught by the cap itself).
TEST(TestSerialization, TestDeserialRejectsHugeLogCount) {
  state_t* state = state_create();
  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  // log_count lives at offset 4(magic) + 4(version) + 8(state_version)
  //                                   + 4(item_count) + 4(policy_count) = 24
  uint32_t huge_log_count = 999999; // just under CRABS_DESER_MAX_LOG
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    buf->data[24 + byte_index] = (uint8_t)((huge_log_count >> (byte_index * 8)) & 0xFF);
  }

  // Recompute checksum so only the count bound can reject the blob
  uint8_t hash[32];
  SHA256(buf->data, buf->len - 32, hash);
  memcpy(buf->data + buf->len - 32, hash, 32);

  state_t* result = crabs_deserialize_state(buf->data, buf->len);
  EXPECT_EQ(result, nullptr);

  serialized_buffer_destroy(buf);
  state_destroy(state);
}

// Audit finding (MEDIUM): the v8 ordered-set reader accepted duplicate
// element ids, unlike the OT tree path which rejects them. Craft a valid
// blob, overwrite the second element's id with the first element's id,
// fix the checksum, and expect rejection.
TEST(TestSerialization, TestDeserialRejectsDuplicateOrderedSetElementIds) {
  state_t* state = state_create();
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  ASSERT_NE(set, nullptr);

  crabs_ot_op_id_t id1 = {"node1", 1, 1000};
  crabs_ot_op_id_t id2 = {"node1", 2, 2000};
  crabs_ot_operation_t op1 = {};
  op1.id = id1;
  op1.op_type = CRABS_OT_OP_INSERT;
  op1.payload = (uint8_t*)"aaaa";
  op1.payload_size = 4;
  ASSERT_NE(crabs_ot_ordered_set_apply_insert(set, &op1), nullptr);
  crabs_ot_operation_t op2 = {};
  op2.id = id2;
  op2.op_type = CRABS_OT_OP_INSERT;
  op2.payload = (uint8_t*)"bbbb";
  op2.payload_size = 4;
  ASSERT_NE(crabs_ot_ordered_set_apply_insert(set, &op2), nullptr);

  data_item_t* item = data_item_create("set1", (data_type_e)DATA_TYPE_OT_ORDERED_SET, CRDT_CUSTOM);
  item->value = set;
  item->ot_data = set->ot_data;
  state_add_item(state, item);

  // Sanity: the unmodified blob must round-trip
  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  state_t* sane = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(sane, nullptr);
  state_destroy(sane);

  // Each element's id (80 bytes: node_id[64] + seq(8) + ts(8)) immediately
  // precedes its value bytes32 (4-byte length + payload). The last occurrence
  // of each unique payload is the element value (earlier occurrences are the
  // op_log payloads inside the ot_data blob). Overwrite element 2's id with
  // element 1's id.
  uint8_t* value_a = NULL;
  uint8_t* value_b = NULL;
  for (size_t scan = buf->len - 5; scan > 0; scan--) {
    if (value_b == NULL && memcmp(buf->data + scan, "bbbb", 4) == 0) value_b = buf->data + scan;
    if (value_a == NULL && memcmp(buf->data + scan, "aaaa", 4) == 0) value_a = buf->data + scan;
  }
  ASSERT_NE(value_a, nullptr);
  ASSERT_NE(value_b, nullptr);
  memcpy(value_b - 84, value_a - 84, 80);

  uint8_t hash[32];
  SHA256(buf->data, buf->len - 32, hash);
  memcpy(buf->data + buf->len - 32, hash, 32);

  state_t* result = crabs_deserialize_state(buf->data, buf->len);
  EXPECT_EQ(result, nullptr);

  serialized_buffer_destroy(buf);
  state_destroy(state);
}

// Audit A10-M7: the ordered-set reader capped the element count at
// CRABS_DESER_MAX_LOG (1,000,000) and then ran a per-element linear
// duplicate-id scan over the accumulated set — O(n²), ~10¹² id comparisons
// for a ~120 MB crafted blob. The count is now bounded at
// CRABS_DESER_MAX_SET_ELEMENTS (10,000), matching the OT tree node cap from
// Audit 8. A legitimate blob carrying 10,001 elements (one above the cap, far
// below the old 1M cap) must now be rejected outright.
TEST(OrderedSetDeserialize, ElementCountBoundedAboveTreeNodes) {
  state_t* state = state_create();
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  ASSERT_NE(set, nullptr);

  const uint32_t element_total = 10001; // CRABS_DESER_MAX_SET_ELEMENTS + 1
  for (uint32_t elem_index = 0; elem_index < element_total; elem_index++) {
    crabs_ot_operation_t insert_op = {};
    strncpy(insert_op.id.node_id, "node1", sizeof(insert_op.id.node_id) - 1);
    insert_op.id.sequence_num = elem_index + 1;
    insert_op.id.timestamp = 1000 + elem_index;
    insert_op.op_type = CRABS_OT_OP_INSERT;
    insert_op.payload = (uint8_t*)"vv";
    insert_op.payload_size = 2;
    ASSERT_NE(crabs_ot_ordered_set_apply_insert(set, &insert_op), nullptr);
  }

  data_item_t* item = data_item_create("set1", (data_type_e)DATA_TYPE_OT_ORDERED_SET, CRDT_CUSTOM);
  item->value = set;
  item->ot_data = set->ot_data;
  state_add_item(state, item);

  // The blob is well-formed; only the element count exceeds the new cap.
  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* result = crabs_deserialize_state(buf->data, buf->len);
  EXPECT_EQ(result, nullptr);

  serialized_buffer_destroy(buf);
  state_destroy(state);
}

// Audit A10-M7: the element count is also bounded against the bytes actually
// remaining in the buffer (each element needs at least one 80-byte op id).
// Craft a valid 2-element blob, overwrite the count with 5000 — plausible in
// magnitude (under CRABS_DESER_MAX_SET_ELEMENTS, so the count cap is not what
// rejects it) but unsatisfiable by the blob — fix the checksum, and expect
// rejection before the duplicate-id scan runs.
TEST(OrderedSetDeserialize, CountBoundedByRemainingBytes) {
  state_t* state = state_create();
  crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
  ASSERT_NE(set, nullptr);

  crabs_ot_op_id_t id1 = {"node1", 1, 1000};
  crabs_ot_op_id_t id2 = {"node1", 2, 2000};
  crabs_ot_operation_t op1 = {};
  op1.id = id1;
  op1.op_type = CRABS_OT_OP_INSERT;
  op1.payload = (uint8_t*)"aaaa";
  op1.payload_size = 4;
  ASSERT_NE(crabs_ot_ordered_set_apply_insert(set, &op1), nullptr);
  crabs_ot_operation_t op2 = {};
  op2.id = id2;
  op2.op_type = CRABS_OT_OP_INSERT;
  op2.payload = (uint8_t*)"bbbb";
  op2.payload_size = 4;
  ASSERT_NE(crabs_ot_ordered_set_apply_insert(set, &op2), nullptr);

  data_item_t* item = data_item_create("set2", (data_type_e)DATA_TYPE_OT_ORDERED_SET, CRDT_CUSTOM);
  item->value = set;
  item->ot_data = set->ot_data;
  state_add_item(state, item);

  // Sanity: the unmodified blob must round-trip
  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  state_t* sane = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(sane, nullptr);
  state_destroy(sane);

  // Locate the ordered-set element count. State header is magic(4) +
  // version(4) + state_version(8) + item_count(4) + policy_count(4) +
  // log_count(4) = 28 bytes. The single item then carries name string16,
  // type/crdt/protocol (3 bytes), the ot_data bytes32, and finally the
  // type-state element count.
  const size_t state_header_len = 28;
  const size_t ot_data_len_offset = state_header_len + 2 + strlen("set2") + 3;
  uint32_t ot_data_len = 0;
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    ot_data_len |= ((uint32_t)buf->data[ot_data_len_offset + byte_index]) << (byte_index * 8);
  }
  const size_t count_offset = ot_data_len_offset + 4 + ot_data_len;
  uint32_t stored_count = 0;
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    stored_count |= ((uint32_t)buf->data[count_offset + byte_index]) << (byte_index * 8);
  }
  ASSERT_EQ(stored_count, 2u); // guard against wire-layout drift

  uint32_t bloated_count = 5000; // under CRABS_DESER_MAX_SET_ELEMENTS
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    buf->data[count_offset + byte_index] = (uint8_t)((bloated_count >> (byte_index * 8)) & 0xFF);
  }

  // Recompute checksum so only the remaining-bytes bound can reject the blob
  uint8_t hash[32];
  SHA256(buf->data, buf->len - 32, hash);
  memcpy(buf->data + buf->len - 32, hash, 32);

  state_t* result = crabs_deserialize_state(buf->data, buf->len);
  EXPECT_EQ(result, nullptr);

  serialized_buffer_destroy(buf);
  state_destroy(state);
}

// ============================================================
// Audit A-4: HLC nanos bound on the wire paths
//
// crabs_hlc_deserialize enforces physical_nanos < 1e9, but the op and
// log-entry wire readers parsed raw uint64 fields without that bound. A
// crafted op with nanos >= 1e9 would flow into crabs_hlc_next's comparisons
// and freeze the node's clock if receive were ever wired. Both readers must
// fail closed, matching crabs_hlc_deserialize.
// ============================================================

// Serialize-then-patch: find the HLC physical_seconds field in the wire blob
// by its unique little-endian value; the nanos field follows it immediately.
static size_t _find_le_u64(const serialized_buffer_t* blob, uint64_t value) {
  uint8_t pattern[8];
  for (int byte_index = 0; byte_index < 8; byte_index++) {
    pattern[byte_index] = (uint8_t)(value >> (8 * byte_index));
  }
  for (size_t offset = 0; offset + 8 <= blob->len; offset++) {
    if (memcmp(blob->data + offset, pattern, 8) == 0) return offset;
  }
  return (size_t)-1;
}

TEST(TestSerialization, TestHlcOpNanosOverflowRejectedOnWire) {
  operation_t* original = operation_create(CRABS_OP_LOCK);
  ASSERT_NE(original, nullptr);
  original->ordering_system = CRABS_ORDERING_HLC;
  // Distinctive seconds so the patch helper locates exactly one site.
  original->hlc.physical_seconds = 0x1122334455667788ULL;
  original->hlc.physical_nanos = 42;
  original->hlc.logical_counter = 7;
  strncpy(original->hlc.node_id, "node-hlc", CRABS_HLC_NODE_ID_SIZE - 1);
  original->lamport_time = 0;

  serialized_buffer_t* wire = crabs_serialize_operation(original);
  ASSERT_NE(wire, nullptr);

  // Sanity: the site is unique and a patched-but-valid nanos value
  // round-trips.
  size_t seconds_offset = _find_le_u64(wire, 0x1122334455667788ULL);
  ASSERT_NE(seconds_offset, (size_t)-1);
  size_t nanos_offset = seconds_offset + 8;
  wire->data[nanos_offset] = 42;

  operation_t* restored = crabs_deserialize_operation(wire->data, wire->len);
  ASSERT_NE(restored, nullptr);
  EXPECT_EQ(restored->hlc.physical_nanos, 42u);
  operation_destroy(restored);

  // Now patch nanos to exactly 1e9 — must fail the deserialize.
  uint64_t overflow_nanos = 1000000000ULL;
  for (int byte_index = 0; byte_index < 8; byte_index++) {
    wire->data[nanos_offset + byte_index] =
        (uint8_t)(overflow_nanos >> (8 * byte_index));
  }
  EXPECT_EQ(crabs_deserialize_operation(wire->data, wire->len), nullptr);

  serialized_buffer_destroy(wire);
  operation_destroy(original);
}

TEST(TestSerialization, TestLogEntryHlcNanosOverflowRejected) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  // Append an HLC log entry directly (the writer carries whatever is in
  // memory; the reader must reject a nanos overflow just like the op path).
  state->log_count = 1;
  state->log = (log_entry_t*)malloc(sizeof(log_entry_t));
  ASSERT_NE(state->log, nullptr);
  memset(&state->log[0], 0, sizeof(log_entry_t));
  state->log[0].version = 1;
  state->log[0].ordering_system = CRABS_ORDERING_HLC;
  state->log[0].hlc.physical_seconds = 1234567890;
  state->log[0].hlc.physical_nanos = 1000000000;  // invalid: >= 1e9
  state->log[0].hlc.logical_counter = 7;
  strncpy(state->log[0].type, "__lock__", CRABS_MAX_OP_NAME - 1);
  strncpy(state->log[0].signer_id, "alice", CRABS_MAX_USER_ID - 1);
  strncpy(state->log[0].node_id, "node-hlc", CRABS_MAX_USER_ID - 1);
  strncpy(state->log[0].hlc.node_id, "node-hlc", CRABS_HLC_NODE_ID_SIZE - 1);

  serialized_buffer_t* wire = crabs_serialize_state(state);
  ASSERT_NE(wire, nullptr);
  EXPECT_EQ(crabs_deserialize_state(wire->data, wire->len), nullptr);

  serialized_buffer_destroy(wire);
  state_destroy(state);
}

// ============================================================
// v10 serialization: op_type_defs, user registry, child manifest
// space, sealed MSK (§11.5 durability)
// ============================================================

TEST(TestSerialization, V10OpTypeDefsRoundTrip) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  dedup_spec_t spec;
  memset(&spec, 0, sizeof(spec));
  spec.type = DEDUP_PER_USER;
  strncpy(spec.tracker_path, "trackers/op1", sizeof(spec.tracker_path) - 1);
  strncpy(spec.rejection_message, "duplicate op", sizeof(spec.rejection_message) - 1);
  ASSERT_EQ(state_register_op_type_def(state, "vote-once", &spec), CRABS_SUCCESS);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  const dedup_spec_t* restored_dedup = state_find_op_type_def(restored, "vote-once");
  ASSERT_NE(restored_dedup, nullptr);
  EXPECT_EQ(restored_dedup->type, DEDUP_PER_USER);
  EXPECT_STREQ(restored_dedup->tracker_path, "trackers/op1");
  EXPECT_STREQ(restored_dedup->rejection_message, "duplicate op");

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

TEST(TestSerialization, V10UserRegistryRoundTripPreservesAttributesAndKeys) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  // Simulate a CLI-style machine: an attribute machine holding users. The
  // shell is caller-managed in this test — detached and freed manually below,
  // because state_destroy never owned it.
  state->attr_machine = (attribute_machine_t*)get_clear_memory(sizeof(attribute_machine_t));
  state->attr_machine->base_state = *state;   // alias for pointer wiring only
  user_t* writer = (user_t*)get_clear_memory(sizeof(user_t));
  strncpy(writer->user_id, "alice", CRABS_MAX_USER_ID - 1);
  writer->status = USER_ACTIVE;
  writer->key_version = 3;
  strncpy(writer->attributes[0].value, "role:writer", CRABS_MAX_POLICY_EXPR - 1);
  writer->attribute_count = 1;
  // Crypto random 33-byte key material is NOT validated here — serialization
  // is a byte-level round trip; validation belongs to register_user.
  user_key_t* first_key = (user_key_t*)get_clear_memory(sizeof(user_key_t));
  strncpy(first_key->key_id, "k1", CRABS_MAX_KEY_ID - 1);
  first_key->scheme = ECDSA_SECP256K1;
  first_key->public_key_len = 33;
  for (int byte_index = 0; byte_index < 33; byte_index++)
    first_key->public_key[byte_index] = (uint8_t)(byte_index + 1);
  first_key->status = KEY_ACTIVE;
  writer->keys = first_key;
  writer->key_count = 1;
  strncpy(writer->default_key_id, "k1", CRABS_MAX_KEY_ID - 1);
  state->attr_machine->users = writer;
  state->attr_machine->user_count = 1;

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state->attr_machine->users = NULL;   // detach before destroy
  state->attr_machine->base_state.attr_machine = NULL;
  state->attr_machine->base_state.abe_mk = NULL;  // owned by the original state
  free(state->attr_machine);           // caller-managed shell
  state->attr_machine = NULL;
  state_destroy(state);
  user_key_destroy_all(writer);
  free(writer);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);
  ASSERT_NE(restored->attr_machine, nullptr);
  user_t* restored_writer = attribute_machine_find_user(restored->attr_machine, "alice");
  ASSERT_NE(restored_writer, nullptr);
  EXPECT_EQ(restored_writer->status, USER_ACTIVE);
  EXPECT_EQ(restored_writer->key_version, 3);
  // Attributes persist verbatim ("name:value" pairs); role lookup keys on the
  // name part (matches the attribute machine's own convention, see
  // test_cli.cpp / test_integration.cpp which pass "role").
  EXPECT_TRUE(attribute_machine_user_has_role(restored_writer, "role"));
  ASSERT_EQ(restored_writer->key_count, 1);
  ASSERT_NE(restored_writer->keys, nullptr);
  EXPECT_STREQ(restored_writer->keys->key_id, "k1");
  EXPECT_EQ(restored_writer->keys->scheme, ECDSA_SECP256K1);
  EXPECT_EQ(restored_writer->keys->public_key[0], 1);

  serialized_buffer_destroy(buf);
  // The restored state carries the deserializer-owned attribute machine shell;
  // state_destroy releases both the state fields and its user registry.
  state_destroy(restored);
}

TEST(TestSerialization, V10SealedMskRoundTripRestoresAuthority) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  uint8_t seal_key[32];
  ASSERT_EQ(crypto_random_bytes(seal_key, sizeof(seal_key)), CRABS_SUCCESS);

  serialized_buffer_t* buf = crabs_serialize_state_sealed(state, seal_key);
  ASSERT_NE(buf, nullptr);

  // Wrong key: substrate restores, MSK stays fresh.
  uint8_t wrong_key[32];
  memcpy(wrong_key, seal_key, 32);
  wrong_key[0] ^= 0xFF;
  state_t* wrong = crabs_deserialize_state_keys(buf->data, buf->len, wrong_key);
  ASSERT_NE(wrong, nullptr);
  ASSERT_NE(wrong->abe_mk, nullptr);   // fresh key, never NULL
  state_destroy(wrong);

  // Correct key: the restored MSK matches the original bit-for-bit (same
  // serialized MPK bytes) — the authority is preserved.
  uint8_t* original_msk = (uint8_t*)malloc(16384);
  size_t original_len = crypto_master_key_serialize(
      (const abe_master_key_t*)state->abe_mk, original_msk, 16384);
  ASSERT_GT(original_len, (size_t)0);

  state_t* restored = crabs_deserialize_state_keys(buf->data, buf->len, seal_key);
  ASSERT_NE(restored, nullptr);
  uint8_t* restored_msk = (uint8_t*)malloc(16384);
  size_t restored_len = crypto_master_key_serialize(
      (const abe_master_key_t*)restored->abe_mk, restored_msk, 16384);
  ASSERT_EQ(restored_len, original_len);
  EXPECT_EQ(memcmp(restored_msk, original_msk, original_len), 0);
  free(original_msk);
  free(restored_msk);

  // No key: MSK section cannot be unsealed — substrate restores with a FRESH
  // MSK (the compat path), never NULL.
  state_t* fresh = crabs_deserialize_state_keys(buf->data, buf->len, NULL);
  ASSERT_NE(fresh, nullptr);
  ASSERT_NE(fresh->abe_mk, nullptr);
  state_destroy(fresh);

  state_destroy(restored);
  serialized_buffer_destroy(buf);
  state_destroy(state);
}

TEST(TestSerialization, V10CorruptUserEntryFailsWholeLoad) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  // Same fixture style as V10UserRegistryRoundTripPreservesAttributesAndKeys:
  // a caller-managed attribute-machine shell holding one user with one key.
  state->attr_machine = (attribute_machine_t*)get_clear_memory(sizeof(attribute_machine_t));
  state->attr_machine->base_state = *state;   // alias for pointer wiring only
  user_t* writer = (user_t*)get_clear_memory(sizeof(user_t));
  strncpy(writer->user_id, "alice", CRABS_MAX_USER_ID - 1);
  writer->status = USER_ACTIVE;
  writer->key_version = 3;
  strncpy(writer->attributes[0].value, "role:writer", CRABS_MAX_POLICY_EXPR - 1);
  writer->attribute_count = 1;
  user_key_t* first_key = (user_key_t*)get_clear_memory(sizeof(user_key_t));
  strncpy(first_key->key_id, "k1", CRABS_MAX_KEY_ID - 1);
  first_key->scheme = ECDSA_SECP256K1;
  first_key->public_key_len = 33;
  first_key->status = KEY_ACTIVE;
  writer->keys = first_key;
  writer->key_count = 1;
  strncpy(writer->default_key_id, "k1", CRABS_MAX_KEY_ID - 1);
  state->attr_machine->users = writer;
  state->attr_machine->user_count = 1;

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  // Control: the intact blob loads (whole parse, no partial adoption).
  state_t* control = crabs_deserialize_state_keys(buf->data, buf->len, NULL);
  ASSERT_NE(control, nullptr);
  state_destroy(control);

  // Detach and free the fixture exactly as in the round-trip test: the shell
  // is caller-managed and state_destroy must not double-free its registry.
  state->attr_machine->users = NULL;
  state->attr_machine->base_state.attr_machine = NULL;
  state->attr_machine->base_state.abe_mk = NULL;   // owned by the original state
  free(state->attr_machine);
  state->attr_machine = NULL;
  state_destroy(state);
  user_key_destroy_all(writer);
  free(writer);

  // Deterministic corruption INSIDE the user entry. The user's key_count
  // field (u32, value 1) is located by its unique wire neighborhood:
  // [01 00 00 00]key_count=1 followed by [02 00 'k' '1'], the first key's
  // string16 id. Bumping the count to 2 makes the reader parse a second key
  // out of the bytes after the real one (temp-attr count, child manifest,
  // MSK flag) — a mid-entry failure with the first key already spliced into
  // the user's keyring. The checksum is recomputed so the corruption reaches
  // the section parsers (otherwise the checksum gate rejects before the
  // registry is even reached).
  const uint8_t needle[8] = {0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 'k', '1'};
  bool found = false;
  for (size_t index = 8; index + 8 <= buf->len - 32; index++) {
    if (memcmp(buf->data + index, needle, 8) == 0) {
      buf->data[index] = 0x02;   // key_count 1 -> 2
      found = true;
      break;
    }
  }
  ASSERT_TRUE(found);

  uint8_t recomputed_hash[CRABS_HASH_SIZE];
  SHA256(buf->data, buf->len - CRABS_HASH_SIZE, recomputed_hash);
  memcpy(buf->data + buf->len - CRABS_HASH_SIZE, recomputed_hash, CRABS_HASH_SIZE);

  // The corrupted entry must fail the WHOLE load — the reader returns NULL
  // (never a partially restored state); the user-record cleanup on the fail
  // path plus state_destroy's embedded-machine guard must free everything
  // (verified leak-free under valgrind).
  state_t* result = crabs_deserialize_state_keys(buf->data, buf->len, NULL);
  EXPECT_EQ(result, nullptr);
  state_t* result_again = crabs_deserialize_state(buf->data, buf->len);
  EXPECT_EQ(result_again, nullptr);

  serialized_buffer_destroy(buf);
}

// Plan-1 follow-up #1: a sealed snapshot loaded with a WRONG seal key must be
// distinguishable from a snapshot with no sealed MSK section at all — the
// substrate keeps a FRESH authority in both cases, so callers need explicit
// restoration reporting.
TEST(TestSerialization, AuthorityRestorationIsReportable) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  uint8_t seal_key[32];
  ASSERT_EQ(crypto_random_bytes(seal_key, sizeof(seal_key)), CRABS_SUCCESS);

  serialized_buffer_t* buf = crabs_serialize_state_sealed(state, seal_key);
  ASSERT_NE(buf, nullptr);

  uint8_t wrong_key[32];
  memcpy(wrong_key, seal_key, 32);
  wrong_key[0] ^= 0xFF;

  bool authority_restored = true;
  bool msk_section_present = false;
  state_t* wrong = crabs_deserialize_state_keys_reported(
      buf->data, buf->len, wrong_key, &authority_restored, &msk_section_present);
  ASSERT_NE(wrong, nullptr);
  EXPECT_FALSE(authority_restored);
  EXPECT_TRUE(msk_section_present);

  authority_restored = false;
  state_t* correct = crabs_deserialize_state_keys_reported(
      buf->data, buf->len, seal_key, &authority_restored, &msk_section_present);
  ASSERT_NE(correct, nullptr);
  EXPECT_TRUE(authority_restored);
  EXPECT_TRUE(msk_section_present);
  state_destroy(correct);
  state_destroy(wrong);
  serialized_buffer_destroy(buf);
  state_destroy(state);
}

// ============================================================
// v11: lineage child manifest + parent binding
// ============================================================

// v11 fixture: append one manifest entry by direct field writes. The children
// array is a heap array OWNED by the state (state_destroy frees it), so the
// fixture reallocs it and lets state_destroy release it — the same ownership
// the spawn path will use.
static void append_manifest_entry(state_t* state, const char* child_id,
                                  lineage_trust_mode_e mode,
                                  lineage_status_e status,
                                  uint64_t attestation_ttl_ms,
                                  uint64_t spawned_at) {
  child_manifest_entry_t* grown = (child_manifest_entry_t*)realloc(
      state->children, (state->child_count + 1) * sizeof(child_manifest_entry_t));
  ASSERT_NE(grown, nullptr);
  state->children = grown;
  child_manifest_entry_t* entry = &state->children[state->child_count];
  memset(entry, 0, sizeof(*entry));
  strncpy(entry->child_id, child_id, CRABS_MAX_USER_ID - 1);
  entry->mode = mode;
  entry->status = status;
  entry->attestation_ttl_ms = attestation_ttl_ms;
  entry->spawned_at = spawned_at;
  state->child_count++;
}

TEST(TestSerialization, V11ManifestRoundTrip) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  // Two entries with every field deliberately different so a swapped or
  // truncated entry cannot pass by coincidence.
  append_manifest_entry(state, "child-red", LINEAGE_SHARED_ROOT, LINEAGE_ACTIVE,
                        60000, 1700000000000);
  append_manifest_entry(state, "child-blue", LINEAGE_DELEGATED_COPY,
                        LINEAGE_DISSOLVED, 120000, 1700000600000);
  for (int hash_byte = 0; hash_byte < CRABS_HASH_SIZE; hash_byte++) {
    state->children[0].genesis_snapshot_hash[hash_byte] = (uint8_t)(hash_byte + 0xA0);
    state->children[1].genesis_snapshot_hash[hash_byte] = (uint8_t)(0x5A ^ hash_byte);
  }
  for (int signature_byte = 0; signature_byte < CRABS_SIG_SIZE; signature_byte++) {
    state->children[0].genesis_attestation_signature[signature_byte] =
        (uint8_t)(signature_byte * 7 + 1);
    state->children[1].genesis_attestation_signature[signature_byte] =
        (uint8_t)(signature_byte * 11 + 3);
  }

  // Parent binding: the child resolves endorsements as "machine-self-id"
  // against the parent key that signed its genesis attestation.
  state->lineage_parent_bound = true;
  strncpy(state->lineage_parent_id, "parent-root", CRABS_MAX_USER_ID - 1);
  for (int public_byte = 0; public_byte < 33; public_byte++) {
    state->lineage_parent_public_key[public_byte] = (uint8_t)(public_byte + 0x21);
  }
  strncpy(state->lineage_self_id, "machine-self-id", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state_keys(buf->data, buf->len, NULL);
  ASSERT_NE(restored, nullptr);
  ASSERT_EQ(restored->child_count, 2u);
  ASSERT_NE(restored->children, nullptr);

  EXPECT_STREQ(restored->children[0].child_id, "child-red");
  EXPECT_EQ(restored->children[0].mode, LINEAGE_SHARED_ROOT);
  EXPECT_EQ(restored->children[0].status, LINEAGE_ACTIVE);
  EXPECT_EQ(restored->children[0].attestation_ttl_ms, 60000u);
  EXPECT_EQ(restored->children[0].spawned_at, 1700000000000ull);
  EXPECT_EQ(memcmp(restored->children[0].genesis_snapshot_hash,
                   state->children[0].genesis_snapshot_hash,
                   CRABS_HASH_SIZE), 0);
  EXPECT_EQ(memcmp(restored->children[0].genesis_attestation_signature,
                   state->children[0].genesis_attestation_signature,
                   CRABS_SIG_SIZE), 0);

  EXPECT_STREQ(restored->children[1].child_id, "child-blue");
  EXPECT_EQ(restored->children[1].mode, LINEAGE_DELEGATED_COPY);
  EXPECT_EQ(restored->children[1].status, LINEAGE_DISSOLVED);
  EXPECT_EQ(restored->children[1].attestation_ttl_ms, 120000u);
  EXPECT_EQ(restored->children[1].spawned_at, 1700000600000ull);
  EXPECT_EQ(memcmp(restored->children[1].genesis_snapshot_hash,
                   state->children[1].genesis_snapshot_hash,
                   CRABS_HASH_SIZE), 0);
  EXPECT_EQ(memcmp(restored->children[1].genesis_attestation_signature,
                   state->children[1].genesis_attestation_signature,
                   CRABS_SIG_SIZE), 0);

  EXPECT_TRUE(restored->lineage_parent_bound);
  EXPECT_STREQ(restored->lineage_parent_id, "parent-root");
  EXPECT_EQ(memcmp(restored->lineage_parent_public_key,
                   state->lineage_parent_public_key, 33), 0);
  EXPECT_STREQ(restored->lineage_self_id, "machine-self-id");

  serialized_buffer_destroy(buf);
  state_destroy(state);   // frees the fixture's children array
  state_destroy(restored);
}

// Reader strictness under byte surgery. The writer never emits out-of-range
// values, so malformed entries are produced by patching a real blob and
// recomputing the checksum trailer — the same deterministic approach as
// V10CorruptUserEntryFailsWholeLoad. Wire layout of one entry (fixed order):
//   [u16 len]['child-red'] [u8 mode] [32B hash] [64B sig]
//   [u64 ttl] [u64 spawned_at] [u8 status]
// so the needle {09 00 'child-red'} locates the entry head: mode sits at
// needle + 11, status at needle + 124.
TEST(TestSerialization, V11RejectsBadManifestEntry) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  append_manifest_entry(state, "child-red", LINEAGE_SHARED_ROOT, LINEAGE_ACTIVE,
                        60000, 1700000000000);
  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  state_destroy(state);   // frees the children array; buf is independent

  // Control: the intact blob loads.
  state_t* control = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(control, nullptr);
  state_destroy(control);

  // Out-of-range trust mode: 0x7F is between no enum value.
  const uint8_t needle[11] = {0x09, 0x00, 'c', 'h', 'i', 'l', 'd', '-', 'r', 'e', 'd'};
  bool found = false;
  for (size_t index = 0; index + 11 <= buf->len - CRABS_HASH_SIZE; index++) {
    if (memcmp(buf->data + index, needle, 11) == 0) {
      buf->data[index + 11] = 0x7F;   // mode byte
      found = true;
      break;
    }
  }
  ASSERT_TRUE(found);

  uint8_t recomputed_hash[CRABS_HASH_SIZE];
  SHA256(buf->data, buf->len - CRABS_HASH_SIZE, recomputed_hash);
  memcpy(buf->data + buf->len - CRABS_HASH_SIZE, recomputed_hash, CRABS_HASH_SIZE);

  EXPECT_EQ(crabs_deserialize_state(buf->data, buf->len), nullptr);
  EXPECT_EQ(crabs_deserialize_state_keys(buf->data, buf->len, NULL), nullptr);

  serialized_buffer_destroy(buf);
}

// Same surgery machinery against the parent-binding block: the strict 0/1
// bool flag must reject any other value. With one entry followed by
// [u8 bound][u16 len]['parent-root'][33B pubkey][u16 len self id], the flag
// byte sits directly before the parent-id length prefix.
TEST(TestSerialization, V11RejectsBadParentBoundFlag) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  append_manifest_entry(state, "child-red", LINEAGE_SHARED_ROOT, LINEAGE_ACTIVE,
                        60000, 1700000000000);
  state->lineage_parent_bound = true;
  strncpy(state->lineage_parent_id, "parent-root", CRABS_MAX_USER_ID - 1);
  strncpy(state->lineage_self_id, "machine-self-id", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  state_destroy(state);

  const char parent_needle[] = "parent-root";
  bool found = false;
  for (size_t index = 0; index + sizeof(parent_needle) - 1 <= buf->len - CRABS_HASH_SIZE; index++) {
    if (memcmp(buf->data + index, parent_needle, sizeof(parent_needle) - 1) == 0) {
      // bound flag is [u16 len] + parent_id chars - ... : before the prefix,
      // i.e. one byte above the chars minus their length and 2 prefix bytes.
      buf->data[index - 3] = 0x42;
      found = true;
      break;
    }
  }
  ASSERT_TRUE(found);

  uint8_t recomputed_hash[CRABS_HASH_SIZE];
  SHA256(buf->data, buf->len - CRABS_HASH_SIZE, recomputed_hash);
  memcpy(buf->data + buf->len - CRABS_HASH_SIZE, recomputed_hash, CRABS_HASH_SIZE);

  EXPECT_EQ(crabs_deserialize_state(buf->data, buf->len), nullptr);

  serialized_buffer_destroy(buf);
}

// v10-shape compat: the v11 reader must accept a blob that carries NO manifest
// entries and NO parent binding (count 0, bound flag 0) and restore the
// lineage-neutral defaults. This is the shape every pre-lineage state
// serializes to, and it is what a v10 file reduces to once the count position
// is consumed.
TEST(TestSerialization, V10ShapeBlobStillLoadsUnderV11) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);
  EXPECT_EQ(restored->child_count, 0u);
  EXPECT_EQ(restored->children, nullptr);
  EXPECT_FALSE(restored->lineage_parent_bound);
  EXPECT_STREQ(restored->lineage_self_id, "");

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

// Reader cap: the manifest count is attacker-controlled on the wire, so it is
// strictly capped at CRABS_MAX_CHILD_MACHINES. The writer does not validate,
// so a fixture with an over-cap count reaches the reader unchanged.
TEST(TestSerialization, V11RejectsOverCapChildCount) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  for (uint32_t child_index = 0; child_index <= CRABS_MAX_CHILD_MACHINES; child_index++) {
    char child_id[CRABS_MAX_USER_ID];
    snprintf(child_id, sizeof(child_id), "child-%02u", (unsigned)child_index);
    append_manifest_entry(state, child_id, LINEAGE_SHARED_ROOT, LINEAGE_ACTIVE,
                          60000, 1700000000000);
  }
  ASSERT_EQ(state->child_count, CRABS_MAX_CHILD_MACHINES + 1);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  state_destroy(state);

  EXPECT_EQ(crabs_deserialize_state(buf->data, buf->len), nullptr);

  serialized_buffer_destroy(buf);
}

// Wire-check: serialization must be CANONICAL — serialize → deserialize →
// serialize must reproduce the exact byte stream. Fixed-width fields and
// walk-derived counts make the v11 blob deterministic; this is the strongest
// regression net for the spawn/restart work that follows.
TEST(TestSerialization, V11SerializationIsByteStableAcrossRoundTrip) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  append_manifest_entry(state, "child-red", LINEAGE_SHARED_ROOT, LINEAGE_ACTIVE,
                        60000, 1700000000000);
  append_manifest_entry(state, "child-blue", LINEAGE_SOVEREIGN,
                        LINEAGE_WITHDRAWN, 120000, 1700000600000);
  for (int hash_byte = 0; hash_byte < CRABS_HASH_SIZE; hash_byte++) {
    state->children[0].genesis_snapshot_hash[hash_byte] = (uint8_t)(hash_byte + 0xA0);
    state->children[1].genesis_snapshot_hash[hash_byte] = (uint8_t)(0x5A ^ hash_byte);
  }
  for (int signature_byte = 0; signature_byte < CRABS_SIG_SIZE; signature_byte++) {
    state->children[0].genesis_attestation_signature[signature_byte] =
        (uint8_t)(signature_byte * 7 + 1);
    state->children[1].genesis_attestation_signature[signature_byte] =
        (uint8_t)(signature_byte * 11 + 3);
  }
  state->lineage_parent_bound = true;
  strncpy(state->lineage_parent_id, "parent-root", CRABS_MAX_USER_ID - 1);
  for (int public_byte = 0; public_byte < 33; public_byte++) {
    state->lineage_parent_public_key[public_byte] = (uint8_t)(public_byte + 0x21);
  }
  strncpy(state->lineage_self_id, "machine-self-id", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* first = crabs_serialize_state(state);
  ASSERT_NE(first, nullptr);
  state_t* restored = crabs_deserialize_state_keys(first->data, first->len, NULL);
  ASSERT_NE(restored, nullptr);
  serialized_buffer_t* second = crabs_serialize_state(restored);
  ASSERT_NE(second, nullptr);

  ASSERT_EQ(first->len, second->len);
  EXPECT_EQ(memcmp(first->data, second->data, first->len), 0);

  serialized_buffer_destroy(second);
  state_destroy(restored);
  serialized_buffer_destroy(first);
  state_destroy(state);
}

// v12: the parent-binding block gains a trailing byte — the dissolve
// tombstone flag — so a child that accepted dissolution comes back dissolved
// after a restart instead of trusting the (now-stale) parent endorsements.
// Layout when bound: [u8 bound][string16 parent_id][33B pubkey]
// [string16 self_id][u8 parent_dissolved].
TEST(TestSerialization, V12ParentDissolvedFlagRoundTrips) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  state->lineage_parent_bound = true;
  state->lineage_parent_dissolved = true;
  strncpy(state->lineage_parent_id, "parent-root", CRABS_MAX_USER_ID - 1);
  for (int public_byte = 0; public_byte < 33; public_byte++) {
    state->lineage_parent_public_key[public_byte] = (uint8_t)(public_byte + 0x21);
  }
  strncpy(state->lineage_self_id, "machine-self-id", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state_keys(buf->data, buf->len, NULL);
  ASSERT_NE(restored, nullptr);
  EXPECT_TRUE(restored->lineage_parent_bound);
  EXPECT_STREQ(restored->lineage_parent_id, "parent-root");
  EXPECT_EQ(memcmp(restored->lineage_parent_public_key,
                   state->lineage_parent_public_key, 33), 0);
  EXPECT_STREQ(restored->lineage_self_id, "machine-self-id");
  EXPECT_TRUE(restored->lineage_parent_dissolved);

  state_destroy(restored);
  serialized_buffer_destroy(buf);
  state_destroy(state);

  // An undissolved binding must round trip false, not come back sticky-true.
  state_t* undissolved = state_create();
  ASSERT_NE(undissolved, nullptr);
  undissolved->lineage_parent_bound = true;
  strncpy(undissolved->lineage_parent_id, "parent-root", CRABS_MAX_USER_ID - 1);
  strncpy(undissolved->lineage_self_id, "machine-self-id", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* plain_buf = crabs_serialize_state(undissolved);
  ASSERT_NE(plain_buf, nullptr);

  state_t* plain_restored =
      crabs_deserialize_state_keys(plain_buf->data, plain_buf->len, NULL);
  ASSERT_NE(plain_restored, nullptr);
  EXPECT_TRUE(plain_restored->lineage_parent_bound);
  EXPECT_FALSE(plain_restored->lineage_parent_dissolved);

  state_destroy(plain_restored);
  serialized_buffer_destroy(plain_buf);
  state_destroy(undissolved);
}

// v11-layout compat: a blob written WITHOUT the trailing dissolved byte must
// still load. Surgery: serialize a bound v13 blob, locate the self id, remove
// everything between the self id and the final unsealed-MSK flag byte (the
// v12 dissolved byte plus the v13 chain / key-version / transition tail —
// none of which a v11 reader knows about), patch the version field back
// to 11 (offset 4, uint32 LE, same idiom as TestSerializeV1StateStillLoads)
// and recompute the checksum trailer. The v11 reader never reaches the flag
// read, so the field falls back to its fresh-state default (false).
TEST(TestSerialization, V11BoundBlobWithoutDissolvedByteLoadsFalse) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  append_manifest_entry(state, "child-red", LINEAGE_SHARED_ROOT, LINEAGE_ACTIVE,
                        60000, 1700000000000);
  state->lineage_parent_bound = true;
  state->lineage_parent_dissolved = true;
  strncpy(state->lineage_parent_id, "parent-root", CRABS_MAX_USER_ID - 1);
  strncpy(state->lineage_self_id, "machine-self-id", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  state_destroy(state);

  const char self_needle[] = "machine-self-id";
  bool found = false;
  for (size_t index = 0; index + sizeof(self_needle) <= buf->len - CRABS_HASH_SIZE;
       index++) {
    if (memcmp(buf->data + index, self_needle, sizeof(self_needle) - 1) == 0) {
      // Everything between the self id and the trailing unsealed-MSK flag
      // byte is post-v11 format surface: the v12 dissolved byte and the v13
      // chain / key-version / transition sections. Drop all of it, leaving
      // the MSK flag and checksum trailer intact.
      size_t tail_start = index + sizeof(self_needle) - 1;
      size_t payload_len = buf->len - CRABS_HASH_SIZE;
      size_t msk_flag_offset = payload_len - 1;
      ASSERT_LT(tail_start, msk_flag_offset);
      buf->data[tail_start] = buf->data[msk_flag_offset];
      buf->len -= msk_flag_offset - tail_start;
      found = true;
      break;
    }
  }
  ASSERT_TRUE(found);

  uint32_t version_value = 11;
  memcpy(buf->data + 4, &version_value, sizeof(version_value));

  uint8_t recomputed_hash[CRABS_HASH_SIZE];
  SHA256(buf->data, buf->len - CRABS_HASH_SIZE, recomputed_hash);
  memcpy(buf->data + buf->len - CRABS_HASH_SIZE, recomputed_hash, CRABS_HASH_SIZE);

  state_t* restored = crabs_deserialize_state_keys(buf->data, buf->len, NULL);
  ASSERT_NE(restored, nullptr);
  EXPECT_TRUE(restored->lineage_parent_bound);
  EXPECT_STREQ(restored->lineage_parent_id, "parent-root");
  EXPECT_STREQ(restored->lineage_self_id, "machine-self-id");
  EXPECT_EQ(restored->child_count, 1u);
  EXPECT_FALSE(restored->lineage_parent_dissolved);

  state_destroy(restored);
  serialized_buffer_destroy(buf);
}

// ============================================================
// v13 (A10-M6): lineage parent key chain + key version + last transition
// ============================================================
//
// Wire layout additions over v12: the binding block's tail gains the child's
// parent key chain (u8 count >= 1; per entry: u64 key_version + 33-byte
// public key; entry [0] IS the binding block's spawn pin). Immediately after
// the binding block — bound or not — come the parent-side fields: u64
// lineage_key_version and a bytes32 holding the last signed key transition
// record (capped at LINEAGE_KEY_TRANSITION_WIRE_MAX).

// A rotating parent (node key k1 -> k2 via lineage_key_rotate, so the signed
// record is stashed as lineage_last_key_transition) and its bound child,
// whose chain has advanced via lineage_child_accept_key_transition to
// [{1, k1.public}, {2, k2.public}]. Built with the real APIs so the states
// satisfy every invariant the writer validates.
typedef struct {
  state_t*         parent_state;
  state_t*         child_state;
  ecdsa_keypair_t* k1;
  ecdsa_keypair_t* k2;
} keychain_wire_fixture_t;

static void keychain_wire_fixture_setup(keychain_wire_fixture_t* fixture) {
  memset(fixture, 0, sizeof(*fixture));
  fixture->k1 = crypto_ecdsa_generate();
  fixture->k2 = crypto_ecdsa_generate();
  ASSERT_NE(fixture->k1, nullptr);
  ASSERT_NE(fixture->k2, nullptr);

  fixture->parent_state = state_create();
  ASSERT_NE(fixture->parent_state, nullptr);
  ASSERT_EQ(state_set_node_key(fixture->parent_state,
                               fixture->k1->private_key,
                               fixture->k1->public_key), CRABS_SUCCESS);
  // A root parent has no lineage_self_id; the rotate record falls back to
  // bootstrap_admin (the id children persist as lineage_parent_id).
  strncpy(fixture->parent_state->config.bootstrap_admin, "parent-red",
          sizeof(fixture->parent_state->config.bootstrap_admin) - 1);

  fixture->child_state = state_create();
  ASSERT_NE(fixture->child_state, nullptr);
  state_t* child = fixture->child_state;
  memcpy(child->lineage_parent_public_key, fixture->k1->public_key, 33);
  strncpy(child->lineage_parent_id, "parent-red",
          sizeof(child->lineage_parent_id) - 1);
  strncpy(child->lineage_self_id, "child-red",
          sizeof(child->lineage_self_id) - 1);
  child->lineage_parent_bound = true;
  child->lineage_key_chain = (lineage_key_chain_entry_t*)calloc(
      1, sizeof(lineage_key_chain_entry_t));
  ASSERT_NE(child->lineage_key_chain, nullptr);
  child->lineage_key_chain[0].key_version = CRABS_LINEAGE_KEY_VERSION_START;
  memcpy(child->lineage_key_chain[0].public_key, fixture->k1->public_key, 33);
  child->lineage_key_chain_count = 1;

  // Rotate the parent (k1 -> k2) and feed the child the signed record, so
  // both sides carry their v13 surfaces: parent has key_version 2 and the
  // stashed record; the child has a two-entry chain.
  uint8_t* record = nullptr;
  size_t record_len = 0;
  ASSERT_EQ(lineage_key_rotate(fixture->parent_state,
                               fixture->k2->private_key,
                               fixture->k2->public_key,
                               1700000000000ULL, &record, &record_len),
            CRABS_SUCCESS);
  ASSERT_EQ(lineage_child_accept_key_transition(child, record, record_len),
            CRABS_SUCCESS);
  free(record);
}

static void keychain_wire_fixture_destroy(keychain_wire_fixture_t* fixture) {
  state_destroy(fixture->parent_state);
  state_destroy(fixture->child_state);
  crypto_ecdsa_keypair_destroy(fixture->k1);
  crypto_ecdsa_keypair_destroy(fixture->k2);
}

TEST(LineageKeyChainWire, RoundTrip) {
  keychain_wire_fixture_t fixture;
  keychain_wire_fixture_setup(&fixture);

  // Parent side: the key version and the stashed signed transition record
  // must survive the blob exactly.
  serialized_buffer_t* parent_buf = crabs_serialize_state(fixture.parent_state);
  ASSERT_NE(parent_buf, nullptr);
  state_t* parent_restored =
      crabs_deserialize_state_keys(parent_buf->data, parent_buf->len, NULL);
  ASSERT_NE(parent_restored, nullptr);
  EXPECT_EQ(parent_restored->lineage_key_version,
            fixture.parent_state->lineage_key_version);
  EXPECT_EQ(parent_restored->lineage_key_version,
            (uint64_t)CRABS_LINEAGE_KEY_VERSION_START + 1);
  ASSERT_NE(parent_restored->lineage_last_key_transition, nullptr);
  ASSERT_EQ(parent_restored->lineage_last_key_transition_len,
            fixture.parent_state->lineage_last_key_transition_len);
  EXPECT_GT(parent_restored->lineage_last_key_transition_len, 0u);
  EXPECT_EQ(memcmp(parent_restored->lineage_last_key_transition,
                   fixture.parent_state->lineage_last_key_transition,
                   parent_restored->lineage_last_key_transition_len), 0);
  // A root parent carries no binding and no chain.
  EXPECT_FALSE(parent_restored->lineage_parent_bound);
  EXPECT_EQ(parent_restored->lineage_key_chain, nullptr);
  EXPECT_EQ(parent_restored->lineage_key_chain_count, 0u);

  state_destroy(parent_restored);
  serialized_buffer_destroy(parent_buf);

  // Child side: the two-entry chain must survive exactly — versions, keys,
  // and order.
  serialized_buffer_t* child_buf = crabs_serialize_state(fixture.child_state);
  ASSERT_NE(child_buf, nullptr);
  state_t* child_restored =
      crabs_deserialize_state_keys(child_buf->data, child_buf->len, NULL);
  ASSERT_NE(child_restored, nullptr);
  ASSERT_TRUE(child_restored->lineage_parent_bound);
  ASSERT_EQ(child_restored->lineage_key_chain_count, 2u);
  EXPECT_EQ(child_restored->lineage_key_chain[0].key_version,
            (uint64_t)CRABS_LINEAGE_KEY_VERSION_START);
  EXPECT_EQ(memcmp(child_restored->lineage_key_chain[0].public_key,
                   fixture.k1->public_key, 33), 0);
  EXPECT_EQ(child_restored->lineage_key_chain[1].key_version,
            (uint64_t)CRABS_LINEAGE_KEY_VERSION_START + 1);
  EXPECT_EQ(memcmp(child_restored->lineage_key_chain[1].public_key,
                   fixture.k2->public_key, 33), 0);
  // The child never rotated: no parent-side fields of its own.
  EXPECT_EQ(child_restored->lineage_key_version, 0u);
  EXPECT_EQ(child_restored->lineage_last_key_transition, nullptr);
  EXPECT_EQ(child_restored->lineage_last_key_transition_len, 0u);

  state_destroy(child_restored);
  serialized_buffer_destroy(child_buf);
  keychain_wire_fixture_destroy(&fixture);
}

// A v12-format blob carries no chain — the loader must synthesize the
// single-entry pin chain (entry [0] == the binding block's public key at
// CRABS_LINEAGE_KEY_VERSION_START) and leave the parent-side fields at their
// fresh-state defaults. Surgery: serialize a bound v13 blob, keep the
// v12 dissolved byte (a v12 blob requires it; it sits directly after the
// self id and is already 0 for this undissolved fixture), drop the v13
// sections that follow it — everything up to the trailing unsealed-MSK flag
// byte — patch the version field back to 12 (offset 4, uint32 LE), and
// recompute the checksum.
TEST(LineageKeyChainWire, V12BlobSynthesizesChain) {
  keychain_wire_fixture_t fixture;
  keychain_wire_fixture_setup(&fixture);

  serialized_buffer_t* buf = crabs_serialize_state(fixture.child_state);
  ASSERT_NE(buf, nullptr);
  keychain_wire_fixture_destroy(&fixture);

  const char self_needle[] = "child-red";
  bool found = false;
  for (size_t index = 0; index + sizeof(self_needle) <= buf->len - CRABS_HASH_SIZE;
       index++) {
    if (memcmp(buf->data + index, self_needle, sizeof(self_needle) - 1) == 0) {
      // dissolved_offset + 1 is where the v13 chain section begins.
      size_t dissolved_offset = index + sizeof(self_needle) - 1;
      size_t payload_len = buf->len - CRABS_HASH_SIZE;
      size_t msk_flag_offset = payload_len - 1;
      ASSERT_LT(dissolved_offset + 1, msk_flag_offset);
      buf->data[dissolved_offset + 1] = buf->data[msk_flag_offset];
      buf->len -= msk_flag_offset - dissolved_offset - 1;
      found = true;
      break;
    }
  }
  ASSERT_TRUE(found);

  uint32_t version_value = 12;
  memcpy(buf->data + 4, &version_value, sizeof(version_value));

  uint8_t recomputed_hash[CRABS_HASH_SIZE];
  SHA256(buf->data, buf->len - CRABS_HASH_SIZE, recomputed_hash);
  memcpy(buf->data + buf->len - CRABS_HASH_SIZE, recomputed_hash, CRABS_HASH_SIZE);

  state_t* restored = crabs_deserialize_state_keys(buf->data, buf->len, NULL);
  ASSERT_NE(restored, nullptr);
  EXPECT_TRUE(restored->lineage_parent_bound);
  // Chain synthesized from the spawn pin, exactly as the v11/v12 paths do.
  ASSERT_EQ(restored->lineage_key_chain_count, 1u);
  EXPECT_EQ(restored->lineage_key_chain[0].key_version,
            (uint64_t)CRABS_LINEAGE_KEY_VERSION_START);
  EXPECT_EQ(memcmp(restored->lineage_key_chain[0].public_key,
                   restored->lineage_parent_public_key, 33), 0);
  // The dissolved byte survived the surgery (it is v12 surface) and reads
  // back false; the v13 parent-side fields revert to their defaults.
  EXPECT_FALSE(restored->lineage_parent_dissolved);
  EXPECT_EQ(restored->lineage_key_version, 0u);
  EXPECT_EQ(restored->lineage_last_key_transition, nullptr);
  EXPECT_EQ(restored->lineage_last_key_transition_len, 0u);

  state_destroy(restored);
  serialized_buffer_destroy(buf);
}

// Fail-closed chain validation: the whole load must be refused (state NULL)
// when the wire chain violates any invariant. Cases: count 0, count above
// CRABS_MAX_LINEAGE_KEY_CHAIN, non-increasing key versions, entry [0] not
// equal to the binding block's public key, and a transition length above
// LINEAGE_KEY_TRANSITION_WIRE_MAX.
TEST(LineageKeyChainWire, CorruptChainRejected) {
  keychain_wire_fixture_t fixture;
  keychain_wire_fixture_setup(&fixture);

  serialized_buffer_t* good_buf = crabs_serialize_state(fixture.child_state);
  ASSERT_NE(good_buf, nullptr);
  keychain_wire_fixture_destroy(&fixture);

  // Locate the chain section: the self id's last character is followed by
  // the dissolved byte, then the count byte, then entry [0] (u64 version +
  // 33-byte key), then entry [1], then the parent-side u64 key version and
  // u32 transition length.
  const char self_needle[] = "child-red";
  size_t self_end = 0;
  bool found = false;
  for (size_t index = 0;
       index + sizeof(self_needle) <= good_buf->len - CRABS_HASH_SIZE;
       index++) {
    if (memcmp(good_buf->data + index, self_needle,
               sizeof(self_needle) - 1) == 0) {
      self_end = index + sizeof(self_needle) - 1;
      found = true;
      break;
    }
  }
  ASSERT_TRUE(found);

  auto expect_rejected = [&](void (*mutate)(uint8_t* blob, size_t self_end_pos)) {
    std::vector<uint8_t> tampered(good_buf->data,
                                  good_buf->data + good_buf->len);
    mutate(tampered.data(), self_end);
    uint8_t recomputed_hash[CRABS_HASH_SIZE];
    SHA256(tampered.data(), tampered.size() - CRABS_HASH_SIZE, recomputed_hash);
    memcpy(tampered.data() + tampered.size() - CRABS_HASH_SIZE,
           recomputed_hash, CRABS_HASH_SIZE);
    state_t* restored =
        crabs_deserialize_state_keys(tampered.data(), tampered.size(), NULL);
    EXPECT_EQ(restored, nullptr);
    if (restored != nullptr) state_destroy(restored);
  };

  // count = 0: an empty chain cannot satisfy entry [0] == spawn pin.
  expect_rejected([](uint8_t* blob, size_t pos) { blob[pos + 1] = 0; });
  // count above CRABS_MAX_LINEAGE_KEY_CHAIN.
  expect_rejected([](uint8_t* blob, size_t pos) {
    blob[pos + 1] = (uint8_t)(CRABS_MAX_LINEAGE_KEY_CHAIN + 1);
  });
  // Non-increasing key versions: rewind entry [1] to entry [0]'s version.
  expect_rejected([](uint8_t* blob, size_t pos) {
    size_t e0 = pos + 2;
    size_t e1_version = e0 + 8 + 33;
    memcpy(blob + e1_version, blob + e0, 8);
  });
  // Entry [0] public key != the binding block's public key.
  expect_rejected([](uint8_t* blob, size_t pos) {
    blob[pos + 2 + 8] ^= 0xFF;
  });
  // Record length above LINEAGE_KEY_TRANSITION_WIRE_MAX.
  expect_rejected([](uint8_t* blob, size_t pos) {
    size_t len_off = pos + 2 + 2 * (8 + 33) + 8;
    uint32_t oversized = (uint32_t)LINEAGE_KEY_TRANSITION_WIRE_MAX + 1;
    memcpy(blob + len_off, &oversized, sizeof(oversized));
  });

  serialized_buffer_destroy(good_buf);
}

// Fail-loud writer validation: the serializer must refuse (NULL buffer) a
// state whose parent-side lineage key fields or child-side chain break the
// invariants the reader enforces — an oversized or NULL transition record,
// and a NULL chain with a non-zero count.
TEST(LineageKeyChainWire, WriterRejectsInvalidParentSideFields) {
  keychain_wire_fixture_t fixture;
  keychain_wire_fixture_setup(&fixture);

  // transition_len above LINEAGE_KEY_TRANSITION_WIRE_MAX.
  {
    uint8_t* original_transition =
        fixture.parent_state->lineage_last_key_transition;
    size_t original_len = fixture.parent_state->lineage_last_key_transition_len;
    fixture.parent_state->lineage_last_key_transition_len =
        LINEAGE_KEY_TRANSITION_WIRE_MAX + 1;
    serialized_buffer_t* buf = crabs_serialize_state(fixture.parent_state);
    EXPECT_EQ(buf, nullptr);
    if (buf != nullptr) serialized_buffer_destroy(buf);
    fixture.parent_state->lineage_last_key_transition = original_transition;
    fixture.parent_state->lineage_last_key_transition_len = original_len;
  }

  // Non-zero transition_len with a NULL transition pointer.
  {
    uint8_t* original_transition =
        fixture.parent_state->lineage_last_key_transition;
    fixture.parent_state->lineage_last_key_transition = nullptr;
    ASSERT_GT(fixture.parent_state->lineage_last_key_transition_len, 0u);
    serialized_buffer_t* buf = crabs_serialize_state(fixture.parent_state);
    EXPECT_EQ(buf, nullptr);
    if (buf != nullptr) serialized_buffer_destroy(buf);
    fixture.parent_state->lineage_last_key_transition = original_transition;
  }

  // Non-zero chain count with a NULL chain array (bound child).
  {
    lineage_key_chain_entry_t* original_chain =
        fixture.child_state->lineage_key_chain;
    fixture.child_state->lineage_key_chain = nullptr;
    ASSERT_GT(fixture.child_state->lineage_key_chain_count, 0u);
    serialized_buffer_t* buf = crabs_serialize_state(fixture.child_state);
    EXPECT_EQ(buf, nullptr);
    if (buf != nullptr) serialized_buffer_destroy(buf);
    fixture.child_state->lineage_key_chain = original_chain;
  }

  // Sanity: the restored fixtures serialize cleanly again.
  serialized_buffer_t* parent_buf = crabs_serialize_state(fixture.parent_state);
  EXPECT_NE(parent_buf, nullptr);
  serialized_buffer_destroy(parent_buf);
  serialized_buffer_t* child_buf = crabs_serialize_state(fixture.child_state);
  EXPECT_NE(child_buf, nullptr);
  serialized_buffer_destroy(child_buf);

  keychain_wire_fixture_destroy(&fixture);
}

// ============================================================
// v14 (write-domains): per-item domain tail
// ============================================================
// The state header is magic(4) + version(4) + state_version(8) +
// item_count(4) + policy_count(4) + log_count(4), then items in list order.
// crabs_serialize_data_item yields exactly the pre-domain (v13) per-item
// form, so a v14 item's domain tail begins at item_start + pre_domain_len
// and the tail length is computable from the in-memory item. Layout:
//   [u8 write_domain]
//   SOVEREIGN:     [u16 wlen][writer][u64 seq][32B digest][u8 fork_count]
//                  + per entry [u16 flen][fork_writer][32B evidence]
//   GROUP_ORDERED: [u8 ordering_module]
//   FREE_MERGE:    nothing more.

static const size_t kV14ItemsOffset = 4 + 4 + 8 + 4 + 4 + 4;

static size_t v14_tail_len(const data_item_t* item) {
  if (item->write_domain == CRABS_DOMAIN_SOVEREIGN) {
    size_t tail_len = 1 + 2 + strlen(item->writer) + 8 + CRABS_HASH_SIZE + 1;
    for (uint32_t fork_index = 0; fork_index < item->fork_count; fork_index++) {
      tail_len += 2 + strlen(item->fork_writers[fork_index]) + CRABS_HASH_SIZE;
    }
    return tail_len;
  }
  if (item->write_domain == CRABS_DOMAIN_GROUP_ORDERED) {
    return 2;
  }
  return 1;
}

// Offset of item `name`'s v14 domain tail inside the serialized state blob;
// verifies along the way that the blob's item stream prefixes each tail with
// exactly the pre-domain bytes (the hash-chain preimage contract).
static size_t v14_find_tail_offset(state_t* state, const serialized_buffer_t* buf,
                                   const char* name) {
  size_t offset = kV14ItemsOffset;
  for (data_item_t* item = state->items; item != nullptr; item = item->next) {
    serialized_buffer_t* pre_domain = crabs_serialize_data_item(item);
    EXPECT_EQ(memcmp(buf->data + offset, pre_domain->data, pre_domain->len), 0);
    bool wanted = (strcmp(item->name, name) == 0);
    offset += pre_domain->len;
    serialized_buffer_destroy(pre_domain);
    if (wanted) return offset;
    offset += v14_tail_len(item);
  }
  ADD_FAILURE() << "item not found: " << name;
  return 0;
}

static void v14_rehash(serialized_buffer_t* buf) {
  uint8_t recomputed_hash[CRABS_HASH_SIZE];
  SHA256(buf->data, buf->len - CRABS_HASH_SIZE, recomputed_hash);
  memcpy(buf->data + buf->len - CRABS_HASH_SIZE, recomputed_hash, CRABS_HASH_SIZE);
}

// Round-trip every domain field exactly: a FREE_MERGE counter, a SOVEREIGN
// register with a live chain head (seq + digest) and one quarantined fork
// writer, and a GROUP_ORDERED counter at the v1 seam (module 0, read-only).
TEST(StateSerialize, V14ItemDomainRoundTrip) {
  state_t* original = state_create();
  ASSERT_NE(original, nullptr);
  original->version = 77;

  data_item_t* free_item =
      data_item_create("free-counter", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* free_counter = g_counter_create();
  ASSERT_EQ(g_counter_increment(free_counter, "node1", 123), CRABS_SUCCESS);
  free_item->value = free_counter;
  ASSERT_EQ(state_add_item(original, free_item), CRABS_SUCCESS);

  data_item_t* sov_item = nullptr;
  data_item_options_t sov_opts = {CRABS_DOMAIN_SOVEREIGN, "alice", 0};
  ASSERT_EQ(data_item_create_with_options("sov-register", DATA_TYPE_REGISTER,
                                          CRDT_LWW_REG, &sov_opts, &sov_item),
            CRABS_SUCCESS);
  int64_t sov_register_value = 7;
  sov_item->value = lww_register_create((const uint8_t*)&sov_register_value,
                                        sizeof(int64_t), 0, "alice");
  ASSERT_NE(sov_item->value, nullptr);
  sov_item->item_seq = 9;
  for (int digest_byte = 0; digest_byte < CRABS_HASH_SIZE; digest_byte++) {
    sov_item->item_digest[digest_byte] = (uint8_t)(0x40 + digest_byte);
  }
  uint8_t evidence_digest[CRABS_HASH_SIZE];
  for (int evidence_byte = 0; evidence_byte < CRABS_HASH_SIZE; evidence_byte++) {
    evidence_digest[evidence_byte] = (uint8_t)(0xC0 ^ evidence_byte);
  }
  ASSERT_EQ(state_append_fork_evidence(sov_item, "mallory", evidence_digest),
            CRABS_SUCCESS);
  ASSERT_EQ(state_add_item(original, sov_item), CRABS_SUCCESS);

  data_item_t* group_item = nullptr;
  data_item_options_t group_opts = {CRABS_DOMAIN_GROUP_ORDERED, nullptr, 0};
  ASSERT_EQ(data_item_create_with_options("grp-counter", DATA_TYPE_COUNTER,
                                          CRDT_G_COUNTER, &group_opts, &group_item),
            CRABS_SUCCESS);
  g_counter_t* group_counter = g_counter_create();
  ASSERT_EQ(g_counter_increment(group_counter, "node1", 999), CRABS_SUCCESS);
  group_item->value = group_counter;
  ASSERT_EQ(state_add_item(original, group_item), CRABS_SUCCESS);

  serialized_buffer_t* buf = crabs_serialize_state(original);
  ASSERT_NE(buf, nullptr);
  ASSERT_EQ((uint32_t)CRABS_SERIAL_VERSION, 15u);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);
  EXPECT_EQ(restored->version, original->version);

  data_item_t* restored_free = state_find_item(restored, "free-counter");
  ASSERT_NE(restored_free, nullptr);
  EXPECT_EQ(restored_free->write_domain, CRABS_DOMAIN_FREE_MERGE);
  EXPECT_STREQ(restored_free->writer, "");
  EXPECT_EQ(restored_free->item_seq, (uint64_t)0);
  EXPECT_EQ(restored_free->ordering_module, 0);
  EXPECT_EQ(restored_free->fork_count, 0u);

  data_item_t* restored_sov = state_find_item(restored, "sov-register");
  ASSERT_NE(restored_sov, nullptr);
  EXPECT_EQ(restored_sov->write_domain, CRABS_DOMAIN_SOVEREIGN);
  EXPECT_STREQ(restored_sov->writer, "alice");
  EXPECT_EQ(restored_sov->item_seq, (uint64_t)9);
  EXPECT_EQ(memcmp(restored_sov->item_digest, sov_item->item_digest,
                   CRABS_HASH_SIZE), 0);
  EXPECT_EQ(restored_sov->ordering_module, 0);
  ASSERT_EQ(restored_sov->fork_count, 1u);
  EXPECT_STREQ(restored_sov->fork_writers[0], "mallory");
  EXPECT_EQ(memcmp(restored_sov->fork_evidence_digests[0], evidence_digest,
                   CRABS_HASH_SIZE), 0);

  data_item_t* restored_group = state_find_item(restored, "grp-counter");
  ASSERT_NE(restored_group, nullptr);
  EXPECT_EQ(restored_group->write_domain, CRABS_DOMAIN_GROUP_ORDERED);
  EXPECT_EQ(restored_group->ordering_module, 0);
  EXPECT_STREQ(restored_group->writer, "");
  EXPECT_EQ(restored_group->fork_count, 0u);

  serialized_buffer_destroy(buf);
  state_destroy(original);
  state_destroy(restored);
}

// The sovereign-chain digest preimage covers ONLY the pre-domain item form:
// two items identical in the v13-covered fields but differing in every
// domain field serialize to byte-identical crabs_serialize_data_item output.
TEST(StateSerialize, V14ItemDigestPreimageExcludesDomainTail) {
  int64_t register_content = 42;
  data_item_t* free_item =
      data_item_create("chain-item", DATA_TYPE_REGISTER, CRDT_LWW_REG);
  free_item->value = lww_register_create((const uint8_t*)&register_content,
                                         sizeof(int64_t), 0, "");
  ASSERT_NE(free_item->value, nullptr);

  data_item_t* sov_item = nullptr;
  data_item_options_t sov_opts = {CRABS_DOMAIN_SOVEREIGN, "alice", 0};
  ASSERT_EQ(data_item_create_with_options("chain-item", DATA_TYPE_REGISTER,
                                          CRDT_LWW_REG, &sov_opts, &sov_item),
            CRABS_SUCCESS);
  sov_item->value = lww_register_create((const uint8_t*)&register_content,
                                        sizeof(int64_t), 0, "");
  ASSERT_NE(sov_item->value, nullptr);
  sov_item->item_seq = 12;
  memset(sov_item->item_digest, 0xAB, CRABS_HASH_SIZE);

  serialized_buffer_t* free_form = crabs_serialize_data_item(free_item);
  serialized_buffer_t* sov_form = crabs_serialize_data_item(sov_item);
  ASSERT_NE(free_form, nullptr);
  ASSERT_NE(sov_form, nullptr);
  ASSERT_EQ(free_form->len, sov_form->len);
  EXPECT_EQ(memcmp(free_form->data, sov_form->data, free_form->len), 0)
      << "the hash-chain preimage must not move with domain fields";

  serialized_buffer_destroy(free_form);
  serialized_buffer_destroy(sov_form);
  // Struct-backed values: data_item_destroy's default arm frees only the
  // struct shell (no register destroy case), so release properly first.
  lww_register_destroy((lww_register_t*)free_item->value); free_item->value = nullptr;
  lww_register_destroy((lww_register_t*)sov_item->value); sov_item->value = nullptr;
  data_item_destroy(free_item);
  data_item_destroy(sov_item);
}

// The chain preimage (crabs_serialize_data_item_chain_preimage, what the
// sovereign digest actually hashes) emits the SAME field set as the durable
// per-item form MINUS the runtime protocol_state byte — and, like the durable
// form, excludes the v14 domain tail. Two items whose ONLY differences are
// runtime protocol_state plus domain metadata must produce byte-identical
// chain preimages; and a chain preimage is exactly one byte shorter than the
// durable form of an otherwise-identical item.
TEST(StateSerialize, V14ChainPreimageExcludesProtocolStateAndDomainTail) {
  int64_t register_content = 42;
  data_item_t* locked_free =
      data_item_create("chain-item", DATA_TYPE_REGISTER, CRDT_LWW_REG);
  locked_free->value = lww_register_create((const uint8_t*)&register_content,
                                           sizeof(int64_t), 0, "");
  ASSERT_NE(locked_free->value, nullptr);
  locked_free->protocol_state = PROTOCOL_LOCKED;

  data_item_t* modified_sov = nullptr;
  data_item_options_t sov_opts = {CRABS_DOMAIN_SOVEREIGN, "alice", 0};
  ASSERT_EQ(data_item_create_with_options("chain-item", DATA_TYPE_REGISTER,
                                          CRDT_LWW_REG, &sov_opts, &modified_sov),
            CRABS_SUCCESS);
  modified_sov->value = lww_register_create((const uint8_t*)&register_content,
                                            sizeof(int64_t), 0, "");
  ASSERT_NE(modified_sov->value, nullptr);
  modified_sov->item_seq = 12;
  memset(modified_sov->item_digest, 0xAB, CRABS_HASH_SIZE);
  modified_sov->protocol_state = PROTOCOL_MODIFIED;

  serialized_buffer_t* locked_form =
      crabs_serialize_data_item_chain_preimage(locked_free);
  serialized_buffer_t* modified_form =
      crabs_serialize_data_item_chain_preimage(modified_sov);
  ASSERT_NE(locked_form, nullptr);
  ASSERT_NE(modified_form, nullptr);
  ASSERT_EQ(locked_form->len, modified_form->len);
  EXPECT_EQ(memcmp(locked_form->data, modified_form->data, locked_form->len), 0)
      << "chain preimage must not move with protocol_state or domain fields";

  // The chain preimage differs from the durable form of an otherwise identical
  // item by exactly nine bytes: the protocol_state byte (1) plus
  // last_compaction_time (8) — both replica-local metadata excluded from the
  // chain digest.
  serialized_buffer_t* durable_form = crabs_serialize_data_item(locked_free);
  ASSERT_NE(durable_form, nullptr);
  EXPECT_EQ(durable_form->len, locked_form->len + 9)
      << "chain preimage = durable form minus protocol_state and compaction time";

  EXPECT_EQ(crabs_serialize_data_item_chain_preimage(nullptr), nullptr);

  serialized_buffer_destroy(locked_form);
  serialized_buffer_destroy(modified_form);
  serialized_buffer_destroy(durable_form);
  lww_register_destroy((lww_register_t*)locked_free->value); locked_free->value = nullptr;
  lww_register_destroy((lww_register_t*)modified_sov->value); modified_sov->value = nullptr;
  data_item_destroy(locked_free);
  data_item_destroy(modified_sov);
}

// Pre-v14 loads: a v13 blob carries no domain tail; every item restores as
// FREE_MERGE with zeroed chain/quarantine fields. Surgery: the v14 tail for
// a default item is exactly one 0x00 byte — strip each one (the strip points
// are located via the pre-domain helper bytes), patch the version field
// 14->13, and re-fix the checksum.
TEST(StateSerialize, V13BlobLoadsAllFreeMerge) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  state->version = 55;
  data_item_t* counter_item =
      data_item_create("v13-counter", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* v13_counter = g_counter_create();
  ASSERT_EQ(g_counter_increment(v13_counter, "node1", 4), CRABS_SUCCESS);
  counter_item->value = v13_counter;
  ASSERT_EQ(state_add_item(state, counter_item), CRABS_SUCCESS);
  data_item_t* register_item =
      data_item_create("v13-register", DATA_TYPE_REGISTER, CRDT_LWW_REG);
  int64_t v13_register_value = 900;
  register_item->value = lww_register_create((const uint8_t*)&v13_register_value,
                                             sizeof(int64_t), 0, "alice");
  ASSERT_NE(register_item->value, nullptr);
  ASSERT_EQ(state_add_item(state, register_item), CRABS_SUCCESS);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  // Strip the per-item tail byte (must be 0x00 for every default item). The
  // walk order matches the writer's, so each strip shifts only the bytes
  // AFTER the current item — no offset recomputation needed mid-walk.
  size_t offset = kV14ItemsOffset;
  for (data_item_t* item = state->items; item != nullptr; item = item->next) {
    serialized_buffer_t* pre_domain = crabs_serialize_data_item(item);
    EXPECT_EQ(memcmp(buf->data + offset, pre_domain->data, pre_domain->len), 0);
    offset += pre_domain->len;
    serialized_buffer_destroy(pre_domain);
    ASSERT_EQ(buf->data[offset], 0x00)
        << "v14 tail of default item " << item->name
        << " must be exactly one free-merge byte";
    memmove(buf->data + offset, buf->data + offset + 1,
            buf->len - offset - 1);
    buf->len -= 1;
  }
  state_destroy(state);

  // Version 15 -> 13 (pre-domain-tail). The downgraded blob's item values
  // load through the legacy raw-int64 path regardless of content shape —
  // this test asserts only domain-field defaults.
  buf->data[4] = 13;
  v14_rehash(buf);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);
  EXPECT_EQ(restored->version, (uint64_t)55);
  for (data_item_t* item = restored->items; item != nullptr; item = item->next) {
    EXPECT_EQ(item->write_domain, CRABS_DOMAIN_FREE_MERGE)
        << "pre-v14 item " << item->name << " must restore as FREE_MERGE";
    EXPECT_STREQ(item->writer, "");
    EXPECT_EQ(item->item_seq, (uint64_t)0);
    EXPECT_EQ(item->ordering_module, 0);
    EXPECT_EQ(item->fork_count, 0u);
    uint8_t zero_digest[CRABS_HASH_SIZE] = {0};
    EXPECT_EQ(memcmp(item->item_digest, zero_digest, CRABS_HASH_SIZE), 0);
  }
  ASSERT_NE(state_find_item(restored, "v13-counter"), nullptr);
  ASSERT_NE(state_find_item(restored, "v13-register"), nullptr);
  // Value assertions deliberately dropped: the v15 writer emits struct
  // content (not the v13 raw int64), so a version-downgraded blob read
  // through the legacy raw-int64 path no longer recovers them — the same
  // class of value-loss as real pre-v15 files with struct-backed values (a
  // pre-existing bug this work fixes going forward, not backward).

  serialized_buffer_destroy(buf);
  state_destroy(restored);
}

// Corruption matrix: each case serializes an honest v14 blob, applies byte
// surgery, re-fixes the checksum, and requires the load to fail.

// Enum whitelist: a domain byte between no known values rejects the load.
TEST(StateSerialize, V14RejectsUnknownDomainByte) {
  state_t* state = state_create();
  data_item_t* item = data_item_create("item", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* counter_tmp = g_counter_create();
  ASSERT_EQ(g_counter_increment(counter_tmp, "node1", 1), CRABS_SUCCESS);
  item->value = counter_tmp;
  state_add_item(state, item);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  size_t tail_offset = v14_find_tail_offset(state, buf, "item");
  ASSERT_EQ(buf->data[tail_offset], 0x00);
  buf->data[tail_offset] = 0x03;   // one past CRABS_DOMAIN_GROUP_ORDERED
  v14_rehash(buf);
  EXPECT_EQ(crabs_deserialize_state(buf->data, buf->len), nullptr);

  serialized_buffer_destroy(buf);
  state_destroy(state);
}

// A SOVEREIGN tail whose writer string is empty must fail (the item would
// have no bound writer — DOMAIN_CHECK could never accept a write).
TEST(StateSerialize, V14RejectsSovereignEmptyWriter) {
  state_t* state = state_create();
  data_item_t* item = nullptr;
  data_item_options_t opts = {CRABS_DOMAIN_SOVEREIGN, "alice", 0};
  ASSERT_EQ(data_item_create_with_options("sov", DATA_TYPE_REGISTER, CRDT_LWW_REG,
                                          &opts, &item), CRABS_SUCCESS);
  state_add_item(state, item);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  size_t tail_offset = v14_find_tail_offset(state, buf, "sov");
  ASSERT_EQ(buf->data[tail_offset], (uint8_t)CRABS_DOMAIN_SOVEREIGN);
  // Shrink the string16 prefix to 0; the leftover "alice" bytes misalign the
  // rest of the parse, but the empty-writer gate fires first.
  buf->data[tail_offset + 1] = 0;
  buf->data[tail_offset + 2] = 0;
  v14_rehash(buf);
  EXPECT_EQ(crabs_deserialize_state(buf->data, buf->len), nullptr);

  serialized_buffer_destroy(buf);
  state_destroy(state);
}

// Consistency: item_seq == 0 exactly when item_digest is all-zero. Surgery
// in both directions must fail the load.
TEST(StateSerialize, V14RejectsSeqDigestMismatch) {
  for (int direction = 0; direction < 2; direction++) {
    state_t* state = state_create();
    data_item_t* item = nullptr;
    data_item_options_t opts = {CRABS_DOMAIN_SOVEREIGN, "alice", 0};
    ASSERT_EQ(data_item_create_with_options("sov", DATA_TYPE_REGISTER,
                                            CRDT_LWW_REG, &opts, &item),
              CRABS_SUCCESS);
    item->item_seq = 6;
    memset(item->item_digest, 0x5A, CRABS_HASH_SIZE);
    state_add_item(state, item);

    serialized_buffer_t* buf = crabs_serialize_state(state);
    ASSERT_NE(buf, nullptr);
    size_t tail_offset = v14_find_tail_offset(state, buf, "sov");
    size_t writer_len = strlen("alice");
    size_t seq_offset = tail_offset + 1 + 2 + writer_len;
    size_t digest_offset = seq_offset + 8;
    if (direction == 0) {
      memset(buf->data + seq_offset, 0, 8);        // seq 0, digest non-zero
    } else {
      memset(buf->data + digest_offset, 0, CRABS_HASH_SIZE);  // seq 6, digest zero
    }
    v14_rehash(buf);
    EXPECT_EQ(crabs_deserialize_state(buf->data, buf->len), nullptr)
        << "direction " << direction;

    serialized_buffer_destroy(buf);
    state_destroy(state);
  }
}

// fork_count is attacker-controlled: above CRABS_MAX_FORK_WRITERS the load
// fails (the in-memory fork set is inline and capped).
TEST(StateSerialize, V14RejectsForkCountOverCap) {
  state_t* state = state_create();
  data_item_t* item = nullptr;
  data_item_options_t opts = {CRABS_DOMAIN_SOVEREIGN, "alice", 0};
  ASSERT_EQ(data_item_create_with_options("sov", DATA_TYPE_REGISTER, CRDT_LWW_REG,
                                          &opts, &item), CRABS_SUCCESS);
  uint8_t evidence_digest[CRABS_HASH_SIZE];
  memset(evidence_digest, 0x11, CRABS_HASH_SIZE);
  ASSERT_EQ(state_append_fork_evidence(item, "mallory", evidence_digest),
            CRABS_SUCCESS);
  state_add_item(state, item);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  size_t tail_offset = v14_find_tail_offset(state, buf, "sov");
  size_t count_offset = tail_offset + 1 + 2 + strlen("alice") + 8 + CRABS_HASH_SIZE;
  ASSERT_EQ(buf->data[count_offset], 0x01);
  buf->data[count_offset] = CRABS_MAX_FORK_WRITERS + 1;
  v14_rehash(buf);
  EXPECT_EQ(crabs_deserialize_state(buf->data, buf->len), nullptr);

  serialized_buffer_destroy(buf);
  state_destroy(state);
}

// Same count channel, second bound: in-cap but unsatisfiable by the bytes
// actually remaining (each entry needs at least an empty string16 + 32
// digest bytes). The patched count is derived from the blob so this test
// exercises the remaining-bytes path, never the cap path.
TEST(StateSerialize, V14RejectsForkCountBeyondRemainingBytes) {
  state_t* state = state_create();
  data_item_t* item = nullptr;
  data_item_options_t opts = {CRABS_DOMAIN_SOVEREIGN, "alice", 0};
  ASSERT_EQ(data_item_create_with_options("sov", DATA_TYPE_REGISTER, CRDT_LWW_REG,
                                          &opts, &item), CRABS_SUCCESS);
  uint8_t evidence_digest[CRABS_HASH_SIZE];
  memset(evidence_digest, 0x22, CRABS_HASH_SIZE);
  ASSERT_EQ(state_append_fork_evidence(item, "m", evidence_digest), CRABS_SUCCESS);
  state_add_item(state, item);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  size_t tail_offset = v14_find_tail_offset(state, buf, "sov");
  size_t count_offset = tail_offset + 1 + 2 + strlen("alice") + 8 + CRABS_HASH_SIZE;
  ASSERT_EQ(buf->data[count_offset], 0x01);
  // After the count byte there are real bytes (one entry + later sections +
  // checksum); bound the count against exactly what remains.
  size_t entry_wire_min = 2 + CRABS_HASH_SIZE;
  size_t remaining = buf->len - (count_offset + 1);
  uint8_t patched_count = (uint8_t)(remaining / entry_wire_min + 1);
  ASSERT_LE(patched_count, CRABS_MAX_FORK_WRITERS)
      << "test no longer exercises the remaining-bytes bound";
  buf->data[count_offset] = patched_count;
  v14_rehash(buf);
  EXPECT_EQ(crabs_deserialize_state(buf->data, buf->len), nullptr);

  serialized_buffer_destroy(buf);
  state_destroy(state);
}

// Writer/reader lockstep (the writer never emits a blob its own reader
// rejects): inconsistent domain fields fail the serialize, not the load.
TEST(StateSerialize, V14WriterRefusesInconsistentDomainFields) {
  state_t* state = state_create();
  data_item_t* item = nullptr;
  data_item_options_t opts = {CRABS_DOMAIN_SOVEREIGN, "alice", 0};
  ASSERT_EQ(data_item_create_with_options("sov", DATA_TYPE_REGISTER, CRDT_LWW_REG,
                                          &opts, &item), CRABS_SUCCESS);
  state_add_item(state, item);

  // seq advanced but digest still zero.
  item->item_seq = 1;
  serialized_buffer_t* buf = crabs_serialize_state(state);
  EXPECT_EQ(buf, nullptr);
  if (buf != nullptr) serialized_buffer_destroy(buf);
  memset(item->item_digest, 0x5A, CRABS_HASH_SIZE);

  // seq rewound to 0 with a live digest.
  item->item_seq = 0;
  buf = crabs_serialize_state(state);
  EXPECT_EQ(buf, nullptr);
  if (buf != nullptr) serialized_buffer_destroy(buf);

  // Healthy again — control.
  item->item_seq = 3;
  buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  serialized_buffer_destroy(buf);

  // Over-cap fork count (above the inline array's wire allowance).
  item->fork_count = CRABS_MAX_FORK_WRITERS + 1;
  buf = crabs_serialize_state(state);
  EXPECT_EQ(buf, nullptr);
  if (buf != nullptr) serialized_buffer_destroy(buf);
  item->fork_count = 0;

  // Fork evidence on a non-sovereign item carries no wire home.
  item->write_domain = CRABS_DOMAIN_FREE_MERGE;
  uint8_t evidence_digest[CRABS_HASH_SIZE];
  memset(evidence_digest, 0x33, CRABS_HASH_SIZE);
  ASSERT_EQ(state_append_fork_evidence(item, "mallory", evidence_digest),
            CRABS_SUCCESS);
  buf = crabs_serialize_state(state);
  EXPECT_EQ(buf, nullptr);
  if (buf != nullptr) serialized_buffer_destroy(buf);

  // Sovereign chain fields (writer/seq/digest) without the fork set still
  // have no wire home on a non-sovereign item.
  item->fork_count = 0;
  item->fork_writers[0][0] = '\0';
  item->writer[0] = '\0';
  item->item_seq = 0;
  memset(item->item_digest, 0, CRABS_HASH_SIZE);
  buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr) << "zeroed domain fields serialize cleanly";
  serialized_buffer_destroy(buf);
  item->item_seq = 3;
  buf = crabs_serialize_state(state);
  EXPECT_EQ(buf, nullptr);
  if (buf != nullptr) serialized_buffer_destroy(buf);
  item->item_seq = 0;
  strncpy(item->writer, "alice", CRABS_MAX_USER_ID - 1);
  buf = crabs_serialize_state(state);
  EXPECT_EQ(buf, nullptr);
  if (buf != nullptr) serialized_buffer_destroy(buf);

  // Unterminated writer string: never reaches the wire (strlen-guard).
  item->write_domain = CRABS_DOMAIN_SOVEREIGN;
  memset(item->writer, 'x', CRABS_MAX_USER_ID);
  buf = crabs_serialize_state(state);
  EXPECT_EQ(buf, nullptr);
  if (buf != nullptr) serialized_buffer_destroy(buf);

  state_destroy(state);
}
