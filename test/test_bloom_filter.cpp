#include <gtest/gtest.h>
extern "C" {
#include "../src/Util/bloom_filter.h"
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/crypto.h"
#include "../src/Serialization/serialization.h"
#include "../src/CRDT/crdt_merge.h"
#include "../src/Util/allocator.h"
}

// ============================================================
// Bloom filter unit tests
// ============================================================

static uint8_t uuid_a[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                              0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
static uint8_t uuid_b[16] = {0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
                              0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20};
static uint8_t uuid_c[16] = {0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
                              0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30};

TEST(BloomFilter, AddAndContains) {
  crabs_bloom_filter_t bf;
  memset(&bf, 0, sizeof(bf));

  EXPECT_FALSE(crabs_bloom_contains(&bf, uuid_a));
  crabs_bloom_add(&bf, uuid_a);
  EXPECT_TRUE(crabs_bloom_contains(&bf, uuid_a));
  EXPECT_FALSE(crabs_bloom_contains(&bf, uuid_b));
}

TEST(BloomFilter, MultipleInserts) {
  crabs_bloom_filter_t bf;
  memset(&bf, 0, sizeof(bf));

  crabs_bloom_add(&bf, uuid_a);
  crabs_bloom_add(&bf, uuid_b);
  EXPECT_TRUE(crabs_bloom_contains(&bf, uuid_a));
  EXPECT_TRUE(crabs_bloom_contains(&bf, uuid_b));
  EXPECT_FALSE(crabs_bloom_contains(&bf, uuid_c));
  EXPECT_EQ(crabs_bloom_count(&bf), (size_t)2);
}

TEST(BloomFilter, Reset) {
  crabs_bloom_filter_t bf;
  memset(&bf, 0, sizeof(bf));

  crabs_bloom_add(&bf, uuid_a);
  EXPECT_TRUE(crabs_bloom_contains(&bf, uuid_a));
  crabs_bloom_reset(&bf);
  EXPECT_FALSE(crabs_bloom_contains(&bf, uuid_a));
  EXPECT_EQ(crabs_bloom_count(&bf), (size_t)0);
}

TEST(BloomFilter, NullParamsAreSafe) {
  crabs_bloom_filter_t bf;
  memset(&bf, 0, sizeof(bf));

  crabs_bloom_add(NULL, uuid_a);  // should not crash
  crabs_bloom_add(&bf, NULL);     // should not crash
  EXPECT_FALSE(crabs_bloom_contains(NULL, uuid_a));
  EXPECT_FALSE(crabs_bloom_contains(&bf, NULL));
  crabs_bloom_reset(NULL);        // should not crash
  EXPECT_EQ(crabs_bloom_count(NULL), (size_t)0);
}

TEST(BloomFilter, NoFalseNegatives) {
  // Insert 1000 UUIDs and verify all are found (no false negatives)
  crabs_bloom_filter_t bf;
  memset(&bf, 0, sizeof(bf));

  for (int i = 0; i < 1000; i++) {
    uint8_t uuid[16];
    memset(uuid, 0, 16);
    uuid[0] = (uint8_t)(i & 0xFF);
    uuid[1] = (uint8_t)((i >> 8) & 0xFF);
    crabs_bloom_add(&bf, uuid);
  }

  for (int i = 0; i < 1000; i++) {
    uint8_t uuid[16];
    memset(uuid, 0, 16);
    uuid[0] = (uint8_t)(i & 0xFF);
    uuid[1] = (uint8_t)((i >> 8) & 0xFF);
    EXPECT_TRUE(crabs_bloom_contains(&bf, uuid));
  }
}

// ============================================================
// Compaction safety integration tests
// ============================================================

class CompactionBloomIntegration : public ::testing::Test {
protected:
  state_t* state;
  attribute_machine_t* am;
  ecdsa_keypair_t* alice_key;

  void SetUp() override {
    state = state_create();

    // Add a 2P-Set data item (compactible type)
    data_item_t* set_item = data_item_create("test_set", DATA_TYPE_2P_SET, CRDT_2P_SET);
    two_p_set_t* set_val = two_p_set_create();
    two_p_set_add(set_val, "element_1");
    set_item->value = set_val;
    state_add_item(state, set_item);

    // Add a policy for a custom operation
    state_add_policy(state, "add_to_set", "role:admin");

    alice_key = crypto_ecdsa_generate();
    ASSERT_NE(alice_key, nullptr);

    uint8_t admin_pk[33];
    memset(admin_pk, 0xAA, 33);
    admin_pk[0] = 0x02;
    am = attribute_machine_create("admin", admin_pk);
    ASSERT_NE(am, nullptr);

    ASSERT_EQ(attribute_machine_register_user(am, "alice", alice_key->public_key, "role:admin"),
              CRABS_SUCCESS);
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

  operation_t* make_op(const char* type, const uint8_t uuid[16]) {
    operation_t* op = operation_create(type);
    memcpy(op->uuid, uuid, CRABS_UUID_SIZE);
    strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
    strncpy(op->node_id, "node1", CRABS_MAX_USER_ID - 1);
    op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
    strncpy(op->resources[0], "test_set", CRABS_MAX_USER_ID - 1);
    op->resource_count = 1;
    op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
    op->required_state[0] = PROTOCOL_IDLE;
    op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
    op->next_state[0] = PROTOCOL_IDLE;
    op->lamport_time = 1;

    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
    crypto_sign_operation(alice_key->private_key, ser->data, ser->len, op->signature);
    serialized_buffer_destroy(ser);
    return op;
  }
};

TEST_F(CompactionBloomIntegration, BloomPopulatedForCompactibleType) {
  // Initially no bloom filter
  EXPECT_EQ(state->compaction_bloom, nullptr);

  // Execute an operation on a 2P-Set (compactible type)
  operation_t* op = make_op("add_to_set", uuid_a);
  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);

  // Bloom filter should now exist and contain the UUID
  EXPECT_NE(state->compaction_bloom, nullptr);
  crabs_bloom_filter_t* bf = (crabs_bloom_filter_t*)state->compaction_bloom;
  EXPECT_TRUE(crabs_bloom_contains(bf, uuid_a));
}

TEST_F(CompactionBloomIntegration, ReplayOfCompactibleOpRejected) {
  // First execution succeeds
  operation_t* op1 = make_op("add_to_set", uuid_a);
  EXPECT_EQ(state_machine_execute(state, op1), CRABS_SUCCESS);
  operation_destroy(op1);

  // Second execution with same UUID is caught by idempotency check first
  // (processed_ops array), which returns CRABS_SUCCESS. But if we bypass
  // that by using a fresh state without the processed_ops entry, the bloom
  // filter should catch it.
  //
  // Create a second state with the bloom filter pre-populated
  state_t* state2 = state_create();
  data_item_t* set2 = data_item_create("test_set", DATA_TYPE_2P_SET, CRDT_2P_SET);
  two_p_set_t* sv2 = two_p_set_create();
  two_p_set_add(sv2, "element_1");
  set2->value = sv2;
  state_add_item(state2, set2);
  state_add_policy(state2, "add_to_set", "role:admin");
  state2->attr_machine = am;

  ecdsa_keypair_t* nk2 = crypto_ecdsa_generate();
  state_set_node_key(state2, nk2->private_key, nk2->public_key);
  crypto_ecdsa_keypair_destroy(nk2);

  // Pre-populate the bloom filter with uuid_a
  state2->compaction_bloom = get_clear_memory(sizeof(crabs_bloom_filter_t));
  crabs_bloom_add((crabs_bloom_filter_t*)state2->compaction_bloom, uuid_a);

  // Now execute an op with uuid_a on state2 — should be rejected by bloom
  operation_t* op2 = make_op("add_to_set", uuid_a);
  EXPECT_EQ(state_machine_execute(state2, op2), CRABS_ERR_ALREADY_EXECUTED);
  operation_destroy(op2);
  state_destroy(state2);
}

TEST_F(CompactionBloomIntegration, NonCompactibleTypeSkipsBloom) {
  // Add a G-Counter (non-compactible type)
  data_item_t* ctr = data_item_create("test_ctr", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  int64_t* cv = (int64_t*)malloc(sizeof(int64_t));
  *cv = 0;
  ctr->value = cv;
  state_add_item(state, ctr);
  state_add_policy(state, "inc_counter", "role:admin");

  // Execute an operation on a G-Counter
  operation_t* op = make_op("inc_counter", uuid_a);
  op->resources[0][0] = '\0';
  strncpy(op->resources[0], "test_ctr", CRABS_MAX_USER_ID - 1);
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  crypto_sign_operation(alice_key->private_key, ser->data, ser->len, op->signature);
  serialized_buffer_destroy(ser);

  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);

  // Bloom filter should NOT have been created (non-compactible type)
  EXPECT_EQ(state->compaction_bloom, nullptr);
}
