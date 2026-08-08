#include <gtest/gtest.h>
extern "C" {
#include "../src/TxManager/tx_manager.h"
#include "../src/TxManager/tx_manager_memory.h"
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/crypto.h"
#include "../src/Serialization/serialization.h"
#include "../src/Util/allocator.h"
}

// ============================================================
// None tx_manager tests
// ============================================================

TEST(TxManagerNone, AcceptAlwaysReturnsSuccess) {
  crabs_tx_manager_t* tx = crabs_tx_manager_none();
  ASSERT_NE(tx, nullptr);
  EXPECT_STREQ(tx->vtable.name, "none");

  state_t* state = state_create();
  operation_t* op = operation_create("test");

  // Should always accept
  EXPECT_EQ(tx->vtable.accept(tx, state, op), CRABS_SUCCESS);
  // Second time should also accept (no tracking)
  EXPECT_EQ(tx->vtable.accept(tx, state, op), CRABS_SUCCESS);

  operation_destroy(op);
  state_destroy(state);
  tx->vtable.destroy(tx);
}

TEST(TxManagerNone, CommitAndDestroyAreNoops) {
  crabs_tx_manager_t* tx = crabs_tx_manager_none();
  state_t* state = state_create();
  operation_t* op = operation_create("test");

  // Should not crash
  tx->vtable.commit(tx, state, op);
  tx->vtable.destroy(tx);

  operation_destroy(op);
  state_destroy(state);
}

// ============================================================
// Memory tx_manager tests
// ============================================================

TEST(TxManagerMemory, AcceptNewAndRejectDuplicate) {
  crabs_tx_manager_t* tx = crabs_tx_manager_memory(64);
  ASSERT_NE(tx, nullptr);
  EXPECT_STREQ(tx->vtable.name, "memory");

  state_t* state = state_create();
  operation_t* op = operation_create("test");
  // Give it a real UUID
  memset(op->uuid, 0x42, 16);

  // First time: accept
  EXPECT_EQ(tx->vtable.accept(tx, state, op), CRABS_SUCCESS);
  tx->vtable.commit(tx, state, op);

  // Second time: reject
  EXPECT_EQ(tx->vtable.accept(tx, state, op), CRABS_ERR_ALREADY_EXECUTED);

  operation_destroy(op);
  state_destroy(state);
  tx->vtable.destroy(tx);
}

TEST(TxManagerMemory, DifferentUuidsAreAccepted) {
  crabs_tx_manager_t* tx = crabs_tx_manager_memory(64);
  state_t* state = state_create();

  for (int i = 0; i < 100; i++) {
    operation_t* op = operation_create("test");
    op->uuid[0] = (uint8_t)(i & 0xFF);
    op->uuid[1] = (uint8_t)((i >> 8) & 0xFF);

    EXPECT_EQ(tx->vtable.accept(tx, state, op), CRABS_SUCCESS);
    tx->vtable.commit(tx, state, op);
    operation_destroy(op);
  }

  state_destroy(state);
  tx->vtable.destroy(tx);
}

TEST(TxManagerMemory, LargeScaleNoFalseNegatives) {
  // Insert 10000 UUIDs and verify all are rejected on second attempt
  crabs_tx_manager_t* tx = crabs_tx_manager_memory(1024);
  state_t* state = state_create();

  for (int i = 0; i < 10000; i++) {
    operation_t* op = operation_create("test");
    op->uuid[0] = (uint8_t)(i & 0xFF);
    op->uuid[1] = (uint8_t)((i >> 8) & 0xFF);
    op->uuid[2] = (uint8_t)((i >> 16) & 0xFF);

    EXPECT_EQ(tx->vtable.accept(tx, state, op), CRABS_SUCCESS);
    tx->vtable.commit(tx, state, op);
    operation_destroy(op);
  }

  // Replay all 10000 — all should be rejected
  for (int i = 0; i < 10000; i++) {
    operation_t* op = operation_create("test");
    op->uuid[0] = (uint8_t)(i & 0xFF);
    op->uuid[1] = (uint8_t)((i >> 8) & 0xFF);
    op->uuid[2] = (uint8_t)((i >> 16) & 0xFF);

    EXPECT_EQ(tx->vtable.accept(tx, state, op), CRABS_ERR_ALREADY_EXECUTED);
    operation_destroy(op);
  }

  state_destroy(state);
  tx->vtable.destroy(tx);
}

// ============================================================
// Integration: tx_manager wired to state_machine_execute
// ============================================================

class TxManagerIntegration : public ::testing::Test {
protected:
  state_t* state;
  attribute_machine_t* am;
  ecdsa_keypair_t* alice_key;

  static crabs_error_e noop_handler(state_t* s, operation_t* o) {
    (void)s;
    (void)o;
    return CRABS_SUCCESS;
  }

  void SetUp() override {
    state = state_create();

    data_item_t* res = data_item_create("test_resource", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
    int64_t* val = (int64_t*)malloc(sizeof(int64_t));
    *val = 0;
    res->value = val;
    state_add_item(state, res);

    state_add_policy(state, "transfer", "role:admin");
    state_machine_register_handler(state, "transfer", noop_handler);

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

  operation_t* make_op(const uint8_t uuid[16]) {
    operation_t* op = operation_create("transfer");
    memcpy(op->uuid, uuid, CRABS_UUID_SIZE);
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

    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
    crypto_sign_operation(alice_key->private_key, ser->data, ser->len, op->signature);
    serialized_buffer_destroy(ser);
    return op;
  }
};

TEST_F(TxManagerIntegration, NoTxManagerAcceptsAll) {
  // NULL tx_manager = accept everything (backward compatible)
  uint8_t uuid[16];
  memset(uuid, 0xAB, 16);

  operation_t* op = make_op(uuid);
  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);

  // Same UUID again — accepted (no tx_manager to reject)
  op = make_op(uuid);
  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);
}

TEST_F(TxManagerIntegration, MemoryTxManagerRejectsDuplicate) {
  state->tx_manager = crabs_tx_manager_memory(64);

  uint8_t uuid[16];
  memset(uuid, 0xCD, 16);

  operation_t* op = make_op(uuid);
  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);

  // Same UUID — rejected by tx_manager
  op = make_op(uuid);
  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_ALREADY_EXECUTED);
  operation_destroy(op);
}

TEST_F(TxManagerIntegration, MemoryTxManagerDifferentUuidsBothAccepted) {
  state->tx_manager = crabs_tx_manager_memory(64);

  uint8_t uuid1[16], uuid2[16];
  memset(uuid1, 0x11, 16);
  memset(uuid2, 0x22, 16);

  operation_t* op1 = make_op(uuid1);
  EXPECT_EQ(state_machine_execute(state, op1), CRABS_SUCCESS);
  operation_destroy(op1);

  operation_t* op2 = make_op(uuid2);
  EXPECT_EQ(state_machine_execute(state, op2), CRABS_SUCCESS);
  operation_destroy(op2);
}
