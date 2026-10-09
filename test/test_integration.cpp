//
// Integration tests covering the full CRABS protocol lifecycle.
//

#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>

extern "C" {
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/CRDT/crdt_merge.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/crypto.h"
#include "../src/Serialization/serialization.h"
#include "../src/Condition/condition.h"
#include "../src/Trigger/trigger.h"
#include "test_helpers.h"
}

// ============================================================
// Test Fixture
// ============================================================

class TestIntegration : public ::testing::Test {
protected:
  void SetUp() override {}
  void TearDown() override {}
};

// ============================================================
// 1. Full Lock-Modify-Verify-Unlock Lifecycle
// ============================================================

TEST_F(TestIntegration, LockModifyVerifyUnlock) {
  // Use the shared test env: real admin keypair, attribute machine, policies.
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  state_t* state = env.state;

  // Register alice with a real keypair and role:admin so she can sign.
  ecdsa_keypair_t* alice_key = crypto_ecdsa_generate();
  ASSERT_NE(alice_key, nullptr);
  ASSERT_EQ(crabs_test_register_user_with_role(state->attr_machine, "alice",
                                               alice_key->public_key,
                                               "role", "admin"), CRABS_SUCCESS);

  data_item_t* res = data_item_create("resource1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  ASSERT_NE(res, nullptr);
  int64_t* val = (int64_t*)malloc(sizeof(int64_t));
  *val = 100;
  res->value = val;
  state_add_item(state, res);

  uint8_t uuid1[CRABS_UUID_SIZE];
  memset(uuid1, 0x01, CRABS_UUID_SIZE);

  // Lock the resource
  operation_t* lock_op = operation_create(CRABS_OP_LOCK);
  memcpy(lock_op->uuid, uuid1, CRABS_UUID_SIZE);
  lock_op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(lock_op->resources[0], "resource1", CRABS_MAX_USER_ID - 1);
  lock_op->resource_count = 1;
  lock_op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  lock_op->required_state[0] = PROTOCOL_IDLE;
  lock_op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  lock_op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(lock_op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(state->attr_machine, alice_key,lock_op);

  crabs_error_e result = state_machine_execute(state, lock_op);
  EXPECT_EQ(result, CRABS_SUCCESS);
  operation_destroy(lock_op);

  data_item_t* item = state_find_item(state, "resource1");
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->protocol_state, PROTOCOL_LOCKED);
  EXPECT_TRUE(item->lock_state.lock_token_valid);

  // Modify the value
  *(int64_t*)item->value = 200;
  item->protocol_state = PROTOCOL_MODIFIED;

  // Verify invariants (non-negative value)
  EXPECT_EQ(*(int64_t*)item->value, 200);

  // Verify
  uint8_t uuid2[CRABS_UUID_SIZE];
  memset(uuid2, 0x02, CRABS_UUID_SIZE);
  operation_t* verify_op = operation_create(CRABS_OP_VERIFY);
  memcpy(verify_op->uuid, uuid2, CRABS_UUID_SIZE);
  verify_op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(verify_op->resources[0], "resource1", CRABS_MAX_USER_ID - 1);
  verify_op->resource_count = 1;
  verify_op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  verify_op->required_state[0] = PROTOCOL_MODIFIED;
  verify_op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  verify_op->next_state[0] = PROTOCOL_VERIFIED;
  verify_op->lock_claims = (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(verify_op->lock_claims[0].resource, "resource1", CRABS_MAX_USER_ID - 1);
  memcpy(verify_op->lock_claims[0].lock_token, item->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE);
  verify_op->lock_claim_count = 1;
  strncpy(verify_op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(state->attr_machine, alice_key,verify_op);

  result = state_machine_execute(state, verify_op);
  EXPECT_EQ(result, CRABS_SUCCESS);
  EXPECT_EQ(item->protocol_state, PROTOCOL_VERIFIED);
  operation_destroy(verify_op);

  // Unlock
  uint8_t uuid3[CRABS_UUID_SIZE];
  memset(uuid3, 0x03, CRABS_UUID_SIZE);
  operation_t* unlock_op = operation_create(CRABS_OP_UNLOCK);
  memcpy(unlock_op->uuid, uuid3, CRABS_UUID_SIZE);
  unlock_op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(unlock_op->resources[0], "resource1", CRABS_MAX_USER_ID - 1);
  unlock_op->resource_count = 1;
  unlock_op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  unlock_op->required_state[0] = PROTOCOL_VERIFIED;
  unlock_op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  unlock_op->next_state[0] = PROTOCOL_IDLE;
  unlock_op->lock_claims = (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(unlock_op->lock_claims[0].resource, "resource1", CRABS_MAX_USER_ID - 1);
  memcpy(unlock_op->lock_claims[0].lock_token, item->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE);
  unlock_op->lock_claim_count = 1;
  strncpy(unlock_op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(state->attr_machine, alice_key,unlock_op);

  result = state_machine_execute(state, unlock_op);
  EXPECT_EQ(result, CRABS_SUCCESS);
  operation_destroy(unlock_op);

  // Assert value changed and lock is released
  item = state_find_item(state, "resource1");
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(*(int64_t*)item->value, 200);
  EXPECT_EQ(item->protocol_state, PROTOCOL_IDLE);
  EXPECT_FALSE(item->lock_state.lock_token_valid);

  crypto_ecdsa_keypair_destroy(alice_key);
  crabs_test_env_destroy(&env);
}

// ============================================================
// 2. CRDT Merge Between Replicas
// ============================================================

TEST_F(TestIntegration, CRDTMergeBetweenReplicas) {
  // Create two states with G-Counter items
  state_t* state_a = state_create();
  state_t* state_b = state_create();
  ASSERT_NE(state_a, nullptr);
  ASSERT_NE(state_b, nullptr);

  // State A: counter on nodeA=5, nodeB=3
  data_item_t* item_a = data_item_create("visits", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc_a = g_counter_create();
  g_counter_increment(gc_a, "nodeA", 5);
  g_counter_increment(gc_a, "nodeB", 3);
  item_a->value = gc_a;
  state_add_item(state_a, item_a);

  // State B: counter on nodeB=7, nodeC=2
  data_item_t* item_b = data_item_create("visits", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc_b = g_counter_create();
  g_counter_increment(gc_b, "nodeB", 7);
  g_counter_increment(gc_b, "nodeC", 2);
  item_b->value = gc_b;
  state_add_item(state_b, item_b);

  // Set versions to test merge takes max
  state_a->version = 5;
  state_b->version = 10;

  // Merge state_b into state_a
  crabs_error_e err = crdt_merge_state(state_a, state_b);
  EXPECT_EQ(err, CRABS_SUCCESS);

  // Assert merged value equals sum of all increments: max(5,0)+max(3,7)+max(0,2) = 5+7+2 = 14
  data_item_t* merged_item = state_find_item(state_a, "visits");
  ASSERT_NE(merged_item, nullptr);
  g_counter_t* merged_gc = (g_counter_t*)merged_item->value;
  EXPECT_EQ(g_counter_value(merged_gc), 14);

  // Assert version is max(5, 10) = 10
  EXPECT_EQ(state_a->version, 10u);

  for (data_item_t* it = state_a->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  for (data_item_t* it = state_b->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state_a);
  state_destroy(state_b);
}

// ============================================================
// 3. Attribute Machine Lifecycle
// ============================================================

TEST_F(TestIntegration, AttributeMachineLifecycle) {
  // Create attribute machine with admin (audit N-3: real generated keys)
  uint8_t admin_pk[33];
  ecdsa_keypair_t* admin_kp = crypto_ecdsa_generate();
  ASSERT_NE(admin_kp, nullptr);
  memcpy(admin_pk, admin_kp->public_key, 33);
  crypto_ecdsa_keypair_destroy(admin_kp);
  attribute_machine_t* am = attribute_machine_create("admin", admin_pk);
  ASSERT_NE(am, nullptr);
  EXPECT_EQ(am->user_count, 1u);

  // Register a user
  uint8_t user_pk[33];
  ecdsa_keypair_t* kp = crypto_ecdsa_generate();
  ASSERT_NE(kp, nullptr);
  memcpy(user_pk, kp->public_key, 33);
  crypto_ecdsa_keypair_destroy(kp);
  crabs_error_e result = attribute_machine_register_user(am, "alice", user_pk, "dept:eng");
  EXPECT_EQ(result, CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->status, USER_ACTIVE);
  EXPECT_EQ(alice->attribute_count, 1u);

  // Grant a role
  result = attribute_machine_grant_role(am, "alice", "role", "editor", "admin");
  EXPECT_EQ(result, CRABS_SUCCESS);

  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_TRUE(attribute_machine_user_has_role(alice, "role"));
  EXPECT_TRUE(attribute_machine_user_has_role(alice, "dept"));

  attribute_value_t* role_attr = attribute_machine_find_attribute(alice, "role");
  ASSERT_NE(role_attr, nullptr);
  EXPECT_STREQ(role_attr->value, "role:editor");
  EXPECT_STREQ(role_attr->verified_by, "admin");

  // Self-assert an attribute
  result = attribute_machine_self_assert(am, "email", "alice@example.com", "alice");
  EXPECT_EQ(result, CRABS_SUCCESS);

  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  attribute_value_t* email_attr = attribute_machine_find_attribute(alice, "email");
  ASSERT_NE(email_attr, nullptr);
  EXPECT_STREQ(email_attr->value, "email:alice@example.com");
  EXPECT_STREQ(email_attr->verified_by, "");  // self-asserted

  // Verify identity
  result = attribute_machine_verify_identity(am, "alice", "email", "alice@verified.com", "admin");
  EXPECT_EQ(result, CRABS_SUCCESS);

  alice = attribute_machine_find_user(am, "alice");
  email_attr = attribute_machine_find_attribute(alice, "email");
  ASSERT_NE(email_attr, nullptr);
  EXPECT_STREQ(email_attr->value, "email:alice@verified.com");
  EXPECT_STREQ(email_attr->verified_by, "admin");

  // Revoke the role
  result = attribute_machine_revoke_role(am, "alice", "role", "admin");
  EXPECT_EQ(result, CRABS_SUCCESS);

  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_FALSE(attribute_machine_user_has_role(alice, "role"));

  // Suspend user
  result = attribute_machine_suspend_user(am, "alice", "admin");
  EXPECT_EQ(result, CRABS_SUCCESS);

  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->status, USER_SUSPENDED);

  // Register new user after suspend check — suspended user cannot be granted roles
  result = attribute_machine_grant_role(am, "alice", "role", "viewer", "admin");
  EXPECT_EQ(result, CRABS_ERR_USER_SUSPENDED);

  attribute_machine_destroy(am);
}

// ============================================================
// 4. Threshold Trigger Fire
// ============================================================

TEST_F(TestIntegration, ThresholdTriggerFire) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  // Create a counter data item
  data_item_t* counter = data_item_create("counter", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 5);
  counter->value = gc;
  state_add_item(state, counter);

  // Create a trigger with condition "counter >= 10"
  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_CHANGE_POLICY;
  strncpy(effect.policy_operation, "__threshold__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect.policy_expression, "threshold_reached", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("thresh1", "Counter threshold",
    "counter >= 10", &effect, 0, false, "admin");
  ASSERT_NE(trigger, nullptr);

  // Add trigger to state
  state->trigger_count = 1;
  state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
  state->triggers[0] = *trigger;
  free(trigger);

  // Set counter value to 5, process triggers — should NOT fire
  uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
  EXPECT_EQ(fired, 0u);
  EXPECT_EQ(state->triggers[0].last_triggered_at, 0u);

  // Verify policy was NOT added
  const char* policy = state_find_policy(state, "__threshold__");
  EXPECT_EQ(policy, nullptr);

  // Set counter value to 10 by incrementing further
  data_item_t* item = state_find_item(state, "counter");
  ASSERT_NE(item, nullptr);
  g_counter_t* gc_item = (g_counter_t*)item->value;
  g_counter_increment(gc_item, "nodeA", 5);
  EXPECT_EQ(g_counter_value(gc_item), 10);

  // Process triggers — should fire
  fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 2000);
  EXPECT_EQ(fired, 1u);
  EXPECT_EQ(state->triggers[0].last_triggered_at, 2000u);

  // Verify the trigger fired (policy was added)
  policy = state_find_policy(state, "__threshold__");
  ASSERT_NE(policy, nullptr);
  EXPECT_STREQ(policy, "threshold_reached");

  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}

// ============================================================
// 5. Serialization Round-Trip
// ============================================================

TEST_F(TestIntegration, SerializationRoundTrip) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  state->version = 42;
  state->config.max_lock_duration_ms = 10000;
  state->config.max_lock_extensions = 5;
  state->config.allow_force_unlock = false;
  strncpy(state->config.bootstrap_admin, "admin_user", CRABS_MAX_USER_ID - 1);

  // Add items
  data_item_t* item1 = data_item_create("counter1", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* counter1 = g_counter_create();
  ASSERT_EQ(g_counter_increment(counter1, "node1", 12345), CRABS_SUCCESS);
  item1->value = counter1;
  state_add_item(state, item1);

  data_item_t* item2 = data_item_create("resource1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* val2 = (int64_t*)malloc(sizeof(int64_t));
  *val2 = 999;
  item2->value = val2;
  item2->protocol_state = PROTOCOL_LOCKED;
  state_add_item(state, item2);

  // Add invariants
  invariant_t* invs = (invariant_t*)malloc(sizeof(invariant_t));
  invs[0].type = INVARIANT_GREATER_THAN;
  invs[0].param = 0;
  invs[0].error_message = strdup("must be positive");
  item1->invariants = invs;
  item1->invariant_count = 1;

  // Add policies
  state_add_policy(state, CRABS_OP_LOCK, "role:admin");
  state_add_policy(state, CRABS_OP_UNLOCK, "role:admin");

  // Serialize
  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  EXPECT_GT(buf->len, (size_t)0);

  // Deserialize
  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  // Verify all fields match
  EXPECT_EQ(restored->version, 42u);

  // Verify item names/values
  data_item_t* r_item1 = state_find_item(restored, "counter1");
  ASSERT_NE(r_item1, nullptr);
  EXPECT_EQ(r_item1->type, DATA_TYPE_COUNTER);
  EXPECT_EQ(r_item1->crdt_type, CRDT_G_COUNTER);
  EXPECT_EQ(g_counter_value((g_counter_t*)r_item1->value), (int64_t)12345);
  EXPECT_EQ(r_item1->invariant_count, (uint32_t)1);
  EXPECT_EQ(r_item1->invariants[0].type, INVARIANT_GREATER_THAN);

  data_item_t* r_item2 = state_find_item(restored, "resource1");
  ASSERT_NE(r_item2, nullptr);
  EXPECT_EQ(r_item2->type, DATA_TYPE_RESOURCE);
  EXPECT_EQ(r_item2->crdt_type, CRDT_PN_COUNTER);
  EXPECT_EQ(*(int64_t*)r_item2->value, (int64_t)999);
  EXPECT_EQ(r_item2->protocol_state, PROTOCOL_LOCKED);

  // Verify policy count
  EXPECT_EQ(restored->policy_count, (uint32_t)2);

  // Verify config values
  EXPECT_EQ(restored->config.max_lock_duration_ms, (uint64_t)10000);
  EXPECT_EQ(restored->config.max_lock_extensions, (uint32_t)5);
  EXPECT_EQ(restored->config.allow_force_unlock, false);
  EXPECT_STREQ(restored->config.bootstrap_admin, "admin_user");

  free((void*)invs[0].error_message);
  serialized_buffer_destroy(buf);
  // item1's value is struct-backed: data_item_destroy's default free() arm
  // releases only the g_counter shell (no counter destroy case — pre-existing
  // gap), so release it properly first. item2 (RESOURCE) keeps the raw int64
  // representation state_destroy handles.
  g_counter_destroy((g_counter_t*)state_find_item(state, "counter1")->value);
  state_find_item(state, "counter1")->value = nullptr;
  g_counter_destroy((g_counter_t*)state_find_item(restored, "counter1")->value);
  state_find_item(restored, "counter1")->value = nullptr;
  state_destroy(state);
  state_destroy(restored);
}

// ============================================================
// 6. Crypto Sign and Verify
// ============================================================

TEST_F(TestIntegration, CryptoSignAndVerify) {
  // Generate ECDSA keypair
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  ASSERT_NE(keypair, nullptr);

  // Sign a message
  const uint8_t message[] = "CRABS protocol integration test message";
  uint8_t signature[CRABS_SIG_SIZE];

  crabs_error_e rc = crypto_ecdsa_sign(keypair->private_key, message, sizeof(message), signature);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Verify with correct public key — true
  bool valid = crypto_ecdsa_verify(keypair->public_key, message, sizeof(message), signature);
  EXPECT_TRUE(valid);

  // Verify with wrong public key — false
  ecdsa_keypair_t* wrong_keypair = crypto_ecdsa_generate();
  ASSERT_NE(wrong_keypair, nullptr);
  valid = crypto_ecdsa_verify(wrong_keypair->public_key, message, sizeof(message), signature);
  EXPECT_FALSE(valid);

  // SHA-256 hash consistency
  uint8_t hash1[CRABS_HASH_SIZE];
  uint8_t hash2[CRABS_HASH_SIZE];
  rc = crypto_sha256(message, sizeof(message), hash1);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  rc = crypto_sha256(message, sizeof(message), hash2);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  // Same input produces same hash
  EXPECT_EQ(memcmp(hash1, hash2, CRABS_HASH_SIZE), 0);

  // Different input produces different hash
  const uint8_t other_message[] = "Different message entirely";
  uint8_t hash3[CRABS_HASH_SIZE];
  rc = crypto_sha256(other_message, sizeof(other_message), hash3);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_NE(memcmp(hash1, hash3, CRABS_HASH_SIZE), 0);

  crypto_ecdsa_keypair_destroy(keypair);
  crypto_ecdsa_keypair_destroy(wrong_keypair);
}

// ============================================================
// 7. Key Version Verification
// ============================================================

TEST_F(TestIntegration, KeyVersionVerification) {
  // Create state with attr_machine
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  data_item_t* res = data_item_create("resource1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* val = (int64_t*)malloc(sizeof(int64_t));
  *val = 50;
  res->value = val;
  state_add_item(state, res);

  state_add_policy(state, CRABS_OP_LOCK, "role:admin");
  state_add_policy(state, CRABS_OP_UNLOCK, "role:admin");

  // Generate ECDSA keypair for alice
  ecdsa_keypair_t* alice_key = crypto_ecdsa_generate();
  ASSERT_NE(alice_key, nullptr);

  // Set up attribute machine with alice registered with real key and role:admin
  uint8_t admin_pk[33];
  ecdsa_keypair_t* admin_kp2 = crypto_ecdsa_generate();
  ASSERT_NE(admin_kp2, nullptr);
  memcpy(admin_pk, admin_kp2->public_key, 33);
  crypto_ecdsa_keypair_destroy(admin_kp2);
  attribute_machine_t* am = attribute_machine_create("admin", admin_pk);
  ASSERT_NE(am, nullptr);

  crabs_error_e reg_rc = crabs_test_register_user_with_role(
      am, "alice", alice_key->public_key, "role", "admin");
  ASSERT_EQ(reg_rc, CRABS_SUCCESS);

  // Set alice's key_version to 3
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  alice->key_version = 3;

  state->attr_machine = am;

  // Helper to sign an operation. R7-11: Lamport monotonicity is enforced per
  // signer, so each op must carry a strictly increasing lamport_time.
  uint64_t lamport_counter = 0;
  auto sign_op = [&](operation_t* op) {
    op->lamport_time = ++lamport_counter;
    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
    if (ser) {
      crypto_sign_operation(alice_key->private_key, ser->data, ser->len, op->signature);
      serialized_buffer_destroy(ser);
    }
  };

  // Execute operation with correct key version — SUCCESS
  uint8_t uuid1[CRABS_UUID_SIZE];
  memset(uuid1, 0x01, CRABS_UUID_SIZE);
  operation_t* op1 = operation_create(CRABS_OP_LOCK);
  memcpy(op1->uuid, uuid1, CRABS_UUID_SIZE);
  op1->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op1->resources[0], "resource1", CRABS_MAX_USER_ID - 1);
  op1->resource_count = 1;
  op1->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op1->required_state[0] = PROTOCOL_IDLE;
  op1->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op1->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op1->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op1->signer_key_version = 3;  // correct version
  sign_op(op1);

  crabs_error_e result = state_machine_execute(state, op1);
  EXPECT_EQ(result, CRABS_SUCCESS);
  operation_destroy(op1);

  // Unlock to reset state for next test
  data_item_t* item = state_find_item(state, "resource1");
  ASSERT_NE(item, nullptr);
  item->protocol_state = PROTOCOL_IDLE;
  item->lock_state.lock_token_valid = false;

  // Execute operation with wrong key version — KEY_STALE
  uint8_t uuid2[CRABS_UUID_SIZE];
  memset(uuid2, 0x02, CRABS_UUID_SIZE);
  operation_t* op2 = operation_create(CRABS_OP_LOCK);
  memcpy(op2->uuid, uuid2, CRABS_UUID_SIZE);
  op2->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op2->resources[0], "resource1", CRABS_MAX_USER_ID - 1);
  op2->resource_count = 1;
  op2->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op2->required_state[0] = PROTOCOL_IDLE;
  op2->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op2->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op2->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op2->signer_key_version = 1;  // stale version
  sign_op(op2);

  result = state_machine_execute(state, op2);
  EXPECT_EQ(result, CRABS_ERR_KEY_STALE);
  operation_destroy(op2);

  // Execute operation with key_version=0 — R7-04: the bypass is closed, so a
  // signer with a nonzero key_version can no longer skip the staleness check.
  uint8_t uuid3[CRABS_UUID_SIZE];
  memset(uuid3, 0x03, CRABS_UUID_SIZE);
  operation_t* op3 = operation_create(CRABS_OP_LOCK);
  memcpy(op3->uuid, uuid3, CRABS_UUID_SIZE);
  op3->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op3->resources[0], "resource1", CRABS_MAX_USER_ID - 1);
  op3->resource_count = 1;
  op3->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op3->required_state[0] = PROTOCOL_IDLE;
  op3->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op3->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op3->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  op3->signer_key_version = 0;  // stale version
  sign_op(op3);

  result = state_machine_execute(state, op3);
  EXPECT_EQ(result, CRABS_ERR_KEY_STALE);
  operation_destroy(op3);

  state->attr_machine = NULL;
  attribute_machine_destroy(am);
  crypto_ecdsa_keypair_destroy(alice_key);
  state_destroy(state);
}

// ============================================================
// 8. Condition Evaluation Integration
// ============================================================

TEST_F(TestIntegration, ConditionEvaluation) {
  // Parse condition "resource1.flags >= 5 AND resource2.score <= 100"
  condition_node_t* cond = condition_parse("resource1.flags >= 5 AND resource2.score <= 100");
  ASSERT_NE(cond, nullptr);
  EXPECT_EQ(cond->type, NODE_AND);

  // Create state with resource1.flags = 10 and resource2.score = 50
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);

  data_item_t* flags = data_item_create("resource1.flags", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc_flags = g_counter_create();
  g_counter_increment(gc_flags, "nodeA", 10);
  flags->value = gc_flags;
  state_add_item(state, flags);

  data_item_t* score = data_item_create("resource2.score", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc_score = g_counter_create();
  g_counter_increment(gc_score, "nodeA", 50);
  score->value = gc_score;
  state_add_item(state, score);

  // Evaluate — true (10 >= 5 AND 50 <= 100)
  bool result = condition_evaluate(cond, state);
  EXPECT_TRUE(result);

  // Change resource2.score to 150
  data_item_t* score_item = state_find_item(state, "resource2.score");
  ASSERT_NE(score_item, nullptr);
  g_counter_t* gc = (g_counter_t*)score_item->value;
  // Increment by 100 to make total 150
  g_counter_increment(gc, "nodeA", 100);
  EXPECT_EQ(g_counter_value(gc), 150);

  // Evaluate — false (10 >= 5 AND 150 <= 100 is false)
  result = condition_evaluate(cond, state);
  EXPECT_FALSE(result);

  condition_node_destroy(cond);
  for (data_item_t* it = state->items; it != NULL; it = it->next) {
    if (it->value != NULL) { crdt_value_destroy(it->crdt_type, it->value); it->value = NULL; }
  }
  state_destroy(state);
}