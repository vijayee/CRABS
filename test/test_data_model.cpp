//
// CRABS-44: Core Data Model Tests
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/crypto.h"
#include "../src/Serialization/serialization.h"
#include "test_helpers.h"
}

// ============================================================
// State Creation & Defaults
// ============================================================

TEST(TestDataModel, StateCreateDefaults) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  EXPECT_EQ(state->version, (uint64_t)0);
  EXPECT_EQ(state->items, nullptr);
  EXPECT_EQ(state->policies, nullptr);
  EXPECT_EQ(state->policy_count, (uint32_t)0);
  EXPECT_EQ(state->log, nullptr);
  EXPECT_EQ(state->log_count, (uint64_t)0);
  EXPECT_EQ(state->tx_manager, nullptr);
  EXPECT_EQ(state->triggers, nullptr);
  EXPECT_EQ(state->trigger_count, (uint32_t)0);
  EXPECT_EQ(state->attr_machine, nullptr);
  EXPECT_EQ(state->node_key_valid, false);
  EXPECT_EQ(state->last_refresh_envelope, nullptr);
  state_destroy(state);
}

TEST(TestDataModel, StateDestroyNull) {
  state_destroy(nullptr);
}

TEST(TestDataModel, StateConfigDefaults) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  EXPECT_EQ(state->config.max_lock_duration_ms, (uint64_t)CRABS_DEFAULT_LOCK_MS);
  EXPECT_EQ(state->config.max_lock_extensions, (uint32_t)CRABS_MAX_LOCK_EXTENDS);
  EXPECT_EQ(state->config.allow_force_unlock, true);
  EXPECT_STREQ(state->config.bootstrap_admin, "");
  state_destroy(state);
}

// ============================================================
// DataItem Creation & Destruction
// ============================================================

TEST(TestDataModel, DataItemCreateBasic) {
  data_item_t* item = data_item_create("test_counter", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  ASSERT_NE(item, nullptr);
  EXPECT_STREQ(item->name, "test_counter");
  EXPECT_EQ(item->type, DATA_TYPE_COUNTER);
  EXPECT_EQ(item->crdt_type, CRDT_G_COUNTER);
  EXPECT_EQ(item->protocol_state, PROTOCOL_IDLE);
  EXPECT_EQ(item->value, nullptr);
  EXPECT_EQ(item->invariants, nullptr);
  EXPECT_EQ(item->invariant_count, (uint32_t)0);
  EXPECT_EQ(item->next, nullptr);
  data_item_destroy(item);
}

TEST(TestDataModel, DataItemCreateAllTypes) {
  struct { data_type_e type; crdt_type_e crdt; } types[] = {
    {DATA_TYPE_COUNTER, CRDT_G_COUNTER},
    {DATA_TYPE_PN_COUNTER, CRDT_PN_COUNTER},
    {DATA_TYPE_SET, CRDT_OR_SET},
    {DATA_TYPE_2P_SET, CRDT_2P_SET},
    {DATA_TYPE_REGISTER, CRDT_LWW_REG},
    {DATA_TYPE_DOCUMENT, CRDT_RGA},
    {DATA_TYPE_RESOURCE, CRDT_PN_COUNTER},
    {DATA_TYPE_CUSTOM, CRDT_CUSTOM},
  };

  for (auto& t : types) {
    data_item_t* item = data_item_create("item", t.type, t.crdt);
    ASSERT_NE(item, nullptr) << "Failed for type=" << t.type;
    EXPECT_EQ(item->type, t.type);
    EXPECT_EQ(item->crdt_type, t.crdt);
    data_item_destroy(item);
  }
}

TEST(TestDataModel, DataItemCreateNullName) {
  data_item_t* item = data_item_create(nullptr, DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  ASSERT_NE(item, nullptr);
  EXPECT_STREQ(item->name, "");
  data_item_destroy(item);
}

TEST(TestDataModel, DataItemDestroyNull) {
  data_item_destroy(nullptr);
}

TEST(TestDataModel, DataItemResourceLockStateDefaults) {
  data_item_t* item = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->lock_state.lock_token_valid, false);
  EXPECT_STREQ(item->lock_state.lock_owner, "");
  EXPECT_EQ(item->lock_state.lock_expiry, (uint64_t)0);
  EXPECT_EQ(item->lock_state.lock_extensions, (uint32_t)0);
  EXPECT_EQ(item->lock_state.pre_lock_snapshot, nullptr);
  data_item_destroy(item);
}

// ============================================================
// CRABS_BUILTIN_TYPES Registry
// ============================================================

TEST(TestDataModel, BuiltinTypesRegistry) {
  EXPECT_EQ(CRABS_BUILTIN_TYPES[0].type_id, DATA_TYPE_COUNTER);
  EXPECT_STREQ(CRABS_BUILTIN_TYPES[0].name, "COUNTER");
  EXPECT_EQ(CRABS_BUILTIN_TYPES[0].requires_lock, false);

  EXPECT_EQ(CRABS_BUILTIN_TYPES[1].type_id, DATA_TYPE_PN_COUNTER);
  EXPECT_STREQ(CRABS_BUILTIN_TYPES[1].name, "PN_COUNTER");
  EXPECT_EQ(CRABS_BUILTIN_TYPES[1].requires_lock, true);

  EXPECT_EQ(CRABS_BUILTIN_TYPES[2].type_id, DATA_TYPE_SET);
  EXPECT_STREQ(CRABS_BUILTIN_TYPES[2].name, "SET");
  EXPECT_EQ(CRABS_BUILTIN_TYPES[2].requires_lock, false);

  EXPECT_EQ(CRABS_BUILTIN_TYPES[3].type_id, DATA_TYPE_2P_SET);
  EXPECT_STREQ(CRABS_BUILTIN_TYPES[3].name, "2P_SET");
  EXPECT_EQ(CRABS_BUILTIN_TYPES[3].requires_lock, false);

  EXPECT_EQ(CRABS_BUILTIN_TYPES[4].type_id, DATA_TYPE_REGISTER);
  EXPECT_STREQ(CRABS_BUILTIN_TYPES[4].name, "REGISTER");
  EXPECT_EQ(CRABS_BUILTIN_TYPES[4].requires_lock, false);

  EXPECT_EQ(CRABS_BUILTIN_TYPES[5].type_id, DATA_TYPE_DOCUMENT);
  EXPECT_STREQ(CRABS_BUILTIN_TYPES[5].name, "DOCUMENT");
  EXPECT_EQ(CRABS_BUILTIN_TYPES[5].requires_lock, false);

  EXPECT_EQ(CRABS_BUILTIN_TYPES[6].type_id, DATA_TYPE_RESOURCE);
  EXPECT_STREQ(CRABS_BUILTIN_TYPES[6].name, "RESOURCE");
  EXPECT_EQ(CRABS_BUILTIN_TYPES[6].requires_lock, true);

  EXPECT_EQ(CRABS_BUILTIN_TYPES[7].type_id, DATA_TYPE_ONE_SHOT_SET);
  EXPECT_STREQ(CRABS_BUILTIN_TYPES[7].name, "ONE_SHOT_SET");
  EXPECT_EQ(CRABS_BUILTIN_TYPES[7].requires_lock, false);

  EXPECT_EQ(CRABS_BUILTIN_TYPES[8].type_id, DATA_TYPE_ONE_SHOT_FLAG);
  EXPECT_STREQ(CRABS_BUILTIN_TYPES[8].name, "ONE_SHOT_FLAG");
  EXPECT_EQ(CRABS_BUILTIN_TYPES[8].requires_lock, false);

  EXPECT_EQ(CRABS_BUILTIN_TYPES[9].type_id, DATA_TYPE_CUSTOM);
  EXPECT_STREQ(CRABS_BUILTIN_TYPES[9].name, "CUSTOM");
  EXPECT_EQ(CRABS_BUILTIN_TYPES[9].requires_lock, false);
}

// ============================================================
// State Query Helpers
// ============================================================

TEST(TestDataModel, StateFindItemNotFound) {
  state_t* state = state_create();
  EXPECT_EQ(state_find_item(state, "nonexistent"), nullptr);
  state_destroy(state);
}

TEST(TestDataModel, StateFindItemEmptyState) {
  state_t* state = state_create();
  EXPECT_EQ(state_find_item(state, "nonexistent"), nullptr);
  state_destroy(state);
}

TEST(TestDataModel, StateAddItemNullParams) {
  EXPECT_EQ(state_add_item(nullptr, nullptr), CRABS_ERR_INVALID_PARAM);
  state_t* state = state_create();
  EXPECT_EQ(state_add_item(state, nullptr), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state_add_item(nullptr, nullptr), CRABS_ERR_INVALID_PARAM);
  state_destroy(state);
}

TEST(TestDataModel, StateAddItemPrepends) {
  state_t* state = state_create();
  data_item_t* a = data_item_create("a", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  data_item_t* b = data_item_create("b", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  EXPECT_EQ(state_add_item(state, a), CRABS_SUCCESS);
  EXPECT_EQ(state_add_item(state, b), CRABS_SUCCESS);
  // b was added last, so it should be at the head
  EXPECT_STREQ(state->items->name, "b");
  EXPECT_STREQ(state->items->next->name, "a");
  state_destroy(state);
}

// ============================================================
// Policy Management
// ============================================================

TEST(TestDataModel, StateAddPolicyNullParams) {
  EXPECT_EQ(state_add_policy(nullptr, "op", "expr"), CRABS_ERR_INVALID_PARAM);
  state_t* state = state_create();
  EXPECT_EQ(state_add_policy(state, nullptr, "expr"), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state_add_policy(state, "op", nullptr), CRABS_ERR_INVALID_PARAM);
  state_destroy(state);
}

TEST(TestDataModel, StateAddPolicyMultiple) {
  state_t* state = state_create();
  EXPECT_EQ(state_add_policy(state, CRABS_OP_LOCK, "role:admin"), CRABS_SUCCESS);
  EXPECT_EQ(state_add_policy(state, CRABS_OP_UNLOCK, "role:admin"), CRABS_SUCCESS);
  EXPECT_EQ(state->policy_count, (uint32_t)2);

  const char* p1 = state_find_policy(state, CRABS_OP_LOCK);
  ASSERT_NE(p1, nullptr);
  EXPECT_STREQ(p1, "role:admin");

  const char* p2 = state_find_policy(state, CRABS_OP_UNLOCK);
  ASSERT_NE(p2, nullptr);
  EXPECT_STREQ(p2, "role:admin");
  state_destroy(state);
}

TEST(TestDataModel, StateFindPolicyNotFound) {
  state_t* state = state_create();
  EXPECT_EQ(state_find_policy(state, "nonexistent_op"), nullptr);
  state_destroy(state);
}

TEST(TestDataModel, StateFindPolicyEmptyState) {
  state_t* state = state_create();
  EXPECT_EQ(state_find_policy(state, "nonexistent_op"), nullptr);
  state_destroy(state);
}

TEST(TestDataModel, StateAddPolicySameOpTwice) {
  state_t* state = state_create();
  EXPECT_EQ(state_add_policy(state, CRABS_OP_LOCK, "role:admin"), CRABS_SUCCESS);
  EXPECT_EQ(state_add_policy(state, CRABS_OP_LOCK, "role:editor"), CRABS_SUCCESS);
  // Re-adding a policy for the same operation updates it in place (a second
  // entry would be a shadow never returned by state_find_policy, and would
  // grow the table without bound).
  EXPECT_EQ(state->policy_count, (uint32_t)1);
  const char* p = state_find_policy(state, CRABS_OP_LOCK);
  ASSERT_NE(p, nullptr);
  EXPECT_STREQ(p, "role:editor");
  state_destroy(state);
}

// ============================================================
// Node Key Management
// ============================================================

TEST(TestDataModel, StateSetNodeKeyNullParams) {
  uint8_t priv[32] = {0};
  uint8_t pub[33] = {0};
  EXPECT_EQ(state_set_node_key(nullptr, priv, pub), CRABS_ERR_INVALID_PARAM);
  state_t* state = state_create();
  EXPECT_EQ(state_set_node_key(state, nullptr, pub), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state_set_node_key(state, priv, nullptr), CRABS_ERR_INVALID_PARAM);
  state_destroy(state);
}

TEST(TestDataModel, StateSetNodeKeySetsValid) {
  state_t* state = state_create();
  EXPECT_EQ(state->node_key_valid, false);

  ecdsa_keypair_t* key = crypto_ecdsa_generate();
  ASSERT_NE(key, nullptr);
  crabs_error_e rc = state_set_node_key(state, key->private_key, key->public_key);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(state->node_key_valid, true);
  EXPECT_EQ(memcmp(state->node_private_key, key->private_key, 32), 0);
  EXPECT_EQ(memcmp(state->node_public_key, key->public_key, 33), 0);

  crypto_ecdsa_keypair_destroy(key);
  state_destroy(state);
}

TEST(TestDataModel, StateSetNodeKeyOverwrite) {
  state_t* state = state_create();
  ecdsa_keypair_t* key1 = crypto_ecdsa_generate();
  ecdsa_keypair_t* key2 = crypto_ecdsa_generate();
  ASSERT_NE(key1, nullptr);
  ASSERT_NE(key2, nullptr);

  state_set_node_key(state, key1->private_key, key1->public_key);
  EXPECT_EQ(state->node_key_valid, true);

  state_set_node_key(state, key2->private_key, key2->public_key);
  EXPECT_EQ(state->node_key_valid, true);
  EXPECT_EQ(memcmp(state->node_private_key, key2->private_key, 32), 0);
  EXPECT_EQ(memcmp(state->node_public_key, key2->public_key, 33), 0);

  crypto_ecdsa_keypair_destroy(key1);
  crypto_ecdsa_keypair_destroy(key2);
  state_destroy(state);
}

// ============================================================
// Invariant Evaluation
// ============================================================

TEST(TestDataModel, InvariantCheckGreaterThan) {
  invariant_t inv = {INVARIANT_GREATER_THAN, 10, "must be > 10"};
  int64_t val_ok = 15;
  int64_t val_fail = 5;
  int64_t val_eq = 10;
  EXPECT_TRUE(invariant_check(&inv, &val_ok, DATA_TYPE_COUNTER));
  EXPECT_FALSE(invariant_check(&inv, &val_fail, DATA_TYPE_COUNTER));
  EXPECT_FALSE(invariant_check(&inv, &val_eq, DATA_TYPE_COUNTER));
}

TEST(TestDataModel, InvariantCheckLessThan) {
  invariant_t inv = {INVARIANT_LESS_THAN, 100, "must be < 100"};
  int64_t val_ok = 50;
  int64_t val_fail = 150;
  int64_t val_eq = 100;
  EXPECT_TRUE(invariant_check(&inv, &val_ok, DATA_TYPE_COUNTER));
  EXPECT_FALSE(invariant_check(&inv, &val_fail, DATA_TYPE_COUNTER));
  EXPECT_FALSE(invariant_check(&inv, &val_eq, DATA_TYPE_COUNTER));
}

TEST(TestDataModel, InvariantCheckEqualTo) {
  invariant_t inv = {INVARIANT_EQUAL_TO, 42, "must equal 42"};
  int64_t val_ok = 42;
  int64_t val_fail = 43;
  EXPECT_TRUE(invariant_check(&inv, &val_ok, DATA_TYPE_COUNTER));
  EXPECT_FALSE(invariant_check(&inv, &val_fail, DATA_TYPE_COUNTER));
}

TEST(TestDataModel, InvariantCheckNotEqual) {
  invariant_t inv = {INVARIANT_NOT_EQUAL, 0, "must not be 0"};
  int64_t val_ok = 1;
  int64_t val_fail = 0;
  EXPECT_TRUE(invariant_check(&inv, &val_ok, DATA_TYPE_COUNTER));
  EXPECT_FALSE(invariant_check(&inv, &val_fail, DATA_TYPE_COUNTER));
}

TEST(TestDataModel, InvariantCheckDivisibleBy) {
  invariant_t inv = {INVARIANT_DIVISIBLE_BY, 3, "must be divisible by 3"};
  int64_t val_ok = 9;
  int64_t val_fail = 10;
  EXPECT_TRUE(invariant_check(&inv, &val_ok, DATA_TYPE_COUNTER));
  EXPECT_FALSE(invariant_check(&inv, &val_fail, DATA_TYPE_COUNTER));
  // Division by zero should return false
  invariant_t inv_zero = {INVARIANT_DIVISIBLE_BY, 0, "div by zero"};
  int64_t any_val = 42;
  EXPECT_FALSE(invariant_check(&inv_zero, &any_val, DATA_TYPE_COUNTER));
}

TEST(TestDataModel, InvariantCheckNonNegative) {
  invariant_t inv = {INVARIANT_NON_NEGATIVE, 0, "must be >= 0"};
  int64_t val_ok = 0;
  int64_t val_pos = 100;
  int64_t val_fail = -1;
  EXPECT_TRUE(invariant_check(&inv, &val_ok, DATA_TYPE_COUNTER));
  EXPECT_TRUE(invariant_check(&inv, &val_pos, DATA_TYPE_COUNTER));
  EXPECT_FALSE(invariant_check(&inv, &val_fail, DATA_TYPE_COUNTER));
}

TEST(TestDataModel, InvariantCheckNullParams) {
  int64_t val = 5;
  EXPECT_FALSE(invariant_check(nullptr, &val, DATA_TYPE_COUNTER));
  invariant_t inv = {INVARIANT_NON_NEGATIVE, 0, ""};
  EXPECT_FALSE(invariant_check(&inv, nullptr, DATA_TYPE_COUNTER));
}

TEST(TestDataModel, InvariantCheckNonCounterType) {
  invariant_t inv = {INVARIANT_NON_NEGATIVE, 0, ""};
  int64_t val = 42;
  // Non-counter types always pass (returns true per implementation)
  EXPECT_TRUE(invariant_check(&inv, &val, DATA_TYPE_SET));
  EXPECT_TRUE(invariant_check(&inv, &val, DATA_TYPE_REGISTER));
  EXPECT_TRUE(invariant_check(&inv, &val, DATA_TYPE_RESOURCE));
}

TEST(TestDataModel, InvariantCheckUnsupportedType) {
  // INVARIANT_UNIQUE, INVARIANT_SUBSET_OF, INVARIANT_CUSTOM
  // return true (default case in switch)
  invariant_t inv_unique = {INVARIANT_UNIQUE, 0, ""};
  invariant_t inv_subset = {INVARIANT_SUBSET_OF, 0, ""};
  invariant_t inv_custom = {INVARIANT_CUSTOM, 0, ""};
  int64_t val = 5;
  EXPECT_TRUE(invariant_check(&inv_unique, &val, DATA_TYPE_COUNTER));
  EXPECT_TRUE(invariant_check(&inv_subset, &val, DATA_TYPE_COUNTER));
  EXPECT_TRUE(invariant_check(&inv_custom, &val, DATA_TYPE_COUNTER));
}

TEST(TestDataModel, InvariantCheckPNCounter) {
  invariant_t inv = {INVARIANT_GREATER_THAN, 0, "positive"};
  int64_t val = 10;
  EXPECT_TRUE(invariant_check(&inv, &val, DATA_TYPE_PN_COUNTER));
  int64_t neg = -5;
  EXPECT_FALSE(invariant_check(&inv, &neg, DATA_TYPE_PN_COUNTER));
}

// ============================================================
// Log Entry Tracking
// ============================================================

TEST(TestDataModel, LogEntryAfterLock) {
  state_t* state = state_create();
  data_item_t* res = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* val = (int64_t*)malloc(sizeof(int64_t));
  *val = 0;
  res->value = val;
  state_add_item(state, res);
  state_add_policy(state, CRABS_OP_LOCK, "role:admin");

  // Set up attribute machine for auth
  uint8_t admin_pk[33];
  memset(admin_pk, 0xAA, 33);
  admin_pk[0] = 0x02;
  attribute_machine_t* am = attribute_machine_create("admin", admin_pk);
  ASSERT_NE(am, nullptr);
  ecdsa_keypair_t* alice_key = crypto_ecdsa_generate();
  crabs_test_register_user_with_role(am, "alice", alice_key->public_key, "role", "admin");
  state->attr_machine = am;

  ecdsa_keypair_t* node_key = crypto_ecdsa_generate();
  state_set_node_key(state, node_key->private_key, node_key->public_key);

  operation_t* op = operation_create(CRABS_OP_LOCK);
  uint8_t uuid[CRABS_UUID_SIZE];
  memset(uuid, 0x42, CRABS_UUID_SIZE);
  memcpy(op->uuid, uuid, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  user_t* signer = attribute_machine_find_user(am, "alice");
  if (signer != NULL) op->signer_key_version = signer->key_version;
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  if (ser) {
    crypto_sign_operation(alice_key->private_key, ser->data, ser->len, op->signature);
    serialized_buffer_destroy(ser);
  }

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(state->log_count, (uint64_t)1);

  log_entry_t* entry = &state->log[0];
  // Log records the version before increment (append_log called before version++)
  EXPECT_EQ(entry->version, (uint64_t)0);
  EXPECT_EQ(memcmp(entry->uuid, uuid, CRABS_UUID_SIZE), 0);
  EXPECT_STREQ(entry->type, CRABS_OP_LOCK);
  EXPECT_STRNE(entry->signer_id, "");
  // state_hash is populated by execution (32 bytes)
  // Just verify it was set (non-zero is typical but not guaranteed)
  (void)entry->state_hash;

  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(node_key);
  crypto_ecdsa_keypair_destroy(alice_key);
  state->attr_machine = nullptr;
  state_destroy(state);
  attribute_machine_destroy(am);
}

// ============================================================
// Processed Ops Tracking
// ============================================================

TEST(TestDataModel, ProcessedOpsAfterExecution) {
  state_t* state = state_create();
  data_item_t* res = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* val = (int64_t*)malloc(sizeof(int64_t));
  *val = 0;
  res->value = val;
  state_add_item(state, res);
  state_add_policy(state, CRABS_OP_LOCK, "role:admin");

  uint8_t admin_pk[33];
  memset(admin_pk, 0xAA, 33);
  admin_pk[0] = 0x02;
  attribute_machine_t* am = attribute_machine_create("admin", admin_pk);
  ASSERT_NE(am, nullptr);
  ecdsa_keypair_t* alice_key = crypto_ecdsa_generate();
  crabs_test_register_user_with_role(am, "alice", alice_key->public_key, "role", "admin");
  state->attr_machine = am;

  ecdsa_keypair_t* node_key = crypto_ecdsa_generate();
  state_set_node_key(state, node_key->private_key, node_key->public_key);

  uint8_t uuid1[CRABS_UUID_SIZE];
  memset(uuid1, 0x11, CRABS_UUID_SIZE);

  operation_t* op = operation_create(CRABS_OP_LOCK);
  memcpy(op->uuid, uuid1, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  user_t* signer = attribute_machine_find_user(am, "alice");
  if (signer != NULL) op->signer_key_version = signer->key_version;
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  if (ser) {
    crypto_sign_operation(alice_key->private_key, ser->data, ser->len, op->signature);
    serialized_buffer_destroy(ser);
  }

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);

  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(node_key);
  crypto_ecdsa_keypair_destroy(alice_key);
  state->attr_machine = nullptr;
  state_destroy(state);
  attribute_machine_destroy(am);
}

// ============================================================
// Lock Expiry & Pruning
// ============================================================

TEST(TestDataModel, PruneExpiredLocks) {
  state_t* state = state_create();
  data_item_t* res = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* val = (int64_t*)malloc(sizeof(int64_t));
  *val = 42;
  res->value = val;
  res->protocol_state = PROTOCOL_LOCKED;
  res->lock_state.lock_token_valid = true;
  strncpy(res->lock_state.lock_owner, "alice", CRABS_MAX_USER_ID - 1);
  res->lock_state.lock_expiry = 1000; // expired in the past
  res->lock_state.pre_lock_snapshot = malloc(sizeof(int64_t));
  memcpy(res->lock_state.pre_lock_snapshot, val, sizeof(int64_t));
  state_add_item(state, res);

  uint32_t pruned = state_machine_prune_expired(state, 5000);
  EXPECT_EQ(pruned, (uint32_t)1);
  EXPECT_EQ(res->protocol_state, PROTOCOL_IDLE);
  EXPECT_FALSE(res->lock_state.lock_token_valid);
  EXPECT_EQ(res->lock_state.pre_lock_snapshot, nullptr);
  EXPECT_EQ(res->lock_state.lock_extensions, (uint32_t)0);

  state_destroy(state);
}

TEST(TestDataModel, PruneNoExpiredLocks) {
  state_t* state = state_create();
  data_item_t* res = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* val = (int64_t*)malloc(sizeof(int64_t));
  *val = 42;
  res->value = val;
  res->protocol_state = PROTOCOL_LOCKED;
  res->lock_state.lock_token_valid = true;
  strncpy(res->lock_state.lock_owner, "alice", CRABS_MAX_USER_ID - 1);
  res->lock_state.lock_expiry = 10000; // not expired yet
  state_add_item(state, res);

  uint32_t pruned = state_machine_prune_expired(state, 5000);
  EXPECT_EQ(pruned, (uint32_t)0);
  EXPECT_EQ(res->protocol_state, PROTOCOL_LOCKED);
  EXPECT_TRUE(res->lock_state.lock_token_valid);

  state_destroy(state);
}

TEST(TestDataModel, PruneOnlyAffectsResources) {
  state_t* state = state_create();
  data_item_t* counter = data_item_create("c1", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  counter->protocol_state = PROTOCOL_MODIFIED;
  state_add_item(state, counter);

  // Should not prune non-resource items even if in non-IDLE state
  uint32_t pruned = state_machine_prune_expired(state, 999999);
  EXPECT_EQ(pruned, (uint32_t)0);

  state_destroy(state);
}

// ============================================================
// Protocol State Transitions (exhaustive valid/invalid)
// ============================================================

TEST(TestDataModel, ValidTransitions) {
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_IDLE, CRABS_OP_LOCK));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_LOCKED, CRABS_OP_EXTEND));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_LOCKED, CRABS_OP_UNLOCK));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_MODIFIED, CRABS_OP_VERIFY));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_MODIFIED, CRABS_OP_ROLLBACK));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_VERIFIED, CRABS_OP_UNLOCK));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_LOCKED, CRABS_OP_FORCE_UNLOCK));
  EXPECT_TRUE(state_machine_is_valid_transition(PROTOCOL_ERROR, CRABS_OP_ROLLBACK));
}

TEST(TestDataModel, InvalidTransitions) {
  EXPECT_FALSE(state_machine_is_valid_transition(PROTOCOL_IDLE, CRABS_OP_UNLOCK));
  EXPECT_FALSE(state_machine_is_valid_transition(PROTOCOL_IDLE, CRABS_OP_VERIFY));
  EXPECT_FALSE(state_machine_is_valid_transition(PROTOCOL_IDLE, CRABS_OP_EXTEND));
  EXPECT_FALSE(state_machine_is_valid_transition(PROTOCOL_VERIFIED, CRABS_OP_LOCK));
}

// ============================================================
// Operation Lifecycle
// ============================================================

TEST(TestDataModel, OperationCreateDestroy) {
  operation_t* op = operation_create("custom_op");
  ASSERT_NE(op, nullptr);
  EXPECT_STREQ(op->type, "custom_op");
  operation_destroy(op);

  operation_destroy(nullptr);
}

TEST(TestDataModel, OperationIsBuiltinAll) {
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_LOCK));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_EXTEND));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_VERIFY));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_ROLLBACK));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_UNLOCK));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_FORCE_UNLOCK));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_CHANGE_CONFIG));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_REFRESH_KEY));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_CREATE_TRIGGER));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_DELETE_TRIGGER));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_DISABLE_TRIGGER));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_ENABLE_TRIGGER));
  EXPECT_FALSE(operation_is_builtin("custom_transfer"));
  EXPECT_FALSE(operation_is_builtin(""));
}

// ============================================================
// Invariant Violation in State Machine Execution
// ============================================================

TEST(TestDataModel, InvariantViolationRejected) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  state_t* state = env.state;

  // Register alice with a real keypair so she can sign.
  ecdsa_keypair_t* alice_key = crypto_ecdsa_generate();
  ASSERT_NE(alice_key, nullptr);
  ASSERT_EQ(crabs_test_register_user_with_role(state->attr_machine, "alice",
                                               alice_key->public_key,
                                               "role", "admin"), CRABS_SUCCESS);

  // Use a COUNTER type so invariant_check actually evaluates the value
  data_item_t* counter = data_item_create("c1", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  int64_t* val = (int64_t*)malloc(sizeof(int64_t));
  *val = 0;
  counter->value = val;

  invariant_t* inv = (invariant_t*)malloc(sizeof(invariant_t));
  inv->type = INVARIANT_GREATER_THAN;
  inv->param = 0;
  inv->error_message = strdup("must be > 0");
  counter->invariants = inv;
  counter->invariant_count = 1;

  state_add_item(state, counter);

  // Counter items don't need locking, just set to MODIFIED directly
  counter->protocol_state = PROTOCOL_MODIFIED;

  operation_t* verify_op = operation_create(CRABS_OP_VERIFY);
  uint8_t verify_uuid[CRABS_UUID_SIZE];
  memset(verify_uuid, 0x33, CRABS_UUID_SIZE);
  memcpy(verify_op->uuid, verify_uuid, CRABS_UUID_SIZE);
  verify_op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(verify_op->resources[0], "c1", CRABS_MAX_USER_ID - 1);
  verify_op->resource_count = 1;
  verify_op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  verify_op->required_state[0] = PROTOCOL_MODIFIED;
  verify_op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  verify_op->next_state[0] = PROTOCOL_VERIFIED;
  strncpy(verify_op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(env.am, alice_key, verify_op);

  // Value 0 is not > 0, so verify should fail with INVARIANT_VIOLATED
  crabs_error_e rc = state_machine_execute(state, verify_op);
  EXPECT_EQ(rc, CRABS_ERR_INVARIANT_VIOLATED);
  operation_destroy(verify_op);

  free((void*)counter->invariants[0].error_message);
  crypto_ecdsa_keypair_destroy(alice_key);
  crabs_test_env_destroy(&env);
}

// ============================================================
// Lock Token Generation
// ============================================================

TEST(TestDataModel, LockTokenEntropy) {
  uint8_t token1[CRABS_LOCK_TOKEN_SIZE];
  uint8_t token2[CRABS_LOCK_TOKEN_SIZE];
  state_machine_generate_lock_token(token1);
  state_machine_generate_lock_token(token2);
  // Two tokens should differ with overwhelming probability
  EXPECT_NE(memcmp(token1, token2, CRABS_LOCK_TOKEN_SIZE), 0);
}

// ============================================================
// State Destroy Cleanses Node Private Key
// ============================================================

TEST(TestDataModel, StateDestroyCleansesNodeKey) {
  state_t* state = state_create();
  ecdsa_keypair_t* key = crypto_ecdsa_generate();
  state_set_node_key(state, key->private_key, key->public_key);
  // Save the key bytes before destroy
  uint8_t saved_priv[32];
  memcpy(saved_priv, state->node_private_key, 32);
  crypto_ecdsa_keypair_destroy(key);
  state_destroy(state);
  // Can't directly verify OPENSSL_cleanse ran (memory is freed),
  // but the test verifies the code path exists without crash
}

// ============================================================
// Serialization Round-Trip for Config
// ============================================================

TEST(TestDataModel, ConfigRoundTrip) {
  state_t* state = state_create();
  state->config.max_lock_duration_ms = 30000;
  state->config.max_lock_extensions = 5;
  state->config.allow_force_unlock = false;
  strncpy(state->config.bootstrap_admin, "superuser", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(restored->config.max_lock_duration_ms, (uint64_t)30000);
  EXPECT_EQ(restored->config.max_lock_extensions, (uint32_t)5);
  EXPECT_EQ(restored->config.allow_force_unlock, false);
  EXPECT_STREQ(restored->config.bootstrap_admin, "superuser");

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

// ============================================================
// Write Domains (v1): creation options, fork evidence, digest
// ============================================================

TEST(TestDataModel, ItemCreateWithOptionsNullIsFreeMergeDefault) {
  data_item_t* item = nullptr;
  EXPECT_EQ(data_item_create_with_options("sovereignless", DATA_TYPE_COUNTER,
                                          CRDT_G_COUNTER, nullptr, &item),
            CRABS_SUCCESS);
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->write_domain, CRABS_DOMAIN_FREE_MERGE);
  EXPECT_STREQ(item->writer, "");
  EXPECT_EQ(item->item_seq, (uint64_t)0);
  EXPECT_EQ(item->ordering_module, (uint8_t)0);
  EXPECT_EQ(item->fork_count, (uint32_t)0);
  uint8_t zero_digest[CRABS_HASH_SIZE] = {0};
  EXPECT_EQ(memcmp(item->item_digest, zero_digest, CRABS_HASH_SIZE), 0);
  EXPECT_EQ(state_item_domain(item), CRABS_DOMAIN_FREE_MERGE);
  data_item_destroy(item);

  // A zeroed options struct must behave identically to NULL.
  data_item_options_t zeroed = {};
  data_item_t* item2 = nullptr;
  EXPECT_EQ(data_item_create_with_options("zeroed", DATA_TYPE_COUNTER,
                                          CRDT_G_COUNTER, &zeroed, &item2),
            CRABS_SUCCESS);
  ASSERT_NE(item2, nullptr);
  EXPECT_EQ(item2->write_domain, CRABS_DOMAIN_FREE_MERGE);
  EXPECT_STREQ(item2->writer, "");
  data_item_destroy(item2);
}

TEST(TestDataModel, ItemCreateWithOptionsSovereign) {
  data_item_options_t options = {};
  options.write_domain = CRABS_DOMAIN_SOVEREIGN;
  options.writer = "alice";

  data_item_t* item = nullptr;
  EXPECT_EQ(data_item_create_with_options("alice_counter", DATA_TYPE_COUNTER,
                                          CRDT_G_COUNTER, &options, &item),
            CRABS_SUCCESS);
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->write_domain, CRABS_DOMAIN_SOVEREIGN);
  EXPECT_STREQ(item->writer, "alice");
  EXPECT_EQ(item->item_seq, (uint64_t)0);
  EXPECT_EQ(state_item_domain(item), CRABS_DOMAIN_SOVEREIGN);
  data_item_destroy(item);

  // REGISTER is the other v1-supported sovereign type.
  data_item_t* reg = nullptr;
  EXPECT_EQ(data_item_create_with_options("alice_reg", DATA_TYPE_REGISTER,
                                          CRDT_LWW_REG, &options, &reg),
            CRABS_SUCCESS);
  ASSERT_NE(reg, nullptr);
  EXPECT_EQ(reg->write_domain, CRABS_DOMAIN_SOVEREIGN);
  EXPECT_STREQ(reg->writer, "alice");
  data_item_destroy(reg);
}

TEST(TestDataModel, ItemCreateWithOptionsSovereignRequiresWriter) {
  data_item_options_t options = {};
  options.write_domain = CRABS_DOMAIN_SOVEREIGN;

  data_item_t* item = nullptr;
  // NULL writer
  EXPECT_EQ(data_item_create_with_options("c", DATA_TYPE_COUNTER,
                                          CRDT_G_COUNTER, &options, &item),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(item, nullptr);
  // Empty writer
  options.writer = "";
  EXPECT_EQ(data_item_create_with_options("c", DATA_TYPE_COUNTER,
                                          CRDT_G_COUNTER, &options, &item),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(item, nullptr);
}

TEST(TestDataModel, ItemCreateWithOptionsSovereignTypeRestricted) {
  data_item_options_t options = {};
  options.write_domain = CRABS_DOMAIN_SOVEREIGN;
  options.writer = "alice";

  // v1 restricts SOVEREIGN to COUNTER/REGISTER: only those types have a
  // well-defined serialized post-state for the hash-chain digest.
  data_item_t* item = nullptr;
  EXPECT_EQ(data_item_create_with_options("s", DATA_TYPE_SET,
                                          CRDT_OR_SET, &options, &item),
            CRABS_ERR_TYPE_MISMATCH);
  EXPECT_EQ(item, nullptr);
  EXPECT_EQ(data_item_create_with_options("d", DATA_TYPE_DOCUMENT,
                                          CRDT_RGA, &options, &item),
            CRABS_ERR_TYPE_MISMATCH);
  EXPECT_EQ(item, nullptr);
}

TEST(TestDataModel, ItemCreateWithOptionsWriterOnlyForSovereign) {
  data_item_options_t options = {};
  options.write_domain = CRABS_DOMAIN_FREE_MERGE;
  options.writer = "alice";

  data_item_t* item = nullptr;
  EXPECT_EQ(data_item_create_with_options("c", DATA_TYPE_COUNTER,
                                          CRDT_G_COUNTER, &options, &item),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(item, nullptr);
}

TEST(TestDataModel, ItemCreateWithOptionsUnknownDomainRejected) {
  data_item_options_t options = {};
  options.write_domain = (crabs_write_domain_e)0x7F;

  data_item_t* item = nullptr;
  EXPECT_EQ(data_item_create_with_options("c", DATA_TYPE_COUNTER,
                                          CRDT_G_COUNTER, &options, &item),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(item, nullptr);
}

TEST(TestDataModel, ItemCreateWithOptionsGroupOrderedV1Seam) {
  data_item_options_t options = {};
  options.write_domain = CRABS_DOMAIN_GROUP_ORDERED;

  // v1 ships no ordering modules: module id 0 (unset) is creatable and the
  // item is read-only until a module is registered (DOMAIN_CHECK fail-closed).
  data_item_t* item = nullptr;
  EXPECT_EQ(data_item_create_with_options("g", DATA_TYPE_COUNTER,
                                          CRDT_G_COUNTER, &options, &item),
            CRABS_SUCCESS);
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->write_domain, CRABS_DOMAIN_GROUP_ORDERED);
  EXPECT_EQ(item->ordering_module, (uint8_t)0);
  data_item_destroy(item);

  // A non-zero module id cannot resolve in v1 (no module registry yet) and
  // must fail closed at creation.
  options.ordering_module = 1;
  item = nullptr;
  EXPECT_EQ(data_item_create_with_options("g", DATA_TYPE_COUNTER,
                                          CRDT_G_COUNTER, &options, &item),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(item, nullptr);
}

TEST(TestDataModel, StateAddItemRejectsMalformedSovereign) {
  // Hand-built item (not via data_item_create_with_options) claiming
  // SOVEREIGN without a writer: state_add_item fails closed.
  state_t* state = state_create();
  data_item_t* item = data_item_create("handmade", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  item->write_domain = CRABS_DOMAIN_SOVEREIGN;  // writer left empty
  EXPECT_EQ(state_add_item(state, item), CRABS_ERR_INVALID_PARAM);
  data_item_destroy(item);
  state_destroy(state);
}

TEST(TestDataModel, AppendForkEvidenceDedupeAndCap) {
  data_item_options_t options = {};
  options.write_domain = CRABS_DOMAIN_SOVEREIGN;
  options.writer = "alice";
  data_item_t* item = nullptr;
  ASSERT_EQ(data_item_create_with_options("c", DATA_TYPE_COUNTER,
                                          CRDT_G_COUNTER, &options, &item),
            CRABS_SUCCESS);

  uint8_t evidence[CRABS_HASH_SIZE];
  memset(evidence, 0x11, CRABS_HASH_SIZE);
  EXPECT_EQ(state_append_fork_evidence(item, "mallory", evidence), CRABS_SUCCESS);
  EXPECT_EQ(item->fork_count, (uint32_t)1);
  EXPECT_STREQ(item->fork_writers[0], "mallory");
  EXPECT_EQ(memcmp(item->fork_evidence_digests[0], evidence, CRABS_HASH_SIZE), 0);
  EXPECT_TRUE(state_item_is_quarantined(item, "mallory"));
  EXPECT_FALSE(state_item_is_quarantined(item, "alice"));

  // Monotone-union: duplicate writer rejected even with different evidence.
  uint8_t evidence2[CRABS_HASH_SIZE];
  memset(evidence2, 0x22, CRABS_HASH_SIZE);
  EXPECT_EQ(state_append_fork_evidence(item, "mallory", evidence2),
            CRABS_ERR_DUPLICATE_OPERATION);
  // Different writer reusing the same evidence digest is also a duplicate.
  EXPECT_EQ(state_append_fork_evidence(item, "sybil", evidence),
            CRABS_ERR_DUPLICATE_OPERATION);
  EXPECT_EQ(item->fork_count, (uint32_t)1);

  // Cap: fill to CRABS_MAX_FORK_WRITERS, then one more must fail.
  for (uint32_t i = (uint32_t)item->fork_count; i < CRABS_MAX_FORK_WRITERS; i++) {
    char fork_writer[CRABS_MAX_USER_ID];
    snprintf(fork_writer, sizeof(fork_writer), "forker_%u", i);
    uint8_t fork_evidence[CRABS_HASH_SIZE];
    memset(fork_evidence, 0, CRABS_HASH_SIZE);
    fork_evidence[0] = (uint8_t)(0xA0 + i);
    EXPECT_EQ(state_append_fork_evidence(item, fork_writer, fork_evidence),
              CRABS_SUCCESS) << "i=" << i;
  }
  EXPECT_EQ(item->fork_count, (uint32_t)CRABS_MAX_FORK_WRITERS);
  uint8_t extra_evidence[CRABS_HASH_SIZE];
  memset(extra_evidence, 0xFF, CRABS_HASH_SIZE);
  EXPECT_EQ(state_append_fork_evidence(item, "overflow", extra_evidence),
            CRABS_ERR_OOM);
  EXPECT_EQ(item->fork_count, (uint32_t)CRABS_MAX_FORK_WRITERS);
  EXPECT_FALSE(state_item_is_quarantined(item, "overflow"));

  // Null params
  EXPECT_EQ(state_append_fork_evidence(nullptr, "x", evidence), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state_append_fork_evidence(item, nullptr, evidence), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state_append_fork_evidence(item, "", evidence), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state_append_fork_evidence(item, "x", nullptr), CRABS_ERR_INVALID_PARAM);

  data_item_destroy(item);
}

TEST(TestDataModel, ItemDigestComputeDeterministic) {
  int64_t value_a = 7;
  int64_t value_b = 7;

  data_item_t* item_a = data_item_create("c", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  data_item_t* item_b = data_item_create("c", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  item_a->value = &value_a;
  item_b->value = &value_b;

  uint8_t digest_a[CRABS_HASH_SIZE];
  uint8_t digest_b[CRABS_HASH_SIZE];
  ASSERT_EQ(state_item_digest_compute(item_a, digest_a), CRABS_SUCCESS);
  ASSERT_EQ(state_item_digest_compute(item_b, digest_b), CRABS_SUCCESS);
  // Same content → same digest (content-comparable across replicas).
  EXPECT_EQ(memcmp(digest_a, digest_b, CRABS_HASH_SIZE), 0);

  // Different content → different digest.
  value_b = 8;
  ASSERT_EQ(state_item_digest_compute(item_b, digest_b), CRABS_SUCCESS);
  EXPECT_NE(memcmp(digest_a, digest_b, CRABS_HASH_SIZE), 0);

  // A freshly created (value-less) item still digests deterministically.
  data_item_t* empty_a = data_item_create("c", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  data_item_t* empty_b = data_item_create("c", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  uint8_t digest_ea[CRABS_HASH_SIZE];
  uint8_t digest_eb[CRABS_HASH_SIZE];
  ASSERT_EQ(state_item_digest_compute(empty_a, digest_ea), CRABS_SUCCESS);
  ASSERT_EQ(state_item_digest_compute(empty_b, digest_eb), CRABS_SUCCESS);
  EXPECT_EQ(memcmp(digest_ea, digest_eb, CRABS_HASH_SIZE), 0);
  EXPECT_NE(memcmp(digest_a, digest_ea, CRABS_HASH_SIZE), 0);

  EXPECT_EQ(state_item_digest_compute(nullptr, digest_a), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state_item_digest_compute(item_a, nullptr), CRABS_ERR_INVALID_PARAM);

  // Values point into test-owned storage — detach before destroy.
  item_a->value = nullptr;
  item_b->value = nullptr;
  data_item_destroy(item_a);
  data_item_destroy(item_b);
  data_item_destroy(empty_a);
  data_item_destroy(empty_b);
}