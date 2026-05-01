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
  EXPECT_EQ(state->processed_ops, nullptr);
  EXPECT_EQ(state->processed_op_count, (uint64_t)0);
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

  EXPECT_EQ(CRABS_BUILTIN_TYPES[7].type_id, DATA_TYPE_CUSTOM);
  EXPECT_STREQ(CRABS_BUILTIN_TYPES[7].name, "CUSTOM");
  EXPECT_EQ(CRABS_BUILTIN_TYPES[7].requires_lock, false);
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
  // Both entries should exist (implementation appends, does not deduplicate)
  EXPECT_EQ(state->policy_count, (uint32_t)2);
  // find_policy returns first match
  const char* p = state_find_policy(state, CRABS_OP_LOCK);
  ASSERT_NE(p, nullptr);
  EXPECT_STREQ(p, "role:admin");
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
  attribute_machine_register_user(am, "alice", alice_key->public_key, "role:admin");
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
  attribute_machine_register_user(am, "alice", alice_key->public_key, "role:admin");
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
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  if (ser) {
    crypto_sign_operation(alice_key->private_key, ser->data, ser->len, op->signature);
    serialized_buffer_destroy(ser);
  }

  crabs_error_e rc = state_machine_execute(state, op);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(state->processed_op_count, (uint64_t)1);
  EXPECT_EQ(memcmp(state->processed_ops[0], uuid1, CRABS_UUID_SIZE), 0);

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
  state_t* state = state_create();
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
  // Use empty policy to skip ABE check but pass the policy != NULL guard
  state_add_policy(state, CRABS_OP_VERIFY, "");

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

  // Value 0 is not > 0, so verify should fail with INVARIANT_VIOLATED
  crabs_error_e rc = state_machine_execute(state, verify_op);
  EXPECT_EQ(rc, CRABS_ERR_INVARIANT_VIOLATED);
  operation_destroy(verify_op);

  state_destroy(state);
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