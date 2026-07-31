//
// Created by victor on 5/1/25.
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/CLI/cli.h"
#include "../src/CRABS/data_model.h"
#include "../src/CRDT/one_shot.h"
}

// ============================================================
// Test Fixture
// ============================================================
class TestCLI : public ::testing::Test {
protected:
  cli_node_t* node;

  void SetUp() override {
    node = cli_node_create();
    ASSERT_NE(node, nullptr);
  }

  void TearDown() override {
    cli_node_destroy(node);
  }
};

// ============================================================
// Node Lifecycle Tests
// ============================================================

TEST_F(TestCLI, CreateDestroy) {
  EXPECT_NE(node, nullptr);
  EXPECT_FALSE(node->initialized);
}

TEST_F(TestCLI, InitNode) {
  cli_result_e rc = cli_node_init(node, "admin");
  EXPECT_EQ(rc, CLI_OK);
  EXPECT_TRUE(node->initialized);
  EXPECT_NE(node->attr_machine, nullptr);
  EXPECT_NE(node->abe_mk, nullptr);
  EXPECT_NE(node->node_key, nullptr);
}

TEST_F(TestCLI, InitNullParams) {
  EXPECT_EQ(cli_node_init(nullptr, "admin"), CLI_ERR_ARGS);
  EXPECT_EQ(cli_node_init(node, nullptr), CLI_ERR_ARGS);
}

TEST_F(TestCLI, InitTwiceFails) {
  cli_result_e rc = cli_node_init(node, "admin");
  EXPECT_EQ(rc, CLI_OK);
  EXPECT_EQ(cli_node_init(node, "admin2"), CLI_ERR_ARGS);
}

// ============================================================
// Hex Conversion Tests
// ============================================================

TEST_F(TestCLI, HexToBytesRoundTrip) {
  // 4 bytes = 8 hex chars - simple round trip test
  const char* hex = "deadbeef";
  ASSERT_EQ(strlen(hex), (size_t)8);

  uint8_t bytes[4];
  EXPECT_EQ(cli_hex_to_bytes(hex, bytes, 4), CLI_OK);

  char out[9];
  cli_bytes_to_hex(bytes, 4, out);
  EXPECT_STREQ(out, hex);
}

TEST_F(TestCLI, HexToBytesNullParams) {
  uint8_t buf[4];
  EXPECT_EQ(cli_hex_to_bytes(nullptr, buf, 4), CLI_ERR_ARGS);
  EXPECT_EQ(cli_hex_to_bytes("abcd", nullptr, 4), CLI_ERR_ARGS);
}

TEST_F(TestCLI, HexToBytesWrongLength) {
  uint8_t buf[4];
  EXPECT_EQ(cli_hex_to_bytes("abcdef", buf, 4), CLI_ERR_ARGS);
}

TEST_F(TestCLI, HexToBytesInvalidChars) {
  uint8_t buf[2];
  EXPECT_EQ(cli_hex_to_bytes("GG", buf, 2), CLI_ERR_ARGS);
}

// ============================================================
// Error String Tests
// ============================================================

TEST_F(TestCLI, ErrorStrings) {
  EXPECT_STREQ(cli_error_string(CRABS_SUCCESS), "success");
  EXPECT_STREQ(cli_error_string(CRABS_ERR_PROTOCOL_VIOLATION), "protocol_violation");
  EXPECT_STREQ(cli_error_string(CRABS_ERR_UNAUTHORIZED), "unauthorized");
  EXPECT_STREQ(cli_error_string(CRABS_ERR_OOM), "out_of_memory");
  EXPECT_STREQ(cli_error_string((crabs_error_e)0xFFFF), "unknown");
}

TEST_F(TestCLI, ProtocolStateStrings) {
  EXPECT_STREQ(cli_protocol_state_string(PROTOCOL_IDLE), "idle");
  EXPECT_STREQ(cli_protocol_state_string(PROTOCOL_LOCKED), "locked");
  EXPECT_STREQ(cli_protocol_state_string(PROTOCOL_MODIFIED), "modified");
  EXPECT_STREQ(cli_protocol_state_string(PROTOCOL_VERIFIED), "verified");
  EXPECT_STREQ(cli_protocol_state_string(PROTOCOL_ERROR), "error");
}

// ============================================================
// State Query Tests
// ============================================================

TEST_F(TestCLI, StateShowWithoutInit) {
  EXPECT_EQ(cli_cmd_state_show(node), CLI_ERR_NOT_INIT);
}

TEST_F(TestCLI, StateShowAfterInit) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_state_show(node), CLI_OK);
}

TEST_F(TestCLI, StateItemsEmpty) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_state_items(node), CLI_OK);
}

TEST_F(TestCLI, StatePoliciesEmpty) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_state_policies(node), CLI_OK);
}

TEST_F(TestCLI, StateConfig) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_state_config(node), CLI_OK);
}

// ============================================================
// User Management Tests
// ============================================================

TEST_F(TestCLI, UserListEmpty) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_user_list(node), CLI_OK);
}

TEST_F(TestCLI, UserRegisterAndList) {
  cli_node_init(node, "admin");

  // Generate a key for a new user
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  char pk_hex[67];
  cli_bytes_to_hex(keypair->public_key, 33, pk_hex);

  EXPECT_EQ(cli_cmd_user_register(node, "alice", pk_hex), CLI_OK);

  // Duplicate registration should fail
  EXPECT_NE(cli_cmd_user_register(node, "alice", pk_hex), CLI_OK);

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST_F(TestCLI, UserRegisterInvalidKey) {
  cli_node_init(node, "admin");
  EXPECT_NE(cli_cmd_user_register(node, "bob", "not_hex"), CLI_OK);
}

TEST_F(TestCLI, UserGrantAndRevoke) {
  cli_node_init(node, "admin");

  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  char pk_hex[67];
  cli_bytes_to_hex(keypair->public_key, 33, pk_hex);

  cli_cmd_user_register(node, "alice", pk_hex);
  EXPECT_EQ(cli_cmd_user_grant(node, "alice", "role:admin", ""), CLI_OK);

  user_t* alice = attribute_machine_find_user(node->attr_machine, "alice");
  ASSERT_NE(alice, nullptr);
  // _attribute_matches_name extracts the name before ':' so "role:admin" has name "role"
  EXPECT_TRUE(attribute_machine_user_has_role(alice, "role"));

  // Revoke uses the full attribute format "role:admin"
  // _attribute_matches_name compares extracted name ("role") with the query parameter
  EXPECT_EQ(cli_cmd_user_revoke(node, "alice", "role"), CLI_OK);
  EXPECT_FALSE(attribute_machine_user_has_role(alice, "role"));

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST_F(TestCLI, UserSuspend) {
  cli_node_init(node, "admin");

  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  char pk_hex[67];
  cli_bytes_to_hex(keypair->public_key, 33, pk_hex);

  cli_cmd_user_register(node, "charlie", pk_hex);
  EXPECT_EQ(cli_cmd_user_suspend(node, "charlie"), CLI_OK);

  user_t* charlie = attribute_machine_find_user(node->attr_machine, "charlie");
  ASSERT_NE(charlie, nullptr);
  EXPECT_EQ(charlie->status, USER_SUSPENDED);

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST_F(TestCLI, UserNullParams) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_user_register(node, nullptr, "hex"), CLI_ERR_ARGS);
  EXPECT_EQ(cli_cmd_user_register(node, "alice", nullptr), CLI_ERR_ARGS);
  EXPECT_EQ(cli_cmd_user_grant(node, nullptr, "role", "val"), CLI_ERR_ARGS);
  EXPECT_EQ(cli_cmd_user_suspend(node, nullptr), CLI_ERR_ARGS);
}

// ============================================================
// Data Item Tests
// ============================================================

TEST_F(TestCLI, ItemAddAndList) {
  cli_node_init(node, "admin");

  EXPECT_EQ(cli_cmd_item_add(node, "counter1", "counter"), CLI_OK);
  EXPECT_EQ(cli_cmd_item_add(node, "set1", "set"), CLI_OK);

  data_item_t* item = state_find_item(&node->attr_machine->base_state, "counter1");
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->type, DATA_TYPE_COUNTER);

  // Duplicate should fail
  EXPECT_NE(cli_cmd_item_add(node, "counter1", "counter"), CLI_OK);
}

TEST_F(TestCLI, ItemAddNullParams) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_item_add(node, nullptr, "counter"), CLI_ERR_ARGS);
  EXPECT_EQ(cli_cmd_item_add(node, "name", nullptr), CLI_ERR_ARGS);
}

TEST_F(TestCLI, ItemAddUninitialized) {
  EXPECT_EQ(cli_cmd_item_add(node, "name", "counter"), CLI_ERR_NOT_INIT);
}

// ============================================================
// Policy Tests
// ============================================================

TEST_F(TestCLI, PolicyAddAndList) {
  cli_node_init(node, "admin");

  EXPECT_EQ(cli_cmd_policy_add(node, CRABS_OP_LOCK, "role:admin"), CLI_OK);
  EXPECT_EQ(cli_cmd_state_policies(node), CLI_OK);

  const char* expr = state_find_policy(&node->attr_machine->base_state, CRABS_OP_LOCK);
  EXPECT_NE(expr, nullptr);
  EXPECT_STREQ(expr, "role:admin");
}

TEST_F(TestCLI, PolicyAddNullParams) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_policy_add(node, nullptr, "expr"), CLI_ERR_ARGS);
  EXPECT_EQ(cli_cmd_policy_add(node, "op", nullptr), CLI_ERR_ARGS);
}

// ============================================================
// Key Management Tests
// ============================================================

TEST_F(TestCLI, KeyGenerate) {
  // Key generate doesn't need init
  EXPECT_EQ(cli_cmd_key_generate(), CLI_OK);
}

TEST_F(TestCLI, KeyRefreshUninitialized) {
  EXPECT_EQ(cli_cmd_key_refresh(node, "alice"), CLI_ERR_NOT_INIT);
}

TEST_F(TestCLI, KeyRefresh) {
  cli_node_init(node, "admin");

  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  char pk_hex[67];
  cli_bytes_to_hex(keypair->public_key, 33, pk_hex);

  cli_cmd_user_register(node, "alice", pk_hex);

  // Refresh key for alice via the CLI
  EXPECT_EQ(cli_cmd_key_refresh(node, "alice"), CLI_OK);

  user_t* alice = attribute_machine_find_user(node->attr_machine, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->key_version, node->attr_machine->base_state.version);

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST_F(TestCLI, KeyRefreshNullUserId) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_key_refresh(node, nullptr), CLI_ERR_ARGS);
}

TEST_F(TestCLI, KeyRevoke) {
  cli_node_init(node, "admin");

  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  char pk_hex[67];
  cli_bytes_to_hex(keypair->public_key, 33, pk_hex);

  cli_cmd_user_register(node, "alice", pk_hex);
  EXPECT_EQ(cli_cmd_key_revoke(node, "alice"), CLI_OK);

  crypto_ecdsa_keypair_destroy(keypair);
}

TEST_F(TestCLI, KeyRevokeNullUserId) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_key_revoke(node, nullptr), CLI_ERR_ARGS);
}

// ============================================================
// Operation Submission Tests
// ============================================================

TEST_F(TestCLI, OpSubmitLock) {
  cli_node_init(node, "admin");

  // Add a resource item
  cli_cmd_item_add(node, "res1", "resource");

  // Add empty policy for lock operations (allows any signer, skips ABE check)
  state_add_policy(&node->attr_machine->base_state, CRABS_OP_LOCK, "");

  // Submit lock operation with admin signer
  EXPECT_EQ(cli_cmd_op_submit(node, CRABS_OP_LOCK, nullptr, "admin"), CLI_OK);

  data_item_t* item = state_find_item(&node->attr_machine->base_state, "res1");
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->protocol_state, PROTOCOL_LOCKED);
}

TEST_F(TestCLI, OpSubmitUninitialized) {
  EXPECT_EQ(cli_cmd_op_submit(node, CRABS_OP_LOCK, nullptr, "alice"),
            CLI_ERR_NOT_INIT);
}

TEST_F(TestCLI, OpSubmitNullType) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_op_submit(node, nullptr, nullptr, nullptr), CLI_ERR_ARGS);
}

// ============================================================
// Command Dispatch Tests
// ============================================================

TEST_F(TestCLI, DispatchHelp) {
  char* argv[] = {(char*)"crabs_node", (char*)"help"};
  EXPECT_EQ(cli_dispatch(node, 2, argv), CLI_OK);
}

TEST_F(TestCLI, DispatchNoArgs) {
  char* argv[] = {(char*)"crabs_node"};
  EXPECT_EQ(cli_dispatch(node, 1, argv), CLI_ERR_ARGS);
}

TEST_F(TestCLI, DispatchInit) {
  char* argv[] = {(char*)"crabs_node", (char*)"init", (char*)"admin"};
  EXPECT_EQ(cli_dispatch(node, 3, argv), CLI_OK);
  EXPECT_TRUE(node->initialized);
}

TEST_F(TestCLI, DispatchInitNoAdminId) {
  char* argv[] = {(char*)"crabs_node", (char*)"init"};
  EXPECT_EQ(cli_dispatch(node, 2, argv), CLI_ERR_ARGS);
}

TEST_F(TestCLI, DispatchKeyGenerate) {
  char* argv[] = {(char*)"crabs_node", (char*)"key", (char*)"generate"};
  EXPECT_EQ(cli_dispatch(node, 3, argv), CLI_OK);
}

TEST_F(TestCLI, DispatchUnknownCommand) {
  char* argv[] = {(char*)"crabs_node", (char*)"bogus"};
  EXPECT_EQ(cli_dispatch(node, 2, argv), CLI_ERR_ARGS);
}

TEST_F(TestCLI, DispatchStateShow) {
  cli_node_init(node, "admin");
  char* argv[] = {(char*)"crabs_node", (char*)"state", (char*)"show"};
  EXPECT_EQ(cli_dispatch(node, 3, argv), CLI_OK);
}

TEST_F(TestCLI, DispatchUserRegister) {
  cli_node_init(node, "admin");

  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  char pk_hex[67];
  cli_bytes_to_hex(keypair->public_key, 33, pk_hex);

  char* argv[] = {(char*)"crabs_node", (char*)"user", (char*)"register",
                  (char*)"alice", pk_hex};
  EXPECT_EQ(cli_dispatch(node, 5, argv), CLI_OK);

  crypto_ecdsa_keypair_destroy(keypair);
}

// ============================================================
// Save/Load Round-Trip Test
// ============================================================

TEST_F(TestCLI, SaveLoadRoundTrip) {
  cli_node_init(node, "admin");

  // Add some state
  cli_cmd_item_add(node, "counter1", "counter");
  cli_cmd_policy_add(node, CRABS_OP_LOCK, "role:admin");

  const char* tmp_path = "/tmp/crabs_test_state.bin";
  EXPECT_EQ(cli_node_save(node, tmp_path), CLI_OK);

  // Load into a new node
  cli_node_t* node2 = cli_node_create();
  EXPECT_EQ(cli_node_load(node2, tmp_path), CLI_OK);
  EXPECT_TRUE(node2->initialized);

  // Verify loaded state
  state_t* loaded = &node2->attr_machine->base_state;
  EXPECT_NE(loaded, nullptr);

  // Clean up
  remove(tmp_path);
  cli_node_destroy(node2);
}

TEST_F(TestCLI, SaveNullParams) {
  EXPECT_EQ(cli_node_save(node, nullptr), CLI_ERR_ARGS);
  EXPECT_EQ(cli_node_save(nullptr, "/tmp/test"), CLI_ERR_ARGS);
}

TEST_F(TestCLI, LoadNullParams) {
  EXPECT_EQ(cli_node_load(node, nullptr), CLI_ERR_ARGS);
}

TEST_F(TestCLI, LoadNonexistentFile) {
  EXPECT_EQ(cli_node_load(node, "/tmp/nonexistent_crabs_file_12345"), CLI_ERR_IO);
}

// ============================================================
// ONE_SHOT item type tests
// ============================================================

TEST_F(TestCLI, ItemAddOneShotSet) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_item_add(node, "voters", "one_shot_set"), CLI_OK);

  data_item_t* item = state_find_item(&node->attr_machine->base_state, "voters");
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->type, DATA_TYPE_ONE_SHOT_SET);
  EXPECT_EQ(item->crdt_type, CRDT_ONE_SHOT_SET);
}

TEST_F(TestCLI, ItemAddOneShotFlag) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_item_add(node, "executed", "one_shot_flag"), CLI_OK);

  data_item_t* item = state_find_item(&node->attr_machine->base_state, "executed");
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->type, DATA_TYPE_ONE_SHOT_FLAG);
  EXPECT_EQ(item->crdt_type, CRDT_ONE_SHOT_FLAG);
}

// ============================================================
// Op Define and Check-Dedup tests
// ============================================================

TEST_F(TestCLI, OpDefinePerUser) {
  cli_node_init(node, "admin");
  cli_cmd_item_add(node, "voters", "one_shot_set");

  EXPECT_EQ(cli_cmd_op_define(node, "vote", "per_user", "voters", NULL, NULL), CLI_OK);

  // Verify the operation type was registered
  const dedup_spec_t* spec = state_find_op_type_def(&node->attr_machine->base_state, "vote");
  ASSERT_NE(spec, nullptr);
  EXPECT_EQ(spec->type, DEDUP_PER_USER);
  EXPECT_STREQ(spec->tracker_path, "voters");
}

TEST_F(TestCLI, OpDefineGlobal) {
  cli_node_init(node, "admin");
  cli_cmd_item_add(node, "executed", "one_shot_flag");

  EXPECT_EQ(cli_cmd_op_define(node, "execute_proposal", "global", NULL, "executed", NULL), CLI_OK);

  const dedup_spec_t* spec = state_find_op_type_def(&node->attr_machine->base_state, "execute_proposal");
  ASSERT_NE(spec, nullptr);
  EXPECT_EQ(spec->type, DEDUP_GLOBAL);
  EXPECT_STREQ(spec->flag_path, "executed");
}

TEST_F(TestCLI, OpDefineCustom) {
  cli_node_init(node, "admin");

  EXPECT_EQ(cli_cmd_op_define(node, "spend", "custom", NULL, NULL, "balance >= amount"), CLI_OK);

  const dedup_spec_t* spec = state_find_op_type_def(&node->attr_machine->base_state, "spend");
  ASSERT_NE(spec, nullptr);
  EXPECT_EQ(spec->type, DEDUP_CUSTOM);
  EXPECT_STREQ(spec->condition, "balance >= amount");
}

TEST_F(TestCLI, OpDefineNone) {
  cli_node_init(node, "admin");

  EXPECT_EQ(cli_cmd_op_define(node, "comment", "none", NULL, NULL, NULL), CLI_OK);

  const dedup_spec_t* spec = state_find_op_type_def(&node->attr_machine->base_state, "comment");
  ASSERT_NE(spec, nullptr);
  EXPECT_EQ(spec->type, DEDUP_NONE);
}

TEST_F(TestCLI, OpDefineInvalidDedupType) {
  cli_node_init(node, "admin");

  EXPECT_EQ(cli_cmd_op_define(node, "bad_op", "invalid_type", NULL, NULL, NULL), CLI_ERR_ARGS);
}

TEST_F(TestCLI, OpDefineUninitialized) {
  EXPECT_EQ(cli_cmd_op_define(node, "vote", "per_user", "voters", NULL, NULL), CLI_ERR_NOT_INIT);
}

TEST_F(TestCLI, OpDefineNullParams) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_op_define(node, NULL, "per_user", "voters", NULL, NULL), CLI_ERR_ARGS);
  EXPECT_EQ(cli_cmd_op_define(node, "vote", NULL, "voters", NULL, NULL), CLI_ERR_ARGS);
}

TEST_F(TestCLI, OpCheckDedupPerUserPasses) {
  cli_node_init(node, "admin");
  cli_cmd_item_add(node, "voters", "one_shot_set");
  cli_cmd_op_define(node, "vote", "per_user", "voters", NULL, NULL);

  // Check dedup for "vote" by "alice" — should pass (empty set)
  EXPECT_EQ(cli_cmd_op_check_dedup(node, "vote", "alice"), CLI_OK);
}

TEST_F(TestCLI, OpCheckDedupGlobalPasses) {
  cli_node_init(node, "admin");
  cli_cmd_item_add(node, "executed", "one_shot_flag");
  cli_cmd_op_define(node, "execute_proposal", "global", NULL, "executed", NULL);

  // Check dedup for "execute_proposal" by "carol" — should pass (flag is false)
  EXPECT_EQ(cli_cmd_op_check_dedup(node, "execute_proposal", "carol"), CLI_OK);
}

TEST_F(TestCLI, OpCheckDedupNoSpecPasses) {
  cli_node_init(node, "admin");

  // No registered dedup spec for "unknown_op" — should pass
  EXPECT_EQ(cli_cmd_op_check_dedup(node, "unknown_op", "alice"), CLI_OK);
}

TEST_F(TestCLI, OpCheckDedupUninitialized) {
  EXPECT_EQ(cli_cmd_op_check_dedup(node, "vote", "alice"), CLI_ERR_NOT_INIT);
}

// ============================================================
// Dispatch tests for new op subcommands
// ============================================================

TEST_F(TestCLI, DispatchOpDefine) {
  cli_node_init(node, "admin");
  cli_cmd_item_add(node, "voters", "one_shot_set");

  char* argv[] = {(char*)"crabs_node", (char*)"op", (char*)"define",
                  (char*)"vote", (char*)"per_user", (char*)"voters"};
  EXPECT_EQ(cli_dispatch(node, 6, argv), CLI_OK);

  const dedup_spec_t* spec = state_find_op_type_def(&node->attr_machine->base_state, "vote");
  ASSERT_NE(spec, nullptr);
  EXPECT_EQ(spec->type, DEDUP_PER_USER);
}

TEST_F(TestCLI, DispatchOpCheckDedup) {
  cli_node_init(node, "admin");
  cli_cmd_item_add(node, "voters", "one_shot_set");

  char* define_argv[] = {(char*)"crabs_node", (char*)"op", (char*)"define",
                         (char*)"vote", (char*)"per_user", (char*)"voters"};
  EXPECT_EQ(cli_dispatch(node, 6, define_argv), CLI_OK);

  char* check_argv[] = {(char*)"crabs_node", (char*)"op", (char*)"check-dedup",
                         (char*)"vote", (char*)"alice"};
  EXPECT_EQ(cli_dispatch(node, 5, check_argv), CLI_OK);
}
// Regression for audit M-17: the CLI must sign operations with the signer's
// own custodied key, not the node key. A user without a CLI-custodied key
// cannot submit a valid op (it is left unsigned and rejected); a user whose
// key the CLI holds can.
TEST_F(TestCLI, OpSubmitSignsWithCustodiedKey) {
  cli_node_init(node, "admin");
  cli_cmd_item_add(node, "res1", "resource");
  state_add_policy(&node->attr_machine->base_state, CRABS_OP_LOCK, "");

  // Register alice with a CLI-custodied keypair.
  ecdsa_keypair_t* alice_key = crypto_ecdsa_generate();
  ASSERT_NE(alice_key, nullptr);
  char pk_hex[67];
  cli_bytes_to_hex(alice_key->public_key, 33, pk_hex);
  ASSERT_EQ(cli_cmd_user_register(node, "alice", pk_hex), CLI_OK);
  // Grant alice role:admin so she satisfies the (empty) policy is fine, but
  // for a role:admin policy she needs the attribute; use empty policy instead.
  ASSERT_EQ(cli_node_add_user_key(node, "alice", alice_key), CLI_OK);

  // Alice can submit because the CLI holds her key.
  EXPECT_EQ(cli_cmd_op_submit(node, CRABS_OP_LOCK, nullptr, "alice"), CLI_OK);

  // A user with no custodied key cannot submit (unsigned op is rejected).
  cli_cmd_user_register(node, "bob", pk_hex);
  EXPECT_NE(cli_cmd_op_submit(node, CRABS_OP_LOCK, nullptr, "bob"), CLI_OK);
}
