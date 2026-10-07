//
// Created by victor on 5/1/25.
//

#include <gtest/gtest.h>
#include <vector>
extern "C" {
#include "../src/CLI/cli.h"
#include "../src/CRABS/data_model.h"
#include "../src/Serialization/serialization.h"
#include "../src/CRDT/one_shot.h"
#include <openssl/sha.h>
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

// Durability (v10): cli_node_save persists a SEALED MSK and refuses to save
// without an imported at-rest seal key. Tests that save must import this
// fixed test seal key first (in-memory custody, never serialized).
static bool _apply_test_seal_key(cli_node_t* node) {
  const uint8_t test_seal_key[32] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
  };
  memcpy(node->seal_key, test_seal_key, sizeof(test_seal_key));
  node->seal_key_valid = true;
  return true;
}

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
  // Single live authority: the node keeps NO second master key instance —
  // the attribute machine's base_state.abe_mk is the only MSK.
  EXPECT_EQ(node->abe_mk, nullptr);
  EXPECT_NE(node->attr_machine->base_state.abe_mk, nullptr);
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
  // Audit H-B: node-blind rotation — supply the user's new public key.
  ecdsa_keypair_t* new_keypair = crypto_ecdsa_generate();
  char new_pk_hex[67];
  cli_bytes_to_hex(new_keypair->public_key, 33, new_pk_hex);
  EXPECT_EQ(cli_cmd_key_revoke(node, "alice", new_pk_hex), CLI_OK);

  crypto_ecdsa_keypair_destroy(keypair);
  crypto_ecdsa_keypair_destroy(new_keypair);
}

TEST_F(TestCLI, KeyRevokeNullUserId) {
  cli_node_init(node, "admin");
  EXPECT_EQ(cli_cmd_key_revoke(node, nullptr, nullptr), CLI_ERR_ARGS);
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
  ASSERT_TRUE(_apply_test_seal_key(node));

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
// Signed state blob tests (audit M-1: the plain SHA-256 checksum is
// integrity only — an attacker who can write the file can recompute it.
// cli_node_save must emit node-key-signed blobs and cli_node_load /
// cli_node_load_key must enforce the signature before custody).
// ============================================================

static bool test_read_file_bytes(const char* path, std::vector<uint8_t>& file_bytes) {
  FILE* f = fopen(path, "rb");
  if (f == NULL) return false;
  fseek(f, 0, SEEK_END);
  long file_size = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (file_size <= 0) {
    fclose(f);
    return false;
  }
  file_bytes.resize((size_t)file_size);
  size_t read_count = fread(file_bytes.data(), 1, file_bytes.size(), f);
  fclose(f);
  return read_count == file_bytes.size();
}

static bool test_write_file_bytes(const char* path, const std::vector<uint8_t>& file_bytes) {
  FILE* f = fopen(path, "wb");
  if (f == NULL) return false;
  size_t written = fwrite(file_bytes.data(), 1, file_bytes.size(), f);
  fclose(f);
  return written == file_bytes.size();
}

TEST_F(TestCLI, SaveLoadSignedRoundTripAuthenticates) {
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  ASSERT_TRUE(_apply_test_seal_key(node));
  ASSERT_EQ(cli_cmd_item_add(node, "counter1", "counter"), CLI_OK);

  // The operator persists the node private key out-of-band; capture it here
  // the same way an operator would hold it.
  char node_private_key_hex[65];
  cli_bytes_to_hex(node->node_key->private_key, 32, node_private_key_hex);

  const char* tmp_path = "/tmp/crabs_test_signed_state.bin";
  ASSERT_EQ(cli_node_save(node, tmp_path), CLI_OK);

  cli_node_t* loaded_node = cli_node_create();
  ASSERT_NE(loaded_node, nullptr);
  ASSERT_EQ(cli_node_load(loaded_node, tmp_path), CLI_OK);
  EXPECT_TRUE(loaded_node->initialized);
  // A signed snapshot is recognized but NOT trusted until the operator
  // proves custody of the signing key.
  EXPECT_TRUE(loaded_node->state_sig_pending);

  // Custody restore must authenticate the snapshot signature.
  EXPECT_EQ(cli_node_load_key(loaded_node, node_private_key_hex), CLI_OK);
  EXPECT_FALSE(loaded_node->state_sig_pending);

  remove(tmp_path);
  cli_node_destroy(loaded_node);
}

TEST_F(TestCLI, LoadRejectsTamperedSignedState) {
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  ASSERT_TRUE(_apply_test_seal_key(node));
  ASSERT_EQ(cli_cmd_item_add(node, "counter1", "counter"), CLI_OK);

  const char* tmp_path = "/tmp/crabs_test_tampered_state.bin";
  ASSERT_EQ(cli_node_save(node, tmp_path), CLI_OK);

  std::vector<uint8_t> file_bytes;
  ASSERT_TRUE(test_read_file_bytes(tmp_path, file_bytes));
  ASSERT_GT(file_bytes.size(), (size_t)CRABS_SIG_SIZE);

  // Flip one payload byte in the middle of the blob (away from the trailing
  // signature). The load must reject the blob outright.
  file_bytes[file_bytes.size() / 2] ^= 0x01;
  ASSERT_TRUE(test_write_file_bytes(tmp_path, file_bytes));

  cli_node_t* loaded_node = cli_node_create();
  ASSERT_NE(loaded_node, nullptr);
  EXPECT_EQ(cli_node_load(loaded_node, tmp_path), CLI_ERR_EXEC);
  EXPECT_FALSE(loaded_node->initialized);

  remove(tmp_path);
  cli_node_destroy(loaded_node);
}

TEST_F(TestCLI, KeyImportRejectsRechecksummedTamperedState) {
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  ASSERT_TRUE(_apply_test_seal_key(node));
  char node_private_key_hex[65];
  cli_bytes_to_hex(node->node_key->private_key, 32, node_private_key_hex);
  ASSERT_EQ(cli_cmd_item_add(node, "counter1", "counter"), CLI_OK);

  const char* tmp_path = "/tmp/crabs_test_rechecksummed_state.bin";
  ASSERT_EQ(cli_node_save(node, tmp_path), CLI_OK);

  std::vector<uint8_t> file_bytes;
  ASSERT_TRUE(test_read_file_bytes(tmp_path, file_bytes));
  ASSERT_GT(file_bytes.size(), (size_t)CRABS_SIG_SIZE + CRABS_HASH_SIZE);

  // An attacker with file-write access can recompute the SHA-256 integrity
  // checksum, so flip a payload byte and repair the checksum. Only the
  // node-key signature can catch this.
  size_t payload_len = file_bytes.size() - CRABS_SIG_SIZE;
  file_bytes[payload_len / 2] ^= 0x01;
  std::vector<uint8_t> checksum(CRABS_HASH_SIZE);
  SHA256(file_bytes.data(), payload_len - CRABS_HASH_SIZE, checksum.data());
  memcpy(file_bytes.data() + payload_len - CRABS_HASH_SIZE, checksum.data(),
         CRABS_HASH_SIZE);
  ASSERT_TRUE(test_write_file_bytes(tmp_path, file_bytes));

  cli_node_t* loaded_node = cli_node_create();
  ASSERT_NE(loaded_node, nullptr);
  // The blob parses (checksum repaired) and stays pending until key import.
  ASSERT_EQ(cli_node_load(loaded_node, tmp_path), CLI_OK);
  ASSERT_TRUE(loaded_node->state_sig_pending);

  // The ECDSA signature over the payload rejects the tampered snapshot.
  EXPECT_EQ(cli_node_load_key(loaded_node, node_private_key_hex), CLI_ERR_EXEC);
  EXPECT_TRUE(loaded_node->state_sig_pending);

  remove(tmp_path);
  cli_node_destroy(loaded_node);
}

TEST_F(TestCLI, LoadLegacyUnsignedStateStillWorks) {
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  ASSERT_EQ(cli_cmd_item_add(node, "counter1", "counter"), CLI_OK);

  // Legacy blobs written by older CLIs carry no signature trailer.
  serialized_buffer_t* legacy_blob =
      crabs_serialize_state(&node->attr_machine->base_state);
  ASSERT_NE(legacy_blob, nullptr);
  const char* tmp_path = "/tmp/crabs_test_legacy_state.bin";
  std::vector<uint8_t> file_bytes(legacy_blob->data,
                                  legacy_blob->data + legacy_blob->len);
  serialized_buffer_destroy(legacy_blob);
  ASSERT_TRUE(test_write_file_bytes(tmp_path, file_bytes));

  cli_node_t* loaded_node = cli_node_create();
  ASSERT_NE(loaded_node, nullptr);
  EXPECT_EQ(cli_node_load(loaded_node, tmp_path), CLI_OK);
  EXPECT_TRUE(loaded_node->initialized);
  EXPECT_FALSE(loaded_node->state_sig_pending);

  remove(tmp_path);
  cli_node_destroy(loaded_node);
}

TEST_F(TestCLI, SaveRefusesUnverifiedLoadedState) {
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  ASSERT_TRUE(_apply_test_seal_key(node));
  char node_private_key_hex[65];
  cli_bytes_to_hex(node->node_key->private_key, 32, node_private_key_hex);
  ASSERT_EQ(cli_cmd_item_add(node, "counter1", "counter"), CLI_OK);

  const char* tmp_path = "/tmp/crabs_test_resave_state.bin";
  ASSERT_EQ(cli_node_save(node, tmp_path), CLI_OK);

  cli_node_t* loaded_node = cli_node_create();
  ASSERT_NE(loaded_node, nullptr);
  ASSERT_EQ(cli_node_load(loaded_node, tmp_path), CLI_OK);
  ASSERT_TRUE(loaded_node->state_sig_pending);
  // Re-saving the verified snapshot also needs a seal key (same durability
  // contract as any save).
  ASSERT_TRUE(_apply_test_seal_key(loaded_node));

  // Do not persist state whose provenance is unverified: the save would
  // re-sign it with the ephemeral load-time key no one holds.
  EXPECT_EQ(cli_node_save(loaded_node, "/tmp/crabs_test_unverified_out.bin"),
            CLI_ERR_EXEC);

  // Once custody is proven the snapshot is authenticated and re-saving works.
  EXPECT_EQ(cli_node_load_key(loaded_node, node_private_key_hex), CLI_OK);
  const char* resave_path = "/tmp/crabs_test_resaved_state.bin";
  EXPECT_EQ(cli_node_save(loaded_node, resave_path), CLI_OK);

  // The re-saved blob is signed by the imported key and loads again.
  cli_node_t* reloaded_node = cli_node_create();
  ASSERT_NE(reloaded_node, nullptr);
  EXPECT_EQ(cli_node_load(reloaded_node, resave_path), CLI_OK);
  EXPECT_TRUE(reloaded_node->state_sig_pending);
  EXPECT_EQ(cli_node_load_key(reloaded_node, node_private_key_hex), CLI_OK);

  remove(tmp_path);
  remove(resave_path);
  cli_node_destroy(loaded_node);
  cli_node_destroy(reloaded_node);
}

// ============================================================
// Unauthenticated (unsigned) snapshot acknowledgment gate (audit: the
// operator's node key must not end up signing attacker-supplied state —
// save is refused until the operator explicitly acknowledges the
// unauthenticated load).
// ============================================================

TEST_F(TestCLI, SaveRefusesUnacknowledgedUnsignedState) {
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  ASSERT_EQ(cli_cmd_item_add(node, "counter1", "counter"), CLI_OK);

  // Legacy blobs written by older CLIs carry no signature trailer.
  serialized_buffer_t* legacy_blob =
      crabs_serialize_state(&node->attr_machine->base_state);
  ASSERT_NE(legacy_blob, nullptr);
  const char* tmp_path = "/tmp/crabs_test_unauth_state.bin";
  std::vector<uint8_t> file_bytes(legacy_blob->data,
                                  legacy_blob->data + legacy_blob->len);
  serialized_buffer_destroy(legacy_blob);
  ASSERT_TRUE(test_write_file_bytes(tmp_path, file_bytes));

  cli_node_t* loaded_node = cli_node_create();
  ASSERT_NE(loaded_node, nullptr);
  ASSERT_EQ(cli_node_load(loaded_node, tmp_path), CLI_OK);
  // The unsigned fallback must mark the snapshot unauthenticated.
  EXPECT_TRUE(loaded_node->loaded_unauthenticated);
  // Re-saving after acknowledgment also needs a seal key.
  ASSERT_TRUE(_apply_test_seal_key(loaded_node));

  // Save must refuse — re-saving would put THIS node's signature on
  // unauthenticated state (signature laundering).
  const char* resave_path = "/tmp/crabs_test_unauth_resaved.bin";
  EXPECT_EQ(cli_node_save(loaded_node, resave_path), CLI_ERR_EXEC);

  // After an explicit acknowledgment the save is allowed.
  EXPECT_EQ(cli_cmd_state_accept_unverified(loaded_node), CLI_OK);
  EXPECT_FALSE(loaded_node->loaded_unauthenticated);
  EXPECT_EQ(cli_node_save(loaded_node, resave_path), CLI_OK);

  remove(tmp_path);
  remove(resave_path);
  cli_node_destroy(loaded_node);
}

TEST_F(TestCLI, SignedVerifiedLoadNeedsNoAcknowledgment) {
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  ASSERT_TRUE(_apply_test_seal_key(node));
  ASSERT_EQ(cli_cmd_item_add(node, "counter1", "counter"), CLI_OK);
  char node_private_key_hex[65];
  cli_bytes_to_hex(node->node_key->private_key, 32, node_private_key_hex);

  const char* tmp_path = "/tmp/crabs_test_signed_gate_state.bin";
  ASSERT_EQ(cli_node_save(node, tmp_path), CLI_OK);

  cli_node_t* loaded_node = cli_node_create();
  ASSERT_NE(loaded_node, nullptr);
  ASSERT_EQ(cli_node_load(loaded_node, tmp_path), CLI_OK);
  // A signed snapshot is pending verification, not unauthenticated.
  EXPECT_TRUE(loaded_node->state_sig_pending);
  EXPECT_FALSE(loaded_node->loaded_unauthenticated);
  // Re-saving the verified snapshot also needs a seal key.
  ASSERT_TRUE(_apply_test_seal_key(loaded_node));

  // Save is gated on signature verification (existing M-1 behavior), and
  // once verified no acknowledgment is needed.
  EXPECT_EQ(cli_node_save(loaded_node, "/tmp/crabs_test_signed_gate_out.bin"),
            CLI_ERR_EXEC);
  ASSERT_EQ(cli_node_load_key(loaded_node, node_private_key_hex), CLI_OK);
  EXPECT_FALSE(loaded_node->loaded_unauthenticated);

  const char* resave_path = "/tmp/crabs_test_signed_gate_resaved.bin";
  EXPECT_EQ(cli_node_save(loaded_node, resave_path), CLI_OK);

  remove(tmp_path);
  remove(resave_path);
  cli_node_destroy(loaded_node);
}

TEST_F(TestCLI, AcceptUnverifiedOnFreshNodeIsHarmless) {
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  EXPECT_FALSE(node->loaded_unauthenticated);
  EXPECT_EQ(cli_cmd_state_accept_unverified(node), CLI_OK);
  EXPECT_FALSE(node->loaded_unauthenticated);
}

TEST_F(TestCLI, DispatchStateAcceptUnverifiedClearsGate) {
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  ASSERT_EQ(cli_cmd_item_add(node, "counter1", "counter"), CLI_OK);

  serialized_buffer_t* legacy_blob =
      crabs_serialize_state(&node->attr_machine->base_state);
  ASSERT_NE(legacy_blob, nullptr);
  const char* tmp_path = "/tmp/crabs_test_dispatch_unauth.bin";
  std::vector<uint8_t> file_bytes(legacy_blob->data,
                                  legacy_blob->data + legacy_blob->len);
  serialized_buffer_destroy(legacy_blob);
  ASSERT_TRUE(test_write_file_bytes(tmp_path, file_bytes));

  cli_node_t* loaded_node = cli_node_create();
  ASSERT_NE(loaded_node, nullptr);
  ASSERT_EQ(cli_node_load(loaded_node, tmp_path), CLI_OK);
  ASSERT_TRUE(loaded_node->loaded_unauthenticated);
  // Re-saving after acknowledgment also needs a seal key.
  ASSERT_TRUE(_apply_test_seal_key(loaded_node));

  const char* save_argv[] = {"crabs", "save", "/tmp/crabs_test_dispatch_out.bin"};
  EXPECT_EQ(cli_dispatch(loaded_node, 3, (char**)save_argv), CLI_ERR_EXEC);

  const char* accept_argv[] = {"crabs", "state", "accept-unverified"};
  EXPECT_EQ(cli_dispatch(loaded_node, 3, (char**)accept_argv), CLI_OK);
  EXPECT_FALSE(loaded_node->loaded_unauthenticated);

  const char* resave_argv[] = {"crabs", "save", "/tmp/crabs_test_dispatch_out.bin"};
  EXPECT_EQ(cli_dispatch(loaded_node, 3, (char**)resave_argv), CLI_OK);

  remove(tmp_path);
  remove("/tmp/crabs_test_dispatch_out.bin");
  cli_node_destroy(loaded_node);
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

// ============================================================
// Durability (v10): seal-key custody and the save fail-loud gate.
// Saving without an at-rest seal key would silently lose the machine's
// ABE master key (a reload gets a FRESH MSK and every previously issued
// envelope becomes garbage), so cli_node_save refuses.
// ============================================================

TEST(TestCliDurability, SaveRefusesWithoutSealKey) {
  cli_node_t* node = cli_node_create();
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  EXPECT_FALSE(node->seal_key_valid);
  EXPECT_NE(cli_node_save(node, "/tmp/crabs-noseal.crabs"), CLI_OK);
  // The refusal is a durability gate, not a transient error: still refused
  // after the operator retries without importing a key.
  EXPECT_NE(cli_node_save(node, "/tmp/crabs-noseal.crabs"), CLI_OK);
  cli_node_destroy(node);
}

TEST(TestCliDurability, SealKeyRoundTripPreservesUsersAndAuthority) {
  cli_node_t* node = cli_node_create();
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  ASSERT_TRUE(_apply_test_seal_key(node));
  // Register a second user through the attribute machine. initial_attrs
  // stays empty: register_user must not mint privileged "role:*" attributes
  // (R7-08) — attributes are granted via the admin grant path, not here.
  ecdsa_keypair_t* other = crypto_ecdsa_generate();
  ASSERT_NE(other, nullptr);
  ASSERT_EQ(attribute_machine_register_user(node->attr_machine, "writer",
            other->public_key, ""), CRABS_SUCCESS);
  crypto_ecdsa_keypair_destroy(other);

  ASSERT_EQ(cli_node_save(node, "/tmp/crabs-durable.crabs"), CLI_OK);
  cli_node_destroy(node);

  cli_node_t* reloaded = cli_node_create();
  const uint8_t test_seal_key[32] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
  };
  char seal_hex[65];
  cli_bytes_to_hex(test_seal_key, 32, seal_hex);
  seal_hex[64] = '\0';
  ASSERT_EQ(cli_node_load_sealed(reloaded, "/tmp/crabs-durable.crabs",
            seal_hex), CLI_OK);
  ASSERT_NE(attribute_machine_find_user(reloaded->attr_machine, "writer"),
            nullptr);
  ASSERT_NE(attribute_machine_find_user(reloaded->attr_machine, "admin"),
            nullptr);
  // Authority preserved: the reloaded MSK is in the same domain (it can
  // mint a user key that verifies against the machine's policy engine).
  user_t* writer =
      attribute_machine_find_user(reloaded->attr_machine, "writer");
  ASSERT_NE(writer, nullptr);
  // state_t::abe_mk is a type-erased void* in the data model; cast to the
  // concrete key type for keygen (same pattern as test_serialization.cpp).
  abe_user_key_t* sk = crypto_abe_keygen(
      (const abe_master_key_t*)reloaded->attr_machine->base_state.abe_mk,
      "role:writer");
  ASSERT_NE(sk, nullptr);
  crypto_abe_user_key_destroy(sk);
  cli_node_destroy(reloaded);
  remove("/tmp/crabs-durable.crabs");
}

TEST(TestCliDurability, SealKeyImportRejectsBadHex) {
  cli_node_t* node = cli_node_create();
  ASSERT_NE(node, nullptr);
  // Wrong length, invalid characters, and NULL are all refused; a refusal
  // must not leave a half-imported key behind.
  EXPECT_EQ(cli_node_set_seal_key(node, "abcd"), CLI_ERR_ARGS);
  EXPECT_EQ(cli_node_set_seal_key(node,
            "zz1111111111111111111111111111111111111111111111111111111111111"),
            CLI_ERR_ARGS);
  EXPECT_EQ(cli_node_set_seal_key(node, nullptr), CLI_ERR_ARGS);
  EXPECT_FALSE(node->seal_key_valid);
  cli_node_destroy(node);
}

TEST(TestCliDurability, KeyReimportFailureKeepsPreviousKey) {
  cli_node_t* node = cli_node_create();
  ASSERT_NE(node, nullptr);
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  ASSERT_TRUE(_apply_test_seal_key(node));

  // A failed re-import must leave the PREVIOUS key intact and valid.
  // cli_hex_to_bytes decodes incrementally, so a partial decode must never
  // touch the node's key storage.
  EXPECT_EQ(cli_node_set_seal_key(node,
            "zzzzffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            CLI_ERR_ARGS);
  EXPECT_TRUE(node->seal_key_valid);
  const uint8_t expected[32] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
  };
  EXPECT_EQ(memcmp(node->seal_key, expected, sizeof(expected)), 0);
  cli_node_destroy(node);
}

TEST(TestCliDurability, LoadSealedRejectsBadKeyHexBeforeReading) {
  cli_node_t* node = cli_node_create();
  ASSERT_NE(node, nullptr);
  // A malformed key hex is refused before any load attempt; no half-imported
  // seal key remains.
  EXPECT_EQ(cli_node_load_sealed(node, "/tmp/crabs-durable-should-not-exist",
            "abcd"), CLI_ERR_ARGS);
  EXPECT_FALSE(node->seal_key_valid);
  EXPECT_FALSE(node->initialized);
  cli_node_destroy(node);
}

TEST(TestCliDurability, LoadSealedFailClearsImportedKey) {
  cli_node_t* node = cli_node_create();
  ASSERT_NE(node, nullptr);
  // A failed load must not leave a half-imported seal key on the node.
  EXPECT_EQ(cli_node_load_sealed(node, "/tmp/crabs-nosuch-file-9876",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
            CLI_ERR_IO);
  EXPECT_FALSE(node->seal_key_valid);
  EXPECT_FALSE(node->initialized);
  cli_node_destroy(node);
}

// Dispatch wiring: 'seal-key import' reads the 64-hex-char key from a file
// and cleanses the hex buffer; the imported key then lets a save succeed.
TEST(TestCliDurability, DispatchSealKeyImportEnablesSave) {
  cli_node_t* node = cli_node_create();
  ASSERT_NE(node, nullptr);
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);

  const char* key_hex =
      "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
  const char* key_path = "/tmp/crabs_test_seal_key.hex";
  ASSERT_TRUE(test_write_file_bytes(key_path, std::vector<uint8_t>(
      key_hex, key_hex + strlen(key_hex))));

  char* import_argv[] = {(char*)"crabs", (char*)"seal-key", (char*)"import",
                         (char*)key_path};
  EXPECT_EQ(cli_dispatch(node, 4, import_argv), CLI_OK);
  EXPECT_TRUE(node->seal_key_valid);

  EXPECT_EQ(cli_node_save(node, "/tmp/crabs_test_sealed_dispatch.crabs"),
            CLI_OK);

  // save via dispatch works with the imported key too.
  char* save_argv[] = {(char*)"crabs", (char*)"save",
                       (char*)"/tmp/crabs_test_sealed_dispatch.crabs"};
  EXPECT_EQ(cli_dispatch(node, 3, save_argv), CLI_OK);

  remove(key_path);
  remove("/tmp/crabs_test_sealed_dispatch.crabs");
  cli_node_destroy(node);
}

TEST(TestCliDurability, DispatchSealKeyImportBadFileFails) {
  cli_node_t* node = cli_node_create();
  ASSERT_NE(node, nullptr);
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);

  // Missing file is an IO error; a short file is refused; the node keeps no
  // partial seal key in either case.
  char* missing_argv[] = {(char*)"crabs", (char*)"seal-key", (char*)"import",
                          (char*)"/tmp/crabs_no_such_seal_file"};
  EXPECT_EQ(cli_dispatch(node, 4, missing_argv), CLI_ERR_IO);
  EXPECT_FALSE(node->seal_key_valid);

  const char* key_path = "/tmp/crabs_test_short_seal_key.hex";
  ASSERT_TRUE(test_write_file_bytes(key_path, std::vector<uint8_t>(
      {'a', 'b', 'c', 'd'})));
  char* short_argv[] = {(char*)"crabs", (char*)"seal-key", (char*)"import",
                        (char*)key_path};
  EXPECT_EQ(cli_dispatch(node, 4, short_argv), CLI_ERR_IO);
  EXPECT_FALSE(node->seal_key_valid);
  remove(key_path);

  cli_node_destroy(node);
}

// ============================================================
// Durability (v10): v9->v10 migration. A legacy snapshot carries no user
// registry, so loading it restores the substrate with an EMPTY registry —
// the recorded bootstrap_admin id is the only trace of who held authority.
// 'state migrate' re-enrolls that admin (the §8.3 genesis equivalent) so the
// machine can execute admin operations again, and afterwards the machine can
// be saved sealed and reloaded with the admin intact.
// ============================================================

TEST(TestCliDurability, MigrateRebuildsBootstrapAdminOnLegacyLoad) {
  // 1. "Legacy" content: an unkeyed state whose config names an admin but
  //    whose user registry is empty (what every pre-v10 file restores to).
  state_t* legacy_state = state_create();
  ASSERT_NE(legacy_state, nullptr);
  strncpy(legacy_state->config.bootstrap_admin, "admin", CRABS_MAX_USER_ID - 1);
  serialized_buffer_t* legacy_blob = crabs_serialize_state(legacy_state);
  ASSERT_NE(legacy_blob, nullptr);
  state_destroy(legacy_state);
  ASSERT_TRUE(test_write_file_bytes("/tmp/crabs-legacy.crabs",
      std::vector<uint8_t>(legacy_blob->data,
                           legacy_blob->data + legacy_blob->len)));
  serialized_buffer_destroy(legacy_blob);

  // 2. Load it the way the loader handles empty-registry files: a bare state
  //    wrapped in a fresh attribute machine with no users.
  cli_node_t* node = cli_node_create();
  ASSERT_NE(node, nullptr);
  ASSERT_EQ(cli_node_load(node, "/tmp/crabs-legacy.crabs"), CLI_OK);
  EXPECT_EQ(node->attr_machine->user_count, 0u);
  ASSERT_EQ(attribute_machine_find_user(node->attr_machine, "admin"), nullptr)
      << "legacy load must start with no restored users";

  // 3. Migrate re-enrolls the bootstrap admin.
  ASSERT_EQ(cli_cmd_machine_migrate(node), CLI_OK);
  user_t* admin = attribute_machine_find_user(node->attr_machine, "admin");
  ASSERT_NE(admin, nullptr);
  EXPECT_EQ(admin->status, USER_ACTIVE);
  EXPECT_TRUE(attribute_machine_user_has_role(admin, "role"));
  EXPECT_EQ(admin->key_version, 1u);

  // Migration is idempotent-gated: a machine that now carries users is a
  // no-op.
  EXPECT_EQ(cli_cmd_machine_migrate(node), CLI_OK);

  // 4. Now save-able and durable: with a seal key the machine persists and
  //    reloads WITH the admin intact (authority survives restart). The
  //    legacy blob was unsigned, so the operator must acknowledge it first
  //    (fail-loud provenance gate).
  ASSERT_EQ(cli_cmd_state_accept_unverified(node), CLI_OK);
  ASSERT_TRUE(_apply_test_seal_key(node));
  ASSERT_EQ(cli_node_save(node, "/tmp/crabs-migrated.crabs"), CLI_OK);
  cli_node_destroy(node);

  cli_node_t* reloaded = cli_node_create();
  ASSERT_NE(reloaded, nullptr);
  const uint8_t test_seal_key[32] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
  };
  char seal_hex[65];
  cli_bytes_to_hex(test_seal_key, 32, seal_hex);
  seal_hex[64] = '\0';
  ASSERT_EQ(cli_node_load_sealed(reloaded, "/tmp/crabs-migrated.crabs",
            seal_hex), CLI_OK);
  admin = attribute_machine_find_user(reloaded->attr_machine, "admin");
  ASSERT_NE(admin, nullptr);
  EXPECT_EQ(admin->status, USER_ACTIVE);
  EXPECT_TRUE(attribute_machine_user_has_role(admin, "role"));
  cli_node_destroy(reloaded);

  remove("/tmp/crabs-legacy.crabs");
  remove("/tmp/crabs-migrated.crabs");
}
