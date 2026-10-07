// Durability (v10) restart round-trip: a full CLI machine — identity registry,
// custom op dedup registry, policies, log — survives save (sealed MSK),
// destroy and load, and the reloaded machine still AUTHORIZES the writer.
// Exercises the real custody path end to end: cli_node_init, seal-key
// import, cli_node_save, cli_node_load_sealed.

#include <gtest/gtest.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "../src/CLI/cli.h"
#include "../src/Crypto/crypto.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Scheduler/scheduler.h"
#include "../src/Lineage/lineage.h"
#include "../src/Serialization/serialization.h"
}
#include "test_helpers.h"

// Fixed at-rest seal key (same test constant as test_cli.cpp). Never
// serialized — imported through the custody API on both sides of the restart.
static const uint8_t test_seal_key[32] = {
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
};

static void _import_test_seal_key(cli_node_t* node, char seal_hex[65]) {
  cli_bytes_to_hex(test_seal_key, 32, seal_hex);
  seal_hex[64] = '\0';
  ASSERT_EQ(cli_node_set_seal_key(node, seal_hex), CLI_OK);
}

TEST(TestDurability, FullMachineSurvivesRestartAndKeepsAuthority) {
  // ------------------------------------------------------------------
  // 1. Live machine through the CLI layer with seal-key custody.
  // ------------------------------------------------------------------
  cli_node_t* node = cli_node_create();
  ASSERT_NE(node, nullptr);
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);

  char seal_hex[65];
  _import_test_seal_key(node, seal_hex);

  // ------------------------------------------------------------------
  // 2. Second user: register with EMPTY attrs (R7-08 forbids privileged
  //    attrs at registration) and grant role:writer via the admin path.
  //    The CLI keyring takes ownership of the writer's ECDSA keypair.
  // ------------------------------------------------------------------
  ecdsa_keypair_t* writer_key = crypto_ecdsa_generate();
  ASSERT_NE(writer_key, nullptr);
  ASSERT_EQ(attribute_machine_register_user(node->attr_machine, "writer",
            writer_key->public_key, ""), CRABS_SUCCESS);
  ASSERT_EQ(attribute_machine_grant_role(node->attr_machine, "writer",
            "role", "writer", "admin"), CRABS_SUCCESS);
  user_t* writer = attribute_machine_find_user(node->attr_machine, "writer");
  ASSERT_NE(writer, nullptr);
  ASSERT_TRUE(attribute_machine_user_has_role(writer, "role"));
  ASSERT_EQ(cli_node_add_user_key(node, "writer", writer_key), CLI_OK);

  // ------------------------------------------------------------------
  // 3. Register a custom op "heartbeat" (DEDUP_NONE spec — exercises the
  //    v10 op_type_defs section) and a policy allowing writers or admins
  //    (R7-09 infix form: uppercase OR).
  // ------------------------------------------------------------------
  state_t* live = &node->attr_machine->base_state;
  dedup_spec_t spec;
  memset(&spec, 0, sizeof(spec));
  spec.type = DEDUP_NONE;
  ASSERT_EQ(state_register_op_type_def(live, "heartbeat", &spec),
            CRABS_SUCCESS);
  ASSERT_EQ(state_add_policy(live, "heartbeat", "role:writer OR role:admin"),
            CRABS_SUCCESS);

  // ------------------------------------------------------------------
  // 4. Execute "heartbeat" as the writer: sign with the custodied key and
  //    run through state_machine_execute (the submission path the op tests
  //    use). The signature binds the op to the writer's registered key.
  // ------------------------------------------------------------------
  operation_t* op = operation_create("heartbeat");
  ASSERT_NE(op, nullptr);
  memset(op->uuid, 0xA1, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "writer", CRABS_MAX_USER_ID - 1);
  // Lamport ordering is per-signer monotonic (R7-11): stamp explicit times
  // so the pre- and post-restart ops strictly increase.
  op->lamport_time = 1;
  crabs_test_sign_op_with(node->attr_machine, writer_key, op);
  ASSERT_EQ(state_machine_execute(live, op), CRABS_SUCCESS);
  operation_destroy(op);

  // ------------------------------------------------------------------
  // 5. Capture what must survive, snapshot the writer key material
  //    (the keypair OBJECT now belongs to the node and is freed with it),
  //    save sealed, destroy.
  // ------------------------------------------------------------------
  const uint64_t original_log_count = live->log_count;
  ASSERT_GT(original_log_count, (uint64_t)0);
  ecdsa_keypair_t writer_key_snapshot = *writer_key;

  ASSERT_EQ(cli_node_save(node, "/tmp/crabs-integration.crabs"), CLI_OK);
  cli_node_destroy(node);  // frees writer_key — must not free it again

  // ------------------------------------------------------------------
  // 6. Reload with the same seal key through the sealed-load path.
  // ------------------------------------------------------------------
  cli_node_t* reloaded = cli_node_create();
  ASSERT_NE(reloaded, nullptr);
  ASSERT_EQ(cli_node_load_sealed(reloaded, "/tmp/crabs-integration.crabs",
            seal_hex), CLI_OK);

  // ------------------------------------------------------------------
  // 7. Identity and machine state survived.
  // ------------------------------------------------------------------
  user_t* admin_restored =
      attribute_machine_find_user(reloaded->attr_machine, "admin");
  user_t* writer_restored =
      attribute_machine_find_user(reloaded->attr_machine, "writer");
  ASSERT_NE(admin_restored, nullptr);
  ASSERT_NE(writer_restored, nullptr);
  EXPECT_TRUE(attribute_machine_user_has_role(writer_restored, "role"));
  // The registry restored the SAME identity key, not a regenerated one.
  EXPECT_EQ(memcmp(writer_restored->public_key, writer_key_snapshot.public_key,
                   sizeof(writer_key_snapshot.public_key)), 0);

  const dedup_spec_t* restored_spec = state_find_op_type_def(
      &reloaded->attr_machine->base_state, "heartbeat");
  ASSERT_NE(restored_spec, nullptr);
  EXPECT_EQ(restored_spec->type, DEDUP_NONE);
  EXPECT_EQ(reloaded->attr_machine->base_state.log_count, original_log_count);
  // Authority: the machine's ABE master key survived the seal/unseal.
  EXPECT_NE(reloaded->attr_machine->base_state.abe_mk, nullptr);

  // ------------------------------------------------------------------
  // 8. THE assertion — authority survived: the writer can still act on the
  //    reloaded machine. Build a FRESH custody object holding the writer's
  //    identity key (the original object was freed with the first node);
  //    Mode A verification binds the signature to the registered public
  //    key, so the reloaded signing key must be that same key.
  // ------------------------------------------------------------------
  ecdsa_keypair_t* restored_writer_key =
      (ecdsa_keypair_t*)malloc(sizeof(ecdsa_keypair_t));
  ASSERT_NE(restored_writer_key, nullptr);
  *restored_writer_key = writer_key_snapshot;
  ASSERT_EQ(cli_node_add_user_key(reloaded, "writer", restored_writer_key),
            CLI_OK);

  operation_t* op2 = operation_create("heartbeat");
  ASSERT_NE(op2, nullptr);
  memset(op2->uuid, 0xA2, CRABS_UUID_SIZE);
  strncpy(op2->signer_id, "writer", CRABS_MAX_USER_ID - 1);
  op2->lamport_time = 2;
  crabs_test_sign_op_with(reloaded->attr_machine, restored_writer_key, op2);
  EXPECT_EQ(state_machine_execute(&reloaded->attr_machine->base_state, op2),
            CRABS_SUCCESS);
  operation_destroy(op2);

  // Fail closed: a DIFFERENT identity cannot ride the restored registry —
  // a signature that does not verify against the writer's registered key
  // is rejected even with an intact user record and policy.
  ecdsa_keypair_t* stranger_key = crypto_ecdsa_generate();
  ASSERT_NE(stranger_key, nullptr);
  operation_t* op3 = operation_create("heartbeat");
  ASSERT_NE(op3, nullptr);
  memset(op3->uuid, 0xA3, CRABS_UUID_SIZE);
  strncpy(op3->signer_id, "writer", CRABS_MAX_USER_ID - 1);
  op3->lamport_time = 3;
  crabs_test_sign_op_with(reloaded->attr_machine, stranger_key, op3);
  EXPECT_EQ(state_machine_execute(&reloaded->attr_machine->base_state, op3),
            CRABS_ERR_UNAUTHORIZED);
  operation_destroy(op3);
  crypto_ecdsa_keypair_destroy(stranger_key);

  cli_node_destroy(reloaded);
  remove("/tmp/crabs-integration.crabs");
}

// A pending timed transaction (schedules, v6 section) must survive the sealed
// save/load cycle AND be released exactly once by the CLI destroy path — the
// loaded state's schedules are owned by the attribute-machine teardown.
TEST(TestDurability, RestoredScheduleSurvivesRestartAndDestroy) {
  cli_node_t* node = cli_node_create();
  ASSERT_NE(node, nullptr);
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);

  char seal_hex[65];
  _import_test_seal_key(node, seal_hex);

  state_t* live = &node->attr_machine->base_state;
  operation_t* op = operation_create("heartbeat");
  ASSERT_NE(op, nullptr);
  memset(op->uuid, 0xB1, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  const uint64_t far_future_execute_at_ms = 9000000000000ULL;
  uint64_t schedule_id =
      scheduler_schedule(live, far_future_execute_at_ms, "admin", op);
  ASSERT_NE(schedule_id, 0u);
  operation_destroy(op);

  ASSERT_EQ(cli_node_save(node, "/tmp/crabs-schedule.crabs"), CLI_OK);
  cli_node_destroy(node);

  cli_node_t* reloaded = cli_node_create();
  ASSERT_NE(reloaded, nullptr);
  ASSERT_EQ(cli_node_load_sealed(reloaded, "/tmp/crabs-schedule.crabs",
            seal_hex), CLI_OK);

  state_t* restored = &reloaded->attr_machine->base_state;
  const scheduled_operation_t* restored_schedule = restored->scheduled_operations;
  ASSERT_NE(restored_schedule, nullptr);
  EXPECT_EQ(restored_schedule->schedule_id, schedule_id);
  EXPECT_EQ(restored_schedule->execute_at_ms, far_future_execute_at_ms);
  EXPECT_STREQ(restored_schedule->submitter, "admin");
  EXPECT_EQ(restored->scheduled_operations->next, nullptr);

  cli_node_destroy(reloaded);
  remove("/tmp/crabs-schedule.crabs");
}

// ============================================================
// Lineage (v1.7) durability: spawn a delegated child, save BOTH machines
// (parent through the CLI sealed+signed path, child as a raw sealed+signed
// state snapshot), destroy everything, then prove the whole lineage stack
// comes back:
//   - the parent's manifest entry (child_id / mode / status / ttl) and the
//     genesis provenance — the genesis hash and the parent's ECDSA genesis
//     signature still verify against the RELOADED parent's node public key;
//   - the parent's snapshot signature verifies via cli_node_load_key;
//   - the child's sealed MSK survived (authority_restored) along with its
//     parent binding, and the child's OWN authority still authorizes its
//     bootstrap admin's ops;
//   - the runtime-only fields are gone (no resident child), while the
//     DURABLE lineage memory refuses to re-spawn the same child_id.
// ============================================================

TEST(TestDurability, LineageSurvivesRestartWithManifestSignatureVerified) {
  const char* parent_path = "/tmp/crabs-lineage-parent.crabs";
  const char* child_path = "/tmp/crabs-lineage-child.crabs";

  // ------------------------------------------------------------------
  // 1. Parent machine through the CLI layer: node key, seal key, the
  //    lineage op installer.
  // ------------------------------------------------------------------
  cli_node_t* node = cli_node_create();
  ASSERT_NE(node, nullptr);
  ASSERT_EQ(cli_node_init(node, "parent-root"), CLI_OK);

  char seal_hex[65];
  _import_test_seal_key(node, seal_hex);
  lineage_install(&node->attr_machine->base_state);

  // Capture the parent node key material BEFORE destroy: the genesis admin
  // of a delegated child is registered against the parent's node public key
  // (the parent vouches for its genesis admin), and the private key signs
  // both the parent snapshot and every op the child's bootstrap admin
  // submits. The hex re-imports via cli_node_load_key after the restart.
  ecdsa_keypair_t parent_key_snapshot = *node->node_key;
  char parent_priv_hex[65];
  cli_bytes_to_hex(parent_key_snapshot.private_key, 32, parent_priv_hex);
  parent_priv_hex[64] = '\0';
  uint8_t parent_pub_snapshot[33];
  memcpy(parent_pub_snapshot, parent_key_snapshot.public_key, 33);

  state_t* parent_state = &node->attr_machine->base_state;

  // ------------------------------------------------------------------
  // 2. Blueprint (child "protocol-red", DELEGATED_COPY) and DIRECT spawn.
  // ------------------------------------------------------------------
  machine_blueprint_t* blueprint = machine_blueprint_create();
  ASSERT_NE(blueprint, nullptr);
  strncpy(blueprint->child_id, "protocol-red", sizeof(blueprint->child_id) - 1);
  blueprint->trust_mode = LINEAGE_DELEGATED_COPY;
  strncpy(blueprint->bootstrap_admin, "child-admin",
          sizeof(blueprint->bootstrap_admin) - 1);
  blueprint->attestation_ttl_ms = 3600000;
  ASSERT_EQ(blueprint_add_item(blueprint, "counter", DATA_TYPE_COUNTER,
                               CRDT_G_COUNTER), CRABS_SUCCESS);
  ASSERT_EQ(blueprint_add_policy(blueprint, "increment", "role:child-admin"),
            CRABS_SUCCESS);
  dedup_spec_t counter_dedup;
  memset(&counter_dedup, 0, sizeof(counter_dedup));
  counter_dedup.type = DEDUP_NONE;
  ASSERT_EQ(blueprint_add_op_type_def(blueprint, "increment", &counter_dedup),
            CRABS_SUCCESS);
  ASSERT_EQ(lineage_blueprint_validate(blueprint), CRABS_SUCCESS);

  attribute_machine_t* child = nullptr;
  ASSERT_EQ(lineage_spawn_machine(parent_state, blueprint, &child),
            CRABS_SUCCESS);
  ASSERT_NE(child, nullptr);
  state_t* child_state = &child->base_state;
  ASSERT_EQ(parent_state->child_count, 1u);

  // ------------------------------------------------------------------
  // 3. Verify the genesis provenance CRYPTOGRAPHICALLY while the child is
  //    pristine: the manifest's genesis hash must equal the canonical
  //    unkeyed serialization of the child state, and the stored genesis
  //    signature must verify against the parent's node public key. After
  //    this snapshot the child registry is granted an extra role, which
  //    changes the canonical image — that is expected and safe.
  // ------------------------------------------------------------------
  const child_manifest_entry_t* manifest_entry = &parent_state->children[0];
  serialized_buffer_t* genesis_blob = crabs_serialize_state(child_state);
  ASSERT_NE(genesis_blob, nullptr);
  uint8_t recomputed_genesis_hash[CRABS_HASH_SIZE];
  ASSERT_EQ(crypto_sha256(genesis_blob->data, genesis_blob->len,
                          recomputed_genesis_hash), CRABS_SUCCESS);
  EXPECT_EQ(memcmp(recomputed_genesis_hash,
                   manifest_entry->genesis_snapshot_hash, CRABS_HASH_SIZE), 0);
  EXPECT_TRUE(crypto_ecdsa_verify(parent_pub_snapshot, genesis_blob->data,
                                  genesis_blob->len,
                                  manifest_entry->genesis_attestation_signature));
  serialized_buffer_destroy(genesis_blob);

  // The delegated child's bootstrap admin holds role:admin from genesis. The
  // blueprint's "increment" policy wants "role:child-admin" — grant the
  // additional attribute in the child's OWN registry (two-step pattern:
  // register + admin grant) so the policy authorizes without any parent
  // involvement.
  ASSERT_EQ(attribute_machine_grant_role(child, "child-admin", "role",
                                         "child-admin", "child-admin"),
            CRABS_SUCCESS);

  // ------------------------------------------------------------------
  // 4. Give the child a node key of its OWN (distinct from the parent's)
  //    so the child's sealed snapshot carries the signed trailer, then
  //    persist the child directly: crabs_serialize_state_sealed_signed over
  //    the child's base_state, written to disk byte for byte.
  // ------------------------------------------------------------------
  ecdsa_keypair_t* child_node_key = crypto_ecdsa_generate();
  ASSERT_NE(child_node_key, nullptr);
  ASSERT_EQ(state_set_node_key(child_state, child_node_key->private_key,
                               child_node_key->public_key), CRABS_SUCCESS);
  ecdsa_keypair_t child_node_key_snapshot = *child_node_key;

  serialized_buffer_t* child_blob = crabs_serialize_state_sealed_signed(
      child_state, test_seal_key);
  ASSERT_NE(child_blob, nullptr);
  FILE* child_file = fopen(child_path, "wb");
  ASSERT_NE(child_file, nullptr);
  ASSERT_EQ(fwrite(child_blob->data, 1, child_blob->len, child_file),
            child_blob->len);
  fclose(child_file);
  const size_t child_blob_len = child_blob->len;
  serialized_buffer_destroy(child_blob);

  // ------------------------------------------------------------------
  // 5. Save the parent through the CLI (sealed + signed via the centralized
  //    composition) and capture what must survive the restart.
  // ------------------------------------------------------------------
  ASSERT_EQ(cli_node_save(node, parent_path), CLI_OK);
  child_manifest_entry_t manifest_snapshot = parent_state->children[0];

  // Destroy BOTH machines — child first, then the parent. The parent's
  // resident-children registry still holds the (now-dangling) child slot
  // until this destroy; parent teardown frees the pointer array only.
  attribute_machine_destroy(child);
  crypto_ecdsa_keypair_destroy(child_node_key);
  cli_node_destroy(node);

  // ------------------------------------------------------------------
  // 6. Reload the parent with the same seal key, then re-import the saved
  //    node key: cli_node_load_key must VERIFY the snapshot's pending
  //    signature before granting custody (audit M-1) — that is the
  //    manifest-signature verification this test is named for.
  // ------------------------------------------------------------------
  cli_node_t* reloaded = cli_node_create();
  ASSERT_NE(reloaded, nullptr);
  ASSERT_EQ(cli_node_load_sealed(reloaded, parent_path, seal_hex), CLI_OK);
  ASSERT_EQ(cli_node_load_key(reloaded, parent_priv_hex), CLI_OK);

  state_t* reloaded_parent = &reloaded->attr_machine->base_state;
  EXPECT_TRUE(reloaded_parent->node_key_valid);
  EXPECT_EQ(memcmp(reloaded_parent->node_public_key, parent_pub_snapshot, 33),
            0);

  // ------------------------------------------------------------------
  // 7. Manifest integrity: the v11 child manifest came through the sealed
  //    snapshot untouched, and lineage_query_children exposes it.
  // ------------------------------------------------------------------
  const child_manifest_entry_t* restored_entries = nullptr;
  ASSERT_EQ(lineage_query_children(reloaded_parent, &restored_entries), 1u);
  ASSERT_NE(restored_entries, nullptr);
  EXPECT_STREQ(restored_entries[0].child_id, "protocol-red");
  EXPECT_EQ(restored_entries[0].mode, LINEAGE_DELEGATED_COPY);
  EXPECT_EQ(restored_entries[0].status, LINEAGE_ACTIVE);
  EXPECT_EQ(restored_entries[0].attestation_ttl_ms, 3600000u);
  EXPECT_EQ(memcmp(restored_entries[0].genesis_snapshot_hash,
                   manifest_snapshot.genesis_snapshot_hash, CRABS_HASH_SIZE),
            0);
  EXPECT_EQ(memcmp(restored_entries[0].genesis_attestation_signature,
                   manifest_snapshot.genesis_attestation_signature,
                   CRABS_SIG_SIZE), 0);

  // Runtime-only registry is GONE after a restart.
  EXPECT_EQ(lineage_query_resident_child(reloaded_parent, "protocol-red"),
            nullptr);
  EXPECT_EQ(reloaded_parent->resident_child_count, 0u);

  // ...but the durable lineage memory REMEMBERS: re-spawning the same
  // child_id is refused as a duplicate — the parent cannot mint a second
  // "protocol-red" from a manifest that outlived the process.
  machine_blueprint_t* respawn = machine_blueprint_create();
  ASSERT_NE(respawn, nullptr);
  strncpy(respawn->child_id, "protocol-red", sizeof(respawn->child_id) - 1);
  respawn->trust_mode = LINEAGE_DELEGATED_COPY;
  strncpy(respawn->bootstrap_admin, "child-admin",
          sizeof(respawn->bootstrap_admin) - 1);
  respawn->attestation_ttl_ms = 3600000;
  ASSERT_EQ(blueprint_add_item(respawn, "counter", DATA_TYPE_COUNTER,
                               CRDT_G_COUNTER), CRABS_SUCCESS);
  ASSERT_EQ(blueprint_add_policy(respawn, "increment", "role:child-admin"),
            CRABS_SUCCESS);
  ASSERT_EQ(blueprint_add_op_type_def(respawn, "increment", &counter_dedup),
            CRABS_SUCCESS);
  attribute_machine_t* respawn_child = nullptr;
  EXPECT_EQ(lineage_spawn_machine(reloaded_parent, respawn, &respawn_child),
            CRABS_ERR_DUPLICATE_OPERATION);

  // ------------------------------------------------------------------
  // 8. Reload the child from its own sealed+signed snapshot: verify the
  //    child's snapshot signature against the child's node key, then load
  //    with restoration reporting — the child's OWN MSK must come back.
  // ------------------------------------------------------------------
  FILE* child_file_read = fopen(child_path, "rb");
  ASSERT_NE(child_file_read, nullptr);
  fseek(child_file_read, 0, SEEK_END);
  long child_file_len = ftell(child_file_read);
  ASSERT_GT(child_file_len, 0L);
  fseek(child_file_read, 0, SEEK_SET);
  std::vector<uint8_t> child_bytes((size_t)child_file_len);
  ASSERT_EQ(fread(child_bytes.data(), 1, child_bytes.size(), child_file_read),
            child_bytes.size());
  fclose(child_file_read);
  ASSERT_EQ(child_bytes.size(), child_blob_len);

  // The signed trailer is the last CRABS_SIG_SIZE bytes; verify it against
  // the child's node public key BEFORE parsing.
  ASSERT_GT(child_bytes.size(), (size_t)CRABS_SIG_SIZE);
  size_t child_payload_len = child_bytes.size() - CRABS_SIG_SIZE;
  EXPECT_TRUE(crypto_ecdsa_verify(child_node_key_snapshot.public_key,
                                  child_bytes.data(), child_payload_len,
                                  child_bytes.data() + child_payload_len));

  bool authority_restored = false;
  bool msk_section_present = false;
  state_t* restored_child = crabs_deserialize_state_keys_reported(
      child_bytes.data(), child_payload_len, test_seal_key,
      &authority_restored, &msk_section_present);
  ASSERT_NE(restored_child, nullptr);
  EXPECT_TRUE(msk_section_present);
  // THE authority assertion: the child's OWN master key survived the seal /
  // unseal round trip.
  EXPECT_TRUE(authority_restored);
  ASSERT_NE(restored_child->abe_mk, nullptr);

  // The parent binding is intact on the reloaded child.
  EXPECT_TRUE(restored_child->lineage_parent_bound);
  EXPECT_STREQ(restored_child->lineage_parent_id, "parent-root");
  EXPECT_STREQ(restored_child->lineage_self_id, "protocol-red");
  EXPECT_EQ(memcmp(restored_child->lineage_parent_public_key,
                   parent_pub_snapshot, 33), 0);
  // The child has no children of its own.
  EXPECT_EQ(restored_child->child_count, 0u);
  const child_manifest_entry_t* empty_entries = nullptr;
  EXPECT_EQ(lineage_query_children(restored_child, &empty_entries), 0u);

  // ------------------------------------------------------------------
  // 9. The reloaded child still AUTHORIZES under its OWN authority: the
  //    bootstrap admin "child-admin" (registered at genesis against the
  //    parent's node public key) executes "increment" on the reloaded child
  //    state — no parent machine involved.
  // ------------------------------------------------------------------
  operation_t* reloaded_op = operation_create("increment");
  ASSERT_NE(reloaded_op, nullptr);
  memset(reloaded_op->uuid, 0xC1, CRABS_UUID_SIZE);
  strncpy(reloaded_op->signer_id, "child-admin", CRABS_MAX_USER_ID - 1);
  reloaded_op->lamport_time = 1;
  crabs_test_sign_op_with(restored_child->attr_machine, &parent_key_snapshot,
                          reloaded_op);
  EXPECT_EQ(state_machine_execute(restored_child, reloaded_op),
            CRABS_SUCCESS);
  operation_destroy(reloaded_op);

  machine_blueprint_destroy(blueprint);
  machine_blueprint_destroy(respawn);
  cli_node_destroy(reloaded);
  state_destroy(restored_child);
  remove(parent_path);
  remove(child_path);
}

// ============================================================
// Lineage surfaces (v1.7) end to end: the WHOLE surface chain is exercised
// through cli_dispatch exactly as an operator types it — blueprint
// authoring, blueprint save, spawn via the op pipeline, `machine children`,
// attest (printed wire re-verified), then a REAL restart: both machines
// saved (parent sealed+signed through the CLI custody path, child as its
// own sealed+signed snapshot), everything destroyed, both reloaded, the
// child manifest consulted through dispatch again, and the lifecycle
// continued with a dissolve (+ its de-duplicated refusal).
// ============================================================

// The longest even-length run of lowercase-hex characters captured from the
// redirected stdout — the printed attestation wire (same extractor shape as
// test_cli.cpp; the command prints no other hex string near that length).
static std::vector<uint8_t> test_extract_hex_wire(const std::string& captured) {
  static const std::string hex_lower = "0123456789abcdef";
  size_t best_start = std::string::npos;
  size_t best_len = 0;
  size_t run_start = 0;
  for (size_t cursor = 0; cursor <= captured.size(); cursor++) {
    bool is_hex = cursor < captured.size() &&
                  hex_lower.find(captured[cursor]) != std::string::npos;
    if (!is_hex) {
      size_t run_len = cursor - run_start;
      if (run_len % 2 == 0 && run_len > best_len) {
        best_len = run_len;
        best_start = run_start;
      }
      run_start = cursor + 1;
    }
  }
  std::vector<uint8_t> wire;
  for (size_t byte_index = 0; byte_index < best_len / 2; byte_index++) {
    std::string byte_text = captured.substr(best_start + byte_index * 2, 2);
    wire.push_back((uint8_t)std::strtol(byte_text.c_str(), nullptr, 16));
  }
  return wire;
}

// Read a whole file back (the durability round trips below re-import saved
// bytes byte for byte).
static bool test_read_saved_bytes(const char* path,
                                  std::vector<uint8_t>& file_bytes) {
  FILE* saved_file = fopen(path, "rb");
  if (saved_file == NULL) return false;
  fseek(saved_file, 0, SEEK_END);
  long saved_size = ftell(saved_file);
  fseek(saved_file, 0, SEEK_SET);
  if (saved_size <= 0) {
    fclose(saved_file);
    return false;
  }
  file_bytes.resize((size_t)saved_size);
  size_t read_count = fread(file_bytes.data(), 1, file_bytes.size(), saved_file);
  fclose(saved_file);
  return read_count == file_bytes.size();
}

TEST(TestDurability, LineageSurfacesEndToEnd) {
  const char* parent_path = "/tmp/crabs-e2e-parent.crabs";
  const char* child_path = "/tmp/crabs-e2e-child.crabs";
  const char* blueprint_path = "/tmp/crabs-e2e.cbp";

  // ------------------------------------------------------------------
  // 1. Parent through the CLI layer: seal-key custody + the lineage op
  //    installer (the CLI never installs lineage itself — the spawning
  //    protocol calls lineage_install, as the machine usage note documents).
  // ------------------------------------------------------------------
  cli_node_t* node = cli_node_create();
  ASSERT_NE(node, nullptr);
  ASSERT_EQ(cli_node_init(node, "parent-root"), CLI_OK);

  char seal_hex[65];
  _import_test_seal_key(node, seal_hex);
  lineage_install(&node->attr_machine->base_state);

  // Node key material is persisted out-of-band by the operator and
  // re-imported via cli_node_load_key after the restart.
  char parent_priv_hex[65];
  cli_bytes_to_hex(node->node_key->private_key, 32, parent_priv_hex);
  parent_priv_hex[64] = '\0';
  uint8_t parent_pub_snapshot[33];
  memcpy(parent_pub_snapshot, node->node_key->public_key, 33);

  // ------------------------------------------------------------------
  // 2. Blueprint authoring entirely through dispatch: draft → item →
  //    policy → dedup → save. The child policy names role:admin — the
  //    DELEGATED_COPY genesis registers its bootstrap admin ("child-admin")
  //    with role:admin under the parent's node public key.
  // ------------------------------------------------------------------
  char* new_argv[] = {(char*)"crabs_node", (char*)"machine", (char*)"blueprint",
                      (char*)"new", (char*)"child-red", (char*)"delegated",
                      (char*)"child-admin", (char*)"3600000"};
  ASSERT_EQ(cli_dispatch(node, 8, new_argv), CLI_OK);
  char* item_argv[] = {(char*)"crabs_node", (char*)"machine", (char*)"blueprint",
                       (char*)"item", (char*)"counter1", (char*)"counter",
                       (char*)"g_counter"};
  ASSERT_EQ(cli_dispatch(node, 7, item_argv), CLI_OK);
  char* policy_argv[] = {(char*)"crabs_node", (char*)"machine", (char*)"blueprint",
                         (char*)"policy", (char*)"increment", (char*)"role:admin"};
  ASSERT_EQ(cli_dispatch(node, 6, policy_argv), CLI_OK);
  char* dedup_argv[] = {(char*)"crabs_node", (char*)"machine", (char*)"blueprint",
                        (char*)"dedup", (char*)"increment", (char*)"none"};
  ASSERT_EQ(cli_dispatch(node, 6, dedup_argv), CLI_OK);
  char* save_argv[] = {(char*)"crabs_node", (char*)"machine", (char*)"blueprint",
                       (char*)"save", (char*)blueprint_path};
  ASSERT_EQ(cli_dispatch(node, 5, save_argv), CLI_OK);

  // ------------------------------------------------------------------
  // 3. Spawn via the op pipeline (__spawn_machine__ carries the wire image).
  // ------------------------------------------------------------------
  char* spawn_argv[] = {(char*)"crabs_node", (char*)"machine", (char*)"spawn",
                        (char*)blueprint_path};
  ASSERT_EQ(cli_dispatch(node, 4, spawn_argv), CLI_OK);

  state_t* parent_state = &node->attr_machine->base_state;
  const child_manifest_entry_t* manifest_entries = NULL;
  ASSERT_EQ(lineage_query_children(parent_state, &manifest_entries), 1u);
  ASSERT_NE(manifest_entries, nullptr);
  EXPECT_STREQ(manifest_entries[0].child_id, "child-red");
  EXPECT_EQ(manifest_entries[0].status, LINEAGE_ACTIVE);
  EXPECT_EQ(manifest_entries[0].attestation_ttl_ms, 3600000u);
  EXPECT_NE(lineage_query_resident_child(parent_state, "child-red"), nullptr);

  char* children_argv[] = {(char*)"crabs_node", (char*)"machine",
                           (char*)"children"};
  EXPECT_EQ(cli_dispatch(node, 3, children_argv), CLI_OK);

  // ------------------------------------------------------------------
  // 4. `machine attest` through dispatch: the printed wire must re-verify.
  //    Capture stdout the same way the attest surface test does.
  // ------------------------------------------------------------------
  const char* captured_path = "/tmp/crabs-e2e-attest-captured.log";
  FILE* captured_stream = fopen(captured_path, "w");
  ASSERT_NE(captured_stream, nullptr);
  FILE* saved_stdout = stdout;
  stdout = captured_stream;
  char* attest_argv[] = {(char*)"crabs_node", (char*)"machine", (char*)"attest",
                         (char*)"child-red", (char*)"child-admin",
                         (char*)"role:writer"};
  cli_result_e attest_result = cli_dispatch(node, 6, attest_argv);
  fflush(captured_stream);
  fclose(captured_stream);
  stdout = saved_stdout;
  ASSERT_EQ(attest_result, CLI_OK);

  std::vector<uint8_t> captured_bytes;
  ASSERT_TRUE(test_read_saved_bytes(captured_path, captured_bytes));
  std::string captured(captured_bytes.begin(), captured_bytes.end());
  std::vector<uint8_t> attestation_wire = test_extract_hex_wire(captured);
  ASSERT_GE(attestation_wire.size(), 4u + CRABS_SIG_SIZE);
  attestation_t* printed_attestation =
      attestation_deserialize(attestation_wire.data(), attestation_wire.size());
  ASSERT_NE(printed_attestation, nullptr);
  EXPECT_STREQ(printed_attestation->child_id, "child-red");
  EXPECT_STREQ(printed_attestation->user_id, "child-admin");
  EXPECT_STREQ(printed_attestation->attributes, "role:writer");
  EXPECT_EQ(printed_attestation->expires_at - printed_attestation->not_before,
            3600000ull);
  EXPECT_TRUE(attestation_verify(parent_pub_snapshot, "child-red",
                                 printed_attestation,
                                 printed_attestation->not_before));
  attestation_destroy(printed_attestation);
  remove(captured_path);

  // ------------------------------------------------------------------
  // 5. Persist BOTH machines like the lineage durability test does: the
  //    child gets a node key OF ITS OWN and a raw sealed+signed snapshot;
  //    the parent saves through the CLI custody path (sealed + node-key
  //    signature).
  // ------------------------------------------------------------------
  attribute_machine_t* child =
      lineage_query_resident_child(parent_state, "child-red");
  ASSERT_NE(child, nullptr);
  state_t* child_state = &child->base_state;
  ecdsa_keypair_t* child_node_key = crypto_ecdsa_generate();
  ASSERT_NE(child_node_key, nullptr);
  ASSERT_EQ(state_set_node_key(child_state, child_node_key->private_key,
                               child_node_key->public_key), CRABS_SUCCESS);
  ecdsa_keypair_t child_node_key_snapshot = *child_node_key;

  serialized_buffer_t* child_blob = crabs_serialize_state_sealed_signed(
      child_state, test_seal_key);
  ASSERT_NE(child_blob, nullptr);
  FILE* child_file = fopen(child_path, "wb");
  ASSERT_NE(child_file, nullptr);
  ASSERT_EQ(fwrite(child_blob->data, 1, child_blob->len, child_file),
            child_blob->len);
  fclose(child_file);
  const size_t child_blob_len = child_blob->len;
  serialized_buffer_destroy(child_blob);

  child_manifest_entry_t manifest_snapshot = manifest_entries[0];
  ASSERT_EQ(cli_node_save(node, parent_path), CLI_OK);

  // Destroy everything — the child first, then the parent (the parent's
  // resident-children array drops the pointer; teardown frees the array).
  crypto_ecdsa_keypair_destroy(child_node_key);
  cli_node_destroy(node);

  // ------------------------------------------------------------------
  // 6. Restart the parent: sealed load + operator key import (the import
  //    verifies the snapshot signature before custody — the M-1 gate).
  // ------------------------------------------------------------------
  cli_node_t* reloaded = cli_node_create();
  ASSERT_NE(reloaded, nullptr);
  ASSERT_EQ(cli_node_load_sealed(reloaded, parent_path, seal_hex), CLI_OK);
  ASSERT_EQ(cli_node_load_key(reloaded, parent_priv_hex), CLI_OK);

  state_t* reloaded_parent = &reloaded->attr_machine->base_state;
  EXPECT_TRUE(reloaded_parent->node_key_valid);
  EXPECT_EQ(memcmp(reloaded_parent->node_public_key, parent_pub_snapshot, 33),
            0);

  // ------------------------------------------------------------------
  // 7. `machine children` through dispatch on the RELOADED parent; the
  //    manifest came through the sealed snapshot and the runtime residency
  //    did not.
  // ------------------------------------------------------------------
  char* reloaded_children_argv[] = {(char*)"crabs_node", (char*)"machine",
                                    (char*)"children"};
  EXPECT_EQ(cli_dispatch(reloaded, 3, reloaded_children_argv), CLI_OK);
  const child_manifest_entry_t* restored_entries = NULL;
  ASSERT_EQ(lineage_query_children(reloaded_parent, &restored_entries), 1u);
  ASSERT_NE(restored_entries, nullptr);
  EXPECT_STREQ(restored_entries[0].child_id, "child-red");
  EXPECT_EQ(restored_entries[0].status, LINEAGE_ACTIVE);
  EXPECT_EQ(memcmp(restored_entries[0].genesis_snapshot_hash,
                   manifest_snapshot.genesis_snapshot_hash, CRABS_HASH_SIZE),
            0);
  EXPECT_EQ(lineage_query_resident_child(reloaded_parent, "child-red"),
            nullptr);

  // ------------------------------------------------------------------
  // 8. The lifecycle CONTINUES across the restart through dispatch. First
  //    the fail-closed contract: a reloaded machine registers op types and
  //    policies durably, but the C op HANDLERS are runtime registrations —
  //    without lineage_install the pipeline would log the dissolve as a
  //    silent no-op success, so the CLI refuses the command loudly instead.
  // ------------------------------------------------------------------
  char* dissolve_argv[] = {(char*)"crabs_node", (char*)"machine",
                           (char*)"dissolve", (char*)"child-red"};
  EXPECT_NE(cli_dispatch(reloaded, 4, dissolve_argv), CLI_OK);
  EXPECT_EQ(restored_entries[0].status, LINEAGE_ACTIVE);
  EXPECT_EQ(
      state_machine_find_handler(reloaded_parent, CRABS_LINEAGE_OP_DISSOLVE),
      (op_handler_fn)NULL);

  // Re-registering the handlers (idempotent installer, same protocol step as
  // the original machine creation) makes the dissolve go through.
  lineage_install(reloaded_parent);
  ASSERT_EQ(cli_dispatch(reloaded, 4, dissolve_argv), CLI_OK);
  child_manifest_entry_t* dissolved_entry = lineage_find_manifest_entry(
      reloaded_parent, "child-red");
  ASSERT_NE(dissolved_entry, nullptr);
  EXPECT_EQ(dissolved_entry->status, LINEAGE_DISSOLVED);
  EXPECT_EQ(lineage_query_resident_child(reloaded_parent, "child-red"),
            nullptr);

  // De-duplicated re-dissolve is refused.
  EXPECT_NE(cli_dispatch(reloaded, 4, dissolve_argv), CLI_OK);

  // The dissolved lineage also stops issuing: the manifest gate survives the
  // restart (the direct attest path refuses a non-ACTIVE child).
  char* attest_after_argv[] = {(char*)"crabs_node", (char*)"machine",
                               (char*)"attest", (char*)"child-red",
                               (char*)"child-admin", (char*)"role:writer"};
  EXPECT_NE(cli_dispatch(reloaded, 6, attest_after_argv), CLI_OK);

  cli_node_destroy(reloaded);

  // ------------------------------------------------------------------
  // 9. Reload the child from its sealed+signed snapshot: verify the trailer
  //    against the child's OWN node key, then load with restoration
  //    reporting — the child's OWN authority must come back.
  // ------------------------------------------------------------------
  std::vector<uint8_t> child_bytes;
  ASSERT_TRUE(test_read_saved_bytes(child_path, child_bytes));
  ASSERT_EQ(child_bytes.size(), child_blob_len);
  ASSERT_GT(child_bytes.size(), (size_t)CRABS_SIG_SIZE);
  size_t child_payload_len = child_bytes.size() - CRABS_SIG_SIZE;
  EXPECT_TRUE(crypto_ecdsa_verify(child_node_key_snapshot.public_key,
                                  child_bytes.data(), child_payload_len,
                                  child_bytes.data() + child_payload_len));

  bool authority_restored = false;
  bool msk_section_present = false;
  state_t* restored_child = crabs_deserialize_state_keys_reported(
      child_bytes.data(), child_payload_len, test_seal_key,
      &authority_restored, &msk_section_present);
  ASSERT_NE(restored_child, nullptr);
  EXPECT_TRUE(msk_section_present);
  EXPECT_TRUE(authority_restored);
  EXPECT_TRUE(restored_child->lineage_parent_bound);
  EXPECT_STREQ(restored_child->lineage_parent_id, "parent-root");
  EXPECT_STREQ(restored_child->lineage_self_id, "child-red");

  state_destroy(restored_child);
  remove(parent_path);
  remove(child_path);
  remove(blueprint_path);
}

// Attach a live attestation to an op shell (the signing image excludes
// attestations — the same idiom test_lineage.cpp uses; op shells are
// destroyed with operation_destroy, which frees the attached copy).
static void test_attach_attestation(operation_t* op, const attestation_t* att) {
  op->attestations = (attestation_t*)malloc(sizeof(attestation_t));
  ASSERT_NE(op->attestations, nullptr);
  op->attestations[0] = *att;
  op->attestation_count = 1;
}

// The lineage dissolve deferred fix, closed END TO END across processes:
// the parent machine dissolves a child it last saw in a PREVIOUS process
// (the child's in-process copy is destroyed with the first parent process,
// so the runtime severed flag can never leak into the child's FILE), prints
// the dissolution tombstone via cli_dispatch, and the child — a machine
// under a SEPARATE cli_node_t loaded from its own saved file, in no way
// related to the first child instance — learns of the severance ONLY
// through 'machine accept-tombstone'. The delivered flag is durable (v12):
// it survives the child's own save/reload, and the custody chain it ends is
// proven by a still-valid @parent/ endorsement op refusing afterwards.
TEST(TestDurability, DissolutionSurvivesRestartThroughTombstoneDelivery) {
  const char* parent_path = "/tmp/crabs-dissolution-parent.crabs";
  const char* child_path = "/tmp/crabs-dissolution-child.crabs";
  const char* child_saved_path = "/tmp/crabs-dissolution-child-saved.crabs";
  const char* blueprint_path = "/tmp/crabs-dissolution.cbp";
  const char* tombstone_hex_path = "/tmp/crabs-dissolution-tombstone.hex";

  // ------------------------------------------------------------------
  // 1. Parent through the CLI layer: seal-key custody + lineage installer;
  //    its node key doubles as the genesis-registered child admin's signing
  //    key (DELEGATED_COPY registers "child-admin" under the parent's node
  //    public key — the established test custody model).
  // ------------------------------------------------------------------
  cli_node_t* node = cli_node_create();
  ASSERT_NE(node, nullptr);
  ASSERT_EQ(cli_node_init(node, "parent-root"), CLI_OK);

  char seal_hex[65];
  _import_test_seal_key(node, seal_hex);
  lineage_install(&node->attr_machine->base_state);

  char parent_priv_hex[65];
  cli_bytes_to_hex(node->node_key->private_key, 32, parent_priv_hex);
  parent_priv_hex[64] = '\0';
  ecdsa_keypair_t parent_key_snapshot = *node->node_key;

  // ------------------------------------------------------------------
  // 2. Blueprint through dispatch. The child policy "render" resolves ONLY
  //    through a @parent/ endorsement — the op whose authorization the
  //    custody payoff below will exercise after the delivery.
  // ------------------------------------------------------------------
  char* new_argv[] = {(char*)"crabs_node", (char*)"machine", (char*)"blueprint",
                      (char*)"new", (char*)"child-red", (char*)"delegated",
                      (char*)"child-admin", (char*)"3600000"};
  ASSERT_EQ(cli_dispatch(node, 8, new_argv), CLI_OK);
  char* item_argv[] = {(char*)"crabs_node", (char*)"machine", (char*)"blueprint",
                       (char*)"item", (char*)"counter1", (char*)"counter",
                       (char*)"g_counter"};
  ASSERT_EQ(cli_dispatch(node, 7, item_argv), CLI_OK);
  char* policy_argv[] = {(char*)"crabs_node", (char*)"machine",
                         (char*)"blueprint", (char*)"policy", (char*)"render",
                         (char*)"@parent/role:writer"};
  ASSERT_EQ(cli_dispatch(node, 6, policy_argv), CLI_OK);
  char* dedup_argv[] = {(char*)"crabs_node", (char*)"machine", (char*)"blueprint",
                        (char*)"dedup", (char*)"render", (char*)"none"};
  ASSERT_EQ(cli_dispatch(node, 6, dedup_argv), CLI_OK);
  char* save_argv[] = {(char*)"crabs_node", (char*)"machine", (char*)"blueprint",
                       (char*)"save", (char*)blueprint_path};
  ASSERT_EQ(cli_dispatch(node, 5, save_argv), CLI_OK);

  // ------------------------------------------------------------------
  // 3. Spawn via the op pipeline, then mint a LIVE attestation for the
  //    child admin and keep it: the endorsement material the dissolved
  //    lineage must stop honoring even though it stays cryptographically
  //    valid ("revocation stops issuing, dissolution voids endorsements").
  // ------------------------------------------------------------------
  char* spawn_argv[] = {(char*)"crabs_node", (char*)"machine", (char*)"spawn",
                        (char*)blueprint_path};
  ASSERT_EQ(cli_dispatch(node, 4, spawn_argv), CLI_OK);
  state_t* parent_state = &node->attr_machine->base_state;

  const char* captured_path = "/tmp/crabs-dissolution-attest-captured.log";
  FILE* captured_stream = fopen(captured_path, "w");
  ASSERT_NE(captured_stream, nullptr);
  FILE* saved_stdout = stdout;
  stdout = captured_stream;
  char* attest_argv[] = {(char*)"crabs_node", (char*)"machine", (char*)"attest",
                         (char*)"child-red", (char*)"child-admin",
                         (char*)"role:writer"};
  ASSERT_EQ(cli_dispatch(node, 6, attest_argv), CLI_OK);
  fflush(captured_stream);
  fclose(captured_stream);
  stdout = saved_stdout;
  std::vector<uint8_t> captured_bytes;
  ASSERT_TRUE(test_read_saved_bytes(captured_path, captured_bytes));
  std::string captured(captured_bytes.begin(), captured_bytes.end());
  std::vector<uint8_t> attestation_wire = test_extract_hex_wire(captured);
  ASSERT_GE(attestation_wire.size(), 4u + CRABS_SIG_SIZE);
  attestation_t* printed_attestation =
      attestation_deserialize(attestation_wire.data(), attestation_wire.size());
  ASSERT_NE(printed_attestation, nullptr);
  remove(captured_path);

  // ------------------------------------------------------------------
  // 4. Persist the child: give it its own node key (so its operator can
  //    keep saving snapshots independently) and write a SEALED snapshot
  //    WITHOUT
  //    the node-key signature — the child CLI node below then goes through
  //    the unauthenticated-provenance path ('state accept-unverified'),
  //    exactly an operator loading an unsigned-but-sealed machine file.
  //    The child file is written BEFORE the dissolve, so the flag it
  //    carries is the pre-severance false.
  // ------------------------------------------------------------------
  attribute_machine_t* child =
      lineage_query_resident_child(parent_state, "child-red");
  ASSERT_NE(child, nullptr);
  ecdsa_keypair_t* child_node_key = crypto_ecdsa_generate();
  ASSERT_NE(child_node_key, nullptr);
  ASSERT_EQ(state_set_node_key(&child->base_state, child_node_key->private_key,
                               child_node_key->public_key), CRABS_SUCCESS);
  // The child operator's seal key is a DIFFERENT secret from the parent's.
  static const uint8_t child_seal_key[32] = {
    41,11,52,12,63,13,74,14,85,15,96,16,107,17,118,18,
    19,129,20,131,21,142,22,153,23,164,24,175,25,186,26,197
  };
  char child_seal_hex[65];
  cli_bytes_to_hex(child_seal_key, 32, child_seal_hex);
  child_seal_hex[64] = '\0';

  serialized_buffer_t* child_blob = crabs_serialize_state_sealed(
      &child->base_state, child_seal_key);
  ASSERT_NE(child_blob, nullptr);
  FILE* child_file = fopen(child_path, "wb");
  ASSERT_NE(child_file, nullptr);
  ASSERT_EQ(fwrite(child_blob->data, 1, child_blob->len, child_file),
            child_blob->len);
  fclose(child_file);
  serialized_buffer_destroy(child_blob);

  // ------------------------------------------------------------------
  // 5. Process one of the parent ends: save the parent, then destroy the
  //    CHILD INSTANCE first — the detached-operator scenario — followed by
  //    the parent. From here on the child exists only as its FILE.
  // ------------------------------------------------------------------
  ASSERT_EQ(cli_node_save(node, parent_path), CLI_OK);
  attribute_machine_destroy(child);
  crypto_ecdsa_keypair_destroy(child_node_key);
  cli_node_destroy(node);

  // ------------------------------------------------------------------
  // 6. Parent restart: sealed load + key re-import, lineage handlers
  //    re-installed, dissolve through dispatch — the child is NOT resident
  //    in this process (a real parent process has no resident pointer for
  //    a child it spawned two processes ago), so NO in-process flag is
  //    ever set: the manifest is the only parent-side record.
  // ------------------------------------------------------------------
  cli_node_t* reloaded = cli_node_create();
  ASSERT_NE(reloaded, nullptr);
  ASSERT_EQ(cli_node_load_sealed(reloaded, parent_path, seal_hex), CLI_OK);
  ASSERT_EQ(cli_node_load_key(reloaded, parent_priv_hex), CLI_OK);
  lineage_install(&reloaded->attr_machine->base_state);

  char* dissolve_argv[] = {(char*)"crabs_node", (char*)"machine",
                           (char*)"dissolve", (char*)"child-red"};
  ASSERT_EQ(cli_dispatch(reloaded, 4, dissolve_argv), CLI_OK);
  ASSERT_EQ(
      lineage_find_manifest_entry(&reloaded->attr_machine->base_state,
                                  "child-red")->status,
      LINEAGE_DISSOLVED);

  // ------------------------------------------------------------------
  // 7. Tombstone print through dispatch; capture the hex exactly as an
  //    operator would pipe it, and write the hand-off file (trailing
  //    newline included — the accept command parses the hex run
  //    dynamically).
  // ------------------------------------------------------------------
  captured_path = "/tmp/crabs-dissolution-tombstone-captured.log";
  captured_stream = fopen(captured_path, "w");
  ASSERT_NE(captured_stream, nullptr);
  stdout = captured_stream;
  char* tombstone_argv[] = {(char*)"crabs_node", (char*)"machine",
                            (char*)"tombstone", (char*)"child-red"};
  ASSERT_EQ(cli_dispatch(reloaded, 4, tombstone_argv), CLI_OK);
  fflush(captured_stream);
  fclose(captured_stream);
  stdout = saved_stdout;
  captured_bytes.clear();
  ASSERT_TRUE(test_read_saved_bytes(captured_path, captured_bytes));
  captured.assign(captured_bytes.begin(), captured_bytes.end());
  std::vector<uint8_t> tombstone_wire = test_extract_hex_wire(captured);
  ASSERT_EQ(tombstone_wire.size(),
            3 + strlen("child-red") + CRABS_SIG_SIZE);
  EXPECT_EQ(tombstone_wire[0], (uint8_t)LINEAGE_DISSOLVED);
  EXPECT_TRUE(crypto_ecdsa_verify(parent_key_snapshot.public_key,
                                  tombstone_wire.data(),
                                  tombstone_wire.size() - CRABS_SIG_SIZE,
                                  tombstone_wire.data() +
                                      tombstone_wire.size() - CRABS_SIG_SIZE));
  char tombstone_hex_text[CRABS_DISSOLUTION_WIRE_MAX * 2 + 1];
  cli_bytes_to_hex(tombstone_wire.data(), tombstone_wire.size(),
                   tombstone_hex_text);
  std::string tombstone_file_text = std::string(tombstone_hex_text) + "\n";
  FILE* tombstone_file = fopen(tombstone_hex_path, "w");
  ASSERT_NE(tombstone_file, nullptr);
  ASSERT_EQ(tombstone_file_text.size(),
            fwrite(tombstone_file_text.data(), 1, tombstone_file_text.size(),
                   tombstone_file));
  fclose(tombstone_file);
  remove(captured_path);
  cli_node_destroy(reloaded);

  // ------------------------------------------------------------------
  // 8. The child operator's machine, under its OWN cli_node_t in a fresh
  //    process: sealed load of the child file, key custody restored (the
  //    genesis-registered child admin signs with the parent's node key
  //    material), lineage handlers re-installed — and the severed flag is
  //    FALSE right up until the tombstone delivery.
  // ------------------------------------------------------------------
  cli_node_t* child_node = cli_node_create();
  ASSERT_NE(child_node, nullptr);
  ASSERT_EQ(cli_node_load_sealed(child_node, child_path, child_seal_hex),
            CLI_OK);
  state_t* child_state = &child_node->attr_machine->base_state;
  ASSERT_TRUE(child_state->lineage_parent_bound);
  ASSERT_STREQ(child_state->lineage_self_id, "child-red");
  ASSERT_STREQ(child_state->lineage_parent_id, "parent-root");
  ASSERT_FALSE(child_state->lineage_parent_dissolved);
  ASSERT_EQ(cli_node_load_key(child_node, parent_priv_hex), CLI_OK);
  ASSERT_NE(cli_node_get_user_key(child_node, "child-admin"), nullptr);

  // Delivery is refused while the reloaded machine has no handler installed
  // (the runtime-registration gate every machine lifecycle command shares).
  char* accept_argv[] = {(char*)"crabs_node", (char*)"machine",
                         (char*)"accept-tombstone", (char*)tombstone_hex_path};
  EXPECT_EQ(cli_dispatch(child_node, 4, accept_argv), CLI_ERR_EXEC);

  lineage_install(child_state);
  ASSERT_EQ(cli_dispatch(child_node, 4, accept_argv), CLI_OK);
  ASSERT_TRUE(child_state->lineage_parent_dissolved);

  // A re-delivery is already-performed through the SAME command path.
  EXPECT_EQ(cli_dispatch(child_node, 4, accept_argv), CLI_ERR_EXEC);

  // ------------------------------------------------------------------
  // 9. The child persists through its own seal-key custody, is destroyed
  //    and reloaded AGAIN — the delivered flag survives on its own (v12
  //    dissolved-flag tail), even though nothing in this second process saw
  //    the delivery.
  // ------------------------------------------------------------------
  char* accept_unverified_argv[] = {(char*)"crabs_node", (char*)"state",
                                    (char*)"accept-unverified"};
  ASSERT_EQ(cli_dispatch(child_node, 3, accept_unverified_argv), CLI_OK);
  ASSERT_EQ(cli_node_save(child_node, child_saved_path), CLI_OK);
  cli_node_destroy(child_node);

  cli_node_t* child_reloaded = cli_node_create();
  ASSERT_NE(child_reloaded, nullptr);
  ASSERT_EQ(cli_node_load_sealed(child_reloaded, child_saved_path,
                                 child_seal_hex), CLI_OK);
  ASSERT_EQ(cli_node_load_key(child_reloaded, parent_priv_hex), CLI_OK);
  ASSERT_TRUE(
      child_reloaded->attr_machine->base_state.lineage_parent_dissolved);

  // ------------------------------------------------------------------
  // 10. THE CUSTODY PAYOFF: the still-valid, already-minted attestation
  //     (minted in process one, BEFORE the dissolve; never re-issued —
  //     crabs_issue_attestation refuses a non-ACTIVE lineage) cannot carry a
  //     @parent/-endorsed op across the delivered severance. The op's own
  //     signature verifies (child-admin's registered key), and the dissolved
  //     flag fail-closes the endorsement: CRABS_ERR_UNAUTHORIZED.
  // ------------------------------------------------------------------
  operation_t* render_op = operation_create("render");
  ASSERT_NE(render_op, nullptr);
  strncpy(render_op->signer_id, "child-admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(child_reloaded->attr_machine, &parent_key_snapshot,
                          render_op);
  test_attach_attestation(render_op, printed_attestation);
  EXPECT_EQ(state_machine_execute(
                &child_reloaded->attr_machine->base_state, render_op),
            CRABS_ERR_UNAUTHORIZED);
  operation_destroy(render_op);
  attestation_destroy(printed_attestation);

  cli_node_destroy(child_reloaded);
  remove(parent_path);
  remove(child_path);
  remove(child_saved_path);
  remove(blueprint_path);
  remove(tombstone_hex_path);
}
