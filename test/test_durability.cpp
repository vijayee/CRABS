// Durability (v10) restart round-trip: a full CLI machine — identity registry,
// custom op dedup registry, policies, log — survives save (sealed MSK),
// destroy and load, and the reloaded machine still AUTHORIZES the writer.
// Exercises the real custody path end to end: cli_node_init, seal-key
// import, cli_node_save, cli_node_load_sealed.

#include <gtest/gtest.h>
#include <cstdlib>
#include <cstring>
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
