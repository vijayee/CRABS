// Durability (v10) restart round-trip: a full CLI machine — identity registry,
// custom op dedup registry, policies, log — survives save (sealed MSK),
// destroy and load, and the reloaded machine still AUTHORIZES the writer.
// Exercises the real custody path end to end: cli_node_init, seal-key
// import, cli_node_save, cli_node_load_sealed.

#include <gtest/gtest.h>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "../src/CLI/cli.h"
#include "../src/Crypto/crypto.h"
#include "../src/StateMachine/state_machine.h"
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