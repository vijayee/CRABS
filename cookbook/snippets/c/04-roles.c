/* Recipe 4 — roles and who-can-do-what (C core, signed execution).
 *
 * Full path: generate a real key, register the user (unprivileged facts
 * only — privileged attribute names are invalid_param per audit R7-08),
 * grant the role via the admin path, register a policy for a custom op
 * type, sign, and let state_machine_execute authorize it. A member passes;
 * a member missing a policy clause is refused before any effect. Signing
 * discipline mirrors test/test_durability.cpp:98-106 (stamp uuid, lamport
 * time and the signer's key_version, serialize-for-signing, sign). */
#include "Attribute/attribute_machine.h"
#include "StateMachine/state_machine.h"
#include "Crypto/crypto.h"
#include "Serialization/serialization.h"
#include "CRABS/crabs.h"
#include "CRABS/data_model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* The 'post' effect itself: a counting handler proves the op LANDED —
 * authorization passing is only half the story, so the snippet counts the
 * times the member's op actually ran. */
static int landed_posts = 0;
static crabs_error_e counting_post_handler(state_t* state, operation_t* op) {
  (void)state;
  (void)op;
  landed_posts++;
  return CRABS_SUCCESS;
}

int main(void) {
  ecdsa_keypair_t* admin_key = crypto_ecdsa_generate();
  assert(admin_key != NULL);
  attribute_machine_t* am = attribute_machine_create("admin", admin_key->public_key);
  assert(am != NULL);
  /* The base state's attribute-machine back-pointer is attached by the
   * INTEGRATOR, not by attribute_machine_create — the exact line the wasm
   * glue (src/Util/wasm_helpers.c:242) and the CLI (src/CLI/cli.c:257) run. */
  am->base_state.attr_machine = am;

  /* register_user must refuse a privileged attribute name. */
  ecdsa_keypair_t* sneak_key = crypto_ecdsa_generate();
  assert(attribute_machine_register_user(am, "sneak", sneak_key->public_key,
                                         "role:admin") == CRABS_ERR_INVALID_PARAM);
  assert(attribute_machine_find_user(am, "sneak") == NULL);
  crypto_ecdsa_keypair_destroy(sneak_key);

  /* alice: unprivileged fact at registration + admin-granted role. */
  ecdsa_keypair_t* alice_key = crypto_ecdsa_generate();
  assert(attribute_machine_register_user(am, "alice", alice_key->public_key,
                                         "adult") == CRABS_SUCCESS);
  assert(attribute_machine_grant_role(am, "alice", "role", "member", "admin")
         == CRABS_SUCCESS);
  user_t* alice = attribute_machine_find_user(am, "alice");
  assert(alice != NULL);
  assert(attribute_machine_user_has_role(alice, "role"));

  /* mallory: member but never asserted 'adult'. */
  ecdsa_keypair_t* mallory_key = crypto_ecdsa_generate();
  assert(attribute_machine_register_user(am, "mallory", mallory_key->public_key, NULL)
         == CRABS_SUCCESS);
  assert(attribute_machine_grant_role(am, "mallory", "role", "member", "admin")
         == CRABS_SUCCESS);

  state_t* state = &am->base_state;
  assert(state_add_policy(state, "post", "AND role:member adult") == CRABS_SUCCESS);
  assert(state_machine_register_handler(state, "post", counting_post_handler)
         == CRABS_SUCCESS);

  /* Sign the way the executor expects: the R7-04 staleness check requires
   * the signer's CURRENT key_version stamped into the op. */
  operation_t* alices = operation_create("post");
  assert(alices != NULL);
  memset(alices->uuid, 0xA1, CRABS_UUID_SIZE);
  strncpy(alices->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  alices->lamport_time = 1;
  user_t* alice_signer = attribute_machine_find_user(am, "alice");
  assert(alice_signer != NULL);
  alices->signer_key_version = alice_signer->key_version;
  serialized_buffer_t* alice_wire = crabs_serialize_for_signing(alices);
  assert(alice_wire != NULL);
  assert(crypto_sign_operation(alice_key->private_key, alice_wire->data,
                               alice_wire->len, alices->signature)
         == CRABS_SUCCESS);
  serialized_buffer_destroy(alice_wire);
  assert(state_machine_execute(state, alices) == CRABS_SUCCESS);
  operation_destroy(alices);
  assert(landed_posts == 1);

  /* Mallory is a member but the policy's 'adult' clause fails — refused,
   * handler never runs, nothing lands. */
  operation_t* mallorys = operation_create("post");
  assert(mallorys != NULL);
  memset(mallorys->uuid, 0xA2, CRABS_UUID_SIZE);
  strncpy(mallorys->signer_id, "mallory", CRABS_MAX_USER_ID - 1);
  mallorys->lamport_time = 1;
  user_t* mallory_signer = attribute_machine_find_user(am, "mallory");
  assert(mallory_signer != NULL);
  mallorys->signer_key_version = mallory_signer->key_version;
  serialized_buffer_t* mallory_wire = crabs_serialize_for_signing(mallorys);
  assert(mallory_wire != NULL);
  assert(crypto_sign_operation(mallory_key->private_key, mallory_wire->data,
                               mallory_wire->len, mallorys->signature)
         == CRABS_SUCCESS);
  serialized_buffer_destroy(mallory_wire);
  assert(state_machine_execute(state, mallorys) == CRABS_ERR_UNAUTHORIZED);
  operation_destroy(mallorys);
  assert(landed_posts == 1);

  /* tamper: the same op re-signed with the WRONG key (eve's key, alice's
   * identity) fails verification. */
  ecdsa_keypair_t* eve_key = crypto_ecdsa_generate();
  operation_t* forged = operation_create("post");
  assert(forged != NULL);
  memset(forged->uuid, 0xA3, CRABS_UUID_SIZE);
  strncpy(forged->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  forged->lamport_time = 2;
  user_t* alice_now = attribute_machine_find_user(am, "alice");
  assert(alice_now != NULL);
  forged->signer_key_version = alice_now->key_version;
  serialized_buffer_t* forged_wire = crabs_serialize_for_signing(forged);
  assert(forged_wire != NULL);
  assert(crypto_sign_operation(eve_key->private_key, forged_wire->data,
                               forged_wire->len, forged->signature)
         == CRABS_SUCCESS);
  serialized_buffer_destroy(forged_wire);
  assert(state_machine_execute(state, forged) == CRABS_ERR_UNAUTHORIZED);
  operation_destroy(forged);
  assert(landed_posts == 1);
  crypto_ecdsa_keypair_destroy(eve_key);

  printf("roles OK: authorized post landed, clause failure and forgery refused\n");

  /* admin_key ownership transfers to the attribute machine via cli-style
   * flows... not here: the attribute machine keeps no pointer to it, so it
   * is released by the caller after the machine is torn down. */
  attribute_machine_destroy(am);
  crypto_ecdsa_keypair_destroy(admin_key);
  return 0;
}