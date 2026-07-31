// Regression tests for co-signature verification (audit finding C-4).
#include <gtest/gtest.h>
extern "C" {
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/crypto.h"
#include "../src/Serialization/serialization.h"
#include "../src/Util/allocator.h"
#include "test_helpers.h"
}

// Build a signed __lock__ op signed by `key` (signer_id), against a state that
// already has a locked-eligible resource.
static operation_t* make_lock_op_signed(ecdsa_keypair_t* key, const char* signer_id,
                                          const char* resource, state_t* state) {
  operation_t* op = operation_create(CRABS_OP_LOCK);
  for (int i = 0; i < CRABS_UUID_SIZE; i++) op->uuid[i] = (uint8_t)(i + 1);
  op->resources = (char(*)[CRABS_MAX_USER_ID])get_clear_memory(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], resource, CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)get_clear_memory(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)get_clear_memory(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, signer_id, CRABS_MAX_USER_ID - 1);
  op->signer_key_version = attribute_machine_find_user(state->attr_machine, signer_id)->key_version;
  crabs_test_sign_op_with(key, op);
  return op;
}

static void add_resource(state_t* state, const char* name) {
  data_item_t* res = data_item_create(name, DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* v = (int64_t*)get_clear_memory(sizeof(int64_t));
  *v = 0;
  res->value = v;
  state_add_item(state, res);
}

static co_signature_t* make_co_sig(ecdsa_keypair_t* key, const char* signer_id,
                                     operation_t* op) {
  co_signature_t* cs = (co_signature_t*)get_clear_memory(sizeof(co_signature_t));
  strncpy(cs->signer_id, signer_id, CRABS_MAX_USER_ID - 1);
  // Legacy ECDSA: no key_id, scheme UNSPECIFIED → uses user->public_key.
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  crypto_ecdsa_sign(key->private_key, ser->data, ser->len, cs->signature);
  cs->signature_len = CRABS_SIG_SIZE;
  serialized_buffer_destroy(ser);
  return cs;
}

TEST(TestCoSign, BelowThresholdRejected) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  state_t* state = env.state;
  state->config.sig_config.co_sign_threshold = 2;
  add_resource(state, "res");

  operation_t* op = make_lock_op_signed(env.admin_key, "admin", "res", state);
  // No co-signers → below threshold.
  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_UNAUTHORIZED);
  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(TestCoSign, MeetsThresholdWithValidCoSigners) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  state_t* state = env.state;
  state->config.sig_config.co_sign_threshold = 2;

  // Register a second admin (bob) with a real key.
  ecdsa_keypair_t* bob_key = crypto_ecdsa_generate();
  attribute_machine_register_user(state->attr_machine, "bob", bob_key->public_key, "role:admin");

  add_resource(state, "res");
  operation_t* op = make_lock_op_signed(env.admin_key, "admin", "res", state);

  op->co_signers = (co_signature_t*)get_clear_memory(sizeof(co_signature_t) * 2);
  co_signature_t* cs0 = make_co_sig(bob_key, "bob", op);
  op->co_signers[0] = *cs0;
  free(cs0);
  // Second co-signer: register a third user carol.
  ecdsa_keypair_t* carol_key = crypto_ecdsa_generate();
  attribute_machine_register_user(state->attr_machine, "carol", carol_key->public_key, "role:admin");
  co_signature_t* cs1 = make_co_sig(carol_key, "carol", op);
  op->co_signers[1] = *cs1;
  free(cs1);
  op->co_signer_count = 2;

  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(bob_key);
  crypto_ecdsa_keypair_destroy(carol_key);
  crabs_test_env_destroy(&env);
}

TEST(TestCoSign, InvalidCoSignatureRejected) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  state_t* state = env.state;
  state->config.sig_config.co_sign_threshold = 1;

  ecdsa_keypair_t* bob_key = crypto_ecdsa_generate();
  attribute_machine_register_user(state->attr_machine, "bob", bob_key->public_key, "role:admin");

  add_resource(state, "res");
  operation_t* op = make_lock_op_signed(env.admin_key, "admin", "res", state);

  op->co_signers = (co_signature_t*)get_clear_memory(sizeof(co_signature_t));
  strncpy(op->co_signers[0].signer_id, "bob", CRABS_MAX_USER_ID - 1);
  // Garbage signature.
  memset(op->co_signers[0].signature, 0x11, CRABS_SIG_SIZE);
  op->co_signers[0].signature_len = CRABS_SIG_SIZE;
  op->co_signer_count = 1;

  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_UNAUTHORIZED);
  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(bob_key);
  crabs_test_env_destroy(&env);
}

TEST(TestCoSign, DuplicateCoSignerRejected) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  state_t* state = env.state;
  state->config.sig_config.co_sign_threshold = 2;

  ecdsa_keypair_t* bob_key = crypto_ecdsa_generate();
  attribute_machine_register_user(state->attr_machine, "bob", bob_key->public_key, "role:admin");

  add_resource(state, "res");
  operation_t* op = make_lock_op_signed(env.admin_key, "admin", "res", state);

  op->co_signers = (co_signature_t*)get_clear_memory(sizeof(co_signature_t) * 2);
  co_signature_t* cs = make_co_sig(bob_key, "bob", op);
  op->co_signers[0] = *cs;
  op->co_signers[1] = *cs;  // duplicate
  op->co_signer_count = 2;

  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_DUPLICATE_OPERATION);
  free(cs);
  operation_destroy(op);
  crypto_ecdsa_keypair_destroy(bob_key);
  crabs_test_env_destroy(&env);
}