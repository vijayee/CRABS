#ifndef CRABS_TEST_HELPERS_H
#define CRABS_TEST_HELPERS_H

#include "StateMachine/state_machine.h"
#include "Attribute/attribute_machine.h"
#include "Crypto/crypto.h"
#include "CRABS/data_model.h"

// Test environment that provides a state with a real ECDSA admin keypair,
// an attached attribute machine whose bootstrap admin uses that keypair,
// and policies registered for every built-in operation type so that
// fail-closed authorization can succeed.
typedef struct {
  state_t* state;
  attribute_machine_t* am;
  ecdsa_keypair_t* admin_key;
} crabs_test_env_t;

// Initialize env: create state, generate admin keypair, create attribute
// machine with the admin's real public key, register admin with role:admin,
// and register policies for all built-in op types.
void crabs_test_env_init(crabs_test_env_t* env);

// Destroy env and free all resources.
void crabs_test_env_destroy(crabs_test_env_t* env);

// Register policies for all built-in operation types on the given state.
void crabs_test_register_builtin_policies(state_t* state);

// Sign op in place using env->admin_key (signs crabs_serialize_for_signing(op)).
void crabs_test_sign_op(crabs_test_env_t* env, operation_t* op);

// Sign op with an arbitrary key (e.g. a second user's key).
void crabs_test_sign_op_with(ecdsa_keypair_t* key, operation_t* op);

#endif // CRABS_TEST_HELPERS_H