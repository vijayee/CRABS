#ifndef CRABS_TEST_HELPERS_H
#define CRABS_TEST_HELPERS_H

#include "StateMachine/state_machine.h"
#include "Attribute/attribute_machine.h"
#include "Crypto/crypto.h"
#include "CRABS/data_model.h"

#ifdef __cplusplus
extern "C" {
#endif

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

// Sign op with an arbitrary key (e.g. a second user's key). The attribute
// machine is used to stamp op->signer_key_version from the signer's current
// key_version so the state machine's staleness check can pass (R7-04).
void crabs_test_sign_op_with(attribute_machine_t* am, ecdsa_keypair_t* key, operation_t* op);

// R7-08: register_user no longer accepts privileged attribute names (role,
// admin, owner, ...). Tests that need a role attribute must register the
// user with no attributes and grant the role via the admin grant_role path.
// Returns CRABS_SUCCESS on success, otherwise the failing error code.
crabs_error_e crabs_test_register_user_with_role(attribute_machine_t* am,
                                                  const char* user_id,
                                                  const uint8_t public_key[33],
                                                  const char* role,
                                                  const char* value);

#ifdef __cplusplus
}
#endif

#endif // CRABS_TEST_HELPERS_H