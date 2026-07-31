#include "test_helpers.h"
#include "../src/CRABS/crabs.h"
#include "../src/Serialization/serialization.h"
#include "../src/Util/allocator.h"
#include <string.h>

void crabs_test_register_builtin_policies(state_t* state) {
  if (state == NULL) return;
  // Privileged operations require an admin attribute.
  state_add_policy(state, CRABS_OP_LOCK, "role:admin");
  state_add_policy(state, CRABS_OP_EXTEND, "role:admin");
  state_add_policy(state, CRABS_OP_VERIFY, "role:admin");
  state_add_policy(state, CRABS_OP_ROLLBACK, "role:admin");
  state_add_policy(state, CRABS_OP_UNLOCK, "role:admin");
  state_add_policy(state, CRABS_OP_REFRESH_KEY, "role:admin");
  state_add_policy(state, CRABS_OP_CHANGE_CONFIG, "role:admin");
  state_add_policy(state, CRABS_OP_CREATE_TRIGGER, "role:admin");
  state_add_policy(state, CRABS_OP_DELETE_TRIGGER, "role:admin");
  state_add_policy(state, CRABS_OP_DISABLE_TRIGGER, "role:admin");
  state_add_policy(state, CRABS_OP_ENABLE_TRIGGER, "role:admin");
  state_add_policy(state, CRABS_OP_DEFINE_OPERATION, "role:admin");
  state_add_policy(state, CRABS_OP_CHECK_DEDUP, "role:admin");
  state_add_policy(state, CRABS_OP_COMPACT, "role:admin");
  state_add_policy(state, CRABS_OP_EXECUTE_OT, "role:admin");
  // Self-service keyring operations: any active user may manage their own
  // keys (the handler binds the change to op->signer_id). An empty policy
  // means "no attribute requirement" — a valid signature is still required.
  state_add_policy(state, CRABS_OP_REGISTER_KEY, "");
  state_add_policy(state, CRABS_OP_REVOKE_KEY, "");
  state_add_policy(state, CRABS_OP_SET_DEFAULT_KEY, "");
  state_add_policy(state, CRABS_OP_SUSPEND_KEY, "");
  state_add_policy(state, CRABS_OP_ACTIVATE_KEY, "");
  state_add_policy(state, CRABS_OP_ROTATE_KEY, "");
  // Force-unlock is intentionally open (anyone may release an expired lock).
  state_add_policy(state, CRABS_OP_FORCE_UNLOCK, "");
}

void crabs_test_env_init(crabs_test_env_t* env) {
  env->admin_key = crypto_ecdsa_generate();
  env->am = attribute_machine_create("admin", env->admin_key->public_key);
  env->state = state_create();
  env->state->attr_machine = env->am;
  crabs_test_register_builtin_policies(env->state);

  // Ensure state has a node key for envelope signing (refresh_key etc.).
  ecdsa_keypair_t* node_key = crypto_ecdsa_generate();
  state_set_node_key(env->state, node_key->private_key, node_key->public_key);
  crypto_ecdsa_keypair_destroy(node_key);
}

void crabs_test_env_destroy(crabs_test_env_t* env) {
  if (env == NULL) return;
  if (env->state != NULL) {
    env->state->attr_machine = NULL;
    state_destroy(env->state);
  }
  if (env->am != NULL) attribute_machine_destroy(env->am);
  if (env->admin_key != NULL) crypto_ecdsa_keypair_destroy(env->admin_key);
}

void crabs_test_sign_op_with(ecdsa_keypair_t* key, operation_t* op) {
  if (key == NULL || op == NULL) return;
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  if (ser == NULL) return;
  crypto_sign_operation(key->private_key, ser->data, ser->len, op->signature);
  serialized_buffer_destroy(ser);
}

void crabs_test_sign_op(crabs_test_env_t* env, operation_t* op) {
  crabs_test_sign_op_with(env->admin_key, op);
}