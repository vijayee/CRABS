/* Recipe 16 — data that must be revocable (C core).
 *
 * The full revocation story, on the engine the bindings wrap:
 *   - user-level revocation (revoke_user — the tool BOTH JS bindings
 *     expose) is terminal and refuses the reader's next ops
 *     (verify R7-14 collapse, src/Crypto/crypto.c:1395-1403);
 *   - key-level lifecycle — suspend/activate/rotate (C-only, api-map §2) —
 *     each bump of the user's key_version is the staleness fence R7-04
 *     signs ops against (src/StateMachine/state_machine.c:863-877);
 *   - the honest boundary: revocation does NOT recall a CP-ABE key already
 *     derived from the old attributes (no revocation registry exists);
 *     real recall is the re-encrypt-under-next-epoch pattern.
 * Signing discipline mirrors test/test_key_lifecycle.cpp (R8-C-2) and
 * recipe 4's execute path. */
#include "Attribute/attribute_machine.h"
#include "StateMachine/state_machine.h"
#include "Crypto/crypto.h"
#include "Serialization/serialization.h"
#include "CRABS/crabs.h"
#include "CRABS/data_model.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The 'adjust' effect itself: a counting handler proves the op LANDED. */
static int landed_adjusts = 0;
static crabs_error_e counting_adjust_handler(state_t* state, operation_t* op) {
  (void)state;
  (void)op;
  landed_adjusts++;
  return CRABS_SUCCESS;
}

/* Sign (R7-04 discipline: stamp the signer's CURRENT key_version) and
 * execute a fresh 'adjust' op through the named keyring key. */
static crabs_error_e execute_adjust_as(attribute_machine_t* am, state_t* state,
                                       const char* key_id,
                                       const ecdsa_keypair_t* signing_key,
                                       const uint64_t stamped_version) {
  static uint8_t uuid_counter = 0x10;
  user_t* reader = attribute_machine_find_user(am, "reader");
  assert(reader != NULL);
  operation_t* op = operation_create("adjust");
  assert(op != NULL);
  memset(op->uuid, ++uuid_counter, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "reader", CRABS_MAX_USER_ID - 1);
  op->lamport_time = uuid_counter;
  op->signer_key_version = stamped_version;
  strncpy(op->key_id, key_id, CRABS_MAX_KEY_ID - 1);
  op->sig_scheme = ECDSA_SECP256K1;
  serialized_buffer_t* wire = crabs_serialize_for_signing(op);
  assert(wire != NULL);
  assert(crypto_sign_operation(signing_key->private_key, wire->data,
                               wire->len, op->signature)
         == CRABS_SUCCESS);
  serialized_buffer_destroy(wire);
  crabs_error_e rc = state_machine_execute(state, op);
  operation_destroy(op);
  return rc;
}

int main(void) {
  /* The scheme registry the keyring dispatches through (the exact wiring
   * test_key_lifecycle.cpp:538-545 uses around state-machine execute). */
  crypto_sig_scheme_init();
  ecdsa_keypair_t* admin_key = crypto_ecdsa_generate();
  assert(admin_key != NULL);
  attribute_machine_t* am = attribute_machine_create("admin", admin_key->public_key);
  assert(am != NULL);
  /* Integrator wiring — the line wasm_helpers.c:242 and cli.c share. */
  am->base_state.attr_machine = am;
  state_t* state = &am->base_state;

  /* Reader: unprivileged fact at registration + the admin grant. The
   * key_version bumps at every mutation — 1 at register
   * (attribute_machine.c:495), 2 at grant (:617). On crabs-node this is
   * exactly what UserInfo.keyVersion reads (bindings/node/src/
   * crabs_node.cc:1147); the wasm readback of the same field is a stubbed 0. */
  ecdsa_keypair_t* reader_id_key = crypto_ecdsa_generate();
  assert(reader_id_key != NULL);
  assert(attribute_machine_register_user(am, "reader", reader_id_key->public_key,
                                         "vetted") == CRABS_SUCCESS);
  assert(attribute_machine_grant_role(am, "reader", "role", "member", "admin")
         == CRABS_SUCCESS);
  user_t* reader = attribute_machine_find_user(am, "reader");
  assert(reader != NULL);
  assert(reader->key_version == 2);
  printf("revocable OK: reader's epoch counter at %llu after register+grant\n",
         (unsigned long long)reader->key_version);

  /* Register the reader's SIGNING ledger key (keyring, v1.3 §9). Precise
   * honesty about the counter: the epoch counter bumps on RECORD mutations
   * (attributes, key status) — `user_key_register` itself does NOT bump it
   * (attribute_machine.c:1091-1151), so the value stays 2 here. */
  ecdsa_keypair_t* k1_key = crypto_ecdsa_generate();
  assert(k1_key != NULL);
  assert(user_key_register(reader, "k1", ECDSA_SECP256K1, k1_key->public_key,
                           33, "primary") == CRABS_SUCCESS);
  user_t* reader_now = attribute_machine_find_user(am, "reader");
  assert(reader_now != NULL);
  assert(reader_now->key_version == 2);

  /* The write gate + the reader's op via the keyring's explicit key path
   * (op carries key_id + sig_scheme — crypto.c:1322-1331). Grammar honesty:
   * the CRABS policy grammar is PREFIX ('AND' takes two clauses); a
   * single-clause policy must be the bare token — 'AND role:member' with
   * one clause silently mis-parses (an empty right operand evals false) and
   * refuses, pinned below. */
  assert(state_add_policy(state, "adjust", "role:member") == CRABS_SUCCESS);
  assert(state_machine_register_handler(state, "adjust", counting_adjust_handler)
         == CRABS_SUCCESS);
  assert(execute_adjust_as(am, state, "k1", k1_key, reader_now->key_version)
         == CRABS_SUCCESS);
  assert(landed_adjusts == 1);
  printf("revocable OK: reader's op landed on the active keyring key\n");

  /* Grammar pin: 'AND role:member' (one clause after AND) refuses a member
   * — the legacy prefix parser reads it as two operands and the empty right
   * one evaluates false (src/Crypto/crypto.c:676-696). */
  assert(state_add_policy(state, "adjust_pitfall", "AND role:member")
         == CRABS_SUCCESS);
  {
    static uint8_t pitfall_uuid = 0x30;
    operation_t* op = operation_create("adjust_pitfall");
    assert(op != NULL);
    memset(op->uuid, ++pitfall_uuid, CRABS_UUID_SIZE);
    strncpy(op->signer_id, "reader", CRABS_MAX_USER_ID - 1);
    op->lamport_time = pitfall_uuid;
    op->signer_key_version = reader_now->key_version;
    strncpy(op->key_id, "k1", CRABS_MAX_KEY_ID - 1);
    op->sig_scheme = ECDSA_SECP256K1;
    serialized_buffer_t* wire = crabs_serialize_for_signing(op);
    assert(wire != NULL);
    assert(crypto_sign_operation(k1_key->private_key, wire->data, wire->len,
                                 op->signature) == CRABS_SUCCESS);
    serialized_buffer_destroy(wire);
    assert(state_machine_execute(state, op) == CRABS_ERR_UNAUTHORIZED);
    operation_destroy(op);
    assert(landed_adjusts == 1);  /* the handler did not run */
  }
  printf("revocable OK: the one-clause 'AND role:member' pitfall refuses a member (fail-closed grammar)\n");
  reader_now = attribute_machine_find_user(am, "reader");
  assert(reader_now != NULL);

  /* SUSPEND (C-only surface, api-map §2): the key stops verifying — refused
   * with collapsed 'unauthorized' BEFORE any handler runs
   * (crypto.c:1325: status != KEY_ACTIVE). */
  assert(user_key_suspend(reader_now, "k1") == CRABS_SUCCESS);
  assert(user_key_find(reader_now, "k1")->status == KEY_SUSPENDED);
  assert(user_key_find_active(reader_now, ECDSA_SECP256K1) == NULL);
  reader_now = attribute_machine_find_user(am, "reader");
  assert(reader_now != NULL);
  const uint64_t version_at_suspend = reader_now->key_version;  /* 2 -> 3 */
  assert(version_at_suspend == 3);
  assert(execute_adjust_as(am, state, "k1", k1_key, version_at_suspend)
         == CRABS_ERR_UNAUTHORIZED);
  assert(landed_adjusts == 1);
  printf("revocable OK: suspended key refused (unauthorized), nothing landed\n");

  /* ACTIVATE recovers the key — and R8-A-5 bumps the version ON
   * activation, so every op signed while suspended is stale even for the
   * restored key. */
  assert(user_key_activate(reader_now, "k1") == CRABS_SUCCESS);
  assert(user_key_find(reader_now, "k1")->status == KEY_ACTIVE);
  reader_now = attribute_machine_find_user(am, "reader");
  assert(reader_now != NULL);
  const uint64_t version_after_reactivate = reader_now->key_version;  /* 5 */
  assert(version_after_reactivate == version_at_suspend + 1);
  /* The stale stamp refuses with the typed staleness error
   * (state_machine.c:862-873 — R7-04 mandatory, CRABS_ERR_KEY_STALE). */
  assert(execute_adjust_as(am, state, "k1", k1_key, version_at_suspend)
         == CRABS_ERR_KEY_STALE);
  /* The fresh stamp lands again. */
  assert(execute_adjust_as(am, state, "k1", k1_key, version_after_reactivate)
         == CRABS_SUCCESS);
  assert(landed_adjusts == 2);
  printf("revocable OK: reactivation is real, and the version bump killed the suspended-window stamps\n");

  /* ROTATE (C-only): the old key is revoked and the new one chained to it
   * (test_key_lifecycle.cpp:258-287). */
  ecdsa_keypair_t* k2_key = crypto_ecdsa_generate();
  assert(k2_key != NULL);
  reader_now = attribute_machine_find_user(am, "reader");
  assert(reader_now != NULL);
  assert(user_key_rotate(reader_now, "k1", "k2", ECDSA_SECP256K1,
                         k2_key->public_key, 33, "rotated primary")
         == CRABS_SUCCESS);
  reader_now = attribute_machine_find_user(am, "reader");
  assert(reader_now != NULL);
  /* Rotate bumps ONCE — via the revoke of the old key
   * (attribute_machine.c: user_key_revoke bumps; the k2 registration does
   * not). */
  assert(reader_now->key_version == version_after_reactivate + 1);
  assert(user_key_find(reader_now, "k1")->status == KEY_REVOKED);
  user_key_t* k2 = user_key_find(reader_now, "k2");
  assert(k2 != NULL);
  assert(k2->status == KEY_ACTIVE);
  assert(strcmp(k2->predecessor_key_id, "k1") == 0);
  assert(strcmp(reader_now->default_key_id, "k2") == 0);
  /* The rotated-away signing key authorizes nothing. */
  assert(execute_adjust_as(am, state, "k1", k1_key, reader_now->key_version)
         == CRABS_ERR_UNAUTHORIZED);
  assert(execute_adjust_as(am, state, "k2", k2_key, reader_now->key_version)
         == CRABS_SUCCESS);
  assert(landed_adjusts == 3);
  printf("revocable OK: rotation revoked the old key, chained the new one, old-key ops refused\n");

  /* The seal: the machine's own CP-ABE authority
   * (attribute_machine.c:309 wires abe_mk into the base state — the same
   * mk Node.encrypt uses). Seal under an epoch attribute the reader holds:
   * CRABS 'name:value' tokens map to OpenABE words (name_value,
   * src/Crypto/crypto.c:100-111 — 'epoch:1,member' -> 'epoch_1|member'). */
  const uint8_t payload[] = "vault payload at epoch one";
  abe_master_key_t* authority = (abe_master_key_t*)state->abe_mk;
  assert(authority != NULL);
  abe_ciphertext_t* sealed_v1 = crypto_abe_encrypt(
      authority, payload, sizeof(payload), "epoch_1 and member");
  assert(sealed_v1 != NULL);
  abe_user_key_t* reader_v1 = crypto_abe_keygen(authority, "epoch:1,member");
  assert(reader_v1 != NULL);
  uint8_t* opened = NULL;
  size_t opened_len = 0;
  assert(crypto_abe_decrypt(reader_v1, sealed_v1, &opened, &opened_len)
         == CRABS_SUCCESS);
  assert(opened_len == sizeof(payload));
  assert(memcmp(opened, payload, opened_len) == 0);
  free(opened);
  opened = NULL;
  printf("revocable OK: the epoch-one key opens the epoch-one seal\n");

  /* USER-LEVEL revocation (the tool both JS bindings expose:
   * revokeUser): admin-gated, terminal, bumps the epoch counter
   * (attribute_machine_revoke_user — the exact handler the bindings wrap,
   * attribute_machine.c:888-907). */
  assert(attribute_machine_revoke_user(am, "reader", "admin") == CRABS_SUCCESS);
  reader_now = attribute_machine_find_user(am, "reader");
  assert(reader_now != NULL);
  assert(reader_now->status == USER_REVOKED);
  assert(reader_now->key_version == version_after_reactivate + 2);  /* rotate +1, revoke +1 */
  printf("revocable OK: user revoked (terminal), epoch counter now %llu\n",
         (unsigned long long)reader_now->key_version);

  /* Every authorization gate whitelists USER_ACTIVE (attribute_machine.c:588
   * audit R4-2) — the revoked reader's op refuses fail-closed even with an
   * ACTIVE key (mode A status collapse, crypto.c:1395-1403, R7-14), and
   * re-grants are refused too. */
  assert(execute_adjust_as(am, state, "k2", k2_key, reader_now->key_version)
         == CRABS_ERR_UNAUTHORIZED);
  assert(landed_adjusts == 3);
  assert(attribute_machine_grant_role(am, "reader", "role", "member", "admin")
         == CRABS_ERR_USER_SUSPENDED);
  printf("revocable OK: revoked user's ops and re-grants refused (fail-closed)\n");

  /* THE HONEST BOUNDARY: revocation did NOT recall the CP-ABE key the reader
   * already holds. crypto_abe_decrypt consults no revocation registry and no
   * user status (crypto.c:1041-1079) — the pre-revocation key still opens
   * the pre-revocation ciphertext. This is the property every revocation
   * scheme on this codebase must be designed AROUND. */
  assert(crypto_abe_decrypt(reader_v1, sealed_v1, &opened, &opened_len)
         == CRABS_SUCCESS);
  free(opened);
  opened = NULL;
  printf("revocable OK (boundary): the already-held ABE key still opens the old ciphertext after revocation\n");

  /* So the real recall is the re-key: seal v2 under the NEXT epoch. The
   * epoch-one key misses the new clause ('epoch_1 and member' != 'epoch_2
   * and member' — CRABS_ERR_UNAUTHORIZED), and a FRESH derivation for the
   * re-keyed audience (a new enrollment; the old account stays terminal)
   * opens it. */
  const uint8_t payload_v2[] = "vault payload at epoch two";
  abe_ciphertext_t* sealed_v2 = crypto_abe_encrypt(
      authority, payload_v2, sizeof(payload_v2), "epoch_2 and member");
  assert(sealed_v2 != NULL);
  assert(crypto_abe_decrypt(reader_v1, sealed_v2, &opened, &opened_len)
         == CRABS_ERR_UNAUTHORIZED);
  abe_user_key_t* audience_v2 = crypto_abe_keygen(authority, "epoch:2,member");
  assert(audience_v2 != NULL);
  assert(crypto_abe_decrypt(audience_v2, sealed_v2, &opened, &opened_len)
         == CRABS_SUCCESS);
  assert(opened_len == sizeof(payload_v2));
  assert(memcmp(opened, payload_v2, opened_len) == 0);
  free(opened);
  opened = NULL;
  printf("revocable OK: re-encryption under the next epoch recalled access — old key refused, new audience opened\n");

  crypto_abe_user_key_destroy(reader_v1);
  crypto_abe_user_key_destroy(audience_v2);
  crypto_abe_ciphertext_destroy(sealed_v1);
  crypto_abe_ciphertext_destroy(sealed_v2);

  attribute_machine_destroy(am);
  crypto_ecdsa_keypair_destroy(k1_key);
  crypto_ecdsa_keypair_destroy(k2_key);
  crypto_ecdsa_keypair_destroy(reader_id_key);
  crypto_ecdsa_keypair_destroy(admin_key);
  crypto_sig_scheme_cleanup();
  return 0;
}