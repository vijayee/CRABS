/* Recipe 12 — federating two machines' machines via attestations (C core).
 *
 * The consumption side of federation, which lives in C (the JS bindings can
 * issue attestations but never attach or resolve them): a child machine is
 * bound to a parent, its policy carries a @parent/ endorsement token, and an
 * op signed by a member — carrying the parent-signed attestation in its
 * payload — authorizes through the attestation, tip-verified against the
 * child's parent-key chain. Every failure mode fails closed: forged parent,
 * wrong child, wrong user, uncovered attributes, expired window, tampered
 * body, and an unbound machine. Mirrors test/test_lineage.cpp
 * (AttestationSignVerifyRoundTrip, AttestationForWrongUserOrAttributesFailsClosed,
 * MatchingAttestationAuthorizesEndorsementPolicy, AttestationSignedByWrongParentFailsClosed). */
#include "Lineage/lineage.h"
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
#include <time.h>

/* Attach a value copy of the attestation to the op (the executor verifies
 * op->attestations during authorization). Single-op demo; the exec/validate
 * pipeline copies nothing back. */
static void attach_attestation(operation_t* op, const attestation_t* att) {
  op->attestations = (attestation_t*)malloc(sizeof(attestation_t));
  assert(op->attestations != NULL);
  op->attestations[0] = *att;
  op->attestation_count = 1;
}

/* A signed __check_dedup__ op by 'alice' — the authorization-only builtin
 * makes the whole pipeline observable (state_machine_validate) without any
 * resource machinery. Signature discipline as in snippet 04. */
static operation_t* make_signed_dedup_check_op(attribute_machine_t* registry,
                                               ecdsa_keypair_t* alice_key) {
  operation_t* op = operation_create(CRABS_OP_CHECK_DEDUP);
  assert(op != NULL);
  memset(op->uuid, 0x42, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  user_t* signer = attribute_machine_find_user(registry, "alice");
  assert(signer != NULL);
  op->signer_key_version = signer->key_version;
  op->lamport_time = 1;
  serialized_buffer_t* wire = crabs_serialize_for_signing(op);
  assert(wire != NULL);
  assert(crypto_sign_operation(alice_key->private_key, wire->data, wire->len,
                               op->signature) == CRABS_SUCCESS);
  serialized_buffer_destroy(wire);
  return op;
}

int main(void) {
  /* ---- The two federating machines -------------------------------------
   * Machine A (the parent): a bare state with its node key — the signer of
   * attestations. Machine B (the child): its own attribute machine with an
   * 'alice' registered by its OWN genesis admin, bound to the parent. */
  ecdsa_keypair_t* parent_key = crypto_ecdsa_generate();
  assert(parent_key != NULL);
  state_t* parent = state_create();
  assert(parent != NULL);
  assert(state_set_node_key(parent, parent_key->private_key,
                            parent_key->public_key) == CRABS_SUCCESS);

  state_t* child_state = state_create();
  assert(child_state != NULL);
  ecdsa_keypair_t* alice_key = crypto_ecdsa_generate();
  assert(alice_key != NULL);
  ecdsa_keypair_t* child_admin_key = crypto_ecdsa_generate();
  assert(child_admin_key != NULL);
  attribute_machine_t* registry =
      attribute_machine_create("b-admin", child_admin_key->public_key);
  assert(registry != NULL);
  assert(attribute_machine_register_user(registry, "alice",
                                         alice_key->public_key, "")
         == CRABS_SUCCESS);
  assert(attribute_machine_grant_role(registry, "alice", "role", "admin",
                                      "b-admin") == CRABS_SUCCESS);
  child_state->attr_machine = registry;
  assert(state_add_policy(child_state, CRABS_OP_CHECK_DEDUP,
                          "@parent/role:writer") == CRABS_SUCCESS);

  /* Bind the child to the parent: the parent's public key, ids, bound flag,
   * and chain entry [0] — the spawn pin — so chain-aware verification works
   * from genesis (spawn stamps the same shape; see recipe 11). */
  memcpy(child_state->lineage_parent_public_key, parent_key->public_key, 33);
  strncpy(child_state->lineage_parent_id, "parent-root",
          sizeof(child_state->lineage_parent_id) - 1);
  strncpy(child_state->lineage_self_id, "child-red",
          sizeof(child_state->lineage_self_id) - 1);
  child_state->lineage_parent_bound = true;
  child_state->lineage_key_chain =
      (lineage_key_chain_entry_t*)calloc(1, sizeof(lineage_key_chain_entry_t));
  assert(child_state->lineage_key_chain != NULL);
  child_state->lineage_key_chain[0].key_version =
      CRABS_LINEAGE_KEY_VERSION_START;
  memcpy(child_state->lineage_key_chain[0].public_key, parent_key->public_key,
         33);
  child_state->lineage_key_chain_count = 1;

  /* ---- The vouch: A signs a TTL-bounded attestation for alice -----------
   * The window is stamped from the CALLER's time (the machine never reads
   * the wall clock itself); on the child, the pipeline reads the machine's
   * own time source — the default here is the platform clock, and the
   * window is deliberately wide. */
  const uint64_t now_ms = (uint64_t)time(NULL) * 1000ULL;
  attestation_t attestation = {0};
  assert(attestation_create(parent, &attestation, "parent-root", "child-red",
                            "alice", "role:writer", now_ms - 60000,
                            now_ms + 3600000) == CRABS_SUCCESS);
  assert(attestation.format_version == CRABS_ATTESTATION_FORMAT_VERSION);
  assert(attestation.parent_key_version == CRABS_LINEAGE_KEY_VERSION_START);

  /* Byte transport round trip: the wire image (u32le length + body +
   * signature) re-parses and re-verifies — the exact bytes crossing the
   * federation seam. */
  uint8_t wire[CRABS_ATTESTATION_WIRE_MAX];
  size_t wire_len = attestation_serialize(&attestation, wire, sizeof(wire));
  assert(wire_len > 0);
  attestation_t* restored = attestation_deserialize(wire, wire_len);
  assert(restored != NULL);
  assert(attestation_verify(parent_key->public_key, "child-red", restored,
                            now_ms + 10) == true);
  attestation_destroy(restored);

  /* ---- The consume: alice's op on the child now authorizes -------------
   * The endorsement policy needs ONE attestation that verifies against the
   * chain TIP, names the child's parent, names the RESOLVED signer, and
   * covers the endorsement attribute exactly. */
  operation_t* endorsed = make_signed_dedup_check_op(registry, alice_key);
  attach_attestation(endorsed, &attestation);
  assert(state_machine_validate(child_state, endorsed) == CRABS_SUCCESS);
  operation_destroy(endorsed);

  /* A comma-separated list covers the endorsement when it CONTAINS the
   * exact attribute among several — a fresh, properly signed multi-
   * attribute attestation (a post-mint edit would break the signature). */
  attestation_t multi_attr = {0};
  assert(attestation_create(parent, &multi_attr, "parent-root", "child-red",
                            "alice", "dept:red,role:writer", now_ms - 60000,
                            now_ms + 3600000) == CRABS_SUCCESS);
  operation_t* covered_among_many =
      make_signed_dedup_check_op(registry, alice_key);
  attach_attestation(covered_among_many, &multi_attr);
  assert(state_machine_validate(child_state, covered_among_many)
         == CRABS_SUCCESS);
  operation_destroy(covered_among_many);

  /* ---- Fail-closed paths (every one is engine-tested behavior) ----------
   * Forged parent: right shape, WRONG parent key. */
  ecdsa_keypair_t* impostor_key = crypto_ecdsa_generate();
  state_t* impostor = state_create();
  assert(state_set_node_key(impostor, impostor_key->private_key,
                            impostor_key->public_key) == CRABS_SUCCESS);
  attestation_t forged = {0};
  assert(attestation_create(impostor, &forged, "parent-root", "child-red",
                            "alice", "role:writer", now_ms - 60000,
                            now_ms + 3600000) == CRABS_SUCCESS);
  operation_t* forged_op = make_signed_dedup_check_op(registry, alice_key);
  attach_attestation(forged_op, &forged);
  assert(state_machine_validate(child_state, forged_op)
         == CRABS_ERR_UNAUTHORIZED);
  operation_destroy(forged_op);

  /* Wrong child id: the canonical check matches exactly. */
  attestation_t wrong_child = {0};
  assert(attestation_create(parent, &wrong_child, "parent-root", "child-blue",
                            "alice", "role:writer", now_ms - 60000,
                            now_ms + 3600000) == CRABS_SUCCESS);
  assert(attestation_verify(parent_key->public_key, "child-red",
                            &wrong_child, now_ms) == false);

  /* Wrong attested user: must name the op's RESOLVED signer. */
  attestation_t wrong_user = {0};
  assert(attestation_create(parent, &wrong_user, "parent-root", "child-red",
                            "bob", "role:writer", now_ms - 60000,
                            now_ms + 3600000) == CRABS_SUCCESS);
  operation_t* wrong_user_op = make_signed_dedup_check_op(registry, alice_key);
  attach_attestation(wrong_user_op, &wrong_user);
  assert(state_machine_validate(child_state, wrong_user_op)
         == CRABS_ERR_UNAUTHORIZED);
  operation_destroy(wrong_user_op);

  /* Uncovered attributes: the list must contain the endorsement EXACTLY. */
  attestation_t uncovered = {0};
  assert(attestation_create(parent, &uncovered, "parent-root", "child-red",
                            "alice", "role:reader", now_ms - 60000,
                            now_ms + 3600000) == CRABS_SUCCESS);
  operation_t* uncovered_op = make_signed_dedup_check_op(registry, alice_key);
  attach_attestation(uncovered_op, &uncovered);
  assert(state_machine_validate(child_state, uncovered_op)
         == CRABS_ERR_UNAUTHORIZED);
  operation_destroy(uncovered_op);

  /* The TTL: expiry refuses. attestation_verify checks
   * not_before <= now <= expires_at; the endorsement pipeline reads the
   * child's own time source — so expiry is only ever as trustworthy as the
   * clocks on BOTH machines. */
  attestation_t expired = {0};
  assert(attestation_create(parent, &expired, "parent-root", "child-red",
                            "alice", "role:writer", now_ms - 120000,
                            now_ms - 60000) == CRABS_SUCCESS);
  assert(attestation_verify(parent_key->public_key, "child-red", &expired,
                            now_ms) == false);

  /* Tampered body: any body byte flip breaks the signature check. */
  operation_t* intact = make_signed_dedup_check_op(registry, alice_key);
  attach_attestation(intact, &attestation);
  assert(state_machine_validate(child_state, intact) == CRABS_SUCCESS);
  attestation_t tampered = attestation;
  tampered.attributes[0] ^= 0x01;
  assert(attestation_verify(parent_key->public_key, "child-red", &tampered,
                            now_ms) == false);
  operation_destroy(intact);

  /* An UNBOUND machine (never spawned/pinned): an endorsement policy can
   * neither fail open nor be satisfied by any attestation. */
  state_t* unbound = state_create();
  assert(unbound != NULL);
  attribute_machine_t* unbound_registry =
      attribute_machine_create("unbound-admin", child_admin_key->public_key);
  assert(unbound_registry != NULL);
  assert(attribute_machine_register_user(unbound_registry, "alice",
                                         alice_key->public_key, "")
         == CRABS_SUCCESS);
  assert(attribute_machine_grant_role(unbound_registry, "alice", "role",
                                      "admin", "unbound-admin")
         == CRABS_SUCCESS);
  unbound->attr_machine = unbound_registry;
  assert(state_add_policy(unbound, CRABS_OP_CHECK_DEDUP,
                          "@parent/role:writer") == CRABS_SUCCESS);
  operation_t* unbound_op =
      make_signed_dedup_check_op(unbound_registry, alice_key);
  attach_attestation(unbound_op, &attestation);
  assert(state_machine_validate(unbound, unbound_op)
         == CRABS_ERR_UNAUTHORIZED);
  operation_destroy(unbound_op);

  attribute_machine_destroy(unbound_registry);
  state_destroy(unbound);
  crypto_ecdsa_keypair_destroy(impostor_key);
  state_destroy(impostor);
  attribute_machine_destroy(registry);
  state_destroy(child_state);
  state_destroy(parent);
  crypto_ecdsa_keypair_destroy(alice_key);
  crypto_ecdsa_keypair_destroy(child_admin_key);
  crypto_ecdsa_keypair_destroy(parent_key);

  printf("federation-between-machines OK: attestation round-trips, endorsed"
         " op authorized, forgery/expiry/tamper/unbound refused\n");
  return 0;
}