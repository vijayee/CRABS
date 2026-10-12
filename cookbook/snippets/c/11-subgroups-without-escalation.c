/* Recipe 11 — a group with subgroups that can't escalate (C core).
 *
 * The full parent-side lineage flow on the C surface: build + validate a
 * blueprint (the subgroup's charter), spawn the child machine, verify the
 * fresh-authority isolation (a DELEGATED_COPY child mints its own MSK and
 * its own user registry), refuse a duplicate child id, then dissolve the
 * child through the OP PIPELINE (a registered role:admin user signs the
 * __dissolve_machine__ op) and watch the manifest flip to dissolved with
 * the resident slot cleared. Signing discipline mirrors
 * test/test_durability.cpp:98-106 as in snippet 04; lineage usage mirrors
 * test/test_lineage.cpp (SpawnSharedRootSharesParentAuthority,
 * SpawnDelegatedCopyMintsFreshAuthority, SpawnRejectsDuplicateChildId,
 * QueryResidentChildAccessor). */
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

int main(void) {
  /* Machine A: the parent group machine. attribute_machine_create seeds the
   * genesis admin with role:admin; the node key is what signs attestations
   * and tombstones. */
  ecdsa_keypair_t* parent_key = crypto_ecdsa_generate();
  assert(parent_key != NULL);
  attribute_machine_t* parent =
      attribute_machine_create("parent-root", parent_key->public_key);
  assert(parent != NULL);
  assert(state_set_node_key(&parent->base_state, parent_key->private_key,
                            parent_key->public_key) == CRABS_SUCCESS);
  parent->base_state.attr_machine = parent;

  /* The lineage ops become submitable through the pipeline after install. */
  lineage_install(&parent->base_state);

  /* ---- The subgroup's charter: a validated blueprint -------------------- */
  machine_blueprint_t* blueprint = machine_blueprint_create();
  assert(blueprint != NULL);
  strncpy(blueprint->child_id, "billing-team", sizeof(blueprint->child_id) - 1);
  blueprint->trust_mode = LINEAGE_DELEGATED_COPY;
  strncpy(blueprint->bootstrap_admin, "team-admin",
          sizeof(blueprint->bootstrap_admin) - 1);
  blueprint->attestation_ttl_ms = 3600000;
  assert(blueprint_add_item(blueprint, "score", DATA_TYPE_COUNTER,
                            CRDT_G_COUNTER) == CRABS_SUCCESS);
  assert(blueprint_add_policy(blueprint, "view", "role:member")
         == CRABS_SUCCESS);
  assert(lineage_blueprint_validate(blueprint) == CRABS_SUCCESS);

  /* Spawn: the child machine is built, parent-bound, and pinned to the
   * parent's node key (chain entry [0]); only afterwards is the manifest
   * entry appended — every earlier failure leaves no residue. */
  attribute_machine_t* child = NULL;
  assert(lineage_spawn_machine(&parent->base_state, blueprint, &child)
         == CRABS_SUCCESS);
  assert(child != NULL);

  /* Fresh authority — the isolation that makes the subgroup its own machine:
   * its attribute machine is its OWN (the registry the child's ops resolve
   * through), its MSK is its own (borrowed nowhere), and the parent's
   * registry does not leak in. */
  assert(child->base_state.attr_machine == child);
  assert(child->base_state.abe_mk != parent->base_state.abe_mk);
  assert(child->base_state.abe_mk_borrowed == false);
  assert(attribute_machine_find_user(child, "dissolver") == NULL);
  assert(attribute_machine_find_user(child, "team-admin") != NULL);
  assert(child->base_state.lineage_parent_bound == true);
  assert(strcmp(child->base_state.lineage_parent_id, "parent-root") == 0);
  assert(strcmp(child->base_state.lineage_self_id, "billing-team") == 0);

  /* The manifest is the parent's durable track record. The query hands back
   * a BORROWED view: the return value is the entry count, *out_entries the
   * state-owned array. */
  child_manifest_entry_t const* manifest_entries = NULL;
  uint32_t child_count = lineage_query_children(&parent->base_state,
                                                &manifest_entries);
  assert(manifest_entries != NULL);
  assert(child_count == 1u);
  assert(strcmp(manifest_entries[0].child_id, "billing-team") == 0);
  assert(manifest_entries[0].mode == LINEAGE_DELEGATED_COPY);
  assert(manifest_entries[0].status == LINEAGE_ACTIVE);
  assert(manifest_entries[0].attestation_ttl_ms == 3600000u);

  /* No double-mint: the same child_id is refused even with identical
   * content (and the parent's own machine id is refused too). */
  attribute_machine_t* duplicate = NULL;
  assert(lineage_spawn_machine(&parent->base_state, blueprint, &duplicate)
         == CRABS_ERR_DUPLICATE_OPERATION);
  assert(duplicate == NULL);

  /* ---- Severance, through the OP PIPELINE -------------------------------
   * role:admin must resolve against a registered user: register 'dissolver'
   * (unprivileged facts only — register_user rejects privileged attribute
   * names) and grant the admin role on the admin path. */
  ecdsa_keypair_t* dissolver_key = crypto_ecdsa_generate();
  assert(dissolver_key != NULL);
  assert(attribute_machine_register_user(parent, "dissolver",
                                         dissolver_key->public_key, "adult")
         == CRABS_SUCCESS);
  assert(attribute_machine_grant_role(parent, "dissolver", "role", "admin",
                                      "parent-root") == CRABS_SUCCESS);

  operation_t* dissolve = operation_create(CRABS_LINEAGE_OP_DISSOLVE);
  assert(dissolve != NULL);
  memset(dissolve->uuid, 0xD1, CRABS_UUID_SIZE);
  strncpy(dissolve->signer_id, "dissolver", CRABS_MAX_USER_ID - 1);
  dissolve->lamport_time = 1;
  user_t* dissolver = attribute_machine_find_user(parent, "dissolver");
  assert(dissolver != NULL);
  dissolve->signer_key_version = dissolver->key_version;
  dissolve->payload = (uint8_t*)malloc(strlen("billing-team"));
  assert(dissolve->payload != NULL);
  memcpy(dissolve->payload, "billing-team", strlen("billing-team"));
  dissolve->payload_size = (uint32_t)strlen("billing-team");
  serialized_buffer_t* dissolve_wire = crabs_serialize_for_signing(dissolve);
  assert(dissolve_wire != NULL);
  assert(crypto_sign_operation(dissolver_key->private_key, dissolve_wire->data,
                               dissolve_wire->len, dissolve->signature)
         == CRABS_SUCCESS);
  serialized_buffer_destroy(dissolve_wire);
  assert(state_machine_execute(&parent->base_state, dissolve)
         == CRABS_SUCCESS);
  operation_destroy(dissolve);

  /* Teeth: the in-process dissolve durably flagged the child (every parent
   * endorsement on it fails closed from now), the resident slot is gone,
   * and the manifest entry reads DISSOLVED. */
  assert(lineage_query_resident_child(&parent->base_state, "billing-team")
         == NULL);
  assert(child->base_state.lineage_parent_dissolved == true);
  assert(manifest_entries[0].status == LINEAGE_DISSOLVED);

  /* The parent's vouching stops on refusal: attestations for a non-ACTIVE
   * manifest entry fail closed. */
  attestation_t attestation = {0};
  assert(crabs_issue_attestation(&parent->base_state, &attestation,
                                 "billing-team", "alice", "role:member", 0)
         == CRABS_ERR_UNAUTHORIZED);

  attribute_machine_destroy(child);
  machine_blueprint_destroy(blueprint);
  attribute_machine_destroy(parent);
  crypto_ecdsa_keypair_destroy(parent_key);
  crypto_ecdsa_keypair_destroy(dissolver_key);

  printf("subgroups-without-escalation OK: spawned, isolated, duplicated"
         " refuse, dissolved\n");
  return 0;
}