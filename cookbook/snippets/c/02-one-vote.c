/* Recipe 2 — one vote per member (C core): the strict DedupSpec guard.
 *
 * Where the JS bindings can only track who voted, the C core can ENFORCE it:
 * a DEDUP_PER_USER spec registered for the "vote" op type is resolved by the
 * executor via state_find_op_type_def and guarded regardless of what the op
 * carries on the wire (audit F-2). This mirrors the guard/apply lifecycle in
 * test/test_dedup.cpp. */
#include "Dedup/dedup.h"
#include "CRABS/data_model.h"
#include "CRABS/crabs.h"
#include "CRDT/one_shot.h"
#include "CRDT/crdt_merge.h"
#include "StateMachine/state_machine.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  state_t* state = state_create();
  assert(state != NULL);

  /* The once-record the spec guards on. */
  data_item_t* voters = data_item_create("proposal_42_voters",
                                         DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  assert(voters != NULL);
  voters->value = one_shot_set_create();
  voters->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  assert(state_add_item(state, voters) == CRABS_SUCCESS);

  /* Register the strict per-user spec SERVER-SIDE. A signer cannot change
   * this definition, and cannot bypass it by sending dedup.type = NONE. */
  dedup_spec_t spec;
  memset(&spec, 0, sizeof(spec));
  spec.type = DEDUP_PER_USER;
  strncpy(spec.tracker_path, "proposal_42_voters", CRABS_MAX_DEDUP_PATH - 1);
  assert(state_register_op_type_def(state, "vote", &spec) == CRABS_SUCCESS);

  /* Alice's first vote — carried with dedup.type = DEDUP_NONE (the default)
   * to show the registered spec wins over the wire. */
  operation_t* first = operation_create("vote");
  assert(first != NULL);
  strncpy(first->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  const dedup_spec_t* registered = state_find_op_type_def(state, "vote");
  assert(registered != NULL && registered->type == DEDUP_PER_USER);
  assert(dedup_check_guard_spec(state, registered, first) == CRABS_SUCCESS);
  assert(dedup_apply_mutation_spec(state, registered, first) == CRABS_SUCCESS);
  operation_destroy(first);
  assert(one_shot_set_count((one_shot_set_t*)voters->value) == 1);

  /* Alice's second attempt: the guard rejects before anything lands. */
  operation_t* retry = operation_create("vote");
  assert(retry != NULL);
  strncpy(retry->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  retry->dedup.type = DEDUP_NONE; /* the would-be bypass */
  assert(dedup_check_guard_spec(state, registered, retry)
         == CRABS_ERR_ALREADY_PERFORMED);
  operation_destroy(retry);
  assert(one_shot_set_count((one_shot_set_t*)voters->value) == 1);

  /* A different member still passes; the union grows monotonic. */
  operation_t* bobs = operation_create("vote");
  assert(bobs != NULL);
  strncpy(bobs->signer_id, "bob", CRABS_MAX_USER_ID - 1);
  assert(dedup_check_guard_spec(state, registered, bobs) == CRABS_SUCCESS);
  assert(dedup_apply_mutation_spec(state, registered, bobs) == CRABS_SUCCESS);
  operation_destroy(bobs);
  assert(one_shot_set_count((one_shot_set_t*)voters->value) == 2);
  assert(one_shot_set_contains((one_shot_set_t*)voters->value, "alice"));
  assert(one_shot_set_contains((one_shot_set_t*)voters->value, "bob"));

  printf("one-vote OK: voters=2, alice retry rejected\n");

  /* The item's CRDT struct value is released before the state that owns the
   * item shell (same teardown convention as test/test_dedup.cpp). */
  crdt_value_destroy(voters->crdt_type, voters->value);
  voters->value = NULL;
  state_destroy(state);
  return 0;
}