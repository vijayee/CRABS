/* Recipe 3 — execute once, ever (C core): the flag, its once-set, and the
 * strict DEDUP_GLOBAL guard.
 *
 * The JS bindings can only raise and read the boolean; the C struct records
 * WHO set it and WHEN, second sets are no-ops, and a registered GLOBAL
 * DedupSpec rejects any second execution attempt before it runs (mirrors
 * test/test_one_shot.cpp and the GlobalExecutionOnceLifecycle in
 * test/test_dedup.cpp:726-762). */
#include "CRABS/crabs.h"
#include "CRDT/one_shot.h"
#include "CRDT/crdt_merge.h"
#include "Dedup/dedup.h"
#include "CRABS/data_model.h"
#include "StateMachine/state_machine.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  /* --- the flag itself: exactly one transition, first setter wins --- */
  one_shot_flag_t* flag = one_shot_flag_create();
  assert(flag != NULL);
  assert(one_shot_flag_value(flag) == false);

  assert(one_shot_flag_set(flag, "carol", 1000) == CRABS_SUCCESS);
  assert(one_shot_flag_value(flag) == true);
  assert(strcmp(flag->set_by, "carol") == 0);
  assert(flag->set_at == (uint64_t)1000);

  /* A second set with a different setter is a no-op — the once-property.
   * JS raises the flag but cannot observe this; C can. */
  assert(one_shot_flag_set(flag, "dave", 2000) == CRABS_SUCCESS);
  assert(one_shot_flag_value(flag) == true);
  assert(strcmp(flag->set_by, "carol") == 0);
  assert(flag->set_at == (uint64_t)1000);

  /* Merge: two replicas that each saw an execution keep the EARLIER one. */
  one_shot_flag_t* remote = one_shot_flag_create();
  assert(remote != NULL);
  assert(one_shot_flag_set(remote, "bob", 2000) == CRABS_SUCCESS);
  one_shot_flag_t* merged = one_shot_flag_merge(flag, remote);
  assert(merged != NULL);
  assert(one_shot_flag_value(merged) == true);
  assert(strcmp(merged->set_by, "carol") == 0);
  assert(merged->set_at == (uint64_t)1000);

  printf("execute-once OK: first setter kept after merge\n");
  one_shot_flag_destroy(merged);
  one_shot_flag_destroy(remote);
  one_shot_flag_destroy(flag);

  /* --- the strict version: a registered DEDUP_GLOBAL spec guards the op --- */
  state_t* state = state_create();
  assert(state != NULL);
  data_item_t* executed = data_item_create("proposal_42_executed",
                                           DATA_TYPE_ONE_SHOT_FLAG,
                                           CRDT_ONE_SHOT_FLAG);
  assert(executed != NULL);
  executed->value = one_shot_flag_create();
  executed->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  assert(state_add_item(state, executed) == CRABS_SUCCESS);

  dedup_spec_t spec;
  memset(&spec, 0, sizeof(spec));
  spec.type = DEDUP_GLOBAL;
  strncpy(spec.flag_path, "proposal_42_executed", CRABS_MAX_DEDUP_PATH - 1);
  assert(state_register_op_type_def(state, "execute_proposal", &spec)
         == CRABS_SUCCESS);

  operation_t* first = operation_create("execute_proposal");
  assert(first != NULL);
  strncpy(first->signer_id, "carol", CRABS_MAX_USER_ID - 1);
  const dedup_spec_t* registered = state_find_op_type_def(state, "execute_proposal");
  assert(registered != NULL && registered->type == DEDUP_GLOBAL);
  assert(dedup_check_guard_spec(state, registered, first) == CRABS_SUCCESS);
  assert(dedup_apply_mutation_spec(state, registered, first) == CRABS_SUCCESS);
  assert(one_shot_flag_value((one_shot_flag_t*)executed->value) == true);
  operation_destroy(first);

  /* A different signer's attempt is rejected — the guard is global. */
  operation_t* second = operation_create("execute_proposal");
  assert(second != NULL);
  strncpy(second->signer_id, "dave", CRABS_MAX_USER_ID - 1);
  assert(dedup_check_guard_spec(state, registered, second)
         == CRABS_ERR_ALREADY_EXECUTED);
  operation_destroy(second);

  printf("execute-once OK: DEDUP_GLOBAL rejects the second run\n");

  crdt_value_destroy(executed->crdt_type, executed->value);
  executed->value = NULL;
  state_destroy(state);
  return 0;
}