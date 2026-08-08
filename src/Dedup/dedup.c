//
// CRABS v1.4: DedupSpec & Desugaring (§3-4)
//

#include "dedup.h"
#include "../Util/allocator.h"
#include "../Condition/condition.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

// ============================================================
// Path resolution
// ============================================================

data_item_t* dedup_resolve_path(state_t* state, const char* path) {
  if (state == NULL || path == NULL) return NULL;

  // Find the first dot to separate item name from field
  char path_buf[CRABS_MAX_DEDUP_PATH];
  strncpy(path_buf, path, CRABS_MAX_DEDUP_PATH - 1);
  path_buf[CRABS_MAX_DEDUP_PATH - 1] = '\0';

  // The path refers to a data item name (e.g., "proposal_42")
  // We look up the item directly
  return state_find_item(state, path_buf);
}

// ============================================================
// Dedup Guard Check (§5.2)
// ============================================================
// NOTE: state_machine_execute now uses dedup_check_and_apply_spec (below)
// for the step 8 mutation, which re-checks the guard and applies the mutation
// atomically in a single call. The step 5 guard check (dedup_check_guard_spec)
// is a fast-fail before the handler runs; the step 8 atomic check-and-apply
// is the authoritative enforcement.

crabs_error_e dedup_check_guard_spec(const state_t* state,
                                        const dedup_spec_t* spec,
                                        const operation_t* op) {
  if (state == NULL || op == NULL || spec == NULL) return CRABS_ERR_INVALID_PARAM;

  switch (spec->type) {
    case DEDUP_NONE:
      return CRABS_SUCCESS;

    case DEDUP_PER_USER: {
      // Find the tracker ONE_SHOT_SET
      data_item_t* tracker = state_find_item((state_t*)state, spec->tracker_path);
      if (tracker == NULL) return CRABS_ERR_TRACKER_NOT_FOUND;

      // Verify it's a ONE_SHOT_SET
      if (tracker->type != DATA_TYPE_ONE_SHOT_SET) return CRABS_ERR_TRACKER_NOT_FOUND;

      // Check if the signer is already in the set
      one_shot_set_t* set = (one_shot_set_t*)tracker->value;
      if (set != NULL && one_shot_set_contains(set, op->signer_id)) {
        return CRABS_ERR_ALREADY_PERFORMED;
      }
      return CRABS_SUCCESS;
    }

    case DEDUP_GLOBAL: {
      // Find the flag ONE_SHOT_FLAG
      data_item_t* flag_item = state_find_item((state_t*)state, spec->flag_path);
      if (flag_item == NULL) return CRABS_ERR_FLAG_NOT_FOUND;

      // Verify it's a ONE_SHOT_FLAG
      if (flag_item->type != DATA_TYPE_ONE_SHOT_FLAG) return CRABS_ERR_FLAG_NOT_FOUND;

      // Check if the flag is already set
      one_shot_flag_t* flag = (one_shot_flag_t*)flag_item->value;
      if (flag != NULL && one_shot_flag_value(flag)) {
        return CRABS_ERR_ALREADY_EXECUTED;
      }
      return CRABS_SUCCESS;
    }

    case DEDUP_CUSTOM: {
      // Evaluate the condition expression against the current state
      if (spec->condition[0] == '\0') return CRABS_ERR_CONDITION_NOT_MET;
      condition_node_t* ast = condition_parse(spec->condition);
      if (ast == NULL) return CRABS_ERR_CONDITION_NOT_MET;
      bool result = condition_evaluate(ast, state);
      condition_node_destroy(ast);
      return result ? CRABS_SUCCESS : CRABS_ERR_CONDITION_NOT_MET;
    }

    default:
      return CRABS_ERR_INVALID_PARAM;
  }
}

crabs_error_e dedup_check_guard(const state_t* state, const operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  return dedup_check_guard_spec(state, &op->dedup, op);
}

// ============================================================
// Dedup State Mutation (§5.3)
// ============================================================

crabs_error_e dedup_apply_mutation_spec(state_t* state,
                                          const dedup_spec_t* spec,
                                          const operation_t* op) {
  if (state == NULL || op == NULL || spec == NULL) return CRABS_ERR_INVALID_PARAM;

  switch (spec->type) {
    case DEDUP_NONE:
      return CRABS_SUCCESS;

    case DEDUP_PER_USER: {
      // Add signer to the tracker ONE_SHOT_SET
      data_item_t* tracker = state_find_item(state, spec->tracker_path);
      if (tracker == NULL) return CRABS_ERR_TRACKER_NOT_FOUND;
      if (tracker->type != DATA_TYPE_ONE_SHOT_SET) return CRABS_ERR_TRACKER_NOT_FOUND;

      one_shot_set_t* set = (one_shot_set_t*)tracker->value;
      if (set == NULL) return CRABS_ERR_TRACKER_NOT_FOUND;

      return one_shot_set_add(set, op->signer_id);
    }

    case DEDUP_GLOBAL: {
      // Set the flag ONE_SHOT_FLAG
      data_item_t* flag_item = state_find_item(state, spec->flag_path);
      if (flag_item == NULL) return CRABS_ERR_FLAG_NOT_FOUND;
      if (flag_item->type != DATA_TYPE_ONE_SHOT_FLAG) return CRABS_ERR_FLAG_NOT_FOUND;

      one_shot_flag_t* flag = (one_shot_flag_t*)flag_item->value;
      if (flag == NULL) return CRABS_ERR_FLAG_NOT_FOUND;

      return one_shot_flag_set(flag, op->signer_id, op->lamport_time);
    }

    case DEDUP_CUSTOM: {
      state_mutation_t* mut = (state_mutation_t*)&spec->update;
      switch (mut->type) {
        case MUTATION_SET_ADD: {
          data_item_t* item = state_find_item(state, mut->set_path);
          if (item == NULL) return CRABS_ERR_TRACKER_NOT_FOUND;
          if (item->type != DATA_TYPE_ONE_SHOT_SET && item->type != DATA_TYPE_SET &&
              item->type != DATA_TYPE_2P_SET) return CRABS_ERR_INVALID_PARAM;

          one_shot_set_t* set = (one_shot_set_t*)item->value;
          if (set == NULL) return CRABS_ERR_TRACKER_NOT_FOUND;
          // Substitute {signer_id} if element_value is a template
          const char* elem = mut->element_value;
          if (strcmp(elem, "{signer_id}") == 0) elem = op->signer_id;
          return one_shot_set_add(set, elem);
        }

        case MUTATION_FLAG_SET: {
          data_item_t* item = state_find_item(state, mut->flag_path);
          if (item == NULL) return CRABS_ERR_FLAG_NOT_FOUND;
          if (item->type != DATA_TYPE_ONE_SHOT_FLAG) return CRABS_ERR_FLAG_NOT_FOUND;

          one_shot_flag_t* flag = (one_shot_flag_t*)item->value;
          if (flag == NULL) return CRABS_ERR_FLAG_NOT_FOUND;
          return one_shot_flag_set(flag, op->signer_id, op->lamport_time);
        }

        case MUTATION_COUNTER_INCREMENT: {
          data_item_t* item = state_find_item(state, mut->counter_path);
          if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
          if (item->value == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;

          if (item->type == DATA_TYPE_COUNTER || item->type == DATA_TYPE_PN_COUNTER ||
              item->type == DATA_TYPE_RESOURCE) {
            int64_t* val = (int64_t*)item->value;
            // Audit N-15: checked addition. mut->delta is signed and covered by
            // the operation signature (C-6 fix), but a large delta in a
            // registered dedup spec could overflow the counter — undefined
            // behavior. Reject on overflow instead of wrapping, matching
            // g_counter_increment's checked-add discipline.
            if (mut->delta > 0 && *val > INT64_MAX - mut->delta) {
              return CRABS_ERR_INVALID_PARAM;
            }
            if (mut->delta < 0 && *val < INT64_MIN - mut->delta) {
              return CRABS_ERR_INVALID_PARAM;
            }
            *val += mut->delta;
            return CRABS_SUCCESS;
          }
          return CRABS_ERR_TYPE_MISMATCH;
        }

        case MUTATION_ASSIGN: {
          data_item_t* item = state_find_item(state, mut->target_path);
          if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
          if (item->type != DATA_TYPE_REGISTER) return CRABS_ERR_TYPE_MISMATCH;

          // For registers, store the value as an int64
          if (item->value != NULL) {
            int64_t* old = (int64_t*)item->value;
            // Value is a string representation, parse it
            *old = atoll(mut->value);
          }
          return CRABS_SUCCESS;
        }

        case MUTATION_CUSTOM:
          // Application-defined callback - requires external mutation handler
          return CRABS_ERR_INTERNAL;

        default:
          return CRABS_ERR_INVALID_PARAM;
      }
    }

    default:
      return CRABS_ERR_INVALID_PARAM;
  }
}

crabs_error_e dedup_apply_mutation(state_t* state, const operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  return dedup_apply_mutation_spec(state, &op->dedup, op);
}

// ============================================================
// Desugaring: Build policy guard from DedupSpec (§4)
// ============================================================

char* dedup_build_policy_guard(const dedup_spec_t* dedup, const char* signer_id) {
  if (dedup == NULL) return NULL;
  if (dedup->type == DEDUP_NONE) return NULL;

  char* guard = NULL;

  switch (dedup->type) {
    case DEDUP_PER_USER: {
      // Guard: "tracker_path NOT CONTAINS signer_id"
      size_t len = strlen(dedup->tracker_path) + strlen(signer_id) + 20;
      guard = get_memory(len);
      snprintf(guard, len, "%s NOT CONTAINS %s", dedup->tracker_path, signer_id);
      break;
    }

    case DEDUP_GLOBAL: {
      // Guard: "flag_path == false"
      size_t len = strlen(dedup->flag_path) + 16;
      guard = get_memory(len);
      snprintf(guard, len, "%s == false", dedup->flag_path);
      break;
    }

    case DEDUP_CUSTOM: {
      // Guard: the condition expression itself
      size_t len = strlen(dedup->condition) + 1;
      guard = get_memory(len);
      strncpy(guard, dedup->condition, len - 1);
      guard[len - 1] = '\0';
      break;
    }

    default:
      break;
  }

  return guard;
}

// ============================================================
// Atomic check-and-apply (§5.4)
// ============================================================
// Eliminates the TOCTOU window between dedup_check_guard_spec (step 6) and
// dedup_apply_mutation_spec (step 8) by performing both in a single call.
// The guard is evaluated and, if it passes, the mutation is applied
// immediately — no other operation can interleave.

crabs_error_e dedup_check_and_apply_spec(state_t* state,
                                          const dedup_spec_t* spec,
                                          const operation_t* op) {
  if (state == NULL || op == NULL || spec == NULL) return CRABS_ERR_INVALID_PARAM;

  switch (spec->type) {
    case DEDUP_NONE:
      return CRABS_SUCCESS;

    case DEDUP_PER_USER: {
      data_item_t* tracker = state_find_item(state, spec->tracker_path);
      if (tracker == NULL) return CRABS_ERR_TRACKER_NOT_FOUND;
      if (tracker->type != DATA_TYPE_ONE_SHOT_SET) return CRABS_ERR_TRACKER_NOT_FOUND;

      one_shot_set_t* set = (one_shot_set_t*)tracker->value;
      if (set == NULL) return CRABS_ERR_TRACKER_NOT_FOUND;

      // Guard: reject if signer already in set
      if (one_shot_set_contains(set, op->signer_id)) {
        return CRABS_ERR_ALREADY_PERFORMED;
      }
      // Mutation: add signer to set
      return one_shot_set_add(set, op->signer_id);
    }

    case DEDUP_GLOBAL: {
      data_item_t* flag_item = state_find_item(state, spec->flag_path);
      if (flag_item == NULL) return CRABS_ERR_FLAG_NOT_FOUND;
      if (flag_item->type != DATA_TYPE_ONE_SHOT_FLAG) return CRABS_ERR_FLAG_NOT_FOUND;

      one_shot_flag_t* flag = (one_shot_flag_t*)flag_item->value;
      if (flag == NULL) return CRABS_ERR_FLAG_NOT_FOUND;

      // Guard: reject if flag already set
      if (one_shot_flag_value(flag)) {
        return CRABS_ERR_ALREADY_EXECUTED;
      }
      // Mutation: set the flag
      return one_shot_flag_set(flag, op->signer_id, op->lamport_time);
    }

    case DEDUP_CUSTOM: {
      // Guard: evaluate the condition
      if (spec->condition[0] == '\0') return CRABS_ERR_CONDITION_NOT_MET;
      condition_node_t* ast = condition_parse(spec->condition);
      if (ast == NULL) return CRABS_ERR_CONDITION_NOT_MET;
      bool passed = condition_evaluate(ast, state);
      condition_node_destroy(ast);
      if (!passed) return CRABS_ERR_CONDITION_NOT_MET;

      // Mutation: apply the state mutation
      const state_mutation_t* mut = &spec->update;
      switch (mut->type) {
        case MUTATION_SET_ADD: {
          data_item_t* item = state_find_item(state, mut->set_path);
          if (item == NULL) return CRABS_ERR_TRACKER_NOT_FOUND;
          if (item->type != DATA_TYPE_ONE_SHOT_SET && item->type != DATA_TYPE_SET &&
              item->type != DATA_TYPE_2P_SET) return CRABS_ERR_INVALID_PARAM;
          one_shot_set_t* set = (one_shot_set_t*)item->value;
          if (set == NULL) return CRABS_ERR_TRACKER_NOT_FOUND;
          const char* elem = mut->element_value;
          if (strcmp(elem, "{signer_id}") == 0) elem = op->signer_id;
          return one_shot_set_add(set, elem);
        }
        case MUTATION_FLAG_SET: {
          data_item_t* item = state_find_item(state, mut->flag_path);
          if (item == NULL) return CRABS_ERR_FLAG_NOT_FOUND;
          if (item->type != DATA_TYPE_ONE_SHOT_FLAG) return CRABS_ERR_FLAG_NOT_FOUND;
          one_shot_flag_t* flag = (one_shot_flag_t*)item->value;
          if (flag == NULL) return CRABS_ERR_FLAG_NOT_FOUND;
          return one_shot_flag_set(flag, op->signer_id, op->lamport_time);
        }
        case MUTATION_COUNTER_INCREMENT: {
          data_item_t* item = state_find_item(state, mut->counter_path);
          if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
          if (item->value == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
          if (item->type != DATA_TYPE_COUNTER && item->type != DATA_TYPE_PN_COUNTER &&
              item->type != DATA_TYPE_RESOURCE) return CRABS_ERR_INVALID_PARAM;
          int64_t* val = (int64_t*)item->value;
          int64_t delta = (int64_t)mut->delta;
          // Overflow guard
          if (delta > 0 && *val > INT64_MAX - delta) return CRABS_ERR_INVALID_PARAM;
          if (delta < 0 && *val < INT64_MIN - delta) return CRABS_ERR_INVALID_PARAM;
          *val += delta;
          return CRABS_SUCCESS;
        }
        case MUTATION_ASSIGN: {
          data_item_t* item = state_find_item(state, mut->target_path);
          if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
          if (item->type != DATA_TYPE_REGISTER) return CRABS_ERR_INVALID_PARAM;
          if (item->value != NULL) {
            int64_t* old = (int64_t*)item->value;
            *old = atoll(mut->value);
          }
          return CRABS_SUCCESS;
        }
        case MUTATION_CUSTOM:
          return CRABS_ERR_INTERNAL;
        default:
          return CRABS_ERR_INVALID_PARAM;
      }
    }

    default:
      return CRABS_ERR_INVALID_PARAM;
  }
}