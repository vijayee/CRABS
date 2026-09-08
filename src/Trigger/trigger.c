//
// Created by victor on 4/30/25.
//

#include "trigger.h"
#include "../Util/platform.h"
#include "../StateMachine/state_machine.h"
#include "../Util/allocator.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

// ============================================================
// Trigger Effect Creation
// ============================================================
trigger_effect_t* trigger_effect_create_issue_attribute(const char* attr, const char* role,
                                                          uint64_t duration, const char* value) {
  if (attr == NULL || role == NULL || value == NULL) return NULL;

  trigger_effect_t* effect = get_clear_memory(sizeof(trigger_effect_t));
  if (effect == NULL) return NULL;

  effect->type = TRIGGER_EFFECT_ISSUE_ATTRIBUTE;
  strncpy(effect->issue_attribute, attr, CRABS_MAX_POLICY_EXPR - 1);
  strncpy(effect->target_role, role, CRABS_MAX_USER_ID - 1);
  effect->duration_ms = duration;
  strncpy(effect->attribute_value, value, CRABS_MAX_POLICY_EXPR - 1);

  return effect;
}

// ============================================================
// Trigger Creation / Destruction
// ============================================================
trigger_t* trigger_create(const char* id, const char* description,
                           const char* condition, trigger_effect_t* effect,
                           uint64_t cooldown_ms, bool one_shot,
                           const char* created_by) {
  if (id == NULL || condition == NULL) return NULL;

  trigger_t* trigger = get_clear_memory(sizeof(trigger_t));
  if (trigger == NULL) return NULL;

  strncpy(trigger->trigger_id, id, CRABS_MAX_USER_ID - 1);
  if (description != NULL) {
    strncpy(trigger->description, description, CRABS_MAX_POLICY_EXPR - 1);
  }
  strncpy(trigger->condition, condition, CRABS_MAX_POLICY_EXPR - 1);

  // Parse condition string into AST
  trigger->condition_ast = condition_parse(condition);

  if (effect != NULL) {
    trigger->effect = *effect;
  }

  trigger->cooldown_ms = cooldown_ms;
  trigger->one_shot = one_shot;
  trigger->enabled = true;
  trigger->expires_at = 0;  // 0 = never expires
  trigger->created_at = 0;
  if (created_by != NULL) {
    strncpy(trigger->created_by, created_by, CRABS_MAX_USER_ID - 1);
  }

  return trigger;
}

void trigger_destroy(trigger_t* trigger) {
  if (trigger == NULL) return;

  if (trigger->condition_ast != NULL) {
    condition_node_destroy(trigger->condition_ast);
  }

  free(trigger);
}

// ============================================================
// Execute Trigger Effect (Amendment 1, §5.3)
// ============================================================
static crabs_error_e _execute_trigger_effect(state_t* state, trigger_t* trigger,
                                              attribute_machine_t* am, uint64_t now_ms) {
  if (state == NULL || trigger == NULL) return CRABS_ERR_INVALID_PARAM;

  switch (trigger->effect.type) {
    case TRIGGER_EFFECT_ISSUE_ATTRIBUTE: {
      if (am == NULL) {
        // Without an attribute machine, we can't issue temp attributes
        // This is expected when called from the state machine without an AM
        return CRABS_SUCCESS;
      }
      crabs_error_e err = attribute_machine_issue_temporary(
        am,
        trigger->effect.issue_attribute,
        trigger->effect.attribute_value,
        trigger->effect.target_role,
        trigger->effect.duration_ms
      );
      if (err != CRABS_SUCCESS) return err;
      // This notification fires synchronously inside the trigger loop —
      // hooks must not assume trigger storage is stable across this call
      // (the loop re-finds triggers by id after each effect).
      state_notify_change(state, CRABS_CHANGE_TRIGGER, "issue_temporary", NULL,
                          NULL,
                          state->hlc_state_initialized
                              ? state->hlc_state.last.node_id
                              : state->config.bootstrap_admin,
                          trigger->effect.issue_attribute,
                          "trigger issued temporary attribute", CRABS_SUCCESS);
      break;
    }

    case TRIGGER_EFFECT_CHANGE_POLICY: {
      // Audit H-E: a trigger firing CHANGE_POLICY can rewrite the
      // authorization policy for any op — including weakening
      // __force_unlock__ or __change_config__ to an empty policy that any
      // signature satisfies, which would let a holder of any attribute
      // reconfigure the machine. Two guards:
      //   (1) Never allow an empty policy_expression via a trigger — it
      //       removes attribute gating. Use a signed __change_config__-class
      //       op to set an empty policy if that is ever intended.
      //   (2) Never allow a trigger to change the policy of a BUILTIN op
      //       type. Triggers may only set policies for application-defined
      //       (non-builtin) op types; builtin policies must be changed by a
      //       direct signed operation, not a side effect of condition
      //       evaluation.
      if (trigger->effect.policy_operation[0] == '\0') break;
      if (trigger->effect.policy_expression[0] == '\0') {
        return CRABS_ERR_INVALID_PARAM;
      }
      if (operation_is_builtin(trigger->effect.policy_operation)) {
        return CRABS_ERR_UNAUTHORIZED;
      }
      // Audit fix (High): defense in depth for triggers that bypass
      // state_machine_op_create_trigger (direct trigger_create callers have
      // no creation-time validation). A CONTAINS-only expression preprocesses
      // to an empty ABE policy — applying it would leave the target op gated
      // by signature alone. Skip the effect instead of applying it.
      policy_preprocess_result_t pp =
        preprocess_policy(trigger->effect.policy_expression, state, trigger->created_by);
      if (pp.abe_policy[0] == '\0') {
        return CRABS_ERR_INVALID_PARAM;
      }
      crabs_error_e err = state_add_policy(state,
        trigger->effect.policy_operation,
        trigger->effect.policy_expression);
      if (err != CRABS_SUCCESS) return err;
      break;
    }

    case TRIGGER_EFFECT_CREATE_TRIGGER:
    case TRIGGER_EFFECT_DELETE_TRIGGER:
    case TRIGGER_EFFECT_DISABLE_TRIGGER:
      // These trigger effects modify the trigger list itself.
      // For safety, we log but don't recursively modify triggers during processing.
      // These would be handled by dedicated operations.
      break;

    case TRIGGER_EFFECT_CUSTOM:
    default:
      // Custom effects are not implemented in the base spec
      break;
  }

  return CRABS_SUCCESS;
}

// ============================================================
// PROCESS_TRIGGERS (Amendment 1, §5.2)
// ============================================================
uint32_t trigger_process_all(state_t* state, trigger_t* triggers, uint32_t trigger_count,
                              attribute_machine_t* am, uint64_t now_ms) {
  if (state == NULL || triggers == NULL) return 0;

  // Audit 9 A-6: defer nested processing. A change hook fired inside the
  // loop below can execute ops that run the state machine again; a nested
  // trigger_process_all would re-fire the same trigger before the outer loop
  // has written last_triggered_at (double-fire) and recurse unboundedly.
  if (state->trigger_ticking) return 0;
  state->trigger_ticking = true;

  uint32_t fired_count = 0;

  // Step 1: Prune expired temporary attributes
  if (am != NULL) {
    attribute_machine_prune_expired_temporary(am);
  }

  // Audit 9 A-2: when the caller passes the state-owned array (the
  // production shape — state_machine.c passes state->triggers), the loop
  // must NOT hold a captured triggers pointer across effect execution: an
  // effect's change hook can create/delete triggers, and
  // state_machine_op_create_trigger reallocs state->triggers, moving (and
  // freeing) the array. Re-read state->triggers and state->trigger_count at
  // the top of every iteration. Callers that pass a foreign (non-state)
  // array keep iterating it directly — such arrays are not mutated by op
  // handlers. The triggers/trigger_count parameters are therefore used for
  // initial validation only in the state-owned case.
  bool state_owned_array = (triggers == state->triggers);

  // Step 2: Process each trigger
  for (uint32_t i = 0; ; i++) {
    trigger_t* current_triggers = state_owned_array ? state->triggers : triggers;
    uint32_t current_count = state_owned_array ? state->trigger_count : trigger_count;
    if (current_triggers == NULL || i >= current_count) break;

    trigger_t* trigger = &current_triggers[i];

    // Skip if disabled
    if (!trigger->enabled) continue;

    // Skip if in cooldown. Guard against clock regression: if now_ms <
    // last_triggered_at (NTP step), the unsigned subtraction would wrap to a
    // huge value and bypass the cooldown.
    if (trigger->cooldown_ms > 0 && trigger->last_triggered_at > 0) {
      if (now_ms < trigger->last_triggered_at) continue; // clock stepped back
      if (now_ms - trigger->last_triggered_at < trigger->cooldown_ms) continue;
    }

    // Skip if expired
    if (trigger->expires_at != 0 && now_ms >= trigger->expires_at) continue;

    // Skip if one-shot and already fired
    if (trigger->one_shot && trigger->last_triggered_at > 0) continue;

    // Evaluate condition
    if (trigger->condition_ast == NULL) {
      continue;
    }

    bool condition_result = condition_evaluate(trigger->condition_ast, state);
    if (!condition_result) continue;

    // Snapshot the id BEFORE executing the effect: the effect's change hook
    // may realloc (or shrink) the state-owned array, invalidating `trigger`.
    char trigger_id_snapshot[CRABS_MAX_USER_ID];
    strncpy(trigger_id_snapshot, trigger->trigger_id, CRABS_MAX_USER_ID - 1);
    trigger_id_snapshot[CRABS_MAX_USER_ID - 1] = '\0';

    // Condition is true: execute the effect
    crabs_error_e err = _execute_trigger_effect(state, trigger, am, now_ms);
    if (err != CRABS_SUCCESS) continue;

    // Audit 9 A-2: the effect may have moved or freed the array the loop is
    // iterating (hooks run synchronously inside it), so re-find the fired
    // trigger by id in the fresh state->triggers before writing its
    // bookkeeping. If it was deleted mid-effect, skip the write.
    if (state_owned_array) {
      int32_t found_index = -1;
      for (uint32_t scan_index = 0; scan_index < state->trigger_count; scan_index++) {
        if (state->triggers != NULL &&
            strcmp(state->triggers[scan_index].trigger_id, trigger_id_snapshot) == 0) {
          found_index = (int32_t)scan_index;
          break;
        }
      }
      if (found_index < 0) continue;
      trigger = &state->triggers[found_index];
    }

    // Update trigger state
    trigger->last_triggered_at = now_ms;

    // If one-shot, disable after firing
    if (trigger->one_shot) {
      trigger->enabled = false;
    }

    fired_count++;
  }

  state->trigger_ticking = false;
  return fired_count;
}

// ============================================================
// Built-in Trigger Operations (Amendment 1, §4)
// ============================================================

// Helper to find a trigger by ID in the state's trigger array
static int32_t _find_trigger_index(state_t* state, const char* trigger_id) {
  if (state == NULL || trigger_id == NULL) return -1;
  for (uint32_t i = 0; i < state->trigger_count; i++) {
    if (strcmp(state->triggers[i].trigger_id, trigger_id) == 0) {
      return (int32_t)i;
    }
  }
  return -1;
}

crabs_error_e state_machine_op_create_trigger(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (op->payload == NULL || op->payload_size == 0) return CRABS_ERR_INVALID_PARAM;

  // Payload format (simple key=value pairs separated by semicolons):
  // trigger_id=<id>;condition=<expr>;effect_type=<num>;description=<desc>;
  // cooldown_ms=<num>;one_shot=<0|1>;expires_at=<num>;
  // For ISSUE_ATTRIBUTE: issue_attribute=<attr>;target_role=<role>;
  //   duration_ms=<num>;attribute_value=<val>;
  // For CHANGE_POLICY: policy_operation=<op>;policy_expression=<expr>;

  char* payload = (char*)op->payload;

  // Parse fields from payload
  char trigger_id[CRABS_MAX_USER_ID] = {0};
  char condition_expr[CRABS_MAX_POLICY_EXPR] = {0};
  char description[CRABS_MAX_POLICY_EXPR] = {0};
  trigger_effect_type_e effect_type = TRIGGER_EFFECT_ISSUE_ATTRIBUTE;
  uint64_t cooldown_ms = 0;
  bool one_shot = false;
  uint64_t expires_at = 0;

  // Effect fields
  char issue_attribute[CRABS_MAX_POLICY_EXPR] = {0};
  char target_role[CRABS_MAX_USER_ID] = {0};
  uint64_t duration_ms = 0;
  char attribute_value[CRABS_MAX_POLICY_EXPR] = {0};
  char policy_operation[CRABS_MAX_OP_NAME] = {0};
  char policy_expression[CRABS_MAX_POLICY_EXPR] = {0};

  // Reject oversized payloads — truncation could change the meaning of
  // security-critical fields like policy_expression or condition.
  if (op->payload_size >= 4096) {
    return CRABS_ERR_INVALID_PARAM;
  }
  char buf[4096];
  memcpy(buf, op->payload, op->payload_size);
  buf[op->payload_size] = '\0';

  char* saveptr = NULL;
  char* token = platform_strtok_r(buf, ";", &saveptr);
  while (token != NULL) {
    // Trim leading whitespace
    while (*token == ' ') token++;

    char* eq = strchr(token, '=');
    if (eq == NULL) {
      token = platform_strtok_r(NULL, ";", &saveptr);
      continue;
    }

    *eq = '\0';
    char* key = token;
    char* value = eq + 1;

    if (strcmp(key, "trigger_id") == 0) {
      strncpy(trigger_id, value, CRABS_MAX_USER_ID - 1);
    } else if (strcmp(key, "condition") == 0) {
      strncpy(condition_expr, value, CRABS_MAX_POLICY_EXPR - 1);
    } else if (strcmp(key, "description") == 0) {
      strncpy(description, value, CRABS_MAX_POLICY_EXPR - 1);
    } else if (strcmp(key, "effect_type") == 0) {
      errno = 0;
      long ev = strtol(value, NULL, 10);
      if (errno == 0 && ev >= 0 && ev <= 0xFF) {
        effect_type = (trigger_effect_type_e)ev;
      }
    } else if (strcmp(key, "cooldown_ms") == 0) {
      errno = 0;
      cooldown_ms = strtoull(value, NULL, 10);
      if (errno != 0) cooldown_ms = 0;
    } else if (strcmp(key, "one_shot") == 0) {
      one_shot = (strcmp(value, "1") == 0 || strcmp(value, "true") == 0);
    } else if (strcmp(key, "expires_at") == 0) {
      errno = 0;
      expires_at = strtoull(value, NULL, 10);
      if (errno != 0) expires_at = 0;
    } else if (strcmp(key, "issue_attribute") == 0) {
      strncpy(issue_attribute, value, CRABS_MAX_POLICY_EXPR - 1);
    } else if (strcmp(key, "target_role") == 0) {
      strncpy(target_role, value, CRABS_MAX_USER_ID - 1);
    } else if (strcmp(key, "duration_ms") == 0) {
      errno = 0;
      duration_ms = strtoull(value, NULL, 10);
      if (errno != 0) duration_ms = 0;
    } else if (strcmp(key, "attribute_value") == 0) {
      strncpy(attribute_value, value, CRABS_MAX_POLICY_EXPR - 1);
    } else if (strcmp(key, "policy_operation") == 0) {
      strncpy(policy_operation, value, CRABS_MAX_OP_NAME - 1);
    } else if (strcmp(key, "policy_expression") == 0) {
      strncpy(policy_expression, value, CRABS_MAX_POLICY_EXPR - 1);
    }

    token = platform_strtok_r(NULL, ";", &saveptr);
  }

  if (trigger_id[0] == '\0' || condition_expr[0] == '\0') {
    return CRABS_ERR_INVALID_PARAM;
  }

  // Check for duplicate trigger_id
  if (_find_trigger_index(state, trigger_id) >= 0) {
    return CRABS_ERR_DUPLICATE_OPERATION;
  }

  // Audit fix (High): a CHANGE_POLICY effect whose policy_expression is
  // CONTAINS-only (e.g. "a NOT IN b") preprocesses to an EMPTY abe_policy
  // with resolved_ok = true — preprocess_policy strips every CONTAINS node
  // before handing the remainder to the ABE evaluator. An empty ABE policy
  // authorizes the target operation by signature alone, so the trigger would
  // silently strip all attribute gating from policy_operation when it fires.
  // The empty policy_expression case below (audit H-E) is the degenerate
  // form of the same problem; here we also reject any expression that
  // preprocesses to an empty ABE policy. Validation happens at creation —
  // the only state-aware site (trigger_create has no state_t) — using the
  // same preprocessing the authorization path applies.
  if (effect_type == TRIGGER_EFFECT_CHANGE_POLICY && policy_expression[0] != '\0') {
    policy_preprocess_result_t pp = preprocess_policy(policy_expression, state, op->signer_id);
    if (pp.abe_policy[0] == '\0') {
      return CRABS_ERR_INVALID_PARAM;
    }
  }

  // Build the effect struct
  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = effect_type;
  strncpy(effect.issue_attribute, issue_attribute, CRABS_MAX_POLICY_EXPR - 1);
  strncpy(effect.target_role, target_role, CRABS_MAX_USER_ID - 1);
  effect.duration_ms = duration_ms;
  strncpy(effect.attribute_value, attribute_value, CRABS_MAX_POLICY_EXPR - 1);
  strncpy(effect.policy_operation, policy_operation, CRABS_MAX_OP_NAME - 1);
  strncpy(effect.policy_expression, policy_expression, CRABS_MAX_POLICY_EXPR - 1);

  // Create the trigger
  trigger_t* new_trigger = trigger_create(trigger_id, description, condition_expr,
                                           &effect, cooldown_ms, one_shot, op->signer_id);
  if (new_trigger == NULL) return CRABS_ERR_OOM;

  // Audit fix (High): an unparseable condition would be stored with a NULL
  // AST and silently never fire (trigger_process_all skips NULL ASTs). That
  // is fail-closed for the effect but hides the authoring error from the
  // operator, so reject the operation instead.
  if (new_trigger->condition_ast == NULL) {
    trigger_destroy(new_trigger);
    return CRABS_ERR_INVALID_PARAM;
  }

  // Set parsed AST and other fields
  new_trigger->expires_at = expires_at;
  new_trigger->created_at = (uint64_t)time(NULL) * 1000;

  // Add trigger to state's trigger array
  uint32_t idx = state->trigger_count;
  state->trigger_count++;
  trigger_t* new_triggers = realloc(state->triggers,
    state->trigger_count * sizeof(trigger_t));
  if (new_triggers == NULL) {
    trigger_destroy(new_trigger);
    state->trigger_count--;
    return CRABS_ERR_OOM;
  }
  state->triggers = new_triggers;
  // Audit R5-4: struct copy transfers ownership of condition_ast (and all
  // other pointer fields) to the array entry. We use free() — NOT
  // trigger_destroy() — because trigger_destroy would free condition_ast,
  // leaving the array entry with a dangling pointer. The heap allocation
  // itself (the trigger_t struct) is freed, but its heap-allocated members
  // (condition_ast) remain valid via the copy. If trigger_destroy is ever
  // changed to be used here, the condition_ast must be deep-copied for the
  // array entry first.
  state->triggers[idx] = *new_trigger;
  free(new_trigger);

  return CRABS_SUCCESS;
}

crabs_error_e state_machine_op_delete_trigger(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (op->payload == NULL || op->payload_size == 0) return CRABS_ERR_INVALID_PARAM;

  // Payload: trigger_id=<id>
  char trigger_id[CRABS_MAX_USER_ID] = {0};
  char buf[512];
  { size_t _c = op->payload_size < sizeof(buf) - 1 ? op->payload_size : (uint32_t)(sizeof(buf) - 1);
    memcpy(buf, op->payload, _c);
    buf[_c] = '\0'; }

  char* eq = strchr(buf, '=');
  if (eq == NULL) return CRABS_ERR_INVALID_PARAM;
  *eq = '\0';
  if (strcmp(buf, "trigger_id") != 0) return CRABS_ERR_INVALID_PARAM;
  strncpy(trigger_id, eq + 1, CRABS_MAX_USER_ID - 1);

  int32_t idx = _find_trigger_index(state, trigger_id);
  if (idx < 0) return CRABS_ERR_RESOURCE_NOT_FOUND;

  // Destroy the condition AST of the trigger being removed
  if (state->triggers[idx].condition_ast != NULL) {
    condition_node_destroy(state->triggers[idx].condition_ast);
    state->triggers[idx].condition_ast = NULL;
  }

  // Shift remaining triggers down
  for (uint32_t i = (uint32_t)idx; i < state->trigger_count - 1; i++) {
    state->triggers[i] = state->triggers[i + 1];
  }
  state->trigger_count--;

  return CRABS_SUCCESS;
}

crabs_error_e state_machine_op_disable_trigger(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (op->payload == NULL || op->payload_size == 0) return CRABS_ERR_INVALID_PARAM;

  // Payload: trigger_id=<id>
  char trigger_id[CRABS_MAX_USER_ID] = {0};
  char buf[512];
  { size_t _c = op->payload_size < sizeof(buf) - 1 ? op->payload_size : (uint32_t)(sizeof(buf) - 1);
    memcpy(buf, op->payload, _c);
    buf[_c] = '\0'; }

  char* eq = strchr(buf, '=');
  if (eq == NULL) return CRABS_ERR_INVALID_PARAM;
  *eq = '\0';
  if (strcmp(buf, "trigger_id") != 0) return CRABS_ERR_INVALID_PARAM;
  strncpy(trigger_id, eq + 1, CRABS_MAX_USER_ID - 1);

  int32_t idx = _find_trigger_index(state, trigger_id);
  if (idx < 0) return CRABS_ERR_RESOURCE_NOT_FOUND;

  state->triggers[idx].enabled = false;
  return CRABS_SUCCESS;
}

crabs_error_e state_machine_op_enable_trigger(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;
  if (op->payload == NULL || op->payload_size == 0) return CRABS_ERR_INVALID_PARAM;

  // Payload: trigger_id=<id>
  char trigger_id[CRABS_MAX_USER_ID] = {0};
  char buf[512];
  { size_t _c = op->payload_size < sizeof(buf) - 1 ? op->payload_size : (uint32_t)(sizeof(buf) - 1);
    memcpy(buf, op->payload, _c);
    buf[_c] = '\0'; }

  char* eq = strchr(buf, '=');
  if (eq == NULL) return CRABS_ERR_INVALID_PARAM;
  *eq = '\0';
  if (strcmp(buf, "trigger_id") != 0) return CRABS_ERR_INVALID_PARAM;
  strncpy(trigger_id, eq + 1, CRABS_MAX_USER_ID - 1);

  int32_t idx = _find_trigger_index(state, trigger_id);
  if (idx < 0) return CRABS_ERR_RESOURCE_NOT_FOUND;

  state->triggers[idx].enabled = true;
  return CRABS_SUCCESS;
}
