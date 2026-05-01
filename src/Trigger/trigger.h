//
// Created by victor on 4/30/25.
//

#ifndef CRABS_TRIGGER_H
#define CRABS_TRIGGER_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "../Condition/condition.h"
#include "../Attribute/attribute_machine.h"

// ============================================================
// Trigger Effect Types (Amendment 1, §2.3)
// ============================================================
typedef enum {
  TRIGGER_EFFECT_ISSUE_ATTRIBUTE = 0x01,
  TRIGGER_EFFECT_CREATE_TRIGGER  = 0x02,
  TRIGGER_EFFECT_DELETE_TRIGGER  = 0x03,
  TRIGGER_EFFECT_DISABLE_TRIGGER = 0x04,
  TRIGGER_EFFECT_CHANGE_POLICY  = 0x05,
  TRIGGER_EFFECT_CUSTOM         = 0xFF
} trigger_effect_type_e;

// ============================================================
// Trigger Effect (Amendment 1, §2.3)
// ============================================================
typedef struct trigger_effect_t {
  trigger_effect_type_e type;

  // For ISSUE_ATTRIBUTE:
  char     issue_attribute[CRABS_MAX_POLICY_EXPR];
  char     target_role[CRABS_MAX_USER_ID];
  uint64_t duration_ms;
  char     attribute_value[CRABS_MAX_POLICY_EXPR];

  // For CHANGE_POLICY:
  char     policy_operation[CRABS_MAX_OP_NAME];
  char     policy_expression[CRABS_MAX_POLICY_EXPR];
} trigger_effect_t;

// ============================================================
// Trigger Definition (Amendment 1, §2.2)
// ============================================================
typedef struct trigger_t {
  char             trigger_id[CRABS_MAX_USER_ID];
  char             description[CRABS_MAX_POLICY_EXPR];
  char             condition[CRABS_MAX_POLICY_EXPR];
  condition_node_t* condition_ast;
  trigger_effect_t effect;
  uint64_t         cooldown_ms;
  uint64_t         last_triggered_at;
  bool             one_shot;
  bool             enabled;
  uint64_t         expires_at;
  uint64_t         created_at;
  char             created_by[CRABS_MAX_USER_ID];
} trigger_t;

// ============================================================
// Trigger Functions
// ============================================================
trigger_t*      trigger_create(const char* id, const char* description,
                               const char* condition, trigger_effect_t* effect,
                               uint64_t cooldown_ms, bool one_shot,
                               const char* created_by);
void            trigger_destroy(trigger_t* trigger);
trigger_effect_t* trigger_effect_create_issue_attribute(const char* attr, const char* role,
                                                          uint64_t duration, const char* value);

// Processing (Amendment 1, §5.2)
uint32_t       trigger_process_all(state_t* state, trigger_t* triggers, uint32_t trigger_count,
                                    attribute_machine_t* am, uint64_t now_ms);

#endif // CRABS_TRIGGER_H