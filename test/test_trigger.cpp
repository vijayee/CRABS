#include <gtest/gtest.h>
extern "C" {
#include "../src/Trigger/trigger.h"
#include "../src/CRABS/crabs.h"
#include "../src/CRABS/data_model.h"
#include "../src/Condition/condition.h"
#include "../src/CRDT/crdt_merge.h"
#include "../src/StateMachine/state_machine.h"
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/crypto.h"
}
#include "test_helpers.h"

// ============================================================
// Test Fixture
// ============================================================
class TestTrigger : public ::testing::Test {
protected:
  state_t* state;

  void SetUp() override {
    state = state_create();
  }

  void TearDown() override {
    // Free CRDT struct values manually since data_item_destroy uses free()
    for (data_item_t* item = state->items; item != NULL; item = item->next) {
      if (item->value != NULL) {
        crdt_value_destroy(item->crdt_type, item->value);
        item->value = NULL;
      }
    }
    state_destroy(state);
  }
};

// ============================================================
// Trigger Creation / Destruction Tests
// ============================================================

TEST_F(TestTrigger, TestCreateDestroy) {
  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_ISSUE_ATTRIBUTE;
  strncpy(effect.issue_attribute, "role", CRABS_MAX_POLICY_EXPR - 1);
  strncpy(effect.target_role, "moderator", CRABS_MAX_USER_ID - 1);
  effect.duration_ms = 5000;
  strncpy(effect.attribute_value, "elevated", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("test_trigger", "Test description",
    "views >= 100", &effect, 1000, false, "admin");
  ASSERT_NE(trigger, nullptr);
  EXPECT_STREQ(trigger->trigger_id, "test_trigger");
  EXPECT_STREQ(trigger->description, "Test description");
  EXPECT_STREQ(trigger->condition, "views >= 100");
  EXPECT_NE(trigger->condition_ast, nullptr);
  EXPECT_EQ(trigger->effect.type, TRIGGER_EFFECT_ISSUE_ATTRIBUTE);
  EXPECT_STREQ(trigger->effect.issue_attribute, "role");
  EXPECT_EQ(trigger->cooldown_ms, 1000u);
  EXPECT_EQ(trigger->one_shot, false);
  EXPECT_EQ(trigger->enabled, true);
  EXPECT_EQ(trigger->expires_at, 0u);
  EXPECT_STREQ(trigger->created_by, "admin");

  trigger_destroy(trigger);
}

TEST_F(TestTrigger, TestCreateNullId) {
  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  trigger_t* trigger = trigger_create(NULL, "desc", "x > 0", &effect, 0, false, NULL);
  EXPECT_EQ(trigger, nullptr);
}

TEST_F(TestTrigger, TestCreateNullCondition) {
  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  trigger_t* trigger = trigger_create("id", "desc", NULL, &effect, 0, false, NULL);
  EXPECT_EQ(trigger, nullptr);
}

TEST_F(TestTrigger, TestCreateNullEffect) {
  trigger_t* trigger = trigger_create("id", "desc", "x >= 0", NULL, 0, false, "admin");
  ASSERT_NE(trigger, nullptr);
  // NULL effect means the effect struct is zero-initialized
  EXPECT_EQ(trigger->effect.type, (trigger_effect_type_e)0);
  trigger_destroy(trigger);
}

TEST_F(TestTrigger, TestDestroyNull) {
  trigger_destroy(nullptr);
  // Should not crash
}

// ============================================================
// Trigger Effect Creation Tests
// ============================================================

TEST_F(TestTrigger, TestEffectCreateIssueAttribute) {
  trigger_effect_t* effect = trigger_effect_create_issue_attribute("role", "moderator", 5000, "elevated");
  ASSERT_NE(effect, nullptr);
  EXPECT_EQ(effect->type, TRIGGER_EFFECT_ISSUE_ATTRIBUTE);
  EXPECT_STREQ(effect->issue_attribute, "role");
  EXPECT_STREQ(effect->target_role, "moderator");
  EXPECT_EQ(effect->duration_ms, 5000u);
  EXPECT_STREQ(effect->attribute_value, "elevated");
  free(effect);
}

TEST_F(TestTrigger, TestEffectCreateNullParams) {
  trigger_effect_t* effect = trigger_effect_create_issue_attribute(NULL, "moderator", 5000, "elevated");
  EXPECT_EQ(effect, nullptr);

  effect = trigger_effect_create_issue_attribute("role", NULL, 5000, "elevated");
  EXPECT_EQ(effect, nullptr);

  effect = trigger_effect_create_issue_attribute("role", "moderator", 5000, NULL);
  EXPECT_EQ(effect, nullptr);
}

// ============================================================
// Trigger Processing Tests
// ============================================================

TEST_F(TestTrigger, TestProcessTriggersConditionTrue) {
  // Add a counter item "views" with value 100
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(state, views);

  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_CHANGE_POLICY;
  strncpy(effect.policy_operation, "__read__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect.policy_expression, "role >= moderator", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("high_views", "Fires when views >= 50",
    "views >= 50", &effect, 0, false, "admin");
  ASSERT_NE(trigger, nullptr);
  ASSERT_NE(trigger->condition_ast, nullptr);

  // Add trigger to state
  state->trigger_count = 1;
  state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
  state->triggers[0] = *trigger;
  free(trigger);

  // Process triggers
  uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
  EXPECT_EQ(fired, 1u);

  // Verify the policy was added (CHANGE_POLICY effect)
  const char* policy = state_find_policy(state, "__read__");
  EXPECT_NE(policy, nullptr);
  EXPECT_STREQ(policy, "role >= moderator");

  // Verify last_triggered_at was updated
  EXPECT_EQ(state->triggers[0].last_triggered_at, 1000u);
}

// Regression for audit H-E: a trigger firing CHANGE_POLICY must NOT weaken
// authorization. (1) An empty policy_expression is rejected — it would
// remove attribute gating for the target op. (2) A change targeting a
// BUILTIN op (here __force_unlock__) is rejected — builtin policies must
// be changed by a direct signed operation, not a trigger side effect, so a
// holder of __create_trigger__ authority cannot escalate by weakening the
// force-unlock or change-config policy.
TEST_F(TestTrigger, TestChangePolicyRejectsEmptyAndBuiltinTargets) {
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(state, views);

  // Case 1: empty policy_expression → rejected, trigger does not fire.
  {
    trigger_effect_t effect;
    memset(&effect, 0, sizeof(effect));
    effect.type = TRIGGER_EFFECT_CHANGE_POLICY;
    strncpy(effect.policy_operation, "__read__", CRABS_MAX_OP_NAME - 1);
    effect.policy_expression[0] = '\0'; // empty — would remove attribute gating
    trigger_t* trigger = trigger_create("empty_policy", "Fires when views >= 50",
      "views >= 50", &effect, 0, false, "admin");
    ASSERT_NE(trigger, nullptr);
    state->trigger_count = 1;
    state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
    state->triggers[0] = *trigger;
    free(trigger);
    uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
    EXPECT_EQ(fired, 0u); // did not fire (effect rejected)
    // Clean up this trigger's AST before reusing the slot in case 2.
    condition_node_destroy(state->triggers[0].condition_ast);
    state->triggers[0].condition_ast = NULL;
    state->trigger_count = 0;
    free(state->triggers);
    state->triggers = NULL;
  }

  // Case 2: builtin target (__force_unlock__) → rejected.
  {
    trigger_effect_t effect;
    memset(&effect, 0, sizeof(effect));
    effect.type = TRIGGER_EFFECT_CHANGE_POLICY;
    strncpy(effect.policy_operation, "__force_unlock__", CRABS_MAX_OP_NAME - 1);
    strncpy(effect.policy_expression, "role:member", CRABS_MAX_POLICY_EXPR - 1);
    trigger_t* trigger = trigger_create("weaken_force_unlock", "Fires when views >= 50",
      "views >= 50", &effect, 0, false, "admin");
    ASSERT_NE(trigger, nullptr);
    state->trigger_count = 1;
    state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
    state->triggers[0] = *trigger;
    free(trigger);
    uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
    EXPECT_EQ(fired, 0u); // rejected — builtin policy not changed
    // The force-unlock policy is NOT added.
    EXPECT_EQ(state_find_policy(state, "__force_unlock__"), nullptr);
    // TearDown's state_destroy will free the remaining trigger's AST.
  }
}

TEST_F(TestTrigger, TestProcessTriggersConditionFalse) {
  // Add a counter item "views" with value 10
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 10);
  views->value = gc;
  state_add_item(state, views);

  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_CHANGE_POLICY;
  strncpy(effect.policy_operation, "__read__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect.policy_expression, "role >= moderator", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("high_views", "Fires when views >= 50",
    "views >= 50", &effect, 0, false, "admin");
  ASSERT_NE(trigger, nullptr);

  state->trigger_count = 1;
  state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
  state->triggers[0] = *trigger;
  free(trigger);

  uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
  EXPECT_EQ(fired, 0u);
  EXPECT_EQ(state->triggers[0].last_triggered_at, 0u);

  // Verify the policy was NOT added
  const char* policy = state_find_policy(state, "__read__");
  EXPECT_EQ(policy, nullptr);
}

TEST_F(TestTrigger, TestProcessTriggersCooldown) {
  // Add a counter item "views" with value 100
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(state, views);

  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_CHANGE_POLICY;
  strncpy(effect.policy_operation, "__read__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect.policy_expression, "role >= moderator", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("cooldown_trigger", "Fires with cooldown",
    "views >= 50", &effect, 5000, false, "admin");
  ASSERT_NE(trigger, nullptr);

  state->trigger_count = 1;
  state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
  state->triggers[0] = *trigger;
  free(trigger);

  // First fire at t=1000
  uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
  EXPECT_EQ(fired, 1u);
  EXPECT_EQ(state->triggers[0].last_triggered_at, 1000u);

  // Second fire at t=3000 (within 5000ms cooldown)
  fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 3000);
  EXPECT_EQ(fired, 0u);

  // Third fire at t=7000 (cooldown has passed: 7000-1000=6000 > 5000)
  fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 7000);
  EXPECT_EQ(fired, 1u);
  EXPECT_EQ(state->triggers[0].last_triggered_at, 7000u);
}

TEST_F(TestTrigger, TestProcessTriggersOneShot) {
  // Add a counter item "views" with value 100
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(state, views);

  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_CHANGE_POLICY;
  strncpy(effect.policy_operation, "__oneshot__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect.policy_expression, "oneshot", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("oneshot_trigger", "One-shot trigger",
    "views >= 50", &effect, 0, true, "admin");
  ASSERT_NE(trigger, nullptr);
  EXPECT_EQ(trigger->one_shot, true);

  state->trigger_count = 1;
  state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
  state->triggers[0] = *trigger;
  free(trigger);

  // First fire
  uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
  EXPECT_EQ(fired, 1u);
  EXPECT_EQ(state->triggers[0].enabled, false);  // One-shot disables itself

  // Second fire attempt should be skipped (disabled)
  fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 2000);
  EXPECT_EQ(fired, 0u);
}

TEST_F(TestTrigger, TestProcessTriggersDisabled) {
  // Add a counter item "views" with value 100
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(state, views);

  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_CHANGE_POLICY;
  strncpy(effect.policy_operation, "__disabled__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect.policy_expression, "disabled", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("disabled_trigger", "Disabled trigger",
    "views >= 50", &effect, 0, false, "admin");
  ASSERT_NE(trigger, nullptr);

  state->trigger_count = 1;
  state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
  state->triggers[0] = *trigger;
  free(trigger);

  // Disable the trigger
  state->triggers[0].enabled = false;

  uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
  EXPECT_EQ(fired, 0u);
}

TEST_F(TestTrigger, TestProcessTriggersExpired) {
  // Add a counter item "views" with value 100
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(state, views);

  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_CHANGE_POLICY;
  strncpy(effect.policy_operation, "__expired__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect.policy_expression, "expired", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("expired_trigger", "Expired trigger",
    "views >= 50", &effect, 0, false, "admin");
  ASSERT_NE(trigger, nullptr);

  state->trigger_count = 1;
  state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
  state->triggers[0] = *trigger;
  free(trigger);

  // Set expiry to 500ms ago (expires_at=500, now=1000)
  state->triggers[0].expires_at = 500;

  uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
  EXPECT_EQ(fired, 0u);
}

TEST_F(TestTrigger, TestProcessTriggersNotExpired) {
  // Add a counter item "views" with value 100
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(state, views);

  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_CHANGE_POLICY;
  strncpy(effect.policy_operation, "__notexpired__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect.policy_expression, "notexpired", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("notexpired_trigger", "Not expired trigger",
    "views >= 50", &effect, 0, false, "admin");
  ASSERT_NE(trigger, nullptr);

  state->trigger_count = 1;
  state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
  state->triggers[0] = *trigger;
  free(trigger);

  // Set expiry far in the future (expires_at=10000, now=1000)
  state->triggers[0].expires_at = 10000;

  uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
  EXPECT_EQ(fired, 1u);
}

TEST_F(TestTrigger, TestProcessTriggersNullState) {
  trigger_t trigger;
  memset(&trigger, 0, sizeof(trigger));
  uint32_t fired = trigger_process_all(NULL, &trigger, 1, NULL, 0);
  EXPECT_EQ(fired, 0u);
}

TEST_F(TestTrigger, TestProcessTriggersNullTriggers) {
  uint32_t fired = trigger_process_all(state, NULL, 0, NULL, 0);
  EXPECT_EQ(fired, 0u);
}

TEST_F(TestTrigger, TestProcessTriggersMultipleTriggers) {
  // Add a counter item "views" with value 100
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(state, views);

  trigger_effect_t effect1;
  memset(&effect1, 0, sizeof(effect1));
  effect1.type = TRIGGER_EFFECT_CHANGE_POLICY;
  strncpy(effect1.policy_operation, "__op1__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect1.policy_expression, "policy1", CRABS_MAX_POLICY_EXPR - 1);

  trigger_effect_t effect2;
  memset(&effect2, 0, sizeof(effect2));
  effect2.type = TRIGGER_EFFECT_CHANGE_POLICY;
  strncpy(effect2.policy_operation, "__op2__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect2.policy_expression, "policy2", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger1 = trigger_create("trigger1", "Views >= 50",
    "views >= 50", &effect1, 0, false, "admin");
  trigger_t* trigger2 = trigger_create("trigger2", "Views >= 200",
    "views >= 200", &effect2, 0, false, "admin");
  ASSERT_NE(trigger1, nullptr);
  ASSERT_NE(trigger2, nullptr);

  state->trigger_count = 2;
  state->triggers = (trigger_t*)realloc(state->triggers, 2 * sizeof(trigger_t));
  state->triggers[0] = *trigger1;
  state->triggers[1] = *trigger2;
  free(trigger1);
  free(trigger2);

  // Only trigger1 should fire (views=100 >= 50, but views=100 < 200)
  uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
  EXPECT_EQ(fired, 1u);
  EXPECT_EQ(state->triggers[0].last_triggered_at, 1000u);
  EXPECT_EQ(state->triggers[1].last_triggered_at, 0u);

  // Verify policy1 was added but policy2 was not
  const char* policy1 = state_find_policy(state, "__op1__");
  EXPECT_NE(policy1, nullptr);
  const char* policy2 = state_find_policy(state, "__op2__");
  EXPECT_EQ(policy2, nullptr);
}

// ============================================================
// Trigger Operation Tests (via state machine)
// ============================================================

TEST_F(TestTrigger, TestCreateTriggerOperation) {
  operation_t* op = operation_create(CRABS_OP_CREATE_TRIGGER);
  const char* payload = "trigger_id=thresh1;condition=views >= 100;effect_type=5;"
                        "policy_operation=__read__;policy_expression=role >= moderator;"
                        "cooldown_ms=1000;one_shot=0";
  op->payload = (uint8_t*)strdup(payload);
  op->payload_size = strlen(payload) + 1;
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);

  crabs_error_e result = state_machine_op_create_trigger(state, op);
  EXPECT_EQ(result, CRABS_SUCCESS);
  EXPECT_EQ(state->trigger_count, 1u);
  EXPECT_STREQ(state->triggers[0].trigger_id, "thresh1");
  EXPECT_STREQ(state->triggers[0].condition, "views >= 100");
  EXPECT_NE(state->triggers[0].condition_ast, nullptr);
  EXPECT_EQ(state->triggers[0].effect.type, TRIGGER_EFFECT_CHANGE_POLICY);
  EXPECT_EQ(state->triggers[0].cooldown_ms, 1000u);
  EXPECT_EQ(state->triggers[0].one_shot, false);
  EXPECT_EQ(state->triggers[0].enabled, true);

  operation_destroy(op);
}

TEST_F(TestTrigger, TestCreateTriggerDuplicate) {
  operation_t* op1 = operation_create(CRABS_OP_CREATE_TRIGGER);
  const char* payload = "trigger_id=dup1;condition=views >= 100;effect_type=1";
  op1->payload = (uint8_t*)strdup(payload);
  op1->payload_size = strlen(payload) + 1;
  strncpy(op1->signer_id, "admin", CRABS_MAX_USER_ID - 1);

  crabs_error_e result = state_machine_op_create_trigger(state, op1);
  EXPECT_EQ(result, CRABS_SUCCESS);

  operation_t* op2 = operation_create(CRABS_OP_CREATE_TRIGGER);
  op2->payload = (uint8_t*)strdup(payload);
  op2->payload_size = strlen(payload) + 1;
  strncpy(op2->signer_id, "admin", CRABS_MAX_USER_ID - 1);

  result = state_machine_op_create_trigger(state, op2);
  EXPECT_EQ(result, CRABS_ERR_DUPLICATE_OPERATION);

  operation_destroy(op1);
  operation_destroy(op2);
}

TEST_F(TestTrigger, TestDeleteTriggerOperation) {
  // Create a trigger first
  operation_t* create_op = operation_create(CRABS_OP_CREATE_TRIGGER);
  const char* payload = "trigger_id=del1;condition=views >= 100;effect_type=1";
  create_op->payload = (uint8_t*)strdup(payload);
  create_op->payload_size = strlen(payload) + 1;
  strncpy(create_op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  state_machine_op_create_trigger(state, create_op);
  operation_destroy(create_op);

  EXPECT_EQ(state->trigger_count, 1u);

  // Delete the trigger
  operation_t* del_op = operation_create(CRABS_OP_DELETE_TRIGGER);
  const char* del_payload = "trigger_id=del1";
  del_op->payload = (uint8_t*)strdup(del_payload);
  del_op->payload_size = strlen(del_payload) + 1;

  crabs_error_e result = state_machine_op_delete_trigger(state, del_op);
  EXPECT_EQ(result, CRABS_SUCCESS);
  EXPECT_EQ(state->trigger_count, 0u);

  operation_destroy(del_op);
}

TEST_F(TestTrigger, TestDeleteTriggerNotFound) {
  operation_t* del_op = operation_create(CRABS_OP_DELETE_TRIGGER);
  const char* payload = "trigger_id=nonexistent";
  del_op->payload = (uint8_t*)strdup(payload);
  del_op->payload_size = strlen(payload) + 1;

  crabs_error_e result = state_machine_op_delete_trigger(state, del_op);
  EXPECT_EQ(result, CRABS_ERR_RESOURCE_NOT_FOUND);

  operation_destroy(del_op);
}

TEST_F(TestTrigger, TestDisableTriggerOperation) {
  // Create a trigger
  operation_t* create_op = operation_create(CRABS_OP_CREATE_TRIGGER);
  const char* payload = "trigger_id=dis1;condition=views >= 100;effect_type=1";
  create_op->payload = (uint8_t*)strdup(payload);
  create_op->payload_size = strlen(payload) + 1;
  strncpy(create_op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  state_machine_op_create_trigger(state, create_op);
  operation_destroy(create_op);

  EXPECT_EQ(state->triggers[0].enabled, true);

  // Disable the trigger
  operation_t* dis_op = operation_create(CRABS_OP_DISABLE_TRIGGER);
  const char* dis_payload = "trigger_id=dis1";
  dis_op->payload = (uint8_t*)strdup(dis_payload);
  dis_op->payload_size = strlen(dis_payload) + 1;

  crabs_error_e result = state_machine_op_disable_trigger(state, dis_op);
  EXPECT_EQ(result, CRABS_SUCCESS);
  EXPECT_EQ(state->triggers[0].enabled, false);

  operation_destroy(dis_op);
}

TEST_F(TestTrigger, TestEnableTriggerOperation) {
  // Create a trigger and disable it
  operation_t* create_op = operation_create(CRABS_OP_CREATE_TRIGGER);
  const char* payload = "trigger_id=en1;condition=views >= 100;effect_type=1";
  create_op->payload = (uint8_t*)strdup(payload);
  create_op->payload_size = strlen(payload) + 1;
  strncpy(create_op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  state_machine_op_create_trigger(state, create_op);
  operation_destroy(create_op);

  state->triggers[0].enabled = false;

  // Enable the trigger
  operation_t* en_op = operation_create(CRABS_OP_ENABLE_TRIGGER);
  const char* en_payload = "trigger_id=en1";
  en_op->payload = (uint8_t*)strdup(en_payload);
  en_op->payload_size = strlen(en_payload) + 1;

  crabs_error_e result = state_machine_op_enable_trigger(state, en_op);
  EXPECT_EQ(result, CRABS_SUCCESS);
  EXPECT_EQ(state->triggers[0].enabled, true);

  operation_destroy(en_op);
}

TEST_F(TestTrigger, TestEnableTriggerNotFound) {
  operation_t* en_op = operation_create(CRABS_OP_ENABLE_TRIGGER);
  const char* payload = "trigger_id=nonexistent";
  en_op->payload = (uint8_t*)strdup(payload);
  en_op->payload_size = strlen(payload) + 1;

  crabs_error_e result = state_machine_op_enable_trigger(state, en_op);
  EXPECT_EQ(result, CRABS_ERR_RESOURCE_NOT_FOUND);

  operation_destroy(en_op);
}

TEST_F(TestTrigger, TestDisableTriggerNotFound) {
  operation_t* dis_op = operation_create(CRABS_OP_DISABLE_TRIGGER);
  const char* payload = "trigger_id=nonexistent";
  dis_op->payload = (uint8_t*)strdup(payload);
  dis_op->payload_size = strlen(payload) + 1;

  crabs_error_e result = state_machine_op_disable_trigger(state, dis_op);
  EXPECT_EQ(result, CRABS_ERR_RESOURCE_NOT_FOUND);

  operation_destroy(dis_op);
}

// ============================================================
// Integration: Trigger Processing with Attribute Machine
// ============================================================

TEST_F(TestTrigger, TestIssueAttributeEffect) {
  // Create an attribute machine with a user who has role "viewer"
  uint8_t admin_pk[33];
  ecdsa_keypair_t* admin_kp = crypto_ecdsa_generate();
  ASSERT_NE(admin_kp, nullptr);
  memcpy(admin_pk, admin_kp->public_key, 33);
  crypto_ecdsa_keypair_destroy(admin_kp);
  attribute_machine_t* am = attribute_machine_create("admin", admin_pk);
  ASSERT_NE(am, nullptr);

  // Register a user with viewer role
  uint8_t user_pk[33];
  ecdsa_keypair_t* kp = crypto_ecdsa_generate();
  ASSERT_NE(kp, nullptr);
  memcpy(user_pk, kp->public_key, 33);
  crypto_ecdsa_keypair_destroy(kp);
  crabs_test_register_user_with_role(am, "alice", user_pk, "role", "viewer");

  // Set current time for temp attr expiry
  am->current_time_ms = 1000;

  // Add counter to the attribute machine's base_state so condition evaluation works
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(&am->base_state, views);

  // Create a trigger with ISSUE_ATTRIBUTE effect
  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_ISSUE_ATTRIBUTE;
  strncpy(effect.issue_attribute, "temp_access", CRABS_MAX_POLICY_EXPR - 1);
  // target_role should match the attribute name ("role" from "role:viewer")
  strncpy(effect.target_role, "role", CRABS_MAX_USER_ID - 1);
  effect.duration_ms = 60000;
  strncpy(effect.attribute_value, "granted", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("issue_attr_trigger", "Issue temp attr",
    "views >= 50", &effect, 0, false, "admin");
  ASSERT_NE(trigger, nullptr);

  // Process triggers with attribute machine, using base_state for condition evaluation
  uint32_t fired = trigger_process_all(&am->base_state, trigger, 1, am, 1000);
  EXPECT_EQ(fired, 1u);

  // Check that alice got the temporary attribute
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_NE(alice->temp_attrs, nullptr);

  trigger_destroy(trigger);
  attribute_machine_destroy(am);
}

// File-scope captures for the change-hook test below. The hook is a
// captureless lambda (plain function pointer), so observed events must be
// copied out: the event strings are only valid during the hook call.
static int change_hook_trigger_event_count = 0;
static char change_hook_last_trigger_type[CRABS_MAX_POLICY_EXPR];

static void record_trigger_change_events(state_t* observed_state,
                                         const crabs_change_event_t* event,
                                         void* user_data) {
  (void)observed_state;
  (void)user_data;
  if (event->kind != CRABS_CHANGE_TRIGGER) {
    return;
  }
  change_hook_trigger_event_count++;
  if (event->type != NULL) {
    strncpy(change_hook_last_trigger_type, event->type,
            sizeof(change_hook_last_trigger_type) - 1);
    change_hook_last_trigger_type[sizeof(change_hook_last_trigger_type) - 1] = '\0';
  }
}

// The trigger engine must announce ISSUE_ATTRIBUTE effects on the state
// change hook: a fired threshold trigger that successfully issues a
// temporary attribute emits an event with kind CRABS_CHANGE_TRIGGER and
// type "issue_temporary" (trigger.c, Amendment 1 §5.3).
TEST_F(TestTrigger, TestIssueAttributeEffectNotifiesChangeHook) {
  // Create an attribute machine with a user who has role "viewer"
  uint8_t admin_pk[33];
  ecdsa_keypair_t* admin_kp = crypto_ecdsa_generate();
  ASSERT_NE(admin_kp, nullptr);
  memcpy(admin_pk, admin_kp->public_key, 33);
  crypto_ecdsa_keypair_destroy(admin_kp);
  attribute_machine_t* am = attribute_machine_create("admin", admin_pk);
  ASSERT_NE(am, nullptr);

  // Register a user with viewer role
  uint8_t user_pk[33];
  ecdsa_keypair_t* kp = crypto_ecdsa_generate();
  ASSERT_NE(kp, nullptr);
  memcpy(user_pk, kp->public_key, 33);
  crypto_ecdsa_keypair_destroy(kp);
  crabs_test_register_user_with_role(am, "alice", user_pk, "role", "viewer");

  // Set current time for temp attr expiry
  am->current_time_ms = 1000;

  // Add counter to the attribute machine's base_state so condition evaluation works
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(&am->base_state, views);

  // Register the change hook on the state the trigger engine notifies
  change_hook_trigger_event_count = 0;
  change_hook_last_trigger_type[0] = '\0';
  state_set_change_hook(&am->base_state, record_trigger_change_events, NULL);

  // Create a trigger with ISSUE_ATTRIBUTE effect
  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_ISSUE_ATTRIBUTE;
  strncpy(effect.issue_attribute, "temp_access", CRABS_MAX_POLICY_EXPR - 1);
  // target_role should match the attribute name ("role" from "role:viewer")
  strncpy(effect.target_role, "role", CRABS_MAX_USER_ID - 1);
  effect.duration_ms = 60000;
  strncpy(effect.attribute_value, "granted", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("issue_attr_trigger", "Issue temp attr",
    "views >= 50", &effect, 0, false, "admin");
  ASSERT_NE(trigger, nullptr);

  // Process triggers with attribute machine, using base_state for condition evaluation
  uint32_t fired = trigger_process_all(&am->base_state, trigger, 1, am, 1000);
  EXPECT_EQ(fired, 1u);

  // The hook must have observed the trigger change event.
  EXPECT_GE(change_hook_trigger_event_count, 1);
  EXPECT_STREQ(change_hook_last_trigger_type, "issue_temporary");

  // Check that alice got the temporary attribute
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_NE(alice->temp_attrs, nullptr);

  state_set_change_hook(&am->base_state, NULL, NULL);
  trigger_destroy(trigger);
  attribute_machine_destroy(am);
}

// ============================================================
// Audit 9 (A-2/A-6): trigger re-entrancy and mid-loop mutation
// ============================================================
// The ISSUE_ATTRIBUTE change notification fires synchronously INSIDE the
// trigger processing loop, before last_triggered_at is written. A hook that
// executes ops during that notification can create/delete triggers, and
// state_machine_op_create_trigger reallocs state->triggers — moving the array
// the loop is iterating. The loop must therefore re-derive
// state->triggers/state->trigger_count every iteration, re-find the fired
// trigger by id after its effect runs, and defer nested trigger processing.

// File-scope captures for the captureless-lambda change hooks below.
static attribute_machine_t* reentrancy_hook_am = NULL;
static int reentrancy_hook_call_count = 0;

// A hook that mimics executing a __create_trigger__ op during trigger
// processing: it appends a trigger to state->triggers exactly the way
// state_machine_op_create_trigger does (trigger_count++ then realloc — the
// realloc moves the array the outer loop is iterating).
static void create_trigger_during_processing(state_t* observed_state,
                                             const crabs_change_event_t* event,
                                             void* user_data) {
  (void)user_data;
  if (event->kind != CRABS_CHANGE_TRIGGER) return;
  reentrancy_hook_call_count++;
  if (reentrancy_hook_call_count > 1) return; // only mutate on the first event

  trigger_effect_t hook_effect;
  memset(&hook_effect, 0, sizeof(hook_effect));
  hook_effect.type = TRIGGER_EFFECT_ISSUE_ATTRIBUTE;
  strncpy(hook_effect.issue_attribute, "hook_attr", CRABS_MAX_POLICY_EXPR - 1);
  strncpy(hook_effect.target_role, "role", CRABS_MAX_USER_ID - 1);
  hook_effect.duration_ms = 60000;
  strncpy(hook_effect.attribute_value, "hook", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* hook_trigger = trigger_create("hook_created", "Created by hook",
    "views >= 999999", &hook_effect, 0, false, "admin");
  ASSERT_NE(hook_trigger, nullptr);

  uint32_t append_index = observed_state->trigger_count;
  observed_state->trigger_count++;
  trigger_t* grown_triggers = (trigger_t*)realloc(observed_state->triggers,
    observed_state->trigger_count * sizeof(trigger_t));
  ASSERT_NE(grown_triggers, nullptr);
  observed_state->triggers = grown_triggers;
  observed_state->triggers[append_index] = *hook_trigger;
  free(hook_trigger);
}

static bool state_has_trigger_with_id(state_t* checked_state, const char* trigger_id) {
  for (uint32_t i = 0; i < checked_state->trigger_count; i++) {
    if (strcmp(checked_state->triggers[i].trigger_id, trigger_id) == 0) return true;
  }
  return false;
}

static uint32_t count_temp_attributes(user_t* user) {
  uint32_t temp_attr_count = 0;
  for (temp_attr_list_t* temp = user->temp_attrs; temp != NULL; temp = temp->next) {
    temp_attr_count++;
  }
  return temp_attr_count;
}

// Shared setup for the re-entrancy tests: an attribute machine with a viewer
// user, a views counter past the threshold, and a threshold trigger with an
// ISSUE_ATTRIBUTE effect stored in the STATE-OWNED trigger array (the
// production shape — state_machine.c passes state->triggers).
static attribute_machine_t* setup_reentrancy_state(state_t** out_state) {
  uint8_t admin_pk[33];
  ecdsa_keypair_t* admin_kp = crypto_ecdsa_generate();
  if (admin_kp == NULL) return NULL;
  memcpy(admin_pk, admin_kp->public_key, 33);
  crypto_ecdsa_keypair_destroy(admin_kp);
  attribute_machine_t* am = attribute_machine_create("admin", admin_pk);
  if (am == NULL) return NULL;

  uint8_t user_pk[33];
  ecdsa_keypair_t* kp = crypto_ecdsa_generate();
  if (kp == NULL) {
    attribute_machine_destroy(am);
    return NULL;
  }
  memcpy(user_pk, kp->public_key, 33);
  crypto_ecdsa_keypair_destroy(kp);
  crabs_test_register_user_with_role(am, "alice", user_pk, "role", "viewer");

  am->current_time_ms = 1000;

  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(&am->base_state, views);

  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_ISSUE_ATTRIBUTE;
  strncpy(effect.issue_attribute, "temp_access", CRABS_MAX_POLICY_EXPR - 1);
  strncpy(effect.target_role, "role", CRABS_MAX_USER_ID - 1);
  effect.duration_ms = 60000;
  strncpy(effect.attribute_value, "granted", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("issue_attr_trigger", "Issue temp attr",
    "views >= 50", &effect, 0, false, "admin");
  if (trigger == NULL) {
    attribute_machine_destroy(am);
    return NULL;
  }
  am->base_state.trigger_count = 1;
  am->base_state.triggers =
    (trigger_t*)realloc(am->base_state.triggers, sizeof(trigger_t));
  am->base_state.triggers[0] = *trigger;
  free(trigger);

  *out_state = &am->base_state;
  return am;
}

// Audit 9 A-2: a change hook that creates a trigger while the trigger loop is
// running must not corrupt the loop. The loop re-finds triggers by id after
// each effect, so the realloc inside the hook is survivable, and the fired
// trigger's bookkeeping lands in the live (post-realloc) array.
TEST_F(TestTrigger, HookCreateTriggerDuringProcessingDoesNotCorrupt) {
  state_t* reentrancy_state = NULL;
  attribute_machine_t* am = setup_reentrancy_state(&reentrancy_state);
  ASSERT_NE(am, nullptr);
  ASSERT_NE(reentrancy_state, nullptr);

  reentrancy_hook_am = am;
  reentrancy_hook_call_count = 0;
  state_set_change_hook(reentrancy_state, create_trigger_during_processing, NULL);

  uint32_t fired = trigger_process_all(reentrancy_state, reentrancy_state->triggers,
                                       reentrancy_state->trigger_count, am, 1000);
  EXPECT_EQ(fired, 1u);

  // The fired trigger's bookkeeping must be readable in the LIVE array: the
  // hook's realloc moved it, and without the re-find the write landed in
  // freed memory.
  ASSERT_EQ(reentrancy_state->trigger_count, 2u);
  EXPECT_STREQ(reentrancy_state->triggers[0].trigger_id, "issue_attr_trigger");
  EXPECT_EQ(reentrancy_state->triggers[0].last_triggered_at, 1000u);
  EXPECT_EQ(reentrancy_state->triggers[0].enabled, true);

  // The hook-created trigger persisted.
  EXPECT_TRUE(state_has_trigger_with_id(reentrancy_state, "hook_created"));

  // No double-fire: exactly one temporary attribute was issued for alice.
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(count_temp_attributes(alice), 1u);

  state_set_change_hook(reentrancy_state, NULL, NULL);
  reentrancy_hook_am = NULL;
  attribute_machine_destroy(am);
}

// Audit 9 A-6: a hook that re-enters trigger_process_all during processing
// must be deferred — the nested call processes nothing (the same trigger
// must not double-fire before the outer loop writes last_triggered_at).
static int nested_fired_count = -1;
static int nested_hook_call_count = 0;

static void recurse_into_trigger_processing(state_t* observed_state,
                                            const crabs_change_event_t* event,
                                            void* user_data) {
  (void)user_data;
  if (event->kind != CRABS_CHANGE_TRIGGER) return;
  nested_hook_call_count++;
  if (nested_fired_count >= 0) return; // only recurse on the first event

  nested_fired_count = (int)trigger_process_all(observed_state,
    observed_state->triggers, observed_state->trigger_count,
    reentrancy_hook_am, 1000);
}

TEST_F(TestTrigger, NestedProcessingIsDeferred) {
  state_t* reentrancy_state = NULL;
  attribute_machine_t* am = setup_reentrancy_state(&reentrancy_state);
  ASSERT_NE(am, nullptr);
  ASSERT_NE(reentrancy_state, nullptr);

  reentrancy_hook_am = am;
  nested_fired_count = -1;
  nested_hook_call_count = 0;
  state_set_change_hook(reentrancy_state, recurse_into_trigger_processing, NULL);

  uint32_t fired = trigger_process_all(reentrancy_state, reentrancy_state->triggers,
                                       reentrancy_state->trigger_count, am, 1000);
  EXPECT_EQ(fired, 1u);

  // The nested call was deferred: it processed nothing.
  EXPECT_EQ(nested_fired_count, 0);
  EXPECT_EQ(nested_hook_call_count, 1);

  // No double-fire: exactly one temporary attribute was issued.
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(count_temp_attributes(alice), 1u);
  EXPECT_EQ(reentrancy_state->triggers[0].last_triggered_at, 1000u);

  state_set_change_hook(reentrancy_state, NULL, NULL);
  reentrancy_hook_am = NULL;
  attribute_machine_destroy(am);
}

// ============================================================
// Combined Condition + Trigger Tests
// ============================================================

TEST_F(TestTrigger, TestAndConditionTrigger) {
  // Add counters for AND condition
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(state, views);

  data_item_t* flags = data_item_create("flags", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc2 = g_counter_create();
  g_counter_increment(gc2, "nodeA", 5);
  flags->value = gc2;
  state_add_item(state, flags);

  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_CHANGE_POLICY;
  strncpy(effect.policy_operation, "__combined__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect.policy_expression, "combined", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("and_trigger", "AND condition",
    "views >= 50 AND flags >= 3", &effect, 0, false, "admin");
  ASSERT_NE(trigger, nullptr);

  state->trigger_count = 1;
  state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
  state->triggers[0] = *trigger;
  free(trigger);

  uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
  EXPECT_EQ(fired, 1u);
  // Note: gc and gc2 will be freed by state_destroy via data_item_destroy
}

TEST_F(TestTrigger, TestOrConditionTriggerPartial) {
  // Add counters - only one condition is true
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(state, views);

  data_item_t* flags = data_item_create("flags", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc2 = g_counter_create();
  g_counter_increment(gc2, "nodeA", 1);
  flags->value = gc2;
  state_add_item(state, flags);

  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_CHANGE_POLICY;
  strncpy(effect.policy_operation, "__or_op__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect.policy_expression, "or_policy", CRABS_MAX_POLICY_EXPR - 1);

  trigger_t* trigger = trigger_create("or_trigger", "OR condition",
    "views >= 50 OR flags >= 10", &effect, 0, false, "admin");
  ASSERT_NE(trigger, nullptr);

  state->trigger_count = 1;
  state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
  state->triggers[0] = *trigger;
  free(trigger);

  // views >= 50 is true, flags >= 10 is false, OR should still fire
  uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
  EXPECT_EQ(fired, 1u);
  // Note: gc and gc2 will be freed by state_destroy via data_item_destroy
}

// ============================================================
// operation_is_builtin with trigger operations
// ============================================================

TEST_F(TestTrigger, TestOperationIsBuiltinTriggerOps) {
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_CREATE_TRIGGER));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_DELETE_TRIGGER));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_DISABLE_TRIGGER));
  EXPECT_TRUE(operation_is_builtin(CRABS_OP_ENABLE_TRIGGER));
  EXPECT_FALSE(operation_is_builtin("custom_op"));
}
// ============================================================
// Audit fix (High): CHANGE_POLICY effects must not be able to strip
// attribute gating from the target operation.
//
// A CONTAINS-only policy_expression (e.g. "a NOT IN b") preprocesses to an
// EMPTY abe_policy with resolved_ok = true — preprocess_policy strips every
// CONTAINS node before handing the remainder to the ABE evaluator. An empty
// ABE policy authorizes by signature alone, so the trigger would silently
// remove all attribute checks from policy_operation when it fires.
// ============================================================

TEST_F(TestTrigger, TestCreateTriggerOperationRejectsContainsOnlyPolicyExpression) {
  operation_t* op = operation_create(CRABS_OP_CREATE_TRIGGER);
  const char* payload = "trigger_id=weaken1;condition=views >= 100;effect_type=5;"
                        "policy_operation=__read__;policy_expression=role NOT IN blacklist;"
                        "cooldown_ms=1000;one_shot=0";
  op->payload = (uint8_t*)strdup(payload);
  op->payload_size = strlen(payload) + 1;
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);

  crabs_error_e result = state_machine_op_create_trigger(state, op);
  EXPECT_EQ(result, CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state->trigger_count, 0u);

  operation_destroy(op);
}

TEST_F(TestTrigger, TestCreateTriggerOperationAllowsMixedPolicyExpression) {
  // A CONTAINS clause combined with a real ABE constraint is fine: the
  // preprocessed policy keeps the non-CONTAINS part ("role >= moderator"),
  // so attribute gating is preserved.
  operation_t* op = operation_create(CRABS_OP_CREATE_TRIGGER);
  const char* payload = "trigger_id=mixed1;condition=views >= 100;effect_type=5;"
                        "policy_operation=__read__;"
                        "policy_expression=role >= moderator AND role NOT IN blacklist;"
                        "cooldown_ms=1000;one_shot=0";
  op->payload = (uint8_t*)strdup(payload);
  op->payload_size = strlen(payload) + 1;
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);

  crabs_error_e result = state_machine_op_create_trigger(state, op);
  EXPECT_EQ(result, CRABS_SUCCESS);
  ASSERT_EQ(state->trigger_count, 1u);
  EXPECT_STREQ(state->triggers[0].trigger_id, "mixed1");

  operation_destroy(op);
}

TEST_F(TestTrigger, TestCreateTriggerOperationRejectsUnparseableCondition) {
  // A condition the parser rejects (quoted-string operand) must not be
  // stored as a trigger that silently never fires — the create operation
  // fails instead.
  operation_t* op = operation_create(CRABS_OP_CREATE_TRIGGER);
  const char* payload = "trigger_id=badcond1;condition=subscription == \"active\";effect_type=1";
  op->payload = (uint8_t*)strdup(payload);
  op->payload_size = strlen(payload) + 1;
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);

  crabs_error_e result = state_machine_op_create_trigger(state, op);
  EXPECT_EQ(result, CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(state->trigger_count, 0u);

  operation_destroy(op);
}

TEST_F(TestTrigger, TestChangePolicyRejectsContainsOnlyPolicyAtExecution) {
  // Defense in depth: a trigger created via the direct trigger_create API
  // (no creation-time validation) must not be able to apply a CONTAINS-only
  // policy expression when it fires — the effect is skipped.
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(state, views);

  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_CHANGE_POLICY;
  strncpy(effect.policy_operation, "__read__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect.policy_expression, "role NOT IN blacklist", CRABS_MAX_POLICY_EXPR - 1);
  trigger_t* trigger = trigger_create("contains_only_policy", "Fires when views >= 50",
    "views >= 50", &effect, 0, false, "admin");
  ASSERT_NE(trigger, nullptr);
  state->trigger_count = 1;
  state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
  state->triggers[0] = *trigger;
  free(trigger);

  uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
  EXPECT_EQ(fired, 0u); // effect skipped — empty ABE policy
  // The target policy is NOT added: attribute gating cannot be stripped.
  EXPECT_EQ(state_find_policy(state, "__read__"), nullptr);

  // TearDown's state_destroy will free the trigger's AST.
}

TEST_F(TestTrigger, TestChangePolicyAllowsAbePolicyAtExecution) {
  // A CHANGE_POLICY effect with a genuine ABE expression still applies.
  data_item_t* views = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  g_counter_t* gc = g_counter_create();
  g_counter_increment(gc, "nodeA", 100);
  views->value = gc;
  state_add_item(state, views);

  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_CHANGE_POLICY;
  strncpy(effect.policy_operation, "__read__", CRABS_MAX_OP_NAME - 1);
  strncpy(effect.policy_expression, "role:member", CRABS_MAX_POLICY_EXPR - 1);
  trigger_t* trigger = trigger_create("abe_policy", "Fires when views >= 50",
    "views >= 50", &effect, 0, false, "admin");
  ASSERT_NE(trigger, nullptr);
  state->trigger_count = 1;
  state->triggers = (trigger_t*)realloc(state->triggers, sizeof(trigger_t));
  state->triggers[0] = *trigger;
  free(trigger);

  uint32_t fired = trigger_process_all(state, state->triggers, state->trigger_count, NULL, 1000);
  EXPECT_EQ(fired, 1u);
  const char* policy = state_find_policy(state, "__read__");
  ASSERT_NE(policy, nullptr);
  EXPECT_STREQ(policy, "role:member");

  // TearDown's state_destroy will free the trigger's AST.
}
