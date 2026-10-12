/* Recipe 6 — progressive disclosure moderation (C core).
 *
 * Two halves, both library-level, mirroring the C test suite:
 *   1. The threshold trigger: a trigger over a counter item fires an
 *      ISSUE_ATTRIBUTE effect that fans a TEMPORARY 'clearance:moderator'
 *      out to every holder of an attribute NAMED 'role'; the cooldown
 *      rate-limits re-fires (test/test_trigger.cpp:125-170 cooldown,
 *      :378-415; temp-attr expiry test/test_attribute_machine.cpp:561-584).
 *   2. The sealed payload: CP-ABE encrypt/decrypt where a user key derived
 *      from the granted attributes decrypts and a key missing one clause
 *      cannot (test/test_crypto.cpp:249-294 TestPolicyAnd). */
#include "Trigger/trigger.h"
#include "Attribute/attribute_machine.h"
#include "Condition/condition.h"
#include "Crypto/crypto.h"
#include "CRDT/crdt_merge.h"
#include "CRABS/data_model.h"
#include "CRABS/crabs.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Count a user's temporary attributes (the list is prepend-ordered, newest
 * first — attribute_machine.c prepends each issue). */
static uint32_t count_temp_attrs(user_t* user) {
  uint32_t count = 0;
  for (temp_attr_list_t* entry = user->temp_attrs; entry != NULL; entry = entry->next) {
    count++;
  }
  return count;
}

int main(void) {
  /* Machine: attribute machine + its wired base state (integrator wiring,
   * src/Util/wasm_helpers.c:242). */
  ecdsa_keypair_t* admin_key = crypto_ecdsa_generate();
  assert(admin_key != NULL);
  attribute_machine_t* am = attribute_machine_create("admin", admin_key->public_key);
  assert(am != NULL);
  am->base_state.attr_machine = am;
  state_t* state = &am->base_state;

  /* alice is a member; the moderation mechanism below gives her clearance
   * only when the threshold trigger says so. */
  ecdsa_keypair_t* alice_key = crypto_ecdsa_generate();
  assert(alice_key != NULL);
  assert(attribute_machine_register_user(am, "alice", alice_key->public_key,
                                         "adult") == CRABS_SUCCESS);
  assert(attribute_machine_grant_role(am, "alice", "role", "member", "admin")
         == CRABS_SUCCESS);

  /* The threshold item: counter 'abuse_reports' = 2 (below threshold).
   * Conditions resolve the FULL item path to its logical value — for a
   * struct g_counter, the entry sum (condition_resolve_path,
   * src/Condition/condition.c:916-943). */
  data_item_t* reports = data_item_create("abuse_reports", DATA_TYPE_COUNTER,
                                          CRDT_G_COUNTER);
  assert(reports != NULL);
  g_counter_t* reports_counter = g_counter_create();
  assert(reports_counter != NULL);
  assert(g_counter_increment(reports_counter, "community", 2) == CRABS_SUCCESS);
  reports->value = reports_counter;
  reports->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  assert(state_add_item(state, reports) == CRABS_SUCCESS);

  /* The effect: when the trigger fires, every ACTIVE user holding an
   * attribute NAMED 'role' (target_role is the audience attribute NAME)
   * receives the temporary token 'clearance:moderator' for 10 minutes
   * (attribute_machine_issue_temporary fans out over name holders,
   * src/Attribute/attribute_machine.c:966-990). Privileged names are
   * refused at issue time too (audit N-1, attribute_machine.c:973-995). */
  trigger_effect_t effect;
  memset(&effect, 0, sizeof(effect));
  effect.type = TRIGGER_EFFECT_ISSUE_ATTRIBUTE;
  strncpy(effect.issue_attribute, "clearance", CRABS_MAX_POLICY_EXPR - 1);
  strncpy(effect.target_role, "role", CRABS_MAX_USER_ID - 1);
  effect.duration_ms = 600000;
  strncpy(effect.attribute_value, "moderator", CRABS_MAX_POLICY_EXPR - 1);

  /* The trigger: condition 'abuse_reports >= 3', parsed to an AST at create
   * (an unparseable condition is INVALID_PARAM at the op level). */
  trigger_t* trigger = trigger_create("clearance_gateway",
                                      "issue clearance at the report threshold",
                                      "abuse_reports >= 3", &effect, 60000,
                                      false, "admin");
  assert(trigger != NULL);
  assert(trigger->condition_ast != NULL);
  assert(trigger->enabled == true);

  /* Install into the STATE-OWNED array — the production shape the executor
   * passes back into trigger_process_all (state_machine.c:1519). A struct
   * copy transfers ownership of condition_ast; free() the wrapper only
   * (audit R5-4, the exact pattern test/test_trigger.cpp installs). */
  uint32_t install_index = state->trigger_count++;
  state->triggers = (trigger_t*)realloc(state->triggers,
                                        state->trigger_count * sizeof(trigger_t));
  assert(state->triggers != NULL);
  state->triggers[install_index] = *trigger;
  free(trigger);

  /* BELOW threshold: the counter is 2, so processing must not fire. */
  attribute_machine_set_time(am, 1000);
  assert(trigger_process_all(state, state->triggers, state->trigger_count, am,
                             1000) == 0);
  user_t* alice = attribute_machine_find_user(am, "alice");
  assert(alice != NULL);
  assert(alice->temp_attrs == NULL);

  /* The report arrives (counter 2 -> 3): the next post-execute trigger pass
   * fires. In production the executor runs this pass after every successful
   * op (Step 9, src/StateMachine/state_machine.c:1508-1520); the driver here
   * is the explicit tick. ISSUE_ATTRIBUTE stamps the grant with the
   * ATTRIBUTE MACHINE's injected clock (am->current_time_ms), while
   * last_triggered_at bookkeeping uses the pass's now — inject both. */
  attribute_machine_set_time(am, 2000);
  assert(g_counter_increment(reports_counter, "community", 1) == CRABS_SUCCESS);
  assert(g_counter_value(reports_counter) == 3);
  assert(trigger_process_all(state, state->triggers, state->trigger_count, am,
                             2000) == 1);

  alice = attribute_machine_find_user(am, "alice");
  assert(alice != NULL);
  assert(alice->temp_attrs != NULL);
  assert(strcmp(alice->temp_attrs->name, "clearance:moderator") == 0);
  assert(strcmp(alice->temp_attrs->value, "moderator") == 0);
  assert(alice->temp_attrs->issued_at == 2000);
  assert(alice->temp_attrs->expires_at == (uint64_t)2000 + 600000u);
  /* Fan-out: the bootstrap admin also holds an attribute named 'role'
   * ('role:admin') — the demo mechanism issues to EVERY holder. */
  user_t* bootstrap = attribute_machine_find_user(am, "admin");
  assert(bootstrap != NULL);
  assert(bootstrap->temp_attrs != NULL);
  assert(strcmp(bootstrap->temp_attrs->name, "clearance:moderator") == 0);
  printf("moderation OK: threshold trigger issued temporary clearance\n");

  /* Rate limit: a re-evaluation INSIDE the 60s cooldown must not re-issue. */
  assert(trigger_process_all(state, state->triggers, state->trigger_count, am,
                             3000) == 0);
  alice = attribute_machine_find_user(am, "alice");
  assert(count_temp_attrs(alice) == 1);  /* no second entry */
  printf("moderation OK: cooldown suppressed the immediate re-fire\n");

  /* After the cooldown the trigger re-issues (one_shot false) — a fresh
   * 10-minute window instead of a permanent grant. */
  attribute_machine_set_time(am, (uint64_t)2000 + 60001);
  assert(trigger_process_all(state, state->triggers, state->trigger_count, am,
                             (uint64_t)2000 + 60001) == 1);
  alice = attribute_machine_find_user(am, "alice");
  assert(count_temp_attrs(alice) == 2);
  assert(alice->temp_attrs->issued_at == (uint64_t)2000 + 60001);
  printf("moderation OK: cooldown elapsed, clearance re-issued on a new window\n");

  /* ===== Half 2: the payload is SEALED, not just gated =====
   * Real CP-ABE: seal under the ABE policy words the attributes map to
   * (CRABS 'name:value' tokens become 'name_value' words,
   * src/Crypto/crypto.c:95-115). Key discipline: a user key with BOTH
   * attributes decrypts; one missing the clearance clause cannot. */
  abe_master_key_t* authority = crypto_abe_setup();
  assert(authority != NULL);

  const uint8_t contact_card[] = "contact for verified viewers";
  abe_ciphertext_t* sealed = crypto_abe_encrypt(
      authority, contact_card, sizeof(contact_card),
      "moderator and member");
  assert(sealed != NULL);
  assert(strcmp(crypto_abe_ciphertext_get_policy(sealed),
                "moderator and member") == 0);

  size_t sealed_len = 0;
  crypto_abe_ciphertext_get_data(sealed, &sealed_len);
  assert(sealed_len > 0);

  abe_user_key_t* verified = crypto_abe_keygen(authority, "moderator,member");
  assert(verified != NULL);
  uint8_t* opened = NULL;
  size_t opened_len = 0;
  assert(crypto_abe_decrypt(verified, sealed, &opened, &opened_len)
         == CRABS_SUCCESS);
  assert(opened_len == sizeof(contact_card));
  assert(memcmp(opened, contact_card, opened_len) == 0);
  free(opened);
  opened = NULL;
  printf("moderation OK: policy-satisfying key opened the sealed contact card\n");

  abe_user_key_t* low_trust = crypto_abe_keygen(authority, "viewer,member");
  assert(low_trust != NULL);
  assert(crypto_abe_decrypt(low_trust, sealed, &opened, &opened_len)
         == CRABS_ERR_UNAUTHORIZED);
  printf("moderation OK: low-trust key refused (attributes do not satisfy the policy)\n");

  crypto_abe_user_key_destroy(low_trust);
  crypto_abe_user_key_destroy(verified);
  crypto_abe_ciphertext_destroy(sealed);
  crypto_abe_master_key_destroy(authority);

  attribute_machine_destroy(am);
  crypto_ecdsa_keypair_destroy(alice_key);
  crypto_ecdsa_keypair_destroy(admin_key);
  return 0;
}