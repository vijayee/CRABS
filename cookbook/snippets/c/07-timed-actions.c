/* Recipe 7 — timed actions (C core): the scheduler engine the wasm binding
 * wraps. The embedded op is signed AT SUBMISSION; every tick
 * (scheduler_process_due) materializes what is due through the machine's
 * FULL authorization — policy, signature, staleness — and records failures
 * instead of propagating them. Covers a one-off mint (not due / due /
 * idempotent), a cancel, a recurring series exhausted by catch-up, and the
 * per-tick occurrence budget, mirroring:
 *   test/test_scheduler.cpp:485-529  (due op materialized exactly once)
 *   test/test_scheduler.cpp:877-891  (cadence until count exhausted)
 *   test/test_scheduler.cpp:1029-1082 (budget limits catch-up with carry over). */
#include "Scheduler/scheduler.h"
#include "Attribute/attribute_machine.h"
#include "StateMachine/state_machine.h"
#include "Crypto/crypto.h"
#include "Serialization/serialization.h"
#include "CRABS/crabs.h"
#include "CRABS/data_model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* The timed effect: a 'mint' op counted by a trivial handler. */
static uint32_t landed_mints = 0;
static crabs_error_e mint_handler(state_t* state, operation_t* op) {
  (void)state;
  (void)op;
  landed_mints++;
  return CRABS_SUCCESS;
}

/* Sign a custom op of the given name, attributing it to the bootstrap
 * admin, and give it a DISTINCT nonzero uuid: the wire carries no uuid, the
 * uuid is covered by the signature, and the materialization guard keys on
 * it — a zero uuid would collide with the all-zero sentinel (the exact
 * stamp-unique-uuid discipline of test/test_scheduler.cpp:290-299). */
static operation_t* make_signed_mint(attribute_machine_t* am,
                                     ecdsa_keypair_t* admin_key,
                                     uint8_t uuid_fill) {
  operation_t* op = operation_create("mint");
  assert(op != NULL);
  memset(op->uuid, uuid_fill, CRABS_UUID_SIZE);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->lamport_time = 1;
  op->signer_key_version = attribute_machine_find_user(am, "admin")->key_version;
  serialized_buffer_t* wire = crabs_serialize_for_signing(op);
  assert(wire != NULL);
  assert(crypto_sign_operation(admin_key->private_key, wire->data, wire->len,
                               op->signature) == CRABS_SUCCESS);
  serialized_buffer_destroy(wire);
  return op;
}

int main(void) {
  ecdsa_keypair_t* admin_key = crypto_ecdsa_generate();
  assert(admin_key != NULL);
  attribute_machine_t* am = attribute_machine_create("admin", admin_key->public_key);
  assert(am != NULL);
  am->base_state.attr_machine = am;  /* integrator wiring */
  state_t* state = &am->base_state;

  /* Scheduling is an AUTHORIZED pipeline for the embedded op, not a free
   * side channel: the mint type needs a policy, and the signature + key
   * version are checked at materialization time. */
  assert(state_add_policy(state, "mint", "role:admin") == CRABS_SUCCESS);
  assert(state_machine_register_handler(state, "mint", mint_handler)
         == CRABS_SUCCESS);

  const uint64_t base = (uint64_t)1000000000;  /* fixed demo epoch (ms) */

  /* ---- One-off ---- */
  operation_t* embed_a = make_signed_mint(am, admin_key, 0xB1);
  uint64_t schedule_id = scheduler_schedule(state, base + 1000, "admin", embed_a);
  assert(schedule_id != 0);
  assert(scheduler_count(state) == 1u);
  const scheduled_operation_t* pending = scheduler_first(state);
  assert(pending != NULL);
  assert(pending->schedule_id == schedule_id);
  assert(pending->execute_at_ms == base + 1000);
  assert(strcmp(pending->submitter, "admin") == 0);
  assert(pending->op_len > 0u);   /* the embedded op is serialized, replayed later */

  /* Not due: the tick advances the clock without materializing. */
  assert(scheduler_process_due(state, base + 999) == CRABS_SUCCESS);
  assert(scheduler_count(state) == 1u);
  assert(landed_mints == 0u);

  /* Due: materializes exactly once — the embedded op runs through the FULL
   * executor (auth checked at submission policy, signature re-verified). */
  assert(scheduler_process_due(state, base + 1000) == CRABS_SUCCESS);
  assert(scheduler_count(state) == 0u);
  assert(landed_mints == 1u);
  assert(scheduler_process_due(state, base + 2000) == CRABS_SUCCESS);
  assert(landed_mints == 1u);  /* idempotent: an empty queue re-fires nothing */
  printf("timed-actions OK: one-off mint materialized exactly once\n");

  /* ---- Cancel: a queued change of plans is retrievable before due ---- */
  operation_t* embed_b = make_signed_mint(am, admin_key, 0xB2);
  uint64_t cancelled_id = scheduler_schedule(state, base + 5000, "admin", embed_b);
  assert(cancelled_id != 0);
  assert(scheduler_cancel(state, cancelled_id) == CRABS_SUCCESS);
  assert(scheduler_count(state) == 0u);
  assert(scheduler_process_due(state, base + 5001) == CRABS_SUCCESS);
  assert(landed_mints == 1u);
  printf("timed-actions OK: cancelled schedule never materializes\n");

  /* ---- Recurring: 3 fires at 1s cadence, exhausted by one catch-up tick ---- */
  operation_t* embed_c = make_signed_mint(am, admin_key, 0xB3);
  uint64_t recurring_id = scheduler_schedule_recurring(state, base + 1000,
                                                       1000, 3, 0, "admin",
                                                       embed_c);
  assert(recurring_id != 0);
  const scheduled_operation_t* cadence = scheduler_first(state);
  assert(cadence != NULL);
  assert(cadence->interval_ms == 1000u);
  assert(cadence->repeat_count == 3u);
  assert(cadence->end_at_ms == 0u);
  assert(scheduler_process_due(state, base + 3000) == CRABS_SUCCESS);
  assert(scheduler_count(state) == 0u);   /* series exhausted */
  assert(landed_mints == 4u);             /* 1 one-off + 3 cadence fires */
  printf("timed-actions OK: recurring series fired 3x in cadence order\n");

  /* ---- Budget: bound the per-tick burst; deferred slots carry over ---- */
  operation_t* embed_d = make_signed_mint(am, admin_key, 0xB4);
  uint64_t budgeted_id = scheduler_schedule_recurring(state, base + 1000,
                                                      1000, 3, 0, "admin",
                                                      embed_d);
  assert(budgeted_id != 0);
  scheduler_set_max_occurrences_per_tick(state, 2);
  assert(scheduler_process_due(state, base + 3000) == CRABS_SUCCESS);
  assert(scheduler_count(state) == 1u);   /* slot 3000 carried over */
  assert(landed_mints == 6u);             /* 4 earlier + 2 budgeted */
  /* 0 = unlimited: the deferred slot fires on the next tick. */
  scheduler_set_max_occurrences_per_tick(state, 0);
  assert(scheduler_process_due(state, base + 3000) == CRABS_SUCCESS);
  assert(scheduler_count(state) == 0u);
  assert(landed_mints == 7u);
  printf("timed-actions OK: occurrence budget bounded the burst, carry-over fired\n");

  operation_destroy(embed_d);
  operation_destroy(embed_c);
  operation_destroy(embed_b);
  operation_destroy(embed_a);
  attribute_machine_destroy(am);
  crypto_ecdsa_keypair_destroy(admin_key);
  return 0;
}