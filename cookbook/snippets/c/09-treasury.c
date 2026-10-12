/* Recipe 9 — treasury with atomic transfers (C core: the full protocol).
 *
 * What the C executor guarantees for a shared pot, and what this snippet
 * drives on a real signed state machine:
 *   A. the lock ceremony — only one holder can acquire a live RESOURCE
 *      lease; a competing `__lock__` is refused; a custom op acting on a
 *      LOCKED item is token-checked when it claims; the claim is verified
 *      against the live owner/token (mirrors TestLockOperation /
 *      TestLockVerifyUnlockCycle / TestLockTokenMismatch,
 *      test/test_state_machine.cpp:196-352);
 *   B. a real debit/credit through a registered handler, applied exactly
 *      once — the memory tx_manager records committed ops and rejects the
 *      duplicate uuid with CRABS_ERR_ALREADY_EXECUTED (mirrors
 *      test/test_tx_manager.cpp:230-244);
 *   C. all-or-nothing preconditions: an op naming {real pot, unknown item}
 *      fails resource_not_found BEFORE the handler and leaves no partial
 *      apply — no log entry, no balance moved (mirrors
 *      ProtocolTransitionIsAtomicAcrossResources,
 *      test/test_state_machine.cpp:1153).
 * The lock is machine-local coordination: lock state is runtime-only and
 * never serialized (src/CRABS/data_model.h:126-131) — see the recipe page. */
#include "Attribute/attribute_machine.h"
#include "StateMachine/state_machine.h"
#include "Crypto/crypto.h"
#include "Serialization/serialization.h"
#include "TxManager/tx_manager_memory.h"
#include "CRABS/crabs.h"
#include "CRABS/data_model.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static attribute_machine_t* recipe_machine;
static uint64_t lamport_clock = 0;

/* The treasury movement itself: debit the pot, credit the member. The
 * handler owns the arithmetic — the machine owns everything around it. */
static crabs_error_e transfer_handler(state_t* context_state, operation_t* op) {
  (void)context_state; /* the handler reads items through state_find_item */
  if (op->resource_count != 2) return CRABS_ERR_INVALID_PARAM;
  data_item_t* pot_item = state_find_item(context_state, op->resources[0]);
  data_item_t* member_item = state_find_item(context_state, op->resources[1]);
  if (pot_item == NULL || member_item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
  int64_t* pot = (int64_t*)pot_item->value;
  int64_t* member_pot = (int64_t*)member_item->value;
  const int64_t amount = 100;
  if (*pot < amount) return CRABS_ERR_PROTOCOL_VIOLATION;
  *pot -= amount;
  *member_pot += amount;
  return CRABS_SUCCESS;
}

/* Sign the op as its declared signer, the way the executor expects:
 * stamp the signer's CURRENT key_version (R7-04 staleness check) and a
 * strictly increasing lamport time (R7-11 replay backstop). */
static void op_sign_as(ecdsa_keypair_t* signer_key, operation_t* op) {
  user_t* signer = attribute_machine_find_user(recipe_machine, op->signer_id);
  assert(signer != NULL);
  op->signer_key_version = signer->key_version;
  op->lamport_time = ++lamport_clock;
  serialized_buffer_t* wire = crabs_serialize_for_signing(op);
  assert(wire != NULL);
  assert(crypto_sign_operation(signer_key->private_key, wire->data, wire->len,
                               op->signature) == CRABS_SUCCESS);
  serialized_buffer_destroy(wire);
}

static operation_t* make_one_resource_op(const char* op_type, const char* signer,
                                         const char* resource,
                                         protocol_state_e required_state,
                                         protocol_state_e next_state,
                                         uint8_t uuid_fill) {
  operation_t* op = operation_create(op_type);
  assert(op != NULL);
  memset(op->uuid, uuid_fill, CRABS_UUID_SIZE);
  strncpy(op->signer_id, signer, CRABS_MAX_USER_ID - 1);
  op->resources =
      (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], resource, CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = required_state;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = next_state;
  return op;
}

static void claim_live_token(operation_t* op, const data_item_t* item) {
  op->lock_claims = (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(op->lock_claims[0].resource, item->name, CRABS_MAX_USER_ID - 1);
  memcpy(op->lock_claims[0].lock_token, item->lock_state.lock_token,
         CRABS_LOCK_TOKEN_SIZE);
  op->lock_claim_count = 1;
}

int main(void) {
  ecdsa_keypair_t* admin_key = crypto_ecdsa_generate();
  assert(admin_key != NULL);
  recipe_machine = attribute_machine_create("admin", admin_key->public_key);
  assert(recipe_machine != NULL);
  /* The base state's attribute-machine back-pointer is attached by the
   * INTEGRATOR, not by attribute_machine_create. */
  recipe_machine->base_state.attr_machine = recipe_machine;
  state_t* ledger_state = &recipe_machine->base_state;

  ecdsa_keypair_t* alice_key = crypto_ecdsa_generate();
  ecdsa_keypair_t* bob_key = crypto_ecdsa_generate();
  assert(attribute_machine_register_user(recipe_machine, "alice",
                                         alice_key->public_key, NULL)
         == CRABS_SUCCESS);
  assert(attribute_machine_register_user(recipe_machine, "bob",
                                         bob_key->public_key, NULL)
         == CRABS_SUCCESS);
  assert(attribute_machine_grant_role(recipe_machine, "alice", "role",
                                      "member", "admin") == CRABS_SUCCESS);
  assert(attribute_machine_grant_role(recipe_machine, "bob", "role",
                                      "member", "admin") == CRABS_SUCCESS);

  /* --- the pot: a RESOURCE item — protocol state, lock owner/token/
   * expiry, and a pre-lock snapshot all live on the item. Value starts at
   * 1000 --- */
  data_item_t* treasury =
      data_item_create("treasury", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  assert(treasury != NULL);
  int64_t* treasury_balance = (int64_t*)malloc(sizeof(int64_t));
  *treasury_balance = 1000;
  treasury->value = treasury_balance;
  data_item_t* member_pot =
      data_item_create("member_pot", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  assert(member_pot != NULL);
  int64_t* member_balance = (int64_t*)malloc(sizeof(int64_t));
  *member_balance = 0;
  member_pot->value = member_balance;
  assert(state_add_item(ledger_state, treasury) == CRABS_SUCCESS);
  assert(state_add_item(ledger_state, member_pot) == CRABS_SUCCESS);

  assert(state_add_policy(ledger_state, CRABS_OP_LOCK, "role:member")
         == CRABS_SUCCESS);
  assert(state_add_policy(ledger_state, CRABS_OP_VERIFY, "role:member")
         == CRABS_SUCCESS);
  assert(state_add_policy(ledger_state, CRABS_OP_UNLOCK, "role:member")
         == CRABS_SUCCESS);
  assert(state_add_policy(ledger_state, "observe", "role:member")
         == CRABS_SUCCESS);
  assert(state_add_policy(ledger_state, "transfer", "role:member")
         == CRABS_SUCCESS);
  assert(state_machine_register_handler(ledger_state, "transfer",
                                        transfer_handler) == CRABS_SUCCESS);

  /* --- Demo A: exactly one holder of the live lease --- */
  operation_t* acquire = make_one_resource_op(CRABS_OP_LOCK, "alice",
                                              "treasury", PROTOCOL_IDLE,
                                              PROTOCOL_LOCKED, 0x42);
  op_sign_as(alice_key, acquire);
  assert(state_machine_execute(ledger_state, acquire) == CRABS_SUCCESS);
  operation_destroy(acquire);

  data_item_t* treasury_now = state_find_item(ledger_state, "treasury");
  assert(treasury_now->protocol_state == PROTOCOL_LOCKED);
  assert(treasury_now->lock_state.lock_token_valid);
  assert(strcmp(treasury_now->lock_state.lock_owner, "alice") == 0);

  /* Bob's competing `__lock__` while the lease is live: refused — the pot
   * is not re-acquirable until expiry or release. */
  operation_t* competing =
      make_one_resource_op(CRABS_OP_LOCK, "bob", "treasury", PROTOCOL_IDLE,
                           PROTOCOL_LOCKED, 0x43);
  op_sign_as(bob_key, competing);
  assert(state_machine_execute(ledger_state, competing)
         == CRABS_ERR_PROTOCOL_VIOLATION);
  operation_destroy(competing);
  assert(strcmp(treasury_now->lock_state.lock_owner, "alice") == 0);

  /* A custom op acting on the LOCKED pot is token-checked WHEN it claims
   * (step 5 verifies whichever claims the op presents) — a forged claim
   * (wrong bearer token) is refused before any effect. The executor does
   * not force an op to claim; the required_state gate is what the driver
   * itself declares. See the recipe page's atomicity discussion. */
  operation_t* forged_claimer = make_one_resource_op("observe", "alice",
                                                     "treasury",
                                                     PROTOCOL_LOCKED,
                                                     PROTOCOL_MODIFIED, 0x44);
  forged_claimer->lock_claims =
      (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(forged_claimer->lock_claims[0].resource, "treasury",
          CRABS_MAX_USER_ID - 1);
  memset(forged_claimer->lock_claims[0].lock_token, 0xFF, CRABS_LOCK_TOKEN_SIZE);
  forged_claimer->lock_claim_count = 1;
  op_sign_as(alice_key, forged_claimer);
  assert(state_machine_execute(ledger_state, forged_claimer)
         == CRABS_ERR_LOCK_TOKEN_MISMATCH);
  operation_destroy(forged_claimer);
  assert(treasury_now->protocol_state == PROTOCOL_LOCKED);

  /* The honest path: the wildcard apply advances LOCKED→MODIFIED for
   * handler-less custom ops (state_machine.c:1440-1464); presenting the
   * live bearer token with the claim is driver discipline the executor
   * verifies. */
  operation_t* adjust = make_one_resource_op("observe", "alice", "treasury",
                                             PROTOCOL_LOCKED,
                                             PROTOCOL_MODIFIED, 0x45);
  claim_live_token(adjust, treasury_now);
  op_sign_as(alice_key, adjust);
  assert(state_machine_execute(ledger_state, adjust) == CRABS_SUCCESS);
  operation_destroy(adjust);
  assert(treasury_now->protocol_state == PROTOCOL_MODIFIED);

  /* The verify/unlock tail of the ceremony (owner-checked). */
  operation_t* verify = make_one_resource_op(CRABS_OP_VERIFY, "alice",
                                             "treasury", PROTOCOL_MODIFIED,
                                             PROTOCOL_VERIFIED, 0x46);
  claim_live_token(verify, treasury_now);
  op_sign_as(alice_key, verify);
  assert(state_machine_execute(ledger_state, verify) == CRABS_SUCCESS);
  operation_destroy(verify);
  assert(treasury_now->protocol_state == PROTOCOL_VERIFIED);

  operation_t* release = make_one_resource_op(CRABS_OP_UNLOCK, "alice",
                                              "treasury", PROTOCOL_VERIFIED,
                                              PROTOCOL_IDLE, 0x47);
  claim_live_token(release, treasury_now);
  op_sign_as(alice_key, release);
  assert(state_machine_execute(ledger_state, release) == CRABS_SUCCESS);
  operation_destroy(release);
  assert(treasury_now->protocol_state == PROTOCOL_IDLE);
  assert(!treasury_now->lock_state.lock_token_valid);

  printf("treasury OK: single lease, forged claim refused, ceremony completes\n");

  /* --- Demo B: the debit/credit, applied exactly once --- */
  ledger_state->tx_manager = crabs_tx_manager_memory(64);
  assert(ledger_state->tx_manager != NULL);

  operation_t* first_transfer = operation_create("transfer");
  assert(first_transfer != NULL);
  memset(first_transfer->uuid, 0x55, CRABS_UUID_SIZE);
  strncpy(first_transfer->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  first_transfer->resources =
      (char(*)[CRABS_MAX_USER_ID])malloc(2 * sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(first_transfer->resources[0], "treasury", CRABS_MAX_USER_ID - 1);
  strncpy(first_transfer->resources[1], "member_pot", CRABS_MAX_USER_ID - 1);
  first_transfer->resource_count = 2;
  first_transfer->required_state =
      (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  first_transfer->required_state[0] = PROTOCOL_IDLE;
  first_transfer->required_state[1] = PROTOCOL_IDLE;
  first_transfer->next_state =
      (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  first_transfer->next_state[0] = PROTOCOL_IDLE;
  first_transfer->next_state[1] = PROTOCOL_IDLE;
  op_sign_as(alice_key, first_transfer);
  assert(state_machine_execute(ledger_state, first_transfer) == CRABS_SUCCESS);
  operation_destroy(first_transfer);
  assert(*treasury_balance == 900);
  assert(*member_balance == 100);

  /* A duplicate submission of the SAME uuid — a replayed transfer — is
   * recorded by the tx_manager and refused with ALREADY_EXECUTED. */
  operation_t* replayed_transfer = operation_create("transfer");
  assert(replayed_transfer != NULL);
  memset(replayed_transfer->uuid, 0x55, CRABS_UUID_SIZE);
  strncpy(replayed_transfer->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  replayed_transfer->resources =
      (char(*)[CRABS_MAX_USER_ID])malloc(2 * sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(replayed_transfer->resources[0], "treasury", CRABS_MAX_USER_ID - 1);
  strncpy(replayed_transfer->resources[1], "member_pot", CRABS_MAX_USER_ID - 1);
  replayed_transfer->resource_count = 2;
  replayed_transfer->required_state =
      (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  replayed_transfer->required_state[0] = PROTOCOL_IDLE;
  replayed_transfer->required_state[1] = PROTOCOL_IDLE;
  replayed_transfer->next_state =
      (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  replayed_transfer->next_state[0] = PROTOCOL_IDLE;
  replayed_transfer->next_state[1] = PROTOCOL_IDLE;
  op_sign_as(alice_key, replayed_transfer);
  assert(state_machine_execute(ledger_state, replayed_transfer)
         == CRABS_ERR_ALREADY_EXECUTED);
  operation_destroy(replayed_transfer);
  assert(*treasury_balance == 900);
  assert(*member_balance == 100);

  printf("treasury OK: debit/credit 900+100, duplicate submission refused\n");

  /* --- Demo C: all-or-nothing preconditions across named resources ---
   * One unknown item poisons the whole op: the transition check runs over
   * EVERY named resource before the handler, so nothing moves and nothing
   * is logged. */
  uint64_t log_count_before = ledger_state->log_count;
  operation_t* poisoned = operation_create("transfer");
  assert(poisoned != NULL);
  memset(poisoned->uuid, 0x66, CRABS_UUID_SIZE);
  strncpy(poisoned->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  poisoned->resources =
      (char(*)[CRABS_MAX_USER_ID])malloc(2 * sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(poisoned->resources[0], "treasury", CRABS_MAX_USER_ID - 1);
  strncpy(poisoned->resources[1], "ghost_treasury", CRABS_MAX_USER_ID - 1);
  poisoned->resource_count = 2;
  poisoned->required_state =
      (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  poisoned->required_state[0] = PROTOCOL_IDLE;
  poisoned->required_state[1] = PROTOCOL_IDLE;
  poisoned->next_state =
      (protocol_state_e*)malloc(2 * sizeof(protocol_state_e));
  poisoned->next_state[0] = PROTOCOL_IDLE;
  poisoned->next_state[1] = PROTOCOL_IDLE;
  op_sign_as(alice_key, poisoned);
  assert(state_machine_execute(ledger_state, poisoned)
         == CRABS_ERR_RESOURCE_NOT_FOUND);
  operation_destroy(poisoned);
  assert(*treasury_balance == 900);
  assert(*member_balance == 100);
  assert(ledger_state->log_count == log_count_before);

  printf("treasury OK: unknown poisons the op, no partial apply\n");

  /* state_t stores the manager as a void* (data_model.h:486) — the commit
   * records uuids the executor made; destroy frees the dedup memory. */
  ((crabs_tx_manager_t*)ledger_state->tx_manager)->vtable.destroy(
      (crabs_tx_manager_t*)ledger_state->tx_manager);
  ledger_state->tx_manager = NULL;
  attribute_machine_destroy(recipe_machine);
  crypto_ecdsa_keypair_destroy(alice_key);
  crypto_ecdsa_keypair_destroy(bob_key);
  crypto_ecdsa_keypair_destroy(admin_key);
  return 0;
}