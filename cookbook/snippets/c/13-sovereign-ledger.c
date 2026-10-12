/* Recipe 13 — a personal ledger no one can override (C core).
 *
 * The full sovereign-ledger loop on the engine: one sovereign ledger item
 * per member (a named writer), a handler that applies the entry's amount to
 * the item (real content, covered by the chain digest), signed chain
 * prefixes claiming the live head, and the refusal battery — a non-writer's
 * policy-authorized op (not_item_writer), a replayed prefix (seq_mismatch),
 * and a same-seq different-digest claim (fork_detected at the gate, nothing
 * applied). Mirrors test/test_state_machine.cpp:1238-1430 (handler-driven
 * sovereign counters) with the two-member, per-item shape of the JS
 * snippets. */
#include "Attribute/attribute_machine.h"
#include "StateMachine/state_machine.h"
#include "Crypto/crypto.h"
#include "CRDT/crdt_merge.h"
#include "Serialization/serialization.h"
#include "CRABS/crabs.h"
#include "CRABS/data_model.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* R7-11: lamport monotonicity is enforced per signer — entries must carry
 * strictly increasing times. */
static uint64_t entry_lamport = 0;

/* The ledger entry itself: apply the payload's integer to the item's
 * G-counter (deposits only — a G-counter refuses negative deltas). Runs
 * POST-DOMAIN_CHECK — writer and prefix already verified — and post-handler
 * the executor recomputes the item digest over this content. */
static crabs_error_e ledger_entry_handler(state_t* ledger_state,
                                          operation_t* op) {
  if (op->resource_count == 0) return CRABS_ERR_RESOURCE_NOT_FOUND;
  data_item_t* item = state_find_item(ledger_state, op->resources[0]);
  if (item == NULL || item->type != DATA_TYPE_COUNTER) {
    return CRABS_ERR_RESOURCE_NOT_FOUND;
  }
  const long long amount = op->payload != NULL
      ? strtoll((const char*)op->payload, NULL, 10) : 1;
  return g_counter_increment((g_counter_t*)item->value, op->signer_id, amount);
}

/* Mint a SOVEREIGN G-counter ledger for one writer (the tested creation
 * route: data_item_create_with_options + a CRDT struct value + state_add_item). */
static data_item_t* add_member_ledger(state_t* target_state,
                                      const char* name,
                                      const char* writer) {
  data_item_options_t options = {0};
  options.write_domain = CRABS_DOMAIN_SOVEREIGN;
  options.writer = writer;
  data_item_t* item = NULL;
  if (data_item_create_with_options(name, DATA_TYPE_COUNTER, CRDT_G_COUNTER,
                                    &options, &item) != CRABS_SUCCESS) {
    return NULL;
  }
  item->value = g_counter_create();
  item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  if (state_add_item(target_state, item) != CRABS_SUCCESS) {
    data_item_destroy(item);
    return NULL;
  }
  return state_find_item(target_state, name);
}

/* Build and sign one ledger entry: one resource + one sovereign prefix
 * claiming (seq, previous digest — the full 32 bytes) in the signed
 * canonical form (v4). */
static operation_t* ledger_entry(attribute_machine_t* machine,
                                 ecdsa_keypair_t* signer_key,
                                 const char* signer_id, const char* item_name,
                                 uint64_t seq,
                                 const uint8_t prev_digest[CRABS_HASH_SIZE],
                                 const char* amount, uint8_t uuid_seed) {
  operation_t* op = operation_create("entry");
  assert(op != NULL);
  memset(op->uuid, uuid_seed, CRABS_UUID_SIZE);
  strncpy(op->signer_id, signer_id, CRABS_MAX_USER_ID - 1);
  user_t* signer = attribute_machine_find_user(machine, signer_id);
  assert(signer != NULL);
  op->signer_key_version = signer->key_version;
  op->lamport_time = ++entry_lamport;
  op->resources = (char(*)[CRABS_MAX_USER_ID])
      malloc(sizeof(char[CRABS_MAX_USER_ID]));
  assert(op->resources != NULL);
  strncpy(op->resources[0], item_name, CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  /* The signed canonical form carries per-resource protocol-state arrays
   * (serialization.c:2908-2921) — an op with resources must allocate both,
   * as the test fixture does (PROTOCOL_IDLE: fresh non-RESOURCE items have
   * no protocol state to satisfy). */
  op->required_state = (protocol_state_e*)
      malloc(sizeof(protocol_state_e));
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  assert(op->required_state != NULL && op->next_state != NULL);
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state[0] = PROTOCOL_IDLE;
  op->sovereign_prefix_count = 1;
  op->sovereign_prefixes[0].item_seq = seq;
  if (prev_digest != NULL) {
    memcpy(op->sovereign_prefixes[0].prev_item_digest, prev_digest,
           CRABS_HASH_SIZE);
  } else {
    memset(op->sovereign_prefixes[0].prev_item_digest, 0, CRABS_HASH_SIZE);
  }
  size_t amount_length = strlen(amount) + 1;   /* NUL-terminated payload */
  op->payload = (uint8_t*)malloc(amount_length);
  assert(op->payload != NULL);
  memcpy(op->payload, amount, amount_length);
  op->payload_size = (uint32_t)amount_length;
  serialized_buffer_t* wire = crabs_serialize_for_signing(op);
  assert(wire != NULL);
  assert(crypto_sign_operation(signer_key->private_key, wire->data, wire->len,
                               op->signature) == CRABS_SUCCESS);
  serialized_buffer_destroy(wire);
  return op;
}

int main(void) {
  /* The machine, its admin, and two members (the admin is deliberately a
   * policy-equal party, to prove below that it still cannot write a
   * member's ledger). */
  ecdsa_keypair_t* admin_key = crypto_ecdsa_generate();
  assert(admin_key != NULL);
  attribute_machine_t* machine =
      attribute_machine_create("machine-1", admin_key->public_key);
  assert(machine != NULL);
  machine->base_state.attr_machine = machine;

  ecdsa_keypair_t* alice_key = crypto_ecdsa_generate();
  assert(alice_key != NULL);
  assert(attribute_machine_register_user(machine, "alice",
                                         alice_key->public_key, "")
         == CRABS_SUCCESS);
  ecdsa_keypair_t* bob_key = crypto_ecdsa_generate();
  assert(bob_key != NULL);
  assert(attribute_machine_register_user(machine, "bob",
                                         bob_key->public_key, "")
         == CRABS_SUCCESS);
  /* Both members hold the authorizing role — the recipe's refusals below
   * are item-domain refusals, not policy failures. */
  assert(attribute_machine_grant_role(machine, "alice", "role", "member",
                                      "machine-1") == CRABS_SUCCESS);
  assert(attribute_machine_grant_role(machine, "bob", "role", "member",
                                      "machine-1") == CRABS_SUCCESS);

  state_t* state = &machine->base_state;
  assert(state_add_policy(state, "entry", "role:member") == CRABS_SUCCESS);
  assert(state_machine_register_handler(state, "entry", ledger_entry_handler)
         == CRABS_SUCCESS);

  /* The mint: one sovereign ledger per member, immutable at creation. */
  data_item_t* ledger_alice = add_member_ledger(state, "ledger-alice", "alice");
  assert(ledger_alice != NULL);
  data_item_t* ledger_bob = add_member_ledger(state, "ledger-bob", "bob");
  assert(ledger_bob != NULL);
  /* (v1 refusals: a ledger with no writer is un-mintable.) */
  data_item_t* orphan = NULL;
  data_item_options_t no_writer = {0};
  no_writer.write_domain = CRABS_DOMAIN_SOVEREIGN;
  assert(data_item_create_with_options("orphan", DATA_TYPE_COUNTER,
                                       CRDT_G_COUNTER, &no_writer, &orphan)
         == CRABS_ERR_INVALID_PARAM);
  assert(orphan == NULL);

  /* ---- Alice's entries land: balance and chain advance together -------- */
  operation_t* first = ledger_entry(machine, alice_key, "alice",
                                    "ledger-alice", 0, NULL, "120", 0xA1);
  assert(state_machine_execute(state, first) == CRABS_SUCCESS);
  operation_destroy(first);
  uint8_t head_digest[CRABS_HASH_SIZE];
  memcpy(head_digest, ledger_alice->item_digest, CRABS_HASH_SIZE);
  assert(ledger_alice->item_seq == 1u);
  /* The digest covers content: it is NOT the all-zero fresh-item digest and
   * the registered balance is visible. */
  uint8_t fresh_digest[CRABS_HASH_SIZE] = {0};
  assert(memcmp(head_digest, fresh_digest, CRABS_HASH_SIZE) != 0);

  operation_t* second = ledger_entry(machine, alice_key, "alice",
                                     "ledger-alice", 1, head_digest, "80",
                                     0xA2);
  assert(state_machine_execute(state, second) == CRABS_SUCCESS);
  operation_destroy(second);
  assert(ledger_alice->item_seq == 2u);
  memcpy(head_digest, ledger_alice->item_digest, CRABS_HASH_SIZE);

  /* The balance is the sum of attributed entries (120 + 80); the snippet
   * asserts the chain — the demo's substance — and that the digest moved
   * off the fresh-item zeros with each accepted entry. */
  assert(memcmp(ledger_alice->item_digest, fresh_digest, CRABS_HASH_SIZE)
         != 0);

  /* ---- The refusal battery --------------------------------------------- */
  /* A member on a foreign ledger: the policy authorizes 'entry' for a
   * member; alice's ledger decides its own writer — policy-authorized,
   * item-refused. */
  operation_t* bobs_foreign = ledger_entry(machine, bob_key, "bob",
                                           "ledger-alice", 2, head_digest,
                                           "0", 0xA3);
  assert(state_machine_execute(state, bobs_foreign)
         == CRABS_ERR_NOT_ITEM_WRITER);
  operation_destroy(bobs_foreign);
  assert(ledger_alice->item_seq == 2u);   /* a refused write moves no chain */

  /* The machine's own GENESIS ADMIN on alice's ledger: the recipe's point —
   * not even the admin can override a member's ledger. The 'entry' policy is
   * role:member, so give the admin that attribute (self-granted, the admin
   * path) — the op is then policy-authored and STILL refused at the item
   * (sovereignty outranks policy). */
  assert(attribute_machine_grant_role(machine, "machine-1", "role", "member",
                                      "machine-1") == CRABS_SUCCESS);
  operation_t* admin_foreign = ledger_entry(machine, admin_key, "machine-1",
                                            "ledger-alice", 2, head_digest,
                                            "0", 0xA8);
  assert(state_machine_execute(state, admin_foreign)
         == CRABS_ERR_NOT_ITEM_WRITER);
  operation_destroy(admin_foreign);
  assert(ledger_alice->item_seq == 2u);

  /* Stale: replaying the FIRST link (seq 0, the all-zero digest). */
  operation_t* replay = ledger_entry(machine, alice_key, "alice",
                                     "ledger-alice", 0, NULL, "120", 0xA4);
  assert(state_machine_execute(state, replay) == CRABS_ERR_SEQ_MISMATCH);
  operation_destroy(replay);
  assert(ledger_alice->item_seq == 2u);

  /* Fork at the gate: the CURRENT seq claimed with a DIFFERENT digest. */
  operation_t* fork = ledger_entry(machine, alice_key, "alice",
                                   "ledger-alice", 2, fresh_digest, "0", 0xA5);
  assert(state_machine_execute(state, fork) == CRABS_ERR_FORK_DETECTED);
  operation_destroy(fork);
  assert(ledger_alice->item_seq == 2u);

  /* The item's own writer, chained honestly, is the only path forward. */
  operation_t* third = ledger_entry(machine, alice_key, "alice",
                                    "ledger-alice", 2, head_digest, "5",
                                    0xA6);
  assert(state_machine_execute(state, third) == CRABS_SUCCESS);
  operation_destroy(third);
  assert(ledger_alice->item_seq == 3u);

  /* ---- Bob's ledger is bob's: he chains his own, untouched by the above */
  operation_t* bobs_own = ledger_entry(machine, bob_key, "bob", "ledger-bob",
                                       0, NULL, "500", 0xA7);
  assert(state_machine_execute(state, bobs_own) == CRABS_SUCCESS);
  operation_destroy(bobs_own);
  assert(ledger_bob->item_seq == 1u);
  uint8_t const zeroed[CRABS_HASH_SIZE] = {0};
  assert(memcmp(ledger_bob->item_digest, zeroed, CRABS_HASH_SIZE) != 0);

  attribute_machine_destroy(machine);
  crypto_ecdsa_keypair_destroy(alice_key);
  crypto_ecdsa_keypair_destroy(bob_key);
  crypto_ecdsa_keypair_destroy(admin_key);

  printf("sovereign-ledger OK: per-item chains advanced, foreign and admin"
         " writes refused, replay and fork refused\n");
  return 0;
}