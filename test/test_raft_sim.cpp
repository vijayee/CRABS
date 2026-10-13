//
// Deterministic Raft simulation harness (raft-ordering plan, Phase 1).
//
// Harness v1 shape: N module instances in one process, each optionally
// attached to its own state machine, plus an in-memory "network" that routes
// drained outbound messages to peer instances. The host model scripts loss,
// duplication and reorder — the module idempotency story will lean on those
// knobs in Phase 2 (partitions, dropped/duplicated/reordered messages).
// v1 builds and exercises the full plumbing with ONE instance plus one
// scripted peer so the multi-instance Phase 2 scenarios drop straight in.
//

#include <gtest/gtest.h>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <vector>

extern "C" {
#include "Raft/raft_module.h"
#include "CRABS/data_model.h"
#include "StateMachine/state_machine.h"
#include "Serialization/serialization.h"
#include "CRDT/crdt_merge.h"
#include "Crypto/crypto.h"
#include "Util/allocator.h"
#include "test_helpers.h"
}

// ============================================================
// Harness network plumbing
// ============================================================

constexpr int kSimMaxNodes = CRABS_RAFT_MAX_PEERS;

typedef struct {
  uint32_t from_node;
  uint32_t to_node;
  std::vector<uint8_t> blob;
} sim_wire_message_t;

typedef struct {
  crabs_raft_module_t* module;
  state_t* state;   // NULL for pure-network peers (no pipeline attached)
  std::string node_id;
} sim_node_t;

// The "network": a scripted wire holding messages the model has routed but
// not yet (or not ever) delivered. Delivery order == vector order; the
// scripted fault helpers (drop/duplicate/reorder below) edit the wire
// between route and deliver.
typedef struct {
  sim_node_t nodes[kSimMaxNodes];
  uint32_t node_count;
  std::vector<sim_wire_message_t> wire;
  uint64_t now_ms;
} sim_host_t;

static sim_host_t sim_host_make() {
  sim_host_t host = {};   // pods zeroed; std::vector/string default-construct
  return host;
}

static void sim_host_destroy(sim_host_t* host) {
  for (uint32_t node_index = 0; node_index < host->node_count; node_index++) {
    if (host->nodes[node_index].module != nullptr) {
      crabs_raft_module_destroy(host->nodes[node_index].module);
      host->nodes[node_index].module = nullptr;
    }
    if (host->nodes[node_index].state != nullptr) {
      // States own no module pointers here (detached or never attached).
      state_destroy(host->nodes[node_index].state);
      host->nodes[node_index].state = nullptr;
    }
  }
  host->node_count = 0;
  host->wire.clear();
}

typedef void (*sim_state_setup_fn)(state_t* state);

// Attach a node: create module + optional state (test-env style: admin key,
// builtin policies). Returns the node index (0 on failure).
static uint32_t sim_attach_node(sim_host_t* host, const char* node_id,
                                uint64_t seed, sim_state_setup_fn setup_state) {
  if (host->node_count >= (uint32_t)kSimMaxNodes) {
    ADD_FAILURE() << "sim host full";
    return 0;
  }
  sim_node_t* node = &host->nodes[host->node_count];
  memset(node, 0, sizeof(*node));
  node->node_id = node_id;
  crabs_raft_config_t config;
  crabs_raft_config_defaults(&config);
  strncpy(config.node_id, node_id, CRABS_MAX_USER_ID - 1);
  config.seed = seed + host->now_ms;   // distinct streams per node
  node->module = crabs_raft_module_create(&config);
  EXPECT_NE(node->module, nullptr);
  if (setup_state != nullptr) {
    node->state = state_create();
    setup_state(node->state);
  }
  // (Cluster shapes beyond the per-node peer table are Phase 2: membership
  // change owns growing a running cluster; the wire plumbing here is ready.)
  host->node_count++;
  return host->node_count - 1;
}

// Route every drained outbound message onto the wire (addressed by the
// to_peer id).
static void sim_route_outbound(sim_host_t* host) {
  for (uint32_t node_index = 0; node_index < host->node_count; node_index++) {
    crabs_raft_outbound_message_t outbound;
    while (crabs_raft_module_poll_outbound(host->nodes[node_index].module,
                                           &outbound)) {
      sim_wire_message_t message;
      message.from_node = node_index;
      message.to_node = kSimMaxNodes;   // resolved at delivery
      message.blob.assign(outbound.bytes, outbound.bytes + outbound.len);
      for (uint32_t peer_index = 0; peer_index < host->node_count; peer_index++) {
        if (host->nodes[peer_index].node_id == outbound.to_peer) {
          message.to_node = peer_index;
          break;
        }
      }
      free((void*)outbound.bytes);
      host->wire.push_back(message);
    }
  }
}

// Deliver every wire message to its addressed node (in order).
static void sim_deliver_all(sim_host_t* host) {
  for (const sim_wire_message_t& message : host->wire) {
    ASSERT_LT(message.to_node, host->node_count);
    EXPECT_EQ(crabs_raft_module_inbound(host->nodes[message.to_node].module,
                                        host->nodes[message.from_node].node_id.c_str(),
                                        message.blob.data(), message.blob.size(),
                                        host->now_ms), CRABS_SUCCESS);
  }
  host->wire.clear();
}

// Scripted faults — the host models loss/duplication/reorder, the module
// must stay idempotent.
static void sim_wire_drop(sim_host_t* host, size_t index) {
  ASSERT_LT(index, host->wire.size());
  host->wire.erase(host->wire.begin() + (long)index);
}

static void sim_wire_duplicate(sim_host_t* host, size_t index) {
  ASSERT_LT(index, host->wire.size());
  host->wire.push_back(host->wire[index]);
}

static void sim_wire_reorder(sim_host_t* host, size_t index_a, size_t index_b) {
  ASSERT_LT(index_a, host->wire.size());
  ASSERT_LT(index_b, host->wire.size());
  sim_wire_message_t swapped = host->wire[index_a];
  host->wire[index_a] = host->wire[index_b];
  host->wire[index_b] = swapped;
}

// One simulated turn: tick every module at now_ms, route, (host script runs
// faults here), deliver, pump notifications through the pipeline.
static void sim_step(sim_host_t* host, uint64_t delta_ms) {
  host->now_ms += delta_ms;
  for (uint32_t node_index = 0; node_index < host->node_count; node_index++) {
    EXPECT_EQ(crabs_raft_module_tick(host->nodes[node_index].module, host->now_ms),
              CRABS_SUCCESS);
  }
  sim_route_outbound(host);
  sim_deliver_all(host);
  for (uint32_t node_index = 0; node_index < host->node_count; node_index++) {
    if (host->nodes[node_index].state != nullptr &&
        host->nodes[node_index].state->raft_module != nullptr) {
      EXPECT_EQ(state_raft_process_notifications(host->nodes[node_index].state),
                CRABS_SUCCESS);
    } else {
      // Pure-network peers drain notifications into the void (leader change
      // events are host concerns; committed events are consumed by their
      // own pipeline).
      crabs_raft_notification_t notification;
      while (crabs_raft_module_poll_notification(host->nodes[node_index].module,
                                                 &notification)) {
      }
    }
  }
}

// Run turns until a predicate holds (or fail after max_steps). Returns the
// number of turns taken (0 on immediate satisfaction).
static uint32_t sim_run_until(sim_host_t* host, uint64_t delta_ms,
                              uint32_t max_turns, bool (*predicate)(sim_host_t*)) {
  for (uint32_t turn = 0; turn < max_turns; turn++) {
    if (predicate(host)) return turn;
    sim_step(host, delta_ms);
  }
  EXPECT_TRUE(predicate(host)) << "sim_run_until exhausted after "
                               << max_turns << " turns";
  return max_turns;
}

static bool sim_node_is_leader(sim_host_t* host) {
  return crabs_raft_module_is_leader(host->nodes[0].module);
}

// ============================================================
// Harness v1 scenario: single-node degenerate cluster, full pipeline
// ============================================================

// A handler the pipeline test materializes through: replace "council"'s
// register value with the op payload (the GROUP_ORDERED write op).
static crabs_error_e sim_handler_council_write(state_t* state, operation_t* op) {
  if (op->resource_count == 0 || op->payload_size == 0) {
    return CRABS_ERR_INVALID_PARAM;
  }
  data_item_t* item = state_find_item(state, op->resources[0]);
  if (item == nullptr) return CRABS_ERR_RESOURCE_NOT_FOUND;
  lww_register_destroy((lww_register_t*)item->value);
  item->value = lww_register_create(op->payload, op->payload_size, 1, "nodeA");
  item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  return CRABS_SUCCESS;
}

static void sim_setup_council_state(state_t* state) {
  crabs_test_register_builtin_policies(state);
  state_add_policy(state, "council_write", "role:admin");
  ASSERT_EQ(state_machine_register_handler(state, "council_write",
                                           sim_handler_council_write),
            CRABS_SUCCESS);
  data_item_options_t options;
  memset(&options, 0, sizeof(options));
  options.write_domain = CRABS_DOMAIN_GROUP_ORDERED;
  data_item_t* item = nullptr;
  ASSERT_EQ(data_item_create_with_options("council", DATA_TYPE_REGISTER,
                                          CRDT_LWW_REG, &options, &item),
            CRABS_SUCCESS);
  item->value = lww_register_create((const uint8_t*)"origin", 6, 1, "nodeA");
  item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  ASSERT_EQ(state_add_item(state, item), CRABS_SUCCESS);
}

typedef struct {
  ecdsa_keypair_t* keypair;
  state_t* state;
  attribute_machine_t* attr_machine;   // externally owned like test env fixtures
  crabs_raft_module_t* module;
} sim_single_fixture_t;

static void sim_single_fixture_init(sim_single_fixture_t* fixture) {
  fixture->keypair = crypto_ecdsa_generate();
  fixture->state = state_create();
  sim_setup_council_state(fixture->state);
  fixture->attr_machine = attribute_machine_create(
      "admin", fixture->keypair->public_key);
  fixture->state->attr_machine = fixture->attr_machine;
  crabs_raft_config_t config;
  crabs_raft_config_defaults(&config);
  config.seed = 99;
  fixture->module = crabs_raft_module_create(&config);
  ASSERT_NE(fixture->module, nullptr);
  ASSERT_EQ(state_attach_raft_module(fixture->state, fixture->module),
            CRABS_SUCCESS);
}

static void sim_single_fixture_destroy(sim_single_fixture_t* fixture) {
  state_attach_raft_module(fixture->state, nullptr);
  crabs_raft_module_destroy(fixture->module);
  fixture->state->attr_machine = NULL;
  state_destroy(fixture->state);
  attribute_machine_destroy(fixture->attr_machine);
  crypto_ecdsa_keypair_destroy(fixture->keypair);
}

static operation_t* sim_signed_council_write(sim_single_fixture_t* fixture,
                                             const char* value) {
  operation_t* op = operation_create("council_write");
  EXPECT_NE(op, nullptr);
  if (op == nullptr) return nullptr;
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload_size = strlen(value);
  op->payload = (uint8_t*)get_memory(op->payload_size);
  memcpy(op->payload, value, op->payload_size);
  char(*resources)[CRABS_MAX_USER_ID] = (char(*)[CRABS_MAX_USER_ID])get_memory(
      sizeof(char) * CRABS_MAX_USER_ID);
  strncpy(resources[0], "council", CRABS_MAX_USER_ID - 1);
  op->resources = resources;
  op->resource_count = 1;
  // The signing preimage walks the resource slots — required/next state
  // arrays must match the count (state_machine test idiom).
  op->required_state = (protocol_state_e*)get_memory(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)get_memory(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_IDLE;
  crypto_random_bytes(op->uuid, CRABS_UUID_SIZE);   // fresh id per op
  crabs_test_sign_op_with(fixture->state->attr_machine, fixture->keypair, op);
  return op;
}

static void sim_stamp_council_write(sim_single_fixture_t* fixture,
                                    operation_t* op) {
  crabs_test_sign_op_with(fixture->state->attr_machine, fixture->keypair, op);
}

static const lww_register_t* sim_council_register(state_t* state) {
  data_item_t* item = state_find_item(state, "council");
  if (item == nullptr) return nullptr;
  return (const lww_register_t*)item->value;
}

TEST(RaftSimHarness, SubmitCommitsAndMaterializesThroughPipeline) {
  sim_single_fixture_t fixture;
  sim_single_fixture_init(&fixture);

  // Election: the degenerate node needs one scripted tick past its deadline.
  uint64_t deadline = crabs_raft_module_next_election_deadline(fixture.module);
  EXPECT_EQ(crabs_raft_module_tick(fixture.module, deadline), CRABS_SUCCESS);
  EXPECT_TRUE(crabs_raft_module_is_leader(fixture.module));

  // Submission: validated at the gate, routed as a pending proposal, NOT
  // executed. The item's content is untouched and nothing is durable yet.
  operation_t* op = sim_signed_council_write(&fixture, "decree-7");
  ASSERT_NE(op, nullptr);
  uint8_t submitted_uuid[CRABS_UUID_SIZE];
  memcpy(submitted_uuid, op->uuid, CRABS_UUID_SIZE);
  EXPECT_EQ(state_machine_execute(fixture.state, op),
            CRABS_ERR_ORDERING_PENDING);
  operation_destroy(op);

  EXPECT_TRUE(crabs_raft_module_is_leader(fixture.module));
  EXPECT_EQ(crabs_raft_module_log_length(fixture.module), 1u);
  EXPECT_EQ(crabs_raft_module_committed_tip(fixture.module), 0u);
  const raft_pending_proposal_t* pending =
      (const raft_pending_proposal_t*)fixture.state->raft_pending_proposals;
  ASSERT_NE(pending, nullptr);
  EXPECT_EQ(memcmp(pending->uuid, submitted_uuid, CRABS_UUID_SIZE), 0);
  EXPECT_GT(pending->op_len, 0u);
  const lww_register_t* before_commit = sim_council_register(fixture.state);
  ASSERT_NE(before_commit, nullptr);
  EXPECT_EQ(memcmp(before_commit->value, "origin", 6), 0);

  // Host storage loop: the persist request is stored anywhere durable and
  // acknowledged. NO commit counts before the ack.
  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(fixture.module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(fixture.module, persist.handle,
                                               true), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(fixture.module), 1u);

  // Notification pump: the committed op materializes — the group item now
  // carries the committed content and the machine log carries the op.
  EXPECT_EQ(state_raft_process_notifications(fixture.state), CRABS_SUCCESS);
  const lww_register_t* after_commit = sim_council_register(fixture.state);
  ASSERT_NE(after_commit, nullptr);
  EXPECT_EQ(memcmp(after_commit->value, "decree-7", 8), 0);
  bool committed_to_log = false;
  for (uint64_t log_index = 0; log_index < fixture.state->log_count;
       log_index++) {
    if (memcmp(fixture.state->log[log_index].uuid, submitted_uuid,
               CRABS_UUID_SIZE) == 0) {
      committed_to_log = true;
    }
  }
  EXPECT_TRUE(committed_to_log);
  // The pending proposal was consumed by the materialization.
  EXPECT_EQ(fixture.state->raft_pending_proposals, nullptr);

  // Idempotency: resubmitting the SAME op (same uuid) is an idempotent skip,
  // not a second proposal. The uuid rides the SIGNING preimage, so set it
  // before re-signing the duplicate.
  op = sim_signed_council_write(&fixture, "decree-7");
  ASSERT_NE(op, nullptr);
  memcpy(op->uuid, submitted_uuid, CRABS_UUID_SIZE);
  crabs_test_sign_op_with(fixture.state->attr_machine, fixture.keypair, op);
  EXPECT_EQ(state_machine_execute(fixture.state, op),
            CRABS_ERR_ALREADY_EXECUTED);
  operation_destroy(op);
  EXPECT_EQ(crabs_raft_module_log_length(fixture.module), 1u);

  sim_single_fixture_destroy(&fixture);
}

TEST(RaftSimHarness, WithoutModuleGroupWritesStayRejected) {
  sim_single_fixture_t fixture;
  sim_single_fixture_init(&fixture);
  // Detach: the no-module fail-closed seam — the exact v1 behavior.
  state_attach_raft_module(fixture.state, nullptr);

  operation_t* op = sim_signed_council_write(&fixture, "decree-8");
  ASSERT_NE(op, nullptr);
  EXPECT_EQ(state_machine_execute(fixture.state, op),
            CRABS_ERR_ORDERING_PATH);
  operation_destroy(op);
  const lww_register_t* value = sim_council_register(fixture.state);
  ASSERT_NE(value, nullptr);
  EXPECT_EQ(memcmp(value->value, "origin", 6), 0);
  EXPECT_EQ(fixture.state->raft_pending_proposals, nullptr);

  sim_single_fixture_destroy(&fixture);
}

TEST(RaftSimHarness, UnvalidatedProposalIsRefusedAtTheGate) {
  sim_single_fixture_t fixture;
  sim_single_fixture_init(&fixture);
  uint64_t deadline = crabs_raft_module_next_election_deadline(fixture.module);
  EXPECT_EQ(crabs_raft_module_tick(fixture.module, deadline), CRABS_SUCCESS);

  // An op with no valid signature / no policy satisfaction never reaches the
  // module: the submission gate rejects it BEFORE the propose routing.
  operation_t* op = operation_create("council_write");
  ASSERT_NE(op, nullptr);
  strncpy(op->signer_id, "nobody", CRABS_MAX_USER_ID - 1);   // no such user/key
  char(*resources)[CRABS_MAX_USER_ID] = (char(*)[CRABS_MAX_USER_ID])get_memory(
      sizeof(char) * CRABS_MAX_USER_ID);
  strncpy(resources[0], "council", CRABS_MAX_USER_ID - 1);
  op->resources = resources;
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)get_memory(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)get_memory(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_IDLE;
  op->payload_size = 4;
  op->payload = (uint8_t*)get_memory(4);
  memcpy(op->payload, "evil", 4);
  EXPECT_EQ(state_machine_execute(fixture.state, op), CRABS_ERR_UNAUTHORIZED);
  operation_destroy(op);
  EXPECT_EQ(crabs_raft_module_log_length(fixture.module), 0u);

  sim_single_fixture_destroy(&fixture);
}

// Restart script: commit → serialize the machine → recreate module + state →
// import the v16 section → commit CONTINUES (durability re-drives).
TEST(RaftSimHarness, RestartRoundTripContinuesCommitting) {
  sim_single_fixture_t fixture;
  sim_single_fixture_init(&fixture);
  uint64_t deadline = crabs_raft_module_next_election_deadline(fixture.module);
  EXPECT_EQ(crabs_raft_module_tick(fixture.module, deadline), CRABS_SUCCESS);

  operation_t* op = sim_signed_council_write(&fixture, "pre-restart");
  ASSERT_NE(op, nullptr);
  EXPECT_EQ(state_machine_execute(fixture.state, op), CRABS_ERR_ORDERING_PENDING);
  operation_destroy(op);
  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(fixture.module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(fixture.module, persist.handle,
                                               true), CRABS_SUCCESS);
  EXPECT_EQ(state_raft_process_notifications(fixture.state), CRABS_SUCCESS);
  const lww_register_t* registered = sim_council_register(fixture.state);
  ASSERT_NE(registered, nullptr);
  EXPECT_EQ(memcmp(registered->value, "pre-restart", 11), 0);
  EXPECT_EQ(crabs_raft_module_committed_tip(fixture.module), 1u);

  // Serialize the machine WITH the module attached; the v16 section carries
  // the module state out.
  serialized_buffer_t* blob = crabs_serialize_state(fixture.state);
  ASSERT_NE(blob, nullptr);

  // --- restart: object destroyed, only the blob + admin key survive ---
  ecdsa_keypair_t* surviving_admin_key = fixture.keypair;
  state_attach_raft_module(fixture.state, nullptr);
  crabs_raft_module_destroy(fixture.module);
  state_destroy(fixture.state);
  fixture.module = nullptr;
  fixture.state = nullptr;
  fixture.keypair = nullptr;

  state_t* restored_state = crabs_deserialize_state(blob->data, blob->len);
  serialized_buffer_destroy(blob);
  ASSERT_NE(restored_state, nullptr);
  crabs_raft_module_state_t* parsed =
      (crabs_raft_module_state_t*)restored_state->raft_module_state;
  ASSERT_NE(parsed, nullptr);
  EXPECT_EQ(parsed->commit_index, 1u);

  // Host re-creates the module object and imports the persisted state.
  crabs_raft_config_t config;
  crabs_raft_config_defaults(&config);
  config.seed = 99;
  crabs_raft_module_t* revived = crabs_raft_module_create(&config);
  ASSERT_NE(revived, nullptr);
  EXPECT_EQ(crabs_raft_module_import_state(revived, parsed), CRABS_SUCCESS);
  ASSERT_EQ(state_attach_raft_module(restored_state, revived), CRABS_SUCCESS);
  // Node-local handler registry is runtime-side: a real host re-registers
  // its handlers after restart; the pipeline reuses the same seam.
  EXPECT_EQ(state_machine_register_handler(restored_state, "council_write",
                                           sim_handler_council_write),
            CRABS_SUCCESS);
  // The revived node re-enters leadership before the next submission.
  uint64_t revived_deadline =
      crabs_raft_module_next_election_deadline(revived);
  EXPECT_EQ(crabs_raft_module_tick(revived, revived_deadline), CRABS_SUCCESS);
  EXPECT_TRUE(crabs_raft_module_is_leader(revived));

  // The group item's committed content survived the restart on its own.
  const lww_register_t* carried = nullptr;
  for (const data_item_t* item = restored_state->items; item != nullptr;
       item = item->next) {
    if (strcmp(item->name, "council") == 0) {
      carried = (const lww_register_t*)item->value;
      break;
    }
  }
  ASSERT_NE(carried, nullptr);
  EXPECT_EQ(memcmp(carried->value, "pre-restart", 11), 0);

  // Committing CONTINUES: a new submission rides index 2. The op verifies
  // against the RESTORED registry (the original admin key persists in the
  // attribute machine's user section).
  operation_t* post_op = operation_create("council_write");
  ASSERT_NE(post_op, nullptr);
  strncpy(post_op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  post_op->payload_size = 12;
  post_op->payload = (uint8_t*)get_memory(post_op->payload_size);
  memcpy(post_op->payload, "post-restart", post_op->payload_size);
  char(*resources)[CRABS_MAX_USER_ID] = (char(*)[CRABS_MAX_USER_ID])get_memory(
      sizeof(char) * CRABS_MAX_USER_ID);
  strncpy(resources[0], "council", CRABS_MAX_USER_ID - 1);
  post_op->resources = resources;
  post_op->resource_count = 1;
  post_op->required_state = (protocol_state_e*)get_memory(sizeof(protocol_state_e));
  post_op->required_state[0] = PROTOCOL_IDLE;
  post_op->next_state = (protocol_state_e*)get_memory(sizeof(protocol_state_e));
  post_op->next_state[0] = PROTOCOL_IDLE;
  crypto_random_bytes(post_op->uuid, CRABS_UUID_SIZE);
  crabs_test_sign_op_with(restored_state->attr_machine, surviving_admin_key, post_op);
  EXPECT_EQ(state_machine_execute(restored_state, post_op),
            CRABS_ERR_ORDERING_PENDING);
  operation_destroy(post_op);
  crabs_raft_persist_request_t restart_persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(revived, &restart_persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(revived, restart_persist.handle,
                                               true), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(revived), 2u);
  EXPECT_EQ(state_raft_process_notifications(restored_state), CRABS_SUCCESS);
  const lww_register_t* post_value =
      (const lww_register_t*)state_find_item(restored_state, "council")->value;
  ASSERT_NE(post_value, nullptr);
  EXPECT_EQ(memcmp(post_value->value, "post-restart", 12), 0);

  state_attach_raft_module(restored_state, nullptr);
  crabs_raft_module_destroy(revived);
  state_destroy(restored_state);
  crypto_ecdsa_keypair_destroy(surviving_admin_key);
}

// ============================================================
// Harness plumbing (Phase 2 readiness): routing + scripted faults across
// two real module instances. The Phase 2 partition/loss/dup scenarios build
// directly on sim_wire_* and sim_run_until.
// ============================================================
static bool sim_pred_alpha_elected(sim_host_t* host) {
  return crabs_raft_module_current_term(host->nodes[0].module) >= 1;
}

TEST(RaftSimHarness, NetworkPlumbingRoutesFaultsAndDelivers) {
  sim_host_t host = sim_host_make();
  // A mutual two-node cluster: both modules carry both peer ids.
  crabs_raft_config_t config_a;
  crabs_raft_config_defaults(&config_a);
  strncpy(config_a.node_id, "alpha", CRABS_MAX_USER_ID - 1);
  strncpy(config_a.peer_ids[0], "alpha", CRABS_MAX_USER_ID - 1);
  strncpy(config_a.peer_ids[1], "beta", CRABS_MAX_USER_ID - 1);
  config_a.peer_count = 2;
  config_a.seed = 11;
  crabs_raft_config_t config_b;
  crabs_raft_config_defaults(&config_b);
  strncpy(config_b.node_id, "beta", CRABS_MAX_USER_ID - 1);
  strncpy(config_b.peer_ids[0], "beta", CRABS_MAX_USER_ID - 1);
  strncpy(config_b.peer_ids[1], "alpha", CRABS_MAX_USER_ID - 1);
  config_b.peer_count = 2;
  config_b.seed = 22;
  host.nodes[0].node_id = "alpha";
  host.nodes[0].module = crabs_raft_module_create(&config_a);
  ASSERT_NE(host.nodes[0].module, nullptr);
  host.nodes[1].node_id = "beta";
  host.nodes[1].module = crabs_raft_module_create(&config_b);
  ASSERT_NE(host.nodes[1].module, nullptr);
  host.node_count = 2;

  // Scripted ticks elect alpha to candidacy (sim_run_until drives turn-based
  // ticks through routing and delivery).
  uint32_t turns = sim_run_until(&host, 100, 20, sim_pred_alpha_elected);
  ASSERT_LT(turns, 20u);
  // A fresh re-election tick re-solicits the peer: the wire holds a live
  // message we can fault and deliver.
  EXPECT_EQ(crabs_raft_module_tick(host.nodes[0].module, host.now_ms + 10000),
            CRABS_SUCCESS);
  sim_route_outbound(&host);
  ASSERT_FALSE(host.wire.empty());
  EXPECT_EQ(host.wire[0].from_node, 0u);
  EXPECT_GE(host.wire.size(), 1u);
  EXPECT_EQ(host.wire[0].to_node, 1u);

  // Fault script: DUPLICATE the first solicitation and REORDER the copies.
  sim_wire_duplicate(&host, 0);
  sim_wire_reorder(&host, 0, 1);
  sim_deliver_all(&host);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(host.nodes[1].module), 0u);
  // The duplicate carried the re-election term: beta absorbs it idempotently.
  EXPECT_EQ(crabs_raft_module_current_term(host.nodes[1].module), 2u);

  // Beta's duplicate vote responses flow back to the candidate and are
  // absorbed idempotently (no tally side effects in P1, no corruption in P2
  // once tallies land).
  sim_route_outbound(&host);
  ASSERT_GE(host.wire.size(), 1u);
  sim_deliver_all(&host);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(host.nodes[0].module), 0u);
  EXPECT_TRUE(host.wire.empty());

  sim_host_destroy(&host);
}