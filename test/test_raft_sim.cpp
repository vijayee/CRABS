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
  ecdsa_keypair_t* keypair;          // externally owned per-node signing key
  attribute_machine_t* attr_machine; // externally owned per-node authority
  uint32_t partition_group;          // 0 = connected to everyone (full mesh)
  bool auto_persist;                 // host storage answers persist requests
} sim_node_t;

// The "network": a scripted wire holding messages the model has routed but
// not yet (or not ever) delivered. Delivery order == vector order; the
// scripted fault helpers (drop/duplicate/reorder below) edit the wire
// between route and deliver. The partition model is per-node group ids:
// two nodes deliver to each other only while group ids match or either is
// 0 (ungrouped).
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
    if (host->nodes[node_index].state != nullptr &&
        host->nodes[node_index].state->raft_module != nullptr) {
      state_attach_raft_module(host->nodes[node_index].state, nullptr);
    }
    if (host->nodes[node_index].module != nullptr) {
      crabs_raft_module_destroy(host->nodes[node_index].module);
      host->nodes[node_index].module = nullptr;
    }
    if (host->nodes[node_index].attr_machine != nullptr) {
      attribute_machine_destroy(host->nodes[node_index].attr_machine);
      host->nodes[node_index].attr_machine = nullptr;
    }
    if (host->nodes[node_index].keypair != nullptr) {
      crypto_ecdsa_keypair_destroy(host->nodes[node_index].keypair);
      host->nodes[node_index].keypair = nullptr;
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

// Defined in the scenario section below; the cluster attach calls it for
// every node's base state (before the caller's extras).
static void sim_setup_council_state(state_t* state);

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
  node->auto_persist = true;
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

// ============================================================
// Cluster harness (Phase 2): a mutual 3-node cluster (alpha/beta/gamma),
// each node carrying its own keypair + attached state (council item +
// handler + authority) so elections, replication, partitions and
// follower-side materialization run end to end in-process.
// ============================================================

static const char* kSimClusterIds[3] = {"alpha", "beta", "gamma"};
static const uint64_t kSimClusterSeeds[3] = {11, 22, 33};

// Partition predicate: two connected nodes deliver; group 0 = ungrouped
// (connected to everyone).
static bool sim_connected(const sim_host_t* host, uint32_t from, uint32_t to) {
  if (from >= host->node_count || to >= host->node_count) return false;
  uint32_t group_from = host->nodes[from].partition_group;
  uint32_t group_to = host->nodes[to].partition_group;
  return group_from == 0 || group_to == 0 || group_from == group_to;
}

// Attach the whole cluster. Extra state setup runs after the council base
// (tests add domain items there).
typedef void (*sim_extra_setup_fn)(state_t* state);

static void sim_cluster_attach(sim_host_t* host, sim_extra_setup_fn extra_setup) {
  ASSERT_EQ(host->node_count, 0u);
  for (uint32_t node_slot = 0; node_slot < 3; node_slot++) {
    sim_node_t* node = &host->nodes[node_slot];
    memset(node, 0, sizeof(*node));
    node->node_id = kSimClusterIds[node_slot];
    node->partition_group = 0;
    node->auto_persist = true;
    node->keypair = crypto_ecdsa_generate();
    ASSERT_NE(node->keypair, nullptr);
    node->state = state_create();
    sim_setup_council_state(node->state);
    node->attr_machine = attribute_machine_create("admin",
                                                  node->keypair->public_key);
    ASSERT_NE(node->attr_machine, nullptr);
    node->state->attr_machine = node->attr_machine;
    if (extra_setup != nullptr) {
      extra_setup(node->state);
    }
    crabs_raft_config_t config;
    crabs_raft_config_defaults(&config);
    strncpy(config.node_id, kSimClusterIds[node_slot], CRABS_MAX_USER_ID - 1);
    for (uint32_t member_slot = 0; member_slot < 3; member_slot++) {
      strncpy(config.peer_ids[member_slot], kSimClusterIds[member_slot],
              CRABS_MAX_USER_ID - 1);
    }
    config.peer_count = 3;
    config.seed = kSimClusterSeeds[node_slot];
    node->module = crabs_raft_module_create(&config);
    ASSERT_NE(node->module, nullptr);
    ASSERT_EQ(state_attach_raft_module(node->state, node->module),
              CRABS_SUCCESS);
    host->node_count = node_slot + 1;
  }
  host->node_count = 3;
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

// Deliver every wire message its partition permits (in order). A partitioned
// message stays ON the wire (the script may heal and re-deliver it, or drop
// it explicitly) — this models lossy, eventually-healing links.
static void sim_deliver_all(sim_host_t* host) {
  std::vector<sim_wire_message_t> undelivered;
  for (const sim_wire_message_t& message : host->wire) {
    ASSERT_LT(message.from_node, host->node_count);
    if (!sim_connected(host, message.from_node, message.to_node)) {
      undelivered.push_back(message);
      continue;
    }
    EXPECT_EQ(crabs_raft_module_inbound(host->nodes[message.to_node].module,
                                        host->nodes[message.from_node].node_id.c_str(),
                                        message.blob.data(), message.blob.size(),
                                        host->now_ms), CRABS_SUCCESS);
  }
  host->wire = undelivered;
}

// Route any drained outbound messages to the wire (the deliver loop calls
// this between delivery rounds — replies ride the same turn).
static void sim_route_after_delivery(sim_host_t* host) {
  sim_route_outbound(host);
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

// Host storage model: every node whose auto_persist is on answers its
// outstanding persist window immediately (durable). A FALSE node holds the
// window (slow-persist scenario): the request stays polled-but-unacked.
static void sim_pump_persist(sim_host_t* host) {
  for (uint32_t node_index = 0; node_index < host->node_count; node_index++) {
    if (!host->nodes[node_index].auto_persist) continue;
    crabs_raft_persist_request_t persist;
    if (crabs_raft_module_poll_persist(host->nodes[node_index].module,
                                       &persist)) {
      EXPECT_EQ(crabs_raft_module_persist_complete(
                    host->nodes[node_index].module, persist.handle, true),
                CRABS_SUCCESS);
    }
  }
}

// Notification pump: attached states materialize through the pipeline; bare
// nodes drain leadership events into the void (host concerns). Counting
// pump mode records COMMITTED_OP deliveries per node for the dedup
// assertions (exactly-once materialization).
typedef struct {
  uint32_t committed_count[kSimMaxNodes];
} sim_delivery_tally_t;

static void sim_pump_notifications(sim_host_t* host, sim_delivery_tally_t* tally) {
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
        if (tally != NULL && notification.kind == RAFT_NOTIFY_COMMITTED_OP) {
          tally->committed_count[node_index]++;
        }
      }
    }
  }
}

// Deliver + route until the wire settles (replies ride the same turn); the
// round bound keeps a hypothetical message storm from looping forever.
static void sim_settle_wire(sim_host_t* host) {
  for (uint32_t round = 0; round < 32 && !host->wire.empty(); round++) {
    sim_deliver_all(host);
    sim_route_after_delivery(host);
  }
}

// One simulated turn: tick every module at now_ms, pump the host storage
// model, route, run the optional fault script, deliver, pump notifications.
static void sim_step(sim_host_t* host, uint64_t delta_ms,
                     sim_delivery_tally_t* tally) {
  host->now_ms += delta_ms;
  for (uint32_t node_index = 0; node_index < host->node_count; node_index++) {
    EXPECT_EQ(crabs_raft_module_tick(host->nodes[node_index].module, host->now_ms),
              CRABS_SUCCESS);
  }
  sim_pump_persist(host);
  sim_route_outbound(host);
  sim_settle_wire(host);
  sim_pump_notifications(host, tally);
}

// Run turns until a predicate holds (or fail after max_steps). Returns the
// number of turns taken (0 on immediate satisfaction).
static uint32_t sim_run_until(sim_host_t* host, uint64_t delta_ms,
                              uint32_t max_turns, bool (*predicate)(sim_host_t*)) {
  for (uint32_t turn = 0; turn < max_turns; turn++) {
    if (predicate(host)) return turn;
    sim_step(host, delta_ms, nullptr);
  }
  EXPECT_TRUE(predicate(host)) << "sim_run_until exhausted after "
                               << max_turns << " turns";
  return max_turns;
}

// ============================================================
// Cluster query helpers
// ============================================================
static uint32_t sim_leader_count(sim_host_t* host) {
  uint32_t leaders = 0;
  for (uint32_t node_index = 0; node_index < host->node_count; node_index++) {
    if (crabs_raft_module_is_leader(host->nodes[node_index].module)) {
      leaders++;
    }
  }
  return leaders;
}

static int sim_find_leader(sim_host_t* host) {
  for (uint32_t node_index = 0; node_index < host->node_count; node_index++) {
    if (crabs_raft_module_is_leader(host->nodes[node_index].module)) {
      return (int)node_index;
    }
  }
  return -1;
}

static bool sim_pred_any_leader(sim_host_t* host) {
  return sim_leader_count(host) == 1;
}

// How many state-log entries carry the given op uuid (materialization
// dedup check: exactly once per replica).
static uint32_t sim_state_uuid_occurrences(const state_t* state,
                                           const uint8_t* uuid) {
  uint32_t count = 0;
  for (uint64_t log_index = 0; log_index < state->log_count; log_index++) {
    if (memcmp(state->log[log_index].uuid, uuid, CRABS_UUID_SIZE) == 0) {
      count++;
    }
  }
  return count;
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

// Generic signed write op for a registered op type / named resource — the
// shape every scenario op shares (single resource slot, IDLE transition,
// fresh uuid, signed by the node's own authority).
static operation_t* sim_build_write_op(state_t* state, ecdsa_keypair_t* keypair,
                                       const char* op_type, const char* resource,
                                       const char* value, bool sovereign) {
  operation_t* op = operation_create(op_type);
  EXPECT_NE(op, nullptr);
  if (op == nullptr) return nullptr;
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  op->payload_size = strlen(value);
  op->payload = (uint8_t*)get_memory(op->payload_size);
  memcpy(op->payload, value, op->payload_size);
  char(*resources)[CRABS_MAX_USER_ID] = (char(*)[CRABS_MAX_USER_ID])get_memory(
      sizeof(char) * CRABS_MAX_USER_ID);
  strncpy(resources[0], resource, CRABS_MAX_USER_ID - 1);
  op->resources = resources;
  op->resource_count = 1;
  // The signing preimage walks the resource slots — required/next state
  // arrays must match the count (state_machine test idiom).
  op->required_state = (protocol_state_e*)get_memory(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)get_memory(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_IDLE;
  crypto_random_bytes(op->uuid, CRABS_UUID_SIZE);   // fresh id per op
  // SOVEREIGN ops bind the writer's chain head (seq + prev digest) into the
  // signed preimage — a fresh item is (seq 0, zero digest).
  if (sovereign) {
    op->sovereign_prefix_count = 1;
    op->sovereign_prefixes[0].item_seq = 0;
    memset(op->sovereign_prefixes[0].prev_item_digest, 0, CRABS_HASH_SIZE);
  }
  crabs_test_sign_op_with(state->attr_machine, keypair, op);
  return op;
}

static operation_t* sim_signed_council_write(sim_single_fixture_t* fixture,
                                             const char* value) {
  return sim_build_write_op(fixture->state, fixture->keypair, "council_write",
                            "council", value, false);
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

// ============================================================
// Phase 2 scenarios (the plan's heart): elections, split votes, partitions,
// message faults, slow persistence, restart resume — all scripted, all
// deterministic.
// ============================================================

// Submit a signed write for `resource` against node `node_index`'s own
// authority. Returns the executor's code; the op's uuid is copied out when
// requested (for dedup/exactly-once assertions).
// Submit a signed write for `resource` against node `node_index`'s own
// authority. Returns the executor's code; the op's uuid is copied out when
// requested (for dedup/exactly-once assertions).
static crabs_error_e sim_submit_write(sim_host_t* host, uint32_t node_index,
                                      const char* op_type, const char* resource,
                                      const char* value, uint8_t* uuid_out) {
  EXPECT_LT(node_index, host->node_count);
  if (node_index >= host->node_count) return CRABS_ERR_INVALID_PARAM;
  sim_node_t* node = &host->nodes[node_index];
  operation_t* op = sim_build_write_op(node->state, node->keypair, op_type,
                                       resource, value,
                                       strcmp(op_type, "sovereign_write") == 0);
  EXPECT_NE(op, nullptr);
  if (op == nullptr) return CRABS_ERR_SERIALIZATION_ERROR;
  crabs_error_e rc = state_machine_execute(node->state, op);
  if (uuid_out != nullptr) {
    memcpy(uuid_out, op->uuid, CRABS_UUID_SIZE);
  }
  operation_destroy(op);
  return rc;
}

// A fault-scripted turn: ticks, persist pump, route, RUN THE FAULTS on the
// wire, then settle/ack/pump (the second persist pump + round covers the
// responses the delivery created in this same turn).
typedef void (*sim_fault_fn)(sim_host_t* host);

static void sim_step_faulted(sim_host_t* host, uint64_t delta_ms,
                             sim_fault_fn faults) {
  host->now_ms += delta_ms;
  for (uint32_t node_index = 0; node_index < host->node_count; node_index++) {
    EXPECT_EQ(crabs_raft_module_tick(host->nodes[node_index].module, host->now_ms),
              CRABS_SUCCESS);
  }
  sim_pump_persist(host);
  sim_route_outbound(host);
  if (faults != nullptr) {
    faults(host);
  }
  sim_settle_wire(host);
  sim_pump_persist(host);
  sim_route_outbound(host);
  sim_settle_wire(host);
  sim_pump_notifications(host, nullptr);
}

// Hand-crafted v16 module-section snapshot (term, committed tip, entry
// terms) — lets tests install an ARBITRARY durable module history without
// running elections: the up-to-dateness unit test keys on it. Caller
// destroys with crabs_raft_module_state_destroy.
static crabs_raft_module_state_t* sim_snapshot_make(uint64_t term,
                                                    uint32_t entry_count,
                                                    const uint64_t* entry_terms) {
  crabs_raft_module_state_t* snapshot =
      (crabs_raft_module_state_t*)get_clear_memory(
          sizeof(crabs_raft_module_state_t));
  snapshot->module_id = 0;
  snapshot->term = term;
  snapshot->commit_index = entry_count;
  snapshot->log_count = entry_count;
  crabs_raft_entry_persisted_t** tail = &snapshot->log;
  for (uint32_t entry_index = 0; entry_index < entry_count; entry_index++) {
    crabs_raft_entry_persisted_t* entry =
        (crabs_raft_entry_persisted_t*)get_clear_memory(
            sizeof(crabs_raft_entry_persisted_t));
    entry->term = entry_terms[entry_index];
    entry->proposal_id = entry_index + 1;
    entry->op_wire = (uint8_t*)get_memory(1);
    entry->op_wire[0] = 'z';
    entry->wire_len = 1;
    *tail = entry;
    tail = &entry->next;
  }
  return snapshot;
}

// Tip predicate for sim_run_until: every module committed exactly the
// target tip (set sim_target_tip before passing the predicate).
static uint32_t sim_target_tip = 0;

static bool sim_pred_target_tips(sim_host_t* host) {
  for (uint32_t node_index = 0; node_index < host->node_count; node_index++) {
    if (crabs_raft_module_committed_tip(host->nodes[node_index].module) !=
        sim_target_tip) {
      return false;
    }
  }
  return true;
}

TEST(RaftSimHarness, ThreeNodeClusterElectsExactlyOneLeader) {
  sim_host_t host = sim_host_make();
  sim_cluster_attach(&host, nullptr);

  // Randomized (seeded) election timeouts resolve 3 nodes to ONE leader.
  sim_run_until(&host, 100, 40, sim_pred_any_leader);
  EXPECT_EQ(sim_leader_count(&host), 1u);
  int leader_index = sim_find_leader(&host);
  ASSERT_GE(leader_index, 0);
  uint64_t leader_term =
      crabs_raft_module_current_term(host.nodes[leader_index].module);
  EXPECT_GE(leader_term, 1u);
  // Every follower converged onto the leader's term (heartbeats).
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    EXPECT_EQ(crabs_raft_module_current_term(host.nodes[node_index].module),
              leader_term);
  }
  // No proposals yet: empty logs everywhere, zero commits, clean wire.
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    EXPECT_EQ(crabs_raft_module_log_length(host.nodes[node_index].module), 0u);
    EXPECT_EQ(crabs_raft_module_committed_tip(host.nodes[node_index].module), 0u);
    EXPECT_EQ(crabs_raft_module_rejected_message_count(
                  host.nodes[node_index].module), 0u);
  }

  sim_host_destroy(&host);
}

TEST(RaftSimHarness, SplitVoteResolvesThroughReelection) {
  sim_host_t host = sim_host_make();
  sim_cluster_attach(&host, nullptr);

  // Scripted three-way split: all three hit their own (seeded) election
  // deadline in the same instant, BEFORE any vote traffic flows — each is a
  // term-1 candidate with a self-vote, so they refuse one another.
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    uint64_t deadline =
        crabs_raft_module_next_election_deadline(host.nodes[node_index].module);
    EXPECT_EQ(crabs_raft_module_tick(host.nodes[node_index].module, deadline),
              CRABS_SUCCESS);
  }
  sim_route_outbound(&host);
  sim_settle_wire(&host);
  EXPECT_EQ(sim_leader_count(&host), 0u);
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    EXPECT_EQ(crabs_raft_module_current_term(host.nodes[node_index].module), 1u);
  }

  // The randomized retry deadlines de-synchronize the next terms: eventually
  // ONE candidate collects a quorum and the split resolves upward.
  sim_run_until(&host, 100, 60, sim_pred_any_leader);
  EXPECT_EQ(sim_leader_count(&host), 1u);
  int leader_index = sim_find_leader(&host);
  ASSERT_GE(leader_index, 0);
  EXPECT_GT(crabs_raft_module_current_term(host.nodes[leader_index].module), 1u);

  sim_host_destroy(&host);
}

TEST(RaftSimHarness, MajorityRefusesOutOfDateCandidate) {
  // The up-to-dateness check (carried item 2) at unit scale: a candidate
  // with a SHORTER log tail is refused even from a newer term — committed
  // history can never fall behind whoever gets elected.
  sim_host_t host = sim_host_make();

  crabs_raft_config_t config_a;
  crabs_raft_config_defaults(&config_a);
  strncpy(config_a.node_id, "upsilon", CRABS_MAX_USER_ID - 1);
  strncpy(config_a.peer_ids[0], "upsilon", CRABS_MAX_USER_ID - 1);
  strncpy(config_a.peer_ids[1], "phi", CRABS_MAX_USER_ID - 1);
  config_a.peer_count = 2;
  config_a.seed = 7;
  crabs_raft_config_t config_b = config_a;
  strncpy(config_b.node_id, "phi", CRABS_MAX_USER_ID - 1);
  strncpy(config_b.peer_ids[0], "phi", CRABS_MAX_USER_ID - 1);
  strncpy(config_b.peer_ids[1], "upsilon", CRABS_MAX_USER_ID - 1);
  config_b.peer_count = 2;
  config_b.seed = 8;
  host.nodes[0].node_id = "upsilon";
  host.nodes[0].module = crabs_raft_module_create(&config_a);
  ASSERT_NE(host.nodes[0].module, nullptr);
  host.nodes[1].node_id = "phi";
  host.nodes[1].module = crabs_raft_module_create(&config_b);
  ASSERT_NE(host.nodes[1].module, nullptr);
  host.node_count = 2;

  // Hand-crafted v16 snapshots: phi carries TWO entries (tail term 6), so a
  // term-7 candidate whose tail is (term 5, index 1) is refused on the TERM
  // branch of the up-to-dateness check first…
  uint64_t terms_a[1] = {5};
  uint64_t terms_b[2] = {5, 6};
  crabs_raft_module_state_t* snapshot_a = sim_snapshot_make(5, 1, terms_a);
  crabs_raft_module_state_t* snapshot_b = sim_snapshot_make(5, 2, terms_b);
  ASSERT_NE(snapshot_a, nullptr);
  ASSERT_NE(snapshot_b, nullptr);
  EXPECT_EQ(crabs_raft_module_import_state(host.nodes[0].module, snapshot_a),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_import_state(host.nodes[1].module, snapshot_b),
            CRABS_SUCCESS);
  crabs_raft_module_state_destroy(snapshot_a);
  crabs_raft_module_state_destroy(snapshot_b);

  // …then the EQUAL-term branch: re-import upsilon to tail (term 7, index
  // 1) against phi's (term 7, index 2) — still refused, on the INDEX branch.
  uint64_t terms_short[1] = {7};
  crabs_raft_module_state_t* snapshot_a2 =
      sim_snapshot_make(6, 1, terms_short);
  uint64_t terms_long[2] = {7, 7};
  crabs_raft_module_state_t* snapshot_b2 =
      sim_snapshot_make(6, 2, terms_long);
  ASSERT_NE(snapshot_a2, nullptr);
  ASSERT_NE(snapshot_b2, nullptr);
  EXPECT_EQ(crabs_raft_module_import_state(host.nodes[0].module, snapshot_a2),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_import_state(host.nodes[1].module, snapshot_b2),
            CRABS_SUCCESS);
  crabs_raft_module_state_destroy(snapshot_a2);
  crabs_raft_module_state_destroy(snapshot_b2);

  // Upsilon hits its deadline → term-7 candidacy soliciting phi.
  crabs_raft_module_t* upsilon = host.nodes[0].module;
  EXPECT_EQ(crabs_raft_module_tick(
                upsilon, crabs_raft_module_next_election_deadline(upsilon)),
            CRABS_SUCCESS);
  sim_route_outbound(&host);
  sim_deliver_all(&host);
  sim_route_outbound(&host);
  sim_deliver_all(&host);

  // No quorum for the out-of-date candidate: phi acknowledged nothing that
  // promotes upsilon — NO member is leader, phi absorbed the request's term.
  EXPECT_EQ(sim_leader_count(&host), 0u);
  EXPECT_EQ(crabs_raft_module_current_term(host.nodes[1].module), 7u);
  EXPECT_GE(crabs_raft_module_current_term(upsilon), 7u);
  EXPECT_FALSE(crabs_raft_module_is_leader(upsilon));

  sim_host_destroy(&host);
}

TEST(RaftSimHarness, PartitionIsolatedLeaderHaltsMajorityCommitsAndHeals) {
  sim_host_t host = sim_host_make();
  sim_cluster_attach(&host, nullptr);
  sim_run_until(&host, 100, 40, sim_pred_any_leader);
  int old_leader = sim_find_leader(&host);
  ASSERT_GE(old_leader, 0);
  uint32_t peer_a = 0;
  uint32_t peer_b = 0;
  {
    uint32_t next_free = 0;
    for (uint32_t node_index = 0; node_index < 3; node_index++) {
      if ((int)node_index == old_leader) continue;
      if (next_free == 0) {
        peer_a = node_index;
        next_free = 1;
      } else {
        peer_b = node_index;
      }
    }
  }

  // Baseline commit with the whole cluster: the majority opinion the heal
  // is judged against.
  uint8_t decree_1_uuid[CRABS_UUID_SIZE];
  ASSERT_EQ(sim_submit_write(&host, (uint32_t)old_leader, "council_write",
                             "council", "decree-1", decree_1_uuid),
            CRABS_ERR_ORDERING_PENDING);
  sim_target_tip = 1;
  sim_run_until(&host, 100, 20, sim_pred_target_tips);

  // --- PARTITION: the isolated leader vs the two-node majority ---
  host.nodes[old_leader].partition_group = 1;
  host.nodes[peer_a].partition_group = 2;
  host.nodes[peer_b].partition_group = 2;

  // Minority halts: the isolated leader still accepts a proposal (it
  // believes itself leader) but can never commit — the durable entry sits
  // uncommitted at index 2 and the group item's content does not move.
  uint8_t lost_uuid[CRABS_UUID_SIZE];
  ASSERT_EQ(sim_submit_write(&host, (uint32_t)old_leader, "council_write",
                             "council", "decree-lost", lost_uuid),
            CRABS_ERR_ORDERING_PENDING);
  for (uint32_t step = 0; step < 6; step++) {
    sim_step(&host, 100, nullptr);
  }
  EXPECT_EQ(crabs_raft_module_log_length(host.nodes[old_leader].module), 2u);
  EXPECT_EQ(crabs_raft_module_committed_tip(host.nodes[old_leader].module), 1u);
  const lww_register_t* isolated_value =
      sim_council_register(host.nodes[old_leader].state);
  ASSERT_NE(isolated_value, nullptr);
  EXPECT_EQ(memcmp(isolated_value->value, "decree-1", 8), 0);

  // Majority: a NEW leader emerges (the old one's group is unreachable to
  // it) and commits its own op at the same contested position.
  // The majority elects its own leader (the isolated one keeps believing it
  // leads — it cannot know until heal; both roles coexist across the split).
  uint32_t majority_steps = 0;
  int new_leader = -1;
  while (majority_steps < 40) {
    sim_step(&host, 100, nullptr);
    majority_steps++;
    new_leader = crabs_raft_module_is_leader(host.nodes[peer_a].module)
                     ? (int)peer_a
                     : (crabs_raft_module_is_leader(host.nodes[peer_b].module)
                            ? (int)peer_b
                            : -1);
    if (new_leader >= 0) break;
  }
  ASSERT_GE(new_leader, 0);
  ASSERT_NE(new_leader, old_leader);
  uint8_t majority_uuid[CRABS_UUID_SIZE];
  ASSERT_EQ(sim_submit_write(&host, (uint32_t)new_leader, "council_write",
                             "council", "decree-majority", majority_uuid),
            CRABS_ERR_ORDERING_PENDING);
  {
    uint32_t turns = 0;
    while (crabs_raft_module_committed_tip(host.nodes[new_leader].module) != 2u &&
           turns < 25) {
      sim_step(&host, 100, nullptr);
      turns++;
    }
    ASSERT_EQ(crabs_raft_module_committed_tip(host.nodes[new_leader].module), 2u);
  }
  ASSERT_NE(memcmp(majority_uuid, decree_1_uuid, CRABS_UUID_SIZE), 0);

  // --- HEAL: the partition dissolves ---
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    host.nodes[node_index].partition_group = 0;
  }
  sim_target_tip = 2;
  sim_run_until(&host, 100, 60, sim_pred_target_tips);

  // Log-matching repair: the healed replica's UNCOMMITTED suffix was
  // discarded, the majority's entry adopted — the lost op exists NOWHERE
  // (no zombie log entry, no duplicate commit anywhere), and every
  // committed op materialized exactly once per replica.
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    EXPECT_EQ(crabs_raft_module_committed_tip(host.nodes[node_index].module), 2u);
    EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[node_index].state,
                                         majority_uuid), 1u);
    EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[node_index].state,
                                         lost_uuid), 0u);
    EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[node_index].state,
                                         decree_1_uuid), 1u);
    const lww_register_t* healed_value =
        sim_council_register(host.nodes[node_index].state);
    ASSERT_NE(healed_value, nullptr);
    EXPECT_EQ(memcmp(healed_value->value, "decree-majority", 14), 0);
  }
  // The old leader is NOT leader anymore (its out-of-date log can never win
  // a vote; the majority refused the candidacy per the up-to-dateness
  // check), and a submission it now attempts refuses NOT_LEADER.
  EXPECT_FALSE(crabs_raft_module_is_leader(host.nodes[old_leader].module));
  EXPECT_EQ(sim_submit_write(&host, (uint32_t)old_leader, "council_write",
                             "council", "post-heal", nullptr),
            CRABS_ERR_ORDERING_NOT_LEADER);
  sim_step(&host, 100, nullptr);

  sim_host_destroy(&host);
}

TEST(RaftSimHarness, MessageFaultsDroppedDuplicatedReorderedConvergeIdempotently) {
  sim_host_t host = sim_host_make();
  sim_cluster_attach(&host, nullptr);
  sim_run_until(&host, 100, 40, sim_pred_any_leader);
  int leader_index = sim_find_leader(&host);
  ASSERT_GE(leader_index, 0);

  // Fault scripts (the host models the faults; the module must be
  // idempotent): turn 1 duplicates the head message and drops the tail —
  // lost append traffic rides the next heartbeat; turn 2 reorders and
  // duplicates — out-of-order vote/append traffic is rejected-or-absorbed
  // fail-closed. Data still converges, applied exactly once everywhere.
  uint8_t decree_uuid[CRABS_UUID_SIZE];
  ASSERT_EQ(sim_submit_write(&host, (uint32_t)leader_index, "council_write",
                             "council", "fault-decree", decree_uuid),
            CRABS_ERR_ORDERING_PENDING);
  sim_step_faulted(&host, 100, [](sim_host_t* fault_host) {
    ASSERT_FALSE(fault_host->wire.empty());
    sim_wire_duplicate(fault_host, 0);
    sim_wire_drop(fault_host, fault_host->wire.size() - 1);
  });
  sim_step_faulted(&host, 100, [](sim_host_t* fault_host) {
    // The earlier drop may have emptied the wire this turn — the reorder
    // script only fires when there is traffic to scramble.
    if (fault_host->wire.size() < 2u) return;
    sim_wire_reorder(fault_host, 0, 1);
    sim_wire_duplicate(fault_host, 1);
  });
  bool converged = false;
  for (uint32_t turn = 0; turn < 40 && !converged; turn++) {
    sim_step(&host, 100, nullptr);
    converged = true;
    for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
      if (crabs_raft_module_committed_tip(host.nodes[node_index].module) != 1u ||
          sim_state_uuid_occurrences(host.nodes[node_index].state,
                                     decree_uuid) != 1u) {
        converged = false;
      }
    }
  }
  EXPECT_TRUE(converged);
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    EXPECT_EQ(crabs_raft_module_committed_tip(host.nodes[node_index].module), 1u);
    EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[node_index].state,
                                         decree_uuid), 1u);
    EXPECT_EQ(crabs_raft_module_rejected_message_count(
                  host.nodes[node_index].module), 0u);
  }
  sim_host_destroy(&host);
}

TEST(RaftSimHarness, SlowPersistFollowerLagsThenConverges) {
  sim_host_t host = sim_host_make();
  sim_cluster_attach(&host, nullptr);
  sim_run_until(&host, 100, 40, sim_pred_any_leader);
  int leader_index = sim_find_leader(&host);
  ASSERT_GE(leader_index, 0);
  int slow_node = (leader_index + 1) % 3;
  uint32_t fast_node = (uint32_t)(leader_index + 2) % 3;

  // Hold node storage: the laggard's durability (and hence its commit)
  // waits for the host's persist_complete.
  host.nodes[slow_node].auto_persist = false;
  uint8_t decree_uuid[CRABS_UUID_SIZE];
  ASSERT_EQ(sim_submit_write(&host, (uint32_t)leader_index, "council_write",
                             "council", "slow-decree", decree_uuid),
            CRABS_ERR_ORDERING_PENDING);

  // The cluster still reaches quorum WITHOUT the laggard: leader + fast
  // follower commit while the slow follower's tip stays anchored at 0 (its
  // persistence contract has not closed).
  sim_step(&host, 100, nullptr);
  sim_step(&host, 100, nullptr);
  EXPECT_EQ(crabs_raft_module_log_length(host.nodes[slow_node].module), 1u);
  EXPECT_EQ(crabs_raft_module_committed_tip(host.nodes[slow_node].module), 0u);
  {
    uint32_t turns = 0;
    while (crabs_raft_module_committed_tip(host.nodes[fast_node].module) != 1u &&
           turns < 20) {
      sim_step(&host, 100, nullptr);
      turns++;
    }
    ASSERT_EQ(crabs_raft_module_committed_tip(host.nodes[fast_node].module), 1u);
  }
  EXPECT_EQ(crabs_raft_module_committed_tip(host.nodes[slow_node].module), 0u);
  EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[slow_node].state,
                                       decree_uuid), 0u);

  // The host answers the held window: the laggard catches up — commit
  // advances past the tip and the committed op materializes exactly once.
  host.nodes[slow_node].auto_persist = true;
  sim_target_tip = 1;
  sim_run_until(&host, 100, 20, sim_pred_target_tips);
  EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[slow_node].state,
                                       decree_uuid), 1u);
  const lww_register_t* caught_up_value =
      sim_council_register(host.nodes[slow_node].state);
  ASSERT_NE(caught_up_value, nullptr);
  EXPECT_EQ(memcmp(caught_up_value->value, "slow-decree", 10), 0);
  sim_host_destroy(&host);
}
TEST(RaftSimHarness, RestartSaveLoadSaveCarriesModuleSectionAndPending) {
  // Carried items 3+4, end to end: (a) the pending proposal list and the
  // module log round-trip through the v16 module section; (b) the attach
  // API carries the imported section into the fresh module so the WRITER
  // re-emits last-known module state; (c) a save→load→save round-trip is
  // byte-identical (also through the never-reimported writer fallback).
  sim_single_fixture_t fixture;
  sim_single_fixture_init(&fixture);
  uint64_t deadline = crabs_raft_module_next_election_deadline(fixture.module);
  EXPECT_EQ(crabs_raft_module_tick(fixture.module, deadline), CRABS_SUCCESS);

  // Entry 1 commits and materializes; entry 2 stays PENDING (proposed,
  // durable-tail only) — the restart-resume case the pending section exists
  // for.
  operation_t* op1 = sim_signed_council_write(&fixture, "carry-1");
  ASSERT_NE(op1, nullptr);
  EXPECT_EQ(state_machine_execute(fixture.state, op1), CRABS_ERR_ORDERING_PENDING);
  operation_destroy(op1);
  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(fixture.module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(fixture.module, persist.handle,
                                               true), CRABS_SUCCESS);
  EXPECT_EQ(state_raft_process_notifications(fixture.state), CRABS_SUCCESS);
  operation_t* op2 = sim_signed_council_write(&fixture, "carry-2");
  ASSERT_NE(op2, nullptr);
  EXPECT_EQ(state_machine_execute(fixture.state, op2), CRABS_ERR_ORDERING_PENDING);
  operation_destroy(op2);
  ASSERT_NE(fixture.state->raft_pending_proposals, nullptr);
  EXPECT_EQ(crabs_raft_module_log_length(fixture.module), 2u);

  serialized_buffer_t* blob1 = crabs_serialize_state(fixture.state);
  ASSERT_NE(blob1, nullptr);

  // --- restart: object graph gone, only the blob survives ---
  state_attach_raft_module(fixture.state, nullptr);
  crabs_raft_module_destroy(fixture.module);
  state_destroy(fixture.state);
  fixture.module = nullptr;
  fixture.state = nullptr;
  fixture.keypair = nullptr;
  fixture.attr_machine = nullptr;

  // Writer fallback leg: the loaded state re-emits its carried module
  // section UNCHANGED even though no module was ever attached to it.
  state_t* loaded = crabs_deserialize_state(blob1->data, blob1->len);
  ASSERT_NE(loaded, nullptr);
  ASSERT_NE(loaded->raft_module_state, nullptr);
  for (const raft_pending_proposal_t* pending =
           (const raft_pending_proposal_t*)loaded->raft_pending_proposals;
       pending != nullptr; pending = pending->next) {
    EXPECT_GT(pending->op_len, 0u);
  }
  serialized_buffer_t* blob_reload = crabs_serialize_state(loaded);
  ASSERT_NE(blob_reload, nullptr);
  EXPECT_EQ(blob_reload->len, blob1->len);
  EXPECT_EQ(memcmp(blob_reload->data, blob1->data, blob1->len), 0);
  serialized_buffer_destroy(blob_reload);

  // Attach leg: importing the carried section restores the durable tip, and
  // the re-emitted blob is byte-identical to the original save.
  crabs_raft_config_t config;
  crabs_raft_config_defaults(&config);
  config.seed = 99;
  crabs_raft_module_t* revived = crabs_raft_module_create(&config);
  ASSERT_NE(revived, nullptr);
  crabs_raft_module_state_t* carried =
      (crabs_raft_module_state_t*)loaded->raft_module_state;
  ASSERT_EQ(carried->commit_index, 1u);
  EXPECT_EQ(crabs_raft_module_import_state(revived, carried), CRABS_SUCCESS);
  ASSERT_EQ(state_attach_raft_module(loaded, revived), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(revived), 1u);
  EXPECT_EQ(crabs_raft_module_log_length(revived), 2u);
  EXPECT_EQ(loaded->raft_pending_proposals != nullptr, true);
  serialized_buffer_t* blob2 = crabs_serialize_state(loaded);
  ASSERT_NE(blob2, nullptr);
  EXPECT_EQ(blob2->len, blob1->len);
  EXPECT_EQ(memcmp(blob2->data, blob1->data, blob1->len), 0);
  serialized_buffer_destroy(blob2);

  state_attach_raft_module(loaded, nullptr);
  crabs_raft_module_destroy(revived);
  state_destroy(loaded);
  serialized_buffer_destroy(blob1);
}

// SOVEREIGN/FREE domains ride the SAME op shape;DOMAIN_CHECK must stay
// untouched by the module seam (the mixed-machine property).
static void sim_setup_domain_extras(state_t* state) {
  state_add_policy(state, "sovereign_write", "role:admin");
  state_add_policy(state, "free_write", "role:admin");
  EXPECT_EQ(state_machine_register_handler(state, "sovereign_write",
                                           sim_handler_council_write),
            CRABS_SUCCESS);
  EXPECT_EQ(state_machine_register_handler(state, "free_write",
                                           sim_handler_council_write),
            CRABS_SUCCESS);
  data_item_options_t options;
  memset(&options, 0, sizeof(options));
  options.write_domain = CRABS_DOMAIN_SOVEREIGN;
  options.writer = "admin";
  data_item_t* item = nullptr;
  ASSERT_EQ(data_item_create_with_options("sovereign_reg", DATA_TYPE_REGISTER,
                                          CRDT_LWW_REG, &options, &item),
            CRABS_SUCCESS);
  item->value = lww_register_create((const uint8_t*)"origin", 6, 1, "admin");
  item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  ASSERT_EQ(state_add_item(state, item), CRABS_SUCCESS);

  memset(&options, 0, sizeof(options));
  options.write_domain = CRABS_DOMAIN_FREE_MERGE;
  item = nullptr;
  ASSERT_EQ(data_item_create_with_options("free_reg", DATA_TYPE_REGISTER,
                                          CRDT_LWW_REG, &options, &item),
            CRABS_SUCCESS);
  item->value = lww_register_create((const uint8_t*)"origin", 6, 1, "admin");
  item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;
  ASSERT_EQ(state_add_item(state, item), CRABS_SUCCESS);
}

TEST(RaftSimHarness, MixedMachineGroupHaltsWhileSovereignFreeExecute) {
  sim_host_t host = sim_host_make();
  sim_cluster_attach(&host, sim_setup_domain_extras);
  sim_run_until(&host, 100, 40, sim_pred_any_leader);
  int leader_index = sim_find_leader(&host);
  ASSERT_GE(leader_index, 0);

  // The GROUP item halts: submitted, accepted as pending, NOT executed
  // inline (its register keeps origin on every replica until commit).
  uint8_t group_uuid[CRABS_UUID_SIZE];
  ASSERT_EQ(sim_submit_write(&host, (uint32_t)leader_index, "council_write",
                             "council", "group-decree", group_uuid),
            CRABS_ERR_ORDERING_PENDING);
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    const lww_register_t* held_value =
        sim_council_register(host.nodes[node_index].state);
    ASSERT_NE(held_value, nullptr);
    EXPECT_EQ(memcmp(held_value->value, "origin", 6), 0);
  }

  // SOVEREIGN and FREE execute INLINE on every replica (DOMAIN_CHECK
  // unaffected by the attached module — the ordering module only owns the
  // GROUP-ORDERED namespace).
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    EXPECT_EQ(sim_submit_write(&host, node_index, "sovereign_write",
                               "sovereign_reg", "sovereign-set", nullptr),
              CRABS_SUCCESS);
    EXPECT_EQ(sim_submit_write(&host, node_index, "free_write", "free_reg",
                               "free-set", nullptr),
              CRABS_SUCCESS);
  }
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    const lww_register_t* sovereign_value = (const lww_register_t*)
        state_find_item(host.nodes[node_index].state, "sovereign_reg")->value;
    ASSERT_NE(sovereign_value, nullptr);
    EXPECT_EQ(memcmp(sovereign_value->value, "sovereign-set", 13), 0);
    const lww_register_t* free_value = (const lww_register_t*)
        state_find_item(host.nodes[node_index].state, "free_reg")->value;
    ASSERT_NE(free_value, nullptr);
    EXPECT_EQ(memcmp(free_value->value, "free-set", 8), 0);
    // …while the group item STILL holds on every replica.
    const lww_register_t* still_held = sim_council_register(host.nodes[node_index].state);
    ASSERT_NE(still_held, nullptr);
    EXPECT_EQ(memcmp(still_held->value, "origin", 6), 0);
  }

  // Commit rides replication: every replica's group item materializes the
  // committed decree; the sovereign/free contents are untouched by it.
  sim_target_tip = 1;
  sim_run_until(&host, 100, 20, sim_pred_target_tips);
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    const lww_register_t* committed_value = sim_council_register(host.nodes[node_index].state);
    ASSERT_NE(committed_value, nullptr);
    EXPECT_EQ(memcmp(committed_value->value, "group-decree", 12), 0);
    EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[node_index].state,
                                         group_uuid), 1u);
  }
  sim_host_destroy(&host);
}

TEST(RaftMerge, GroupItemAdoptsByCommittedPosition) {
  // Carried item 6: the merge hold-stub became adopt-by-committed-position.
  state_t* dst = state_create();
  sim_setup_council_state(dst);
  state_t* src = state_create();
  sim_setup_council_state(src);

  // Diverge src's content at the same position.
  data_item_t* src_item = state_find_item(src, "council");
  lww_register_destroy((lww_register_t*)src_item->value);
  src_item->value = lww_register_create((const uint8_t*)"src-decree", 10, 2, "nodeA");
  src_item->value_repr = (data_value_repr_t)DATA_VALUE_REPR_CRDT_STRUCT;

  // Both module-less → the v1 hold behavior (content divergence unresolvable).
  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);
  {
    const lww_register_t* value = (const lww_register_t*)
        state_find_item(dst, "council")->value;
    ASSERT_NE(value, nullptr);
    EXPECT_EQ(memcmp(value->value, "origin", 6), 0);
  }

  // src's module committed FURTHER: dst adopts the committed content.
  uint64_t src_terms[2] = {1, 1};
  crabs_raft_module_state_t* src_snapshot = sim_snapshot_make(1, 2, src_terms);
  ASSERT_NE(src_snapshot, nullptr);
  src->raft_module_state = src_snapshot;
  EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);
  {
    const lww_register_t* value = (const lww_register_t*)
        state_find_item(dst, "council")->value;
    ASSERT_NE(value, nullptr);
    EXPECT_EQ(memcmp(value->value, "src-decree", 10), 0);
  }

  // dst's module committed further (or equal): dst keeps its content — a
  // stale tail must not reach backward past the committed position.
  uint64_t dst_terms[3] = {1, 1, 1};
  crabs_raft_module_state_t* dst_snapshot = sim_snapshot_make(1, 3, dst_terms);
  ASSERT_NE(dst_snapshot, nullptr);
  dst->raft_module_state = dst_snapshot;
  src->raft_module_state = NULL;
  uint64_t src_terms2[2] = {1, 1};
  crabs_raft_module_state_t* src_snapshot2 = sim_snapshot_make(1, 2, src_terms2);
  ASSERT_NE(src_snapshot2, nullptr);
  src->raft_module_state = src_snapshot2;
  {
    EXPECT_EQ(crdt_merge_state(dst, src), CRABS_SUCCESS);
    const lww_register_t* after = (const lww_register_t*)
        state_find_item(dst, "council")->value;
    ASSERT_EQ(after->value_size, (uint32_t)10);
    EXPECT_EQ(memcmp(after->value, "src-decree", 10), 0);
  }

  crabs_raft_module_state_destroy(src_snapshot);
  crabs_raft_module_state_destroy(src_snapshot2);
  crabs_raft_module_state_destroy(dst_snapshot);
  dst->raft_module_state = NULL;
  src->raft_module_state = NULL;
  state_destroy(dst);
  state_destroy(src);
}
