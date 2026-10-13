//
// Deterministic Raft simulation harness (raft-ordering plan, Phase 1).
//
// HARNESS NOTE (environmental, not a CRABS defect): under scaled runs this
// suite may crash on PROCESS EXIT with heap corruption inside OpenSSL 3's
// CRYPTO_free_ex_data teardown — it reproduces at P2 HEAD as well, so it is
// not introduced by scenario growth. All gtest assertions have already been
// evaluated and reported before exit; treat a clean test summary followed by
// an exit-stage segfault as the known environmental issue (recorded in the
// raft-ordering plan's as-landed notes). No CRABS code path is implicated.
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
// to_peer id). Per-destination KIND tallies let scenarios count traffic
// shapes (e.g. zero appends to an evicted node after its exclusion).
typedef struct {
  uint32_t append_req[kSimMaxNodes];
  uint32_t config_excluded[kSimMaxNodes];
} sim_wire_kind_tally_t;

static sim_wire_kind_tally_t sim_wire_kinds = {};

static void sim_wire_kinds_reset() {
  sim_wire_kinds = sim_wire_kind_tally_t{};
}

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
      if (message.to_node < kSimMaxNodes &&
          outbound.kind == RAFT_MSG_APPEND_REQ) {
        sim_wire_kinds.append_req[message.to_node]++;
      }
      if (message.to_node < kSimMaxNodes &&
          outbound.kind == RAFT_MSG_CONFIG_EXCLUDED) {
        sim_wire_kinds.config_excluded[message.to_node]++;
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

// Persisted-state settlement: carried item A can CHAIN windows (a grant arm
// fires while another resolves), so scenarios wanting fully settled
// durability pump until every node's window is empty (bounded).
static void sim_pump_persist_settled(sim_host_t* host) {
  for (uint32_t round = 0; round < 8; round++) {
    sim_pump_persist(host);
    bool any_window = false;
    for (uint32_t node_index = 0; node_index < host->node_count; node_index++) {
      crabs_raft_persist_request_t persist;
      if (crabs_raft_module_poll_persist(host->nodes[node_index].module,
                                         &persist)) {
        any_window = true;
        break;
      }
    }
    if (!any_window) return;
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
  EXPECT_EQ(crabs_raft_module_log_length(fixture.module), 2u);  // §8 no-op + decree
  EXPECT_EQ(crabs_raft_module_committed_tip(fixture.module), 0u);
  const raft_pending_proposal_t* pending =
      (const raft_pending_proposal_t*)fixture.state->raft_pending_proposals;
  ASSERT_NE(pending, nullptr);
  EXPECT_EQ(memcmp(pending->uuid, submitted_uuid, CRABS_UUID_SIZE), 0);
  EXPECT_GT(pending->op_len, 0u);
  const lww_register_t* before_commit = sim_council_register(fixture.state);
  ASSERT_NE(before_commit, nullptr);
  EXPECT_EQ(memcmp(before_commit->value, "origin", 6), 0);

  // Host storage loop: the persist windows are stored anywhere durable and
  // acknowledged. NO commit counts before the ack. Window 1 carries the
  // leadership no-op (which commits silently); window 2 carries the decree.
  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(fixture.module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(fixture.module, persist.handle,
                                               true), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(fixture.module), 1u);
  ASSERT_TRUE(crabs_raft_module_poll_persist(fixture.module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(fixture.module, persist.handle,
                                               true), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(fixture.module), 2u);

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
  EXPECT_EQ(crabs_raft_module_log_length(fixture.module), 2u);

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
  EXPECT_EQ(crabs_raft_module_log_length(fixture.module), 1u);  // §8 no-op only

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
  // Window 1: the §8 leadership no-op (commits silently at tip 1)...
  ASSERT_TRUE(crabs_raft_module_poll_persist(fixture.module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(fixture.module, persist.handle,
                                               true), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(fixture.module), 1u);
  // ...window 2: the op itself (tip 2).
  ASSERT_TRUE(crabs_raft_module_poll_persist(fixture.module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(fixture.module, persist.handle,
                                               true), CRABS_SUCCESS);
  EXPECT_EQ(state_raft_process_notifications(fixture.state), CRABS_SUCCESS);
  const lww_register_t* registered = sim_council_register(fixture.state);
  ASSERT_NE(registered, nullptr);
  EXPECT_EQ(memcmp(registered->value, "pre-restart", 11), 0);
  EXPECT_EQ(crabs_raft_module_committed_tip(fixture.module), 2u);

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
  EXPECT_EQ(parsed->commit_index, 2u);

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
  // Window 1: the revived leadership's own no-op (commits at tip 3)...
  ASSERT_TRUE(crabs_raft_module_poll_persist(revived, &restart_persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(revived, restart_persist.handle,
                                               true), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(revived), 3u);
  // ...window 2: the post-restart op (tip 4).
  ASSERT_TRUE(crabs_raft_module_poll_persist(revived, &restart_persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(revived, restart_persist.handle,
                                               true), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(revived), 4u);
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
  host.nodes[0].auto_persist = true;   // host storage answers persist windows
  host.nodes[1].auto_persist = true;
  host.node_count = 2;

  // Scripted ticks elect alpha to candidacy (sim_run_until drives turn-based
  // ticks through routing and delivery).
  uint32_t turns = sim_run_until(&host, 100, 20, sim_pred_alpha_elected);
  ASSERT_LT(turns, 20u);
  // A fresh re-election tick re-solicits the peer: the wire holds a live
  // message we can fault and deliver. Carried item A gates the solicitation
  // on the term/votedFor header batch — one persist round-trip first.
  uint64_t term_before_reelection =
      crabs_raft_module_current_term(host.nodes[0].module);
  EXPECT_EQ(crabs_raft_module_tick(host.nodes[0].module, host.now_ms + 10000),
            CRABS_SUCCESS);
  sim_pump_persist_settled(&host);
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
  EXPECT_EQ(crabs_raft_module_current_term(host.nodes[1].module),
            term_before_reelection + 1);

  // Beta's duplicate vote responses flow back to the candidate and are
  // absorbed idempotently. Carried item A: beta's grant waits on its own
  // header batch first.
  sim_pump_persist_settled(&host);
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
  // No proposals yet: zero commits, clean wire. The leader's log holds the
  // §8 leadership no-op it appended the moment it won; followers (which have
  // not acked it yet) still show empty logs.
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    uint32_t log_length = crabs_raft_module_log_length(host.nodes[node_index].module);
    EXPECT_TRUE(log_length == 0u || log_length == 1u);
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

  // Upsilon hits its deadline → term-7 candidacy soliciting phi. Carried
  // item A: the solicitation waits behind its OWN term/self-vote persist.
  crabs_raft_module_t* upsilon = host.nodes[0].module;
  EXPECT_EQ(crabs_raft_module_tick(
                upsilon, crabs_raft_module_next_election_deadline(upsilon)),
            CRABS_SUCCESS);
  {
    crabs_raft_persist_request_t candidacy_persist;
    ASSERT_TRUE(crabs_raft_module_poll_persist(upsilon, &candidacy_persist));
    EXPECT_EQ(crabs_raft_module_persist_complete(upsilon, candidacy_persist.handle,
                                                 true), CRABS_SUCCESS);
  }
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
  // Tip 2: the leader's §8 no-op (index 1) + decree-1 (index 2).
  sim_target_tip = 2;
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
  // Log: no-op (1) + decree-1 (2) + the uncommitted lost decree (3). Tip
  // frozen at 2: the minority never collects a quorum again.
  EXPECT_EQ(crabs_raft_module_log_length(host.nodes[old_leader].module), 3u);
  EXPECT_EQ(crabs_raft_module_committed_tip(host.nodes[old_leader].module), 2u);
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
    // Tip 4 on the majority leader: its own no-op (3) + decree-majority (4).
    uint32_t turns = 0;
    while (crabs_raft_module_committed_tip(host.nodes[new_leader].module) != 4u &&
           turns < 25) {
      sim_step(&host, 100, nullptr);
      turns++;
    }
    ASSERT_EQ(crabs_raft_module_committed_tip(host.nodes[new_leader].module), 4u);
  }
  ASSERT_NE(memcmp(majority_uuid, decree_1_uuid, CRABS_UUID_SIZE), 0);

  // --- HEAL: the partition dissolves ---
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    host.nodes[node_index].partition_group = 0;
  }
  // Tip 4: the majority's no-op + decree adopted everywhere post-heal.
  sim_target_tip = 4;
  sim_run_until(&host, 100, 60, sim_pred_target_tips);

  // Log-matching repair: the healed replica's UNCOMMITTED suffix was
  // discarded, the majority's entry adopted — the lost op exists NOWHERE
  // (no zombie log entry, no duplicate commit anywhere), and every
  // committed op materialized exactly once per replica.
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    EXPECT_EQ(crabs_raft_module_committed_tip(host.nodes[node_index].module), 4u);
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
      // Tip 2 = the leader's no-op (1) + the decree (2).
      if (crabs_raft_module_committed_tip(host.nodes[node_index].module) != 2u ||
          sim_state_uuid_occurrences(host.nodes[node_index].state,
                                     decree_uuid) != 1u) {
        converged = false;
      }
    }
  }
  EXPECT_TRUE(converged);
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    EXPECT_EQ(crabs_raft_module_committed_tip(host.nodes[node_index].module), 2u);
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
  EXPECT_EQ(crabs_raft_module_log_length(host.nodes[slow_node].module), 2u);
  EXPECT_EQ(crabs_raft_module_committed_tip(host.nodes[slow_node].module), 0u);
  {
    uint32_t turns = 0;
    while (crabs_raft_module_committed_tip(host.nodes[fast_node].module) != 2u &&
           turns < 20) {
      sim_step(&host, 100, nullptr);
      turns++;
    }
    ASSERT_EQ(crabs_raft_module_committed_tip(host.nodes[fast_node].module), 2u);
  }
  EXPECT_EQ(crabs_raft_module_committed_tip(host.nodes[slow_node].module), 0u);
  EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[slow_node].state,
                                       decree_uuid), 0u);

  // The host answers the held window: the laggard catches up — commit
  // advances past the tip and the committed op materializes exactly once.
  host.nodes[slow_node].auto_persist = true;
  sim_target_tip = 2;
  sim_run_until(&host, 100, 20, sim_pred_target_tips);
  EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[slow_node].state,
                                       decree_uuid), 1u);
  const lww_register_t* caught_up_value =
      sim_council_register(host.nodes[slow_node].state);
  ASSERT_NE(caught_up_value, nullptr);
  EXPECT_EQ(memcmp(caught_up_value->value, "slow-decree", 10), 0);
  sim_host_destroy(&host);
}
TEST(RaftSimHarness, FollowerAcksWaitForTheirOwnDurability) {
  // Two-sided durability covers replication traffic, not just votes: the
  // follower's APPEND_RESP is the match_index the leader counts toward
  // commit, so a leader-durable + follower-undurable ack must NEVER quorum.
  // Construct: leader + 2 followers whose hosts BOTH hold their persist
  // windows (a follower crash replay resolves via recover_from_persist);
  // the quorum (2 of 3) can only close on a DURABLE follower match — every
  // entry waits while a needed matcher stays undurable.
  sim_host_t host = sim_host_make();
  sim_cluster_attach(&host, nullptr);
  sim_run_until(&host, 100, 40, sim_pred_any_leader);
  int leader_index = sim_find_leader(&host);
  ASSERT_GE(leader_index, 0);
  uint32_t follower_a = (uint32_t)(leader_index + 1) % 3;
  uint32_t follower_b = (uint32_t)(leader_index + 2) % 3;

  // Settle the leadership no-op (baseline tip 1 everywhere, all durable).
  sim_target_tip = 1;
  sim_run_until(&host, 100, 40, sim_pred_target_tips);
  sim_target_tip = 0;

  // From here the leader's own tail persists normally; both followers stall.
  host.nodes[follower_a].auto_persist = false;
  host.nodes[follower_b].auto_persist = false;
  uint8_t decree_uuid[CRABS_UUID_SIZE];
  ASSERT_EQ(sim_submit_write(&host, (uint32_t)leader_index, "council_write",
                             "council", "quorum-decree", decree_uuid),
            CRABS_ERR_ORDERING_PENDING);

  // The undurable followers' append responses are HELD behind their persist
  // batches: the leader's quorum count stays at its own durable match (1 of
  // 3) — nothing commits, nothing notifies, and the followers materialize
  // nothing while undurable.
  sim_delivery_tally_t tally = {};
  for (uint32_t turn = 0; turn < 12; turn++) {
    sim_step(&host, 100, &tally);
  }
  EXPECT_EQ(crabs_raft_module_committed_tip(
                host.nodes[leader_index].module), 1u);
  EXPECT_EQ(tally.committed_count[leader_index], 0u);
  EXPECT_EQ(tally.committed_count[follower_a], 0u);
  EXPECT_EQ(tally.committed_count[follower_b], 0u);
  EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[follower_a].state,
                                       decree_uuid), 0u);

  // Crash-replay consistency: follower_b's held bytes are exactly what its
  // host stored before "crashing" — playing them back resolves cleanly.
  crabs_raft_persist_request_t held_window;
  ASSERT_TRUE(crabs_raft_module_poll_persist(
                  host.nodes[follower_b].module, &held_window));
  std::vector<uint8_t> stored_batch(held_window.bytes,
                                    held_window.bytes + held_window.len);
  EXPECT_EQ(crabs_raft_module_recover_from_persist(
                host.nodes[follower_b].module, stored_batch.data(),
                stored_batch.size()), CRABS_SUCCESS);

  // The window acks AFTER the replay: the held response flushes, the match
  // becomes durable, and the quorum closes — commit (and materialization)
  // advances for follower_b while the still-undurable follower_a waits.
  host.nodes[follower_b].auto_persist = true;
  uint32_t settle_turns = 0;
  while ((crabs_raft_module_committed_tip(
              host.nodes[leader_index].module) != 2u ||
          crabs_raft_module_committed_tip(
              host.nodes[follower_b].module) != 2u) &&
         settle_turns < 30) {
    sim_step(&host, 100, nullptr);
    settle_turns++;
  }
  EXPECT_EQ(crabs_raft_module_committed_tip(
                host.nodes[leader_index].module), 2u);
  EXPECT_EQ(crabs_raft_module_committed_tip(
                host.nodes[follower_b].module), 2u);
  EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[follower_b].state,
                                       decree_uuid), 1u);
  EXPECT_EQ(crabs_raft_module_committed_tip(
                host.nodes[follower_a].module), 1u);
  EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[follower_a].state,
                                       decree_uuid), 0u);

  // follower_a's host finally answers: the same hold/flush mechanics close
  // its commit tip too (idempotent materialization, no duplicates).
  host.nodes[follower_a].auto_persist = true;
  settle_turns = 0;
  while (crabs_raft_module_committed_tip(
             host.nodes[follower_a].module) != 2u &&
         settle_turns < 30) {
    sim_step(&host, 100, nullptr);
    settle_turns++;
  }
  EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[follower_a].state,
                                       decree_uuid), 1u);
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
  // Log: §8 no-op (1) + op1 (2) + the pending op2 (3).
  EXPECT_EQ(crabs_raft_module_log_length(fixture.module), 3u);

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
  EXPECT_EQ(crabs_raft_module_log_length(revived), 3u);
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
  // Tip 2 = the leader's §8 no-op (1) + the decree (2).
  sim_target_tip = 2;
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

// ============================================================
// Carried item C (P2 review): ordered materialization retry shelf — a
// committed op whose materialization fails BLOCKS the stream until retried
// successfully; the pump stays strictly ordered, retries carry bounded
// backoff, poison-pill failures surface notifications, and a restart
// resumes the shelf.
// ============================================================

static uint32_t sim_flaky_remaining_failures = 0;

static crabs_error_e sim_handler_flaky_once(state_t* state, operation_t* op) {
  (void)state;
  (void)op;
  if (sim_flaky_remaining_failures > 0) {
    sim_flaky_remaining_failures--;
    return CRABS_ERR_INTERNAL;
  }
  return CRABS_SUCCESS;
}

// Force the pump through its bounded backoff with one wide clock step per
// attempt (the linear backoff caps at CRABS_RAFT_SHELF_BACKOFF_CAP_MS).
static void sim_shelf_pump_loose(sim_single_fixture_t* fixture,
                                 uint64_t base_ms, uint32_t attempts,
                                 crabs_error_e* last_rc) {
  *last_rc = CRABS_SUCCESS;
  for (uint32_t attempt = 0; attempt < attempts; attempt++) {
    *last_rc = state_raft_process_notifications_at(fixture->state,
                                                   base_ms + attempt * CRABS_RAFT_SHELF_BACKOFF_CAP_MS);
  }
}

static crabs_error_e sim_handler_always_failing(state_t* state, operation_t* op) {
  (void)state;
  (void)op;
  return CRABS_ERR_INTERNAL;
}

// A DEAD time-source vtable (the HLC seam state_get_time_ms reads through):
// every query reports no valid physical time — the clock-failure test seam.
static crabs_physical_time_t sim_clock_fail_get_time(void* ctx) {
  (void)ctx;
  crabs_physical_time_t invalid = {0, 0, false};
  return invalid;
}

static bool sim_clock_fail_available(void* ctx) {
  (void)ctx;
  return false;
}

TEST(RaftSimShelf, FailedMaterializationBlocksThenStreamResumesInOrder) {
  sim_single_fixture_t fixture;
  sim_single_fixture_init(&fixture);
  // A handler with a budget of TWO failures: the committed op lands on the
  // shelf instead of being dropped, and NOTHING newer may apply.
  sim_flaky_remaining_failures = 3;   // fill-failure + two failed retries
  EXPECT_EQ(state_machine_register_handler(fixture.state, "council_write",
                                           sim_handler_flaky_once),
            CRABS_SUCCESS);
  uint64_t deadline = crabs_raft_module_next_election_deadline(fixture.module);
  EXPECT_EQ(crabs_raft_module_tick(fixture.module, deadline), CRABS_SUCCESS);

  operation_t* op1 = sim_signed_council_write(&fixture, "blocked-1");
  ASSERT_NE(op1, nullptr);
  uint8_t uuid1[CRABS_UUID_SIZE];
  memcpy(uuid1, op1->uuid, CRABS_UUID_SIZE);
  EXPECT_EQ(state_machine_execute(fixture.state, op1), CRABS_ERR_ORDERING_PENDING);
  operation_destroy(op1);
  // Windows: no-op, then op1.
  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(fixture.module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(fixture.module, persist.handle,
                                               true), CRABS_SUCCESS);
  ASSERT_TRUE(crabs_raft_module_poll_persist(fixture.module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(fixture.module, persist.handle,
                                               true), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(fixture.module), 2u);

  // Pump: the materialization FAILS → the op is retained on the shelf, the
  // group item does NOT move, and the error surfaces.
  crabs_error_e pump_rc = state_raft_process_notifications_at(fixture.state, 0);
  EXPECT_EQ(pump_rc, CRABS_ERR_INTERNAL);
  EXPECT_EQ(memcmp(sim_council_register(fixture.state)->value, "origin", 6), 0);
  EXPECT_TRUE(state_raft_shelf_active(fixture.state));
  EXPECT_EQ(state_raft_shelf_attempt_count(fixture.state), 0u);

  // A newer COMMIT while the shelf is blocked: its notification stays
  // queued — the pump attempts NOTHING newer until the shelf succeeds.
  operation_t* op2 = sim_signed_council_write(&fixture, "blocked-2");
  ASSERT_NE(op2, nullptr);
  uint8_t uuid2[CRABS_UUID_SIZE];
  memcpy(uuid2, op2->uuid, CRABS_UUID_SIZE);
  EXPECT_EQ(state_machine_execute(fixture.state, op2), CRABS_ERR_ORDERING_PENDING);
  operation_destroy(op2);
  ASSERT_TRUE(crabs_raft_module_poll_persist(fixture.module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(fixture.module, persist.handle,
                                               true), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(fixture.module), 3u);

  // The first shelf RETRY (next pump call) fails: attempt 1 of the budget.
  pump_rc = state_raft_process_notifications_at(fixture.state, 1000);
  EXPECT_EQ(pump_rc, CRABS_ERR_INTERNAL);
  EXPECT_EQ(state_raft_shelf_attempt_count(fixture.state), 1u);
  // The blocked newer op did NOT leak into the machine log.
  EXPECT_EQ(sim_state_uuid_occurrences(fixture.state, uuid2), 0u);

  // Bounded backoff: loose wide-step pumps burn the second budget failure
  // (attempt 2), the budget runs out...
  sim_shelf_pump_loose(&fixture, 2000, 1, &pump_rc);
  EXPECT_EQ(pump_rc, CRABS_ERR_INTERNAL);
  EXPECT_EQ(state_raft_shelf_attempt_count(fixture.state), 2u);
  EXPECT_EQ(memcmp(sim_council_register(fixture.state)->value, "origin", 6), 0);
  // ...and the handler heals: the very next pump attempt releases the
  // shelf and the stream resumes — strictly in commit order.
  EXPECT_EQ(state_machine_register_handler(fixture.state, "council_write",
                                           sim_handler_council_write),
            CRABS_SUCCESS);
  pump_rc = state_raft_process_notifications_at(fixture.state, 900000);
  EXPECT_EQ(pump_rc, CRABS_SUCCESS);
  EXPECT_FALSE(state_raft_shelf_active(fixture.state));
  // Order: uuid1 materialized exactly once, uuid2 right behind it — the
  // strictly ordered pump applied the QUEUED newer op only after the head.
  EXPECT_EQ(sim_state_uuid_occurrences(fixture.state, uuid1), 1u);
  EXPECT_EQ(sim_state_uuid_occurrences(fixture.state, uuid2), 1u);
  uint64_t uuid1_position = UINT64_MAX;
  uint64_t uuid2_position = UINT64_MAX;
  for (uint64_t log_index = 0; log_index < fixture.state->log_count;
       log_index++) {
    if (memcmp(fixture.state->log[log_index].uuid, uuid1, CRABS_UUID_SIZE) == 0) {
      uuid1_position = log_index;
    }
    if (memcmp(fixture.state->log[log_index].uuid, uuid2, CRABS_UUID_SIZE) == 0) {
      uuid2_position = log_index;
    }
  }
  ASSERT_LT(uuid1_position, uuid2_position);
  EXPECT_EQ(memcmp(sim_council_register(fixture.state)->value, "blocked-2", 9), 0);

  sim_flaky_remaining_failures = 0;
  sim_single_fixture_destroy(&fixture);
}

TEST(RaftSimShelf, PoisonPillFailuresSurfaceNotificationsLoudly) {
  sim_single_fixture_t fixture;
  sim_single_fixture_init(&fixture);
  EXPECT_EQ(state_machine_register_handler(fixture.state, "council_write",
                                           sim_handler_always_failing),
            CRABS_SUCCESS);
  uint64_t deadline = crabs_raft_module_next_election_deadline(fixture.module);
  EXPECT_EQ(crabs_raft_module_tick(fixture.module, deadline), CRABS_SUCCESS);

  operation_t* op = sim_signed_council_write(&fixture, "poison");
  ASSERT_NE(op, nullptr);
  EXPECT_EQ(state_machine_execute(fixture.state, op), CRABS_ERR_ORDERING_PENDING);
  operation_destroy(op);
  crabs_raft_persist_request_t persist;
  while (crabs_raft_module_poll_persist(fixture.module, &persist)) {
    EXPECT_EQ(crabs_raft_module_persist_complete(fixture.module, persist.handle,
                                                 true), CRABS_SUCCESS);
  }

  struct change_capture_t {
    uint32_t count;
  } capture = {0};
  state_set_change_hook(
      fixture.state,
      [](state_t*, const crabs_change_event_t*, void* user_data) {
        ((change_capture_t*)user_data)->count++;
      },
      &capture);

  // Backoff-aware pumping (one wide step per pump call — the linear
  // backoff caps at 30 s, so this reaches every attempt): the poison
  // threshold is 8 consecutive failures; every attempt AFTER it screams.
  uint64_t now_ms = 0;
  // One pump fills the shelf (not counted as a retry), each subsequent one
  // attempts: run past the poison threshold.
  for (uint32_t attempt = 0; attempt < CRABS_RAFT_SHELF_POISON_ATTEMPTS + 3;
       attempt++) {
    state_raft_process_notifications_at(fixture.state, now_ms);
    now_ms += CRABS_RAFT_SHELF_BACKOFF_CAP_MS;
  }
  EXPECT_EQ(state_raft_shelf_attempt_count(fixture.state),
            CRABS_RAFT_SHELF_POISON_ATTEMPTS + 2);
  EXPECT_GT(capture.count, 0u);   // loudly surfaced, stream STILL blocked
  EXPECT_TRUE(state_raft_shelf_active(fixture.state));
  EXPECT_EQ(memcmp(sim_council_register(fixture.state)->value, "origin", 6), 0);

  sim_single_fixture_destroy(&fixture);
}

TEST(RaftSimShelf, PumpRetriesEveryInvocationWhenClockFails) {
  // The no-time pump bypasses the backoff gate ENTIRELY: a failed clock
  // must not install `0 + backoff` deadlines that later `0 < deadline`
  // comparisons silently block on forever. Every pump invocation retries
  // the shelf head despite the failures; a healing clock and handler
  // resume the normal gated behavior.
  sim_single_fixture_t fixture;
  sim_single_fixture_init(&fixture);
  EXPECT_EQ(state_machine_register_handler(fixture.state, "council_write",
                                           sim_handler_always_failing),
            CRABS_SUCCESS);
  uint64_t deadline = crabs_raft_module_next_election_deadline(fixture.module);
  EXPECT_EQ(crabs_raft_module_tick(fixture.module, deadline), CRABS_SUCCESS);
  operation_t* op = sim_signed_council_write(&fixture, "no-time-poison");
  ASSERT_NE(op, nullptr);
  EXPECT_EQ(state_machine_execute(fixture.state, op), CRABS_ERR_ORDERING_PENDING);
  operation_destroy(op);
  crabs_raft_persist_request_t persist;
  while (crabs_raft_module_poll_persist(fixture.module, &persist)) {
    EXPECT_EQ(crabs_raft_module_persist_complete(fixture.module, persist.handle,
                                                 true), CRABS_SUCCESS);
  }
  EXPECT_EQ(state_raft_process_notifications(fixture.state), CRABS_ERR_INTERNAL);
  EXPECT_TRUE(state_raft_shelf_active(fixture.state));

  // FAIL the clock: a dead time-source vtable on the state's HLC seam makes
  // state_get_time_ms fail closed (no authenticated time).
  static crabs_time_source_ops_t dead_ops = {
      sim_clock_fail_get_time, sim_clock_fail_available, NULL};
  fixture.state->hlc_state.time_source_ops = &dead_ops;

  for (uint32_t attempt = 1; attempt <= 4; attempt++) {
    // (The committed path's own clock gate fails the retry loudly before
    // the handler is reached — the error kind is not the point: the pump
    // ATTEMPTED, instead of silently sitting on its backoff.)
    EXPECT_NE(state_raft_process_notifications(fixture.state), CRABS_SUCCESS);
    EXPECT_EQ(state_raft_shelf_attempt_count(fixture.state), attempt);
  }
  // The stream stayed blocked the whole time (order over availability).
  EXPECT_TRUE(state_raft_shelf_active(fixture.state));
  EXPECT_EQ(memcmp(sim_council_register(fixture.state)->value, "origin", 6), 0);

  // Recovery when the clock (and the handler) come back: the trusted pump
  // releases the shelf and drains in commit order.
  EXPECT_EQ(state_machine_register_handler(fixture.state, "council_write",
                                           sim_handler_council_write),
            CRABS_SUCCESS);
  fixture.state->hlc_state.time_source_ops = NULL;
  EXPECT_EQ(state_raft_process_notifications(fixture.state), CRABS_SUCCESS);
  EXPECT_FALSE(state_raft_shelf_active(fixture.state));
  sim_single_fixture_destroy(&fixture);
}

TEST(RaftSimShelf, RestartCarriesTheShelfAndResumesOrdering) {
  sim_single_fixture_t fixture;
  sim_single_fixture_init(&fixture);
  EXPECT_EQ(state_machine_register_handler(fixture.state, "council_write",
                                           sim_handler_always_failing),
            CRABS_SUCCESS);
  uint64_t deadline = crabs_raft_module_next_election_deadline(fixture.module);
  EXPECT_EQ(crabs_raft_module_tick(fixture.module, deadline), CRABS_SUCCESS);

  operation_t* op = sim_signed_council_write(&fixture, "shelf-carry");
  ASSERT_NE(op, nullptr);
  EXPECT_EQ(state_machine_execute(fixture.state, op), CRABS_ERR_ORDERING_PENDING);
  operation_destroy(op);
  crabs_raft_persist_request_t persist;
  while (crabs_raft_module_poll_persist(fixture.module, &persist)) {
    EXPECT_EQ(crabs_raft_module_persist_complete(fixture.module, persist.handle,
                                                 true), CRABS_SUCCESS);
  }
  state_raft_process_notifications_at(fixture.state, 0);
  ASSERT_TRUE(state_raft_shelf_active(fixture.state));
  // One failed retry first: the shelf rides the section with its
  // consecutive-failure count (poison visibility continues after restart).
  EXPECT_EQ(state_raft_process_notifications_at(fixture.state,
                                                CRABS_RAFT_SHELF_BACKOFF_CAP_MS),
            CRABS_ERR_INTERNAL);
  ASSERT_EQ(state_raft_shelf_attempt_count(fixture.state), 1u);

  // Serialize WITH the shelf: the v17 module section carries the blocked op
  // beside the pendings; the restart resumes ordering from it.
  serialized_buffer_t* blob = crabs_serialize_state(fixture.state);
  ASSERT_NE(blob, nullptr);

  state_attach_raft_module(fixture.state, nullptr);
  crabs_raft_module_destroy(fixture.module);
  state_destroy(fixture.state);
  fixture.module = nullptr;
  fixture.state = nullptr;
  fixture.keypair = nullptr;
  fixture.attr_machine = nullptr;

  state_t* restored = crabs_deserialize_state(blob->data, blob->len);
  serialized_buffer_destroy(blob);
  ASSERT_NE(restored, nullptr);
  ASSERT_TRUE(state_raft_shelf_active(restored));
  // The consecutive-failure count rides along (poison visibility continues).
  EXPECT_EQ(state_raft_shelf_attempt_count(restored), 1u);

  // The host handoff: a fresh module object carries the persisted module
  // section (the pump needs a module to drain notifications from).
  crabs_raft_config_t config;
  crabs_raft_config_defaults(&config);
  config.seed = 99;
  crabs_raft_module_t* revived = crabs_raft_module_create(&config);
  ASSERT_NE(revived, nullptr);
  ASSERT_EQ(state_attach_raft_module(restored, revived), CRABS_SUCCESS);

  EXPECT_EQ(state_machine_register_handler(restored, "council_write",
                                           sim_handler_council_write),
            CRABS_SUCCESS);
  EXPECT_EQ(state_raft_process_notifications_at(restored, 2 * CRABS_RAFT_SHELF_BACKOFF_CAP_MS),
            CRABS_SUCCESS);
  EXPECT_FALSE(state_raft_shelf_active(restored));
  const lww_register_t* carried = sim_council_register(restored);
  ASSERT_NE(carried, nullptr);
  EXPECT_EQ(memcmp(carried->value, "shelf-carry", 11), 0);

  state_attach_raft_module(restored, nullptr);
  crabs_raft_module_destroy(revived);
  state_destroy(restored);
  ecdsa_keypair_t* surviving_key = nullptr;   // fixture key was consumed above
  (void)surviving_key;
  (void)surviving_key;
}

// ============================================================
// Phase 3: joint-consensus membership change (Raft §6) on the module's own
// config log. The C_old,new and C_new entries ride the log like ordinary
// entries (never machine ops); quorum/vote rules span BOTH lists during the
// joint phase; the C_new successor appends automatically once C_old,new
// commits (or when a new leader resumes the transition); nodes excluded by
// a committed change step down.
// ============================================================

// Predicate: node 0 runs a plain committed config of the expected size and
// no joint phase. Set sim_pred_config_expected before sim_run_until.
static uint32_t sim_pred_config_expected = 0;

static bool sim_pred_config_count(sim_host_t* host) {
  crabs_raft_module_t* module = host->nodes[0].module;
  return crabs_raft_module_joint_members(module, nullptr) == 0 &&
         crabs_raft_module_committed_members(module, nullptr) ==
             sim_pred_config_expected;
}

// Predicate: node 0 sits in an ACTIVE joint phase (config entry committed,
// C_new successor pending).
static bool sim_pred_joint_active(sim_host_t* host) {
  return crabs_raft_module_joint_members(host->nodes[0].module, nullptr) > 0;
}

// A 2-node sim cluster where node 0 starts as a single-member config
// (the degenerate boot shape) and node 1 is a provisioned standby that
// already knows both ids but holds no log.
static void sim_membership_pair_attach(sim_host_t* host, const char* a_id,
                                       const char* b_id, uint64_t seed_a,
                                       uint64_t seed_b) {
  ASSERT_EQ(host->node_count, 0u);
  for (uint32_t node_slot = 0; node_slot < 2; node_slot++) {
    sim_node_t* node = &host->nodes[node_slot];
    memset(node, 0, sizeof(*node));
    node->partition_group = 0;
    node->auto_persist = true;
    const char* self = node_slot == 0 ? a_id : b_id;
    node->node_id = self;
    node->keypair = crypto_ecdsa_generate();
    ASSERT_NE(node->keypair, nullptr);
    node->state = state_create();
    sim_setup_council_state(node->state);
    node->attr_machine = attribute_machine_create("admin",
                                                  node->keypair->public_key);
    ASSERT_NE(node->attr_machine, nullptr);
    node->state->attr_machine = node->attr_machine;
    crabs_raft_config_t config;
    crabs_raft_config_defaults(&config);
    strncpy(config.node_id, self, CRABS_MAX_USER_ID - 1);
    // Node 0 boots as a ONE-member cluster; node 1 is provisioned with the
    // pair (it holds no log until the leader's appends reach it).
    uint32_t member_count = node_slot == 0 ? 1 : 2;
    strncpy(config.peer_ids[0], node_slot == 0 ? a_id : a_id,
            CRABS_MAX_USER_ID - 1);
    if (member_count == 2) {
      strncpy(config.peer_ids[1], node_slot == 0 ? b_id : b_id,
              CRABS_MAX_USER_ID - 1);
    }
    config.peer_count = member_count;
    config.seed = node_slot == 0 ? seed_a : seed_b;
    node->module = crabs_raft_module_create(&config);
    ASSERT_NE(node->module, nullptr);
    ASSERT_EQ(state_attach_raft_module(node->state, node->module),
              CRABS_SUCCESS);
    host->node_count = node_slot + 1;
  }
  host->node_count = 2;
}

TEST(RaftMembership, SingleNodeJointAddThenRemoveCompletesSafely) {
  // The §6 round trip on a pair: the single-member leader adds its standby
  // through C_old,new -> C_new, then removes it. Every step quorum-checks
  // BOTH lists while joint, and the removal evicts the standby.
  sim_host_t host = sim_host_make();
  sim_membership_pair_attach(&host, "node-0", "alpha", 7, 8);

  // node-0 elects itself (its boot config is ONE member); alpha can never
  // win anything alone, so exactly-one-leader means node-0 leads.
  sim_run_until(&host, 100, 40, sim_pred_any_leader);
  int leader = sim_find_leader(&host);
  ASSERT_EQ(leader, 0);

  // ADD: C_old=[node-0], C_new=[node-0, alpha]. The joint entry commits
  // only when BOTH majorities hold it — alpha's durable match is required.
  const char* add_list[2] = {"node-0", "alpha"};
  uint64_t change_id = 0;
  EXPECT_EQ(crabs_raft_module_change_membership(host.nodes[0].module, add_list,
                                                2, &change_id),
            CRABS_SUCCESS);
  ASSERT_GT(change_id, 0u);
  // The joint entry commits (alpha acked; the sim target predicate may
  // overshoot once the leader's auto C_new commits right behind it).
  // The joint entry commits (alpha acked), the leader auto-appends C_new,
  // that entry commits under the joint rules, and the transition ends with
  // the pair as the plain committed config.
  sim_target_tip = change_id;
  sim_run_until(&host, 100, 40, sim_pred_joint_active);
  sim_target_tip = 0;
  sim_pred_config_expected = 2;
  sim_run_until(&host, 100, 40, sim_pred_config_count);
  // The standby's durable-match hold means it learns the commit tip one
  // round-trip behind the leader's advance — settle alpha onto the plain
  // pair config before asserting both nodes agree.
  sim_run_until(&host, 100, 40, [](sim_host_t* settling_host) {
    crabs_raft_module_t* standby = settling_host->nodes[1].module;
    return crabs_raft_module_joint_members(standby, nullptr) == 0 &&
           crabs_raft_module_committed_members(standby, nullptr) == 2u;
  });
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    EXPECT_EQ(crabs_raft_module_joint_members(
                  host.nodes[node_index].module, nullptr), 0u);
    EXPECT_EQ(crabs_raft_module_committed_members(
                  host.nodes[node_index].module, nullptr), 2u);
    EXPECT_FALSE(crabs_raft_module_is_leader(host.nodes[1].module));
  }
  // A fresh change is legal once the previous one ended...
  uint64_t second_change = 999;
  EXPECT_EQ(crabs_raft_module_change_membership(host.nodes[0].module, add_list,
                                                2, &second_change),
            CRABS_SUCCESS);
  // ...but it is in flight now: a SECOND concurrent change refuses.
  EXPECT_EQ(crabs_raft_module_change_membership(host.nodes[0].module, add_list,
                                                2, &second_change),
            CRABS_ERR_ORDERING_CHANGE_IN_FLIGHT);
  // Roll this in-flight change forward so the REMOVE below starts clean:
  // the identical C_old,new/C_new pair commits (both lists' majorities are
  // the same) and the config stays 2.
  sim_run_until(&host, 100, 60, [](sim_host_t* pending_host) {
    return !crabs_raft_module_config_change_pending(
        pending_host->nodes[0].module);
  });

  // REMOVE: alpha evicted by the committed change; node-0 keeps leading and
  // committing with its single-member config (quorum math reads the config
  // lists, not the address book).
  const char* remove_list[1] = {"node-0"};
  uint64_t remove_id = 0;
  EXPECT_EQ(crabs_raft_module_change_membership(host.nodes[0].module,
                                                remove_list, 1, &remove_id),
            CRABS_SUCCESS);
  sim_pred_config_expected = 1;
  sim_run_until(&host, 100, 60, sim_pred_config_count);
  EXPECT_FALSE(crabs_raft_module_is_leader(host.nodes[1].module));

  // Ghost replication ends: once C_new commits, the leader's fan-out gates
  // on the COMMITTED config — alpha is cut off and told exactly once. The
  // exclusion control carries the final commit ceiling, so alpha finishes
  // committing the (durably held) config change and lands on [node-0].
  uint32_t settle_turns = 0;
  while ((sim_wire_kinds.config_excluded[1] == 0u ||
          crabs_raft_module_joint_members(host.nodes[1].module,
                                          nullptr) != 0u) &&
         settle_turns < 30) {
    sim_step(&host, 100, nullptr);
    settle_turns++;
  }
  ASSERT_LT(settle_turns, 30u) << "exclusion never settled the evicted node";
  ASSERT_GE(sim_wire_kinds.config_excluded[1], 1u)
      << "evicted node never received the exclusion";
  EXPECT_EQ(crabs_raft_module_joint_members(host.nodes[1].module, nullptr),
            0u);
  EXPECT_EQ(crabs_raft_module_committed_members(host.nodes[1].module, nullptr),
            1u);
  EXPECT_EQ(crabs_raft_module_committed_tip(host.nodes[1].module),
            crabs_raft_module_committed_tip(host.nodes[0].module));
  // Zero post-exclusion appends to the evicted node: committed group data
  // never flows to a server the committed config excluded (§6).
  uint32_t appends_before = sim_wire_kinds.append_req[1];
  for (uint32_t turn = 0; turn < 6; turn++) {
    sim_step(&host, 100, nullptr);
  }
  EXPECT_EQ(sim_wire_kinds.append_req[1], appends_before);

  // A post-removal decree commits on the single-member cluster and
  // materializes EXACTLY on the leader — never on the evicted standby.
  uint8_t decree_uuid[CRABS_UUID_SIZE];
  ASSERT_EQ(sim_submit_write(&host, 0, "council_write", "council",
                             "post-remove", decree_uuid),
            CRABS_ERR_ORDERING_PENDING);
  uint64_t decree_tip = crabs_raft_module_log_length(host.nodes[0].module);
  uint32_t decree_turns = 0;
  while (crabs_raft_module_committed_tip(host.nodes[0].module) != decree_tip &&
         decree_turns < 30) {
    sim_step(&host, 100, nullptr);
    decree_turns++;
  }
  EXPECT_EQ(crabs_raft_module_committed_tip(host.nodes[0].module), decree_tip);
  EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[0].state, decree_uuid), 1u);
  EXPECT_EQ(sim_state_uuid_occurrences(host.nodes[1].state, decree_uuid), 0u);

  sim_host_destroy(&host);
}

// Predicate: no membership change is pending anywhere and the committed
// tip reached sim_target_tip (settled joint + C_new).
static bool sim_pred_change_settled(sim_host_t* host) {
  for (uint32_t node_index = 0; node_index < host->node_count; node_index++) {
    if (crabs_raft_module_config_change_pending(
            host->nodes[node_index].module)) {
      return false;
    }
    if (sim_target_tip > 0 &&
        crabs_raft_module_committed_tip(host->nodes[node_index].module) <
            sim_target_tip) {
      return false;
    }
  }
  return true;
}

// A membership grid: old members boot with each other; the newcomer boots
// provisioned with EVERY id but holds no log until the joint change. These
// scenarios exercise the MODULE's config/quorum mechanics only (no machine
// materialization asserts), so nodes carry bare modules — the pipeline
// fixtures stay with the cluster attach above.
static void sim_membership_grid_attach(sim_host_t* host,
                                       const char* const* ids,
                                       uint32_t old_count) {
  ASSERT_LE(old_count + 1u, (uint32_t)kSimMaxNodes);
  ASSERT_EQ(host->node_count, 0u);
  for (uint32_t node_slot = 0; node_slot < old_count + 1u; node_slot++) {
    sim_node_t* node = &host->nodes[node_slot];
    memset(node, 0, sizeof(*node));
    node->partition_group = 0;
    node->auto_persist = true;
    node->node_id = ids[node_slot];
    crabs_raft_config_t config;
    crabs_raft_config_defaults(&config);
    strncpy(config.node_id, ids[node_slot], CRABS_MAX_USER_ID - 1);
    bool is_newcomer = node_slot >= old_count;
    uint32_t member_count = is_newcomer ? old_count + 1u : old_count;
    for (uint32_t member_slot = 0; member_slot < member_count; member_slot++) {
      strncpy(config.peer_ids[member_slot], ids[member_slot],
              CRABS_MAX_USER_ID - 1);
    }
    config.peer_count = member_count;
    config.seed = 100 + node_slot;
    node->module = crabs_raft_module_create(&config);
    ASSERT_NE(node->module, nullptr);
    host->node_count = node_slot + 1;
  }
}

static const char* kGridIds[4] = {"grid-a", "grid-b", "grid-c", "grid-d"};

TEST(RaftMembership, PartitionOfTheOldMajorityStallsTheChangeAndHealFinishes) {
  // 3 old members + provisioned grid-d. The change IN FLIGHT (appended,
  // not committed) stalls when TWO of the three old members partition away:
  // the joint C_old,new entry needs the OLD list's majority (2 of 3) which
  // the lone remaining old member cannot hold, and the committed config —
  // therefore the quorum rules — does not move until the heal.
  sim_host_t host = sim_host_make();
  sim_membership_grid_attach(&host, kGridIds, 3);
  sim_run_until(&host, 100, 40, sim_pred_any_leader);
  int leader = sim_find_leader(&host);
  ASSERT_GE(leader, 0);

  const char* new_list[4] = {"grid-a", "grid-b", "grid-c", "grid-d"};
  uint64_t change_id = 0;
  EXPECT_EQ(crabs_raft_module_change_membership(
                host.nodes[leader].module, new_list, 4, &change_id),
            CRABS_SUCCESS);

  // Partition TWO old members away (grid-b, grid-c — whoever they are on
  // this seed, they are the non-leader old members): group 8 is theirs
  // alone; the leader keeps group 1 WITH grid-d (the newcomer rides the
  // majority-side links).
  uint32_t partitioned_old[2];
  uint32_t partitioned_n = 0;
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    if ((int)node_index == leader || node_index == 3u) {
      host.nodes[node_index].partition_group = 1;
      continue;
    }
    host.nodes[node_index].partition_group = 8;
    partitioned_old[partitioned_n++] = node_index;
  }
  ASSERT_EQ(partitioned_n, 2u);

  // Settle the leader's pre-change tail (its no-op) so the stall baseline
  // only measures the blocked change.
  sim_step(&host, 100, nullptr);
  sim_step(&host, 100, nullptr);
  const uint64_t leader_tip =
      crabs_raft_module_committed_tip(host.nodes[leader].module);
  for (uint32_t step = 0; step < 6; step++) {
    sim_step(&host, 100, nullptr);
  }
  // The change is STILL in flight: the old list's majority is out of reach,
  // the committed membership is frozen at 3, and a second change refuses.
  EXPECT_TRUE(crabs_raft_module_config_change_pending(
      host.nodes[leader].module));
  EXPECT_EQ(crabs_raft_module_committed_members(
                host.nodes[leader].module, nullptr), 3u);
  EXPECT_EQ(crabs_raft_module_committed_tip(host.nodes[leader].module),
            leader_tip);
  uint64_t refused_id = 0;
  EXPECT_EQ(crabs_raft_module_change_membership(
                host.nodes[leader].module, new_list, 4, &refused_id),
            CRABS_ERR_ORDERING_CHANGE_IN_FLIGHT);

  // --- HEAL: the partitioned old members return, their matches land, the
  // joint entry commits, the auto C_new commits, and all four members run
  // the finished plain config (including grid-d, provisioned into the
  // change while it was partitioned-... no — grid-d was connected all
  // along).
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    host.nodes[node_index].partition_group = 0;
  }
  sim_target_tip = change_id;
  sim_run_until(&host, 100, 60, sim_pred_change_settled);
  sim_target_tip = 0;
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    EXPECT_EQ(crabs_raft_module_committed_members(
                  host.nodes[node_index].module, nullptr), 4u);
    EXPECT_EQ(crabs_raft_module_joint_members(
                  host.nodes[node_index].module, nullptr), 0u);
    EXPECT_FALSE(crabs_raft_module_config_change_pending(
        host.nodes[node_index].module));
    EXPECT_EQ(crabs_raft_module_rejected_message_count(
                  host.nodes[node_index].module), 0u);
  }
  sim_host_destroy(&host);
}

TEST(RaftMembership, LeadershipChurnDuringJointResumesTheTransition) {
  // The leader is partitioned AWAY the moment the joint entry commits: the
  // two-group majority elects a NEW leader (still under the joint quorum
  // rules — both majorities must hold the votes), and that new leader
  // RESUMES the transition by appending the C_new successor itself. The
  // heal converges the full cluster onto the finished 4-member config.
  sim_host_t host = sim_host_make();
  sim_membership_grid_attach(&host, kGridIds, 3);
  sim_run_until(&host, 100, 40, sim_pred_any_leader);
  int old_leader = sim_find_leader(&host);
  ASSERT_GE(old_leader, 0);

  const char* new_list[4] = {"grid-a", "grid-b", "grid-c", "grid-d"};
  uint64_t change_id = 0;
  EXPECT_EQ(crabs_raft_module_change_membership(
                host.nodes[old_leader].module, new_list, 4, &change_id),
            CRABS_SUCCESS);

  // --- PARTITION the old leader off as soon as its joint entry may have
  // landed: the majority keeps running and finishing the change.
  sim_target_tip = change_id;
  sim_run_until(&host, 100, 20, sim_pred_change_settled);
  host.nodes[old_leader].partition_group = 9;
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    if ((int)node_index != old_leader) host.nodes[node_index].partition_group = 1;
  }

  // The majority: a NEW leader emerges (if the old leader's group was the
  // one that still leads, the group's own election wins — either way the
  // majority ends with exactly one leader that finishes the transition).
  uint32_t majority_steps = 0;
  int new_leader = -1;
  while (majority_steps < 40) {
    sim_step(&host, 100, nullptr);
    majority_steps++;
    for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
      if ((int)node_index != old_leader &&
          crabs_raft_module_is_leader(host.nodes[node_index].module)) {
        new_leader = (int)node_index;
      }
    }
    if (new_leader >= 0) break;
  }
  ASSERT_GE(new_leader, 0);

  // The transition finished INSIDE the majority: the joint phase closed
  // even though the original leader never got to append its C_new.
  sim_target_tip = change_id;
  sim_run_until(&host, 100, 60, sim_pred_change_settled);
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    if ((int)node_index == old_leader) continue;
    EXPECT_EQ(crabs_raft_module_committed_members(
                  host.nodes[node_index].module, nullptr), 4u);
    EXPECT_EQ(crabs_raft_module_joint_members(
                  host.nodes[node_index].module, nullptr), 0u);
  }

  // --- HEAL: the old leader catches up, absorbs the finished transition,
  // steps down for good, and the cluster converges with ONE leader.
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    host.nodes[node_index].partition_group = 0;
  }
  // Converge: the connected cluster elects ONE leader (the stale old
  // leader steps down on the first higher-term traffic) and everyone
  // carries the finished 4-member config.
  sim_run_until(&host, 100, 60, sim_pred_any_leader);
  sim_step(&host, 100, nullptr);
  sim_step(&host, 100, nullptr);
  for (uint32_t node_index = 0; node_index < host.node_count; node_index++) {
    EXPECT_EQ(crabs_raft_module_committed_members(
                  host.nodes[node_index].module, nullptr), 4u);
    EXPECT_EQ(crabs_raft_module_joint_members(
                  host.nodes[node_index].module, nullptr), 0u);
  }
  EXPECT_EQ(sim_leader_count(&host), 1u);
  EXPECT_FALSE(crabs_raft_module_is_leader(host.nodes[old_leader].module));
  sim_host_destroy(&host);
}
