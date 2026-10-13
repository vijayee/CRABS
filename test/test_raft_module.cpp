//
// Raft ordering module — Phase 1: reactor lifecycle, persistence contract,
// fail-closed message discipline, v16 module-section round-trip, and the
// degenerate single-node commit path.
//

#include <gtest/gtest.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "Raft/raft_module.h"
#include "CRABS/data_model.h"
#include "StateMachine/state_machine.h"
#include "Serialization/serialization.h"
#include "Crypto/crypto.h"
#include "Util/allocator.h"
#include "test_helpers.h"
}

// ============================================================
// Fixtures
// ============================================================
static crabs_raft_config_t make_single_config(uint64_t seed, uint8_t module_id) {
  crabs_raft_config_t config;
  crabs_raft_config_defaults(&config);
  config.seed = seed;
  config.module_id = module_id;
  return config;
}

static operation_t* make_signed_op(const char* op_type, const char* signer,
                                   const uint8_t* payload, uint32_t payload_len) {
  operation_t* op = operation_create(op_type);
  if (op == nullptr) return nullptr;
  strncpy(op->signer_id, signer, CRABS_MAX_USER_ID - 1);
  op->payload_size = payload_len;
  op->payload = (uint8_t*)get_memory(payload_len > 0 ? payload_len : 1);
  if (payload_len > 0) memcpy(op->payload, payload, payload_len);
  op->lamport_time = 1;
  return op;
}

// Drain all notifications, returning the COMITTED ones for assertions.
static std::vector<crabs_raft_notification_t> drain_committed(
    crabs_raft_module_t* module) {
  std::vector<crabs_raft_notification_t> committed;
  crabs_raft_notification_t notification;
  while (crabs_raft_module_poll_notification(module, &notification)) {
    if (notification.kind == RAFT_NOTIFY_COMMITTED_OP) {
      committed.push_back(notification);
    }
  }
  return committed;
}

static void drain_all_notifications(crabs_raft_module_t* module) {
  crabs_raft_notification_t notification;
  while (crabs_raft_module_poll_notification(module, &notification)) {
  }
}

static void drive_to_leader(crabs_raft_module_t* module, uint64_t* now_ms) {
  while (!crabs_raft_module_is_leader(module)) {
    *now_ms += 1;
    ASSERT_EQ(crabs_raft_module_tick(module, *now_ms), CRABS_SUCCESS);
    ASSERT_LT(*now_ms, 100000u);   // never spin forever on a broken timer
  }
}

TEST(RaftModuleLifecycle, DefaultsCreateDegenerateSingleNode) {
  crabs_raft_config_t config;
  crabs_raft_config_defaults(&config);
  EXPECT_STREQ(config.node_id, "node-0");
  EXPECT_EQ(config.peer_count, 1u);

  crabs_raft_module_t* module = crabs_raft_module_create(nullptr);
  ASSERT_NE(module, nullptr);
  EXPECT_FALSE(crabs_raft_module_is_leader(module));
  EXPECT_EQ(crabs_raft_module_committed_tip(module), 0u);
  EXPECT_EQ(crabs_raft_module_current_term(module), 0u);
  EXPECT_EQ(crabs_raft_module_log_length(module), 0u);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(module), 0u);
  crabs_raft_module_destroy(module);

  // A config with 0 peers, an over-cap peer table, or a node outside its
  // own cluster is refused.
  crabs_raft_config_t broken = make_single_config(0, 0);
  broken.peer_count = 0;
  EXPECT_EQ(crabs_raft_module_create(&broken), nullptr);
  broken = make_single_config(0, 0);
  strncpy(broken.node_id, "loner", CRABS_MAX_USER_ID - 1);
  EXPECT_EQ(crabs_raft_module_create(&broken), nullptr);
}

// Same seed → same randomized election deadline: the determinism contract
// the simulation harness leans on.
TEST(RaftModuleLifecycle, RandomizedTimeoutsAreDeterministicPerSeed) {
  for (int seed = 0; seed < 8; seed++) {
    crabs_raft_config_t config_a = make_single_config(seed, 0);
    crabs_raft_config_t config_b = make_single_config(seed, 0);
    crabs_raft_module_t* module_a = crabs_raft_module_create(&config_a);
    crabs_raft_module_t* module_b = crabs_raft_module_create(&config_b);
    ASSERT_NE(module_a, nullptr);
    ASSERT_NE(module_b, nullptr);
    EXPECT_EQ(crabs_raft_module_next_election_deadline(module_a),
              crabs_raft_module_next_election_deadline(module_b));
    EXPECT_GE(crabs_raft_module_next_election_deadline(module_a),
              CRABS_RAFT_ELECTION_TIMEOUT_MIN_MS);
    crabs_raft_module_destroy(module_a);
    crabs_raft_module_destroy(module_b);
  }
}

TEST(RaftModuleLifecycle, TickPastDeadlineElectsSelfWithoutVoteExchange) {
  crabs_raft_config_t config = make_single_config(7, 0);
  crabs_raft_module_t* module = crabs_raft_module_create(&config);
  ASSERT_NE(module, nullptr);

  uint64_t now_ms = 0;
  uint64_t deadline = crabs_raft_module_next_election_deadline(module);
  // One tick BEFORE the deadline changes nothing; the tick AT the deadline
  // self-elects with no outbound vote traffic at all.
  EXPECT_EQ(crabs_raft_module_tick(module, deadline - 1), CRABS_SUCCESS);
  EXPECT_FALSE(crabs_raft_module_is_leader(module));
  EXPECT_EQ(crabs_raft_module_current_term(module), 0u);

  EXPECT_EQ(crabs_raft_module_tick(module, deadline), CRABS_SUCCESS);
  EXPECT_TRUE(crabs_raft_module_is_leader(module));
  EXPECT_EQ(crabs_raft_module_current_term(module), 1u);

  crabs_raft_notification_t notification;
  ASSERT_TRUE(crabs_raft_module_poll_notification(module, &notification));
  EXPECT_EQ(notification.kind, RAFT_NOTIFY_BECAME_LEADER);
  EXPECT_FALSE(crabs_raft_module_poll_notification(module, &notification));

  crabs_raft_outbound_message_t outbound;
  EXPECT_FALSE(crabs_raft_module_poll_outbound(module, &outbound));

  crabs_raft_module_destroy(module);
}

// The full degenerate path: propose → persist request → (and ONLY after)
// persist_complete(true) → commit tip advances → COMMITTED_OP carries the op
// wire.
TEST(RaftSingleNodeCommit, ProposePersistsThenCommits) {
  crabs_raft_config_t config = make_single_config(42, 0);
  crabs_raft_module_t* module = crabs_raft_module_create(&config);
  ASSERT_NE(module, nullptr);
  uint64_t now_ms = 0;
  drive_to_leader(module, &now_ms);

  const char* payload = "mint-one";
  operation_t* op = make_signed_op("mint", "admin",
                                   (const uint8_t*)payload,
                                   (uint32_t)strlen(payload));
  ASSERT_NE(op, nullptr);

  uint64_t proposal_id = 0;
  EXPECT_EQ(crabs_raft_module_propose(module, op, &proposal_id),
            CRABS_SUCCESS);
  operation_destroy(op);
  EXPECT_EQ(proposal_id, 1u);
  EXPECT_EQ(crabs_raft_module_log_length(module), 1u);
  // Nothing counts for commit before the host acked durability.
  EXPECT_EQ(crabs_raft_module_committed_tip(module), 0u);

  // The persist event exists IMMEDIATELY (no tick required).
  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist));
  EXPECT_EQ(persist.handle, 1u);
  ASSERT_GE(persist.len, 4u);

  // The same outstanding request is reported until completion (single
  // window): the blob pointer is stable.
  crabs_raft_persist_request_t persist_again;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist_again));
  EXPECT_EQ(persist_again.handle, persist.handle);
  EXPECT_EQ(persist_again.bytes, persist.bytes);

  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist.handle, true),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(module), 1u);

  std::vector<crabs_raft_notification_t> committed = drain_committed(module);
  ASSERT_EQ(committed.size(), 1u);
  EXPECT_EQ(committed[0].proposal_id, 1u);
  EXPECT_EQ(committed[0].commit_index, 1u);
  ASSERT_NE(committed[0].op_bytes, nullptr);
  operation_t* restored = crabs_deserialize_operation(committed[0].op_bytes,
                                                      committed[0].op_len);
  ASSERT_NE(restored, nullptr);
  EXPECT_STREQ(restored->type, "mint");
  EXPECT_EQ(restored->payload_size, strlen(payload));
  EXPECT_EQ(memcmp(restored->payload, payload, strlen(payload)), 0);
  operation_destroy(restored);

  // The window is free again; a second proposal rides a new handle.
  op = make_signed_op("mint", "admin", (const uint8_t*)"mint-two", 8);
  ASSERT_NE(op, nullptr);
  EXPECT_EQ(crabs_raft_module_propose(module, op, &proposal_id),
            CRABS_SUCCESS);
  operation_destroy(op);
  EXPECT_EQ(proposal_id, 2u);
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist));
  EXPECT_EQ(persist.handle, 2u);
  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist.handle, true),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(module), 2u);
  committed = drain_committed(module);
  ASSERT_EQ(committed.size(), 1u);
  EXPECT_EQ(committed[0].proposal_id, 2u);

  // Stale handles (already resolved, or unknown) refuse loudly.
  crabs_raft_persist_request_t empty;
  EXPECT_FALSE(crabs_raft_module_poll_persist(module, &empty));
  EXPECT_EQ(crabs_raft_module_persist_complete(module, 99, true),
            CRABS_ERR_INVALID_PARAM);

  crabs_raft_module_destroy(module);
}

// The durability contract's failure side: persist_complete(false) makes
// NOTHING durable — the commit tip and the log stay put, a PERSIST_FAILED
// notification surfaces, and the batch retries on the next tick.
TEST(RaftSingleNodeCommit, FailedPersistNeverCommitsAndRetries) {
  crabs_raft_config_t config = make_single_config(42, 0);
  crabs_raft_module_t* module = crabs_raft_module_create(&config);
  ASSERT_NE(module, nullptr);
  uint64_t now_ms = 0;
  drive_to_leader(module, &now_ms);
  drain_all_notifications(module);

  operation_t* op = make_signed_op("mint", "admin", (const uint8_t*)"x", 1);
  ASSERT_NE(op, nullptr);
  uint64_t proposal_id = 0;
  EXPECT_EQ(crabs_raft_module_propose(module, op, &proposal_id), CRABS_SUCCESS);
  operation_destroy(op);

  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist));
  // Copy the batch bytes BEFORE completing: the blob is module-owned and is
  // released when the window resolves.
  std::vector<uint8_t> stored_batch(persist.bytes,
                                    persist.bytes + persist.len);
  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist.handle, false),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(module), 0u);

  crabs_raft_notification_t notification;
  ASSERT_TRUE(crabs_raft_module_poll_notification(module, &notification));
  EXPECT_EQ(notification.kind, RAFT_NOTIFY_PERSIST_FAILED);

  // The tick re-arms persistence for the undurable tail with a fresh handle.
  now_ms++;
  EXPECT_EQ(crabs_raft_module_tick(module, now_ms), CRABS_SUCCESS);
  crabs_raft_persist_request_t retry;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &retry));
  EXPECT_EQ(retry.handle, persist.handle + 1);
  // Same batch bytes: the undurable tail re-issues unchanged.
  EXPECT_EQ(retry.len, stored_batch.size());
  EXPECT_EQ(memcmp(retry.bytes, stored_batch.data(), stored_batch.size()), 0);
  EXPECT_EQ(crabs_raft_module_persist_complete(module, retry.handle, true),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(module), 1u);
  EXPECT_EQ(drain_committed(module).size(), 1u);

  crabs_raft_module_destroy(module);
}

// A proposal reaching a non-leader is refused and surfaces via notification;
// the log stays untouched.
TEST(RaftProposalGate, NonLeaderProposalRefused) {
  crabs_raft_config_t config = make_single_config(42, 0);
  crabs_raft_module_t* module = crabs_raft_module_create(&config);
  ASSERT_NE(module, nullptr);

  operation_t* op = make_signed_op("mint", "admin", (const uint8_t*)"x", 1);
  ASSERT_NE(op, nullptr);
  uint64_t proposal_id = 123;
  EXPECT_EQ(crabs_raft_module_propose(module, op, &proposal_id),
            CRABS_ERR_ORDERING_NOT_LEADER);
  operation_destroy(op);
  EXPECT_EQ(proposal_id, 0u);
  EXPECT_EQ(crabs_raft_module_log_length(module), 0u);

  crabs_raft_notification_t notification;
  ASSERT_TRUE(crabs_raft_module_poll_notification(module, &notification));
  EXPECT_EQ(notification.kind, RAFT_NOTIFY_PROPOSAL_NOT_LEADER);
  crabs_raft_module_destroy(module);
}

// Bounded log: an op whose serialized wire exceeds the per-entry cap is
// refused; the module stays healthy.
TEST(RaftProposalGate, OverCapOpWireRefused) {
  crabs_raft_config_t config = make_single_config(42, 0);
  crabs_raft_module_t* module = crabs_raft_module_create(&config);
  ASSERT_NE(module, nullptr);
  uint64_t now_ms = 0;
  drive_to_leader(module, &now_ms);

  std::vector<uint8_t> oversized(CRABS_RAFT_MAX_OP_WIRE_BYTES + 64, 0xAB);
  operation_t* op = make_signed_op("mint", "admin", oversized.data(),
                                   (uint32_t)oversized.size());
  ASSERT_NE(op, nullptr);
  uint64_t proposal_id = 5;
  EXPECT_EQ(crabs_raft_module_propose(module, op, &proposal_id),
            CRABS_ERR_SERIALIZATION_ERROR);
  operation_destroy(op);
  EXPECT_EQ(proposal_id, 0u);
  EXPECT_EQ(crabs_raft_module_log_length(module), 0u);
  crabs_raft_module_destroy(module);
}

// ============================================================
// Message discipline: malformed inbound is dropped fail-closed
// ============================================================
static void expect_rejected(crabs_raft_module_t* module, const char* peer_id,
                            const std::vector<uint8_t>& blob) {
  uint32_t before = crabs_raft_module_rejected_message_count(module);
  bool was_leader = crabs_raft_module_is_leader(module);
  uint64_t tip = crabs_raft_module_committed_tip(module);
  // An empty vector hands data() == nullptr to the C API: back it with a
  // real (zero-length) buffer so the module sees a message body, not a
  // NULL parameter.
  static uint8_t empty_placeholder;
  const uint8_t* blob_bytes = blob.empty() ? &empty_placeholder : blob.data();
  EXPECT_EQ(crabs_raft_module_inbound(module, peer_id, blob_bytes, blob.size(), 0),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(module), before + 1);
  EXPECT_EQ(crabs_raft_module_is_leader(module), was_leader);
  EXPECT_EQ(crabs_raft_module_committed_tip(module), tip);
}

TEST(RaftInboundDiscipline, MalformedMessagesDropWithoutStateCorruption) {
  crabs_raft_config_t config = make_single_config(42, 0);
  strncpy(config.node_id, "nodeA", CRABS_MAX_USER_ID - 1);
  strncpy(config.peer_ids[0], "nodeA", CRABS_MAX_USER_ID - 1);

  crabs_raft_module_t* module = crabs_raft_module_create(&config);
  ASSERT_NE(module, nullptr);

  // Empty, NULL-ish and unknown-peer messages count as rejects.
  expect_rejected(module, "nodeA", {});
  expect_rejected(module, "stranger", {0x52, 0x01, 0x01});

  // Garbage bytes.
  expect_rejected(module, "nodeA", {0x01, 0x02, 0x03});
  // Right magic, wrong version.
  expect_rejected(module, "nodeA", {0x52, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  // Unknown kind.
  expect_rejected(module, "nodeA", {0x52, 0x01, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  // Truncated header.
  expect_rejected(module, "nodeA", {0x52, 0x01, 0x01, 0});
  // Vote request with an empty candidate id.
  expect_rejected(module, "nodeA",
                  {0x52, 0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00});
  // Vote request whose candidate string overruns the wire.
  expect_rejected(module, "nodeA",
                  {0x52, 0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 'x'});
  // Vote response truncation.
  expect_rejected(module, "nodeA", {0x52, 0x01, 0x02, 0, 0, 0, 0, 0, 0, 0, 0});
  // Append response truncation.
  expect_rejected(module, "nodeA",
                  {0x52, 0x01, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 1});
  // Append request with an empty leader id.
  expect_rejected(module, "nodeA",
                  {0x52, 0x01, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00});
  // Append request from an unknown peer id.
  expect_rejected(module, "nodeA",
                  {0x52, 0x01, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 'z'});

  // NULL blob with positive length is a parameter error (not a reject).
  uint32_t before = crabs_raft_module_rejected_message_count(module);
  EXPECT_EQ(crabs_raft_module_inbound(module, "nodeA", nullptr, 4, 0),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(module), before);

  // Fuzz-lite: 200 random blobs — the module must survive all of them.
  for (int round = 0; round < 200; round++) {
    size_t blob_len = (size_t)(1 + (round % 40));
    std::vector<uint8_t> blob(blob_len, (uint8_t)(0x52 ^ round));
    for (size_t byte_index = 0; byte_index < blob_len; byte_index++) {
      blob[byte_index] = (uint8_t)((round * 31 + byte_index * 7) & 0xFF);
    }
    EXPECT_EQ(crabs_raft_module_inbound(module, "nodeA", blob.data(),
                                        blob.size(), 0), CRABS_SUCCESS);
  }
  EXPECT_GT(crabs_raft_module_rejected_message_count(module), 0u);

  // Still an intact follower with empty queues.
  crabs_raft_persist_request_t persist;
  EXPECT_FALSE(crabs_raft_module_poll_persist(module, &persist));
  crabs_raft_module_destroy(module);
}

// Round-trip: a marshaled vote request parses cleanly on a real peer (zero
// rejections) and the answer round-trips back — the full wire path.
TEST(RaftWireRoundTrip, VoteRequestResponseBetweenTwoModules) {
  crabs_raft_config_t config_a = make_single_config(42, 0);
  crabs_raft_config_t config_b = make_single_config(42, 0);
  strncpy(config_a.node_id, "nodeA", CRABS_MAX_USER_ID - 1);
  strncpy(config_b.node_id, "nodeB", CRABS_MAX_USER_ID - 1);
  strncpy(config_a.peer_ids[0], "nodeA", CRABS_MAX_USER_ID - 1);
  strncpy(config_a.peer_ids[1], "nodeB", CRABS_MAX_USER_ID - 1);
  config_a.peer_count = 2;
  strncpy(config_b.peer_ids[0], "nodeA", CRABS_MAX_USER_ID - 1);
  strncpy(config_b.peer_ids[1], "nodeB", CRABS_MAX_USER_ID - 1);
  config_b.peer_count = 2;

  crabs_raft_module_t* module_a = crabs_raft_module_create(&config_a);
  crabs_raft_module_t* module_b = crabs_raft_module_create(&config_b);
  ASSERT_NE(module_a, nullptr);
  ASSERT_NE(module_b, nullptr);

  // A's deadline fires → candidate → vote solicitations to B.
  uint64_t deadline_a = crabs_raft_module_next_election_deadline(module_a);
  EXPECT_EQ(crabs_raft_module_tick(module_a, deadline_a), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_current_term(module_a), 1u);

  crabs_raft_outbound_message_t outbound;
  ASSERT_TRUE(crabs_raft_module_poll_outbound(module_a, &outbound));
  EXPECT_EQ(outbound.kind, RAFT_MSG_VOTE_REQ);
  EXPECT_STREQ(outbound.to_peer, "nodeB");

  // B (still term 0 follower) grants the vote: wire parses with zero
  // rejections.
  EXPECT_EQ(crabs_raft_module_inbound(module_b, "nodeA", outbound.bytes,
                                      outbound.len, deadline_a), CRABS_SUCCESS);
  free((void*)outbound.bytes);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(module_b), 0u);
  EXPECT_EQ(crabs_raft_module_current_term(module_b), 1u);
  ASSERT_TRUE(crabs_raft_module_poll_outbound(module_b, &outbound));
  EXPECT_EQ(outbound.kind, RAFT_MSG_VOTE_RESP);
  EXPECT_STREQ(outbound.to_peer, "nodeA");
  EXPECT_EQ(outbound.bytes[11], 1);   // first body byte: vote_granted
  EXPECT_FALSE(crabs_raft_module_poll_outbound(module_b, &outbound));
  free((void*)outbound.bytes);

  crabs_raft_module_destroy(module_a);
  crabs_raft_module_destroy(module_b);
}

// Hand-marshal an APPEND_REQ (the layout is the module's public wire
// contract) and check the follower path end-to-end: append → persist window
// → durability → commit bounded by the leader's ceiling.
TEST(RaftWireRoundTrip, FollowerAppendsPersistsThenCommits) {
  crabs_raft_config_t config = make_single_config(42, 0);
  strncpy(config.node_id, "nodeF", CRABS_MAX_USER_ID - 1);
  strncpy(config.peer_ids[0], "nodeF", CRABS_MAX_USER_ID - 1);
  strncpy(config.peer_ids[1], "nodeL", CRABS_MAX_USER_ID - 1);
  config.peer_count = 2;

  crabs_raft_module_t* follower = crabs_raft_module_create(&config);
  ASSERT_NE(follower, nullptr);

  // header: magic, version(1), kind APPEND_REQ, term 5
  // body: string16 leader "nodeL", prev_term 0, prev_index 0, commit 1,
  //       entry_count 2
  std::vector<uint8_t> blob;
  auto push_u8 = [&](uint8_t value) { blob.push_back(value); };
  auto push_u64 = [&](uint64_t value) {
    for (int byte_index = 0; byte_index < 8; byte_index++) {
      push_u8((uint8_t)((value >> (byte_index * 8)) & 0xFF));
    }
  };
  auto push_u32 = [&](uint32_t value) {
    push_u8((uint8_t)(value & 0xFF));
    push_u8((uint8_t)((value >> 8) & 0xFF));
    push_u8((uint8_t)((value >> 16) & 0xFF));
    push_u8((uint8_t)((value >> 24) & 0xFF));
  };
  auto push_str16 = [&](const char* text) {
    uint16_t len = (uint16_t)strlen(text);
    push_u8((uint8_t)(len & 0xFF));
    push_u8((uint8_t)(len >> 8));
    for (uint16_t char_index = 0; char_index < len; char_index++) {
      push_u8((uint8_t)text[char_index]);
    }
  };

  push_u8(0x52); push_u8(1); push_u8(3);
  push_u64(5);
  push_str16("nodeL");
  push_u64(0);   // prev_term
  push_u64(0);   // prev_index
  push_u64(2);   // leader commit
  push_u32(2);   // entry count
  // entry 1 (term 4, wire 'op1')
  push_u64(4); push_u64(1);
  push_u32(3); push_u8('o'); push_u8('p'); push_u8('1');
  // entry 2 (term 5, wire 'op2')
  push_u64(5); push_u64(2);
  push_u32(3); push_u8('o'); push_u8('p'); push_u8('2');

  // Note: the op-wire bytes above are NOT valid CRABS op blobs — they test
  // the module's transport framing only. The follower appends, persists, and
  // commits WITHOUT interpreting op content.
  EXPECT_EQ(crabs_raft_module_inbound(follower, "nodeL", blob.data(),
                                      blob.size(), 100), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(follower), 0u);
  EXPECT_EQ(crabs_raft_module_log_length(follower), 2u);
  EXPECT_EQ(crabs_raft_module_current_term(follower), 5u);

  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(follower, &persist));
  EXPECT_EQ(persist.handle, 1u);
  // Append commit NEVER passes the follower's own durability line.
  EXPECT_EQ(crabs_raft_module_committed_tip(follower), 0u);
  EXPECT_EQ(crabs_raft_module_persist_complete(follower, persist.handle, true),
            CRABS_SUCCESS);
  // Now the leader ceiling (2) applies over the durable line (2).
  EXPECT_EQ(crabs_raft_module_committed_tip(follower), 2u);
  auto committed = drain_committed(follower);
  ASSERT_EQ(committed.size(), 2u);
  EXPECT_EQ(committed[0].proposal_id, 1u);
  EXPECT_EQ(committed[1].proposal_id, 2u);
  EXPECT_EQ(committed[1].commit_index, 2u);

  crabs_raft_module_destroy(follower);
}

// ============================================================
// v16 module section: export/import round-trip + state blob round-trip
// ============================================================
TEST(RaftPersistedState, ExportImportRoundTripSurvivesRestart) {
  crabs_raft_config_t config = make_single_config(42, 3);
  crabs_raft_module_t* module = crabs_raft_module_create(&config);
  ASSERT_NE(module, nullptr);
  uint64_t now_ms = 0;
  drive_to_leader(module, &now_ms);

  operation_t* op = make_signed_op("mint", "admin", (const uint8_t*)"one", 3);
  ASSERT_NE(op, nullptr);
  uint64_t throwaway_proposal = 0;
  EXPECT_EQ(crabs_raft_module_propose(module, op, &throwaway_proposal),
            CRABS_SUCCESS);
  EXPECT_EQ(throwaway_proposal, 1u);
  operation_destroy(op);

  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist.handle, true),
            CRABS_SUCCESS);
  drain_committed(module);

  // Export matches the live module.
  crabs_raft_module_state_t* export_a = crabs_raft_module_export_state(module);
  ASSERT_NE(export_a, nullptr);
  EXPECT_EQ(export_a->module_id, 3);
  EXPECT_EQ(export_a->term, crabs_raft_module_current_term(module));
  EXPECT_EQ(export_a->commit_index, 1u);
  EXPECT_EQ(export_a->log_count, 1u);
  ASSERT_NE(export_a->log, nullptr);
  EXPECT_EQ(export_a->log->term, 1u);
  EXPECT_EQ(export_a->log->proposal_id, 1u);
  // The entry carries the serialized OP WIRE (a full CRABS op blob), not
  // the raw payload.
  EXPECT_GT(export_a->log->wire_len, 3u);
  crabs_raft_module_state_destroy(export_a);

  // Import into a FRESH module (the restart: object recreated, state kept).
  crabs_raft_module_t* revived = crabs_raft_module_create(&config);
  ASSERT_NE(revived, nullptr);
  crabs_raft_module_state_t* export_b = crabs_raft_module_export_state(module);
  ASSERT_NE(export_b, nullptr);
  EXPECT_EQ(crabs_raft_module_import_state(revived, export_b), CRABS_SUCCESS);
  crabs_raft_module_state_destroy(export_b);
  EXPECT_EQ(crabs_raft_module_current_term(revived),
            crabs_raft_module_current_term(module));
  EXPECT_EQ(crabs_raft_module_committed_tip(revived),
            crabs_raft_module_committed_tip(module));
  EXPECT_EQ(crabs_raft_module_log_length(revived),
            crabs_raft_module_log_length(module));
  EXPECT_FALSE(crabs_raft_module_is_leader(revived));
  // Committed entries are NOT re-notified after the restart.
  crabs_raft_notification_t notification;
  EXPECT_FALSE(crabs_raft_module_poll_notification(revived, &notification));

  // Committing CONTINUES on the revived module.
  drive_to_leader(revived, &now_ms);
  op = make_signed_op("mint", "admin", (const uint8_t*)"two", 3);
  ASSERT_NE(op, nullptr);
  uint64_t proposal_id = 0;
  EXPECT_EQ(crabs_raft_module_propose(revived, op, &proposal_id), CRABS_SUCCESS);
  operation_destroy(op);
  EXPECT_EQ(proposal_id, 2u);
  ASSERT_TRUE(crabs_raft_module_poll_persist(revived, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(revived, persist.handle, true),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(revived), 2u);

  crabs_raft_module_destroy(module);
  crabs_raft_module_destroy(revived);
}

TEST(RaftPersistedState, ImportRejectsForeignAndMalformedSections) {
  crabs_raft_config_t config = make_single_config(42, 3);
  crabs_raft_module_t* module = crabs_raft_module_create(&config);
  ASSERT_NE(module, nullptr);

  crabs_raft_module_state_t foreign = {};
  foreign.module_id = 9;   // mismatch with the module's config id
  EXPECT_EQ(crabs_raft_module_import_state(module, &foreign),
            CRABS_ERR_INVALID_PARAM);

  crabs_raft_module_state_t overcap = {};
  overcap.module_id = 3;
  overcap.log_count = CRABS_RAFT_MAX_LOG_ENTRIES + 1;
  overcap.commit_index = 0;
  EXPECT_EQ(crabs_raft_module_import_state(module, &overcap),
            CRABS_ERR_INVALID_PARAM);

  crabs_raft_module_state_t ahead_commit = {};
  ahead_commit.module_id = 3;
  ahead_commit.log_count = 1;
  ahead_commit.commit_index = 2;   // commit beyond the log tail
  EXPECT_EQ(crabs_raft_module_import_state(module, &ahead_commit),
            CRABS_ERR_INVALID_PARAM);

  crabs_raft_module_destroy(module);
}

// The full state-blob round-trip: attach → commit → serialize → deserialize
// → the v16 section restores as a parse snapshot the host can import.
TEST(RaftPersistedState, MachineBlobRoundTripCarriesModuleSection) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);

  crabs_raft_config_t config = make_single_config(42, 5);
  crabs_raft_module_t* module = crabs_raft_module_create(&config);
  ASSERT_NE(module, nullptr);
  ASSERT_EQ(state_attach_raft_module(env.state, module), CRABS_SUCCESS);

  uint64_t now_ms = 0;
  drive_to_leader(module, &now_ms);
  operation_t* op = make_signed_op("mint", "admin", (const uint8_t*)"zz", 2);
  ASSERT_NE(op, nullptr);
  uint64_t proposal_id = 0;
  EXPECT_EQ(crabs_raft_module_propose(module, op, &proposal_id), CRABS_SUCCESS);
  operation_destroy(op);
  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist.handle, true),
            CRABS_SUCCESS);
  drain_committed(module);

  serialized_buffer_t* blob = crabs_serialize_state(env.state);
  ASSERT_NE(blob, nullptr);
  // Detach BEFORE destroy: the state never owns the module object.
  state_attach_raft_module(env.state, nullptr);
  state_destroy(env.state);
  crabs_raft_module_destroy(module);

  state_t* restored = crabs_deserialize_state(blob->data, blob->len);
  serialized_buffer_destroy(blob);
  ASSERT_NE(restored, nullptr);
  crabs_raft_module_state_t* parsed =
      (crabs_raft_module_state_t*)restored->raft_module_state;
  ASSERT_NE(parsed, nullptr);
  EXPECT_EQ(parsed->module_id, 5);
  EXPECT_EQ(parsed->term, 1u);
  EXPECT_EQ(parsed->commit_index, 1u);
  EXPECT_EQ(parsed->log_count, 1u);
  ASSERT_NE(parsed->log, nullptr);
  EXPECT_EQ(parsed->log->proposal_id, 1u);

  // The host handoff: create a fresh module with the SAME cfg and import.
  crabs_raft_module_t* revived_module = crabs_raft_module_create(&config);
  ASSERT_NE(revived_module, nullptr);
  EXPECT_EQ(crabs_raft_module_import_state(revived_module, parsed),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(revived_module), 1u);
  crabs_raft_module_destroy(revived_module);

  // The snapshot is state-owned: state_destroy must release it (no leak
  // under valgrind) and a NULL snapshot state must survive destroy.
  state_attach_raft_module(restored, nullptr);
  state_destroy(restored);

  state_t* empty_state = state_create();
  serialized_buffer_t* empty_blob = crabs_serialize_state(empty_state);
  ASSERT_NE(empty_blob, nullptr);
  state_t* empty_restored = crabs_deserialize_state(empty_blob->data, empty_blob->len);
  ASSERT_NE(empty_restored, nullptr);
  EXPECT_EQ(empty_restored->raft_module_state, nullptr);
  state_destroy(empty_restored);
  serialized_buffer_destroy(empty_blob);
  state_destroy(empty_state);
}