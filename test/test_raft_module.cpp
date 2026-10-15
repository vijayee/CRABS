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
// wire. The leadership NO-OP entry (Raft §8) commits at index 1 first and
// never materializes as a machine op.
TEST(RaftSingleNodeCommit, ProposePersistsThenCommits) {
  crabs_raft_config_t config = make_single_config(42, 0);
  crabs_raft_module_t* module = crabs_raft_module_create(&config);
  ASSERT_NE(module, nullptr);
  uint64_t now_ms = 0;
  drive_to_leader(module, &now_ms);

  // The leader-start no-op sits at index 1, undurable until the host acks.
  EXPECT_EQ(crabs_raft_module_log_length(module), 1u);
  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist));
  EXPECT_EQ(persist.handle, 1u);
  ASSERT_GE(persist.len, 4u);

  const char* payload = "mint-one";
  operation_t* op = make_signed_op("mint", "admin",
                                   (const uint8_t*)payload,
                                   (uint32_t)strlen(payload));
  ASSERT_NE(op, nullptr);

  uint64_t proposal_id = 0;
  EXPECT_EQ(crabs_raft_module_propose(module, op, &proposal_id),
            CRABS_SUCCESS);
  operation_destroy(op);
  EXPECT_EQ(proposal_id, 2u);   // index 1 = the no-op
  EXPECT_EQ(crabs_raft_module_log_length(module), 2u);
  // Nothing counts for commit before the host acked durability.
  EXPECT_EQ(crabs_raft_module_committed_tip(module), 0u);

  // The single window is busy with the no-op batch; the same outstanding
  // request is reported until completion (blob pointer stable).
  crabs_raft_persist_request_t persist_again;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist_again));
  EXPECT_EQ(persist_again.handle, persist.handle);
  EXPECT_EQ(persist_again.bytes, persist.bytes);

  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist.handle, true),
            CRABS_SUCCESS);
  // The no-op committed (index 1) but emitted NO COMMITTED_OP: control
  // entries never materialize as machine ops.
  EXPECT_EQ(crabs_raft_module_committed_tip(module), 1u);
  EXPECT_EQ(drain_committed(module).size(), 0u);

  // The op entry follows on the next window (re-armed by the completion).
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist));
  EXPECT_EQ(persist.handle, 2u);
  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist.handle, true),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(module), 2u);

  std::vector<crabs_raft_notification_t> committed = drain_committed(module);
  ASSERT_EQ(committed.size(), 1u);
  EXPECT_EQ(committed[0].proposal_id, 2u);
  EXPECT_EQ(committed[0].commit_index, 2u);
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
  EXPECT_EQ(proposal_id, 3u);
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist));
  EXPECT_EQ(persist.handle, 3u);
  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist.handle, true),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(module), 3u);
  committed = drain_committed(module);
  ASSERT_EQ(committed.size(), 1u);
  EXPECT_EQ(committed[0].proposal_id, 3u);

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
  EXPECT_EQ(crabs_raft_module_propose(module, op, &proposal_id),
            CRABS_SUCCESS);   // index 2; index 1 is the leadership no-op
  operation_destroy(op);

  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist));
  // Copy the batch bytes BEFORE completing: the blob is module-owned and is
  // released when the window resolves. (The window covers the no-op — the
  // single outstanding window held when the proposal arrived.)
  std::vector<uint8_t> stored_batch(persist.bytes,
                                    persist.bytes + persist.len);
  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist.handle, false),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(module), 0u);

  crabs_raft_notification_t notification;
  ASSERT_TRUE(crabs_raft_module_poll_notification(module, &notification));
  EXPECT_EQ(notification.kind, RAFT_NOTIFY_PERSIST_FAILED);

  // The tick re-arms persistence for the whole undurable tail with a fresh
  // handle: the failed batch re-issues unchanged, PLUS the op entry that
  // joined the log after the window was armed.
  now_ms++;
  EXPECT_EQ(crabs_raft_module_tick(module, now_ms), CRABS_SUCCESS);
  crabs_raft_persist_request_t retry;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &retry));
  EXPECT_EQ(retry.handle, persist.handle + 1);
  // The retry batch re-issues the SAME header record (version u8 + first
  // index u64 + header term u64 + votedFor string16: 25 bytes for
  // "node-0"); the tail grew, so the entry_count field and the body differ.
  constexpr size_t kPersistHeaderPrefix = 1 + 8 + 8 + 2 + 6;
  ASSERT_GT(retry.len, stored_batch.size());
  EXPECT_EQ(memcmp(retry.bytes, stored_batch.data(), kPersistHeaderPrefix), 0);
  EXPECT_EQ(crabs_raft_module_persist_complete(module, retry.handle, true),
            CRABS_SUCCESS);
  // The no-op committed silently (no machine op); the op committed right
  // behind it on the same batch.
  EXPECT_EQ(crabs_raft_module_committed_tip(module), 2u);
  std::vector<crabs_raft_notification_t> committed = drain_committed(module);
  ASSERT_EQ(committed.size(), 1u);
  EXPECT_EQ(committed[0].proposal_id, 2u);
  EXPECT_EQ(committed[0].commit_index, 2u);

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
  // Only the leadership no-op occupies the log; the refused op added nothing.
  EXPECT_EQ(crabs_raft_module_log_length(module), 1u);
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
// rejections) and the answer round-trips back — the full wire path. Carry
// item A: BOTH directions are gated on the term/votedFor header batch being
// durable — the candidacy solicitation waits for its own self-vote persist,
// and the grant response waits for the grant persist.
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

  // A's deadline fires → candidate → its solicitation is HELD (no vote
  // traffic leaves before the term/votedFor header batch is durable).
  uint64_t deadline_a = crabs_raft_module_next_election_deadline(module_a);
  EXPECT_EQ(crabs_raft_module_tick(module_a, deadline_a), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_current_term(module_a), 1u);

  crabs_raft_outbound_message_t outbound;
  crabs_raft_persist_request_t persist_a;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module_a, &persist_a));
  EXPECT_FALSE(crabs_raft_module_poll_outbound(module_a, &outbound));
  EXPECT_EQ(crabs_raft_module_persist_complete(module_a, persist_a.handle,
                                               true), CRABS_SUCCESS);

  // Durable candidacy: the solicitation flows now.
  ASSERT_TRUE(crabs_raft_module_poll_outbound(module_a, &outbound));
  EXPECT_EQ(outbound.kind, RAFT_MSG_VOTE_REQ);
  EXPECT_STREQ(outbound.to_peer, "nodeB");

  // B (still term 0 follower) grants the vote: wire parses with zero
  // rejections — but B's grant is HELD behind ITS OWN header batch.
  EXPECT_EQ(crabs_raft_module_inbound(module_b, "nodeA", outbound.bytes,
                                      outbound.len, deadline_a), CRABS_SUCCESS);
  free((void*)outbound.bytes);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(module_b), 0u);
  EXPECT_EQ(crabs_raft_module_current_term(module_b), 1u);
  crabs_raft_persist_request_t persist_b;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module_b, &persist_b));
  EXPECT_FALSE(crabs_raft_module_poll_outbound(module_b, &outbound));
  // ... and flows exactly when the grant's persist completes.
  EXPECT_EQ(crabs_raft_module_persist_complete(module_b, persist_b.handle,
                                               true), CRABS_SUCCESS);
  ASSERT_TRUE(crabs_raft_module_poll_outbound(module_b, &outbound));
  EXPECT_EQ(outbound.kind, RAFT_MSG_VOTE_RESP);
  EXPECT_STREQ(outbound.to_peer, "nodeA");
  EXPECT_EQ(outbound.bytes[11], 1);   // first body byte: vote_granted
  EXPECT_FALSE(crabs_raft_module_poll_outbound(module_b, &outbound));
  free((void*)outbound.bytes);

  crabs_raft_module_destroy(module_a);
  crabs_raft_module_destroy(module_b);
}

// Carry item A — election safety across a crash: the persisted batch is a
// complete election record. A grant + crash + fresh module that recovers
// from the host's stored batch CANNOT re-vote for a different candidate in
// the same term, and the vote response never left the reactor before the
// header batch was durable.
TEST(RaftVoteDurability, GrantPersistsBeforeResponseAndSurvivesCrash) {
  crabs_raft_config_t config_b = make_single_config(42, 0);
  strncpy(config_b.node_id, "nodeB", CRABS_MAX_USER_ID - 1);
  strncpy(config_b.peer_ids[0], "nodeB", CRABS_MAX_USER_ID - 1);
  strncpy(config_b.peer_ids[1], "nodeA", CRABS_MAX_USER_ID - 1);
  strncpy(config_b.peer_ids[2], "nodeC", CRABS_MAX_USER_ID - 1);
  config_b.peer_count = 3;

  crabs_raft_module_t* module_b = crabs_raft_module_create(&config_b);
  ASSERT_NE(module_b, nullptr);

  // Hand-marshal a term-7 vote request from nodeA (the public wire format).
  std::vector<uint8_t> vote_req;
  auto push_u8 = [&](uint8_t value) { vote_req.push_back(value); };
  auto push_u64 = [&](uint64_t value) {
    for (int byte_index = 0; byte_index < 8; byte_index++) {
      push_u8((uint8_t)((value >> (byte_index * 8)) & 0xFF));
    }
  };
  auto push_str16 = [&](const char* text) {
    uint16_t len = (uint16_t)strlen(text);
    push_u8((uint8_t)(len & 0xFF));
    push_u8((uint8_t)(len >> 8));
    for (uint16_t char_index = 0; char_index < len; char_index++) {
      push_u8((uint8_t)text[char_index]);
    }
  };
  push_u8(0x52); push_u8(1); push_u8(1);
  push_u64(7);
  push_str16("nodeA");
  push_u64(9);    // last_log_term
  push_u64(12);   // last_log_index

  EXPECT_EQ(crabs_raft_module_inbound(module_b, "nodeA", vote_req.data(),
                                      vote_req.size(), 100), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(module_b), 0u);
  EXPECT_EQ(crabs_raft_module_current_term(module_b), 7u);

  // The grant is HELD: nothing leaves the reactor...
  crabs_raft_outbound_message_t outbound;
  EXPECT_FALSE(crabs_raft_module_poll_outbound(module_b, &outbound));
  // ...until the header batch carrying (7, nodeA) is durable. The host
  // copies the batch bytes as its durable record (the crash artifact).
  crabs_raft_persist_request_t persist_b;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module_b, &persist_b));
  std::vector<uint8_t> stored_batch(persist_b.bytes,
                                    persist_b.bytes + persist_b.len);
  EXPECT_EQ(crabs_raft_module_persist_complete(module_b, persist_b.handle,
                                               true), CRABS_SUCCESS);
  ASSERT_TRUE(crabs_raft_module_poll_outbound(module_b, &outbound));
  EXPECT_EQ(outbound.kind, RAFT_MSG_VOTE_RESP);
  free((void*)outbound.bytes);

  // --- crash: object destroyed, only the stored batch survives ---
  crabs_raft_module_destroy(module_b);
  crabs_raft_module_t* revived = crabs_raft_module_create(&config_b);
  ASSERT_NE(revived, nullptr);
  EXPECT_EQ(crabs_raft_module_recover_from_persist(
                revived, stored_batch.data(), stored_batch.size()),
            CRABS_SUCCESS);
  // The recovered durable election record: term 7, voted nodeA, and the
  // header record is acknowledged durable for restart-continued committing.
  crabs_raft_module_state_t* exported = crabs_raft_module_export_state(revived);
  ASSERT_NE(exported, nullptr);
  EXPECT_EQ(exported->term, 7u);
  EXPECT_STREQ(exported->voted_for, "nodeA");
  crabs_raft_module_state_destroy(exported);

  // A second candidate (nodeC) solicits the SAME term: refused — the node
  // cannot re-vote/revote incorrectly in the term it already granted.
  // (Wire layout: header 11 bytes, then string16 = 2 length bytes + chars.)
  std::vector<uint8_t> vote_req_c(vote_req);
  memcpy(&vote_req_c[13], "nodeC", 5);
  EXPECT_EQ(crabs_raft_module_inbound(revived, "nodeC", vote_req_c.data(),
                                      vote_req_c.size(), 101), CRABS_SUCCESS);
  // The deny flows IMMEDIATELY (a denial carries no vote, no durability
  // gate) — and it denies.
  ASSERT_TRUE(crabs_raft_module_poll_outbound(revived, &outbound));
  EXPECT_EQ(outbound.kind, RAFT_MSG_VOTE_RESP);
  EXPECT_STREQ(outbound.to_peer, "nodeC");
  EXPECT_EQ(outbound.bytes[11], 0);
  free((void*)outbound.bytes);

  crabs_raft_module_destroy(revived);
}

// Carry item A — the same crash leg on the CANDIDACY side: a fresh module
// recovered from its stored batch knows durably that it self-voted at term 7
// (its own solicitation was durable before it ever left).
TEST(RaftVoteDurability, CandidacySelfVoteDurableBeforeSolicitation) {
  crabs_raft_config_t config = make_single_config(42, 0);
  strncpy(config.node_id, "nodeA", CRABS_MAX_USER_ID - 1);
  strncpy(config.peer_ids[0], "nodeA", CRABS_MAX_USER_ID - 1);
  strncpy(config.peer_ids[1], "nodeB", CRABS_MAX_USER_ID - 1);
  config.peer_count = 2;

  crabs_raft_module_t* module_a = crabs_raft_module_create(&config);
  ASSERT_NE(module_a, nullptr);
  uint64_t deadline = crabs_raft_module_next_election_deadline(module_a);
  EXPECT_EQ(crabs_raft_module_tick(module_a, deadline), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_current_term(module_a), 1u);

  // Solicitation held behind the header batch; the host stores the bytes.
  crabs_raft_outbound_message_t outbound;
  EXPECT_FALSE(crabs_raft_module_poll_outbound(module_a, &outbound));
  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module_a, &persist));
  std::vector<uint8_t> stored_batch(persist.bytes,
                                    persist.bytes + persist.len);
  EXPECT_EQ(crabs_raft_module_persist_complete(module_a, persist.handle, true),
            CRABS_SUCCESS);
  ASSERT_TRUE(crabs_raft_module_poll_outbound(module_a, &outbound));
  EXPECT_EQ(outbound.kind, RAFT_MSG_VOTE_REQ);
  free((void*)outbound.bytes);

  crabs_raft_module_destroy(module_a);
  crabs_raft_module_t* revived = crabs_raft_module_create(&config);
  ASSERT_NE(revived, nullptr);
  EXPECT_EQ(crabs_raft_module_recover_from_persist(
                revived, stored_batch.data(), stored_batch.size()),
            CRABS_SUCCESS);
  crabs_raft_module_state_t* exported = crabs_raft_module_export_state(revived);
  ASSERT_NE(exported, nullptr);
  EXPECT_EQ(exported->term, 1u);
  EXPECT_STREQ(exported->voted_for, "nodeA");
  crabs_raft_module_state_destroy(exported);
  crabs_raft_module_destroy(revived);
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
  EXPECT_EQ(throwaway_proposal, 2u);   // index 1 is the leadership no-op
  operation_destroy(op);

  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist.handle, true),
            CRABS_SUCCESS);              // no-op window → tip 1
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist.handle, true),
            CRABS_SUCCESS);              // op window → tip 2
  drain_committed(module);

  // Export matches the live module.
  crabs_raft_module_state_t* export_a = crabs_raft_module_export_state(module);
  ASSERT_NE(export_a, nullptr);
  EXPECT_EQ(export_a->module_id, 3);
  EXPECT_EQ(export_a->term, crabs_raft_module_current_term(module));
  EXPECT_EQ(export_a->commit_index, 2u);
  EXPECT_EQ(export_a->log_count, 2u);
  ASSERT_NE(export_a->log, nullptr);
  // Entry 1 is the leadership no-op: zero-length wire, never a machine op.
  EXPECT_EQ(export_a->log->term, 1u);
  EXPECT_EQ(export_a->log->proposal_id, 1u);
  EXPECT_EQ(export_a->log->wire_len, 0u);
  ASSERT_NE(export_a->log->next, nullptr);
  EXPECT_EQ(export_a->log->next->proposal_id, 2u);
  // The data entry carries the serialized OP WIRE (a full CRABS op blob),
  // not the raw payload.
  EXPECT_GT(export_a->log->next->wire_len, 3u);
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

  // Committing CONTINUES on the revived module. A new leadership start
  // appends ITS OWN no-op first (§8: every leadership term appends one), so
  // the op lands at index 4 after the revived no-op at 3.
  drive_to_leader(revived, &now_ms);
  EXPECT_EQ(crabs_raft_module_log_length(revived), 3u);
  op = make_signed_op("mint", "admin", (const uint8_t*)"two", 3);
  ASSERT_NE(op, nullptr);
  uint64_t proposal_id = 0;
  EXPECT_EQ(crabs_raft_module_propose(revived, op, &proposal_id), CRABS_SUCCESS);
  operation_destroy(op);
  EXPECT_EQ(proposal_id, 4u);
  EXPECT_EQ(crabs_raft_module_log_length(revived), 4u);
  ASSERT_TRUE(crabs_raft_module_poll_persist(revived, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(revived, persist.handle, true),
            CRABS_SUCCESS);              // revived no-op → tip 3
  ASSERT_TRUE(crabs_raft_module_poll_persist(revived, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(revived, persist.handle, true),
            CRABS_SUCCESS);              // op → tip 4
  EXPECT_EQ(crabs_raft_module_committed_tip(revived), 4u);

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

TEST(RaftModule, ImportStateRefusesListLongerThanCount) {
  // pass-3 LOW: the splice capacity is grown to log_count, but the splice
  // loop walks the FULL linked list — a section whose list outruns its
  // declared count wrote past the-grown capacity. The import must refuse
  // BEFORE any module state is touched.
  crabs_raft_config_t config = make_single_config(42, 3);
  crabs_raft_module_t* module = crabs_raft_module_create(&config);
  ASSERT_NE(module, nullptr);

  uint8_t wire_byte = 0x00;   // below the config marker, so no config path
  crabs_raft_entry_persisted_t second_node = {};
  second_node.term = 1;
  second_node.proposal_id = 2;
  second_node.op_wire = &wire_byte;
  second_node.wire_len = 1;
  second_node.next = nullptr;

  crabs_raft_entry_persisted_t first_node = {};
  first_node.term = 1;
  first_node.proposal_id = 1;
  first_node.op_wire = &wire_byte;
  first_node.wire_len = 1;
  first_node.next = &second_node;

  crabs_raft_module_state_t section = {};
  section.module_id = 3;
  section.term = 1;
  section.commit_index = 0;
  section.log_count = 1;        // declares ONE entry...
  section.log = &first_node;    // ...but carries TWO nodes

  EXPECT_EQ(crabs_raft_module_import_state(module, &section),
            CRABS_ERR_INVALID_PARAM);
  // Pre-count validation refuses before any mutation: the module state is
  // unchanged.
  EXPECT_EQ(crabs_raft_module_log_length(module), 0u);
  EXPECT_EQ(crabs_raft_module_committed_tip(module), 0u);
  EXPECT_FALSE(crabs_raft_module_is_leader(module));

  crabs_raft_module_destroy(module);
}
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
            CRABS_SUCCESS);              // no-op → tip 1
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist.handle, true),
            CRABS_SUCCESS);              // op → tip 2
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
  EXPECT_EQ(parsed->commit_index, 2u);
  EXPECT_EQ(parsed->log_count, 2u);
  ASSERT_NE(parsed->log, nullptr);
  // The carried history begins with the leadership no-op (zero wire length).
  EXPECT_EQ(parsed->log->proposal_id, 1u);
  EXPECT_EQ(parsed->log->wire_len, 0u);

  // The host handoff: create a fresh module with the SAME cfg and import.
  crabs_raft_module_t* revived_module = crabs_raft_module_create(&config);
  ASSERT_NE(revived_module, nullptr);
  EXPECT_EQ(crabs_raft_module_import_state(revived_module, parsed),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(revived_module), 2u);
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
// Carry item D (P2-review nit): the EMPTY-range AppendEntries round trip —
// an up-to-date leader's heartbeat (entry_count 0) parses on a real follower
// with zero rejections and gets a success/match response.
TEST(RaftWireRoundTrip, EmptyRangeHeartbeatRoundTrips) {
  crabs_raft_config_t config_f = make_single_config(42, 0);
  strncpy(config_f.node_id, "nodeF", CRABS_MAX_USER_ID - 1);
  strncpy(config_f.peer_ids[0], "nodeF", CRABS_MAX_USER_ID - 1);
  strncpy(config_f.peer_ids[1], "nodeL", CRABS_MAX_USER_ID - 1);
  config_f.peer_count = 2;
  crabs_raft_config_t config_l = make_single_config(42, 0);
  strncpy(config_l.node_id, "nodeL", CRABS_MAX_USER_ID - 1);
  strncpy(config_l.peer_ids[0], "nodeL", CRABS_MAX_USER_ID - 1);
  strncpy(config_l.peer_ids[1], "nodeF", CRABS_MAX_USER_ID - 1);
  config_l.peer_count = 2;

  crabs_raft_module_t* follower = crabs_raft_module_create(&config_f);
  crabs_raft_module_t* leader = crabs_raft_module_create(&config_l);
  ASSERT_NE(follower, nullptr);
  ASSERT_NE(leader, nullptr);

  // Leader: elected, §8 no-op appended, header batch durable; the first
  // AppendEntries (with the no-op) reaches the follower, whose ack feeds
  // back through the same wire helpers.
  // Mini two-node wire: tick, settle each node's persist windows, and
  // shuttle every queued message across (until the leader wins over the
  // follower's grants). Carry item A rides along: every vote hop is durably
  // gated by its own header batch.
  uint64_t now_ms = 0;
  crabs_raft_persist_request_t persist;
  crabs_raft_outbound_message_t outbound;
  for (int settle_round = 0; settle_round < 1000 &&
                            !crabs_raft_module_is_leader(leader); settle_round++) {
    now_ms += 100;
    EXPECT_EQ(crabs_raft_module_tick(leader, now_ms), CRABS_SUCCESS);
    for (int window_round = 0; window_round < 4; window_round++) {
      crabs_raft_persist_request_t leader_persist;
      if (crabs_raft_module_poll_persist(leader, &leader_persist)) {
        EXPECT_EQ(crabs_raft_module_persist_complete(leader, leader_persist.handle,
                                                     true), CRABS_SUCCESS);
      }
    }
    for (int shuttle = 0; shuttle < 8; shuttle++) {
      while (crabs_raft_module_poll_outbound(leader, &outbound)) {
        crabs_raft_module_inbound(follower, "nodeL", outbound.bytes, outbound.len,
                                  now_ms);
        free((void*)outbound.bytes);
        while (crabs_raft_module_poll_persist(follower, &persist)) {
          EXPECT_EQ(crabs_raft_module_persist_complete(follower, persist.handle,
                                                       true), CRABS_SUCCESS);
        }
        while (crabs_raft_module_poll_outbound(follower, &outbound)) {
          crabs_raft_module_inbound(leader, "nodeF", outbound.bytes,
                                    outbound.len, now_ms);
          free((void*)outbound.bytes);
        }
      }
      while (crabs_raft_module_poll_outbound(follower, &outbound)) {
        crabs_raft_module_inbound(leader, "nodeF", outbound.bytes, outbound.len,
                                  now_ms);
        free((void*)outbound.bytes);
        while (crabs_raft_module_poll_persist(leader, &persist)) {
          EXPECT_EQ(crabs_raft_module_persist_complete(leader, persist.handle,
                                                       true), CRABS_SUCCESS);
        }
      }
    }
  }
  ASSERT_TRUE(crabs_raft_module_is_leader(leader));
  ASSERT_TRUE(crabs_raft_module_poll_persist(leader, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(leader, persist.handle, true),
            CRABS_SUCCESS);
  // Feed every queued leader Append to the follower (and its ack back).
  while (crabs_raft_module_poll_outbound(leader, &outbound)) {
    EXPECT_EQ(outbound.kind, RAFT_MSG_APPEND_REQ);
    EXPECT_EQ(crabs_raft_module_inbound(follower, "nodeL", outbound.bytes,
                                        outbound.len, now_ms), CRABS_SUCCESS);
    free((void*)outbound.bytes);
    crabs_raft_persist_request_t follower_persist;
    ASSERT_TRUE(crabs_raft_module_poll_persist(follower, &follower_persist));
    EXPECT_EQ(crabs_raft_module_persist_complete(follower, follower_persist.handle,
                                                 true), CRABS_SUCCESS);
    while (crabs_raft_module_poll_outbound(follower, &outbound)) {
      EXPECT_EQ(outbound.kind, RAFT_MSG_APPEND_RESP);
      crabs_raft_module_inbound(leader, "nodeF", outbound.bytes, outbound.len,
                                now_ms);
      free((void*)outbound.bytes);
    }
  }
  EXPECT_EQ(crabs_raft_module_log_length(follower), 1u);   // the no-op tail

  // Follower caught up: a fresh leader tick emits the EMPTY-range heartbeat.
  now_ms += CRABS_RAFT_HEARTBEAT_INTERVAL_MS;
  EXPECT_EQ(crabs_raft_module_tick(leader, now_ms), CRABS_SUCCESS);
  {
    crabs_raft_persist_request_t heartbeat_persist;
    while (crabs_raft_module_poll_persist(leader, &heartbeat_persist)) {
      EXPECT_EQ(crabs_raft_module_persist_complete(leader, heartbeat_persist.handle,
                                                   true), CRABS_SUCCESS);
    }
  }
  bool heartbeat_seen = false;
  while (crabs_raft_module_poll_outbound(leader, &outbound)) {
    if (outbound.kind != RAFT_MSG_APPEND_REQ) {
      free((void*)outbound.bytes);
      continue;
    }
    // Entry count at the fixed wire offset (header 11 + leader string16
    // 2+5 + prev_term 8 + prev_index 8 + commit 8 = byte 42): 0 == empty.
    uint32_t entry_count = (uint32_t)outbound.bytes[42] |
                           ((uint32_t)outbound.bytes[43] << 8) |
                           ((uint32_t)outbound.bytes[44] << 16) |
                           ((uint32_t)outbound.bytes[45] << 24);
    if (outbound.len == 46) {
      heartbeat_seen = true;
      EXPECT_EQ(entry_count, 0u);
      EXPECT_EQ(crabs_raft_module_inbound(follower, "nodeL", outbound.bytes,
                                          outbound.len, now_ms), CRABS_SUCCESS);
      free((void*)outbound.bytes);
      ASSERT_TRUE(crabs_raft_module_poll_outbound(follower, &outbound));
      EXPECT_EQ(outbound.kind, RAFT_MSG_APPEND_RESP);
      EXPECT_EQ(outbound.bytes[11], 1);   // success
      uint64_t match_index = 0;
      for (int byte_index = 0; byte_index < 8; byte_index++) {
        match_index |=
            ((uint64_t)outbound.bytes[12 + byte_index]) << (byte_index * 8);
      }
      EXPECT_EQ(match_index, 1u);   // the leader's tail, adopted
      free((void*)outbound.bytes);
    } else {
      free((void*)outbound.bytes);
    }
  }
  EXPECT_TRUE(heartbeat_seen);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(follower), 0u);

  crabs_raft_module_destroy(follower);
  crabs_raft_module_destroy(leader);
}

// ============================================================
// Log compaction decision (Phase 3): the bounded log REACHES the cap and
// refuses beyond it, loudly; the module stays healthy and the full log
// round-trips the v17 section and the persist recovery.
// ============================================================
TEST(RaftLogBound, ReachesCapAndRefusesBeyond) {
  crabs_raft_config_t config = make_single_config(42, 3);
  crabs_raft_module_t* module = crabs_raft_module_create(&config);
  ASSERT_NE(module, nullptr);
  uint64_t now_ms = 0;
  drive_to_leader(module, &now_ms);
  // The §8 no-op occupies index 1 (its window is open; the fill below
  // shares the single window until the host acks).
  crabs_raft_persist_request_t persist_window;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist_window));
  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist_window.handle,
                                               true), CRABS_SUCCESS);

  // Stress: fill the log TO the cap with small ops (the per-op wire stays
  // tiny; the bound is on ENTRY COUNT).
  const char* payload = "x";
  for (uint64_t entry_index = 2; entry_index <= CRABS_RAFT_MAX_LOG_ENTRIES;
       entry_index++) {
    operation_t* op = make_signed_op("mint", "admin", (const uint8_t*)payload,
                                     (uint32_t)strlen(payload));
    ASSERT_NE(op, nullptr);
    uint64_t proposal_id = 0;
    crabs_error_e rc = crabs_raft_module_propose(module, op, &proposal_id);
    operation_destroy(op);
    ASSERT_EQ(rc, CRABS_SUCCESS);
    ASSERT_EQ(proposal_id, entry_index);
  }
  EXPECT_EQ(crabs_raft_module_log_length(module), CRABS_RAFT_MAX_LOG_ENTRIES);

  // Evidence for the growth model: the retained wire bytes (the host's
  // planning number at the bound is cap * (entry + wire) worst case; the
  // tiny-op reality here is printed for the record).
  crabs_raft_module_state_t* export_state = crabs_raft_module_export_state(module);
  ASSERT_NE(export_state, nullptr);
  size_t total_wire = 0;
  uint32_t count_entries = 0;
  for (const crabs_raft_entry_persisted_t* entry = export_state->log;
       entry != NULL; entry = entry->next) {
    total_wire += entry->wire_len;
    count_entries++;
  }
  printf("bound evidence: %u entries, %zu op-wire bytes retained "
         "(worst-case planning bound: %d * %d = %d bytes)\n",
         count_entries, total_wire, CRABS_RAFT_MAX_LOG_ENTRIES,
         CRABS_RAFT_MAX_OP_WIRE_BYTES,
         CRABS_RAFT_MAX_LOG_ENTRIES * CRABS_RAFT_MAX_OP_WIRE_BYTES);
  EXPECT_EQ(count_entries, CRABS_RAFT_MAX_LOG_ENTRIES);
  EXPECT_LE(total_wire, (size_t)CRABS_RAFT_MAX_LOG_ENTRIES *
                            CRABS_RAFT_MAX_OP_WIRE_BYTES);

  // AT the bound: another proposal REFUSES, loudly (notification), leaving
  // the log and the committed prefix intact.
  operation_t* over = make_signed_op("mint", "admin", (const uint8_t*)"y", 1);
  ASSERT_NE(over, nullptr);
  uint64_t refused_id = 7;
  EXPECT_EQ(crabs_raft_module_propose(module, over, &refused_id),
            CRABS_ERR_INTERNAL);
  operation_destroy(over);
  EXPECT_EQ(refused_id, 0u);
  EXPECT_EQ(crabs_raft_module_log_length(module), CRABS_RAFT_MAX_LOG_ENTRIES);
  crabs_raft_notification_t notification;
  bool saw_log_full = false;
  while (crabs_raft_module_poll_notification(module, &notification)) {
    if (notification.kind == RAFT_NOTIFY_LOG_FULL) saw_log_full = true;
  }
  EXPECT_TRUE(saw_log_full);

  // Restart at the bound: import the full section; the module stays
  // bounded and healthy (still refuses, still has its committed prefix).
  crabs_raft_module_state_t* carried = crabs_raft_module_export_state(module);
  ASSERT_NE(carried, nullptr);
  EXPECT_EQ(carried->log_count, CRABS_RAFT_MAX_LOG_ENTRIES);
  crabs_raft_module_t* revived = crabs_raft_module_create(&config);
  ASSERT_NE(revived, nullptr);
  EXPECT_EQ(crabs_raft_module_import_state(revived, carried), CRABS_SUCCESS);
  crabs_raft_module_state_destroy(carried);
  EXPECT_EQ(crabs_raft_module_log_length(revived), CRABS_RAFT_MAX_LOG_ENTRIES);
  drive_to_leader(revived, &now_ms);
  operation_t* over2 = make_signed_op("mint", "admin", (const uint8_t*)"z", 1);
  ASSERT_NE(over2, nullptr);
  uint64_t refused_id2 = 7;
  EXPECT_EQ(crabs_raft_module_propose(revived, over2, &refused_id2),
            CRABS_ERR_INTERNAL);
  operation_destroy(over2);

  crabs_raft_module_state_destroy(export_state);
  crabs_raft_module_destroy(module);
  crabs_raft_module_destroy(revived);
}

// ============================================================
// Audit C-1: the claimed leader is bound to the transport-authenticated
// sender; MEDIUM follow: impossible commit receipts fold into the repair
// path instead of inflating the commit tally.
// ============================================================

// AppendEntries carrying ANOTHER member's leader_id is leader impersonation:
// rejected on the identity binding alone (no step-down, no log rewrite).
TEST(RaftWireRoundTrip, AppendRequestLeaderClaimMustMatchTransportSender) {
  crabs_raft_config_t config = make_single_config(42, 0);
  strncpy(config.node_id, "nodeF", CRABS_MAX_USER_ID - 1);
  strncpy(config.peer_ids[0], "nodeF", CRABS_MAX_USER_ID - 1);
  strncpy(config.peer_ids[1], "nodeL", CRABS_MAX_USER_ID - 1);
  config.peer_count = 2;

  crabs_raft_module_t* follower = crabs_raft_module_create(&config);
  ASSERT_NE(follower, nullptr);

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

  // APPEND_REQ with term 5, leadership "nodeL" — delivered under the
  // authenticated identity of a DIFFERENT member ("nodeA").
  push_u8(0x52); push_u8(1); push_u8(3);
  push_u64(5);
  push_str16("nodeL");
  push_u64(0);   // prev_term
  push_u64(0);   // prev_index
  push_u64(0);   // leader commit
  push_u32(0);   // entry count

  EXPECT_EQ(crabs_raft_module_inbound(follower, "nodeA", blob.data(),
                                      blob.size(), 100), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(follower), 1u);
  EXPECT_EQ(crabs_raft_module_current_term(follower), 0u);
  EXPECT_EQ(crabs_raft_module_log_length(follower), 0u);
  crabs_raft_module_destroy(follower);
}

// A well-formed APPEND_REQ still applies when the claimed leader matches the
// transport sender (C-1 must not break the legitimate flow).
TEST(RaftWireRoundTrip, AppendRequestMatchingSenderStillAppends) {
  crabs_raft_config_t config = make_single_config(42, 0);
  strncpy(config.node_id, "nodeF", CRABS_MAX_USER_ID - 1);
  strncpy(config.peer_ids[0], "nodeF", CRABS_MAX_USER_ID - 1);
  strncpy(config.peer_ids[1], "nodeL", CRABS_MAX_USER_ID - 1);
  config.peer_count = 2;

  crabs_raft_module_t* follower = crabs_raft_module_create(&config);
  ASSERT_NE(follower, nullptr);

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
  push_u64(0); push_u64(0); push_u64(0); push_u32(0);

  EXPECT_EQ(crabs_raft_module_inbound(follower, "nodeL", blob.data(),
                                      blob.size(), 100), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(follower), 0u);
  EXPECT_EQ(crabs_raft_module_current_term(follower), 5u);
  crabs_raft_module_destroy(follower);
}

// A commit receipt claiming replication beyond the leader's own log tip is
// impossible for the current term; it must fold into the repair path, never
// inflate the commit tally or push next_index off the log.
TEST(RaftWireRoundTrip, CommitReceiptBeyondLeaderLogTipTreatedAsRepair) {
  crabs_raft_config_t config = make_single_config(42, 0);
  crabs_raft_module_t* module = crabs_raft_module_create(&config);
  ASSERT_NE(module, nullptr);
  uint64_t now_ms = 0;
  drive_to_leader(module, &now_ms);

  operation_t* op = make_signed_op("mint", "admin",
                                   (const uint8_t*)"receipt-check", 13);
  ASSERT_NE(op, nullptr);
  uint64_t proposal_id = 0;
  EXPECT_EQ(crabs_raft_module_propose(module, op, &proposal_id),
            CRABS_SUCCESS);
  operation_destroy(op);
  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist.handle, true),
            CRABS_SUCCESS);
  ASSERT_TRUE(crabs_raft_module_poll_persist(module, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(module, persist.handle, true),
            CRABS_SUCCESS);
  drain_committed(module);          // the legit tip (2) committed
  EXPECT_EQ(crabs_raft_module_committed_tip(module), 2u);
  uint64_t tip_before = crabs_raft_module_committed_tip(module);
  uint32_t rejects_before =
      crabs_raft_module_rejected_message_count(module);

  // Leader's log tip is 2; the receipt claims 99 — beyond-top claim. Wire:
  // magic, version 1, kind APPEND_RESP, term = current, success 1,
  // match_index 99.
  std::vector<uint8_t> blob;
  blob.push_back(0x52); blob.push_back(1); blob.push_back(4);
  for (int byte_index = 0; byte_index < 8; byte_index++) {
    blob.push_back((uint8_t)((crabs_raft_module_current_term(module) >>
                              (byte_index * 8)) & 0xFF));
  }
  blob.push_back(1);
  for (int byte_index = 0; byte_index < 8; byte_index++) {
    blob.push_back((uint8_t)((99u >> (byte_index * 8)) & 0xFF));
  }
  // Self-delivery keeps the peer registered in the single-node module.
  EXPECT_EQ(crabs_raft_module_inbound(module, config.node_id, blob.data(),
                                      blob.size(), 10), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(module),
            rejects_before);
  EXPECT_EQ(crabs_raft_module_committed_tip(module), tip_before);
  crabs_raft_module_destroy(module);
}

// ============================================================
// Audit pass-3 defense-in-depth (consensus findings 4 and 5): the term
// ceiling is never adopted and never wraps, and a same-(term, index) resend
// must carry IDENTICAL content to count as an idempotent duplicate.
// ============================================================

// Consensus finding 4: a crafted APPEND_REQ with term == UINT64_MAX must not
// move the node's term (adopting the ceiling would let the next election
// increment wrap current_term to 0, resetting term monotonicity for stale
// leaders). The caller re-check fails the message closed as stale, and a
// later election timeout increments from the ORIGINAL term.
TEST(RaftModule, TermCeilingNeverWraps) {
  crabs_raft_config_t config = make_single_config(42, 0);
  strncpy(config.node_id, "nodeF", CRABS_MAX_USER_ID - 1);
  strncpy(config.peer_ids[0], "nodeF", CRABS_MAX_USER_ID - 1);
  strncpy(config.peer_ids[1], "nodeL", CRABS_MAX_USER_ID - 1);
  config.peer_count = 2;

  crabs_raft_module_t* follower = crabs_raft_module_create(&config);
  ASSERT_NE(follower, nullptr);

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

  // APPEND_REQ at the term ceiling: sender-bound leader "nodeL", empty
  // range over an empty log.
  push_u8(0x52); push_u8(1); push_u8(3);
  push_u64(UINT64_MAX);
  push_str16("nodeL");
  push_u64(0);   // prev_term
  push_u64(0);   // prev_index
  push_u64(0);   // leader commit
  push_u32(0);   // entry count

  EXPECT_EQ(crabs_raft_module_inbound(follower, "nodeL", blob.data(),
                                      blob.size(), 100), CRABS_SUCCESS);
  // The ceiling is REFUSED: the term does not move and nothing is appended.
  EXPECT_EQ(crabs_raft_module_current_term(follower), 0u);
  EXPECT_EQ(crabs_raft_module_log_length(follower), 0u);
  // Failed closed as stale (the append-request stale path): a failure
  // response goes back to the claimed leader, nothing else leaves.
  crabs_raft_outbound_message_t outbound;
  ASSERT_TRUE(crabs_raft_module_poll_outbound(follower, &outbound));
  EXPECT_EQ(outbound.kind, RAFT_MSG_APPEND_RESP);
  EXPECT_STREQ(outbound.to_peer, "nodeL");
  EXPECT_EQ(outbound.bytes[11], 0);   // body byte 0: success = false
  free((void*)outbound.bytes);
  EXPECT_FALSE(crabs_raft_module_poll_outbound(follower, &outbound));

  // The election timeout fires on the public tick API: the term increments
  // from the ORIGINAL value (0 -> 1) — never wrapping UINT64_MAX to 0.
  uint64_t deadline = crabs_raft_module_next_election_deadline(follower);
  EXPECT_EQ(crabs_raft_module_tick(follower, deadline), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_current_term(follower), 1u);

  crabs_raft_module_destroy(follower);
}

// Consensus finding 5: same (term, index) with DIVERGENT content is an
// equivocating leader, not an idempotent duplicate. A proposal-id mismatch
// or a wire-bytes mismatch refuses the whole message (rejected count rises,
// the held slot's original content stands); a byte-identical resend stays
// idempotent.
TEST(RaftModule, AppendEquivocationWithDivergentBytesRejected) {
  crabs_raft_config_t config = make_single_config(42, 0);
  strncpy(config.node_id, "nodeF", CRABS_MAX_USER_ID - 1);
  strncpy(config.peer_ids[0], "nodeF", CRABS_MAX_USER_ID - 1);
  strncpy(config.peer_ids[1], "nodeL", CRABS_MAX_USER_ID - 1);
  config.peer_count = 2;

  crabs_raft_module_t* follower = crabs_raft_module_create(&config);
  ASSERT_NE(follower, nullptr);

  // Build a one-entry APPEND_REQ (term 5 from leader "nodeL", empty prev,
  // commit ceiling 1) with the entry's proposal id and wire bytes
  // parameterized.
  auto make_append = [&](uint64_t proposal_id,
                         const std::vector<uint8_t>& wire_bytes) {
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
    push_u64(1);   // leader commit (ceiling: entry 1)
    push_u32(1);   // entry count
    push_u64(5);              // entry term (the leader's current term)
    push_u64(proposal_id);
    push_u32((uint32_t)wire_bytes.size());
    for (uint8_t wire_byte : wire_bytes) push_u8(wire_byte);
    return blob;
  };

  const std::vector<uint8_t> original_wire = {'o', 'p', 'A'};

  // First write at (term 5, index 1): accepted. The leader's ceiling (1)
  // commits it behind the module's own durability line — the occupied-slot
  // path only fires for slots the resend CANNOT truncate away (the
  // committed prefix: truncation is gated on prev_index >= commit_index).
  std::vector<uint8_t> first = make_append(7, original_wire);
  EXPECT_EQ(crabs_raft_module_inbound(follower, "nodeL", first.data(),
                                      first.size(), 100), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(follower), 0u);
  EXPECT_EQ(crabs_raft_module_log_length(follower), 1u);
  EXPECT_EQ(crabs_raft_module_current_term(follower), 5u);
  crabs_raft_persist_request_t persist;
  ASSERT_TRUE(crabs_raft_module_poll_persist(follower, &persist));
  EXPECT_EQ(crabs_raft_module_persist_complete(follower, persist.handle, true),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_committed_tip(follower), 1u);
  drain_all_notifications(follower);

  // Equivocation by proposal id (same bytes): refused.
  std::vector<uint8_t> divergent_id = make_append(8, original_wire);
  EXPECT_EQ(crabs_raft_module_inbound(follower, "nodeL", divergent_id.data(),
                                      divergent_id.size(), 101), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(follower), 1u);
  EXPECT_EQ(crabs_raft_module_log_length(follower), 1u);

  // Equivocation by wire bytes (same proposal id): refused.
  std::vector<uint8_t> divergent_bytes = make_append(7, {'o', 'p', 'B'});
  EXPECT_EQ(crabs_raft_module_inbound(follower, "nodeL",
                                      divergent_bytes.data(),
                                      divergent_bytes.size(), 102),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(follower), 2u);
  EXPECT_EQ(crabs_raft_module_log_length(follower), 1u);

  // Equivocation by length (a shared prefix over a longer wire): refused.
  std::vector<uint8_t> divergent_len =
      make_append(7, {'o', 'p', 'A', '-', 'e', 'x', 't', 'r', 'a'});
  EXPECT_EQ(crabs_raft_module_inbound(follower, "nodeL", divergent_len.data(),
                                      divergent_len.size(), 103),
            CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(follower), 3u);
  EXPECT_EQ(crabs_raft_module_log_length(follower), 1u);

  // The byte-identical resend is the honest idempotent duplicate: silently
  // absorbed, no rejection.
  std::vector<uint8_t> duplicate = make_append(7, original_wire);
  EXPECT_EQ(crabs_raft_module_inbound(follower, "nodeL", duplicate.data(),
                                      duplicate.size(), 104), CRABS_SUCCESS);
  EXPECT_EQ(crabs_raft_module_rejected_message_count(follower), 3u);
  EXPECT_EQ(crabs_raft_module_log_length(follower), 1u);

  // The held slot kept the FIRST write's image throughout.
  crabs_raft_module_state_t* exported = crabs_raft_module_export_state(follower);
  ASSERT_NE(exported, nullptr);
  ASSERT_NE(exported->log, nullptr);
  EXPECT_EQ(exported->log->term, 5u);
  EXPECT_EQ(exported->log->proposal_id, 7u);
  ASSERT_EQ(exported->log->wire_len, 3u);
  EXPECT_EQ(memcmp(exported->log->op_wire, original_wire.data(), 3), 0);
  crabs_raft_module_state_destroy(exported);

  crabs_raft_module_destroy(follower);
}
