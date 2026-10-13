//
// Created by victor on 10/12/25.
//

#include "raft_module.h"
#include "../Serialization/serialization.h"
#include "../Util/allocator.h"
#include <string.h>
#include <stdlib.h>

// ============================================================
// Wire layout (compact versioned structs, module-owned; hosts treat the
// blobs as opaque):
//
//   every message:  u8 magic (0x52 'R'), u8 version (1), u8 kind, u64 term,
//                   then kind-specific fields.
//   VOTE_REQ:    string16 candidate_id, u64 last_log_term, u64 last_log_index
//   VOTE_RESP:   u8 vote_granted
//   APPEND_REQ:  string16 leader_id, u64 prev_log_term, u64 prev_log_index,
//                u64 commit_index, u32 entry_count, entries {
//                  u64 term, u64 proposal_id, u32 wire_len, op wire bytes }
//   APPEND_RESP: u8 success, u64 match_index
//
// Persist batch (poll_persist blob): u32 entry_count, then per entry
// u64 term, u64 proposal_id, u32 wire_len, op wire bytes.
//
// Strings are length-prefixed u16 little-endian. All integers little-endian.
// Deserializer discipline (fail-closed, like every other deserializer in
// this codebase): any malformed field drops the message, bumps the rejection
// counter, and leaves module state untouched.
// ============================================================
#define RAFT_WIRE_MAGIC       0x52
#define RAFT_WIRE_VERSION     1
#define RAFT_WIRE_HEADER_LEN  11   // magic(1) + version(1) + kind(1) + term(8)
// Framing bytes of one log entry on any wire (term + proposal_id + length).
#define RAFT_ENTRY_FRAMING_LEN (8 + 8 + 4)

// ============================================================
// Internal types
// ============================================================
typedef enum {
  RAFT_ROLE_FOLLOWER = 0,
  RAFT_ROLE_CANDIDATE = 1,
  RAFT_ROLE_LEADER = 2
} raft_role_e;

typedef struct {
  uint64_t term;
  uint64_t proposal_id;
  uint8_t* op_wire;
  uint32_t wire_len;
} raft_log_entry_t;

// One durable batch handed to the host; resolved by persist_complete. The
// blob is module-owned until the completion (or a retry re-issues it).
typedef struct raft_persist_request_node_t {
  uint64_t handle;
  uint64_t first_index;
  uint64_t last_index;
  uint8_t* blob;
  size_t   blob_len;
  struct raft_persist_request_node_t* next;
} raft_persist_request_node_t;

// Outbound message queue node: the blob is module-owned heap.
typedef struct raft_outbound_msg_t {
  raft_msg_kind_e kind;
  char to_peer[CRABS_MAX_USER_ID];
  uint8_t* bytes;
  size_t len;
  struct raft_outbound_msg_t* next;
} raft_outbound_msg_t;

typedef struct raft_notification_node_t {
  raft_notification_e kind;
  char peer_id[CRABS_MAX_USER_ID];
  uint64_t proposal_id;
  const uint8_t* op_bytes;   // borrowed view into the log
  size_t op_len;
  uint64_t commit_index;
  struct raft_notification_node_t* next;
} raft_notification_node_t;

typedef struct crabs_raft_module_s {
  crabs_raft_config_t config;

  raft_role_e role;
  uint64_t current_term;
  char     voted_for[CRABS_MAX_USER_ID];
  char     leader_id[CRABS_MAX_USER_ID];
  uint64_t commit_index;          // highest index that counts for commit
  uint64_t last_log_index;        // 1-based tail (== entry count)
  uint64_t durable_upto;          // highest index acked durable (persist_complete)
  // Follower-side commit ceiling: the leader's commit_index from the most
  // recent APPEND_REQ. Commit may never pass the durability line, so the
  // follower's commit waits for its OWN persist_complete (see
  // _raft_advance_commit).
  uint64_t follower_commit_target;

  raft_log_entry_t* log;          // heap array, capacity grows to the cap
  uint64_t log_capacity;

  // Peer bookkeeping (warm from Phase 1; driven in Phase 2 replication).
  uint64_t next_index[CRABS_RAFT_MAX_PEERS];
  uint64_t match_index[CRABS_RAFT_MAX_PEERS];

  // Timers (the module's clock origin is the host's now_ms domain).
  uint64_t election_deadline_ms;

  // splitmix64 state — same seed, same election deadlines, forever.
  uint64_t rng_state;

  // Queues (module-owned; host drains).
  raft_outbound_msg_t*  outbound_head;
  raft_outbound_msg_t*  outbound_tail;
  raft_notification_node_t*  notification_head;
  raft_notification_node_t*  notification_tail;

  // Persistence window: AT MOST ONE outstanding batch at a time (host
  // stores it anywhere durable, then answers persist_complete). While the
  // window is held, the undurable tail waits; once the window frees, the
  // next tick (propose/append emit earlier when one is riding) re-issues it.
  raft_persist_request_node_t* persist_outstanding;
  uint64_t persist_handle_seq;

  // Fail-closed inbound counter (rejected malformed messages).
  uint32_t rejected_message_count;
} crabs_raft_module_s;

// Forward: the persistence window is shared by the propose, append and tick
// paths (defined in the parsing/persistence sections below).
static bool _raft_emit_persist_request(crabs_raft_module_s* module);

// ============================================================
// Small helpers
// ============================================================
static uint64_t _raft_rng_next(crabs_raft_module_s* module) {
  uint64_t state = module->rng_state + 0x9E3779B97F4A7C15ULL;
  module->rng_state = state;
  uint64_t scrambled = state;
  scrambled = (scrambled ^ (scrambled >> 30)) * 0xBF58476D1CE4E5B9ULL;
  scrambled = (scrambled ^ (scrambled >> 27)) * 0x94D049BB133111EBULL;
  return scrambled ^ (scrambled >> 31);
}

static uint64_t _raft_random_election_timeout(crabs_raft_module_s* module) {
  uint64_t span = module->config.election_timeout_max_ms -
                  module->config.election_timeout_min_ms;
  return module->config.election_timeout_min_ms +
         (_raft_rng_next(module) % (span + 1));
}

static int _raft_peer_index(const crabs_raft_module_s* module, const char* peer_id) {
  if (peer_id == NULL) return -1;
  for (uint32_t member_index = 0; member_index < module->config.peer_count;
       member_index++) {
    if (strncmp(module->config.peer_ids[member_index], peer_id,
                CRABS_MAX_USER_ID) == 0) {
      return (int)member_index;
    }
  }
  return -1;
}

static bool _raft_is_self(const crabs_raft_module_s* module, const char* peer_id) {
  return peer_id != NULL &&
         strncmp(peer_id, module->config.node_id, CRABS_MAX_USER_ID) == 0;
}

static void _raft_store_u64_le(uint8_t* out, uint64_t value) {
  // Little-endian writer (the codebase avoids <endian.h>).
  for (int byte_index = 0; byte_index < 8; byte_index++) {
    out[byte_index] = (uint8_t)((value >> (byte_index * 8)) & 0xFF);
  }
}

static uint64_t _raft_load_u64(const uint8_t* bytes) {
  uint64_t value = 0;
  for (int byte_index = 0; byte_index < 8; byte_index++) {
    value |= ((uint64_t)bytes[byte_index]) << (byte_index * 8);
  }
  return value;
}

static uint32_t _raft_load_u32(const uint8_t* bytes) {
  return (uint32_t)bytes[0] |
         ((uint32_t)bytes[1] << 8) |
         ((uint32_t)bytes[2] << 16) |
         ((uint32_t)bytes[3] << 24);
}

static uint16_t _raft_load_u16(const uint8_t* bytes) {
  return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

// ============================================================
// Log
// ============================================================
static raft_log_entry_t* _raft_log_entry(crabs_raft_module_s* module,
                                         uint64_t log_index) {
  if (log_index < 1 || log_index > module->last_log_index ||
      log_index > module->log_capacity) {
    return NULL;
  }
  return &module->log[log_index - 1];
}

static void _raft_log_entry_release(raft_log_entry_t* entry) {
  if (entry->op_wire != NULL) {
    free(entry->op_wire);
    entry->op_wire = NULL;
  }
  entry->wire_len = 0;
}

static crabs_error_e _raft_log_grow(crabs_raft_module_s* module,
                                    uint64_t needed_capacity) {
  if (needed_capacity <= module->log_capacity) return CRABS_SUCCESS;
  if (needed_capacity > CRABS_RAFT_MAX_LOG_ENTRIES) return CRABS_ERR_INTERNAL;
  uint64_t new_capacity = module->log_capacity == 0 ? 32 : module->log_capacity;
  while (new_capacity < needed_capacity) {
    new_capacity *= 2;
    if (new_capacity > CRABS_RAFT_MAX_LOG_ENTRIES) {
      new_capacity = CRABS_RAFT_MAX_LOG_ENTRIES;
      break;
    }
  }
  // A log entry that grew to the cap covers every need below it.
  raft_log_entry_t* grown =
      (raft_log_entry_t*)realloc(module->log,
                                 sizeof(raft_log_entry_t) * new_capacity);
  if (grown == NULL) return CRABS_ERR_OOM;
  memset(grown + module->log_capacity, 0,
         sizeof(raft_log_entry_t) * (new_capacity - module->log_capacity));
  module->log = grown;
  module->log_capacity = new_capacity;
  return CRABS_SUCCESS;
}

// ============================================================
// Queues
// ============================================================
static void _raft_enqueue_outbound(crabs_raft_module_s* module,
                                   raft_msg_kind_e kind, const char* to_peer,
                                   uint8_t* bytes, size_t len) {
  raft_outbound_msg_t* message =
      (raft_outbound_msg_t*)get_clear_memory(sizeof(raft_outbound_msg_t));
  message->kind = kind;
  strncpy(message->to_peer, to_peer, CRABS_MAX_USER_ID - 1);
  message->bytes = bytes;
  message->len = len;
  message->next = NULL;
  if (module->outbound_tail == NULL) {
    module->outbound_head = message;
  } else {
    module->outbound_tail->next = message;
  }
  module->outbound_tail = message;
}

static void _raft_enqueue_notification(crabs_raft_module_s* module,
                                       raft_notification_e kind,
                                       const char* peer_id,
                                       uint64_t proposal_id,
                                       const uint8_t* op_bytes, size_t op_len) {
  raft_notification_node_t* event =
      (raft_notification_node_t*)get_clear_memory(sizeof(raft_notification_node_t));
  event->kind = kind;
  if (peer_id != NULL) {
    strncpy(event->peer_id, peer_id, CRABS_MAX_USER_ID - 1);
  }
  event->proposal_id = proposal_id;
  event->op_bytes = op_bytes;
  event->op_len = op_len;
  event->commit_index = module->commit_index;
  event->next = NULL;
  if (module->notification_tail == NULL) {
    module->notification_head = event;
  } else {
    module->notification_tail->next = event;
  }
  module->notification_tail = event;
}

// Commit advance: entries count for commit ONLY once durability is behind
// them (the two-sided persistence contract). Invariants:
//   - commit never passes durable_upto, never passes the log tail;
//   - single node: quorum is the node itself, so acked durability IS commit;
//   - follower: commit target is the leader's commit_index from APPEND_REQ,
//     still behind the follower's own durability line;
//   - multi-node leader/candidate: quorum match advances commit (Phase 2) —
//     the leader's own durability is only ever a precondition.
// Every newly committed entry emits one COMMITTED_OP notification carrying
// the op wire for host materialization.
static void _raft_advance_commit(crabs_raft_module_s* module) {
  uint64_t commit_target;
  if (module->config.peer_count == 1) {
    commit_target = module->durable_upto;         // degenerate quorum
  } else if (module->role == RAFT_ROLE_FOLLOWER) {
    commit_target = module->follower_commit_target;
  } else {
    return;   // Phase 2: leader/candidate commit rides quorum match
  }
  if (commit_target > module->durable_upto) {
    commit_target = module->durable_upto;
  }
  if (commit_target > module->last_log_index) {
    commit_target = module->last_log_index;
  }
  if (commit_target <= module->commit_index) return;
  uint64_t previous_commit = module->commit_index;
  module->commit_index = commit_target;
  // Emit one COMMITTED_OP per newly committed entry, oldest to newest.
  for (uint64_t committed_index = previous_commit + 1;
       committed_index <= module->commit_index; committed_index++) {
    raft_log_entry_t* entry = _raft_log_entry(module, committed_index);
    if (entry == NULL) break;
    _raft_enqueue_notification(module, RAFT_NOTIFY_COMMITTED_OP, NULL,
                               entry->proposal_id, entry->op_wire,
                               entry->wire_len);
  }
}

// ============================================================
// Message marshaling
// ============================================================
typedef struct {
  uint8_t* bytes;
  size_t   len;
  size_t   offset;
  bool     failed;
} raft_wire_writer_t;

static void _raft_write_bytes(raft_wire_writer_t* writer, const uint8_t* data,
                              size_t len) {
  if (writer->failed) return;
  if (writer->offset + len > writer->len) {
    writer->failed = true;
    return;
  }
  memcpy(writer->bytes + writer->offset, data, len);
  writer->offset += len;
}

static void _raft_write_u8(raft_wire_writer_t* writer, uint8_t value) {
  _raft_write_bytes(writer, &value, 1);
}

static void _raft_write_u64(raft_wire_writer_t* writer, uint64_t value) {
  uint8_t scratch[8];
  _raft_store_u64_le(scratch, value);
  _raft_write_bytes(writer, scratch, 8);
}

static void _raft_write_u32(raft_wire_writer_t* writer, uint32_t value) {
  uint8_t scratch[4] = {
    (uint8_t)(value & 0xFF), (uint8_t)((value >> 8) & 0xFF),
    (uint8_t)((value >> 16) & 0xFF), (uint8_t)((value >> 24) & 0xFF)
  };
  _raft_write_bytes(writer, scratch, 4);
}

static void _raft_write_u16(raft_wire_writer_t* writer, uint16_t value) {
  uint8_t scratch[2] = { (uint8_t)(value & 0xFF), (uint8_t)((value >> 8) & 0xFF) };
  _raft_write_bytes(writer, scratch, 2);
}

static void _raft_write_string16(raft_wire_writer_t* writer, const char* text) {
  if (text == NULL) text = "";
  size_t text_len = strlen(text);
  if (text_len > UINT16_MAX) {
    writer->failed = true;
    return;
  }
  _raft_write_u16(writer, (uint16_t)text_len);
  _raft_write_bytes(writer, (const uint8_t*)text, text_len);
}

// Prepends the fixed header (magic/version/kind/term) onto a prebuilt body
// buffer; on success the full message blob is returned (caller frees).
static uint8_t* _raft_marshal(raft_msg_kind_e kind, uint64_t term,
                              const uint8_t* body, size_t body_len,
                              size_t* out_len) {
  if (body == NULL && body_len > 0) {
    *out_len = 0;
    return NULL;
  }
  uint8_t* bytes = (uint8_t*)get_memory(RAFT_WIRE_HEADER_LEN + body_len);
  raft_wire_writer_t header = { bytes, RAFT_WIRE_HEADER_LEN + body_len, 0, false };
  _raft_write_u8(&header, RAFT_WIRE_MAGIC);
  _raft_write_u8(&header, RAFT_WIRE_VERSION);
  _raft_write_u8(&header, (uint8_t)kind);
  _raft_write_u64(&header, term);
  memcpy(bytes + RAFT_WIRE_HEADER_LEN, body, body_len);
  *out_len = RAFT_WIRE_HEADER_LEN + body_len;
  return bytes;
}

// Vote request round-trips are exercised in Phase 1's wire tests; election
// tallies land with Phase 2.
static bool _raft_marshal_vote_request(crabs_raft_module_s* module,
                                       const char* to_peer, uint64_t last_log_term,
                                       uint64_t last_log_index) {
  size_t body_len = CRABS_MAX_USER_ID + 2 + 16;
  uint8_t* body = (uint8_t*)get_clear_memory(body_len);
  raft_wire_writer_t writer = { body, body_len, 0, false };
  _raft_write_string16(&writer, module->config.node_id);
  _raft_write_u64(&writer, last_log_term);
  _raft_write_u64(&writer, last_log_index);
  if (writer.failed) {
    free(body);
    return false;
  }
  size_t len = 0;
  uint8_t* bytes = _raft_marshal(RAFT_MSG_VOTE_REQ, module->current_term,
                                 body, writer.offset, &len);
  free(body);
  if (bytes == NULL) return false;
  _raft_enqueue_outbound(module, RAFT_MSG_VOTE_REQ, to_peer, bytes, len);
  return true;
}

static bool _raft_marshal_vote_response(crabs_raft_module_s* module,
                                        const char* to_peer, bool granted) {
  uint8_t body[1];
  raft_wire_writer_t writer = { body, sizeof(body), 0, false };
  _raft_write_u8(&writer, granted ? 1 : 0);
  size_t len = 0;
  uint8_t* bytes = _raft_marshal(RAFT_MSG_VOTE_RESP, module->current_term,
                                 body, writer.offset, &len);
  if (bytes == NULL) return false;
  _raft_enqueue_outbound(module, RAFT_MSG_VOTE_RESP, to_peer, bytes, len);
  return true;
}

// AppendEntries: entries after the point of agreement ship in order; an
// empty range is a heartbeat. Used in Phase 1 wire round-trip tests; the
// leader's replication loop drives it from Phase 2 on.
static bool _raft_marshal_append_request(crabs_raft_module_s* module,
                                         const char* to_peer,
                                         uint64_t first_index, uint64_t last_index,
                                         uint64_t prev_log_term,
                                         uint64_t prev_log_index) {
  if (first_index == 0 || last_index > module->last_log_index ||
      first_index > last_index + 1) {
    return false;
  }
  uint64_t entry_count =
      last_index >= first_index ? last_index - first_index + 1 : 0;
  size_t body_len = CRABS_MAX_USER_ID + 2 + 8 * 3 + 4;
  for (uint64_t entry_index = first_index; entry_index <= last_index;
       entry_index++) {
    raft_log_entry_t* entry = _raft_log_entry(module, entry_index);
    if (entry == NULL) return false;
    body_len += RAFT_ENTRY_FRAMING_LEN + entry->wire_len;
  }
  uint8_t* body = (uint8_t*)get_clear_memory(body_len);
  raft_wire_writer_t writer = { body, body_len, 0, false };
  _raft_write_string16(&writer, module->config.node_id);
  _raft_write_u64(&writer, prev_log_term);
  _raft_write_u64(&writer, prev_log_index);
  _raft_write_u64(&writer, module->commit_index);
  _raft_write_u32(&writer, (uint32_t)entry_count);
  for (uint64_t entry_index = first_index; entry_index <= last_index;
       entry_index++) {
    raft_log_entry_t* entry = _raft_log_entry(module, entry_index);
    _raft_write_u64(&writer, entry->term);
    _raft_write_u64(&writer, entry->proposal_id);
    _raft_write_u32(&writer, entry->wire_len);
    _raft_write_bytes(&writer, entry->op_wire, entry->wire_len);
  }
  if (writer.failed) {
    free(body);
    return false;
  }
  size_t len = 0;
  uint8_t* bytes = _raft_marshal(RAFT_MSG_APPEND_REQ, module->current_term,
                                 body, writer.offset, &len);
  free(body);
  if (bytes == NULL) return false;
  _raft_enqueue_outbound(module, RAFT_MSG_APPEND_REQ, to_peer, bytes, len);
  return true;
}

static bool _raft_marshal_append_response(crabs_raft_module_s* module,
                                          const char* to_peer, bool success,
                                          uint64_t match_index) {
  uint8_t body[9];
  raft_wire_writer_t writer = { body, sizeof(body), 0, false };
  _raft_write_u8(&writer, success ? 1 : 0);
  _raft_write_u64(&writer, match_index);
  size_t len = 0;
  uint8_t* bytes = _raft_marshal(RAFT_MSG_APPEND_RESP, module->current_term,
                                 body, writer.offset, &len);
  if (bytes == NULL) return false;
  _raft_enqueue_outbound(module, RAFT_MSG_APPEND_RESP, to_peer, bytes, len);
  return true;
}

// ============================================================
// Message parsing (fail-closed)
// ============================================================
typedef struct {
  const uint8_t* bytes;
  size_t   len;
  size_t   offset;
} raft_wire_reader_t;

static const uint8_t* _raft_read_bytes(raft_wire_reader_t* reader, size_t len,
                                       bool* failed) {
  if (reader->offset + len > reader->len) {
    *failed = true;
    return NULL;
  }
  const uint8_t* out = reader->bytes + reader->offset;
  reader->offset += len;
  return out;
}

static bool _raft_read_u8(raft_wire_reader_t* reader, uint8_t* out) {
  bool failed = false;
  const uint8_t* bytes = _raft_read_bytes(reader, 1, &failed);
  if (failed) return false;
  *out = bytes[0];
  return true;
}

static bool _raft_read_u64(raft_wire_reader_t* reader, uint64_t* out) {
  bool failed = false;
  const uint8_t* bytes = _raft_read_bytes(reader, 8, &failed);
  if (failed) return false;
  *out = _raft_load_u64(bytes);
  return true;
}

static bool _raft_read_u32(raft_wire_reader_t* reader, uint32_t* out) {
  bool failed = false;
  const uint8_t* bytes = _raft_read_bytes(reader, 4, &failed);
  if (failed) return false;
  *out = _raft_load_u32(bytes);
  return true;
}

static bool _raft_read_u16(raft_wire_reader_t* reader, uint16_t* out) {
  bool failed = false;
  const uint8_t* bytes = _raft_read_bytes(reader, 2, &failed);
  if (failed) return false;
  *out = _raft_load_u16(bytes);
  return true;
}

static bool _raft_read_string16(raft_wire_reader_t* reader, char* out, size_t out_cap) {
  uint16_t string_len;
  if (!_raft_read_u16(reader, &string_len)) return false;
  // A string longer than the (NUL-terminated) destination cannot be
  // satisfied: reject rather than truncate (fail-closed).
  if (string_len >= out_cap) return false;
  bool failed = false;
  const uint8_t* bytes = _raft_read_bytes(reader, string_len, &failed);
  if (failed) return false;
  memcpy(out, bytes, string_len);
  out[string_len] = '\0';
  return true;
}

// A term from ahead of ours steps any role down to follower (RAFT paper
// §5.1). One vote per term is guarded by voted_for afterwards.
static void _raft_step_down(crabs_raft_module_s* module, uint64_t term,
                            const char* new_leader_hint) {
  if (term <= module->current_term) return;
  module->current_term = term;
  module->voted_for[0] = '\0';
  if (module->role == RAFT_ROLE_LEADER) {
    _raft_enqueue_notification(module, RAFT_NOTIFY_LOST_LEADERSHIP,
                               new_leader_hint != NULL ? new_leader_hint : "",
                               0, NULL, 0);
  }
  module->role = RAFT_ROLE_FOLLOWER;
}

static void _raft_handle_vote_request(crabs_raft_module_s* module,
                                      uint64_t term, raft_wire_reader_t* reader,
                                      uint64_t now_ms) {
  char candidate_id[CRABS_MAX_USER_ID];
  uint64_t last_log_term;
  uint64_t last_log_index;
  if (!_raft_read_string16(reader, candidate_id, sizeof(candidate_id)) ||
      !_raft_read_u64(reader, &last_log_term) ||
      !_raft_read_u64(reader, &last_log_index)) {
    module->rejected_message_count++;
    return;
  }
  if (candidate_id[0] == '\0') {
    module->rejected_message_count++;
    return;
  }
  (void)last_log_term;
  (void)last_log_index;
  // A leading node learns of a newer term from any RequestVote: step down
  // first, then evaluate the grant (only followers grant votes).
  _raft_step_down(module, term, candidate_id);
  if (term < module->current_term) {
    _raft_marshal_vote_response(module, candidate_id, false);
    return;
  }
  bool grant =
      module->voted_for[0] == '\0' ||
      strncmp(module->voted_for, candidate_id, CRABS_MAX_USER_ID) == 0;
  if (grant) {
    strncpy(module->voted_for, candidate_id, CRABS_MAX_USER_ID - 1);
    module->election_deadline_ms = now_ms + _raft_random_election_timeout(module);
  }
  _raft_marshal_vote_response(module, candidate_id, grant);
}

static void _raft_handle_vote_response(crabs_raft_module_s* module,
                                       uint64_t term,
                                       raft_wire_reader_t* reader) {
  uint8_t granted;
  if (!_raft_read_u8(reader, &granted)) {
    module->rejected_message_count++;
    return;
  }
  _raft_step_down(module, term, NULL);
  (void)granted;
  // Vote tallies land with Phase 2 elections.
}

static void _raft_handle_append_request(crabs_raft_module_s* module,
                                        uint64_t term,
                                        raft_wire_reader_t* reader,
                                        uint64_t now_ms) {
  char leader_id[CRABS_MAX_USER_ID];
  uint64_t prev_log_term;
  uint64_t prev_log_index;
  uint64_t leader_commit;
  uint32_t entry_count;
  if (!_raft_read_string16(reader, leader_id, sizeof(leader_id)) ||
      !_raft_read_u64(reader, &prev_log_term) ||
      !_raft_read_u64(reader, &prev_log_index) ||
      !_raft_read_u64(reader, &leader_commit) ||
      !_raft_read_u32(reader, &entry_count)) {
    module->rejected_message_count++;
    return;
  }
  if (leader_id[0] == '\0') {
    module->rejected_message_count++;
    return;
  }
  // Bound the claimed entry count against the remaining wire bytes: every
  // entry needs its full framing plus at least one op-wire byte.
  if ((uint64_t)entry_count > (reader->len - reader->offset)) {
    module->rejected_message_count++;
    return;
  }
  int peer_index = _raft_peer_index(module, leader_id);
  if (peer_index < 0) {
    module->rejected_message_count++;
    return;
  }
  _raft_step_down(module, term, leader_id);
  strncpy(module->leader_id, leader_id, CRABS_MAX_USER_ID - 1);
  module->election_deadline_ms = now_ms + _raft_random_election_timeout(module);

  // Log matching (Phase 2 replication core): the prefix must agree.
  raft_log_entry_t* prev_entry = _raft_log_entry(module, prev_log_index);
  bool prefix_matches =
      (prev_log_index == 0 && prev_log_term == 0) ||
      (prev_entry != NULL && prev_entry->term == prev_log_term);
  // A point of agreement inside the COMMITTED prefix that disagrees means a
  // leader claiming history that contradicts durability — reject outright.
  if (prev_log_index <= module->commit_index && !prefix_matches) {
    module->rejected_message_count++;
    return;
  }
  if (!prefix_matches) {
    _raft_marshal_append_response(module, leader_id, false, 0);
    return;
  }

  // Truncate the uncommitted local suffix past the point of agreement
  // (never the committed prefix: it is durable history on this node).
  if (module->last_log_index > prev_log_index &&
      prev_log_index >= module->commit_index) {
    for (uint64_t stale_index = prev_log_index + 1;
         stale_index <= module->last_log_index; stale_index++) {
      raft_log_entry_t* stale = _raft_log_entry(module, stale_index);
      if (stale == NULL) break;
      _raft_log_entry_release(stale);
    }
    module->last_log_index = prev_log_index;
  }

  uint64_t accepted_match = prev_log_index;
  bool appended_any = false;
  for (uint32_t entry_cursor = 0; entry_cursor < entry_count; entry_cursor++) {
    uint64_t entry_term = 0;
    uint64_t entry_proposal_id = 0;
    uint32_t entry_wire_len = 0;
    if (!_raft_read_u64(reader, &entry_term) ||
        !_raft_read_u64(reader, &entry_proposal_id) ||
        !_raft_read_u32(reader, &entry_wire_len)) {
      module->rejected_message_count++;
      return;
    }
    if (entry_wire_len == 0 ||
        entry_wire_len > CRABS_RAFT_MAX_OP_WIRE_BYTES ||
        (size_t)entry_wire_len > reader->len - reader->offset) {
      module->rejected_message_count++;
      return;
    }
    bool wire_failed = false;
    const uint8_t* entry_wire = _raft_read_bytes(reader, entry_wire_len, &wire_failed);
    if (entry_wire == NULL) {
      module->rejected_message_count++;
      return;
    }
    uint64_t append_index = accepted_match + 1;
    if (append_index > CRABS_RAFT_MAX_LOG_ENTRIES ||
        _raft_log_grow(module, append_index) != CRABS_SUCCESS) {
      module->rejected_message_count++;
      return;
    }
    raft_log_entry_t* slot = _raft_log_entry(module, append_index);
    if (slot != NULL) {
      if (slot->term != entry_term) {
        // Conflicting entry after the point of agreement: refuse instead of
        // rewriting (full conflict repair is a Phase 2 concern).
        module->rejected_message_count++;
        return;
      }
      // Same term at the same position: idempotent duplicate — skip.
    } else {
      uint8_t* copy = (uint8_t*)get_memory(entry_wire_len);
      memcpy(copy, entry_wire, entry_wire_len);
      raft_log_entry_t* fresh = &module->log[append_index - 1];
      fresh->term = entry_term;
      fresh->proposal_id = entry_proposal_id;
      fresh->op_wire = copy;
      fresh->wire_len = entry_wire_len;
      module->last_log_index = append_index;
      appended_any = true;   // follower durability rides the persist window too
    }
    accepted_match = append_index;
  }

  // Commit advance on the follower waits for the follower's OWN durability:
  // the leader's commit index is only the ceiling. persist_complete re-runs
  // _raft_advance_commit once the appended range is acked durable.
  if (module->follower_commit_target < leader_commit) {
    module->follower_commit_target = leader_commit;
  }
  if (appended_any) {
    _raft_emit_persist_request(module);
  }
  _raft_marshal_append_response(module, leader_id, true, accepted_match);
}

static void _raft_handle_append_response(crabs_raft_module_s* module,
                                         uint64_t term,
                                         raft_wire_reader_t* reader) {
  uint8_t success;
  uint64_t match_index;
  if (!_raft_read_u8(reader, &success) || !_raft_read_u64(reader, &match_index)) {
    module->rejected_message_count++;
    return;
  }
  _raft_step_down(module, term, NULL);
  (void)success;
  (void)match_index;
  // Leader bookkeeping lands with Phase 2 replication.
}

static void _raft_process_inbound(crabs_raft_module_s* module,
                                  const uint8_t* blob, size_t len,
                                  uint64_t now_ms) {
  raft_wire_reader_t reader = { blob, len, 0 };
  uint8_t magic = 0;
  uint8_t version = 0;
  uint8_t kind = 0;
  uint64_t term = 0;
  if (!_raft_read_u8(&reader, &magic) || !_raft_read_u8(&reader, &version) ||
      !_raft_read_u8(&reader, &kind) || !_raft_read_u64(&reader, &term)) {
    module->rejected_message_count++;
    return;
  }
  if (magic != RAFT_WIRE_MAGIC || version != RAFT_WIRE_VERSION) {
    module->rejected_message_count++;
    return;
  }
  switch (kind) {
    case RAFT_MSG_VOTE_REQ:
      _raft_handle_vote_request(module, term, &reader, now_ms);
      break;
    case RAFT_MSG_VOTE_RESP:
      _raft_handle_vote_response(module, term, &reader);
      break;
    case RAFT_MSG_APPEND_REQ:
      _raft_handle_append_request(module, term, &reader, now_ms);
      break;
    case RAFT_MSG_APPEND_RESP:
      _raft_handle_append_response(module, term, &reader);
      break;
    default:
      module->rejected_message_count++;
      break;
  }
}

// ============================================================
// Persistence (single outstanding window)
// ============================================================
// Build and hand out one persist request covering the undurable tail
// [durable_upto + 1, last_log_index]. Returns true when a request became
// outstanding (or nothing needed doing).
static bool _raft_emit_persist_request(crabs_raft_module_s* module) {
  if (module->persist_outstanding != NULL) return true;   // window busy
  if (module->durable_upto >= module->last_log_index) return true;
  uint64_t first_index = module->durable_upto + 1;
  size_t batch_len = 4;
  for (uint64_t entry_index = first_index; entry_index <= module->last_log_index;
       entry_index++) {
    raft_log_entry_t* entry = _raft_log_entry(module, entry_index);
    if (entry == NULL) return false;
    batch_len += RAFT_ENTRY_FRAMING_LEN + entry->wire_len;
  }
  uint8_t* batch = (uint8_t*)get_clear_memory(batch_len);
  raft_wire_writer_t writer = { batch, batch_len, 0, false };
  _raft_write_u32(&writer,
                  (uint32_t)(module->last_log_index - first_index + 1));
  for (uint64_t entry_index = first_index; entry_index <= module->last_log_index;
       entry_index++) {
    raft_log_entry_t* entry = _raft_log_entry(module, entry_index);
    _raft_write_u64(&writer, entry->term);
    _raft_write_u64(&writer, entry->proposal_id);
    _raft_write_u32(&writer, entry->wire_len);
    _raft_write_bytes(&writer, entry->op_wire, entry->wire_len);
  }
  if (writer.failed) {
    free(batch);
    return false;
  }
  raft_persist_request_node_t* node =
      (raft_persist_request_node_t*)get_clear_memory(sizeof(raft_persist_request_node_t));
  module->persist_handle_seq++;
  node->handle = module->persist_handle_seq;
  node->first_index = first_index;
  node->last_index = module->last_log_index;
  node->blob = batch;
  node->blob_len = batch_len;
  node->next = NULL;
  module->persist_outstanding = node;
  return true;
}

// ============================================================
// Role transitions
// ============================================================
static void _raft_begin_election(crabs_raft_module_s* module, uint64_t now_ms) {
  module->current_term++;
  module->voted_for[0] = '\0';

  if (module->config.peer_count == 1) {
    // Degenerate single node: NO vote exchange — the sole member elects
    // itself immediately (quorum of 1 is trivially reached).
    module->role = RAFT_ROLE_LEADER;
    strncpy(module->voted_for, module->config.node_id, CRABS_MAX_USER_ID - 1);
    module->leader_id[0] = '\0';
    _raft_enqueue_notification(module, RAFT_NOTIFY_BECAME_LEADER,
                               module->config.node_id, 0, NULL, 0);
    module->election_deadline_ms = now_ms + _raft_random_election_timeout(module);
    // An undurable tail re-arms under the new term on the next tick's
    // persist window check.
    return;
  }

  // Multi-node path (Phase 2 election logic; the wire path round-trips now):
  // self-vote, then solicit every other member.
  module->role = RAFT_ROLE_CANDIDATE;
  strncpy(module->voted_for, module->config.node_id, CRABS_MAX_USER_ID - 1);
  module->election_deadline_ms = now_ms + _raft_random_election_timeout(module);
  raft_log_entry_t* tail = _raft_log_entry(module, module->last_log_index);
  for (uint32_t member_index = 0; member_index < module->config.peer_count;
       member_index++) {
    const char* peer_id = module->config.peer_ids[member_index];
    if (_raft_is_self(module, peer_id)) continue;
    _raft_marshal_vote_request(
        module, peer_id, tail != NULL ? tail->term : 0, module->last_log_index);
  }
}

// ============================================================
// Public lifecycle
// ============================================================
void crabs_raft_config_defaults(crabs_raft_config_t* config) {
  if (config == NULL) return;
  memset(config, 0, sizeof(*config));
  strncpy(config->node_id, "node-0", CRABS_MAX_USER_ID - 1);
  strncpy(config->peer_ids[0], "node-0", CRABS_MAX_USER_ID - 1);
  config->peer_count = 1;
  config->election_timeout_min_ms = CRABS_RAFT_ELECTION_TIMEOUT_MIN_MS;
  config->election_timeout_max_ms = CRABS_RAFT_ELECTION_TIMEOUT_MAX_MS;
  config->heartbeat_interval_ms = CRABS_RAFT_HEARTBEAT_INTERVAL_MS;
  config->seed = 0;
  config->module_id = 0;
}

crabs_raft_module_t* crabs_raft_module_create(const crabs_raft_config_t* cfg) {
  crabs_raft_config_t defaults;
  if (cfg == NULL) {
    crabs_raft_config_defaults(&defaults);
    cfg = &defaults;
  }
  if (cfg->peer_count == 0 || cfg->peer_count > CRABS_RAFT_MAX_PEERS ||
      cfg->node_id[0] == '\0') {
    return NULL;
  }
  bool self_is_member = false;
  for (uint32_t member_index = 0; member_index < cfg->peer_count;
       member_index++) {
    if (strncmp(cfg->peer_ids[member_index], cfg->node_id, CRABS_MAX_USER_ID) == 0) {
      self_is_member = true;
    }
  }
  if (!self_is_member) return NULL;   // the node must be a member of its cluster

  crabs_raft_module_s* module =
      (crabs_raft_module_s*)get_clear_memory(sizeof(crabs_raft_module_s));
  memcpy(&module->config, cfg, sizeof(crabs_raft_config_t));
  // Normalize timers (hand-assembled configs may carry degenerate fields).
  if (module->config.election_timeout_min_ms == 0) {
    module->config.election_timeout_min_ms = CRABS_RAFT_ELECTION_TIMEOUT_MIN_MS;
  }
  if (module->config.election_timeout_max_ms <
      module->config.election_timeout_min_ms) {
    module->config.election_timeout_max_ms =
        module->config.election_timeout_min_ms;
  }
  if (module->config.heartbeat_interval_ms == 0) {
    module->config.heartbeat_interval_ms = CRABS_RAFT_HEARTBEAT_INTERVAL_MS;
  }
  module->rng_state = module->config.seed ^ 0x1234567890ABCDEFULL;
  module->role = RAFT_ROLE_FOLLOWER;
  module->leader_id[0] = '\0';
  // Time origin: the host's now_ms domain. The first deadline is the
  // randomized timeout after "time zero", so the first tick at now_ms >=
  // deadline triggers the election. Deadlines re-randomize on every reset.
  module->election_deadline_ms = _raft_random_election_timeout(module);
  for (uint32_t member_index = 0; member_index < CRABS_RAFT_MAX_PEERS;
       member_index++) {
    module->next_index[member_index] = 1;
    module->match_index[member_index] = 0;
  }
  return module;
}

void crabs_raft_module_destroy(crabs_raft_module_t* module_opaque) {
  crabs_raft_module_s* module = (crabs_raft_module_s*)module_opaque;
  if (module == NULL) return;
  for (uint64_t entry_index = 1; entry_index <= module->last_log_index;
       entry_index++) {
    raft_log_entry_t* entry = _raft_log_entry(module, entry_index);
    if (entry != NULL) _raft_log_entry_release(entry);
  }
  free(module->log);
  raft_outbound_msg_t* outbound = module->outbound_head;
  while (outbound != NULL) {
    raft_outbound_msg_t* next = outbound->next;
    free(outbound->bytes);
    free(outbound);
    outbound = next;
  }
  raft_notification_node_t* notification = module->notification_head;
  while (notification != NULL) {
    raft_notification_node_t* next = notification->next;
    free(notification);
    notification = next;
  }
  if (module->persist_outstanding != NULL) {
    free(module->persist_outstanding->blob);
    free(module->persist_outstanding);
  }
  free(module);
}

// ============================================================
// Public inbound events
// ============================================================
crabs_error_e crabs_raft_module_tick(crabs_raft_module_t* module_opaque,
                                     uint64_t now_ms) {
  crabs_raft_module_s* module = (crabs_raft_module_s*)module_opaque;
  if (module == NULL) return CRABS_ERR_INVALID_PARAM;
  switch (module->role) {
    case RAFT_ROLE_FOLLOWER:
    case RAFT_ROLE_CANDIDATE:
      if (now_ms >= module->election_deadline_ms) {
        _raft_begin_election(module, now_ms);   // candidate retry on split vote
      }
      break;
    case RAFT_ROLE_LEADER:
      // Phase 1: single-node leadership needs no heartbeats (no peers);
      // multi-node heartbeats ride Phase 2 replication.
      break;
  }
  // Durability re-arm (any role): the undurable tail rides the persist
  // window; the host's storage answers persist_complete.
  _raft_emit_persist_request(module);
  return CRABS_SUCCESS;
}

crabs_error_e crabs_raft_module_inbound(crabs_raft_module_t* module_opaque,
                                        const char* peer_id,
                                        const uint8_t* blob, size_t len,
                                        uint64_t now_ms) {
  crabs_raft_module_s* module = (crabs_raft_module_s*)module_opaque;
  if (module == NULL || peer_id == NULL || blob == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (!_raft_is_self(module, peer_id) && _raft_peer_index(module, peer_id) < 0) {
    module->rejected_message_count++;
    return CRABS_SUCCESS;   // unknown origin: dropped, module healthy
  }
  _raft_process_inbound(module, blob, len, now_ms);
  return CRABS_SUCCESS;
}

crabs_error_e crabs_raft_module_propose(crabs_raft_module_t* module_opaque,
                                        const operation_t* op,
                                        uint64_t* proposal_id) {
  crabs_raft_module_s* module = (crabs_raft_module_s*)module_opaque;
  if (module == NULL || op == NULL || proposal_id == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  *proposal_id = 0;
  if (module->role != RAFT_ROLE_LEADER) {
    _raft_enqueue_notification(module, RAFT_NOTIFY_PROPOSAL_NOT_LEADER,
                               module->leader_id, 0, NULL, 0);
    return CRABS_ERR_ORDERING_NOT_LEADER;
  }
  serialized_buffer_t* wire = crabs_serialize_operation(op);
  if (wire == NULL) return CRABS_ERR_SERIALIZATION_ERROR;
  if (wire->len == 0 || wire->len > CRABS_RAFT_MAX_OP_WIRE_BYTES) {
    serialized_buffer_destroy(wire);
    return CRABS_ERR_SERIALIZATION_ERROR;   // op too big for the bounded log
  }
  if (_raft_log_grow(module, module->last_log_index + 1) != CRABS_SUCCESS) {
    serialized_buffer_destroy(wire);
    return CRABS_ERR_INTERNAL;   // bounded log full (see header growth model)
  }
  uint64_t new_index = module->last_log_index + 1;
  raft_log_entry_t* entry = &module->log[new_index - 1];
  entry->term = module->current_term;
  entry->proposal_id = new_index;
  entry->op_wire = wire->data;           // blob ownership moves into the log
  entry->wire_len = (uint32_t)wire->len;
  free(wire);   // release the wrapper only; the data block lives in the log
  module->last_log_index = new_index;
  // Hand the undurable tail to the host immediately (a leader tick is not
  // required for the persistence event to exist).
  _raft_emit_persist_request(module);
  *proposal_id = new_index;
  return CRABS_SUCCESS;
}

crabs_error_e crabs_raft_module_persist_complete(
    crabs_raft_module_t* module_opaque, uint64_t handle, bool ok) {
  crabs_raft_module_s* module = (crabs_raft_module_s*)module_opaque;
  if (module == NULL) return CRABS_ERR_INVALID_PARAM;
  raft_persist_request_node_t* outstanding = module->persist_outstanding;
  if (outstanding == NULL || outstanding->handle != handle) {
    // Unknown/stale handle (or answered twice): refuse loudly.
    return CRABS_ERR_INVALID_PARAM;
  }
  uint64_t last_index = outstanding->last_index;
  module->persist_outstanding = NULL;
  free(outstanding->blob);
  free(outstanding);

  if (!ok) {
    // The host failed to store the batch. Nothing becomes durable, nothing
    // counts for commit; the tail re-arms and retries on the next tick.
    _raft_enqueue_notification(module, RAFT_NOTIFY_PERSIST_FAILED, NULL, 0,
                               NULL, 0);
    return CRABS_SUCCESS;
  }

  // Durability confirmed for [first_index, last_index]; commit may now
  // advance — and ONLY now (the persistence contract).
  if (last_index > module->durable_upto) {
    module->durable_upto = last_index;
  }
  _raft_advance_commit(module);
  return CRABS_SUCCESS;
}

// ============================================================
// Public drains
// ============================================================
bool crabs_raft_module_poll_outbound(crabs_raft_module_t* module_opaque,
                                     crabs_raft_outbound_message_t* out) {
  crabs_raft_module_s* module = (crabs_raft_module_s*)module_opaque;
  if (module == NULL || out == NULL) return false;
  raft_outbound_msg_t* head = module->outbound_head;
  if (head == NULL) return false;
  module->outbound_head = head->next;
  if (module->outbound_head == NULL) module->outbound_tail = NULL;
  out->kind = head->kind;
  memcpy(out->to_peer, head->to_peer, CRABS_MAX_USER_ID);
  out->bytes = head->bytes;
  out->len = head->len;
  free(head);   // the blob ownership transfers to the caller's window
  return true;
}

bool crabs_raft_module_poll_persist(crabs_raft_module_t* module_opaque,
                                    crabs_raft_persist_request_t* out) {
  crabs_raft_module_s* module = (crabs_raft_module_s*)module_opaque;
  if (module == NULL || out == NULL) return false;
  raft_persist_request_node_t* outstanding = module->persist_outstanding;
  if (outstanding == NULL) return false;
  // The SAME outstanding request is reported until persist_complete(handl­e)
  // resolves it — the blob pointer stays valid for exactly that window.
  out->handle = outstanding->handle;
  out->bytes = outstanding->blob;
  out->len = outstanding->blob_len;
  return true;
}

bool crabs_raft_module_poll_notification(crabs_raft_module_t* module_opaque,
                                         crabs_raft_notification_t* out) {
  crabs_raft_module_s* module = (crabs_raft_module_s*)module_opaque;
  if (module == NULL || out == NULL) return false;
  raft_notification_node_t* head = module->notification_head;
  if (head == NULL) return false;
  module->notification_head = head->next;
  if (module->notification_head == NULL) module->notification_tail = NULL;
  out->kind = head->kind;
  memcpy(out->peer_id, head->peer_id, CRABS_MAX_USER_ID);
  out->proposal_id = head->proposal_id;
  out->op_bytes = head->op_bytes;
  out->op_len = head->op_len;
  out->commit_index = head->commit_index;
  free(head);
  return true;
}

// ============================================================
// Public queries
// ============================================================
bool crabs_raft_module_is_leader(const crabs_raft_module_t* module_opaque) {
  const crabs_raft_module_s* module = (const crabs_raft_module_s*)module_opaque;
  return module != NULL && module->role == RAFT_ROLE_LEADER;
}

uint64_t crabs_raft_module_committed_tip(const crabs_raft_module_t* module_opaque) {
  const crabs_raft_module_s* module = (const crabs_raft_module_s*)module_opaque;
  return module != NULL ? module->commit_index : 0;
}

uint64_t crabs_raft_module_current_term(const crabs_raft_module_t* module_opaque) {
  const crabs_raft_module_s* module = (const crabs_raft_module_s*)module_opaque;
  return module != NULL ? module->current_term : 0;
}

uint64_t crabs_raft_module_log_length(const crabs_raft_module_t* module_opaque) {
  const crabs_raft_module_s* module = (const crabs_raft_module_s*)module_opaque;
  return module != NULL ? module->last_log_index : 0;
}

uint64_t crabs_raft_module_next_election_deadline(
    const crabs_raft_module_t* module_opaque) {
  const crabs_raft_module_s* module = (const crabs_raft_module_s*)module_opaque;
  return module != NULL ? module->election_deadline_ms : 0;
}

uint32_t crabs_raft_module_rejected_message_count(
    const crabs_raft_module_t* module_opaque) {
  const crabs_raft_module_s* module = (const crabs_raft_module_s*)module_opaque;
  return module != NULL ? module->rejected_message_count : 0;
}

// ============================================================
// Persisted-state export/import
// ============================================================
crabs_raft_module_state_t* crabs_raft_module_export_state(
    const crabs_raft_module_t* module_opaque) {
  const crabs_raft_module_s* module_const = (const crabs_raft_module_s*)module_opaque;
  if (module_const == NULL) return NULL;
  // The export is read-only over the log; _raft_log_entry is a non-const
  // accessor, so view the module through a mutable alias here.
  crabs_raft_module_s* module = (crabs_raft_module_s*)module_const;
  crabs_raft_module_state_t* export =
      (crabs_raft_module_state_t*)get_clear_memory(sizeof(crabs_raft_module_state_t));
  export->module_id = module->config.module_id;
  export->term = module->current_term;
  strncpy(export->voted_for, module->voted_for, CRABS_MAX_USER_ID - 1);
  export->commit_index = module->commit_index;
  export->log_count = (uint32_t)module->last_log_index;
  crabs_raft_entry_persisted_t** tail = &export->log;
  for (uint64_t entry_index = 1; entry_index <= module->last_log_index;
       entry_index++) {
    raft_log_entry_t* entry = _raft_log_entry(module, entry_index);
    if (entry == NULL) break;
    crabs_raft_entry_persisted_t* node =
        (crabs_raft_entry_persisted_t*)get_clear_memory(
            sizeof(crabs_raft_entry_persisted_t));
    node->term = entry->term;
    node->proposal_id = entry->proposal_id;
    node->op_wire = (uint8_t*)get_memory(entry->wire_len > 0 ? entry->wire_len : 1);
    if (entry->wire_len > 0) {
      memcpy(node->op_wire, entry->op_wire, entry->wire_len);
    }
    node->wire_len = entry->wire_len;
    node->next = NULL;
    *tail = node;
    tail = &node->next;
  }
  return export;
}

crabs_error_e crabs_raft_module_import_state(
    crabs_raft_module_t* module_opaque,
    const crabs_raft_module_state_t* persisted) {
  crabs_raft_module_s* module = (crabs_raft_module_s*)module_opaque;
  if (module == NULL || persisted == NULL) return CRABS_ERR_INVALID_PARAM;
  if (persisted->module_id != module->config.module_id) {
    return CRABS_ERR_INVALID_PARAM;   // a section from another module id does not fit
  }
  if (persisted->log_count > CRABS_RAFT_MAX_LOG_ENTRIES ||
      persisted->commit_index > persisted->log_count) {
    return CRABS_ERR_INVALID_PARAM;
  }
  for (const crabs_raft_entry_persisted_t* node = persisted->log; node != NULL;
       node = node->next) {
    if (node->wire_len > CRABS_RAFT_MAX_OP_WIRE_BYTES) {
      return CRABS_ERR_INVALID_PARAM;
    }
  }
  // Wipe the current log, then splice in the persisted one.
  for (uint64_t entry_index = 1; entry_index <= module->last_log_index;
       entry_index++) {
    raft_log_entry_t* entry = _raft_log_entry(module, entry_index);
    if (entry != NULL) _raft_log_entry_release(entry);
  }
  module->last_log_index = 0;
  crabs_error_e grow_rc = _raft_log_grow(module, persisted->log_count);
  if (grow_rc != CRABS_SUCCESS) return grow_rc;
  uint64_t entry_index = 0;
  for (const crabs_raft_entry_persisted_t* node = persisted->log; node != NULL;
       node = node->next) {
    entry_index++;
    raft_log_entry_t* entry = &module->log[entry_index - 1];
    entry->term = node->term;
    entry->proposal_id = node->proposal_id;
    uint8_t* copy = node->wire_len > 0 ? (uint8_t*)get_memory(node->wire_len) : NULL;
    if (node->wire_len > 0) memcpy(copy, node->op_wire, node->wire_len);
    entry->op_wire = copy;
    entry->wire_len = node->wire_len;
  }
  module->last_log_index = persisted->log_count;
  module->current_term = persisted->term;
  module->voted_for[0] = '\0';
  if (persisted->voted_for[0] != '\0') {
    strncpy(module->voted_for, persisted->voted_for, CRABS_MAX_USER_ID - 1);
  }
  module->commit_index = persisted->commit_index;
  // d­urable_upto starts at the restored commit tip: the persisted section
  // IS the durable history (the host wrote it), so nothing re-persists.
  module->durable_upto = persisted->commit_index;
  // Already-committed entries are NOT re-notified (they were materialized
  // before the restart); a restored node waits for its election deadline.
  // Undurable tail entries (log_count > commit_index) re-arm persist.
  module->role = RAFT_ROLE_FOLLOWER;
  module->leader_id[0] = '\0';
  module->follower_commit_target = 0;
  module->election_deadline_ms = _raft_random_election_timeout(module);
  return CRABS_SUCCESS;
}

void crabs_raft_module_state_destroy(crabs_raft_module_state_t* persisted) {
  if (persisted == NULL) return;
  crabs_raft_entry_persisted_t* entry = persisted->log;
  while (entry != NULL) {
    crabs_raft_entry_persisted_t* next = entry->next;
    free(entry->op_wire);
    free(entry);
    entry = next;
  }
  free(persisted);
}