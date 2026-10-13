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
//                (wire_len 0 identifies the leadership NO-OP entry, Raft §8;
//                 wire [0xFF,1,...] identifies a CONFIG entry, below)
//   APPEND_RESP: u8 success, u64 match_index
//
// Persist batch (poll_persist blob), version 2: u8 format version, then
//   u64 first_log_index, u64 header_term, string16 header_voted_for,
//   u32 entry_count, then per entry
//   u64 term, u64 proposal_id, u32 wire_len, op wire bytes.
// The header record carries currentTerm + votedFor so the host's durable
// batch is a complete election record (carry item A: the vote MUST be
// durable before the vote response leaves the module — restarts replay
// stored batches over the machine-state blob, which may predate a grant).
//
// CONFIG entries (joint consensus, Raft §6) ride the module log as ordinary
// entries whose op wire begins with the two-byte marker 0xFF 0x01 (never a
// CRABS op: an op wire starts with its u32 format version 3..6):
//   0xFF, 0x01, u8 kind, then
//     kind 1 (joint C_old,new):  u32 old_count, old×string16,
//                                u32 new_count, new×string16
//     kind 2 (final C_new):      u32 count, count×string16
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
// Persist batch format version (v2 = term/votedFor header, recoverable).
#define RAFT_PERSIST_VERSION  2
// Configuration entry payload framing (marker, version, kind, count words).
#define RAFT_CONFIG_MARKER        0xFF
#define RAFT_CONFIG_FORMAT        0x01
#define RAFT_CONFIG_KIND_JOINT    0x01
#define RAFT_CONFIG_KIND_FINAL    0x02
#define RAFT_CONFIG_HEADER_LEN    (2 + 1)   // marker + format + kind
#define RAFT_CONFIG_COUNT_LEN     4
// The member address book: every id ever named by the boot config or a
// committed-config decode, kept across config generations so replication
// cursors (match/next) stay addressable while lists churn. A joint pair of
// maxed lists needs both — the table spans 2 * CRABS_RAFT_MAX_PEERS.
#define RAFT_MEMBER_TABLE_MAX     (2 * CRABS_RAFT_MAX_PEERS)

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

// One durable batch handed to the host; resolved by persist_complete. The
// blob is module-owned until the completion (or a retry re-issues it).
typedef struct raft_persist_request_node_t {
  uint64_t handle;
  uint64_t first_index;
  uint64_t last_index;
  uint64_t epoch;   // persist epoch the batch was issued under (staleness)
  uint64_t header_term;               // the batch's term/votedFor header
  char     header_voted_for[CRABS_MAX_USER_ID];
  uint8_t* blob;
  size_t   blob_len;
  struct raft_persist_request_node_t* next;
} raft_persist_request_node_t;

// Vote traffic WITHHELD until the term/votedFor record is durable (carry
// item A): a grant response never leaves the reactor before the header
// batch carrying that grant is acked, and a candidacy solicitation waits
// the same way. Holds from superseded terms drop at flush time.
typedef struct raft_held_msg_t {
  raft_msg_kind_e kind;    // RAFT_MSG_VOTE_REQ or RAFT_MSG_VOTE_RESP only
  uint64_t term;
  char     to_peer[CRABS_MAX_USER_ID];
  bool     granted;        // VOTE_RESP payload
  uint64_t last_log_term;  // VOTE_REQ payload
  uint64_t last_log_index;
  struct raft_held_msg_t* next;
} raft_held_msg_t;

// One membership list (a consensus config): member indices into the module
// address book. A maxed peer table fits; the joint pair keeps both lists.
typedef struct {
  uint32_t member[CRABS_RAFT_MAX_PEERS];
  uint32_t member_n;
} raft_config_list_t;

typedef struct crabs_raft_module_s {
  crabs_raft_config_t config;

  // Member address book + ACTIVE COMMITTED config (joint consensus, §6):
  // config_old is the voting/commit list; config_new (member_n > 0) marks an
  // active joint C_old,new phase. Both derive from the boot config at create
  // and from committed config entries afterwards.
  char     member_ids[RAFT_MEMBER_TABLE_MAX][CRABS_MAX_USER_ID];
  uint32_t member_n;
  raft_config_list_t config_old;
  raft_config_list_t config_new;
  // Log index of the newest appended-but-uncommitted CONFIG entry (0 = no
  // change in flight) — the one-change-at-a-time guard of §6.
  uint64_t config_change_in_flight;

  raft_role_e role;
  uint64_t current_term;
  char     voted_for[CRABS_MAX_USER_ID];
  // Durable election record (carry item A): the term/votedFor values from
  // the last header batch the host acked. The LIVE pair above may run ahead
  // (a fresh grant) only while its header batch is undurable.
  uint64_t durable_term;
  char     durable_voted_for[CRABS_MAX_USER_ID];
  raft_held_msg_t* held_msgs;     // vote traffic awaiting header durability
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

  // Peer bookkeeping (Phase 2 replication):
  //   next_index[i] — next entry index to send to member i (leader only);
  //   match_index[i] — highest entry index member i accepted (AppendResp);
  //   vote_granted[i] — member i granted THIS candidate's current-term vote
  //     (idempotency guard for duplicated VoteResp — one tally per grant).
  // All indexed by the member ADDRESS BOOK (config generations reference it).
  uint64_t next_index[RAFT_MEMBER_TABLE_MAX];
  uint64_t match_index[RAFT_MEMBER_TABLE_MAX];
  bool     vote_granted[RAFT_MEMBER_TABLE_MAX];

  // Timers (the module's clock origin is the host's now_ms domain).
  uint64_t election_deadline_ms;
  uint64_t last_now_ms;          // most recent host clock this module saw
  uint64_t last_append_ms;       // last heartbeat/replication emit (leader)

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
  // Persist epoch: bumped whenever the undurable tail's meaning changes
  // under an outstanding window (log-suffix truncation). A persist_complete
  // answering a window from an older epoch is a STALE ack — the host stored
  // bytes the module has since discarded — and must not advance durability.
  uint64_t persist_epoch;

  // Fail-closed inbound counter (rejected malformed messages).
  uint32_t rejected_message_count;
} crabs_raft_module_s;

// Forward: the persistence window is shared by the propose, append and tick
// paths (defined in the parsing/persistence sections below).
static bool _raft_emit_persist_request(crabs_raft_module_s* module);
// Forward: replication fan-out and quorum bookkeeping (leader side, Phase 2).
static void _raft_send_append_to(crabs_raft_module_s* module,
                                 uint32_t member_index);
static void _raft_send_appends_all(crabs_raft_module_s* module);
static void _raft_become_leader(crabs_raft_module_s* module, uint64_t now_ms);
// Forward: joint-consensus config entry encode/commit-apply (below).
static bool _raft_entry_is_config(const raft_log_entry_t* entry);
// Validate a config entry payload and register its ids in the member table
// (called at append/import time so replication cursors exist pre-commit).
static crabs_error_e _raft_config_register_members(
    crabs_raft_module_s* module, const raft_log_entry_t* entry);
// Decode a committed config entry into its consensus lists (no mutation).
static crabs_error_e _raft_config_entry_lists(
    crabs_raft_module_s* module, const raft_log_entry_t* entry,
    raft_config_list_t* out_old, raft_config_list_t* out_new, uint8_t* out_kind);
// Commit-side apply: adopt the entry's lists into the active config.
static void _raft_config_apply_committed(crabs_raft_module_s* module,
                                         const raft_log_entry_t* entry);
// Append a config entry at the log tail (leader side, joint §6 mechanics):
// the C_old,new joint pair or the automatic C_new successor. Returns false
// on a full log / oversized payload — state stays untouched in that case.
static bool _raft_append_config_entry(crabs_raft_module_s* module,
                                      raft_config_list_t old_list,
                                      raft_config_list_t new_list,
                                      uint8_t kind);
// Shared leader-start tail (both the degenerate self-election and the won
// multi-node election): no-op entry, joint-resume, persist, fan-out.
static void _raft_become_leader_tail(crabs_raft_module_s* module, uint64_t now_ms);

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
  for (uint32_t member_index = 0; member_index < module->member_n;
       member_index++) {
    if (strncmp(module->member_ids[member_index], peer_id,
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

// Add an id to the member address book (idempotent); -1 when the table is
// full — a config generation that big is refused at decode time, so this
// only guards against corrupt input.
static int _raft_member_table_add(crabs_raft_module_s* module, const char* peer_id) {
  int existing = _raft_peer_index(module, peer_id);
  if (existing >= 0) return existing;
  if (module->member_n >= RAFT_MEMBER_TABLE_MAX) return -1;
  strncpy(module->member_ids[module->member_n], peer_id, CRABS_MAX_USER_ID - 1);
  module->member_n++;
  return (int)(module->member_n - 1);
}

static bool _raft_in_list(const raft_config_list_t* list, uint32_t member_index) {
  for (uint32_t slot = 0; slot < list->member_n; slot++) {
    if (list->member[slot] == member_index) return true;
  }
  return false;
}

static bool _raft_in_active_config(const crabs_raft_module_s* module,
                                   uint32_t member_index) {
  return _raft_in_list(&module->config_old, member_index) ||
         _raft_in_list(&module->config_new, member_index);
}

// Majority of a consensus list (Raft §5.1/§6: lists include this node).
static uint32_t _raft_list_majority(const raft_config_list_t* list) {
  return list->member_n / 2 + 1;
}

// The degenerate single-node cluster: a ONE-member committed config and no
// joint phase (self-election without vote exchange).
static bool _raft_single_member_config(const crabs_raft_module_s* module) {
  return module->config_old.member_n == 1 && module->config_new.member_n == 0;
}

// Whether the quorum rule currently spans a joint C_old,new phase.
static bool _raft_joint_active(const crabs_raft_module_s* module) {
  return module->config_new.member_n > 0;
}

// Majority reachability of ONE list for a log index (leader-side commit and
// the vote tally both reduce to "each config list's majority holds this").
static uint32_t _raft_stored_in_list(const crabs_raft_module_s* module,
                                     const raft_config_list_t* list,
                                     uint64_t entry_index) {
  uint32_t stored = 0;
  for (uint32_t slot = 0; slot < list->member_n; slot++) {
    uint32_t member_index = list->member[slot];
    if (_raft_is_self(module, module->member_ids[member_index])) {
      if (module->durable_upto >= entry_index) stored++;
    } else if (module->match_index[member_index] >= entry_index) {
      stored++;
    }
  }
  return stored;
}

// Votes currently tallied inside one list (the self-vote is vote_granted[]
// at this node's own index from election start).
static uint32_t _raft_votes_in_list(const crabs_raft_module_s* module,
                                    const raft_config_list_t* list) {
  uint32_t votes = 0;
  for (uint32_t slot = 0; slot < list->member_n; slot++) {
    if (module->vote_granted[list->member[slot]]) votes++;
  }
  return votes;
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
//   - multi-node leader/candidate (Raft §5.3/§5.4.2): commit rides the
//     quorum match — only entries from the CURRENT term are counted toward
//     a quorum (the §5.4.2 safety rule; committing one index commits the
//     whole prefix below it implicitly), and the leader's own durability
//     line stays the hard ceiling (the persistence contract above).
// Every newly committed CONTROL entry (no-op / config) is applied module-
// side only — it NEVER materializes as a machine op (no COMMITTED_OP
// notification). Config entries additionally update the active committed
// membership as the commit tip crosses them.
static void _raft_advance_commit(crabs_raft_module_s* module) {
  uint64_t commit_target;
  if (_raft_single_member_config(module)) {
    commit_target = module->durable_upto;         // degenerate quorum
  } else if (module->role == RAFT_ROLE_FOLLOWER) {
    commit_target = module->follower_commit_target;
  } else {
    // LEADER (and candidate-voted-self): quorum match over the config
    // list(s). Joint phase (Raft §6): BOTH lists' majorities must hold the
    // entry. Quorum rules always come from the COMMITTED config — a
    // C_old,new entry commits under the pre-change rules, exactly as the
    // dissertation requires.
    commit_target = module->commit_index;
    for (uint64_t entry_index = module->last_log_index;
         entry_index > module->commit_index; entry_index--) {
      raft_log_entry_t* entry = _raft_log_entry(module, entry_index);
      if (entry == NULL || entry->term != module->current_term) continue;
      bool quorum = _raft_stored_in_list(module, &module->config_old,
                                         entry_index) >=
                    _raft_list_majority(&module->config_old);
      if (quorum && _raft_joint_active(module)) {
        quorum = _raft_stored_in_list(module, &module->config_new,
                                      entry_index) >=
                 _raft_list_majority(&module->config_new);
      }
      if (quorum) {
        commit_target = entry_index;   // highest current-term quorum match
        break;
      }
    }
    if (commit_target == module->commit_index) {
      return;   // no current-term entry has quorum yet
    }
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
  bool joint_committed = false;   // the leader finishes the transition post-loop
  // Walk the newly committed range, oldest to newest: apply config state,
  // emit one COMMITTED_OP per DATA entry (control entries are suppressed).
  for (uint64_t committed_index = previous_commit + 1;
       committed_index <= module->commit_index; committed_index++) {
    raft_log_entry_t* entry = _raft_log_entry(module, committed_index);
    if (entry == NULL) break;
    bool is_config = _raft_entry_is_config(entry);
    if (is_config) {
      // The commit tip just crossed a config entry: an appended-but-
      // uncommitted change pointer at or below the tip is resolved.
      if (module->config_change_in_flight <= committed_index) {
        module->config_change_in_flight = 0;
      }
      _raft_config_apply_committed(module, entry);
      if (module->config_new.member_n > 0) joint_committed = true;
    }
    if (is_config || entry->wire_len == 0) {
      continue;   // control entry: module-internal, never a machine op
    }
    _raft_enqueue_notification(module, RAFT_NOTIFY_COMMITTED_OP, NULL,
                               entry->proposal_id, entry->op_wire,
                               entry->wire_len);
  }
  // Transition step 2 (leader side): a committed C_old,new commits its own
  // C_new successor automatically. Any leader (even one the change evicts)
  // may finish it — commit quorums still ride the committed joint rules.
  if (joint_committed && module->role == RAFT_ROLE_LEADER &&
      module->config_change_in_flight == 0) {
    raft_config_list_t joint_new = module->config_new;
    _raft_append_config_entry(module, module->config_old, joint_new,
                               RAFT_CONFIG_KIND_FINAL);
  }
  // A committed change that evicted this node steps it down (§6: a removed
  // member stops leading; it only learns through the committed entry).
  if (module->role == RAFT_ROLE_LEADER) {
    int self_index = _raft_peer_index(module, module->config.node_id);
    bool member = self_index >= 0 && _raft_in_active_config(module, (uint32_t)self_index);
    if (!member) {
      _raft_enqueue_notification(module, RAFT_NOTIFY_CONFIG_EXCLUDED, NULL,
                                 0, NULL, 0);
      module->role = RAFT_ROLE_FOLLOWER;
      module->leader_id[0] = '\0';
    }
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
// tallies land with Phase 2. Carried item A: both vote marshals take the
// EXPLICIT election term — held traffic (see the flush below) marshals the
// recorded term, never whatever the module's term happens to be later.
static bool _raft_marshal_vote_request(crabs_raft_module_s* module,
                                       const char* to_peer, uint64_t term,
                                       uint64_t last_log_term,
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
  uint8_t* bytes = _raft_marshal(RAFT_MSG_VOTE_REQ, term,
                                 body, writer.offset, &len);
  free(body);
  if (bytes == NULL) return false;
  _raft_enqueue_outbound(module, RAFT_MSG_VOTE_REQ, to_peer, bytes, len);
  return true;
}

static bool _raft_marshal_vote_response(crabs_raft_module_s* module,
                                        const char* to_peer, uint64_t term,
                                        bool granted) {
  uint8_t body[1];
  raft_wire_writer_t writer = { body, sizeof(body), 0, false };
  _raft_write_u8(&writer, granted ? 1 : 0);
  size_t len = 0;
  uint8_t* bytes = _raft_marshal(RAFT_MSG_VOTE_RESP, term,
                                 body, writer.offset, &len);
  if (bytes == NULL) return false;
  _raft_enqueue_outbound(module, RAFT_MSG_VOTE_RESP, to_peer, bytes, len);
  return true;
}

// ============================================================
// Vote-durability holds (carry item A — election safety)
// ============================================================
// Election safety (Raft §5.4.1) demands the term+vote be DURABLE before the
// vote is effective. The chosen design: a compact term/votedFor HEADER
// record rides EVERY persist batch, and hold-delayed vote traffic (a grant
// response, a candidacy solicitation) only leaves the reactor once the
// header batch acks durable. Tradeoff logged here: the candidate's election
// may wait one extra persist round-trip — a latency cost, never a safety
// one; the alternative (a dedicated persist request type ahead of the vote
// response, second queue lane) would split the single persistence window the
// whole reactor leans on and complicate the host contract for the same
// guarantee, so the header-in-batch design keeps the reactor simple and
// pure.
static void _raft_hold_msg(crabs_raft_module_s* module, raft_msg_kind_e kind,
                           uint64_t term, const char* to_peer, bool granted,
                           uint64_t last_log_term, uint64_t last_log_index) {
  raft_held_msg_t* held =
      (raft_held_msg_t*)get_clear_memory(sizeof(raft_held_msg_t));
  held->kind = kind;
  held->term = term;
  strncpy(held->to_peer, to_peer, CRABS_MAX_USER_ID - 1);
  held->granted = granted;
  held->last_log_term = last_log_term;
  held->last_log_index = last_log_index;
  held->next = module->held_msgs;
  module->held_msgs = held;
}

// Header batch acked (or the window resolved): release what is durably
// effective, drop what a newer term superseded, retain what a LATER header
// batch (already armed or to be armed on the next tick) will cover.
static void _raft_flush_held_msgs(crabs_raft_module_s* module) {
  raft_held_msg_t** link = &module->held_msgs;
  while (*link != NULL) {
    raft_held_msg_t* held = *link;
    enum { RETAIN, DELIVER, DROP } verdict = DELIVER;
    if (module->current_term < held->term || module->durable_term > held->term) {
      // Unreachable states (terms only move up): fail closed as DROP.
      verdict = DROP;
    } else if (module->current_term > held->term) {
      // Superseded term: the module moved on, this traffic never flows.
      verdict = DROP;
    } else if (module->durable_term < held->term) {
      // This term's header is still undurable — retain for a later flush.
      verdict = RETAIN;
    } else {
      // Header durable at this term: releases iff the durable vote agrees.
      if (held->granted &&
          strncmp(module->durable_voted_for, held->to_peer,
                  CRABS_MAX_USER_ID) != 0) {
        // A grant is effective only when the durable record carries it.
        verdict = DROP;
      } else if (!held->granted &&
                 strncmp(module->durable_voted_for, module->config.node_id,
                         CRABS_MAX_USER_ID) != 0) {
        // A solicitation flows only for a durably recorded candidacy.
        verdict = DROP;
      }
    }
    if (verdict == RETAIN) {
      link = &held->next;
      continue;
    }
    *link = held->next;
    if (verdict == DELIVER) {
      if (held->kind == RAFT_MSG_VOTE_REQ) {
        _raft_marshal_vote_request(module, held->to_peer, held->term,
                                   held->last_log_term, held->last_log_index);
      } else if (held->kind == RAFT_MSG_VOTE_RESP) {
        _raft_marshal_vote_response(module, held->to_peer, held->term,
                                    held->granted);
      }
    }
    free(held);
  }
}

// AppendEntries: entries after the point of agreement ship in order; an
// empty range is a heartbeat. Used in Phase 1 wire round-trip tests; the
// leader's replication loop drives it from Phase 2 on.
static bool _raft_marshal_append_request(crabs_raft_module_s* module,
                                         const char* to_peer,
                                         uint64_t first_index, uint64_t last_index,
                                         uint64_t prev_log_term,
                                         uint64_t prev_log_index) {
  // first_index == 0 encodes the EMPTY range (a heartbeat): entry_count 0,
  // entries ride only when first_index >= 1. first/last disagreeing about
  // emptiness, a range past the log tail, or a descending range refuse.
  bool empty_range = first_index == 0 && last_index == 0;
  if ((first_index == 0) != empty_range ||
      last_index > module->last_log_index ||
      (first_index > 0 && first_index > last_index + 1)) {
    return false;
  }
  uint64_t entry_count = empty_range ? 0 : last_index - first_index + 1;
  size_t body_len = CRABS_MAX_USER_ID + 2 + 8 * 3 + 4;
  for (uint64_t entry_index = first_index; empty_range == false &&
           entry_index <= last_index; entry_index++) {
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
  for (uint64_t entry_index = first_index; empty_range == false &&
           entry_index <= last_index; entry_index++) {
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
// Replication fan-out (Raft §5.3) — leader side
// ============================================================
// Ship the batch starting at next_index[i]: a heartbeat (prev = log tail,
// empty entry range) when the follower is caught up, else the next batch of
// entries with the log-matching prev_term/prev_index prefix. The response's
// success/failure drives next_index/match_index repair.
static void _raft_send_append_to(crabs_raft_module_s* module,
                                 uint32_t member_index) {
  if (member_index >= module->member_n) return;
  if (_raft_is_self(module, module->member_ids[member_index])) return;
  // Leader guard: replication only ever runs on the leader (a deposed node
  // keeps stale bookkeeping — never send from a follower/candidate).
  if (module->role != RAFT_ROLE_LEADER) return;

  uint64_t send_index = module->next_index[member_index];
  if (send_index < 1) send_index = 1;
  if (send_index > module->last_log_index + 1) {
    send_index = module->last_log_index + 1;   // stale bookkeeping: clamp
  }
  uint64_t prev_log_index = send_index - 1;
  uint64_t prev_log_term = 0;
  raft_log_entry_t* prev_entry = _raft_log_entry(module, prev_log_index);
  if (prev_entry != NULL) {
    prev_log_term = prev_entry->term;
  }
  // Heartbeat when the peer has everything; else a bounded batch.
  uint64_t first_index = send_index;
  uint64_t last_index = send_index - 1;
  if (send_index <= module->last_log_index) {
    last_index = send_index + CRABS_RAFT_APPEND_BATCH_ENTRIES - 1;
    if (last_index > module->last_log_index) {
      last_index = module->last_log_index;
    }
  } else {
    first_index = 0;   // empty range == heartbeat
    last_index = 0;
  }
  if (_raft_marshal_append_request(module, module->member_ids[member_index],
                                   first_index, last_index,
                                   prev_log_term, prev_log_index)) {
    module->last_append_ms = module->last_now_ms;
  }
}

static void _raft_send_appends_all(crabs_raft_module_s* module) {
  for (uint32_t member_index = 0; member_index < module->member_n;
       member_index++) {
    _raft_send_append_to(module, member_index);
  }
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
  // A leading node learns of a newer term from any RequestVote: step down
  // first, then evaluate the grant (only followers grant votes). A voter
  // grants only to a member of its OWN active committed config (§6: joint
  // phase members belong to the union of the two lists).
  _raft_step_down(module, term, candidate_id);
  if (term < module->current_term) {
    _raft_marshal_vote_response(module, candidate_id, module->current_term, false);
    return;
  }
  int candidate_index = _raft_peer_index(module, candidate_id);
  bool config_allows_grant = candidate_index >= 0 &&
                             _raft_in_active_config(module, (uint32_t)candidate_index);
  // Up-to-dateness check (Raft §5.4.1): the candidate's log must be at
  // least as long as ours — its last entry's term strictly newer, or the
  // same term with an index at least ours. Denying an out-of-date candidate
  // is what keeps committed entries ahead of whoever gets elected.
  raft_log_entry_t* tail = _raft_log_entry(module, module->last_log_index);
  uint64_t my_last_log_term = tail != NULL ? tail->term : 0;
  bool candidate_up_to_date =
      last_log_term > my_last_log_term ||
      (last_log_term == my_last_log_term &&
       last_log_index >= module->last_log_index);
  bool grant =
      candidate_up_to_date &&
      config_allows_grant &&
      (module->voted_for[0] == '\0' ||
       strncmp(module->voted_for, candidate_id, CRABS_MAX_USER_ID) == 0);
  if (grant) {
    strncpy(module->voted_for, candidate_id, CRABS_MAX_USER_ID - 1);
    module->election_deadline_ms = now_ms + _raft_random_election_timeout(module);
    // Carry item A: the vote is effective only AFTER its term/votedFor
    // header batch is durable — hold the response out of the reactor and
    // arm the header batch immediately (no tick required).
    _raft_hold_msg(module, RAFT_MSG_VOTE_RESP, module->current_term,
                   candidate_id, true, 0, 0);
    _raft_emit_persist_request(module);
    return;
  }
  // Denials carry no vote — no durability gate needed for them.
  _raft_marshal_vote_response(module, candidate_id, module->current_term, false);
}

static void _raft_handle_vote_response(crabs_raft_module_s* module,
                                       uint64_t term,
                                       raft_wire_reader_t* reader,
                                       const char* voter_id,
                                       uint64_t now_ms) {
  uint8_t granted;
  if (!_raft_read_u8(reader, &granted)) {
    module->rejected_message_count++;
    return;
  }
  _raft_step_down(module, term, NULL);
  // Tallies count ONLY for a candidate in its own election term: a stale
  // response (older term) must not increment anything, and a deposed
  // candidate stops tallying entirely (step_down above already flipped the
  // role for a newer term).
  if (module->role != RAFT_ROLE_CANDIDATE || term != module->current_term) {
    return;
  }
  int voter_index = _raft_peer_index(module, voter_id);
  if (voter_index < 0) {
    module->rejected_message_count++;
    return;
  }
  if (granted != 1) return;
  // Duplicate response (fault model duplicates wire messages): one grant
  // per member per election — the per-member guard keeps the tally honest.
  if (module->vote_granted[voter_index]) return;
  module->vote_granted[voter_index] = true;
  // Joint phase (Raft §6): the election wins only when BOTH config lists
  // carry majorities; otherwise the committed config's majority decides.
  bool elected = _raft_votes_in_list(module, &module->config_old) >=
                 _raft_list_majority(&module->config_old);
  if (elected && _raft_joint_active(module)) {
    elected = _raft_votes_in_list(module, &module->config_new) >=
              _raft_list_majority(&module->config_new);
  }
  if (elected) {
    _raft_become_leader(module, now_ms);
  }
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
  // Same-term claims (Raft §5.2): a candidate loses to a leader from its own
  // election term — that leader already proved the quorum. A leader ignores
  // a same-term rival's AppendEntries entirely (two leaders in one term
  // cannot both hold quorum; the false claim must not rewrite our log).
  if (term == module->current_term && module->role == RAFT_ROLE_LEADER) {
    module->rejected_message_count++;
    return;
  }
  if (term == module->current_term && module->role == RAFT_ROLE_CANDIDATE) {
    module->role = RAFT_ROLE_FOLLOWER;
  }
  _raft_step_down(module, term, leader_id);
  // A STALE leader's AppendEntries (older term — a partitioned leader whose
  // term has been overtaken) must be refused outright: its prev/entries
  // describe a history the current term may have replaced, letting it write
  // would be a stale-leader resurrection. Reply with a failure response so
  // the old leader (still thinking it leads) backtracks — harmless, it
  // cannot win a vote again with an out-of-date log.
  if (term < module->current_term) {
    _raft_marshal_append_response(module, leader_id, false, 0);
    return;
  }
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
  // Discarded entries must also STOP counting as durable here: durable_upto
  // falls back with them, so a rewritten index cannot inherit its dead
  // occupant's ack. The outstanding persist window (if any) stays valid for
  // the host — but its batch is STALE (it named entries that no longer
  // exist): the persist epoch makes its eventual ack identify as stale, and
  // the re-armed window re-persists what survives.
  if (module->last_log_index > prev_log_index &&
      prev_log_index >= module->commit_index) {
    for (uint64_t stale_index = prev_log_index + 1;
         stale_index <= module->last_log_index; stale_index++) {
      raft_log_entry_t* stale = _raft_log_entry(module, stale_index);
      if (stale == NULL) break;
      _raft_log_entry_release(stale);
    }
    if (module->durable_upto > prev_log_index) {
      module->durable_upto = prev_log_index;
    }
    module->persist_epoch++;
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
    // wire_len 0 is the leadership NO-OP entry (Raft §8); cap and remaining
    // bytes still bound every non-empty payload.
    if (entry_wire_len > CRABS_RAFT_MAX_OP_WIRE_BYTES ||
        (size_t)entry_wire_len > reader->len - reader->offset) {
      module->rejected_message_count++;
      return;
    }
    bool wire_failed = false;
    const uint8_t* entry_wire = _raft_read_bytes(reader, entry_wire_len, &wire_failed);
    if (entry_wire == NULL && entry_wire_len > 0) {
      module->rejected_message_count++;
      return;
    }
    uint64_t append_index = accepted_match + 1;
    if (append_index > CRABS_RAFT_MAX_LOG_ENTRIES ||
        _raft_log_grow(module, append_index) != CRABS_SUCCESS) {
      module->rejected_message_count++;
      return;
    }
    raft_log_entry_t incoming = { entry_term, entry_proposal_id,
                                  (uint8_t*)entry_wire, entry_wire_len };
    raft_log_entry_t* slot = _raft_log_entry(module, append_index);
    if (slot != NULL) {
      if (slot->term != entry_term) {
        // Conflicting entry after the point of agreement: refuse instead of
        // rewriting (full conflict repair is a Phase 2 concern).
        module->rejected_message_count++;
        return;
      }
      // Same term at the same position: idempotent duplicate — skip. A
      // duplicate CONFIG entry still registers its members (idempotent).
      if (_raft_entry_is_config(&incoming)) {
        (void)_raft_config_register_members(module, &incoming);
      }
    } else {
      // A CONFIG entry must decode cleanly BEFORE it enters the log (fail
      // closed; its ids also join the member table here, pre-commit).
      if (_raft_entry_is_config(&incoming) &&
          _raft_config_register_members(module, &incoming) != CRABS_SUCCESS) {
        module->rejected_message_count++;
        return;
      }
      uint8_t* copy = entry_wire_len > 0 ? (uint8_t*)get_memory(entry_wire_len) : NULL;
      if (copy != NULL) memcpy(copy, entry_wire, entry_wire_len);
      slot = &module->log[append_index - 1];
      slot->term = entry_term;
      slot->proposal_id = entry_proposal_id;
      slot->op_wire = copy;
      slot->wire_len = entry_wire_len;
      module->last_log_index = append_index;
      appended_any = true;   // follower durability rides the persist window too
    }
    accepted_match = append_index;
  }

  // Commit advance on the follower waits for the follower's OWN durability:
  // the leader's commit index is only the ceiling. persist_complete re-runs
  // _raft_advance_commit once the appended range is acked durable; this call
  // covers the heartbeat case where the target rises with durability already
  // behind it.
  if (module->follower_commit_target < leader_commit) {
    module->follower_commit_target = leader_commit;
  }
  if (appended_any) {
    _raft_emit_persist_request(module);
  }
  _raft_advance_commit(module);
  _raft_marshal_append_response(module, leader_id, true, accepted_match);
}

static void _raft_handle_append_response(crabs_raft_module_s* module,
                                         uint64_t term,
                                         raft_wire_reader_t* reader,
                                         const char* responder_id,
                                         uint64_t now_ms) {
  uint8_t success;
  uint64_t match_index;
  if (!_raft_read_u8(reader, &success) || !_raft_read_u64(reader, &match_index)) {
    module->rejected_message_count++;
    return;
  }
  _raft_step_down(module, term, NULL);
  // Repair bookkeeping is a LEADER-only concern: a deposed (or stale-term)
  // response must not move next/match indices.
  if (module->role != RAFT_ROLE_LEADER || term != module->current_term) {
    return;
  }
  int responder_index = _raft_peer_index(module, responder_id);
  if (responder_index < 0) {
    module->rejected_message_count++;
    return;
  }
  if (success != 1) {
    // Log-matching failure (Raft §5.3): backtrack next_index one entry and
    // retry immediately — the next probe finds the conflict point (or the
    // follower's tail) without waiting for the heartbeat.
    if (module->next_index[responder_index] > 1) {
      module->next_index[responder_index]--;
    }
    _raft_send_append_to(module, (uint32_t)responder_index);
    return;
  }
  bool match_advanced = match_index > module->match_index[responder_index];
  if (match_advanced) {
    module->match_index[responder_index] = match_index;
  }
  if (match_index >= module->next_index[responder_index]) {
    module->next_index[responder_index] = match_index + 1;
  }
  if (match_advanced) {
    _raft_advance_commit(module);
  }
  // Anything left unsent beyond the accepted batch rides the next heartbeat
  // (tick) — bounded batches converge without uncontrolled fan-out.
  (void)now_ms;
}

static void _raft_process_inbound(crabs_raft_module_s* module,
                                  const char* peer_id,
                                  const uint8_t* blob, size_t len,
                                  uint64_t now_ms) {
  module->last_now_ms = now_ms;
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
      _raft_handle_vote_response(module, term, &reader, peer_id, now_ms);
      break;
    case RAFT_MSG_APPEND_REQ:
      _raft_handle_append_request(module, term, &reader, now_ms);
      break;
    case RAFT_MSG_APPEND_RESP:
      _raft_handle_append_response(module, term, &reader, peer_id, now_ms);
      break;
    default:
      module->rejected_message_count++;
      break;
  }
}

// ============================================================
// Joint-consensus configuration entries (Raft §6, on the module's own log)
// ============================================================
// A config entry is an ordinary log entry whose op wire begins with the
// 0xFF/0x01 marker (never a CRABS op). Control entries materialize NOWHERE:
// they are applied module-side, never notified as machine ops.
static bool _raft_entry_is_config(const raft_log_entry_t* entry) {
  return entry != NULL && entry->wire_len >= RAFT_CONFIG_HEADER_LEN &&
         entry->op_wire != NULL &&
         entry->op_wire[0] == RAFT_CONFIG_MARKER &&
         entry->op_wire[1] == RAFT_CONFIG_FORMAT;
}

// Validate a config entry payload AND register all its ids in the member
// address book (idempotent). Called whenever the entry first becomes known
// (leader append, follower append, import, recovery) so replication cursors
// and member indices exist BEFORE the entry can commit.
static crabs_error_e _raft_config_register_members(crabs_raft_module_s* module,
                                                   const raft_log_entry_t* entry) {
  raft_wire_reader_t reader = { entry->op_wire, entry->wire_len, 0 };
  uint8_t format_marker = 0;
  uint8_t format = 0;
  uint8_t kind = 0;
  if (!_raft_read_u8(&reader, &format_marker) ||
      !_raft_read_u8(&reader, &format) || !_raft_read_u8(&reader, &kind)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  static const uint8_t list_counts[2][2] = {
    /* kind JOINT: old 1, new 1 */ {1, 1},
    /* kind FINAL: new list only */ {0, 1}
  };
  if (format != RAFT_CONFIG_FORMAT ||
      (kind != RAFT_CONFIG_KIND_JOINT && kind != RAFT_CONFIG_KIND_FINAL)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  int kind_slot = kind == RAFT_CONFIG_KIND_JOINT ? 0 : 1;
  for (uint32_t list_slot = 0; list_slot < 2; list_slot++) {
    if (list_counts[kind_slot][list_slot] == 0) continue;
    uint32_t member_count = 0;
    if (!_raft_read_u32(&reader, &member_count) ||
        member_count == 0 || member_count > CRABS_RAFT_MAX_PEERS) {
      return CRABS_ERR_INVALID_PARAM;
    }
    for (uint32_t id_slot = 0; id_slot < member_count; id_slot++) {
      char id[CRABS_MAX_USER_ID];
      if (!_raft_read_string16(&reader, id, sizeof(id))) {
        return CRABS_ERR_INVALID_PARAM;
      }
      if (_raft_member_table_add(module, id) < 0) {
        return CRABS_ERR_INTERNAL;   // address book exhausted
      }
    }
  }
  if (reader.offset != entry->wire_len) {
    return CRABS_ERR_INVALID_PARAM;   // trailing bytes: corruption
  }
  return CRABS_SUCCESS;
}

// Decode a config entry into consensus lists (indices resolved through the
// address book registered by _raft_config_register_members).
static crabs_error_e _raft_config_entry_lists(crabs_raft_module_s* module,
                                              const raft_log_entry_t* entry,
                                              raft_config_list_t* out_old,
                                              raft_config_list_t* out_new,
                                              uint8_t* out_kind) {
  memset(out_old, 0, sizeof(*out_old));
  memset(out_new, 0, sizeof(*out_new));
  raft_wire_reader_t reader = { entry->op_wire, entry->wire_len, 0 };
  uint8_t dump = 0;
  uint8_t kind = 0;
  if (!_raft_read_u8(&reader, &dump) || !_raft_read_u8(&reader, &dump) ||
      !_raft_read_u8(&reader, &kind)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  uint32_t list_count = kind == RAFT_CONFIG_KIND_JOINT ? 2 : 1;
  for (uint32_t list_slot = 0; list_slot < list_count; list_slot++) {
    // The joint pair decodes old→out_old, new→out_new; the FINAL entry's
    // single list decodes into out_NEW (it BECOMES the plain committed
    // config at apply time).
    raft_config_list_t* list =
        (list_slot == 0 && kind == RAFT_CONFIG_KIND_JOINT) ? out_old : out_new;
    list->member_n = 0;
    uint32_t member_count = 0;
    if (!_raft_read_u32(&reader, &member_count) ||
        member_count == 0 || member_count > CRABS_RAFT_MAX_PEERS) {
      return CRABS_ERR_INVALID_PARAM;
    }
    for (uint32_t id_slot = 0; id_slot < member_count; id_slot++) {
      char id[CRABS_MAX_USER_ID];
      if (!_raft_read_string16(&reader, id, sizeof(id))) {
        return CRABS_ERR_INVALID_PARAM;
      }
      int member_index = _raft_peer_index(module, id);
      if (member_index < 0) return CRABS_ERR_INVALID_PARAM;   // not registered
      list->member[list->member_n++] = (uint32_t)member_index;
    }
  }
  *out_kind = kind;
  return CRABS_SUCCESS;
}

// Adopt a committed config entry into the active committed config.
static void _raft_config_apply_committed(crabs_raft_module_s* module,
                                         const raft_log_entry_t* entry) {
  raft_config_list_t entry_old;
  raft_config_list_t entry_new;
  uint8_t kind = 0;
  // Validated at append/import; a decode failure here means module-internal
  // corruption — leave the active config untouched (fail closed).
  if (_raft_config_entry_lists(module, entry, &entry_old, &entry_new,
                               &kind) != CRABS_SUCCESS) {
    return;
  }
  if (kind == RAFT_CONFIG_KIND_JOINT) {
    module->config_old = entry_old;
    module->config_new = entry_new;
  } else {
    module->config_old = entry_new;
    module->config_new.member_n = 0;
  }
}

// Leader-side append of a config entry at the log tail (the joint
// C_old,new from change_membership and the automatic C_new successor).
static bool _raft_append_config_entry(crabs_raft_module_s* module,
                                      raft_config_list_t old_list,
                                      raft_config_list_t new_list,
                                      uint8_t kind) {
  if (module->last_log_index >= CRABS_RAFT_MAX_LOG_ENTRIES) {
    _raft_enqueue_notification(module, RAFT_NOTIFY_LOG_FULL, NULL, 0, NULL, 0);
    return false;
  }
  // Encode the payload: joint carries BOTH lists, final carries the new one.
  size_t wire_len = RAFT_CONFIG_HEADER_LEN;
  if (kind == RAFT_CONFIG_KIND_JOINT) {
    wire_len += RAFT_CONFIG_COUNT_LEN +
                (size_t)old_list.member_n * (2 + CRABS_MAX_USER_ID);
  }
  wire_len += RAFT_CONFIG_COUNT_LEN +
              (size_t)new_list.member_n * (2 + CRABS_MAX_USER_ID);
  if (wire_len > CRABS_RAFT_MAX_OP_WIRE_BYTES) return false;
  uint8_t* wire = (uint8_t*)get_clear_memory(wire_len);
  raft_wire_writer_t writer = { wire, wire_len, 0, false };
  _raft_write_u8(&writer, RAFT_CONFIG_MARKER);
  _raft_write_u8(&writer, RAFT_CONFIG_FORMAT);
  _raft_write_u8(&writer, kind);
  if (kind == RAFT_CONFIG_KIND_JOINT) {
    _raft_write_u32(&writer, old_list.member_n);
    for (uint32_t slot = 0; slot < old_list.member_n; slot++) {
      _raft_write_string16(&writer, module->member_ids[old_list.member[slot]]);
    }
  }
  _raft_write_u32(&writer, new_list.member_n);
  for (uint32_t slot = 0; slot < new_list.member_n; slot++) {
    _raft_write_string16(&writer, module->member_ids[new_list.member[slot]]);
  }
  if (writer.failed) {
    free(wire);
    return false;
  }
  if (_raft_log_grow(module, module->last_log_index + 1) != CRABS_SUCCESS) {
    free(wire);
    return false;
  }
  uint64_t entry_index = module->last_log_index + 1;
  raft_log_entry_t* entry = &module->log[entry_index - 1];
  entry->term = module->current_term;
  entry->proposal_id = entry_index;
  entry->op_wire = wire;
  // The buffer was sized with the PER-MEMBER MAX; the entry's true length
  // is what the encoder actually wrote (the decoder requires exact
  // consumption).
  entry->wire_len = (uint32_t)writer.offset;
  module->last_log_index = entry_index;
  // The ids join the address book NOW (pre-commit): replication cursors and
  // quorum counts stay addressable while the entry is only appended.
  if (_raft_config_register_members(module, entry) != CRABS_SUCCESS) {
    // Encode/decode disagreement is module-internal corruption — roll the
    // entry back (fail closed rather than ship an invalid entry).
    _raft_log_entry_release(entry);
    entry->term = 0;
    entry->proposal_id = 0;
    module->last_log_index = entry_index - 1;
    return false;
  }
  module->config_change_in_flight = entry_index;
  _raft_emit_persist_request(module);
  _raft_send_appends_all(module);
  return true;
}

// ============================================================
// Persistence (single outstanding window)
// ============================================================
// Build and hand out one persist request covering the undurable tail
// [durable_upto + 1, last_log_index], ALWAYS carrying the term/votedFor
// header record (carry item A). Returns true when a request became
// outstanding (or nothing needed doing).
static bool _raft_emit_persist_request(crabs_raft_module_s* module) {
  if (module->persist_outstanding != NULL) return true;   // window busy
  bool header_dirty =
      module->current_term != module->durable_term ||
      strncmp(module->voted_for, module->durable_voted_for,
              CRABS_MAX_USER_ID) != 0;
  if (module->durable_upto >= module->last_log_index && !header_dirty) {
    return true;
  }
  uint64_t first_index = module->durable_upto + 1;
  size_t batch_len = 1 + 8 + 8 + 2 + strlen(module->voted_for) + 4;
  for (uint64_t entry_index = first_index; entry_index <= module->last_log_index;
       entry_index++) {
    raft_log_entry_t* entry = _raft_log_entry(module, entry_index);
    if (entry == NULL) return false;
    batch_len += RAFT_ENTRY_FRAMING_LEN + entry->wire_len;
  }
  uint8_t* batch = (uint8_t*)get_clear_memory(batch_len);
  raft_wire_writer_t writer = { batch, batch_len, 0, false };
  _raft_write_u8(&writer, RAFT_PERSIST_VERSION);
  _raft_write_u64(&writer, first_index);
  _raft_write_u64(&writer, module->current_term);
  _raft_write_string16(&writer, module->voted_for);
  _raft_write_u32(&writer,
                  (uint32_t)(module->last_log_index >= first_index
                                 ? module->last_log_index - first_index + 1
                                 : 0));
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
  node->epoch = module->persist_epoch;
  node->header_term = module->current_term;
  strncpy(node->header_voted_for, module->voted_for, CRABS_MAX_USER_ID - 1);
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

  // Election tally: fresh per term — the self-vote sits at this node's own
  // address-book index, each member answers at most once (vote_granted
  // guard), and the config list(s)' majorities promote.
  memset(module->vote_granted, 0, sizeof(module->vote_granted));
  int self_index = _raft_peer_index(module, module->config.node_id);
  if (self_index >= 0) module->vote_granted[(uint32_t)self_index] = true;

  if (_raft_single_member_config(module)) {
    // Degenerate single node: NO vote exchange — the sole member elects
    // itself immediately (quorum of 1 is trivially reached).
    module->role = RAFT_ROLE_LEADER;
    strncpy(module->voted_for, module->config.node_id, CRABS_MAX_USER_ID - 1);
    module->leader_id[0] = '\0';
    _raft_enqueue_notification(module, RAFT_NOTIFY_BECAME_LEADER,
                               module->config.node_id, 0, NULL, 0);
    module->election_deadline_ms = now_ms + _raft_random_election_timeout(module);
    _raft_become_leader_tail(module, now_ms);
    return;
  }

  // Multi-node path: candidate — self-vote, then solicit every other known
  // member of the address book (the joint phase spans both lists' members).
  module->role = RAFT_ROLE_CANDIDATE;
  strncpy(module->voted_for, module->config.node_id, CRABS_MAX_USER_ID - 1);
  module->leader_id[0] = '\0';
  module->election_deadline_ms = now_ms + _raft_random_election_timeout(module);
  raft_log_entry_t* tail = _raft_log_entry(module, module->last_log_index);
  for (uint32_t member_index = 0; member_index < module->member_n;
       member_index++) {
    const char* peer_id = module->member_ids[member_index];
    if (_raft_is_self(module, peer_id)) continue;
    // Carry item A: the term+self-vote must be durable BEFORE any
    // solicitation is effective — hold them behind the header batch.
    _raft_hold_msg(module, RAFT_MSG_VOTE_REQ, module->current_term, peer_id,
                   false, tail != NULL ? tail->term : 0, module->last_log_index);
  }
}

// Majority vote secured (Raft §5.2): the candidate becomes leader, seeds the
// replication cursors, and immediately fans out AppendEntries — an empty
// body per caught-up peer, or the unsent batch for laggards. The fan-out is
// also the heartbeat that demobilizes the losers' election clocks.
static void _raft_become_leader(crabs_raft_module_s* module, uint64_t now_ms) {
  module->role = RAFT_ROLE_LEADER;
  module->leader_id[0] = '\0';
  for (uint32_t member_index = 0; member_index < RAFT_MEMBER_TABLE_MAX;
       member_index++) {
    module->match_index[member_index] = 0;
    module->next_index[member_index] = module->last_log_index + 1;
  }
  module->last_append_ms = now_ms;
  _raft_enqueue_notification(module, RAFT_NOTIFY_BECAME_LEADER,
                             module->config.node_id, 0, NULL, 0);
  _raft_become_leader_tail(module, now_ms);
}

// Shared leader-start tail (degenerate single node and won elections alike):
// append the §8 leadership NO-OP entry immediately, resume a joint
// consensus transition the committed config left open, persist the new
// tail, and fan the batch out.
static void _raft_become_leader_tail(crabs_raft_module_s* module,
                                     uint64_t now_ms) {
  // Leadership no-op (Raft §8 liveness): the leader can commit in its own
  // term even when prior-term tails stall under the §5.4.2 rule. wire_len 0
  // marks the entry; committed no-ops never materialize as machine ops.
  if (_raft_log_grow(module, module->last_log_index + 1) == CRABS_SUCCESS) {
    uint64_t noop_index = module->last_log_index + 1;
    raft_log_entry_t* entry = &module->log[noop_index - 1];
    entry->term = module->current_term;
    entry->proposal_id = noop_index;
    entry->op_wire = NULL;
    entry->wire_len = 0;
    module->last_log_index = noop_index;
  }
  // A committed C_old,new awaiting its C_new successor resumes under a NEW
  // leader too (it inherits the joint phase and finishes the transition; the
  // leader that committed the joint entry appended C_new in its own
  // advance_commit post-loop step).
  if (_raft_joint_active(module) && module->config_change_in_flight == 0) {
    raft_config_list_t joint_new = module->config_new;
    _raft_append_config_entry(module, module->config_old, joint_new,
                               RAFT_CONFIG_KIND_FINAL);
  }
  _raft_emit_persist_request(module);
  _raft_send_appends_all(module);
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
  // Membership: the boot config IS the initial committed config (a config
  // entry in the log replaces it the moment one commits).
  for (uint32_t member_index = 0; member_index < cfg->peer_count;
       member_index++) {
    _raft_member_table_add(module, cfg->peer_ids[member_index]);
  }
  module->config_old.member_n = 0;
  for (uint32_t member_index = 0; member_index < cfg->peer_count;
       member_index++) {
    int slot = _raft_peer_index(module, cfg->peer_ids[member_index]);
    module->config_old.member[slot] = (uint32_t)slot;
    module->config_old.member_n++;
  }
  // Time origin: the host's now_ms domain. The first deadline is the
  // randomized timeout after "time zero", so the first tick at now_ms >=
  // deadline triggers the election. Deadlines re-randomize on every reset.
  module->election_deadline_ms = _raft_random_election_timeout(module);
  for (uint32_t member_index = 0; member_index < RAFT_MEMBER_TABLE_MAX;
       member_index++) {
    module->next_index[member_index] = 1;
    module->match_index[member_index] = 0;
  }
  // Durable election record starts consistent with the (durable) boot state.
  module->durable_term = 0;
  module->durable_voted_for[0] = '\0';
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
  raft_held_msg_t* held = module->held_msgs;
  while (held != NULL) {
    raft_held_msg_t* next = held->next;
    free(held);
    held = next;
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
  module->last_now_ms = now_ms;
  switch (module->role) {
    case RAFT_ROLE_FOLLOWER:
    case RAFT_ROLE_CANDIDATE:
      if (now_ms >= module->election_deadline_ms) {
        _raft_begin_election(module, now_ms);   // candidate retry on split vote
      }
      break;
    case RAFT_ROLE_LEADER:
      // Heartbeats (Raft §5.2): an empty AppendEntries to every peer on the
      // heartbeat interval, at the slowest (any earlier replication rides
      // propose/persist events). The election deadline keeps ticking under
      // the leader too — a stale bookkeeping clock must not silence it.
      if (now_ms - module->last_append_ms >=
          module->config.heartbeat_interval_ms) {
        _raft_send_appends_all(module);
      }
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
  _raft_process_inbound(module, peer_id, blob, len, now_ms);
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
    // Bounded log full (see the header growth model — compaction decision
    // shipped Phase 3): refusal keeps the module healthy and the committed
    // prefix intact; the notification makes the ceiling explicit.
    _raft_enqueue_notification(module, RAFT_NOTIFY_LOG_FULL, NULL, 0, NULL, 0);
    return CRABS_ERR_INTERNAL;
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
  // required for the persistence event to exist), and fan the new entry out
  // to the followers the same way (propose-driven replication; the batch
  // heartbeats cover anything the fan-out misses).
  _raft_emit_persist_request(module);
  _raft_send_appends_all(module);
  *proposal_id = new_index;
  return CRABS_SUCCESS;
}

// Joint-consensus membership change (Raft §6): the leader appends the
// C_old,new joint entry (old = the active committed config, new = the
// caller's list). The C_new successor appends automatically once the joint
// entry commits (or when a new leader resumes the transition), and THAT
// entry's commit ends the phase.
crabs_error_e crabs_raft_module_change_membership(
    crabs_raft_module_t* module_opaque, const char* const* new_member_ids,
    uint32_t member_count, uint64_t* proposal_id) {
  crabs_raft_module_s* module = (crabs_raft_module_s*)module_opaque;
  if (module == NULL || proposal_id == NULL ||
      (member_count > 0 && new_member_ids == NULL)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  *proposal_id = 0;
  if (module->role != RAFT_ROLE_LEADER) {
    _raft_enqueue_notification(module, RAFT_NOTIFY_PROPOSAL_NOT_LEADER,
                               module->leader_id, 0, NULL, 0);
    return CRABS_ERR_ORDERING_NOT_LEADER;
  }
  if (member_count == 0 || member_count > CRABS_RAFT_MAX_PEERS) {
    return CRABS_ERR_INVALID_PARAM;
  }
  for (uint32_t slot = 0; slot < member_count; slot++) {
    if (new_member_ids[slot] == NULL || new_member_ids[slot][0] == '\0') {
      return CRABS_ERR_INVALID_PARAM;
    }
  }
  // ONE change at a time (§6): an appended-but-uncommitted config entry, or
  // an active joint phase, blocks a new change.
  if (module->config_change_in_flight != 0 || _raft_joint_active(module)) {
    return CRABS_ERR_ORDERING_CHANGE_IN_FLIGHT;
  }
  // Build the joint pair: old = the active committed config, new = the
  // requested list (its ids join the address book in order of first use so
  // both lists reference stable member indices).
  raft_config_list_t new_list = {{0}, 0};
  for (uint32_t slot = 0; slot < member_count; slot++) {
    int member_index = _raft_member_table_add(module, new_member_ids[slot]);
    if (member_index < 0) return CRABS_ERR_INTERNAL;   // address book full
    new_list.member[new_list.member_n++] = (uint32_t)member_index;
  }
  if (!_raft_append_config_entry(module, module->config_old, new_list,
                                 RAFT_CONFIG_KIND_JOINT)) {
    return CRABS_ERR_INTERNAL;   // full log or oversized payload
  }
  *proposal_id = module->last_log_index;
  return CRABS_SUCCESS;
}

// Crash recovery from the HOST's durable raft record (carry item A): parse
// a stored persist batch (v2, with the term/votedFor header) and merge it —
// election records adopt, entries at/after the batch's first index land,
// committed-prefix contradictions fail closed.
crabs_error_e crabs_raft_module_recover_from_persist(
    crabs_raft_module_t* module_opaque, const uint8_t* batch, size_t batch_len) {
  crabs_raft_module_s* module = (crabs_raft_module_s*)module_opaque;
  if (module == NULL || batch == NULL || batch_len == 0) {
    return CRABS_ERR_INVALID_PARAM;
  }
  raft_wire_reader_t reader = { batch, batch_len, 0 };
  uint8_t version = 0;
  uint64_t first_index = 0;
  uint64_t header_term = 0;
  char header_voted_for[CRABS_MAX_USER_ID];
  uint32_t entry_count = 0;
  if (!_raft_read_u8(&reader, &version) || version != RAFT_PERSIST_VERSION ||
      !_raft_read_u64(&reader, &first_index) ||
      !_raft_read_u64(&reader, &header_term) ||
      !_raft_read_string16(&reader, header_voted_for,
                           sizeof(header_voted_for)) ||
      !_raft_read_u32(&reader, &entry_count)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // Bound-then-allocate: every entry needs its full 20-byte framing (a
  // no-op entry carries zero wire bytes but still its framing).
  if ((size_t)entry_count > (reader.len - reader.offset) / RAFT_ENTRY_FRAMING_LEN) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (entry_count > 0 && (first_index == 0 ||
      first_index + entry_count - 1 > CRABS_RAFT_MAX_LOG_ENTRIES)) {
    return CRABS_ERR_INVALID_PARAM;
  }
  // Header adoption: a batch from the CURRENT term may inject the vote ONLY
  // into an empty record; a contradictory record means divergent durable
  // state (fail closed). Older batches yield to the machine blob's term.
  if (header_term >= module->current_term) {
    if (header_term > module->current_term) {
      module->current_term = header_term;
      strncpy(module->voted_for, header_voted_for, CRABS_MAX_USER_ID - 1);
      module->voted_for[CRABS_MAX_USER_ID - 1] = '\0';
    } else if (header_voted_for[0] != '\0') {
      if (module->voted_for[0] != '\0' &&
          strncmp(module->voted_for, header_voted_for, CRABS_MAX_USER_ID) != 0) {
        return CRABS_ERR_INVALID_PARAM;   // two votes in one term: corruption
      }
      strncpy(module->voted_for, header_voted_for, CRABS_MAX_USER_ID - 1);
    }
    // The recovered record IS the durable truth for what it covers.
    module->durable_term = header_term;
    strncpy(module->durable_voted_for, header_voted_for, CRABS_MAX_USER_ID - 1);
    module->durable_voted_for[CRABS_MAX_USER_ID - 1] = '\0';
  }
  for (uint32_t entry_slot = 0; entry_slot < entry_count; entry_slot++) {
    uint64_t entry_term = 0;
    uint64_t entry_proposal_id = 0;
    uint32_t entry_wire_len = 0;
    if (!_raft_read_u64(&reader, &entry_term) ||
        !_raft_read_u64(&reader, &entry_proposal_id) ||
        !_raft_read_u32(&reader, &entry_wire_len) ||
        entry_wire_len > CRABS_RAFT_MAX_OP_WIRE_BYTES ||
        (size_t)entry_wire_len > reader.len - reader.offset) {
      return CRABS_ERR_INVALID_PARAM;
    }
    bool wire_truncated = false;
    const uint8_t* entry_wire = entry_wire_len > 0
        ? _raft_read_bytes(&reader, entry_wire_len, &wire_truncated) : NULL;
    if (entry_wire_len > 0 && entry_wire == NULL) {
      return CRABS_ERR_INVALID_PARAM;
    }
    uint64_t recover_index = first_index + entry_slot;
    if (_raft_log_grow(module, recover_index) != CRABS_SUCCESS) {
      return CRABS_ERR_INTERNAL;
    }
    if (recover_index > module->last_log_index) {
      // Fresh tail entry (host-stored durable history arrives in order).
      uint8_t* copy = entry_wire_len > 0
          ? (uint8_t*)get_memory(entry_wire_len) : NULL;
      if (copy != NULL) memcpy(copy, entry_wire, entry_wire_len);
      module->log[recover_index - 1].term = entry_term;
      module->log[recover_index - 1].proposal_id = entry_proposal_id;
      module->log[recover_index - 1].op_wire = copy;
      module->log[recover_index - 1].wire_len = entry_wire_len;
      module->last_log_index = recover_index;
    } else {
      // Overlap with the restored history: same term = idempotent (keep the
      // machine-blob copy); contradictory rewrite = fail closed.
      raft_log_entry_t* existing = &module->log[recover_index - 1];
      if (existing->term != entry_term) {
        return CRABS_ERR_INVALID_PARAM;
      }
    }
    // A CONFIG entry in a recovered batch registers its ids like on append.
    raft_log_entry_t decoded = { entry_term, entry_proposal_id,
                                 (uint8_t*)entry_wire, entry_wire_len };
    if (_raft_entry_is_config(&decoded) &&
        _raft_config_register_members(module, &decoded) != CRABS_SUCCESS) {
      return CRABS_ERR_INVALID_PARAM;
    }
  }
  uint64_t recovered_last = entry_count > 0
      ? first_index + entry_count - 1 : first_index - 1;
  if (recovered_last > module->durable_upto) {
    module->durable_upto = recovered_last;
  }
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
  uint64_t outstanding_epoch = outstanding->epoch;
  bool stale_ack = outstanding_epoch != module->persist_epoch;
  // The window resolves below; keep the header values to adopt.
  uint64_t header_term = outstanding->header_term;
  char header_voted_for[CRABS_MAX_USER_ID];
  strncpy(header_voted_for, outstanding->header_voted_for, CRABS_MAX_USER_ID - 1);
  header_voted_for[CRABS_MAX_USER_ID - 1] = '\0';
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

  // A stale epoch means the window's bytes were DISCARDED after the poll
  // (log-suffix truncation): the host faithfully stored dead entries. The
  // ack resolves the window (the module's bookkeeping is done) but must not
  // advance durability — the re-armed window re-persists the live tail
  // WITH the fresh header.
  if (stale_ack) {
    _raft_emit_persist_request(module);
    return CRABS_SUCCESS;
  }

  // Durability confirmed for [first_index, last_index] and for the term/
  // votedFor header record; the election record is now durable — held vote
  // traffic may flow (carry item A).
  if (last_index > module->durable_upto) {
    module->durable_upto = last_index;
  }
  module->durable_term = header_term;
  strncpy(module->durable_voted_for, header_voted_for,
          CRABS_MAX_USER_ID - 1);
  module->durable_voted_for[CRABS_MAX_USER_ID - 1] = '\0';
  _raft_flush_held_msgs(module);
  _raft_advance_commit(module);
  // Re-arm immediately: an undurable tail or a fresher header (window
  // resolved under an older election record) rides the next window without
  // waiting for a tick.
  _raft_emit_persist_request(module);
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

uint32_t crabs_raft_module_committed_members(
    const crabs_raft_module_t* module_opaque, char (*out)[CRABS_MAX_USER_ID]) {
  const crabs_raft_module_s* module = (const crabs_raft_module_s*)module_opaque;
  if (module == NULL) return 0;
  if (out != NULL) {
    for (uint32_t slot = 0; slot < module->config_old.member_n &&
                            slot < CRABS_RAFT_MAX_PEERS; slot++) {
      strncpy(out[slot], module->member_ids[module->config_old.member[slot]],
              CRABS_MAX_USER_ID - 1);
      out[slot][CRABS_MAX_USER_ID - 1] = '\0';
    }
  }
  return module->config_old.member_n;
}

uint32_t crabs_raft_module_joint_members(
    const crabs_raft_module_t* module_opaque, char (*out)[CRABS_MAX_USER_ID]) {
  const crabs_raft_module_s* module = (const crabs_raft_module_s*)module_opaque;
  if (module == NULL) return 0;
  if (out != NULL) {
    for (uint32_t slot = 0; slot < module->config_new.member_n &&
                            slot < CRABS_RAFT_MAX_PEERS; slot++) {
      strncpy(out[slot], module->member_ids[module->config_new.member[slot]],
              CRABS_MAX_USER_ID - 1);
      out[slot][CRABS_MAX_USER_ID - 1] = '\0';
    }
  }
  return module->config_new.member_n;
}

bool crabs_raft_module_config_change_pending(
    const crabs_raft_module_t* module_opaque) {
  const crabs_raft_module_s* module = (const crabs_raft_module_s*)module_opaque;
  return module != NULL && (module->config_change_in_flight != 0 ||
                            _raft_joint_active(
                                (crabs_raft_module_s*)module));
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
  // Joint membership: rebuild the address book from the boot config first,
  // then validate every config entry's payload against the imported log.
  module->member_n = 0;
  module->config_old.member_n = 0;
  module->config_new.member_n = 0;
  for (uint32_t member_index = 0; member_index < module->config.peer_count;
       member_index++) {
    _raft_member_table_add(module, module->config.peer_ids[member_index]);
  }
  for (const crabs_raft_entry_persisted_t* node = persisted->log; node != NULL;
       node = node->next) {
    if (node->wire_len >= RAFT_CONFIG_HEADER_LEN &&
        node->op_wire[0] == RAFT_CONFIG_MARKER &&
        node->op_wire[1] == RAFT_CONFIG_FORMAT) {
      raft_log_entry_t decoded = { node->term, node->proposal_id,
                                   node->op_wire, node->wire_len };
      if (_raft_config_register_members(module, &decoded) !=
          CRABS_SUCCESS) {
        return CRABS_ERR_INVALID_PARAM;   // malformed config entry on the wire
      }
    }
  }
  // The boot config seeds the committed list; a committed config entry in
  // the imported log (applied while splicing below) replaces it.
  for (uint32_t member_index = 0; member_index < module->config.peer_count;
       member_index++) {
    int slot = _raft_peer_index(module, module->config.peer_ids[member_index]);
    module->config_old.member[module->config_old.member_n++] = (uint32_t)slot;
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
  uint64_t change_in_flight = 0;
  for (const crabs_raft_entry_persisted_t* node = persisted->log; node != NULL;
       node = node->next) {
    entry_index++;
    raft_log_entry_t decoded = { node->term, node->proposal_id,
                                 node->op_wire, node->wire_len };
    bool committed_config = _raft_entry_is_config(&decoded) &&
                            entry_index <= persisted->commit_index;
    if (_raft_entry_is_config(&decoded) && entry_index > persisted->commit_index) {
      change_in_flight = entry_index;   // newest appended-uncommitted change
    }
    raft_log_entry_t* entry = &module->log[entry_index - 1];
    entry->term = node->term;
    entry->proposal_id = node->proposal_id;
    uint8_t* copy = node->wire_len > 0 ? (uint8_t*)get_memory(node->wire_len) : NULL;
    if (node->wire_len > 0) memcpy(copy, node->op_wire, node->wire_len);
    entry->op_wire = copy;
    entry->wire_len = node->wire_len;
    // Re-derive the ACTIVE COMMITTED config while splicing so elections and
    // commit quorums are correct the moment import returns.
    if (committed_config) {
      _raft_config_apply_committed(module, entry);
    }
  }
  module->last_log_index = persisted->log_count;
  module->current_term = persisted->term;
  module->voted_for[0] = '\0';
  if (persisted->voted_for[0] != '\0') {
    strncpy(module->voted_for, persisted->voted_for, CRABS_MAX_USER_ID - 1);
  }
  // The persisted section IS the durable history (the host wrote every
  // entry in it) — including its term/votedFor record.
  module->durable_term = persisted->term;
  strncpy(module->durable_voted_for, persisted->voted_for,
          CRABS_MAX_USER_ID - 1);
  module->durable_voted_for[CRABS_MAX_USER_ID - 1] = '\0';
  module->commit_index = persisted->commit_index;
  // durable_upto starts at the restored log tail: ... commit tip may ride
  // normal quorum/persist events.
  module->durable_upto = persisted->log_count;
  // Already-committed entries are NOT re-notified (they were materialized
  // before the restart); a restored node waits for its election deadline.
  module->role = RAFT_ROLE_FOLLOWER;
  module->leader_id[0] = '\0';
  module->follower_commit_target = 0;
  // A config change appended but uncommitted at the restart resumes.
  module->config_change_in_flight = change_in_flight;
  // Fresh peer bookkeeping and election tally (the restored node restarts
  // as a follower with no in-flight election or replication cursor state);
  // held vote traffic has nothing to ride on after a restart — drop it.
  memset(module->vote_granted, 0, sizeof(module->vote_granted));
  {
    raft_held_msg_t* held = module->held_msgs;
    while (held != NULL) {
      raft_held_msg_t* held_next = held->next;
      free(held);
      held = held_next;
    }
    module->held_msgs = NULL;
  }
  for (uint32_t member_index = 0; member_index < RAFT_MEMBER_TABLE_MAX;
       member_index++) {
    module->next_index[member_index] = 1;
    module->match_index[member_index] = 0;
  }
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