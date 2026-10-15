//
// Created by victor on 10/12/25.
//

#ifndef CRABS_RAFT_MODULE_H
#define CRABS_RAFT_MODULE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "../CRABS/crabs.h"
#include "../StateMachine/state_machine.h"

// ============================================================
// Raft ordering module — transport-agnostic deterministic reactor
// (raft-ordering plan, Phase 1)
// ============================================================
//
// The module is a PURE state machine. It receives inbound events (tick,
// inbound messages, propose, persist completions) and exposes outbound
// queues (messages, persist requests, notifications) that the host drains.
// It performs no syscalls, no blocking, no threading: the HOST owns the
// transport (hosts re-inject drained message blobs to peers), storage
// (hosts answer persist requests with persist_complete), and timers (hosts
// call tick with their own clock). This makes the module the same object in
// wasm (JS glue drives it) and in-process tests (deterministic sim).
//
// Two-sided durability: a log entry is durable ONLY when the host answers
// the persist request with persist_complete(handle, true). Nothing counts
// for commit before that (the persistence contract).
//
// Growth model (compaction decision CLOSED under Phase 3 harness evidence,
// never silently unbounded): the module log holds at most
// CRABS_RAFT_MAX_LOG_ENTRIES entries. Each entry carries at most
// CRABS_RAFT_MAX_OP_WIRE_BYTES of serialized op wire. Proposals beyond the
// caps are REFUSED (the module stays healthy and keeps its committed prefix,
// surfacing RAFT_NOTIFY_LOG_FULL); a single-node cluster's commit tip
// therefore bounds retained state at cap * (entry + per-op wire) — a
// documented, finite bound the host can plan storage around. Phase 3
// evidence (test_raft_module.cpp, RaftLogBound.ReachesCapAndRefusesBeyond):...
// DECISION: compaction-as-snapshot is DEFERRED to its own follow-up plan —
// discarding committed prefixes requires persisting machine-state snapshots
// alongside the log prefix and an install-on-demand path; the 4096-entry
// ceiling with refusal at the cap is the honest shipped answer for now, and
// the harness stress test pins the behavior AT the bound.

// Cluster shape: peers counts ALL members including this node (1 = the
// degenerate single-node cluster: self-election without vote exchange).
#define CRABS_RAFT_MAX_PEERS          16
// Committed log retention cap (see growth model above). Tightened in Phase 2
// from the P1 draft 65536: 65536 entries x the op-wire cap below let one
// module section approach a gigabyte of worst-case state — 4096 entries is a
// sane operating ceiling while compaction stays open (Phase 3 evidence).
#define CRABS_RAFT_MAX_LOG_ENTRIES    4096
// One serialized CRABS op per log entry, capped like every other bounded
// wire field (the scheduler persists whole serialized ops; the same order
// of magnitude).
#define CRABS_RAFT_MAX_OP_WIRE_BYTES  16384
// Entries shipped per AppendEntries batch: bounds one message body at
// batch * op-wire-cap and keeps a lagging follower's repair converging over
// several heartbeats instead of one giant frame.
#define CRABS_RAFT_APPEND_BATCH_ENTRIES 8
// Default timer configuration; election timeouts are randomized in
// [election_timeout_min_ms, election_timeout_max_ms] from the seed.
#define CRABS_RAFT_ELECTION_TIMEOUT_MIN_MS 1500u
#define CRABS_RAFT_ELECTION_TIMEOUT_MAX_MS 3000u
#define CRABS_RAFT_HEARTBEAT_INTERVAL_MS   500u

// The module object is opaque: callers pass it back into the API and drain
// its queues; its state reaches the wire only through the v16 serializer
// (via export/import below).
typedef struct crabs_raft_module_s crabs_raft_module_t;

// ============================================================
// Configuration
// ============================================================
typedef struct {
  char node_id[CRABS_MAX_USER_ID];
  char peer_ids[CRABS_RAFT_MAX_PEERS][CRABS_MAX_USER_ID];  // all members, self included
  uint32_t peer_count;
  uint64_t election_timeout_min_ms;
  uint64_t election_timeout_max_ms;
  uint64_t heartbeat_interval_ms;
  uint64_t seed;              // deterministic randomized election timeouts
  uint8_t  module_id;         // per-machine ordering-module id (v16 section)
} crabs_raft_config_t;

// Fill cfg with the degenerate single-node defaults ("node-0", peers=1,
// default timers, seed 0). Callers may then override fields.
void crabs_raft_config_defaults(crabs_raft_config_t* config);

// ============================================================
// Outbound drains
// ============================================================
// Raft control messages travel between hosts OUTSIDE the CRABS op log
// entirely — they are opaque blobs the host addresses to peers. The host
// never parses them; replies come back through crabs_raft_module_inbound.
typedef enum {
  RAFT_MSG_VOTE_REQ   = 1,
  RAFT_MSG_VOTE_RESP  = 2,
  RAFT_MSG_APPEND_REQ = 3,
  RAFT_MSG_APPEND_RESP = 4,
  // Leader-side membership eviction notice (Raft §6): the committed config
  // no longer counts the addressed peer, so the leader stopped replicating
  // to it. Body: u64 commit ceiling — the exclusion REPLACES the follower's
  // append traffic, so the ceiling lets the evicted node finish committing
  // what it durably holds before it stops. The peer surfaces
  // RAFT_NOTIFY_CONFIG_EXCLUDED and steps down.
  RAFT_MSG_CONFIG_EXCLUDED = 5
} raft_msg_kind_e;

typedef struct {
  raft_msg_kind_e  kind;
  char             to_peer[CRABS_MAX_USER_ID];
  const uint8_t*   bytes;   // module-owned until the next poll_* call
  size_t           len;
} crabs_raft_outbound_message_t;

// Persist requests do NOT follow the transfer-on-poll ownership of the
// message and notification queues: poll_persist hands out a VIEW of the one
// outstanding request (the blob pointer remains MODULE-owned until
// persist_complete(handle, ok) resolves the window, and the host must not
// free it). Hosts that must defer storage copy the bytes first. This is the
// deliberate contrast with poll_outbound, where each poll TRANSFERS blob
// ownership to the caller (free after reading) — poll_persist transfers
// nothing; it reports (and re-reports, until resolved) the same window.
typedef struct {
  uint64_t         handle;
  const uint8_t*   bytes;   // module-owned until persist_complete(handle, ok)
  size_t           len;
} crabs_raft_persist_request_t;

// Notifications surface leadership changes and committed operations to the
// host. RAFT_NOTIFY_COMMITTED_OP carries the committed op's SERIALIZED WIRE
// bytes (crabs_serialize_operation form) — the host materializes it (the
// pipeline seam deserializes and executes through the scheduled-
// materialization path). Bytes/fields are module-owned BORROWS: valid only
// while the pump keeps using them — copy or deserialize them IMMEDIATELY;
// crabs_raft_module_import_state and module destroy free the committed
// op_wires, which would invalidate un-drained borrowed pointers.
typedef enum {
  RAFT_NOTIFY_BECAME_LEADER      = 1,
  RAFT_NOTIFY_LOST_LEADERSHIP    = 2,
  RAFT_NOTIFY_COMMITTED_OP       = 3,
  RAFT_NOTIFY_PROPOSAL_NOT_LEADER = 4,
  RAFT_NOTIFY_PERSIST_FAILED     = 5,
  RAFT_NOTIFY_LOG_FULL           = 6,  // a proposal hit the CRABS_RAFT_MAX_LOG_ENTRIES ceiling
  RAFT_NOTIFY_CONFIG_EXCLUDED    = 7   // a membership change committed this node OUT of the config
} raft_notification_e;

typedef struct {
  raft_notification_e kind;
  char     peer_id[CRABS_MAX_USER_ID]; // leadership-change actor ("" when n/a)
  uint64_t proposal_id;                // COMMITTED_OP: committed op's log index
  const uint8_t* op_bytes;             // COMMITTED_OP: op wire bytes (module log)
  size_t   op_len;
  uint64_t commit_index;               // commit tip after this event
} crabs_raft_notification_t;

// ============================================================
// Persisted module state (v16 machine section)
// ============================================================
// Namespace-separated module state serializes into the state blob's own
// versioned section — never into items, attributes or the op log. The
// deserializer hands the parse result back as this struct (the module
// OBJECT is host-created; the module's state is what survives restart).
typedef struct {
  uint8_t  module_id;
  uint64_t term;
  char     voted_for[CRABS_MAX_USER_ID];
  uint64_t commit_index;
  uint32_t log_count;                  // entry [i] is log index (i + 1)
  struct crabs_raft_entry_persisted_t* log;
} crabs_raft_module_state_t;

typedef struct crabs_raft_entry_persisted_t {
  uint64_t term;
  uint64_t proposal_id;
  uint8_t* op_wire;
  uint32_t wire_len;
  struct crabs_raft_entry_persisted_t* next;
} crabs_raft_entry_persisted_t;

// ============================================================
// Lifecycle
// ============================================================
// NULL config selects the degenerate single-node defaults. Ownership: the
// caller destroys the module. The pipeline seam attaches a module to a
// state with state_attach_raft_module (state_machine.h) — the state never
// owns the module object.
crabs_raft_module_t* crabs_raft_module_create(const crabs_raft_config_t* cfg);
void                 crabs_raft_module_destroy(crabs_raft_module_t* module);

// ============================================================
// Inbound events
// ============================================================
crabs_error_e crabs_raft_module_tick(crabs_raft_module_t* module, uint64_t now_ms);
crabs_error_e crabs_raft_module_inbound(crabs_raft_module_t* module,
                                        const char* peer_id,
                                        const uint8_t* blob, size_t len,
                                        uint64_t now_ms);
// Phase 1: the caller has pre-validated the op (pipeline seam). Returns the
// assigned proposal_id (= log index). Refusals (not leader, over-cap,
// full log) emit RAFT_NOTIFY_PROPOSAL_NOT_LEADER / an error code and leave
// the log untouched.
crabs_error_e crabs_raft_module_propose(crabs_raft_module_t* module,
                                        const operation_t* op,
                                        uint64_t* proposal_id);
crabs_error_e crabs_raft_module_persist_complete(crabs_raft_module_t* module,
                                                 uint64_t handle, bool ok);

// Joint-consensus membership change (Raft §6, on the module's OWN config
// log): the leader appends a joint C_old,new entry carrying BOTH peer lists
// like an ordinary entry; when committed the leader appends the final C_new
// entry automatically, and that entry's commit ends the transition. Voting
// and commit quorums during the joint phase require majorities of BOTH
// lists; only ONE change may be in flight (an appended-but-uncommitted
// config entry, or an active joint phase refuses further changes with
// CRABS_ERR_ORDERING_CHANGE_IN_FLIGHT). A node excluded by the committed
// config steps down (RAFT_NOTIFY_CONFIG_EXCLUDED). new_member_ids entries
// replace the whole membership — copy id arrays that must outlive the call
// is NOT required; the module copies the strings.
crabs_error_e crabs_raft_module_change_membership(
    crabs_raft_module_t* module, const char* const* new_member_ids,
    uint32_t member_count, uint64_t* proposal_id);

// Crash recovery from the HOST's durable raft record: parse a stored persist
// batch blob (the bytes the host copied when serving a poll_persist window)
// and merge it into the module's durable state — the term/votedFor HEADER
// record rides every batch (carry item A: election safety requires the vote
// to be durable BEFORE the vote response is effective, so restart must play
// back the stored batches over the machine-state blob, which may predate the
// last grants). Entries under the committed prefix are never rewritten
// (contradiction fails closed).
crabs_error_e crabs_raft_module_recover_from_persist(
    crabs_raft_module_t* module, const uint8_t* batch, size_t batch_len);

// ============================================================
// Outbound drains — each poll moves the head event out; the pointer stays
// valid until the next poll of that queue.
// ============================================================
bool crabs_raft_module_poll_outbound(crabs_raft_module_t* module,
                                     crabs_raft_outbound_message_t* out);
bool crabs_raft_module_poll_persist(crabs_raft_module_t* module,
                                    crabs_raft_persist_request_t* out);
bool crabs_raft_module_poll_notification(crabs_raft_module_t* module,
                                         crabs_raft_notification_t* out);

// ============================================================
// Queries (harness assertions, host glue)
// ============================================================
bool     crabs_raft_module_is_leader(const crabs_raft_module_t* module);
uint64_t crabs_raft_module_committed_tip(const crabs_raft_module_t* module);
uint64_t crabs_raft_module_current_term(const crabs_raft_module_t* module);
uint64_t crabs_raft_module_log_length(const crabs_raft_module_t* module);
// Next randomized election deadline in ms — exposed so the simulation
// harness can tick deterministically (same seed → same deadlines).
uint64_t crabs_raft_module_next_election_deadline(const crabs_raft_module_t* module);
// Fail-closed deserializer discipline: malformed inbound messages are
// dropped, never crash or corrupt state. The counter reports rejections.
uint32_t crabs_raft_module_rejected_message_count(const crabs_raft_module_t* module);

// Membership queries (harness assertions, host glue): the ACTIVE committed
// config lists — "committed" peers (the election/voting list, empty only for
// the never-configured degenerate create... the create-time boot config is
// the committed config until a config entry commits) and the SECOND list of
// an active joint consensus (0 members when the cluster runs a plain single
// consensus). out gets up to CRABS_RAFT_MAX_PEERS id strings; the return is
// the member count of that list.
uint32_t crabs_raft_module_committed_members(
    const crabs_raft_module_t* module, char (*out)[CRABS_MAX_USER_ID]);
uint32_t crabs_raft_module_joint_members(
    const crabs_raft_module_t* module, char (*out)[CRABS_MAX_USER_ID]);
// A membership change is appended-but-uncommitted, or the committed joint
// phase still spans both lists.
bool crabs_raft_module_config_change_pending(const crabs_raft_module_t* module);

// ============================================================
// Persisted-state export/import (v16 serialization support)
// ============================================================
// Export a heap snapshot of the module's durable state for the state
// serializer. Caller destroys with crabs_raft_module_state_destroy.
crabs_raft_module_state_t* crabs_raft_module_export_state(
    const crabs_raft_module_t* module);
// Restore module durable state (term/voted_for/log/commit tip) from the
// parsed v16 section. The module's timers and queues stay fresh — commit
// continues through new persist events, and already-committed entries are
// NOT re-notified (the host materialized them before the restart).
crabs_error_e crabs_raft_module_import_state(crabs_raft_module_t* module,
                                             const crabs_raft_module_state_t* persisted);
void          crabs_raft_module_state_destroy(crabs_raft_module_state_t* persisted);

#endif // CRABS_RAFT_MODULE_H