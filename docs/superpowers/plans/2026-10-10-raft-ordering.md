# Raft Ordering Module — Transport-Agnostic Reactor Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Spec updates first:** docs/superpowers/specs/2026-10-08-write-domains-design.md — replace the attribute-membership sketch (rejected: couples election protocol state into the business authorization domain and serializes election churn into the signed audit log) and the CFT-only framing (a single-sequencer CFT already has Raft's shape; Raft it is). GROUP-ORDERED v1's read-only seam becomes the integration point.

**Core design (controller-decided, authoritative):**

1. **Pure deterministic reactor.** The module is a state machine with INBOUND events (`tick`, `inbound_message`, `propose`, `persist_complete`) and an OUTBOUND drain queue (messages-to-send, persist-requests, notifications). No syscalls, no blocking, no threads. The HOST owns transport, storage, timers — transport-agnostic by construction (works in wasm: JS glue drives `tick()` on a timer, re-injects inbound frames, drains and sends async).
2. **Opaque message blobs.** The module marshals/parses its own Raft messages; hosts address blobs to peers and re-inject replies. Hosts never parse Raft.
3. **Persistence is event-driven and two-sided** — persist-requests are emitted; durability holds only when the host answers `persist_complete`. In wasm, storage is the user's (IndexedDB/localStorage/server).
4. **Pipeline integration is two-phase** (scheduler precedent): submit touching a GROUP-ORDERED item → validated → pending proposal handed to the module; when the module later reports commit, the op materializes through the existing scheduled-materialization path (`skip_authorization` was validated at submission). Non-leaders/failed proposals surface via notification events (host retries or redirects).
5. **Module state is namespace-separated** in the state blob (own versioned section, like the lineage chain block) — never items, never attributes. Election/config churn lives there, NOT in the op log.
6. **Deterministic simulation harness is the testing backbone:** N module instances in one C test process + scripted event lists (dropped/reordered/duplicated messages, partitions, slow hosts) → Jepsen-class coverage with no network.

**Baseline:** master e455fb7, ctest 1698/1698; node 105; wasm npm chain green. Worktree-based.

**Wire/version moves:** state v15→**16** (module-state section); no signing-format move (module messages are opaque payloads inside ops? NO — Raft control messages are NOT CRABS ops; they travel between hosts OUTSIDE the op log entirely — no CRABS wire-version coupling at all except the persisted module section in v16).

---

### Phase 1: Reactor core, module-state section, pipeline seam, degenerate single-node

**Files (expected):** `src/Raft/raft_module.{c,h}` (new dir, reactor + message marshaling), `src/Serialization/serialization.{c,h}` (v16 module section), `src/StateMachine/state_machine.c` (group-item propose path + pending-proposal store + materialization), `test/test_raft_module.cpp` (new), `test/test_raft_sim.cpp` (new harness).

- [ ] `raft_module.h`: lifecycle + inbound events + drains — sketch:
```c
typedef enum { RAFT_MSG_VOTE_REQ, RAFT_MSG_VOTE_RESP, RAFT_MSG_APPEND_REQ, RAFT_MSG_APPEND_RESP } raft_msg_kind_e;
typedef struct { ... } raft_outbound_message_t;  // peer_id[CRABS_MAX_USER_ID], kind, blob ptr+len (module-owned until drained)
typedef struct { uint64_t handle; const uint8_t* bytes; size_t len; } raft_persist_request_t;
typedef enum { RAFT_NOTIFY_BECAME_LEADER, RAFT_NOTIFY_LOST_LEADERSHIP, RAFT_NOTIFY_COMMITTED_OP, RAFT_NOTIFY_PROPOSAL_NOT_LEADER } raft_notification_e;
crabs_raft_module_t* raft_module_create(const raft_config_t* cfg /* node_id, peers, election/heartbeat defaults; NULL → defaults */);
crabs_error_e raft_module_tick(module, uint64_t now_ms);
crabs_error_e raft_module_inbound(module, const char* peer_id, const uint8_t* blob, size_t len, uint64_t now_ms);
crabs_error_e raft_module_propose(module, const operation_t* op, uint64_t* proposal_id);
crabs_error_e raft_module_persist_complete(module, uint64_t handle, bool ok);
bool raft_module_poll_outbound(module, raft_outbound_message_t* out);
bool raft_module_poll_persist(module, raft_persist_request_t* out);
bool raft_module_poll_notification(module, raft_notification_t* out);
bool raft_module_is_leader(module); uint64_t raft_module_committed_tip(module);
```
   Internal state: term, votedFor, log entries {term, proposal_id, op-wire bytes}, commitIndex, leaderId, peer bookkeeping; election/heartbeat timers from cfg with deterministic randomized timeout (seedable — required for the harness).
- [ ] Message marshaling: compact versioned structs (tag+term+etc.), owned by the module; round-trip fuzz-lite tests (malformed inbound → rejection, no state corruption — fail-closed discipline like every other deserializer).
- [ ] Degenerate single node: `cfg.peers == 1` → self-election without vote exchange, propose appends, persist_complete advances commit, notification carries the committed op → materialization callback invoked by the host loop. Harness v1: ONE module instance, scripted ticks/persists, full submit→commit→materialize assertions.
- [ ] State serialization: v16 module section — term/votedFor/log/commitIndex per machine, capped entry bytes (reuse op-wire cap CRABS_MAX_OP_WIRE? bound by the existing op cap), remaining-bounds discipline as always; pre-16 loads = no module attached (state has a module-config field: attached flag + module_id; unset = the GROUP items behave as today).
- [ ] Pipeline seam: replace GROUP_ORDERED's `CRABS_ERR_ORDERING_PATH` rejection: op reaching DOMAIN_CHECK on group items with an ATTACHED module → route propose (non-blocking) → pending-proposal entry (uuid-keyed, like scheduled ops); NO attached module → keep today's rejection. Materialization on `RAFT_NOTIFY_COMMITTED_OP`. Merge: group items adopt by committed position (module's committed log per item) — wired in crdt_merge (replaces the hold stub).
- [ ] Surfaces minimal in P1: C-level only + `crabs_raft_module_*` exported; bindings/CLI come in P4.
- [ ] Commit: `feat: transport-agnostic Raft reactor core + single-node degenerate commit path`.

### Phase 2: Full Raft — elections, replication, partition behavior (LANDED 497e5ba, ctest 1725/1725)

**Files:** raft_module.c (election + log matching), test/test_raft_sim.cpp (the harness grows the real scenarios).
- [x] Elections: terms, randomized timeouts (seedable), RequestVote round-trip, split-vote resolution, leadership loss on AppendEntries conflict.
- [x] Replication: leader AppendEntries to peers, log matching (prevTerm/prevIndex conflict repair), quorum commit advance, heartbeats; follower reads committed to local machine state via notifications.
- [x] **Harness scenarios (the heart of this phase — each is a scripted deterministic C test):**
  - elect-1-of-3 basic; split-vote-2-of-3 → re-election;  <!-- as-landed: ThreeNodeClusterElectsExactlyOneLeader, SplitVoteResolvesThroughReelection, MajorityRefusesOutOfDateCandidate (item 2 at unit scale) -->
  - partition: leader isolated → minority halts (proposals pending, notifications NOT_LEADER at old leader), majority elects new leader and commits; heal partition → old leader's uncommitted entries discarded per log matching, no duplicate commits;
  - dropped/duplicated/reordered messages (host models loss/duplication/reorder in the script — module idempotent); slow-persist follower; <!-- as-landed: MessageFaultsDroppedDuplicatedReorderedConvergeIdempotently, SlowPersistFollowerLagsThenConverges -->
  - restart: module state round-trips through the v16 serializer, commit continues (persistence events re-drive);
  - mixed-machine property test: group items halt while SOVEREIGN/FREE items execute on all replicas (DOMAIN_CHECK unaffected).
- [x] **P1 carried items (from the P1 review — all load-bearing at P2):**
  1. Follower materialization: Step-0's pending-uuid gate blocks follower-side COMMITTED_OP delivery (followers never propose locally). AS LANDED: `state->raft_commit_delivery` runtime marker — the pump raises it around each `state_machine_execute_committed`; Step-0 admits a non-authorizing pass when pending OR delivering. Pending lifecycle unchanged; uuid dedup guards both.
  2. Vote grants MUST include the up-to-dateness check (candidate term/lastLogIndex/lastLogTerm) — P1 landed `(void)last_log_*`; correctness-critical once elections are real.
  3. Restart + pending tail: serialize the pending list into the v16 module section (uuid + op bytes) so leader restarts resume; follower deliveries unaffected via item 1. AS LANDED: section tail u32 count + entries (uuid/len/bytes), bounded by CRABS_RAFT_MAX_PENDING_PROPOSALS, restored in traversal order (byte-stable round-trips).
  4. Import/emit state-drop hazard: AS LANDED both ways: `state_attach_raft_module` imports+consumes the carried snapshot, AND the writer re-emits `raft_module_state` verbatim when no module is attached; byte-identity tested both legs (RestartSaveLoadSaveCarriesModuleSectionAndPending).
  5. Tighten caps: AS LANDED — CRABS_RAFT_MAX_LOG_ENTRIES 65536→4096 (worst section ≈ 64 MB, documented in the header); compaction decision still open (Phase 3).
  6. Merge wiring (plan-scope slip acknowledged): AS LANDED — `_merge_group_ordered_item` adopts src content when src's module commit tip (attached module or carried v16 snapshot) exceeds dst's; equal-tip divergence and module-less divergence still hold fail-closed; Raft's append-index invariant makes the per-state committed tip sound for every committed item.
  7. Clarify poll-ownership comment: AS LANDED — the persist-request comment now states the deliberate contrast (poll_outbound transfers blob ownership; poll_persist hands out a view, module-owned until persist_complete).
- [x] Commit: `feat: Raft elections and replicated log — deterministic simulations for partitions and message faults`.

### Phase 3: Membership change (joint consensus) + log compaction decision

- [ ] Joint consensus on the MODULE's own config log (opaque to CRABS ops); safety tests (config change during election/replication interleavings in the harness).
- [ ] Log compaction: DECIDE under harness evidence — bounded-log stress; if snapshot work is needed, scope it as its own follow-up plan (snapshot = persisted module section prefix, install-on-demand). Do NOT silently ship unbounded growth: document the growth model + the bound.
- [ ] Commit: `feat: Raft joint-consensus membership change` (+ optional `feat: raft log compaction`).

### Phase 4: Surfaces + docs + final verification

- [ ] wasm exports (`crabs_wasm_raft_*`: create/tick/inbound/propose/poll*/drain disposal) + JS glue: the host loop (setTimeout tick, WebSocket-style async send of drained blobs, inbound re-injection, storage-backed persist events) shipped as a REFERENCE host in bindings-core (documented: user-suppliable transport). Node binding mirror. CLI: `module attach/detach` diagnostic? (keep minimal: show module status in `item info` group rows).
- [ ] Demo/tests: wasm 3-node in-memory cluster test (queues between instances in Node) + extend the video-platform demo? (only if cheap; otherwise test-level). Artifacts regen.
- [ ] README/spec: architecture section — reactor model, host responsibilities, partition semantics; audit-doc note. Spec doc "as implemented".
- [ ] Final verification: full suites + parity + de-wonk two rounds.

**Commit cadence:** per phase per the checklists, each green (ctest/node/wasm as applicable). P1 C-only; wasm regen at P4 (and once at P1 if exports needed early — decide by whether P1 tests can drive modules in-process (they can — pure C), so wasm regen only at P4 or at the first binding-touching commit).