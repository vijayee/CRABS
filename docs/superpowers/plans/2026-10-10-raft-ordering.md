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

### Phase 3: Membership change (joint consensus) + log compaction decision (LANDED a586e0f + 66040dd, ctest 1735/1735)

- [x] Joint consensus on the MODULE's own config log: AS LANDED — config entries (joint `C_old,new` + auto-appended `C_new`) ride the log like ordinary entries behind a 0xFF/0x01 payload marker (never collides with CRABS op wires, which start with their u32 format version 3..6); control entries never materialize as machine ops; quorum/vote rules span BOTH lists during the joint phase and always read the COMMITTED config (a `C_old,new` entry commits under pre-change rules, per Ongaro §6); one change at a time (`CRABS_ERR_ORDERING_CHANGE_IN_FLIGHT`); a new leader resumes a committed-but-unfinished transition in `become_leader`; an evicted node steps down with `RAFT_NOTIFY_CONFIG_EXCLUDED`. Membership = member address book referenced by config-list indices; derived on restart/import from the committed prefix; queries `crabs_raft_module_{committed,joint}_members` + `crabs_raft_module_config_change_pending` expose the state to hosts/tests. Safety scenarios in the harness: single-member add→remove round trip (fresh concurrent-change refusal + clean re-commit), old-majority partition STALLS an in-flight change (committed config frozen at 3, second change refused, heal completes the transition), leadership churn DURING the joint phase (majority elects under joint quorum rules; the new leader resumes the transition; heal converges one leader), provisioned newcomer replication.
- [x] Carried P2-review fixes landed in the same module release (they interlock: one persist format, one member table):
  - A (votedFor/currentTerm durability): AS LANDED — compact term/votedFor HEADER record inside every persist batch (v2 format, `crabs_raft_module_recover_from_persist` replays host-stored batches over the machine-state blob on restart); the grant response AND the candidacy solicitation are HELD out of the reactor until their header batch acks. Chosen design logged in `raft_module.c`: header-in-batch over a second persist-lane because the single persistence window is the reactor's whole contract. Tradeoff: up to one extra persist round-trip of election latency.
  - B (leadership no-op): AS LANDED — `wire_len 0` marks the §8 no-op appended at every leadership start; committed no-ops never notify; v17 (state serializer) tolerates zero-length entries.
  - C (ordered materialization retry shelf): AS LANDED machine-side (separate commit 66040dd) — a failed delivery RETAINS the op on a state-side shelf and BLOCKS newer deliveries (log order preserved; group-item folding order is the reason skipping was rejected); retries on pump invocations with bounded linear backoff (1 s × attempt, cap 30 s, `state_raft_process_notifications_at` hosts/tests pass their own clock); ≥ `CRABS_RAFT_SHELF_POISON_ATTEMPTS` consecutive failures emit a loud change notification per attempt while the stream stays blocked; the shelf serializes into the v17 module section beside the pendings (restart resumes ordering, failure count rides along).
  - D: AS LANDED — empty-range heartbeat unit round trip (`RaftWireRoundTrip.EmptyRangeHeartbeatRoundTrips`).
- [x] Log compaction: DECISION — compaction-as-snapshot DEFERRED to its own follow-up plan; evidence = `RaftLogBound.ReachesCapAndRefusesBeyond` (4096 entries filled; ≈ 0.6 MB retained with tiny ops vs the 64 MB worst-case planning bound; refusal beyond the cap with `RAFT_NOTIFY_LOG_FULL` keeps the module healthy and restarts at the bound stay healthy). The growth model + bound + refusal behavior are documented in `raft_module.h`'s growth notes. Rationale for deferral: discarding a committed prefix requires machine-state snapshots + install-on-demand — heavy machinery that the bound makes non-urgent.
- [x] Commit: `feat: Raft joint-consensus membership change on the module's own config log` (carried A/B/D + compaction decision ride the release, noted in the body) + `fix: ordered materialization retry shelf on the machine seam`.

### Phase 4: Surfaces + docs + final verification

- [ ] wasm exports (`crabs_wasm_raft_*`: create/tick/inbound/propose/poll*/drain disposal) + JS glue: the host loop (setTimeout tick, WebSocket-style async send of drained blobs, inbound re-injection, storage-backed persist events) shipped as a REFERENCE host in bindings-core (documented: user-suppliable transport). Node binding mirror. CLI: `module attach/detach` diagnostic? (keep minimal: show module status in `item info` group rows).
- [ ] Demo/tests: wasm 3-node in-memory cluster test (queues between instances in Node) + extend the video-platform demo? (only if cheap; otherwise test-level). Artifacts regen.
- [ ] README/spec: architecture section — reactor model, host responsibilities, partition semantics; audit-doc note. Spec doc "as implemented".
- [ ] Final verification: full suites + parity + de-wonk two rounds.

**Commit cadence:** per phase per the checklists, each green (ctest/node/wasm as applicable). P1 C-only; wasm regen at P4 (and once at P1 if exports needed early — decide by whether P1 tests can drive modules in-process (they can — pure C), so wasm regen only at P4 or at the first binding-touching commit).
### As-landed corrections (2026-10-12, worktree `raft-ordering`)

Three review fixes on the landed Phase 2/3 module, each with a RED-first harness scenario:

- **Follower APPEND_RESP durability hold** — the append response's match_index
  counts toward the leader's commit, so it now rides the exact vote-hold
  machinery: held out of the reactor until the persist batch covering the
  stored suffix acks (supersede-by-term flush mechanics unchanged; a match
  already durable flows immediately). Covers the leader-durable +
  follower-undurable window where a follower crash could evaporate a
  "committed" entry. Scenario: `FollowerAcksWaitForTheirOwnDurability` (both
  followers' persists held → nothing commits; a crash replay via
  `recover_from_persist` resolves; late durability closes the quorum).
- **Pump retry gate under a failed clock** — the no-time pump passed
  `_at(state, 0)` into the shelf's backoff gate, minting `0 + backoff`
  deadlines every later pump silently sat on. The pump body now carries an
  explicit clock-trusted flag: a failed time source bypasses the gate
  entirely and stamps no deadline; the trusted path is unchanged. Scenario:
  `PumpRetriesEveryInvocationWhenClockFails` (dead time-source vtable seam).
- **Ghost replication to evicted members** — the leader fan-out gated on the
  address book; committed group data kept flowing to committed-config
  evictions. Fan-out now gates on `_raft_append_admitted`: the COMMITTED
  config (both lists during a joint phase) plus members of the in-flight
  (appended-but-uncommitted) config entry — the change's own commit needs
  those matches, so the gate must never deadlock the change it announces.
  A ghost gets ONE `RAFT_MSG_CONFIG_EXCLUDED` control per leadership carrying
  the commit ceiling (it replaces the peer's append traffic, letting it
  finish committing what it durably holds), and the fan-out after the
  auto-appended `C_new` successor ships it while the joint is still active.
  Scenario: extended `SingleNodeJointAddThenRemoveCompletesSafely`.

**Known environmental issue (not a CRABS defect):** an OpenSSL 3 exit-time
`CRYPTO_free_ex_data` heap corruption surfaces at scale (many keypairs /
ex-data registrations over a long test run) — a crash-on-process-exit that
reproduces at P2 `HEAD` as well. Environmental (allocator/teardown ordering
inside libcrypto), does not affect test outcomes before exit; no workaround
beyond running suites under a toolchain whose libcrypto build avoids it.
Noted here because there is no project KNOWN_ISSUES file; revisit if a
keyring lifecycle migration to the OpenSSL 3 EVP APIs (audit N-19) changes
the ex-data usage.

### Phase 4 as-landed (2026-10-12, worktree `raft-ordering`)

Surfaces + docs + final verification, all green:

- **wasm exports** (`src/Util/wasm_helpers.c`): the module-handle idiom is raw
  C pointers; a small module→machine registry lets `crabs_wasm_raft_destroy`
  detach before teardown, and `crabs_wasm_raft_create` fails closed on a
  double-attach (one module per machine, single state slot). Drains follow
  the plan's disposal conventions: poll_outbound/poll_notification return a
  self-contained copy envelope (the poll's transferred blobs are released in
  C); poll_persist_request re-reports the open window. Notifications
  materialize through `crabs_wasm_raft_pump` (state pipeline) — raw
  `poll_notification` stays available for hosts driving without a state
  pipeline. Export/import state is covered by the v17 state serializer +
  attach-time import; `recover_from_persist` covers the restart replay.
- **Reference host** (`bindings/wasm/bindings-core.js`): `Node.attachRaft`
  returns `RaftHost` — setTimeout tick loop, `setRaftTransport` /
  `setRaftStorage` seams, `raftDeliver` inbound, raw drains, `raftStatus`.
  The pump orders persist-ack before tick (vote requests ride vote-header
  durability) but never stalls ticks on in-flight storage. execute() now
  resolves `ordering_pending` as success (two-phase acceptance) and the
  error table gained the 0xA006..0xA008 names. Typed surface in
  `index.d.ts`/`dev.d.ts`; dev.d.ts unchanged (re-exports).
- **Node binding** (`crabs_node.cc` + `index.js`): same reactor surfaces;
  the reference host mirrors wasm's with a `pumpNotifications: false`
  raw-host mode (no JS-handler surface on this binding — committed ops are
  asserted at the wire); plus a readonly `adminId` accessor for host-default
  node identity. BigInt handles convert losslessly (Uint64Value bool*).
- **CLI**: `raft attach <node_id> [peers...]` + `raft status` (term, leader,
  tip, members, pending/shelf counts, rejected-message count) and a live
  module row on `item info` group items (`test_cli.cpp` — a self-not-member
  config is not constructible through the CLI, so that refusal stays
  module-suite covered).
- **Tests**: wasm `test/raft.js` — 3-node in-process cluster through the
  REAL artifacts (election → two-phase group write → committed+materialized
  on all three via change events → partition halts `nodeC` while the quorum
  commits → heal converges to one shared tip). Native `test/raft.js` — same
  shape with raw notifications and byte-identical committed-op wires across
  replicas. Two test-only notes: (1) identical module seeds randomize
  identical election deadlines — the lockstep split-vote livelock needs
  per-node seeds; (2) wasm handlers read payload strings through
  `crabs_wasm_handler_op_get_payload_str`, which requires NUL-terminated
  payloads — string payloads are written `'text\x00'`.
- **Verification**: ctest 1739/1739, node npm 105+cluster suite, wasm npm
  chain (9 suites + cluster E2E), `write-domains-parity.mjs`
  byte-identical, both lineage smokes OK. De-wonk two rounds: R1 —
  outbound-drain blob leak (both bindings; free after enveloping/copied
  buffer), persist-window early-return stalling heartbeats on slow storage
  (module tolerates ticks with a busy window), unreachable peer-count clamp,
  double-attach guard, tests touching private `_raftHost` fields (now
  keep the returned host); R2 — pumpInbound notification gating removed,
  persist_complete rc surfaced (unknown/stale handle = loud host bug), no
  new issues on re-read.

Commit cadence (per area): `feat: wasm raft module exports + reference
host` / `feat: node binding raft surfaces` / `test: wasm/node raft cluster
suites` / `feat: CLI raft diagnostics` / `docs: raft ordering — README/spec
as-implemented` / `chore: regenerate wasm artifacts`.
