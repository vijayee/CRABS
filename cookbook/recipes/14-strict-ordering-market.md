---
number: 14
slug: strict-ordering-market
title: A market that needs strict ordering
section: Composition
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: wasm node
teaches: strict ordering from an elected leader (raft module)
---
## The problem

A market lists one fill slot. Two buyers bid for it at effectively the same
moment, and the bids reach three replicas in *different orders* — replica A
saw the red bid first, replica B saw the blue one first, and all three
replicas are healthy. When the replicas sync, what is the fill? "First
accepted wins" cannot even be evaluated, because acceptance is local: each
replica accepted whichever bid arrived first *there*.

Stated exactly, the requirement is:

- two bids racing for the same slot produce exactly one fill, in an order
  that is *not* a function of which replica read whose message first;
- every replica — including one that was offline, or partitioned, or
  restarted mid-fill — converges to the SAME committed sequence;
- nothing is "filled" until the cluster can prove the fill durable (a fill
  forgotten by a crash is worse than a fill delayed).

## The naive version, and where it breaks

The naive market is two free-merge items — `bids` and `fills` — with a
policy, and the assumption that "first accepted wins". Every replica ACCEPTS
the two racing claim ops in its own arrival order, merge takes them both
(free-merge converges by combining, not ordering), and the machine converges
to a state where two buyers hold the same slot. Nothing in the free-merge
domain can distinguish a race's winner, because nothing represents an order.

A sovereign item (Recipe 13) fixes the per-writer problem only: one writer's
fills are chained, but the market's problem is a *shared* order over many
writers' claims — and building the order in the application ("each claim
carries an id, replicas dedupe") rebuilds the ordering module by hand,
except without the one thing Raft has: a commit point replicas agree on
across partitions.

## The idea

A strict total order is not something merging can produce. Combining states
is order-free *by design* — that is the property that lets replicas
converge without a coordinator (Recipe 1) — so an order every replica agrees
on must come from somewhere else: **one authority per item**. The pattern is
consensus, and its pieces are worth naming before the API:

- **One leader per term.** All the racing bids route to whoever won the
  current election, and that leader assigns each accepted bid its log
  position. Order-assignment cannot be committee work done in parallel —
  racing assignments are precisely the problem.
- **A commit point.** An assignment is not the order yet. The order becomes
  real when a *quorum* has made the assignment durable — that is the
  moment every replica, including one that was offline, can later agree
  the entry took position N. This is what an application-level "dedupe by
  id" scheme never has: it dedupes, but it has no commit point, so two
  partitions can dedupe differently.
- **The log is the order.** Once committed, the log is append-only and
  agreed; each replica *replays positions* of the committed log, and the
  fill order — the thing the market needed — is a fact everyone reads off
  one sequence instead of a property anyone argues.

The price is explicit, and it is why the rest of this cookbook doesn't work
this way: writes halt when no quorum can be reached (partition = unavailability
for group items), only the leader (or a route through it) accepts proposals,
and the leader's log is durable state the operators must provision. Choose
this mechanism when racing claims on one slot are the failure you cannot
afford — that is the whole trade.

## How CRABS encodes it

- *The domain is declared at mint*: `defineItem(name, 'register',
  'lww_reg', { domain: 'group', orderingModule: <module id> })` — both
  bindings. The module id must match the machine's attached ordering
  module; the only id the bindings mint is 0, and a non-zero
  `ordering_module` is refused at item creation fail-closed (the id
  resolves against the machine's attached module, not a registry of many).
- *The module*: `attachRaft` (both bindings; the node host loop is
  `createRaftHost`). It wraps the C reactor `crabs_raft_module_t` — a PURE
  state machine with no syscalls: the HOST owns transport
  (`setRaftTransport` — drained blobs go anywhere; incoming return through
  `raftDeliver`), storage (`setRaftStorage` — persist windows, answered
  with `raftPersistComplete(handle, ok)`), and timers (`startRaftHost`'s
  tick loop or manual `raftTick`). All seams are replaceable: the reference
  loop is the transport/storage/timer wiring, not a networking claim.
- *Two-phase submission*: an op touching a group-ordered item NEVER
  executes inline. With NO module attached the write fails closed
  `ordering_path`; with one attached the same op is ACCEPTED as a pending
  proposal — `execute` resolves, the uuid is enqueued pending, and nothing
  materializes until commit (`CRABS_ERR_ORDERING_PENDING`; the leader
  routes the proposal into its module log).
- *Proposals ride the leader*: only the module that is leader can append
  (`RAFT_NOTIFY_PROPOSAL_NOT_LEADER` otherwise). Elections: randomized
  timeouts in `[electionMinMs, electionMaxMs]` from a seed; distinct seeds
  per node or the randomized deadlines lockstep and the vote livelocks —
  the reason every example below seeds `77 + i`.
- *Commit rides persistence*: a log entry is durable ONLY when the host
  answers its persist window `complete(true)` — the node that never
  acknowledges keeps committing nothing. The outstanding window is a VIEW
  the module RE-REPORTS until acknowledged — poll it once per async store
  round, never in a drain loop.
- *Materialization through the machine's pipeline*: committed ops return as
  notifications whose `opBytes` are the serialized op wire; the pump
  (`raftPump`/the host's materialization step) re-runs them through the
  full executor pipeline — on crabs-wasm that fires the registered handler
  and `change` events, so group items become real content in one settled
  order. MERGE adopts by committed position, not by combining: the module's
  committed index is the arbiter of group-item content, and two committed
  logs cannot disagree at the same index (Raft's append-index invariant).
- *Crash recovery is two-sided*: the machine blob carries the module's
  durable state (term/votedFor/log) as its own v16 section, and the HOST's
  retained persist batches replay through `raftRecoverFromPersist` when the
  module state is stale — corrupt or contradictory batches fail closed.

## Try it

### crabs-wasm (browser / Node / edge)

Three machines, one leader, a burst of racing bids materialized through
each machine's handler into a fill-order register — the committed order as
readable content, identical on every replica. (The demo carries two
registers on purpose: the market register holds the latest fill; the
fill-order register is the ledger of the RACE — the handler appends each
committed bid, so "what order did we agree on" becomes content you can
read, and diff across replicas, instead of a claim about bytes.)

```snippet:wasm/14-strict-ordering-market.js
```

### crabs-node (native Node.js)

The same cluster over the native binding's raft surface — `createRaftHost`
wraps `node.attachRaft` with the reference tick loop. No handler surface
here (api-map known difference #2), so the fill order is asserted where
this binding can see it: the committed-op notifications drained raw, whose
`proposalId` (the log index) orders the bytes. The three replicas' filled
sequences are byte-identical, position for position — one commit order,
everywhere.

```snippet:node/14-strict-ordering-market.js
```

## What it guarantees / what it doesn't

Guaranteed (both snippets execute it; the binding suites go further):

- *Exactly one leader* per election round, and each replica's group writes
  route through it.
- *One committed order.* A burst of racing bids (two vying for one slot)
  materializes as ONE sequence, byte-identical on every replica, in
  identical log positions — the fill order is the committed log.
- *Two-phase honesty.* `execute` resolving is an ACCEPTANCE, not a fill:
  the pending proposal changes no content (the wasm snippet pins that).
- *The seam exists even without a module* — a group-ordered item on a
  machine with nothing attached refuses every write `ordering_path`. The
  snippets demonstrate the pre-attach refusal, so the module's meaning is
  visible.

Not guaranteed — the price, stated where you read it:

- *The reference host is a transport contract, not a transport.* The demo
  runs three machines in one process with in-memory queues. The blobs are
  opaque raft control messages — swap `setRaftTransport` for WebSocket or a
  relay and `setRaftStorage` for IndexedDB or a server; what the tests
  prove (election, partition, recovery) transfers because the module is the
  same pure state machine.
- *The committed log is bounded, not compacted*: at most 4096 entries of at
  most 16384 op-wire bytes each; a proposal beyond the cap is REFUSED (the
  module stays healthy). Compaction is deliberately deferred — plan storage
  around the documented bound.
- *Non-leader proposals don't execute*: submit through the leader (the
  module refuses a follower's proposal and the pending shelf absorbs it).
- *The fill CONTENT only materializes where the pipeline runs* — through
  registered handlers on crabs-wasm; crabs-node has no handler surface
  (api-map known difference #2), so the node snippet asserts the fill order
  at the wire (byte-identical committed-op sequences), which is the same
  guarantee one layer down. Partition healing and crash-recovery legs: the
  snippets keep them out (single-process demo brevity) and cite the suites
  — the guarantees hold there, over the real artifacts.
- *Group-ordered halts, sovereigns don't mix*: a machine whose module
  cannot commit halts writes of exactly its group items while free-merge
  and sovereign items keep executing.

## Variations

- *Changing membership*: when the operator set changes, joint-consensus
  reconfiguration is engine-real — an excluded member steps down and stops
  receiving replication; the sim pins the single-node joint add/remove
  cycle and the leadership-churn cases. Hosts that drive this raw take the
  module handle (`moduleHandle()` on wasm).
- *When order doesn't matter*: Recipe 2's commutative merges are the tool
  for sums and counts — the value combines and the race disappears by
  construction. A lock (Recipe 9) serializes inside one machine; Recipe 13's
  sovereign chains keep per-writer order without any module (but no
  cross-writer order); Recipe 10's delegated-writer model is the trust
  trade-off when ordering by application choice suffices. This recipe is
  the one that removes the application-choice trust: the order is
  quorum-committed machinery.

## Verified against the code

<!-- PROVENANCE
target: all-bindings
domain + mint: defineItem group-ordered — wasm bindings/wasm/index.d.ts:535
  (DefineItemOptions :309-316), node :363 (DefineItemOptions :214-221);
  the only id the mint path accepts is 0 — a non-zero ordering_module is
  refused at creation (src/CRABS/data_model.c:161-172, "the only creatable
  state is ordering_module == 0"); the id resolves against the machine's
  attached module
module: Node.attachRaft — wasm bindings/wasm/index.d.ts:670
  (RaftHostOptions :377-392), node :593-597; node reference host loop
  createRaftHost bindings/node/index.js:91 (module export :259, d.ts
  :715-763); C reactor crabs_raft_module_t src/Raft/raft_module.h:190
  (create) — pure state machine, no syscalls; propose :205; poll queues
  :241-246; persist contract :113-132 (poll_persist re-reports the
  outstanding window until raftPersistComplete(handle, ok)); notifications
  RAFT_NOTIFY_COMMITTED_OP :140-148 (opBytes = serialized op wire),
  RAFT_NOTIFY_PROPOSAL_NOT_LEADER :144 (refusals tested
  test/test_raft_module.cpp:300), RAFT_NOTIFY_LOG_FULL
  (log caps: CRABS_RAFT_MAX_LOG_ENTRIES 4096 × 16384 op-wire bytes —
  raft_module.h:55-59, grow-model comment :33-46, refusals tested
  test/test_raft_module.cpp:1033; compaction deliberately deferred)
two-phase seam: a group op never executes inline — no module →
  CRABS_ERR_ORDERING_PATH (src/CRABS/crabs.h:128); module attached →
  CRABS_ERR_ORDERING_PENDING (crabs.h:131) accepted as pending; executor
  seam src/StateMachine/state_machine.c:1526-1560 (also :1532-1560), leader
  propose route :1246-1294
election: randomized timeouts from seed in [electionMinMs, electionMaxMs];
  identical seeds lockstep and livelock (the binding suites' comment —
  every example seeds 77 + i); one leader per round
  (test/test_raft_sim.cpp:985)
materialization + merge: committed ops pump through the full executor
  pipeline (handler + change events on wasm); merge adopts by committed
  position, equal tips must agree — src/CRDT/crdt_merge.c:751-790
  (append-index invariant; adopted-content test test/test_raft_sim.cpp:1637)
module state: state_attach_raft_module src/StateMachine/state_machine.h:260;
  module durable state terms/votedFor/log = its own v16 machine section
  (RaftPersistedState round trips test/test_raft_module.cpp:705-890, never
  into items or the op log); crash recovery two-sided — host retained
  persist batches replay through raftRecoverFromPersist; corrupt batches
  fail closed (src/Raft/raft_module.h:226-235); raftStatus reads null after
  a detach; one module per machine
membership: joint-consensus reconfiguration —
  crabs_raft_module_change_membership src/Raft/raft_module.h:222; an
  excluded member steps down, RAFT_MSG_CONFIG_EXCLUDED; pinned
  test/test_raft_sim.cpp:2183-2439; moduleHandle() wasm :473
mixed-machine behavior: a halted module halts only its group items while
  free-merge + sovereign keep executing — test/test_raft_sim.cpp:1576

target: crabs-wasm (snippet wasm/14-strict-ordering-market.js)
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:774
  KeyPair.generate          bindings/wasm/index.d.ts:44
  registerUser / grantRole  bindings/wasm/index.d.ts:480 / :481
  setPolicy                 bindings/wasm/index.d.ts:638
  registerHandlerJs         bindings/wasm/index.d.ts:683 (HandlerState :194,
                            HandlerOperation :268; setRegisterBytes/getRegisterBytes
                            inside handlers :206/:227)
  Node.getRegisterBytes     bindings/wasm/index.d.ts:566
  defineItem                bindings/wasm/index.d.ts:535 (DefineItemOptions :309-316)
  Operation.create          bindings/wasm/index.d.ts:122
  Node.sign / Node.execute  bindings/wasm/index.d.ts:657 / :656 (group op =
                            ORDERING_PENDING acceptance, state_machine.c:1532-1560)
  attachRaft                bindings/wasm/index.d.ts:670 (RaftHostOptions :377-392)
  RaftHost                  bindings/wasm/index.d.ts:427-476 (setRaftTransport
                            :434, setRaftStorage :443, startRaftHost :446,
                            raftPollOutbound :453, status :474)
  raftDeliver / raftStatus  bindings/wasm/index.d.ts:676 / :678
  (C reactor)               src/Raft/raft_module.h:190 (create) — propose :205,
                            poll queues :241-246, persist contract :113-132
  (two-phase seam)          src/StateMachine/state_machine.c:1532-1560
  (pending / path errors)   src/CRABS/crabs.h:131 (ORDERING_PENDING), :128 (ORDERING_PATH)
  (merge by committed position) src/CRDT/crdt_merge.c:751-790
maturity: full cluster loop + materialization STABLE (C-tested via
  test/test_raft_sim.cpp; pinned on this binding by test/raft.js)
test_ref: bindings/wasm/test/raft.js (3-node cluster E2E over the REAL wasm
  artifacts: election, pending-not-materialized, partition + heal, crash
  recovery, diagnostics) + test/test_raft_sim.cpp:985 (one leader), :1134
  (partition + heal), :685 (restart), :1637 (merge adopts committed position)

target: crabs-node (snippet node/14-strict-ordering-market.js)
verified: executed
symbols:
  new Node (NodeStatic)     bindings/node/index.d.ts:641-643
  KeyPair.generate          bindings/node/index.d.ts:71
  registerUser / grantRole  bindings/node/index.d.ts:304 / :305
  Node.setPolicy            bindings/node/index.d.ts:450
  defineItem                bindings/node/index.d.ts:363 (DefineItemOptions :214-221)
  Operation.new             bindings/node/index.d.ts (payload/signerId/addResource :62-83)
  Node.sign / Node.execute  bindings/node/index.d.ts:463 / :464
  attachRaft                bindings/node/index.d.ts:593-597
  raftTick / raftDeliver    bindings/node/index.d.ts:597 / :599
  raftPersistComplete       bindings/node/index.d.ts:601
  raftRecoverFromPersist    bindings/node/index.d.ts:608
  raftPollOutbound / PersistRequest / Notifications / raftStatus
                            bindings/node/index.d.ts:618 / :624 / :630 / :634
  raftDetach                bindings/node/index.d.ts:638
  createRaftHost (reference loop)  bindings/node/index.js:91 (module export
                            :259; d.ts :715-763 — transport/storage seams +
                            pumpInbound + raw-notification mode)
  (C reactor)               src/Raft/raft_module.h:190 (create) — propose :205,
                            persist contract :113-132, notifications :140-148
  (two-phase seam)          src/StateMachine/state_machine.c:1532-1560
  (pending / path errors)   src/CRABS/crabs.h:131 / :128
maturity: full cluster loop STABLE on the native surface (C-tested via
  test/test_raft_sim.cpp; pinned by test/raft.js — raw-notification mode)
test_ref: bindings/node/test/raft.js (3-node native cluster: election,
  fail-closed probe, committed-op wire identity across replicas, persist
  window re-report, partition + heal, crash recovery from stored batches)
persist-window note: the outstanding persist window is a VIEW re-reported
  until answered — poll once per async store round, never in a drain loop;
  the outbound queue, by contrast, TRANSFERS each blob (drain until empty);
  both snippets respect the difference — confusing it stalls the module
-->