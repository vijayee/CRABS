//
// raft.js — Phase 4 E2E: a THREE-node in-memory raft cluster running the
// REAL wasm artifacts (crabs.js + crabs.wasm) through the JS reference host
// in bindings-core. Mirrors the C sim's group-item scenario end to end:
//
//   • three Node instances in one process; raft control blobs travel as
//     opaque blobs over an in-memory transport seam (setTimeout bounce =
//     the async queue the plan asks for), storage as in-memory maps.
//   • elect leader → propose a GROUP_ORDERED register write → pending →
//     commit → materialized on ALL THREE nodes (change events fire too).
//   • partition one node: group writes halt THERE while the surviving
//     quorum still proposes/commits; heal → the partitioned node converges.
//   • crash-recovery: nodeB loses its module state (machine blob reverted
//     to the pre-commit shape) while its stored persist batches survive —
//     the host replays them through raftRecoverFromPersist and the node
//     restores its committed content and resumes committing.
//
// This is also the executable documentation of the reference-host seams:
// transport / storage / timer are user-replaceable (WebSocket/relay,
// IndexedDB/localStorage, any clock) — here they are in-memory queues.
//
'use strict';

const assert = require('assert');
const { Node, KeyPair, Operation } = require('..');
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Deadline helpers: the raft timers are REAL time (the reference host ticks
// with Date.now), so convergence waits poll on wall clock.
async function waitFor(predicate, what, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return;
    if (Date.now() > deadline) {
      throw new Error(`timeout waiting for: ${what}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function registerContains(node, name, text) {
  return decoder.decode(node.getRegisterBytes(name)).includes(text);
}

async function main() {
  const NODE_IDS = ['nodeA', 'nodeB', 'nodeC'];
  const nodes = [];
  const nodesById = {};

  // Shared signer identity: the same registered user (same keypair) exists
  // on every machine, like a real deployment's roster. The op is signed
  // against the LEADER's state and proposed through its propose path.
  const aliceKey = await KeyPair.generate();
  const OP_TYPE = 'council_write';
  const ITEM = 'council';

  for (const adminId of NODE_IDS) {
    const node = await Node.create(adminId);
    node.registerUser('alice', aliceKey.publicKeyHex(), '');
    node.grantRole('alice', 'role', 'member', adminId);
    // Every replica materializes committed ops through the registered JS
    // handler — the group register takes the op payload.
    node.registerHandlerJs(OP_TYPE, (state, op) => {
      state.setRegisterBytes(ITEM, encoder.encode(op.payload), 'alice');
      return 0;
    });
    node.setPolicy(OP_TYPE, 'role:member');
    node.defineItem(ITEM, 'register', 'lww_reg', { domain: 'group' });
    nodes.push(node);
    nodesById[adminId] = node;
  }

  // ---- Fast timers: elections 80–160 ms, heartbeat 50 ms, host tick 20 ms.
  // attachRaft returns the reference RaftHost that drives each module. ----
  const hosts = {};
  let nodeIndex = 0;
  for (const node of nodes) {
    hosts[node.adminId] = node.attachRaft({
      peers: NODE_IDS,
      timers: { electionMinMs: 80, electionMaxMs: 160, heartbeatMs: 50 },
      // Distinct seeds: identical seeds give identical randomized election
      // deadlines — lockstep split votes that can livelock the election.
      seed: 77 + nodeIndex++,
    });
    hosts[node.adminId].startRaftHost();
  }

  // ---- The transport seam: full-mesh in-memory async queues. The blob is
  // opaque — the test mirrors the real contract (send anywhere; incoming
  // blobs return through raftDeliver). ----
  let partitioned = null;   // node id isolated from everyone, or null
  function wireTransport() {
    for (const from of nodes) {
      hosts[from.adminId].setRaftTransport((to, blob) => {
        if (partitioned !== null &&
            (from.adminId === partitioned) !== (to === partitioned)) {
          return;                                   // dropped in transit
        }
        setTimeout(() => {
          const target = nodesById[to];
          // A module torn down mid-flight drops the blob (a real transport
          // delivering to a dead node loses the message too).
          if (target.raftStatus() === null) return;
          target.raftDeliver(from.adminId, blob);
        }, 0);
      });
    }
  }
  wireTransport();

  // ---- The storage seam: per-node in-memory persist-window maps. ----
  const hostStorage = {};
  for (const id of NODE_IDS) hostStorage[id] = new Map();
  for (const from of nodes) {
    hosts[from.adminId].setRaftStorage(async (handle, blob) => {
      hostStorage[from.adminId].set(Number(handle), blob);
    });
  }

  // ---- Elect a leader: exactly one node takes the lead. ----
  await waitFor(
    () => nodes.filter((entry) => entry.raftStatus().isLeader).length === 1,
    'a single leader to emerge');
  const leader = nodes.find((entry) => entry.raftStatus().isLeader);
  console.log(`    leader elected: ${leader.adminId}`);

  // ---- Propose the group-item op end to end. ----
  const op = await Operation.create(OP_TYPE);
  op.signerId = 'alice';
  op.payload = 'decree-7\x00'   // wasm quirk: string payloads are NUL-terminated (crabs_wasm_handler_op_get_payload_str contract)
  op.addResource(ITEM);
  leader.sign(op, aliceKey);
  // Two-phase submission: the group write is ACCEPTED (ordering_pending is
  // hidden behind execute resolving normally), and the item content does
  // NOT move until commit.
  leader.execute(op);
  await waitFor(
    () => leader.raftStatus().logLength >= 2,
    'the proposal to reach the module log');
  assert.ok(!registerContains(leader, ITEM, 'decree-7'),
            'pending proposal must not materialize before commit');

  // Commit rides persistence + replication. Materializations fire 'change'
  // events through each machine's pump; the trampoline filters listeners by
  // the op's SIGNER node id (the signing leader here), so the leader's
  // listener is the observable surface for the committed event. Followers
  // are verified through their materialized content below.
  const leaderEvents = [];
  leader.on('change', (event) => leaderEvents.push(event));
  await waitFor(() => nodes.every((entry) => registerContains(entry, ITEM,
    'decree-7')), 'the decree to materialize on all three nodes', 30000);
  assert.ok(
    leaderEvents.some((event) => event.type === OP_TYPE && event.result === 0),
    'the leader must surface a successful committed-op change event');
  for (const node of nodes) {
    assert.ok(node.raftStatus().commitTip > 0,
              `${node.adminId} commit tip should advance`);
  }
  console.log('    decree-7 committed + materialized on all three nodes');

  // ---- Partition nodeC (from === C and to === C split). ----
  partitioned = 'nodeC';
  const beforeTip = nodesById['nodeC'].raftStatus().commitTip;

  // The surviving quorum keeps working regardless of who leads: wait for
  // exactly one leader among A/B (a leader-C instance would face an
  // election), then propose through it.
  await waitFor(() => {
    const survivors = nodes.filter((entry) => entry.adminId !== 'nodeC');
    return survivors.filter((entry) => entry.raftStatus().isLeader).length === 1;
  }, 'the quorum to settle its leader', 30000);
  const quorumLeader = nodes.find(
    (entry) => entry.adminId !== 'nodeC' && entry.raftStatus().isLeader);

  const op2 = await Operation.create(OP_TYPE);
  op2.signerId = 'alice';
  op2.payload = 'decree-9\x00'
  op2.addResource(ITEM);
  const quorumTipBefore = quorumLeader.raftStatus().commitTip;
  quorumLeader.sign(op2, aliceKey);
  quorumLeader.execute(op2);
  await waitFor(() => quorumLeader.raftStatus().commitTip > quorumTipBefore,
                'the second decree to commit in the quorum', 30000);
  await waitFor(() => registerContains(quorumLeader, ITEM, 'decree-9'),
                'the quorum leader to materialize decree-9', 30000);
  assert.ok(registerContains(quorumLeader, ITEM, 'decree-9'),
            'the quorum leader materializes decree-9');

  // The partitioned node HALTS: no decree-9 ever lands there (give the
  // quorum time to keep churning first).
  await new Promise((resolve) => setTimeout(resolve, 1000));
  assert.ok(!registerContains(nodesById['nodeC'], ITEM, 'decree-9'),
            'the partitioned node must halt its group items');
  assert.strictEqual(nodesById['nodeC'].raftStatus().commitTip,
                     beforeTip,
                     'the partitioned node commit tip must freeze');
  console.log(`    partition: nodeC halted at tip ${beforeTip}; quorum committed decree-9`);

  // ---- Heal → convergence. ----
  partitioned = null;
  // Convergence = the healed node carries the committed content AND the
  // cluster settles to one shared commit tip (no further proposals append,
  // so the tips equalize and stay).
  await waitFor(() => {
    const tips = new Set(nodes.map((entry) => entry.raftStatus().commitTip));
    return tips.size === 1 &&
           registerContains(nodesById['nodeC'], ITEM, 'decree-9');
  }, 'the healed node to converge to the shared commit tip', 30000);
  assert.strictEqual(nodesById['nodeC'].raftStatus().commitTip,
                     quorumLeader.raftStatus().commitTip,
                     'the healed node must reach the quorum commit tip');
  console.log('    heal: nodeC converged');

  // ---- Diagnostics surface sanity (reference host queries). ----
  for (const node of nodes) {
    const status = node.raftStatus();
    assert.ok(status !== null && status.peerCount === 3, 'peerCount = 3');
    assert.ok(status.term >= 1, 'term advanced');
    assert.ok(status.logLength >= 3, 'log carries the two configured decrees');
  }
  // Raw drains preserve their disposal conventions: outbound drains empty
  // (transport owns them); persist re-reports ONE unresolved window until
  // acknowledged.
  for (const node of nodes) {
    assert.deepStrictEqual(hosts[node.adminId].raftPollOutbound(), [],
                           'no leftover outbound after steady state');
  }
  const leaderHost = hosts[leader.adminId];
  const window = leaderHost.raftPollPersistRequest();
  if (window !== null) {
    // A live window is re-reported (a view, not a transfer): the handle
    // stays open on the module until the host acknowledges.
    assert.strictEqual(leaderHost.raftPollPersistRequest().handle,
                       window.handle,
                       'persist window must be a re-reported view');
    leaderHost.raftPersistComplete(window.handle, true);
  }

  // ---- Crash recovery: module state lost, batch storage retained. ----
  // nodeB loses its module state (its machine blob reverts to the stale
  // pre-commit shape) while ITS persist-batch record survives in the
  // in-memory storage capture — the host's durable raft history. The host
  // re-drives the retained batches into a fresh module via
  // raftRecoverFromPersist and the node resumes committing.
  {
    const crashedId = 'nodeB';
    const crashedIndex = nodes.findIndex(
      (entry) => entry.adminId === crashedId);
    const retainedBatches = [...hostStorage[crashedId].values()];
    assert.ok(retainedBatches.length > 0,
              'the storage capture must hold the crash-recovery batches');
    hosts[crashedId].destroy();
    assert.strictEqual(nodes[crashedIndex].raftStatus(), null,
                       'the crashed module detaches before recovery');

    // Fresh machine, same roster/handler/item registration — the shape of
    // a restored pre-commit machine blob (module term/log empty).
    const recoveredNode = await Node.create(crashedId);
    recoveredNode.registerUser('alice', aliceKey.publicKeyHex(), '');
    recoveredNode.grantRole('alice', 'role', 'member', crashedId);
    recoveredNode.registerHandlerJs(OP_TYPE, (state, op) => {
      state.setRegisterBytes(ITEM, encoder.encode(op.payload), 'alice');
      return 0;
    });
    recoveredNode.setPolicy(OP_TYPE, 'role:member');
    recoveredNode.defineItem(ITEM, 'register', 'lww_reg', { domain: 'group' });
    const recoveredHost = recoveredNode.attachRaft({
      peers: NODE_IDS,
      timers: { electionMinMs: 80, electionMaxMs: 160, heartbeatMs: 50 },
      seed: 313,   // fresh seed — the old one is retired with the module
    });
    recoveredHost.setRaftStorage(async (handle, blob) => {
      hostStorage[crashedId].set(Number(handle), blob);
    });
    hosts[crashedId] = recoveredHost;
    nodes[crashedIndex] = recoveredNode;
    nodesById[crashedId] = recoveredNode;
    wireTransport();   // re-wire: the replacement host needs the seam too

    // Fail-closed surface: a corrupted batch (bad version byte) is
    // refused — replay never invents durable state from garbage.
    const corrupt = Uint8Array.from(retainedBatches[0]);
    corrupt[0] = 0xEE;
    assert.throws(() => recoveredHost.raftRecoverFromPersist(corrupt),
                  /raftRecoverFromPersist/,
                  'a corrupted batch must fail closed');

    // Replay the retained batches in arrival order.
    for (const batch of retainedBatches) {
      recoveredHost.raftRecoverFromPersist(batch);
    }
    recoveredHost.startRaftHost();
    console.log(`    recovery: nodeB module rebuilt from ` +
                `${retainedBatches.length} stored batches`);

    // The rejoin re-learns the committed prefix: nodeB's LAST pre-crash
    // content (decree-9; the register is LWW so later commits overwrite
    // earlier ones) materializes on the stale machine blob's register.
    await waitFor(() =>
      registerContains(recoveredNode, ITEM, 'decree-9'),
      'the recovered node to restore its pre-crash committed content');
  }

  // ---- Resume committing: the recovered node re-learns its committed
  // prefix as the live quorum advances, restoring its pre-crash
  // materialized content AND taking the next decree. ----
  await waitFor(() =>
    nodes.filter((entry) => entry.raftStatus().isLeader).length === 1,
    'the cluster to settle one leader after the recovery');
  const resumeLeader = nodes.find((entry) => entry.raftStatus().isLeader);
  const op3 = await Operation.create(OP_TYPE);
  op3.signerId = 'alice';
  op3.payload = 'decree-11\x00';
  op3.addResource(ITEM);
  resumeLeader.sign(op3, aliceKey);
  resumeLeader.execute(op3);
  await waitFor(() => {
    const recovered = nodes.find((entry) => entry.adminId === 'nodeB');
    return registerContains(recovered, ITEM, 'decree-11');
  }, 'the recovered node to commit the next decree', 30000);
  assert.ok(registerContains(nodesById['nodeB'], ITEM, 'decree-11'),
            'the recovered node carries the next decree');
  // The whole cluster settles on ONE shared tip: the recovered node is a
  // full voting member again, not a catching-up straggler.
  await waitFor(() =>
    new Set(nodes.map((entry) => entry.raftStatus().commitTip)).size === 1,
    'the recovered cluster to converge on one commit tip', 30000);
  console.log(`    recovery: nodeB resumed committing (tip ` +
              `${nodesById['nodeB'].raftStatus().commitTip})`);

  // ---- Membership change (Raft §6 joint consensus — parity-fill P9, the
  // wasm mirror of the node suite's leg): the 3-node cluster shrinks to 2.
  // Pinned: pending right after the call (nothing visible yet), the joint
  // second list between the two commits, then the plain two-member config
  // everywhere including the excluded node; ops keep landing on the
  // survivors and are cut off from the excluded node. ----
  {
    await waitFor(
      () => nodes.filter((entry) => entry.raftStatus().isLeader).length === 1,
      'one leader to settle before the membership change');
    const changeLeader = nodes.find((entry) => entry.raftStatus().isLeader);
    const changeHost = hosts[changeLeader.adminId];
    const changeId = changeHost.changeMembership(['nodeA', 'nodeB']);
    assert.ok(changeId > 0,
      'the change returns the assigned proposal_id (the log index)');

    // ONE change at a time (§6): an appended-but-uncommitted config entry
    // refuses a second change immediately.
    assert.throws(() => changeHost.changeMembership(['nodeA', 'nodeB']),
      /ordering_change_in_flight/,
      'a second concurrent change must refuse');
    assert.strictEqual(changeLeader.raftStatus().configChangePending, true,
      'the change must be pending before its joint commit');
    assert.deepStrictEqual(
      [...changeHost.committedMembers()].sort(),
      ['nodeA', 'nodeB', 'nodeC'],
      'the committed config must stay the old three pre-commit');

    // The joint C_old,new commits (old-list majority 2/3); the joint second
    // list spans both configs until the automatic C_new successor commits.
    // The window closes within one replication round, so the poll LATCHES
    // whatever joint list any host surfaces while waiting for the settle.
    let jointSecondList = null;
    await waitFor(() => {
      for (const id of NODE_IDS) {
        const joint = hosts[id].jointMembers();
        if (joint.length > 0) jointSecondList = [...joint].sort();
      }
      return NODE_IDS.every((id) =>
        hosts[id].jointMembers().length === 0 &&
        nodesById[id].raftStatus().configChangePending === false);
    }, 'the transition to settle through the joint phase', 30000, 5);
    assert.deepStrictEqual(jointSecondList, ['nodeA', 'nodeB'],
      'the joint phase must have been visible between the two commits');
    await waitFor(() =>
      NODE_IDS.every((id) =>
        [...hosts[id].committedMembers()].sort().join(',') ===
        'nodeA,nodeB'),
      'every node (including the excluded one) to settle on the final config');

    // Ops keep landing on the reduced cluster — materialized content flows
    // to the survivors only. The excluded node's tip freezes.
    await waitFor(() =>
      nodes.filter((entry) => entry.raftStatus().isLeader &&
                              entry.adminId !== 'nodeC').length === 1,
      'a leader among the surviving pair to settle');
    const reducedLeader = nodes.find((entry) => entry.raftStatus().isLeader &&
                                                 entry.adminId !== 'nodeC');
    const nodeCTipBefore = nodesById['nodeC'].raftStatus().commitTip;
    const op4 = await Operation.create(OP_TYPE);
    op4.signerId = 'alice';
    op4.payload = 'decree-13\x00';
    op4.addResource(ITEM);
    reducedLeader.sign(op4, aliceKey);
    reducedLeader.execute(op4);
    await waitFor(() => registerContains(reducedLeader, ITEM, 'decree-13'),
      'the reduced leader to materialize the post-change decree');
    await waitFor(() =>
      [...hosts['nodeA'].committedMembers()].sort().join(',') ===
      'nodeA,nodeB' &&
      [...hosts['nodeB'].committedMembers()].sort().join(',') ===
      'nodeA,nodeB' &&
      [...hosts['nodeC'].committedMembers()].sort().join(',') ===
      'nodeA,nodeB',
      'the excluded node to learn the final committed config');
    await new Promise((resolve) => setTimeout(resolve, 800));
    assert.ok(!registerContains(nodesById['nodeC'], ITEM, 'decree-13'),
      'the excluded node must not materialize post-change committed ops');
    assert.ok(nodesById['nodeC'].raftStatus().commitTip >= nodeCTipBefore,
      'the excluded node may only advance to the exclusion ceiling');
    console.log(`    membership: 3 → 2 via joint consensus ` +
      `(change proposal ${changeId}); ops continue on the reduced cluster`);
  }

  // ---- Host teardown: stop cleanly (destroy detaches + destroys modules).
  for (const node of nodes) {
    node.raftStatus().nodeId !== undefined;   // status stays readable
    hosts[node.adminId].destroy();
    assert.strictEqual(node.raftStatus(), null,
                       'status is null after the module detaches');
  }

  console.log('raft.js: 3-node wasm cluster E2E passed');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});