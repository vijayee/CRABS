//
// raft.js — Node-binding raft surfaces: a smaller mirror of the wasm
// bindings' 3-node cluster suite. Runs THREE native Node instances in one
// process through the reference host from index.js (createRaftHost), with
// in-memory transport/storage seams and a RAW notification drain
// (pumpNotifications: false — this binding predates the JS-handler
// surface, so materialization is asserted at the wire level instead: every
// replica's committed-op notification carries the same opaque op bytes).
//
'use strict';

const assert = require('assert');

const { Node, KeyPair, Operation, createRaftHost } = require('..');

const NODE_IDS = ['nodeA', 'nodeB', 'nodeC'];
const OP_TYPE = 'council_write';
const ITEM = 'council';
const RAFT_NOTIFY_COMMITTED_OP = 3;

async function waitFor(predicate, what, timeoutMs = 30000, intervalMs = 20) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return;
    if (Date.now() > deadline) throw new Error(`timeout waiting for: ${what}`);
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

async function main() {
  const nodes = [];
  const hosts = [];
  const hostById = {};
  const storageById = {};   // crash-recovery leg replays these batches
  const aliceKey = KeyPair.generate();

  let nodeIndex = 0;
  for (const adminId of NODE_IDS) {
    const node = new Node(adminId, { ordering: 'hlc' });
    node.registerUser('alice', aliceKey.publicKeyHex(), '');
    node.grantRole('alice', 'role', 'member', adminId);
    node.setPolicy(OP_TYPE, 'role:member');
    // GROUP_ORDERED item bound to module id 0 (the only module each node
    // carries); group writes then fail closed until attachRaft.
    node.defineItem(ITEM, 'register', 'lww_reg',
      { domain: 'group', orderingModule: 0 });

    const host = createRaftHost(node, {
      peers: NODE_IDS,
      // Distinct seeds: identical seeds give identical randomized election
      // deadlines — a lockstep split-vote livelock.
      seed: 77 + nodeIndex++,
      timers: { electionMinMs: 80, electionMaxMs: 160, heartbeatMs: 50 },
      tickMs: 20,
      // Raw mode: no materialization handlers exist on this binding, so the
      // committed-op notifications are drained directly at the wire.
      pumpNotifications: false,
    });
    nodes.push(node);
    hosts.push(host);
    hostById[adminId] = host;

    const storage = new Map();
    storageById[adminId] = storage;
    host.setRaftStorage(async (handle, blob) => { storage.set(Number(handle), blob); });
    // Full-mesh async in-memory transport; `partitioned` isolates one node.
    host.setRaftTransport((to, blob) => {
      if (global.__partitioned &&
          (adminId === global.__partitioned) !== (to === global.__partitioned)) {
        return;
      }
      setTimeout(() => hostById[to].pumpInbound(adminId, blob), 0);
    });
  }

  // ---- Election: exactly one leader. ----
  for (const host of hosts) host.startRaftHost();
  await waitFor(
    () => hosts.filter((host) => host.status().isLeader).length === 1,
    'a single leader to emerge');
  const leaderIndex = hosts.findIndex((host) => host.status().isLeader);
  const leader = nodes[leaderIndex];
  console.log(`    leader elected: ${NODE_IDS[leaderIndex]}`);

  // ---- Group write before attach fails closed (the v1 seam). ----
  {
    const detached = new Node('probe', { ordering: 'hlc' });
    const probeKey = KeyPair.generate();
    detached.registerUser('alice', probeKey.publicKeyHex(), '');
    detached.defineItem(ITEM, 'register', 'lww_reg',
      { domain: 'group', orderingModule: 0 });
    const probeOp = new Operation(OP_TYPE);
    probeOp.signerId = 'alice';
    probeOp.addResource(ITEM);
    detached.sign(probeOp, probeKey);
    assert.throws(() => detached.execute(probeOp), /ordering_path/,
      'a group write without an attached module must fail closed');
  }

  // ---- Two-phase submission on the leader. ----
  const op = new Operation(OP_TYPE);
  op.signerId = 'alice';
  op.addResource(ITEM);
  leader.sign(op, aliceKey);
  const opWire = op.serialize();
  leader.execute(op);                 // accepted (ordering_pending resolved OK)
  await waitFor(() => hosts[leaderIndex].status().logLength >= 2,
                'the proposal to reach the module log');

  // ---- Replication + commit: every replica's committed-op notification
  // carries the SAME opaque op bytes (raw mode — no pump consumed them). ----
  const committedWires = [];
  const drainedNotifications = hosts.map(() => []);
  for (let hostIndex = 0; hostIndex < hosts.length; hostIndex++) {
    await waitFor(
      () => {
        drainedNotifications[hostIndex].push(
          ...hosts[hostIndex].raftPollNotifications());
        return drainedNotifications[hostIndex].some(
          (entry) => entry.kind === RAFT_NOTIFY_COMMITTED_OP &&
                     entry.opBytes &&
                     Buffer.compare(Buffer.from(entry.opBytes), opWire) === 0);
      },
      `host ${NODE_IDS[hostIndex]} to surface the committed op`);
    const committed = drainedNotifications[hostIndex]
      .filter((entry) => entry.kind === RAFT_NOTIFY_COMMITTED_OP);
    assert.ok(committed.length >= 1,
      `every replica must see the committed op (${NODE_IDS[hostIndex]})`);
    committedWires.push(Buffer.from(committed[0].opBytes));
  }
  for (const wire of committedWires) {
    assert.strictEqual(Buffer.compare(wire, opWire), 0,
      'the committed op wire must be byte-identical on every replica');
  }
  for (const host of hosts) {
    assert.ok(host.status().commitTip >= 2,
      `${host.status().nodeId} commit tip should advance`);
  }
  console.log('    decree committed; committed-op wire identical on all three nodes');

  // ---- Persist windows: the storage seam filled; the outstanding window is
  // a re-reported view until acknowledged (checked on the leader). ----
  {
    const leaderHost = hosts[leaderIndex];
    const window = leaderHost.raftPollPersistRequest();
    if (window) {
      const windowAgain = leaderHost.raftPollPersistRequest();
      if (windowAgain) {
        assert.strictEqual(windowAgain.handle, window.handle,
          'the outstanding persist window must be re-reported');
        leaderHost.raftPersistComplete(windowAgain.handle, true);
      }
    }
  }

  // ---- Partition one node: the quorum keeps working; the partitioned
  // node freezes its group path. ----
  global.__partitioned = 'nodeC';
  const beforeTip = hosts[2].status().commitTip;
  const survivorHosts = [hosts[0], hosts[1]];
  await waitFor(
    () => survivorHosts.filter((host) => host.status().isLeader).length === 1,
    'the surviving quorum to settle its leader');
  const quorumIndex = hosts.findIndex(
    (host) => host.status().isLeader && host !== hosts[2]);
  const quorumLeader = nodes[quorumIndex];

  const op2 = new Operation(OP_TYPE);
  op2.signerId = 'alice';
  op2.addResource(ITEM);
  quorumLeader.sign(op2, aliceKey);
  quorumLeader.execute(op2);
  const quorumTipBefore = hosts[quorumIndex].status().commitTip;
  await waitFor(() => hosts[quorumIndex].status().commitTip > quorumTipBefore,
                'the second decree to commit in the quorum');
  await waitFor(() =>
    hosts[quorumIndex].raftPollNotifications().some(
      (entry) => entry.kind === RAFT_NOTIFY_COMMITTED_OP),
    'the quorum leader to surface the second committed op');
  await new Promise((resolve) => setTimeout(resolve, 1000));
  assert.strictEqual(hosts[2].status().commitTip, beforeTip,
    'the partitioned node commit tip must freeze');
  console.log(`    partition: nodeC halted at tip ${beforeTip}; quorum committed the second decree`);

  // ---- Heal → convergence. ----
  global.__partitioned = null;
  await waitFor(() => {
    const tips = new Set(hosts.map((host) => host.status().commitTip));
    return tips.size === 1;
  }, 'the healed cluster to converge to one commit tip');
  const healedOps = hosts[2].raftPollNotifications()
    .filter((entry) => entry.kind === RAFT_NOTIFY_COMMITTED_OP);
  // The first decree committed while nodeC was CONNECTED (its notification
  // was drained in the first phase); the halted second decree MUST arrive
  // only after the heal.
  assert.ok(healedOps.some(
    (entry) => Buffer.compare(Buffer.from(entry.opBytes), op2.serialize()) === 0),
    'the healed node must receive the second decree only after the heal');
  console.log('    heal: nodeC converged');

  // ---- Crash recovery: module state lost, batch storage retained — the
  // smaller raw-mode mirror of the wasm suite's recovery leg. nodeB loses
  // its module state (a fresh machine: no raft term/log — the stale machine
  // blob's shape) while ITS persist-batch record survives in the storage
  // capture. The host re-drives the retained batches into a fresh module
  // via raftRecoverFromPersist; the next group write then lands as the same
  // byte-identical committed-op wire. ----
  {
    const crashedId = 'nodeB';
    const crashedIndex = NODE_IDS.indexOf(crashedId);
    const retainedBatches = [...storageById[crashedId].values()];
    assert.ok(retainedBatches.length > 0,
      'the storage capture must hold the crash-recovery batches');
    hosts[crashedIndex].destroy();
    assert.strictEqual(nodes[crashedIndex].raftStatus(), null,
      'the crashed module detaches before recovery');

    // Fresh machine, same roster/policy/item registration — the shape of a
    // restored pre-commit machine blob (module term/log empty).
    const recoveredNode = new Node(crashedId, { ordering: 'hlc' });
    recoveredNode.registerUser('alice', aliceKey.publicKeyHex(), '');
    recoveredNode.grantRole('alice', 'role', 'member', crashedId);
    recoveredNode.setPolicy(OP_TYPE, 'role:member');
    recoveredNode.defineItem(ITEM, 'register', 'lww_reg',
      { domain: 'group', orderingModule: 0 });
    const recoveredHost = createRaftHost(recoveredNode, {
      peers: NODE_IDS,
      timers: { electionMinMs: 80, electionMaxMs: 160, heartbeatMs: 50 },
      tickMs: 20,
      seed: 313,   // fresh seed — the old one is retired with the module
      pumpNotifications: false,
    });
    hosts[crashedIndex] = recoveredHost;
    hostById[crashedId] = recoveredHost;
    nodes[crashedIndex] = recoveredNode;
    // Fail-closed surface: a corrupted batch (bad version byte) throws and
    // invents no durable state.
    const corruptBatch = Buffer.from(retainedBatches[0]);
    corruptBatch[0] = 0xEE;
    assert.throws(() => recoveredHost.raftRecoverFromPersist(corruptBatch),
      /raftRecoverFromPersist/,
      'a corrupted batch must fail closed');
    // Replay the retained batches in arrival order.
    for (const batch of retainedBatches) {
      recoveredHost.raftRecoverFromPersist(batch);
    }
    recoveredHost.setRaftStorage(async (handle, blob) => {
      storageById[crashedId].set(Number(handle), blob);
    });
    recoveredHost.setRaftTransport((to, blob) => {
      if (global.__partitioned &&
          (crashedId === global.__partitioned) !== (to === global.__partitioned)) {
        return;
      }
      setTimeout(() => hostById[to].pumpInbound(crashedId, blob), 0);
    });
    recoveredHost.startRaftHost();
    console.log(`    recovery: nodeB module rebuilt from ` +
      `${retainedBatches.length} stored batches`);
  }

  // ---- Resume committing: the next decree lands on the recovered node. ----
  await waitFor(
    () => hosts.filter((host) => host.status().isLeader).length === 1,
    'the cluster to settle one leader after the recovery');
  const resumeIndex = hosts.findIndex((host) => host.status().isLeader);
  const op3 = new Operation(OP_TYPE);
  op3.signerId = 'alice';
  op3.addResource(ITEM);
  nodes[resumeIndex].sign(op3, aliceKey);
  const op3Wire = op3.serialize();
  nodes[resumeIndex].execute(op3);
  await waitFor(() =>
    hosts[NODE_IDS.indexOf('nodeB')].raftPollNotifications().some(
      (entry) => entry.kind === RAFT_NOTIFY_COMMITTED_OP && entry.opBytes &&
                 Buffer.compare(Buffer.from(entry.opBytes), op3Wire) === 0),
    'the recovered node to surface the post-recovery committed op');
  await waitFor(() => {
    const tips = new Set(hosts.map((host) => host.status().commitTip));
    return tips.size === 1;
  }, 'the recovered cluster to converge on one commit tip');
  console.log('    recovery: nodeB resumed committing (byte-identical committed op)');

  // ---- Membership change (Raft §6 joint consensus — node mirror of the
  // C sim's RaftMembership scenarios): the 3-node cluster shrinks to 2.
  // The two-phase evolution is pinned: the leader appends C_old,new; when
  // that entry commits the joint second list is visible while the committed
  // config STILL counts three; the automatic C_new successor's commit then
  // ends the transition on the plain two-member config. Ops keep landing on
  // the reduced cluster; the removed node is excluded (ghost replication
  // stops) but converges onto the same committed config. ----
  {
    await waitFor(
      () => hosts.filter((host) => host.status().isLeader).length === 1,
      'one leader to settle before the membership change');
    const changeLeader = hosts.find((host) => host.status().isLeader);
    const changeId = changeLeader.changeMembership(['nodeA', 'nodeB']);
    assert.ok(changeId > 0,
      'the change returns the assigned proposal_id (the log index)');

    // ONE change at a time (§6): an appended-but-uncommitted config entry
    // refuses a second change immediately.
    assert.throws(() => changeLeader.changeMembership(['nodeA', 'nodeB']),
      /ordering_change_in_flight/,
      'a second concurrent change must refuse');

    // Appended-but-uncommitted: pending, and the committed config still
    // counts the three boot members (phase 0: nothing visible yet).
    assert.strictEqual(changeLeader.status().configChangePending, true,
      'the change must be pending before its joint commit');
    assert.deepStrictEqual(
      [...changeLeader.committedMembers()].sort(),
      ['nodeA', 'nodeB', 'nodeC'],
      'the committed config must stay the old three pre-commit');

    // Phase 1 → 2: the joint C_old,new commits (old-list majority 2/3); the
    // joint second list spans both configs while the automatic C_new
    // successor commits under BOTH lists' majorities. That window closes
    // within one replication round, so the poll LATCHES whatever joint list
    // any host surfaces while waiting for the transition to settle.
    let jointSecondList = null;
    await waitFor(() => {
      for (const host of hosts) {
        const joint = host.jointMembers();
        if (joint.length > 0) jointSecondList = [...joint].sort();
      }
      return hosts.every((host) => host.jointMembers().length === 0 &&
                                 host.status().configChangePending === false);
    }, 'the transition to settle through the joint phase', 30000, 5);
    assert.deepStrictEqual(jointSecondList, ['nodeA', 'nodeB'],
      'the joint phase must have been visible between the two commits');

    // Transition ends plain: exactly {nodeA, nodeB} as the committed config
    // everywhere — including the excluded node, which learns through the
    // committed entry the exclusion control carries.
    await waitFor(
      () => hosts.every((host) => host.committedMembers().length === 2),
      'every node (including the excluded one) to settle on the final config');
    for (const host of hosts) {
      assert.deepStrictEqual([...host.committedMembers()].sort(),
        ['nodeA', 'nodeB'],
        `${host.status().nodeId}: committed config must be exactly the pair`);
    }
    assert.strictEqual(changeLeader.status().configChangePending, false,
      'no change may stay pending after C_new commits');

    // Ops keep landing on the reduced cluster: the reduced leader proposes;
    // the fellow survivor surfaces the committed op; nodeC does not.
    global.__partitioned = null;
    await waitFor(
      () => hosts.filter((host) =>
        host.status().isLeader && host.status().nodeId !== 'nodeC').length === 1,
      'a leader among the surviving pair to settle');
    const reducedIndex = hosts.findIndex(
      (host) => host.status().isLeader && host.status().nodeId !== 'nodeC');
    assert.notStrictEqual(reducedIndex, -1,
      'the reduced cluster must settle a leader from the survivors');
    const reducedLeader = nodes[reducedIndex];
    const op4 = new Operation(OP_TYPE);
    op4.signerId = 'alice';
    op4.addResource(ITEM);
    reducedLeader.sign(op4, aliceKey);
    const op4Wire = op4.serialize();
    reducedLeader.execute(op4);
    await waitFor(() =>
      hosts[1 - reducedIndex].raftPollNotifications().some(
        (entry) => entry.kind === RAFT_NOTIFY_COMMITTED_OP && entry.opBytes &&
          Buffer.compare(Buffer.from(entry.opBytes), op4Wire) === 0),
      'the fellow survivor to surface the post-change committed op');
    await new Promise((resolve) => setTimeout(resolve, 800));
    assert.ok(hosts[2].raftPollNotifications().every(
      (entry) => !entry.opBytes ||
        Buffer.compare(Buffer.from(entry.opBytes), op4Wire) !== 0),
      'the excluded node must not receive post-change committed ops');
    console.log(`    membership: 3 → 2 via joint consensus ` +
      `(change proposal ${changeId}); ops continue on the reduced cluster`);
  }

  // ---- Diagnostics surface sanity. ----
  for (const host of hosts) {
    const status = host.status();
    assert.ok(status.peerCount === 2, 'peerCount = 2 (post-change)');
    assert.ok(status.term >= 1, 'term advanced');
    assert.strictEqual(status.nodeId !== undefined, true, 'nodeId present');
    host.destroy();
    assert.strictEqual(nodes[hosts.indexOf(host)].raftStatus(), null,
      'status is null after the module detaches');
  }

  console.log('raft.js: node-binding raft cluster suite passed');
}

main().then(() => process.exit(0)).catch((error) => {
  console.error(error);
  process.exit(1);
});