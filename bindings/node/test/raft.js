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

async function waitFor(predicate, what, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return;
    if (Date.now() > deadline) throw new Error(`timeout waiting for: ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

async function main() {
  const nodes = [];
  const hosts = [];
  const hostById = {};
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

  // ---- Diagnostics surface sanity. ----
  for (const host of hosts) {
    const status = host.status();
    assert.ok(status.peerCount === 3, 'peerCount = 3');
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