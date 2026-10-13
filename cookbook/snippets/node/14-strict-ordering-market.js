'use strict';
// Recipe 14 — a market that needs strict ordering (crabs-node).
//
// A market's fills need ONE order every replica agrees on. Free-merge CRDTs
// converge by combining, not by ordering — two racing bids both survive and
// both replicas can read a different winner. The fix is CRABS' group-ordered
// domain + the attached raft ordering module: the module elects a leader,
// every proposal becomes a log entry at ONE index, and the committed log is
// the fill order.
//
// Three machines run in one process. The raft blobs travel across the
// reference host's in-memory transport seam (a real deployment swaps it for
// WebSocket/relay); this binding has no custom-handler surface
// (api-map known difference #2), so the committed order is asserted at the
// wire: each replica drains its module's committed-op notifications and the
// three sequences must be byte-identical, index for index. Mirrors
// bindings/node/test/raft.js.

const assert = require('assert');
const { Node, KeyPair, Operation, createRaftHost } =
  require('../../../bindings/node');

const NODE_IDS = ['node-a', 'node-b', 'node-c'];
const OP_TYPE = 'market_bid';
const ITEM = 'market';
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
  const aliceKey = KeyPair.generate();
  const nodes = [];
  const hosts = [];
  const hostById = {};
  const storageById = {};

  let nodeIndex = 0;
  for (const adminId of NODE_IDS) {
    const node = new Node(adminId, { ordering: 'hlc' });
    node.registerUser('alice', aliceKey.publicKeyHex(), '');
    node.grantRole('alice', 'role', 'member', adminId);
    node.setPolicy(OP_TYPE, 'role:member');
    // The market item declares the group-ordered domain. orderingModule must
    // match the machine's attached raft module — 0 is the only module id the
    // bindings mint, so a non-zero value is refused at item creation
    // (src/CRABS/data_model.c:161-172).
    node.defineItem(ITEM, 'register', 'lww_reg',
      { domain: 'group', orderingModule: 0 });
    // Distinct seeds: identical seeds give identical randomized election
    // deadlines — a lockstep split-vote livelock. The raft module is the
    // machine's own; the HOST is the reference loop with replaceable
    // transport/storage seams.
    const host = createRaftHost(node, {
      peers: NODE_IDS,
      seed: 77 + nodeIndex++,
      timers: { electionMinMs: 80, electionMaxMs: 160, heartbeatMs: 50 },
      tickMs: 20,
      // Raw-host mode: no materialization handlers exist on this binding,
      // so the committed-op queue is drained at the wire below.
      pumpNotifications: false,
    });
    // Storage seam: each persist window stored "durably" here (a real host
    // writes IndexedDB / a server) — and this capture is what crash recovery
    // replays (raftRecoverFromPersist).
    const storage = new Map();
    storageById[adminId] = storage;
    host.setRaftStorage(async (handle, blob) => {
      storage.set(Number(handle), blob);
    });
    // Transport seam: full-mesh in-memory delivery (asynchronous bounce).
    host.setRaftTransport((to, blob) => {
      setTimeout(() => hostById[to].pumpInbound(adminId, blob), 0);
    });
    nodes.push(node);
    hosts.push(host);
    hostById[adminId] = host;
  }

  // ---- Election: exactly one replica takes the lead. -----------------------
  for (const host of hosts) host.startRaftHost();
  await waitFor(
    () => hosts.filter((host) => host.status().isLeader).length === 1,
    'a single leader to emerge');
  const leaderIndex = hosts.findIndex((host) => host.status().isLeader);
  const leader = nodes[leaderIndex];
  console.log(`    leader elected: ${NODE_IDS[leaderIndex]}`);

  // ---- The seam the module unseals: a group write without an attached
  // module fails closed (ordering_path) — the fail-closed case that makes
  // the module's arrival meaningful rather than decorative. ----------------
  {
    const detached = new Node('probe', { ordering: 'hlc' });
    const probeKey = KeyPair.generate();
    detached.registerUser('alice', probeKey.publicKeyHex(), '');
    detached.grantRole('alice', 'role', 'member', 'probe');
    detached.setPolicy(OP_TYPE, 'role:member');
    detached.defineItem(ITEM, 'register', 'lww_reg',
      { domain: 'group', orderingModule: 0 });
    const probeOp = new Operation(OP_TYPE);
    probeOp.signerId = 'alice';
    probeOp.addResource(ITEM);
    detached.sign(probeOp, probeKey);
    assert.throws(() => detached.execute(probeOp), /ordering_path/,
      'a group write without an attached module must fail closed');
  }

  // ---- The burst: three bids, two racing for the same slot. Every op is
  // submitted through the leader's propose path (a follower's proposal would
  // surface not-leader), and the committed log — not arrival luck — is the
  // fill order. ----------------------------------------------------------------
  const bids = ['slot-3:alice', 'slot-3:bob', 'slot-9:alice'];
  const bidWires = [];
  for (const bid of bids) {
    const bidOp = new Operation(OP_TYPE);
    bidOp.signerId = 'alice';
    bidOp.addResource(ITEM);
    bidOp.payload = bid;
    leader.sign(bidOp, aliceKey);
    leader.execute(bidOp);   // accepted as a pending proposal (two-phase)
    bidWires.push(bidOp.serialize());
  }

  // ---- Every replica converges to ONE committed order: the same bid wires
  // at the same log positions. The committed-op notification carries the
  // log-index proposal id, so per-replica ordering is observable. ----------
  const notifiedPerHost = hosts.map(() => ({}));   // proposalId -> wire bytes
  await waitFor(
    () => {
      for (let hostIndex = 0; hostIndex < hosts.length; hostIndex++) {
        for (const entry of hosts[hostIndex].raftPollNotifications()) {
          if (entry.kind === RAFT_NOTIFY_COMMITTED_OP && entry.opBytes) {
            notifiedPerHost[hostIndex][Number(entry.proposalId)] =
              Buffer.from(entry.opBytes);
          }
        }
      }
      return notifiedPerHost.every((orderLog) =>
        bids.every((_, bidIndex) =>
          Object.keys(orderLog).some((logIndex) =>
            Buffer.compare(orderLog[logIndex], bidWires[bidIndex]) === 0)));
    },
    'every replica to surface all three committed bids');
  // The committed order is byte-identical across replicas, index for index.
  const orderedLogs = notifiedPerHost.map((orderLog) =>
    Object.keys(orderLog).map(Number).sort((a, b) => a - b)
      .map((logIndex) => orderLog[logIndex]));
  for (let otherIndex = 1; otherIndex < orderedLogs.length; otherIndex++) {
    assert.strictEqual(orderedLogs[otherIndex].length, orderedLogs[0].length,
      'every replica commits the same number of bids');
    for (let position = 0; position < orderedLogs[0].length; position++) {
      assert.strictEqual(
        Buffer.compare(orderedLogs[otherIndex][position],
                       orderedLogs[0][position]), 0,
        `replica ${NODE_IDS[otherIndex]} holds a different fill order at ` +
        `log position ${position}`);
    }
  }
  // The market's bookkeeping the order decides: both slot-3 bids are in the
  // log, but only ONE position in the shared sequence "fills" the slot — and
  // every replica names the same one because the sequence is the same.
  const fillOrder = orderedLogs[0].map((wire) =>
    bidWires.findIndex((candidate) => Buffer.compare(candidate, wire) === 0));
  console.log(`    committed fill order: ${fillOrder.map((bidIndex) => bids[bidIndex]).join(' -> ')}`);

  // ---- The seams stay honest: the outstanding persist window re-reports
  // until acknowledged (a view, not a transfer), and diagnostics read. -----
  for (const host of hosts) {
    const status = host.status();
    assert.strictEqual(status.peerCount, 3, 'peerCount = 3');
    assert.ok(status.term >= 1, 'term advanced');
    assert.ok(status.commitTip >= 4, 'commit tip covers the three bids');
    const window = host.raftPollPersistRequest();
    if (window) {
      assert.strictEqual(host.raftPollPersistRequest().handle, window.handle,
        'the outstanding persist window must re-report');
    }
  }

  for (const host of hosts) host.destroy();
  for (const node of nodes) assert.strictEqual(node.raftStatus(), null,
    'the module detaches on host destroy');

  console.log('strict-ordering-market node OK: one leader, a burst of racing' +
    ' bids, ONE committed order byte-identical on all three replicas');
}

main().then(() => process.exit(0)).catch((failure) => {
  console.error('strict-ordering-market node FAILED:', failure);
  process.exit(1);
});