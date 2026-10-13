'use strict';
// Recipe 14 — a market that needs strict ordering (crabs-wasm).
//
// The same three-node cluster as the node section, PLUS what the wasm
// binding's custom handlers make demoable: each committed bid is
// MATERIALIZED through the machine's pipeline, appending to a fill-order
// register — so "the one order" is readable content, not just wire
// equality. Two racing bids enter the burst; the commit order decides which
// one fills slot-3, and every replica's fill-order register ends
// byte-identical. Mirrors bindings/wasm/test/raft.js.

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../../../bindings/wasm');

const NODE_IDS = ['node-a', 'node-b', 'node-c'];
const OP_TYPE = 'market_bid';
const ITEM = 'market';
const ORDER_LOG = 'fill-order';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

async function waitFor(predicate, what, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return;
    if (Date.now() > deadline) throw new Error(`timeout waiting for: ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function registerText(node, name) {
  const bytes = node.getRegisterBytes(name);
  return bytes && bytes.length ? decoder.decode(bytes) : '';
}

async function main() {
  const aliceKey = await KeyPair.generate();
  const nodesById = {};
  const hosts = {};

  // One shared signer identity everywhere (the market's member roster).
  for (const adminId of NODE_IDS) {
    const node = await Node.create(adminId);
    node.registerUser('alice', aliceKey.publicKeyHex(), '');
    node.grantRole('alice', 'role', 'member', adminId);
    node.setPolicy(OP_TYPE, 'role:member');
    // EVERY replica materializes committed bids through this handler: the
    // racing bid rides into the market register, and the bid is APPENDED to
    // the fill-order register — the committed sequence becomes content.
    node.registerHandlerJs(OP_TYPE, (handlerState, op) => {
      const bid = op.payload.replace(/\x00+$/, '');
      const logBytes = handlerState.getRegisterBytes(ORDER_LOG);
      // A register written only through setRegister starts with the raw
      // int64 repr's zero bytes — strip them so "never filled yet" reads
      // as empty (after the first byte write the repr is raw bytes).
      const logText = (logBytes && logBytes.length
        ? decoder.decode(logBytes).replace(/^\x00+/, '') : '');
      handlerState.setRegisterBytes(ORDER_LOG,
        encoder.encode(logText + (logText === '' ? '' : ' -> ') + bid),
        'alice');
      handlerState.setRegisterBytes(ITEM, encoder.encode(bid), 'alice');
      return 0;
    });
    // The market item is group-ordered; orderingModule must match the
    // attached raft module's id (0 = the only id the bindings mint).
    node.defineItem(ITEM, 'register', 'lww_reg',
      { domain: 'group', orderingModule: 0 });
    // The fill-order log is an ordinary free-merge register the handler owns.
    node.defineItem(ORDER_LOG, 'register', 'lww_reg');
    nodesById[adminId] = node;
  }

  // ---- attachRaft returns the reference host; fast timers, distinct
  // seeds (identical seeds give identical randomized election deadlines —
  // a lockstep split-vote livelock). ----
  let nodeIndex = 0;
  for (const adminId of NODE_IDS) {
    const node = nodesById[adminId];
    hosts[adminId] = node.attachRaft({
      peers: NODE_IDS,
      timers: { electionMinMs: 80, electionMaxMs: 160, heartbeatMs: 50 },
      seed: 77 + nodeIndex++,
    });
    hosts[adminId].startRaftHost();
  }

  // Transport seam: full-mesh in-memory delivery (a real deployment swaps
  // this for WebSocket/relay — the blob is opaque to the host).
  function wireTransport() {
    for (const from of NODE_IDS) {
      hosts[from].setRaftTransport((to, blob) => {
        setTimeout(() => {
          const target = nodesById[to];
          if (target.raftStatus() === null) return;   // dead module drops it
          target.raftDeliver(from, blob);
        }, 0);
      });
    }
  }
  wireTransport();

  // Storage seam: per-node persist-window maps (the durable raft history
  // crash recovery replays through raftRecoverFromPersist).
  const hostStorage = {};
  for (const id of NODE_IDS) {
    hostStorage[id] = new Map();
    hosts[id].setRaftStorage(async (handle, blob) => {
      hostStorage[id].set(Number(handle), blob);
    });
  }

  // ---- Election: exactly one replica takes the lead. ----
  const nodes = Object.values(nodesById);
  await waitFor(
    () => nodes.filter((entry) => entry.raftStatus().isLeader).length === 1,
    'a single leader to emerge');
  const leader = nodes.find((entry) => entry.raftStatus().isLeader);
  console.log(`    leader elected: ${leader.adminId}`);

  // ---- The first bid: accepted as a PENDING proposal (execute resolves; the
  // item content does NOT move until the commit materializes it). ----
  const bids = ['slot-3:alice', 'slot-3:bob', 'slot-9:alice'];
  function bidOpAsync(bid) {
    return (async () => {
      const op = await Operation.create(OP_TYPE);
      op.signerId = 'alice';
      op.addResource(ITEM);
      // The wasm handler bridge exposes op.payload as a STRING only when it
      // is NUL-terminated (crabs_wasm_handler_op_get_payload_str contract).
      op.payload = bid + '\x00';
      leader.sign(op, aliceKey);
      return op;
    })();
  }

  const firstBid = await bidOpAsync(bids[0]);
  leader.execute(firstBid);
  await waitFor(() => leader.raftStatus().logLength >= 2,
    'the first bid to reach the module log');
  assert.ok(!registerText(leader, ITEM).includes(bids[0]),
    'the pending bid must not materialize before commit');

  // ---- The rest of the burst (both bids committed in the module's order). ----
  for (const bid of bids.slice(1)) {
    const bidOp = await bidOpAsync(bid);
    leader.execute(bidOp);
  }

  // ---- Commit materializes on all three machines; the fill-order register
  // is THE one committed order, identical everywhere. ----
  await waitFor(() => {
    const logTexts = nodes.map((entry) => registerText(entry, ORDER_LOG));
    return logTexts.every((logText) =>
      bids.every((bid) => logText.includes(bid)));
  }, 'the fill order to materialize on every replica');
  const logTexts = nodes.map((entry) => registerText(entry, ORDER_LOG));
  for (let otherIndex = 1; otherIndex < logTexts.length; otherIndex++) {
    assert.strictEqual(logTexts[otherIndex], logTexts[0],
      `replica ${NODE_IDS[otherIndex]} holds a different fill order`);
  }
  // The race resolves IN the order: both racing bids appear, and the slot-3
  // WINNER is whichever bid is later in the shared sequence — the same
  // winner on every replica.
  const slot3Fills = logTexts[0].split(' -> ')
    .filter((bid) => bid.startsWith('slot-3:'));
  assert.strictEqual(slot3Fills.length, 2,
    'both racing bids committed somewhere in the shared order');
  console.log(`    fill order: ${logTexts[0]} (slot-3 filled by ${slot3Fills[1]})`);

  // ---- Diagnostics: every replica carries the same committed tip; the
  // outbound queue is drained (transport owns the blobs). ----
  for (const node of nodes) {
    const status = node.raftStatus();
    assert.strictEqual(status.peerCount, 3, 'peerCount = 3');
    assert.ok(status.commitTip >= 4, 'commit tip covers the three bids');
    assert.deepStrictEqual(hosts[node.adminId].raftPollOutbound(), [],
      'no leftover outbound after steady state');
  }

  for (const id of NODE_IDS) hosts[id].destroy();
  for (const node of nodes) assert.strictEqual(node.raftStatus(), null,
    'the module detaches on host destroy');

  console.log('strict-ordering-market wasm OK: one leader, a burst of racing' +
    ' bids, the committed fill order materialized byte-identical on all' +
    ' three replicas');
}

main().catch((failure) => {
  console.error('strict-ordering-market wasm FAILED:', failure);
  process.exit(1);
});