//
// index.js — High-level JavaScript API for CRABS Node.js bindings.
//
// This module loads the native N-API addon and provides a clean JavaScript
// API on top of the raw bindings. The native addon is built by cmake-js
// and loaded via the `bindings` package.
//

'use strict';

const path = require('path');
const { existsSync } = require('fs');

// Try to load the native addon from several possible locations
let nativeModule = null;
const possiblePaths = [
  // cmake-js default output
  path.join(__dirname, 'build', 'Release', 'crabs_node.node'),
  path.join(__dirname, 'build', 'Debug', 'crabs_node.node'),
  // prebuilt
  path.join(__dirname, 'prebuilds', 'crabs_node.node'),
];

for (const p of possiblePaths) {
  if (existsSync(p)) {
    nativeModule = require(p);
    break;
  }
}

if (!nativeModule) {
  // Fall back to the bindings package if available
  try {
    nativeModule = require('bindings')('crabs_node.node');
  } catch (e) {
    throw new Error(
      'Could not load the crabs_node native addon. ' +
      'Run `npm run build` to compile it, or ensure the prebuilt .node file is available. ' +
      `Checked: ${possiblePaths.join(', ')}`
    );
  }
}

// Re-export the native classes
const { Node, KeyPair, Operation, Blueprint, AbeKey, TRUST_MODE, DATA_TYPE, CRDT_TYPE,
    wireVersions } = nativeModule;

// Mirror the wasm wrapper's frozen-object contract for the version table.
const frozenWireVersions = Object.freeze(wireVersions);

// ============================================================
// Replay ingest (HLC bounded-skew replay fix; wasm parity)
// ============================================================
// The native class's prototype slots are SEALED (read-only, not
// configurable), so replayOp cannot be JS-wrapped in place the way wasm
// wraps its own — the batch helper is ADDED as a new prototype method
// instead, and performs the wasm binding's per-op module guard itself
// (wasm's replayOp throws TypeError for a foreign-module Operation; on this
// binding a foreign wrapper would unwrap into an unrelated pointer, so the
// structural check must run BEFORE the native call).
const nativeReplayOp = Node.prototype.replayOp;

// Batch helper over Node#replayOp. Per-op replay FAILURES never abort the
// batch — each skip is warned and returned with its index, so bulk history
// ingest converges. Structurally INVALID input still throws (the per-entry
// guard below throws TypeError for a non-Operation or foreign-module
// Operation; the array guard handles non-arrays) — repair the input, the
// batch is fine. applied HOLDS INDICES; pending (raft GROUP_ORDERED)
// outcomes also land in applied — accepted into the ordering log, not yet
// committed. Match skips on `code` (message shapes differ across bindings).
// defineProperty keeps the JS method's descriptor deliberately more permissive
// than the native class's read-only sealed slots (writable + configurable).
const replayOpsHelper = function (operations) {
  if (!Array.isArray(operations)) {
    throw new TypeError('replayOps: expected an array of Operations');
  }
  const applied = [];
  const skipped = [];
  operations.forEach((entryOperation, entryIndex) => {
    if (!entryOperation || !(entryOperation instanceof Operation)) {
      throw new TypeError(`replayOps[${entryIndex}]: expected an Operation from this module`);
    }
    const outcome = nativeReplayOp.call(this, entryOperation);
    if (outcome.status !== 'skipped') {
      applied.push(entryIndex);
    } else {
      console.warn(`crabs-node: replay skipped op[${entryIndex}]: ${outcome.message}`);
      skipped.push({ index: entryIndex, code: outcome.code, message: outcome.message });
    }
  });
  return { applied, skipped };
};
Object.defineProperty(Node.prototype, 'replayOps', {
  value: replayOpsHelper,
  writable: true,
  configurable: true,
  enumerable: false,
});

// ============================================================
// Raft ordering module — reference host
// ============================================================
// Native surface: attach/tick/deliver/poll/pump on the Node class. This
// host wrapper mirrors bindings/wasm's RaftHost: a setTimeout tick loop
// with user-replaceable transport (`setRaftTransport(fn(peerId, blob))`)
// and storage (`setRaftStorage(async (handle, blob) => …)` ) seams, and
// inbound delivery through `node.raftDeliver(peerId, blob)`.
//
// Drain disposal conventions (mirroring Raft/raft_module.h):
//   - raftPollOutbound TRANSFERS: every drained blob is copied into a JS
//     Buffer and the C bytes are consumed by the poll. Drain until empty.
//   - raftPollPersistRequest REPORTS: the handle stays module-open until
//     raftPersistComplete(handle, ok) and is re-reported while unresolved —
//     never drain-loop this queue; the host stops polling while one async
//     store round is in flight.
//   - committed-op notifications are consumed exclusively by raftPump
//     (state_raft_process_notifications_at), which materializes them
//     through the machine's pipeline ('change' events fire).

const RAFT_ERROR_NAMES = {
  0x3001: 'invariant_violated', 0x3002: 'resource_not_found',
  0x3003: 'duplicate_operation', 0x4001: 'serialization_error',
  0x4002: 'cryptographic_error', 0x5001: 'internal_error',
  0x5003: 'invalid_param', 0x5002: 'out_of_memory',
};

function raftError(rc, context) {
  const name = RAFT_ERROR_NAMES[rc] || ('error_0x' + rc.toString(16));
  const error = new Error(context + ': ' + name);
  error.rc = rc;
  return error;
}

function toBuffer(blob) {
  if (Buffer.isBuffer(blob)) return blob;
  if (blob instanceof Uint8Array || Array.isArray(blob)) return Buffer.from(blob);
  throw new TypeError('raft blob must be a Buffer/Uint8Array');
}

function createRaftHost(node, options = {}) {
  if (node.raftStatus() !== null) {
    throw new Error('attachRaft: a raft module is already attached');
  }
  const nodeId = options.nodeId || node.adminId;
  const peers = options.peers || [nodeId];
  if (!Array.isArray(peers) || peers.length === 0 || peers.length > 16) {
    throw new RangeError('attachRaft: peers must be an array of 1..16 ids');
  }
  if (!peers.includes(nodeId)) {
    throw new Error('attachRaft: peers must include this node');
  }
  const timers = options.timers || {};
  node.attachRaft({
    nodeId, peers,
    electionMinMs: timers.electionMinMs || 1500,
    electionMaxMs: timers.electionMaxMs || 3000,
    heartbeatMs: timers.heartbeatMs || 500,
    seed: options.seed || 0,
  });

  const tickMs = options.tickMs || 100;
  // Raw-host mode (pumpNotifications: false): the committed-op notification
  // queue is left for the host to drain via raftPollNotifications(). Use it
  // when no materialization handlers are registered — otherwise every
  // committed op would fail the pipeline and pile onto the retry shelf.
  const pumpNotifications = options.pumpNotifications !== false;
  const host = {
    _pumpNotifications: pumpNotifications,
    nodeId,
    peers: peers.slice(),
    _timer: null,
    _destroyed: false,
    _transport: null,
    _storage: null,
    _persistOutstanding: false,

    // The transport seam — drained control blobs go anywhere. Without one,
    // outbound messages deliberately stay queued (nothing is lost).
    //
    // RAFT TRANSPORT-AUTHENTICATION REQUIREMENT (the integrator's half of
    // the trust model — see README "Trust model" and raft_module.h): every
    // blob this fn sends must reach the named peer over a channel that
    // AUTHENTICATES that peer's identity (mTLS with client certificates,
    // SSH transport, a Noise/PSK MAC channel, ...), and the receiving side
    // must pumpInbound() with the HANDSHAKE-VERIFIED peer id — never one
    // from the wire. A follower materializes committed ops on the delivery
    // marker alone (cross-machine replicas cannot re-verify a leader's
    // signers), so an unauthenticated socket is a total log-forgery
    // primitive: any network peer speaks as any other.
    setRaftTransport(fn) { this._transport = fn; },
    // The storage seam — persist windows stored anywhere durable. A
    // resolved promise acks the window (persist_complete true); a rejected
    // one marks it failed.
    setRaftStorage(fn) { this._storage = fn; },

    startRaftHost() {
      if (this._timer || this._destroyed) return;
      this._timer = setInterval(() => this.raftTick(), tickMs);
    },
    stopRaftHost() {
      if (this._timer) { clearInterval(this._timer); this._timer = null; }
    },

    raftTick(nowMs) {
      if (this._destroyed) throw new Error('RaftHost destroyed');
      node.raftTick(nowMs === undefined ? Date.now() : nowMs);
      this._dispatch();
    },

    // Transport receive half: inject one inbound raft blob from peerId.
    // The `peerId` argument here is the module's sole credential for
    // follower-side materialization (see the RAFT TRANSPORT-AUTHENTICATION
    // REQUIREMENT on setRaftTransport): pass the identity your transport's
    // handshake VERIFIED, never an id the wire claimed.
    pumpInbound(peerId, blob) {
      if (this._destroyed) throw new Error('RaftHost destroyed');
      const rc = node.raftDeliver(peerId, toBuffer(blob));
      if (rc !== 0) throw raftError(rc, 'raftDeliver');
      this._dispatch();
    },

    _dispatch() {
      // 1. Outbound messages → transport (fire-and-forget; the queue is
      //    drained synchronously, delivery belongs to the transport loop).
      if (this._transport) {
        for (const message of node.raftPollOutbound()) {
          try {
            const sent = this._transport(message.to, message.blob);
            if (sent && typeof sent.catch === 'function') {
              sent.catch((sendError) =>
                console.warn('crabs: raft transport failed', sendError));
            }
          } catch (sendError) {
            console.warn('crabs: raft transport failed', sendError);
          }
        }
      }
      // 2. One persist window → storage. The module re-reports the same
      //    handle while unresolved, so this queue is polled once per async
      //    store round.
      if (!this._persistOutstanding && this._storage) {
        const request = node.raftPollPersistRequest();
        if (request) {
          this._persistOutstanding = true;
          let ack;
          try {
            ack = this._storage(request.handle, request.blob);
          } catch (storageError) {
            this._ackPersist(request.handle, false, storageError);
            return;
          }
          if (ack && typeof ack.then === 'function') {
            ack.then(
              () => this._ackPersist(request.handle, true, null),
              (storageError) => this._ackPersist(request.handle, false, storageError));
          } else {
            this._ackPersist(request.handle, true, null);
          }
        }
      }
      // 3. Committed-op notifications → materialization through the
      //    machine's pipeline (fires 'change' events, shelves retries).
      //    Suppressed on raw hosts (pumpNotifications: false) — such hosts
      //    drain notifications themselves via raftPollNotifications, so
      //    double-draining must not consume them here.
      if (this._pumpNotifications) {
        const now = Date.now();
        const pumpError = node.raftPump(now);
        if (pumpError !== 0 && pumpError !== 0xA006) {
          console.warn('crabs: raft notification pump returned',
                       raftError(pumpError, 'raftPump'));
        }
      }
    },

    _ackPersist(handle, ok, storageError) {
      this._persistOutstanding = false;
      if (storageError) {
        console.warn('crabs: raft persist failed', storageError);
      }
      // Unknown/stale handles (double acks) are host bookkeeping bugs —
      // surface loudly rather than silently dropping the ack.
      const rc = node.raftPersistComplete(handle, ok);
      if (rc !== 0) {
        console.warn('crabs: raft persist complete refused',
                     raftError(rc, 'raftPersistComplete'));
      }
      this._dispatch();
    },

    // Raw surfaces mirroring the native module boundary.
    raftPollOutbound() { return node.raftPollOutbound(); },
    raftPollPersistRequest() { return node.raftPollPersistRequest(); },
    raftPersistComplete(handle, ok) { node.raftPersistComplete(handle, ok); },

    // Crash recovery: replay one stored persist batch into the module's
    // durable state — the host's persist-batch record is the durable raft
    // history that survives a module/host restart whose machine blob is
    // stale (restored from a pre-commit snapshot). Batches replay in
    // arrival order; corrupt/contradictory batches fail closed (throws).
    raftRecoverFromPersist(batch) {
      if (this._destroyed) throw new Error('RaftHost destroyed');
      const rc = node.raftRecoverFromPersist(toBuffer(batch));
      if (rc !== 0) throw raftError(rc, 'raftRecoverFromPersist');
    },
    raftPollNotifications() { return node.raftPollNotifications(); },
    raftPump(nowMs) { return node.raftPump(nowMs === undefined ? Date.now() : nowMs); },

    // Joint-consensus membership change (Raft §6, parity-fill P9): the
    // leader appends the C_old,new joint entry to its own config log; when
    // committed it auto-appends C_new, and that commit ends the transition.
    // ONE change at a time (ordering_change_in_flight otherwise); the
    // returned number is the assigned proposal_id (the config entry's log
    // index). Leader-only — refusals throw (raftError via the raw rc).
    changeMembership(members) {
      if (this._destroyed) throw new Error('RaftHost destroyed');
      if (!Array.isArray(members) ||
          members.some((id) => typeof id !== 'string' || id.length === 0)) {
        throw new TypeError('changeMembership: members must be an array of non-empty id strings');
      }
      if (members.length === 0 || members.length > 16) {
        throw new RangeError('changeMembership: members must have 1..16 ids');
      }
      const proposalId = node.raftChangeMembership(members);
      // The appended entry produces persist + fan-out work immediately —
      // move it without waiting for the next tick (mirrors pumpInbound).
      this._dispatch();
      return proposalId;
    },
    // Membership reads (C config order, not sorted): the ACTIVE committed
    // config (the election/voting list) and the SECOND list of an active
    // joint consensus — empty while a plain single consensus runs.
    jointMembers() { return node.raftJointMembers(); },
    committedMembers() { return node.raftCommittedMembers(); },

    // Point diagnostics of the attached module.
    status() { return node.raftStatus(); },

    destroy() {
      if (this._destroyed) return;
      this._destroyed = true;
      this.stopRaftHost();
      node.raftDetach();
    },
  };
  return host;
}

module.exports = { Node, KeyPair, Operation, Blueprint, AbeKey, TRUST_MODE, DATA_TYPE, CRDT_TYPE,
    wireVersions: frozenWireVersions, createRaftHost };