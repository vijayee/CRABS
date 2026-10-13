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
const { Node, KeyPair, Operation, Blueprint, TRUST_MODE, DATA_TYPE, CRDT_TYPE,
    wireVersions } = nativeModule;

// Mirror the wasm wrapper's frozen-object contract for the version table.
const frozenWireVersions = Object.freeze(wireVersions);

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
    raftPollNotifications() { return node.raftPollNotifications(); },
    raftPump(nowMs) { return node.raftPump(nowMs === undefined ? Date.now() : nowMs); },

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

module.exports = { Node, KeyPair, Operation, Blueprint, TRUST_MODE, DATA_TYPE, CRDT_TYPE,
    wireVersions: frozenWireVersions, createRaftHost };