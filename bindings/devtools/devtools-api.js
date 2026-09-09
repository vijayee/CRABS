//
// devtools-api.js — plumbing between a crabs-wasm/dev Node and the
// <crabs-devtools> panel: drains the C event ring, pulls state snapshots,
// and diffs consecutive snapshots into a dot-path -> diff-kind map.
//

'use strict';

const MAX_KEPT_EVENTS = 5000;

// The panel's State tab renders this derived view of the snapshot (raw
// internals like node_id/version/hlc live in the overview header instead).
// Both diffFromPrevious() and the tree renderer flatten THIS shape, so
// diff dot-paths (e.g. 'items.0.value') always match the rendered paths.
function deriveView(snapshot) {
  if (!snapshot) return null;
  // Key sections by their natural identifier so the State tree shows names
  // ('items.views', 'policies.lock') instead of array indices. The snapshot
  // stores arrays, but every section's entries carry a unique key in a valid
  // state (item names, op types, trigger/user/schedule ids); a malformed
  // duplicate would overwrite — acceptable for an inspector.
  const keyBy = (list, keyField) => {
    const keyed = {};
    for (const entry of (list || [])) {
      const key = (entry != null && entry[keyField] != null)
        ? String(entry[keyField]) : 'unknown';
      keyed[key] = entry;
    }
    return keyed;
  };
  return {
    items: keyBy(snapshot.items, 'name'),
    policies: keyBy(snapshot.policies, 'operation'),
    triggers: keyBy(snapshot.triggers, 'id'),
    users: keyBy(snapshot.users, 'id'),
    schedules: keyBy(snapshot.schedules, 'id'),
    log_head: snapshot.log_head || { entries: 0, state_hash: '' },
  };
}

// Flatten a snapshot subtree into scalar leaves so plain === comparison
// detects every change. Arrays recurse (one row per element) and also record
// a length marker at the container path,
// so a length change reads as 'changed' there instead of the container
// itself falsely flipping 'removed'/'added'. Distinct-but-equal empty
// containers collapse to their JSON form so they don't read as a change.
function flattenSnapshot(value, prefix, into) {
  if (value === null || typeof value !== 'object') {
    into[prefix] = value;
    return;
  }
  const keys = Object.keys(value);
  if (Array.isArray(value)) {
    into[prefix] = '[array:' + keys.length + ']';
  } else if (keys.length === 0) {
    into[prefix] = '{}';
    return;
  }
  for (const key of keys) {
    flattenSnapshot(value[key], prefix ? prefix + '.' + key : key, into);
  }
}

function readWasmString(M, pointer) {
  if (!pointer) return null;
  const text = M.UTF8ToString(pointer);
  M._crabs_wasm_devtools_string_destroy(pointer);
  return text;
}

function createDevtoolsController(node, options) {
  const M = node._M;
  // nodeId is the node's bootstrap admin id — the identity crabs_wasm_sign
  // stamps into op->node_id. All WASM nodes share one global C event ring, so
  // an unfiltered drain would attribute every node's events to this panel.
  // Passing nodeId drains only this node's events and preserves the rest for
  // their owning panels; without it the unfiltered global drain is used.
  const nodeId = (options && options.nodeId) || null;
  const maxEvents = (options && options.maxEvents) || MAX_KEPT_EVENTS;

  const controller = {
    events: [],              // drained operation events (oldest first)
    listeners: [],           // callbacks fired on every refresh
    diffs: {},               // dot-path -> 'added' | 'changed' | 'removed'
    lastSnapshot: null,
    closed: false,

    drainEvents() {
      const hasFilteredDrain = typeof M._crabs_wasm_devtools_drain_events_for === 'function';
      // Raw exported functions cannot take JS strings, so the node id goes
      // through ccall (which converts it to a heap-allocated C string).
      const pointer = nodeId && hasFilteredDrain
        ? M.ccall('crabs_wasm_devtools_drain_events_for', 'number',
                  ['string'], [nodeId])
        : M._crabs_wasm_devtools_drain_events();
      const text = readWasmString(M, pointer);
      let batch = [];
      try {
        batch = JSON.parse(text || '[]');
      } catch (parseError) {
        // The C ring is already drained at this point, so the malformed
        // batch is unrecoverable — warn rather than silently dropping it.
        batch = [];
        console.warn('crabs-devtools: dropped malformed event batch:',
                     parseError.message);
      }
      if (batch.length > 0) {
        controller.events.push(...batch);
        if (controller.events.length > maxEvents) {
          controller.events.splice(0, controller.events.length - maxEvents);
        }
      }
      return batch;
    },

    // Flat dot-path -> diff kind map over the whole snapshot (against the
    // previous one). Only the previous snapshot is retained (bounded buffer;
    // a later time-travel view builds on this). Paths key the derived view
    // so they line up with the State tab tree ('items.0.value').
    diffFromPrevious(next) {
      const previous = this.lastSnapshot;
      if (previous == null || next == null || next.error) return {};
      const diffs = {};
      const before = {};
      const after = {};
      flattenSnapshot(deriveView(previous), '', before);
      flattenSnapshot(deriveView(next), '', after);
      for (const path of Object.keys(after)) {
        if (!(path in before)) diffs[path] = 'added';
        else if (before[path] !== after[path]) diffs[path] = 'changed';
      }
      for (const path of Object.keys(before)) {
        if (!(path in after)) diffs[path] = 'removed';
      }
      return diffs;
    },

    pullSnapshot() {
      const pointer = M._crabs_wasm_devtools_snapshot(node._am);
      const text = readWasmString(M, pointer);
      if (!text) return null;
      let snapshot;
      try {
        snapshot = JSON.parse(text);
      } catch (parseError) {
        // A parse failure must not poison the diff baseline: keep the last
        // good snapshot and the diffs that describe it.
        return { error: 'snapshot parse failed: ' + parseError.message };
      }
      controller.diffs = controller.diffFromPrevious(snapshot);
      controller.lastSnapshot = snapshot;
      return snapshot;
    },

    refresh() {
      if (controller.closed) return null;
      const batch = controller.drainEvents();
      const snapshot = controller.pullSnapshot();
      for (const listener of controller.listeners) {
        listener({
          snapshot,
          events: batch,
          allEvents: controller.events,
          diffs: controller.diffs,
        });
      }
      return { snapshot, batch };
    },

    onUpdate(callback) {
      controller.listeners.push(callback);
      return () => {
        const listenerIndex = controller.listeners.indexOf(callback);
        if (listenerIndex >= 0) controller.listeners.splice(listenerIndex, 1);
      };
    },

    close() {
      controller.closed = true;
      controller.listeners.length = 0;
      if (controller.detachChange) controller.detachChange();
      if (controller.detachExecute) controller.detachExecute();
    },
  };

  if (typeof M._crabs_wasm_devtools_snapshot !== 'function') {
    throw new Error(
      'This WASM build was not compiled with devtools support. ' +
      "Import 'crabs-wasm/dev' instead of 'crabs-wasm'."
    );
  }

  // Seed the diff baseline so the first refresh only reports what actually
  // changed between construction and the first refresh.
  controller.pullSnapshot();

  // Refresh on the node's push change events when available; otherwise fall
  // back to wrapping node.execute so user-driven executes still refresh.
  if (typeof node.on === 'function') {
    const changeListener = () => controller.refresh();
    // Some emitters return an unsubscribe function instead of exposing off();
    // capture it so close() can detach either way.
    const unsubscribe = node.on('change', changeListener);
    controller.detachChange = () => {
      if (typeof unsubscribe === 'function') unsubscribe();
      else if (typeof node.off === 'function') node.off('change', changeListener);
    };
  } else {
    const originalExecute = node.execute.bind(node);
    node.execute = (operation) => {
      try {
        return originalExecute(operation);
      } finally {
        controller.refresh();
      }
    };
    controller.detachExecute = () => { node.execute = originalExecute; };
  }

  return controller;
}

if (typeof module === 'object' && module.exports) {
  module.exports = { createDevtoolsController, deriveView };
}
if (typeof window !== 'undefined') {
  window.CRABSDevtoolsApi = { createDevtoolsController, deriveView };
}
