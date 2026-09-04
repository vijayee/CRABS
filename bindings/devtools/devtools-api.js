//
// devtools-api.js — plumbing between a crabs-wasm/dev Node and the
// <crabs-devtools> panel: drains the C event ring, pulls state snapshots,
// and derives per-item state transitions by diffing consecutive snapshots.
//

'use strict';

const MAX_KEPT_EVENTS = 5000;

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
    previousItemStates: {},  // item name -> protocol state at last snapshot
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

    pullSnapshot() {
      const pointer = M._crabs_wasm_devtools_snapshot(node._am);
      const text = readWasmString(M, pointer);
      if (!text) return null;
      try {
        return JSON.parse(text);
      } catch (parseError) {
        return { error: 'snapshot parse failed: ' + parseError.message };
      }
    },

    refresh() {
      if (controller.closed) return null;
      const batch = controller.drainEvents();
      const snapshot = controller.pullSnapshot();

      // Derive transitions: diff item states against the previous snapshot,
      // then attribute each transition to the newest event targeting that item.
      const transitions = {};
      if (snapshot && snapshot.items) {
        for (const item of snapshot.items) {
          const before = controller.previousItemStates[item.name];
          if (before && before !== item.protocol_state) {
            transitions[item.name] = { from: before, to: item.protocol_state };
          }
          controller.previousItemStates[item.name] = item.protocol_state;
        }
      }
      if (snapshot && snapshot.items) {
        for (const item of snapshot.items) {
          for (let eventIndex = batch.length - 1; eventIndex >= 0; eventIndex--) {
            const event = batch[eventIndex];
            if (event.target === item.name) {
              const derived = transitions[item.name];
              if (derived) {
                event.transition = derived.from + '→' + derived.to;
              }
              break;
            }
          }
        }
      }

      controller.lastSnapshot = snapshot;
      for (const listener of controller.listeners) {
        listener({ snapshot, events: batch, allEvents: controller.events });
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
      if (controller.detachExecute) controller.detachExecute();
    },
  };

  if (typeof M._crabs_wasm_devtools_snapshot !== 'function') {
    throw new Error(
      'This WASM build was not compiled with devtools support. ' +
      "Import 'crabs-wasm/dev' instead of 'crabs-wasm'."
    );
  }

  // Seed the previous-state map so the first refresh does not report a
  // transition for every item.
  const initialSnapshot = controller.pullSnapshot();
  if (initialSnapshot && initialSnapshot.items) {
    for (const item of initialSnapshot.items) {
      controller.previousItemStates[item.name] = item.protocol_state;
    }
    controller.lastSnapshot = initialSnapshot;
  }

  // Wrap node.execute so every user-driven execute refreshes the panel.
  const originalExecute = node.execute.bind(node);
  node.execute = (operation) => {
    try {
      return originalExecute(operation);
    } finally {
      controller.refresh();
    }
  };
  controller.detachExecute = () => { node.execute = originalExecute; };

  return controller;
}

if (typeof module === 'object' && module.exports) {
  module.exports = { createDevtoolsController };
}
if (typeof window !== 'undefined') {
  window.CRABSDevtoolsApi = { createDevtoolsController };
}
