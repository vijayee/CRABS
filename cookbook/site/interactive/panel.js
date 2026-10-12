//
// panel.js — boots the crabs-wasm dev bundle for the cookbook's interactive
// demo panels. Same loading pattern as examples/devtools_demo: the Emscripten
// glue (crabs.dev.js) exposes window.createCRABSModuleDev, and bindings-core.js
// maps it onto the high-level Node/KeyPair API via window.CRABSWasmCore, with
// locateFile pointing at the sibling .wasm binary under /assets/wasm/.
//
// A panel declares itself in markup:
//   <div data-demo="shared-count" class="interactive">
//     <button data-action="increment">…</button>
//     <strong data-state="counter">0</strong>
//     <p data-status>…</p>
//   </div>
// Buttons are wired by data-action; every readout lives in a data-state
// element; the wasm boot state and any failure surface in [data-status]
// (red on error) and on console.error — a demo that fails silently is a
// broken demo, so errors are always made visible.
//

'use strict';

const WASM_BASE = '/assets/wasm/';

function bootCrabs() {
  if (!window.CRABSWasmCore || !window.createCRABSModuleDev) {
    throw new Error('crabs-wasm scripts not loaded (expected /assets/wasm/crabs.dev.js + bindings-core.js)');
  }
  return window.CRABSWasmCore(() => window.createCRABSModuleDev({
    locateFile: (basePath) => WASM_BASE + basePath,
  }));
}

// Booted exactly once per panel; the promise is shared so every action
// (including clicks landing while the binary is still downloading) waits for
// the same module instead of racing to load a second one. CRABSWasmCore
// returns the bindings object synchronously — the actual wasm module loads
// inside Node.create — so it is wrapped in a resolved promise; a rejection
// surfaces in the status line and is rethrown so the triggering action's own
// catch reports it too.
function bootCrabsOnce(panel) {
  if (!panel.bootPromise) {
    panel.status('Loading the CRABS WebAssembly module (about 1.8 MB)…');
    panel.bootPromise = Promise.resolve(bootCrabs()).catch((bootError) => {
      panel.status('WASM boot failed: ' + bootError.message, 'error');
      console.error('panel.js: wasm boot failed', bootError);
      throw bootError;
    });
  }
  return panel.bootPromise;
}

// --- demo: shared-count (recipe 1) ---
// One in-page G-counter node; increments are attributed to a fixed demo node
// id, so the readout is simply the number of clicks (retries merge, they
// cannot double-count).
function sharedCountDemo(panel) {
  const COUNTER_NAME = 'opens';
  const DEMO_NODE_ID = 'site-visitor';
  let node = null;

  function readValue() {
    if (!node) return null;
    return node.getCounter(COUNTER_NAME);
  }

  function refresh() {
    const value = readValue();
    if (value !== null) {
      panel.state('counter', String(value));
      panel.state('node-id', node.adminId);
      const nodeIdLine = panel.root.querySelector('[data-node-id-line]');
      if (nodeIdLine) nodeIdLine.style.display = '';
    }
  }

  return {
    async init() {
      if (!node) {
        const dev = await bootCrabsOnce(panel);
        node = await dev.Node.create('demo-panel', { ordering: 'hlc' });
        node.addCounter(COUNTER_NAME);
      }
      refresh();
      panel.status('Node "' + node.adminId + '" is live — counter "' +
        COUNTER_NAME + '" is at ' + readValue() + '. Increments are ' +
        'attributed to "' + DEMO_NODE_ID + '", the way every G-counter ' +
        'entry is per-node.');
    },
    async increment() {
      if (!node) await this.init();
      node.incrementCounter(COUNTER_NAME, 1, DEMO_NODE_ID);
      refresh();
      panel.status('increment "' + COUNTER_NAME + '" +1 (from "' +
        DEMO_NODE_ID + '") — read back ' + readValue() + '.');
    },
    async read() {
      if (!node) await this.init();
      const value = node.getCounter(COUNTER_NAME);
      refresh();
      panel.status('getCounter("' + COUNTER_NAME + '") = ' + value +
        ' — the per-node table sums to ' + value + '.');
    },
  };
}

const demos = { 'shared-count': sharedCountDemo };

(function main() {
  const root = document.querySelector('[data-demo]');
  if (!root) {
    console.error('panel.js: no [data-demo] panel element on this page');
    return;
  }
  const demoName = root.dataset.demo;
  if (!demos[demoName]) {
    console.error('panel.js: unknown demo "' + demoName + '"');
    return;
  }
  const panel = {
    bootPromise: null,
    root,
    state: (stateName, text) => {
      const readouts = root.querySelectorAll('[data-state="' + stateName + '"]');
      if (!readouts.length) {
        console.error('panel.js: panel has no [data-state="' + stateName + '"] readout');
      }
      readouts.forEach((readout) => { readout.textContent = text; });
    },
    status: (message, kind) => {
      const slot = root.querySelector('[data-status]');
      if (slot) {
        slot.textContent = message;
        slot.classList.toggle('error', kind === 'error');
      }
    },
  };

  const demo = demos[demoName](panel);
  for (const actionButton of root.querySelectorAll('[data-action]')) {
    const actionName = actionButton.dataset.action;
    if (typeof demo[actionName] !== 'function') {
      actionButton.disabled = true;
      console.error('panel.js: demo "' + demoName + '" has no action "' + actionName + '"');
      continue;
    }
    actionButton.addEventListener('click', async () => {
      try {
        panel.status('…');
        await demo[actionName]();
      } catch (actionError) {
        panel.status('"' + actionName + '" failed: ' + actionError.message, 'error');
        console.error('panel.js: action "' + actionName + '" failed', actionError);
      }
    });
  }

  // Debug handle for browser automation, mirroring examples/devtools_demo.
  window.__crabsDemoPanel = { panel, demo, root };
})();