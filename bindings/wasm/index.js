//
// index.js — production crabs-wasm bindings (no devtools support).
//

'use strict';

const createBindings = require('./bindings-core');

module.exports = createBindings(() => {
  if (typeof window !== 'undefined' && typeof window.createCRABSModule === 'function') {
    return window.createCRABSModule();
  }
  const path = require('path');
  const fs = require('fs');
  const wasmPaths = [
    path.join(__dirname, 'crabs.js'),
    path.join(__dirname, '..', '..', 'build-wasm', 'crabs.js'),
  ];
  let wasmModulePath = null;
  for (const candidate of wasmPaths) {
    if (fs.existsSync(candidate)) { wasmModulePath = candidate; break; }
  }
  if (!wasmModulePath) {
    throw new Error(
      'CRABS WASM module not found. Run `./build_wasm.sh` to compile it.\n' +
      'Checked: ' + wasmPaths.join(', ')
    );
  }
  return require(wasmModulePath)();
});