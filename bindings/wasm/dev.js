//
// dev.js — devtools-enabled crabs-wasm bindings.
//
// Same API as index.js but loads crabs.dev.js, which was built with
// CRABS_ENABLE_DEVTOOLS and exposes the crabs_wasm_devtools_* exports used
// by bindings/devtools.
//

'use strict';

const createBindings = require('./bindings-core');

module.exports = createBindings(() => {
  if (typeof window !== 'undefined' && typeof window.createCRABSModuleDev === 'function') {
    return window.createCRABSModuleDev();
  }
  const path = require('path');
  const fs = require('fs');
  const wasmPaths = [
    path.join(__dirname, 'crabs.dev.js'),
    path.join(__dirname, '..', '..', 'build-wasm', 'crabs.dev.js'),
    path.join(__dirname, '..', '..', 'build-wasm.dev', 'crabs.dev.js'),
  ];
  let wasmModulePath = null;
  for (const candidate of wasmPaths) {
    if (fs.existsSync(candidate)) { wasmModulePath = candidate; break; }
  }
  if (!wasmModulePath) {
    throw new Error(
      'CRABS dev WASM module not found. Run `./build_wasm.sh` (it builds both variants).\n' +
      'Checked: ' + wasmPaths.join(', ')
    );
  }
  return require(wasmModulePath)();
});