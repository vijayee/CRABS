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
const { Node, KeyPair, Operation } = nativeModule;

module.exports = { Node, KeyPair, Operation };