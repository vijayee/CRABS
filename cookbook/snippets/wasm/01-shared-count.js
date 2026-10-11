'use strict';
// Recipe 1 — a shared count that can't be double-counted (crabs-wasm, run in Node).
const { Node, KeyPair } = require('../../../bindings/wasm');

async function main() {
  const node = await Node.create('node-1', { ordering: 'hlc' });
  const key = await KeyPair.generate();
  node.registerUser('counter', key.publicKeyHex(), 'adult');

  node.addCounter('opens');
  node.incrementCounter('opens', 1, 'counter');
  node.incrementCounter('opens', 1, 'counter');

  const reads = node.getCounter('opens');
  if (reads !== 2) throw new Error(`expected opens=2, got ${reads}`);
  console.log(`opens=${reads}`);
  node.destroy();
  key.destroy();
}
main()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });