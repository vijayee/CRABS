//
// devtools.js — smoke test for the dev/prod artifact split.
//
// Production artifact must NOT expose devtools exports; dev artifact must,
// and drain + snapshot must return valid JSON.
//

'use strict';

const assert = require('assert');

async function main() {
  const prod = require('../index.js');
  const prodM = await prod.getModule();
  assert.strictEqual(typeof prodM._crabs_wasm_devtools_snapshot, 'undefined',
    'production artifact must not expose devtools exports');
  assert.strictEqual(typeof prodM._crabs_wasm_devtools_drain_events, 'undefined',
    'production artifact must not expose devtools exports');
  console.log('prod artifact: devtools exports correctly absent');

  const dev = require('../dev.js');
  const devM = await dev.getModule();
  assert.strictEqual(typeof devM._crabs_wasm_devtools_snapshot, 'function',
    'dev artifact must expose devtools exports');
  assert.strictEqual(typeof devM._crabs_wasm_devtools_drain_events, 'function',
    'dev artifact must expose devtools exports');
  assert.strictEqual(typeof devM._crabs_wasm_devtools_string_destroy, 'function',
    'dev artifact must expose devtools exports');

  const drainPtr = devM._crabs_wasm_devtools_drain_events();
  const drained = devM.UTF8ToString(drainPtr);
  devM._crabs_wasm_devtools_string_destroy(drainPtr);
  assert.ok(Array.isArray(JSON.parse(drained)),
    'drain must return a JSON array string');
  console.log('dev artifact: devtools exports present, drain returns JSON');
}

main().then(
  () => console.log('devtools smoke test passed'),
  (error) => { console.error(error); process.exit(1); }
);