//
// time-source.js — smoke test for the wasm setTimeSource/getTimeSource
// wiring (authenticated HTTPS time source selection).
//
// Attach-time behavior only: no fetch happens on attach, so every attach in
// this file succeeds with no network dependency (verified by using an
// unroutable endpoint in one case). The fail-closed R7-02 fetch behavior is
// covered by the C library's own time-source tests.
//
'use strict';

const assert = require('assert');
const { Node } = require('..');

function expectTimeSourceRejection(thunk, errorType, label) {
  try {
    thunk();
    assert.fail(`${label} should throw ${errorType.name}`);
  } catch (rejection) {
    assert(rejection instanceof errorType &&
           rejection.message.includes('setTimeSource'),
      `${label} should throw a typed setTimeSource error, got: ${rejection}`);
  }
}

async function main() {
  const nodeA = await Node.create('admin-a', { ordering: 'hlc' });
  const nodeB = await Node.create('admin-b', { ordering: 'hlc' });

  // A fresh node defaults to the system clock — no authenticated source
  // attached until setTimeSource says so.
  assert.strictEqual(nodeA.getTimeSource().mode, 'system',
    'fresh node getTimeSource should report mode system');

  // Default https attach: no fetch, default endpoint surfaces as url null,
  // omitted numbers echo the documented CRABS_TIME_SOURCE_DEFAULT_* values.
  nodeA.setTimeSource({ mode: 'https' });
  const httpsDefault = nodeA.getTimeSource();
  assert.strictEqual(httpsDefault.mode, 'https');
  assert.strictEqual(httpsDefault.url, null,
    'default endpoint should surface as url null');
  assert.strictEqual(httpsDefault.resyncMs, 30000);
  assert.strictEqual(httpsDefault.timeoutMs, 1000);
  assert.strictEqual(httpsDefault.maxSkewMs, 5000);
  assert.strictEqual(httpsDefault.created, true);

  // The module-shared source does NOT auto-attach to other machines: nodeB
  // never selected anything, so it stays on the system clock.
  assert.strictEqual(nodeB.getTimeSource().mode, 'system',
    'module source must not auto-attach to unconfigured machines');

  // Custom url and numeric overrides echo; resync 0 is a real value
  // (re-query every fetch), NOT a default request.
  nodeB.setTimeSource({ mode: 'https', url: 'https://time.example.com/trace',
                        resyncMs: 0, timeoutMs: 2000, maxSkewMs: 9000 });
  const httpsCustom = nodeB.getTimeSource();
  assert.strictEqual(httpsCustom.mode, 'https');
  assert.strictEqual(httpsCustom.url, 'https://time.example.com/trace');
  assert.strictEqual(httpsCustom.resyncMs, 0,
    'resync 0 must be kept as 0, not replaced by the default');
  assert.strictEqual(httpsCustom.timeoutMs, 2000);
  assert.strictEqual(httpsCustom.maxSkewMs, 9000);
  assert.strictEqual(httpsCustom.created, true);

  // Module-shared semantics (per-module, not per-machine): nodeB's 'https'
  // selection replaced the ONE module slot, so nodeA — still attached — now
  // reports the fresh configuration too.
  const aReplaced = nodeA.getTimeSource();
  assert.strictEqual(aReplaced.mode, 'https');
  assert.strictEqual(aReplaced.url, 'https://time.example.com/trace',
    'attached machines follow the module-shared source');

  // Detaching nodeA leaves nodeB attached (the shared ops is retired only
  // when the LAST attached machine leaves).
  nodeA.setTimeSource({ mode: 'system' });
  assert.strictEqual(nodeA.getTimeSource().mode, 'system');
  assert.strictEqual(nodeB.getTimeSource().mode, 'https',
    'detaching one machine must not detach the others');

  // An unroutable endpoint attaches successfully: attach performs no fetch
  // (the query runs lazily inside authenticated-time checks).
  nodeA.setTimeSource({ mode: 'https', url: 'https://unroutable.invalid/' });
  assert.strictEqual(nodeA.getTimeSource().url, 'https://unroutable.invalid/');
  nodeA.setTimeSource({ mode: 'system' });

  // Typed rejections — bogus mode / missing mode / non-object arg.
  expectTimeSourceRejection(() => nodeA.setTimeSource({ mode: 'ntp' }),
    TypeError, 'setTimeSource({mode: ntp})');
  expectTimeSourceRejection(() => nodeA.setTimeSource({}),
    TypeError, 'setTimeSource({}) (missing mode)');
  expectTimeSourceRejection(() => nodeA.setTimeSource('https'),
    TypeError, 'setTimeSource(string)');
  expectTimeSourceRejection(() => nodeA.setTimeSource(),
    TypeError, 'setTimeSource() (no arg)');
  expectTimeSourceRejection(() => nodeA.setTimeSource({ mode: 'https',
                                                        timeoutMs: 'fast' }),
    TypeError, 'setTimeSource(string timeoutMs)');
  expectTimeSourceRejection(() => nodeA.setTimeSource({ mode: 'https',
                                                        resyncMs: -1 }),
    RangeError, 'setTimeSource(negative resyncMs)');
  expectTimeSourceRejection(() => nodeA.setTimeSource({ mode: 'https',
                                                        maxSkewMs: NaN }),
    RangeError, 'setTimeSource(NaN maxSkewMs)');

  // url validation mirrors the CLI checks — http://, empty host and
  // over-long urls are RangeErrors and change NOTHING on the node.
  expectTimeSourceRejection(() => nodeA.setTimeSource({ mode: 'https',
                                                        url: 'http://example.com/t' }),
    RangeError, 'setTimeSource(http:// url)');
  expectTimeSourceRejection(() => nodeA.setTimeSource({ mode: 'https',
                                                        url: 'https://' }),
    RangeError, 'setTimeSource(empty host)');
  expectTimeSourceRejection(() => nodeA.setTimeSource({ mode: 'https',
                                                        url: 'https:///' }),
    RangeError, 'setTimeSource(slash host)');
  expectTimeSourceRejection(() => nodeA.setTimeSource({ mode: 'https',
      url: 'https://' + 'a'.repeat(256) }),
    RangeError, 'setTimeSource(url > 255 chars)');
  expectTimeSourceRejection(() => nodeA.setTimeSource({ mode: 'https', url: 42 }),
    TypeError, 'setTimeSource(number url)');
  assert.strictEqual(nodeA.getTimeSource().mode, 'system',
    'rejected setTimeSource calls must leave the selection untouched');
  assert.strictEqual(nodeB.getTimeSource().mode, 'https',
    'rejections on one node must leave the others untouched');

  // Last detach retires the module-owned ops (observable only through the
  // honest per-node echo).
  nodeB.setTimeSource({ mode: 'system' });
  assert.strictEqual(nodeB.getTimeSource().mode, 'system');

  console.log('time-source OK');

  nodeA.destroy();
  nodeB.destroy();
}

main().catch(e => { console.error(e); process.exit(1); });
