//
// hlc-skew-replay.js — N-API e2e for the bounded-skew replay fix
// (brief 2026-10-17; parity with bindings/wasm/test/hlc-skew-replay.js).
//
// Replay of a beyond-window op fails closed on the default config and
// CLAMPS through on the replay-opt-in config (Node option
// skew.replayPolicy). The op is AGED 6.1s past the 5s default window
// (wall-clock age, no forged stamps). crabs-node has no registerHandlerJs
// surface, so the stateful op is the defineOperationType + per-user dedup
// tracker shape (the setContains readback pins the materialization). Also
// pins: bad skew options throw on the public surface (while skew:null /
// undefined are tolerated as "no options", wasm parity), re-ingesting an
// executed op is a typed already_executed (0x7002) skip that does not
// re-run the mutation, and the replayOps batch survives per-op skips
// (applied holds INDICES; a fresh-uuid second op clamp-materializes in the
// same batch). Also pins the class-checked Operation unwraps (a plain
// object or a foreign wrapper instance refuses execute/replayOp with a
// TypeError, before any native deref) and the replayOps warn throttle
// (first 10 skips warn individually, then ONE summary line — while
// `skipped` still carries every entry).
//
// The N-API binding is synchronous — the only async leg is the 6.1s aging
// wait itself.
//

'use strict';

const { Node, KeyPair, Operation } = require('..');

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) {
    passed++;
  } else {
    failed++;
    console.error('FAIL:', msg);
  }
}

function mustThrowWith(invoke, fragment, label) {
  let caught = null;
  try { invoke(); } catch (caughtError) { caught = caughtError; }
  assert(caught !== null, `${label}: expected a throw`);
  assert(caught && caught.message.includes(fragment),
    `${label}: expected message containing "${fragment}", ` +
    `got "${caught && caught.message}"`);
}

(async () => {
  // --- Validation first (cheap): bad skew options reject on the public
  // surface before any machine exists.
  mustThrowWith(() => new Node('bad', { skew: { replayPolicy: 'clampX' } }),
    "skew.replayPolicy must be 'clamp' or 'reject'", 'unknown replayPolicy');
  mustThrowWith(() => new Node('bad', { skew: { maxSkewMs: -1 } }),
    'skew.maxSkewMs must be a non-negative safe integer', 'negative maxSkewMs');
  // 2**53 + 1 collapses to 2**53 in the double space — the first UNREPRESENTABLE
  // safe value — so either spelling must refuse instead of silently arming a
  // huge (broken) window.
  mustThrowWith(() => new Node('bad', { skew: { maxSkewMs: 2 ** 53 + 1 } }),
    'skew.maxSkewMs must be a non-negative safe integer', 'out-of-range maxSkewMs');
  mustThrowWith(() => new Node('bad', { skew: 'bogus' }),
    'skew must be an options object', 'non-object skew');
  mustThrowWith(() => new Node('bad', { skew: { maxSkewMs: 1.5 } }),
    'skew.maxSkewMs must be a non-negative safe integer', 'fractional maxSkewMs');
  // skew.strategy whitelist (full wasm parseSkewOptions parity): a junk
  // strategy throws rather than silently falling back to the default.
  mustThrowWith(() => new Node('bad', { skew: { strategy: 'bogus' } }),
    "skew.strategy must be one of 'naive'|'bounded'|'quorum'|'strict'|'trusted'",
    'unknown strategy');
  // Falsy skew VALUES are "no skew options" (wasm parseSkewOptions's
  // `!options.skew` early return) — only truthy junk throws.
  assert(new Node('skew-null', { skew: null }) !== null,
    'skew:null tolerates as "no options"');
  assert(new Node('skew-undefined', { skew: undefined }) !== undefined,
    'skew:undefined tolerates as "no options"');

  const aliceKey = KeyPair.generate();
  const bobKey = KeyPair.generate();

  // Shared registration + policy setup any replayer needs (the log replays
  // ops; the user registry arrives with the snapshot in real deployments).
  // grantRole's signer must match the machine's own bootstrap admin id.
  // crabs-node has no registerHandlerJs, so the stateful op type is wired
  // through defineOperationType (per-user dedup spec whose tracker IS the
  // record — the executor's applied spec mutation writes membership).
  const setupNode = (nodeName, nodeOptions) => {
    const node = new Node(nodeName, nodeOptions);
    node.registerUser('alice', aliceKey.publicKeyHex(), '');
    node.grantRole('alice', 'role', 'member', nodeName);
    node.registerUser('bob', bobKey.publicKeyHex(), '');
    node.grantRole('bob', 'role', 'member', nodeName);
    node.addOneShotSet('proposal-42_voters');
    node.setPolicy('__define_operation_type__', 'role:admin');
    node.setPolicy('vote', 'role:member');
    node.defineOperationType('vote', {
      dedup: 'per-user',
      trackerPath: 'proposal-42_voters',
      rejectionMessage: 'already_performed',
    });
    return node;
  };

  // --- Author: sign an op NOW (its HLC stamp carries the author clock T).
  const author = setupNode('author', { ordering: 'hlc' });
  const op = new Operation('vote');
  op.signerId = 'alice';
  op.nodeId = 'author';
  op.addResource('proposal-42_voters');
  author.sign(op, aliceKey);
  author.execute(op);
  assert(author.setContains('proposal-42_voters', 'alice') === true,
    'author executed its own vote');
  const opWire = op.serialize();

  // --- Second op, signed + serialized but NEVER executed anywhere: its
  // clamp replay materializes in the mixed batch below, proving `applied`
  // holds INDICES of ingested entries while the already-executed op stays
  // skipped. A DIFFERENT signer avoids the per-user dedup guard (alice is
  // already a voter once the aged op ingests) and its own fresh uuid keeps
  // it out of the uuid-dedup set — the readback setContains('bob') pins the
  // materialization. Its HLC was stamped at author-sign time (T0), also
  // >5s old at replay, so only the clamp path lets it through.
  const secondOp = new Operation('vote');
  secondOp.signerId = 'bob';
  secondOp.nodeId = 'author';
  secondOp.addResource('proposal-42_voters');
  author.sign(secondOp, bobKey);
  const secondOpWire = secondOp.serialize();

  // --- Wait past the default 5s skew window (the N-API HLC stamps the WALL
  // clock at sign, same timing semantics as the wasm binding).
  await new Promise((resolve) => setTimeout(resolve, 6100));

  // --- Fresh node, 0-SENTINEL skew config (wasm parity): maxSkewMs 0 maps
  // to the C-side default 5000ms window (NOT accept-all), so the aged op
  // still fails closed on a live execute with protocol_violation and
  // mutates nothing.
  const defaultReplayer = setupNode('default-replayer', { skew: { maxSkewMs: 0 } });
  const defaultOp = Operation.deserialize(opWire);
  let defaultThrew = '';
  try { defaultReplayer.execute(defaultOp); }
  catch (caughtError) { defaultThrew = caughtError.message; }
  assert(defaultThrew.includes('protocol_violation'),
    `default live replay must throw protocol_violation, got "${defaultThrew}"`);
  assert(!defaultReplayer.setContains('proposal-42_voters', 'alice'),
    'the refused live replay must not mutate the tracker');

  // --- Fresh CLAMP node: replayOp materializes the historic op.
  const clampReplayer = setupNode(
    'clamp-replayer', { ordering: 'hlc', skew: { replayPolicy: 'clamp' } });

  // --- Batch guard first: a non-array is structurally invalid input and
  // throws (repair the input; a VALID batch never throws on per-op skips).
  mustThrowWith(() => clampReplayer.replayOps('nonsense'),
    'expected an array', 'non-array replayOps');

  const clampOutcome = clampReplayer.replayOp(Operation.deserialize(opWire));
  assert(clampOutcome.status === 'applied',
    `clamp replay must ingest the historic op (got ${JSON.stringify(clampOutcome)})`);
  assert(clampReplayer.setContains('proposal-42_voters', 'alice') === true,
    'clamp replay must materialize the tracker membership');
  assert(clampOutcome.code === undefined && clampOutcome.message === undefined,
    'an applied outcome carries no error fields');

  // --- Re-ingest the same op: the typed idempotent skip.
  const reOutcome = clampReplayer.replayOp(Operation.deserialize(opWire));
  assert(reOutcome.status === 'skipped',
    `re-ingest must be a skip (got ${JSON.stringify(reOutcome)})`);
  assert(reOutcome.code === 0x7002 /* CRABS_ERR_ALREADY_EXECUTED */,
    `re-ingest skip must carry already_executed 0x7002, got 0x${(reOutcome.code || 0).toString(16)}`);
  // Skip-shape parity pin: match the skip on `code` — message SHAPES differ
  // across bindings (wasm wraps its error context, the N-API layer returns
  // the bare error name), so only the string-ness is pinned here.
  assert(reOutcome.code === 0x7002 && typeof reOutcome.message === 'string',
    `re-ingest skip must carry a string message, got "${reOutcome.message}"`);
  assert(clampReplayer.setContains('proposal-42_voters', 'alice') === true,
    'the skip must not unwind the materialized membership');

  // --- Mixed batch pin (wasm parity): index 0 is the already-executed op
  // (skipped 0x7002), index 1 is the never-executed second op
  // (clamp-materializes). `applied` must equal the INDICES array — not the
  // op objects themselves — and the per-op skip must not abort the batch.
  const mixed = clampReplayer.replayOps([
    Operation.deserialize(opWire),
    Operation.deserialize(secondOpWire),
  ]);
  assert(JSON.stringify(mixed.applied) === '[1]',
    `mixed batch applied must equal [1] (indices), got ${JSON.stringify(mixed.applied)}`);
  assert(mixed.skipped.length === 1 &&
         mixed.skipped[0].index === 0 &&
         mixed.skipped[0].code === 0x7002,
    `mixed batch must skip entry 0 with already_executed, got ${JSON.stringify(mixed.skipped)}`);
  assert(clampReplayer.setContains('proposal-42_voters', 'bob') === true,
    'the never-executed second op materialized through clamp');

  // --- skew.strategy positive pin (wasm parseSkewOptions parity): a node
  // built with an explicit bounded strategy + clamp policy ACCEPTS and
  // applies the aged op — proving the option is honored, not silently
  // dropped (while an unknown strategy threw above).
  const strategyReplayer = setupNode('strategy-replayer', {
    ordering: 'hlc', skew: { strategy: 'bounded', maxSkewMs: 100, replayPolicy: 'clamp' },
  });
  const strategyOutcome = strategyReplayer.replayOp(Operation.deserialize(secondOpWire));
  assert(strategyOutcome.status === 'applied',
    `bounded-strategy node must apply the aged op (got ${JSON.stringify(strategyOutcome)})`);
  assert(strategyReplayer.setContains('proposal-42_voters', 'bob') === true,
    'bounded-strategy node must materialize the tracker membership');

  // --- Class-checked unwrap pins (review follow-up): ObjectWrap::Unwrap is
  // class-agnostic, so a plain object used to null-deref and a KeyPair
  // instance used to be a type-confused read fed into the executor. Both
  // must now throw the typed TypeError instead (the guard fires BEFORE any
  // native unwrap, so a wrong object never reaches the executor).
  mustThrowWith(() => clampReplayer.execute({}),
    'expected an Operation', 'execute with plain object');
  mustThrowWith(() => clampReplayer.replayOp({}),
    'expected an Operation', 'replayOp with plain object');
  mustThrowWith(() => clampReplayer.replayOp(KeyPair.generate()),
    'expected an Operation', 'replayOp with a KeyPair instance');

  // --- Warn-throttle pin (wasm parity, 6deefd4): a 13-skip batch warns the
  // first 10 skips individually, then ONE summary line — while `skipped`
  // still carries ALL 13 entries (the historic op already applied above, so
  // every copy re-ingests as a no-op already_executed dedup).
  const floodOps = [];
  for (let floodIndex = 0; floodIndex < 13; floodIndex++) {
    floodOps.push(Operation.deserialize(opWire));
  }
  const capturedWarns = [];
  const realWarn = console.warn;
  console.warn = (...warnArgs) => capturedWarns.push(warnArgs.join(' '));
  let floodBatch = null;
  try {
    floodBatch = clampReplayer.replayOps(floodOps);
  } finally {
    console.warn = realWarn;
  }
  assert(floodBatch.skipped.length === 13,
    `every flood skip must still be reported, got ${floodBatch.skipped.length}`);
  assert(floodBatch.applied.length === 0,
    `no flood entry may apply, got ${JSON.stringify(floodBatch.applied)}`);
  assert(capturedWarns.length === 10 + 1,
    `throttled batch must emit exactly 11 warn lines (10 + summary), got ${capturedWarns.length}`);
  assert(capturedWarns[0].includes('replay skipped op[0]: already_executed'),
    `first individual warn must carry op[0], got "${capturedWarns[0]}"`);
  assert(capturedWarns[9].includes('replay skipped op[9]: already_executed'),
    `tenth individual warn must carry op[9], got "${capturedWarns[9]}"`);
  assert(capturedWarns[10].includes('...and 3 more skipped (total 13)'),
    `summary line must be "...and 3 more skipped (total 13)", got "${capturedWarns[10]}"`);
  assert(!capturedWarns[10].includes('replay skipped op[10]'),
    'the 11th skip must NOT warn individually after the throttle');

  console.log(`hlc-skew-replay OK: ${passed} passed, ${failed} failed — clamp ingest materializes, ` +
    'default (and 0-sentinel) rejects the aged op live, batch survives with applied holding indices');
  process.exit(failed > 0 ? 1 : 0);
})().catch((caughtError) => {
  console.error(caughtError);
  process.exit(1);
});