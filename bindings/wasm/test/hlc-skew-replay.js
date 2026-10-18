'use strict';

// HLC bounded-skew replay fix e2e (brief 2026-10-17): replay of a
// beyond-window op fails closed on the default config and CLAMPS through on
// the replay-opt-in config. 6.1s wall-clock age crosses the 5s default
// window (the 15s scenario is covered natively with forged stamps). Also
// pins: maxSkewMs 0 is the C-default sentinel (not accept-all), prototype-
// chain option names throw, and replayOps' `applied` carries INDICES.
// Also pins the audit M-7 Operation guards (a destroyed or foreign-module op
// refuses execute/sign/replayOp with a TypeError, before any wasm deref) and
// the replayOps warn throttle (first 10 skips warn individually, then ONE
// summary line — while `skipped` still carries every entry).

const { Node, Operation, KeyPair } = require('..');
const createBindings = require('../bindings-core');

const assertEquals = (actual, expected, label) => {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
};

(async () => {
  // --- Validation first (cheap): bad skew options reject on the public
  // surface, before any expensive module load beyond the first create.
  const mustThrowWith = async (invoke, fragment, label) => {
    let caught = null;
    try { await invoke(); } catch (caughtError) { caught = caughtError; }
    if (!caught) throw new Error(`${label}: expected a throw`);
    if (!caught.message.includes(fragment)) {
      throw new Error(`${label}: expected message containing "${fragment}", got "${caught.message}"`);
    }
    return caught;
  };
  // Node.create is async — its parseSkewOptions throws surface as promise
  // rejections, so the helper awaits before asserting.
  await mustThrowWith(() => Node.create('bad', { skew: { maxSkewMs: 2 ** 53 } }),
    'skew.maxSkewMs must be a non-negative safe integer', 'unsafe maxSkewMs');
  await mustThrowWith(() => Node.create('bad', { skew: { replayPolicy: 'bogus' } }),
    "skew.replayPolicy must be 'reject' or 'clamp'", 'unknown replayPolicy');
  await mustThrowWith(() => Node.create('bad', { skew: { strategy: 'bogus' } }),
    "skew.strategy must be one of 'naive'|'bounded'|'quorum'|'strict'|'trusted'", 'unknown strategy');
  await mustThrowWith(() => Node.create('bad', { skew: 'bogus' }),
    'skew must be an options object', 'non-object skew');
  // Prototype-chain pins: 'toString'/'valueOf' pass a naive `in` check and
  // would map a Function into the wasm i32 param (NaN→0 = HLC_STRATEGY_NAIVE,
  // silently disarming the skew defense) instead of throwing.
  await mustThrowWith(() => Node.create('bad', { skew: { strategy: 'toString' } }),
    "skew.strategy must be one of 'naive'|'bounded'|'quorum'|'strict'|'trusted'",
    'prototype-chain strategy');
  await mustThrowWith(() => Node.create('bad', { skew: { replayPolicy: 'valueOf' } }),
    "skew.replayPolicy must be 'reject' or 'clamp'", 'prototype-chain replayPolicy');

  const aliceKey = await KeyPair.generate();

  // Shared registration+policy setup any replayer needs (the log replays
  // ops; the user registry arrives with the snapshot in real deployments).
  // grantRole's signer is the node's own bootstrap admin id — it must match
  // the creating admin, not a global 'admin' name.
  const registerUsersOn = async (node) => {
    node.registerUser('alice', aliceKey.publicKeyHex(), '');
    node.grantRole('alice', 'role', 'admin', node.adminId);
    node.setPolicy('flip', 'role:admin');
  };

  // --- Author: sign an op NOW (its HLC stamp carries the author clock T).
  const author = await Node.create('author');
  await registerUsersOn(author);
  author.addRegister('flips', 0);
  author.registerHandlerJs(
      'flip', (state) => { state.setRegister('flips', state.getRegister('flips') + 1); return 0; });
  const op = await Operation.create('flip');
  op.signerId = 'alice';
  op.nodeId = 'author';
  author.sign(op, aliceKey.privateKeyHex());
  author.execute(op);
  assertEquals(author.getRegister('flips'), 1, 'author executed its own op');
  const opWire = op.serialize();
  op.destroy();

  // Second op, signed + serialized but NEVER executed anywhere: its clamp
  // replay materializes in the mixed batch below, proving `applied` holds
  // INDICES of ingested entries while the already-executed op stays skipped.
  // Its HLC was stamped at author-sign time (T0) — also >5s old at replay,
  // so the clamp path is exactly what lets it through.
  const secondOp = await Operation.create('flip');
  secondOp.signerId = 'alice';
  secondOp.nodeId = 'author';
  author.sign(secondOp, aliceKey.privateKeyHex());
  const secondOpWire = secondOp.serialize();
  secondOp.destroy();
  author.destroy();

  // --- Wait past the default 5s skew window.
  await new Promise((resolve) => setTimeout(resolve, 6100));

  // --- Fresh node, 0-SENTINEL skew config: maxSkewMs 0 maps to the C-side
  // default 5000ms window (NOT accept-all), so the same aged op still
  // fails closed on a live execute.
  const defaultReplayer = await Node.create(
      'default-replayer', { skew: { maxSkewMs: 0 } });
  await registerUsersOn(defaultReplayer);
  defaultReplayer.addRegister('flips', 0);
  defaultReplayer.registerHandlerJs(
      'flip', (state) => { state.setRegister('flips', state.getRegister('flips') + 1); return 0; });
  const defaultOp = await Operation.deserialize(opWire);
  let defaultThrew = null;
  try { defaultReplayer.execute(defaultOp); } catch (caughtError) {
    defaultThrew = caughtError.message;
  }
  if (!defaultThrew || !defaultThrew.includes('protocol_violation')) {
    throw new Error(`default live replay must throw protocol_violation, got "${defaultThrew}"`);
  }
  assertEquals(defaultReplayer.getRegister('flips'), 0, 'default replay did not mutate');

  // --- Fresh node, CLAMP replay policy: the op materializes.
  const clampReplayer = await Node.create(
      'clamp-replayer', { skew: { replayPolicy: 'clamp' } });
  await registerUsersOn(clampReplayer);
  clampReplayer.addRegister('flips', 0);
  clampReplayer.registerHandlerJs(
      'flip', (state) => { state.setRegister('flips', state.getRegister('flips') + 1); return 0; });
  await mustThrowWith(() => clampReplayer.replayOps('nonsense'),
    'replayOps: expected an array of Operations', 'non-array replayOps');

  const clampOp = await Operation.deserialize(opWire);
  const clampOutcome = clampReplayer.replayOp(clampOp);
  assertEquals(clampOutcome.status, 'applied', 'clamp replay ingested the historic op');
  assertEquals(clampReplayer.getRegister('flips'), 1, 'handler materialized through clamp replay');
  clampOp.destroy();

  // --- Re-ingest the same op: skipped, batch survives.
  const reOp = await Operation.deserialize(opWire);
  const reOutcome = clampReplayer.replayOp(reOp);
  assertEquals(reOutcome.status, 'skipped', 're-ingest is an idempotent skip');
  if (reOutcome.code !== 0x7002) {
    throw new Error(`re-ingest skip expected already_executed (0x7002), got 0x${reOutcome.code.toString(16)}`);
  }
  assertEquals(clampReplayer.getRegister('flips'), 1, 'skip did not re-run the handler');
  reOp.destroy();

  // --- Batch API: per-op failures never abort the batch.
  const batchOps = [];
  for (let entryIndex = 0; entryIndex < 2; entryIndex++) {
    batchOps.push(await Operation.deserialize(opWire));
  }
  const batch = clampReplayer.replayOps(batchOps);
  assertEquals(batch.applied.length, 0, 'both entries dedup as already-executed');
  assertEquals(batch.skipped.length, 2, 'both skips are reported');
  assertEquals(batch.skipped[0].code, 0x7002, 'skip entry carries the error code');

  // --- Mixed batch pin: index 0 is the already-executed op (skipped
  // 0x7002), index 1 is the never-executed second op (clamp-materializes).
  // `applied` must equal the INDICES array — not the op objects themselves.
  const mixedBatch = [
    await Operation.deserialize(opWire),
    await Operation.deserialize(secondOpWire),
  ];
  const mixed = clampReplayer.replayOps(mixedBatch);
  assertEquals(mixed.applied, [1], 'applied holds indices, not operations');
  assertEquals(mixed.skipped.length, 1, 'one skip in the mixed batch');
  assertEquals(mixed.skipped[0].index, 0, 'the executed op is the skipped entry');
  assertEquals(mixed.skipped[0].code, 0x7002, 'mixed-batch skip carries already_executed');
  assertEquals(clampReplayer.getRegister('flips'), 2, 'never-executed op materialized through clamp');

  // --- Audit M-7 guards: a DESTROYED op refuses execute/sign/replayOp with
  // a TypeError (NOT the C-side invalid_param that dereferenced anyway).
  const doomedOp = await Operation.deserialize(opWire);
  doomedOp.destroy();
  const executeGuardError = await mustThrowWith(() => clampReplayer.execute(doomedOp),
    'execute: expected an Operation from this module', 'destroyed-op execute');
  const signGuardError = await mustThrowWith(
    () => clampReplayer.sign(doomedOp, aliceKey.privateKeyHex()),
    'sign: expected an Operation from this module', 'destroyed-op sign');
  const replayGuardError = await mustThrowWith(() => clampReplayer.replayOp(doomedOp),
    'replayOp: expected an Operation from this module', 'destroyed-op replayOp');
  // The guards throw BEFORE touching wasm memory, so a destroyed op can
  // never reach the C entry (its `_ptr` is already dead).
  for (const thrownGuard of [executeGuardError, signGuardError, replayGuardError]) {
    if (!(thrownGuard instanceof TypeError)) {
      throw new Error(`destroyed-op guard must throw TypeError, got ${thrownGuard.constructor.name}`);
    }
  }

  // --- Audit M-7 guards: an op minted by a DIFFERENT module instance has a
  // foreign-heap `_ptr` — feeding it to execute/sign would be a
  // memory-confusion read of that instance's linear memory.
  const foreignModule = createBindings(
    () => require(require('path').join(__dirname, '..', 'crabs.js'))());
  {
    const foreignOp = await foreignModule.Operation.create('flip');
    await mustThrowWith(() => clampReplayer.execute(foreignOp),
      'execute: expected an Operation from this module', 'foreign-op execute');
    await mustThrowWith(() => clampReplayer.replayOp(foreignOp),
      'replayOp: expected an Operation from this module', 'foreign-op replayOp');
    foreignOp.destroy();
  }

  // --- Warn throttle: a 13-skip batch warns the first 10 individually, then
  // ONE summary line — with no console flood — while `skipped` still carries
  // ALL 13 entries and the register does not move (every skip is a
  // no-op already_executed dedup).
  const floodNode = await Node.create('flood-replayer', { skew: { replayPolicy: 'clamp' } });
  await registerUsersOn(floodNode);
  floodNode.addRegister('flips', 0);
  floodNode.registerHandlerJs(
      'flip', (state) => { state.setRegister('flips', state.getRegister('flips') + 1); return 0; });
  const floodOps = [];
  for (let floodIndex = 0; floodIndex < 13; floodIndex++) {
    floodOps.push(await Operation.deserialize(opWire));
  }
  // Seed the flood: the FIRST ingest of the historic op materializes through
  // clamp (flips -> 1); the 13-batch copies are then all already_executed
  // skips — exactly the warn flood the throttle must not surface.
  const floodSeed = await Operation.deserialize(opWire);
  assertEquals(floodNode.replayOp(floodSeed).status, 'applied',
    'flood-seed op materializes once on the fresh node');
  floodSeed.destroy();
  const capturedWarns = [];
  const realWarn = console.warn;
  console.warn = (...warnArgs) => capturedWarns.push(warnArgs.join(' '));
  let floodBatch = null;
  try {
    floodBatch = floodNode.replayOps(floodOps);
  } finally {
    console.warn = realWarn;
  }
  assertEquals(floodBatch.skipped.length, 13, 'every flood skip is still reported');
  assertEquals(floodNode.getRegister('flips'), 1, 'flood skips did not mutate');
  const individualWarns = capturedWarns.filter(
    (warnLine) => /^crabs-wasm: replay skipped op\[\d+\]: /.test(warnLine));
  const summaryWarns = capturedWarns.filter(
    (warnLine) => /^crabs-wasm: \.\.\.and \d+ more skipped \(total \d+\)$/.test(warnLine));
  assertEquals(individualWarns.length, 10, 'exactly the first 10 skips warn individually');
  assertEquals(summaryWarns.length, 1, 'exactly ONE summary warn follows');
  if (!summaryWarns[0].includes('and 3 more skipped (total 13)')) {
    throw new Error(`summary warn must name the tail and total, got "${summaryWarns[0]}"`);
  }

  floodNode.destroy();
  for (const floodOperation of floodOps) floodOperation.destroy();

  console.log('hlc-skew-replay OK: clamp ingest materializes, default (and 0-sentinel) reject, '
      + 'batch survives, applied holds indices, op guards refuse, warns throttled');
  defaultReplayer.destroy();
  clampReplayer.destroy();
  aliceKey.destroy();
  for (const batchOperation of batchOps) batchOperation.destroy();
  for (const mixedOperation of mixedBatch) mixedOperation.destroy();
  defaultOp.destroy();
})().catch(e => { console.error(e); process.exit(1); });
