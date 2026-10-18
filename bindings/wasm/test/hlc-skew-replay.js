'use strict';

// HLC bounded-skew replay fix e2e (brief 2026-10-17): replay of a
// beyond-window op fails closed on the default config and CLAMPS through on
// the replay-opt-in config. 6.1s wall-clock age crosses the 5s default
// window (the 15s scenario is covered natively with forged stamps).

const { Node, Operation, KeyPair } = require('..');

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
  author.destroy();

  // --- Wait past the default 5s skew window.
  await new Promise((resolve) => setTimeout(resolve, 6100));

  // --- Fresh node, DEFAULT skew config: live execute still fails closed.
  const defaultReplayer = await Node.create('default-replayer');
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
  const clampOutcome = clampReplayer.replayOp(await Operation.deserialize(opWire));
  assertEquals(clampOutcome.status, 'applied', 'clamp replay ingested the historic op');
  assertEquals(clampReplayer.getRegister('flips'), 1, 'handler materialized through clamp replay');

  // --- Re-ingest the same op: skipped, batch survives.
  const reOutcome = clampReplayer.replayOp(await Operation.deserialize(opWire));
  assertEquals(reOutcome.status, 'skipped', 're-ingest is an idempotent skip');
  if (reOutcome.code !== 0x7002) {
    throw new Error(`re-ingest skip expected already_executed (0x7002), got 0x${reOutcome.code.toString(16)}`);
  }
  assertEquals(clampReplayer.getRegister('flips'), 1, 'skip did not re-run the handler');

  // --- Batch API: per-op failures never abort the batch.
  const batchOps = [];
  for (let entryIndex = 0; entryIndex < 2; entryIndex++) {
    batchOps.push(await Operation.deserialize(opWire));
  }
  const batch = clampReplayer.replayOps(batchOps);
  assertEquals(batch.applied.length, 0, 'both entries dedup as already-executed');
  assertEquals(batch.skipped.length, 2, 'both skips are reported');
  assertEquals(batch.skipped[0].code, 0x7002, 'skip entry carries the error code');

  console.log('hlc-skew-replay OK: clamp ingest materializes, default rejects, batch survives');
  defaultReplayer.destroy();
  clampReplayer.destroy();
  aliceKey.destroy();
  for (const batchOperation of batchOps) batchOperation.destroy();
  defaultOp.destroy();
})().catch(e => { console.error(e); process.exit(1); });