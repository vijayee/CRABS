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
// pins: bad skew options throw on the public surface, and re-ingesting an
// executed op is a typed already_executed (0x7002) skip that does not
// re-run the mutation.
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

  const aliceKey = KeyPair.generate();

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

  // --- Wait past the default 5s skew window (the N-API HLC stamps the WALL
  // clock at sign, same timing semantics as the wasm binding).
  await new Promise((resolve) => setTimeout(resolve, 6100));

  // --- Fresh default node (reject policy): live execute of the aged op
  // must fail closed with protocol_violation and mutate nothing.
  const defaultReplayer = setupNode('default-replayer', { ordering: 'hlc' });
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
  assert(typeof reOutcome.message === 'string' &&
         reOutcome.message.includes('already_executed'),
    `re-ingest skip must name the error, got "${reOutcome.message}"`);
  assert(clampReplayer.setContains('proposal-42_voters', 'alice') === true,
    'the skip must not unwind the materialized membership');

  console.log(`hlc-skew-replay OK: ${passed} passed, ${failed} failed — clamp ingest materializes, ` +
    'default rejects the aged op live, skip is typed already_executed');
  process.exit(failed > 0 ? 1 : 0);
})().catch((caughtError) => {
  console.error(caughtError);
  process.exit(1);
});