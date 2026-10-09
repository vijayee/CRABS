//
// write-domains-parity.mjs — cross-binding parity smoke (write-domains v1,
// spec §Testing "Cross-binding"). The SAME sovereign sequence runs through
// the N-API binding (arg 'node') and the WASM dev binding (arg 'wasm'):
//   defineItem sovereign → writer op accepted via setSovereignPrefix →
//   non-writer op rejected (not_item_writer) → fork evidence reported →
//   writer quarantined.
// Every step records its outcome into a trace; the two runs must produce
// byte-identical traces.
//
// Usage:
//   node bindings/write-domains-parity.mjs node  > /tmp/parity-node.txt
//   node bindings/write-domains-parity.mjs wasm  > /tmp/parity-wasm.txt
//   diff /tmp/parity-node.txt /tmp/parity-wasm.txt
//

import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const side = process.argv[2];
if (side !== 'node' && side !== 'wasm') {
  console.error('usage: node write-domains-parity.mjs <node|wasm>');
  process.exit(1);
}

const require_ = createRequire(import.meta.url);
const binding = side === 'node'
  ? require_(path.join(scriptDir, 'node'))
  : require_(path.join(scriptDir, 'wasm', 'dev.js'));

const trace = [];
function record(step, outcome) {
  // Outcomes must be side-invariant: typed error names, counts, booleans —
  // never addresses, timestamps, or signature bytes.
  trace.push(`${step}: ${outcome}`);
}
async function outcomeOf(step, thunk) {
  try {
    const value = await thunk();
    record(step, value === undefined ? 'ok' : String(value));
  } catch (failure) {
    const message = failure && failure.message ? failure.message : String(failure);
    // Keep the typed tail ("bump: not_item_writer" -> "not_item_writer").
    record(step, 'threw ' + message.split(': ').pop());
  }
}

async function main() {
  const ZERO_DIGEST = '0'.repeat(64);

  let nodeRoot, aliceKey, malloryKey;
  if (side === 'node') {
    nodeRoot = new binding.Node('parity-admin');
    aliceKey = binding.KeyPair.generate();
    malloryKey = binding.KeyPair.generate();
  } else {
    nodeRoot = await binding.Node.create('parity-admin');
    aliceKey = await binding.KeyPair.generate();
    malloryKey = await binding.KeyPair.generate();
  }
  nodeRoot.registerUser('alice', aliceKey.publicKeyHex(), '');
  nodeRoot.grantRole('alice', 'role', 'member', 'parity-admin');
  nodeRoot.registerUser('mallory', malloryKey.publicKeyHex(), '');
  nodeRoot.grantRole('mallory', 'role', 'member', 'parity-admin');

  await outcomeOf('define sovereign item', () => nodeRoot.defineItem(
    'score', 'counter', 'g_counter', { domain: 'sovereign', writer: 'alice' }));
  await outcomeOf('define free item (adder path)', () =>
    nodeRoot.addCounter('free-counter'));
  await outcomeOf('policy bump', () => nodeRoot.setPolicy('bump', 'role:member'));

  async function stagedOp(signer, seq, digest) {
    const op = side === 'node'
      ? new binding.Operation('bump')
      : await binding.Operation.create('bump');
    op.signerId = signer;
    op.addResource('score');
    op.setSovereignPrefix(0, seq, digest);
    nodeRoot.sign(op, signer === 'alice' ? aliceKey : malloryKey);
    return op;
  }

  const opA = await stagedOp('alice', 0, ZERO_DIGEST);
  const opAWire = opA.serialize();
  await outcomeOf('writer first op', () => nodeRoot.execute(opA));

  // The writer's second op must claim the live chain head; itemChainHead is
  // the binding-side read for it. The trace records side-invariant facts
  // only (seq number, digest shape) — the digest itself must be identical
  // across sides but asserting that here would double as the diff.
  await outcomeOf('head after first op', () => {
    const head = nodeRoot.itemChainHead('score');
    return `seq=${head.seq} digest=${/^[0-9a-f]{64}$/.test(head.digestHex) ? 'hex64' : 'bad'}`
      + ` nonzero=${head.digestHex !== ZERO_DIGEST}`;
  });
  const head = nodeRoot.itemChainHead('score');
  const opSecond = await stagedOp('alice', head.seq, head.digestHex);
  await outcomeOf('writer second op (head-claimed)', () => nodeRoot.execute(opSecond));
  await outcomeOf('head after second op', () =>
    `seq=${nodeRoot.itemChainHead('score').seq}`);
  await outcomeOf('head of unknown item', () => nodeRoot.itemChainHead('ghost'));

  const rogue = await stagedOp('mallory', 1, ZERO_DIGEST);
  await outcomeOf('non-writer op', () => nodeRoot.execute(rogue));

  // The fork: a second alice-signed claim to the same chain head that never
  // executed here (fresh random uuid keeps the wire bytes distinct).
  const opB = await stagedOp('alice', 0, ZERO_DIGEST);
  const opBWire = opB.serialize();

  await outcomeOf('report policy', () =>
    nodeRoot.setPolicy('__report_equivocation__', 'role:admin'));
  await outcomeOf('report genuine fork', () =>
    nodeRoot.reportEquivocation('score', opAWire, opBWire));

  const quarantined = await stagedOp('alice', 1, ZERO_DIGEST);
  await outcomeOf('quarantined writer op', () => nodeRoot.execute(quarantined));

  await outcomeOf('same-op-twice report', () =>
    nodeRoot.reportEquivocation('score', opAWire, opAWire));
  await outcomeOf('report vs free-merge item', () =>
    nodeRoot.reportEquivocation('free-counter', opAWire, opBWire));
  await outcomeOf('report vs unknown item', () =>
    nodeRoot.reportEquivocation('ghost', opAWire, opBWire));
  await outcomeOf('duplicate re-report (swapped)', () =>
    nodeRoot.reportEquivocation('score', opBWire, opAWire));

  process.stdout.write(trace.join('\n') + '\n');
}

main().catch((failure) => {
  console.error(`parity smoke FAILED (${side}):`, failure);
  process.exit(1);
});
