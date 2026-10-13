'use strict';
// Recipe 13 — a personal ledger no one can override (crabs-wasm).
//
// Same per-user sovereign ledgers as the node section — plus what the wasm
// binding's custom handlers make demoable: the entry op MUTATES the
// member's ledger (handler-driven balance increment), so the hash chain
// covers real content, not just the fact of a write. The writer's ledger is
// one named item with one named writer; nobody else, not even the machine
// admin, can write it; forks are refused at the gate and actionable through
// the equivocation report. Mirrors bindings/wasm/test/write-domains.js.

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../../../bindings/wasm');

async function main() {
  const node = await Node.create('machine-1');

  const aliceKey = await KeyPair.generate();
  node.registerUser('alice', aliceKey.publicKeyHex(), '');
  node.grantRole('alice', 'role', 'member', 'machine-1');
  const bobKey = await KeyPair.generate();
  node.registerUser('bob', bobKey.publicKeyHex(), '');
  node.grantRole('bob', 'role', 'member', 'machine-1');

  // ---- The mint: one sovereign ledger per member ---------------------------
  node.defineItem('ledger-alice', 'register', 'lww_reg',
    { domain: 'sovereign', writer: 'alice' });
  node.defineItem('ledger-bob', 'register', 'lww_reg',
    { domain: 'sovereign', writer: 'bob' });
  node.setPolicy('__report_equivocation__', 'role:admin');

  const ZERO_DIGEST = '0'.repeat(64);
  const FORK_DIGEST = 'f'.repeat(64);   // a digest that is NOT the live head

  // The entry's content mutation: registered handlers (a wasm-only surface,
  // api-map §8) apply entries as balance movements on the member's register.
  // The handler sees the op's signer/payload but NOT its resources
  // (HandlerOperation carries no resource list), so each ledger rides its
  // own op type — 'ledger-alice' entries through 'entry-alice', 'ledger-bob'
  // through 'entry-bob'. The DOMAIN_CHECK has verified writer + signed
  // prefix for the resource before the handler runs; the handler reads the
  // balance and applies the (possibly negative) entry the payload names.
  const ledgerForEntryType = { 'entry-alice': 'ledger-alice',
                               'entry-bob': 'ledger-bob' };
  for (const [entryType, ledgerName] of Object.entries(ledgerForEntryType)) {
    node.registerHandlerJs(entryType, (handlerState, op) => {
      const amount = Number.parseInt(
        op.payload === undefined || op.payload === '' ? '0' : op.payload, 10);
      handlerState.setRegister(ledgerName,
                               handlerState.getRegister(ledgerName) +
                               (Number.isFinite(amount) ? amount : 0));
      return 0;
    });
  }
  node.setPolicy('entry-alice', 'role:member');
  node.setPolicy('entry-bob', 'role:member');

  function depositAs(signerId, signerKey, ledgerName, seq, digestHex, amount) {
    return (async () => {
      const entryOp =
        await Operation.create('entry-' + ledgerName.slice('ledger-'.length));
      entryOp.signerId = signerId;
      entryOp.addResource(ledgerName);
      entryOp.setSovereignPrefix(0, seq, digestHex);
      if (amount !== undefined) {
        // The wasm handler bridge exposes the op payload as a STRING only
        // when it is NUL-terminated (crabs_wasm_handler_op_get_payload_str,
        // src/Util/wasm_helpers.c:1195-1201) — terminate the entry amount.
        const amountBytes = new TextEncoder().encode(amount);
        const terminated = new Uint8Array(amountBytes.length + 1);
        terminated.set(amountBytes);
        entryOp.payload = terminated;
      }
      node.sign(entryOp, signerKey);
      return entryOp;
    })();
  }

  const firstDeposit = await depositAs('alice', aliceKey, 'ledger-alice', 0,
                                       ZERO_DIGEST, '120');
  node.execute(firstDeposit);
  firstDeposit.destroy();
  assert(node.getRegister('ledger-alice') === 120,
    "the handler's movement should land: balance = 120");

  // The head advanced and now covers real content (the digest is recomputed
  // over the item's post-op content-only form — a no-op op would not move
  // it over a counter that changed by 120).
  let head = node.itemChainHead('ledger-alice');
  assert(head.seq === 1 || head.seq === 1n, 'head should advance to 1');
  assert(/^[0-9a-f]{64}$/.test(head.digestHex), 'head digest is full width');

  // Entry two: claim the live head, chain advances, balance grows.
  const secondDeposit = await depositAs('alice', aliceKey, 'ledger-alice',
                                        head.seq, head.digestHex, '-80');
  node.execute(secondDeposit);
  secondDeposit.destroy();
  assert(node.getRegister('ledger-alice') === 40, 'balance = 120 - 80');
  assert(node.itemChainHead('ledger-alice').seq === 2n ||
         node.itemChainHead('ledger-alice').seq === 2, 'head at 2');

  // Bob's ledger is bob's — separate writer, separate chain, separate balance.
  const bobDeposit = await depositAs('bob', bobKey, 'ledger-bob', 0,
                                     ZERO_DIGEST, '5');
  node.execute(bobDeposit);
  bobDeposit.destroy();
  assert(node.getRegister('ledger-bob') === 5, "bob's balance");
  assert(node.itemChainHead('ledger-bob').seq === 1n ||
         node.itemChainHead('ledger-bob').seq === 1, "bob's chain");

  // ---- Nobody else — including the machine's own admin — can write it -----
  const adminKey = await KeyPair.generate();
  node.registerUser('admin', adminKey.publicKeyHex(), '');
  node.grantRole('admin', 'role', 'member', 'machine-1');
  const adminOp = await depositAs('admin', adminKey, 'ledger-alice', 2,
                                  node.itemChainHead('ledger-alice').digestHex);
  assert.throws(() => node.execute(adminOp), /not_item_writer/,
    "the admin's op on alice's ledger must be refused");
  adminOp.destroy();

  // bob→alice: policy-authorized, item-refused.
  const bobOp = await depositAs('bob', bobKey, 'ledger-alice', 2,
                                node.itemChainHead('ledger-alice').digestHex);
  assert.throws(() => node.execute(bobOp), /not_item_writer/,
    "bob's op on alice's ledger must be refused");
  bobOp.destroy();
  assert(node.getRegister('ledger-alice') === 40, 'a refused write moves none');

  // ---- The chain refuses stale and forked claims --------------------------
  const replayOp = await depositAs('alice', aliceKey, 'ledger-alice', 0,
                                   ZERO_DIGEST);
  assert.throws(() => node.execute(replayOp), /seq_mismatch/,
    'a replayed prefix must be refused');
  replayOp.destroy();

  const forkOp = await depositAs('alice', aliceKey, 'ledger-alice', 2,
                                 FORK_DIGEST);
  assert.throws(() => node.execute(forkOp), /fork_detected/,
    'a same-seq different-digest claim must be refused');
  forkOp.destroy();

  // ---- Accountability: a REAL fork across replicas is actionable ----------
  // An equivocation needs two DISTINCT signed claims to the same head. The
  // fourth deposit claims the head (seq 2) and executes; a second alice-
  // signed claim to that same head exists on another replica — minted here,
  // never executed, wire provably distinct.
  const headNow = node.itemChainHead('ledger-alice');
  const executedForkVictim = await depositAs('alice', aliceKey,
                                             'ledger-alice', headNow.seq,
                                             headNow.digestHex, '-10');
  node.execute(executedForkVictim);
  const executedWire = executedForkVictim.serialize();
  executedForkVictim.destroy();
  assert(node.itemChainHead('ledger-alice').seq === 3n ||
         node.itemChainHead('ledger-alice').seq === 3, 'head at 3');

  const forkVictim = await depositAs('alice', aliceKey, 'ledger-alice',
                                     headNow.seq, headNow.digestHex, '-10');
  const forkWire = forkVictim.serialize();
  forkVictim.destroy();
  assert.notDeepStrictEqual(Buffer.from(executedWire), Buffer.from(forkWire),
    'fork evidence must be two distinct serialized ops');

  // The report verifies the pair and quarantines alice on HER ledger; her
  // next write (a claim to the new head) is refused.
  node.reportEquivocation('ledger-alice', executedWire, forkWire);
  const postQuarantine = await depositAs('alice', aliceKey, 'ledger-alice', 3,
                                         node.itemChainHead('ledger-alice')
                                           .digestHex);
  assert.throws(() => node.execute(postQuarantine), /quarantined/,
    'a quarantined writer op should throw quarantined');
  postQuarantine.destroy();

  // Typed failure paths: same-op-twice, foreign target, unknown item, and a
  // re-report of the same conviction.
  assert.throws(() => node.reportEquivocation('ledger-alice', forkWire,
                                              forkWire),
    /invalid_param/, 'same-op-twice evidence is invalid');
  assert.throws(() => node.reportEquivocation('ledger-bob', forkWire,
                                              executedWire),
    /invalid_param/, 'a report naming the other item is off-target');
  assert.throws(() => node.reportEquivocation('ghost', forkWire, executedWire),
    /resource_not_found/, 'an unknown item is resource_not_found');

  node.destroy();
  console.log('sovereign-ledger wasm OK: real balances chained, cross-writer' +
    ' refused, fork quarantined');
}

main().catch((failure) => {
  console.error('sovereign-ledger wasm FAILED:', failure);
  process.exit(1);
});