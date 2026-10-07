//
// change-events.js — smoke test for node.on('change') push events.
//
'use strict';

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../dev.js');

async function main() {
  const node = await Node.create('admin', { ordering: 'hlc' });
  const key = await KeyPair.generate();

  // The listener is registered before any mutation so attribute-kind events
  // (register_user / grant_role) are observed alongside op-kind events.
  const events = [];
  node.on('change', (event) => events.push(event));

  node.registerUser('alice', key.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'admin');
  node.addCounter('views');
  node.setPolicy('view', 'AND role:member adult');
  // The engine no longer silently no-ops handler-less, resource-less custom
  // ops, so the view op needs a registered handler to execute (the handler
  // fires the same op change event the old no-op path did).
  node.registerHandlerJs('view', (state) => { return 0; });

  const op = await Operation.create('view');
  op.signerId = 'alice';
  op.nodeId = 'alice';
  node.sign(op, key.privateKeyHex());
  node.execute(op);
  node.incrementCounter('views', 1, 'alice');

  // Pinned exactly: registerUser and grantRole each fire one attribute event,
  // the executed view op fires one op event; the counter increment and policy
  // set emit no change events, so the sequence yields exactly these three.
  const expectedEvents = [
    { kind: 'attribute', type: 'register_user', target: 'alice' },
    { kind: 'attribute', type: 'grant_role', target: 'alice' },
    { kind: 'op', type: 'view', target: '' },
  ];
  assert.strictEqual(events.length, expectedEvents.length,
                     `expected exactly ${expectedEvents.length} change events, got ${events.length}`);
  expectedEvents.forEach((expected, index) => {
    assert.strictEqual(events[index].kind, expected.kind,
                       `event ${index} kind mismatch`);
    assert.strictEqual(events[index].type, expected.type,
                       `event ${index} type mismatch`);
    assert.strictEqual(events[index].target, expected.target,
                       `event ${index} target mismatch`);
  });
  assert.ok(events.every((event) => event.node === 'admin'),
            'events must carry the node id');

  // off must stop delivery; grant_role fires an attribute event on every call,
  // so a still-registered listener would observe it.
  let mustNotFireFired = false;
  const mustNotFire = () => { mustNotFireFired = true; };
  node.on('change', mustNotFire);
  node.off('change', mustNotFire);
  node.grantRole('alice', 'role', 'member', 'admin');
  assert.strictEqual(mustNotFireFired, false, 'off must stop delivery');

  node.destroy();
  key.destroy();
  console.log('change-events smoke OK: ' + events.length + ' events');

  await runProdCheck();
  process.exit(0);
}

// The dev checks above run on crabs.dev.js, which has devtools compiled in;
// change events are core (not devtools-gated), so the production build must
// push them too. Force a fresh module load and repeat one op against the prod
// artifact (index.js -> crabs.js, factory createCRABSModule).
async function runProdCheck() {
  try {
    delete require.cache[require.resolve('../dev.js')];
    for (const cachePath of Object.keys(require.cache)) {
      if (cachePath.endsWith('crabs.dev.js')) delete require.cache[cachePath];
    }

    const { Node: ProdNode, KeyPair: ProdKeyPair, Operation: ProdOperation } =
      require('..');

    const prodNode = await ProdNode.create('admin', { ordering: 'hlc' });
    const prodKey = await ProdKeyPair.generate();
    const prodEvents = [];
    prodNode.on('change', (event) => prodEvents.push(event));

    prodNode.registerUser('alice', prodKey.publicKeyHex(), 'adult');
    prodNode.grantRole('alice', 'role', 'member', 'admin');
    prodNode.setPolicy('view', 'AND role:member adult');
    // Same engine contract as the dev run: handler-less resource-less custom
    // ops fail, so register the handler ahead of the executed op.
    prodNode.registerHandlerJs('view', (state) => { return 0; });
    const prodOp = await ProdOperation.create('view');
    prodOp.signerId = 'alice';
    prodOp.nodeId = 'alice';
    prodNode.sign(prodOp, prodKey.privateKeyHex());
    prodNode.execute(prodOp);

    const opEvents = prodEvents.filter((event) => event.kind === 'op');
    assert.strictEqual(opEvents.length, 1,
                       `prod build must push one op event, got ${opEvents.length}`);
    assert.strictEqual(opEvents[0].type, 'view',
                       'prod build op event type mismatch');
    assert.strictEqual(opEvents[0].node, 'admin',
                       'prod build op event must carry the node id');

    prodNode.destroy();
    prodKey.destroy();
    console.log('change-events prod OK: ' + prodEvents.length + ' events');
  } catch (prodError) {
    throw new Error('prod-build change events failed: ' + prodError.message);
  }
}

main().catch((err) => { console.error(err); process.exit(1); });