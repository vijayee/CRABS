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
  process.exit(0);
}

main().catch((err) => { console.error(err); process.exit(1); });