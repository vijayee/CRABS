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

  assert.ok(events.length >= 2, 'expected change events from mutations');
  assert.ok(events.some((event) => event.kind === 'op'),
            'expected at least one op-kind event');
  assert.ok(events.some((event) => event.kind === 'attribute'),
            'attribute mutations (registerUser/grantRole) must fire events');
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