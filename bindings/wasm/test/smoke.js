'use strict';

const { Node, KeyPair, Operation } = require('..');

(async () => {
  const node = await Node.create('admin', { ordering: 'hlc' });
  const key = await KeyPair.generate();
  node.registerUser('alice', key.publicKeyHex(), 'role:member|adult');

  node.addCounter('views');
  node.addPNCounter('likes');
  node.addORSet('subscribers');
  node.addRegister('vote_alice', 0);
  node.setPolicy('view', 'AND role:member adult');
  node.setPolicy('like', 'AND role:member adult');

  const op = await Operation.create('view');
  op.signerId = 'alice';
  op.nodeId = 'alice';
  node.sign(op, key.privateKeyHex());
  node.execute(op);
  node.incrementCounter('views', 1, 'alice');

  // Round-trip serialization should preserve the operation bytes.
  const serialized = op.serialize();
  op.destroy();
  const op2 = await Operation.deserialize(serialized);
  if (op2.type !== 'view' || op2.signerId !== 'alice') {
    throw new Error('Deserialized operation does not match');
  }
  op2.destroy();

  const views = node.getCounter('views');
  const user = node.getUser('alice');
  const attrs = user ? user.attributes.map(a => a.value).join(',') : 'none';

  if (views !== 1) {
    throw new Error(`Expected views=1, got ${views}`);
  }
  if (!attrs.includes('role:member') || !attrs.includes('adult')) {
    throw new Error(`Expected alice attributes role:member and adult, got ${attrs}`);
  }

  console.log('smoke OK: views=' + views + ', attrs=' + attrs);

  node.destroy();
  key.destroy();
})().catch(e => { console.error(e); process.exit(1); });
