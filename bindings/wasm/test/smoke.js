'use strict';

const { Node, KeyPair, Operation } = require('..');

(async () => {
  const node = await Node.create('admin', { ordering: 'hlc' });
  const key = await KeyPair.generate();
  // register_user rejects privileged attribute names (audit R7-08), so the
  // role must be granted via the admin grantRole path after registration.
  node.registerUser('alice', key.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'admin');

  node.addCounter('views');
  node.addPNCounter('likes');
  node.addORSet('subscribers');
  node.addRegister('vote_alice', 0);
  node.setPolicy('view', 'AND role:member adult');
  node.setPolicy('like', 'AND role:member adult');
  // The engine no longer silently no-ops handler-less, resource-less custom
  // ops, so the view op needs a registered handler to execute.
  node.registerHandlerJs('view', (state) => { return 0; });

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

  // registerUser must reject a public key that is not 33 bytes of hex.
  let invalidKeyRejected = false;
  try {
    node.registerUser('mallory', 'not-hex', 'adult');
  } catch (registerError) {
    invalidKeyRejected = registerError.message.includes('Invalid public key hex');
  }
  if (!invalidKeyRejected) {
    throw new Error('registerUser must reject an invalid public key hex');
  }

  // registerHandlerJs routes through the WASM function table; re-registering
  // an op type must replace the previous handler (not stack table slots), and
  // unregisterHandler must release the entry.
  node.addCounter('pings');
  node.setPolicy('ping', 'role:member');
  node.registerHandlerJs('ping', (state) => {
    state.incrementCounter('views', 1, 'handler-v1');
    return 0;
  });
  const pingOp = await Operation.create('ping');
  pingOp.signerId = 'alice';
  node.sign(pingOp, key.privateKeyHex());
  node.execute(pingOp);
  if (node.getCounter('views') !== 2) {
    throw new Error(`Expected views=2 after ping handler, got ${node.getCounter('views')}`);
  }

  node.registerHandlerJs('ping', (state) => {
    state.incrementCounter('pings', 1, 'handler-v2');
    return 0;
  });
  const pingOp2 = await Operation.create('ping');
  pingOp2.signerId = 'alice';
  node.sign(pingOp2, key.privateKeyHex());
  node.execute(pingOp2);
  if (node.getCounter('pings') !== 1) {
    throw new Error(`Expected pings=1 after handler replacement, got ${node.getCounter('pings')}`);
  }

  node.unregisterHandler('ping');
  // After unregister the ping op has no handler anymore. The engine no
  // longer silently no-ops handler-less, resource-less custom ops — it must
  // reject the execution with resource_not_found instead.
  const pingOp3 = await Operation.create('ping');
  pingOp3.signerId = 'alice';
  node.sign(pingOp3, key.privateKeyHex());
  let unregisteredPingRejected = false;
  try {
    node.execute(pingOp3);
  } catch (unregisteredPingError) {
    unregisteredPingRejected =
      unregisteredPingError.message.includes('resource_not_found');
  }
  if (!unregisteredPingRejected) {
    throw new Error('Executing an unregistered handler op must fail loudly');
  }
  if (node.getCounter('pings') !== 1) {
    throw new Error(`Expected pings=1 after unregister, got ${node.getCounter('pings')}`);
  }
  pingOp.destroy();
  pingOp2.destroy();
  pingOp3.destroy();

  if (!attrs.includes('role:member') || !attrs.includes('adult')) {
    throw new Error(`Expected alice attributes role:member and adult, got ${attrs}`);
  }

  // ABE encrypt container layout: u16 policy byte length, UTF-8 policy bytes,
  // u32 ciphertext length, ciphertext. The policy length must be counted in
  // UTF-8 bytes, not UTF-16 code units, so multi-byte policies round-trip.
  const policy = '属性テスト';
  const container = node.encrypt('秘密のデータ', policy);
  const containerView = new DataView(container.buffer);
  const policyByteLength = containerView.getUint16(0, true);
  const expectedPolicyBytes = Buffer.byteLength(policy, 'utf8');
  if (policyByteLength !== expectedPolicyBytes) {
    throw new Error(`Policy length prefix ${policyByteLength} != UTF-8 byte length ${expectedPolicyBytes}`);
  }
  const decodedPolicy = new TextDecoder().decode(
    container.subarray(2, 2 + policyByteLength));
  if (decodedPolicy !== policy) {
    throw new Error(`Policy roundtrip mismatch: ${decodedPolicy}`);
  }
  const ciphertextLength = containerView.getUint32(2 + policyByteLength, true);
  if (2 + policyByteLength + 4 + ciphertextLength !== container.length) {
    throw new Error(`Container length ${container.length} does not match header ${2 + policyByteLength + 4 + ciphertextLength}`);
  }

  console.log('smoke OK: views=' + views + ', attrs=' + attrs +
              ', policyBytes=' + policyByteLength);

  node.destroy();
  key.destroy();
})().catch(e => { console.error(e); process.exit(1); });
