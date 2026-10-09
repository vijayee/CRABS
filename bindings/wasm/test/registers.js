'use strict';

// Registers: integer-only contract guards (consumption finding 1).
// Registers carry an int64 in C; the JS wrapper must reject NaN, Infinity,
// fractional values, and numbers beyond ±Number.MAX_SAFE_INTEGER BEFORE the
// C conversion can silently truncate, and must accept BigInt and the
// ±MAX_SAFE_INTEGER boundaries verbatim.

const { Node } = require('..');

(async () => {
  const node = await Node.create('admin', { ordering: 'hlc' });
  node.addRegister('slot', 0);

  const INTEGER_ONLY_MESSAGE =
    'registers are integer-only; encode fractional values in register units (e.g. per-mille)';
  const SAFE_INTEGER_MESSAGE =
    'registers are integer-only; |value| exceeds Number.MAX_SAFE_INTEGER';

  const mustThrowWith = (invoke, fragment, label) => {
    let caught = null;
    try { invoke(); } catch (caughtError) { caught = caughtError; }
    if (!caught) throw new Error(`${label}: expected a throw`);
    if (!caught.message.includes(fragment)) {
      throw new Error(`${label}: expected message containing "${fragment}", got "${caught.message}"`);
    }
  };

  // Fractional numbers are rejected with the integer-only message.
  mustThrowWith(() => node.setRegister('slot', 1.5), INTEGER_ONLY_MESSAGE, 'fractional 1.5');
  mustThrowWith(() => node.setRegister('slot', -0.25), INTEGER_ONLY_MESSAGE, 'fractional -0.25');
  mustThrowWith(() => node.setRegister('slot', NaN), INTEGER_ONLY_MESSAGE, 'NaN');
  mustThrowWith(() => node.setRegister('slot', Infinity), INTEGER_ONLY_MESSAGE, '+Infinity');
  mustThrowWith(() => node.setRegister('slot', -Infinity), INTEGER_ONLY_MESSAGE, '-Infinity');

  // Non-number non-BigInt inputs are rejected with the integer-only message.
  mustThrowWith(() => node.setRegister('slot', '42'), 'registers are integer-only', 'string "42"');
  mustThrowWith(() => node.setRegister('slot', undefined), 'registers are integer-only', 'undefined');
  mustThrowWith(() => node.setRegister('slot', null), 'registers are integer-only', 'null');

  // |value| > Number.MAX_SAFE_INTEGER is rejected with the BigInt hint.
  mustThrowWith(() => node.setRegister('slot', Number.MAX_SAFE_INTEGER + 1),
    SAFE_INTEGER_MESSAGE, 'MAX_SAFE_INTEGER + 1');
  mustThrowWith(() => node.setRegister('slot', -(Number.MAX_SAFE_INTEGER + 1)),
    SAFE_INTEGER_MESSAGE, '-(MAX_SAFE_INTEGER + 1)');
  mustThrowWith(() => node.setRegister('slot', 2 ** 60),
    SAFE_INTEGER_MESSAGE, '2^60');

  // Boundaries pass through verbatim.
  node.setRegister('slot', Number.MAX_SAFE_INTEGER);
  if (node.getRegister('slot') !== Number.MAX_SAFE_INTEGER) {
    throw new Error(`+MAX_SAFE_INTEGER failed to round-trip (got ${node.getRegister('slot')})`);
  }
  node.setRegister('slot', -Number.MAX_SAFE_INTEGER);
  if (node.getRegister('slot') !== -Number.MAX_SAFE_INTEGER) {
    throw new Error(`-MAX_SAFE_INTEGER failed to round-trip (got ${node.getRegister('slot')})`);
  }

  // BigInt passes through (and reaches past safe-integer number range).
  node.setRegister('slot', 42n);
  if (node.getRegister('slot') !== 42) {
    throw new Error('BigInt 42n did not set the register');
  }
  // Note: getRegister returns a number; values above MAX_SAFE_INTEGER come
  // back through the int64 -> double conversion. Setting them must still be
  // accepted by the wrapper.
  node.setRegister('slot', BigInt(2) ** 60n);

  // Ordinary integers still set.
  node.setRegister('slot', -7, 'alice');
  if (node.getRegister('slot') !== -7) {
    throw new Error('integer -7 did not set the register');
  }

  // The handler-context setRegister (registerHandlerJs) applies the same
  // guard before crossing into C. A registered member user signs the op;
  // the wasm Node never exposes its bootstrap admin private key.
  const { Operation, KeyPair } = require('..');
  const workerKey = await KeyPair.generate();
  await node.registerUser('worker', workerKey.publicKeyHex(), '');
  node.grantRole('worker', 'role', 'member', 'admin');
  node.setPolicy('poke', 'role:member');
  node.registerHandlerJs('poke', (state) => {
    let fractionalRejected = false;
    try { state.setRegister('slot', 0.5); } catch (handlerError) {
      fractionalRejected = handlerError.message.includes(INTEGER_ONLY_MESSAGE);
    }
    if (!fractionalRejected) {
      throw new Error('handler setRegister must reject fractional values');
    }
    state.setRegister('slot', 99n);
    return 0;
  });
  const pokeOp = await Operation.create('poke');
  pokeOp.signerId = 'worker';
  pokeOp.nodeId = 'worker';
  node.sign(pokeOp, workerKey.privateKeyHex());
  node.execute(pokeOp);
  if (node.getRegister('slot') !== 99) {
    throw new Error(`handler setRegister(99n) did not land (got ${node.getRegister('slot')})`);
  }
  pokeOp.destroy();
  workerKey.destroy();

  console.log('registers OK: integer-only guard enforced on direct + handler paths');
  node.destroy();
})().catch(e => { console.error(e); process.exit(1); });
