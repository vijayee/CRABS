//
// demo.js — two in-browser CRABS nodes with devtools panels attached.
//
// Each node registers JS handlers for custom op types ('view', 'like',
// 'dislike', 'subscribe', 'flag'); firing one of those ops goes through
// state_machine_execute, so the devtools timeline, transitions, and CRDT
// values all update. A second browser tab acts as a peer: fired ops are
// relayed as serialized signed bytes over BroadcastChannel and re-executed.
//
// Identity layout:
//   - Each node bootstraps a literal 'admin' user whose private key never
//     leaves the WASM heap, so it cannot sign demo ops (and so the
//     createTrigger/evaluateTriggers admin ops verify — see setupNode).
//   - The demo actor (alice/bob) is registered as a regular user with a
//     fixed demo keypair and granted role:member via the admin grantRole
//     path (register_user rejects privileged attribute names, audit R7-08).
//   - The keypairs are fixed so a second tab registers the same public keys
//     and relayed operations still verify.
//

'use strict';

const CHANNEL_NAME = 'crabs-devtools-demo';

// Devtools controllers, populated in main(); refreshPanels() re-renders them
// after mutations that happen outside state_machine_execute (execute already
// auto-refreshes the panel of the node it ran on).
let panelControllers = [];

function refreshPanels() {
  for (const { controller } of panelControllers) controller.refresh();
}

// Fixed demo signing keys (secp256r1 scalars, generated once out-of-band).
const DEMO_PRIVATE_KEYS = {
  alice: '0ea17cd46d644f2660952d724a1ed4718aabe0b1415752a2883d7731ea200ad8',
  bob: '72e779b58fe8e6358059c28791345b8484294a2993aa46351d8f8e4e318d1bd1',
};

async function setupNode(dev, actorId, signingKeypair) {
  // The bootstrap admin must be literally 'admin': createTrigger and
  // evaluateTriggers sign admin ops as signer 'admin' with the node key
  // (same convention as examples/video_platform).
  const node = await dev.Node.create('admin', { ordering: 'hlc' });

  node.addCounter('views');
  node.addPNCounter('likes');
  node.addORSet('subscribers');
  node.addOneShotSet('flaggers');
  node.addCounter('flag_count');
  node.addRegister('contact');
  node.setPolicy('view', 'role:member');
  node.setPolicy('like', 'role:member');
  node.setPolicy('flag', 'role:member');
  // Admin-only ops used by createTrigger and evaluateTriggers (mirrors
  // examples/video_platform).
  node.setPolicy('__create_trigger__', 'role:admin');
  node.setPolicy('noop', 'role:admin');
  node.registerUser(actorId, signingKeypair.publicKeyHex(), 'adult');
  node.grantRole(actorId, 'role', 'member', 'admin');

  node.createTrigger({
    triggerId: 'tos_threshold',
    condition: 'flag_count >= 3',
    description: 'Issue tos_investigator attribute when flag threshold reached',
    effectType: 'issue_attribute',
    issueAttribute: 'tos_investigator',
    targetRole: 'clearance',
    attributeValue: 'verified',
    durationMs: 3600000,
    oneShot: false,
    cooldownMs: 60000
  });

  node.registerHandlerJs('view', (state, operation) => {
    state.incrementCounter('views', 1, operation.nodeId);
    return 0;
  });
  node.registerHandlerJs('like', (state, operation) => {
    state.incrementPNCounter('likes', 1, operation.nodeId);
    return 0;
  });
  node.registerHandlerJs('dislike', (state, operation) => {
    state.decrementPNCounter('likes', 1, operation.nodeId);
    return 0;
  });
  node.registerHandlerJs('subscribe', (state, operation) => {
    state.setAdd('subscribers', operation.signerId, operation.signerId + ':1');
    return 0;
  });
  node.registerHandlerJs('flag', (state, operation) => {
    state.incrementCounter('flag_count', 1, operation.nodeId);
    state.setAdd('flaggers', operation.signerId, operation.signerId + ':1');
    return 0;
  });

  return node;
}

async function fireOperation(dev, node, actorId, signingKeypair, opType) {
  const operation = await dev.Operation.create(opType);
  operation.signerId = actorId;
  operation.nodeId = actorId;
  node.sign(operation, signingKeypair);
  try {
    node.execute(operation);
  } catch (executeError) {
    // Rejections (no policy, replay guard) are expected demo behavior and
    // already appear in the devtools timeline; keep them out of the console.
    console.info('execute rejected ' + opType + ': ' + executeError.message);
  }
  // Trigger evaluation runs outside execute, so refresh the panels explicitly
  // afterwards (e.g. three Flag ops fire the tos_threshold trigger).
  node.evaluateTriggers();
  refreshPanels();
  // Broadcast regardless of the local outcome: a peer that has not applied
  // this operation yet may still accept it.
  if (window.demoChannel) {
    window.demoChannel.postMessage(operation.serialize());
  }
}

function startRelay(dev, node) {
  window.demoChannel = new BroadcastChannel(CHANNEL_NAME);
  window.demoChannel.onmessage = async (message) => {
    const operation = await dev.Operation.deserialize(new Uint8Array(message.data));
    try {
      node.execute(operation);
    } catch (executeError) {
      console.info('relay rejected ' + operation.type + ': ' + executeError.message);
    }
    node.evaluateTriggers();
    refreshPanels();
  };
}

(async function main() {
  // bindings-core.js (loaded as a plain <script>) exposes the factory; the
  // dev glue (crabs.dev.js) exposes window.createCRABSModuleDev.
  const dev = window.CRABSWasmCore(() => window.createCRABSModuleDev());
  // crabs-devtools.js exposes attach() on window.CRABSDevtools; the
  // controller plumbing it consumes lives on window.CRABSDevtoolsApi.
  const { attach } = window.CRABSDevtools;

  const aliceKeypair = await dev.KeyPair.fromPrivateHex(DEMO_PRIVATE_KEYS.alice);
  const bobKeypair = await dev.KeyPair.fromPrivateHex(DEMO_PRIVATE_KEYS.bob);

  const aliceNode = await setupNode(dev, 'alice', aliceKeypair);
  const bobNode = await setupNode(dev, 'bob', bobKeypair);

  // ABE-encrypt the demo contact once (the encrypting node acts as admin) and
  // store the raw ciphertext bytes in both nodes' contact registers. The CRDT
  // tab then shows "[encrypted: N bytes]" instead of the plaintext address.
  const encryptedContact = aliceNode.encrypt(
    new TextEncoder().encode('alice@example.com'), 'tos_investigator');
  aliceNode.setRegisterBytes('contact', encryptedContact, 'alice');
  bobNode.setRegisterBytes('contact', encryptedContact, 'bob');

  panelControllers = [
    attach(aliceNode, { nodeId: 'alice', mount: document.getElementById('alice-panel') }),
    attach(bobNode, { nodeId: 'bob', mount: document.getElementById('bob-panel') }),
  ];

  const actions = [
    ['View (increment views)', (node, actorId, keypair) => fireOperation(dev, node, actorId, keypair, 'view')],
    ['Like', (node, actorId, keypair) => fireOperation(dev, node, actorId, keypair, 'like')],
    ['Dislike (no policy, may reject)', (node, actorId, keypair) => fireOperation(dev, node, actorId, keypair, 'dislike'), 'bad'],
    ['Subscribe', (node, actorId, keypair) => fireOperation(dev, node, actorId, keypair, 'subscribe')],
    ['Flag', (node, actorId, keypair) => fireOperation(dev, node, actorId, keypair, 'flag')],
  ];

  for (const [gridId, node, actorId, keypair] of [
    ['alice-ops', aliceNode, 'alice', aliceKeypair],
    ['bob-ops', bobNode, 'bob', bobKeypair],
  ]) {
    const grid = document.getElementById(gridId);
    for (const [label, action, extraClass] of actions) {
      const button = document.createElement('button');
      button.textContent = label;
      if (extraClass) button.className = extraClass;
      button.addEventListener('click', () => action(node, actorId, keypair));
      grid.appendChild(button);
    }
  }

  startRelay(dev, aliceNode);
})();
