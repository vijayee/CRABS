//
// demo.js — two in-browser CRABS nodes with devtools panels attached.
//
// Each node registers JS handlers for custom op types ('view', 'like',
// 'dislike', 'subscribe', 'flag'); firing one of those ops goes through
// state_machine_execute. Every mutation path fires a change event, and the
// devtools panels subscribe to node.on('change'), so timeline, transitions,
// and CRDT values all update without any manual refresh. A second browser
// tab acts as a peer: fired ops are relayed as serialized signed bytes over
// BroadcastChannel and re-executed.
//
// Identity layout:
//   - Each node bootstraps a distinct admin user ('alice-admin'/'bob-admin')
//     whose private key never leaves the WASM heap, so it cannot sign demo
//     ops. The admin id is also the node's HLC identity: signing stamps it
//     into op->node_id, so the devtools panels can drain events per node
//     (createTrigger/evaluateTriggers sign admin ops as that user — see
//     setupNode).
//   - The demo actor (alice/bob) is registered as a regular user with a
//     fixed demo keypair and granted role:member via the admin grantRole
//     path (register_user rejects privileged attribute names, audit R7-08).
//   - The keypairs are fixed so a second tab registers the same public keys
//     and relayed operations still verify.
//

'use strict';

const CHANNEL_NAME = 'crabs-devtools-demo';

// Fixed demo signing keys (secp256r1 scalars, generated once out-of-band).
const DEMO_PRIVATE_KEYS = {
  alice: '0ea17cd46d644f2660952d724a1ed4718aabe0b1415752a2883d7731ea200ad8',
  bob: '72e779b58fe8e6358059c28791345b8484294a2993aa46351d8f8e4e318d1bd1',
};

async function setupNode(dev, adminId, actorId, signingKeypair) {
  // The bootstrap admin id doubles as the node's HLC identity —
  // createTrigger and evaluateTriggers sign admin ops as that user with the
  // node key, and devtools drains filter events by it. Each demo node gets a
  // distinct admin id so the two panels never attribute each other's events.
  const node = await dev.Node.create(adminId, { ordering: 'hlc' });

  node.addCounter('views');
  node.addPNCounter('likes');
  node.addORSet('subscribers');
  node.addOneShotSet('flaggers');
  node.addCounter('flag_count');
  node.addRegister('contact');
  node.addCounter('tokens');
  node.setPolicy('view', 'role:member');
  node.setPolicy('mint', 'role:member');
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
  node.registerHandlerJs('mint', (state, operation) => {
    state.incrementCounter('tokens', 1, operation.nodeId);
    return 0;
  });

  return node;
}

// Schedule a mint 60 seconds out. The signed operation goes into the node's
// durable pending set (no execute, no broadcast) and materializes locally when
// the node's clock passes the scheduled time — scheduling is a per-node
// decision, so the peer never sees the pending op.
async function scheduleMint(dev, node, actorId, signingKeypair) {
  const mintOperation = await dev.Operation.create('mint');
  mintOperation.signerId = actorId;
  mintOperation.nodeId = actorId;
  node.sign(mintOperation, signingKeypair);
  node.schedule(mintOperation, Date.now() + 60000);
  // Scheduling fires a change event, so the panels show the new Schedules row
  // in the Config tab without any manual refresh.
}

// Schedule a mint every 15 seconds, three times. The series fires in order
// (catch-up on missed slots) and disappears from the Schedules section once
// the third mint has materialized.
async function scheduleRecurringMint(dev, node, actorId, signingKeypair) {
  const mintOperation = await dev.Operation.create('mint');
  mintOperation.signerId = actorId;
  mintOperation.nodeId = actorId;
  node.sign(mintOperation, signingKeypair);
  node.scheduleRecurring(mintOperation, Date.now() + 15000, 15000, 3, 0);
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
  // Trigger evaluation runs outside execute; its attribute issuances fire
  // change events too (e.g. three Flag ops fire the tos_threshold trigger).
  node.evaluateTriggers();
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

  const aliceNode = await setupNode(dev, 'alice-admin', 'alice', aliceKeypair);
  const bobNode = await setupNode(dev, 'bob-admin', 'bob', bobKeypair);

  // ABE-encrypt the demo contact once (the encrypting node acts as admin) and
  // store the raw ciphertext bytes in both nodes' contact registers. The CRDT
  // tab then shows "[encrypted: N bytes]" instead of the plaintext address.
  const encryptedContact = aliceNode.encrypt(
    new TextEncoder().encode('alice@example.com'), 'tos_investigator');
  aliceNode.setRegisterBytes('contact', encryptedContact, 'alice');
  bobNode.setRegisterBytes('contact', encryptedContact, 'bob');

  // No mount target: both panels default to a floating overlay in the corner
  // of the viewport (pass mount: <element> to embed one in the page).
  attach(aliceNode, { nodeId: 'alice-admin' });
  attach(bobNode, { nodeId: 'bob-admin' });

  const actions = [
    ['View (increment views)', (node, actorId, keypair) => fireOperation(dev, node, actorId, keypair, 'view')],
    ['Like', (node, actorId, keypair) => fireOperation(dev, node, actorId, keypair, 'like')],
    ['Dislike (no policy, may reject)', (node, actorId, keypair) => fireOperation(dev, node, actorId, keypair, 'dislike'), 'bad'],
    ['Subscribe', (node, actorId, keypair) => fireOperation(dev, node, actorId, keypair, 'subscribe')],
    ['Flag', (node, actorId, keypair) => fireOperation(dev, node, actorId, keypair, 'flag')],
    ['Schedule mint (+60s)', (node, actorId, keypair) => scheduleMint(dev, node, actorId, keypair)],
    ['Schedule 3 mints (every 15s)', (node, actorId, keypair) => scheduleRecurringMint(dev, node, actorId, keypair)],
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
