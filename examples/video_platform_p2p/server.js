//
// server.js — P2P video platform relay.
//
// Serves static files and the penguin.mp4 video. Relays WebSocket messages
// between browser peers. Holds ABE-encrypted contact info and decrypts it
// for users whose state-machine attributes include tos_investigator.
//

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');
const { Node, KeyPair, Operation } = require('crabs-node');
const { MOD1_PRIVATE_KEY } = require('./demo_keys');

const PORT = 5674;
const FLAG_THRESHOLD = 3;
const CONTACT_INFO = JSON.stringify({
  owner: 'video_creator@example.com',
  phone: '+1-555-0123',
  address: '123 Main St, Anytown, USA'
});

const MIME = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.wasm': 'application/wasm',
  '.mp4': 'video/mp4',
};

// ============================================================
// CRABS Node for ABE gate (server-side only)
// ============================================================
const node = new Node('admin', { ordering: 'hlc' });

// Demo moderator account used for the ABE contact gate.
const modKey = KeyPair.fromPrivateHex(MOD1_PRIVATE_KEY);
const mod1UserId = modKey.publicKeyHex().slice(0, 63);
node.registerUser(mod1UserId, modKey.publicKeyHex(), 'role:member|clearance:moderator|adult');

node.addCounter('flag_count');
node.addOneShotSet('flaggers');
node.setPolicy('__create_trigger__', 'role:admin');
node.setPolicy('__change_config__', 'role:admin');
node.setPolicy('__define_operation__', 'role:admin');
node.setPolicy('noop', 'role:admin');

node.createTrigger({
  triggerId: 'tos_threshold',
  condition: `flag_count >= ${FLAG_THRESHOLD}`,
  description: 'Issue tos_investigator to moderators',
  effectType: 'issue_attribute',
  issueAttribute: 'tos_investigator',
  targetRole: 'clearance',
  attributeValue: 'verified',
  durationMs: 3600000,
  oneShot: false,
  cooldownMs: 60000
});

const nodeKey = node.getNodeKey();

const encryptedContact = node.encrypt(Buffer.from(CONTACT_INFO), 'tos_investigator');
console.log('ABE contact info encrypted');

// Trigger evaluation only runs inside state_machine_execute. We use a signed
// admin "noop" operation as a safe way to re-evaluate triggers after direct
// state changes such as flag_event handling.
function evaluateTriggers() {
  try {
    const op = new Operation('noop');
    op.signerId = 'admin';
    op.nodeId = 'admin';
    node.sign(op, nodeKey.privateKeyHex);
    node.execute(op);
  } catch (e) {
    console.warn('Trigger evaluation failed:', e.message);
  }
}

// ============================================================
// Static HTTP server
// ============================================================
const publicDir = path.join(__dirname, 'public');

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  if (req.url === '/contact' && req.method === 'POST') {
    return handleContact(req, res);
  }

  let filePath = req.url === '/' ? '/index.html' : req.url;
  filePath = path.join(publicDir, path.normalize(filePath));
  if (!filePath.startsWith(publicDir)) {
    res.writeHead(403); res.end('Forbidden'); return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404); res.end('Not found'); return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
});

// ============================================================
// /contact endpoint
// ============================================================
function handleContact(req, res) {
  let body = '';
  req.on('data', c => body += c);
  req.on('end', () => {
    try {
      const data = JSON.parse(body || '{}');
      const userId = data.userId;
      if (!userId) { send(res, 400, { error: 'userId required' }); return; }

      node.setTime(Date.now());
      node.pruneExpiredTempAttrs();

      const user = node.getUser(userId);
      const hasAttr = user && user.attributes.some(a =>
        a.value === 'tos_investigator:verified' ||
        (a.temporary && a.value.startsWith('tos_investigator'))
      );
      if (!hasAttr) { send(res, 403, { error: 'Not authorized' }); return; }

      send(res, 200, { success: true, contactInfo: JSON.parse(CONTACT_INFO) });
    } catch (e) {
      send(res, 500, { error: e.message });
    }
  });
}

function send(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

// ============================================================
// WebSocket relay
// ============================================================
const wss = new WebSocketServer({ server });
const clients = new Set();

wss.on('connection', ws => {
  clients.add(ws);
  ws.on('message', raw => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }

    // Keep the server state in sync so the ABE gate can check attributes.
    if (msg.type === 'register_user') {
      const attrs = ['role:member'];
      if (msg.age >= 13) attrs.push('adult');
      try {
        node.registerUser(msg.userId, msg.publicKeyHex, attrs.join('|'));
      } catch (e) {
        // User may already be registered (e.g., duplicate broadcast).
      }
    } else if (msg.type === 'operation' && msg.payload) {
      // We don't deserialize operations server-side (crabs-node exposes no
      // deserialize), but we can directly track flags to keep the trigger alive.
    } else if (msg.type === 'flag_event' && msg.userId) {
      try {
        if (!node.setContains('flaggers', msg.userId)) {
          node.setAdd('flaggers', msg.userId, `flag_${msg.userId}`);
          node.incrementCounter('flag_count', 1, msg.userId);
          node.setTime(Date.now());
          node.pruneExpiredTempAttrs();
          evaluateTriggers();
        }
      } catch (e) {
        // Ignore duplicate-flag errors and relay side effects.
      }
    }

    // Relay to all other sockets.
    for (const client of clients) {
      if (client !== ws && client.readyState === 1) {
        client.send(raw);
      }
    }
  });
  ws.on('close', () => clients.delete(ws));
});

// ============================================================
// Start
// ============================================================
server.listen(PORT, () => {
  console.log(`CRABS P2P Video Platform: http://localhost:${PORT}`);
});
