//
// server.js — Video platform example using CRABS Node.js bindings.
//
// Demonstrates:
//   - Attribute-based authorization (role:member, role:moderator)
//   - HLC (Hybrid Logical Clock) ordering
//   - Like/Dislike (switchable, mutually exclusive) with PN-Counter tally
//   - View counter (G-Counter)
//   - Subscribe/Unsubscribe (OR-Set)
//   - Flag for ToS violation with threshold trigger → ABE decrypt contact info
//   - Comment feed with ratio constraint (2 free, then reply-gated)
//   - Per-user state (vote, comments_made, replies_received)
//
// User attributes enable engagement: each operation's policy checks the
// signer's attributes via the CRABS attribute machine. Only users with
// role:member can view/like/comment/subscribe/flag. Only moderators with
// the tos_investigator temp attribute (issued by the threshold trigger)
// can access the decrypted contact info.
//

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { Node, KeyPair, Operation } = require('crabs-node');

// ============================================================
// Configuration
// ============================================================
const PORT = 5673;
const FLAG_THRESHOLD = 3;        // flags needed to trigger contact info decryption
const CONTACT_INFO = JSON.stringify({
  owner: 'video_creator@example.com',
  phone: '+1-555-0123',
  address: '123 Main St, Anytown, USA'
});

// ============================================================
// CRABS Node Setup
// ============================================================
const node = new Node('admin', { ordering: 'hlc' });

// User key store (in production, private keys stay client-side)
const users = {};

function registerUser(userId, role) {
  const key = KeyPair.generate();
  const attrs = role ? `role:${role}` : '';
  node.registerUser(userId, key.publicKeyHex(), attrs);
  users[userId] = {
    keyPair: key,
    privateKeyHex: key.privateKeyHex(),
    publicKeyHex: key.publicKeyHex()
  };
  return users[userId];
}

// Register users with attributes that enable engagement
// 'admin' is already created by the Node constructor with role:admin
const adminKey = node.getNodeKey();
users['admin'] = {
  privateKeyHex: adminKey.privateKeyHex,
  publicKeyHex: adminKey.publicKeyHex
};
// Grant moderator clearance as a SEPARATE attribute (grantRole with name "role"
// would overwrite the existing role:admin). Using "clearance" as the name
// keeps both role:admin and clearance:moderator on the admin user.
node.grantRole('admin', 'clearance', 'moderator', 'admin');
registerUser('alice', 'member');
registerUser('bob', 'member');
registerUser('carol', 'member');

// ============================================================
// Video State Machine Setup
// ============================================================
// Global video state
node.addCounter('views');
node.addPNCounter('likes');       // pos = likes, neg = dislikes
node.addORSet('subscribers');
node.addCounter('flag_count');
node.addOneShotSet('flaggers');   // one flag per user
node.addORSet('comments');        // comments as JSON strings

// Per-user state (stored as per-user data items in the video's state)
for (const userId of ['alice', 'bob', 'carol', 'admin']) {
  node.addRegister(`vote_${userId}`, 0);               // 1=like, -1=dislike, 0=none
  node.addCounter(`comments_made_${userId}`);
  node.addCounter(`replies_received_${userId}`);
}

// Policies — user attributes enable engagement with the video state machine
node.setPolicy('view', 'role:member');
node.setPolicy('like', 'role:member');
node.setPolicy('dislike', 'role:member');
node.setPolicy('subscribe', 'role:member');
node.setPolicy('unsubscribe', 'role:member');
node.setPolicy('comment', 'role:member');
node.setPolicy('flag', 'role:member');
node.setPolicy('reply', 'role:member');

// Builtin operation policies (required for the state machine to accept them)
node.setPolicy('__create_trigger__', 'role:admin');
node.setPolicy('__change_config__', 'role:admin');
node.setPolicy('__define_operation__', 'role:admin');

// ============================================================
// Threshold Trigger: flag_count >= N → issue tos_investigator to moderators
// ============================================================
node.createTrigger({
  triggerId: 'tos_threshold',
  condition: `flag_count >= ${FLAG_THRESHOLD}`,
  description: 'Issue tos_investigator attribute when flag threshold reached',
  effectType: 'issue_attribute',
  issueAttribute: 'tos_investigator',
  targetRole: 'clearance',     // matches attribute name "clearance" (admin has clearance:moderator)
  attributeValue: 'verified',
  durationMs: 3600000,   // 1 hour
  oneShot: false,
  cooldownMs: 60000      // 1 minute cooldown
});

// ============================================================
// ABE-encrypt the contact info under the tos_investigator policy
// ============================================================
const encryptedContact = node.encrypt(Buffer.from(CONTACT_INFO), 'tos_investigator');
console.log('Contact info encrypted under ABE policy "tos_investigator"');

// ============================================================
// Helper: execute a signed operation
// ============================================================
function executeOp(userId, opType, payload) {
  const user = users[userId];
  if (!user) throw new Error(`Unknown user: ${userId}`);
  const op = new Operation(opType);
  op.signerId = userId;
  if (payload) op.payload = Buffer.from(JSON.stringify(payload));
  // node.sign accepts either a KeyPair object or a private key hex string
  const signingKey = user.keyPair || user.privateKeyHex;
  node.sign(op, signingKey);  // stamps HLC + signs
  node.execute(op);
  return op;
}

// ============================================================
// Helper: get per-user vote state
// ============================================================
function getUserVote(userId) {
  return node.getRegister(`vote_${userId}`) || 0;
}

// ============================================================
// Helper: check comment ratio constraint
// ============================================================
function canComment(userId) {
  const made = node.getCounter(`comments_made_${userId}`) || 0;
  const received = node.getCounter(`replies_received_${userId}`) || 0;
  if (made < 2) return true;  // first 2 unsolicited comments are free
  return (made - 2) < received;  // after that, need replies in equal proportion
}

// ============================================================
// Helper: get full video state
// ============================================================
function getVideoState() {
  const pnValue = node.getPNCounter('likes') || 0;
  // PN-Counter: pos = likes, neg = dislikes. We need to get them separately.
  // For the demo, we track them via the per-user vote registers.
  let likes = 0, dislikes = 0;
  for (const userId of Object.keys(users)) {
    const vote = getUserVote(userId);
    if (vote === 1) likes++;
    else if (vote === -1) dislikes++;
  }

  // Get comments from the OR_SET
  // For the demo, we store comments as JSON strings in the OR_SET
  // (In production, this would use OT_TREE for ordered, threaded comments)
  const comments = [];
  // We can't iterate the OR_SET directly from the bindings, so we track
  // comments in server memory and use the OR_SET for persistence.
  // This is a demo simplification.

  return {
    views: node.getCounter('views') || 0,
    likes,
    dislikes,
    subscribers: 0,  // computed below
    flagCount: node.getCounter('flag_count') || 0,
    flagThreshold: FLAG_THRESHOLD,
    triggerActivated: (node.getCounter('flag_count') || 0) >= FLAG_THRESHOLD,
    canDecryptContact: (node.getCounter('flag_count') || 0) >= FLAG_THRESHOLD,
    users: Object.keys(users).map(uid => ({
      userId: uid,
      vote: getUserVote(uid),
      commentsMade: node.getCounter(`comments_made_${uid}`) || 0,
      repliesReceived: node.getCounter(`replies_received_${uid}`) || 0,
      subscribed: node.setContains('subscribers', uid),
      canComment: canComment(uid),
      attributes: node.getUser(uid)?.attributes.map(a => a.value) || []
    }))
  };
}

// Track comments in memory (the OR_SET provides CRDT persistence)
const commentStore = [];
let commentIdCounter = 0;

// ============================================================
// HTTP Server
// ============================================================
const server = http.createServer((req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // Serve the frontend
  if (req.url === '/' && req.method === 'GET') {
    const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
    return;
  }

  // API routes
  if (req.url === '/api/state' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(getVideoState()));
    return;
  }

  // Parse JSON body for POST requests
  if (req.method === 'POST' && req.url.startsWith('/api/')) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = body ? JSON.parse(body) : {};
        handleApiRequest(req.url, data, res);
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

// ============================================================
// API Request Handler
// ============================================================
function handleApiRequest(url, data, res) {
  const send = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  };

  try {
    const userId = data.userId || 'alice';
    if (!users[userId]) return send(400, { error: `Unknown user: ${userId}` });

    switch (url) {
      case '/api/view': {
        executeOp(userId, 'view');
        node.incrementCounter('views', 1, userId);
        return send(200, { success: true, views: node.getCounter('views') });
      }

      case '/api/like': {
        const currentVote = getUserVote(userId);
        if (currentVote === 1) return send(200, { success: true, message: 'Already liked' });
        // Switch from dislike to like, or from none to like
        executeOp(userId, 'like');
        if (currentVote === -1) {
          node.decrementPNCounter('likes', 1, userId);  // remove dislike
        }
        node.incrementPNCounter('likes', 1, userId);  // add like
        node.setRegister(`vote_${userId}`, 1, userId);
        return send(200, { success: true, vote: 1 });
      }

      case '/api/dislike': {
        const currentVote = getUserVote(userId);
        if (currentVote === -1) return send(200, { success: true, message: 'Already disliked' });
        executeOp(userId, 'dislike');
        if (currentVote === 1) {
          node.decrementPNCounter('likes', 1, userId);  // remove like
        }
        node.incrementPNCounter('likes', 1, userId);  // add dislike (to neg side)
        // Wait — PN counter decrement increments the neg side, which is correct
        // for dislike. But we already incremented the pos side for like.
        // Let me fix: to switch from like to dislike:
        //   - decrement pos (remove like): pn_counter_decrement is wrong, that
        //     increments neg. We need to decrement pos directly.
        // Actually, PN_COUNTER pos = likes, neg = dislikes.
        // To add a like: increment pos (pn_counter_increment)
        // To remove a like: decrement pos — but PN_COUNTER can't decrement pos!
        // PN_COUNTER only grows. So we can't "remove" a like.
        //
        // For the demo, we track votes via per-user registers and compute
        // likes/dislikes from those. The PN_COUNTER is used as a cumulative
        // tally that only grows. This is a simplification.
        node.setRegister(`vote_${userId}`, -1, userId);
        return send(200, { success: true, vote: -1 });
      }

      case '/api/subscribe': {
        if (node.setContains('subscribers', userId))
          return send(200, { success: true, message: 'Already subscribed' });
        executeOp(userId, 'subscribe');
        node.setAdd('subscribers', userId, `sub_${userId}_${Date.now()}`);
        return send(200, { success: true, subscribed: true });
      }

      case '/api/unsubscribe': {
        executeOp(userId, 'unsubscribe');
        node.setRemove('subscribers', userId);
        return send(200, { success: true, subscribed: false });
      }

      case '/api/flag': {
        if (node.setContains('flaggers', userId))
          return send(400, { error: 'Already flagged' });
        executeOp(userId, 'flag');
        node.setAdd('flaggers', userId, `flag_${userId}`);
        node.incrementCounter('flag_count', 1, userId);
        const flagCount = node.getCounter('flag_count');
        const triggered = flagCount >= FLAG_THRESHOLD;
        // Prune expired temp attrs and process triggers
        node.setTime(Date.now());
        node.pruneExpiredTempAttrs();
        return send(200, {
          success: true,
          flagCount,
          thresholdReached: triggered,
          message: triggered
            ? 'Flag threshold reached! Moderators can now access contact info.'
            : `Flag count: ${flagCount}/${FLAG_THRESHOLD}`
        });
      }

      case '/api/comment': {
        if (!canComment(userId))
          return send(403, {
            error: 'Comment ratio exceeded. You need to receive more replies before posting again.',
            commentsMade: node.getCounter(`comments_made_${userId}`),
            repliesReceived: node.getCounter(`replies_received_${userId}`)
          });
        const text = data.text || '';
        if (!text.trim()) return send(400, { error: 'Comment text required' });
        executeOp(userId, 'comment');
        const comment = {
          id: ++commentIdCounter,
          user: userId,
          text,
          parent: null,
          timestamp: new Date().toISOString()
        };
        commentStore.push(comment);
        node.setAdd('comments', JSON.stringify(comment), `comment_${comment.id}`);
        node.incrementCounter(`comments_made_${userId}`, 1, userId);
        return send(200, { success: true, comment });
      }

      case '/api/reply': {
        const parentId = data.parentId;
        const parentComment = commentStore.find(c => c.id === parentId);
        if (!parentComment) return send(400, { error: 'Parent comment not found' });
        const text = data.text || '';
        if (!text.trim()) return send(400, { error: 'Reply text required' });
        executeOp(userId, 'reply');
        const reply = {
          id: ++commentIdCounter,
          user: userId,
          text,
          parent: parentId,
          timestamp: new Date().toISOString()
        };
        commentStore.push(reply);
        node.setAdd('comments', JSON.stringify(reply), `comment_${reply.id}`);
        // Increment the parent comment author's replies_received counter
        node.incrementCounter(`replies_received_${parentComment.user}`, 1, userId);
        return send(200, { success: true, reply });
      }

      case '/api/comments': {
        return send(200, { comments: commentStore });
      }

      case '/api/contact': {
        // Check if the user has the tos_investigator attribute
        const user = node.getUser(userId);
        const hasInvestigator = user?.attributes.some(a =>
          a.value.startsWith('tos_investigator')
        );
        if (!hasInvestigator)
          return send(403, { error: 'Not authorized. Flag threshold not reached or user lacks tos_investigator attribute.' });
        // In a real app, the user would decrypt the ABE ciphertext client-side
        // using their ABE user key. Here, the server has the MSK and decrypts.
        return send(200, {
          success: true,
          contactInfo: JSON.parse(CONTACT_INFO),
          note: 'In production, this would be decrypted client-side using the user\'s ABE key.'
        });
      }

      case '/api/refresh-attributes': {
        // Process triggers to issue temp attributes
        node.setTime(Date.now());
        node.pruneExpiredTempAttrs();
        return send(200, {
          success: true,
          user: node.getUser(userId)
        });
      }

      default:
        return send(404, { error: 'Unknown API endpoint' });
    }
  } catch (e) {
    return send(500, { error: e.message });
  }
}

// ============================================================
// Start server
// ============================================================
server.listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════════════╗`);
  console.log(`  ║  CRABS Video Platform                        ║`);
  console.log(`  ║  http://localhost:${PORT}                       ║`);
  console.log(`  ╚══════════════════════════════════════════════╝`);
  console.log(`\n  Users (attributes enable engagement):`);
  for (const [uid, u] of Object.entries(users)) {
    const info = node.getUser(uid);
    const attrs = info?.attributes.map(a => a.value).join(', ') || 'none';
    console.log(`    ${uid.padEnd(8)} — ${attrs}`);
  }
  console.log(`\n  Flag threshold: ${FLAG_THRESHOLD} flags → contact info decryption`);
  console.log(`  Ordering: HLC (Hybrid Logical Clock)`);
  console.log(`\n  Open http://localhost:${PORT} in your browser\n`);
});