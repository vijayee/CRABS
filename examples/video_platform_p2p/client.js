//
// client.js — Browser peer for the CRABS P2P video platform demo.
//
// Each tab runs a full CRABS node in WebAssembly, signs operations locally, and
// streams them to every other tab through the Node.js WebSocket relay.
//

'use strict';

const { Node, KeyPair, Operation } = require('crabs-wasm');
const { MOD1_PRIVATE_KEY } = require('./demo_keys');

const FLAG_THRESHOLD = 3;

let node = null;
let currentUser = null;
let ws = null;
let viewRecorded = false;
let reconnectTimer = null;

// Demo accounts are pre-seeded so any tab can log in as them.
const DEMO_ACCOUNTS = [
  { name: 'alice', age: 25 },
  { name: 'bob', age: 30 },
  { name: 'carol', age: 10 },
  { name: 'mod1', age: 40 },
];

// name -> { name, userId, publicKeyHex, privateKeyHex, age, keyPair }
const localUsers = new Map();

// Parallel JS store for comments (OR-set iteration is not exposed to JS).
const commentsStore = [];

// ============================================================
// Bootstrap
// ============================================================

async function init() {
  await seedDemoUsers();
  node = await Node.create('admin', { ordering: 'hlc' });
  await registerDemoUsers();
  initStateMachine();
  connectWebSocket();
  bindAuth();
}

async function seedDemoUsers() {
  for (const demo of DEMO_ACCOUNTS) {
    const key = demo.name === 'mod1'
      ? await KeyPair.fromPrivateHex(MOD1_PRIVATE_KEY)
      : await KeyPair.generate();
    // CRABS user IDs are limited to 63 usable chars (CRABS_MAX_USER_ID=64
    // minus the null terminator). The public key hex is 66 chars, so truncate.
    const publicKeyHex = key.publicKeyHex();
    const userId = publicKeyHex.slice(0, 63);
    localUsers.set(demo.name, {
      name: demo.name,
      userId,
      publicKeyHex,
      privateKeyHex: key.privateKeyHex(),
      age: demo.age,
      keyPair: key,
    });
  }
}

async function registerDemoUsers() {
  for (const u of localUsers.values()) {
    await registerUserInNode(u);
  }
}

function buildAttrs(age, isModerator) {
  const attrs = ['role:member'];
  if (age >= 13) attrs.push('adult');
  if (isModerator) attrs.push('clearance:moderator');
  return attrs.join('|');
}

async function registerUserInNode(user) {
  const attrs = buildAttrs(user.age, user.name === 'mod1');
  try {
    await node.registerUser(user.userId, user.publicKeyHex, attrs);
  } catch (e) {
    // Duplicate registrations are harmless in this demo.
    if (!/duplicate/i.test(e.message)) throw e;
  }
}

function initStateMachine() {
  node.addCounter('views');
  node.addPNCounter('likes');
  node.addORSet('subscribers');
  node.addCounter('flag_count');
  node.addOneShotSet('flaggers');
  node.addORSet('comments');

  for (const u of localUsers.values()) {
    ensureUserState(u.userId);
  }

  // Note: a "reply" operation type is defined in the state machine for future
  // threading, but the UI only supports top-level comments in this demo.

  const adultPolicy = 'AND role:member adult';
  node.setPolicy('view', adultPolicy);
  node.setPolicy('like', adultPolicy);
  node.setPolicy('dislike', adultPolicy);
  node.setPolicy('subscribe', adultPolicy);
  node.setPolicy('unsubscribe', adultPolicy);
  node.setPolicy('comment', adultPolicy);
  node.setPolicy('flag', adultPolicy);

  node.setPolicy('__create_trigger__', 'role:admin');
  node.setPolicy('__change_config__', 'role:admin');
  node.setPolicy('__define_operation__', 'role:admin');

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
    cooldownMs: 60000,
  });
}

function ensureUserState(userId) {
  try { node.addRegister(`vote_${userId}`, 0); } catch (e) { /* exists */ }
  try { node.addCounter(`comments_made_${userId}`); } catch (e) { /* exists */ }
}

// ============================================================
// WebSocket relay
// ============================================================

function connectWebSocket() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }

  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${window.location.host}`);

  ws.onopen = () => setStatus('online');
  ws.onclose = () => {
    setStatus('offline');
    scheduleReconnect();
  };
  ws.onerror = () => {
    setStatus('offline');
    if (ws) ws.close();
  };
  ws.onmessage = handleMessage;
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectWebSocket();
  }, 3000);
}

async function handleMessage(evt) {
  let msg;
  try {
    msg = JSON.parse(evt.data);
  } catch (e) {
    return;
  }

  if (msg.type === 'register_user') {
    ensureUserState(msg.userId);
    const attrs = buildAttrs(msg.age, msg.name === 'mod1');
    try {
      await node.registerUser(msg.userId, msg.publicKeyHex, attrs);
    } catch (e) {
      if (!/duplicate/i.test(e.message)) console.warn('register_user failed', e);
    }
  } else if (msg.type === 'operation' && msg.payload) {
    try {
      const op = await Operation.deserialize(base64ToBytes(msg.payload));
      node.execute(op);
      applyOperationEffect(op);
      op.destroy();
      refreshUI();
    } catch (e) {
      console.warn('incoming operation failed', e.message);
    }
  } else if (msg.type === 'flag_event' && msg.userId) {
    applyFlagEvent(msg.userId);
    refreshUI();
  }
}

function setStatus(state) {
  const el = document.getElementById('connectionStatus');
  el.className = 'status ' + state;
  el.textContent = state === 'online' ? 'Connected' : 'Disconnected';
}

// ============================================================
// Auth
// ============================================================

function bindAuth() {
  document.getElementById('loginBtn').addEventListener('click', () => doAuth(false));
  document.getElementById('registerBtn').addEventListener('click', () => doAuth(true));
}

async function doAuth(isRegister) {
  const name = document.getElementById('authName').value.trim();
  const ageStr = document.getElementById('authAge').value.trim();
  const age = parseInt(ageStr, 10);
  const errEl = document.getElementById('authError');
  errEl.textContent = '';

  if (!name) {
    errEl.textContent = 'Name is required';
    return;
  }
  if (!ageStr || isNaN(age)) {
    errEl.textContent = 'Age is required';
    return;
  }

  if (isRegister) {
    if (localUsers.has(name)) {
      errEl.textContent = 'That name is already taken';
      return;
    }
    const key = await KeyPair.generate();
    // CRABS user IDs are limited to 63 usable chars (CRABS_MAX_USER_ID=64
    // minus the null terminator). The public key hex is 66 chars, so truncate.
    const publicKeyHex = key.publicKeyHex();
    const userId = publicKeyHex.slice(0, 63);
    currentUser = {
      name,
      userId,
      publicKeyHex,
      privateKeyHex: key.privateKeyHex(),
      age,
      keyPair: key,
    };
    localUsers.set(name, currentUser);
    ensureUserState(userId);
    await registerUserInNode(currentUser);
    broadcastRegister(currentUser);
  } else {
    const existing = localUsers.get(name);
    if (!existing) {
      errEl.textContent = 'Unknown user';
      return;
    }
    currentUser = existing;
  }

  showPlayer();
  bindEngagement();
  refreshUI();
}

function broadcastRegister(user) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: 'register_user',
      name: user.name,
      userId: user.userId,
      publicKeyHex: user.publicKeyHex,
      age: user.age,
      role: 'member',
    }));
  }
}

function showPlayer() {
  document.getElementById('authScreen').classList.add('hidden');
  document.getElementById('playerScreen').classList.remove('hidden');

  const video = document.getElementById('videoPlayer');
  const underage = currentUser.age < 13;

  document.getElementById('ageGate').classList.toggle('hidden', !underage);

  if (underage) {
    video.removeAttribute('controls');
    video.pause();
    video.addEventListener('click', blockUnderagePlayback, true);
  } else {
    video.setAttribute('controls', 'controls');
    video.removeEventListener('click', blockUnderagePlayback, true);
  }

  updateEngagementDisabled();
}

function blockUnderagePlayback(e) {
  e.preventDefault();
  e.stopPropagation();
  showError('This content is not available to users under 12.');
}

function updateEngagementDisabled() {
  const underage = currentUser && currentUser.age < 13;
  const ids = ['likeBtn', 'dislikeBtn', 'subscribeBtn', 'flagBtn', 'postCommentBtn', 'commentText'];
  for (const id of ids) {
    const el = document.getElementById(id);
    if (el) el.disabled = underage;
  }
}

function canAct() {
  if (!currentUser) return false;
  if (currentUser.age < 13) {
    showError('This action is not available to users under 12.');
    return false;
  }
  return true;
}

// ============================================================
// Engagement actions
// ============================================================

function bindEngagement() {
  document.getElementById('likeBtn').addEventListener('click', () => doLike());
  document.getElementById('dislikeBtn').addEventListener('click', () => doDislike());
  document.getElementById('subscribeBtn').addEventListener('click', () => doSubscribe());
  document.getElementById('flagBtn').addEventListener('click', () => doFlag());
  document.getElementById('contactBtn').addEventListener('click', () => viewContact());
  document.getElementById('postCommentBtn').addEventListener('click', () => doComment());
  document.getElementById('videoPlayer').addEventListener('play', () => doView());
}

async function doLike() {
  if (!canAct()) return;
  await runOperation('like');
  node.incrementPNCounter('likes', 1, currentUser.userId);
  node.setRegister(`vote_${currentUser.userId}`, 1, currentUser.userId);
  refreshUI();
}

async function doDislike() {
  if (!canAct()) return;
  await runOperation('dislike');
  node.decrementPNCounter('likes', 1, currentUser.userId);
  node.setRegister(`vote_${currentUser.userId}`, -1, currentUser.userId);
  refreshUI();
}

async function doSubscribe() {
  if (!canAct()) return;
  const subscribed = node.setContains('subscribers', currentUser.userId);
  const type = subscribed ? 'unsubscribe' : 'subscribe';
  await runOperation(type);
  if (subscribed) {
    node.setRemove('subscribers', currentUser.userId);
  } else {
    node.setAdd('subscribers', currentUser.userId, `sub_${currentUser.userId}_${Date.now()}`);
  }
  refreshUI();
}

async function doFlag() {
  if (!canAct()) return;
  if (node.setContains('flaggers', currentUser.userId)) {
    showError('You have already flagged this video');
    return;
  }
  await runOperation('flag');
  applyFlagEvent(currentUser.userId);
  broadcastFlagEvent(currentUser.userId);
  refreshUI();
}

async function doView() {
  if (!currentUser || currentUser.age < 13) return;
  if (viewRecorded) return;
  viewRecorded = true;
  await runOperation('view');
  node.incrementCounter('views', 1, currentUser.userId);
  refreshUI();
}

async function doComment() {
  if (!canAct()) return;
  const input = document.getElementById('commentText');
  const text = input.value.trim();
  if (!text) return;

  const comment = {
    id: `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    user: currentUser.name,
    userId: currentUser.userId,
    text,
    parent: null,
    timestamp: new Date().toISOString(),
  };

  await runOperation('comment', JSON.stringify(comment));
  applyLocalComment(comment);
  node.incrementCounter(`comments_made_${currentUser.userId}`, 1, currentUser.userId);
  input.value = '';
  document.getElementById('commentError').textContent = '';
  refreshUI();
}

// ============================================================
// Operation helpers
// ============================================================

async function runOperation(type, payload) {
  const op = await Operation.create(type);
  op.signerId = currentUser.userId;
  op.nodeId = currentUser.userId;
  if (payload) op.payload = payload;
  node.sign(op, currentUser.keyPair);
  node.execute(op);
  broadcastOperation(op.serialize());
  op.destroy();
}

function broadcastOperation(bytes) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ type: 'operation', payload: bytesToBase64(bytes) }));
}

function broadcastFlagEvent(userId) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ type: 'flag_event', userId }));
}

function applyOperationEffect(op) {
  const signer = op.signerId || 'system';
  ensureUserState(signer);

  switch (op.type) {
    case 'view':
      node.incrementCounter('views', 1, signer);
      break;
    case 'like':
      node.incrementPNCounter('likes', 1, signer);
      node.setRegister(`vote_${signer}`, 1, signer);
      break;
    case 'dislike':
      node.decrementPNCounter('likes', 1, signer);
      node.setRegister(`vote_${signer}`, -1, signer);
      break;
    case 'subscribe':
      node.setAdd('subscribers', signer, `sub_${signer}_${Date.now()}`);
      break;
    case 'unsubscribe':
      node.setRemove('subscribers', signer);
      break;
    case 'flag':
      applyFlagEvent(signer);
      break;
    case 'comment': {
      const payload = op.payload;
      if (payload) {
        applyCommentPayload(payload);
        node.incrementCounter(`comments_made_${signer}`, 1, signer);
      }
      break;
    }
    default:
      break;
  }
}

function applyFlagEvent(userId) {
  if (!node.setContains('flaggers', userId)) {
    try {
      node.setAdd('flaggers', userId, `flag_${userId}`);
      node.incrementCounter('flag_count', 1, userId);
      node.setTime(Date.now());
      node.pruneExpiredTempAttrs();
    } catch (e) {
      console.warn('flag event apply failed', e);
    }
  }
}

function applyLocalComment(comment) {
  try {
    node.setAdd('comments', JSON.stringify(comment), `comment_${comment.id}`);
  } catch (e) {
    // Duplicate comment entries are harmless.
  }
  if (!commentsStore.find(c => c.id === comment.id)) {
    commentsStore.push(comment);
  }
}

function applyCommentPayload(payloadBuf) {
  try {
    const comment = JSON.parse(new TextDecoder().decode(payloadBuf));
    if (comment && comment.id) applyLocalComment(comment);
  } catch (e) {
    // Ignore malformed comment payloads.
  }
}

// ============================================================
// UI refresh
// ============================================================

function refreshUI() {
  const views = node.getCounter('views') || 0;
  const likes = node.getPNCounter('likes') || 0;
  const flags = node.getCounter('flag_count') || 0;
  const triggered = flags >= FLAG_THRESHOLD;

  document.getElementById('viewCount').textContent = `${views} view${views === 1 ? '' : 's'}`;
  document.getElementById('likes').textContent = Math.max(0, likes);
  document.getElementById('dislikes').textContent = Math.max(0, -likes);

  const triggerBadge = document.getElementById('triggerStatus');
  triggerBadge.textContent = triggered
    ? 'Flag threshold reached — contact info unlocked'
    : `Flag threshold: ${flags}/${FLAG_THRESHOLD}`;
  triggerBadge.classList.toggle('active', triggered);

  if (currentUser) {
    const vote = node.getRegister(`vote_${currentUser.userId}`) || 0;
    document.getElementById('likeBtn').classList.toggle('active', vote === 1);
    document.getElementById('dislikeBtn').classList.toggle('active', vote === -1);

    const subscribed = node.setContains('subscribers', currentUser.userId);
    const subBtn = document.getElementById('subscribeBtn');
    subBtn.textContent = subscribed ? 'Subscribed' : 'Subscribe';
    subBtn.classList.toggle('active', subscribed);

    const alreadyFlagged = node.setContains('flaggers', currentUser.userId);
    document.getElementById('flagBtn').disabled = alreadyFlagged || currentUser.age < 13;

    const u = node.getUser(currentUser.userId);
    const isMod = u && u.attributes.some(a => a.value === 'clearance:moderator');
    const hasInvestigator = u && u.attributes.some(a => a.value.startsWith('tos_investigator'));
    document.getElementById('contactBtn').classList.toggle('hidden', !(isMod && triggered && hasInvestigator));
  }

  renderComments();
}

function renderComments() {
  const list = document.getElementById('commentList');
  const sorted = commentsStore.slice().sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  list.innerHTML = sorted.map(c => `
    <div class="comment">
      <span class="user">${escapeHtml(c.user)}</span>
      <span class="time">${new Date(c.timestamp).toLocaleTimeString()}</span>
      <div class="text">${escapeHtml(c.text)}</div>
    </div>
  `).join('');
}

function escapeHtml(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

async function viewContact() {
  if (!currentUser) return;
  try {
    const res = await fetch('/contact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: currentUser.userId }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    document.getElementById('contactData').textContent = JSON.stringify(data.contactInfo, null, 2);
    document.getElementById('contactPanel').classList.remove('hidden');
  } catch (e) {
    showError(e.message);
  }
}

function showError(msg) {
  const el = document.getElementById('commentError') || document.getElementById('authError');
  if (el) {
    el.textContent = msg;
    setTimeout(() => { if (el.textContent === msg) el.textContent = ''; }, 5000);
  }
}

// ============================================================
// Base64 helpers (binary-safe in browsers)
// ============================================================

function base64ToBytes(str) {
  const bin = atob(str);
  const len = bin.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64(bytes) {
  const len = bytes.length;
  const chars = new Array(len);
  for (let i = 0; i < len; i++) {
    chars[i] = String.fromCharCode(bytes[i]);
  }
  return btoa(chars.join(''));
}

// ============================================================
// Exports
// ============================================================

module.exports = { init };
