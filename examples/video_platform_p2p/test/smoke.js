'use strict';

const http = require('http');
const WebSocket = require('ws');
const { KeyPair } = require('crabs-node');
const { MOD1_PRIVATE_KEY } = require('../demo_keys');

const FLAG_THRESHOLD = 3;
const modKey = KeyPair.fromPrivateHex(MOD1_PRIVATE_KEY);
const MOD1_USER_ID = modKey.publicKeyHex().slice(0, 63);

function postContact(userId) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ userId });
    const req = http.request({
      hostname: 'localhost',
      port: 5674,
      path: '/contact',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
    }, res => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => resolve({ status: res.statusCode, body: body ? JSON.parse(body) : null }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function send(ws, msg) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

(async () => {
  console.log('Opening WebSocket...');
  const ws = new WebSocket('ws://localhost:5674');
  await new Promise((resolve, reject) => {
    ws.on('open', resolve);
    ws.on('error', reject);
  });

  console.log('Contact before flags should be forbidden');
  const before = await postContact(MOD1_USER_ID);
  if (before.status !== 403) {
    throw new Error(`Expected 403 before flags, got ${before.status}: ${JSON.stringify(before.body)}`);
  }

  console.log('Sending flag events...');
  for (let i = 1; i <= FLAG_THRESHOLD; i++) {
    send(ws, { type: 'flag_event', userId: `flagger_${i}` });
  }

  // Give the server time to process the WebSocket messages and evaluate triggers.
  await new Promise(r => setTimeout(r, 1000));

  console.log('Contact after flags should succeed');
  const after = await postContact(MOD1_USER_ID);
  if (after.status !== 200) {
    throw new Error(`Expected 200 after flags, got ${after.status}: ${JSON.stringify(after.body)}`);
  }
  if (!after.body || !after.body.contactInfo || after.body.contactInfo.owner !== 'video_creator@example.com') {
    throw new Error(`Unexpected contact response: ${JSON.stringify(after.body)}`);
  }

  console.log('Contact for non-moderator should still be forbidden');
  const nonMod = await postContact('flagger_1');
  if (nonMod.status !== 403) {
    throw new Error(`Expected 403 for non-moderator, got ${nonMod.status}`);
  }

  ws.close();
  console.log('Smoke test passed');
})().catch(e => {
  console.error(e);
  process.exit(1);
});
