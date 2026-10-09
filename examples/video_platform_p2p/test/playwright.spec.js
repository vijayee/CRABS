//
// playwright.spec.js — Browser-level smoke tests for the CRABS P2P video
// platform demo. Spawns the real server, opens Chromium tabs, logs in as demo
// users, and verifies cross-tab state, age restriction, and flag threshold.
//

const { test, expect } = require('@playwright/test');
const { spawn } = require('child_process');
const path = require('path');

let server;

const PORT = 5674;
const BASE_URL = `http://localhost:${PORT}`;

test.beforeAll(async () => {
  server = spawn('node', ['server.js'], { cwd: path.join(__dirname, '..'), env: process.env });
  await new Promise((resolve, reject) => {
    let resolved = false;
    const onData = (data) => {
      const text = data.toString();
      // eslint-disable-next-line no-console
      console.log('server:', text.trim());
      if (!resolved && text.includes('CRABS P2P Video Platform')) {
        resolved = true;
        resolve();
      }
    };
    const onErr = (data) => {
      // eslint-disable-next-line no-console
      console.error('server stderr:', data.toString().trim());
    };
    server.stdout.on('data', onData);
    server.stderr.on('data', onErr);
    server.on('error', (err) => {
      if (!resolved) reject(err);
    });
    setTimeout(() => {
      if (!resolved) reject(new Error('server start timeout'));
    }, 30000);
  });
  // Give the HTTP/WebSocket stack a moment to settle.
  await new Promise((r) => setTimeout(r, 1000));
});

test.afterAll(() => {
  if (server) {
    server.kill();
    // Force-kill if graceful shutdown stalls.
    setTimeout(() => server.kill('SIGKILL'), 5000);
  }
});

async function setupConsoleCapture(page) {
  page.on('console', (msg) => {
    // eslint-disable-next-line no-console
    console.log(`[browser ${page.url()} ${msg.type()}]`, msg.text());
  });
  page.on('pageerror', (err) => {
    // eslint-disable-next-line no-console
    console.error(`[browser ${page.url()} pageerror]`, err.message);
  });
}

async function login(page, name, age) {
  await setupConsoleCapture(page);
  await page.goto(BASE_URL);
  // Wait for the WASM loading screen to disappear before interacting.
  await page.locator('#loadingScreen').waitFor({ state: 'hidden', timeout: 30000 });
  // Wait for the WASM bundle to load and present the auth screen.
  await expect(page.locator('#authScreen')).not.toHaveClass(/hidden/);
  await page.locator('#authName').fill(name);
  await page.locator('#authAge').fill(String(age));
  await page.locator('#loginBtn').click();
  await page.locator('#connectionStatus').filter({ hasText: 'Connected' }).waitFor({ timeout: 15000 });
  await expect(page.locator('#playerScreen')).not.toHaveClass(/hidden/);
  // Wait a moment for the login register_user broadcast to reach peers.
  await page.waitForTimeout(1500);
}

test('adult users can like and comment, and changes propagate across tabs', async ({ browser }) => {
  const alice = await browser.newPage();
  const bob = await browser.newPage();
  try {
    await login(alice, 'alice', 25);
    await login(bob, 'bob', 30);

    await expect(alice.locator('#likes')).toHaveText('0');
    await expect(bob.locator('#likes')).toHaveText('0');

    await alice.locator('#likeBtn').click();
    await expect(alice.locator('#likeBtn')).toHaveAttribute('class', /active/);
    await expect(alice.locator('#likes')).toHaveText('1');

    // Wait for the operation to round-trip through the WebSocket relay.
    await bob.locator('#likes').filter({ hasText: '1' }).waitFor({ timeout: 10000 });

    await alice.locator('#commentText').fill('Hello from Alice');
    await alice.locator('#postCommentBtn').click();
    await expect(alice.locator('.comment .text')).toHaveText('Hello from Alice');

    await bob.locator('.comment .text').filter({ hasText: 'Hello from Alice' }).waitFor({ timeout: 10000 });

    // Subscription is per-user: Alice subscribing only changes Alice's UI.
    await alice.locator('#subscribeBtn').click();
    await expect(alice.locator('#subscribeBtn')).toHaveText('Subscribed');
    await expect(alice.locator('#subscribeBtn')).toHaveAttribute('class', /active/);
    await expect(bob.locator('#subscribeBtn')).toHaveText('Subscribe');

    // Bob subscribing changes Bob's UI and leaves Alice's unchanged.
    await bob.locator('#subscribeBtn').click();
    await expect(bob.locator('#subscribeBtn')).toHaveText('Subscribed');
    await expect(bob.locator('#subscribeBtn')).toHaveAttribute('class', /active/);
    await expect(alice.locator('#subscribeBtn')).toHaveText('Subscribed');

    // Unsubscribe is also per-user.
    await alice.locator('#subscribeBtn').click();
    await expect(alice.locator('#subscribeBtn')).toHaveText('Subscribe');
    await expect(alice.locator('#subscribeBtn')).not.toHaveAttribute('class', /active/);
    await expect(bob.locator('#subscribeBtn')).toHaveText('Subscribed');
  } finally {
    await alice.close();
    await bob.close();
  }
});

test('users under 12 cannot play the video or engage', async ({ page }) => {
  await login(page, 'carol', 10);

  // Age gate is visible and engagement controls are disabled.
  await expect(page.locator('#ageGate')).not.toHaveClass(/hidden/);
  await expect(page.locator('#likeBtn')).toBeDisabled();
  await expect(page.locator('#dislikeBtn')).toBeDisabled();
  await expect(page.locator('#subscribeBtn')).toBeDisabled();
  await expect(page.locator('#flagBtn')).toBeDisabled();
  await expect(page.locator('#postCommentBtn')).toBeDisabled();
  await expect(page.locator('#commentText')).toBeDisabled();

  // The video player has no controls for under-age users.
  await expect(page.locator('#videoPlayer')).not.toHaveAttribute('controls');
});

test('three flags unlock contact info for the moderator', async ({ browser }) => {
  const alice = await browser.newPage();
  const bob = await browser.newPage();
  const mod = await browser.newPage();
  try {
    await login(alice, 'alice', 25);
    await login(bob, 'bob', 30);
    await login(mod, 'mod1', 40);

    await expect(mod.locator('#triggerStatus')).toHaveText(/Flag threshold: 0\/3/);
    await expect(mod.locator('#contactBtn')).toHaveClass(/hidden/);

    await alice.locator('#flagBtn').click();
    await bob.locator('#flagBtn').click();
    await mod.locator('#flagBtn').click();

    await mod.locator('#triggerStatus').filter({ hasText: /threshold reached/ }).waitFor({ timeout: 10000 });
    await expect(mod.locator('#contactBtn')).not.toHaveClass(/hidden/);

    await mod.locator('#contactBtn').click();
    await expect(mod.locator('#contactPanel')).not.toHaveClass(/hidden/);
    await expect(mod.locator('#contactData')).toContainText('video_creator@example.com');
    await expect(mod.locator('#contactData')).toContainText('+1-555-0123');
  } finally {
    await alice.close();
    await bob.close();
    await mod.close();
  }
});

test('debug drawer shows current user and CRABS video state', async ({ page }) => {
  await login(page, 'alice', 25);

  await page.locator('#debugBtn').click();
  await expect(page.locator('#debugDrawer')).not.toHaveClass(/hidden/);

  const body = page.locator('#debugBody');
  await expect(body).toContainText('alice');
  await expect(body).toContainText('Penguins in their natural habitat');
  await expect(body).toContainText(/Threshold.*0\/3/);

  await page.locator('#debugClose').click();
  await expect(page.locator('#debugDrawer')).toHaveClass(/hidden/);
});

test('sovereign check-ins: owner writes, impersonation is rejected, domain pill renders in both tabs', async ({ browser }) => {
  const alice = await browser.newPage();
  const bob = await browser.newPage();
  try {
    await login(alice, 'alice', 25);
    await login(bob, 'bob', 30);

    // The owner's signed ops claim the live chain head each time and advance
    // the per-user sovereign counter.
    await expect(alice.locator('#myCheckins')).toHaveText('0 check-ins');
    await alice.locator('#checkinBtn').click();
    await expect(alice.locator('#myCheckins')).toHaveText('1 check-in');
    await alice.locator('#checkinBtn').click();
    await expect(alice.locator('#myCheckins')).toHaveText('2 check-ins');

    // A well-formed check-in naming another user's item is rejected with
    // not_item_writer; the typed error surfaces in the UI.
    await alice.locator('#attackCheckinBtn').click();
    await expect(alice.locator('#checkinError')).toContainText('not_item_writer');

    // Devtools (CRABS launcher, bottom-right): every checkins_* item row
    // carries the domain pill with its chain seq — in BOTH tabs, since the
    // relayed ops advance bob's machine too.
    await alice.locator('crabs-devtools .toggle').click();
    await bob.locator('crabs-devtools .toggle').click();

    const alicePills = alice.locator('crabs-devtools .layer-pill').filter({ hasText: /^sovereign$/ });
    await expect(alicePills.first()).toBeVisible();
    // Alice's own row reads seq 2 after her two accepted writes.
    const aliceChainRow = alice.locator('crabs-devtools [data-item-name^="checkins_"]')
      .filter({ hasText: 'seq 2' });
    await expect(aliceChainRow).toHaveCount(1);

    // Bob's tab renders the same pills, and alice's chain there reaches
    // seq 2 once her ops have replicated through the relay.
    const bobPills = bob.locator('crabs-devtools .layer-pill').filter({ hasText: /^sovereign$/ });
    await expect(bobPills.first()).toBeVisible();
    const bobChainRow = bob.locator('crabs-devtools [data-item-name^="checkins_"]')
      .filter({ hasText: 'seq 2' });
    await expect(bobChainRow).toHaveCount(1, { timeout: 10000 });
  } finally {
    await alice.close();
    await bob.close();
  }
});
