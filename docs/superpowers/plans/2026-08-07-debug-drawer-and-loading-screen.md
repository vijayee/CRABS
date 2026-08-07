# Debug drawer and WASM loading screen implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a global CRABS WASM loading screen and a real-time CRABS state debug drawer to the `examples/video_platform_p2p` browser demo, with Playwright coverage.

**Architecture:** The loading screen hides the auth screen until the WASM node is ready. The debug drawer is a right-side panel toggled from the topbar; it re-renders from `currentUser`, the video element, and `node.get*` calls whenever `refreshUI()` runs.

**Tech Stack:** Plain HTML/CSS/JS, existing CRABS WASM bindings, esbuild for bundling, Playwright for browser tests.

---

### Task 1: Add global WASM loading screen markup and styles

**Files:**
- Modify: `examples/video_platform_p2p/public/index.html`
- Modify: `examples/video_platform_p2p/public/styles.css`

- [ ] **Step 1: Add loading card markup**

In `public/index.html`, add a `#loadingScreen` section inside `#app`, between the topbar and `main`. It should contain a spinner and the text "Loading CRABS node…" plus an error area.

```html
<section id="loadingScreen" class="loading-screen">
  <div class="loading-card">
    <div class="spinner"></div>
    <p>Loading CRABS node…</p>
    <div id="loadingError" class="error hidden"></div>
    <button id="reloadBtn" class="hidden secondary">Reload</button>
  </div>
</section>
```

Also add `id="mainContent"` to the existing `<main>` element.

- [ ] **Step 2: Add loading screen CSS**

In `public/styles.css`, add styles for the loading screen, card, spinner, and hidden utility. Keep existing `.hidden` rule unchanged.

```css
.loading-screen {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: calc(100vh - 60px);
  padding: 24px;
}
.loading-card {
  background: #fff;
  padding: 40px;
  border-radius: 12px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.06);
  text-align: center;
  max-width: 360px;
  width: 100%;
}
.loading-card p {
  margin-top: 16px;
  color: #555;
  font-size: 15px;
}
.spinner {
  width: 40px;
  height: 40px;
  border: 4px solid #e1e2e5;
  border-top-color: #cc0000;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto;
}
@keyframes spin { to { transform: rotate(360deg); } }
```

- [ ] **Step 3: Commit**

```bash
git add examples/video_platform_p2p/public/index.html examples/video_platform_p2p/public/styles.css
git commit -m "feat(p2p-demo): add global WASM loading screen markup and styles"
```

---

### Task 2: Wire up loading screen in client.js

**Files:**
- Modify: `examples/video_platform_p2p/client.js`

- [ ] **Step 1: Wrap init in a try/catch that shows/hides the loading screen**

Locate the top-level `async function init()` at line 43. Modify it to call `setLoading(true)` at the start, then `setLoading(false)` on success, or `setLoadingError(error)` on failure.

```javascript
async function init() {
  setLoading(true);
  try {
    await seedDemoUsers();
    node = await Node.create('admin', { ordering: 'hlc' });
    await registerDemoUsers();
    initStateMachine();
    connectWebSocket();
    bindAuth();
    setLoading(false);
  } catch (e) {
    console.error('CRABS init failed', e);
    setLoadingError(e.message || 'Failed to initialize CRABS node');
  }
}
```

- [ ] **Step 2: Add loading helpers**

Add the following helper functions near the top of the file, after the `commentsStore` declaration:

```javascript
function setLoading(isLoading) {
  const loading = document.getElementById('loadingScreen');
  const main = document.getElementById('mainContent');
  if (!loading || !main) return;
  if (isLoading) {
    loading.classList.remove('hidden');
    main.classList.add('hidden');
  } else {
    loading.classList.add('hidden');
    main.classList.remove('hidden');
  }
}

function setLoadingError(msg) {
  const loading = document.getElementById('loadingScreen');
  const main = document.getElementById('mainContent');
  const errEl = document.getElementById('loadingError');
  const reloadBtn = document.getElementById('reloadBtn');
  if (loading) loading.classList.remove('hidden');
  if (main) main.classList.add('hidden');
  if (errEl) {
    errEl.textContent = msg;
    errEl.classList.remove('hidden');
  }
  if (reloadBtn) {
    reloadBtn.classList.remove('hidden');
    reloadBtn.onclick = () => window.location.reload();
  }
}
```

- [ ] **Step 3: Build and smoke test**

```bash
cd examples/video_platform_p2p
npm run build:client
npm run start
```

In another terminal or by visiting the URL, verify the page loads, shows "Loading CRABS node…" briefly, then the auth screen appears. Stop the server with Ctrl+C.

- [ ] **Step 4: Commit**

```bash
git add examples/video_platform_p2p/client.js
git commit -m "feat(p2p-demo): wire up global WASM loading screen"
```

---

### Task 3: Add debug drawer markup and styles

**Files:**
- Modify: `examples/video_platform_p2p/public/index.html`
- Modify: `examples/video_platform_p2p/public/styles.css`

- [ ] **Step 1: Add Debug button to topbar**

In `index.html`, inside `.topbar`, add a Debug button next to the status span. Keep the title and status in place.

```html
<header class="topbar">
  <h1>CRABS P2P Video</h1>
  <div class="topbar-actions">
    <button id="debugBtn" class="debug-btn hidden">Debug</button>
    <span id="connectionStatus" class="status">Connecting...</span>
  </div>
</header>
```

- [ ] **Step 2: Add drawer markup**

Add the drawer markup as the last child of `#app`, after the closing `</main>` tag.

```html
<div id="debugBackdrop" class="debug-backdrop hidden"></div>
<aside id="debugDrawer" class="debug-drawer hidden">
  <div class="drawer-header">
    <h2>CRABS Debug State</h2>
    <button id="debugClose" aria-label="Close">×</button>
  </div>
  <div class="drawer-body" id="debugBody">
    <p class="drawer-placeholder">Loading CRABS state…</p>
  </div>
</aside>
```

- [ ] **Step 3: Add drawer CSS**

Add to `styles.css`:

```css
.topbar-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}
.debug-btn {
  background: #f0f0f0;
  border: 1px solid #d1d2d5;
  color: #333;
  padding: 6px 12px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
}
.debug-btn:hover { background: #e6e6e6; }
.debug-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.4);
  z-index: 20;
}
.debug-drawer {
  position: fixed;
  top: 0;
  right: 0;
  width: 400px;
  max-width: 90vw;
  height: 100vh;
  background: #fff;
  box-shadow: -4px 0 20px rgba(0, 0, 0, 0.12);
  z-index: 21;
  display: flex;
  flex-direction: column;
}
.drawer-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  border-bottom: 1px solid #e1e2e5;
}
.drawer-header h2 { font-size: 16px; font-weight: 700; }
.drawer-header button {
  background: none;
  border: none;
  font-size: 24px;
  cursor: pointer;
  color: #666;
}
.drawer-body {
  flex: 1;
  overflow-y: auto;
  padding: 20px;
}
.drawer-section {
  margin-bottom: 24px;
}
.drawer-section h3 {
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #888;
  margin-bottom: 10px;
  border-bottom: 1px solid #f0f0f0;
  padding-bottom: 6px;
}
.drawer-dl {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 6px 12px;
  font-size: 13px;
}
.drawer-dl dt { color: #666; }
.drawer-dl dd { color: #1f1f1f; word-break: break-word; }
.drawer-dl dd ul { list-style: none; padding: 0; }
.drawer-dl dd li { margin-bottom: 2px; }
.drawer-placeholder { color: #888; font-size: 14px; }
```

- [ ] **Step 4: Commit**

```bash
git add examples/video_platform_p2p/public/index.html examples/video_platform_p2p/public/styles.css
git commit -m "feat(p2p-demo): add debug drawer markup and styles"
```

---

### Task 4: Implement debug drawer state rendering in client.js

**Files:**
- Modify: `examples/video_platform_p2p/client.js`

- [ ] **Step 1: Capture video element reference**

At the top of `client.js`, add:

```javascript
let videoEl = null;
```

In `showPlayer()`, add:

```javascript
videoEl = document.getElementById('videoPlayer');
```

- [ ] **Step 2: Add drawer open/close binding and helpers**

Add these functions after `bindAuth()`:

```javascript
function bindDebugDrawer() {
  const btn = document.getElementById('debugBtn');
  const close = document.getElementById('debugClose');
  const backdrop = document.getElementById('debugBackdrop');
  if (btn) btn.addEventListener('click', openDebugDrawer);
  if (close) close.addEventListener('click', closeDebugDrawer);
  if (backdrop) backdrop.addEventListener('click', closeDebugDrawer);
}

function openDebugDrawer() {
  document.getElementById('debugBackdrop')?.classList.remove('hidden');
  document.getElementById('debugDrawer')?.classList.remove('hidden');
  renderDebugDrawer();
}

function closeDebugDrawer() {
  document.getElementById('debugBackdrop')?.classList.add('hidden');
  document.getElementById('debugDrawer')?.classList.add('hidden');
}

function isDebugDrawerOpen() {
  return !document.getElementById('debugDrawer')?.classList.contains('hidden');
}
```

Call `bindDebugDrawer()` from `init()` after `bindAuth()`.

- [ ] **Step 3: Reveal Debug button on player screen**

In `showPlayer()`, add:

```javascript
document.getElementById('debugBtn')?.classList.remove('hidden');
```

- [ ] **Step 4: Implement renderDebugDrawer**

Add this function near `refreshUI()`:

```javascript
function renderDebugDrawer() {
  if (!isDebugDrawerOpen()) return;
  const body = document.getElementById('debugBody');
  if (!body) return;
  if (!node) {
    body.innerHTML = '<p class="drawer-placeholder">Loading CRABS state…</p>';
    return;
  }

  const sections = [];

  // Current User section
  let userHtml = '';
  if (!currentUser) {
    userHtml = '<p class="drawer-placeholder">Not logged in</p>';
  } else {
    const u = safeGet(() => node.getUser(currentUser.userId));
    const attrs = u?.attributes?.map(a => a.value).join(', ') || 'none';
    const subscribed = safeGet(() => node.setContains('subscribers', currentUser.userId), false);
    const flagged = safeGet(() => node.setContains('flaggers', currentUser.userId), false);
    userHtml = `
      <div class="drawer-section">
        <h3>Current User</h3>
        <dl class="drawer-dl">
          <dt>Name</dt><dd>${escapeHtml(currentUser.name)}</dd>
          <dt>Age</dt><dd>${currentUser.age}</dd>
          <dt>User ID</dt><dd>${escapeHtml(currentUser.userId)}</dd>
          <dt>Roles</dt><dd>${currentUser.age >= 13 ? 'adult' : 'underage'}${currentUser.name === 'mod1' ? ', moderator' : ''}</dd>
          <dt>Attributes</dt><dd>${escapeHtml(attrs)}</dd>
          <dt>Subscribed</dt><dd>${subscribed ? 'yes' : 'no'}</dd>
          <dt>Flagged</dt><dd>${flagged ? 'yes' : 'no'}</dd>
        </dl>
      </div>
    `;
  }
  sections.push(userHtml);

  // Video State section
  const video = videoEl || document.getElementById('videoPlayer');
  const playing = video ? !video.paused : false;
  const currentTime = video ? formatTime(video.currentTime || 0) : '0:00';
  const duration = video ? formatTime(video.duration || 0) : '0:00';
  const views = safeGet(() => node.getCounter('views'), 0);
  const ageGate = !document.getElementById('ageGate')?.classList.contains('hidden');
  sections.push(`
    <div class="drawer-section">
      <h3>Video State</h3>
      <dl class="drawer-dl">
        <dt>Title</dt><dd>Penguins in their natural habitat</dd>
        <dt>Playback</dt><dd>${playing ? 'playing' : 'paused'}</dd>
        <dt>Current time</dt><dd>${currentTime} / ${duration}</dd>
        <dt>Views</dt><dd>${views}</dd>
        <dt>Age gate visible</dt><dd>${ageGate ? 'yes' : 'no'}</dd>
      </dl>
    </div>
  `);

  // CRABS State section
  const likes = safeGet(() => node.getPNCounter('likes'), 0);
  const dislikes = Math.max(0, -likes);
  const flagCount = safeGet(() => node.getCounter('flag_count'), 0);
  const flags = safeGet(() => knownSetMembers('flaggers'), []);
  const subscribers = safeGet(() => knownSetMembers('subscribers'), []);
  const comments = commentsStore.slice(0, 10);
  const triggered = flagCount >= FLAG_THRESHOLD;
  sections.push(`
    <div class="drawer-section">
      <h3>CRABS State</h3>
      <dl class="drawer-dl">
        <dt>Likes</dt><dd>${Math.max(0, likes)}</dd>
        <dt>Dislikes</dt><dd>${dislikes}</dd>
        <dt>Flag count</dt><dd>${flagCount}</dd>
        <dt>Threshold</dt><dd>${triggered ? 'reached' : `${flagCount}/${FLAG_THRESHOLD}`}</dd>
        <dt>Flaggers</dt><dd>${flags.length ? '<ul><li>' + flags.map(escapeHtml).join('</li><li>') + '</li></ul>' : 'none'}</dd>
        <dt>Subscribers</dt><dd>${subscribers.length ? '<ul><li>' + subscribers.map(escapeHtml).join('</li><li>') + '</li></ul>' : 'none'}</dd>
        <dt>Comments</dt><dd>${comments.length}
          ${comments.length ? '<ul><li>' + comments.map(c => escapeHtml(`${c.user}: ${c.text}`)).join('</li><li>') + '</li></ul>' : ''}
        </dd>
      </dl>
    </div>
  `);

  body.innerHTML = sections.join('');
}

function safeGet(fn, fallback = 'unavailable') {
  try { return fn(); } catch (e) { return fallback; }
}

function knownSetMembers(setName) {
  const found = [];
  for (const demo of DEMO_ACCOUNTS) {
    const u = localUsers.get(demo.name);
    if (!u) continue;
    try {
      if (node.setContains(setName, u.userId)) found.push(demo.name);
    } catch (e) { /* ignore */ }
  }
  return found;
}

function formatTime(seconds) {
  const s = Math.floor(seconds % 60);
  const m = Math.floor(seconds / 60);
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}:${String(m % 60).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  return `${m}:${String(s).padStart(2, '0')}`;
}
```

- [ ] **Step 5: Re-render drawer when UI refreshes**

At the end of `refreshUI()`, add:

```javascript
renderDebugDrawer();
```

- [ ] **Step 6: Build and run the app**

```bash
cd examples/video_platform_p2p
npm run build:client
npm run start
```

Open http://localhost:5674 in a browser, log in as `alice`, click Debug, and verify the drawer shows user, video, and CRABS state. Stop the server.

- [ ] **Step 7: Commit**

```bash
git add examples/video_platform_p2p/client.js
git commit -m "feat(p2p-demo): implement debug drawer state rendering"
```

---

### Task 5: Add Playwright test for the debug drawer

**Files:**
- Modify: `examples/video_platform_p2p/test/playwright.spec.js`

- [ ] **Step 1: Write the failing test**

Add a new test at the end of the file, before any closing braces:

```javascript
test('debug drawer shows current user and CRABS video state', async ({ page }) => {
  await login(page, 'alice', 25);

  await page.locator('#debugBtn').click();
  await expect(page.locator('#debugDrawer')).not.toHaveClass(/hidden/);

  const body = page.locator('#debugBody');
  await expect(body).toContainText('alice');
  await expect(body).toContainText('Penguins in their natural habitat');
  await expect(body).toContainText('Flag threshold: 0/3');

  await page.locator('#debugClose').click();
  await expect(page.locator('#debugDrawer')).toHaveClass(/hidden/);
});
```

- [ ] **Step 2: Run it to verify it fails before implementation**

This step is not applicable because the implementation in Task 4 already exists. Run the full suite to verify the new test passes.

```bash
cd examples/video_platform_p2p
npm run test:browser
```

Expected: all 4 tests pass.

- [ ] **Step 3: Commit**

```bash
git add examples/video_platform_p2p/test/playwright.spec.js
git commit -m "test(p2p-demo): add debug drawer Playwright test"
```

---

### Task 6: Final verification

**Files:**
- All of the above.

- [ ] **Step 1: Run full Playwright suite**

```bash
cd examples/video_platform_p2p
npm run test:browser
```

Expected output:

```
Running 4 tests using 1 worker
...
  4 passed
```

- [ ] **Step 2: Manual spot check**

Start the server (`npm run start`), log in as `alice` and `bob` in two tabs, like/comment/subscribe/flag, and confirm the debug drawer updates in real time for both users. Stop the server.

- [ ] **Step 3: Mark task complete**

No commit needed if tests already passed.

---

## Spec coverage self-review

| Spec requirement | Task |
|---|---|
| Global WASM loading screen with spinner | Task 1, Task 2 |
| Loading screen hides auth screen until ready | Task 2 |
| Init failure shows error and reload button | Task 2 |
| Debug button in topbar | Task 3, Task 4 |
| Right-side drawer with backdrop and close | Task 3, Task 4 |
| Current User section | Task 4 |
| Video State section | Task 4 |
| CRABS State section | Task 4 |
| Live updates via refreshUI | Task 4 |
| Error handling per section | Task 4 (safeGet) |
| Playwright test for drawer | Task 5 |
