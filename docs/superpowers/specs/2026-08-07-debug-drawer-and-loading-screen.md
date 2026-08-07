# Debug drawer and WASM loading screen for P2P video demo

## Goal

Add a real-time CRABS state debug drawer to the `examples/video_platform_p2p` browser demo, plus a global loading screen that appears while the CRABS WASM node is initializing.

## Scope

- UI changes in `examples/video_platform_p2p/public/index.html` and `styles.css`.
- Behavior changes in `examples/video_platform_p2p/client.js`.
- New Playwright test in `examples/video_platform_p2p/test/playwright.spec.js`.

## User-visible behavior

### Global WASM loading screen

- On page load the user sees a centered card reading "Loading CRABS node…" with a spinner.
- The topbar title remains visible.
- Once `Node.create()` and the initial state-machine setup finish, the loading card is hidden and the auth screen is shown.
- If initialization fails, the card shows the error and a "Reload" button.

### Debug drawer

- A "Debug" button appears in the topbar on the player screen.
- Clicking it opens a 400px right-side drawer over a semi-transparent backdrop.
- The drawer contains three sections:
  1. **Current User** — name, age, userId, roles (adult/underage, moderator), current CRABS attributes, subscription state, flagged status.
  2. **Video State** — playing/paused, currentTime/duration, view count, age-gate visible.
  3. **CRABS State** — counters (views, likes, dislikes, flag_count), set summaries (subscribers count + known demo users subscribed; flaggers count + list), comments count/list, trigger threshold status.
- Data updates live whenever `refreshUI()` runs, so numbers change in real time while the drawer is open.
- Clicking the backdrop or an X button closes the drawer.

## Data sources

| Field | Source |
|---|---|
| User name/age | `currentUser` object in `client.js` |
| CRABS attributes | `node.getUser(currentUser.userId)` |
| Subscription state | `node.setContains('subscribers', currentUser.userId)` |
| Flagged state | `node.setContains('flaggers', currentUser.userId)` |
| Video playback | `<video>` element `paused`, `currentTime`, `duration` properties |
| Views/likes/flags | `node.getCounter` / `node.getPNCounter` |
| Subscriber/flagger list | `DEMO_ACCOUNTS` iterated, checking `node.setContains` for each userId |
| Comments | `commentsStore` length and first N entries |
| Threshold status | `flag_count >= FLAG_THRESHOLD` |

## Error handling

- If the drawer is opened before login, show "Not logged in".
- If the WASM node is not ready, show "Loading CRABS state…".
- Each section catches its own query errors and renders `unavailable` for that value.
- Initialization failure renders an error in the loading card with a reload button.

## Testing

- Add a Playwright test that logs in as `alice`, opens the debug drawer, and asserts the drawer contains her name, the video title, and the threshold text.
- Existing tests must continue to pass.

## Files changed

- `examples/video_platform_p2p/public/index.html`
- `examples/video_platform_p2p/public/styles.css`
- `examples/video_platform_p2p/client.js`
- `examples/video_platform_p2p/test/playwright.spec.js`
