# CRABS P2P Video Platform Design

## Date

2026-08-06

## Status

Approved design, ready for implementation planning.

## Goal

Build a truly peer-to-peer video platform demo in `examples/video_platform_p2p/`.
Each browser tab runs a full CRABS node via the new `crabs-wasm` build, signs
operations locally, and streams them to all other tabs through a minimal Node.js
WebSocket relay. The shared video state machine lives in every peer. A real
`penguin.mp4` replaces the dummy player. The UI is video-platform-centric.

The demo also demonstrates attribute-based authorization in the negative: users
under 12 register with an `age:<age>` attribute and are blocked from viewing or
interacting with the video by state-machine policies.

## Scope

- New `examples/video_platform_p2p/` directory; the existing
  `examples/video_platform/` demo remains untouched for comparison.
- Expand `crabs-wasm` JS wrapper to parity with `crabs-node` for the API
  surface used by the demo.
- Browser peer runs the full CRABS state machine in WASM.
- Server is a WebSocket relay and static file server; it also holds ABE-encrypted
  contact info and exposes a decrypt endpoint gated by attributes.
- Simple login/register flow; no password validation.
- Age-based content restriction (`age >= 13`).
- Real video playback with view-counting.

## Out of Scope

- Persistence across page reloads.
- Offline catch-up / state snapshots on reconnect.
- Production-grade identity or key management.
- Tests beyond manual smoke tests for the example.

## Architecture

```
┌─────────────────┐       WebSocket         ┌─────────────────┐
│  Browser Tab 1  │  <───operation──────>  │  Browser Tab 2  │
│  (crabs-wasm)   │                         │  (crabs-wasm)   │
│   user: alice   │                         │   user: bob     │
└─────────────────┘                         └─────────────────┘
         ^                                          ^
         │                                          │
         └──────────────────┬───────────────────────┘
                            │
                    ┌────────▼────────┐
                    │  Node.js Server │
                    │  WebSocket relay│
                    │  + static files │
                    │  + /contact ABE │
                    └─────────────────┘
```

### Components

1. **`crabs-wasm` JS wrapper** (`bindings/wasm/index.js`, `index.d.ts`)
   - `KeyPair.generate()`, `fromPrivateHex()`, `derivePublicHex()`.
   - `Operation.create(type)` with `signerId`, `nodeId`, `payload`, `lamportTime`.
   - `Node.create(adminId, opts)` with the same API shape as `crabs-node`:
     user management, state setup, CRDT operations, policies, `execute`,
     `sign` (HLC + signature), `createTrigger`, `encrypt`, `serialize`,
     `setTime`, `pruneExpiredTempAttrs`, `destroy`.
   - Function signatures match `crabs-node` so the demo code can be reasoned
     about in both environments.

2. **`examples/video_platform_p2p/server.js`**
   - Static file server for `index.html`, `client.js`, `crabs.js`, `crabs.wasm`,
     and `penguin.mp4`.
   - WebSocket relay: assigns a peer ID, broadcasts `peer_joined`, and forwards
     `operation` and `register_user` messages to all other sockets.
   - In-memory Node.js CRABS node used only for ABE: encrypts contact info at
     startup under policy `tos_investigator`.
   - `POST /contact` accepts `{ publicKey }`, checks whether that user has the
     `tos_investigator` attribute in the server's state machine, decrypts, and
     returns JSON.

3. **`examples/video_platform_p2p/public/index.html`**
   - Auth screen: name and age inputs, "Register" and "Login" buttons.
     Password field optional/ignored for the demo.
   - Main player screen: real `<video>` player for `penguin.mp4`, engagement
     stats, like/dislike/subscribe/flag/comment actions, comment thread.
   - Under-12 users see a clear message and cannot play the video or use
     engagement actions.
   - Video-platform-centric styling (clean, modern streaming UI).

4. **`examples/video_platform_p2p/public/client.js`**
   - Loads `crabs-wasm` and creates a local Node in HLC mode.
   - Initializes the shared video state machine (counters, PN-counter, OR-set,
     one-shot sets/flags, registers, policies, threshold trigger).
   - Pre-seeds demo accounts: `alice` (25), `bob` (30), `carol` (10, blocked),
     `mod1` (40, moderator).
   - On **Register**: generates a keypair, registers locally, broadcasts
     `{ type: 'register_user', name, userId, publicKeyHex, age, role: 'member' }`
     so every peer can register the same identity locally. The public key hex is
     the CRABS `userId`; `name` is only a display label.
   - On **Login**: selects from a dropdown of registered/demo users by `name`;
     loads the corresponding keypair. No password check.
   - On local action: creates, signs, and executes an operation locally, then
     serializes it and sends it over WebSocket.
   - On incoming operation: deserializes and executes it on the local node,
     then refreshes the UI.
   - On **View Contact Info**: if the local user has `tos_investigator`, calls
     `POST /contact`.

## Data Flow

### Bootstrap

1. Server starts, initializes a Node.js CRABS node, and ABE-encrypts contact
   info under `tos_investigator`.
2. Each browser tab loads the WASM module, creates a Node, and initializes the
   same state machine configuration as every other peer.
3. Tab connects to the WebSocket.

### Register / Login

- **Register**: user enters `name` + `age`. Client generates a `KeyPair`. The
  public key hex becomes the CRABS `userId`. The client sends
  `{ type: 'register_user', name, userId, publicKeyHex, age, role: 'member' }`.
  Every peer calls
  `node.registerUser(userId, publicKeyHex, 'role:member,age:<age>')`.
- **Login**: user enters `name`. Client searches its local user store. If found,
  it becomes that user. Pre-seeded demo accounts are always available.
- After login, the UI checks the age policy and either shows the full player
  or the under-12 restriction screen.

### Local Engagement Action (e.g. Like)

1. User clicks **Like**.
2. Client creates `Operation` type `like`, sets `signerId`, sets `nodeId` to the
   current user, and calls `node.sign(op, keyPair)` which stamps HLC and signs.
3. Local node executes `node.execute(op)`.
4. Client serializes the operation with `crabs_serialize_operation`, base64
   encodes it, and sends `{ type: 'operation', payload: '<base64>' }` over
   WebSocket.
5. Server broadcasts to all other sockets.

### Incoming Operation

1. Peer receives the message.
2. Deserializes bytes into an `operation_t*` via
   `crabs_deserialize_operation`.
3. Executes `node.execute(op)` on the reconstructed operation.
4. CRABS signature verification, policy checks, and idempotency handling keep
   all peer states consistent.
5. UI refreshes from local state.

### Contact Info Decryption

- When `flag_count >= threshold`, the trigger in every peer's state issues
  `tos_investigator` to users with `clearance:moderator`.
- The server also receives and applies operations, so its state machine reaches
  the threshold.
- A moderator peer clicks **View Contact Info**, sending `POST /contact` with
  their `publicKey`.
- Server checks the user's attributes; if `tos_investigator` is present, it
  decrypts the pre-encrypted contact info and returns it.

### Video Playback and View Count

- The dummy player is replaced with a real `<video src="/penguin.mp4" controls>`.
- A `view` operation is emitted once per session when the user clicks play,
  guarded by a local one-shot flag so replaying does not inflate the count.
- Users under 12 cannot start playback; the restriction is enforced both by the
  disabled UI and by the state-machine `view` policy.

## State Machine Configuration

All peers initialize the same state machine:

- Counters: `views`
- PN-Counter: `likes` (pos = likes, neg = dislikes)
- OR-Set: `subscribers`, `comments`
- One-Shot Set: `flaggers`
- Counter: `flag_count`
- One-Shot Flag: per-session view flag (local only, not synchronized)
- Registers per user: `vote_<userId>`, `comments_made_<userId>`,
  `replies_received_<userId>` (where `userId` is the public key hex)

Policies:

- `view`, `like`, `dislike`, `subscribe`, `unsubscribe`, `comment`, `reply`,
  `flag`: `role:member AND age:13+`
- `__create_trigger__`, `__change_config__`, `__define_operation__`: `role:admin`

Threshold trigger:

- `triggerId`: `tos_threshold`
- `condition`: `flag_count >= 3`
- `effectType`: `issue_attribute`
- `issueAttribute`: `tos_investigator`
- `targetRole`: `clearance`
- `attributeValue`: `verified`
- `durationMs`: 3600000
- `cooldownMs`: 60000

## Error Handling

| Situation | Handling |
|---|---|
| Duplicate operation from multiple peers | CRABS deduplicates by operation UUID; peers silently ignore. |
| Out-of-order arrival | HLC ordering resolves causal order deterministically. |
| Unsigned or bad-signature operation | `state_machine_execute` returns unauthorized; logged and ignored. |
| Under-age action | Policy check fails; UI shows a clear unauthorized message. |
| User not found on login | UI shows an error; no crash. |
| WASM module load failure | UI shows a clear error message. |
| Server disconnect | UI shows disconnected status; operations queue locally until reconnect (best-effort for demo). |
| Contact endpoint without attribute | Server returns 403. |

## UI Design Direction

- Move away from the current dark hacker/console theme.
- Light/neutral modern video-platform look.
- Large video player as the focal point.
- Engagement row directly under the player: title, views, like/dislike bar,
  subscribe button.
- Comments section below, threaded.
- Clear under-12 restriction banner when applicable.
- Trigger status and moderator contact button in a small info panel.

## Manual Test Plan

1. Open two tabs. Register/login as `bob` and `alice` (age >= 13). Like and
   comment in one tab; verify the other tab updates.
2. Open a third tab, login as `carol` (age 10). Verify video is blocked and
   action buttons disabled/unauthorized.
3. With three distinct adult users, flag the video three times. Verify trigger
   status shows threshold reached in all tabs.
4. Login as `mod1` in a tab, click **View Contact Info**, verify decrypted
   contact info appears.

## Dependencies

- `crabs-wasm` package with expanded JS wrapper.
- `ws` WebSocket library for the Node server.
- `http` module for static serving.
- Existing `penguin.mp4` reused from `examples/video_platform/`.

## Risks

- WASM wrapper parity may require careful struct offset and pointer work.
- HLC timestamps must be stamped before signing and identical handling across
  wrapper and native bindings.
- Base64 serialization of operations needs to preserve binary exactly.
