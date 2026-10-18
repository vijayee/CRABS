# Fix: CRABS HLC bounded-skew rejection makes >5s replays permanently blind nodes

> Agent handoff brief, 2026-10-17. Authored from the ResonantDAO Example feed-page verification
> session (F7); the consumer-side verification walk hit this deterministically.

## Context

Two-repo layout:
- **CRABS library** (this repo): C-based replicated state machine compiled to WASM, consumed via
  `addFunction` trampolines and JSON in/out.
- **Consumer**: `ResonantDAO Example` (sibling repo, `../ResonantDAO Example`) — a Vue client +
  Node server. Its headless e2e is `test-voting-browser.js`; its new feed verification walk is
  `scripts/feed-walk.mjs`.

Signed ops are authored on a client, which stamps each op with a Hybrid Logical Clock (HLC)
derived from JS `Date.now()`. Other nodes materialize state by **re-executing ops from the op
log** ("replay"), and also apply live-broadcast ops from already-connected peers.

## Symptom (reproduce any time)

From the Example repo, fresh state, both servers up:

```bash
WAVEDB_PATH=/tmp/dao-repro npm run dev:server &
npm run dev:client &
node scripts/feed-walk.mjs
```

Deterministic failure: the second client (registers ~15s after the first op's authorship) replays
the log, hits `execute: protocol_violation` on the *first* replayed op, and its entire replay
aborts — the node is blind to all earlier state. The main e2e (`node test-voting-browser.js`)
passes only because its pages register within ~3s or act on live-broadcast state; a 4th page
registering ~15s in hits the same violation there — this is latent, not walk-specific.

Side effect worth knowing: the Example client's `register()` path overwrites the status with
"Registered and logged in." after the failed replay, masking the outage. Server-side hydration
(`Example/server/src/server.ts:51`, `hydrateDao`) *skips* invalid ops and continues, so client and
server tolerance semantics already diverge.

## Root cause (leads — verify before acting)

- HLC is configured with the **BOUNDED skew strategy, `max_skew_ms = 5000`**:
  `src/HLC/hlc.c:134` (constant/config) and `hlc.c:410-422` (strategy application).
- A received op whose HLC is more than 5s older than the receiver's local clock is treated as
  "time travel" and rejected: probe at `src/state_machine.c:683-691` →
  `CRABS_ERR_PROTOCOL_VIOLATION`.
- The consumer's vendored wrapper (`Example/client/src/crabs-wasm-wrapper.ts`) calls
  `Node.create`, and **that constructor currently ignores its options argument** — so even a
  correctly configured consumer cannot widen the window. That plumb-through may itself be part
  of the fix surface.

## Security implications (why not just `max_skew_ms = ∞`)

1. **The current guard is not a trust boundary — do not treat relaxing it as closing a vuln.**
   Clients sign their own ops and stamp their own HLC, so a misbehaving client can already emit
   arbitrary timestamps; the 5s window only protects against *well-behaved clocks running slow*.
2. **The real (current) vulnerability is state divergence.** Reject-entirely-on-one-node,
   skip-and-continue-on-another means nodes that replay the same log end up in *different*
   materialized states. For a consensus/CRDT ledger the convergence invariant is the security
   property; the status-masking on the client means users see "logged in" while holding a
   divergent, silent subset of state. Silent divergence is arguably worse than loud corruption.
3. **Risk of the naive fix:** accepting arbitrarily old HLCs lets clock regressions poison HLC
   ordering (HLC exists to preserve causal ordering; garbage-in corrupts ordering for
   everything downstream, including conflict resolution and audit trails). The fix must bound
   the damage while tolerating old ops.

## Required fix

1. **Make HLC configuration reachable through the public API** so consumers can set (at minimum)
   the skew strategy and `max_skew_ms` when creating a node. Default behavior must remain
   byte-compatible with today's (BOUNDED / 5000ms) for existing consumers that don't opt in.
2. **Separate live-op skew policy from replay-op skew policy.** A replay of historic ops is a
   *bulk history ingest*, not a freshness race — the 5s clock-skew attack surface doesn't apply.
   Recommended: allow a consumer-configurable `replay` policy, where out-of-window (older) HLCs
   are **clamped into the local HLC domain** (adopt max(local, received) and log a WARN) instead
   of rejected, while ops stamped in the *future* beyond the window remain hard errors from both
   paths. Keep BOUNDED-reject as the live-path default.
3. **Clamp, don't stretch, inside the HLC core:** never let a received historic HLC regress the
   local HLC or pollute ordering beyond the clamp event itself; document the ordering caveat.
4. **Error hygiene:** out-of-window replay ops must not abort the whole replay — emit a per-op
   diagnostic (with op id/signer/stamp) and continue, so consumers can converge by design rather
   than by skip-lists.

## Acceptance criteria

- A CRABS unit/integration test reproduces the walk scenario: op authored at T, replayed at
  T+15s by a fresh node with the replay policy set → op materializes (clamped), WARN emitted,
  local HLC monotonic, subsequent ops order correctly (assert with explicit HLC expectations).
- A second test asserts the *default* configuration is unchanged: live-op at T-15s still yields
  `CRABS_ERR_PROTOCOL_VIOLATION`.
- A third test: future-stamped op (T+15s) rejected on BOTH paths.
- The Example repo's `scripts/feed-walk.mjs` passes end-to-end after the wrapper passes the new
  options (that consumer-side follow-up happens in the Example repo — make sure the API
  contract you ship is what the vendored wrapper can consume: document the exact options schema
  in your PR description).
- No change to op signature validation, membership/authorization checks, or op-payload
  interpretation — timestamp policy only.