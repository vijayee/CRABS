# CRABS Devtools: State Machine Viewer — Design

Date: 2026-09-01
Status: Approved design, pending implementation plan

## Goal

A browser-based devtools panel for inspecting CRABS state machines when running
the WASM build: per-item protocol states (IDLE / LOCKED / MODIFIED / VERIFIED /
ERROR), a live operation/audit timeline, current CRDT values, and the
configuration (policies, triggers, users) the machine consults.

## Decisions made

- **Form:** Hybrid — a reusable embedded panel shipped in the bindings, designed
  so it can be reused in a Chrome DevTools extension later.
- **Data flow:** Event stream + snapshots. A C-side recorder appends an event per
  executed operation (accepted or rejected); the panel drains events and pulls
  state snapshots.
- **Generality:** Generic reusable package, dogfooded in a dedicated demo page.
  The video_platform example is untouched (it runs CRABS via Node bindings
  server-side, so an in-browser panel cannot observe it).
- **UI tech:** Vanilla zero-dependency web component (`<crabs-devtools>`), no
  build step.
- **Layout:** Tabbed panel (Chrome DevTools style): States · Timeline · CRDT ·
  Config.
- **Styling:** Light theme only. Direction: "soft & friendly" — rounded corners,
  pill badges, subtle shadows, pastel status colors. No dark mode.

## Architecture

```
┌─ C (compiled into WASM) ──────────────────────────────┐
│ src/Devtools/devtools.c + devtools.h                  │
│  • Fixed-size ring buffer of event records (1024)     │
│  • devtools_record_event(state, op, result, reason)   │
│  • devtools_snapshot_json(state_t*) → char*           │
│  • devtools_events_json(...) → char* (drain buffer)   │
└──────────────┬────────────────────────────────────────┘
               │  called from crabs_wasm_execute (one line,
               │  #ifdef CRABS_ENABLE_DEVTOOLS)
┌─ JS bindings ─▼───────────────────────────────────────┐
│ bindings/wasm/index.js: new exports (drain events,    │
│   snapshot, free strings) — dev build only            │
│ bindings/devtools/crabs-devtools.js                   │
│  • attach(module, node) → controller                  │
│  • <crabs-devtools> web component, 4 tabs             │
└──────────────┬────────────────────────────────────────┘
               │  attach + DOM
┌─ Example ────▼────────────────────────────────────────┐
│ examples/devtools_demo/index.html                     │
│  • loads devtools-enabled WASM artifact               │
│  • 2 nodes; ops exchanged in-page / BroadcastChannel  │
└───────────────────────────────────────────────────────┘
```

### Production vs dev builds

Two artifacts are built and shipped in the npm module; consumers select in
JavaScript, no recompilation:

- `crabs.js` + `crabs.wasm` — production, no devtools code (default).
- `crabs.dev.js` + `crabs.dev.wasm` — compiled with `CRABS_ENABLE_DEVTOOLS`
  and the extra devtools exports.

- `build_wasm.sh` builds both every run.
- `bindings/wasm/package.json` gains an exports map with a `./dev` entry
  pointing at `crabs.dev.js`; bundler users can also map a custom condition.
- `index.d.ts` gains dev-only declarations under the dev entry.
- Both artifacts are committed to the repo, matching the existing pattern.
- The devtools C code (and the one-line hook in `crabs_wasm_execute`) is fully
  `#ifdef CRABS_ENABLE_DEVTOOLS` — production binaries contain zero devtools
  code, no exports, no overhead.
- `attach()` accepts any module; handed a production module it throws
  "this WASM build was not compiled with devtools support" rather than
  silently no-oping. The snapshot exposes plaintext CRDT values, users, roles,
  and key metadata, so it must not be reachable in production binaries.

## Data model

### Event record

Appended after `state_machine_execute` returns, so rejects are captured:

```json
{
  "seq": 1042,
  "op_type": "increment",
  "uuid": "f3a1-…",
  "signer": "bob",
  "lamport": 87,
  "hlc": {"physical": 1693500000, "logical": 2, "node": "node-b"},
  "target": "views",
  "result": "accepted",
  "error_code": 0,
  "error": null
}
```

- Ring buffer of 1024 entries in C; oldest dropped on overflow (documented
  behavior). JS drains as a JSON array after each execute; draining on attach
  backfills history.
- Transitions are **derived on the JS side** by diffing item states between
  consecutive snapshots — the C recorder stays a pure reader and never
  duplicates transition knowledge.

### Snapshot

One JSON document per pull:

```json
{
  "node_id": "node-b",
  "version": 12,
  "hlc": {"physical": 1693500000, "logical": 2, "node": "node-b"},
  "items": [
    {"name": "views", "crdt_type": "g_counter", "protocol_state": "MODIFIED",
     "lock_state": "unlocked", "value": {"alice": 12, "bob": 3}, "invariants": []}
  ],
  "policies": [{"op_type": "increment", "role": "role:member"}],
  "triggers": [{"name": "tos_threshold", "watch": "flaggers",
                "condition": "count>=3", "action": "issue:tos_investigator",
                "fired": true}],
  "users": [{"id": "alice", "roles": ["member"], "attrs": ["…"], "keys": 2}],
  "log_head": {"entries": 210, "state_hash": "9f2c…"}
}
```

- CRDT `value` rendering is per type (register, G-Counter, PN-Counter, OR-Set,
  OneShotSet, …) — the per-type walkers are the bulk of `devtools.c`.
- `log_head` gives a cheap integrity view of the hash-chained audit log
  (entry count + head hash). Full log enumeration is covered by the drained
  event timeline; deeper log access can come later.
- The C JSON writer is a tiny internal string-builder (grow-on-append), no
  dependency. Strings cross to JS via Emscripten `UTF8ToString`, then freed.

## UI panel

- Tabbed panel (~380px tall, docked bottom of the demo page), collapsible via
  a floating toggle button. Keyboard-navigable tabs. Light theme only, styled
  in the "soft & friendly" direction (rounded corners, pill badges, subtle
  shadows, pastel status colors).
- **States** — all items as cards with colored protocol-state badges; clicking
  a card highlights the item's position on the state diagram
  (IDLE → LOCKED → MODIFIED → VERIFIED, ERROR as off-ramp) with recent
  per-item transitions.
- **Timeline** — live streaming op list, accepted (✓) and rejected (✗ with
  reason), filter box (type / signer / item), pause button (draining continues
  in background), expandable row detail with derived transition.
- **CRDT** — each item's value rendered per CRDT type; ABE-encrypted values
  shown as `[encrypted: policy=…]`, never decrypted.
- **Config** — policies, triggers with fired-state warning badges,
  users with roles/attributes/key counts, audit-log head. Read-only context.
- Updates piggyback on drained batches after `execute` returns — no timers,
  so an idle app costs nothing.

## Demo page

`examples/devtools_demo/index.html` — static, no build step. Loads the
devtools-enabled artifact, creates two nodes (alice, bob), and wires a slice of
the video_platform setup inline (G-Counter, PN-Counter, OR-Set, a register, a
threshold trigger). Buttons fire ops on either node. A "two tabs = two peers"
mode uses `BroadcastChannel` so ops in one tab replicate into the other, making
HLC ordering and CRDT merges visible. Each node gets its own attached
`<crabs-devtools>` panel, side by side.

## Error handling

- `attach()` on a production module: loud error as above.
- Malformed/partial snapshot: degraded tab with an error banner, never a blank
  panel.
- Ring-buffer overflow: drops oldest events, by design.
- Encrypted values: rendered as ciphertext markers, never decrypted by devtools.

## Testing

- C: `test/test_devtools.cpp` (ctest) — snapshot JSON structure per CRDT type,
  event recording on accept and reject paths, ring-buffer wraparound.
- WASM: `bindings/wasm/test/smoke.js` gains a dev-artifact check — load dev
  wasm, drain events, pull snapshot, assert fields; production artifact
  asserts devtools exports are absent.
- Demo page: verified manually in the browser (golden path + two-tab mode).
- All C follows `docs/STYLE_GUIDE.md` (refcounter patterns, `_t` types,
  `get_clear_memory`).

## Out of scope

- Chrome DevTools extension (the panel is designed for later reuse, but the
  extension itself is not built).
- Full enumeration of the hash-chained audit log (drained events cover the
  same ground).
- Mutating state from the panel (read-only inspector).