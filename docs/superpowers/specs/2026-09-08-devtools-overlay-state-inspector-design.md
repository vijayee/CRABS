# CRABS Devtools Overlay, State Inspector, and Change Events — Design

**Date:** 2026-09-08
**Status:** Approved design (pending implementation)

## Goal

Make the browser devtools behave like Vue DevTools does for Vuex state:

1. The panel is a **true overlay** floating above the app (a launcher button
   toggles it), not elements sitting in the page body.
2. A **full-state inspector** renders the entire machine state as one
   browsable object tree with change highlighting — today only transitions
   (tabs of cards / events) are visible.
3. The library gains **API-level change notification**: hooks in C fired on
   every state-mutating path, and `node.on('change', …)` events in JS. Today
   the JS layer learns about changes only by wrapping `node.execute`, which
   misses scheduled materialization, trigger effects, replication, and direct
   attribute-machine mutations.

## Background (current state)

- `<crabs-devtools>` is a shadow-DOM custom element, but `attach()` appends it
  to `options.mount || document.body` as a normal layout element; the demo
  mounts it inside page layout containers.
- Data flow is pull-only: the JS controller wraps `node.execute` and refreshes
  from `crabs_wasm_devtools_snapshot` + the drained event ring after each
  call. `devtools_record_event` fires from only three call sites
  (`crabs_wasm_execute`, scheduler materialize/fire). Trigger evaluation and
  attribute-machine mutations are never recorded.
- The snapshot JSON (dev build only) already contains the full state: items
  with typed CRDT values and lock state, policies, triggers, users, schedule
  list, log head. Nothing renders it as a single object.

## Design

### 1. Overlay shell (`crabs-devtools.js`)

- Default mount is a **fixed overlay**: `position: fixed`, docked right,
  full viewport height, 380 px wide, `z-index` above page content, shadow-DOM
  isolated. A floating launcher button (bottom-right, "CRABS") toggles
  open/closed. Default state: open.
- `options.mount` still overrides to in-flow placement (the two-node demo
  keeps using it), but the default no longer participates in page layout.
- No drag or resize (YAGNI).

### 2. Tabs: State | Timeline

The old States-cards, CRDT, and Config tabs are removed; their content is
subsumed by the state tree.

**State tab**

- One collapsible tree of the whole snapshot JSON: `items` (each with CRDT
  value, protocol state, lock state), `policies`, `triggers`, `users`,
  `schedules`, `log head`.
- Values render expanded and typed: counters as numbers, sets as arrays,
  registers as values, opaque LWW payloads as `[encrypted: N bytes]`.
- **Diff highlighting**: the controller keeps the previous snapshot; on
  refresh, changed keys get a badge (green added, yellow changed, red
  removed), cleared on the next refresh. The controller also keeps a bounded
  buffer of recent diffs (implementation detail today; it is what makes a
  time-travel view a later add-on rather than a rewrite).
- **Overview header** on the panel: node id, ordering system, HLC state,
  state version, log head hash, pending-schedule count.
- **Export** button: downloads/prints the snapshot JSON.

**Timeline**

- Unchanged interaction (filter, pause, JSON detail view), plus:
  - **Layer tags**: every event carries a layer — `op`, `schedule`,
    `trigger`, `attribute` — rendered as a colored pill and filterable.
  - **Payload preview** per row (e.g. `views +1`, target item names),
    computed at record time; opaque payloads stay opaque.
- Clicking an event can scroll-to and flash the affected item in the State
  tree.

### 3. C change hook (single choke point, NOT devtools-gated)

```c
typedef enum {
  CRABS_CHANGE_OP        = 0x01,  // executed operation (direct execution only)
  CRABS_CHANGE_SCHEDULE  = 0x02,  // scheduled materialization (each fire)
  CRABS_CHANGE_TRIGGER   = 0x03,  // trigger-fired mutation
  CRABS_CHANGE_ATTRIBUTE = 0x04   // attribute-machine user mutation
} crabs_change_kind_e;

typedef struct {
  crabs_change_kind_e kind;
  const char*         type;        // op type / attribute action name
  const uint8_t*      uuid;        // op uuid (NULL for attribute actions)
  const char*         signer_id;
  const char*         node_id;
  const char*         target;      // primary target item/user
  const char*         preview;     // short human-readable payload summary
  crabs_error_e       result;
} crabs_change_event_t;

typedef void (*crabs_change_hook_fn)(state_t* state,
                                     const crabs_change_event_t* event,
                                     void* user_data);

void state_set_change_hook(state_t* state, crabs_change_hook_fn hook,
                           void* user_data);
```

- Fired after every state-mutating completion: `state_machine_execute` and
  `state_machine_execute_scheduled` (both success and durable failure),
  trigger-fired mutations, and attribute-machine mutations
  (`register_user`, `grant_role`, `revoke_role`, `suspend_user`,
  `activate_user`, `revoke_user`, `self_assert`, `verify_identity`,
  `issue_temporary`).
- `devtools_record_event` moves behind the hook: in dev builds
  `wasm_helpers` registers a devtools hook at module init, so every mutation
  path feeds the ring automatically (today only three paths do).
- A broken observer can never fail an op: hook invocation is wrapped so any
  failure is swallowed. The hook must not mutate state.
- The hook mechanism lives in the core (state_machine), compiled in all
  builds; only the devtools *recorder* is behind `CRABS_ENABLE_DEVTOOLS`.

### 4. JS change events

- `node.on('change', cb)` and `node.off('change', cb)` on the WASM `Node`
  (and the node binding), delivering the change event as a JS object
  (kind, type, target, signer, result, preview).
- Delivery: `wasm_helpers` registers a C hook whose body invokes a JS
  trampoline installed with `addFunction` (push model, no polling). The
  trampoline emits to JS listeners and, in dev builds, triggers a devtools
  refresh.
- The devtools controller uses the change event instead of wrapping
  `node.execute`; the demo drops its manual `refreshPanels()` calls.
- Listener exceptions are caught and never propagate into the state machine.
- `on/off` work in prod builds (events without the ring/snapshot); snapshot
  and ring access throw in prod builds as today.

### 5. Data flow

```
mutation path (C) ──► crabs_change_event_t ──► state change hook
      │                                        ├─► devtools hook (dev): ring + JSON
      │                                        └─► JS trampoline ─► node.emit('change')
      │                                                             ├─ app listeners
      │                                                             └─ devtools controller ─► refresh()
      └─ snapshot JSON (pull, dev-only) ──────────────────────────────────► State tree + diffs
```

## Error handling

- Hook invocation wrapped: observer failures never affect the operation.
- Ring overflow keeps the existing wraparound semantics.
- Snapshot/JSON functions keep failing closed with NULL on invalid input.
- JS listener exceptions are isolated per listener (try/catch around each).

## Testing

- **Native**: hook fires on execute success/failure; on scheduled
  materialization (budget-deferred slots do NOT fire until they fire);
  on trigger effects; on every attribute-machine mutation listed above;
  hook never breaks ops (listener that throws — C side — is tolerated by
  contract test that the op still succeeds); `state_set_change_hook(NULL)`
  is a no-op; hooks survive serialization round-trips (hook is runtime
  state, not serialized).
- **JS**: smoke test — `node.on('change')` fires on execute, on
  `processSchedules` materialization, and on `registerUser`; devtools smoke
  updated for overlay + State tree diff badges.
- **Demo**: two-node demo updated — overlay default, State tree visible,
  no manual refresh calls.

## Out of scope (explicitly declined for now)

Time travel, node switcher, live state editing / op builder, dependency
graph, policy preview, command palette, separate window, drag/resize.