# crabs-wasm

WebAssembly bindings for the [CRABS](https://github.com/vijayee/CRABS) cryptographic attribute-based state machine library.

Runs in **any environment with a WASM runtime**: browsers, Node.js, Deno, Bun, Cloudflare Workers, Vercel Edge Functions, and standalone runtimes (Wasmtime, WasmEdge).

## Installation

```bash
npm install crabs-wasm
```

That's it — the pre-built `crabs.wasm` (1.7MB) ships with the package. No compilation needed. The same binary works in every environment.

### Rebuilding from source (optional)

If you need to rebuild the WASM module from source:

```bash
# Prerequisites: Emscripten SDK, OpenSSL source, openabe-to-c project
cd bindings/wasm
npm run build   # runs ../../build_wasm.sh
```

## Quick Start

```javascript
const { Node, KeyPair } = require('crabs-wasm');

async function main() {
  // Create a CRABS node (async — loads the WASM module)
  const node = await Node.create('admin', { ordering: 'hlc' });

  // Generate a user keypair
  const aliceKey = await KeyPair.generate();
  console.log('Alice public key:', aliceKey.publicKeyHex());

  // Register the user. registerUser rejects privileged (role:) initial
  // attributes — grant roles through the admin path instead.
  await node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'admin');

  // Get the node's signing key
  const nodeKey = node.getNodeKey();
  console.log('Node public key:', nodeKey.publicKeyHex);

  node.destroy();
}

main();
```

## Architecture

This package wraps the CRABS C library compiled to WebAssembly via Emscripten:

```
crabs.wasm (1.7MB)  ←  CRABS + OpenABE + RELIC + OpenSSL (all compiled to WASM)
crabs.js   (77KB)   ←  Emscripten JS glue (loads and interfaces with the .wasm)
index.js            ←  High-level JavaScript API (this package)
```

The `.wasm` binary is platform-agnostic — the same file runs everywhere.

## API

The API mirrors `crabs-node` (the N-API bindings). See `../node/index.d.ts` for the full type definitions. Key classes:

- **`Node`** — CRABS node (attribute machine + state + ABE master key)
- **`KeyPair`** — ECDSA secp256k1 keypair
- **`Operation`** — A signed state-machine operation

## Differences from crabs-node

| | crabs-node (N-API) | crabs-wasm (this package) |
|---|---|---|
| Runtime | Node.js only | Any WASM runtime (browser, Node, edge, etc.) |
| Loading | Synchronous (`require`) | Async (WASM module load) |
| Performance | Native speed | ~2-5x slower (WASM overhead) |
| ABE keygen | ~2-5 seconds | ~5-15 seconds |
| Binary size | Links against system libs | 1.7MB self-contained `.wasm` |

## Trust boundary: admin authorization

Every user-mutating operation — `grantRole`, `revokeRole`, `suspendUser`
(where exposed), `revokeUser`, `activateUser` — is gated in C: the signer
must be an ACTIVE user holding the `role:admin` attribute, and the gate runs
at module level, not in the JS layer. The bootstrap admin created by
`Node.create('admin', …)` holds `role:admin`; a suspended admin loses the
gate. Key-compromise recovery (node-driven suspension during key rotation)
bypasses the gate deliberately — the node acts with system authority there,
not on behalf of a signing admin.

## Devtools build

`build_wasm.sh` produces two artifacts:

- `crabs.js` + `crabs.wasm` — production. No devtools code.
- `crabs.dev.js` + `crabs.dev.wasm` — devtools-enabled (`CRABS_ENABLE_DEVTOOLS`).

To inspect CRABS state machines in the browser:

```js
const { Node } = require('crabs-wasm/dev');   // dev build
const { attach } = require('crabs-devtools'); // bindings/devtools

const node = await Node.create('admin');
attach(node, { nodeId: 'admin' });            // appends <crabs-devtools> to <body>
```

The panel has four tabs — **States** (per-item protocol state), **Timeline**
(live operation stream with accept/reject reasons), **CRDT** (current
replicated values), and **Config** (policies, triggers, users, audit-log head).

Importing `crabs-wasm/dev` and attaching to a production module throws
"not compiled with devtools support" — the devtools snapshot exposes
plaintext CRDT values, users, and key metadata, so it is only available in
the dev artifact.

See `examples/devtools_demo/` for a working two-node demo (open the page in
two tabs to watch operations replicate between peers over BroadcastChannel).

### State inspector & change events

By default `attach` renders the panel as a floating overlay appended to
`document.body`; pass `mount: <element>` to embed it inside the page instead.

- **State tab** — a tree of the node's full CRABS state (CRDT items, policies,
  triggers, schedules, users) with diff badges marking what the latest change
  event added, changed, or removed, an overview header (node id, version, HLC,
  audit-log head, pending schedules), and an Export button that downloads the
  snapshot as JSON.
- **Timeline tab** — the live change-event stream. Every row carries a layer
  pill (`op`, `schedule`, `trigger`, or `attribute`), filter checkboxes let
  you show or hide layers, and payload previews summarize what each mutation
  touched.

Every mutation (executed operations, schedule submission and
materialization, trigger effects, attribute grants) also fires a `'change'`
event to JS listeners.
`node.on('change', listener)` returns an unsubscribe function;
`node.off('change', listener)` does the same by identity:

```js
const unsubscribe = node.on('change', (event) => {
  console.log(event.kind, event.type, event.target, event.result);
});
unsubscribe();  // when done
```

Note: direct CRDT convenience calls that mutate without executing an
operation (e.g. `addCounter`, `setPolicy`, and similar direct-write helpers)
do not fire change events; executed operations, schedules, triggers, and
attribute mutations do.

Trust note: change events are observational — the callback must not mutate
node state. Nested mutations raised inside a listener are deferred rather
than forbidden, but re-entrant mutation from a listener is a design smell;
the events carry no credentials, so they cannot authorize anything.

## Timed transactions

Operations whose effects apply at a future time. A signed operation is stored
in the node's durable pending set and materialized — applied exactly as
signed — when the node's clock passes the scheduled time.

```js
const inner = await Operation.create('mint');
inner.signerId = 'alice';
inner.nodeId = 'alice';
node.sign(inner, key.privateKeyHex());

const scheduleId = node.schedule(inner, Date.now() + 60_000); // bigint id
node.pendingSchedules();   // [{ id, executeAt, submitter }]
node.processSchedules();   // materialize anything due (also runs on every execute)
node.cancelSchedule(scheduleId);
```

Recurring schedules repeat on a fixed cadence and terminate on a repeat
count (0 = infinite), an end date, or `cancelSchedule` — whichever comes
first. Missed slots fire in order on the next tick (catch-up):

```js
node.scheduleRecurring(mintOp, Date.now() + 15_000, 15_000, 3, 0); // 3 fires
```

Catch-up is bounded per tick: at most 64 scheduled occurrences materialize
per `processSchedules` call (or per automatic tick on `execute`). Deferred
slots carry over — they stay pending on their exact slots and fire on the
next tick, so nothing is skipped or double-fired; catching up after long
downtime takes as many ticks as the budget requires. Pass `0` to remove the
cap (unbounded catch-up, the pre-budget behavior):

```js
node.setScheduleOccurrenceBudget(0);   // unbounded catch-up
node.scheduleOccurrenceBudget();       // read the current cap
```

Occurrence identity
is derived deterministically from the embedded operation and its slot time,
so replicas converging on the same missed slots deduplicate via the audit
log instead of double-firing.

Notes:

- `node.schedule` stores the operation directly (like the other convenience
  methods) without re-running policy validation — the operation must already
  be signed by an authorized signer. The policy-gated path is the
  `__schedule__` operation type itself.
- `cancelSchedule` is policy-gated, not submitter-bound: any caller satisfying
  the `__cancel_schedule__` policy can cancel any pending schedule id (admins
  retain full power).
- `processSchedules(nowMs?)` trusts the JS-supplied clock (default
  `Date.now()`). The WASM binding attaches no authenticated time source: all
  timing — including the automatic tick that runs on every `execute` — runs
  on the platform clock. Deployments needing authenticated time must attach a
  time source (`state_set_time_source` is not yet exposed to JS).
- Materialization failures (state drifted, invariant violated) are recorded
  durably as `__schedule_failed__` audit-log entries and never affect other
  operations. A schedule fires exactly once. Two nodes with skewed clocks may
  resolve the same schedule differently; CRDT-typed items reconcile via merge,
  non-CRDT items can diverge like any conflicting concurrent ops.
- Pending schedules are part of the serialized state and survive restarts.

## License

MIT
