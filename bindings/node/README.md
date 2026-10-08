# crabs-node

Node.js N-API bindings for the [CRABS](https://github.com/vijayee/CRABS) cryptographic attribute-based state machine library.

## Installation

```bash
# From the CRABS repository root:
cd bindings/node
npm install
```

This runs `cmake-js compile` as a postinstall step, which builds the native addon against the CRABS C library. You need:

- **CMake 3.22+**
- **C++17 compiler** (GCC, Clang, or MSVC)
- **OpenSSL development libraries**
- **GMP** (GNU Multiple Precision Arithmetic Library)
- **OpenABE** (built as a submodule in `deps/openabe-c/`)

### Prerequisites on Ubuntu/Debian

```bash
sudo apt install cmake build-essential libssl-dev libgmp-dev
git submodule update --init --recursive
cd deps/openabe-c && mkdir build && cd build && cmake .. && make
```

### Prerequisites on macOS

```bash
brew install cmake openssl gmp
git submodule update --init --recursive
cd deps/openabe-c && mkdir build && cd build && cmake .. && make
```

## Quick Start

```javascript
const { Node, KeyPair, Operation } = require('crabs-node');

// Create a CRABS node with HLC (Hybrid Logical Clock) ordering
const node = new Node('admin', { ordering: 'hlc' });

// Generate a keypair for a new user
const aliceKey = KeyPair.generate();
console.log('Alice public key:', aliceKey.publicKeyHex());

// Register the user
node.registerUser('alice', aliceKey.publicKeyHex(), 'role:member');

// Add data items
node.addCounter('views');
node.addPNCounter('likes');    // pos = likes, neg = dislikes
node.addORSet('subscribers');

// Set policies
node.setPolicy('view', 'role:member');
node.setPolicy('like', 'role:member');
node.setPolicy('subscribe', 'role:member');

// Create and execute a signed operation
// Use node.sign() (not op.sign()) to stamp the HLC timestamp before signing
const op = new Operation('view');
op.signerId = 'alice';
node.sign(op, aliceKey);
node.execute(op);

// Query state
console.log('Views:', node.getCounter('views'));  // 1

// Get HLC timestamp
const hlc = node.getHLC();
console.log('Current HLC:', hlc.formatted);
```

## Architecture

The CRABS library uses **Hybrid Logical Clocks (HLC)** by default in these bindings, which provides:

- **Human-readable timestamps** — each operation carries the physical time it was created
- **Causal ordering** — the `max` rule preserves happens-before relationships
- **Attack mitigation** — bounded skew rejection prevents time-travel attacks

Use `new Node('admin', { ordering: 'lamport' })` for the original Lamport clock ordering.

## API Reference

### `KeyPair`

- `KeyPair.generate()` → `KeyPair` — generate a new ECDSA secp256k1 keypair
- `KeyPair.fromPrivateHex(hex)` → `KeyPair` — create from a 32-byte private key (64 hex chars)
- `KeyPair.derivePublicHex(privateHex)` → `string` — derive the 33-byte public key (66 hex chars) from a private key
- `keyPair.publicKeyHex()` → `string` — 33-byte compressed public key (66 hex chars)
- `keyPair.privateKeyHex()` → `string` — 32-byte private key (64 hex chars)

### `Operation`

- `new Operation(type)` — create an operation with the given type string
- `op.type` — get/set the operation type
- `op.signerId` — get/set the signer's user ID
- `op.nodeId` — get/set the node ID
- `op.payload` — get/set the payload (Buffer or string)
- `op.lamportTime` — get/set the Lamport timestamp
- `op.sign(keyPair)` — sign the operation with a KeyPair
- `op.signWithPrivateKey(privateKeyHex)` — sign with a raw private key hex string

### `Blueprint`

A serializable machine definition a parent instantiates via `node.lineageSpawn(blueprint)` (or ships between processes as a `__spawn_machine__` op payload). JS owns the blueprint — release it with `destroy()`.

- `Blueprint.create(childId, trustMode, bootstrapAdmin, ttlMs)` → `Blueprint` — build a fresh blueprint. `trustMode` is `'shared_root'` / `'delegated_copy'` / `'sovereign'` (short words `'shared'` / `'delegated'` accepted) or a `TRUST_MODE` number; `ttlMs` bounds every attestation the parent later issues for this child
- `Blueprint.deserialize(wire)` → `Blueprint` — parse a wire image; the embedded hash is verified and the blueprint structurally validated
- `blueprint.addItem(name, dataType, crdtType)` — append a replicated data item (`DATA_TYPE` / `CRDT_TYPE` words or numbers)
- `blueprint.addPolicy(operation, expression)` — append an authorization policy
- `blueprint.stampHash()` — recompute the blueprint's SHA-256 over its canonical body
- `blueprint.serialize()` → `Buffer` — wire image (u32le length + canonical body + 32-byte hash); stamps the hash first
- `blueprint.destroy()` — release the underlying C blueprint

The enum tables `TRUST_MODE`, `DATA_TYPE`, `CRDT_TYPE` are exported alongside the classes.

### `Node`

- `new Node(adminId, options?)` — create a CRABS node with the given admin user
  - `options.ordering` — `'hlc'` (default) or `'lamport'`
  - `options.strategy` — HLC receive strategy (`'bounded'` default)

#### User Management

- `node.registerUser(userId, publicKeyHex, initialAttrs?)` — register a new user
- `node.grantRole(targetUser, role, value, signerId)` — grant a role attribute
- `node.selfAssert(attribute, value, signerId)` — self-assert a non-privileged attribute
- `node.verifyIdentity(targetUser, attribute, value, signerId)` — verify a user's attribute
- `node.revokeUser(userId)` — revoke a user (terminal)
- `node.getUser(userId)` → `UserInfo | undefined` — get user info
- `node.getNodeKey()` → `NodeKey` — get the node's signing keypair

#### Data Items

- `node.addCounter(name)` — add a G-Counter (grow-only)
- `node.addPNCounter(name)` — add a PN-Counter (positive/negative)
- `node.addORSet(name)` — add an OR-Set (observed-remove)
- `node.addOneShotSet(name)` — add a one-shot set (add-only, max 256 elements)
- `node.addOneShotFlag(name)` — add a one-shot flag (monotonic boolean)
- `node.addRegister(name, initialValue?)` — add an LWW-Register
- `node.addResource(name)` — add a resource (PN-Counter + lock protocol)

#### Queries

- `node.getCounter(name)` → `number | undefined`
- `node.getPNCounter(name)` → `number | undefined`
- `node.getRegister(name)` → `number | undefined`
- `node.setContains(name, element)` → `boolean`

#### Direct Counter Operations (for setup/testing)

- `node.incrementCounter(name, delta?, nodeId?)` — increment a G-Counter
- `node.incrementPNCounter(name, delta?, nodeId?)` — increment the positive side of a PN-Counter
- `node.decrementPNCounter(name, delta?, nodeId?)` — increment the negative side of a PN-Counter

#### Direct Set Operations (for setup/testing)

- `node.setAdd(name, element, tag?)` — add to a set
- `node.setRemove(name, element)` — remove from an OR-Set
- `node.flagSet(name, setBy, setAt?)` — set a one-shot flag
- `node.flagValue(name)` → `boolean`

#### Policies & Operations

- `node.setPolicy(opType, expression)` — register a policy for an operation type
- `node.sign(op, key)` — stamp HLC timestamp and sign an operation. **Use this instead of `op.sign()` when using HLC ordering** — it stamps the HLC timestamp before signing so the signature covers the timestamp. `key` can be a `KeyPair` object or a private key hex string.
- `node.execute(op)` — execute a signed operation

#### Triggers

- `node.createTrigger(config)` — create a threshold trigger
  - `config.triggerId` — unique trigger ID
  - `config.condition` — condition expression (e.g., `"flag_count >= 5"`)
  - `config.effectType` — `'issue_attribute'` or `'change_policy'`
  - `config.oneShot` — fire only once
  - `config.cooldownMs` — minimum interval between fires
  - For `issue_attribute`: `issueAttribute`, `targetRole`, `attributeValue`, `durationMs`

#### ABE

- `node.encrypt(payload, policy)` → `Buffer` — ABE-encrypt data under a policy

#### Serialization

- `node.serialize()` → `Buffer` — serialize the entire state

#### HLC

- `node.getHLC()` → `HLC | undefined` — get the current HLC timestamp
- `node.setTime(nowMs)` — inject the wall clock (for testing temp attribute expiry)
- `node.pruneExpiredTempAttrs()` — prune expired temporary attributes
- `node.setTimeSource({ mode, url?, resyncMs?, timeoutMs?, maxSkewMs? })` — attach an authenticated time source (`mode: 'https'`) or revert to the platform clock (`mode: 'system'`). Machine-local: the source is attached to the underlying machine's state, not to the wrapper
- `node.getTimeSource()` → `{ mode, url }` — inspect the current selection

**Cross-wrapper caveat (A11-L6):** two Node wrappers can wrap the SAME machine (e.g. `lineageSpawn`/`lineageResidentChild` give a child wrapper while the machine is owned elsewhere). If both wrappers configure a time source, destroying EITHER wrapper detaches the machine's clock from its state — a wrapper teardown always clears the ops pointer it installed before freeing it, so the surviving wrapper's live configuration is silently stripped (the machine thereafter fails closed per R7-02, never silently reverting mid-operation). Consequence: treat the time source as machine-scoped; re-apply `setTimeSource` on the surviving wrapper if you destroy a sibling wrapper that had configured one.

#### Lineage (v1.7: machines mint machines)

- `node.lineageInstall()` — register the five `__lineage__` op types, their default `role:admin` policies and handlers. Idempotent; call once after machine creation
- `node.lineageSpawn(blueprint)` → `Node` — instantiate a child machine. The returned Node **borrows** the spawned machine: this node owns it (destroyed when the parent node is collected) and the child wrapper keeps the parent alive
- `node.lineageChildren()` → `[{ childId, mode, status, spawnedAtMs, attestationTtlMs }]` — borrowed view over the child manifest
- `node.lineageResidentChild(childId)` → `Node | null` — the still-resident in-process spawned child (fresh wrapper over the same machine), or `null` when unknown/dissolved. Machines spawned through the ops pipeline are owned by C's resident-children registry
- `node.lineageAttest(childId, userId, attributes?)` → `Buffer` — parent-signed, TTL-bounded attribute grant (attestation wire image). Requires an authenticated time source (`setTime`) and an `active` manifest entry
- `node.lineageTombstone(childId)` → `Buffer` — off-chain dissolution proof (`u8 LINEAGE_DISSOLVED tag + string16 childId` + 64-byte parent ECDSA — the exact bytes a `__receive_dissolution__` op transports). Honesty-gate refusals surface as typed errors (`resource_not_found` / `unauthorized` / `cryptographic_error`)

Dissolution/dissolve/withdraw/revoke-attestation travel through the normal `Operation` + `node.execute()` pipeline after `lineageInstall()`; `__receive_dissolution__` runs the same way on the child machine.

## Testing

```bash
npm run build   # cmake-js build (also runs on install); the .node lands in build/Release/
npm test        # node test/test.js — basic surface smoke
node lineage_smoke.mjs   # v1.7 lineage flow: blueprint → spawn → children → attest → dissolve → tombstone
```

## License

MIT