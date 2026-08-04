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

## License

MIT