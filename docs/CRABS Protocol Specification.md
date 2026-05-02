# CRABS Protocol Specification v1.0

## *Cryptographic Attribute Based State Machines*

---

**Document Status:** Draft Specification  
**Last Updated:** April 30, 2026  
**Protocol Version:** 1.0.0  
**License:** MIT

---

# Table of Contents

1. [Introduction](#1-introduction)
2. [Notation and Conventions](#2-notation-and-conventions)
3. [System Model](#3-system-model)
4. [Data Model](#4-data-model)
5. [Data Types](#5-data-types)
6. [Protocol State Machine](#6-protocol-state-machine)
7. [Operations](#7-operations)
8. [The Attribute Machine](#8-the-attribute-machine)
9. [Locking Protocol](#9-locking-protocol)
10. [Cryptographic Primitives](#10-cryptographic-primitives)
11. [Key Management](#11-key-management)
12. [CRDT Merge Rules](#12-crdt-merge-rules)
13. [Serialization](#13-serialization)
14. [Security Considerations](#14-security-considerations)
15. [Implementation Guidelines](#15-implementation-guidelines)
16. [Test Vectors](#16-test-vectors)

---

# 1. Introduction

## 1.1 Purpose

The CRABS protocol defines a framework for decentralized, attribute-based authorization using state machines whose state converges via Conflict-free Replicated Data Types (CRDTs). It unifies Attribute-Based Encryption (ABE) with protocol state machines to create a system where:

- **Attributes are state** — The set of all users and their attributes is the state of a protocol-governed machine
- **Authorization is cryptographic** — Operations are gated by ABE policies and authenticated via ECDSA signatures
- **State is convergent** — CRDT merge rules ensure all nodes reach the same state without consensus
- **Resources are protected** — Atomic multi-resource locking with timeout-based liveness guarantees

## 1.2 Scope

This specification covers:

- The CRABS data model and type system
- The protocol state machine for resource lifecycle management
- The operation format and execution semantics
- The Attribute Machine for self-sovereign identity
- The locking protocol with atomic acquisition and timeout
- CRDT merge rules for all built-in types
- Key management and versioning
- Security properties and threat model

## 1.3 Conformance

A CRABS implementation MUST implement all REQUIRED components and SHOULD implement RECOMMENDED components. Implementation-defined behavior is explicitly noted.

---

# 2. Notation and Conventions

## 2.1 Data Types

Notation	Description
`uint8_t`	Unsigned 8-bit integer
`uint16_t`	Unsigned 16-bit integer
`uint32_t`	Unsigned 32-bit integer
`uint64_t`	Unsigned 64-bit integer
`byte[N]`	N-byte sequence
`string`	UTF-8 encoded string, null-terminated
`T[]`	Variable-length array of type T
`{k1: T1, k2: T2}`	Map/dictionary type

## 2.2 Cryptographic Primitives

Notation	Description
`SHA256(x)`	SHA-256 hash of data x
`ABE_setup()`	Generate ABE master public/secret keys
`ABE_keygen(msk, mpk, attrs)`	Generate ABE user key from attributes
`ABE_encrypt(mpk, msg, policy)`	Encrypt message under policy
`ABE_decrypt(sk, ct)`	Decrypt ciphertext with user key
`ECDSA_sign(sk, msg)`	Sign message with ECDSA private key
`ECDSA_verify(pk, msg, sig)`	Verify ECDSA signature
`RAND_bytes(buf, len)`	Cryptographically secure random bytes

## 2.3 Protocol Constants

```c
#define CRABS_HASH_SIZE         32   // SHA-256 output
#define CRABS_SIG_SIZE          64   // ECDSA secp256k1 signature
#define CRABS_MAX_USER_ID       64   // Maximum user ID length
#define CRABS_MAX_OP_NAME       64   // Maximum operation name length
#define CRABS_MAX_POLICY_EXPR   256  // Maximum policy expression length
#define CRABS_MAX_RESOURCES     8    // Maximum resources per operation
#define CRABS_MAX_ATTRIBUTES    64   // Maximum attributes per user
#define CRABS_MAX_LOG_ENTRIES   0    // Unlimited (0 = no limit)
#define CRABS_DEFAULT_LOCK_MS   5000 // Default lock timeout (5 seconds)
#define CRABS_MAX_LOCK_EXTENDS  3    // Maximum lock extensions
```

---

# 3. System Model

## 3.1 Participants

Participant	Role	Description
**Node**	State machine host	Maintains a replica of the state, processes operations
**User**	Protocol participant	Has attributes, signs operations, holds ABE keys
**Attribute Machine**	Root state machine	Governs all user attributes and policies
**Application Machine**	Domain state machine	Governs application-specific state (treasury, documents, etc.)

## 3.2 Network Model

CRABS assumes an **asynchronous network** with the following properties:

- Messages may be delayed, reordered, or dropped
- Nodes communicate over point-to-point authenticated channels
- No global clock is assumed (though local clocks are used for lock expiry with generous margins)
- The network is eventually reliable (messages eventually arrive if retransmitted)

## 3.3 Trust Model

Trust Assumption	Description
**Honest majority of nodes**	At least f+1 nodes behave correctly (for f Byzantine faults)
**Users control their signing keys**	ECDSA private keys are stored securely by users
**ABE MSK is protected**	The Master Secret Key is stored only on nodes, never exposed to users
**No quantum adversary**	Bilinear pairings are assumed secure against classical attacks

## 3.4 Consistency Model

CRABS provides **eventual consistency**:

- All correct nodes that have processed the same set of operations will converge to the same state
- CRDT merge rules are deterministic and commutative
- Temporary divergence is possible during network partitions
- Lock acquisition provides a linearizability point for resource operations

---

# 4. Data Model

## 4.1 State Structure

A CRABS state is a **bag of named data items**, each with a type, value, protocol state, and metadata:

```
State = {
    version: uint64,
    items: {
        "<name>": DataItem,
        ...
    },
    policies: {
        "<operation>": "<abe_policy_expression>",
        ...
    },
    lock_manager: LockManager,
    log: TransitionLog,
    config: MachineConfig
}
```

## 4.2 Data Item

```
DataItem = {
    type: DataType,
    crdt_type: CrdtType,
    value: any,
    protocol_state: ProtocolState,
    invariants: Invariant[],
    
    // Lock state (only for RESOURCE type)
    lock_token: byte[32] | null,
    lock_owner: string | null,
    lock_expiry: uint64,
    lock_extensions: uint32,
    pre_lock_snapshot: any | null
}
```

## 4.3 Policy

A policy maps an operation name to an ABE policy expression:

```plaintext
Policy = {
    operation: string,   // e.g., "transfer", "lock"
    expression: string   // e.g., "role:admin OR (role:member AND weight >= 3)"
}
```

Policy expressions use the CP-ABE syntax:

Expression	Meaning
`attr1 AND attr2`	Both attributes required
`attr1 OR attr2`	Either attribute sufficient
`2of3(attr1, attr2, attr3)`	Any 2 of the 3 required
`(A OR B) AND C`	Grouped expressions

## 4.4 Machine Configuration

```plaintext
MachineConfig = {
    max_lock_duration_ms: uint64,   // Default: 5000
    max_lock_extensions: uint32,    // Default: 3
    allow_force_unlock: bool,       // Default: true
    bootstrap_admin: string | null  // User ID of genesis admin
}
```

---

# 5. Data Types

## 5.1 Built-in Types

Type ID	Name	CRDT Strategy	Lock Required	Description
`0x01`	`COUNTER`	G-Counter	No	Grow-only counter
`0x02`	`PN_COUNTER`	PN-Counter	For transfers	Positive/negative counter
`0x03`	`SET`	OR-Set	No	Observed-remove set
`0x04`	`2P_SET`	Two-phase set	No	Add-then-remove set
`0x05`	`REGISTER`	LWW-Register	No	Last-writer-wins register
`0x06`	`DOCUMENT`	RGA	No	Replicated growable array
`0x07`	`RESOURCE`	PN-Counter + lock	**Yes**	Scarce item with protocol
`0xFF`	`CUSTOM`	User-defined	Configurable	Application-defined

## 5.2 Type Definition

```
DataTypeDefinition = {
    type_id: uint8,
    name: string,
    crdt_merge: function(any, any) -> any,
    requires_lock: bool,
    default_invariants: Invariant[]
}
```

## 5.3 Invariants

```
Invariant = {
    type: InvariantType,
    params: any,
    error_message: string
}

InvariantType = enum {
    GREATER_THAN    = 0x01,  // value > param
    LESS_THAN       = 0x02,  // value < param
    EQUAL_TO        = 0x03,  // value == param
    NOT_EQUAL       = 0x04,  // value != param
    DIVISIBLE_BY    = 0x05,  // value % param == 0
    UNIQUE          = 0x06,  // No duplicates (for sets)
    SUBSET_OF       = 0x07,  // All values in another set
    NON_NEGATIVE    = 0x08,  // value >= 0
    CUSTOM          = 0xFF   // User-defined callback
}
```

---

# 6. Protocol State Machine

## 6.1 Resource Protocol States

Every data item of type `RESOURCE` follows this protocol state machine:

```plaintext
┌─────────────────────────────────────────────────────────────┐
│                    RESOURCE PROTOCOL                          │
│                                                              │
│  States:                                                     │
│    IDLE       — Resource available, no lock held             │
│    LOCKED     — Resource locked by a user                    │
│    MODIFIED   — Resource has been modified while locked      │
│    VERIFIED   — Modifications passed invariant checks        │
│    ERROR      — Invariant check failed, awaiting rollback    │
│                                                              │
│  Transitions:                                                │
│    IDLE     ──__lock__──►  LOCKED                            │
│    LOCKED   ──operation──► MODIFIED                          │
│    MODIFIED ──__verify__──► VERIFIED                         │
│    MODIFIED ──__rollback__──► IDLE                           │
│    MODIFIED ──__force_unlock__──► IDLE  (after expiry)       │
│    VERIFIED ──__unlock__──► IDLE                             │
│    LOCKED   ──__force_unlock__──► IDLE  (after expiry)       │
│    ERROR    ──__rollback__──► IDLE                           │
│    ERROR    ──__force_unlock__──► IDLE                       │
└─────────────────────────────────────────────────────────────┘
```

## 6.2 Protocol State Encoding

```
ProtocolState = enum {
    IDLE    = 0x00,
    LOCKED  = 0x01,
    MODIFIED = 0x02,
    VERIFIED = 0x03,
    ERROR   = 0x04
}
```

## 6.3 Valid Transition Table

Current State	Operation	Next State	Condition
`IDLE`	`__lock__`	`LOCKED`	Policy satisfied
`LOCKED`	`__extend__`	`LOCKED`	Same owner, under limit
`LOCKED`	Any user operation	`MODIFIED`	Lock token matches
`MODIFIED`	`__verify__`	`VERIFIED`	All invariants pass
`MODIFIED`	`__verify__`	`ERROR`	Any invariant fails
`MODIFIED`	`__rollback__`	`IDLE`	Same owner
`VERIFIED`	`__unlock__`	`IDLE`	Same owner
`LOCKED`	`__force_unlock__`	`IDLE`	Lock expired
`MODIFIED`	`__force_unlock__`	`IDLE`	Lock expired
`ERROR`	`__rollback__`	`IDLE`	Anyone
`ERROR`	`__force_unlock__`	`IDLE`	Lock expired

---

# 7. Operations

## 7.1 Operation Structure

```
Operation = {
    // Operation identity
    type: string,                    // e.g., "transfer", "__lock__"
    uuid: byte[16],                  // Unique operation ID (UUID v4)
    
    // Payload (application-defined)
    payload: byte[],                 // Arbitrary data
    payload_format: uint8,           // 0 = opaque, 1 = JSON, 2 = CBOR
    
    // Resource declarations
    resources: string[],             // Names of data items touched
    required_state: ProtocolState[], // Required protocol state per resource
    next_state: ProtocolState[],     // Target protocol state per resource
    
    // Lock claims
    lock_claims: LockClaim[],        // Proof of lock ownership
    
    // Authorization
    policy: string,                  // ABE policy expression
    signature: byte[64],             // ECDSA signature
    
    // Identity
    signer_id: string,               // User ID (empty for Mode B privacy)
    signer_key_version: uint64,      // State version when key was issued
    
    // Ordering
    lamport_time: uint64,            // Lamport clock value
    node_id: string                  // Originating node ID
}
```

## 7.2 Lock Claim

```plaintext
LockClaim = {
    resource: string,    // Resource name
    lock_token: byte[32] // Random token from lock acquisition
}
```

## 7.3 Built-in Operations

### 7.3.1 `__lock__`

Acquire exclusive access to one or more resources atomically.

```plaintext
Operation = {
    type: "__lock__",
    resources: ["<resource1>", "<resource2>", ...],
    required_state: ["idle", "idle", ...],
    next_state: ["locked", "locked", ...],
    policy: "<lock_policy>",
    // Lock tokens are generated by the node and returned in response
}
```

**Response:**

```plaintext
LockResponse = {
    success: bool,
    lock_tokens: byte[32][],  // One random token per resource
    expiry: uint64            // Lock expiration timestamp
}
```

### 7.3.2 `__extend__`

Extend an existing lock's expiry time.

```
Operation = {
    type: "__extend__",
    resources: ["<resource>"],
    required_state: ["locked"],
    next_state: ["locked"],
    lock_claims: [{resource: "<resource>", lock_token: <token>}],
    policy: "<lock_policy>"
}
```

### 7.3.3 `__verify__`

Check invariants on a modified resource.

```
Operation = {
    type: "__verify__",
    resources: ["<resource>"],
    required_state: ["modified"],
    next_state: ["verified"],  // or ["error"] if invariants fail
    lock_claims: [{resource: "<resource>", lock_token: <token>}],
    policy: "<lock_policy>"
}
```

**Note:** The state machine checks all invariants defined for the resource's type. If all pass, state becomes `VERIFIED`. If any fail, state becomes `ERROR`.

### 7.3.4 `__rollback__`

Revert a resource to its pre-lock state.

```plaintext
Operation = {
    type: "__rollback__",
    resources: ["<resource>"],
    required_state: ["modified"],  // or ["error"]
    next_state: ["idle"],
    lock_claims: [{resource: "<resource>", lock_token: <token>}],
    policy: "<lock_policy>"
}
```

### 7.3.5 `__unlock__`

Release a lock after successful verification.

```plaintext
Operation = {
    type: "__unlock__",
    resources: ["<resource>"],
    required_state: ["verified"],
    next_state: ["idle"],
    lock_claims: [{resource: "<resource>", lock_token: <token>}],
    policy: "<lock_policy>"
}
```

### 7.3.6 `__force_unlock__`

Release an expired lock (anyone can call).

```
Operation = {
    type: "__force_unlock__",
    resources: ["<resource>"],
    required_state: ["locked"],  // or ["modified"], or ["error"]
    next_state: ["idle"],
    // No lock token required — anyone can force-unlock expired locks
    policy: "<force_unlock_policy>"
}
```

### 7.3.7 `__refresh_abe_key__`

Request a new ABE key derived from current attribute state.

```
Operation = {
    type: "__refresh_abe_key__",
    resources: [],
    payload: {"user_id": "<user_id>"},
    policy: "role:member",
    // No resources to lock — this reads from the Attribute Machine
}
```

### 7.3.8 `__change_config__`

Change the machine configuration (lock timeouts, etc.).

```plaintext
Operation = {
    type: "__change_config__",
    resources: [],
    payload: {"max_lock_duration_ms": 10000},
    policy: "role:admin AND weight >= 3"
}
```

## 7.4 Operation Execution Algorithm

```
Algorithm: EXECUTE_OPERATION

Input:
  state — Current machine state
  op    — Operation to execute
  mpk   — ABE master public key

Output:
  result — SUCCESS or error code

1.  // Prune expired locks
    for each item in state.items:
        if item.type == RESOURCE and item.protocol_state != IDLE:
            if now() >= item.lock_expiry:
                item.protocol_state = IDLE
                item.lock_token = null
                item.lock_owner = null
                item.pre_lock_snapshot = null
                log(state, {type: "__force_unlock__", resource: item.name,
                           forced_by: "__system__"})

2.  // Check operation is not a duplicate (idempotency)
    if state.processed_ops.contains(op.uuid):
        return SUCCESS  // Already applied

3.  // Verify protocol state transitions
    for i = 0 to len(op.resources) - 1:
        item = state.items[op.resources[i]]
        if item.protocol_state != op.required_state[i]:
            return PROTOCOL_VIOLATION
            // "{op.resources[i]} is in state {item.protocol_state},
            //  expected {op.required_state[i]}"

4.  // Verify lock claims (for locked resources)
    for each claim in op.lock_claims:
        item = state.items[claim.resource]
        if item.protocol_state == LOCKED or item.protocol_state == MODIFIED:
            if item.lock_token != claim.lock_token:
                return LOCK_TOKEN_MISMATCH
            if item.lock_owner != op.signer_id and op.signer_id != "":
                return LOCK_OWNER_MISMATCH

5.  // Verify ABE signature
    message = serialize_for_signing(op)
    if not ABE_decrypt_and_verify(state, op.policy, message, op.signature):
        return UNAUTHORIZED

6.  // Verify key is current (if signer_id is provided)
    if op.signer_id != "":
        user = attribute_machine.users[op.signer_id]
        if user.key_version != op.signer_key_version:
            return KEY_STALE

7.  // Execute operation handler
    if op.type is a built-in:
        result = execute_builtin(state, op)
    else:
        result = op.handler(state, op)  // Application-defined
    if result != SUCCESS:
        return result

8.  // Transition protocol states
    for i = 0 to len(op.resources) - 1:
        item = state.items[op.resources[i]]
        item.protocol_state = op.next_state[i]

9.  // Log operation
    log_entry = {
        version: state.version,
        uuid: op.uuid,
        type: op.type,
        signer_id: op.signer_id,
        lamport_time: op.lamport_time,
        node_id: op.node_id,
        state_hash: SHA256(state)
    }
    state.log.append(log_entry)
    state.version += 1
    state.processed_ops.add(op.uuid)

10. return SUCCESS
```

## 7.5 Serialization for Signing

The serialization format for signing MUST be deterministic to ensure signature verification is portable across implementations:

```plaintext
Algorithm: SERIALIZE_FOR_SIGNING

Input:
  op — Operation

Output:
  bytes — Deterministic byte sequence

1. fields = [
     op.type,
     op.uuid,
     op.payload,
     op.resources,
     op.required_state,
     op.next_state,
     op.lock_claims,
     op.policy,
     op.signer_id,
     op.signer_key_version,
     op.lamport_time,
     op.node_id
   ]

2. return canonical_encode(fields)
   // Canonical encoding: sorted map keys, fixed-width integers,
   // length-prefixed strings, no whitespace
```

---

# 8. The Attribute Machine

## 8.1 Purpose

The Attribute Machine is a CRABS state machine whose state IS the set of all users and their attributes. It is the **root of trust** for the entire system — all other machines reference its state for authorization decisions.

## 8.2 State Structure

```
AttributeMachine State = {
    // Inherits all standard CRABS state fields
    
    users: {
        "<user_id>": {
            attributes: {
                "<name>": AttributeValue,
                ...
            },
            public_key: byte[33],       // ECDSA public key (compressed)
            status: UserStatus,
            key_version: uint64,        // Incremented on each attribute change
            created_at: uint64,
            updated_at: uint64
        },
        ...
    },
    
    // Standard policies for attribute operations
    policies: {
        "grant_role":       "role:admin",
        "revoke_role":      "role:admin",
        "verify_identity":  "role:admin OR role:verifier",
        "self_assert":      "role:member",
        "register":         "role:admin",           // New user registration
        "suspend":          "role:admin",           // Suspend a user
        "change_policy":    "role:admin AND weight >= 3",
        "__refresh_abe_key__": "role:member",
        "__change_config__":   "role:admin AND weight >= 3"
    }
}

AttributeValue = {
    value: string,
    verified_by: string | null,  // User ID of verifier, null if self-asserted
    verified_at: uint64 | null,
    expires_at: uint64 | null
}

UserStatus = enum {
    ACTIVE   = 0x00,
    SUSPENDED = 0x01,
    REVOKED  = 0x02
}
```

## 8.3 Genesis

The Attribute Machine is created with a single bootstrap admin:

```plaintext
Algorithm: ATTRIBUTE_MACHINE_GENESIS

Input:
  admin_id    — Bootstrap admin user ID
  admin_pk    — Bootstrap admin ECDSA public key
  admin_attrs — Bootstrap admin attributes (e.g., "role:admin|weight:5")
  mpk, msk    — ABE master keys

Output:
  state — Initialized Attribute Machine state

1. state = new State()
2. state.version = 0
3. state.config.bootstrap_admin = admin_id

4. // Create bootstrap admin user
5. state.users[admin_id] = {
       attributes: parse_attributes(admin_attrs),
       public_key: admin_pk,
       status: ACTIVE,
       key_version: 0,
       created_at: now(),
       updated_at: now()
   }

6. // Set default policies
7. state.policies = DEFAULT_ATTRIBUTE_POLICIES

8. // Generate initial ABE key for admin
9. sk_abe = ABE_keygen(msk, mpk, admin_attrs)
10. // Return sk_abe to admin via secure channel

11. // Log genesis
12. state.log.append({
        version: 0,
        type: "__genesis__",
        admin_id: admin_id,
        timestamp: now()
    })

13. return state
```

## 8.4 Attribute Operations

### 8.4.1 Register User

```
Algorithm: REGISTER_USER

Operation:
  type: "register"
  payload: {user_id, public_key, initial_attrs}
  policy: "role:admin"

Effect:
  1. Verify user_id is unique
  2. Create user entry with initial attributes
  3. Generate initial ABE key
  4. Return ABE key to user via secure channel
  5. Log: "{signer_id} registered {user_id} with {initial_attrs}"
```

### 8.4.2 Grant Role

```plaintext
Algorithm: GRANT_ROLE

Operation:
  type: "grant_role"
  payload: {target_user, role, weight}
  policy: "role:admin"

Effect:
  1. Verify target_user exists
  2. Add or update role attribute
  3. Increment target_user.key_version
  4. Log: "{signer_id} granted {role} to {target_user}"
```

### 8.4.3 Self-Assert Attribute

```plaintext
Algorithm: SELF_ASSERT

Operation:
  type: "self_assert"
  payload: {attribute, value}
  policy: "role:member"

Effect:
  1. Add attribute with verified_by = null
  2. Increment signer's key_version
  3. Log: "{signer_id} self-asserted {attribute} = {value}"
```

### 8.4.4 Verify Identity

```
Algorithm: VERIFY_IDENTITY

Operation:
  type: "verify_identity"
  payload: {target_user, attribute, value}
  policy: "role:admin OR role:verifier"

Effect:
  1. Verify target_user exists
  2. Set attribute with verified_by = signer_id
  3. Increment target_user.key_version
  4. Log: "{signer_id} verified {target_user}'s {attribute} = {value}"
```

### 8.4.5 Revoke Role

```
Algorithm: REVOKE_ROLE

Operation:
  type: "revoke_role"
  payload: {target_user, role}
  policy: "role:admin"

Effect:
  1. Remove the specified role attribute
  2. Increment target_user.key_version
  3. Log: "{signer_id} revoked {role} from {target_user}"
```

## 8.5 Key Refresh

```
Algorithm: REFRESH_ABE_KEY

Input:
  state   — Attribute Machine state
  msk     — ABE master secret key
  mpk     — ABE master public key
  user_id — User requesting refresh

Output:
  envelope — New key envelope

1. user = state.users[user_id]
2. if user.status != ACTIVE:
       return USER_SUSPENDED

3. // Build attribute string from current state
4. attrs = []
5. for each (name, attr) in user.attributes:
        attrs.append("{name}:{attr.value}")
6. attr_string = join(attrs, "|")

7. // Generate new ABE key
8. sk_abe = ABE_keygen(msk, mpk, attr_string)

9. // Create key envelope
10. envelope = {
        user_id: user_id,
        state_version: state.version,
        attributes_hash: SHA256(canonical_encode(user.attributes)),
        sk_abe: sk_abe
    }

11. // Update user's key version
12. user.key_version = state.version
13. user.updated_at = now()

14. return envelope
```

---

# 9. Locking Protocol

## 9.1 Lock Manager

```
LockManager = {
    config: {
        max_duration_ms: uint64,    // Default: 5000
        max_extensions: uint32,     // Default: 3
        allow_force_unlock: bool    // Default: true
    },
    active_locks: {
        "<resource_name>": {
            token: byte[32],
            owner: string,
            acquired_at: uint64,
            expires_at: uint64,
            extensions: uint32,
            pre_lock_snapshot: any
        },
        ...
    }
}
```

## 9.2 Atomic Lock Acquisition

```plaintext
Algorithm: ATOMIC_ACQUIRE_LOCKS

Input:
  state     — Machine state
  resources — Resource names to lock
  requester — User ID requesting the lock

Output:
  tokens    — Lock tokens (one per resource) on success
  error     — Error code on failure

1. tokens = []
2. acquired = []

3. // Phase 1: Attempt to acquire ALL locks
4. for each resource_name in resources:
5.     item = state.items[resource_name]
6.     
7.     if item.type != RESOURCE:
8.         goto rollback  // Only RESOURCE types can be locked
9.     
10.    if item.protocol_state != IDLE:
11.        goto rollback  // Resource is already locked or in invalid state
12.    
13.    if not check_policy(state, "__lock__", requester):
14.        goto rollback
15.    
16.    // Generate lock token
17.    token = RAND_bytes(32)
18.    
19.    // Acquire
20.    item.protocol_state = LOCKED
21.    item.lock_token = token
22.    item.lock_owner = requester
23.    item.lock_expiry = now() + state.config.max_duration_ms
24.    item.lock_extensions = 0
25.    item.pre_lock_snapshot = deep_copy(item.value)
26.    
27.    tokens.append(token)
28.    acquired.append(resource_name)

29. // Phase 2: All acquired — return tokens
30. return {tokens: tokens, expiry: now() + state.config.max_duration_ms}

rollback:
31. // Release all partially acquired locks
32. for each resource_name in acquired:
33.     item = state.items[resource_name]
34.     item.protocol_state = IDLE
35.     item.lock_token = null
36.     item.lock_owner = null
37.     item.lock_expiry = 0
38.     item.lock_extensions = 0
39.     item.pre_lock_snapshot = null

40. return LOCK_CONTENTION
```

## 9.3 Lock Extension

```
Algorithm: EXTEND_LOCK

Input:
  state       — Machine state
  resource    — Resource name
  lock_token  — Current lock token
  requester   — User requesting extension

Output:
  new_expiry  — New expiration time on success
  error       — Error code on failure

1. item = state.items[resource]

2. if item.protocol_state != LOCKED and item.protocol_state != MODIFIED:
       return NOT_LOCKED

3. if item.lock_token != lock_token:
       return LOCK_TOKEN_MISMATCH

4. if item.lock_owner != requester:
       return LOCK_OWNER_MISMATCH

5. if item.lock_extensions >= state.config.max_extensions:
       return MAX_EXTENSIONS_REACHED

6. // Extend
7. item.lock_expiry = now() + state.config.max_duration_ms
8. item.lock_extensions += 1

9. return {new_expiry: item.lock_expiry}
```

## 9.4 Force Unlock

```plaintext
Algorithm: FORCE_UNLOCK

Input:
  state     — Machine state
  resource  — Resource name
  requester — User requesting force unlock

Output:
  success   — True if unlocked
  error     — Error code

1. item = state.items[resource]

2. if item.protocol_state == IDLE:
       return NOT_LOCKED  // Nothing to force

3. if now() < item.lock_expiry:
       return LOCK_NOT_EXPIRED
       // "Lock on {resource} expires in {item.lock_expiry - now()}ms"

4. if not state.config.allow_force_unlock:
       return FORCE_UNLOCK_DISABLED

5. // Roll back to pre-lock snapshot
6. if item.pre_lock_snapshot != null:
       item.value = item.pre_lock_snapshot
       item.pre_lock_snapshot = null

7. // Release
8. item.protocol_state = IDLE
9. item.lock_token = null
10. item.lock_owner = null
11. item.lock_expiry = 0
12. item.lock_extensions = 0

13. // Log
14. log(state, {
         type: "__force_unlock__",
         resource: resource,
         forced_by: requester,
         previous_owner: item.lock_owner  // Note: captured before clearing
     })

15. return SUCCESS
```

## 9.5 Lock Expiry Pruning

Called at the start of every operation:

```plaintext
Algorithm: PRUNE_EXPIRED_LOCKS

Input:
  state — Machine state

Output:
  pruned_count — Number of locks force-unlocked

1. pruned = 0
2. for each (name, item) in state.items:
3.     if item.type == RESOURCE and item.protocol_state != IDLE:
4.         if now() >= item.lock_expiry:
5.             FORCE_UNLOCK(state, name, "__system__")
6.             pruned += 1
7. return pruned
```

---

# 10. Cryptographic Primitives

## 10.1 ABE Scheme

CRABS uses **Ciphertext-Policy Attribute-Based Encryption (CP-ABE)** as defined by Bethencourt, Sahai, and Waters (2007).

### 10.1.1 Setup

```plaintext
Algorithm: ABE_SETUP

Output:
  mpk — Master public key
  msk — Master secret key

1. Generate bilinear group parameters (Type-1 or Type-3)
2. mpk = (g, g^α, e(g,g)^β, ...)
3. msk = (β, g^α, ...)
4. return (mpk, msk)
```

### 10.1.2 Key Generation

```plaintext
Algorithm: ABE_KEYGEN

Input:
  msk   — Master secret key
  mpk   — Master public key
  attrs — Pipe-separated attribute string (e.g., "role:admin|dept:eng")

Output:
  sk — User secret key

1. Parse attrs into attribute set S
2. Generate random r, r_j for each attribute j in S
3. sk = (D = g^{(α+r)/β}, {D_j = g^r · H(j)^{r_j}, D'_j = g^{r_j}})
4. return sk
```

### 10.1.3 Encryption

```
Algorithm: ABE_ENCRYPT

Input:
  mpk    — Master public key
  msg    — Plaintext message
  policy — Policy expression string

Output:
  ct — Ciphertext

1. Parse policy into access tree T
2. Generate random secret s, share s down the tree
3. ct = (T, C = msg · e(g,g)^{αs}, C' = g^s,
          {C_y = g^{q_y(0)}, C'_y = H(att(y))^{q_y(0)}})
4. return ct
```

### 10.1.4 Decryption

```plaintext
Algorithm: ABE_DECRYPT

Input:
  sk — User secret key
  ct — Ciphertext

Output:
  msg — Plaintext (or error if attributes don't satisfy policy)

1. Recursively decrypt nodes of access tree using user's attributes
2. If leaf node satisfied: DecryptNode(ct, sk, node) = e(g,g)^{r·q_node(0)}
3. Combine shares using Lagrange interpolation
4. If root satisfied: A = e(g,g)^{rs}
5. msg = C / (e(C', D) / A) = C / e(g,g)^{αs}
6. return msg
```

## 10.2 ECDSA Signatures

CRABS uses **ECDSA with secp256k1** curve for operation signatures.

### 10.2.1 Signing

```plaintext
Algorithm: OPERATION_SIGN

Input:
  sk_ecdsa — ECDSA private key (32 bytes)
  op       — Operation to sign

Output:
  signature — ECDSA signature (64 bytes: r || s)

1. msg_bytes = SERIALIZE_FOR_SIGNING(op)
2. hash = SHA256(msg_bytes)
3. signature = ECDSA_sign(sk_ecdsa, hash)
4. return signature
```

### 10.2.2 Verification

```plaintext
Algorithm: OPERATION_VERIFY

Input:
  pk_ecdsa  — ECDSA public key (33 bytes, compressed)
  op        — Signed operation
  signature — ECDSA signature

Output:
  valid — True if signature is valid

1. msg_bytes = SERIALIZE_FOR_SIGNING(op)
2. hash = SHA256(msg_bytes)
3. return ECDSA_verify(pk_ecdsa, hash, signature)
```

## 10.3 ABE-Gated Signatures

The core authorization mechanism combines ABE and ECDSA:

```
Algorithm: VERIFY_OPERATION_AUTHORIZATION

Input:
  state     — Machine state (for attribute lookup)
  op        — Operation to verify
  mpk       — ABE master public key

Output:
  authorized — True if operation is authorized

1. // Find the policy for this operation
2. policy = state.policies[op.type]
3. if policy == null:
        return false  // No policy defined for this operation

4. // If signer_id is provided (Mode A), verify specific user
5. if op.signer_id != "":
        user = attribute_machine.users[op.signer_id]
        if user == null or user.status != ACTIVE:
            return false
        
        // Verify ECDSA signature with user's public key
        if not OPERATION_VERIFY(user.public_key, op, op.signature):
            return false
        
        // Verify user's attributes satisfy the policy
        // This is done by attempting ABE decryption with user's key
        attr_string = build_attr_string(user.attributes)
        sk_test = ABE_keygen(msk, mpk, attr_string)  // Temporary key for verification
        test_ct = ABE_encrypt(mpk, dummy_msg, policy)
        result = ABE_decrypt(sk_test, test_ct)
        return result == dummy_msg

6. // If signer_id is empty (Mode B), verify against ALL authorized users
7. else:
        authorized_users = find_users_satisfying_policy(attribute_machine, policy)
        for each user in authorized_users:
            if OPERATION_VERIFY(user.public_key, op, op.signature):
                return true  // Some authorized user signed this
        return false  // No authorized user's key verifies the signature
```

## 10.4 Key Version Verification

```
Algorithm: VERIFY_KEY_VERSION

Input:
  state          — Attribute Machine state
  user_id        — User identifier
  claimed_version — Claimed key version from operation

Output:
  valid — True if key version is current

1. if user_id == "":
        return true  // Mode B — skip version check

2. user = state.users[user_id]
3. if user == null:
        return false

4. if user.key_version != claimed_version:
        return false
        // "Key version {claimed_version} is stale.
        //  Current version is {user.key_version}.
        //  Please refresh your key."

5. return true
```

---

# 11. Key Management

## 11.1 Key Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                    KEY HIERARCHY                              │
│                                                              │
│  Master Secret Key (MSK)                                     │
│    ├── Held by: All nodes (secret-shared optional)           │
│    ├── Used for: ABE key generation                          │
│    └── Rotation: Via protocol transition (threshold)         │
│                                                              │
│  Master Public Key (MPK)                                     │
│    ├── Held by: All nodes + all users                        │
│    ├── Used for: ABE encryption, key verification            │
│    └── Public: No protection needed                          │
│                                                              │
│  User ABE Key (SK_abe)                                       │
│    ├── Held by: User only                                    │
│    ├── Used for: Decrypting capability vault entries         │
│    ├── Versioned: Bound to state version                     │
│    └── Refresh: Via __refresh_abe_key__ operation            │
│                                                              │
│  User ECDSA Key (sk_ecdsa / pk_ecdsa)                        │
│    ├── Held by: User (sk_ecdsa), public (pk_ecdsa)          │
│    ├── Used for: Signing operations                          │
│    ├── Long-lived: Changes only on compromise                │
│    └── Registered: In Attribute Machine at user creation     │
│                                                              │
│  Lock Tokens                                                 │
│    ├── Held by: User (temporary)                             │
│    ├── Used for: Proving lock ownership                      │
│    ├── Ephemeral: Generated per lock acquisition             │
│    └── Expire: With the lock                                 │
└─────────────────────────────────────────────────────────────┘
```

## 11.2 Key Envelope Format

```
KeyEnvelope = {
    format_version: uint8 = 0x01,
    user_id: string,
    state_version: uint64,
    attributes_hash: byte[32],
    issued_at: uint64,
    expires_at: uint64,       // 0 = no expiry
    sk_abe: byte[],           // ABE secret key (implementation-specific)
    signature: byte[64]       // Signed by the node for authenticity
}
```

## 11.3 Key Refresh Flow

```
1. User detects their key is stale (operation rejected with KEY_STALE)

2. User creates __refresh_abe_key__ operation:
   op = {
       type: "__refresh_abe_key__",
       payload: {user_id: "alice"},
       policy: "role:member",
       signature: ECDSA_sign(user_sk_ecdsa, serialize(op))
   }

3. Node processes operation:
   a. Verify signature against user's registered public key
   b. Look up user's current attributes from Attribute Machine state
   c. Generate new ABE key: sk_new = ABE_keygen(msk, mpk, current_attrs)
   d. Create key envelope with current state version
   e. Increment user.key_version in Attribute Machine state
   f. Return envelope to user

4. User receives new key envelope:
   a. Verify envelope signature
   b. Store new key
   c. Discard old key
   d. Retry failed operation with new key
```

## 11.4 Key Compromise Recovery

```
Algorithm: REVOKE_AND_ROTATE_KEYS

Input:
  state       — Attribute Machine state
  msk         — ABE master secret key
  mpk         — ABE master public key
  compromised_user — User ID whose key was compromised
  requester   — Admin performing the revocation

1. // Suspend the compromised user
2. state.users[compromised_user].status = SUSPENDED

3. // Increment key version (invalidates all existing keys for this user)
4. state.users[compromised_user].key_version += 1

5. // Generate new ECDSA keypair for the user
6. new_sk, new_pk = ECDSA_generate()

7. // Update user's public key
8. state.users[compromised_user].public_key = new_pk

9. // Generate new ABE key
10. attr_string = build_attr_string(state.users[compromised_user].attributes)
11. new_sk_abe = ABE_keygen(msk, mpk, attr_string)

12. // Log
13. log(state, {
         type: "key_compromise_recovery",
         user: compromised_user,
         performed_by: requester,
         timestamp: now()
     })

14. // Return new keys (delivered via secure out-of-band channel)
15. return {sk_ecdsa: new_sk, sk_abe: new_sk_abe}
```

---

# 12. CRDT Merge Rules

## 12.1 General Merge Algorithm

```
Algorithm: CRDT_MERGE

Input:
  state_a — First state replica
  state_b — Second state replica

Output:
  merged — Merged state

1. merged = deep_copy(state_a)

2. // Merge each data item
3. for each (name, item_b) in state_b.items:
4.     if name not in merged.items:
5.         merged.items[name] = item_b
6.     else:
7.         item_a = merged.items[name]
8.         merged.items[name].value = MERGE_VALUE(item_a, item_b)

9. // Merge transition logs (sorted by lamport_time, then node_id)
10. merged.log = MERGE_LOGS(state_a.log, state_b.log)

11. // Merge processed operation sets (union)
12. merged.processed_ops = state_a.processed_ops ∪ state_b.processed_ops

13. // Version is max of both
14. merged.version = max(state_a.version, state_b.version)

15. return merged
```

## 12.2 Per-Type Merge Functions

### 12.2.1 G-Counter (COUNTER)

```
Algorithm: MERGE_G_COUNTER

Input:
  a, b — Counter values

Output:
  merged — Merged counter

// G-Counter is represented as a vector of per-node increments
// Merge takes the element-wise maximum

1. merged = copy(a)
2. for each node_id in b:
3.     merged[node_id] = max(merged[node_id], b[node_id])
4. return merged

// Total value: sum of all elements
```

### 12.2.2 PN-Counter (PN_COUNTER)

```plaintext
Algorithm: MERGE_PN_COUNTER

Input:
  a, b — PN-Counter values (each has pos and neg G-Counters)

Output:
  merged — Merged PN-Counter

1. merged.pos = MERGE_G_COUNTER(a.pos, b.pos)
2. merged.neg = MERGE_G_COUNTER(a.neg, b.neg)
3. return merged

// Total value: sum(pos) - sum(neg)
```

### 12.2.3 OR-Set (SET)

```plaintext
Algorithm: MERGE_OR_SET

Input:
  a, b — OR-Set values (each has elements and tombstones)

Output:
  merged — Merged OR-Set

1. merged.elements = a.elements ∪ b.elements
2. merged.tombstones = a.tombstones ∪ b.tombstones
3. merged.elements = merged.elements ∖ merged.tombstones
4. return merged

// Add: element added with unique tag (node_id + counter)
// Remove: element tag added to tombstones
// Element is visible iff tag is in elements but not in tombstones
```

### 12.2.4 Two-Phase Set (2P_SET)

```plaintext
Algorithm: MERGE_2P_SET

Input:
  a, b — 2P-Set values (each has add_set and remove_set)

Output:
  merged — Merged 2P-Set

1. merged.add_set = a.add_set ∪ b.add_set
2. merged.remove_set = a.remove_set ∪ b.remove_set
3. return merged

// Element is visible iff in add_set but not in remove_set
// Once removed, cannot be re-added
```

### 12.2.5 LWW-Register (REGISTER)

```
Algorithm: MERGE_LWW_REGISTER

Input:
  a, b — LWW-Register values (each has value and timestamp)

Output:
  merged — Merged LWW-Register

1. if b.timestamp > a.timestamp:
2.     merged = copy(b)
3. else if a.timestamp > b.timestamp:
4.     merged = copy(a)
5. else:
6.     // Same timestamp — use node_id as tiebreaker
7.     if b.node_id > a.node_id:
8.         merged = copy(b)
9.     else:
10.        merged = copy(a)
11. return merged
```

### 12.2.6 RGA (DOCUMENT)

```plaintext
Algorithm: MERGE_RGA

Input:
  a, b — RGA values (each is a linked list of nodes with IDs)

Output:
  merged — Merged RGA

// RGA uses a tree-based merge:
// 1. Each insert creates a node with a unique ID and a reference to its predecessor
// 2. Merge preserves the causal order of inserts
// 3. Concurrent inserts at the same position are ordered by node_id

1. merged = copy(a)
2. for each node in b:
3.     if node.id not in merged:
4.         // Find the insert position (after predecessor)
5.         pos = find_predecessor_position(merged, node.predecessor_id)
6.         // If concurrent with existing nodes at same position,
7.         // order by (predecessor_id, node_id)
8.         insert_at(merged, pos, node)
9. return merged
```

## 12.3 Lock State Merge

Locks are NOT merged across replicas — they are local to each node. However, the lock timeout mechanism ensures convergence:

```
Algorithm: MERGE_LOCK_STATE

Input:
  lock_a — Lock state from replica A
  lock_b — Lock state from replica B

Output:
  merged — Merged lock state

// Lock state is NOT replicated. Each node maintains its own.
// Convergence is achieved via lock timeout:
//   - If a node sees a lock that has expired, it force-unlocks
//   - All nodes eventually agree that expired locks are released
//   - Active locks are only meaningful on the node that granted them

1. return lock_a  // Local lock state is authoritative
```

---

# 13. Serialization

## 13.1 State Serialization Format

```plaintext
SerializedState = {
    magic: byte[4] = "CRAB",        // Magic bytes
    version: uint32 = 1,            // Serialization format version
    
    // Header
    state_version: uint64,          // CRABS state version
    item_count: uint32,             // Number of data items
    policy_count: uint32,           // Number of policies
    log_count: uint32,              // Number of log entries
    
    // Data items
    items: DataItemSerialized[],
    
    // Policies
    policies: PolicySerialized[],
    
    // Configuration
    config: ConfigSerialized,
    
    // Log
    log: LogEntrySerialized[],
    
    // Checksum
    checksum: byte[32]              // SHA256 of all preceding bytes
}
```

## 13.2 Data Item Serialization

```
DataItemSerialized = {
    name_length: uint16,
    name: byte[name_length],
    type_id: uint8,
    crdt_type_id: uint8,
    protocol_state: uint8,
    value_length: uint32,
    value: byte[value_length],
    invariant_count: uint8,
    invariants: InvariantSerialized[invariant_count]
}
```

## 13.3 Operation Serialization (for signing)

See Section 7.5 — `SERIALIZE_FOR_SIGNING`.

---

# 14. Security Considerations

## 14.1 Threat Model

Threat	Description	Mitigation
**Key compromise**	User's ECDSA key or ABE key is stolen	Key revocation protocol, key versioning
**MSK compromise**	Master secret key is stolen	Threshold MSK (future work), MSK rotation
**Replay attack**	Old operation is replayed	UUID uniqueness, Lamport clocks, processed_ops set
**Lock starvation**	User holds lock indefinitely	Lock timeout, force-unlock
**Collusion**	Users combine keys to gain unauthorized access	ABE collusion resistance (randomized keys)
**Sybil attack**	Attacker creates many fake users	Registration policy (role:admin required)
**Timing attack**	Attacker observes lock timing to infer information	Constant-time operations where possible
**State fork**	Two nodes diverge permanently	CRDT merge guarantees eventual convergence

## 14.2 Security Assumptions

1. **Hash function security**: SHA-256 is collision-resistant
2. **Signature security**: ECDSA with secp256k1 is existentially unforgeable
3. **Pairing security**: The bilinear group is secure against the q-SDH and DLIN assumptions
4. **Randomness**: All random values are generated with a CSPRNG
5. **Clock synchronization**: Node clocks are within reasonable skew (NTP-synchronized)

## 14.3 Operational Security

1. **MSK protection**: The MSK MUST be stored encrypted at rest and only loaded into memory during key generation operations
2. **Key delivery**: Initial ABE keys and ECDSA keypairs MUST be delivered via secure out-of-band channels
3. **Lock token entropy**: Lock tokens MUST be generated with a CSPRNG (at least 256 bits of entropy)
4. **Log integrity**: The transition log SHOULD be periodically hashed and the hash published to an external audit service
5. **Clock skew**: Lock timeout values SHOULD be at least 2x the expected maximum network latency

---

# 15. Implementation Guidelines

## 15.1 Required Dependencies

Library	Version	Purpose
openabe-c	≥ 0.1.0	CP-ABE implementation
OpenSSL	≥ 1.1.1	ECDSA, SHA-256, CSPRNG
PBC	≥ 0.5.14	Bilinear pairings (via openabe-c)
GMP	≥ 6.0	Arbitrary precision arithmetic (via openabe-c)

## 15.2 Implementation Checklist

A conforming implementation MUST implement:

- [ ] State data model (Section 4)
- [ ] Built-in data types with CRDT merge (Sections 5, 12)
- [ ] Protocol state machine with all transitions (Section 6)
- [ ] Operation structure and execution (Section 7)
- [ ] All built-in operations (Section 7.3)
- [ ] Attribute Machine with all attribute operations (Section 8)
- [ ] Atomic lock acquisition (Section 9.2)
- [ ] Lock extension (Section 9.3)
- [ ] Force unlock (Section 9.4)
- [ ] Lock expiry pruning (Section 9.5)
- [ ] ABE key generation and verification (Section 10)
- [ ] ECDSA signing and verification (Section 10.2)
- [ ] ABE-gated signature verification (Section 10.3)
- [ ] Key version verification (Section 10.4)
- [ ] Key refresh flow (Section 11.3)
- [ ] State serialization (Section 13)

A conforming implementation SHOULD implement:

- [ ] Key compromise recovery (Section 11.4)
- [ ] CRDT merge for all types (Section 12)
- [ ] Log integrity checks (Section 14.3.4)

## 15.3 Test Vectors

Test vectors are provided in Appendix A for:

1. Genesis state creation
2. User registration
3. Lock acquisition and release
4. Operation signing and verification
5. CRDT merge of concurrent operations
6. Lock timeout and force-unlock
7. Key refresh after attribute change
8. Collusion resistance verification

---

# 16. Test Vectors

*To be generated by reference implementation.*

---

# Appendix A: Glossary

Term	Definition
**ABE**	Attribute-Based Encryption — cryptographic primitive for policy-based access control
**Attribute Machine**	The root CRABS state machine whose state is the set of all users and their attributes
**Capability Vault**	Data structure mapping (operation, user_id) to ABE-encrypted ECDSA signing keys
**CP-ABE**	Ciphertext-Policy ABE — policies are embedded in ciphertexts
**CRABS**	Cryptographic Role-based Attribute-gated Blockchain-like State machine
**CRDT**	Conflict-free Replicated Data Type — data structure that converges without consensus
**ECDSA**	Elliptic Curve Digital Signature Algorithm — used for operation signatures
**Force Unlock**	Releasing an expired lock, rolling back any unverified changes
**Invariant**	Post-condition check on a data item's value (e.g., "must be ≥ 0")
**Lamport Clock**	Logical clock for causal ordering of operations
**Lock Token**	Random 32-byte value proving ownership of a lock
**Mode A**	Audit mode — operation includes signer identity
**Mode B**	Privacy mode — operation omits signer identity
**MSK**	Master Secret Key — used to generate ABE user keys
**MPK**	Master Public Key — used to encrypt data under policies
**Protocol State**	The current state of a resource in its lifecycle (idle, locked, modified, etc.)
**Resource**	A data item with inherent scarcity that requires locking for safe access

---

# Appendix B: Error Codes

Code	Name	Description
`0x0000`	`SUCCESS`	Operation completed successfully
`0x1001`	`PROTOCOL_VIOLATION`	Resource is not in the required protocol state
`0x1002`	`LOCK_TOKEN_MISMATCH`	Provided lock token does not match the resource's lock
`0x1003`	`LOCK_OWNER_MISMATCH`	Operation signer does not match lock owner
`0x1004`	`LOCK_CONTENTION`	Could not acquire all locks atomically
`0x1005`	`LOCK_NOT_EXPIRED`	Cannot force-unlock a lock that hasn't expired
`0x1006`	`MAX_EXTENSIONS_REACHED`	Lock has been extended the maximum number of times
`0x1007`	`FORCE_UNLOCK_DISABLED`	This machine does not allow force-unlock
`0x2001`	`UNAUTHORIZED`	Signer's attributes do not satisfy the operation's policy
`0x2002`	`KEY_STALE`	Signer's ABE key version does not match current state
`0x2003`	`USER_NOT_FOUND`	Specified user does not exist in the Attribute Machine
`0x2004`	`USER_SUSPENDED`	Specified user is suspended
`0x3001`	`INVARIANT_VIOLATED`	Operation result violates a data item's invariant
`0x3002`	`RESOURCE_NOT_FOUND`	Specified resource does not exist in the state
`0x3003`	`DUPLICATE_OPERATION`	Operation UUID has already been processed
`0x4001`	`SERIALIZATION_ERROR`	Failed to serialize or deserialize state
`0x4002`	`CRYPTOGRAPHIC_ERROR`	Underlying cryptographic primitive failed
`0x5001`	`INTERNAL_ERROR`	Unexpected internal error

---

# Appendix C: Canonical Encoding

All data structures that are hashed or signed MUST use canonical encoding to ensure cross-implementation compatibility.

## C.1 Rules

1. **Integers**: Fixed-width, little-endian byte order
2. **Strings**: Length-prefixed (uint16 length + UTF-8 bytes)
3. **Byte arrays**: Length-prefixed (uint32 length + bytes)
4. **Arrays**: Length-prefixed (uint32 count + elements)
5. **Maps**: Sorted by key (lexicographic byte order), then key-value pairs
6. **Enums**: Single byte value
7. **No optional fields**: All fields are present (use sentinel values for null)

## C.2 Example

```
Operation canonical encoding:
┌──────────────────────────────────────────────┐
│ type:         uint16 len + bytes              │
│ uuid:         16 bytes                        │
│ payload:      uint32 len + bytes              │
│ resources:    uint32 count                    │
│   [0]:        uint16 len + bytes              │
│   ...                                         │
│ required_state: uint32 count + uint8[]        │
│ next_state:   uint32 count + uint8[]          │
│ lock_claims:  uint32 count                    │
│   [0]:        uint16 len + bytes (resource)   │
│               32 bytes (token)                │
│   ...                                         │
│ policy:       uint16 len + bytes              │
│ signer_id:    uint16 len + bytes              │
│ signer_key_version: uint64                    │
│ lamport_time: uint64                          │
│ node_id:      uint16 len + bytes              │
└──────────────────────────────────────────────┘
```

🦀 **"Hard shell. Sharp pincers. No backdoors."**