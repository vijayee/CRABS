# CRABS Protocol Specification v1.3 — Amendment 3

## *Cryptographic Agility: Pluggable Signature Schemes*

---

**Amendment Status:** Draft
**Spec Version:** 1.3.0
**Date:** April 30, 2026
**Supersedes:** Base spec §10.2 (ECDSA Signatures)

---

## Preamble

The base CRABS protocol (v1.0) specifies ECDSA with secp256k1 as the sole signature scheme for operation authentication. This creates a hard dependency on a single cryptographic primitive, which is undesirable for several reasons:

1. **Post-quantum migration**: ECDSA is vulnerable to Shor's algorithm. Future-proof systems must support lattice-based schemes like Dilithium.
2. **Performance diversity**: Different deployment contexts benefit from different schemes — Ed25519 for mobile devices, BLS for signature aggregation, RSA for legacy HSM integration.
3. **Regulatory requirements**: Some jurisdictions mandate specific algorithms (e.g., CNSA in US government systems).
4. **Key rotation**: Migrating between schemes should not require protocol changes.

This amendment introduces a **pluggable signature abstraction layer** that allows CRABS to support multiple signature schemes simultaneously, with per-user multi-key registration, per-operation scheme selection, and policy-level scheme constraints.

---

## 1. Motivation

### 1.1 Current Limitation

```plaintext
Base spec v1.0:
  - Signature: ECDSA secp256k1 only
  - Key size: 33 bytes public, 32 bytes private
  - Signature size: 64 bytes
  - Hardcoded in operation struct and verification logic
```

### 1.2 Desired Flexibility

```plaintext
v1.3:
  - Multiple schemes: ECDSA, Ed25519, Schnorr, BLS, Dilithium, RSA
  - Per-user multi-key: User registers keys for different schemes
  - Per-operation selection: Operation declares which scheme was used
  - Policy constraints: "sig_scheme:dilithium_3" in policies
  - Graceful migration: Accept multiple schemes during transition periods
  - Extensible: New schemes added without protocol changes
```

---

## 2. Signature Scheme Registry

### 2.1 Scheme Identifiers

Each supported signature scheme is identified by a unique byte:

```plaintext
SignatureScheme = enum {
    // Elliptic curve schemes
    ECDSA_SECP256K1     = 0x01,  // ECDSA over secp256k1 (Bitcoin/Ethereum compatible)
    ECDSA_P256          = 0x02,  // ECDSA over NIST P-256
    ED25519             = 0x03,  // EdDSA over Curve25519
    SCHNORR_SECP256K1   = 0x04,  // Schnorr over secp256k1 (BIP-340)

    // Pairing-based schemes
    BLS_BLS12_381       = 0x05,  // BLS signatures over BLS12-381

    // Legacy schemes
    RSA_2048            = 0x06,  // RSA with 2048-bit key
    RSA_4096            = 0x07,  // RSA with 4096-bit key

    // Post-quantum schemes (NIST standardized)
    DILITHIUM_2         = 0x08,  // ML-DSA-44 (NIST Level 2)
    DILITHIUM_3         = 0x09,  // ML-DSA-65 (NIST Level 3)
    DILITHIUM_5         = 0x0A,  // ML-DSA-87 (NIST Level 5)
    FALCON_512          = 0x0B,  // FN-DSA-512 (NIST alternative)
    FALCON_1024         = 0x0C,  // FN-DSA-1024 (NIST alternative)
    SPHINCS_PLUS_128S   = 0x0D,  // SLH-DSA-SHAKE-128s (stateless hash-based)

    // Reserved for application-defined schemes
    CUSTOM_BASE         = 0xF0,
    CUSTOM_MAX          = 0xFE,

    // Invalid / unset
    SCHEME_UNSPECIFIED  = 0x00,
    SCHEME_CUSTOM       = 0xFF
}
```

### 2.2 Scheme Properties

Each scheme has a fixed set of properties known at registration time:

```plaintext
SchemeProperties = {
    scheme_id: uint8,
    name: string,                    // Human-readable name
    security_level: uint8,           // 1-5 (matching NIST security levels)
    is_post_quantum: bool,           // True if resistant to quantum attacks

    // Key sizes
    public_key_size: uint16,         // Maximum public key size in bytes
    secret_key_size: uint16,         // Maximum secret key size in bytes
    signature_size: uint16,          // Maximum signature size in bytes

    // Capabilities
    supports_batch_verification: bool,
    supports_aggregation: bool,
    supports_threshold: bool,

    // Performance characteristics (relative, for documentation)
    sign_speed: uint8,               // 1 (slow) to 10 (fast)
    verify_speed: uint8,             // 1 (slow) to 10 (fast)
    keygen_speed: uint8              // 1 (slow) to 10 (fast)
}
```

### 2.3 Built-in Scheme Properties

```plaintext
┌─────────────────────┬──────┬───────┬───┬────────┬──────┬──────┬──────┐
│ Scheme              │  ID  │ PK sz │SK sz│Sig sz  │PQ?  │Batch?│Speed │
├─────────────────────┼──────┼───────┼───┼────────┼──────┼──────┼──────┤
│ ECDSA secp256k1     │ 0x01 │   33  │ 32│   64   │  No  │  No  │ Fast │
│ ECDSA P-256         │ 0x02 │   33  │ 32│   64   │  No  │  No  │ Fast │
│ Ed25519             │ 0x03 │   32  │ 32│   64   │  No  │ Yes  │ Fast │
│ Schnorr secp256k1   │ 0x04 │   32  │ 32│   64   │  No  │ Yes  │ Fast │
│ BLS BLS12-381       │ 0x05 │   48  │ 32│   96   │  No  │ Yes  │ Med  │
│ RSA 2048            │ 0x06 │  256  │512│  256   │  No  │  No  │ Slow │
│ RSA 4096            │ 0x07 │  512  │1K │  512   │  No  │  No  │ Slow │
│ Dilithium 2         │ 0x08 │ 1312  │2.5K│ 2420  │ Yes  │  No  │ Med  │
│ Dilithium 3         │ 0x09 │ 1952  │4K │ 3293  │ Yes  │  No  │ Med  │
│ Dilithium 5         │ 0x0A │ 2592  │5K │ 4595  │ Yes  │  No  │ Med  │
│ Falcon 512          │ 0x0B │  897  │1.3K│  666  │ Yes  │  No  │ Slow │
│ Falcon 1024         │ 0x0C │ 1793  │2.6K│ 1280  │ Yes  │  No  │ Slow │
│ SPHINCS+ 128s       │ 0x0D │   32  │ 64│ 7856  │ Yes  │  No  │ VSlow│
└─────────────────────┴──────┴───────┴───┴────────┴──────┴──────┴──────┘
```

---

## 3. Virtual Table Interface

### 3.1 Signature VTable

Every signature scheme MUST implement this interface:

```plaintext
SignatureVTable = {
    // Identity
    scheme_id: uint8,
    name: string,
    properties: SchemeProperties,

    // === Required Operations ===

    // Generate a keypair
    //   pk:  Output buffer for public key
    //   pk_len:  Input: buffer capacity, Output: actual length
    //   sk:  Output buffer for secret key
    //   sk_len:  Input: buffer capacity, Output: actual length
    //   Returns: SUCCESS or error
    generate_keypair: function(
        pk: byte[], pk_len: uint32*,
        sk: byte[], sk_len: uint32*
    ) -> int,

    // Sign a message
    //   sk:     Secret key
    //   sk_len: Secret key length
    //   msg:    Message to sign
    //   msg_len: Message length
    //   sig:    Output buffer for signature
    //   sig_len: Input: buffer capacity, Output: actual length
    //   Returns: SUCCESS or error
    sign: function(
        sk: byte[], sk_len: uint32,
        msg: byte[], msg_len: uint32,
        sig: byte[], sig_len: uint32*
    ) -> int,

    // Verify a signature
    //   pk:     Public key
    //   pk_len: Public key length
    //   msg:    Message that was signed
    //   msg_len: Message length
    //   sig:    Signature to verify
    //   sig_len: Signature length
    //   Returns: SUCCESS if valid, VERIFY_FAILED if invalid, error otherwise
    verify: function(
        pk: byte[], pk_len: uint32,
        msg: byte[], msg_len: uint32,
        sig: byte[], sig_len: uint32
    ) -> int,

    // === Optional Operations (may be NULL) ===

    // Batch verification — verify multiple signatures at once
    //   Can be more efficient than individual verification
    //   If NULL, the protocol falls back to individual verify() calls
    verify_batch: function(
        pks: byte[][], pk_lens: uint32[],
        msgs: byte[][], msg_lens: uint32[],
        sigs: byte[][], sig_lens: uint32[],
        count: uint32
    ) -> int,  // NULL if not supported

    // Aggregate signatures (for BLS)
    aggregate_signatures: function(
        sigs: byte[][], sig_lens: uint32[],
        count: uint32,
        aggregated: byte[], aggregated_len: uint32*
    ) -> int,  // NULL if not supported

    // Serialization helpers
    export_public_key: function(
        pk: byte[], pk_len: uint32,
        buf: byte[], buf_len: uint32*
    ) -> int,

    import_public_key: function(
        buf: byte[], buf_len: uint32,
        pk: byte[], pk_len: uint32*
    ) -> int,

    export_secret_key: function(
        sk: byte[], sk_len: uint32,
        buf: byte[], buf_len: uint32*
    ) -> int,

    import_secret_key: function(
        buf: byte[], buf_len: uint32,
        sk: byte[], sk_len: uint32*
    ) -> int
}
```

### 3.2 VTable Registry

```plaintext
Global registry mapping scheme_id → VTable:

SignatureRegistry = {
    schemes: {
        <scheme_id>: SignatureVTable,
        ...
    },
    count: uint32
}

// Register a scheme at initialization time
function REGISTER_SIGNATURE_SCHEME(vtable: SignatureVTable) -> int:
    if registry.schemes[vtable.scheme_id] != null:
        return SCHEME_ALREADY_REGISTERED
    registry.schemes[vtable.scheme_id] = vtable
    registry.count += 1
    return SUCCESS

// Look up a scheme by ID
function GET_SIGNATURE_VTABLE(scheme_id: uint8) -> SignatureVTable:
    return registry.schemes[scheme_id]

// List all registered schemes
function LIST_REGISTERED_SCHEMES() -> SignatureScheme[]:
    result = []
    for each (id, vtable) in registry.schemes:
        result.append(id)
    return result
```

---

## 4. Changes to Data Structures

### 4.1 Updated User Record

The user record in the Attribute Machine is extended to support multiple keys:

```plaintext
User = {
    // ... existing fields (attributes, status, key_version, ...)

    // NEW: Multiple public keys for different signature schemes
    keys: {
        "<key_id>": UserKey,
        ...
    },
    default_key_id: string,      // Which key to use by default

    // ... existing fields (temporary_attributes, etc.) ...
}

UserKey = {
    key_id: string,              // e.g., "ecdsa_main", "ed25519_mobile"
    scheme: SignatureScheme,     // e.g., ECDSA_SECP256K1
    public_key: byte[],          // Raw public key bytes
    public_key_len: uint32,
    label: string,               // Human-readable label
    registered_at: uint64,
    last_used_at: uint64,
    is_active: bool              // Can be disabled without removal
}
```

### 4.2 Updated Operation Structure

```plaintext
Operation = {
    // ... existing fields (type, payload, resources, etc.) ...

    // REPLACED: Single ECDSA signature → scheme-aware signature
    sig_scheme: SignatureScheme,     // NEW: Which scheme was used
    key_id: string,                  // NEW: Which of the user's keys signed
    signature: byte[],               // Variable-length signature
    signature_len: uint32,

    // NEW: Co-signers for multi-signature operations
    co_signers: CoSignature[],
    co_signer_count: uint32,

    // ... existing fields (signer_id, lamport_time, etc.) ...
}

CoSignature = {
    signer_id: string,
    key_id: string,
    sig_scheme: SignatureScheme,
    signature: byte[],
    signature_len: uint32
}
```

### 4.3 Updated Vault Entry

```plaintext
VaultEntry = {
    user_id: string,
    key_id: string,              // NEW: Which key this entry is for
    scheme: SignatureScheme,     // NEW: Which scheme this key uses
    encrypted_sk: byte[],        // ABE-encrypted secret key
    encrypted_sk_len: uint32
}
```

---

## 5. New Built-in Operations

### 5.1 `__register_key__`

Register a new public key for a user.

```plaintext
Operation = {
    type: "__register_key__",
    payload: {
        key_id: "ecdsa_main",
        scheme: ECDSA_SECP256K1,
        public_key: <33 bytes>,
        label: "My primary ECDSA key",
        set_as_default: true
    },
    policy: "role:member",       // Any member can register their own key
    // Signed with EXISTING registered key to prove ownership
    signature: {...}
}
```

### 5.2 `__revoke_key__`

Revoke a registered key without removing the user.

```plaintext
Operation = {
    type: "__revoke_key__",
    payload: {
        key_id: "ecdsa_main",
        reason: "Key compromised"
    },
    policy: "role:member OR role:admin",
    signature: {...}
}
```

### 5.3 `__set_default_key__`

Change which key is used by default for signing.

```plaintext
Operation = {
    type: "__set_default_key__",
    payload: {
        key_id: "ed25519_mobile"
    },
    policy: "role:member",
    signature: {...}
}
```

---

## 6. Modified Verification Algorithm

### 6.1 Single-Signature Verification

```plaintext
Algorithm: VERIFY_OPERATION_SIGNATURE (v1.3)

Input:
  state     — Current CRABS state
  op        — Operation with signature
  signer_id — Claimed signer (from op.signer_id)

Output:
  valid     — True if signature verifies against a registered key

1. if signer_id == "":
       // Mode B (privacy) — handled separately
       return VERIFY_OPERATION_SIGNATURE_MODE_B(state, op)

2. // Look up the user
3. user = attribute_machine.users[signer_id]
4. if user == null or user.status != ACTIVE:
       return false

5. // Get the specific key used for this signature
6. if op.key_id != "":
       // User specified which key they used
       key = user.keys[op.key_id]
       if key == null or not key.is_active:
           return false
       if key.scheme != op.sig_scheme:
           return false  // Key exists but scheme doesn't match
       return VERIFY_WITH_KEY(key, op)

7. else:
       // No key_id specified — try all active keys for this scheme
       for each (key_id, key) in user.keys:
           if key.is_active and key.scheme == op.sig_scheme:
               if VERIFY_WITH_KEY(key, op):
                   return true
       return false


Algorithm: VERIFY_WITH_KEY

Input:
  key — UserKey to verify against
  op  — Operation with signature

Output:
  valid — True if signature verifies

1. vtable = GET_SIGNATURE_VTABLE(key.scheme)
2. if vtable == null:
       return false  // Scheme not registered on this node

3. msg_bytes = SERIALIZE_FOR_SIGNING(op)
4. result = vtable.verify(
       key.public_key, key.public_key_len,
       msg_bytes, len(msg_bytes),
       op.signature, op.signature_len
   )

5. if result == SUCCESS:
       key.last_used_at = now()
       return true

6. return false
```

### 6.2 Mode B (Privacy) Verification

```plaintext
Algorithm: VERIFY_OPERATION_SIGNATURE_MODE_B

Input:
  state — Current CRABS state
  op    — Operation with signature (signer_id is empty)

Output:
  valid — True if ANY authorized user's key verifies

1. // Find the policy for this operation
2. policy = state.policies[op.type]
3. if policy == null:
       return false

4. // Find ALL users whose attributes satisfy the policy
5. authorized_users = FIND_USERS_SATISFYING_POLICY(
       attribute_machine, policy
   )

6. // Try each user's keys
7. for each user_id in authorized_users:
8.     user = attribute_machine.users[user_id]
9.     for each (key_id, key) in user.keys:
10.        if key.is_active and key.scheme == op.sig_scheme:
11.            vtable = GET_SIGNATURE_VTABLE(key.scheme)
12.            if vtable == null:
13.                continue
14.
15.            msg_bytes = SERIALIZE_FOR_SIGNING(op)
16.            if vtable.verify(
17.                key.public_key, key.public_key_len,
18.                msg_bytes, len(msg_bytes),
19.                op.signature, op.signature_len
20.            ) == SUCCESS:
21.                return true  // Some authorized user signed this

22. return false  // No authorized user's key verifies
```

### 6.3 Multi-Signature Verification

```plaintext
Algorithm: VERIFY_MULTI_SIGNATURE_OPERATION

Input:
  state — Current CRABS state
  op    — Operation with co-signers

Output:
  valid — True if ALL required signatures are valid

1. // Verify the primary signature (the operation's main signer)
2. if not VERIFY_OPERATION_SIGNATURE(state, op, op.signer_id):
       return false

3. // Verify each co-signer
4. for each co_sig in op.co_signers:
5.     if not VERIFY_OPERATION_SIGNATURE(state, op, co_sig.signer_id):
6.         return false  // A co-signer's signature is invalid

7. // Check that the policy's threshold is met
8. // (e.g., "2of3(role:admin)" requires 2 of 3 admins to sign)
9. if not CHECK_MULTI_SIG_THRESHOLD(state, op):
10.    return false

11. return true
```

---

## 7. Policy Integration

### 7.1 Scheme Constraints in Policies

Policies can now reference signature schemes:

```plaintext
// Standard attribute-based policy
"role:admin"

// Scheme-constrained: must use a specific scheme
"role:admin AND sig_scheme:ed25519"

// Multiple acceptable schemes
"role:admin AND (sig_scheme:ecdsa_secp256k1 OR sig_scheme:ed25519)"

// Post-quantum requirement
"role:admin AND sig_scheme:dilithium_3"

// Key ID constraint (specific key)
"role:admin AND key_id:ecdsa_hsm_1"

// Multi-sig with scheme constraints
"2of3(role:admin AND sig_scheme:dilithium_3)"
```

### 7.2 Policy Pre-processing

```plaintext
Algorithm: PREPROCESS_SCHEME_POLICY

Input:
  policy    — Policy expression string
  op        — Operation being verified

Output:
  abe_policy    — ABE-compatible policy (sig_scheme constraints removed)
  scheme_ok     — Whether the operation's scheme satisfies constraints

1. abe_policy = policy
2. scheme_ok = true

3. // Extract sig_scheme constraints
4. scheme_exprs = EXTRACT_SCHEME_EXPRESSIONS(policy)

5. for each expr in scheme_exprs:
6.     if expr specifies a single scheme:
7.         if op.sig_scheme != expr.required_scheme:
8.             scheme_ok = false
9.             break
10.
11.    if expr specifies multiple schemes (OR):
12.        if op.sig_scheme not in expr.accepted_schemes:
13.            scheme_ok = false
14.            break
15.
16.    // Remove satisfied scheme constraint from ABE policy
17.    abe_policy = REMOVE_EXPRESSION(abe_policy, expr)

18. // Extract key_id constraints
19. key_exprs = EXTRACT_KEY_ID_EXPRESSIONS(policy)
20. for each expr in key_exprs:
21.     if op.key_id != expr.required_key_id:
22.         scheme_ok = false
23.         break
24.     abe_policy = REMOVE_EXPRESSION(abe_policy, expr)

25. return {abe_policy, scheme_ok}
```

---

## 8. Machine Configuration

### 8.1 Allowed Schemes

Each state machine can restrict which signature schemes are accepted:

```plaintext
MachineConfig = {
    // ... existing fields ...

    // NEW: Signature scheme configuration
    sig_config: SignatureConfig
}

SignatureConfig = {
    // Which schemes are accepted by this machine
    allowed_schemes: SignatureScheme[],

    // Minimum security level required (1-5)
    min_security_level: uint8,       // 0 = no minimum

    // Whether post-quantum schemes are required
    require_post_quantum: bool,

    // Whether multi-signature operations are allowed
    allow_multi_sig: bool,

    // Maximum number of co-signers
    max_co_signers: uint32,          // Default: 0 (disabled)

    // Whether to accept operations with no key_id specified
    require_key_id: bool             // Default: false
}
```

### 8.2 Setup with Scheme Configuration

```plaintext
crabs_setup(&state, &mpk, &msk,
    .sig_config = {
        .allowed_schemes = {
            ECDSA_SECP256K1,
            ED25519,
            DILITHIUM_3
        },
        .min_security_level = 2,
        .require_post_quantum = false,
        .allow_multi_sig = true,
        .max_co_signers = 5,
        .require_key_id = false
    }
);
```

### 8.3 Changing Scheme Configuration

```plaintext
Operation = {
    type: "__change_sig_config__",
    payload: {
        allowed_schemes: [ECDSA_SECP256K1, ED25519, DILITHIUM_3],
        min_security_level: 3,
        require_post_quantum: true
    },
    policy: "role:admin AND weight >= 3",
    signature: {...}
}
```

---

## 9. Key Lifecycle

### 9.1 Registration Flow

```plaintext
1. User generates a keypair locally:
   vtable = GET_SIGNATURE_VTABLE(ED25519)
   vtable.generate_keypair(pk, &pk_len, sk, &sk_len)

2. User registers the public key:
   Operation = {
       type: "__register_key__",
       payload: {
           key_id: "ed25519_mobile",
           scheme: ED25519,
           public_key: pk,
           label: "Phone key",
           set_as_default: false
       },
       // Signed with EXISTING registered key
       sig_scheme: ECDSA_SECP256K1,
       key_id: "ecdsa_main",
       signature: ecdsa_sign(existing_sk, serialize(op))
   }

3. State machine:
   a. Verifies signature with existing ECDSA key
   b. Stores new Ed25519 public key
   c. Adds vault entry: ABE_encrypt(sk_ed25519, "user_id:alice")
   d. Logs: "alice registered key 'ed25519_mobile' (Ed25519)"
```

### 9.2 Key Rotation Flow

```plaintext
Phase 1: Both keys active (transition)
  policy: "role:admin AND (sig_scheme:ecdsa_secp256k1 OR sig_scheme:ed25519)"

Phase 2: Revoke old key
  Operation = {
      type: "__revoke_key__",
      payload: { key_id: "ecdsa_main", reason: "Migrating to Ed25519" },
      // Signed with NEW key
      sig_scheme: ED25519,
      key_id: "ed25519_mobile",
      signature: ed25519_sign(new_sk, serialize(op))
  }

Phase 3: Update policy to only accept new scheme
  Operation = {
      type: "__change_policy__",
      payload: {
          operation: "transfer",
          new_expression: "role:admin AND sig_scheme:ed25519"
      },
      policy: "role:admin AND weight >= 3",
      signature: ed25519_sign(...)
  }
```

### 9.3 Key Compromise Recovery

```plaintext
Algorithm: REVOKE_COMPROMISED_KEY

Input:
  state     — Attribute Machine state
  user_id   — Affected user
  key_id    — Compromised key
  requester — Admin or the user themselves

1. key = state.users[user_id].keys[key_id]
2. if key == null:
       return KEY_NOT_FOUND

3. // Disable the compromised key
4. key.is_active = false

5. // Increment key version (invalidates ABE keys that could decrypt this vault entry)
6. state.users[user_id].key_version += 1

7. // Log
8. LOG(state, {
         type: "__key_revoked__",
         user_id: user_id,
         key_id: key_id,
         scheme: key.scheme,
         reason: "Compromised",
         performed_by: requester
     })

9. // If this was the only active key, force the user to register a new one
10. active_count = count_active_keys(state.users[user_id])
11. if active_count == 0:
        state.users[user_id].status = SUSPENDED
        LOG(state, {
                type: "__user_suspended__",
                user_id: user_id,
                reason: "No active signing keys"
            })

12. return SUCCESS
```

---

## 10. Vault Integration

### 10.1 Scheme-Aware Vault Population

```plaintext
Algorithm: VAULT_POPULATE_FOR_USER

Input:
  state     — Machine state
  mpk       — ABE master public key
  user_id   — User to populate vault for
  keys      — User's registered keys

1. for each (key_id, key) in user.keys:
2.     if not key.is_active:
3.         continue
4.
5.     // Get the secret key (from user during registration or key generation)
6.     sk = GET_USER_SECRET_KEY(user_id, key_id)
7.     if sk == null:
8.         continue  // Secret key not available
9.
10.    // Encrypt the secret key under the user's identity
11.    ct = ABE_encrypt(mpk, sk, "user_id:{user_id} AND key_id:{key_id}")
12.
13.    // Store in vault
14.    state.vault[user_id][key_id] = {
            scheme: key.scheme,
            encrypted_sk: ct
        }
```

### 10.2 Vault Decryption During Operation

```plaintext
Algorithm: VAULT_DECRYPT_SIGNING_KEY

Input:
  state     — Machine state
  user_id   — User requesting decryption
  key_id    — Which key to decrypt
  sk_abe    — User's ABE secret key

Output:
  sk        — Decrypted signing key
  scheme    — Signature scheme of the key

1. entry = state.vault[user_id][key_id]
2. if entry == null:
       return KEY_NOT_FOUND

3. // Decrypt with ABE
4. sk = ABE_decrypt(sk_abe, entry.encrypted_sk)
5. if sk == null:
       return DECRYPTION_FAILED

6. return {sk: sk, scheme: entry.scheme}
```

---

## 11. Serialization

### 11.1 Updated Operation Serialization

The canonical encoding for signing (Section 7.5 of base spec) is updated to include the new fields:

```plaintext
Algorithm: SERIALIZE_FOR_SIGNING (v1.3)

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
     op.node_id,

     // NEW fields
     op.sig_scheme,           // uint8
     op.key_id,               // string

     // Co-signers (sorted by signer_id for determinism)
     sort(op.co_signers, by signer_id),
     for each co_sig in op.co_signers:
         co_sig.signer_id,
         co_sig.key_id,
         co_sig.sig_scheme
   ]

2. return canonical_encode(fields)
```

### 11.2 User Key Serialization

```plaintext
UserKeySerialized = {
    key_id_length: uint16,
    key_id: byte[key_id_length],
    scheme: uint8,
    public_key_length: uint32,
    public_key: byte[public_key_length],
    label_length: uint16,
    label: byte[label_length],
    registered_at: uint64,
    last_used_at: uint64,
    is_active: uint8
}
```

---

## 12. Security Considerations

### 12.1 Scheme Downgrade Attack

```plaintext
Attack: Attacker intercepts an Ed25519-signed operation and
        re-presents it as ECDSA-signed to a node that accepts both.

Mitigation: The sig_scheme field is INCLUDED in the serialized
            data that gets signed. An Ed25519 signature cannot
            verify as an ECDSA signature because the signed data
            is different (sig_scheme field differs).

Proof:
  Ed25519 signs:   {..., sig_scheme: ED25519, ...}
  ECDSA would need: {..., sig_scheme: ECDSA, ...}
  These are different messages → different signatures
  → Downgrade impossible
```

### 12.2 Key ID Spoofing

```plaintext
Attack: Attacker claims to have used key_id "ecdsa_hsm_1"
        but actually used a different key.

Mitigation: The key_id is INCLUDED in the signed data.
            Verification checks that the key_id matches
            a registered key AND that the signature verifies
            against that key's public key.
```

### 12.3 Weak Scheme Injection

```plaintext
Attack: Attacker adds a weak scheme (e.g., RSA 512-bit)
        to the registry and uses it to forge signatures.

Mitigation:
  1. Scheme registration requires machine policy approval
  2. Machine config sets min_security_level
  3. Post-quantum requirement can be enforced
  4. Custom schemes (0xF0-0xFE) can be restricted
```

### 12.4 Multi-Sig Threshold Bypass

```plaintext
Attack: Attacker submits an operation with only their own
        signature but claims it has 3 co-signers.

Mitigation: ALL co-signer signatures are verified independently.
            The threshold is checked AFTER verification.
            Missing or invalid co-signer signatures cause rejection.
```

### 12.5 Key Proliferation

```plaintext
Attack: User registers thousands of keys to bloat the state.

Mitigation:
  - Maximum keys per user (configurable, default: 8)
  - Key registration requires policy approval
  - Storage costs are local to the node
```

---

## 13. Backward Compatibility

### 13.1 Operation Format Migration

Operations signed with the old format (no sig_scheme, no key_id) are treated as:

```plaintext
sig_scheme = ECDSA_SECP256K1  (assumed)
key_id     = "default"        (assumed)
```

A compatibility flag in the machine config controls this:

```plaintext
MachineConfig.sig_config.accept_legacy_operations: bool  // Default: true

// When true, operations without sig_scheme field are treated as ECDSA
// When false, such operations are rejected
```

### 13.2 User Key Migration

Existing users (with only an ECDSA key) are automatically assigned:

```plaintext
user.keys["default"] = {
    key_id: "default",
    scheme: ECDSA_SECP256K1,
    public_key: user.pk_ecdsa,    // Migrated from old field
    label: "Legacy ECDSA key",
    registered_at: genesis_time,
    is_active: true
}
user.default_key_id = "default"
```

### 13.3 Vault Migration

Existing vault entries (without key_id or scheme) are treated as:

```plaintext
vault[user_id]["default"] = {
    scheme: ECDSA_SECP256K1,
    encrypted_sk: existing_vault_entry  // No change needed
}
```

---

## 14. Test Vectors

### 14.1 Multi-Scheme Registration

```plaintext
Setup:
  - Alice has ECDSA key "ecdsa_main"
  - Alice registers Ed25519 key "ed25519_mobile"

Operation:
  type: "__register_key__"
  payload: { key_id: "ed25519_mobile", scheme: ED25519, ... }
  sig_scheme: ECDSA_SECP256K1
  key_id: "ecdsa_main"
  signature: <ecdsa_sig>

Expected:
  - ECDSA signature verifies ✅
  - Ed25519 public key stored ✅
  - Vault entry created for Ed25519 secret key ✅
  - Logged: "alice registered key 'ed25519_mobile' (Ed25519)"
```

### 14.2 Cross-Scheme Signing

```plaintext
Setup:
  - Alice has both ECDSA and Ed25519 keys
  - Policy: "role:admin AND sig_scheme:ed25519"

Operation:
  type: "transfer"
  sig_scheme: ED25519
  key_id: "ed25519_mobile"
  signature: <ed25519_sig>

Verification:
  - sig_scheme matches policy? ED25519 == ED25519 ✅
  - Ed25519 signature verifies against stored key? ✅
  - ABE policy "role:admin" satisfied? ✅
  → AUTHORIZED
```

### 14.3 Scheme Mismatch Rejection

```plaintext
Setup:
  - Alice has both ECDSA and Ed25519 keys
  - Policy: "role:admin AND sig_scheme:ed25519"

Operation:
  type: "transfer"
  sig_scheme: ECDSA_SECP256K1  // Wrong scheme!
  key_id: "ecdsa_main"
  signature: <ecdsa_sig>

Verification:
  - sig_scheme matches policy? ECDSA != Ed25519 ❌
  → REJECTED: SCHEME_MISMATCH
```

### 14.4 Multi-Signature Operation

```plaintext
Setup:
  - Policy: "2of3(role:admin)"
  - Alice, Bob, Carol all have role:admin

Operation:
  type: "transfer"
  payload: { amount: 100 }
  sig_scheme: ECDSA_SECP256K1
  signer_id: "alice"
  signature: <alice_ecdsa_sig>
  co_signers: [
    { signer_id: "bob", key_id: "default",
      sig_scheme: ECDSA_SECP256K1, signature: <bob_ecdsa_sig> },
    { signer_id: "carol", key_id: "ed25519_main",
      sig_scheme: ED25519, signature: <carol_ed25519_sig> }
  ]

Verification:
  - Alice's ECDSA signature verifies ✅
  - Bob's ECDSA signature verifies ✅
  - Carol's Ed25519 signature verifies ✅
  - 3 of 3 >= 2 (threshold)? ✅
  → AUTHORIZED
```

### 14.5 Key Revocation

```plaintext
Setup:
  - Alice has keys: "ecdsa_main" (active), "ed25519_mobile" (active)

Operation:
  type: "__revoke_key__"
  payload: { key_id: "ed25519_mobile", reason: "Lost phone" }
  sig_scheme: ECDSA_SECP256K1
  key_id: "ecdsa_main"
  signature: <ecdsa_sig>

Expected:
  - "ed25519_mobile" marked inactive ✅
  - Vault entry for "ed25519_mobile" preserved but marked inactive ✅
  - Alice can still sign with "ecdsa_main" ✅
  - Any future operation claiming "ed25519_mobile" is rejected ✅
```

---

## 15. Implementation Guidelines

### 15.1 Minimum Required Schemes

A conforming implementation MUST support at least:

```plaintext
ECDSA_SECP256K1   // Required for backward compatibility
```

A conforming implementation SHOULD support:

```plaintext
ED25519           // Recommended for new deployments
```

A conforming implementation MAY support:

```plaintext
DILITHIUM_3       // Recommended for post-quantum readiness
SCHNORR_SECP256K1 // Recommended for multi-sig efficiency
BLS_BLS12_381     // Recommended for signature aggregation
```

### 15.2 Scheme Registration Order

Built-in schemes SHOULD be registered in this order:

```plaintext
1. ECDSA_SECP256K1   (always available)
2. ECDSA_P256        (if OpenSSL provides it)
3. ED25519           (if libsodium or similar is available)
4. SCHNORR_SECP256K1 (if libsecp256k1 is available)
5. BLS_BLS12_381     (if bls-library is available)
6. DILITHIUM_3       (if liboqs or similar is available)
7. FALCON_512        (if liboqs or similar is available)
```

### 15.3 External Library Mapping

```plaintext
┌─────────────────────┬──────────────────────────────┐
│ Scheme              │ Recommended Library           │
├─────────────────────┼──────────────────────────────┤
│ ECDSA secp256k1     │ OpenSSL EVP + libsecp256k1   │
│ ECDSA P-256         │ OpenSSL EVP                  │
│ Ed25519             │ libsodium / OpenSSL 3.2+     │
│ Schnorr secp256k1   │ libsecp256k1 (schnorr module)│
│ BLS BLS12-381       │ bls-signatures (Chia)        │
│ RSA 2048/4096       │ OpenSSL EVP                  │
│ Dilithium           │ liboqs (Open Quantum Safe)   │
│ Falcon              │ liboqs (Open Quantum Safe)   │
│ SPHINCS+            │ liboqs (Open Quantum Safe)   │
└─────────────────────┴──────────────────────────────┘
```

---

## 16. Summary of Changes from v1.2

Section	Change
§2	Signature scheme registry with 13+ defined schemes
§3	VTable interface for pluggable signature operations
§4.1	Extended User record with multi-key support
§4.2	Updated Operation with sig_scheme, key_id, co_signers
§4.3	Updated VaultEntry with scheme and key_id
§5	New built-in operations: __register_key__, __revoke_key__, __set_default_key__
§6	Updated verification algorithms for multi-scheme, multi-sig
§7	Policy integration with sig_scheme and key_id constraints
§8	Machine config for allowed schemes and security levels
§9	Key lifecycle: registration, rotation, compromise recovery
§10	Vault integration for scheme-aware key storage
§11	Updated serialization for signing
§12	Security considerations for scheme agility
§13	Backward compatibility with legacy ECDSA-only format
§14	Test vectors for multi-scheme operations
§15	Implementation guidelines and library mappings

---

## Appendix: Migration Guide

### From v1.2 (ECDSA-only) to v1.3 (Multi-Scheme)

```plaintext
Step 1: Update library to v1.3
  - All existing ECDSA keys are auto-migrated to key_id "default"
  - All existing operations are accepted with assumed ECDSA scheme
  - No breaking changes to existing functionality

Step 2: Register additional keys (optional)
  - Users can register Ed25519, Dilithium, etc.
  - Existing ECDSA keys continue to work

Step 3: Update policies (optional)
  - Add sig_scheme constraints to policies
  - Transition period: accept multiple schemes

Step 4: Revoke old keys (optional)
  - Once all users have migrated, revoke ECDSA keys
  - Update policies to require new scheme only

Step 5: Disable legacy operations (optional)
  - Set accept_legacy_operations = false
  - All operations must now include sig_scheme and key_id
```