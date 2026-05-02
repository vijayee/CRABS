# CRABS Protocol Specification v1.4 — Amendment 4

## *Idempotent Operations and One-Shot Semantics*

---

**Amendment Status:** Draft  
**Spec Version:** 1.4.0  
**Date:** April 30, 2026  
**Supersedes:** Base spec §7.4 (Operation Execution Algorithm)

---

## Preamble

The base CRABS protocol provides **byte-level idempotency** — the same operation bytes cannot be applied twice (via UUID deduplication). However, many applications require **semantic idempotency**: preventing the same *logical action* from being performed twice, even if the operation bytes differ.

Common patterns include:

- **One vote per user**: "Alice can vote on proposal #42 only once"
- **One-shot execution**: "Proposal #42 can be executed only once, by anyone"
- **Single-use tokens**: "This authorization token can be used only once"
- **First-past-the-post**: "The first user to claim this resource gets it"

These patterns share a common structure: a **stateful guard** that is checked before execution and **atomically updated** after execution. This amendment introduces **`DedupSpec`** — a declarative mechanism for specifying such guards — and **`ONE_SHOT_SET`** and **`ONE_SHOT_FLAG`** — new data types optimized for idempotency tracking.

---

## 1. Motivation

### 1.1 Current Limitations

```plaintext
Without semantic idempotency:

1. Alice votes on proposal #42:
   → votes = {bob, carol}
   → votes.add("alice") → votes = {bob, carol, alice}

2. Network hiccup. Alice retries:
   → votes = {bob, carol, alice}
   → votes.add("alice") → votes = {bob, carol, alice}  // Idempotent
   
   This works for OR-Sets (add is idempotent). But what about:

3. Alice executes proposal #42:
   → executed = false
   → executed = true
   → Treasury sends 100 ETH

4. Network hiccup. Alice retries:
   → executed = true
   → executed = true  // ❌ Treasury sends ANOTHER 100 ETH!
```

The problem is that **some state changes are not idempotent**. Transferring funds, minting tokens, and other resource-modifying operations must be guarded to ensure they happen exactly once.

### 1.2 Current Workaround

Users can manually construct policies with stateful guards:

```plaintext
policy: "role:admin AND proposal_42.executed == false"
```

This works but has drawbacks:

- **Policy bloat**: Guards make policies longer and harder to read
- **No atomicity guarantee**: The guard check and state update are separate steps
- **No standard pattern**: Every application re-implements the same logic
- **No CRDT optimization**: The protocol doesn't know these are idempotency checks

---

## 2. New Data Types

### 2.1 `ONE_SHOT_SET`

A set that tracks which users (or entities) have performed an action. Each element can be added only once.

```plaintext
Type ID: 0x08
Name: ONE_SHOT_SET
CRDT Strategy: Single-writer-per-element set
Lock Required: No
Description: Set where each element can be added at most once.
             Add is idempotent — adding an existing element is a no-op.
             Remove is not supported.
```

**CRDT Merge Rule:**

```plaintext
Algorithm: MERGE_ONE_SHOT_SET

Input:
  a, b — ONE_SHOT_SET values

Output:
  merged — Merged set

// Merge is union — once an element exists in any replica,
// it exists in all replicas. This is safe because elements
// can never be removed.

1. merged.elements = a.elements ∪ b.elements
2. return merged
```

**Operations:**

```plaintext
add(element):   // Add element if not present. Returns true if added, false if already present.
contains(element):  // Check if element exists.
count():        // Number of elements.
to_set():       // Return as regular set for iteration.
```

### 2.2 `ONE_SHOT_FLAG`

A boolean flag that can transition from `false` to `true` exactly once.

```plaintext
Type ID: 0x09
Name: ONE_SHOT_FLAG
CRDT Strategy: LWW with true-dominates
Lock Required: No
Description: A flag that can be set to true at most once.
             Once true, it stays true forever.
             Setting an already-true flag is a no-op.
```

**CRDT Merge Rule:**

```plaintext
Algorithm: MERGE_ONE_SHOT_FLAG

Input:
  a, b — ONE_SHOT_FLAG values

Output:
  merged — Merged flag

// Once true in any replica, always true in merged result.
// This is a "set-once" register.

1. merged.value = a.value OR b.value
2. merged.set_at = min(a.set_at, b.set_at)  // When it was first set
3. merged.set_by = a.set_by if a.set_at < b.set_at else b.set_by
4. return merged
```

**Operations:**

```plaintext
set(signer_id):  // Set to true if false. Returns true if this call set it, false if already set.
is_set():        // Returns current value.
set_by():        // Returns who set it (first signer_id).
set_at():        // Returns when it was set (first timestamp).
```

---

## 3. The DedupSpec

### 3.1 Definition

```plaintext
DedupSpec = {
    // Which type of idempotency to enforce
    type: DedupType,
    
    // For PER_USER: which set tracks participants
    tracker_path: string,        // e.g., "proposal_42.voters"
    
    // For GLOBAL: which flag tracks execution
    flag_path: string,           // e.g., "proposal_42.executed"
    
    // For CUSTOM: arbitrary condition
    condition: string,           // e.g., "treasury.balance >= 100"
    update: StateMutation,       // What to change after success
    
    // Error message on rejection
    rejection_message: string    // "You have already voted on this proposal"
}

DedupType = enum {
    NONE        = 0x00,  // No dedup (default)
    PER_USER    = 0x01,  // One per user, tracked by ONE_SHOT_SET
    GLOBAL      = 0x02,  // One ever, tracked by ONE_SHOT_FLAG
    CUSTOM      = 0xFF   // Application-defined condition + update
}

StateMutation = {
    type: MutationType,
    
    // For SET_ADD:
    set_path: string,
    element_value: string,     // Often "{signer_id}"
    
    // For FLAG_SET:
    flag_path: string,
    
    // For COUNTER_INCREMENT:
    counter_path: string,
    delta: int64,
    
    // For ASSIGN:
    target_path: string,
    value: string
}

MutationType = enum {
    SET_ADD           = 0x01,  // Add element to ONE_SHOT_SET
    FLAG_SET          = 0x02,  // Set ONE_SHOT_FLAG to true
    COUNTER_INCREMENT = 0x03,  // Increment a counter
    ASSIGN            = 0x04,  // Assign a value
    CUSTOM            = 0xFF   // Application-defined callback
}
```

### 3.2 Operation Integration

```plaintext
OperationType = {
    type: string,                    // e.g., "vote"
    policy: string,                  // e.g., "role:member"
    
    // NEW: Idempotency specification
    dedup: DedupSpec,                // How to enforce one-shot semantics
    
    // ... other operation type metadata ...
}
```

### 3.3 Per-Operation Dedup

Individual operations can also specify dedup inline:

```plaintext
Operation = {
    type: "vote",
    payload: { proposal: "42", vote: "yes" },
    policy: "role:member",
    
    // NEW: Inline dedup spec
    dedup: {
        type: PER_USER,
        tracker_path: "proposal_42.voters",
        rejection_message: "You have already voted on proposal #42"
    },
    
    signature: {...}
}
```

---

## 4. Desugaring

The `DedupSpec` is **desugared** into standard CRABS operations at processing time. This means no new core primitives are needed — the protocol already has everything required.

### 4.1 PER_USER Desugaring

```plaintext
Input:
  dedup: {
      type: PER_USER,
      tracker_path: "proposal_42.voters",
      rejection_message: "You have already voted"
  }
  signer_id: "alice"

Desugared into:

// 1. Policy guard (checked before execution):
policy_guard = "proposal_42.voters NOT CONTAINS alice"
// Combined with existing policy:
effective_policy = "role:member AND proposal_42.voters NOT CONTAINS alice"

// 2. State mutation (applied after successful execution):
state_mutation = "proposal_42.voters.add(alice)"

// 3. Rejection message (returned to user on failure):
"Already voted: You have already voted on proposal #42"
```

### 4.2 GLOBAL Desugaring

```plaintext
Input:
  dedup: {
      type: GLOBAL,
      flag_path: "proposal_42.executed",
      rejection_message: "Proposal already executed"
  }

Desugared into:

// 1. Policy guard:
policy_guard = "proposal_42.executed == false"
effective_policy = "role:admin AND proposal_42.executed == false"

// 2. State mutation:
state_mutation = "proposal_42.executed.set(signer_id)"

// 3. Rejection message:
"Already executed: Proposal #42 has already been executed"
```

### 4.3 CUSTOM Desugaring

```plaintext
Input:
  dedup: {
      type: CUSTOM,
      condition: "treasury.balance >= 100",
      update: {
          type: COUNTER_INCREMENT,
          counter_path: "treasury.balance",
          delta: -100
      },
      rejection_message: "Insufficient funds"
  }

Desugared into:

// 1. Policy guard:
policy_guard = "treasury.balance >= 100"
effective_policy = "role:admin AND treasury.balance >= 100"

// 2. State mutation:
state_mutation = "treasury.balance -= 100"

// 3. Rejection message:
"Insufficient funds: Treasury balance is below 100"
```

---

## 5. Modified Operation Execution Algorithm

### 5.1 Execution with Dedup

```plaintext
Algorithm: EXECUTE_OPERATION (v1.4)

Input:
  state — Current CRABS state
  op    — Operation to execute
  mpk   — ABE master public key

Output:
  result — SUCCESS or error code

// Steps 1–4: Unchanged from v1.0
1. PRUNE_EXPIRED_LOCKS(state)
2. if state.processed_ops.contains(op.uuid): return SUCCESS
3. Verify protocol state transitions
4. Verify lock claims

// Step 5: NEW — Check dedup guard BEFORE policy verification
5. if op.dedup.type != NONE:
       guard_result = CHECK_DEDUP_GUARD(state, op)
       if guard_result != SUCCESS:
           return guard_result  // e.g., ALREADY_VOTED

// Steps 6–8: Unchanged
6. Verify ABE signature
7. Verify key version
8. Execute operation handler

// Step 9: NEW — Apply dedup state mutation AFTER successful execution
9. if op.dedup.type != NONE:
       APPLY_DEDUP_MUTATION(state, op)

// Steps 10–12: Unchanged
10. Transition protocol states
11. PROCESS_TRIGGERS(state)
12. Log and increment version

13. return SUCCESS
```

### 5.2 Dedup Guard Check

```plaintext
Algorithm: CHECK_DEDUP_GUARD

Input:
  state — Current CRABS state
  op    — Operation with dedup spec

Output:
  SUCCESS or error code

1. switch op.dedup.type:
2.     case PER_USER:
3.         tracker = RESOLVE_PATH(state, op.dedup.tracker_path)
4.         if tracker == null:
5.             return TRACKER_NOT_FOUND
6.         
7.         if tracker.contains(op.signer_id):
8.             return ALREADY_PERFORMED
9.             // Error message: op.dedup.rejection_message
10.        
11.        return SUCCESS
12.    
13.    case GLOBAL:
14.        flag = RESOLVE_PATH(state, op.dedup.flag_path)
15.        if flag == null:
16.            return FLAG_NOT_FOUND
17.        
18.        if flag.is_set():
19.            return ALREADY_PERFORMED
20.            // Error message: op.dedup.rejection_message
21.        
22.        return SUCCESS
23.    
24.    case CUSTOM:
25.        condition_met = EVALUATE_CONDITION(state, op.dedup.condition)
26.        if not condition_met:
27.            return CONDITION_NOT_MET
28.            // Error message: op.dedup.rejection_message
29.        
30.        return SUCCESS
31.    
32.    case NONE:
33.        return SUCCESS  // No guard to check
```

### 5.3 Dedup State Mutation

```plaintext
Algorithm: APPLY_DEDUP_MUTATION

Input:
  state — Current CRABS state
  op    — Operation with dedup spec

Output:
  SUCCESS or error code

1. switch op.dedup.type:
2.     case PER_USER:
3.         tracker = RESOLVE_PATH(state, op.dedup.tracker_path)
4.         tracker.add(op.signer_id)
5.         return SUCCESS
6.     
7.     case GLOBAL:
8.         flag = RESOLVE_PATH(state, op.dedup.flag_path)
9.         flag.set(op.signer_id)
10.        return SUCCESS
11.    
12.    case CUSTOM:
13.        switch op.dedup.update.type:
14.            case SET_ADD:
15.                set = RESOLVE_PATH(state, op.dedup.update.set_path)
16.                set.add(op.dedup.update.element_value)
17.            
18.            case FLAG_SET:
19.                flag = RESOLVE_PATH(state, op.dedup.update.flag_path)
20.                flag.set(op.signer_id)
21.            
22.            case COUNTER_INCREMENT:
23.                counter = RESOLVE_PATH(state, op.dedup.update.counter_path)
24.                counter.value += op.dedup.update.delta
25.            
26.            case ASSIGN:
27.                target = RESOLVE_PATH(state, op.dedup.update.target_path)
28.                target.value = op.dedup.update.value
29.            
30.            case CUSTOM:
31.                op.dedup.update.callback(state, op)
32.        
33.        return SUCCESS
34.    
35.    case NONE:
36.        return SUCCESS  // No mutation needed
```

---

## 6. New Error Codes

```plaintext
ErrorCode = enum {
    // ... existing error codes ...
    
    // NEW: Dedup-related errors
    ALREADY_PERFORMED   = 0x6001,  // Operation already performed by this user
    ALREADY_EXECUTED    = 0x6002,  // Operation already executed globally
    CONDITION_NOT_MET   = 0x6003,  // Custom dedup condition not satisfied
    TRACKER_NOT_FOUND   = 0x6004,  // ONE_SHOT_SET tracker not found
    FLAG_NOT_FOUND      = 0x6005,  // ONE_SHOT_FLAG not found
}
```

---

## 7. New Built-in Operations

### 7.1 `__define_operation_type__`

Define an operation type with a dedup spec at machine setup or runtime.

```plaintext
Operation = {
    type: "__define_operation_type__",
    payload: {
        operation_type: "vote",
        policy: "role:member",
        dedup: {
            type: PER_USER,
            tracker_path: "{resource}.voters",
            rejection_message: "You have already voted on this proposal"
        }
    },
    policy: "role:admin",
    signature: {...}
}

// After this, any operation with type "vote" automatically
// gets the dedup spec applied.
```

### 7.2 `__check_dedup__`

Check whether a dedup guard would pass without executing the operation.

```plaintext
Operation = {
    type: "__check_dedup__",
    payload: {
        operation_type: "vote",
        resource: "proposal_42",
        signer_id: "alice"
    },
    policy: "role:member",
    signature: {...}
}

// Returns: SUCCESS (can vote) or ALREADY_PERFORMED (already voted)
```

---

## 8. Common Patterns

### 8.1 One Vote Per User

```plaintext
// State setup
proposal_42 = {
    title: "Buy new servers",
    voters: ONE_SHOT_SET,     // Tracks who voted
    votes_yes: COUNTER,       // Running tally
    votes_no: COUNTER,
    executed: ONE_SHOT_FLAG
}

// Operation type definition
__define_operation_type__ {
    type: "vote",
    policy: "role:member",
    dedup: {
        type: PER_USER,
        tracker_path: "proposal_42.voters",
        rejection_message: "You have already voted on proposal #42"
    }
}

// Alice votes
Operation = {
    type: "vote",
    resource: "proposal_42",
    payload: { vote: "yes" },
    signature: {...}
}

// Execution:
//   1. Check: proposal_42.voters NOT CONTAINS alice? ✅
//   2. Execute: if vote == "yes": proposal_42.votes_yes++
//               else: proposal_42.votes_no++
//   3. Mutate: proposal_42.voters.add("alice")
//   4. Next time: proposal_42.voters NOT CONTAINS alice? ❌ → ALREADY_PERFORMED
```

### 8.2 One-Shot Execution

```plaintext
// Operation type definition
__define_operation_type__ {
    type: "execute_proposal",
    policy: "role:admin",
    dedup: {
        type: GLOBAL,
        flag_path: "proposal_42.executed",
        rejection_message: "Proposal #42 has already been executed"
    }
}

// Carol executes
Operation = {
    type: "execute_proposal",
    resource: "proposal_42",
    payload: {},
    signature: {...}
}

// Execution:
//   1. Check: proposal_42.executed == false? ✅
//   2. Execute: treasury.transfer(100 ETH)
//   3. Mutate: proposal_42.executed.set("carol")
//   4. Next time anyone tries: proposal_42.executed == false? ❌ → ALREADY_EXECUTED
```

### 8.3 First-Past-The-Post (Claim)

```plaintext
// Resource claim — first user to claim gets it
__define_operation_type__ {
    type: "claim_username",
    policy: "role:member",
    dedup: {
        type: PER_USER,
        tracker_path: "usernames.{payload.username}.claimed_by",
        rejection_message: "Username '{payload.username}' is already taken"
    }
}

// Alice tries to claim "alice123"
Operation = {
    type: "claim_username",
    payload: { username: "alice123" },
    signature: {...}
}

// Execution:
//   1. Check: usernames.alice123.claimed_by NOT CONTAINS anyone? ✅
//      (Empty set — no one has claimed it)
//   2. Execute: usernames.alice123.owner = "alice"
//   3. Mutate: usernames.alice123.claimed_by.add("alice")
//   4. Bob tries: usernames.alice123.claimed_by NOT CONTAINS bob? ✅
//      But the set already has "alice" in it!
//      Wait — this checks for BOB, not for anyone.
//      PER_USER only prevents the SAME user from claiming twice.
//      We need GLOBAL for "anyone can claim once".
```

### 8.4 First-Past-The-Post (Global) — Corrected

```plaintext
// For "first to claim wins", use GLOBAL with a custom tracker:
__define_operation_type__ {
    type: "claim_username",
    policy: "role:member",
    dedup: {
        type: GLOBAL,
        flag_path: "usernames.{payload.username}.claimed",
        rejection_message: "Username '{payload.username}' is already taken"
    }
}

// Alice claims "alice123"
//   1. Check: usernames.alice123.claimed == false? ✅
//   2. Execute: usernames.alice123.owner = "alice"
//   3. Mutate: usernames.alice123.claimed.set("alice")
//   4. Bob tries: usernames.alice123.claimed == false? ❌ → ALREADY_EXECUTED
```

### 8.5 Single-Use Authorization Token

```plaintext
// A one-time authorization code
__define_operation_type__ {
    type: "redeem_code",
    policy: "role:member",
    dedup: {
        type: PER_USER,
        tracker_path: "codes.{payload.code}.redeemed_by",
        rejection_message: "Code '{payload.code}' has already been redeemed"
    }
}

// Alice redeems code "SUMMER2024"
Operation = {
    type: "redeem_code",
    payload: { code: "SUMMER2024" },
    signature: {...}
}

// Execution:
//   1. Check: codes.SUMMER2024.redeemed_by NOT CONTAINS alice? ✅
//   2. Execute: alice.balance += 100
//   3. Mutate: codes.SUMMER2024.redeemed_by.add("alice")
//   4. Alice tries again: codes.SUMMER2024.redeemed_by NOT CONTAINS alice? ❌
//   5. Bob tries: codes.SUMMER2024.redeemed_by NOT CONTAINS bob? ✅
//      Wait — Bob can ALSO redeem the same code!
//      This is PER_USER, not GLOBAL.
```

### 8.6 Single-Use Token (Global) — Corrected

```plaintext
// For "code can be used once by anyone":
__define_operation_type__ {
    type: "redeem_code",
    policy: "role:member",
    dedup: {
        type: GLOBAL,
        flag_path: "codes.{payload.code}.redeemed",
        rejection_message: "Code '{payload.code}' has already been redeemed"
    }
}

// Alice redeems → code.redeemed = true
// Bob tries → code.redeemed == false? ❌ → ALREADY_EXECUTED
```

---

## 9. CRDT Safety Analysis

### 9.1 ONE_SHOT_SET Safety

```plaintext
Property: Once an element is added, it can never be removed.
This is safe under CRDT merge because:
  - Merge is union: a ∪ b
  - An element present in any replica will be present in the merged result
  - There is no remove operation

Concurrent adds of the same element:
  - Node A: add("alice") at t=100
  - Node B: add("alice") at t=200
  - Merge: {"alice"} ∪ {"alice"} = {"alice"} ✅
  - No conflict, no duplication
```

### 9.2 ONE_SHOT_FLAG Safety

```plaintext
Property: Once set to true, it can never become false.
This is safe under CRDT merge because:
  - Merge is OR: a.value OR b.value
  - true in any replica → true in merged result
  - There is no "unset" operation

Concurrent sets:
  - Node A: set("alice") at t=100
  - Node B: set("bob") at t=200
  - Merge: true OR true = true ✅
  - set_by = "alice" (first timestamp wins)
  - No conflict
```

### 9.3 Dedup + CRDT Interaction

```plaintext
Scenario: Two nodes receive Alice's vote concurrently.

Node A:
  1. Check: voters NOT CONTAINS alice? ✅ (empty set)
  2. Execute: count++
  3. Mutate: voters.add("alice")
  4. State: voters = {"alice"}, count = 1

Node B:
  1. Check: voters NOT CONTAINS alice? ✅ (empty set — hasn't seen A's add yet)
  2. Execute: count++
  3. Mutate: voters.add("alice")
  4. State: voters = {"alice"}, count = 1

Merge:
  - voters = {"alice"} ∪ {"alice"} = {"alice"} ✅ (correct)
  - count = max(1, 1) = 1 ✅ (G-Counter merge)
  
Result: Alice's vote counted ONCE. ✅

But what if the operation is NOT idempotent?
  - Node A: treasury.transfer(100)
  - Node B: treasury.transfer(100)
  - Merge: treasury = 100 - 100 - 100 = -100 ❌ (double spend!)

This is why the GUARD CHECK and STATE MUTATION must be ATOMIC
within a single node. The CRDT merge then ensures convergence.

The key insight: Dedup guards prevent the SAME LOGICAL OPERATION
from being applied twice, even if two nodes receive it independently.
The first node to process it "wins" — the second node's guard check
will fail because the tracker has already been updated (via CRDT merge).
```

---

## 10. Serialization

### 10.1 DedupSpec Serialization

```plaintext
DedupSpecSerialized = {
    dedup_type: uint8,              // 0=NONE, 1=PER_USER, 2=GLOBAL, 0xFF=CUSTOM
    
    // For PER_USER:
    tracker_path_length: uint16,
    tracker_path: byte[tracker_path_length],
    
    // For GLOBAL:
    flag_path_length: uint16,
    flag_path: byte[flag_path_length],
    
    // For CUSTOM:
    condition_length: uint16,
    condition: byte[condition_length],
    update_type: uint8,
    update_set_path_length: uint16,
    update_set_path: byte[update_set_path_length],
    update_element_value_length: uint16,
    update_element_value: byte[update_element_value_length],
    update_flag_path_length: uint16,
    update_flag_path: byte[update_flag_path_length],
    update_counter_path_length: uint16,
    update_counter_path: byte[update_counter_path_length],
    update_delta: int64,
    update_target_path_length: uint16,
    update_target_path: byte[update_target_path_length],
    update_value_length: uint16,
    update_value: byte[update_value_length],
    
    // Rejection message
    rejection_message_length: uint16,
    rejection_message: byte[rejection_message_length]
}
```

### 10.2 Updated Operation Serialization

The canonical encoding for signing (Section 7.5 of base spec) is updated to include the dedup field:

```plaintext
Algorithm: SERIALIZE_FOR_SIGNING (v1.4)

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
     op.sig_scheme,
     op.key_id,
     
     // NEW: Dedup spec
     op.dedup.type,
     op.dedup.tracker_path,    // if PER_USER
     op.dedup.flag_path,       // if GLOBAL
     op.dedup.condition,       // if CUSTOM
     op.dedup.update,          // if CUSTOM
     op.dedup.rejection_message,
     
     // Co-signers
     sort(op.co_signers, by signer_id),
     for each co_sig in op.co_signers:
         co_sig.signer_id,
         co_sig.key_id,
         co_sig.sig_scheme
   ]

2. return canonical_encode(fields)
```

---

## 11. Security Considerations

### 11.1 Guard Bypass

```plaintext
Attack: Attacker crafts an operation that skips the dedup guard.

Mitigation: The dedup spec is INCLUDED in the signed data.
            The guard check happens BEFORE execution.
            The state mutation happens AFTER execution.
            All three are in the same atomic operation.
            An attacker cannot remove the dedup spec from a signed operation.
```

### 11.2 Concurrent Guard Check Race

```plaintext
Attack: Two operations arrive at different nodes simultaneously,
        both passing the guard check before either sees the other's mutation.

Scenario:
  - Node A: check voters NOT CONTAINS alice? ✅ (empty)
  - Node B: check voters NOT CONTAINS alice? ✅ (empty)
  - Node A: execute vote, add alice to voters
  - Node B: execute vote, add alice to voters
  - Merge: voters = {"alice"}, count = 2

Result: Alice's vote counted TWICE!

Mitigation: This is a FUNDAMENTAL LIMITATION of eventual consistency.
            CRABS provides EVENTUAL consistency, not strong consistency.
            
            For strict "vote once" guarantees, you need:
              a) A single leader that sequences operations, OR
              b) A consensus protocol (Raft, PBFT), OR
              c) Accept that concurrent votes may both succeed
                 and use application-level reconciliation

            In practice, for most applications:
              - The window for concurrent votes is very small
              - CRDT merge means the tracker is correct (alice is in voters)
              - The count may be off by 1 in rare cases
              - Application can detect and correct: count = voters.count()
```

### 11.3 Tracker/Flag Spoofing

```plaintext
Attack: Attacker creates a ONE_SHOT_SET or ONE_SHOT_FLAG with
        a pre-set value to block legitimate operations.

Mitigation:
  - Trackers and flags can only be modified by the dedup mutation
  - Direct modification requires the appropriate policy
  - The dedup mutation is atomic with the operation
  - Trackers are initialized as empty/false at resource creation
```

### 11.4 Resource Exhaustion

```plaintext
Attack: Attacker creates many proposals, each with a ONE_SHOT_SET
        tracker, to bloat the state.

Mitigation:
  - Maximum number of trackers per machine (configurable)
  - ONE_SHOT_SET elements are small (user IDs)
  - Old proposals can be archived (state pruning)
```

---

## 12. Backward Compatibility

### 12.1 Operations Without Dedup

Operations without a `dedup` field are treated as `DedupType.NONE`:

```plaintext
// v1.3 operation (no dedup)
Operation = {
    type: "vote",
    payload: {...},
    policy: "role:member",
    signature: {...}
}

// Treated as:
dedup = { type: NONE }
// No guard check, no state mutation
```

### 12.2 Data Type Migration

Existing OR-Sets used for voter tracking can be migrated to ONE_SHOT_SET:

```plaintext
// Before: OR_SET
proposal_42.voters: OR_SET = {alice, bob}

// After: ONE_SHOT_SET (same elements, same state)
proposal_42.voters: ONE_SHOT_SET = {alice, bob}

// Migration is a no-op — the data is the same
// The only difference is that ONE_SHOT_SET doesn't support remove
```

Existing boolean flags used for execution tracking can be migrated to ONE_SHOT_FLAG:

```plaintext
// Before: LWW_REGISTER
proposal_42.executed: LWW_REGISTER = {value: true, timestamp: ...}

// After: ONE_SHOT_FLAG
proposal_42.executed: ONE_SHOT_FLAG = {value: true, set_by: "carol", set_at: ...}

// Migration: copy value, set set_by from log if available
```

---

## 13. Test Vectors

### 13.1 PER_USER — First Vote Succeeds

```plaintext
Setup:
  - proposal_42.voters = ONE_SHOT_SET({})
  - Operation type "vote" with PER_USER dedup

Operation 1:
  type: "vote"
  signer_id: "alice"
  dedup: { type: PER_USER, tracker_path: "proposal_42.voters" }

Expected:
  - Guard check: voters NOT CONTAINS alice? ✅ (empty)
  - Execute: vote counted
  - Mutation: voters.add("alice")
  - Result: SUCCESS
  - State: voters = {"alice"}
```

### 13.2 PER_USER — Second Vote Rejected

```plaintext
Setup:
  - proposal_42.voters = ONE_SHOT_SET({"alice"})

Operation 2:
  type: "vote"
  signer_id: "alice"
  dedup: { type: PER_USER, tracker_path: "proposal_42.voters" }

Expected:
  - Guard check: voters NOT CONTAINS alice? ❌ (already in set)
  - Result: ALREADY_PERFORMED
  - State: voters = {"alice"} (unchanged)
```

### 13.3 PER_USER — Different User Can Vote

```plaintext
Setup:
  - proposal_42.voters = ONE_SHOT_SET({"alice"})

Operation 3:
  type: "vote"
  signer_id: "bob"
  dedup: { type: PER_USER, tracker_path: "proposal_42.voters" }

Expected:
  - Guard check: voters NOT CONTAINS bob? ✅ (bob not in set)
  - Execute: vote counted
  - Mutation: voters.add("bob")
  - Result: SUCCESS
  - State: voters = {"alice", "bob"}
```

### 13.4 GLOBAL — First Execution Succeeds

```plaintext
Setup:
  - proposal_42.executed = ONE_SHOT_FLAG({value: false})

Operation 1:
  type: "execute_proposal"
  signer_id: "carol"
  dedup: { type: GLOBAL, flag_path: "proposal_42.executed" }

Expected:
  - Guard check: executed == false? ✅
  - Execute: proposal executed
  - Mutation: executed.set("carol")
  - Result: SUCCESS
  - State: executed = {value: true, set_by: "carol"}
```

### 13.5 GLOBAL — Second Execution Rejected

```plaintext
Setup:
  - proposal_42.executed = ONE_SHOT_FLAG({value: true, set_by: "carol"})

Operation 2:
  type: "execute_proposal"
  signer_id: "dave"
  dedup: { type: GLOBAL, flag_path: "proposal_42.executed" }

Expected:
  - Guard check: executed == false? ❌ (already true)
  - Result: ALREADY_EXECUTED
  - State: executed = {value: true, set_by: "carol"} (unchanged)
```

### 13.6 CRDT Merge — Concurrent Votes

```plaintext
Setup:
  - proposal_42.voters = ONE_SHOT_SET({})
  - Node A and Node B both receive Alice's vote concurrently

Node A:
  - Guard check: voters NOT CONTAINS alice? ✅
  - Execute: count++
  - Mutation: voters.add("alice")
  - State: voters = {"alice"}, count = 1

Node B:
  - Guard check: voters NOT CONTAINS alice? ✅
  - Execute: count++
  - Mutation: voters.add("alice")
  - State: voters = {"alice"}, count = 1

Merge:
  - voters = {"alice"} ∪ {"alice"} = {"alice"} ✅
  - count = max(1, 1) = 1 ✅ (G-Counter)

Result: Alice's vote counted ONCE. ✅
```

### 13.7 CRDT Merge — Concurrent Different Users

```plaintext
Setup:
  - proposal_42.voters = ONE_SHOT_SET({})

Node A receives Alice's vote:
  - voters.add("alice")
  - State: voters = {"alice"}

Node B receives Bob's vote:
  - voters.add("bob")
  - State: voters = {"bob"}

Merge:
  - voters = {"alice"} ∪ {"bob"} = {"alice", "bob"} ✅

Result: Both votes counted. ✅
```

---

## 14. Implementation Guidelines

### 14.1 ONE_SHOT_SET Implementation

```c
typedef struct {
    // Hash set of element strings
    struct {
        char element[CRABS_MAX_USER_ID];
    } *elements;
    size_t count;
    size_t capacity;
} crabs_one_shot_set_t;

int crabs_one_shot_set_add(crabs_one_shot_set_t *set, const char *element) {
    // Check if already present
    if (crabs_one_shot_set_contains(set, element)) {
        return CRABS_ALREADY_PRESENT;  // Not an error — idempotent
    }
    
    // Add
    // ... grow if needed, insert ...
    return CRABS_SUCCESS;
}

bool crabs_one_shot_set_contains(crabs_one_shot_set_t *set, const char *element) {
    // Hash lookup
    // ...
}
```

### 14.2 ONE_SHOT_FLAG Implementation

```c
typedef struct {
    bool value;
    char set_by[CRABS_MAX_USER_ID];
    uint64_t set_at;
} crabs_one_shot_flag_t;

int crabs_one_shot_flag_set(crabs_one_shot_flag_t *flag, const char *set_by) {
    if (flag->value) {
        return CRABS_ALREADY_SET;  // Not an error — idempotent
    }
    
    flag->value = true;
    strncpy(flag->set_by, set_by, CRABS_MAX_USER_ID - 1);
    flag->set_at = now();
    return CRABS_SUCCESS;
}
```

---

## 15. Summary of Changes from v1.3

Section	Change
§2.1	New data type: `ONE_SHOT_SET` (type ID 0x08)
§2.2	New data type: `ONE_SHOT_FLAG` (type ID 0x09)
§3	`DedupSpec` definition with PER_USER, GLOBAL, CUSTOM types
§4	Desugaring rules for each DedupType
§5	Modified `EXECUTE_OPERATION` with dedup guard check and mutation
§6	New error codes: `ALREADY_PERFORMED`, `ALREADY_EXECUTED`, etc.
§7	New built-in operations: `__define_operation_type__`, `__check_dedup__`
§8	Common patterns with examples
§9	CRDT safety analysis for concurrent operations
§10	Updated serialization formats
§11	Security considerations
§12	Backward compatibility
§13	Test vectors
§14	Implementation guidelines

---

## Appendix: Quick Reference

### DedupType Selection Guide

```plaintext
┌─────────────────────────────────────────────────────────────┐
│                    WHICH DEDUP TYPE TO USE                    │
│                                                              │
│  PER_USER:                                                    │
│    "Each user can do this once"                               │
│    Examples: voting, claiming a username, rating a product    │
│    Tracker: ONE_SHOT_SET per resource                        │
│    Guard:   tracker NOT CONTAINS signer_id                   │
│    Mutation: tracker.add(signer_id)                          │
│                                                              │
│  GLOBAL:                                                      │
│    "This can be done once, by anyone"                        │
│    Examples: executing a proposal, redeeming a code,          │
│              claiming a first-come-first-served resource     │
│    Tracker: ONE_SHOT_FLAG per resource                       │
│    Guard:   flag == false                                    │
│    Mutation: flag.set(signer_id)                             │
│                                                              │
│  CUSTOM:                                                      │
│    "Do this only if condition is met"                        │
│    Examples: spending funds (check balance),                  │
│              upgrading (check level), unlocking (check key)   │
│    Guard:   Custom condition expression                      │
│    Mutation: Custom state update                             │
│                                                              │
│  NONE:                                                        │
│    "Anyone can do this any number of times"                  │
│    Examples: viewing content, adding comments, liking         │
│    Guard:   None                                              │
│    Mutation: None                                             │
└─────────────────────────────────────────────────────────────┘
```

### State Transition Diagram for Dedup

```plaintext
PER_USER (ONE_SHOT_SET):

  ┌──────────┐    add(alice)     ┌──────────┐
  │          │ ────────────────► │          │
  │  Empty   │                   │ Has Alice│
  │          │◄──────────────── │          │
  └──────────┘   add(alice)      └──────────┘
                    (no-op)

GLOBAL (ONE_SHOT_FLAG):

  ┌──────────┐    set(alice)     ┌──────────┐
  │          │ ────────────────► │          │
  │  false   │                   │   true   │
  │          │◄──────────────── │          │
  └──────────┘   set(bob)        └──────────┘
                    (no-op)
```
