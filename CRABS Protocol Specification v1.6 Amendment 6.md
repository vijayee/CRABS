# CRABS Protocol Specification v1.6 — Amendment 6

## *Hybrid Logical Clocks: Physical-Time-Anchored Ordering with Attack Mitigation*

---

**Amendment Status:** Draft  
**Spec Version:** 1.6.0  
**Date:** April 30, 2026  
**Supersedes:** Base spec §7.4 (Operation Execution — Lamport clock fields)

---

## Preamble

The base CRABS protocol uses **Lamport clocks** for operation ordering — a pure logical counter that provides causal ordering but produces opaque, non-human-readable timestamps. Many applications benefit from **physical-time-anchored ordering** where the timestamp conveys *when* an event occurred, not just its relative order.

This amendment introduces **Hybrid Logical Clocks (HLC)** as an alternative ordering system. HLCs combine physical time (Unix epoch + nanoseconds) with a logical counter, providing:

1. **Human-readable timestamps** — Each operation carries the physical time it was created
2. **Causal ordering** — The `max` rule preserves happens-before relationships
3. **Attack mitigation** — Bounded skew, quorum validation, and strict mode prevent time travel attacks
4. **Backward compatibility** — Lamport clocks remain supported; HLC is an opt-in alternative

---

## 1. Motivation

### 1.1 Limitations of Pure Lamport Clocks

```plaintext
Lamport clock operation ID:
  (lamport_time: 42, node_id: "alice", sequence_num: 7)

This tells you:
  - Operation 42 happened before operation 43 from the same node ✅
  - Nothing about WHEN it happened ❌
  - Nothing about whether it was 2 seconds or 2 days ago ❌

For debugging, auditing, and user-facing displays:
  "42" is meaningless.
  "2026-04-30 14:30:00.500" tells you exactly when.
```

### 1.2 Use Cases for Physical-Time Anchoring

```plaintext
Audit log review:
  "Show me all operations that happened between 2pm and 3pm yesterday."
  → Lamport: Need to scan all operations, no time filter
  → HLC: Direct timestamp comparison

Conflict resolution:
  "Two users edited the same document. Who went first?"
  → Lamport: Compare (42, alice) vs (43, bob) — 42 < 43, alice first
  → HLC: Compare (36000.500, alice) vs (36000.501, bob) — alice first
  → Both work, but HLC also tells you they happened 1ms apart

Lock timeout:
  "This lock was acquired at 14:30:00. It expires in 5 seconds."
  → Lamport: Can't determine expiry from logical clock alone
  → HLC: Direct comparison with wall clock
```

### 1.3 The Attack Vector

Naive HLC implementations are vulnerable to **time travel attacks**:

```plaintext
Malicious node M sends message with timestamp far in the future:
  M → A: (epoch: 99999, nanos: 0, counter: 0)

Honest node A receives it:
  A's local time: (epoch: 36000, nanos: 500)
  A does max(36000.500, 99999.000) + 1 = 100000
  A's clock JUMPS to epoch 100000!

Now:
  - All of A's future operations have timestamps >= 100000
  - Honest nodes with correct clocks (36000) appear "in the past"
  - Operations may be rejected or misordered
```

This amendment defines **four defense strategies** against this attack, configurable per deployment.

---

## 2. The Hybrid Logical Clock

### 2.1 Data Structure

```c
typedef struct {
    uint64_t physical_seconds;   // Unix epoch seconds
    uint64_t physical_nanos;     // Nanosecond component (0-999,999,999)
    uint64_t logical_counter;    // Per-node counter for same-nanosecond events
    char     node_id[64];        // Unique node identifier (tiebreaker)
} crabs_hlc_t;

// Size: 16 bytes + node_id string
// Human-readable: "2026-04-30T14:30:00.500123+0000#42@alice"
```

### 2.2 Total Ordering

Operations are ordered by `(physical_seconds, physical_nanos, logical_counter, node_id)`:

```c
int crabs_hlc_compare(const crabs_hlc_t *a, const crabs_hlc_t *b) {
    // Compare physical seconds
    if (a->physical_seconds < b->physical_seconds) return -1;
    if (a->physical_seconds > b->physical_seconds) return 1;
    
    // Compare nanoseconds
    if (a->physical_nanos < b->physical_nanos) return -1;
    if (a->physical_nanos > b->physical_nanos) return 1;
    
    // Compare logical counter (same-nanosecond events)
    if (a->logical_counter < b->logical_counter) return -1;
    if (a->logical_counter > b->logical_counter) return 1;
    
    // Tiebreaker: node_id (lexicographic)
    return strcmp(a->node_id, b->node_id);
}
```

### 2.3 Human Readable Format

```c
// Format: "YYYY-MM-DDTHH:MM:SS.nnnnnnnnn#counter@node_id"
// Example: "2026-04-30T14:30:00.500123456#42@alice"

int crabs_hlc_format(const crabs_hlc_t *hlc, char *buf, size_t buf_len) {
    // Convert epoch seconds to UTC time
    time_t sec = (time_t)hlc->physical_seconds;
    struct tm tm;
    gmtime_r(&sec, &tm);
    
    return snprintf(buf, buf_len,
        "%04d-%02d-%02dT%02d:%02d:%02d.%09lu#%lu@%s",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec,
        (unsigned long)hlc->physical_nanos,
        (unsigned long)hlc->logical_counter,
        hlc->node_id);
}
```

---

## 3. HLC State and Configuration

### 3.1 Per-Node HLC State

```c
typedef struct {
    // The last timestamp issued by this node
    crabs_hlc_t last;
    
    // Physical time source
    crabs_time_source_t time_source;  // SYSTEM_CLOCK, NTP_AUTH, TPM, CONSENSUS
    
    // Attack mitigation strategy
    crabs_hlc_strategy_t receive_strategy;
    
    // BOUNDED strategy: maximum acceptable clock skew
    uint64_t max_skew_ms;            // Default: 5000 (5 seconds)
    
    // QUORUM strategy: number of confirmations needed
    uint32_t quorum_size;            // Default: 3
    uint64_t quorum_timeout_ms;      // Default: 1000 (1 second)
    
    // TRUSTED source configuration
    uint64_t trusted_resync_ms;      // Default: 30000 (30 seconds)
    
    // Strict mode: never update local clock from received messages
    bool strict_mode;                // Default: false
    
    // Statistics (for monitoring)
    uint64_t clock_regressions_detected;
    uint64_t time_travel_attempts_rejected;
    uint64_t quorum_failures;
    
} crabs_hlc_state_t;
```

### 3.2 Configuration

```c
typedef struct {
    // Which ordering system to use
    crabs_ordering_system_t ordering_system;  // LAMPORT or HLC
    
    // HLC-specific configuration (only used if ordering_system == HLC)
    struct {
        crabs_hlc_strategy_t receive_strategy;
        uint64_t max_skew_ms;
        uint32_t quorum_size;
        uint64_t quorum_timeout_ms;
        bool     strict_mode;
        bool     trusted_time_source;
        uint64_t trusted_resync_ms;
    } hlc;
    
} crabs_ordering_config_t;

crabs_hlc_strategy_t = enum {
    HLC_STRATEGY_NAIVE    = 0x00,  // Take max blindly (not recommended)
    HLC_STRATEGY_BOUNDED  = 0x01,  // Reject timestamps beyond max_skew_ms
    HLC_STRATEGY_QUORUM   = 0x02,  // Require multiple confirmations
    HLC_STRATEGY_STRICT   = 0x03,  // Never update local clock from received
    HLC_STRATEGY_TRUSTED  = 0x04   // Use authenticated time source
};

crabs_time_source_t = enum {
    TIME_SOURCE_SYSTEM_CLOCK = 0x00,  // gettimeofday() / clock_gettime()
    TIME_SOURCE_NTP_AUTH     = 0x01,  // Authenticated NTP (NTPv4 autokey)
    TIME_SOURCE_TPM          = 0x02,  // TPM hardware clock
    TIME_SOURCE_CONSENSUS    = 0x03   // Consensus-based agreed time
};
```

---

## 4. HLC Generation Algorithm

### 4.1 Next Timestamp (Local Event)

```c
Algorithm: HLC_NEXT

Input:
  state — Per-node HLC state

Output:
  hlc   — New HLC timestamp

1. // Read physical time
2. now_sec, now_ns = GET_PHYSICAL_TIME(state.time_source)

3. // Compare with last timestamp
4. if now_sec < state.last.physical_seconds OR
5.    (now_sec == state.last.physical_seconds AND
6.     now_ns < state.last.physical_nanos):
7.     // Physical clock regressed
8.     state.clock_regressions_detected += 1
9.     
10.    // Use last physical time + increment logical counter
11.    hlc.physical_seconds = state.last.physical_seconds
12.    hlc.physical_nanos = state.last.physical_nanos
13.    hlc.logical_counter = state.last.logical_counter + 1
14.
15. else if now_sec == state.last.physical_seconds AND
16.         now_ns == state.last.physical_nanos:
17.    // Same physical time as last event
18.    hlc.physical_seconds = now_sec
19.    hlc.physical_nanos = now_ns
20.    hlc.logical_counter = state.last.logical_counter + 1
21.
22. else:
23.    // Physical time advanced normally
24.    hlc.physical_seconds = now_sec
25.    hlc.physical_nanos = now_ns
26.    hlc.logical_counter = 0
27.
28. hlc.node_id = state.node_id
29. state.last = hlc
30. return hlc
```

### 4.2 On Receive (Incoming Message)

```c
Algorithm: HLC_RECEIVE

Input:
  state    — Per-node HLC state
  received — HLC timestamp from received message

Output:
  accepted — Whether to accept the message
  hlc      — Updated local HLC (if accepted)

1. // Step 1: Validate the received timestamp based on strategy
2. switch state.receive_strategy:
3.     case HLC_STRATEGY_NAIVE:
4.         accepted = true
5.         break
6.     
7.     case HLC_STRATEGY_BOUNDED:
8.         local_sec, local_ns = GET_PHYSICAL_TIME(state.time_source)
9.         skew_ms = HLC_DIFF_MS(received, local_sec, local_ns)
10.        
11.        if skew_ms > state.max_skew_ms:
12.            // Received timestamp too far in the future
13.            state.time_travel_attempts_rejected += 1
14.            LOG("Rejected HLC from %s: %lldms ahead of local clock "
15.                "(max %lldms)", received.node_id, skew_ms, state.max_skew_ms)
16.            return {accepted: false}
17.        
18.        if skew_ms < -state.max_skew_ms:
19.            // Received timestamp too far in the past
20.            LOG("Rejected HLC from %s: %lldms behind local clock",
21.                received.node_id, -skew_ms)
22.            return {accepted: false}
23.        
24.        accepted = true
25.        break
26.     
27.     case HLC_STRATEGY_QUORUM:
28.         // Wait for multiple independent reports
29.         confirmations = COLLECT_HLC_CONFIRMATIONS(
30.             received, state.quorum_size - 1, state.quorum_timeout_ms)
31.        
32.        if confirmations < state.quorum_size - 1:
33.            state.quorum_failures += 1
34.            LOG("Rejected HLC from %s: only %d/%d confirmations",
35.                received.node_id, confirmations + 1, state.quorum_size)
36.            return {accepted: false}
37.        
38.        accepted = true
39.        break
40.     
41.     case HLC_STRATEGY_STRICT:
42.         // Never update local clock from received messages
43.         // Only use received timestamp for ordering comparisons
44.         return {accepted: true, hlc: state.last}
45.         // NOTE: No update to local state
46.     
47.     case HLC_STRATEGY_TRUSTED:
48.         if not VERIFY_TRUSTED_TIMESTAMP(received):
49.             LOG("Rejected HLC from %s: untrusted timestamp", received.node_id)
50.             return {accepted: false}
51.         accepted = true
52.         break

53. // Step 2: If using STRICT strategy, we already returned
54. // Step 3: Update local HLC (max rule)
55. if state.strict_mode:
56.     // Strict mode: never update local clock
57.     return {accepted: true, hlc: state.last}
58. 
59. // Compare received with local physical time
60. local_sec, local_ns = GET_PHYSICAL_TIME(state.time_source)
61. 
62. // Take the max of local physical time and received time
63. if received.physical_seconds > local_sec OR
64.    (received.physical_seconds == local_sec AND
65.     received.physical_nanos > local_ns):
66.     // Received time is ahead of local physical time
67.     max_sec = received.physical_seconds
68.     max_ns = received.physical_nanos
69. else:
70.     max_sec = local_sec
71.     max_ns = local_ns
72. 
73. // Update local HLC
74. if max_sec > state.last.physical_seconds OR
75.    (max_sec == state.last.physical_seconds AND
76.     max_ns > state.last.physical_nanos):
77.     // Max is ahead of last — reset counter
78.     state.last.physical_seconds = max_sec
79.     state.last.physical_nanos = max_ns
80.     state.last.logical_counter = 0
81. elif max_sec == state.last.physical_seconds AND
82.      max_ns == state.last.physical_nanos:
83.     // Same time — take max of counters
84.     state.last.logical_counter = max(
85.         state.last.logical_counter,
86.         received.logical_counter
87.     ) + 1
88. 
89. return {accepted: true, hlc: state.last}
```

---

## 5. Attack Mitigation Strategies

### 5.1 Strategy Comparison

Strategy	Time Travel Protection	Causal Ordering	Complexity	Network Requirement
`NAIVE`	❌ None	✅ Yes	Low	None
`BOUNDED`	✅ Up to `max_skew_ms`	✅ Yes	Low	None
`QUORUM`	✅ Requires f+1 collusion	✅ Yes	Medium	Multiple nodes respond
`STRICT`	✅ Absolute	🔶 Limited	Low	None
`TRUSTED`	✅ Hardware-level	✅ Yes	High	Auth time source

### 5.2 BOUNDED Strategy (Recommended Default)

```plaintext
Configuration:
  receive_strategy: BOUNDED
  max_skew_ms: 5000

Behavior:
  - Accept received timestamps within 5 seconds of local clock
  - Reject timestamps more than 5 seconds ahead (potential attack)
  - Reject timestamps more than 5 seconds behind (stale/attacker)

Security:
  - Attacker can force at most a 5-second jump
  - 5 seconds is harmless for ordering purposes
  - No single attacker can cause catastrophic time travel

Rationale:
  - NTP-synchronized clocks are typically within 100ms of each other
  - 5 seconds provides generous margin for legitimate clock skew
  - Any jump > 5 seconds is almost certainly malicious
```

### 5.3 QUORUM Strategy (High Security)

```plaintext
Configuration:
  receive_strategy: QUORUM
  quorum_size: 3
  quorum_timeout_ms: 1000

Behavior:
  - On receiving a timestamp, ask other nodes: "Is this timestamp reasonable?"
  - Require at least 2 other nodes to confirm before accepting
  - If quorum not reached within timeout, reject

Security:
  - Single malicious node cannot force a time jump
  - Requires attacker to control quorum_size - 1 other nodes
  - For quorum_size = 3, attacker needs 2 other compromised nodes

Tradeoff:
  - Adds latency (waiting for confirmations)
  - Requires network communication for every received message
  - Not suitable for high-throughput scenarios
```

### 5.4 STRICT Strategy (Paranoid)

```plaintext
Configuration:
  receive_strategy: STRICT
  strict_mode: true

Behavior:
  - Local clock is NEVER updated from received messages
  - Received timestamps are used ONLY for ordering comparisons
  - Local HLC advances based solely on physical time + local counter

Security:
  - Absolute immunity to time travel attacks
  - No amount of malicious messages can affect local clock

Tradeoff:
  - Causal ordering is NOT guaranteed across nodes with skewed clocks
  - If Node A's clock is 10 seconds behind Node B's:
    - B's operations will always have higher timestamps than A's
    - Even if A's operation causally follows B's, it may have a lower timestamp
  - Requires all nodes to have synchronized clocks (NTP) for correctness

When to use:
  - Air-gapped systems
  - High-security environments where any risk is unacceptable
  - Systems with guaranteed clock synchronization (hardware PTP)
```

### 5.5 TRUSTED Strategy (Hardware)

```plaintext
Configuration:
  receive_strategy: TRUSTED
  trusted_time_source: true
  trusted_resync_ms: 30000

Behavior:
  - Physical time comes from a trusted, tamper-resistant source
  - TPM: Platform Trust Module with monotonic counter
  - NTP Auth: NTPv4 with autokey authentication
  - Consensus: Nodes periodically agree on time via protocol

Security:
  - Attacker cannot spoof time without compromising hardware
  - TPM counters are physically tamper-resistant
  - Authenticated NTP prevents man-in-the-middle time attacks

Tradeoff:
  - Requires hardware support (TPM) or authenticated NTP infrastructure
  - Higher complexity
  - TPM counters may have limited resolution
```

---

## 6. Integration with CRABS Operations

### 6.1 Updated Operation Structure

```c
typedef struct crabs_operation {
    // ... existing fields ...
    
    // Ordering system discriminator
    crabs_ordering_system_t ordering_system;  // LAMPORT or HLC
    
    union {
        // Lamport clock fields (existing)
        struct {
            uint64_t lamport_time;
            uint64_t sequence_num;
        } lamport;
        
        // HLC fields (NEW)
        crabs_hlc_t hlc;
    };
    
    char node_id[64];  // Common tiebreaker
    
    // ... existing fields ...
} crabs_operation_t;
```

### 6.2 Serialization for Signing

The canonical encoding for signing includes the ordering system and its fields:

```c
Algorithm: SERIALIZE_FOR_SIGNING (v1.6)

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
     
     // Ordering system
     op.ordering_system,        // uint8: 0=LAMPORT, 1=HLC
     
     if op.ordering_system == LAMPORT:
         op.lamport.lamport_time,
         op.lamport.sequence_num,
     else:
         op.hlc.physical_seconds,
         op.hlc.physical_nanos,
         op.hlc.logical_counter,
     
     op.node_id,
     op.sig_scheme,
     op.key_id,
     op.dedup,
     op.co_signers
   ]

2. return canonical_encode(fields)
```

### 6.3 Machine Configuration

```c
// Per-machine ordering configuration
crabs_ordering_config_t config = {
    .ordering_system = CRABS_ORDERING_HLC,  // or CRABS_ORDERING_LAMPORT
    
    .hlc = {
        .receive_strategy = HLC_STRATEGY_BOUNDED,
        .max_skew_ms = 5000,
        .quorum_size = 3,
        .quorum_timeout_ms = 1000,
        .strict_mode = false,
        .trusted_time_source = false,
        .trusted_resync_ms = 30000
    }
};

// Set at machine setup
crabs_setup(&state, &mpk, &msk,
    .ordering = &config
);

// Changeable via policy transition (logged)
Operation = {
    type: "__change_ordering_config__",
    payload: {
        ordering_system: CRABS_ORDERING_HLC,
        hlc: {
            receive_strategy: HLC_STRATEGY_QUORUM,
            quorum_size: 5
        }
    },
    policy: "role:admin AND weight >= 3",
    signature: {...}
}
```

### 6.4 Mixed-Mode Interoperability

```plaintext
A machine can accept operations with BOTH Lamport and HLC ordering,
but each operation uses exactly one system.

Rules:
  1. An operation's ordering_system field determines how it's ordered
  2. Lamport operations are ordered by (lamport_time, node_id, sequence_num)
  3. HLC operations are ordered by (physical_seconds, physical_nanos, 
     logical_counter, node_id)
  4. Cross-system ordering: HLC operations always sort AFTER Lamport operations
     (HLC has a higher system priority)
  
  This ensures:
    - No ambiguity between the two systems
    - All nodes agree on the same total order
    - Migration is possible: start with Lamport, switch to HLC
```

---

## 7. Physical Time Sources

### 7.1 System Clock

```c
Algorithm: GET_SYSTEM_CLOCK_TIME

Output:
  seconds — Unix epoch seconds
  nanos   — Nanosecond component

1. struct timespec ts;
2. clock_gettime(CLOCK_REALTIME, &ts)
3.   // Or: CLOCK_MONOTONIC for monotonicity (but no epoch)
4. return {seconds: ts.tv_sec, nanos: ts.tv_nsec}

// NOTE: CLOCK_REALTIME can jump backward (NTP adjustments)
// CLOCK_MONOTONIC cannot jump backward but has no epoch reference
// Recommendation: Use CLOCK_REALTIME with HLC's regression detection
```

### 7.2 Authenticated NTP

```c
Algorithm: GET_NTP_AUTH_TIME

Output:
  seconds — Authenticated NTP time
  nanos   — Nanosecond component
  valid   — Whether the time is authenticated

1. // Send NTPv4 request with autokey authentication
2. request = NTPv4_autokey_request()
3. response = ntp_send_and_receive(request, timeout_ms=1000)
4. 
5. if response == null:
6.     return {valid: false}  // No response
7. 
8. if not VERIFY_NTP_AUTH(response):
9.     return {valid: false}  // Authentication failed
10.
11. // Extract and adjust for network latency
12. adjusted_time = NTP_ADJUST(response)
13. return {seconds: adjusted_time.sec, nanos: adjusted_time.nsec, valid: true}

// Fallback: Use system clock if NTP unavailable
// (with a logged warning)
```

### 7.3 TPM Hardware Clock

```c
Algorithm: GET_TPM_TIME

Output:
  seconds — TPM monotonic time
  nanos   — Nanosecond component (may be coarse)

1. // TPM2_GetTime or TPM2_ReadClock
2. tpm_time = TPM2_GetTime()
3. 
4. if tpm_time == null:
5.     return {valid: false}  // TPM unavailable
6. 
7. // TPM time is monotonic and tamper-resistant
8. // May need to convert from TPM ticks to epoch
9. seconds = TPM_TICKS_TO_EPOCH(tpm_time.ticks)
10. return {seconds: seconds, nanos: 0, valid: true}

// NOTE: TPM time may have limited resolution (milliseconds or ticks)
// The logical counter handles same-tick events
```

### 7.4 Consensus-Based Time

```c
Algorithm: GET_CONSENSUS_TIME

Output:
  seconds — Consensus-agreed time
  nanos   — Nanosecond component

1. // Nodes periodically agree on the current time
2. // via a simple consensus protocol (e.g., Raft-style)
3. //
4. // Each node proposes its local time
5. // The leader computes the median and broadcasts it
6. // Nodes accept the consensus time if signed by quorum
7. 
8. if CONSENSUS_TIME_AVAILABLE():
9.     return CONSENSUS_READ_TIME()
10. else:
11.     // Fall back to local system clock
12.     return GET_SYSTEM_CLOCK_TIME()
```

---

## 8. Lock Integration

### 8.1 HLC-Based Lock Priority

```c
Algorithm: HLC_LOCK_PRIORITY

Input:
  lock_a — First lock claim
  lock_b — Second lock claim

Output:
  winner — Which lock wins (-1 = a, 1 = b, 0 = same)

// Lock priority uses HLC ordering:
// The operation with the EARLIER timestamp wins
// (first-come, first-served)

1. return crabs_hlc_compare(&lock_a.hlc, &lock_b.hlc)
// Returns: -1 if a wins, 1 if b wins, 0 if tie (use node_id)
```

### 8.2 HLC-Based Lock Expiry

```c
Algorithm: HLC_LOCK_EXPIRY

Input:
  lock       — Lock with HLC acquisition time
  duration_ms — Lock duration in milliseconds

Output:
  expired — Whether the lock has expired

1. // Get current HLC
2. now = HLC_NEXT(state)
3. 
4. // Compute expiry HLC
5. expiry = lock.acquired_at
6. expiry.physical_nanos += duration_ms * 1000000
7. NORMALIZE_HLC(&expiry)  // Handle nanosecond overflow → seconds
8. 
9. // Compare
10. return crabs_hlc_compare(&now, &expiry) > 0
```

---

## 9. Serialization

### 9.1 HLC Serialization

```c
HlcSerialized = {
    physical_seconds: uint64,    // 8 bytes
    physical_nanos: uint64,      // 8 bytes
    logical_counter: uint64,     // 8 bytes
    node_id_length: uint16,      // 2 bytes
    node_id: byte[node_id_length]
}
// Total: 26 bytes + node_id (typically 32-64 bytes)
// Compare to Lamport: 8 bytes (lamport_time) + 8 bytes (sequence_num) + node_id
```

### 9.2 Operation Serialization Update

```c
OperationSerialized = {
    // ... existing fields ...
    
    // NEW: Ordering system discriminator
    ordering_system: uint8,      // 0=LAMPORT, 1=HLC
    
    // Conditional on ordering_system:
    if ordering_system == LAMPORT:
        lamport_time: uint64,
        sequence_num: uint64,
    else:
        hlc: HlcSerialized,
    
    node_id: string,
    // ... remaining fields ...
}
```

---

## 10. Migration from Lamport to HLC

### 10.1 Migration Path

```plaintext
Phase 1: Dual-accept (both systems accepted)
  config.ordering_system = LAMPORT  (keep producing Lamport)
  Accept both Lamport and HLC operations
  All nodes run HLC-aware code

Phase 2: Gradual switch
  Some nodes switch to producing HLC operations
  Both systems coexist in the same log
  Cross-system ordering: HLC > Lamport (by convention)

Phase 3: HLC-only
  config.ordering_system = HLC
  Reject Lamport-only operations
  All nodes produce HLC operations
```

### 10.2 Cross-System Ordering

```c
Algorithm: COMPARE_OPERATIONS

Input:
  a — First operation
  b — Second operation

Output:
  -1 if a < b, 1 if a > b, 0 if equal

1. // Cross-system ordering: HLC sorts after Lamport
2. if a.ordering_system == LAMPORT AND b.ordering_system == HLC:
3.     return -1  // Lamport before HLC
4. if a.ordering_system == HLC AND b.ordering_system == LAMPORT:
5.     return 1   // HLC after Lamport

6. // Same system: use system-specific ordering
7. if a.ordering_system == LAMPORT:
8.     return COMPARE_LAMPORT(a, b)
9. else:
10.    return crabs_hlc_compare(&a.hlc, &b.hlc)
```

---

## 11. Security Considerations

### 11.1 Time Travel Attack Surface

```plaintext
┌──────────────────────┬────────────────────────┬──────────────────────┐
│      Strategy        │   Max Attack Impact    │   Detection          │
├──────────────────────┼────────────────────────┼──────────────────────┤
│ NAIVE                │ Unlimited              │ ❌ Not detectable    │
│ BOUNDED (5s)         │ 5 seconds              │ ✅ Logged            │
│ QUORUM (3 nodes)     │ Requires 2 colluders   │ ✅ Quorum failure    │
│ STRICT               │ None                   │ N/A                  │
│ TRUSTED              │ Hardware-dependent     │ ✅ Auth failure      │
└──────────────────────┴────────────────────────┴──────────────────────┘
```

### 11.2 Clock Regression

```plaintext
Attack: Attacker causes node's physical clock to jump backward
        (e.g., NTP manipulation, VM state rollback)

Impact:
  - HLC detects regression (physical time < last timestamp)
  - Uses last timestamp + increment counter
  - Logical counter grows unboundedly during regression
  - Once physical time catches up, counter resets to 0

Mitigation:
  - Use CLOCK_MONOTONIC instead of CLOCK_REALTIME
    (monotonic clock never jumps backward)
  - Tradeoff: monotonic clock has no epoch reference
  - Solution: Store epoch at startup, use monotonic offset
```

### 11.3 Quorum Starvation

```plaintext
Attack: Attacker floods a node with messages, each requiring
        quorum confirmation, causing the node to exhaust
        resources waiting for confirmations.

Mitigation:
  - Per-sender rate limiting
  - Quorum timeout (fail fast if confirmations don't arrive)
  - Cache recent confirmations (same timestamp from same sender)
  - Maximum concurrent quorum requests
```

---

## 12. Test Vectors

### 12.1 Basic HLC Generation

```plaintext
Setup:
  - Node: alice
  - Physical time: epoch=36000, nanos=500000000
  - No prior events

HLC_NEXT:
  now = (36000, 500000000)
  state.last = (0, 0, 0)  // Initial
  
  now > last → normal advance
  result = (36000, 500000000, 0, "alice")

Expected:
  physical_seconds = 36000
  physical_nanos = 500000000
  logical_counter = 0
  node_id = "alice"
```

### 12.2 Same-Nanosecond Events

```plaintext
Setup:
  - Node: alice
  - Physical time: epoch=36000, nanos=500000000

Event 1:
  HLC_NEXT → (36000, 500000000, 0, "alice")

Event 2 (same nanosecond):
  HLC_NEXT → (36000, 500000000, 1, "alice")

Event 3 (same nanosecond):
  HLC_NEXT → (36000, 500000000, 2, "alice")

Expected:
  Events ordered: 0 < 1 < 2 (by logical_counter)
  All have same physical time
```

### 12.3 Clock Regression

```plaintext
Setup:
  - Node: alice
  - state.last = (36000, 500000000, 5, "alice")
  - Physical time: epoch=35999, nanos=900000000  (clock jumped BACK 600ms)

HLC_NEXT:
  now = (35999, 900000000)
  now.seconds (35999) < last.seconds (36000) → regression detected
  
  result.seconds = last.seconds = 36000
  result.nanos = last.nanos = 500000000
  result.counter = last.counter + 1 = 6

Expected:
  (36000, 500000000, 6, "alice")
  clock_regressions_detected incremented
```

### 12.4 BOUNDED Strategy — Accept

```plaintext
Setup:
  - Node A: local time = (36000, 0, 0)
  - max_skew_ms = 5000
  - Received from Node B: (36002, 0, 0, "bob")  // 2 seconds ahead

HLC_RECEIVE (BOUNDED):
  skew_ms = (36002 - 36000) * 1000 + (0 - 0) / 1000000 = 2000ms
  2000ms <= 5000ms → ACCEPT

  max(local, received) = (36002, 0)
  state.last = (36002, 0, 0)

Expected:
  accepted = true
  state.last = (36002, 0, 0)
```

### 12.5 BOUNDED Strategy — Reject

```plaintext
Setup:
  - Node A: local time = (36000, 0, 0)
  - max_skew_ms = 5000
  - Received from Node M: (99999, 0, 0, "malicious")  // far in future

HLC_RECEIVE (BOUNDED):
  skew_ms = (99999 - 36000) * 1000 = 63999000ms
  63999000ms > 5000ms → REJECT

Expected:
  accepted = false
  time_travel_attempts_rejected incremented
  state.last unchanged
```

### 12.6 STRICT Strategy

```plaintext
Setup:
  - Node A: state.last = (36000, 500, 3, "alice")
  - strict_mode = true
  - Received from Node B: (99999, 0, 0, "bob")

HLC_RECEIVE (STRICT):
  strict_mode = true → return immediately without updating

Expected:
  accepted = true  (message is accepted for ordering)
  state.last = (36000, 500, 3, "alice")  // UNCHANGED
  // The received timestamp is used only for ordering comparisons
```

### 12.7 Cross-System Ordering

```plaintext
Setup:
  - Operation A: Lamport (lamport_time=42, seq=1, node="alice")
  - Operation B: HLC (36000, 500, 0, "bob")

COMPARE_OPERATIONS(A, B):
  A is LAMPORT, B is HLC → A < B

COMPARE_OPERATIONS(B, A):
  B is HLC, A is LAMPORT → B > A

Expected:
  All Lamport operations sort before all HLC operations.
  This ensures deterministic ordering during migration.
```

---

## 13. Summary of Changes from v1.5

Section	Change
§2	HLC data structure and total ordering
§3	HLC state, configuration, and strategies
§4	HLC generation and receive algorithms
§5	Attack mitigation strategies (BOUNDED, QUORUM, STRICT, TRUSTED)
§6	Integration with CRABS operations
§7	Physical time sources (system, NTP auth, TPM, consensus)
§8	Lock integration with HLC
§9	Serialization formats
§10	Migration from Lamport to HLC
§11	Security considerations
§12	Test vectors

---

## Appendix: Configuration Quick Reference

```plaintext
┌────────────────────────────┬──────────────────┬──────────────────────┐
│       Deployment           │   Strategy        │   Rationale          │
├────────────────────────────┼──────────────────┼──────────────────────┤
│ Development / testing      │ NAIVE            │ Simplicity, no       │
│                            │                  │ attacker model       │
├────────────────────────────┼──────────────────┼──────────────────────┤
│ General purpose            │ BOUNDED (5s)     │ Good balance of      │
│                            │                  │ safety and simplicity │
├────────────────────────────┼──────────────────┼──────────────────────┤
│ High-security (finance)    │ QUORUM (3-5)     │ Multiple nodes must  │
│                            │                  │ agree on time        │
├────────────────────────────┼──────────────────┼──────────────────────┤
│ Air-gapped / military      │ STRICT           │ Absolute immunity    │
│                            │                  │ to time attacks      │
├────────────────────────────┼──────────────────┼──────────────────────┤
│ Hardware-backed (TPM)      │ TRUSTED          │ Hardware-level       │
│                            │                  │ tamper resistance    │
├────────────────────────────┼──────────────────┼──────────────────────┤
│ Mixed (migration)          │ LAMPORT (system) │ Keep Lamport during  │
│                            │ + BOUNDED HLC    │ transition, accept   │
│                            │ (accept)         │ both                 │
└────────────────────────────┴──────────────────┴──────────────────────┘
```
