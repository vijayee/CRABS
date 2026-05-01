# CRABS Protocol Specification v1.5 — Amendment 5 (Addendum)

## *Tombstone Management and State Compaction for OT/CRDT Types*

---

**Amendment Status:** Draft  
**Spec Version:** 1.5.1  
**Date:** April 30, 2026  
**Addendum to:** Amendment 5 §3 (OT/CRDT Data Types)

---

## Preamble

OT/CRDT hybrid types maintain a **position map** — a balanced BST that tracks all deleted positions (tombstones) and inserted positions (shifts). This map is essential for correct convergence: it enables the `xi` and `xi_inv` functions that translate between internal and visible coordinate spaces. However, tombstones accumulate with every DELETE operation and grow linearly with edit count, not document size.

Without management, the position map can grow unboundedly, consuming memory and degrading performance. This addendum defines **compaction** — the process of removing tombstones by rebuilding the visible state into a fresh data item — and specifies when compaction is safe, how it is performed, and how it integrates with the CRABS protocol.

---

## 1. The Tombstone Problem

### 1.1 Growth Over Time

```plaintext
For an OT_DOCUMENT with V visible characters and E total edits:

Position map size ≈ E (every edit adds a node)
Visible size = V (characters the user sees)
Tombstone ratio = E / V

Example:
  Document created:    V = 0,    E = 0,     ratio = 0
  After 100 edits:     V = 80,   E = 100,   ratio = 1.25
  After 1,000 edits:   V = 500,  E = 1,000, ratio = 2.0
  After 10,000 edits:  V = 2000, E = 10,000, ratio = 5.0
  After 100,000 edits: V = 5000, E = 100,000,ratio = 20.0
```

Without compaction, a document with 5,000 visible characters and 100,000 edits has a position map of ~100,000 nodes — **20x the visible content**.

### 1.2 Performance Impact

```plaintext
Position map operations are O(log N) where N = node count.

With 100,000 nodes:
  xi() / xi_inv():     ~17 comparisons  (log₂ 100,000)
  union_one():         ~17 comparisons + rebalancing
  xi_one():            ~17 comparisons + rebalancing

With 1,000,000 nodes:
  xi() / xi_inv():     ~20 comparisons
  union_one():         ~20 comparisons + rebalancing

Memory: ~48 bytes per node (left, right, value, size, height, deleted)
  100,000 nodes → ~4.8 MB
  1,000,000 nodes → ~48 MB
```

For most applications, this is acceptable. But for long-lived, heavily-edited documents, compaction becomes necessary.

---

## 2. Compaction Safety

### 2.1 When Compaction is Safe

Compaction is safe **only when all peers have observed all operations** that preceded the compaction point. Otherwise, a peer that hasn't seen an operation will have a different position map and will compute different `xi`/`xi_inv` values after compaction.

```plaintext
Safe:  All peers have seen operations 0..1000
       → Compact at operation 1000
       → All peers rebuild from the same visible state
       → Future operations reference the new coordinate space
       → Convergence preserved

Unsafe: Peer A has seen operations 0..1000
        Peer B has seen operations 0..950
        → Compact at operation 1000
        → Peer B's position map doesn't match
        → Peer B computes wrong xi/xi_inv values
        → Convergence broken
```

### 2.2 Determining Safety

Each node tracks what it has observed from every other node:

```plaintext
VectorClock = {
    "<node_id>": uint64,   // Highest sequence number observed from this node
    ...
}
```

Compaction is safe when:

```plaintext
for each node_id in all_nodes:
    for each peer_id in all_peers:
        if peer_id.vector_clock[node_id] < all_nodes[node_id].max_sequence:
            return NOT_SAFE  // Peer hasn't seen all operations from node_id

return SAFE  // All peers have seen all operations
```

### 2.3 Safety Levels

```plaintext
SAFE_LEVELS:

STRONG:   All known peers have acknowledged all operations.
          Guarantees convergence. Requires all peers to be online.

QUORUM:   A configurable fraction of peers (e.g., 80%) have acknowledged.
          May cause divergence for peers not in the quorum.
          Those peers must re-sync from the compacted state.

TIMESTAMP: No peer acknowledgment check.
           Compaction happens after a grace period (e.g., 24 hours).
           Risky — only safe for single-node deployments.

FORCE:    Compaction happens regardless of peer state.
          All peers must discard their state and re-sync from the compactor.
          Used for emergency recovery only.
```

---

## 3. Compaction Algorithm

### 3.1 Standard Compaction

```plaintext
Algorithm: COMPACT_OT_ITEM

Input:
  item     — OT/CRDT data item to compact
  state    — Current CRABS state (for peer tracking)
  config   — Tombstone configuration

Output:
  compacted — Compacted data item
  error     — Error code if compaction is not safe

1. // Check safety
2. safety = CHECK_COMPACTION_SAFETY(state, config)
3. if safety == NOT_SAFE and config.force == false:
4.     return {error: COMPACTION_NOT_SAFE}
5. 
6. // Read the visible value (tombstones already hidden by position map)
7. visible_value = EXTRACT_VISIBLE_VALUE(item)
8. 
9. // Generate a compaction operation
10. compaction_op = {
         id: generate_compaction_id(state),
         op_type: COMPACT,              // New built-in OT operation type
         visible_pos: 0,
         payload: SERIALIZE(visible_value),
         priority: 0,                    // Lowest — overridden by any concurrent op
         deps: [],                       // Depends on ALL previous ops (implicitly)
         timestamp: now()
     }
11. 
12. // Create a fresh data item with the visible content
13. compacted = ALLOCATE_OT_ITEM(item.ot_type_id)
14. compacted.visible_value = visible_value
15. compacted.position_map = EMPTY_POSITION_MAP  // No tombstones
16. compacted.op_log = [compaction_op]           // Single operation
17. compacted.priority_counters = item.priority_counters  // Preserve counters
18. 
19. // Log the compaction
20. LOG(state, {
         type: "__compaction__",
         item_name: item.name,
         previous_op_count: item.op_log.count,
         new_op_count: 1,
         previous_tombstone_count: COUNT_TOMBSTONES(item.position_map),
         new_tombstone_count: 0,
         safety_level: safety,
         timestamp: now()
     })
21. 
22. // Increment the state version (compaction is a state change)
23. state.version += 1
24. 
25. return {compacted: compacted, error: SUCCESS}
```

### 3.2 Extracting the Visible Value

```plaintext
Algorithm: EXTRACT_VISIBLE_VALUE

Input:
  item — OT/CRDT data item

Output:
  visible_value — The user-visible content with tombstones removed

// For OT_ORDERED_SET:
1. visible = []
2. for i = 0 to item.visible_value.count - 1:
3.     internal_pos = xi_inv(item.position_map, i)
4.     if not IS_DELETED(item.position_map, internal_pos):
5.         visible.append(item.full_value[internal_pos])
6. return visible

// For OT_DOCUMENT:
7. visible_str = ""
8. for i = 0 to LENGTH(item.visible_value) - 1:
9.     internal_pos = xi_inv(item.position_map, i)
10.    if not IS_DELETED(item.position_map, internal_pos):
11.        visible_str += CHAR_AT(item.full_value, internal_pos)
12. return visible_str

// For OT_TREE:
13. visible_tree = {}
14. for each node_id in item.nodes:
15.     node = item.nodes[node_id]
16.     if node.deleted:
17.         continue
18.     visible_tree[node_id] = {
19.         value: node.value,
20.         children: node.children  // Children are already filtered
21.     }
22. return visible_tree
```

### 3.3 Compaction Operation

Compaction introduces a new built-in OT operation type:

```plaintext
OTOpType = enum {
    // ... existing types ...
    COMPACT = 0x05  // NEW: Compaction operation
}
```

The `COMPACT` operation has special semantics:

```plaintext
COMPACT(pos, payload):
  - pos is always 0 (compaction replaces the entire visible content)
  - payload is the serialized visible value
  - priority is 0 (lowest — any concurrent operation overrides it)
  - deps is empty (compaction implicitly depends on ALL prior operations)

Transform rules for COMPACT:
  - COMPACT vs INSERT: COMPACT wins (insert is absorbed into compacted state)
  - COMPACT vs DELETE: COMPACT wins (delete is absorbed)
  - COMPACT vs MOVE: COMPACT wins (move is absorbed)
  - COMPACT vs COMPACT: last-writer-wins by timestamp
```

---

## 4. Integration with Operation Execution

### 4.1 Modified Execution Flow

```plaintext
Algorithm: EXECUTE_OPERATION (v1.5.1)

// Steps 1-7: Unchanged from v1.5
1. PRUNE_EXPIRED_LOCKS(state)
2. Check for duplicate UUID
3. Verify protocol state transitions
4. Verify lock claims
5. Verify ABE signature and key version
6. Extract OT operations from payload
7. Transform and apply each OT operation

// Step 8: NEW — Check if compaction is needed
8. for each item modified by this operation:
9.     if item.type is an OT/CRDT type (0x10-0x1F):
10.        tombstone_ratio = COUNT_TOMBSTONES(item.position_map) / 
11.                          VISIBLE_SIZE(item.visible_value)
12.        
13.        if tombstone_ratio > state.config.tombstone.max_ratio:
14.            // Trigger compaction
15.            result = COMPACT_OT_ITEM(item, state, state.config.tombstone)
16.            if result.error == SUCCESS:
17.                state.items[item.name] = result.compacted

// Steps 9-10: Unchanged
9. Transition protocol states
10. PROCESS_TRIGGERS(state)
11. Log and increment version

12. return SUCCESS
```

### 4.2 Periodic Compaction

```plaintext
Algorithm: PERIODIC_COMPACTION

Input:
  state — Current CRABS state

// Called on a timer (configurable interval)

1. for each (name, item) in state.items:
2.     if item.type is not an OT/CRDT type:
3.         continue
4.     
5.     // Check if compaction is needed
6.     tombstone_count = COUNT_TOMBSTONES(item.position_map)
7.     visible_size = VISIBLE_SIZE(item.visible_value)
8.     tombstone_ratio = tombstone_count / max(visible_size, 1)
9.     
10.    if tombstone_ratio > state.config.tombstone.max_ratio:
11.        COMPACT_OT_ITEM(item, state, state.config.tombstone)
12.    
13.    // Time-based compaction
14.    if state.config.tombstone.strategy == TIME_BASED:
15.        time_since_last = now() - item.last_compaction_time
16.        if time_since_last > state.config.tombstone.compaction_interval_ms:
17.            COMPACT_OT_ITEM(item, state, state.config.tombstone)
```

---

## 5. Peer Synchronization After Compaction

After compaction, the coordinate space changes. Peers that missed the compaction must re-sync.

### 5.1 Compaction Notification

```plaintext
When a node compacts an item, it broadcasts a COMPACT operation:

Broadcast:
  {
      type: "ot_op",
      item_name: "document_42",
      op: {
          id: <compaction_id>,
          op_type: COMPACT,
          visible_pos: 0,
          payload: <serialized_visible_value>,
          priority: 0,
          deps: [],
          timestamp: now()
      }
  }
```

### 5.2 Peer Receives Compaction

```plaintext
Algorithm: RECEIVE_COMPACTION

Input:
  peer — Local peer state
  item_name — Name of the compacted item
  compaction_op — The COMPACT operation

1. // Check if the peer has seen all operations before the compaction
2. if peer.vector_clock[compaction_op.node_id] < compaction_op.sequence_num:
3.     // Peer is missing operations — must sync first
4.     REQUEST_MISSING_OPS(peer, compaction_op.node_id, 
5.                          peer.vector_clock[compaction_op.node_id],
6.                          compaction_op.sequence_num)
7.     return DEFERRED  // Will apply compaction after sync

8. // Peer has all prior operations — apply compaction
9. item = peer.state.items[item_name]
10. 
11. // Discard old position map and operation log
12. item.position_map = EMPTY_POSITION_MAP
13. item.op_log = [compaction_op]
14. item.visible_value = DESERIALIZE(compaction_op.payload)
15. item.full_value = item.visible_value  // No tombstones
16. item.last_compaction_time = now()
17. 
18. // Update vector clock
19. peer.vector_clock[compaction_op.node_id] = compaction_op.sequence_num
20. 
21. return SUCCESS
```

### 5.3 Late Peer Recovery

```plaintext
A peer that was offline during compaction must:

1. On reconnection, request all missed operations
2. Receive the COMPACT operation
3. Apply all operations BEFORE the compaction in order
4. Apply the compaction (discards old state)
5. Apply all operations AFTER the compaction

This is equivalent to:
  "Catch up to the compaction point, then fast-forward to current."
```

---

## 6. Configuration

```plaintext
TombstoneConfig = {
    // Compaction strategy
    strategy: CompactionStrategy,   // NONE, TIME_BASED, SIZE_BASED, QUORUM, HYBRID
    
    // Size-based: compact when tombstone ratio exceeds this
    max_tombstone_ratio: float,     // Default: 10.0 (10x visible size)
    
    // Time-based: compact every N milliseconds
    compaction_interval_ms: uint64, // Default: 86400000 (24 hours)
    
    // Quorum: fraction of peers that must acknowledge
    quorum_threshold: float,        // Default: 1.0 (all peers)
    
    // Emergency: force compact when tombstone count exceeds this
    emergency_tombstone_count: uint64, // Default: 1000000
    
    // Whether to allow force compaction
    allow_force: bool,              // Default: false
    
    // Whether to auto-compact on every Nth operation
    auto_compact_interval: uint32,  // Default: 0 (disabled)
    
    // Log level for compaction events
    log_level: LogLevel             // INFO, WARN, DEBUG
}

CompactionStrategy = enum {
    NONE        = 0x00,  // Never compact (tombstones grow unbounded)
    TIME_BASED  = 0x01,  // Compact on a timer
    SIZE_BASED  = 0x02,  // Compact when tombstone ratio exceeds threshold
    QUORUM      = 0x03,  // Compact when quorum of peers acknowledge
    HYBRID      = 0x04   // Size-based with time-based fallback
}
```

### 6.1 Recommended Defaults

```plaintext
General purpose:
  strategy: HYBRID
  max_tombstone_ratio: 10.0
  compaction_interval_ms: 86400000  (24 hours)
  quorum_threshold: 1.0
  emergency_tombstone_count: 1000000
  allow_force: false

High-throughput collaborative editing:
  strategy: SIZE_BASED
  max_tombstone_ratio: 5.0
  auto_compact_interval: 1000  (compact every 1000 operations)
  emergency_tombstone_count: 500000

Single-node deployment:
  strategy: TIME_BASED
  compaction_interval_ms: 604800000  (7 days)
  allow_force: true

Resource-constrained (mobile):
  strategy: SIZE_BASED
  max_tombstone_ratio: 20.0  (tolerate more tombstones to avoid compaction CPU)
  emergency_tombstone_count: 50000
```

---

## 7. Security Considerations

### 7.1 Compaction as a Denial-of-Service Vector

```plaintext
Attack: Attacker triggers frequent compactions to consume CPU and I/O.

Mitigation:
  - Minimum interval between compactions (configurable, default: 60 seconds)
  - Compaction requires the same authorization as any other operation
  - Force compaction requires admin-level policy
  - Compaction is rate-limited per node
```

### 7.2 Compaction and Causality

```plaintext
Attack: Attacker compacts at an unsafe point, causing peers to diverge.

Mitigation:
  - STRONG safety level requires all peers to acknowledge
  - QUORUM safety level risks divergence for non-quorum peers
  - FORCE compaction is logged and auditable
  - Peers can detect divergence by comparing state hashes
```

### 7.3 Compaction and Key Versioning

```plaintext
After compaction, the coordinate space changes.
Old ABE keys that reference specific positions may be invalid.

Mitigation:
  - Compaction increments the item's version number
  - Operations that reference positions from before compaction
    are transformed against the COMPACT operation
  - This is handled automatically by the transform matrix
```

---

## 8. Test Vectors

### 8.1 Basic Compaction

```plaintext
Setup:
  - OT_DOCUMENT with content "Hello World"
  - Delete 'W' at position 6
  - Position map: {6: deleted}
  - Visible: "Hello World" (11 chars) → "Hello World" (10 chars, 'W' hidden)
  - Wait — actually after delete, visible is "Hello World" (no 'W')
  - Visible: "Hello World" (10 chars)
  - Tombstone ratio: 1/10 = 0.1

Compaction:
  - Extract visible value: "Hello World"
  - Create new document with "Hello World"
  - Position map: empty
  - Op log: [COMPACT]

After compaction:
  - Insert 'X' at position 5:
    - xi_inv(empty, 5) = 5 (no tombstones to account for)
    - Insert at internal position 5
    - Result: "Hello XWorld"

Without compaction (tombstone still present):
  - Insert 'X' at position 5:
    - xi_inv({6: deleted}, 5) = 5 (tombstone at 6 is after position 5)
    - Insert at internal position 5
    - Result: "Hello XWorld"
    
// Same result! ✅ Compaction preserves correctness.
```

### 8.2 Compaction with Concurrent Operations

```plaintext
Setup:
  - OT_DOCUMENT with content "ABC"
  - Alice deletes 'B' at position 1
  - Bob compacts at the same time

Alice's operation:
  op_a = DELETE(pos=1)

Bob's compaction:
  op_b = COMPACT(pos=0, payload="AC")  // 'B' removed

These are CONCURRENT — neither knows about the other.

Transform op_a against op_b:
  // COMPACT absorbs all prior operations
  // op_a's delete is already reflected in the compacted state
  // op_a becomes a no-op
  op_a' = NULL

Transform op_b against op_a:
  // op_b's payload is "AC" (already includes Alice's delete)
  // No change needed
  op_b' = COMPACT(pos=0, payload="AC")

Apply op_b' then op_a':
  Start: "ABC"
  Apply op_b': "AC" (compacted)
  Apply op_a': NULL (no-op)
  Result: "AC" ✅

Apply op_a' then op_b':
  Start: "ABC"
  Apply op_a': "AC" (delete 'B')
  Apply op_b': "AC" (compacted — same result)
  Result: "AC" ✅

// Convergence! ✅
```

### 8.3 Unsafe Compaction Detection

```plaintext
Setup:
  - Three peers: A, B, C
  - Peer C has been offline for 100 operations
  - Peer A attempts compaction

Peer A's vector clock:
  A: 500, B: 450, C: 200

Peer B's vector clock:
  A: 500, B: 450, C: 200

Peer C's vector clock (offline):
  A: 400, B: 350, C: 200  // Missing operations 401-500 from A, 351-450 from B

Compaction safety check:
  for each node in {A, B, C}:
    for each peer in {A, B, C}:
      if peer.vector_clock[node] < max_sequence[node]:
        return NOT_SAFE

  // Peer C has not seen operations 401-500 from A
  // Peer C has not seen operations 351-450 from B
  // → NOT SAFE

Result:
  - Compaction is deferred
  - Peer A waits for Peer C to come online and sync
  - Once C's vector clock matches, compaction proceeds
```

---

## 9. Summary

Aspect	Detail
**Tombstone location**	Position map BST (every deleted position is a node)
**Growth rate**	Linear with edit count, not document size
**Compaction trigger**	Time-based, size-based, or quorum-based
**Safety condition**	All peers must have observed all prior operations
**Compaction effect**	Discards position map, rebuilds from visible value
**CRDT convergence**	Preserved — compaction is a CRDT operation
**Peer recovery**	Late peers catch up by replaying operations up to compaction point

---

*End of CRABS Protocol Specification v1.5 — Addendum: Tombstone Management and State Compaction*

---

This gives you a complete framework for managing tombstone growth in OT/CRDT types. The key design decisions are:

1. **Compaction is an OT operation** — it has a type (`COMPACT`), a position, a payload, and transforms against concurrent operations like any other op.

2. **Safety is determined by vector clocks** — compaction only proceeds when all peers have acknowledged all prior operations.

3. **Multiple strategies** — time-based for simplicity, size-based for predictability, quorum-based for safety.

4. **Emergency force compaction** — available but logged and auditable.

The position map tombstones are the "memory" of the CRDT. Compaction is the "release" of that memory — safe only when everyone remembers the same past.