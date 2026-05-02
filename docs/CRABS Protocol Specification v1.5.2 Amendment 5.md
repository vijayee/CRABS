# CRABS Protocol Specification v1.5 — Amendment 5, Addendum B

## *Unified Tombstone Compaction for All CRDT Types*

---

**Amendment Status:** Draft  
**Spec Version:** 1.5.2  
**Date:** April 30, 2026  
**Supersedes:** v1.5 Addendum §3–§5 (extends compaction to non-OT types)

---

## Preamble

Amendment 5 (Addendum A) introduced tombstone compaction for OT/CRDT hybrid types (OT_ORDERED_SET, OT_DOCUMENT, OT_TREE). However, several non-OT types also accumulate tombstones: OR-Set, 2P-Set, and RGA. These tombstones grow unboundedly with destructive operations and must be managed for long-lived state machines.

This addendum extends the compaction framework to **all tombstone-bearing types** through a unified interface. Every type that accumulates tombstones implements the same compaction vtable, shares the same safety conditions, and is managed by the same periodic compaction engine.

---

## 1. Tombstone-Bearing Types: Complete Inventory

### 1.1 All Types and Their Tombstone Status

Type ID	Name	Tombstones?	Source	Growth Rate
`0x01`	`COUNTER`	❌ No	—	—
`0x02`	`PN_COUNTER`	❌ No	—	—
`0x03`	`SET` (OR-Set)	✅ **Yes**	Removed element tags	O(removes)
`0x04`	`2P_SET`	✅ **Yes**	Remove set	O(removes)
`0x05`	`REGISTER` (LWW)	❌ No	—	—
`0x06`	`DOCUMENT` (RGA)	✅ **Yes**	Deleted nodes in linked list	O(deletes)
`0x07`	`RESOURCE`	❌ No	—	—
`0x08`	`ONE_SHOT_SET`	❌ No	—	—
`0x09`	`ONE_SHOT_FLAG`	❌ No	—	—
`0x10`	`OT_ORDERED_SET`	✅ **Yes**	Position map nodes	O(edits)
`0x11`	`OT_DOCUMENT`	✅ **Yes**	Position map nodes	O(edits)
`0x13`	`OT_TREE`	✅ **Yes**	Position map nodes	O(edits)

### 1.2 Why Tombstones Persist in Non-OT Types

#### OR-Set (Type 0x03)

```plaintext
Internal structure:
  elements: { (value, tag), ... }     // tag = unique per add
  tombstones: { tag, ... }            // removed tags

A tombstone must persist because:
  - A concurrent add from another node creates a NEW tag
  - The tombstone only blocks the SPECIFIC tag that was removed
  - Without the tombstone, a delayed add with the OLD tag
    could reappear after a remove

Example:
  Node A: add("apple")  → tag = apple@A_5
  Node B: add("apple")  → tag = apple@B_3  (concurrent, different tag)
  
  Node A: remove("apple") → tombstones = {apple@A_5}
  
  Merge: elements = {apple@A_5, apple@B_3}
         tombstones = {apple@A_5}
         visible = {apple@B_3}  // B's add survives!
  
  Without tombstones:
    Merge: elements = {apple@A_5, apple@B_3}
           visible = {apple@A_5, apple@B_3}  // Both visible! ❌
```

#### 2P-Set (Type 0x04)

```plaintext
Internal structure:
  add_set: { element, ... }
  remove_set: { element, ... }

The remove_set must persist because:
  - Once an element is removed, it can never be re-added
  - The remove_set is the record of that decision
  - Without it, a concurrent add could reintroduce the element

Example:
  Node A: remove("apple") → remove_set = {apple}
  Node B: add("apple")    → add_set = {apple}
  
  Merge: add_set = {apple}, remove_set = {apple}
         visible = add_set ∖ remove_set = {}  // Empty — correct!
  
  Without remove_set:
    Merge: add_set = {apple}, remove_set = {}
           visible = {apple}  // Wrong! ❌
```

#### RGA (Type 0x06)

```plaintext
Internal structure:
  nodes: LinkedList<RGANode>
  each node: {id, content, prev_id, deleted}

A deleted node must persist because:
  - Other nodes may have inserted after it
  - Removing it would break the linked list
  - The prev pointers of subsequent nodes reference it

Example:
  Node A: insert "X" after "Hello" → node X1
  Node B: insert "Y" after X1      → node Y1 (prev = X1)
  Node A: delete X1                → X1.deleted = true
  
  If X1 were removed:
    Y1.prev = X1 → dangling reference ❌
  
  With X1 as tombstone:
    Y1.prev = X1 → valid reference (X1 is deleted but exists)
    Traversal skips X1, goes to Y1 → correct ✅
```

---

## 2. Unified Compaction Interface

### 2.1 Compaction VTable

Every tombstone-bearing type implements this interface:

```c
typedef struct crabs_compaction_vtable {
    // Type identification
    uint8_t type_id;                // e.g., 0x03 for OR-Set
    const char *type_name;          // e.g., "OR_SET"
    
    // === Required Operations ===
    
    // Extract the user-visible value, hiding all tombstones
    // Returns a fresh value with no tombstone references
    crabs_value_t (*extract_visible)(const void *item);
    
    // Rebuild a fresh data item from a visible value
    // The new item has NO tombstones
    void *(*rebuild_from_visible)(crabs_value_t visible);
    
    // Count tombstones in the current item
    uint64_t (*count_tombstones)(const void *item);
    
    // Count visible elements in the current item
    uint64_t (*count_visible)(const void *item);
    
    // === Optional Operations ===
    
    // Check if compaction is safe for this specific item
    // (Default: check vector clock across all peers)
    bool (*compaction_safe)(const void *item, const crabs_state_t *state);
    
    // Estimate memory savings from compaction
    // (Used by the scheduler to prioritize which items to compact)
    uint64_t (*estimated_savings)(const void *item);
    
    // Human-readable description of the item's tombstone state
    // (For logging and debugging)
    void (*describe_tombstones)(const void *item, char *buf, size_t buf_len);
    
} crabs_compaction_vtable_t;
```

### 2.2 VTable Registry

```c
// Global registry of compaction vtables
static crabs_compaction_vtable_t *compaction_registry[256];

// Register a compaction vtable for a type
int crabs_register_compaction(crabs_compaction_vtable_t *vtable) {
    if (compaction_registry[vtable->type_id] != NULL) {
        return CRABS_ERR_ALREADY_REGISTERED;
    }
    compaction_registry[vtable->type_id] = vtable;
    return CRABS_SUCCESS;
}

// Look up the compaction vtable for a type
crabs_compaction_vtable_t *crabs_get_compaction_vtable(uint8_t type_id) {
    return compaction_registry[type_id];
}

// Check if a type supports compaction
bool crabs_type_supports_compaction(uint8_t type_id) {
    return compaction_registry[type_id] != NULL;
}
```

### 2.3 Registration at Initialization

```c
int crabs_global_init(void) {
    // ... existing initialization ...
    
    // Register compaction vtables for all tombstone-bearing types
    crabs_register_compaction(&crabs_or_set_compaction);
    crabs_register_compaction(&crabs_two_phase_set_compaction);
    crabs_register_compaction(&crabs_rga_compaction);
    crabs_register_compaction(&crabs_ot_ordered_set_compaction);
    crabs_register_compaction(&crabs_ot_document_compaction);
    crabs_register_compaction(&crabs_ot_tree_compaction);
    
    return CRABS_SUCCESS;
}
```

---

## 3. Compaction Algorithms for Non-OT Types

### 3.1 OR-Set Compaction

```c
/*
 * OR-Set compaction:
 *   1. Compute visible = elements ∖ tombstones
 *   2. For each visible element, re-add with a FRESH tag
 *   3. Discard all old tombstones
 */

static crabs_value_t or_set_extract_visible(const void *item) {
    const crabs_or_set_t *set = (const crabs_or_set_t *)item;
    crabs_value_t result;
    result.type = CRABS_VALUE_SET;
    result.set.count = 0;
    
    for (uint32_t i = 0; i < set->elements.count; i++) {
        crabs_tagged_element_t *el = &set->elements.items[i];
        
        // Check if this element's tag is in the tombstone set
        bool is_tombstoned = false;
        for (uint32_t j = 0; j < set->tombstones.count; j++) {
            if (crabs_tag_equal(&el->tag, &set->tombstones.items[j])) {
                is_tombstoned = true;
                break;
            }
        }
        
        if (!is_tombstoned) {
            // Add to visible set (just the value, not the old tag)
            crabs_set_add(&result.set, el->value);
        }
    }
    
    return result;
}

static void *or_set_rebuild_from_visible(crabs_value_t visible) {
    crabs_or_set_t *fresh = crabs_or_set_new();
    
    for (uint32_t i = 0; i < visible.set.count; i++) {
        // Re-add with a FRESH tag
        crabs_or_set_add(fresh, visible.set.items[i]);
    }
    
    // Tombstones are empty — all elements have fresh tags
    // fresh->tombstones is already initialized to empty
    
    return fresh;
}

static uint64_t or_set_count_tombstones(const void *item) {
    const crabs_or_set_t *set = (const crabs_or_set_t *)item;
    return set->tombstones.count;
}

static uint64_t or_set_count_visible(const void *item) {
    const crabs_or_set_t *set = (const crabs_or_set_t *)item;
    return set->elements.count - set->tombstones.count;
}

crabs_compaction_vtable_t crabs_or_set_compaction = {
    .type_id = 0x03,
    .type_name = "OR_SET",
    .extract_visible = or_set_extract_visible,
    .rebuild_from_visible = or_set_rebuild_from_visible,
    .count_tombstones = or_set_count_tombstones,
    .count_visible = or_set_count_visible,
    .compaction_safe = NULL,  // Use default (vector clock check)
    .estimated_savings = NULL,
    .describe_tombstones = NULL
};
```

### 3.2 2P-Set Compaction

```c
/*
 * 2P-Set compaction:
 *   1. Compute visible = add_set ∖ remove_set
 *   2. Create fresh 2P-Set with visible elements in add_set
 *   3. remove_set is empty (all removed elements are gone)
 *   
 *   NOTE: This changes the semantics slightly.
 *   After compaction, removed elements CAN be re-added
 *   (because the remove_set is empty).
 *   This is the SAFETY TRADEOFF of 2P-Set compaction.
 */

static crabs_value_t two_phase_set_extract_visible(const void *item) {
    const crabs_two_phase_set_t *set = (const crabs_two_phase_set_t *)item;
    crabs_value_t result;
    result.type = CRABS_VALUE_SET;
    result.set.count = 0;
    
    for (uint32_t i = 0; i < set->add_set.count; i++) {
        const char *element = set->add_set.items[i];
        
        // Check if element is in the remove set
        bool is_removed = false;
        for (uint32_t j = 0; j < set->remove_set.count; j++) {
            if (strcmp(element, set->remove_set.items[j]) == 0) {
                is_removed = true;
                break;
            }
        }
        
        if (!is_removed) {
            crabs_set_add(&result.set, element);
        }
    }
    
    return result;
}

static void *two_phase_set_rebuild_from_visible(crabs_value_t visible) {
    crabs_two_phase_set_t *fresh = crabs_two_phase_set_new();
    
    // Add all visible elements to the add_set
    for (uint32_t i = 0; i < visible.set.count; i++) {
        crabs_two_phase_set_add(fresh, visible.set.items[i]);
    }
    
    // remove_set is empty
    // WARNING: After compaction, previously removed elements
    // CAN be re-added. This is a semantic change.
    
    return fresh;
}

static uint64_t two_phase_set_count_tombstones(const void *item) {
    const crabs_two_phase_set_t *set = (const crabs_two_phase_set_t *)item;
    return set->remove_set.count;
}

static uint64_t two_phase_set_count_visible(const void *item) {
    const crabs_two_phase_set_t *set = (const crabs_two_phase_set_t *)item;
    return set->add_set.count - set->remove_set.count;
}

crabs_compaction_vtable_t crabs_two_phase_set_compaction = {
    .type_id = 0x04,
    .type_name = "2P_SET",
    .extract_visible = two_phase_set_extract_visible,
    .rebuild_from_visible = two_phase_set_rebuild_from_visible,
    .count_tombstones = two_phase_set_count_tombstones,
    .count_visible = two_phase_set_count_visible,
    .compaction_safe = NULL,
    .estimated_savings = NULL,
    .describe_tombstones = NULL
};
```

### 3.3 RGA Compaction

```c
/*
 * RGA compaction:
 *   1. Walk the linked list, collecting visible characters
 *   2. Create a fresh RGA with only visible characters
 *   3. No deleted nodes — all tombstones removed
 */

static crabs_value_t rga_extract_visible(const void *item) {
    const crabs_rga_t *doc = (const crabs_rga_t *)item;
    crabs_value_t result;
    result.type = CRABS_VALUE_STRING;
    result.string.len = 0;
    
    // Walk the linked list
    crabs_rga_node_t *current = doc->head;
    while (current != NULL) {
        if (!current->deleted) {
            // Append character to result
            result.string.data[result.string.len++] = current->content;
        }
        current = current->next;
    }
    result.string.data[result.string.len] = '\0';
    
    return result;
}

static void *rga_rebuild_from_visible(crabs_value_t visible) {
    crabs_rga_t *fresh = crabs_rga_new();
    
    // Insert each character at the end
    for (uint32_t i = 0; i < visible.string.len; i++) {
        crabs_rga_insert_at_end(fresh, visible.string.data[i]);
    }
    
    // No deleted nodes — all tombstones removed
    // fresh->head has no deleted flags set
    
    return fresh;
}

static uint64_t rga_count_tombstones(const void *item) {
    const crabs_rga_t *doc = (const crabs_rga_t *)item;
    uint64_t count = 0;
    
    crabs_rga_node_t *current = doc->head;
    while (current != NULL) {
        if (current->deleted) {
            count++;
        }
        current = current->next;
    }
    
    return count;
}

static uint64_t rga_count_visible(const void *item) {
    const crabs_rga_t *doc = (const crabs_rga_t *)item;
    uint64_t count = 0;
    
    crabs_rga_node_t *current = doc->head;
    while (current != NULL) {
        if (!current->deleted) {
            count++;
        }
        current = current->next;
    }
    
    return count;
}

crabs_compaction_vtable_t crabs_rga_compaction = {
    .type_id = 0x06,
    .type_name = "RGA",
    .extract_visible = rga_extract_visible,
    .rebuild_from_visible = rga_rebuild_from_visible,
    .count_tombstones = rga_count_tombstones,
    .count_visible = rga_count_visible,
    .compaction_safe = NULL,
    .estimated_savings = NULL,
    .describe_tombstones = NULL
};
```

---

## 4. Unified Compaction Engine

### 4.1 The Core Algorithm

```c
Algorithm: COMPACT_ITEM

Input:
  item  — Any tombstone-bearing data item
  state — Current CRABS state (for peer tracking)
  force — Whether to bypass safety checks

Output:
  compacted — Compacted item, or NULL if not safe

1. // Get the compaction vtable for this type
2. vtable = GET_COMPACTION_VTABLE(item->type)
3. if vtable == NULL:
4.     LOG(state, "Compaction not supported for type %d", item->type)
5.     return NULL

6. // Count current state
7. tombstone_count = vtable->count_tombstones(item)
8. visible_count = vtable->count_visible(item)
9. 
10. if tombstone_count == 0:
11.     return item  // Nothing to compact

12. // Check safety
13. if not force:
14.     if vtable->compaction_safe != NULL:
15.         safe = vtable->compaction_safe(item, state)
16.     else:
17.         safe = CHECK_DEFAULT_COMPACTION_SAFETY(state)
18.     
19.     if not safe:
20.         LOG(state, "Compaction not safe for %s: peers not synchronized",
21.             item->name)
22.         return NULL

23. // Extract visible value
24. visible = vtable->extract_visible(item)

25. // Rebuild from visible value
26. compacted = vtable->rebuild_from_visible(visible)

27. // Preserve metadata
28. compacted->name = item->name
29. compacted->last_compaction_time = now()

30. // Log
31. LOG(state, {
         type: "__compaction__",
         item_name: item->name,
         item_type: item->type,
         previous_tombstones: tombstone_count,
         previous_visible: visible_count,
         new_tombstones: 0,
         new_visible: vtable->count_visible(compacted),
         forced: force
     })

32. return compacted
```

### 4.2 Default Safety Check

```c
Algorithm: CHECK_DEFAULT_COMPACTION_SAFETY

Input:
  state — Current CRABS state

Output:
  safe — Whether compaction is safe

1. // Get the maximum sequence number produced by each node
2. for each node_id in state.nodes:
3.     max_seq[node_id] = state.node_max_sequence[node_id]

4. // Check that every peer has seen every operation
5. for each peer_id in state.peers:
6.     for each node_id in state.nodes:
7.         observed = state.peers[peer_id].vector_clock[node_id]
8.         if observed < max_seq[node_id]:
9.             LOG(state, "Peer %s has not seen operation %d from node %s "
10.                       "(max is %d)", peer_id, observed, node_id, max_seq[node_id])
11.            return false

12. return true
```

### 4.3 Periodic Compaction Scheduler

```c
Algorithm: PERIODIC_COMPACTION

Input:
  state — Current CRABS state

// Called on a timer (configurable interval)

1. for each (name, item) in state.items:
2.     // Skip types that don't support compaction
3.     vtable = GET_COMPACTION_VTABLE(item->type)
4.     if vtable == NULL:
5.         continue
6.     
7.     // Count tombstones
8.     tombstone_count = vtable->count_tombstones(item)
9.     if tombstone_count == 0:
10.        continue
11.    
12.    visible_count = vtable->count_visible(item)
13.    ratio = tombstone_count / max(visible_count, 1)
14.    
15.    // Check compaction triggers
16.    should_compact = false
17.    
18.    // Size-based trigger
19.    if ratio > state.config.tombstone.max_ratio:
20.        should_compact = true
21.    
22.    // Time-based trigger
23.    if state.config.tombstone.strategy == TIME_BASED:
24.        if now() - item.last_compaction_time > 
25.           state.config.tombstone.compaction_interval_ms:
26.            should_compact = true
27.    
28.    // Emergency trigger
29.    if tombstone_count > state.config.tombstone.emergency_count:
30.        should_compact = true
31.        LOG(state, "EMERGENCY: %s has %d tombstones, forcing compaction",
32.            name, tombstone_count)
33.    
34.    if should_compact:
35.        compacted = COMPACT_ITEM(item, state, 
36.                                 tombstone_count > state.config.tombstone.emergency_count)
37.        if compacted != NULL:
38.            state.items[name] = compacted
39.            FREE_ITEM(item)  // Release old memory
```

---

## 5. Safety Considerations by Type

### 5.1 OR-Set Safety

```plaintext
After compaction:
  - All visible elements have FRESH tags
  - Old tombstones are gone

Risks:
  - A delayed remove operation referencing an OLD tag
    will be a no-op (tag doesn't exist in compacted set)
  - The element that was removed will reappear

Mitigation:
  - Only compact when all peers are synchronized
  - The window for delayed operations is bounded by
    the time between the last operation and compaction
```

### 5.2 2P-Set Safety

```plaintext
After compaction:
  - Visible elements are in the add_set
  - remove_set is EMPTY

Risks:
  - Elements that were removed BEFORE compaction
    can now be re-added (2P-Set guarantee is lost)
  - This is a SEMANTIC CHANGE

Mitigation:
  - 2P-Set compaction should be used with EXTREME caution
  - Only compact when the set's "no re-add" guarantee
    is no longer needed
  - Document in the compaction log which elements were
    permanently forgotten
  - Consider using ONE_SHOT_SET instead if the
    "no re-add" guarantee is critical
```

### 5.3 RGA Safety

```plaintext
After compaction:
  - All deleted nodes are removed
  - The linked list is rebuilt from scratch

Risks:
  - A delayed insert that referenced a deleted node's ID
    as its predecessor will have a dangling reference
  - The insert will be placed at the end of the document
    (fallback behavior)

Mitigation:
  - Only compact when all peers are synchronized
  - RGA compaction preserves document content exactly
  - Only the internal node IDs change
```

### 5.4 Summary Table

```plaintext
┌──────────┬────────────────────────────────┬──────────────────────────┐
│   Type   │   What Changes After Compact   │   Risk if Not Synced     │
├──────────┼────────────────────────────────┼──────────────────────────┤
│ OR-Set   │ Elements get fresh tags        │ Delayed remove becomes   │
│          │ Old tombstones discarded       │ no-op, element reappears │
├──────────┼────────────────────────────────┼──────────────────────────┤
│ 2P-Set   │ remove_set emptied             │ Previously removed       │
│          │                                │ elements can be re-added │
├──────────┼────────────────────────────────┼──────────────────────────┤
│ RGA      │ Deleted nodes removed          │ Delayed insert with old  │
│          │ Linked list rebuilt            │ prev ID goes to end      │
├──────────┼────────────────────────────────┼──────────────────────────┤
│ OT types │ Position map emptied           │ xi/xi_inv computed       │
│          │ Coordinate space reset         │ against wrong map        │
└──────────┴────────────────────────────────┴──────────────────────────┘
```

---

## 6. Configuration

### 6.1 Unified Tombstone Configuration

```c
typedef struct {
    // Compaction strategy
    crabs_compaction_strategy_t strategy;  // NONE, TIME_BASED, SIZE_BASED,
                                           // QUORUM, HYBRID
    
    // Size-based: compact when tombstone ratio exceeds this
    // Applied to ALL tombstone-bearing types
    float max_tombstone_ratio;             // Default: 10.0
    
    // Per-type overrides (indexed by type_id)
    struct {
        float max_tombstone_ratio;         // Override for specific type
    } per_type[256];
    
    // Time-based: compact every N milliseconds
    uint64_t compaction_interval_ms;       // Default: 86400000 (24h)
    
    // Quorum: fraction of peers that must acknowledge
    float quorum_threshold;                // Default: 1.0 (all peers)
    
    // Emergency: force compact when tombstone count exceeds this
    uint64_t emergency_tombstone_count;    // Default: 1000000
    
    // Whether to allow force compaction
    bool allow_force;                      // Default: false
    
    // Whether to log compaction events
    bool verbose_logging;                  // Default: false
    
} crabs_tombstone_config_t;
```

### 6.2 Recommended Defaults by Deployment

```plaintext
General purpose:
  strategy: HYBRID
  max_tombstone_ratio: 10.0
  compaction_interval_ms: 86400000  (24h)
  quorum_threshold: 1.0
  emergency_tombstone_count: 1000000
  allow_force: false

High-throughput (many edits):
  strategy: SIZE_BASED
  max_tombstone_ratio: 5.0
  per_type[0x03].max_tombstone_ratio: 20.0  // OR-Set: tolerate more
  per_type[0x06].max_tombstone_ratio: 3.0   // RGA: compact more often
  emergency_tombstone_count: 500000

Resource-constrained (mobile):
  strategy: SIZE_BASED
  max_tombstone_ratio: 20.0  // Tolerate more to avoid compaction CPU
  emergency_tombstone_count: 50000

Append-only (few deletes):
  strategy: TIME_BASED
  compaction_interval_ms: 604800000  (7 days)
  max_tombstone_ratio: 50.0  // Rarely triggers
```

---

## 7. Integration with Existing Spec

### 7.1 Modified State Serialization

The state serialization format is updated to include `last_compaction_time` for each data item:

```c
DataItemSerialized = {
    // ... existing fields ...
    
    // NEW: Compaction metadata
    last_compaction_time: uint64,    // 0 = never compacted
    tombstone_count_at_serialization: uint32,  // For diagnostics
}
```

### 7.2 New Built-in Operation

```c
/*
 * __compact__ operation
 *
 * Manually trigger compaction on a specific item.
 * Requires admin-level policy.
 */

Operation = {
    type: "__compact__",
    payload: {
        item_name: "document_42",
        force: false                    // Bypass safety check?
    },
    policy: "role:admin",
    signature: {...}
}
```

### 7.3 New Error Codes

```c
#define CRABS_ERR_COMPACTION_NOT_SUPPORTED  -0x7001
#define CRABS_ERR_COMPACTION_NOT_SAFE       -0x7002
#define CRABS_ERR_COMPACTION_IN_PROGRESS    -0x7003
```

---

## 8. Test Vectors

### 8.1 OR-Set Compaction

```plaintext
Setup:
  - OR-Set with elements:
      {("apple", tag_A1), ("banana", tag_B1), ("cherry", tag_C1)}
  - Tombstones: {tag_A1}  ("apple" was removed)
  - Visible: {banana, cherry}

Compaction:
  - Extract visible: {banana, cherry}
  - Rebuild: fresh OR-Set with:
      {("banana", tag_B2), ("cherry", tag_C2)}
  - Tombstones: {} (empty)

After compaction:
  - Contains "banana"? ✅ Yes (tag_B2)
  - Contains "cherry"? ✅ Yes (tag_C2)
  - Contains "apple"? ❌ No (was removed, not re-added)
  
  - Add "apple": creates tag_A3
  - Contains "apple"? ✅ Yes (tag_A3) — correct, it's a new add
```

### 8.2 RGA Compaction

```plaintext
Setup:
  - RGA document: "Hello" (H, e, l, l, o)
  - Delete 'l' at position 2 → node deleted
  - Delete 'o' at position 4 → node deleted
  - Visible: "Hel" (H, e, l)

Compaction:
  - Extract visible: "Hel"
  - Rebuild: fresh RGA with nodes:
      {id: R1, content: 'H', prev: null, deleted: false}
      {id: R2, content: 'e', prev: R1, deleted: false}
      {id: R3, content: 'l', prev: R2, deleted: false}
  - No deleted nodes

After compaction:
  - Content: "Hel" ✅
  - Insert 'p' at end: "Help" ✅
  - Delete 'e': "Hlp" ✅
```

### 8.3 Unsafe Compaction Detection

```plaintext
Setup:
  - Three peers: A, B, C
  - Peer C has been offline (missed operations 50-100 from A)

Vector clocks:
  A: {A: 100, B: 80, C: 30}
  B: {A: 100, B: 80, C: 30}
  C: {A: 50, B: 80, C: 30}  // Missing A:51-100

Compaction safety check:
  for each node in {A, B, C}:
    max_seq[A] = 100, max_seq[B] = 80, max_seq[C] = 30
    
    Check peer C:
      C.vector_clock[A] = 50 < max_seq[A] = 100 → NOT SAFE ❌

Result:
  - Compaction deferred
  - Waiting for peer C to sync
  - Once C's clock shows A:100, compaction proceeds
```

---

## 9. Summary

### 9.1 Types Now Covered by Compaction

Type	Before v1.5.2	After v1.5.2
`COUNTER`	N/A	N/A
`PN_COUNTER`	N/A	N/A
`SET` (OR-Set)	❌ Not covered	✅ Covered
`2P_SET`	❌ Not covered	✅ Covered (with caveats)
`REGISTER`	N/A	N/A
`DOCUMENT` (RGA)	❌ Not covered	✅ Covered
`RESOURCE`	N/A	N/A
`ONE_SHOT_SET`	N/A	N/A
`ONE_SHOT_FLAG`	N/A	N/A
`OT_ORDERED_SET`	✅ Covered	✅ Covered
`OT_DOCUMENT`	✅ Covered	✅ Covered
`OT_TREE`	✅ Covered	✅ Covered

### 9.2 What This Addendum Adds

Section	Content
§1	Complete tombstone inventory for all types
§2	Unified compaction vtable interface
§3	Compaction algorithms for OR-Set, 2P-Set, RGA
§4	Unified compaction engine (shared with OT types)
§5	Safety considerations per type
§6	Unified configuration
§7	Integration with existing spec
§8	Test vectors
