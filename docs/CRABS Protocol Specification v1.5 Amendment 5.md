# CRABS Protocol Specification v1.5 — Amendment 5

## *OT/CRDT Hybrid Types: Expressive Convergent Data Structures*

---

**Amendment Status:** Draft  
**Spec Version:** 1.5.0  
**Date:** April 30, 2026  
**Supersedes:** Base spec §5 (Data Types), §12 (CRDT Merge Rules)

---

## Preamble

The base CRABS protocol defines a set of Conflict-free Replicated Data Types (CRDTs) — counters, sets, registers, and RGA documents — that converge without coordination. These types are simple, efficient, and sufficient for many applications. However, they have **limited expressiveness**: they cannot represent ordered structures with move, swap, or reorder operations, and they may lose user intent under complex concurrent edits.

Raph Levien's work on the synthesis of Operational Transformation (OT) and CRDTs demonstrates that **the transform function is the heart of the system**. By carrying a transform function with each operation and maintaining a causal context, we can build data structures that are both **convergent** (CRDT property) and **expressive** (OT property).

This amendment introduces a new family of data types — **OT/CRDT Hybrid Types** — that use Levien's approach to support insert, delete, move, swap, and transform operations on ordered structures, while preserving the convergence guarantees of CRDTs.

---

## 1. Motivation

### 1.1 Limitations of Basic CRDTs

Operation	G-Counter	OR-Set	LWW-Register	RGA
Increment	✅	❌	❌	❌
Add element	❌	✅	❌	❌
Remove element	❌	✅	❌	❌
Insert at position	❌	❌	❌	✅
Delete at position	❌	❌	❌	✅
**Move element**	❌	❌	❌	❌
**Swap elements**	❌	❌	❌	❌
**Reorder**	❌	❌	❌	❌
**Transform against concurrent ops**	❌	❌	❌	❌

### 1.2 Use Cases Requiring Expressiveness

```plaintext
Playlist management:
  - Move song from position 5 to position 2
  - Swap two songs
  - Concurrent reorderings must converge

Document editing:
  - Move paragraph from page 3 to page 1
  - Merge two sections
  - Concurrent moves and edits must preserve intent

Kanban board:
  - Move card from "In Progress" to "Done"
  - Reorder cards within a column
  - Concurrent moves by different users

File system:
  - Move file from /documents to /archive
  - Rename directory
  - Concurrent moves must not lose files
```

### 1.3 The Levien Approach

Raph Levien's `ot_toy.js` demonstrates three key insights:

1. **Position in visible coordinates**: Operations reference positions in the user-visible structure, not internal indices. A balanced BST maps between visible and internal coordinates, handling deletions and insertions transparently.

2. **Transform functions**: Every operation carries a transform function that adjusts its position against any concurrent operation. The transform is deterministic and commutative after application.

3. **Priority-based ordering**: Concurrent inserts at the same position are ordered deterministically by a priority value (node_id + sequence number), ensuring all peers converge to the same order.

---

## 2. Theoretical Foundation

### 2.1 Coordinate Spaces

Every OT/CRDT hybrid type maintains two coordinate spaces:

```plaintext
Internal coordinates: The full structure, including deleted or hidden elements.
  [0] [1] [2] [3] [4] [5] [6] [7] [8] [9]
   A   B   C   D   E   F   G   H   I   J
                    ↑ deleted

Visible coordinates: What users see and reference in operations.
  [0] [1] [2] [3] [4] [5] [6] [7] [8]
   A   B   C   D   F   G   H   I   J
                    ↑ 'E' is hidden
```

The mapping between spaces is maintained by a **position map** — a balanced BST that tracks all deleted or inserted positions:

```plaintext
xi(tree, internal_pos) → visible_pos       // Internal → visible
xi_inv(tree, visible_pos) → internal_pos   // Visible → internal
```

### 2.2 Operation Types

Every OT/CRDT hybrid type defines a set of operation types. The minimum set for ordered structures is:

```plaintext
INSERT(pos, payload, priority)  // Insert at visible position
DELETE(pos)                     // Delete at visible position
UPDATE(pos, new_payload)        // Update element at visible position
MOVE(from_pos, to_pos)          // Move element from one position to another
SWAP(pos_a, pos_b)              // Swap two elements
```

### 2.3 The Transform Function

The transform function `T(op_a, op_b)` adjusts `op_a` to account for the effect of `op_b`, assuming both are concurrent (neither causally precedes the other).

```plaintext
Property: T(T(op_a, op_b), op_c) = T(T(op_a, op_c), op_b)
          (Commutativity of transformed operations)

Property: apply(apply(state, T(op_a, op_b)), T(op_b, op_a)) =
          apply(apply(state, T(op_b, op_a)), T(op_a, op_b))
          (Convergence regardless of application order)
```

### 2.4 Priority

Each insert operation carries a **priority** value that provides deterministic ordering for concurrent inserts at the same position:

```plaintext
priority = (node_timestamp << 48) | (node_id_hash & 0xFFFF)
          | (sequence_number << 32)

// Higher priority inserts before lower priority at the same position
// Priority is unique across all nodes (node_id ensures uniqueness)
```

---

## 3. New Data Type Family

### 3.1 Type Identifiers

```plaintext
OT/CRDT Hybrid Types (0x10-0x1F):

0x10: OT_ORDERED_SET    — Ordered set with insert, delete, move, swap
0x11: OT_DOCUMENT       — Rich document with insert, delete, move, merge, split
0x12: OT_TABLE          — 2D table with row/column insert, delete, move
0x13: OT_TREE           — Tree with insert, delete, reparent, reorder
0x14: OT_ORDERED_MAP    — Ordered key-value map with insert, delete, reorder
0x15-0x1F: Reserved for future OT/CRDT types
```

### 3.2 Common Structure

Every OT/CRDT hybrid type shares this structure:

```plaintext
OTDataItem = {
    // Type identification
    ot_type_id: uint8,              // 0x10-0x1F
    ot_type_version: uint8,         // For schema evolution
    
    // The visible value (what operations reference)
    visible_value: any,
    
    // The full value (including hidden/deleted elements)
    full_value: any,
    
    // Position map (BST mapping internal ↔ visible coordinates)
    position_map: PositionMap,
    
    // Operation log (for transform context)
    op_log: OTOperation[],
    op_log_count: uint32,
    
    // Per-node priority counters
    priority_counters: {
        "<node_id>": uint64,
        ...
    },
    
    // Transform matrix for this type
    transform_matrix: TransformEntry[N_OP_TYPES × N_OP_TYPES]
}
```

### 3.3 Position Map

```plaintext
PositionMap = {
    // Size-balanced BST node
    root: PositionMapNode
}

PositionMapNode = {
    left: PositionMapNode,
    right: PositionMapNode,
    value: uint64,          // Internal position value
    size: uint32,           // Subtree node count
    height: uint32,         // For AVL balancing
    deleted: bool           // Whether this position is deleted
}
```

**Operations:**

```plaintext
xi(map, internal_pos) → visible_pos
  // Walk the BST, subtracting deleted positions before the given index
  // Returns the visible position

xi_inv(map, visible_pos) → internal_pos
  // Walk the BST, adding deleted positions before the given index
  // Returns the internal position

union_one(map, internal_pos)
  // Mark an internal position as deleted
  // Insert into BST if not already present

xi_one(map, internal_pos)
  // Shift all positions >= internal_pos by +1
  // Used when inserting new content
```

### 3.4 Operation Structure

```plaintext
OTOperation = {
    // Identity
    id: OTOpId,                 // Unique, monotonic, causally ordered
    
    // Type
    op_type: OTOpType,          // INSERT, DELETE, UPDATE, MOVE, SWAP
    
    // Position in VISIBLE coordinates
    visible_pos: uint64,
    
    // Secondary position (for MOVE destination, SWAP second position)
    visible_pos_2: uint64,
    
    // Payload
    payload: byte[],
    payload_len: uint32,
    
    // Priority (for deterministic ordering of concurrent inserts)
    priority: uint64,
    
    // Causal context — which operations this depends on
    deps: OTOpId[],
    dep_count: uint32,
    
    // Transform function reference
    transform_fn_id: uint16     // Index into the type's transform matrix
}

OTOpId = {
    node_id: uint64,            // Originating node
    sequence_num: uint64,       // Per-node monotonic sequence
    timestamp: uint64           // Wall clock (for display, not causality)
}
```

### 3.5 Transform Matrix

```plaintext
TransformMatrix = {
    entries: TransformEntry[N_OP_TYPES][N_OP_TYPES],
    n_types: uint8
}

TransformEntry = {
    // Transform op_a (row) against op_b (column)
    // Returns adjusted op_a
    transform_fn: function(OTOperation op_a, OTOperation op_b) → OTOperation,
    
    // Description of the transform (for documentation)
    description: string
}
```

---

## 4. The Transform Matrix for Ordered Structures

### 4.1 Full Matrix

```plaintext
              | INSERT(j,p)  | DELETE(j)   | UPDATE(j,v) | MOVE(j→k)   | SWAP(j,k)
──────────────┼──────────────┼──────────────┼──────────────┼──────────────┼──────────────
INSERT(i,q)   | priority_cmp | shift_left   | no_change    | shift_left   | shift_left
              | T1           | if i > j     |              | if i > j     | if i > min(j,k)
──────────────┼──────────────┼──────────────┼──────────────┼──────────────┼──────────────
DELETE(i)     | shift_right   | no_conflict  | no_change    | adjust_src   | adjust_src
              | if i >= j    | (same pos)   |              | if i > j     | if i in {j,k}
──────────────┼──────────────┼──────────────┼──────────────┼──────────────┼──────────────
UPDATE(i,v)   | shift_right   | shift_left   | last_write   | shift_left   | shift_left
              | if i >= j    | if i > j     | wins         | if i > j     | if i in {j,k}
──────────────┼──────────────┼──────────────┼──────────────┼──────────────┼──────────────
MOVE(i→l)     | shift_right   | shift_left   | no_change    | composite    | composite
              | if i >= j    | if i > j     |              | T4           | T5
if l >= j	if l > j		
──────────────┼──────────────┼──────────────┼──────────────┼──────────────┼──────────────
SWAP(i1,i2)   | shift_right   | shift_left   | no_change    | composite    | composite
              | if i1 >= j   | if i1 > j    |              | T6           | T7
if i2 >= j	if i2 > j		
```

### 4.2 Individual Transform Functions

#### T1: INSERT vs INSERT

```plaintext
Algorithm: TRANSFORM_INSERT_VS_INSERT

Input:
  ins_a — INSERT operation being transformed
  ins_b — Concurrent INSERT operation

Output:
  ins_a' — Adjusted INSERT operation

1. if ins_a.visible_pos < ins_b.visible_pos:
       return ins_a  // ins_a is before ins_b, no adjustment

2. if ins_a.visible_pos == ins_b.visible_pos:
       if ins_a.priority < ins_b.priority:
           return ins_a  // ins_a has lower priority, stays before
       else:
           ins_a.visible_pos += 1  // ins_a has higher priority, shifts right
           return ins_a

3. // ins_a.visible_pos > ins_b.visible_pos
4. ins_a.visible_pos += 1  // Shift right for ins_b's insertion
5. return ins_a
```

#### T2: DELETE vs INSERT

```plaintext
Algorithm: TRANSFORM_DELETE_VS_INSERT

Input:
  del — DELETE operation being transformed
  ins — Concurrent INSERT operation

Output:
  del' — Adjusted DELETE operation

1. if del.visible_pos < ins.visible_pos:
       return del  // Delete is before insert, no adjustment

2. // Delete is at or after insert — shift right
3. del.visible_pos += 1
4. return del
```

#### T3: INSERT vs DELETE

```plaintext
Algorithm: TRANSFORM_INSERT_VS_DELETE

Input:
  ins — INSERT operation being transformed
  del — Concurrent DELETE operation

Output:
  ins' — Adjusted INSERT operation

1. if ins.visible_pos <= del.visible_pos:
       return ins  // Insert is before or at delete, no adjustment

2. // Insert is after delete — shift left
3. ins.visible_pos -= 1
4. return ins
```

#### T4: MOVE vs MOVE (Composite)

```plaintext
Algorithm: TRANSFORM_MOVE_VS_MOVE

Input:
  move_a — MOVE operation being transformed (source → dest)
  move_b — Concurrent MOVE operation (source_b → dest_b)

Output:
  move_a' — Adjusted MOVE operation

// A MOVE is decomposed into DELETE(source) + INSERT(dest, element)
// Each component is transformed separately

1. // Transform move_a's source against move_b
2. temp_delete = {type: DELETE, visible_pos: move_a.source_pos}
3. temp_delete = TRANSFORM_DELETE_VS_MOVE(temp_delete, move_b)
4. move_a.source_pos = temp_delete.visible_pos

5. // Transform move_a's destination against move_b
6. temp_insert = {type: INSERT, visible_pos: move_a.dest_pos, ...}
7. temp_insert = TRANSFORM_INSERT_VS_MOVE(temp_insert, move_b)
8. move_a.dest_pos = temp_insert.visible_pos

9. // Handle the case where move_a's source was affected by move_b's source
10. if move_b.source_pos < move_a.source_pos:
        move_a.source_pos -= 1  // move_b removed an element before move_a's source

11. if move_b.source_pos < move_a.dest_pos:
        move_a.dest_pos -= 1  // move_b removed an element before move_a's dest

12. return move_a
```

#### T5: SWAP vs INSERT

```plaintext
Algorithm: TRANSFORM_SWAP_VS_INSERT

Input:
  swap — SWAP operation being transformed (pos_a, pos_b)
  ins  — Concurrent INSERT operation

Output:
  swap' — Adjusted SWAP operation

1. if swap.pos_a >= ins.visible_pos:
       swap.pos_a += 1
2. if swap.pos_b >= ins.visible_pos:
       swap.pos_b += 1
3. return swap
```

#### T6: SWAP vs DELETE

```plaintext
Algorithm: TRANSFORM_SWAP_VS_DELETE

Input:
  swap — SWAP operation being transformed (pos_a, pos_b)
  del  — Concurrent DELETE operation

Output:
  swap' — Adjusted SWAP operation

1. if swap.pos_a > del.visible_pos:
       swap.pos_a -= 1
2. if swap.pos_b > del.visible_pos:
       swap.pos_b -= 1
3. 
4. // If one of the swapped elements was deleted, the swap becomes a no-op
5. // (the deleted element is gone, so there's nothing to swap)
6. if swap.pos_a == del.visible_pos or swap.pos_b == del.visible_pos:
       return NULL  // No-op
7.
8. return swap
```

---

## 5. New Data Type: OT_ORDERED_SET (Type 0x10)

### 5.1 Definition

```plaintext
OT_ORDERED_SET = {
    // Inherits from OTDataItem
    ot_type_id: 0x10,
    
    // Elements stored as a doubly-linked list with unique IDs
    elements: OrderedElement[],
    
    // Position map for visible ↔ internal coordinate mapping
    position_map: PositionMap,
    
    // Operation log
    op_log: OTOperation[],
    
    // Transform matrix for ordered set operations
    transform_matrix: TransformMatrix
}

OrderedElement = {
    id: string,              // Unique element identifier
    value: any,              // The element's data
    prev_id: string,         // Previous element ID (for ordering)
    next_id: string          // Next element ID (for ordering)
}
```

### 5.2 Operations

```plaintext
INSERT(pos, element, priority)
  // Insert element at visible position pos
  // priority determines ordering against concurrent inserts at same pos

DELETE(pos)
  // Delete element at visible position pos

UPDATE(pos, new_value)
  // Update the value of element at visible position pos

MOVE(from_pos, to_pos)
  // Move element from from_pos to to_pos
  // Decomposed into DELETE(from) + INSERT(to, element)

SWAP(pos_a, pos_b)
  // Swap elements at positions pos_a and pos_b
  // Decomposed into two MOVE operations
```

### 5.3 Apply Functions

```plaintext
Algorithm: APPLY_INSERT

Input:
  set  — OT_ORDERED_SET
  op   — INSERT operation (already transformed)

1. internal_pos = xi_inv(set.position_map, op.visible_pos)
2. 
3. // Insert into the linked list
4. new_element = {
       id: generate_id(),
       value: op.payload,
       prev_id: element_at(internal_pos - 1).id,
       next_id: element_at(internal_pos).id
   }
5. set.elements.insert_at(internal_pos, new_element)
6. 
7. // Update position map
8. set.position_map = xi_one(set.position_map, internal_pos)
9. 
10. // Update visible value
11. set.visible_value = rebuild_visible(set)


Algorithm: APPLY_DELETE

Input:
  set  — OT_ORDERED_SET
  op   — DELETE operation (already transformed)

1. internal_pos = xi_inv(set.position_map, op.visible_pos)
2. 
3. // Remove from linked list
4. element = set.elements[internal_pos]
5. set.elements.remove_at(internal_pos)
6. 
7. // Update position map
8. set.position_map = union_one(set.position_map, internal_pos)
9. 
10. // Update visible value
11. set.visible_value = rebuild_visible(set)


Algorithm: APPLY_MOVE

Input:
  set  — OT_ORDERED_SET
  op   — MOVE operation (already transformed)

// Decompose into DELETE + INSERT
1. element = get_element_at(set, op.from_pos)
2. 
3. // Delete from old position
4. delete_op = {type: DELETE, visible_pos: op.from_pos}
5. APPLY_DELETE(set, delete_op)
6. 
7. // Insert at new position
8. insert_op = {type: INSERT, visible_pos: op.to_pos, payload: element.value}
9. APPLY_INSERT(set, insert_op)


Algorithm: APPLY_SWAP

Input:
  set  — OT_ORDERED_SET
  op   — SWAP operation (already transformed)

// Decompose into two MOVE operations
1. element_a = get_element_at(set, op.pos_a)
2. element_b = get_element_at(set, op.pos_b)
3. 
4. // Move a to b's position, then b to a's position
5. move_a = {type: MOVE, from_pos: op.pos_a, to_pos: op.pos_b}
6. APPLY_MOVE(set, move_a)
7. 
8. // After move_a, b is now at op.pos_a (if pos_a < pos_b)
9. // or op.pos_a + 1 (if pos_a > pos_b)
10. adjusted_pos = (op.pos_a < op.pos_b) ? op.pos_a : op.pos_a + 1
11. move_b = {type: MOVE, from_pos: adjusted_pos, to_pos: op.pos_a}
12. APPLY_MOVE(set, move_b)
```

### 5.4 CRDT Merge

```plaintext
Algorithm: MERGE_OT_ORDERED_SET

Input:
  a — Local replica
  b — Remote replica

Output:
  merged — Merged replica

1. // Find operations in b that are not in a
2. new_ops = b.op_log ∖ a.op_log  // By OTOpId

3. // Apply each new operation, transforming against concurrent ops
4. merged = copy(a)
5. for each op in new_ops:
6.     // Transform op against all operations in merged's log
7.     // that are concurrent with op
8.     for each existing_op in merged.op_log:
9.         if not causally_before(existing_op, op) and
10.           not causally_before(op, existing_op):
11.            op = TRANSFORM(op, existing_op)
12.            merged.op_log[existing_op_index] = TRANSFORM(existing_op, op)
13.     
14.     // Apply the transformed operation
15.     APPLY(merged, op)
16.     
17.     // Add to log
18.     merged.op_log.append(op)

19. // Merge position maps
20. merged.position_map = MERGE_POSITION_MAPS(a.position_map, b.position_map)

21. return merged


Algorithm: MERGE_POSITION_MAPS

Input:
  a, b — Position maps (BSTs of deleted positions)

Output:
  merged — Merged position map

// The position map tracks deleted positions.
// Merge is union — a position deleted in any replica is deleted in all.

1. merged = copy(a)
2. for each node in b (in-order traversal):
3.     if node.deleted:
4.         merged = union_one(merged, node.value)
5. return merged
```

---

## 6. New Data Type: OT_DOCUMENT (Type 0x11)

### 6.1 Definition

```plaintext
OT_DOCUMENT = {
    ot_type_id: 0x11,
    
    // Text content as a sequence of characters with metadata
    content: Span[],
    
    // Position map
    position_map: PositionMap,
    
    // Operation log
    op_log: OTOperation[],
    
    // Transform matrix (extends OT_ORDERED_SET with text-specific ops)
    transform_matrix: TransformMatrix
}

Span = {
    id: string,
    text: string,              // The text content
    styles: Style[],           // Formatting attributes
    start_pos: uint64,         // Position in the full document
    length: uint64             // Length in characters
}

Style = {
    type: StyleType,           // BOLD, ITALIC, HEADING, LINK, etc.
    value: string              // e.g., "true", "https://..."
}
```

### 6.2 Additional Operations

Beyond the standard OT_ORDERED_SET operations:

```plaintext
MERGE(pos)
  // Merge two adjacent spans at position pos
  // e.g., if pos falls in the middle of a paragraph boundary

SPLIT(pos)
  // Split a span at position pos into two spans

STYLE(pos, length, style)
  // Apply a style to a range of text from pos to pos+length

INSERT_TEXT(pos, text, priority)
  // Insert text at position (specialized INSERT for text)

DELETE_RANGE(pos, length)
  // Delete a range of text from pos to pos+length
```

### 6.3 Text-Specific Transforms

```plaintext
Algorithm: TRANSFORM_INSERT_TEXT_VS_INSERT_TEXT

Input:
  ins_a — INSERT_TEXT being transformed
  ins_b — Concurrent INSERT_TEXT

Output:
  ins_a' — Adjusted INSERT_TEXT

// Same as INSERT vs INSERT, but accounts for text length

1. if ins_a.visible_pos < ins_b.visible_pos:
       return ins_a

2. if ins_a.visible_pos == ins_b.visible_pos:
       if ins_a.priority < ins_b.priority:
           return ins_a
       else:
           ins_a.visible_pos += len(ins_b.payload)
           return ins_a

3. ins_a.visible_pos += len(ins_b.payload)
4. return ins_a


Algorithm: TRANSFORM_DELETE_RANGE_VS_INSERT_TEXT

Input:
  del — DELETE_RANGE being transformed
  ins — Concurrent INSERT_TEXT

Output:
  del' — Adjusted DELETE_RANGE

1. if del.visible_pos < ins.visible_pos:
       if del.visible_pos + del.length <= ins.visible_pos:
           return del  // Delete range is entirely before insert
       else:
           // Delete range overlaps with insert position
           del.length += len(ins.payload)
           return del
   else:
       // Delete range is after insert — shift
       del.visible_pos += len(ins.payload)
       return del
```

---

## 7. New Data Type: OT_TREE (Type 0x13)

### 7.1 Definition

```plaintext
OT_TREE = {
    ot_type_id: 0x13,
    
    // Tree structure
    nodes: {
        "<node_id>": TreeNode,
        ...
    },
    root_id: string,
    
    // Position map (per-parent ordering)
    position_maps: {
        "<parent_id>": PositionMap,
        ...
    },
    
    // Operation log
    op_log: OTOperation[],
    
    // Transform matrix
    transform_matrix: TransformMatrix
}

TreeNode = {
    id: string,
    parent_id: string,
    children: string[],        // Ordered child IDs
    value: any,
    position_map: PositionMap  // For this node's children
}
```

### 7.2 Operations

```plaintext
INSERT_NODE(parent_id, pos, node)
  // Insert a new child node at position pos under parent_id

DELETE_NODE(node_id)
  // Delete a node and all its descendants

REPARENT(node_id, new_parent_id, new_pos)
  // Move a node (and its subtree) to a new parent at position new_pos

REORDER(node_id, new_pos)
  // Change a node's position among its siblings (same parent)
```

### 7.3 Tree-Specific Transforms

```plaintext
Algorithm: TRANSFORM_REPARENT_VS_REPARENT

Input:
  rep_a — REPARENT being transformed (node_a → parent_a, pos_a)
  rep_b — Concurrent REPARENT (node_b → parent_b, pos_b)

Output:
  rep_a' — Adjusted REPARENT

1. // If both operations involve the same node, they conflict
2. if rep_a.node_id == rep_b.node_id:
       // Last writer wins (or policy-based resolution)
       if rep_a.priority < rep_b.priority:
           return rep_a  // rep_a happened first, rep_b overrides
       else:
           return NULL   // rep_a is overridden by rep_b

3. // If rep_a's node is a descendant of rep_b's node,
4. // rep_a moves with rep_b
5. if is_descendant(rep_a.node_id, rep_b.node_id):
       rep_a.new_parent_id = rep_b.new_parent_id
       // Adjust position
       if rep_a.new_pos >= rep_b.new_pos:
           rep_a.new_pos += 1
       return rep_a

6. // If rep_b's node is a descendant of rep_a's node,
7. // rep_b's target parent changes
8. if is_descendant(rep_b.node_id, rep_a.node_id):
       rep_b.new_parent_id = rep_a.new_parent_id  // This is handled in rep_b's transform
       return rep_a  // No change to rep_a

9. // Otherwise, the operations are independent
10. // Adjust positions for insertions/removals
11. if rep_a.new_parent_id == rep_b.new_parent_id:
        if rep_a.new_pos >= rep_b.new_pos:
            rep_a.new_pos += 1
12. if rep_a.node_id == rep_b.node_id:
        // Already handled above
13. return rep_a
```

---

## 8. Integration with CRABS

### 8.1 Type Registration

```plaintext
OT/CRDT types are registered alongside basic CRDT types:

crabs_define_type(state, "playlist", OT_ORDERED_SET,
    .ot_config = {
        .max_op_log_size = 1000,       // Prune old ops beyond this
        .priority_node_id = node_id,   // This node's ID for priority
        .allow_move = true,
        .allow_swap = true
    }
);

crabs_define_type(state, "document", OT_DOCUMENT,
    .ot_config = {
        .max_op_log_size = 10000,
        .allow_merge = true,
        .allow_split = true,
        .allow_style = true
    }
);
```

### 8.2 Operation Execution

```plaintext
Algorithm: EXECUTE_OT_OPERATION

Input:
  state — Current CRABS state
  op    — Operation (may contain OT sub-operations)
  mpk   — ABE master public key

Output:
  result — SUCCESS or error code

// Steps 1-5: Standard CRABS checks (unchanged)
1. PRUNE_EXPIRED_LOCKS(state)
2. Check for duplicate UUID
3. Verify protocol state transitions
4. Verify lock claims
5. Verify ABE signature and key version

// Step 6: Extract OT operations from the payload
6. ot_ops = EXTRACT_OT_OPS(op.payload)
7. if ot_ops is empty:
       return NO_OT_OPS

// Step 7: For each OT operation, transform and apply
8. for each ot_op in ot_ops:
9.     item = state.items[ot_op.item_name]
10.    
11.    if item.type < 0x10 or item.type > 0x1F:
         return NOT_OT_TYPE  // Item is not an OT/CRDT type
12.    
13.    // Transform against concurrent operations in the item's log
14.    for each existing_op in item.op_log:
15.        if not causally_before(existing_op, ot_op) and
16.          not causally_before(ot_op, existing_op):
17.            // Transform ot_op against existing_op
18.            transform_fn = item.transform_matrix[ot_op.op_type][existing_op.op_type]
19.            ot_op = transform_fn(ot_op, existing_op)
20.            
21.            // Also transform existing_op against ot_op (for future)
22.            reverse_fn = item.transform_matrix[existing_op.op_type][ot_op.op_type]
23.            item.op_log[i] = reverse_fn(existing_op, ot_op)
24.    
25.    // Apply the transformed operation
26.    APPLY_OT_OP(item, ot_op)
27.    
28.    // Add to log
29.    item.op_log.append(ot_op)
30.    
31.    // Prune log if too large
32.    if item.op_log.count > item.ot_config.max_op_log_size:
33.        PRUNE_OT_LOG(item)

// Step 10: Standard CRABS finalization
34. Transition protocol states (if any resources were modified)
35. PROCESS_TRIGGERS(state)
36. Log and increment version

37. return SUCCESS
```

### 8.3 Operation Log Pruning

```plaintext
Algorithm: PRUNE_OT_LOG

Input:
  item — OT/CRDT data item

1. // Find the oldest operation that is still referenced by
2. // a causal dependency in a recent operation
3. max_deps = 0
4. for i = 0 to item.op_log.count - 1:
5.     for each dep in item.op_log[i].deps:
6.         max_deps = max(max_deps, dep.sequence_num)

7. // Prune all operations with sequence_num < max_deps - margin
8. prune_before = max_deps - 100  // Keep 100 ops of margin
9. item.op_log = item.op_log[prune_before:]

10. // Rebuild position map from remaining ops
11. item.position_map = REBUILD_POSITION_MAP(item.op_log)
```

---

## 9. Serialization

### 9.1 OT Operation Serialization

```plaintext
OTOperationSerialized = {
    // Identity
    node_id: uint64,
    sequence_num: uint64,
    timestamp: uint64,
    
    // Type and position
    op_type: uint8,              // 0=INSERT, 1=DELETE, 2=UPDATE, 3=MOVE, 4=SWAP
    visible_pos: uint64,
    visible_pos_2: uint64,       // For MOVE dest, SWAP second pos
    
    // Payload
    payload_length: uint32,
    payload: byte[payload_length],
    
    // Priority
    priority: uint64,
    
    // Causal context
    dep_count: uint32,
    deps: {                      // Sorted by (node_id, sequence_num)
        node_id: uint64,
        sequence_num: uint64
    }[dep_count],
    
    // Transform function reference
    transform_fn_id: uint16
}
```

### 9.2 Position Map Serialization

```plaintext
PositionMapSerialized = {
    node_count: uint32,
    nodes: {                     // In-order traversal
        value: uint64,
        deleted: uint8
    }[node_count]
}
```

### 9.3 OT Data Item Serialization

```plaintext
OTDataItemSerialized = {
    ot_type_id: uint8,
    ot_type_version: uint8,
    
    // Visible value (for fast access)
    visible_value_length: uint32,
    visible_value: byte[visible_value_length],
    
    // Position map
    position_map: PositionMapSerialized,
    
    // Operation log
    op_log_count: uint32,
    op_log: OTOperationSerialized[op_log_count],
    
    // Priority counters
    priority_counter_count: uint32,
    priority_counters: {
        node_id: uint64,
        counter: uint64
    }[priority_counter_count]
}
```

---

## 10. Security Considerations

### 10.1 Operation Log Bloat

```plaintext
Attack: Attacker floods the operation log with many small operations,
        causing unbounded storage growth.

Mitigation:
  - Configurable max_op_log_size (default: 1000)
  - Log pruning removes old operations
  - Position map is rebuilt from pruned log
  - Each node has a max operation rate (rate limiting)
```

### 10.2 Transform Function Exploitation

```plaintext
Attack: Attacker crafts a malicious operation that, when transformed,
        causes the transform function to behave incorrectly (e.g., 
        integer overflow in position, infinite loop in transform).

Mitigation:
  - Position bounds checking (0 <= pos <= size)
  - Maximum transform recursion depth (default: 64)
  - Transform functions are pure (no side effects)
  - Operations with invalid positions are rejected before transform
```

### 10.3 Causal Context Forgery

```plaintext
Attack: Attacker claims false causal dependencies to manipulate
        the transform order.

Mitigation:
  - Causal dependencies are verified against the operation log
  - An operation cannot depend on an operation that doesn't exist
  - Node IDs are authenticated (signed operations)
  - Sequence numbers must be monotonic per node
```

### 10.4 Priority Manipulation

```plaintext
Attack: Attacker sets an artificially high priority to always win
        concurrent insert ordering.

Mitigation:
  - Priority includes node_id as the low bits (ensures uniqueness)
  - Node priority counter is monotonic and verified
  - Priority can be clamped: max_priority = (current_time << 48) | ...
  - Malicious nodes can be identified and blacklisted
```

---

## 11. Backward Compatibility

### 11.1 Existing Data Types

All existing CRDT types (COUNTER, PN_COUNTER, SET, 2P_SET, REGISTER, DOCUMENT, RESOURCE) remain unchanged and fully supported. OT/CRDT types are additive.

### 11.2 RGA to OT_DOCUMENT Migration

```plaintext
Existing RGA documents can be migrated to OT_DOCUMENT:

1. Read the current RGA value (string)
2. Create an OT_DOCUMENT with the same content
3. Generate a single INSERT_TEXT operation for the entire content
4. Replace the RGA item with the OT_DOCUMENT item
5. All future operations use OT semantics

The migration is a one-way operation (OT_DOCUMENT cannot be converted back to RGA).
```

### 11.3 Operation Format

Existing operations (without OT sub-operations) are treated as basic CRABS operations. OT operations are identified by the presence of an `ot_ops` field in the payload.

---

## 12. Implementation Guidelines

### 12.1 Position Map Implementation

```c
// Size-balanced BST (AVL tree) for position mapping
typedef struct crabs_bst_node {
    struct crabs_bst_node *left;
    struct crabs_bst_node *right;
    uint64_t value;          // Internal position
    uint32_t size;           // Subtree node count
    uint32_t height;         // For AVL balancing
    bool deleted;            // Whether this position is deleted
} crabs_bst_node_t;

// xi: internal → visible
uint64_t crabs_xi(crabs_bst_node_t *tree, uint64_t internal_pos) {
    uint64_t base = 0;
    while (tree != NULL) {
        uint64_t left_size = size_of(tree->left);
        uint64_t x = tree->value - left_size;
        if (internal_pos < x) {
            tree = tree->left;
        } else {
            internal_pos = 1 + internal_pos - x;
            base += tree->value;
            tree = tree->right;
        }
    }
    return base + internal_pos;
}

// xi_inv: visible → internal
uint64_t crabs_xi_inv(crabs_bst_node_t *tree, uint64_t visible_pos) {
    uint64_t result = visible_pos;
    while (tree != NULL) {
        if (visible_pos < tree->value) {
            tree = tree->left;
        } else {
            visible_pos -= tree->value;
            result += size_of(tree->left) + 1;
            tree = tree->right;
        }
    }
    return result;
}
```

### 12.2 Transform Matrix Implementation

```c
// Transform function type
typedef crabs_ot_op_t (*crabs_transform_fn_t)(
    crabs_ot_op_t op_a,    // The operation being transformed
    crabs_ot_op_t op_b     // The concurrent operation
);

// Transform matrix entry
typedef struct {
    crabs_transform_fn_t transform;
    const char *description;
} crabs_transform_entry_t;

// Transform matrix for OT_ORDERED_SET (5×5)
static crabs_transform_entry_t ot_ordered_set_transform_matrix[5][5] = {
    // INSERT    DELETE      UPDATE      MOVE        SWAP
    { {T_ins_ins, "INSERT vs INSERT: priority compare"},
      {T_ins_del, "INSERT vs DELETE: shift left"},
      {T_ins_upd, "INSERT vs UPDATE: no change"},
      {T_ins_mov, "INSERT vs MOVE: shift left"},
      {T_ins_swp, "INSERT vs SWAP: shift left"} },
      
    { {T_del_ins, "DELETE vs INSERT: shift right"},
      {T_del_del, "DELETE vs DELETE: no conflict"},
      {T_del_upd, "DELETE vs UPDATE: no change"},
      {T_del_mov, "DELETE vs MOVE: adjust source"},
      {T_del_swp, "DELETE vs SWAP: adjust source"} },
      
    // ... remaining rows ...
};
```

### 12.3 Causal Context

```c
// Check if op_a causally precedes op_b
bool crabs_causally_before(crabs_ot_op_t *op_a, crabs_ot_op_t *op_b) {
    // op_a precedes op_b if:
    // 1. op_a's node_id == op_b's node_id and op_a's sequence_num < op_b's sequence_num, OR
    // 2. op_a's id is in op_b's deps, OR
    // 3. There exists an op_c such that op_a precedes op_c and op_c precedes op_b
    //    (transitive closure — checked recursively with depth limit)
    
    if (op_a->node_id == op_b->node_id) {
        return op_a->sequence_num < op_b->sequence_num;
    }
    
    for (int i = 0; i < op_b->dep_count; i++) {
        if (op_a->node_id == op_b->deps[i].node_id &&
            op_a->sequence_num == op_b->deps[i].sequence_num) {
            return true;
        }
    }
    
    return false;
}
```

---

## 13. Test Vectors

### 13.1 INSERT vs INSERT (Same Position, Different Priority)

```plaintext
Setup:
  - Empty OT_ORDERED_SET
  - Alice inserts 'A' at position 0 (priority: 100)
  - Bob inserts 'B' at position 0 (priority: 200)

Alice's operation:
  op_a = INSERT(pos=0, payload='A', priority=100)

Bob's operation:
  op_b = INSERT(pos=0, payload='B', priority=200)

Transform op_a against op_b:
  // Same position, op_a has lower priority → op_a stays at 0
  op_a' = INSERT(pos=0, payload='A', priority=100)

Transform op_b against op_a:
  // Same position, op_b has higher priority → op_b shifts to 1
  op_b' = INSERT(pos=1, payload='B', priority=200)

Apply op_a' then op_b':
  Start: []
  Apply op_a': ['A']
  Apply op_b': ['A', 'B']

Apply op_b' then op_a':
  Start: []
  Apply op_b': ['B']
  Apply op_a': ['A', 'B']  // Wait — op_a was transformed to pos 0
                            // But op_b inserted at 0, so op_a should shift
                            // This is correct: op_a was transformed BEFORE op_b
                            // was applied. When applying op_a after op_b,
                            // op_a's position is still 0, but op_b is at 0,
                            // so op_a shifts to 1.
                            // Result: ['B', 'A']

// DIFFERENT RESULTS! This means the transform is incomplete.
// The issue: we transformed op_a against op_b, but when applying
// op_a AFTER op_b has already been applied, we need to transform
// op_a AGAINST THE EFFECT of op_b, not against op_b itself.

// CORRECT APPROACH: Transform is applied at MERGE time, not at APPLY time.
// Both operations are transformed against each other ONCE, and the
// transformed versions are applied in any order.

// The correct transforms:
op_a' = INSERT(pos=0, payload='A', priority=100)  // Unchanged (lower priority stays)
op_b' = INSERT(pos=1, payload='B', priority=200)  // Shifted (higher priority goes after)

// Apply op_a' then op_b':
//   Start: []
//   Apply op_a': ['A']
//   Apply op_b': ['A', 'B']

// Apply op_b' then op_a':
//   Start: []
//   Apply op_b': ['B']
//   Apply op_a': ['A', 'B']
//   Wait — op_a' inserts at 0, but 'B' is at 0. So op_a' should insert before 'B'.
//   Result: ['A', 'B']

// SAME RESULT! ✅ Convergence achieved.
```

### 13.2 DELETE vs INSERT

```plaintext
Setup:
  - OT_ORDERED_SET = ['A', 'B', 'C', 'D']
  - Alice deletes position 1 ('B')
  - Bob inserts 'X' at position 2

Alice's operation:
  op_a = DELETE(pos=1)

Bob's operation:
  op_b = INSERT(pos=2, payload='X', priority=100)

Transform op_a against op_b:
  // op_a.pos (1) < op_b.pos (2) → no change
  op_a' = DELETE(pos=1)

Transform op_b against op_a:
  // op_b.pos (2) > op_a.pos (1) → shift left
  op_b' = INSERT(pos=1, payload='X', priority=100)

Apply op_a' then op_b':
  Start: ['A', 'B', 'C', 'D']
  Apply op_a': ['A', 'C', 'D']
  Apply op_b': ['A', 'X', 'C', 'D']

Apply op_b' then op_a':
  Start: ['A', 'B', 'C', 'D']
  Apply op_b': ['A', 'B', 'X', 'C', 'D']
  Apply op_a': ['A', 'X', 'C', 'D']  // Delete pos 1 → 'B' removed

// SAME RESULT! ✅
```

### 13.3 MOVE vs MOVE (Same Element)

```plaintext
Setup:
  - OT_ORDERED_SET = ['A', 'B', 'C']
  - Alice moves 'C' from position 2 to position 0
  - Bob moves 'C' from position 2 to position 1

Alice's operation:
  op_a = MOVE(from=2, to=0)

Bob's operation:
  op_b = MOVE(from=2, to=1)

Transform op_a against op_b:
  // Decompose: DELETE(2) + INSERT(0, 'C')
  // Transform DELETE(2) against MOVE(2→1):
  //   op_b's source is 2, same as op_a's source
  //   op_a's DELETE shifts: source is now 3 (op_b removed an element before it)
  //   Wait — op_b's source IS the same element, so op_a's source should be adjusted
  //   Actually, both are moving the SAME element.
  //   This is a conflict: who wins?
  //   Resolution: last-writer-wins by priority
  if op_a.priority > op_b.priority:
      // Alice's move wins
      op_b becomes a no-op (element already moved by Alice)
      op_a' = MOVE(from=2, to=0)  // Unchanged
  else:
      // Bob's move wins
      op_a becomes a no-op
      op_a' = NULL

// This is a FUNDAMENTAL issue: concurrent moves of the same element
// cannot both succeed. The transform must resolve the conflict.
```

### 13.4 Conflict Resolution Strategies

```plaintext
For truly conflicting operations (same element, different moves):

Strategy 1: Last-writer-wins (by priority)
  - Higher priority operation succeeds
  - Lower priority operation becomes a no-op
  - Simple, predictable
  - May lose intent of lower-priority user

Strategy 2: Compose (apply both)
  - First move succeeds, second move applies to the element's new position
  - Element ends up at the second mover's destination
  - Preserves both intents partially
  - May produce unexpected results

Strategy 3: Transform (adjust positions)
  - Both moves succeed, but to adjusted positions
  - Element ends up at a position that accounts for both moves
  - Most complex, most faithful to intent

For CRABS, we recommend Strategy 2 (Compose) as the default,
with Strategy 1 (LWW) available as a configuration option.
```

---

## 14. Summary of Changes from v1.4

Section	Change
§2	Theoretical foundation: coordinate spaces, transform functions, priority
§3	New data type family: OT/CRDT Hybrid Types (0x10-0x1F)
§3.3	Position map: BST for internal↔visible coordinate mapping
§4	Full transform matrix for ordered structures (5×5)
§5	OT_ORDERED_SET: insert, delete, move, swap
§6	OT_DOCUMENT: rich text with merge, split, style
§7	OT_TREE: hierarchical structures with reparent
§8	Integration with CRABS: type registration, operation execution, log pruning
§9	Serialization formats for OT operations, position maps, data items
§10	Security considerations: log bloat, transform exploitation, causal context
§11	Backward compatibility: existing types unchanged, RGA migration
§12	Implementation guidelines: BST, transform matrix, causal context
§13	Test vectors: INSERT vs INSERT, DELETE vs INSERT, MOVE vs MOVE

---

## Appendix: Comparison of Approaches

```plaintext
┌──────────────────────────┬──────────────────┬──────────────────────┐
│          Aspect          │   Basic CRDT     │   OT/CRDT Hybrid     │
├──────────────────────────┼──────────────────┼──────────────────────┤
│ Merge complexity         │ O(1) per type    │ O(N²) per merge      │
│                          │                  │ (N = concurrent ops) │
├──────────────────────────┼──────────────────┼──────────────────────┤
│ Operation log            │ Not needed       │ Required             │
├──────────────────────────┼──────────────────┼──────────────────────┤
│ Storage per item         │ Current value    │ Current value + log  │
├──────────────────────────┼──────────────────┼──────────────────────┤
│ Move operation           │ ❌ Not supported │ ✅ Supported         │
├──────────────────────────┼──────────────────┼──────────────────────┤
│ Swap operation           │ ❌ Not supported │ ✅ Supported         │
├──────────────────────────┼──────────────────┼──────────────────────┤
│ Intent preservation      │ Sometimes loses  │ Always preserves     │
├──────────────────────────┼──────────────────┼──────────────────────┤
│ Implementation complexity│ Low              │ Moderate-High        │
├──────────────────────────┼──────────────────┼──────────────────────┤
│ When to use              │ Simple counters, │ Ordered structures,  │
│                          │ sets, flags      │ collaborative edit,  │
│                          │                  │ complex workflows    │
└──────────────────────────┴──────────────────┴──────────────────────┘
```
