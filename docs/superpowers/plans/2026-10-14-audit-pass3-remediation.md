# Audit Pass-3 Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every actionable finding from the 2026-10-14 third-pass audit (3 HIGH, 7 MEDIUM, actionable LOWs), each with a regression test.

**Architecture:** Seven phases matching the audit's subsystems: OT transform correctness (TP1/dup-ids/causal admission), serialization hardening (caps + canonical gates + canonicality), crypto timing-oracle equalization + policy depth cap, binding seams (cleansing, u64 gates, wasm rotate), state-machine committed-op loss, raft hardening (term ceiling, equivocation, import bounds, pending flush), tx dedup restart seeding, compaction trusted clock. Each task carries its own regression test built against the existing GoogleTest suite (`build/test/testcrabs`).

**Tech Stack:** C11 + GoogleTest (FetchedContent), CMake (`build/` normal, `build-san/` sanitizer), Node N-API + emscripten bindings.

**Build/test commands (use throughout):**
```bash
cmake --build build -j$(nproc)            # then run the test binary directly
./build/test/testcrabs --gtest_filter='*' # full suite (use the binary, not plain ctest)
# sanitizer build (intermittent ASan shadow-map/ASLR startup segfault is NOT code):
# setarch $(uname -m) -R ./build-san/test/testcrabs --gtest_filter='...'
```

**Findings intentionally NOT remediated (documented residuals):** CRDT/OT refcounter convention (INFO, design-wide migration), `PrivateKeyHex` unwipeable export surfaces (documented API), unkeyed snapshot trailer (needs serialization API design, known-open from pass 2), raft wire-MAC layer (byzantine transport out of model), step-0 group-item over-capture (quirk), CLI unsigned ops (documented residual), sig-length cheap-reject (length is public knowledge), trigger.c `created_at` wall clock (metadata only, unflagged).

---

## Phase A — OT transform correctness (HIGH)

### Task A1: Fix move_vs_move same-source TP1 violation

**Files:**
- Modify: `src/OT/ot_transform.c:123-148`
- Test: `test/test_ot_transform.cpp` (update `MoveMoveSameSource`, add convergence tests)

**Step 1: Update/extend the failing tests**

The existing `TEST(OTTransform, MoveMoveSameSource)` pins the BUGGY behavior (`op1.op_type == 0` unconditionally). Replace it with tie-break-aware tests. Also note `make_op` initializes `id` from "node",1,1000 for every op — extend the helper usage: tests needing distinct node ids init `op.id` after `make_op` (via `crabs_ot_op_id_init(&op.id, "nodeA", 1, 1)`).

```cpp
TEST(OTTransform, MoveMoveSameSourceHigherPriorityWins) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_MOVE, 3, 7);
  crabs_ot_op_id_init(&op1.id, "nodeA", 1, 1000);
  op1.priority = 1;
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_MOVE, 3, 9);
  crabs_ot_op_id_init(&op2.id, "nodeB", 1, 1000);
  op2.priority = 1;
  // nodeA wins: op1 keeps its op_type and positions.
  crabs_transform_move_move(&op1, &op2);
  EXPECT_EQ(op1.op_type, CRABS_OT_OP_MOVE);
}

TEST(OTTransform, MoveMoveSameSourceLowerPriorityLoses) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_MOVE, 3, 7);
  crabs_ot_op_id_init(&op1.id, "nodeA", 1, 1000);
  op1.priority = 1;
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_MOVE, 3, 9);
  crabs_ot_op_id_init(&op2.id, "nodeB", 1, 1000);
  op2.priority = 2;
  // nodeB's (priority, node_id) is larger: op1 becomes a no-op.
  crabs_transform_move_move(&op1, &op2);
  EXPECT_EQ(op1.op_type, 0);
}

TEST(OTTransform, MoveMoveSamePriorityNodeIdTiebreak) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_MOVE, 3, 7);
  crabs_ot_op_id_init(&op1.id, "nodeZ", 1, 1000);
  op1.priority = 1;
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_MOVE, 3, 9);
  crabs_ot_op_id_init(&op2.id, "nodeA", 1, 1000);
  op2.priority = 1;
  // "nodeZ" > "nodeA" lexicographically: op1 wins and stays.
  crabs_transform_move_move(&op1, &op2);
  EXPECT_EQ(op1.op_type, CRABS_OT_OP_MOVE);
}
```

- [ ] Run: `./build/test/testcrabs --gtest_filter='OTTransform.*'` — new tests FAIL (MoveMoveSameSourceHigherPriorityWins gets op_type 0).

**Step 2: Implement the total-order tie-break**

Replace the same-source branch in `crabs_transform_move_move` (`src/OT/ot_transform.c:133-138`):

```c
  // Audit pass-3 H-1: same-source concurrent MOVEs previously no-op'd the
  // incoming op unconditionally on ALL replicas — each replica kept its own
  // move, diverging content AND op logs (the serialized state then refuses
  // to merge, permanently forking the replicas). TP1 requires a strict total
  // order: the larger (priority, node_id) wins and the loser is no-op'd on
  // BOTH replicas, mirroring the F-4 insert/insert convention. The winner's
  // source/destination need no further shift: the loser's delete+insert is
  // no-op'd on every replica, so nothing shifts against it.
  if (op1->visible_pos == op2->visible_pos) {
    bool op1_wins;
    if (op1->priority != op2->priority) {
      op1_wins = (op1->priority > op2->priority);
    } else {
      int cmp = strncmp(op1->id.node_id, op2->id.node_id, CRABS_MAX_USER_ID);
      op1_wins = (cmp > 0);
      // Equal ids (same-node reentry) cannot be concurrent — keep the op.
      if (cmp == 0) op1_wins = true;
    }
    if (!op1_wins) op1->op_type = 0;
    return op1;
  }
```

- [ ] Run: `./build/test/testcrabs --gtest_filter='OTTransform.*'` — PASS.
- [ ] Commit:
```bash
git add src/OT/ot_transform.c test/test_ot_transform.cpp
git commit -m "fix(ot): move/move same-source resolves via (priority,node_id) total order (TP1, audit pass-3 H-1)"
```

### Task A2: swap_vs_swap antisymmetric tie-break

**Files:**
- Modify: `src/OT/ot_transform.c:232-246`

**Step 1: Failing test**

```cpp
TEST(OTTransform, SwapSwapSamePositionsHigherPriorityFlips) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_SWAP, 3, 7);
  crabs_ot_op_id_init(&op1.id, "nodeA", 1, 1000);
  op1.priority = 2;
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_SWAP, 3, 7);
  crabs_ot_op_id_init(&op2.id, "nodeB", 1, 1000);
  op2.priority = 1;
  // pass-3 LOW: `>=` flipped BOTH sides on equal priority (non-antisymmetric).
  // Only the larger (priority, node_id) op flips; the other does not.
  crabs_transform_swap_swap(&op1, &op2);
  uint64_t expected_pos = 7, expected_pos2 = 3;  // op1 flipped
  EXPECT_EQ(op1.visible_pos, expected_pos);
  EXPECT_EQ(op1.visible_pos_2, expected_pos2);
}

TEST(OTTransform, SwapSwapEqualPriorityLowerIdDoesNotFlip) {
  crabs_ot_operation_t op1 = make_op(CRABS_OT_OP_SWAP, 3, 7);
  crabs_ot_op_id_init(&op1.id, "nodeA", 1, 1000);
  op1.priority = 1;
  crabs_ot_operation_t op2 = make_op(CRABS_OT_OP_SWAP, 3, 7);
  crabs_ot_op_id_init(&op2.id, "nodeZ", 1, 1000);
  op2.priority = 1;
  // "nodeZ" > "nodeA": op1 loses and does NOT flip.
  crabs_transform_swap_swap(&op1, &op2);
  EXPECT_EQ(op1.visible_pos, 3u);
  EXPECT_EQ(op1.visible_pos_2, 7u);
}
```

- [ ] Run: `./build/test/testcrabs --gtest_filter='OTTransform.*'` — first test FAILS (equal-priority case currently flips both, and with these distinct node ids the current `>=` also flips regardless of ids... with priorities 2 vs 1, `op1->priority >= op2->priority` is TRUE so it passes today; the second test FAILS today).

**Step 2: Implement**

In `crabs_transform_swap_swap`, replace the flip condition:

```c
  // Audit pass-3 LOW: the prior `op1->priority >= op2->priority` flipped BOTH
  // ops when priorities were equal — the same non-antisymmetric class as the
  // F-4 insert/insert flaw. A strict (priority, node_id) order keeps exactly
  // one replica flipping per tie-case, so both replicas agree on the final
  // pair of positions. (Today the flip is a semantic no-op — apply_swap is
  // involutive and position-symmetric — but one transform-matrix change away
  // from a divergence bug.)
  if (op1->visible_pos == op2->visible_pos &&
      op1->visible_pos_2 == op2->visible_pos_2) {
    bool flip;
    if (op1->priority != op2->priority) {
      flip = (op1->priority > op2->priority);
    } else {
      int cmp = strncmp(op1->id.node_id, op2->id.node_id, CRABS_MAX_USER_ID);
      if (cmp > 0) flip = true;
      else if (cmp < 0) flip = false;
      else flip = true;  // equal ids: local reentry, flip is a semantic no-op
    }
    if (flip) {
      uint64_t tmp = op1->visible_pos;
      op1->visible_pos = op1->visible_pos_2;
      op1->visible_pos_2 = tmp;
    }
  }
```

- [ ] Run: `./build/test/testcrabs --gtest_filter='OTTransform.*'` — PASS.
- [ ] Commit:
```bash
git add src/OT/ot_transform.c test/test_ot_transform.cpp
git commit -m "fix(ot): swap/swap flip is antisymmetric on (priority,node_id) (audit pass-3 LOW)"
```

### Task A3: Reject duplicate tree node-ids on the live op path

**Files:**
- Modify: `src/OT/ot_tree.c:207-215` (`crabs_ot_tree_insert_node`)
- Modify: `src/OT/ot_execution.c:497-511` (check the insert return value)
- Test: `test/test_ot_tree.cpp`

**Step 1: Failing test**

```cpp
TEST(OTTree, InsertRejectsDuplicateNodeId) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  ASSERT_NE(tree, nullptr);
  crabs_tree_node_t* root = crabs_ot_tree_insert_node(tree, NULL, 0, "n0", (const uint8_t*)"r", 1);
  ASSERT_NE(root, nullptr);
  // pass-3 HIGH: a second INSERT_NODE carrying the same node_id must be
  // refused — only the deserializer rejected duplicates, so a live signed op
  // pair minted ambiguous pool entries (find() is pool-order-dependent).
  crabs_tree_node_t* dup = crabs_ot_tree_insert_node(tree, NULL, 0, "n0", (const uint8_t*)"r2", 2);
  EXPECT_EQ(dup, nullptr);
  EXPECT_EQ(crabs_ot_tree_find(tree, "n0"), root);
  crabs_ot_tree_destroy(tree);
}
```

- [ ] Run: `./build/test/testcrabs --gtest_filter='OTTree.*'` — `EXPECT_EQ(dup, nullptr)` FAILS (duplicate inserted).

**Step 2: Implement the gate**

In `crabs_ot_tree_insert_node` (after the param checks, before `crabs_tree_node_create`):

```c
  // Audit pass-3 HIGH: pool duplicates make crabs_ot_tree_find pool-order
  // dependent (arrival order legitimately differs across replicas), so
  // DELETE_NODE/REPARENT hit different nodes per replica and the
  // _rebuild_links max-id cycle-break tie argument silently fails. The
  // deserializer rejected duplicates; the op path must too. Content-based
  // refusal → every replica refuses the same op → convergent.
  if (crabs_ot_tree_find(tree, node_id) != NULL) return NULL;
```

`crabs_ot_tree_find` is declared earlier in ot_tree.h — verify it's visible; it is (it's used by this file already).

**Step 3: Wire the insert return value in ot_execution.c**

The INSERT_NODE case (ot_execution.c:506-509) currently ignores the return. Change:

```c
        case CRABS_OT_OP_INSERT_NODE: {
          // Payload format: parent_id[64] + node_id[64] + value
          if (op->payload == NULL || op->payload_size < 128) {
            return CRABS_ERR_INVALID_PARAM;
          }
          char parent_id[64] = {0};
          char node_id[64] = {0};
          memcpy(parent_id, op->payload, 63);
          memcpy(node_id, op->payload + 64, 63);
          if (crabs_ot_tree_insert_node(tree,
              parent_id[0] ? parent_id : NULL,
              op->visible_pos, node_id,
              op->payload + 128, op->payload_size - 128) == NULL) {
            return CRABS_ERR_INVALID_PARAM;
          }
          break;
        }
```

- [ ] Run: `./build/test/testcrabs --gtest_filter='OTTree.*:OTExecution.*'` — PASS.
- [ ] Commit:
```bash
git add src/OT/ot_tree.c src/OT/ot_execution.c test/test_ot_tree.cpp
git commit -m "fix(ot): tree insert refuses duplicate node_ids on the live op path (audit pass-3 H-2)"
```

### Task A4: Buffer OT ops whose causal dependencies are missing

**Files:**
- Modify: `src/OT/ot_types.h` (struct fields on `crabs_ot_data_item_t`)
- Modify: `src/OT/ot_types.c` (destroy frees pending payloads)
- Modify: `src/OT/ot_execution.c` (deferral + flush)
- Test: `test/test_ot_execution.cpp`

**Design:** add to `crabs_ot_data_item_t`:

```c
  // Audit pass-3 M: causal admission. Ops whose declared deps are absent
  // from the log must not transform against incomplete history. Deferred
  // ops re-arm after every successful apply; the cap bounds a Byzantine
  // peer's forever-pending garbage. In-memory only: a restart defers
  // re-delivered ops again (state merges re-deliver op logs, so the queue
  // refills from the merged log).
  crabs_ot_operation_t* pending_ops;
  uint32_t              pending_count;
  uint32_t              pending_capacity;
```

Cap constant in `ot_types.h` (near `CRABS_OT_MAX_OP_LOG_DEFAULT`):

```c
// Audit pass-3 M: cap on causally-blocked buffered ops per item.
#define CRABS_OT_MAX_PENDING_OPS 512
```

**Step 1: Failing test**

```cpp
TEST(OTExecution, OpWithMissingDependencyIsDeferredNotApplied) {
  state_t* state = build_two_item_state();   // existing helper pattern in this file
  // craft an op whose deps name an op-id not yet in the item's log
  // (use the same op-crafting idiom test_ot_execution.cpp already uses for
  // extract/transform tests).
  // ... craft crabs_ot_operation_t with dep_count=1 and a dep id "ghost"...
  crabs_ot_operation_t ghost;
  crabs_ot_operation_init(&ghost);
  ghost.op_type = CRABS_OT_OP_INSERT;
  ghost.visible_pos = 1;
  crabs_ot_op_id_init(&ghost.id, "nodeZ", 9, 1000);
  crabs_ot_op_id_set? /* see existing dep-set idiom in this file for deps */
  // After execute: op NOT applied, NOT logged.
  // Then inject the dependency op into the log and re-execute or flush:
  // the deferred op now applies.
}
```

IMPORTANT: the exact op-crafting idiom (deps field name, dep add helper) must be copied from the existing dep tests in `test/test_ot_execution.cpp` — grep `dep_count` there and mirror it. Write the test body around the real idiom; if the file builds ops via `crabs_extract_ot_ops(op->payload...)`, craft the payload the same way the existing tests do.

Expected behavior before fix: op transforms+applies immediately (divergence). After fix: returns `CRABS_SUCCESS` (op deferred), item state unchanged, op parked in `pending_ops`.

**Step 2: Implement**

In `crabs_execute_ot_operation`, inside the per-item loop, after `_op_already_applied` skip and before `crabs_transform_ot_op`:

```c
      // Audit pass-3 M: causal admission. An op whose declared deps are
      // absent from the log must not transform against incomplete history
      // (per-replica partial logs yield different transforms → permanent
      // divergence). Defer until the dependencies land; re-armed on every
      // successful append below.
      if (!_op_deps_satisfied(ot_data, &ot_ops[i])) {
        if (!_ot_data_pending_push(ot_data, &ot_ops[i])) {
          crabs_ot_ops_free(ot_ops, ot_op_count);
          return CRABS_ERR_INTERNAL;
        }
        continue;
      }
```

Helpers next to `_op_already_applied` in ot_execution.c:

```c
static bool _op_deps_satisfied(const crabs_ot_data_item_t* ot_data,
                               const crabs_ot_operation_t* op) {
  for (uint32_t i = 0; i < op->dep_count; i++) {
    if (!_op_already_applied(ot_data, &op->deps[i])) return false;
  }
  return true;
}

// Push a deep copy of the op (payload owned) onto the item's pending set.
// On cap/OOM: fail-closed (CRABS_ERR_INTERNAL) — under-apply is recoverable
// by re-execution; a silently skipped op would diverge replicas.
static bool _ot_data_pending_push(crabs_ot_data_item_t* ot_data,
                                  const crabs_ot_operation_t* op) {
  if (ot_data->pending_count >= CRABS_OT_MAX_PENDING_OPS) return false;
  if (ot_data->pending_count == ot_data->pending_capacity) {
    uint32_t new_cap = ot_data->pending_capacity == 0 ? 8
                                                      : ot_data->pending_capacity * 2;
    if (new_cap > CRABS_OT_MAX_PENDING_OPS) new_cap = CRABS_OT_MAX_PENDING_OPS;
    crabs_ot_operation_t* grown =
        (crabs_ot_operation_t*)realloc(ot_data->pending_ops,
                                       sizeof(crabs_ot_operation_t) * new_cap);
    if (grown == NULL) return false;
    ot_data->pending_ops = grown;
    ot_data->pending_capacity = new_cap;
  }
  crabs_ot_operation_t* slot = &ot_data->pending_ops[ot_data->pending_count++];
  crabs_ot_operation_init(slot);
  *slot = *op;                       // shallow copy first
  slot->payload = NULL;              // re-own deep parts
  if (op->payload != NULL && op->payload_size > 0) {
    slot->payload = (uint8_t*)get_memory(op->payload_size);
    if (slot->payload == NULL) { ot_data->pending_count--; return false; }
    memcpy(slot->payload, op->payload, op->payload_size);
  }
  return true;
}
```

Flush after each successful append (right after `*log_entry = ot_ops[i];` block + payload copy, still inside the ops loop — run after the loop for efficiency; flush BEFORE the loop returns on later iterations):

```c
  // Audit pass-3 M: newly landed ops may unblock deferred ones. Flush the
  // pending set (bounded by CRABS_OT_MAX_PENDING_OPS iterations; ops whose
  // deps are STILL missing re-defer below via _op_deps_satisfied and stay).
```

Structural note: the ops loop lives inside the resources loop. The flush must run per-resource after that resource's ops loop completes (a pending op whose deps are satisfied applies at its correct position in the stream). Implementation shape: keep the existing per-op loop untouched except for the deferral `continue`, then immediately after the ops loop (per resource), loop `while (flushed_any)`: iterate `pending ops`, apply deps-satisfied ones via the SAME transform/cap/apply/append sequence (factor the body into a helper `static crabs_error_e _apply_one_ot_op(state_t*, data_item_t*, crabs_ot_operation_t*, bool* log_full_err)` to avoid duplicating ~50 lines — the existing body between the `_op_already_applied` skip and the prune becomes this helper, called from both places). Cap flush iterations at `CRABS_OT_MAX_PENDING_OPS * 2` to avoid livelock; if progress stalls (nothing flushed), break — remaining ops wait for the next op arrival.

Destroy path (`crabs_ot_data_item_destroy` in ot_types.c): free pending payloads and array:

```c
  if (item->pending_ops != NULL) {
    for (uint32_t i = 0; i < item->pending_count; i++) {
      if (item->pending_ops[i].payload != NULL) free(item->pending_ops[i].payload);
    }
    free(item->pending_ops);
  }
```

Serialization: pending set is NOT serialized (restart caveat documented in the comment above). `_deserialize_ot_data` creates items via `crabs_ot_data_item_create` with zeroed defaults — no writer change.

- [ ] Run: `./build/test/testcrabs --gtest_filter='OTExecution.*:OTTransform.*'` — PASS plus suite green (no convergence regressions).
- [ ] Commit:
```bash
git add src/OT/ot_types.h src/OT/ot_types.c src/OT/ot_execution.c test/test_ot_execution.cpp
git commit -m "fix(ot): defer ops whose causal deps are missing; flush after each apply (audit pass-3 M)"
```

### Task A5: Make the OT position bound check history-independent

**Files:**
- Modify: `src/OT/ot_execution.c:613-621`
- Verify first: read `crabs_ot_ordered_set_apply` / document apply paths — confirm each validates `pos` against the CURRENT doc structure and fails gracefully (`CRABS_ERR_*` or safe no-op) rather than indexing OOB. If any apply path indexes unbounded, ALSO add a bounds check inside that apply; the execution-level pre-gate below stays.
- Test: `test/test_ot_execution.cpp`

**Step 1: Failing test**

The bug: the 100000 post-transform check fires based on LOCAL log growth, so a replica with longer history rejects an op another accepts. Test the deterministic half: an op whose wire-carried `visible_pos` exceeds the cap is refused BEFORE transform, regardless of log content.

```cpp
TEST(OTExecution, PositionCapRejectsBeforeTransform) {
  // craft op with visible_pos = 200000, a short (empty) item log
  // expect CRABS_ERR_OT_POSITION_BOUNDS (unchanged).
  // craft the same op against an item whose log contains an op that would
  // have pushed the position ABOVE the cap had the pre-gate not refused —
  // still CRABS_ERR_OT_POSITION_BOUNDS (deterministic).
}
```

**Step 2: Implement**

Replace the post-transform check:

```c
      // Audit pass-3 M: the cap decision must not depend on the local log —
      // a post-TRANSFORM check is replica-history-dependent (a longer local
      // op log can push the same op over the cap and diverge accept/reject).
      // Gate the WIRE-CARRIED position instead (content-determined, identical
      // verdict on every replica); the transformed position is then guarded
      // by the apply functions' own content-derived bounds validation.
      if (ot_ops[i].visible_pos > 100000) {
        crabs_ot_ops_free(ot_ops, ot_op_count);
        return CRABS_ERR_OT_POSITION_BOUNDS;
      }

      crabs_error_e transform_err = crabs_transform_ot_op(
        &ot_ops[i], ot_data, op->node_id, CRABS_OT_MAX_TRANSFORM_DEPTH);

      if (transform_err != CRABS_SUCCESS) {
        crabs_ot_ops_free(ot_ops, ot_op_count);
        return transform_err;
      }
```

(i.e., the bounds check moves above `crabs_transform_ot_op`).

- [ ] Run: `./build/test/testcrabs --gtest_filter='OTExecution.*'` — PASS.
- [ ] Commit:
```bash
git add src/OT/ot_execution.c test/test_ot_execution.cpp
git commit -m "fix(ot): position cap gates the wire-carried position before transform (audit pass-3 M)"
```

### Task A6: Guard `crabs_xi` against tombstone-driven underflow

**Files:**
- Modify: `src/OT/position_map.c:200-212`
- Test: `test/test_position_map.cpp`

**Step 1: Failing test**

```cpp
TEST(PositionMap, XiRefusesFullyTombstonedPrefix) {
  // build a BST via the crabs_xi_one/delete idiom already used in this file;
  // tombstone every position <= p, then call crabs_xi(tree, p):
  // today it wraps to UINT64_MAX (internal_pos - offset underflow).
  // After fix: returns UINT64_MAX as an EXPLICIT sentinel — or the existing
  // callers' documented invalid sentinel; grep for crabs_xi callers first
  // (audit found none in-tree, so a direct unit assertion is right).
  EXPECT_EQ(crabs_xi(tree, /*internal_pos=*/0u), UINT64_MAX);
}
```

**Step 2: Implement**

```c
  // Audit pass-3 LOW: internal_pos - offset wraps when every position at or
  // before internal_pos is tombstoned (offset > internal_pos). Surface an
  // explicit sentinel instead of silent wrap arithmetic (no in-tree caller
  // today; any future caller tests against the sentinel).
  if (offset > internal_pos) return UINT64_MAX;
  return internal_pos - offset;
```

- [ ] Run: `./build/test/testcrabs --gtest_filter='PositionMap.*'` — PASS.
- [ ] Commit:
```bash
git add src/OT/position_map.c test/test_position_map.cpp
git commit -m "fix(ot): crabs_xi guards tombstone underflow to an explicit sentinel (audit pass-3 LOW)"
```

---

## Phase B — serialization hardening

### Task B1: Cap + byte-bound CRDT set/flag deserializer counts

**Files:**
- Modify: `src/Serialization/serialization.c:859-933` (`_deserialize_crdt_value`)
- Test: `test/test_serialization.cpp`

**Step 1: Failing test**

Craft a `DATA_TYPE_SET` item payload whose wire element_count is 1M but that carries only a few bytes; previously this looped O(n²) until timeout/OOM (or, with a cap only, realloc churn). Test asserts refusal:

```cpp
TEST(Serialization, OrSetDeserializerRejectsUnsatisfiableCount) {
  // payload: u32le count = 100000 (way above CRABS_DESER_MAX_SET_ELEMENTS)
  // then a couple of real elements
  // crabs_deserialize_data_item on a crafted SET item must return NULL.
}
```

Craft per the existing state-blob craft idiom in `test_serialization.cpp` (the file already builds raw item payloads for v19 tests — mirror one). Assertion: `crabs_deserialize_data_item(...) == NULL` after wiring the gate through `_deserialize_data_item`'s SET arm (parse failure → item rejected) — the failing behavior today is a 100k-iteration loop + realloc churn (still "succeeds" or OOMs), so the test initially asserts the item PARSES only in the honest case, and the gate makes the corrupt case NULL.

**Step 2: Implement**

In `_deserialize_crdt_value`, after each count read, apply cap + byte-bound (mirroring `_deserialize_g_counter_entries` at :982):

```c
    case DATA_TYPE_SET: {
      or_set_t* s = or_set_create();
      if (!s) return NULL;
      uint32_t ec;
      if (!_read_uint32_le(&rb, &ec)) { or_set_destroy(s); return NULL; }
      // pass-3 M: cap (same rationale as the ordered sets' cap) AND a
      // remaining-bytes bound: each observed element pair costs >= 4 wire
      // bytes (two empty string16). Without the bound a 4-byte count drives
      // 100k O(n)-strcmp or_set_add calls + per-add realloc of the array.
      if ((uint64_t)ec > CRABS_DESER_MAX_SET_ELEMENTS ||
          (uint64_t)ec * 4u > rb.len - rb.offset) { or_set_destroy(s); return NULL; }
      // Pre-reserve so the parse loop does one allocation instead of a
      // realloc-per-add (crdt_merge.c:263 reallocs the whole array each add).
      if (ec > 0) {
        s->elements = realloc(s->elements, sizeof(or_set_entry_t) * ec);
        if (!s->elements) { or_set_destroy(s); return NULL; }
      }
      for (uint32_t i = 0; i < ec; i++) { /* unchanged body */ }
      uint32_t tc;
      if (!_read_uint32_le(&rb, &tc)) { or_set_destroy(s); return NULL; }
      if ((uint64_t)tc > CRABS_DESER_MAX_SET_ELEMENTS ||
          (uint64_t)tc * 4u > rb.len - rb.offset) { or_set_destroy(s); return NULL; }
      ...
```

Same pattern for the 2P-set and one-shot-set arms: cap + `(uint64_t)ac * 2u > rb.len - rb.offset` (each string16 costs >= 2 bytes) and pre-reserve their arrays analogously (2P `add_set`, one-shot `elements` — verify member names in `crdt_merge.h`).

Note: the `or_set_add` duplicate-pair dedup stays (it is semantic). The pre-reserve merely sizes the array.

- [ ] Run: `./build/test/testcrabs --gtest_filter='Serialization.*'` — PASS.
- [ ] Commit:
```bash
git add src/Serialization/serialization.c test/test_serialization.cpp
git commit -m "fix(serialization): cap and byte-bound CRDT set/flag counts; pre-reserve arrays (audit pass-3 M)"
```

### Task B2: Canonical (type, crdt_type) gate in the state-file item loop

**Files:**
- Modify: `src/Serialization/serialization.c:2589-2614`
- Test: `test/test_serialization.cpp`

**Step 1: Failing test**

Craft a state blob whose item carries `type = DATA_TYPE_COUNTER`, `crdt_type = CRDT_OR_SET` (value section holding a raw int64). Before the gate, the blob loads and a following `crdt_merge_state` miscasts the int64 as `or_set_t*`. After the fix, `crabs_deserialize_state` fails the item (whole blob refused):

```cpp
TEST(Serialization, StateLoadRejectsNonCanonicalTypeCrdtPair) {
  // serialize a v-current state holding one item, then patch the type/crdt_type
  // bytes to (COUNTER, CRDT_OR_SET) and re-checksum per the existing blob-surgery
  // idiom used by the v19 tests in this file.
  ASSERT_EQ(crabs_deserialize_state(blob, len, &state), CRABS_ERR_SERIALIZATION_ERROR);
}
```

**Step 2: Implement**

In the state item loop, after `_deserialize_data_item` succeeds:

```c
    // pass-3 M: the single-item reader refuses non-canonical (type,
    // crdt_type) pairs (line ~1568) because every crdt-dispatched consumer
    // (crdt_merge_value) miscasts the value slot. The state-file item loop
    // skipped that gate, letting a crafted blob mint a raw int64 tagged as
    // e.g. CRDT_OR_SET — merge then dereferences attacker bytes. NOTE: only
    // the pair is gated here — persisted items legitimately carry
    // protocol_state != PROTOCOL_IDLE (the lock pipeline mid-flight), so
    // the single-item reader's protocol_state clause must NOT apply.
    if (!data_item_type_crdt_pair_canonical(item->type, item->crdt_type)) {
      data_item_destroy(item);
      goto fail;
    }
```

`data_model.h` is already included by serialization.c (verify — it serializes items, so yes).

- [ ] Run: `./build/test/testcrabs --gtest_filter='Serialization.*:CRDT.*'` — PASS.
- [ ] Commit:
```bash
git add src/Serialization/serialization.c test/test_serialization.cpp
git commit -m "fix(serialization): state-file items gated on canonical (type,crdt_type) pair (audit pass-3 M)"
```

### Task B3: Canonicality gates — declared counts, type-id, full consumption, duplicate spans

**Files:**
- Modify: `src/Serialization/serialization.c`
  - `crabs_deserialize_bst` (~:3904): compare declared count to parsed node count
  - position_map arm of `crabs_deserialize_ot_data` (~:3994): same
  - per-tree-node `bst_count` (~:657-663): same (via `_deserialize_bst_recursive` out-param or a returning-count helper)
  - `crabs_deserialize_ot_data` (~:3965): compare wire `type_id` to the `ot_type_id` parameter; add full-consumption after priority_counters
  - `crabs_deserialize_ot_op` (~:3823) and `crabs_deserialize_ot_op_log` (~:3856): full-consumption checks (R7-L-6 pattern)
  - OT document span loop (~:573-610): reject duplicate span ids (same id scan as ordered sets :510-513)
- Test: `test/test_ot_serialization.cpp`

**Step 1: Failing tests**

```cpp
TEST(OTSerialization, OtDataRejectsTypeIdMismatch) {
  // serialize a valid OT_DOCUMENT ot_data; patch the type_id field to 4
  // (a different OT type); deserialize → NULL (previously accepted).
}
TEST(OTSerialization, OtDataRejectsTrailingBytes) {
  // append 4 zero bytes to a valid serialized ot_data → NULL (previously accepted).
}
TEST(OTSerialization, OtOpRejectsTrailingBytes) {
  // same shape for crabs_deserialize_ot_op.
}
TEST(OTSerialization, OtOpLogRejectsTrailingBytes) {
  // same shape for crabs_deserialize_ot_op_log.
}
TEST(OTSerialization, BstDeclaredCountMismatchRejected) {
  // patch a bst_count to +1 → NULL.
}
TEST(OTSerialization, DocumentRejectsDuplicateSpanIds) {
  // two spans carrying the same op id → NULL.
}
```

**Step 2: Implement**

For the count-vs-parsed comparison, thread a parsed count:
- `_deserialize_bst_recursive(buf, depth)` → add `uint32_t* parsed_count_out` (NULL allowed). Increment in the recursive node create; the existing per-call return contract is unchanged.
- Call sites pass a local `uint32_t parsed = 0;` and compare: `if (parsed != bst_count) fail;`

For `crabs_deserialize_ot_data`:

```c
  // ot_type_id
  uint32_t type_id;
  if (!_read_uint32_le(&buf, &type_id)) goto fail;
  // pass-3 LOW: the wire-carried type id MUST agree with the caller's
  // expected type — a disagreeing id is a smuggled cross-type blob.
  if (type_id != (uint32_t)ot_type_id) goto fail;
```

and after the priority_counters loop (before `crabs_transform_matrix_init`):

```c
  // pass-3 LOW: full consumption — trailing bytes are an unvalidated tail.
  if (buf.offset != buf.len) goto fail;
```

For `crabs_deserialize_ot_op` and `crabs_deserialize_ot_op_log`: add the same `buf.offset != buf.len → fail/return 0(+free parsed ops)` tail checks, deleting parsed ops on the failure path (mirror each function's existing fail shape).

For duplicate span ids in the document loop (after `_deserialize_ot_op_id(buf, &id)`): scan `doc->head..tail.prev` comparing `crabs_ot_op_id_equal` (or the struct's memcmp shape these ids use — mirror the ordered-set id scan at :510-513) and fail via the existing `span_fail` label.

- [ ] Run: `./build/test/testcrabs --gtest_filter='OTSerialization.*'` — PASS.
- [ ] Commit:
```bash
git add src/Serialization/serialization.c test/test_ot_serialization.cpp test/test_serialization.cpp
git commit -m "fix(serialization): canonicality gates for ot_data/trees/spans — declared counts, type id, full consumption, dup span ids (audit pass-3 LOW)"
```

---

## Phase C — crypto: policy depth cap + timing-oracle equalization

### Task C1: Bounded-depth policy evaluator

**Files:**
- Modify: `src/Crypto/crypto.c:649-752`

**Step 1: Failing test**

```cpp
TEST(CryptoPolicy, NestedPolicyBeyondDepthCapRefuses) {
  // 200-deep nested parens: "((((...x...))))" — evaluator must refuse
  // (return false), not consume megabytes of stack / overflow.
  std::string deep;
  for (int i = 0; i < 200; i++) deep += '(';
  deep += "role:admin";
  for (int i = 0; i < 200; i++) deep += ')';
  EXPECT_FALSE(crypto_abe_eval_policy(deep.c_str(), "role:admin"));
}

TEST(CryptoPolicy, NestedPolicyWithinDepthCapWorks) {
  const char* policy = "(((role:admin)))";
  EXPECT_TRUE(crypto_abe_eval_policy(policy, "role:admin"));
}
```

The first test fails today by stack overflow in the worst case — to keep it observable add a moderate depth (200 is enough to crash a default stack on the current recursion cost; if it does not crash deterministically in CI, assert depth-capping via a smaller cap constant in the test after introducing `CRABS_POLICY_MAX_DEPTH` — the test may temporarily rely on the constant being low; if needed make the constant test-tunable via a small `crypto_policy_set_max_depth(uint32_t)` setter, default 64 — ONLY if the compile-time constant can't produce a deterministic failing test; otherwise keep the constant private).

**Step 2: Implement**

Thread a depth parameter through the mutually recursive pair:

```c
// pass-3 M: nested-paren policies recursed without bound — a megabyte of
// '(' exhausts the stack from verify_operation_auth (no length cap reaches
// here). 64 nested levels is far beyond any legitimate policy.
#define CRABS_POLICY_MAX_DEPTH 64

static bool _eval_policy_term(const char** pp, const char* attrs, uint32_t depth);
static bool _eval_policy_expr(const char** pp, const char* attrs, uint32_t depth);
```

Every recursive call site passes `depth + 1` and each function starts with:

```c
  if (depth > CRABS_POLICY_MAX_DEPTH) return false;
```

Call sites: paren branch in `_eval_policy_term` (calls `_eval_policy_expr(pp, attrs, depth + 1)`; guard before descending), prefix AND/OR and infix AND/OR in `_eval_policy_expr` (+1), the term call `depth + 1`. `crypto_abe_eval_policy` calls `_eval_policy_expr(&p, attrs, 0)`.

- [ ] Run: `./build/test/testcrabs --gtest_filter='*Crypto*Policy*:*PolicyConfig*'` — PASS.
- [ ] Commit:
```bash
git add src/Crypto/crypto.c test/test_crypto.cpp
git commit -m "fix(crypto): cap ABE policy evaluator recursion depth (stack-exhaustion DoS, audit pass-3 M)"
```

### Task C2: Equal-work signature verification on every refuse path

**Files:**
- Modify: `src/Crypto/crypto.c` (`crypto_verify_operation_auth` Mode A/B, `crypto_verify_operation_auth_v2` Mode A/B, `_verify_user_signature`, `crypto_verify_co_signature`)
- Test: `test/test_crypto.cpp`, `test/test_scheme_verify.cpp`

**Design:** one helper + five restructured sites. The refuse-vs-work asymmetries (pass-3 findings 2/3): (a) v1 Mode-B `!has_attr_policy` branch short-circuits on keyring presence, (b) `_verify_user_signature` early-returns skip the ECDSA trial (RESOURCE_NOT_FOUND / UNAUTHORIZED for missing/inactive/expired/mismatched keys), (c) Mode-A user-not-found / not-active instant refuse, (d) co-sign policy-then-sign ordering. The standard constant-work fix: on refuse paths verify the REAL signature against a FIXED dummy public key (secp256k1 generator) so every outcome costs exactly one ECDSA-verify + policy evaluation. Refuse costs MORE or EQUAL, never less; every unauthorized outcome is indistinguishable by latency.

**Step 1: Failing tests**

Latency cannot be asserted in CI. Test the OBSERVABLE semantics plus code-level equality:

```cpp
TEST(CryptoVerifyTiming, V2ModeBRefusedStillPerformsSignatureTrial) {
  // register two users, one WITH a keyring (rotate), one legacy; craft an op
  // signed by NEITHER; call crypto_verify_operation_auth_v2 Mode B with
  // explicit key_id naming a key_id that exists on NO user.
  // Semantics: UNAUTHORIZED. The equal-work property is structural — the
  // regression guard is the code review + this smoke over the refusal path;
  // a timing test is flaky, so assert only the refused result and that a
  // valid signature over a REAL key still authorizes (no false negatives).
}
TEST(CryptoVerifyTiming, V1ModeBKeyringUsersNoWorkAsymmetry) {
  // Mode B v1, no attr policy: an op signed by a legacy user's key while a
  // KEYRING user sits first in the list must STILL authorize (today the
  // `(user->keys == NULL) && verify` shape skips keyring users — correct
  // reject, but the restructure must not break the accept). Assert: matches
  // the legacy-signer user.
}
TEST(CryptoVerifyTiming, CosignRefusalForPolicyFailStillVerifiesSignature) {
  // policy-unsatisfied co-signer + VALID signature must be refused, and a
  // policy-unsatisfied co-signer + INVALID signature must give the same
  // result in the same API contract (UNAUTHORIZED) — structurally both now
  // run signature + policy.
}
```

**Step 2: Implement**

Add near the secp256k1 helpers in crypto.c:

```c
// Audit pass-3 findings 2/3: equal-work refusal evidence. Refuse paths that
// previously skipped the ECDSA trial now verify the submitted signature
// against a fixed dummy public key (secp256k1 generator — a valid on-curve
// point, so the verify performs full modular work and fails on the math,
// never on a cheap structural reject). Every unauthorized outcome then costs
// exactly one ECDSA verify + policy evaluation, identical to an authorized
// one; latency cannot enumerate users, statuses, or keyring composition.
// Hosts registering ADDITIONAL schemes must ensure their vtable verify has
// the same refuse-path work discipline (in-tree, only ECDSA_SECP256K1 is
// registered).
static const uint8_t CRABS_CRYPTO_DUMMY_PK[33] = {
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55,
    0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC,
    0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
    0xF8, 0x17, 0x98};

static bool _dummy_signature_trial(const uint8_t* serialized_op,
                                   size_t op_len,
                                   const uint8_t* signature,
                                   uint32_t signature_len) {
  return crypto_ecdsa_verify(CRABS_CRYPTO_DUMMY_PK, serialized_op,
                             op_len, signature);
}
```

Sites:

1. `_verify_user_signature`: on EVERY early return that would skip the trial, first run `_dummy_signature_trial(...)` (result ignored), then return the original error. Keep returning the same error codes (R7-14/R8-C-6 error collapses are separately handled at call sites — check callers: `crypto_verify_operation_auth_v2` Mode A converts any `sig_rc != CRABS_SUCCESS` to UNAUTHORIZED; the co-sign path collapses; direct callers of `_verify_user_signature`... it is static — grep it and convert exposed distinct codes at the caller of record; per the pass-2 work the exposed surface already collapses).

2. v1 Mode A user-not-found / not-active: prepend `_dummy_signature_trial(serialized_op, op_len, signature, /*sig len = CRABS_SIG_SIZE*/)` before the UNAUTHORIZED return. Signature length for the trial: the v1 API's signature is the fixed 64-byte array (CRABS_SIG_SIZE).

3. v1 Mode B `!has_attr_policy` branch:

```c
        if (!has_attr_policy) {
          // pass-3 finding 2: the `keyring-presence && verify` chain made
          // per-candidate work vary with keyring state (leaks who rotated).
          // Evaluate the key/sig factors unconditionally; combine results.
          bool key_ok = (user->keys == NULL);
          bool sig_ok = crypto_ecdsa_verify(user->public_key,
                                            serialized_op, op_len, signature);
          user_ok = key_ok && sig_ok;
        }
```

4. v1 Mode B loop restructure — inactive users also run the trial (so position/status do not gate work):

```c
    while (user != NULL) {
      bool status_ok = (user->status == USER_ACTIVE);
      bool key_ok = (user->keys == NULL);
      bool sig_ok = crypto_ecdsa_verify(user->public_key, serialized_op,
                                        op_len, signature);
      bool user_ok = false;
      if (!has_attr_policy) {
        user_ok = status_ok && key_ok && sig_ok;
      } else {
        char attr_string[CRABS_ATTR_STRING_MAX];
        _build_attr_string(user, attr_string, sizeof(attr_string),
                           attr_machine->current_time_ms);
        bool policy_ok = crypto_abe_eval_policy(abe_policy, attr_string);
        user_ok = status_ok && policy_ok && key_ok && sig_ok;
      }
      if (user_ok && !matched) {
        matched = true;
        strncpy(result.signer_id, user->user_id, CRABS_MAX_USER_ID - 1);
        result.signer_id[CRABS_MAX_USER_ID - 1] = '\0';
      }
      user = user->next;
    }
```

Mirror the same restructure in v2 Mode B (the loop at :1605-1644 already evaluates policy unconditionally; extend it so inactive users also run the trial — add `status_ok` and drop the `if (user->status == USER_ACTIVE)` gate; the v2 trial calls `_verify_user_signature`, which is itself equalized in (1)).

5. `crypto_verify_co_signature`: restructure policy + signature into independent evaluations, combining at the end (remove the policy early-return):

```c
  bool policy_ok = true;
  if (abe_policy != NULL && abe_policy[0] != '\0') {
    char attr_string[CRABS_ATTR_STRING_MAX];
    _build_attr_string(user, attr_string, sizeof(attr_string),
                       attr_machine->current_time_ms);
    policy_ok = crypto_abe_eval_policy(abe_policy, attr_string);
  }
  crabs_error_e sig_rc = _verify_user_signature(user, key_id, sig_scheme,
                                                attr_machine->current_time_ms,
                                                serialized_op, op_len,
                                                signature, signature_len);
  if (sig_rc != CRABS_SUCCESS || !policy_ok) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  return CRABS_SUCCESS;
```

- [ ] Run: `./build/test/testcrabs --gtest_filter='*Verify*:*CoSign*:*Auth*'` — PASS; watch for tests asserting DISTINCT error codes from these paths (e.g. `RESOURCE_NOT_FOUND` leaked through Mode B) — those assert the OLD oracle contract; update them to UNAUTHORIZED with a comment citing pass-3 finding 2.
- [ ] Run the full suite.
- [ ] Commit:
```bash
git add src/Crypto/crypto.c test/test_crypto.cpp test/test_scheme_verify.cpp
git commit -m "fix(crypto): equal-work signature trial on every refuse path (dummy-pk ECDSA trial; audit pass-3 findings 2/3)"
```

### Task C3: Encrypt-path IV generation routes through crypto_random_bytes

**Files:**
- Modify: `src/Crypto/crypto.c:1939`

**Step 1: test** — existing GCM/envelope tests cover correctness (`test_crypto.cpp` abe/envelope suites). The change is a one-liner with no behavior delta beyond the health gate; assert via the existing envelope round-trip suite running green. Write no new test (the gate's failure mode is environmental).

**Step 2: Implement**

```c
  uint8_t* iv = out + 33;
  // pass-3 LOW: route through crypto_random_bytes so the fail-closed
  // RAND_status() health probe guards this path like every other one
  // (finding 5: the direct RAND_bytes call skipped the DRBG gate).
  if (crypto_random_bytes(iv, 12) != CRABS_SUCCESS) {
    OPENSSL_cleanse(shared, 32);
    return 0;
  }
```

- [ ] Run: `./build/test/testcrabs --gtest_filter='*Envelope*:*Abe*:*Gcm*:*Crypto*'` — PASS.
- [ ] Commit:
```bash
git add src/Crypto/crypto.c
git commit -m "fix(crypto): ECIES IV generation uses crypto_random_bytes (RAND_status gate, audit pass-3 LOW)"
```

---

## Phase D — binding seams

### Task D1: Cleanse the FromPrivateHex derive-failure free

**Files:**
- Modify: `bindings/node/src/crabs_node.cc:476-479`
- Test: `bindings/node/test/` — add to the existing keypair test file (see `test/` scripts) or create `keypair-secret-lifecycle.js` following `test/abe.js`'s structure; assert `fromPrivateHex('000...0')` rejects AND the API surface stays correct for a valid key.

**Step 1: Failing test**

```js
// bindings/node/test/keypair-secret-lifecycle.js (mirrors test/abe.js harness)
// 1. fromPrivateHex with an all-zero scalar rejects (crypto_ecdsa_derive_public_key
//    refuses non-canonical scalars).
// 2. fromPrivateHex with a VALID scalar yields a working KeyPair.
// The cleansing itself is invisible to JS; the regression value is pinning
// the rejection path so a future refactor cannot skip the struct cleanse.
```

**Step 2: Implement**

```cpp
    if (rc != CRABS_SUCCESS) {
      // Audit pass-3 M: the calloc'd keypair struct ALREADY holds the decoded
      // secret in private_key[32] — free(kp->kp_) alone put the scalar on
      // libc's free list. Cleanse the whole struct before releasing.
      OPENSSL_cleanse(kp->kp_, sizeof(ecdsa_keypair_t));
      free(kp->kp_);
      kp->kp_ = nullptr;
      throw crabs_error(env, rc, "KeyPair.fromPrivateHex");
    }
```

- [ ] Build: `cd bindings/node && npm run build && npm test` — PASS (new test included in `npm test` chain: add `node test/keypair-secret-lifecycle.js` to package.json's test script chain after the abe test).
- [ ] Commit:
```bash
git add bindings/node/src/crabs_node.cc bindings/node/test/keypair-secret-lifecycle.js bindings/node/package.json
git commit -m "fix(bindings): cleanse the FromPrivateHex keypair struct on derive failure (audit pass-3 M)"
```

### Task D2: wasm lineageRotateKey uses the keypair heap without a hex round-trip

**Files:**
- Modify: `bindings/wasm/bindings-core.js:3575-3604`, plus the `sign()` `_M` guard (bindings-core.js:2278)

**Step 1: Failing test** — `bindings/wasm/test/key-transport.js` style: rotate via a `KeyPair._ptr` object and assert the transition record verifies; the un-wipeable V8 string is invisible, so the regression test pins the API signature change (rotating with a KeyPair from ANOTHER module instance now throws):

```js
// in test/lineage-extras.js (wasm) — add:
// 1. lineageRotateKey with a foreign-module KeyPair throws ('lineageRotateKey:
//    the new keypair must come from this module instance').
// 2. lineageRotateKey with a module-local KeyPair.rotate still returns a
//    record whose public key matches the paired state set.
```

**Step 2: Implement**

Both KeyPair forms (`_raw` and keypair) keep private_key at `+0` and public_key at `+32` of `_ptr` (the keypair struct field order matches the raw 32+33 layout). Replace the hex decode:

```js
  lineageRotateKey(newKey) {
    const M = this._M;
    // Audit pass-3 M: the prior round-trip through newKey.privateKeyHex()
    // minted a permanent V8 string copy of the fresh scalar (unwipeable) —
    // the exact seam the M-7 sign() fix closed. Copy the 65 raw bytes
    // (private_key[32] + public_key[33] — identical layout for the raw and
    // keypair forms) straight from this module's heap and wipe the staging
    // in a finally.
    if (!newKey || !newKey._ptr || newKey._M !== this._M) {
      throw new TypeError(
          'lineageRotateKey: expected a KeyPair minted by THIS module instance');
    }
    const staged = M._malloc(65);
    try {
      const view = new Uint8Array(M.HEAPU8.buffer, newKey._ptr, 65);
      new Uint8Array(M.HEAPU8.buffer, staged, 65).set(view);
      const ser = M._crabs_wasm_lineage_key_rotate(this._am, staged, staged + 32);
      if (!ser) {
        throw new Error(
            'lineageRotateKey failed (the C gate refused — see the lineage_key_rotate contract)');
      }
      const len = M._crabs_wasm_buffer_len(ser);
      const data = M._crabs_wasm_buffer_data(ser);
      const out = new Uint8Array(M.HEAPU8.subarray(data, data + len));
      M._crabs_wasm_buffer_destroy(ser);
      return out;
    } finally {
      wipeFree(M, staged, 65);
    }
  }
```

Note: `new Uint8Array(M.HEAPU8.buffer, ...)` — keep the `_crabs_wasm_buffer_*` ordering EXACTLY as the current success path (buffer destroy BEFORE the finally wipe? the current code destroys `ser` before returning; the finally wipe of `staged` happens after — ordering is fine because `ser` is owned by the C heap of the SAME module; keep `M._crabs_wasm_buffer_destroy(ser)` inside the try so an exception between `ser` allocation and destroy does not leak — move the destroy before the throw too).

Also add the same-module-instance guard to `sign()`'s KeyPair fast path (pass-3 finding 5):

```js
    if (signingKey && typeof signingKey === 'object' && signingKey._ptr &&
        signingKey._M === this._M) {
```

(dev-module KeyPair handed to a prod-module machine now falls through to the hex path — which decodes the dev module's heap bytes?? NO: the hex path reads `signingKey.privateKeyHex()` from the WRONG module's heap pointer. So make the cross-instance case a hard throw instead of a fall-through:)

```js
    if (signingKey && typeof signingKey === 'object') {
      if (!signingKey._ptr) throw new Error('Expected KeyPair or private key hex string');
      if (signingKey._M !== this._M) {
        throw new Error('sign: the KeyPair was minted by a different module instance');
      }
      ... (ptr fast path unchanged)
    }
```

- [ ] Rebuild wasm (ONLY if the emsdk environment is available — check `/home/victor/emsdk`): `cd bindings/wasm && npm run build`. If wasm rebuild is impossible this session, ship the bindings-core.js change and run the DEV module tests against the rebuilt dev bundle (`crabs.dev.js` is generated by build_wasm.sh — check whether it embeds bindings-core.js at build time via emcc `-s --pre-js`; if so, wasm rebuild is REQUIRED for the test to see the change — run it).
- [ ] Run: `cd bindings/wasm && npm test` — PASS.
- [ ] Commit:
```bash
git add bindings/wasm/bindings-core.js bindings/wasm/test/lineage-extras.js bindings/wasm/crabs.dev.js bindings/wasm/crabs.js
git commit -m "fix(bindings): wasm lineageRotateKey/sign read the keypair heap instance-safely (no V8 secret string; audit pass-3 M/info)"
```

### Task D3: u64 gates + Encrypt buffer gate on the node seam

**Files:**
- Modify: `bindings/node/src/crabs_node.cc` — `SetTime` (:5582), Blueprint `ttlMs` (:652-653), `attachRaft` seed (:5657), sites :3064, :4596, :4621, `Encrypt` (:4834-4838)
- Test: `bindings/node/test/` — extend `test.js` (or the file covering those APIs) with negative cases: `setTime(-1)` throws RangeError; `setTime(2**53)` round-trips losslessly (or throws past 2**53 — `require_u64_numeric` on Number input throws when outside `[0, MAX_SAFE_INTEGER]`; verify the helper's Number branch bounds at implementation time and copy its exact contract into the test).

**Step 1: negative tests** (one per site, asserting the existing `require_u64_numeric` contract — read its Number branch at :294-303 for the exact throw shape; tests assert `RangeError` for negative/fractional and accept integers within range).

**Step 2: Implement** — replace each `info[N].As<Napi::Number>().DoubleValue()`-to-uint64 cast with `require_u64_numeric(info[N], "<method>", "<field>")` (matching the ctx-string convention used by nearby call sites). In `Encrypt`, gate the info arg:

```cpp
    if (!info[1].IsBuffer()) {
      throw Napi::TypeError::New(env, "Encrypt: info must be a Buffer");
    }
    Napi::Buffer<uint8_t> info_buf = info[1].As<Napi::Buffer<uint8_t>>();
```

(read the current Encrypt signature at :4820-4845 to see which index the `info` arg is and mirror `IsBuffer()` exactly as used by peer methods).

- [ ] Build + test: `cd bindings/node && npm run build && npm test` — PASS.
- [ ] Commit:
```bash
git add bindings/node/src/crabs_node.cc bindings/node/test/*.js
git commit -m "fix(bindings): node entry points gate u64 casts and Encrypt's info buffer (audit pass-3 LOW)"
```

---

## Phase E — consensus / transaction correctness

### Task E1: Unparseable committed ops block the stream instead of being dropped

**Files:**
- Modify: `src/StateMachine/state_machine.c:1488-1495`
- Verify FIRST: read `crabs_raft_module_poll_notification` (raft_module.c) — determine whether a poll DEQUEUES (consumes) the notification or peeks it. If the module KEEPS the notification queued across a poll that returns it (the pump's comment claims "notification stays queued"), the current early return is correct and only the comment/doc needs the truthful semantics — in that case, fix the comment + the `raft_module.h` notification-lifetime doc and SKIP the shelf change.
- Test: `test/test_state_machine.cpp` or `test/test_raft_module.cpp` (whichever holds the pump tests — grep `poll_notification`).

**Step 1: Failing test (only if poll dequeues)**

```cpp
// Pump twice: first pump returns CRABS_ERR_SERIALIZATION_ERROR for the
// corrupted committed op; the SECOND pump must ALSO report the same error
// (order preserved — the entry still blocks) and the later committed op
// must never materialize.
```

**Step 2: Implement (only if poll dequeues)** — mirror the shelf-creation block at :1510-1523 (copy its exact field sets: op_wire, op_len, attempt_count, retry_not_before_ms, next):

```c
    if (op == NULL) {
      // pass-3 HIGH: the poll already consumed the notification — a bare
      // error return LOSES the entry and the next pump skips ahead past an
      // ordered slot this machine can never materialize (silent divergence,
      // commit-comment was wrong). Park the wire on the same retry shelf the
      // execute-failure path uses: the shelf head BLOCKS the stream and each
      // pump retries the parse loudly (poison-pill posture). A version bump
      // that ships new parse rules, or an operator repair, releases it when
      // the parse succeeds.
      raft_retry_shelf_t* shelf = ...;   // exact copy of the :1510 block shape
      state->raft_retry_shelf = shelf;
      return CRABS_ERR_SERIALIZATION_ERROR;
    }
```

Note: `_raft_shelf_attempt` handles `op == NULL` (sets `rc = CRABS_ERR_SERIALIZATION_ERROR`, shelf not released) — parse-failure entries flow through the SAME retry loop automatically.

- [ ] Run: `./build/test/testcrabs --gtest_filter='*Raft*:*StateMachine*'` — PASS.
- [ ] Commit:
```bash
git add src/StateMachine/state_machine.c test/test_state_machine.cpp
git commit -m "fix(state): unparseable committed ops park on the retry shelf instead of silently dropping (audit pass-3 H-3)"
```

### Task E2: Raft term ceiling + equivocation content check

**Files:**
- Modify: `src/Raft/raft_module.c` (`_raft_step_down` :1029-1033, `_raft_begin_election` :1766-1768, append duplicate check :1292-1302)
- Test: `test/test_raft_module.cpp`

**Step 1: Failing tests**

```cpp
TEST(RaftModule, TermCeilingNeverWraps) {
  // feed a crafted APPEND_REQ/vote with term == UINT64_MAX → the node adopts
  // the ceiling; then force an election → current_term must NOT wrap to 0
  // (the node goes inert with a surfaced error/count instead).
}
TEST(RaftModule, AppendEquivocationWithDivergentBytesRejected) {
  // same (term,index) as an existing entry but DIFFERENT proposal_id/bytes
  // → rejected (previously silently accepted as "idempotent duplicate").
}
```

**Step 2: Implement**

In `_raft_step_down`:

```c
static void _raft_step_down(crabs_raft_module_s* module, uint64_t term,
                            const char* new_leader_hint) {
  // pass-3 defense-in-depth (finding 4): refuse the term ceiling — beyond
  // it _begin_election would wrap current_term to 0 and reset monotonicity
  // (stale leaders regain freshness). Callers re-check `term ==
  // current_term` after step-down and fail the message fail-closed.
  if (term == UINT64_MAX || term <= module->current_term) return;
  ...
```

(CHECK the dispatch after step-down really re-checks term equality — read each `_raft_step_down` caller; if any proceeds on the original `term` variable without re-checking, gate it too. `limit` note: this refusal converts a crafted ceiling-term message from "adopt ceiling" to "rejected as stale", which is fail-closed for safety; liveness for the LEGITIMATE case is unaffected because a legitimate election never reaches UINT64_MAX.)

In `_raft_begin_election`:

```c
static void _raft_begin_election(crabs_raft_module_s* module, uint64_t now_ms) {
  // pass-3: inert past the ceiling — never wrap term monotonicity.
  if (module->current_term >= UINT64_MAX) return;
  module->current_term++;
  ...
```

In the append duplicate branch (:1292-1302): on term match, ALSO compare `proposal_id` and, when equal proposal ids, compare the wire bytes with `memcmp` up to `min(len...)`; mismatch → treat as equivocation: reject the message (increment the module's rejected-message counter the other paths use) and, if a notification hook exists for it, surface it (reuse the same counter; do NOT add a new notification kind in this fix).

- [ ] Run: `./build/test/testcrabs --gtest_filter='*Raft*'` — PASS.
- [ ] Commit:
```bash
git add src/Raft/raft_module.c test/test_raft_module.cpp
git commit -m "fix(raft): term ceiling guards and equivocation content check on append (audit pass-3 defense-in-depth)"
```

### Task E3: import_state splice bound + notification-lifetime doc truth

**Files:**
- Modify: `src/Raft/raft_module.c:2504-2519` (splice loop)
- Modify: `src/Raft/raft_module.h:137-139` (comment)
- Test: `test/test_raft_module.cpp` (a persisted-state craft with log_count smaller than the linked list → import must fail cleanly, not write past capacity)

**Step 1: Failing test**

```cpp
TEST(RaftModule, ImportStateRefsusesListLongerThanCount) {
  // craft crabs_raft_persisted_t with log_count = 1 but a 2-node list
  // → crabs_raft_module_import_state returns CRABS_ERR_INVALID_PARAM.
}
```

**Step 2: Implement**

```c
  uint64_t entry_index = 0;
  for (const crabs_raft_entry_persisted_t* node = persisted->log; node != NULL;
       node = node->next) {
    // pass-3 LOW: the capacity was grown to log_count — a struct whose list
    // outruns its declared count wrote past it. Fail closed (input
    // provenance is the signed machine blob; this is defense-in-depth).
    if (entry_index == persisted->log_count) return CRABS_ERR_INVALID_PARAM;
    ...
  }
```

Fix the header comment (~:137-139) to the invalidation truth:

```c
// Bytes/fields stay module-owned; for RAFT_NOTIFY_COMMITTED_OP the op bytes
// point into the module log and stay valid only while the pump does not
// dequeue the next notification AND the module log is not released — copy
// them (or deserialize immediately) before calling import_state or destroying
// the module. (pass-3 finding 8: import_state frees committed op_wires.)
```

- [ ] Run: `./build/test/testcrabs --gtest_filter='*Raft*'` — PASS.
- [ ] Commit:
```bash
git add src/Raft/raft_module.c src/Raft/raft_module.h test/test_raft_module.cpp
git commit -m "fix(raft): import_state bounds the log splice; notification lifetime doc states the real invalidation point (audit pass-3 M/LOW)"
```

### Task E4: Purge proposal pendings on lost leadership

**Files:**
- Modify: `src/StateMachine/state_machine.c` (pump notification loop :1484-1487)
- Test: `test/test_state_machine.cpp`

**Step 1: Failing test**

Propose a group op as leader (pending created), force a leadership loss via the module API, pump — the pending list must be empty afterwards (previously the proposal stayed until `CRABS_RAFT_MAX_PENDING_PROPOSALS` wedged group proposals with `ERR_INTERNAL`).

**Step 2: Implement**

In the pump loop:

```c
    if (notification.kind != RAFT_NOTIFY_COMMITTED_OP) {
      // pass-3 LOW (finding 7): a proposal truncated from the log before
      // commit can never complete — its pending record would linger to the
      // cap and wedge group proposals. On leadership loss the pending
      // lifecycle for THIS module's proposals is over; purge them.
      if (notification.kind == RAFT_NOTIFY_LOST_LEADERSHIP) {
        _raft_pending_flush(state);   // new helper next to _raft_pending_remove
      }
      continue;
    }
```

`_raft_pending_flush` (freelist shape copied from the destroy path :1360-1370): walk `state->raft_pending_proposals`, free each record (payload + uuid copy — mirror `_raft_pending_remove`'s frees), NULL the head. Count each purged proposal in the change-notification if the destroy path does (mirror whatever the destroy path does; keep it silent if destroy is silent).

- [ ] Run: `./build/test/testcrabs --gtest_filter='*Raft*:*StateMachine*'` — PASS.
- [ ] Commit:
```bash
git add src/StateMachine/state_machine.c test/test_state_machine.cpp
git commit -m "fix(state): purge raft proposal pendings on lost leadership (wedged cap, audit pass-3 LOW)"
```

### Task E5: Seed the uuid dedup AVL from the durable log at first accept

**Files:**
- Modify: `src/TxManager/tx_manager_memory.c` (accept path)
- Test: `test/test_tx_manager.cpp`

**Step 1: Failing test**

```cpp
TEST(TxManagerMemory, RestartAdoptsDurableLogUuids) {
  // state with one executed log entry (uuid U) as the manager is attached;
  // call accept with an op whose uuid == U → CRABS_ERR_ALREADY_EXECUTED
  // (previously accepted — the volatile set was empty).
}
```

**Step 2: Implement**

Add a `bool seeded;` to the memory manager's internal struct. In its `accept` (before processing):

```c
  // pass-3 LOW: the AVL set is volatile — across a restart, exactly-once
  // rested solely on the R7-11 watermark, and an authorized signer re-signing
  // the same uuid with a FRESH ordering stamp slipped through. Seed once
  // from the durable log (every logged uuid IS an executed op), restoring
  // retained-log coverage. Compaction-pruned entries lose coverage — the
  // watermark remains the compaction-era backstop (same as before, nothing
  // regressed, and the seeding strictly widens protection).
  if (mgr->seeded == false && state->log_count > 0) {
    for (uint64_t i = 0; i < state->log_count; i++) {
      const log_entry_t* entry = &state->log[i];
      // duplicate uuids in a log would already be an internal violation;
      // avl insert's duplicate result is ignored on seed.
      avl_uuid_insert(mgr->set, entry->uuid);   // use the EXACT insert API in avl_uuid.h
    }
    mgr->seeded = true;
  }
```

(Check the real API names in `avl_uuid.h`/`tx_manager_memory.h` — struct field names, `accept` signature, and whether a `state->log_count`/`state->log` reach is legal from tx_manager_memory.c — the accept signature carries `state`.)

- [ ] Run: `./build/test/testcrabs --gtest_filter='*TxManager*:*Serialization*'` — PASS.
- [ ] Commit:
```bash
git add src/TxManager/tx_manager_memory.c test/test_tx_manager.cpp
git commit -m "fix(tx): seed the uuid dedup set from the durable log at restart (audit pass-3 LOW)"
```

### Task E6: Compaction compact-now uses the trusted clock

**Files:**
- Modify: `src/StateMachine/state_machine.c:3045-3070` (`state_machine_op_compact`)
- Test: `test/test_compaction_periodic.cpp` or `test_compaction.cpp` (whichever exercises `__compact__`) — a test that pins the rate-limit window against a state whose time source is NOT host wall clock.

**Step 1: Failing test** — attach a state time source at an offset from wall clock (the test helpers' time-source injection idiom), fire two `__compact__` ops inside one rate window and one past it, and assert compaction gating follows the INJECTED clock, not `time(NULL)`.

**Step 2: Implement**

`state_machine_op_compact` resolves the trusted clock and calls `crabs_op_compact` with it directly (drop the two `crabs_op_compact_now` uses in this function; keep the public `crabs_op_compact_now` API for other callers — it stays wall-clock, now unused in-tree? grep its callers: in-tree callers are exactly these two lines — after the change, mark `crabs_op_compact_now` for removal? NO: it is public API declared in compaction_engine.h:143; leave it (hosts may call it) but the in-tree `__compact__` path stops using it):

```c
  // pass-3 LOW (finding 3): resolve the AUTHENTICATED platform clock
  // (R8-T-1 discipline) and drive compaction's rate window + compaction
  // timestamp comparisons from it. Falling back to the engine wall clock
  // keeps the API contract for clock-less hosts (matching the
  // clock-trusted/clock-untrusted pump convention).
  uint64_t now_ms = 0;
  bool clock_trusted = state_get_time_ms(state, &now_ms);
  crabs_compaction_engine_t engine;
  ...
  if (!clock_trusted) now_ms = crabs_engine_get_time_ms();
  ...
  return crabs_op_compact(engine_ptr, state, now_ms);
```

- [ ] Run: `./build/test/testcrabs --gtest_filter='*Compaction*'` — PASS.
- [ ] Commit:
```bash
git add src/StateMachine/state_machine.c test/test_compaction.cpp
git commit -m "fix(state): __compact__ drives rate-limiting from the authenticated clock (audit pass-3 LOW)"
```

---

## Phase F — full verification

- [ ] Full native suite: `cmake --build build -j$(nproc) && ./build/test/testcrabs --gtest_filter='*'` — all green.
- [ ] Sanitizer: rebuild `build-san` and run `setarch $(uname -m) -R ./build-san/test/testcrabs --gtest_filter='*'` — all green.
- [ ] Node bindings: `cd bindings/node && npm run build && npm test` — PASS.
- [ ] Wasm bindings (if emsdk available): `cd bindings/wasm && npm run build && npm test` — PASS; bundle artifacts refreshed.
- [ ] Update README if any user-visible semantic changed materially (Mode-B error codes are already UNAUTHORIZED-only via prior collapse — verify no README table references a now-removed distinct error).

---

## Execution Notes

- The audit agents that produced the findings are still resumable (`SendMessage` to their agent ids) with exact file:line context if a fix site looks different from the plan's expectation.
- Wire-format impact: none of the tasks change wire serialization EXCEPT pending-ops are in-memory only (B3/E1/E5 are accept-refusal changes; E2 fails previously-accepted messages). Cluster-version skew after these commits: older nodes accept blobs/messages newer nodes now refuse — treat as pre-release breakage, acceptable per project convention.
- Where an implementation detail deviates from the audit agent's line numbers (comments shifted after earlier fixes), grep for the quoted comment text to find the site.