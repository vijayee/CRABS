# HLC Bounded-Skew Replay-Blindness Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replay of historic op logs must converge instead of aborting — a replaying node accepts HLC stamps older than the 5s live skew window (clamped into the local HLC domain, per-op diagnostics) while future stamps stay hard-rejected on both paths, and the skew policy is reachable through the public bindings API.

**Architecture:** New replay-policy enum value pair lives in `crabs_ordering_config_t.hlc` (runtime-only, never serialized — wire-safe). `crabs_hlc_receive` is refactored into a shared windowed implementation; a new public `crabs_hlc_receive_replay` accepts past-window stamps as `CRABS_HLC_ACCEPTED_CLAMPED`. A new C `state_machine_execute_replay` / wasm `crabs_wasm_execute_replay` seam marks a materialization as bulk-history ingest; the live `execute` path keeps byte-identical behavior. The JS bindings gain `Node.create(id, { skew })` options and `replayOp`/`replayOps` batch methods (wasm + N-API parity).

**Tech Stack:** C11 (CRABS core), gtest (native `test/testcrabs` binary), Emscripten (`build_wasm.sh`, keepalive exports), shared JS wrapper `bindings/wasm/bindings-core.js`, N-API C++ (`bindings/node/src/crabs_node.cc`, cmake-js).

**Spec source:** `docs/2026-10-17-hlc-bounded-skew-replay-fix-brief.md` (all leads verified against the code on 2026-10-17: default BOUNDED/5000 at `src/HLC/hlc.h:134`, windowed reject at `src/HLC/hlc.c:380-411`, probe at `src/StateMachine/state_machine.c:675-692`, wasm `Node.create` ignoring options at `bindings/wasm/bindings-core.js:1100-1111`, HLC stamped at sign time at `src/Util/wasm_helpers.c:417-424`, ordering fields signed at `src/Serialization/serialization.c` sign-format fields 17-18, ordering config never serialized at `src/Util/wasm_helpers.c:3103-3115`, receive-result enum not exhaustively mapped anywhere else).

**Consumer contract (Example repo follow-up):** the vendored wasm wrapper passes
```js
Node.create(adminId, { ordering: 'hlc', skew: {
  strategy?: 'naive'|'bounded'|'quorum'|'strict'|'trusted',  // default 'bounded'
  maxSkewMs?: number,       // default 5000; non-negative safe integer (0 = keep the C default)
  replayPolicy?: 'reject'|'clamp',   // default 'reject' (byte-compatible today)
} })
```
and ingests history with `node.replayOps(opWireBytes[])` or per-op `await Operation.deserialize(bytes)` + `node.replayOp(op)` → `{ status: 'applied'|'skipped'|'pending', code?, message? }`. `replayOps` never aborts the batch; it returns `{ applied: number[], skipped: {index, code, message}[] }` (also `console.warn`s each skip).

Controller decisions from Task 2's quality review (2026-10-18):
- **Clamp acceptance is silent in C** (`ACCEPTED_CLAMPED` is internal): no telemetry plumb-through. The binding-level skip diagnostics satisfy the brief's "per-op diagnostic and continue"; the clamped op's OBSERVABLE marker is its as-authored historic stamp in the audit log. Comments must say "accepted for ordering; the stamp is retained as-authored; the real clock adopts nothing" (no observable clamp).
- **GROUP_ORDERED ops are out of scope for replay ingest in v1.** Raft-committed history recovers through the raft module's own persisted batches (`raftRecoverFromPersist`), not through replayOps; `state_machine_execute_replay` on a GROUP_ORDERED op follows the normal submission gate and may return `ordering_pending` — replayOps treats `pending` as a recorded outcome, not a crash. Documented in Task 4/6.

---

## File Structure

| File | Responsibility in this change |
|---|---|
| `src/HLC/hlc.h` | New `crabs_hlc_receive_result_e` value, `crabs_hlc_replay_policy_e` enum, config field, `crabs_hlc_receive_replay` decl |
| `src/HLC/hlc.c` | Refactor receive into `_hlc_receive_impl(state, received, clamp_past)`; public replay variant |
| `src/StateMachine/state_machine.h` | `state_machine_execute_replay` decl |
| `src/StateMachine/state_machine.c` | `_validate_received_hlc` gains replay mode; `_internal` +1 param; new public execute_replay |
| `src/Util/wasm_helpers.c` | `crabs_wasm_execute_replay`, `crabs_wasm_node_create_ex` (+ shared creation helper) |
| `build_wasm.sh` | Exports the two new keepalive symbols |
| `bindings/wasm/bindings-core.js` | `parseSkewOptions`, `Node.create` options, `replayOp`/`replayOps` |
| `bindings/wasm/test/hlc-skew-replay.js` | e2e walk-scenario test (clamp applied, default still rejects) |
| `bindings/wasm/package.json` | test-chain entry |
| `bindings/node/src/crabs_node.cc` | skew options parse, `ExecuteReplay`, extracted error-name helper |
| `bindings/node/test/hlc-skew-replay.js` | N-API replay test |
| `bindings/node/package.json` | test-chain entry |
| `bindings/node/index.d.ts` | skew options + replayOp/replayOps types |
| `test/test_hlc.cpp` | Core receive tests (4 new) |
| `test/test_state_machine.cpp` | Integration tests (3 new) |
| `README.md`, `bindings/wasm/README.md` | Options schema, ordering caveat, convergence policy note |

Ownership note: `crabs_ordering_config_t` today is a POD struct the host allocates and hands to `state_set_ordering_config`; `state_destroy` does not free it (pre-existing wasm no-op teardown and N-API member-struct patterns are unchanged by this plan). New fields are scalars inside the existing struct — no new allocations, no new ownership paths.

---

### Task 1: HLC core — replay-ingest receive

**Files:**
- Modify: `test/test_hlc.cpp` (append to end)
- Modify: `src/HLC/hlc.h` (result enum, policy enum, config field, decl)
- Modify: `src/HLC/hlc.c` (refactor receive; add replay variant)

- [ ] **Step 1: Write the failing tests**

Append to `test/test_hlc.cpp` (reuses the existing `make_mock_state` helper with local time (36000, 0) and the file's `TEST`/`EXPECT` gtest idioms):

```cpp
// ============================================================
// Replay ingest receive (bounded-skew replay fix, 2026-10-17 brief)
// ============================================================

// A replayed historic op (15s old, beyond the 5s live window) is CLAMPED:
// accepted for ordering, not counted as a time-travel attack, and it must
// not move the local clock backward.
TEST(HLCReceiveReplay, ClampsPast) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_BOUNDED;
  state.max_skew_ms = 5000;

  crabs_hlc_t received = {35985, 0, 0, "bob"};  // 15s behind local
  crabs_hlc_receive_result_e result = crabs_hlc_receive_replay(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_ACCEPTED_CLAMPED);
  // Clamp invariant: the historic stamp does not regress the local clock.
  EXPECT_EQ(state.last.physical_seconds, 36000u);
  EXPECT_EQ(state.last.physical_nanos, 0u);
}

// Future stamps stay hard-rejected on the replay path: bulk ingest is not a
// license to force the clock forward.
TEST(HLCReceiveReplay, StillRejectsFuture) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_BOUNDED;
  state.max_skew_ms = 5000;

  crabs_hlc_t received = {99999, 0, 0, "malicious"};
  uint64_t rejections_before = state.time_travel_attempts_rejected;
  crabs_hlc_receive_result_e result = crabs_hlc_receive_replay(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_REJECTED_SKEW);
  EXPECT_EQ(state.time_travel_attempts_rejected, rejections_before + 1);
}

// The plain receive path is untouched: a past-window stamp still rejects
// (default compatibility for the live path).
TEST(HLCReceiveReplay, PlainReceiveRejectsPast) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_BOUNDED;
  state.max_skew_ms = 5000;

  crabs_hlc_t received = {35985, 0, 0, "old"};  // 15s behind local
  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_REJECTED_SKEW);
  EXPECT_EQ(state.last.physical_seconds, 36000u);
}

// In-window stamps accept NORMALLY on the replay path — same result as the
// live path, no clamp marker.
TEST(HLCReceiveReplay, InWindowAcceptsNormally) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_BOUNDED;
  state.max_skew_ms = 5000;

  crabs_hlc_t received = {36002, 0, 0, "bob"};  // 2s ahead — inside window
  crabs_hlc_receive_result_e result = crabs_hlc_receive_replay(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_ACCEPTED);
  EXPECT_EQ(state.last.physical_seconds, 36002u);
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cmake --build build --target testcrabs -- -j8 && ./build/test/testcrabs --gtest_filter='HLCReceiveReplay.*'
```
Expected: compile FAILURE — `crabs_hlc_receive_replay` undeclared and `CRABS_HLC_ACCEPTED_CLAMPED` unknown.

- [ ] **Step 3: Implement**

`src/HLC/hlc.h` — in `crabs_hlc_receive_result_e` add the new value:

```c
typedef enum {
  CRABS_HLC_ACCEPTED         = 0,  // Timestamp accepted, state updated
  CRABS_HLC_REJECTED_SKEW    = 1,  // BOUNDED: too far ahead/behind
  CRABS_HLC_REJECTED_QUORUM = 2,  // QUORUM: insufficient confirmations
  CRABS_HLC_REJECTED_TRUST  = 3,  // TRUSTED: verification failed
  CRABS_HLC_ACCEPTED_STRICT = 4,  // STRICT: accepted but state unchanged
  CRABS_HLC_ACCEPTED_CLAMPED = 5  // REPLAY: past-window stamp clamped (accepted)
} crabs_hlc_receive_result_e;
```

In `crabs_ordering_config_t.hlc` (the anonymous-ish sub-struct), append the field AND a new enum before `crabs_ordering_config_t`:

```c
// Replay ingest skew policy (bounded-skew replay fix):
// the LIVE path always follows receive_strategy; this policy governs the
// dedicated replay-ingest execute path only.
typedef enum {
  CRABS_HLC_REPLAY_REJECT = 0,  // default: replay follows the live strategy (byte-compatible)
  CRABS_HLC_REPLAY_CLAMP  = 1   // historic (past-window) stamps accepted + clamped; future still rejected
} crabs_hlc_replay_policy_e;
```

and inside `crabs_ordering_config_t`'s `hlc` sub-struct after `trusted_resync_ms`:

```c
    crabs_hlc_replay_policy_e replay_policy;
```

(Both config inits `memset(0)` then fill — the zero value == `CRABS_HLC_REPLAY_REJECT`, so defaults are automatically unchanged.)

After the `crabs_hlc_receive` decl, add:

```c
// Process a received HLC timestamp as REPLAY INGEST. Identical to
// crabs_hlc_receive except that under BOUNDED a stamp OLDER than max_skew_ms
// is CRABS_HLC_ACCEPTED_CLAMPED instead of rejected: a historic op is bulk
// history, not a freshness race, so the live window's clock-skew defense
// does not apply to it. The clamp never regresses the local clock (the max
// rule can only move it forward), the implausible-counter bound and
// future-stamp rejection stay hard errors, and every other strategy
// behaves as in crabs_hlc_receive.
crabs_hlc_receive_result_e crabs_hlc_receive_replay(crabs_hlc_state_t* state,
                                                     const crabs_hlc_t* received);
```

`src/HLC/hlc.c` — rename the existing `crabs_hlc_receive` (at line ~353) to a static three-arg implementation and re-export both entry points. Keep the ENTIRE existing body (null checks, counter bound, strategy switch, strict mode, max-rule update) unchanged EXCEPT the past-window branch inside `HLC_STRATEGY_BOUNDED`, which becomes:

```c
crabs_hlc_receive_result_e crabs_hlc_receive(crabs_hlc_state_t* state,
                                               const crabs_hlc_t* received) {
  return _hlc_receive_impl(state, received, false);
}

crabs_hlc_receive_result_e crabs_hlc_receive_replay(crabs_hlc_state_t* state,
                                                     const crabs_hlc_t* received) {
  return _hlc_receive_impl(state, received, true);
}
```

with, above them, the moved body as:

```c
static crabs_hlc_receive_result_e _hlc_receive_impl(crabs_hlc_state_t* state,
                                                    const crabs_hlc_t* received,
                                                    bool clamp_past) {
```

and the `skew_ms < -max_skew` branch inside BOUNDED changed from the unconditional reject to:

```c
      if (skew_ms < -max_skew) {
        if (clamp_past) {
          // Replay ingest (bounded-skew replay fix): a op stamped further
          // back than the live window is bulk HISTORY, not a freshness race
          // — the window exists to defend the live path against well-behaved
          // clocks running slow. Clamp into the local HLC domain: accept for
          // ordering without regressing the local clock (the max rule below
          // can only move it forward); the executor emits the per-op
          // diagnostic. Ordering caveat: the materialized op keeps its
          // ORIGINAL stamp, so it sorts before everything stamped after it;
          // a log replayed out of order yields ALREADY_EXECUTED for the
          // older entry, never divergence of already-converged state.
          return CRABS_HLC_ACCEPTED_CLAMPED;
        }
        // Received timestamp too far in the past
        state->time_travel_attempts_rejected += 1;
        return CRABS_HLC_REJECTED_SKEW;
      }
```

Everything else in the moved body stays byte-for-byte what `crabs_hlc_receive` had (future check, counter bound, NAIVE/QUORUM/STRICT/TRUSTED branches, strict mode, max rule).

- [ ] **Step 4: Run to verify it passes**

```bash
cmake --build build --target testcrabs -- -j8 && ./build/test/testcrabs --gtest_filter='HLCReceiveReplay.*:HLCReceive.*' && ./build/test/testcrabs --gtest_filter='HLCCore.*'
```
Expected: all PASS (including pre-existing HLCReceive* regressions).

- [ ] **Step 5: Commit**

```bash
git add src/HLC/hlc.h src/HLC/hlc.c test/test_hlc.cpp
git commit -m "feat(hlc): replay-ingest receive accepts past-window stamps (clamped, future still rejected)"
```

---

### Task 2: State machine — replay validation mode + `state_machine_execute_replay`

**Files:**
- Modify: `src/StateMachine/state_machine.h` (decl, near the existing execute decls — find `state_machine_execute` with grep)
- Modify: `src/StateMachine/state_machine.c` (`_validate_received_hlc`, `_internal` signature + 3 call sites, new public fn)
- Modify: `test/test_state_machine.cpp` (3 new tests at end of file)

- [ ] **Step 1: Write the failing tests**

Append to `test/test_state_machine.cpp` (the `TestStateMachine` fixture supplies `state`, `am`, `alice_key`, `test_uuid`, `make_lock_op`, `sign_operation`, `set_signer_key_version`):

```cpp
// ============================================================
// Bounded-skew replay ingest (2026-10-17 brief)
// op->ordering_system and op->hlc are INSIDE the signature (sign-format
// fields 17-18) — they must be stamped before sign_operation runs.
// ============================================================

// Build a signed lock op carrying an explicit HLC stamp (seconds offset
// relative to the receiver's real clock at execute time, which IS the
// machine's live clock — no sleeping needed). uuid_fill distinguishes per
// test so the dedup guard never treats two test ops as the same op.
operation_t* make_hlc_stamp_lock_op(int64_t stamp_offset_seconds, uint8_t uuid_fill) {
  operation_t* op = operation_create(CRABS_OP_LOCK);
  memset(op->uuid, uuid_fill, CRABS_UUID_SIZE);
  op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  set_signer_key_version(op);
  op->ordering_system = CRABS_ORDERING_HLC;
  memset(&op->hlc, 0, sizeof(crabs_hlc_t));
  op->hlc.physical_seconds = (uint64_t)((int64_t)time(NULL) + stamp_offset_seconds);
  op->hlc.physical_nanos = 0;
  op->hlc.logical_counter = 0;
  strncpy(op->hlc.node_id, "alice", CRABS_HLC_NODE_ID_SIZE - 1);
  sign_operation(op);
  return op;
}

// Configure the machine's ordering to BOUNDED + given replay policy with a
// live, initialized clock (mirrors crabs_wasm_node_create's setup).
void set_skew_ordering(crabs_hlc_replay_policy_e replay_policy) {
  crabs_ordering_config_t* config =
      (crabs_ordering_config_t*)malloc(sizeof(crabs_ordering_config_t));
  ASSERT_NE(config, nullptr);
  crabs_ordering_config_init_hlc(config, HLC_STRATEGY_BOUNDED);
  config->hlc.replay_policy = replay_policy;
  state_set_ordering_config(state, config);
  crabs_hlc_state_init(&state->hlc_state, "admin");
  state->hlc_state_initialized = true;
}

// The walk scenario: a log op authored at T is replayed at T+15s by a node
// with the clamp replay policy — the op MATERIALIZES (locked) instead of
// aborting the replay.
TEST_F(TestStateMachine, ReplayClampMaterializesHistoricOp) {
  set_skew_ordering(CRABS_HLC_REPLAY_CLAMP);
  operation_t* op = make_hlc_stamp_lock_op(-15, 0x42);
  EXPECT_EQ(state_machine_execute_replay(state, op), CRABS_SUCCESS);
  data_item_t* resource = state_find_item(state, "test_resource");
  ASSERT_NE(resource, nullptr);
  EXPECT_EQ(resource->protocol_state, PROTOCOL_LOCKED);
  operation_destroy(op);
}

// After a clamped ingest the local HLC stays monotonic and a subsequent
// CURRENT-time op (via the live path) still executes — the clamp did not
// poison ordering.
TEST_F(TestStateMachine, ReplayClampKeepsClockMonotonic) {
  set_skew_ordering(CRABS_HLC_REPLAY_CLAMP);
  operation_t* old_op = make_hlc_stamp_lock_op(-15, 0x42);
  EXPECT_EQ(state_machine_execute_replay(state, old_op), CRABS_SUCCESS);
  uint64_t clock_before = state->hlc_state.last.physical_seconds;
  EXPECT_TRUE(clock_before >= (uint64_t)time(NULL) - 1);

  // A second, current op from the same signer executes through the live path.
  operation_t* current_op = make_hlc_stamp_lock_op(0, 0x41);
  EXPECT_EQ(state_machine_execute(state, current_op), CRABS_SUCCESS);
  EXPECT_TRUE(state->hlc_state.last.physical_seconds >= clock_before);
  operation_destroy(old_op);
  operation_destroy(current_op);
}

// Default configuration is unchanged: live execute of a T-15s op still
// returns protocol_violation, and the replay path WITHOUT the clamp opt-in
// behaves byte-identically (REJECT policy).
TEST_F(TestStateMachine, DefaultLiveStillRejectsOldStamp) {
  set_skew_ordering(CRABS_HLC_REPLAY_REJECT);
  operation_t* op = make_hlc_stamp_lock_op(-15, 0x42);
  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_PROTOCOL_VIOLATION);
  EXPECT_EQ(state_machine_execute_replay(state, op), CRABS_ERR_PROTOCOL_VIOLATION);
  operation_destroy(op);
}

// Future stamps are rejected on BOTH paths, default or clamp policy.
TEST_F(TestStateMachine, FutureStampRejectedOnBothPaths) {
  set_skew_ordering(CRABS_HLC_REPLAY_CLAMP);
  operation_t* op = make_hlc_stamp_lock_op(+15, 0x42);
  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_PROTOCOL_VIOLATION);
  EXPECT_EQ(state_machine_execute_replay(state, op), CRABS_ERR_PROTOCOL_VIOLATION);
  operation_destroy(op);
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cmake --build build --target testcrabs -- -j8 && ./build/test/testcrabs --gtest_filter='TestStateMachine.ReplayClamp*:TestStateMachine.DefaultLiveStillRejectsOldStamp:TestStateMachine.FutureStampRejectedOnBothPaths:TestStateMachine.ClampPolicyDoesNotRelaxLivePath'
```
Expected: compile FAILURE — `state_machine_execute_replay` undeclared.

- [ ] **Step 3: Implement**

`src/StateMachine/state_machine.h` — next to the existing execute declarations, add:

```c
// Replay ingest (bounded-skew replay fix): execute a signed op as BULK
// HISTORY ingest governed by the ordering config's hlc.replay_policy
// (CRABS_HLC_REPLAY_REJECT — byte-compatible default — or
// CRABS_HLC_REPLAY_CLAMP: stamps older than max_skew_ms are accepted,
// clamped into the local HLC domain, instead of
// CRABS_ERR_PROTOCOL_VIOLATION). Future-stamped ops fail on both paths.
// Authorization, dedup and ordering monotonicity behave exactly as
// state_machine_execute.
crabs_error_e state_machine_execute_replay(state_t* state, operation_t* op);
```

`src/StateMachine/state_machine.c`:

1. `_validate_received_hlc` (line ~675) gains a mode parameter and the clamp dispatch. Replace the whole function with:

```c
static crabs_error_e _validate_received_hlc(state_t* state, const operation_t* op,
                                            bool is_replay_ingest) {
  crabs_ordering_config_t* config = state_get_ordering_config(state);
  if (op->ordering_system != CRABS_ORDERING_HLC ||
      !state->hlc_state_initialized ||
      config == NULL || config->ordering_system != CRABS_ORDERING_HLC) {
    return CRABS_SUCCESS;
  }

  crabs_hlc_state_t probe_state = state->hlc_state;
  probe_state.receive_strategy = config->hlc.receive_strategy;
  probe_state.max_skew_ms = config->hlc.max_skew_ms;
  probe_state.strict_mode = config->hlc.strict_mode;
  // Replay ingest consults the config's SEPARATE replay policy: with
  // CRABS_HLC_REPLAY_CLAMP a past-window historic stamp is clamped into the
  // local HLC domain (accepted for ordering) instead of failing the whole
  // op. The live path — and the replay path when no clamp was configured —
  // keep the plain windowed validation. The probe copy is discarded either
  // way: the real clock adopts nothing from ops (see above).
  crabs_hlc_receive_result_e receive_rc;
  if (is_replay_ingest && config->hlc.replay_policy == CRABS_HLC_REPLAY_CLAMP) {
    receive_rc = crabs_hlc_receive_replay(&probe_state, &op->hlc);
  } else {
    receive_rc = crabs_hlc_receive(&probe_state, &op->hlc);
  }
  if (receive_rc == CRABS_HLC_ACCEPTED ||
      receive_rc == CRABS_HLC_ACCEPTED_STRICT ||
      receive_rc == CRABS_HLC_ACCEPTED_CLAMPED) {
    return CRABS_SUCCESS;
  }
  return CRABS_ERR_PROTOCOL_VIOLATION;
}
```

Also extend its doc comment block above with: `Replay ingest (state_machine_execute_replay) passes is_replay_ingest=true and delegates the past-window decision to the config's replay_policy; ACCEPTED_CLAMPED counts as acceptance.`

2. `state_machine_execute_internal` — both the forward declaration (line ~1236) and the definition (line ~1610) gain a 5th parameter and the definition validates accordingly:

```c
static crabs_error_e state_machine_execute_internal(state_t* state, operation_t* op,
                                                    bool skip_authorization,
                                                    bool process_schedules,
                                                    bool is_replay_ingest);
```

(definition gets `is_replay_ingest` appended; update its two call sites — line ~1769 `if (!skip_authorization) {` block becomes

```c
  if (!skip_authorization) {
    crabs_error_e hlc_rc = _validate_received_hlc(state, op, is_replay_ingest);
    if (hlc_rc != CRABS_SUCCESS) {
      return hlc_rc;
    }
  }
```

— and every call site updated:
- `state_machine_execute_committed` (line ~1414): `(state, op, true, false, false)`
- `state_machine_execute` (line ~2083): `(state, op, false, true, false)`
- `state_machine_execute_scheduled` (line ~2096): `(state, op, true, false, false)`)

3. New public function right after `state_machine_execute` (line ~2089):

```c
crabs_error_e state_machine_execute_replay(state_t* state, operation_t* op) {
  char preview[CRABS_MAX_OP_NAME + CRABS_MAX_USER_ID + 2];
  _op_preview(op, preview, sizeof(preview));
  crabs_error_e rc = state_machine_execute_internal(state, op, false, true, true);
  // CRABS_ERR_ALREADY_EXECUTED is an idempotent skip: no mutation, no event.
  if (rc != CRABS_ERR_ALREADY_EXECUTED) {
    state_notify_change_for_op(state, CRABS_CHANGE_OP, op, preview, rc);
  }
  return rc;
}
```

4. `state_machine_validate` (line ~2123) call site becomes `_validate_received_hlc(state, op, false)` (a scheduled submission is a live-authored op: live semantics apply at authorship time).

- [ ] **Step 4: Run to verify it passes**

```bash
cmake --build build --target testcrabs -- -j8 && ./build/test/testcrabs --gtest_filter='TestStateMachine.ReplayClamp*:TestStateMachine.DefaultLiveStillRejectsOldStamp:TestStateMachine.FutureStampRejectedOnBothPaths:TestStateMachine.ClampPolicyDoesNotRelaxLivePath' && ./build/test/testcrabs
```
Expected: the 4 new tests PASS, then the FULL native suite passes (no regressions in default behavior).

- [ ] **Step 5: Commit**

```bash
git add src/StateMachine/state_machine.h src/StateMachine/state_machine.c test/test_state_machine.cpp
git commit -m "feat(state-machine): replay ingest path with per-node HLC clamp policy; live path unchanged"
```

---

### Task 3: WASM C seam — `crabs_wasm_execute_replay` + configurable node creation

**Files:**
- Modify: `src/Util/wasm_helpers.c` (keepalive functions near `crabs_wasm_execute` at line ~452 and `crabs_wasm_node_create` at line ~242)
- Modify: `build_wasm.sh` (BASE_EXPORTS)

- [ ] **Step 1: Refactor node creation to a shared configured helper**

Replace the body of `crabs_wasm_node_create` (wasm_helpers.c lines 241-271) with a shared static + two keepalive entries (the existing body moves verbatim into the helper except the one config line):

```c
static attribute_machine_t* _wasm_node_create_configured(
    const char* admin_id,
    crabs_hlc_strategy_e strategy,
    uint64_t max_skew_ms,
    crabs_hlc_replay_policy_e replay_policy) {
  ecdsa_keypair_t* node_key = crypto_ecdsa_generate();
  if (!node_key) return NULL;

  attribute_machine_t* am = attribute_machine_create(admin_id, node_key->public_key);
  if (!am) {
    crypto_ecdsa_keypair_destroy(node_key);
    return NULL;
  }

  am->base_state.attr_machine = am;
  state_set_node_key(&am->base_state, node_key->private_key, node_key->public_key);

  crabs_ordering_config_t* ordering_config = (crabs_ordering_config_t*)malloc(sizeof(crabs_ordering_config_t));
  if (!ordering_config) {
    crypto_ecdsa_keypair_destroy(node_key);
    attribute_machine_destroy(am);
    return NULL;
  }
  crabs_ordering_config_init_hlc(ordering_config, strategy);
  ordering_config->hlc.max_skew_ms =
      max_skew_ms != 0 ? max_skew_ms : CRABS_HLC_DEFAULT_MAX_SKEW_MS;
  ordering_config->hlc.replay_policy = replay_policy;
  state_set_ordering_config(&am->base_state, ordering_config);

  crabs_hlc_state_init(&am->base_state.hlc_state, admin_id);
  am->base_state.hlc_state_initialized = true;

  state_set_change_hook(&am->base_state, _node_change_hook, am);

  crypto_ecdsa_keypair_destroy(node_key);
  return am;
}

EMSCRIPTEN_KEEPALIVE
attribute_machine_t* crabs_wasm_node_create(const char* admin_id) {
  // Defaults mirror the pre-skew-options behavior exactly (BOUNDED/5000/reject).
  return _wasm_node_create_configured(admin_id, HLC_STRATEGY_BOUNDED,
                                      CRABS_HLC_DEFAULT_MAX_SKEW_MS,
                                      CRABS_HLC_REPLAY_REJECT);
}

// Skew-configured creation (bounded-skew replay fix):
//   strategy      — HLC_STRATEGY_* enum value (0x00 naive … 0x04 trusted)
//   max_skew_ms   — BOUNDED window in ms; 0 keeps the 5000 default
//   replay_policy — CRABS_HLC_REPLAY_* replay-ingest policy
EMSCRIPTEN_KEEPALIVE
attribute_machine_t* crabs_wasm_node_create_ex(const char* admin_id,
                                               crabs_hlc_strategy_e strategy,
                                               uint64_t max_skew_ms,
                                               crabs_hlc_replay_policy_e replay_policy) {
  return _wasm_node_create_configured(admin_id, strategy, max_skew_ms, replay_policy);
}
```

Keep the trailing `crabs_wasm_node_destroy` untouched.

- [ ] **Step 2: Add the replay execute seam**

Right below `crabs_wasm_execute` (wasm_helpers.c line ~452-455):

```c
EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_execute_replay(attribute_machine_t* am, operation_t* op) {
  if (!am || !op) return CRABS_ERR_INVALID_PARAM;
  return state_machine_execute_replay(&am->base_state, op);
}
```

- [ ] **Step 3: Export the new symbols**

`build_wasm.sh` — inside `BASE_EXPORTS` just before the closing `]` (after `"_crabs_wasm_raft_joint_members"`):

```
  ,
  "_crabs_wasm_node_create_ex",
  "_crabs_wasm_execute_replay"
]
```

(i.e. change the last list element `"_crabs_wasm_raft_joint_members"\n]` to `"_crabs_wasm_raft_joint_members",\n  "_crabs_wasm_node_create_ex",\n  "_crabs_wasm_execute_replay"\n]`)

- [ ] **Step 4: Rebuild wasm and verify exports exist**

```bash
source /home/victor/emsdk/emsdk_env.sh && ./build_wasm.sh 2>&1 | tail -6 && grep -c '_crabs_wasm_node_create_ex\|_crabs_wasm_execute_replay' build-wasm/crabs.js
```
Expected: `=== CRABS WASM Build Complete ===` and the grep count is ≥ 4 (each symbol once per JS variant).

- [ ] **Step 5: Sanity-check the pre-existing wasm tests still pass (fresh binaries)**

```bash
npm test --prefix bindings/wasm 2>&1 | tail -6
```
Expected: full chain passes — the new default config path is behaviorally identical.

- [ ] **Step 6: Commit**

```bash
git add src/Util/wasm_helpers.c build_wasm.sh bindings/wasm/crabs.js bindings/wasm/crabs.wasm bindings/wasm/crabs.dev.js bindings/wasm/crabs.dev.wasm build-wasm build-wasm.dev
git commit -m "chore(wasm): replay-execute + configured node-creation seams"
```
(Include artifacts if `build-wasm*` are tracked — otherwise drop those two trailing paths from the git add; `git status` decides.)

---

### Task 4: JS wrapper — `Node.create` skew options + `replayOp`/`replayOps` + e2e test

**Files:**
- Modify: `bindings/wasm/bindings-core.js` (module-level `parseSkewOptions` near `crabsError`; `Node.create` at line 1100; new methods after `execute` at line ~2274)
- Create: `bindings/wasm/test/hlc-skew-replay.js`
- Modify: `bindings/wasm/package.json` (test chain)

- [ ] **Step 1: `parseSkewOptions` + create plumbing**

Add at module level (after `wrapRc`, bindings-core.js line ~385):

```js
// Skew configuration surface (bounded-skew replay fix). Defaults mirror the
// C library exactly (BOUNDED strategy / 5000ms window / reject on replay) so
// Node.create(id) remains byte-identical to today's behavior.
function parseSkewOptions(options) {
  const skew = {
    strategy: 0x01,       // HLC_STRATEGY_BOUNDED
    maxSkewMs: 0,         // 0 keeps the C-side CRABS_HLC_DEFAULT_MAX_SKEW_MS
    replayPolicy: 0,      // CRABS_HLC_REPLAY_REJECT
  };
  if (!options || !options.skew) return skew;
  const s = options.skew;
  if (typeof s !== 'object') {
    throw new TypeError('Node.create: skew must be an options object');
  }
  if (s.strategy !== undefined) {
    // Object.create(null) + Object.hasOwn: a plain `in` check accepts
    // prototype-chain strings like 'toString' and maps a Function to the
    // wasm i32 param (NaN→0 = HLC_STRATEGY_NAIVE — silently disarms the
    // skew defense instead of throwing).
    const strategyNames = Object.assign(Object.create(null), {
      naive: 0x00, bounded: 0x01, quorum: 0x02, strict: 0x03, trusted: 0x04,
    });
    if (typeof s.strategy !== 'string' || !Object.hasOwn(strategyNames, s.strategy)) {
      throw new TypeError(
          "Node.create: skew.strategy must be one of 'naive'|'bounded'|'quorum'|'strict'|'trusted'");
    }
    skew.strategy = strategyNames[s.strategy];
  }
  if (s.maxSkewMs !== undefined) {
    // Number.isSafeInteger, not Number.isInteger: the C ABI takes max_skew_ms
    // as an i64 (wasm BigInt ABI), so the value must survive a 2^53-exact
    // BigInt coercion — anything wider silently rounds BEFORE the cast.
    if (typeof s.maxSkewMs !== 'number' || !Number.isSafeInteger(s.maxSkewMs) || s.maxSkewMs < 0) {
      throw new TypeError('Node.create: skew.maxSkewMs must be a non-negative integer');
    }
    skew.maxSkewMs = s.maxSkewMs;
  }
  if (s.replayPolicy !== undefined) {
    const replayNames = Object.assign(Object.create(null), { reject: 0, clamp: 1 });
    if (typeof s.replayPolicy !== 'string' || !Object.hasOwn(replayNames, s.replayPolicy)) {
      throw new TypeError(
          "Node.create: skew.replayPolicy must be 'reject' or 'clamp'");
    }
    skew.replayPolicy = replayNames[s.replayPolicy];
  }
  return skew;
}
```

Replace `Node.create`'s body (line 1100-1111):

```js
  static async create(adminId, options = {}) {
    const M = await getModule();
    // Validate options BEFORE staging the admin id: a rejected create must
    // not leak the writeString allocation into the module heap.
    const skew = parseSkewOptions(options);
    const adminPtr = writeString(M, adminId);
    // max_skew_ms crosses the wasm ABI as i64 → a BigInt is REQUIRED at the
    // call site (a Number throws `Cannot convert N to a BigInt`). 0 keeps
    // the C-side 5000 default — it is a sentinel, NOT "unbounded" (oversized
    // windows are safe: the consumer clamps to INT64_MAX, hlc.c R6-4).
    const amPtr = M._crabs_wasm_node_create_ex(
        adminPtr, skew.strategy, BigInt(skew.maxSkewMs), skew.replayPolicy);
    if (adminPtr) M._free(adminPtr);
    if (!amPtr) throw new Error('Node.create failed');
    const node = new Node(M, amPtr);
    // The bootstrap admin id becomes the node's HLC identity: signing stamps
    // op->node_id from it, and devtools events are attributed per node by it.
    node.adminId = adminId;
    return node;
  }
```

- [ ] **Step 2: Replay API on Node**

Add after `execute(op)` (line ~2274):

```js
  // Replay ingest (bounded-skew replay fix): execute a signed op under this
  // node's REPLAY skew policy (Node.create option skew.replayPolicy). Never
  // throws for an individually failed op — returns an outcome so a log
  // replay can converge by design:
  //   { status: 'applied' | 'pending' } on success/raft-pending
  //   { status: 'skipped', code, message } on failure (e.g. 0x1002
  //   protocol_violation for a future stamp, 0x7002 already_executed on a
  //   re-ingested op) — skipped does not mutate state.
  replayOp(op) {
    const rc = this._M._crabs_wasm_execute_replay(this._am, op._ptr);
    if (rc === 0) return { status: 'applied' };
    if (rc === 0xA006) return { status: 'pending' };   // raft GROUP_ORDERED path
    return { status: 'skipped', code: rc, message: crabsError(rc, 'replayOp').message };
  }

  // Bulk history ingest: replay a batch of ALREADY-DESERIALIZED Operations.
  // Per-op failures never abort the batch — each skip is console.warn'd and
  // returned with its index, so consumers converge (and can surface gaps)
  // instead of dying on the first out-of-window/opaque entry. Pass
  // `operation.serialize()` wires through a node in the SAME module instance
  // after `Operation.deserialize` per entry, mirroring a log replay.
  replayOps(operations) {
    if (!Array.isArray(operations)) {
      throw new TypeError('replayOps: expected an array of Operations');
    }
    const applied = [];
    const skipped = [];
    operations.forEach((entryOperation, entryIndex) => {
      const outcome = this.replayOp(entryOperation);
      if (outcome.status !== 'skipped') {
        applied.push(entryIndex);
      } else {
        console.warn(`crabs-wasm: replay skipped op[${entryIndex}]: ${outcome.message}`);
        skipped.push({ index: entryIndex, code: outcome.code, message: outcome.message });
      }
    });
    return { applied, skipped };
  }
```

- [ ] **Step 3: Write the e2e test**

Create `bindings/wasm/test/hlc-skew-replay.js` — the walk scenario in miniature: an op is signed on the author node at T, a fresh node with DEFAULT config replays it at T+6s (beyond the 5s live window) and fails; a fresh node with the clamp policy replays it and it materializes; re-replay is an idempotent skip. (6s instead of the walk's 15s — past the 5s default window is what matters; keeps CI fast.)

```js
'use strict';

// HLC bounded-skew replay fix e2e (brief 2026-10-17): replay of a
// beyond-window op fails closed on the default config and CLAMPS through on
// the replay-opt-in config. 6s wall-clock age crosses the 5s default window.

const { Node, Operation, KeyPair } = require('..');

const assertEquals = (actual, expected, label) => {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
};

(async () => {
  const aliceKey = await KeyPair.generate();

  // Shared registration+policy setup any replayer needs (the log replays
  // ops; the user registry arrives with the snapshot in real deployments).
  const registerUsersOn = async (node) => {
    await node.registerUser('alice', aliceKey.publicKeyHex(), '');
    node.grantRole('alice', 'role', 'admin', 'admin');
    node.setPolicy('flip', 'role:admin');
  };

  // --- Author: sign an op NOW (its HLC stamp carries the author clock T).
  const author = await Node.create('author');
  await registerUsersOn(author);
  author.addRegister('flips', 0);
  author.registerHandlerJs(
      'flip', (state) => { state.setRegister('flips', state.getRegister('flips') + 1); return 0; });
  const op = await Operation.create('flip');
  op.signerId = 'alice';
  op.nodeId = 'author';
  author.sign(op, aliceKey.privateKeyHex());
  author.execute(op);
  assertEquals(author.getRegister('flips'), 1, 'author executed its own op');
  const opWire = op.serialize();
  op.destroy();
  author.destroy();

  // --- Wait past the default 5s skew window.
  await new Promise((resolve) => setTimeout(resolve, 6100));

  // --- Fresh node, DEFAULT skew config: live execute still fails closed.
  const defaultReplayer = await Node.create('default-replayer');
  await registerUsersOn(defaultReplayer);
  defaultReplayer.addRegister('flips', 0);
  defaultReplayer.registerHandlerJs(
      'flip', (state) => { state.setRegister('flips', state.getRegister('flips') + 1); return 0; });
  const defaultOp = await Operation.deserialize(opWire);
  let defaultThrew = null;
  try { defaultReplayer.execute(defaultOp); } catch (caughtError) {
    defaultThrew = caughtError.message;
  }
  if (!defaultThrew || !defaultThrew.includes('protocol_violation')) {
    throw new Error(`default live replay must throw protocol_violation, got "${defaultThrew}"`);
  }
  assertEquals(defaultReplayer.getRegister('flips'), 0, 'default replay did not mutate');

  // --- Fresh node, CLAMP replay policy: the op materializes.
  const clampReplayer = await Node.create('clamp-replayer', { skew: { replayPolicy: 'clamp' } });
  await registerUsersOn(clampReplayer);
  clampReplayer.addRegister('flips', 0);
  clampReplayer.registerHandlerJs(
      'flip', (state) => { state.setRegister('flips', state.getRegister('flips') + 1); return 0; });
  const clampOutcome = clampReplayer.replayOp(await Operation.deserialize(opWire));
  assertEquals(clampOutcome.status, 'applied', 'clamp replay ingested the historic op');
  assertEquals(clampReplayer.getRegister('flips'), 1, 'handler materialized through clamp replay');

  // --- Re-ingest the same op: skipped, batch survives.
  const reOutcome = clampReplayer.replayOp(await Operation.deserialize(opWire));
  assertEquals(reOutcome.status, 'skipped', 're-ingest is an idempotent skip');
  if (reOutcome.code !== 0x7002) {
    throw new Error(`re-ingest skip expected already_executed (0x7002), got 0x${reOutcome.code.toString(16)}`);
  }
  assertEquals(clampReplayer.getRegister('flips'), 1, 'skip did not re-run the handler');

  // --- Batch API: one bad op does not abort the batch.
  const batchDeserialized = await Promise.all(
      [Operation.deserialize(opWire), Operation.deserialize(opWire)]);
  const batch = clampReplayer.replayOps(batchDeserialized);
  assertEquals(batch.applied.length, 0, 'both entries dedup as already-executed');
  assertEquals(batch.skipped.length, 2, 'both skips are reported');

  console.log('hlc-skew-replay OK: clamp ingest materializes, default rejects, batch survives');
  defaultReplayer.destroy();
  clampReplayer.destroy();
})().catch(e => { console.error(e); process.exit(1); });
```

(If `Operation.deserialize` needs a bytes-shaped input differing from `op.serialize()` output, mirror whatever the sibling tests use at the deserialize call sites.)

- [ ] **Step 4: Wire into the test chain**

`bindings/wasm/package.json` — append to the "test" script: `&& node test/hlc-skew-replay.js`.

- [ ] **Step 5: Run the new test only, then the full wasm chain**

```bash
npm run build --prefix bindings/wasm >/dev/null 2>&1 || true   # no-op here; binaries fresh from Task 3
node bindings/wasm/test/hlc-skew-replay.js
```
Expected: `hlc-skew-replay OK: ...` then exit 0. Then:

```bash
npm test --prefix bindings/wasm 2>&1 | tail -10
```
Expected: full chain passes including the new line.

- [ ] **Step 6: Commit**

```bash
git add bindings/wasm/bindings-core.js bindings/wasm/test/hlc-skew-replay.js bindings/wasm/package.json
git commit -m "feat(bindings/wasm): Node.create skew options + replayOp/replayOps ingest API"
```

---

### Task 5: N-API parity — skew options + `replayOp` on `crabs-node`

**Files:**
- Modify: `bindings/node/src/crabs_node.cc` (error-name extraction at line ~124; Node::Create options at line ~1640; ExecuteReplay after `Execute` at line ~4409; InstanceMethod list at line ~1542)
- Modify: `bindings/node/index.d.ts` (Node.create options type + replayOp/replayOps declarations)
- Create: `bindings/node/test/hlc-skew-replay.js`
- Modify: `bindings/node/package.json` (test chain)

- [ ] **Step 1: Extract the error-name switch into a reusable helper**

In `crabs_node.cc`, `crabs_error` (line ~124) computes `msg` inside a big switch. Add above it:

```cpp
static std::string crabs_error_name(crabs_error_e err) {
  // The name table lifted verbatim from crabs_error's switch below —
  // ExecuteReplay needs the NAME (not a thrown Error) for outcome objects.
  switch (err) {
    // ... the exact existing case list from crabs_error's switch, moved verbatim ...
    default: return "unknown_error";
  }
}

static Napi::Error crabs_error(Napi::Env env, crabs_error_e err, const char* ctx) {
  std::string full = std::string(ctx) + ": " + crabs_error_name(err);
  return Napi::Error::New(env, full);
}
```

(The `switch` cases and their strings are a mechanical verbatim move — every `case X: msg = "..."; break;` becomes `case X: return "..." ;`. `CRABS_SUCCESS: return "success";` included.)

- [ ] **Step 2: Parse skew options in Node::Create**

(Carry-over from Task 3's quality review: the C seam takes raw enums with no validation — the JS whitelist is the enforcement point, so this block must replicate the wasm binding's `parseSkewOptions` whitelist EXACTLY: maxSkewMs non-negative safe integer, replayPolicy ∈ {reject, clamp}. And the 0-sentinel rule: 0 keeps the default 5000, it does not mean unbounded.)

In `Node::Create` (line ~1629-1680), extend the options parsing block and the ordering-config section:

```cpp
    // Parse options: { ordering: 'hlc' | 'lamport', skew: { maxSkewMs, replayPolicy } }
    bool use_hlc = true;  // Default to HLC (user requested hybrid time)
    uint64_t max_skew_ms = 0;                      // 0 keeps the C default 5000
    crabs_hlc_replay_policy_e replay_policy = CRABS_HLC_REPLAY_REJECT;
    if (info.Length() > 1 && info[1].IsObject()) {
      Napi::Object opts = info[1].As<Napi::Object>();
      if (opts.Has("ordering")) {
        std::string ord = require_js_string(opts.Get("ordering"), "Node", "ordering");
        use_hlc = (ord == "hlc");
      }
      if (opts.Has("skew") && opts.Get("skew").IsObject()) {
        Napi::Object skew = opts.Get("skew").As<Napi::Object>();
        if (skew.Has("maxSkewMs")) {
          Napi::Value value = skew.Get("maxSkewMs");
          if (!value.IsNumber() || (double)value.As<Napi::Number>() < 0) {
            throw Napi::TypeError::New(env, "Node: skew.maxSkewMs must be a non-negative number");
          }
          max_skew_ms = (uint64_t)value.As<Napi::Number>().DoubleValue();
        }
        if (skew.Has("replayPolicy")) {
          std::string policy = require_js_string(skew.Get("replayPolicy"), "Node", "skew.replayPolicy");
          if (policy != "clamp" && policy != "reject") {
            throw Napi::TypeError::New(env, "Node: skew.replayPolicy must be 'clamp' or 'reject'");
          }
          replay_policy = (policy == "clamp") ? CRABS_HLC_REPLAY_CLAMP : CRABS_HLC_REPLAY_REJECT;
        }
      }
    }
```

and the `if (use_hlc)` block becomes:

```cpp
    if (use_hlc) {
      crabs_ordering_config_init_hlc(&ordering_config_, HLC_STRATEGY_BOUNDED);
      if (max_skew_ms != 0) ordering_config_.hlc.max_skew_ms = max_skew_ms;
      ordering_config_.hlc.replay_policy = replay_policy;
      state_set_ordering_config(&am_->base_state, &ordering_config_);
      // Initialize HLC state with admin_id as node_id
      crabs_hlc_state_init(&am_->base_state.hlc_state, admin_id.c_str());
      am_->base_state.hlc_state_initialized = true;
    }
```

(Note: `0x1002`-style future-stamp policy stays C-side; the N-API surfaces no strategy override here — parity with the wasm binding's skew surface except `strategy`, mirroring the pre-existing N-API shape which never exposed one. If the wasm side later needs it here, add it in the same shape.)

- [ ] **Step 3: `ExecuteReplay` method**

After `Node::Execute` (line ~4409-4423):

```cpp
  Napi::Value ExecuteReplay(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsObject())
      throw Napi::TypeError::New(env, "Expected Operation");
    Operation* op = Operation::Unwrap(info[0].As<Napi::Object>());
    // Replay ingest: same gates as Execute, but the HLC skew decision uses
    // the node's replay policy (hlc.replay_policy) instead of the live one.
    crabs_error_e rc = state_machine_execute_replay(&am_->base_state, op->raw());
    Napi::Object outcome = Napi::Object::New(env);
    if (rc == CRABS_SUCCESS) {
      outcome.Set("status", "applied");
      return outcome;
    }
    if (rc == CRABS_ERR_ORDERING_PENDING) {
      outcome.Set("status", "pending");
      return outcome;
    }
    outcome.Set("status", "skipped");
    outcome.Set("code", Napi::Number::New(env, (double)rc));
    outcome.Set("message", crabs_error_name(rc));
    return outcome;
  }
```

Register it in the class definition's InstanceMethod list, next to `InstanceMethod("execute", &Node::Execute),` (line ~1542):

```cpp
      InstanceMethod("replayOp", &Node::ExecuteReplay),
```

- [ ] **Step 4: Type declarations**

`bindings/node/index.d.ts` — inside the existing `Node.create` options type add:

```ts
  skew?: {
    maxSkewMs?: number;               // non-negative safe integer; default 5000 (0 = keep default, not unbounded)
    replayPolicy?: 'reject' | 'clamp'; // default 'reject' (live-identical)
  };
```

and on the Node interface (next to `execute(op: Operation): void;`):

```ts
  replayOp(op: Operation): { status: 'applied' | 'pending' | 'skipped'; code?: number; message?: string };
```

(Update whatever interface/decl literal the file actually uses for `create` options — locate `create(adminId` in the file first.)

- [ ] **Step 5: Write the N-API test**

Create `bindings/node/test/hlc-skew-replay.js` — same scenario as the wasm e2e but without handler plumbing (use direct register writes):

```js
'use strict';
// N-API parity: skew options + replayOp ingest (HLC bounded-skew replay fix).

const { Node } = require('..');

const assert = require('assert');

setTimeout(async () => {
  // Node B replays an op authored on node A 6 seconds ago; B's default live
  // window is 5s, so the LIVE path must refuse and the CLAMP path ingest.
  const nodeA = new Node('author', { ordering: 'hlc' });
  // Mint a trivial signed op via A's node: use register/lock-free type via A
  // — simplest cross-node carrier is a signed 'vote' registered as an admin
  // op with no state effect beyond the log entry.
  await nodeA.registerUser('alice', 'aabbccdd'.repeat(8).slice(0, 66).replace(/^.{2}/, '03'), '');
  // ... build op identical to the wasm test using node.sign + node.execute,
  // serialize() the wire, hand it over.
}, 0);
```

The N-API test file body above is a SKELETON — implement it by copying the working scenario from `bindings/wasm/test/hlc-skew-replay.js` step 3 (Node creation/registration/sign/serialize are the N-API equivalents of the same calls; consult `bindings/node/test/raft.js` for exact N-API op/sign idioms used by sibling tests). The three assertions to land: default live replay throws `protocol_violation`; `replayOp(applied)` materializes under `{skew:{replayPolicy:'clamp'}}`; re-ingest returns `skipped` with code `0x7002`.

- [ ] **Step 6: Rebuild + run**

```bash
npm run build --prefix bindings/node 2>&1 | tail -2 && node bindings/node/test/hlc-skew-replay.js
```
Expected: build OK, test prints its pass line, exit 0. Then the full chain:

```bash
npm test --prefix bindings/node 2>&1 | tail -8
```
Expected: all pass including the new file.

- [ ] **Step 7: Commit**

```bash
git add bindings/node/src/crabs_node.cc bindings/node/index.d.ts bindings/node/test/hlc-skew-replay.js bindings/node/package.json bindings/node/build/Release/crabs_node.node
git commit -m "feat(bindings/node): skew options + replayOp ingest — parity with wasm replay fix"
```

---

### Task 6: Documentation

**Files:**
- Modify: `README.md` (Trust model section — locate with `grep -n 'Trust model' README.md`)
- Modify: `bindings/wasm/README.md` (after the Raft section)

- [ ] **Step 1: README trust-model note**

Add to the README "Trust model" section (or as a bullet in the nearest clock/trust discussion):

```markdown
**HLC skew policy.** Live ops are validated against the receiver's clock
(BOUNDED, 5s default) as before. Replay ingest of a historic op log is a
separate path (`replayOp`/`replayOps`, or the C `state_machine_execute_replay`)
whose policy is configuration, defaulting to the same reject rule; a
consumer may switch it to clamp, which ACCEPTS stamps older than the window
(a log is history, not a freshness race) while future-stamped ops remain
hard-rejected on BOTH paths. Clamping never moves the node's clock backward
and the clamped op keeps its original stamp in the audit log — it sorts
before anything stamped after it. This is a convergence policy, not a trust
extension: signed ops still carry author-stamped HLCs either way.

Two trust caveats for clamp-enabled nodes (code-review findings, Task 1):
1. **Ancient-stamp queue jump.** A signer already authorized on the node can
   stamp its OWN op arbitrarily far in the past and submit it through the
   replay path, ordering it ahead of pending live ops (e.g. to win
   lock/vote contention). Live-ops-only deployments should not enable
   clamp; deployments that do accept insider-stamped ordering bias by
   configuration. A future hardening may add an age ceiling even under
   clamp.
2. **The clamp marker (diagnostic) exists only under the BOUNDED strategy.**
   `{strategy:"naive", replayPolicy:"clamp"}` silently behaves as plain
   NAIVE (no historic marker, no future reject); QUORUM/TRUSTED remain
   fail-closed regardless of the replay policy. Clamp is
   meaningful only for BOUNDED nodes.
```

- [ ] **Step 1b: wasm `index.d.ts` parity (Task 5 review follow-up)**

`bindings/wasm/index.d.ts` — the `NodeOptions` interface (~line 431) predates the skew surface and still lists a stale `strategy?` top-level field the runtime never read. Update it to the shipped contract:

```ts
export interface NodeOptions {
  ordering?: 'hlc' | 'lamport';
  /** Skew configuration (HLC bounded-skew replay fix). Defaults mirror the
   *  C library: BOUNDED / 5000ms / 'reject' on replay. maxSkewMs 0 is a
   *  sentinel for the C default, not "unbounded". */
  strategy?: 'naive' | 'bounded' | 'quorum' | 'strict' | 'trusted';
  skew?: {
    strategy?: 'naive' | 'bounded' | 'quorum' | 'strict' | 'trusted';
    maxSkewMs?: number;                 // non-negative safe integer; 0 = keep C default 5000
    replayPolicy?: 'reject' | 'clamp';  // replay-ingest path policy
  };
}
```

and on the Node interface (locate `execute(op` in the file): the `replayOp`/`replayOps` declarations mirroring `bindings/node/index.d.ts`:

```ts
  replayOp(op: Operation): { status: 'applied' | 'pending' | 'skipped'; code?: number; message?: string };
  replayOps(operations: Operation[]): { applied: number[]; skipped: { index: number; code: number; message: string }[] };
```

- [ ] **Step 2: wasm README — API documentation**

Add a "## Replay skew policy" section to `bindings/wasm/README.md` (before "## Differences from crabs-node"):

```markdown
## Replay skew policy

`Node.create(id, { skew: { strategy, maxSkewMs, replayPolicy } })` configures
the HLC skew handling. Defaults mirror the C library (BOUNDED / 5000ms /
`'reject'`) — a node created without options behaves exactly as before.

Replaying a historic op log is a different trust situation than a live op:
the 5s window defends the live path against well-behaved clocks running
slow, which does not apply to bulk history ingest. On a node created with
`skew.replayPolicy: 'clamp'`, `node.replayOp(op)` / `node.replayOps([...])`
materialize ops stamped further back than the window (clamped into the local
HLC domain — the node's clock never moves backward, future-stamped ops stay
hard-rejected on BOTH paths, and every per-op failure is a recorded skip, not
a batch abort):

```js
const { applied, skipped } = node.replayOps(logOps);   // always continues
for (const skip of skipped) report(`op[${skip.index}] ${skip.code}: ${skip.message}`);
```

The clamped op keeps its ORIGINAL stamp in the audit log (it is signed
material — stamps are never rewritten), so it sorts before everything
stamped after it.

Notes for operators:

- `maxSkewMs: 0` is a SENTINEL for the C-side default (5000), not
  "unbounded"; oversized windows are safe (the consumer clamps to
  INT64_MAX), but choose the window deliberately.
- Replayed GROUP_ORDERED ops surface as `{ status: 'pending' }` (the raft
  ordering module accepted them as pending proposals). They still emit a
  `'change'` event carrying the `ordering_pending` result — do not wire
  those events to live-UI mutation paths; replayed events are
  indistinguishable from live ones (bulk re-ingest re-emits the whole
  history).
- Raft-committed history recovers through the raft module's own persisted
  batches (`raftRecoverFromPersist`), NOT through `replayOps`.
- Per-op replay FAILURES never abort a `replayOps` batch; structurally
  BOUND input does (a destroyed or foreign-module Operation throws
  TypeError) — repair the input array, the batch itself is fine.
- **Skip-matching contract: match on `code`** — skip `message` strings
  differ between bindings (wasm prefixes `replayOp: `; N-API returns the
  bare name) but both contain the name; `code` is the stable selector on
  both.
```

- [ ] **Step 3: Commit**

```bash
git add README.md bindings/wasm/README.md
git commit -m "docs: replay skew policy — clamp semantics, options schema, convergence note"
```

---

### Task 7: Full verification (CLAUDE.md freshness rule + every tier)

- [ ] **Step 1: Full native suite**

```bash
cmake --build build --target testcrabs -- -j8 && ./build/test/testcrabs 2>&1 | tail -3
```
Expected: `[  PASSED  ]` across the board.

- [ ] **Step 2: Rebuild wasm from current source and copy everything downstream**

```bash
source /home/victor/emsdk/emsdk_env.sh && ./build_wasm.sh 2>&1 | tail -4
cp build-wasm/crabs.js build-wasm/crabs.wasm examples/video_platform_p2p/public/
cp build-wasm/crabs.js build-wasm/crabs.wasm build-wasm.dev/crabs.dev.js build-wasm.dev/crabs.dev.wasm cookbook/site/dist/assets/wasm/
```
(`build_wasm.sh` now auto-copies into `bindings/wasm/`; the two downstream copies stay manual — that is what the refreshed CLAUDE.md documents.)

- [ ] **Step 3: wasm binding tests**

```bash
npm test --prefix bindings/wasm 2>&1 | tail -6
```
Expected: full chain passes including `hlc-skew-replay OK: ...`.

- [ ] **Step 4: node binding rebuild + tests** (already run per-task; re-confirm after any last C touch)

```bash
npm run build --prefix bindings/node >/dev/null 2>&1 && npm test --prefix bindings/node 2>&1 | tail -6
```

- [ ] **Step 5: Report the consumer contract**

Include in the final report to the user the exact options schema (from the plan header) for the ResonantDAO Example follow-up (`scripts/feed-walk.mjs` + wrapper `Node.create` plumb + replace `execute` with `replayOps` in its replay loop).

---

## Self-Review notes (already resolved against the spec)

- Spec coverage: req 1 → Tasks 3-5 (public API surface both bindings); req 2 → Tasks 1-4 (replay path + clamp, live default untouched); req 3 → Task 1 clamp invariants + Task 6 ordering caveat docs; req 4 → Task 4 per-op diagnostics + Task 6 prose; acceptance tests 1-3 → Tasks 2 (native three) + 4 (wasm e2e materialize/default); signature/auth/payload untouched throughout.
- Known deliberate deviations: wasm e2e ages ops ~6.1s instead of 15s (crosses the 5s default window; fast CI); the 15s scenario is covered natively by forged stamps (no sleeping). `strategy` override is wasm-only via `skew.strategy` (N-API parity scope documented in Task 5).
- The Task 2 test helper takes a `uuid_fill` byte so distinct test ops never collide with the fixture's shared `test_uuid` or each other under the dedup guard.