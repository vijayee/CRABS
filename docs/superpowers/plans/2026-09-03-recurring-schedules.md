# Recurring Schedules (Timed Transactions v2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A scheduled operation can repeat on a fixed cadence — `interval_ms`, a `repeat_count` (0 = infinite), and an optional `end_at_ms` — with deterministic slot catch-up after downtime.

**Architecture:** `scheduled_operation_t` gains `interval_ms` / `repeat_count` / `end_at_ms` (serialization v7). The materialization tick keeps a recurring entry resident in the pending list and fires it once per due slot (advancing `execute_at += interval_ms`), firing ALL missed slots in slot order on the next tick, removing the entry when a termination rule hits. Occurrences after the first get fresh random uuids (safe: materialization skips signature verification — authorized at submission).

**Tech Stack:** C11, GoogleTest, Emscripten, vanilla JS bindings + web component.

**Spec:** `docs/superpowers/specs/2026-09-03-timed-transactions-design.md` (v2 addendum at the bottom).

---

## File Structure

| File | Responsibility |
|------|----------------|
| `src/CRABS/data_model.h` | 3 new fields on `scheduled_operation_t` |
| `src/Scheduler/scheduler.{h,c}` | `scheduler_schedule_recurring`; recurring materialization branch |
| `src/Serialization/serialization.{h,c}` | v7: write/read the 3 fields per entry |
| `test/test_scheduler.cpp` | Recurring coverage |
| `src/Util/wasm_helpers.c`, `build_wasm.sh` | `crabs_wasm_schedule_recurring` + accessors (both variants) |
| `bindings/wasm/bindings-core.js`, `index.d.ts` | `node.scheduleRecurring`; pendingSchedules rows extended |
| `bindings/wasm/test/schedules.js` | Recurring smoke coverage |
| `src/Devtools/devtools.c`, `bindings/devtools/crabs-devtools.js` | Cadence in snapshot + Config tab |
| `examples/devtools_demo/`, `bindings/wasm/README.md` | Demo button + docs |

Build/test commands: `cmake --build build && ctest --test-dir build` (baseline: only `TestCLI.UserGrantAndRevoke` fails — owner's uncommitted work, never touch); WASM: `source ~/emsdk/emsdk_env.sh && ./build_wasm.sh && cp build-wasm/crabs.js build-wasm/crabs.wasm bindings/wasm/ && cp build-wasm.dev/crabs.dev.js build-wasm.dev/crabs.dev.wasm bindings/wasm/`; smokes `node bindings/wasm/test/{smoke,devtools,schedules}.js`. Style: docs/STYLE_GUIDE.md, no single-letter variables, stage only your files, do not push.

---

### Task R1: Data model, serialization v7, `scheduler_schedule_recurring`

**Files:**
- Modify: `src/CRABS/data_model.h` (3 fields), `src/Scheduler/scheduler.h`, `src/Scheduler/scheduler.c`
- Modify: `src/Serialization/serialization.h` (v7), `src/Serialization/serialization.c`
- Test: `test/test_scheduler.cpp`

- [ ] **Step 1: Failing tests (append to `test/test_scheduler.cpp`)**

```cpp
TEST(SchedulerRecurring, ScheduleRecurringStoresCadence) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");

  uint64_t schedule_id = scheduler_schedule_recurring(
      env.state, 1000000000, 60000, 5, 0, "admin", op);

  EXPECT_NE(schedule_id, 0u);
  const scheduled_operation_t* pending = scheduler_first(env.state);
  ASSERT_NE(pending, nullptr);
  EXPECT_EQ(pending->execute_at_ms, 1000000000u);
  EXPECT_EQ(pending->interval_ms, 60000u);
  EXPECT_EQ(pending->repeat_count, 5u);
  EXPECT_EQ(pending->end_at_ms, 0u);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerRecurring, RecurringValidationRejections) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");

  // interval 0
  EXPECT_EQ(scheduler_schedule_recurring(env.state, 1000, 0, 5, 0, "admin", op), 0u);
  // end before start
  EXPECT_EQ(scheduler_schedule_recurring(env.state, 1000000000, 60000, 5,
                                         999999, "admin", op), 0u);
  // plain invalid-input guards still apply
  EXPECT_EQ(scheduler_schedule_recurring(NULL, 1000, 60000, 5, 0, "admin", op), 0u);
  EXPECT_EQ(scheduler_schedule_recurring(env.state, 1000, 60000, 5, 0, NULL, op), 0u);
  EXPECT_EQ(scheduler_count(env.state), 0u);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerSerialization, RecurringFieldsSurviveRoundtrip) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");
  uint64_t schedule_id = scheduler_schedule_recurring(
      env.state, 1000000000, 60000, 5, 2000000000, "admin", op);
  operation_destroy(op);

  serialized_buffer_t* blob = crabs_serialize_state(env.state);
  ASSERT_NE(blob, nullptr);
  state_t* restored = crabs_deserialize_state(blob->data, blob->len);
  serialized_buffer_destroy(blob);
  ASSERT_NE(restored, nullptr);

  const scheduled_operation_t* pending = scheduler_first(restored);
  ASSERT_NE(pending, nullptr);
  EXPECT_EQ(pending->schedule_id, schedule_id);
  EXPECT_EQ(pending->interval_ms, 60000u);
  EXPECT_EQ(pending->repeat_count, 5u);
  EXPECT_EQ(pending->end_at_ms, 2000000000u);
  state_destroy(restored);

  crabs_test_env_destroy(&env);
}
```

- [ ] **Step 2: Run to verify failure** — `cmake --build build && ctest --test-dir build -R SchedulerRecurring` → FAIL (`scheduler_schedule_recurring` undeclared; `interval_ms` unknown member).

- [ ] **Step 3: Implement**

`src/CRABS/data_model.h` — extend `scheduled_operation_t` (after `execute_at_ms`):

```c
  uint64_t    interval_ms;    // 0 = one-shot
  uint64_t    repeat_count;   // remaining fires; 0 = infinite
  uint64_t    end_at_ms;      // 0 = no end date
```

`src/Scheduler/scheduler.h` — declare:

```c
// Add a recurring pending schedule: fires at start_at_ms, then every
// interval_ms, until repeat_count fires have happened (0 = infinite) or
// execute_at passes end_at_ms (0 = none), whichever comes first. Same
// ownership/return semantics as scheduler_schedule (0 on invalid input).
uint64_t scheduler_schedule_recurring(state_t* state, uint64_t start_at_ms,
                                      uint64_t interval_ms, uint64_t repeat_count,
                                      uint64_t end_at_ms, const char* submitter,
                                      const operation_t* op);
```

`src/Scheduler/scheduler.c` — extract the entry-allocation tail of `scheduler_schedule` into a static `_append_pending(state, execute_at_ms, submitter, op, interval_ms, repeat_count, end_at_ms)` returning the id (shared by both entry points — the one-shot wrapper passes interval 0/count 1/end 0 so v1 behavior is unchanged), and add:

```c
uint64_t scheduler_schedule_recurring(state_t* state, uint64_t start_at_ms,
                                      uint64_t interval_ms, uint64_t repeat_count,
                                      uint64_t end_at_ms, const char* submitter,
                                      const operation_t* op) {
  if (interval_ms == 0) return 0;
  if (end_at_ms != 0 && end_at_ms <= start_at_ms) return 0;
  return _append_pending(state, start_at_ms, submitter, op, interval_ms, repeat_count, end_at_ms);
}
```

`src/Serialization/serialization.c` — bump `CRABS_SERIAL_VERSION` to 7 (`// v7: recurring schedules (interval/repeat_count/end_at)`). In the schedules WRITE loop, after `execute_at_ms`: write `interval_ms`, `repeat_count`, `end_at_ms` (u64 each). In the READ loop (gated `version >= 6`), read the three fields after `execute_at_ms` when `version >= 7`; for `version == 6` blobs the fields default to 0 (entries created via `get_clear_memory`) — restructure the gate so the three reads happen inside a `if (version >= 7)` block nested after the execute_at read, or read them unconditionally in the v6+ block and keep v6 blobs unreadable-if-mismatched (checksum protects integrity; a v6 blob read by a v7 reader would misparse — so GATE the three reads on `version >= 7` explicitly and leave v6 blobs reading only the v6 fields).

- [ ] **Step 3: Run tests** — `ctest --test-dir build -R Scheduler` all pass; full suite baseline.

- [ ] **Step 4: Commit**

```bash
git add src/CRABS/data_model.h src/Scheduler/scheduler.h src/Scheduler/scheduler.c src/Serialization/serialization.h src/Serialization/serialization.c test/test_scheduler.cpp
git commit -m "feat: recurring schedule data model with serialization v7"
```

---

### Task R2: Materialization — recurring branch with catch-up

**Files:**
- Modify: `src/Scheduler/scheduler.c`
- Test: `test/test_scheduler.cpp`

- [ ] **Step 1: Failing tests**

```cpp
TEST(SchedulerRecurring, FiresOnCadenceUntilCountExhausted) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
  ASSERT_EQ(scheduler_schedule_recurring(state, 1000001000, 1000, 3, 0,
                                         "admin", embedded) != 0, true);

  // First fire.
  ASSERT_EQ(scheduler_process_due(state, 1000001000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 1u);
  // Second + third fires (catch-up of one missed slot + on-time slot).
  ASSERT_EQ(scheduler_process_due(state, 1000003000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 0u);  // count exhausted after 3rd fire

  // The embedded uuid appears exactly once (first fire); occurrences 2 and 3
  // have fresh random uuids, so count distinct mint-op entries: total log
  // entries with type "mint" == 3.
  uint32_t mint_entries = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "mint") == 0) mint_entries++;
  }
  EXPECT_EQ(mint_entries, 3u);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerRecurring, EndAtTerminatesBeforeNextFire) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
  // start 1000001000, interval 1000, infinite, end_at 1000002000 → fires at
  // 1000001000 and 1000002000, then the third slot (1000003000) is past end.
  ASSERT_EQ(scheduler_schedule_recurring(state, 1000001000, 1000, 0, 1000002000,
                                         "admin", embedded) != 0, true);

  ASSERT_EQ(scheduler_process_due(state, 1000003000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 0u);  // end_at reached → removed
  uint32_t mint_entries = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "mint") == 0) mint_entries++;
  }
  EXPECT_EQ(mint_entries, 2u);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerRecurring, CatchUpFiresAllMissedSlotsInOrder) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
  ASSERT_EQ(scheduler_schedule_recurring(state, 1000001000, 1000, 0, 0,
                                         "admin", embedded) != 0, true);

  // Jump 5 slots ahead: one tick fires all 5 missed occurrences in order.
  // (Tick between slots — 1000005500 — so the 5 slots 1000001000..5000 fire
  // and the next slot 1000006000 remains future.)
  ASSERT_EQ(scheduler_process_due(state, 1000005500u), CRABS_SUCCESS);
  uint32_t mint_entries = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "mint") == 0) mint_entries++;
  }
  EXPECT_EQ(mint_entries, 5u);
  // Entry stays resident (infinite) with execute_at advanced to the next slot.
  ASSERT_EQ(scheduler_count(state), 1u);
  EXPECT_EQ(scheduler_first(state)->execute_at_ms, 1000006000u);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerRecurring, OneShotEntriesUnaffected) {
  // A one-shot (interval 0) entry must behave exactly as before: removed from
  // the list before materialization, consumed after one fire.
  // (Reuse DueOpMaterializedExactlyOnce's flow but assert it still passes.)
}
```

For the last test, do not duplicate — simply confirm the existing `SchedulerMaterialize.DueOpMaterializedExactlyOnce` still passes in the full run (the recurring branch must not change one-shot behavior).

- [ ] **Step 2: Run to verify failure** — `ctest -R SchedulerRecurring` → FAIL.

- [ ] **Step 3: Implement the recurring branch in `scheduler_process_due`**

Restructure: after finding `entry` by id and BEFORE the one-shot removal, branch on `entry->interval_ms`:

```c
    if (entry->interval_ms == 0) {
      // ---- one-shot (v1 path, unchanged) ----
      *link = entry->next;   // remove first (idempotency guard)
      ... existing deserialize/skip/execute/failure handling, frees ...
      continue;
    }

    // Recurring: fire all due slots in order; the entry stays resident.
    // Termination bookkeeping: repeat_count is "remaining fires" where
    // 0 = INFINITE (never decremented). A finite series counts down and is
    // removed the moment its count HITS 0 after a fire (series_exhausted).
    bool bytes_corrupt = false;
    bool series_exhausted = false;
    uint32_t fires_this_tick = 0;
    while (entry->execute_at_ms <= now_ms) {
      if (entry->end_at_ms != 0 && entry->execute_at_ms > entry->end_at_ms) break;

      // (de)materialize one occurrence:
      operation_t* occurrence = crabs_deserialize_operation(entry->op_bytes, entry->op_len);
      if (occurrence == NULL) {
        uint8_t failure_uuid[CRABS_UUID_SIZE];
        memset(failure_uuid, 0, sizeof(failure_uuid));
        crypto_random_bytes(failure_uuid, CRABS_UUID_SIZE);  // best effort (zero fallback)
        state_machine_log_schedule_failure(state, failure_uuid, entry->submitter);
        bytes_corrupt = true;
        break;  // undecodable: terminate the series
      }
      if (fires_this_tick > 0) {
        crypto_random_bytes(occurrence->uuid, CRABS_UUID_SIZE);  // fresh identity per occurrence
      }
      if (_uuid_in_log(state, occurrence->uuid)) {
        operation_destroy(occurrence);
      } else {
        crabs_error_e fire_rc = state_machine_execute_scheduled(state, occurrence);
        if (fire_rc != CRABS_SUCCESS && fire_rc != CRABS_ERR_ALREADY_EXECUTED) {
          state_machine_log_schedule_failure(state, occurrence->uuid, occurrence->signer_id);
        }
        operation_destroy(occurrence);
      }
      fires_this_tick++;

      // Advance cadence and termination bookkeeping. Decrement ONLY finite
      // counts (0 = infinite sentinel, never decremented).
      entry->execute_at_ms += entry->interval_ms;
      if (entry->repeat_count != 0) {
        entry->repeat_count--;
        if (entry->repeat_count == 0) {
          series_exhausted = true;  // last allowed fire consumed
          break;
        }
      }
      if (entry->end_at_ms != 0 && entry->execute_at_ms > entry->end_at_ms) break;

      // A handler may have cancelled the entry mid-loop — re-find by identity
      // and stop if it was unlinked (it is freed; do not touch it further).
      scheduled_operation_t** recheck_link = &state->scheduled_operations;
      bool still_linked_mid_loop = false;
      while (*recheck_link != NULL) {
        if (*recheck_link == entry) { still_linked_mid_loop = true; break; }
        recheck_link = &(*recheck_link)->next;
      }
      if (!still_linked_mid_loop) return CRABS_SUCCESS;  // cancelled mid-series
    }

    // Termination: remove the entry when the count is exhausted, the next
    // slot is past end_at, or the series was terminated by corrupt bytes.
    // (Re-find by identity first — a handler may have cancelled the entry,
    // unlinking and freeing it; touching `entry` then would be use-after-free.)
    scheduled_operation_t** recheck = &state->scheduled_operations;
    bool still_linked = false;
    while (*recheck != NULL) {
      if (*recheck == entry) { still_linked = true; break; }
      recheck = &(*recheck)->next;
    }
    if (!still_linked) continue;

    bool past_end = (entry->end_at_ms != 0 && entry->execute_at_ms > entry->end_at_ms);
    if (series_exhausted || past_end || bytes_corrupt) {
      *link = entry->next;
      free(entry->op_bytes);
      free(entry);
    }
```

Write this concretely (no ellipses — the implementer must resolve `fires_used` by simply decrementing `repeat_count` in place: finite series start with repeat_count = N; infinite has repeat_count == 0 and never terminates by count. The `series_terminated` case is the undecodable-bytes break — track with a local bool `bool bytes_corrupt = false;` set before the break). Keep the re-entrancy guard and the `due_ids` snapshot unchanged; a recurring entry that is still due after its own advance (interval elapsed within the same tick) is naturally handled by the while loop.

NOTES the implementer must respect:
- The uuid-in-log skip on the FIRST occurrence keeps v1 semantics; occurrences 2+ carry fresh uuids so `_uuid_in_log` cannot block them.
- `state_machine_execute_scheduled` skips signature verification (fresh uuids are safe).
- The entry pointer stays valid through the loop EXCEPT if a handler cancels it — hence the recheck before the termination removal. The fire loop itself must re-find the entry by id after EACH fire if handlers can cancel (do the cheap thing: re-find by identity in the linked list after each fire; break out if unlinked).
- Failure of one occurrence does NOT terminate the series (record + continue) — only undecodable bytes does.

- [ ] **Step 4: Run tests** — `ctest -R Scheduler` all pass; full suite baseline.

- [ ] **Step 5: De-wonk audit** (invoke the de-wonk skill), then commit:

```bash
git add src/Scheduler/scheduler.c test/test_scheduler.cpp
git commit -m "feat: materialize recurring schedules with slot-ordered catch-up"
```

---

### Task R3: Bindings, devtools cadence, demo, docs

**Files:**
- Modify: `src/Util/wasm_helpers.c`, `build_wasm.sh`, `bindings/wasm/bindings-core.js`, `index.d.ts`, `bindings/wasm/test/schedules.js`
- Modify: `src/Devtools/devtools.c`, `test/test_devtools.cpp`, `bindings/devtools/crabs-devtools.js`
- Modify: `examples/devtools_demo/demo.js`, `examples/devtools_demo/index.html`, `bindings/wasm/README.md`

- [ ] **Step 1: C helper** — `crabs_wasm_schedule_recurring(am, inner_op, start_at_ms, interval_ms, repeat_count, end_at_ms)` mirroring `crabs_wasm_schedule` (including the `state_machine_validate` gate), added to BASE_EXPORTS in build_wasm.sh.
- [ ] **Step 2: JS** — `node.scheduleRecurring(innerOp, startAtMs, intervalMs, repeatCount, endAtMs)` (BigInt args, throws on id 0; `endAtMs` 0 = none). `pendingSchedules()` rows gain `intervalMs`, `repeatCount`, `endAt` from three new C accessors (`crabs_wasm_schedule_interval/repeat_count/end_at`). `index.d.ts` declarations.
- [ ] **Step 3: Devtools** — `_write_schedules_json` adds the three fields; Config tab rows show cadence (`every 60s × 24` / `every 60s ∞` / `until 12:00`); C test `DevtoolsSnapshot.RecurringSchedulesSection` asserts the new fields.
- [ ] **Step 4: WASM smoke** — extend `test/schedules.js`: schedule 3-fire series with 1s interval via injected `processSchedules` ticks; assert 3 materializations then removal; cancel mid-series works.
- [ ] **Step 5: Demo + README** — add a "Schedule 3 mints (every 15s)" button (handler `scheduleMint` with `node.scheduleRecurring(mintOp, Date.now() + 15000, 15000, 3, 0)`); update hint lines; README Timed transactions section gains a recurring paragraph + example; rebuild artifacts; all smoke tests pass.
- [ ] **Step 6: Browser verification** (headless Chrome via CDP, as established): schedule the 3-mint series → Config shows `every 15s × 3` → force ticks → three mint Timeline entries + tokens = 3 → row disappears. Screenshot to `examples/devtools_demo/recurring_demo.png`, committed.
- [ ] **Step 7: Commit**

```bash
git add src/Util/wasm_helpers.c build_wasm.sh bindings/wasm/bindings-core.js bindings/wasm/index.d.ts bindings/wasm/test/schedules.js bindings/wasm/crabs.js bindings/wasm/crabs.wasm bindings/wasm/crabs.dev.js bindings/wasm/crabs.dev.wasm src/Devtools/devtools.c test/test_devtools.cpp bindings/devtools/crabs-devtools.js examples/devtools_demo/ bindings/wasm/README.md
git commit -m "feat: recurring schedule bindings, devtools cadence display, demo and docs"
```

---

### Task R4: Final verification

- Full native suite (baseline failure set only), all three WASM smoke tests, de-wonk audit of the recurring branch, final review dispatch.

---

## Self-Review Notes

- Spec coverage: cadence anchoring (execute_at += interval), count+end termination, catch-up-all-in-order, per-occurrence uuid identity, scheduleRecurring API with validation, devtools cadence, tests, demo. Cross-node reconciliation documented as the application's responsibility (per user).
- The recurring materialization branch reuses v1's failure-record and idempotency machinery; one-shot behavior is gated behind `interval_ms == 0` and covered by the existing test suite.
- Per-occurrence uuid randomness means the 2nd+ occurrences are NOT byte-identical to the signed op — safe only because materialization skips signature verification (authorized at submission). Comment this loudly in the code.