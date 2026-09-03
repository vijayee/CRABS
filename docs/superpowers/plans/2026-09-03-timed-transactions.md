# Timed Transactions (Scheduler) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Operations whose effects apply at a future time — a signed op is submitted now, stored durably in the replicated state, and materialized exactly as signed when a node's authenticated clock passes the scheduled time.

**Architecture:** New `src/Scheduler/` module owning a pending list on `state_t`. The `__schedule__` builtin op embeds a fully-signed inner op; it flows through the normal pipeline and, on acceptance, stores the embedded op after `state_machine_validate` (new extraction of the pipeline's check steps) passes. At the end of every `execute` (same slot as trigger processing), `scheduler_process_due` materializes due entries through `state_machine_execute_internal(skip_authorization=true)` — transitions/dedup/handlers/log all apply, user-facing auth and the ordering check are skipped (authorized at submission). Failures are recorded as `__schedule_failed__` log entries and never propagated to the enclosing op.

**Tech Stack:** C11 (Emscripten for WASM), GoogleTest, Emscripten exports, vanilla JS bindings + web component.

**Spec:** `docs/superpowers/specs/2026-09-03-timed-transactions-design.md`

---

## File Structure

| File | Responsibility |
|------|----------------|
| `src/Scheduler/scheduler.h` | Public API: schedule/cancel/count/process_due/first |
| `src/Scheduler/scheduler.c` | Pending-list management + materialization tick |
| `src/CRABS/data_model.h` / `.c` | `state_t` gains `scheduled_operations` + `schedule_seq`; destroy cleanup |
| `src/StateMachine/state_machine.h` / `.c` | `state_machine_validate`, `state_machine_execute_scheduled`, `_execute_internal(skip_authorization)`, `__schedule__`/`__cancel_schedule__` handlers, dispatch + builtin list |
| `src/Serialization/serialization.{h,c}` | Wire-format v6: schedules section |
| `test/test_scheduler.cpp` | Native coverage for the whole feature |
| `src/Util/wasm_helpers.c` | `crabs_wasm_schedule_*` exports (dev-independent, both artifacts) |
| `bindings/wasm/bindings-core.js` | `node.schedule/cancelSchedule/processSchedules/pendingSchedules` |
| `bindings/wasm/index.d.ts` | Declarations for the new methods |
| `bindings/wasm/test/schedules.js` | WASM smoke test |
| `src/Devtools/devtools.c` | Snapshot `"schedules"` section |
| `bindings/devtools/crabs-devtools.js` | Config tab Schedules section |

Build commands: native `cmake --build build && ctest --test-dir build` (expect 1315/1316+new; the sole `TestCLI.UserGrantAndRevoke` failure is pre-existing from the owner's uncommitted work — never touch it). WASM: `source ~/emsdk/emsdk_env.sh && ./build_wasm.sh && cp build-wasm/crabs.js build-wasm/crabs.wasm bindings/wasm/ && cp build-wasm.dev/crabs.dev.js build-wasm.dev/crabs.dev.wasm bindings/wasm/`. Smoke tests: `node bindings/wasm/test/smoke.js`, `node bindings/wasm/test/devtools.js`, `node bindings/wasm/test/schedules.js`.

Conventions: `docs/STYLE_GUIDE.md` — 2-space indent, `_t` types, `module_action()` naming, `get_memory`/`get_clear_memory`, NEVER single-letter variables (use `entry_index`, `schedule_index`, etc.).

---

### Task 1: Scheduler data model, list management, serialization v6

**Files:**
- Create: `src/Scheduler/scheduler.h`, `src/Scheduler/scheduler.c`
- Modify: `src/CRABS/data_model.h` (state_t fields), `src/CRABS/data_model.c` (destroy cleanup)
- Modify: `src/Serialization/serialization.h` (version bump), `src/Serialization/serialization.c` (section write/read)
- Test: `test/test_scheduler.cpp` (new), `test/CMakeLists.txt`

- [ ] **Step 1: Add the data model to `src/CRABS/data_model.h`**

After the `Log Entry` section (before `State`), add:

```c
// ============================================================
// Scheduled Operation (timed transactions v1)
// ============================================================
typedef struct scheduled_operation_t {
  uint64_t    schedule_id;    // per-state monotonic counter
  uint64_t    execute_at_ms;  // epoch ms; compared against authenticated now
  char        submitter[CRABS_MAX_USER_ID];
  uint8_t*    op_bytes;       // crabs_serialize_operation of the embedded op
  uint32_t    op_len;
  struct scheduled_operation_t* next;
} scheduled_operation_t;
```

In `state_t` (after the `trigger_t* triggers; uint32_t trigger_count;` lines), add:

```c
  // Timed transactions (v1): pending operations awaiting materialization.
  scheduled_operation_t* scheduled_operations;
  uint64_t        schedule_seq;
```

- [ ] **Step 2: Free the pending list in `state_destroy` (`src/CRABS/data_model.c`)**

Insert after the `state->triggers` cleanup block (before the `tx_manager` block):

```c
  scheduler_destroy_all(state);
```

And add the include at the top of `data_model.c` (with the other module includes):

```c
#include "../Scheduler/scheduler.h"
```

- [ ] **Step 3: Create `src/Scheduler/scheduler.h`**

```c
//
// Created by victor on 9/3/25.
//

#ifndef CRABS_SCHEDULER_H
#define CRABS_SCHEDULER_H

#include <stdint.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"

// Add a pending scheduled operation. `op` is the embedded operation (already
// fully signed by its authorizer); it is serialized with
// crabs_serialize_operation and stored. Returns the new schedule_id, or 0 on
// invalid input (NULL state/op, empty submitter) or serialization failure.
// The caller keeps ownership of `op`.
uint64_t scheduler_schedule(state_t* state, uint64_t execute_at_ms,
                            const char* submitter, const operation_t* op);

// Remove a pending schedule by id. CRABS_ERR_RESOURCE_NOT_FOUND when absent.
crabs_error_e scheduler_cancel(state_t* state, uint64_t schedule_id);

// Number of pending schedules.
uint32_t scheduler_count(const state_t* state);

// Head of the pending list (oldest insertion first). NULL when empty.
const scheduled_operation_t* scheduler_first(const state_t* state);

// Materialize every pending schedule whose execute_at_ms <= now_ms.
// Failures are recorded as __schedule_failed__ log entries and never
// propagated. Returns CRABS_SUCCESS.
crabs_error_e scheduler_process_due(state_t* state, uint64_t now_ms);

// Free the entire pending list (called from state_destroy).
void scheduler_destroy_all(state_t* state);

#endif // CRABS_SCHEDULER_H
```

- [ ] **Step 4: Write the failing tests — create `test/test_scheduler.cpp`**

```cpp
//
// Scheduler (timed transactions) tests.
//

#include <gtest/gtest.h>
#include <cstring>
#include <string>

extern "C" {
#include "Scheduler/scheduler.h"
#include "CRABS/data_model.h"
#include "StateMachine/state_machine.h"
#include "Serialization/serialization.h"
#include "Crypto/crypto.h"
#include "test_helpers.h"
}

static operation_t* make_counter_op(const char* op_type, const char* signer) {
  operation_t* op = operation_create(op_type);
  strncpy(op->signer_id, signer, CRABS_MAX_USER_ID - 1);
  return op;
}

TEST(SchedulerList, ScheduleStoresPendingEntry) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");

  uint64_t schedule_id = scheduler_schedule(env.state, 9999999, "admin", op);

  EXPECT_NE(schedule_id, 0u);
  EXPECT_EQ(scheduler_count(env.state), 1u);
  const scheduled_operation_t* pending = scheduler_first(env.state);
  ASSERT_NE(pending, nullptr);
  EXPECT_EQ(pending->schedule_id, schedule_id);
  EXPECT_EQ(pending->execute_at_ms, 9999999u);
  EXPECT_STREQ(pending->submitter, "admin");
  EXPECT_GT(pending->op_len, 0u);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerList, ScheduleRejectsInvalidInput) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");

  EXPECT_EQ(scheduler_schedule(env.state, 1000, NULL, op), 0u);
  EXPECT_EQ(scheduler_schedule(env.state, 1000, "", op), 0u);
  EXPECT_EQ(scheduler_schedule(env.state, 1000, "admin", NULL), 0u);
  EXPECT_EQ(scheduler_schedule(NULL, 1000, "admin", op), 0u);
  EXPECT_EQ(scheduler_count(env.state), 0u);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerList, ScheduleIdsAreMonotonic) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* first_op = make_counter_op("mint", "admin");
  operation_t* second_op = make_counter_op("mint", "admin");

  uint64_t first_id = scheduler_schedule(env.state, 1000, "admin", first_op);
  uint64_t second_id = scheduler_schedule(env.state, 2000, "admin", second_op);
  EXPECT_GT(second_id, first_id);
  EXPECT_EQ(scheduler_count(env.state), 2u);

  operation_destroy(first_op);
  operation_destroy(second_op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerList, CancelRemovesPendingEntry) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");

  uint64_t keep_id = scheduler_schedule(env.state, 1000, "admin", op);
  uint64_t drop_id = scheduler_schedule(env.state, 2000, "admin", op);

  EXPECT_EQ(scheduler_cancel(env.state, keep_id), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(env.state), 1u);
  EXPECT_EQ(scheduler_first(env.state)->schedule_id, keep_id + 1);

  EXPECT_EQ(scheduler_cancel(env.state, 424242), CRABS_ERR_RESOURCE_NOT_FOUND);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerSerialization, PendingSetSurvivesRoundtrip) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_counter_op("mint", "admin");
  uint64_t schedule_id = scheduler_schedule(env.state, 1234567, "admin", op);
  operation_destroy(op);

  serialized_buffer_t* blob = crabs_serialize_state(env.state);
  ASSERT_NE(blob, nullptr);
  state_t* restored = crabs_deserialize_state(blob->data, blob->len);
  serialized_buffer_destroy(blob);
  ASSERT_NE(restored, nullptr);

  EXPECT_EQ(scheduler_count(restored), 1u);
  const scheduled_operation_t* pending = scheduler_first(restored);
  ASSERT_NE(pending, nullptr);
  EXPECT_EQ(pending->schedule_id, schedule_id);
  EXPECT_EQ(pending->execute_at_ms, 1234567u);
  EXPECT_STREQ(pending->submitter, "admin");
  EXPECT_GT(pending->op_len, 0u);
  state_destroy(restored);

  crabs_test_env_destroy(&env);
}
```

Register the test in `test/CMakeLists.txt` (add `test_scheduler.cpp` after `test_devtools.cpp` in the `add_executable` list).

- [ ] **Step 5: Run tests to verify they fail**

Run: `cmake --build build && ctest --test-dir build -R Scheduler -v`
Expected: FAIL — `Scheduler/scheduler.h: No such file or directory`

- [ ] **Step 6: Create `src/Scheduler/scheduler.c`**

```c
//
// Created by victor on 9/3/25.
//
// Scheduler: timed transactions. Pending operations are stored durably in
// the state (serialized with crabs_serialize_state) and materialized when a
// node's authenticated clock passes the scheduled time.
//

#include "scheduler.h"
#include <stdlib.h>
#include <string.h>
#include "../Serialization/serialization.h"
#include "../StateMachine/state_machine.h"

uint32_t scheduler_count(const state_t* state) {
  if (state == NULL) return 0;
  uint32_t count = 0;
  for (const scheduled_operation_t* entry = state->scheduled_operations;
       entry != NULL; entry = entry->next) {
    count++;
  }
  return count;
}

const scheduled_operation_t* scheduler_first(const state_t* state) {
  return state ? state->scheduled_operations : NULL;
}

uint64_t scheduler_schedule(state_t* state, uint64_t execute_at_ms,
                            const char* submitter, const operation_t* op) {
  if (state == NULL || op == NULL || submitter == NULL || submitter[0] == '\0') {
    return 0;
  }

  serialized_buffer_t* serialized = crabs_serialize_operation(op);
  if (serialized == NULL) return 0;

  scheduled_operation_t* entry =
      (scheduled_operation_t*)get_clear_memory(sizeof(scheduled_operation_t));
  if (entry == NULL) {
    serialized_buffer_destroy(serialized);
    return 0;
  }
  entry->schedule_id = ++state->schedule_seq;
  entry->execute_at_ms = execute_at_ms;
  strncpy(entry->submitter, submitter, CRABS_MAX_USER_ID - 1);
  entry->op_bytes = (uint8_t*)get_clear_memory(serialized->len);
  if (entry->op_bytes == NULL) {
    free(entry);
    serialized_buffer_destroy(serialized);
    return 0;
  }
  memcpy(entry->op_bytes, serialized->data, serialized->len);
  entry->op_len = serialized->len;
  serialized_buffer_destroy(serialized);

  // Append at the tail so iteration order follows submission order; due
  // entries are materialized in execute_at order by scheduler_process_due.
  if (state->scheduled_operations == NULL) {
    state->scheduled_operations = entry;
  } else {
    scheduled_operation_t* tail = state->scheduled_operations;
    while (tail->next != NULL) tail = tail->next;
    tail->next = entry;
  }
  return entry->schedule_id;
}

crabs_error_e scheduler_cancel(state_t* state, uint64_t schedule_id) {
  if (state == NULL) return CRABS_ERR_INVALID_PARAM;
  scheduled_operation_t** link = &state->scheduled_operations;
  while (*link != NULL) {
    if ((*link)->schedule_id == schedule_id) {
      scheduled_operation_t* removed = *link;
      *link = removed->next;
      free(removed->op_bytes);
      free(removed);
      return CRABS_SUCCESS;
    }
    link = &(*link)->next;
  }
  return CRABS_ERR_RESOURCE_NOT_FOUND;
}

void scheduler_destroy_all(state_t* state) {
  if (state == NULL) return;
  scheduled_operation_t* entry = state->scheduled_operations;
  while (entry != NULL) {
    scheduled_operation_t* next = entry->next;
    free(entry->op_bytes);
    free(entry);
    entry = next;
  }
  state->scheduled_operations = NULL;
}
```

Add the two materialization-related functions as stubs for now (implemented in Task 4):

```c
crabs_error_e scheduler_process_due(state_t* state, uint64_t now_ms) {
  (void)state;
  (void)now_ms;
  return CRABS_SUCCESS;
}
```

Also add to the end of `scheduler.h` (declared there so data_model.c can call it):

```c
void scheduler_destroy_all(state_t* state);
```

(The header from Step 3 above already declares `scheduler_destroy_all` — if you followed Step 3 exactly, do NOT add it a second time. The header must declare exactly: `scheduler_schedule`, `scheduler_cancel`, `scheduler_count`, `scheduler_first`, `scheduler_process_due`, `scheduler_destroy_all`, plus `CRABS_SCHEDULER_MAX_DUE_PER_TICK`.)

- [ ] **Step 7: Serialization v6 — schedules section**

In `src/Serialization/serialization.h`, bump:

```c
#define CRABS_SERIAL_VERSION    6           // v6: adds scheduled_operations (timed transactions)
```

In `crabs_serialize_state` (serialization.c:1215), after the log-entries loop and BEFORE the checksum block, add:

```c
  // schedules (v6): pending timed transactions
  uint32_t schedule_count = 0;
  for (const scheduled_operation_t* schedule_entry = state->scheduled_operations;
       schedule_entry != NULL; schedule_entry = schedule_entry->next) {
    schedule_count++;
  }
  _write_uint32_le(buf, schedule_count);
  for (const scheduled_operation_t* schedule_entry = state->scheduled_operations;
       schedule_entry != NULL; schedule_entry = schedule_entry->next) {
    _write_uint64_le(buf, schedule_entry->schedule_id);
    _write_uint64_le(buf, schedule_entry->execute_at_ms);
    _write_bytes(buf, (const uint8_t*)schedule_entry->submitter, CRABS_MAX_USER_ID);
    _write_uint32_le(buf, schedule_entry->op_len);
    _write_bytes(buf, schedule_entry->op_bytes, schedule_entry->op_len);
  }
```

In `crabs_deserialize_state`, after the log-entries loop and BEFORE the checksum... note the checksum is verified FIRST (before parsing), so insert the schedule read after the log-entries read, guarded by format version:

```c
  // schedules (v6+): pending timed transactions
  if (version >= 6) {
    uint32_t schedule_count;
    if (!_read_uint32_le(&buf, &schedule_count)) goto fail;
    if (schedule_count > CRABS_DESER_MAX_ITEMS) goto fail;
    for (uint32_t schedule_index = 0; schedule_index < schedule_count; schedule_index++) {
      scheduled_operation_t* entry =
          (scheduled_operation_t*)get_clear_memory(sizeof(scheduled_operation_t));
      if (!_read_uint64_le(&buf, &entry->schedule_id) ||
          !_read_uint64_le(&buf, &entry->execute_at_ms)) {
        free(entry);
        goto fail;
      }
      if (!_read_bytes(&buf, (uint8_t*)entry->submitter, CRABS_MAX_USER_ID)) {
        free(entry);
        goto fail;
      }
      if (!_read_uint32_le(&buf, &entry->op_len) || entry->op_len == 0 ||
          entry->op_len > CRABS_DESER_MAX_LOG) {
        free(entry);
        goto fail;
      }
      entry->op_bytes = (uint8_t*)get_clear_memory(entry->op_len);
      if (entry->op_bytes == NULL ||
          !_read_bytes(&buf, entry->op_bytes, entry->op_len)) {
        free(entry->op_bytes);
        free(entry);
        goto fail;
      }
      entry->next = state->scheduled_operations;
      state->scheduled_operations = entry;
    }
  }
```

Notes: verify `_read_bytes` exists in serialization.c with signature `static bool _read_bytes(read_buf_t* buf, uint8_t* out, size_t len)` — check the actual name/signature near the other `_read_*` helpers and use it; if only a different helper exists, add the missing `_read_bytes` next to it. Entry order after read is reversed relative to write order — acceptable (order only affects materialization ordering within a tick); the roundtrip test asserts contents, not order.

- [ ] **Step 8: Run tests to verify they pass**

Run: `cmake --build build && ctest --test-dir build -R Scheduler -v`
Expected: PASS (5 tests)

- [ ] **Step 9: Run the full suite for regressions**

Run: `ctest --test-dir build`
Expected: all pass except the known `TestCLI.UserGrantAndRevoke` (any serialization tests must still pass — old v5 blobs remain readable since the section read is version-gated).

- [ ] **Step 9b: Run the de-wonk audit**

Invoke the de-wonk skill before declaring the task done.

- [ ] **Step 10: Commit**

```bash
git add src/Scheduler/ src/CRABS/data_model.h src/CRABS/data_model.c src/Serialization/serialization.h src/Serialization/serialization.c test/test_scheduler.cpp test/CMakeLists.txt
git commit -m "feat: add scheduler pending-set data model with serialization v6"
```

---

### Task 2: Pipeline refactor — `state_machine_execute_internal` + `state_machine_validate`

**Files:**
- Modify: `src/StateMachine/state_machine.h` (new public functions), `src/StateMachine/state_machine.c`
- Test: `test/test_scheduler.cpp`

- [ ] **Step 1: Write the failing test (append to `test/test_scheduler.cpp`)**

```cpp
static operation_t* make_signed_view_op(crabs_test_env_t* env) {
  operation_t* op = operation_create("view");
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(env->state->attr_machine, env->admin_key, op);
  return op;
}

TEST(SchedulerValidate, ValidOpPassesWithoutApplying) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_signed_view_op(&env);

  EXPECT_EQ(state_machine_validate(env.state, op), CRABS_SUCCESS);
  // Nothing applied: no log entry, version unchanged.
  EXPECT_EQ(env.state->log_count, 0u);
  EXPECT_EQ(env.state->version, 0u);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerValidate, BadSignatureRejectedWithoutApplying) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_signed_view_op(&env);
  op->signature[0] ^= 0xFF;

  EXPECT_EQ(state_machine_validate(env.state, op), CRABS_ERR_UNAUTHORIZED);
  EXPECT_EQ(env.state->log_count, 0u);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerValidate, MissingPolicyRejectedWithoutApplying) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* op = make_signed_view_op(&env);
  // "nosuchop" has no registered policy in the env.
  strncpy(op->type, "nosuchop", CRABS_MAX_OP_NAME - 1);
  memset(op->signature, 0, CRABS_SIG_SIZE);

  EXPECT_EQ(state_machine_validate(env.state, op), CRABS_ERR_UNAUTHORIZED);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cmake --build build && ctest --test-dir build -R Scheduler`
Expected: FAIL — `state_machine_validate` undeclared.

- [ ] **Step 3: Refactor `state_machine.c` into check helpers + `execute_internal`**

The goal: the authorization-only check blocks become static helpers, the pipeline body moves into `static crabs_error_e state_machine_execute_internal(state_t* state, operation_t* op, bool skip_authorization)`, and both public entry points wrap it. NO behavior change for the normal path (every check stays in its current order and applies in both modes unless noted).

Add to `state_machine.h`:

```c
// Check-only pipeline: authorization (signature + policy + key staleness +
// scheme + co-signatures) and transition feasibility, without applying
// anything. Used by the scheduler to authorize a scheduled operation at
// submission time.
crabs_error_e  state_machine_validate(state_t* state, const operation_t* op);

// Internal executor for scheduled materialization: runs transitions, dedup,
// handlers, and logging, but skips user-facing authorization (already
// enforced at submission) and the R7-11 ordering check.
crabs_error_e  state_machine_execute_scheduled(state_t* state, operation_t* op);
```

In `state_machine.c`:

(a) Extract step 3 (lines ~477-530: policy lookup, preprocess, serialize-for-signing, `crypto_verify_operation_auth[_v2]`, authorized check) into:

```c
// Step 3 (§10.3): authorization. Resolves the policy (CONTAINS operators and
// {user_id} placeholders) and verifies the signature. Returns CRABS_SUCCESS
// when authorized; fills pp_out for later co-signature verification.
static crabs_error_e _verify_operation_authorization(state_t* state,
                                                     operation_t* op,
                                                     policy_preprocess_result_t* pp_out) {
  if (state->attr_machine == NULL) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  const char* policy = state_find_policy(state, op->type);
  if (policy == NULL) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  policy_preprocess_result_t pp = preprocess_policy(policy, state, op->signer_id);
  if (!pp.resolved_ok) {
    return CRABS_ERR_UNAUTHORIZED;
  }
  *pp_out = pp;

  verify_mode_e mode = (op->signer_id[0] != '\0') ? VERIFY_MODE_A : VERIFY_MODE_B;

  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  if (ser == NULL) {
    return CRABS_ERR_SERIALIZATION_ERROR;
  }
  if (state->abe_mk == NULL) {
    serialized_buffer_destroy(ser);
    return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  }

  verify_result_t vr;
  if (op->sig_scheme != SCHEME_UNSPECIFIED || op->key_id[0] != '\0') {
    vr = crypto_verify_operation_auth_v2(
        state->abe_mk, pp.abe_policy, state->attr_machine,
        ser->data, ser->len,
        op->signature, CRABS_SIG_SIZE,
        op->signer_id, op->key_id, op->sig_scheme, mode);
  } else {
    vr = crypto_verify_operation_auth(
        state->abe_mk, pp.abe_policy, state->attr_machine,
        ser->data, ser->len,
        op->signature, op->signer_id, mode);
  }
  serialized_buffer_destroy(ser);

  if (!vr.authorized) {
    return vr.error;
  }
  return CRABS_SUCCESS;
}
```

(b) Extract step 4 (transition checks, lines ~578-585) into:

```c
static crabs_error_e _check_transitions(state_t* state, const operation_t* op) {
  for (uint32_t resource_index = 0; resource_index < op->resource_count; resource_index++) {
    data_item_t* item = state_find_item(state, op->resources[resource_index]);
    if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
    if (item->protocol_state != op->required_state[resource_index]) {
      return CRABS_ERR_PROTOCOL_VIOLATION;
    }
  }
  return CRABS_SUCCESS;
}
```

(c) Extract step 6 (key version, ~lines 629-640) into `_check_key_version(state_t* state, const operation_t* op)` (body unchanged, returns CRABS_SUCCESS at the end).

(d) Extract step 6b (scheme constraints, ~lines 642-672) into `_check_scheme_constraints(state_t* state, const operation_t* op)` (body unchanged).

(e) Extract step 6c (co-signatures, ~lines 674-717, needs `pp`) into:

```c
static crabs_error_e _verify_co_signatures(state_t* state, operation_t* op,
                                           const policy_preprocess_result_t* pp) {
  // body of the existing step 6c block + the threshold check at ~714-717
}
```

(f) Rewrite `state_machine_execute` as:

```c
static crabs_error_e state_machine_execute_internal(state_t* state, operation_t* op,
                                                    bool skip_authorization) {
  // Step 1/2 (prune) ... unchanged ...
  // Step 3 authorization:
  policy_preprocess_result_t pp = {0};
  if (!skip_authorization) {
    crabs_error_e auth_rc = _verify_operation_authorization(state, op, &pp);
    if (auth_rc != CRABS_SUCCESS) return auth_rc;
  }
  // Step 3b tx accept: BOTH modes (materialization still wants uuid dedup).
  // Step 3c ordering check: wrap in `if (!skip_authorization) { ... }`.
  // Step 4: `crabs_error_e rc = _check_transitions(state, op); if (rc != CRABS_SUCCESS) return rc;`
  // Step 5 lock claims: BOTH modes.
  // Step 6 dedup guard + validate: BOTH modes.
  // Steps 6/6b/6c: `if (!skip_authorization) { _check_key_version...; _check_scheme_constraints...; _verify_co_signatures(state, op, &pp); }`
  // Steps 7-9 (dispatch, transitions apply, dedup apply, compaction, log, tx commit,
  // trigger processing): BOTH modes, unchanged order.
  // Step 9b (added in Task 4): scheduler_process_due(state, now_ms);
  ...
}

crabs_error_e state_machine_execute(state_t* state, operation_t* op) {
  return state_machine_execute_internal(state, op, false);
}

crabs_error_e state_machine_execute_scheduled(state_t* state, operation_t* op) {
  return state_machine_execute_internal(state, op, true);
}
```

IMPORTANT invariants for this refactor: no check moves position in the normal path; the error precedence for any malformed op must be identical to before; `pp` flows from step 3 to step 6c exactly as before. Run the FULL suite after this refactor — every existing test must pass.

(g) Add `state_machine_validate`:

```c
crabs_error_e state_machine_validate(state_t* state, const operation_t* op) {
  if (state == NULL || op == NULL) return CRABS_ERR_INVALID_PARAM;

  // Freshness: prune locks/temp attrs first so staleness checks are honest.
  uint64_t now_ms;
  if (!state_get_time_ms(state, &now_ms)) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  state_machine_prune_expired(state, now_ms);
  if (state->attr_machine != NULL) {
    attribute_machine_set_time(state->attr_machine, now_ms);
    attribute_machine_prune_expired_temporary(state->attr_machine);
  }

  policy_preprocess_result_t pp;
  crabs_error_e rc = _verify_operation_authorization(state, op, &pp);
  if (rc != CRABS_SUCCESS) return rc;
  rc = _check_transitions(state, op);
  if (rc != CRABS_SUCCESS) return rc;
  rc = _check_key_version(state, op);
  if (rc != CRABS_SUCCESS) return rc;
  rc = _check_scheme_constraints(state, op);
  if (rc != CRABS_SUCCESS) return rc;
  rc = _verify_co_signatures(state, op, &pp);
  if (rc != CRABS_SUCCESS) return rc;
  return CRABS_SUCCESS;
}
```

- [ ] **Step 4: Run tests to verify they pass, then the full suite**

Run: `cmake --build build && ctest --test-dir build`
Expected: Scheduler validate tests PASS; entire existing suite unchanged (1315/1316 with only the known pre-existing failure).

- [ ] **Step 5: Commit**

```bash
git add src/StateMachine/state_machine.h src/StateMachine/state_machine.c test/test_scheduler.cpp
git commit -m "refactor: extract pipeline check helpers; add state_machine_validate and scheduled executor"
```

---

### Task 2b: de-wonk audit

Run the de-wonk skill on the refactor before proceeding. Confirm no check silently dropped, no behavioral change on the normal path (the full suite passing is the primary evidence).

---

### Task 3: `__schedule__` builtin op

**Files:**
- Modify: `src/CRABS/crabs.h` (op name constants), `src/StateMachine/state_machine.c`
- Test: `test/test_scheduler.cpp`

- [ ] **Step 1: Write the failing tests (append to `test/test_scheduler.cpp`)**

```cpp
#include <stdint.h>  // already present via other headers

// Payload layout for __schedule__: [u64 execute_at_ms LE][u32 op_len LE][op_bytes].
// Uses htole64/htole32 from <endian.h> explicitly (see Task 3 Step 3's note on
// availability; if htole64 is unavailable, use the _load/_store LE helpers
// described there).

```cpp
static void set_schedule_payload(operation_t* op, uint64_t execute_at_ms,
                                 const operation_t* embedded) {
  serialized_buffer_t* inner = crabs_serialize_operation(embedded);
  ASSERT_NE(inner, nullptr);
  uint32_t payload_len = 8 + 4 + (uint32_t)inner->len;
  uint8_t* payload = (uint8_t*)get_clear_memory(payload_len);
  uint64_t execute_at_le = htole64(execute_at_ms);
  uint32_t inner_len_le = htole32((uint32_t)inner->len);
  memcpy(payload, &execute_at_le, 8);
  memcpy(payload + 8, &inner_len_le, 4);
  memcpy(payload + 12, inner->data, inner->len);
  serialized_buffer_destroy(inner);
  op->payload = payload;
  op->payload_size = payload_len;
}

static operation_t* make_schedule_op(crabs_test_env_t* env, uint64_t execute_at_ms,
                                     operation_t* embedded) {
  operation_t* op = operation_create(CRABS_OP_SCHEDULE);
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  set_schedule_payload(op, execute_at_ms, embedded);
  crabs_test_sign_op_with(env->state->attr_machine, env->admin_key, op);
  return op;
}

TEST(SchedulerOps, ScheduleOpStoresPendingEntryAndLogs) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* embedded = make_counter_op("mint", "admin");
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, embedded);

  operation_t* schedule_op = make_schedule_op(&env, 9999999, embedded);
  EXPECT_EQ(state_machine_execute(env.state, schedule_op), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(env.state), 1u);
  EXPECT_STREQ(scheduler_first(env.state)->submitter, "admin");

  operation_destroy(schedule_op);
  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerOps, ScheduleInPastRejected) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* embedded = make_counter_op("mint", "admin");
  operation_t* schedule_op = make_schedule_op(&env, 1, embedded);
  EXPECT_EQ(state_machine_execute(env.state, schedule_op), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(scheduler_count(env.state), 0u);
  operation_destroy(schedule_op);
  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerOps, NestedScheduleRejected) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* inner_schedule = operation_create(CRABS_OP_SCHEDULE);
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, inner_schedule);
  operation_t* schedule_op = make_schedule_op(&env, 9999999, inner_schedule);
  EXPECT_EQ(state_machine_execute(env.state, schedule_op), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(scheduler_count(env.state), 0u);
  operation_destroy(schedule_op);
  operation_destroy(inner_schedule);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerOps, ScheduleWithInvalidEmbeddedOpRejected) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  // Embedded op has no registered policy -> state_machine_validate rejects.
  operation_t* embedded = operation_create("nosuchop");
  strncpy(embedded->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(env.state->attr_machine, env.admin_key, embedded);
  operation_t* schedule_op = make_schedule_op(&env, 9999999, embedded);
  EXPECT_EQ(state_machine_execute(env.state, schedule_op), CRABS_ERR_SCHEDULE_INVALID);
  EXPECT_EQ(scheduler_count(env.state), 0u);
  operation_destroy(schedule_op);
  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cmake --build build && ctest --test-dir build -R Scheduler`
Expected: FAIL — `CRABS_OP_SCHEDULE` undeclared.

- [ ] **Step 3: Implement**

In `src/CRABS/crabs.h`, after the Dedup Operations block:

```c
// Timed Transactions (v1)
#define CRABS_OP_SCHEDULE        "__schedule__"
#define CRABS_OP_CANCEL_SCHEDULE "__cancel_schedule__"
```

In `state_machine.c`:
- Add to `operation_is_builtin`: `strcmp(type, CRABS_OP_SCHEDULE) == 0 || strcmp(type, CRABS_OP_CANCEL_SCHEDULE) == 0 ||`
- Add to the step-7 dispatch chain (after `CRABS_OP_COMPACT`):

```c
  } else if (strcmp(op->type, CRABS_OP_SCHEDULE) == 0) {
    result = state_machine_op_schedule(state, op);
  } else if (strcmp(op->type, CRABS_OP_CANCEL_SCHEDULE) == 0) {
    result = state_machine_op_cancel_schedule(state, op);
```

- Declare in `state_machine.h` (public, like the other builtin op handlers):

```c
crabs_error_e  state_machine_op_schedule(state_t* state, operation_t* op);
crabs_error_e  state_machine_op_cancel_schedule(state_t* state, operation_t* op);
```

- Implement in `state_machine.c` (after the other builtin handlers) — includes `../Scheduler/scheduler.h` and `../Serialization/serialization.h` (check existing includes):

```c
// ============================================================
// Timed Transactions (v1)
// ============================================================

crabs_error_e state_machine_op_schedule(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL || op->payload == NULL ||
      op->payload_size < 12) {
    return CRABS_ERR_INVALID_PARAM;
  }

  uint64_t execute_at_ms;
  uint32_t inner_len;
  memcpy(&execute_at_ms, op->payload, 8);
  memcpy(&inner_len, op->payload + 8, 4);
  execute_at_ms = le64toh(execute_at_ms);
  inner_len = le32toh(inner_len);
  if (op->payload_size != 12 + inner_len || inner_len == 0) {
    return CRABS_ERR_INVALID_PARAM;
  }

  uint64_t now_ms;
  if (!state_get_time_ms(state, &now_ms)) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
  if (execute_at_ms <= now_ms) return CRABS_ERR_INVALID_PARAM;

  operation_t* embedded = crabs_deserialize_operation(op->payload + 12, inner_len);
  if (embedded == NULL) return CRABS_ERR_INVALID_PARAM;

  // No nesting: a scheduled op cannot itself be a schedule.
  if (strcmp(embedded->type, CRABS_OP_SCHEDULE) == 0) {
    operation_destroy(embedded);
    return CRABS_ERR_INVALID_PARAM;
  }

  // Authorize the embedded operation NOW (submission-time authorization):
  // full pipeline checks, nothing applied. Failure rejects the whole
  // __schedule__ so nothing is stored.
  crabs_error_e validation = state_machine_validate(state, embedded);
  if (validation != CRABS_SUCCESS) {
    operation_destroy(embedded);
    return CRABS_ERR_SCHEDULE_INVALID;
  }

  uint64_t schedule_id = scheduler_schedule(state, execute_at_ms, op->signer_id, embedded);
  operation_destroy(embedded);
  if (schedule_id == 0) return CRABS_ERR_OOM;
  return CRABS_SUCCESS;
}

crabs_error_e state_machine_op_cancel_schedule(state_t* state, operation_t* op) {
  if (state == NULL || op == NULL || op->payload == NULL ||
      op->payload_size != 8) {
    return CRABS_ERR_INVALID_PARAM;
  }
  uint64_t schedule_id;
  memcpy(&schedule_id, op->payload, 8);
  return scheduler_cancel(state, le64toh(schedule_id));
}
```

In `src/CRABS/crabs.h` error enum (near `CRABS_ERR_NO_OT_OPS`), add:

```c
  CRABS_ERR_SCHEDULE_INVALID      = 0x7006,
```

Note on byte order: the codebase's serialization uses explicit LE helpers; the payload here uses `htole64`/`le64toh` from `<endian.h>` (already available via the `-include strings.h` build flags on Linux/wasm — verify; if `htole64` is unavailable, write two small static helpers `_load_u64_le`/`_store_u64_le` in state_machine.c mirroring serialization.c's `_read_uint64_le` logic and use those instead).

- [ ] **Step 4: Run tests, full suite, de-wonk, commit**

Run: `cmake --build build && ctest --test-dir build` → Scheduler tests pass, full suite unchanged.
Run the de-wonk skill.
```bash
git add src/StateMachine/state_machine.c src/StateMachine/state_machine.h src/CRABS/crabs.h test/test_scheduler.cpp
git commit -m "feat: add __schedule__ builtin op with submission-time embedded-op validation"
```

---

### Task 4: Materialization — `scheduler_process_due`, failure records, tick hook

**Files:**
- Modify: `src/Scheduler/scheduler.c`, `src/StateMachine/state_machine.c` (tick hook only)
- Test: `test/test_scheduler.cpp`

- [ ] **Step 1: Write the failing tests**

```cpp
// A state whose authenticated clock is controllable: the mock time ops from
// test_hlc.cpp are static there, so declare a local mock here.
static crabs_physical_time_t g_sched_mock_time = {0, 0, false};
static crabs_physical_time_t sched_mock_get_time(void* ctx) {
  (void)ctx;
  return g_sched_mock_time;
}
static bool sched_mock_is_available(void* ctx) {
  (void)ctx;
  return g_sched_mock_time.valid;
}
static crabs_time_source_ops_t g_sched_mock_ops = {
  sched_mock_get_time, sched_mock_is_available, NULL
};

TEST(SchedulerMaterialize, DueOpMaterializedExactlyOnce) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  state_t* state = env.state;

  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;
  state_set_time_source(state, &g_sched_mock_ops);

  operation_t* embedded = make_counter_op("mint", "admin");
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
  operation_t* schedule_op = make_schedule_op(&env, 1000005000, embedded);
  ASSERT_EQ(state_machine_execute(state, schedule_op), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 1u);

  // Before due: nothing happens.
  g_sched_mock_time.seconds = 1000000;
  ASSERT_EQ(scheduler_process_due(state, 1000004999000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 1u);

  // After due: materialized and consumed.
  ASSERT_EQ(scheduler_process_due(state, 1000005000000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 0u);

  // Idempotent: a second tick is a no-op.
  ASSERT_EQ(scheduler_process_due(state, 1000006000000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 0u);

  // The embedded op's uuid appears in the log exactly once.
  uint32_t uuid_matches = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (memcmp(state->log[entry_index].uuid, embedded->uuid, CRABS_UUID_SIZE) == 0) {
      uuid_matches++;
    }
  }
  EXPECT_EQ(uuid_matches, 1u);

  operation_destroy(embedded);
  operation_destroy(schedule_op);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerMaterialize, SignerSubsequentOpsNotFlaggedReplay) {
  // The scheduled op carries an HLC from sign time. After materialization,
  // the signer's normal (newer-HLC) ops must still pass the R7-11 check.
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  state_t* state = env.state;
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;
  state_set_time_source(state, &g_sched_mock_ops);

  operation_t* embedded = make_counter_op("mint", "admin");
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
  operation_t* schedule_op = make_schedule_op(&env, 1000005000, embedded);
  ASSERT_EQ(state_machine_execute(state, schedule_op), CRABS_SUCCESS);

  // Signer does a normal op NOW (HLC ordering from the env is lamport by
  // default; the helper stamps an increasing lamport, which is fine).
  operation_t* direct = make_counter_op("mint", "admin");
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, direct);
  ASSERT_EQ(state_machine_execute(state, direct), CRABS_SUCCESS);
  operation_destroy(direct);

  g_sched_mock_time.seconds = 1000005;
  ASSERT_EQ(scheduler_process_due(state, 1000005000000u), CRABS_SUCCESS);
  EXPECT_EQ(scheduler_count(state), 0u);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}

TEST(SchedulerMaterialize, FailedMaterializationRecordedNotPropagated) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  state_t* state = env.state;

  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;
  state_set_time_source(state, &g_sched_mock_ops);

  // Schedule a LOCK on a resource; at materialization time the resource is
  // already LOCKED by someone else → transition check fails at T.
  data_item_t* resource = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  int64_t* value = (int64_t*)get_clear_memory(sizeof(int64_t));
  *value = 5;
  resource->value = value;
  state_add_item(state, resource);

  // Signed __lock__ op (mirrors make_lock_op_signed in test/test_co_sign.cpp):
  // resources[0]="res1", required_state=IDLE, next_state=LOCKED.
  operation_t* embedded = operation_create(CRABS_OP_LOCK);
  embedded->resources =
      (char(*)[CRABS_MAX_USER_ID])get_clear_memory(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(embedded->resources[0], "res1", CRABS_MAX_USER_ID - 1);
  embedded->resource_count = 1;
  embedded->required_state =
      (protocol_state_e*)get_clear_memory(sizeof(protocol_state_e));
  embedded->required_state[0] = PROTOCOL_IDLE;
  embedded->next_state =
      (protocol_state_e*)get_clear_memory(sizeof(protocol_state_e));
  embedded->next_state[0] = PROTOCOL_LOCKED;
  strncpy(embedded->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);

  operation_t* schedule_op = make_schedule_op(&env, 1000005000, embedded);
  ASSERT_EQ(state_machine_execute(state, schedule_op), CRABS_SUCCESS);

  // State drift: lock the resource directly before materialization, so the
  // scheduled __lock__ hits a protocol violation at T.
  resource->protocol_state = PROTOCOL_LOCKED;
  resource->lock_state.lock_token_valid = true;

  // A normal user op executes at the same tick and MUST still succeed.
  operation_t* unrelated = make_counter_op("mint", "admin");
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, unrelated);
  EXPECT_EQ(state_machine_execute(state, unrelated), CRABS_SUCCESS);

  // The failure is recorded: exactly one __schedule_failed__ log entry whose
  // uuid matches the embedded op, and the pending entry is consumed.
  uint32_t failure_records = 0;
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (strcmp(state->log[entry_index].type, "__schedule_failed__") == 0) {
      failure_records++;
    }
  }
  EXPECT_EQ(failure_records, 1u);
  EXPECT_EQ(scheduler_count(state), 0u);

  operation_destroy(unrelated);
  operation_destroy(embedded);
  operation_destroy(schedule_op);
  crabs_test_env_destroy(&env);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cmake --build build && ctest --test-dir build -R Scheduler`
Expected: the two materialization tests fail (process_due is a stub; nothing materializes).

- [ ] **Step 3: Implement `scheduler_process_due` and the tick hook**

In `src/Scheduler/scheduler.c` (replace the stub), with includes of `../Serialization/serialization.h` and `../StateMachine/state_machine.h`:

```c
static bool _uuid_in_log(const state_t* state, const uint8_t uuid[CRABS_UUID_SIZE]) {
  for (uint64_t entry_index = 0; entry_index < state->log_count; entry_index++) {
    if (memcmp(state->log[entry_index].uuid, uuid, CRABS_UUID_SIZE) == 0) {
      return true;
    }
  }
  return false;
}

crabs_error_e scheduler_process_due(state_t* state, uint64_t now_ms) {
  if (state == NULL) return CRABS_ERR_INVALID_PARAM;

  // Iterate by id snapshot so reentrant modifications during materialization
  // cannot skip or double-process entries: collect due ids first.
  uint64_t due_ids[CRABS_SCHEDULER_MAX_DUE_PER_TICK];
  uint32_t due_count = 0;
  for (const scheduled_operation_t* entry = state->scheduled_operations;
       entry != NULL && due_count < CRABS_SCHEDULER_MAX_DUE_PER_TICK;
       entry = entry->next) {
    if (entry->execute_at_ms <= now_ms) {
      due_ids[due_count++] = entry->schedule_id;
    }
  }

  for (uint32_t due_index = 0; due_index < due_count; due_index++) {
    uint64_t schedule_id = due_ids[due_index];
    scheduled_operation_t** link = &state->scheduled_operations;
    scheduled_operation_t* entry = NULL;
    while (*link != NULL) {
      if ((*link)->schedule_id == schedule_id) {
        entry = *link;
        break;
      }
      link = &(*link)->next;
    }
    if (entry == NULL) continue;  // cancelled during this tick

    // Remove from the pending list FIRST (idempotency guard).
    *link = entry->next;

    operation_t* embedded = crabs_deserialize_operation(entry->op_bytes, entry->op_len);
    if (embedded == NULL) {
      // Undecodable bytes: record with a zero uuid (the op identity is not
      // recoverable) and the submitter as the log signer.
      uint8_t zero_uuid[CRABS_UUID_SIZE];
      memset(zero_uuid, 0, sizeof(zero_uuid));
      state_machine_log_schedule_failure(state, zero_uuid, entry->submitter);
      free(entry->op_bytes);
      free(entry);
      continue;
    }

    // Already applied via replication? Idempotent skip.
    if (_uuid_in_log(state, embedded->uuid)) {
      operation_destroy(embedded);
      free(entry->op_bytes);
      free(entry);
      continue;
    }

    // Internal execution: auth already enforced at submission.
    crabs_error_e materialize_rc =
        state_machine_execute_scheduled(state, embedded);
    if (materialize_rc != CRABS_SUCCESS) {
      // Durable failure record keyed by the embedded op's uuid, so all nodes
      // agree the schedule resolved as failed and the devtools Timeline can
      // show it. lamport 0 + LAMPORT ordering keeps the record neutral for
      // the signer's ordering check: HLC signers sort after any lamport
      // entry; lamport signers already must exceed their signed lamport.
      state_machine_log_schedule_failure(state, embedded->uuid, embedded->signer_id);
    }
    operation_destroy(embedded);
    free(entry->op_bytes);
    free(entry);
  }
  return CRABS_SUCCESS;
}
```

`append_log` is static in state_machine.c, so the failure record is written by a state_machine.c function. Add to `state_machine.h`:

```c
// Record a failed scheduled materialization in the audit log (system entry,
// no signature, lamport 0 / LAMPORT ordering). Used by the scheduler; never
// fails the caller's op.
void state_machine_log_schedule_failure(state_t* state,
                                        const uint8_t uuid[CRABS_UUID_SIZE],
                                        const char* signer_id);
```

implemented in state_machine.c as:

```c
void state_machine_log_schedule_failure(state_t* state,
                                        const uint8_t uuid[CRABS_UUID_SIZE],
                                        const char* signer_id) {
  if (state == NULL || uuid == NULL || signer_id == NULL) return;
  uint8_t state_hash[CRABS_HASH_SIZE];
  memset(state_hash, 0, CRABS_HASH_SIZE);
  crabs_hlc_t zero_hlc;
  memset(&zero_hlc, 0, sizeof(zero_hlc));
  if (!append_log(state, uuid, "__schedule_failed__", signer_id,
                  0, state->hlc_state_initialized
                         ? state->hlc_state.last.node_id : "",
                  CRABS_ORDERING_LAMPORT, &zero_hlc, state_hash)) {
    return;  // OOM appending a failure record must not crash the tick
  }
  state->version++;
}
```

(Reasoning to keep as a code comment in scheduler.c: the failure entry is LAMPORT-ordered with lamport 0, so it never blocks the signer's later HLC ops (lamport sorts before HLC) and never blocks a lamport signer whose next op carries a lamport > 0 — which the test helper guarantees.)

Tick hook — at the very end of `state_machine_execute_internal` (after trigger processing), BOTH modes? No: only the normal path ticks (the scheduled path must not recurse). Add the parameter from Task 2: change `state_machine_execute_internal(state, op, bool skip_authorization)` to `state_machine_execute_internal(state, op, bool skip_authorization, bool process_schedules)`; `state_machine_execute` passes true, `state_machine_execute_scheduled` passes false. At the end:

```c
  // Step 9b: Materialize due scheduled operations (timed transactions v1).
  // Failures are recorded in the log, never propagated to this op.
  if (process_schedules) {
    scheduler_process_due(state, now_ms);
  }
```

(`now_ms` was computed at the top of the pipeline — reuse it.)

- [ ] **Step 4: Run tests, full suite, de-wonk**

Run: `cmake --build build && ctest --test-dir build` — all Scheduler tests pass; full suite green except the known TestCLI failure. Run the de-wonk skill.

- [ ] **Step 5: Commit**

```bash
git add src/Scheduler/scheduler.c src/Scheduler/scheduler.h src/StateMachine/state_machine.c src/StateMachine/state_machine.h test/test_scheduler.cpp
git commit -m "feat: materialize due schedules with durable failure records"
```

---

### Task 5: Bindings — schedule APIs in wasm helpers + JS

**Files:**
- Modify: `src/Util/wasm_helpers.c`, `build_wasm.sh` (export list), `bindings/wasm/bindings-core.js`, `bindings/wasm/index.d.ts`
- Test: `bindings/wasm/test/schedules.js` (new)

- [ ] **Step 1: C helpers in `src/Util/wasm_helpers.c`** (before the devtools section):

```c
// ============================================================
// Timed transactions (v1)
// ============================================================

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_schedule(attribute_machine_t* am, operation_t* inner_op,
                             uint64_t execute_at_ms) {
  if (!am || !inner_op) return 0;
  return scheduler_schedule(&am->base_state, execute_at_ms,
                            inner_op->signer_id, inner_op);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_cancel_schedule(attribute_machine_t* am, uint64_t schedule_id) {
  if (!am) return CRABS_ERR_INVALID_PARAM;
  return scheduler_cancel(&am->base_state, schedule_id);
}

EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_process_schedules(attribute_machine_t* am, uint64_t now_ms) {
  if (!am) return CRABS_ERR_INVALID_PARAM;
  return scheduler_process_due(&am->base_state, now_ms);
}

EMSCRIPTEN_KEEPALIVE
uint32_t crabs_wasm_schedule_count(attribute_machine_t* am) {
  return am ? scheduler_count(&am->base_state) : 0;
}

EMSCRIPTEN_KEEPALIVE
const scheduled_operation_t* crabs_wasm_schedule_first(attribute_machine_t* am) {
  return am ? scheduler_first(&am->base_state) : NULL;
}

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_schedule_execute_at(const scheduled_operation_t* entry) {
  return entry ? entry->execute_at_ms : 0;
}

EMSCRIPTEN_KEEPALIVE
uint64_t crabs_wasm_schedule_id(const scheduled_operation_t* entry) {
  return entry ? entry->schedule_id : 0;
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_schedule_submitter(const scheduled_operation_t* entry) {
  return entry ? entry->submitter : NULL;
}

EMSCRIPTEN_KEEPALIVE
const scheduled_operation_t* crabs_wasm_schedule_next(const scheduled_operation_t* entry) {
  return entry ? entry->next : NULL;
}
```

Add `#include "../Scheduler/scheduler.h"` to the include block. Add these symbols to `BASE_EXPORTS` in `build_wasm.sh` (both variants need them).

- [ ] **Step 2: JS methods in `bindings/wasm/bindings-core.js`** (inside the Node class):

```js
  schedule(innerOp, executeAtMs) {
    const M = this._M;
    const scheduleId = M._crabs_wasm_schedule(this._am, innerOp._ptr, BigInt(executeAtMs));
    if (!scheduleId) throw new Error('schedule failed');
    return scheduleId;
  }

  cancelSchedule(scheduleId) {
    wrapRc(this._M._crabs_wasm_cancel_schedule(this._am, BigInt(scheduleId)), 'cancelSchedule');
  }

  processSchedules(nowMs = Date.now()) {
    wrapRc(this._M._crabs_wasm_process_schedules(this._am, BigInt(nowMs)), 'processSchedules');
  }

  pendingSchedules() {
    const M = this._M;
    const schedules = [];
    for (let entry = M._crabs_wasm_schedule_first(this._am); entry;
         entry = M._crabs_wasm_schedule_next(entry)) {
      schedules.push({
        id: M._crabs_wasm_schedule_id(entry),
        executeAt: M._crabs_wasm_schedule_execute_at(entry),
        submitter: M.UTF8ToString(M._crabs_wasm_schedule_submitter(entry)),
      });
    }
    return schedules;
  }
```

Note: `schedule()` stores the embedded op directly via the C API — the embedded op must already be signed by the caller (`node.sign(innerOp, key)` before `node.schedule(innerOp, at)`). Add `schedule`, `cancelSchedule`, `processSchedules`, `pendingSchedules` to `index.d.ts`'s `Node` interface:

```ts
  schedule(innerOp: Operation, executeAtMs: number): bigint;
  cancelSchedule(scheduleId: bigint): void;
  processSchedules(nowMs?: number): void;
  pendingSchedules(): Array<{ id: bigint; executeAt: bigint; submitter: string }>;
```

- [ ] **Step 3: WASM smoke test `bindings/wasm/test/schedules.js`**

```js
//
// schedules.js — smoke test for timed transactions through the WASM bindings.
//

'use strict';

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../dev.js');

(async () => {
  const node = await Node.create('admin', { ordering: 'hlc' });
  node.addCounter('tokens');
  const key = await KeyPair.generate();
  node.registerUser('minter', key.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'alice');
  node.setPolicy('mint', 'role:member');

  const inner = await Operation.create('mint');
  inner.signerId = 'alice';
  inner.nodeId = 'alice';
  node.sign(inner, key.privateKeyHex());

  const now = 1000000000000;
  const scheduleId = node.schedule(inner, now + 60000);
  assert.ok(scheduleId > 0n);
  assert.strictEqual(node.pendingSchedules().length, 1);

  // Not due yet: nothing materializes.
  node.processSchedules(now);
  assert.strictEqual(node.pendingSchedules().length, 1);

  // Due: materializes.
  node.processSchedules(now + 60001);
  assert.strictEqual(node.pendingSchedules().length, 0);

  console.log('schedules smoke OK: id=' + scheduleId);
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
```

Note: the mint op is not executed via `node.execute` — it is embedded unsigned-then-signed into the schedule; the counter does not move because no handler is registered for 'mint' in this smoke test (a full handler-driven materialization is covered by native tests and the demo).

- [ ] **Step 4: Rebuild WASM, run all three smoke tests, commit**

```bash
source ~/emsdk/emsdk_env.sh && ./build_wasm.sh
cp build-wasm/crabs.js build-wasm/crabs.wasm bindings/wasm/
cp build-wasm.dev/crabs.dev.js build-wasm.dev/crabs.dev.wasm bindings/wasm/
node bindings/wasm/test/smoke.js && node bindings/wasm/test/devtools.js && node bindings/wasm/test/schedules.js
git add src/Util/wasm_helpers.c build_wasm.sh bindings/wasm/bindings-core.js bindings/wasm/index.d.ts bindings/wasm/test/schedules.js bindings/wasm/crabs.js bindings/wasm/crabs.wasm bindings/wasm/crabs.dev.js bindings/wasm/crabs.dev.wasm
git commit -m "feat: expose schedule/cancel/process/pending through the bindings"
```

---

### Task 6: Devtools snapshot + panel Schedules section

**Files:**
- Modify: `src/Devtools/devtools.c`, `test/test_devtools.cpp`
- Modify: `bindings/devtools/crabs-devtools.js`

- [ ] **Step 1: Failing C test (append to `test/test_devtools.cpp`)**

```cpp
TEST(DevtoolsSnapshot, SchedulesSection) {
  // Reuse the pattern from test_scheduler.cpp: env + one pending schedule.
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  operation_t* embedded = operation_create("mint");
  strncpy(embedded->signer_id, "admin", CRABS_MAX_USER_ID - 1);
  uint64_t schedule_id = scheduler_schedule(env.state, 5555555, "admin", embedded);

  char* json = devtools_snapshot_json(env.state);
  ASSERT_NE(json, nullptr);
  std::string text = json;
  devtools_string_destroy(json);

  EXPECT_NE(text.find("\"schedules\":["), std::string::npos);
  EXPECT_NE(text.find("\"id\":" + std::to_string(schedule_id)), std::string::npos);
  EXPECT_NE(text.find("\"execute_at\":5555555"), std::string::npos);
  EXPECT_NE(text.find("\"submitter\":\"admin\""), std::string::npos);

  operation_destroy(embedded);
  crabs_test_env_destroy(&env);
}
```

(Add the needed includes: `test_helpers.h` and `Scheduler/scheduler.h` in the extern "C" block.)

- [ ] **Step 2: Implement in `src/Devtools/devtools.c`**

Add before `devtools_snapshot_json`:

```c
static void _write_schedules_json(json_writer_t* writer, const state_t* state) {
  _json_writer_raw(writer, "\"schedules\":[");
  const scheduled_operation_t* entry = state->scheduled_operations;
  bool first_entry = true;
  while (entry != NULL) {
    if (!first_entry) _json_writer_raw(writer, ",");
    first_entry = false;
    _json_writer_raw(writer, "{\"id\":");
    _json_writer_uint(writer, entry->schedule_id);
    _json_writer_raw(writer, ",\"execute_at\":");
    _json_writer_uint(writer, entry->execute_at_ms);
    _json_writer_raw(writer, ",\"submitter\":");
    _json_writer_string(writer, entry->submitter);
    _json_writer_raw(writer, ",\"op_type\":");
    // The embedded op's type is readable from the serialized bytes only after
    // deserialization; skip it rather than paying the cost per snapshot.
    _json_writer_string(writer, "");
    _json_writer_raw(writer, "}");
    entry = entry->next;
  }
  _json_writer_raw(writer, "]");
}
```

and call it in `devtools_snapshot_json` after `_write_log_head_json` (add a comma separator matching the existing pattern). Include `../Scheduler/scheduler.h`.

- [ ] **Step 3: Panel Config tab — Schedules section**

In `bindings/devtools/crabs-devtools.js`, `renderConfig`, after the log-head block:

```js
      const schedulesTitle = document.createElement('div');
      const schedulesLabel = document.createElement('span');
      schedulesLabel.className = 'label muted';
      schedulesLabel.textContent = 'Schedules';
      // (render only when there are schedules)
      const schedules = snapshot.schedules || [];
      if (schedules.length > 0) {
        body.appendChild(schedulesLabel);
        for (const schedule of schedules) {
          const row = document.createElement('div');
          row.className = 'row';
          const left = document.createElement('span');
          const dueIn = schedule.execute_at - Date.now();
          left.textContent = '#' + schedule.id + ' by ' + schedule.submitter +
            (dueIn <= 0 ? ' · due' : ' · in ' + Math.round(dueIn / 1000) + 's');
          const right = document.createElement('span');
          right.className = 'muted';
          right.textContent = new Date(schedule.execute_at).toISOString().slice(11, 19);
          row.appendChild(left);
          row.appendChild(right);
          body.appendChild(row);
        }
      }
```

- [ ] **Step 4: Rebuild WASM artifacts, run devtools tests, commit**

```bash
cmake --build build && ctest --test-dir build -R Devtools
source ~/emsdk/emsdk_env.sh && ./build_wasm.sh && cp build-wasm/crabs.js build-wasm/crabs.wasm bindings/wasm/ && cp build-wasm.dev/crabs.dev.js build-wasm.dev/crabs.dev.wasm bindings/wasm/
node bindings/wasm/test/devtools.js && node bindings/wasm/test/schedules.js
git add src/Devtools/devtools.c test/test_devtools.cpp bindings/devtools/crabs-devtools.js bindings/wasm/crabs.js bindings/wasm/crabs.wasm bindings/wasm/crabs.dev.js bindings/wasm/crabs.dev.wasm
git commit -m "feat: show pending schedules in the devtools snapshot and Config tab"
```

---

### Task 7: Final verification + docs

- [ ] **Step 1: Full native suite** — `cmake --build build && ctest --test-dir build` (all green except the known TestCLI failure).
- [ ] **Step 2: All three WASM smoke tests** — smoke.js, devtools.js, schedules.js.
- [ ] **Step 3: Demo verification in browser** — add a "Schedule mint (+60s)" button to `examples/devtools_demo/demo.js` that registers a `mint` handler (`state.incrementCounter('tokens', 1, operation.nodeId)`), adds a `tokens` counter, signs a mint op as alice, calls `node.schedule(mintOp, Date.now() + 60000)`, and refreshes the panel; then in the browser: Config tab shows the schedule, after ~60s a tick materializes it and the Timeline shows the mint with the counter incremented. Add an `add tokens` button so the counter is visible. Commit demo changes with the browser verification evidence.
- [ ] **Step 4: README** — add a "Timed transactions" section to `bindings/wasm/README.md` mirroring the devtools section style (two artifacts note, `node.schedule` usage, failure-record semantics).
- [ ] **Step 5: Commit** — `git commit -m "docs: document timed transactions"`.

---

## Self-Review Notes

- Spec coverage: durable pending set + serialization (Task 1); submission-time validation (Tasks 2-3); `__schedule__`/`__cancel_schedule__` (Task 3); materialization with idempotency + failure records + tick hook (Task 4); bindings (Task 5); devtools (Task 6); tests throughout; recurring schedules out of scope.
- Known plan-level simplification: `state_machine_execute_internal` gains a second bool (`process_schedules`) in Task 4 — Task 2 must anticipate the two-parameter shape or Task 4 adjusts the signature again (noted inline in Task 4).
- The failure-record test's `__lock__` construction is written out in full in Task 4 (mirroring `test/test_co_sign.cpp`'s `make_lock_op_signed`).