# Devtools Overlay, State Inspector, Change Events — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the devtools a true overlay with a full-state inspector tree (diffs, layers, payload previews) and give the library API-level change notification (C hook + JS `node.on('change')`).

**Architecture:** A non-devtools-gated change hook on `state_t` (`state_set_change_hook`) fires at every mutation completion (execute, scheduled materialization, trigger effects, attribute-machine mutations). In dev builds the devtools recorder registers as a hook so the event ring records every path; a JS trampoline installed via `addFunction` receives serialized change events and drives `node.on('change')` plus devtools refreshes (push, no polling). The panel becomes a fixed overlay with a launcher button and two tabs: State (collapsible full-state tree with diff badges, overview header, export) and Timeline (layer pills, filters, payload previews).

**Tech Stack:** C11 (OpenSSL EVP), Emscripten/WASM (two build variants via `build_wasm.sh`), vanilla-JS shadow-DOM web component, GoogleTest native suite, Node smoke tests.

**Spec:** `docs/superpowers/specs/2026-09-08-devtools-overlay-state-inspector-design.md`

**Conventions:** Follow `docs/STYLE_GUIDE.md` (2-space indent, `type_action()` naming, `_private` underscore prefix, early returns). Test helpers `crabs_test_env_t`, `crabs_test_env_init`, `crabs_test_sign_op_with`, `make_counter_op`, `stamp_unique_uuid` live in `test/test_helpers.h` / test files. No single-letter variable names (never `t`, `i`, `x`) — use `op_index`, `entry_index`, etc. Never add Co-Authored-By lines.

---

### Task 1: Change-hook core — types, registration, notify helpers (TDD)

**Files:**
- Modify: `src/CRABS/data_model.h` (change kinds/event struct/hook typedef; two fields on `state_t`)
- Modify: `src/StateMachine/state_machine.h` (function declarations)
- Modify: `src/StateMachine/state_machine.c` (implementations)
- Test: `test/test_state_machine.cpp`

- [ ] **Step 1: Write the failing tests**

Append to `test/test_state_machine.cpp` (after the audit-log hash-chain test works with the fixture `state`, `am`, `alice_key`, `sign_operation`, `make_lock_op`):

```cpp
// ============================================================
// State Change Notification (devtools change events core)
// ============================================================

// Stateless sink: a captureless lambda cannot reach local variables, so the
// hook tests use a static struct. Place ABOVE the first test that uses it.
struct ChangeSink {
  static const crabs_change_event_t* last_event;
  static int call_count;
  static void hook(state_t*, const crabs_change_event_t* event, void* user_data) {
    (void)user_data;
    ChangeSink::last_event = event;
    ChangeSink::call_count++;
  }
};
const crabs_change_event_t* ChangeSink::last_event = nullptr;
int ChangeSink::call_count = 0;

TEST_F(TestStateMachine, ChangeHookFiresOnExecuteSuccess) {
  state_set_change_hook(state, ChangeSink::hook, nullptr);
  ChangeSink::call_count = 0;

  operation_t* op = make_lock_op();
  ASSERT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);

  EXPECT_EQ(ChangeSink::call_count, 1);
  ASSERT_NE(ChangeSink::last_event, nullptr);
  // Copy out before the next op overwrites the ring-adjacent storage: the
  // event struct lives on the notify helper's stack, so copy it if the test
  // needs it after another execute. For this test, read immediately.
  EXPECT_STREQ(ChangeSink::last_event->type, "lock");
  EXPECT_EQ(ChangeSink::last_event->kind, CRABS_CHANGE_OP);
  EXPECT_EQ(ChangeSink::last_event->result, CRABS_SUCCESS);
  state_set_change_hook(state, nullptr, nullptr);
}

TEST_F(TestStateMachine, ChangeHookFiresOnExecuteFailure) {
  state_set_change_hook(state, ChangeSink::hook, nullptr);
  ChangeSink::call_count = 0;

  // Unsigned op → cryptographic failure; no state mutation, but the event
  // still fires (devtools parity with the old recorder).
  operation_t* op = make_lock_op();
  op->signature[0] = (uint8_t)(op->signature[0] ^ 0xFF);  // corrupt signature
  EXPECT_NE(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);

  EXPECT_EQ(ChangeSink::call_count, 1);
  EXPECT_NE(ChangeSink::last_event->result, CRABS_SUCCESS);
  state_set_change_hook(state, nullptr, nullptr);
}

TEST_F(TestStateMachine, ChangeHookIdempotentSkipFiresNothing) {
  state_set_change_hook(state, ChangeSink::hook, nullptr);
  ChangeSink::call_count = 0;

  operation_t* op = make_lock_op();
  ASSERT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  crabs_error_e replay = state_machine_execute(state, op);
  operation_destroy(op);

  // CRABS_ERR_ALREADY_EXECUTED is an idempotent skip: no mutation, no event.
  EXPECT_EQ(replay, CRABS_ERR_ALREADY_EXECUTED);
  EXPECT_EQ(ChangeSink::call_count, 1);
  state_set_change_hook(state, nullptr, nullptr);
}

TEST_F(TestStateMachine, ChangeHookNullIsNoOp) {
  state_set_change_hook(state, nullptr, nullptr);  // must not crash
  operation_t* op = make_lock_op();
  ASSERT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);
}

TEST_F(TestStateMachine, ChangeHookIsRuntimeStateNotSerialized) {
  state_set_change_hook(state, ChangeSink::hook, nullptr);
  ChangeSink::call_count = 0;

  serialized_buffer_t* blob = crabs_serialize_state(state);
  ASSERT_NE(blob, nullptr);
  state_t* restored = crabs_deserialize_state(blob->data, blob->len);
  serialized_buffer_destroy(blob);
  ASSERT_NE(restored, nullptr);

  // The hook is runtime state: a restored state starts with NO hook.
  operation_t* op = make_lock_op();
  ASSERT_EQ(state_machine_execute(restored, op), CRABS_SUCCESS);
  operation_destroy(op);
  EXPECT_EQ(ChangeSink::call_count, 0);
  EXPECT_EQ(restored->change_hook, nullptr);
  state_destroy(restored);
  state_set_change_hook(state, nullptr, nullptr);
}
```

Note: `ChangeSink` is a plain struct with static members; place it ABOVE the first test that uses it. All hook tests use this static sink — a captureless lambda cannot reach local variables, and stateless callables are the only ones convertible to the C function-pointer type.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cmake --build build -j 8 2>&1 | grep -E "error" | head -5`
Expected: compile errors — `CRABS_CHANGE_OP`, `state_set_change_hook`, `crabs_change_event_t` undeclared.

- [ ] **Step 3: Implement the core**

In `src/CRABS/data_model.h`, add after the `machine_config_t` block (before the Dedup Specification section):

```c
// ============================================================
// State Change Notification (core; NOT devtools-gated)
// ============================================================
typedef enum {
  CRABS_CHANGE_OP        = 0x01,  // executed operation (direct execution only)
  CRABS_CHANGE_SCHEDULE  = 0x02,  // scheduled materialization (each fire)
  CRABS_CHANGE_TRIGGER   = 0x03,  // trigger-fired mutation
  CRABS_CHANGE_ATTRIBUTE = 0x04   // attribute-machine user mutation
} crabs_change_kind_e;

typedef struct {
  crabs_change_kind_e kind;
  const char*         type;        // op type / attribute action name
  const uint8_t*      uuid;        // op uuid; NULL for attribute actions
  const char*         signer_id;   // NULL when not applicable
  const char*         node_id;     // NULL when not applicable
  const char*         target;      // primary target item/user; NULL when none
  const char*         preview;     // short human-readable payload summary
  crabs_error_e       result;
} crabs_change_event_t;

typedef void (*crabs_change_hook_fn)(state_t* state,
                                     const crabs_change_event_t* event,
                                     void* user_data);
```

In `state_t` (data_model.h), next to the `max_occurrences_per_tick` field, add:

```c
  // Change notification (core, not devtools-gated): invoked after every
  // state-mutating completion. Runtime state; not serialized.
  crabs_change_hook_fn change_hook;
  void*                change_hook_user_data;
```

In `src/StateMachine/state_machine.h`, after the `op_handler_entry_t` struct:

```c
// ============================================================
// State Change Notification (devtools change events core)
// ============================================================
// Register a callback fired after every state-mutating completion: direct
// execution (kind OP), scheduled materialization (kind SCHEDULE), trigger
// effects (kind TRIGGER), attribute-machine mutations (kind ATTRIBUTE).
// Idempotent skips (CRABS_ERR_ALREADY_EXECUTED) do NOT fire. The hook must
// not mutate state. Pass NULL to clear. Runtime state; not serialized.
void state_set_change_hook(state_t* state, crabs_change_hook_fn hook,
                           void* user_data);

// Fire a change event manually (used by the attribute machine and trigger
// engine, which mutate without going through state_machine_execute). Does
// nothing when no hook is registered. All strings are borrowed for the
// duration of the hook call only.
void state_notify_change(state_t* state, crabs_change_kind_e kind,
                         const char* type, const uint8_t* uuid,
                         const char* signer_id, const char* node_id,
                         const char* target, const char* preview,
                         crabs_error_e result);

// Convenience: build the event from an operation's fields. preview_override
// replaces the default (NULL) preview when non-NULL.
void state_notify_change_for_op(state_t* state, crabs_change_kind_e kind,
                                const operation_t* op,
                                const char* preview_override,
                                crabs_error_e result);
```

In `src/StateMachine/state_machine.c` (near the top, after includes):

```c
// ============================================================
// State Change Notification
// ============================================================

void state_set_change_hook(state_t* state, crabs_change_hook_fn hook,
                           void* user_data) {
  if (state == NULL) return;
  state->change_hook = hook;
  state->change_hook_user_data = user_data;
}

void state_notify_change(state_t* state, crabs_change_kind_e kind,
                         const char* type, const uint8_t* uuid,
                         const char* signer_id, const char* node_id,
                         const char* target, const char* preview,
                         crabs_error_e result) {
  if (state == NULL || state->change_hook == NULL) return;
  crabs_change_event_t event;
  memset(&event, 0, sizeof(event));
  event.kind = kind;
  event.type = type;
  event.uuid = uuid;
  event.signer_id = signer_id;
  event.node_id = node_id;
  event.target = target;
  event.preview = preview;
  event.result = result;
  // Contract: the hook never mutates state and never fails the op. The
  // borrow is valid only for the duration of the call.
  state->change_hook(state, &event, state->change_hook_user_data);
}

void state_notify_change_for_op(state_t* state, crabs_change_kind_e kind,
                                const operation_t* op,
                                const char* preview_override,
                                crabs_error_e result) {
  if (op == NULL) return;
  const char* target = NULL;
  if (op->resource_count > 0 && op->resources != NULL) {
    target = op->resources[0];
  }
  state_notify_change(state, kind, op->type, op->uuid, op->signer_id,
                      op->node_id, target, preview_override, result);
}
```

- [ ] **Step 4: Build and run the hook tests**

Run: `cmake --build build -j 8 2>&1 | grep -E "error" | head -5; ctest --test-dir build -R "ChangeHook" --output-on-failure 2>&1 | tail -3`
Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/CRABS/data_model.h src/StateMachine/state_machine.h src/StateMachine/state_machine.c test/test_state_machine.cpp
git commit -m "feat: add state change notification hook (core)"
```

---

### Task 2: Fire the hook on the execute paths (TDD)

**Files:**
- Modify: `src/StateMachine/state_machine.c:970-978` (the two public wrappers around `state_machine_execute_internal`)

- [ ] **Step 1: Write the failing tests**

Append to `test/test_state_machine.cpp` (uses `ChangeSink` from Task 1):

```cpp
TEST_F(TestStateMachine, ChangeHookPreviewCarriesTypeAndTarget) {
  state_set_change_hook(state, ChangeSink::hook, nullptr);
  ChangeSink::call_count = 0;

  operation_t* op = make_lock_op();
  ASSERT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  operation_destroy(op);

  // preview is "<type> <first resource>" — assert it mentions both.
  ASSERT_NE(ChangeSink::last_event, nullptr);
  EXPECT_NE(strstr(ChangeSink::last_event->preview, "lock"), nullptr);
  EXPECT_NE(strstr(ChangeSink::last_event->preview, "test_resource"), nullptr);
  state_set_change_hook(state, nullptr, nullptr);
}
```

(Preview assertions drive Task 2's implementation; the kind/result assertions from Task 1 already pass.)

- [ ] **Step 2: Implement**

Replace the two wrappers near state_machine.c:970-978. Current code:

```c
crabs_error_e state_machine_execute(state_t* state, operation_t* op) {
  ...
  return state_machine_execute_internal(state, op, false, true);
}
crabs_error_e state_machine_execute_scheduled(state_t* state, operation_t* op) {
  ...
  return state_machine_execute_internal(state, op, true, false);
}
```

New (keep any existing guard code inside the wrappers; only the tail changes):

```c
// Human-readable "<type> <first resource>" for change events. Empty target
// renders as just the type.
static void _op_preview(const operation_t* op, char* out, size_t out_size) {
  if (op == NULL) { out[0] = '\0'; return; }
  const char* target = (op->resource_count > 0 && op->resources != NULL)
                           ? op->resources[0] : "";
  snprintf(out, out_size, "%s%s%s", op->type, target[0] != '\0' ? " " : "",
           target);
}
```

and:

```c
crabs_error_e state_machine_execute(state_t* state, operation_t* op) {
  char preview[CRABS_MAX_OP_NAME + CRABS_MAX_USER_ID + 2];
  _op_preview(op, preview, sizeof(preview));
  crabs_error_e rc = state_machine_execute_internal(state, op, false, true);
  // CRABS_ERR_ALREADY_EXECUTED is an idempotent skip: no mutation, no event.
  if (rc != CRABS_ERR_ALREADY_EXECUTED) {
    state_notify_change_for_op(state, CRABS_CHANGE_OP, op, preview, rc);
  }
  return rc;
}

crabs_error_e state_machine_execute_scheduled(state_t* state, operation_t* op) {
  char preview[CRABS_MAX_OP_NAME + CRABS_MAX_USER_ID + 16];
  memcpy(preview, "scheduled ", strlen("scheduled "));
  _op_preview(op, preview + strlen("scheduled "),
              sizeof(preview) - strlen("scheduled "));
  crabs_error_e rc = state_machine_execute_internal(state, op, true, false);
  if (rc != CRABS_ERR_ALREADY_EXECUTED) {
    state_notify_change_for_op(state, CRABS_CHANGE_SCHEDULE, op, preview, rc);
  }
  return rc;
}
```


- [ ] **Step 3: Build and run**

Run: `cmake --build build -j 8 2>&1 | grep -E "error" | head -5; ctest --test-dir build -R "TestStateMachine" --output-on-failure 2>&1 | tail -3`
Expected: all TestStateMachine tests pass, including the new preview test.

- [ ] **Step 4: Commit**

```bash
git add src/StateMachine/state_machine.c src/StateMachine/state_machine.h test/test_state_machine.cpp
git commit -m "feat: fire change hook on execute and scheduled-materialization paths"
```

---

### Task 3: Attribute-machine, trigger, and scheduler failure fire sites (TDD)

**Files:**
- Modify: `src/Attribute/attribute_machine.c` (9 mutation sites)
- Modify: `src/Trigger/trigger.c` (issue_temporary effect site, ~line 96)
- Modify: `src/Scheduler/scheduler.c` (durable failure records, 4 sites)
- Test: `test/test_attribute_machine.cpp`, `test/test_scheduler.cpp`

- [ ] **Step 1: Write the failing attribute-machine test**

Append to `test/test_attribute_machine.cpp`:

```cpp
// Change notification: attribute mutations fire CRABS_CHANGE_ATTRIBUTE.
TEST_F(TestAttributeMachine, ChangeHookFiresOnAttributeMutations) {
  static const crabs_change_event_t* captured_event;
  static int captured_count;
  captured_count = 0;
  state_set_change_hook(&am->base_state, [](state_t* hook_state,
                                            const crabs_change_event_t* event,
                                            void* user_data) {
    (void)hook_state; (void)user_data;
    captured_event = event;
    captured_count++;
  }, nullptr);
  // NOTE: captureless lambdas convert to function pointers; the statics
  // above make the state reachable. Reset them before use (done above).

  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(attribute_machine_register_user(am, "bob", user_pk, NULL), CRABS_SUCCESS);
  EXPECT_EQ(captured_count, 1);
  EXPECT_EQ(captured_event->kind, CRABS_CHANGE_ATTRIBUTE);
  EXPECT_STREQ(captured_event->type, "register_user");
  EXPECT_STREQ(captured_event->target, "bob");

  ASSERT_EQ(attribute_machine_grant_role(am, "bob", "role", "member", "admin"), CRABS_SUCCESS);
  EXPECT_EQ(captured_count, 2);
  EXPECT_STREQ(captured_event->type, "grant_role");

  ASSERT_EQ(attribute_machine_revoke_user(am, "bob", "admin"), CRABS_SUCCESS);
  EXPECT_EQ(captured_count, 3);
  EXPECT_STREQ(captured_event->type, "revoke_user");

  state_set_change_hook(&am->base_state, nullptr, nullptr);
}
```

(Captureless lambdas may reference variables with static storage duration, so this compiles — the statics make the sink reachable without a capturing callable.)

- [ ] **Step 2: Run to verify failure, then wire the attribute sites**

Run: `ctest --test-dir build -R "ChangeHookFiresOnAttributeMutations" 2>&1 | tail -2` → FAIL (captured_count 0).

In `src/Attribute/attribute_machine.c`, `attribute_machine.h` includes `../StateMachine/state_machine.h` already (verify; add it if not). Add this helper near `_check_signer_is_active_admin`:

```c
// Fire the state change hook (devtools change events) for an attribute
// mutation. am->base_state carries the hook; preview is a short summary.
static void _notify_attribute_change(attribute_machine_t* am, const char* action,
                                     const char* target_user, const char* preview) {
  state_notify_change(&am->base_state, CRABS_CHANGE_ATTRIBUTE, action, NULL,
                      NULL, am->base_state.config.bootstrap_admin, target_user,
                      preview, CRABS_SUCCESS);
}
```

Then, immediately before the final `return CRABS_SUCCESS;` of each of these functions, add one call (action strings exactly as shown; use the function's own locals for target/preview):

| function | call |
|---|---|
| `attribute_machine_register_user` | `_notify_attribute_change(am, "register_user", user_id, "user registered");` |
| `attribute_machine_grant_role` | `_notify_attribute_change(am, "grant_role", target_user, role_value_pairs);` — build with `snprintf(preview, sizeof(preview), "%s:%s", role, value);` |
| `attribute_machine_self_assert` | `_notify_attribute_change(am, "self_assert", signer_id, attribute);` |
| `attribute_machine_verify_identity` | `_notify_attribute_change(am, "verify_identity", target_user, attribute);` |
| `attribute_machine_revoke_role` | `_notify_attribute_change(am, "revoke_role", target_user, role);` |
| `attribute_machine_suspend_user` | `_notify_attribute_change(am, "suspend_user", user_id, "user suspended");` |
| `attribute_machine_suspend_user_internal` | `_notify_attribute_change(am, "suspend_user", user_id, "key-rotation suspension");` |
| `attribute_machine_activate_user` | `_notify_attribute_change(am, "activate_user", target_user, "user activated");` |
| `attribute_machine_revoke_user` | `_notify_attribute_change(am, "revoke_user", user_id, "user revoked");` |

`attribute_machine_issue_temporary` (same file): fire with action `"issue_temporary"`, target = the trigger/user the attribute was issued to (the function's own target parameter), preview = the attribute name.

Each function has its own preview buffer — declare `char preview[64];` (or an existing suitable buffer) at the top of the success path where needed. Do NOT fire on failure returns.

- [ ] **Step 3: Scheduler durable-failure events**

In `src/Scheduler/scheduler.c` there are four `state_machine_log_schedule_failure(...)` call sites (one-shot undecodable bytes ~line 195, one-shot failure ~line 240, recurring undecodable ~line 285, recurring failure ~line 325). Immediately AFTER each call, add:

```c
state_notify_change(state, CRABS_CHANGE_SCHEDULE, "__schedule_failed__",
                    failure_uuid, entry->submitter, NULL, NULL,
                    "schedule failed; durable failure recorded",
                    CRABS_ERR_INTERNAL);
```

For the recurring failure site the uuid variable is the occurrence's uuid and the signer is `occurrence->signer_id` — use those variables, matching each site's existing locals. Include `../StateMachine/state_machine.h` is already present (scheduler.h includes it).

- [ ] **Step 4: Trigger effect event**

In `src/Trigger/trigger.c`, the effect site around line 96 calls `attribute_machine_issue_temporary(...)`. After a successful call (`err == CRABS_SUCCESS`), add:

```c
state_notify_change(state, CRABS_CHANGE_TRIGGER, "issue_temporary", NULL,
                    NULL, NULL, attribute, "trigger issued temporary attribute",
                    CRABS_SUCCESS);
```

using the site's actual variable names for `attribute` (the attribute name being issued; read the surrounding code and pass what is in scope — the op's target attribute string). Include `../StateMachine/state_machine.h` if not already included.

- [ ] **Step 5: Write the scheduler/trigger tests**

In `test/test_scheduler.cpp` (uses `g_sched_mock_ops`, `register_schedule_test_policies`, `make_counter_op`, `stamp_unique_uuid`, `crabs_test_sign_op_with` — follow the pattern in `SchedulerRecurring.FiresOnCadenceUntilCountExhausted`):

```cpp
// Change notification: each materialized slot fires a SCHEDULE event;
// budget-deferred slots fire nothing until they actually fire.
TEST(SchedulerRecurring, ChangeHookFiresPerMaterializedSlot) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  register_schedule_test_policies(&env);
  state_t* state = env.state;
  state_set_time_source(state, &g_sched_mock_ops);
  g_sched_mock_time.seconds = 1000000;
  g_sched_mock_time.nanos = 0;
  g_sched_mock_time.valid = true;

  static int change_count;
  change_count = 0;
  scheduler_set_max_occurrences_per_tick(state, 2);
  state_set_change_hook(state, [](state_t* hook_state,
                                  const crabs_change_event_t* event,
                                  void* user_data) {
    (void)hook_state; (void)user_data;
    if (event->kind == CRABS_CHANGE_SCHEDULE) change_count++;
  }, nullptr);

  operation_t* embedded = make_counter_op("mint", "admin");
  stamp_unique_uuid(embedded);
  crabs_test_sign_op_with(state->attr_machine, env.admin_key, embedded);
  ASSERT_NE(scheduler_schedule_recurring(
      state, 1000001000, 1000, 3, 0, "admin", embedded), 0u);
  operation_destroy(embedded);

  // Budget 2: only slots 1000001000 and 1000002000 fire → 2 events.
  ASSERT_EQ(scheduler_process_due(state, 1000003000u), CRABS_SUCCESS);
  EXPECT_EQ(change_count, 2);
  state_set_change_hook(state, nullptr, nullptr);
  crabs_test_env_destroy(&env);
}
```

In `test/test_trigger.cpp`, add a test asserting the TRIGGER event fires when a threshold trigger issues an attribute (mirror an existing trigger-fires test's setup; assert `event->kind == CRABS_CHANGE_TRIGGER`).

- [ ] **Step 6: Build and run everything affected**

Run: `cmake --build build -j 8 2>&1 | grep -E "error" | head -5; ctest --test-dir build -R "TestAttributeMachine|Scheduler|Trigger" 2>&1 | tail -3`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/Attribute/attribute_machine.c src/Trigger/trigger.c src/Scheduler/scheduler.c test/test_attribute_machine.cpp test/test_scheduler.cpp test/test_trigger.cpp
git commit -m "feat: fire change events from attribute, trigger, and schedule paths"
```

---

### Task 4: Devtools recorder behind the hook + layer/preview in the ring (TDD)

**Files:**
- Modify: `src/Devtools/devtools.h`, `src/Devtools/devtools.c` (record API takes `crabs_change_event_t`; ring stores layer + preview; events JSON gains `layer` + `preview`)
- Modify: `src/Util/wasm_helpers.c` (register devtools hook at node creation; DELETE the direct `devtools_record_event` calls at wasm_helpers.c:186-192 and the ones in `src/Scheduler/scheduler.c` — the recorder now runs from the hook)
- Test: `test/test_devtools.cpp`

- [ ] **Step 1: Write the failing tests**

In `test/test_devtools.cpp` (uses the existing snapshot/ring helpers — follow `DevtoolsEvents.*` tests):

```cpp
// The recorder runs from the change hook: attribute mutations, which no
// direct call site ever recorded, now land in the ring.
TEST(DevtoolsEvents, RecordsAttributeMutationsViaChangeHook) {
  // Build a node the same way crabs_wasm_node_create does: the hook must be
  // registered by the node creator. Use the existing test node factory.
  attribute_machine_t* am = make_devtools_test_am();  // reuse an existing helper
  // Simulate the wasm node creator's registration:
  state_set_change_hook(&am->base_state, devtools_change_hook, am);

  uint8_t user_pk[33];
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, NULL), CRABS_SUCCESS);

  const char* json = devtools_events_json();  // drains the ring
  ASSERT_NE(json, nullptr);
  EXPECT_NE(strstr(json, "\"layer\":\"attribute\""), nullptr);
  EXPECT_NE(strstr(json, "\"type\":\"register_user\""), nullptr);
  free((void*)json);
  attribute_machine_destroy(am);
}
```

Adapt names to the file's actual helpers (read the existing `DevtoolsEvents` tests first and copy their node construction). The assertion essentials: (a) the ring JSON contains `"layer"` for every event (`op`, `schedule`, `trigger`, or `attribute`), and (b) an attribute mutation shows up without any direct `devtools_record_event` call.

- [ ] **Step 2: Extend the ring**

In `src/Devtools/devtools.h`: replace `void devtools_record_event(state_t* state, const operation_t* op, crabs_error_e result);` with:

```c
// Record a state change into the devtools ring. Layered recorder for the
// state change hook (dev builds only).
void devtools_record_change(state_t* state, const crabs_change_event_t* event);
```

In `src/Devtools/devtools.c`:
- Add to `devtools_event_t` (the ring slot struct): `char layer[12];` and `char preview[64];`.
- Replace `devtools_record_event` with:

```c
static const char* _change_kind_name(crabs_change_kind_e kind) {
  switch (kind) {
    case CRABS_CHANGE_OP:        return "op";
    case CRABS_CHANGE_SCHEDULE:  return "schedule";
    case CRABS_CHANGE_TRIGGER:   return "trigger";
    case CRABS_CHANGE_ATTRIBUTE: return "attribute";
    default:                     return "op";
  }
}

void devtools_record_change(state_t* state, const crabs_change_event_t* event) {
  if (!event || !event->type) return;

  devtools_event_t* slot = &devtools_ring[devtools_ring_head];
  memset(slot, 0, sizeof(*slot));
  slot->seq = ++devtools_event_seq;
  strncpy(slot->op_type, event->type ? event->type : "?", CRABS_MAX_OP_NAME - 1);
  if (event->uuid != NULL) {
    _hex_encode_uuid(slot->uuid_hex, event->uuid);
  }
  strncpy(slot->signer_id, event->signer_id ? event->signer_id : "",
          CRABS_MAX_USER_ID - 1);
  strncpy(slot->node_id, event->node_id ? event->node_id : "",
          CRABS_MAX_USER_ID - 1);
  slot->lamport_time = 0;  // attribute/trigger events carry no lamport stamp
  if (event->uuid != NULL && event->kind == CRABS_CHANGE_OP) {
    // lamport/hlc details live on the operation only for op kinds; the
    // operation pointer is not available here, so the ring keeps the fields
    // zero for other kinds. Existing op events keep parity because the hook
    // fires with the same information the old direct call had.
  }
  strncpy(slot->target, event->target ? event->target : "",
          CRABS_MAX_USER_ID - 1);
  strncpy(slot->layer, _change_kind_name(event->kind), sizeof(slot->layer) - 1);
  strncpy(slot->preview, event->preview ? event->preview : "",
          sizeof(slot->preview) - 1);
  slot->result = event->result;

  devtools_ring_head = (devtools_ring_head + 1) % CRABS_DEVTOOLS_RING_SIZE;
  if (devtools_ring_used < CRABS_DEVTOOLS_RING_SIZE) {
    devtools_ring_used++;
  }
  (void)state;
}
```

NOTE on lamport/HLC: the old recorder copied `op->lamport_time` and `op->hlc`. To preserve that for op/schedule kinds WITHOUT keeping operation pointers in the event, extend `crabs_change_event_t` in data_model.h with two optional fields:

```c
  bool                has_hlc;
  crabs_hlc_t         hlc;         // valid when has_hlc
  uint64_t            lamport_time;
```

and set them in `state_notify_change_for_op` from the op (same logic as the old recorder: `op->ordering_system == CRABS_ORDERING_HLC ? has_hlc=true,hlc=op->hlc : has_hlc=false`; `lamport_time = op->lamport_time`). The devtools recorder copies them. Update Task 1's header/code blocks accordingly.

- In `_write_event_json` (devtools.c:190-218) add two fields after `"target"`:

```c
  // "layer":"op|schedule|trigger|attribute", "preview":"<short summary>"
  _json_writer_raw(writer, ",\"layer\":\"");
  _json_writer_raw(writer, slot->layer);
  _json_writer_raw(writer, "\",\"preview\":");
  _json_writer_string(writer, slot->preview);
```

(Adapt to the file's actual JSON helper names — read `_write_event_json` first; the existing code writes `"target"` with an escaped-string helper; use the same helper for `preview`.)

- [ ] **Step 3: Rewire the recorder through the hook**

In `src/Util/wasm_helpers.c`:

1. Delete the `#ifdef CRABS_ENABLE_DEVTOOLS / devtools_record_event(...)` block from `crabs_wasm_execute` (~lines 186-192).
2. Near the devtools exports (~line 650), add:

```c
#ifdef CRABS_ENABLE_DEVTOOLS
static void _devtools_change_hook(state_t* state,
                                  const crabs_change_event_t* event,
                                  void* user_data) {
  (void)state; (void)user_data;
  devtools_record_change(state, event);
}
#endif
```

3. In `crabs_wasm_node_create` (the function that builds the attribute machine for `Node.create`), after successful creation add:

```c
#ifdef CRABS_ENABLE_DEVTOOLS
  state_set_change_hook(&am->base_state, _devtools_change_hook, am);
#endif
```

4. In `src/Scheduler/scheduler.c`, delete the two `devtools_record_event` call sites (~lines 241-246 and ~320-323) and the `#ifdef CRABS_ENABLE_DEVTOOLS #include` if now unused. Scheduled fires now arrive via `state_machine_execute_scheduled`'s hook (kind SCHEDULE, Task 2).

Run a `grep -rn "devtools_record_event" src/` afterwards: it must return nothing (every caller removed; the symbol replaced by `devtools_record_change`).

- [ ] **Step 4: Build and run**

Run: `cmake --build build -j 8 2>&1 | grep -E "error" | head -5; ctest --test-dir build -R "Devtools|Scheduler|TestStateMachine" 2>&1 | tail -3`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/Devtools/devtools.h src/Devtools/devtools.c src/Util/wasm_helpers.c src/Scheduler/scheduler.c src/CRABS/data_model.h src/StateMachine/state_machine.h src/StateMachine/state_machine.c test/test_devtools.cpp
git commit -m "feat: record devtools events from the change hook with layers and previews"
```

---

### Task 5: JS change events — trampoline export + `node.on('change')` (TDD)

**Files:**
- Modify: `src/Util/wasm_helpers.c` (trampoline export + core change-hook forward; works in prod too)
- Modify: `build_wasm.sh` (export `_crabs_wasm_set_change_trampoline`)
- Modify: `bindings/wasm/bindings-core.js`, `bindings/wasm/index.d.ts`
- Test: `bindings/wasm/test/change-events.js` (new)

- [ ] **Step 1: C side**

In `src/Util/wasm_helpers.c` (near the top, after includes):

```c
// ============================================================
// Change-event forwarding to JS
// ============================================================
// A single module-wide JS trampoline receives one JSON string per change
// event. Registered once per module by any Node via
// crabs_wasm_set_change_trampoline. The C-side hook is registered per node
// inside crabs_wasm_node_create (always, not just in dev builds — events
// work without the devtools ring).

static void (*s_js_change_trampoline)(const char* json) = NULL;

static void _forward_change_to_js(state_t* state,
                                  const crabs_change_event_t* event,
                                  void* user_data) {
  (void)state; (void)user_data;
  if (s_js_change_trampoline == NULL || event == NULL) return;
  char* json = _change_event_json(event);
  if (json == NULL) return;
  s_js_change_trampoline(json);
  free(json);
}
```

Add the JSON builder (static, in the same file — string ids come from
constrained charsets, but still escape `"` and `\`):

```c
// Serialize a change event as a JSON object string (malloc'd; caller frees).
static void _json_escape_into(const char* src, char* out, size_t out_size) {
  size_t out_index = 0;
  for (const char* p = (src != NULL) ? src : ""; *p != '\0'; p++) {
    if (out_index + 2 >= out_size) break;
    if (*p == '"' || *p == '\\') out[out_index++] = '\\';
    out[out_index++] = *p;
  }
  out[out_index] = '\0';
}

static char* _change_event_json(const crabs_change_event_t* event) {
  char type_buf[CRABS_MAX_OP_NAME + 8];
  char signer_buf[CRABS_MAX_USER_ID + 8];
  char node_buf[CRABS_MAX_USER_ID + 8];
  char target_buf[CRABS_MAX_USER_ID + 8];
  char preview_buf[128];
  _json_escape_into(event->type, type_buf, sizeof(type_buf));
  _json_escape_into(event->signer_id, signer_buf, sizeof(signer_buf));
  _json_escape_into(event->node_id, node_buf, sizeof(node_buf));
  _json_escape_into(event->target, target_buf, sizeof(target_buf));
  _json_escape_into(event->preview, preview_buf, sizeof(preview_buf));

  char uuid_hex[CRABS_UUID_SIZE * 2 + 1];
  uuid_hex[0] = '\0';
  if (event->uuid != NULL) {
    static const char hex_chars[] = "0123456789abcdef";
    for (uint32_t uuid_byte_index = 0; uuid_byte_index < CRABS_UUID_SIZE; uuid_byte_index++) {
      uuid_hex[uuid_byte_index * 2] = hex_chars[event->uuid[uuid_byte_index] >> 4];
      uuid_hex[uuid_byte_index * 2 + 1] = hex_chars[event->uuid[uuid_byte_index] & 0x0F];
    }
    uuid_hex[CRABS_UUID_SIZE * 2] = '\0';
  }

  const char* kind_name = "op";
  switch (event->kind) {
    case CRABS_CHANGE_SCHEDULE:  kind_name = "schedule"; break;
    case CRABS_CHANGE_TRIGGER:   kind_name = "trigger"; break;
    case CRABS_CHANGE_ATTRIBUTE: kind_name = "attribute"; break;
    default: break;
  }

  size_t needed = strlen(type_buf) + strlen(signer_buf) + strlen(node_buf) +
                  strlen(target_buf) + strlen(preview_buf) + 160;
  char* json = (char*)get_memory(needed);
  if (json == NULL) return NULL;
  snprintf(json, needed,
           "{\"kind\":\"%s\",\"type\":\"%s\",\"uuid\":\"%s\","
           "\"signer\":\"%s\",\"node\":\"%s\",\"target\":\"%s\","
           "\"preview\":\"%s\",\"result\":%u}",
           kind_name, type_buf, uuid_hex, signer_buf, node_buf, target_buf,
           preview_buf, (unsigned)event->result);
  return json;
}
```

In `crabs_wasm_node_create`, after creating the attribute machine (and AFTER the devtools hook registration from Task 4 so dev builds get both — call `state_set_change_hook` once, forwarding to both; simplest correct shape):

```c
  // Change events: one hook per node; dev builds record to the ring, all
  // builds forward to the JS trampoline. One registration chain.
  state_set_change_hook(&am->base_state, _node_change_hook, am);
```

with a single C hook that does both jobs (devtools recording guarded by the ifdef):

```c
static void _node_change_hook(state_t* state,
                              const crabs_change_event_t* event,
                              void* user_data) {
  (void)state;
#ifdef CRABS_ENABLE_DEVTOOLS
  devtools_record_change(state, event);
#endif
  _forward_change_to_js(state, event, user_data);
}
```

(Move the Task 4 registration here so there is exactly ONE hook per node.)

Add the export:

```c
EMSCRIPTEN_KEEPALIVE
void crabs_wasm_set_change_trampoline(void (*trampoline)(const char* json)) {
  s_js_change_trampoline = trampoline;
}
```

In `build_wasm.sh`, add `"_crabs_wasm_set_change_trampoline",` next to the other exports (~line 114).

- [ ] **Step 2: JS side**

In `bindings/wasm/bindings-core.js`, in the `Node` class (after `constructor`), add:

```js
  // Change events: 'change' listeners receive one event object per state
  // mutation, pushed from the C change hook through a WASM trampoline.
  on(eventName, listener) {
    if (eventName !== 'change' || typeof listener !== 'function') return;
    ensureChangeTrampoline(this._M);
    getChangeListeners(this._M).push({ node: this.adminId, listener });
  }

  off(eventName, listener) {
    if (eventName !== 'change') return;
    const listeners = getChangeListeners(this._M);
    const entry_index = listeners.findIndex(
      (entry) => entry.listener === listener);
    if (entry_index >= 0) listeners.splice(entry_index, 1);
  }
```

and at module scope (top of `bindings-core.js`, after the require/imports):

```js
// Module-wide change-event plumbing: one trampoline per WASM module,
// dispatching to every Node's listeners (filtered by node id, which is the
// bootstrap admin id stamped into op->node_id).
const _changeListenerRegistry = new WeakMap();  // M -> array of {node, listener}

function getChangeListeners(M) {
  if (!_changeListenerRegistry.has(M)) {
    _changeListenerRegistry.set(M, []);
  }
  return _changeListenerRegistry.get(M);
}

function ensureChangeTrampoline(M) {
  if (_changeListenerRegistry.get(M)?._trampoline) return;
  const listeners = getChangeListeners(M);
  const trampoline = M.addFunction((jsonPointer) => {
    const text = jsonPointer ? M.UTF8ToString(jsonPointer) : '';
    let event;
    try {
      event = JSON.parse(text);
    } catch (parseError) {
      return;  // malformed event: drop, never throw into C
    }
    for (const entry of listeners.slice()) {
      if (entry.node != null && event.node !== entry.node) continue;
      try {
        entry.listener(event);
      } catch (listenerError) {
        console.warn('crabs: change listener failed', listenerError);
      }
    }
  }, 'vi');
  listeners._trampoline = trampoline;
  M._crabs_wasm_set_change_trampoline(trampoline);
}
```

In `bindings/wasm/index.d.ts`, inside the `Node` interface (after `revokeUser`):

```ts
  /** Subscribe to state-change events ('change' only). */
  on(eventName: 'change', listener: (event: CrabsChangeEvent) => void): void;
  /** Remove a previously registered 'change' listener. */
  off(eventName: 'change', listener: (event: CrabsChangeEvent) => void): void;
```

and near the other interfaces:

```ts
export interface CrabsChangeEvent {
  kind: 'op' | 'schedule' | 'trigger' | 'attribute';
  type: string;
  uuid: string;
  signer: string;
  node: string;
  target: string | null;
  preview: string;
  result: number;  // crabs_error_e
}
```

- [ ] **Step 3: Smoke test**

Create `bindings/wasm/test/change-events.js`:

```js
//
// change-events.js — smoke test for node.on('change') push events.
//
'use strict';

const assert = require('assert');
const { Node, KeyPair, Operation } = require('../dev.js');

async function main() {
  const node = await Node.create('admin', { ordering: 'hlc' });
  const key = await KeyPair.generate();
  node.registerUser('alice', key.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'admin');
  node.addCounter('views');
  node.setPolicy('view', 'AND role:member adult');

  const events = [];
  node.on('change', (event) => events.push(event));

  const op = await Operation.create('view');
  op.signerId = 'alice';
  op.nodeId = 'alice';
  node.sign(op, key.privateKeyHex());
  node.execute(op);
  node.incrementCounter('views', 1, 'alice');

  assert.ok(events.length >= 2, 'expected change events from execute');
  assert.ok(events.some((event) => event.kind === 'op'),
            'expected at least one op-kind event');
  assert.ok(events.every((event) => event.node === 'admin'),
            'events must carry the node id');

  const seen = events.length;
  const listener = (event) => { throw new Error('must not fire after off'); };
  node.on('change', listener);
  node.off('change', listener);
  node.incrementCounter('views', 1, 'alice');  // would fire if off failed
  assert.strictEqual(events.length, seen, 'off must stop delivery');
  node.destroy();
  key.destroy();
  console.log('change-events smoke OK: ' + events.length + ' events');
  process.exit(0);
}

main().catch((err) => { console.error(err); process.exit(1); });
```

- [ ] **Step 4: Rebuild WASM, run smokes**

Run: `source /home/victor/emsdk/emsdk_env.sh && bash build_wasm.sh && cp build-wasm/crabs.js build-wasm/crabs.wasm build-wasm.dev/crabs.dev.js build-wasm.dev/crabs.dev.wasm bindings/wasm/ && cd bindings/wasm && node test/change-events.js && node test/smoke.js`
Expected: `change-events smoke OK`, `smoke OK`.

- [ ] **Step 5: Commit**

```bash
git add src/Util/wasm_helpers.c build_wasm.sh bindings/wasm/bindings-core.js bindings/wasm/index.d.ts bindings/wasm/test/change-events.js bindings/wasm/crabs.js bindings/wasm/crabs.wasm bindings/wasm/crabs.dev.js bindings/wasm/crabs.dev.wasm
git commit -m "feat: node.on('change') push events via WASM change trampoline"
```

---

### Task 6: Overlay shell (crabs-devtools.js)

**Files:**
- Modify: `bindings/devtools/crabs-devtools.js` (attach(), STYLES, connectedCallback)

- [ ] **Step 1: Make the default an overlay**

In `crabs-devtools.js`:

1. In `attach(node, options)` (~line 462), change the mount default:

```js
  const mount = options.mount || null;  // null → overlay mode (appended to
                                        // document.body with fixed position)
  const overlayMode = mount === null;
  const host = mount || document.body;
  host.appendChild(panel);
  if (overlayMode) panel.classList.add('overlay');
```

2. In the `STYLES` template, add overlay rules (light theme, per the styling standard):

```css
.panel.overlay {
  position: fixed;
  top: 0; right: 0; bottom: 0;
  width: 380px;
  max-width: 100vw;
  z-index: 10000;
  border-radius: 14px 0 0 14px;
  height: 100vh;
  box-shadow: -2px 0 14px rgba(0,0,0,.12);
}
.panel.overlay.collapsed { display: none; }
```

3. The existing `position:fixed bottom-right` toggle button (connectedCallback, ~lines 126-145) becomes the launcher: when overlay mode is active, clicking it toggles `.collapsed` on the overlay panel; when a `mount` was provided, keep the current in-flow collapse behavior. Show the button only in overlay mode.

4. `close()`/destroy path: `panel.remove()` already works; ensure the launcher button is removed with it (same shadow root).

- [ ] **Step 2: Update the devtools smoke test**

In `bindings/wasm/test/devtools.js`, after attaching, assert overlay behavior:

```js
// Overlay default: the panel is fixed-position and above the page.
const panelHost = result.panel;  // whatever attach() returns in this test
// (jsdom-free smoke runs in Node against the C API only; overlay assertions
// belong to the browser demo. Skip DOM assertions in the Node smoke.)
```

The Node-based smoke can only assert that attach() still constructs and refreshes. The overlay is verified by the demo (Task 10) in a browser. Update the smoke only if attach() signature changed; otherwise no change.

- [ ] **Step 3: Commit**

```bash
git add bindings/devtools/crabs-devtools.js
git commit -m "feat: devtools panel defaults to a fixed overlay with launcher button"
```

---

### Task 7: State tab — full-state tree with diffs, overview header, export

**Files:**
- Modify: `bindings/devtools/crabs-devtools.js` (replace the States/CRDT/Config tabs with one State tab; add overview header and export button)
- Modify: `bindings/devtools/devtools-api.js` (diff computation helper)

- [ ] **Step 1: Diff helper in the controller**

In `devtools-api.js`, add to the controller object:

```js
    // Flat path -> diff kind map over the whole snapshot. Paths look like
    // 'items.views.value'. Bounded buffer: only the previous snapshot is
    // retained (this is what makes a later time-travel view an add-on).
    diffFromPrevious(next) {
      const previous = this.lastSnapshot;
      const diffs = {};
      if (previous == null) return diffs;
      const walk = (before, after, path) => {
        if (previous === next) return;
        const prevValue = path.length === 0 ? previous : undefined;
        void prevValue;
      };
      // Practical implementation: flatten both snapshots into path->json maps.
      const flatten = (value, prefix, into) => {
        if (value === null || typeof value !== 'object') {
          into[prefix] = value;
          return;
        }
        if (Array.isArray(value)) {
          into[prefix] = JSON.stringify(value);
          return;
        }
        into[prefix] = '{';  // container marker
        for (const key of Object.keys(value)) {
          flatten(value[key], prefix ? prefix + '.' + key : key, into);
        }
      };
      const before = {}; const after = {};
      flatten(previous, '', before);
      flatten(next, '', after);
      for (const key of Object.keys(after)) {
        if (!(key in before)) diffs[key] = 'added';
        else if (before[key] !== after[key]) diffs[key] = 'changed';
      }
      for (const key of Object.keys(before)) {
        if (!(key in after)) diffs[key] = 'removed';
      }
      return diffs;
    },
```

…and in `pullSnapshot()`, after storing the new snapshot, expose `this.diffs = this.diffFromPrevious(snapshot)` and set `this.lastSnapshot = snapshot`. (Read the existing `pullSnapshot` body first and integrate — `previousItemStates` is superseded by this diff map; delete `previousItemStates` and the transition-diff code in devtools-api.js:79-104 that attributes transitions, since the State tab now diffs values directly.)

- [ ] **Step 2: State tree renderer**

In `crabs-devtools.js`, add a tree renderer and rework the tab body. Replace the four-tab body with two tabs (`State`, `Timeline`) — keep the tab bar markup pattern from the current file (read lines 160-210 for the tab strip construction; the tabs array becomes `['State', 'Timeline']`).

```js
// Render a snapshot subtree as an expandable tree. `diffs` maps dot-paths to
// 'added' | 'changed' | 'removed' for badge highlighting.
const BADGE_COLORS = { added: '#d1fae5', changed: '#fef3c7', removed: '#fee2e2' };
const BADGE_TEXT = { added: '#065f46', changed: '#92400e', removed: '#991b1b' };

function renderStateTree(container, snapshot, diffs, expandedPaths) {
  container.innerHTML = '';
  const renderValue = (value, path, depth) => {
    const row = document.createElement('div');
    row.className = 'tree-row';
    row.style.paddingLeft = (depth * 14) + 'px';
    const isObject = value !== null && typeof value === 'object';
    if (isObject) {
      const keys = Object.keys(value);
      const toggle = document.createElement('span');
      toggle.className = 'tree-toggle';
      const expanded = expandedPaths.has(path);
      toggle.textContent = (expanded ? '▾ ' : '▸ ') + lastKey(path) +
        ' (' + keys.length + ')';
      toggle.addEventListener('click', () => {
        if (expandedPaths.has(path)) expandedPaths.delete(path);
        else expandedPaths.add(path);
        renderStateTree(container, snapshot, diffs, expandedPaths);  // re-render
      });
      row.appendChild(toggle);
      const diff = diffs[path];
      if (diff) appendBadge(row, diff);
      container.appendChild(row);
      if (expanded) {
        for (const key of keys) renderValue(value[key], path ? path + '.' + key : key, depth + 1);
      }
    } else {
      const label = document.createElement('span');
      label.className = 'mono';
      label.textContent = lastKey(path) + ': ' + formatLeaf(value);
      row.appendChild(label);
      const diff = diffs[path];
      if (diff) appendBadge(row, diff);
      container.appendChild(row);
    }
  };
  const lastKey = (path) => path.split('.').pop();
  const appendBadge = (row, diff) => {
    const badge = document.createElement('span');
    badge.className = 'diff-badge';
    badge.textContent = diff;
    badge.style.background = BADGE_COLORS[diff] || '#f3f4f6';
    badge.style.color = BADGE_TEXT[diff] || '#374151';
    row.appendChild(badge);
  };
  renderValue(snapshot, '', 0);
}

// Leaf formatting: counters as numbers, sets/arrays inline, opaque payloads
// already arrive as "[encrypted: N bytes]" strings from the C snapshot.
function formatLeaf(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}
```

The full snapshot arrives as JSON; top-level sections render as tree roots: `items`, `policies`, `triggers`, `users`, `schedules`, `log_head`. Seed `expandedPaths` with `['items']` so items show on first open.

- [ ] **Step 3: Overview header + export button**

Above the tab bar in the panel body, add a header strip:

```js
// Overview: node id, ordering system, HLC, version, log head, schedules.
const overview = document.createElement('div');
overview.className = 'overview mono';
overview.textContent = overviewLine(this.data.snapshot);
```

```js
function overviewLine(snapshot) {
  if (!snapshot) return '';
  const pending = (snapshot.schedules || []).length;
  const head = (snapshot.log_head && snapshot.log_head.state_hash) || '';
  return '#' + snapshot.node_id + ' · v' + snapshot.version +
    ' · hlc ' + (snapshot.hlc || '—') + ' · log ' + head.slice(0, 8) +
    ' · ' + pending + ' pending';
}
```

(Adapt field names to what `devtools_snapshot_json` actually emits — read `src/Devtools/devtools.c:570-610` for exact keys: `node_id`, `version`, `hlc`, `log_head{entries,state_hash}`, `schedules`.)

Export button in the panel header row:

```js
const exportButton = document.createElement('button');
exportButton.textContent = 'Export';
exportButton.addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(this.data.snapshot, null, 2)],
                        { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'crabs-snapshot-' + (this.data.snapshot.node_id || 'node') + '.json';
  link.click();
  URL.revokeObjectURL(url);
});
```

- [ ] **Step 4: Timeline click → flash item in State tree**

When a timeline row is clicked, if the event has a `target`, ensure the `items.<target>` path is in `expandedPaths`, switch to the State tab, and add a `.flash` CSS class (yellow background fading via transition) to that row.

- [ ] **Step 5: Commit**

```bash
git add bindings/devtools/crabs-devtools.js bindings/devtools/devtools-api.js
git commit -m "feat: full-state inspector tree with diff badges, overview header, export"
```

---

### Task 8: Timeline layers + payload previews

**Files:**
- Modify: `bindings/devtools/crabs-devtools.js` (render layer pill + preview; layer filter)

- [ ] **Step 1: Layer pill and filter**

Each timeline row gains a colored pill from `event.layer` (`op` blue `#dbeafe`, `schedule` amber `#fef3c7`, `trigger` green `#d1fae5`, `attribute` gray `#e5e7eb`), and a filter row of layer checkboxes above the list (default: all on). Filtering composes with the existing text filter.

```js
const LAYER_COLORS = {
  op: ['#dbeafe', '#1e40af'], schedule: ['#fef3c7', '#92400e'],
  trigger: ['#d1fae5', '#065f46'], attribute: ['#e5e7eb', '#374151'],
};
```

- [ ] **Step 2: Preview text**

Append `event.preview` (when non-empty) to the row text after the target: `#seq · type · target · preview · result`. The C ring writes `preview` since Task 4; keep `preview: ''` rendering as nothing.

- [ ] **Step 3: Commit**

```bash
git add bindings/devtools/crabs-devtools.js
git commit -m "feat: timeline layer pills, filters, and payload previews"
```

---

### Task 9: crabs-node (N-API) binding — `on('change')` / `off('change')`

**Files:**
- Modify: `bindings/node/src/crabs_node.cc`, `bindings/node/index.d.ts`, `bindings/node/test/test.js`

- [ ] **Step 1: C++ emitter**

In `crabs_node.cc`, Node class — members (private section, near `admin_id_`):

```cpp
  std::vector<Napi::FunctionReference> change_listeners_;
```

`on('change', cb)` returns an unsubscribe function (identity matching in
N-API is awkward, so the returned closure removes the slot):

```cpp
  // node.on('change', cb) returns an off() function.
  Napi::Value On(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsFunction())
      throw Napi::TypeError::New(env, "Expected (eventName, listener)");
    if (info[0].As<Napi::String>().Utf8Value() != "change")
      return env.Undefined();
    change_listeners_.push_back(
        Napi::Persistent(info[1].As<Napi::Function>()));
    size_t slot = change_listeners_.size() - 1;
    auto* node_self = this;
    return Napi::Function::New(env, [node_self, slot](const Napi::CallbackInfo& off_info) {
      (void)off_info;
      if (slot < node_self->change_listeners_.size()) {
        node_self->change_listeners_[slot].Reset();
      }
    });
  }
```

Register the C change hook once, at the end of the Node constructor (after
`state_set_node_key`):

```cpp
    state_set_change_hook(&am_->base_state, _node_change_hook_thunk, this);
```

with a file-scope thunk and the emit method:

```cpp
static const char* _change_kind_name(crabs_change_kind_e kind) {
  switch (kind) {
    case CRABS_CHANGE_OP:        return "op";
    case CRABS_CHANGE_SCHEDULE:  return "schedule";
    case CRABS_CHANGE_TRIGGER:   return "trigger";
    case CRABS_CHANGE_ATTRIBUTE: return "attribute";
    default:                     return "op";
  }
}

static void _node_change_hook_thunk(state_t* state,
                                    const crabs_change_event_t* event,
                                    void* user_data) {
  (void)state;
  static_cast<Node*>(user_data)->EmitChange(event);
}

  void EmitChange(const crabs_change_event_t* event) {
    if (event == NULL) return;
    // Same-thread: execute() is called from JS, so the hook fires on the
    // JS thread and a plain synchronous call is safe.
    Napi::Env env = Env();
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("kind", Napi::String::New(env, _change_kind_name(event->kind)));
    obj.Set("type", Napi::String::New(env, event->type ? event->type : ""));
    obj.Set("signer", event->signer_id ? Napi::String::New(env, event->signer_id) : env.Null());
    obj.Set("node", event->node_id ? Napi::String::New(env, event->node_id) : env.Null());
    obj.Set("target", event->target ? Napi::String::New(env, event->target) : env.Null());
    obj.Set("preview", Napi::String::New(env, event->preview ? event->preview : ""));
    obj.Set("result", Napi::Number::New(env, (double)event->result));
    Napi::Value undefined_value = env.Undefined();
    for (auto& listener : change_listeners_) {
      if (listener.IsEmpty()) continue;
      try {
        listener.Call(undefined_value, {obj});
      } catch (...) {
        // A throwing listener must never break the state machine.
      }
    }
  }
```

(Place `_change_kind_name`/`_node_change_hook_thunk` at file scope near the
other static helpers; `EmitChange` is a Node method. Note the thunk is
declared before the class or forward-declared.)

- [ ] **Step 2: Test**

In `bindings/node/test/test.js`, add:

```js
// Test: change events fire on execute.
const changeEvents = [];
const unsubscribe = node.on('change', (event) => changeEvents.push(event));
node.execute(viewOp);
assert.ok(changeEvents.length > 0, 'change events should fire on execute');
unsubscribe();
```

- [ ] **Step 3: Build and test**

Run: `cd bindings/node && npm run build && npm test` → `19+ passed, 0 failed`.

- [ ] **Step 4: Commit**

```bash
git add bindings/node/src/crabs_node.cc bindings/node/index.d.ts bindings/node/test/test.js
git commit -m "feat: node.on('change') events in the N-API binding"
```

---

### Task 10: Demo update, docs, full verification

**Files:**
- Modify: `examples/devtools_demo/demo.js`, `bindings/wasm/README.md`, `bindings/wasm/test/devtools.js`
- Rebuild: WASM artifacts, native suite

- [ ] **Step 1: Demo**

In `examples/devtools_demo/demo.js`:
- Remove `options.mount` from both `attach()` calls so the panels overlay (true overlay default).
- Remove the `refreshPanels()` helper and all its call sites (demo.js:33-35, 122, 134, 152, 170) — change events drive refreshes now.
- Keep the BroadcastChannel relay; peer ops arriving via `execute` fire change events automatically.

- [ ] **Step 2: README**

In `bindings/wasm/README.md`, under the Devtools build section, document: overlay default + `mount` opt-out, the State tree (diff badges, export), timeline layers, and `node.on('change', cb)` / `node.off('change', cb)` with a short example:

```js
const unsubscribe = node.on('change', (event) => {
  console.log(event.kind, event.type, event.target, event.result);
});
unsubscribe();  // when done
```

- [ ] **Step 3: Full verification**

```bash
cmake --build build -j 8 && ctest --test-dir build 2>&1 | tail -2
source /home/victor/emsdk/emsdk_env.sh && bash build_wasm.sh
cp build-wasm/crabs.js build-wasm/crabs.wasm build-wasm.dev/crabs.dev.js build-wasm.dev/crabs.dev.wasm bindings/wasm/
cd bindings/wasm && node test/smoke.js && node test/devtools.js && node test/schedules.js && node test/change-events.js
cd ../node && npm run build && npm test
```

Expected: all pass (1399+ native tests, 4 JS smokes, node binding tests).

- [ ] **Step 4: Commit artifacts + demo**

```bash
git add examples/devtools_demo/demo.js bindings/wasm/README.md bindings/wasm/crabs.js bindings/wasm/crabs.wasm bindings/wasm/crabs.dev.js bindings/wasm/crabs.dev.wasm
git commit -m "feat: demo uses overlay devtools with push refresh; document change events"
```

---

## Task dependency notes

- Tasks 1-4 are sequential (C core → execute paths → other fire sites → recorder).
- Task 5 depends on Task 4 (trampoline forwards into the hook registered in Task 4).
- Tasks 6-8 (JS UI) depend on Task 4 (ring fields) but only Task 5's events make refresh push-based; they can start after Task 4.
- Task 9 (N-API binding) depends on Task 1 only.
- Task 10 last.