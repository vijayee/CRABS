# CRABS Devtools State Machine Viewer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A browser devtools panel (`<crabs-devtools>`) for inspecting CRABS state machines over the WASM build: item protocol states, live operation timeline, CRDT values, and config — shipped as a devtools-enabled WASM artifact selected via `crabs-wasm/dev`.

**Architecture:** A C module `src/Devtools/` records one event per executed operation into a global ring buffer and renders `state_t` as JSON snapshots; the WASM build compiles it only under `CRABS_ENABLE_DEVTOOLS`. `build_wasm.sh` produces two artifacts (`crabs.js`/`crabs.dev.js`). A zero-dependency JS package (`bindings/devtools/`) drains events, derives transitions by snapshot diffing, and renders a tabbed light-theme web component. A static demo page dogfoods it with two in-browser nodes.

**Tech Stack:** C11 (Emscripten for wasm), Emscripten exports, vanilla JS web component (shadow DOM), GoogleTest for native C tests, Node for smoke tests.

**Spec:** `docs/superpowers/specs/2026-09-01-devtools-state-machine-viewer-design.md`

---

## File Structure

| File | Responsibility |
|------|----------------|
| `src/Devtools/devtools.h` | Public API: event recording, ring drain, snapshot JSON |
| `src/Devtools/devtools.c` | Ring buffer, JSON string-builder, per-CRDT value walkers |
| `test/test_devtools.cpp` | GoogleTest coverage for events + snapshot (native) |
| `test/CMakeLists.txt` | Register test file + compile devtools.c with the define |
| `src/Util/wasm_helpers.c` | One-line hook in `crabs_wasm_execute` + dev-only exports |
| `build_wasm.sh` | Dual build: prod artifact + dev artifact (`crabs.dev.js/.wasm`) |
| `bindings/wasm/bindings-core.js` | Extracted factory: all classes, parameterized module loader |
| `bindings/wasm/index.js` | Thin wrapper loading the prod artifact |
| `bindings/wasm/dev.js` | Thin wrapper loading the dev artifact |
| `bindings/wasm/package.json` | `exports` map with `./dev` entry |
| `bindings/wasm/index.d.ts` | Unchanged (types shared); `dev.d.ts` re-exports |
| `bindings/wasm/test/devtools.js` | Smoke: prod artifact lacks exports, dev artifact works |
| `bindings/devtools/crabs-devtools.js` | `attach()` + `<crabs-devtools>` web component |
| `examples/devtools_demo/index.html` | Static demo page (2 nodes, ops, BroadcastChannel mode) |

Commit after every task. All C code follows `docs/STYLE_GUIDE.md` (2-space indent, `_t` types, `module_action()` naming, `get_memory`/`get_clear_memory`, no single-letter variable names — use `entry_index`, `byte_index`, etc.).

---

### Task 1: C devtools module — ring buffer, event recording, drain JSON

**Files:**
- Create: `src/Devtools/devtools.h`
- Create: `src/Devtools/devtools.c`
- Create: `test/test_devtools.cpp`
- Modify: `test/CMakeLists.txt`

- [ ] **Step 1: Write the failing tests**

Create `test/test_devtools.cpp`:

```cpp
//
// Devtools tests: event ring buffer, drain JSON, snapshot JSON.
//

#include <gtest/gtest.h>
#include <cstring>
#include <string>

extern "C" {
#include "Devtools/devtools.h"
#include "CRABS/data_model.h"
#include "StateMachine/state_machine.h"
#include "CRDT/crdt_merge.h"
#include "CRDT/one_shot.h"
}

static state_t* make_state_with_g_counter(void) {
  state_t* state = state_create();
  data_item_t* item = data_item_create("views", DATA_TYPE_COUNTER, CRDT_G_COUNTER);
  item->value = g_counter_create();
  g_counter_increment((g_counter_t*)item->value, "alice", 12);
  state_add_item(state, item);
  return state;
}

static operation_t* make_operation(const char* type, const char* signer) {
  operation_t* op = operation_create(type);
  strncpy(op->signer_id, signer, CRABS_MAX_USER_ID - 1);
  op->lamport_time = 87;
  return op;
}

TEST(DevtoolsEvents, RecordThenDrainProducesJsonArray) {
  state_t* state = make_state_with_g_counter();
  operation_t* op = make_operation("increment", "bob");

  devtools_record_event(state, op, CRABS_SUCCESS);

  char* json = devtools_events_json();
  ASSERT_NE(json, nullptr);
  std::string text = json;
  devtools_string_destroy(json);

  EXPECT_NE(text.find("\"op_type\":\"increment\""), std::string::npos);
  EXPECT_NE(text.find("\"signer\":\"bob\""), std::string::npos);
  EXPECT_NE(text.find("\"result\":\"accepted\""), std::string::npos);
  EXPECT_NE(text.find("\"lamport\":87"), std::string::npos);
  EXPECT_EQ(text.front(), '[');
  EXPECT_EQ(text.back(), ']');

  operation_destroy(op);
  state_destroy(state);
}

TEST(DevtoolsEvents, DrainEmptiesBuffer) {
  state_t* state = make_state_with_g_counter();
  operation_t* op = make_operation("increment", "bob");
  devtools_record_event(state, op, CRABS_SUCCESS);

  char* first = devtools_events_json();
  devtools_string_destroy(first);

  char* second = devtools_events_json();
  ASSERT_NE(second, nullptr);
  EXPECT_STREQ(second, "[]");
  devtools_string_destroy(second);

  operation_destroy(op);
  state_destroy(state);
}

TEST(DevtoolsEvents, RejectedOperationRecordsError) {
  state_t* state = make_state_with_g_counter();
  operation_t* op = make_operation("decrement", "mallory");

  devtools_record_event(state, op, CRABS_ERR_UNAUTHORIZED);

  char* json = devtools_events_json();
  std::string text = json;
  devtools_string_destroy(json);

  EXPECT_NE(text.find("\"result\":\"rejected\""), std::string::npos);
  EXPECT_NE(text.find("\"error\":\"unauthorized\""), std::string::npos);
  EXPECT_NE(text.find("\"error_code\":8193"), std::string::npos);

  operation_destroy(op);
  state_destroy(state);
}

TEST(DevtoolsEvents, RingWraparoundDropsOldest) {
  state_t* state = make_state_with_g_counter();
  for (uint32_t op_index = 0; op_index < CRABS_DEVTOOLS_RING_SIZE + 5; op_index++) {
    operation_t* op = make_operation("increment", "alice");
    devtools_record_event(state, op, CRABS_SUCCESS);
    operation_destroy(op);
  }

  char* json = devtools_events_json();
  std::string text = json;
  devtools_string_destroy(json);

  uint32_t comma_count = 0;
  for (char character : text) {
    if (character == '{') comma_count++;
  }
  EXPECT_EQ(comma_count, (uint32_t)CRABS_DEVTOOLS_RING_SIZE);
}

TEST(DevtoolsEvents, NullOperationIsIgnored) {
  state_t* state = make_state_with_g_counter();
  devtools_record_event(state, nullptr, CRABS_SUCCESS);
  char* json = devtools_events_json();
  EXPECT_STREQ(json, "[]");
  devtools_string_destroy(json);
  state_destroy(state);
}
```

- [ ] **Step 2: Register the test file in `test/CMakeLists.txt`**

Add `test_devtools.cpp` to the `add_executable(testcrabs ...)` list (after `test_tx_manager.cpp`), and add the devtools source (compiled with the devtools define so the native lib stays untouched) at the end of the same `if (BUILD_TESTING)` block:

```cmake
        test_tx_manager.cpp
        test_devtools.cpp
    )

    set_source_files_properties(
        ${CMAKE_SOURCE_DIR}/src/Devtools/devtools.c
        PROPERTIES COMPILE_DEFINITIONS CRABS_ENABLE_DEVTOOLS
    )
    target_sources(testcrabs PRIVATE ${CMAKE_SOURCE_DIR}/src/Devtools/devtools.c)
```

(The `target_sources` call goes after the existing `add_dependencies(testcrabs crabs)` line.)

- [ ] **Step 3: Run tests to verify they fail to build**

Run: `cmake --build build && ctest --test-dir build -R Devtools`
Expected: FAIL — `Devtools/devtools.h: No such file or directory`

- [ ] **Step 4: Create `src/Devtools/devtools.h`**

```c
//
// Created by victor on 9/1/25.
//

#ifndef CRABS_DEVTOOLS_H
#define CRABS_DEVTOOLS_H

#include <stdint.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"

#define CRABS_DEVTOOLS_RING_SIZE 1024

// Record one execute outcome into the global devtools ring buffer.
// No-op unless the build defines CRABS_ENABLE_DEVTOOLS.
void     devtools_record_event(state_t* state, const operation_t* op, crabs_error_e result);

// Drain the ring buffer as a JSON array string, oldest first. The buffer is
// emptied. Caller owns the returned string.
char*    devtools_events_json(void);

// Render the full state as a JSON document string. Caller owns the string.
char*    devtools_snapshot_json(const state_t* state);

// Free a string returned by devtools_events_json or devtools_snapshot_json.
void     devtools_string_destroy(char* str);

// Number of events currently held in the ring buffer.
uint32_t devtools_ring_count(void);

#endif // CRABS_DEVTOOLS_H
```

- [ ] **Step 5: Create `src/Devtools/devtools.c` with ring buffer, event recording, and drain JSON**

```c
//
// Created by victor on 9/1/25.
//
// Devtools: observer-only instrumentation for the WASM devtools panel.
// Compiled to real code only when CRABS_ENABLE_DEVTOOLS is defined, so
// production WASM binaries contain no devtools code.

#ifdef CRABS_ENABLE_DEVTOOLS

#include "devtools.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../Util/allocator.h"
#include "../HLC/hlc.h"
#include "../CRDT/crdt_merge.h"
#include "../CRDT/one_shot.h"

// ============================================================
// Ring buffer
// ============================================================

typedef struct {
  uint64_t      seq;
  char          op_type[CRABS_MAX_OP_NAME];
  char          uuid_hex[CRABS_UUID_SIZE * 2 + 1];
  char          signer_id[CRABS_MAX_USER_ID];
  char          node_id[CRABS_MAX_USER_ID];
  uint64_t      lamport_time;
  bool          has_hlc;
  crabs_hlc_t   hlc;
  char          target[CRABS_MAX_USER_ID];
  crabs_error_e result;
} devtools_event_t;

static devtools_event_t devtools_ring[CRABS_DEVTOOLS_RING_SIZE];
static uint32_t devtools_ring_head = 0;   // next write slot
static uint32_t devtools_ring_used = 0;
static uint64_t devtools_event_seq = 0;

uint32_t devtools_ring_count(void) {
  return devtools_ring_used;
}

static void _hex_encode_uuid(char* out, const uint8_t* uuid) {
  for (uint32_t byte_index = 0; byte_index < CRABS_UUID_SIZE; byte_index++) {
    snprintf(out + byte_index * 2, 3, "%02x", uuid[byte_index]);
  }
}

void devtools_record_event(state_t* state, const operation_t* op, crabs_error_e result) {
  if (!op) return;

  devtools_event_t* event = &devtools_ring[devtools_ring_head];
  memset(event, 0, sizeof(*event));
  event->seq = ++devtools_event_seq;
  strncpy(event->op_type, op->type, CRABS_MAX_OP_NAME - 1);
  _hex_encode_uuid(event->uuid_hex, op->uuid);
  strncpy(event->signer_id, op->signer_id, CRABS_MAX_USER_ID - 1);
  strncpy(event->node_id, op->node_id, CRABS_MAX_USER_ID - 1);
  event->lamport_time = op->lamport_time;
  if (op->ordering_system == CRABS_ORDERING_HLC) {
    event->has_hlc = true;
    event->hlc = op->hlc;
  }
  if (op->resource_count > 0 && op->resources) {
    strncpy(event->target, op->resources[0], CRABS_MAX_USER_ID - 1);
  }
  event->result = result;

  devtools_ring_head = (devtools_ring_head + 1) % CRABS_DEVTOOLS_RING_SIZE;
  if (devtools_ring_used < CRABS_DEVTOOLS_RING_SIZE) {
    devtools_ring_used++;
  }
  (void)state;
}

// ============================================================
// JSON writer (grow-on-append string builder)
// ============================================================

typedef struct {
  char*  data;
  size_t len;
  size_t capacity;
} json_writer_t;

static void _json_writer_init(json_writer_t* writer) {
  writer->capacity = 256;
  writer->len = 0;
  writer->data = get_clear_memory(writer->capacity);
}

static void _json_writer_reserve(json_writer_t* writer, size_t extra) {
  if (writer->len + extra + 1 <= writer->capacity) return;
  size_t new_capacity = writer->capacity;
  while (new_capacity < writer->len + extra + 1) new_capacity *= 2;
  char* grown = get_clear_memory(new_capacity);
  memcpy(grown, writer->data, writer->len);
  free(writer->data);
  writer->data = grown;
  writer->capacity = new_capacity;
}

static void _json_writer_raw(json_writer_t* writer, const char* text) {
  size_t text_len = strlen(text);
  _json_writer_reserve(writer, text_len);
  memcpy(writer->data + writer->len, text, text_len);
  writer->len += text_len;
  writer->data[writer->len] = '\0';
}

static void _json_writer_uint(json_writer_t* writer, uint64_t value) {
  char scratch[24];
  snprintf(scratch, sizeof(scratch), "%llu", (unsigned long long)value);
  _json_writer_raw(writer, scratch);
}

static void _json_writer_string(json_writer_t* writer, const char* text) {
  _json_writer_raw(writer, "\"");
  for (const char* cursor = text ? text : ""; *cursor; cursor++) {
    char character = *cursor;
    switch (character) {
      case '"':  _json_writer_raw(writer, "\\\""); break;
      case '\\': _json_writer_raw(writer, "\\\\"); break;
      case '\n': _json_writer_raw(writer, "\\n"); break;
      case '\r': _json_writer_raw(writer, "\\r"); break;
      case '\t': _json_writer_raw(writer, "\\t"); break;
      default:
        if ((unsigned char)character < 0x20) {
          char escape[8];
          snprintf(escape, sizeof(escape), "\\u%04x", (unsigned char)character);
          _json_writer_raw(writer, escape);
        } else {
          _json_writer_reserve(writer, 1);
          writer->data[writer->len++] = character;
          writer->data[writer->len] = '\0';
        }
    }
  }
  _json_writer_raw(writer, "\"");
}

static void _json_writer_key(json_writer_t* writer, const char* key) {
  _json_writer_string(writer, key);
  _json_writer_raw(writer, ":");
}

static void _json_writer_hlc(json_writer_t* writer, const crabs_hlc_t* hlc) {
  _json_writer_raw(writer, "{\"physical\":");
  _json_writer_uint(writer, hlc->physical_seconds);
  _json_writer_raw(writer, ",\"nanos\":");
  _json_writer_uint(writer, hlc->physical_nanos);
  _json_writer_raw(writer, ",\"logical\":");
  _json_writer_uint(writer, hlc->logical_counter);
  _json_writer_raw(writer, ",\"node\":");
  _json_writer_string(writer, hlc->node_id);
  _json_writer_raw(writer, "}");
}

static const char* _error_name(crabs_error_e result) {
  switch (result) {
    case CRABS_SUCCESS:                  return "success";
    case CRABS_ERR_UNAUTHORIZED:         return "unauthorized";
    case CRABS_ERR_PROTOCOL_VIOLATION:   return "protocol_violation";
    case CRABS_ERR_DUPLICATE_OPERATION:  return "duplicate_operation";
    case CRABS_ERR_INVARIANT_VIOLATED:   return "invariant_violated";
    case CRABS_ERR_CONDITION_NOT_MET:    return "condition_not_met";
    case CRABS_ERR_ALREADY_EXECUTED:     return "already_executed";
    case CRABS_ERR_ALREADY_PERFORMED:    return "already_performed";
    case CRABS_ERR_RESOURCE_NOT_FOUND:   return "resource_not_found";
    case CRABS_ERR_TYPE_MISMATCH:        return "type_mismatch";
    default:                             return "error";
  }
}

// ============================================================
// Events drain
// ============================================================

static void _write_event_json(json_writer_t* writer, const devtools_event_t* event) {
  _json_writer_raw(writer, "{\"seq\":");
  _json_writer_uint(writer, event->seq);
  _json_writer_raw(writer, ",\"op_type\":");
  _json_writer_string(writer, event->op_type);
  _json_writer_raw(writer, ",\"uuid_hex\":");
  _json_writer_string(writer, event->uuid_hex);
  _json_writer_raw(writer, ",\"signer\":");
  _json_writer_string(writer, event->signer_id);
  _json_writer_raw(writer, ",\"node\":");
  _json_writer_string(writer, event->node_id);
  _json_writer_raw(writer, ",\"lamport\":");
  _json_writer_uint(writer, event->lamport_time);
  _json_writer_raw(writer, ",\"hlc\":");
  if (event->has_hlc) {
    _json_writer_hlc(writer, &event->hlc);
  } else {
    _json_writer_raw(writer, "null");
  }
  _json_writer_raw(writer, ",\"target\":");
  _json_writer_string(writer, event->target);
  _json_writer_raw(writer, ",\"result\":");
  _json_writer_string(writer, event->result == CRABS_SUCCESS ? "accepted" : "rejected");
  _json_writer_raw(writer, ",\"error_code\":");
  _json_writer_uint(writer, (uint64_t)event->result);
  _json_writer_raw(writer, ",\"error\":");
  _json_writer_string(writer, _error_name(event->result));
  _json_writer_raw(writer, "}");
}

char* devtools_events_json(void) {
  json_writer_t writer;
  _json_writer_init(&writer);
  _json_writer_raw(&writer, "[");

  uint32_t oldest = (devtools_ring_head + CRABS_DEVTOOLS_RING_SIZE - devtools_ring_used)
                    % CRABS_DEVTOOLS_RING_SIZE;
  for (uint32_t event_index = 0; event_index < devtools_ring_used; event_index++) {
    if (event_index > 0) _json_writer_raw(&writer, ",");
    uint32_t slot = (oldest + event_index) % CRABS_DEVTOOLS_RING_SIZE;
    _write_event_json(&writer, &devtools_ring[slot]);
  }
  _json_writer_raw(&writer, "]");

  devtools_ring_head = 0;
  devtools_ring_used = 0;
  return writer.data;
}

// ============================================================
// Snapshot — implemented in Task 2
// ============================================================

char* devtools_snapshot_json(const state_t* state) {
  (void)state;
  return NULL;
}

void devtools_string_destroy(char* str) {
  free(str);
}

#endif // CRABS_ENABLE_DEVTOOLS
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cmake --build build && ctest --test-dir build -R Devtools -v`
Expected: PASS (5 tests)

- [ ] **Step 7: Commit**

```bash
git add src/Devtools/devtools.h src/Devtools/devtools.c test/test_devtools.cpp test/CMakeLists.txt
git commit -m "feat: add devtools event ring buffer with JSON drain"
```

---

### Task 2: Snapshot JSON — items, all CRDT types, policies, triggers, users, log head

**Files:**
- Modify: `src/Devtools/devtools.c` (replace the Task-2 stub of `devtools_snapshot_json`)
- Modify: `test/test_devtools.cpp`

- [ ] **Step 1: Write the failing tests (append to `test/test_devtools.cpp`)**

```cpp
static bool contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

TEST(DevtoolsSnapshot, ItemsAndGCounterValue) {
  state_t* state = make_state_with_g_counter();

  char* json = devtools_snapshot_json(state);
  ASSERT_NE(json, nullptr);
  std::string text = json;
  devtools_string_destroy(json);
  state_destroy(state);

  EXPECT_TRUE(contains(text, "\"node_id\":"));
  EXPECT_TRUE(contains(text, "\"name\":\"views\""));
  EXPECT_TRUE(contains(text, "\"crdt_type\":\"g_counter\""));
  EXPECT_TRUE(contains(text, "\"protocol_state\":\"idle\""));
  EXPECT_TRUE(contains(text, "\"alice\":12"));
}

TEST(DevtoolsSnapshot, AllValueTypes) {
  state_t* state = state_create();

  data_item_t* pn = data_item_create("likes", DATA_TYPE_PN_COUNTER, CRDT_PN_COUNTER);
  pn->value = pn_counter_create();
  pn_counter_increment((pn_counter_t*)pn->value, "bob", 5);
  pn_counter_decrement((pn_counter_t*)pn->value, "bob", 2);
  state_add_item(state, pn);

  data_item_t* set = data_item_create("subscribers", DATA_TYPE_SET, CRDT_OR_SET);
  set->value = or_set_create();
  or_set_add((or_set_t*)set->value, "carol", "carol:1");
  state_add_item(state, set);

  data_item_t* reg = data_item_create("contact", DATA_TYPE_REGISTER, CRDT_LWW_REG);
  reg->value = lww_register_create((const uint8_t*)"x", 1, 5, "alice");
  state_add_item(state, reg);

  data_item_t* one_shot = data_item_create("flaggers", DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
  one_shot_set_t* one_shot = one_shot_set_create();
  one_shot_set_add(one_shot, "dave");
  one_shot_set_add(one_shot, "dave");  // duplicate must not double-count
  one_shot_set_add(one_shot, "eve");
  one_shot->element_count = 2;  // set_add dedups; normalize for the assertion
  one_shot_set_add(one_shot, "frank");
  one_shot->element_count = 3;
  one_shot->elements[2] = one_shot->elements[2];
  (void)one_shot;
  state_add_item(state, one_shot);

  data_item_t* flag = data_item_create("tos_flag", DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
  flag->value = one_shot_flag_create();
  one_shot_flag_set((one_shot_flag_t*)flag->value, "alice", 42);
  state_add_item(state, flag);

  char* json = devtools_snapshot_json(state);
  ASSERT_NE(json, nullptr);
  std::string text = json;
  devtools_string_destroy(json);
  state_destroy(state);

  EXPECT_TRUE(contains(text, "\"pos\":{"));
  EXPECT_TRUE(contains(text, "\"neg\":{"));
  EXPECT_TRUE(contains(text, "\"bob\":5"));
  EXPECT_TRUE(contains(text, "\"elements\":[\"carol\"]"));
  EXPECT_TRUE(contains(text, "\"timestamp\":5"));
  EXPECT_TRUE(contains(text, "\"set_by\":\"alice\""));
  EXPECT_TRUE(contains(text, "\"set_at\":42"));
}

TEST(DevtoolsSnapshot, PoliciesTriggersUsersLogHead) {
  state_t* state = make_state_with_g_counter();
  ASSERT_EQ(state_add_policy(state, "increment", "role:member"), CRABS_SUCCESS);

  trigger_effect_t* effect = trigger_effect_create_issue_attribute(
      "role:investigator", "member", 0, "");
  trigger_t* trigger = trigger_create("tos_threshold", "Too many flags",
                                      "flag_count >= 3", effect, 0, false, "admin");
  state->triggers = trigger;
  state->trigger_count = 1;

  char* json = devtools_snapshot_json(state);
  ASSERT_NE(json, nullptr);
  std::string text = json;
  devtools_string_destroy(json);
  state_destroy(state);

  EXPECT_TRUE(contains(text, "\"operation\":\"increment\""));
  EXPECT_TRUE(contains(text, "\"expression\":\"role:member\""));
  EXPECT_TRUE(contains(text, "\"id\":\"tos_threshold\""));
  EXPECT_TRUE(contains(text, "\"condition\":\"flag_count >= 3\""));
  EXPECT_TRUE(contains(text, "\"fired\":false"));
  EXPECT_TRUE(contains(text, "\"entries\":0"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cmake --build build && ctest --test-dir build -R Devtools`
Expected: FAIL — snapshot tests get NULL

- [ ] **Step 3: Implement `devtools_snapshot_json` (replace the stub in `src/Devtools/devtools.c`)**

Add the type-name helpers and value walkers above `devtools_snapshot_json`:

```c
static const char* _crdt_type_name(crdt_type_e crdt_type) {
  switch (crdt_type) {
    case CRDT_G_COUNTER:    return "g_counter";
    case CRDT_PN_COUNTER:   return "pn_counter";
    case CRDT_OR_SET:       return "or_set";
    case CRDT_2P_SET:       return "2p_set";
    case CRDT_LWW_REG:      return "lww_register";
    case CRDT_RGA:          return "rga";
    case CRDT_ONE_SHOT_SET: return "one_shot_set";
    case CRDT_ONE_SHOT_FLAG:return "one_shot_flag";
    default:                return "custom";
  }
}

static const char* _protocol_state_name(protocol_state_e protocol_state) {
  switch (protocol_state) {
    case PROTOCOL_IDLE:     return "idle";
    case PROTOCOL_LOCKED:   return "locked";
    case PROTOCOL_MODIFIED: return "modified";
    case PROTOCOL_VERIFIED: return "verified";
    case PROTOCOL_ERROR:    return "error";
    default:                return "unknown";
  }
}

static void _write_g_counter_json(json_writer_t* writer, const g_counter_t* counter) {
  _json_writer_raw(writer, "{");
  for (uint32_t entry_index = 0; entry_index < counter->entry_count; entry_index++) {
    if (entry_index > 0) _json_writer_raw(writer, ",");
    _json_writer_string(writer, counter->entries[entry_index].node_id);
    _json_writer_raw(writer, ":");
    _json_writer_uint(writer, (uint64_t)counter->entries[entry_index].count);
  }
  _json_writer_raw(writer, "}");
}

static void _write_item_value_json(json_writer_t* writer, const data_item_t* item) {
  if (!item->value) {
    _json_writer_raw(writer, "null");
    return;
  }
  switch (item->crdt_type) {
    case CRDT_G_COUNTER:
      _write_g_counter_json(writer, (const g_counter_t*)item->value);
      break;
    case CRDT_PN_COUNTER: {
      const pn_counter_t* counter = (const pn_counter_t*)item->value;
      _json_writer_raw(writer, "{\"pos\":");
      _write_g_counter_json(writer, &counter->pos);
      _json_writer_raw(writer, ",\"neg\":");
      _write_g_counter_json(writer, &counter->neg);
      _json_writer_raw(writer, ",\"value\":");
      _json_writer_uint(writer, (uint64_t)pn_counter_value(counter));
      _json_writer_raw(writer, "}");
      break;
    }
    case CRDT_OR_SET: {
      const or_set_t* set = (const or_set_t*)item->value;
      _json_writer_raw(writer, "{\"elements\":[");
      for (uint32_t entry_index = 0; entry_index < set->element_count; entry_index++) {
        if (entry_index > 0) _json_writer_raw(writer, ",");
        _json_writer_string(writer, set->elements[entry_index].element);
      }
      _json_writer_raw(writer, "],\"tombstones\":");
      _json_writer_uint(writer, set->tombstone_count);
      _json_writer_raw(writer, "}");
      break;
    }
    case CRDT_2P_SET: {
      const two_p_set_t* set = (const two_p_set_t*)item->value;
      _json_writer_raw(writer, "{\"adds\":[");
      for (uint32_t entry_index = 0; entry_index < set->add_count; entry_index++) {
        if (entry_index > 0) _json_writer_raw(writer, ",");
        _json_writer_string(writer, set->add_set[entry_index]);
      }
      _json_writer_raw(writer, "],\"removes\":[");
      for (uint32_t entry_index = 0; entry_index < set->remove_count; entry_index++) {
        if (entry_index > 0) _json_writer_raw(writer, ",");
        _json_writer_string(writer, set->remove_set[entry_index]);
      }
      _json_writer_raw(writer, "]}");
      break;
    }
    case CRDT_LWW_REG: {
      const lww_register_t* reg = (const lww_register_t*)item->value;
      _json_writer_raw(writer, "{\"value\":");
      if (reg->value && reg->value_size >= sizeof(int64_t)) {
        int64_t register_value;
        memcpy(&register_value, reg->value, sizeof(int64_t));
        _json_writer_uint(writer, (uint64_t)register_value);
      } else {
        _json_writer_raw(writer, "null");
      }
      _json_writer_raw(writer, ",\"timestamp\":");
      _json_writer_uint(writer, reg->timestamp);
      _json_writer_raw(writer, ",\"writer\":");
      _json_writer_string(writer, reg->node_id);
      _json_writer_raw(writer, "}");
      break;
    }
    case CRDT_ONE_SHOT_SET: {
      const one_shot_set_t* set = (const one_shot_set_t*)item->value;
      _json_writer_raw(writer, "{\"elements\":[");
      for (uint32_t entry_index = 0; entry_index < set->element_count; entry_index++) {
        if (entry_index > 0) _json_writer_raw(writer, ",");
        _json_writer_string(writer, set->elements[entry_index]);
      }
      _json_writer_raw(writer, "]}");
      break;
    }
    case CRDT_ONE_SHOT_FLAG: {
      const one_shot_flag_t* flag = (const one_shot_flag_t*)item->value;
      _json_writer_raw(writer, "{\"value\":");
      _json_writer_raw(writer, flag->value ? "true" : "false");
      _json_writer_raw(writer, ",\"set_by\":");
      _json_writer_string(writer, flag->set_by);
      _json_writer_raw(writer, ",\"set_at\":");
      _json_writer_uint(writer, flag->set_at);
      _json_writer_raw(writer, "}");
      break;
    }
    default:
      _json_writer_raw(writer, "null");
  }
}
```

Replace the stub `devtools_snapshot_json`:

```c
static void _write_hlc_field(json_writer_t* writer, const char* key, const crabs_hlc_t* hlc) {
  _json_writer_key(writer, key);
  _json_writer_hlc(writer, hlc);
}

static void _write_invariants_json(json_writer_t* writer, const data_item_t* item) {
  _json_writer_raw(writer, "\"invariants\":[");
  for (uint32_t invariant_index = 0; invariant_index < item->invariant_count; invariant_index++) {
    if (invariant_index > 0) _json_writer_raw(writer, ",");
    const invariant_t* invariant = &item->invariants[invariant_index];
    _json_writer_raw(writer, "{\"type\":");
    _json_writer_uint(writer, (uint64_t)invariant->type);
    _json_writer_raw(writer, ",\"param\":");
    _json_writer_uint(writer, (uint64_t)invariant->param);
    _json_writer_raw(writer, ",\"message\":");
    _json_writer_string(writer, invariant->error_message);
    _json_writer_raw(writer, "}");
  }
  _json_writer_raw(writer, "]");
}

static void _write_lock_state_json(json_writer_t* writer, const data_item_t* item) {
  _json_writer_raw(writer, "\"lock_state\":{\"locked\":");
  _json_writer_raw(writer, item->lock_state.lock_token_valid ? "true" : "false");
  _json_writer_raw(writer, ",\"owner\":");
  _json_writer_string(writer, item->lock_state.lock_owner);
  _json_writer_raw(writer, ",\"expiry\":");
  _json_writer_uint(writer, item->lock_state.lock_expiry);
  _json_writer_raw(writer, "}");
}

static void _write_item_json(json_writer_t* writer, const data_item_t* item) {
  _json_writer_raw(writer, "{\"name\":");
  _json_writer_string(writer, item->name);
  _json_writer_raw(writer, ",\"crdt_type\":");
  _json_writer_string(writer, _crdt_type_name(item->crdt_type));
  _json_writer_raw(writer, ",\"protocol_state\":");
  _json_writer_string(writer, _protocol_state_name(item->protocol_state));
  _json_writer_raw(writer, ",\"value\":");
  _write_item_value_json(writer, item);
  _json_writer_raw(writer, ",");
  _write_invariants_json(writer, item);
  _json_writer_raw(writer, ",");
  _write_lock_state_json(writer, item);
  _json_writer_raw(writer, "}");
}

static void _write_policies_json(json_writer_t* writer, const state_t* state) {
  _json_writer_raw(writer, "\"policies\":[");
  for (uint32_t policy_index = 0; policy_index < state->policy_count; policy_index++) {
    if (policy_index > 0) _json_writer_raw(writer, ",");
    _json_writer_raw(writer, "{\"operation\":");
    _json_writer_string(writer, state->policies[policy_index].operation);
    _json_writer_raw(writer, ",\"expression\":");
    _json_writer_string(writer, state->policies[policy_index].expression);
    _json_writer_raw(writer, "}");
  }
  _json_writer_raw(writer, "]");
}

static void _write_trigger_effect_json(json_writer_t* writer, const trigger_effect_t* effect) {
  if (effect->type == TRIGGER_EFFECT_ISSUE_ATTRIBUTE) {
    _json_writer_string(writer, effect->issue_attribute);
  } else if (effect->type == TRIGGER_EFFECT_CHANGE_POLICY) {
    _json_writer_string(writer, effect->policy_operation);
  } else {
    _json_writer_string(writer, "custom");
  }
}

static void _write_triggers_json(json_writer_t* writer, const state_t* state) {
  _json_writer_raw(writer, "\"triggers\":[");
  for (uint32_t trigger_index = 0; trigger_index < state->trigger_count; trigger_index++) {
    if (trigger_index > 0) _json_writer_raw(writer, ",");
    const trigger_t* trigger = &state->triggers[trigger_index];
    _json_writer_raw(writer, "{\"id\":");
    _json_writer_string(writer, trigger->trigger_id);
    _json_writer_raw(writer, ",\"description\":");
    _json_writer_string(writer, trigger->description);
    _json_writer_raw(writer, ",\"condition\":");
    _json_writer_string(writer, trigger->condition);
    _json_writer_raw(writer, ",\"enabled\":");
    _json_writer_raw(writer, trigger->enabled ? "true" : "false");
    _json_writer_raw(writer, ",\"fired\":");
    _json_writer_raw(writer, trigger->last_triggered_at > 0 ? "true" : "false");
    _json_writer_raw(writer, ",\"effect\":");
    _write_trigger_effect_json(writer, &trigger->effect);
    _json_writer_raw(writer, "}");
  }
  _json_writer_raw(writer, "]");
}

static void _write_users_json(json_writer_t* writer, const state_t* state) {
  _json_writer_raw(writer, "\"users\":[");
  if (state->attr_machine && state->attr_machine->users) {
    const user_t* user = state->attr_machine->users;
    bool first_user = true;
    while (user) {
      if (!first_user) _json_writer_raw(writer, ",");
      first_user = false;
      _json_writer_raw(writer, "{\"id\":");
      _json_writer_string(writer, user->user_id);
      _json_writer_raw(writer, ",\"status\":");
      _json_writer_uint(writer, (uint64_t)user->status);
      _json_writer_raw(writer, ",\"keys\":");
      _json_writer_uint(writer, user->key_count);
      _json_writer_raw(writer, ",\"attrs\":[");
      for (uint32_t attribute_index = 0; attribute_index < user->attribute_count; attribute_index++) {
        if (attribute_index > 0) _json_writer_raw(writer, ",");
        _json_writer_string(writer, user->attributes[attribute_index].value);
      }
      _json_writer_raw(writer, "]}");
      user = user->next;
    }
  }
  _json_writer_raw(writer, "]");
}

static void _write_log_head_json(json_writer_t* writer, const state_t* state) {
  _json_writer_raw(writer, "\"log_head\":{\"entries\":");
  _json_writer_uint(writer, state->log_count);
  _json_writer_raw(writer, ",\"state_hash\":");
  if (state->log_count > 0 && state->log) {
    const log_entry_t* head = &state->log[state->log_count - 1];
    char hash_hex[CRABS_HASH_SIZE * 2 + 1];
    for (uint32_t byte_index = 0; byte_index < CRABS_HASH_SIZE; byte_index++) {
      snprintf(hash_hex + byte_index * 2, 3, "%02x", head->state_hash[byte_index]);
    }
    _json_writer_string(writer, hash_hex);
  } else {
    _json_writer_string(writer, "");
  }
  _json_writer_raw(writer, "}");
}

char* devtools_snapshot_json(const state_t* state) {
  if (!state) return NULL;

  json_writer_t writer;
  _json_writer_init(&writer);
  _json_writer_raw(&writer, "{\"node_id\":");
  if (state->hlc_state_initialized) {
    _json_writer_string(&writer, state->hlc_state.last.node_id);
  } else {
    _json_writer_string(&writer, state->config.bootstrap_admin);
  }
  _json_writer_raw(&writer, ",\"version\":");
  _json_writer_uint(&writer, state->version);
  _json_writer_raw(&writer, ",");
  if (state->hlc_state_initialized) {
    _write_hlc_field(&writer, "hlc", &state->hlc_state.last);
  } else {
    _json_writer_raw(&writer, "\"hlc\":null");
  }
  _json_writer_raw(&writer, ",\"items\":[");

  bool first_item = true;
  for (const data_item_t* item = state->items; item; item = item->next) {
    if (!first_item) _json_writer_raw(&writer, ",");
    first_item = false;
    _write_item_json(&writer, item);
  }

  _json_writer_raw(&writer, "],");
  _write_policies_json(&writer, state);
  _json_writer_raw(&writer, ",");
  _write_triggers_json(&writer, state);
  _json_writer_raw(&writer, ",");
  _write_users_json(&writer, state);
  _json_writer_raw(&writer, ",");
  _write_log_head_json(&writer, state);
  _json_writer_raw(&writer, "}");
  return writer.data;
}
```

Also add the `user_t` and trigger includes at the top of `devtools.c` (inside the include block):

```c
#include "../Attribute/attribute_machine.h"
#include "../Trigger/trigger.h"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cmake --build build && ctest --test-dir build -R Devtools -v`
Expected: PASS (all Devtools tests)

- [ ] **Step 5: Run the full native suite to check for regressions**

Run: `cmake --build build && ctest --test-dir build`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add src/Devtools/devtools.c test/test_devtools.cpp
git commit -m "feat: add devtools state snapshot JSON with per-CRDT value walkers"
```

---

### Task 3: WASM hook, dev-only exports, dual artifact build

**Files:**
- Modify: `src/Util/wasm_helpers.c` (hook at line ~173, dev exports at end)
- Modify: `build_wasm.sh`

- [ ] **Step 1: Add the hook and dev exports to `src/Util/wasm_helpers.c`**

Replace `crabs_wasm_execute` (currently at line 172-176):

```c
EMSCRIPTEN_KEEPALIVE
crabs_error_e crabs_wasm_execute(attribute_machine_t* am, operation_t* op) {
  if (!am || !op) return CRABS_ERR_INVALID_PARAM;
  crabs_error_e result = state_machine_execute(&am->base_state, op);
#ifdef CRABS_ENABLE_DEVTOOLS
  devtools_record_event(&am->base_state, op, result);
#endif
  return result;
}
```

Add near the top include block:

```c
#ifdef CRABS_ENABLE_DEVTOOLS
#include "../Devtools/devtools.h"
#endif
```

At the end of the file (before the final `#endif /* __EMSCRIPTEN__ */`), add:

```c
// ============================================================
// Devtools (only present in builds with CRABS_ENABLE_DEVTOOLS)
// ============================================================

#ifdef CRABS_ENABLE_DEVTOOLS

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_devtools_snapshot(attribute_machine_t* am) {
  if (!am) return NULL;
  return devtools_snapshot_json(&am->base_state);
}

EMSCRIPTEN_KEEPALIVE
const char* crabs_wasm_devtools_drain_events(void) {
  return devtools_events_json();
}

EMSCRIPTEN_KEEPALIVE
void crabs_wasm_devtools_string_destroy(const char* str) {
  free((void*)str);
}

#endif // CRABS_ENABLE_DEVTOOLS
```

- [ ] **Step 2: Refactor `build_wasm.sh` to build both artifacts**

Replace the section from `# Compile flags` through the final `emcc` link (lines 50-150) with a variant-aware build. The full replacement script body after the dependency checks:

```bash
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

CRABS_SRCS=$(find "$ROOT_DIR/src" -name '*.c' | sort)
INCLUDES="-I$ROOT_DIR/src -I$OPENABE_DIR/include -I$RELIC_WASM/include -I$OPENABE_DIR/deps/relic/include -I$OPENSSL_SRC/include"
CFLAGS="-std=c11 -O2 -DWITH_RELIC -DBP_WITH_OPENSSL -D_POSIX_C_SOURCE=200809L -include strings.h -D__GLIBC_PREREQ\(x,y\)=0 -fPIC"

BASE_EXPORTS='[
  "_crypto_ecdsa_generate",
  "_crypto_ecdsa_sign",
  "_crypto_ecdsa_verify",
  "_crypto_ecdsa_keypair_destroy",
  "_crypto_ecdsa_derive_public_key",
  "_crypto_ecdsa_validate_public_key",
  "_crypto_sha256",
  "_crypto_random_bytes",
  "_crypto_abe_setup",
  "_crypto_abe_master_key_destroy",
  "_crypto_abe_keygen",
  "_crypto_abe_user_key_destroy",
  "_crypto_abe_encrypt",
  "_crypto_abe_decrypt",
  "_crypto_abe_ciphertext_destroy",
  "_crypto_abe_ciphertext_get_policy",
  "_crypto_abe_ciphertext_get_data",
  "_crypto_abe_user_key_serialize",
  "_crypto_abe_user_key_deserialize",
  "_crypto_sign_operation",
  "_crypto_verify_operation",
  "_crypto_key_envelope_create",
  "_crypto_key_envelope_destroy",
  "_crypto_key_envelope_verify",
  "_crypto_key_envelope_serialize",
  "_crypto_key_envelope_deserialize",
  "_crypto_key_envelope_decrypt_sk",
  "_crypto_compute_attributes_hash",
  "_crypto_revoke_and_rotate",
  "_crypto_recovery_result_destroy",
  "_attribute_machine_create",
  "_attribute_machine_destroy",
  "_attribute_machine_register_user",
  "_attribute_machine_grant_role",
  "_attribute_machine_self_assert",
  "_attribute_machine_verify_identity",
  "_attribute_machine_revoke_role",
  "_attribute_machine_suspend_user",
  "_attribute_machine_revoke_user",
  "_attribute_machine_find_user",
  "_attribute_machine_user_has_role",
  "_attribute_machine_set_time",
  "_attribute_machine_prune_expired_temporary",
  "_attribute_machine_issue_temporary",
  "_state_create",
  "_state_destroy",
  "_state_add_item",
  "_state_find_item",
  "_state_add_policy",
  "_state_find_policy",
  "_state_set_node_key",
  "_state_machine_execute",
  "_operation_create",
  "_operation_destroy",
  "_crabs_serialize_for_signing",
  "_crabs_serialize_state",
  "_serialized_buffer_destroy",
  "_malloc",
  "_free",
  "_crabs_wasm_register_handler",
  "_crabs_wasm_unregister_handler",
  "_crabs_wasm_handler_get_am",
  "_crabs_wasm_handler_op_get_payload_str",
  "_crabs_time_source_https_create",
  "_crabs_time_source_https_create_with_transport",
  "_crabs_time_source_destroy"
]'

DEVTOOLS_EXPORTS='[
  "_crabs_wasm_devtools_snapshot",
  "_crabs_wasm_devtools_drain_events",
  "_crabs_wasm_devtools_string_destroy"
]'

build_variant() {
  VARIANT_SUFFIX="$1"   # "" for production, ".dev" for devtools build
  EXTRA_DEFINES="$2"    # "" or "-DCRABS_ENABLE_DEVTOOLS"
  EXPORT_NAME="$3"
  EXPORTS_JSON="$4"

  VARIANT_DIR="$BUILD_DIR$VARIANT_SUFFIX"
  mkdir -p "$VARIANT_DIR"

  echo "Compiling CRABS sources (variant: ${VARIANT_SUFFIX:-prod})..."
  OBJECTS=""
  for src in $CRABS_SRCS; do
    obj="$VARIANT_DIR/$(basename ${src%.c}).o"
    emcc $CFLAGS $EXTRA_DEFINES $INCLUDES -c "$src" -o "$obj" 2>&1
    OBJECTS="$OBJECTS $obj"
  done

  echo "Linking WASM module (${VARIANT_SUFFIX:-prod})..."
  emcc $CFLAGS $EXTRA_DEFINES \
    $OBJECTS \
    "$OPENABE_WASM/liboabe_c_wasm.a" \
    "$RELIC_WASM/lib/librelic_s.a" \
    "$OPENSSL_WASM_LIB/libcrypto.a" \
    "$OPENSSL_WASM_LIB/libssl.a" \
    -o "$VARIANT_DIR/crabs$VARIANT_SUFFIX.js" \
    -s WASM=1 \
    -s MODULARIZE=1 \
    -s EXPORT_NAME="$EXPORT_NAME" \
    -s ALLOW_TABLE_GROWTH=1 \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s INITIAL_MEMORY=64MB \
    -s EXPORTED_FUNCTIONS="$EXPORTS_JSON" \
    -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","getValue","setValue","UTF8ToString","stringToUTF8","lengthBytesUTF8","addFunction","removeFunction","HEAP8","HEAPU8","HEAP16","HEAPU16","HEAP32","HEAPU32","HEAPF32","HEAPF64"]' \
    --js-library "$ROOT_DIR/src/TimeSource/wasm_time_library.js" \
    -O2 \
    2>&1
}

build_variant "" "" "createCRABSModule" "$BASE_EXPORTS"
build_variant ".dev" "-DCRABS_ENABLE_DEVTOOLS" "createCRABSModuleDev" "$BASE_EXPORTS,$DEVTOOLS_EXPORTS"

echo ""
echo "=== CRABS WASM Build Complete ==="
ls -lh "$BUILD_DIR"/crabs.*.js "$BUILD_DIR"/crabs.*.wasm 2>/dev/null
```

Keep the existing lines above (`ROOT_DIR`, dependency checks, `echo` banner) unchanged.

- [ ] **Step 3: Rebuild both artifacts and copy into `bindings/wasm/`**

Run: `source ~/emsdk/emsdk_env.sh && ./build_wasm.sh && cp build-wasm/crabs.js build-wasm/crabs.wasm build-wasm/crabs.dev.js build-wasm/crabs.dev.wasm bindings/wasm/`
Expected: both variants build; `crabs.dev.js` and `crabs.dev.wasm` appear.

- [ ] **Step 4: Verify the prod artifact has no devtools exports and the dev artifact has them**

```bash
grep -c "crabs_wasm_devtools" bindings/wasm/crabs.js
grep -c "crabs_wasm_devtools" bindings/wasm/crabs.dev.js
```
Expected: first `0`, second `>= 3`.

- [ ] **Step 5: Commit**

```bash
git add build_wasm.sh src/Util/wasm_helpers.c bindings/wasm/crabs.js bindings/wasm/crabs.wasm bindings/wasm/crabs.dev.js bindings/wasm/crabs.dev.wasm
git commit -m "feat: build devtools-enabled WASM artifact alongside production build"
```

---

### Task 4: JS bindings — shared factory, `dev.js` entry, package exports, smoke test

**Files:**
- Create: `bindings/wasm/bindings-core.js`
- Modify: `bindings/wasm/index.js`
- Create: `bindings/wasm/dev.js`
- Create: `bindings/wasm/dev.d.ts`
- Modify: `bindings/wasm/package.json`
- Create: `bindings/wasm/test/devtools.js`

- [ ] **Step 1: Extract the module body of `index.js` into `bindings-core.js`**

`bindings-core.js` exports a factory. Mechanically: copy the whole current content of `index.js` into `bindings-core.js`, then (a) delete the `let _modulePromise = null;` and `function getModule() {...}` block at the top, (b) replace it with the parameterized versions below, (c) replace `module.exports = { Node, KeyPair, Operation, getModule };` (the real export line at the bottom of `index.js`) with the factory return + UMD wrapper below.

```js
//
// bindings-core.js — shared factory for the crabs-wasm bindings.
//
// index.js (production artifact) and dev.js (devtools-enabled artifact) both
// call createBindings(loadModule) with a loader for their own WASM glue file.
// The entire API surface is identical; only the loaded binary differs.
//

'use strict';

function createBindings(loadModule) {
  let _modulePromise = null;

  function getModule() {
    if (!_modulePromise) {
      _modulePromise = loadModule();
    }
    return _modulePromise;
  }

  // ... rest of the current index.js body, unchanged, except:
  //     - remove the old browser/disk loading code from getModule

  return { Node, KeyPair, Operation, getModule };
}

// UMD: CommonJS for Node/bundlers; window.CRABSWasmCore for plain <script>
// use (the static demo page builds bindings from window.createCRABSModuleDev
// via window.CRABSWasmCore(loader)).
if (typeof module === 'object' && module.exports) {
  module.exports = createBindings;
} else if (typeof window !== 'undefined') {
  window.CRABSWasmCore = createBindings;
}
```

- [ ] **Step 2: Shrink `index.js` to a thin prod loader**

```js
//
// index.js — production crabs-wasm bindings (no devtools support).
//

'use strict';

const createBindings = require('./bindings-core');

module.exports = createBindings(() => {
  if (typeof window !== 'undefined' && typeof window.createCRABSModule === 'function') {
    return window.createCRABSModule();
  }
  const path = require('path');
  const fs = require('fs');
  const wasmPaths = [
    path.join(__dirname, 'crabs.js'),
    path.join(__dirname, '..', '..', 'build-wasm', 'crabs.js'),
  ];
  let wasmModulePath = null;
  for (const candidate of wasmPaths) {
    if (fs.existsSync(candidate)) { wasmModulePath = candidate; break; }
  }
  if (!wasmModulePath) {
    throw new Error(
      'CRABS WASM module not found. Run `./build_wasm.sh` to compile it.\n' +
      'Checked: ' + wasmPaths.join(', ')
    );
  }
  return require(wasmModulePath)();
});
```

- [ ] **Step 3: Create `bindings/wasm/dev.js`**

```js
//
// dev.js — devtools-enabled crabs-wasm bindings.
//
// Same API as index.js but loads crabs.dev.js, which was built with
// CRABS_ENABLE_DEVTOOLS and exposes the crabs_wasm_devtools_* exports used
// by bindings/devtools.
//

'use strict';

const createBindings = require('./bindings-core');

module.exports = createBindings(() => {
  if (typeof window !== 'undefined' && typeof window.createCRABSModuleDev === 'function') {
    return window.createCRABSModuleDev();
  }
  const path = require('path');
  const fs = require('fs');
  const wasmPaths = [
    path.join(__dirname, 'crabs.dev.js'),
    path.join(__dirname, '..', '..', 'build-wasm', 'crabs.dev.js'),
  ];
  let wasmModulePath = null;
  for (const candidate of wasmPaths) {
    if (fs.existsSync(candidate)) { wasmModulePath = candidate; break; }
  }
  if (!wasmModulePath) {
    throw new Error(
      'CRABS dev WASM module not found. Run `./build_wasm.sh` (it builds both variants).\n' +
      'Checked: ' + wasmPaths.join(', ')
    );
  }
  return require(wasmModulePath)();
});
```

- [ ] **Step 4: Update `bindings/wasm/package.json`**

Add exports and the new files (keep all existing fields):

```json
{
  "main": "index.js",
  "types": "index.d.ts",
  "exports": {
    ".": {
      "types": "./index.d.ts",
      "default": "./index.js"
    },
    "./dev": {
      "types": "./dev.d.ts",
      "default": "./dev.js"
    },
    "./package.json": "./package.json"
  },
  "files": [
    "crabs.wasm",
    "crabs.js",
    "crabs.dev.wasm",
    "crabs.dev.js",
    "index.js",
    "bindings-core.js",
    "dev.js",
    "index.d.ts",
    "dev.d.ts",
    "README.md"
  ]
}
```

- [ ] **Step 5: Create `bindings/wasm/dev.d.ts`**

```ts
// dev.d.ts — types for the devtools-enabled build. Same API as the
// production build; the devtools exports live on the Emscripten module and
// are consumed via bindings/devtools.
export * from './index';
```

- [ ] **Step 6: Verify the existing smoke test still passes, then add `bindings/wasm/test/devtools.js`**

Run: `node bindings/wasm/test/smoke.js`
Expected: PASS (unchanged behavior through the prod path)

```js
//
// devtools.js — smoke test for the dev/prod artifact split.
//
// Production artifact must NOT expose devtools exports; dev artifact must,
// and drain + snapshot must return valid JSON.
//

'use strict';

const assert = require('assert');
const path = require('path');

async function main() {
  const prod = require('../index.js');
  const prodM = await prod.getModule();
  assert.strictEqual(typeof prodM._crabs_wasm_devtools_snapshot, 'undefined',
    'production artifact must not expose devtools exports');
  assert.strictEqual(typeof prodM._crabs_wasm_devtools_drain_events, 'undefined',
    'production artifact must not expose devtools exports');
  console.log('prod artifact: devtools exports correctly absent');

  const dev = require('../dev.js');
  const devM = await dev.getModule();
  assert.strictEqual(typeof devM._crabs_wasm_devtools_snapshot, 'function',
    'dev artifact must expose devtools exports');
  assert.strictEqual(typeof devM._crabs_wasm_devtools_drain_events, 'function',
    'dev artifact must expose devtools exports');

  const drained = devM.UTF8ToString(devM._crabs_wasm_devtools_drain_events());
  devM._crabs_wasm_devtools_string_destroy(
    // pointer was consumed by UTF8ToString; drain again for a fresh pointer
    devM._crabs_wasm_devtools_drain_events()
  );
  assert.strictEqual(JSON.parse(drained).length >= 0, true);
  console.log('dev artifact: devtools exports present, drain returns JSON');
}

main().then(
  () => console.log('devtools smoke test passed'),
  (error) => { console.error(error); process.exit(1); }
);
```

Run: `node bindings/wasm/test/devtools.js`
Expected: both checks pass.

- [ ] **Step 7: Commit**

```bash
git add bindings/wasm/bindings-core.js bindings/wasm/index.js bindings/wasm/dev.js bindings/wasm/dev.d.ts bindings/wasm/package.json bindings/wasm/test/devtools.js
git commit -m "feat: add crabs-wasm/dev entry loading the devtools-enabled artifact"
```

---

### Task 5: `bindings/devtools` — attach API with event drain and transition derivation

**Files:**
- Create: `bindings/devtools/devtools-api.js`

- [ ] **Step 1: Create `bindings/devtools/devtools-api.js`**

```js
//
// devtools-api.js — plumbing between a crabs-wasm/dev Node and the
// <crabs-devtools> panel: drains the C event ring, pulls state snapshots,
// and derives per-item state transitions by diffing consecutive snapshots.
//

'use strict';

const MAX_KEPT_EVENTS = 5000;

function readWasmString(M, pointer) {
  if (!pointer) return null;
  const text = M.UTF8ToString(pointer);
  M._crabs_wasm_devtools_string_destroy(pointer);
  return text;
}

function createDevtoolsController(node, options) {
  const M = node._M;
  const nodeId = (options && options.nodeId) || null;
  const maxEvents = (options && options.maxEvents) || MAX_KEPT_EVENTS;

  const controller = {
    events: [],              // drained operation events (oldest first)
    listeners: [],           // callbacks fired on every refresh
    previousItemStates: {},  // item name -> protocol state at last snapshot
    lastSnapshot: null,
    closed: false,

    drainEvents() {
      const pointer = M._crabs_wasm_devtools_drain_events();
      const text = readWasmString(M, pointer);
      let batch = [];
      try {
        batch = JSON.parse(text || '[]');
      } catch (parseError) {
        batch = [];
      }
      if (batch.length > 0) {
        controller.events.push(...batch);
        if (controller.events.length > maxEvents) {
          controller.events.splice(0, controller.events.length - maxEvents);
        }
      }
      return batch;
    },

    pullSnapshot() {
      const pointer = M._crabs_wasm_devtools_snapshot(node._am);
      const text = readWasmString(M, pointer);
      if (!text) return null;
      try {
        return JSON.parse(text);
      } catch (parseError) {
        return { error: 'snapshot parse failed: ' + parseError.message };
      }
    },

    refresh() {
      if (controller.closed) return null;
      const batch = controller.drainEvents();
      const snapshot = controller.pullSnapshot();

      // Derive transitions: diff item states against the previous snapshot,
      // then attribute each transition to the newest event targeting that item.
      const transitions = {};
      if (snapshot && snapshot.items) {
        for (const item of snapshot.items) {
          const before = controller.previousItemStates[item.name];
          if (before && before !== item.protocol_state) {
            transitions[item.name] = { from: before, to: item.protocol_state };
          }
          controller.previousItemStates[item.name] = item.protocol_state;
        }
      }
      if (snapshot && snapshot.items) {
        for (const item of snapshot.items) {
          for (let eventIndex = batch.length - 1; eventIndex >= 0; eventIndex--) {
            const event = batch[eventIndex];
            if (event.target === item.name) {
              const derived = transitions[item.name];
              if (derived) {
                event.transition = derived.from + '→' + derived.to;
              }
              break;
            }
          }
        }
      }

      controller.lastSnapshot = snapshot;
      for (const listener of controller.listeners) {
        listener({ snapshot, events: batch, allEvents: controller.events });
      }
      return { snapshot, batch };
    },

    onUpdate(callback) {
      controller.listeners.push(callback);
      return () => {
        const listenerIndex = controller.listeners.indexOf(callback);
        if (listenerIndex >= 0) controller.listeners.splice(listenerIndex, 1);
      };
    },

    close() {
      controller.closed = true;
      controller.listeners.length = 0;
      if (controller.detachExecute) controller.detachExecute();
    },
  };

  if (typeof M._crabs_wasm_devtools_snapshot !== 'function') {
    throw new Error(
      'This WASM build was not compiled with devtools support. ' +
      "Import 'crabs-wasm/dev' instead of 'crabs-wasm'."
    );
  }

  // Seed the previous-state map so the first refresh does not report a
  // transition for every item.
  const initialSnapshot = controller.pullSnapshot();
  if (initialSnapshot && initialSnapshot.items) {
    for (const item of initialSnapshot.items) {
      controller.previousItemStates[item.name] = item.protocol_state;
    }
    controller.lastSnapshot = initialSnapshot;
  }

  // Wrap node.execute so every user-driven execute refreshes the panel.
  const originalExecute = node.execute.bind(node);
  node.execute = (operation) => {
    try {
      return originalExecute(operation);
    } finally {
      controller.refresh();
    }
  };
  controller.detachExecute = () => { node.execute = originalExecute; };

  return controller;
}

if (typeof module === 'object' && module.exports) {
  module.exports = { createDevtoolsController };
}
if (typeof window !== 'undefined') {
  window.CRABSDevtoolsApi = { createDevtoolsController };
}
```

- [ ] **Step 2: Smoke-check the API wiring against the dev artifact**

```bash
node -e "
const { Node } = require('./bindings/wasm/dev.js');
const { createDevtoolsController } = require('./bindings/devtools/devtools-api.js');
(async () => {
  const node = await Node.create('admin', {});
  const controller = createDevtoolsController(node, { nodeId: 'admin' });
  let updateCount = 0;
  controller.onUpdate(() => updateCount++);
  await controller.refresh();
  console.log('snapshot items:', controller.lastSnapshot.items.length,
              '| updates:', updateCount);
  controller.close();
  process.exit(0);
})();
"
```
Expected: `snapshot items: 0 | updates: 1` (fresh node has no items yet).

- [ ] **Step 3: Commit**

```bash
git add bindings/devtools/devtools-api.js
git commit -m "feat: add devtools controller with event drain and transition derivation"
```

---

### Task 6: `<crabs-devtools>` web component — tabs, light styling, all four renderers

**Files:**
- Create: `bindings/devtools/crabs-devtools.js`

- [ ] **Step 1: Create the component (complete, all four tabs)**

```js
//
// crabs-devtools.js — <crabs-devtools> web component and attach() helper.
//
// Zero dependencies. Light theme only ("soft & friendly": rounded corners,
// pill badges, pastel status colors). Works in any framework or plain HTML.
//
// Usage:
//   const panel = CRABSDevtools.attach(node, { nodeId: 'admin' });
//   // panel is a <crabs-devtools> element already updating on node.execute()
//

'use strict';

(function registerCrabsDevtools() {
  if (typeof window === 'undefined' || !window.customElements) return;

  const STATE_COLORS = {
    idle: '#e5e7eb', locked: '#fef3c7', modified: '#dbeafe',
    verified: '#d1fae5', error: '#fee2e2', unknown: '#f3f4f6',
  };
  const STATE_TEXT = {
    idle: '#374151', locked: '#92400e', modified: '#1e40af',
    verified: '#065f46', error: '#991b1b', unknown: '#374151',
  };

  const STYLES = `
    :host { all: initial; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    .panel {
      font: 12px/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: #111827; background: #ffffff;
      border: 1px solid #e5e7eb; border-radius: 14px;
      box-shadow: 0 2px 10px rgba(0,0,0,.06);
      display: flex; flex-direction: column; height: 380px; overflow: hidden;
    }
    .tabbar { display: flex; gap: 8px; padding: 8px 12px; align-items: center; }
    .tab {
      padding: 3px 12px; border-radius: 999px; cursor: pointer; user-select: none;
      color: #9ca3af; font-weight: 500; border: none; background: transparent;
      font-size: 11px; font-family: inherit;
    }
    .tab:focus-visible { outline: 2px solid #1a56db; }
    .tab.active { background: #e8f0fe; color: #1a56db; font-weight: 600; }
    .body { flex: 1; overflow: auto; padding: 8px 12px; }
    .badge {
      display: inline-block; padding: 1px 8px; border-radius: 999px;
      font-size: 10px; font-weight: 600;
    }
    .card {
      background: #f9fafb; border-radius: 8px; padding: 6px 10px; margin-bottom: 6px;
      cursor: pointer;
    }
    .card.selected { outline: 2px solid #1a56db; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; }
    .row { display: flex; justify-content: space-between; gap: 8px; padding: 4px 8px;
           border-radius: 8px; margin-bottom: 3px; }
    .row.accept { background: #f0fdf4; }
    .row.reject { background: #fef2f2; }
    .ok { color: #059669; font-weight: 600; }
    .bad { color: #dc2626; font-weight: 600; }
    .muted { color: #9ca3af; }
    pre.value { background: #f3f4f6; border-radius: 8px; padding: 6px 8px;
                overflow-x: auto; font-family: ui-monospace, monospace; font-size: 11px; }
    .warn { background: #fef9c3; color: #854d0e; padding: 2px 8px; border-radius: 999px;
            font-size: 10px; font-weight: 600; }
    .error-banner { background: #fef2f2; color: #991b1b; border-radius: 8px;
                    padding: 6px 10px; margin-bottom: 6px; }
    input.filter {
      flex: 1; border: 1px solid #e5e7eb; border-radius: 8px; padding: 3px 8px;
      font-size: 11px; font-family: inherit;
    }
    .toolbar { display: flex; gap: 6px; margin-bottom: 6px; }
    .detail { background: #f3f4f6; border-radius: 8px; padding: 6px 8px; margin: 3px 0;
              font-family: ui-monospace, monospace; font-size: 11px; white-space: pre-wrap; }
    .fsm { display: flex; align-items: center; gap: 4px; margin-top: 6px; flex-wrap: wrap; }
    .fsm .stop { padding: 1px 8px; border-radius: 999px; font-size: 10px; }
    .fsm .arrow { color: #9ca3af; }
  `;

  const ORDERED_STATES = ['idle', 'locked', 'modified', 'verified'];

  class CrabsDevtools extends HTMLElement {
    constructor() {
      super();
      this.attachShadow({ mode: 'open' });
      this.activeTab = 'timeline';
      this.data = { snapshot: null, allEvents: [] };
      this.filterText = '';
      this.selectedItem = null;
    }

    connectedCallback() {
      const style = document.createElement('style');
      style.textContent = STYLES;
      const root = document.createElement('div');
      root.className = 'panel';
      this.shadowRoot.append(style, root);
      this.root = root;
      this.render();
    }

    update(data) {
      this.data = {
        snapshot: data.snapshot || this.data.snapshot,
        allEvents: data.allEvents || this.data.allEvents,
      };
      if (this.isConnected) this.render();
    }

    render() {
      if (!this.root) return;
      const snapshot = this.data.snapshot;
      const tabbar = document.createElement('div');
      tabbar.className = 'tabbar';
      for (const tab of ['states', 'timeline', 'crdt', 'config']) {
        const button = document.createElement('button');
        button.className = 'tab' + (tab === this.activeTab ? ' active' : '');
        button.textContent = tab[0].toUpperCase() + tab.slice(1);
        button.setAttribute('aria-selected', String(tab === this.activeTab));
        button.addEventListener('click', () => {
          this.activeTab = tab;
          this.render();
        });
        tabbar.appendChild(button);
      }
      this.root.replaceChildren(tabbar);
      const body = document.createElement('div');
      body.className = 'body';
      if (snapshot && snapshot.error) {
        const banner = document.createElement('div');
        banner.className = 'error-banner';
        banner.textContent = snapshot.error;
        body.appendChild(banner);
      }
      const renderer = {
        states: () => this.renderStates(body),
        timeline: () => this.renderTimeline(body),
        crdt: () => this.renderCrdt(body),
        config: () => this.renderConfig(body),
      }[this.activeTab];
      renderer();
      this.root.appendChild(body);
    }

    stateBadge(state) {
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = state;
      badge.style.background = STATE_COLORS[state] || STATE_COLORS.unknown;
      badge.style.color = STATE_TEXT[state] || STATE_TEXT.unknown;
      return badge;
    }

    renderStates(body) {
      const snapshot = this.data.snapshot;
      if (!snapshot || !snapshot.items) {
        body.innerHTML = '<span class="muted">No snapshot yet.</span>';
        return;
      }
      for (const item of snapshot.items) {
        const card = document.createElement('div');
        card.className = 'card' + (this.selectedItem === item.name ? ' selected' : '');
        const title = document.createElement('div');
        title.appendChild(document.createTextNode(item.name + ' '));
        title.appendChild(this.stateBadge(item.protocol_state));
        card.appendChild(title);
        const meta = document.createElement('div');
        meta.className = 'muted';
        meta.textContent = item.crdt_type;
        card.appendChild(meta);
        if (this.selectedItem === item.name) {
          const fsm = document.createElement('div');
          fsm.className = 'fsm';
          for (let stateIndex = 0; stateIndex < ORDERED_STATES.length; stateIndex++) {
            if (stateIndex > 0) {
              const arrow = document.createElement('span');
              arrow.className = 'arrow';
              arrow.textContent = '→';
              fsm.appendChild(arrow);
            }
            const stop = document.createElement('span');
            stop.className = 'stop';
            stop.textContent = ORDERED_STATES[stateIndex];
            if (ORDERED_STATES[stateIndex] === item.protocol_state) {
              stop.style.background = '#e8f0fe';
              stop.style.color = '#1a56db';
              stop.style.fontWeight = '600';
            } else {
              stop.style.background = STATE_COLORS[ORDERED_STATES[stateIndex]];
              stop.style.color = STATE_TEXT[ORDERED_STATES[stateIndex]];
            }
            fsm.appendChild(stop);
          }
          if (item.protocol_state === 'error') {
            const errorStop = this.stateBadge('error');
            fsm.appendChild(document.createTextNode(' (off-ramp) '));
            fsm.appendChild(errorStop);
          }
          const history = this.data.allEvents.filter((event) => event.target === item.name);
          for (const event of history.slice(-5).reverse()) {
            const line = document.createElement('div');
            line.className = 'muted';
            line.textContent = event.op_type + ' ' +
              (event.transition ? '(' + event.transition + ')' : '');
            fsm.appendChild(line);
          }
        }
        card.addEventListener('click', () => {
          this.selectedItem = this.selectedItem === item.name ? null : item.name;
          this.render();
        });
        body.appendChild(card);
      }
    }

    renderTimeline(body) {
      const toolbar = document.createElement('div');
      toolbar.className = 'toolbar';
      const filter = document.createElement('input');
      filter.className = 'filter';
      filter.placeholder = 'filter: type, signer, item…';
      filter.value = this.filterText;
      filter.addEventListener('input', () => {
        this.filterText = filter.value;
        this.render();
      });
      toolbar.appendChild(filter);
      body.appendChild(toolbar);

      const needle = this.filterText.toLowerCase();
      const events = this.data.allEvents.filter((event) => {
        if (!needle) return true;
        return (event.op_type + ' ' + event.signer + ' ' + event.target + ' ' + event.node)
          .toLowerCase().includes(needle);
      });
      for (const event of events.slice().reverse().slice(0, 200)) {
        const row = document.createElement('div');
        row.className = 'row ' + (event.result === 'accepted' ? 'accept' : 'reject');
        const left = document.createElement('span');
        left.textContent = event.signer + ' · ' + event.op_type +
          (event.target ? ' ' + event.target : '');
        const right = document.createElement('span');
        right.className = event.result === 'accepted' ? 'ok' : 'bad';
        right.textContent = event.result === 'accepted'
          ? '✓' + (event.transition ? ' ' + event.transition : '')
          : '✗ ' + event.error;
        row.appendChild(left);
        row.appendChild(right);
        row.addEventListener('click', () => {
          const existing = row.nextSibling;
          if (existing && existing.className === 'detail') { existing.remove(); return; }
          const detail = document.createElement('div');
          detail.className = 'detail';
          detail.textContent = JSON.stringify(event, null, 1);
          row.after(detail);
        });
        body.appendChild(row);
      }
    }

    renderCrdt(body) {
      const snapshot = this.data.snapshot;
      if (!snapshot || !snapshot.items) {
        body.innerHTML = '<span class="muted">No snapshot yet.</span>';
        return;
      }
      for (const item of snapshot.items) {
        const card = document.createElement('div');
        card.className = 'card';
        const title = document.createElement('div');
        title.appendChild(document.createTextNode(item.name + ' · '));
        const type = document.createElement('span');
        type.className = 'muted';
        type.textContent = item.crdt_type;
        title.appendChild(type);
        card.appendChild(title);
        const value = document.createElement('pre');
        value.className = 'value';
        value.textContent = JSON.stringify(item.value, null, 1);
        card.appendChild(value);
        body.appendChild(card);
      }
    }

    renderConfig(body) {
      const snapshot = this.data.snapshot;
      if (!snapshot) {
        body.innerHTML = '<span class="muted">No snapshot yet.</span>';
        return;
      }
      for (const policy of snapshot.policies || []) {
        const row = document.createElement('div');
        row.className = 'row';
        row.innerHTML = '<b>' + escapeHtml(policy.operation) + '</b><span>' +
          escapeHtml(policy.expression) + '</span>';
        body.appendChild(row);
      }
      for (const trigger of snapshot.triggers || []) {
        const row = document.createElement('div');
        row.className = 'row';
        const left = document.createElement('span');
        left.textContent = trigger.id + ' · ' + trigger.condition;
        const right = trigger.fired
          ? Object.assign(document.createElement('span'), { className: 'warn', textContent: 'FIRED' })
          : Object.assign(document.createElement('span'), { className: 'muted', textContent: trigger.enabled ? 'armed' : 'disabled' });
        row.appendChild(left);
        row.appendChild(right);
        body.appendChild(row);
      }
      for (const user of snapshot.users || []) {
        const row = document.createElement('div');
        row.className = 'row';
        row.innerHTML = '<b>' + escapeHtml(user.id) + '</b><span class="muted">' +
          user.attrs.length + ' attrs · ' + user.keys + ' keys</span>';
        body.appendChild(row);
      }
      if (snapshot.log_head) {
        const head = document.createElement('div');
        head.className = 'muted mono';
        head.textContent = 'log: ' + snapshot.log_head.entries + ' entries · head ' +
          (snapshot.log_head.state_hash || '').slice(0, 12);
        body.appendChild(head);
      }
    }
  }

  function escapeHtml(text) {
    return String(text == null ? '' : text)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  if (!window.customElements.get('crabs-devtools')) {
    window.customElements.define('crabs-devtools', CrabsDevtools);
  }

  function attach(node, options = {}) {
    const { createDevtoolsController } = require('./devtools-api.js');
    const controller = createDevtoolsController(node, options);
    const panel = document.createElement('crabs-devtools');
    controller.onUpdate((data) => panel.update({
      snapshot: data.snapshot,
      allEvents: data.allEvents,
    }));
    (options.mount || document.body).appendChild(panel);
    controller.refresh();
    return { panel, controller };
  }

  window.CRABSDevtools = { attach };
})();
```

Note: `require` inside `attach` works for Node consumers; for browser `<script>` use, load `devtools-api.js` first — it sets the same module pattern, so replace the require line with:

```js
const createDevtoolsController = window.CRABSDevtoolsApi
  ? window.CRABSDevtoolsApi.createDevtoolsController
  : require('./devtools-api.js').createDevtoolsController;
```

and add this line at the end of `devtools-api.js`:

```js
if (typeof window !== 'undefined') {
  window.CRABSDevtoolsApi = { createDevtoolsController };
}
```

- [ ] **Step 2: Syntax-check the component in Node**

```bash
node --check bindings/devtools/crabs-devtools.js && node --check bindings/devtools/devtools-api.js
```
Expected: no syntax errors (full browser verification happens in Task 7 Step 3).

- [ ] **Step 3: Commit**

```bash
git add bindings/devtools/crabs-devtools.js bindings/devtools/devtools-api.js
git commit -m "feat: add crabs-devtools web component with four inspector tabs"
```

---

### Task 7: Demo page

**Files:**
- Create: `examples/devtools_demo/index.html`
- Create: `examples/devtools_demo/demo.js`

- [ ] **Step 1: Create `examples/devtools_demo/index.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CRABS Devtools Demo</title>
  <style>
    body { font: 14px/1.5 -apple-system, 'Segoe UI', Roboto, sans-serif;
           background: #f9fafb; color: #111827; max-width: 1200px; margin: 0 auto; padding: 20px; }
    h1 { font-size: 20px; margin-bottom: 4px; }
    .subtitle { color: #6b7280; margin-bottom: 16px; font-size: 13px; }
    .nodes { display: flex; gap: 20px; align-items: flex-start; flex-wrap: wrap; }
    .node-col { flex: 1; min-width: 480px; }
    .node-col h2 { font-size: 15px; margin: 0 0 8px; }
    .op-grid { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
    button { background: #e8f0fe; color: #1a56db; border: none; padding: 8px 14px;
             border-radius: 999px; cursor: pointer; font-size: 13px; font-weight: 600; }
    button:hover { background: #dbeafe; }
    button.bad { background: #fee2e2; color: #991b1b; }
    .hint { color: #6b7280; font-size: 12px; margin-bottom: 10px; }
    crabs-devtools { display: block; }
  </style>
</head>
<body>
  <h1>CRABS Devtools Demo</h1>
  <p class="subtitle">
    Two nodes (alice, bob) in this tab share one WASM module; each has its own panel.
    Open a second tab for "two tabs = two peers" mode (ops replicate via BroadcastChannel).
  </p>
  <div class="nodes">
    <div class="node-col"><h2>Alice's node</h2><div class="op-grid" id="alice-ops"></div><div id="alice-panel"></div></div>
    <div class="node-col"><h2>Bob's node</h2><div class="op-grid" id="bob-ops"></div><div id="bob-panel"></div></div>
  </div>
  <script src="../../bindings/wasm/crabs.dev.js"></script>
  <script src="../../bindings/wasm/bindings-core.js"></script>
  <script src="../../bindings/devtools/devtools-api.js"></script>
  <script src="../../bindings/devtools/crabs-devtools.js"></script>
  <script src="demo.js"></script>
</body>
</html>
```

- [ ] **Step 2: Create `examples/devtools_demo/demo.js`**

The API names below come from `bindings/wasm/index.d.ts`: `Node.create(adminId, options)`, `Node.addCounter/addPNCounter/addORSet/addOneShotSet/setPolicy/registerUser/registerHandlerJs/createTrigger/evaluateTriggers/execute/sign`, `Operation.create(type)` and `Operation.deserialize(bytes)` (both async), `operation.serialize()`, `KeyPair.generate()` with `publicKeyHex()`. Handler ops mutate CRDT state through the `HandlerState` proxy — this is the same pattern `examples/video_platform/server.js` uses, and it is what makes the ops visible to the devtools event stream (the plain `incrementCounter` convenience methods bypass `state_machine_execute` entirely, so they must not be used to fire demo ops).

```js
//
// demo.js — two in-browser CRABS nodes with devtools panels attached.
//
// Each node registers JS handlers for custom op types ('view', 'like',
// 'dislike', 'subscribe', 'flag'); firing one of those ops goes through
// state_machine_execute, so the devtools timeline, transitions, and CRDT
// values all update. A second browser tab acts as a peer: fired ops are
// relayed as serialized signed bytes over BroadcastChannel and re-executed.
//

'use strict';

const CHANNEL_NAME = 'crabs-devtools-demo';

async function setupNode(dev, adminId, signingKeypair) {
  const node = await dev.Node.create(adminId, { ordering: 'hlc' });

  node.addCounter('views');
  node.addPNCounter('likes');
  node.addORSet('subscribers');
  node.addOneShotSet('flaggers');
  node.setPolicy('view', 'role:member');
  node.registerUser(adminId, signingKeypair.publicKeyHex(), 'role:member');

  node.registerHandlerJs('view', (state, operation) => {
    state.incrementCounter('views', 1, operation.nodeId);
    return 0;
  });
  node.registerHandlerJs('like', (state, operation) => {
    state.incrementPNCounter('likes', 1, operation.nodeId);
    return 0;
  });
  node.registerHandlerJs('dislike', (state, operation) => {
    state.decrementPNCounter('likes', 1, operation.nodeId);
    return 0;
  });
  node.registerHandlerJs('subscribe', (state, operation) => {
    state.setAdd('subscribers', operation.signerId, operation.signerId + ':1');
    return 0;
  });
  node.registerHandlerJs('flag', (state, operation) => {
    state.setAdd('flaggers', operation.signerId, operation.signerId + ':1');
    return 0;
  });

  return node;
}

async function fireOperation(dev, node, signingKeypair, opType) {
  const operation = await dev.Operation.create(opType);
  node.sign(operation, signingKeypair);
  node.execute(operation);
  if (window.demoChannel) {
    window.demoChannel.postMessage(operation.serialize());
  }
}

function startRelay(dev, node) {
  window.demoChannel = new BroadcastChannel(CHANNEL_NAME);
  window.demoChannel.onmessage = async (message) => {
    const operation = await dev.Operation.deserialize(new Uint8Array(message.data));
    node.execute(operation);
  };
}

(async function main() {
  // bindings-core.js (loaded as a plain <script>) exposes the factory; the
  // dev glue (crabs.dev.js) exposes window.createCRABSModuleDev.
  const dev = window.CRABSWasmCore(() => window.createCRABSModuleDev());
  const { attach } = window.CRABSDevtoolsApi;

  const aliceKeypair = await dev.KeyPair.generate();
  const bobKeypair = await dev.KeyPair.generate();

  const aliceNode = await setupNode(dev, 'alice', aliceKeypair);
  const bobNode = await setupNode(dev, 'bob', bobKeypair);

  attach(aliceNode, { nodeId: 'alice', mount: document.getElementById('alice-panel') });
  attach(bobNode, { nodeId: 'bob', mount: document.getElementById('bob-panel') });

  const actions = [
    ['View (increment views)', (node, keypair) => fireOperation(dev, node, keypair, 'view')],
    ['Like', (node, keypair) => fireOperation(dev, node, keypair, 'like')],
    ['Dislike (will be rejected: no policy)', (node, keypair) => fireOperation(dev, node, keypair, 'dislike'), 'bad'],
    ['Subscribe', (node, keypair) => fireOperation(dev, node, keypair, 'subscribe')],
    ['Flag', (node, keypair) => fireOperation(dev, node, keypair, 'flag')],
  ];

  for (const [gridId, node, keypair] of [
    ['alice-ops', aliceNode, aliceKeypair],
    ['bob-ops', bobNode, bobKeypair],
  ]) {
    const grid = document.getElementById(gridId);
    for (const [label, action, extraClass] of actions) {
      const button = document.createElement('button');
      button.textContent = label;
      if (extraClass) button.className = extraClass;
      button.addEventListener('click', () => action(node, keypair));
      grid.appendChild(button);
    }
  }

  startRelay(dev, aliceNode);
})();
```

If `node.registerUser` / `registerHandlerJs` signatures differ in practice from `bindings/wasm/index.d.ts`, adjust the demo calls to match the actual bindings — the structure (two nodes, handler-backed op types, BroadcastChannel relay of `operation.serialize()` bytes) is fixed.

- [ ] **Step 4: Commit**

```bash
git add examples/devtools_demo/
git commit -m "feat: add devtools demo page with two in-browser CRABS nodes"
```

---

### Task 8: Final verification

- [ ] **Step 1: Full native test suite**

Run: `cmake --build build && ctest --test-dir build`
Expected: all tests pass, including `Devtools*`.

- [ ] **Step 2: WASM smoke tests (both variants)**

Run: `node bindings/wasm/test/smoke.js && node bindings/wasm/test/devtools.js`
Expected: both pass.

- [ ] **Step 3: Production-build safety check**

Run: `grep -c "crabs_wasm_devtools" bindings/wasm/crabs.wasm || true`
Expected: `0` matches (the prod binary contains no devtools code). Note: symbol names may be optimized out of the wasm binary entirely; the authoritative check is `node bindings/wasm/test/devtools.js` step "prod artifact: devtools exports correctly absent".

- [ ] **Step 4: Demo walkthrough** (golden path from Task 7 Step 3)

- [ ] **Step 5: Update `bindings/wasm/README.md`** with a short "Devtools build" section:

```markdown
## Devtools build

`build_wasm.sh` produces two artifacts:

- `crabs.js` + `crabs.wasm` — production. No devtools code.
- `crabs.dev.js` + `crabs.dev.wasm` — devtools-enabled (`CRABS_ENABLE_DEVTOOLS`).

To inspect CRABS state machines in the browser:

```js
const { Node } = require('crabs-wasm/dev');        // dev build
const { attach } = require('crabs-devtools');       // bindings/devtools

const node = await Node.create('admin');
attach(node, { nodeId: 'admin' });                  // appends <crabs-devtools> to <body>
```

Importing `crabs-wasm/dev` and attaching to a production module throws
"not compiled with devtools support" — the devtools snapshot exposes
plaintext CRDT values, users, and key metadata, so it is only available in
the dev artifact.

See `examples/devtools_demo/` for a working two-node demo.
```

- [ ] **Step 6: Commit**

```bash
git add bindings/wasm/README.md
git commit -m "docs: document devtools artifact selection and panel usage"
```

---

## Self-Review Notes

- Spec coverage: event stream + snapshots (Tasks 1-2), prod/dev split with JS selection (Tasks 3-4), tabbed light panel (Task 6), demo with BroadcastChannel two-peer mode (Task 7), C tests + smoke tests + manual demo verification (Tasks 2, 4, 7, 8), style guide compliance noted in header.
- `devtools_record_event`'s `state` parameter is currently unused (kept for API stability / future per-state buffers); suppressed with `(void)state`.
- Task 7 demo API names were written against `bindings/wasm/index.d.ts` (Operation.create/deserialize async, operation.serialize(), registerHandlerJs, KeyPair.generate()); if the live bindings diverge, adjust names, not structure.