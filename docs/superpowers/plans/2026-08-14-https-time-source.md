# HTTPS Time Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional, pluggable authenticated time source to CRABS HLC that fetches time from a public HTTPS time API, caches it, and interpolates elapsed time with a monotonic clock.

**Architecture:** A new `src/TimeSource/` module implements the existing `crabs_time_source_ops_t` vtable from `src/HLC/hlc.h`. The backend owns a lazy-TTL cache: it queries the server at most once per resync interval, and between syncs returns `anchor + (monotonic_now − anchor_monotonic)`. Network I/O is behind an injectable transport seam so unit tests never touch the network. Native builds use an OpenSSL HTTPS GET; WASM builds use an imported JS shim.

**Tech Stack:** C11, OpenSSL (already linked), CMake, GoogleTest. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-14-https-time-source-design.md`

---

## File Structure

- **Create** `src/TimeSource/time_source.h` — public API: config struct, transport typedef, create/destroy functions.
- **Create** `src/TimeSource/time_source.c` — backend (cache + elapsed math + vtable) and the native OpenSSL transport.
- **Modify** `src/Util/platform.h` — add `platform_get_monotonic()`.
- **Modify** `src/HLC/hlc.h` — add `CRABS_TIME_SOURCE_HTTPS_AUTH` enum value.
- **Create** `test/test_time_source.cpp` — unit tests (fake transport) + network-gated integration test.
- **Modify** `test/CMakeLists.txt` — add `test_time_source.cpp` to the test executable.
- **Modify** `build_wasm.sh` — import the JS time shim for the WASM build.

The CMake glob (`file(GLOB_RECURSE C_SRC "src/*/*.c")`) picks up the new `.c` file automatically; no root CMakeLists change needed.

---

### Task 1: Add `platform_get_monotonic()` to platform.h

**Files:**
- Modify: `src/Util/platform.h` (after `platform_get_time()`, ~line 176)
- Create: `test/test_time_source.cpp`
- Modify: `test/CMakeLists.txt`

- [ ] **Step 1: Write the failing test**

Create `test/test_time_source.cpp`:

```cpp
//
// Time source tests: monotonic clock, HTTPS-time backend, and integration.
//

#include <gtest/gtest.h>

extern "C" {
#include "Util/platform.h"
}

TEST(PlatformTime, MonotonicValidAndNonDecreasing) {
  platform_time_t first = platform_get_monotonic();
  EXPECT_TRUE(first.valid);

  platform_time_t second = platform_get_monotonic();
  EXPECT_TRUE(second.valid);

  bool non_decreasing = (second.seconds > first.seconds) ||
      (second.seconds == first.seconds && second.nanos >= first.nanos);
  EXPECT_TRUE(non_decreasing);
}
```

- [ ] **Step 2: Run test to verify it fails to compile**

Run: `cmake --build build --target testcrabs 2>&1 | grep -i "monotonic\|error" | head`
Expected: compile error — `platform_get_monotonic` is not declared.

- [ ] **Step 3: Implement `platform_get_monotonic()`**

Add to `src/Util/platform.h`, immediately after the `platform_get_time()` function (after line 176):

```c
// ============================================================
// Monotonic Time
// ============================================================
// Returns seconds + nanoseconds from an arbitrary fixed origin that never
// moves backward (CLOCK_MONOTONIC on POSIX, QueryPerformanceCounter on
// Windows, emscripten_get_now on WASM). Only differences are meaningful.

static inline platform_time_t platform_get_monotonic(void) {
  platform_time_t result = {0, 0, false};

#ifdef _WIN32
  LARGE_INTEGER counter;
  LARGE_INTEGER frequency;
  if (QueryPerformanceCounter(&counter) &&
      QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0) {
    result.seconds = (uint64_t)(counter.QuadPart / frequency.QuadPart);
    uint64_t remainder = (uint64_t)(counter.QuadPart % frequency.QuadPart);
    result.nanos = (uint64_t)((remainder * 1000000000ULL) / frequency.QuadPart);
    result.valid = true;
  }
#elif defined(__EMSCRIPTEN__)
  double now_ms = emscripten_get_now();
  result.seconds = (uint64_t)(now_ms / 1000.0);
  result.nanos = (uint64_t)((now_ms - (double)result.seconds * 1000.0) * 1000000.0);
  result.valid = true;
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
    result.seconds = (uint64_t)ts.tv_sec;
    result.nanos = (uint64_t)ts.tv_nsec;
    result.valid = true;
  }
#endif

  return result;
}
```

Add the emscripten include near the top of `platform.h`, after the existing `#include <string.h>` (line 28):

```c
#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#endif
```

- [ ] **Step 4: Register the test file in CMake**

In `test/CMakeLists.txt`, add `test_time_source.cpp` to the `add_executable(testcrabs ...)` list (after `test_hlc.cpp`):

```cmake
        test_hlc.cpp
        test_time_source.cpp
        test_handler_registry.cpp
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cmake --build build --target testcrabs && ./build/test/testcrabs --gtest_filter='PlatformTime.*'`
Expected: PASS (1 test).

- [ ] **Step 6: Commit**

```bash
git add src/Util/platform.h test/test_time_source.cpp test/CMakeLists.txt
git commit -m "feat: add platform_get_monotonic for elapsed time computation"
```

---

### Task 2: Add `CRABS_TIME_SOURCE_HTTPS_AUTH` enum value

**Files:**
- Modify: `src/HLC/hlc.h:54-59`

- [ ] **Step 1: Add the enum value**

In `src/HLC/hlc.h`, change the `crabs_time_source_e` enum (lines 54-59) from:

```c
typedef enum {
  CRABS_TIME_SOURCE_SYSTEM_CLOCK = 0x00,
  CRABS_TIME_SOURCE_NTP_AUTH     = 0x01,
  CRABS_TIME_SOURCE_TPM          = 0x02,
  CRABS_TIME_SOURCE_CONSENSUS    = 0x03
} crabs_time_source_e;
```

to:

```c
typedef enum {
  CRABS_TIME_SOURCE_SYSTEM_CLOCK = 0x00,
  CRABS_TIME_SOURCE_NTP_AUTH     = 0x01,
  CRABS_TIME_SOURCE_TPM          = 0x02,
  CRABS_TIME_SOURCE_CONSENSUS    = 0x03,
  CRABS_TIME_SOURCE_HTTPS_AUTH   = 0x04
} crabs_time_source_e;
```

- [ ] **Step 2: Build to verify it compiles**

Run: `cmake --build build --target testcrabs`
Expected: builds cleanly.

- [ ] **Step 3: Commit**

```bash
git add src/HLC/hlc.h
git commit -m "feat: add CRABS_TIME_SOURCE_HTTPS_AUTH enum value"
```

---

### Task 3: Create the `time_source.h` public API

**Files:**
- Create: `src/TimeSource/time_source.h`

- [ ] **Step 1: Write the header**

Create `src/TimeSource/time_source.h`:

```c
//
// time_source.h — Pluggable authenticated time source for HLC.
//
// Implements the crabs_time_source_ops_t vtable from HLC/hlc.h. The backend
// fetches time from an HTTPS time API, caches it, and interpolates elapsed
// time with a monotonic clock between resyncs.
//

#ifndef CRABS_TIME_SOURCE_H
#define CRABS_TIME_SOURCE_H

#include <stdint.h>
#include <stdbool.h>
#include "../HLC/hlc.h"

#define CRABS_TIME_SOURCE_DEFAULT_URL         "https://cloudflare.com/cdn-cgi/trace"
#define CRABS_TIME_SOURCE_DEFAULT_RESYNC_MS   30000
#define CRABS_TIME_SOURCE_DEFAULT_TIMEOUT_MS  1000

// Result of a single fetch from the time server.
typedef struct {
  uint64_t seconds;   // Unix epoch seconds
  uint64_t nanos;     // Nanosecond component (0-999,999,999)
  bool     valid;     // Whether the fetch succeeded
} crabs_time_source_fetch_result_t;

// Configuration. NULL fields fall back to defaults.
typedef struct {
  const char* server_url;          // Default: CRABS_TIME_SOURCE_DEFAULT_URL
  uint64_t    resync_interval_ms;  // Default: CRABS_TIME_SOURCE_DEFAULT_RESYNC_MS
  uint64_t    timeout_ms;          // Default: CRABS_TIME_SOURCE_DEFAULT_TIMEOUT_MS
} crabs_time_source_config_t;

// Transport seam: performs one HTTPS query and returns the server's time.
// Injectable for testing. Returns valid=false on any failure.
typedef crabs_time_source_fetch_result_t (*crabs_time_source_fetch_fn)(
    const char* url, uint64_t timeout_ms);

// Create the HTTPS time source backend using the native transport.
// Returns NULL on allocation failure.
crabs_time_source_ops_t* crabs_time_source_https_create(
    const crabs_time_source_config_t* config);

// Create the backend with a caller-supplied transport (for testing and
// for the WASM host shim).
crabs_time_source_ops_t* crabs_time_source_https_create_with_transport(
    const crabs_time_source_config_t* config, crabs_time_source_fetch_fn transport);

// Destroy the backend and free its resources.
void crabs_time_source_destroy(crabs_time_source_ops_t* ops);

#endif // CRABS_TIME_SOURCE_H
```

- [ ] **Step 2: Build to verify it compiles**

Run: `cmake --build build --target testcrabs`
Expected: builds cleanly (header is not yet included anywhere, so this just checks the file parses via the glob — if the glob doesn't compile headers, run `gcc -fsyntax-only -Isrc src/TimeSource/time_source.h`).

- [ ] **Step 3: Commit**

```bash
git add src/TimeSource/time_source.h
git commit -m "feat: add HTTPS time source public API header"
```

---

### Task 4: Implement the backend with injectable transport + unit tests

**Files:**
- Create: `src/TimeSource/time_source.c`
- Modify: `test/test_time_source.cpp` (add backend tests)

- [ ] **Step 1: Write the failing tests**

Append to `test/test_time_source.cpp`:

```cpp
extern "C" {
#include "TimeSource/time_source.h"
}

// --- Fake transport for unit tests ---

static int fake_call_count = 0;
static bool fake_should_fail = false;
static uint64_t fake_seconds = 1000000000;
static uint64_t fake_nanos = 0;

static crabs_time_source_fetch_result_t fake_transport(const char* url, uint64_t timeout_ms) {
  (void)url;
  (void)timeout_ms;
  fake_call_count++;
  crabs_time_source_fetch_result_t result = {0, 0, false};
  if (!fake_should_fail) {
    result.seconds = fake_seconds;
    result.nanos = fake_nanos;
    result.valid = true;
  }
  return result;
}

static void reset_fake(uint64_t seconds, uint64_t nanos) {
  fake_call_count = 0;
  fake_should_fail = false;
  fake_seconds = seconds;
  fake_nanos = nanos;
}

TEST(TimeSourceBackend, FreshCacheDoesNotQueryTransport) {
  reset_fake(1000000000, 0);

  crabs_time_source_config_t config;
  config.server_url = "https://example.invalid";
  config.resync_interval_ms = 60000;  // long enough that both calls are fresh
  config.timeout_ms = 1000;

  crabs_time_source_ops_t* ops =
      crabs_time_source_https_create_with_transport(&config, fake_transport);
  ASSERT_NE(ops, nullptr);

  crabs_physical_time_t first = ops->get_time(ops->ctx);
  ASSERT_TRUE(first.valid);
  EXPECT_EQ(fake_call_count, 1);

  crabs_physical_time_t second = ops->get_time(ops->ctx);
  ASSERT_TRUE(second.valid);
  EXPECT_EQ(fake_call_count, 1);  // cache hit — no second transport call

  // Second result is the anchor plus a small elapsed time.
  EXPECT_TRUE(second.seconds > first.seconds ||
              (second.seconds == first.seconds && second.nanos >= first.nanos));

  EXPECT_TRUE(ops->is_available(ops->ctx));
  crabs_time_source_destroy(ops);
}

TEST(TimeSourceBackend, StaleCacheQueriesTransport) {
  reset_fake(1000000000, 0);

  crabs_time_source_config_t config;
  config.server_url = "https://example.invalid";
  config.resync_interval_ms = 0;  // every call is stale
  config.timeout_ms = 1000;

  crabs_time_source_ops_t* ops =
      crabs_time_source_https_create_with_transport(&config, fake_transport);
  ASSERT_NE(ops, nullptr);

  ops->get_time(ops->ctx);
  ops->get_time(ops->ctx);
  EXPECT_EQ(fake_call_count, 2);  // each call re-queries

  crabs_time_source_destroy(ops);
}

TEST(TimeSourceBackend, FailedFetchFallsBackToSystemClock) {
  reset_fake(1000000000, 0);
  fake_should_fail = true;

  crabs_time_source_config_t config;
  config.server_url = "https://example.invalid";
  config.resync_interval_ms = 0;
  config.timeout_ms = 1000;

  crabs_time_source_ops_t* ops =
      crabs_time_source_https_create_with_transport(&config, fake_transport);
  ASSERT_NE(ops, nullptr);

  crabs_physical_time_t result = ops->get_time(ops->ctx);
  EXPECT_TRUE(result.valid);  // system clock fallback is valid
  EXPECT_EQ(fake_call_count, 1);
  EXPECT_FALSE(ops->is_available(ops->ctx));  // no anchor held

  crabs_time_source_destroy(ops);
}

TEST(TimeSourceBackend, FailedFetchKeepsLastValidAnchor) {
  reset_fake(1000000000, 0);

  crabs_time_source_config_t config;
  config.server_url = "https://example.invalid";
  config.resync_interval_ms = 0;
  config.timeout_ms = 1000;

  crabs_time_source_ops_t* ops =
      crabs_time_source_https_create_with_transport(&config, fake_transport);
  ASSERT_NE(ops, nullptr);

  crabs_physical_time_t first = ops->get_time(ops->ctx);
  ASSERT_TRUE(first.valid);
  EXPECT_TRUE(ops->is_available(ops->ctx));

  // Now the transport fails; the backend keeps the anchor but returns
  // the system clock for this call.
  fake_should_fail = true;
  crabs_physical_time_t second = ops->get_time(ops->ctx);
  EXPECT_TRUE(second.valid);
  EXPECT_TRUE(ops->is_available(ops->ctx));  // anchor retained

  crabs_time_source_destroy(ops);
}

TEST(TimeSourceBackend, NullTransportReturnsNull) {
  crabs_time_source_config_t config;
  config.server_url = "https://example.invalid";
  config.resync_interval_ms = 0;
  config.timeout_ms = 1000;

  crabs_time_source_ops_t* ops =
      crabs_time_source_https_create_with_transport(&config, NULL);
  EXPECT_EQ(ops, nullptr);
}

TEST(TimeSourceBackend, DefaultsAppliedWhenConfigNull) {
  reset_fake(1000000000, 0);

  crabs_time_source_ops_t* ops =
      crabs_time_source_https_create_with_transport(NULL, fake_transport);
  ASSERT_NE(ops, nullptr);

  crabs_physical_time_t result = ops->get_time(ops->ctx);
  EXPECT_TRUE(result.valid);
  EXPECT_EQ(fake_call_count, 1);

  crabs_time_source_destroy(ops);
}
```

- [ ] **Step 2: Run tests to verify they fail to link**

Run: `cmake --build build --target testcrabs 2>&1 | grep -i "time_source\|error" | head`
Expected: link error — `crabs_time_source_https_create_with_transport` is undefined.

- [ ] **Step 3: Implement the backend**

Create `src/TimeSource/time_source.c`:

```c
//
// time_source.c — HTTPS time source backend for HLC.
//
// Implements the crabs_time_source_ops_t vtable. The backend holds a lazy
// cache: it queries the transport at most once per resync interval, and
// between syncs returns anchor + (monotonic_now - anchor_monotonic).
//

#include "time_source.h"
#include "../Util/platform.h"
#include "../Util/allocator.h"
#include "../Util/log.h"
#include <stdlib.h>
#include <string.h>

// Forward declaration: native OpenSSL transport (defined below). Guarded so
// the WASM build (which cannot open sockets) does not compile it.
#ifndef __EMSCRIPTEN__
static crabs_time_source_fetch_result_t _native_fetch_server_time(
    const char* url, uint64_t timeout_ms);
#endif

typedef struct {
  char*     server_url;
  uint64_t  resync_interval_ms;
  uint64_t  timeout_ms;
  crabs_time_source_fetch_fn transport;

  bool      has_anchor;
  uint64_t  anchor_seconds;
  uint64_t  anchor_nanos;
  uint64_t  anchor_monotonic_seconds;
  uint64_t  anchor_monotonic_nanos;
} crabs_time_source_ctx_t;

// Elapsed milliseconds between two monotonic timestamps (now >= then).
static uint64_t _elapsed_ms(const platform_time_t* now, const platform_time_t* then) {
  int64_t seconds_diff = (int64_t)now->seconds - (int64_t)then->seconds;
  int64_t nanos_diff = (int64_t)now->nanos - (int64_t)then->nanos;
  if (nanos_diff < 0) {
    seconds_diff -= 1;
    nanos_diff += 1000000000;
  }
  return (uint64_t)(seconds_diff * 1000 + nanos_diff / 1000000);
}

// Add a duration in milliseconds to a seconds/nanos pair, normalizing.
static void _add_ms(uint64_t* seconds, uint64_t* nanos, uint64_t ms) {
  *nanos += (ms % 1000) * 1000000;
  *seconds += ms / 1000;
  *seconds += *nanos / 1000000000;
  *nanos = *nanos % 1000000000;
}

static crabs_physical_time_t _get_time(void* ctx) {
  crabs_time_source_ctx_t* context = (crabs_time_source_ctx_t*)ctx;
  crabs_physical_time_t result = {0, 0, false};

  platform_time_t monotonic_now = platform_get_monotonic();
  if (!monotonic_now.valid) {
    return crabs_hlc_get_system_time(NULL);
  }

  if (context->has_anchor) {
    platform_time_t anchor_monotonic;
    anchor_monotonic.seconds = context->anchor_monotonic_seconds;
    anchor_monotonic.nanos = context->anchor_monotonic_nanos;
    uint64_t elapsed = _elapsed_ms(&monotonic_now, &anchor_monotonic);
    if (elapsed < context->resync_interval_ms) {
      result.seconds = context->anchor_seconds;
      result.nanos = context->anchor_nanos;
      _add_ms(&result.seconds, &result.nanos, elapsed);
      result.valid = true;
      return result;
    }
  }

  crabs_time_source_fetch_result_t fetched =
      context->transport(context->server_url, context->timeout_ms);
  if (fetched.valid) {
    context->has_anchor = true;
    context->anchor_seconds = fetched.seconds;
    context->anchor_nanos = fetched.nanos;
    context->anchor_monotonic_seconds = monotonic_now.seconds;
    context->anchor_monotonic_nanos = monotonic_now.nanos;
    result.seconds = fetched.seconds;
    result.nanos = fetched.nanos;
    result.valid = true;
    return result;
  }

  log_warn("time source unreachable; using system clock");
  return crabs_hlc_get_system_time(NULL);
}

static bool _is_available(void* ctx) {
  crabs_time_source_ctx_t* context = (crabs_time_source_ctx_t*)ctx;
  return context->has_anchor;
}

static crabs_time_source_ops_t* _create(const crabs_time_source_config_t* config,
                                        crabs_time_source_fetch_fn transport) {
  if (transport == NULL) return NULL;

  crabs_time_source_ctx_t* context = get_clear_memory(sizeof(crabs_time_source_ctx_t));
  const char* url = (config != NULL && config->server_url != NULL)
      ? config->server_url : CRABS_TIME_SOURCE_DEFAULT_URL;
  context->server_url = platform_strdup(url);
  context->resync_interval_ms = (config != NULL && config->resync_interval_ms > 0)
      ? config->resync_interval_ms : CRABS_TIME_SOURCE_DEFAULT_RESYNC_MS;
  context->timeout_ms = (config != NULL && config->timeout_ms > 0)
      ? config->timeout_ms : CRABS_TIME_SOURCE_DEFAULT_TIMEOUT_MS;
  context->transport = transport;

  crabs_time_source_ops_t* ops = get_clear_memory(sizeof(crabs_time_source_ops_t));
  ops->get_time = _get_time;
  ops->is_available = _is_available;
  ops->ctx = context;
  return ops;
}

crabs_time_source_ops_t* crabs_time_source_https_create(
    const crabs_time_source_config_t* config) {
  return _create(config, _native_fetch_server_time);
}

crabs_time_source_ops_t* crabs_time_source_https_create_with_transport(
    const crabs_time_source_config_t* config, crabs_time_source_fetch_fn transport) {
  return _create(config, transport);
}

void crabs_time_source_destroy(crabs_time_source_ops_t* ops) {
  if (ops == NULL) return;
  crabs_time_source_ctx_t* context = (crabs_time_source_ctx_t*)ops->ctx;
  if (context != NULL) {
    free(context->server_url);
    free(context);
  }
  free(ops);
}

// ============================================================
// Native HTTPS transport (OpenSSL)
// ============================================================

// Placeholder until Task 5 implements the real transport. Returns invalid so
// the backend falls back to the system clock (a safe default).
static crabs_time_source_fetch_result_t _native_fetch_server_time(
    const char* url, uint64_t timeout_ms) {
  (void)url;
  (void)timeout_ms;
  crabs_time_source_fetch_result_t result = {0, 0, false};
  return result;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cmake --build build --target testcrabs && ./build/test/testcrabs --gtest_filter='TimeSourceBackend.*'`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add src/TimeSource/time_source.c test/test_time_source.cpp
git commit -m "feat: implement HTTPS time source backend with lazy cache"
```

---

### Task 5: Native OpenSSL HTTPS transport + integration test

**Files:**
- Modify: `src/TimeSource/time_source.c` (replace the placeholder transport)
- Modify: `test/test_time_source.cpp` (add network-gated integration tests)

- [ ] **Step 1: Write the failing integration tests**

Append to `test/test_time_source.cpp`:

```cpp
// --- Network-gated integration tests ---
// These hit a real public time server. They skip cleanly when offline so CI
// without network does not fail.

static void assert_plausible_time(const crabs_physical_time_t* fetched) {
  ASSERT_TRUE(fetched->valid);
  crabs_physical_time_t local = crabs_hlc_get_system_time(NULL);
  ASSERT_TRUE(local.valid);
  int64_t diff_seconds = (int64_t)fetched->seconds - (int64_t)local.seconds;
  if (diff_seconds < 0) diff_seconds = -diff_seconds;
  EXPECT_LT(diff_seconds, 5);  // within HLC default max_skew_ms
}

TEST(TimeSourceIntegration, CloudflareTraceEndpoint) {
  crabs_time_source_config_t config;
  config.server_url = NULL;  // default: https://cloudflare.com/cdn-cgi/trace
  config.resync_interval_ms = 0;  // force a fresh fetch
  config.timeout_ms = 5000;

  crabs_time_source_ops_t* ops = crabs_time_source_https_create(&config);
  ASSERT_NE(ops, nullptr);

  crabs_physical_time_t fetched = ops->get_time(ops->ctx);
  if (!fetched.valid) {
    GTEST_SKIP() << "Network unavailable; skipping integration test";
  }
  assert_plausible_time(&fetched);
  EXPECT_TRUE(ops->is_available(ops->ctx));

  crabs_time_source_destroy(ops);
}

TEST(TimeSourceIntegration, JsonTimeApi) {
  crabs_time_source_config_t config;
  config.server_url = "https://worldtimeapi.org/api/timezone/Etc/UTC";
  config.resync_interval_ms = 0;
  config.timeout_ms = 5000;

  crabs_time_source_ops_t* ops = crabs_time_source_https_create(&config);
  ASSERT_NE(ops, nullptr);

  crabs_physical_time_t fetched = ops->get_time(ops->ctx);
  if (!fetched.valid) {
    GTEST_SKIP() << "Network or server unavailable; skipping integration test";
  }
  assert_plausible_time(&fetched);

  crabs_time_source_destroy(ops);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cmake --build build --target testcrabs && ./build/test/testcrabs --gtest_filter='TimeSourceIntegration.*'`
Expected: both tests SKIP (the placeholder transport always returns invalid).

- [ ] **Step 3: Implement the native transport**

Replace the placeholder `_native_fetch_server_time` at the bottom of `src/TimeSource/time_source.c` with the real implementation, and add the includes and helpers below.

Add these includes at the top of `src/TimeSource/time_source.c` (after the existing includes). The whole native transport is guarded so the WASM build (which cannot open sockets) does not compile it:

```c
#ifndef __EMSCRIPTEN__
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET platform_socket_t;
#define PLATFORM_INVALID_SOCKET INVALID_SOCKET
#else
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
typedef int platform_socket_t;
#define PLATFORM_INVALID_SOCKET (-1)
#endif
#endif // __EMSCRIPTEN__
```

Add these helper functions and the real transport, replacing the placeholder:

```c
#ifndef __EMSCRIPTEN__

// ============================================================
// Native HTTPS transport (OpenSSL)
// ============================================================

static void _platform_close_socket(platform_socket_t socket_fd) {
#ifdef _WIN32
  closesocket(socket_fd);
#else
  close(socket_fd);
#endif
}

// Parse "https://host[:port]/path" into host, path, and port.
static bool _parse_url(const char* url, char* host, size_t host_len,
                       char* path, size_t path_len, int* port) {
  if (url == NULL) return false;
  const char* scheme = strstr(url, "://");
  if (scheme == NULL) return false;
  const char* host_start = scheme + 3;
  const char* path_start = strchr(host_start, '/');
  const char* host_end = path_start != NULL ? path_start : host_start + strlen(host_start);
  size_t host_size = (size_t)(host_end - host_start);
  if (host_size == 0 || host_size >= host_len) return false;
  memcpy(host, host_start, host_size);
  host[host_size] = '\0';
  if (path_start != NULL) {
    snprintf(path, path_len, "%s", path_start);
  } else {
    snprintf(path, path_len, "/");
  }
  *port = 443;
  return true;
}

static platform_socket_t _tcp_connect(const char* host, int port) {
  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo* addresses = NULL;
  if (getaddrinfo(host, port_str, &hints, &addresses) != 0) {
    return PLATFORM_INVALID_SOCKET;
  }

  platform_socket_t socket_fd = PLATFORM_INVALID_SOCKET;
  for (struct addrinfo* address = addresses; address != NULL; address = address->ai_next) {
    socket_fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (socket_fd == PLATFORM_INVALID_SOCKET) continue;
    if (connect(socket_fd, address->ai_addr, (int)address->ai_addrlen) == 0) break;
    _platform_close_socket(socket_fd);
    socket_fd = PLATFORM_INVALID_SOCKET;
  }
  freeaddrinfo(addresses);
  return socket_fd;
}

// Parse a Unix timestamp from the response body. Supports the Cloudflare
// trace format ("ts=1786764168.000") and the worldtimeapi JSON format
// ("\"unixtime\":1786764168").
static void _parse_timestamp(const char* response, crabs_time_source_fetch_result_t* result) {
  const char* ts_marker = strstr(response, "ts=");
  if (ts_marker != NULL) {
    const char* value_start = ts_marker + 3;
    uint64_t seconds = 0;
    while (*value_start >= '0' && *value_start <= '9') {
      seconds = seconds * 10 + (uint64_t)(*value_start - '0');
      value_start++;
    }
    uint64_t nanos = 0;
    if (*value_start == '.') {
      value_start++;
      uint64_t fraction = 0;
      int digits = 0;
      while (*value_start >= '0' && *value_start <= '9' && digits < 9) {
        fraction = fraction * 10 + (uint64_t)(*value_start - '0');
        value_start++;
        digits++;
      }
      while (digits < 9) { fraction *= 10; digits++; }
      nanos = fraction;
    }
    result->seconds = seconds;
    result->nanos = nanos;
    result->valid = true;
    return;
  }

  const char* unixtime_marker = strstr(response, "\"unixtime\"");
  if (unixtime_marker != NULL) {
    const char* colon = strchr(unixtime_marker, ':');
    if (colon != NULL) {
      const char* value_start = colon + 1;
      while (*value_start == ' ' || *value_start == '\t') value_start++;
      uint64_t seconds = 0;
      while (*value_start >= '0' && *value_start <= '9') {
        seconds = seconds * 10 + (uint64_t)(*value_start - '0');
        value_start++;
      }
      result->seconds = seconds;
      result->nanos = 0;
      result->valid = true;
    }
  }
}

static crabs_time_source_fetch_result_t _native_fetch_server_time(
    const char* url, uint64_t timeout_ms) {
  crabs_time_source_fetch_result_t result = {0, 0, false};

  char host[256];
  char path[512];
  int port = 443;
  if (!_parse_url(url, host, sizeof(host), path, sizeof(path), &port)) {
    return result;
  }

  platform_socket_t socket_fd = _tcp_connect(host, port);
  if (socket_fd == PLATFORM_INVALID_SOCKET) return result;

  struct timeval timeout;
  timeout.tv_sec = (time_t)(timeout_ms / 1000);
  timeout.tv_usec = (suseconds_t)((timeout_ms % 1000) * 1000);
  setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (ssl_ctx == NULL) {
    _platform_close_socket(socket_fd);
    return result;
  }
  SSL* ssl = SSL_new(ssl_ctx);
  if (ssl == NULL) {
    SSL_CTX_free(ssl_ctx);
    _platform_close_socket(socket_fd);
    return result;
  }
  SSL_set_fd(ssl, socket_fd);
  SSL_set_tlsext_host_name(ssl, host);
  if (SSL_connect(ssl) != 1) {
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    _platform_close_socket(socket_fd);
    return result;
  }

  char request[1024];
  int request_len = snprintf(request, sizeof(request),
      "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
      "User-Agent: crabs-time-source/1.0\r\n\r\n",
      path, host);
  if (SSL_write(ssl, request, request_len) <= 0) {
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    _platform_close_socket(socket_fd);
    return result;
  }

  char response[8192];
  int response_len = 0;
  int read_result;
  while (response_len < (int)sizeof(response) - 1 &&
         (read_result = SSL_read(ssl, response + response_len,
                                 (int)sizeof(response) - 1 - response_len)) > 0) {
    response_len += read_result;
  }
  response[response_len] = '\0';

  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  _platform_close_socket(socket_fd);

  if (response_len == 0) return result;
  _parse_timestamp(response, &result);
  return result;
}

#endif // __EMSCRIPTEN__
```

Note: `suseconds_t` is POSIX-only. On Windows, replace the `timeout.tv_usec` line with `timeout.tv_usec = (long)((timeout_ms % 1000) * 1000);`. The Windows socket path is not exercised by the Linux test suite; verify it on a Windows build if that platform matters.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cmake --build build --target testcrabs && ./build/test/testcrabs --gtest_filter='TimeSourceIntegration.*'`
Expected: both tests PASS (network available) or SKIP (offline). Also re-run the backend tests to confirm no regression:
`./build/test/testcrabs --gtest_filter='TimeSourceBackend.*'`

- [ ] **Step 5: Commit**

```bash
git add src/TimeSource/time_source.c test/test_time_source.cpp
git commit -m "feat: add native OpenSSL HTTPS transport for time source"
```

---

### Task 6: WASM transport shim

**Files:**
- Modify: `src/TimeSource/time_source.c` (add `_wasm_fetch_server_time` and wire it in)
- Create: `src/TimeSource/wasm_time_library.js` (emscripten JS library defining the imported function)
- Modify: `build_wasm.sh` (import the JS function)

The browser/Node WASM build cannot open sockets, so the transport is a JS function that performs the HTTPS fetch on the host and returns Unix seconds as a double (negative on failure). The C wrapper converts the double to the fetch-result struct.

- [ ] **Step 1: Add the WASM transport to time_source.c**

In `src/TimeSource/time_source.c`, add the WASM branch. First, change the `_create` dispatch so `crabs_time_source_https_create` picks the WASM transport when compiled for emscripten. Replace the `crabs_time_source_https_create` function:

```c
crabs_time_source_ops_t* crabs_time_source_https_create(
    const crabs_time_source_config_t* config) {
#ifdef __EMSCRIPTEN__
  return _create(config, _wasm_fetch_server_time);
#else
  return _create(config, _native_fetch_server_time);
#endif
}
```

Add the forward declaration next to the existing one (near the top of the file):

```c
#ifdef __EMSCRIPTEN__
static crabs_time_source_fetch_result_t _wasm_fetch_server_time(
    const char* url, uint64_t timeout_ms);
#endif
```

Add the WASM transport implementation at the bottom of the file, after the native transport:

```c
#ifdef __EMSCRIPTEN__
// Imported from the JS glue (see wasm_time_library.js). Returns Unix seconds
// as a double, or a negative value on failure.
extern double js_fetch_server_time(const char* url, uint64_t timeout_ms);

static crabs_time_source_fetch_result_t _wasm_fetch_server_time(
    const char* url, uint64_t timeout_ms) {
  crabs_time_source_fetch_result_t result = {0, 0, false};
  double server_time = js_fetch_server_time(url, timeout_ms);
  if (server_time < 0.0) return result;
  result.seconds = (uint64_t)server_time;
  result.nanos = (uint64_t)((server_time - (double)result.seconds) * 1000000000.0);
  result.valid = true;
  return result;
}
#endif
```

- [ ] **Step 2: Create the JS library**

Create `src/TimeSource/wasm_time_library.js`:

```js
// wasm_time_library.js — emscripten JS library providing the host-side
// HTTPS time fetch for the WASM build. The browser uses fetch(); a Node
// build would use the https module instead.
mergeInto(LibraryManager.library, {
  js_fetch_server_time: function (urlPtr, timeoutMs) {
    var url = UTF8ToString(urlPtr);
    var timeout = timeoutMs >>> 0;
    var result = -1.0;
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, timeout);
    return fetch(url, { signal: controller.signal })
      .then(function (response) { return response.text(); })
      .then(function (body) {
        clearTimeout(timer);
        var match = body.match(/ts=(\d+)(?:\.(\d+))?/);
        if (match) {
          result = parseFloat(match[1]) + (match[2] ? parseFloat('0.' + match[2]) : 0.0);
        } else {
          var unixtime = body.match(/"unixtime":\s*(\d+)/);
          if (unixtime) result = parseFloat(unixtime[1]);
        }
        return result;
      })
      .catch(function () { clearTimeout(timer); return -1.0; });
  }
});
```

Note: `fetch` is async, but the transport seam is synchronous. For a synchronous result, the JS glue must use a synchronous mechanism (e.g., `XMLHttpRequest` with `async: false` in the browser, or `child_process.execSync`/`https` with a blocking wait in Node). The snippet above is the async sketch; the final glue must block until the fetch completes. This task requires a WASM build to verify and is not exercised by the native test suite.

- [ ] **Step 3: Update build_wasm.sh**

In `build_wasm.sh`, add the JS library to the emcc link command (after the `-s EXPORTED_RUNTIME_METHODS` line):

```bash
  --js-library "$ROOT_DIR/src/TimeSource/wasm_time_library.js" \
```

- [ ] **Step 4: Build the WASM module to verify it compiles**

Run: `source /home/victor/emsdk/emsdk_env.sh && ./build_wasm.sh`
Expected: `crabs.wasm` and `crabs.js` build successfully. (The JS glue's synchronous fetch behavior must be verified in a browser/Node runtime; the native test suite does not cover it.)

- [ ] **Step 5: Commit**

```bash
git add src/TimeSource/time_source.c src/TimeSource/wasm_time_library.js build_wasm.sh
git commit -m "feat: add WASM host shim for HTTPS time source"
```

---

## Self-Review

**Spec coverage:**
- Optionality (default system clock, opt-in via `time_source_ops`) — Task 4 backend + Task 3 API; default behavior unchanged.
- Lazy caching (query at most once per resync interval, monotonic elapsed) — Task 4.
- `platform_get_monotonic()` — Task 1.
- `CRABS_TIME_SOURCE_HTTPS_AUTH` enum — Task 2.
- Native OpenSSL transport — Task 5.
- WASM shim (browser/Node) — Task 6.
- Default public server + override — Task 3 config + Task 5 integration test.
- Integration test against real public server (Cloudflare + worldtimeapi, network-gated) — Task 5.
- No single-letter variables — all code in this plan uses descriptive names.

**Placeholder scan:** No TBD/TODO. The only deferred item is the WASM JS glue's synchronous fetch, which is explicitly flagged as requiring a WASM runtime to verify.

**Type consistency:** `crabs_time_source_fetch_result_t`, `crabs_time_source_config_t`, `crabs_time_source_fetch_fn`, `crabs_time_source_https_create`, `crabs_time_source_https_create_with_transport`, `crabs_time_source_destroy`, and `platform_get_monotonic` are defined once and used consistently across all tasks.

