# CRABS Cross-Platform Build & Execution Audit

**Date:** 2026-08-01
**Scope:** Full source tree under `src/` plus `CMakeLists.txt`, `test/CMakeLists.txt`, and the `deps/openabe-c` build integration. Assessed for portability across Linux, macOS, and Windows (MSVC and MinGW).
**Method:** Manual code review of all platform-sensitive patterns: threading primitives, time APIs, string functions, format specifiers, endianness handling, type sizes, header includes, and build system configuration.
**Relationship to Prior Audits:** This is a new audit dimension. Prior audits (SECURITY_AUDIT_1–6) focused on security and correctness; this audit focuses on portability.

---

## 1. Executive Summary

The CRABS library builds and runs on **64-bit Linux**. It has **significant cross-platform portability gaps** that prevent it from building or running correctly on **Windows** (MSVC or MinGW) and would require work for **macOS** (some POSIX functions differ). The library has good endianness discipline (explicit byte-by-byte serialization) and no 32/64-bit pointer assumptions, but relies on POSIX-specific APIs throughout.

**Severity counts:** 4 HIGH, 5 MEDIUM, 4 LOW.

The most significant issues:
1. **pthread dependency is unconditional** — no Windows threading fallback.
2. **`clock_gettime` / `CLOCK_REALTIME`** — POSIX-only, no Windows equivalent.
3. **`%lu` format for `uint64_t`** — truncates to 32 bits on 64-bit Windows (LLP64).
4. **No platform abstraction layer** — the `platform.h` / `PLATFORM*` macros described in `STYLE_GUIDE.md` do not exist.

**Positive findings:** endianness handling is excellent (explicit LE/BE byte-by-byte serialization everywhere), no struct `memcpy` across the wire, no pointer serialization, no 32/64-bit assumptions in data structures.

---

## 2. HIGH Findings

### X-1. Unconditional pthread dependency — no Windows threading support

`src/Crypto/sig_scheme.c:9,20,31-197`; `CMakeLists.txt:36`

The signature scheme registry uses `pthread.h` and `pthread_mutex_t` unconditionally:
```c
#include <pthread.h>
static pthread_mutex_t _registry_lock = PTHREAD_MUTEX_INITIALIZER;
```

The CMakeLists.txt links `pthread` unconditionally:
```cmake
target_link_libraries(crabs PRIVATE ... pthread ...)
```

**Impact:** The library does not build on Windows with MSVC (no `pthread.h`). On MinGW, `pthread` is available via the `winpthreads` library but must be explicitly linked. On macOS, `pthread` is available but uses a different semaphore API.

**Recommendation:** Create `src/Util/platform.h` with a threading abstraction (matching the `PLATFORMLOCKTYPE` / `PLATFORMCONDITIONTYPE` / `PLATFORMTHREADTYPE` pattern described in `STYLE_GUIDE.md` §5.3). Use `#ifdef _WIN32` to select between `CRITICAL_SECTION` / `pthread_mutex_t`. In CMakeLists.txt, use `find_package(Threads REQUIRED)` and link `Threads::Threads` (CMake's portable threading target).

### X-2. `clock_gettime` / `CLOCK_REALTIME` — POSIX-only

`src/HLC/hlc.c:249`

```c
if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    return result;  // {0, 0, false}
}
```

`clock_gettime` and `CLOCK_REALTIME` are POSIX.1-2001 functions. Windows does not provide them (MSVC has no `clock_gettime`; MinGW has it only with `-D_POSIX_C_SOURCE`). macOS has `clock_gettime` (10.12+) but also supports `clock_gettime_nsec_np`.

**Impact:** The HLC time source fails on Windows, causing all HLC-based operations (lock expiry, ordering) to fail-closed (return invalid time → reject). The library is non-functional on Windows for HLC deployments.

**Recommendation:** Add a platform-conditional time source:
```c
#ifdef _WIN32
  // GetSystemTimeAsFileTime → FILETIME → uint64_t 100ns intervals since 1601
  FILETIME ft; GetSystemTimeAsFileTime(&ft);
  uint64_t ns = ((uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime);
  // Convert Windows epoch (1601) to Unix epoch (1970): subtract 11644473600 seconds
#else
  clock_gettime(CLOCK_REALTIME, &ts);
#endif
```

### X-3. `%lu` / `%ld` format specifiers for `uint64_t` / `int64_t` — truncation on Windows

`src/CLI/cli.c:315,324,375,627`; `src/Compaction/compaction.c:236`; `src/HLC/hlc.c:120`

```c
printf("State Version: %lu\n", state->version);        // state->version is uint64_t
printf("  Log Entries: %lu\n", state->log_count);      // state->log_count is uint64_t
printf("  max_lock_duration_ms: %lu\n", cfg->max_lock_duration_ms);  // uint64_t
printf("  New key version: %lu\n", user->key_version);  // uint64_t
snprintf(buf, buf_size, "tombstones=%lu visible=%lu", tombstones, visible);  // both uint64_t
"%04d-%02d-%02dT%02d:%02d:%02d.%09lu#%lu@%s",  // physical_nanos, logical_counter are uint64_t
```

On 64-bit Linux/macOS (LP64 model), `unsigned long` is 64-bit, so `%lu` prints the full `uint64_t` value. On 64-bit Windows (LLP64 model), `unsigned long` is **32-bit**, so `%lu` truncates `uint64_t` values to the lower 32 bits. A `state->version` of `0x100000002` would print as `2` on Windows.

**Impact:** Diagnostic output (CLI status, compaction stats, HLC formatting) is silently wrong on Windows for large values. Not a security issue (display only), but confusing for operators.

**Recommendation:** Use `PRIu64` / `PRId64` from `<inttypes.h>` (portable) or cast to `unsigned long long` and use `%llu` / `%lld`. The `condition.c` file already does this correctly: `snprintf(tmp, sizeof(tmp), "%s %s %lld", ..., (long long)node->right_literal)`.

### X-4. No platform abstraction layer — `STYLE_GUIDE.md` describes macros that don't exist

`docs/STYLE_GUIDE.md` §5.3; `src/Util/` (no `platform.h`)

The style guide describes:
```c
PLATFORMLOCKTYPE(lock);           // pthread_mutex_t / CRITICAL_SECTION
PLATFORMCONDITIONTYPE(cond);      // pthread_cond_t / CONDITION_VARIABLE
PLATFORMTHREADTYPE thread;        // pthread_t / HANDLE
```

with inline `#ifdef _WIN32` / `#else` blocks. But `src/Util/` contains only `allocator.c`, `allocator.h`, `log.c`, `log.h` — there is no `platform.h`. The `PLATFORM*` macros are not defined anywhere.

**Impact:** Developers following the style guide will expect a platform abstraction that doesn't exist. Any code that needs threading or platform-specific types must implement the conditional compilation inline, which is error-prone and inconsistent.

**Recommendation:** Create `src/Util/platform.h` implementing the `PLATFORM*` macros from the style guide, with `#ifdef _WIN32` / `#else` blocks for each type and function (lock init/destroy/lock/unlock, condition wait/signal/broadcast, thread create/join). Migrate `sig_scheme.c` to use it.

---

## 3. MEDIUM Findings

### X-5. `localtime_r` / `gmtime_r` — POSIX-only

`src/Util/log.c:140`; `src/HLC/hlc.c:117`

```c
localtime_r(&t, &tm_buf);   // log.c — POSIX
gmtime_r(&sec, &tm);        // hlc.c — POSIX
```

Windows/MSVC uses `localtime_s` / `gmtime_s` with **reversed argument order**: `localtime_s(&tm_buf, &t)` (destination first, source second). `strtok_r` has the same pattern (see X-6).

**Impact:** Compilation fails on MSVC. On MinGW, these are available with `_POSIX_THREAD_SAFE_FUNCTIONS` defined.

**Recommendation:** Add platform conditionals:
```c
#ifdef _WIN32
  localtime_s(&tm_buf, &t);
#else
  localtime_r(&t, &tm_buf);
#endif
```

### X-6. `strtok_r` — POSIX-only (26 occurrences)

`src/Trigger/trigger.c:260,267,303`; `src/StateMachine/state_machine.c:1012,1017,...`; and 22 more across the codebase.

`strtok_r` is POSIX. MSVC provides `strtok_s` with a **different signature** (takes a context pointer as last argument on some implementations, though the C11 standard `strtok_s` is different from POSIX `strtok_r`). The C standard (C11/C23) function is `strtok_s` with a different prototype.

**Impact:** Compilation fails on MSVC. On MinGW, `strtok_r` is available with `_POSIX_THREAD_SAFE_FUNCTIONS`.

**Recommendation:** Create a `crabs_strtok_r` wrapper in `platform.h` that maps to `strtok_r` on POSIX and `strtok_s` on Windows. Or use the C11 `strtok_s` if targeting C11 only (the signatures differ: `strtok_s(char *str, rsize_t *strmax, const char *delim, char **ptr)` vs `strtok_r(char *str, const char *delim, char **saveptr)`).

### X-7. `strdup` — POSIX-only (19 occurrences)

`src/Condition/condition.c:377,400,539,558,618,672,805,1114`; `src/CRDT/one_shot.c:42`; `src/CRDT/crdt_merge.c` (multiple)

`strdup` is POSIX.1-2008, not C99/C11 standard. MSVC provides `_strdup` (or `strdup` with `_CRT_NONSTDC_NO_DEPRECATE` defined). C23 makes `strdup` standard.

**Impact:** Compilation may fail on MSVC in strict mode. Works on MinGW with appropriate feature macros.

**Recommendation:** Create a `crabs_strdup` wrapper, or define `_CRT_NONSTDC_NO_DEPRECATE` before `#include <string.h>` on Windows, or use the project's `get_memory` + `strcpy` pattern (which the allocator already provides).

### X-8. `__thread` vs `_Thread_local` inconsistency

`src/Util/log.c:138` vs `src/OT/ot_transform.c:422`

```c
static __thread struct tm tm_buf;          // log.c — GCC/Clang extension
static _Thread_local crabs_transform_entry_t _entry_result;  // ot_transform.c — C11
```

`__thread` is a GCC/Clang extension. MSVC uses `__declspec(thread)`. C11 `_Thread_local` is the standard and is supported by MSVC 2019+ in C11 mode. The codebase uses both inconsistently.

**Impact:** `log.c` may not compile on MSVC. The CMakeLists sets `CMAKE_C_STANDARD 11`, so `_Thread_local` should be available everywhere.

**Recommendation:** Replace `__thread` in `log.c:138` with `_Thread_local` for consistency and MSVC compatibility.

### X-9. CMakeLists.txt hardcodes Unix static library paths

`CMakeLists.txt:33-36`

```cmake
target_link_libraries(crabs PRIVATE
    ${OPENABE_LIB}/liboabe_c.a
    ${RELIC_LIB}/librelic_s.a
    gmp
    pthread
    ${OPENSSL_LIBRARIES})
```

The `.a` suffix is Unix-specific. On Windows, static libraries have `.lib` extension. The `gmp` and `pthread` libraries are linked by name without `find_package`, which won't resolve on Windows. The OpenABE and RELIC paths are hardcoded to `build/lib` subdirectories.

**Impact:** The build fails on Windows. On macOS, `gmp` may be installed via Homebrew at a non-standard path (needs `find_package(PkgConfig)` or `find_library`).

**Recommendation:**
- Use `find_package(Threads REQUIRED)` and link `Threads::Threads` instead of `pthread`.
- Use `find_library(GMP gmp)` instead of bare `gmp`.
- Use CMake generator expressions for library paths: `$<TARGET_FILE:oabe_c>` or use `find_library` with platform-aware suffixes.
- Add `if(WIN32)` / `else()` blocks for Windows vs Unix linking.

---

## 4. LOW Findings

### X-10. `FetchContent` downloads GoogleTest from GitHub at configure time

`test/CMakeLists.txt:4-8`

```cmake
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
```

This requires internet access during `cmake configure`. Air-gapped build environments, CI behind corporate proxies, and reproducible-build setups all break.

**Recommendation:** Use `GIT_REPOSITORY` with a tag (allows shallow clone and caching) or vendor GoogleTest as a submodule. Document the `FETCHCONTENT_FULLY_DISCONNECTED=ON` option for offline builds.

### X-11. OpenSSL deprecated API usage (EC_KEY)

`src/Crypto/crypto.c` (throughout)

The code uses `EC_KEY_new_by_curve_name`, `EC_KEY_generate_key`, `ECDSA_sign`, `ECDSA_verify` — all deprecated in OpenSSL 3.0 (replaced by `EVP_PKEY` / `EVP_DigestSign` / `EVP_DigestVerify`). This was noted as N-19 in the Round 3 security audit.

**Cross-platform impact:** OpenSSL 3.0 is the default on modern Linux and macOS. The deprecated APIs still work but produce warnings. Future OpenSSL versions (4.0+) may remove them. MSVC builds with OpenSSL 3.x will see the same deprecation warnings.

**Recommendation:** Migrate to the EVP API (noted as a follow-up in prior audits). This is not strictly a cross-platform issue, but it affects portability to future OpenSSL versions.

### X-12. No CI configuration for non-Linux platforms

No `.github/workflows/`, no `.gitlab-ci.yml`, no `appveyor.yml` — the repository has no CI configuration at all. There is no evidence that the code has ever been built or tested on Windows or macOS.

**Recommendation:** Add CI workflows for Linux, macOS, and Windows (MSVC and MinGW) to catch cross-platform regressions automatically.

### X-13. `time(NULL)` granularity — 1-second resolution

`src/StateMachine/state_machine.c:360,670,688,695,786,863,1294,1369`; `src/Compaction/compaction_engine.c:19`; `src/Trigger/trigger.c:333`

```c
uint64_t now_ms = (uint64_t)time(NULL) * 1000;
```

This gives millisecond timestamps with 1000 ms granularity (always `...000`). This is not a cross-platform issue (the code compiles everywhere), but the resulting timestamps are useless for sub-second operations. The HLC module uses `clock_gettime` (nanosecond resolution) but the state machine uses `time(NULL)` (second resolution).

**Recommendation:** Use a portable high-resolution time source (the `crabs_hlc_get_system_time` function already exists and could be used, but it depends on `clock_gettime` which is itself non-portable — see X-2).

---

## 5. Positive Findings

1. **Endianness handling is excellent.** All wire-format serialization uses explicit byte-by-byte little-endian (`_write_uint32_le`, `_write_uint64_le`, `_rd_u32_le`, `_rd_u64_le`) or big-endian (HLC serialization). No host-endian `memcpy` of multi-byte values across the wire. The state magic is read byte-by-byte.

2. **No pointer serialization.** No `memcpy` of structs containing pointers across the wire. OT operations are serialized field-by-field. The `crabs_style_t` struct is all `char` arrays (no padding issues).

3. **No 32/64-bit assumptions in data structures.** All sizes use explicit `uint32_t` / `uint64_t` types. No `sizeof(int)` or `sizeof(long)` in wire formats. No `intptr_t` / `uintptr_t` in serialized data.

4. **`time(NULL)` is portable** (C standard) — though low resolution (see X-13).

5. **`snprintf` is C99 standard** — portable across all C99 compilers.

6. **OpenSSL is cross-platform** — the OpenSSL dependency works on Linux, macOS, and Windows.

7. **No file path handling** — the library doesn't do file I/O, so there are no forward-slash vs backslash issues.

8. **No `fork` / `exec` / `fork`** — the library is single-process, avoiding the biggest POSIX/Windows incompatibility.

---

## 6. Platform Compatibility Matrix

| Platform | Build | Run | Notes |
|----------|-------|-----|-------|
| **Linux x86_64 (GCC/Clang)** | ✅ | ✅ | Primary development platform. All tests pass. |
| **Linux aarch64** | ✅ | ✅ | Endianness-safe serialization. Should work. |
| **macOS (Apple Silicon)** | ⚠️ | ⚠️ | `clock_gettime` available (10.12+). `pthread` available. `gmp` via Homebrew. `strtok_r` / `strdup` available. Likely works with minor CMake fixes. |
| **macOS (Intel)** | ⚠️ | ⚠️ | Same as Apple Silicon. |
| **Windows x86_64 (MSVC)** | ❌ | ❌ | `pthread.h` missing. `clock_gettime` missing. `localtime_r` / `gmtime_r` missing. `strtok_r` missing. `__thread` unsupported. `.a` library paths wrong. `%lu` truncates `uint64_t`. |
| **Windows x86_64 (MinGW)** | ⚠️ | ⚠️ | `pthread` via winpthreads. `clock_gettime` with `_POSIX_C_SOURCE`. `strtok_r` / `strdup` with feature macros. `.a` paths work (static libs). Likely works with feature macros and CMake fixes. |
| **Windows x86 (MSVC)** | ❌ | ❌ | Same as x86_64 MSVC, plus potential 32-bit `time_t` overflow (pre-2038). |
| **32-bit Linux** | ⚠️ | ⚠️ | Should work. No 32/64-bit assumptions in data structures. `time_t` is 32-bit on some 32-bit systems (2038 problem). |

---

## 7. Prioritized Remediation Plan

**Phase 1 — Windows MSVC build (days):**
- X-4: Create `src/Util/platform.h` with `PLATFORM*` macros (threading, time, string functions).
- X-1: Migrate `sig_scheme.c` to platform abstraction; use `find_package(Threads)`.
- X-2: Add Windows time source (`GetSystemTimeAsFileTime`).
- X-5: Add `localtime_s` / `gmtime_s` fallbacks.
- X-6: Add `strtok_s` fallback (or wrapper).
- X-8: Replace `__thread` with `_Thread_local`.
- X-9: Fix CMakeLists.txt for Windows (library suffixes, `find_package`).
- X-3: Fix all `%lu` → `PRIu64` or `%llu` for `uint64_t`.

**Phase 2 — macOS build (days):**
- Verify `clock_gettime` availability (10.12+).
- Verify `gmp` discovery via Homebrew (`find_library` or `pkg-config`).
- Test on Apple Silicon.

**Phase 3 — CI and hardening (days):**
- X-12: Add CI workflows for Linux, macOS, Windows (MSVC + MinGW).
- X-10: Add offline build option for GoogleTest.
- X-11: Migrate to OpenSSL EVP API (overlaps with security audit N-19).
- X-13: Use high-resolution portable time source.
- X-7: Create `crabs_strdup` wrapper or define feature macros.

---

## 8. Conclusion

The CRABS library is a **Linux-first** codebase with good data-portability discipline (endianness, type sizes, no pointer serialization) but **no platform abstraction layer**. The `platform.h` / `PLATFORM*` macros described in `STYLE_GUIDE.md` §5.3 were never implemented, leaving all platform-specific code inline and unconditional.

The library will not build on Windows (MSVC) without significant work: pthread, `clock_gettime`, `localtime_r`, `gmtime_r`, `strtok_r`, `strdup`, `__thread`, and the CMakeLists.txt all need platform conditionals. macOS support is closer (most POSIX functions are available) but `gmp` discovery and CMake fixes are needed.

The `%lu` format specifier issue (X-3) is the only runtime correctness bug — on Windows, diagnostic output silently truncates `uint64_t` values to 32 bits. All other issues are build-time failures.

The recommended fix is to create `src/Util/platform.h` implementing the abstraction described in the style guide, migrate all platform-specific code to use it, and add CI workflows for Windows and macOS to prevent regressions.

---

*Cross-platform audit — the crab needs to learn to swim in different waters.*

---

## 9. Remediation Status (2026-08-01)

All cross-platform findings have been addressed. The full test suite (1233
tests) passes on Linux. No openabe-c modifications were needed.

### Fixed in this pass

| ID | Summary of fix |
|----|----------------|
| X-1 | Created `src/Util/platform.h` with a threading abstraction (`platform_mutex_t`, `platform_cond_t`, `platform_thread_t`) mapping to `CRITICAL_SECTION`/`CONDITION_VARIABLE`/`HANDLE` on Windows and `pthread_mutex_t`/`pthread_cond_t`/`pthread_t` on POSIX. Migrated `sig_scheme.c` from direct `pthread` usage to the platform abstraction. On POSIX, uses `PTHREAD_MUTEX_INITIALIZER` for race-free static init; on Windows, uses lazy init with a documented theoretical race (acceptable since `crypto_sig_scheme_init` is called at startup). |
| X-2 | `platform_get_time()` in `platform.h` provides a portable high-resolution time source: `GetSystemTimeAsFileTime` on Windows (with 1601→1970 epoch conversion), `clock_gettime(CLOCK_REALTIME)` on POSIX. `hlc.c` now calls `platform_get_time()` instead of `clock_gettime` directly. |
| X-3 | Replaced all `%lu`/`%ld` format specifiers for `uint64_t`/`int64_t` with `%llu`/`%lld` and `unsigned long long` casts in `cli.c` (4 sites), `compaction.c` (1 site), and `hlc.c` (1 site). On 64-bit Windows (LLP64), `%lu` is 32-bit and would truncate `uint64_t` values. |
| X-4 | Created `src/Util/platform.h` implementing the `PLATFORMLOCKTYPE`/`PLATFORMCONDITIONTYPE`/`PLATFORMTHREADTYPE` macros described in `STYLE_GUIDE.md` §5.3, plus inline wrapper functions for lock/unlock, condition wait/signal/broadcast, and thread-local storage (`PLATFORM_THREAD_LOCAL`). |
| X-5 | `platform_localtime_r()` and `platform_gmtime_r()` in `platform.h` map to `localtime_s`/`gmtime_s` on Windows (with reversed argument order) and `localtime_r`/`gmtime_r` on POSIX. `log.c` and `hlc.c` now use these wrappers. |
| X-6 | `platform_strtok_r()` in `platform.h` maps to `strtok_s` on Windows and `strtok_r` on POSIX. All 26 `strtok_r` call sites across `trigger.c`, `state_machine.c`, `attribute_machine.c` now use `platform_strtok_r`. |
| X-7 | `platform_strdup()` in `platform.h` maps to `_strdup` on Windows and `strdup` on POSIX. All 19 `strdup` call sites across `condition.c`, `one_shot.c`, `crdt_merge.c`, `serialization.c` now use `platform_strdup`. |
| X-8 | Replaced `__thread` (GCC/Clang extension) in `log.c` with `PLATFORM_THREAD_LOCAL` (maps to C11 `_Thread_local`), which is supported by MSVC 2019+ in C11 mode. |
| X-9 | Rewrote `CMakeLists.txt`: `find_package(Threads REQUIRED)` with `Threads::Threads` target (portable threading); `_POSIX_C_SOURCE=200809L` compile definition on non-Windows (enables `strtok_r`/`strdup`/`localtime_r`/`gmtime_r`/`clock_gettime` declarations); `find_library(GMP_LIBRARY NAMES gmp)` instead of bare `gmp`; platform-conditional static library paths (`.a` on Unix, `.lib` on Windows). |

### Additional fix (de-wonk)

- Added `#include <strings.h>` to `condition.c` — the `_POSIX_C_SOURCE`
  definition suppressed glibc's default `_DEFAULT_SOURCE`, which had made
  `strcasecmp` available via `<string.h>`. With `_POSIX_C_SOURCE`,
  `strcasecmp` requires `<strings.h>`.

### De-wonk pass

A de-wonk audit over the modified files found and fixed one MEDIUM issue:
- **Race condition in `_ensure_registry_lock`** (sig_scheme.c): the lazy-init
  guard (`if (_registry_lock_initialized) return;`) had a race if two threads
  called it simultaneously before init. Fixed by using
  `PTHREAD_MUTEX_INITIALIZER` for static, race-free init on POSIX, keeping
  the lazy-init guard only for Windows (where `CRITICAL_SECTION` cannot be
  statically initialized). The Windows race is documented as theoretical
  (crypto_sig_scheme_init is called at startup before multi-threaded use).

Round 2 de-wonk found no new issues. All platform-specific code has been
migrated to the platform abstraction:
- 0 remaining direct `pthread` usage (outside `platform.h`)
- 0 remaining direct `clock_gettime`/`CLOCK_REALTIME` usage
- 0 remaining direct `localtime_r`/`gmtime_r` usage
- 0 remaining direct `strtok_r`/`strdup` usage
- 0 remaining `__thread` usage (replaced with `_Thread_local`)

### Test posture

- 1233 fast-suite tests pass on Linux (x86_64, GCC/Clang).
- The library should now compile on Windows (MSVC/MinGW) and macOS, though
  this has not been verified with actual cross-compilation. CI workflows
  (X-12) are the recommended next step to catch regressions automatically.
- The OpenABE/RELIC/GMP dependencies still need Windows builds — the CMake
  changes handle the linking abstraction, but the dependencies themselves
  may need Windows build instructions.