//
// platform.h — Cross-platform abstraction for threading, time, and string
// functions.
//
// This header implements the PLATFORM* macros described in STYLE_GUIDE.md
// §5.3. It abstracts the differences between POSIX (Linux/macOS) and Windows
// (MSVC/MinGW) for:
//   - Mutexes (pthread_mutex_t / CRITICAL_SECTION)
//   - Condition variables (pthread_cond_t / CONDITION_VARIABLE)
//   - Threads (pthread_t / HANDLE)
//   - High-resolution time (clock_gettime / QueryPerformanceCounter)
//   - Reentrant string tokenization (strtok_r / strtok_s)
//   - Thread-safe time conversion (localtime_r / localtime_s, gmtime_r / gmtime_s)
//   - String duplication (strdup / _strdup)
//
// Usage: include this header instead of <pthread.h> or <windows.h> directly.
// Use PLATFORMLOCKTYPE/PLATFORMCONDITIONTYPE/PLATFORMTHREADTYPE for
// declarations, and the platform_lock/platform_unlock/etc. functions for
// operations.
//

#ifndef CRABS_PLATFORM_H
#define CRABS_PLATFORM_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#endif

// ============================================================
// Threading Primitives
// ============================================================

#ifdef _WIN32

#include <windows.h>

typedef CRITICAL_SECTION   platform_mutex_t;
typedef CONDITION_VARIABLE platform_cond_t;
typedef HANDLE             platform_thread_t;

static inline void platform_mutex_init(platform_mutex_t* m) {
  InitializeCriticalSection(m);
}
static inline void platform_mutex_destroy(platform_mutex_t* m) {
  DeleteCriticalSection(m);
}
static inline void platform_mutex_lock(platform_mutex_t* m) {
  EnterCriticalSection(m);
}
static inline void platform_mutex_unlock(platform_mutex_t* m) {
  LeaveCriticalSection(m);
}

static inline void platform_cond_init(platform_cond_t* c) {
  InitializeConditionVariable(c);
}
static inline void platform_cond_destroy(platform_cond_t* c) {
  (void)c; // Windows condition variables don't need destruction
}
static inline void platform_cond_signal(platform_cond_t* c) {
  WakeConditionVariable(c);
}
static inline void platform_cond_broadcast(platform_cond_t* c) {
  WakeAllConditionVariable(c);
}
// Returns 0 on success, non-zero on timeout (matching pthread_cond_timedwait)
static inline int platform_cond_wait(platform_cond_t* c, platform_mutex_t* m) {
  return SleepConditionVariableCS(c, m, INFINITE) ? 0 : 1;
}

#elif defined(__EMSCRIPTEN__)

// WASM is single-threaded by default (no pthreads without -pthread flag +
// SharedArrayBuffer). Mutexes and condition variables are no-ops. This is
// safe because the CRABS state machine is not accessed from multiple threads
// in a single-threaded WASM context.
typedef int platform_mutex_t;
typedef int platform_cond_t;
typedef int platform_thread_t;

static inline void platform_mutex_init(platform_mutex_t* m)   { (void)m; }
static inline void platform_mutex_destroy(platform_mutex_t* m) { (void)m; }
static inline void platform_mutex_lock(platform_mutex_t* m)    { (void)m; }
static inline void platform_mutex_unlock(platform_mutex_t* m)  { (void)m; }
static inline void platform_cond_init(platform_cond_t* c)      { (void)c; }
static inline void platform_cond_destroy(platform_cond_t* c)   { (void)c; }
static inline void platform_cond_signal(platform_cond_t* c)    { (void)c; }
static inline void platform_cond_broadcast(platform_cond_t* c) { (void)c; }
static inline int platform_cond_wait(platform_cond_t* c, platform_mutex_t* m) {
  (void)c; (void)m; return 0;
}

#else // POSIX

#include <pthread.h>

typedef pthread_mutex_t platform_mutex_t;
typedef pthread_cond_t  platform_cond_t;
typedef pthread_t       platform_thread_t;

static inline void platform_mutex_init(platform_mutex_t* m) {
  pthread_mutex_init(m, NULL);
}
static inline void platform_mutex_destroy(platform_mutex_t* m) {
  pthread_mutex_destroy(m);
}
static inline void platform_mutex_lock(platform_mutex_t* m) {
  pthread_mutex_lock(m);
}
static inline void platform_mutex_unlock(platform_mutex_t* m) {
  pthread_mutex_unlock(m);
}

static inline void platform_cond_init(platform_cond_t* c) {
  pthread_cond_init(c, NULL);
}
static inline void platform_cond_destroy(platform_cond_t* c) {
  pthread_cond_destroy(c);
}
static inline void platform_cond_signal(platform_cond_t* c) {
  pthread_cond_signal(c);
}
static inline void platform_cond_broadcast(platform_cond_t* c) {
  pthread_cond_broadcast(c);
}
static inline int platform_cond_wait(platform_cond_t* c, platform_mutex_t* m) {
  return pthread_cond_wait(c, m);
}

#endif // _WIN32

// Style-guide-compliant macros (STYLE_GUIDE.md §5.3)
#define PLATFORMLOCKTYPE(name)      platform_mutex_t name
#define PLATFORMCONDITIONTYPE(name) platform_cond_t  name
#define PLATFORMTHREADTYPE(name)    platform_thread_t name

// ============================================================
// High-Resolution Time
// ============================================================
// Returns seconds + nanoseconds since the Unix epoch (1970-01-01).
// On Windows, uses GetSystemTimeAsFileTime and converts from the Windows
// epoch (1601-01-01) to the Unix epoch.
// On POSIX, uses clock_gettime(CLOCK_REALTIME).

typedef struct {
  uint64_t seconds;
  uint64_t nanos;
  bool     valid;
} platform_time_t;

static inline platform_time_t platform_get_time(void) {
  platform_time_t t = {0, 0, false};

#ifdef _WIN32
  // Windows epoch is 1601-01-01, 11644473600 seconds before Unix epoch.
  // FILETIME is 100ns intervals since 1601.
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  uint64_t intervals = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
  // Convert 100ns intervals to seconds since Unix epoch
  uint64_t unix_100ns = intervals - 116444736000000000ULL;
  t.seconds = unix_100ns / 10000000ULL;           // 100ns intervals → seconds
  t.nanos = (unix_100ns % 10000000ULL) * 100ULL;   // remaining 100ns → nanos
  t.valid = true;
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
    t.seconds = (uint64_t)ts.tv_sec;
    t.nanos = (uint64_t)ts.tv_nsec;
    t.valid = true;
  }
#endif

  return t;
}

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

// ============================================================
// Reentrant String Tokenization
// ============================================================
// POSIX strtok_r and MSVC strtok_s have different signatures. The C11
// standard strtok_s (with rsize_t*) is also different. We provide a wrapper
// with the POSIX signature (strtok_r) that maps to the right function per
// platform.

static inline char* platform_strtok_r(char* str, const char* delim, char** saveptr) {
#ifdef _WIN32
  // MSVC strtok_s has the same signature as POSIX strtok_r when using
  // the 3-argument form (not the C11 standard 4-argument form with rsize_t).
  return strtok_s(str, delim, saveptr);
#else
  return strtok_r(str, delim, saveptr);
#endif
}

// ============================================================
// Thread-Safe Time Conversion
// ============================================================
// POSIX: localtime_r(time_t*, struct tm*) / gmtime_r(time_t*, struct tm*)
// Windows: localtime_s(struct tm*, time_t*) / gmtime_s(struct tm*, time_t*)
// Note the reversed argument order on Windows. Our wrapper uses the POSIX
// argument order (source first, destination second).

static inline struct tm* platform_localtime_r(const time_t* timep, struct tm* result) {
#ifdef _WIN32
  return localtime_s(result, timep) == 0 ? result : NULL;
#else
  return localtime_r(timep, result);
#endif
}

static inline struct tm* platform_gmtime_r(const time_t* timep, struct tm* result) {
#ifdef _WIN32
  return gmtime_s(result, timep) == 0 ? result : NULL;
#else
  return gmtime_r(timep, result);
#endif
}

// ============================================================
// String Duplication
// ============================================================
// strdup is POSIX, not C99/C11 standard. MSVC provides _strdup. C23 makes
// strdup standard. We provide a portable wrapper.

static inline char* platform_strdup(const char* s) {
#ifdef _WIN32
  return _strdup(s);
#else
  return strdup(s);
#endif
}

// ============================================================
// Thread-Local Storage
// ============================================================
// C11 _Thread_local is the standard and is supported by GCC, Clang, and
// MSVC 2019+ in C11 mode. Use _Thread_local everywhere (not __thread).
// The CMakeLists sets CMAKE_C_STANDARD 11, so this is available.

#define PLATFORM_THREAD_LOCAL _Thread_local

#endif // CRABS_PLATFORM_H