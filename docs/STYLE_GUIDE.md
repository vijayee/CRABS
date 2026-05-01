# CRABS Style Guide

Adapted from conventions observed in the liboffs codebase.

## 1. Repository & Directory Layout

### Top-Level Structure

```
CRABS/
├── src/            # All source code
├── test/           # Unit tests
├── docs/           # Architecture & standards documentation
├── deps/           # Dependencies
└── CMakeLists.txt  # Root build file
```

### `src/` Module Layout

Each module gets its own PascalCase directory. The directory name is the module name:

```
src/
├── ModuleName/
│   ├── module_name.h    # Public header
│   └── module_name.c    # Implementation
```

For sub-components within a module:

```
src/ModuleName/
├── module_name.h
├── module_name.c
├── sub_component.h
└── sub_component.c
```

### Test Layout

Tests live in `test/` and mirror module names:

```
test/
├── CMakeLists.txt
├── test_main.cpp
├── test_module.cpp
└── ...
```

## 2. Naming Conventions

### 2.1 Types

`snake_case` with a `_t` suffix:

```c
typedef struct {
  uint16_t count;
  uint8_t yield;
} refcounter_t;
```

### 2.2 Enums

`snake_case` values with a `_e` suffix on the type:

```c
typedef enum {
  readable_stream = 0,
  writeable_stream = 1
} stream_type_e;
```

Use explicit integer values where they carry semantic meaning.

### 2.3 Functions

`module_action()` pattern — lowercase snake_case matching the filename:

```c
// Creation / destruction
block_t*      block_create(buffer_t* data);
void          block_destroy(block_t* block);

// Actions
void          stream_init(stream_t* stream);

// Queries
uint16_t      refcounter_count(refcounter_t* refcounter);
```

Private / internal functions use a leading underscore:

```c
void _block_cache_get(block_cache_get_ctx* ctx);
```

### 2.4 Macros

`UPPER_CASE` with underscores:

```c
#define REFERENCE(N, T)   (T*) refcounter_reference((refcounter_t*) N)
#define DESTROY(N, T)     T##_destroy(N); N = NULL
#define DEFAULT_CHUNK_SIZE 128000
```

### 2.5 Includes

Order: own header first, then project headers by module, then system headers.

```c
// In src/ModuleName/module_name.c:
#include "module_name.h"
#include "../OtherModule/other.h"
#include <stdlib.h>
```

Local headers use quotes `""`. System headers use angle brackets `<>`.

## 3. File Conventions

### 3.1 Header Guards

```c
#ifndef CRABS_MODULE_NAME_H
#define CRABS_MODULE_NAME_H

#include <stdint.h>

// ... declarations ...

#endif // CRABS_MODULE_NAME_H
```

### 3.2 Source Files

Every `.c` file includes its own `.h` first.

### 3.3 File Headers

```c
//
// Created by victor on 3/30/25.
//
```

Third-party files retain their original copyright headers.

## 4. Formatting & Style

- **2-space indentation**, no tabs.
- Opening braces on the same line (Egyptian style).
- Single space between `if`/`while`/`for` and the opening parenthesis.
- Pointer `*` next to the variable name: `block_t* block` not `block_t *block`.
- Variables declared one per line at top of block scope.
- Prefer early returns over deep nesting.

```c
void pool_shutdown(pool_t* pool) {
  platform_lock(&pool->lock);
  pool->stop = 1;
  platform_broadcast_condition(&pool->condition);
  platform_unlock(&pool->lock);
}
```

## 5. Core Patterns

### 5.1 Reference Counting

Embed `refcounter_t` as the first member of every heap-allocated shared object:

```c
typedef struct {
  refcounter_t refcounter;
  uint8_t* data;
  size_t size;
} buffer_t;

buffer_t* buffer_create(size_t size) {
  buffer_t* buf = get_clear_memory(sizeof(buffer_t));
  buf->data = get_clear_memory(size);
  buf->size = size;
  refcounter_init((refcounter_t*) buf);
  return buf;
}
```

Destructor pattern:

```c
void buffer_destroy(buffer_t* buf) {
  refcounter_dereference((refcounter_t*) buf);
  if (refcounter_count((refcounter_t*) buf) == 0) {
    free(buf->data);
    free(buf);
  }
}
```

Ownership macros:

| Macro | Effect |
|-------|--------|
| `REFERENCE(obj, T)` | Increment refcount, return typed pointer |
| `YIELD(obj)` | Transfer ownership without incrementing |
| `DESTROY(obj, T)` | Call destructor, null out pointer |
| `CONSUME(obj, T)` | Claim ownership from a yielded reference |

### 5.2 Memory Allocation

Use wrappers, never raw `malloc`/`calloc`:

```c
void* ptr = get_memory(size);         // aborts on OOM
void* ptr = get_clear_memory(size);   // zero-initialized, aborts on OOM
```

### 5.3 Platform Abstraction

Abstract platform-specific types behind macros in a central `platform.h`:

```c
PLATFORMLOCKTYPE(lock);           // pthread_mutex_t / CRITICAL_SECTION
PLATFORMCONDITIONTYPE(cond);      // pthread_cond_t / CONDITION_VARIABLE
PLATFORMTHREADTYPE thread;        // pthread_t / HANDLE
```

Platform-conditional blocks inline with `#ifdef _WIN32` / `#else`:

```c
#ifdef _WIN32
  pool->workers[i] = CreateThread(NULL, 0, workerFunction, pool, 0, &pool->workerIds[i]);
#else
  pthread_create(&pool->workers[i], NULL, (void*)workerFunction, pool);
#endif
```

### 5.4 Async Work / Promise Pattern

Context struct + work item + promise:

```c
typedef struct {
  cache_t* cache;
  buffer_t* hash;
  promise_t* promise;
} cache_get_ctx;

void cache_get(cache_t* cache, buffer_t* hash, promise_t* promise) {
  cache_get_ctx* ctx = get_memory(sizeof(cache_get_ctx));
  ctx->promise = promise;
  ctx->cache = cache;
  ctx->hash = REFERENCE(hash, buffer_t);
  work_t* work = work_create(ctx, (void*)_cache_get, (void*)_cache_get_abort);
  work_pool_enqueue(cache->pool, CONSUME(work, work_t));
}

void _cache_get(cache_get_ctx* ctx) {
  // ... do work ...
  promise_resolve(ctx->promise, result);
  free(ctx);
}

void _cache_get_abort(cache_get_ctx* ctx) {
  promise_reject(ctx->promise, ERROR("Aborted"));
  free(ctx);
}
```

### 5.5 Error Handling

Error macro that captures file, function, and line:

```c
#define ERROR(MESSAGE) error_create(MESSAGE, (char*)__FILE__, (char*)__func__, __LINE__)

// Usage:
stream_notify(stream, error_event, ERROR("Stream is already destroyed"));
```

### 5.6 Lock Ordering

Establish and document a global lock ordering to prevent deadlocks:

1. Cache lock
2. Index lock
3. Section lock
4. LRU cache lock

## 6. Tests

C++ with GoogleTest. C headers wrapped in `extern "C"`:

```cpp
#include <gtest/gtest.h>
extern "C" {
#include "../src/ModuleName/module_name.h"
}
```

Test naming: `TEST(TestModule, TestFunction_Scenario)`.

`ASSERT_*` for fatal assertions, `EXPECT_*` for non-fatal.

## 7. Summary

| Concern | Convention |
|---------|-----------|
| Source root | `src/ModuleName/module_name.c` |
| Public header | `src/ModuleName/module_name.h` |
| Type naming | `snake_case_t` |
| Enum naming | `snake_case_e` |
| Function naming | `module_action()` |
| Private functions | `_function_name()` |
| Macros | `UPPER_CASE` |
| Include guard | `#ifndef CRABS_MODULE_NAME_H` |
| Indentation | 2 spaces, no tabs |
| Brace style | Egyptian (same line) |
| Memory allocation | `get_memory()` / `get_clear_memory()` |
| Object lifecycle | `_create()` → refcounted → `_destroy()` |
| Ownership macros | `REFERENCE`, `YIELD`, `DESTROY`, `CONSUME` |
| Platform abstraction | `PLATFORM*` macros |
| Test framework | GoogleTest, `extern "C"` wrappers |