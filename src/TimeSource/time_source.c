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
  // A non-NULL config's values are used as-is (0 is a valid value, e.g.
  // resync_interval_ms = 0 means "always re-query"). Defaults apply only
  // when the whole config is NULL.
  context->resync_interval_ms = (config != NULL)
      ? config->resync_interval_ms : CRABS_TIME_SOURCE_DEFAULT_RESYNC_MS;
  context->timeout_ms = (config != NULL)
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
