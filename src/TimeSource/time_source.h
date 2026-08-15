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
#define CRABS_TIME_SOURCE_DEFAULT_MAX_SKEW_MS 5000

// Result of a single fetch from the time server.
typedef struct {
  uint64_t seconds;   // Unix epoch seconds
  uint64_t nanos;     // Nanosecond component (0-999,999,999)
  bool     valid;     // Whether the fetch succeeded
} crabs_time_source_fetch_result_t;

// Configuration. Pass NULL to use all defaults. A non-NULL config's values
// are used as-is: 0 is a valid value (e.g. resync_interval_ms = 0 means
// re-query on every call).
typedef struct {
  const char* server_url;          // Default: CRABS_TIME_SOURCE_DEFAULT_URL
  uint64_t    resync_interval_ms;  // Default: CRABS_TIME_SOURCE_DEFAULT_RESYNC_MS
  uint64_t    timeout_ms;          // Default: CRABS_TIME_SOURCE_DEFAULT_TIMEOUT_MS
  // R7-18: maximum allowed difference (ms) between a fetched timestamp and the
  // local clock. Fetches outside this bound are rejected. 0 disables the check.
  uint64_t    max_skew_ms;         // Default: CRABS_TIME_SOURCE_DEFAULT_MAX_SKEW_MS
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
