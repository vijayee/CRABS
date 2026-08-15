# HTTPS Time Source for HLC (authenticated time via HTTPS)

## Goal

Add an optional, pluggable authenticated time source to CRABS HLC that fetches time from a public HTTPS time API, caches it, and interpolates elapsed time with a monotonic clock. This replaces the spec's deprecated autokey-NTP design (v1.6 Amendment 6 §7.2) with a mechanism that works on native, browser WASM, and Node WASM, and provides TLS server authentication + response integrity.

## Background

- HLC already defines the integration point: `crabs_time_source_ops_t` vtable (`src/HLC/hlc.h:72`) and the `CRABS_TIME_SOURCE_NTP_AUTH` enum value (`src/HLC/hlc.h:56`). `crabs_hlc_get_physical_time()` (`src/HLC/hlc.c:264`) checks `time_source_ops` before falling back to the system clock.
- The spec's original "Authenticated NTP" used autokey (RFC 5906), which is deprecated/obsolete and unsupported by modern servers.
- The library has no networking code today. `platform.h` handles wall-clock time but has no monotonic clock and no sockets.
- The WASM build (`build_wasm.sh`) compiles all of `src/` with emcc; browsers cannot open UDP or raw TCP sockets, so NTP/NTS are impossible in the browser.

## Requirements

1. **Optional.** Default behavior is unchanged: HLC uses the system clock. No new dependencies, no network, no behavior change for existing users.
2. **Highest security the architecture can muster.** TLS server authentication + response integrity (the same guarantee class as NTS, RFC 8915). Sub-millisecond precision is explicitly not required; 10–100ms is acceptable.
3. **Works on all three platforms** — native (Linux/macOS/Windows), browser WASM, Node WASM — through one shared code path.
4. **Lazy caching.** The server is queried at most once per resync interval, and only when HLC actually generates a timestamp. Between syncs, elapsed time comes from a monotonic clock.
5. **Defaults to a public server**, with a caller-supplied override.
6. **Tested against a real public server** (network-gated integration test).
7. **No single-letter variables** in any new code.

## Architecture

### New module `src/TimeSource/`

- **`time_source.h`** — public API:
  - `crabs_time_source_ops_t* crabs_time_source_https_create(const crabs_time_source_config_t* config)`
  - `void crabs_time_source_destroy(crabs_time_source_ops_t* ops)`
  - `crabs_time_source_config_t` — `server_url`, `resync_interval_ms`, `timeout_ms`
- **`time_source.c`** — the backend: owns the lazy-TTL cache, the elapsed math, and the vtable (`get_time`/`is_available`/`ctx`).
- **Transport seam** — one function: `crabs_time_source_fetch_result_t fetch_server_time(const char* url, uint64_t timeout_ms)`. This is the only per-platform code.

### Platform additions

- **`src/Util/platform.h`**: add `platform_get_monotonic()` returning `{seconds, nanos, valid}`:
  - POSIX: `CLOCK_MONOTONIC`
  - Browser WASM: `performance.now()` (via imported JS shim)
  - Node WASM: `process.hrtime()` (via imported JS shim)
- **Native transport**: OpenSSL TLS + minimal HTTP/1.1 GET. No new dependency — OpenSSL is already linked.
- **Browser transport**: imported JS `fetchTime()` shim using `fetch()`.
- **Node transport**: imported JS shim using the `https` module.

### Wiring into HLC

No changes to HLC's core. The caller opts in by creating the backend and assigning `state->time_source_ops`. `crabs_hlc_get_physical_time()` picks it up automatically.

Add `CRABS_TIME_SOURCE_HTTPS_AUTH` to the `crabs_time_source_e` enum so the enum and the backend line up. The existing `CRABS_TIME_SOURCE_NTP_AUTH` value remains for compatibility.

## Backend mechanism

```
get_time(ctx):
  if monotonic_now - anchor_monotonic < resync_interval_ms:
      return anchor + (monotonic_now - anchor_monotonic)   # no network
  else:
      fetched = fetch_server_time(server_url, timeout_ms)   # one HTTPS GET
      if fetched.valid:
          anchor = fetched
          anchor_monotonic = monotonic_now
          return fetched
      else:
          log_warning("time source unreachable; using system clock")
          return system_clock()                            # fallback per spec §7.2
```

- **`is_available(ctx)`** returns true if a sync has succeeded (a valid anchor is held).
- **Offset math**: the HTTPS response's server timestamp plus `RTT/2` gives the anchor; the monotonic clock carries elapsed time between syncs.
- The elapsed computation must use the monotonic clock, never the wall clock, so OS time adjustments cannot corrupt it.

## Configuration

| Field | Default | Notes |
|---|---|---|
| `server_url` | `https://cloudflare.com/cdn-cgi/trace` | Public, ms resolution, TLS 1.3, no API key. Caller may override. |
| `resync_interval_ms` | `30000` | Matches the spec's `trusted_resync_ms` default. |
| `timeout_ms` | `1000` | Matches the spec's `timeout_ms=1000`. |

## Optionality

- Default: `crabs_hlc_state_init()` sets `time_source_ops = NULL` → HLC uses the system clock, exactly as today.
- Opt-in: create the backend, assign `state->time_source_ops`. That is the entire activation.

## Error handling

- HTTPS query fails (timeout, DNS, TLS error, bad response) → log a warning, return the system clock for that call, and keep the last valid anchor if one exists.
- `is_available()` → true only if a sync has succeeded; lets callers detect "no authenticated time" before relying on it.

## Testing

### Unit tests (no network)

Inject a fake `fetch_server_time` and verify:
- Fresh cache returns `anchor + elapsed` with zero transport calls.
- Stale cache triggers exactly one transport call.
- Failed transport call falls back to the system clock and keeps the last valid anchor.
- Resync interval boundary behavior (just under vs. just over the interval).
- Monotonic elapsed math across the resync boundary.

### Integration test (network-gated)

Performs a real HTTPS query against a public server. Skips cleanly when offline so CI without network does not fail, but runs in normal dev/CI.
- Primary server: Cloudflare trace endpoint (`https://cloudflare.com/cdn-cgi/trace`).
- Secondary server: `worldtimeapi.org` (verifies the transport handles a JSON response, not just the trace text format).
- Assertions:
  - `valid == true`.
  - Returned time is within ±5s of the local clock (matching HLC's default `max_skew_ms`).
  - A second call within the resync interval returns elapsed time without a new network round-trip.

## Files changed

- `src/TimeSource/time_source.h` (new)
- `src/TimeSource/time_source.c` (new)
- `src/Util/platform.h` (add `platform_get_monotonic()`)
- `src/HLC/hlc.h` (add `CRABS_TIME_SOURCE_HTTPS_AUTH` enum value)
- `test/` (unit tests + network-gated integration test)
- `CMakeLists.txt` (glob picks up new sources automatically)
- `build_wasm.sh` (export/import the transport shim for browser/Node)
