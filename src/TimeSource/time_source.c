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

// Native HTTPS transport (OpenSSL). Guarded so the WASM build (which cannot
// open sockets) does not compile it.
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
