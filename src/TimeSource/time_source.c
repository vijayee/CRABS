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
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <limits.h>
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

// Parse "https://host[:port]/path" into host, path, and port. Only the
// "https" scheme is accepted; the port defaults to 443 when omitted.
static bool _parse_url(const char* url, char* host, size_t host_len,
                       char* path, size_t path_len, int* port) {
  if (url == NULL) return false;
  const char* scheme = strstr(url, "://");
  if (scheme == NULL) return false;
  if ((size_t)(scheme - url) != 5 || strncmp(url, "https", 5) != 0) return false;

  const char* host_start = scheme + 3;
  const char* host_end = host_start;
  while (*host_end != '\0' && *host_end != '/' && *host_end != ':') host_end++;
  size_t host_size = (size_t)(host_end - host_start);
  if (host_size == 0 || host_size >= host_len) return false;
  memcpy(host, host_start, host_size);
  host[host_size] = '\0';

  int parsed_port = 443;
  if (*host_end == ':') {
    const char* port_start = host_end + 1;
    const char* port_end = port_start;
    while (*port_end >= '0' && *port_end <= '9') port_end++;
    if (port_end == port_start) return false;          // empty or non-numeric port
    if (*port_end != '\0' && *port_end != '/') return false;  // garbage after port
    if (port_end - port_start > 5) return false;      // max port 65535 is 5 digits
    uint64_t port_value = 0;
    for (const char* digit = port_start; digit < port_end; digit++) {
      port_value = port_value * 10 + (uint64_t)(*digit - '0');
    }
    if (port_value > 65535) return false;
    parsed_port = (int)port_value;
    host_end = port_end;
  }
  *port = parsed_port;

  if (*host_end == '/') {
    snprintf(path, path_len, "%s", host_end);
  } else {
    snprintf(path, path_len, "/");
  }
  return true;
}

// Wait for a non-blocking connect() to complete, bounded by timeout_ms.
// Returns 0 if the socket became writable, -1 on timeout or error.
static int _wait_for_connect(platform_socket_t socket_fd, uint64_t timeout_ms) {
#ifdef _WIN32
  fd_set write_set;
  FD_ZERO(&write_set);
  FD_SET(socket_fd, &write_set);
  struct timeval timeout;
  timeout.tv_sec = (long)(timeout_ms / 1000);
  timeout.tv_usec = (long)((timeout_ms % 1000) * 1000);
  int select_result = select(0, NULL, &write_set, NULL, &timeout);
  if (select_result <= 0) return -1;
  return 0;
#else
  struct pollfd poll_fd;
  poll_fd.fd = socket_fd;
  poll_fd.events = POLLOUT;
  poll_fd.revents = 0;
  int poll_timeout = timeout_ms > (uint64_t)INT_MAX ? INT_MAX : (int)timeout_ms;
  int poll_result = poll(&poll_fd, 1, poll_timeout);
  if (poll_result <= 0) return -1;
  return 0;
#endif
}

static platform_socket_t _tcp_connect(const char* host, int port, uint64_t timeout_ms) {
  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  // Note: getaddrinfo() performs DNS resolution and is not bounded by
  // timeout_ms. A blackholed DNS server can still block here.
  struct addrinfo* addresses = NULL;
  if (getaddrinfo(host, port_str, &hints, &addresses) != 0) {
    return PLATFORM_INVALID_SOCKET;
  }

  platform_socket_t socket_fd = PLATFORM_INVALID_SOCKET;
  for (struct addrinfo* address = addresses; address != NULL; address = address->ai_next) {
    socket_fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (socket_fd == PLATFORM_INVALID_SOCKET) continue;

    // Set the socket non-blocking so connect() can be bounded by timeout_ms.
#ifdef _WIN32
    unsigned long nonblocking = 1;
    ioctlsocket(socket_fd, FIONBIO, &nonblocking);
#else
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags < 0) {
      _platform_close_socket(socket_fd);
      socket_fd = PLATFORM_INVALID_SOCKET;
      continue;
    }
    fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK);
#endif

    int connect_result = connect(socket_fd, address->ai_addr, (int)address->ai_addrlen);
    if (connect_result != 0) {
#ifdef _WIN32
      int connect_error = WSAGetLastError();
      if (connect_error != WSAEWOULDBLOCK) {
        _platform_close_socket(socket_fd);
        socket_fd = PLATFORM_INVALID_SOCKET;
        continue;
      }
#else
      if (errno != EINPROGRESS) {
        _platform_close_socket(socket_fd);
        socket_fd = PLATFORM_INVALID_SOCKET;
        continue;
      }
#endif
      if (_wait_for_connect(socket_fd, timeout_ms) != 0) {
        _platform_close_socket(socket_fd);
        socket_fd = PLATFORM_INVALID_SOCKET;
        continue;
      }
    }

    // Confirm the connection actually succeeded via SO_ERROR.
    int socket_error = 0;
    socklen_t error_len = sizeof(socket_error);
    if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_len) != 0 ||
        socket_error != 0) {
      _platform_close_socket(socket_fd);
      socket_fd = PLATFORM_INVALID_SOCKET;
      continue;
    }

    // Restore blocking mode before returning.
#ifdef _WIN32
    nonblocking = 0;
    ioctlsocket(socket_fd, FIONBIO, &nonblocking);
#else
    fcntl(socket_fd, F_SETFL, flags);
#endif
    break;
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
    int digit_count = 0;
    // Bound the loop to 19 digits so seconds cannot overflow uint64.
    while (*value_start >= '0' && *value_start <= '9' && digit_count < 19) {
      seconds = seconds * 10 + (uint64_t)(*value_start - '0');
      value_start++;
      digit_count++;
    }
    if (digit_count > 0) {
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
    // No digits after "ts=" — not a valid timestamp. Fall through to the
    // unixtime check in case the response also carries a JSON timestamp.
  }

  const char* unixtime_marker = strstr(response, "\"unixtime\"");
  if (unixtime_marker != NULL) {
    const char* colon = strchr(unixtime_marker, ':');
    if (colon != NULL) {
      const char* value_start = colon + 1;
      while (*value_start == ' ' || *value_start == '\t') value_start++;
      uint64_t seconds = 0;
      int digit_count = 0;
      // Bound the loop to 19 digits so seconds cannot overflow uint64.
      while (*value_start >= '0' && *value_start <= '9' && digit_count < 19) {
        seconds = seconds * 10 + (uint64_t)(*value_start - '0');
        value_start++;
        digit_count++;
      }
      if (digit_count > 0) {
        result->seconds = seconds;
        result->nanos = 0;
        result->valid = true;
      }
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

  platform_socket_t socket_fd = _tcp_connect(host, port, timeout_ms);
  if (socket_fd == PLATFORM_INVALID_SOCKET) return result;

  struct timeval timeout;
  timeout.tv_sec = (time_t)(timeout_ms / 1000);
#ifdef _WIN32
  timeout.tv_usec = (long)((timeout_ms % 1000) * 1000);
#else
  timeout.tv_usec = (suseconds_t)((timeout_ms % 1000) * 1000);
#endif
  setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (ssl_ctx == NULL) {
    _platform_close_socket(socket_fd);
    return result;
  }
  // Verify the server certificate against the system CA store and require
  // hostname matching, so a MITM cannot impersonate the time server.
  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_default_verify_paths(ssl_ctx);
  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);

  SSL* ssl = SSL_new(ssl_ctx);
  if (ssl == NULL) {
    SSL_CTX_free(ssl_ctx);
    _platform_close_socket(socket_fd);
    return result;
  }
  if (SSL_set1_host(ssl, host) != 1) {
    SSL_free(ssl);
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
  // Fail closed: even if SSL_connect returned success, require a clean
  // certificate verification result.
  if (SSL_get_verify_result(ssl) != X509_V_OK) {
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
  if (request_len < 0 || request_len >= (int)sizeof(request)) {
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    _platform_close_socket(socket_fd);
    return result;
  }
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
