//
// Created by victor on 5/2/25.
//
// Hybrid Logical Clock (v1.6 Amendment 6)
// Physical-time-anchored ordering with attack mitigation.
//

#include "hlc.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

// ============================================================
// HLC Initialization (v1.6 Amd6 §3)
// ============================================================

void crabs_hlc_state_init(crabs_hlc_state_t* state, const char* node_id) {
  if (state == NULL) return;
  memset(state, 0, sizeof(crabs_hlc_state_t));

  if (node_id != NULL) {
    strncpy(state->last.node_id, node_id, CRABS_HLC_NODE_ID_SIZE - 1);
    state->last.node_id[CRABS_HLC_NODE_ID_SIZE - 1] = '\0';
  }

  state->time_source = CRABS_TIME_SOURCE_SYSTEM_CLOCK;
  state->receive_strategy = HLC_STRATEGY_BOUNDED;
  state->max_skew_ms = CRABS_HLC_DEFAULT_MAX_SKEW_MS;
  state->quorum_size = CRABS_HLC_DEFAULT_QUORUM_SIZE;
  state->quorum_timeout_ms = CRABS_HLC_DEFAULT_QUORUM_TIMEOUT_MS;
  state->trusted_resync_ms = CRABS_HLC_DEFAULT_TRUSTED_RESYNC_MS;
  state->strict_mode = false;
  state->time_source_ops = NULL;
}

void crabs_hlc_state_init_strategy(crabs_hlc_state_t* state,
                                    const char* node_id,
                                    crabs_hlc_strategy_e strategy) {
  crabs_hlc_state_init(state, node_id);
  state->receive_strategy = strategy;

  switch (strategy) {
    case HLC_STRATEGY_NAIVE:
      // No additional config needed
      break;
    case HLC_STRATEGY_BOUNDED:
      // Defaults already set
      break;
    case HLC_STRATEGY_QUORUM:
      state->quorum_size = CRABS_HLC_DEFAULT_QUORUM_SIZE;
      state->quorum_timeout_ms = CRABS_HLC_DEFAULT_QUORUM_TIMEOUT_MS;
      break;
    case HLC_STRATEGY_STRICT:
      state->strict_mode = true;
      break;
    case HLC_STRATEGY_TRUSTED:
      state->trusted_resync_ms = CRABS_HLC_DEFAULT_TRUSTED_RESYNC_MS;
      break;
  }
}

void crabs_ordering_config_init(crabs_ordering_config_t* config) {
  if (config == NULL) return;
  memset(config, 0, sizeof(crabs_ordering_config_t));
  config->ordering_system = CRABS_ORDERING_LAMPORT;
}

void crabs_ordering_config_init_hlc(crabs_ordering_config_t* config,
                                     crabs_hlc_strategy_e strategy) {
  if (config == NULL) return;
  memset(config, 0, sizeof(crabs_ordering_config_t));
  config->ordering_system = CRABS_ORDERING_HLC;

  config->hlc.receive_strategy = strategy;
  config->hlc.max_skew_ms = CRABS_HLC_DEFAULT_MAX_SKEW_MS;
  config->hlc.quorum_size = CRABS_HLC_DEFAULT_QUORUM_SIZE;
  config->hlc.quorum_timeout_ms = CRABS_HLC_DEFAULT_QUORUM_TIMEOUT_MS;
  config->hlc.strict_mode = (strategy == HLC_STRATEGY_STRICT);
  config->hlc.trusted_time_source = (strategy == HLC_STRATEGY_TRUSTED);
  config->hlc.trusted_resync_ms = CRABS_HLC_DEFAULT_TRUSTED_RESYNC_MS;
}

// ============================================================
// HLC Comparison (v1.6 Amd6 §2.2)
// ============================================================

int crabs_hlc_compare(const crabs_hlc_t* a, const crabs_hlc_t* b) {
  if (a == NULL && b == NULL) return 0;
  if (a == NULL) return -1;
  if (b == NULL) return 1;

  // Compare physical seconds
  if (a->physical_seconds < b->physical_seconds) return -1;
  if (a->physical_seconds > b->physical_seconds) return 1;

  // Compare nanoseconds
  if (a->physical_nanos < b->physical_nanos) return -1;
  if (a->physical_nanos > b->physical_nanos) return 1;

  // Compare logical counter (same-nanosecond events)
  if (a->logical_counter < b->logical_counter) return -1;
  if (a->logical_counter > b->logical_counter) return 1;

  // Tiebreaker: node_id (lexicographic)
  return strcmp(a->node_id, b->node_id);
}

// ============================================================
// HLC Formatting (v1.6 Amd6 §2.3)
// ============================================================

int crabs_hlc_format(const crabs_hlc_t* hlc, char* buf, size_t buf_len) {
  if (hlc == NULL || buf == NULL || buf_len == 0) return -1;

  time_t sec = (time_t)hlc->physical_seconds;
  struct tm tm;
  if (gmtime_r(&sec, &tm) == NULL) return -1;

  int written = snprintf(buf, buf_len,
    "%04d-%02d-%02dT%02d:%02d:%02d.%09lu#%lu@%s",
    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
    tm.tm_hour, tm.tm_min, tm.tm_sec,
    (unsigned long)hlc->physical_nanos,
    (unsigned long)hlc->logical_counter,
    hlc->node_id);

  if (written < 0 || (size_t)written >= buf_len) {
    return -1;
  }

  return written;
}

// ============================================================
// HLC Normalization (v1.6 Amd6 §8.2)
// ============================================================

void crabs_hlc_normalize(crabs_hlc_t* hlc) {
  if (hlc == NULL) return;

  const uint64_t NANOS_PER_SEC = 1000000000ULL;

  while (hlc->physical_nanos >= NANOS_PER_SEC) {
    hlc->physical_seconds += 1;
    hlc->physical_nanos -= NANOS_PER_SEC;
  }
}

// ============================================================
// HLC Lock Integration (v1.6 Amd6 §8)
// ============================================================

int crabs_hlc_lock_priority(const crabs_hlc_t* lock_a, const crabs_hlc_t* lock_b) {
  // Earlier timestamp wins (first-come, first-served)
  return crabs_hlc_compare(lock_a, lock_b);
}

crabs_hlc_t crabs_hlc_add_duration(crabs_hlc_t hlc, uint64_t duration_ms) {
  // Split duration into seconds + nanos to avoid uint64 overflow
  uint64_t add_seconds = duration_ms / 1000ULL;
  uint64_t add_nanos = (duration_ms % 1000ULL) * 1000000ULL;

  // Audit M-N: saturating add. Without this, a huge/attacker-chosen duration
  // wraps physical_seconds to a small value, inverting lock-expiry comparisons
  // (an active lock would read as expired, or vice versa).
  if (hlc.physical_seconds > UINT64_MAX - add_seconds) {
    hlc.physical_seconds = UINT64_MAX;
    hlc.physical_nanos = 999999999ULL;
    return hlc;
  }
  hlc.physical_seconds += add_seconds;
  // Cap the nano carry so normalize's +1 cannot overflow physical_seconds.
  if (hlc.physical_nanos + add_nanos >= 1000000000ULL) {
    if (hlc.physical_seconds == UINT64_MAX) {
      hlc.physical_nanos = 999999999ULL;
      return hlc;
    }
  }
  hlc.physical_nanos += add_nanos;
  crabs_hlc_normalize(&hlc);
  return hlc;
}

bool crabs_hlc_lock_expired(crabs_hlc_state_t* state,
                              const crabs_hlc_t* acquired_at,
                              uint64_t duration_ms) {
  if (state == NULL || acquired_at == NULL) return true;

  crabs_hlc_t now = crabs_hlc_next(state);
  crabs_hlc_t expiry = crabs_hlc_add_duration(*acquired_at, duration_ms);

  return crabs_hlc_compare(&now, &expiry) > 0;
}

// ============================================================
// HLC Difference (v1.6 Amd6 §4.2)
// ============================================================

int64_t crabs_hlc_diff_ms(const crabs_hlc_t* hlc,
                           uint64_t ref_seconds, uint64_t ref_nanos) {
  if (hlc == NULL) return 0;

  // Convert each side to milliseconds with saturating arithmetic. The
  // naive `seconds * 1000` wraps modulo 2^64 for attacker-chosen seconds
  // (>= ~2^54), which can make an aeons-future timestamp appear within
  // max_skew of local time and bypass the BOUNDED strategy.
  const uint64_t MAX_SEC_BEFORE_OVERFLOW = (uint64_t)INT64_MAX / 1000ULL;
  int64_t hlc_ms;
  if (hlc->physical_seconds > MAX_SEC_BEFORE_OVERFLOW) {
    hlc_ms = INT64_MAX;
  } else {
    uint64_t sec_ms = hlc->physical_seconds * 1000ULL;
    uint64_t ns_ms = hlc->physical_nanos / 1000000ULL;
    if (sec_ms > (uint64_t)INT64_MAX - ns_ms) {
      hlc_ms = INT64_MAX;
    } else {
      hlc_ms = (int64_t)(sec_ms + ns_ms);
    }
  }
  int64_t ref_ms;
  if (ref_seconds > MAX_SEC_BEFORE_OVERFLOW) {
    ref_ms = INT64_MAX;
  } else {
    uint64_t sec_ms = ref_seconds * 1000ULL;
    uint64_t ns_ms = ref_nanos / 1000000ULL;
    if (sec_ms > (uint64_t)INT64_MAX - ns_ms) {
      ref_ms = INT64_MAX;
    } else {
      ref_ms = (int64_t)(sec_ms + ns_ms);
    }
  }

  // Saturating subtraction.
  if (hlc_ms == INT64_MAX && ref_ms != INT64_MAX) return INT64_MAX;
  if (ref_ms == INT64_MAX && hlc_ms != INT64_MAX) return INT64_MIN;
  if (hlc_ms == INT64_MAX && ref_ms == INT64_MAX) return 0;
  return hlc_ms - ref_ms;
}

// ============================================================
// Physical Time Source (v1.6 Amd6 §7)
// ============================================================

crabs_physical_time_t crabs_hlc_get_system_time(void* ctx) {
  (void)ctx;
  crabs_physical_time_t result = {0, 0, false};

  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    return result;
  }

  result.seconds = (uint64_t)ts.tv_sec;
  result.nanos = (uint64_t)ts.tv_nsec;
  result.valid = true;
  return result;
}

crabs_physical_time_t crabs_hlc_get_physical_time(crabs_hlc_state_t* state) {
  if (state == NULL) {
    crabs_physical_time_t empty = {0, 0, false};
    return empty;
  }

  // Use custom time source ops if available
  if (state->time_source_ops != NULL &&
      state->time_source_ops->get_time != NULL) {
    return state->time_source_ops->get_time(state->time_source_ops->ctx);
  }

  // Fall back to system clock based on configured source
  switch (state->time_source) {
    case CRABS_TIME_SOURCE_SYSTEM_CLOCK:
    case CRABS_TIME_SOURCE_NTP_AUTH:
    case CRABS_TIME_SOURCE_TPM:
    case CRABS_TIME_SOURCE_CONSENSUS:
      // All non-system sources fall back to system clock for now
      // (NTP, TPM, and consensus require external infrastructure)
      return crabs_hlc_get_system_time(NULL);
    default:
      return crabs_hlc_get_system_time(NULL);
  }
}

// ============================================================
// HLC Generation (v1.6 Amd6 §4.1)
// ============================================================

// Audit M-N: saturating increment. The HLC logical counter must never wrap
// to 0 — that would regress the clock and allow duplicate timestamps. Cap
// at UINT64_MAX instead of +1 when already at the maximum.
static uint64_t _hlc_saturate_inc(uint64_t v) {
  return (v == UINT64_MAX) ? UINT64_MAX : v + 1;
}

crabs_hlc_t crabs_hlc_next(crabs_hlc_state_t* state) {
  crabs_hlc_t hlc = {0, 0, 0, {'\0'}};

  if (state == NULL) return hlc;

  // Get physical time
  crabs_physical_time_t now = crabs_hlc_get_physical_time(state);

  // Copy node_id
  strncpy(hlc.node_id, state->last.node_id, CRABS_HLC_NODE_ID_SIZE);
  hlc.node_id[CRABS_HLC_NODE_ID_SIZE - 1] = '\0';

  if (!now.valid) {
    // Fallback: use last known time + increment counter
    hlc.physical_seconds = state->last.physical_seconds;
    hlc.physical_nanos = state->last.physical_nanos;
    hlc.logical_counter = _hlc_saturate_inc(state->last.logical_counter);
    state->last = hlc;
    return hlc;
  }

  // Compare with last timestamp (HLC_NEXT algorithm)
  if (now.seconds < state->last.physical_seconds ||
      (now.seconds == state->last.physical_seconds &&
       now.nanos < state->last.physical_nanos)) {
    // Physical clock regressed
    state->clock_regressions_detected += 1;

    // Use last physical time + increment logical counter
    hlc.physical_seconds = state->last.physical_seconds;
    hlc.physical_nanos = state->last.physical_nanos;
    hlc.logical_counter = _hlc_saturate_inc(state->last.logical_counter);

  } else if (now.seconds == state->last.physical_seconds &&
             now.nanos == state->last.physical_nanos) {
    // Same physical time as last event
    hlc.physical_seconds = now.seconds;
    hlc.physical_nanos = now.nanos;
    hlc.logical_counter = _hlc_saturate_inc(state->last.logical_counter);

  } else {
    // Physical time advanced normally
    hlc.physical_seconds = now.seconds;
    hlc.physical_nanos = now.nanos;
    hlc.logical_counter = 0;
  }

  state->last = hlc;
  return hlc;
}

// ============================================================
// HLC Receive (v1.6 Amd6 §4.2, §5)
// ============================================================

crabs_hlc_receive_result_e crabs_hlc_receive(crabs_hlc_state_t* state,
                                               const crabs_hlc_t* received) {
  if (state == NULL || received == NULL) {
    return CRABS_HLC_REJECTED_SKEW;
  }

  // Step 1: Validate based on strategy
  switch (state->receive_strategy) {
    case HLC_STRATEGY_NAIVE:
      // Accept everything blindly
      break;

    case HLC_STRATEGY_BOUNDED: {
      crabs_physical_time_t local = crabs_hlc_get_physical_time(state);
      if (!local.valid) {
        // Can't verify without local time, reject
        return CRABS_HLC_REJECTED_SKEW;
      }

      int64_t skew_ms = crabs_hlc_diff_ms(received, local.seconds, local.nanos);

      if (skew_ms > (int64_t)state->max_skew_ms) {
        // Received timestamp too far in the future
        state->time_travel_attempts_rejected += 1;
        return CRABS_HLC_REJECTED_SKEW;
      }

      if (skew_ms < -(int64_t)state->max_skew_ms) {
        // Received timestamp too far in the past
        state->time_travel_attempts_rejected += 1;
        return CRABS_HLC_REJECTED_SKEW;
      }
      break;
    }

    case HLC_STRATEGY_QUORUM:
      // Quorum requires network confirmation from other nodes, which is not
      // implemented. Fail closed: reject rather than accept blindly (the
      // prior stub accepted every timestamp, providing no time-travel
      // protection while implying it did).
      state->quorum_failures += 1;
      return CRABS_HLC_REJECTED_SKEW;

    case HLC_STRATEGY_STRICT:
      // Accept message for ordering but never update local clock
      return CRABS_HLC_ACCEPTED_STRICT;

    case HLC_STRATEGY_TRUSTED:
      // Trusted requires an authenticated/verified time source, which is
      // not implemented. Fail closed: reject rather than accept blindly.
      state->time_travel_attempts_rejected += 1;
      return CRABS_HLC_REJECTED_SKEW;
  }

  // Step 2: Check strict mode
  if (state->strict_mode) {
    return CRABS_HLC_ACCEPTED_STRICT;
  }

  // Step 3: Update local HLC (max rule)
  crabs_physical_time_t local = crabs_hlc_get_physical_time(state);

  // Take max of local physical time and received time
  uint64_t max_sec, max_ns;
  if (received->physical_seconds > local.seconds ||
      (received->physical_seconds == local.seconds &&
       received->physical_nanos > local.nanos)) {
    max_sec = received->physical_seconds;
    max_ns = received->physical_nanos;
  } else {
    max_sec = local.seconds;
    max_ns = local.nanos;
  }

  // Update local HLC
  if (max_sec > state->last.physical_seconds ||
      (max_sec == state->last.physical_seconds &&
       max_ns > state->last.physical_nanos)) {
    // Max is ahead of last — reset counter
    state->last.physical_seconds = max_sec;
    state->last.physical_nanos = max_ns;
    state->last.logical_counter = 0;
  } else if (max_sec == state->last.physical_seconds &&
             max_ns == state->last.physical_nanos) {
    // Same time — take max of counters
    uint64_t max_counter = state->last.logical_counter;
    if (received->logical_counter > max_counter) {
      max_counter = received->logical_counter;
    }
    state->last.logical_counter = _hlc_saturate_inc(max_counter);
  }
  // else: max is behind last, keep last as-is (shouldn't happen normally)

  return CRABS_HLC_ACCEPTED;
}

// ============================================================
// HLC Serialization (v1.6 Amd6 §9)
// ============================================================

size_t crabs_hlc_serialize(const crabs_hlc_t* hlc, uint8_t* buf, size_t buf_len) {
  if (hlc == NULL || buf == NULL) return 0;

  // Calculate node_id length (without null terminator)
  size_t node_id_len = strlen(hlc->node_id);
  size_t total_len = 8 + 8 + 8 + 2 + node_id_len;  // 26 + node_id

  if (buf_len < total_len) return 0;

  // Validate nanos
  if (hlc->physical_nanos >= 1000000000ULL) return 0;

  size_t offset = 0;

  // physical_seconds (8 bytes, big-endian)
  for (int i = 7; i >= 0; i--) {
    buf[offset++] = (uint8_t)(hlc->physical_seconds >> (i * 8));
  }

  // physical_nanos (8 bytes, big-endian)
  for (int i = 7; i >= 0; i--) {
    buf[offset++] = (uint8_t)(hlc->physical_nanos >> (i * 8));
  }

  // logical_counter (8 bytes, big-endian)
  for (int i = 7; i >= 0; i--) {
    buf[offset++] = (uint8_t)(hlc->logical_counter >> (i * 8));
  }

  // node_id_length (2 bytes, big-endian)
  buf[offset++] = (uint8_t)(node_id_len >> 8);
  buf[offset++] = (uint8_t)(node_id_len & 0xFF);

  // node_id (variable length)
  memcpy(buf + offset, hlc->node_id, node_id_len);
  offset += node_id_len;

  return offset;
}

size_t crabs_hlc_deserialize(crabs_hlc_t* hlc, const uint8_t* data, size_t data_len) {
  if (hlc == NULL || data == NULL) return 0;

  // Minimum: 8 + 8 + 8 + 2 = 26 bytes (with empty node_id)
  if (data_len < 26) return 0;

  memset(hlc, 0, sizeof(crabs_hlc_t));

  size_t offset = 0;

  // physical_seconds (8 bytes, big-endian)
  hlc->physical_seconds = 0;
  for (int i = 0; i < 8; i++) {
    hlc->physical_seconds = (hlc->physical_seconds << 8) | data[offset++];
  }

  // physical_nanos (8 bytes, big-endian)
  hlc->physical_nanos = 0;
  for (int i = 0; i < 8; i++) {
    hlc->physical_nanos = (hlc->physical_nanos << 8) | data[offset++];
  }

  // logical_counter (8 bytes, big-endian)
  hlc->logical_counter = 0;
  for (int i = 0; i < 8; i++) {
    hlc->logical_counter = (hlc->logical_counter << 8) | data[offset++];
  }

  // Validate nanos
  if (hlc->physical_nanos >= 1000000000ULL) return 0;

  // node_id_length (2 bytes, big-endian)
  uint16_t node_id_len = ((uint16_t)data[offset] << 8) | data[offset + 1];
  offset += 2;

  // Validate node_id_length
  if (node_id_len >= CRABS_HLC_NODE_ID_SIZE) return 0;

  // Check remaining data
  if (data_len < offset + node_id_len) return 0;

  // node_id
  memcpy(hlc->node_id, data + offset, node_id_len);
  hlc->node_id[node_id_len] = '\0';
  offset += node_id_len;

  return offset;
}