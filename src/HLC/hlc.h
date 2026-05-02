//
// Created by victor on 5/2/25.
//
// Hybrid Logical Clock (v1.6 Amendment 6)
// Physical-time-anchored ordering with attack mitigation.
//

#ifndef CRABS_HLC_H
#define CRABS_HLC_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../CRABS/crabs.h"

// ============================================================
// HLC Data Structure (v1.6 Amd6 §2.1)
// ============================================================

#define CRABS_HLC_NODE_ID_SIZE 64

typedef struct {
  uint64_t physical_seconds;   // Unix epoch seconds
  uint64_t physical_nanos;     // Nanosecond component (0-999,999,999)
  uint64_t logical_counter;    // Per-node counter for same-nanosecond events
  char     node_id[CRABS_HLC_NODE_ID_SIZE]; // Node identifier (tiebreaker)
} crabs_hlc_t;

// ============================================================
// Ordering System (v1.6 Amd6 §6.1)
// ============================================================

typedef enum {
  CRABS_ORDERING_LAMPORT = 0,
  CRABS_ORDERING_HLC    = 1
} crabs_ordering_system_e;

// ============================================================
// HLC Strategy (v1.6 Amd6 §3.2)
// ============================================================

typedef enum {
  HLC_STRATEGY_NAIVE   = 0x00,  // Take max blindly
  HLC_STRATEGY_BOUNDED = 0x01,  // Reject beyond max_skew_ms
  HLC_STRATEGY_QUORUM  = 0x02,  // Require multiple confirmations
  HLC_STRATEGY_STRICT  = 0x03,  // Never update from received
  HLC_STRATEGY_TRUSTED = 0x04   // Authenticated time source
} crabs_hlc_strategy_e;

// ============================================================
// Time Source (v1.6 Amd6 §3.2, §7)
// ============================================================

typedef enum {
  CRABS_TIME_SOURCE_SYSTEM_CLOCK = 0x00,
  CRABS_TIME_SOURCE_NTP_AUTH     = 0x01,
  CRABS_TIME_SOURCE_TPM          = 0x02,
  CRABS_TIME_SOURCE_CONSENSUS    = 0x03
} crabs_time_source_e;

// ============================================================
// Time Source VTable (v1.6 Amd6 §7)
// ============================================================

// Forward declaration for physical time result
typedef struct {
  uint64_t seconds;
  uint64_t nanos;
  bool     valid;
} crabs_physical_time_t;

typedef struct {
  crabs_physical_time_t (*get_time)(void* ctx);
  bool                  (*is_available)(void* ctx);
  void*                 ctx;
} crabs_time_source_ops_t;

// ============================================================
// HLC Receive Result (v1.6 Amd6 §4.2)
// ============================================================

typedef enum {
  CRABS_HLC_ACCEPTED         = 0,  // Timestamp accepted, state updated
  CRABS_HLC_REJECTED_SKEW    = 1,  // BOUNDED: too far ahead/behind
  CRABS_HLC_REJECTED_QUORUM = 2,  // QUORUM: insufficient confirmations
  CRABS_HLC_REJECTED_TRUST  = 3,  // TRUSTED: verification failed
  CRABS_HLC_ACCEPTED_STRICT = 4   // STRICT: accepted but state unchanged
} crabs_hlc_receive_result_e;

// ============================================================
// HLC State (v1.6 Amd6 §3.1)
// ============================================================

typedef struct {
  crabs_hlc_t            last;                       // Last timestamp issued
  crabs_time_source_e    time_source;                // Physical time source
  crabs_hlc_strategy_e   receive_strategy;           // Attack mitigation strategy
  uint64_t               max_skew_ms;                // BOUNDED: max clock skew (default 5000)
  uint32_t               quorum_size;                // QUORUM: confirmations needed (default 3)
  uint64_t               quorum_timeout_ms;          // QUORUM: confirmation timeout (default 1000)
  uint64_t               trusted_resync_ms;          // TRUSTED: resync interval (default 30000)
  bool                   strict_mode;                // Never update from received (default false)
  crabs_time_source_ops_t* time_source_ops;          // Time source vtable (optional override)

  // Statistics
  uint64_t               clock_regressions_detected;  // Count of regressions
  uint64_t               time_travel_attempts_rejected; // Count of rejected attacks
  uint64_t               quorum_failures;             // Count of quorum failures
} crabs_hlc_state_t;

// ============================================================
// Ordering Configuration (v1.6 Amd6 §3.2, §6.3)
// ============================================================

typedef struct {
  crabs_ordering_system_e ordering_system;  // LAMPORT or HLC

  struct {
    crabs_hlc_strategy_e receive_strategy;
    uint64_t             max_skew_ms;
    uint32_t             quorum_size;
    uint64_t             quorum_timeout_ms;
    bool                 strict_mode;
    bool                 trusted_time_source;
    uint64_t             trusted_resync_ms;
  } hlc;
} crabs_ordering_config_t;

// ============================================================
// HLC Defaults
// ============================================================

#define CRABS_HLC_DEFAULT_MAX_SKEW_MS          5000   // 5 seconds
#define CRABS_HLC_DEFAULT_QUORUM_SIZE          3
#define CRABS_HLC_DEFAULT_QUORUM_TIMEOUT_MS    1000   // 1 second
#define CRABS_HLC_DEFAULT_TRUSTED_RESYNC_MS    30000  // 30 seconds

// ============================================================
// HLC Initialization (v1.6 Amd6 §3)
// ============================================================

// Initialize HLC state with defaults (BOUNDED strategy, SYSTEM_CLOCK)
void crabs_hlc_state_init(crabs_hlc_state_t* state, const char* node_id);

// Initialize HLC state with a specific strategy
void crabs_hlc_state_init_strategy(crabs_hlc_state_t* state,
                                    const char* node_id,
                                    crabs_hlc_strategy_e strategy);

// Initialize ordering config with defaults (LAMPORT ordering)
void crabs_ordering_config_init(crabs_ordering_config_t* config);

// Initialize ordering config for HLC with a specific strategy
void crabs_ordering_config_init_hlc(crabs_ordering_config_t* config,
                                     crabs_hlc_strategy_e strategy);

// ============================================================
// HLC Comparison (v1.6 Amd6 §2.2)
// ============================================================

// Compare two HLC timestamps.
// Returns: -1 if a < b, 0 if a == b, 1 if a > b
int crabs_hlc_compare(const crabs_hlc_t* a, const crabs_hlc_t* b);

// ============================================================
// HLC Formatting (v1.6 Amd6 §2.3)
// ============================================================

// Format HLC as human-readable string.
// Format: "YYYY-MM-DDTHH:MM:SS.nnnnnnnnn#counter@node_id"
// Returns number of characters written (excluding null terminator),
// or negative on error.
int crabs_hlc_format(const crabs_hlc_t* hlc, char* buf, size_t buf_len);

// ============================================================
// HLC Normalization (v1.6 Amd6 §8.2)
// ============================================================

// Normalize nanoseconds: if physical_nanos >= 1,000,000,000,
// carry overflow into physical_seconds.
void crabs_hlc_normalize(crabs_hlc_t* hlc);

// ============================================================
// HLC Difference (v1.6 Amd6 §4.2)
// ============================================================

// Compute the difference in milliseconds between an HLC timestamp
// and a physical time reference. Returns positive if hlc is ahead,
// negative if hlc is behind.
int64_t crabs_hlc_diff_ms(const crabs_hlc_t* hlc,
                           uint64_t ref_seconds, uint64_t ref_nanos);

// ============================================================
// Physical Time Source (v1.6 Amd6 §7)
// ============================================================

// Get physical time from system clock (CLOCK_REALTIME)
crabs_physical_time_t crabs_hlc_get_system_time(void* ctx);

// Get physical time using the configured time source
crabs_physical_time_t crabs_hlc_get_physical_time(crabs_hlc_state_t* state);

// ============================================================
// HLC Generation (v1.6 Amd6 §4.1)
// ============================================================

// Generate the next HLC timestamp for a local event.
// Uses the configured time source and handles clock regression.
crabs_hlc_t crabs_hlc_next(crabs_hlc_state_t* state);

// ============================================================
// HLC Receive (v1.6 Amd6 §4.2, §5)
// ============================================================

// Process a received HLC timestamp according to the configured strategy.
// Updates state if accepted (except STRICT mode).
// Returns the result indicating acceptance or rejection reason.
crabs_hlc_receive_result_e crabs_hlc_receive(crabs_hlc_state_t* state,
                                               const crabs_hlc_t* received);

// ============================================================
// HLC Serialization (v1.6 Amd6 §9)
// ============================================================

// HLC serialized format:
//   physical_seconds: uint64 (8 bytes)
//   physical_nanos:   uint64 (8 bytes)
//   logical_counter:  uint64 (8 bytes)
//   node_id_length:   uint16 (2 bytes)
//   node_id:          byte[node_id_length]
// Total: 26 bytes + node_id

// Serialize an HLC timestamp to a byte buffer.
// Returns number of bytes written, or 0 on error.
// buf must be at least 26 + strlen(node_id) bytes.
size_t crabs_hlc_serialize(const crabs_hlc_t* hlc, uint8_t* buf, size_t buf_len);

// Deserialize an HLC timestamp from a byte buffer.
// Returns number of bytes consumed, or 0 on error.
// Validates that nanos < 1,000,000,000 and node_id_length <= CRABS_HLC_NODE_ID_SIZE.
size_t crabs_hlc_deserialize(crabs_hlc_t* hlc, const uint8_t* data, size_t data_len);

#endif // CRABS_HLC_H