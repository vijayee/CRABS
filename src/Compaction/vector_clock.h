//
// Created by victor on 5/1/25.
//
// Vector Clock Tracking & Compaction Safety (v1.6 §2, §8.4)
// Node-id → sequence mapping for determining compaction safety.
//

#ifndef CRABS_VECTOR_CLOCK_H
#define CRABS_VECTOR_CLOCK_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "compaction.h"

// ============================================================
// Vector Clock Entry (v1.6 §2)
// ============================================================

#define CRABS_VC_MAX_NODES 64

typedef struct {
  char     node_id[CRABS_MAX_USER_ID];
  uint64_t sequence;
} crabs_vc_entry_t;

// ============================================================
// Vector Clock (v1.6 §2)
// ============================================================

typedef struct {
  crabs_vc_entry_t entries[CRABS_VC_MAX_NODES];
  uint32_t         count;
} crabs_vector_clock_t;

// ============================================================
// Vector Clock Functions
// ============================================================

// Initialize a vector clock (zero entries)
void crabs_vector_clock_init(crabs_vector_clock_t* vc);

// Get the sequence number for a node. Returns 0 if not found.
uint64_t crabs_vector_clock_get(const crabs_vector_clock_t* vc,
                                const char* node_id);

// Set the sequence number for a node. Creates entry if not found.
crabs_error_e crabs_vector_clock_set(crabs_vector_clock_t* vc,
                                      const char* node_id,
                                      uint64_t sequence);

// Increment the sequence number for a node. Creates entry at 1 if not found.
crabs_error_e crabs_vector_clock_increment(crabs_vector_clock_t* vc,
                                            const char* node_id);

// Merge another vector clock into this one (element-wise max).
// After merge, each entry's sequence is max(local, other).
// Returns CRABS_ERR_OOM if the VC is full and a new entry can't be added.
crabs_error_e crabs_vector_clock_merge(crabs_vector_clock_t* vc,
                              const crabs_vector_clock_t* other);

// Copy a vector clock.
void crabs_vector_clock_copy(crabs_vector_clock_t* dst,
                             const crabs_vector_clock_t* src);

// Check if this vector clock dominates another (all entries >= other's entries).
bool crabs_vector_clock_dominates(const crabs_vector_clock_t* vc,
                                  const crabs_vector_clock_t* other);

// Get the number of nodes in the vector clock
uint32_t crabs_vector_clock_count(const crabs_vector_clock_t* vc);

// ============================================================
// Compaction Safety Checks (v1.6 §8.4)
// ============================================================

// Check if compaction is safe for a data item given the state and config.
// Uses the config's safety_level to determine the check:
//   STRONG    — all known peers must have acknowledged
//   QUORUM    — at least quorum_threshold peers must have acknowledged
//   TIMESTAMP — grace period must have elapsed (uses compaction_interval_ms)
//   FORCE     — always safe
bool crabs_check_compaction_safety(const crabs_tombstone_config_t* config,
                                   const state_t* state,
                                   const data_item_t* item,
                                   const crabs_vector_clock_t* local_vc,
                                   const crabs_vector_clock_t* peer_vc);

#endif // CRABS_VECTOR_CLOCK_H