//
// Created by victor on 5/1/25.
//
// Vector Clock Tracking & Compaction Safety (v1.6 §2, §8.4)
// Node-id → sequence mapping for determining compaction safety.
//

#include "vector_clock.h"
#include <string.h>

// ============================================================
// Vector Clock Functions
// ============================================================

void crabs_vector_clock_init(crabs_vector_clock_t* vc) {
  if (vc == NULL) return;
  memset(vc, 0, sizeof(crabs_vector_clock_t));
}

uint64_t crabs_vector_clock_get(const crabs_vector_clock_t* vc,
                                const char* node_id) {
  if (vc == NULL || node_id == NULL) return 0;
  for (uint32_t i = 0; i < vc->count; i++) {
    if (strcmp(vc->entries[i].node_id, node_id) == 0) {
      return vc->entries[i].sequence;
    }
  }
  return 0;
}

crabs_error_e crabs_vector_clock_set(crabs_vector_clock_t* vc,
                                      const char* node_id,
                                      uint64_t sequence) {
  if (vc == NULL || node_id == NULL) return CRABS_ERR_INVALID_PARAM;

  // Update existing entry
  for (uint32_t i = 0; i < vc->count; i++) {
    if (strcmp(vc->entries[i].node_id, node_id) == 0) {
      vc->entries[i].sequence = sequence;
      return CRABS_SUCCESS;
    }
  }

  // Add new entry
  if (vc->count >= CRABS_VC_MAX_NODES) {
    return CRABS_ERR_OOM;
  }

  strncpy(vc->entries[vc->count].node_id, node_id, CRABS_MAX_USER_ID - 1);
  vc->entries[vc->count].node_id[CRABS_MAX_USER_ID - 1] = '\0';
  vc->entries[vc->count].sequence = sequence;
  vc->count++;
  return CRABS_SUCCESS;
}

crabs_error_e crabs_vector_clock_increment(crabs_vector_clock_t* vc,
                                            const char* node_id) {
  if (vc == NULL || node_id == NULL) return CRABS_ERR_INVALID_PARAM;

  // Increment existing entry (saturating at UINT64_MAX to prevent wrap)
  for (uint32_t i = 0; i < vc->count; i++) {
    if (strcmp(vc->entries[i].node_id, node_id) == 0) {
      if (vc->entries[i].sequence < UINT64_MAX) {
        vc->entries[i].sequence++;
      }
      return CRABS_SUCCESS;
    }
  }

  // Create new entry starting at 1
  return crabs_vector_clock_set(vc, node_id, 1);
}

crabs_error_e crabs_vector_clock_merge(crabs_vector_clock_t* vc,
                              const crabs_vector_clock_t* other) {
  if (vc == NULL || other == NULL) return CRABS_ERR_INVALID_PARAM;

  for (uint32_t i = 0; i < other->count; i++) {
    uint64_t local_seq = crabs_vector_clock_get(vc, other->entries[i].node_id);
    uint64_t other_seq = other->entries[i].sequence;
    if (other_seq > local_seq) {
      crabs_error_e err = crabs_vector_clock_set(vc, other->entries[i].node_id, other_seq);
      if (err != CRABS_SUCCESS) return err;
    }
  }
  return CRABS_SUCCESS;
}

void crabs_vector_clock_copy(crabs_vector_clock_t* dst,
                             const crabs_vector_clock_t* src) {
  if (dst == NULL || src == NULL) return;
  memcpy(dst, src, sizeof(crabs_vector_clock_t));
}

bool crabs_vector_clock_dominates(const crabs_vector_clock_t* vc,
                                  const crabs_vector_clock_t* other) {
  if (vc == NULL || other == NULL) return false;

  // vc dominates other if for every entry in other, vc has an entry >= it
  for (uint32_t i = 0; i < other->count; i++) {
    uint64_t local_seq = crabs_vector_clock_get(vc, other->entries[i].node_id);
    if (local_seq < other->entries[i].sequence) {
      return false;
    }
  }
  return true;
}

uint32_t crabs_vector_clock_count(const crabs_vector_clock_t* vc) {
  if (vc == NULL) return 0;
  return vc->count;
}

// ============================================================
// Compaction Safety Checks (v1.6 §8.4)
// ============================================================

bool crabs_check_compaction_safety(const crabs_tombstone_config_t* config,
                                   const state_t* state,
                                   const data_item_t* item,
                                   const crabs_vector_clock_t* local_vc,
                                   const crabs_vector_clock_t* peer_vc) {
  (void)item;
  if (config == NULL) return false;

  switch (config->safety_level) {
    case CRABS_SAFETY_FORCE:
      // Force compaction — only allowed if config->allow_force is true
      return config->allow_force;

    case CRABS_SAFETY_STRONG:
      // All peers must have acknowledged — local VC must dominate peer VC.
      // Audit F-3: the prior fallback (`local_vc->count <= 1` when peer_vc is
      // NULL) always passed because local_vc is never populated outside
      // src/Compaction, so compaction proceeded without peer agreement and
      // destroyed concurrent remote operations. Fail closed: multi-replica
      // deployments MUST call crabs_compaction_engine_set_peer_vc; single-
      // replica deployments should use CRABS_SAFETY_FORCE.
      if (local_vc == NULL) return false;
      if (peer_vc == NULL) return false;
      return crabs_vector_clock_dominates(local_vc, peer_vc);

    case CRABS_SAFETY_QUORUM: {
      // At least quorum_threshold peers must have acknowledged.
      if (local_vc == NULL) return false;
      // Audit F-3: fail closed without a peer VC (see STRONG above).
      if (peer_vc == NULL) return false;
      if (peer_vc->count == 0) return true;  // No peers to wait for

      uint32_t acknowledged = 0;
      for (uint32_t i = 0; i < peer_vc->count; i++) {
        uint64_t local_seq = crabs_vector_clock_get(local_vc, peer_vc->entries[i].node_id);
        if (local_seq >= peer_vc->entries[i].sequence) {
          acknowledged++;
        }
      }
      return acknowledged >= config->quorum_threshold;
    }

    case CRABS_SAFETY_TIMESTAMP:
      // Timestamp-based: compaction is safe if the state version is
      // sufficiently ahead of the last compaction point. Since we don't
      // have wall-clock time in this module, we use the state version as
      // a proxy — safe if state version is non-zero (operations have
      // been applied since startup).
      if (state == NULL) return false;
      if (config->compaction_interval_ms == 0) return true;
      return (state->version > 0);
  }

  return false;
}