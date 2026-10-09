//
// Created by victor on 4/30/25.
//

#include "crdt_merge.h"
#include "../Util/platform.h"
#include "one_shot.h"
#include "../Util/allocator.h"
#include "../Crypto/crypto.h"
#include "../StateMachine/state_machine.h"
#include <string.h>
#include <stdlib.h>

// ============================================================
// Internal helpers
// ============================================================

static g_counter_entry_t* _g_counter_find_entry(g_counter_t* counter, const char* node_id) {
  for (uint32_t i = 0; i < counter->entry_count; i++) {
    if (strcmp(counter->entries[i].node_id, node_id) == 0) {
      return &counter->entries[i];
    }
  }
  return NULL;
}

static const g_counter_entry_t* _g_counter_find_entry_const(const g_counter_t* counter, const char* node_id) {
  for (uint32_t i = 0; i < counter->entry_count; i++) {
    if (strcmp(counter->entries[i].node_id, node_id) == 0) {
      return &counter->entries[i];
    }
  }
  return NULL;
}

static bool _or_set_tag_in_tombstones(const or_set_t* set, const char* tag) {
  for (uint32_t i = 0; i < set->tombstone_count; i++) {
    if (strcmp(set->tombstones[i].tag, tag) == 0) {
      return true;
    }
  }
  return false;
}

static bool _or_set_element_has_live_tag(const or_set_t* set, const char* element) {
  for (uint32_t i = 0; i < set->element_count; i++) {
    if (strcmp(set->elements[i].element, element) == 0) {
      if (!_or_set_tag_in_tombstones(set, set->elements[i].tag)) {
        return true;
      }
    }
  }
  return false;
}

static bool _string_in_array(const char** arr, uint32_t count, const char* str) {
  for (uint32_t i = 0; i < count; i++) {
    if (strcmp(arr[i], str) == 0) {
      return true;
    }
  }
  return false;
}

// ============================================================
// G-Counter (12.2.1)
// ============================================================

g_counter_t* g_counter_create(void) {
  g_counter_t* counter = get_clear_memory(sizeof(g_counter_t));
  counter->entries = NULL;
  counter->entry_count = 0;
  return counter;
}

void g_counter_destroy(g_counter_t* counter) {
  if (counter == NULL) return;
  if (counter->entries != NULL) free(counter->entries);
  free(counter);
}

crabs_error_e g_counter_increment(g_counter_t* counter, const char* node_id, int64_t delta) {
  if (counter == NULL || node_id == NULL) return CRABS_ERR_INVALID_PARAM;
  // A G-Counter only grows; a negative delta is convergently lost on merge
  // (merge takes per-node max). Reject negative deltas — use a PN-Counter
  // for decrementing counters.
  if (delta < 0) return CRABS_ERR_INVALID_PARAM;

  g_counter_entry_t* entry = _g_counter_find_entry(counter, node_id);
  if (entry != NULL) {
    // Checked addition to avoid silent int64 overflow with attacker-chosen deltas.
    if (entry->count > INT64_MAX - delta) return CRABS_ERR_INVALID_PARAM;
    entry->count += delta;
    return CRABS_SUCCESS;
  }

  uint32_t new_count = counter->entry_count + 1;
  g_counter_entry_t* new_entries = realloc(counter->entries, new_count * sizeof(g_counter_entry_t));
  if (new_entries == NULL) return CRABS_ERR_OOM;
  counter->entries = new_entries;

  g_counter_entry_t* new_entry = &counter->entries[counter->entry_count];
  strncpy(new_entry->node_id, node_id, CRABS_MAX_USER_ID - 1);
  new_entry->node_id[CRABS_MAX_USER_ID - 1] = '\0';
  new_entry->count = delta;
  counter->entry_count = new_count;
  return CRABS_SUCCESS;
}

int64_t g_counter_value(const g_counter_t* counter) {
  if (counter == NULL) return 0;
  int64_t total = 0;
  // Audit M-G: saturating accumulation. Per-entry increments are checked,
  // but the sum can overflow int64 with many entries / large counts; that is
  // undefined behavior. Clamp to INT64_MAX instead of wrapping.
  for (uint32_t i = 0; i < counter->entry_count; i++) {
    int64_t c = counter->entries[i].count;
    if (c >= 0) {
      if (total > INT64_MAX - c) total = INT64_MAX;
      else total += c;
    } else {
      if (total < INT64_MIN - c) total = INT64_MIN;
      else total += c;
    }
  }
  return total;
}

g_counter_t* g_counter_merge(const g_counter_t* a, const g_counter_t* b) {
  if (a == NULL && b == NULL) return NULL;
  if (a == NULL) {
    g_counter_t* result = g_counter_create();
    for (uint32_t i = 0; i < b->entry_count; i++) {
      g_counter_increment(result, b->entries[i].node_id, b->entries[i].count);
    }
    return result;
  }
  if (b == NULL) {
    g_counter_t* result = g_counter_create();
    for (uint32_t i = 0; i < a->entry_count; i++) {
      g_counter_increment(result, a->entries[i].node_id, a->entries[i].count);
    }
    return result;
  }

  g_counter_t* result = g_counter_create();
  // Add all entries from a
  for (uint32_t i = 0; i < a->entry_count; i++) {
    g_counter_increment(result, a->entries[i].node_id, a->entries[i].count);
  }
  // Merge entries from b: take max for existing nodes, add new nodes
  for (uint32_t i = 0; i < b->entry_count; i++) {
    g_counter_entry_t* existing = _g_counter_find_entry(result, b->entries[i].node_id);
    if (existing != NULL) {
      int64_t a_val = existing->count;
      int64_t b_val = b->entries[i].count;
      existing->count = (a_val > b_val) ? a_val : b_val;
    } else {
      g_counter_increment(result, b->entries[i].node_id, b->entries[i].count);
    }
  }
  return result;
}

// ============================================================
// PN-Counter (12.2.2)
// ============================================================

pn_counter_t* pn_counter_create(void) {
  pn_counter_t* counter = get_clear_memory(sizeof(pn_counter_t));
  counter->pos.entries = NULL;
  counter->pos.entry_count = 0;
  counter->neg.entries = NULL;
  counter->neg.entry_count = 0;
  return counter;
}

void pn_counter_destroy(pn_counter_t* counter) {
  if (counter == NULL) return;
  if (counter->pos.entries != NULL) free(counter->pos.entries);
  if (counter->neg.entries != NULL) free(counter->neg.entries);
  free(counter);
}

crabs_error_e pn_counter_increment(pn_counter_t* counter, const char* node_id, int64_t delta) {
  if (counter == NULL || node_id == NULL) return CRABS_ERR_INVALID_PARAM;
  return g_counter_increment(&counter->pos, node_id, delta);
}

crabs_error_e pn_counter_decrement(pn_counter_t* counter, const char* node_id, int64_t delta) {
  if (counter == NULL || node_id == NULL) return CRABS_ERR_INVALID_PARAM;
  return g_counter_increment(&counter->neg, node_id, delta);
}

int64_t pn_counter_value(const pn_counter_t* counter) {
  if (counter == NULL) return 0;
  // Audit R6-3: both g_counter_value calls return values in [0, INT64_MAX]
  // because g_counter_increment rejects negative deltas (a G-Counter only
  // grows). The subtraction pos - neg is therefore in [-INT64_MAX, INT64_MAX],
  // which fits in int64_t without overflow. This invariant (g_counter entries
  // are always non-negative) is what makes the unchecked subtraction safe; if
  // g_counter_increment ever accepts negative deltas, this subtraction would
  // need saturating arithmetic to prevent overflow.
  return g_counter_value(&counter->pos) - g_counter_value(&counter->neg);
}

pn_counter_t* pn_counter_merge(const pn_counter_t* a, const pn_counter_t* b) {
  if (a == NULL && b == NULL) return NULL;

  pn_counter_t* result = pn_counter_create();

  // Merge positive counters
  const g_counter_t* pos_a = (a != NULL) ? &a->pos : NULL;
  const g_counter_t* pos_b = (b != NULL) ? &b->pos : NULL;
  g_counter_t* merged_pos = g_counter_merge(pos_a, pos_b);
  if (merged_pos != NULL) {
    if (result->pos.entries != NULL) free(result->pos.entries);
    result->pos = *merged_pos;
    free(merged_pos); // Free the wrapper, keep the data
  }

  // Merge negative counters
  const g_counter_t* neg_a = (a != NULL) ? &a->neg : NULL;
  const g_counter_t* neg_b = (b != NULL) ? &b->neg : NULL;
  g_counter_t* merged_neg = g_counter_merge(neg_a, neg_b);
  if (merged_neg != NULL) {
    if (result->neg.entries != NULL) free(result->neg.entries);
    result->neg = *merged_neg;
    free(merged_neg);
  }

  return result;
}

// ============================================================
// OR-Set (12.2.3)
// ============================================================

or_set_t* or_set_create(void) {
  or_set_t* set = get_clear_memory(sizeof(or_set_t));
  set->elements = NULL;
  set->element_count = 0;
  set->tombstones = NULL;
  set->tombstone_count = 0;
  return set;
}

void or_set_destroy(or_set_t* set) {
  if (set == NULL) return;
  for (uint32_t i = 0; i < set->element_count; i++) {
    free(set->elements[i].element);
    free(set->elements[i].tag);
  }
  if (set->elements != NULL) free(set->elements);
  for (uint32_t i = 0; i < set->tombstone_count; i++) {
    free(set->tombstones[i].element);
    free(set->tombstones[i].tag);
  }
  if (set->tombstones != NULL) free(set->tombstones);
  free(set);
}

crabs_error_e or_set_add(or_set_t* set, const char* element, const char* tag) {
  if (set == NULL || element == NULL || tag == NULL) return CRABS_ERR_INVALID_PARAM;

  // Audit H-J: dedup by tag. An OR-Set add is uniquely identified by its tag;
  // re-adding the same tag (e.g. merge(A, A) under gossip/replay) must be
  // idempotent. Without this, element_count doubled on every self-merge,
  // yielding unbounded memory growth and a remote memory-exhaustion DoS.
  for (uint32_t i = 0; i < set->element_count; i++) {
    if (strcmp(set->elements[i].tag, tag) == 0) return CRABS_SUCCESS;
  }
  // A tag that is already tombstoned should not be re-added either.
  if (_or_set_tag_in_tombstones(set, tag)) return CRABS_SUCCESS;

  uint32_t new_count = set->element_count + 1;
  or_set_entry_t* new_elements = realloc(set->elements, new_count * sizeof(or_set_entry_t));
  if (new_elements == NULL) return CRABS_ERR_OOM;
  set->elements = new_elements;

  set->elements[set->element_count].element = platform_strdup(element);
  set->elements[set->element_count].tag = platform_strdup(tag);
  set->element_count = new_count;
  return CRABS_SUCCESS;
}

crabs_error_e or_set_remove(or_set_t* set, const char* element) {
  if (set == NULL || element == NULL) return CRABS_ERR_INVALID_PARAM;

  // Add all tags for this element to tombstones
  for (uint32_t i = 0; i < set->element_count; i++) {
    if (strcmp(set->elements[i].element, element) == 0) {
      // Check if already tombstoned
      if (_or_set_tag_in_tombstones(set, set->elements[i].tag)) continue;

      uint32_t new_ts_count = set->tombstone_count + 1;
      or_set_entry_t* new_tombstones = realloc(set->tombstones, new_ts_count * sizeof(or_set_entry_t));
      if (new_tombstones == NULL) return CRABS_ERR_OOM;
      set->tombstones = new_tombstones;

      set->tombstones[set->tombstone_count].element = platform_strdup(set->elements[i].element);
      set->tombstones[set->tombstone_count].tag = platform_strdup(set->elements[i].tag);
      set->tombstone_count = new_ts_count;
    }
  }
  return CRABS_SUCCESS;
}

bool or_set_contains(const or_set_t* set, const char* element) {
  if (set == NULL || element == NULL) return false;
  for (uint32_t i = 0; i < set->element_count; i++) {
    if (strcmp(set->elements[i].element, element) == 0) {
      if (!_or_set_tag_in_tombstones(set, set->elements[i].tag)) {
        return true;
      }
    }
  }
  return false;
}

or_set_t* or_set_merge(const or_set_t* a, const or_set_t* b) {
  if (a == NULL && b == NULL) return NULL;

  or_set_t* result = or_set_create();

  // Collect all elements from both sets
  const or_set_t* sources[2] = {a, b};
  for (int s = 0; s < 2; s++) {
    if (sources[s] == NULL) continue;
    for (uint32_t i = 0; i < sources[s]->element_count; i++) {
      or_set_add(result, sources[s]->elements[i].element, sources[s]->elements[i].tag);
    }
  }

  // Collect all tombstones from both sets
  for (int s = 0; s < 2; s++) {
    if (sources[s] == NULL) continue;
    for (uint32_t i = 0; i < sources[s]->tombstone_count; i++) {
      // Avoid duplicate tombstones
      if (!_or_set_tag_in_tombstones(result, sources[s]->tombstones[i].tag)) {
        uint32_t new_count = result->tombstone_count + 1;
        or_set_entry_t* new_ts = realloc(result->tombstones, new_count * sizeof(or_set_entry_t));
        if (new_ts == NULL) continue;
        result->tombstones = new_ts;
        result->tombstones[result->tombstone_count].element = platform_strdup(sources[s]->tombstones[i].element);
        result->tombstones[result->tombstone_count].tag = platform_strdup(sources[s]->tombstones[i].tag);
        result->tombstone_count = new_count;
      }
    }
  }

  return result;
}

// ============================================================
// 2P-Set (12.2.4)
// ============================================================

two_p_set_t* two_p_set_create(void) {
  two_p_set_t* set = get_clear_memory(sizeof(two_p_set_t));
  set->add_set = NULL;
  set->add_count = 0;
  set->remove_set = NULL;
  set->remove_count = 0;
  return set;
}

void two_p_set_destroy(two_p_set_t* set) {
  if (set == NULL) return;
  for (uint32_t i = 0; i < set->add_count; i++) {
    free(set->add_set[i]);
  }
  if (set->add_set != NULL) free(set->add_set);
  for (uint32_t i = 0; i < set->remove_count; i++) {
    free(set->remove_set[i]);
  }
  if (set->remove_set != NULL) free(set->remove_set);
  free(set);
}

crabs_error_e two_p_set_add(two_p_set_t* set, const char* element) {
  if (set == NULL || element == NULL) return CRABS_ERR_INVALID_PARAM;

  // Check for duplicate in add_set
  if (_string_in_array((const char**)set->add_set, set->add_count, element)) {
    return CRABS_SUCCESS; // Idempotent
  }

  uint32_t new_count = set->add_count + 1;
  char** new_add_set = realloc(set->add_set, new_count * sizeof(char*));
  if (new_add_set == NULL) return CRABS_ERR_OOM;
  set->add_set = new_add_set;
  set->add_set[set->add_count] = platform_strdup(element);
  set->add_count = new_count;
  return CRABS_SUCCESS;
}

crabs_error_e two_p_set_remove(two_p_set_t* set, const char* element) {
  if (set == NULL || element == NULL) return CRABS_ERR_INVALID_PARAM;

  // Check for duplicate in remove_set
  if (_string_in_array((const char**)set->remove_set, set->remove_count, element)) {
    return CRABS_SUCCESS; // Idempotent
  }

  uint32_t new_count = set->remove_count + 1;
  char** new_remove_set = realloc(set->remove_set, new_count * sizeof(char*));
  if (new_remove_set == NULL) return CRABS_ERR_OOM;
  set->remove_set = new_remove_set;
  set->remove_set[set->remove_count] = platform_strdup(element);
  set->remove_count = new_count;
  return CRABS_SUCCESS;
}

bool two_p_set_contains(const two_p_set_t* set, const char* element) {
  if (set == NULL || element == NULL) return false;
  bool in_add = _string_in_array((const char**)set->add_set, set->add_count, element);
  bool in_remove = _string_in_array((const char**)set->remove_set, set->remove_count, element);
  return in_add && !in_remove;
}

two_p_set_t* two_p_set_merge(const two_p_set_t* a, const two_p_set_t* b) {
  if (a == NULL && b == NULL) return NULL;

  two_p_set_t* result = two_p_set_create();

  const two_p_set_t* sources[2] = {a, b};
  for (int s = 0; s < 2; s++) {
    if (sources[s] == NULL) continue;
    for (uint32_t i = 0; i < sources[s]->add_count; i++) {
      two_p_set_add(result, sources[s]->add_set[i]);
    }
    for (uint32_t i = 0; i < sources[s]->remove_count; i++) {
      two_p_set_remove(result, sources[s]->remove_set[i]);
    }
  }

  return result;
}

// ============================================================
// LWW-Register (12.2.5)
// ============================================================

lww_register_t* lww_register_create(const uint8_t* value, uint32_t size, uint64_t timestamp, const char* node_id) {
  lww_register_t* reg = get_clear_memory(sizeof(lww_register_t));
  if (value != NULL && size > 0) {
    reg->value = get_memory(size);
    memcpy(reg->value, value, size);
  }
  reg->value_size = size;
  reg->timestamp = timestamp;
  if (node_id != NULL) {
    strncpy(reg->node_id, node_id, CRABS_MAX_USER_ID - 1);
    reg->node_id[CRABS_MAX_USER_ID - 1] = '\0';
  }
  return reg;
}

void lww_register_destroy(lww_register_t* reg) {
  if (reg == NULL) return;
  if (reg->value != NULL) free(reg->value);
  free(reg);
}

lww_register_t* lww_register_merge(const lww_register_t* a, const lww_register_t* b) {
  if (a == NULL && b == NULL) return NULL;
  if (a == NULL) return lww_register_create(b->value, b->value_size, b->timestamp, b->node_id);
  if (b == NULL) return lww_register_create(a->value, a->value_size, a->timestamp, a->node_id);

  // Higher timestamp wins; on tie, compare node_id lexicographically
  int winner = 0; // 0 = a wins, 1 = b wins
  if (b->timestamp > a->timestamp) {
    winner = 1;
  } else if (a->timestamp == b->timestamp) {
    if (strcmp(b->node_id, a->node_id) > 0) {
      winner = 1;
    }
    // If equal or a wins, winner stays 0
  }

  if (winner == 1) {
    return lww_register_create(b->value, b->value_size, b->timestamp, b->node_id);
  }
  return lww_register_create(a->value, a->value_size, a->timestamp, a->node_id);
}

// ============================================================
// State-level merge (12.1)
// ============================================================

static data_item_t* _data_item_deep_copy(const data_item_t* item) {
  if (item == NULL) return NULL;
  data_item_t* copy = data_item_create(item->name, item->type, item->crdt_type);
  copy->protocol_state = item->protocol_state;
  copy->lock_state = item->lock_state;
  // R7-L-12: the shallow lock_state copy would share the pre_lock_snapshot
  // pointer with the source — a latent double-free if both items are destroyed.
  // The merge path does not use the snapshot, so drop it on the copy.
  copy->lock_state.pre_lock_snapshot = NULL;
  // Write-domains v1: propagate the per-item domain fields. Without this a
  // sovereign item new to dst silently arrived as FREE_MERGE — a domain
  // downgrade on merge. The inline fork storage is copied in full (not just
  // fork_count entries) for deterministic bytes; fork_count carries the bound.
  copy->write_domain = item->write_domain;
  copy->ordering_module = item->ordering_module;
  memcpy(copy->writer, item->writer, sizeof(copy->writer));
  copy->item_seq = item->item_seq;
  memcpy(copy->item_digest, item->item_digest, sizeof(copy->item_digest));
  memcpy(copy->fork_writers, item->fork_writers, sizeof(copy->fork_writers));
  memcpy(copy->fork_evidence_digests, item->fork_evidence_digests,
         sizeof(copy->fork_evidence_digests));
  copy->fork_count = item->fork_count;
  // Deep copy value pointer - the caller must handle CRDT-specific deep copies
  if (item->value != NULL) {
    // We do not deep copy CRDT values here; the merge function handles that
    copy->value = NULL;
  }
  return copy;
}

static int _compare_log_entries(const void* a, const void* b) {
  const log_entry_t* ea = (const log_entry_t*)a;
  const log_entry_t* eb = (const log_entry_t*)b;
  if (ea->lamport_time < eb->lamport_time) return -1;
  if (ea->lamport_time > eb->lamport_time) return 1;
  return strcmp(ea->node_id, eb->node_id);
}

// ============================================================
// Write-domain merge dispatch (write-domains v1, spec 2026-10-08
// §Merge dispatch)
// ============================================================
// FREE_MERGE items keep the A5 type-merge below unchanged. SOVEREIGN items
// merge by chain-head comparison (item_seq/item_digest) — never by type
// merge: two sovereign snapshots of different content are a divergence, not
// a CRDT to combine. GROUP_ORDERED (v1 ships no modules) holds any
// divergence. Divergence is NOT a merge failure — merge still converges and
// returns CRABS_SUCCESS; what was withheld surfaces through the dst state's
// change hook as a CRABS_CHANGE_MERGE event.

// Propagate src's quarantine evidence into dst by monotone union. Union-only:
// an entry is never evicted and duplicates (same writer OR same evidence
// digest) are the idempotent no-op signal. A full set (CRABS_MAX_FORK_WRITERS)
// is also non-fatal: the audit log is the authoritative evidence store and
// DOMAIN_CHECK honors what is present (spec §Error handling — merge union
// truncated).
static void _merge_union_fork_evidence(data_item_t* dst_item,
                                       const data_item_t* src_item) {
  for (uint32_t fork_index = 0; fork_index < src_item->fork_count; fork_index++) {
    (void)state_append_fork_evidence(dst_item,
                                     src_item->fork_writers[fork_index],
                                     src_item->fork_evidence_digests[fork_index]);
  }
}

// Evidence digest for a merge-detected fork: SHA-256 over the two forking
// chain-head digests in lexicographic order (min ‖ max). Content-derived, so
// any replica merging the same two heads derives the same entry and the
// dedupe in state_append_fork_evidence keeps the union idempotent. The full
// op bytes stay the durable evidence in the log; this digest only convicts.
static crabs_error_e _merge_fork_evidence_digest(
    const uint8_t digest_a[CRABS_HASH_SIZE],
    const uint8_t digest_b[CRABS_HASH_SIZE],
    uint8_t out_digest[CRABS_HASH_SIZE]) {
  uint8_t pair[2 * CRABS_HASH_SIZE];
  if (memcmp(digest_a, digest_b, CRABS_HASH_SIZE) < 0) {
    memcpy(pair, digest_a, CRABS_HASH_SIZE);
    memcpy(pair + CRABS_HASH_SIZE, digest_b, CRABS_HASH_SIZE);
  } else {
    memcpy(pair, digest_b, CRABS_HASH_SIZE);
    memcpy(pair + CRABS_HASH_SIZE, digest_a, CRABS_HASH_SIZE);
  }
  return crypto_sha256(pair, sizeof(pair), out_digest);
}

static void _merge_notify_divergence(state_t* dst, const char* type,
                                     const char* target, crabs_error_e reason) {
  state_notify_change(dst, CRABS_CHANGE_MERGE, type, NULL, NULL, NULL,
                      target, NULL, reason);
}

// SOVEREIGN v1 merge rule over two chain-head snapshots (item_a = local,
// item_b = remote):
//   - writer mismatch: the writer is creation-immutable, so a same-named
//     sovereign item under another writer is corrupted lineage — keep
//     item_a's content, union fork evidence, and surface an event.
//   - item_b seq ahead (same writer): its digest chain continues item_a's —
//     accept item_b's snapshot wholesale (value + head fields).
//   - item_a seq ahead: keep item_a; item_b is a stale tail.
//   - equal seq, equal digest: identical head — no-op.
//   - equal seq, DIFFERENT digest: a fork. Do NOT apply either side's new
//     content (quarantine semantics — merge-time forks must not overwrite),
//     monotone-union the fork sets, convict the writer with a content-derived
//     evidence digest so DOMAIN_CHECK blocks further writes, and surface a
//     FORK_DETECTED change event. Note the chain history that a full fork
//     proof needs lives in the op log, not derivable from two snapshots —
//     the v1 rule therefore keys on (seq, digest) alone.
//
// Conviction soundness rests on the digest being content-only: the preimage
// (crabs_serialize_data_item_chain_preimage via state_item_digest_compute)
// excludes runtime protocol_state, so a lock taken on ONE replica moves only
// that replica's runtime state, never its chain head. If the digest moved
// with runtime state, this branch would convict an honest writer for a
// replica-local lock — see the fix-note in serialization.h.
static void _merge_sovereign_item(state_t* dst, data_item_t* dst_item,
                                  const data_item_t* src_item) {
  if (strcmp(dst_item->writer, src_item->writer) != 0) {
    _merge_union_fork_evidence(dst_item, src_item);
    _merge_notify_divergence(dst, "__merge_writer_mismatch__", dst_item->name,
                             CRABS_ERR_PROTOCOL_VIOLATION);
    return;
  }
  // A same-named item of a different shape is corrupted lineage too — and
  // merging values across differing types would cast across incompatible
  // structs. Hold item_a whole.
  if (src_item->type != dst_item->type ||
      src_item->crdt_type != dst_item->crdt_type) {
    _merge_union_fork_evidence(dst_item, src_item);
    _merge_notify_divergence(dst, "__merge_type_mismatch__", dst_item->name,
                             CRABS_ERR_PROTOCOL_VIOLATION);
    return;
  }
  // Quarantine evidence propagates in every branch (union-only, monotone).
  _merge_union_fork_evidence(dst_item, src_item);

  if (src_item->item_seq > dst_item->item_seq) {
    // Accept the ahead snapshot: value plus chain-head fields.
    void* ahead_value = crdt_merge_value(dst_item->type, dst_item->crdt_type,
                                         NULL, src_item->value,
                                         dst_item->name, src_item->name);
    if (ahead_value == NULL && src_item->value != NULL) {
      // The value deep-copy failed (unsupported CRDT type — unreachable for
      // the v1 sovereign types COUNTER/REGISTER, but src states come from
      // the wire). Adopting the head without the content would split content
      // from chain: fail closed, keep item_a whole, surface it.
      _merge_notify_divergence(dst, "__merge_held__", dst_item->name,
                               CRABS_ERR_PROTOCOL_VIOLATION);
      return;
    }
    if (ahead_value != NULL) {
      crdt_value_destroy(dst_item->crdt_type, dst_item->value);
      dst_item->value = ahead_value;
    }
    dst_item->item_seq = src_item->item_seq;
    memcpy(dst_item->item_digest, src_item->item_digest,
           sizeof(dst_item->item_digest));
    return;
  }
  if (src_item->item_seq < dst_item->item_seq) {
    return; // local head is ahead — keep
  }
  if (memcmp(dst_item->item_digest, src_item->item_digest,
             CRABS_HASH_SIZE) == 0) {
    return; // identical head — no-op
  }
  // Fork: pin quarantine on the writer; content stays item_a's.
  if (!state_item_is_quarantined(dst_item, dst_item->writer)) {
    uint8_t evidence_digest[CRABS_HASH_SIZE];
    if (_merge_fork_evidence_digest(dst_item->item_digest,
                                    src_item->item_digest,
                                    evidence_digest) == CRABS_SUCCESS) {
      (void)state_append_fork_evidence(dst_item, dst_item->writer,
                                       evidence_digest);
    }
  }
  _merge_notify_divergence(dst, "__merge_fork__", dst_item->name,
                           CRABS_ERR_FORK_DETECTED);
}

// GROUP_ORDERED v1: no ordering modules ship, so there is no committed-prefix
// log to adopt from and a module-less item is read-only under DOMAIN_CHECK.
// ANY content divergence between two replicas is therefore unresolvable in
// v1 — keep item_a unchanged and surface a held-divergence event. Identity is
// proven by comparing digests of the serialized item form (content-comparable
// across replicas). Real committed-prefix logic is future work that arrives
// with ordering modules.
static void _merge_group_ordered_item(state_t* dst, data_item_t* dst_item,
                                      const data_item_t* src_item) {
  uint8_t digest_a[CRABS_HASH_SIZE];
  uint8_t digest_b[CRABS_HASH_SIZE];
  crabs_error_e status_a = state_item_digest_compute(dst_item, digest_a);
  crabs_error_e status_b = state_item_digest_compute(src_item, digest_b);
  bool identical = (status_a == CRABS_SUCCESS && status_b == CRABS_SUCCESS &&
                    memcmp(digest_a, digest_b, CRABS_HASH_SIZE) == 0);
  if (!identical) {
    // Fail closed on an undigestable item too: hold, hold, hold.
    _merge_notify_divergence(dst, "__merge_held__", dst_item->name,
                             CRABS_ERR_ORDERING_PATH);
  }
}

crabs_error_e crdt_merge_state(state_t* dst, const state_t* src) {
  if (dst == NULL || src == NULL) return CRABS_ERR_INVALID_PARAM;

  // Merge items: for each item in src, if not in dst add it; if in dst, merge values
  data_item_t* src_item = src->items;
  while (src_item != NULL) {
    data_item_t* dst_item = state_find_item(dst, src_item->name);
    if (dst_item == NULL) {
      // Item not in dst, add it
      data_item_t* new_item = _data_item_deep_copy(src_item);
      if (new_item == NULL) return CRABS_ERR_OOM;
      // Deep copy the CRDT value
      new_item->value = crdt_merge_value(src_item->type, src_item->crdt_type,
                                          NULL, src_item->value, NULL, src_item->name);
      crabs_error_e add_status = state_add_item(dst, new_item);
      if (add_status != CRABS_SUCCESS) {
        // state_add_item fails closed on a malformed domain declaration
        // (write-domains v1) — hold the item out of dst, surface the
        // rejection, then free the copy. The event borrows new_item->name
        // only for the duration of the hook call. (data_item_destroy only
        // frees the wrapper for counter/register types, so destroy the value
        // first.)
        _merge_notify_divergence(dst, "__merge_domain_mismatch__",
                                 new_item->name, CRABS_ERR_PROTOCOL_VIOLATION);
        if (new_item->value != NULL) {
          crdt_value_destroy(new_item->crdt_type, new_item->value);
          new_item->value = NULL;
        }
        data_item_destroy(new_item);
      }
    } else if (src_item->write_domain != dst_item->write_domain) {
      // The write domain is creation-immutable: a same-named item declaring a
      // different domain is lineage corruption. Keep item_a and surface it.
      _merge_notify_divergence(dst, "__merge_domain_mismatch__",
                               dst_item->name, CRABS_ERR_PROTOCOL_VIOLATION);
    } else if (dst_item->write_domain == CRABS_DOMAIN_SOVEREIGN) {
      _merge_sovereign_item(dst, dst_item, src_item);
    } else if (dst_item->write_domain == CRABS_DOMAIN_GROUP_ORDERED) {
      _merge_group_ordered_item(dst, dst_item, src_item);
    } else {
      // FREE_MERGE: Item exists in dst, merge values (A5 type merge)
      void* merged_value = crdt_merge_value(dst_item->type, dst_item->crdt_type,
                                              dst_item->value, src_item->value,
                                              dst_item->name, src_item->name);
      if (merged_value != NULL) {
        crdt_value_destroy(dst_item->crdt_type, dst_item->value);
        dst_item->value = merged_value;
      }
    }
    src_item = src_item->next;
  }

  // Merge logs (sorted by lamport_time then node_id). Idempotency is a core
  // CRDT requirement: merging the same src twice must not duplicate entries.
  // Dedup by uuid before appending.
  if (src->log_count > 0) {
    // Count how many src entries are NOT already present in dst (by uuid).
    uint64_t add_count = 0;
    for (uint64_t i = 0; i < src->log_count; i++) {
      bool found = false;
      for (uint64_t j = 0; j < dst->log_count; j++) {
        if (memcmp(dst->log[j].uuid, src->log[i].uuid, CRABS_UUID_SIZE) == 0) {
          found = true;
          break;
        }
      }
      if (!found) add_count++;
    }
    if (add_count > 0) {
      uint64_t total_count = dst->log_count + add_count;
      log_entry_t* merged_log = realloc(dst->log, total_count * sizeof(log_entry_t));
      if (merged_log == NULL) return CRABS_ERR_OOM;
      dst->log = merged_log;
      for (uint64_t i = 0; i < src->log_count; i++) {
        bool found = false;
        for (uint64_t j = 0; j < dst->log_count; j++) {
          if (memcmp(dst->log[j].uuid, src->log[i].uuid, CRABS_UUID_SIZE) == 0) {
            found = true;
            break;
          }
        }
        if (!found) {
          dst->log[dst->log_count++] = src->log[i];
        }
      }
      qsort(dst->log, dst->log_count, sizeof(log_entry_t), _compare_log_entries);
    }
  }

  // Transaction manager state is owned by the tx_manager, not merged here.
  // If merging tx_manager state is needed, add a merge method to the vtable.

  // Version = max(dst.version, src.version)
  if (src->version > dst->version) {
    dst->version = src->version;
  }

  return CRABS_SUCCESS;
}

// ============================================================
// Per-value merge dispatch
// ============================================================

void* crdt_merge_value(data_type_e type, crdt_type_e crdt_type,
                       void* value_a, void* value_b,
                       const char* node_id_a, const char* node_id_b) {
  switch (crdt_type) {
    case CRDT_G_COUNTER: {
      g_counter_t* a = (g_counter_t*)value_a;
      g_counter_t* b = (g_counter_t*)value_b;
      if (a == NULL && b == NULL) return NULL;
      return g_counter_merge(a, b);
    }
    case CRDT_PN_COUNTER: {
      pn_counter_t* a = (pn_counter_t*)value_a;
      pn_counter_t* b = (pn_counter_t*)value_b;
      if (a == NULL && b == NULL) return NULL;
      return pn_counter_merge(a, b);
    }
    case CRDT_OR_SET: {
      or_set_t* a = (or_set_t*)value_a;
      or_set_t* b = (or_set_t*)value_b;
      if (a == NULL && b == NULL) return NULL;
      return or_set_merge(a, b);
    }
    case CRDT_2P_SET: {
      two_p_set_t* a = (two_p_set_t*)value_a;
      two_p_set_t* b = (two_p_set_t*)value_b;
      if (a == NULL && b == NULL) return NULL;
      return two_p_set_merge(a, b);
    }
    case CRDT_LWW_REG: {
      lww_register_t* a = (lww_register_t*)value_a;
      lww_register_t* b = (lww_register_t*)value_b;
      if (a == NULL && b == NULL) return NULL;
      return lww_register_merge(a, b);
    }
    case CRDT_ONE_SHOT_SET: {
      one_shot_set_t* a = (one_shot_set_t*)value_a;
      one_shot_set_t* b = (one_shot_set_t*)value_b;
      if (a == NULL && b == NULL) return NULL;
      return one_shot_set_merge(a, b);
    }
    case CRDT_ONE_SHOT_FLAG: {
      one_shot_flag_t* a = (one_shot_flag_t*)value_a;
      one_shot_flag_t* b = (one_shot_flag_t*)value_b;
      if (a == NULL && b == NULL) return NULL;
      return one_shot_flag_merge(a, b);
    }
    case CRDT_RGA:
    case CRDT_CUSTOM:
    default:
      return NULL;
  }
}

void crdt_value_destroy(crdt_type_e crdt_type, void* value) {
  if (value == NULL) return;
  switch (crdt_type) {
    case CRDT_G_COUNTER:
      g_counter_destroy((g_counter_t*)value);
      break;
    case CRDT_PN_COUNTER:
      pn_counter_destroy((pn_counter_t*)value);
      break;
    case CRDT_OR_SET:
      or_set_destroy((or_set_t*)value);
      break;
    case CRDT_2P_SET:
      two_p_set_destroy((two_p_set_t*)value);
      break;
    case CRDT_LWW_REG:
      lww_register_destroy((lww_register_t*)value);
      break;
    case CRDT_ONE_SHOT_SET:
      one_shot_set_destroy((one_shot_set_t*)value);
      break;
    case CRDT_ONE_SHOT_FLAG:
      one_shot_flag_destroy((one_shot_flag_t*)value);
      break;
    default:
      free(value);
      break;
  }
}
