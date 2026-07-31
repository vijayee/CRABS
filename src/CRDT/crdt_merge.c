//
// Created by victor on 4/30/25.
//

#include "crdt_merge.h"
#include "one_shot.h"
#include "../Util/allocator.h"
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
  for (uint32_t i = 0; i < counter->entry_count; i++) {
    total += counter->entries[i].count;
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

  uint32_t new_count = set->element_count + 1;
  or_set_entry_t* new_elements = realloc(set->elements, new_count * sizeof(or_set_entry_t));
  if (new_elements == NULL) return CRABS_ERR_OOM;
  set->elements = new_elements;

  set->elements[set->element_count].element = strdup(element);
  set->elements[set->element_count].tag = strdup(tag);
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

      set->tombstones[set->tombstone_count].element = strdup(set->elements[i].element);
      set->tombstones[set->tombstone_count].tag = strdup(set->elements[i].tag);
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
        result->tombstones[result->tombstone_count].element = strdup(sources[s]->tombstones[i].element);
        result->tombstones[result->tombstone_count].tag = strdup(sources[s]->tombstones[i].tag);
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
  set->add_set[set->add_count] = strdup(element);
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
  set->remove_set[set->remove_count] = strdup(element);
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
      state_add_item(dst, new_item);
    } else {
      // Item exists in dst, merge values
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

  // Merge processed_ops (union)
  if (src->processed_ops != NULL && src->processed_op_count > 0) {
    // Simple union: allocate enough for both, add only new ones from src
    uint64_t new_count = 0;
    for (uint64_t i = 0; i < src->processed_op_count; i++) {
      bool found = false;
      for (uint64_t j = 0; j < dst->processed_op_count; j++) {
        if (memcmp(dst->processed_ops[j], src->processed_ops[i], CRABS_UUID_SIZE) == 0) {
          found = true;
          break;
        }
      }
      if (!found) new_count++;
    }
    if (new_count > 0) {
      uint8_t(*new_ops)[CRABS_UUID_SIZE] = realloc(dst->processed_ops,
        (dst->processed_op_count + new_count) * CRABS_UUID_SIZE);
      if (new_ops == NULL) return CRABS_ERR_OOM;
      dst->processed_ops = new_ops;
      for (uint64_t i = 0; i < src->processed_op_count; i++) {
        bool found = false;
        for (uint64_t j = 0; j < dst->processed_op_count; j++) {
          if (memcmp(dst->processed_ops[j], src->processed_ops[i], CRABS_UUID_SIZE) == 0) {
            found = true;
            break;
          }
        }
        if (!found) {
          memcpy(dst->processed_ops[dst->processed_op_count], src->processed_ops[i], CRABS_UUID_SIZE);
          dst->processed_op_count++;
        }
      }
    }
  }

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