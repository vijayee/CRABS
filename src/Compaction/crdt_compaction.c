//
// Created by victor on 5/2/25.
//
// CRDT Compaction VTables (v1.5.2 §3.1-3.3)
// Compaction support for OR-Set, 2P-Set, G-Counter, and PN-Counter CRDT types.
//

#include "crdt_compaction.h"
#include <stdio.h>
#include <string.h>

// ============================================================
// OR-Set Compaction (v1.5.2 §3.1)
// ============================================================

uint64_t crabs_or_set_count_tombstones(const void* item) {
  if (item == NULL) return 0;
  const or_set_t* set = (const or_set_t*)item;
  return set->tombstone_count;
}

uint64_t crabs_or_set_count_visible(const void* item) {
  if (item == NULL) return 0;
  const or_set_t* set = (const or_set_t*)item;

  // Count elements whose (element, tag) pair is not tombstoned (pair
  // semantics: a tombstone kills only its own pair — see crdt_merge.c).
  uint64_t visible = 0;
  for (uint32_t i = 0; i < set->element_count; i++) {
    bool tombstoned = false;
    for (uint32_t j = 0; j < set->tombstone_count; j++) {
      if (strcmp(set->elements[i].tag, set->tombstones[j].tag) == 0 &&
          strcmp(set->elements[i].element, set->tombstones[j].element) == 0) {
        tombstoned = true;
        break;
      }
    }
    if (!tombstoned) visible++;
  }
  return visible;
}

void* crabs_or_set_extract_visible(const void* item) {
  if (item == NULL) return NULL;
  const or_set_t* set = (const or_set_t*)item;

  or_set_t* visible = or_set_create();
  if (visible == NULL) return NULL;

  // Copy only elements whose (element, tag) pair is not tombstoned
  for (uint32_t i = 0; i < set->element_count; i++) {
    bool tombstoned = false;
    for (uint32_t j = 0; j < set->tombstone_count; j++) {
      if (strcmp(set->elements[i].tag, set->tombstones[j].tag) == 0 &&
          strcmp(set->elements[i].element, set->tombstones[j].element) == 0) {
        tombstoned = true;
        break;
      }
    }
    if (!tombstoned) {
      or_set_add(visible, set->elements[i].element, set->elements[i].tag);
    }
  }

  // No tombstones in the extracted visible set
  return visible;
}

void* crabs_or_set_rebuild_from_visible(const void* visible) {
  if (visible == NULL) return NULL;
  // The visible set is already a valid or_set_t with no tombstones
  // Just return it as-is — caller takes ownership
  or_set_t* result = or_set_create();
  if (result == NULL) return NULL;

  const or_set_t* src = (const or_set_t*)visible;
  for (uint32_t i = 0; i < src->element_count; i++) {
    or_set_add(result, src->elements[i].element, src->elements[i].tag);
  }

  return result;
}

bool crabs_or_set_compaction_safe(const void* item, const state_t* state) {
  (void)state;
  if (item == NULL) return false;
  return true;
}

double crabs_or_set_estimated_savings(const void* item) {
  if (item == NULL) return 0.0;
  const or_set_t* set = (const or_set_t*)item;
  uint64_t total = set->element_count + set->tombstone_count;
  if (total == 0) return 0.0;
  return (double)set->tombstone_count / (double)total;
}

void crabs_or_set_describe_tombstones(const void* item, char* buf, uint32_t buf_size) {
  if (buf == NULL || buf_size == 0) return;
  buf[0] = '\0';
  if (item == NULL) {
    snprintf(buf, buf_size, "null or-set");
    return;
  }
  const or_set_t* set = (const or_set_t*)item;
  snprintf(buf, buf_size, "OR-Set: %u elements, %u tombstoned tags",
           (unsigned)set->element_count, (unsigned)set->tombstone_count);
}

crabs_error_e crabs_register_or_set_vtable(crabs_compaction_registry_t* registry) {
  if (registry == NULL) return CRABS_ERR_INVALID_PARAM;

  static const crabs_compaction_vtable_t vtable = {
    .count_tombstones    = crabs_or_set_count_tombstones,
    .count_visible       = crabs_or_set_count_visible,
    .extract_visible     = crabs_or_set_extract_visible,
    .rebuild_from_visible = crabs_or_set_rebuild_from_visible,
    .compaction_safe     = crabs_or_set_compaction_safe,
    .estimated_savings   = crabs_or_set_estimated_savings,
    .describe_tombstones = crabs_or_set_describe_tombstones,
  };

  return crabs_compaction_register(registry, DATA_TYPE_SET, &vtable);
}

// ============================================================
// 2P-Set Compaction (v1.5.2 §3.2)
// ============================================================

uint64_t crabs_two_p_set_count_tombstones(const void* item) {
  if (item == NULL) return 0;
  const two_p_set_t* set = (const two_p_set_t*)item;
  return set->remove_count;
}

uint64_t crabs_two_p_set_count_visible(const void* item) {
  if (item == NULL) return 0;
  const two_p_set_t* set = (const two_p_set_t*)item;

  // Count elements in add_set but not in remove_set
  uint64_t visible = 0;
  for (uint32_t i = 0; i < set->add_count; i++) {
    bool in_remove = false;
    for (uint32_t j = 0; j < set->remove_count; j++) {
      if (strcmp(set->add_set[i], set->remove_set[j]) == 0) {
        in_remove = true;
        break;
      }
    }
    if (!in_remove) visible++;
  }
  return visible;
}

void* crabs_two_p_set_extract_visible(const void* item) {
  if (item == NULL) return NULL;
  const two_p_set_t* set = (const two_p_set_t*)item;

  two_p_set_t* visible = two_p_set_create();
  if (visible == NULL) return NULL;

  // Copy only elements in add_set but not in remove_set
  for (uint32_t i = 0; i < set->add_count; i++) {
    bool in_remove = false;
    for (uint32_t j = 0; j < set->remove_count; j++) {
      if (strcmp(set->add_set[i], set->remove_set[j]) == 0) {
        in_remove = true;
        break;
      }
    }
    if (!in_remove) {
      two_p_set_add(visible, set->add_set[i]);
    }
  }

  // WARNING: After compaction, previously removed elements CAN be re-added
  // because the remove_set is discarded. This is a semantic change.
  return visible;
}

void* crabs_two_p_set_rebuild_from_visible(const void* visible) {
  if (visible == NULL) return NULL;

  two_p_set_t* result = two_p_set_create();
  if (result == NULL) return NULL;

  const two_p_set_t* src = (const two_p_set_t*)visible;
  for (uint32_t i = 0; i < src->add_count; i++) {
    two_p_set_add(result, src->add_set[i]);
  }

  return result;
}

bool crabs_two_p_set_compaction_safe(const void* item, const state_t* state) {
  (void)state;
  if (item == NULL) return false;
  return true;
}

double crabs_two_p_set_estimated_savings(const void* item) {
  if (item == NULL) return 0.0;
  const two_p_set_t* set = (const two_p_set_t*)item;
  uint64_t total = set->add_count + set->remove_count;
  if (total == 0) return 0.0;
  // Savings include both the remove_set entries AND the tombstoned entries
  // in the add_set (duplicates in add_set that are also in remove_set)
  uint64_t tombstoned_in_add = 0;
  for (uint32_t i = 0; i < set->add_count; i++) {
    for (uint32_t j = 0; j < set->remove_count; j++) {
      if (strcmp(set->add_set[i], set->remove_set[j]) == 0) {
        tombstoned_in_add++;
        break;
      }
    }
  }
  return (double)(set->remove_count + tombstoned_in_add) / (double)total;
}

void crabs_two_p_set_describe_tombstones(const void* item, char* buf, uint32_t buf_size) {
  if (buf == NULL || buf_size == 0) return;
  buf[0] = '\0';
  if (item == NULL) {
    snprintf(buf, buf_size, "null 2p-set");
    return;
  }
  const two_p_set_t* set = (const two_p_set_t*)item;
  snprintf(buf, buf_size, "2P-Set: %u added, %u removed",
           (unsigned)set->add_count, (unsigned)set->remove_count);
}

crabs_error_e crabs_register_two_p_set_vtable(crabs_compaction_registry_t* registry) {
  if (registry == NULL) return CRABS_ERR_INVALID_PARAM;

  static const crabs_compaction_vtable_t vtable = {
    .count_tombstones    = crabs_two_p_set_count_tombstones,
    .count_visible       = crabs_two_p_set_count_visible,
    .extract_visible     = crabs_two_p_set_extract_visible,
    .rebuild_from_visible = crabs_two_p_set_rebuild_from_visible,
    .compaction_safe     = crabs_two_p_set_compaction_safe,
    .estimated_savings   = crabs_two_p_set_estimated_savings,
    .describe_tombstones = crabs_two_p_set_describe_tombstones,
  };

  return crabs_compaction_register(registry, DATA_TYPE_2P_SET, &vtable);
}

// ============================================================
// G-Counter Compaction (v1.5.2 §3.3 — counter variant)
// ============================================================

uint64_t crabs_g_counter_count_tombstones(const void* item) {
  if (item == NULL) return 0;
  const g_counter_t* counter = (const g_counter_t*)item;

  // Tombstones = zero-count entries (stale/unused node slots)
  uint64_t tombstones = 0;
  for (uint32_t i = 0; i < counter->entry_count; i++) {
    if (counter->entries[i].count == 0) tombstones++;
  }
  return tombstones;
}

uint64_t crabs_g_counter_count_visible(const void* item) {
  if (item == NULL) return 0;
  const g_counter_t* counter = (const g_counter_t*)item;

  uint64_t visible = 0;
  for (uint32_t i = 0; i < counter->entry_count; i++) {
    if (counter->entries[i].count > 0) visible++;
  }
  return visible;
}

void* crabs_g_counter_extract_visible(const void* item) {
  if (item == NULL) return NULL;
  const g_counter_t* counter = (const g_counter_t*)item;

  g_counter_t* visible = g_counter_create();
  if (visible == NULL) return NULL;

  for (uint32_t i = 0; i < counter->entry_count; i++) {
    if (counter->entries[i].count > 0) {
      g_counter_increment(visible, counter->entries[i].node_id,
                          counter->entries[i].count);
    }
  }
  return visible;
}

void* crabs_g_counter_rebuild_from_visible(const void* visible) {
  if (visible == NULL) return NULL;

  const g_counter_t* src = (const g_counter_t*)visible;
  g_counter_t* result = g_counter_create();
  if (result == NULL) return NULL;

  for (uint32_t i = 0; i < src->entry_count; i++) {
    g_counter_increment(result, src->entries[i].node_id,
                        src->entries[i].count);
  }
  return result;
}

bool crabs_g_counter_compaction_safe(const void* item, const state_t* state) {
  (void)state;
  if (item == NULL) return false;
  return true;
}

double crabs_g_counter_estimated_savings(const void* item) {
  if (item == NULL) return 0.0;
  const g_counter_t* counter = (const g_counter_t*)item;
  if (counter->entry_count == 0) return 0.0;

  uint64_t zero_count = 0;
  for (uint32_t i = 0; i < counter->entry_count; i++) {
    if (counter->entries[i].count == 0) zero_count++;
  }
  return (double)zero_count / (double)counter->entry_count;
}

void crabs_g_counter_describe_tombstones(const void* item, char* buf, uint32_t buf_size) {
  if (buf == NULL || buf_size == 0) return;
  buf[0] = '\0';
  if (item == NULL) {
    snprintf(buf, buf_size, "null g-counter");
    return;
  }
  const g_counter_t* counter = (const g_counter_t*)item;
  uint64_t zero_count = 0;
  for (uint32_t i = 0; i < counter->entry_count; i++) {
    if (counter->entries[i].count == 0) zero_count++;
  }
  snprintf(buf, buf_size, "G-Counter: %u nodes, %llu zero-count",
           (unsigned)counter->entry_count, (unsigned long long)zero_count);
}

crabs_error_e crabs_register_g_counter_vtable(crabs_compaction_registry_t* registry) {
  if (registry == NULL) return CRABS_ERR_INVALID_PARAM;

  static const crabs_compaction_vtable_t vtable = {
    .count_tombstones    = crabs_g_counter_count_tombstones,
    .count_visible       = crabs_g_counter_count_visible,
    .extract_visible     = crabs_g_counter_extract_visible,
    .rebuild_from_visible = crabs_g_counter_rebuild_from_visible,
    .compaction_safe     = crabs_g_counter_compaction_safe,
    .estimated_savings   = crabs_g_counter_estimated_savings,
    .describe_tombstones = crabs_g_counter_describe_tombstones,
  };

  return crabs_compaction_register(registry, DATA_TYPE_COUNTER, &vtable);
}

// ============================================================
// PN-Counter (RGA) Compaction (v1.5.2 §3.3)
// ============================================================

uint64_t crabs_pn_counter_count_tombstones(const void* item) {
  if (item == NULL) return 0;
  const pn_counter_t* counter = (const pn_counter_t*)item;
  return counter->neg.entry_count;
}

uint64_t crabs_pn_counter_count_visible(const void* item) {
  if (item == NULL) return 0;
  const pn_counter_t* counter = (const pn_counter_t*)item;

  // Count nodes where the net value is positive
  uint64_t visible = 0;
  for (uint32_t i = 0; i < counter->pos.entry_count; i++) {
    int64_t pos_val = counter->pos.entries[i].count;
    // Find matching neg entry
    int64_t neg_val = 0;
    for (uint32_t j = 0; j < counter->neg.entry_count; j++) {
      if (strcmp(counter->pos.entries[i].node_id,
                  counter->neg.entries[j].node_id) == 0) {
        neg_val = counter->neg.entries[j].count;
        break;
      }
    }
    if (pos_val - neg_val > 0) visible++;
  }
  return visible;
}

void* crabs_pn_counter_extract_visible(const void* item) {
  if (item == NULL) return NULL;
  const pn_counter_t* counter = (const pn_counter_t*)item;

  pn_counter_t* visible = pn_counter_create();
  if (visible == NULL) return NULL;

  // Only keep nodes with net-positive values
  for (uint32_t i = 0; i < counter->pos.entry_count; i++) {
    int64_t pos_val = counter->pos.entries[i].count;
    int64_t neg_val = 0;
    for (uint32_t j = 0; j < counter->neg.entry_count; j++) {
      if (strcmp(counter->pos.entries[i].node_id,
                  counter->neg.entries[j].node_id) == 0) {
        neg_val = counter->neg.entries[j].count;
        break;
      }
    }
    int64_t net = pos_val - neg_val;
    if (net > 0) {
      pn_counter_increment(visible, counter->pos.entries[i].node_id, net);
    }
  }

  // WARNING: After compaction, neg counter is discarded.
  // Previously decremented values can be re-incremented from zero.
  return visible;
}

void* crabs_pn_counter_rebuild_from_visible(const void* visible) {
  if (visible == NULL) return NULL;

  const pn_counter_t* src = (const pn_counter_t*)visible;
  pn_counter_t* result = pn_counter_create();
  if (result == NULL) return NULL;

  // Copy only positive entries (visible should have empty neg)
  for (uint32_t i = 0; i < src->pos.entry_count; i++) {
    pn_counter_increment(result, src->pos.entries[i].node_id,
                         src->pos.entries[i].count);
  }
  return result;
}

bool crabs_pn_counter_compaction_safe(const void* item, const state_t* state) {
  (void)state;
  if (item == NULL) return false;
  return true;
}

double crabs_pn_counter_estimated_savings(const void* item) {
  if (item == NULL) return 0.0;
  const pn_counter_t* counter = (const pn_counter_t*)item;
  uint64_t total = counter->pos.entry_count + counter->neg.entry_count;
  if (total == 0) return 0.0;
  return (double)counter->neg.entry_count / (double)total;
}

void crabs_pn_counter_describe_tombstones(const void* item, char* buf, uint32_t buf_size) {
  if (buf == NULL || buf_size == 0) return;
  buf[0] = '\0';
  if (item == NULL) {
    snprintf(buf, buf_size, "null pn-counter");
    return;
  }
  const pn_counter_t* counter = (const pn_counter_t*)item;
  snprintf(buf, buf_size, "PN-Counter: %u pos nodes, %u neg entries",
           (unsigned)counter->pos.entry_count,
           (unsigned)counter->neg.entry_count);
}

crabs_error_e crabs_register_pn_counter_vtable(crabs_compaction_registry_t* registry) {
  if (registry == NULL) return CRABS_ERR_INVALID_PARAM;

  static const crabs_compaction_vtable_t vtable = {
    .count_tombstones    = crabs_pn_counter_count_tombstones,
    .count_visible       = crabs_pn_counter_count_visible,
    .extract_visible     = crabs_pn_counter_extract_visible,
    .rebuild_from_visible = crabs_pn_counter_rebuild_from_visible,
    .compaction_safe     = crabs_pn_counter_compaction_safe,
    .estimated_savings   = crabs_pn_counter_estimated_savings,
    .describe_tombstones = crabs_pn_counter_describe_tombstones,
  };

  return crabs_compaction_register(registry, DATA_TYPE_PN_COUNTER, &vtable);
}

// ============================================================
// Register all built-in CRDT vtables
// ============================================================

crabs_error_e crabs_register_crdt_vtables(crabs_compaction_registry_t* registry) {
  if (registry == NULL) return CRABS_ERR_INVALID_PARAM;

  crabs_error_e err = crabs_register_or_set_vtable(registry);
  if (err != CRABS_SUCCESS) return err;

  err = crabs_register_two_p_set_vtable(registry);
  if (err != CRABS_SUCCESS) return err;

  err = crabs_register_g_counter_vtable(registry);
  if (err != CRABS_SUCCESS) return err;

  return crabs_register_pn_counter_vtable(registry);
}