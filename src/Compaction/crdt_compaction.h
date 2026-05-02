//
// Created by victor on 5/2/25.
//
// CRDT Compaction VTables (v1.5.2 §3.1-3.2)
// Compaction support for OR-Set and 2P-Set CRDT types.
//

#ifndef CRABS_CRDT_COMPACTION_H
#define CRABS_CRDT_COMPACTION_H

#include "compaction.h"
#include "../CRDT/crdt_merge.h"

// ============================================================
// OR-Set Compaction VTable (v1.5.2 §3.1)
// ============================================================

// Count tombstoned entries in an OR-Set
uint64_t crabs_or_set_count_tombstones(const void* item);

// Count visible (non-tombstoned) entries in an OR-Set
uint64_t crabs_or_set_count_visible(const void* item);

// Extract visible entries from an OR-Set (without tombstones)
void* crabs_or_set_extract_visible(const void* item);

// Rebuild an OR-Set from visible-only entries
void* crabs_or_set_rebuild_from_visible(const void* visible);

// Check if compaction is safe for an OR-Set
bool crabs_or_set_compaction_safe(const void* item, const state_t* state);

// Estimate savings ratio for an OR-Set
double crabs_or_set_estimated_savings(const void* item);

// Describe tombstones in an OR-Set
void crabs_or_set_describe_tombstones(const void* item, char* buf, uint32_t buf_size);

// Register the OR-Set compaction vtable
crabs_error_e crabs_register_or_set_vtable(crabs_compaction_registry_t* registry);

// ============================================================
// 2P-Set Compaction VTable (v1.5.2 §3.2)
// ============================================================

// Count removed entries in a 2P-Set (tombstones)
uint64_t crabs_two_p_set_count_tombstones(const void* item);

// Count visible entries in a 2P-Set (in add_set but not in remove_set)
uint64_t crabs_two_p_set_count_visible(const void* item);

// Extract visible entries from a 2P-Set (add_set minus remove_set, empty remove_set)
void* crabs_two_p_set_extract_visible(const void* item);

// Rebuild a 2P-Set from visible entries
void* crabs_two_p_set_rebuild_from_visible(const void* visible);

// Check if compaction is safe for a 2P-Set
bool crabs_two_p_set_compaction_safe(const void* item, const state_t* state);

// Estimate savings ratio for a 2P-Set
double crabs_two_p_set_estimated_savings(const void* item);

// Describe tombstones in a 2P-Set
void crabs_two_p_set_describe_tombstones(const void* item, char* buf, uint32_t buf_size);

// Register the 2P-Set compaction vtable
crabs_error_e crabs_register_two_p_set_vtable(crabs_compaction_registry_t* registry);

// Register all built-in CRDT compaction vtables
crabs_error_e crabs_register_crdt_vtables(crabs_compaction_registry_t* registry);

// ============================================================
// G-Counter Compaction VTable (v1.5.2 §3.3 — counter variant)
// ============================================================

uint64_t crabs_g_counter_count_tombstones(const void* item);
uint64_t crabs_g_counter_count_visible(const void* item);
void* crabs_g_counter_extract_visible(const void* item);
void* crabs_g_counter_rebuild_from_visible(const void* visible);
bool crabs_g_counter_compaction_safe(const void* item, const state_t* state);
double crabs_g_counter_estimated_savings(const void* item);
void crabs_g_counter_describe_tombstones(const void* item, char* buf, uint32_t buf_size);
crabs_error_e crabs_register_g_counter_vtable(crabs_compaction_registry_t* registry);

// ============================================================
// PN-Counter (RGA) Compaction VTable (v1.5.2 §3.3)
// ============================================================

uint64_t crabs_pn_counter_count_tombstones(const void* item);
uint64_t crabs_pn_counter_count_visible(const void* item);
void* crabs_pn_counter_extract_visible(const void* item);
void* crabs_pn_counter_rebuild_from_visible(const void* visible);
bool crabs_pn_counter_compaction_safe(const void* item, const state_t* state);
double crabs_pn_counter_estimated_savings(const void* item);
void crabs_pn_counter_describe_tombstones(const void* item, char* buf, uint32_t buf_size);
crabs_error_e crabs_register_pn_counter_vtable(crabs_compaction_registry_t* registry);

#endif // CRABS_CRDT_COMPACTION_H