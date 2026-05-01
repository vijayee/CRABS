//
// Created by victor on 4/30/25.
//

#ifndef CRABS_CRDT_MERGE_H
#define CRABS_CRDT_MERGE_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "one_shot.h"

// ============================================================
// G-Counter (12.2.1)
// ============================================================
typedef struct {
  char     node_id[CRABS_MAX_USER_ID];
  int64_t  count;
} g_counter_entry_t;

typedef struct {
  g_counter_entry_t* entries;
  uint32_t           entry_count;
} g_counter_t;

g_counter_t*  g_counter_create(void);
void           g_counter_destroy(g_counter_t* counter);
crabs_error_e  g_counter_increment(g_counter_t* counter, const char* node_id, int64_t delta);
int64_t        g_counter_value(const g_counter_t* counter);
g_counter_t*   g_counter_merge(const g_counter_t* a, const g_counter_t* b);

// ============================================================
// PN-Counter (12.2.2)
// ============================================================
typedef struct {
  g_counter_t pos;
  g_counter_t neg;
} pn_counter_t;

pn_counter_t*  pn_counter_create(void);
void            pn_counter_destroy(pn_counter_t* counter);
crabs_error_e  pn_counter_increment(pn_counter_t* counter, const char* node_id, int64_t delta);
crabs_error_e  pn_counter_decrement(pn_counter_t* counter, const char* node_id, int64_t delta);
int64_t         pn_counter_value(const pn_counter_t* counter);
pn_counter_t*   pn_counter_merge(const pn_counter_t* a, const pn_counter_t* b);

// ============================================================
// OR-Set (12.2.3)
// ============================================================
typedef struct {
  char* element;
  char* tag;  // unique tag: "node_id:counter"
} or_set_entry_t;

typedef struct {
  or_set_entry_t* elements;
  uint32_t        element_count;
  or_set_entry_t* tombstones;
  uint32_t        tombstone_count;
} or_set_t;

or_set_t*      or_set_create(void);
void           or_set_destroy(or_set_t* set);
crabs_error_e  or_set_add(or_set_t* set, const char* element, const char* tag);
crabs_error_e  or_set_remove(or_set_t* set, const char* element);
bool           or_set_contains(const or_set_t* set, const char* element);
or_set_t*      or_set_merge(const or_set_t* a, const or_set_t* b);

// ============================================================
// 2P-Set (12.2.4)
// ============================================================
typedef struct {
  char**   add_set;
  uint32_t add_count;
  char**   remove_set;
  uint32_t remove_count;
} two_p_set_t;

two_p_set_t*   two_p_set_create(void);
void            two_p_set_destroy(two_p_set_t* set);
crabs_error_e  two_p_set_add(two_p_set_t* set, const char* element);
crabs_error_e  two_p_set_remove(two_p_set_t* set, const char* element);
bool            two_p_set_contains(const two_p_set_t* set, const char* element);
two_p_set_t*   two_p_set_merge(const two_p_set_t* a, const two_p_set_t* b);

// ============================================================
// LWW-Register (12.2.5)
// ============================================================
typedef struct {
  uint8_t* value;
  uint32_t value_size;
  uint64_t timestamp;
  char     node_id[CRABS_MAX_USER_ID];
} lww_register_t;

lww_register_t* lww_register_create(const uint8_t* value, uint32_t size, uint64_t timestamp, const char* node_id);
void             lww_register_destroy(lww_register_t* reg);
lww_register_t*  lww_register_merge(const lww_register_t* a, const lww_register_t* b);

// ============================================================
// State-level merge (12.1)
// ============================================================
crabs_error_e crdt_merge_state(state_t* dst, const state_t* src);

// ============================================================
// Per-value merge dispatch
// ============================================================
void* crdt_merge_value(data_type_e type, crdt_type_e crdt_type,
                       void* value_a, void* value_b,
                       const char* node_id_a, const char* node_id_b);

#endif // CRABS_CRDT_MERGE_H