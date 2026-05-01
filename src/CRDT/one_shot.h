//
// CRABS v1.4: ONE_SHOT_SET & ONE_SHOT_FLAG Data Types (§2)
//

#ifndef CRABS_ONE_SHOT_H
#define CRABS_ONE_SHOT_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"

// ============================================================
// ONE_SHOT_SET (v1.4 §2.1)
// Add-only set with idempotent add, contains, count.
// CRDT merge = union of add sets.
// ============================================================
#define CRABS_ONE_SHOT_SET_MAX  256

typedef struct {
  char**   elements;
  uint32_t element_count;
} one_shot_set_t;

one_shot_set_t* one_shot_set_create(void);
void            one_shot_set_destroy(one_shot_set_t* set);
crabs_error_e   one_shot_set_add(one_shot_set_t* set, const char* element);
bool            one_shot_set_contains(const one_shot_set_t* set, const char* element);
uint32_t        one_shot_set_count(const one_shot_set_t* set);
one_shot_set_t* one_shot_set_merge(const one_shot_set_t* a, const one_shot_set_t* b);

// ============================================================
// ONE_SHOT_FLAG (v1.4 §2.2)
// Boolean flag that transitions false→true exactly once.
// Tracks set_by (who set it) and set_at (when).
// CRDT merge = OR-dominates (true wins).
// ============================================================
typedef struct {
  bool     value;
  char     set_by[CRABS_MAX_USER_ID];
  uint64_t set_at;
} one_shot_flag_t;

one_shot_flag_t* one_shot_flag_create(void);
void             one_shot_flag_destroy(one_shot_flag_t* flag);
crabs_error_e    one_shot_flag_set(one_shot_flag_t* flag, const char* set_by, uint64_t set_at);
bool             one_shot_flag_value(const one_shot_flag_t* flag);
one_shot_flag_t* one_shot_flag_merge(const one_shot_flag_t* a, const one_shot_flag_t* b);

#endif // CRABS_ONE_SHOT_H