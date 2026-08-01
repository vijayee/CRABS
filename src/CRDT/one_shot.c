//
// CRABS v1.4: ONE_SHOT_SET & ONE_SHOT_FLAG Data Types (§2)
//

#include "one_shot.h"
#include "../Util/allocator.h"
#include <string.h>
#include <stdlib.h>

// ============================================================
// ONE_SHOT_SET (v1.4 §2.1)
// ============================================================

one_shot_set_t* one_shot_set_create(void) {
  one_shot_set_t* set = get_clear_memory(sizeof(one_shot_set_t));
  set->elements = NULL;
  set->element_count = 0;
  return set;
}

void one_shot_set_destroy(one_shot_set_t* set) {
  if (set == NULL) return;
  for (uint32_t i = 0; i < set->element_count; i++) {
    free(set->elements[i]);
  }
  if (set->elements != NULL) free(set->elements);
  free(set);
}

crabs_error_e one_shot_set_add(one_shot_set_t* set, const char* element) {
  if (set == NULL || element == NULL) return CRABS_ERR_INVALID_PARAM;

  // Idempotent: if already present, no-op
  if (one_shot_set_contains(set, element)) return CRABS_SUCCESS;

  if (set->element_count >= CRABS_ONE_SHOT_SET_MAX) return CRABS_ERR_OOM;

  uint32_t new_count = set->element_count + 1;
  char** new_elements = realloc(set->elements, new_count * sizeof(char*));
  if (new_elements == NULL) return CRABS_ERR_OOM;
  set->elements = new_elements;
  char* dup = strdup(element);
  if (dup == NULL) return CRABS_ERR_OOM;
  set->elements[set->element_count] = dup;
  set->element_count = new_count;
  return CRABS_SUCCESS;
}

bool one_shot_set_contains(const one_shot_set_t* set, const char* element) {
  if (set == NULL || element == NULL) return false;
  for (uint32_t i = 0; i < set->element_count; i++) {
    if (strcmp(set->elements[i], element) == 0) return true;
  }
  return false;
}

uint32_t one_shot_set_count(const one_shot_set_t* set) {
  if (set == NULL) return 0;
  return set->element_count;
}

// Comparator for qsort over C strings (strcmp wrapper).
static int _cmp_str(const void* x, const void* y) {
  const char* const* a = (const char* const*)x;
  const char* const* b = (const char* const*)y;
  return strcmp(*a, *b);
}

one_shot_set_t* one_shot_set_merge(const one_shot_set_t* a, const one_shot_set_t* b) {
  if (a == NULL && b == NULL) return NULL;

  one_shot_set_t* result = one_shot_set_create();

  // Audit M-F: when the union exceeds CRABS_ONE_SHOT_SET_MAX, the prior code
  // added a's elements then b's (dropping the overflow silently), so the
  // surviving subset depended on argument order — merge(A,B) != merge(B,A).
  // Collect the union, sort lexicographically, and keep the first MAX. The
  // sort is a total order, so both replicas converge on the same subset.
  const one_shot_set_t* sources[2] = {a, b};
  uint32_t total = 0;
  for (int s = 0; s < 2; s++) {
    if (sources[s] != NULL) total += sources[s]->element_count;
  }

  char** union_elems = NULL;
  if (total > 0) {
    union_elems = (char**)get_clear_memory(sizeof(char*) * total);
    if (union_elems == NULL) return result; // OOM — return empty set
  }
  uint32_t ucount = 0;
  for (int s = 0; s < 2; s++) {
    if (sources[s] == NULL) continue;
    for (uint32_t i = 0; i < sources[s]->element_count; i++) {
      const char* e = sources[s]->elements[i];
      bool dup = false;
      for (uint32_t j = 0; j < ucount; j++) {
        if (strcmp(union_elems[j], e) == 0) { dup = true; break; }
      }
      if (!dup) union_elems[ucount++] = (char*)e;
    }
  }
  qsort(union_elems, ucount, sizeof(char*), _cmp_str);

  uint32_t keep = (ucount < CRABS_ONE_SHOT_SET_MAX) ? ucount : CRABS_ONE_SHOT_SET_MAX;
  for (uint32_t i = 0; i < keep; i++) {
    one_shot_set_add(result, union_elems[i]);
  }

  if (union_elems != NULL) free(union_elems);
  return result;
}

// ============================================================
// ONE_SHOT_FLAG (v1.4 §2.2)
// ============================================================

one_shot_flag_t* one_shot_flag_create(void) {
  one_shot_flag_t* flag = get_clear_memory(sizeof(one_shot_flag_t));
  flag->value = false;
  flag->set_by[0] = '\0';
  flag->set_at = 0;
  return flag;
}

void one_shot_flag_destroy(one_shot_flag_t* flag) {
  if (flag == NULL) return;
  free(flag);
}

crabs_error_e one_shot_flag_set(one_shot_flag_t* flag, const char* set_by, uint64_t set_at) {
  if (flag == NULL || set_by == NULL) return CRABS_ERR_INVALID_PARAM;

  // Once set to true, it stays true (idempotent)
  if (flag->value) return CRABS_SUCCESS;

  flag->value = true;
  strncpy(flag->set_by, set_by, CRABS_MAX_USER_ID - 1);
  flag->set_by[CRABS_MAX_USER_ID - 1] = '\0';
  flag->set_at = set_at;
  return CRABS_SUCCESS;
}

bool one_shot_flag_value(const one_shot_flag_t* flag) {
  if (flag == NULL) return false;
  return flag->value;
}

one_shot_flag_t* one_shot_flag_merge(const one_shot_flag_t* a, const one_shot_flag_t* b) {
  if (a == NULL && b == NULL) return NULL;

  one_shot_flag_t* result = one_shot_flag_create();

  // OR-dominates: if either is true, result is true
  // If both are true, earlier timestamp wins; on tie, lexicographic node_id
  if (a == NULL || !a->value) {
    if (b != NULL && b->value) {
      result->value = true;
      strncpy(result->set_by, b->set_by, CRABS_MAX_USER_ID - 1);
      result->set_at = b->set_at;
    }
  } else if (b == NULL || !b->value) {
    result->value = true;
    strncpy(result->set_by, a->set_by, CRABS_MAX_USER_ID - 1);
    result->set_at = a->set_at;
  } else {
    // Both true: keep the earlier setter
    if (a->set_at < b->set_at) {
      result->value = true;
      strncpy(result->set_by, a->set_by, CRABS_MAX_USER_ID - 1);
      result->set_at = a->set_at;
    } else if (b->set_at < a->set_at) {
      result->value = true;
      strncpy(result->set_by, b->set_by, CRABS_MAX_USER_ID - 1);
      result->set_at = b->set_at;
    } else {
      // Tie: lexicographic comparison of set_by
      if (strcmp(a->set_by, b->set_by) <= 0) {
        result->value = true;
        strncpy(result->set_by, a->set_by, CRABS_MAX_USER_ID - 1);
        result->set_at = a->set_at;
      } else {
        result->value = true;
        strncpy(result->set_by, b->set_by, CRABS_MAX_USER_ID - 1);
        result->set_at = b->set_at;
      }
    }
  }

  return result;
}