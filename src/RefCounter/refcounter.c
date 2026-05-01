//
// Created by victor on 3/18/25.
//
#include "refcounter.h"
#include <stdint.h>
#include <limits.h>

void refcounter_init(refcounter_t* refcounter) {
  refcounter->count = 1;
  refcounter->yield = 0;
}

void refcounter_yield(refcounter_t* refcounter) {
  __atomic_add_fetch(&refcounter->yield, 1, __ATOMIC_RELAXED);
}

void* refcounter_reference(refcounter_t* refcounter) {
  if (refcounter == NULL) {
    return NULL;
  }
  if (__atomic_load_n(&refcounter->yield, __ATOMIC_RELAXED) > 0) {
    __atomic_fetch_sub(&refcounter->yield, 1, __ATOMIC_RELAXED);
  } else {
    __atomic_fetch_add(&refcounter->count, 1, __ATOMIC_RELAXED);
  }
  return refcounter;
}

void refcounter_dereference(refcounter_t* refcounter) {
  if ((__atomic_load_n(&refcounter->yield, __ATOMIC_RELAXED) == 0) &&
      (__atomic_load_n(&refcounter->count, __ATOMIC_RELAXED) > 0)) {
    __atomic_fetch_sub(&refcounter->count, 1, __ATOMIC_RELAXED);
  }
}

uint16_t refcounter_count(refcounter_t* refcounter) {
  return __atomic_load_n(&refcounter->count, __ATOMIC_RELAXED);
}

uint8_t refcounter_pending_derefs(refcounter_t* refcounter) {
  (void) refcounter;
  return 0;
}

refcounter_t* refcounter_consume(refcounter_t** refcounter) {
  refcounter_t* holder = *refcounter;
  refcounter_yield(holder);
  *refcounter = NULL;
  return holder;
}

void refcounter_destroy_lock(refcounter_t* refcounter) {
  (void) refcounter;
}
