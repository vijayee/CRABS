//
// Created by victor on 3/18/25.
//

#ifndef CRABS_REFCOUNTER_H
#define CRABS_REFCOUNTER_H

#include <stdint.h>
#include "../Util/threadding.h"

#define REFERENCE(N, T) (T*) refcounter_reference((refcounter_t*) N)
#define YIELD(N) refcounter_yield((refcounter_t*) N)
#define DEREFERENCE(N) refcounter_dereference((refcounter_t*) N); N = NULL
#define DESTROY(N, T)  T##_destroy(N); N = NULL
#define CONSUME(N, T)  (T*) refcounter_consume((refcounter_t**) &N)

typedef struct refcounter_t {
  uint16_t count;
  uint8_t yield;
} refcounter_t;

void refcounter_init(refcounter_t* refcounter);
void refcounter_yield(refcounter_t* refcounter);
void* refcounter_reference(refcounter_t* refcounter);
void refcounter_dereference(refcounter_t* refcounter);
refcounter_t* refcounter_consume(refcounter_t** refcounter);
uint16_t refcounter_count(refcounter_t* refcounter);
uint8_t refcounter_pending_derefs(refcounter_t* refcounter);
void refcounter_destroy_lock(refcounter_t* refcounter);

#endif // CRABS_REFCOUNTER_H
