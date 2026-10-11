/* Recipe 1 — a shared count that can't be double-counted (C, native). */
#include "CRDT/crdt_merge.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
  g_counter_t* counter = g_counter_create();
  assert(counter != NULL);

  /* Two workers log the same "open" event from the same node. */
  assert(g_counter_increment(counter, "node-1", 1) == CRABS_SUCCESS);
  assert(g_counter_increment(counter, "node-1", 1) == CRABS_SUCCESS);

  const int64_t opens = g_counter_value(counter);
  printf("opens=%lld\n", (long long)opens);
  assert(opens == 2);

  /* Merge property: two nodes counting separately converge without
   * double-counting the events they both recorded. */
  g_counter_t* remote = g_counter_create();
  assert(remote != NULL);
  assert(g_counter_increment(counter, "node-1", 1) == CRABS_SUCCESS);
  assert(g_counter_increment(remote, "node-2", 1) == CRABS_SUCCESS);
  assert(g_counter_increment(remote, "node-2", 1) == CRABS_SUCCESS);

  g_counter_t* merged = g_counter_merge(counter, remote);
  assert(merged != NULL);
  /* node-1 saw 3 opens, node-2 saw 2; merge keeps the max per node. */
  const int64_t converged = g_counter_value(merged);
  printf("converged=%lld\n", (long long)converged);
  assert(converged == 5);

  g_counter_destroy(merged);
  g_counter_destroy(remote);
  g_counter_destroy(counter);
  return 0;
}