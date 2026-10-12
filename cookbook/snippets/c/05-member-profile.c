/* Recipe 5 — a member's own profile they control (C core).
 *
 * The LWW register carries ARBITRARY bytes natively, so a display-name
 * profile is exactly what the C core was built for: two replicas hold the
 * same member's register, both update it concurrently, and lww_register_merge
 * converges on the NEWEST write (earlier ties break by node id, higher
 * lexicographic id wins) — mirroring test/test_crdt.cpp:485-519. */
#include "CRDT/crdt_merge.h"
#include "CRABS/crabs.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  /* Replica A: alice, seen last at ts 100. */
  lww_register_t* replica_a = lww_register_create(
      (const uint8_t*)"Vic Morrow", 10, (uint64_t)100, "node-a");
  assert(replica_a != NULL);
  assert(replica_a->value_size == 10u);
  assert(strcmp((const char*)replica_a->value, "Vic Morrow") == 0);

  /* Replica B updated alice's profile later (its HLC clock is ahead). */
  lww_register_t* replica_b = lww_register_create(
      (const uint8_t*)"V. Morrow", 9, (uint64_t)200, "node-b");
  assert(replica_b != NULL);

  lww_register_t* merged = lww_register_merge(replica_a, replica_b);
  assert(merged != NULL);
  assert(merged->timestamp == (uint64_t)200);
  assert(merged->value_size == 9u);
  assert(strcmp((const char*)merged->value, "V. Morrow") == 0);
  assert(strcmp(merged->node_id, "node-b") == 0);
  printf("profile OK: newest write wins after merge\n");

  /* Another member's profile is a SEPARATE item — bob's register merges
   * independently of alice's; there is one register per member. */
  lww_register_t* bobs_a = lww_register_create(
      (const uint8_t*)"B. Okafor", 9, (uint64_t)100, "node-a");
  lww_register_t* bobs_b = lww_register_create(
      (const uint8_t*)"Bob Okafor", 10, (uint64_t)150, "node-b");
  lww_register_t* bobs = lww_register_merge(bobs_a, bobs_b);
  assert(bobs != NULL);
  assert(strcmp((const char*)bobs->value, "Bob Okafor") == 0);
  printf("profile OK: per-member registers merge independently\n");

  /* Tie-breaker: identical timestamps resolve by node id, deterministic on
   * every replica (no split-brain display names). */
  lww_register_t* tie_a = lww_register_create(
      (const uint8_t*)"tie-ALPHA", 9, (uint64_t)300, "node-a");
  lww_register_t* tie_b = lww_register_create(
      (const uint8_t*)"tie-BETA", 8, (uint64_t)300, "node-b");
  lww_register_t* tie = lww_register_merge(tie_a, tie_b);
  assert(tie != NULL);
  assert(strcmp(tie->node_id, "node-b") == 0);
  assert(strcmp((const char*)tie->value, "tie-BETA") == 0);
  printf("profile OK: tie broken deterministically by node id\n");

  lww_register_destroy(tie);
  lww_register_destroy(tie_b);
  lww_register_destroy(tie_a);
  lww_register_destroy(bobs);
  lww_register_destroy(bobs_b);
  lww_register_destroy(bobs_a);
  lww_register_destroy(merged);
  lww_register_destroy(replica_b);
  lww_register_destroy(replica_a);
  return 0;
}