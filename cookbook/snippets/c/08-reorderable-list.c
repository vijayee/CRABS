/* Recipe 8 — a reorderable list two people can edit at once (C core): the
 * OT_ORDERED_SET surface — apply INSERT/DELETE/MOVE/SWAP ops and merge two
 * divergent replicas into one deterministic order. The merge never invents
 * an "overwrite": concurrent inserts at the same position are both kept and
 * both replicas materialize the same converged sequence, a duplicated op id
 * with a conflicting payload refuses to merge at all, and a delete beats a
 * concurrent live element. No JS binding exposes any of this — the recipe's
 * wasm/node GAP blocks document that; here the C surface runs directly.
 * Mirrors the real test usage:
 *   test/test_ot_ordered_set.cpp:190-225  (MOVE re-positions elements)
 *   test/test_ot_ordered_set.cpp:347-375  (merge is commutative for
 *                                          concurrent singletons)
 *   test/test_ot_ordered_set.cpp:377-393  (conflicting payload on one op id
 *                                          refuses to merge, dest untouched)
 *   test/test_ot_ordered_set.cpp:395-420  (deletion wins on merge) */
#include "OT/ot_ordered_set.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Stack-allocated op scaffold: init, type, target position, op id, payload. */
static crabs_ot_operation_t make_operation(crabs_ot_op_type_e op_type,
                                           uint64_t visible_pos,
                                           const char* node_id,
                                           uint64_t sequence_num,
                                           uint64_t timestamp,
                                           const uint8_t* payload,
                                           uint32_t payload_size) {
  crabs_ot_operation_t op;
  crabs_ot_operation_init(&op);
  op.op_type = op_type;
  op.visible_pos = visible_pos;
  crabs_ot_op_id_init(&op.id, node_id, sequence_num, timestamp);
  if (payload != NULL && payload_size > 0) {
    assert(crabs_ot_operation_set_payload(&op, payload, payload_size));
  }
  return op;
}

/* The ops COPY their payload into the set's own element storage, so the
 * caller frees the scaffolding payload after every apply (same discipline
 * as op_payload_free in test/test_ot_ordered_set.cpp:20-26). */
static void op_payload_free(crabs_ot_operation_t* op) {
  free(op->payload);
  op->payload = NULL;
  op->payload_size = 0;
}

/* First payload byte of each visible element, in materialized order. */
static void visible_order(const crabs_ot_ordered_set_t* set,
                          char* out, uint32_t out_cap) {
  uint32_t used = 0;
  for (const crabs_ordered_element_t* element = crabs_ot_ordered_set_head(set);
       element != NULL && used + 1 < out_cap; element = element->next) {
    if (element->deleted) continue;
    out[used++] = element->value ? (char)element->value[0] : '?';
  }
  out[used] = '\0';
}

int main(void) {
  /* ---- Two replicas share one seed list: [a, b, c] ---- */
  crabs_ot_ordered_set_t* replica_local = crabs_ot_ordered_set_create();
  crabs_ot_ordered_set_t* replica_remote = crabs_ot_ordered_set_create();
  assert(replica_local != NULL && replica_remote != NULL);
  assert(crabs_ot_ordered_set_count(replica_local) == 0u);
  assert(replica_local->ot_data != NULL);  /* every set carries an op log +
                                              transform matrix (ot_types.h) */

  const uint8_t seed_values[3] = { 'a', 'b', 'c' };
  crabs_ot_operation_t seed_ops[3];
  for (unsigned int seed_index = 0; seed_index < 3; seed_index++) {
    seed_ops[seed_index] = make_operation(CRABS_OT_OP_INSERT, seed_index,
                                          "aaa", seed_index + 1, 1000,
                                          &seed_values[seed_index], 1);
    assert(crabs_ot_ordered_set_apply_insert(replica_local,
                                             &seed_ops[seed_index]) != NULL);
    assert(crabs_ot_ordered_set_apply_insert(replica_remote,
                                             &seed_ops[seed_index]) != NULL);
    op_payload_free(&seed_ops[seed_index]);
  }
  assert(crabs_ot_ordered_set_count(replica_local) == 3u);
  assert(crabs_ot_ordered_set_count(replica_remote) == 3u);
  assert(crabs_ot_ordered_set_visible_count(replica_local) == 3u);

  /* ---- Replica-local reorder: MOVE item 0 to the end. The op re-stamps
   * the placement of every element it knew, and the local list reflects
   * the move immediately (MoveElement, test_ot_ordered_set.cpp:190-225). */
  crabs_ot_operation_t move_op = make_operation(CRABS_OT_OP_MOVE, 0,
                                                "reorderer", 4, 1001,
                                                NULL, 0);
  move_op.visible_pos_2 = 2;
  assert(crabs_ot_ordered_set_apply_move(replica_local, &move_op) != NULL);

  /* [a, b, c] -move 0->2-> [b, c, a] */
  char local_order[16];
  visible_order(replica_local, local_order, sizeof(local_order));
  assert(strcmp(local_order, "bca") == 0);
  assert(crabs_ot_ordered_set_visible_count(replica_local) == 3u);
  printf("reorderable-list OK: local MOVE -> %s\n", local_order);

  /* ---- The other replica converges to the same order by merging: no
   * round-trip of the array, only the merged placement knowledge. Placement
   * winners are decided by deterministic op-id compare (node id bytes, then
   * sequence: ot_ordered_set.c:20-28) — the seed ops are named "aaa" so the
   * "reorderer" op's placements beat them deterministically, and BOTH
   * replicas (whichever merge direction) land on the same sequence with no
   * coordination. */
  assert(crabs_ot_ordered_set_merge(replica_remote, replica_local)
         == replica_remote);
  char converged_order[16];
  visible_order(replica_remote, converged_order,
                sizeof(converged_order));
  assert(strcmp(converged_order, local_order) == 0);
  assert(crabs_ot_ordered_set_count(replica_remote) == 3u);
  printf("reorderable-list OK: merge propagated the reorder -> %s\n",
         converged_order);

  /* ---- SWAP is a local value exchange of two positions
   * (SwapElements, test_ot_ordered_set.cpp:231-261): it is not a placement
   * op, so the demo runs it locally on the merged set rather than across
   * the merge — values of the two elements trade, ids stay put. */
  crabs_ot_operation_t swap_op = make_operation(CRABS_OT_OP_SWAP, 0,
                                                "reorderer", 5, 1002,
                                                NULL, 0);
  swap_op.visible_pos_2 = 2;
  assert(crabs_ot_ordered_set_apply_swap(replica_local, &swap_op) != NULL);
  char swapped_order[16];
  visible_order(replica_local, swapped_order, sizeof(swapped_order));
  assert(strcmp(swapped_order, "acb") == 0);
  printf("reorderable-list OK: local SWAP 0<->2 -> %s\n", swapped_order);

  crabs_ot_ordered_set_destroy(replica_local);
  crabs_ot_ordered_set_destroy(replica_remote);

  /* ---- Two members reorder at once: each inserts one item at the top of
   * the same seed list, offline from each other. Both items survive the
   * merge — nothing is silently overwritten — and both replicas materialize
   * the SAME deterministic order (MergeIsCommutativeForDistinctSingletons,
   * test_ot_ordered_set.cpp:347-375). */
  crabs_ot_ordered_set_t* replica_alice = crabs_ot_ordered_set_create();
  crabs_ot_ordered_set_t* replica_ben = crabs_ot_ordered_set_create();
  uint8_t priority_seed = 'm';
  crabs_ot_operation_t seed_both = make_operation(CRABS_OT_OP_INSERT, 0,
                                                  "aaa", 1, 2000,
                                                  &priority_seed, 1);
  assert(crabs_ot_ordered_set_apply_insert(replica_alice, &seed_both) != NULL);
  assert(crabs_ot_ordered_set_apply_insert(replica_ben, &seed_both) != NULL);
  op_payload_free(&seed_both);

  const uint8_t alice_value = 'p';
  const uint8_t ben_value = 'q';
  crabs_ot_operation_t alice_insert = make_operation(CRABS_OT_OP_INSERT, 0,
                                                     "node-a", 1, 3000,
                                                     &alice_value, 1);
  crabs_ot_operation_t ben_insert = make_operation(CRABS_OT_OP_INSERT, 0,
                                                   "node-b", 1, 3000,
                                                   &ben_value, 1);
  assert(crabs_ot_ordered_set_apply_insert(replica_alice, &alice_insert)
         != NULL);
  assert(crabs_ot_ordered_set_apply_insert(replica_ben, &ben_insert) != NULL);
  op_payload_free(&alice_insert);
  op_payload_free(&ben_insert);

  /* Cross-merge in BOTH directions; divergence must collapse to one order. */
  assert(crabs_ot_ordered_set_merge(replica_alice, replica_ben)
         == replica_alice);
  assert(crabs_ot_ordered_set_merge(replica_ben, replica_alice)
         == replica_ben);

  char alice_order[16];
  char ben_order[16];
  visible_order(replica_alice, alice_order, sizeof(alice_order));
  visible_order(replica_ben, ben_order, sizeof(ben_order));
  assert(strcmp(alice_order, ben_order) == 0);
  assert(strchr(alice_order, 'p') != NULL && strchr(alice_order, 'q') != NULL
         && strchr(alice_order, 'm') != NULL);
  assert(crabs_ot_ordered_set_count(replica_alice) == 3u);
  assert(crabs_ot_ordered_set_visible_count(replica_alice) == 3u);
  printf("reorderable-list OK: concurrent inserts both survive, both "
         "replicas converged -> %s\n", alice_order);

  crabs_ot_ordered_set_destroy(replica_alice);
  crabs_ot_ordered_set_destroy(replica_ben);

  /* ---- A duplicated op id whose payload DISAGREES refuses to merge —
   * replica keeps its own value, count and order whole
   * (MergeRejectsConflictingPayloadWithoutMutation,
   * test_ot_ordered_set.cpp:377-393). A last-writer-wins array would have
   * overwritten 'p' with 'q' silently; this merge returns NULL instead. */
  crabs_ot_ordered_set_t* replica_honest = crabs_ot_ordered_set_create();
  crabs_ot_ordered_set_t* replica_forged = crabs_ot_ordered_set_create();
  const uint8_t honest_value = 'p';
  const uint8_t forged_value = 'q';
  crabs_ot_operation_t honest_claim = make_operation(CRABS_OT_OP_INSERT, 0,
                                                     "duplicate-me", 1,
                                                     4000, &honest_value, 1);
  crabs_ot_operation_t forged_claim = make_operation(CRABS_OT_OP_INSERT, 0,
                                                     "duplicate-me", 1,
                                                     4000, &forged_value, 1);
  assert(crabs_ot_ordered_set_apply_insert(replica_honest, &honest_claim)
         != NULL);
  assert(crabs_ot_ordered_set_apply_insert(replica_forged, &forged_claim)
         != NULL);
  op_payload_free(&honest_claim);
  op_payload_free(&forged_claim);

  assert(crabs_ot_ordered_set_merge(replica_honest, replica_forged) == NULL);
  assert(crabs_ot_ordered_set_count(replica_honest) == 1u);
  char honest_order[16];
  visible_order(replica_honest, honest_order, sizeof(honest_order));
  assert(strcmp(honest_order, "p") == 0);
  printf("reorderable-list OK: conflicting payload on one op id refused to "
         "merge, replica kept -> %s\n", honest_order);

  crabs_ot_ordered_set_destroy(replica_honest);
  crabs_ot_ordered_set_destroy(replica_forged);

  /* ---- Deletion wins, and the merged tombstone positions travel through
   * the position map (merge_position_maps runs inside crabs_ot_ordered_set_merge,
   * ot_ordered_set.c:521) —
   * MergeDeletionWins, test_ot_ordered_set.cpp:395-420. */
  crabs_ot_ordered_set_t* replica_keeper = crabs_ot_ordered_set_create();
  crabs_ot_ordered_set_t* replica_eraser = crabs_ot_ordered_set_create();
  const uint8_t shared_value = 'd';
  crabs_ot_operation_t shared_item = make_operation(CRABS_OT_OP_INSERT, 0,
                                                    "aaa", 1, 5000,
                                                    &shared_value, 1);
  assert(crabs_ot_ordered_set_apply_insert(replica_keeper, &shared_item)
         != NULL);
  assert(crabs_ot_ordered_set_apply_insert(replica_eraser, &shared_item)
         != NULL);
  op_payload_free(&shared_item);

  crabs_ot_operation_t remove_op = make_operation(CRABS_OT_OP_DELETE, 0,
                                                  "aaa", 2, 5001, NULL, 0);
  assert(crabs_ot_ordered_set_apply_delete(replica_eraser, &remove_op)
         != NULL);

  crabs_ot_ordered_set_merge_position_maps(replica_keeper, replica_eraser);
  assert(crabs_ot_ordered_set_merge(replica_keeper, replica_eraser)
         == replica_keeper);
  crabs_ot_op_id_t shared_id;
  crabs_ot_op_id_init(&shared_id, "aaa", 1, 5000);
  const crabs_ordered_element_t* merged_element =
    crabs_ot_ordered_set_find(replica_keeper, &shared_id);
  assert(merged_element != NULL);
  assert(merged_element->deleted);  /* a delete beats a concurrent keep */
  assert(crabs_ot_ordered_set_visible_count(replica_keeper) == 0u);
  assert(crabs_ot_ordered_set_count(replica_keeper) == 1u); /* tombstone stays */
  printf("reorderable-list OK: deletion won through the merged position "
         "map\n");

  crabs_ot_ordered_set_destroy(replica_keeper);
  crabs_ot_ordered_set_destroy(replica_eraser);
  return 0;
}