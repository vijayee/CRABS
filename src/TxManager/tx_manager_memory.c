//
// tx_manager_memory.c — in-memory AVL-tree transaction manager.
//
// Stores operation UUIDs in a balanced AVL tree for O(log n) lookup with
// unbounded growth. No rehashing, no hash collisions, no capacity tuning.
//

#include "tx_manager_memory.h"
#include "avl_uuid.h"
#include "../Util/allocator.h"
#include <string.h>
#include <stdlib.h>

typedef struct {
  crabs_tx_manager_vtable_t vtable;
  crabs_avl_uuid_t* root;
  size_t             count;
  bool               seeded;  // durable-log seeding done (see _mem_accept)
} _tx_mem_t;

// ============================================================
// VTable callbacks
// ============================================================

static crabs_error_e _mem_accept(crabs_tx_manager_t* tx, state_t* state, const operation_t* op) {
  _tx_mem_t* m = (_tx_mem_t*)tx;
  // pass-3 LOW: the AVL set is volatile — across a restart, exactly-once
  // rested solely on the R7-11 watermark (ordering stamps, not uuids), and
  // an authorized signer re-signing the same uuid with a FRESH ordering
  // stamp slipped through. Seed once from the durable log at first accept
  // (every logged uuid IS an executed op); the vtable accept signature
  // carries `state` for exactly this reason (state_machine.c Step 3b).
  // Compaction-pruned log entries lose AVL coverage — there the watermark
  // stays the compaction-era backstop, so seeding is strictly WIDER
  // protection than before, never narrower.
  if (m->seeded == false && state->log_count > 0) {
    for (uint64_t log_index = 0; log_index < state->log_count; log_index++) {
      const log_entry_t* logged = &state->log[log_index];
      // Duplicate-flagged result ignored on seed, matching the accept path's
      // own duplicate handling (contains-then-insert elsewhere).
      m->root = crabs_avl_uuid_insert(m->root, logged->uuid, NULL);
    }
    m->seeded = true;
  }
  if (crabs_avl_uuid_contains(m->root, op->uuid)) {
    return CRABS_ERR_ALREADY_EXECUTED;
  }
  return CRABS_SUCCESS;
}

static void _mem_commit(crabs_tx_manager_t* tx, state_t* state, const operation_t* op) {
  (void)state;
  _tx_mem_t* m = (_tx_mem_t*)tx;
  bool inserted = false;
  m->root = crabs_avl_uuid_insert(m->root, op->uuid, &inserted);
  if (inserted) m->count++;
}

static void _mem_destroy(crabs_tx_manager_t* tx) {
  if (tx == NULL) return;
  _tx_mem_t* m = (_tx_mem_t*)tx;
  crabs_avl_uuid_destroy(m->root);
  free(m);
}

// ============================================================
// Public constructor
// ============================================================

crabs_tx_manager_t* crabs_tx_manager_memory(size_t initial_capacity) {
  (void)initial_capacity;  // AVL tree doesn't need pre-sizing
  _tx_mem_t* m = get_clear_memory(sizeof(_tx_mem_t));
  m->vtable.name = "memory";
  m->vtable.accept = _mem_accept;
  m->vtable.commit = _mem_commit;
  m->vtable.destroy = _mem_destroy;
  return (crabs_tx_manager_t*)m;
}
