//
// tx_manager.c — built-in transaction manager implementations.
//

#include "tx_manager.h"
#include "../Util/allocator.h"
#include <stdlib.h>

// ============================================================
// None: accept everything
// ============================================================

static crabs_error_e _none_accept(crabs_tx_manager_t* tx, state_t* state, const operation_t* op) {
  (void)tx;
  (void)state;
  (void)op;
  return CRABS_SUCCESS;
}

static void _none_commit(crabs_tx_manager_t* tx, state_t* state, const operation_t* op) {
  (void)tx;
  (void)state;
  (void)op;
}

static void _none_destroy(crabs_tx_manager_t* tx) {
  if (tx) free(tx);
}

crabs_tx_manager_t* crabs_tx_manager_none(void) {
  crabs_tx_manager_t* tx = get_clear_memory(sizeof(crabs_tx_manager_t));
  tx->vtable.name = "none";
  tx->vtable.accept = _none_accept;
  tx->vtable.commit = _none_commit;
  tx->vtable.destroy = _none_destroy;
  return tx;
}
