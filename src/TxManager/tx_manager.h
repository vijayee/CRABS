//
// tx_manager.h — pluggable transaction manager for replay protection.
//
// The transaction manager sits in front of the state machine and handles
// transport-level concerns: "have I seen this operation before?" Different
// deployments can use different strategies (in-memory, persistent, no-op)
// without changing the state machine core.
//

#ifndef CRABS_TX_MANAGER_H
#define CRABS_TX_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "../StateMachine/state_machine.h"

typedef struct crabs_tx_manager_t crabs_tx_manager_t;

typedef struct {
  const char* name;
  // Check if an operation should be accepted. Returns CRABS_SUCCESS if new,
  // CRABS_ERR_ALREADY_EXECUTED if duplicate (caller treats as idempotent).
  crabs_error_e (*accept)(crabs_tx_manager_t* tx, state_t* state, const operation_t* op);
  // Commit: the operation was successfully executed. Record it for future
  // duplicate detection.
  void (*commit)(crabs_tx_manager_t* tx, state_t* state, const operation_t* op);
  // Destroy and free all resources.
  void (*destroy)(crabs_tx_manager_t* tx);
} crabs_tx_manager_vtable_t;

struct crabs_tx_manager_t {
  crabs_tx_manager_vtable_t vtable;
};

// Accept everything — no tracking, no memory. For deployments that handle
// replay protection at the transport layer.
crabs_tx_manager_t* crabs_tx_manager_none(void);

#endif // CRABS_TX_MANAGER_H
