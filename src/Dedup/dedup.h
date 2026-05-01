//
// CRABS v1.4: DedupSpec & Desugaring (§3-4)
//

#ifndef CRABS_DEDUP_H
#define CRABS_DEDUP_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "../StateMachine/state_machine.h"
#include "../CRDT/one_shot.h"

// ============================================================
// Dedup Guard Check (§5.2)
// ============================================================

// Check the dedup guard before operation execution.
// Returns CRABS_SUCCESS if the guard passes, or an appropriate error code.
crabs_error_e dedup_check_guard(const state_t* state, const operation_t* op);

// ============================================================
// Dedup State Mutation (§5.3)
// ============================================================

// Apply the dedup state mutation after successful operation execution.
// Returns CRABS_SUCCESS on success.
crabs_error_e dedup_apply_mutation(state_t* state, const operation_t* op);

// ============================================================
// Desugaring helpers
// ============================================================

// Build a policy guard string from a DedupSpec.
// Caller must free the returned string.
// Returns NULL on error or if dedup.type == DEDUP_NONE.
char* dedup_build_policy_guard(const dedup_spec_t* dedup, const char* signer_id);

// Resolve a path like "proposal_42.voters" to a data_item_t in the state.
// The path is dot-separated: "item_name" or "item_name.field".
data_item_t* dedup_resolve_path(state_t* state, const char* path);

#endif // CRABS_DEDUP_H