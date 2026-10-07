//
// Lineage (v1.7: machines mint machines) — blueprint data types + validation.
// Spawn execution, attestations, and lineage ops land with later tasks; this
// header is the serializable data layer every other lineage module builds on.
//

#ifndef CRABS_LINEAGE_H
#define CRABS_LINEAGE_H

#include <stdint.h>
#include "../CRABS/data_model.h"

// Blueprint payload caps. Items and policies use a generic 64-entry ceiling;
// op type definitions are capped at the tighter of that ceiling and the state
// registry's CRABS_MAX_OP_TYPE_DEFS (32) — a blueprint defining more than 32
// could never be applied to a machine.
#define CRABS_MAX_BLUEPRINT_ITEMS        64
#define CRABS_MAX_BLUEPRINT_POLICIES     64
#define CRABS_MAX_BLUEPRINT_OP_TYPE_DEFS 32

// Cross-domain endorsement wire version (spec §attestation bridge).
// Independent of key_envelope_t's 0x03.
#define CRABS_ATTESTATION_FORMAT_VERSION 0x01

// One blueprint data item: name + data type + CRDT strategy.
typedef struct {
  char        name[CRABS_MAX_USER_ID];
  data_type_e type;
  crdt_type_e crdt_type;
} blueprint_item_t;

// One blueprint policy: the op it guards + its authorization expression.
typedef struct {
  char operation[CRABS_MAX_OP_NAME];
  char expression[CRABS_MAX_POLICY_EXPR];
} blueprint_policy_t;

// One blueprint operation type definition: op type name + dedup spec.
typedef struct {
  char         op_type[CRABS_MAX_OP_NAME];
  dedup_spec_t dedup;
} blueprint_op_type_def_t;

// Cross-domain endorsement (spec §attestation bridge): a parent-signed,
// TTL-bounded attribute grant a spawned child resolves against.
typedef struct {
  uint8_t  format_version;
  char     parent_id[CRABS_MAX_USER_ID];
  char     child_id[CRABS_MAX_USER_ID];
  char     user_id[CRABS_MAX_USER_ID];
  char     attributes[CRABS_MAX_POLICY_EXPR];   // comma-separated name:value pairs
  uint64_t not_before;
  uint64_t expires_at;                            // not_before + ttl <= expires_at
  uint8_t  signature[CRABS_SIG_SIZE];             // parent ECDSA over canonical body
} attestation_t;

// Blueprint: a fully serializable machine definition a parent machine
// instantiates via the __spawn_machine__ op.
typedef struct {
  char                 child_id[CRABS_MAX_USER_ID];
  lineage_trust_mode_e trust_mode;
  char                 bootstrap_admin[CRABS_MAX_USER_ID];
  uint64_t             attestation_ttl_ms;
  blueprint_item_t*    items;
  uint32_t             item_count;
  blueprint_policy_t*  policies;
  uint32_t             policy_count;
  blueprint_op_type_def_t* op_type_defs;
  uint32_t             op_type_def_count;
  // SHA-256 of the canonical serialized blueprint body, stamped at build
  // time by the blueprint wire-format task.
  uint8_t              blueprint_hash[CRABS_HASH_SIZE];
} machine_blueprint_t;

// Heap-allocate an empty blueprint (children arrays start NULL; grown by the
// blueprint_add_* helpers).
machine_blueprint_t* machine_blueprint_create(void);
void                 machine_blueprint_destroy(machine_blueprint_t* blueprint);

// Append helpers. Each enforces the corresponding blueprint cap and the id
// safety rules, returning CRABS_ERR_INVALID_PARAM on structural garbage,
// CRABS_ERR_DUPLICATE_OPERATION on a duplicate item name, and
// CRABS_ERR_UNAUTHORIZED for an unparseable policy expression.
// `dedup` is copied by value into the blueprint.
crabs_error_e blueprint_add_item(machine_blueprint_t* blueprint,
                                 const char* name, data_type_e type,
                                 crdt_type_e crdt_type);
crabs_error_e blueprint_add_policy(machine_blueprint_t* blueprint,
                                   const char* operation,
                                   const char* expression);
crabs_error_e blueprint_add_op_type_def(machine_blueprint_t* blueprint,
                                        const char* op_type,
                                        const dedup_spec_t* dedup);

// Full structural validation of a blueprint ahead of a spawn:
//   - child_id non-empty, safe charset (attribute_machine_is_safe_user_id),
//     within CRABS_MAX_USER_ID
//   - trust_mode within the lineage_trust_mode_e enum
//   - bootstrap_admin safe; non-empty required for DELEGATED_COPY/SOVEREIGN
//     (a fresh authority must have someone to mint its first roles;
//     SHARED_ROOT children borrow the parent's authority, so an empty
//     bootstrap admin is acceptable there)
//   - per-policy expression parseability (condition grammar or bare
//     name:value attribute token family)
//   - item names safe + unique; counts within the blueprint caps above
//   - operation/op_type names non-empty and within their capacity
crabs_error_e lineage_blueprint_validate(const machine_blueprint_t* blueprint);

#endif // CRABS_LINEAGE_H