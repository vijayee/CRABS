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

// Canonical attestation body cap. The worst-case body (lineage.c's
// canonical writer) is 1 + 3*(2+63) + (2+255) + 16 = 469 bytes; the cap
// gives headroom. The wire image adds a u32le length prefix and the 64-byte
// signature on top.
#define CRABS_ATTESTATION_BODY_MAX  512
#define CRABS_ATTESTATION_WIRE_MAX  (4 + CRABS_ATTESTATION_BODY_MAX + CRABS_SIG_SIZE)

// Canonical blueprint body cap. The worst-case body (lineage.c's
// _blueprint_write_body) is 1 + 2*(2+63) + 8 + 4 + 64*(2+63+2) + 4 +
// 64*(2+63+2+255) + 4 + 32*(2+63+1567) = 77271 bytes, where 1567 is the
// worst-case dedup_spec image (1 + 2*(2+127) + (2+255) + 1 + 2*(2+127) +
// (2+63) + 2*(2+127) + 8 + (2+255) — mirroring serialization.c's
// _serialize_dedup_spec). The wire image adds a u32le length prefix and the
// 32-byte blueprint hash on top.
#define CRABS_BLUEPRINT_BODY_MAX  81920
#define CRABS_BLUEPRINT_WIRE_MAX  (4 + CRABS_BLUEPRINT_BODY_MAX + CRABS_HASH_SIZE)

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

// ============================================================
// Blueprint wire format: stamp / serialize / deserialize
// ============================================================

// Compute blueprint->blueprint_hash = SHA-256 of the canonical blueprint body
// (every section EXCEPT the hash itself, written by the single shared body
// writer — the same layout attestation signing uses). Returns
// CRABS_ERR_INVALID_PARAM when a fixed-capacity string field is unterminated
// (no reproducible canonical body) or the writer overflows its cap.
// blueprint_serialize calls this internally, so a serialized image always
// carries a hash matching its body; direct callers keep hand-built
// blueprints honest before persisting or signing them.
crabs_error_e machine_blueprint_stamp_hash(machine_blueprint_t* blueprint);

// Wire image: u32le total length (body + hash, EXCLUDING the prefix itself)
// + canonical body + 32-byte blueprint hash. Stamps the hash first, so the
// caller never has to. Returns bytes written, or 0 on overflow/capacity-full
// string fields.
size_t blueprint_serialize(machine_blueprint_t* blueprint,
                           uint8_t* out_buf, size_t buf_len);

// Parse a wire image back into a heap blueprint (free with
// machine_blueprint_destroy). Verifies the embedded hash over the body and
// rejects ANY mismatch (a tampered body can never pass), plus structural
// bounds: counts within the blueprint caps, trust_mode within the enum.
// Returns NULL on malformed input.
machine_blueprint_t* blueprint_deserialize(const uint8_t* buf, size_t len);

// ============================================================
// Spawn: instantiate a child machine from a validated blueprint
// ============================================================

// Instantiate a child machine per the blueprint's trust mode:
//   SHARED_ROOT    — the child runs on the PARENT's authority: its
//                    base_state.attr_machine points at the parent's attribute
//                    machine (one user registry) and its base_state.abe_mk is
//                    the parent's live MSK (borrowed — destroying the child
//                    never touches the parent's authority; the parent is the
//                    ONE owner). Nothing is re-enrolled: the child's
//                    config.bootstrap_admin records the blueprint's id
//                    (possibly empty; no user row is created — the shared
//                    registry already carries whoever it carries).
//   DELEGATED_COPY — a fresh CP-ABE authority is minted for the child via
//                    attribute_machine_create (§8.3 genesis: the bootstrap
//                    admin is registered IN the child's fresh registry with
//                    role:admin). The MSK is the child's own.
//   SOVEREIGN      — identical construction to DELEGATED_COPY; the only
//                    difference is recorded in the parent's manifest entry
//                    (LINEAGE_SOVEREIGN): the parent may only WITHDRAW its
//                    genesis stake (never dissolve) — enforced by Task 8's
//                    lineage ops.
//
// Genesis provenance: the parent's node key signs the canonical UNKEYED
// serialization of the child state (crabs_serialize_state — the genesis
// carries no sealed MSK section: provenance is not authority-at-rest). The
// blob's SHA-256 and the parent's ECDSA signature (over the genesis bytes
// EXPLICITLY — the child has no node key of its own yet; whoever loads the
// child sets one later) are stored in the parent's manifest entry, which is
// appended ONLY after the child is fully built — every earlier failure leaves
// no manifest residue.
//
// Parent binding on the child: lineage_parent_bound = true, lineage_self_id =
// blueprint->child_id, lineage_parent_public_key = the parent's node public
// key, and lineage_parent_id = parent->config.bootstrap_admin — in v1 a
// machine's identity IS its bootstrap_admin id (single-node machines), which
// is the same parent_id string attestations carry (spec §lineage_parent_id).
//
// Child op policies are the blueprint author's responsibility — spawn NEVER
// imposes custody guards (e.g. a "custody:<child_id>" token): that policy
// choice belongs to protocol authors.
//
// Error mapping (crabs.h has no policy/limit-specific enumerator):
//   structural garbage (invalid blueprint / no shared authority)
//                            → CRABS_ERR_INVALID_PARAM
//   manifest ceiling reached → CRABS_ERR_OOM (follows the op-handler
//                            registry's capacity precedent,
//                            state_machine_register_handler)
//   duplicate child_id (in parent->children or == parent->lineage_self_id)
//                            → CRABS_ERR_DUPLICATE_OPERATION
//   parent cannot sign (no node key / sign or hash failure)
//                            → CRABS_ERR_CRYPTOGRAPHIC_ERROR
//   genesis serialization failure → CRABS_ERR_SERIALIZATION_ERROR
//
// child_out receives a heap attribute_machine_t whose state is
// &child->base_state. Ownership: the caller destroys it via
// attribute_machine_destroy.
crabs_error_e lineage_spawn_machine(state_t* parent,
                                    const machine_blueprint_t* blueprint,
                                    attribute_machine_t** child_out);

// ============================================================
// Attestations: issue / verify / wire transport
// ============================================================

// Create an attestation and sign its canonical body with the parent
// machine's node key (state_set_node_key must have been called — a machine
// never reads the wall clock itself, so `now_ms` is supplied by the caller).
// `expires_at` must not precede `now_ms`. Returns CRABS_ERR_INVALID_PARAM on
// missing or structurally invalid inputs (unsafe/overlong ids or attributes),
// and CRABS_ERR_CRYPTOGRAPHIC_ERROR when the node key is invalid or signing
// fails.
crabs_error_e attestation_create(state_t* parent,
                                 attestation_t* attestation_out,
                                 const char* parent_id, const char* child_id,
                                 const char* user_id, const char* attributes,
                                 uint64_t now_ms, uint64_t expires_at);

// Canonical checks: format_version match, child_id exact match, validity
// window (not_before <= now_ms <= expires_at), ECDSA verify over the
// canonical body against `parent_public_key`. No heap use.
bool attestation_verify(const uint8_t parent_public_key[33],
                        const char* child_id,
                        const attestation_t* attestation, uint64_t now_ms);

// Wire format: u32le total length (canonical body + signature, excluding the
// prefix itself) + the canonical body + signature. Returns bytes written, or
// 0 on overflow/error.
size_t attestation_serialize(const attestation_t* attestation,
                             uint8_t* out_buf, size_t buf_len);

// Parse a wire image back into a heap attestation_t (free with
// attestation_destroy). Returns NULL on malformed input.
attestation_t* attestation_deserialize(const uint8_t* buf, size_t len);

void attestation_destroy(attestation_t* attestation);

#endif // CRABS_LINEAGE_H