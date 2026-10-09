//
// Created by victor on 4/30/25.
//

#ifndef CRABS_SERIALIZATION_H
#define CRABS_SERIALIZATION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "../StateMachine/state_machine.h"
#include "../OT/ot_types.h"
#include "../OT/position_map.h"

// ============================================================
// Magic bytes and format version (§13.1)
// ============================================================
#define CRABS_SERIAL_MAGIC      0x42415243  // "CRAB" in little-endian
#define CRABS_SERIAL_VERSION    13          // v13: lineage parent key chain (child side) + key version / last transition (parent side)

// ============================================================
// Serialized buffer
// ============================================================
typedef struct {
  uint8_t* data;
  size_t   len;
} serialized_buffer_t;

// ============================================================
// State serialization (§13.1)
// ============================================================
serialized_buffer_t* crabs_serialize_state(const state_t* state);
state_t*             crabs_deserialize_state(const uint8_t* data, size_t len);

// v10 keyed variants. crabs_serialize_state_sealed persists the machine's
// ABE master key sealed with AES-256-GCM under seal_key (32 bytes); it
// requires state->abe_mk and seal_key to be non-NULL (a "sealed" write
// without the machine's authority is not the sealed format at all). The
// unkeyed APIs keep v9 semantics: the MSK section is written with flag 0
// (substrate-only — the same loss-of-authority behavior as v9).
//
// crabs_deserialize_state_keys restores the sealed MSK when seal_key is
// provided and matches; when the file carries a sealed MSK but seal_key is
// NULL (or wrong), the state still loads with a FRESH MSK (substrate-only
// compatibility path) — the caller must treat authority as unproven in
// that case. Never leaves state->abe_mk NULL.
serialized_buffer_t* crabs_serialize_state_sealed(const state_t* state,
                                                    const uint8_t seal_key[32]);
state_t*             crabs_deserialize_state_keys(const uint8_t* data, size_t len,
                                                     const uint8_t seal_key[32]);

// v10+ load with restoration reporting: *authority_restored is true only when
// a sealed MSK section was present AND unsealed with the provided key;
// *msk_section_present reports whether the authority section existed at all.
// Either out-param may be NULL. Returns a state with a LIVE (restored or
// fresh) MSK in every case — see crabs_deserialize_state_keys's contract.
state_t*             crabs_deserialize_state_keys_reported(
                         const uint8_t* data, size_t len,
                         const uint8_t seal_key[32],
                         bool* authority_restored, bool* msk_section_present);

// R7-03: authenticated state snapshots. crabs_serialize_state_signed appends
// an ECDSA signature (from state->node_private_key) over the whole blob after
// the SHA-256 checksum; crabs_deserialize_state_signed verifies it with the
// node public key BEFORE parsing. The bare SHA-256 is only a corruption check
// — an attacker who can write the state file can recompute it, so snapshot
// load from untrusted sources must use the signed variants.
serialized_buffer_t* crabs_serialize_state_signed(const state_t* state);
state_t*             crabs_deserialize_state_signed(const uint8_t* data, size_t len,
                                                     const uint8_t node_public_key[33]);

// Sealed + node-key-signed full snapshot: _serialize_state_internal with
// seal_key (requires state->abe_mk), then the ECDSA trailer from
// state->node_private_key. Returns NULL when the state has no valid node key
// or no live master key to seal.
serialized_buffer_t* crabs_serialize_state_sealed_signed(
                         const state_t* state, const uint8_t seal_key[32]);

// ============================================================
// Operation serialization (§7.5)
// ============================================================
serialized_buffer_t* crabs_serialize_operation(const operation_t* op);
operation_t*         crabs_deserialize_operation(const uint8_t* data, size_t len);

// ============================================================
// Canonical encoding for signing (§7.5)
// ============================================================
serialized_buffer_t* crabs_serialize_for_signing(const operation_t* op);

// Serialize a single data item in exactly the per-item shape
// crabs_serialize_state writes (name/type/crdt/protocol_state/value/
// invariants/last_compaction_time). Used by the write-domains sovereign
// hash chain so an item's digest is content-comparable across replicas.
// NOTE (v14): this preimage MUST keep covering the pre-domain (v13) item
// form only — the v14 domain tail (write_domain/writer/item_seq/
// item_digest/fork set) is emitted by the state serializer's per-item loop,
// not here, because folding item_digest into its own preimage is
// self-referential and folding item_seq in would couple the digest to chain
// position rather than content.
serialized_buffer_t* crabs_serialize_data_item(const data_item_t* item);

// ============================================================
// Buffer helpers
// ============================================================
serialized_buffer_t* serialized_buffer_create(size_t len);
void                 serialized_buffer_destroy(serialized_buffer_t* buf);

// ============================================================
// OT Serialization (v1.5 §9)
// ============================================================

// Serialize/deserialize an OT operation
serialized_buffer_t* crabs_serialize_ot_op(const crabs_ot_operation_t* op);
crabs_ot_operation_t* crabs_deserialize_ot_op(const uint8_t* data, size_t len);

// Serialize/deserialize an OT operation log (array of ops)
serialized_buffer_t* crabs_serialize_ot_op_log(const crabs_ot_operation_t* ops, uint32_t count);
uint32_t crabs_deserialize_ot_op_log(const uint8_t* data, size_t len,
                                      crabs_ot_operation_t** ops_out);

// Serialize/deserialize a BST position map
serialized_buffer_t* crabs_serialize_bst(const crabs_bst_node_t* root);
crabs_bst_node_t*    crabs_deserialize_bst(const uint8_t* data, size_t len);

// Serialize/deserialize an OT data item (op_log, position_map, priority_counters)
serialized_buffer_t* crabs_serialize_ot_data(const crabs_ot_data_item_t* item);
crabs_ot_data_item_t* crabs_deserialize_ot_data(const uint8_t* data, size_t len, uint32_t ot_type_id);

#endif // CRABS_SERIALIZATION_H
