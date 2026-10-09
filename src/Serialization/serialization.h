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
#define CRABS_SERIAL_VERSION    15          // v15: struct-backed counter/register item values serialize logical content (node-sorted entries / register payload+ts+node), not the struct's first 8 bytes (a heap pointer) — fixes chain-digest determinism and struct-item restore

// Canonical-form version byte emitted by crabs_serialize_for_signing (§7.5).
// Purely domain-separation: nothing parses the signing form, so this MUST
// change whenever the signed field set changes. v4 (write domains) adds the
// per-resource sovereign chain prefixes to the signed bytes.
#define CRABS_SIGNING_FORMAT_VERSION 0x04

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
// invariants/last_compaction_time). Used by the state serializer's per-item
// integrity path — protocol_state IS part of the durable snapshot.
// NOTE (v14): this preimage MUST keep covering the pre-domain (v13) item
// form only — the v14 domain tail (write_domain/writer/item_seq/
// item_digest/fork set) is emitted by the state serializer's per-item loop,
// not here, because folding item_digest into its own preimage is
// self-referential and folding item_seq in would couple the digest to chain
// position rather than content.
serialized_buffer_t* crabs_serialize_data_item(const data_item_t* item);

// Sovereign chain-digest preimage (write-domains v1): identical field set
// to crabs_serialize_data_item MINUS the runtime protocol_state byte — the
// chain digest must be content-only. Runtime lock/MODIFIED state diverges
// across replicas (a lock taken on one replica); pre-fix that alone moved
// the digest, and at merge the equal-seq/different-digest rule convicted the
// writer and appended quarantine evidence. Excluding the byte keeps merge
// conviction as strong as digest determinism — only writer-mutable content
// (name/type/crdt_type/value/invariants/last_compaction_time) distinguishes
// heads. The v14 domain tail is excluded here for the same reason as the
// durable form: chain position and chain digest cannot be their own
// preimage.
serialized_buffer_t* crabs_serialize_data_item_chain_preimage(
    const data_item_t* item);

// ============================================================
// Struct-value logical bytes (value repr canonicalization)
// ============================================================
// Serialize a CRDT_STRUCT-tagged item's value to its LOGICAL content bytes
// — the same bytes the v15 value-slot envelope carries for struct-backed
// items (node-sorted g_counter entries / pn pos+neg entries / register
// payload+timestamp+node), sans the bytes32 envelope. Used by the lock
// snapshot, which must capture CONTENT (rollback rebuilds the struct from
// it via data_item_restore_value_from_logical_bytes) rather than the first
// 8 bytes of the struct (a heap address). Caller owns *out_bytes (free()).
// Errors: INVALID_PARAM on NULL args/value; TYPE_MISMATCH when the item is
// not CRDT_STRUCT-tagged or its crdt_type has no canonical logical form.
crabs_error_e crabs_serialize_item_value_logical(const data_item_t* item,
                                                 uint8_t** out_bytes,
                                                 size_t* out_len);

// Reconstruct item->value from the logical content bytes produced by
// crabs_serialize_item_value_logical, dispatched on the item's
// type+crdt_type pair (COUNTER/G_COUNTER, PN_COUNTER/PN_COUNTER,
// REGISTER/LWW_REG — the struct-backed shapes). Shared by the v15 state
// deserializer and the lock rollback deep-restore. The PREVIOUS item->value
// is NOT released here; ownership stays with the caller (the deserializer
// loads into a fresh item; the rollback destroys the old struct only after
// this returns success). On success item->value holds the new struct and
// value_repr == DATA_VALUE_REPR_CRDT_STRUCT; on failure item->value and
// value_repr are untouched. Errors: INVALID_PARAM on NULL/empty bytes;
// TYPE_MISMATCH on a non-struct (type, crdt_type) pair; INTERNAL on
// malformed bytes (mirrors the deserializer's rejection).
crabs_error_e data_item_restore_value_from_logical_bytes(data_item_t* item,
                                                         const uint8_t* bytes,
                                                         size_t len);

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
