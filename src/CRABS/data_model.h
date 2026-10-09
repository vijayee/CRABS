//
// Created by victor on 3/30/25.
//

#ifndef CRABS_DATA_MODEL_H
#define CRABS_DATA_MODEL_H

#include <stdint.h>
#include <stdbool.h>
#include "crabs.h"
#include "../Crypto/sig_scheme.h"
#include "../HLC/hlc.h"

// Forward declarations
typedef struct trigger_t trigger_t;
typedef struct attribute_machine_t attribute_machine_t;
typedef struct op_handler_entry_t op_handler_entry_t;

// ============================================================
// Data Types (§5.1)
// ============================================================
typedef enum {
  DATA_TYPE_COUNTER     = 0x01,  // G-Counter
  DATA_TYPE_PN_COUNTER  = 0x02,  // PN-Counter
  DATA_TYPE_SET         = 0x03,  // OR-Set
  DATA_TYPE_2P_SET      = 0x04,  // Two-phase set
  DATA_TYPE_REGISTER    = 0x05,  // LWW-Register
  DATA_TYPE_DOCUMENT    = 0x06,  // RGA
  DATA_TYPE_RESOURCE    = 0x07,  // PN-Counter + lock
  DATA_TYPE_ONE_SHOT_SET  = 0x08,  // Add-only set (v1.4 §2)
  DATA_TYPE_ONE_SHOT_FLAG = 0x09,  // Monotonic boolean flag (v1.4 §2)
  // OT/CRDT Hybrid Types (v1.5 §3)
  DATA_TYPE_OT_ORDERED_SET = 0x10,
  DATA_TYPE_OT_DOCUMENT    = 0x11,
  DATA_TYPE_OT_TABLE       = 0x12,
  DATA_TYPE_OT_TREE        = 0x13,
  DATA_TYPE_OT_ORDERED_MAP = 0x14,
  DATA_TYPE_CUSTOM      = 0xFF   // User-defined
} data_type_e;

// ============================================================
// CRDT Strategies (§5.1)
// ============================================================
typedef enum {
  CRDT_G_COUNTER   = 0x01,
  CRDT_PN_COUNTER  = 0x02,
  CRDT_OR_SET      = 0x03,
  CRDT_2P_SET      = 0x04,
  CRDT_LWW_REG     = 0x05,
  CRDT_RGA         = 0x06,
  CRDT_ONE_SHOT_SET  = 0x08,  // v1.4 §2
  CRDT_ONE_SHOT_FLAG = 0x09,  // v1.4 §2
  CRDT_CUSTOM      = 0xFF
} crdt_type_e;

// ============================================================
// Protocol State (§6.2)
// ============================================================
typedef enum {
  PROTOCOL_IDLE     = 0x00,
  PROTOCOL_LOCKED   = 0x01,
  PROTOCOL_MODIFIED = 0x02,
  PROTOCOL_VERIFIED = 0x03,
  PROTOCOL_ERROR    = 0x04
} protocol_state_e;

// ============================================================
// Value Representation Tag (runtime only — never serialized)
// ============================================================
// data_item_t.value is POLYMORPHIC in practice: struct-backed
// (g_counter_t / pn_counter_t / lww_register_t / or_set_t / ...) for values
// produced by the wasm adders, crdt_merge_value, compaction, and the v15+
// state deserializer, versus a bare heap int64_t for legacy pre-v15 loads
// and plain adders. crdt_type CANNOT discriminate (a pre-v15 load tags a
// raw int64 with CRDT_G_COUNTER), so the representation is pinned at every
// assignment site by this tag instead.
typedef enum {
  DATA_VALUE_REPR_RAW_INT64   = 0,  // plain heap value (int64_t* for the
                                    // numeric types; raw blob otherwise)
  DATA_VALUE_REPR_CRDT_STRUCT = 1   // CRDT struct owned via crdt_value_destroy
} data_value_repr_t;

// ============================================================
// Invariant Type (§5.3)
// ============================================================
typedef enum {
  INVARIANT_GREATER_THAN  = 0x01,
  INVARIANT_LESS_THAN     = 0x02,
  INVARIANT_EQUAL_TO      = 0x03,
  INVARIANT_NOT_EQUAL     = 0x04,
  INVARIANT_DIVISIBLE_BY  = 0x05,
  INVARIANT_UNIQUE        = 0x06,
  INVARIANT_SUBSET_OF     = 0x07,
  INVARIANT_NON_NEGATIVE  = 0x08,
  INVARIANT_CUSTOM        = 0xFF
} invariant_type_e;

// ============================================================
// Data Type Definition (§5.2)
// ============================================================
typedef struct {
  uint8_t     type_id;
  const char* name;
  bool        requires_lock;
} data_type_definition_t;

// ============================================================
// Invariant (§5.3)
// ============================================================
typedef struct {
  invariant_type_e type;
  int64_t          param;
  const char*      error_message;
} invariant_t;

// ============================================================
// Lock State (embedded in DataItem for RESOURCE type)
// ============================================================
typedef struct {
  uint8_t  lock_token[CRABS_LOCK_TOKEN_SIZE];
  bool     lock_token_valid;
  char     lock_owner[CRABS_MAX_USER_ID];
  uint64_t lock_expiry;
  uint32_t lock_extensions;
  void*    pre_lock_snapshot;
  // Byte length of pre_lock_snapshot. RAW_INT64 items snapshot 8 bytes (the
  // historical form); CRDT_STRUCT items snapshot the value's serialized
  // LOGICAL content (data_item_restore_value_from_logical_bytes bytes), so
  // rollback rebuilds the struct instead of reviving a freed pointer through
  // an 8-byte memcpy. Runtime only — lock state is never serialized.
  size_t   pre_lock_snapshot_len;
  crabs_hlc_t lock_acquired_at;  // v1.6 Amd6 §8: HLC timestamp when lock was acquired
} lock_state_t;

// ============================================================
// DataItem (§4.2)
// ============================================================
typedef struct data_item_t {
  char             name[CRABS_MAX_USER_ID];
  data_type_e      type;
  crdt_type_e      crdt_type;
  void*            value;
  // Runtime ONLY — never serialized (the wire form re-derives it: pre-v15
  // loads are RAW_INT64, v15+ loads reconstruct structs where the shape
  // carries them). Pins the ownership form of `value` (see
  // data_value_repr_t); every production assignment sets it together with
  // the pointer. crdt_type is NOT a substitute discriminator: pre-v15 loads
  // tag a raw int64 with CRDT_G_COUNTER.
  data_value_repr_t value_repr;
  protocol_state_e protocol_state;
  invariant_t*     invariants;
  uint32_t         invariant_count;

  // Lock state (only for RESOURCE type)
  lock_state_t     lock_state;

  // OT data (only for OT types 0x10-0x1F)
  void*            ot_data;  // crabs_ot_data_item_t* when type is OT

  // Compaction tracking (v1.5.2 §4)
  uint64_t         last_compaction_time;  // Timestamp of last successful compaction

  // Write domain (write-domains v1, spec 2026-10-08). FREE_MERGE (0) for
  // items created without options and for items loaded from pre-v14 states —
  // zero default means zero behavioral change on upgrade. Declared at
  // creation, immutable on a live item in v1.
  crabs_write_domain_e write_domain;
  // SOVEREIGN only: the user_id of the item's single writer ("" otherwise).
  // char (not uint8_t) to match every other user-id field in this header.
  char             writer[CRABS_MAX_USER_ID];
  // SOVEREIGN: writer-assigned monotonic sequence over this writer's ops on
  // the item; 0 before the first op, incremented on each accepted op.
  uint64_t         item_seq;
  // SOVEREIGN: SHA-256 over the item's post-op content-only form
  // (state_item_digest_compute over _serialize_data_item_chain_preimage —
  // runtime protocol_state excluded). Zeroed while item_seq == 0.
  uint8_t          item_digest[CRABS_HASH_SIZE];
  // GROUP_ORDERED: attached ordering module id. 0 = unset — v1 ships no
  // modules, so a GROUP_ORDERED item with module 0 is read-only (DOMAIN_CHECK
  // fails closed with CRABS_ERR_ORDERING_PATH) until a module is registered.
  uint8_t          ordering_module;
  // SOVEREIGN quarantine: fork evidence accumulated for this item, stored
  // inline (no allocation), capped at CRABS_MAX_FORK_WRITERS. Entries are
  // appended by the equivocation-report handler and by merge as a monotone
  // union (union-only, never evicted); a writer present here has all future
  // writes on this item rejected (CRABS_ERR_QUARANTINED). Runtime-populated;
  // serialized from v14 onward.
  char             fork_writers[CRABS_MAX_FORK_WRITERS][CRABS_MAX_USER_ID];
  uint8_t          fork_evidence_digests[CRABS_MAX_FORK_WRITERS][CRABS_HASH_SIZE];
  uint32_t         fork_count;  // ≤ CRABS_MAX_FORK_WRITERS

  // Pointer-based linking
  struct data_item_t* next;
} data_item_t;

// ============================================================
// Write-domain creation options (write-domains v1)
// ============================================================
// All-optional parameters for data_item_create_with_options. NULL options or
// a zeroed struct reproduces data_item_create's behavior exactly:
// FREE_MERGE, no writer, no ordering module.
//
// v1 restrictions (see data_item_create_with_options):
//   - SOVEREIGN requires a non-empty writer and a type among
//     DATA_TYPE_COUNTER / DATA_TYPE_REGISTER.
//   - GROUP_ORDERED requires ordering_module == 0 (no modules exist yet).
//   - writer is meaningful only for SOVEREIGN; ordering_module only for
//     GROUP_ORDERED.
typedef struct {
  crabs_write_domain_e write_domain;    // 0 = CRABS_DOMAIN_FREE_MERGE (default)
  const char*          writer;          // SOVEREIGN only; NULL = none
  uint8_t              ordering_module; // GROUP_ORDERED; 0 = unset (v1-only state)
} data_item_options_t;

// ============================================================
// Policy (§4.3 + v1.3 §7)
// ============================================================
#define CRABS_MAX_ALLOWED_SCHEMES  8

typedef struct {
  char  operation[CRABS_MAX_OP_NAME];
  char  expression[CRABS_MAX_POLICY_EXPR];
  // v1.3: Scheme constraints
  signature_scheme_e allowed_schemes[CRABS_MAX_ALLOWED_SCHEMES];
  uint32_t           allowed_scheme_count;
  uint64_t           min_key_version;
} policy_t;

// ============================================================
// Signature Configuration (v1.3 §8 + §9 Key Lifecycle)
// ============================================================
#define CRABS_DEFAULT_MAX_KEYS   8

typedef struct {
  signature_scheme_e default_scheme;
  uint32_t          max_keys_per_user;
  bool              key_rotation_enabled;
  uint32_t          co_sign_threshold;
  // v1.3 §9: Key lifecycle
  bool              key_expiry_enabled;
  uint64_t          default_key_ttl_ms;  // 0 = no expiry
  uint64_t          max_key_age_ms;      // 0 = no max age
} signature_config_t;

// ============================================================
// Vault Configuration (v1.3 §10)
// ============================================================
#define CRABS_VAULT_ADDRESS_MAX  256
#define CRABS_VAULT_TOKEN_MAX    128

typedef enum {
  VAULT_NONE       = 0x00,
  VAULT_HASHICORP  = 0x01,
  VAULT_AWS_KMS    = 0x02,
  VAULT_HSM        = 0x03,
  VAULT_CUSTOM     = 0xFF
} vault_provider_e;

typedef struct {
  vault_provider_e provider;
  char             address[CRABS_VAULT_ADDRESS_MAX];
  char             auth_token[CRABS_VAULT_TOKEN_MAX];
  bool             signing_delegated;  // vault_sign() instead of local sign
  bool             rotation_delegated; // vault manages rotation
} vault_config_t;

// Default ceiling on scheduled occurrences materialized per tick. Bounds the
// work a single tick does when catching up after a long offline window; the
// remainder carries over to subsequent ticks (nothing is dropped). Node-local
// runtime policy — override with scheduler_set_max_occurrences_per_tick, 0 =
// unlimited. Not part of the serialized state. Defined here (not in
// scheduler.h) because BOTH state creators must apply it: state_create and
// attribute_machine_create, whose zero-cleared embedded base_state never
// runs state_create's defaults.
#define CRABS_SCHEDULER_DEFAULT_MAX_OCCURRENCES_PER_TICK 64

// ============================================================
// Machine Configuration (§4.4 + v1.3 §8 + §10)
// ============================================================
typedef struct {
  uint64_t max_lock_duration_ms;
  uint32_t max_lock_extensions;
  bool     allow_force_unlock;
  char     bootstrap_admin[CRABS_MAX_USER_ID];
  signature_config_t sig_config;
  vault_config_t     vault_config;      // v1.3 §10: vault integration
} machine_config_t;

// ============================================================
// State Change Notification (core; NOT devtools-gated)
// ============================================================
typedef struct state_t state_t;  // full definition below (State, §4.1)

typedef enum {
  CRABS_CHANGE_OP        = 0x01,  // executed operation (direct execution only)
  CRABS_CHANGE_SCHEDULE  = 0x02,  // scheduled materialization (each fire)
  CRABS_CHANGE_TRIGGER   = 0x03,  // trigger-fired mutation
  CRABS_CHANGE_ATTRIBUTE = 0x04,  // attribute-machine user mutation
  CRABS_CHANGE_SPAWN     = 0x05,  // machine spawned from a blueprint (lineage)
  CRABS_CHANGE_LINEAGE   = 0x06,  // lineage lifecycle op (revoke/dissolve/withdraw)
  // Merge-dispatch divergence (write-domains v1): a sovereign fork unioned
  // into the quarantine set, a held group-ordered divergence, or a rejected
  // lineage-inconsistent item. Merge still converges; this event surfaces
  // what was withheld. result carries the reason (CRABS_ERR_FORK_DETECTED,
  // CRABS_ERR_ORDERING_PATH, CRABS_ERR_PROTOCOL_VIOLATION).
  CRABS_CHANGE_MERGE     = 0x07
} crabs_change_kind_e;

typedef struct {
  crabs_change_kind_e kind;
  const char*         type;        // op type / attribute action name
  const uint8_t*      uuid;        // op uuid; NULL for attribute actions
  const char*         signer_id;   // NULL when not applicable
  const char*         node_id;     // NULL when not applicable
  const char*         target;      // primary target item/user; NULL when none
  const char*         preview;     // short human-readable payload summary
  crabs_error_e       result;
  uint64_t            lamport_time; // op ordering stamp; 0 for non-op kinds
  bool                has_hlc;
  crabs_hlc_t         hlc;          // valid when has_hlc
} crabs_change_event_t;

typedef void (*crabs_change_hook_fn)(state_t* state,
                                     const crabs_change_event_t* event,
                                     void* user_data);

// ============================================================
// Dedup Specification (v1.4 §3)
// ============================================================
#define CRABS_MAX_DEDUP_PATH     128
#define CRABS_MAX_DEDUP_MESSAGE  256

typedef enum {
  DEDUP_NONE   = 0x00,
  DEDUP_PER_USER = 0x01,
  DEDUP_GLOBAL   = 0x02,
  DEDUP_CUSTOM   = 0xFF
} dedup_type_e;

typedef enum {
  MUTATION_SET_ADD           = 0x01,
  MUTATION_FLAG_SET          = 0x02,
  MUTATION_COUNTER_INCREMENT = 0x03,
  MUTATION_ASSIGN            = 0x04,
  MUTATION_CUSTOM            = 0xFF
} mutation_type_e;

typedef struct {
  mutation_type_e type;
  // For MUTATION_SET_ADD
  char set_path[CRABS_MAX_DEDUP_PATH];
  char element_value[CRABS_MAX_USER_ID];
  // For MUTATION_FLAG_SET
  char flag_path[CRABS_MAX_DEDUP_PATH];
  // For MUTATION_COUNTER_INCREMENT
  char counter_path[CRABS_MAX_DEDUP_PATH];
  int64_t delta;
  // For MUTATION_ASSIGN
  char target_path[CRABS_MAX_DEDUP_PATH];
  char value[CRABS_MAX_DEDUP_PATH];
} state_mutation_t;

typedef struct {
  dedup_type_e type;
  // For DEDUP_PER_USER
  char tracker_path[CRABS_MAX_DEDUP_PATH];
  // For DEDUP_GLOBAL
  char flag_path[CRABS_MAX_DEDUP_PATH];
  // For DEDUP_CUSTOM
  char condition[CRABS_MAX_POLICY_EXPR];
  state_mutation_t update;
  // Rejection message
  char rejection_message[CRABS_MAX_DEDUP_MESSAGE];
} dedup_spec_t;

// ============================================================
// Operation Type Definition (v1.4 §7)
// ============================================================
#define CRABS_MAX_OP_TYPE_DEFS  32

typedef struct {
  char          op_type[CRABS_MAX_OP_NAME];
  dedup_spec_t  dedup;
} op_type_def_t;

// ============================================================
// Lineage (v1.7: machines mint machines)
// ============================================================
// Ceiling on children a single machine may spawn into its manifest. Bounds
// the serialized manifest and the spawn operation's lookup cost.
#define CRABS_MAX_CHILD_MACHINES 64

// Trust profiles for spawned children (spec §Blueprint payload):
//   SHARED_ROOT    — child resolves attributes against the PARENT's authority
//                    (same pointer; parent revocation is instant).
//   DELEGATED_COPY — child mints a fresh authority via a parent-signed
//                    attestation bridging the two domains.
//   SOVEREIGN      — child self-mints its authority; the parent may only
//                    withdraw, never dissolve.
typedef enum {
  LINEAGE_SHARED_ROOT    = 0x01,
  LINEAGE_DELEGATED_COPY = 0x02,
  LINEAGE_SOVEREIGN      = 0x03
} lineage_trust_mode_e;

// Child lifecycle status (wire: u8; the v11 reader accepts 0..3).
//   ACTIVE    — the parent issues attestations and may dissolve/withdraw.
//   DISSOLVED — the parent severed the lineage (shared-root / delegated).
//   WITHDRAWN — the parent withdrew its genesis stake (sovereign only).
//   ATTESTATION_REVOKED — the parent stopped ISSUING attestations for the
//                    child without dissolving it: existing attestations run
//                    out their TTL, and dissolution remains available
//                    (issuing a new one fails closed).
typedef enum {
  LINEAGE_ACTIVE             = 0x00,
  LINEAGE_DISSOLVED          = 0x01,
  LINEAGE_WITHDRAWN          = 0x02,
  LINEAGE_ATTESTATION_REVOKED = 0x03
} lineage_status_e;

// One entry of the parent's serialized child manifest.
typedef struct {
  char                 child_id[CRABS_MAX_USER_ID];
  lineage_trust_mode_e mode;
  uint8_t              genesis_snapshot_hash[CRABS_HASH_SIZE];
  uint8_t              genesis_attestation_signature[CRABS_SIG_SIZE];
  uint64_t             attestation_ttl_ms;
  uint64_t             spawned_at;
  lineage_status_e     status;
} child_manifest_entry_t;

// A10-M6: one entry of a machine's bounded parent key chain — a parent node
// public key plus its version in the lineage key namespace. Entry [0] is the
// spawn pin (== state_t.lineage_parent_public_key); a signed transition
// record (see lineage.h) advances the chain forward-only when the parent
// rotates its node key. Lives here (not lineage.h) because state_t embeds a
// pointer to it and data_model.h cannot include lineage.h (lineage.h
// includes data_model.h).
typedef struct {
  uint64_t key_version;
  uint8_t  public_key[33];
} lineage_key_chain_entry_t;

// ============================================================
// Log Entry (§7.4 step 9)
// ============================================================
typedef struct {
  uint64_t version;
  uint8_t  uuid[CRABS_UUID_SIZE];
  char     type[CRABS_MAX_OP_NAME];
  char     signer_id[CRABS_MAX_USER_ID];
  uint64_t lamport_time;
  char     node_id[CRABS_MAX_USER_ID];
  uint8_t  state_hash[CRABS_HASH_SIZE];
  // v1.6 Amd6: Ordering system support
  crabs_ordering_system_e ordering_system;  // LAMPORT (default) or HLC
  crabs_hlc_t        hlc;                   // HLC timestamp (used when ordering_system == HLC)
} log_entry_t;

// ============================================================
// Scheduled Operation (timed transactions v1)
// ============================================================
typedef struct scheduled_operation_t {
  uint64_t    schedule_id;    // per-state monotonic counter
  uint64_t    execute_at_ms;  // epoch ms; compared against authenticated now
  uint64_t    interval_ms;    // 0 = one-shot
  uint64_t    repeat_count;   // remaining fires; 0 = infinite
  uint64_t    end_at_ms;      // 0 = no end date
  char        submitter[CRABS_MAX_USER_ID];
  uint8_t*    op_bytes;       // crabs_serialize_operation of the embedded op
  uint32_t    op_len;
  struct scheduled_operation_t* next;
} scheduled_operation_t;

// ============================================================
// State (§4.1)
// ============================================================
typedef struct state_t {
  uint64_t        version;
  data_item_t*    items;
  policy_t*       policies;
  uint32_t        policy_count;
  log_entry_t*    log;
  uint64_t        log_count;
  machine_config_t config;
  void*           tx_manager;           // crabs_tx_manager_t* — replay protection
  trigger_t*      triggers;
  uint32_t        trigger_count;
  // Timed transactions (v1): pending operations awaiting materialization.
  scheduled_operation_t* scheduled_operations;
  uint64_t        schedule_seq;
  // Node-local runtime policy (NOT serialized): maximum scheduled occurrences
  // materialized per tick, so a long offline catch-up cannot run unbounded in
  // one tick. 0 = unlimited. Set via scheduler_set_max_occurrences_per_tick.
  uint32_t        max_occurrences_per_tick;
  // Change notification (core, not devtools-gated): invoked after every
  // state-mutating completion. Runtime state; not serialized.
  crabs_change_hook_fn change_hook;
  void*                change_hook_user_data;
  attribute_machine_t* attr_machine;  // For key verification and policy evaluation
  uint8_t node_private_key[32];       // Node ECDSA private key for envelope signing (§11)
  uint8_t node_public_key[33];        // Node ECDSA public key
  bool    node_key_valid;             // Whether node keys are initialized
  void*   last_refresh_envelope;      // Last key refresh envelope (key_envelope_t*, §11.3)
  // v1.4: Operation type definitions (§7)
  op_type_def_t* op_type_defs;
  uint32_t       op_type_def_count;
  // User-defined operation handler registry
  op_handler_entry_t* op_handlers;
  uint32_t            op_handler_count;
  // Lineage (v1.7 §machines-mint-machines): children this machine spawned.
  // Heap array owned by the state — freed by state_destroy; never a view
  // into embedded storage.
  child_manifest_entry_t* children;
  uint32_t                child_count;
  // This machine's parent binding (present only for spawned children).
  char    lineage_parent_id[CRABS_MAX_USER_ID];
  uint8_t lineage_parent_public_key[33];
  bool    lineage_parent_bound;
  // A10-M6 (v13, runtime + wire): bounded chain of node keys this machine
  // accepts for parent attestations/tombstones. Entry [0] is the spawn pin
  // (== lineage_parent_public_key); forward-only via __parent_key_update__.
  // Verification is TIP-ONLY (A11-4): a minted attestation/tombstone's
  // parent_key_version stamp must equal the TIP entry's key_version and its
  // signature must verify under the tip's key — retired entries verify
  // nothing. Heap array owned by the state — freed by state_destroy /
  // attribute_machine_destroy. Cap CRABS_MAX_LINEAGE_KEY_CHAIN (lineage.h).
  lineage_key_chain_entry_t* lineage_key_chain;
  uint32_t                   lineage_key_chain_count;
  // A10-M6 parent-side: this machine's node key version in the lineage
  // namespace. 0 until the first lineage_key_rotate; the unversioned key a
  // state starts with is generation CRABS_LINEAGE_KEY_VERSION_START.
  uint64_t                   lineage_key_version;
  // A10-M6 parent-side: last signed key transition — re-emitted to children
  // as __parent_key_update__ after a restart (the old private key is gone by
  // then, so the record must survive on its own). State-owned heap; wire cap
  // LINEAGE_KEY_TRANSITION_WIRE_MAX (lineage.h).
  uint8_t*                   lineage_last_key_transition;
  uint32_t                   lineage_last_key_transition_len;
  // v1.7: THIS machine's own id when spawned — the child_id an attestation
  // resolved against this machine must name. Empty for a root (never-spawned)
  // machine, which cannot resolve endorsements at all. Set at spawn time
  // together with the parent binding above; persists in the same v11
  // parent-binding block.
  char    lineage_self_id[CRABS_MAX_USER_ID];
  // v1.7 (persists in the v12 binding-block tail): set on a spawned child when
  // the parent executes __dissolve_machine__. On the wire the flag survives
  // restarts; a resident child is additionally severed immediately in-process.
  // Default when absent (v11 blobs): false.
  bool    lineage_parent_dissolved;
  // v1.7 (runtime ONLY, never serialized): registry of children spawned and
  // still resident in this process, so __dissolve_machine__ can reach the
  // child's state directly. UNOWNED POINTERS — each entry is a child some
  // caller built via lineage_spawn_machine and owns (destroys) itself; the
  // state only frees the POINTER ARRAY. Entries are matched by the child's
  // lineage_self_id, NEVER by position: the manifest above persists across
  // a restart while this registry starts empty, so a slot index bears no
  // relationship to a manifest index (A10-5). Dissolve NULLs the matching
  // slot — a hole — and lookups skip holes (the child may outlive the
  // dissolve). A10-6 liveness invariant: NON-NULL slots always point at LIVE
  // machines — the resident child's attribute_machine_destroy drops its slot
  // first (lineage_resident_child_destroyed, via the child's weak
  // lineage_owner_state back-pointer), and this state's own destroy detaches
  // surviving children's back-pointers before freeing the array
  // (lineage_detach_resident_children), so neither order of death can leave a
  // dangling entry for find-by-id or dissolve to dereference.
  attribute_machine_t** resident_children;
  uint32_t              resident_child_count;
  // v1.5.2 §4: Compaction config (crabs_tombstone_config_t*). Externally owned
  // — the caller must free it after state_destroy.
  void* compaction_config;
  // Audit F-3: optional compaction engine (crabs_compaction_engine_t*). When
  // set, the execute path records each ingested OT op into the engine's local
  // vector clock so the STRONG/QUORUM compaction safety check can be armed.
  // The state does NOT own the engine.
  void* compaction_engine;
  // v1.6 Amd6: Ordering configuration (crabs_ordering_config_t*). Externally
  // owned — the caller must free it after state_destroy.
  void* ordering_config;
  // ABE master key — generated once at state creation, used for all ABE operations
  void* abe_mk;
  // Runtime-only; never serialized. true when abe_mk is a BORROWED pointer —
  // a spawned shared-root child runs on the parent's live authority (its
  // attr_machine is the parent's attribute machine too, so there is exactly
  // one user registry and one MSK for the pair). Both destroy paths skip
  // crypto_abe_master_key_destroy when this is set, so destroying the child
  // leaves the parent's authority intact (ONE owner per machine: the parent).
  bool abe_mk_borrowed;
  // v1.6 Amd6: persistent per-node HLC state (audit M-10). Reused across lock
  // acquisitions so the logical counter advances and clock-regression
  // protection holds across calls (previously each lock built a fresh HLC
  // state, resetting the counter and losing monotonicity).
  crabs_hlc_state_t hlc_state;
  bool             hlc_state_initialized;
  // Runtime-only; never serialized. Guards scheduler_process_due against
  // re-entrant ticks (a materialized op's custom handler calling back into
  // state_machine_execute), which would otherwise recurse unboundedly.
  bool             scheduler_ticking;
  // Runtime-only; never serialized. Guards trigger_process_all against
  // re-entrant processing (a change hook fired inside the trigger loop
  // executing an op that runs the state machine again), which would
  // double-fire triggers whose last_triggered_at is not yet written.
  bool             trigger_ticking;
} state_t;

// ============================================================
// Data Type Definitions (built-in registry)
// ============================================================
extern const data_type_definition_t CRABS_BUILTIN_TYPES[10];

// ============================================================
// Canonical (data_type, crdt_type) pairing
// ============================================================
// Every built-in type is backed by exactly ONE CRDT shape (the map lives in
// data_model.c next to CRABS_BUILTIN_TYPES). A mismatched pair is not a
// "different strategy": a value built for one shape but tagged with
// another's crdt_type miscasts on every repr/crdt-dispatched consumer
// (data_item_destroy, state_item_digest_compute, crdt_merge_value) — the
// reviewed wasm define_item hole minted a g_counter value tagged
// CRDT_PN_COUNTER and destroy cast it to pn_counter_t. The validating
// creation surfaces (data_item_create_with_options, and through it
// crabs_wasm_define_item / the node defineItem binding) fail closed on any
// non-canonical pair.
// Resolve a type's canonical crdt_type. Returns CRABS_ERR_TYPE_MISMATCH for
// a type with no table entry (unknown type ids are wire/JS input) and
// CRABS_ERR_INVALID_PARAM for a NULL out-param.
crabs_error_e data_item_canonical_crdt_for_type(data_type_e type,
                                                crdt_type_e* out_crdt);
// True exactly when (type, crdt_type) is the canonical pair.
bool data_item_type_crdt_pair_canonical(data_type_e type,
                                        crdt_type_e crdt_type);

// ============================================================
// DataItem creation/destruction
// ============================================================
data_item_t* data_item_create(const char* name, data_type_e type, crdt_type_e crdt_type);
// Create a data item with write-domain options (write-domains v1). NULL
// options (or a zeroed struct) is exactly data_item_create: FREE_MERGE, no
// writer. On success *out_item takes ownership of the new item; on failure
// returns the error and leaves *out_item NULL:
//   CRABS_ERR_INVALID_PARAM — NULL out_item; unknown domain; SOVEREIGN
//     without a non-empty writer; writer set on a non-SOVEREIGN domain;
//     ordering_module set on a non-GROUP_ORDERED domain; ordering_module
//     non-zero on GROUP_ORDERED (v1 ships no ordering modules, so no module
//     id can resolve — fail closed at creation).
//   CRABS_ERR_TYPE_MISMATCH — SOVEREIGN on a type other than
//     DATA_TYPE_COUNTER / DATA_TYPE_REGISTER (only those types have a
//     well-defined serialized post-state for the sovereign hash-chain digest;
//     widening the set requires defining a canonical serialized form first); or
//     a (type, crdt_type) pair that is not the canonical pairing
//     (data_item_type_crdt_pair_canonical — enforced for EVERY domain so a
//     miscast value can never be minted).
crabs_error_e data_item_create_with_options(const char* name,
                                            data_type_e type,
                                            crdt_type_e crdt_type,
                                            const data_item_options_t* options,
                                            data_item_t** out_item);
void         data_item_destroy(data_item_t* item);

// True when the item's value is a CRDT struct (the repr tag pinned at
// assignment), false for raw-repr and NULL items. Consumers that need the
// struct form (dedup mutations, condition resolution, invariants) MUST
// consult this instead of inferring the representation from crdt_type.
bool data_item_has_struct_value(const data_item_t* item);
// Replace the item's value with a fresh heap int64_t and tag the item
// RAW_INT64. Any previous value is released per ITS repr (struct values go
// through crdt_value_destroy), so the helper is safe for re-sets too.
void data_item_set_int64_value(data_item_t* item, int64_t value);
// Logical numeric value of an item across BOTH value representations:
//   struct g_counter  — sum of entry counts (g_counter_value)
//   struct pn_counter — pos − neg (pn_counter_value)
//   struct lww_reg    — int64 read from the payload's first 8 bytes
//                       (payloads shorter than 8 bytes fail)
//   RAW_INT64         — the stored int64 (numeric item types only)
// Returns CRABS_ERR_TYPE_MISMATCH for representations with no numeric value
// (sets/documents/OT/...), leaving *out untouched — callers skip invariants
// and resolve conditions to 0 on such items, mirroring the historical
// non-counter behavior.
crabs_error_e data_item_logical_value(const data_item_t* item, int64_t* out);

// ============================================================
// State creation/destruction
// ============================================================
state_t*     state_create(void);
void         state_destroy(state_t* state);

// Set compaction config on state (enables auto-compaction after OT ops)
// Pass NULL to disable. config is NOT owned by state (caller must keep alive).
void         state_set_compaction_config(state_t* state, void* config);
// Audit F-3: set the compaction engine used to record ingested ops into the
// local vector clock. The state does not own the engine.
void         state_set_compaction_engine(state_t* state, void* engine);

// Set ordering config on state (v1.6 Amd6 §6.3)
// Pass NULL to use default Lamport ordering.
void         state_set_ordering_config(state_t* state, crabs_ordering_config_t* config);
crabs_ordering_config_t* state_get_ordering_config(state_t* state);

// R7-01: attach an authenticated time source (crabs_time_source_ops_t) to the
// state's HLC state. When set, state_machine_execute uses it for all expiry
// decisions and fails closed if it is unavailable. The state does NOT own the
// ops — the caller must keep it alive and destroy it after state_destroy.
void         state_set_time_source(state_t* state, void* time_source_ops);

// Initialize node ECDSA keypair for envelope signing (§11)
crabs_error_e state_set_node_key(state_t* state,
                                  const uint8_t private_key[32],
                                  const uint8_t public_key[33]);

// ============================================================
// State query helpers
// ============================================================
data_item_t* state_find_item(state_t* state, const char* name);
// Adds a heap item created by data_item_create[_with_options]; on success the
// state owns it. Fails closed (CRABS_ERR_INVALID_PARAM) on a malformed domain
// declaration (unknown domain value, or SOVEREIGN with an empty writer) so a
// hand-built item cannot bypass data_item_create_with_options validation —
// on failure the CALLER still owns the item.
crabs_error_e state_add_item(state_t* state, data_item_t* item);
crabs_error_e state_add_policy(state_t* state, const char* operation, const char* expression);
const char*  state_find_policy(state_t* state, const char* operation);

// ============================================================
// Write-domain item helpers (write-domains v1)
// ============================================================
// The item's declared write domain. A NULL item reports FREE_MERGE (the
// zero/default domain), matching the pre-v14 load semantics.
crabs_write_domain_e state_item_domain(const data_item_t* item);
// Append one fork-evidence entry (writer + SHA-256 of the two forking op
// bytes) to the item's quarantine set. Monotone-union semantics: an entry
// whose writer OR evidence digest is already present is a duplicate
// (CRABS_ERR_DUPLICATE_OPERATION) — idempotent re-delivery of the same
// report is not an error, just a no-op signal. At CRABS_MAX_FORK_WRITERS the
// set is full: returns CRABS_ERR_OOM (capacity exhaustion, mirroring
// state_register_op_type_def; the cap bounds griefing and the audit log
// remains the authoritative evidence store). Intended for SOVEREIGN items;
// the callers (equivocation handler, merge) enforce that.
crabs_error_e state_append_fork_evidence(data_item_t* item,
                                         const char* writer,
                                         const uint8_t evidence_digest[CRABS_HASH_SIZE]);
// True when writer appears in the item's fork set (a quarantined writer —
// DOMAIN_CHECK rejects their further writes with CRABS_ERR_QUARANTINED).
// NULL item/writer → false (attribution checks run before this lookup).
bool state_item_is_quarantined(const data_item_t* item, const char* writer);
// SHA-256 over the item's content-only serialized form
// (crabs_serialize_data_item_chain_preimage), used for the sovereign hash
// chain. Content-comparable across replicas: identical writer-mutable
// item content ⇒ identical digest. Runtime protocol_state is EXCLUDED —
// replica-local lock state is not chain content (pre-fix its inclusion
// manufactured false fork evidence at merge). The state file's integrity
// checksum still hashes the durable form including protocol_state.
crabs_error_e state_item_digest_compute(const data_item_t* item,
                                        uint8_t out_digest[CRABS_HASH_SIZE]);

// Operation type definition registry (v1.4 §7)
const dedup_spec_t* state_find_op_type_def(const state_t* state, const char* op_type);
crabs_error_e state_register_op_type_def(state_t* state, const char* op_type, const dedup_spec_t* dedup);

#endif // CRABS_DATA_MODEL_H
