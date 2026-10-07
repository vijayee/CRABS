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
  protocol_state_e protocol_state;
  invariant_t*     invariants;
  uint32_t         invariant_count;

  // Lock state (only for RESOURCE type)
  lock_state_t     lock_state;

  // OT data (only for OT types 0x10-0x1F)
  void*            ot_data;  // crabs_ot_data_item_t* when type is OT

  // Compaction tracking (v1.5.2 §4)
  uint64_t         last_compaction_time;  // Timestamp of last successful compaction

  // Pointer-based linking
  struct data_item_t* next;
} data_item_t;

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
  CRABS_CHANGE_LINEAGE   = 0x06   // lineage lifecycle op (revoke/dissolve/withdraw)
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
  // v1.7: THIS machine's own id when spawned — the child_id an attestation
  // resolved against this machine must name. Empty for a root (never-spawned)
  // machine, which cannot resolve endorsements at all. Set at spawn time
  // together with the parent binding above; persists in the same v11
  // parent-binding block.
  char    lineage_self_id[CRABS_MAX_USER_ID];
  // v1.7 (runtime ONLY, never serialized): set on a spawned child when its
  // parent executes __dissolve_machine__ while the child is resident in the
  // same process — every @parent/ endorsement fails closed from that moment.
  // After a restart the flag is gone; delivering the parent's dissolution
  // tombstone as an op on the child is a later-plan concern.
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
  // dissolve). Destroying a child out-of-band without a dissolve leaves a
  // dangling entry.
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
// DataItem creation/destruction
// ============================================================
data_item_t* data_item_create(const char* name, data_type_e type, crdt_type_e crdt_type);
void         data_item_destroy(data_item_t* item);

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
crabs_error_e state_add_item(state_t* state, data_item_t* item);
crabs_error_e state_add_policy(state_t* state, const char* operation, const char* expression);
const char*  state_find_policy(state_t* state, const char* operation);

// Operation type definition registry (v1.4 §7)
const dedup_spec_t* state_find_op_type_def(const state_t* state, const char* op_type);
crabs_error_e state_register_op_type_def(state_t* state, const char* op_type, const dedup_spec_t* dedup);

#endif // CRABS_DATA_MODEL_H
