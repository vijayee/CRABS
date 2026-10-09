//
// Created by victor on 3/30/25.
//

#ifndef CRABS_CRABS_H
#define CRABS_CRABS_H

#include <stdint.h>
#include <stddef.h>

// ============================================================
// Protocol Constants (§2.3)
// ============================================================
#define CRABS_HASH_SIZE         32   // SHA-256 output
#define CRABS_SIG_SIZE          64   // ECDSA secp256k1 signature
#define CRABS_MAX_USER_ID       64   // Maximum user ID length
#define CRABS_MAX_OP_NAME       64   // Maximum operation name length
#define CRABS_MAX_POLICY_EXPR   256  // Maximum policy expression length
#define CRABS_MAX_RESOURCES     8    // Maximum resources per operation
#define CRABS_MAX_ATTRIBUTES    64   // Maximum attributes per user
// Audit N-10: the attribute string is built by concatenating every user
// attribute "name:value" token with commas. The prior callers used a
// CRABS_MAX_POLICY_EXPR (256) byte buffer, which overflows at ~8 attributes
// and made _build_attr_string fail closed (empty string) — a user who gained
// one more attribute would suddenly satisfy no policies. Size the buffer
// for the maximum: up to CRABS_MAX_ATTRIBUTES tokens, each up to
// CRABS_MAX_POLICY_EXPR bytes, plus a comma per token. This is a few KB and
// safe on the stack.
#define CRABS_ATTR_STRING_MAX   (CRABS_MAX_ATTRIBUTES * (CRABS_MAX_POLICY_EXPR + 1))
#define CRABS_MAX_LOG_ENTRIES   0    // Unlimited (0 = no limit)
// Audit L-b: cap the processed-op idempotency set so a long-running node does
// not grow it without bound (memory-exhaustion DoS). Beyond the cap, new ops
// are not recorded; replay protection across sessions relies on Lamport
// clocks and signatures, and within-session idempotency covers the recent
// window of CRABS_PROCESSED_OPS_MAX entries.
#define CRABS_PROCESSED_OPS_MAX 65536
#define CRABS_DEFAULT_LOCK_MS   5000 // Default lock timeout (5 seconds)
#define CRABS_MAX_LOCK_EXTENDS  3    // Maximum lock extensions
#define CRABS_LOCK_TOKEN_SIZE   32   // Lock token byte length
#define CRABS_UUID_SIZE         16   // UUID v4 byte length
// Write domains (2026-10-08 spec): cap on per-item sovereign fork-evidence
// entries. The fork set is a monotone union: a capped set truncates future
// appends but never evicts, and the audit log retains the full evidence ops.
#define CRABS_MAX_FORK_WRITERS  16

// ============================================================
// Write Domains (write-domains v1, spec 2026-10-08)
// ============================================================
// Every data item belongs to exactly one write domain, declared at creation
// and immutable in v1. FREE_MERGE (0) is the default — it carries exactly
// today's semantics, so pre-v14 states and options-less creation need no
// migration. GROUP_ORDERED has no registered ordering module in v1: such
// items are creatable but reject all writes (fail-closed seam).
typedef enum {
  CRABS_DOMAIN_FREE_MERGE    = 0x00,   // any authorized writer; CRDT merge
  CRABS_DOMAIN_SOVEREIGN     = 0x01,   // single registered writer, hash-chained
  CRABS_DOMAIN_GROUP_ORDERED = 0x02    // ordering module governs writes
} crabs_write_domain_e;

// ============================================================
// Error Codes (Appendix B)
// ============================================================
typedef enum {
  // 0x0xxx: Success
  CRABS_SUCCESS                    = 0x0000,

  // 0x1xxx: Protocol & Lock errors
  CRABS_ERR_PROTOCOL_VIOLATION     = 0x1001,
  CRABS_ERR_LOCK_TOKEN_MISMATCH    = 0x1002,
  CRABS_ERR_LOCK_OWNER_MISMATCH    = 0x1003,
  CRABS_ERR_LOCK_CONTENTION        = 0x1004,
  CRABS_ERR_LOCK_NOT_EXPIRED       = 0x1005,
  CRABS_ERR_MAX_EXTENSIONS_REACHED = 0x1006,
  CRABS_ERR_FORCE_UNLOCK_DISABLED   = 0x1007,

  // 0x2xxx: Authorization errors
  CRABS_ERR_UNAUTHORIZED           = 0x2001,
  CRABS_ERR_KEY_STALE              = 0x2002,
  CRABS_ERR_USER_NOT_FOUND         = 0x2003,
  CRABS_ERR_USER_SUSPENDED         = 0x2004,

  // 0x3xxx: Data errors
  CRABS_ERR_INVARIANT_VIOLATED     = 0x3001,
  CRABS_ERR_RESOURCE_NOT_FOUND      = 0x3002,
  CRABS_ERR_DUPLICATE_OPERATION    = 0x3003,
  CRABS_ERR_TYPE_MISMATCH          = 0x3004,

  // 0x4xxx: System errors
  CRABS_ERR_SERIALIZATION_ERROR    = 0x4001,
  CRABS_ERR_CRYPTOGRAPHIC_ERROR     = 0x4002,

  // 0x5xxx: Internal errors
  CRABS_ERR_INTERNAL               = 0x5001,
  CRABS_ERR_OOM                    = 0x5002,
  CRABS_ERR_INVALID_PARAM           = 0x5003,
  CRABS_ERR_SCHEME_ALREADY_REGISTERED = 0x5004,

  // 0x6xxx: Key lifecycle errors (v1.3 §9)
  CRABS_ERR_KEY_SUSPENDED          = 0x6001,
  CRABS_ERR_KEY_REVOKED            = 0x6002,
  CRABS_ERR_KEY_EXPIRED            = 0x6003,
  CRABS_ERR_KEY_NOT_ACTIVE         = 0x6004,
  CRABS_ERR_VAULT_UNAVAILABLE      = 0x6005,

  // 0x7xxx: Dedup errors (v1.4 §6)
  CRABS_ERR_ALREADY_PERFORMED     = 0x7001,
  CRABS_ERR_ALREADY_EXECUTED      = 0x7002,
  CRABS_ERR_CONDITION_NOT_MET     = 0x7003,
  CRABS_ERR_TRACKER_NOT_FOUND    = 0x7004,
  CRABS_ERR_FLAG_NOT_FOUND       = 0x7005,
  CRABS_ERR_SCHEDULE_INVALID     = 0x7006,

  // 0x8xxx: OT errors (v1.5 §8)
  CRABS_ERR_NO_OT_OPS            = 0x8001,
  CRABS_ERR_NOT_OT_TYPE          = 0x8002,
  CRABS_ERR_OT_TRANSFORM_DEPTH   = 0x8003,
  CRABS_ERR_OT_POSITION_BOUNDS   = 0x8004,

  // 0x9xxx: Compaction errors (v1.6 §6)
  CRABS_ERR_COMPACTION_NOT_SUPPORTED = 0x9001,
  CRABS_ERR_COMPACTION_NOT_SAFE     = 0x9002,
  CRABS_ERR_COMPACTION_IN_PROGRESS  = 0x9003,

  // 0xAxxx: Write domain errors (write-domains v1, spec 2026-10-08)
  CRABS_ERR_NOT_ITEM_WRITER  = 0xA001,  // op on a SOVEREIGN item from a non-writer (or unattributable signer)
  CRABS_ERR_SEQ_MISMATCH     = 0xA002,  // stale/duplicate item_seq on a SOVEREIGN op
  CRABS_ERR_FORK_DETECTED    = 0xA003,  // same item_seq, different digest — writer equivocation
  CRABS_ERR_ORDERING_PATH    = 0xA004,  // direct write to a GROUP_ORDERED item (module propose path required)
  CRABS_ERR_QUARANTINED      = 0xA005   // writer present in the item's fork-evidence set
} crabs_error_e;

// ============================================================
// Built-in Operation Names
// ============================================================
#define CRABS_OP_LOCK          "__lock__"
#define CRABS_OP_EXTEND        "__extend__"
#define CRABS_OP_VERIFY        "__verify__"
#define CRABS_OP_ROLLBACK      "__rollback__"
#define CRABS_OP_UNLOCK        "__unlock__"
#define CRABS_OP_FORCE_UNLOCK  "__force_unlock__"
#define CRABS_OP_REFRESH_KEY   "__refresh_abe_key__"
#define CRABS_OP_CHANGE_CONFIG "__change_config__"

// Built-in Trigger Operations (Amendment 1, §4)
#define CRABS_OP_CREATE_TRIGGER  "__create_trigger__"
#define CRABS_OP_DELETE_TRIGGER  "__delete_trigger__"
#define CRABS_OP_DISABLE_TRIGGER "__disable_trigger__"
#define CRABS_OP_ENABLE_TRIGGER  "__enable_trigger__"

// Built-in Key Operations (v1.3 Amendment 3, §5)
#define CRABS_OP_REGISTER_KEY     "__register_key__"
#define CRABS_OP_REVOKE_KEY       "__revoke_key__"
#define CRABS_OP_SET_DEFAULT_KEY  "__set_default_key__"

// Key Lifecycle Operations (v1.3 §9)
#define CRABS_OP_SUSPEND_KEY      "__suspend_key__"
#define CRABS_OP_ACTIVATE_KEY     "__activate_key__"
#define CRABS_OP_ROTATE_KEY       "__rotate_key__"

// Dedup Operations (v1.4 §7)
#define CRABS_OP_DEFINE_OPERATION  "__define_operation_type__"
#define CRABS_OP_CHECK_DEDUP       "__check_dedup__"

// OT Operations (v1.5 §8)
#define CRABS_OP_EXECUTE_OT        "__execute_ot__"

// Compaction Operation (v1.5.2 §4.3)
#define CRABS_OP_COMPACT           "__compact__"

// Timed Transactions (v1)
#define CRABS_OP_SCHEDULE        "__schedule__"
#define CRABS_OP_CANCEL_SCHEDULE "__cancel_schedule__"

// Write Domains (v1): equivocation report against a SOVEREIGN item's writer
#define CRABS_OP_REPORT_EQUIVOCATION "__report_equivocation__"

#endif // CRABS_CRABS_H
