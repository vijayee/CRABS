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
#define CRABS_MAX_LOG_ENTRIES   0    // Unlimited (0 = no limit)
#define CRABS_DEFAULT_LOCK_MS   5000 // Default lock timeout (5 seconds)
#define CRABS_MAX_LOCK_EXTENDS  3    // Maximum lock extensions
#define CRABS_LOCK_TOKEN_SIZE   32   // Lock token byte length
#define CRABS_UUID_SIZE         16   // UUID v4 byte length

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
  CRABS_ERR_VAULT_UNAVAILABLE      = 0x6005
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

#endif // CRABS_CRABS_H
