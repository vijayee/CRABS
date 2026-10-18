//
// crabs_node.cc — N-API bindings for the CRABS C library.
//
// Exposes the core CRABS API (attribute machine, state machine, crypto,
// ABE, serialization) to Node.js via node-addon-api (C++ N-API wrapper).
//
// Classes:
//   KeyPair   — ECDSA secp256k1 keypair (generate, sign, verify)
//   Operation — a signed state-machine operation
//   Blueprint — a serializable machine definition (lineage: machines mint
//               machines); JS owns the blueprint, release it with destroy()
//   Node      — a CRABS node (attribute machine + state + ABE master key)
//
// The Node class supports both Lamport and HLC (Hybrid Logical Clock)
// ordering. Use `new Node('admin', { ordering: 'hlc' })` for HLC mode.
//
// Lineage (v1.7): Node.lineageSpawn(blueprint) instantiates a child machine
// and hands JS a Node wrapper around it. Ownership mirrors the wasm binding's
// resident-registry statement: the child wrapper BORROWS the machine — the
// parent Node owns every machine it spawned (destroyed when the parent is
// collected) and C's resident-children registry keeps borrowed slots until
// dissolve. The child wrapper holds a reference to its parent object, so the
// borrowed pointer stays valid for the wrapper's whole lifetime.
//

#include <napi.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include "CRABS/data_model.h"
#include "Attribute/attribute_machine.h"
#include "StateMachine/state_machine.h"
#include "Crypto/crypto.h"
#include "Crypto/sig_scheme.h"
#include "Serialization/serialization.h"
#include "HLC/hlc.h"
#include "CRDT/crdt_merge.h"
#include "CRDT/one_shot.h"
#include "Lineage/lineage.h"
#include "Scheduler/scheduler.h"
#include "TimeSource/time_source.h"
#include "Raft/raft_module.h"
#include "OT/ot_execution.h"
#include "OT/ot_ordered_set.h"
#include "OT/ot_document.h"
#include "OT/ot_tree.h"
#include "TxManager/tx_manager.h"
#include "Util/allocator.h"
#include "TxManager/tx_manager_memory.h"
#include "Util/platform.h"
}

// ============================================================
// Helpers
// ============================================================

static std::string hex_encode(const uint8_t* data, size_t len) {
  static const char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    out.push_back(hex[(data[i] >> 4) & 0xF]);
    out.push_back(hex[data[i] & 0xF]);
  }
  return out;
}

// The five protocol states (protocol_state_e, src/CRABS/data_model.h:58-65).
// The JS surface spells them as words (the policy/ordering convention); the
// executor consumes the enum numbers in the op's per-resource state arrays.
static bool protocol_state_from_word(const std::string& word,
                                     protocol_state_e* out_state) {
  if (word == "idle")            *out_state = PROTOCOL_IDLE;
  else if (word == "locked")     *out_state = PROTOCOL_LOCKED;
  else if (word == "modified")   *out_state = PROTOCOL_MODIFIED;
  else if (word == "verified")   *out_state = PROTOCOL_VERIFIED;
  else if (word == "error")      *out_state = PROTOCOL_ERROR;
  else return false;
  return true;
}

static const char* protocol_state_name(protocol_state_e state) {
  switch (state) {
    case PROTOCOL_LOCKED:   return "locked";
    case PROTOCOL_MODIFIED: return "modified";
    case PROTOCOL_VERIFIED: return "verified";
    case PROTOCOL_ERROR:    return "error";
    default:                return "idle";
  }
}

static int64_t* resource_balance(data_item_t* item) {
  if (item == NULL || item->type != DATA_TYPE_RESOURCE ||
      item->value == NULL) {
    return NULL;
  }
  return (int64_t*)item->value;
}

static bool hex_decode(const std::string& hex, uint8_t* out, size_t out_len) {
  if (hex.length() != out_len * 2) return false;
  for (size_t i = 0; i < out_len; i++) {
    auto hv = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    int hi = hv(hex[i * 2]);
    int lo = hv(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

// The name table lifted verbatim from crabs_error's switch — ExecuteReplay
// needs the NAME (not a thrown Error) for its outcome object.
static std::string crabs_error_name(crabs_error_e err) {
  switch (err) {
    case CRABS_SUCCESS:                    return "success";
    case CRABS_ERR_PROTOCOL_VIOLATION:     return "protocol_violation";
    case CRABS_ERR_LOCK_TOKEN_MISMATCH:    return "lock_token_mismatch";
    case CRABS_ERR_LOCK_OWNER_MISMATCH:    return "lock_owner_mismatch";
    case CRABS_ERR_LOCK_CONTENTION:        return "lock_contention";
    case CRABS_ERR_LOCK_NOT_EXPIRED:       return "lock_not_expired";
    case CRABS_ERR_MAX_EXTENSIONS_REACHED: return "max_extensions_reached";
    case CRABS_ERR_FORCE_UNLOCK_DISABLED:  return "force_unlock_disabled";
    case CRABS_ERR_UNAUTHORIZED:           return "unauthorized";
    case CRABS_ERR_KEY_STALE:              return "key_stale";
    case CRABS_ERR_USER_NOT_FOUND:         return "user_not_found";
    case CRABS_ERR_USER_SUSPENDED:         return "user_suspended";
    // v1.3 §9 keyring refusals (parity-fill P2): these were previously
    // unnamed in this switch and collapsed into "unknown_error".
    case CRABS_ERR_KEY_SUSPENDED:          return "key_suspended";
    case CRABS_ERR_KEY_REVOKED:            return "key_revoked";
    case CRABS_ERR_KEY_EXPIRED:            return "key_expired";
    case CRABS_ERR_KEY_NOT_ACTIVE:         return "key_not_active";
    case CRABS_ERR_VAULT_UNAVAILABLE:      return "vault_unavailable";
    case CRABS_ERR_INVARIANT_VIOLATED:     return "invariant_violated";
    case CRABS_ERR_RESOURCE_NOT_FOUND:     return "resource_not_found";
    case CRABS_ERR_DUPLICATE_OPERATION:    return "duplicate_operation";
    case CRABS_ERR_TYPE_MISMATCH:          return "type_mismatch";
    case CRABS_ERR_ALREADY_PERFORMED:      return "already_performed";
    case CRABS_ERR_ALREADY_EXECUTED:       return "already_executed";
    case CRABS_ERR_CONDITION_NOT_MET:      return "condition_not_met";
    case CRABS_ERR_TRACKER_NOT_FOUND:      return "tracker_not_found";
    case CRABS_ERR_FLAG_NOT_FOUND:         return "flag_not_found";
    case CRABS_ERR_SCHEDULE_INVALID:       return "schedule_invalid";
    case CRABS_ERR_SERIALIZATION_ERROR:    return "serialization_error";
    case CRABS_ERR_CRYPTOGRAPHIC_ERROR:    return "cryptographic_error";
    case CRABS_ERR_INTERNAL:               return "internal_error";
    case CRABS_ERR_OOM:                    return "out_of_memory";
    case CRABS_ERR_INVALID_PARAM:          return "invalid_param";
    case CRABS_ERR_SCHEME_ALREADY_REGISTERED:
                                           return "scheme_already_registered";
    case CRABS_ERR_NOT_ITEM_WRITER:        return "not_item_writer";
    case CRABS_ERR_SEQ_MISMATCH:           return "seq_mismatch";
    case CRABS_ERR_FORK_DETECTED:          return "fork_detected";
    case CRABS_ERR_ORDERING_PATH:          return "ordering_path";
    case CRABS_ERR_ORDERING_PENDING:       return "ordering_pending";
    case CRABS_ERR_ORDERING_NOT_LEADER:    return "ordering_not_leader";
    case CRABS_ERR_ORDERING_CHANGE_IN_FLIGHT:
                                           return "ordering_change_in_flight";
    case CRABS_ERR_QUARANTINED:            return "quarantined";
    // 0x8xxx: OT errors (v1.5 §8)
    case CRABS_ERR_NO_OT_OPS:              return "no_ot_ops";
    case CRABS_ERR_NOT_OT_TYPE:            return "not_ot_type";
    case CRABS_ERR_OT_TRANSFORM_DEPTH:     return "ot_transform_depth";
    case CRABS_ERR_OT_POSITION_BOUNDS:     return "ot_position_bounds";
    // 0x9xxx: Compaction errors (v1.6 §6)
    case CRABS_ERR_COMPACTION_NOT_SUPPORTED:
                                           return "compaction_not_supported";
    case CRABS_ERR_COMPACTION_NOT_SAFE:    return "compaction_not_safe";
    case CRABS_ERR_COMPACTION_IN_PROGRESS: return "compaction_in_progress";
    default:                               return "unknown_error";
  }
}

static Napi::Error crabs_error(Napi::Env env, crabs_error_e err, const char* ctx) {
  std::string full = std::string(ctx) + ": " + crabs_error_name(err);
  return Napi::Error::New(env, full);
}

// Persistent per-class constructor references. Static factories
// (KeyPair.generate, Blueprint.create/deserialize) and Node's borrowed-child
// wrapper mint instances through these — the single env instance-data slot
// carries them all.
struct NodeAddonInstanceData {
  Napi::FunctionReference key_pair_ctor;
  Napi::FunctionReference abe_key_ctor;
  Napi::FunctionReference blueprint_ctor;
  Napi::FunctionReference node_ctor;
  Napi::FunctionReference operation_ctor;
};

// Adoption packet carried through a Napi::External so the Node constructor
// can wrap a machine it did NOT create (a spawned resident child) without
// changing the JS construction signature. The External finalizer frees it.
struct NodeAdoption {
  attribute_machine_t* am;
};

// A10-L12: reject non-string input at the boundary with a typed error instead
// of letting As<Napi::String>() coerce (or throw an untyped N-API failure)
// on JS-provided values.
static std::string require_js_string(const Napi::Value& value,
                                     const char* method, const char* field) {
  if (!value.IsString()) {
    throw Napi::TypeError::New(value.Env(),
        std::string(method) + ": " + field + " must be a string");
  }
  return value.As<Napi::String>().Utf8Value();
}

// Parity-fill P10 (binding alignment): the getSetElements page cap — the
// node mirror of CRABS_WASM_HANDLER_SET_PAGE_CAP (wasm_helpers.c:3083).
static const uint32_t CRABS_NODE_SET_PAGE_CAP = 256u;

// Byte-wise strcmp ordering for the pagination sort (stable across
// replicas — mirrors _handler_cstr_cmp in wasm_helpers.c).
static bool _crabs_node_cstr_less(const char* left, const char* right) {
  return strcmp(left, right) < 0;
}

// Collect the DISTINCT LIVE elements of an OR-set / one-shot set into
// `elements` (pair-tombstoned entries skipped, one entry per element even
// when several live tags carry it — the wasm binding's
// _handler_set_live_distinct, wasm_helpers.c:3088, entry for entry).
static void _collect_live_distinct(const data_item_t* item,
                                   std::vector<const char*>& elements) {
  elements.clear();
  if (item == NULL) return;
  if (item->crdt_type == CRDT_OR_SET) {
    const or_set_t* set = (const or_set_t*)item->value;
    if (!set) return;
    for (uint32_t entry_index = 0; entry_index < set->element_count;
         entry_index++) {
      const char* element = set->elements[entry_index].element;
      bool tombstoned = false;
      for (uint32_t tombstone_index = 0;
           tombstone_index < set->tombstone_count; tombstone_index++) {
        if (strcmp(set->tombstones[tombstone_index].element, element) == 0 &&
            strcmp(set->tombstones[tombstone_index].tag,
                   set->elements[entry_index].tag) == 0) {
          tombstoned = true;
          break;
        }
      }
      if (tombstoned) continue;
      bool seen = false;
      for (const char* known : elements) {
        if (strcmp(known, element) == 0) { seen = true; break; }
      }
      if (!seen) elements.push_back(element);
    }
  } else if (item->crdt_type == CRDT_ONE_SHOT_SET) {
    const one_shot_set_t* set = (const one_shot_set_t*)item->value;
    if (!set) return;
    for (uint32_t entry_index = 0; entry_index < set->element_count;
         entry_index++) {
      const char* element = set->elements[entry_index];
      bool seen = false;
      for (const char* known : elements) {
        if (strcmp(known, element) == 0) { seen = true; break; }
      }
      if (!seen) elements.push_back(element);
    }
  }
}

static std::string to_lower_ascii(const std::string& value) {
  std::string lowered = value;
  for (char& ch : lowered) {
    if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
  }
  return lowered;
}

// Timed-transactions argument parsing (v1): the schedule surface carries
// epoch ms / intervals / counts / ids as JS numbers (the node binding's
// number-only convention, mirroring setRegister), while the C scheduler API
// is uint64. Bigints are accepted too (mirroring the raft handle args) so a
// schedule id round-trips back into cancelSchedule unchanged. Every double
// must be a finite, non-negative integer within JS's exact-integer range
// (2^53) so the double→uint64 conversion never truncates or wraps.
static uint64_t require_u64_numeric(const Napi::Value& value,
                                    const char* method, const char* field) {
  if (value.IsBigInt()) {
    bool lossless = false;
    const uint64_t raw = value.As<Napi::BigInt>().Uint64Value(&lossless);
    if (!lossless) {
      throw Napi::RangeError::New(value.Env(),
          std::string(method) + ": " + field + " exceeds the 64-bit range");
    }
    return raw;
  }
  if (!value.IsNumber()) {
    throw Napi::TypeError::New(value.Env(),
        std::string(method) + ": " + field +
        " must be a non-negative number or bigint");
  }
  const double raw = value.As<Napi::Number>().DoubleValue();
  if (!std::isfinite(raw) || raw < 0 || raw >= 9007199254740992.0 ||
      raw != floor(raw)) {
    throw Napi::RangeError::New(value.Env(),
        std::string(method) + ": " + field +
        " must be an integer 0..2^53-1");
  }
  return (uint64_t)raw;
}

// trustMode — string word or the wire number (mirrors the wasm bindings'
// TRUST_MODE table). Returns false for anything outside the enum.
static bool lineage_trust_mode_from_js(const Napi::Value& value,
                                       lineage_trust_mode_e* out) {
  if (value.IsNumber()) {
    auto trust_number = value.As<Napi::Number>().DoubleValue();
    if (trust_number == (double)LINEAGE_SHARED_ROOT) { *out = LINEAGE_SHARED_ROOT; return true; }
    if (trust_number == (double)LINEAGE_DELEGATED_COPY) { *out = LINEAGE_DELEGATED_COPY; return true; }
    if (trust_number == (double)LINEAGE_SOVEREIGN) { *out = LINEAGE_SOVEREIGN; return true; }
    return false;
  }
  if (value.IsString()) {
    std::string word = to_lower_ascii(value.As<Napi::String>().Utf8Value());
    if (word == "shared_root" || word == "shared") { *out = LINEAGE_SHARED_ROOT; return true; }
    if (word == "delegated_copy" || word == "delegated") { *out = LINEAGE_DELEGATED_COPY; return true; }
    if (word == "sovereign") { *out = LINEAGE_SOVEREIGN; return true; }
  }
  return false;
}

// data_type_e from a JS string word or wire number. Covers the full
// data_model.h enum, mirroring the wasm DATA_TYPE table's naming.
static bool data_type_from_js(const Napi::Value& value, data_type_e* out) {
  if (value.IsNumber()) {
    auto type_number = value.As<Napi::Number>().DoubleValue();
    if (type_number == (double)DATA_TYPE_COUNTER) { *out = DATA_TYPE_COUNTER; return true; }
    if (type_number == (double)DATA_TYPE_PN_COUNTER) { *out = DATA_TYPE_PN_COUNTER; return true; }
    if (type_number == (double)DATA_TYPE_SET) { *out = DATA_TYPE_SET; return true; }
    if (type_number == (double)DATA_TYPE_2P_SET) { *out = DATA_TYPE_2P_SET; return true; }
    if (type_number == (double)DATA_TYPE_REGISTER) { *out = DATA_TYPE_REGISTER; return true; }
    if (type_number == (double)DATA_TYPE_DOCUMENT) { *out = DATA_TYPE_DOCUMENT; return true; }
    if (type_number == (double)DATA_TYPE_RESOURCE) { *out = DATA_TYPE_RESOURCE; return true; }
    if (type_number == (double)DATA_TYPE_ONE_SHOT_SET) { *out = DATA_TYPE_ONE_SHOT_SET; return true; }
    if (type_number == (double)DATA_TYPE_ONE_SHOT_FLAG) { *out = DATA_TYPE_ONE_SHOT_FLAG; return true; }
    if (type_number == (double)DATA_TYPE_OT_ORDERED_SET) { *out = DATA_TYPE_OT_ORDERED_SET; return true; }
    if (type_number == (double)DATA_TYPE_OT_DOCUMENT) { *out = DATA_TYPE_OT_DOCUMENT; return true; }
    if (type_number == (double)DATA_TYPE_OT_TABLE) { *out = DATA_TYPE_OT_TABLE; return true; }
    if (type_number == (double)DATA_TYPE_OT_TREE) { *out = DATA_TYPE_OT_TREE; return true; }
    if (type_number == (double)DATA_TYPE_OT_ORDERED_MAP) { *out = DATA_TYPE_OT_ORDERED_MAP; return true; }
    if (type_number == (double)DATA_TYPE_CUSTOM) { *out = DATA_TYPE_CUSTOM; return true; }
    return false;
  }
  if (value.IsString()) {
    std::string word = to_lower_ascii(value.As<Napi::String>().Utf8Value());
    if (word == "counter") { *out = DATA_TYPE_COUNTER; return true; }
    if (word == "pn_counter") { *out = DATA_TYPE_PN_COUNTER; return true; }
    if (word == "set") { *out = DATA_TYPE_SET; return true; }
    if (word == "2p_set") { *out = DATA_TYPE_2P_SET; return true; }
    if (word == "register") { *out = DATA_TYPE_REGISTER; return true; }
    if (word == "document") { *out = DATA_TYPE_DOCUMENT; return true; }
    if (word == "resource") { *out = DATA_TYPE_RESOURCE; return true; }
    if (word == "one_shot_set") { *out = DATA_TYPE_ONE_SHOT_SET; return true; }
    if (word == "one_shot_flag") { *out = DATA_TYPE_ONE_SHOT_FLAG; return true; }
    if (word == "ot_ordered_set") { *out = DATA_TYPE_OT_ORDERED_SET; return true; }
    if (word == "ot_document") { *out = DATA_TYPE_OT_DOCUMENT; return true; }
    if (word == "ot_table") { *out = DATA_TYPE_OT_TABLE; return true; }
    if (word == "ot_tree") { *out = DATA_TYPE_OT_TREE; return true; }
    if (word == "ot_ordered_map") { *out = DATA_TYPE_OT_ORDERED_MAP; return true; }
    if (word == "custom") { *out = DATA_TYPE_CUSTOM; return true; }
  }
  return false;
}

// crdt_type_e from a JS string word or wire number (mirrors the wasm
// CRDT_TYPE table).
static bool crdt_type_from_js(const Napi::Value& value, crdt_type_e* out) {
  if (value.IsNumber()) {
    auto crdt_number = value.As<Napi::Number>().DoubleValue();
    if (crdt_number == (double)CRDT_G_COUNTER) { *out = CRDT_G_COUNTER; return true; }
    if (crdt_number == (double)CRDT_PN_COUNTER) { *out = CRDT_PN_COUNTER; return true; }
    if (crdt_number == (double)CRDT_OR_SET) { *out = CRDT_OR_SET; return true; }
    if (crdt_number == (double)CRDT_2P_SET) { *out = CRDT_2P_SET; return true; }
    if (crdt_number == (double)CRDT_LWW_REG) { *out = CRDT_LWW_REG; return true; }
    if (crdt_number == (double)CRDT_RGA) { *out = CRDT_RGA; return true; }
    if (crdt_number == (double)CRDT_ONE_SHOT_SET) { *out = CRDT_ONE_SHOT_SET; return true; }
    if (crdt_number == (double)CRDT_ONE_SHOT_FLAG) { *out = CRDT_ONE_SHOT_FLAG; return true; }
    if (crdt_number == (double)CRDT_CUSTOM) { *out = CRDT_CUSTOM; return true; }
    return false;
  }
  if (value.IsString()) {
    std::string word = to_lower_ascii(value.As<Napi::String>().Utf8Value());
    if (word == "g_counter") { *out = CRDT_G_COUNTER; return true; }
    if (word == "pn_counter") { *out = CRDT_PN_COUNTER; return true; }
    if (word == "or_set") { *out = CRDT_OR_SET; return true; }
    if (word == "2p_set") { *out = CRDT_2P_SET; return true; }
    if (word == "lww_reg") { *out = CRDT_LWW_REG; return true; }
    if (word == "rga") { *out = CRDT_RGA; return true; }
    if (word == "one_shot_set") { *out = CRDT_ONE_SHOT_SET; return true; }
    if (word == "one_shot_flag") { *out = CRDT_ONE_SHOT_FLAG; return true; }
    if (word == "custom") { *out = CRDT_CUSTOM; return true; }
  }
  return false;
}

// ============================================================
// KeyPair — wraps ecdsa_keypair_t
// ============================================================

class KeyPair : public Napi::ObjectWrap<KeyPair> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "KeyPair", {
      InstanceMethod("publicKeyHex", &KeyPair::PublicKeyHex),
      InstanceMethod("privateKeyHex", &KeyPair::PrivateKeyHex),
      StaticMethod("generate", &KeyPair::Generate),
      StaticMethod("fromPrivateHex", &KeyPair::FromPrivateHex),
      StaticMethod("derivePublicHex", &KeyPair::DerivePublicHex),
    });
    // Stored in the shared NodeAddonInstanceData set up by the module Init —
    // static factories mint instances through it.
    auto* inst = env.GetInstanceData<NodeAddonInstanceData>();
    inst->key_pair_ctor = Napi::Persistent(func);
    exports.Set("KeyPair", func);
    return exports;
  }

  KeyPair(const Napi::CallbackInfo& info) : Napi::ObjectWrap<KeyPair>(info) {
    kp_ = nullptr;
  }

  ~KeyPair() {
    if (kp_) crypto_ecdsa_keypair_destroy(kp_);
  }

  ecdsa_keypair_t* raw() { return kp_; }

private:
  ecdsa_keypair_t* kp_;

  Napi::Value PublicKeyHex(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), hex_encode(kp_->public_key, 33));
  }

  Napi::Value PrivateKeyHex(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), hex_encode(kp_->private_key, 32));
  }

  static Napi::Value Generate(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    auto* inst = env.GetInstanceData<NodeAddonInstanceData>();
    Napi::Object obj = inst->key_pair_ctor.New({});
    KeyPair* kp = KeyPair::Unwrap(obj);
    kp->kp_ = crypto_ecdsa_generate();
    if (!kp->kp_) throw crabs_error(env, CRABS_ERR_CRYPTOGRAPHIC_ERROR, "KeyPair.generate");
    return obj;
  }

  static Napi::Value FromPrivateHex(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString())
      throw Napi::TypeError::New(env, "Expected private key hex string");
    std::string hex = info[0].As<Napi::String>().Utf8Value();
    auto* inst = env.GetInstanceData<NodeAddonInstanceData>();
    Napi::Object obj = inst->key_pair_ctor.New({});
    KeyPair* kp = KeyPair::Unwrap(obj);
    kp->kp_ = (ecdsa_keypair_t*)calloc(1, sizeof(ecdsa_keypair_t));
    if (!kp->kp_) {
      // OOM before any decode — nothing landed in the struct, but the hex
      // copy still holds the caller's secret; cleanse before refusing
      // (null deref guard: hex_decode below writes through kp->kp_).
      OPENSSL_cleanse(&hex[0], hex.size());
      throw crabs_error(env, CRABS_ERR_OOM, "KeyPair.fromPrivateHex");
    }
    if (!hex_decode(hex, kp->kp_->private_key, 32)) {
      // Audit M-6: the std::string copy of the secret must never outlive the
      // decode attempt uncleansed (GC-visible heap bytes; the DecryptKeyEnvelope
      // pattern).
      OPENSSL_cleanse(&hex[0], hex.size());
      throw Napi::Error::New(env, "Invalid private key hex (expected 64 chars)");
    }
    // Derive public key from private key
    crabs_error_e rc = crypto_ecdsa_derive_public_key(kp->kp_->private_key, kp->kp_->public_key);
    OPENSSL_cleanse(&hex[0], hex.size());
    if (rc != CRABS_SUCCESS) {
      // Audit pass-3 (D1): the calloc'd keypair struct ALREADY holds the
      // decoded secret in private_key[32] — free(kp->kp_) alone puts the
      // scalar on libc's free list. Cleanse the whole struct before release.
      OPENSSL_cleanse(kp->kp_, sizeof(ecdsa_keypair_t));
      free(kp->kp_);
      kp->kp_ = nullptr;
      throw crabs_error(env, rc, "KeyPair.fromPrivateHex");
    }
    return obj;
  }

  static Napi::Value DerivePublicHex(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString())
      throw Napi::TypeError::New(env, "Expected private key hex string");
    std::string hex = info[0].As<Napi::String>().Utf8Value();
    uint8_t priv[32], pub[33];
    if (!hex_decode(hex, priv, 32)) {
      OPENSSL_cleanse(priv, sizeof(priv));
      OPENSSL_cleanse(&hex[0], hex.size());  // Audit M-6: cleanse the heap copy too
      throw Napi::Error::New(env, "Invalid private key hex");
    }
    crabs_error_e rc = crypto_ecdsa_derive_public_key(priv, pub);
    OPENSSL_cleanse(priv, sizeof(priv));  // key bytes never leave this frame
    OPENSSL_cleanse(&hex[0], hex.size());  // Audit M-6: cleanse the heap copy too
    if (rc != CRABS_SUCCESS) {
      OPENSSL_cleanse(pub, sizeof(pub));
      throw crabs_error(env, rc, "derivePublicHex");
    }
    return Napi::String::New(env, hex_encode(pub, 33));
  }
};

// ============================================================
// AbeKey — wraps abe_user_key_t (gap-fill A11)
// ============================================================

// A machine-derived CP-ABE reader key: Node.abeKeygen derives it from the
// machine's OWN master authority (state->abe_mk), so JS never touches the
// master secret — the machine mints it, JS holds only the derived key. JS
// OWNS the pointer: destroy() releases it (the destructor releases it too,
// matching the KeyPair/Blueprint convention). Portable bytes exist only
// through toWire(): the C crypto_abe_user_key_serialize form — a
// SELF-SUFFICIENT BEARER image of the key: restored on ANY machine
// (Node.abeKeyFromWire asks only that the machine holds an authority; the C
// deserialize takes mk, but OpenABE's key import binds capability to the
// key's own minting domain, so the restored key opens EXACTLY what its
// minting authority sealed — verified cross-machine in test/abe.js), with no
// integrity check of its own. Transport it authenticated, or use the key
// envelope flow (Node.mintKeyEnvelope / Node.decryptKeyEnvelope): the
// signed, ECIES-wrapped transport for channels you do not trust.
class AbeKey : public Napi::ObjectWrap<AbeKey> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "AbeKey", {
      InstanceMethod("toWire", &AbeKey::ToWire),
      InstanceMethod("destroy", &AbeKey::Destroy),
    });
    // Stored in the shared NodeAddonInstanceData set up by the module Init —
    // Node.abeKeygen mints instances through it.
    auto* inst = env.GetInstanceData<NodeAddonInstanceData>();
    inst->abe_key_ctor = Napi::Persistent(func);
    exports.Set("AbeKey", func);
    return exports;
  }

  AbeKey(const Napi::CallbackInfo& info) : Napi::ObjectWrap<AbeKey>(info) {
    sk_ = nullptr;
  }

  ~AbeKey() {
    if (sk_) crypto_abe_user_key_destroy(sk_);
  }

  abe_user_key_t* raw() { return sk_; }

  // Factory the binding's static methods use (keygen mints; nothing else).
  static Napi::Object NewInstance(Napi::Env env, abe_user_key_t* sk) {
    auto* inst = env.GetInstanceData<NodeAddonInstanceData>();
    Napi::Object obj = inst->abe_key_ctor.New({});
    AbeKey* key = AbeKey::Unwrap(obj);
    key->sk_ = sk;
    return obj;
  }

private:
  abe_user_key_t* sk_;

  Napi::Value ToWire(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (sk_ == nullptr)
      throw Napi::Error::New(env, "abeKey.toWire: a destroyed key refuses");
    size_t needed = crypto_abe_user_key_serialize(sk_, nullptr, 0);
    if (needed == 0)
      throw Napi::Error::New(env, "abeKey.toWire: serialization failed");
    Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::New(env, needed);
    size_t written = crypto_abe_user_key_serialize(sk_, out.Data(), needed);
    if (written != needed)
      throw Napi::Error::New(env, "abeKey.toWire: serialization failed");
    return out;
  }

  Napi::Value Destroy(const Napi::CallbackInfo& info) {
    if (sk_) {
      crypto_abe_user_key_destroy(sk_);
      sk_ = nullptr;
    }
    return info.Env().Undefined();
  }
};

// ============================================================
// Blueprint — wraps machine_blueprint_t (Lineage v1.7)
// ============================================================

// JS wrapper over the C machine_blueprint_t. JS OWNS the blueprint: it must
// be released via destroy() (or dropped — the destructor releases it too).
// The MACHINE the blueprint spawns is different — the parent Node keeps
// spawned child machines alive (see Node.lineageSpawn); JS only ever borrows
// those.
class Blueprint : public Napi::ObjectWrap<Blueprint> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "Blueprint", {
      StaticMethod("create", &Blueprint::Create),
      StaticMethod("deserialize", &Blueprint::Deserialize),
      InstanceMethod("addItem", &Blueprint::AddItem),
      InstanceMethod("addOpType", &Blueprint::AddOpType),
      InstanceMethod("addPolicy", &Blueprint::AddPolicy),
      InstanceMethod("stampHash", &Blueprint::StampHash),
      InstanceMethod("serialize", &Blueprint::Serialize),
      InstanceMethod("destroy", &Blueprint::Destroy),
    });
    auto* inst = env.GetInstanceData<NodeAddonInstanceData>();
    inst->blueprint_ctor = Napi::Persistent(func);
    exports.Set("Blueprint", func);
    return exports;
  }

  // Two construction paths on one constructor:
  //   new Blueprint(childId, trustMode, bootstrapAdmin, ttlMs) — a fresh
  //   empty blueprint (the static create() delegates here).
  //   new Blueprint(wireBuffer) — parse a wire image as produced by
  //   serialize(); the embedded hash is verified and the blueprint is
  //   structurally validated (the static deserialize() delegates here).
  Blueprint(const Napi::CallbackInfo& info) : Napi::ObjectWrap<Blueprint>(info) {
    Napi::Env env = info.Env();
    bp_ = nullptr;

    if (info.Length() >= 1 && info[0].IsBuffer()) {
      auto wire = info[0].As<Napi::Buffer<uint8_t>>();
      bp_ = blueprint_deserialize(wire.Data(), wire.Length());
      if (bp_ == nullptr)
        throw Napi::Error::New(env,
            "Blueprint wire image malformed (hash or structure check failed)");
      // Deserialization verifies the hash + bounds; the full structural
      // validation (id safety, admin presence per trust mode, policy
      // expressions) runs here too so a wire image that parses but is not
      // spawnable fails fast at the door.
      crabs_error_e rc = lineage_blueprint_validate(bp_);
      if (rc != CRABS_SUCCESS) {
        machine_blueprint_destroy(bp_);
        bp_ = nullptr;
        throw crabs_error(env, rc, "Blueprint.deserialize");
      }
      return;
    }

    if (info.Length() < 4 || !info[0].IsString() || !info[2].IsString())
      throw Napi::TypeError::New(env,
          "Expected (childId, trustMode, bootstrapAdmin, ttlMs) or a wire Buffer");
    std::string child_id = info[0].As<Napi::String>().Utf8Value();
    std::string bootstrap_admin = info[2].As<Napi::String>().Utf8Value();
    lineage_trust_mode_e trust_mode;
    if (!lineage_trust_mode_from_js(info[1], &trust_mode))
      throw Napi::TypeError::New(env,
          "trustMode must be 'shared_root' | 'delegated_copy' | 'sovereign' "
          "or the matching TRUST_MODE number");
    // Gated BEFORE the double→uint64 conversion: a negative or fractional
    // ttlMs is an out-of-range float→int conversion (UB) or a silent
    // truncation; BigInts carry the full u64 range.
    const uint64_t attestation_ttl_ms =
        require_u64_numeric(info[3], "Blueprint", "ttlMs");

    bp_ = machine_blueprint_create();
    if (bp_ == nullptr) throw Napi::Error::New(env, "Failed to allocate blueprint");
    strncpy(bp_->child_id, child_id.c_str(), CRABS_MAX_USER_ID - 1);
    bp_->child_id[CRABS_MAX_USER_ID - 1] = '\0';
    strncpy(bp_->bootstrap_admin, bootstrap_admin.c_str(), CRABS_MAX_USER_ID - 1);
    bp_->bootstrap_admin[CRABS_MAX_USER_ID - 1] = '\0';
    bp_->trust_mode = trust_mode;
    bp_->attestation_ttl_ms = attestation_ttl_ms;
  }

  ~Blueprint() {
    if (bp_) machine_blueprint_destroy(bp_);
  }

  machine_blueprint_t* raw() { return bp_; }

private:
  machine_blueprint_t* bp_;

  void EnsureAlive(Napi::Env env) {
    if (bp_ == nullptr) throw Napi::Error::New(env, "blueprint already destroyed");
  }

  static Napi::Value Create(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 4)
      throw Napi::TypeError::New(env,
          "Expected (childId, trustMode, bootstrapAdmin, ttlMs)");
    auto* inst = env.GetInstanceData<NodeAddonInstanceData>();
    return inst->blueprint_ctor.New({info[0], info[1], info[2], info[3]});
  }

  static Napi::Value Deserialize(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsBuffer())
      throw Napi::TypeError::New(env, "Expected a blueprint wire Buffer");
    auto* inst = env.GetInstanceData<NodeAddonInstanceData>();
    return inst->blueprint_ctor.New({info[0]});
  }

  Napi::Value AddItem(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    EnsureAlive(env);
    if (info.Length() < 3 || !info[0].IsString())
      throw Napi::TypeError::New(env, "Expected (name, dataType, crdtType, opts?)");
    std::string name = info[0].As<Napi::String>().Utf8Value();
    data_type_e data_type;
    crdt_type_e crdt_type;
    if (!data_type_from_js(info[1], &data_type))
      throw Napi::TypeError::New(env,
          "dataType must be a DATA_TYPE word ('counter', 'set', ...) or number");
    if (!crdt_type_from_js(info[2], &crdt_type))
      throw Napi::TypeError::New(env,
          "crdtType must be a CRDT_TYPE word ('g_counter', 'or_set', ...) or number");
    crabs_error_e rc;
    // With a write-domain declaration ({ domain, writer? }) the item
    // carries write-domains v1 authoring (blueprint_add_item_with_domain,
    // lineage.h:147): a SOVEREIGN item needs its writer id and stays
    // v1-restricted to COUNTER/REGISTER (the C gate refuses type_mismatch),
    // a writer on any other domain refuses invalid_param. A writer with no
    // explicit domain is authored against the DEFAULT domain (FREE) — the
    // C helper refuses that pairing itself, exactly like defineItem's
    // word mapping feeds its defaults through.
    if (info.Length() > 3 && info[3].IsObject()) {
      Napi::Object opts = info[3].As<Napi::Object>();
      crabs_write_domain_e write_domain = CRABS_DOMAIN_FREE_MERGE;
      if (opts.Has("domain")) {
        std::string domain_word = to_lower_ascii(
            require_js_string(opts.Get("domain"), "Blueprint.addItem", "domain"));
        if (domain_word == "free") {
          write_domain = CRABS_DOMAIN_FREE_MERGE;
        } else if (domain_word == "sovereign") {
          write_domain = CRABS_DOMAIN_SOVEREIGN;
        } else if (domain_word == "group") {
          write_domain = CRABS_DOMAIN_GROUP_ORDERED;
        } else {
          throw Napi::TypeError::New(env,
              "Blueprint.addItem: domain must be 'free' | 'sovereign' | 'group'");
        }
      }
      std::string writer;
      if (opts.Has("writer")) {
        writer = require_js_string(opts.Get("writer"), "Blueprint.addItem", "writer");
      }
      rc = blueprint_add_item_with_domain(bp_, name.c_str(), data_type,
                                          crdt_type, write_domain,
                                          writer.empty() ? nullptr
                                                         : writer.c_str(),
                                          0 /* v1: no ordering modules */);
    } else {
      rc = blueprint_add_item(bp_, name.c_str(), data_type, crdt_type);
    }
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "Blueprint.addItem");
    return env.Undefined();
  }

  // Carried dedup-spec authoring (blueprint_add_op_type_def, lineage.h:157)
  // — the same shape Node::DefineOperationType registers machine-locally,
  // authored into the CHILD's registry via the blueprint: at spawn the spec
  // lands in the child's op-type registry and the executor enforces it
  // there exactly like a local define would. Word/validation discipline
  // mirrors DefineOperationType (the 'custom' shape stays C-native).
  Napi::Value AddOpType(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    EnsureAlive(env);
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsObject())
      throw Napi::TypeError::New(env,
          "Expected addOpType(opType, { dedup, trackerPath?, flagPath?, "
          "rejectionMessage? })");
    std::string op_type = require_js_string(info[0], "Blueprint.addOpType", "opType");
    if (op_type.empty())
      throw Napi::TypeError::New(env,
          "Blueprint.addOpType: opType must be a non-empty string");
    Napi::Object options = info[1].As<Napi::Object>();
    std::string dedup_word = to_lower_ascii(
        require_js_string(options.Get("dedup"), "Blueprint.addOpType", "dedup"));
    dedup_type_e dedup_type;
    if (dedup_word == "none") {
      dedup_type = DEDUP_NONE;
    } else if (dedup_word == "per-user") {
      dedup_type = DEDUP_PER_USER;
    } else if (dedup_word == "global") {
      dedup_type = DEDUP_GLOBAL;
    } else {
      throw Napi::TypeError::New(env,
          "Blueprint.addOpType: dedup must be 'per-user' | 'global' | 'none' "
          "(the 'custom' shape is C-native and not surfaceable)");
    }
    std::string tracker_path;
    std::string flag_path;
    std::string rejection_message;
    if (options.Has("trackerPath")) {
      tracker_path = require_js_string(options.Get("trackerPath"),
                                       "Blueprint.addOpType", "trackerPath");
    }
    if (options.Has("flagPath")) {
      flag_path = require_js_string(options.Get("flagPath"),
                                    "Blueprint.addOpType", "flagPath");
    }
    if (dedup_type == DEDUP_PER_USER && tracker_path.empty()) {
      throw Napi::TypeError::New(env,
          "Blueprint.addOpType: dedup 'per-user' requires a trackerPath "
          "(the ONE_SHOT_SET once-record item, carried in the same blueprint)");
    }
    if (dedup_type == DEDUP_NONE &&
        (!tracker_path.empty() || !flag_path.empty())) {
      throw Napi::TypeError::New(env,
          "Blueprint.addOpType: dedup 'none' takes no trackerPath/flagPath "
          "(a 'none' definition removes the guard; nothing to track)");
    }
    if (dedup_type == DEDUP_GLOBAL && flag_path.empty()) {
      throw Napi::TypeError::New(env,
          "Blueprint.addOpType: dedup 'global' requires a flagPath "
          "(the ONE_SHOT_FLAG once-record item, carried in the same blueprint)");
    }
    // The C spec fields are CRABS_MAX_DEDUP_PATH (128) / CRABS_MAX_DEDUP_MESSAGE
    // (256) bytes — a longer string would be silently truncated into a
    // tracker/flag lookup that never resolves (or a cut-off message), so
    // refuse loudly instead.
    if (tracker_path.length() >= CRABS_MAX_DEDUP_PATH) {
      throw Napi::RangeError::New(env,
          "Blueprint.addOpType: trackerPath exceeds 127 bytes");
    }
    if (flag_path.length() >= CRABS_MAX_DEDUP_PATH) {
      throw Napi::RangeError::New(env,
          "Blueprint.addOpType: flagPath exceeds 127 bytes");
    }
    if (options.Has("rejectionMessage")) {
      rejection_message = require_js_string(
          options.Get("rejectionMessage"), "Blueprint.addOpType",
          "rejectionMessage");
      if (rejection_message.length() >= CRABS_MAX_DEDUP_MESSAGE) {
        throw Napi::RangeError::New(env,
            "Blueprint.addOpType: rejectionMessage exceeds 255 bytes");
      }
    }
    dedup_spec_t spec;
    memset(&spec, 0, sizeof(spec));
    spec.type = dedup_type;
    if (!tracker_path.empty()) {
      strncpy(spec.tracker_path, tracker_path.c_str(),
              sizeof(spec.tracker_path) - 1);
    }
    if (!flag_path.empty()) {
      strncpy(spec.flag_path, flag_path.c_str(), sizeof(spec.flag_path) - 1);
    }
    if (!rejection_message.empty()) {
      strncpy(spec.rejection_message, rejection_message.c_str(),
              sizeof(spec.rejection_message) - 1);
    }
    crabs_error_e rc = blueprint_add_op_type_def(bp_, op_type.c_str(), &spec);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "Blueprint.addOpType");
    return env.Undefined();
  }

  Napi::Value AddPolicy(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    EnsureAlive(env);
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString())
      throw Napi::TypeError::New(env, "Expected (operation, expression)");
    std::string operation = info[0].As<Napi::String>().Utf8Value();
    std::string expression = info[1].As<Napi::String>().Utf8Value();
    crabs_error_e rc = blueprint_add_policy(bp_, operation.c_str(),
                                            expression.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "Blueprint.addPolicy");
    return env.Undefined();
  }

  Napi::Value StampHash(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    EnsureAlive(env);
    crabs_error_e rc = machine_blueprint_stamp_hash(bp_);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "Blueprint.stampHash");
    return env.Undefined();
  }

  // Wire image (u32le total length + canonical body + 32-byte blueprint
  // hash). Stamps the hash first — this is exactly the payload a
  // __spawn_machine__ op carries, so blueprints can be shipped between
  // processes.
  Napi::Value Serialize(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    EnsureAlive(env);
    std::vector<uint8_t> wire(CRABS_BLUEPRINT_WIRE_MAX);
    size_t written = blueprint_serialize(bp_, wire.data(), wire.size());
    if (written == 0)
      throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "Blueprint.serialize");
    return Napi::Buffer<uint8_t>::Copy(env, wire.data(), written);
  }

  void Destroy(const Napi::CallbackInfo& info) {
    if (bp_) {
      machine_blueprint_destroy(bp_);
      bp_ = nullptr;
    }
  }
};

// Append a resource name to an operation (shared by Operation.addResource
// and Node.defineOperationType). The wire arrays are heap-grown one slot at
// a time; capacity CRABS_MAX_RESOURCES. Write-domains v1: an op naming a
// SOVEREIGN item among its resources must carry a matching sovereign prefix
// per sovereign resource (DOMAIN_CHECK enforces the exact count). The
// required_state / next_state arrays are per-resource too — the signing
// canonical form and the executor index them all up to resource_count, so
// the three grow together (zeroed states = PROTOCOL_IDLE, matching the
// deserializer's default for a state-unconstrained resource).
static void operation_append_resource(operation_t* op, const std::string& name,
                                      Napi::Env env, const char* ctx) {
  if (name.empty() || name.length() >= CRABS_MAX_USER_ID)
    throw Napi::RangeError::New(env,
        std::string(ctx) + ": name must be 1..63 characters");
  if (op->resource_count >= CRABS_MAX_RESOURCES)
    throw Napi::RangeError::New(env,
        std::string(ctx) + ": resource capacity reached");
  uint32_t grown_count = op->resource_count + 1;
  auto grown_resources = (char(*)[CRABS_MAX_USER_ID])realloc(
      op->resources, grown_count * CRABS_MAX_USER_ID);
  if (grown_resources == NULL) {
    throw crabs_error(env, CRABS_ERR_OOM, ctx);
  }
  op->resources = grown_resources;
  auto grown_required = (protocol_state_e*)realloc(
      op->required_state, grown_count * sizeof(protocol_state_e));
  if (grown_required == NULL) {
    throw crabs_error(env, CRABS_ERR_OOM, ctx);
  }
  op->required_state = grown_required;
  auto grown_next = (protocol_state_e*)realloc(
      op->next_state, grown_count * sizeof(protocol_state_e));
  if (grown_next == NULL) {
    throw crabs_error(env, CRABS_ERR_OOM, ctx);
  }
  op->next_state = grown_next;
  memset(op->resources[op->resource_count], 0, CRABS_MAX_USER_ID);
  strncpy(op->resources[op->resource_count], name.c_str(),
          CRABS_MAX_USER_ID - 1);
  op->required_state[op->resource_count] = PROTOCOL_IDLE;
  op->next_state[op->resource_count] = PROTOCOL_IDLE;
  op->resource_count = grown_count;
}

// ============================================================
// Operation — wraps operation_t
// ============================================================

class Operation : public Napi::ObjectWrap<Operation> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "Operation", {
      // Parity-fill P10 (binding alignment): adopt a wire op — the wasm
      // binding's Operation.deserialize round trip (smoke.js:33,
      // attestations.js:219).
      StaticMethod("deserialize", &Operation::DeserializeStatic),
      InstanceMethod("sign", &Operation::Sign),
      InstanceMethod("signWithPrivateKey", &Operation::SignWithPrivateKey),
      InstanceMethod("addResource", &Operation::AddResource),
      InstanceMethod("setSovereignPrefix", &Operation::SetSovereignPrefix),
      // Lock protocol (recipe 9): per-slot protocol states + lock claims
      InstanceMethod("setRequiredState", &Operation::SetRequiredState),
      InstanceMethod("setNextState", &Operation::SetNextState),
      InstanceMethod("addLockClaim", &Operation::AddLockClaim),
      // Attestation bridge (recipe 12): attach a parent-signed vouch
      InstanceMethod("addAttestation", &Operation::AddAttestation),
      InstanceMethod("serialize", &Operation::SerializeOp),
      InstanceAccessor("type", &Operation::GetType, &Operation::SetType),
      InstanceAccessor("signerId", &Operation::GetSignerId, &Operation::SetSignerId),
      InstanceAccessor("nodeId", &Operation::GetNodeId, &Operation::SetNodeId),
      InstanceAccessor("payload", &Operation::GetPayload, &Operation::SetPayload),
      InstanceAccessor("lamportTime", &Operation::GetLamportTime, &Operation::SetLamportTime),
      InstanceMethod("getWireVersion", &Operation::GetWireVersion),
    });
    exports.Set("Operation", func);
    auto* inst = env.GetInstanceData<NodeAddonInstanceData>();
    inst->operation_ctor = Napi::Persistent(func);
    return exports;
  }

  // Two construction paths on one constructor (the Blueprint(wire) shape):
  //   new Operation(type) — a fresh op with a minted UUID.
  //   new Operation(wireBuffer) — parse a wire image (Operation.deserialize
  //   delegates here through the persistent constructor). The op's UUID and
  //   signature are whatever the wire carries.
  Operation(const Napi::CallbackInfo& info) : Napi::ObjectWrap<Operation>(info) {
    Napi::Env env = info.Env();
    op_ = nullptr;

    if (info.Length() > 0 && info[0].IsBuffer()) {
      auto wire = info[0].As<Napi::Buffer<uint8_t>>();
      op_ = crabs_deserialize_operation(wire.Data(), wire.Length());
      if (!op_)
        throw Napi::Error::New(env,
            "Operation.deserialize: malformed operation wire (parse failed)");
      return;
    }

    std::string type = "unknown";
    if (info.Length() > 0 && info[0].IsString())
      type = info[0].As<Napi::String>().Utf8Value();
    op_ = operation_create(type.c_str());
    if (!op_) throw Napi::Error::New(env, "Failed to create operation");
    // Generate a random UUID so the idempotency check in state_machine_execute
    // doesn't treat this as a duplicate of a prior operation (all-zeros UUID
    // would match any prior all-zeros UUID, causing the op to be silently
    // skipped before trigger processing).
    crypto_random_bytes(op_->uuid, CRABS_UUID_SIZE);
  }

  ~Operation() {
    if (op_) operation_destroy(op_);
  }

  // Static deserialize(wire) → the Operation wrapper over the parsed op
  // (crabs_deserialize_operation, serialization.h:102). Mirrors the wasm
  // binding's Operation.deserialize: a malformed image refuses loudly, a
  // well-formed image round-trips byte-identically on re-serialize, and
  // the adopted op executes exactly like a locally-created one.
  static Napi::Value DeserializeStatic(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || (!info[0].IsBuffer() && !info[0].IsTypedArray()))
      throw Napi::TypeError::New(env,
          "Operation.deserialize: expected a wire Buffer (op.serialize() bytes)");
    auto* inst = env.GetInstanceData<NodeAddonInstanceData>();
    Napi::Object restored = inst->operation_ctor.Value().New({info[0]});
    return restored;
  }

  operation_t* raw() { return op_; }

private:
  operation_t* op_;

  Napi::Value GetType(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), op_->type);
  }
  void SetType(const Napi::CallbackInfo& info, const Napi::Value& val) {
    (void)info;
    strncpy(op_->type, require_js_string(val, "Operation.type", "value").c_str(),
            CRABS_MAX_OP_NAME - 1);
  }

  Napi::Value GetSignerId(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), op_->signer_id);
  }
  void SetSignerId(const Napi::CallbackInfo& info, const Napi::Value& val) {
    (void)info;
    strncpy(op_->signer_id,
            require_js_string(val, "Operation.signerId", "value").c_str(),
            CRABS_MAX_USER_ID - 1);
  }

  Napi::Value GetNodeId(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), op_->node_id);
  }
  void SetNodeId(const Napi::CallbackInfo& info, const Napi::Value& val) {
    (void)info;
    strncpy(op_->node_id,
            require_js_string(val, "Operation.nodeId", "value").c_str(),
            CRABS_MAX_USER_ID - 1);
  }

  Napi::Value GetPayload(const Napi::CallbackInfo& info) {
    if (op_->payload == NULL || op_->payload_size == 0)
      return info.Env().Undefined();
    return Napi::Buffer<uint8_t>::Copy(info.Env(), op_->payload, op_->payload_size);
  }
  void SetPayload(const Napi::CallbackInfo& info, const Napi::Value& val) {
    if (op_->payload) { free(op_->payload); op_->payload = NULL; op_->payload_size = 0; }
    if (val.IsBuffer()) {
      auto buf = val.As<Napi::Buffer<uint8_t>>();
      // A10-L13: payload_size is u32 — reject an oversize payload rather than
      // silently truncating the recorded length.
      if (buf.Length() > UINT32_MAX)
        throw Napi::RangeError::New(info.Env(),
            "payload: buffer exceeds UINT32_MAX bytes");
      op_->payload = (uint8_t*)malloc(buf.Length());
      memcpy(op_->payload, buf.Data(), buf.Length());
      op_->payload_size = (uint32_t)buf.Length();
    } else if (val.IsString()) {
      std::string s = val.As<Napi::String>().Utf8Value();
      if (s.length() > UINT32_MAX)
        throw Napi::RangeError::New(info.Env(),
            "payload: string exceeds UINT32_MAX bytes");
      op_->payload = (uint8_t*)malloc(s.length());
      memcpy(op_->payload, s.data(), s.length());
      op_->payload_size = (uint32_t)s.length();
    }
  }

  Napi::Value GetLamportTime(const Napi::CallbackInfo& info) {
    return Napi::Number::New(info.Env(), (double)op_->lamport_time);
  }
  // Op format version this op carries. Fresh ops report the build's
  // CRABS_OP_FORMAT_VERSION; deserialized ops report the version declared
  // on the wire. Compare against wireVersions.op to detect skew.
  Napi::Value GetWireVersion(const Napi::CallbackInfo& info) {
    return Napi::Number::New(info.Env(), (double)op_->op_version);
  }
  void SetLamportTime(const Napi::CallbackInfo& info, const Napi::Value& val) {
    op_->lamport_time = require_u64_numeric(val, "lamportTime", "value");
  }

  // Append a resource name to the op — the shared wire-array growth helper
  // (operation_append_resource) documents the per-resource invariants.
  Napi::Value AddResource(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addResource", "name");
    operation_append_resource(op_, name, env, "addResource");
    return info.This();
  }

  // Set the per-slot protocol state one declared slot at a time. The
  // executor's step 4 (state_machine.c _check_transitions) checks
  // item->protocol_state == op->required_state[index] for EVERY named
  // resource before anything moves; operation_append_resource hard-codes
  // fresh slots to PROTOCOL_IDLE. Words: idle/locked/modified/verified/error.
  void SetProtocolState(const Napi::CallbackInfo& info, protocol_state_e* array,
                        const char* ctx) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsString())
      throw Napi::TypeError::New(env,
          std::string("Expected ") + ctx + "(slotIndex, stateWord)");
    double slot_value = info[0].As<Napi::Number>().DoubleValue();
    if (slot_value < 0 || slot_value >= CRABS_MAX_RESOURCES ||
        slot_value != (double)(uint32_t)slot_value)
      throw Napi::RangeError::New(env, std::string(ctx) +
          ": slotIndex must be an integer 0..7");
    uint32_t slot_index = (uint32_t)slot_value;
    if (op_->resource_count == 0 || slot_index >= op_->resource_count)
      throw Napi::RangeError::New(env, std::string(ctx) +
          ": slotIndex is past the op's declared resources");
    protocol_state_e state;
    if (!protocol_state_from_word(
            require_js_string(info[1], ctx, "stateWord"), &state))
      throw Napi::RangeError::New(env, std::string(ctx) +
          ": stateWord must be 'idle' | 'locked' | 'modified' | 'verified' | 'error'");
    array[slot_index] = state;
  }

  Napi::Value SetRequiredState(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    SetProtocolState(info, op_->required_state, "setRequiredState");
    return info.This();
  }

  Napi::Value SetNextState(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    SetProtocolState(info, op_->next_state, "setNextState");
    return info.This();
  }

  // Append one lock claim (resources + 32-byte bearer token, signing format
  // v4 §8 — set BEFORE signing). The executor verifies presented claims
  // against the item's live lock token (state_machine.c step 5); claims are
  // grown one slot at a time like the resource arrays.
  Napi::Value AddLockClaim(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString())
      throw Napi::TypeError::New(env,
          "Expected addLockClaim(resource, tokenHex)");
    std::string resource = require_js_string(info[0], "addLockClaim",
                                             "resource");
    std::string token_hex = require_js_string(info[1], "addLockClaim",
                                              "tokenHex");
    // A resource name at or above CRABS_MAX_USER_ID cannot round-trip the
    // wire format: silently truncating it would sign a claim whose resource
    // differs from the one the caller staged (and step 5 of the executor
    // would then fail the claim against the live lock). Refuse loudly, the
    // same invalid-param stance as the wasm export.
    if (resource.size() >= CRABS_MAX_USER_ID)
      throw Napi::RangeError::New(env,
          "addLockClaim: resource name must be " +
          std::to_string(CRABS_MAX_USER_ID - 1) + " bytes or fewer");
    if (op_->lock_claim_count >= CRABS_MAX_RESOURCES)
      throw Napi::RangeError::New(env, "addLockClaim: claim capacity reached");
    // Lock tokens are bearer credentials — the decoded stack copy is
    // cleansed on the failure throws and after the claim copy (the same
    // discipline SignWithPrivateKey applies to its private-key staging).
    uint8_t token[CRABS_LOCK_TOKEN_SIZE];
    if (!hex_decode(token_hex, token, CRABS_LOCK_TOKEN_SIZE)) {
      OPENSSL_cleanse(token, CRABS_LOCK_TOKEN_SIZE);
      OPENSSL_cleanse(&token_hex[0], token_hex.size());  // Audit M-6: heap copy too
      throw Napi::RangeError::New(env,
          "addLockClaim: tokenHex must be 64 hex chars (32 bytes)");
    }
    lock_claim_t* grown_claims = (lock_claim_t*)realloc(
        op_->lock_claims,
        (op_->lock_claim_count + 1) * sizeof(lock_claim_t));
    if (grown_claims == NULL) {
      OPENSSL_cleanse(token, CRABS_LOCK_TOKEN_SIZE);
      OPENSSL_cleanse(&token_hex[0], token_hex.size());  // Audit M-6: heap copy too
      throw crabs_error(env, CRABS_ERR_OOM, "addLockClaim");
    }
    op_->lock_claims = grown_claims;
    lock_claim_t* claim = &op_->lock_claims[op_->lock_claim_count];
    memset(claim, 0, sizeof(*claim));
    strncpy(claim->resource, resource.c_str(), CRABS_MAX_USER_ID - 1);
    memcpy(claim->lock_token, token, CRABS_LOCK_TOKEN_SIZE);
    OPENSSL_cleanse(&token_hex[0], token_hex.size());  // Audit M-6: heap copy too
    OPENSSL_cleanse(token, CRABS_LOCK_TOKEN_SIZE);
    op_->lock_claim_count++;
    return info.This();
  }

  // Recipe 12 (attestation bridge): attach one parent-signed attestation to
  // the op — the credential an executor `@parent/` endorsement policy
  // resolves against (_verify_parent_endorsements, state_machine.c). The
  // JS side parses the fields out of the parent's attestation wire image
  // (canonical body layout in lineage.c) and hands them over; the executor
  // re-verifies everything (chain TIP, ids, window, coverage) during
  // authorization, so a bad field only ever fails closed. NOT part of the
  // canonical signing form — the parent's own ECDSA covers each body —
  // but attached BEFORE signing like every other staged field.
  //
  // The decoded signature staging buffer is cleansed on the failure throws
  // and after the struct copy (the same discipline AddLockClaim applies to
  // lock tokens — attestations are signatures, not bearer secrets, but the
  // copy hygiene keeps every staging path uniform).
  Napi::Value AddAttestation(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsObject())
      throw Napi::TypeError::New(env,
          "Expected addAttestation({ parentId, childId, userId, attributes, "
          "notBefore?, expiresAt?, parentKeyVersion, signatureHex })");
    Napi::Object fields = info[0].As<Napi::Object>();
    auto require_string_field = [&](const char* name) -> std::string {
      Napi::Value value = fields.Get(name);
      if (!value.IsString())
        throw Napi::TypeError::New(env,
            std::string("addAttestation: ") + name + " must be a string");
      return value.As<Napi::String>().Utf8Value();
    };
    std::string parent_id = require_string_field("parentId");
    std::string child_id = require_string_field("childId");
    std::string user_id = require_string_field("userId");
    std::string attributes = require_string_field("attributes");
    // Capacity-bound ids: a field the canonical body writer cannot
    // null-terminate would verify differently after transport than it was
    // staged here. Refuse loudly, mirroring AddLockClaim's invalid-param
    // stance.
    if (parent_id.size() >= CRABS_MAX_USER_ID ||
        child_id.size() >= CRABS_MAX_USER_ID ||
        user_id.size() >= CRABS_MAX_USER_ID)
      throw Napi::RangeError::New(env,
          "addAttestation: ids must be " +
          std::to_string(CRABS_MAX_USER_ID - 1) + " bytes or fewer");
    if (attributes.size() >= CRABS_MAX_POLICY_EXPR)
      throw Napi::RangeError::New(env,
          "addAttestation: attributes must be " +
          std::to_string(CRABS_MAX_POLICY_EXPR - 1) + " bytes or fewer");

    // Stamps from the attestation body field-wise: notBefore/expiresAt are
    // optional (default 0 — epoch, i.e. no lower fence), parentKeyVersion is
    // REQUIRED (the chain-TIP version the parent stamped; the executor's
    // tip-only gate compares it exactly with the child's chain tip).
    auto stamp_field = [&](const char* name, bool required) -> uint64_t {
      Napi::Value value = fields.Get(name);
      if (value.IsUndefined() || value.IsNull()) {
        if (required)
          throw Napi::TypeError::New(env,
              std::string("addAttestation: ") + name + " is required");
        return 0;
      }
      // Stamps arrive as BigInt (attestationFromWire hands exactly this
      // shape back) or as a legacy Number. A double past 2^53 would truncate
      // silently — Numbers keep the 0..2^53-1 gate; BigInts refuse only a
      // value that does not fit u64.
      if (value.IsBigInt()) {
        bool lossless = false;
        uint64_t stamp = value.As<Napi::BigInt>().Uint64Value(&lossless);
        if (!lossless)
          throw Napi::RangeError::New(env,
              std::string("addAttestation: ") + name +
              " does not fit in uint64");
        return stamp;
      }
      if (!value.IsNumber())
        throw Napi::RangeError::New(env,
            std::string("addAttestation: ") + name +
            " must be a number or BigInt (epoch ms)");
      double stamp = value.As<Napi::Number>().DoubleValue();
      // A non-integer or a value past JS's exact-integer range (2^53) would
      // truncate silently on the double -> uint64 conversion; refuse loudly.
      if (stamp < 0 || stamp >= 9007199254740992.0 ||
          stamp != floor(stamp))
        throw Napi::RangeError::New(env,
            std::string("addAttestation: ") + name +
            " must be an integer 0..2^53-1");
      return (uint64_t)stamp;
    };
    uint64_t not_before = stamp_field("notBefore", false);
    uint64_t expires_at = stamp_field("expiresAt", false);
    uint64_t parent_key_version = stamp_field("parentKeyVersion", true);

    // The carried ECDSA: decoded BEFORE any resize so a failed attach
    // changes NOTHING (the reject-before-mutating contract).
    std::string signature_hex =
        require_string_field("signatureHex");
    uint8_t signature[CRABS_SIG_SIZE];
    if (signature_hex.length() != CRABS_SIG_SIZE * 2 ||
        !hex_decode(signature_hex, signature, CRABS_SIG_SIZE)) {
      OPENSSL_cleanse(signature, CRABS_SIG_SIZE);
      throw Napi::RangeError::New(env,
          "addAttestation: signatureHex must be 128 hex chars (64 bytes)");
    }

    if (op_->attestation_count >= CRABS_MAX_OP_ATTESTATIONS)
      throw Napi::RangeError::New(env,
          "addAttestation: attestation capacity reached (" +
          std::to_string(CRABS_MAX_OP_ATTESTATIONS) + ")");
    attestation_t* grown_attestations = (attestation_t*)realloc(
        op_->attestations,
        (op_->attestation_count + 1) * sizeof(attestation_t));
    if (grown_attestations == NULL) {
      OPENSSL_cleanse(signature, CRABS_SIG_SIZE);
      throw crabs_error(env, CRABS_ERR_OOM, "addAttestation");
    }
    op_->attestations = grown_attestations;
    attestation_t* attestation =
        &op_->attestations[op_->attestation_count];
    memset(attestation, 0, sizeof(*attestation));
    attestation->format_version = CRABS_ATTESTATION_FORMAT_VERSION;
    strncpy(attestation->parent_id, parent_id.c_str(), CRABS_MAX_USER_ID - 1);
    strncpy(attestation->child_id, child_id.c_str(), CRABS_MAX_USER_ID - 1);
    strncpy(attestation->user_id, user_id.c_str(), CRABS_MAX_USER_ID - 1);
    strncpy(attestation->attributes, attributes.c_str(),
            sizeof(attestation->attributes) - 1);
    attestation->not_before = not_before;
    attestation->expires_at = expires_at;
    attestation->parent_key_version = parent_key_version;
    memcpy(attestation->signature, signature, CRABS_SIG_SIZE);
    OPENSSL_cleanse(signature, CRABS_SIG_SIZE);
    op_->attestation_count++;
    return info.This();
  }

  // Write-domains v1 (op format v6, signing format v4): set the sovereign
  // chain prefix at `prefixIndex` — the item_seq the writer believes is
  // current and the digest of the item at that sequence (64 hex chars).
  // The prefix array is parallel to the op's sovereign resources in
  // declaration order; setting index i grows the count to i + 1.
  Napi::Value SetSovereignPrefix(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3 || !info[0].IsNumber() || !info[1].IsNumber() ||
        !info[2].IsString())
      throw Napi::TypeError::New(env,
          "Expected setSovereignPrefix(prefixIndex, seq, digestHex)");
    double index_value = info[0].As<Napi::Number>().DoubleValue();
    if (index_value < 0 || index_value >= CRABS_MAX_RESOURCES ||
        index_value != (double)(uint32_t)index_value)
      throw Napi::RangeError::New(env,
          "setSovereignPrefix: prefixIndex must be 0..7");
    uint32_t prefix_index = (uint32_t)index_value;
    double seq_value = info[1].As<Napi::Number>().DoubleValue();
    // A non-integer or a value past JS's exact-integer range (2^53) would
    // truncate silently on the double → uint64 conversion; refuse loudly.
    if (seq_value < 0 || seq_value >= 9007199254740992.0 ||
        seq_value != floor(seq_value))
      throw Napi::RangeError::New(env,
          "setSovereignPrefix: seq must be an integer 0..2^53-1");
    std::string digest_hex = info[2].As<Napi::String>().Utf8Value();
    if (digest_hex.length() != CRABS_HASH_SIZE * 2)
      throw Napi::RangeError::New(env,
          "setSovereignPrefix: digestHex must be 64 hex chars");
    if (!hex_decode(digest_hex,
                    op_->sovereign_prefixes[prefix_index].prev_item_digest,
                    CRABS_HASH_SIZE))
      throw Napi::TypeError::New(env,
          "setSovereignPrefix: digestHex is not valid hex");
    op_->sovereign_prefixes[prefix_index].item_seq = (uint64_t)seq_value;
    if (op_->sovereign_prefix_count < prefix_index + 1)
      op_->sovereign_prefix_count = prefix_index + 1;
    return info.This();
  }

  // Wire bytes of the op as currently staged — equivocation evidence and
  // cross-process relays ship this form.
  Napi::Value SerializeOp(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    serialized_buffer_t* ser = crabs_serialize_operation(op_);
    if (!ser)
      throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR,
                        "Operation.serialize");
    Napi::Buffer<uint8_t> out =
        Napi::Buffer<uint8_t>::Copy(env, ser->data, ser->len);
    serialized_buffer_destroy(ser);
    return out;
  }

  Napi::Value Sign(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsObject())
      throw Napi::TypeError::New(env, "Expected KeyPair");
    KeyPair* kp = KeyPair::Unwrap(info[0].As<Napi::Object>());
    serialized_buffer_t* ser = crabs_serialize_for_signing(op_);
    if (!ser) throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "sign");
    crabs_error_e rc = crypto_ecdsa_sign(kp->raw()->private_key,
                                          ser->data, ser->len, op_->signature);
    serialized_buffer_destroy(ser);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "sign");
    return info.This();
  }

  Napi::Value SignWithPrivateKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString())
      throw Napi::TypeError::New(env, "Expected private key hex string");
    uint8_t priv[32];
    std::string hex = info[0].As<Napi::String>().Utf8Value();
    // A11-L7: cleanse even on the decode-failure throw — a partial decode
    // leaves a prefix of the caller's key bytes on the stack, and every other
    // exit from this buffer is scrubbed. Audit M-6: the std::string is a
    // SECOND heap copy of the same secret — cleanse it on every path too
    // (the DecryptKeyEnvelope pattern), since GC-visible std::string bytes
    // cannot be zeroized by JS.
    if (!hex_decode(hex, priv, 32)) {
      OPENSSL_cleanse(priv, 32);
      OPENSSL_cleanse(&hex[0], hex.size());
      throw Napi::Error::New(env, "Invalid private key hex");
    }
    serialized_buffer_t* ser = crabs_serialize_for_signing(op_);
    if (!ser) {
      OPENSSL_cleanse(priv, 32);
      OPENSSL_cleanse(&hex[0], hex.size());
      throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "sign");
    }
    crabs_error_e rc = crypto_ecdsa_sign(priv, ser->data, ser->len, op_->signature);
    serialized_buffer_destroy(ser);
    OPENSSL_cleanse(priv, 32);
    OPENSSL_cleanse(&hex[0], hex.size());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "sign");
    return info.This();
  }
};

// ============================================================
// Node — wraps attribute_machine_t + state_t + abe_master_key_t + node_key
// ============================================================

// Map a crabs_change_kind_e to the event name surfaced to JS listeners.
static const char* _change_kind_name_napi(crabs_change_kind_e kind) {
  switch (kind) {
    case CRABS_CHANGE_OP:        return "op";
    case CRABS_CHANGE_SCHEDULE:  return "schedule";
    case CRABS_CHANGE_TRIGGER:   return "trigger";
    case CRABS_CHANGE_ATTRIBUTE: return "attribute";
    case CRABS_CHANGE_SPAWN:     return "spawn";
    case CRABS_CHANGE_LINEAGE:   return "lineage";
    case CRABS_CHANGE_MERGE:     return "merge";  // write-domains v1 divergence
    default:                     return "op";
  }
}

// Forward declaration: the body is defined after the Node class so it can
// call Node::EmitChange (the hook fires inside execute()/registerUser(), which
// are always invoked from JS, so calling back into the same thread is safe).
static void _node_change_hook_thunk(state_t* state,
                                    const crabs_change_event_t* event,
                                    void* user_data);

class Node : public Napi::ObjectWrap<Node> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "Node", {
      InstanceMethod("registerUser", &Node::RegisterUser),
      InstanceMethod("grantRole", &Node::GrantRole),
      InstanceMethod("selfAssert", &Node::SelfAssert),
      InstanceMethod("verifyIdentity", &Node::VerifyIdentity),
      InstanceMethod("revokeUser", &Node::RevokeUser),
      // Keyring lifecycle (parity-fill P2, v1.3 §9)
      InstanceMethod("suspendKey", &Node::SuspendKey),
      InstanceMethod("activateKey", &Node::ActivateKey),
      InstanceMethod("rotateKey", &Node::RotateKey),
      InstanceMethod("listKeys", &Node::ListKeys),
      InstanceMethod("getDefaultKey", &Node::GetDefaultKey),
      // Admin demotion + user suspension (parity-fill P3, admin-gated)
      InstanceMethod("revokeRole", &Node::RevokeRole),
      InstanceMethod("suspendUser", &Node::SuspendUser),
      InstanceMethod("activateUser", &Node::ActivateUser),
      InstanceMethod("getUser", &Node::GetUser),
      InstanceMethod("getNodeKey", &Node::GetNodeKey),
      InstanceMethod("addCounter", &Node::AddCounter),
      InstanceMethod("defineItem", &Node::DefineItem),
      InstanceMethod("itemChainHead", &Node::ItemChainHead),
      InstanceMethod("reportEquivocation", &Node::ReportEquivocation),
      InstanceMethod("addPNCounter", &Node::AddPNCounter),
      InstanceMethod("addORSet", &Node::AddORSet),
      InstanceMethod("addOneShotSet", &Node::AddOneShotSet),
      InstanceMethod("addOneShotFlag", &Node::AddOneShotFlag),
      InstanceMethod("addRegister", &Node::AddRegister),
      InstanceMethod("addResource", &Node::AddResource),
      InstanceMethod("getCounter", &Node::GetCounter),
      InstanceMethod("incrementCounter", &Node::IncrementCounter),
      InstanceMethod("incrementPNCounter", &Node::IncrementPNCounter),
      InstanceMethod("decrementPNCounter", &Node::DecrementPNCounter),
      InstanceMethod("getPNCounter", &Node::GetPNCounter),
      InstanceMethod("getRegister", &Node::GetRegister),
      InstanceMethod("setRegister", &Node::SetRegister),
      InstanceMethod("setContains", &Node::SetContains),
      // Parity-fill P10 (binding alignment): the wasm read surface mirrored.
      InstanceMethod("getSetSize", &Node::GetSetSize),
      InstanceMethod("getSetElements", &Node::GetSetElements),
      InstanceMethod("getSetTags", &Node::GetSetTags),
      InstanceMethod("setRegisterBytes", &Node::SetRegisterBytes),
      InstanceMethod("getRegisterBytes", &Node::GetRegisterBytes),
      // Parity-fill P10: the explicit trigger tick (trigger_process_all).
      InstanceMethod("evaluateTriggers", &Node::EvaluateTriggers),
      InstanceMethod("setAdd", &Node::SetAdd),
      InstanceMethod("setRemove", &Node::SetRemove),
      InstanceMethod("flagSet", &Node::FlagSet),
      InstanceMethod("flagValue", &Node::FlagValue),
      // Ordered set (OT_ORDERED_SET, v1.5 §5 — recipe 8)
      InstanceMethod("addOrderedSet", &Node::AddOrderedSet),
      InstanceMethod("getOrderedSet", &Node::GetOrderedSet),
      InstanceMethod("orderedInsert", &Node::OrderedInsert),
      InstanceMethod("orderedDelete", &Node::OrderedDelete),
      InstanceMethod("orderedMove", &Node::OrderedMove),
      InstanceMethod("orderedSwap", &Node::OrderedSwap),
      InstanceMethod("addOTDocument", &Node::AddOTDocument),
      InstanceMethod("getOTDocument", &Node::GetOTDocument),
      InstanceMethod("otInsertText", &Node::OtInsertText),
      InstanceMethod("otDeleteRange", &Node::OtDeleteRange),
      InstanceMethod("otApplyStyle", &Node::OtApplyStyle),
      InstanceMethod("otMergeSpans", &Node::OtMergeSpans),
      InstanceMethod("otSplitSpan", &Node::OtSplitSpan),
      InstanceMethod("otDocumentApply", &Node::OtDocumentApply),
      InstanceMethod("addOTTree", &Node::AddOTTree),
      InstanceMethod("getOTTree", &Node::GetOTTree),
      InstanceMethod("otInsertNode", &Node::OtInsertNode),
      InstanceMethod("otDeleteNode", &Node::OtDeleteNode),
      InstanceMethod("otReparent", &Node::OtReparent),
      InstanceMethod("otReorder", &Node::OtReorder),
      InstanceMethod("otTreeApply", &Node::OtTreeApply),
      InstanceMethod("setPolicy", &Node::SetPolicy),
      InstanceMethod("defineOperationType", &Node::DefineOperationType),
      InstanceMethod("execute", &Node::Execute),
      // Replay ingest (bounded-skew replay fix) — wasm parity
      InstanceMethod("replayOp", &Node::ExecuteReplay),
      // Timed transactions (v1) — mirror of the wasm surface
      // (bindings/wasm/index.d.ts:501-511)
      InstanceMethod("schedule", &Node::Schedule),
      InstanceMethod("scheduleRecurring", &Node::ScheduleRecurring),
      InstanceMethod("cancelSchedule", &Node::CancelSchedule),
      InstanceMethod("processSchedules", &Node::ProcessSchedules),
      InstanceMethod("setScheduleOccurrenceBudget",
                     &Node::SetScheduleOccurrenceBudget),
      InstanceMethod("scheduleOccurrenceBudget", &Node::ScheduleOccurrenceBudget),
      InstanceMethod("pendingSchedules", &Node::PendingSchedules),
      InstanceMethod("on", &Node::On),
      InstanceMethod("sign", &Node::SignOp),
      InstanceMethod("createTrigger", &Node::CreateTrigger),
      InstanceMethod("encrypt", &Node::Encrypt),
      InstanceMethod("abeKeygen", &Node::AbeKeygen),
      InstanceMethod("abeDecrypt", &Node::AbeDecrypt),
      // ABE key transport (parity-fill P4: reader-key wire + key envelopes
      // + master-key durability)
      InstanceMethod("abeKeyFromWire", &Node::AbeKeyFromWire),
      InstanceMethod("mintKeyEnvelope", &Node::MintKeyEnvelope),
      InstanceMethod("decryptKeyEnvelope", &Node::DecryptKeyEnvelope),
      InstanceMethod("serializeMasterKey", &Node::SerializeMasterKey),
      InstanceMethod("masterKeyFromWire", &Node::MasterKeyFromWire),
      InstanceMethod("serialize", &Node::Serialize),
      InstanceMethod("deserialize", &Node::Deserialize),
      InstanceMethod("mergeState", &Node::MergeState),
      InstanceMethod("getHLC", &Node::GetHLC),
      InstanceMethod("setTime", &Node::SetTime),
      InstanceMethod("pruneExpiredTempAttrs", &Node::PruneExpiredTempAttrs),
      InstanceMethod("issueTemporary", &Node::IssueTemporary),
      // Lineage (v1.7: machines mint machines)
      InstanceMethod("lineageInstall", &Node::LineageInstall),
      InstanceMethod("lineageSpawn", &Node::LineageSpawn),
      InstanceMethod("lineageChildren", &Node::LineageChildren),
      InstanceMethod("lineageResidentChild", &Node::LineageResidentChild),
      InstanceMethod("lineageAttest", &Node::LineageAttest),
      InstanceMethod("lineageTombstone", &Node::LineageTombstone),
      InstanceMethod("lineageRotateKey", &Node::LineageRotateKey),
      InstanceMethod("lineageAcceptKeyTransition",
                     &Node::LineageAcceptKeyTransition),
      InstanceMethod("attestationFromWire", &Node::AttestationFromWire),
      // Authenticated time source (A10-L9 wiring)
      InstanceMethod("setTimeSource", &Node::SetTimeSource),
      InstanceMethod("getTimeSource", &Node::GetTimeSource),
      // Raft ordering module (reference host surfaces live in index.js)
      InstanceMethod("attachRaft", &Node::AttachRaft),
      // Lock protocol + tx manager (recipe 9 — locks / replay protection)
      InstanceMethod("attachTxManager", &Node::AttachTxManager),
      InstanceMethod("getLockState", &Node::GetLockState),
      InstanceMethod("getResource", &Node::GetResource),
      InstanceMethod("raftTick", &Node::RaftTick),
      InstanceMethod("raftDeliver", &Node::RaftDeliver),
      InstanceMethod("raftPersistComplete", &Node::RaftPersistComplete),
      InstanceMethod("raftRecoverFromPersist", &Node::RaftRecoverFromPersist),
      InstanceMethod("raftPump", &Node::RaftPump),
      InstanceMethod("raftPollOutbound", &Node::RaftPollOutbound),
      InstanceMethod("raftPollPersistRequest", &Node::RaftPollPersistRequest),
      InstanceMethod("raftPollNotifications", &Node::RaftPollNotifications),
      InstanceMethod("raftStatus", &Node::RaftStatus),
      InstanceMethod("raftChangeMembership", &Node::RaftChangeMembership),
      InstanceMethod("raftJointMembers", &Node::RaftJointMembers),
      InstanceMethod("raftCommittedMembers", &Node::RaftCommittedMembers),
      InstanceMethod("raftDetach", &Node::RaftDetach),
      // The bootstrap admin id — the node's HLC identity and default raft
      // node id (property for parity with the wasm wrapper's readonly
      // adminId).
      InstanceAccessor("adminId", &Node::GetAdminId, nullptr),
    });
    auto* inst = env.GetInstanceData<NodeAddonInstanceData>();
    inst->node_ctor = Napi::Persistent(func);
    exports.Set("Node", func);
    return exports;
  }

  Node(const Napi::CallbackInfo& info) : Napi::ObjectWrap<Node>(info) {
    Napi::Env env = info.Env();

    // Borrowed-child construction (internal only): a Napi::External adoption
    // packet wraps a machine this wrapper did NOT create — see WrapMachine
    // for the ownership statement.
    if (info.Length() >= 1 && info[0].IsExternal()) {
      auto adoption_packet = info[0].As<Napi::External<NodeAdoption>>();
      am_ = adoption_packet.Data()->am;
      adopted_ = true;
      node_key_ = nullptr;  // the child carries no own node key yet
      admin_id_ = am_->base_state.config.bootstrap_admin;
      // No HLC init, and no change-hook registration: this wrapper did not
      // create the machine, and its lifetime is not tied to the machine's —
      // a hook user_data pointing back at this wrapper could dangle.
      return;
    }

    if (info.Length() < 1 || !info[0].IsString())
      throw Napi::TypeError::New(env, "Expected admin user ID string");

    std::string admin_id = info[0].As<Napi::String>().Utf8Value();

    // Parse options: { ordering: 'hlc' | 'lamport',
    //                   skew: { maxSkewMs, replayPolicy } }
    bool use_hlc = true;  // Default to HLC (user requested hybrid time)
    // Skew configuration (bounded-skew replay fix, wasm-parity): the C seam
    // takes raw enum/uint values with no validation — THIS whitelist is the
    // enforcement point (mirror of the wasm binding's parseSkewOptions).
    uint64_t max_skew_ms = 0;  // 0 = keep the C-side default (5000); NOT "unbounded"
    crabs_hlc_replay_policy_e replay_policy = CRABS_HLC_REPLAY_REJECT;
    if (info.Length() > 1 && info[1].IsObject()) {
      Napi::Object opts = info[1].As<Napi::Object>();
      if (opts.Has("ordering")) {
        std::string ord = require_js_string(opts.Get("ordering"),
                                            "Node", "ordering");
        use_hlc = (ord == "hlc");
      }
      if (opts.Has("skew")) {
        // Parity with the wasm wrapper (parseSkewOptions's `!options.skew`
        // early return): a FALSY skew value (null, undefined, 0, '', false)
        // is "no skew options"; only a truthy non-object value throws.
        Napi::Value skew_option = opts.Get("skew");
        if (!skew_option.ToBoolean().Value()) {
          // Fall through to the C-side defaults (5s window, reject policy).
        } else if (!skew_option.IsObject()) {
          // The wasm binding refuses a non-object skew ('skew must be an
          // options object') — a silently-ignored string would arm nothing
          // while the caller believes a window/policy is in force.
          throw Napi::TypeError::New(env, "Node: skew must be an options object");
        } else {
          Napi::Object skew = skew_option.As<Napi::Object>();
          if (skew.Has("maxSkewMs")) {
            Napi::Value skew_window = skew.Get("maxSkewMs");
            // Safe non-negative integer (the wasm parseSkewOptions rule):
            // fractional or above-MAX_SAFE_INTEGER doubles would truncate or
            // have already collapsed in the double space (e.g. 2**53 + 1 IS
            // 2**53), so the window must be exact before the uint64 cast.
            if (!skew_window.IsNumber()) {
              throw Napi::TypeError::New(
                  env, "Node: skew.maxSkewMs must be a non-negative safe integer");
            }
            double window_value = skew_window.As<Napi::Number>().DoubleValue();
            if (!(window_value >= 0) || window_value > 9007199254740991.0 ||
                window_value != std::floor(window_value)) {
              throw Napi::TypeError::New(
                  env, "Node: skew.maxSkewMs must be a non-negative safe integer");
            }
            max_skew_ms = (uint64_t)window_value;
          }
          if (skew.Has("replayPolicy")) {
            std::string policy = require_js_string(skew.Get("replayPolicy"),
                                                   "Node", "skew.replayPolicy");
            if (policy != "clamp" && policy != "reject") {
              throw Napi::TypeError::New(
                  env, "Node: skew.replayPolicy must be 'clamp' or 'reject'");
            }
            replay_policy = (policy == "clamp")
                                ? CRABS_HLC_REPLAY_CLAMP : CRABS_HLC_REPLAY_REJECT;
          }
        }
      }
    }

    // Generate node keypair
    node_key_ = crypto_ecdsa_generate();
    if (!node_key_) throw Napi::Error::New(env, "Failed to generate node key");

    // Create attribute machine with admin
    admin_id_ = admin_id;
    am_ = attribute_machine_create(admin_id.c_str(), node_key_->public_key);
    if (!am_) throw Napi::Error::New(env, "Failed to create attribute machine");

    // Wire back-pointer
    am_->base_state.attr_machine = am_;

    // Set node key on state
    state_set_node_key(&am_->base_state, node_key_->private_key, node_key_->public_key);

    // Configure ordering
    if (use_hlc) {
      crabs_ordering_config_init_hlc(&ordering_config_, HLC_STRATEGY_BOUNDED);
      if (max_skew_ms != 0) ordering_config_.hlc.max_skew_ms = max_skew_ms;
      ordering_config_.hlc.replay_policy = replay_policy;
      state_set_ordering_config(&am_->base_state, &ordering_config_);
      // Initialize HLC state with admin_id as node_id
      crabs_hlc_state_init(&am_->base_state.hlc_state, admin_id.c_str());
      am_->base_state.hlc_state_initialized = true;
    }

    // Init sig scheme registry
    crypto_sig_scheme_init();

    // Route state-machine change events to JS listeners registered via on().
    state_set_change_hook(&am_->base_state, _node_change_hook_thunk, this);
  }

  ~Node() {
    for (auto& listener : change_listeners_) listener.Reset();
    // Raft module cleanup FIRST: the module outlived through raw pointers
    // into the machine's state — detach before the state dies. The state
    // never owns the module object (see state_attach_raft_module).
    if (raft_module_ != nullptr) {
      state_attach_raft_module(&am_->base_state, NULL);
      crabs_raft_module_destroy(raft_module_);
      raft_module_ = nullptr;
    }
    // Time-source cleanup FIRST: the machine's state_t references the ops
    // object through a raw, non-owning pointer (state_set_time_source), so
    // the ops must outlive neither the state nor the pointer stored in it.
    // Detach from the state, then destroy the ops, before the machine is
    // destroyed below. For an adopted wrapper the machine outlives the
    // wrapper (parent keepalive): detaching leaves that machine WITHOUT an
    // authenticated clock, which thereafter fails closed per R7-02 — an
    // accepted, documented consequence of the wrapper dying.
    if (time_source_owned_ && time_source_ops_ != nullptr) {
      state_set_time_source(&am_->base_state, NULL);
      crabs_time_source_destroy(time_source_ops_);
      time_source_ops_ = nullptr;
      time_source_owned_ = false;
    }
    if (node_key_) crypto_ecdsa_keypair_destroy(node_key_);
    // No explicit tx-manager cleanup here: state->tx_manager is host-owned
    // (data_model.h) but the machine's teardown DESTROYS it
    // (attribute_machine_destroy — attribute_machine.c:434-438, mirroring
    // state_destroy:data_model.c:400-404), which covers both owned and
    // adopted (parent-destroyed) machines. The wrapper does need the
    // destroy-on-replace path below (nothing else frees a replaced
    // manager), and the wasm binding destroys explicitly because its
    // machine teardown is intentionally skipped (wasm_helpers.c
    // crabs_wasm_node_destroy).
    // Ownership statement (mirrors the wasm binding's resident-registry one):
    // a wrapper around a machine it did not create NEVER destroys the machine.
    // The parent owns every machine it spawned directly (spawned_machines_,
    // destroyed here); machines spawned through the ops pipeline are owned by
    // C's resident-children registry for the life of the parent machine.
    if (am_ && !adopted_) attribute_machine_destroy(am_);
    for (attribute_machine_t* spawned_machine : spawned_machines_)
      attribute_machine_destroy(spawned_machine);
  }

  // --- Change events (public: _node_change_hook_thunk calls into this) ---

  // Deliver one C change event to every live 'change' listener. A throwing
  // listener must never break the state machine, so exceptions are swallowed.
  void EmitChange(const crabs_change_event_t* event) {
    if (event == NULL) return;
    Napi::Env env = Env();
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("kind", Napi::String::New(env, _change_kind_name_napi(event->kind)));
    obj.Set("type", Napi::String::New(env, event->type ? event->type : ""));
    obj.Set("signer", event->signer_id ? Napi::String::New(env, event->signer_id)
                                        : env.Null());
    obj.Set("node", event->node_id ? Napi::String::New(env, event->node_id)
                                    : env.Null());
    obj.Set("target", event->target ? Napi::String::New(env, event->target)
                                     : env.Null());
    obj.Set("preview", Napi::String::New(env,
                                          event->preview ? event->preview : ""));
    obj.Set("result", Napi::Number::New(env, (double)event->result));
    // A10-M4: a synchronous listener may register or unregister listeners on
    // this Node (push_back reallocates change_listeners_). Iterate a snapshot
    // of live Napi::Function handles instead of the vector itself; each copied
    // handle is scope-owned, so a function stays callable for this dispatch
    // even if its FunctionReference slot is Reset mid-emit (self-unregister).
    std::vector<Napi::Function> listener_snapshot;
    listener_snapshot.reserve(change_listeners_.size());
    for (auto& listener_reference : change_listeners_) {
      if (!listener_reference.IsEmpty()) {
        listener_snapshot.push_back(listener_reference.Value());
      }
    }
    Napi::Value undefined_value = env.Undefined();
    for (auto& live_listener : listener_snapshot) {
      try {
        live_listener.Call(undefined_value, {obj});
      } catch (...) {
        // A throwing listener must never break the state machine.
      }
    }
  }

private:
  ecdsa_keypair_t* node_key_;
  attribute_machine_t* am_;
  std::string admin_id_;
  crabs_ordering_config_t ordering_config_;
  std::vector<Napi::FunctionReference> change_listeners_;
  // Machines this wrapper spawned directly — created via
  // attribute-registry ownership, destroyed in the destructor. Borrowed
  // wrappers (adopted_) are absent from and independent of this list.
  std::vector<attribute_machine_t*> spawned_machines_;
  // True when this wrapper wraps a machine it did NOT create (a spawned
  // resident child); the destructor then leaves the machine's lifetime to
  // its owner.
  bool adopted_ = false;
  // A borrowed child wrapper keeps a reference to its parent object so the
  // parent (and with it the borrowed machine pointer) stays alive.
  Napi::ObjectReference parent_keepalive_;

  // Authenticated time source (A10-L9 wiring, R7-01). The wrapper OWNS the
  // ops object it created in setTimeSource({mode:'https'}); the machine's
  // state_t references it through a raw, non-owning pointer.
  // time_source_owned_ is set only when THIS wrapper created the ops — a
  // wrapper (adopted or not) that never called setTimeSource must not
  // destroy ops belonging to anyone else, so the destructor keys off the
  // pair (owned_, ops != nullptr), not just the pointer.
  crabs_time_source_ops_t* time_source_ops_ = nullptr;
  bool time_source_owned_ = false;
  // The stored selection; getTimeSource reports from this record (the
  // configuration is machine-local and never serialized, so the wrapper's
  // own record is the coherent source of truth). https=false / empty url /
  // default numbers describe the system-clock state.
  bool time_source_https_ = false;
  std::string time_source_url_;  // "" = default endpoint (reported as null)
  uint64_t time_source_resync_ms_ = CRABS_TIME_SOURCE_DEFAULT_RESYNC_MS;
  uint64_t time_source_timeout_ms_ = CRABS_TIME_SOURCE_DEFAULT_TIMEOUT_MS;
  uint64_t time_source_max_skew_ms_ = CRABS_TIME_SOURCE_DEFAULT_MAX_SKEW_MS;

  // Raft ordering module (GROUP_ORDERED writes). The wrapper owns the
  // module object (crabs_raft_module_create); the machine's state only
  // references it non-owning through state_attach_raft_module. nullptr =
  // detached (group writes fail closed at the pipeline gate).
  crabs_raft_module_t* raft_module_ = nullptr;

  // Throws for surfaces that need an attached module.
  void ensure_raft_attached(Napi::Env env, const char* method) {
    if (raft_module_ == nullptr) {
      throw Napi::Error::New(env, std::string(method) +
          ": no raft module attached (call attachRaft first)");
    }
  }

  // Shared construction path for wrapping a borrowed child machine. The
  // adoption packet is freed by the External's finalizer (GC time), so the
  // constructor must not free it.
  static Napi::Object WrapMachine(Napi::Env env, attribute_machine_t* machine,
                                  Napi::Object parent_obj) {
    auto* inst = env.GetInstanceData<NodeAddonInstanceData>();
    NodeAdoption* packet = new NodeAdoption{machine};
    Napi::Object child_obj = inst->node_ctor.New(
        {Napi::External<NodeAdoption>::New(
            env, packet, [](Napi::Env env, NodeAdoption* adoption_packet) {
              delete adoption_packet;
            })});
    Node* child_wrapper = Node::Unwrap(child_obj);
    // Keepalive: the parent cannot be collected while any child wrapper
    // referencing it is alive, which is what keeps `machine` valid here.
    child_wrapper->parent_keepalive_ = Napi::Persistent(parent_obj);
    return child_obj;
  }

  // node.on('change', cb) returns an off() function that unregisters cb.
  Napi::Value On(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsFunction())
      throw Napi::TypeError::New(env, "Expected (eventName, listener)");
    if (info[0].As<Napi::String>().Utf8Value() != "change")
      return env.Undefined();
    change_listeners_.push_back(
        Napi::Persistent(info[1].As<Napi::Function>()));
    size_t slot = change_listeners_.size() - 1;
    auto* node_self = this;
    return Napi::Function::New(env,
        [node_self, slot](const Napi::CallbackInfo& off_info) {
      (void)off_info;
      if (slot < node_self->change_listeners_.size()) {
        node_self->change_listeners_[slot].Reset();
      }
    });
  }

  // --- User management ---

  Napi::Value RegisterUser(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2)
      throw Napi::TypeError::New(env, "Expected (userId, publicKeyHex[, initialAttrs])");
    std::string user_id = require_js_string(info[0], "registerUser", "userId");
    std::string pk_hex = require_js_string(info[1], "registerUser", "publicKeyHex");
    uint8_t pk[33];
    if (!hex_decode(pk_hex, pk, 33))
      throw Napi::Error::New(env, "Invalid public key hex (expected 66 chars)");
    const char* attrs = NULL;
    std::string attrs_str;
    if (info.Length() > 2 && info[2].IsString()) {
      attrs_str = info[2].As<Napi::String>().Utf8Value();
      attrs = attrs_str.c_str();
    }
    crabs_error_e rc = attribute_machine_register_user(am_, user_id.c_str(), pk, attrs);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "registerUser");
    return env.Undefined();
  }

  Napi::Value GrantRole(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 4)
      throw Napi::TypeError::New(env, "Expected (targetUser, role, value, signerId)");
    std::string target = require_js_string(info[0], "grantRole", "targetUser");
    std::string role = require_js_string(info[1], "grantRole", "role");
    std::string value = require_js_string(info[2], "grantRole", "value");
    std::string signer = require_js_string(info[3], "grantRole", "signerId");
    crabs_error_e rc = attribute_machine_grant_role(am_, target.c_str(),
                                                      role.c_str(), value.c_str(),
                                                      signer.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "grantRole");
    return env.Undefined();
  }

  Napi::Value SelfAssert(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3)
      throw Napi::TypeError::New(env, "Expected (attribute, value, signerId)");
    std::string attr = require_js_string(info[0], "selfAssert", "attribute");
    std::string value = require_js_string(info[1], "selfAssert", "value");
    std::string signer = require_js_string(info[2], "selfAssert", "signerId");
    crabs_error_e rc = attribute_machine_self_assert(am_, attr.c_str(),
                                                       value.c_str(), signer.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "selfAssert");
    return env.Undefined();
  }

  Napi::Value VerifyIdentity(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 4)
      throw Napi::TypeError::New(env, "Expected (targetUser, attribute, value, signerId)");
    std::string target = require_js_string(info[0], "verifyIdentity", "targetUser");
    std::string attr = require_js_string(info[1], "verifyIdentity", "attribute");
    std::string value = require_js_string(info[2], "verifyIdentity", "value");
    std::string signer = require_js_string(info[3], "verifyIdentity", "signerId");
    crabs_error_e rc = attribute_machine_verify_identity(am_, target.c_str(),
                                                          attr.c_str(), value.c_str(),
                                                          signer.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "verifyIdentity");
    return env.Undefined();
  }

  Napi::Value RevokeUser(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string user_id = require_js_string(info[0], "revokeUser", "userId");
    // Admin-gated in C (audit follow-up); the signer defaults to the node
    // admin when the caller omits it.
    std::string signer_id = info.Length() > 1 && !info[1].IsUndefined()
        ? require_js_string(info[1], "revokeUser", "signerId") : admin_id_;
    crabs_error_e rc = attribute_machine_revoke_user(am_, user_id.c_str(),
                                                     signer_id.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "revokeUser");
    return env.Undefined();
  }

  // --- Keyring lifecycle (parity-fill P2, v1.3 §9) ---
  //
  // The C keyring primitives are user_t-SCOPED (user_key_suspend /
  // user_key_activate / user_key_rotate — attribute_machine.h:219-221) and
  // intentionally carry no signer/policy gate: the gate story lives on the
  // wire ops (__register_key__ / __suspend_key__ / __activate_key__ /
  // __rotate_key__, state_machine.c). These methods resolve the user id with
  // attribute_machine_find_user (the same pattern getUser rides) and refuse
  // with the typed user_not_found, then drive the primitive directly.
  user_t* RequireUser(Napi::Env env, const char* ctx,
                      const std::string& user_id) {
    user_t* user = attribute_machine_find_user(am_, user_id.c_str());
    if (!user) throw crabs_error(env, CRABS_ERR_USER_NOT_FOUND, ctx);
    return user;
  }

  Napi::Value SuspendKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2)
      throw Napi::TypeError::New(env, "Expected (userId, keyId)");
    std::string user_id = require_js_string(info[0], "suspendKey", "userId");
    std::string key_id = require_js_string(info[1], "suspendKey", "keyId");
    user_t* user = RequireUser(env, "suspendKey", user_id);
    crabs_error_e rc = user_key_suspend(user, key_id.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "suspendKey");
    return env.Undefined();
  }

  Napi::Value ActivateKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2)
      throw Napi::TypeError::New(env, "Expected (userId, keyId)");
    std::string user_id = require_js_string(info[0], "activateKey", "userId");
    std::string key_id = require_js_string(info[1], "activateKey", "keyId");
    user_t* user = RequireUser(env, "activateKey", user_id);
    crabs_error_e rc = user_key_activate(user, key_id.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "activateKey");
    return env.Undefined();
  }

  // Shape follows the C rotate signature exactly (attribute_machine.h:221):
  // (old, new, scheme, pk bytes, label) — nothing is auto-generated; the
  // caller's opts object carries the same fields as explicit values.
  Napi::Value RotateKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 4 || !info[3].IsObject())
      throw Napi::TypeError::New(env,
          "Expected (userId, oldKeyId, newKeyId, { publicKeyHex, scheme?, label? })");
    std::string user_id = require_js_string(info[0], "rotateKey", "userId");
    std::string old_key_id = require_js_string(info[1], "rotateKey", "oldKeyId");
    std::string new_key_id = require_js_string(info[2], "rotateKey", "newKeyId");
    Napi::Object opts = info[3].As<Napi::Object>();

    if (!opts.Has("publicKeyHex") || !opts.Get("publicKeyHex").IsString() ||
        opts.Get("publicKeyHex").As<Napi::String>().Utf8Value().empty()) {
      throw Napi::TypeError::New(env,
          "rotateKey: opts.publicKeyHex is required (the C rotate signs no auto-generated material)");
    }
    std::string pk_hex = opts.Get("publicKeyHex").As<Napi::String>().Utf8Value();
    // The C field is the signature_scheme_e number; unknown words refuse
    // here so nothing truncates through the int32 wire cast. Defaults to
    // ECDSA_SECP256K1 (the registry's secp256k1 entry) like the wire op does.
    uint32_t scheme_number = ECDSA_SECP256K1;
    if (opts.Has("scheme")) {
      Napi::Value scheme_value = opts.Get("scheme");
      if (scheme_value.IsNumber()) {
        double raw = scheme_value.As<Napi::Number>().DoubleValue();
        if (raw < 0.0 || raw > 255.0 || raw != static_cast<double>(
                static_cast<uint32_t>(raw))) {
          throw Napi::RangeError::New(env,
              "rotateKey: scheme must be a sig_scheme.h word or id (e.g. 'ecdsa_secp256k1')");
        }
        scheme_number = static_cast<uint32_t>(raw);
      } else if (scheme_value.IsString()) {
        static const struct { const char* word; uint32_t id; } kSchemeWords[] = {
            {"ecdsa_secp256k1", ECDSA_SECP256K1}, {"ecdsa_p256", ECDSA_P256},
            {"ed25519", ED25519}, {"schnorr_secp256k1", SCHNORR_SECP256K1},
            {"bls_bls12_381", BLS_BLS12_381}, {"rsa_2048", RSA_2048},
            {"rsa_4096", RSA_4096}, {"dilithium_2", DILITHIUM_2},
            {"dilithium_3", DILITHIUM_3}, {"dilithium_5", DILITHIUM_5},
            {"falcon_512", FALCON_512}, {"falcon_1024", FALCON_1024},
            {"sphincs_plus_128s", SPHINCS_PLUS_128S},
        };
        std::string word = scheme_value.As<Napi::String>().Utf8Value();
        bool matched = false;
        for (const auto& entry : kSchemeWords) {
          if (word == entry.word) {
            scheme_number = entry.id;
            matched = true;
            break;
          }
        }
        if (!matched) {
          throw Napi::RangeError::New(env,
              "rotateKey: scheme must be a sig_scheme.h word or id (e.g. 'ecdsa_secp256k1')");
        }
      } else {
        throw Napi::RangeError::New(env,
            "rotateKey: scheme must be a sig_scheme.h word or id (e.g. 'ecdsa_secp256k1')");
      }
    }

    // A malformed hex body would leave zero bytes at the C boundary — decode
    // loudly instead (the same shape check the registerUser path makes).
    if (pk_hex.size() % 2 != 0 ||
        pk_hex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
      throw Napi::Error::New(env,
          "rotateKey: publicKeyHex must be even-length hex, at most 512 bytes");
    }
    if (pk_hex.size() / 2 > CRABS_MAX_PUBLIC_KEY) {
      throw Napi::Error::New(env,
          "rotateKey: publicKeyHex must be even-length hex, at most 512 bytes");
    }
    std::vector<uint8_t> pk_bytes;
    pk_bytes.reserve(pk_hex.size() / 2);
    for (size_t hex_index = 0; hex_index < pk_hex.size(); hex_index += 2) {
      pk_bytes.push_back(
          static_cast<uint8_t>(std::stoul(pk_hex.substr(hex_index, 2), nullptr, 16)));
    }

    std::string label;
    if (opts.Has("label") && opts.Get("label").IsString()) {
      label = opts.Get("label").As<Napi::String>().Utf8Value();
    }

    user_t* user = RequireUser(env, "rotateKey", user_id);
    crabs_error_e rc = user_key_rotate(user, old_key_id.c_str(),
                                        new_key_id.c_str(),
                                        static_cast<signature_scheme_e>(scheme_number),
                                        pk_bytes.data(),
                                        static_cast<uint32_t>(pk_bytes.size()),
                                        label.empty() ? NULL : label.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "rotateKey");
    return env.Undefined();
  }

  // The keyring READBACK (parity-fill P2): walk the user's linked key list
  // and mirror the fields the C lifecycle tests assert
  // (test/test_key_lifecycle.cpp). List-prepend order: index 0 is the most
  // recently registered key.
  Napi::Value ListKeys(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string user_id = require_js_string(info[0], "listKeys", "userId");
    user_t* user = RequireUser(env, "listKeys", user_id);
    Napi::Array keys = Napi::Array::New(env);
    uint32_t index = 0;
    for (user_key_t* key = user->keys; key != NULL; key = key->next, ++index) {
      Napi::Object row = Napi::Object::New(env);
      row.Set("keyId", Napi::String::New(env, key->key_id));
      row.Set("schemeId", Napi::Number::New(env, (double)key->scheme));
      const char* status_str;
      switch (key->status) {
        case KEY_ACTIVE:    status_str = "active"; break;
        case KEY_SUSPENDED: status_str = "suspended"; break;
        case KEY_REVOKED:   status_str = "revoked"; break;
        case KEY_EXPIRED:   status_str = "expired"; break;
        default:            status_str = "unknown"; break;
      }
      row.Set("status", Napi::String::New(env, status_str));
      row.Set("label", Napi::String::New(env, key->label));
      row.Set("predecessorKeyId", Napi::String::New(env, key->predecessor_key_id));
      row.Set("publicKeyHex",
              Napi::String::New(env, hex_encode(key->public_key, key->public_key_len)));
      keys.Set(index, row);
    }
    return keys;
  }

  Napi::Value GetDefaultKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string user_id = require_js_string(info[0], "getDefaultKey", "userId");
    user_t* user = RequireUser(env, "getDefaultKey", user_id);
    if (user->default_key_id[0] == '\0') return Napi::String::New(env, "");
    return Napi::String::New(env, user->default_key_id);
  }

  // --- Admin demotion + user suspension (parity-fill P3) ---
  //
  // All three drive the C machine calls (attribute_machine_revoke_role /
  // _suspend_user / _activate_user — attribute_machine.h:145-171), each
  // ADMIN-GATED in C: the signer must be an ACTIVE user holding
  // role:admin, or the call refuses (unauthorized for non-admins,
  // user_suspended for suspended signers — the gate whitelist). The signer
  // defaults to the node's bootstrap admin id, the same convention the
  // sibling revokeUser wrapper established. revokeRole's C signature takes
  // NO value (attribute, role, signer) — the role NAME matches by attribute
  // name, not name:value.
  static std::string AdminSigner(const Napi::CallbackInfo& info,
                                  uint32_t signer_index, const char* ctx) {
    if (info.Length() <= signer_index || info[signer_index].IsUndefined()) {
      return std::string();
    }
    return require_js_string(info[signer_index], ctx, "signerId");
  }

  Napi::Value RevokeRole(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2)
      throw Napi::TypeError::New(env, "Expected (targetUser, role[, signerId])");
    std::string target = require_js_string(info[0], "revokeRole", "targetUser");
    std::string role = require_js_string(info[1], "revokeRole", "role");
    std::string signer = AdminSigner(info, 2, "revokeRole");
    if (signer.empty()) signer = admin_id_;
    crabs_error_e rc = attribute_machine_revoke_role(am_, target.c_str(),
                                                      role.c_str(),
                                                      signer.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "revokeRole");
    return env.Undefined();
  }

  Napi::Value SuspendUser(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string user_id = require_js_string(info[0], "suspendUser", "userId");
    std::string signer = AdminSigner(info, 1, "suspendUser");
    if (signer.empty()) signer = admin_id_;
    crabs_error_e rc = attribute_machine_suspend_user(am_, user_id.c_str(),
                                                       signer.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "suspendUser");
    return env.Undefined();
  }

  // Reactivates a SUSPENDED user (the key-compromise recovery path). An
  // ACTIVE or REVOKED target is not a recovery state — C refuses with
  // invalid_param; revocation is terminal.
  Napi::Value ActivateUser(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string user_id = require_js_string(info[0], "activateUser", "userId");
    std::string signer = AdminSigner(info, 1, "activateUser");
    if (signer.empty()) signer = admin_id_;
    crabs_error_e rc = attribute_machine_activate_user(am_, user_id.c_str(),
                                                        signer.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "activateUser");
    return env.Undefined();
  }

  Napi::Value GetUser(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string user_id = require_js_string(info[0], "getUser", "userId");
    user_t* user = attribute_machine_find_user(am_, user_id.c_str());
    if (!user) return env.Undefined();
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("userId", Napi::String::New(env, user->user_id));
    obj.Set("publicKeyHex", Napi::String::New(env, hex_encode(user->public_key, 33)));
    obj.Set("keyVersion", Napi::Number::New(env, (double)user->key_version));
    const char* status_str;
    switch (user->status) {
      case USER_ACTIVE:    status_str = "active"; break;
      case USER_SUSPENDED: status_str = "suspended"; break;
      case USER_REVOKED:   status_str = "revoked"; break;
      default:             status_str = "unknown"; break;
    }
    obj.Set("status", Napi::String::New(env, status_str));
    Napi::Array attrs = Napi::Array::New(env, user->attribute_count);
    for (uint32_t i = 0; i < user->attribute_count; i++) {
      Napi::Object a = Napi::Object::New(env);
      a.Set("value", Napi::String::New(env, user->attributes[i].value));
      a.Set("verifiedBy", Napi::String::New(env, user->attributes[i].verified_by));
      a.Set("temporary", Napi::Boolean::New(env, false));
      attrs.Set(i, a);
    }
    // Also include temporary attributes (issued by threshold triggers)
    temp_attr_list_t* temp = user->temp_attrs;
    while (temp != NULL) {
      Napi::Object a = Napi::Object::New(env);
      a.Set("value", Napi::String::New(env, temp->name));
      a.Set("verifiedBy", Napi::String::New(env, "trigger"));
      a.Set("temporary", Napi::Boolean::New(env, true));
      a.Set("expiresAt", Napi::Number::New(env, (double)temp->expires_at));
      attrs.Set(attrs.Length(), a);
      temp = temp->next;
    }
    obj.Set("attributes", attrs);
    return obj;
  }

  Napi::Value GetNodeKey(const Napi::CallbackInfo& info) {
    // Return an object with the node's public/private key hex.
    // A borrowed child wrapper has no own node key — spawn does not mint one;
    // whoever later loads the machine sets it.
    if (node_key_ == nullptr)
      throw Napi::Error::New(info.Env(),
          "getNodeKey: this machine carries no own node key");
    Napi::Object obj = Napi::Object::New(info.Env());
    obj.Set("publicKeyHex", Napi::String::New(info.Env(), hex_encode(node_key_->public_key, 33)));
    obj.Set("privateKeyHex", Napi::String::New(info.Env(), hex_encode(node_key_->private_key, 32)));
    return obj;
  }

  // --- Data items ---

  // Write-domains v1: item creation with an explicit write-domain
  // declaration. Types are restricted to counter/register in v1 — the two
  // domains that need value initialization here are the only types a
  // SOVEREIGN item may have (the hash-chain digest is defined only over
  // their canonical serializations), and FREE-MERGE items of other shapes
  // keep their dedicated add* methods.
  //   opts.domain: 'free' (default) | 'sovereign' | 'group'
  //   opts.writer: string — required for 'sovereign'
  //   opts.orderingModule: number — only legal for 'group' and only 0 in v1
  Napi::Value DefineItem(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3 || !info[0].IsString())
      throw Napi::TypeError::New(env,
          "Expected defineItem(name, dataType, crdtType, opts?)");
    std::string name = require_js_string(info[0], "defineItem", "name");
    data_type_e data_type;
    crdt_type_e crdt_type;
    if (!data_type_from_js(info[1], &data_type))
      throw Napi::TypeError::New(env,
          "defineItem: dataType must be a DATA_TYPE word ('counter', "
          "'register') or number");
    if (!crdt_type_from_js(info[2], &crdt_type))
      throw Napi::TypeError::New(env,
          "defineItem: crdtType must be a CRDT_TYPE word ('g_counter', "
          "'lww_reg') or number");
    if (data_type != DATA_TYPE_COUNTER && data_type != DATA_TYPE_REGISTER)
      throw crabs_error(env, CRABS_ERR_TYPE_MISMATCH,
          "defineItem: v1 supports only counter and register (use the "
          "dedicated add* methods for other types)");
    // The value install below keys on data_type ALONE, so a mismatched
    // crdt_type word would mint a value of one shape tagged with another's
    // crdt_type — every repr/crdt-dispatched consumer then miscasts it (the
    // reviewed wasm define_item hole, folded in here). Create with the
    // canonical pairing only.
    if (!data_item_type_crdt_pair_canonical(data_type, crdt_type))
      throw crabs_error(env, CRABS_ERR_TYPE_MISMATCH,
          "defineItem: dataType/crdtType must be the canonical pair "
          "('counter'+'g_counter', 'register'+'lww_reg')");

    data_item_options_t options;
    memset(&options, 0, sizeof(options));
    std::string writer;
    if (info.Length() > 3 && info[3].IsObject()) {
      Napi::Object opts = info[3].As<Napi::Object>();
      if (opts.Has("domain")) {
        std::string domain_word = to_lower_ascii(
            require_js_string(opts.Get("domain"), "defineItem", "domain"));
        if (domain_word == "free") {
          options.write_domain = CRABS_DOMAIN_FREE_MERGE;
        } else if (domain_word == "sovereign") {
          options.write_domain = CRABS_DOMAIN_SOVEREIGN;
        } else if (domain_word == "group") {
          options.write_domain = CRABS_DOMAIN_GROUP_ORDERED;
        } else {
          throw Napi::TypeError::New(env,
              "defineItem: domain must be 'free' | 'sovereign' | 'group'");
        }
      }
      if (opts.Has("writer")) {
        writer = require_js_string(opts.Get("writer"), "defineItem", "writer");
        options.writer = writer.c_str();
      }
      if (opts.Has("orderingModule")) {
        double module_value =
            opts.Get("orderingModule").As<Napi::Number>().DoubleValue();
        if (module_value < 0 || module_value > 255 ||
            module_value != floor(module_value))
          throw Napi::RangeError::New(env,
              "defineItem: orderingModule must be an integer 0..255");
        options.ordering_module = (uint8_t)module_value;
      }
    }

    data_item_t* item = NULL;
    crabs_error_e rc = data_item_create_with_options(
        name.c_str(), data_type, crdt_type, &options, &item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "defineItem");
    // Value initialization matches the dedicated adders: g_counter for
    // counters, a zeroed int64 LWW register for registers.
    if (data_type == DATA_TYPE_COUNTER) {
      item->value = g_counter_create();
    } else {
      int64_t initial = 0;
      item->value = lww_register_create((const uint8_t*)&initial,
                                        sizeof(int64_t), 0, "system");
    }
    // Struct-backed value (g_counter_t / lww_register_t).
    item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;
    rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) {
      data_item_destroy(item);
      throw crabs_error(env, rc, "defineItem");
    }
    return env.Undefined();
  }

  // Write-domains v1: the live chain head (item_seq + FULL 32-byte
  // item_digest as hex) of item `name` — what a SOVEREIGN writer's next op
  // must claim in its signed prefix (DOMAIN_CHECK compares both). Throws
  // resource_not_found for an unknown item.
  Napi::Value ItemChainHead(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString())
      throw Napi::TypeError::New(env, "Expected itemChainHead(name)");
    std::string name = require_js_string(info[0], "itemChainHead", "name");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item)
      throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "itemChainHead");
    char digest_hex[CRABS_HASH_SIZE * 2 + 1];
    for (uint32_t byte_index = 0; byte_index < CRABS_HASH_SIZE; byte_index++) {
      snprintf(digest_hex + byte_index * 2, 3, "%02x",
               item->item_digest[byte_index]);
    }
    digest_hex[CRABS_HASH_SIZE * 2] = '\0';
    Napi::Object head = Napi::Object::New(env);
    head.Set("seq", Napi::Number::New(env, (double)item->item_seq));
    head.Set("digestHex", Napi::String::New(env, digest_hex));
    return head;
  }

  // Write-domains v1: file a __report_equivocation__ op against the
  // SOVEREIGN item `itemName`, carrying two serialized writer ops as the
  // evidence pair. The handler re-verifies everything (both signatures
  // under the writer's current keyring, equal (item_seq, prev_item_digest)
  // claims); on success the writer is quarantined on the item. Signed by
  // the node's admin with the node key — the same submission idiom as
  // createTrigger (anyone with a policy for the op type may report).
  Napi::Value ReportEquivocation(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3 || !info[0].IsString() || !info[1].IsBuffer() ||
        !info[2].IsBuffer())
      throw Napi::TypeError::New(env,
          "Expected reportEquivocation(itemName, opABytes, opBBytes)");
    std::string item_name =
        require_js_string(info[0], "reportEquivocation", "itemName");
    auto op_a = info[1].As<Napi::Buffer<uint8_t>>();
    auto op_b = info[2].As<Napi::Buffer<uint8_t>>();
    if (op_a.Length() == 0 || op_b.Length() == 0)
      throw Napi::RangeError::New(env,
          "reportEquivocation: evidence ops must be non-empty");

    data_item_t* item =
        state_find_item(&am_->base_state, item_name.c_str());
    if (item == NULL)
      throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND,
                        "reportEquivocation");
    if (item->write_domain != CRABS_DOMAIN_SOVEREIGN ||
        item->writer[0] == '\0')
      throw crabs_error(env, CRABS_ERR_INVALID_PARAM,
          "reportEquivocation: item is not a sovereign item with a writer");
    if (node_key_ == nullptr)
      throw Napi::Error::New(env,
          "reportEquivocation: this machine carries no own node key");

    // Payload v1: u8 version + string16 item + string16 writer +
    // bytes32 op_a + bytes32 op_b (the handler's parser contract).
    uint32_t item_len = (uint32_t)item_name.length();
    uint32_t writer_len = (uint32_t)strlen(item->writer);
    if (item_len > UINT16_MAX || writer_len > UINT16_MAX)
      throw Napi::RangeError::New(env,
          "reportEquivocation: names too long");
    uint64_t payload_len64 = 1ull + 2 + item_len + 2 + writer_len +
                             4 + op_a.Length() + 4 + op_b.Length();
    if (payload_len64 > UINT32_MAX)
      throw Napi::RangeError::New(env,
          "reportEquivocation: evidence exceeds payload capacity");
    uint32_t payload_len = (uint32_t)payload_len64;
    uint8_t* payload = (uint8_t*)malloc(payload_len);
    if (payload == NULL) throw crabs_error(env, CRABS_ERR_OOM,
                                           "reportEquivocation");
    uint32_t offset = 0;
    payload[offset++] = 0x01;
    payload[offset++] = (uint8_t)(item_len & 0xFF);
    payload[offset++] = (uint8_t)((item_len >> 8) & 0xFF);
    memcpy(payload + offset, item_name.c_str(), item_len);
    offset += item_len;
    payload[offset++] = (uint8_t)(writer_len & 0xFF);
    payload[offset++] = (uint8_t)((writer_len >> 8) & 0xFF);
    memcpy(payload + offset, item->writer, writer_len);
    offset += writer_len;
    for (int byte_index = 0; byte_index < 4; byte_index++) {
      payload[offset++] = (uint8_t)((op_a.Length() >> (8 * byte_index)) & 0xFF);
    }
    memcpy(payload + offset, op_a.Data(), op_a.Length());
    offset += (uint32_t)op_a.Length();
    for (int byte_index = 0; byte_index < 4; byte_index++) {
      payload[offset++] = (uint8_t)((op_b.Length() >> (8 * byte_index)) & 0xFF);
    }
    memcpy(payload + offset, op_b.Data(), op_b.Length());
    offset += (uint32_t)op_b.Length();

    operation_t* op = operation_create(CRABS_OP_REPORT_EQUIVOCATION);
    if (op == NULL) {
      free(payload);
      throw crabs_error(env, CRABS_ERR_OOM, "reportEquivocation");
    }
    crypto_random_bytes(op->uuid, CRABS_UUID_SIZE);
    op->payload = payload;
    op->payload_size = payload_len;
    strncpy(op->signer_id, admin_id_.c_str(), CRABS_MAX_USER_ID - 1);
    strncpy(op->node_id, admin_id_.c_str(), CRABS_MAX_USER_ID - 1);

    // Stamp the signer's current key version (R7-04) and HLC when the
    // machine is HLC-ordered, then sign — the same pre-sign stamping
    // node.sign() performs.
    if (am_->base_state.hlc_state_initialized) {
      op->ordering_system = CRABS_ORDERING_HLC;
      op->hlc = crabs_hlc_next(&am_->base_state.hlc_state);
      strncpy(op->node_id, am_->base_state.hlc_state.last.node_id,
              CRABS_MAX_USER_ID - 1);
    }
    user_t* signer_user = attribute_machine_find_user(am_, op->signer_id);
    if (signer_user != NULL) {
      op->signer_key_version = signer_user->key_version;
    }
    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
    if (ser == NULL) {
      operation_destroy(op);
      throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR,
                        "reportEquivocation");
    }
    crabs_error_e rc = crypto_ecdsa_sign(node_key_->private_key, ser->data,
                                         ser->len, op->signature);
    serialized_buffer_destroy(ser);
    if (rc != CRABS_SUCCESS) {
      operation_destroy(op);
      throw crabs_error(env, rc, "reportEquivocation");
    }

    rc = state_machine_execute(&am_->base_state, op);
    operation_destroy(op);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc,
                                               "reportEquivocation");
    return env.Undefined();
  }

  Napi::Value AddCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addCounter", "name");
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_COUNTER, CRDT_G_COUNTER);
    item->value = g_counter_create();
    item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;  // g_counter_t struct
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addCounter");
    return env.Undefined();
  }

  Napi::Value AddPNCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addPNCounter", "name");
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_PN_COUNTER, CRDT_PN_COUNTER);
    item->value = pn_counter_create();
    item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;  // pn_counter_t struct
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addPNCounter");
    return env.Undefined();
  }

  Napi::Value AddORSet(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addORSet", "name");
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_SET, CRDT_OR_SET);
    item->value = or_set_create();
    item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;  // or_set_t struct
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addORSet");
    return env.Undefined();
  }

  Napi::Value AddOneShotSet(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addOneShotSet", "name");
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
    item->value = one_shot_set_create();
    item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;  // one_shot_set_t struct
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addOneShotSet");
    return env.Undefined();
  }

  // Direct temporary-attribute issuance (Amendment 1 §7.1) — the
  // moderation-trigger effect's C call driven by hand
  // (attribute_machine_issue_temporary, attribute_machine.h:200). The grant
  // fans out to EVERY ACTIVE holder of the audience ATTRIBUTE NAME (the C
  // role-match is a name match, attribute_machine.c:592) and stamps
  // issued_at / expires_at from the machine's attr-machine clock. The C
  // machine owns every gate and the typed errors surface as-is:
  // unauthorized — a privileged attribute NAME (the blocklist, Audit N-1);
  // invalid_param — ttl 0, unsafe charset names, or comma/space values.
  Napi::Value IssueTemporary(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString())
      throw Napi::TypeError::New(env,
          "Expected issueTemporary(attribute, value, { audienceRole, ttlMs })");
    std::string attribute = info[0].As<Napi::String>().Utf8Value();
    std::string value = info[1].As<Napi::String>().Utf8Value();
    if (attribute.empty() || value.empty())
      throw Napi::TypeError::New(env,
          "issueTemporary: attribute and value are required non-empty strings");
    if (info.Length() < 3 || !info[2].IsObject())
      throw Napi::TypeError::New(env,
          "issueTemporary: options.audienceRole is required (the audience "
          "attribute NAME the fan-out matches — 'role', not 'role:member')");
    Napi::Object options = info[2].As<Napi::Object>();
    if (!options.Has("audienceRole") || !options.Get("audienceRole").IsString())
      throw Napi::TypeError::New(env,
          "issueTemporary: options.audienceRole is required (the audience "
          "attribute NAME the fan-out matches — 'role', not 'role:member')");
    std::string audience_role =
        options.Get("audienceRole").As<Napi::String>().Utf8Value();
    if (audience_role.empty())
      throw Napi::TypeError::New(env, "issueTemporary: audienceRole must be non-empty");
    if (!options.Has("ttlMs") || !options.Get("ttlMs").IsNumber())
      throw Napi::RangeError::New(env,
          "issueTemporary: ttlMs must be a non-negative integer");
    double ttl_value = options.Get("ttlMs").As<Napi::Number>().DoubleValue();
    // 0 flows through to the C machine (its own invalid_param gate — the C
    // machine owns every gate); only a value a u64 cannot carry refuses at
    // the wrapper.
    if (ttl_value < 0.0 || ttl_value != std::floor(ttl_value) ||
        ttl_value > 9007199254740991.0) {
      throw Napi::RangeError::New(env,
          "issueTemporary: ttlMs must be a non-negative integer (safe-integer "
          "range; use the wasm binding's BigInt path for larger windows)");
    }
    crabs_error_e rc = attribute_machine_issue_temporary(
        am_, attribute.c_str(), value.c_str(), audience_role.c_str(),
        (uint64_t)ttl_value);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "issueTemporary");
    return env.Undefined();
  }

  Napi::Value AddOneShotFlag(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addOneShotFlag", "name");
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
    item->value = one_shot_flag_create();
    item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;  // one_shot_flag_t struct
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addOneShotFlag");
    return env.Undefined();
  }

  Napi::Value AddRegister(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addRegister", "name");
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_REGISTER, CRDT_LWW_REG);
    int64_t initial = 0;
    if (info.Length() > 1 && info[1].IsNumber())
      initial = (int64_t)info[1].As<Napi::Number>().Int64Value();
    item->value = lww_register_create((const uint8_t*)&initial, sizeof(int64_t), 0, "system");
    item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;  // lww_register_t struct
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addRegister");
    return env.Undefined();
  }

  Napi::Value AddResource(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addResource", "name");
    int64_t initial = 0;
    if (info.Length() > 1 && info[1].IsNumber())
      initial = (int64_t)info[1].As<Napi::Number>().Int64Value();
    if (state_find_item(&am_->base_state, name.c_str()) != NULL)
      throw crabs_error(env, CRABS_ERR_DUPLICATE_OPERATION, "addResource");
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
    if (item == NULL) throw crabs_error(env, CRABS_ERR_OOM, "addResource");
    // RESOURCE items carry a bare heap int64_t (the library contract — dedup
    // mutations, the lock snapshot, and destroy all take the raw path for
    // RESOURCE), never a pn_counter struct; value_repr stays RAW_INT64.
    int64_t* initial_balance = (int64_t*)malloc(sizeof(int64_t));
    if (initial_balance == NULL) {
      data_item_destroy(item);
      throw crabs_error(env, CRABS_ERR_OOM, "addResource");
    }
    *initial_balance = initial;
    item->value = initial_balance;
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addResource");
    return env.Undefined();
  }

  // --- Recipe 9: lock protocol + tx manager ----------------------------
  //
  // Attach a replay-protection manager to the machine's state
  // (src/TxManager/tx_manager.h). 'memory' records committed op uuids in an
  // in-memory committed-uuid store (an AVL tree): the executor's step 3b
  // accept — which runs AFTER the signature check (the R7-L-4 oracle
  // placement) — refuses a duplicate submission with already_executed, and
  // step 8c commit records the op after it lands. 'none' is the
  // accept-everything deployment hook (crabs_tx_manager_none). With NO
  // manager attached, the ordering-monotonicity backstop (step 3c,
  // state_signer_has_replay) still rejects a replayed op — including after
  // a restart, when the manager's memory is empty. Replacing an attached
  // manager destroys the previous one (host-owned, vtable destroy). Not
  // serialized: after a state round trip the machine runs manager-less
  // again (attach again after load).
  Napi::Value AttachTxManager(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string kind = require_js_string(info[0], "attachTxManager", "kind");
    crabs_tx_manager_t* attached = NULL;
    if (kind == "memory") {
      attached = crabs_tx_manager_memory(64);
    } else if (kind == "none") {
      attached = crabs_tx_manager_none();
    } else {
      throw Napi::RangeError::New(env,
          "attachTxManager: kind must be 'memory' or 'none'");
    }
    if (attached == NULL) throw crabs_error(env, CRABS_ERR_OOM, "attachTxManager");
    if (am_->base_state.tx_manager != NULL) {
      ((crabs_tx_manager_t*)am_->base_state.tx_manager)->vtable.destroy(
          (crabs_tx_manager_t*)am_->base_state.tx_manager);
    }
    am_->base_state.tx_manager = attached;
    return env.Undefined();
  }

  // LIVE lock state of a RESOURCE item (data_item_t.lock_state_t — runtime
  // only, never serialized). This is how the JS driver receives the bearer
  // token state_machine_op_lock minted: the executor consumes the
  // lock_response_t internally, so the item is the token's only observable
  // home; claim it into the next op's addLockClaim before signing.
  Napi::Value GetLockState(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "getLockState", "name");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (item == NULL) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND,
                                        "getLockState");
    if (item->type != DATA_TYPE_RESOURCE)
      throw crabs_error(env, CRABS_ERR_TYPE_MISMATCH, "getLockState");
    Napi::Object view = Napi::Object::New(env);
    view.Set("protocolState", protocol_state_name(item->protocol_state));
    view.Set("lockOwner", std::string(item->lock_state.lock_owner));
    view.Set("lockTokenHex",
             item->lock_state.lock_token_valid
                 ? hex_encode(item->lock_state.lock_token,
                              CRABS_LOCK_TOKEN_SIZE)
                 : std::string(""));
    view.Set("lockExpiry",
             (double)item->lock_state.lock_expiry);
    view.Set("lockExtensions",
             (double)item->lock_state.lock_extensions);
    return view;
  }

  // Raw int64 readback of a RESOURCE item's balance. Undefined for an
  // unknown name (getCounter's convention); type_mismatch for anything that
  // is not a RESOURCE item.
  Napi::Value GetResource(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "getResource", "name");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (item == NULL) return env.Undefined();
    int64_t* balance = resource_balance(item);
    if (balance == NULL)
      throw crabs_error(env, CRABS_ERR_TYPE_MISMATCH, "getResource");
    return Napi::Number::New(env, (double)*balance);
  }

  // --- Queries ---

  Napi::Value GetCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "getCounter", "name");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) return env.Undefined();
    if (item->crdt_type == CRDT_G_COUNTER)
      return Napi::Number::New(env, (double)g_counter_value((g_counter_t*)item->value));
    return env.Undefined();
  }

  Napi::Value IncrementCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "incrementCounter", "name");
    int64_t delta = info.Length() > 1 ? (int64_t)info[1].As<Napi::Number>().Int64Value() : 1;
    std::string node_id = info.Length() > 2
        ? require_js_string(info[2], "incrementCounter", "nodeId") : "system";
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "incrementCounter");
    crabs_error_e rc = g_counter_increment((g_counter_t*)item->value, node_id.c_str(), delta);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "incrementCounter");
    return env.Undefined();
  }

  Napi::Value IncrementPNCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "incrementPNCounter", "name");
    int64_t delta = info.Length() > 1 ? (int64_t)info[1].As<Napi::Number>().Int64Value() : 1;
    std::string node_id = info.Length() > 2
        ? require_js_string(info[2], "incrementPNCounter", "nodeId") : "system";
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "incrementPNCounter");
    crabs_error_e rc = pn_counter_increment((pn_counter_t*)item->value, node_id.c_str(), delta);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "incrementPNCounter");
    return env.Undefined();
  }

  Napi::Value DecrementPNCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "decrementPNCounter", "name");
    int64_t delta = info.Length() > 1 ? (int64_t)info[1].As<Napi::Number>().Int64Value() : 1;
    std::string node_id = info.Length() > 2
        ? require_js_string(info[2], "decrementPNCounter", "nodeId") : "system";
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "decrementPNCounter");
    crabs_error_e rc = pn_counter_decrement((pn_counter_t*)item->value, node_id.c_str(), delta);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "decrementPNCounter");
    return env.Undefined();
  }

  Napi::Value GetPNCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "getPNCounter", "name");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) return env.Undefined();
    if (item->crdt_type == CRDT_PN_COUNTER)
      return Napi::Number::New(env, (double)pn_counter_value((pn_counter_t*)item->value));
    return env.Undefined();
  }

  Napi::Value GetRegister(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "getRegister", "name");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) return env.Undefined();
    if (item->crdt_type == CRDT_LWW_REG) {
      lww_register_t* reg = (lww_register_t*)item->value;
      if (reg && reg->value && reg->value_size >= sizeof(int64_t))
        return Napi::Number::New(env, (double)*(int64_t*)reg->value);
    }
    return env.Undefined();
  }

  Napi::Value SetRegister(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2)
      throw Napi::TypeError::New(env, "Expected (name, value[, nodeId])");
    std::string name = require_js_string(info[0], "setRegister", "name");
    // Consumption finding 1: registers are integer-only (int64 in C).
    // Parity-fill P10: BigInt accepted TOO (the wasm wrapper's contract) —
    // a BigInt carries the full int64 range, so the safe-integer number
    // ceiling only applies to Number inputs. Fractional values are still
    // rejected — encode scaled units instead (e.g. store 12.5% as 125
    // per-mille).
    int64_t value = 0;
    if (info[1].IsBigInt()) {
      bool lossless = true;
      value = info[1].As<Napi::BigInt>().Int64Value(&lossless);
      if (!lossless)
        throw Napi::TypeError::New(env,
          "setRegister: registers carry a signed 64-bit integer; the BigInt value is outside the int64 range");
    } else if (info[1].IsNumber()) {
      double num_value = info[1].As<Napi::Number>().DoubleValue();
      if (!std::isfinite(num_value) || std::floor(num_value) != num_value)
        throw Napi::TypeError::New(env,
          "setRegister: registers are integer-only; encode fractional values in register units (e.g. per-mille)");
      if (std::fabs(num_value) > 9007199254740991.0 /* 2^53 - 1 */)
        throw Napi::TypeError::New(env,
          "setRegister: registers are integer-only; |value| exceeds Number.MAX_SAFE_INTEGER — pass a BigInt for the full int64 range");
      value = (int64_t)num_value;
    } else {
      throw Napi::TypeError::New(env,
        "setRegister: value must be an integer Number or a BigInt (encode fractional values in register units, e.g. per-mille)");
    }
    std::string node_id = info.Length() > 2
        ? require_js_string(info[2], "setRegister", "nodeId") : "system";
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "setRegister");
    if (item->crdt_type != CRDT_LWW_REG)
      throw crabs_error(env, CRABS_ERR_TYPE_MISMATCH, "setRegister (not a register)");
    lww_register_t* reg = (lww_register_t*)item->value;
    if (!reg) throw crabs_error(env, CRABS_ERR_INTERNAL, "setRegister (null register)");
    // Free old value and set new one
    if (reg->value) free(reg->value);
    reg->value = (uint8_t*)malloc(sizeof(int64_t));
    if (!reg->value) throw crabs_error(env, CRABS_ERR_OOM, "setRegister");
    memcpy(reg->value, &value, sizeof(int64_t));
    reg->value_size = sizeof(int64_t);
    // Update timestamp: use HLC if available, else a monotonic counter
    reg->timestamp = am_->base_state.version + 1;
    strncpy(reg->node_id, node_id.c_str(), CRABS_MAX_USER_ID - 1);
    reg->node_id[CRABS_MAX_USER_ID - 1] = '\0';
    am_->base_state.version++;
    return env.Undefined();
  }

  Napi::Value SetContains(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "setContains", "name");
    std::string element = require_js_string(info[1], "setContains", "element");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) return Napi::Boolean::New(env, false);
    bool contains = false;
    if (item->crdt_type == CRDT_OR_SET)
      contains = or_set_contains((or_set_t*)item->value, element.c_str());
    else if (item->crdt_type == CRDT_ONE_SHOT_SET)
      contains = one_shot_set_contains((one_shot_set_t*)item->value, element.c_str());
    return Napi::Boolean::New(env, contains);
  }

  // --- Parity-fill P10 (binding alignment): the wasm read surface ---

  // Distinct LIVE elements of an OR-set / one-shot set: pair-tombstoned
  // entries skipped, deduped at the element level (the same element may be
  // carried by several live tags post-Task-1; it counts once here). Unknown
  // names and non-set items report 0 — the same readback contract the wasm
  // export (crabs_wasm_handler_set_size) gives JS.
  //
  // The OR-set arm mirrors _handler_set_live_distinct (wasm_helpers.c:3088)
  // entry-for-entry; the JS-visible facts (distinct, live, count) are
  // identical — direct C instead of a wasm round trip.
  Napi::Value GetSetSize(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "getSetSize", "name");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item || (item->crdt_type != CRDT_OR_SET &&
                  item->crdt_type != CRDT_ONE_SHOT_SET))
      return Napi::Number::New(env, 0);
    std::vector<const char*> elements;
    _collect_live_distinct(item, elements);
    return Napi::Number::New(env, (double)elements.size());
  }

  // Bounded enumerator: one page of DISTINCT LIVE elements, sorted
  // ascending (byte-wise strcmp, stable across replicas). 256-hard-cap,
  // snapshot semantics — page at a fixed getSetSize when the set may be
  // changing. Mirrors crabs_wasm_handler_set_elements' contract exactly,
  // including the typed refusals (unknown name → resource_not_found, a
  // non-set item → type_mismatch, limit outside [1, 256] → RangeError).
  Napi::Value GetSetElements(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "getSetElements", "name");
    // Options bag: 0-based offset (default 0, monotone-truncated on the C
    // side), page size in [1, 256] (default 256 — the full small set; the
    // cap is mirrored from CRABS_WASM_HANDLER_SET_PAGE_CAP in
    // wasm_helpers.c:3083).
    uint32_t offset = 0;
    uint32_t limit = CRABS_NODE_SET_PAGE_CAP;
    if (info.Length() > 1) {
      if (!info[1].IsObject())
        throw Napi::TypeError::New(env,
            "getSetElements: expected an options object ({offset?, limit?})");
      Napi::Object options = info[1].As<Napi::Object>();
      if (options.Has("offset")) {
        if (!options.Get("offset").IsNumber())
          throw Napi::TypeError::New(env,
              "getSetElements: offset must be a number");
        double offset_value = options.Get("offset").As<Napi::Number>().DoubleValue();
        if (offset_value < 0 || std::floor(offset_value) != offset_value)
          throw Napi::TypeError::New(env,
              "getSetElements: offset must be a non-negative integer");
        offset = (uint32_t)offset_value;
      }
      if (options.Has("limit")) {
        if (!options.Get("limit").IsNumber())
          throw Napi::TypeError::New(env,
              "getSetElements: limit must be a number");
        double limit_value = options.Get("limit").As<Napi::Number>().DoubleValue();
        if (limit_value < 1 || limit_value > (double)CRABS_NODE_SET_PAGE_CAP ||
            std::floor(limit_value) != limit_value) {
          throw Napi::Error::New(env,
              "getSetElements: limit must be an integer in [1, "
              + std::to_string(CRABS_NODE_SET_PAGE_CAP) + "]");
        }
        limit = (uint32_t)limit_value;
      }
    }
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND,
                                 "getSetElements");
    if (item->crdt_type != CRDT_OR_SET &&
        item->crdt_type != CRDT_ONE_SHOT_SET)
      throw crabs_error(env, CRABS_ERR_TYPE_MISMATCH, "getSetElements");
    std::vector<const char*> elements;
    _collect_live_distinct(item, elements);
    std::sort(elements.begin(), elements.end(), _crabs_node_cstr_less);
    Napi::Array page = Napi::Array::New(env);
    uint32_t start = offset < elements.size() ? offset : (uint32_t)elements.size();
    uint32_t page_count = (uint32_t)elements.size() - start;
    if (page_count > limit) page_count = limit;
    for (uint32_t index = 0; index < page_count; index++) {
      page.Set(index, Napi::String::New(env, elements[start + index]));
    }
    return page;
  }

  // LIVE tags carrying `element` of an OR-set, sorted ascending. Pair
  // semantics (post-Task-1) may carry an element on several tags — every
  // live one reads back. Unknown name → resource_not_found; a one-shot set
  // (element list, no tag axis) or any other non-OR-set → type_mismatch;
  // an element with no live tags → []. Mirrors crabs_wasm_handler_set_tags.
  Napi::Value GetSetTags(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "getSetTags", "name");
    std::string element = require_js_string(info[1], "getSetTags", "element");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND,
                                 "getSetTags");
    if (item->crdt_type != CRDT_OR_SET)
      throw crabs_error(env, CRABS_ERR_TYPE_MISMATCH, "getSetTags");
    const or_set_t* set = (const or_set_t*)item->value;
    if (!set) throw crabs_error(env, CRABS_ERR_INTERNAL, "getSetTags");
    std::vector<const char*> tags;
    tags.reserve(set->element_count);
    for (uint32_t entry_index = 0; entry_index < set->element_count;
         entry_index++) {
      if (element != set->elements[entry_index].element) continue;
      const char* tag = set->elements[entry_index].tag;
      bool tombstoned = false;
      for (uint32_t tombstone_index = 0;
           tombstone_index < set->tombstone_count; tombstone_index++) {
        if (element == set->tombstones[tombstone_index].element &&
            strcmp(tag, set->tombstones[tombstone_index].tag) == 0) {
          tombstoned = true;
          break;
        }
      }
      if (tombstoned) continue;
      tags.push_back(tag);
    }
    std::sort(tags.begin(), tags.end(), _crabs_node_cstr_less);
    Napi::Array tag_list = Napi::Array::New(env);
    for (uint32_t tag_index = 0; tag_index < tags.size(); tag_index++) {
      tag_list.Set(tag_index, Napi::String::New(env, tags[tag_index]));
    }
    return tag_list;
  }

  // Opaque byte payload of an LWW register — the byte-exact inverse of
  // setRegisterBytes. Empty register → an empty Buffer. Mirrors
  // crabs_wasm_handler_get_register_bytes: unknown name → resource_not_found,
  // a non-register item → type_mismatch.
  Napi::Value GetRegisterBytes(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "getRegisterBytes", "name");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND,
                                 "getRegisterBytes");
    if (item->crdt_type != CRDT_LWW_REG)
      throw crabs_error(env, CRABS_ERR_TYPE_MISMATCH, "getRegisterBytes");
    const lww_register_t* reg = (const lww_register_t*)item->value;
    if (!reg) throw crabs_error(env, CRABS_ERR_INTERNAL, "getRegisterBytes");
    // An empty register's value pointer is NULL — construct the empty
    // Buffer directly instead of Copy() over a NULL source.
    if (reg->value_size == 0)
      return Napi::Buffer<uint8_t>::New(env, 0);
    return Napi::Buffer<uint8_t>::Copy(env, reg->value, reg->value_size);
  }

  // Store ARBITRARY bytes as a register payload (the byte-exact inverse of
  // getRegisterBytes). Mirrors crabs_wasm_set_register_bytes: unknown name
  // or a non-LWW-register item → resource_not_found; an over-size payload
  // (payload_size is u32) refuses with RangeError instead of truncating.
  Napi::Value SetRegisterBytes(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2)
      throw Napi::TypeError::New(env,
          "Expected (name, bytes[, nodeId])");
    std::string name = require_js_string(info[0], "setRegisterBytes", "name");
    std::string node_id = info.Length() > 2
        ? require_js_string(info[2], "setRegisterBytes", "nodeId") : "system";
    if (!info[1].IsBuffer() && !info[1].IsTypedArray())
      throw Napi::TypeError::New(env,
          "setRegisterBytes: bytes must be a Buffer or Uint8Array");
    Napi::Buffer<uint8_t> input = info[1].IsBuffer()
        ? info[1].As<Napi::Buffer<uint8_t>>()
        : Napi::Buffer<uint8_t>::Copy(env,
              info[1].As<Napi::Uint8Array>().Data(),
              info[1].As<Napi::Uint8Array>().ByteLength());
    if (input.Length() > UINT32_MAX)
      throw Napi::RangeError::New(env,
          "setRegisterBytes: payload exceeds UINT32_MAX bytes");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item || item->crdt_type != CRDT_LWW_REG)
      throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "setRegisterBytes");
    lww_register_t* reg = (lww_register_t*)item->value;
    if (!reg) throw crabs_error(env, CRABS_ERR_INTERNAL, "setRegisterBytes");
    uint8_t* copy = NULL;
    if (input.Length() > 0) {
      copy = (uint8_t*)malloc(input.Length());
      if (!copy) throw crabs_error(env, CRABS_ERR_OOM, "setRegisterBytes");
      memcpy(copy, input.Data(), input.Length());
    }
    if (reg->value) free(reg->value);
    reg->value = copy;
    reg->value_size = (uint32_t)input.Length();
    // LWW bookkeeping identical to setRegister: timestamp = version + 1,
    // then the machine's version advances.
    reg->timestamp = am_->base_state.version + 1;
    strncpy(reg->node_id, node_id.c_str(), CRABS_MAX_USER_ID - 1);
    reg->node_id[CRABS_MAX_USER_ID - 1] = '\0';
    am_->base_state.version++;
    return env.Undefined();
  }

  // The explicit trigger tick (C trigger_process_all, Trigger/trigger.h:80):
  // prune-expired-temp-attrs + one condition pass over the machine's
  // triggers, driving every matched effect. The executor ALSO runs this pass
  // after each executed op (state_machine.c, step 9) — this surface is for
  // hosts whose state mutations bypass the op path (direct CRDT writers) and
  // for deterministic ticking in tests. Mirrors the executor's clock rule:
  // the machine's own time source (state_get_time_ms) stamps now_ms, and an
  // unreadable clock fails closed. Returns the number of triggers fired —
  // the wasm wrapper discards it (void); node reports it.
  Napi::Value EvaluateTriggers(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    uint64_t now_ms = 0;
    if (!state_get_time_ms(&am_->base_state, &now_ms))
      throw crabs_error(env, CRABS_ERR_CRYPTOGRAPHIC_ERROR, "evaluateTriggers");
    uint32_t fired = trigger_process_all(&am_->base_state,
                                         am_->base_state.triggers,
                                         am_->base_state.trigger_count,
                                         am_, now_ms);
    return Napi::Number::New(env, (double)fired);
  }

  // --- Set operations (direct, for testing/setup) ---

  Napi::Value SetAdd(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "setAdd", "name");
    std::string element = require_js_string(info[1], "setAdd", "element");
    std::string tag = info.Length() > 2
        ? require_js_string(info[2], "setAdd", "tag") : element;
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "setAdd");
    crabs_error_e rc = CRABS_ERR_TYPE_MISMATCH;
    if (item->crdt_type == CRDT_OR_SET)
      rc = or_set_add((or_set_t*)item->value, element.c_str(), tag.c_str());
    else if (item->crdt_type == CRDT_ONE_SHOT_SET)
      rc = one_shot_set_add((one_shot_set_t*)item->value, element.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "setAdd");
    return env.Undefined();
  }

  Napi::Value SetRemove(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "setRemove", "name");
    std::string element = require_js_string(info[1], "setRemove", "element");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "setRemove");
    if (item->crdt_type == CRDT_OR_SET)
      or_set_remove((or_set_t*)item->value, element.c_str());
    return env.Undefined();
  }

  Napi::Value FlagSet(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "flagSet", "name");
    std::string setBy = require_js_string(info[1], "flagSet", "setBy");
    uint64_t setAt = info.Length() > 2
        ? require_u64_numeric(info[2], "flagSet", "setAt") : 0;
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "flagSet");
    one_shot_flag_set((one_shot_flag_t*)item->value, setBy.c_str(), setAt);
    return env.Undefined();
  }

  Napi::Value FlagValue(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "flagValue", "name");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) return Napi::Boolean::New(env, false);
    return Napi::Boolean::New(env, one_shot_flag_value((one_shot_flag_t*)item->value));
  }

  // ============================================================
  // Ordered set (OT_ORDERED_SET, v1.5 §5) — recipe 8
  // ============================================================

  // Item creation mirrors crabs_register_ot_type (ot_execution.c): the OT
  // wrapper allocates its own crabs_ot_ordered_set_t into item->value and
  // its op-log/transform-matrix struct into item->ot_data — crabs_apply_ot_op
  // dereferences both unconditionally (a NULL value is CRABS_ERR_INTERNAL),
  // so there is no lazy attach. Default domain: FREE_MERGE.
  Napi::Value AddOrderedSet(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addOrderedSet", "name");
    data_item_t* item = data_item_create(name.c_str(),
        DATA_TYPE_OT_ORDERED_SET, CRDT_CUSTOM);
    if (!item) throw crabs_error(env, CRABS_ERR_OOM, "addOrderedSet");
    crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
    item->value = set;
    if (!set) {
      data_item_destroy(item);
      throw crabs_error(env, CRABS_ERR_OOM, "addOrderedSet");
    }
    item->ot_data = set->ot_data;
    // Struct-backed value (crabs_ot_ordered_set_t) — data_item_destroy
    // dispatches OT destruction by type.
    item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    // A failure here (e.g. duplicate_operation) leaves the item uninserted —
    // destroy it before throwing or the item, its struct value and its
    // ot_data all leak (mirrors crabs_wasm_add_ordered_set's failure path).
    if (rc != CRABS_SUCCESS) {
      data_item_destroy(item);
      throw crabs_error(env, rc, "addOrderedSet");
    }
    return env.Undefined();
  }

  // Visible elements in materialized order (tombstones skipped), each
  // element's payload value decoded as UTF-8. Throws resource_not_found for
  // an unknown / non-ordered-set name.
  Napi::Value GetOrderedSet(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "getOrderedSet", "name");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item || item->type != DATA_TYPE_OT_ORDERED_SET)
      throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "getOrderedSet");
    crabs_ot_ordered_set_t* set = (crabs_ot_ordered_set_t*)item->value;
    if (!set) throw crabs_error(env, CRABS_ERR_INTERNAL, "getOrderedSet");

    Napi::Array elements = Napi::Array::New(env);
    uint32_t position = 0;
    for (crabs_ordered_element_t* element = crabs_ot_ordered_set_head(set);
         element != NULL; element = element->next) {
      if (element->deleted) continue;
      const uint8_t* value = element->value;
      uint32_t value_size = element->value_size;
      if (value == NULL) {
        elements.Set(position, Napi::String::New(env, ""));
      } else {
        elements.Set(position, Napi::String::New(env,
            reinterpret_cast<const char*>(value), value_size));
      }
      position++;
    }
    Napi::Object result = Napi::Object::New(env);
    result.Set("elements", elements);
    return result;
  }

  // Apply ONE ordered-set op through the machine executor: compose, sign
  // with the node key under this machine's admin (the reportEquivocation
  // idiom — the caller must install the '__execute_ot__' policy first) and
  // execute a CRABS_OP_EXECUTE_OT op whose payload is a wire-encoded
  // crabs_ot_operation_t (crabs_ot_ops_to_wire). Shared by the four sugar
  // methods.
  void OrderedSetApply(const Napi::CallbackInfo& info, Napi::Object options,
                       const std::string& name, uint32_t op_kind,
                       uint64_t visible_pos, uint64_t visible_pos_2,
                       const char* element, uint32_t element_len,
                       const char* ctx) {
    Napi::Env env = info.Env();
    if (!options.Has("id"))
      throw Napi::TypeError::New(env, std::string(ctx) +
          ": id is required — { node, seq, ts? } fixes the op's OT identity");
    Napi::Object id = options.Get("id").As<Napi::Object>();
    if (!id.Has("node") || !id.Get("node").IsString())
      throw Napi::TypeError::New(env, std::string(ctx) +
          ": id.node is required (string, the issuing replica's id)");
    std::string id_node = require_js_string(id.Get("node"), ctx, "id.node");
    if (id_node.empty() || id_node.length() >= CRABS_MAX_USER_ID)
      throw Napi::RangeError::New(env, std::string(ctx) +
          ": id.node must be 1..63 characters");
    if (!id.Has("seq"))
      throw Napi::TypeError::New(env, std::string(ctx) +
          ": id.seq is required (integer >= 0, unique per id.node)");
    // Non-integer / negative numbers truncate silently through the u64
    // conversion — require_u64_numeric refuses them.
    uint64_t id_sequence = require_u64_numeric(id.Get("seq"), ctx, "id.seq");
    uint64_t id_timestamp = 0;
    if (id.Has("ts") && !id.Get("ts").IsUndefined())
      id_timestamp = require_u64_numeric(id.Get("ts"), ctx, "id.ts");

    std::vector<crabs_ot_op_id_t> deps;
    if (options.Has("deps") && !options.Get("deps").IsUndefined()) {
      if (!options.Get("deps").IsArray())
        throw Napi::TypeError::New(env,
            std::string(ctx) + ": deps must be an array of { node, seq, ts? }");
      Napi::Array raw_deps = options.Get("deps").As<Napi::Array>();
      if (raw_deps.Length() > CRABS_OT_MAX_DEPS)
        throw Napi::RangeError::New(env,
            std::string(ctx) + ": at most 16 causal deps per op");
      deps.resize(raw_deps.Length());
      for (uint32_t dep_index = 0; dep_index < raw_deps.Length(); dep_index++) {
        Napi::Value raw_dep = raw_deps.Get(dep_index);
        if (!raw_dep.IsObject())
          throw Napi::TypeError::New(env,
              std::string(ctx) + ": each dep must be { node, seq, ts? }");
        Napi::Object dep = raw_dep.As<Napi::Object>();
        if (!dep.Has("node") || !dep.Get("node").IsString())
          throw Napi::TypeError::New(env,
              std::string(ctx) + ": dep node is required (string)");
        std::string dep_node = require_js_string(dep.Get("node"), ctx,
                                                 "dep.node");
        if (dep_node.empty() || dep_node.length() >= CRABS_MAX_USER_ID)
          throw Napi::RangeError::New(env,
              std::string(ctx) + ": dep node must be 1..63 characters");
        if (!dep.Has("seq"))
          throw Napi::TypeError::New(env,
              std::string(ctx) + ": dep \"" + dep_node + "\" needs integer seq");
        uint64_t dep_sequence = require_u64_numeric(dep.Get("seq"), ctx, "dep.seq");
        uint64_t dep_timestamp = dep.Has("ts") && !dep.Get("ts").IsUndefined()
            ? require_u64_numeric(dep.Get("ts"), ctx, "dep.ts") : 0;
        crabs_ot_op_id_init(&deps[dep_index], dep_node.c_str(), dep_sequence,
                            dep_timestamp);
      }
    }

    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, ctx);
    if (item->type != DATA_TYPE_OT_ORDERED_SET)
      throw crabs_error(env, CRABS_ERR_NOT_OT_TYPE, ctx);
    crabs_ot_ordered_set_t* set = (crabs_ot_ordered_set_t*)item->value;
    if (!set) throw crabs_error(env, CRABS_ERR_INTERNAL, ctx);

    // crabs_apply_ot_op silently no-ops an out-of-range apply (get returns
    // NULL), which would mint a signed, logged op that did nothing — refuse
    // the position pair up front against the live visible count.
    uint32_t visible_count = crabs_ot_ordered_set_visible_count(set);
    if (op_kind == CRABS_OT_OP_INSERT) {
      if (visible_pos > visible_count)
        throw crabs_error(env, CRABS_ERR_OT_POSITION_BOUNDS, ctx);
    } else {
      if (visible_count == 0)
        throw crabs_error(env, CRABS_ERR_OT_POSITION_BOUNDS, ctx);
      if (visible_pos > visible_count - 1)
        throw crabs_error(env, CRABS_ERR_OT_POSITION_BOUNDS, ctx);
      if ((op_kind == CRABS_OT_OP_MOVE || op_kind == CRABS_OT_OP_SWAP) &&
          visible_pos_2 > visible_count - 1)
        throw crabs_error(env, CRABS_ERR_OT_POSITION_BOUNDS, ctx);
    }

    crabs_ot_operation_t ot_op;
    crabs_ot_operation_init(&ot_op);
    ot_op.op_type = (crabs_ot_op_type_e)op_kind;
    ot_op.visible_pos = visible_pos;
    ot_op.visible_pos_2 = (op_kind == CRABS_OT_OP_MOVE ||
                           op_kind == CRABS_OT_OP_SWAP)
        ? visible_pos_2 : 0;
    crabs_ot_op_id_init(&ot_op.id, id_node.c_str(), id_sequence, id_timestamp);
    if (element != NULL && element_len > 0) {
      if (!crabs_ot_operation_set_payload(
              &ot_op, reinterpret_cast<const uint8_t*>(element), element_len)) {
        throw crabs_error(env, CRABS_ERR_INVALID_PARAM, ctx);
      }
    }
    for (const crabs_ot_op_id_t& dep : deps) {
      if (!crabs_ot_operation_add_dep(&ot_op, &dep)) {
        free(ot_op.payload);
        throw crabs_error(env, CRABS_ERR_INVALID_PARAM, ctx);
      }
    }

    std::vector<uint8_t> wire(4 + 4 + CRABS_MAX_USER_ID + 8 * 5 + 4 +
                              CRABS_OT_MAX_PAYLOAD + 4 +
                              CRABS_OT_MAX_DEPS * (CRABS_MAX_USER_ID + 8 + 8));
    uint32_t wire_size = crabs_ot_ops_to_wire(&ot_op, 1, wire.data(),
                                              (uint32_t)wire.size());
    free(ot_op.payload);
    if (wire_size == 0)
      throw crabs_error(env, CRABS_ERR_INTERNAL, ctx);

    if (node_key_ == nullptr)
      throw Napi::Error::New(env,
          std::string(ctx) + ": this machine carries no own node key");
    operation_t* op = operation_create(CRABS_OP_EXECUTE_OT);
    if (op == NULL) throw crabs_error(env, CRABS_ERR_OOM, ctx);
    operation_append_resource(op, name, env, ctx);
    op->payload = (uint8_t*)malloc(wire_size);
    if (op->payload == NULL) {
      operation_destroy(op);
      throw crabs_error(env, CRABS_ERR_OOM, ctx);
    }
    memcpy(op->payload, wire.data(), wire_size);
    op->payload_size = wire_size;
    crypto_random_bytes(op->uuid, CRABS_UUID_SIZE);
    strncpy(op->signer_id, admin_id_.c_str(), CRABS_MAX_USER_ID - 1);
    strncpy(op->node_id, admin_id_.c_str(), CRABS_MAX_USER_ID - 1);

    // Stamp the signer's current key version (R7-04) and HLC when the
    // machine is HLC-ordered, then sign — the same pre-sign stamping
    // node.sign() performs.
    if (am_->base_state.hlc_state_initialized) {
      op->ordering_system = CRABS_ORDERING_HLC;
      op->hlc = crabs_hlc_next(&am_->base_state.hlc_state);
      strncpy(op->node_id, am_->base_state.hlc_state.last.node_id,
              CRABS_MAX_USER_ID - 1);
    }
    user_t* signer_user = attribute_machine_find_user(am_, op->signer_id);
    if (signer_user != NULL) {
      op->signer_key_version = signer_user->key_version;
    }
    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
    if (ser == NULL) {
      operation_destroy(op);
      throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, ctx);
    }
    crabs_error_e rc = crypto_ecdsa_sign(node_key_->private_key, ser->data,
                                         ser->len, op->signature);
    serialized_buffer_destroy(ser);
    if (rc != CRABS_SUCCESS) {
      operation_destroy(op);
      throw crabs_error(env, rc, (std::string(ctx) + " sign").c_str());
    }

    rc = state_machine_execute(&am_->base_state, op);
    operation_destroy(op);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, ctx);
  }

  // Attach the op identity + causal deps from an { id, deps? } options bag
  // onto a composed OT op — the same contract the ordered-set sugar
  // validates inline (OrderedSetApply). Shared by the document and tree
  // appliers.
  void _ot_attach_identity(const Napi::CallbackInfo& info, Napi::Object options,
                           crabs_ot_operation_t* ot_op, const char* ctx) {
    Napi::Env env = info.Env();
    Napi::Object id = options.Get("id").As<Napi::Object>();
    std::string id_node = require_js_string(id.Get("node"), ctx, "id.node");
    if (id_node.empty() || id_node.length() >= CRABS_MAX_USER_ID)
      throw Napi::RangeError::New(env, std::string(ctx) +
          ": id.node must be 1..63 characters");
    uint64_t id_sequence = require_u64_numeric(id.Get("seq"), ctx, "id.seq");
    uint64_t id_timestamp = id.Has("ts") && !id.Get("ts").IsUndefined()
        ? require_u64_numeric(id.Get("ts"), ctx, "id.ts") : 0;
    crabs_ot_op_id_init(&ot_op->id, id_node.c_str(), id_sequence, id_timestamp);

    if (options.Has("deps") && !options.Get("deps").IsUndefined()) {
      if (!options.Get("deps").IsArray())
        throw Napi::TypeError::New(env,
            std::string(ctx) + ": deps must be an array of { node, seq, ts? }");
      Napi::Array raw_deps = options.Get("deps").As<Napi::Array>();
      if (raw_deps.Length() > CRABS_OT_MAX_DEPS)
        throw Napi::RangeError::New(env,
            std::string(ctx) + ": at most 16 causal deps per op");
      for (uint32_t dep_index = 0; dep_index < raw_deps.Length(); dep_index++) {
        Napi::Value raw_dep = raw_deps.Get(dep_index);
        if (!raw_dep.IsObject())
          throw Napi::TypeError::New(env,
              std::string(ctx) + ": each dep must be { node, seq, ts? }");
        Napi::Object dep = raw_dep.As<Napi::Object>();
        if (!dep.Has("node") || !dep.Get("node").IsString())
          throw Napi::TypeError::New(env,
              std::string(ctx) + ": dep node is required (string)");
        std::string dep_node = require_js_string(dep.Get("node"), ctx,
                                                 "dep.node");
        if (dep_node.empty() || dep_node.length() >= CRABS_MAX_USER_ID)
          throw Napi::RangeError::New(env,
              std::string(ctx) + ": dep node must be 1..63 characters");
        if (!dep.Has("seq"))
          throw Napi::TypeError::New(env,
              std::string(ctx) + ": dep \"" + dep_node + "\" needs integer seq");
        uint64_t dep_sequence = require_u64_numeric(dep.Get("seq"), ctx,
                                                    "dep.seq");
        uint64_t dep_timestamp = dep.Has("ts") && !dep.Get("ts").IsUndefined()
            ? require_u64_numeric(dep.Get("ts"), ctx, "dep.ts") : 0;
        crabs_ot_op_id_t dep_id;
        crabs_ot_op_id_init(&dep_id, dep_node.c_str(), dep_sequence,
                            dep_timestamp);
        if (!crabs_ot_operation_add_dep(ot_op, &dep_id)) {
          free(ot_op->payload);
          throw crabs_error(env, CRABS_ERR_INVALID_PARAM, ctx);
        }
      }
    }
  }

  // The options object's position varies by method (last arg) — resolve it
  // once here so OrderedSetApply receives the parsed object.
  static Napi::Object require_ordered_options(const Napi::CallbackInfo& info,
                                              uint32_t options_index,
                                              const char* ctx) {
    Napi::Env env = info.Env();
    if (info.Length() <= options_index || !info[options_index].IsObject())
      throw Napi::TypeError::New(env,
          std::string(ctx) +
          ": id is required — { node, seq, ts? } fixes the op's OT identity");
    return info[options_index].As<Napi::Object>();
  }

  Napi::Value OrderedInsert(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 4)
      throw Napi::TypeError::New(env,
          "Expected orderedInsert(name, element, position, options)");
    Napi::Object options = require_ordered_options(info, 3, "orderedInsert");
    std::string name = require_js_string(info[0], "orderedInsert", "name");
    std::string element = require_js_string(info[1], "orderedInsert", "element");
    if (element.size() > CRABS_OT_MAX_PAYLOAD)
      throw Napi::RangeError::New(env,
          "orderedInsert: element payload exceeds the 4096-byte OT limit");
    uint64_t position = require_u64_numeric(info[2], "orderedInsert", "position");
    OrderedSetApply(info, options, name, CRABS_OT_OP_INSERT, position, 0,
                    element.c_str(), (uint32_t)element.size(), "orderedInsert");
    return env.Undefined();
  }

  Napi::Value OrderedDelete(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3)
      throw Napi::TypeError::New(env, "Expected orderedDelete(name, position, options)");
    Napi::Object options = require_ordered_options(info, 2, "orderedDelete");
    std::string name = require_js_string(info[0], "orderedDelete", "name");
    uint64_t position = require_u64_numeric(info[1], "orderedDelete", "position");
    OrderedSetApply(info, options, name, CRABS_OT_OP_DELETE, position, 0,
                    NULL, 0, "orderedDelete");
    return env.Undefined();
  }

  Napi::Value OrderedMove(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 4)
      throw Napi::TypeError::New(env,
          "Expected orderedMove(name, fromPosition, toPosition, options)");
    Napi::Object options = require_ordered_options(info, 3, "orderedMove");
    std::string name = require_js_string(info[0], "orderedMove", "name");
    uint64_t from_position = require_u64_numeric(info[1], "orderedMove",
                                                 "fromPosition");
    uint64_t to_position = require_u64_numeric(info[2], "orderedMove",
                                               "toPosition");
    OrderedSetApply(info, options, name, CRABS_OT_OP_MOVE, from_position,
                    to_position, NULL, 0, "orderedMove");
    return env.Undefined();
  }

  Napi::Value OrderedSwap(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 4)
      throw Napi::TypeError::New(env,
          "Expected orderedSwap(name, positionA, positionB, options)");
    Napi::Object options = require_ordered_options(info, 3, "orderedSwap");
    std::string name = require_js_string(info[0], "orderedSwap", "name");
    uint64_t position_a = require_u64_numeric(info[1], "orderedSwap",
                                              "positionA");
    uint64_t position_b = require_u64_numeric(info[2], "orderedSwap",
                                              "positionB");
    OrderedSetApply(info, options, name, CRABS_OT_OP_SWAP, position_a,
                    position_b, NULL, 0, "orderedSwap");
    return env.Undefined();
  }

  // ============================================================
  // OT document (OT_DOCUMENT, v1.5 §6) + OT tree (v1.5 §7) — parity-fill P6
  //
  // PRESENT but EXPLICITLY UNBLESSED: the document/tree op paths are real
  // (the __execute_ot__ executor routes both item types through
  // crabs_apply_ot_op) and now bound, but never benchmarked — the O(N) ops
  // cost of document-style concurrency is a design-table claim, not a
  // measured property, and the priority tie-break's generator
  // (crabs_ot_data_item_next_priority) has no production caller
  // (binding-composed ops carry priority 0; the transform's tie-break
  // falls back to the (node_id, seq) total order). NEITHER type has a
  // merge function: a mergeState of one of their snapshots is HELD
  // (__merge_held__, CRABS_ERR_TYPE_MISMATCH 0x3004) and the item does not
  // land. Do not build rich text on this until a benchmark exists.
  // ============================================================

  Napi::Value AddOTDocument(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addOTDocument", "name");
    data_item_t* item = data_item_create(name.c_str(),
        DATA_TYPE_OT_DOCUMENT, CRDT_CUSTOM);
    if (!item) throw crabs_error(env, CRABS_ERR_OOM, "addOTDocument");
    crabs_ot_document_t* doc = crabs_ot_document_create();
    item->value = doc;
    if (!doc) {
      data_item_destroy(item);  // NULL value: destroy is safe on every field
      throw crabs_error(env, CRABS_ERR_OOM, "addOTDocument");
    }
    item->ot_data = doc->ot_data;
    // Struct-backed value (crabs_ot_document_t) — data_item_destroy
    // dispatches OT destruction by type.
    item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    // A failure here (e.g. duplicate_operation) leaves the item uninserted
    // — destroy it before throwing or the item, its struct value and its
    // ot_data all leak (mirrors AddOrderedSet's failure path).
    if (rc != CRABS_SUCCESS) {
      data_item_destroy(item);
      throw crabs_error(env, rc, "addOTDocument");
    }
    return env.Undefined();
  }

  // Readback of one OT document: text — the visible characters in document
  // order concatenated; spans — one record per VISIBLE span (tombstones
  // skipped), each { text, styles: [{ name, value }...] }; charCount — the
  // live visible character count (a byte count in C).
  Napi::Value GetOTDocument(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "getOTDocument", "name");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item || item->type != DATA_TYPE_OT_DOCUMENT)
      throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "getOTDocument");
    crabs_ot_document_t* doc = (crabs_ot_document_t*)item->value;
    if (!doc) throw crabs_error(env, CRABS_ERR_INTERNAL, "getOTDocument");

    Napi::Array spans = Napi::Array::New(env);
    std::string text;
    uint64_t char_count = 0;
    uint32_t span_position = 0;
    for (crabs_span_t* span = doc->head; span != NULL; span = span->next) {
      if (span->deleted) continue;
      std::string span_text = span->text == NULL || span->text_size == 0
          ? std::string("")
          : std::string(reinterpret_cast<const char*>(span->text),
                        span->text_size);
      Napi::Object span_obj = Napi::Object::New(env);
      span_obj.Set("text", Napi::String::New(env, span_text));
      Napi::Array styles = Napi::Array::New(env);
      for (uint32_t style_index = 0; style_index < span->style_count;
           style_index++) {
        Napi::Object style_obj = Napi::Object::New(env);
        style_obj.Set("name", Napi::String::New(env, span->styles[style_index].name));
        style_obj.Set("value", Napi::String::New(env, span->styles[style_index].value));
        styles.Set(style_index, style_obj);
      }
      span_obj.Set("styles", styles);
      spans.Set(span_position++, span_obj);
      text += span_text;
      char_count += span->text_size;
    }
    Napi::Object result = Napi::Object::New(env);
    result.Set("text", Napi::String::New(env, text));
    result.Set("spans", spans);
    // Number-typed like the other count readbacks (double loses precision
    // past 2^53 bytes — no realistic document does).
    result.Set("charCount", Napi::Number::New(env, (double)char_count));
    return result;
  }

  // Position validation + type gate for the document op sugars: mirrors the
  // wasm exporter (src/Util/wasm_helpers.c crabs_wasm_ot_document_apply) —
  // nothing is signed for an out-of-range or otherwise no-op apply.
  crabs_ot_document_t* OtDocumentGate(
      const Napi::CallbackInfo& info, const std::string& name,
      const char* ctx) {
    Napi::Env env = info.Env();
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, ctx);
    if (item->type != DATA_TYPE_OT_DOCUMENT)
      throw crabs_error(env, CRABS_ERR_NOT_OT_TYPE, ctx);
    crabs_ot_document_t* doc = (crabs_ot_document_t*)item->value;
    if (!doc) throw crabs_error(env, CRABS_ERR_INTERNAL, ctx);
    return doc;
  }

  uint64_t OtDocumentCharCount(crabs_ot_document_t* doc) {
    uint64_t char_count = 0;
    for (crabs_span_t* span = doc->head; span != NULL; span = span->next) {
      if (!span->deleted) char_count += span->text_size;
    }
    return char_count;
  }

  uint64_t OtDocumentVisibleSpanCount(crabs_ot_document_t* doc) {
    uint64_t span_count = 0;
    for (crabs_span_t* span = doc->head; span != NULL; span = span->next) {
      if (!span->deleted) span_count++;
    }
    return span_count;
  }

  // Validate the document op args against the LIVE document and compose the
  // crabs_ot_operation_t the executor parses (crabs_apply_ot_op's
  // DATA_TYPE_OT_DOCUMENT cases).
  crabs_ot_operation_t OtDocumentCompose(
      const Napi::CallbackInfo& info, Napi::Object options,
      const std::string& name, uint32_t op_kind, uint64_t pos, uint64_t pos2,
      const std::string& text, const std::string& style_name,
      const std::string& style_value, const char* ctx) {
    Napi::Env env = info.Env();
    crabs_ot_document_t* doc = OtDocumentGate(info, name, ctx);
    uint64_t char_count = OtDocumentCharCount(doc);

    if (op_kind != CRABS_OT_OP_INSERT_TEXT && op_kind != CRABS_OT_OP_DELETE_RANGE &&
        op_kind != CRABS_OT_OP_STYLE && op_kind != CRABS_OT_OP_MERGE_SPANS &&
        op_kind != CRABS_OT_OP_SPLIT_SPAN) {
      throw Napi::TypeError::New(env, std::string(ctx) + ": unknown op.kind");
    }
    if (text.size() > CRABS_OT_MAX_PAYLOAD) {
      throw Napi::RangeError::New(env,
          std::string(ctx) +
          ": text payload exceeds the 4096-byte OT limit");
    }

    crabs_ot_operation_t ot_op;
    crabs_ot_operation_init(&ot_op);
    ot_op.op_type = (crabs_ot_op_type_e)op_kind;
    ot_op.visible_pos = pos;
    uint8_t style_payload[sizeof(crabs_style_t)];

    switch (op_kind) {
      case CRABS_OT_OP_INSERT_TEXT: {
        if (pos > char_count)
          throw crabs_error(env, CRABS_ERR_OT_POSITION_BOUNDS, ctx);
        if (text.empty()) {
          throw Napi::TypeError::New(env,
              std::string(ctx) + ": text must be 1..4096 bytes");
        }
        break;
      }
      case CRABS_OT_OP_DELETE_RANGE: {
        if (pos2 == 0 || pos > char_count || pos2 > char_count ||
            pos + pos2 > char_count)
          throw crabs_error(env, CRABS_ERR_OT_POSITION_BOUNDS, ctx);
        ot_op.visible_pos_2 = pos2;
        break;
      }
      case CRABS_OT_OP_STYLE: {
        if (style_name.empty() || style_name.size() >= CRABS_STYLE_NAME_MAX) {
          throw Napi::RangeError::New(env,
              std::string(ctx) + ": style.name must be 1..31 characters");
        }
        if (style_value.size() >= CRABS_STYLE_VALUE_MAX) {
          throw Napi::RangeError::New(env,
              std::string(ctx) + ": style.value must be at most 63 characters");
        }
        if (pos2 == 0 || pos > char_count || pos2 > char_count ||
            pos + pos2 > char_count)
          throw crabs_error(env, CRABS_ERR_OT_POSITION_BOUNDS, ctx);
        ot_op.visible_pos_2 = pos2;
        memset(style_payload, 0, sizeof(style_payload));
        strncpy(reinterpret_cast<char*>(style_payload), style_name.c_str(),
                CRABS_STYLE_NAME_MAX - 1);
        if (!style_value.empty()) {
          strncpy(reinterpret_cast<char*>(style_payload) + CRABS_STYLE_NAME_MAX,
                  style_value.c_str(), CRABS_STYLE_VALUE_MAX - 1);
        }
        if (!crabs_ot_operation_set_payload(&ot_op, style_payload,
                                            sizeof(style_payload))) {
          throw crabs_error(env, CRABS_ERR_INVALID_PARAM, ctx);
        }
        return ot_op;
      }
      case CRABS_OT_OP_MERGE_SPANS: {
        uint64_t span_count = OtDocumentVisibleSpanCount(doc);
        if (pos >= span_count || pos2 >= span_count || pos == pos2) {
          throw crabs_error(env, CRABS_ERR_OT_POSITION_BOUNDS, ctx);
        }
        ot_op.visible_pos_2 = pos2;
        break;
      }
      case CRABS_OT_OP_SPLIT_SPAN: {
        // A split at a span boundary (offset 0 within its span) or past the
        // end is a silent no-op in the C op — refuse before anything is
        // signed.
        uint64_t remaining = pos;
        uint32_t offset = 0;
        bool inside = false;
        for (crabs_span_t* span = doc->head; span != NULL; span = span->next) {
          if (span->deleted) continue;
          if (remaining < span->text_size) {
            offset = (uint32_t)remaining;
            inside = true;
            break;
          }
          remaining -= span->text_size;
        }
        if (!inside || offset == 0) {
          throw crabs_error(env, CRABS_ERR_OT_POSITION_BOUNDS, ctx);
        }
        break;
      }
      default:
        break;
    }

    if (!text.empty() && op_kind == CRABS_OT_OP_INSERT_TEXT) {
      if (!crabs_ot_operation_set_payload(
              &ot_op, reinterpret_cast<const uint8_t*>(text.data()),
              (uint32_t)text.size())) {
        throw crabs_error(env, CRABS_ERR_INVALID_PARAM, ctx);
      }
    }
    return ot_op;
  }

  // Compose, node-key-sign and execute ONE OT op through the machine
  // executor — the tail shared by the document and tree appliers (the
  // ordered-set sugar OrderedSetApply carries its own copy of this).
  void OtOpExecute(const Napi::CallbackInfo& info, const char* ctx,
                   const std::string& name, crabs_ot_operation_t* ot_op) {
    Napi::Env env = info.Env();
    std::vector<uint8_t> wire(4 + 4 + CRABS_MAX_USER_ID + 8 * 5 + 4 +
                              CRABS_OT_MAX_PAYLOAD + 4 +
                              CRABS_OT_MAX_DEPS * (CRABS_MAX_USER_ID + 8 + 8));
    uint32_t wire_size = crabs_ot_ops_to_wire(ot_op, 1, wire.data(),
                                              (uint32_t)wire.size());
    free(ot_op->payload);
    ot_op->payload = NULL;
    if (wire_size == 0)
      throw crabs_error(env, CRABS_ERR_INTERNAL, ctx);

    if (node_key_ == nullptr)
      throw Napi::Error::New(env,
          std::string(ctx) + ": this machine carries no own node key");
    operation_t* op = operation_create(CRABS_OP_EXECUTE_OT);
    if (op == NULL) throw crabs_error(env, CRABS_ERR_OOM, ctx);
    operation_append_resource(op, name, env, ctx);
    op->payload = (uint8_t*)malloc(wire_size);
    if (op->payload == NULL) {
      operation_destroy(op);
      throw crabs_error(env, CRABS_ERR_OOM, ctx);
    }
    memcpy(op->payload, wire.data(), wire_size);
    op->payload_size = wire_size;
    crypto_random_bytes(op->uuid, CRABS_UUID_SIZE);
    strncpy(op->signer_id, admin_id_.c_str(), CRABS_MAX_USER_ID - 1);
    strncpy(op->node_id, admin_id_.c_str(), CRABS_MAX_USER_ID - 1);

    // Stamp the signer's current key version (R7-04) and HLC when the
    // machine is HLC-ordered, then sign — the same pre-sign stamping
    // node.sign() performs.
    if (am_->base_state.hlc_state_initialized) {
      op->ordering_system = CRABS_ORDERING_HLC;
      op->hlc = crabs_hlc_next(&am_->base_state.hlc_state);
      strncpy(op->node_id, am_->base_state.hlc_state.last.node_id,
              CRABS_MAX_USER_ID - 1);
    }
    user_t* signer_user = attribute_machine_find_user(am_, op->signer_id);
    if (signer_user != NULL) {
      op->signer_key_version = signer_user->key_version;
    }
    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
    if (ser == NULL) {
      operation_destroy(op);
      throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, ctx);
    }
    crabs_error_e rc = crypto_ecdsa_sign(node_key_->private_key, ser->data,
                                         ser->len, op->signature);
    serialized_buffer_destroy(ser);
    if (rc != CRABS_SUCCESS) {
      operation_destroy(op);
      throw crabs_error(env, rc, (std::string(ctx) + " sign").c_str());
    }

    rc = state_machine_execute(&am_->base_state, op);
    operation_destroy(op);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, ctx);
  }

  // The doc/tree apply driver: identity from the options bag (the ordered-
  // set contract), compose against the live item, execute through the
  // machine.
  void OtDocumentExecute(const Napi::CallbackInfo& info, Napi::Object options,
                         const std::string& name, uint32_t op_kind,
                         uint64_t pos, uint64_t pos2,
                         const std::string& text,
                         const std::string& style_name,
                         const std::string& style_value, const char* ctx) {
    crabs_ot_operation_t ot_op = OtDocumentCompose(info, options, name,
        op_kind, pos, pos2, text, style_name, style_value, ctx);
    _ot_attach_identity(info, options, &ot_op, ctx);
    OtOpExecute(info, ctx, name, &ot_op);  // frees the op's payload itself
  }

  Napi::Value OtInsertText(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 4 || !info[3].IsObject())
      throw Napi::TypeError::New(env,
          "Expected otInsertText(name, position, text, options)");
    Napi::Object options = require_ordered_options(info, 3, "otInsertText");
    std::string name = require_js_string(info[0], "otInsertText", "name");
    uint64_t position = require_u64_numeric(info[1], "otInsertText", "position");
    std::string text = require_js_string(info[2], "otInsertText", "text");
    if (text.empty())
      throw Napi::TypeError::New(env, "otInsertText: text must be 1..4096 bytes");
    OtDocumentExecute(info, options, name, CRABS_OT_OP_INSERT_TEXT, position,
                      0, text, "", "", "otInsertText");
    return env.Undefined();
  }

  Napi::Value OtDeleteRange(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 4 || !info[3].IsObject())
      throw Napi::TypeError::New(env,
          "Expected otDeleteRange(name, position, length, options)");
    Napi::Object options = require_ordered_options(info, 3, "otDeleteRange");
    std::string name = require_js_string(info[0], "otDeleteRange", "name");
    uint64_t position = require_u64_numeric(info[1], "otDeleteRange", "position");
    uint64_t length = require_u64_numeric(info[2], "otDeleteRange", "length");
    OtDocumentExecute(info, options, name, CRABS_OT_OP_DELETE_RANGE, position,
                      length, "", "", "", "otDeleteRange");
    return env.Undefined();
  }

  Napi::Value OtApplyStyle(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 5 || !info[4].IsObject())
      throw Napi::TypeError::New(env,
          "Expected otApplyStyle(name, position, length, style, options)");
    Napi::Object options = require_ordered_options(info, 4, "otApplyStyle");
    std::string name = require_js_string(info[0], "otApplyStyle", "name");
    uint64_t position = require_u64_numeric(info[1], "otApplyStyle", "position");
    uint64_t length = require_u64_numeric(info[2], "otApplyStyle", "length");
    if (!info[3].IsObject())
      throw Napi::TypeError::New(env,
          "otApplyStyle: style is required — { name: string, value?: string }");
    Napi::Object style = info[3].As<Napi::Object>();
    if (!style.Has("name") || !style.Get("name").IsString())
      throw Napi::TypeError::New(env,
          "otApplyStyle: style.name must be a string");
    std::string style_name = require_js_string(style.Get("name"),
        "otApplyStyle", "style.name");
    if (style_name.empty())
      throw Napi::RangeError::New(env,
          "otApplyStyle: style.name must be 1..31 characters");
    std::string style_value = style.Has("value") &&
        style.Get("value").IsString()
        ? require_js_string(style.Get("value"), "otApplyStyle", "style.value")
        : std::string("");
    OtDocumentExecute(info, options, name, CRABS_OT_OP_STYLE, position,
                      length, "", style_name, style_value, "otApplyStyle");
    return env.Undefined();
  }

  Napi::Value OtMergeSpans(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 4 || !info[3].IsObject())
      throw Napi::TypeError::New(env,
          "Expected otMergeSpans(name, spanPositionA, spanPositionB, options)");
    Napi::Object options = require_ordered_options(info, 3, "otMergeSpans");
    std::string name = require_js_string(info[0], "otMergeSpans", "name");
    uint64_t position_a = require_u64_numeric(info[1], "otMergeSpans",
                                              "spanPositionA");
    uint64_t position_b = require_u64_numeric(info[2], "otMergeSpans",
                                              "spanPositionB");
    OtDocumentExecute(info, options, name, CRABS_OT_OP_MERGE_SPANS, position_a,
                      position_b, "", "", "", "otMergeSpans");
    return env.Undefined();
  }

  Napi::Value OtSplitSpan(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3 || !info[2].IsObject())
      throw Napi::TypeError::New(env,
          "Expected otSplitSpan(name, position, options)");
    Napi::Object options = require_ordered_options(info, 2, "otSplitSpan");
    std::string name = require_js_string(info[0], "otSplitSpan", "name");
    uint64_t position = require_u64_numeric(info[1], "otSplitSpan", "position");
    OtDocumentExecute(info, options, name, CRABS_OT_OP_SPLIT_SPAN, position,
                      0, "", "", "", "otSplitSpan");
    return env.Undefined();
  }

  // Sugar-level option validation shared by the generic routers below:
  // throws unless options carries a well-formed id (+ optional deps).
  void OtRequireOpOptions(const Napi::CallbackInfo& info, Napi::Object options,
                          const char* ctx) {
    if (!options.Has("id") ||
        !options.Get("id").IsObject()) {
      throw Napi::TypeError::New(info.Env(),
          std::string(ctx) +
          ": id is required — { node, seq, ts? } fixes the op's OT identity");
    }
    Napi::Object id = options.Get("id").As<Napi::Object>();
    if (!id.Has("node") || !id.Get("node").IsString() ||
        id.Get("node").As<Napi::String>().Utf8Value().empty()) {
      throw Napi::TypeError::New(info.Env(),
          std::string(ctx) +
          ": id.node is required (string, the issuing replica's id)");
    }
    if (!id.Has("seq")) {
      throw Napi::TypeError::New(info.Env(),
          std::string(ctx) +
          ": id.seq is required (integer >= 0, unique per id.node)");
    }
    require_u64_numeric(id.Get("seq"), ctx, "id.seq");
    if (id.Has("ts") && !id.Get("ts").IsUndefined())
      require_u64_numeric(id.Get("ts"), ctx, "id.ts");
  }

  // The generic document-op route: op = { kind, position, length?, text?,
  // style?, id, deps? } — kind is one of 'insertText' | 'deleteRange' |
  // 'applyStyle' | 'mergeSpans' | 'splitSpan'.
  Napi::Value OtDocumentApply(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsObject())
      throw Napi::TypeError::New(env,
          "Expected otDocumentApply(name, op)");
    std::string name = require_js_string(info[0], "otDocumentApply", "name");
    Napi::Object op = info[1].As<Napi::Object>();
    if (!op.Has("kind") || !op.Get("kind").IsString())
      throw Napi::TypeError::New(env, "otDocumentApply: op.kind is required");
    std::string kind = to_lower_ascii(op.Get("kind").As<Napi::String>().Utf8Value());
    OtRequireOpOptions(info, op, "otDocumentApply");

    if (kind == "inserttext") {
      if (!op.Has("text") || !op.Get("text").IsString())
        throw Napi::TypeError::New(env, "otDocumentApply: text is required");
      OtDocumentExecute(info, op, name, CRABS_OT_OP_INSERT_TEXT,
          require_u64_numeric(op.Get("position"), "otDocumentApply", "position"),
          0, require_js_string(op.Get("text"), "otDocumentApply", "text"),
          "", "", "otDocumentApply");
    } else if (kind == "deleterange") {
      OtDocumentExecute(info, op, name, CRABS_OT_OP_DELETE_RANGE,
          require_u64_numeric(op.Get("position"), "otDocumentApply", "position"),
          require_u64_numeric(op.Get("length"), "otDocumentApply", "length"),
          "", "", "", "otDocumentApply");
    } else if (kind == "applystyle") {
      if (!op.Has("style") || !op.Get("style").IsObject())
        throw Napi::TypeError::New(env,
            "otDocumentApply: style is required — { name: string, value?: string }");
      Napi::Object style = op.Get("style").As<Napi::Object>();
      if (!style.Has("name") || !style.Get("name").IsString())
        throw Napi::TypeError::New(env,
            "otDocumentApply: style.name must be a string");
      std::string style_name = require_js_string(style.Get("name"),
          "otDocumentApply", "style.name");
      std::string style_value = style.Has("value") &&
          style.Get("value").IsString()
          ? require_js_string(style.Get("value"), "otDocumentApply",
                              "style.value") : std::string("");
      OtDocumentExecute(info, op, name, CRABS_OT_OP_STYLE,
          require_u64_numeric(op.Get("position"), "otDocumentApply", "position"),
          require_u64_numeric(op.Get("length"), "otDocumentApply", "length"),
          "", style_name, style_value, "otDocumentApply");
    } else if (kind == "mergespans") {
      OtDocumentExecute(info, op, name, CRABS_OT_OP_MERGE_SPANS,
          require_u64_numeric(op.Get("position"), "otDocumentApply", "position"),
          require_u64_numeric(op.Get("second"), "otDocumentApply", "second"),
          "", "", "", "otDocumentApply");
    } else if (kind == "splitspan") {
      OtDocumentExecute(info, op, name, CRABS_OT_OP_SPLIT_SPAN,
          require_u64_numeric(op.Get("position"), "otDocumentApply", "position"),
          0, "", "", "", "otDocumentApply");
    } else {
      throw Napi::TypeError::New(env, "otDocumentApply: unknown op.kind");
    }
    return env.Undefined();
  }

  // ============================================================
  // OT tree (OT_TREE, v1.5 §7) — same unblessed caveat as the document
  // ============================================================

  Napi::Value AddOTTree(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addOTTree", "name");
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_OT_TREE,
                                         CRDT_CUSTOM);
    if (!item) throw crabs_error(env, CRABS_ERR_OOM, "addOTTree");
    crabs_ot_tree_t* tree = crabs_ot_tree_create();
    item->value = tree;
    if (!tree) {
      data_item_destroy(item);  // NULL value: destroy is safe on every field
      throw crabs_error(env, CRABS_ERR_OOM, "addOTTree");
    }
    item->ot_data = tree->ot_data;
    // Struct-backed value (crabs_ot_tree_t) — data_item_destroy
    // dispatches OT destruction by type.
    item->value_repr = DATA_VALUE_REPR_CRDT_STRUCT;
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) {
      data_item_destroy(item);
      throw crabs_error(env, rc, "addOTTree");
    }
    return env.Undefined();
  }

  // Readback of one OT tree: nodes — every VISIBLE node in DFS order
  // (roots first, then each node's children left to right; a tombstoned
  // subtree is skipped wholesale), each { id, parentId, value, childIds }.
  // An empty parentId marks a root; the array order IS the sibling order.
  Napi::Value GetOTTree(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "getOTTree", "name");
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item || item->type != DATA_TYPE_OT_TREE)
      throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "getOTTree");
    crabs_ot_tree_t* tree = (crabs_ot_tree_t*)item->value;
    if (!tree) throw crabs_error(env, CRABS_ERR_INTERNAL, "getOTTree");

    // DFS over the root chain + children with an explicit worklist
    // (children pushed in reverse so the leftmost pops first) — deep or
    // attacker-shaped trees must not overflow the C++ stack.
    std::vector<crabs_tree_node_t*> stack;
    std::vector<crabs_tree_node_t*> roots;
    for (crabs_tree_node_t* root = tree->root; root != NULL;
         root = root->next_sibling) {
      roots.push_back(root);
    }
    for (size_t reverse_index = roots.size(); reverse_index-- > 0;) {
      stack.push_back(roots[reverse_index]);
    }

    Napi::Array nodes = Napi::Array::New(env);
    uint32_t node_position = 0;
    while (!stack.empty()) {
      crabs_tree_node_t* node = stack.back();
      stack.pop_back();
      if (node->deleted) continue;

      Napi::Object node_obj = Napi::Object::New(env);
      node_obj.Set("id", Napi::String::New(env, node->id));
      node_obj.Set("parentId", Napi::String::New(env, node->parent_id));
      node_obj.Set("value",
          node->value == NULL || node->value_size == 0
              ? Napi::String::New(env, "")
              : Napi::String::New(env,
                  reinterpret_cast<const char*>(node->value),
                  node->value_size));
      // childIds in sibling order — the node's own position among its
      // siblings is this record's index relative to equal-parent records.
      Napi::Array child_ids = Napi::Array::New(env);
      std::vector<crabs_tree_node_t*> children;
      for (crabs_tree_node_t* child = node->first_child; child != NULL;
           child = child->next_sibling) {
        if (!child->deleted) children.push_back(child);
      }
      for (size_t child_index = 0; child_index < children.size();
           child_index++) {
        child_ids.Set(child_index,
            Napi::String::New(env, children[child_index]->id));
        stack.push_back(children[children.size() - 1 - child_index]);
      }
      node_obj.Set("childIds", child_ids);
      nodes.Set(node_position++, node_obj);
    }
    Napi::Object result = Napi::Object::New(env);
    result.Set("nodes", nodes);
    return result;
  }

  crabs_ot_tree_t* OtTreeGate(const Napi::CallbackInfo& info,
                              const std::string& name, const char* ctx) {
    Napi::Env env = info.Env();
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, ctx);
    if (item->type != DATA_TYPE_OT_TREE)
      throw crabs_error(env, CRABS_ERR_NOT_OT_TYPE, ctx);
    crabs_ot_tree_t* tree = (crabs_ot_tree_t*)item->value;
    if (!tree) throw crabs_error(env, CRABS_ERR_INTERNAL, ctx);
    return tree;
  }

  // Compose the tree op against the live tree (crabs_apply_ot_op's
  // DATA_TYPE_OT_TREE cases) — same no-silent-noop discipline as the wasm
  // exporter: unknown/duplicate ids and no-op applies are refused BEFORE
  // anything is signed.
  crabs_ot_operation_t OtTreeCompose(
      const Napi::CallbackInfo& info, const std::string& name, uint32_t op_kind,
      uint64_t pos, const std::string& node_id, const std::string& parent_id,
      const std::string& value, const char* ctx) {
    Napi::Env env = info.Env();
    crabs_ot_tree_t* tree = OtTreeGate(info, name, ctx);

    if (node_id.empty() || node_id.size() >= CRABS_TREE_NODE_ID_MAX)
      throw Napi::RangeError::New(env,
          std::string(ctx) + ": nodeId must be 1..63 characters");
    if (parent_id.size() >= CRABS_TREE_NODE_ID_MAX)
      throw Napi::RangeError::New(env,
          std::string(ctx) + ": parentId must be at most 63 characters");
    if (value.size() >
        CRABS_OT_MAX_PAYLOAD - 2 * CRABS_TREE_NODE_ID_MAX)
      throw Napi::RangeError::New(env,
          std::string(ctx) +
          ": node value payload exceeds the 3968-byte OT limit");

    crabs_ot_operation_t ot_op;
    crabs_ot_operation_init(&ot_op);
    ot_op.op_type = (crabs_ot_op_type_e)op_kind;
    ot_op.visible_pos = pos;
    std::vector<uint8_t> payload(2 * CRABS_TREE_NODE_ID_MAX + value.size(), 0);
    uint32_t payload_size = 2 * CRABS_TREE_NODE_ID_MAX;

    switch (op_kind) {
      case CRABS_OT_OP_INSERT_NODE: {
        if (crabs_ot_tree_find(tree, node_id.c_str()) != NULL) {
          // A duplicate id would mint a second pool node the find-by-id
          // surface can never address — the wasm exporter refuses with the
          // typed invalid_param (crabs_wasm_ot_tree_apply); mirror it.
          throw crabs_error(env, CRABS_ERR_INVALID_PARAM, ctx);
        }
        // The executor maps an EMPTY parent to a NULL parent (a root).
        if (parent_id.empty()) {
          uint64_t sibling_count = 0;
          for (crabs_tree_node_t* root_node = tree->root; root_node != NULL;
               root_node = root_node->next_sibling) {
            if (!root_node->deleted) sibling_count++;
          }
          if (pos > sibling_count)
            throw crabs_error(env, CRABS_ERR_OT_POSITION_BOUNDS, ctx);
        } else {
          crabs_tree_node_t* parent_node =
              crabs_ot_tree_find(tree, parent_id.c_str());
          if (parent_node == NULL)
            throw crabs_error(env, CRABS_ERR_INVALID_PARAM, ctx);
          uint64_t sibling_count = 0;
          for (crabs_tree_node_t* child = parent_node->first_child;
               child != NULL; child = child->next_sibling) {
            if (!child->deleted) sibling_count++;
          }
          if (pos > sibling_count)
            throw crabs_error(env, CRABS_ERR_OT_POSITION_BOUNDS, ctx);
          memcpy(payload.data(), parent_id.c_str(), parent_id.size());
        }
        memcpy(payload.data() + CRABS_TREE_NODE_ID_MAX, node_id.c_str(),
               node_id.size());
        if (!value.empty()) {
          memcpy(payload.data() + payload_size, value.data(), value.size());
          payload_size += (uint32_t)value.size();
        }
        break;
      }
      case CRABS_OT_OP_DELETE_NODE: {
        crabs_tree_node_t* doomed = crabs_ot_tree_find(tree, node_id.c_str());
        if (doomed == NULL || doomed->deleted)
          throw crabs_error(env, CRABS_ERR_INVALID_PARAM, ctx);
        memcpy(payload.data(), node_id.c_str(), node_id.size());
        payload_size = CRABS_TREE_NODE_ID_MAX;
        break;
      }
      case CRABS_OT_OP_REPARENT: {
        crabs_tree_node_t* moved = crabs_ot_tree_find(tree, node_id.c_str());
        if (moved == NULL || moved->deleted)
          throw crabs_error(env, CRABS_ERR_INVALID_PARAM, ctx);
        bool to_root = parent_id.empty();
        crabs_tree_node_t* new_parent = NULL;
        if (!to_root) {
          new_parent = crabs_ot_tree_find(tree, parent_id.c_str());
          if (new_parent == NULL)
            throw crabs_error(env, CRABS_ERR_INVALID_PARAM, ctx);
          // Mirror the C cycle check (a cycle returns NULL = a signed
          // no-op): the new parent must not be the node or its descendant.
          if (new_parent == moved)
            throw crabs_error(env, CRABS_ERR_INVALID_PARAM, ctx);
          uint32_t steps = 0;
          crabs_tree_node_t* ancestor = new_parent->parent;
          while (ancestor != NULL && steps <= tree->node_count) {
            if (ancestor == moved)
              throw crabs_error(env, CRABS_ERR_INVALID_PARAM, ctx);
            ancestor = ancestor->parent;
            steps++;
          }
        }
        if (to_root) {
          uint64_t sibling_count = 0;
          for (crabs_tree_node_t* root_node = tree->root; root_node != NULL;
               root_node = root_node->next_sibling) {
            if (!root_node->deleted) sibling_count++;
          }
          if (pos > sibling_count)
            throw crabs_error(env, CRABS_ERR_OT_POSITION_BOUNDS, ctx);
        } else {
          uint64_t sibling_count = 0;
          for (crabs_tree_node_t* child = new_parent->first_child;
               child != NULL; child = child->next_sibling) {
            if (!child->deleted) sibling_count++;
          }
          if (pos > sibling_count)
            throw crabs_error(env, CRABS_ERR_OT_POSITION_BOUNDS, ctx);
          memcpy(payload.data() + CRABS_TREE_NODE_ID_MAX, parent_id.c_str(),
                 parent_id.size());
        }
        memcpy(payload.data(), node_id.c_str(), node_id.size());
        payload_size = 2 * CRABS_TREE_NODE_ID_MAX;
        break;
      }
      case CRABS_OT_OP_REORDER: {
        crabs_tree_node_t* moved = crabs_ot_tree_find(tree, node_id.c_str());
        if (moved == NULL || moved->deleted ||
            moved->parent == NULL)  // the C op refuses root-level nodes
          throw crabs_error(env, CRABS_ERR_INVALID_PARAM, ctx);
        uint64_t sibling_count = 0;
        for (crabs_tree_node_t* sibling = moved->parent->first_child;
             sibling != NULL; sibling = sibling->next_sibling) {
          if (!sibling->deleted) sibling_count++;
        }
        if (pos > sibling_count)
          throw crabs_error(env, CRABS_ERR_OT_POSITION_BOUNDS, ctx);
        memcpy(payload.data(), node_id.c_str(), node_id.size());
        payload_size = CRABS_TREE_NODE_ID_MAX;
        break;
      }
      default:
        throw Napi::TypeError::New(env, std::string(ctx) + ": unknown op.kind");
    }

    if (!crabs_ot_operation_set_payload(&ot_op, payload.data(), payload_size))
      throw crabs_error(env, CRABS_ERR_INVALID_PARAM, ctx);
    return ot_op;
  }

  void OtTreeExecute(const Napi::CallbackInfo& info, Napi::Object options,
                     const std::string& name, uint32_t op_kind, uint64_t pos,
                     const std::string& node_id, const std::string& parent_id,
                     const std::string& value, const char* ctx) {
    crabs_ot_operation_t ot_op = OtTreeCompose(info, name, op_kind, pos,
        node_id, parent_id, value, ctx);
    _ot_attach_identity(info, options, &ot_op, ctx);
    OtOpExecute(info, ctx, name, &ot_op);
  }

  Napi::Value OtInsertNode(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 6 || !info[5].IsObject())
      throw Napi::TypeError::New(env,
          "Expected otInsertNode(name, parentId, position, nodeId, value, options)");
    Napi::Object options = require_ordered_options(info, 5, "otInsertNode");
    std::string name = require_js_string(info[0], "otInsertNode", "name");
    std::string parent_id = info[1].IsString()
        ? require_js_string(info[1], "otInsertNode", "parentId")
        : std::string("");
    uint64_t position = require_u64_numeric(info[2], "otInsertNode", "position");
    std::string node_id = require_js_string(info[3], "otInsertNode", "nodeId");
    std::string value = info[4].IsString()
        ? require_js_string(info[4], "otInsertNode", "value")
        : std::string("");
    OtTreeExecute(info, options, name, CRABS_OT_OP_INSERT_NODE, position,
                  node_id, parent_id, value, "otInsertNode");
    return env.Undefined();
  }

  Napi::Value OtDeleteNode(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3 || !info[2].IsObject())
      throw Napi::TypeError::New(env,
          "Expected otDeleteNode(name, nodeId, options)");
    Napi::Object options = require_ordered_options(info, 2, "otDeleteNode");
    std::string name = require_js_string(info[0], "otDeleteNode", "name");
    std::string node_id = require_js_string(info[1], "otDeleteNode", "nodeId");
    OtTreeExecute(info, options, name, CRABS_OT_OP_DELETE_NODE, 0,
                  node_id, "", "", "otDeleteNode");
    return env.Undefined();
  }

  Napi::Value OtReparent(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 5 || !info[4].IsObject())
      throw Napi::TypeError::New(env,
          "Expected otReparent(name, nodeId, newParentId, position, options)");
    Napi::Object options = require_ordered_options(info, 4, "otReparent");
    std::string name = require_js_string(info[0], "otReparent", "name");
    std::string node_id = require_js_string(info[1], "otReparent", "nodeId");
    std::string new_parent_id = info[2].IsString()
        ? require_js_string(info[2], "otReparent", "newParentId")
        : std::string("");
    uint64_t position = require_u64_numeric(info[3], "otReparent", "position");
    OtTreeExecute(info, options, name, CRABS_OT_OP_REPARENT, position,
                  node_id, new_parent_id, "", "otReparent");
    return env.Undefined();
  }

  Napi::Value OtReorder(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 4 || !info[3].IsObject())
      throw Napi::TypeError::New(env,
          "Expected otReorder(name, nodeId, position, options)");
    Napi::Object options = require_ordered_options(info, 3, "otReorder");
    std::string name = require_js_string(info[0], "otReorder", "name");
    std::string node_id = require_js_string(info[1], "otReorder", "nodeId");
    uint64_t position = require_u64_numeric(info[2], "otReorder", "position");
    OtTreeExecute(info, options, name, CRABS_OT_OP_REORDER, position,
                  node_id, "", "", "otReorder");
    return env.Undefined();
  }

  // Generic tree-op route: op = { kind, nodeId, parentId?, newParentId?,
  // position, value?, id, deps? } — kind is one of 'insertNode' |
  // 'deleteNode' | 'reparent' | 'reorder'.
  Napi::Value OtTreeApply(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsObject())
      throw Napi::TypeError::New(env, "Expected otTreeApply(name, op)");
    std::string name = require_js_string(info[0], "otTreeApply", "name");
    Napi::Object op = info[1].As<Napi::Object>();
    if (!op.Has("kind") || !op.Get("kind").IsString())
      throw Napi::TypeError::New(env, "otTreeApply: op.kind is required");
    std::string kind = to_lower_ascii(op.Get("kind").As<Napi::String>().Utf8Value());
    OtRequireOpOptions(info, op, "otTreeApply");

    if (kind == "insertnode") {
      OtTreeExecute(info, op, name, CRABS_OT_OP_INSERT_NODE,
          require_u64_numeric(op.Get("position"), "otTreeApply", "position"),
          require_js_string(op.Get("nodeId"), "otTreeApply", "nodeId"),
          op.Has("parentId") && op.Get("parentId").IsString()
              ? require_js_string(op.Get("parentId"), "otTreeApply", "parentId")
              : std::string(""),
          op.Has("value") && op.Get("value").IsString()
              ? require_js_string(op.Get("value"), "otTreeApply", "value")
              : std::string(""),
          "otTreeApply");
    } else if (kind == "deletenode") {
      OtTreeExecute(info, op, name, CRABS_OT_OP_DELETE_NODE, 0,
          require_js_string(op.Get("nodeId"), "otTreeApply", "nodeId"),
          "", "", "otTreeApply");
    } else if (kind == "reparent") {
      OtTreeExecute(info, op, name, CRABS_OT_OP_REPARENT,
          require_u64_numeric(op.Get("position"), "otTreeApply", "position"),
          require_js_string(op.Get("nodeId"), "otTreeApply", "nodeId"),
          op.Has("newParentId") && op.Get("newParentId").IsString()
              ? require_js_string(op.Get("newParentId"), "otTreeApply",
                                  "newParentId") : std::string(""),
          "", "otTreeApply");
    } else if (kind == "reorder") {
      OtTreeExecute(info, op, name, CRABS_OT_OP_REORDER,
          require_u64_numeric(op.Get("position"), "otTreeApply", "position"),
          require_js_string(op.Get("nodeId"), "otTreeApply", "nodeId"),
          "", "", "otTreeApply");
    } else {
      throw Napi::TypeError::New(env, "otTreeApply: unknown op.kind");
    }
    return env.Undefined();
  }

  // --- Policies ---

  Napi::Value SetPolicy(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string op_type = require_js_string(info[0], "setPolicy", "opType");
    std::string expr = require_js_string(info[1], "setPolicy", "expression");
    crabs_error_e rc = state_add_policy(&am_->base_state, op_type.c_str(), expr.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "setPolicy");
    return env.Undefined();
  }

  // --- Operation execution ---

  // Sign an operation with HLC stamping. This stamps the HLC timestamp and
  // node_id onto the operation BEFORE signing, so the signature covers the
  // HLC fields. Must be called instead of op.sign(keyPair) when using HLC
  // ordering — otherwise execute() will reject the stale signature.
  Napi::Value SignOp(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsObject())
      throw Napi::TypeError::New(env, "Expected (Operation, KeyPair)");
    Operation* op = Operation::Unwrap(info[0].As<Napi::Object>());

    // Stamp HLC before signing so the signature covers the timestamp
    if (am_->base_state.hlc_state_initialized) {
      op->raw()->ordering_system = CRABS_ORDERING_HLC;
      op->raw()->hlc = crabs_hlc_next(&am_->base_state.hlc_state);
      strncpy(op->raw()->node_id, am_->base_state.hlc_state.last.node_id,
              CRABS_MAX_USER_ID - 1);
    }

    // R7-04: ops must carry the signer's current key_version, or verification
    // fails closed with key_stale (same stamping crabs_wasm_sign_operation
    // does for the WASM binding).
    user_t* signer_user =
        attribute_machine_find_user(am_, op->raw()->signer_id);
    if (signer_user != NULL) {
      op->raw()->signer_key_version = signer_user->key_version;
    }

    // Sign
    if (info[1].IsObject()) {
      // KeyPair object
      KeyPair* kp = KeyPair::Unwrap(info[1].As<Napi::Object>());
      serialized_buffer_t* ser = crabs_serialize_for_signing(op->raw());
      if (!ser) throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "sign");
      crabs_error_e rc = crypto_ecdsa_sign(kp->raw()->private_key,
                                            ser->data, ser->len, op->raw()->signature);
      serialized_buffer_destroy(ser);
      if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "sign");
    } else if (info[1].IsString()) {
      // Private key hex string
      uint8_t priv[32];
      std::string hex = info[1].As<Napi::String>().Utf8Value();
      // A11-L7: cleanse even on the decode-failure throw — a partial decode
      // leaves a prefix of the caller's key bytes on the stack. Audit M-6:
      // the std::string is a second heap copy of the secret — cleanse it on
      // every path (the DecryptKeyEnvelope pattern).
      if (!hex_decode(hex, priv, 32)) {
        OPENSSL_cleanse(priv, 32);
        OPENSSL_cleanse(&hex[0], hex.size());
        throw Napi::Error::New(env, "Invalid private key hex");
      }
      serialized_buffer_t* ser = crabs_serialize_for_signing(op->raw());
      if (!ser) {
        OPENSSL_cleanse(priv, 32);
        OPENSSL_cleanse(&hex[0], hex.size());
        throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "sign");
      }
      crabs_error_e rc = crypto_ecdsa_sign(priv, ser->data, ser->len, op->raw()->signature);
      serialized_buffer_destroy(ser);
      OPENSSL_cleanse(priv, 32);
      OPENSSL_cleanse(&hex[0], hex.size());
      if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "sign");
    }
    return info.This();
  }

  Napi::Value Execute(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsObject())
      throw Napi::TypeError::New(env, "Expected Operation");
    Operation* op = Operation::Unwrap(info[0].As<Napi::Object>());
    // Do NOT modify the operation here — it's already signed. Any modification
    // after signing invalidates the signature. Use node.sign(op, key) to stamp
    // HLC and sign in one step before calling execute.
    crabs_error_e rc = state_machine_execute(&am_->base_state, op->raw());
    // Raft two-phase path: a GROUP_ORDERED write under an attached module
    // returns ordering_pending — the op was ACCEPTED into the module's log
    // as a pending proposal and materializes on commit (pumped by the raft
    // host). Mirrors the wasm binding's execute() handling.
    if (rc != CRABS_SUCCESS && rc != CRABS_ERR_ORDERING_PENDING)
      throw crabs_error(env, rc, "execute");
    return env.Undefined();
  }

  Napi::Value ExecuteReplay(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsObject()) {
      throw Napi::TypeError::New(env, "Expected Operation");
    }
    Operation* op = Operation::Unwrap(info[0].As<Napi::Object>());
    // Replay ingest (parity with the wasm binding's replayOp): the HLC skew
    // decision uses the node's replay policy (hlc.replay_policy) instead of
    // the live one. Never throws for a failed VALID op — failures return a
    // skipped outcome object so a bulk log ingest can converge.
    // NOTE: a PENDING outcome (and every skip other than ALREADY_EXECUTED)
    // still emits a 'change' event — the C layer notifies every
    // non-ALREADY_EXECUTED result — the same replay-driven-event caveat as
    // the wasm surface for N-API change listeners.
    crabs_error_e rc = state_machine_execute_replay(&am_->base_state, op->raw());
    Napi::Object outcome = Napi::Object::New(env);
    if (rc == CRABS_SUCCESS) {
      outcome.Set("status", "applied");
      return outcome;
    }
    if (rc == CRABS_ERR_ORDERING_PENDING) {
      outcome.Set("status", "pending");
      return outcome;
    }
    outcome.Set("status", "skipped");
    outcome.Set("code", Napi::Number::New(env, (double)rc));
    outcome.Set("message", crabs_error_name(rc));
    return outcome;
  }

  // --- Timed transactions (v1) ---
  //
  // Mirror of the wasm schedule surface (bindings/wasm/index.d.ts:501-511).
  // The submission-time authorization gate lives HERE in the wrapper:
  // state_machine_validate (policy + signature + key version + co-signatures
  // + read-only domain check) runs BEFORE the op is queued, mirroring
  // crabs_wasm_schedule (src/Util/wasm_helpers.c:1509-1519). The later
  // materialization deliberately skips re-authorization — the scheduler
  // executes with the authorization step off
  // (src/Scheduler/scheduler.c:337-338). The scheduler serializes its own
  // copy of the embedded op at submission, so the JS Operation keeps its
  // lifetime; the pending entries are durable machine state.

  // Queue a signed op for materialization at executeAtMs. Returns the
  // schedule id (a positive bigint) or throws the typed authorization /
  // serialization refusal.
  Napi::Value Schedule(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsObject())
      throw Napi::TypeError::New(env, "Expected schedule(Operation, executeAtMs)");
    Operation* op = Operation::Unwrap(info[0].As<Napi::Object>());
    if (op == nullptr)
      throw Napi::TypeError::New(env, "schedule: expected an Operation");
    const uint64_t execute_at_ms =
        require_u64_numeric(info[1], "schedule", "executeAtMs");
    // Submission-time authorization (mirrors crabs_wasm_schedule). Read-only.
    crabs_error_e validate_rc =
        state_machine_validate(&am_->base_state, op->raw());
    if (validate_rc != CRABS_SUCCESS)
      throw crabs_error(env, validate_rc, "schedule");
    const uint64_t schedule_id = scheduler_schedule(
        &am_->base_state, execute_at_ms, op->raw()->signer_id, op->raw());
    if (schedule_id == 0) {
      // 0 means invalid input (empty submitter) or a serialization failure
      // while stamping the pending copy — distinguish them for the caller.
      throw crabs_error(env,
          op->raw()->signer_id[0] == '\0' ? CRABS_ERR_INVALID_PARAM
                                          : CRABS_ERR_SERIALIZATION_ERROR,
          "schedule");
    }
    return Napi::BigInt::New(env, (int64_t)schedule_id);
  }

  // Queue a recurring series: fires at startAtMs then every intervalMs until
  // repeatCount fires have happened (0 = infinite) or the slots pass
  // endAtMs (0 = none), whichever comes first.
  Napi::Value ScheduleRecurring(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 5 || !info[0].IsObject())
      throw Napi::TypeError::New(
          env, "Expected scheduleRecurring(Operation, startAtMs, intervalMs, "
               "repeatCount, endAtMs)");
    Operation* op = Operation::Unwrap(info[0].As<Napi::Object>());
    if (op == nullptr)
      throw Napi::TypeError::New(env, "scheduleRecurring: expected an Operation");
    // Argument bounds are checked BEFORE submission so a malformed arg can
    // never queue with a silently truncated cadence.
    const uint64_t start_at_ms =
        require_u64_numeric(info[1], "scheduleRecurring", "startAtMs");
    const uint64_t interval_ms =
        require_u64_numeric(info[2], "scheduleRecurring", "intervalMs");
    const uint64_t repeat_count =
        require_u64_numeric(info[3], "scheduleRecurring", "repeatCount");
    const uint64_t end_at_ms =
        require_u64_numeric(info[4], "scheduleRecurring", "endAtMs");
    // Submission-time authorization (mirrors crabs_wasm_schedule). Read-only.
    crabs_error_e validate_rc =
        state_machine_validate(&am_->base_state, op->raw());
    if (validate_rc != CRABS_SUCCESS)
      throw crabs_error(env, validate_rc, "scheduleRecurring");
    const uint64_t schedule_id = scheduler_schedule_recurring(
        &am_->base_state, start_at_ms, interval_ms, repeat_count, end_at_ms,
        op->raw()->signer_id, op->raw());
    if (schedule_id == 0) {
      throw crabs_error(env,
          op->raw()->signer_id[0] == '\0' ? CRABS_ERR_INVALID_PARAM
                                          : CRABS_ERR_SERIALIZATION_ERROR,
          "scheduleRecurring");
    }
    return Napi::BigInt::New(env, (int64_t)schedule_id);
  }

  // Remove one pending schedule by id. resource_not_found when absent.
  Napi::Value CancelSchedule(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 ||
        (!info[0].IsBigInt() && !info[0].IsNumber()))
      throw Napi::TypeError::New(env,
          "cancelSchedule: scheduleId must be a number or bigint");
    const uint64_t schedule_id =
        require_u64_numeric(info[0], "cancelSchedule", "scheduleId");
    crabs_error_e rc = scheduler_cancel(&am_->base_state, schedule_id);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "cancelSchedule");
    return env.Undefined();
  }

  // Materialize every pending schedule whose due time has passed. The tick
  // is an EXPLICIT clock poke: nowMs defaults to the wall clock (the same
  // Date.now() default the wasm wrapper carries, bindings-core.js:1316),
  // but every demo and test passes an explicit `now`. Failures are recorded
  // as __schedule_failed__ entries per the C contract and never propagated.
  Napi::Value ProcessSchedules(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    const uint64_t now_ms = info.Length() > 0 && !info[0].IsUndefined()
        ? require_u64_numeric(info[0], "processSchedules", "nowMs")
        : (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch()).count();
    crabs_error_e rc = scheduler_process_due(&am_->base_state, now_ms);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "processSchedules");
    return env.Undefined();
  }

  // Per-tick ceiling on materialized scheduled occurrences (0 = unlimited).
  // Node-local runtime policy, never serialized (scheduler.h:52-55).
  Napi::Value SetScheduleOccurrenceBudget(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsNumber())
      throw Napi::TypeError::New(env,
          "setScheduleOccurrenceBudget: maxPerTick must be a number");
    const double max_per_tick = info[0].As<Napi::Number>().DoubleValue();
    if (max_per_tick < 0 || max_per_tick > (double)UINT32_MAX ||
        max_per_tick != floor(max_per_tick))
      throw Napi::RangeError::New(env,
          "setScheduleOccurrenceBudget: maxPerTick must be an integer 0..2^32-1");
    scheduler_set_max_occurrences_per_tick(&am_->base_state,
                                           (uint32_t)max_per_tick);
    return env.Undefined();
  }

  Napi::Value ScheduleOccurrenceBudget(const Napi::CallbackInfo& info) {
    return Napi::Number::New(info.Env(),
                             (double)am_->base_state.max_occurrences_per_tick);
  }

  // The pending queue in submission order (also after restore): one row per
  // entry with the same shape the wasm wrapper returns.
  Napi::Value PendingSchedules(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Array rows = Napi::Array::New(env);
    uint32_t row_index = 0;
    for (const scheduled_operation_t* entry =
             scheduler_first(&am_->base_state);
         entry != NULL; entry = entry->next) {
      Napi::Object row = Napi::Object::New(env);
      row.Set("id", Napi::BigInt::New(env, (int64_t)entry->schedule_id));
      row.Set("executeAt",
              Napi::BigInt::New(env, (int64_t)entry->execute_at_ms));
      row.Set("intervalMs",
              Napi::BigInt::New(env, (int64_t)entry->interval_ms));
      row.Set("repeatCount",
              Napi::BigInt::New(env, (int64_t)entry->repeat_count));
      row.Set("endAt", Napi::BigInt::New(env, (int64_t)entry->end_at_ms));
      row.Set("submitter", Napi::String::New(env, entry->submitter));
      rows.Set(row_index++, row);
    }
    return rows;
  }

  // --- Triggers ---

  Napi::Value CreateTrigger(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsObject())
      throw Napi::TypeError::New(env, "Expected trigger config object");
    Napi::Object cfg = info[0].As<Napi::Object>();

    // Build the operation payload for __create_trigger__
    std::string trigger_id = require_js_string(
        cfg.Get("triggerId"), "createTrigger", "triggerId");
    std::string condition = require_js_string(
        cfg.Get("condition"), "createTrigger", "condition");
    std::string effect_type_str = require_js_string(
        cfg.Get("effectType"), "createTrigger", "effectType");
    // Map string effect type to the numeric enum value (trigger_effect_type_e
    // in trigger.h: ISSUE_ATTRIBUTE=0x01, CREATE_TRIGGER=0x02, etc.)
    int effect_type_num = 0;
    if (effect_type_str == "issue_attribute") effect_type_num = 1;   // TRIGGER_EFFECT_ISSUE_ATTRIBUTE
    else if (effect_type_str == "create_trigger") effect_type_num = 2;
    else if (effect_type_str == "delete_trigger") effect_type_num = 3;
    else if (effect_type_str == "disable_trigger") effect_type_num = 4;
    else if (effect_type_str == "change_policy") effect_type_num = 5;
    else throw Napi::Error::New(env, "Unknown effectType: " + effect_type_str);

    std::string description = cfg.Has("description")
        ? require_js_string(cfg.Get("description"), "createTrigger", "description")
        : "";
    uint64_t cooldown = cfg.Has("cooldownMs")
        ? require_u64_numeric(cfg.Get("cooldownMs"), "createTrigger", "cooldownMs")
        : 0;
    bool one_shot = cfg.Has("oneShot") ? cfg.Get("oneShot").As<Napi::Boolean>().Value() : false;

    // Build payload string. Audit 9 A-1: snprintf returns the WOULD-BE
    // length on truncation, so accumulating it unchecked lets `pos` exceed
    // sizeof(payload) and `sizeof(payload) - pos` underflow to a huge
    // size_t — an out-of-bounds stack write driven by attacker-controlled
    // JS strings. Clamp pos after every write.
    char payload[4096];
    int written = snprintf(payload, sizeof(payload),
      "trigger_id=%s;condition=%s;description=%s;effect_type=%d;cooldown_ms=%llu;one_shot=%d",
      trigger_id.c_str(), condition.c_str(), description.c_str(),
      effect_type_num, (unsigned long long)cooldown, one_shot ? 1 : 0);
    if (written < 0) throw Napi::Error::New(env, "payload build failed");
    size_t pos = (size_t)written;
    if (pos >= sizeof(payload)) pos = sizeof(payload) - 1;

    // Add effect-specific fields
    if (effect_type_str == "issue_attribute") {
      std::string attr = require_js_string(
          cfg.Get("issueAttribute"), "createTrigger", "issueAttribute");
      std::string role = require_js_string(
          cfg.Get("targetRole"), "createTrigger", "targetRole");
      std::string value = require_js_string(
          cfg.Get("attributeValue"), "createTrigger", "attributeValue");
      uint64_t duration = cfg.Has("durationMs")
          ? require_u64_numeric(cfg.Get("durationMs"), "createTrigger", "durationMs")
          : 0;
      written = snprintf(payload + pos, sizeof(payload) - pos,
        ";issue_attribute=%s;target_role=%s;attribute_value=%s;duration_ms=%llu",
        attr.c_str(), role.c_str(), value.c_str(), (unsigned long long)duration);
      if (written < 0) throw Napi::Error::New(env, "payload build failed");
      pos += (size_t)written;
      if (pos >= sizeof(payload)) pos = sizeof(payload) - 1;
    }

    // Create and execute the __create_trigger__ operation
    operation_t* op = operation_create(CRABS_OP_CREATE_TRIGGER);
    op->payload = (uint8_t*)malloc(strlen(payload) + 1);
    memcpy(op->payload, payload, strlen(payload) + 1);
    op->payload_size = (uint32_t)strlen(payload) + 1;
    // The machine's real admin identity — the id the node key is registered
    // under (attribute_machine_create at construction), not a hardcoded
    // literal. Signing with the node key while stamping a non-existent
    // 'admin' signer refused with unauthorized on any machine whose admin id
    // differs (reportEquivocation stamps the same way).
    strncpy(op->signer_id, admin_id_.c_str(), CRABS_MAX_USER_ID - 1);
    strncpy(op->node_id, admin_id_.c_str(), CRABS_MAX_USER_ID - 1);

    // Stamp BEFORE signing so the signature covers them (mirrors SignOp):
    // HLC when the machine runs HLC ordering, and the signer's current
    // key_version — execute()'s mandatory staleness gate (R7-04) rejects
    // ops declaring a rotated-out (or unstamped) version with key_stale.
    if (am_->base_state.hlc_state_initialized) {
      op->ordering_system = CRABS_ORDERING_HLC;
      op->hlc = crabs_hlc_next(&am_->base_state.hlc_state);
      strncpy(op->node_id, am_->base_state.hlc_state.last.node_id,
              CRABS_MAX_USER_ID - 1);
    }
    user_t* signer_user = attribute_machine_find_user(am_, op->signer_id);
    if (signer_user != NULL) {
      op->signer_key_version = signer_user->key_version;
    }

    // Sign with node key — adopted child wrappers carry no own key (A10-M3).
    if (node_key_ == nullptr) {
      operation_destroy(op);
      throw Napi::Error::New(env,
        "createTrigger: this machine carries no own node key");
    }
    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
    if (ser == nullptr) {
      operation_destroy(op);
      throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "createTrigger");
    }
    crypto_ecdsa_sign(node_key_->private_key, ser->data, ser->len, op->signature);
    serialized_buffer_destroy(ser);

    crabs_error_e rc = state_machine_execute(&am_->base_state, op);
    operation_destroy(op);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "createTrigger");
    return env.Undefined();
  }

  // --- DedupSpec op-type registration (v1.4 §7) ---

  // Register a machine-enforced dedup spec for a user-defined operation
  // type: builds a '__define_operation_type__' op whose resources[0]
  // carries the op-type name and whose dedup struct carries the spec,
  // signs it with the node key under the machine's real admin identity
  // (the createTrigger idiom; the caller installs the define type's own
  // policy first — setPolicy('__define_operation_type__', 'role:admin')),
  // and executes it. The machine registry stores the spec
  // (state_register_op_type_def — re-defining the same type REPLACES its
  // entry in place, so dedup:'none' removes a guard) and the executor
  // resolves it for every later op of that type, regardless of what the op
  // carries on the wire.
  //
  // Exposed dedup types are the two the machine fully enforces
  // ('per-user' tracker / 'global' flag) + 'none'. 'custom' stays
  // C-native: its condition evaluator and spec-carried mutation target are
  // not reason-able from JS.
  Napi::Value DefineOperationType(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[1].IsObject())
      throw Napi::TypeError::New(env,
          "Expected defineOperationType(opType, { dedup, trackerPath?, "
          "flagPath?, rejectionMessage? })");
    std::string op_type = require_js_string(info[0], "defineOperationType", "opType");
    if (op_type.empty()) {
      throw Napi::TypeError::New(env, "defineOperationType: opType must be a non-empty string");
    }
    Napi::Object options = info[1].As<Napi::Object>();
    std::string dedup_word = to_lower_ascii(
        require_js_string(options.Get("dedup"), "defineOperationType", "dedup"));
    dedup_type_e dedup_type;
    if (dedup_word == "none") {
      dedup_type = DEDUP_NONE;
    } else if (dedup_word == "per-user") {
      dedup_type = DEDUP_PER_USER;
    } else if (dedup_word == "global") {
      dedup_type = DEDUP_GLOBAL;
    } else {
      throw Napi::TypeError::New(env,
          "defineOperationType: dedup must be 'per-user' | 'global' | 'none' "
          "(the 'custom' shape is C-native and not surfaceable)");
    }
    std::string tracker_path;
    std::string flag_path;
    std::string rejection_message;
    bool has_rejection_message = false;
    if (options.Has("trackerPath")) {
      tracker_path = require_js_string(options.Get("trackerPath"), "defineOperationType", "trackerPath");
    }
    if (options.Has("flagPath")) {
      flag_path = require_js_string(options.Get("flagPath"), "defineOperationType", "flagPath");
    }
    if (dedup_type == DEDUP_PER_USER && tracker_path.empty()) {
      throw Napi::TypeError::New(env,
          "defineOperationType: dedup 'per-user' requires a trackerPath "
          "(the ONE_SHOT_SET once-record)");
    }
    if (dedup_type == DEDUP_NONE &&
        (!tracker_path.empty() || !flag_path.empty())) {
      throw Napi::TypeError::New(env,
          "defineOperationType: dedup 'none' takes no trackerPath/flagPath "
          "(a 'none' definition removes the guard; nothing to track)");
    }
    if (dedup_type == DEDUP_GLOBAL && flag_path.empty()) {
      throw Napi::TypeError::New(env,
          "defineOperationType: dedup 'global' requires a flagPath "
          "(the ONE_SHOT_FLAG once-record)");
    }
    // The C spec fields are CRABS_MAX_DEDUP_PATH (128) bytes — a longer
    // path would be silently truncated into a tracker/flag lookup that
    // never resolves, so refuse loudly instead.
    if (tracker_path.length() >= CRABS_MAX_DEDUP_PATH) {
      throw Napi::RangeError::New(env,
          "defineOperationType: trackerPath exceeds 127 bytes");
    }
    if (flag_path.length() >= CRABS_MAX_DEDUP_PATH) {
      throw Napi::RangeError::New(env,
          "defineOperationType: flagPath exceeds 127 bytes");
    }
    if (options.Has("rejectionMessage")) {
      rejection_message = require_js_string(
          options.Get("rejectionMessage"), "defineOperationType", "rejectionMessage");
      has_rejection_message = !rejection_message.empty();
      // The C spec field is CRABS_MAX_DEDUP_MESSAGE (256) bytes — a longer
      // message would be silently truncated mid-text, so refuse loudly
      // instead (std::string::length() counts UTF-8 bytes, matching the
      // C buffer).
      if (rejection_message.length() >= CRABS_MAX_DEDUP_MESSAGE) {
        throw Napi::RangeError::New(env,
            "defineOperationType: rejectionMessage exceeds 255 bytes");
      }
    }
    // An op-type name travels as resources[0] (the define handler reads it),
    // so it obeys the same length bound as every other resource string.
    if (op_type.length() >= CRABS_MAX_USER_ID) {
      throw Napi::RangeError::New(env,
          "defineOperationType: opType must be 1..63 characters");
    }

    operation_t* op = operation_create(CRABS_OP_DEFINE_OPERATION);
    if (op == nullptr) throw crabs_error(env, CRABS_ERR_OOM, "defineOperationType");
    operation_append_resource(op, op_type, env, "defineOperationType");
    op->dedup.type = dedup_type;
    if (dedup_type == DEDUP_PER_USER) {
      strncpy(op->dedup.tracker_path, tracker_path.c_str(), CRABS_MAX_DEDUP_PATH - 1);
      op->dedup.tracker_path[CRABS_MAX_DEDUP_PATH - 1] = '\0';
    } else if (dedup_type == DEDUP_GLOBAL) {
      strncpy(op->dedup.flag_path, flag_path.c_str(), CRABS_MAX_DEDUP_PATH - 1);
      op->dedup.flag_path[CRABS_MAX_DEDUP_PATH - 1] = '\0';
    }
    // rejection_message is metadata carried on the spec (serialized with
    // it); the enforcement error itself is the type's domain error.
    if (has_rejection_message) {
      strncpy(op->dedup.rejection_message, rejection_message.c_str(),
              CRABS_MAX_DEDUP_MESSAGE - 1);
      op->dedup.rejection_message[CRABS_MAX_DEDUP_MESSAGE - 1] = '\0';
    }

    strncpy(op->signer_id, admin_id_.c_str(), CRABS_MAX_USER_ID - 1);
    strncpy(op->node_id, admin_id_.c_str(), CRABS_MAX_USER_ID - 1);

    // Stamp BEFORE signing so the signature covers HLC + key version
    // (the same mandatory execute gates every other op obeys).
    if (am_->base_state.hlc_state_initialized) {
      op->ordering_system = CRABS_ORDERING_HLC;
      op->hlc = crabs_hlc_next(&am_->base_state.hlc_state);
      strncpy(op->node_id, am_->base_state.hlc_state.last.node_id,
              CRABS_MAX_USER_ID - 1);
    }
    user_t* signer_user = attribute_machine_find_user(am_, op->signer_id);
    if (signer_user != nullptr) {
      op->signer_key_version = signer_user->key_version;
    }

    if (node_key_ == nullptr) {
      operation_destroy(op);
      throw Napi::Error::New(env,
        "defineOperationType: this machine carries no own node key");
    }
    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
    if (ser == nullptr) {
      operation_destroy(op);
      throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "defineOperationType");
    }
    crypto_ecdsa_sign(node_key_->private_key, ser->data, ser->len, op->signature);
    serialized_buffer_destroy(ser);

    crabs_error_e rc = state_machine_execute(&am_->base_state, op);
    operation_destroy(op);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "defineOperationType");
    return env.Undefined();
  }

  // --- ABE encryption ---

  Napi::Value Encrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2)
      throw Napi::TypeError::New(env, "Expected (payload, policy)");
    // Gate at the wrapper like the peer methods: a non-Buffer here fails
    // napi_get_buffer_info with a vague "Invalid argument" Error instead of
    // a typed refusal naming the argument.
    if (!info[0].IsBuffer())
      throw Napi::TypeError::New(env, "encrypt: payload must be a Buffer");
    auto buf = info[0].As<Napi::Buffer<uint8_t>>();
    std::string policy = require_js_string(info[1], "encrypt", "policy");

    abe_ciphertext_t* ct = crypto_abe_encrypt((const abe_master_key_t*)am_->base_state.abe_mk,
                                                buf.Data(), buf.Length(),
                                                policy.c_str());
    if (!ct) throw crabs_error(env, CRABS_ERR_CRYPTOGRAPHIC_ERROR, "encrypt");

    // Serialize the ciphertext to a buffer using accessor functions
    const char* policy_str = crypto_abe_ciphertext_get_policy(ct);
    size_t ct_len = 0;
    const uint8_t* ct_data = crypto_abe_ciphertext_get_data(ct, &ct_len);
    size_t policy_len = strlen(policy_str);
    size_t total = 2 + policy_len + 4 + ct_len;
    Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::New(env, total);
    uint8_t* p = out.Data();
    *(uint16_t*)p = (uint16_t)policy_len; p += 2;
    memcpy(p, policy_str, policy_len); p += policy_len;
    *(uint32_t*)p = (uint32_t)ct_len; p += 4;
    if (ct_data && ct_len > 0) memcpy(p, ct_data, ct_len);

    crypto_abe_ciphertext_destroy(ct);
    return out;
  }

  // --- ABE keygen + decrypt (gap-fill A11) ---
  //
  // abeKeygen(attrs) derives a CP-ABE reader key from THE MACHINE'S OWN
  // master authority (state->abe_mk): whoever controls the machine can
  // mint a key for any attribute set it names — the same trust position as
  // encrypt. The master key itself never leaves the machine (no JS handle
  // for it exists; no portable serialized key in v1). attrs is the
  // comma-separated token list the C API takes, with the ':' → '_' token
  // map applied machine-side (crypto.c:98-111) — so a key derived from
  // 'role:member,role:moderator' carries the ABE words role_member /
  // role_moderator, and the seal policy must be written with those same
  // words. The returned AbeKey is JS-owned: destroy() it (or any later
  // decrypt through it refuses).
  Napi::Value AbeKeygen(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1)
      throw Napi::TypeError::New(env, "Expected (attrs)");
    std::string attrs = require_js_string(info[0], "abeKeygen", "attrs");
    if (attrs.empty())
      throw crabs_error(env, CRABS_ERR_INVALID_PARAM, "abeKeygen");
    if (am_->base_state.abe_mk == nullptr)
      throw crabs_error(env, CRABS_ERR_CRYPTOGRAPHIC_ERROR, "abeKeygen");

    abe_user_key_t* sk = crypto_abe_keygen(
        (const abe_master_key_t*)am_->base_state.abe_mk, attrs.c_str());
    if (!sk)
      throw crabs_error(env, CRABS_ERR_CRYPTOGRAPHIC_ERROR, "abeKeygen");
    return AbeKey::NewInstance(env, sk);
  }

  // abeDecrypt(key, sealed) opens the container encrypt() returned —
  // u16le policy byte length + policy bytes + u32le ciphertext length +
  // ciphertext (the layout Encrypt writes). Malformed containers refuse at
  // the boundary; a key whose attributes do not satisfy the container's
  // policy refuses with the typed error — 'unauthorized' — straight from
  // crypto_abe_decrypt (also the tamper path: GCM fail-closed). Staging
  // discipline: the ciphertext handle is rebuilt from the container halves,
  // decrypted, and destroyed on EVERY path (including refusals and the
  // malformed-container throws, each destroying first); the plaintext the
  // C side mallocs is copied into the returned Buffer and freed before
  // anything is handed back to JS.
  Napi::Value AbeDecrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsObject() || !info[1].IsBuffer())
      throw Napi::TypeError::New(env,
        "Expected (AbeKey, encrypted container Buffer)");
    auto* key = AbeKey::Unwrap(info[0].As<Napi::Object>());
    if (key == nullptr || key->raw() == nullptr)
      throw Napi::Error::New(env,
        "abeDecrypt: expected a live AbeKey (a destroyed key refuses)");

    auto sealed = info[1].As<Napi::Buffer<uint8_t>>();
    const uint8_t* bytes = sealed.Data();
    size_t total = sealed.Length();
    if (total < 2 + 4)
      throw Napi::Error::New(env, "abeDecrypt: malformed container (truncated header)");
    size_t policy_len = (size_t)(*(const uint16_t*)bytes);
    size_t ct_len_offset = 2 + policy_len;
    if (ct_len_offset + 4 > total)
      throw Napi::Error::New(env, "abeDecrypt: malformed container (truncated header)");
    size_t ct_len = (size_t)(*(const uint32_t*)(bytes + ct_len_offset));
    if (2 + policy_len + 4 + ct_len != total)
      throw Napi::Error::New(env,
        "abeDecrypt: malformed container (length header does not match container size)");
    std::string policy((const char*)bytes + 2, policy_len);

    abe_ciphertext_t* ct = crypto_abe_ciphertext_load(
        policy.c_str(), bytes + ct_len_offset + 4, ct_len);
    if (!ct)
      throw Napi::Error::New(env,
        "abeDecrypt: container did not reconstruct (policy or ciphertext invalid)");

    uint8_t* out = nullptr;
    size_t out_len = 0;
    crabs_error_e rc = crypto_abe_decrypt(key->raw(), ct, &out, &out_len);
    crypto_abe_ciphertext_destroy(ct);  // destroy the staged handle on every path
    if (rc != CRABS_SUCCESS) {
      if (out != nullptr) { free(out); out = nullptr; }  // paranoid no-op: refusal frees its own buffer
      throw crabs_error(env, rc, "abeDecrypt");
    }
    Napi::Buffer<uint8_t> plain = Napi::Buffer<uint8_t>::Copy(env, out, out_len);
    // The JS caller owns a copy; the C staging copy must not linger in the heap.
    OPENSSL_cleanse(out, out_len);
    free(out);
    return plain;
  }

  // --- ABE key transport (parity-fill P4) ---

  // abeKeyFromWire(wire) re-imports a reader key the AbeKey.toWire() form
  // carries. The C deserialize signature takes the master key
  // (crypto_abe_user_key_deserialize(mk, buf, len) — the header comment says
  // "the master key provides the public params") — so the restore runs on
  // THIS machine's authority and REFUSES without one — but the CAPABILITY is
  // the wire's OWN: OpenABE's key import binds the restored key to its
  // MINTING domain, whatever machine re-imports it (pinned cross-machine in
  // test/abe.js: an n1 wire restored on a stranger machine still opens n1's
  // secrets and refuses another authority's). That is the bearer truth of
  // the wire, not a restore accident. The wire is integrity-blind (no
  // checksum): carry it authenticated or use the envelope flow below.
  // Cross-wire confusion ('MK' master-key magic in the reader slot) refuses
  // with the typed invalid_param — crypto_abe_user_key_deserialize refuses
  // an authority image (crypto.c). Staging discipline (P4 review, mirroring
  // the wasm side's staged-copy cleanse): this method STAGES NOTHING — the
  // wire is read in place from the caller's Buffer, so no C-side copy
  // lingers past the call and the caller's copy remains theirs; the
  // deserialized key object owns its own cleansed-by-destroy copies.
  Napi::Value AbeKeyFromWire(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsBuffer())
      throw Napi::TypeError::New(env,
        "Expected a reader-key wire Buffer (AbeKey.toWire form)");
    if (am_->base_state.abe_mk == nullptr)
      throw crabs_error(env, CRABS_ERR_CRYPTOGRAPHIC_ERROR, "abeKeyFromWire");
    auto wire = info[0].As<Napi::Buffer<uint8_t>>();
    abe_user_key_t* sk = crypto_abe_user_key_deserialize(
        (const abe_master_key_t*)am_->base_state.abe_mk,
        wire.Data(), wire.Length());
    if (!sk)
      throw crabs_error(env, CRABS_ERR_INVALID_PARAM, "abeKeyFromWire");
    return AbeKey::NewInstance(env, sk);
  }

  // mintKeyEnvelope(userId, options?) — the refresh_key materialization
  // shape (state_machine.c:2797) without the protocol bookkeeping: the
  // machine's own authority + node private key issue a real CP-ABE key for
  // the user's CURRENT attribute set, node-ECDSA-signed, with the key
  // ECIES-wrapped to the user's REGISTERED public key (never cleartext).
  // Gates mirrored from the refresh path (fail-closed): ACTIVE users only, a
  // live node key and authority required. Mutates NOTHING (no key_version
  // bump — the transport primitive, not the refresh protocol op).
  // options.expiresAt stamps an epoch-ms expiry into the envelope (default 0
  // = no expiry, what refresh issues; expiry enforcement is integrator-side
  // in C). Returns the envelope wire (crypto_key_envelope_serialize flat
  // form). The envelope staging buffer holds only an ECIES-wrapped key + a
  // signature — cleansed anyway before anything crosses to JS.
  Napi::Value MintKeyEnvelope(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1)
      throw Napi::TypeError::New(env, "Expected (userId, options?)");
    std::string user_id = require_js_string(info[0], "mintKeyEnvelope", "userId");
    uint64_t expires_at = 0;
    if (info.Length() > 1 && !info[1].IsUndefined() && !info[1].IsNull()) {
      if (!info[1].IsObject() || info[1].As<Napi::Object>().IsArray())
        throw Napi::TypeError::New(env,
          "mintKeyEnvelope: options must be an object {expiresAt?}");
      Napi::Object opts = info[1].As<Napi::Object>();
      if (opts.Has("expiresAt")) {
        // `number | bigint` — the wasm wrapper's shape (BigInt-tolerant epoch
        // ms), kept to the same MAX_SAFE_INTEGER ceiling so both bindings
        // accept exactly the same values.
        Napi::Value expiry = opts.Get("expiresAt");
        if (!expiry.IsNumber() && !expiry.IsBigInt())
          throw Napi::TypeError::New(env,
            "mintKeyEnvelope: expiresAt must be a non-negative epoch-ms number");
        if (expiry.IsBigInt()) {
          bool lossless = true;
          uint64_t bigint_ms = expiry.As<Napi::BigInt>().Uint64Value(&lossless);
          // No-loss: negatives and > 2^64-1 wrap (lossless=false); anything
          // past the JS-safe number ceiling is rejected for parity with the
          // wasm wrapper's range gate.
          if (!lossless || bigint_ms > 9007199254740991ULL)
            throw Napi::RangeError::New(env,
              "mintKeyEnvelope: expiresAt must be a non-negative epoch-ms number");
          expires_at = bigint_ms;
        } else {
          double expires_ms = expiry.As<Napi::Number>().DoubleValue();
          if (!(expires_ms >= 0.0) || expires_ms > 9007199254740991.0)
            throw Napi::RangeError::New(env,
              "mintKeyEnvelope: expiresAt must be a non-negative epoch-ms number");
          expires_at = (uint64_t)expires_ms;
        }
      }
    }
    // Gates mirrored from refresh_key (audit H-C): live authority + node key,
    // and only ACTIVE users receive envelopes.
    if (am_->base_state.abe_mk == nullptr || !am_->base_state.node_key_valid)
      throw crabs_error(env, CRABS_ERR_CRYPTOGRAPHIC_ERROR, "mintKeyEnvelope");
    user_t* user = attribute_machine_find_user(am_, user_id.c_str());
    if (!user)
      throw crabs_error(env, CRABS_ERR_USER_NOT_FOUND, "mintKeyEnvelope");
    if (user->status != USER_ACTIVE)
      throw crabs_error(env,
          (user->status == USER_SUSPENDED) ? CRABS_ERR_USER_SUSPENDED
                                           : CRABS_ERR_USER_NOT_FOUND,
          "mintKeyEnvelope");
    uint64_t now_ms;
    if (!state_get_time_ms(&am_->base_state, &now_ms))
      throw crabs_error(env, CRABS_ERR_CRYPTOGRAPHIC_ERROR, "mintKeyEnvelope");

    key_envelope_t* envelope = crypto_key_envelope_create(
        (const abe_master_key_t*)am_->base_state.abe_mk,
        am_->base_state.node_private_key, user, am_->base_state.version,
        now_ms, expires_at);
    if (!envelope)
      throw crabs_error(env, CRABS_ERR_CRYPTOGRAPHIC_ERROR, "mintKeyEnvelope");
    uint8_t wire[CRABS_KEY_ENVELOPE_MAX_SIZE];
    size_t wire_len = crypto_key_envelope_serialize(envelope, wire, sizeof(wire));
    crypto_key_envelope_destroy(envelope);   // cleanses the embedded ECIES copy
    if (wire_len == 0)
      throw crabs_error(env, CRABS_ERR_INTERNAL, "mintKeyEnvelope");
    Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::Copy(env, wire, wire_len);
    OPENSSL_cleanse(wire, sizeof(wire));     // ECIES-wrapped — defense in depth
    return out;
  }

  // decryptKeyEnvelope(envelope, options) opens a mintKeyEnvelope wire on
  // the recipient side and returns the restored AbeKey — the C KeyEnvelope
  // battery's flow (test_crypto.cpp:963-1032): parse (against THIS machine's
  // authority — the envelope carries no public params), verify the ISSUER's
  // ECDSA signature over the canonical envelope, then open the ECIES blob
  // with the recipient's private key and import the recovered reader key
  // against this authority. Both tamper paths fail closed with the typed
  // 'unauthorized' — a tampered wire breaks the signature, a wrong recipient
  // key or tampered blob breaks the GCM tag. options.privateKeyHex — the
  // recipient's 64-hex private key; options.nodePublicKeyHex — the ISSUER
  // node's public key for out-of-machine verification (default: this
  // machine's own node key, which refuses an envelope another machine
  // issued — fail-closed). Staging discipline: the recovered plaintext ABE
  // key never leaves C (cleansed inside before anything returns); the
  // recipient private key bytes AND their JS-side hex-string copies are
  // cleansed on every path (including refusals thrown before the C call).
  Napi::Value DecryptKeyEnvelope(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsObject())
      throw Napi::TypeError::New(env,
        "Expected (envelope Buffer, { privateKeyHex, nodePublicKeyHex? })");
    if (am_->base_state.abe_mk == nullptr)
      throw crabs_error(env, CRABS_ERR_CRYPTOGRAPHIC_ERROR, "decryptKeyEnvelope");
    Napi::Object opts = info[1].As<Napi::Object>();
    if (!opts.Get("privateKeyHex").IsString())
      throw Napi::TypeError::New(env,
        "decryptKeyEnvelope: privateKeyHex must be 64 hex characters (32 bytes)");
    std::string private_hex = require_js_string(
        opts.Get("privateKeyHex"), "decryptKeyEnvelope", "privateKeyHex");
    uint8_t user_private_key[32];
    uint8_t issuer_pub[33];
    bool explicit_issuer = false;
    std::string issuer_hex;
    if (private_hex.length() != 64 ||
        !hex_decode(private_hex, user_private_key, sizeof(user_private_key))) {
      OPENSSL_cleanse(private_hex.data(), private_hex.size());
      OPENSSL_cleanse(user_private_key, sizeof(user_private_key));
      throw Napi::TypeError::New(env,
        "decryptKeyEnvelope: privateKeyHex must be 64 hex characters (32 bytes)");
    }
    if (opts.Has("nodePublicKeyHex")) {
      if (!opts.Get("nodePublicKeyHex").IsString()) {
        OPENSSL_cleanse(user_private_key, sizeof(user_private_key));
        OPENSSL_cleanse(private_hex.data(), private_hex.size());
        throw Napi::TypeError::New(env,
          "decryptKeyEnvelope: nodePublicKeyHex must be 66 hex characters (33 bytes)");
      }
      issuer_hex = require_js_string(
          opts.Get("nodePublicKeyHex"), "decryptKeyEnvelope", "nodePublicKeyHex");
      if (issuer_hex.length() != 66 ||
          !hex_decode(issuer_hex, issuer_pub, sizeof(issuer_pub))) {
        OPENSSL_cleanse(issuer_hex.data(), issuer_hex.size());
        OPENSSL_cleanse(user_private_key, sizeof(user_private_key));
        OPENSSL_cleanse(private_hex.data(), private_hex.size());
        throw Napi::TypeError::New(env,
          "decryptKeyEnvelope: nodePublicKeyHex must be 66 hex characters (33 bytes)");
      }
      explicit_issuer = true;
    }

    const uint8_t* verify_pub = issuer_pub;
    if (!explicit_issuer) {
      if (!am_->base_state.node_key_valid) {
        OPENSSL_cleanse(user_private_key, sizeof(user_private_key));
        OPENSSL_cleanse(private_hex.data(), private_hex.size());
        throw crabs_error(env, CRABS_ERR_CRYPTOGRAPHIC_ERROR, "decryptKeyEnvelope");
      }
      verify_pub = am_->base_state.node_public_key;
    }

    auto wire = info[0].As<Napi::Buffer<uint8_t>>();
    abe_user_key_t* sk = nullptr;
    uint8_t plain[4096];
    size_t plain_len = 0;
    crabs_error_e rc = CRABS_ERR_INTERNAL;
    key_envelope_t* envelope = crypto_key_envelope_deserialize(
        (const abe_master_key_t*)am_->base_state.abe_mk,
        wire.Data(), wire.Length());
    if (!envelope) {
      rc = CRABS_ERR_INVALID_PARAM;   // malformed envelope wire
    } else {
      // Audit M-3: expiry is enforced — machine clock, fail closed on no clock.
      uint64_t now_ms = 0;
      if (!state_get_time_ms(&am_->base_state, &now_ms)) {
        rc = CRABS_ERR_CRYPTOGRAPHIC_ERROR;
      } else if (!crypto_key_envelope_verify(verify_pub, envelope, now_ms)) {
        rc = CRABS_ERR_UNAUTHORIZED;  // wrong issuer key or tampered header/blob
      } else if (crypto_key_envelope_decrypt_sk(
                     envelope, user_private_key, plain,
                     sizeof(plain), &plain_len) != CRABS_SUCCESS) {
        rc = CRABS_ERR_UNAUTHORIZED;  // tag mismatch: wrong recipient or tamper
      } else {
        sk = crypto_abe_user_key_deserialize(
            (const abe_master_key_t*)am_->base_state.abe_mk, plain, plain_len);
        rc = (sk != nullptr) ? CRABS_SUCCESS : CRABS_ERR_CRYPTOGRAPHIC_ERROR;
      }
    }
    // Audit H-4: consume the envelope's signed state_version — the wasm export
    // (wasm_helpers.c) refuses stale/replayed envelopes with key_stale; this
    // binding previously imported them silently. The gate's monotonic
    // watermark only advances once the recipient work completed.
    if (rc == CRABS_SUCCESS) {
      rc = attribute_machine_envelope_import_gate(am_, envelope);
      if (rc != CRABS_SUCCESS) {
        crypto_abe_user_key_destroy(sk);
        sk = nullptr;
      }
    }
    // The recovered plaintext key bytes never linger past this frame.
    OPENSSL_cleanse(plain, sizeof(plain));
    if (envelope) crypto_key_envelope_destroy(envelope);  // cleanses the ECIES copy
    OPENSSL_cleanse(user_private_key, sizeof(user_private_key));
    OPENSSL_cleanse(private_hex.data(), private_hex.size());
    if (explicit_issuer) OPENSSL_cleanse(issuer_hex.data(), issuer_hex.size());
    if (rc != CRABS_SUCCESS)
      throw crabs_error(env, rc, "decryptKeyEnvelope");
    return AbeKey::NewInstance(env, sk);
  }

  // --- Master-key durability (§11.5 — see the d.ts docblocks; these are
  // the CROWN JEWEL surfaces and marked so in both bindings' typings). ---

  // serializeMasterKey(): the machine's authority in its 'MK' wire form —
  // the C battery's backup round trip
  // (TestDurability.MasterKeySerializeRoundTripPreservesAuthority; the
  // restored form is a FULL authority minting keys in the same domain).
  // A machine whose authority is merely BORROWED (a SHARED_ROOT lineage
  // child) refuses protocol_violation (P4 review): only the machine that
  // OWNS the authority may export it — the child uses the parent's MSK
  // pointer, it is not entrusted with the MSK bytes at rest.
  Napi::Value SerializeMasterKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (am_->base_state.abe_mk == nullptr)
      throw crabs_error(env, CRABS_ERR_CRYPTOGRAPHIC_ERROR, "serializeMasterKey");
    if (am_->base_state.abe_mk_borrowed)
      throw crabs_error(env, CRABS_ERR_PROTOCOL_VIOLATION, "serializeMasterKey");
    size_t needed = crypto_master_key_serialize(
        (const abe_master_key_t*)am_->base_state.abe_mk, nullptr, 0);
    if (needed == 0)
      throw crabs_error(env, CRABS_ERR_CRYPTOGRAPHIC_ERROR, "serializeMasterKey");
    Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::New(env, needed);
    size_t written = crypto_master_key_serialize(
        (const abe_master_key_t*)am_->base_state.abe_mk, out.Data(), needed);
    if (written != needed)
      throw crabs_error(env, CRABS_ERR_INTERNAL, "serializeMasterKey");
    return out;
  }

  // masterKeyFromWire(wire): plants a serialized authority as THIS machine's
  // master key — the recovery path a sealed snapshot's MSK section already
  // runs (serialization.c:2862-2866). The previous (owned) authority is
  // destroyed — which cleanses its serialized MPK/MSK wire copies (Audit
  // N-17 discipline through crypto_abe_master_key_destroy); a BORROWED
  // authority (a delegated lineage child's) refuses without mutating
  // anything; malformed / garbage / overrun-length wire refuses (the C
  // battery's pins). Staging discipline (P4 review, mirroring the wasm
  // side's staged-copy cleanse): this method STAGES NOTHING — the wire is
  // read in place from the caller's Buffer, so no C-side copy lingers past
  // the call and the caller's copy remains theirs; the deserialized
  // authority carries the master secret and nothing else but the
  // machine-owned pointer survives the call.
  void MasterKeyFromWire(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsBuffer())
      throw Napi::TypeError::New(env,
        "Expected a master-key wire Buffer (serializeMasterKey form)");
    if (am_->base_state.abe_mk != nullptr && am_->base_state.abe_mk_borrowed)
      throw crabs_error(env, CRABS_ERR_PROTOCOL_VIOLATION, "masterKeyFromWire");
    auto wire = info[0].As<Napi::Buffer<uint8_t>>();
    abe_master_key_t* restored = crypto_master_key_deserialize(
        wire.Data(), wire.Length());
    if (!restored)
      throw crabs_error(env, CRABS_ERR_INVALID_PARAM, "masterKeyFromWire");
    if (am_->base_state.abe_mk != nullptr) {
      crypto_abe_master_key_destroy((abe_master_key_t*)am_->base_state.abe_mk);
    }
    am_->base_state.abe_mk = restored;
  }

  // --- Serialization ---

  // Snapshot serialization (the C families at serialization.h:55-90):
  //   serialize()                  — plain, SHA-256 checksummed (CORRUPTION CHECK ONLY);
  //   serialize({sealKey})         — sealed: MSK AES-256-GCM-wrapped under the key;
  //   serialize({signed: true})    — node-key ECDSA trailer appended;
  //   {sealKey, signed: true}      — sealed + signed (both at-rest guarantees).
  // Sealed variants need the machine's live master key, signed ones its node
  // key; without them C refuses (thrown with a descriptive hint). A snapshot
  // blob is a FULL machine — see deserialize's trust-model note for why the
  // bare checksum is not authentication.
  Napi::Value Serialize(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    std::string seal_key_hex;
    bool with_seal = false;
    bool with_signature = false;
    if (info.Length() > 0 && !info[0].IsUndefined()) {
      if (!info[0].IsObject())
        throw Napi::TypeError::New(env,
            "serialize: options must be an object {sealKey?, signed?}");
      Napi::Object opts = info[0].As<Napi::Object>();
      if (opts.Has("sealKey")) {
        seal_key_hex = require_js_string(opts.Get("sealKey"),
                                         "serialize", "sealKey");
        with_seal = true;
      }
      if (opts.Has("signed")) {
        Napi::Value signed_value = opts.Get("signed");
        if (!signed_value.IsBoolean())
          throw Napi::TypeError::New(env, "serialize: signed must be a boolean");
        with_signature = signed_value.As<Napi::Boolean>().Value();
      }
    }

    serialized_buffer_t* ser = nullptr;
    if (with_seal && with_signature) {
      uint8_t seal_key[32];
      if (!hex_decode(seal_key_hex, seal_key, 32)) {
        OPENSSL_cleanse(seal_key_hex.data(), seal_key_hex.size());
        throw Napi::TypeError::New(env,
            "serialize: sealKey must be 64 hex characters (32 bytes)");
      }
      ser = crabs_serialize_state_sealed_signed(&am_->base_state, seal_key);
      OPENSSL_cleanse(seal_key, sizeof(seal_key));   // staged key never lingers
      OPENSSL_cleanse(seal_key_hex.data(), seal_key_hex.size());  // nor its JS-string copy
    } else if (with_signature) {
      ser = crabs_serialize_state_signed(&am_->base_state);
    } else if (with_seal) {
      uint8_t seal_key[32];
      if (!hex_decode(seal_key_hex, seal_key, 32)) {
        OPENSSL_cleanse(seal_key_hex.data(), seal_key_hex.size());
        throw Napi::TypeError::New(env,
            "serialize: sealKey must be 64 hex characters (32 bytes)");
      }
      ser = crabs_serialize_state_sealed(&am_->base_state, seal_key);
      OPENSSL_cleanse(seal_key, sizeof(seal_key));
      OPENSSL_cleanse(seal_key_hex.data(), seal_key_hex.size());
    } else {
      ser = crabs_serialize_state(&am_->base_state);
    }
    if (!ser) {
      std::string hint;
      if (with_seal)
        hint += " — sealed snapshots need the machine's live master key";
      if (with_signature)
        hint += " — signed snapshots need the machine's node key";
      throw Napi::Error::New(env, std::string("serialize state failed") + hint);
    }
    Napi::Buffer<uint8_t> buf = Napi::Buffer<uint8_t>::Copy(env, ser->data, ser->len);
    serialized_buffer_destroy(ser);
    return buf;
  }

  // Restore a snapshot produced by serialize(): REPLACES this wrapper's
  // underlying machine with the restored state — the same Node stays usable,
  // the previous machine is destroyed unless it was adopted (spawned
  // children are owned by their parent and simply stop being referenced —
  // attribute_machine_destroy's ownership contract protects the borrowed
  // MSK either way). Returns the restore report
  //   { authorityRestored, mskSectionPresent }
  // which only means something for a SEALED blob:
  //   authorityRestored  — the sealed MSK unsealed with sealKey (a wrong or
  //                        missing key still loads, on the substrate-only
  //                        compatibility path, with a FRESH authority);
  //   mskSectionPresent  — the blob carried the authority section at all.
  //
  // options: { sealKey: '64-hex' } restores a sealed snapshot's master key;
  // { verify: 'node-key' } verifies a SIGNED snapshot's ECDSA trailer with
  // THIS machine's node public key BEFORE any parse — a plain load of a
  // signed blob is refused rather than silently accepted unauthenticated.
  // Both combine ({sealKey, verify: 'node-key'}) for sealed+SIGNED blobs.
  //
  // Continuity: the wrapper's node key, change hook, attached time source
  // and raft module ride over from the previous machine, as do the
  // wrapper-owned ordering config and the HLC clock state (the restored
  // machine's clock CONTINUES the previous machine's HLC).
  //
  // TRUST MODEL (serialization.h:70-75): "The bare SHA-256 is only a
  // corruption check — an attacker who can write the state file can recompute
  // it, so snapshot load from untrusted sources must use the signed
  // variants." Loading a snapshot from an untrusted source without
  // {verify: 'node-key'} (and, when authority matters, the matching sealKey)
  // imports whatever state the writer chose. Staged seal key bytes are
  // cleansed on every path.
  Napi::Value Deserialize(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsBuffer())
      throw Napi::TypeError::New(env,
          "deserialize: expected the snapshot wire bytes (Buffer)");
    Napi::Buffer<uint8_t> wire = info[0].As<Napi::Buffer<uint8_t>>();
    const uint8_t* data = wire.Data();
    size_t len = wire.Length();

    std::string seal_key_hex;
    bool with_seal = false;
    bool with_signature_check = false;
    if (info.Length() > 1) {
      if (!info[1].IsObject())
        throw Napi::TypeError::New(env,
            "deserialize: options must be an object {sealKey?, verify?}");
      Napi::Object opts = info[1].As<Napi::Object>();
      if (opts.Has("sealKey")) {
        seal_key_hex = require_js_string(opts.Get("sealKey"),
                                         "deserialize", "sealKey");
        with_seal = true;
      }
      if (opts.Has("verify")) {
        std::string verify_mode = require_js_string(opts.Get("verify"),
                                                    "deserialize", "verify");
        if (verify_mode != "node-key")
          throw Napi::TypeError::New(env,
              "deserialize: verify must be the literal 'node-key'");
        with_signature_check = true;
      }
    }

    // R7-03: the whole body — sealed or plain — is covered by the ECDSA
    // trailer, so verify against THIS machine's node public key before any
    // parse. The wire serializes no key material; self-authored snapshots
    // (crash recovery) are what this machine can authenticate.
    size_t body_len = len;
    if (with_signature_check) {
      if (!am_->base_state.node_key_valid)
        throw Napi::Error::New(env,
            "deserialize: signature verification needs this machine's node key "
            "(none set)");
      if (len <= CRABS_SIG_SIZE)
        throw Napi::Error::New(env,
            "deserialize: signed snapshot too short to carry a signature");
      body_len = len - CRABS_SIG_SIZE;
      if (!crypto_ecdsa_verify(am_->base_state.node_public_key, data, body_len,
                               data + body_len))
        throw Napi::Error::New(env,
            "deserialize: snapshot signature verification failed");
    }

    uint8_t seal_key[32];
    const uint8_t* seal_key_ptr = nullptr;
    if (with_seal) {
      if (!hex_decode(seal_key_hex, seal_key, 32)) {
        OPENSSL_cleanse(seal_key_hex.data(), seal_key_hex.size());
        throw Napi::TypeError::New(env,
            "deserialize: sealKey must be 64 hex characters (32 bytes)");
      }
      seal_key_ptr = seal_key;
      // The JS-string staging is a copy of the key: cleanse it alongside
      // the decoded bytes.
      OPENSSL_cleanse(seal_key_hex.data(), seal_key_hex.size());
    }

    bool authority_restored = false;
    bool msk_section_present = false;
    state_t* loaded = crabs_deserialize_state_keys_reported(
        data, body_len, seal_key_ptr,
        &authority_restored, &msk_section_present);
    // Staged key bytes never linger past the call, on every path.
    if (with_seal) OPENSSL_cleanse(seal_key, sizeof(seal_key));
    if (!loaded)
      throw Napi::Error::New(env,
          "deserialize: snapshot refused — malformed format, failed SHA-256 "
          "checksum, failed signature check, or an unloadable body");

    // Adoption mirrors the CLI's load (cli_node_load): a blob that carried a
    // user registry arrives as an attribute-machine SHELL (its attr_machine
    // points back at its own allocation) — adopt wholesale; a bare state is
    // wrapped in a fresh machine that takes over the state's owned members.
    // In both outcomes the base state keeps ownership of what came off the
    // wire and the previous machine keeps what it owns.
    attribute_machine_t* restored_machine;
    if (loaded->attr_machine != nullptr &&
        loaded->attr_machine == (attribute_machine_t*)loaded) {
      restored_machine = (attribute_machine_t*)loaded;
    } else {
      restored_machine = (attribute_machine_t*)get_clear_memory(
          sizeof(attribute_machine_t));
      if (!restored_machine) {
        state_destroy(loaded);
        throw Napi::Error::New(env,
            "deserialize: out of memory wrapping the restored state");
      }
      restored_machine->base_state = *loaded;   // shallow copy transfers ownership
      restored_machine->base_state.attr_machine = restored_machine;
      restored_machine->users = nullptr;
      restored_machine->user_count = 0;
      restored_machine->current_time_ms = 0;
      free(loaded);
    }

    attribute_machine_t* previous_machine = am_;
    bool previous_owned = !adopted_;

    // Continuity rewiring — the wrapper keeps its identity across the
    // restore. The wire serializes no secrets: re-apply the wrapper's own
    // node key (a borrowed wrapper owns no keypair, so a restored borrowed
    // machine carries NO node key and its signing surfaces fail closed).
    if (node_key_ != nullptr)
      state_set_node_key(&restored_machine->base_state,
                         node_key_->private_key, node_key_->public_key);
    // Ordering config + HLC continuity. Ordering config is wrapper-created
    // (ordering_config_ member) and NEVER serialized — the restored state
    // carries none, so the wrapper's machine-owned instance is re-applied
    // when the previous machine carried it (lock expiry and the other
    // ordering checks keep their configuration). The restored state's
    // hlc_state is zeroed; the restored machine's clock CONTINUES the
    // previous machine's HLC (last-issued timestamp, logical counter and
    // stats ride over — read BEFORE the previous machine is destroyed), so
    // the inbound-op skew validation stays engaged at the previous
    // machine's watermark. The config pointer check ties the re-apply to
    // THIS wrapper's own instance: a machine whose config came from
    // elsewhere (a borrowed previous machine of another wrapper) is not
    // re-pointed here.
    if (previous_machine->base_state.ordering_config != nullptr &&
        previous_machine->base_state.ordering_config == &ordering_config_) {
      state_set_ordering_config(&restored_machine->base_state,
                                &ordering_config_);
    }
    restored_machine->base_state.hlc_state =
        previous_machine->base_state.hlc_state;
    restored_machine->base_state.hlc_state_initialized =
        previous_machine->base_state.hlc_state_initialized;
    // Clock and raft module: the machine references them through raw
    // non-owning pointers, so the restore migrates the wrapper's instances
    // onto the restored machine (A borrowed previous machine loses both —
    // the same fail-closed consequence the wrapper's documented teardown
    // has; the owner must re-apply via its own wrapper).
    if (time_source_owned_ && time_source_ops_ != nullptr) {
      state_set_time_source(&previous_machine->base_state, NULL);
      state_set_time_source(&restored_machine->base_state, time_source_ops_);
    }
    if (raft_module_ != nullptr) {
      // Attaching re-imports the restored state's parsed v16 module snapshot
      // (its durable raft history) INTO the module object, exactly like the
      // C load flow demands. An unloadable snapshot (foreign module_id)
      // leaves the machine detached-but-snapshot-carrying for a later
      // re-attach rather than failing the restore.
      if (state_attach_raft_module(&restored_machine->base_state,
                                   raft_module_) == CRABS_SUCCESS)
        state_attach_raft_module(&previous_machine->base_state, NULL);
    }
    state_set_change_hook(&restored_machine->base_state,
                          _node_change_hook_thunk, this);

    // Ownership transfer: the wrapper now owns the restored machine and the
    // previous one is released only when it was wrapper-owned (mirrors the
    // destructor's ownership statement).
    if (previous_owned) attribute_machine_destroy(previous_machine);
    am_ = restored_machine;
    adopted_ = false;

    Napi::Object report = Napi::Object::New(env);
    report.Set("authorityRestored",
               Napi::Boolean::New(env, authority_restored));
    report.Set("mskSectionPresent",
               Napi::Boolean::New(env, msk_section_present));
    return report;
  }

  // Merge a foreign snapshot INTO this machine via crdt_merge_state (the
  // general item rules: counters max-per-node/sum-across-nodes, register
  // LWW, OR/2P-set union, one-shot take-any; ordered-set items merge in
  // place through crabs_ot_ordered_set_merge — recipe 8's layer; logs merge
  // by lamport time and dedupe by uuid). This machine MUTATES toward the
  // union; the source snapshot is untouched (it is never attached to a
  // machine). Throws — machine untouched — on a malformed snapshot. Held
  // items are NOT a failure: they surface as __merge_held__ divergences on
  // the machine's change hook ('merge' events) and the merge returns
  // SUCCESS (a same-op-id/different-payload ordered-set refusal held is
  // CRABS_ERR_FORK_DETECTED; OT document/tree/table/ordered-map items still
  // hold with CRABS_ERR_TYPE_MISMATCH).
  Napi::Value MergeState(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsBuffer())
      throw Napi::TypeError::New(env,
          "mergeState: expected a serialized state snapshot (Buffer)");
    Napi::Buffer<uint8_t> wire = info[0].As<Napi::Buffer<uint8_t>>();
    state_t* source_state = crabs_deserialize_state(wire.Data(), wire.Length());
    if (!source_state)
      throw Napi::Error::New(env,
          "mergeState: snapshot refused — malformed format or failed SHA-256 checksum");
    crabs_error_e rc = crdt_merge_state(&am_->base_state, source_state);
    state_destroy(source_state);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "mergeState");
    return env.Undefined();
  }

  // --- HLC ---

  // HLC watermark readback (parity-fill P10 semantics alignment): the
  // machine's LAST-issued timestamp, read-only — two consecutive reads are
  // identical, matching crabs-wasm's getHLC (crabs_wasm_get_hlc). The old
  // node behavior issued a NEXT timestamp per call; nothing consumed that
  // side effect (every sign/execute path stamps crabs_hlc_next explicitly,
  // including all of this binding's op drivers), while an advancing read
  // made the watermark non-idempotent and the P1 restore-continuity pins
  // impossible to mirror across bindings.
  Napi::Value GetHLC(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!am_->base_state.hlc_state_initialized)
      return env.Undefined();
    const crabs_hlc_t* hlc = &am_->base_state.hlc_state.last;
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("seconds", Napi::Number::New(env, (double)hlc->physical_seconds));
    obj.Set("nanos", Napi::Number::New(env, (double)hlc->physical_nanos));
    obj.Set("logicalCounter", Napi::Number::New(env, (double)hlc->logical_counter));
    obj.Set("nodeId", Napi::String::New(env, hlc->node_id));
    char fmt[128];
    crabs_hlc_format(hlc, fmt, sizeof(fmt));
    obj.Set("formatted", Napi::String::New(env, fmt));
    return obj;
  }

  Napi::Value SetTime(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1)
      throw Napi::TypeError::New(env, "setTime: nowMs is required");
    const uint64_t now_ms = require_u64_numeric(info[0], "setTime", "nowMs");
    attribute_machine_set_time(am_, now_ms);
    return env.Undefined();
  }

  Napi::Value PruneExpiredTempAttrs(const Napi::CallbackInfo& info) {
    // Mirrors the wasm readback: the caller can pin how many tokens the
    // prune removed (the execute pipeline's own prune reports through the
    // machine's behavior, not a count).
    uint32_t pruned = attribute_machine_prune_expired_temporary(am_);
    return Napi::Number::New(info.Env(), (double)pruned);
  }

  // --- Raft ordering module (GROUP_ORDERED writes) ---
  //
  // The reference host loop (timer, transport, storage seams) lives in the
  // JS wrapper (index.js RaftNodeHost); the native surface stays at the
  // module's own reactor boundary: attach/tick/deliver/drains + pump.
  // Mirrors the wasm binding 1:1 — same query shapes, same disposal
  // conventions (poll_outbound transfers; poll_persist reports a view).

  Napi::Value AttachRaft(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (raft_module_ != nullptr)
      throw Napi::Error::New(env, "attachRaft: a raft module is already attached");
    if (info.Length() < 1 || !info[0].IsObject())
      throw Napi::TypeError::New(env, "attachRaft: expected {nodeId?, peers, "
                                      "electionMinMs?, electionMaxMs?, heartbeatMs?, seed?}");
    Napi::Object opts = info[0].As<Napi::Object>();

    std::string node_id = opts.Has("nodeId") && opts.Get("nodeId").IsString()
        ? opts.Get("nodeId").As<Napi::String>().Utf8Value()
        : admin_id_;
    if (!opts.Has("peers") || !opts.Get("peers").IsArray())
      throw Napi::TypeError::New(env, "attachRaft: peers must be an id array");
    Napi::Array peers = opts.Get("peers").As<Napi::Array>();
    uint32_t peer_count = peers.Length();
    if (peer_count == 0 || peer_count > CRABS_RAFT_MAX_PEERS)
      throw Napi::RangeError::New(env, "attachRaft: peers must have 1..16 ids");

    std::vector<std::string> peer_ids;
    std::vector<const char*> peer_id_ptrs;
    // reserve() first: the char* pointers below borrow the strings' buffers
    // — a push_back reallocation would move (short ids are SSO) and dangle
    // the captured pointers.
    peer_ids.reserve(peer_count);
    peer_id_ptrs.reserve(peer_count);
    for (uint32_t index = 0; index < peer_count; index++) {
      peer_ids.push_back(require_js_string(peers.Get(index),
                                           "attachRaft.peers", "peer id"));
      peer_id_ptrs.push_back(peer_ids.back().c_str());
    }

    crabs_raft_config_t config;
    crabs_raft_config_defaults(&config);
    strncpy(config.node_id, node_id.c_str(), CRABS_MAX_USER_ID - 1);
    config.node_id[CRABS_MAX_USER_ID - 1] = '\0';
    config.peer_count = peer_count;
    for (uint32_t index = 0; index < peer_count; index++) {
      strncpy(config.peer_ids[index], peer_ids[index].c_str(),
              CRABS_MAX_USER_ID - 1);
      config.peer_ids[index][CRABS_MAX_USER_ID - 1] = '\0';
    }
    // read_u64: a missing/non-number/non-positive timer keeps the module
    // default; a present positive value is gated BEFORE the double→uint64
    // conversion (the old `value > 0 ? (uint64_t)value : fallback` cast a
    // huge or fractional double straight through the value > 0 branch —
    // out-of-range float→int UB or a silent truncation).
    auto read_u64 = [&](const char* key, uint64_t fallback) -> uint64_t {
      if (!opts.Has(key) || !opts.Get(key).IsNumber()) return fallback;
      const double value = opts.Get(key).As<Napi::Number>().DoubleValue();
      if (value <= 0) return fallback;
      if (!std::isfinite(value) || value >= 9007199254740992.0 ||
          value != floor(value))
        throw Napi::RangeError::New(env,
            std::string("attachRaft: ") + key +
            " must be an integer 0..2^53-1");
      return (uint64_t)value;
    };
    config.election_timeout_min_ms = read_u64("electionMinMs",
                                              config.election_timeout_min_ms);
    config.election_timeout_max_ms = read_u64("electionMaxMs",
                                              config.election_timeout_max_ms);
    config.heartbeat_interval_ms = read_u64("heartbeatMs",
                                            config.heartbeat_interval_ms);
    if (opts.Has("seed") && !opts.Get("seed").IsUndefined())
      config.seed = require_u64_numeric(opts.Get("seed"), "attachRaft", "seed");

    crabs_raft_module_t* module = crabs_raft_module_create(&config);
    if (!module) throw Napi::Error::New(env, "attachRaft: module create failed");
    crabs_error_e rc = state_attach_raft_module(&am_->base_state, module);
    if (rc != CRABS_SUCCESS) {
      crabs_raft_module_destroy(module);
      throw crabs_error(env, rc, "attachRaft");
    }
    raft_module_ = module;
    return info.This();
  }

  Napi::Value RaftTick(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    ensure_raft_attached(env, "raftTick");
    uint64_t now_ms = info.Length() > 0 && !info[0].IsUndefined()
        ? require_u64_numeric(info[0], "raftTick", "nowMs")
        : (uint64_t)(std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch()).count());
    auto rc = crabs_raft_module_tick(raft_module_, now_ms);
    return Napi::Number::New(env, (double)rc);
  }

  Napi::Value RaftDeliver(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    ensure_raft_attached(env, "raftDeliver");
    std::string peer_id = require_js_string(info[0], "raftDeliver", "peerId");
    if (info.Length() < 2 || !info[1].IsBuffer())
      throw Napi::TypeError::New(env, "raftDeliver: blob must be a Buffer");
    auto blob = info[1].As<Napi::Buffer<uint8_t>>();
    uint64_t now_ms = (uint64_t)(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    crabs_error_e rc = crabs_raft_module_inbound(
        raft_module_, peer_id.c_str(), blob.Data(), blob.Length(), now_ms);
    return Napi::Number::New(env, (double)rc);
  }

  Napi::Value RaftPersistComplete(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    ensure_raft_attached(env, "raftPersistComplete");
    if (info.Length() < 2 || !info[1].IsBoolean())
      throw Napi::TypeError::New(env, "raftPersistComplete: (handle, ok:boolean)");
    // require_u64_numeric covers the BigInt path WITH the lossless check
    // (the old code captured it and ignored it) and the number path with a
    // range/no-fraction gate before the conversion.
    const uint64_t handle =
        require_u64_numeric(info[0], "raftPersistComplete", "handle");
    crabs_error_e rc = crabs_raft_module_persist_complete(
        raft_module_, handle, info[1].As<Napi::Boolean>().Value());
    return Napi::Number::New(env, (double)rc);
  }

  // Crash recovery: replay one stored persist batch into the module's
  // durable state — the host's persist-batch record is the durable raft
  // history that survives a module/host restart whose machine blob is
  // stale (restored from a pre-commit snapshot). Corrupt/contradictory
  // batches fail closed per the C contract (Raft/raft_module.c); the rc is
  // returned and index.js surfaces it as a thrown error.
  Napi::Value RaftRecoverFromPersist(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    ensure_raft_attached(env, "raftRecoverFromPersist");
    if (info.Length() < 1 || !info[0].IsBuffer())
      throw Napi::TypeError::New(env,
        "raftRecoverFromPersist: stored batch must be a Buffer");
    auto batch = info[0].As<Napi::Buffer<uint8_t>>();
    crabs_error_e rc = crabs_raft_module_recover_from_persist(
        raft_module_, batch.Data(), batch.Length());
    return Napi::Number::New(env, (double)rc);
  }

  Napi::Value RaftPump(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    uint64_t now_ms = info.Length() > 0 && !info[0].IsUndefined()
        ? require_u64_numeric(info[0], "raftPump", "nowMs")
        : (uint64_t)(std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch()).count());
    auto rc = state_raft_process_notifications_at(&am_->base_state, now_ms);
    return Napi::Number::New(env, (double)rc);
  }

  Napi::Value RaftPollOutbound(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    ensure_raft_attached(env, "raftPollOutbound");
    Napi::Array out = Napi::Array::New(env);
    uint32_t index = 0;
    crabs_raft_outbound_message_t message;
    while (crabs_raft_module_poll_outbound(raft_module_, &message)) {
      // Ownership-transfer queue: the module hands the blob over, so copy
      // into a JS Buffer and release the transferred C bytes.
      Napi::Object entry = Napi::Object::New(env);
      entry.Set("kind", Napi::Number::New(env, (double)message.kind));
      entry.Set("to", Napi::String::New(env, message.to_peer));
      entry.Set("blob", Napi::Buffer<uint8_t>::Copy(env, message.bytes,
                                                    message.len));
      free(const_cast<uint8_t*>(message.bytes));
      out.Set(index++, entry);
    }
    return out;
  }

  Napi::Value RaftPollPersistRequest(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    ensure_raft_attached(env, "raftPollPersistRequest");
    crabs_raft_persist_request_t request;
    if (!crabs_raft_module_poll_persist(raft_module_, &request))
      return env.Undefined();
    // Report-only view: bytes copied into a JS Buffer; the window stays
    // module-open until raftPersistComplete(handle, ok).
    Napi::Object entry = Napi::Object::New(env);
    entry.Set("handle",
        Napi::BigInt::New(env, (int64_t)request.handle));
    entry.Set("blob", Napi::Buffer<uint8_t>::Copy(env, request.bytes, request.len));
    return entry;
  }

  Napi::Value RaftPollNotifications(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    ensure_raft_attached(env, "raftPollNotifications");
    Napi::Array out = Napi::Array::New(env);
    uint32_t index = 0;
    crabs_raft_notification_t notification;
    while (crabs_raft_module_poll_notification(raft_module_, &notification)) {
      Napi::Object entry = Napi::Object::New(env);
      entry.Set("kind", Napi::Number::New(env, (double)notification.kind));
      entry.Set("peerId", Napi::String::New(env, notification.peer_id));
      entry.Set("proposalId",
                Napi::Number::New(env, (double)notification.proposal_id));
      entry.Set("commitIndex",
                Napi::Number::New(env, (double)notification.commit_index));
      if (notification.op_len > 0 && notification.op_bytes != NULL) {
        entry.Set("opBytes",
                  Napi::Buffer<uint8_t>::Copy(env, notification.op_bytes,
                                              notification.op_len));
      } else {
        entry.Set("opBytes", env.Undefined());
      }
      out.Set(index++, entry);
    }
    return out;
  }

  Napi::Value RaftStatus(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (raft_module_ == nullptr) return env.Null();
    Napi::Object entry = Napi::Object::New(env);
    entry.Set("nodeId", Napi::String::New(env, admin_id_));
    entry.Set("isLeader", crabs_raft_module_is_leader(raft_module_));
    entry.Set("term", Napi::Number::New(env,
        (double)crabs_raft_module_current_term(raft_module_)));
    entry.Set("commitTip", Napi::Number::New(env,
        (double)crabs_raft_module_committed_tip(raft_module_)));
    entry.Set("logLength", Napi::Number::New(env,
        (double)crabs_raft_module_log_length(raft_module_)));
    entry.Set("configChangePending",
              crabs_raft_module_config_change_pending(raft_module_));
    char member_ids[CRABS_RAFT_MAX_PEERS][CRABS_MAX_USER_ID];
    entry.Set("peerCount", crabs_raft_module_committed_members(raft_module_,
                                                              member_ids));
    return entry;
  }

  // Joint-consensus membership change (Raft §6, parity-fill P9): the
  // leader appends the C_old,new joint entry to its OWN config log; when
  // committed it auto-appends the C_new successor, and that entry's commit
  // ends the transition (raft_module.h:216). ONE change at a time — an
  // appended-but-uncommitted entry or an active joint phase refuses with
  // CRABS_ERR_ORDERING_CHANGE_IN_FLIGHT. Throws crabsError on every refusal
  // (not-leader / in-flight / invalid members); returns the assigned
  // proposal_id (= the config entry's log index) on success.
  Napi::Value RaftChangeMembership(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    ensure_raft_attached(env, "raftChangeMembership");
    if (info.Length() < 1 || !info[0].IsArray())
      throw Napi::TypeError::New(env,
        "raftChangeMembership: members must be an id array");
    Napi::Array members = info[0].As<Napi::Array>();
    uint32_t member_count = members.Length();
    if (member_count == 0 || member_count > CRABS_RAFT_MAX_PEERS)
      throw Napi::RangeError::New(env,
        "raftChangeMembership: members must have 1..16 ids");
    // reserve() first: the char* array below borrows each string's buffer —
    // a push_back reallocation would move (short ids are SSO) and dangle
    // the already-captured pointers into freed memory.
    std::vector<std::string> member_ids;
    std::vector<const char*> member_ptrs;
    member_ids.reserve(member_count);
    member_ptrs.reserve(member_count);
    for (uint32_t index = 0; index < member_count; index++) {
      member_ids.push_back(require_js_string(
          members.Get(index), "raftChangeMembership.members", "member id"));
      member_ptrs.push_back(member_ids.back().c_str());
    }
    uint64_t proposal_id = 0;
    crabs_error_e rc = crabs_raft_module_change_membership(
        raft_module_, member_ptrs.data(), member_count, &proposal_id);
    if (rc != CRABS_SUCCESS) {
      throw crabs_error(env, rc, "raftChangeMembership");
    }
    return Napi::Number::New(env, (double)proposal_id);
  }

  // Membership queries (parity-fill P9): the ACTIVE committed config list
  // (the election/voting list) and the SECOND list of an active joint
  // consensus (empty while the cluster runs a plain single consensus) —
  // raft_module.h:264. Order is C config order (not sorted); callers sort.
  Napi::Value RaftCommittedMembers(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    ensure_raft_attached(env, "raftCommittedMembers");
    char member_ids[CRABS_RAFT_MAX_PEERS][CRABS_MAX_USER_ID];
    uint32_t count =
        crabs_raft_module_committed_members(raft_module_, member_ids);
    Napi::Array out = Napi::Array::New(env);
    for (uint32_t index = 0; index < count; index++) {
      out.Set(index, Napi::String::New(env, member_ids[index]));
    }
    return out;
  }

  Napi::Value RaftJointMembers(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    ensure_raft_attached(env, "raftJointMembers");
    char member_ids[CRABS_RAFT_MAX_PEERS][CRABS_MAX_USER_ID];
    uint32_t count =
        crabs_raft_module_joint_members(raft_module_, member_ids);
    Napi::Array out = Napi::Array::New(env);
    for (uint32_t index = 0; index < count; index++) {
      out.Set(index, Napi::String::New(env, member_ids[index]));
    }
    return out;
  }

  Napi::Value RaftDetach(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (raft_module_ == nullptr) return info.Env().Undefined();
    state_attach_raft_module(&am_->base_state, NULL);
    crabs_raft_module_destroy(raft_module_);
    raft_module_ = nullptr;
    return info.Env().Undefined();
  }

  Napi::Value GetAdminId(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), admin_id_);
  }

  // --- Authenticated time source (A10-L9 wiring, R7-01) ---
  //
  // setTimeSource({mode: 'https' | 'system', url?, resyncMs?, timeoutMs?,
  // maxSkewMs?}). The selection is machine-local configuration: adopted
  // child wrappers may call it too — each wrapper's machine has its own
  // state_t, so the source attaches to THIS wrapper's machine
  // (am_->base_state), whether or not this wrapper created that machine.
  //
  // 'system' detaches the machine from any authenticated source (back to
  // the local clock) and destroys the wrapper-owned ops. 'https' attaches
  // the built-in authenticated HTTPS time source. NO fetch happens at
  // attach time — the first query runs lazily inside authenticated-time
  // checks (state_get_time_ms), and a fetch failure makes the machine
  // report invalid time (fail closed, R7-02), never local-clock fallback.
  Napi::Value SetTimeSource(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsObject())
      throw Napi::TypeError::New(env,
          "setTimeSource: expected an options object {mode, url?, ...}");
    Napi::Object opts = info[0].As<Napi::Object>();
    if (!opts.Has("mode") || !opts.Get("mode").IsString())
      throw Napi::TypeError::New(env,
          "setTimeSource: mode must be 'https' or 'system'");
    std::string mode = opts.Get("mode").As<Napi::String>().Utf8Value();

    if (mode == "system") {
      state_set_time_source(&am_->base_state, NULL);
      if (time_source_owned_ && time_source_ops_ != nullptr) {
        crabs_time_source_destroy(time_source_ops_);
      }
      time_source_ops_ = nullptr;
      time_source_owned_ = false;
      time_source_https_ = false;
      time_source_url_.clear();
      return env.Undefined();
    }
    if (mode != "https")
      throw Napi::TypeError::New(env,
          "setTimeSource: mode must be 'https' or 'system'");

    // Validation first — a rejected call must change NOTHING on the machine
    // (mirrors the CLI's reject-before-mutating contract).
    std::string url;
    bool has_url = false;
    if (opts.Has("url") && !opts.Get("url").IsUndefined() &&
        !opts.Get("url").IsNull()) {
      url = require_js_string(opts.Get("url"), "setTimeSource", "url");
      has_url = true;
      // Same checks as the CLI (`time-source https <url>`): https scheme,
      // a non-empty host (no leading '/' or ':'), max 255 chars.
      if (url.compare(0, 8, "https://") != 0 || url.size() < 9 ||
          url[8] == '/' || url[8] == ':')
        throw Napi::RangeError::New(env,
            "setTimeSource: url must be https://<host>[/path] (got '" + url +
            "')");
      if (url.size() > 255)
        throw Napi::RangeError::New(env,
            "setTimeSource: url too long (max 255 chars)");
    }

    // Creator-defaults subtlety (time_source.h): a NON-NULL config's scalar
    // fields are used AS-IS — 0 is meaningful (resync 0 = re-query on every
    // fetch; max_skew 0 disables the plausibility check), NOT "use the
    // default". So omitted numbers must be spelled out as the documented
    // CRABS_TIME_SOURCE_DEFAULT_* values; only server_url maps NULL -> the
    // default endpoint. A passed-in 0 is kept as 0 (the caller asked for
    // the chatty variant on purpose).
    uint64_t resync_ms = CRABS_TIME_SOURCE_DEFAULT_RESYNC_MS;
    uint64_t timeout_ms = CRABS_TIME_SOURCE_DEFAULT_TIMEOUT_MS;
    uint64_t max_skew_ms = CRABS_TIME_SOURCE_DEFAULT_MAX_SKEW_MS;
    struct { const char* field; uint64_t* out; } numeric_fields[] = {
      {"resyncMs", &resync_ms},
      {"timeoutMs", &timeout_ms},
      {"maxSkewMs", &max_skew_ms},
    };
    for (const auto& numeric : numeric_fields) {
      if (!opts.Has(numeric.field) || opts.Get(numeric.field).IsUndefined() ||
          opts.Get(numeric.field).IsNull())
        continue;
      Napi::Value field_value = opts.Get(numeric.field);
      if (!field_value.IsNumber())
        throw Napi::TypeError::New(env,
            std::string("setTimeSource: ") + numeric.field +
            " must be a number");
      double field_number = field_value.As<Napi::Number>().DoubleValue();
      // NaN fails the >= 0 test; values >= 2^64 cannot be cast to uint64_t
      // without UB, so bound the range before the conversion.
      if (!(field_number >= 0.0) || !(field_number < 18446744073709551616.0))
        throw Napi::RangeError::New(env,
            std::string("setTimeSource: ") + numeric.field +
            " must be a non-negative number of milliseconds");
      *numeric.out = (uint64_t)field_number;
    }

    crabs_time_source_config_t config;
    config.server_url = has_url ? url.c_str() : NULL;  // copied by create()
    config.resync_interval_ms = resync_ms;
    config.timeout_ms = timeout_ms;
    config.max_skew_ms = max_skew_ms;
    crabs_time_source_ops_t* fresh = crabs_time_source_https_create(&config);
    if (fresh == nullptr) {
      // Allocation failure: leave the machine on NO source rather than
      // silently on the system clock (fail closed, R7-02), and drop the
      // stale ops — mirrors the CLI's behavior on create failure.
      state_set_time_source(&am_->base_state, NULL);
      if (time_source_owned_ && time_source_ops_ != nullptr) {
        crabs_time_source_destroy(time_source_ops_);
      }
      time_source_ops_ = nullptr;
      time_source_owned_ = false;
      time_source_https_ = false;
      time_source_url_.clear();
      throw Napi::Error::New(env,
          "setTimeSource: could not create the HTTPS time source");
    }
    // Attach the fresh source, THEN retire the old owned ops (the old
    // monotonic anchor belonged to the previous selection anyway).
    state_set_time_source(&am_->base_state, fresh);
    if (time_source_owned_ && time_source_ops_ != nullptr) {
      crabs_time_source_destroy(time_source_ops_);
    }
    time_source_ops_ = fresh;
    time_source_owned_ = true;
    time_source_https_ = true;
    time_source_url_ = has_url ? url : std::string();
    time_source_resync_ms_ = resync_ms;
    time_source_timeout_ms_ = timeout_ms;
    time_source_max_skew_ms_ = max_skew_ms;
    return env.Undefined();
  }

  // getTimeSource() reports the wrapper's stored selection:
  //   { mode: 'system' } or
  //   { mode: 'https', url, resyncMs, timeoutMs, maxSkewMs, created }
  // `url` is the configured endpoint or null (default endpoint); `created`
  // is true while the wrapper-owned ops object is live.
  Napi::Value GetTimeSource(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);
    if (!time_source_https_) {
      result.Set("mode", Napi::String::New(env, "system"));
      return result;
    }
    result.Set("mode", Napi::String::New(env, "https"));
    if (time_source_url_.empty()) {
      result.Set("url", env.Null());
    } else {
      result.Set("url", Napi::String::New(env, time_source_url_));
    }
    result.Set("resyncMs",
               Napi::Number::New(env, (double)time_source_resync_ms_));
    result.Set("timeoutMs",
               Napi::Number::New(env, (double)time_source_timeout_ms_));
    result.Set("maxSkewMs",
               Napi::Number::New(env, (double)time_source_max_skew_ms_));
    result.Set("created",
               Napi::Boolean::New(env, time_source_ops_ != nullptr));
    return result;
  }

  // --- Lineage (v1.7: machines mint machines) ---

  // Register the five __lineage__ op types, their default role:admin policies
  // and their handlers on this machine. Idempotent in C; call once after
  // machine creation. Also the route a spawned child takes to become able to
  // submit __receive_dissolution__.
  void LineageInstall(const Napi::CallbackInfo& info) {
    lineage_install(&am_->base_state);
  }

  // Instantiate a child machine from a validated blueprint. The returned
  // Node BORROWS the spawned machine — this wrapper owns it (destroyed when
  // this wrapper is collected), mirroring the wasm binding's
  // resident-registry ownership statement.
  Napi::Value LineageSpawn(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsObject())
      throw Napi::TypeError::New(env, "Expected Blueprint");
    Blueprint* blueprint_wrapper = Blueprint::Unwrap(info[0].As<Napi::Object>());
    machine_blueprint_t* blueprint = blueprint_wrapper->raw();
    if (blueprint == nullptr)
      throw Napi::Error::New(env, "lineageSpawn: blueprint already destroyed");
    attribute_machine_t* spawned_machine = NULL;
    crabs_error_e rc = lineage_spawn_machine(&am_->base_state, blueprint,
                                             &spawned_machine);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "lineageSpawn");
    spawned_machines_.push_back(spawned_machine);
    return WrapMachine(env, spawned_machine, info.This().As<Napi::Object>());
  }

  // Borrowed view over the child manifest:
  // [{ childId, mode, status, spawnedAtMs, attestationTtlMs }, ...] — mode
  // and status rendered with the C single-source name helpers (the same
  // strings the CLI and wasm devtools show).
  Napi::Value LineageChildren(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    const child_manifest_entry_t* entries = NULL;
    uint32_t entry_count = lineage_query_children(&am_->base_state, &entries);
    Napi::Array child_array = Napi::Array::New(env, entry_count);
    for (uint32_t entry_index = 0; entry_index < entry_count; entry_index++) {
      const child_manifest_entry_t* entry = &entries[entry_index];
      Napi::Object child_entry = Napi::Object::New(env);
      child_entry.Set("childId", Napi::String::New(env, entry->child_id));
      child_entry.Set("mode", Napi::String::New(env,
                                                 lineage_mode_name(entry->mode)));
      child_entry.Set("status", Napi::String::New(env,
                                                   lineage_status_name(entry->status)));
      child_entry.Set("spawnedAtMs",
                      Napi::Number::New(env, (double)entry->spawned_at));
      child_entry.Set("attestationTtlMs",
                      Napi::Number::New(env, (double)entry->attestation_ttl_ms));
      child_array.Set(entry_index, child_entry);
    }
    return child_array;
  }

  // The machine this parent spawned and still holds resident in-process, or
  // null when unknown / dissolved (the dissolve op drops the registry slot).
  // The wrapper BORROWS the machine — the parent keeps it alive.
  Napi::Value LineageResidentChild(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString())
      throw Napi::TypeError::New(env, "Expected childId string");
    std::string child_id = info[0].As<Napi::String>().Utf8Value();
    attribute_machine_t* resident_machine =
        lineage_query_resident_child(&am_->base_state, child_id.c_str());
    if (resident_machine == NULL) return env.Null();
    return WrapMachine(env, resident_machine, info.This().As<Napi::Object>());
  }

  // Parent-signed, TTL-bounded attribute grant for a manifestable child.
  // Returns the attestation WIRE image (u32le length + canonical body +
  // signature) as a Buffer. The parent's own machine identity signs (the
  // node key); `now_ms` comes from the machine's authenticated time source
  // (setTime or an attached time-source).
  Napi::Value LineageAttest(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString())
      throw Napi::TypeError::New(env, "Expected (childId, userId[, attributes])");
    std::string child_id = info[0].As<Napi::String>().Utf8Value();
    std::string user_id = info[1].As<Napi::String>().Utf8Value();
    std::string attributes = info.Length() > 2 && info[2].IsString()
        ? info[2].As<Napi::String>().Utf8Value() : std::string("");
    uint64_t now_ms = 0;
    if (!state_get_time_ms(&am_->base_state, &now_ms))
      throw Napi::Error::New(env,
          "lineageAttest: machine has no authenticated time source — call setTime first");
    attestation_t attestation;
    memset(&attestation, 0, sizeof(attestation));
    crabs_error_e rc = crabs_issue_attestation(&am_->base_state, &attestation,
                                               child_id.c_str(), user_id.c_str(),
                                               attributes.c_str(), now_ms);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "lineageAttest");
    uint8_t wire[CRABS_ATTESTATION_WIRE_MAX];
    size_t wire_len = attestation_serialize(&attestation, wire, sizeof(wire));
    // attestation_destroy free()s its argument — it is only for heap
    // attestations from attestation_deserialize. `attestation` here is a
    // stack struct crabs_issue_attestation filled inline (signature is a
    // fixed array), so there is nothing to release.
    if (wire_len == 0)
      throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "lineageAttest");
    return Napi::Buffer<uint8_t>::Copy(env, wire, wire_len);
  }

  // Off-chain dissolution proof for an already-DISSOLVED child: canonical
  // tombstone body (`u8 LINEAGE_DISSOLVED tag + string16 childId + u64le
  // parent_key_version key-stamp`) + the
  // 64-byte parent ECDSA — the exact bytes a __receive_dissolution__ op
  // transports. The honesty gate (never sign a tombstone for a live child)
  // maps to typed errors: resource_not_found for an unknown child,
  // unauthorized for a not-yet-dissolved one, cryptographic_error when the
  // node key is missing or signing fails.
  Napi::Value LineageTombstone(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString())
      throw Napi::TypeError::New(env, "Expected childId string");
    std::string child_id = info[0].As<Napi::String>().Utf8Value();
    uint8_t wire[CRABS_DISSOLUTION_WIRE_MAX];
    size_t wire_len = 0;
    crabs_error_e rc = lineage_dissolution_serialize(&am_->base_state,
                                                     child_id.c_str(), wire,
                                                     sizeof(wire), &wire_len);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "lineageTombstone");
    return Napi::Buffer<uint8_t>::Copy(env, wire, wire_len);
  }

  // Rotate this machine's lineage parent key (lineage_key_rotate,
  // lineage.h:285) and return the signed transition record Buffer:
  // old_pk + new_pk + created_at + 64-byte ECDSA over the body. The C
  // contract says the CALLER pairs the rotation with state_set_node_key —
  // the wrapper does both, so a stashed record whose new private key never
  // landed cannot happen. Every child bound to this parent takes the SAME
  // record through lineageAcceptKeyTransition (the broadcast feature;
  // A11-L1 says deliver to every child BEFORE minting the next rotation —
  // one stash slot). now_ms stamps the record's informational created_at
  // from the machine's own time source, exactly like lineageAttest.
  Napi::Value LineageRotateKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsObject())
      throw Napi::TypeError::New(env, "Expected lineageRotateKey(keyPair)");
    KeyPair* key_pair = KeyPair::Unwrap(info[0].As<Napi::Object>());
    if (key_pair == nullptr || key_pair->raw() == nullptr)
      throw Napi::Error::New(env, "lineageRotateKey: expected a KeyPair");
    uint64_t now_ms = 0;
    if (!state_get_time_ms(&am_->base_state, &now_ms))
      throw Napi::Error::New(env,
          "lineageRotateKey: machine has no authenticated time source — call setTime first");
    const ecdsa_keypair_t* new_key = key_pair->raw();
    uint8_t* record = nullptr;
    size_t record_len = 0;
    crabs_error_e rc = lineage_key_rotate(&am_->base_state,
                                          new_key->private_key,
                                          new_key->public_key, now_ms,
                                          &record, &record_len);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "lineageRotateKey");
    state_set_node_key(&am_->base_state, new_key->private_key,
                       new_key->public_key);
    Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::Copy(env, record,
                                                            record_len);
    free(record);
    return out;
  }

  // Child side: ingest a parent-minted transition record (the exact bytes
  // lineageRotateKey returned, transported verbatim). The C gate owns every
  // refusal and they surface typed: invalid_param (malformed image, wrong
  // parent_id, rollback/replay gap), unauthorized (machine not bound to a
  // parent, or lineage dissolved), cryptographic_error (record not signed
  // by the chain TIP, or tip-signature failure), already_performed (an
  // exact re-delivery of an accepted record, A11-L5).
  Napi::Value LineageAcceptKeyTransition(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsBuffer())
      throw Napi::TypeError::New(env,
          "Expected lineageAcceptKeyTransition(recordBuffer)");
    auto record = info[0].As<Napi::Buffer<uint8_t>>();
    if (record.Length() == 0)
      throw Napi::RangeError::New(env,
          "lineageAcceptKeyTransition: the record buffer is empty");
    crabs_error_e rc = lineage_child_accept_key_transition(
        &am_->base_state, record.Data(),
        (size_t)record.Length());
    if (rc != CRABS_SUCCESS)
      throw crabs_error(env, rc, "lineageAcceptKeyTransition");
    return env.Undefined();
  }

  // Parse a parent-issued attestation wire image (as produced by
  // lineageAttest) into the field shape Operation.addAttestation consumes
  // with NO verdict — parse-only (attestation_deserialize, lineage.h:666):
  // verification happens at op attach/execution, where the executor
  // re-checks the chain-TIP signature, both ids, the window, and attribute
  // coverage. Malformed input refuses typed (never a partial parse).
  Napi::Value AttestationFromWire(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsBuffer())
      throw Napi::TypeError::New(env,
          "Expected attestationFromWire(attestationWireBuffer)");
    auto wire = info[0].As<Napi::Buffer<uint8_t>>();
    if (wire.Length() == 0)
      throw Napi::RangeError::New(env,
          "attestationFromWire: the wire buffer is empty");
    attestation_t* attestation =
        attestation_deserialize(wire.Data(), (size_t)wire.Length());
    if (attestation == nullptr)
      throw Napi::Error::New(env,
          "attestationFromWire: malformed attestation wire image (structure check failed)");
    Napi::Object fields = Napi::Object::New(env);
    fields.Set("parentId", Napi::String::New(env, attestation->parent_id));
    fields.Set("childId", Napi::String::New(env, attestation->child_id));
    fields.Set("userId", Napi::String::New(env, attestation->user_id));
    fields.Set("attributes", Napi::String::New(env, attestation->attributes));
    // Stamps ride as BigInts — same as the wasm binding and the inbound
    // addAttestation side (this used to double-cast through (double), the
    // only leg of the wire that silently lost precision past 2^53).
    fields.Set("notBefore", Napi::BigInt::New(env, attestation->not_before));
    fields.Set("expiresAt", Napi::BigInt::New(env, attestation->expires_at));
    fields.Set("parentKeyVersion",
               Napi::BigInt::New(env, attestation->parent_key_version));
    fields.Set("signatureHex",
               Napi::String::New(env, hex_encode(attestation->signature,
                                                 CRABS_SIG_SIZE)));
    attestation_destroy(attestation);
    return fields;
  }
};

// C change-hook trampoline: forward-declared before Node so the constructor
// can register it; defined here so it can reach Node::EmitChange.
static void _node_change_hook_thunk(state_t* state,
                                    const crabs_change_event_t* event,
                                    void* user_data) {
  (void)state;
  static_cast<Node*>(user_data)->EmitChange(event);
}

// ============================================================
// Module initialization
// ============================================================

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  // Shared instance data (persistent per-class constructor references) must
  // exist before the class inits store into it.
  env.SetInstanceData(new NodeAddonInstanceData());
  KeyPair::Init(env, exports);
  AbeKey::Init(env, exports);
  Blueprint::Init(env, exports);
  Operation::Init(env, exports);
  Node::Init(env, exports);

  // Enum constant tables, mirroring the wasm bindings' tables — the same
  // naming blueprint fields take in wire form.
  Napi::Object trust_mode = Napi::Object::New(env);
  trust_mode.Set("SHARED_ROOT", (double)LINEAGE_SHARED_ROOT);
  trust_mode.Set("DELEGATED_COPY", (double)LINEAGE_DELEGATED_COPY);
  trust_mode.Set("SOVEREIGN", (double)LINEAGE_SOVEREIGN);
  exports.Set("TRUST_MODE", trust_mode);

  Napi::Object data_type = Napi::Object::New(env);
  data_type.Set("COUNTER", (double)DATA_TYPE_COUNTER);
  data_type.Set("PN_COUNTER", (double)DATA_TYPE_PN_COUNTER);
  data_type.Set("SET", (double)DATA_TYPE_SET);
  data_type.Set("REGISTER", (double)DATA_TYPE_REGISTER);
  data_type.Set("RESOURCE", (double)DATA_TYPE_RESOURCE);
  data_type.Set("ONE_SHOT_SET", (double)DATA_TYPE_ONE_SHOT_SET);
  data_type.Set("ONE_SHOT_FLAG", (double)DATA_TYPE_ONE_SHOT_FLAG);
  // OT_ORDERED_SET is surfaced (recipe 8): addOrderedSet + the ordered*
  // sugar build real OT items; the other OT words stay parse-only.
  data_type.Set("OT_ORDERED_SET", (double)DATA_TYPE_OT_ORDERED_SET);
  data_type.Set("CUSTOM", (double)DATA_TYPE_CUSTOM);
  exports.Set("DATA_TYPE", data_type);

  Napi::Object crdt_type = Napi::Object::New(env);
  crdt_type.Set("G_COUNTER", (double)CRDT_G_COUNTER);
  crdt_type.Set("PN_COUNTER", (double)CRDT_PN_COUNTER);
  crdt_type.Set("OR_SET", (double)CRDT_OR_SET);
  crdt_type.Set("LWW_REG", (double)CRDT_LWW_REG);
  crdt_type.Set("ONE_SHOT_SET", (double)CRDT_ONE_SHOT_SET);
  crdt_type.Set("ONE_SHOT_FLAG", (double)CRDT_ONE_SHOT_FLAG);
  crdt_type.Set("CUSTOM", (double)CRDT_CUSTOM);
  exports.Set("CRDT_TYPE", crdt_type);

  // Wire-version diagnostics (consumption-fixes finding 5): the three
  // active versions mirrored from the C library — no JS hardcoding, no
  // drift between wrapper and library.
  Napi::Object wire_versions = Napi::Object::New(env);
  wire_versions.Set("state", (double)CRABS_SERIAL_VERSION);
  wire_versions.Set("op", (double)CRABS_OP_FORMAT_VERSION);
  wire_versions.Set("signing", (double)CRABS_SIGNING_FORMAT_VERSION);
  exports.Set("wireVersions", wire_versions);

  return exports;
}

NODE_API_MODULE(crabs_node, Init)