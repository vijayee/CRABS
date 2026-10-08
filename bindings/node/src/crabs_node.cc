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
#include "TimeSource/time_source.h"
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

static Napi::Error crabs_error(Napi::Env env, crabs_error_e err, const char* ctx) {
  const char* msg;
  switch (err) {
    case CRABS_SUCCESS:                    msg = "success"; break;
    case CRABS_ERR_PROTOCOL_VIOLATION:     msg = "protocol_violation"; break;
    case CRABS_ERR_LOCK_TOKEN_MISMATCH:    msg = "lock_token_mismatch"; break;
    case CRABS_ERR_LOCK_OWNER_MISMATCH:    msg = "lock_owner_mismatch"; break;
    case CRABS_ERR_LOCK_CONTENTION:        msg = "lock_contention"; break;
    case CRABS_ERR_LOCK_NOT_EXPIRED:       msg = "lock_not_expired"; break;
    case CRABS_ERR_MAX_EXTENSIONS_REACHED: msg = "max_extensions_reached"; break;
    case CRABS_ERR_FORCE_UNLOCK_DISABLED:  msg = "force_unlock_disabled"; break;
    case CRABS_ERR_UNAUTHORIZED:           msg = "unauthorized"; break;
    case CRABS_ERR_KEY_STALE:             msg = "key_stale"; break;
    case CRABS_ERR_USER_NOT_FOUND:         msg = "user_not_found"; break;
    case CRABS_ERR_USER_SUSPENDED:         msg = "user_suspended"; break;
    case CRABS_ERR_INVARIANT_VIOLATED:     msg = "invariant_violated"; break;
    case CRABS_ERR_RESOURCE_NOT_FOUND:     msg = "resource_not_found"; break;
    case CRABS_ERR_DUPLICATE_OPERATION:    msg = "duplicate_operation"; break;
    case CRABS_ERR_TYPE_MISMATCH:          msg = "type_mismatch"; break;
    case CRABS_ERR_ALREADY_PERFORMED:      msg = "already_performed"; break;
    case CRABS_ERR_ALREADY_EXECUTED:       msg = "already_executed"; break;
    case CRABS_ERR_CONDITION_NOT_MET:      msg = "condition_not_met"; break;
    case CRABS_ERR_TRACKER_NOT_FOUND:      msg = "tracker_not_found"; break;
    case CRABS_ERR_FLAG_NOT_FOUND:         msg = "flag_not_found"; break;
    case CRABS_ERR_SERIALIZATION_ERROR:    msg = "serialization_error"; break;
    case CRABS_ERR_CRYPTOGRAPHIC_ERROR:    msg = "cryptographic_error"; break;
    case CRABS_ERR_INTERNAL:               msg = "internal_error"; break;
    case CRABS_ERR_OOM:                    msg = "out_of_memory"; break;
    case CRABS_ERR_INVALID_PARAM:          msg = "invalid_param"; break;
    default:                               msg = "unknown_error"; break;
  }
  std::string full = std::string(ctx) + ": " + msg;
  return Napi::Error::New(env, full);
}

// Persistent per-class constructor references. Static factories
// (KeyPair.generate, Blueprint.create/deserialize) and Node's borrowed-child
// wrapper mint instances through these — the single env instance-data slot
// carries them all.
struct NodeAddonInstanceData {
  Napi::FunctionReference key_pair_ctor;
  Napi::FunctionReference blueprint_ctor;
  Napi::FunctionReference node_ctor;
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

static std::string to_lower_ascii(const std::string& value) {
  std::string lowered = value;
  for (char& ch : lowered) {
    if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
  }
  return lowered;
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
    if (!hex_decode(hex, kp->kp_->private_key, 32))
      throw Napi::Error::New(env, "Invalid private key hex (expected 64 chars)");
    // Derive public key from private key
    crabs_error_e rc = crypto_ecdsa_derive_public_key(kp->kp_->private_key, kp->kp_->public_key);
    if (rc != CRABS_SUCCESS) {
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
    if (!hex_decode(hex, priv, 32))
      throw Napi::Error::New(env, "Invalid private key hex");
    crabs_error_e rc = crypto_ecdsa_derive_public_key(priv, pub);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "derivePublicHex");
    return Napi::String::New(env, hex_encode(pub, 33));
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
    if (!info[3].IsNumber())
      throw Napi::TypeError::New(env, "ttlMs must be a number");
    uint64_t attestation_ttl_ms =
        (uint64_t)info[3].As<Napi::Number>().DoubleValue();

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
      throw Napi::TypeError::New(env, "Expected (name, dataType, crdtType)");
    std::string name = info[0].As<Napi::String>().Utf8Value();
    data_type_e data_type;
    crdt_type_e crdt_type;
    if (!data_type_from_js(info[1], &data_type))
      throw Napi::TypeError::New(env,
          "dataType must be a DATA_TYPE word ('counter', 'set', ...) or number");
    if (!crdt_type_from_js(info[2], &crdt_type))
      throw Napi::TypeError::New(env,
          "crdtType must be a CRDT_TYPE word ('g_counter', 'or_set', ...) or number");
    crabs_error_e rc = blueprint_add_item(bp_, name.c_str(), data_type, crdt_type);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "Blueprint.addItem");
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

// ============================================================
// Operation — wraps operation_t
// ============================================================

class Operation : public Napi::ObjectWrap<Operation> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "Operation", {
      InstanceMethod("sign", &Operation::Sign),
      InstanceMethod("signWithPrivateKey", &Operation::SignWithPrivateKey),
      InstanceAccessor("type", &Operation::GetType, &Operation::SetType),
      InstanceAccessor("signerId", &Operation::GetSignerId, &Operation::SetSignerId),
      InstanceAccessor("nodeId", &Operation::GetNodeId, &Operation::SetNodeId),
      InstanceAccessor("payload", &Operation::GetPayload, &Operation::SetPayload),
      InstanceAccessor("lamportTime", &Operation::GetLamportTime, &Operation::SetLamportTime),
    });
    exports.Set("Operation", func);
    return exports;
  }

  Operation(const Napi::CallbackInfo& info) : Napi::ObjectWrap<Operation>(info) {
    std::string type = "unknown";
    if (info.Length() > 0 && info[0].IsString())
      type = info[0].As<Napi::String>().Utf8Value();
    op_ = operation_create(type.c_str());
    if (!op_) throw Napi::Error::New(info.Env(), "Failed to create operation");
    // Generate a random UUID so the idempotency check in state_machine_execute
    // doesn't treat this as a duplicate of a prior operation (all-zeros UUID
    // would match any prior all-zeros UUID, causing the op to be silently
    // skipped before trigger processing).
    crypto_random_bytes(op_->uuid, CRABS_UUID_SIZE);
  }

  ~Operation() {
    if (op_) operation_destroy(op_);
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
  void SetLamportTime(const Napi::CallbackInfo& info, const Napi::Value& val) {
    op_->lamport_time = (uint64_t)val.As<Napi::Number>().DoubleValue();
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
    // exit from this buffer is scrubbed.
    if (!hex_decode(hex, priv, 32)) {
      OPENSSL_cleanse(priv, 32);
      throw Napi::Error::New(env, "Invalid private key hex");
    }
    serialized_buffer_t* ser = crabs_serialize_for_signing(op_);
    if (!ser) {
      OPENSSL_cleanse(priv, 32);
      throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "sign");
    }
    crabs_error_e rc = crypto_ecdsa_sign(priv, ser->data, ser->len, op_->signature);
    serialized_buffer_destroy(ser);
    OPENSSL_cleanse(priv, 32);
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
      InstanceMethod("getUser", &Node::GetUser),
      InstanceMethod("getNodeKey", &Node::GetNodeKey),
      InstanceMethod("addCounter", &Node::AddCounter),
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
      InstanceMethod("setAdd", &Node::SetAdd),
      InstanceMethod("setRemove", &Node::SetRemove),
      InstanceMethod("flagSet", &Node::FlagSet),
      InstanceMethod("flagValue", &Node::FlagValue),
      InstanceMethod("setPolicy", &Node::SetPolicy),
      InstanceMethod("execute", &Node::Execute),
      InstanceMethod("on", &Node::On),
      InstanceMethod("sign", &Node::SignOp),
      InstanceMethod("createTrigger", &Node::CreateTrigger),
      InstanceMethod("encrypt", &Node::Encrypt),
      InstanceMethod("serialize", &Node::Serialize),
      InstanceMethod("getHLC", &Node::GetHLC),
      InstanceMethod("setTime", &Node::SetTime),
      InstanceMethod("pruneExpiredTempAttrs", &Node::PruneExpiredTempAttrs),
      // Lineage (v1.7: machines mint machines)
      InstanceMethod("lineageInstall", &Node::LineageInstall),
      InstanceMethod("lineageSpawn", &Node::LineageSpawn),
      InstanceMethod("lineageChildren", &Node::LineageChildren),
      InstanceMethod("lineageResidentChild", &Node::LineageResidentChild),
      InstanceMethod("lineageAttest", &Node::LineageAttest),
      InstanceMethod("lineageTombstone", &Node::LineageTombstone),
      // Authenticated time source (A10-L9 wiring)
      InstanceMethod("setTimeSource", &Node::SetTimeSource),
      InstanceMethod("getTimeSource", &Node::GetTimeSource),
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

    // Parse options: { ordering: 'hlc' | 'lamport', strategy: 'bounded' | ... }
    bool use_hlc = true;  // Default to HLC (user requested hybrid time)
    if (info.Length() > 1 && info[1].IsObject()) {
      Napi::Object opts = info[1].As<Napi::Object>();
      if (opts.Has("ordering")) {
        std::string ord = require_js_string(opts.Get("ordering"),
                                            "Node", "ordering");
        use_hlc = (ord == "hlc");
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

  Napi::Value AddCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addCounter", "name");
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_COUNTER, CRDT_G_COUNTER);
    item->value = g_counter_create();
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addCounter");
    return env.Undefined();
  }

  Napi::Value AddPNCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addPNCounter", "name");
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_PN_COUNTER, CRDT_PN_COUNTER);
    item->value = pn_counter_create();
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addPNCounter");
    return env.Undefined();
  }

  Napi::Value AddORSet(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addORSet", "name");
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_SET, CRDT_OR_SET);
    item->value = or_set_create();
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addORSet");
    return env.Undefined();
  }

  Napi::Value AddOneShotSet(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addOneShotSet", "name");
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
    item->value = one_shot_set_create();
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addOneShotSet");
    return env.Undefined();
  }

  Napi::Value AddOneShotFlag(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addOneShotFlag", "name");
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
    item->value = one_shot_flag_create();
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
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addRegister");
    return env.Undefined();
  }

  Napi::Value AddResource(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = require_js_string(info[0], "addResource", "name");
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
    item->value = pn_counter_create();
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addResource");
    return env.Undefined();
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
    int64_t value = (int64_t)info[1].As<Napi::Number>().Int64Value();
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
    uint64_t setAt = info.Length() > 2 ? (uint64_t)info[2].As<Napi::Number>().DoubleValue() : 0;
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
      // leaves a prefix of the caller's key bytes on the stack.
      if (!hex_decode(hex, priv, 32)) {
        OPENSSL_cleanse(priv, 32);
        throw Napi::Error::New(env, "Invalid private key hex");
      }
      serialized_buffer_t* ser = crabs_serialize_for_signing(op->raw());
      if (!ser) {
        OPENSSL_cleanse(priv, 32);
        throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "sign");
      }
      crabs_error_e rc = crypto_ecdsa_sign(priv, ser->data, ser->len, op->raw()->signature);
      serialized_buffer_destroy(ser);
      OPENSSL_cleanse(priv, 32);
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
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "execute");
    return env.Undefined();
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
    uint64_t cooldown = cfg.Has("cooldownMs") ? (uint64_t)cfg.Get("cooldownMs").As<Napi::Number>().DoubleValue() : 0;
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
      uint64_t duration = cfg.Has("durationMs") ? (uint64_t)cfg.Get("durationMs").As<Napi::Number>().DoubleValue() : 0;
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
    strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);
    strncpy(op->node_id, "admin", CRABS_MAX_USER_ID - 1);

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

  // --- ABE encryption ---

  Napi::Value Encrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2)
      throw Napi::TypeError::New(env, "Expected (payload, policy)");
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

  // --- Serialization ---

  Napi::Value Serialize(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    serialized_buffer_t* ser = crabs_serialize_state(&am_->base_state);
    if (!ser) throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "serialize");
    Napi::Buffer<uint8_t> buf = Napi::Buffer<uint8_t>::Copy(env, ser->data, ser->len);
    serialized_buffer_destroy(ser);
    return buf;
  }

  // --- HLC ---

  Napi::Value GetHLC(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!am_->base_state.hlc_state_initialized)
      return env.Undefined();
    crabs_hlc_t hlc = crabs_hlc_next(&am_->base_state.hlc_state);
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("seconds", Napi::Number::New(env, (double)hlc.physical_seconds));
    obj.Set("nanos", Napi::Number::New(env, (double)hlc.physical_nanos));
    obj.Set("logicalCounter", Napi::Number::New(env, (double)hlc.logical_counter));
    obj.Set("nodeId", Napi::String::New(env, hlc.node_id));
    char fmt[128];
    crabs_hlc_format(&hlc, fmt, sizeof(fmt));
    obj.Set("formatted", Napi::String::New(env, fmt));
    return obj;
  }

  Napi::Value SetTime(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    uint64_t now_ms = info[0].As<Napi::Number>().DoubleValue();
    attribute_machine_set_time(am_, now_ms);
    return env.Undefined();
  }

  Napi::Value PruneExpiredTempAttrs(const Napi::CallbackInfo& info) {
    attribute_machine_prune_expired_temporary(am_);
    return info.Env().Undefined();
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

  return exports;
}

NODE_API_MODULE(crabs_node, Init)