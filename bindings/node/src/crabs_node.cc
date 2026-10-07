//
// crabs_node.cc — N-API bindings for the CRABS C library.
//
// Exposes the core CRABS API (attribute machine, state machine, crypto,
// ABE, serialization) to Node.js via node-addon-api (C++ N-API wrapper).
//
// Classes:
//   KeyPair   — ECDSA secp256k1 keypair (generate, sign, verify)
//   Operation — a signed state-machine operation
//   Node      — a CRABS node (attribute machine + state + ABE master key)
//
// The Node class supports both Lamport and HLC (Hybrid Logical Clock)
// ordering. Use `new Node('admin', { ordering: 'hlc' })` for HLC mode.
//

#include <napi.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>
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
    Napi::FunctionReference* constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);
    env.SetInstanceData(constructor);
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
    auto* inst = env.GetInstanceData<Napi::FunctionReference>();
    Napi::Object obj = inst->New({});
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
    auto* inst = env.GetInstanceData<Napi::FunctionReference>();
    Napi::Object obj = inst->New({});
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
    strncpy(op_->type, val.As<Napi::String>().Utf8Value().c_str(), CRABS_MAX_OP_NAME - 1);
  }

  Napi::Value GetSignerId(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), op_->signer_id);
  }
  void SetSignerId(const Napi::CallbackInfo& info, const Napi::Value& val) {
    strncpy(op_->signer_id, val.As<Napi::String>().Utf8Value().c_str(), CRABS_MAX_USER_ID - 1);
  }

  Napi::Value GetNodeId(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), op_->node_id);
  }
  void SetNodeId(const Napi::CallbackInfo& info, const Napi::Value& val) {
    strncpy(op_->node_id, val.As<Napi::String>().Utf8Value().c_str(), CRABS_MAX_USER_ID - 1);
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
      op_->payload = (uint8_t*)malloc(buf.Length());
      memcpy(op_->payload, buf.Data(), buf.Length());
      op_->payload_size = (uint32_t)buf.Length();
    } else if (val.IsString()) {
      std::string s = val.As<Napi::String>().Utf8Value();
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
    if (!hex_decode(hex, priv, 32))
      throw Napi::Error::New(env, "Invalid private key hex");
    serialized_buffer_t* ser = crabs_serialize_for_signing(op_);
    if (!ser) throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "sign");
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
    });
    exports.Set("Node", func);
    return exports;
  }

  Node(const Napi::CallbackInfo& info) : Napi::ObjectWrap<Node>(info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString())
      throw Napi::TypeError::New(env, "Expected admin user ID string");

    std::string admin_id = info[0].As<Napi::String>().Utf8Value();

    // Parse options: { ordering: 'hlc' | 'lamport', strategy: 'bounded' | ... }
    bool use_hlc = true;  // Default to HLC (user requested hybrid time)
    if (info.Length() > 1 && info[1].IsObject()) {
      Napi::Object opts = info[1].As<Napi::Object>();
      if (opts.Has("ordering")) {
        std::string ord = opts.Get("ordering").As<Napi::String>().Utf8Value();
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
    if (node_key_) crypto_ecdsa_keypair_destroy(node_key_);
    if (am_) attribute_machine_destroy(am_);
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
    Napi::Value undefined_value = env.Undefined();
    for (auto& listener : change_listeners_) {
      if (listener.IsEmpty()) continue;
      try {
        listener.Call(undefined_value, {obj});
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
    std::string user_id = info[0].As<Napi::String>().Utf8Value();
    std::string pk_hex = info[1].As<Napi::String>().Utf8Value();
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
    std::string target = info[0].As<Napi::String>().Utf8Value();
    std::string role = info[1].As<Napi::String>().Utf8Value();
    std::string value = info[2].As<Napi::String>().Utf8Value();
    std::string signer = info[3].As<Napi::String>().Utf8Value();
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
    std::string attr = info[0].As<Napi::String>().Utf8Value();
    std::string value = info[1].As<Napi::String>().Utf8Value();
    std::string signer = info[2].As<Napi::String>().Utf8Value();
    crabs_error_e rc = attribute_machine_self_assert(am_, attr.c_str(),
                                                       value.c_str(), signer.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "selfAssert");
    return env.Undefined();
  }

  Napi::Value VerifyIdentity(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 4)
      throw Napi::TypeError::New(env, "Expected (targetUser, attribute, value, signerId)");
    std::string target = info[0].As<Napi::String>().Utf8Value();
    std::string attr = info[1].As<Napi::String>().Utf8Value();
    std::string value = info[2].As<Napi::String>().Utf8Value();
    std::string signer = info[3].As<Napi::String>().Utf8Value();
    crabs_error_e rc = attribute_machine_verify_identity(am_, target.c_str(),
                                                          attr.c_str(), value.c_str(),
                                                          signer.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "verifyIdentity");
    return env.Undefined();
  }

  Napi::Value RevokeUser(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string user_id = info[0].As<Napi::String>().Utf8Value();
    // Admin-gated in C (audit follow-up); the signer defaults to the node
    // admin when the caller omits it.
    std::string signer_id = info.Length() > 1 && !info[1].IsUndefined()
        ? info[1].As<Napi::String>().Utf8Value() : admin_id_;
    crabs_error_e rc = attribute_machine_revoke_user(am_, user_id.c_str(),
                                                     signer_id.c_str());
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "revokeUser");
    return env.Undefined();
  }

  Napi::Value GetUser(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string user_id = info[0].As<Napi::String>().Utf8Value();
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
    // Return an object with the node's public/private key hex
    Napi::Object obj = Napi::Object::New(info.Env());
    obj.Set("publicKeyHex", Napi::String::New(info.Env(), hex_encode(node_key_->public_key, 33)));
    obj.Set("privateKeyHex", Napi::String::New(info.Env(), hex_encode(node_key_->private_key, 32)));
    return obj;
  }

  // --- Data items ---

  Napi::Value AddCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_COUNTER, CRDT_G_COUNTER);
    item->value = g_counter_create();
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addCounter");
    return env.Undefined();
  }

  Napi::Value AddPNCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_PN_COUNTER, CRDT_PN_COUNTER);
    item->value = pn_counter_create();
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addPNCounter");
    return env.Undefined();
  }

  Napi::Value AddORSet(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_SET, CRDT_OR_SET);
    item->value = or_set_create();
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addORSet");
    return env.Undefined();
  }

  Napi::Value AddOneShotSet(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_ONE_SHOT_SET, CRDT_ONE_SHOT_SET);
    item->value = one_shot_set_create();
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addOneShotSet");
    return env.Undefined();
  }

  Napi::Value AddOneShotFlag(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_ONE_SHOT_FLAG, CRDT_ONE_SHOT_FLAG);
    item->value = one_shot_flag_create();
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addOneShotFlag");
    return env.Undefined();
  }

  Napi::Value AddRegister(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
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
    std::string name = info[0].As<Napi::String>().Utf8Value();
    data_item_t* item = data_item_create(name.c_str(), DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
    item->value = pn_counter_create();
    crabs_error_e rc = state_add_item(&am_->base_state, item);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "addResource");
    return env.Undefined();
  }

  // --- Queries ---

  Napi::Value GetCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) return env.Undefined();
    if (item->crdt_type == CRDT_G_COUNTER)
      return Napi::Number::New(env, (double)g_counter_value((g_counter_t*)item->value));
    return env.Undefined();
  }

  Napi::Value IncrementCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
    int64_t delta = info.Length() > 1 ? (int64_t)info[1].As<Napi::Number>().Int64Value() : 1;
    std::string node_id = info.Length() > 2 ? info[2].As<Napi::String>().Utf8Value() : "system";
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "incrementCounter");
    crabs_error_e rc = g_counter_increment((g_counter_t*)item->value, node_id.c_str(), delta);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "incrementCounter");
    return env.Undefined();
  }

  Napi::Value IncrementPNCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
    int64_t delta = info.Length() > 1 ? (int64_t)info[1].As<Napi::Number>().Int64Value() : 1;
    std::string node_id = info.Length() > 2 ? info[2].As<Napi::String>().Utf8Value() : "system";
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "incrementPNCounter");
    crabs_error_e rc = pn_counter_increment((pn_counter_t*)item->value, node_id.c_str(), delta);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "incrementPNCounter");
    return env.Undefined();
  }

  Napi::Value DecrementPNCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
    int64_t delta = info.Length() > 1 ? (int64_t)info[1].As<Napi::Number>().Int64Value() : 1;
    std::string node_id = info.Length() > 2 ? info[2].As<Napi::String>().Utf8Value() : "system";
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "decrementPNCounter");
    crabs_error_e rc = pn_counter_decrement((pn_counter_t*)item->value, node_id.c_str(), delta);
    if (rc != CRABS_SUCCESS) throw crabs_error(env, rc, "decrementPNCounter");
    return env.Undefined();
  }

  Napi::Value GetPNCounter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) return env.Undefined();
    if (item->crdt_type == CRDT_PN_COUNTER)
      return Napi::Number::New(env, (double)pn_counter_value((pn_counter_t*)item->value));
    return env.Undefined();
  }

  Napi::Value GetRegister(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
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
    std::string name = info[0].As<Napi::String>().Utf8Value();
    int64_t value = (int64_t)info[1].As<Napi::Number>().Int64Value();
    std::string node_id = info.Length() > 2 ? info[2].As<Napi::String>().Utf8Value() : "system";
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
    std::string name = info[0].As<Napi::String>().Utf8Value();
    std::string element = info[1].As<Napi::String>().Utf8Value();
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
    std::string name = info[0].As<Napi::String>().Utf8Value();
    std::string element = info[1].As<Napi::String>().Utf8Value();
    std::string tag = info.Length() > 2 ? info[2].As<Napi::String>().Utf8Value() : element;
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
    std::string name = info[0].As<Napi::String>().Utf8Value();
    std::string element = info[1].As<Napi::String>().Utf8Value();
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "setRemove");
    if (item->crdt_type == CRDT_OR_SET)
      or_set_remove((or_set_t*)item->value, element.c_str());
    return env.Undefined();
  }

  Napi::Value FlagSet(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
    std::string setBy = info[1].As<Napi::String>().Utf8Value();
    uint64_t setAt = info.Length() > 2 ? (uint64_t)info[2].As<Napi::Number>().DoubleValue() : 0;
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) throw crabs_error(env, CRABS_ERR_RESOURCE_NOT_FOUND, "flagSet");
    one_shot_flag_set((one_shot_flag_t*)item->value, setBy.c_str(), setAt);
    return env.Undefined();
  }

  Napi::Value FlagValue(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
    data_item_t* item = state_find_item(&am_->base_state, name.c_str());
    if (!item) return Napi::Boolean::New(env, false);
    return Napi::Boolean::New(env, one_shot_flag_value((one_shot_flag_t*)item->value));
  }

  // --- Policies ---

  Napi::Value SetPolicy(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string op_type = info[0].As<Napi::String>().Utf8Value();
    std::string expr = info[1].As<Napi::String>().Utf8Value();
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
      if (!hex_decode(hex, priv, 32))
        throw Napi::Error::New(env, "Invalid private key hex");
      serialized_buffer_t* ser = crabs_serialize_for_signing(op->raw());
      if (!ser) throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "sign");
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
    std::string trigger_id = cfg.Get("triggerId").As<Napi::String>().Utf8Value();
    std::string condition = cfg.Get("condition").As<Napi::String>().Utf8Value();
    std::string effect_type_str = cfg.Get("effectType").As<Napi::String>().Utf8Value();
    // Map string effect type to the numeric enum value (trigger_effect_type_e
    // in trigger.h: ISSUE_ATTRIBUTE=0x01, CREATE_TRIGGER=0x02, etc.)
    int effect_type_num = 0;
    if (effect_type_str == "issue_attribute") effect_type_num = 1;   // TRIGGER_EFFECT_ISSUE_ATTRIBUTE
    else if (effect_type_str == "create_trigger") effect_type_num = 2;
    else if (effect_type_str == "delete_trigger") effect_type_num = 3;
    else if (effect_type_str == "disable_trigger") effect_type_num = 4;
    else if (effect_type_str == "change_policy") effect_type_num = 5;
    else throw Napi::Error::New(env, "Unknown effectType: " + effect_type_str);

    std::string description = cfg.Has("description") ? cfg.Get("description").As<Napi::String>().Utf8Value() : "";
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
      std::string attr = cfg.Get("issueAttribute").As<Napi::String>().Utf8Value();
      std::string role = cfg.Get("targetRole").As<Napi::String>().Utf8Value();
      std::string value = cfg.Get("attributeValue").As<Napi::String>().Utf8Value();
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

    // Sign with node key
    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
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
    std::string policy = info[1].As<Napi::String>().Utf8Value();

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
  KeyPair::Init(env, exports);
  Operation::Init(env, exports);
  Node::Init(env, exports);
  return exports;
}

NODE_API_MODULE(crabs_node, Init)