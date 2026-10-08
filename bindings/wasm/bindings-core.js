//
// bindings-core.js — shared factory for the crabs-wasm bindings.
//
// index.js (production artifact) and dev.js (devtools-enabled artifact) both
// call createBindings(loadModule) with a loader for their own WASM glue file.
// The entire API surface is identical; only the loaded binary differs.
//

'use strict';

function createBindings(loadModule) {
  let _modulePromise = null;

  function getModule() {
    if (!_modulePromise) {
      _modulePromise = loadModule();
    }
    return _modulePromise;
  }

// ============================================================
// Change events
// ============================================================

// Module-wide change-event plumbing: one trampoline per WASM module,
// dispatching to every Node's listeners (filtered by node id, which is the
// bootstrap admin id stamped into op->node_id).
const _changeListenerRegistry = new WeakMap();  // M -> array of {node, listener}

function getChangeListeners(M) {
  if (!_changeListenerRegistry.has(M)) {
    _changeListenerRegistry.set(M, []);
  }
  const listeners = _changeListenerRegistry.get(M);
  if (!listeners._pending) listeners._pending = [];
  return listeners;
}

// Deliver one event to every matching listener. Listener failures are
// contained so one bad listener cannot starve the others.
function dispatchChangeEvent(listeners, event) {
  for (const entry of listeners.slice()) {
    if (entry.node != null && event.node !== entry.node) continue;
    try {
      entry.listener(event);
    } catch (listenerError) {
      console.warn('crabs: change listener failed', listenerError);
    }
  }
}

function ensureChangeTrampoline(M) {
  const listeners = getChangeListeners(M);
  if (listeners._trampoline) return;
  const trampoline = M.addFunction((jsonPointer) => {
    const text = jsonPointer ? M.UTF8ToString(jsonPointer) : '';
    let event;
    try {
      event = JSON.parse(text);
    } catch (parseError) {
      return;  // malformed event: drop, never throw into C
    }
    if (listeners._dispatching) {
      listeners._pending.push(event);   // nested: defer until outer dispatch drains
      return;
    }
    listeners._dispatching = true;
    try {
      dispatchChangeEvent(listeners, event);
      while (listeners._pending.length > 0) {
        dispatchChangeEvent(listeners, listeners._pending.shift());
      }
    } finally {
      listeners._dispatching = false;
    }
  }, 'vi');
  listeners._trampoline = trampoline;
  M._crabs_wasm_set_change_trampoline(trampoline);
}

// ============================================================
// Authenticated time source
// ============================================================
// The WASM module owns ONE time source per module instance, shared by every
// machine that attaches to it (per-module, not per-machine — see the C
// contract in src/Util/wasm_helpers.c): setTimeSource({mode:'https'}) on any
// Node replaces that shared source and attaches it to that Node's machine
// (re-attaching every other attached machine too); {mode:'system'} detaches
// only the calling machine, and the shared ops is retired in C when the last
// attached machine leaves. The config echo getTimeSource reports therefore
// lives at module scope.
const _timeSourceSelections = new WeakMap();  // M -> {url, resyncMs, timeoutMs, maxSkewMs}

// CRABS_TIME_SOURCE_DEFAULT_* from src/TimeSource/time_source.h. A non-NULL
// config's scalars are used AS-IS by crabs_time_source_https_create (0 is a
// real override, not "use the default"), so omitted options must spell these
// out exactly — never pass 0 hoping for the default.
const TIME_SOURCE_DEFAULT_RESYNC_MS = 30000;
const TIME_SOURCE_DEFAULT_TIMEOUT_MS = 1000;
const TIME_SOURCE_DEFAULT_MAX_SKEW_MS = 5000;

// ============================================================
// Helpers
// ============================================================

function hexEncode(bytes, len) {
  return Array.from(bytes.subarray(0, len))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexDecode(M, hex, ptr, maxLen) {
  const len = Math.min(hex.length / 2, maxLen);
  for (let i = 0; i < len; i++) {
    M.HEAPU8[ptr + i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return len;
}

function writeString(M, str) {
  if (!str) return 0;
  const len = M.lengthBytesUTF8(str) + 1;
  const ptr = M._malloc(len);
  M.stringToUTF8(str, ptr, len);
  return ptr;
}

function readString(M, ptr) {
  return ptr ? M.UTF8ToString(ptr) : '';
}

function writeBytes(M, bytes) {
  if (!bytes || bytes.length === 0) return { ptr: 0, len: 0 };
  const ptr = M._malloc(bytes.length);
  M.HEAPU8.set(bytes, ptr);
  return { ptr, len: bytes.length };
}

function encodeText(str) {
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(str);
  }
  return new Uint8Array(Buffer.from(str, 'utf8'));
}

const ERROR_MESSAGES = {
  0x0000: 'success',
  0x1001: 'protocol_violation', 0x1002: 'lock_token_mismatch', 0x1003: 'lock_owner_mismatch',
  0x1004: 'lock_contention', 0x1005: 'lock_not_expired', 0x1006: 'max_extensions_reached',
  0x1007: 'force_unlock_disabled',
  0x2001: 'unauthorized', 0x2002: 'key_stale', 0x2003: 'user_not_found', 0x2004: 'user_suspended',
  0x3001: 'invariant_violated', 0x3002: 'resource_not_found', 0x3003: 'duplicate_operation',
  0x3004: 'type_mismatch',
  0x4001: 'serialization_error', 0x4002: 'cryptographic_error',
  0x5001: 'internal_error', 0x5002: 'out_of_memory', 0x5003: 'invalid_param',
  0x5004: 'scheme_already_registered',
  0x6001: 'key_suspended', 0x6002: 'key_revoked', 0x6003: 'key_expired', 0x6004: 'key_not_active',
  0x6005: 'vault_unavailable',
  0x7001: 'already_performed', 0x7002: 'already_executed', 0x7003: 'condition_not_met',
  0x7004: 'tracker_not_found', 0x7005: 'flag_not_found',
};

function crabsError(code, ctx) {
  const msg = ERROR_MESSAGES[code] || `error_${code.toString(16)}`;
  return new Error(`${ctx}: ${msg}`);
}

function wrapRc(rc, ctx) {
  if (rc !== 0) throw crabsError(rc, ctx);
}

function freeAll(M, ...ptrs) {
  for (const p of ptrs) { if (p) M._free(p); }
}

// ============================================================
// KeyPair
// ============================================================

class KeyPair {
  constructor(M, ptr) {
    this._M = M;
    this._ptr = ptr;
    this._raw = false;
  }

  static async generate() {
    const M = await getModule();
    const ptr = M._crypto_ecdsa_generate();
    if (!ptr) throw new Error('KeyPair.generate failed');
    return new KeyPair(M, ptr);
  }

  static async fromPrivateHex(hex) {
    const M = await getModule();
    const ptr = M._malloc(65);
    const len = hexDecode(M, hex, ptr, 32);
    if (len !== 32) { M._free(ptr); throw new Error('Invalid private key hex'); }
    const rc = M._crypto_ecdsa_derive_public_key(ptr, ptr + 32);
    if (rc !== 0) { M._free(ptr); throw crabsError(rc, 'fromPrivateHex'); }
    const kp = new KeyPair(M, ptr);
    kp._raw = true;
    return kp;
  }

  static async derivePublicHex(hex) {
    const M = await getModule();
    const priv = M._malloc(32);
    const pub = M._malloc(33);
    const len = hexDecode(M, hex, priv, 32);
    if (len !== 32) { freeAll(M, priv, pub); throw new Error('Invalid private key hex'); }
    const rc = M._crypto_ecdsa_derive_public_key(priv, pub);
    const out = rc === 0 ? hexEncode(M.HEAPU8.subarray(pub, pub + 33), 33) : '';
    freeAll(M, priv, pub);
    if (rc !== 0) throw crabsError(rc, 'derivePublicHex');
    return out;
  }

  publicKeyHex() {
    return hexEncode(this._M.HEAPU8.subarray(this._ptr + 32, this._ptr + 65), 33);
  }

  privateKeyHex() {
    return hexEncode(this._M.HEAPU8.subarray(this._ptr, this._ptr + 32), 32);
  }

  destroy() {
    if (this._ptr) {
      if (this._raw) this._M._free(this._ptr);
      else this._M._crypto_ecdsa_keypair_destroy(this._ptr);
      this._ptr = null;
    }
  }
}

// ============================================================
// Operation
// ============================================================

class Operation {
  constructor(M, ptr) {
    this._M = M;
    this._ptr = ptr;
  }

  static async create(type) {
    const M = await getModule();
    const typePtr = writeString(M, type);
    const ptr = M._operation_create(typePtr);
    if (typePtr) M._free(typePtr);
    if (!ptr) throw new Error('Operation.create failed');
    M._crabs_wasm_op_init_uuid(ptr);
    return new Operation(M, ptr);
  }

  static async deserialize(bytes) {
    const M = await getModule();
    const { ptr, len } = writeBytes(M, bytes);
    const opPtr = M._crabs_wasm_deserialize_operation(ptr, len);
    if (ptr) M._free(ptr);
    if (!opPtr) throw new Error('Operation.deserialize failed');
    return new Operation(M, opPtr);
  }

  set signerId(id) {
    const M = this._M;
    const idPtr = writeString(M, id);
    M._crabs_wasm_op_set_signer(this._ptr, idPtr);
    if (idPtr) M._free(idPtr);
  }
  get signerId() { return readString(this._M, this._M._crabs_wasm_op_get_signer(this._ptr)); }

  set nodeId(id) {
    const M = this._M;
    const idPtr = writeString(M, id);
    M._crabs_wasm_op_set_node(this._ptr, idPtr);
    if (idPtr) M._free(idPtr);
  }
  get nodeId() { return readString(this._M, this._M._crabs_wasm_op_get_node(this._ptr)); }

  set type(t) {
    const M = this._M;
    const tPtr = writeString(M, t);
    M._crabs_wasm_op_set_type(this._ptr, tPtr);
    if (tPtr) M._free(tPtr);
  }
  get type() { return readString(this._M, this._M._crabs_wasm_op_get_type(this._ptr)); }

  set payload(buf) {
    const M = this._M;
    let b = buf;
    if (typeof b === 'string') b = encodeText(b);
    if (!b || b.length === 0) {
      M._crabs_wasm_op_set_payload(this._ptr, 0, 0);
      return;
    }
    const { ptr, len } = writeBytes(M, b);
    M._crabs_wasm_op_set_payload(this._ptr, ptr, len);
    if (ptr) M._free(ptr);
  }

  get payload() {
    const M = this._M;
    const len = M._crabs_wasm_op_get_payload_size(this._ptr);
    const ptr = M._crabs_wasm_op_get_payload(this._ptr);
    if (!len || !ptr) return undefined;
    return new Uint8Array(M.HEAPU8.subarray(ptr, ptr + len));
  }

  serialize() {
    const M = this._M;
    const ser = M._crabs_wasm_serialize_operation(this._ptr);
    if (!ser) throw new Error('serialize operation failed');
    const len = M._crabs_wasm_buffer_len(ser);
    const data = M._crabs_wasm_buffer_data(ser);
    const out = new Uint8Array(M.HEAPU8.subarray(data, data + len));
    M._crabs_wasm_buffer_destroy(ser);
    return out;
  }

  destroy() {
    if (this._ptr) { this._M._operation_destroy(this._ptr); this._ptr = null; }
  }
}

// ============================================================
// Lineage (v1.7: machines mint machines)
// ============================================================

// Trust modes for spawned child machines (lineage_trust_mode_e wire values):
//   SHARED_ROOT    — the child resolves attributes against the PARENT's
//                    authority (shared registry + live MSK pointer).
//   DELEGATED_COPY — the child mints a fresh CP-ABE authority; the parent
//                    attests attributes across the domain bridge.
//   SOVEREIGN      — identical construction to DELEGATED_COPY, but the
//                    parent may only WITHDRAW its genesis stake (never
//                    dissolve).
const TRUST_MODE = {
  SHARED_ROOT: 0x01,
  DELEGATED_COPY: 0x02,
  SOVEREIGN: 0x03,
};

// Data item / CRDT strategy numbers used by Blueprint.addItem — the subset
// the v1.7 blueprint surface covers (crabs.h's full enums accept any value).
const DATA_TYPE = {
  COUNTER: 0x01, PN_COUNTER: 0x02, SET: 0x03, REGISTER: 0x05,
  ONE_SHOT_SET: 0x08, ONE_SHOT_FLAG: 0x09,
};
const CRDT_TYPE = {
  G_COUNTER: 0x01, PN_COUNTER: 0x02, OR_SET: 0x03, LWW_REG: 0x05,
  ONE_SHOT_SET: 0x08, ONE_SHOT_FLAG: 0x09,
};

// JS wrapper over the C machine_blueprint_t. JS OWNS the blueprint: it must
// be released with destroy(). The MACHINE the blueprint spawns is different —
// C keeps child machines in the parent's resident-children registry (see
// Node.lineageSpawn) and JS only ever borrows those pointers.
class Blueprint {
  constructor(M, ptr) {
    this._M = M;
    this._ptr = ptr;
  }

  // Build a fresh blueprint. trustMode is a TRUST_MODE value; ttlMs bounds
  // every attestation the parent issues for this child later.
  static async create(childId, trustMode, bootstrapAdmin, ttlMs) {
    const M = await getModule();
    const childIdPtr = writeString(M, childId);
    const adminPtr = writeString(M, bootstrapAdmin);
    const ptr = M._crabs_wasm_lineage_blueprint_new(
        0, childIdPtr, trustMode, adminPtr, BigInt(ttlMs));
    freeAll(M, childIdPtr, adminPtr);
    if (!ptr) throw new Error('Blueprint.create failed');
    return new Blueprint(M, ptr);
  }

  // Parse a blueprint wire image (as produced by serialize). Verifies the
  // embedded blueprint hash — a tampered body can never deserialize.
  static async deserialize(bytes) {
    const M = await getModule();
    const { ptr, len } = writeBytes(M, bytes);
    const bpPtr = M._crabs_wasm_lineage_blueprint_deserialize(ptr, len);
    if (ptr) M._free(ptr);
    if (!bpPtr) throw new Error('Blueprint.deserialize failed');
    return new Blueprint(M, bpPtr);
  }

  // Append a replicated data item to the child's definition.
  addItem(name, dataType, crdtType) {
    const M = this._M;
    const namePtr = writeString(M, name);
    const rc = M._crabs_wasm_lineage_blueprint_add_item(
        this._ptr, namePtr, dataType, crdtType);
    if (namePtr) M._free(namePtr);
    wrapRc(rc, 'blueprint.addItem');
  }

  // Append an authorization policy: operation type + condition expression.
  addPolicy(operation, expression) {
    const M = this._M;
    const opPtr = writeString(M, operation);
    const exprPtr = writeString(M, expression);
    const rc = M._crabs_wasm_lineage_blueprint_add_policy(
        this._ptr, opPtr, exprPtr);
    freeAll(M, opPtr, exprPtr);
    wrapRc(rc, 'blueprint.addPolicy');
  }

  // Recompute the blueprint's SHA-256 over its canonical body. Called before
  // signing hand-built blueprints; serialize() stamps it automatically.
  stampHash() {
    wrapRc(this._M._crabs_wasm_lineage_blueprint_stamp_hash(this._ptr),
        'blueprint.stampHash');
  }

  // Wire image (u32le total length + canonical body + 32-byte blueprint
  // hash). This is exactly the payload an ops-pipeline __spawn_machine__ op
  // carries, so blueprints can be shipped between processes.
  serialize() {
    const M = this._M;
    const ser = M._crabs_wasm_lineage_blueprint_serialize(this._ptr);
    if (!ser) throw new Error('blueprint.serialize failed');
    const len = M._crabs_wasm_buffer_len(ser);
    const data = M._crabs_wasm_buffer_data(ser);
    const out = new Uint8Array(M.HEAPU8.subarray(data, data + len));
    M._crabs_wasm_buffer_destroy(ser);
    return out;
  }

  destroy() {
    if (this._ptr) {
      this._M._crabs_wasm_lineage_blueprint_destroy(this._ptr);
      this._ptr = null;
    }
  }
}

// ============================================================
// Node
// ============================================================

class Node {
  constructor(M, amPtr) {
    this._M = M;
    this._am = amPtr;
    this.adminId = null;
  }

  // Change events: 'change' listeners receive one event object per state
  // mutation, pushed from the C change hook through a WASM trampoline.
  // on('change', listener) returns an unsubscribe function, matching the
  // N-API binding (node.off('change', listener) also works).
  on(eventName, listener) {
    if (eventName !== 'change' || typeof listener !== 'function') return;
    ensureChangeTrampoline(this._M);
    const listeners = getChangeListeners(this._M);
    listeners.push({ node: this.adminId, listener });
    const node = this;
    return () => {
      const entryIndex = listeners.findIndex(
        (entry) => entry.listener === listener && entry.node === node.adminId);
      if (entryIndex >= 0) listeners.splice(entryIndex, 1);
    };
  }

  off(eventName, listener) {
    if (eventName !== 'change') return;
    const listeners = getChangeListeners(this._M);
    const entryIndex = listeners.findIndex(
      (entry) => entry.listener === listener && entry.node === this.adminId);
    if (entryIndex >= 0) listeners.splice(entryIndex, 1);
  }

  static async create(adminId, options = {}) {
    const M = await getModule();
    const adminPtr = writeString(M, adminId);
    const amPtr = M._crabs_wasm_node_create(adminPtr);
    if (adminPtr) M._free(adminPtr);
    if (!amPtr) throw new Error('Node.create failed');
    const node = new Node(M, amPtr);
    // The bootstrap admin id becomes the node's HLC identity: signing stamps
    // op->node_id from it, and devtools events are attributed per node by it.
    node.adminId = adminId;
    return node;
  }

  getNodeKey() {
    // The node private key lives inside the C state and is used internally for
    // admin-level signing (e.g., createTrigger). It is intentionally not
    // exposed to JS.
    return { publicKeyHex: '', privateKeyHex: '' };
  }

  registerUser(userId, publicKeyHex, initialAttrs) {
    const M = this._M;
    const uidPtr = writeString(M, userId);
    const pkPtr = M._malloc(33);
    const keyLength = hexDecode(M, publicKeyHex, pkPtr, 33);
    if (keyLength !== 33) {
      freeAll(M, uidPtr, pkPtr);
      throw new Error('Invalid public key hex');
    }
    const attrsPtr = writeString(M, initialAttrs);
    const rc = M._attribute_machine_register_user(this._am, uidPtr, pkPtr, attrsPtr);
    freeAll(M, uidPtr, pkPtr, attrsPtr);
    wrapRc(rc, 'registerUser');
  }

  grantRole(targetUser, role, value, signerId) {
    const M = this._M;
    const tPtr = writeString(M, targetUser);
    const rPtr = writeString(M, role);
    const vPtr = writeString(M, value);
    const sPtr = writeString(M, signerId);
    const rc = M._attribute_machine_grant_role(this._am, tPtr, rPtr, vPtr, sPtr);
    freeAll(M, tPtr, rPtr, vPtr, sPtr);
    wrapRc(rc, 'grantRole');
  }

  revokeUser(userId, signerId) {
    const M = this._M;
    // Audit follow-up: revoke_user is admin-gated in C now, so the signer
    // must be passed and default to the node's admin identity.
    const uidPtr = writeString(M, userId);
    const sPtr = writeString(M, signerId || this.adminId || 'admin');
    const rc = M._attribute_machine_revoke_user(this._am, uidPtr, sPtr);
    freeAll(M, uidPtr, sPtr);
    wrapRc(rc, 'revokeUser');
  }

  getUser(userId) {
    const M = this._M;
    const uidPtr = writeString(M, userId);
    const userPtr = M._crabs_wasm_find_user(this._am, uidPtr);
    if (uidPtr) M._free(uidPtr);
    if (!userPtr) return undefined;

    const attrs = [];
    const n = M._crabs_wasm_user_attr_count(userPtr);
    for (let i = 0; i < n; i++) {
      attrs.push({
        value: readString(M, M._crabs_wasm_user_attr_value(userPtr, i)),
        verifiedBy: '',
        temporary: false,
      });
    }
    const tempName = readString(M, M._crabs_wasm_user_temp_attr_name(userPtr));
    if (tempName) {
      attrs.push({
        value: tempName + ':' + readString(M, M._crabs_wasm_user_temp_attr_value(userPtr)),
        verifiedBy: 'trigger',
        temporary: true,
      });
    }

    return {
      userId: readString(M, M._crabs_wasm_user_id(userPtr)),
      publicKeyHex: '',
      keyVersion: 0,
      status: 'active',
      attributes: attrs,
    };
  }

  addCounter(name) { this._callAdd(this._M._crabs_wasm_add_counter, name, 'addCounter'); }
  addPNCounter(name) { this._callAdd(this._M._crabs_wasm_add_pn_counter, name, 'addPNCounter'); }
  addORSet(name) { this._callAdd(this._M._crabs_wasm_add_or_set, name, 'addORSet'); }
  addOneShotSet(name) { this._callAdd(this._M._crabs_wasm_add_one_shot_set, name, 'addOneShotSet'); }
  addOneShotFlag(name) { this._callAdd(this._M._crabs_wasm_add_one_shot_flag, name, 'addOneShotFlag'); }

  addRegister(name, initial = 0) {
    const M = this._M;
    const nPtr = writeString(M, name);
    const rc = M._crabs_wasm_add_register(this._am, nPtr, BigInt(initial));
    if (nPtr) M._free(nPtr);
    wrapRc(rc, 'addRegister');
  }

  _callAdd(fn, name, ctx) {
    const M = this._M;
    const nPtr = writeString(M, name);
    const rc = fn(this._am, nPtr);
    if (nPtr) M._free(nPtr);
    wrapRc(rc, ctx);
  }

  setPolicy(opType, expr) {
    const M = this._M;
    const oPtr = writeString(M, opType);
    const ePtr = writeString(M, expr);
    const rc = M._crabs_wasm_set_policy(this._am, oPtr, ePtr);
    freeAll(M, oPtr, ePtr);
    wrapRc(rc, 'setPolicy');
  }

  getCounter(name) { return this._callGet(this._M._crabs_wasm_get_counter, name); }
  getPNCounter(name) { return this._callGet(this._M._crabs_wasm_get_pn_counter, name); }
  getRegister(name) { return this._callGet(this._M._crabs_wasm_get_register, name); }

  _callGet(fn, name) {
    const M = this._M;
    const nPtr = writeString(M, name);
    const raw = fn(this._am, nPtr);
    if (nPtr) M._free(nPtr);
    return typeof raw === 'bigint' ? Number(raw) : raw;
  }

  incrementCounter(name, delta = 1, nodeId = 'system') {
    this._callCounter(this._M._crabs_wasm_increment_counter, name, delta, nodeId, 'incrementCounter');
  }
  incrementPNCounter(name, delta = 1, nodeId = 'system') {
    this._callCounter(this._M._crabs_wasm_increment_pn_counter, name, delta, nodeId, 'incrementPNCounter');
  }
  decrementPNCounter(name, delta = 1, nodeId = 'system') {
    this._callCounter(this._M._crabs_wasm_decrement_pn_counter, name, delta, nodeId, 'decrementPNCounter');
  }

  _callCounter(fn, name, delta, nodeId, ctx) {
    const M = this._M;
    const nPtr = writeString(M, name);
    const idPtr = writeString(M, nodeId);
    const rc = fn(this._am, nPtr, BigInt(delta), idPtr);
    freeAll(M, nPtr, idPtr);
    wrapRc(rc, ctx);
  }

  setRegister(name, value, nodeId = 'system') {
    const M = this._M;
    const nPtr = writeString(M, name);
    const idPtr = writeString(M, nodeId);
    const rc = M._crabs_wasm_set_register(this._am, nPtr, BigInt(value), idPtr);
    freeAll(M, nPtr, idPtr);
    wrapRc(rc, 'setRegister');
  }

  // Stores raw bytes (e.g. ABE ciphertext) in an lww_register. setRegister
  // only accepts an int64, which would force payloads into the 8-byte-int
  // convention; this keeps opaque payloads byte-exact.
  setRegisterBytes(name, bytes, nodeId = 'system') {
    const M = this._M;
    const nPtr = writeString(M, name);
    const { ptr: dPtr, len: dLen } = writeBytes(M, bytes || new Uint8Array(0));
    const idPtr = writeString(M, nodeId);
    const rc = M._crabs_wasm_set_register_bytes(this._am, nPtr, dPtr, dLen, idPtr);
    freeAll(M, nPtr, dPtr, idPtr);
    wrapRc(rc, 'setRegisterBytes');
  }

  setContains(name, element) {
    const M = this._M;
    const nPtr = writeString(M, name);
    const ePtr = writeString(M, element);
    const out = M._crabs_wasm_set_contains(this._am, nPtr, ePtr);
    freeAll(M, nPtr, ePtr);
    return out;
  }

  setAdd(name, element, tag = element) {
    const M = this._M;
    const nPtr = writeString(M, name);
    const ePtr = writeString(M, element);
    const tPtr = writeString(M, tag);
    const rc = M._crabs_wasm_set_add(this._am, nPtr, ePtr, tPtr);
    freeAll(M, nPtr, ePtr, tPtr);
    wrapRc(rc, 'setAdd');
  }

  setRemove(name, element) {
    const M = this._M;
    const nPtr = writeString(M, name);
    const ePtr = writeString(M, element);
    const rc = M._crabs_wasm_set_remove(this._am, nPtr, ePtr);
    freeAll(M, nPtr, ePtr);
    wrapRc(rc, 'setRemove');
  }

  flagValue(name) { return this._callGet(this._M._crabs_wasm_one_shot_flag_value, name); }
  flagSet(name, setBy, setAt = 0) {
    const M = this._M;
    const nPtr = writeString(M, name);
    const sPtr = writeString(M, setBy);
    const rc = M._crabs_wasm_one_shot_flag_set(this._am, nPtr, sPtr, BigInt(setAt));
    freeAll(M, nPtr, sPtr);
    wrapRc(rc, 'flagSet');
  }

  execute(op) {
    wrapRc(this._M._crabs_wasm_execute(this._am, op._ptr), 'execute');
  }

  sign(op, signingKey) {
    const M = this._M;
    let privHex;
    if (typeof signingKey === 'string') {
      privHex = signingKey;
    } else if (signingKey && signingKey._ptr) {
      // Read the private key as a hex string now; the heap view stored on the
      // KeyPair object can become detached after WASM memory growth.
      privHex = signingKey.privateKeyHex();
    } else {
      throw new Error('Expected KeyPair or private key hex string');
    }
    const privPtr = M._malloc(32);
    const len = hexDecode(M, privHex, privPtr, 32);
    if (len !== 32) { M._free(privPtr); throw new Error('Invalid private key hex'); }
    const rc = M._crabs_wasm_sign_operation(this._am, op._ptr, privPtr);
    M._free(privPtr);
    wrapRc(rc, 'sign');
  }

  createTrigger(config) {
    const M = this._M;
    const effectTypeNum = {
      issue_attribute: 1, create_trigger: 2, delete_trigger: 3,
      disable_trigger: 4, change_policy: 5
    }[config.effectType];
    if (!effectTypeNum) throw new Error('Unknown effectType: ' + config.effectType);

    let payload = `trigger_id=${config.triggerId};condition=${config.condition};description=${config.description || ''};effect_type=${effectTypeNum};cooldown_ms=${config.cooldownMs || 0};one_shot=${config.oneShot ? 1 : 0}`;
    if (config.effectType === 'issue_attribute') {
      payload += `;issue_attribute=${config.issueAttribute};target_role=${config.targetRole};attribute_value=${config.attributeValue};duration_ms=${config.durationMs || 0}`;
    }

    const typePtr = writeString(M, '__create_trigger__');
    const signerPtr = writeString(M, this.adminId || 'admin');
    const nodePtr = writeString(M, this.adminId || 'admin');
    const opPtr = M._operation_create(typePtr);
    if (typePtr) M._free(typePtr);
    if (!opPtr) {
      freeAll(M, signerPtr, nodePtr);
      throw new Error('createTrigger: operation_create failed');
    }
    M._crabs_wasm_op_init_uuid(opPtr);
    M._crabs_wasm_op_set_signer(opPtr, signerPtr);
    M._crabs_wasm_op_set_node(opPtr, nodePtr);
    freeAll(M, signerPtr, nodePtr);
    const payloadBytes = encodeText(payload + '\0');
    const { ptr: dPtr, len: dLen } = writeBytes(M, payloadBytes);
    M._crabs_wasm_op_set_payload(opPtr, dPtr, dLen);
    if (dPtr) M._free(dPtr);

    const rcSign = M._crabs_wasm_sign_with_node_key(this._am, opPtr);
    if (rcSign !== 0) {
      M._operation_destroy(opPtr);
      throw crabsError(rcSign, 'createTrigger sign');
    }
    const rcExec = M._crabs_wasm_execute(this._am, opPtr);
    M._operation_destroy(opPtr);
    wrapRc(rcExec, 'createTrigger execute');
  }

  encrypt(data, policy) {
    const M = this._M;
    let b = data;
    if (typeof b === 'string') b = encodeText(b);
    const { ptr: dPtr, len: dLen } = writeBytes(M, b);
    const pPtr = writeString(M, policy);
    const ct = M._crabs_wasm_abe_encrypt(this._am, dPtr, dLen, pPtr);
    freeAll(M, dPtr, pPtr);
    if (!ct) throw new Error('ABE encrypt failed');

    const policyStr = readString(M, M._crabs_wasm_abe_ciphertext_policy(ct));
    const policyBytes = encodeText(policyStr);
    // The container's length prefix is a uint16, so a policy larger than that
    // cannot be represented — fail loudly instead of silently truncating.
    if (policyBytes.length > 0xFFFF) {
      M._crabs_wasm_abe_ciphertext_destroy(ct);
      throw new Error(`ABE policy too large: ${policyBytes.length} UTF-8 bytes (max 65535)`);
    }
    const outLenPtr = M._malloc(4);
    const ctData = M._crabs_wasm_abe_ciphertext_data(ct, outLenPtr);
    const ctLen = M.getValue(outLenPtr, 'i32');
    M._free(outLenPtr);

    const total = 2 + policyBytes.length + 4 + ctLen;
    const out = new Uint8Array(total);
    const dv = new DataView(out.buffer);
    dv.setUint16(0, policyBytes.length, true);
    out.set(policyBytes, 2);
    dv.setUint32(2 + policyBytes.length, ctLen, true);
    out.set(new Uint8Array(M.HEAPU8.subarray(ctData, ctData + ctLen)), 2 + policyBytes.length + 4);

    M._crabs_wasm_abe_ciphertext_destroy(ct);
    return out;
  }

  serialize() {
    const M = this._M;
    const ser = M._crabs_wasm_serialize_state(this._am);
    if (!ser) throw new Error('serialize state failed');
    const len = M._crabs_wasm_buffer_len(ser);
    const data = M._crabs_wasm_buffer_data(ser);
    const out = new Uint8Array(M.HEAPU8.subarray(data, data + len));
    M._crabs_wasm_buffer_destroy(ser);
    return out;
  }

  setTime(nowMs) { this._M._crabs_wasm_set_time(this._am, BigInt(nowMs)); }
  pruneExpiredTempAttrs() { return this._M._crabs_wasm_prune_expired_temp_attrs(this._am); }

  // --- Authenticated time source (R7-01 wiring; R7-02 fail closed) ---
  //
  // setTimeSource({mode: 'https' | 'system', url?, resyncMs?, timeoutMs?,
  // maxSkewMs?}) — the options shape, typed errors, and reject-before-mutating
  // contract match the node binding exactly. One wasm-module caveat: the
  // underlying ops is module-SHARED (one per module instance, not per
  // machine), so selecting 'https' on any Node re-points every attached
  // machine at the fresh source; 'system' detaches only this machine.
  //
  // NO fetch happens at attach time — the first query runs lazily inside
  // authenticated-time checks (state_get_time_ms), and a fetch failure makes
  // the machine report invalid time (fail closed), never local-clock fallback.
  setTimeSource(options) {
    const M = this._M;
    if (options === null || typeof options !== 'object' || Array.isArray(options))
      throw new TypeError(
          'setTimeSource: expected an options object {mode, url?, ...}');
    if (options.mode !== 'https' && options.mode !== 'system')
      throw new TypeError("setTimeSource: mode must be 'https' or 'system'");

    if (options.mode === 'system') {
      const rc = M._crabs_wasm_set_time_source(this._am, 0, 0, 0, 0n, 0n, 0n);
      wrapRc(rc, 'setTimeSource');
      return;
    }

    // Validation first — a rejected call must change NOTHING on the machine.
    let url = null;
    let urlBytes = null;
    if (options.url !== undefined && options.url !== null) {
      if (typeof options.url !== 'string')
        throw new TypeError('setTimeSource: url must be a string');
      url = options.url;
      // Same checks as the CLI (`time-source https <url>`): https scheme, a
      // non-empty host (no leading '/' or ':'), max 255 chars. Count UTF-8
      // bytes, not UTF-16 code units — the C side bounds byte length.
      urlBytes = encodeText(url);
      if (!url.startsWith('https://') || url.length < 9 ||
          url[8] === '/' || url[8] === ':')
        throw new RangeError(
            "setTimeSource: url must be https://<host>[/path] (got '" + url + "')");
      if (urlBytes.length > 255)
        throw new RangeError('setTimeSource: url too long (max 255 chars)');
    }

    let resyncMs = TIME_SOURCE_DEFAULT_RESYNC_MS;
    let timeoutMs = TIME_SOURCE_DEFAULT_TIMEOUT_MS;
    let maxSkewMs = TIME_SOURCE_DEFAULT_MAX_SKEW_MS;
    const millis = {};
    for (const field of ['resyncMs', 'timeoutMs', 'maxSkewMs']) {
      const fieldValue = options[field];
      if (fieldValue === undefined || fieldValue === null) continue;
      if (typeof fieldValue !== 'number')
        throw new TypeError('setTimeSource: ' + field + ' must be a number');
      // NaN fails the >= 0 test; values >= 2^64 cannot be cast to uint64_t
      // without UB, so bound the range before converting to BigInt.
      if (!(fieldValue >= 0) || !(fieldValue < 18446744073709551616))
        throw new RangeError('setTimeSource: ' + field +
            ' must be a non-negative number of milliseconds');
      millis[field] = Math.trunc(fieldValue);
    }
    if (millis.resyncMs !== undefined) resyncMs = millis.resyncMs;
    if (millis.timeoutMs !== undefined) timeoutMs = millis.timeoutMs;
    if (millis.maxSkewMs !== undefined) maxSkewMs = millis.maxSkewMs;

    let urlPtr = 0;
    let urlLen = 0;
    if (urlBytes !== null) {
      ({ ptr: urlPtr, len: urlLen } = writeBytes(M, urlBytes));
    }
    const rc = M._crabs_wasm_set_time_source(this._am, 1, urlPtr, urlLen,
        BigInt(resyncMs), BigInt(timeoutMs), BigInt(maxSkewMs));
    if (urlPtr) M._free(urlPtr);
    if (rc !== 0) throw crabsError(rc, 'setTimeSource');
    _timeSourceSelections.set(M, {
      url, resyncMs, timeoutMs, maxSkewMs,
    });
  }

  // getTimeSource() reports {mode:'system'} or {mode:'https', url,
  // resyncMs, timeoutMs, maxSkewMs, created}. `url` is the configured
  // endpoint or null (default endpoint). The per-machine attached flag comes
  // from C (never from the JS echo), so it stays honest even if another Node
  // in this module reconfigured the shared source.
  getTimeSource() {
    const M = this._M;
    if (!M._crabs_wasm_time_source_attached(this._am)) {
      return { mode: 'system' };
    }
    const selection = _timeSourceSelections.get(M) || {
      url: null, resyncMs: TIME_SOURCE_DEFAULT_RESYNC_MS,
      timeoutMs: TIME_SOURCE_DEFAULT_TIMEOUT_MS,
      maxSkewMs: TIME_SOURCE_DEFAULT_MAX_SKEW_MS,
    };
    return {
      mode: 'https',
      url: selection.url,
      resyncMs: selection.resyncMs,
      timeoutMs: selection.timeoutMs,
      maxSkewMs: selection.maxSkewMs,
      created: true,
    };
  }

  schedule(innerOp, executeAtMs) {
    const scheduleId = this._M._crabs_wasm_schedule(this._am, innerOp._ptr, BigInt(executeAtMs));
    if (!scheduleId) throw new Error('schedule failed');
    return scheduleId;
  }

  scheduleRecurring(innerOp, startAtMs, intervalMs, repeatCount, endAtMs) {
    const scheduleId = this._M._crabs_wasm_schedule_recurring(
        this._am, innerOp._ptr, BigInt(startAtMs), BigInt(intervalMs),
        BigInt(repeatCount), BigInt(endAtMs));
    if (!scheduleId) throw new Error('scheduleRecurring failed');
    return scheduleId;
  }

  cancelSchedule(scheduleId) {
    wrapRc(this._M._crabs_wasm_cancel_schedule(this._am, BigInt(scheduleId)), 'cancelSchedule');
  }

  processSchedules(nowMs = Date.now()) {
    wrapRc(this._M._crabs_wasm_process_schedules(this._am, BigInt(nowMs)), 'processSchedules');
  }

  // Per-tick ceiling on materialized scheduled occurrences (0 = unlimited).
  // Bounds the catch-up burst after long downtime; deferred slots carry over.
  setScheduleOccurrenceBudget(maxPerTick) {
    const M = this._M;
    M._crabs_wasm_set_schedule_occurrence_budget(this._am, maxPerTick >>> 0);
  }

  scheduleOccurrenceBudget() {
    return this._M._crabs_wasm_schedule_occurrence_budget(this._am);
  }

  pendingSchedules() {
    const M = this._M;
    const schedules = [];
    for (let entry = M._crabs_wasm_schedule_first(this._am); entry;
         entry = M._crabs_wasm_schedule_next(entry)) {
      const submitterPtr = M._crabs_wasm_schedule_submitter(entry);
      schedules.push({
        id: M._crabs_wasm_schedule_id(entry),
        executeAt: M._crabs_wasm_schedule_execute_at(entry),
        intervalMs: M._crabs_wasm_schedule_interval(entry),
        repeatCount: M._crabs_wasm_schedule_repeat_count(entry),
        endAt: M._crabs_wasm_schedule_end_at(entry),
        submitter: submitterPtr ? M.UTF8ToString(submitterPtr) : '',
      });
    }
    return schedules;
  }

  evaluateTriggers() {
    const M = this._M;
    const typePtr = writeString(M, 'noop');
    const signerPtr = writeString(M, this.adminId || 'admin');
    const nodePtr = writeString(M, this.adminId || 'admin');
    const opPtr = M._operation_create(typePtr);
    M._crabs_wasm_op_init_uuid(opPtr);
    M._crabs_wasm_op_set_signer(opPtr, signerPtr);
    M._crabs_wasm_op_set_node(opPtr, nodePtr);
    freeAll(M, typePtr, signerPtr, nodePtr);
    if (!opPtr) throw new Error('evaluateTriggers: operation_create failed');
    const rcSign = M._crabs_wasm_sign_with_node_key(this._am, opPtr);
    if (rcSign !== 0) {
      M._operation_destroy(opPtr);
      throw crabsError(rcSign, 'evaluateTriggers sign');
    }
    const rcExec = M._crabs_wasm_execute(this._am, opPtr);
    M._operation_destroy(opPtr);
    wrapRc(rcExec, 'evaluateTriggers execute');
  }

  registerHandler(opType, handler) {
    const M = this._M;
    const typePtr = writeString(M, opType);
    if (!this._handlerTable) this._handlerTable = {};
    const previousTableIndex = this._handlerTable[opType];
    const tableIndex = M.addFunction(handler, 'ipp');
    const rc = M._crabs_wasm_register_handler(this._am, typePtr, tableIndex);
    if (typePtr) M._free(typePtr);
    if (rc !== 0) {
      // The C registry still points at the previous handler (if any), so only
      // the fresh, unused table slot is released here.
      M.removeFunction(tableIndex);
      throw crabsError(rc, 'registerHandler');
    }
    // Only after the C registry points at the new slot may the old function
    // table entry be released; until then a re-registered op could still be
    // dispatched through it.
    if (previousTableIndex !== undefined) M.removeFunction(previousTableIndex);
    this._handlerTable[opType] = tableIndex;
  }

  // High-level handler API: the handler receives a mutable state proxy and a
  // JS operation object, and returns CRABS_SUCCESS (0) on success.
  registerHandlerJs(opType, handler) {
    const M = this._M;
    const node = this;
    const wrapper = (statePtr, opPtr) => {
      const amPtr = M._crabs_wasm_handler_get_am(statePtr);
      const op = {
        type: readString(M, M._crabs_wasm_op_get_type(opPtr)),
        signerId: readString(M, M._crabs_wasm_op_get_signer(opPtr)),
        nodeId: readString(M, M._crabs_wasm_op_get_node(opPtr)),
        payload: readString(M, M._crabs_wasm_handler_op_get_payload_str(opPtr)),
      };
      const state = {
        getCounter(name) { return node._callCounterGetFromAm(M, amPtr, M._crabs_wasm_get_counter, name); },
        getPNCounter(name) { return node._callCounterGetFromAm(M, amPtr, M._crabs_wasm_get_pn_counter, name); },
        getRegister(name) { return node._callCounterGetFromAm(M, amPtr, M._crabs_wasm_get_register, name); },
        setContains(name, element) { return node._callSetContainsFromAm(M, amPtr, name, element); },
        incrementCounter(name, delta = 1, nodeId = 'system') { return node._callCounterFromAm(M, amPtr, M._crabs_wasm_increment_counter, name, delta, nodeId); },
        incrementPNCounter(name, delta = 1, nodeId = 'system') { return node._callCounterFromAm(M, amPtr, M._crabs_wasm_increment_pn_counter, name, delta, nodeId); },
        decrementPNCounter(name, delta = 1, nodeId = 'system') { return node._callCounterFromAm(M, amPtr, M._crabs_wasm_decrement_pn_counter, name, delta, nodeId); },
        setRegister(name, value, nodeId = 'system') { return node._callSetRegisterFromAm(M, amPtr, name, value, nodeId); },
        setAdd(name, element, tag = element) { return node._callSetAddFromAm(M, amPtr, name, element, tag); },
        setRemove(name, element) { return node._callSetRemoveFromAm(M, amPtr, name, element); },
        flagSet(name, setBy, setAt = 0) { return node._callFlagSetFromAm(M, amPtr, name, setBy, setAt); },
      };
      return handler(state, op);
    };
    this.registerHandler(opType, wrapper);
  }

  unregisterHandler(opType) {
    const M = this._M;
    const typePtr = writeString(M, opType);
    M._crabs_wasm_unregister_handler(this._am, typePtr);
    if (typePtr) M._free(typePtr);
    const tableIndex = this._handlerTable ? this._handlerTable[opType] : undefined;
    if (tableIndex !== undefined) {
      M.removeFunction(tableIndex);
      delete this._handlerTable[opType];
    }
  }

  _callCounterGetFromAm(M, amPtr, fn, name) {
    const nPtr = writeString(M, name);
    const raw = fn(amPtr, nPtr);
    if (nPtr) M._free(nPtr);
    return typeof raw === 'bigint' ? Number(raw) : raw;
  }

  _callSetContainsFromAm(M, amPtr, name, element) {
    const nPtr = writeString(M, name);
    const ePtr = writeString(M, element);
    const out = M._crabs_wasm_set_contains(amPtr, nPtr, ePtr);
    freeAll(M, nPtr, ePtr);
    return out;
  }

  _callCounterFromAm(M, amPtr, fn, name, delta, nodeId) {
    const nPtr = writeString(M, name);
    const idPtr = writeString(M, nodeId);
    const rc = fn(amPtr, nPtr, BigInt(delta), idPtr);
    freeAll(M, nPtr, idPtr);
    if (rc !== 0) throw crabsError(rc, 'handler counter mutation');
    return 0;
  }

  _callSetRegisterFromAm(M, amPtr, name, value, nodeId) {
    const nPtr = writeString(M, name);
    const idPtr = writeString(M, nodeId);
    const rc = M._crabs_wasm_set_register(amPtr, nPtr, BigInt(value), idPtr);
    freeAll(M, nPtr, idPtr);
    if (rc !== 0) throw crabsError(rc, 'handler setRegister');
    return 0;
  }

  _callSetAddFromAm(M, amPtr, name, element, tag) {
    const nPtr = writeString(M, name);
    const ePtr = writeString(M, element);
    const tPtr = writeString(M, tag);
    const rc = M._crabs_wasm_set_add(amPtr, nPtr, ePtr, tPtr);
    freeAll(M, nPtr, ePtr, tPtr);
    if (rc !== 0) throw crabsError(rc, 'handler setAdd');
    return 0;
  }

  _callSetRemoveFromAm(M, amPtr, name, element) {
    const nPtr = writeString(M, name);
    const ePtr = writeString(M, element);
    const rc = M._crabs_wasm_set_remove(amPtr, nPtr, ePtr);
    freeAll(M, nPtr, ePtr);
    if (rc !== 0) throw crabsError(rc, 'handler setRemove');
    return 0;
  }

  _callFlagSetFromAm(M, amPtr, name, setBy, setAt) {
    const nPtr = writeString(M, name);
    const sPtr = writeString(M, setBy);
    const rc = M._crabs_wasm_one_shot_flag_set(amPtr, nPtr, sPtr, BigInt(setAt));
    freeAll(M, nPtr, sPtr);
    if (rc !== 0) throw crabsError(rc, 'handler flagSet');
    return 0;
  }

  // ============================================================
  // Lineage (v1.7): machines mint machines
  // ============================================================

  // Registers the four lineage ops (__spawn_machine__ / __revoke_attestation__
  // / __dissolve_machine__ / __withdraw_genesis__) plus their default
  // role:admin policies on this node, so those ops can be submitted through
  // the ordinary execute() path (an __spawn_machine__ op carries a
  // Blueprint.serialize() payload). Idempotent in C.
  lineageInstall() {
    this._M._crabs_wasm_register_lineage_ops(this._am);
  }

  // Instantiates a child machine from the blueprint and appends it to this
  // node's child manifest. Returns the opaque pointer of the child machine.
  // JS NEVER owns that pointer: the parent's resident-children registry in C
  // anchors the child's lifetime, and the returned point of reference must be
  // re-resolved through lineageResidentChild rather than stashed (a dissolve
  // clears the registry slot while the manifest entry remains for history).
  lineageSpawn(blueprint) {
    const childPtr = this._M._crabs_wasm_lineage_spawn(this._am, blueprint._ptr);
    if (!childPtr) throw new Error('lineageSpawn failed');
    return childPtr;
  }

  // Borrowed pointer of the child still resident in this process (spawned
  // here and not dissolved), or null.
  lineageResidentChild(childId) {
    const M = this._M;
    const idPtr = writeString(M, childId);
    const childPtr = M._crabs_wasm_lineage_query_resident_child(this._am, idPtr);
    if (idPtr) M._free(idPtr);
    return childPtr ? childPtr : null;
  }

  childCount() {
    return this._M._crabs_wasm_lineage_children_count(this._am);
  }

  // Manifest index of childId, or -1 when the child is not manifested.
  childIndex(childId) {
    const M = this._M;
    const idPtr = writeString(M, childId);
    const index = M._crabs_wasm_lineage_find_manifest_entry(this._am, idPtr);
    if (idPtr) M._free(idPtr);
    return index;
  }

  // Flat view of the manifest entry at `index` — id/mode/status/ttlMs/
  // spawnedAt are the only fields the manifest renders to JS. Modes and
  // statuses arrive as human names ("delegated_copy", "active", ...).
  childAt(index) {
    const M = this._M;
    if (index < 0 || index >= this.childCount()) return null;
    const idPtr = M._crabs_wasm_lineage_children_get_id(this._am, index);
    if (!idPtr) return null;
    const childId = readString(M, idPtr);
    return {
      childId,
      mode: readString(M, M._crabs_wasm_lineage_children_get_mode(this._am, index)),
      status: readString(M, M._crabs_wasm_lineage_children_get_status(this._am, index)),
      ttlMs: Number(M._crabs_wasm_lineage_children_get_ttl_ms(this._am, index)),
      spawnedAt: Number(M._crabs_wasm_lineage_children_get_spawned_at(this._am, index)),
    };
  }

  childById(childId) {
    const index = this.childIndex(childId);
    return index < 0 ? null : this.childAt(index);
  }

  // Snapshot of the whole child manifest.
  children() {
    const count = this.childCount();
    const children = [];
    for (let childIndex = 0; childIndex < count; childIndex++) {
      children.push(this.childAt(childIndex));
    }
    return children;
  }

  // Issues a parent-signed attestation for an ACTIVE manifest child: the
  // parent vouches for `attributes` (comma-separated name:value pairs) of
  // `userId` in the child's domain, bounded by the child's attestation TTL.
  // Returns the attestation wire bytes (u32le total length + canonical body +
  // 64-byte parent signature) ready for transport to the child.
  attest(childId, userId, attributes) {
    const M = this._M;
    const idPtr = writeString(M, childId);
    const userPtr = writeString(M, userId);
    const attrsPtr = writeString(M, attributes);
    const ser = M._crabs_wasm_lineage_attest(this._am, idPtr, userPtr, attrsPtr);
    freeAll(M, idPtr, userPtr, attrsPtr);
    if (!ser) throw new Error('lineage attest failed (unknown or non-active child)');
    const len = M._crabs_wasm_buffer_len(ser);
    const data = M._crabs_wasm_buffer_data(ser);
    const out = new Uint8Array(M.HEAPU8.subarray(data, data + len));
    M._crabs_wasm_buffer_destroy(ser);
    return out;
  }

  // Mints a dissolution tombstone for a DISSOLVED manifest child: the
  // canonical body (u8 tag LINEAGE_DISSOLVED + string16 childId + u64le
  // parent_key_version key-stamp) plus the
  // 64-byte parent ECDSA signature. The wire has NO length prefix — these are
  // the exact bytes a __receive_dissolution__ op transports and verifies.
  // Refuses (throws) when the child is unknown or NOT currently dissolved —
  // the honesty gate is lineage_dissolution_serialize's own, in C.
  lineageTombstone(childId) {
    const M = this._M;
    const idPtr = writeString(M, childId);
    const ser = M._crabs_wasm_lineage_tombstone(this._am, idPtr);
    if (idPtr) M._free(idPtr);
    if (!ser) throw new Error('lineage tombstone failed (unknown or non-dissolved child)');
    const len = M._crabs_wasm_buffer_len(ser);
    const data = M._crabs_wasm_buffer_data(ser);
    const out = new Uint8Array(M.HEAPU8.subarray(data, data + len));
    M._crabs_wasm_buffer_destroy(ser);
    return out;
  }

  destroy() {
    if (this._am) { this._M._crabs_wasm_node_destroy(this._am); this._am = null; }
  }
}

// ============================================================
// Module exports
// ============================================================

  return { Node, KeyPair, Operation, Blueprint, TRUST_MODE, DATA_TYPE, CRDT_TYPE, getModule };
}

// UMD: CommonJS for Node/bundlers; window.CRABSWasmCore for plain <script>
// use (the static demo page builds bindings from window.createCRABSModuleDev
// via window.CRABSWasmCore(loader)).
if (typeof module === 'object' && module.exports) {
  module.exports = createBindings;
} else if (typeof window !== 'undefined') {
  window.CRABSWasmCore = createBindings;
}
