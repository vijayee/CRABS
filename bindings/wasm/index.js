//
// index.js — WebAssembly bindings for CRABS.
//
// Provides the same API as crabs-node (N-API bindings) but runs entirely
// in WebAssembly. Works in browsers, Node.js, Deno, Bun, etc.
//
// The WASM module (crabs.wasm + crabs.js) is built by build_wasm.sh. In the
// browser, load crabs.js via a <script> tag before the bundle that uses this
// module; in Node.js, it is loaded from disk automatically.
//

'use strict';

let _modulePromise = null;

function getModule() {
  if (!_modulePromise) {
    if (typeof window !== 'undefined' && typeof window.createCRABSModule === 'function') {
      // Browser: crabs.js was loaded via a <script> tag before this bundle.
      _modulePromise = window.createCRABSModule();
    } else {
      // Node.js: load the Emscripten module from disk.
      const path = require('path');
      const fs = require('fs');
      const wasmPaths = [
        path.join(__dirname, 'crabs.js'),
        path.join(__dirname, '..', '..', 'build-wasm', 'crabs.js'),
      ];
      let wasmModulePath = null;
      for (const p of wasmPaths) {
        if (fs.existsSync(p)) { wasmModulePath = p; break; }
      }
      if (!wasmModulePath) {
        throw new Error(
          'CRABS WASM module not found. Run `./build_wasm.sh` to compile it.\n' +
          'Checked: ' + wasmPaths.join(', ')
        );
      }
      const createCRABSModule = require(wasmModulePath);
      _modulePromise = createCRABSModule();
    }
  }
  return _modulePromise;
}

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
// Node
// ============================================================

class Node {
  constructor(M, amPtr) {
    this._M = M;
    this._am = amPtr;
  }

  static async create(adminId, options = {}) {
    const M = await getModule();
    const adminPtr = writeString(M, adminId);
    const amPtr = M._crabs_wasm_node_create(adminPtr);
    if (adminPtr) M._free(adminPtr);
    if (!amPtr) throw new Error('Node.create failed');
    return new Node(M, amPtr);
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
    hexDecode(M, publicKeyHex, pkPtr, 33);
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

  revokeUser(userId) {
    const M = this._M;
    const uidPtr = writeString(M, userId);
    const rc = M._attribute_machine_revoke_user(this._am, uidPtr);
    if (uidPtr) M._free(uidPtr);
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
    const signerPtr = writeString(M, 'admin');
    const nodePtr = writeString(M, 'admin');
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
    const outLenPtr = M._malloc(4);
    const ctData = M._crabs_wasm_abe_ciphertext_data(ct, outLenPtr);
    const ctLen = M.getValue(outLenPtr, 'i32');
    M._free(outLenPtr);

    const total = 2 + policyStr.length + 4 + ctLen;
    const out = new Uint8Array(total);
    const dv = new DataView(out.buffer);
    dv.setUint16(0, policyStr.length, true);
    out.set(encodeText(policyStr), 2);
    dv.setUint32(2 + policyStr.length, ctLen, true);
    out.set(new Uint8Array(M.HEAPU8.subarray(ctData, ctData + ctLen)), 2 + policyStr.length + 4);

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

  evaluateTriggers() {
    const M = this._M;
    const typePtr = writeString(M, 'noop');
    const signerPtr = writeString(M, 'admin');
    const nodePtr = writeString(M, 'admin');
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
    if (!this._handlers) this._handlers = [];
    const wrapped = M.addFunction(handler, 'ipp');
    this._handlers.push(wrapped);
    const rc = M._crabs_wasm_register_handler(this._am, typePtr, wrapped);
    if (typePtr) M._free(typePtr);
    wrapRc(rc, 'registerHandler');
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

  destroy() {
    if (this._am) { this._M._crabs_wasm_node_destroy(this._am); this._am = null; }
  }
}

// ============================================================
// Module exports
// ============================================================

module.exports = { Node, KeyPair, Operation, getModule };
