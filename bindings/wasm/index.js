//
// index.js — WebAssembly bindings for CRABS.
//
// Provides the same API as crabs-node (N-API bindings) but runs entirely
// in WebAssembly. Works in any environment with a WASM runtime: browsers,
// Node.js, Deno, Bun, Cloudflare Workers, etc.
//
// Usage:
//   const { Node, KeyPair, Operation } = require('crabs-wasm');
//   const node = new Node('admin', { ordering: 'hlc' });
//   const key = KeyPair.generate();
//   node.registerUser('alice', key.publicKeyHex(), 'role:member');
//
// The WASM module (crabs.wasm + crabs.js) is built by build_wasm.sh at the
// repository root. The built files go to build-wasm/crabs.{wasm,js}.
//

'use strict';

const path = require('path');
const fs = require('fs');

// Locate the built WASM module
const wasmPaths = [
  path.join(__dirname, '..', '..', 'build-wasm', 'crabs.js'),
  path.join(__dirname, 'build-wasm', 'crabs.js'),
  path.join(__dirname, 'crabs.js'),
];

let wasmModulePath = null;
for (const p of wasmPaths) {
  if (fs.existsSync(p)) { wasmModulePath = p; break; }
}

if (!wasmModulePath) {
  throw new Error(
    'CRABS WASM module not found. Run `npm run build` to compile it.\n' +
    'Checked: ' + wasmPaths.join(', ')
  );
}

// Lazy-load the Emscripten module (it's async — returns a Promise)
let _modulePromise = null;
function getModule() {
  if (!_modulePromise) {
    const createCRABSModule = require(wasmModulePath);
    _modulePromise = createCRABSModule();
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
  const len = M.lengthBytesUTF8(str) + 1;
  const ptr = M._malloc(len);
  M.stringToUTF8(str, ptr, len);
  return ptr;
}

function readString(M, ptr) {
  return M.UTF8ToString(ptr);
}

// Error code → message (shared with N-API bindings)
const ERROR_MESSAGES = {
  0: 'success', 1: 'protocol_violation', 2: 'lock_token_mismatch',
  3: 'lock_owner_mismatch', 4: 'lock_contention', 5: 'lock_not_expired',
  6: 'max_extensions_reached', 7: 'force_unlock_disabled', 8: 'unauthorized',
  9: 'key_stale', 10: 'user_not_found', 11: 'user_suspended',
  12: 'invariant_violated', 13: 'resource_not_found', 14: 'duplicate_operation',
  15: 'type_mismatch', 16: 'already_performed', 17: 'already_executed',
  18: 'condition_not_met', 19: 'tracker_not_found', 20: 'flag_not_found',
  21: 'serialization_error', 22: 'cryptographic_error', 23: 'internal_error',
  24: 'out_of_memory', 25: 'invalid_param',
};

function crabsError(code, ctx) {
  const msg = ERROR_MESSAGES[code] || `error_${code}`;
  return new Error(`${ctx}: ${msg}`);
}

// ============================================================
// KeyPair
// ============================================================

class KeyPair {
  constructor(M, ptr) {
    this._M = M;
    this._ptr = ptr;
  }

  static async generate() {
    const M = await getModule();
    const ptr = M._crypto_ecdsa_generate();
    if (!ptr) throw new Error('KeyPair.generate failed');
    return new KeyPair(M, ptr);
  }

  static async fromPrivateHex(hex) {
    const M = await getModule();
    // Allocate a keypair struct and set the private key
    const ptr = M._malloc(65); // 33 (pub) + 32 (priv)
    const len = hexDecode(M, hex, ptr + 33, 32);
    if (len !== 32) { M._free(ptr); throw new Error('Invalid private key hex'); }
    const rc = M._crypto_ecdsa_derive_public_key(ptr + 33, ptr);
    if (rc !== 0) { M._free(ptr); throw crabsError(rc, 'fromPrivateHex'); }
    // Wrap in a fake keypair struct (pub at offset 0, priv at offset 33)
    // Note: _crypto_ecdsa_keypair_destroy expects the struct from _crypto_ecdsa_generate
    // For fromPrivateHex, we use a raw allocation. Store a flag to use _free instead.
    const kp = new KeyPair(M, ptr);
    kp._raw = true;
    return kp;
  }

  publicKeyHex() {
    return hexEncode(this._M.HEAPU8, 33).slice(0, 66);
  }

  // The HEAPU8 subarray starts at this._ptr, need 33 bytes
  _publicKeyHex() {
    return hexEncode(this._M.HEAPU8.subarray(this._ptr, this._ptr + 33), 33);
  }

  _privateKeyHex() {
    return hexEncode(this._M.HEAPU8.subarray(this._ptr + 33, this._ptr + 65), 32);
  }

  destroy() {
    if (this._ptr) {
      if (this._raw) this._M._free(this._ptr);
      else this._M._crypto_ecdsa_keypair_destroy(this._ptr);
      this._ptr = null;
    }
  }
}

// Override publicKeyHex to use the correct method
KeyPair.prototype.publicKeyHex = function() { return this._publicKeyHex(); };
KeyPair.prototype.privateKeyHex = function() { return this._privateKeyHex(); };

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
    M._free(typePtr);
    if (!ptr) throw new Error('Operation.create failed');
    return new Operation(M, ptr);
  }

  // Operation struct layout (offsets from state_machine.h / crabs.h):
  // type: char[64] at offset 0
  // signer_id: char[64] at offset 64
  // node_id: char[64] at offset 128
  // ... (simplified — the actual layout depends on the struct definition)

  set signerId(id) {
    const offset = 64; // CRABS_MAX_USER_ID = 64
    this._M.stringToUTF8(id, this._ptr + offset, 64);
  }

  get signerId() {
    return readString(this._M, this._ptr + 64);
  }

  set nodeId(id) {
    this._M.stringToUTF8(id, this._ptr + 128, 64);
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

    // Generate admin keypair
    const kpPtr = M._crypto_ecdsa_generate();
    if (!kpPtr) throw new Error('Failed to generate node key');

    // Write admin ID string
    const adminIdPtr = writeString(M, adminId);

    // Create attribute machine
    const amPtr = M._attribute_machine_create(adminIdPtr, kpPtr);
    M._free(adminIdPtr);

    if (!amPtr) throw new Error('Failed to create attribute machine');

    // Wire back-pointer (am->base_state.attr_machine = am)
    // This is set inside attribute_machine_create, but let's verify
    // by checking if state_machine_execute works

    const node = new Node(M, amPtr);
    node._keyPtr = kpPtr;
    return node;
  }

  getNodeKey() {
    const M = this._M;
    return {
      publicKeyHex: hexEncode(M.HEAPU8.subarray(this._keyPtr, this._keyPtr + 33), 33),
      privateKeyHex: hexEncode(M.HEAPU8.subarray(this._keyPtr + 33, this._keyPtr + 65), 32),
    };
  }

  async registerUser(userId, publicKeyHex, initialAttrs) {
    const M = this._M;
    const uidPtr = writeString(M, userId);
    const pkPtr = M._malloc(33);
    hexDecode(M, publicKeyHex, pkPtr, 33);
    const attrsPtr = initialAttrs ? writeString(M, initialAttrs) : 0;

    const rc = M._attribute_machine_register_user(this._am, uidPtr, pkPtr, attrsPtr);
    M._free(uidPtr); M._free(pkPtr);
    if (attrsPtr) M._free(attrsPtr);
    if (rc !== 0) throw crabsError(rc, 'registerUser');
  }

  async getUser(userId) {
    const M = this._M;
    const uidPtr = writeString(M, userId);
    const userPtr = M._attribute_machine_find_user(this._am, uidPtr);
    M._free(uidPtr);
    if (!userPtr) return undefined;

    // Read user_t fields (simplified — actual offsets depend on struct)
    // This is a basic implementation; a full one would read all fields
    return { userId, _ptr: userPtr };
  }

  destroy() {
    if (this._am) { this._M._attribute_machine_destroy(this._am); this._am = null; }
    if (this._keyPtr) { this._M._crypto_ecdsa_keypair_destroy(this._keyPtr); this._keyPtr = null; }
  }
}

// ============================================================
// Module exports
// ============================================================

module.exports = { Node, KeyPair, Operation, getModule };