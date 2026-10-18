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

// STRICT hex decode: throws on empty input, an odd character count, or any
// non-hex character — the previous lenient form coerced garbage to 0 through
// parseInt, so a malformed key could silently become a DIFFERENT byte string
// than the caller intended. Callers that accept a specific key shape must
// still pre-gate the exact length (64 hex private / 66 hex compressed
// public / 128 hex signature) for an instructive error; this gate is the
// floor beneath every call site. Note the decode still truncates at maxLen,
// so callers verify the returned length against what they expect.
function hexDecode(M, hex, ptr, maxLen) {
  if (typeof hex !== 'string' || hex.length === 0 ||
      hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new TypeError('hexDecode: expected a non-empty even-length hex string');
  }
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

// Stage a 32-byte seal key from 64 hex chars. The caller MUST cleanse and
// free the returned pointer after the C call:
//   M.HEAPU8.fill(0, ptr, ptr + 32); M._free(ptr);
// (key bytes never linger in the module heap past the call).
function stageSealKey32(M, sealKeyHex, label) {
  if (typeof sealKeyHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(sealKeyHex)) {
    throw new TypeError(`${label}: sealKey must be 64 hex characters (32 bytes)`);
  }
  const ptr = M._malloc(32);
  hexDecode(M, sealKeyHex, ptr, 32);
  return ptr;
}

// View-typed wire-argument gate shared by deserialize / mergeState.
function requireWireBytes(bytes, label) {
  if (!ArrayBuffer.isView(bytes)) {
    throw new TypeError(`${label}: expected the snapshot wire bytes (Uint8Array)`);
  }
  return bytes;
}

// Page cap for set enumerators (mirrors the C-side
// CRABS_WASM_HANDLER_SET_PAGE_CAP in src/Util/wasm_helpers.c — keep the two
// in lockstep, the JS guard is UX-first so callers get a descriptive throw
// before the wasm round-trip; the C check is the belt-and-braces floor).
const HANDLER_SET_PAGE_CAP = 256;

// Decode the flat string-list protocol emitted by the handler read helpers
// (u16le count, then u16le byte_length + raw bytes per entry; see
// src/Util/wasm_helpers.c for the C-side producer).
function parseStringList(bytes) {
  if (bytes.length < 2) throw new Error('malformed string-list buffer');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const count = view.getUint16(0, true);
  const out = new Array(count);
  const decoder = new TextDecoder();
  let offset = 2;
  for (let i = 0; i < count; i++) {
    if (offset + 2 > bytes.length) throw new Error('malformed string-list buffer');
    const entryLength = view.getUint16(offset, true);
    offset += 2;
    if (offset + entryLength > bytes.length) throw new Error('malformed string-list buffer');
    out[i] = decoder.decode(bytes.subarray(offset, offset + entryLength));
    offset += entryLength;
  }
  return out;
}

function encodeText(str) {
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(str);
  }
  return new Uint8Array(Buffer.from(str, 'utf8'));
}

// ============================================================
// Ordered-set (OT_ORDERED_SET) constants + validation helpers
// ============================================================
// Mirrors src/OT/ot_types.h — keep in lockstep with the C enum values.

const OT_OP_INSERT = 1; // CRABS_OT_OP_INSERT
const OT_OP_DELETE = 2; // CRABS_OT_OP_DELETE
const OT_OP_MOVE   = 4; // CRABS_OT_OP_MOVE
const OT_OP_SWAP   = 5; // CRABS_OT_OP_SWAP

// Document type-specific op words (src/OT/ot_types.h) — see otDocumentApply.
const OT_OP_INSERT_TEXT  = 0x11; // CRABS_OT_OP_INSERT_TEXT
const OT_OP_DELETE_RANGE = 0x12; // CRABS_OT_OP_DELETE_RANGE
const OT_OP_APPLY_STYLE  = 0x13; // CRABS_OT_OP_STYLE
const OT_OP_MERGE_SPANS  = 0x14; // CRABS_OT_OP_MERGE_SPANS
const OT_OP_SPLIT_SPAN   = 0x15; // CRABS_OT_OP_SPLIT_SPAN
// Tree type-specific op words — see otTreeApply.
const OT_TREE_OP_INSERT_NODE = 0x21; // CRABS_OT_OP_INSERT_NODE
const OT_TREE_OP_DELETE_NODE = 0x22; // CRABS_OT_OP_DELETE_NODE
const OT_TREE_OP_REPARENT    = 0x23; // CRABS_OT_OP_REPARENT
const OT_TREE_OP_REORDER     = 0x24; // CRABS_OT_OP_REORDER

const OT_MAX_DEPS = 16;          // CRABS_OT_MAX_DEPS
const OT_ELEMENT_MAX_BYTES = 4096; // CRABS_OT_MAX_PAYLOAD (wasm export copies
                                  // at most this per element)
const OT_TREE_NODE_ID_MAX = 64;  // CRABS_TREE_NODE_ID_MAX

// The OT op identity + causal deps every ot* apply op sugar carries — the
// same contract the ordered-set sugar validates inline (see
// _orderedSetApply): id { node, seq, ts? } is required, deps is an
// optional array of at most OT_MAX_DEPS such ids.
function _otOpIdentity(options, context) {
  if (!options || typeof options.id !== 'object' || options.id === null) {
    throw new Error(
      `${context}: id is required — { node, seq, ts? } fixes the op's OT identity`);
  }
  const id = options.id;
  if (typeof id.node !== 'string' || id.node.length === 0) {
    throw new Error(
      `${context}: id.node is required (string, the issuing replica's id)`);
  }
  if (!Number.isInteger(id.seq) || id.seq < 0) {
    throw new Error(
      `${context}: id.seq is required (integer >= 0, unique per ${id.node})`);
  }
  if (id.ts !== undefined && (!Number.isInteger(id.ts) || id.ts < 0)) {
    throw new Error(`${context}: id.ts must be a non-negative integer ms stamp`);
  }
  const deps = options.deps === undefined ? [] : options.deps;
  if (!Array.isArray(deps) || deps.length > OT_MAX_DEPS) {
    throw new Error(
      `${context}: deps must be an array of at most ${OT_MAX_DEPS} { node, seq, ts? } ids`);
  }
  return { id, deps };
}

// Parse one packed document-span record:
//   [u32le style_count][u32le text_len][text][styles: u32le len + bytes]
function _otDocumentSpanParse(M, bufPtr, writtenSize) {
  if (writtenSize <= 0) throw crabsError(0x5001, 'getOTDocument');
  const bytes = new Uint8Array(M.HEAPU8.subarray(bufPtr, bufPtr + writtenSize));
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const styleCount = view.getUint32(0, true);
  const textLen = view.getUint32(4, true);
  const text = OT_TEXT_DECODER.decode(bytes.subarray(8, 8 + textLen));
  let offset = 8 + textLen;
  const styles = new Array(styleCount);
  for (let styleIndex = 0; styleIndex < styleCount; styleIndex++) {
    const styleNameLen = view.getUint32(offset, true); offset += 4;
    const styleName = OT_TEXT_DECODER.decode(bytes.subarray(offset, offset + styleNameLen));
    offset += styleNameLen;
    const styleValueLen = view.getUint32(offset, true); offset += 4;
    const styleValue = OT_TEXT_DECODER.decode(bytes.subarray(offset, offset + styleValueLen));
    offset += styleValueLen;
    styles[styleIndex] = { name: styleName, value: styleValue };
  }
  // textLen is the C byte count (the visible_char_count currency — the C
  // document counts bytes); a JS consumer reading charCount gets that
  // number back verbatim.
  return { text, textLen, styles };
}

// Parse one packed tree-node record:
//   [id 64 NUL-padded][parent_id 64 NUL-padded][u32le value_len][value]
function _otTreeNodeParse(M, bufPtr, writtenSize) {
  if (writtenSize < 128) throw crabsError(0x5001, 'getOTTree');
  const bytes = new Uint8Array(M.HEAPU8.subarray(bufPtr, bufPtr + writtenSize));
  const readFixed64 = (offset) => {
    let end = offset;
    while (end < offset + 64 && bytes[end] !== 0) end++;
    return OT_TEXT_DECODER.decode(bytes.subarray(offset, end));
  };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const valueLen = view.getUint32(128, true);
  const value = valueLen === 0 ? '' : OT_TEXT_DECODER.decode(bytes.subarray(132, 132 + valueLen));
  return { id: readFixed64(0), parentId: readFixed64(64), value };
}

const OT_TEXT_ENCODER = { encode: (text) => encodeText(text) };
const OT_TEXT_DECODER = typeof TextDecoder !== 'undefined'
  ? new TextDecoder()
  : { decode: (bytes) => Buffer.from(bytes).toString('utf8') };

function validateOrderedPosition(position, context, minimum) {
  if (!Number.isInteger(position) || position < minimum ||
      position > Number.MAX_SAFE_INTEGER) {
    throw new RangeError(
      `${context}: position must be an integer >= ${minimum}`);
  }
  return position;
}

function validateOrderedElement(element, context) {
  const byteLength = encodeText(element).length;
  if (byteLength > OT_ELEMENT_MAX_BYTES) {
    throw new RangeError(
      `${context}: element payload exceeds the ${OT_ELEMENT_MAX_BYTES}-byte OT limit (${byteLength} bytes)`);
  }
}

// Pack ordered-set causal deps into the C exporter's record layout: each
// record is node_id as up-to-63 NUL-padded bytes + sequence_num (u64le) +
// timestamp (u64le) — 80 bytes (see OT_DEP_RECORD_SIZE in wasm_helpers.c).
function packOrderedDeps(deps, context) {
  const bytes = new Uint8Array(deps.length * 80);
  const view = new DataView(bytes.buffer);
  let offset = 0;
  for (const dep of deps) {
    if (!dep || typeof dep !== 'object' || typeof dep.node !== 'string' ||
        dep.node.length === 0) {
      throw new TypeError(
        `${context}: each dep must be { node: string, seq: number, ts?: number }`);
    }
    if (!Number.isInteger(dep.seq) || dep.seq < 0) {
      throw new TypeError(`${context}: dep "${dep.node}" needs an integer seq`);
    }
    const nodeBytes = encodeText(dep.node);
    if (nodeBytes.length >= 64) {
      throw new RangeError(
        `${context}: dep node id "${dep.node}" exceeds 63 bytes`);
    }
    bytes.set(nodeBytes, offset);
    view.setBigUint64(offset + 64, BigInt(dep.seq), true);
    view.setBigUint64(offset + 72, BigInt(dep.ts === undefined ? 0 : dep.ts), true);
    offset += 80;
  }
  return bytes;
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
  0xA001: 'not_item_writer', 0xA002: 'seq_mismatch', 0xA003: 'fork_detected',
  0xA004: 'ordering_path', 0xA005: 'quarantined',
  0xA006: 'ordering_pending', 0xA007: 'ordering_not_leader',
  0xA008: 'ordering_change_in_flight',
  // 0x8xxx: OT errors (v1.5 §8)
  0x8001: 'no_ot_ops', 0x8002: 'not_ot_type', 0x8003: 'ot_transform_depth',
  0x8004: 'ot_position_bounds',
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

// Zeroize then free — for staging buffers whose bytes include key material
// (a private key, a bearer token, decrypted plaintext). dlmalloc's free list
// recycles chunks verbatim, so releasing secrets without wiping hands those
// bytes to the next allocation in module heap.
function wipeFree(M, ptr, len) {
  if (!ptr) return;
  M.HEAPU8.fill(0, ptr, ptr + len);
  M._free(ptr);
}

// Skew configuration surface (bounded-skew replay fix). Defaults mirror the
// C library exactly (BOUNDED strategy / 5000ms window / reject on replay) so
// Node.create(id) remains byte-identical to today's behavior.
function parseSkewOptions(options) {
  const skew = {
    strategy: 0x01,       // HLC_STRATEGY_BOUNDED
    maxSkewMs: 0,         // 0 keeps the C-side CRABS_HLC_DEFAULT_MAX_SKEW_MS (sentinel, NOT unbounded)
    replayPolicy: 0,      // CRABS_HLC_REPLAY_REJECT
  };
  if (!options || !options.skew) return skew;
  const skewInput = options.skew;
  if (typeof skewInput !== 'object') {
    throw new TypeError('Node.create: skew must be an options object');
  }
  if (skewInput.strategy !== undefined) {
    // Object.create(null) + Object.hasOwn: an `in` check would accept
    // prototype-chain strings like 'toString' and map a Function to the wasm
    // i32 param (NaN→0 = HLC_STRATEGY_NAIVE, silently disarming the skew
    // defense instead of throwing).
    const strategyNames = Object.assign(Object.create(null), {
      naive: 0x00, bounded: 0x01, quorum: 0x02, strict: 0x03, trusted: 0x04,
    });
    if (typeof skewInput.strategy !== 'string' ||
        !Object.hasOwn(strategyNames, skewInput.strategy)) {
      throw new TypeError(
          "Node.create: skew.strategy must be one of 'naive'|'bounded'|'quorum'|'strict'|'trusted'");
    }
    skew.strategy = strategyNames[skewInput.strategy];
  }
  if (skewInput.maxSkewMs !== undefined) {
    // Number.isSafeInteger, not Number.isInteger: max_skew_ms crosses the
    // wasm ABI as an i64 (BigInt ABI), so the value must survive 2^53-exact
    // BigInt coercion — anything wider silently rounds BEFORE the cast.
    if (typeof skewInput.maxSkewMs !== 'number' || !Number.isSafeInteger(skewInput.maxSkewMs) ||
        skewInput.maxSkewMs < 0) {
      throw new TypeError('Node.create: skew.maxSkewMs must be a non-negative safe integer');
    }
    skew.maxSkewMs = skewInput.maxSkewMs;
  }
  if (skewInput.replayPolicy !== undefined) {
    const replayNames = Object.assign(Object.create(null), { reject: 0, clamp: 1 });
    if (typeof skewInput.replayPolicy !== 'string' ||
        !Object.hasOwn(replayNames, skewInput.replayPolicy)) {
      throw new TypeError(
          "Node.create: skew.replayPolicy must be 'reject' or 'clamp'");
    }
    skew.replayPolicy = replayNames[skewInput.replayPolicy];
  }
  return skew;
}

// Protocol states (protocol_state_e, src/CRABS/data_model.h:58-65) as the
// JS words the recipes use; the executor consumes the numbers 0..4 in the
// op's per-resource required_state / next_state arrays.
const PROTOCOL_STATE_WORDS = { idle: 0, locked: 1, modified: 2, verified: 3, error: 4 };
const PROTOCOL_STATE_NAMES = ['idle', 'locked', 'modified', 'verified', 'error'];

// Integer-only guard for register writes (consumption finding 1). Registers
// carry an int64 in C; BigInt(non-integer) would throw a generic RangeError
// and numbers past ±2^53 silently lose precision. Reject early with an
// instructive message so callers encode fractional quantities as scaled
// integers (per-mille pattern) or pass a BigInt for the full int64 range.
function validateRegisterInt(value, ctx) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new Error(`${ctx}: registers are integer-only; encode fractional values in register units (e.g. per-mille)`);
    }
    if (Math.abs(value) > Number.MAX_SAFE_INTEGER) {
      throw new Error(`${ctx}: registers are integer-only; |value| exceeds Number.MAX_SAFE_INTEGER — pass a BigInt for exact int64 precision`);
    }
    return BigInt(value);
  }
  throw new Error(`${ctx}: registers are integer-only; value must be an integer number or a BigInt (encode fractional values in register units, e.g. per-mille)`);
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
    // Exact-shape gate ahead of the strict decoder: a longer hex body would
    // truncate into the 32-byte window and mint a DIFFERENT key than the
    // caller named; a shorter one fails the length check below.
    if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex)) {
      throw new TypeError('KeyPair.fromPrivateHex: hex must be 64 hex characters (32 bytes)');
    }
    const M = await getModule();
    const ptr = M._malloc(65);
    const len = hexDecode(M, hex, ptr, 32);
    if (len !== 32) { wipeFree(M, ptr, 32); throw new Error('Invalid private key hex'); }
    const rc = M._crypto_ecdsa_derive_public_key(ptr, ptr + 32);
    if (rc !== 0) { wipeFree(M, ptr, 32); throw crabsError(rc, 'fromPrivateHex'); }
    const kp = new KeyPair(M, ptr);
    kp._raw = true;
    return kp;
  }

  static async derivePublicHex(hex) {
    if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex)) {
      throw new TypeError('KeyPair.derivePublicHex: hex must be 64 hex characters (32 bytes)');
    }
    const M = await getModule();
    const priv = M._malloc(32);
    const pub = M._malloc(33);
    const len = hexDecode(M, hex, priv, 32);
    if (len !== 32) { M._free(pub); wipeFree(M, priv, 32); throw new Error('Invalid private key hex'); }
    const rc = M._crypto_ecdsa_derive_public_key(priv, pub);
    const out = rc === 0 ? hexEncode(M.HEAPU8.subarray(pub, pub + 33), 33) : '';
    M._free(pub);
    wipeFree(M, priv, 32);
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
      // The _raw form is a bare 65-byte frame whose first 32 bytes are the
      // private key — wipe before free (the C destroy path cleanses itself).
      if (this._raw) wipeFree(this._M, this._ptr, 32);
      else this._M._crypto_ecdsa_keypair_destroy(this._ptr);
      this._ptr = null;
    }
  }
}

// ============================================================
// AbeKey
// ============================================================

// A machine-derived CP-ABE reader key (gap-fill A11): abeKeygen derives it
// from the machine's OWN master authority, so JS never touches the master
// secret — the machine mints it, JS holds only the derived key. JS OWNS
// the pointer: release it with destroy() (the KeyPair contract; it is
// idempotent). Portable bytes exist only through toWire(): the C
// crypto_abe_user_key_serialize form — a SELF-SUFFICIENT BEARER image of the
// key: restored on ANY machine (Node.abeKeyFromWire asks only that the
// machine holds an authority; the C deserialize takes mk, but OpenABE's key
// import binds capability to the key's own minting domain, so the restored
// key opens EXACTLY what its minting authority sealed — verified
// cross-machine in key-transport.js), with no integrity check of its own.
// Transport it authenticated, or use the key envelope flow
// (mintKeyEnvelope/decryptKeyEnvelope): the signed, ECIES-wrapped transport
// for channels you do not trust.
class AbeKey {
  constructor(M, ptr) {
    this._M = M;
    this._ptr = ptr;
  }

  destroy() {
    if (this._ptr) {
      this._M._crabs_wasm_abe_key_destroy(this._ptr);
      this._ptr = null;
    }
  }

  // Portable reader-key wire image (crypto_abe_user_key_serialize). The
  // bytes ARE the key — a bearer instrument; toWire() on a destroyed key
  // refuses (the bytes cannot outlive the key object). The C staging buffer
  // is destroyed through the KEY-WIRE cleansed teardown once this copy-out
  // has read it (P4 review: the staged key bytes never linger in the module
  // heap — the shared buffer destroy would merely free them).
  toWire() {
    if (!this._ptr) {
      throw new Error('abeKey.toWire: a destroyed key refuses');
    }
    const M = this._M;
    const ser = M._crabs_wasm_abe_key_serialize(this._ptr);
    if (!ser) throw new Error('abeKey.toWire: serialization failed');
    const len = M._crabs_wasm_buffer_len(ser);
    const data = M._crabs_wasm_buffer_data(ser);
    const out = new Uint8Array(M.HEAPU8.subarray(data, data + len));
    M._crabs_wasm_key_wire_buffer_destroy(ser);
    return out;
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
    wrapRc(M._crabs_wasm_op_init_uuid(ptr), 'Operation.create');
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

  // Append a resource name to the op (capacity 8). An op naming a SOVEREIGN
  // item among its resources must carry a matching sovereign prefix per
  // sovereign resource — DOMAIN_CHECK enforces the exact count.
  addResource(name) {
    const M = this._M;
    const namePtr = writeString(M, name);
    const rc = M._crabs_wasm_op_add_resource(this._ptr, namePtr);
    if (namePtr) M._free(namePtr);
    wrapRc(rc, 'addResource');
    return this;
  }

  // Recipe 9: set the per-slot protocol state at `slotIndex` (slots are
  // created IDLE by addResource). The executor's step 4 checks
  // item->protocol_state == op->requiredState[index] for EVERY named
  // resource before anything moves. stateWord: 'idle' | 'locked' |
  // 'modified' | 'verified' | 'error'. Signed (format v4 §6/§7) — set
  // BEFORE signing. Chainable.
  _setProtocolState(exportFn, ctx, slotIndex, stateWord) {
    const M = this._M;
    const state = PROTOCOL_STATE_WORDS[stateWord];
    if (state === undefined) {
      throw new RangeError(`${ctx}: stateWord must be 'idle' | 'locked' | 'modified' | 'verified' | 'error'`);
    }
    if (!Number.isInteger(slotIndex) || slotIndex < 0 || slotIndex > 7) {
      throw new RangeError(`${ctx}: slotIndex must be an integer 0..7`);
    }
    const rc = exportFn(this._ptr, slotIndex, state);
    wrapRc(rc, ctx);
    return this;
  }

  setRequiredState(slotIndex, stateWord) {
    return this._setProtocolState(this._M._crabs_wasm_op_set_required_state,
      'setRequiredState', slotIndex, stateWord);
  }

  setNextState(slotIndex, stateWord) {
    return this._setProtocolState(this._M._crabs_wasm_op_set_next_state,
      'setNextState', slotIndex, stateWord);
  }

  // Recipe 9: append one lock claim — the resource name plus the 32-byte
  // bearer token the op claims to hold (the executor verifies presented
  // claims against the item's live lock token; state_machine.c step 5).
  // tokenHex is 64 hex chars. Signed (format v4 §8) — set BEFORE signing.
  // Chainable.
  addLockClaim(resource, tokenHex) {
    const M = this._M;
    if (typeof tokenHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(tokenHex)) {
      throw new Error('addLockClaim: tokenHex must be 64 hex chars (32 bytes)');
    }
    const resourcePtr = writeString(M, resource);
    const tokenPtr = M._malloc(32);
    hexDecode(M, tokenHex, tokenPtr, 32);
    const rc = M._crabs_wasm_op_add_lock_claim(this._ptr, resourcePtr, tokenPtr, 32);
    // tokenPtr staged the 32-byte BEARER lock token — wipe before free so the
    // live credential never sits on dlmalloc's free list (the getLockState
    // readback already wipeFrees the same bytes).
    wipeFree(M, tokenPtr, 32);
    freeAll(M, resourcePtr);
    wrapRc(rc, 'addLockClaim');
    return this;
  }

  // Recipe 12 (attestation bridge): attach one parent-signed attestation to
  // the op — the credential an executor `@parent/` endorsement policy
  // resolves against (_verify_parent_endorsements, state_machine.c). The
  // fields are the canonical attestation body (parse them out of the
  // parent's attest() wire image — u32le length + format_version + string16
  // parent/child/user/attributes + u64le not_before/expires_at/
  // parent_key_version + 64-byte signature). The signature must decode to
  // 64 bytes (CRABS_SIG_SIZE) or the attach refuses loudly. Attestations
  // ride the op WIRE as transport (format v5+) but are NOT part of the
  // canonical signing form — the parent's own ECDSA covers each body. Set
  // BEFORE signing; the executor verifies during authorization regardless.
  // Chainable.
  addAttestation(attestation) {
    const M = this._M;
    if (!attestation || typeof attestation !== 'object' ||
        Array.isArray(attestation)) {
      throw new Error(
        'addAttestation: expected { parentId, childId, userId, attributes, notBefore?, expiresAt?, parentKeyVersion, signatureHex }');
    }
    for (const field of ['parentId', 'childId', 'userId', 'attributes']) {
      if (typeof attestation[field] !== 'string') {
        throw new Error(`addAttestation: ${field} must be a string`);
      }
    }
    if (typeof attestation.signatureHex !== 'string' ||
        !/^[0-9a-fA-F]{128}$/.test(attestation.signatureHex)) {
      throw new Error(
        'addAttestation: signatureHex must be 128 hex chars (64 bytes)');
    }
    // The chain-TIP version the parent stamped (attestation body field) —
    // the executor's endorsement verifier compares it with the child's
    // chain tip exactly, so it is required.
    if (attestation.parentKeyVersion === undefined ||
        attestation.parentKeyVersion === null) {
      throw new Error(
        'addAttestation: parentKeyVersion is required (the chain TIP version the parent stamped)');
    }
    // Timestamps/versions: accept integer numbers or BigInts; fractional or
    // out-of-range values would wrap through the u64 wire — refuse.
    const stampToBigInt = (value, field) => {
      if (value === undefined || value === null) return 0n;
      if (typeof value === 'bigint') {
        // The wire fields are u64le; a BigInt above 2^64-1 WRAPS through
        // Emscripten's BigInt→i64 marshaling instead of failing, so the cap
        // must live here.
        if (value < 0n || value > 0xFFFFFFFFFFFFFFFFn) {
          throw new RangeError(
            `addAttestation: ${field} must be within the u64 range (0..2^64-1)`);
        }
        return value;
      }
      if (Number.isInteger(value) && value >= 0) return BigInt(value);
      throw new RangeError(
        `addAttestation: ${field} must be a non-negative integer or BigInt`);
    };
    const notBefore = stampToBigInt(attestation.notBefore, 'notBefore');
    const expiresAt = stampToBigInt(attestation.expiresAt, 'expiresAt');
    const parentKeyVersion = stampToBigInt(
      attestation.parentKeyVersion, 'parentKeyVersion');

    const idPtrs = {};
    for (const field of ['parentId', 'childId', 'userId', 'attributes']) {
      idPtrs[field] = writeString(M, attestation[field]);
    }
    const sigPtr = M._malloc(64);
    hexDecode(M, attestation.signatureHex, sigPtr, 64);
    const rc = M._crabs_wasm_op_add_attestation(
      this._ptr, idPtrs.parentId, idPtrs.childId, idPtrs.userId,
      idPtrs.attributes, notBefore, expiresAt, parentKeyVersion, sigPtr, 64);
    freeAll(M, idPtrs.parentId, idPtrs.childId, idPtrs.userId,
            idPtrs.attributes, sigPtr);
    wrapRc(rc, 'addAttestation');
    return this;
  }

  // Write-domains v1 (op format v6, signing format v4): the sovereign chain
  // prefix at prefixIndex — item_seq plus the 32-byte digest of the item at
  // that sequence, either as 64 hex chars or 32 raw bytes. Set BEFORE
  // signing; the signature binds the prefixes. Chainable.
  setSovereignPrefix(prefixIndex, seq, digest) {
    const M = this._M;
    // BigInt(seq) throws on fractional numbers but silently wraps negatives
    // through the unsigned i64 wire; refuse both loudly.
    const seqIsValid = typeof seq === 'bigint'
      ? seq >= 0n
      : Number.isInteger(seq) && seq >= 0;
    if (!seqIsValid) {
      throw new RangeError(
        'setSovereignPrefix: seq must be a non-negative integer');
    }
    let digestBytes;
    if (typeof digest === 'string') {
      if (!/^[0-9a-fA-F]{64}$/.test(digest)) {
        throw new Error('setSovereignPrefix: digest hex must be 64 hex chars');
      }
      const digestPtr = M._malloc(32);
      const decoded = hexDecode(M, digest, digestPtr, 32);
      if (decoded !== 32) {
        M._free(digestPtr);
        throw new Error('setSovereignPrefix: digest hex decode failed');
      }
      digestBytes = new Uint8Array(M.HEAPU8.subarray(digestPtr, digestPtr + 32));
      M._free(digestPtr);
    } else {
      digestBytes = digest;
      if (!digestBytes || digestBytes.length !== 32) {
        throw new Error('setSovereignPrefix: digest must be 32 bytes');
      }
    }
    const { ptr, len } = writeBytes(M, digestBytes);
    const rc = M._crabs_wasm_op_set_sovereign_prefix(
        this._ptr, prefixIndex, BigInt(seq), ptr);
    if (ptr) M._free(ptr);
    wrapRc(rc, 'setSovereignPrefix');
    return this;
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

  // Op format version this op carries. Fresh ops report the build's
  // CRABS_OP_FORMAT_VERSION; deserialized ops report the version declared on
  // the wire. Compare against wireVersions.op to detect skew.
  getWireVersion() {
    return this._M._crabs_wasm_op_get_wire_version(this._ptr);
  }

  destroy() {
    if (this._ptr) { this._M._operation_destroy(this._ptr); this._ptr = null; }
  }
}

// ============================================================
// Wire-version diagnostics (consumption-fixes finding 5)
// ============================================================
// Mirrors the three wire-format constants from C (no JS hardcoding — no
// drift between wrapper and library). The Promise is cached so the lookup
// happens once per process; the resolved value is frozen.
//   state   — CRABS_SERIAL_VERSION (state wire format, serialization.h)
//   op      — CRABS_OP_FORMAT_VERSION (op wire format, state_machine.h)
//   signing — CRABS_SIGNING_FORMAT_VERSION (signing canonical form, §7.5)
let _wireVersionsPromise = null;
function wireVersions() {
  if (!_wireVersionsPromise) {
    _wireVersionsPromise = getModule().then((M) => {
      const ptr = M._malloc(12);
      try {
        M._crabs_wasm_wire_versions(ptr);
        const u32 = (offset) => M.HEAPU32[(ptr >> 2) + offset] >>> 0;
        return Object.freeze({
          state: u32(0),
          op: u32(1),
          signing: u32(2),
        });
      } finally {
        M._free(ptr);
      }
    });
  }
  return _wireVersionsPromise;
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
  OT_ORDERED_SET: 0x10,
};
const CRDT_TYPE = {
  G_COUNTER: 0x01, PN_COUNTER: 0x02, OR_SET: 0x03, LWW_REG: 0x05,
  ONE_SHOT_SET: 0x08, ONE_SHOT_FLAG: 0x09, CUSTOM: 0xFF,
};

// crabs_write_domain_e (crabs.h) — the write-domains v1 declaration values
// Blueprint.addItem's options carry (crabs_wasm_lineage_blueprint_add_item_domain).
const WRITE_DOMAIN = {
  FREE: 0x00, SOVEREIGN: 0x01, GROUP_ORDERED: 0x02,
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

  // Append a replicated data item to the child's definition. With an
  // options object ({ domain: WRITE_DOMAIN.*, writer?: string }) the item
  // carries a write-domains v1 declaration at MINT time
  // (blueprint_add_item_with_domain, lineage.h:147): a SOVEREIGN item needs
  // its writer id (and stays v1-restricted to COUNTER/REGISTER — the C
  // authoring gate refuses type_mismatch), a writer on any other domain
  // refuses invalid_param. Without options this is the plain FREE-MERGE
  // append (blueprint_add_item).
  addItem(name, dataType, crdtType, options = {}) {
    const M = this._M;
    const namePtr = writeString(M, name);
    let rc;
    if (options && (options.domain !== undefined || options.writer)) {
      // A writer with no explicit domain is authored against the DEFAULT
      // domain (FREE, 0x00) — the C helper then refuses it with its own
      // invalid_param ("writer set on a non-SOVEREIGN domain"), which the
      // caller sees as-is; only an out-of-table domain number refuses here.
      const domain = options.domain === undefined
        ? WRITE_DOMAIN.FREE : options.domain;
      if (!Number.isInteger(domain) ||
          Object.values(WRITE_DOMAIN).indexOf(domain) < 0) {
        freeAll(M, namePtr);
        throw new Error(
          'blueprint.addItem: domain must be a WRITE_DOMAIN value (FREE | ' +
          'SOVEREIGN | GROUP_ORDERED)');
      }
      const writerPtr = options.writer ? writeString(M, options.writer) : 0;
      rc = M._crabs_wasm_lineage_blueprint_add_item_domain(
          this._ptr, namePtr, dataType, crdtType, domain, writerPtr,
          0 /* v1: no ordering modules exist; only module 0 is legal */);
      if (writerPtr) M._free(writerPtr);
    } else {
      rc = M._crabs_wasm_lineage_blueprint_add_item(
          this._ptr, namePtr, dataType, crdtType);
    }
    if (namePtr) M._free(namePtr);
    wrapRc(rc, 'blueprint.addItem');
  }

  // Author a dedup spec INTO the child's registry (blueprint_add_op_type_def,
  // lineage.h:157): at spawn the spec lands in the child's op-type registry
  // (state_register_op_type_def), so the executor enforces it there exactly
  // like a machine-local defineOperationType would — same shape, same
  // refusal words. The 'custom' shape stays C-native (parity with
  // defineOperationType); paths/messages obey the C buffer caps, refused
  // loudly rather than silently truncated.
  addOpType(opType, options = {}) {
    const M = this._M;
    if (!options || typeof options !== 'object') {
      throw new Error('blueprint.addOpType: expected an options object with a dedup field');
    }
    if (typeof opType !== 'string' || opType.length === 0) {
      throw new Error('blueprint.addOpType: opType must be a non-empty string');
    }
    const DEDUP_NUMBERS = { none: 0, 'per-user': 1, global: 2 };
    const dedupType = DEDUP_NUMBERS[options.dedup];
    if (dedupType === undefined) {
      throw new Error("blueprint.addOpType: dedup must be 'per-user' | 'global' | 'none' (" +
        "the 'custom' shape is C-native and not surfaceable)");
    }
    if (options.dedup === 'per-user' && !options.trackerPath) {
      throw new Error("blueprint.addOpType: dedup 'per-user' requires a trackerPath (the ONE_SHOT_SET once-record item, carried in the same blueprint)");
    }
    if (options.dedup === 'none' && (options.trackerPath || options.flagPath)) {
      throw new Error("blueprint.addOpType: dedup 'none' takes no trackerPath/flagPath (a 'none' definition removes the guard; nothing to track)");
    }
    if (options.dedup === 'global' && !options.flagPath) {
      throw new Error("blueprint.addOpType: dedup 'global' requires a flagPath (the ONE_SHOT_FLAG once-record item, carried in the same blueprint)");
    }
    // The C spec fields are CRABS_MAX_DEDUP_PATH (128) / CRABS_MAX_DEDUP_MESSAGE
    // (256) bytes — a longer string would be silently truncated into a
    // tracker/flag lookup that never resolves (or a cut-off message), so
    // refuse loudly instead. The C buffers count BYTES, so measure the UTF-8
    // encoding, never the UTF-16 string length.
    const DEDUP_PATH_MAX = 127;
    const DEDUP_MESSAGE_MAX = 255;
    if (options.trackerPath && encodeText(options.trackerPath).length > DEDUP_PATH_MAX) {
      throw new Error(`blueprint.addOpType: trackerPath exceeds ${DEDUP_PATH_MAX} bytes`);
    }
    if (options.flagPath && encodeText(options.flagPath).length > DEDUP_PATH_MAX) {
      throw new Error(`blueprint.addOpType: flagPath exceeds ${DEDUP_PATH_MAX} bytes`);
    }
    if (options.rejectionMessage && encodeText(options.rejectionMessage).length > DEDUP_MESSAGE_MAX) {
      throw new Error(`blueprint.addOpType: rejectionMessage exceeds ${DEDUP_MESSAGE_MAX} bytes`);
    }
    const opTypePtr = writeString(M, opType);
    const trackerPtr = options.trackerPath ? writeString(M, options.trackerPath) : 0;
    const flagPtr = options.flagPath ? writeString(M, options.flagPath) : 0;
    const messagePtr = options.rejectionMessage ? writeString(M, options.rejectionMessage) : 0;
    const rc = M._crabs_wasm_lineage_blueprint_add_op_type(
        this._ptr, opTypePtr, dedupType, trackerPtr, flagPtr, messagePtr);
    freeAll(M, opTypePtr, trackerPtr, flagPtr, messagePtr);
    wrapRc(rc, 'blueprint.addOpType');
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
    // Skew configuration (bounded-skew replay fix): { strategy, maxSkewMs,
    // replayPolicy }. Defaults produce the same config the 1-arg C entry
    // always produced — Node.create(id) is byte-identical to today's.
    // Validate options BEFORE staging the admin id: a rejected create must
    // not leak the writeString allocation into the module heap.
    const skew = parseSkewOptions(options);
    const adminPtr = writeString(M, adminId);
    // max_skew_ms crosses the wasm ABI as i64 → a BigInt is REQUIRED at the
    // call site (a Number throws `Cannot convert N to a BigInt`)
    const amPtr = M._crabs_wasm_node_create_ex(
        adminPtr, skew.strategy, BigInt(skew.maxSkewMs), skew.replayPolicy);
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
    // Exact compressed-secp256k1 shape ahead of the strict decoder — a longer
    // body would truncate into the 33-byte window and register a DIFFERENT
    // public key than the caller named.
    if (typeof publicKeyHex !== 'string' || !/^[0-9a-fA-F]{66}$/.test(publicKeyHex)) {
      throw new TypeError('registerUser: publicKeyHex must be 66 hex characters (33 bytes, compressed)');
    }
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

  // --- Keyring lifecycle (parity-fill P2, v1.3 §9) ---
  //
  // The C keyring primitives are user_t-scoped; these wrappers resolve the
  // user id through attribute_machine_find_user and refuse with the same
  // typed `user_not_found` the C machine would report for an unknown id.
  // The primitives carry no signer gate by design — the wire ops
  // (__suspend_key__ / __activate_key__ / __rotate_key__) own the policy
  // story; these run through the module's own authority.

  _resolveUser(ctx, userId) {
    const M = this._M;
    const uidPtr = writeString(M, userId);
    const userPtr = M._crabs_wasm_find_user(this._am, uidPtr);
    if (uidPtr) M._free(uidPtr);
    if (!userPtr) throw crabsError(0x2003, ctx);
    return userPtr;
  }

  suspendKey(userId, keyId) {
    const M = this._M;
    const userPtr = this._resolveUser('suspendKey', userId);
    const kidPtr = writeString(M, keyId);
    const rc = M._crabs_wasm_user_key_suspend(userPtr, kidPtr);
    if (kidPtr) M._free(kidPtr);
    wrapRc(rc, 'suspendKey');
  }

  activateKey(userId, keyId) {
    const M = this._M;
    const userPtr = this._resolveUser('activateKey', userId);
    const kidPtr = writeString(M, keyId);
    const rc = M._crabs_wasm_user_key_activate(userPtr, kidPtr);
    if (kidPtr) M._free(kidPtr);
    wrapRc(rc, 'activateKey');
  }

  // Shape follows the C rotate signature exactly (attribute_machine.h:221):
  // (old, new, scheme, pk bytes, label) — the JS opts carry the same fields
  // as explicit args; nothing is auto-generated. opts.publicKeyHex is
  // REQUIRED (the C rotate refuses empty material itself, but the wrapper
  // refuses earlier so the caller gets a typed, actionable error), and
  // opts.scheme accepts the same lowercase word map the sig_scheme.h ids
  // take on the wire or a raw number.
  rotateKey(userId, oldKeyId, newKeyId, opts = {}) {
    if (!opts || typeof opts !== 'object' || Array.isArray(opts) ||
        typeof opts.publicKeyHex !== 'string' || opts.publicKeyHex.length === 0) {
      throw new TypeError('rotateKey: opts.publicKeyHex is required (the C rotate signs no auto-generated material)');
    }
    const SCHEME_NUMBERS = {
      ecdsa_secp256k1: 0x01, ecdsa_p256: 0x02, ed25519: 0x03,
      schnorr_secp256k1: 0x04, bls_bls12_381: 0x05,
      rsa_2048: 0x06, rsa_4096: 0x07,
      dilithium_2: 0x08, dilithium_3: 0x09, dilithium_5: 0x0A,
      falcon_512: 0x0B, falcon_1024: 0x0C, sphincs_plus_128s: 0x0D,
    };
    // The C field is the signature_scheme_e number; unknown words refuse
    // here so nothing truncates through the int32 wire cast.
    const schemeNumber = typeof opts.scheme === 'number'
      ? opts.scheme
      : SCHEME_NUMBERS[opts.scheme === undefined ? 'ecdsa_secp256k1' : opts.scheme];
    if (schemeNumber === undefined || !Number.isInteger(schemeNumber) ||
        schemeNumber < 0 || schemeNumber > 0xFF) {
      throw new RangeError(
        "rotateKey: scheme must be a sig_scheme.h word or id (e.g. 'ecdsa_secp256k1')");
    }
    // A malformed hex body would coerce to 0 through hexDecode (it trusts
    // its input) — regex-gate the shape, mirroring addLockClaim.
    const pkHex = (opts.publicKeyHex.length % 2 === 0 &&
                   /^[0-9a-fA-F]+$/.test(opts.publicKeyHex))
      ? opts.publicKeyHex : '';
    if (pkHex.length === 0 || pkHex.length / 2 > 512) {  // CRABS_MAX_PUBLIC_KEY
      throw new Error('rotateKey: publicKeyHex must be even-length hex, at most 512 bytes');
    }
    const M = this._M;
    const userPtr = this._resolveUser('rotateKey', userId);
    const oldPtr = writeString(M, oldKeyId);
    const newPtr = writeString(M, newKeyId);
    const labelPtr = opts.label ? writeString(M, opts.label) : 0;
    const pkCap = pkHex.length / 2;
    const pkPtr = M._malloc(pkCap);
    hexDecode(M, pkHex, pkPtr, pkCap);
    const rc = M._crabs_wasm_user_key_rotate(userPtr, oldPtr, newPtr,
        schemeNumber, pkPtr, pkCap, labelPtr);
    freeAll(M, oldPtr, newPtr, labelPtr);
    M._free(pkPtr);
    wrapRc(rc, 'rotateKey');
  }

  // The keyring READBACK: index-walk the user's linked key list and mirror
  // the fields the C lifecycle tests assert. Indices are stable across the
  // scan (the JS loop performs no keyring writes between reads).
  listKeys(userId) {
    const M = this._M;
    const userPtr = this._resolveUser('listKeys', userId);
    // user_key_t key_status_e order: ACTIVE/SUSPENDED/REVOKED/EXPIRED = 0/1/2/3
    // (attribute_machine.h:48-53); user_key_status_name's words mirrored.
    const STATUS_NAMES = ['active', 'suspended', 'revoked', 'expired'];
    const count = M._crabs_wasm_user_key_count(userPtr) | 0;
    const keys = [];
    for (let index = 0; index < count; index++) {
      const pkPtr = M._malloc(512);
      const pkLen = M._crabs_wasm_user_key_public_key(userPtr, index, pkPtr, 512);
      const publicKeyHex = pkLen > 0
        ? hexEncode(M.HEAPU8.subarray(pkPtr, pkPtr + pkLen), pkLen) : '';
      M._free(pkPtr);
      keys.push({
        keyId: readString(M, M._crabs_wasm_user_key_id(userPtr, index)),
        schemeId: M._crabs_wasm_user_key_scheme(userPtr, index) | 0,
        status: STATUS_NAMES[M._crabs_wasm_user_key_status(userPtr, index)] || 'unknown',
        label: readString(M, M._crabs_wasm_user_key_label(userPtr, index)),
        predecessorKeyId: readString(M, M._crabs_wasm_user_key_predecessor(userPtr, index)),
        publicKeyHex,
      });
    }
    return keys;
  }

  getDefaultKey(userId) {
    const M = this._M;
    const userPtr = this._resolveUser('getDefaultKey', userId);
    return readString(M, M._crabs_wasm_user_default_key_id(userPtr)) || '';
  }

  // --- Admin demotion + user suspension (parity-fill P3) ---
  //
  // All three drive the C machine calls (attribute_machine_revoke_role /
  // _suspend_user / _activate_user — attribute_machine.h:145-171), each
  // ADMIN-GATED in C: the signer must be an ACTIVE user holding
  // role:admin, or the call refuses (unauthorized for non-admins,
  // user_suspended for suspended signers — the gate whitelist). The signer
  // defaults to the node's bootstrap admin id, the same convention the
  // sibling revokeUser wrapper established.

  _adminSigner(signerId, ctx) {
    if (signerId === undefined || signerId === null) return this.adminId || 'admin';
    if (typeof signerId !== 'string' || signerId.length === 0) {
      throw new TypeError(`${ctx}: signerId must be a non-empty string when given`);
    }
    return signerId;
  }

  revokeRole(targetUser, role, signerId) {
    const M = this._M;
    const sPtr = writeString(M, this._adminSigner(signerId, 'revokeRole'));
    const tPtr = writeString(M, targetUser);
    const rPtr = writeString(M, role);
    const rc = M._attribute_machine_revoke_role(this._am, tPtr, rPtr, sPtr);
    freeAll(M, tPtr, rPtr, sPtr);
    wrapRc(rc, 'revokeRole');
  }

  suspendUser(userId, signerId) {
    const M = this._M;
    const sPtr = writeString(M, this._adminSigner(signerId, 'suspendUser'));
    const uidPtr = writeString(M, userId);
    const rc = M._attribute_machine_suspend_user(this._am, uidPtr, sPtr);
    freeAll(M, uidPtr, sPtr);
    wrapRc(rc, 'suspendUser');
  }

  // Reactivates a SUSPENDED user (the key-compromise recovery path). An
  // ACTIVE or REVOKED target is not a recovery state — C refuses with
  // invalid_param; revocation is terminal.
  activateUser(userId, signerId) {
    const M = this._M;
    const sPtr = writeString(M, this._adminSigner(signerId, 'activateUser'));
    const uidPtr = writeString(M, userId);
    const rc = M._attribute_machine_activate_user(this._am, uidPtr, sPtr);
    freeAll(M, uidPtr, sPtr);
    wrapRc(rc, 'activateUser');
  }

  // Non-replicated attribute-writing primitives (parity-fill P10 — the
  // node binding's surface, mirrored). Both drive the C machines directly —
  // no op, no signature, no policy — so the privileged-name blocklist
  // (audit C-5), the safe-charset gates (R4-5), the suspended-user gates
  // (R4-2) and the verified-attribute overwrite rule are the C machine's
  // own and surface typed as-is:

  // Self-assert a non-privileged attribute: `signerId`'s record gains
  // `attribute:value` with an EMPTY verified_by. Typed refusals:
  // unauthorized (a name in the privileged blocklist, or overwriting an
  // already-VERIFIED attribute — §8.4.3), invalid_param (an unsafe-charset
  // name, a comma/space value, or empty arguments), user_not_found /
  // user_suspended for the signer's own record.
  selfAssert(attribute, value, signerId) {
    const M = this._M;
    const attrPtr = writeString(M, attribute);
    const valPtr = writeString(M, value);
    const signerPtr = writeString(M, signerId);
    const rc = M._crabs_wasm_self_assert(this._am, attrPtr, valPtr, signerPtr);
    freeAll(M, attrPtr, valPtr, signerPtr);
    wrapRc(rc, 'selfAssert');
  }

  // Verify another user's attribute (§8.4.4): `attribute:value` is recorded
  // (or the existing attribute's value updated) with verified_by =
  // `signerId`. Admin-gated: the verifying signer must hold 'role:admin'.
  // Typed refusals: unauthorized (a non-admin verifier), user_not_found
  // (unknown target), user_suspended (a suspended or revoked target),
  // invalid_param (the same argument gates selfAssert applies).
  verifyIdentity(targetUser, attribute, value, signerId) {
    const M = this._M;
    const targetPtr = writeString(M, targetUser);
    const attrPtr = writeString(M, attribute);
    const valPtr = writeString(M, value);
    const signerPtr = writeString(M, signerId);
    const rc = M._crabs_wasm_verify_identity(this._am, targetPtr, attrPtr,
                                             valPtr, signerPtr);
    freeAll(M, targetPtr, attrPtr, valPtr, signerPtr);
    wrapRc(rc, 'verifyIdentity');
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
        // Mirror the node mapper (crabs_node.cc:1199-1201): each stored
        // attribute records the verifier that stamped it.
        verifiedBy: readString(M, M._crabs_wasm_user_attr_verified_by(userPtr, i)),
        temporary: false,
      });
    }
    // Temporary attributes: full-list walk (count + by-index), mirroring the
    // node mapper (crabs_node.cc's GetUser) — a user can hold several tokens
    // (one per grant), not just the most recent one.
    const tempAttrCount = M._crabs_wasm_user_temp_attr_count(userPtr) | 0;
    for (let tempIndex = 0; tempIndex < tempAttrCount; tempIndex++) {
      attrs.push({
        // The temp attr name IS the full 'name:value' token the C policy
        // evaluator matches (src/Crypto/crypto.c:1126-1158) — return it
        // plain, exactly like the node mapper, rather than concatenating the
        // stored value onto it a second time.
        value: readString(
          M, M._crabs_wasm_user_temp_attr_name_at(userPtr, tempIndex)),
        // The C temp list carries no origin marker, so the shared
        // 'trigger' label covers both issuance paths (trigger effect and
        // issueTemporary) — same word the node mapper stamps.
        verifiedBy: 'trigger',
        temporary: true,
        // Matches the node mapper's expiresAt field; 0 means no expiry.
        expiresAt: Number(
          M._crabs_wasm_user_temp_attr_expires_at_at(userPtr, tempIndex)),
      });
    }

    // The 33-byte legacy ECDSA public key is copied into a scratch buffer
    // and hex-encoded with the same idiom as the KeyPair surfaces.
    const pkPtr = M._malloc(33);
    const pkLen = M._crabs_wasm_user_public_key(userPtr, pkPtr);
    const publicKeyHex = pkLen === 33
      ? hexEncode(M.HEAPU8.subarray(pkPtr, pkPtr + 33), 33) : '';
    M._free(pkPtr);

    // user_status_e order: USER_ACTIVE/SUSPENDED/REVOKED = 0/1/2
    // (attribute_machine.h:17-21), matching the node mapper's switch.
    const STATUS_NAMES = ['active', 'suspended', 'revoked'];
    const statusNumber = M._crabs_wasm_user_status(userPtr);

    return {
      userId: readString(M, M._crabs_wasm_user_id(userPtr)),
      publicKeyHex,
      keyVersion: Number(M._crabs_wasm_user_key_version(userPtr)),
      status: STATUS_NAMES[statusNumber] || 'unknown',
      attributes: attrs,
    };
  }

  // Write-domains v1: item creation with an explicit write-domain
  // declaration. v1 supports 'counter'/'register' (or the DATA_TYPE numbers)
  // — the SOVEREIGN-legal types; other shapes keep their dedicated add*
  // methods. opts: { domain: 'free'|'sovereign'|'group' (default 'free'),
  // writer: string (required for 'sovereign'), orderingModule: number
  // ('group' only; only 0 is legal in v1 — no ordering modules exist) }.
  defineItem(name, dataType, crdtType, opts = {}) {
    const M = this._M;
    const DOMAIN_NUMBERS = { free: 0, sovereign: 1, group: 2 };
    const DATA_TYPE_WORDS = { counter: DATA_TYPE.COUNTER, register: DATA_TYPE.REGISTER };
    const CRDT_TYPE_WORDS = { g_counter: CRDT_TYPE.G_COUNTER, lww_reg: CRDT_TYPE.LWW_REG };
    const dataTypeNum = typeof dataType === 'string' ? DATA_TYPE_WORDS[dataType] : dataType;
    const crdtTypeNum = typeof crdtType === 'string' ? CRDT_TYPE_WORDS[crdtType] : crdtType;
    if (dataTypeNum === undefined || crdtTypeNum === undefined) {
      throw new Error('defineItem: unknown dataType/crdtType word (v1 supports counter/register)');
    }
    const domainNum = DOMAIN_NUMBERS[opts.domain || 'free'];
    if (domainNum === undefined) {
      throw new Error("defineItem: domain must be 'free' | 'sovereign' | 'group'");
    }
    // The C export narrows the module to uint8 — refuse out-of-range or
    // non-integer values here instead of letting 256 truncate to "unset".
    let orderingModule = 0;
    if (opts.orderingModule !== undefined) {
      if (!Number.isInteger(opts.orderingModule) ||
          opts.orderingModule < 0 || opts.orderingModule > 255) {
        throw new RangeError(
          'defineItem: orderingModule must be an integer 0..255');
      }
      orderingModule = opts.orderingModule;
    }
    const namePtr = writeString(M, name);
    const writerPtr = opts.writer ? writeString(M, opts.writer) : 0;
    const rc = M._crabs_wasm_define_item(
        this._am, namePtr, dataTypeNum, crdtTypeNum, domainNum, writerPtr,
        orderingModule);
    freeAll(M, namePtr, writerPtr);
    wrapRc(rc, 'defineItem');
  }

  // Write-domains v1: the live chain head (seq + full 32-byte digest hex)
  // of item `name` — exactly what a SOVEREIGN writer's next op must claim
  // in its signed prefix (DOMAIN_CHECK compares both). The devtools
  // snapshot's item_digest_head is only the first 8 bytes; signing needs
  // the full digest. Throws resource_not_found for an unknown item.
  itemChainHead(name) {
    const M = this._M;
    const namePtr = writeString(M, name);
    const seq = M._crabs_wasm_item_chain_seq(this._am, namePtr);
    if (seq < 0n) {
      freeAll(M, namePtr);
      // Match the wrapRc message shape: 'itemChainHead: resource_not_found'.
      throw crabsError(0x3002, 'itemChainHead');
    }
    const digestPtr = M._malloc(32);
    const rc = M._crabs_wasm_item_chain_digest(this._am, namePtr, digestPtr);
    const digestHex = rc === 0
      ? hexEncode(M.HEAPU8.subarray(digestPtr, digestPtr + 32), 32)
      : null;
    freeAll(M, namePtr, digestPtr);
    wrapRc(rc, 'itemChainHead');
    // i64 arrives as a BigInt; seq fits comfortably in a JS number for any
    // realistic chain (and matches setSovereignPrefix's number arm).
    return { seq: Number(seq), digestHex };
  }

  // Write-domains v1: file a __report_equivocation__ op against the
  // SOVEREIGN item `itemName`, carrying two serialized writer ops as the
  // evidence pair. The C helper builds the payload (the writer field is
  // read from the ITEM, so a forged writer string can never parse); the op
  // is then signed by this node's admin with the node key and executed —
  // the same compose/sign/execute idiom as createTrigger.
  reportEquivocation(itemName, opABytes, opBBytes) {
    const M = this._M;
    const typePtr = writeString(M, '__report_equivocation__');
    const opPtr = M._operation_create(typePtr);
    if (typePtr) M._free(typePtr);
    if (!opPtr) throw new Error('reportEquivocation: operation_create failed');
    const namePtr = writeString(M, itemName);
    const { ptr: aPtr, len: aLen } = writeBytes(M, opABytes);
    const { ptr: bPtr, len: bLen } = writeBytes(M, opBBytes);
    const rcFill = M._crabs_wasm_report_equivocation(
        this._am, opPtr, namePtr, aPtr, aLen, bPtr, bLen);
    freeAll(M, namePtr, aPtr, bPtr);
    if (rcFill !== 0) {
      M._operation_destroy(opPtr);
      throw crabsError(rcFill, 'reportEquivocation');
    }
    const signerPtr = writeString(M, this.adminId || 'admin');
    const nodePtr = writeString(M, this.adminId || 'admin');
    M._crabs_wasm_op_set_signer(opPtr, signerPtr);
    M._crabs_wasm_op_set_node(opPtr, nodePtr);
    freeAll(M, signerPtr, nodePtr);
    const rcSign = M._crabs_wasm_sign_with_node_key(this._am, opPtr);
    if (rcSign !== 0) {
      M._operation_destroy(opPtr);
      throw crabsError(rcSign, 'reportEquivocation sign');
    }
    const rcExec = M._crabs_wasm_execute(this._am, opPtr);
    M._operation_destroy(opPtr);
    wrapRc(rcExec, 'reportEquivocation execute');
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

  // ============================================================
  // Resource items + lock protocol (recipe 9)
  // ============================================================

  // Mint a lock-capable RESOURCE item ("PN-Counter + lock") whose value is
  // a raw int64 balance (the library contract — the lock snapshot and dest-
  // roy take the raw path for RESOURCE). Node.addResource on the node
  // binding gained the same shape; `initial` seeds the balance so demo/
  // test drivers can mint a pot without a client-side op.
  addResource(name, initial = 0) {
    const M = this._M;
    if (initial !== undefined && !Number.isInteger(initial)) {
      throw new Error('addResource: initial must be an integer (int64 balance)');
    }
    const nPtr = writeString(M, name);
    const rc = M._crabs_wasm_add_resource(this._am, nPtr, BigInt(initial));
    if (nPtr) M._free(nPtr);
    wrapRc(rc, 'addResource');
  }

  // Raw int64 readback of the RESOURCE balance. Throws resource_not_found
  // for an unknown name, type_mismatch for a non-RESOURCE item. Balances
  // beyond ±2^53 lose precision through Number (the driver-owned values the
  // demos use stay far below) — same convention as the schedule ids.
  getResource(name) {
    const M = this._M;
    const nPtr = writeString(M, name);
    const outPtr = M._malloc(8);
    const rc = M._crabs_wasm_get_resource(this._am, nPtr, outPtr);
    let balance = null;
    if (rc === 0) {
      balance = new DataView(M.HEAPU8.buffer, M.HEAPU8.byteOffset + outPtr, 8)
        .getBigInt64(0, true);
    }
    freeAll(M, nPtr, outPtr);
    wrapRc(rc, 'getResource');
    return Number(balance);
  }

  // LIVE lock state of a RESOURCE item — how the driver receives the 32-byte
  // bearer token state_machine_op_lock minted (the executor consumes the
  // lock response internally; the item's lock_state is the token's only
  // observable home). Packed read buffer (fixed offsets, documented on the
  // C export): u32 protocol_state | u32 token_valid | u64 extensions |
  // u64 expiry | char[64] lock_owner | u8[32] lock_token.
  getLockState(name) {
    const M = this._M;
    const nPtr = writeString(M, name);
    const bufPtr = M._malloc(120);
    const rc = M._crabs_wasm_lock_state(this._am, nPtr, bufPtr);
    freeAll(M, nPtr);
    wrapRc(rc, 'getLockState');

    const view = new DataView(M.HEAPU8.buffer, M.HEAPU8.byteOffset + bufPtr, 120);
    const protocolState = PROTOCOL_STATE_NAMES[view.getUint32(0, true)];
    const tokenValid = view.getUint32(4, true) === 1;
    const extensions = Number(view.getBigUint64(8, true));
    const expiry = Number(view.getBigUint64(16, true));
    const ownerBuf = M.HEAPU8.subarray(bufPtr + 24, bufPtr + 88);
    const ownerEnd = ownerBuf.indexOf(0);
    const lockOwner = M.UTF8ToString(bufPtr + 24,
      (ownerEnd === -1 ? 64 : ownerEnd));
    const lockTokenHex = tokenValid
      ? hexEncode(M.HEAPU8.subarray(bufPtr + 88, bufPtr + 120), 32) : '';
    // bufPtr's frame carries the live 32-byte bearer lock token — wipe before
    // it returns to the free list.
    wipeFree(M, bufPtr, 120);
    return {
      protocolState: protocolState || 'idle',
      lockOwner,
      lockTokenHex,
      lockExpiry: expiry,
      lockExtensions: extensions,
    };
  }

  // Attach a replay-protection manager to this machine's state
  // (src/TxManager/tx_manager.h): 'memory' records committed op uuids and
  // the executor's step 3b refuses duplicate submissions with
  // already_executed; 'none' is the accept-everything hook
  // (crabs_tx_manager_none). With NO manager attached the executor's
  // ordering-monotonicity backstop still rejects a replayed op. Runtime
  // only — never serialized; attach again after a state round trip.
  attachTxManager(kind) {
    const M = this._M;
    const kinds = { none: 0, memory: 1 };
    if (kinds[kind] === undefined) {
      throw new Error("attachTxManager: kind must be 'memory' or 'none'");
    }
    const rc = M._crabs_wasm_attach_tx_manager(this._am, kinds[kind]);
    wrapRc(rc, 'attachTxManager');
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
    const intValue = validateRegisterInt(value, 'setRegister');
    const M = this._M;
    const nPtr = writeString(M, name);
    const idPtr = writeString(M, nodeId);
    const rc = M._crabs_wasm_set_register(this._am, nPtr, intValue, idPtr);
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

  // Raw bytes of an LWW register (byte-exact inverse of setRegisterBytes).
  // Throws resource_not_found for an unknown name, type_mismatch for a
  // non-register item. An empty register returns an empty Uint8Array.
  getRegisterBytes(name) {
    return this._callGetRegisterBytesFromAm(this._M, this._am, name);
  }

  setContains(name, element) {
    const M = this._M;
    const nPtr = writeString(M, name);
    const ePtr = writeString(M, element);
    const out = M._crabs_wasm_set_contains(this._am, nPtr, ePtr);
    freeAll(M, nPtr, ePtr);
    return out;
  }

  // Distinct visible element count of an OR-set/one-shot set — alive after
  // tombstones, deduped at the element level (the same element may be carried
  // by multiple live tags post-Task-1; it counts once here). Pair with
  // getSetElements for pagination math. Returns 0 for unknown/non-set items.
  getSetSize(name) {
    const M = this._M;
    const nPtr = writeString(M, name);
    const out = M._crabs_wasm_handler_set_size(this._am, nPtr);
    if (nPtr) M._free(nPtr);
    return out;
  }

  // Bounded enumerator over the DISTINCT LIVE elements of `name`. The page
  // is sorted ascending by byte-wise strcmp so pagination is stable across
  // replicas (OR-set insertion order is NOT cross-replica deterministic).
  // `limit` defaults to 256 and is HARD-capped at 256 — anything larger
  // throws before the wasm round-trip. Mirrors the C-side cap in
  // wasm_helpers.c (CRABS_WASM_HANDLER_SET_PAGE_CAP).
  getSetElements(name, options = {}) {
    const offset = options.offset === undefined ? 0 : options.offset >>> 0;
    const limit = options.limit === undefined ? HANDLER_SET_PAGE_CAP : options.limit;
    if (!Number.isInteger(limit) || limit < 1 || limit > HANDLER_SET_PAGE_CAP) {
      throw new Error(
        `getSetElements: limit must be an integer in [1, ${HANDLER_SET_PAGE_CAP}]`
      );
    }
    return this._callGetSetElementsFromAm(this._M, this._am, name, offset, limit);
  }

  // LIVE tags of a single element of an OR-set (post-Task-1 a single element
  // may be carried by several tags). Sorted ascending for cross-replica
  // stability. Throws type_mismatch for non-OR-set items, resource_not_found
  // for an unknown name; an element with no live tags returns [].
  getSetTags(name, element) {
    return this._callGetSetTagsFromAm(this._M, this._am, name, element);
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

  // ============================================================
  // Ordered set (OT_ORDERED_SET, v1.5 §5) — recipe 8
  // ============================================================

  addOrderedSet(name) {
    this._callAdd(this._M._crabs_wasm_add_ordered_set, name, 'addOrderedSet');
  }

  // Visible elements in materialized order (tombstones skipped), each
  // element's payload value decoded as UTF-8. Throws resource_not_found for
  // an unknown / non-ordered-set name.
  getOrderedSet(name) {
    const M = this._M;
    const namePtr = writeString(M, name);
    const count = M._crabs_wasm_ot_ordered_count(this._am, namePtr);
    if (count < 0n) {
      M._free(namePtr);
      throw crabsError(0x3002, 'getOrderedSet');
    }
    const bufPtr = M._malloc(OT_ELEMENT_MAX_BYTES);
    const elements = new Array(Number(count));
    try {
      for (let position = 0; position < Number(count); position++) {
        const elementLength = M._crabs_wasm_ot_ordered_element(
          this._am, namePtr, position, bufPtr, OT_ELEMENT_MAX_BYTES);
        if (elementLength < 0) throw crabsError(0x3002, 'getOrderedSet');
        elements[position] =
          OT_TEXT_DECODER.decode(M.HEAPU8.subarray(bufPtr, bufPtr + elementLength));
      }
    } finally {
      freeAll(M, namePtr, bufPtr);
    }
    return { elements };
  }

  // ---- Ordered-set mutation sugar ------------------------------------------
  //
  // Every call routes ONE ordered-set op through the machine as a
  // __execute_ot__ op: composed, signed with the node key under the
  // bootstrap admin (the createTrigger idiom — the caller installs the type's
  // policy first: setPolicy('__execute_ot__', 'role:admin')) and executed.
  // The C exporter validates positions against the live visible count before
  // anything is signed,
  //
  //   orderedInsert(name, element, position, options)
  //   orderedDelete(name, position, options)
  //   orderedMove(name, fromPosition, toPosition, options)
  //   orderedSwap(name, positionA, positionB, options)
  //
  // options (required):
  //   id:  { node, seq, ts? }  — the op's OT identity (deduplicated on
  //        replay by (node, seq): a replay with the SAME id and args is a
  //        silent no-op).
  //   deps: [{ node, seq, ts? }, ...] — causal context the ISSUER had at
  //        issue time (max 16). Cross-replica replays need it: without deps
  //        the transform treats the replica's prior ops as concurrent and
  //        shifts positions wrongly.

  orderedInsert(name, element, position, options) {
    this._orderedSetApply(name, OT_OP_INSERT,
      { first: validateOrderedPosition(position, 'orderedInsert', 0) },
      element, options, 'orderedInsert');
  }

  orderedDelete(name, position, options) {
    this._orderedSetApply(name, OT_OP_DELETE,
      { first: validateOrderedPosition(position, 'orderedDelete', 0) },
      null, options, 'orderedDelete');
  }

  orderedMove(name, fromPosition, toPosition, options) {
    this._orderedSetApply(name, OT_OP_MOVE, {
      first: validateOrderedPosition(fromPosition, 'orderedMove.fromPosition', 0),
      second: validateOrderedPosition(toPosition, 'orderedMove.toPosition', 0),
    }, null, options, 'orderedMove');
  }

  orderedSwap(name, positionA, positionB, options) {
    this._orderedSetApply(name, OT_OP_SWAP, {
      first: validateOrderedPosition(positionA, 'orderedSwap.positionA', 0),
      second: validateOrderedPosition(positionB, 'orderedSwap.positionB', 0),
    }, null, options, 'orderedSwap');
  }

  _orderedSetApply(name, opKind, positions, element, options, ctx) {
    const M = this._M;
    if (!options || typeof options.id !== 'object' || options.id === null) {
      throw new Error(`${ctx}: id is required — { node, seq, ts? } fixes the op's OT identity`);
    }
    const id = options.id;
    if (typeof id.node !== 'string' || id.node.length === 0) {
      throw new Error(`${ctx}: id.node is required (string, the issuing replica's id)`);
    }
    if (!Number.isInteger(id.seq) || id.seq < 0) {
      throw new Error(`${ctx}: id.seq is required (integer >= 0, unique per ${id.node})`);
    }
    if (id.ts !== undefined && (!Number.isInteger(id.ts) || id.ts < 0)) {
      throw new Error(`${ctx}: id.ts must be a non-negative integer ms stamp`);
    }
    const deps = options.deps === undefined ? [] : options.deps;
    if (!Array.isArray(deps) || deps.length > OT_MAX_DEPS) {
      throw new Error(`${ctx}: deps must be an array of at most ${OT_MAX_DEPS} { node, seq, ts? } ids`);
    }
    if (typeof element === 'string') {
      validateOrderedElement(element, ctx);
    }

    const idNodePtr = writeString(M, id.node);
    const elementBytes = element === null || element === undefined
      ? { ptr: 0, len: 0 }
      : writeBytes(M, OT_TEXT_ENCODER.encode(element));
    const depsPtr = writeBytes(M, packOrderedDeps(deps, ctx));
    const namePtr = writeString(M, name);
    const rc = M._crabs_wasm_ot_apply(
      this._am, namePtr, opKind,
      BigInt(positions.first),
      BigInt(positions.second === undefined ? 0 : positions.second),
      elementBytes.ptr, elementBytes.len,
      idNodePtr, BigInt(id.seq), BigInt(id.ts === undefined ? 0 : id.ts),
      depsPtr.ptr, deps.length);
    freeAll(M, namePtr, idNodePtr, elementBytes.ptr, depsPtr.ptr);
    wrapRc(rc, ctx);
  }

  // ============================================================
  // OT document (OT_DOCUMENT, v1.5 §6) + OT tree (v1.5 §7) — parity-fill P6
  //
  // PRESENT but EXPLICITLY UNBLESSED: the document/tree paths are
  // implemented (the __execute_ot__ executor routes both item types) but
  // never benchmarked — the O(N) span/ops cost of document-style
  // concurrency is a design-table claim, not a measured property, and the
  // priority tie-break's generator (crabs_ot_data_item_next_priority) has
  // no production caller (binding-composed ops carry priority 0; the
  // transform's tie-break falls back to the (node_id, seq) total order).
  // NEITHER type has a merge function: mergeState of one of their
  // snapshots is HELD (__merge_held__, CRABS_ERR_TYPE_MISMATCH 0x3004) and
  // the item does not land. Do not build rich text on this until a
  // benchmark exists.
  //
  // Mirrors the ordered-set sugar: addOTDocument, the ot* op sugars, and
  // otDocumentApply/otTreeApply take a required options bag
  // { id: { node, seq, ts? }, deps?: [...] } with the same replay
  // (deps-declared ops replay; same-id replays are silent no-ops) and
  // transform semantics. Positions and the per-op shape are validated in
  // C against the live item BEFORE anything is signed.
  // ============================================================

  addOTDocument(name) {
    this._callAdd(this._M._crabs_wasm_add_ot_document, name, 'addOTDocument');
  }

  // Readback of one OT document: `text` — the visible characters in
  // document order concatenated; `spans` — one record per VISIBLE span
  // (skipping tombstones), each { text, styles: [{ name, value }, ...] };
  // `charCount` — the live visible character count. Throws
  // resource_not_found for an unknown or non-document name.
  getOTDocument(name) {
    const M = this._M;
    const namePtr = writeString(M, name);
    try {
      const count = Number(M._crabs_wasm_ot_document_span_count(this._am, namePtr));
      if (count < 0) throw crabsError(0x3002, 'getOTDocument');
      const spans = new Array(count);
      let text = '';
      let charCount = 0;
      for (let spanIndex = 0; spanIndex < count; spanIndex++) {
        // Probe first (out = 0): the export returns the packed size to
        // allocate, refusing nothing — then fetch into the sized buffer.
        const size = Number(M._crabs_wasm_ot_document_span(
          this._am, namePtr, spanIndex, 0, 0));
        if (size < 0) throw crabsError(0x3002, 'getOTDocument');
        const bufPtr = M._malloc(size);
        try {
          const span = _otDocumentSpanParse(M, bufPtr, Number(
            M._crabs_wasm_ot_document_span(this._am, namePtr, spanIndex,
                                           bufPtr, size)));
          spans[spanIndex] = span;
          text += span.text;
          charCount += span.textLen;
        } finally {
          M._free(bufPtr);
        }
      }
      return { text, spans, charCount };
    } finally {
      M._free(namePtr);
    }
  }

  addOTTree(name) {
    this._callAdd(this._M._crabs_wasm_add_ot_tree, name, 'addOTTree');
  }

  // Readback of one OT tree: `nodes` — every VISIBLE node in DFS order
  // (roots first, then each node's children left to right; a tombstoned
  // subtree is skipped wholesale), each { id, parentId, value, childIds }.
  // An empty parentId marks a root. The array order IS the sibling order,
  // so a consumer can rebuild the hierarchy from parentId alone; childIds
  // is pre-resolved here for convenience. Throws resource_not_found for
  // an unknown or non-tree name.
  getOTTree(name) {
    const M = this._M;
    const namePtr = writeString(M, name);
    try {
      const count = Number(M._crabs_wasm_ot_tree_count(this._am, namePtr));
      if (count < 0) throw crabsError(0x3002, 'getOTTree');
      const records = new Array(count);
      for (let nodeIndex = 0; nodeIndex < count; nodeIndex++) {
        const size = Number(M._crabs_wasm_ot_tree_node(
          this._am, namePtr, nodeIndex, 0, 0));
        if (size < 0) throw crabsError(0x3002, 'getOTTree');
        const bufPtr = M._malloc(size);
        try {
          records[nodeIndex] = _otTreeNodeParse(M, bufPtr, Number(
            M._crabs_wasm_ot_tree_node(this._am, namePtr, nodeIndex,
                                       bufPtr, size)));
        } finally {
          M._free(bufPtr);
        }
      }
      // The DFS record order encodes sibling order; group the children under
      // their parent (records appear after their parent, parents before).
      const byId = new Map(records.map((entry) => [entry.id, entry]));
      const rootIds = [];
      const childIdsByParent = new Map();
      for (const entry of records) {
        if (entry.parentId === '') {
          rootIds.push(entry.id);
          continue;
        }
        const parent = byId.get(entry.parentId);
        if (!parent) { rootIds.push(entry.id); continue; }
        let siblings = childIdsByParent.get(entry.parentId);
        if (!siblings) {
          siblings = [];
          childIdsByParent.set(entry.parentId, siblings);
        }
        siblings.push(entry.id);
      }
      return { nodes: records.map((entry) => ({
        ...entry,
        childIds: childIdsByParent.get(entry.id) || [],
      })), rootIds };
    } finally {
      M._free(namePtr);
    }
  }

  // ---- OT document mutation sugar (one __execute_ot__ op per call) ------
  //
  //   otInsertText(name, position, text, options)
  //   otDeleteRange(name, position, length, options)
  //   otApplyStyle(name, position, length, style, options)
  //   otMergeSpans(name, spanPosA, spanPosB, options)   — SPAN indexes
  //   otSplitSpan(name, position, options)              — mid-span offset
  //   otDocumentApply(name, op) — the same ops behind op.kind words

  otInsertText(name, position, text, options) {
    this._otDocumentApply(name, OT_OP_INSERT_TEXT, {
      position: validateOrderedPosition(position, 'otInsertText.position', 0),
    }, text, null, null, options, 'otInsertText');
  }

  otDeleteRange(name, position, length, options) {
    this._otDocumentApply(name, OT_OP_DELETE_RANGE, {
      position: validateOrderedPosition(position, 'otDeleteRange.position', 0),
      second: validateOrderedPosition(length, 'otDeleteRange.length', 1),
    }, null, null, null, options, 'otDeleteRange');
  }

  otApplyStyle(name, position, length, style, options) {
    if (!style || typeof style !== 'object' ||
        typeof style.name !== 'string' || style.name.length === 0) {
      throw new TypeError(
        "otApplyStyle: style is required — { name: string, value?: string }");
    }
    if (typeof style.value !== 'undefined' && typeof style.value !== 'string') {
      throw new TypeError('otApplyStyle: style.value must be a string');
    }
    this._otDocumentApply(name, OT_OP_APPLY_STYLE, {
      position: validateOrderedPosition(position, 'otApplyStyle.position', 0),
      second: validateOrderedPosition(length, 'otApplyStyle.length', 1),
    }, null, style.name, style.value === undefined ? '' : style.value,
    options, 'otApplyStyle');
  }

  otMergeSpans(name, spanPositionA, spanPositionB, options) {
    this._otDocumentApply(name, OT_OP_MERGE_SPANS, {
      position: validateOrderedPosition(spanPositionA, 'otMergeSpans.spanPositionA', 0),
      second: validateOrderedPosition(spanPositionB, 'otMergeSpans.spanPositionB', 0),
    }, null, null, null, options, 'otMergeSpans');
  }

  otSplitSpan(name, position, options) {
    this._otDocumentApply(name, OT_OP_SPLIT_SPAN, {
      position: validateOrderedPosition(position, 'otSplitSpan.position', 0),
    }, null, null, null, options, 'otSplitSpan');
  }

  // Generic document-op route: op = { kind, position, length?, text?,
  // style?, id, deps? } — kind is one of 'insertText' | 'deleteRange' |
  // 'applyStyle' | 'mergeSpans' | 'splitSpan'.
  otDocumentApply(name, op) {
    if (!op || typeof op !== 'object') {
      throw new TypeError('otDocumentApply: op object is required');
    }
    const kinds = {
      insertText: OT_OP_INSERT_TEXT, deleteRange: OT_OP_DELETE_RANGE,
      applyStyle: OT_OP_APPLY_STYLE, mergeSpans: OT_OP_MERGE_SPANS,
      splitSpan: OT_OP_SPLIT_SPAN,
    };
    const opKind = kinds[op.kind];
    if (!opKind) throw new TypeError('otDocumentApply: unknown op.kind');
    if (opKind === OT_OP_INSERT_TEXT) {
      this._otDocumentApply(name, opKind, {
        position: validateOrderedPosition(op.position, 'otDocumentApply.position', 0),
      }, op.text, null, null, op, 'otDocumentApply');
    } else if (opKind === OT_OP_MERGE_SPANS) {
      this._otDocumentApply(name, opKind, {
        position: validateOrderedPosition(op.position, 'otDocumentApply.position', 0),
        second: validateOrderedPosition(op.second, 'otDocumentApply.second', 0),
      }, null, null, null, op, 'otDocumentApply');
    } else if (opKind === OT_OP_SPLIT_SPAN) {
      this._otDocumentApply(name, opKind, {
        position: validateOrderedPosition(op.position, 'otDocumentApply.position', 0),
      }, null, null, null, op, 'otDocumentApply');
    } else {
      this._otDocumentApply(name, opKind, {
        position: validateOrderedPosition(op.position, 'otDocumentApply.position', 0),
        second: validateOrderedPosition(op.length, 'otDocumentApply.length', 1),
      }, null,
      op.style && op.style.name ? String(op.style.name) : null,
      op.style && op.style.value !== undefined ? String(op.style.value) : null,
      op, 'otDocumentApply');
    }
  }

  // ---- OT tree mutation sugar --------------------------------------------
  //
  //   otInsertNode(name, parentId, position, nodeId, value, options)
  //   otDeleteNode(name, nodeId, options)
  //   otReparent(name, nodeId, newParentId, position, options)
  //   otReorder(name, nodeId, position, options)
  //   otTreeApply(name, op) — the same ops behind op.kind words

  otInsertNode(name, parentId, position, nodeId, value, options) {
    if (value !== null && value !== undefined &&
        typeof value !== 'string') {
      throw new TypeError('otInsertNode: value must be a string or null');
    }
    this._otTreeApply(name, OT_TREE_OP_INSERT_NODE, {
      position: validateOrderedPosition(position, 'otInsertNode.position', 0),
    }, nodeId, parentId, value, options, 'otInsertNode');
  }

  otDeleteNode(name, nodeId, options) {
    this._otTreeApply(name, OT_TREE_OP_DELETE_NODE, {
      position: 0,
    }, nodeId, '', null, options, 'otDeleteNode');
  }

  otReparent(name, nodeId, newParentId, position, options) {
    this._otTreeApply(name, OT_TREE_OP_REPARENT, {
      position: validateOrderedPosition(position, 'otReparent.position', 0),
    }, nodeId, newParentId, null, options, 'otReparent');
  }

  otReorder(name, nodeId, position, options) {
    this._otTreeApply(name, OT_TREE_OP_REORDER, {
      position: validateOrderedPosition(position, 'otReorder.position', 0),
    }, nodeId, '', null, options, 'otReorder');
  }

  // Generic tree-op route: op = { kind, nodeId, parentId?, newParentId?,
  // position, value?, id, deps? } — kind is one of 'insertNode' |
  // 'deleteNode' | 'reparent' | 'reorder'.
  otTreeApply(name, op) {
    if (!op || typeof op !== 'object') {
      throw new TypeError('otTreeApply: op object is required');
    }
    if (op.kind === 'insertNode') {
      this.otInsertNode(name, op.parentId || '', op.position, op.nodeId,
        op.value, op);
    } else if (op.kind === 'deleteNode') {
      this.otDeleteNode(name, op.nodeId, op);
    } else if (op.kind === 'reparent') {
      this.otReparent(name, op.nodeId, op.newParentId || '', op.position, op);
    } else if (op.kind === 'reorder') {
      this.otReorder(name, op.nodeId, op.position, op);
    } else {
      throw new TypeError('otTreeApply: unknown op.kind');
    }
  }

  _otDocumentApply(name, opKind, positions, text, styleName, styleValue,
                   options, ctx) {
    const M = this._M;
    const { id, deps } = _otOpIdentity(options, ctx);
    const textBytes = text === null || text === undefined
      ? { ptr: 0, len: 0 }
      : writeBytes(M, OT_TEXT_ENCODER.encode(text));
    const depsPtr = writeBytes(M, packOrderedDeps(deps, ctx));
    const namePtr = writeString(M, name);
    const idNodePtr = writeString(M, id.node);
    const styleNamePtr = styleName === null || styleName === undefined
      ? 0 : writeString(M, styleName);
    const styleValuePtr = styleValue === null || styleValue === undefined
      ? 0 : writeString(M, styleValue);
    const rc = M._crabs_wasm_ot_document_apply(
      this._am, namePtr, opKind,
      BigInt(positions.position),
      BigInt(positions.second === undefined ? 0 : positions.second),
      textBytes.ptr, textBytes.len, styleNamePtr, styleValuePtr,
      idNodePtr, BigInt(id.seq), BigInt(id.ts === undefined ? 0 : id.ts),
      depsPtr.ptr, deps.length);
    freeAll(M, namePtr, idNodePtr, styleNamePtr, styleValuePtr);
    freeAll(M, textBytes.ptr === 0 ? 0 : textBytes.ptr, depsPtr.ptr);
    wrapRc(rc, ctx);
  }

  _otTreeApply(name, opKind, positions, nodeId, parentId, value, options,
               ctx) {
    if (typeof nodeId !== 'string' || nodeId.length === 0 ||
        nodeId.length >= OT_TREE_NODE_ID_MAX) {
      throw new RangeError(
        `${ctx}: nodeId must be 1..${OT_TREE_NODE_ID_MAX - 1} characters`);
    }
    if (parentId !== null && parentId !== undefined &&
        (typeof parentId !== 'string' ||
         parentId.length >= OT_TREE_NODE_ID_MAX)) {
      throw new RangeError(
        `${ctx}: parentId must be at most ${OT_TREE_NODE_ID_MAX - 1} characters`);
    }
    if (value !== null && value !== undefined) {
      const valueBytes = OT_TEXT_ENCODER.encode(String(value));
      if (valueBytes.length > OT_ELEMENT_MAX_BYTES - 2 * OT_TREE_NODE_ID_MAX) {
        throw new RangeError(
          `${ctx}: node value payload exceeds the ${OT_ELEMENT_MAX_BYTES - 2 * OT_TREE_NODE_ID_MAX}-byte OT limit`);
      }
    }
    const M = this._M;
    const { id, deps } = _otOpIdentity(options, ctx);
    const valueBytes = value === null || value === undefined
      ? { ptr: 0, len: 0 }
      : writeBytes(M, OT_TEXT_ENCODER.encode(String(value)));
    const depsPtr = writeBytes(M, packOrderedDeps(deps, ctx));
    const namePtr = writeString(M, name);
    const idNodePtr = writeString(M, id.node);
    const nodeIdPtr = writeString(M, nodeId);
    const parentIdPtr = parentId === null || parentId === undefined || parentId === ''
      ? 0 : writeString(M, parentId);
    const rc = M._crabs_wasm_ot_tree_apply(
      this._am, namePtr, opKind, BigInt(positions.position), nodeIdPtr,
      parentIdPtr, valueBytes.ptr, valueBytes.len,
      idNodePtr, BigInt(id.seq), BigInt(id.ts === undefined ? 0 : id.ts),
      depsPtr.ptr, deps.length);
    freeAll(M, namePtr, idNodePtr, nodeIdPtr, parentIdPtr);
    freeAll(M, valueBytes.ptr === 0 ? 0 : valueBytes.ptr, depsPtr.ptr);
    wrapRc(rc, ctx);
  }

  execute(op) {
    // RAFT ordering module path: a GROUP_ORDERED write through an attached
    // module returns ordering_pending (0xA006) — the op was ACCEPTED into
    // the module's log as a pending proposal and materializes on commit
    // (pumped by the raft host or processRaftNotifications at later now). An
    // attachment-less direct write to a group item still throws (the v1
    // fail-closed 'ordering_path' seam). Other error codes keep their
    // pre-raft shape.
    const rc = this._M._crabs_wasm_execute(this._am, op._ptr);
    if (rc === 0xA006) return;
    wrapRc(rc, 'execute');
  }

  // Replay ingest (bounded-skew replay fix): execute a signed op under this
  // node's REPLAY skew policy (Node.create option skew.replayPolicy). For a
  // VALID op it never throws — returns an outcome so a log replay can
  // converge by design:
  //   { status: 'applied' | 'pending' } on success / raft-pending
  //   { status: 'skipped', code, message } on failure (e.g. 0x1002
  //   protocol_violation for a future stamp, 0x7002 already_executed on a
  //   re-ingested op) — a skipped op mutates nothing.
  // A destroyed op (_ptr === 0) or an Operation minted by a DIFFERENT module
  // instance throws TypeError: the destroyed case has nothing to replay, and
  // a foreign-module op's `_ptr` is a valid offset in a different address
  // space — feeding it here would be a memory-confusion read of someone
  // else's heap.
  // GROUP_ORDERED note: a pending outcome still emits a 'change' event on
  // the node (the C layer notifies every non-ALREADY_EXECUTED result) — do
  // not wire replay-driven events to live-UI mutation paths.
  replayOp(op) {
    // Audit M-7 parity with sign(): a foreign-module Operation's `_ptr` is a
    // valid offset in a DIFFERENT address space — reading it here would be a
    // memory-confusion read of someone else's heap.
    if (!op || !op._ptr || op._M !== this._M) {
      throw new TypeError('replayOp: expected an Operation from this module');
    }
    const rc = this._M._crabs_wasm_execute_replay(this._am, op._ptr);
    if (rc === 0) return { status: 'applied' };
    if (rc === 0xA006) return { status: 'pending' };   // raft GROUP_ORDERED path
    return { status: 'skipped', code: rc, message: crabsError(rc, 'replayOp').message };
  }

  // Bulk history ingest: replay a batch of ALREADY-DESERIALIZED Operations.
  // Per-op failures never abort the batch — each skip is console.warn'd and
  // returned with its index, so consumers converge (and can surface gaps)
  // instead of dying on the first out-of-window or opaque entry. `applied`
  // holds INDICES; pending outcomes (raft GROUP_ORDERED) also land in
  // `applied` — accepted into the ordering log, not yet committed.
  // NOTE: raft-committed history recovers through the raft module's own
  // persisted batches (raftRecoverFromPersist), NOT through this API.
  replayOps(operations) {
    if (!Array.isArray(operations)) {
      throw new TypeError('replayOps: expected an array of Operations');
    }
    const applied = [];
    const skipped = [];
    operations.forEach((entryOperation, entryIndex) => {
      const outcome = this.replayOp(entryOperation);
      if (outcome.status !== 'skipped') {
        applied.push(entryIndex);
      } else {
        console.warn(`crabs-wasm: replay skipped op[${entryIndex}]: ${outcome.message}`);
        skipped.push({ index: entryIndex, code: outcome.code, message: outcome.message });
      }
    });
    return { applied, skipped };
  }

  sign(op, signingKey) {
    const M = this._M;
    if (signingKey && typeof signingKey === 'object') {
      if (!signingKey._ptr) throw new Error('Expected KeyPair or private key hex string');
      if (signingKey._M !== this._M) {
        // A KeyPair from ANOTHER module instance has a foreign-heap _ptr —
        // reading it as if local would deref someone else's linear memory.
        throw new Error('sign: the KeyPair was minted by a different module instance');
      }
      // Audit M-7: the scalar already lives in THIS module's heap at _ptr —
      // point at it directly instead of materializing a JS hex string (V8
      // strings can't be zeroized, so the old round-trip minted an
      // unwipeable copy of the private key on every signature). The C-side
      // frame is the authority; heap growth detaches ArrayBuffer VIEWS, it
      // never moves a live C allocation, so _ptr stays valid here.
      const rc = M._crabs_wasm_sign_operation(this._am, op._ptr, signingKey._ptr);
      wrapRc(rc, 'sign');
      return;
    }
    let privHex;
    if (typeof signingKey === 'string') {
      privHex = signingKey;
    } else {
      throw new Error('Expected KeyPair or private key hex string');
    }
    if (typeof privHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(privHex)) {
      throw new Error('sign: private key must be 64 hex chars (32 bytes)');
    }
    const privPtr = M._malloc(32);
    try {
      hexDecode(M, privHex, privPtr, 32);
      const rc = M._crabs_wasm_sign_operation(this._am, op._ptr, privPtr);
      wrapRc(rc, 'sign');
    } finally {
      // The staged 32-byte private scalar must never linger in wasm linear
      // memory (the heap never shrinks and dlmalloc recycles chunks
      // verbatim) — zeroize on the success path AND every error path.
      wipeFree(M, privPtr, 32);
    }
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
    wrapRc(M._crabs_wasm_op_init_uuid(opPtr), 'createTrigger');
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

  // DedupSpec op-type registration (v1.4 §7): register a machine-enforced
  // dedup spec for a USER-DEFINED operation type. The C export composes,
  // node-key-signs (as the machine's bootstrap admin) and executes a
  // '__define_operation_type__' op whose resources[0] carries opType and
  // whose dedup struct carries the spec; the machine registry stores it
  // (state_register_op_type_def) and the executor resolves it for every
  // later op of that type — registered specs win over anything the op
  // carries on the wire (the F-2 bypass shape fails closed).
  //
  // options.dedup: 'per-user' (options.trackerPath: a ONE_SHOT_SET item
  // name, created with addOneShotSet — the executor validates it exists
  // before any handler runs) | 'global' (options.flagPath: an
  // addOneShotFlag item name) | 'none' (disables a previously defined
  // guard for the type and seals it against op-carried specs). The
  // 'custom' shape stays C-native: its condition evaluator and its
  // spec-carried mutation target are not reason-able from JS.
  // options.rejectionMessage is stored metadata on the spec; the refusal
  // itself surfaces as the machine's dedup domain error
  // ('already_performed' / 'already_executed').
  //
  // Like createTrigger, the caller installs the define type's own policy
  // first (node.setPolicy('__define_operation_type__', 'role:admin')) —
  // the bootstrap admin holds role:admin, so an admin-owned policy is the
  // natural wiring.
  defineOperationType(opType, options) {
    const M = this._M;
    if (!options || typeof options !== 'object') {
      throw new Error('defineOperationType: expected an options object with a dedup field');
    }
    if (typeof opType !== 'string' || opType.length === 0) {
      throw new Error('defineOperationType: opType must be a non-empty string');
    }
    const DEDUP_NUMBERS = { none: 0, 'per-user': 1, global: 2 };
    const dedupType = DEDUP_NUMBERS[options.dedup];
    if (dedupType === undefined) {
      throw new Error("defineOperationType: dedup must be 'per-user' | 'global' | 'none' (" +
        "the 'custom' shape is C-native and not surfaceable)");
    }
    if (options.dedup === 'per-user' && !options.trackerPath) {
      throw new Error("defineOperationType: dedup 'per-user' requires a trackerPath (the ONE_SHOT_SET once-record)");
    }
    if (options.dedup === 'none' && (options.trackerPath || options.flagPath)) {
      throw new Error("defineOperationType: dedup 'none' takes no trackerPath/flagPath (a 'none' definition removes the guard; nothing to track)");
    }
    if (options.dedup === 'global' && !options.flagPath) {
      throw new Error("defineOperationType: dedup 'global' requires a flagPath (the ONE_SHOT_FLAG once-record)");
    }
    // The C spec fields are CRABS_MAX_DEDUP_PATH (128) / CRABS_MAX_DEDUP_MESSAGE
    // (256) bytes — a longer string would be silently truncated into a
    // tracker/flag lookup that never resolves (or a cut-off message), so
    // refuse loudly instead. The C buffers count BYTES, so measure the UTF-8
    // encoding, never the UTF-16 string length.
    const DEDUP_PATH_MAX = 127;
    const DEDUP_MESSAGE_MAX = 255;
    if (options.trackerPath && encodeText(options.trackerPath).length > DEDUP_PATH_MAX) {
      throw new Error(`defineOperationType: trackerPath exceeds ${DEDUP_PATH_MAX} bytes`);
    }
    if (options.flagPath && encodeText(options.flagPath).length > DEDUP_PATH_MAX) {
      throw new Error(`defineOperationType: flagPath exceeds ${DEDUP_PATH_MAX} bytes`);
    }
    if (options.rejectionMessage && encodeText(options.rejectionMessage).length > DEDUP_MESSAGE_MAX) {
      throw new Error(`defineOperationType: rejectionMessage exceeds ${DEDUP_MESSAGE_MAX} bytes`);
    }
    const opTypePtr = writeString(M, opType);
    const trackerPtr = options.trackerPath ? writeString(M, options.trackerPath) : 0;
    const flagPtr = options.flagPath ? writeString(M, options.flagPath) : 0;
    const messagePtr = options.rejectionMessage ? writeString(M, options.rejectionMessage) : 0;
    const rc = M._crabs_wasm_define_operation_type(
      this._am, opTypePtr, dedupType, trackerPtr, flagPtr, 0, messagePtr);
    freeAll(M, opTypePtr, trackerPtr, flagPtr, messagePtr);
    wrapRc(rc, 'defineOperationType');
  }

  encrypt(data, policy) {
    const M = this._M;
    let b = data;
    if (typeof b === 'string') b = encodeText(b);
    const { ptr: dPtr, len: dLen } = writeBytes(M, b);
    const pPtr = writeString(M, policy);
    const ct = M._crabs_wasm_abe_encrypt(this._am, dPtr, dLen, pPtr);
    // Audit M-5: the staged plaintext is a secret on BOTH arms — before handoff
    // (this copy) and after decrypt (the recovered key/bytes) — so it takes the
    // same wipeFree as every other staging arm; freeAll's plain free hands the
    // plaintext to dlmalloc's free list.
    wipeFree(M, dPtr, dLen);
    if (pPtr) M._free(pPtr);
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

  // --- ABE keygen + decrypt (gap-fill A11) ---
  //
  // abeKeygen(attrs) derives a CP-ABE reader key from THE MACHINE'S OWN
  // master authority (state->abe_mk, attribute_machine.c:309): whoever
  // controls the machine can mint a key for any attribute set it names —
  // the same trust position as encrypt. The master key itself never leaves
  // the machine (no JS handle for it exists; no portable serialized key in
  // v1). attrs is the comma-separated token list the C API takes, with the
  // ':' → '_' token map applied machine-side (crypto.c:98-111) — so a key
  // derived from 'role:member,role:moderator' carries the ABE words
  // role_member / role_moderator, and the seal policy must be written with
  // those same words. The returned AbeKey is JS-owned: destroy it (or any
  // later decrypt through it refuses).
  abeKeygen(attrs) {
    if (typeof attrs !== 'string' || attrs.length === 0) {
      throw new Error('abeKeygen: attrs must be a non-empty attribute token list');
    }
    const M = this._M;
    const aPtr = writeString(M, attrs);
    const keyPtr = M._crabs_wasm_abe_keygen(this._am, aPtr);
    freeAll(M, aPtr);
    if (!keyPtr) throw new Error('abeKeygen failed (no machine authority or refused attrs)');
    return new AbeKey(M, keyPtr);
  }

  // abeDecrypt(key, encrypted) opens the container encrypt() returned —
  // u16le policy byte length + policy bytes + u32le ciphertext length +
  // ciphertext (layouts pinned by smoke.js:111-130). Malformed containers
  // refuse at the binding boundary; a key whose attributes do not satisfy
  // the container's policy refuses with the typed error word —
  // 'unauthorized' — straight from crypto_abe_decrypt (also the tamper
  // path: GCM fail-closed). Staging discipline: the ciphertext handle is
  // rebuilt from the container halves, decrypted, and DESTROYED on every
  // path (inner finally); the plaintext the C side mallocs is copied into
  // a fresh Uint8Array and M._free()d before returning — nothing lingers
  // on the WASM heap.
  abeDecrypt(key, encrypted) {
    if (!(key instanceof AbeKey) || !key._ptr) {
      throw new Error('abeDecrypt: expected a live AbeKey (from abeKeygen; a destroyed key refuses)');
    }
    if (!(encrypted instanceof Uint8Array) || encrypted.length === 0) {
      throw new Error('abeDecrypt: expected the ABE container encrypt() returned');
    }
    const M = this._M;
    // Refuse sub-minimum containers BEFORE any DataView read — getUint16 on
    // a shorter view would throw a raw RangeError instead of this typed one.
    if (encrypted.length < 2 + 4) {
      throw new Error('abeDecrypt: malformed container (truncated header)');
    }
    const view = new DataView(encrypted.buffer, encrypted.byteOffset,
                              encrypted.byteLength);
    const policyByteLen = view.getUint16(0, true);
    const ctLenOffset = 2 + policyByteLen;
    if (ctLenOffset + 4 > encrypted.length) {
      throw new Error('abeDecrypt: malformed container (truncated header)');
    }
    const ctLen = view.getUint32(ctLenOffset, true);
    if (2 + policyByteLen + 4 + ctLen !== encrypted.length) {
      throw new Error(`abeDecrypt: malformed container (header declares ${2 + policyByteLen + 4 + ctLen} bytes, container is ${encrypted.length})`);
    }
    const policyText = new TextDecoder().decode(encrypted.subarray(2, ctLenOffset));
    const pPtr = writeString(M, policyText);
    const { ptr: cPtr } = writeBytes(M, encrypted.subarray(ctLenOffset + 4,
                                                            ctLenOffset + 4 + ctLen));
    const ctPtr = M._crabs_wasm_abe_ciphertext_load(pPtr, cPtr, ctLen);
    freeAll(M, pPtr, cPtr);
    if (!ctPtr) {
      throw new Error('abeDecrypt: container did not reconstruct (policy or ciphertext invalid)');
    }
    const outPtrPtr = M._malloc(4);
    const outLenPtr = M._malloc(4);
    try {
      const rc = M._crabs_wasm_abe_decrypt(key._ptr, ctPtr, outPtrPtr, outLenPtr);
      if (rc !== 0) throw crabsError(rc, 'abeDecrypt');
      const outPtr = M.getValue(outPtrPtr, 'i32');
      const outLen = M.getValue(outLenPtr, 'i32');
      const plain = new Uint8Array(M.HEAPU8.subarray(outPtr, outPtr + outLen));  // copy
      wipeFree(M, outPtr, outLen);  // copied into `plain` above — the heap copy must not linger
      return plain;
    } finally {
      freeAll(M, outPtrPtr, outLenPtr);
      M._crabs_wasm_abe_ciphertext_destroy(ctPtr);
    }
  }

  // --- ABE key transport (parity-fill P4) ---

  // abeKeyFromWire(wire) re-imports a reader key the AbeKey.toWire() form
  // carries. The C deserialize signature takes the master key
  // (crypto_abe_user_key_deserialize(mk, buf, len) — the header comment says
  // "the master key provides the public params") — so the restore runs on
  // THIS machine's authority and REFUSES without one — but the CAPABILITY is
  // the wire's OWN: OpenABE's key import binds the restored key to its
  // MINTING domain, whatever machine re-imports it (pinned cross-machine in
  // key-transport.js: an n1 wire restored on a stranger machine still opens
  // n1's secrets and refuses a stranger authority's. That is the bearer
  // truth of the wire, not a restore accident). The wire is integrity-blind
  // (no checksum): carry it over an authenticated channel, or use the key
  // envelope flow below. A returned key is JS-owned (idempotent destroy);
  // malformed or empty wire throws (the 'MK' master-key magic refuses with
  // the typed invalid_param — an authority image is not a reader key).
  //
  // Staging discipline (P4 review, mirroring stageSealKey32): the wire bytes
  // are staged into the module heap for the call and ZEROED + freed in the
  // finally — the staged copy of a key wire is as sensitive as the key.
  abeKeyFromWire(wire) {
    requireWireBytes(wire, 'abeKeyFromWire');
    if (wire.length === 0) {
      throw new Error('abeKeyFromWire: empty wire refuses');
    }
    if (this._am === null) {
      throw new Error('abeKeyFromWire: a destroyed node cannot restore keys');
    }
    const M = this._M;
    const { ptr, len } = writeBytes(M, wire);
    const rcPtr = M._malloc(4);
    try {
      const keyPtr = M._crabs_wasm_abe_key_deserialize(this._am, ptr, len, rcPtr);
      if (!keyPtr) {
        throw crabsError(M.getValue(rcPtr, 'i32'), 'abeKeyFromWire');
      }
      return new AbeKey(M, keyPtr);
    } finally {
      M.HEAPU8.fill(0, ptr, ptr + len);
      freeAll(M, ptr, rcPtr);
    }
  }

  // mintKeyEnvelope(userId, options?) — the refresh_key materialization
  // shape (state_machine.c:2797) without the protocol bookkeeping: the
  // machine's own authority + node private key issue a real CP-ABE key for
  // the user's CURRENT attribute set, verified by the node's ECDSA
  // signature, and the key travels ECIES-wrapped to the user's REGISTERED
  // public key (never cleartext). Gates mirrored from the refresh path
  // (fail-closed): only ACTIVE users receive envelopes (suspended →
  // user_suspended, unknown → user_not_found), a live node key and authority
  // are required. Unlike the refresh protocol op this mutates NOTHING (no
  // key_version bump). options.expiresAt — epoch-ms expiry stamped into the
  // envelope (default 0 = no expiry, exactly what refresh issues; expiry
  // READBACK/enforcement is integrator-side, C carries it unenforced).
  // Returns the envelope wire (crypto_key_envelope_serialize flat form).
  mintKeyEnvelope(userId, options) {
    if (typeof userId !== 'string' || userId.length === 0) {
      throw new Error('mintKeyEnvelope: userId must be a non-empty string');
    }
    if (options !== undefined && options !== null &&
        (typeof options !== 'object' || Array.isArray(options))) {
      throw new Error('mintKeyEnvelope: options must be an object {expiresAt?}');
    }
    const expiresAtValue = options?.expiresAt;
    if (expiresAtValue !== undefined && expiresAtValue !== null &&
        (!(typeof expiresAtValue === 'number' || typeof expiresAtValue === 'bigint') ||
        expiresAtValue < 0 || expiresAtValue > Number.MAX_SAFE_INTEGER)) {
      throw new RangeError('mintKeyEnvelope: expiresAt must be a non-negative epoch-ms number');
    }
    if (this._am === null) {
      throw new Error('mintKeyEnvelope: a destroyed node cannot mint envelopes');
    }
    const M = this._M;
    const userPtr = writeString(M, userId);
    const rcPtr = M._malloc(4);
    let env = null;
    try {
      env = M._crabs_wasm_mint_key_envelope(this._am, userPtr,
          expiresAtValue === undefined || expiresAtValue === null
            ? 0n : BigInt(expiresAtValue), rcPtr);
      if (!env) {
        throw crabsError(M.getValue(rcPtr, 'i32'), 'mintKeyEnvelope');
      }
      const len = M._crabs_wasm_buffer_len(env);
      const data = M._crabs_wasm_buffer_data(env);
      const out = new Uint8Array(M.HEAPU8.subarray(data, data + len));
      M._crabs_wasm_buffer_destroy(env);
      env = null;
      return out;
    } finally {
      freeAll(M, userPtr, rcPtr);
      if (env) M._crabs_wasm_buffer_destroy(env);
    }
  }

  // decryptKeyEnvelope(envelope, options) opens a mintKeyEnvelope wire on
  // the recipient side and returns the restored AbeKey — the C
  // KeyEnvelope battery's flow (test_crypto.cpp:963-1032): parse (against
  // THIS machine's authority — the envelope carries no public params),
  // verify the ISSUER's ECDSA signature over the canonical envelope, then
  // open the ECIES blob with the recipient's private key and import the
  // recovered reader key against this authority. Both tamper paths fail
  // closed with the typed 'unauthorized' — a tampered envelope wire breaks
  // the signature, a wrong recipient private key or tampered blob breaks the
  // GCM tag. options.privateKeyHex — the recipient's 64-hex private key (the
  // KeyPair your public key was registered with); options.nodePublicKeyHex —
  // the ISSUER node's public key for out-of-machine verification (default:
  // this machine's own node key, which refuses envelopes another machine
  // issued — fail-closed). Staging discipline: the recipient private key
  // bytes are zeroed in the module heap on EVERY path (including type
  // refusals thrown before the call), and the recovered plaintext ABE key
  // never leaves C — it is cleansed inside the export before this returns.
  decryptKeyEnvelope(envelope, options) {
    if (!ArrayBuffer.isView(envelope) || envelope.length === 0) {
      throw new Error('decryptKeyEnvelope: expected the mintKeyEnvelope wire (Uint8Array)');
    }
    if (options === undefined || options === null || typeof options !== 'object' ||
        Array.isArray(options)) {
      throw new TypeError(
        'decryptKeyEnvelope: expected options { privateKeyHex, nodePublicKeyHex? }');
    }
    const privateKeyHex = options.privateKeyHex;
    if (typeof privateKeyHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(privateKeyHex)) {
      throw new TypeError('decryptKeyEnvelope: privateKeyHex must be 64 hex characters (32 bytes)');
    }
    const nodePublicKeyHex = options.nodePublicKeyHex;
    if (nodePublicKeyHex !== undefined && nodePublicKeyHex !== null &&
        (typeof nodePublicKeyHex !== 'string' ||
         !/^[0-9a-fA-F]{66}$/.test(nodePublicKeyHex))) {
      throw new TypeError('decryptKeyEnvelope: nodePublicKeyHex must be 66 hex characters (33 bytes)');
    }
    if (this._am === null) {
      throw new Error('decryptKeyEnvelope: a destroyed node cannot import keys');
    }
    const M = this._M;
    const privPtr = stageSealKey32(M, privateKeyHex, 'decryptKeyEnvelope');
    const wire = new Uint8Array(
        envelope.buffer, envelope.byteOffset, envelope.byteLength);
    const { ptr: wirePtr } = writeBytes(M, wire);
    let pubPtr = 0;
    if (nodePublicKeyHex !== undefined && nodePublicKeyHex !== null) {
      pubPtr = M._malloc(33);
      hexDecode(M, nodePublicKeyHex, pubPtr, 33);
    }
    const outKeyPtr = M._malloc(4);
    try {
      const rc = M._crabs_wasm_key_envelope_import(this._am, wirePtr, wire.length,
          privPtr, pubPtr, outKeyPtr);
      if (rc !== 0) throw crabsError(rc, 'decryptKeyEnvelope');
      const keyPtr = M.getValue(outKeyPtr, 'i32');
      if (!keyPtr) throw new Error('decryptKeyEnvelope: import staged no key');
      return new AbeKey(M, keyPtr);
    } finally {
      // The staged recipient private key never lingers past the call.
      M.HEAPU8.fill(0, privPtr, privPtr + 32);
      freeAll(M, privPtr, wirePtr, pubPtr, outKeyPtr);
    }
  }

  // serializeMasterKey() — the §11.5 durability backup (the C battery's
  // MasterKeySerializeRoundTripPreservesAuthority): the machine's authority
  // in its 'MK' wire form, restorable into a machine via masterKeyFromWire.
  // A machine whose authority is merely BORROWED (a SHARED_ROOT lineage
  // child) refuses protocol_violation — the child USES the parent's
  // authority pointer, it is not entrusted with the MSK bytes at rest.
  //
  // TRUST FACT (the d.ts prose must keep saying it): THIS IS THE MACHINE'S
  // CROWN JEWEL — whoever holds these bytes mints reader keys for ANY policy
  // and decrypts EVERYTHING the authority ever sealed. Treat the return like
  // an unencrypted private key.
  //
  // Staging discipline (P4 review): the C staging buffer is torn down through
  // the KEY-WIRE cleansed destroy once this copy-out has read it, so the
  // crown-jewel bytes linger nowhere in the module heap past the call.
  serializeMasterKey() {
    if (this._am === null) {
      throw new Error('serializeMasterKey: a destroyed node refuses');
    }
    const M = this._M;
    const rcPtr = M._malloc(4);
    let ser = null;
    try {
      ser = M._crabs_wasm_master_key_serialize(this._am, rcPtr);
      if (!ser) {
        throw crabsError(M.getValue(rcPtr, 'i32'), 'serializeMasterKey');
      }
      const len = M._crabs_wasm_buffer_len(ser);
      const data = M._crabs_wasm_buffer_data(ser);
      const out = new Uint8Array(M.HEAPU8.subarray(data, data + len));
      return out;
    } finally {
      if (ser) M._crabs_wasm_key_wire_buffer_destroy(ser);
      M._free(rcPtr);
    }
  }

  // masterKeyFromWire(wire) REPLACES this machine's authority with the one
  // the wire carries (the recovery path a sealed snapshot's MSK section
  // already runs, serialization.c:2862-2866). A fresh authority makes the
  // machine mint keys in the restored domain — mirror of the C battery's
  // "restored authority is a full authority" fact. Refuses: malformed wire
  // (bad magic/overrun lengths — the C battery's garbage/overrun pins) with
  // the typed 'invalid_param', and a machine whose authority is merely
  // BORROWED (a delegated lineage child) with protocol_violation — never
  // replaces a borrowed authority. The restore cleanses the REPLACED
  // authority's serialized MPK/MSK wire copies in C (its context remains
  // the wasm policy leak); what survives the swap is only the new live
  // authority.
  //
  // Staging discipline (P4 review, mirroring stageSealKey32): the staged
  // 'MK' wire copy is zeroed in the module heap on every path — the staged
  // copy IS the crown jewel.
  masterKeyFromWire(wire) {
    requireWireBytes(wire, 'masterKeyFromWire');
    if (this._am === null) {
      throw new Error('masterKeyFromWire: a destroyed node cannot plant authorities');
    }
    const M = this._M;
    const { ptr, len } = writeBytes(M, wire);
    try {
      wrapRc(M._crabs_wasm_master_key_restore(this._am, ptr, len), 'masterKeyFromWire');
    } finally {
      M.HEAPU8.fill(0, ptr, ptr + len);
      M._free(ptr);
    }
  }

  // Snapshot serialization (the C families at serialization.h:55-90):
  //   serialize()               — plain, SHA-256 checksummed (CORRUPTION CHECK ONLY);
  //   serialize({sealKey})      — sealed: MSK AES-256-GCM-wrapped under the key;
  //   serialize({signed: true}) — node-key ECDSA trailer appended;
  //   {sealKey, signed: true}   — sealed + signed (both at-rest guarantees).
  // Sealed variants need the machine's live master key, signed ones its node
  // key; without them C refuses (caught as a descriptive throw). A snapshot
  // blob is a FULL machine — see the restoreReport block on deserialize for
  // why the bare checksum is not authentication.
  serialize(options) {
    const M = this._M;
    if (options !== undefined && options !== null &&
        (typeof options !== 'object' || Array.isArray(options))) {
      throw new TypeError('serialize: options must be an object {sealKey?, signed?}');
    }
    if (options?.signed !== undefined && typeof options?.signed !== 'boolean') {
      throw new TypeError('serialize: signed must be a boolean');
    }
    const withSeal = options?.sealKey !== undefined && options?.sealKey !== null;
    const withSignature = options?.signed === true;

    let sealPtr = 0;
    let ser;
    try {
      if (withSeal) sealPtr = stageSealKey32(M, options.sealKey, 'serialize');
      if (withSignature && withSeal) {
        ser = M._crabs_wasm_serialize_state_sealed_signed(this._am, sealPtr);
      } else if (withSignature) {
        ser = M._crabs_wasm_serialize_state_signed(this._am);
      } else if (withSeal) {
        ser = M._crabs_wasm_serialize_state_sealed(this._am, sealPtr);
      } else {
        ser = M._crabs_wasm_serialize_state(this._am);
      }
    } finally {
      if (sealPtr !== 0) {  // the staged seal key never lingers past the call
        M.HEAPU8.fill(0, sealPtr, sealPtr + 32);
        M._free(sealPtr);
      }
    }
    if (!ser) {
      let hint = '';
      if (withSeal) hint += " — sealed snapshots need the machine's live master key";
      if (withSignature) hint += " — signed snapshots need the machine's node key";
      throw new Error(`serialize state failed${hint}`);
    }
    const len = M._crabs_wasm_buffer_len(ser);
    const data = M._crabs_wasm_buffer_data(ser);
    const out = new Uint8Array(M.HEAPU8.subarray(data, data + len));
    M._crabs_wasm_buffer_destroy(ser);
    return out;
  }

  // Restore a snapshot produced by serialize(): REPLACES this wrapper's
  // underlying machine with the restored state (the same Node stays usable;
  // the previous machine stays alive inside the module — wasm machines are
  // never destroyed). Returns the restore report
  //   { authorityRestored, mskSectionPresent }
  // which only means something for a SEALED blob:
  //   authorityRestored  — the sealed MSK unsealed with seal_key (a wrong or
  //                        missing key still loads, on the substrate-only
  //                        compatibility path, with a FRESH authority);
  //   mskSectionPresent  — the blob carried the authority section at all.
  //
  // options: { sealKey: '64-hex' } restores a sealed snapshot's master key;
  // { verify: 'node-key' } verifies a SIGNED snapshot's ECDSA trailer with
  // THIS machine's node public key BEFORE any parse — a plain load of a
  // signed blob is refused rather than silently accepted unauthenticated.
  // Both combine ({sealKey, verify:'node-key'}) for sealed+SIGNED blobs.
  //
  // Continuity: the node key, change hook, module-shared time source, live
  // raft module (re-pointed to the restored machine so raftPump keeps
  // driving it), the wrapper's ordering config, and the HLC clock state
  // (the restored machine's clock CONTINUES the previous machine's HLC)
  // ride over from the previous machine.
  //
  // TRUST MODEL: the blob's embedded SHA-256 is an INTEGRITY check, not
  // authentication — an attacker who can write the blob can recompute it
  // (serialization.h). Loading a snapshot from an untrusted source without
  // {verify:'node-key'} (and, when authority matters, the seal key) imports
  // whatever state the writer chose. Staged seal key bytes are zeroed on
  // every path.
  deserialize(wire, options) {
    const M = this._M;
    requireWireBytes(wire, 'deserialize');
    if (options !== undefined && (typeof options !== 'object' ||
                                  Array.isArray(options))) {
      throw new TypeError('deserialize: options must be an object {sealKey?, verify?}');
    }
    if (options?.verify !== undefined && options.verify !== 'node-key') {
      throw new TypeError("deserialize: verify must be the literal 'node-key'");
    }
    const withSeal = options?.sealKey !== undefined && options?.sealKey !== null;
    const verifySigned = options?.verify === 'node-key';
    // Same destroyed-wrapper gate shape the verifySigned branch uses — the
    // restore migrates the wrapper's machine (node key, time source, raft
    // module, ordering config, HLC clock), so a wrapper without one has
    // nothing to restore INTO.
    if (this._am === null) {
      throw new Error("deserialize: a destroyed node cannot restore snapshots");
    }

    let sealPtr = 0;
    let outAuthority = 0;
    let outMskSection = 0;
    let wirePtr = 0;
    try {
      if (withSeal) sealPtr = stageSealKey32(M, options.sealKey, 'deserialize');
      outAuthority = M._malloc(1);
      outMskSection = M._malloc(1);
      wirePtr = M._malloc(wire.length);
      M.HEAPU8.set(wire, wirePtr);
      const restoredPointer = M._crabs_wasm_deserialize_state(
          this._am, wirePtr, wire.length, sealPtr, verifySigned ? 1 : 0,
          outAuthority, outMskSection);
      const authorityRestored = M.getValue(outAuthority, 'i8') !== 0;
      const mskSectionPresent = M.getValue(outMskSection, 'i8') !== 0;
      if (restoredPointer === 0) {
        throw new Error(
            'deserialize: snapshot refused — malformed format, failed SHA-256 ' +
            'checksum, failed signature check, or an unloadable body');
      }
      this._am = restoredPointer;
      // A restore migrates the attached raft module to the restored machine
      // (the C side re-attaches it); the host's machine pointer must follow
      // or raftPump would drive the stale machine.
      if (this._raftHost) this._raftHost._am = restoredPointer;
      return { authorityRestored, mskSectionPresent };
    } finally {
      if (sealPtr !== 0) {
        M.HEAPU8.fill(0, sealPtr, sealPtr + 32);
        M._free(sealPtr);
      }
      freeAll(M, wirePtr, outAuthority, outMskSection);
    }
  }

  // Merge a foreign snapshot INTO this machine via crdt_merge_state (the
  // general item rules: counters max-per-node/sum-across-nodes, register
  // LWW, OR/2P-set union, one-shot take-any — order via the merge's logs —
  // and, since parity-fill P5, ordered-set items merge in place through
  // crabs_ot_ordered_set_merge: fresh items adopt, equivocating snapshots
  // refuse). This machine MUTATES toward the union; the source snapshot is
  // untouched (it has no machine attached). Returns undefined; throws
  // (machine untouched) on a malformed snapshot. Held items are NOT a
  // failure: they surface as __merge_held__ divergences on the change hook
  // and the merge returns SUCCESS — OT ordered sets can still fire one (a
  // same-op-id/different-payload refusal is CRABS_ERR_FORK_DETECTED), and
  // OT document/tree/table/ordered-map items (no merge machinery yet) hold
  // with CRABS_ERR_TYPE_MISMATCH.
  mergeState(wire) {
    const M = this._M;
    requireWireBytes(wire, 'mergeState');
    if (this._am === null) {
      throw new Error('mergeState: a destroyed node cannot merge snapshots');
    }
    let wirePtr = 0;
    try {
      wirePtr = M._malloc(wire.length);
      M.HEAPU8.set(wire, wirePtr);
      const rc = M._crabs_wasm_merge_state(this._am, wirePtr, wire.length);
      wrapRc(rc, 'mergeState');
    } finally {
      if (wirePtr) M._free(wirePtr);
    }
  }

  setTime(nowMs) { this._M._crabs_wasm_set_time(this._am, BigInt(nowMs)); }

  // HLC watermark readback: the machine's LAST-issued hybrid timestamp,
  // WITHOUT advancing the clock. Parity-fill P10 unified the semantics: the
  // native binding's getHLC is now this SAME read-only watermark (advance
  // happens only when an op executes — every sign/execute path issues
  // crabs_hlc_next explicitly), so two consecutive reads are identical and
  // restore continuity pins stay deterministic. The readback carries the
  // node binding's shape: {seconds, nanos, logicalCounter, nodeId,
  // formatted}. undefined on an uninitialized clock (a lamport-ordered
  // machine, or a restored state whose Continuity block never re-applied
  // the clock).
  // Out-buffer layout: u64le physical_seconds | u64le physical_nanos |
  // u64le logical_counter | 64-byte node id | 128-byte formatted stamp.
  getHLC() {
    const M = this._M;
    const outPtr = M._malloc(24);
    const nodeIdPtr = M._malloc(64);
    const formattedPtr = M._malloc(128);
    try {
      const watermark = M._crabs_wasm_get_hlc(this._am, outPtr, outPtr + 8,
                                              outPtr + 16,
                                              nodeIdPtr, 64,
                                              formattedPtr, 128);
      if (!watermark) return undefined;
      const view = new DataView(M.HEAPU8.buffer, M.HEAPU8.byteOffset + outPtr,
                                24);
      return {
        seconds: Number(view.getBigUint64(0, true)),
        nanos: Number(view.getBigUint64(8, true)),
        logicalCounter: Number(view.getBigUint64(16, true)),
        nodeId: M.UTF8ToString(nodeIdPtr),
        formatted: M.UTF8ToString(formattedPtr),
      };
    } finally {
      freeAll(M, outPtr, nodeIdPtr, formattedPtr);
    }
  }

  pruneExpiredTempAttrs() { return this._M._crabs_wasm_prune_expired_temp_attrs(this._am); }

  // Direct temporary-attribute issuance (Amendment 1 §7.1) — the path the
  // moderation trigger's issue_attribute effect takes, driven by hand. The
  // grant fans out to EVERY ACTIVE holder of the audience attribute NAME
  // (attribute_machine.c:592's name-match; pass 'role', never 'role:member')
  // and stamps issued_at / expires_at from the machine's attr-machine clock —
  // pair with setTime for test timelines or a live clock. The C machine owns
  // every gate (typed refusals surfaced as-is):
  //   unauthorized — the attribute NAME is in the privileged blocklist
  //     (the 'role'/'admin'/'verifier' family — issueTemporary('role', ...)
  //     would forge the admin gate otherwise, Audit N-1);
  //   invalid_param — ttl 0, a name outside the safe charset, or a value
  //     carrying comma/space (the attribute-string token-injection guard).
  issueTemporary(attribute, value, options = {}) {
    const M = this._M;
    if (typeof attribute !== 'string' || attribute.length === 0 ||
        typeof value !== 'string' || value.length === 0) {
      throw new TypeError('issueTemporary: attribute and value are required non-empty strings');
    }
    if (!options || typeof options !== 'object' || Array.isArray(options) ||
        typeof options.audienceRole !== 'string' || options.audienceRole.length === 0) {
      throw new TypeError(
        "issueTemporary: options.audienceRole is required (the audience attribute NAME the fan-out matches — 'role', not 'role:member')");
    }
    // u64 wire: a fractional or negative ttl would wrap — refuse at the
    // wrapper; ttl 0 flows through to the C machine's own invalid_param gate
    // (the C machine owns every gate).
    const ttlMs = typeof options.ttlMs === 'bigint'
      ? options.ttlMs
      : Number.isInteger(options.ttlMs) ? BigInt(options.ttlMs) : null;
    if (ttlMs === null || ttlMs < 0n) {
      throw new RangeError('issueTemporary: ttlMs must be a non-negative integer or BigInt');
    }
    const attributePtr = writeString(M, attribute);
    const valuePtr = writeString(M, value);
    const rolePtr = writeString(M, options.audienceRole);
    const rc = M._crabs_wasm_issue_temporary(
        this._am, attributePtr, valuePtr, rolePtr, ttlMs);
    freeAll(M, attributePtr, valuePtr, rolePtr);
    wrapRc(rc, 'issueTemporary');
  }

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

  // Explicit trigger tick (parity-fill P10): the C primitive the executor
  // runs post-execute (trigger_process_all, Trigger/trigger.h:81), driven
  // by hand. The old shape — a signed zero-resource 'noop' execute —
  // refused resource_not_found on any policy-less machine (the executor's
  // step-7 rule), so it was replaced by the direct tick export. An
  // unreadable machine clock fails closed with the typed
  // 'cryptographic_error' the node binding throws for the same refusal.
  // Returns the number of triggers fired this tick.
  evaluateTriggers() {
    const M = this._M;
    const fired = M._crabs_wasm_evaluate_triggers(this._am);
    if (fired < 0) {
      throw crabsError(0x4002 /* CRABS_ERR_CRYPTOGRAPHIC_ERROR */,
                       'evaluateTriggers');
    }
    return Number(fired);
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
      // The op's declared resource names, in order (fixed 64-byte C slots
      // read synchronously) — what a handler needs to resolve the items it
      // debits/credits (recipe 9).
      const resources = [];
      const resourceCount = M._crabs_wasm_op_resource_count(opPtr);
      for (let slot = 0; slot < resourceCount; slot++) {
        const namePtr = M._crabs_wasm_handler_op_resource(opPtr, slot);
        resources.push(namePtr ? readString(M, namePtr) : null);
      }
      const op = {
        type: readString(M, M._crabs_wasm_op_get_type(opPtr)),
        signerId: readString(M, M._crabs_wasm_op_get_signer(opPtr)),
        nodeId: readString(M, M._crabs_wasm_op_get_node(opPtr)),
        payload: readString(M, M._crabs_wasm_handler_op_get_payload_str(opPtr)),
        resources,
      };
      const state = {
        getCounter(name) { return node._callCounterGetFromAm(M, amPtr, M._crabs_wasm_get_counter, name); },
        getPNCounter(name) { return node._callCounterGetFromAm(M, amPtr, M._crabs_wasm_get_pn_counter, name); },
        getRegister(name) { return node._callCounterGetFromAm(M, amPtr, M._crabs_wasm_get_register, name); },
        setContains(name, element) { return node._callSetContainsFromAm(M, amPtr, name, element); },
        // Consumption findings 3-4 read APIs — see Node.getSetSize et al for
        // the bounded/cap/sort contracts.
        getSetSize(name) {
          const nPtr = writeString(M, name);
          const out = M._crabs_wasm_handler_set_size(amPtr, nPtr);
          if (nPtr) M._free(nPtr);
          return out;
        },
        getSetElements(name, options = {}) {
          const offset = options.offset === undefined ? 0 : options.offset >>> 0;
          const limit = options.limit === undefined ? HANDLER_SET_PAGE_CAP : options.limit;
          if (!Number.isInteger(limit) || limit < 1 || limit > HANDLER_SET_PAGE_CAP) {
            throw new Error(
              `handler getSetElements: limit must be an integer in [1, ${HANDLER_SET_PAGE_CAP}]`
            );
          }
          return node._callGetSetElementsFromAm(M, amPtr, name, offset, limit);
        },
        getSetTags(name, element) { return node._callGetSetTagsFromAm(M, amPtr, name, element); },
        getRegisterBytes(name) { return node._callGetRegisterBytesFromAm(M, amPtr, name); },
        // Recipe 9 handler surface: raw RESOURCE balance readback + the
        // overflow-checked int64 adjustment a debit/credit handler uses (the
        // C handlers do the same find-and-mutate). Only RESOURCE items are
        // accepted; the executor's preconditions ran before this handler.
        getResource(name) {
          const M2 = M;
          const nPtr = writeString(M2, name);
          const outPtr = M2._malloc(8);
          const rc = M2._crabs_wasm_get_resource(amPtr, nPtr, outPtr);
          let balance = 0n;
          if (rc === 0) {
            balance = new DataView(M2.HEAPU8.buffer,
              M2.HEAPU8.byteOffset + outPtr, 8).getBigInt64(0, true);
          }
          freeAll(M2, nPtr, outPtr);
          wrapRc(rc, 'handler getResource');
          return Number(balance);
        },
        adjustResource(name, delta) {
          const M2 = M;
          if (!Number.isInteger(delta)) {
            throw new Error('adjustResource: delta must be an integer (int64)');
          }
          const nPtr = writeString(M2, name);
          const rc = M2._crabs_wasm_handler_adjust_resource(
            statePtr, nPtr, BigInt(delta));
          if (nPtr) M2._free(nPtr);
          wrapRc(rc, 'handler adjustResource');
        },
        setRegisterBytes(name, bytes, nodeId = 'system') { return node._callSetRegisterBytesFromAm(M, amPtr, name, bytes, nodeId); },
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
    const intValue = validateRegisterInt(value, 'handler setRegister');
    const nPtr = writeString(M, name);
    const idPtr = writeString(M, nodeId);
    const rc = M._crabs_wasm_set_register(amPtr, nPtr, intValue, idPtr);
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

  // Invoke a read helper that hands back a serialized_buffer_t on success
  // and a u32 crabs_error_e via an out-param on failure. `buildArgs` returns
  // `{ ptrs, extras }`: `ptrs` are the wasm-pointer arguments to free after
  // the call, `extras` are all C-side arguments in order (including the
  // pointer values from `ptrs`). `ctx` ends up in the thrown crabsError.
  // Returns the raw buffer bytes; the buffer is destroyed before return.
  _callHandlerReadBufferFromAm(M, amPtr, cfn, buildArgs, ctx) {
    const rcPtr = M._malloc(4);
    M.setValue(rcPtr, 0, 'i32');
    const { ptrs, extras } = buildArgs();
    const bufferPtr = cfn(amPtr, ...extras, rcPtr);
    freeAll(M, ...ptrs);
    const rc = M.getValue(rcPtr, 'i32') >>> 0;
    if (rcPtr) M._free(rcPtr);
    if (rc !== 0) throw crabsError(rc, ctx);
    if (!bufferPtr) throw new Error(`${ctx}: empty result buffer`);
    const data = M._crabs_wasm_buffer_data(bufferPtr);
    const len = M._crabs_wasm_buffer_len(bufferPtr);
    const bytes = new Uint8Array(M.HEAPU8.subarray(data, data + len));
    M._crabs_wasm_buffer_destroy(bufferPtr);
    return bytes;
  }

  _callGetSetElementsFromAm(M, amPtr, name, offset, limit) {
    const bytes = this._callHandlerReadBufferFromAm(
      M, amPtr, M._crabs_wasm_handler_set_elements,
      () => {
        const nPtr = writeString(M, name);
        return { ptrs: [nPtr], extras: [nPtr, offset, limit] };
      },
      'getSetElements'
    );
    return parseStringList(bytes);
  }

  _callGetSetTagsFromAm(M, amPtr, name, element) {
    const bytes = this._callHandlerReadBufferFromAm(
      M, amPtr, M._crabs_wasm_handler_set_tags,
      () => {
        const nPtr = writeString(M, name);
        const ePtr = writeString(M, element);
        return { ptrs: [nPtr, ePtr], extras: [nPtr, ePtr] };
      },
      'getSetTags'
    );
    return parseStringList(bytes);
  }

  _callGetRegisterBytesFromAm(M, amPtr, name) {
    return this._callHandlerReadBufferFromAm(
      M, amPtr, M._crabs_wasm_handler_get_register_bytes,
      () => {
        const nPtr = writeString(M, name);
        return { ptrs: [nPtr], extras: [nPtr] };
      },
      'getRegisterBytes'
    );
  }

  _callSetRegisterBytesFromAm(M, amPtr, name, bytes, nodeId) {
    const nPtr = writeString(M, name);
    const { ptr: dPtr, len: dLen } = writeBytes(M, bytes || new Uint8Array(0));
    const idPtr = writeString(M, nodeId || 'system');
    const rc = M._crabs_wasm_set_register_bytes(amPtr, nPtr, dPtr, dLen, idPtr);
    freeAll(M, nPtr, dPtr, idPtr);
    if (rc !== 0) throw crabsError(rc, 'handler setRegisterBytes');
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

  // Rotate this machine's lineage parent key (lineage_key_rotate,
  // lineage.h:285) and return the signed transition record: old_pk + new_pk
  // + created_at + 64-byte ECDSA over the body. The C contract says the
  // CALLER pairs the rotation with state_set_node_key — the wrapper does
  // both, so a stashed record whose new private key never landed cannot
  // happen. Every child bound to this parent takes the SAME record through
  // lineageAcceptKeyTransition (the broadcast feature; A11-L1 says deliver
  // to every child BEFORE minting the next rotation — one stash slot).
  // Refusals surface typed (e.g. cryptographic_error when the machine
  // carries no node key).
  lineageRotateKey(newKey) {
    // Audit pass-3 M: the prior round-trip through newKey.privateKeyHex()
    // minted a permanent V8 string copy of the fresh scalar (V8 strings
    // can't be zeroized) — the exact seam the M-7 sign() fix closed. Read
    // the 65 raw bytes (private_key[32] + public_key[33]; identical layout
    // for the raw and keypair forms) from THIS module's heap and wipe the
    // staging in a finally.
    const M = this._M;
    if (!newKey || !newKey._ptr || newKey._M !== this._M) {
      throw new TypeError(
          'lineageRotateKey: expected a KeyPair minted by THIS module instance');
    }
    const staged = M._malloc(65);
    try {
      new Uint8Array(M.HEAPU8.buffer, staged, 65)
          .set(new Uint8Array(M.HEAPU8.buffer, newKey._ptr, 65));
      const ser = M._crabs_wasm_lineage_key_rotate(this._am, staged, staged + 32);
      if (!ser) {
        throw new Error(
            'lineageRotateKey failed (the C gate refused — see the lineage_key_rotate contract)');
      }
      const len = M._crabs_wasm_buffer_len(ser);
      const data = M._crabs_wasm_buffer_data(ser);
      const out = new Uint8Array(M.HEAPU8.subarray(data, data + len));
      M._crabs_wasm_buffer_destroy(ser);
      return out;
    } finally {
      wipeFree(M, staged, 65);
    }
  }

  // Child side: ingest a parent-minted transition record (the exact bytes
  // lineageRotateKey returned, transported verbatim). The C gate owns every
  // refusal (lineage_child_accept_key_transition, lineage.h:318) and they
  // surface typed: invalid_param (malformed image, wrong parent_id,
  // rollback/replay gap), unauthorized (machine not bound to a parent, or
  // lineage dissolved), cryptographic_error (record not signed by the
  // chain TIP, or tip-signature failure), already_performed (an exact
  // re-delivery of an accepted record — A11-L5, matching the
  // dissolve/withdraw/tombstone re-delivery siblings).
  lineageAcceptKeyTransition(record) {
    const M = this._M;
    if (!(record instanceof Uint8Array) || record.length === 0) {
      throw new Error('lineageAcceptKeyTransition: expected the transition record bytes (Uint8Array)');
    }
    const { ptr, len } = writeBytes(M, record);
    const rc = M._crabs_wasm_lineage_child_accept_key_transition(this._am, ptr, len);
    if (ptr) M._free(ptr);
    wrapRc(rc, 'lineageAcceptKeyTransition');
  }

  // Parse a parent-issued attestation wire image (as produced by attest)
  // into the field shape Operation.addAttestation consumes with NO verdict
  // — parse-only (attestation_deserialize, lineage.h:666): verification
  // happens at op attach/execution, where the executor re-checks the
  // chain-TIP signature, both ids, the window, and attribute coverage.
  // Malformed input refuses typed (never a partial parse).
  attestationFromWire(bytes) {
    const M = this._M;
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      throw new Error('attestationFromWire: expected the attestation wire bytes (Uint8Array)');
    }
    const { ptr, len } = writeBytes(M, bytes);
    const attPtr = M._crabs_wasm_attestation_parse(ptr, len);
    if (ptr) M._free(ptr);
    if (!attPtr) {
      throw new Error('attestationFromWire: malformed attestation wire image (structure check failed)');
    }
    const fields = {
      parentId: readString(M, M._crabs_wasm_attestation_parent_id(attPtr)),
      childId: readString(M, M._crabs_wasm_attestation_child_id(attPtr)),
      userId: readString(M, M._crabs_wasm_attestation_user_id(attPtr)),
      attributes: readString(M, M._crabs_wasm_attestation_attributes(attPtr)),
      notBefore: M._crabs_wasm_attestation_not_before(attPtr),
      expiresAt: M._crabs_wasm_attestation_expires_at(attPtr),
      parentKeyVersion: M._crabs_wasm_attestation_parent_key_version(attPtr),
      signatureHex: hexEncode(M.HEAPU8.subarray(
        M._crabs_wasm_attestation_signature(attPtr),
        M._crabs_wasm_attestation_signature(attPtr) + 64), 64),
    };
    M._crabs_wasm_attestation_free(attPtr);
    return fields;
  }

  // ============================================================
  // Raft ordering module (GROUP_ORDERED writes)
  // ============================================================

  // Attaches a raft ordering module to THIS machine's state and returns the
  // RaftHost that drives it. This is a REFERENCE host: every seam it wires
  // is user-replaceable —
  //   • transport  raftHost.setRaftTransport(fn(peerId, blob)) — drained
  //     raft control blobs go anywhere (WebSocket, HTTP relay, in-memory
  //     queues in tests); incoming blobs come back through
  //     node.raftDeliver(peerId, blob).
  //   • storage    raftHost.setRaftStorage(fn(handle, blob)) — persist
  //     windows are stored anywhere durable (IndexedDB, localStorage, a
  //     server); the reference host acknowledges with persist_complete when
  //     the handler resolves, or marks the window failed when it rejects.
  //   • timer      startRaftHost() runs a setTimeout tick loop at
  //     options.tickMs — hosts that own their own clock can skip it and
  //     drive raftTick(ms)/raftPump(ms)/raftDeliver directly.
  // options: { nodeId, peers, tickMs, timers: { electionMinMs,
  // electionMaxMs, heartbeatMs }, seed, moduleId }. peers counts ALL
  // members including this node (a single-entry list is the degenerate
  // one-node cluster). Throws if a raft module is already attached.
  attachRaft(options = {}) {
    const M = this._M;
    if (this._raftHost && this._raftHost._modulePtr) {
      throw new Error('attachRaft: a raft module is already attached');
    }
    const nodeId = options.nodeId || this.adminId;
    const peers = options.peers || [nodeId];
    if (!Array.isArray(peers) || peers.length === 0 || peers.length > 16) {
      throw new RangeError('attachRaft: peers must be an array of 1..16 ids');
    }
    if (!peers.includes(nodeId)) {
      throw new Error('attachRaft: peers must include this node');
    }
    const timers = options.timers || {};
    this._raftHost = new RaftHost(M, this, nodeId, peers, {
      tickMs: options.tickMs || 100,
      electionMinMs: timers.electionMinMs || 0,
      electionMaxMs: timers.electionMaxMs || 0,
      heartbeatMs: timers.heartbeatMs || 0,
      seed: options.seed || 0,
      moduleId: options.moduleId || 0,
    });
    return this._raftHost;
  }

  // Host delivery seam: inject one inbound raft blob from `peerId`. Runs the
  // inbound event through the module and then drains the module (outbound
  // transport, persist windows, notification materialization), so delivery
  // provokes the same cascade as a timer loop in a single JS entry.
  raftDeliver(peerId, blob) {
    if (!this._raftHost || !this._raftHost._modulePtr) {
      throw new Error('raftDeliver: no raft module attached');
    }
    return this._raftHost.pumpInbound(peerId, blob);
  }

  // Point diagnostics of the attached module (null fields when detached).
  raftStatus() {
    if (!this._raftHost || !this._raftHost._modulePtr) return null;
    return this._raftHost.status();
  }

  destroy() {
    if (this._raftHost) this._raftHost.destroy();
    this._raftHost = null;
    if (this._am) { this._M._crabs_wasm_node_destroy(this._am); this._am = null; }
  }
}

// ============================================================
// Raft reference host
// ============================================================
// The raft module (crabs_raft_module_t) is a pure reactive C core: tick /
// inbound / propose / persist_complete go in, message / persist /
// notification queues come out. RaftHost owns the event loop that turns
// those queues into real I/O. It wraps the transport/storage seams so the
// SAME reference loop works against real transports and against in-memory
// queues in tests.

// Wire envelope decoders for the C polls (little-endian):
//   outbound:    [u32 kind][u16 to-peer len][peer][u32 blob len][blob]
//   notification:[u32 kind][u16 peer len][peer][u64 proposal id][u64 commit
//                 index][u32 op len][op bytes]
//   persist view:[u64 handle][u32 blob len][blob]
function _raftDecodeOutbound(envBytes) {
  const view = new DataView(envBytes.buffer, envBytes.byteOffset,
                            envBytes.byteLength);
  let cursor = 0;
  const kind = view.getUint32(cursor, true); cursor += 4;
  const peerLen = view.getUint16(cursor, true); cursor += 2;
  const to = new TextDecoder().decode(
    envBytes.subarray(cursor, cursor + peerLen)); cursor += peerLen;
  const blobLen = view.getUint32(cursor, true); cursor += 4;
  const blob = envBytes.slice(cursor, cursor + blobLen);
  return { kind, to, blob };
}

function _raftDecodePersist(envBytes) {
  const view = new DataView(envBytes.buffer, envBytes.byteOffset,
                            envBytes.byteLength);
  let cursor = 0;
  const handle = view.getBigUint64(cursor, true); cursor += 8;
  const blobLen = view.getUint32(cursor, true); cursor += 4;
  const blob = envBytes.slice(cursor, cursor + blobLen);
  return { handle, blob };
}

function _raftDecodeNotification(envBytes) {
  const view = new DataView(envBytes.buffer, envBytes.byteOffset,
                            envBytes.byteLength);
  let cursor = 0;
  const kind = view.getUint32(cursor, true); cursor += 4;
  const peerLen = view.getUint16(cursor, true); cursor += 2;
  const peerId = new TextDecoder().decode(
    envBytes.subarray(cursor, cursor + peerLen)); cursor += peerLen;
  const proposalId = view.getBigUint64(cursor, true); cursor += 8;
  const commitIndex = view.getBigUint64(cursor, true); cursor += 8;
  const opLen = view.getUint32(cursor, true); cursor += 4;
  const opBytes = envBytes.slice(cursor, cursor + opLen);
  return { kind, peerId, proposalId: Number(proposalId),
           commitIndex: Number(commitIndex), opBytes };
}

class RaftHost {
  constructor(M, node, nodeId, peers, options) {
    this._M = M;
    this._node = node;
    this._am = node._am;
    // Build the wasm-side char*[] for the peer id list: a malloc'd pointer
    // array whose entries point at heap strings written below.
    this._peerPtrs = peers.map((peerId) => writeString(M, peerId));
    this._peerArrayPtr = M._malloc(peers.length * 4);
    for (let peerIndex = 0; peerIndex < peers.length; peerIndex++) {
      M.setValue(this._peerArrayPtr + peerIndex * 4, this._peerPtrs[peerIndex], 'i32');
    }
    const nodeIdPtr = writeString(M, nodeId);
    this._modulePtr = M._crabs_wasm_raft_create(
      this._am, nodeIdPtr, this._peerArrayPtr, peers.length,
      BigInt(options.electionMinMs), BigInt(options.electionMaxMs),
      BigInt(options.heartbeatMs), BigInt(options.seed), options.moduleId);
    M._free(nodeIdPtr);
    for (const peerPtr of this._peerPtrs) M._free(peerPtr);
    M._free(this._peerArrayPtr);
    if (!this._modulePtr) {
      throw new Error('attachRaft: raft module create failed');
    }
    this.nodeId = nodeId;
    this.peers = peers.slice();
    this._tickMs = options.tickMs;
    this._timer = null;
    this._transport = null;
    this._storage = null;
    this._persistOutstanding = false;
    this._destroyed = false;
  }

  // ---- Seams ----

  // The transport seam replaces the default throw: fn(peerId, blob) ships
  // one drained raft control blob anywhere. Failures are surfaced to the
  // console and retried implicitly by the module's own retransmit-free
  // timer model — the reference host does not queue on the app's behalf.
  setRaftTransport(transportFn) {
    this._transport = transportFn;
  }

  // The storage seam replaces the default throw: fn(handle, blob) stores one
  // persist window; resolution of the returned promise (or thrown rejection)
  // is acknowledged to the module as persist_complete(true/false).
  setRaftStorage(storageFn) {
    this._storage = storageFn;
  }

  // ---- Host loop ----

  // Start the reference setTimeout tick loop (tick → drain cascade).
  startRaftHost() {
    if (this._timer || this._destroyed) return;
    this._timer = setInterval(() => this.onTick(), this._tickMs);
  }

  stopRaftHost() {
    if (this._timer) { clearInterval(this._timer); this._timer = null; }
  }

  // One manual tick at an explicit time — for hosts that own the clock.
  // tickMs defaults to Date.now(). The persist window is pumped FIRST so an
  // acked-but-undrained store resolves before the tick (vote requests ride
  // vote-header durability); the module tolerates ticks while an async
  // store is in flight (window-busy), so heartbeats never stall on storage.
  raftTick(nowMs) {
    if (this._destroyed) throw new Error('RaftHost destroyed');
    const now = BigInt(nowMs === undefined ? Date.now() : nowMs);
    this._pumpPersist();
    this._M._crabs_wasm_raft_tick(this._modulePtr, now);
    this._drainOutbound();
    this._pumpNotifications(now);
  }

  // The loop body: tick, then drain everything the tick produced.
  onTick() {
    try {
      this.raftTick();
    } catch (tickError) {
      console.warn('crabs: raft tick failed', tickError);
    }
  }

  // Inject an inbound blob (the receive half of the transport seam) and
  // drain the cascade it provokes.
  pumpInbound(peerId, blob) {
    if (this._destroyed) throw new Error('RaftHost destroyed');
    const bytes = blob instanceof Uint8Array ? blob : new Uint8Array(blob);
    const { ptr: blobPtr, len } = writeBytes(this._M, bytes);
    const peerPtr = writeString(this._M, peerId);
    const now = BigInt(Date.now());
    const rc = this._M._crabs_wasm_raft_inbound(this._modulePtr, peerPtr,
                                                blobPtr, len, now);
    freeAll(this._M, peerPtr, blobPtr);
    if (rc !== 0) throw crabsError(rc, 'raftDeliver');
    this._drainOutbound();
    this._pumpPersist();
    this._pumpNotifications(now);
  }

  // ---- Drains ----

  // OUTBOUND: poll every queued message and hand it to the transport seam
  // (async fire-and-forget — the module's queue is drained synchronously;
  // delivery itself belongs to the transport's event loop).
  _drainOutbound() {
    if (!this._transport) return;
    for (;;) {
      const envelope = this._M._crabs_wasm_raft_poll_outbound(this._modulePtr);
      if (!envelope) break;
      const data = this._M._crabs_wasm_buffer_data(envelope);
      const len = this._M._crabs_wasm_buffer_len(envelope);
      const message = _raftDecodeOutbound(
        this._M.HEAPU8.subarray(data, data + len));
      this._M._crabs_wasm_buffer_destroy(envelope);
      try {
        const sent = this._transport(message.to, message.blob);
        if (sent && typeof sent.catch === 'function') {
          sent.catch((sendError) =>
            console.warn('crabs: raft transport failed', sendError));
        }
      } catch (sendError) {
        console.warn('crabs: raft transport failed', sendError);
      }
    }
  }

  // PERSIST: one window per call round. The module re-reports an unresolved
  // handle, so this queue is never drain-looped — while an async store is in
  // flight the host simply stops polling it.
  _pumpPersist() {
    if (this._persistOutstanding || !this._storage) return;
    const envelope = this._M._crabs_wasm_raft_poll_persist_request(
      this._modulePtr);
    if (!envelope) return;
    const data = this._M._crabs_wasm_buffer_data(envelope);
    const len = this._M._crabs_wasm_buffer_len(envelope);
    const request = _raftDecodePersist(this._M.HEAPU8.subarray(data, data + len));
    this._M._crabs_wasm_buffer_destroy(envelope);
    this._persistOutstanding = true;
    let storeResult;
    try {
      storeResult = this._storage(request.handle, request.blob);
    } catch (storeError) {
      this._completePersist(request.handle, false, storeError);
      return;
    }
    if (storeResult && typeof storeResult.then === 'function') {
      storeResult.then(
        () => this._completePersist(request.handle, true, null),
        (storeError) => this._completePersist(request.handle, false, storeError));
    } else {
      this._completePersist(request.handle, true, null);
    }
  }

  _completePersist(handle, ok, storageError) {
    this._persistOutstanding = false;
    if (storageError) {
      console.warn('crabs: raft persist failed', storageError);
    }
    wrapRc(this._M._crabs_wasm_raft_persist_complete(this._modulePtr,
                                                     BigInt(handle), ok ? 1 : 0),
           'raftPersistComplete');
    // The ack itself may have produced outbound/persist/notification work.
    this._drainOutbound();
    this._pumpPersist();
    if (!this._persistOutstanding) this._pumpNotifications(Date.now());
  }

  // NOTIFICATIONS (materialization): committed ops go back through the
  // state's pipeline (crabs_wasm_raft_pump → state_raft_process_notifications_at),
  // which executes them, fires 'change' events, and shelves ordered retries.
  _pumpNotifications(nowMs) {
    const rc = this._M._crabs_wasm_raft_pump(this._am, BigInt(nowMs));
    if (rc !== 0 && rc !== 0xA006) {
      console.warn('crabs: raft notification pump failed', crabsError(rc, 'raftPump'));
    }
  }

  // ---- Raw surfaces ----

  // Manual drain of the outbound queue WITHOUT the transport seam — returns
  // [{ kind, to, blob }] for hosts implementing custom replay/inspection.
  raftPollOutbound() {
    const out = [];
    for (;;) {
      const envelope = this._M._crabs_wasm_raft_poll_outbound(this._modulePtr);
      if (!envelope) break;
      const data = this._M._crabs_wasm_buffer_data(envelope);
      const len = this._M._crabs_wasm_buffer_len(envelope);
      const message = _raftDecodeOutbound(
        this._M.HEAPU8.subarray(data, data + len));
      this._M._crabs_wasm_buffer_destroy(envelope);
      out.push(message);
    }
    return out;
  }

  // One outstanding persist window ({ handle, blob } | null) — a VIEW: the
  // handle stays open on the module until raftPersistComplete(handle, ok).
  raftPollPersistRequest() {
    const envelope = this._M._crabs_wasm_raft_poll_persist_request(
      this._modulePtr);
    if (!envelope) return null;
    const data = this._M._crabs_wasm_buffer_data(envelope);
    const len = this._M._crabs_wasm_buffer_len(envelope);
    const request = _raftDecodePersist(this._M.HEAPU8.subarray(data, data + len));
    this._M._crabs_wasm_buffer_destroy(envelope);
    return request;
  }

  // Acknowledge a persist window obtained from raftPollPersistRequest.
  // Unknown/stale handles (double acks) are host bookkeeping bugs and throw.
  raftPersistComplete(handle, ok) {
    wrapRc(this._M._crabs_wasm_raft_persist_complete(this._modulePtr,
                                                    BigInt(handle), ok ? 1 : 0),
           'raftPersistComplete');
  }

  // Crash recovery: replay one stored persist batch into the module's
  // durable state — the host's persist-batch record (crabs_wasm_raft_poll_persist_request
  // bytes kept by the storage seam) is the durable raft history that
  // survives a module/host restart whose machine blob is stale (restored
  // from a pre-commit snapshot: empty election record, empty log). Batches
  // replay in arrival order; corrupt or contradictory batches fail closed
  // (crabsError — the C contract in Raft/raft_module.c).
  raftRecoverFromPersist(batch) {
    if (this._destroyed) throw new Error('RaftHost destroyed');
    const bytes = batch instanceof Uint8Array ? batch : new Uint8Array(batch);
    const { ptr, len } = writeBytes(this._M, bytes);
    const rc = this._M._crabs_wasm_raft_recover_from_persist(
      this._modulePtr, ptr, len);
    freeAll(this._M, ptr);
    wrapRc(rc, 'raftRecoverFromPersist');
  }

  // Raw notification drain — NOT for state-attached reference hosts (use
  // raftPump; the pump consumes this queue itself and double-draining here
  // would silently drop committed ops). Returns
  // [{ kind, peerId, proposalId, commitIndex, opBytes: Uint8Array }].
  raftPollNotifications() {
    const out = [];
    for (;;) {
      const envelope = this._M._crabs_wasm_raft_poll_notification(
        this._modulePtr);
      if (!envelope) break;
      const data = this._M._crabs_wasm_buffer_data(envelope);
      const len = this._M._crabs_wasm_buffer_len(envelope);
      const notification = _raftDecodeNotification(
        this._M.HEAPU8.subarray(data, data + len));
      this._M._crabs_wasm_buffer_destroy(envelope);
      out.push(notification);
    }
    return out;
  }

  // Materialize committed ops through the attached machine's pipeline at an
  // explicit time (manual mode). rc 0 = clean; a thrown/shelving pump failure
  // is surfaced to the caller.
  raftPump(nowMs) {
    wrapRc(this._M._crabs_wasm_raft_pump(this._am,
      BigInt(nowMs === undefined ? Date.now() : nowMs)), 'raftPump');
  }

  // Direct module handle — raw-propose / membership-change exports for
  // hosts bypassing the state pipeline. Returns the crabs_raft_module_t
  // pointer; treat it as borrowed (lifetime anchored by the host object).
  moduleHandle() {
    return this._modulePtr;
  }

  // Joint-consensus membership change (Raft §6, parity-fill P9): the leader
  // appends the C_old,new joint entry to the module's OWN config log; when
  // committed the module auto-appends the C_new successor, and that entry's
  // commit ends the transition (raft_module.h:216). Returns the assigned
  // proposal_id (the config entry's log index); every refusal throws —
  // ordering_not_leader (leader-only), ordering_change_in_flight (ONE change
  // at a time: an appended-but-uncommitted config entry or an active joint
  // phase blocks), invalid_param (1..16 non-empty member ids).
  changeMembership(members) {
    if (this._destroyed) throw new Error('RaftHost destroyed');
    if (!Array.isArray(members) ||
        members.some((id) => typeof id !== 'string' || id.length === 0)) {
      throw new TypeError(
        'changeMembership: members must be an array of non-empty id strings');
    }
    if (members.length === 0 || members.length > 16) {
      throw new RangeError('changeMembership: members must have 1..16 ids');
    }
    const M = this._M;
    // char*[] like the constructor's peer list (all ids are heap strings).
    const memberPtrs = members.map((memberId) => writeString(M, memberId));
    const memberArrayPtr = M._malloc(memberPtrs.length * 4);
    for (let memberIndex = 0; memberIndex < memberPtrs.length; memberIndex++) {
      M.setValue(memberArrayPtr + memberIndex * 4, memberPtrs[memberIndex],
                 'i32');
    }
    const outProposalPtr = M._malloc(8);
    const rc = M._crabs_wasm_raft_change_membership(
      this._modulePtr, memberArrayPtr, memberPtrs.length, outProposalPtr);
    const proposalId = Number(M.getValue(outProposalPtr, 'i64'));
    freeAll(M, memberArrayPtr, outProposalPtr);
    for (const memberPtr of memberPtrs) M._free(memberPtr);
    wrapRc(rc, 'changeMembership');
    // The appended entry produces persist + fan-out work immediately — move
    // it without waiting for the next tick (mirrors pumpInbound's cascade).
    this._drainOutbound();
    this._pumpPersist();
    return proposalId;
  }

  // Membership reads (C config order, not sorted): the ACTIVE committed
  // config (the election/voting list) and the SECOND list of an active
  // joint consensus — empty while the cluster runs a plain single consensus
  // (visible between the joint entry's commit and the C_new successor's).
  _parseMemberList(envelope) {
    const M = this._M;
    const out = [];
    if (envelope) {
      const dataPtr = M._crabs_wasm_buffer_data(envelope);
      const len = M._crabs_wasm_buffer_len(envelope);
      const bytes = M.HEAPU8.subarray(dataPtr, dataPtr + len);
      const view = new DataView(bytes.buffer, bytes.byteOffset,
                                bytes.byteLength);
      const count = view.getUint32(0, true);
      let cursor = 4;
      for (let index = 0; index < count; index++) {
        const idLen = view.getUint16(cursor, true); cursor += 2;
        out.push(new TextDecoder().decode(
          bytes.subarray(cursor, cursor + idLen)));
        cursor += idLen;
      }
      M._crabs_wasm_buffer_destroy(envelope);
    }
    return out;
  }

  jointMembers() {
    if (this._destroyed) throw new Error('RaftHost destroyed');
    return this._parseMemberList(
      this._M._crabs_wasm_raft_joint_members(this._modulePtr));
  }

  committedMembers() {
    if (this._destroyed) throw new Error('RaftHost destroyed');
    return this._parseMemberList(
      this._M._crabs_wasm_raft_committed_members(this._modulePtr));
  }

  status() {
    const M = this._M;
    // The committed-config member list arrives as [u32 count][entries…];
    // diagnostics only need the count, so the list body is skipped.
    const committed = M._crabs_wasm_raft_committed_members(this._modulePtr);
    let peerCount = 0;
    if (committed) {
      const dataPtr = M._crabs_wasm_buffer_data(committed);
      peerCount = M.getValue(dataPtr, 'i32') >>> 0;
      M._crabs_wasm_buffer_destroy(committed);
    }
    return {
      nodeId: this.nodeId,
      isLeader: M._crabs_wasm_raft_is_leader(this._modulePtr) !== 0,
      term: Number(M._crabs_wasm_raft_current_term(this._modulePtr)),
      commitTip: Number(M._crabs_wasm_raft_committed_tip(this._modulePtr)),
      logLength: Number(M._crabs_wasm_raft_log_length(this._modulePtr)),
      configChangePending:
        M._crabs_wasm_raft_config_change_pending(this._modulePtr) !== 0,
      peerCount,
    };
  }

  destroy() {
    if (this._destroyed) return;
    this._destroyed = true;
    this.stopRaftHost();
    if (this._modulePtr) {
      this._M._crabs_wasm_raft_destroy(this._modulePtr);
      this._modulePtr = null;
    }
  }
}

// ============================================================
// Module exports
// ============================================================

  return { Node, KeyPair, Operation, Blueprint, TRUST_MODE, DATA_TYPE, CRDT_TYPE, WRITE_DOMAIN, getModule, wireVersions };
}

// UMD: CommonJS for Node/bundlers; window.CRABSWasmCore for plain <script>
// use (the static demo page builds bindings from window.createCRABSModuleDev
// via window.CRABSWasmCore(loader)).
if (typeof module === 'object' && module.exports) {
  module.exports = createBindings;
} else if (typeof window !== 'undefined') {
  window.CRABSWasmCore = createBindings;
}
