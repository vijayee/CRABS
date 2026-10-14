// TypeScript definitions for crabs-wasm

/**
 * One parent-signed attestation, field-wise — the canonical attestation body
 * (attestation_t, src/Lineage/lineage.h) parsed out of attest's wire image,
 * ready for Operation.addAttestation. Signature carries the parent's ECDSA
 * over the body; the chain-TIP version stamp rides in parentKeyVersion.
 */
export interface AttestationFields {
  parentId: string;
  childId: string;
  userId: string;
  /** Comma-separated name:value pairs; an endorsement resolves when the
   *  list CONTAINS the token exactly. */
  attributes: string;
  /** Epoch ms; 0 = no lower fence (integer or BigInt). */
  notBefore?: number | bigint;
  /** Epoch ms; 0 is a legal (instant-then-expired) window. */
  expiresAt?: number | bigint;
  /** The chain TIP version the parent stamped (required — tip-only verify). */
  parentKeyVersion: number | bigint;
  /** 128 hex chars (64 bytes = CRABS_SIG_SIZE). */
  signatureHex: string;
}

export interface CrabsChangeEvent {
  kind: 'op' | 'schedule' | 'trigger' | 'attribute' | 'spawn' | 'lineage' | 'merge';
  type: string;
  uuid: string;
  signer: string;
  node: string;
  target: string | null;
  preview: string;
  result: number;  // crabs_error_e
}

/** Machine-issued hybrid timestamp (readback shape of getHLC — the native
 *  binding's HLC view minus its formatted/nodeId fields). */
export interface CrabsHLC {
  seconds: number;
  nanos: number;
  logicalCounter: number;
}

export interface KeyPair {
  publicKeyHex(): string;
  privateKeyHex(): string;
  destroy(): void;
}

export namespace KeyPair {
  function generate(): Promise<KeyPair>;
  function fromPrivateHex(hex: string): Promise<KeyPair>;
  function derivePublicHex(hex: string): Promise<string>;
}

/**
 * A machine-derived CP-ABE reader key (gap-fill A11 + parity-fill P4):
 * abeKeygen derives it from the machine's OWN master authority, so JS never
 * touches the master secret — the machine mints it, JS holds only the
 * derived key. JS owns the pointer: destroy() it (idempotent, like KeyPair's
 * destroy). Portable bytes exist through toWire() (parity-fill P4): a
 * SELF-SUFFICIENT BEARER image of the key (crypto_abe_user_key_serialize) —
 * it carries its own minting domain, restores on any machine via
 * Node.abeKeyFromWire (the restored key opens exactly what its minting
 * authority sealed, wherever it was restored), and has NO integrity check —
 * carry it over an authenticated channel, or move keys with the key
 * envelope flow (Node.mintKeyEnvelope / Node.decryptKeyEnvelope) instead.
 */
export interface AbeKey {
  /**
   * Portable reader-key wire image (crypto_abe_user_key_serialize). The
   * bytes ARE the key — treat the return like a bearer token. Refuses on a
   * destroyed key.
   */
  toWire(): Uint8Array;
  destroy(): void;
}

export interface Operation {
  type: string;
  signerId: string;
  nodeId: string;
  payload: Uint8Array | string | undefined;
  serialize(): Uint8Array;
  /** Append a resource name to the op (capacity 8). Chainable. */
  addResource(name: string): this;
  /**
   * Write-domains v1: set the sovereign chain prefix (item_seq + prev
   * digest as 64 hex chars or 32 raw bytes) at prefixIndex — parallel to
   * the op's sovereign resources in declaration order. Set BEFORE signing;
   * the signature (format v4) binds the prefixes. Chainable.
   */
  setSovereignPrefix(prefixIndex: number, seq: number | bigint,
                     digest: string | Uint8Array): this;
  /**
   * Recipe 9 (lock protocol): set the per-slot required_state at slotIndex —
   * the executor refuses the op with protocol_violation unless every named
   * resource is in exactly that state before anything moves.
   * Slots are created 'idle' by addResource. Signed (format v4) — set
   * BEFORE signing. Chainable.
   */
  setRequiredState(slotIndex: number, state: ProtocolStateWord): this;
  /** The per-slot next_state (the state the driver says the op leaves the
   * resource in). Signed — set BEFORE signing. Chainable. */
  setNextState(slotIndex: number, state: ProtocolStateWord): this;
  /**
   * Recipe 9 (lock protocol): append one lock claim — the resource name plus
   * the 32-byte bearer token the op claims to hold (getLockState's
   * lockTokenHex). The executor verifies presented claims against the item's
   * live lock token; a forged claim is refused lock_token_mismatch BEFORE
   * any effect. tokenHex: 64 hex chars. Signed — set BEFORE signing.
   * Chainable.
   */
  addLockClaim(resource: string, tokenHex: string): this;
  /**
   * Recipe 12 (attestation bridge): attach one parent-signed attestation to
   * the op — the credential an executor `@parent/` endorsement policy
   * resolves against (_verify_parent_endorsements, src/StateMachine/
   * state_machine.c). Parse the fields out of attest's wire image
   * (canonical body: format_version + string16 parent/child/user/attributes
   * + u64le not_before/expires_at/parent_key_version + 64-byte signature).
   * The executor re-verifies everything during authorization (chain TIP,
   * ids, window, exact coverage) — every bad field fails closed
   * ('unauthorized'). signatureHex must be 128 hex chars
   * (64 bytes = CRABS_SIG_SIZE) or the attach refuses loudly. Attestations
   * ride the op WIRE (format v5+) but are NOT part of the canonical signing
   * form. Set BEFORE signing. Chainable.
   */
  addAttestation(attestation: AttestationFields): this;
  /**
   * Op format version this op carries. Fresh ops report the build's
   * wireVersions.op; deserialized ops report the version declared on the
   * wire.
   */
  getWireVersion(): number;
  destroy(): void;
}

export namespace Operation {
  function create(type: string): Promise<Operation>;
  function deserialize(bytes: Uint8Array): Promise<Operation>;
}

// Trust modes for spawned child machines (v1.7 lineage wire values).
export const TRUST_MODE: {
  SHARED_ROOT: number;       // 0x01
  DELEGATED_COPY: number;    // 0x02
  SOVEREIGN: number;         // 0x03
};
// Data item / CRDT strategy numbers for Blueprint.addItem.
export const DATA_TYPE: Record<string, number>;
export const CRDT_TYPE: Record<string, number>;

export interface Blueprint {
  /** Append a replicated data item to the child's definition. */
  addItem(name: string, dataType: number, crdtType: number): void;
  /** Append an authorization policy: operation type + condition expression. */
  addPolicy(operation: string, expression: string): void;
  /** Recompute the blueprint's SHA-256 over its canonical body. */
  stampHash(): void;
  /** Wire image (u32le length + canonical body + 32-byte hash). */
  serialize(): Uint8Array;
  destroy(): void;
}

export namespace Blueprint {
  function create(childId: string, trustMode: number,
                  bootstrapAdmin: string, ttlMs: number): Promise<Blueprint>;
  function deserialize(bytes: Uint8Array): Promise<Blueprint>;
}

export interface ChildManifestView {
  childId: string;
  /** Human name, e.g. "delegated_copy". */
  mode: string;
  /** Human name, e.g. "active". */
  status: string;
  ttlMs: number;
  spawnedAt: number;
}

/** Pagination options for getSetElements (Node and HandlerState). */
export interface GetSetElementsOptions {
  /** 0-based start index into the sorted distinct-element list. Default 0. */
  offset?: number;
  /** Page size, integer in [1, 256]. Default 256. Anything larger throws. */
  limit?: number;
}

/** An OT op identity: (node, seq) is the dedup key, ts the issuing stamp. */
export interface OrderedSetOpId {
  /** Issuing replica's id (max 63 bytes). */
  node: string;
  /** Per-replica sequence number (integer >= 0). */
  seq: number;
  /** Issuing ms stamp. Optional, defaults to 0. */
  ts?: number;
}

/** Options for orderedInsert/orderedDelete/orderedMove/orderedSwap. */
export interface OrderedSetApplyOptions {
  /** Required — the op's OT identity (see Node's ordered* docs). */
  id: OrderedSetOpId;
  /**
   * Optional causal context (max 16), i.e. the op ids the issuing replica
   * had already seen when it issued this op. Required for cross-replica
   * replays; omit for locally-issued ops.
   */
  deps?: OrderedSetOpId[];
}

export interface HandlerState {
  incrementCounter(name: string, delta?: number, nodeId?: string): void;
  incrementPNCounter(name: string, delta?: number, nodeId?: string): void;
  decrementPNCounter(name: string, delta?: number, nodeId?: string): void;
  /**
   * Integer-only: a register carries an int64. Numbers must be integers
   * within ±Number.MAX_SAFE_INTEGER; for the full int64 range pass a BigInt.
   * Fractional values are rejected — encode scaled units instead
   * (e.g. store 12.5% as 125 per-mille).
   */
  setRegister(name: string, value: number | bigint, nodeId?: string): void;
  /** Byte-exact inverse of getRegisterBytes — opaque payload storage. */
  setRegisterBytes(name: string, bytes: Uint8Array, nodeId?: string): void;
  setAdd(name: string, element: string, tag?: string): void;
  setRemove(name: string, element: string): void;
  flagSet(name: string, setBy: string, setAt?: number): void;
  getCounter(name: string): number;
  getPNCounter(name: string): number;
  getRegister(name: string): number;
  /**
   * Recipe 9: raw int64 readback of a RESOURCE item's balance — the handler
   * equivalent of Node.getResource. Throws resource_not_found /
   * type_mismatch the same way: on the wasm binding this method throws on
   * failure and never returns undefined.
   */
  getResource(name: string): number;
  /**
   * Recipe 9: the overflow-checked int64 adjustment a debit/credit handler
   * performs (the same find-and-mutate the C handlers do). RESOURCE items
   * only; the machine runs its precondition gates BEFORE the handler.
   */
  adjustResource(name: string, delta: number): void;
  /** Raw bytes of an LWW register; empty register → empty Uint8Array. */
  getRegisterBytes(name: string): Uint8Array;
  setContains(name: string, element: string): boolean;
  /**
   * Distinct visible element count (alive after tombstones, deduped at the
   * element level). Pair with getSetElements for pagination math.
   */
  getSetSize(name: string): number;
  /**
   * Bounded enumerator: returns a page of DISTINCT LIVE elements sorted
   * ascending by byte-wise strcmp (OR-set insertion order is not stable
   * across replicas; the sort is). Hard cap 256 per call — larger limit
   * throws; use getSetSize + successive offsets to paginate bigger sets.
   * Each call is an independent point-in-time snapshot, not a cursor — if
   * elements are added/removed between page calls, offsets shift (re-read
   * getSetSize when paginating a set that may be changing).
   */
  getSetElements(name: string, options?: GetSetElementsOptions): string[];
  /** LIVE tags of `element` of an OR-set (sorted ascending). */
  getSetTags(name: string, element: string): string[];
}

/** Protocol state words (protocol_state_e, src/CRABS/data_model.h:58-65). */
export type ProtocolStateWord = 'idle' | 'locked' | 'modified' | 'verified' | 'error';

/**
 * Live lock state of a RESOURCE item (data_item_t.lock_state_t — runtime
 * only, never serialized). lockTokenHex is the 32-byte CSPRNG bearer token
 * the executor minted at __lock__ (lockTokenHex '' when the item carries no
 * valid token): claim it into the next op's addLockClaim BEFORE signing —
 * the signature binds the claims.
 */
export interface LockStateView {
  protocolState: ProtocolStateWord;
  lockOwner: string;
  lockTokenHex: string;
  /** Expiry in epoch ms (0 = the item is IDLE / un-locked). */
  lockExpiry: number;
  /** Number of __extend__ extensions granted this lease. */
  lockExtensions: number;
}

export interface HandlerOperation {
  type: string;
  signerId: string;
  nodeId: string;
  payload: string | undefined;
  /** The op's declared resource names, in order (what the handler mutates). */
  resources: string[];
}

export interface UserInfo {
  userId: string;
  publicKeyHex: string;
  keyVersion: number;
  status: 'active' | 'suspended' | 'revoked' | 'unknown';
  attributes: Array<{
    value: string;
    verifiedBy: string;
    temporary: boolean;
    expiresAt?: number;
  }>;
}

export interface NodeKey {
  publicKeyHex: string;
  privateKeyHex: string;
}

/**
 * One keyring entry (a C `user_key_t`, attribute_machine.h:62-76) mirrored
 * from the user's linked key list — index 0 is the MOST RECENTLY registered
 * key (list-prepend order inside user_key_register).
 */
export interface UserKeyInfo {
  keyId: string;
  /** sig_scheme.h id (1 = ECDSA_SECP256K1). */
  schemeId: number;
  /** key_status_e word (attribute_machine.h:48-53). */
  status: 'active' | 'suspended' | 'revoked' | 'expired' | 'unknown';
  /** '' when the key was registered without a label. */
  label: string;
  /** '' unless the key was minted by rotateKey. */
  predecessorKeyId: string;
  /** The key's declared public bytes, hex. */
  publicKeyHex: string;
}

/**
 * Keyring rotation material (parity-fill P2). Shape follows the C rotate
 * signature exactly (user_key_rotate — attribute_machine.h:221): (old, new,
 * scheme, pk bytes, label). Nothing is auto-generated — the caller owns the
 * new key material; the old key is left in the state it had (it must be
 * ACTIVE) and reads back 'revoked' after the rotation.
 */
export interface RotateKeyOptions {
  /** sig_scheme.h word or raw id; defaults to 'ecdsa_secp256k1'. */
  scheme?: string | number;
  /** REQUIRED — the new key's public bytes, hex (even-length, ≤ 512 bytes). */
  publicKeyHex: string;
  label?: string;
}

export interface TriggerConfig {
  triggerId: string;
  condition: string;
  description?: string;
  effectType: 'issue_attribute' | 'create_trigger' | 'delete_trigger' | 'disable_trigger' | 'change_policy';
  issueAttribute?: string;
  targetRole?: string;
  attributeValue?: string;
  durationMs?: number;
  oneShot?: boolean;
  cooldownMs?: number;
}

/** Write-domains v1 item options for Node.defineItem. */
export interface DefineItemOptions {
  /** Write domain declared at mint; immutable on a live item in v1. */
  domain?: 'free' | 'sovereign' | 'group';
  /** Required for 'sovereign': the item's single-writer user id. */
  writer?: string;
  /** 'group' only; must match the moduleId of the attached raft module. */
  orderingModule?: number;
}

/**
 * Options for Node.defineOperationType — a machine-enforced DedupSpec
 * registered for a user-defined operation type (v1.4 §7). The executor
 * resolves the spec for every later op of that type; a registered spec wins
 * over anything the op carries on the wire.
 */
export interface DefineOperationTypeOptions {
  /**
   * 'per-user': one op per signer, tracked in the ONE_SHOT_SET item named
   * by trackerPath (created with addOneShotSet; the executor validates the
   * tracker exists before any handler runs).
   * 'global': the op can execute once, ever — the ONE_SHOT_FLAG item named
   * by flagPath (created with addOneShotFlag) is set by the first run and
   * refuses every later run.
   * 'none': removes a previously defined guard for the type (the registry
   * entry is replaced in place) and seals it against op-carried specs.
   */
  dedup: 'per-user' | 'global' | 'none';
  /** 'per-user' only: the ONE_SHOT_SET once-record item name. */
  trackerPath?: string;
  /** 'global' only: the ONE_SHOT_FLAG once-record item name. */
  flagPath?: string;
  /**
   * Stored metadata on the spec (serialized with it, surfaced by tooling).
   * The refusal itself always surfaces as the machine's dedup domain error
   * ('already_performed' for per-user, 'already_executed' for global).
   */
  rejectionMessage?: string;
}

export interface NodeOptions {
  ordering?: 'hlc' | 'lamport';
  strategy?: 'naive' | 'bounded' | 'quorum' | 'strict' | 'trusted';
}

export interface TimeSourceOptions {
  /** 'https' attaches the authenticated HTTPS time source; 'system' detaches (local clock). */
  mode: 'https' | 'system';
  /** https:// endpoint (max 255 UTF-8 bytes). Omit for the default endpoint. */
  url?: string;
  /** Omitted numbers use the documented defaults (30000/1000/5000); 0 is a real override. */
  resyncMs?: number;
  timeoutMs?: number;
  maxSkewMs?: number;
}

export type TimeSourceInfo =
  | { mode: 'system' }
  | { mode: 'https'; url: string | null; resyncMs: number;
      timeoutMs: number; maxSkewMs: number; created: boolean };

// ============================================================
// Raft ordering module — reference host types
// ============================================================
// The raft module orders GROUP_ORDERED writes through a two-phase
// pipeline (submit → pending → committed → materialized). Hosts drive the
// module through the reference RaftHost; its transport/storage/timer seams
// are user-replaceable.

export interface RaftHostOptions {
  /** Own identity among peers (defaults to adminId). */
  nodeId?: string;
  /** ALL cluster members including this node; 1..16 entries. */
  peers?: string[];
  /** Reference setTimeout tick interval in ms (default 100). */
  tickMs?: number;
  /** Module timer knobs; 0/undefined uses the C defaults (1500/3000/500). */
  timers?: { electionMinMs?: number; electionMaxMs?: number;
             heartbeatMs?: number };
  /** Deterministic seed for randomized election-timeout deadlines. */
  seed?: number;
  /** Per-machine ordering-module id (v16 state section). Default 0. */
  moduleId?: number;
}

/** Point diagnostics of the attached raft module. */
export interface RaftStatus {
  nodeId: string;
  isLeader: boolean;
  term: number;
  commitTip: number;
  logLength: number;
  configChangePending: boolean;
  peerCount: number;
}

/** One drained raft control blob (opaque — the host never parses it). */
export interface RaftOutboundMessage {
  /** Wire kind (RAFT_MSG_* numbers). */
  kind: number;
  to: string;
  blob: Uint8Array;
}

/** One reported persist window — a VIEW: unresolved until acknowledged. */
export interface RaftPersistRequest {
  handle: bigint;
  blob: Uint8Array;
}

/** Raw notification (hosts bypassing the state pipeline only). */
export interface RaftNotification {
  kind: number;
  peerId: string;
  proposalId: number;
  commitIndex: number;
  opBytes: Uint8Array;
}

export interface RaftHost {
  /**
   * The transport seam: drained control blobs go anywhere (WebSocket,
   * relay, in-memory queues). Incoming blobs return through
   * Node.raftDeliver(peerId, blob). Replaces the default throw (a host
   * with no transport simply queues undelivered messages).
   */
  setRaftTransport(fn?: (peerId: string, blob: Uint8Array) => void |
                       Promise<void>): void;
  /**
   * The storage seam: persist windows are stored anywhere durable
   * (IndexedDB, localStorage, a server). Resolving the returned promise
   * acknowledges the window (persist_complete true); rejecting marks it
   * failed. While a async store is in flight the host stops polling the
   * persist queue (the module re-reports an unresolved handle).
   */
  setRaftStorage(fn?: (handle: bigint, blob: Uint8Array) => void |
                     Promise<void>): void;
  /** Start / stop the reference setTimeout tick loop (options.tickMs). */
  startRaftHost(): void;
  stopRaftHost(): void;
  /** Manual tick at an explicit time (Date.now() when omitted). */
  raftTick(nowMs?: number): void;
  /** Manual materialization pump at an explicit time. */
  raftPump(nowMs?: number): void;
  /** Manual outbound drain WITHOUT the transport seam. */
  raftPollOutbound(): RaftOutboundMessage[];
  /** Report (does not consume) the outstanding persist window. */
  raftPollPersistRequest(): RaftPersistRequest | null;
  /** Acknowledge a window from raftPollPersistRequest. */
  raftPersistComplete(handle: bigint, ok: boolean): void;
  /**
   * Crash recovery: replay one stored persist batch into the module's
   * durable state — the host's batch record (the storage seam's kept
   * persist bytes) is the durable raft history that survives a module/host
   * restart whose machine blob is stale. Batches replay in arrival order;
   * corrupt or contradictory batches fail closed (crabsError).
   */
  raftRecoverFromPersist(batch: Uint8Array): void;
  /**
   * Raw notification drain — for hosts driving the module WITHOUT the
   * state pipeline ONLY. State-attached hosts use raftPump (the pump
   * consumes this queue itself; double-draining drops committed ops).
   */
  raftPollNotifications(): RaftNotification[];
  /** Borrowed crabs_raft_module_t pointer (raw-propose / membership). */
  moduleHandle(): number;
  status(): RaftStatus;
  destroy(): void;
}

export interface Node {
  getNodeKey(): NodeKey;
  registerUser(userId: string, publicKeyHex: string, initialAttrs?: string): void;
  grantRole(targetUser: string, role: string, value: string, signerId: string): void;
  revokeUser(userId: string, signerId?: string): void;
  /**
   * Admin demotion (parity-fill P3): strip ONE role attribute (attribute
   * NAME match, no value — the C signature is (targetUser, role, signer)).
   * Works on suspended/REVOKED targets by design (audit R4-4 — the
   * decommission path); ADMIN-GATED: the signer must be an ACTIVE user
   * holding role:admin (unauthorized / user_suspended refusals otherwise).
   * signerId defaults to the node's bootstrap admin id (the revokeUser
   * convention). Bumps the target's keyVersion readback.
   */
  revokeRole(targetUser: string, role: string, signerId?: string): void;
  /**
   * Suspend a user (parity-fill P3, admin-gated). Recoverable — a REVOKED
   * user refuses (revocation is terminal, audit R8-C-4); bumps the user's
   * keyVersion (the suspension kills the stamps made before it) and the
   * suspended signer fails every authorization gate after it.
   */
  suspendUser(userId: string, signerId?: string): void;
  /**
   * Reactivate a SUSPENDED user (parity-fill P3, admin-gated) — the
   * key-compromise recovery path. ACTIVE/REVOKED targets refuse
   * (invalid_param: revocation is terminal). Bumps keyVersion again
   * (R8-A-5), so ops stamped pre-suspension replay into key_stale.
   */
  activateUser(userId: string, signerId?: string): void;
  // Keyring-direct helpers carry NO signer gate and emit NO change event
  // (only user key_version moves) — unlike the __suspend_key__ wire ops, they
  // leave no op-log trail; replicas observe the change only via state sync.
  suspendKey(userId: string, keyId: string): void;
  activateKey(userId: string, keyId: string): void;
  rotateKey(userId: string, oldKeyId: string, newKeyId: string, opts: RotateKeyOptions): void;
  listKeys(userId: string): UserKeyInfo[];
  getDefaultKey(userId: string): string;
  /** Subscribe to state-change events ('change' only). Returns an
   *  unsubscribe function that removes the listener again. */
  on(eventName: 'change', listener: (event: CrabsChangeEvent) => void): () => void;
  /** Remove a previously registered 'change' listener. */
  off(eventName: 'change', listener: (event: CrabsChangeEvent) => void): void;
  getUser(userId: string): UserInfo | undefined;

  addCounter(name: string): void;
  addPNCounter(name: string): void;
  addORSet(name: string): void;
  addOneShotSet(name: string): void;
  addOneShotFlag(name: string): void;
  addRegister(name: string, initialValue?: number): void;
  /**
   * Recipe 9: mint a lock-capable RESOURCE item ("PN-Counter + lock"). The
   * value is a raw int64 balance (the lock snapshot and destroy take the raw
   * path for RESOURCE); `initial` seeds it. Pair with getLockState /
   * Operation.setRequiredState + addLockClaim to drive the lock ceremony.
   */
  addResource(name: string, initial?: number): void;
  /**
   * Raw int64 readback of the RESOURCE balance. Throws resource_not_found
   * for an unknown name, type_mismatch for a non-RESOURCE item. Balances
   * beyond ±2^53 lose precision through Number (pass such ledger sizes
   * through the handler surface / C core instead).
   */
  getResource(name: string): number;
  /**
   * Recipe 9: LIVE lock state of a RESOURCE item — the driver reads the
   * bearer token here and claims it into the next op's addLockClaim BEFORE
   * signing. Throws resource_not_found for an unknown name and
   * type_mismatch for a non-RESOURCE item (only RESOURCE has protocol
   * state). Lock state is runtime only — never serialized.
   */
  getLockState(name: string): LockStateView;
  /**
   * Recipe 9: attach a replay-protection manager to this machine's state
   * (src/TxManager/tx_manager.h). 'memory' records committed op uuids — the
   * executor's step 3b refuses a duplicate submission with
   * already_executed; 'none' is the accept-everything hook
   * (crabs_tx_manager_none). With NO manager attached, the ordering-
   * monotonicity backstop still rejects a replayed op. Runtime only —
   * never serialized; attach again after a state round trip. Replacing an
   * attached manager destroys the previous one.
   */
  attachTxManager(kind: 'memory' | 'none'): void;

  /**
   * Write-domains v1: item creation with an explicit write-domain
   * declaration. v1 supports 'counter'/'register' (or the DATA_TYPE
   * numbers); other shapes keep their dedicated add* methods.
   */
  defineItem(name: string, dataType: string | number,
             crdtType: string | number, options?: DefineItemOptions): void;
  /**
   * Write-domains v1: the live chain head of a SOVEREIGN item — what the
   * writer's next op must claim in its signed prefix. digestHex is the
   * FULL 32-byte digest as 64 hex chars (the devtools snapshot's
   * item_digest_head is only the first 8 bytes). Throws resource_not_found
   * for an unknown item.
   */
  itemChainHead(name: string): { seq: number; digestHex: string };
  /**
   * Write-domains v1: file a __report_equivocation__ op against the
   * SOVEREIGN item `itemName`, carrying two serialized writer ops as the
   * evidence pair. Signed by this node's admin with the node key; failures
   * throw typed crabs errors and set nothing.
   */
  reportEquivocation(itemName: string, opABytes: Uint8Array,
                     opBBytes: Uint8Array): void;

  getCounter(name: string): number;
  getPNCounter(name: string): number;
  getRegister(name: string): number;
  /**
   * Integer-only: a register carries an int64. Numbers must be integers
   * within ±Number.MAX_SAFE_INTEGER; for the full int64 range pass a BigInt.
   * Fractional values are rejected — encode scaled units instead
   * (e.g. store 12.5% as 125 per-mille).
   */
  setRegister(name: string, value: number | bigint, nodeId?: string): void;
  setRegisterBytes(name: string, bytes: Uint8Array, nodeId?: string): void;
  /** Raw bytes of an LWW register; empty register → empty Uint8Array. */
  getRegisterBytes(name: string): Uint8Array;
  setContains(name: string, element: string): boolean;
  /**
   * Distinct visible element count (alive after tombstones, deduped at the
   * element level). Pair with getSetElements for pagination math.
   */
  getSetSize(name: string): number;
  /**
   * Bounded enumerator: returns a page of DISTINCT LIVE elements sorted
   * ascending by byte-wise strcmp (OR-set insertion order is not stable
   * across replicas; the sort is). Hard cap 256 per call — larger limit
   * throws; use getSetSize + successive offsets to paginate bigger sets.
   * Each call is an independent point-in-time snapshot, not a cursor — if
   * elements are added/removed between page calls, offsets shift (re-read
   * getSetSize when paginating a set that may be changing).
   */
  getSetElements(name: string, options?: GetSetElementsOptions): string[];
  /** LIVE tags of `element` of an OR-set (sorted ascending). */
  getSetTags(name: string, element: string): string[];

  incrementCounter(name: string, delta?: number, nodeId?: string): void;
  incrementPNCounter(name: string, delta?: number, nodeId?: string): void;
  decrementPNCounter(name: string, delta?: number, nodeId?: string): void;

  setAdd(name: string, element: string, tag?: string): void;
  setRemove(name: string, element: string): void;
  flagSet(name: string, setBy: string, setAt?: number): void;
  flagValue(name: string): boolean;

  // ============================================================
  // Ordered set (OT_ORDERED_SET, v1.5 §5 — recipe 8)
  // ============================================================
  /**
   * Create an OT ordered-set item (data type 0x10) on this machine.
   * The item carries its own op log + transform matrix; apply ops with
   * orderedInsert/orderedDelete/orderedMove/orderedSwap, read it back with
   * getOrderedSet.
   */
  addOrderedSet(name: string): void;
  /**
   * Visible elements of the ordered set in materialized order (tombstones
   * skipped), each element's payload value decoded as UTF-8. Throws
   * resource_not_found for an unknown or non-ordered-set name.
   */
  getOrderedSet(name: string): { elements: string[] };
  /**
   * Apply ONE ordered-set op through the machine executor, signed with the
   * node key under the bootstrap admin (the createTrigger idiom — install
   * the op type's policy first:
   * setPolicy('__execute_ot__', 'role:admin')).
   *
   * options.id is required: { node, seq, ts? } is the op's OT identity —
   * replaying the SAME id (and the same payload/position) is a silent no-op.
   * options.deps (optional, max 16) is the causal context the ISSUER had at
   * issue time; cross-replica replays need it or the transform treats the
   * replica's prior ops as concurrent and shifts positions.
   */
  orderedInsert(name: string, element: string, position: number,
                options: OrderedSetApplyOptions): void;
  /** Tombstone the element at `position` (deletes travel like any other op). */
  orderedDelete(name: string, position: number,
                options: OrderedSetApplyOptions): void;
  /** Move the element at `fromPosition` to `toPosition`. */
  orderedMove(name: string, fromPosition: number, toPosition: number,
              options: OrderedSetApplyOptions): void;
  /**
   * Exchange the VALUES of the two positions' elements in place — a local
   * value exchange, not a placement op (recipe 8's caveat).
   */
  orderedSwap(name: string, positionA: number, positionB: number,
              options: OrderedSetApplyOptions): void;

  setPolicy(opType: string, expression: string): void;
  /**
   * Registers a machine-enforced DedupSpec for a user-defined op type
   * (v1.4 §7): composes, node-key-signs as the bootstrap admin and executes
   * a '__define_operation_type__' op; the spec lands in the machine
   * registry and guards every later op of that type, regardless of what
   * the op carries on the wire. Installing the define type's own policy
   * first is the caller's job (setPolicy('__define_operation_type__',
   * 'role:admin')). The 'custom' dedup shape is C-native and not
   * surfaceable from the bindings.
   */
  defineOperationType(opType: string, options: DefineOperationTypeOptions): void;
  /**
   * Executes a validated op. A GROUP_ORDERED write on a machine with an
   * attached raft module resolves normally (not throwing): the two-phase
   * pipeline ACCEPTS the op as a pending proposal (ordering_pending) and it
   * materializes on commit, surfaced as a 'change' event by the pump.
   */
  execute(op: Operation): void;
  sign(op: Operation, key: KeyPair | string): void;
  createTrigger(config: TriggerConfig): void;

  // ============================================================
  // Raft ordering module — reference host (GROUP_ORDERED writes)
  // ============================================================
  /**
   * Attach a raft ordering module to this machine and return the RaftHost
   * driving it. This is a REFERENCE host — the transport, storage and
   * timer seams it wires are user-replaceable (see RaftHost). The
   * attachment is what routes group-item writes through the two-phase
   * pipeline: before any attach they fail closed (ordering_path).
   */
  attachRaft(options?: RaftHostOptions): RaftHost;
  /**
   * Transport receive half: inject one inbound raft control blob from
   * peerId and drain the module cascade it provokes (outbound transport,
   * persist windows, notification materialization).
   */
  raftDeliver(peerId: string, blob: Uint8Array): void;
  /** Point diagnostics (null when detached). */
  raftStatus(): RaftStatus | null;

  // Low-level handler: receives raw WASM pointers (statePtr, opPtr).
  registerHandler(opType: string, handler: (statePtr: number, opPtr: number) => number): void;
  // High-level handler: receives a mutable HandlerState proxy and a HandlerOperation.
  registerHandlerJs(opType: string, handler: (state: HandlerState, op: HandlerOperation) => number): void;
  unregisterHandler(opType: string): void;

  encrypt(payload: Uint8Array | string, policy: string): Uint8Array;
  /**
   * Derives a CP-ABE reader key from THE MACHINE'S OWN master authority:
   * whoever controls the machine can mint a key for any attribute set it
   * names — the same trust position as encrypt. The master key itself never
   * leaves the machine (no JS handle for it exists; no portable serialized
   * key in v1). attrs is the comma-separated token list the C API takes,
   * with the ':' → '_' token map applied machine-side (crypto.c:98-111) —
   * a key derived from 'role:member,role:moderator' carries the ABE words
   * role_member / role_moderator, so the seal policy must be written with
   * those same words. The returned key is JS-owned: destroy() it.
   */
  abeKeygen(attrs: string): AbeKey;
  /**
   * Opens the container encrypt() returned (u16le policy byte length +
   * policy bytes + u32le ciphertext length + ciphertext, the smoke.js:111-130
   * layout). Refuses with the typed error word 'unauthorized' when the key's
   * attributes do not satisfy the container's policy — the same typed path
   * tampering fails closed on. Malformed containers refuse at the binding
   * boundary. No portable keys: `key` must be the AbeKey abeKeygen returned
   * (a destroyed key refuses).
   */
  abeDecrypt(key: AbeKey, encrypted: Uint8Array): Uint8Array;

  // ============================================================
  // ABE key transport (parity-fill P4)
  // ============================================================
  /**
   * Re-import a reader key the AbeKey.toWire() form carries. The restore
   * runs on THIS machine's authority (crypto_abe_user_key_deserialize takes
   * mk) and refuses on a machine without one — but the CAPABILITY is the
   * wire's own: the restored key binds to its MINTING domain (pinned
   * cross-machine in test/key-transport.js). The wire is integrity-blind:
   * carry it authenticated or use the envelope flow.
   */
  abeKeyFromWire(wire: Uint8Array): AbeKey;
  /**
   * Mint a key envelope for a REGISTERED user — the refresh_key
   * materialization shape (state_machine.c:2797) without the protocol
   * bookkeeping: the machine's authority + node key issue a real CP-ABE key
   * for the user's CURRENT attribute set (one value per attribute NAME, the
   * token map applies), node-ECDSA-signed, with the key ECIES-wrapped to the
   * user's REGISTERED public key (never cleartext — audit H-A). Fail-closed
   * gates mirrored from the refresh path: ACTIVE users only (suspended →
   * user_suspended, unknown → user_not_found), a live node key and
   * authority required. Mutates NOTHING. options.expiresAt — epoch-ms expiry
   * stamped into the envelope (default 0 = no expiry, what refresh issues;
   * expiry enforcement is integrator-side in C). Returns the envelope wire
   * (crypto_key_envelope_serialize flat form: format_version + user_id +
   * state_version + attributes_hash + issued_at + expires_at + key blob +
   * signature).
   */
  mintKeyEnvelope(userId: string, options?: { expiresAt?: number | bigint }): Uint8Array;
  /**
   * Open a mintKeyEnvelope wire on the recipient side and return the
   * restored AbeKey — the C KeyEnvelope battery's flow: parse (against THIS
   * machine's authority), verify the ISSUER's ECDSA signature, open the
   * ECIES blob with the recipient's private key, import the recovered key.
   * Both tamper paths fail closed with the typed 'unauthorized' (wrong
   * recipient key or tampered blob → GCM tag; tampered wire → signature).
   * options.privateKeyHex — the recipient's 64-hex private key (the KeyPair
   * whose public key was registered); options.nodePublicKeyHex — the ISSUER
   * node's public key for out-of-machine verification (default: this
   * machine's own node key, which refuses envelopes another machine issued
   * — fail-closed). The recovered plaintext key never leaves C: the envelope
   * staging is cleansed inside the export on every path.
   */
  decryptKeyEnvelope(envelope: Uint8Array,
                     options: { privateKeyHex: string;
                                nodePublicKeyHex?: string }): AbeKey;
  /**
   * TRUST FACT — this is the machine's CROWN JEWEL: whoever holds these
   * bytes mints keys for ANY policy and decrypts EVERYTHING the authority
   * ever sealed. serializeMasterKey() emits the authority in its 'MK' wire
   * form (crypto_master_key_serialize, §11.5) for durability backup — the
   * C battery's MasterKeySerializeRoundTripPreservesAuthority: the restored
   * form is a FULL authority minting keys in the same domain. Treat the
   * return like an unencrypted private key; ship it only encrypted.
   */
  serializeMasterKey(): Uint8Array;
  /**
   * Plant a serialized authority as THIS machine's master key (masterKey_
   * FromWire — the recovery path a sealed snapshot's MSK section already
   * runs, serialization.c:2862-2866). A fresh authority makes the machine
   * mint keys in the restored domain. Refuses: malformed wire (bad magic,
   * overrun lengths — the C battery's garbage/overrun pins) with
   * invalid_param, and a machine whose authority is merely BORROWED (a
   * delegated lineage child) with protocol_violation — never replaces a
   * borrowed authority.
   */
  masterKeyFromWire(wire: Uint8Array): void;

  // ============================================================
  // State snapshots (parity-fill P1)
  // ============================================================
  /**
   * Snapshot serialization — the C families at serialization.h:55-90:
   *   serialize()                    plain, SHA-256 checksummed;
   *   serialize({sealKey})           sealed — the MSK is AES-256-GCM-wrapped
   *                                  under `sealKey` (64 hex chars, 32 bytes;
   *                                  needs the machine's LIVE master key);
   *   serialize({signed: true})      a node-key ECDSA trailer is appended
   *                                  (needs the machine's node key);
   *   serialize({sealKey, signed})   sealed + signed (both at-rest
   *                                  guarantees in one blob).
   * Staged seal-key bytes are zeroed inside the module heap on every path.
   * A snapshot blob carries the FULL machine (items, log, registry) — but
   * the bare SHA-256 inside it is an INTEGRITY check, not authentication:
   * anyone who can write the blob can recompute that checksum. Loading from
   * an untrusted source belongs to the signed variants (see deserialize).
   */
  serialize(options?: { sealKey?: string; signed?: boolean }): Uint8Array;
  /**
   * RESTORE a snapshot produced by serialize(): the wrapper's underlying
   * machine is REPLACED with the restored state — the same Node stays usable
   * (reads, writes); the previous machine is simply dropped from
   * the wrapper's reference (wasm machines are never destroyed — the module
   * leaks them by design). Returns the restore report
   *   { authorityRestored: boolean, mskSectionPresent: boolean }
   * which only means something for a SEALED blob:
   *   authorityRestored  — the sealed MSK unsealed with `sealKey`; a wrong or
   *                        missing key still loads, on the substrate-only
   *                        compatibility path, with a FRESH authority
   *                        (serialization.h:50-54) — treat authority as
   *                        unproven then;
   *   mskSectionPresent  — the blob carried the authority section at all.
   *
   * options: { sealKey?: '64-hex' } restores a sealed snapshot's master key;
   * { verify: 'node-key' } verifies a SIGNED snapshot's ECDSA trailer with
   * THIS machine's node public key BEFORE any parse (R7-03 — a machine
   * without a node key cannot verify; the signed blob is refused rather
   * than silently accepted unauthenticated). Both combine:
   * { sealKey, verify: 'node-key' } for sealed+SIGNED blobs. Continuity:
   * the node key, change hook, attached (module-shared) time source, a live
   * raft module (re-pointed to the restored machine — RaftHost.raftPump
   * keeps driving it), the wrapper's ordering config and the HLC clock
   * state (the restored machine's clock CONTINUES the previous machine's
   * HLC, so inbound-op skew validation stays at the previous watermark)
   * ride over from the previous machine; the tx manager is runtime-only —
   * attachTxManager again after a restore.
   */
  deserialize(wire: Uint8Array,
              options?: { sealKey?: string; verify?: 'node-key' }):
      { authorityRestored: boolean; mskSectionPresent: boolean };
  /**
   * Merge a foreign snapshot INTO this machine via crdt_merge_state — the
   * general item rules: counters max-per-node / sum-across-nodes, register
   * LWW (timestamp, then node id on tie), OR/2P-set union, one-shot
   * take-any; op logs merge by lamport time and dedupe by uuid. This
   * machine MUTATES toward the union; the source snapshot is untouched (it
   * is never attached to a machine). Throws, machine untouched, on a
   * malformed snapshot. Held items are NOT a failure: content the merge
   * layer cannot apply (an OT item, any type without a merge dispatch)
   * surfaces as a __merge_held__ change event on the machine's hook and
   * the merge returns SUCCESS. NOT the OT path: ordered-set items
   * need the dedicated ordered-set merge layer.
   */
  mergeState(wire: Uint8Array): void;

  /**
   * HLC watermark readback — the machine's LAST-issued hybrid timestamp,
   * WITHOUT advancing the clock (the native binding's getHLC issues a NEXT
   * timestamp instead; this wasm readback stays read-only so restore tests
   * can pin clock continuity exactly). Returns undefined on an
   * uninitialized clock (lamport-ordered machine). After a restore the
   * watermark CONTINUES the previous machine's HLC (deserialize's
   * Continuity note).
   */
  getHLC(): CrabsHLC | undefined;
  setTime(nowMs: number): void;
  pruneExpiredTempAttrs(): number;

  // Authenticated time source (R7-01 wiring; R7-02 fail closed). WASM-module
  // caveat: the ops object is module-SHARED — one per module instance, not
  // per machine. setTimeSource({mode:'https'}) on any Node replaces the
  // shared source and attaches it to this machine (re-attaching every other
  // attached machine in the module too); {mode:'system'} detaches only this
  // machine, and the shared ops is retired when the last attached machine
  // leaves. No fetch happens at attach time: the first query runs lazily
  // inside authenticated-time checks, and a fetch failure fails closed (the
  // machine reports invalid time), never falling back to the local clock.
  setTimeSource(options: TimeSourceOptions): void;
  getTimeSource(): TimeSourceInfo;

  schedule(innerOp: Operation, executeAtMs: number): bigint;
  scheduleRecurring(innerOp: Operation, startAtMs: number, intervalMs: number,
                    repeatCount: number, endAtMs: number): bigint;
  cancelSchedule(scheduleId: bigint): void;
  processSchedules(nowMs?: number): void;
  /** Per-tick ceiling on materialized scheduled occurrences (0 = unlimited). */
  setScheduleOccurrenceBudget(maxPerTick: number): void;
  scheduleOccurrenceBudget(): number;
  pendingSchedules(): Array<{ id: bigint; executeAt: bigint;
                              intervalMs: bigint; repeatCount: bigint;
                              endAt: bigint; submitter: string }>;

  evaluateTriggers(): void;

  // Lineage (v1.7): machines mint machines. Child machines are NEVER owned
  // by JS — the parent's resident-children registry in C anchors their
  // lifetime; JS only borrows the opaque pointers.
  /** Register the four lineage ops + default admin policies (idempotent). */
  lineageInstall(): void;
  /** Spawn a child machine; returns its opaque borrowed pointer. */
  lineageSpawn(blueprint: Blueprint): number;
  /** Borrowed pointer of the child still resident, or null. */
  lineageResidentChild(childId: string): number | null;
  /** Child manifest size. */
  childCount(): number;
  /** Manifest index of childId, or -1 when not manifested. */
  childIndex(childId: string): number;
  /** Flat manifest entry at index (id/mode/status/ttlMs/spawnedAt). */
  childAt(index: number): ChildManifestView | null;
  childById(childId: string): ChildManifestView | null;
  /** Snapshot of the whole child manifest. */
  children(): ChildManifestView[];
  /** Issue a parent-signed attestation; returns the transport wire bytes. */
  attest(childId: string, userId: string, attributes: string): Uint8Array;
  /** Mint a dissolution tombstone for a DISSOLVED child: canonical body
   *  (u8 tag + string16 childId + u64le parent_key_version key-stamp) +
   *  64-byte parent signature over the body, NO length
   *  prefix. Throws when the child is unknown or not dissolved. */
  lineageTombstone(childId: string): Uint8Array;

  // The bootstrap admin id this node was created with — also the node's HLC
  // identity, which signing stamps into op->node_id (used by devtools
  // per-node event drains).
  readonly adminId: string;
  destroy(): void;
}

export namespace Node {
  function create(adminId: string, options?: NodeOptions): Promise<Node>;
}

export function getModule(): Promise<any>;

/**
 * Active wire-format versions, mirrored from the C library (no JS
 * hardcoding). Cached after first call; the resolved object is frozen.
 *   state   — CRABS_SERIAL_VERSION (state wire format)
 *   op      — CRABS_OP_FORMAT_VERSION (op wire format)
 *   signing — CRABS_SIGNING_FORMAT_VERSION (signing canonical form)
 */
export function wireVersions(): Promise<{
  readonly state: number;
  readonly op: number;
  readonly signing: number;
}>;
