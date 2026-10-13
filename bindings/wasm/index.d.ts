// TypeScript definitions for crabs-wasm

export interface CrabsChangeEvent {
  kind: 'op' | 'schedule' | 'trigger' | 'attribute' | 'spawn' | 'lineage';
  type: string;
  uuid: string;
  signer: string;
  node: string;
  target: string | null;
  preview: string;
  result: number;  // crabs_error_e
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

export interface HandlerOperation {
  type: string;
  signerId: string;
  nodeId: string;
  payload: string | undefined;
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
  serialize(): Uint8Array;

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
