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

export interface HandlerState {
  incrementCounter(name: string, delta?: number, nodeId?: string): void;
  incrementPNCounter(name: string, delta?: number, nodeId?: string): void;
  decrementPNCounter(name: string, delta?: number, nodeId?: string): void;
  setRegister(name: string, value: number, nodeId?: string): void;
  setAdd(name: string, element: string, tag?: string): void;
  setRemove(name: string, element: string): void;
  flagSet(name: string, setBy: string, setAt?: number): void;
  getCounter(name: string): number;
  getPNCounter(name: string): number;
  getRegister(name: string): number;
  setContains(name: string, element: string): boolean;
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
  /** 'group' only; v1 ships no ordering modules, so only 0 is legal. */
  orderingModule?: number;
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
  setRegister(name: string, value: number, nodeId?: string): void;
  setRegisterBytes(name: string, bytes: Uint8Array, nodeId?: string): void;
  setContains(name: string, element: string): boolean;

  incrementCounter(name: string, delta?: number, nodeId?: string): void;
  incrementPNCounter(name: string, delta?: number, nodeId?: string): void;
  decrementPNCounter(name: string, delta?: number, nodeId?: string): void;

  setAdd(name: string, element: string, tag?: string): void;
  setRemove(name: string, element: string): void;
  flagSet(name: string, setBy: string, setAt?: number): void;
  flagValue(name: string): boolean;

  setPolicy(opType: string, expression: string): void;
  execute(op: Operation): void;
  sign(op: Operation, key: KeyPair | string): void;
  createTrigger(config: TriggerConfig): void;

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
