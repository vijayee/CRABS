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

export interface NodeOptions {
  ordering?: 'hlc' | 'lamport';
  strategy?: 'naive' | 'bounded' | 'quorum' | 'strict' | 'trusted';
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
   *  (u8 tag + string16 childId) + 64-byte parent signature, NO length
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
