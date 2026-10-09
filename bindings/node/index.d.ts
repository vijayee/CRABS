//
// index.d.ts — TypeScript type definitions for crabs-node
//

/// <reference types="node" />

export interface KeyPair {
  publicKeyHex(): string;
  privateKeyHex(): string;
}

export interface KeyPairStatic {
  new (): KeyPair;
  generate(): KeyPair;
  fromPrivateHex(hex: string): KeyPair;
  derivePublicHex(hex: string): string;
}

export interface Operation {
  type: string;
  signerId: string;
  nodeId: string;
  payload: Buffer | string | undefined;
  lamportTime: number;
  /** Append a resource name to the op (capacity 8). */
  addResource(name: string): this;
  /**
   * Write-domains v1: set the sovereign chain prefix (item_seq, prev digest
   * as 64 hex chars) at prefixIndex — parallel to the op's sovereign
   * resources in declaration order. Signed (format v4) and wire-carried
   * (op format v6).
   */
  setSovereignPrefix(prefixIndex: number, seq: number, digestHex: string): this;
  /** Wire bytes of the op as currently staged (sign first, then serialize). */
  serialize(): Buffer;
  sign(keyPair: KeyPair): this;
  signWithPrivateKey(privateKeyHex: string): this;
}

export interface OperationStatic {
  new (type: string): Operation;
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

// ============================================================
// Lineage (v1.7: machines mint machines)
// ============================================================

/** Trust mode for a spawned child: string word or the wire number. */
export type TrustMode =
  | 'shared_root' | 'shared'
  | 'delegated_copy' | 'delegated'
  | 'sovereign'
  | number;

/**
 * A serializable machine definition a parent instantiates via
 * Node.lineageSpawn (or ships between processes as a __spawn_machine__
 * op payload). JS owns the blueprint; release it with destroy().
 */
export interface Blueprint {
  /** Append a replicated data item to the child's definition. */
  addItem(name: string, dataType: string | number, crdtType: string | number): void;
  /** Append an authorization policy: operation type + condition expression. */
  addPolicy(operation: string, expression: string): void;
  /** Recompute the blueprint's SHA-256 over its canonical body. */
  stampHash(): void;
  /** Wire image: u32le length + canonical body + 32-byte blueprint hash. */
  serialize(): Buffer;
  /** Release the underlying C blueprint. */
  destroy(): void;
}

export interface BlueprintStatic {
  new (childId: string, trustMode: TrustMode, bootstrapAdmin: string, ttlMs: number): Blueprint;
  new (wire: Buffer): Blueprint;
  create(childId: string, trustMode: TrustMode, bootstrapAdmin: string, ttlMs: number): Blueprint;
  /** Parse a wire image; verifies the embedded hash + structural validation. */
  deserialize(wire: Buffer): Blueprint;
}

/** One entry of the parent's (borrowed) child manifest view. */
export interface ChildManifestEntry {
  childId: string;
  mode: 'shared_root' | 'delegated_copy' | 'sovereign' | 'unknown';
  status: 'active' | 'dissolved' | 'withdrawn' | 'attestation_revoked' | 'unknown';
  spawnedAtMs: number;
  attestationTtlMs: number;
}

export interface HLC {
  seconds: number;
  nanos: number;
  logicalCounter: number;
  nodeId: string;
  formatted: string;
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

export interface TriggerConfig {
  triggerId: string;
  condition: string;
  description?: string;
  effectType: 'issue_attribute' | 'change_policy';
  cooldownMs?: number;
  oneShot?: boolean;
  // For issue_attribute:
  issueAttribute?: string;
  targetRole?: string;
  attributeValue?: string;
  durationMs?: number;
  // For change_policy:
  policyOperation?: string;
  policyExpression?: string;
}

export interface NodeOptions {
  ordering?: 'hlc' | 'lamport';
  strategy?: 'naive' | 'bounded' | 'quorum' | 'strict' | 'trusted';
}

export interface TimeSourceOptions {
  /** 'https' attaches the authenticated HTTPS time source; 'system' detaches (local clock). */
  mode: 'https' | 'system';
  /** https:// endpoint (max 255 chars). Omit for the default endpoint. */
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

export interface CrabsChangeEvent {
  kind: 'op' | 'schedule' | 'trigger' | 'attribute' | 'spawn' | 'lineage';
  type: string;
  signer: string | null;
  node: string | null;
  target: string | null;
  preview: string;
  result: number;  // crabs_error_e
}

export interface Node {
  // User management
  registerUser(userId: string, publicKeyHex: string, initialAttrs?: string): void;
  grantRole(targetUser: string, role: string, value: string, signerId: string): void;
  selfAssert(attribute: string, value: string, signerId: string): void;
  verifyIdentity(targetUser: string, attribute: string, value: string, signerId: string): void;
  revokeUser(userId: string, signerId?: string): void;
  /** Subscribe to state-change events ('change' only). Returns an off() function. */
  on(eventName: 'change', listener: (event: CrabsChangeEvent) => void): () => void;
  getUser(userId: string): UserInfo | undefined;
  getNodeKey(): NodeKey;

  // Data items
  addCounter(name: string): void;
  addPNCounter(name: string): void;
  addORSet(name: string): void;
  addOneShotSet(name: string): void;
  addOneShotFlag(name: string): void;
  addRegister(name: string, initialValue?: number): void;
  addResource(name: string): void;
  /**
   * Write-domains v1: item creation with an explicit write-domain
   * declaration. v1 supports 'counter'/'register' (the SOVEREIGN-legal
   * types; other shapes keep their dedicated add* methods).
   */
  defineItem(name: string, dataType: string | number,
             crdtType: string | number, options?: DefineItemOptions): void;
  /**
   * Write-domains v1: the live chain head of a SOVEREIGN item — what the
   * writer's next op must claim in its signed prefix. digestHex is the
   * FULL 32-byte digest as 64 hex chars. Throws resource_not_found for an
   * unknown item.
   */
  itemChainHead(name: string): { seq: number; digestHex: string };
  /**
   * Write-domains v1: file a __report_equivocation__ op against the
   * SOVEREIGN item `itemName`, carrying two serialized writer ops as the
   * evidence pair. Submitted through the node's sign path (admin signer,
   * node key). On success the writer is quarantined on the item; failures
   * throw typed crabs errors and set nothing.
   */
  reportEquivocation(itemName: string, opABytes: Buffer, opBBytes: Buffer): void;

  // Queries
  getCounter(name: string): number | undefined;
  getPNCounter(name: string): number | undefined;
  getRegister(name: string): number | undefined;
  setRegister(name: string, value: number, nodeId?: string): void;
  setContains(name: string, element: string): boolean;

  // Direct counter operations (for setup/testing)
  incrementCounter(name: string, delta?: number, nodeId?: string): void;
  incrementPNCounter(name: string, delta?: number, nodeId?: string): void;
  decrementPNCounter(name: string, delta?: number, nodeId?: string): void;

  // Direct set operations (for setup/testing)
  setAdd(name: string, element: string, tag?: string): void;
  setRemove(name: string, element: string): void;
  flagSet(name: string, setBy: string, setAt?: number): void;
  flagValue(name: string): boolean;

  // Policies & Operations
  setPolicy(opType: string, expression: string): void;
  sign(op: Operation, key: KeyPair | string): void;
  execute(op: Operation): void;

  // Triggers
  createTrigger(config: TriggerConfig): void;

  // ABE
  encrypt(payload: Buffer, policy: string): Buffer;

  // Serialization
  serialize(): Buffer;

  // HLC
  getHLC(): HLC | undefined;
  setTime(nowMs: number): void;
  pruneExpiredTempAttrs(): void;

  // Authenticated time source (A10-L9 wiring, R7-01). Machine-local
  // configuration — adopted child wrappers may set it on their own machine.
  // 'https' attaches the authenticated HTTPS source; no fetch happens at
  // attach time (queries run lazily inside authenticated-time checks, and a
  // fetch failure fails closed per R7-02 — never a local-clock fallback).
  // A11-L6: the source rides the MACHINE, not the wrapper. When two Node
  // wrappers wrap the same machine (lineageSpawn / lineageResidentChild),
  // destroying EITHER wrapper detaches the machine's clock from its state —
  // teardown always clears the ops pointer it installed first, so a sibling
  // wrapper's live configuration is silently stripped (fail-closed from then
  // on). Re-apply setTimeSource on the surviving wrapper if you destroy a
  // sibling that had configured one.
  setTimeSource(options: TimeSourceOptions): void;
  getTimeSource(): TimeSourceInfo;

  // Lineage (v1.7: machines mint machines)
  /** Register the five __lineage__ op types, policies and handlers. Idempotent. */
  lineageInstall(): void;
  /**
   * Instantiate a child machine from a blueprint. The returned Node BORROWS
   * the spawned machine — this Node owns it (destroyed when the parent is
   * collected); the wrapper keeps the parent alive.
   */
  lineageSpawn(blueprint: Blueprint): Node;
  /** Borrowed view over the child manifest. */
  lineageChildren(): ChildManifestEntry[];
  /** The still-resident in-process spawned child, or null when unknown/dissolved. */
  lineageResidentChild(childId: string): Node | null;
  /**
   * Parent-signed, TTL-bounded attribute grant — returns the attestation
   * wire image (u32le length + canonical body + signature). Requires an
   * authenticated time source (setTime) and an ACTIVE manifest entry.
   */
  lineageAttest(childId: string, userId: string, attributes?: string): Buffer;
  /**
   * Off-chain dissolution proof for an already-DISSOLVED child: canonical
   * tombstone body (u8 tag + string16 childId + u64le parent_key_version
   * key-stamp) + 64-byte parent ECDSA over the body — the exact bytes a
   * __receive_dissolution__ op transports. Honesty-gate refusals surface as
   * typed errors (resource_not_found / unauthorized / cryptographic_error).
   */
  lineageTombstone(childId: string): Buffer;
}

export interface NodeStatic {
  new (adminId: string, options?: NodeOptions): Node;
}

export const KeyPair: KeyPairStatic;
export const Operation: OperationStatic;
export const Blueprint: BlueprintStatic;
export const Node: NodeStatic;

export const TRUST_MODE: {
  SHARED_ROOT: number;
  DELEGATED_COPY: number;
  SOVEREIGN: number;
};

export const DATA_TYPE: {
  COUNTER: number;
  PN_COUNTER: number;
  SET: number;
  REGISTER: number;
  RESOURCE: number;
  ONE_SHOT_SET: number;
  ONE_SHOT_FLAG: number;
  CUSTOM: number;
};

export const CRDT_TYPE: {
  G_COUNTER: number;
  PN_COUNTER: number;
  OR_SET: number;
  LWW_REG: number;
  ONE_SHOT_SET: number;
  ONE_SHOT_FLAG: number;
  CUSTOM: number;
};