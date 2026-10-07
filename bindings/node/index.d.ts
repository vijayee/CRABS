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

export interface HLC {
  seconds: number;
  nanos: number;
  logicalCounter: number;
  nodeId: string;
  formatted: string;
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
}

export interface NodeStatic {
  new (adminId: string, options?: NodeOptions): Node;
}

export const KeyPair: KeyPairStatic;
export const Operation: OperationStatic;
export const Node: NodeStatic;