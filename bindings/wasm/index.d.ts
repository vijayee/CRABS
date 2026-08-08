// TypeScript definitions for crabs-wasm

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
  deserialize(bytes: Uint8Array): Promise<Operation>;
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
  revokeUser(userId: string): void;
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
  evaluateTriggers(): void;
  destroy(): void;
}

export namespace Node {
  function create(adminId: string, options?: NodeOptions): Promise<Node>;
}

export function getModule(): Promise<any>;
