// TypeScript definitions for crabs-wasm (mirrors crabs-node)

export interface KeyPair {
  publicKeyHex(): string;
  privateKeyHex(): string;
  destroy(): void;
}

export interface Node {
  getNodeKey(): { publicKeyHex: string; privateKeyHex: string };
  registerUser(userId: string, publicKeyHex: string, initialAttrs?: string): Promise<void>;
  getUser(userId: string): Promise<{ userId: string } | undefined>;
  destroy(): void;
}

export interface Operation {
  signerId: string;
  nodeId: string;
  destroy(): void;
}

export function getModule(): Promise<any>;