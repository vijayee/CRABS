//
// index.d.ts — TypeScript type definitions for crabs-node
//

/// <reference types="node" />

/** Protocol state words (protocol_state_e, src/CRABS/data_model.h:58-65). */
export type ProtocolStateWord = 'idle' | 'locked' | 'modified' | 'verified' | 'error';

/**
 * Live lock state of a RESOURCE item (data_item_t.lock_state_t — runtime
 * only, never serialized). lockTokenHex is the 32-byte CSPRNG bearer token
 * the executor minted at __lock__ ('' when the item carries no valid
 * token): claim it into the next op's addLockClaim BEFORE signing — the
 * signature binds the claims.
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

export interface KeyPair {
  publicKeyHex(): string;
  privateKeyHex(): string;
}

/**
 * One parent-signed attestation, field-wise — the canonical attestation body
 * (attestation_t, src/Lineage/lineage.h) parsed out of lineageAttest's wire
 * image, ready for Operation.addAttestation. Signature carries the parent's
 * ECDSA over the body; the chain-TIP version stamp rides in
 * parentKeyVersion.
 */
export interface AttestationFields {
  parentId: string;
  childId: string;
  userId: string;
  /** Comma-separated name:value pairs; an endorsement resolves when the
   *  list CONTAINS the token exactly. */
  attributes: string;
  /** Epoch ms; 0 = no lower fence. */
  notBefore?: number;
  /** Epoch ms; 0 is a legal (instant-then-expired) window. */
  expiresAt?: number;
  /** The chain TIP version the parent stamped (required — tip-only verify). */
  parentKeyVersion: number;
  /** 128 hex chars (64 bytes = CRABS_SIG_SIZE). */
  signatureHex: string;
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
  /**
   * Recipe 9 (lock protocol): set the per-slot required_state at slotIndex —
   * the executor refuses the op with protocol_violation unless every named
   * resource is in exactly that state before anything moves. Slots are
   * created 'idle' by addResource. Signed (format v4) — set BEFORE signing.
   * Chainable.
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
   * state_machine.c). Parse the fields out of lineageAttest's wire image
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
  /** Wire bytes of the op as currently staged (sign first, then serialize). */
  serialize(): Buffer;
  /**
   * Op format version this op carries. Fresh ops report the build's
   * wireVersions.op; deserialized ops report the version declared on the
   * wire.
   */
  getWireVersion(): number;
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
  /** 'group' only; must match the moduleId of the attached raft module. */
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
  /**
   * Recipe 9: mint a lock-capable RESOURCE item ("PN-Counter + lock"). The
   * value is a raw int64 balance (dedup mutations, the lock snapshot and
   * destroy all take the raw path for RESOURCE); `initial` seeds it. Pair
   * with getLockState / Operation.setRequiredState + addLockClaim to drive
   * the lock ceremony from JS.
   */
  addResource(name: string, initial?: number): void;
  /**
   * Raw int64 readback of the RESOURCE balance (previously machine-read
   * only). Undefined for an unknown name (getCounter's convention);
   * type_mismatch for anything that is not a RESOURCE item. Unlike the wasm
   * binding's HandlerState.getResource (which throws on failure), this one
   * signals a missing name by returning undefined. Balances beyond ±2^53
   * lose precision through Number.
   */
  getResource(name: string): number | undefined;
  /**
   * Recipe 9: LIVE lock state of a RESOURCE item — the driver reads the
   * bearer token here and claims it into the next op's addLockClaim BEFORE
   * signing. Lock state is runtime only — never serialized (and never
   * part of the chain digest).
   */
  getLockState(name: string): LockStateView;
  /**
   * Recipe 9: attach a replay-protection manager to the machine's state
   * (src/TxManager/tx_manager.h). 'memory' records committed op uuids — the
   * executor's signature-verified step 3b refuses a duplicate submission
   * with already_executed; 'none' is the accept-everything hook
   * (crabs_tx_manager_none). With NO manager attached, the ordering-
   * monotonicity backstop still rejects a replayed op, including after a
   * restart. Runtime only — never serialized; attach again after a state
   * round trip. Replacing an attached manager destroys the previous one;
   * the machine's own teardown destroys whatever remains attached
   * (attribute_machine_destroy — the binding does not double-manage it).
   */
  attachTxManager(kind: 'memory' | 'none'): void;
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
  /**
   * Integer-only: a register carries an int64. Numbers must be integers
   * within ±Number.MAX_SAFE_INTEGER (the node binding accepts numbers only;
   * for full int64 range use crabs-wasm's BigInt acceptance). Fractional
   * values are rejected — encode scaled units instead
   * (e.g. store 12.5% as 125 per-mille).
   */
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

  // ============================================================
  // Ordered set (OT_ORDERED_SET, v1.5 §5 — recipe 8)
  // ============================================================
  /**
   * Create an OT ordered-set item (data type 0x10) on this machine. The
   * item carries its own op log + transform matrix; apply ops with
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
   * node key under this machine's admin (the reportEquivocation idiom —
   * install the op type's policy first:
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

  // Policies & Operations
  setPolicy(opType: string, expression: string): void;
  /**
   * Registers a machine-enforced DedupSpec for a user-defined op type
   * (v1.4 §7): builds a '__define_operation_type__' op, signs it with the
   * node key under the machine's real admin identity and executes it; the
   * spec lands in the machine registry and guards every later op of that
   * type (the registry entry is replaced in place on re-definition, so
   * dedup 'none' removes a guard). Installing the define type's own policy
   * first is the caller's job (setPolicy('__define_operation_type__',
   * 'role:admin')). The 'custom' dedup shape is C-native and not
   * surfaceable from the bindings.
   */
  defineOperationType(opType: string, options: DefineOperationTypeOptions): void;
  sign(op: Operation, key: KeyPair | string): void;
  execute(op: Operation): void;

  // Timed transactions (v1) — mirror of the wasm surface
  // (bindings/wasm/index.d.ts:501-510). The submission-time authorization
  // gate lives in the wrapper: every schedule* call runs the machine's
  // read-only validate pass (policy + signature + key version +
  // co-signatures + domain check, state_machine_validate) BEFORE queueing,
  // and throws the typed crabs error on refusal. Materialization (below)
  // deliberately skips re-authorization — the fire re-runs only the domain
  // check and the engine's guards; a failed fire is recorded as an
  // '__schedule_failed__' entry and never propagated.
  /**
   * Queue a signed op for materialization at executeAtMs (epoch ms).
   * Returns the schedule id (per-state monotonic, persists past a
   * serialize/restore round trip) as a bigint.
   */
  schedule(innerOp: Operation, executeAtMs: number): bigint;
  /**
   * Queue a recurring series: fires at startAtMs, then every intervalMs,
   * until repeatCount fires have happened (0 = infinite) or the slots pass
   * endAtMs (0 = no end), whichever comes first.
   */
  scheduleRecurring(innerOp: Operation, startAtMs: number, intervalMs: number,
                    repeatCount: number, endAtMs: number): bigint;
  /** Remove one pending schedule before it fires (resource_not_found when absent). */
  cancelSchedule(scheduleId: bigint | number): void;
  /**
   * Explicit clock poke: materialize everything due against `nowMs`
   * (epoch ms). Defaults to the wall clock — pass it explicitly in demos
   * and tests.
   */
  processSchedules(nowMs?: number): void;
  /** Per-tick ceiling on materialized scheduled occurrences (0 = unlimited). */
  setScheduleOccurrenceBudget(maxPerTick: number): void;
  scheduleOccurrenceBudget(): number;
  /** The pending queue in submission order. */
  pendingSchedules(): Array<{ id: bigint; executeAt: bigint;
                              intervalMs: bigint; repeatCount: bigint;
                              endAt: bigint; submitter: string }>;

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

  // ============================================================
  // Raft ordering module (GROUP_ORDERED writes)
  // ============================================================
  /** The bootstrap admin id — the machine's HLC identity and default raft node id. */
  readonly adminId: string;
  /**
   * Attach a raft ordering module to this machine's state. The reference
   * host loop (createRaftHost in index.js) wraps these surfaces with the
   * setTimeout tick loop and the user-replaceable transport/storage seams.
   * Before any attach, group-item writes fail closed (ordering_path).
   */
  attachRaft(options: { nodeId?: string; peers: string[];
                        electionMinMs?: number; electionMaxMs?: number;
                        heartbeatMs?: number; seed?: number }): this;
  /** Manual tick at an explicit time (Date.now() when omitted). Returns the crabs_error_e. */
  raftTick(nowMs?: number): number;
  /** Inject one inbound raft control blob from peerId. Returns the crabs_error_e. */
  raftDeliver(peerId: string, blob: Buffer): number;
  /** Acknowledge a persist window from raftPollPersistRequest. Returns the crabs_error_e. */
  raftPersistComplete(handle: bigint | number, ok: boolean): number;
  /**
   * Crash recovery: replay one stored persist batch into the module's
   * durable state — the host's batch record is the durable raft history
   * that survives a module/host restart whose machine blob is stale.
   * Corrupt/contradictory batches fail closed. Returns the crabs_error_e.
   */
  raftRecoverFromPersist(batch: Buffer): number;
  /**
   * Materialize committed ops through the machine's pipeline (fires
   * 'change' events, shelves ordered retries). Returns the crabs_error_e.
   */
  raftPump(nowMs?: number): number;
  /**
   * Drain outbound control blobs ({kind, to, blob}) — TRANSFERS each blob;
   * drain until empty.
   */
  raftPollOutbound(): Array<{ kind: number; to: string; blob: Buffer }>;
  /**
   * Report the outstanding persist window ({handle: bigint, blob}) — a
   * VIEW: the handle stays module-open until raftPersistComplete; the same
   * handle is re-reported while unresolved. Undefined when drained.
   */
  raftPollPersistRequest(): { handle: bigint; blob: Buffer } | undefined;
  /**
   * Raw committed-op / leadership notifications ({kind, peerId, proposalId,
   * commitIndex, opBytes?}). With the reference host's pumpNotifications:
   * false mode, hosts drain this queue themselves.
   */
  raftPollNotifications(): Array<{ kind: number; peerId: string;
                                   proposalId: number; commitIndex: number;
                                   opBytes?: Buffer }>;
  /** Point diagnostics of the attached module (null when detached). */
  raftStatus(): { nodeId: string; isLeader: boolean; term: number;
                  commitTip: number; logLength: number;
                  configChangePending: boolean; peerCount: number } | null;
  /** Detach and destroy the attached module (the destructor does this too). */
  raftDetach(): void;
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

/** An OT op identity: (node, seq) is the dedup key, ts the issuing stamp. */
export interface OrderedSetOpId {
  /** Issuing replica's id (max 63 bytes, UTF-8). */
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

export const DATA_TYPE: {
  COUNTER: number;
  PN_COUNTER: number;
  SET: number;
  REGISTER: number;
  RESOURCE: number;
  ONE_SHOT_SET: number;
  ONE_SHOT_FLAG: number;
  OT_ORDERED_SET: number;
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

/**
 * Active wire-format versions, mirrored from the C library (no JS
 * hardcoding). Frozen at module load.
 *   state   — CRABS_SERIAL_VERSION (state wire format)
 *   op      — CRABS_OP_FORMAT_VERSION (op wire format)
 *   signing — CRABS_SIGNING_FORMAT_VERSION (signing canonical form)
 */
export const wireVersions: {
  readonly state: number;
  readonly op: number;
  readonly signing: number;
};
/**
 * Raft reference host — wraps a Node's attached raft module with the
 * setTimeout tick loop and the user-replaceable transport/storage seams
 * (mirroring bindings/wasm's RaftHost). Transport: drained control blobs go
 * anywhere; incoming blobs return through node.raftDeliver. Storage:
 * persist windows stored anywhere durable; a resolved promise acks the
 * window (persist_complete true), a rejected one marks it failed. With
 * pumpNotifications: false (raw-host mode) the committed-op queue is left
 * for the host to drain via raftPollNotifications — use it when no
 * materialization handlers are registered, otherwise every committed op
 * fails the pipeline and piles onto the retry shelf.
 */
export function createRaftHost(node: Node, options?: {
  nodeId?: string;
  peers?: string[];
  tickMs?: number;
  timers?: { electionMinMs?: number; electionMaxMs?: number; heartbeatMs?: number };
  seed?: number;
  pumpNotifications?: boolean;
}): {
  readonly nodeId: string;
  readonly peers: string[];
  setRaftTransport(fn?: (peerId: string, blob: Buffer) => void | Promise<void>): void;
  setRaftStorage(fn?: (handle: bigint, blob: Buffer) => void | Promise<void>): void;
  startRaftHost(): void;
  stopRaftHost(): void;
  raftTick(nowMs?: number): void;
  pumpInbound(peerId: string, blob: Buffer): void;
  raftPollOutbound(): Array<{ kind: number; to: string; blob: Buffer }>;
  raftPollPersistRequest(): { handle: bigint; blob: Buffer } | undefined;
  raftPersistComplete(handle: bigint | number, ok: boolean): void;
  /** Replay one stored persist batch (crash recovery); throws on refusal. */
  raftRecoverFromPersist(batch: Buffer): void;
  raftPollNotifications(): Array<{ kind: number; peerId: string;
                                   proposalId: number; commitIndex: number;
                                   opBytes?: Buffer }>;
  raftPump(nowMs?: number): void;
  status(): { nodeId: string; isLeader: boolean; term: number; commitTip: number;
              logLength: number; configChangePending: boolean; peerCount: number };
  destroy(): void;
};
