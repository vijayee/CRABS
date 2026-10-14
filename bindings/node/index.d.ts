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
 * A machine-derived CP-ABE reader key (gap-fill A11 + parity-fill P4):
 * Node.abeKeygen derives it from the machine's OWN master authority, so JS
 * never touches the master secret — the machine mints it, JS holds only the
 * derived key. JS OWNS the pointer: destroy() releases it (the destructor
 * releases it too, matching the KeyPair/Blueprint convention). Portable
 * bytes exist through toWire() (parity-fill P4): a SELF-SUFFICIENT BEARER
 * image of the key (crypto_abe_user_key_serialize) — it carries its own
 * minting domain, restores on any machine via Node.abeKeyFromWire (the
 * restored key opens exactly what its minting authority sealed, wherever it
 * was restored), and has NO integrity check — carry it over an
 * authenticated channel, or move keys with the key envelope flow
 * (Node.mintKeyEnvelope / Node.decryptKeyEnvelope) instead.
 */
export interface AbeKey {
  /**
   * Portable reader-key wire image (crypto_abe_user_key_serialize). The
   * bytes ARE the key — treat the return like a bearer token. Refuses on a
   * destroyed key.
   */
  toWire(): Buffer;
  destroy(): void;
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
  kind: 'op' | 'schedule' | 'trigger' | 'attribute' | 'spawn' | 'lineage' | 'merge';
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
  /**
   * Keyring lifecycle (parity-fill P2): suspend/activate/rotate the named
   * key of the RESOLVED user. The C primitives are user_t-scoped and carry
   * NO signer gate by design — the wire ops (__suspend_key__ / ...)
   * own the policy story; these run through the module's own authority.
   * suspend/activate bump the user's keyVersion readback (the R7-04
   * staleness anchor: ops stamped pre-bump refuse with key_stale).
   */
  // Keyring-direct helpers carry NO signer gate and emit NO change event
  // (only user key_version moves) — unlike the __suspend_key__ wire ops, they
  // leave no op-log trail; replicas observe the change only via state sync.
  suspendKey(userId: string, keyId: string): void;
  activateKey(userId: string, keyId: string): void;
  rotateKey(userId: string, oldKeyId: string, newKeyId: string,
            opts: RotateKeyOptions): void;
  /** Readback: the user's keyring (see UserKeyInfo). Unknown users refuse. */
  listKeys(userId: string): UserKeyInfo[];
  /** Readback: the user's default key id ('' when the user has none). */
  getDefaultKey(userId: string): string;
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
   * policy bytes + u32le ciphertext length + ciphertext). Refuses with the
   * typed error word 'unauthorized' when the key's attributes do not satisfy
   * the container's policy — the same typed path tampering fails closed on.
   * Malformed containers refuse at the binding boundary. No portable keys:
   * `key` must be the AbeKey abeKeygen returned (a destroyed key refuses).
   */
  abeDecrypt(key: AbeKey, encrypted: Buffer): Buffer;

  // ============================================================
  // ABE key transport (parity-fill P4)
  // ============================================================
  /**
   * Re-import a reader key the AbeKey.toWire() form carries. The restore
   * runs on THIS machine's authority (crypto_abe_user_key_deserialize takes
   * mk) and refuses on a machine without one — but the CAPABILITY is the
   * wire's own: the restored key binds to its MINTING domain (pinned
   * cross-machine in test/abe.js). The wire is integrity-blind: carry it
   * authenticated or use the envelope flow.
   */
  abeKeyFromWire(wire: Buffer): AbeKey;
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
   * (crypto_key_envelope_serialize flat form).
   */
  mintKeyEnvelope(userId: string, options?: { expiresAt?: number }): Buffer;
  /**
   * Open a mintKeyEnvelope wire on the recipient side and return the
   * restored AbeKey — the C KeyEnvelope battery's flow: parse (against THIS
   * machine's authority), verify the ISSUER's ECDSA signature, open the
   * ECIES blob with the recipient's private key, import the recovered key.
   * Both tamper paths fail closed with the typed 'unauthorized' (wrong
   * recipient key or tampered blob → GCM tag; tampered wire → signature).
   * options.privateKeyHex — the recipient's 64-hex private key (the KeyPair
   * whose public key was registered); options.nodePublicKeyHex — the ISSUER
   * node's public key (66 hex) for out-of-machine verification (default:
   * this machine's own node key, which refuses envelopes another machine
   * issued — fail-closed). The recovered plaintext key never leaves C:
   * staging is cleansed on every path, the recipient private key bytes and
   * their hex-string copies included.
   */
  decryptKeyEnvelope(envelope: Buffer,
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
  serializeMasterKey(): Buffer;
  /**
   * Plant a serialized authority as THIS machine's master key
   * (masterKeyFromWire — the recovery path a sealed snapshot's MSK section
   * already runs, serialization.c:2862-2866). A fresh authority makes the
   * machine mint keys in the restored domain; the replaced (owned)
   * authority is destroyed and cleansed. Refuses: malformed wire (bad
   * magic, overrun lengths — the C battery's garbage/overrun pins) with
   * invalid_param, and a machine whose authority is merely BORROWED (a
   * delegated lineage child) with protocol_violation — never replaces a
   * borrowed authority.
   */
  masterKeyFromWire(wire: Buffer): void;

  // Serialization
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
   * Staged seal-key bytes are cleansed on every path. A snapshot blob
   * carries the FULL machine (items, log, registry) — but the bare SHA-256
   * inside it is an INTEGRITY check, not authentication: anyone who can
   * write the blob can recompute that checksum. Loading from an untrusted
   * source belongs to the signed variants (see deserialize).
   */
  serialize(options?: { sealKey?: string; signed?: boolean }): Buffer;
  /**
   * RESTORE a snapshot produced by serialize(): the wrapper's underlying
   * machine is REPLACED with the restored state — the same Node stays
   * usable (reads, writes). The previous machine is destroyed
   * when this wrapper owned it; a spawned (borrowed) child wrapper re-points
   * instead — the borrowed machine stays with its parent. Returns the
   * restore report { authorityRestored: boolean, mskSectionPresent: boolean }
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
   * than silently accepted unauthenticated; a borrowed wrapper owns no node
   * key, so its restored machine signs nothing until a key exists). Both
   * combine: { sealKey, verify: 'node-key' } for sealed+SIGNED blobs.
   * Continuity: the wrapper's node key, change hook, attached time source
   * and raft module ride over from the previous machine, as do the
   * wrapper-owned ordering config and the HLC clock state (the restored
   * machine's clock CONTINUES the previous machine's HLC, so inbound-op
   * skew validation stays at the previous watermark; a borrowed previous
   * machine — whose owner wrapper also re-applies them — loses the config
   * and clock); the tx manager is runtime-only — attachTxManager again
   * after a restore.
   */
  deserialize(wire: Buffer,
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
   * surfaces as a __merge_held__ change event on the machine's hook ('merge'
   * events) and the merge returns SUCCESS. NOT the OT path: ordered-set
   * items need the dedicated ordered-set merge layer.
   */
  mergeState(wire: Buffer): void;

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
export const AbeKey: { new (): AbeKey };
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
