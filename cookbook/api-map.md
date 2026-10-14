# CRABS API Map

Every recipe's provenance footer cites the entries defined here. Two JS bindings expose the C core:

| Binding | Types | Read in full | Lines |
|---|---|---|---|
| `crabs-wasm` (Emscripten) | [`bindings/wasm/index.d.ts`](../bindings/wasm/index.d.ts) | 2026-10-13 | 937 |
| `crabs-node` (N-API) | [`bindings/node/index.d.ts`](../bindings/node/index.d.ts) | 2026-10-13 | 891 |

**Maturity labels**

- `STABLE` — exercised by tests in `bindings/*/test/`, `bindings/*/lineage_smoke.mjs`, or `cookbook/recipes/` examples.
- `PRESENT` — declared in a `.d.ts` (or compiled C) but not exercised anywhere we found. Write recipes against it carefully.
- `DESIGNED` — exists only in design docs / C internals, not reachable from JS. Cited to its design source.

Unless a row says otherwise, wasm and node share the symbol at the same d.ts line family. Binding-differing rows are called out in bold text inside each subsection.

---

## 1. Machine: creation and lifecycle

`Node` is the machine handle. **Node bindings differ on construction:** wasm has a static factory `Node.create(adminId, options)` (async, `bindings/wasm/index.d.ts:774`); node has a constructor `new Node(adminId, options)` (`bindings/node/index.d.ts:641-643`) — there is no `Node.create` on the node binding.

**`destroy()` also differs**: wasm `Node.destroy()` (`bindings/wasm/index.d.ts:770`) is explicit and tested (`smoke.js:135`); the node `.d.ts` declares no `Node.destroy` — the C machine follows the wrapper's lifetime (see the sibling-wrapper clock caveat at `bindings/node/index.d.ts:545-553`).

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.create` | factory (wasm only) | `create(adminId, options?) -> Promise<Node>` | `bindings/wasm/index.d.ts:774` | STABLE (`smoke.js:6`) |
| `new Node` | constructor (node only) | `new Node(adminId, options?)` | `bindings/node/index.d.ts:642` | STABLE (`test/test.js:31`, lineage_smoke.mjs:47) |
| `Node.destroy` | method | `destroy()` | `bindings/wasm/index.d.ts:770` | STABLE (`smoke.js:135`) |
| `Node.serialize` | method | `serialize(options?) -> Uint8Array\|Buffer` — `{sealKey: '64-hex'}` = sealed family (needs live MSK), `{signed: true}` = node-key ECDSA trailer (needs node key), both combined = sealed+signed; bare call stays the plain checksummed snapshot | wasm `index.d.ts:729`, node `index.d.ts:548` | STABLE (`test/test.js:116`, `bindings/wasm/test/state-restore.js`) |
| `Node.deserialize` | method (both bindings) | `deserialize(wire, {sealKey?, verify?}) -> {authorityRestored, mskSectionPresent}` — REPLACES the wrapper's machine with the restored state (the same wrapper stays usable; node destroys the previous machine unless adopted; wasm drops the reference — wasm machines are never destroyed). Signed blobs load ONLY through `verify:'node-key'` (ECDSA checked BEFORE parse); a sealed restore needs `sealKey` — a wrong key still loads on the substrate-only compat path with a FRESH authority and reports `authorityRestored: false`. Continuity: node key, change hook, time source and raft module ride over; so do the ordering config and the HLC clock state (the restored machine's clock CONTINUES the previous machine's HLC). A destroyed (wasm) wrapper refuses both mergeState and deserialize | wasm `index.d.ts:755`, node `index.d.ts:575` | STABLE (`bindings/wasm/test/state-restore.js`, `test/test.js` P1 block) |
| `Node.mergeState` | method (both bindings) | `mergeState(wire) -> undefined` — `crdt_merge_state` into this machine: counters max-per-node / sum-across-nodes, register LWW (timestamp then node id), OR/2P-set union; logs dedupe by uuid; malformed wire throws, machine untouched. Held items are NOT a failure — content without a merge dispatch (OT types) surfaces as `__merge_held__` change events and the merge returns SUCCESS | wasm `index.d.ts:768`, node `index.d.ts:588` | STABLE (`bindings/wasm/test/state-restore.js`, `test/test.js` P1 block) |
| `Node.getNodeKey` | getter | `getNodeKey() -> NodeKey{publicKeyHex, privateKeyHex}` | wasm :479, node :312 | STABLE (`test/test.js:35`) |
| `Node.setPolicy` | method | `setPolicy(opType, expression)` | wasm :638, node :450 | STABLE (`smoke.js:17`) |
| `Node.adminId` | property (wasm) | `readonly adminId: string` | `bindings/wasm/index.d.ts:767` | STABLE (`test/raft.js` peers default via `adminId`; setPolicy paths) |

`NodeOptions = { ordering: 'hlc'|'lamport', strategy: 'naive'|'bounded'|'quorum'|'strict'|'trusted' }` — wasm:348-351 / node:271-274; `{ordering:'hlc'}` tested (`smoke.js:6`, `test/test.js:31`), `strategy` values untested → PRESENT.

## 2. Users, roles, attributes (registerUser, tokens)

`grantRole` is the admin path for privileged attributes: `registerUser` rejects privileged attribute names (audit R7-08), so a role is granted afterward — `smoke.js:8-11`.

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.registerUser` | method | `registerUser(userId, publicKeyHex, initialAttrs?)` | wasm :480, node :304 | STABLE (`smoke.js:10`) |
| `Node.grantRole` | method | `grantRole(targetUser, role, value, signerId)` | wasm :481, node :305 | STABLE (`smoke.js:11`) |
| `Node.revokeUser` | method | `revokeUser(userId, signerId?)` | wasm :482, node :308 | STABLE (`getuser-readback.js` + recipe 15 snippets: the terminal status + the bumped `keyVersion` are real readbacks) |
| `Node.selfAssert` | method (**node only**) | `selfAssert(attribute, value, signerId)` | `bindings/node/index.d.ts:306` | STABLE (`test/test.js:97`) |
| `Node.verifyIdentity` | method (**node only**) | `verifyIdentity(targetUser, attribute, value, signerId)` | `bindings/node/index.d.ts:307` | PRESENT (no test found) |
| `Node.getUser` | query | `getUser(userId) -> UserInfo \| undefined` | wasm :488, node :311 | STABLE (`smoke.js:40`, `getuser-readback.js`) |
| `UserInfo` | interface | `{userId, publicKeyHex, keyVersion, status, attributes[]}` | wasm :277-288, node :142-152 | STABLE (`getuser-readback.js` — keyVersion/status/publicKeyHex/verifiedBy are REAL readbacks on BOTH bindings now: wasm maps them in `bindings/wasm/bindings-core.js:895-952`, node in `bindings/node/src/crabs_node.cc:1567-1601`; the former wasm display stubs are gone) |
| `UserInfo.attributes[].verifiedBy` | field | attribute provenance string | wasm :284, node :149 | STABLE (`getuser-readback.js`; recipe 15 snippets) |
| `Node.pruneExpiredTempAttrs` | method | `pruneExpiredTempAttrs() -> number (wasm) / void (node)` | wasm :712, node :537 | PRESENT |

**Tokens / key lifecycle**: `UserInfo.keyVersion` (wasm :280, node :145) is the JS-visible key-version read — REAL on BOTH bindings (wasm mapped in `bindings/wasm/bindings-core.js:895-952` after the readback fix pinned by `getuser-readback.js`; node mapped in `bindings/node/src/crabs_node.cc:1147`). The keyring lifecycle is now JS-reachable user-id-scoped: `suspendKey` / `activateKey` / `rotateKey` + the `listKeys` / `getDefaultKey` readbacks (wasm d.ts :525-529, node d.ts :351-358; wasm mapped in `bindings/wasm/bindings-core.js:931-1038` over the user_t-scoped primitives `user_key_suspend/activate/rotate` — `src/Attribute/attribute_machine.h:219-221` — resolved via `attribute_machine_find_user`; node direct-C in `crabs_node.cc:1593-1758`). The C primitives carry NO signer gate by design (the wire ops `__suspend_key__` / `__activate_key__` / `__rotate_key__` own the policy story); pinning: `bindings/wasm/test/keyring.js` + the keyring block in node `test/test.js`. Honest residual: `user_key_revoke` / `user_key_set_default` have no method form (the wire ops `__revoke_key__` / `__set_default_key__` cover them power-side), and ops that DECLARE a keyring key on the signature (op `key_id`/`scheme`, crypto.c:1349-1371) remain C-only — binding ops ride the legacy stamp until a keyring exists, after which they refuse fail-closed (`unauthorized`, R8-C-2; pinned in keyring.js).

## 3. Policy surface (setPolicy, role grants)

Policies are condition expressions over attributes: `"AND role:member adult"` (`smoke.js:17`). `grantRole` installs `role:<value>` attributes (§2). Typed errors on execution include `resource_not_found` and `condition_not_met` (`bindings/node/src/crabs_node.cc:98,103`).

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.setPolicy` | method | `setPolicy(opType, expression)` | wasm :638, node :450 | STABLE (`smoke.js:17`) |
| `Node.execute` | method | `execute(op)` — throws typed errors (a group-ordered write with an attached raft module resolves as the two-phase ACCEPTANCE, ORDERING_PENDING — §11) | wasm :656, node :464 | STABLE (`smoke.js:27`) |
| `Node.sign` | method | `sign(op, key: KeyPair \| privateKeyHexString)` | wasm :657, node :463 | STABLE (`smoke.js:26`) |
| `Node.revokeRole` | method (parity-fill P3, **both bindings**) | `revokeRole(targetUser, role, signerId?)` — attribute-NAME match, no value (C takes (target, role, signer), `attribute_machine.h:145-147`); works on suspended/REVOKED targets by design (R4-4 decommission path); ADMIN-GATED (active + role:admin signer); bumps the target's `keyVersion` | wasm `index.d.ts:534` (`bindings-core.js:1057-1066`), node `index.d.ts:352` (`crabs_node.cc:1783`) | STABLE (`bindings/wasm/test/roles-admin.js`: strip + absent-role/unknown-user + non-admin + revoked-target pins; node `test/test.js` admin block) |
| `Node.suspendUser` | method (parity-fill P3, **both bindings**) | `suspendUser(userId, signerId?)` — recoverable suspension; REVOKED target refuses (terminal, R8-C-4); bumps the user's `keyVersion` (:878) and kills every pre-suspension stamp | wasm `index.d.ts:541` (`bindings-core.js:1067-1077`), node `index.d.ts:359` (`crabs_node.cc:1798`) | STABLE (`roles-admin.js` + node admin block — suspended signer refuses, keyVersion bump, revoked-target refusal, self-lockout `user_suspended` word) |
| `Node.activateUser` | method (parity-fill P3, **both bindings**) | `activateUser(userId, signerId?)` — the key-compromise recovery path; ACTIVE/REVOKED targets refuse `invalid_param`; SECOND `keyVersion` bump (R8-A-5) → ops stamped pre-suspension replay into genuine `key_stale` (pinned from JS in `roles-admin.js`) | wasm `index.d.ts:548` (`bindings-core.js:1079-1089`), node `index.d.ts:366` (`crabs_node.cc:1812`) | STABLE (`roles-admin.js` + node admin block) |

Condition expression grammar lives in `src/Condition/`; `attribute` change events kind `'attribute'` are emitted on grants (`change-events.js:44-52`).

## 4. CRDT surface — counters, sets, registers, RESOURCE items

Shared creation/query API (both bindings except where marked). **Node `.d.ts` differs**: node exposes only `setContains`; the bounded enumerator (`getSetSize` / `getSetElements` / `getSetTags`) and the register byte API (`setRegisterBytes` / `getRegisterBytes`) are **wasm-only**.

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.addCounter` | method | `addCounter(name)` — G-counter | wasm :490, node :315 | STABLE (`smoke.js:13`) |
| `Node.addPNCounter` | method | `addPNCounter(name)` | wasm :491, node :316 | STABLE (`smoke.js:14`) |
| `Node.addORSet` | method | `addORSet(name)` | wasm :492, node :317 | STABLE (`smoke.js:15`) |
| `Node.addOneShotSet` | method | `addOneShotSet(name)` | wasm :493, node :318 | STABLE (`test/test.js:53`; wasm declared only) |
| `Node.addOneShotFlag` | method | `addOneShotFlag(name)` | wasm :494, node :319 | STABLE (`test/test.js:54,112-113`) |
| `Node.addRegister` | method | `addRegister(name, initialValue?)` | wasm :495, node :320 | STABLE (`registers.js:13`) |
| `Node.incrementCounter` | method | `incrementCounter(name, delta?, nodeId?)` | wasm :586, node :396 | STABLE (`smoke.js:28`) |
| `Node.incrementPNCounter` | method | `incrementPNCounter(name, delta?, nodeId?)` | wasm :587, node :397 | STABLE (wasm test path; node declared) |
| `Node.decrementPNCounter` | method | `decrementPNCounter(name, delta?, nodeId?)` | wasm :588, node :398 | PRESENT (no test found) |
| `Node.getCounter` | query | `getCounter(name) -> number` | wasm :554, node :382 | STABLE (`smoke.js:39`) |
| `Node.getPNCounter` | query | `getPNCounter(name) -> number` | wasm :555, node :383 | PRESENT |
| `Node.getRegister` | query | `getRegister(name) -> number` | wasm :556, node :384 | STABLE (`registers.js:51`) |
| `Node.setRegister` | method | `setRegister(name, value, nodeId?)` | wasm :563, node :392 | STABLE (`registers.js:50`) |
| `Node.setAdd` | method | `setAdd(name, element, tag?)` | wasm :590, node :401 | STABLE (`test/test.js:87`) |
| `Node.setRemove` | method | `setRemove(name, element)` | wasm :591, node :402 | STABLE (`handler-reads.js:79`) |
| `Node.setContains` | query | `setContains(name, element) -> boolean` | wasm :567, node :393 | STABLE (`test/test.js:88`) |
| `Node.flagSet` | method | `flagSet(name, setBy, setAt?)` — one-shot flag | wasm :592, node :403 | STABLE (`test/test.js:112`) |
| `Node.flagValue` | query | `flagValue(name) -> boolean` | wasm :593, node :404 | STABLE (`test/test.js:113`) |

**LWW registers — int64/BigInt handling (R5, R15).** Registers carry a signed int64. Both bindings accept integers within ±`Number.MAX_SAFE_INTEGER` and reject fractions/NaN/Infinity (consumption finding 1; `registers.js:30-46`, node `test/test.js:555-578`). The wasm binding additionally accepts `BigInt` for the full int64 range (`bindings/wasm/index.d.ts:262-263`; `registers.js:60-67`: `2**60 BigInt round-trips`, and inside handlers at `registers.js:91`); **the node binding accepts numbers only** — full int64 range requires crabs-wasm (`bindings/node/index.d.ts:227-234`). C source: `src/StateMachine/state_machine.h`.

**wasm-only pagination + register bytes:**

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.getSetSize` | query (wasm only) | `getSetSize(name) -> number` — distinct live elements | `bindings/wasm/index.d.ts:572` | STABLE (`handler-reads.js:36`) |
| `Node.getSetElements` | query (wasm only) | `getSetElements(name, {offset?, limit?<=256}) -> string[]` — sorted strcmp, snapshot semantics | `bindings/wasm/index.d.ts:582` | STABLE (`handler-reads.js:39-46`) |
| `Node.getSetTags` | query (wasm only) | `getSetTags(name, element) -> string[]` — live tags of an OR-set element | `bindings/wasm/index.d.ts:584` | STABLE (`handler-reads.js:68-74`) |
| `Node.getRegisterBytes` | query (wasm only) | `getRegisterBytes(name) -> Uint8Array` — raw register payload | `bindings/wasm/index.d.ts:566` | STABLE (`handler-reads.js:88-90`) |
| `Node.setRegisterBytes` | method (wasm only) | `setRegisterBytes(name, bytes, nodeId?)` — byte-exact inverse | `bindings/wasm/index.d.ts:564` | STABLE (`handler-reads.js:89,108`) |
| `setRemove` tombstone/`GetSetElementsOptions` behavior | contract | removal leaves tombstones; size counts live only | `bindings/wasm/index.d.ts:164-244` | STABLE (`handler-reads.js:80-83`) |

**RESOURCE items, locks and the tx manager (R9):**

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.addResource` | method | `addResource(name, initial?)` — the lock-capable `DATA_TYPE_RESOURCE` item ("PN-Counter + lock", raw int64 value) | wasm :502, node :328 + :325-327 docs | STABLE (`locks-tx.js`; node `test/locks-tx.js`) |
| `Node.getResource` | query | `getResource(name) -> number` — raw int64 balance readback (wasm throws `resource_not_found`/`type_mismatch`; node returns undefined for unknown, throws for non-RESOURCE) | wasm :509, node :337 | STABLE (`locks-tx.js`) |
| `Node.getLockState` | query | `getLockState(name) -> LockStateView` — `protocolState` word (`idle`/`locked`/`modified`/`verified`/`error`), `lockOwner`, `lockTokenHex` (the 32-byte CSPRNG bearer token, '' when unset), `lockExpiry`, `lockExtensions` | wasm :517 + LockStateView :258, node :344 + LockStateView :17 | STABLE (`locks-tx.js`) |
| `Node.attachTxManager` | method | `attachTxManager('memory' \| 'none')` — attaches the replay-protection manager (`src/TxManager/tx_manager.h:19-41` vtable; memory impl `src/TxManager/tx_manager_memory.h:16`) to `state->tx_manager` (`src/CRABS/data_model.h:486`); step 3b refuses duplicates `already_executed` (`src/StateMachine/state_machine.c:1600-1620`) | wasm :528, node :357 | STABLE (`locks-tx.js` duplicate-submission scenario) |

## 5. One-shot sets / flags and dedup (R2, R3)

One-shot sets and flags are added like any item (`addOneShotSet` / `addOneShotFlag`, §4) — their "once" semantics come from the DedupSpec machinery in C, and `Node.defineOperationType` installs a spec on the machine registry from BOTH bindings (`'custom'`-conditioned specs + their spec-carried mutations stay C-native: the bindings surface only the machine-enforceable per-user / global / none shapes):

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.addOneShotSet` | method | item whose elements can be inserted once per dedup scope | wasm :493, node :318 | STABLE (node test; wasm declared) |
| `Node.addOneShotFlag` | method | one-shot boolean | wasm :494, node :319 | STABLE (`test/test.js:112`) |
| `Node.defineOperationType` | method | `defineOperationType(opType, { dedup: 'per-user' \| 'global' \| 'none', trackerPath?, flagPath?, rejectionMessage? })` | wasm :649 + docs :645-648, node :462 | STABLE (`bindings/wasm/test/dedup-surface.js`, `test/test.js:659`) |
| `DefineOperationTypeOptions` | interface | `{dedup, trackerPath?, flagPath?, rejectionMessage?}` | wasm :324-345, node :242-266 | STABLE (same tests) |
| `dedup_check_guard` | C fn | `dedup_check_guard(state, op) -> crabs_error_e` | `src/Dedup/dedup.h:21-22` | PRESENT in C; the executor resolves REGISTERED specs via `state_find_op_type_def` — a registered spec wins over whatever the op carries (register + bypass-refusal pinned in `test/test_state_machine.cpp` `DefineOperationTypeExecutesThroughMachine`) |
| `state_register_op_type_def` | C fn | `state_register_op_type_def(state, op_type, dedup_spec_t*)` | `src/CRABS/data_model.h:794` | PRESENT; reachable from both JS bindings via `Node.defineOperationType` (first-match update in place — re-defining REPLACES the spec, capacity 32 at `data_model.h:379`) |

`DedupSpec` types (`dedup_type_e`, `dedup_spec_t`) at `src/CRABS/data_model.h:333-338,363-374`; the op format carries a `dedup_spec` since wire v3 (`src/StateMachine/state_machine.h:61,99`).

## 6. Schedules and time sources (R7)

**All schedule methods exist on BOTH bindings** (wasm `bindings/wasm/index.d.ts:726-737`; node `bindings/node/index.d.ts:480-503` — ported from the wasm surface). The submission-time authorization gate in both wrappers runs `state_machine_validate` before queueing (wasm `src/Util/wasm_helpers.c:1509-1519`, node `bindings/node/src/crabs_node.cc:1902-1906`). A node-specific divergence: no `registerHandlerJs` on node, so a scheduled fire is observed as a kind-`schedule` change event, not a counter effect (node `test/test.js` schedule-surface block). HLC reads differ: node has `getHLC()` + an `HLC` interface (`bindings/node/index.d.ts:208-213,535`); wasm has no HLC getter (HLC identity shows up as `Node.adminId` / op `nodeId`).

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.schedule` | method | `schedule(innerOp, executeAtMs) -> bigint` | wasm :726, node :480 | STABLE (`schedules.js:25-35`; node `test/test.js` schedule block) |
| `Node.scheduleRecurring` | method | `scheduleRecurring(innerOp, startAtMs, intervalMs, repeatCount, endAtMs) -> bigint` | wasm :727-728, node :486-487 | STABLE (`schedules.js:60-66`; node test) |
| `Node.cancelSchedule` | method | `cancelSchedule(scheduleId: bigint \| number)` — number/bigint on node, bigint on wasm | wasm :729, node :489 | STABLE (`schedules.js:51`; node test) |
| `Node.processSchedules` | method | `processSchedules(nowMs?)` — defaults to the wall clock on both | wasm :730, node :495 | STABLE (`schedules.js:38-42`; node test) |
| `Node.setScheduleOccurrenceBudget` | method | `setScheduleOccurrenceBudget(maxPerTick)` — 0 = unlimited | wasm :733, node :497 | STABLE (`schedules.js:84`; node test) |
| `Node.scheduleOccurrenceBudget` | query | `scheduleOccurrenceBudget() -> number` | wasm :734, node :498 | STABLE (`schedules.js:85`; node test) |
| `Node.pendingSchedules` | query | `pendingSchedules() -> [{id, executeAt, intervalMs, repeatCount, endAt, submitter}]` (bigints) | wasm :735-737, node :500-503 | STABLE (`schedules.js:33-35,63-65`; node test) |
| `Node.setTime` | method | `setTime(nowMs)` | wasm :711, node :536 | STABLE (`lineage_smoke.mjs:48` node) |
| `Node.setTimeSource` | method | `setTimeSource({mode:'https'|'system', url?, resyncMs?, timeoutMs?, maxSkewMs?})` — fetch fails closed, no local-clock fallback | wasm :723, node :551 | STABLE (`time-source.js:37,54`; node `test/test.js:272`) |
| `Node.getTimeSource` | query | `getTimeSource() -> TimeSourceInfo` | wasm :724, node :552 | STABLE (`time-source.js:32,39-45`) |
| `Node.getHLC` | query (**node only**) | `getHLC() -> HLC \| undefined` | `bindings/node/index.d.ts:535` | STABLE (`test/test.js:81`) |

Timing semantics of the authenticated HTTPS time source (defaults 30000/1000/5000) and the wasm module-shared-vs-machine-local difference are documented in the d.ts prose: wasm `bindings/wasm/index.d.ts:353-371` (`TimeSourceOptions` module-shared; replacing the source re-attaches every machine), node `bindings/node/index.d.ts:276-295` (machine-local; destroying a sibling wrapper silently strips the clock — re-apply, `:545-553`). C source: `src/TimeSource/`. HLC C surface: `src/HLC/hlc.h:144,164` (`crabs_hlc_state_init`, `crabs_hlc_compare`) — PRESENT, used by recipes only via node `getHLC`.

## 7. Triggers (R6)

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.createTrigger` | method | `createTrigger(config: TriggerConfig)` | wasm :658, node :505 | STABLE (`test/test.js:165`) |
| `TriggerConfig` | interface | `{triggerId, condition, description?, effectType, issueAttribute?, targetRole?, attributeValue?, durationMs?, oneShot?, cooldownMs?}` (node adds `policyOperation`/`policyExpression` for `change_policy`) | wasm :295-313, node :224-238 | STABLE (`test/test.js:165`) |
| `Node.evaluateTriggers` | method (wasm only) | `evaluateTriggers()` | `bindings/wasm/index.d.ts:738` | PRESENT (no test found) |
| trigger effects in C | C fn | `state_machine_op_create_trigger` and the `__create_trigger__`-family ops (Amendment 1 §4) | `src/StateMachine/state_machine.h:200-201`, `src/Trigger/` | STABLE (C tests) |

**Binding difference on effect types:** wasm `TriggerConfig.effectType` is `'issue_attribute' | 'create_trigger' | 'delete_trigger' | 'disable_trigger' | 'change_policy'` (`bindings/wasm/index.d.ts:299`); node's union is only `'issue_attribute' | 'change_policy'` with explicit `policyOperation` / `policyExpression` fields (`bindings/node/index.d.ts:228`, 231-238). Oversized-field and adopted-child-wrapper refusals are typed (audits 9 A-1 / 10 A10-M3, `test/test.js:168-197`).

## 8. Custom handlers (registerHandlerJs, HandlerState)

**Custom handlers are wasm-only.** The node `.d.ts` has no `registerHandler*`, no `HandlerState`, and no `unregisterHandler` — node recipes drive state directly (`node.sign` + `node.incrementCounter`, `test/test.js:66-78`). Engine behavior: handler-less, resource-less custom ops are no longer silently no-oped — execution throws `resource_not_found` (`smoke.js:19-21,84-101`).

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.registerHandlerJs` | method (wasm only) | `registerHandlerJs(opType, (state: HandlerState, op: HandlerOperation) -> number)` | `bindings/wasm/index.d.ts:683` | STABLE (`smoke.js:59`; re-registration replaces, `smoke.js:71-81`) |
| `Node.unregisterHandler` | method (wasm only) | `unregisterHandler(opType)` | `bindings/wasm/index.d.ts:684` | STABLE (`smoke.js:83-102`) |
| `Node.registerHandler` | method (wasm only) | `registerHandler(opType, (statePtr, opPtr) -> number)` — low-level raw WASM pointers | `bindings/wasm/index.d.ts:681` | PRESENT (high-level variant is what tests use) |
| `HandlerState` | interface (wasm only) | mutation + read proxy: `incrementCounter`, `incrementPNCounter`, `decrementPNCounter`, `setRegister` (int/BigInt, integer-only), `setRegisterBytes`, `setAdd`, `setRemove`, `flagSet`, `getCounter`, `getPNCounter`, `getRegister`, `getResource`, `adjustResource` (recipe 9), `getRegisterBytes`, `setContains`, `getSetSize`, `getSetElements`, `getSetTags` | `bindings/wasm/index.d.ts:194-266` | STABLE (`registers.js:83-100`, `handler-reads.js:104-126`, `locks-tx.js` transfer handler) |
| `HandlerState.getSetElements` inside a handler | method (wasm only) | same as Node's, same 256-hard-cap → `getSetElements(name, {limit:999})` throws inside handlers too | `bindings/wasm/index.d.ts:243` + `handler-reads.js:139-146` | STABLE |
| `HandlerOperation` | interface (wasm only) | `{type, signerId, nodeId, payload?: string, resources: string[]}` — `resources` are the op's declared resource names (recipe 9's transfer handler resolves the pots through them) | `bindings/wasm/index.d.ts:268-278` | STABLE (`smoke.js:59-63`, `locks-tx.js` transfer handler) |

## 9. ABE encryption + machine-side keygen/decrypt (R6, R15)

Both bindings carry the full seal/open round trip. **Trust shape:** the
CP-ABE master key is machine-held (`state->abe_mk`,
`src/CRABS/data_model.h`; wired at `src/Attribute/attribute_machine.c:309`)
— no JS handle for it exists and no portable reader-key bytes ship in v1:
`abeKeygen` derives a key from the machine's OWN authority (whoever
controls the machine can mint a reader key for any attribute set it names;
`crypto_abe_keygen` consults no user record), and `AbeKey` is a destroyable
JS-owned wrapper (idempotent `destroy()`, like `KeyPair`).

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.encrypt` | method | `encrypt(payload: Uint8Array\|string (wasm) / Buffer (node), policy: string) -> ABE container` | wasm :686, node :508 | STABLE (`smoke.js:115`) |
| container layout | contract | u16le policy byte length (UTF-8 bytes, not UTF-16 units) + policy bytes + u32le ciphertext length + ciphertext | `bindings/wasm/index.d.ts:686` (signature) + `bindings/wasm/test/smoke.js:111-130` (layout round-trip) | STABLE |
| `Node.abeKeygen` | method | `abeKeygen(attrs: string) -> AbeKey` — attrs = the comma-separated CRABS token list; the ':' → '_' / ',' → '\|' token map applies machine-side (`src/Crypto/crypto.c:98-111`), so the seal policy must carry the mapped words (`'role:member'` key ↔ `role_member` policy word) | wasm `index.d.ts:698` (`bindings/wasm/bindings-core.js`), node `index.d.ts:520` (`crabs_node.cc:3078`) | STABLE (`abe-decrypt.js`, node `test/abe.js` — round trip + refusals + token map) |
| `AbeKey` | class (both bindings) | destroyable wrapper around the machine-derived `abe_user_key_t*`; portable bytes via `AbeKey.toWire()` (below) | wasm `index.d.ts:57-67`, node `index.d.ts:32-50` | STABLE (destroy idempotence pinned by both tests) |
| `Node.abeDecrypt` | method | `abeDecrypt(key: AbeKey, encrypted: container) -> Uint8Array (wasm) / Buffer (node)` — parses the container, rebuilds the ciphertext (`crypto_abe_ciphertext_load`, `src/Crypto/crypto.h:129`), decrypts; refuses with the typed `unauthorized` when the key's attributes do not satisfy the policy (also the tamper path, GCM fail-closed); malformed containers refuse at the binding boundary | wasm `index.d.ts:708`, node `index.d.ts:529` | STABLE (`abe-decrypt.js` / node `test/abe.js`: right-attrs decrypt, wrong-attrs + partial-clause + tampered refusals) |
| `AbeKey.toWire` | method (both bindings, parity-fill P4) | `toWire() -> Uint8Array (wasm) / Buffer (node)` — the portable user-key wire (`crypto_abe_user_key_serialize`, `src/Crypto/crypto.c:872`). SELF-SUFFICIENT BEARER image: it carries the key's own minting domain (restored on any machine — even one holding a different authority — it opens exactly what its minting authority sealed and refuses others; pinned cross-machine) and has NO integrity check — carry it authenticated | wasm + node `index.d.ts` `AbeKey` | STABLE (`key-transport.js` / node `test/abe.js`: round trip == capability, wrong-attrs refusal, bearer cross-machine semantics, destroyed-key refusal) |
| `Node.abeKeyFromWire` | method (both bindings) | `abeKeyFromWire(bytes) -> AbeKey` — restores a `toWire` image through `crypto_abe_user_key_deserialize` (`crypto.h:144`). The C signature takes the master key (its header says "the master key provides the public params"), so the restore gates on the machine's authority — but the CAPABILITY is the wire's own (OpenABE's key import binds to the minting domain, not the importing machine — verified cross-authority in both tests). Cross-wire confusion refuses typed: a wire wearing the 'MK' master-key magic is an authority image, not a reader key (`invalid_param`) | wasm `index.d.ts` ABE transport block, node same | STABLE (same pins + the cross-wire refusal) |
| `Node.mintKeyEnvelope` | method (both bindings) | `mintKeyEnvelope(userId, options?: {expiresAt?}) -> envelope wire` — the refresh_key materialization shape (`state_machine.c:2797`) without the protocol bookkeeping: real CP-ABE key for the user's CURRENT attributes (one value per attribute NAME), node-ECDSA-signed, key ECIES-wrapped to the registered public key (audit H-A); gates mirrored from refresh (ACTIVE-only → `user_suspended`/`user_not_found`, live node key + authority); mutates nothing (no key_version bump — the transport primitive, not the refresh op). Wire = `crypto_key_envelope_serialize` flat form (`crypto.h:282-292`) | wasm + node `index.d.ts` | STABLE (`key-transport.js` / node `test/abe.js`: envelope round trip, ACTIVE gate, unknown user refusal) |
| `Node.decryptKeyEnvelope` | method (both bindings) | `decryptKeyEnvelope(envelope, {privateKeyHex, nodePublicKeyHex?}) -> AbeKey` — parse → verify ISSUER's ECDSA → open the ECIES blob with the recipient key → import (the C KeyEnvelope battery's flow, `test_crypto.cpp:963-1032`). Both tamper paths fail closed typed `unauthorized` (wire tamper → signature; wrong recipient / blob tamper → GCM tag). The recovered plaintext key never leaves C (cleansed inside the staging frame on every path). `nodePublicKeyHex` verifies cross-machine (default: the machine's own node key — a foreign envelope refuses fail-closed; wasm's `getNodeKey` exposes no node key, so the explicit-issuer open is node-pinned only) | wasm + node `index.d.ts` | STABLE (`key-transport.js` / node `test/abe.js`: wrong-recipient, wire-tamper and wrong-issuer refusals; node additionally opens a foreign envelope with the issuer key) |
| `Node.serializeMasterKey` / `Node.masterKeyFromWire` | methods (both bindings) | `serializeMasterKey() -> wire` / `masterKeyFromWire(wire)` — the §11.5 durability backup (`crypto_master_key_serialize/deserialize`, `crypto.h:156-160`; C round trip `test_crypto.cpp:1199-1256`). CROWN JEWEL trust step: whoever holds these bytes mints keys for ANY policy and decrypts EVERYTHING the authority ever sealed — the d.ts prose says exactly that. `masterKeyFromWire` REPLACES the machine's authority (the serialization.c:2864 recovery path): restored authority mints keys in the same domain (pinned); garbage / bad-magic / overrun-length wire refuses `invalid_param`; a borrowed authority refuses `protocol_violation` on BOTH surfaces (the child uses the parent's MSK pointer, it is not entrusted with the MSK bytes at rest — serialize-side and replace-side, pinned in both tests) without mutating. Staging note: wasm's restore still leaks the replaced authority's CONTEXT (wasm OpenABE teardown hazard — the `crabs_wasm_node_destroy` rationale, documented at the export) but its serialized MPK/MSK wire copies are cleansed + released before the pointer swap (`crypto_abe_master_key_cleanse_wire_copies`); the native binding destroys + cleanses the whole replaced authority. Copy-out of `toWire()`/`serializeMasterKey()` staging is a cleansed destroy on both paths | wasm + node `index.d.ts` | STABLE (`key-transport.js` / node `test/abe.js`: durability round trip into a fresh machine, garbage + shape-confusion refusals, borrowed-authority refusals) |

C surface: `crypto_abe_setup` etc. at `src/Crypto/crypto.h:96-137` — the JS
rows above are the supported path; the keyring lifecycle
(`user_key_suspend/activate/rotate`) is user-id-reachable from JS now
(api-map §2 — `suspendKey`/`activateKey`/`rotateKey` + `listKeys`), and the
serialized-key transport (reader-key wire, key envelopes, master-key
durability backup) is JS-reachable too (parity-fill P4, rows above).

## 10. Lineage: Blueprint, spawn, attest, tombstone (R11, R12)

Machines mint machines (v1.7). **The biggest wasm/node divergence:** wasm `lineageSpawn` returns an **opaque borrowed C pointer** (`number`), while node returns a **full Node wrapper** that borrows the machine. Child lifetimes are anchored by the parent's resident-children registry in C in both cases.

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Blueprint.create` | factory | `create(childId, trustMode, bootstrapAdmin, ttlMs) -> Promise<Blueprint>`  (wasm + node: `bindings/node/index.d.ts:192`) | `bindings/wasm/index.d.ts:149-150` | STABLE (`lineage_smoke.mjs:54`) |
| `new Blueprint` | constructor (node only) | `new Blueprint(childId, trustMode, bootstrapAdmin, ttlMs)` or `new Blueprint(wire)` | `bindings/node/index.d.ts:176-193` | STABLE (`test/test.js:132`) |
| `Blueprint.deserialize` | static | wasm: `Promise<Blueprint>`; node: sync | wasm :151, node :194 | STABLE (`lineage_smoke.mjs:62`) |
| `Blueprint.addItem` | method | `addItem(name, dataType, crdtType)` — wasm takes numbers only (`bindings/wasm/index.d.ts:137`); node accepts words or numbers (`bindings/node/index.d.ts:178`) | both | STABLE (`wasm lineage_smoke.mjs:43`) |
| `Blueprint.addPolicy` | method | `addPolicy(operation, expression)` — `@parent/` endorsement tokens validate (lineage.c grammar) | wasm :140, node :180 | STABLE (`lineage_smoke.mjs:44`, recipe 12 snippets) |
| `Blueprint.stampHash` | method | `stampHash()` | wasm :142, node :182 | STABLE (`lineage_smoke.mjs:45`) |
| `Blueprint.serialize` | method | `serialize() -> Uint8Array\|Buffer` — u32le length + body + 32-byte hash | wasm :144, node :184 | STABLE (`lineage_smoke.mjs:48`) |
| `Node.lineageInstall` | method | `lineageInstall()` — registers lineage ops + default admin policies, idempotent | wasm :744, node :556 | STABLE (`lineage_smoke.mjs` both) |
| `Node.lineageSpawn` | method | wasm: `lineageSpawn(blueprint) -> number` (opaque ptr); node: `lineageSpawn(blueprint) -> Node` (borrowed wrapper) | wasm :746, node :562 | STABLE (`lineage_smoke.mjs:54/66`) |
| `Node.lineageResidentChild` | query | wasm: `-> number \| null`; node: `-> Node \| null` | wasm :748, node :566 | STABLE (`test/test.js:184`) |
| `Node.childCount`, `childIndex`, `childAt`, `childById`, `children` | manifest reads (**wasm only**; wasm names) | flat manifest accessors | `bindings/wasm/index.d.ts:750-757` | STABLE (`wasm lineage_smoke.mjs:60-76`) |
| `Node.lineageChildren` | manifest read (**node only**) | `lineageChildren() -> ChildManifestEntry[]` | `bindings/node/index.d.ts:564` | STABLE (node lineage_smoke.mjs:86) |
| `Node.attest` (wasm) / `Node.lineageAttest` (node) | method | `attest(lineageAttest)(childId, userId, attributes) -> wire bytes` — parent-signed TTL attribute grant; needs authenticated time; wasm `attest` takes 3 args (`index.d.ts:759`), node `attributes` optional (`index.d.ts:572`) | both | STABLE (`wasm lineage_smoke.mjs:82`, node lineage_smoke.mjs:104) |
| `Node.lineageTombstone` | method | `lineageTombstone(childId) -> Uint8Array\|Buffer` — canonical body (u8 tag + string16 childId + u64le parent_key_version) + 64-byte parent sig, NO length prefix; fails closed for live children | wasm :764, node :580 | STABLE (`lineage_smoke.mjs:155/170`) |
| `ChildManifestView` (wasm) / `ChildManifestEntry` (node) | interface | wasm `{childId, mode, status, ttlMs, spawnedAt}`; node `{childId, mode, status, spawnedAtMs, attestationTtlMs}` | wasm :154-161, node :198-204 | STABLE |
| `TRUST_MODE` | const | `{SHARED_ROOT: 1, DELEGATED_COPY: 2, SOVEREIGN: 3}` — node also accepts word aliases `'shared_root'|'shared'|'delegated_copy'|'delegated'|'sovereign'` | wasm :127-131, node :159-166,651-656 | STABLE (`lineage_smoke.mjs:54`) |
| dissolution / receive ops | op types | `__dissolve_machine__`, `__receive_dissolution__`, `__spawn_machine__`, `__revoke_attestation__`, `__withdraw_genesis__` | `src/Lineage/lineage.h:4-5`; used at wasm lineage_smoke.mjs:100, node lineage_smoke.mjs:127,207 | STABLE |
| `Operation.addAttestation` | method | `addAttestation(fields: AttestationFields) -> this` — stage one parent-signed vouch onto the op for a `@parent/` endorsement policy; fields parsed from `attest`'s wire (canonical body in `src/Lineage/lineage.c`); `signatureHex` must be 128 hex chars (CRABS_SIG_SIZE) or the attach refuses; identical name both bindings | wasm :111 (`bindings/wasm/bindings-core.js:498`), node :125 (direct `op_->attestations` fill, `crabs_node.cc:870-979`) | STABLE (`attestations.js` both bindings; recipe 12 snippets) |
| `AttestationFields` | interface | `{parentId, childId, userId, attributes, notBefore?, expiresAt?, parentKeyVersion (required, the chain TIP stamp), signatureHex (128 hex)}`; wasm optional numerics accept `number | bigint`, node accepts `number` only — a real binding divergence | wasm :9-24, node :52-66 | STABLE |
| attestation VERIFICATION | executor pipeline (C) | the executor re-verifies every carried attestation per op vs the chain TIP (`attestation_verify_by_lineage_key` `src/Lineage/lineage.h:654-670`, `_verify_parent_endorsements` `src/StateMachine/state_machine.c:709-762`, exact coverage `:663-689`); NO JS verifier surface — `attestation_deserialize` (`src/Lineage/lineage.h:666`) stays C-only, JS verifies by EXECUTING | C-only (by design) | STABLE (engine-tested `test/test_lineage.cpp`, recipe 12 batteries) |

Wire version `CRABS_ATTESTATION_FORMAT_VERSION 0x02` (`src/Lineage/lineage.h:32`), body cap 512 (`:38`).

## 11. Write domains (R10, R13)

Write-domains v1: items declare a domain at mint — `'free' | 'sovereign' | 'group'` — immutable on a live item; sovereign items must also name their `writer`; `group` items take `orderingModule`, which must match the machine's attached raft module (the only module id the mint path accepts is 0 — a non-zero value is refused at creation, `src/CRABS/data_model.c:161-172` — and the raft module the machine attaches resolves id 0, §17 R14).

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.defineItem` | method | `defineItem(name, dataType, crdtType, options?: DefineItemOptions)` — typed refusals: sovereign-without-writer, writer-on-free, unknown domain, non-legal type | wasm :535 (options :309-316), node :363 (options :214-221) | STABLE (`write-domains.js:23-59`, node `test/test.js:353ff`) |
| `Operation.setSovereignPrefix` | method | `setSovereignPrefix(prefixIndex, seq, digest: 64-hex \| 32 raw bytes (wasm))` — signed in format v4, wire-carried in op format v6; set BEFORE signing | wasm :75, node :90 | STABLE (`write-domains.js:71-104`) |
| `Node.itemChainHead` | query | `itemChainHead(name) -> {seq, digestHex}` — full 32-byte hex; `resource_not_found` on unknown item | wasm :544, node :371 | STABLE (`write-domains.js:80-96`) |
| `Node.reportEquivocation` | method | `reportEquivocation(itemName, opABytes, opBBytes)` — files `__report_equivocation__`; quarantines the writer; failure modes typed (`invalid_param`, `resource_not_found`, `duplicate_operation`) | wasm :551, node :379 | STABLE (`write-domains.js:124-145`, node `test/test.js:493-540`) |
| quarantine enforcement | contract | a quarantined writer's next op throws `quarantined`; a non-writer op throws `not_item_writer` | `write-domains.js:106,132`; node `test/test.js:462,493` | STABLE |

Domain error taxonomy (`CRABS_ERR_NOT_ITEM_WRITER` etc.) maps in `bindings/node/src/crabs_node.cc:111`.

**Raft ordering module (R14) — the group-ordered surface's engine.** The
module is a pure C reactor (`crabs_raft_module_t`, `src/Raft/raft_module.h`)
the host drives through three replaceable seams (transport / storage /
timers); the JS reference host (wasm `RaftHost`, node `createRaftHost`) is
the shipped default wiring, and both bindings run 3-node E2E cluster suites
over it (election, partition + heal, crash recovery).

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.attachRaft` | method (both bindings) | `attachRaft(options) -> RaftHost` — attaches the raft module to the machine's state (`state_attach_raft_module`, `src/StateMachine/state_machine.h:260`); before any attach, group-item writes fail closed `ordering_path` (`src/CRABS/crabs.h:128`) | wasm `index.d.ts:670` (`RaftHostOptions` :377-392), node `:593-597` | STABLE (`test/raft.js` both bindings) |
| `RaftHost` reference host (wasm) | interface | `setRaftTransport` `:434` / `setRaftStorage` `:443` / `startRaftHost` `:446` / `raftTick` `:449` / `raftPump` `:451` / `raftPollOutbound` `:453` / `raftPollPersistRequest` `:455` / `raftPersistComplete` `:457` / `raftRecoverFromPersist` `:465` / `raftPollNotifications` `:471` / `moduleHandle` `:473` / `status` `:474` / `destroy` `:475` | `bindings/wasm/index.d.ts:427-476` | STABLE (`test/raft.js`: 3-node E2E, partition + heal, recovery) |
| `createRaftHost(node, options)` reference host (node) | module fn | mirrors wasm's host: transport/storage seams, `pumpInbound(peerId, blob)`, `raftPollNotifications()` raw mode (`pumpNotifications: false` — no handler surface exists on this binding), `status()`, `destroy()` | `bindings/node/index.js:91` (export :259; d.ts `:715-763`) | STABLE (`test/raft.js`) |
| `Node.raftTick` / `raftDeliver` / `raftPersistComplete` / `raftRecoverFromPersist` / `raftPump` / `raftPoll*` / `raftStatus` / `raftDetach` | raw methods (node; wasm exposes equivalents on the host) | the raw machine seams the reference host wraps | node `bindings/node/index.d.ts:597-638` | STABLE (raw-host mode pinned by `bindings/node/test/raft.js`) |
| two-phase submission | contract | a group op NEVER executes inline: no module → `ordering_path` (`src/CRABS/crabs.h:128`); module attached → accepted as a pending proposal (`ORDERING_PENDING`, `src/CRABS/crabs.h:131`; seam `src/StateMachine/state_machine.c:1526-1560`, propose route `:1246-1294`), materializing only on commit through `raftPump`/the notification pipeline | C seam (by design) | STABLE (`test/test_raft_sim.cpp:557` submits-commits-materializes; `:634` without module) |
| merge by committed position | contract | group-item merge adopts src's committed content by the module's commit tip (equal tips must agree; divergence is held, never combined) | `src/CRDT/crdt_merge.c:751-790` | STABLE (`test/test_raft_sim.cpp:1637`) |
| log caps | contract | 4096 entries × 16384 op-wire bytes; a proposal beyond the cap refuses in place (`RAFT_NOTIFY_LOG_FULL`), compaction deliberately deferred | `src/Raft/raft_module.h:55-59`, grow-model comment :33-46 | STABLE (`test/test_raft_module.cpp:1033`) |
| `Node.raftStatus` | query | `{nodeId, isLeader, term, commitTip, logLength, configChangePending, peerCount} \| null` (null = detached) | wasm :678 (RaftStatus :394-403), node :634 | STABLE (`test/raft.js` both) |

Members of the host types: `RaftStatus` :394, `RaftOutboundMessage` :405,
`RaftPersistRequest` :413, `RaftNotification` :419 (wasm). The C reactor
surface is directly exercisable in C (and the C sim harness drives it
headlessly — `test/test_raft_module.cpp`, `test/test_raft_sim.cpp`); no C
cookbook snippet exists because the reference host loop lives in JS — the
C integrator writes its own host (that is the transport-agnostic point).

## 12. Operation (sign / serialize / deserialize)

**Construction differs:** wasm `Operation.create(type)` is an async static (wasm :122; destroy `:118`, tested, `smoke.js:31-37`); node constructs synchronously with `new Operation(type)` (`bindings/node/index.d.ts:138-140`, `test/test.js:66`).

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Operation.create` | static (wasm) | `create(type: string) -> Promise<Operation>` | `bindings/wasm/index.d.ts:122` | STABLE (`smoke.js:23`) |
| `new Operation` | ctor (node) | `new Operation(type: string)` | `bindings/node/index.d.ts:138-140` | STABLE (`test/test.js:66`) |
| `Operation.deserialize` | static | wasm: async `deserialize(bytes) -> Promise<Operation>`; node `.d.ts` has no `Operation.deserialize` (node round-trips state, not ops) | `bindings/wasm/index.d.ts:123` | STABLE (`smoke.js:33`) |
| `Operation.serialize` | method | `serialize() -> Uint8Array\|Buffer` ("sign first, then serialize") | wasm :66, node :127 | STABLE (`smoke.js:31`) |
| `Operation.sign` (node) | method | `sign(keyPair)` / `signWithPrivateKey(privateKeyHex)` | `bindings/node/index.d.ts:134-135` | STABLE (implied by node test flow) |
| `operation.signerId` / `.nodeId` | assignment | wasm ops get their signer via `node.sign(op, key)` + fields set by JS (`smoke.js:24-26`); node supports field assignment (`test.js`) | wasm :62-71, node :62-75 | STABLE |
| `Operation.lamportTime` | property (**node only**) | `lamportTime: number` | `bindings/node/index.d.ts:81` | PRESENT |
| `Operation.addResource` | method | `addResource(name) -> this` — capacity 8 | wasm :68, node :83 | STABLE (`write-domains.js:46`, `locks-tx.js`) |
| `Node.addResource` | method | `addResource(name, initial?)` — mints the `DATA_TYPE_RESOURCE` lock-capable item (recipe 9; `initial` seeds the raw int64 balance) | wasm :502, node :328 | STABLE (`locks-tx.js:30`, node `test/locks-tx.js`) |
| `Operation.setRequiredState` | method | `setRequiredState(slotIndex, 'idle'|'locked'|'modified'|'verified'|'error') -> this` — the per-slot `required_state` the executor's step 4 checks; slots are created 'idle' by addResource. Signed (format v4) — set BEFORE signing | wasm :84, node :98 | STABLE (`locks-tx.js`, C mirror `cookbook/snippets/c/09-treasury.c`) |
| `Operation.setNextState` | method | `setNextState(slotIndex, stateWord) -> this` — the per-slot `next_state` the driver declares (signed) | wasm :87, node :101 | STABLE (`locks-tx.js`) |
| `Operation.addLockClaim` | method | `addLockClaim(resource, tokenHex) -> this` — one 32-byte bearer-token claim (64 hex chars); the executor's step 5 verifies presented claims against the item's live token. Signed — set BEFORE signing | wasm :96, node :110 | STABLE (`locks-tx.js` forged-claim + ceremony scenarios; `test/test_state_machine.cpp:417` = the C pin for `lock_token_mismatch`) |
| `Operation.addAttestation` | method | `addAttestation(fields: AttestationFields) -> this` — one parent-signed vouch (the `@parent/` endorsement credential). NOT part of the canonical signing form (each attestation carries its own parent ECDSA) but rides op wire v5+ transport (§10 full row) | wasm :111, node :125 | STABLE (`attestations.js` both bindings) |
| `Operation.getWireVersion` | method | fresh ops report the build's `wireVersions().op`; parsed ops report the wire's version | wasm :117, node :133 | STABLE (`wire-versions.js:44-56`) |
| `Operation.destroy` | method (wasm only) | `destroy()` | `bindings/wasm/index.d.ts:118` | STABLE (`smoke.js:103-105`) |

## 13. KeyPair

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `KeyPair.generate` | static | wasm: `Promise<KeyPair>`; node: sync `generate()` | wasm :44, node :71 | STABLE (`smoke.js:7`) |
| `KeyPair.fromPrivateHex` | static | `fromPrivateHex(hex) -> KeyPair` | wasm :45, node :72 | STABLE (`smoke.js`-style; used in node tests via public-derive) |
| `KeyPair.derivePublicHex` | static | `derivePublicHex(hex) -> string` | wasm :46, node :73 | STABLE (`test/test.js:27`) |
| `KeyPair.publicKeyHex` / `.privateKeyHex` | method | hex string of the secp256k1 key (33-byte compressed pk; wrong length rejected, `smoke.js:44-52`) | wasm :38-39, node :26-31 | STABLE |
| `KeyPair.destroy` | method (wasm only) | `destroy()` | `bindings/wasm/index.d.ts:42` | STABLE (`smoke.js:136`) |

**Node KeyPair construction**: node's `KeyPairStatic` has `new ()` (`bindings/node/index.d.ts:69-74`) — a default-constructed keypair — wasm generates via the static only.

## 14. Change events (on/off)

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.on` | method | `on('change', listener) -> unsubscribe()` | wasm :485, node :310 | STABLE (`change-events.js:16`; node `test/test.js:124`) |
| `Node.off` | method (**wasm only**; node `.d.ts` documents the off() returned by `on()` instead) | `off('change', listener)` | `bindings/wasm/index.d.ts:487` | STABLE (`change-events.js:59-60`) |
| `CrabsChangeEvent` | interface | kinds `op|schedule|trigger|attribute|spawn|lineage`; wasm adds a `uuid` field and non-null `signer`/`node`; node makes `signer`/`node` nullable (`bindings/node/index.d.ts:295-297`) and has no `uuid` | wasm :26-36, node :292-297 | STABLE (`change-events.js:44-52`) |

Mid-emit re-entrancy and self-unregistering listeners are safe and tested (node `test/test.js:204-240`).

## 15. Wire versions + DATA_TYPE / CRDT_TYPE constants

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `wireVersions` | function (wasm) / const (node) | `{state, op, signing}` frozen; wasm caches after first call (`await wireVersions()`), node freezes at module load | wasm :782-789, node :708-713 | STABLE (`wire-versions.js:11-38`, node `test/test.js:594-597` asserting state=15, op=6, signing=4) |
| `DATA_TYPE` | const | `{COUNTER, PN_COUNTER, SET, REGISTER, RESOURCE, ONE_SHOT_SET, ONE_SHOT_FLAG, OT_ORDERED_SET, CUSTOM}` | wasm :133, node :679-689 | STABLE (`lineage_smoke.mjs:43`, `ordered-set.js:20`) |
| `OT_ORDERED_SET` item + ordered* sugar | Node methods (both bindings) | `addOrderedSet(name)`, `getOrderedSet(name) -> {elements: string[]}`, `orderedInsert/ orderedDelete/ orderedMove/ orderedSwap(name, ..., {id, deps?})` — ops route the `__execute_ot__` executor; op id `{node, seq, ts?}` required, `deps` = causal context for cross-replica replays | wasm `index.d.ts:604-635` (options :182) + `bindings-core.js:1071-1188`; node `index.d.ts:412-446` (options :667) + `crabs_node.cc:1809-2100`; C: `crabs_wasm_add_ordered_set`/`crabs_wasm_ot_apply` (`src/Util/wasm_helpers.c:917/1003`), `crabs_ot_ops_to_wire` (`src/OT/ot_execution.h:49-54`) | STABLE (`ordered-set.js` both bindings) |
| OT data-type words | parser (node only, internal) | `crabs_node.cc` maps `'ot_ordered_set'|'ot_document'|'ot_table'|'ot_tree'|'ot_ordered_map'` (`bindings/node/src/crabs_node.cc:289-293`) to `DATA_TYPE_OT_*` (`0x10-0x14`, `src/CRABS/data_model.h:33-37`) | node binding source | PRESENT — `'ot_ordered_set'` has real item machinery (§15 row above); the other OT words remain parse-only |
| `CRDT_TYPE` | const | `{G_COUNTER, PN_COUNTER, OR_SET, LWW_REG, ONE_SHOT_SET, ONE_SHOT_FLAG, CUSTOM}` | wasm :134, node :691-698 | STABLE (`lineage_smoke.mjs:43`) |
| wasm devtools exports | module fns (**dev build only**) | `_crabs_wasm_devtools_snapshot`, `_crabs_wasm_devtools_drain_events`, `_crabs_wasm_devtools_string_destroy`, `crabs_wasm_devtools_drain_events_for` via `ccall` | `dev.d.ts` + `devtools.js:25-108` | STABLE (dev artifact asserts prod absence, `devtools.js:14-21`) |

## 16. Module loading

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `getModule` | function (wasm) | `getModule() -> Promise<any>` — raw Emscripten module for devtools/dev builds | `bindings/wasm/index.d.ts:778` | STABLE (`devtools.js:14,24`) |

## 17. Capability-coverage ledger for recipes 2–15

Where a recipe capability has **no JS map entry**, that fact is recorded here — recipe authors must not invent an API.

| Recipe | Capability | Resolution |
|---|---|---|
| R2 | one-shot set | `addOneShotSet` / `setAdd` + `setRemove` tombstones (§4), STABLE |
| R2 | DedupSpec / per-user guard | `Node.defineOperationType` (§5, STABLE — both bindings): the registered spec guards every op of the type inside the executor (`state_find_op_type_def`), replacing the old custom-handler emulation |
| R3 | `ONE_SHOT_FLAG`, global dedup | `addOneShotFlag` / `flagSet` / `flagValue` (§4), STABLE; global dedup → `Node.defineOperationType` with `dedup: 'global'` (§5, STABLE — both bindings) |
| R4 | `registerUser`, `grantRole`, `setPolicy`, admin demotion | §2 / §3, STABLE — including the P3 admin gates: `revokeRole` / `suspendUser` / `activateUser` (§3, both bindings — policies re-evaluate fail-closed after the revoke/suspend; pinned `bindings/wasm/test/roles-admin.js` + node `test/test.js`) |
| R5 | register LWW + key versioning/pair | `Node.setRegister` / `getRegister` + BigInt-vs-number split (§4); key pair = `KeyPair.*` (§13); `UserInfo.keyVersion` is the JS-visible version (§2) |
| R6 | triggers, threshold attributes, ABE | `createTrigger` / `TriggerConfig` (§7, STABLE); threshold conditions live in the C condition grammar `src/Condition/` (PRESENT in C, surface tested via `createTrigger`); `Node.encrypt` + `Node.abeKeygen`/`Node.abeDecrypt` + `AbeKey` (§9, STABLE — the full seal/open round trip runs from JS on both bindings) |
| R7 | schedules, `setTimeSource`, HLC | §6; schedules STABLE on both bindings (wasm `bindings/wasm/index.d.ts:726-737`, node `bindings/node/index.d.ts:480-503`, node test pinned), HLC via node `getHLC` (STABLE) + C `src/HLC/hlc.h` (PRESENT) |
| R8 | OT ordered set surface | **Op layer JS-bound on both bindings** (§15): `addOrderedSet` + `orderedInsert/orderedDelete/orderedMove/orderedSwap` (op id `{node,seq,ts?}` + optional causal `deps`) + `getOrderedSet` readback — wasm `index.d.ts:604-635`, node `index.d.ts:412-446`; executor path `crabs_wasm_ot_apply` (`src/Util/wasm_helpers.c:1003`) / `crabs_node.cc:1868`, payload from `crabs_ot_ops_to_wire` (`src/OT/ot_execution.h:49-54`). **Merge layer still C-only:** `crabs_ot_ordered_set_merge` + `merge_position_maps` (`src/OT/ot_ordered_set.h:114-118`) — conflicting-payload refusal and merged position-map guarantees demoable only in C (`test/test_ot_ordered_set.cpp:377-420`) → recipe R8 is PARTIAL with `languages: c wasm node` |
| R9 | resources, locks / transaction manager | **Full surface STABLE JS (both bindings)** (recipe 9): `Node.addResource(name, initial?)` + `getResource` (§4) — the lock-capable RESOURCE item mint (wasm export `crabs_wasm_add_resource`, `src/Util/wasm_helpers.c:638`; node `crabs_node.cc:1927`); the lock drive = `__lock__`/`__verify__`/`__unlock__` built-ins + `Node.getLockState(name)` (the live bearer-token read; wasm `wasm_helpers.c:730`, node `crabs_node.cc:1993`) + `Operation.setRequiredState`/`setNextState`/`addLockClaim` (§12; executor steps 4-5, `src/StateMachine/state_machine.c:848-866,1653-1668`); replay = `Node.attachTxManager('memory'|'none')` (wasm `wasm_helpers.c:886`, node `crabs_node.cc:1778` — wraps `src/TxManager/tx_manager.h:19-41` vtable + `crabs_tx_manager_memory`/`crabs_tx_manager_none`). Residual limits: lock state is runtime-only (never serialized), claim discipline stays cooperative (recipe 9's honesty notes), and crabs-node still has no handler surface — the debit/credit *arithmetic* there stays the driver's |
| R10 | op signing modes / sovereign prefixes | `Operation.setSovereignPrefix` + signing format v4 (§11/§12), STABLE |
| R11 | Blueprint + spawn + attenuation | §10, STABLE (wasm pointer vs node wrapper divergence documented) |
| R12 | attestations, parent key chain | **Full loop STABLE JS (both bindings)** (recipe 12): issuance `attest`/`lineageAttest` + tombstone (§10, STABLE); CONSUME = `Operation.addAttestation(fields)` staging the parent-signed credential onto the op (`AttestationFields`, §10) and the executor resolving `@parent/` endorsements engine-side (`_verify_parent_endorsements` `src/StateMachine/state_machine.c:709-762`, tip-only verify `src/Lineage/lineage.h:654-670`); refusals (tampered/wrong-user/uncovered/wrong-child/expired) collapse to `unauthorized` in the binding tests. The forged-parent + unbound-machine refusals and the `attestation_deserialize` helper remain C-only (JS cannot mint a forged parent or spawn an unbound child — recipe 12 documents why) |
| R13 | write domain SOVEREIGN | `defineItem({domain:'sovereign', writer})` + `itemChainHead` + `reportEquivocation` (§11, STABLE) |
| R14 | GROUP-ORDERED / raft-ordered shared writes | **Shipped — the module is REAL and node-bound.** `Node.attachRaft` (§11: wasm `index.d.ts:670` + `RaftHost` :427-476; node `:593-597` + the `createRaftHost` reference host loop, `bindings/node/index.js:91`) attaches the `crabs_raft_module_t` reactor (`src/Raft/raft_module.h:190` — transport/storage/timer seams user-replaceable); a group-ordered item writes fail-closed WITHOUT a module (`ordering_path`, `src/CRABS/crabs.h:128`) and rides the two-phase pipeline with one (`ORDERING_PENDING`, `src/CRABS/crabs.h:131`; seam `src/StateMachine/state_machine.c:1526-1560`); `DefineItemOptions.orderingModule` carries the MACHINE's attached module id (mint path accepts only 0, `src/CRABS/data_model.c:161-172` — one module per machine); merge adopts by committed position (`src/CRDT/crdt_merge.c:751-790`). E2E: `bindings/wasm/test/raft.js` + `bindings/node/test/raft.js` (3-node election / partition + heal / crash recovery) + the C sim (`test/test_raft_sim.cpp:985,1134,685,1637`) → recipe R14 is COMPLETE, `languages: wasm node` (the C reactor is engine-tested; the reference host loop is JS — recipe 14 documents why no C cookbook snippet exists) |
| R15 | key versioning / epoch attributes | `UserInfo.keyVersion` (§2, real readback on both bindings); ABE seal + open round trip from JS: `Node.abeKeygen`/`Node.abeDecrypt` (§9, STABLE — recipe 15's snippets execute the bearer-instrument boundary and the epoch re-key from both bindings); keyring lifecycle JS-reachable user-id-scoped (§2): `suspendKey`/`activateKey`/`rotateKey` + `listKeys`/`getDefaultKey` (wasm `bindings-core.js:931-1038`, node `crabs_node.cc:1593-1758`; pinned `bindings/wasm/test/keyring.js` + node `test/test.js` keyring block) over `user_key_suspend/activate/rotate` `src/Attribute/attribute_machine.h:219-221` + `test/test_key_lifecycle.cpp`; remaining C-only: the primitives' method forms `user_key_revoke`/`user_key_set_default` (wire ops `__revoke_key__`/`__set_default_key__` cover them) and the key_id-declaring sign path (binding ops ride the legacy stamp; a keyring-ed signer refuses fail-closed, R8-C-2); "epoch" as an attribute convention is a recipe-level pattern, not a library symbol |

### Known wasm/node differences (full list found while mapping)

1. Construction: `Node.create` (wasm) vs `new Node` (node). `Operation.create` vs `new Operation`. `KeyPair.generate` async vs sync. `Blueprint.create` exists in both bindings (node also has `new Blueprint`).
2. Handlers: `registerHandlerJs` / `unregisterHandler` / low-level `registerHandler` / `HandlerState` / `HandlerOperation` are wasm-only — node has **no custom-handler surface**.
3. Schedules exist on both bindings (same names, wasm `:726-737` / node `:480-503`); node observes fires via 'schedule' change events (no `registerHandlerJs`). HLC: node `getHLC()`, wasm none.
4. OR-set pagination (`getSetSize`/`getSetElements`/`getSetTags`) and register byte API (`setRegisterBytes`/`getRegisterBytes`) are wasm-only.
5. BigInt stamp inputs: register/prefix values and `AttestationFields` timestamps/`parentKeyVersion` — wasm `number | bigint`, node `number` only.
6. `Node.off` exists in wasm.d.ts; node relies on the unsubscribe function returned by `on`.
7. Node-only symbols: `selfAssert`, `verifyIdentity`, `Operation.lamportTime`, `Operation.sign`/`signWithPrivateKey`, `getHLC`+`HLC` interface, `UserInfo.attributes[].expiresAt`.
8. Trigger effect unions differ (wasm has create/delete/disable trigger variants; node is `issue_attribute|change_policy` + `policy*` fields).
9. Lineage shapes: wasm exposes opaque pointers + flat manifest accessors + `attest`; node returns `Node` wrappers + `lineageChildren` + `lineageAttest`.
10. `Operation.deserialize` and `destroy()` are wasm-side lifecycle obligations; node wrappers rely on ownership semantics documented in the d.ts prose.
11. Node `Node` interface has no `destroy` declaration; wasm requires explicit `Node.destroy()`.