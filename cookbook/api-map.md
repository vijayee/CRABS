# CRABS API Map

Every recipe's provenance footer cites the entries defined here. Two JS bindings expose the C core:

| Binding | Types | Read in full | Lines |
|---|---|---|---|
| `crabs-wasm` (Emscripten) | [`bindings/wasm/index.d.ts`](../bindings/wasm/index.d.ts) | 2026-10-13 | 717 |
| `crabs-node` (N-API) | [`bindings/node/index.d.ts`](../bindings/node/index.d.ts) | 2026-10-13 | 678 |

**Maturity labels**

- `STABLE` — exercised by tests in `bindings/*/test/`, `bindings/*/lineage_smoke.mjs`, or `cookbook/recipes/` examples.
- `PRESENT` — declared in a `.d.ts` (or compiled C) but not exercised anywhere we found. Write recipes against it carefully.
- `DESIGNED` — exists only in design docs / C internals, not reachable from JS. Cited to its design source.

Unless a row says otherwise, wasm and node share the symbol at the same d.ts line family. Binding-differing rows are called out in bold text inside each subsection.

---

## 1. Machine: creation and lifecycle

`Node` is the machine handle. **Node bindings differ on construction:** wasm has a static factory `Node.create(adminId, options)` (async, `bindings/wasm/index.d.ts:372`); node has a constructor `new Node(adminId, options)` (`bindings/node/index.d.ts:311-313`) — there is no `Node.create` on the node binding.

**`destroy()` also differs**: wasm `Node.destroy()` (`bindings/wasm/index.d.ts:368`) is explicit and tested (`smoke.js:135`); the node `.d.ts` declares no `Node.destroy` — the C machine follows the wrapper's lifetime (see the sibling-wrapper clock caveat at `bindings/node/index.d.ts:273-278`).

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.create` | factory (wasm only) | `create(adminId, options?) -> Promise<Node>` | `bindings/wasm/index.d.ts:372` | STABLE (`smoke.js:6`) |
| `new Node` | constructor (node only) | `new Node(adminId, options?)` | `bindings/node/index.d.ts:312` | STABLE (`test/test.js:31`, lineage_smoke.mjs:47) |
| `Node.destroy` | method | `destroy()` | `bindings/wasm/index.d.ts:368` | STABLE (`smoke.js:135`) |
| `Node.serialize` | method | `serialize() -> Uint8Array\|Buffer` | wasm :307, node :260 | STABLE (`test/test.js:116`) |
| `Node.getNodeKey` | getter | `getNodeKey() -> NodeKey{publicKeyHex, privateKeyHex}` | wasm :212, node :190 | STABLE (`test/test.js:35`) |
| `Node.setPolicy` | method | `setPolicy(opType, expression)` | wasm :295, node :249 | STABLE (`smoke.js:17`) |
| `Node.adminId` | property (wasm) | `readonly adminId: string` | `bindings/wasm/index.d.ts:367` | PRESENT |

`NodeOptions = { ordering: 'hlc'|'lamport', strategy: 'naive'|'bounded'|'quorum'|'strict'|'trusted' }` — wasm:190-193 / node:149-152; `{ordering:'hlc'}` tested (`smoke.js:6`, `test/test.js:31`), `strategy` values untested → PRESENT.

## 2. Users, roles, attributes (registerUser, tokens)

`grantRole` is the admin path for privileged attributes: `registerUser` rejects privileged attribute names (audit R7-08), so a role is granted afterward — `smoke.js:8-11`.

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.registerUser` | method | `registerUser(userId, publicKeyHex, initialAttrs?)` | wasm :213, node :182 | STABLE (`smoke.js:10`) |
| `Node.grantRole` | method | `grantRole(targetUser, role, value, signerId)` | wasm :214, node :183 | STABLE (`smoke.js:11`) |
| `Node.revokeUser` | method | `revokeUser(userId, signerId?)` | wasm :215, node :186 | STABLE (`test/test.js:253` type check only) |
| `Node.selfAssert` | method (**node only**) | `selfAssert(attribute, value, signerId)` | `bindings/node/index.d.ts:184` | STABLE (`test/test.js:97`) |
| `Node.verifyIdentity` | method (**node only**) | `verifyIdentity(targetUser, attribute, value, signerId)` | `bindings/node/index.d.ts:185` | PRESENT (no test found) |
| `Node.getUser` | query | `getUser(userId) -> UserInfo \| undefined` | wasm :221, node :189 | STABLE (`smoke.js:40`) |
| `UserInfo` | interface | `{userId, publicKeyHex, keyVersion, status, attributes[]}` | wasm :150-160, node :50-61 | STABLE (`smoke.js:41` — attributes list only; the wasm readback returns STUBS for `publicKeyHex`/`keyVersion`/`status`, `bindings/wasm/bindings-core.js:693-706`; crabs-node maps them directly, `bindings/node/src/crabs_node.cc:1139-1157`) |
| `UserInfo.attributes[].verifiedBy` | field | attribute provenance string | wasm :157, node :57 | STABLE (`roles.test`-style asserts, `test/test.js:92`) |
| `Node.pruneExpiredTempAttrs` | method | `pruneExpiredTempAttrs() -> number (wasm) / void (node)` | wasm :310, node :265 | PRESENT |

**Tokens / key lifecycle**: `UserInfo.keyVersion` (wasm :153, node :53) is the JS-visible key-version read — REAL on crabs-node (mapped from the machine, `bindings/node/src/crabs_node.cc:1147`), a stubbed `0` on wasm (`bindings/wasm/bindings-core.js:698`). Suspend/activate/rotate exist only in C — `user_key_suspend`, `user_key_activate`, `user_key_rotate` at `src/Attribute/attribute_machine.h:219-221`, exercised in `test/test_key_lifecycle.cpp:96,180,269`. Not JS-bound → `DESIGNED` (documented by cookbook recipe 16 with its readback-stub gap).

## 3. Policy surface (setPolicy, role grants)

Policies are condition expressions over attributes: `"AND role:member adult"` (`smoke.js:17`). `grantRole` installs `role:<value>` attributes (§2). Typed errors on execution include `resource_not_found` and `condition_not_met` (`bindings/node/src/crabs_node.cc:98,103`).

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.setPolicy` | method | `setPolicy(opType, expression)` | wasm :295, node :249 | STABLE (`smoke.js:17`) |
| `Node.execute` | method | `execute(op)` — throws typed errors | wasm :296, node :251 | STABLE (`smoke.js:27`) |
| `Node.sign` | method | `sign(op, key: KeyPair \| privateKeyHexString)` | wasm :297, node :250 | STABLE (`smoke.js:26`) |

Condition expression grammar lives in `src/Condition/`; `attribute` change events kind `'attribute'` are emitted on grants (`change-events.js:44-52`).

## 4. CRDT surface — counters, sets, registers, RESOURCE items

Shared creation/query API (both bindings except where marked). **Node `.d.ts` differs**: node exposes only `setContains`; the bounded enumerator (`getSetSize` / `getSetElements` / `getSetTags`) and the register byte API (`setRegisterBytes` / `getRegisterBytes`) are **wasm-only**.

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.addCounter` | method | `addCounter(name)` — G-counter | wasm :427, node :263 | STABLE (`smoke.js:13`) |
| `Node.addPNCounter` | method | `addPNCounter(name)` | wasm :428, node :264 | STABLE (`smoke.js:14`) |
| `Node.addORSet` | method | `addORSet(name)` | wasm :429, node :265 | STABLE (`smoke.js:15`) |
| `Node.addOneShotSet` | method | `addOneShotSet(name)` | wasm :430, node :266 | STABLE (`test/test.js:53`; wasm declared only) |
| `Node.addOneShotFlag` | method | `addOneShotFlag(name)` | wasm :431, node :267 | STABLE (`test/test.js:54,112-113`) |
| `Node.addRegister` | method | `addRegister(name, initialValue?)` | wasm :432, node :268 | STABLE (`registers.js:13`) |
| `Node.incrementCounter` | method | `incrementCounter(name, delta?, nodeId?)` | wasm :523, node :343 | STABLE (`smoke.js:28`) |
| `Node.incrementPNCounter` | method | `incrementPNCounter(name, delta?, nodeId?)` | wasm :524, node :344 | STABLE (wasm test path; node declared) |
| `Node.decrementPNCounter` | method | `decrementPNCounter(name, delta?, nodeId?)` | wasm :525, node :345 | PRESENT (no test found) |
| `Node.getCounter` | query | `getCounter(name) -> number` | wasm :491, node :329 | STABLE (`smoke.js:39`) |
| `Node.getPNCounter` | query | `getPNCounter(name) -> number` | wasm :492, node :330 | PRESENT |
| `Node.getRegister` | query | `getRegister(name) -> number` | wasm :493, node :331 | STABLE (`registers.js:51`) |
| `Node.setRegister` | method | `setRegister(name, value, nodeId?)` | wasm :500, node :339 | STABLE (`registers.js:50`) |
| `Node.setAdd` | method | `setAdd(name, element, tag?)` | wasm :527, node :348 | STABLE (`test/test.js:87`) |
| `Node.setRemove` | method | `setRemove(name, element)` | wasm :528, node :349 | STABLE (`handler-reads.js:79`) |
| `Node.setContains` | query | `setContains(name, element) -> boolean` | wasm :504, node :340 | STABLE (`test/test.js:88`) |
| `Node.flagSet` | method | `flagSet(name, setBy, setAt?)` — one-shot flag | wasm :529, node :350 | STABLE (`test/test.js:112`) |
| `Node.flagValue` | query | `flagValue(name) -> boolean` | wasm :530, node :351 | STABLE (`test/test.js:113`) |

**LWW registers — int64/BigInt handling (R5, R16).** Registers carry a signed int64. Both bindings accept integers within ±`Number.MAX_SAFE_INTEGER` and reject fractions/NaN/Infinity (consumption finding 1; `registers.js:30-46`, node `test/test.js:555-578`). The wasm binding additionally accepts `BigInt` for the full int64 range (`bindings/wasm/index.d.ts:262-263`; `registers.js:60-67`: `2**60 BigInt round-trips`, and inside handlers at `registers.js:91`); **the node binding accepts numbers only** — full int64 range requires crabs-wasm (`bindings/node/index.d.ts:227-234`). C source: `src/StateMachine/state_machine.h`.

**wasm-only pagination + register bytes:**

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.getSetSize` | query (wasm only) | `getSetSize(name) -> number` — distinct live elements | `bindings/wasm/index.d.ts:509` | STABLE (`handler-reads.js:36`) |
| `Node.getSetElements` | query (wasm only) | `getSetElements(name, {offset?, limit?<=256}) -> string[]` — sorted strcmp, snapshot semantics | `bindings/wasm/index.d.ts:519-520` | STABLE (`handler-reads.js:39-46`) |
| `Node.getSetTags` | query (wasm only) | `getSetTags(name, element) -> string[]` — live tags of an OR-set element | `bindings/wasm/index.d.ts:521` | STABLE (`handler-reads.js:68-74`) |
| `Node.getRegisterBytes` | query (wasm only) | `getRegisterBytes(name) -> Uint8Array` — raw register payload | `bindings/wasm/index.d.ts:503` | STABLE (`handler-reads.js:88-90`) |
| `Node.setRegisterBytes` | method (wasm only) | `setRegisterBytes(name, bytes, nodeId?)` — byte-exact inverse | `bindings/wasm/index.d.ts:501` | STABLE (`handler-reads.js:89,108`) |
| `setRemove` tombstone/`GetSetElementsOptions` behavior | contract | removal leaves tombstones; size counts live only | `bindings/wasm/index.d.ts:115-161` | STABLE (`handler-reads.js:80-83`) |

**RESOURCE items, locks and the tx manager (R9):**

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.addResource` | method | `addResource(name, initial?)` — the lock-capable `DATA_TYPE_RESOURCE` item ("PN-Counter + lock", raw int64 value) | wasm :439, node :276 | STABLE (`locks-tx.js`; node `test/locks-tx.js`) |
| `Node.getResource` | query | `getResource(name) -> number` — raw int64 balance readback (wasm throws `resource_not_found`/`type_mismatch`; node returns undefined for unknown, throws for non-RESOURCE) | wasm :446, node :283 | STABLE (`locks-tx.js`) |
| `Node.getLockState` | query | `getLockState(name) -> LockStateView` — `protocolState` word (`idle`/`locked`/`modified`/`verified`/`error`), `lockOwner`, `lockTokenHex` (the 32-byte CSPRNG bearer token, '' when unset), `lockExpiry`, `lockExtensions` | wasm :454 + LockStateView :195, node :290 + LockStateView :17 | STABLE (`locks-tx.js`) |
| `Node.attachTxManager` | method | `attachTxManager('memory' \| 'none')` — attaches the replay-protection manager (`src/TxManager/tx_manager.h:19-41` vtable; memory impl `src/TxManager/tx_manager_memory.h:16`) to `state->tx_manager` (`src/CRABS/data_model.h:486`); step 3b refuses duplicates `already_executed` (`src/StateMachine/state_machine.c:1600-1620`) | wasm :465, node :304 | STABLE (`locks-tx.js` duplicate-submission scenario) |

## 5. One-shot sets / flags and dedup (R2, R3)

One-shot sets and flags are added like any item (`addOneShotSet` / `addOneShotFlag`, §4) — their "once" semantics come from the DedupSpec machinery in C, and `Node.defineOperationType` installs a spec on the machine registry from BOTH bindings (`'custom'`-conditioned specs + their spec-carried mutations stay C-native: the bindings surface only the machine-enforceable per-user / global / none shapes):

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.addOneShotSet` | method | item whose elements can be inserted once per dedup scope | wasm :366, node :226 | STABLE (node test; wasm declared) |
| `Node.addOneShotFlag` | method | one-shot boolean | wasm :367, node :227 | STABLE (`test/test.js:112`) |
| `Node.defineOperationType` | method | `defineOperationType(opType, { dedup: 'per-user' \| 'global' \| 'none', trackerPath?, flagPath?, rejectionMessage? })` | wasm :446, node :291 | STABLE (`bindings/wasm/test/dedup-surface.js`, `test/test.js:659`) |
| `DefineOperationTypeOptions` | interface | `{dedup, trackerPath?, flagPath?, rejectionMessage?}` | wasm :197-217, node :155-175 | STABLE (same tests) |
| `dedup_check_guard` | C fn | `dedup_check_guard(state, op) -> crabs_error_e` | `src/Dedup/dedup.h:21-22` | PRESENT in C; the executor resolves REGISTERED specs via `state_find_op_type_def` — a registered spec wins over whatever the op carries (register + bypass-refusal pinned in `test/test_state_machine.cpp` `DefineOperationTypeExecutesThroughMachine`) |
| `state_register_op_type_def` | C fn | `state_register_op_type_def(state, op_type, dedup_spec_t*)` | `src/CRABS/data_model.h:794` | PRESENT; reachable from both JS bindings via `Node.defineOperationType` (first-match update in place — re-defining REPLACES the spec, capacity 32 at `data_model.h:379`) |

`DedupSpec` types (`dedup_type_e`, `dedup_spec_t`) at `src/CRABS/data_model.h:333-338,363-374`; the op format carries a `dedup_spec` since wire v3 (`src/StateMachine/state_machine.h:61,99`).

## 6. Schedules and time sources (R7)

**All schedule methods exist on BOTH bindings** (wasm `bindings/wasm/index.d.ts:501-511`; node `bindings/node/index.d.ts:306-331` — ported from the wasm surface). The submission-time authorization gate in both wrappers runs `state_machine_validate` before queueing (wasm `src/Util/wasm_helpers.c:1509-1519`, node `bindings/node/src/crabs_node.cc:1902-1906`). A node-specific divergence: no `registerHandlerJs` on node, so a scheduled fire is observed as a kind-`schedule` change event, not a counter effect (node `test/test.js` schedule-surface block). HLC reads differ: node has `getHLC()` + an `HLC` interface (`bindings/node/index.d.ts:114-120,343`); wasm has no HLC getter (HLC identity shows up as `Node.adminId` / op `nodeId`).

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.schedule` | method | `schedule(innerOp, executeAtMs) -> bigint` | wasm :501, node :309 | STABLE (`schedules.js:25-35`; node `test/test.js` schedule block) |
| `Node.scheduleRecurring` | method | `scheduleRecurring(innerOp, startAtMs, intervalMs, repeatCount, endAtMs) -> bigint` | wasm :502-503, node :315-316 | STABLE (`schedules.js:60-66`; node test) |
| `Node.cancelSchedule` | method | `cancelSchedule(scheduleId: bigint \| number)` — number/bigint on node, bigint on wasm | wasm :504, node :318 | STABLE (`schedules.js:51`; node test) |
| `Node.processSchedules` | method | `processSchedules(nowMs?)` — defaults to the wall clock on both | wasm :505, node :324 | STABLE (`schedules.js:38-42`; node test) |
| `Node.setScheduleOccurrenceBudget` | method | `setScheduleOccurrenceBudget(maxPerTick)` — 0 = unlimited | wasm :507, node :326 | STABLE (`schedules.js:84`; node test) |
| `Node.scheduleOccurrenceBudget` | query | `scheduleOccurrenceBudget() -> number` | wasm :508, node :327 | STABLE (`schedules.js:85`; node test) |
| `Node.pendingSchedules` | query | `pendingSchedules() -> [{id, executeAt, intervalMs, repeatCount, endAt, submitter}]` (bigints) | wasm :509-511, node :329-331 | STABLE (`schedules.js:33-35,63-65`; node test) |
| `Node.setTime` | method | `setTime(nowMs)` | wasm :309, node :264 | STABLE (`lineage_smoke.mjs:48` node) |
| `Node.setTimeSource` | method | `setTimeSource({mode:'https'|'system', url?, resyncMs?, timeoutMs?, maxSkewMs?})` — fetch fails closed, no local-clock fallback | wasm :321, node :279 | STABLE (`time-source.js:37,54`; node `test/test.js:272`) |
| `Node.getTimeSource` | query | `getTimeSource() -> TimeSourceInfo` | wasm :322, node :280 | STABLE (`time-source.js:32,39-45`) |
| `Node.getHLC` | query (**node only**) | `getHLC() -> HLC \| undefined` | `bindings/node/index.d.ts:263` | STABLE (`test/test.js:81`) |

Timing semantics of the authenticated HTTPS time source (defaults 30000/1000/5000) and the wasm module-shared-vs-machine-local difference are documented in the d.ts prose: wasm `bindings/wasm/index.d.ts:491-498` (module-shared; replacing the source re-attaches every machine), node `bindings/node/index.d.ts:346-359` (machine-local; destroying a sibling wrapper silently strips the clock — re-apply). C source: `src/TimeSource/`. HLC C surface: `src/HLC/hlc.h:144,164` (`crabs_hlc_state_init`, `crabs_hlc_compare`) — PRESENT, used by recipes only via node `getHLC`.

## 7. Triggers (R6)

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.createTrigger` | method | `createTrigger(config: TriggerConfig)` | wasm :298, node :254 | STABLE (`test/test.js:165`) |
| `TriggerConfig` | interface | `{triggerId, condition, description?, effectType, issueAttribute?, targetRole?, attributeValue?, durationMs?, oneShot?, cooldownMs?}` | wasm :167-178, node :132-147 | STABLE (`test/test.js:165`) |
| `Node.evaluateTriggers` | method (wasm only) | `evaluateTriggers()` | `bindings/wasm/index.d.ts:336` | PRESENT (no test found) |
| trigger effects in C | C fn | `state_machine_op_create_trigger` and the `__create_trigger__`-family ops (Amendment 1 §4) | `src/StateMachine/state_machine.h:200-201`, `src/Trigger/` | STABLE (C tests) |

**Binding difference on effect types:** wasm `TriggerConfig.effectType` includes `'create_trigger' | 'delete_trigger' | 'disable_trigger'` (`bindings/wasm/index.d.ts:171`); node's union is only `'issue_attribute' | 'change_policy'` with explicit `policyOperation` / `policyExpression` fields (`bindings/node/index.d.ts:140-146`). Oversized-field and adopted-child-wrapper refusals are typed (audits 9 A-1 / 10 A10-M3, `test/test.js:168-197`).

## 8. Custom handlers (registerHandlerJs, HandlerState)

**Custom handlers are wasm-only.** The node `.d.ts` has no `registerHandler*`, no `HandlerState`, and no `unregisterHandler` — node recipes drive state directly (`node.sign` + `node.incrementCounter`, `test/test.js:66-78`). Engine behavior: handler-less, resource-less custom ops are no longer silently no-oped — execution throws `resource_not_found` (`smoke.js:19-21,84-101`).

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.registerHandlerJs` | method (wasm only) | `registerHandlerJs(opType, (state: HandlerState, op: HandlerOperation) -> number)` | `bindings/wasm/index.d.ts:620` | STABLE (`smoke.js:59`; re-registration replaces, `smoke.js:71-81`) |
| `Node.unregisterHandler` | method (wasm only) | `unregisterHandler(opType)` | `bindings/wasm/index.d.ts:621` | STABLE (`smoke.js:83-102`) |
| `Node.registerHandler` | method (wasm only) | `registerHandler(opType, (statePtr, opPtr) -> number)` — low-level raw WASM pointers | `bindings/wasm/index.d.ts:618` | PRESENT (high-level variant is what tests use) |
| `HandlerState` | interface (wasm only) | mutation + read proxy: `incrementCounter`, `incrementPNCounter`, `decrementPNCounter`, `setRegister` (int/BigInt, integer-only), `setRegisterBytes`, `setAdd`, `setRemove`, `flagSet`, `getCounter`, `getPNCounter`, `getRegister`, `getResource`, `adjustResource` (recipe 9), `getRegisterBytes`, `setContains`, `getSetSize`, `getSetElements`, `getSetTags` | `bindings/wasm/index.d.ts:144-191` | STABLE (`registers.js:83-100`, `handler-reads.js:104-126`, `locks-tx.js` transfer handler) |
| `HandlerState.getSetElements` inside a handler | method (wasm only) | same as Node's, same 256-hard-cap → `getSetElements(name, {limit:999})` throws inside handlers too | `bindings/wasm/index.d.ts:180` + `handler-reads.js:139-146` | STABLE |
| `HandlerOperation` | interface (wasm only) | `{type, signerId, nodeId, payload?: string, resources: string[]}` — `resources` are the op's declared resource names (recipe 9's transfer handler resolves the pots through them) | `bindings/wasm/index.d.ts:212-218` | STABLE (`smoke.js:59-63`, `locks-tx.js` transfer handler) |

## 9. ABE encryption (encrypt) (R6)

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.encrypt` | method | `encrypt(payload: Uint8Array\|string (wasm) / Buffer (node), policy: string) -> ABE container` | wasm :306, node :257 | STABLE (`smoke.js:115`) |
| container layout | contract | u16le policy byte length (UTF-8 bytes, not UTF-16 units) + policy bytes + u32le ciphertext length + ciphertext | `bindings/wasm/index.d.ts:306` (signature) + `bindings/wasm/test/smoke.js:111-130` (layout round-trip) | STABLE |

C surface: `crypto_abe_setup` etc. at `src/Crypto/crypto.h:96-101` — the JS row is the supported path (PRESENT).

## 10. Lineage: Blueprint, spawn, attest, tombstone (R11, R12)

Machines mint machines (v1.7). **The biggest wasm/node divergence:** wasm `lineageSpawn` returns an **opaque borrowed C pointer** (`number`), while node returns a **full Node wrapper** that borrows the machine. Child lifetimes are anchored by the parent's resident-children registry in C in both cases.

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Blueprint.create` | factory | `create(childId, trustMode, bootstrapAdmin, ttlMs) -> Promise<Blueprint>`  (wasm + node: `bindings/node/index.d.ts:100`) | `bindings/wasm/index.d.ts:79-81` | STABLE (`lineage_smoke.mjs:54`) |
| `new Blueprint` | constructor (node only) | `new Blueprint(childId, trustMode, bootstrapAdmin, ttlMs)` or `new Blueprint(wire)` | `bindings/node/index.d.ts:97-100` | STABLE (`test/test.js:132`) |
| `Blueprint.deserialize` | static | wasm: `Promise<Blueprint>`; node: sync | wasm :81, node :102 | STABLE (`lineage_smoke.mjs:62`) |
| `Blueprint.addItem` | method | `addItem(name, dataType, crdtType)` — wasm takes numbers only (`bindings/wasm/index.d.ts:68`); node accepts words or numbers (`bindings/node/index.d.ts:86`) | both | STABLE (`wasm lineage_smoke.mjs:43`) |
| `Blueprint.addPolicy` | method | `addPolicy(operation, expression)` | wasm :70, node :88 | STABLE (`lineage_smoke.mjs:44`) |
| `Blueprint.stampHash` | method | `stampHash()` | wasm :72, node :90 | STABLE (`lineage_smoke.mjs:45`) |
| `Blueprint.serialize` | method | `serialize() -> Uint8Array\|Buffer` — u32le length + body + 32-byte hash | wasm :74, node :92 | STABLE (`lineage_smoke.mjs:48`) |
| `Node.lineageInstall` | method | `lineageInstall()` — registers lineage ops + default admin policies, idempotent | wasm :342, node :284 | STABLE (`lineage_smoke.mjs` both) |
| `Node.lineageSpawn` | method | wasm: `lineageSpawn(blueprint) -> number` (opaque ptr); node: `lineageSpawn(blueprint) -> Node` (borrowed wrapper) | wasm :344, node :290 | STABLE (`lineage_smoke.mjs:54/66`) |
| `Node.lineageResidentChild` | query | wasm: `-> number \| null`; node: `-> Node \| null` | wasm :346, node :294 | STABLE (`test/test.js:184`) |
| `Node.childCount`, `childIndex`, `childAt`, `childById`, `children` | manifest reads (**wasm only**; wasm names) | flat manifest accessors | `bindings/wasm/index.d.ts:348-355` | STABLE (`wasm lineage_smoke.mjs:60-76`) |
| `Node.lineageChildren` | manifest read (**node only**) | `lineageChildren() -> ChildManifestEntry[]` | `bindings/node/index.d.ts:292` | STABLE (node lineage_smoke.mjs:86) |
| `Node.attest` (wasm) / `Node.lineageAttest` (node) | method | `attest(lineageAttest)(childId, userId, attributes) -> wire bytes` — parent-signed TTL attribute grant; needs authenticated time; wasm `attest` takes 3 args (`index.d.ts:357`), node `attributes` optional (`index.d.ts:300`) | both | STABLE (`wasm lineage_smoke.mjs:82`, node lineage_smoke.mjs:104) |
| `Node.lineageTombstone` | method | `lineageTombstone(childId) -> Uint8Array\|Buffer` — canonical body (u8 tag + string16 childId + u64le parent_key_version) + 64-byte parent sig, NO length prefix; fails closed for live children | wasm :358-362, node :295-308 | STABLE (`lineage_smoke.mjs:155/170`) |
| `ChildManifestView` (wasm) / `ChildManifestEntry` (node) | interface | wasm `{childId, mode, status, ttlMs, spawnedAt}`; node `{childId, mode, status, spawnedAtMs, attestationTtlMs}` | wasm :84-92, node :106-112 | STABLE |
| `TRUST_MODE` | const | `{SHARED_ROOT: 1, DELEGATED_COPY: 2, SOVEREIGN: 3}` — node also accepts word aliases `'shared_root'|'shared'|'delegated_copy'|'delegated'|'sovereign'` | wasm :57-61, node :73-77,320-324 | STABLE (`lineage_smoke.mjs:54`) |
| dissolution / receive ops | op types | `__dissolve_machine__`, `__receive_dissolution__`, `__spawn_machine__`, `__revoke_attestation__`, `__withdraw_genesis__` | `src/Lineage/lineage.h:4-5`; used at wasm lineage_smoke.mjs:100, node lineage_smoke.mjs:127,207 | STABLE |
| attestation verify / genesis blob / cross-domain bridge | C fn | `attestation_verify_by_lineage_key`, genesis attestation, endorsement wire (spec §attestation bridge) | `src/Lineage/lineage.h:89,312-314,434-440` | PRESENT (C; not JS-bound) |

Wire version `CRABS_ATTESTATION_FORMAT_VERSION 0x02` (`src/Lineage/lineage.h:32`), body cap 512 (`:38`).

## 11. Write domains (R10, R13)

Write-domains v1: items declare a domain at mint — `'free' | 'sovereign' | 'group'` — immutable on a live item; sovereign items must also name their `writer`; `group` items take `orderingModule` but **v1 ships no ordering modules, so only 0 is legal**.

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.defineItem` | method | `defineItem(name, dataType, crdtType, options?: DefineItemOptions)` — typed refusals: sovereign-without-writer, writer-on-free, unknown domain, non-legal type | wasm :235-236, node :205-206, options wasm :181-188 / node :123-130 | STABLE (`write-domains.js:23-59`, node `test/test.js:353ff`) |
| `Operation.setSovereignPrefix` | method | `setSovereignPrefix(prefixIndex, seq, digest: 64-hex \| 32 raw bytes (wasm))` — signed in format v4, wire-carried in op format v6; set BEFORE signing | wasm :40-41, node :33 | STABLE (`write-domains.js:71-104`) |
| `Node.itemChainHead` | query | `itemChainHead(name) -> {seq, digestHex}` — full 32-byte hex; `resource_not_found` on unknown item | wasm :244, node :213 | STABLE (`write-domains.js:80-96`) |
| `Node.reportEquivocation` | method | `reportEquivocation(itemName, opABytes, opBBytes)` — files `__report_equivocation__`; quarantines the writer; failure modes typed (`invalid_param`, `resource_not_found`, `duplicate_operation`) | wasm :251-252, node :221 | STABLE (`write-domains.js:124-145`, node `test/test.js:493-540`) |
| quarantine enforcement | contract | a quarantined writer's next op throws `quarantined`; a non-writer op throws `not_item_writer` | `write-domains.js:106,132`; node `test/test.js:462,493` | STABLE |

Domain error taxonomy (`CRABS_ERR_NOT_ITEM_WRITER` etc.) maps in `bindings/node/src/crabs_node.cc:111`.

## 12. Operation (sign / serialize / deserialize)

**Construction differs:** wasm `Operation.create(type)` is an async static (wasm :52) with explicit `destroy()` (tested, `smoke.js:31-37`); node constructs synchronously with `new Operation(type)` (`bindings/node/index.d.ts:47`, `test/test.js:66`).

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Operation.create` | static (wasm) | `create(type: string) -> Promise<Operation>` | `bindings/wasm/index.d.ts:72-76` | STABLE (`smoke.js:23`) |
| `new Operation` | ctor (node) | `new Operation(type: string)` | `bindings/node/index.d.ts:47` | STABLE (`test/test.js:66`) |
| `Operation.deserialize` | static | wasm: async `deserialize(bytes) -> Promise<Operation>`; node `.d.ts` has no `Operation.deserialize` (node round-trips state, not ops) | `bindings/wasm/index.d.ts:53` | STABLE (`smoke.js:33`) |
| `Operation.serialize` | method | `serialize() -> Uint8Array\|Buffer` ("sign first, then serialize", node :34) | wasm :31, node :75 | STABLE (`smoke.js:31`) |
| `Operation.sign` (node) | method | `sign(keyPair)` / `signWithPrivateKey(privateKeyHex)` | `bindings/node/index.d.ts:82-83` | STABLE (implied by node test flow) |
| `operation.signerId` / `.nodeId` | assignment | wasm ops get their signer via `node.sign(op, key)` + fields set by JS (`smoke.js:24-26`); node supports field assignment (`test.js`) | wasm :54-60, node :40-44 | STABLE |
| `Operation.lamportTime` | property (**node only**) | `lamportTime: number` | `bindings/node/index.d.ts:64` | PRESENT |
| `Operation.addResource` | method | `addResource(name) -> this` — capacity 8 | wasm :33, node :46 | STABLE (`write-domains.js:46`, `locks-tx.js`) |
| `Node.addResource` | method | `addResource(name, initial?)` — mints the `DATA_TYPE_RESOURCE` lock-capable item (recipe 9; `initial` seeds the raw int64 balance) | wasm :439, node :276 | STABLE (`locks-tx.js:30`, node `test/locks-tx.js`) |
| `Operation.setRequiredState` | method | `setRequiredState(slotIndex, 'idle'|'locked'|'modified'|'verified'|'error') -> this` — the per-slot `required_state` the executor's step 4 checks; slots are created 'idle' by addResource. Signed (format v4) — set BEFORE signing | wasm :49, node :61 | STABLE (`locks-tx.js`, C mirror `cookbook/snippets/c/09-treasury.c`) |
| `Operation.setNextState` | method | `setNextState(slotIndex, stateWord) -> this` — the per-slot `next_state` the driver declares (signed) | wasm :52, node :64 | STABLE (`locks-tx.js`) |
| `Operation.addLockClaim` | method | `addLockClaim(resource, tokenHex) -> this` — one 32-byte bearer-token claim (64 hex chars); the executor's step 5 verifies presented claims against the item's live token. Signed — set BEFORE signing | wasm :61, node :73 | STABLE (`locks-tx.js` forged-claim + ceremony scenarios; `test/test_state_machine.cpp:417` = the C pin for `lock_token_mismatch`) |
| `Operation.getWireVersion` | method | fresh ops report the build's `wireVersions().op`; parsed ops report the wire's version | wasm :67, node :81 | STABLE (`wire-versions.js:44-56`) |
| `Operation.destroy` | method (wasm only) | `destroy()` | `bindings/wasm/index.d.ts:68` | STABLE (`smoke.js:103-105`) |

## 13. KeyPair

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `KeyPair.generate` | static | wasm: `Promise<KeyPair>`; node: sync `generate()` | wasm :21, node :14 | STABLE (`smoke.js:7`) |
| `KeyPair.fromPrivateHex` | static | `fromPrivateHex(hex) -> KeyPair` | wasm :22, node :15 | STABLE (`smoke.js`-style; used in node tests via public-derive) |
| `KeyPair.derivePublicHex` | static | `derivePublicHex(hex) -> string` | wasm :23, node :16 | STABLE (`test/test.js:27`) |
| `KeyPair.publicKeyHex` / `.privateKeyHex` | method | hex string of the secp256k1 key (33-byte compressed pk; wrong length rejected, `smoke.js:44-52`) | wasm :15-16, node :8-9 | STABLE |
| `KeyPair.destroy` | method (wasm only) | `destroy()` | `bindings/wasm/index.d.ts:17` | STABLE (`smoke.js:136`) |

**Node KeyPair construction**: node's `KeyPairStatic` has `new ()` (`bindings/node/index.d.ts:13`) — a default-constructed keypair — wasm generates via the static only.

## 14. Change events (on/off)

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `Node.on` | method | `on('change', listener) -> unsubscribe()` | wasm :218, node :188 | STABLE (`change-events.js:16`; node `test/test.js:124`) |
| `Node.off` | method (**wasm only**; node `.d.ts` documents the off() returned by `on()` instead, :187) | `off('change', listener)` | `bindings/wasm/index.d.ts:220` | STABLE (`change-events.js:59-60`) |
| `CrabsChangeEvent` | interface | kinds `op|schedule|trigger|attribute|spawn|lineage`; wasm adds a `uuid` field and non-null `signer`/`node`; node makes `signer`/`node` nullable (`bindings/node/index.d.ts:173-175`) and has no `uuid` | wasm :3-12, node :170-178 | STABLE (`change-events.js:44-52`) |

Mid-emit re-entrancy and self-unregistering listeners are safe and tested (node `test/test.js:204-240`).

## 15. Wire versions + DATA_TYPE / CRDT_TYPE constants

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `wireVersions` | function (wasm) / const (node) | `{state, op, signing}` frozen; wasm caches after first call (`await wireVersions()`), node freezes at module load | wasm :384-388, node :354-358 | STABLE (`wire-versions.js:11-38`, node `test/test.js:594-597` asserting state=15, op=6, signing=4) |
| `DATA_TYPE` | const | `{COUNTER, PN_COUNTER, SET, REGISTER, RESOURCE, ONE_SHOT_SET, ONE_SHOT_FLAG, OT_ORDERED_SET, CUSTOM}` | wasm :63, node :3240-3257 | STABLE (`lineage_smoke.mjs:43`, `ordered-set.js:20`) |
| `OT_ORDERED_SET` item + ordered* sugar | Node methods (both bindings) | `addOrderedSet(name)`, `getOrderedSet(name) -> {elements: string[]}`, `orderedInsert/ orderedDelete/ orderedMove/ orderedSwap(name, ..., {id, deps?})` — ops route the `__execute_ot__` executor; op id `{node, seq, ts?}` required, `deps` = causal context for cross-replica replays | wasm `index.d.ts:466-498` + `bindings-core.js:1071-1188`; node `index.d.ts:287-319` + `crabs_node.cc:1809-2100`; C: `crabs_wasm_add_ordered_set`/`crabs_wasm_ot_apply` (`src/Util/wasm_helpers.c:626/712`), `crabs_ot_ops_to_wire` (`src/OT/ot_execution.h:49-54`) | STABLE (`ordered-set.js` both bindings) |
| OT data-type words | parser (node only, internal) | `crabs_node.cc` maps `'ot_ordered_set'|'ot_document'|'ot_table'|'ot_tree'|'ot_ordered_map'` (`bindings/node/src/crabs_node.cc:212-216`) to `DATA_TYPE_OT_*` (`0x10-0x14`, `src/CRABS/data_model.h:33-37`) | node binding source | PRESENT — `'ot_ordered_set'` now has real item machinery (§17 R8); the other OT words remain parse-only |
| `CRDT_TYPE` | const | `{G_COUNTER, PN_COUNTER, OR_SET, LWW_REG, ONE_SHOT_SET, ONE_SHOT_FLAG, CUSTOM}` | wasm :64, node :337-345 | STABLE (`lineage_smoke.mjs:43`) |
| wasm devtools exports | module fns (**dev build only**) | `_crabs_wasm_devtools_snapshot`, `_crabs_wasm_devtools_drain_events`, `_crabs_wasm_devtools_string_destroy`, `crabs_wasm_devtools_drain_events_for` via `ccall` | `dev.d.ts` + `devtools.js:25-108` | STABLE (dev artifact asserts prod absence, `devtools.js:14-21`) |

## 16. Module loading

| symbol | kind | signature | source | maturity |
|---|---|---|---|---|
| `getModule` | function (wasm) | `getModule() -> Promise<any>` — raw Emscripten module for devtools/dev builds | `bindings/wasm/index.d.ts:375` | STABLE (`devtools.js:14,24`) |

## 17. Capability-coverage ledger for recipes 2–16

Where a recipe capability has **no JS map entry**, that fact is recorded here — recipe authors must not invent an API.

| Recipe | Capability | Resolution |
|---|---|---|
| R2 | one-shot set | `addOneShotSet` / `setAdd` + `setRemove` tombstones (§4), STABLE |
| R2 | DedupSpec / per-user guard | `Node.defineOperationType` (§5, STABLE — both bindings): the registered spec guards every op of the type inside the executor (`state_find_op_type_def`), replacing the old custom-handler emulation |
| R3 | `ONE_SHOT_FLAG`, global dedup | `addOneShotFlag` / `flagSet` / `flagValue` (§4), STABLE; global dedup → `Node.defineOperationType` with `dedup: 'global'` (§5, STABLE — both bindings) |
| R4 | `registerUser`, `grantRole`, `setPolicy` | §2 / §3, STABLE |
| R5 | register LWW + key versioning/pair | `Node.setRegister` / `getRegister` + BigInt-vs-number split (§4); key pair = `KeyPair.*` (§13); `UserInfo.keyVersion` is the JS-visible version (§2) |
| R6 | triggers, threshold attributes, ABE | `createTrigger` / `TriggerConfig` (§7, STABLE); threshold conditions live in the C condition grammar `src/Condition/` (PRESENT in C, surface tested via `createTrigger`); `Node.encrypt` (§9, STABLE) |
| R7 | schedules, `setTimeSource`, HLC | §6; schedules STABLE on both bindings (wasm `bindings/wasm/index.d.ts:501-511`, node `bindings/node/index.d.ts:306-331`, node test pinned), HLC via node `getHLC` (STABLE) + C `src/HLC/hlc.h` (PRESENT) |
| R8 | OT ordered set surface | **Op layer JS-bound on both bindings** (§15): `addOrderedSet` + `orderedInsert/orderedDelete/orderedMove/orderedSwap` (op id `{node,seq,ts?}` + optional causal `deps`) + `getOrderedSet` readback — wasm `index.d.ts:466-498`, node `index.d.ts:287-319`; executor path `crabs_wasm_ot_apply` (`src/Util/wasm_helpers.c:712`) / `crabs_node.cc:1868`, payload from `crabs_ot_ops_to_wire` (`src/OT/ot_execution.h:49-54`). **Merge layer still C-only:** `crabs_ot_ordered_set_merge` + `merge_position_maps` (`src/OT/ot_ordered_set.h:114-118`) — conflicting-payload refusal and merged position-map guarantees demoable only in C (`test/test_ot_ordered_set.cpp:377-420`) → recipe R8 is PARTIAL with `languages: c wasm node` |
| R9 | resources, locks / transaction manager | **Full surface STABLE JS (both bindings)** (recipe 9): `Node.addResource(name, initial?)` + `getResource` (§4) — the lock-capable RESOURCE item mint (wasm export `crabs_wasm_add_resource`, `src/Util/wasm_helpers.c:638`; node `crabs_node.cc:1731`); the lock drive = `__lock__`/`__verify__`/`__unlock__` built-ins + `Node.getLockState(name)` (the live bearer-token read; wasm `wasm_helpers.c:730`, node `crabs_node.cc:1741`) + `Operation.setRequiredState`/`setNextState`/`addLockClaim` (§12; executor steps 4-5, `src/StateMachine/state_machine.c:848-866,1653-1668`); replay = `Node.attachTxManager('memory'|'none')` (wasm `wasm_helpers.c:828`, node `crabs_node.cc:1770` — wraps `src/TxManager/tx_manager.h:19-41` vtable + `crabs_tx_manager_memory`/`crabs_tx_manager_none`). Residual limits: lock state is runtime-only (never serialized), claim discipline stays cooperative (recipe 9's honesty notes), and crabs-node still has no handler surface — the debit/credit *arithmetic* there stays the driver's |
| R10 | op signing modes / sovereign prefixes | `Operation.setSovereignPrefix` + signing format v4 (§11/§12), STABLE |
| R11 | Blueprint + spawn + attenuation | §10, STABLE (wasm pointer vs node wrapper divergence documented) |
| R12 | attestations, parent key chain | `attest`/`lineageAttest`, `lineageTombstone`, `TRUST_MODE` (§10, STABLE); verify-side C functions PRESENT |
| R13 | write domain SOVEREIGN | `defineItem({domain:'sovereign', writer})` + `itemChainHead` + `reportEquivocation` (§11, STABLE) |
| R14 | GROUP-ORDERED / elected ordering module | **Not shipped.** `DefineItemOptions.orderingModule` accepts only 0 (`bindings/wasm/index.d.ts:186-187`, node :128-129 — "v1 ships no ordering modules"); C field exists (`src/CRABS/data_model.h:206-212`: "GROUP_ORDERED requires ordering_module == 0 (no modules exist yet)") → DESIGNED; no consensus/election module found in `src/` → recipe R14 is DESIGNED-level, must be labeled as such |
| R15 | hardware attestation namespace | **Not found anywhere** — no `hardware`/`secure element`/attestation-attribute symbol in `src/` or `bindings/`; the only TPM-shaped code is the declared-unimplemented HLC time-source enum `CRABS_TIME_SOURCE_TPM = 0x02` (`src/HLC/hlc.h:57`, ops-required/fail-closed `src/HLC/hlc.c:276-286`; designed in `docs/CRABS Protocol Specification v1.6 Amendment 6.md:218,669-689` as a *time* source) plus the cookbook plan mention (`docs/superpowers/plans/2026-10-11-cookbook-github-pages.md:709`) → no map entry; recipe R15 must be labeled DESIGNED / future-work |
| R16 | key versioning / epoch attributes | `UserInfo.keyVersion` (§2); full lifecycle C-only: `user_key_suspend/activate/rotate` `src/Attribute/attribute_machine.h:219-221` + `test/test_key_lifecycle.cpp` → key-version read is PRESENT-in-JS, rotation is DESIGNED (C-only); "epoch" as an attribute convention is a recipe-level pattern, not a library symbol |

### Known wasm/node differences (full list found while mapping)

1. Construction: `Node.create` (wasm) vs `new Node` (node). `Operation.create` vs `new Operation`. `KeyPair.generate` async vs sync. `Blueprint.create` exists in both bindings (node also has `new Blueprint`).
2. Handlers: `registerHandlerJs` / `unregisterHandler` / low-level `registerHandler` / `HandlerState` / `HandlerOperation` are wasm-only — node has **no custom-handler surface**.
3. Schedules exist on both bindings (same names, wasm `:501-511` / node `:306-331`); node observes fires via 'schedule' change events (no `registerHandlerJs`). HLC: node `getHLC()`, wasm none.
4. OR-set pagination (`getSetSize`/`getSetElements`/`getSetTags`) and register byte API (`setRegisterBytes`/`getRegisterBytes`) are wasm-only.
5. BigInt register/prefix inputs: wasm `number | bigint`, node `number` only.
6. `Node.off` exists in wasm.d.ts; node relies on the unsubscribe function returned by `on`.
7. Node-only symbols: `selfAssert`, `verifyIdentity`, `Operation.lamportTime`, `Operation.sign`/`signWithPrivateKey`, `getHLC`+`HLC` interface, `UserInfo.attributes[].expiresAt`.
8. Trigger effect unions differ (wasm has create/delete/disable trigger variants; node is `issue_attribute|change_policy` + `policy*` fields).
9. Lineage shapes: wasm exposes opaque pointers + flat manifest accessors + `attest`; node returns `Node` wrappers + `lineageChildren` + `lineageAttest`.
10. `Operation.deserialize` and `destroy()` are wasm-side lifecycle obligations; node wrappers rely on ownership semantics documented in the d.ts prose.
11. Node `Node` interface has no `destroy` declaration; wasm requires explicit `Node.destroy()`.