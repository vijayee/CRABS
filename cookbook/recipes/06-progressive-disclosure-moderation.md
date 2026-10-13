---
number: 6
slug: progressive-disclosure-moderation
title: Progressive disclosure moderation
section: Conditions
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
teaches: triggers, thresholds and attribute-gated payloads
---
## Intent

You want moderation where disclosure is progressive: an action — showing
contact information, granting view access — becomes available to a member
only once the community's accumulated trust in them crosses a threshold,
low-trust viewers get nothing (not a "locked" teaser they can poke at), an
escalation can't repeat without limit, and the sealed payload is *readable
only by* viewers whose attributes satisfy a policy — with the machine, not
the client, running the check.

## The naive version, and where it breaks

The naive version is a client-side gate: `if (reportCount >= 3) show()`.
Every flaw of client-side authorization (Recipe 4) applies, plus two
structural ones. First, the client that renders the payload already holds
it — "progressive" is theater, there is only one threshold and it is on the
wrong side of the copy. Second, the *escalation* is unbounded: nothing ties
"how many reports" to "what may be revealed", so a modified client just
reads, and an honest one re-escalates on every render.

Storing the payload on a server and gating the endpoint moves the problem,
not the guarantee: the gate and the payload are now one process you must
trust. What you want is the payload *cryptographically* out of reach of
users below the threshold, and the *threshold* evaluated by the same
machine that verifies the ops. That is two mechanisms working together:
a **trigger** that turns a state condition into a temporary attribute
grant, and **attribute-based encryption** that seals the payload to the
attribute policy.

## The shape

- The threshold item is a named counter: `addCounter('abuse_reports')`,
  incremented by the signed `report_abuse` op. Trigger conditions resolve a
  FULL item path to its logical value — for a struct G-counter, the entry
  sum; a missing path resolves to 0, it never aliases a sibling item
  (`condition_resolve_path`, `src/Condition/condition.c:916-943`).
- Install the trigger: `createTrigger(config)` with a condition expression
  like `'abuse_reports >= 3'`, parsed to an AST at creation — an
  unparseable condition is refused, never stored as silently-dead
  (`src/Trigger/trigger.c:434-441`). Triggers are installed by a signed
  `__create_trigger__` op; give that op type a policy
  (`setPolicy('__create_trigger__', 'role:admin')` — the wiring
  `examples/devtools_demo/demo.js:54-57` uses).
- The effect: `effectType: 'issue_attribute'` with `issueAttribute:
  'clearance'`, `attributeValue: 'moderator'`, `durationMs: 600000`.
  On fire the effect fans out to every ACTIVE user holding an attribute
  whose NAME matches `targetRole` (the demo's `'role'` — name-only
  matching, any value; `attribute_machine_user_has_role`,
  `src/Attribute/attribute_machine.c:928-937`) and prepends a temporary
  `'clearance:moderator'` token to each holder with an expiry
  (`attribute_machine_issue_temporary`,
  `src/Attribute/attribute_machine.c:954-1026`). Privileged names
  (`role`, `admin`, …) are refused at issue time too — a trigger cannot
  mint a temporary `role:admin` (audit N-1, :981-983).
- Evaluation is automatic and machine-side: after every successfully
  executed op the executor processes all triggers
  (Step 9, `src/StateMachine/state_machine.c:1508-1520`). `cooldownMs`
  rate-limits re-fires (`src/Trigger/trigger.c:219-222`); `oneShot: true`
  disables after the first fire (:268-271).
- The gate: `setPolicy('view_contact', 'AND role:member
  clearance:moderator')`. While unexpired, the temporary token
  participates in policy evaluation as the full `'name:value'` token
  (`src/Crypto/crypto.c:1126-1163`; expired tokens are fail-closed drops).
  Below the threshold the clause cannot be met — `unauthorized`, nothing
  lands.
- The payload: `node.encrypt(payload, policy)` seals it under an attribute
  policy — the same attribute machinery whose user keys authorize ops
  produces the ciphertext, so a container can leave the machine without
  the payload travelling at all. Layout:
  u16le policy byte length + policy bytes + u32le ciphertext length +
  ciphertext (exercised `bindings/wasm/test/smoke.js:111-130`, which pins
  the round-trip; `Node.encrypt`'s signature is
  `bindings/wasm/index.d.ts:686`). The reader's side of the same container:
  `node.abeKeygen(attrs)` + `node.abeDecrypt(key, container)`
  (`bindings/wasm/index.d.ts:698,708`) — see the decrypt provenance below.

## What it guarantees / what it doesn't

Guaranteed: the escalation decision runs inside the machine, after every
op that lands — no client can render the gate, skip the threshold, or
re-escalate past the cooldown. The issued permission is a *temporary*
attribute whose expiry the machine enforces — an expired token is dropped
from policy evaluation fail-closed (`src/Crypto/crypto.c:1126-1163`, the
`expires_at <= now` skip) — it cannot itself be privileged
(audit N-1), and the payload it unlocks is additionally sealed under the
attribute policy: without a policy-satisfying key, the ciphertext decrypts
to nothing (the C snippet pins the negative).

Not guaranteed: *when* the trigger fires relative to real time. Trigger
passes run after executed ops — a machine nobody sends ops to (or one
driving ticks through `evaluateTriggers`, wasm only
`bindings/wasm/index.d.ts:738`) evaluates on *its* cadence. The
`targetRole` audience is a fan-out over every ACTIVE holder of an
attribute name, so a broad name fans out broadly — narrow audiences want
narrow names (the demo uses the role *attribute* `role:…`, not user ids).
And the decrypt key comes from the machine: a viewer decrypts with a key
`abeKeygen` minted from the machine's master authority (the key-minting
trust position is the machine admin's, below).

## Variations

- Explicit ticking: `evaluateTriggers()` (wasm) signs and executes an admin
  no-op purely to run the trigger pass — the pattern the devtools demo
  uses (`bindings/wasm/index.d.ts:738`). On crabs-node there is no such
  method; any landing op is the tick (see the node snippet).
- Self-extinguishing escalation: `oneShot: true` disables the trigger after
  its first fire (`src/Trigger/trigger.c:268-271`) — useful for a one-time
  promotion, while `cooldownMs` shapes the *repeatable* one (the demo).
- Contains conditions: the condition grammar also speaks `CONTAINS` over
  sets — `CONTAINS_SINGLE` / `ANY` / `ALL` against OR-set items
  (`src/Condition/condition.h:34-38,76-77`), e.g. a trigger when a badge
  set contains an element; exercised at C level in
  `test/test_trigger_contains.cpp`.
- Set-expiry: `TriggerConfig` has no `expiresAt` field in either binding
  d.ts, but the C trigger carries one (`src/Trigger/trigger.h:57`) and the
  pass skips expired triggers (`src/Trigger/trigger.c:224-225`) — a
  scheduled `disable_trigger` op is the JS-visible path.

## Recipe

### crabs-wasm (browser / Node / edge)

```snippet:wasm/06-moderation.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create              bindings/wasm/index.d.ts:774
  KeyPair.generate         bindings/wasm/index.d.ts:43-47
  publicKeyHex             bindings/wasm/index.d.ts:38
  KeyPair.destroy          bindings/wasm/index.d.ts:40
  registerUser             bindings/wasm/index.d.ts:480
  grantRole                bindings/wasm/index.d.ts:481
  getUser                  bindings/wasm/index.d.ts:488
  addCounter               bindings/wasm/index.d.ts:490
  setPolicy                bindings/wasm/index.d.ts:638
  createTrigger            bindings/wasm/index.d.ts:658
  TriggerConfig            bindings/wasm/index.d.ts:295+
  registerHandlerJs        bindings/wasm/index.d.ts:683
  HandlerState.incrementCounter bindings/wasm/index.d.ts:195
  HandlerOperation.signerId bindings/wasm/index.d.ts:270
  Operation.create         bindings/wasm/index.d.ts:122
  Operation.signerId       bindings/wasm/index.d.ts:63
  Node.sign                bindings/wasm/index.d.ts:657
  Node.execute             bindings/wasm/index.d.ts:656
  Node.on                  bindings/wasm/index.d.ts:485
  Node.encrypt             bindings/wasm/index.d.ts:686
  Node.abeKeygen           bindings/wasm/index.d.ts:698
  AbeKey.destroy           bindings/wasm/index.d.ts:57-59
  Node.abeDecrypt          bindings/wasm/index.d.ts:708
  Node.destroy             bindings/wasm/index.d.ts:770
  (temp attr read, plain token) bindings/wasm/bindings-core.js (getUser temp branch)
  (trigger fire on execute) src/StateMachine/state_machine.c:1508-1520
  (issue fan-out)          src/Attribute/attribute_machine.c:954-1026
  (temp token in policy)   src/Crypto/crypto.c:1126-1163
  (cooldown skip)          src/Trigger/trigger.c:219-222
maturity: all STABLE
test_ref: bindings/wasm/test/abe-decrypt.js (machine-held-M-key keygen/decrypt round trip, unauthorized refusals, token map, tamper fail-closed) + bindings/wasm/test/smoke.js:111-130 (encrypt container layout) + bindings/wasm/test/change-events.js:44-52 (change event shape) + examples/devtools_demo/demo.js:54-84 (createTrigger policy + config wiring)
-->

The snippet's decrypt half closes the old "C-only decrypt" gap: `abeKeygen`
derives a reader key from the *machine's own* master authority and
`abeDecrypt` opens the container locally — a browser can read the payload
exactly when a policy-satisfying key has been minted for its holder's
attributes. The master key never leaves the machine; there is no JS handle
for it and no portable serialized key in v1 (`AbeKey` is a destroyable
wrapper around the machine-derived key, api-map §9). The trust fact to
carry into designs: **whoever controls the machine can mint a reader key
for any attribute set it names** — keygen consults no user record
(`crypto_abe_keygen`, `src/Crypto/crypto.c:809-855`), so "a moderator
decrypts" is true in this recipe only because a policy-satisfying key was
minted for that purpose. A policy-missing key (the snippet's `guest`)
refuses with the typed `unauthorized` — the same typed path the C battery
pins (`test/test_crypto.cpp:163-301`) and the same path tampering fails
closed on.

### crabs-node (native Node.js)

```snippet:node/06-moderation.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  NodeStatic.new           bindings/node/index.d.ts:641-643
  KeyPair.generate         bindings/node/index.d.ts:58
  publicKeyHex             bindings/node/index.d.ts:28
  registerUser             bindings/node/index.d.ts:304
  grantRole                bindings/node/index.d.ts:305
  getUser                  bindings/node/index.d.ts:311
  UserInfo.keyVersion      bindings/node/index.d.ts:145
  (temp attr read, direct token + expiresAt) bindings/node/src/crabs_node.cc:1593-1601
  addCounter               bindings/node/index.d.ts:315
  incrementCounter         bindings/node/index.d.ts:396
  getCounter               bindings/node/index.d.ts:382
  setPolicy                bindings/node/index.d.ts:450
  createTrigger            bindings/node/index.d.ts:505
  TriggerConfig (issue_attribute | change_policy only) bindings/node/index.d.ts:224-241
  Operation.new            bindings/node/index.d.ts:139
  Operation.addResource    bindings/node/index.d.ts:70
  Node.sign                bindings/node/index.d.ts:463
  Node.execute             bindings/node/index.d.ts:464
  Node.on                  bindings/node/index.d.ts:310
  Node.encrypt             bindings/node/index.d.ts:508
  Node.abeKeygen           bindings/node/index.d.ts:520
  AbeKey.destroy           bindings/node/index.d.ts:41-43
  Node.abeDecrypt          bindings/node/index.d.ts:529
  (createTrigger stamps the machine's real admin id and signs with the node key)
                           bindings/node/src/crabs_node.cc:2842-2871
  (event result field)     bindings/node/src/crabs_node.cc:1376
  (trigger fire on execute) src/StateMachine/state_machine.c:1508-1520
  (wildcard non-RESOURCE resources apply nothing, op still lands)
                           src/StateMachine/state_machine.c:1414-1428
maturity: createTrigger/encrypt/trigger fire STABLE; abeKeygen/abeDecrypt pinned by bindings/node/test/abe.js — STABLE (asserted by this snippet); the 'tick' op is the driver convention of node tests
test_ref: bindings/node/test/abe.js (keygen/decrypt round trip + refusals + token map) + bindings/node/test/test.js:158-197 (createTrigger refusal paths) + test/test_trigger.cpp:378-415 (cooldown semantics) + test/test_attribute_machine.cpp:561-584 (temp attr expiry + fan-out semantics)
-->

crabs-node carries the same mechanism without the handler surface: the
counter is driver-written, the tick is a landing op, and the observable
for "the gate opened" is the `op` change event with `result === 0`. The
snippet's decrypt tail runs the identical `abeKeygen`/`abeDecrypt` round
trip on the native binding (same container layout Encrypt serializes,
`bindings/node/src/crabs_node.cc:3036-3119`; same typed `unauthorized`
refusal to a policy-missing key).
`TriggerConfig` here is the *narrower* union
(`'issue_attribute' | 'change_policy'` — no self-perpetuating
`create_trigger`/`delete_trigger`/`disable_trigger` effects), which is the
shape to prefer unless the wasm-only variants are specifically needed.

### C (native)

```snippet:c/06-moderation.c
```

<!-- PROVENANCE
target: native-c
verified: executed
symbols:
  trigger_create               src/Trigger/trigger.h:65-68
  trigger_destroy              src/Trigger/trigger.h:69
  trigger_effect_t             src/Trigger/trigger.h:30-42
  trigger_process_all          src/Trigger/trigger.h:81-82
  (cooldown / one-shot / expiry skips) src/Trigger/trigger.c:214-236
  (ISSUE_ATTRIBUTE → issue_temporary)  src/Trigger/trigger.c:90-114
  attribute_machine_create     src/Attribute/attribute_machine.h:118
  attribute_machine_set_time   src/Attribute/attribute_machine.h:182
  attribute_machine_find_user  src/Attribute/attribute_machine.h:187
  attribute_machine_issue_temporary src/Attribute/attribute_machine.h:200-202
  (fan-out + expiry + keyVersion bump) src/Attribute/attribute_machine.c:961-1026
  condition_resolve_path       src/Condition/condition.c:916-943
  condition.h grammar          src/Condition/condition.h:16-38
  data_item_create             src/CRABS/data_model.h:636
  state_add_item               src/CRABS/data_model.h:719
  g_counter_create/increment/value src/CRDT/crdt_merge.h:27-30
  crypto_abe_setup             src/Crypto/crypto.h:101
  crypto_abe_keygen            src/Crypto/crypto.h:104-107
  crypto_abe_encrypt           src/Crypto/crypto.h:110-114
  crypto_abe_ciphertext_get_policy/data src/Crypto/crypto.h:117-121
  crypto_abe_decrypt           src/Crypto/crypto.h:134-137
  (attr token → ABE word mapping) src/Crypto/crypto.c:95-115
  crypto_ecdsa_generate        src/Crypto/crypto.h:21
  CRABS_SUCCESS                src/CRABS/crabs.h:65
  CRABS_ERR_UNAUTHORIZED       src/CRABS/crabs.h:77
maturity: all STABLE
test_ref: test/test_trigger.cpp:125-170,378-452 (process/cooldown/one-shot) + test/test_attribute_machine.cpp:561-584 (temp attr set_time/expiry) + test/test_crypto.cpp:163-301 (ABE setup/keygen round trip + and/or policies)
-->

## Notes

- `targetRole` is a NAME audience, and the demo leans on that: the fan-out
  matches the attribute *name* part only
  (`_attribute_matches_name`, `src/Attribute/attribute_machine.c:198-204`),
  so every member holding any `role:…` value receives the clearance. That
  is the "established users" predicate of this recipe; an audience keyed to
  specific users wants dedicated attribute names or per-user triggers.
- Temporary attributes read back as the PLAIN token on both runtimes: the
  wasm `getUser` and crabs-node both surface the temp attribute's `value`
  as the full `name:value` string (`clearance:moderator`) — the same token
  the C policy evaluator matches (`src/Crypto/crypto.c:1126-1158`) —
  alongside `verifiedBy: 'trigger'` and `expiresAt`
  (`bindings/node/src/crabs_node.cc:1208-1211`). The snippets pin the
  observed shapes; match on `verifiedBy === 'trigger'` / `temporary` in
  UI code, not on the string.
- Installing a trigger is itself an authorized op: both snippets set
  `setPolicy('__create_trigger__', 'role:admin')` (the demo wiring). On
  crabs-node, `createTrigger` signs with the node key, but it stamps the
  machine's REAL admin identity — the id the node key is registered under at
  construction (`crabs_node.cc:1891-1897`), so any admin id works; the
  snippet pins that by running with the deliberately non-default admin id
  `'chair'`. (Older bindings stamped a literal `'admin'` signer and refused
  with `unauthorized` on machines whose admin id differed.)
- The ABE policy in `encrypt` is not the condition-expression grammar: it
  is the OpenABE CP-ABE grammar (lowercase `and`/`or` with parentheses,
  plain words), pinned by `test/test_crypto.cpp:249-301`. CRABS attribute
  tokens (`'role:member'`) map to ABE words (`role_member`) when keys are
  derived from them (`src/Crypto/crypto.c:95-115`) — keep the policy words
  consistent with what will be in the reader's key.
- A refused op still STREAMS as an op-kind change event (with a nonzero
  `result`, `crabs_node.cc:988`) — "the gate opened" is read as
  `result === 0`, which the node snippet filters explicitly.
- The C snippet runs `trigger_process_all` explicitly because C callers
  *own* the tick loop; the bindings run it for you (post-execute), which
  is why the JS demos never call it.