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
## The problem

A community machine runs a members-only discussion, and the contact
directory — real names, reach-me-when channels — sits in the machine's
data next to the posts. A spam wave rolls in. Four fresh accounts post
forty messages in an hour; members respond the way humans respond — they
click "report". Under each spam post the counter ticks up: `1`, `2`,
`3`. The rule the community agrees on: **three reports and the reported
poster loses their mouth** — from that moment, an established member may
open the poster's contact information to warn the rest, and any member
still below that bar cannot.

Two things must hold for that rule to mean anything. The *decision* —
three reports, no fewer, no re-fires every second — is made by something
the spammer cannot talk around and cannot see through. And the
*disclosure* is real: below the threshold, the contact information must
be out of reach, not merely hidden behind a check the client runs for
politeness.

## The naive version, and where it breaks

The naive version is a client-side gate: `if (reportCount >= 3) show()`.
Every flaw of client-side authorization (Recipe 4) applies, plus two
structural ones. First, the client that renders the payload already holds
it — "progressive" is theater, there is only one threshold and it is on
the wrong side of the copy. Second, the *escalation* is unbounded: nothing
ties "how many reports" to "what may be revealed", so a modified client
just reads, and an honest one re-escalates on every render.

Storing the payload on a server and gating the endpoint moves the problem,
not the guarantee: the gate and the payload are now one process you must
trust. What you want is the payload *cryptographically* out of reach of
users below the threshold, and the *threshold* evaluated by the same
machine that verifies the ops. That is two mechanisms working together:
a **trigger** that turns a state condition into a temporary attribute
grant, and **attribute-based encryption** that seals the payload to the
attribute policy.

## The idea

A threshold is not a check, it is a **state-transition rule**: when the
accumulated state satisfies a predicate, the machine moves itself into a
new state. Three inputs, one consequence:

- **The count is data.** `abuse_reports` is a plain grow-only counter;
  every report is a signed op. Nothing about counting reports needs a new
  mechanism.
- **The rule is a trigger.** A condition (`report count >= 3`) paired with
  an effect ("issue a temporary attribute"), evaluated *by the machine*
  after every op that lands. The count can cross the threshold only
  through the machine, so the transition can never be skipped.
- **The consequence is a lease.** The effect mints an attribute that has
  an expiry — `clearance:moderator`, good for 10 minutes. Authority is
  not a boolean, it is a lease: the permission existed, it timed out, and
  an expired lease is treated as no lease (fail-closed), not as
  "probably still good".

With the numbers: at `abuse_reports = 2` the condition is false and no
`clearance:moderator` exists anywhere. The third report lands, the next
executed op runs the rule pass, and every established member now holds a
10-minute lease. Only a lease-holder can run the gated op — and *separately*, only
a key derived from the machine's encryption authority can open the
sealed directory.

That separation is the privacy half of the idea. A machine can enforce
two different questions over one payload, and they are *not* the same
question:

- **The policy gate** answers "may these bytes be *read by this op, in
  this machine, right now*" — a signature-and-policy check, evaluated per
  op execution. It binds to a *place* (the machine).
- **The seal** answers "can anyone holding these bytes decrypt them at
  all" — cryptographic, evaluated per read. It binds to a *key*, so a
  copied container is still just garbage without a key.

Each covers the other's blind spot. A gate alone is beaten by lifting the
bytes (a log dump, a data export); a seal alone is beaten by the key-minting
policy running away from the access policy. Here both are fed by the same
attribute state: the gate evaluates `clearance:moderator` directly; the
seal is opened by a key minted for that same attribute set.

## How CRABS encodes it

- **The count:** `addCounter('abuse_reports')`, incremented by the signed
  `report_abuse` op. Trigger conditions resolve FULL item paths to logical
  values — for a struct G-counter, the entry sum; a missing path resolves
  to 0 and never aliases a sibling item.
- **The rule:** `createTrigger(config)` with condition
  `'abuse_reports >= 3'` — parsed to an AST at creation and refused (never
  silently dead) if it cannot parse. Triggers are installed by a signed
  `__create_trigger__` op; give that op type a policy
  (`setPolicy('__create_trigger__', 'role:admin')`) or any member can
  mint clearance for themselves.
- **The lease:** `effectType: 'issue_attribute'` with
  `attributeValue: 'moderator'` and `durationMs: 600000`. On fire the
  effect fans out to every ACTIVE user whose attribute *name* matches
  `targetRole`, prepending a temporary `clearance:moderator` token with an
  expiry. Privileged names (`role`, `admin`, …) are refused at issue
  time — a trigger cannot mint a temporary `role:admin`.
- **Automatic evaluation:** after every successfully executed op the
  machine processes all triggers; `cooldownMs` rate-limits re-fires,
  `oneShot: true` disables after the first.
- **The gate:** `setPolicy('view_contact', 'AND role:member
  clearance:moderator')`. While unexpired, the temporary token counts as
  the full `name:value` clause; expired tokens drop out of evaluation
  fail-closed. Below the threshold the clause cannot be met —
  `unauthorized`, nothing lands.
- **The seal:** `node.encrypt(payload, policy)` produces a container
  (policy + ciphertext bytes) whose payload travels only as ciphertext;
  `node.abeKeygen(attrs)` + `node.abeDecrypt(key, container)` is the
  reader side of the same container — the full round trip exists in both
  JS bindings. The key is derived from the machine's master authority:
  JS never touches the master key, and whoever controls the machine can
  mint a reader key for any attribute set it names — that is the trust
  position to design around. A key whose attributes miss the policy
  refuses with a typed `unauthorized`.
- **Two policy grammars, and they differ.** The *gate* accepts prefix
  (`AND a b`) and infix (`a AND b`); a single-clause prefix form
  (`'AND x'`) collapses to the plain token. The *seal* uses the underlying
  CP-ABE grammar, which is infix-only: `and`/`or` lowercase with
  parentheses, attribute words derived from the CRABS tokens
  (`role:member` ↔ `role_member`). Keep seal-policy words consistent with
  whatever the reader's key was minted from.
- **Temp-attr readback:** on both runtimes the temporary attribute
  surfaces as the plain `name:value` token (`clearance:moderator`) with
  `verifiedBy: 'trigger'` and an `expiresAt` — match on `verifiedBy`/
  `temporary` in UI code, not on the string.
- **C owns its tick:** the C snippet calls `trigger_process_all`
  explicitly; both JS bindings run the pass for you after each execute —
  on wasm `evaluateTriggers()` can also force a pass by executing an
  admin no-op, and on crabs-node any landing op is the tick.

## Try it

### crabs-wasm (browser / Node / edge)

```snippet:wasm/06-moderation.js
```

### crabs-node (native Node.js)

```snippet:node/06-moderation.js
```

### C (native)

```snippet:c/06-moderation.c
```

## What it guarantees / what it doesn't

- The escalation decision runs inside the machine after every op that
  lands — no client can render the gate, skip the threshold, or
  re-escalate past the cooldown.
- The issued permission is a temporary attribute whose expiry the machine
  enforces fail-closed; it cannot itself carry a privileged name.
- The payload it unlocks is *additionally* sealed under the attribute
  policy: without a policy-satisfying key the ciphertext decrypts to
  nothing, and a wrong-attribute key is refused with the same typed
  error.
- The reader key comes from the machine's master authority — the
  key-minting trust position belongs to whoever controls the machine.
- Not guaranteed: *when* the trigger fires relative to real time — the
  pass runs after executed ops, so a machine nobody sends ops to
  evaluates on its own cadence.
- The `targetRole` audience is name-based fan-out: every ACTIVE holder
  of that attribute name, so a broad name fans out broadly — narrow
  audiences want narrow names or per-user triggers.

## Variations

- Explicit ticking — when a machine is mostly idle but the rule should
  still be checked anyway: `evaluateTriggers()` (wasm) signs and executes
  an admin no-op purely to run the trigger pass. On crabs-node there is
  no such method; any landing op is the tick (see the node snippet).
- Self-extinguishing escalation — when the consequence should fire only
  once (a one-time promotion): `oneShot: true` disables the trigger after
  its first fire, while `cooldownMs` shapes the *repeatable* one.
- Watching instead of polling — when a UI should react without syncing:
  each op streams a `change` event, and a *refused* op still appears as
  an op-kind event with a nonzero `result` — "the gate opened" is read as
  `result === 0`.
- Contains conditions — when the state to check is set membership rather
  than a number: the condition grammar also speaks `CONTAINS` over
  OR-set items, e.g. a trigger when a badge set contains an element
  (exercised at C level in `test/test_trigger_contains.cpp`).
- Scheduled disable instead of trigger expiry — when the rule should
  switch off at a known instant: `TriggerConfig` carries no `expiresAt`
  in either binding's JS surface (the C trigger struct does, and the
  trigger pass skips expired ones); a scheduled `disable_trigger` op is
  the JS-visible path.
- Narrower effect vocabulary on node — when you prefer the smallest
  surface: crabs-node's `TriggerConfig.effectType` is only
  `'issue_attribute' | 'change_policy'`, which is the shape to prefer
  unless the wasm-only self-perpetuating variants
  (`create_trigger`/`delete_trigger`/`disable_trigger`) are specifically
  needed.

## Verified against the code

<!-- PROVENANCE
trigger pass: machine-evaluated after every executed op — Step 9, src/StateMachine/state_machine.c:1907-1919; wasm evaluateTriggers signs+executes an admin no-op to run the pass (bindings/wasm/index.d.ts:738).
resolve path: FULL item path → logical value; missing path resolves 0, no sibling aliasing — condition_resolve_path src/Condition/condition.c:916-943.
creation-time parse refusal: unparseable condition is rejected instead of stored as a silently-dead NULL AST — src/Trigger/trigger.c:432-437.
skip discipline: cooldown :219-221 (clock-regression guard) · expired :224-226 · one-shot :228 (also :269) — src/Trigger/trigger.c.
fan-out: issue audience matches attribute NAME only (_attribute_matches_name src/Attribute/attribute_machine.c:198-204; role match at :932-943); issue_temporary prepends a temp token with expiry + fans out to every ACTIVE name-holder — attribute_machine_issue_temporary src/Attribute/attribute_machine.c:954-1027.
privileged refusal: _is_privileged_attr_name gate refuses a trigger-issued 'role:…' — src/Attribute/attribute_machine.c:981-983 (the privileged-name gate).
temp token in policy: expired temp attributes are dropped fail-closed (expires_at <= now, or clock==0) before the token is offered to the policy evaluator — src/Crypto/crypto.c:1128-1177 (_build_attr_string; R8-A-8 comment at :1170-1174).
token shape: the temp attr readback is the PLAIN name:value token — wasm bindings/wasm/bindings-core.js:895-926 (value: tempName, verifiedBy 'trigger', temporary true, expiresAt) · node bindings/node/src/crabs_node.cc:1592-1601 · matched in C at crypto.c:1128-1177.
machine-held master key (trust note): abe_mk lives in the machine (wired src/Attribute/attribute_machine.c:309); abeKeygen consults no user record — crypto_abe_keygen src/Crypto/crypto.c:809-857 — so "a moderator decrypts" holds only because a policy-satisfying key was minted for it; policy-missing keys refuse typed unauthorized; the C battery pins it end to end.
policy grammar: gate accepts prefix and infix; single-clause 'AND x' collapses to x — src/Crypto/crypto.c:680-699 (single_clause branch at :694-699); every OTHER dangling shape still refuses (pinned) — and the SEAL grammar is OpenABE CP-ABE: infix-only, lowercase and/or, parens — pinned by test/test_crypto.cpp:262-447 (TestPolicyAnd/Or + TestPolicyInfixAndComparison + SingleClauseAndPolicyIsTheClause).
seal round trip: encrypt → abeKeygen(attrs) → abeDecrypt exists on BOTH bindings; container layout = u16le policy length + policy bytes + u32le ct length + ct — pinned by bindings/wasm/test/abe-decrypt.js + bindings/node/test/abe.js (round trip, refusals, token map, tamper fail-closed) and bindings/wasm/test/smoke.js:111-130 (container layout).
C owns the tick: trigger_process_all src/Trigger/trigger.h:81-82 — the C snippet calls it explicitly; wasm/node run it post-execute (trigger_ticking defer note, trigger.h:80).
node narrower TriggerConfig: effectType 'issue_attribute' | 'change_policy' only; wasm adds the trigger-management effects — bindings/node/index.d.ts:224-245 vs bindings/wasm/index.d.ts:295-307.
node createTrigger stamps the machine's REAL admin id (the id the node key is registered under) and signs with the node key — bindings/node/src/crabs_node.cc:2772 (stub) + :2842-2843 (signer stamp); admin_id_ is set at construction, :1288 — so any admin id works; the node snippet pins that by running with the deliberately non-default admin id 'chair'.
refused ops still stream: an event with a nonzero result field is emitted for refused ops — bindings/node/src/crabs_node.cc:1376 ("the gate opened" = result === 0).

target: crabs-wasm (snippet wasm/06-moderation.js)
verified: executed
symbols:
  Node.create              bindings/wasm/index.d.ts:774
  KeyPair.generate         bindings/wasm/index.d.ts:44
  publicKeyHex             bindings/wasm/index.d.ts:38
  KeyPair.destroy          bindings/wasm/index.d.ts:40
  registerUser             bindings/wasm/index.d.ts:480
  grantRole                bindings/wasm/index.d.ts:481
  getUser                  bindings/wasm/index.d.ts:488
  addCounter               bindings/wasm/index.d.ts:490
  setPolicy                bindings/wasm/index.d.ts:638
  createTrigger            bindings/wasm/index.d.ts:658
  TriggerConfig            bindings/wasm/index.d.ts:295-307
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
  (temp attr read, plain token) bindings/wasm/bindings-core.js:895-926 (getUser temp branch)
  (trigger fire on execute) src/StateMachine/state_machine.c:1907-1919
  (issue fan-out)          src/Attribute/attribute_machine.c:954-1027
  (temp token in policy)   src/Crypto/crypto.c:1128-1177
  (cooldown skip)          src/Trigger/trigger.c:219-221
maturity: all STABLE
test_ref: bindings/wasm/test/abe-decrypt.js (machine-held-M-key keygen/decrypt round trip, unauthorized refusals, token map, tamper fail-closed) + bindings/wasm/test/smoke.js:111-130 (encrypt container layout) + bindings/wasm/test/change-events.js:44-52 (change event shape) + examples/devtools_demo/demo.js:54-84 (createTrigger policy + config wiring)

target: crabs-node (snippet node/06-moderation.js)
verified: executed
symbols:
  NodeStatic.new           bindings/node/index.d.ts:641-642 (new Node)
  KeyPair.generate         bindings/node/index.d.ts:71 (KeyPairStatic :69-73)
  publicKeyHex             bindings/node/index.d.ts:28
  registerUser             bindings/node/index.d.ts:304
  grantRole                bindings/node/index.d.ts:305
  getUser                  bindings/node/index.d.ts:311
  UserInfo.keyVersion      bindings/node/index.d.ts:145
  (temp attr read, plain token + expiresAt) bindings/node/src/crabs_node.cc:1592-1601
  addCounter               bindings/node/index.d.ts:315
  incrementCounter         bindings/node/index.d.ts:396
  getCounter               bindings/node/index.d.ts:382
  setPolicy                bindings/node/index.d.ts:450
  createTrigger            bindings/node/index.d.ts:505
  TriggerConfig (issue_attribute | change_policy only) bindings/node/index.d.ts:224-245
  Operation.new            bindings/node/index.d.ts:139 (OperationStatic :138)
  Operation.addResource    bindings/node/index.d.ts:83
  Node.sign                bindings/node/index.d.ts:463
  Node.execute             bindings/node/index.d.ts:464
  Node.on                  bindings/node/index.d.ts:310
  Node.encrypt             bindings/node/index.d.ts:508
  Node.abeKeygen           bindings/node/index.d.ts:520
  AbeKey.destroy           bindings/node/index.d.ts:41-43
  Node.abeDecrypt          bindings/node/index.d.ts:529
  (createTrigger stamps the machine's real admin id and signs with the node key)
                           bindings/node/src/crabs_node.cc:2772 + :2842-2843
  (event result field)     bindings/node/src/crabs_node.cc:1376
  (trigger fire on execute) src/StateMachine/state_machine.c:1907-1919
  (wildcard non-RESOURCE resources apply nothing, op still lands)
                           src/StateMachine/state_machine.c:1850-1856
maturity: createTrigger/encrypt/trigger fire STABLE; abeKeygen/abeDecrypt pinned by bindings/node/test/abe.js — STABLE (asserted by this snippet); the 'tick' op is the driver convention of node tests
test_ref: bindings/node/test/abe.js (keygen/decrypt round trip + refusals + token map) + bindings/node/test/test.js:158-197 (createTrigger refusal paths) + test/test_trigger.cpp:378-416 (cooldown semantics) + test/test_attribute_machine.cpp:561-585 (temp attr expiry + fan-out semantics)

target: native-c (snippet c/06-moderation.c)
verified: executed
symbols:
  trigger_create               src/Trigger/trigger.h:65-68
  trigger_destroy              src/Trigger/trigger.h:69
  trigger_effect_t             src/Trigger/trigger.h:30-42
  trigger_process_all          src/Trigger/trigger.h:81-82
  (cooldown / one-shot / expiry skips) src/Trigger/trigger.c:216-236
  (ISSUE_ATTRIBUTE → issue_temporary)  src/Trigger/trigger.c:90-114
  attribute_machine_create     src/Attribute/attribute_machine.h:118
  attribute_machine_set_time   src/Attribute/attribute_machine.h:182
  attribute_machine_find_user  src/Attribute/attribute_machine.h:187
  attribute_machine_issue_temporary src/Attribute/attribute_machine.h:200-202
  (fan-out + expiry + keyVersion bump) src/Attribute/attribute_machine.c:954-1027
  condition_resolve_path       src/Condition/condition.c:916-943
  condition.h grammar          src/Condition/condition.h:16-38
  data_item_create             src/CRABS/data_model.h:636
  state_add_item               src/CRABS/data_model.h:719
  g_counter_create/increment/value src/CRDT/crdt_merge.h:27-30
  crypto_abe_setup             src/Crypto/crypto.h:101
  crypto_abe_keygen            src/Crypto/crypto.h:107
  crypto_abe_encrypt           src/Crypto/crypto.h:112-117
  crypto_abe_ciphertext_get_policy/data src/Crypto/crypto.h:120-121
  crypto_abe_decrypt           src/Crypto/crypto.h:134-137
  (attr token → ABE word mapping) src/Crypto/crypto.c:100-113
  (single-clause 'AND x' collapses to x) src/Crypto/crypto.c:680-699
  crypto_ecdsa_generate        src/Crypto/crypto.h:21
  CRABS_SUCCESS                src/CRABS/crabs.h:65
  CRABS_ERR_UNAUTHORIZED       src/CRABS/crabs.h:77
maturity: all STABLE
test_ref: test/test_trigger.cpp:125-170,378-452 (process/cooldown/one-shot) + test/test_attribute_machine.cpp:561-585 (temp attr set_time/expiry) + test/test_crypto.cpp:162-447 (keygen + round trip + and/or + infix + single-clause pins)
-->