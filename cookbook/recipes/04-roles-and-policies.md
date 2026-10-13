---
number: 4
slug: roles-and-policies
title: Roles and who-can-do-what
section: Basics
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
teaches: authorization as state — attributes deciding what runs
---
## The problem

A merge request sits open on a small team's machine. Anyone on the team can
comment; only a maintainer may close it. One evening, two closing events
land: a maintainer closes it, and — minutes later — an ordinary member's
client sends a second "close" op that the member's app produced by accident.

Whoever holds the record at merge time has to answer one question: was this
second closer *allowed*? The answer cannot depend on the client that sent
the op, because the client in this story is precisely the thing that got it
wrong. It cannot depend on a checklist a human ran before clicking, because
checklists do not run at merge time. The permission has to be a fact about
the *machine's state* that refuses the wrong closer and lets the right one
through, on every replica, in every order of arrival.

## The naive version, and where it breaks

The naive version checks roles in the client: `if (user.role === 'member')
send(op)`. The check and the action live in different places, so the check
is only as honest as the client that runs it — a modified client just
sends `op` anyway. Moving the check "to the server" (one authoritative
process) fixes enforcement but reintroduces the single point of failure
this library exists to avoid.

What you need is for the *authorization* to be part of the verified
operation itself: the machine's executor evaluates the signer's attributes
against the policy as part of verification, in the same step that checks
the signature. The client can no longer separate "check" from "act" — a
refused op is a typed error, never a landed effect.

## The idea

Authorization is a function of **who the signer is** and **what the state
says they're entitled to** — so store both as state and evaluate the
function at execution time. A user record carries *facts* (unprivileged
claims a user makes about themselves, like `adult` or `dept:eng`) and
*roles* (things only the admin's signature can install, like `role:member`).
A policy is a boolean expression over those attribute tokens, attached to
an operation *type*; execution evaluates it fresh every time, so
permissions can change (a grant, a promotion, a demotion) and the answer
changes with them.

The split between facts and roles exists because some attributes are
privileges, and a system that lets users mint their own privileges has
decided nothing at all. Self-assertion covers bookkeeping facts; the admin
path covers everything the policies gate on. And because policies match
whole `name:value` tokens, the meaning of an attribute rides with its name
— a self-asserted `clearance:member` cannot satisfy a `role:member` clause,
no matter how the values rhyme.

## How CRABS encodes it

- Users: `registerUser(userId, publicKeyHex, initialAttrs)` — facts live in
  `initialAttrs` as a `|`-separated list of `name:value` tokens (a bare
  `'adult'` is already the full token — a fact needs no name).
- Roles: `grantRole(targetUser, role, value, signerId)` — installs the
  `role:<value>` attribute verified by the admin; the user record's
  `attributes[].verifiedBy` records that provenance.
- Policies: `setPolicy(opType, expression)` — a condition expression over
  attributes. Clauses join with whitespace or a leading `AND`
  (`'AND role:member adult'` is the smoke-test form); disjunction uses
  uppercase `OR` (`'role:writer OR role:admin'` is the durability-suite
  form).
- The gate itself: a policy *without* an op is simply never satisfied —
  custom op types carry the policy, and their handler runs only after the
  machine verified signature and attributes together.
- One subtlety worth knowing before writing code: **self-assertion cannot
  mint privileges.** Registration and self-assertion both refuse the
  privileged blocklist (`role`, `admin`, `owner`, …), case-insensitively.
  The snippets make this their negative path.

## Try it

### crabs-wasm (browser / Node / edge)

```snippet:wasm/04-roles.js
```

### crabs-node (native Node.js)

```snippet:node/04-roles.js
```

### C (native)

```snippet:c/04-roles.c
```

The three snippets split the negative path deliberately: crabs-wasm runs the
full happy path (policy → handler → effect) and refuses the clause-missing
op; crabs-node proves the authorization gate directly (member passes →
`resource_not_found`, the *next* gate; missing clause → `unauthorized`, the
gate itself); the C snippet adds the forged signature case. "An unauthorized
op is rejected" is not a side note — it is the only observable that makes
the policy real.

## What it guarantees / what it doesn't

- A signed op of a policy-gated type executes only when the signer's
  current attribute set (self-asserted facts + admin-granted roles)
  satisfies the policy expression, against the signer's registered key.
- Forgery (right identity, wrong key) and clause failure both refuse the
  op before any effect; refusals are typed errors and the refused op
  changes nothing.
- Privilege acquisition is bounded: neither registration nor
  self-assertion can mint a privileged attribute.
- No secrecy about *why* the refusal happened: a wrong clause and a wrong
  key surface with the same error text — deliberately, anti-enumeration.
  Distinguishing "which clause failed" means constructing ops that isolate
  clauses.
- Roles that depend on *time* or on other users are Recipe 6/7 territory
  (triggers, attestations), not policy expressions.

## Variations

- Role churn — when promotions and demotions are routine: `grantRole`
  updates the existing `role:` attribute in place, so re-granting a
  different value demotes as well as promotes.
- Suspension — when access needs an off switch: `revokeUser` (or the C
  suspend call) flips the user's status, and the verification path refuses
  non-`ACTIVE` signers the same way as failed clauses.
- Node binding without handlers — when you want to watch the gate itself:
  the same policy evaluation runs for custom op types even without a
  handler surface; the op passes authorization and then fails closed with
  `resource_not_found`, which is why the node snippet asserts membership
  *through* the typed error sequence.

## Verified against the code

<!-- PROVENANCE
authorization as verification (policy + signature evaluated together in the executor's verify step): _verify_operation_authorization src/StateMachine/state_machine.c:777ff, invoked at :1601.
attribute tokens: facts parse from registerUser's initial_attrs — attribute_machine_register_user src/Attribute/attribute_machine.c:463 + _parse_attributes; whole "name:value" token matching (audit F-1) — src/Crypto/crypto.c:1129-1190; OR disjunction form — test/test_durability.cpp:87.
privileged blocklist: registration refuses minted privileges (audit R7-08) — src/Attribute/attribute_machine.c:509-524; self-assert refusal — :648; list + strcasecmp (case-insensitive) — :215-233; policy tokens cannot be satisfied by a differently-named member value (whole-token match, F-1) — crypto.c:1134-1157.
anti-enumeration collapse of not-found/suspended to unauthorized (R7-14) — src/Crypto/crypto.c:1228-1239.
C signing stamps the JS sign path performs for you: crabs_wasm_sign_operation src/Util/wasm_helpers.c:392-423 (HLC + ordering system, R7-15) + caller-fills key_version (:410); R7-04 staleness gate _check_key_version src/StateMachine/state_machine.c:880-892; R7-11 lamport monotonicity :1640-1650. Integrator wiring of the attr_machine back-pointer: src/Util/wasm_helpers.c:247, src/CLI/cli.c:259.
verifiedBy provenance reads back on BOTH bindings: node maps user->attributes[].verified_by (bindings/node/src/crabs_node.cc:1588, snippet asserts 'admin'); wasm maps the same machine field (bindings/wasm/bindings-core.js:895-952, pinned by bindings/wasm/test/getuser-readback.js).
typed error names: node map bindings/node/src/crabs_node.cc:125-158; wasm map bindings/wasm/bindings-core.js (0x2001 unauthorized / 0x5003 invalid_param); CRABS_ERR_UNAUTHORIZED = 0x2001 src/CRABS/crabs.h:77, CRABS_ERR_INVALID_PARAM = 0x5003 :95.
role IS an attribute: grantRole installs role:<value>; smoke.js reads it back via getUser — bindings/wasm/test/smoke.js:11, :40 area.

target: crabs-wasm (snippet wasm/04-roles.js)
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:774
  KeyPair.generate          bindings/wasm/index.d.ts:44
  publicKeyHex              bindings/wasm/index.d.ts:38
  KeyPair.destroy           bindings/wasm/index.d.ts:40
  registerUser              bindings/wasm/index.d.ts:480
  grantRole                 bindings/wasm/index.d.ts:481
  getUser                   bindings/wasm/index.d.ts:488
  UserInfo                  bindings/wasm/index.d.ts:277-288 (attributes[] · verifiedBy :284)
  addCounter                bindings/wasm/index.d.ts:490
  setPolicy                 bindings/wasm/index.d.ts:638
  registerHandlerJs         bindings/wasm/index.d.ts:683
  HandlerState.incrementCounter bindings/wasm/index.d.ts:195
  HandlerOperation.signerId bindings/wasm/index.d.ts:270
  Operation.create          bindings/wasm/index.d.ts:122
  Operation.destroy         bindings/wasm/index.d.ts:118
  Node.sign                 bindings/wasm/index.d.ts:657
  Node.execute              bindings/wasm/index.d.ts:656
  getCounter                bindings/wasm/index.d.ts:554
  Node.destroy              bindings/wasm/index.d.ts:770
maturity: all STABLE
test_ref: bindings/wasm/test/smoke.js:8-17 (registerUser + grantRole + setPolicy idiom) · getuser-readback.js (verifiedBy machine readback)

target: crabs-node (snippet node/04-roles.js)
verified: executed
symbols:
  NodeStatic.new   bindings/node/index.d.ts:642 (new Node)
  KeyPair.generate bindings/node/index.d.ts:71
  publicKeyHex     bindings/node/index.d.ts:28
  registerUser     bindings/node/index.d.ts:304
  grantRole        bindings/node/index.d.ts:305
  getUser          bindings/node/index.d.ts:311
  UserInfo         bindings/node/index.d.ts:142-152 (verifiedBy :149)
  setPolicy        bindings/node/index.d.ts:450
  Operation        bindings/node/index.d.ts:76 (signerId :78) · OperationStatic :138
  Node.sign        bindings/node/index.d.ts:463
  Node.execute     bindings/node/index.d.ts:464
  selfAssert       bindings/node/index.d.ts:306
maturity: all STABLE
test_ref: bindings/node/test/test.js:66-78 (policy-authorized op fails closed without a handler) + :97-109 (selfAssert + privileged refusal)

target: native-c (snippet c/04-roles.c)
verified: executed
symbols:
  crypto_ecdsa_generate         src/Crypto/crypto.h:21
  crypto_ecdsa_keypair_destroy  src/Crypto/crypto.h:22
  crypto_sign_operation         src/Crypto/crypto.h:171-174
  attribute_machine_create      src/Attribute/attribute_machine.h:118
  attribute_machine_register_user src/Attribute/attribute_machine.h:130-132
  attribute_machine_grant_role  src/Attribute/attribute_machine.h:133-135
  attribute_machine_find_user   src/Attribute/attribute_machine.h:187
  attribute_machine_user_has_role src/Attribute/attribute_machine.h:188
  attribute_machine_destroy     src/Attribute/attribute_machine.h:119
  state_add_policy              src/CRABS/data_model.h:759
  state_machine_register_handler src/StateMachine/state_machine.h:340-341 (op_handler_fn :127)
  operation_create              src/StateMachine/state_machine.h:346
  operation_destroy             src/StateMachine/state_machine.h:347
  signer_key_version (op field) src/StateMachine/state_machine.h:82
  crabs_serialize_for_signing   src/Serialization/serialization.h:96
  serialized_buffer_destroy     src/Serialization/serialization.h:160
  CRABS_UUID_SIZE               src/CRABS/crabs.h:40
  CRABS_MAX_USER_ID             src/CRABS/crabs.h:16
  CRABS_SUCCESS                 src/CRABS/crabs.h:65
  CRABS_ERR_UNAUTHORIZED        src/CRABS/crabs.h:77
  CRABS_ERR_INVALID_PARAM       src/CRABS/crabs.h:95
maturity: all STABLE
test_ref: test/test_durability.cpp:65-106 (signed custom op through state_machine_execute, 'role:writer OR role:admin' at :87) + test/test_attribute_machine.cpp:100-113 (privileged registration refused) + :152-166 (single-attribute replacement on re-grant)
-->