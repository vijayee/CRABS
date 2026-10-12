---
number: 4
slug: roles-and-policies
title: Roles and who-can-do-what
section: Basics
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
---
## Intent

You want a machine where *who may do what* is a property of the machine, not
of the client: users register with facts they can assert about themselves,
the admin grants roles that users cannot grant themselves, and every signed
operation type is gated by a policy expression over those attributes — with
the machine refusing ops that fail the policy before any effect runs.

## The naive version, and where it breaks

The naive version checks roles in the client: `if (user.role === 'member')
send(op)`. The check and the action live in different places, so the check
is only as honest as the client that runs it — a modified client just
sends `op` anyway. Moving the check "to the server" (one authoritative
process) fixes enforcement but reintroduces the single point of failure
this library exists to avoid.

What you actually need is for the *authorization* to be part of the
verified operation itself: the op is signed, the signer's attributes are
state the machine maintains, and the machine's executor evaluates the
policy against those attributes as part of verification
(`src/StateMachine/state_machine.c:1207`, `src/StateMachine/state_machine.c:768-843`).
The client can no longer separate "check" from "act" — a refused op is a
typed error, never a landed effect.

One subtlety worth knowing before writing code: **self-assertion cannot mint
privileges.** A user registers with *unprivileged* facts (`adult`,
`dept:eng`) and the admin grants *roles* — attempts to register or
self-assert an attribute in the privileged blocklist (`role`, `admin`,
`owner`, …) are refused (`src/Attribute/attribute_machine.c:503-516`,
`:630-648`; the JS demo makes this its negative path, too). The blocklist
is matched case-insensitively so `Role` and `ADMIN` do not slip through
(`src/Attribute/attribute_machine.c:204-233`).

## The shape

- Users: `registerUser(userId, publicKeyHex, initialAttrs)` — facts live in
  `initialAttrs` as a `|`-separated list of `name:value` tokens (C-side
  parsing at `src/Attribute/attribute_machine.c:463-516`; `'adult'` alone is
  already the full token — a bare fact needs no name).
- Roles: `grantRole(targetUser, role, value, signerId)` — installs the
  `role:<value>` attribute *verified by the admin*; the user record's
  `attributes[].verifiedBy` records that provenance.
- Policies: `setPolicy(opType, expression)` — a condition expression over
  attributes. Conjunction of clauses is whitespace or a leading `AND`
  (`'AND role:member adult'` is the smoke-test form, `bindings/wasm/test/smoke.js:17`);
  disjunction uses uppercase `OR` (`'role:writer OR role:admin'`,
  `test/test_durability.cpp:87`). Policies match whole `name:value` tokens
  against the signer's attribute set — a policy `role:member` cannot be
  satisfied by a self-asserted `clearance:member` (audit F-1,
  `src/Crypto/crypto.c:1094-1120`).
- The gate itself: a policy *without* an op is simply never satisfied —
  custom op types carry the policy and their handler runs only after the
  machine verified signature + attributes
  (`src/StateMachine/state_machine.c:1353-1429`).

## What it guarantees / what it doesn't

Guaranteed: a signed op of a policy-gated type executes only when the
signer's current attribute set (self-asserted facts + admin-granted roles)
satisfies the policy expression, against the signer's registered key —
forgery (right identity, wrong key) and clause failure both refuse the op
before any effect. Refusals are typed errors, and the refused op changes
nothing. Privilege acquisition is bounded: neither registration nor
self-assertion can mint a privileged attribute.

Not guaranteed: secrecy about *why* the refusal happened. A wrong clause
and a wrong key surface with the same error text the binding maps from the
machine's decision — deliberately, anti-enumeration (R7-14 collapses
not-found/suspended distinctions to
`unauthorized`, `src/Crypto/crypto.c:1194-1206`). Your application can
distinguish "which clause failed" only by constructing ops that isolate
clauses. Also outside this recipe: expressing roles that depend on *time*
or on other users is Recipe 6/7 territory (triggers, attestations).

## Variations

- Role churn: `grantRole` updates the existing `role:` attribute in place
  (`src/Attribute/attribute_machine.c` — the C test pins single-attribute
  replacement, `test/test_attribute_machine.cpp:152-166`); re-granting a
  different value demotes as well as promotes.
- Suspension: `revokeUser` / C `attribute_machine_suspend_user` flips the
  user's status; the verification path refuses non-`ACTIVE` signers the
  same way as failed clauses (`src/Crypto/crypto.c`, Mode A status check).
- Node binding without handlers: the same policy evaluation runs for
  custom op types even when the binding has no handler surface — the op
  passes authorization and then fails closed with `resource_not_found`,
  which is why the node snippet asserts membership *through* the typed
  error sequence (this mirrors `bindings/node/test/test.js:66-78`).

## Recipe

### crabs-wasm (browser / Node / edge)

```snippet:wasm/04-roles.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:372
  KeyPair.generate          bindings/wasm/index.d.ts:21
  publicKeyHex              bindings/wasm/index.d.ts:15
  KeyPair.destroy           bindings/wasm/index.d.ts:17
  registerUser              bindings/wasm/index.d.ts:213
  grantRole                 bindings/wasm/index.d.ts:214
  getUser                   bindings/wasm/index.d.ts:221
  UserInfo.attributes       bindings/wasm/index.d.ts:155-159
  addCounter                bindings/wasm/index.d.ts:223
  setPolicy                 bindings/wasm/index.d.ts:295
  registerHandlerJs         bindings/wasm/index.d.ts:303
  HandlerState.incrementCounter bindings/wasm/index.d.ts:103
  Operation.create          bindings/wasm/index.d.ts:52
  Operation.signerId        bindings/wasm/index.d.ts:28
  Node.sign                 bindings/wasm/index.d.ts:297
  Node.execute              bindings/wasm/index.d.ts:296
  getCounter                bindings/wasm/index.d.ts:254
  Node.destroy              bindings/wasm/index.d.ts:368
  (error names)             bindings/wasm/bindings-core.js:172-189 (0x2001 unauthorized / 0x5003 invalid_param)
  (privileged check)        src/Attribute/attribute_machine.c:503-516 (audit R7-08)
maturity: all STABLE
test_ref: bindings/wasm/test/smoke.js:8-17 (registerUser + grantRole + setPolicy idiom)
-->

### crabs-node (native Node.js)

```snippet:node/04-roles.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  NodeStatic.new   bindings/node/index.d.ts:312
  KeyPair.generate bindings/node/index.d.ts:14
  publicKeyHex     bindings/node/index.d.ts:8
  registerUser     bindings/node/index.d.ts:182
  grantRole        bindings/node/index.d.ts:183
  getUser          bindings/node/index.d.ts:189
  UserInfo.attributes verifiedBy bindings/node/index.d.ts:55-60 (provenance read:57)
  setPolicy        bindings/node/index.d.ts:249
  Operation.new    bindings/node/index.d.ts:47
  Operation.signerId bindings/node/index.d.ts:21
  Node.sign        bindings/node/index.d.ts:250
  Node.execute     bindings/node/index.d.ts:251
  selfAssert       bindings/node/index.d.ts:184
  (error names)    bindings/node/src/crabs_node.cc:84-120 (typed crabs_error map)
maturity: all STABLE
test_ref: bindings/node/test/test.js:66-78 (policy-authorized op fails closed without a handler) + :97-109 (selfAssert + privileged refusal)
-->

### C (native)

```snippet:c/04-roles.c
```

<!-- PROVENANCE
target: native-c
verified: executed
symbols:
  crypto_ecdsa_generate         src/Crypto/crypto.h:21
  crypto_ecdsa_keypair_destroy  src/Crypto/crypto.h:22
  crypto_sign_operation         src/Crypto/crypto.h:162-164
  attribute_machine_create      src/Attribute/attribute_machine.h:118
  attribute_machine_register_user src/Attribute/attribute_machine.h:130-132
  attribute_machine_grant_role  src/Attribute/attribute_machine.h:133-135
  attribute_machine_find_user   src/Attribute/attribute_machine.h:187
  attribute_machine_user_has_role src/Attribute/attribute_machine.h:188
  attribute_machine_destroy     src/Attribute/attribute_machine.h:119
  (integrator wiring)           base_state.attr_machine back-pointer — src/Util/wasm_helpers.c:242, src/CLI/cli.c:257
  state_add_policy              src/CRABS/data_model.h:720
  state_machine_register_handler src/StateMachine/state_machine.h:238 (op_handler_fn :127)
  operation_create              src/StateMachine/state_machine.h:243
  operation_destroy             src/StateMachine/state_machine.h:244
  signer_key_version (op field) src/StateMachine/state_machine.h:82
  crabs_serialize_for_signing   src/Serialization/serialization.h:96
  serialized_buffer_destroy     src/Serialization/serialization.h:160
  CRABS_UUID_SIZE               src/CRABS/crabs.h:40
  CRABS_MAX_USER_ID             src/CRABS/crabs.h:16
  CRABS_SUCCESS                 src/CRABS/crabs.h:65
  CRABS_ERR_UNAUTHORIZED        src/CRABS/crabs.h:77
  CRABS_ERR_INVALID_PARAM       src/CRABS/crabs.h:95
maturity: all STABLE
test_ref: test/test_durability.cpp:65-106 (signed custom op through state_machine_execute) + test/test_attribute_machine.cpp:100-113 (privileged registration refused)
-->

### Notes

- The three snippets split the recipe's negative path deliberately:
  crabs-wasm runs the full happy path (policy → handler → effect) and
  refuses the clause-missing op; crabs-node proves the authorization gate
  directly (member passes → `resource_not_found`, the *next* gate; missing
  clause → `unauthorized`, the gate itself); the C snippet adds the forged
  signature case. "An unauthorized op is rejected" is not a side note — it
  is the only observable that makes the policy real.
- `verifiedBy` is not equal on both bindings: crabs-node populates
  `attributes[].verifiedBy` (the node snippet asserts `'admin'`, mirroring
  `bindings/node/test/test.js:92`), crabs-wasm currently hands back an
  empty string for it — the wasm snippet asserts values only, and the
  divergence is recorded rather than hidden.
- The registered role IS an attribute: `grantRole('alice','role','member',…)`
  installs `role:member` (smoke.js reads it back via `getUser`, :107-109);
  policies match whole tokens, so express *everything you mean to match*
  as `name:value` tokens, not bare values.
- Signing on C carries three stamps the executor demands, all of which the
  JS `sign` path does for you (see what `crabs_wasm_sign_operation` does,
  `src/Util/wasm_helpers.c:379-408`): HLC + ordering system (`R7-15`), the
  signer's current `key_version` (`R7-04` staleness check, `src/StateMachine/state_machine.c:862-876`),
  and a lamport time strictly newer than the signer's prior op (`R7-11`,
  `src/StateMachine/state_machine.c:1246-1258`). The C snippet stamps all
  three manually — miss one and the op is refused as stale or replayed.
- The C snippet attaches `am->base_state.attr_machine = am` itself because
  `attribute_machine_create` does not (compare `src/Util/wasm_helpers.c:242`
  and `src/CLI/cli.c:257` — both integrators wire it right after create).
  Forget it and every signed op refuses with `unauthorized` regardless of
  attributes.