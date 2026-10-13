---
number: 5
slug: member-profile
title: A member's own profile they control
section: Basics
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
---
## Intent

You want per-member profile data a member can update and everyone can read
— a display name, a bio, a preference. The guarantees that make it a
*profile* and not a bulletin board: only the member writes their own, every
reader sees the same latest value after replicas sync, and a write that
lost a race does not resurrect later.

## The naive version, and where it breaks

The naive version stores the profile on a per-user row and lets whoever
arrives last write it — with no notion of *when* the write happened. Two
updates in flight ("Vic" from one replica, "Vincent" from another) resolve
however the storage settles, differently on different replicas, and can
even settle backwards later (an old row syncs in and overwrites the newer
one). Retry logic makes it worse: a delayed retry of the old write lands
after the new one and wins.

The fix is to give every write an ordering stamp and to make the merge
rule "newest stamp wins, deterministic tie-break" — that is a
last-writer-wins (LWW) register, and it is what the machine's
`LWW_REG` items already are (`src/CRDT/crdt_merge.h:92-103`).

## The shape

- One register per member: `addRegister('profile_alice', 0)` — an LWW
  register item (`CRDT_TYPE` `LWW_REG`).
- On crabs-wasm, the register carries ARBITRARY bytes:
  `setRegisterBytes(name, utf8Bytes, who)` / `getRegisterBytes(name)` — so
  the display name itself is one write (`bindings/wasm/index.d.ts:264,266`;
  exercised at `bindings/wasm/test/handler-reads.js:88-108`).
- On crabs-node, registers are *number-only* int64 slots
  (`bindings/node/index.d.ts:227-234`) — an integer profile field (karma,
  level) travels the same LWW shape; text needs crabs-wasm's byte API.
- Who may write: the wasm snippet routes writes through a policy-gated
  custom op (`setPolicy('update_profile', 'role:member')`) whose handler
  compares the op's signer to the requested target — writing someone
  else's profile is refused inside the machine with `unauthorized`
  (0x2001, `src/CRABS/crabs.h:77`), before `execute` returns.
- Key provenance: `UserInfo.keyVersion` is the JS-visible epoch of the
  member's key material — registration starts it at 1
  (`src/Attribute/attribute_machine.c:495`) and every role grant bumps it
  (`src/Attribute/attribute_machine.c:597,617`); the executor refuses ops
  signed by a stale version (`R7-04`, `src/StateMachine/state_machine.c:873-889`).

## What it guarantees / what it doesn't

Guaranteed: LWW convergence — two replicas that each saw a different
update of the same member's register converge to the newest timestamp's
value, with deterministic tie-breaks (equal timestamps resolve by node id,
higher lexicographic id wins, `test/test_crdt.cpp:502-519`), and no lost
update resurfaces. On crabs-wasm, ownership is machine-enforced for the
op path: a signed op naming a profile other than the signer's is refused
with nothing landed.

Not guaranteed: atomic multi-profile edits (each register is its own LWW
item; there is no transaction across two members' registers — that is
Recipe 9's territory), and a *deletion* that propagates as anything other
than another overwrite (an empty-value write is just the newest write;
registers have no tombstone).

## Variations

- Numeric profiles on every surface: keep the profile schema to integers
  and the same shape runs identically on crabs-wasm, crabs-node *and* C
  — the node snippet shows the int64 discipline (fractional/NaN/Infinity
  refused before the C int64 can truncate; BigInt beyond ±MAX_SAFE_INTEGER
  is wasm-only, `bindings/wasm/index.d.ts:258-263` vs node `:227-234`).
- Rotation-aware writers: a member's writes must carry their CURRENT
  key_version (the `R7-04` gate stamps and checks it); when the C key
  lifecycle rotates the key — `user_key_rotate`
  (`src/Attribute/attribute_machine.h:219-221`, exercised
  `test/test_key_lifecycle.cpp:269`) — stale-key writes are refused, and
  `keyVersion` is how readers observe the rotation happened.
- Wider profiles: the same handler pattern can write several registers per
  op — one op, one member, several fields.

## Recipe

### crabs-wasm (browser / Node / edge)

```snippet:wasm/05-profile.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create                 bindings/wasm/index.d.ts:372
  KeyPair.generate            bindings/wasm/index.d.ts:21
  publicKeyHex                bindings/wasm/index.d.ts:15
  KeyPair.destroy             bindings/wasm/index.d.ts:17
  registerUser                bindings/wasm/index.d.ts:213
  grantRole                   bindings/wasm/index.d.ts:214
  getUser                     bindings/wasm/index.d.ts:221
  UserInfo.keyVersion         bindings/wasm/index.d.ts:153 (wasm-glued value HARDCODED 0, bindings/wasm/bindings-core.js:694-700)
  addRegister                 bindings/wasm/index.d.ts:228
  setRegisterBytes            bindings/wasm/index.d.ts:264
  getRegisterBytes            bindings/wasm/index.d.ts:266
  setPolicy                   bindings/wasm/index.d.ts:295
  registerHandlerJs           bindings/wasm/index.d.ts:303
  HandlerOperation.signerId   bindings/wasm/index.d.ts:145
  HandlerOperation.payload    bindings/wasm/index.d.ts:147 (NUL-terminated string, src/Util/wasm_helpers.c:1195-1201)
  HandlerState.setRegisterBytes bindings/wasm/index.d.ts:114
  Operation.create            bindings/wasm/index.d.ts:52
  Operation.signerId          bindings/wasm/index.d.ts:28
  Operation.payload           bindings/wasm/index.d.ts:30
  Node.sign                   bindings/wasm/index.d.ts:297
  Node.execute                bindings/wasm/index.d.ts:296
  Node.destroy                bindings/wasm/index.d.ts:368
  (handler return code)       src/CRABS/crabs.h:77 (CRABS_ERR_UNAUTHORIZED = 0x2001)
  (LWW struct)                src/CRDT/crdt_merge.h:94-103
maturity: all STABLE
test_ref: bindings/wasm/test/handler-reads.js:88-108 (byte-register round trip, direct + handler)
-->

### crabs-node (native Node.js)

```snippet:node/05-profile.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  NodeStatic.new     bindings/node/index.d.ts:312
  KeyPair.generate   bindings/node/index.d.ts:14
  publicKeyHex       bindings/node/index.d.ts:8
  registerUser       bindings/node/index.d.ts:182
  grantRole          bindings/node/index.d.ts:183
  addRegister        bindings/node/index.d.ts:198
  setRegister        bindings/node/index.d.ts:234 (number-only int64 discipline declared :227-233)
  getRegister        bindings/node/index.d.ts:226
  getUser            bindings/node/index.d.ts:189
  UserInfo.keyVersion bindings/node/index.d.ts:53 (mapped from user->key_version, bindings/node/src/crabs_node.cc:1147)
  (key epoch bumps)  src/Attribute/attribute_machine.c:495 (register) + :597,617 (each grantRole)
  (int64 payload)    src/CRDT/crdt_merge.h:94-99
maturity: all STABLE
test_ref: bindings/wasm/test/registers.js:30-46 (integer-only rejections) + bindings/node/test/test.js:555-578 (node-side register guards)
-->

### C (native)

```snippet:c/05-member-profile.c
```

<!-- PROVENANCE
target: native-c
verified: executed
symbols:
  lww_register_create   src/CRDT/crdt_merge.h:101
  lww_register_merge    src/CRDT/crdt_merge.h:103
  lww_register_destroy  src/CRDT/crdt_merge.h:102
  (struct: value/value_size/timestamp/node_id) src/CRDT/crdt_merge.h:94-99
  CRABS_SUCCESS         src/CRABS/crabs.h:65
maturity: all STABLE
test_ref: test/test_crdt.cpp:485-519 (newer wins + node-id tie-breaker)
-->

### Notes

- The three snippets are three halves of one honest mechanism: crabs-wasm
  demos the byte-register profile end to end (create, enforce ownership,
  LWW overwrite); crabs-node demos the SAME registers with the integer
  payload it can carry, plus the guards the binding itself enforces; the C
  snippet demos the merge rule the JS demos depend on but cannot observe
  (there is no cross-machine merge call in either JS binding — merging
  happens in C, and the C test suite is the pinning evidence).
- `keyVersion` is NOT equal on both bindings: crabs-node maps the real
  `user->key_version` (registration = 1, one grant = 2, asserted in the
  node snippet), while the wasm `getUser` builds its result with hardcoded
  provenance placeholders — `keyVersion: 0`, `publicKeyHex: ''`,
  `verifiedBy: ''` (`bindings/wasm/bindings-core.js:694-700`). Same for the
  Recipe 4 note about `verifiedBy`. If your wasm UI needs key epochs,
  read the C struct or track writes yourself.
- The integer-only discipline is not cosmetic: registers carry a signed
  int64 in C (`crabs_node.cc` converts to int64); both bindings reject
  fractions/NaN/Infinity, wasm additionally accepts BigInt for the full
  int64 range (`bindings/wasm/index.d.ts:262-263`,
  `bindings/wasm/test/registers.js:60-67`). Store scaled units (per-mille)
  rather than decimals.
- Ownership here is handler-level, not policy-grammar-level: the policy
  (`role:member`) gates *who may call the op*, and the handler checks
  `op.signerId` against the requested item. Could the policy expression
  itself express "item owner only"? Not in v1's condition grammar — see
  the {user_id} placeholder support in `preprocess_policy`
  (`src/Condition/condition.c:1501`) for what IS expressible.