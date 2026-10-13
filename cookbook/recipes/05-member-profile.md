---
number: 5
slug: member-profile
title: A member's own profile they control
section: Basics
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
teaches: last-writer-wins registers and per-member data
---
## The problem

Two tabs are open on the same profile editor. Tab one saves the display
name "Vic Morrow"; tab two saves "V. Morrow" a moment later. The two saves
leave the machine they were issued on out of order — a slow network holds
the first; the second arrives, then the first straggles in behind it. A
profile is *one field per member*, not an event feed, so the record has to
pick a winner, and the picking has to agree on every replica that syncs:
the same winner everywhere, no matter what order the writes arrive in, and
no winner that later gets demoted when some old copy finally syncs down.

Also implied in "profile": this member writes it, everyone reads it. Bob
must not be able to save into Alice's field — and the enforcement has to
live somewhere stronger than Bob's form validation.

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
`LWW_REG` items already are.

## The idea

Keep one small tuple per field instead of bare content: **(value, stamp,
writer)**. Two replicas that have never met each other's writes still hold
comparable tuples, so "which write is newer" is a pure function of the two
tuples — timestamp, and if timestamps tie, writer id. That is why the rule
can survive *any* merge order: it consults only the tuples, never the
arrival sequence.

The tie-break is not decoration. Timestamps tie when two devices write
inside the same clock tick or carry skewed clocks, and a rule that left
ties unresolved would settle them by luck — differently on different
replicas. A total ordering (stamp, then lexicographic writer id) makes the
winner a *fact*, which is the whole point of teaching this register first:
LWW is the smallest CRDT, and every rule it needs — monotone orderings and
a deterministic tie-break — is the thing plain timestamps alone cannot give
you.

The cost is the flip side: a concurrent update is not *merged*, it is
*replaced*. Last-writer-wins can discard a write. For a profile that is
usually what you want; for a counter, never.

## How CRABS encodes it

- One register per member: `addRegister('profile_alice', 0)` — an LWW
  register item.
- On crabs-wasm, the register carries ARBITRARY bytes:
  `setRegisterBytes(name, utf8Bytes, who)` / `getRegisterBytes(name)` — so
  the display name itself is one write.
- On crabs-node, registers are *number-only* int64 slots — an integer
  profile field (karma, level) travels the same LWW shape; text needs
  crabs-wasm's byte API. Both bindings reject fractional/NaN/Infinity
  values before the C int64 could truncate them; only wasm additionally
  accepts BigInt for the full int64 range.
- Who may write: the wasm snippet routes writes through a policy-gated
  custom op (`setPolicy('update_profile', 'role:member')`) whose handler
  compares the op's signer to the requested target — writing someone
  else's profile is refused inside the machine with `unauthorized`,
  before `execute` returns.
- Key provenance: `UserInfo.keyVersion` is the JS-visible epoch of the
  member's key material — registration starts it at 1 and every role grant
  bumps it; the executor refuses ops signed by a stale version.

## Try it

### crabs-wasm (browser / Node / edge)

```snippet:wasm/05-profile.js
```

### crabs-node (native Node.js)

```snippet:node/05-profile.js
```

### C (native)

```snippet:c/05-member-profile.c
```

## What it guarantees / what it doesn't

- LWW convergence: two replicas that each saw a different update of the
  same member's register converge to the newest timestamp's value, with
  deterministic tie-breaks (equal timestamps resolve by node id, higher
  lexicographic id wins), and no lost update resurfaces.
- Ownership is machine-enforced on the op path: a signed op naming a
  profile other than the signer's is refused with nothing landed.
- No atomic multi-profile edits — each register is its own LWW item;
  there is no transaction across two members' registers (Recipe 9's
  territory).
- No real deletion: an empty-value write is just the newest write;
  registers have no tombstone.
- Ownership here is handler-level, not policy-grammar-level: the policy
  (`role:member`) gates *who may call the op*; the op-body "item owner
  only" is not expressible in v1's condition grammar.
- Merging happens in C — there is no cross-machine merge call in either JS
  binding, so the C snippet is where the merge rule itself is exercised.

## Variations

- Numeric profiles on every surface — when the same schema must run on
  all three targets: keep the profile schema to integers and the same
  shape runs identically on crabs-wasm, crabs-node *and* C — the node
  snippet shows the int64 discipline.
- Rotation-aware writers — when keys rotate: a member's writes must carry
  their CURRENT key_version; when the C key lifecycle rotates the key,
  stale-key writes are refused, and `keyVersion` is how readers observe
  the rotation happened.
- Wider profiles — when one write should move several fields: the same
  handler pattern can write several registers per op — one op, one
  member, several fields.

## Verified against the code

<!-- PROVENANCE
LWW structure: single register item, (value, timestamp, node_id) tuple, merge keeps the newest with node-id tie-break.
LWW C shape: lww_register_t src/CRDT/crdt_merge.h:94-99 · create :101 · merge :103 · destroy :102. Test pins: test/test_crdt.cpp:485-500 (newer wins) · :502-519 (tie broken by node id).
byte-register API: wasm-only — setRegisterBytes bindings/wasm/index.d.ts:564 · getRegisterBytes :566 (HandlerState.setRegisterBytes :206, HandlerOperation :268-278); the node binding has no byte API and accepts numbers only for its int64 registers — bindings/node/index.d.ts:386-392; wasm additionally accepts BigInt past ±Number.MAX_SAFE_INTEGER — wasm register discipline docs :558-563. Pinned by bindings/wasm/test/registers.js:36-46 (integer-only rejections), :60-67 (BigInt round-trip incl. 2**60) and bindings/node/test/test.js:552-578 (node-side guards); byte round trip direct + handler context: bindings/wasm/test/handler-reads.js:86-110.
ownership refusal: the handler returns CRABS_ERR_UNAUTHORIZED = 0x2001 (src/CRABS/crabs.h:77) and execute surfaces the typed name (node crabs_node.cc:132; wasm map in bindings/wasm/bindings-core.js). NUL-terminated payloads reach handlers (src/Util/wasm_helpers.c:1741-1749).
keyVersion: registration starts at 1 — src/Attribute/attribute_machine.c:495; every role grant bumps it — :597,617; JS-visible readback on BOTH bindings (wasm machine-mapped bindings/wasm/bindings-core.js:895-952, keyVersion at :945; node mapped bindings/node/src/crabs_node.cc:1575 — pinned by getuser-readback.js + the node snippet's =2 assertion). R7-04 staleness gate: _check_key_version src/StateMachine/state_machine.c:880-892. Key rotation (user_key_rotate — src/Attribute/attribute_machine.h:219-221) is C-only; test/test_key_lifecycle.cpp:269.
"item owner only" is not in v1's grammar: the {user_id} placeholder in preprocess_policy — src/Condition/condition.c:1245-1262, applied :1510.
Note: the node snippet's header comment cites the pre-A12 d.ts line range (227-234) — current node register-discipline lines are 386-392; the behavior is unchanged.

target: crabs-wasm (snippet wasm/05-profile.js)
verified: executed
symbols:
  Node.create                 bindings/wasm/index.d.ts:774
  KeyPair.generate            bindings/wasm/index.d.ts:44
  publicKeyHex                bindings/wasm/index.d.ts:38
  KeyPair.destroy             bindings/wasm/index.d.ts:42
  registerUser                bindings/wasm/index.d.ts:480
  grantRole                   bindings/wasm/index.d.ts:481
  getUser                     bindings/wasm/index.d.ts:488
  UserInfo.keyVersion         bindings/wasm/index.d.ts:279
  addRegister                 bindings/wasm/index.d.ts:495
  setRegisterBytes            bindings/wasm/index.d.ts:564
  getRegisterBytes            bindings/wasm/index.d.ts:566
  setPolicy                   bindings/wasm/index.d.ts:638
  registerHandlerJs           bindings/wasm/index.d.ts:683
  HandlerState.setRegisterBytes bindings/wasm/index.d.ts:206
  HandlerOperation.signerId   bindings/wasm/index.d.ts:270
  HandlerOperation.payload    bindings/wasm/index.d.ts:271
  Operation.create            bindings/wasm/index.d.ts:122
  Operation.destroy           bindings/wasm/index.d.ts:118
  Node.sign                   bindings/wasm/index.d.ts:657
  Node.execute                bindings/wasm/index.d.ts:656
  Node.destroy                bindings/wasm/index.d.ts:770
maturity: all STABLE
test_ref: bindings/wasm/test/handler-reads.js:86-110 (byte-register round trip, direct + handler)

target: crabs-node (snippet node/05-profile.js)
verified: executed
symbols:
  NodeStatic.new     bindings/node/index.d.ts:642 (new Node)
  KeyPair.generate   bindings/node/index.d.ts:71
  publicKeyHex       bindings/node/index.d.ts:28
  registerUser       bindings/node/index.d.ts:304
  grantRole          bindings/node/index.d.ts:305
  addRegister        bindings/node/index.d.ts:320
  setRegister        bindings/node/index.d.ts:392 (number-only int64 discipline docs :386-390)
  getRegister        bindings/node/index.d.ts:384
  getUser            bindings/node/index.d.ts:311
  UserInfo.keyVersion bindings/node/index.d.ts:145 (mapped from user->key_version, bindings/node/src/crabs_node.cc:1575)
  (key epoch bumps)  src/Attribute/attribute_machine.c:495 (register) + :597,617 (each grantRole)
  (int64 payload)    src/CRDT/crdt_merge.h:94-99
maturity: all STABLE
test_ref: bindings/wasm/test/registers.js:36-46 (integer-only rejections) + bindings/node/test/test.js:552-578 (node-side register guards)

target: native-c (snippet c/05-member-profile.c)
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