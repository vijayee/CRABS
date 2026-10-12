---
number: 16
slug: revocable-data
title: Data that must be revocable
section: Ground truth
status: PARTIAL
maturity: STABLE
target: crabs-wasm
languages: c wasm node
---
## Intent

You have data leaving the machine (or staying in it) that someone can lose
their right to: an encrypted payload sealed under an attribute policy, a
reader granted access, and later — revocation. Stated exactly, the
requirement has three halves, and they fail separately:

- *Forward sealing*: future ciphertexts should only be openable by
  currently-authorized readers (policy-gated encryption);
- *Fail-closed writes*: once a reader is revoked, the ops they sign refuse —
  on every surface, with or without the reader present;
- *Recall*: the ciphertexts the revoked reader may already hold stop
  opening.

## The naive version, and where it breaks

The naive version treats `revokeUser` as an un-open button on the data:
revoke the reader, the ciphertext refuses. That is not what an ABE
ciphertext is. The seal carries its policy **forever** — the re-check at
decryption time is *the reader's key against the policy*, and a CP-ABE key
derived from attributes when access was granted is a bearer instrument: no
user-record lookup happens at decrypt. The C snippet below executes the
refutation — a reader whose user record is REVOKED still opens the payload
they were already able to derive a key for, because
`crypto_abe_decrypt` consults no user status and no revocation registry
(`src/Crypto/crypto.c:1041-1079`).

The other naive direction fails at the other end: skipping revocation
entirely, because "the data is already sealed" — which ignores the *write*
half. A revoked reader who keeps signing ops is refused, and CRABS' epoch
mechanism makes the refusal structural rather than a list check: every user
carries a monotonically increasing `key_version`, bumped by every record
mutation, and every op the v1.3 signing path stamps that version — an op
carrying a stale stamp refuses with a typed staleness error (R7-04,
`src/StateMachine/state_machine.c:862-873`). Revocation without that stamp
would rot into a race: a op signed *just before* the revoke would replay
fine afterward.

## The shape

- *The seal*: `node.encrypt(payload, policy)` — both JS bindings
  (`bindings/wasm/index.d.ts:306`, `bindings/node/index.d.ts:257`; node
  impl `bindings/node/src/crabs_node.cc:1889-1913`) — sealing under the
  machine's own CP-ABE authority
  (`attribute_machine.c:309` wires `abe_mk` into the state; the wasm glue
  `encrypt` uses it), with the container layout
  `u16le policy byte length + policy bytes + u32le ciphertext length +
  ciphertext` pinned by `bindings/wasm/test/smoke.js:111-130`. This is
  Recipe 6's seal; the ABE-word mapping (`'name:value'` → `name_value`,
  `src/Crypto/crypto.c:99-111`) is what makes an *epoch attribute* possible
  (below).
- *Revoke the reader*: `revokeUser(userId)` — both bindings
  (`bindings/wasm/index.d.ts:215`, `bindings/node/index.d.ts:186`; C
  `attribute_machine_revoke_user`, `src/Attribute/attribute_machine.h:175`,
  `src/Attribute/attribute_machine.c:888-907`). Admin-gated (the signer
  must hold `role:admin`), TERMINAL (`USER_REVOKED` cannot be suspended
  back or resurrected, `src/Attribute/attribute_machine.c:841-843`,
  audit R8-C-4), and it bumps the user's epoch counter (`.c:901`).
- *The epoch observable*: `UserInfo.keyVersion` — the JS-visible read of the
  machine's per-user mutation counter (`bindings/node/index.d.ts:53`,
  mapped directly in `bindings/node/src/crabs_node.cc:1147-1157`).
  **Readback asymmetry**: the crabs-node readback is real; the WASM
  binding's `getUser` returns STUBS for `keyVersion` (`0`) and `status`
  (`'active'`) — hardcoded in `bindings/wasm/bindings-core.js:693-706` —
  so the browser cannot observe a revocation through `getUser` (the gap
  block, below).
- *The fail-closed gates*: a non-ACTIVE user's op refuses with the collapsed
  `unauthorized` (mode A, `src/Crypto/crypto.c:1395-1403`, R7-14); a
  suspended or revoked *keyring* key refuses the same way
  (`src/Crypto/crypto.c:1325`); attribute grants whitelist `USER_ACTIVE` —
  a revoked target cannot be re-armed (`src/Attribute/attribute_machine.c:585-588`,
  audit R4-2); and the staleness gate refuses ops stamped with a
  superseded `key_version` (`CRABS_ERR_KEY_STALE`,
  `src/StateMachine/state_machine.c:862-873`).
- *The C-only deeper tools*: `user_key_suspend` / `user_key_activate` /
  `user_key_rotate` (`src/Attribute/attribute_machine.h:219-221`,
  exercised `test/test_key_lifecycle.cpp:96,180,269`). Suspension is
  *recoverable* and *version-bumped on activation* (R8-A-5 — ops signed
  during the suspended window are stale even after the key returns);
  rotation revokes the old key, chains the new one via
  `predecessor_key_id`, and moves the default
  (`test/test_key_lifecycle.cpp:258-287`, the C snippet executes it).

## What it guarantees / what it doesn't

Guaranteed (every line below is executed by the snippets):

- *Write-side revocation is real, immediate, and fail-closed on every
  surface.* The revoked reader's next signed op refuses `unauthorized`
  (the wasm and node snippets), and nothing lands — the handler/effect
  never runs.
- *Revocation is terminal.* Re-granting to a revoked user refuses
  (R4-2 whitelist), and no suspension/reactivation path resurrects a
  `USER_REVOKED` account (R8-C-4).
- *The epoch mechanism is machine-enforced.* Grant, suspend, activate,
  rotate, and revoke each bump `key_version`; ops stamped before the bump
  refuse `CRABS_ERR_KEY_STALE` (R7-04 — observed in the C snippet even for
  a key that was suspended and then re-activated).
- *Rotate-recall works for signing keys.* The rotated-away key authorizes
  nothing; the successor verifies and chains back to the predecessor (C
  snippet).

Not guaranteed — the honesty this recipe owes:

- *Recall of already-sealed payloads is NOT a user-record story.* A CP-ABE
  key already derived from the old attributes keeps opening the ciphertext
  it satisfied — the C snippet revokes the user first and then opens the
  old payload anyway. Real recall is *re-keying*: re-encrypt under the next
  epoch's policy and derive fresh reader keys (the epoch-attribute pattern,
  demonstrated in the C snippet; the old account stays terminal — the new
  epoch's audience is a new enrollment). The library has no revocation
  registry, no `crypto_abe_revoke`, and no re-encrypt — this is a
  recipe-level pattern, not a library feature (api-map §17, `cookbook/api-map.md:290`).
- *On the JS bindings there is no decrypt at all* (Recipe 6's gap, one
  level up), and no keyring lifecycle:

  > [!WARNING] GAP
  >
  > **Prose describes:** proving the revocation end-to-end from JS — the
  > revoked reader's key failing to open the sealed payload, and the
  > key-level tools (suspend / activate / rotate) available to the
  > application.
  >
  > **Codebase status:** exists in C and is engine-tested —
  > `crypto_abe_keygen` / `crypto_abe_decrypt`
  > (`src/Crypto/crypto.h:104-107,123-127`, pinned positive AND negative in
  > `test/test_crypto.cpp:163-301`), `user_key_suspend/activate/rotate`
  > (`src/Attribute/attribute_machine.h:219-221`,
  > `test/test_key_lifecycle.cpp`). Neither JS binding maps any of it: grep
  > both `.d.ts` files — decrypt rows do not exist, keyring-mutation rows
  > do not exist (only the `keyVersion`/`status` READS are mapped; api-map
  > §9 records the encrypt-only rows at `bindings/wasm/index.d.ts:306`,
  > `bindings/node/index.d.ts:257`; api-map §2 records the C-only
  > lifecycle).
  >
  > **Divergence:** the design (v1.3 §9 key lifecycle) treats suspension
  > and rotation as operational tools; JS consumers can observe their
  > *effects* (a bumped `keyVersion` on crabs-node, refused ops on both
  > bindings) but cannot *perform* them, and cannot open the sealed
  > payload from JS at all — the demonstrable halves on this page stop at
  > the refusal gate.
  >
  > **Tracking:** an internal implementation plan (not published on this
  > site).
  >
  > **Agent action:** code block omitted for the missing half — do not
  > invent `decrypt()`, `suspendKey()`, or `rotateKey()` onto either
  > binding; the C section is where this half is real.

- *The wasm readback cannot show the revocation at all:*

  > [!WARNING] GAP
  >
  > **Prose describes:** a browser (crabs-wasm) observing that a reader is
  > revoked — reading `getUser('reader').status` / `.keyVersion` after
  > `revokeUser` and rendering the account state.
  >
  > **Codebase status:** the wasm `getUser` implementation returns
  > hardcoded stubs for three of its fields — `publicKeyHex: ''`,
  > `keyVersion: 0`, `status: 'active'`
  > (`bindings/wasm/bindings-core.js:693-706`) — while the node binding
  > maps the same fields directly from the machine
  > (`bindings/node/src/crabs_node.cc:1139-1157`; the same fields are
  > declared at `bindings/wasm/index.d.ts:150-160`). The snippets pin the
  > stubbed readback executing `revokeUser` and then observing
  > `status: 'active'` / `keyVersion: 0`.
  >
  > **Divergence:** the api-map §2 documents `UserInfo` as STABLE on wasm
  > (`cookbook/api-map.md:50`, exercised only for the attributes list at
  > `bindings/wasm/test/smoke.js:41`); the `keyVersion`/`status` fields
  > are display stubs on wasm — a wasm consumer's only revocation
  > observable is the *refusal of the revoked user's next op*, not the
  > account readback. The node binding is the surface where the honest
  > readback exists.
  >
  > **Tracking:** none found — the stub is undocumented in the bindings'
  > own READMEs; this page records it.
  >
  > **Agent action:** code block omitted for the fix; do not present
  > wasm `getUser().keyVersion` / `.status` as live values (they are
  > constants of the wasm glue today).

For that reason the frontmatter status is PARTIAL: the recipe *delivers*
seal + revocation-refusal on wasm and node (with the node-side honest
readback), and the full story — keyring lifecycle, decryption, and the
epoch re-key pattern — on C.

## Variations

- *The epoch-attribute pattern (recipe-level, not a symbol)*: grant readers
  an ordinary attribute pair like `epoch:1`, include the epoch word in the
  seal policy (`'epoch_1 and member'` — the token map,
  `src/Crypto/crypto.c:99-111`), and treat every mutation of the audience
  as a re-seal under the next epoch. The C snippet runs the whole cycle:
  epoch-one key opens epoch-one data; epoch-two data refuses the epoch-one
  key and opens for a fresh derivation. What the library gives you is the
  attribute system + ABE; the *convention* of what an epoch means (who
  bumps it, when re-seal happens) is yours (api-map `cookbook/api-map.md:290`
  marks the same boundary).
- *Demote, not delete*: `attribute_machine_revoke_role` strips ONE role and
  works on suspended/revoked targets by design (R4-4,
  `src/Attribute/attribute_machine.h:147`,
  `src/Attribute/attribute_machine.c:799-847`) — but no JS binding exposes
  it; the JS-reachable tools are the user-level `revokeUser` (terminal) and
  nothing finer. A JS consumer who wants demotion cannot get it today; this
  is the wasm/node surface of the gap above.
- *Suspension vs revocation*: user-level suspension —
  `attribute_machine_suspend_user` (`src/Attribute/attribute_machine.c:821-857`)
  — is the recoverable tool (the key-compromise recovery flow uses its
  internal form, `src/Crypto/crypto.c:2035`) and it is ALSO C-only; the
  recoverable/terminal pair (`KEY_SUSPENDED`→activate with a version bump,
  R8-A-5) is the C surface's honest split.
- *Observability differences after the same revoke*: on crabs-node the
  attribute-kind change event (`kind: 'attribute'`, `type: 'revoke_user'`)
  streams the revocation, `getUser` shows the terminal status, and even the
  bump is observable; on crabs-wasm only the refusal is observable (the
  gaps above); in C you own the record directly.

## Recipe

### crabs-wasm (browser / Node / edge)

Seed the reader (register + grant), seal the payload, revoke, and watch the
only two wasm observables: the revoked reader's op refusing fail-closed, and
(getClient-side pinned) the `getUser` readback stubs that stay fake.

```snippet:wasm/16-revocable-data.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create              bindings/wasm/index.d.ts:372
  KeyPair.generate         bindings/wasm/index.d.ts:21
  registerUser             bindings/wasm/index.d.ts:213
  grantRole                bindings/wasm/index.d.ts:214
  Node.revokeUser          bindings/wasm/index.d.ts:215 (C: attribute_machine_revoke_user, src/Attribute/attribute_machine.c:888-907)
  (readback stub)          bindings/wasm/bindings-core.js:693-706
  addCounter               bindings/wasm/index.d.ts:223
  getCounter               bindings/wasm/index.d.ts:254
  setPolicy                bindings/wasm/index.d.ts:295
  registerHandlerJs        bindings/wasm/index.d.ts:303
  HandlerState.incrementCounter bindings/wasm/index.d.ts:103
  Operation.create         bindings/wasm/index.d.ts:52
  Node.sign / Node.execute bindings/wasm/index.d.ts:297 / :296
  Node.encrypt             bindings/wasm/index.d.ts:306
  Node.destroy             bindings/wasm/index.d.ts:368
  (fail-closed user gate)  src/Crypto/crypto.c:1395-1403 (R7-14 collapse)
  (re-grant whitelist)     src/Attribute/attribute_machine.c:585-588 (R4-2)
maturity: revokeUser semantics STABLE (C-tested via the R4-2/R7-14 gates; the
  binding suite only type-checks the method — bindings/node/test/test.js:253 —
  this snippet is the first executable demonstration of the semantics on wasm)
test_ref: bindings/wasm/test/smoke.js:111-130 (encrypt container layout)
-->

The decrypt half is C-only (recipe 6's gap, above) and the keyring
lifecycle is C-only — see the C section for where the story completes.

### crabs-node (native Node.js)

The same flow with the readback the browser binding stubs away: the machine
maps `keyVersion` and `status` directly, so the revocation is observable as
a `1 -> 2 -> 3` bump plus the terminal `revoked` status, and it streams as
an `attribute`-kind change event.

```snippet:node/16-revocable-data.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  NodeStatic.new           bindings/node/index.d.ts:312
  KeyPair.generate         bindings/node/index.d.ts:14
  registerUser             bindings/node/index.d.ts:182
  grantRole                bindings/node/index.d.ts:183
  Node.revokeUser          bindings/node/index.d.ts:186
  getUser                  bindings/node/index.d.ts:189 (crabs_node.cc:1139-1157)
  UserInfo.keyVersion      bindings/node/index.d.ts:53 (crabs_node.cc:1147)
  defineItem               bindings/node/index.d.ts:205
  Node.sign / Node.execute bindings/node/index.d.ts:250 / :251
  Node.on                  bindings/node/index.d.ts:188
  Node.encrypt             bindings/node/index.d.ts:257 (crabs_node.cc:1889-1913)
  Operation.new            bindings/node/index.d.ts:47
  Operation.addResource    bindings/node/index.d.ts:26
  (change event shape)     bindings/node/src/crabs_node.cc:950-962
  (fail-closed user gate)  src/Crypto/crypto.c:1395-1403 (R7-14 collapse)
  (re-grant whitelist)     src/Attribute/attribute_machine.c:585-588 (R4-2)
maturity: all STABLE; the revoke readback (keyVersion/status) is mapped
  directly from the machine — no stub
test_ref: bindings/node/test/test.js:143-147 (op-event result field) + :253
-->

### C (native)

The full revocation story on the engine surface: the epoch counter bumping
on every mutation, the keyring lifecycle (suspend → refused; activate →
recovered but stale-stamps killed; rotate → old key revoked and chained),
the user-level revocation refusing ops and re-grants, the honest boundary
(an already-derived ABE key keeps opening the old ciphertext), and the
epoch re-encryption pattern that actually recalls access.

```snippet:c/16-revocable-data.c
```

<!-- PROVENANCE
target: native-c
verified: executed
symbols:
  attribute_machine_create       src/Attribute/attribute_machine.h:118 (abe_mk wiring .c:309)
  attribute_machine_register_user src/Attribute/attribute_machine.h:130
  attribute_machine_grant_role   src/Attribute/attribute_machine.h:133
  (find_user)                    src/Attribute/attribute_machine.h:187
  (key_version bump sites)       .c:495 (register), :597/:617 (grant), :878 (suspend_user), :901 (revoke_user), :1231 (key suspend), :1265 (key activate, R8-A-5), :1161 (key revoke); user_key_register does NOT bump (attribute_machine.c:1091-1151)
  user_key_register              src/Attribute/attribute_machine.h:210
  user_key_suspend               src/Attribute/attribute_machine.h:219
  user_key_activate              src/Attribute/attribute_machine.h:220
  user_key_rotate                src/Attribute/attribute_machine.h:221
  user_key_find / find_active    src/Attribute/attribute_machine.h:208-209
  (key status gate)              src/Crypto/crypto.c:1325
  (user status gate, R7-14)      src/Crypto/crypto.c:1395-1403
  (staleness gate, R7-04)        src/StateMachine/state_machine.c:862-873 (CRABS_ERR_KEY_STALE, src/CRABS/crabs.h:78)
  state_add_policy               src/CRABS/data_model.h:720
  state_machine_register_handler src/StateMachine/state_machine.h:237
  (policy grammar)               src/StateMachine/state_machine.c:768-783 + preprocess src/Condition/condition.c:1507-1600
  crypto_abe_encrypt             src/Crypto/crypto.h:110-114
  crypto_abe_keygen              src/Crypto/crypto.h:104-107 (token map .c:99-111)
  crypto_abe_decrypt             src/Crypto/crypto.h:123-127 (no status/registry check, .c:1041-1079)
  crypto_ecdsa_generate          src/Crypto/crypto.h:21
  CRABS_SUCCESS / ERR_UNAUTHORIZED / ERR_USER_SUSPENDED / ERR_KEY_STALE src/CRABS/crabs.h:65,77,80,78
maturity: all exercise the same C-tested paths the header comments describe
test_ref: test/test_key_lifecycle.cpp:88-125 (suspend), :171-251 (activate + R8-A-5 note), :258-287 (rotate), :586-619 (state-machine suspend/activate ops) + test/test_crypto.cpp:163-301 (ABE round trip) + test/test_attribute_machine.cpp:561-584
-->

## Notes

- *Why the wasm readback pin matters*: the recipe treats the stub as a
  finding, not a footnote — a revocation UI built on the wasm binding today
  would show every revoked member as `active / keyVersion 0` forever. The
  binding suite only type-checks `revokeUser`
  (`bindings/node/test/test.js:253`) and never reads back, which is why the
  snippets are the first executable pin of the semantics on either binding.
- *What the epoch counter actually counts*: record mutations, not keys —
  `user_key_register` does not bump it (`src/Attribute/attribute_machine.c:1091-1151`),
  while every attribute mutation and every key-status transition does
  (list in the C provenance). The bump-on-activation is deliberate
  (R8-A-5): signatures made while a key was suspended must not outlive the
  reactivation.
- *A grammar pitfall pinned on the way*: the CRABS policy grammar is prefix
  — `AND` takes two clauses. The single-clause `'AND role:member'` is a
  legal-looking string that mis-parses (an empty right operand evaluates
  false, `src/Crypto/crypto.c:676-696`) and silently refuses every member —
  the C snippet pins it. Single-clause policies are the bare token; this
  recipe uses `'role:member'` on all three surfaces.
- *The re-encryption recall is only as sound as the re-seal*: the epoch
  pattern protects future READS of newly-sealed data; data sealed under
  epoch N stays openable to every epoch-N-derived key (bearer-instrument
  property, demonstrated). If a reader's key was already extracted from an
  envelope, the epoch bump does not help retroactively any more than
  revocation does — re-encrypt early.
- *The api-map correction*: §2's `UserInfo` row was marked STABLE on both
  bindings; the wasm readback's stub fields now have their own ledger
  caveat (api-map §2) — matching what this page demonstrates.