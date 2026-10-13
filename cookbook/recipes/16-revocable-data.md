---
number: 16
slug: revocable-data
title: Data that must be revocable
section: Ground truth
status: COMPLETE
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
user-record lookup happens at decrypt. Every snippet below (C, wasm, node)
executes the refutation — a reader whose user record is REVOKED still opens
the payload they were already able to derive a key for, because
`crypto_abe_keygen` and `crypto_abe_decrypt` consult no user status and no
revocation registry (`src/Crypto/crypto.c:1075-1105`).

The other naive direction fails at the other end: skipping revocation
entirely, because "the data is already sealed" — which ignores the *write*
half. A revoked reader who keeps signing ops is refused, and CRABS' epoch
mechanism makes the refusal structural rather than a list check: every user
carries a monotonically increasing `key_version`, bumped by every record
mutation, and every op the v1.3 signing path stamps that version — an op
carrying a stale stamp refuses with a typed staleness error (R7-04,
`src/StateMachine/state_machine.c:873-884`). Revocation without that stamp
would rot into a race: a op signed *just before* the revoke would replay
fine afterward.

## The shape

- *The seal*: `node.encrypt(payload, policy)` — both JS bindings
  (`bindings/wasm/index.d.ts:686`, `bindings/node/index.d.ts:508`; node
  impl `bindings/node/src/crabs_node.cc:3036-3060`) — sealing under the
  machine's own CP-ABE authority
  (`attribute_machine.c:309` wires `abe_mk` into the state; the wasm glue
  seals with it via `src/Util/wasm_helpers.c:1622-1628`), with the container layout
  `u16le policy byte length + policy bytes + u32le ciphertext length +
  ciphertext` pinned by `bindings/wasm/test/smoke.js:111-130`. This is
  Recipe 6's seal; the ABE-word mapping (`'name:value'` → `name_value`,
  `src/Crypto/crypto.c:98-111`) is what makes an *epoch attribute* possible
  (below).
- *Revoke the reader*: `revokeUser(userId)` — both bindings
  (`bindings/wasm/index.d.ts:482`, `bindings/node/index.d.ts:308`; C
  `attribute_machine_revoke_user`, `src/Attribute/attribute_machine.h:175`,
  `src/Attribute/attribute_machine.c:888-907`). Admin-gated (the signer
  must hold `role:admin`), TERMINAL (`USER_REVOKED` cannot be suspended
  back or resurrected — the R8-C-4 refusal,
  `src/Attribute/attribute_machine.c:841-843`), and it bumps the user's
  epoch counter (`.c:901`).
- *The epoch observable*: `UserInfo.keyVersion` — the JS-visible read of the
  machine's per-user mutation counter on BOTH bindings (node
  `bindings/node/index.d.ts:145`, mapped directly in
  `bindings/node/src/crabs_node.cc:1567-1601`; wasm
  `bindings/wasm/index.d.ts:277-288`, mapped in
  `bindings/wasm/bindings-core.js:895-952` — the former hardcoded stubs
  were replaced by real readbacks in the binding fix that
  `bindings/wasm/test/getuser-readback.js` pins).
- *The fail-closed gates*: a non-ACTIVE user's op refuses with the collapsed
  `unauthorized` (mode A, `src/Crypto/crypto.c:1395-1403`, R7-14); a
  suspended or revoked *keyring* key refuses the same way
  (`src/Crypto/crypto.c:1325`); attribute grants whitelist `USER_ACTIVE` —
  a revoked target cannot be re-armed (`src/Attribute/attribute_machine.c:585-588`,
  audit R4-2); and the staleness gate refuses ops stamped with a
  superseded `key_version` (`CRABS_ERR_KEY_STALE`,
  `src/StateMachine/state_machine.c:873-884`).
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
  it satisfied — the C and JS snippets all revoke the user first (the JS
  snippets derive the key AFTER the revocation) and then open the old
  payload anyway. Real recall is *re-keying*: re-encrypt under the next
  epoch's policy and derive fresh reader keys (the epoch-attribute pattern,
  demonstrated in every snippet; the old account stays terminal — the new
  epoch's audience is a new enrollment). The library has no revocation
  registry, no `crypto_abe_revoke`, and no re-encrypt — this is a
  recipe-level pattern, not a library feature (api-map §17, `cookbook/api-map.md:290`).
- *The decrypt half is JS-bound now; the keyring lifecycle is the C
  surface:*

  > [!NOTE] RESIDUAL SCOPE
  >
  > **What is real from JS (both bindings):** `abeKeygen(attrs)` derives a
  > reader key from the machine's own master authority and
  > `abeDecrypt(key, container)` opens the container `encrypt` returned —
  > `bindings/wasm/index.d.ts:698,708`, `bindings/node/index.d.ts:520,529`
  > (api-map §9; pinned by `bindings/wasm/test/abe-decrypt.js` and
  > `bindings/node/test/abe.js`, and executed by both snippets below —
  > including the bearer-instrument demonstration and the epoch-two
  > re-seal).
  >
  > **What stays C-only in v1:** the keyring mutation tools —
  > `user_key_suspend` / `user_key_activate` / `user_key_rotate`
  > (`src/Attribute/attribute_machine.h:219-221`, exercised
  > `test/test_key_lifecycle.cpp`). JS consumers observe their *effects*
  > (a bumped `keyVersion` on both bindings, refused ops) but cannot
  > *perform* them; the C snippet is where that lifecycle is executable.
  > No portable reader-key bytes ship: `AbeKey` is a destroyable wrapper
  > around the machine-derived key — the C-side
  > `crypto_abe_user_key_serialize`/`deserialize` pair remains outside the
  > JS surface by design (the machine, not the file system, holds the key
  > material).

For that reason the JS halves of this recipe are complete as demonstrated
by the snippets: seal + revocation-refusal + readback + keygen/decrypt
(including the honest bearer-instrument boundary and the epoch re-key
pattern) run on both bindings, and the keyring lifecycle is the C
section's executable half.

## Variations

- *The epoch-attribute pattern (recipe-level, not a symbol)*: grant readers
  an ordinary attribute pair like `epoch:1`, include the epoch word in the
  seal policy (`'epoch_1 and member'` — the token map,
  `src/Crypto/crypto.c:100-111`), and treat every mutation of the audience
  as a re-seal under the next epoch. The C snippet runs the whole cycle:
  epoch-one key opens epoch-one data; epoch-two data refuses the epoch-one
  key and opens for a fresh derivation. What the library gives you is the
  attribute system + ABE; the *convention* of what an epoch means (who
  bumps it, when re-seal happens) is yours (api-map `cookbook/api-map.md:290`
  marks the same boundary).
- *Demote, not delete*: `attribute_machine_revoke_role` strips ONE role and
  works on suspended/revoked targets by design (R4-4,
  `src/Attribute/attribute_machine.h:147`, decl; the whitelist-bypass
  comment and body at `src/Attribute/attribute_machine.c:772-820`) — but no
  JS binding exposes
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
three wasm observables of the revocation: the revoked reader's op refusing
fail-closed, the REAL `getUser` readback flipping to `revoked` with the
bumped `keyVersion`, and the sealed payload staying openable to the
policy-derived key even after the revocation (the bearer-instrument
boundary — the reader for its recall is the epoch re-seal, which the
snippet executes too).

```snippet:wasm/16-revocable-data.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create              bindings/wasm/index.d.ts:774
  KeyPair.generate         bindings/wasm/index.d.ts:43-47
  registerUser             bindings/wasm/index.d.ts:480
  grantRole                bindings/wasm/index.d.ts:481
  Node.revokeUser          bindings/wasm/index.d.ts:482 (C: attribute_machine_revoke_user, src/Attribute/attribute_machine.c:888-907)
  getUser (real readback)  bindings/wasm/index.d.ts:488 (mapper: bindings/wasm/bindings-core.js:895-952)
  addCounter               bindings/wasm/index.d.ts:490
  getCounter               bindings/wasm/index.d.ts:554
  setPolicy                bindings/wasm/index.d.ts:638
  registerHandlerJs        bindings/wasm/index.d.ts:683
  HandlerState.incrementCounter bindings/wasm/index.d.ts:195
  Operation.create         bindings/wasm/index.d.ts:122
  Node.sign / Node.execute bindings/wasm/index.d.ts:657 / :656
  Node.encrypt             bindings/wasm/index.d.ts:686
  Node.abeKeygen           bindings/wasm/index.d.ts:698
  Node.abeDecrypt          bindings/wasm/index.d.ts:708
  AbeKey.destroy           bindings/wasm/index.d.ts:57-59
  Node.destroy             bindings/wasm/index.d.ts:770
  (fail-closed user gate)  src/Crypto/crypto.c:1395-1403 (R7-14 collapse)
  (re-grant whitelist)     src/Attribute/attribute_machine.c:585-588 (R4-2)
  (keygen consults no user record) src/Crypto/crypto.c:809-855
  (decrypt consults no user record) src/Crypto/crypto.c (crypto_abe_decrypt)
maturity: revokeUser + readback + abeKeygen/abeDecrypt semantics STABLE
  (C-tested via the R4-2/R7-14 gates; pinned on this binding by
  test/abe-decrypt.js + test/getuser-readback.js)
test_ref: bindings/wasm/test/abe-decrypt.js (keygen/decrypt round trip +
  refusals + token map) + bindings/wasm/test/getuser-readback.js + bindings/wasm/test/smoke.js:111-130 (encrypt container layout)
-->

The JS-residual is exactly the keyring lifecycle (suspend / activate /
rotate — C-only; the RESIDUAL SCOPE note above). Everything else — seal,
refusals, readback, decrypt — is executable from this binding.

### crabs-node (native Node.js)

The same flow — this binding maps `keyVersion` and `status` directly from
the machine, so the revocation is observable as a `1 -> 2 -> 3` bump plus
the terminal `revoked` status, and it streams as an `attribute`-kind change
event. (The wasm binding maps the same readback too — the recipe-level
parity the RESIDUAL SCOPE note above records; what remains wasm/node-odd
is only in the C-only keyring lifecycle, not the readback.)

```snippet:node/16-revocable-data.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  NodeStatic.new           bindings/node/index.d.ts:641-643
  KeyPair.generate         bindings/node/index.d.ts:58
  registerUser             bindings/node/index.d.ts:304
  grantRole                bindings/node/index.d.ts:305
  Node.revokeUser          bindings/node/index.d.ts:308
  getUser                  bindings/node/index.d.ts:311 (crabs_node.cc:1567-1601)
  UserInfo.keyVersion      bindings/node/index.d.ts:145 (crabs_node.cc)
  defineItem               bindings/node/index.d.ts:363
  Node.sign / Node.execute bindings/node/index.d.ts:463 / :464
  Node.on                  bindings/node/index.d.ts:310
  Node.encrypt             bindings/node/index.d.ts:508 (crabs_node.cc:3036-3060)
  Node.abeKeygen           bindings/node/index.d.ts:520 (crabs_node.cc:3078-3104)
  Node.abeDecrypt          bindings/node/index.d.ts:529 (crabs_node.cc:3106-3119)
  AbeKey.destroy           bindings/node/index.d.ts:41-43 (crabs_node.cc:430-474)
  Operation.new            bindings/node/index.d.ts:139
  Operation.addResource    bindings/node/index.d.ts:70
  (change event shape)     bindings/node/src/crabs_node.cc (EmitChange)
  (fail-closed user gate)  src/Crypto/crypto.c:1395-1403 (R7-14 collapse)
  (re-grant whitelist)     src/Attribute/attribute_machine.c:585-588 (R4-2)
maturity: all STABLE; the revoke readback (keyVersion/status) is mapped
  directly from the machine — no stub; abeKeygen/abeDecrypt pinned by
  bindings/node/test/abe.js
test_ref: bindings/node/test/abe.js (keygen/decrypt round trip + refusals)
  + bindings/node/test/test.js:143-147 (op-event result field) + :253
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
  (staleness gate, R7-04)        src/StateMachine/state_machine.c:873-884 (CRABS_ERR_KEY_STALE, src/CRABS/crabs.h:78)
  state_add_policy               src/CRABS/data_model.h:720
  state_machine_register_handler src/StateMachine/state_machine.h:237
  (policy grammar)               src/StateMachine/state_machine.c:768-783 + preprocess src/Condition/condition.c:1501-1598
  crypto_abe_encrypt             src/Crypto/crypto.h:110-114
  crypto_abe_keygen              src/Crypto/crypto.h:104-107 (token map .c:99-111)
  crypto_abe_decrypt             src/Crypto/crypto.h:134-137 (no status/registry check, .c:1075-1105)
  crypto_ecdsa_generate          src/Crypto/crypto.h:21
  CRABS_SUCCESS / ERR_UNAUTHORIZED / ERR_USER_SUSPENDED / ERR_KEY_STALE src/CRABS/crabs.h:65,77,80,78
maturity: all exercise the same C-tested paths the header comments describe
test_ref: test/test_key_lifecycle.cpp:88-125 (suspend), :171-251 (activate + R8-A-5 note), :258-287 (rotate), :586-619 (state-machine suspend/activate ops) + test/test_crypto.cpp:163-301 (ABE round trip) + test/test_attribute_machine.cpp:561-584
-->

## Notes

- *Why the readback pin matters*: the user records of every surface are
  machine-mapped now — a revocation UI reading `getUser(...).status` /
  `.keyVersion` observes `revoked` / the bump on BOTH bindings
  (`bindings/wasm/test/getuser-readback.js` pins the wasm readback;
  `bindings/node/test/test.js:253` type-checks the node surface).
- *What the epoch counter actually counts*: record mutations, not keys —
  `user_key_register` does not bump it (`src/Attribute/attribute_machine.c:1091-1151`),
  while every attribute mutation and every key-status transition does
  (list in the C provenance). The bump-on-activation is deliberate
  (R8-A-5): signatures made while a key was suspended must not outlive the
  reactivation.
- *The grammar pin, after the single-clause fix*: the CRABS policy evaluator
  accepts both prefix (`AND <l> <r>`) and infix (`<l> AND <r>`) forms. A
  one-clause prefix policy `'AND role:member'` — a legal-looking string that
  used to mis-parse (an empty right operand evaluated false, silently
  refusing every member) — now collapses to the bare token
  (`src/Crypto/crypto.c:680-699`): any leading single-clause `AND` is the
  plain token, and both forms are pinned as equivalent in the C snippet.
  The fail-closed rule still stands for every OTHER dangling shape — a bare
  `'AND'`, a compound dangling operator (`'AND role:member AND'`), a
  parenthesized sub-expression — all refuse, also pinned. Note the
  encrypt/decrypt surface is stricter: OpenABE's policy parser is infix-only
  (this fork's parser is case-insensitive), so a prefix `'AND member'` fails
  the *encrypt* call itself (noisy, fail-closed) — encode encrypt policies
  infix (`'epoch_1 and member'`), as this recipe's seal does.
- *The re-encryption recall is only as sound as the re-seal*: the epoch
  pattern protects future READS of newly-sealed data; data sealed under
  epoch N stays openable to every epoch-N-derived key (bearer-instrument
  property, demonstrated). If a reader's key was already extracted from an
  envelope, the epoch bump does not help retroactively any more than
  revocation does — re-encrypt early.
- *The api-map rows*: §2's `UserInfo` row reflects the readback being a
  real machine-mapped surface on BOTH bindings, and §9 records the full
  ABE round trip (`encrypt` + `abeKeygen`/`abeDecrypt` + `AbeKey`) with
  the machine-held-master-key trust shape — matching what this page
  demonstrates.