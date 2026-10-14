---
number: 15
slug: revocable-data
title: Data that must be revocable
section: Ground truth
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
teaches: revocation, key versions and epoch re-encryption
---
## The problem

A club's machine seals its minutes under a member policy: 80 members today,
and the seal only opens for someone the policy admits. At the end of the
month, one member — dan — leaves, and three things must happen, and they
fail differently:

- *Forward sealing*: the minutes sealed *after* he leaves must refuse him
  — future ciphertexts open only for currently-authorized readers;
- *Fail-closed writes*: dan's ops — votes, comments, anything he signs —
  must refuse on every surface the moment he is revoked, even if his key
  is present in a browser tab somewhere;
- *Recall*: whatever dan may already hold that opens the old minutes stops
  opening — and nobody can un-share a key he copied in January.

The first two are record problems. The third is not, and the whole recipe
turns on seeing that difference.

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

## The idea

Two kinds of authorization act at different moments, and revocation means
opposite things for each:

- An authorization **record** is consulted at the moment of the action. The
  user shows up (or their op does), the machine looks up who they are
  *now*, and the action is allowed or refused on the spot. Revoke the
  record, the action stops — this works completely, and it is the right
  mechanism for anything the machine executes on the user's behalf.
- An issued **key** is a bearer instrument. Whoever holds it has the power,
  with no lookup at use time — like a copied door key: revoking a club
  membership does not call the copy home. A decryption key derived from
  attributes is exactly this: once derived and carried away, it opens what
  it satisfied, and no amount of *record* revocation pulls it back.

The remedy for issued instruments is not better bookkeeping — it is
retirement: change the lock and reissue. In cryptographic terms,
*epoch re-encryption*: seal the content under a policy carrying the next
epoch's marker and derive fresh reader keys; the old instruments don't
stop working — they stop *mattering*, because the data no longer answers
to them. The "epoch" is the lifecycle counter of the audience: every
mutation of who should read becomes a new epoch and a re-seal of forward-
going data. (What it cannot do is reach backwards into already-distributed
envelopes — re-encrypt early.)

The write half gets the structural version of the same idea: each user
carries a monotonically bumping version counter, and every op they sign
stamps it. A stale stamp — one signed before a suspension, rotation, or
revocation — is refused on its face, so revocation can't rot into a
"replay what I signed yesterday" race.

## How CRABS encodes it

- *The seal*: `node.encrypt(payload, policy)` — both JS bindings — sealing
  under the machine's own CP-ABE authority, with the container layout
  `u16le policy byte length + policy bytes + u32le ciphertext length +
  ciphertext`. This is Recipe 6's seal; the ABE-word mapping
  (`'name:value'` → `name_value`) is what makes an *epoch attribute*
  possible (below).
- *Revoke the reader*: `revokeUser(userId)` — both bindings. Admin-gated
  (the signer must hold `role:admin`), TERMINAL (`USER_REVOKED` cannot be
  suspended back or resurrected), and it bumps the user's epoch counter.
- *The epoch observable*: `UserInfo.keyVersion` — the JS-visible read of
  the machine's per-user mutation counter on BOTH bindings (real readbacks;
  a revocation UI reading `getUser(...).status` / `.keyVersion` observes
  `revoked` / the bump on both surfaces).
- *The fail-closed gates*: a non-ACTIVE user's op refuses with the
  collapsed `unauthorized`; a suspended or revoked *keyring* key refuses
  the same way; attribute grants whitelist `USER_ACTIVE` — a revoked
  target cannot be re-armed; and the staleness gate refuses ops stamped
  with a superseded `key_version`.
- *The reader keys*: `abeKeygen(attrs)` derives a reader key from the
  machine's own master authority and `abeDecrypt(key, container)` opens
  what `encrypt` returned — the full seal/open round trip runs from JS on
  both bindings, refusals typed (`unauthorized` on wrong attributes, GCM
  fail-closed on tamper).
- *The keyring mutation tools* (parity-fill P2 — JS-reachable on BOTH
  bindings, user-id-scoped over the user_t-scoped C primitives
  `user_key_suspend` / `user_key_activate` / `user_key_rotate`,
  `src/Attribute/attribute_machine.h:219-221`): `suspendKey(userId, keyId)`
  (recoverable; bumps `keyVersion`), `activateKey(userId, keyId)`
  (version-bumped — stamps made during the suspended window are gone;
  does NOT restore a vacated default), and
  `rotateKey(userId, oldId, newId, { scheme?, publicKeyHex, label? })`
  (explicit material, nothing auto-generated — the old key revokes and the
  new one chains via `predecessor_key_id`). Readback: `listKeys(userId)` +
  `getDefaultKey(userId)`. Pinned: `bindings/wasm/test/keyring.js` + the
  keyring block in bindings/node `test/test.js`.

## Try it

### crabs-wasm (browser / Node / edge)

Seed the reader (register + grant), seal the payload, revoke, and watch the
three wasm observables of the revocation: the revoked reader's op refusing
fail-closed, the REAL `getUser` readback flipping to `revoked` with the
bumped `keyVersion`, and the sealed payload staying openable to the
policy-derived key even after the revocation (the bearer-instrument
boundary — the reader for its recall is the epoch re-seal, which the
snippet executes too).

```snippet:wasm/15-revocable-data.js
```

The JS-residual is nearly gone: the keyring mutation tools
(`suspendKey` / `activateKey` / `rotateKey` — parity-fill P2, §2) are
executable from wasm too; what stays off the method surface is only the
`user_key_revoke` / `user_key_set_default` method forms (the wire ops
`__revoke_key__` / `__set_default_key__` cover them power-side) and the
key_id-declaring sign path. Everything else — seal, refusals, readback,
decrypt — is executable from this binding.

### crabs-node (native Node.js)

The same flow — this binding maps `keyVersion` and `status` directly from
the machine, so the revocation is observable as a `1 -> 2 -> 3` bump plus
the terminal `revoked` status, and it streams as an `attribute`-kind change
event. (The wasm binding maps the same readback too — recipe-level parity;
the keyring mutation methods land on BOTH bindings (parity-fill P2), so
nothing lifecycle-shaped is wasm/node-odd anymore.)

```snippet:node/15-revocable-data.js
```

### C (native)

The full revocation story on the engine surface: the epoch counter bumping
on every mutation, the keyring lifecycle (suspend → refused; activate →
recovered but stale-stamps killed; rotate → old key revoked and chained),
the user-level revocation refusing ops and re-grants, the honest boundary
(an already-derived ABE key keeps opening the old ciphertext), and the
epoch re-encryption pattern that actually recalls access.

```snippet:c/15-revocable-data.c
```

## What it guarantees / what it doesn't

Guaranteed (every line below is executed by the snippets):

- *Write-side revocation is real, immediate, and fail-closed on every
  surface.* The revoked reader's next signed op refuses `unauthorized`,
  and nothing lands — the handler/effect never runs.
- *Revocation is terminal.* Re-granting to a revoked user refuses, and no
  suspension/reactivation path resurrects a `USER_REVOKED` account.
- *The epoch mechanism is machine-enforced.* Grant, suspend, activate,
  rotate, and revoke each bump `key_version`; ops stamped before the bump
  refuse `CRABS_ERR_KEY_STALE` (observed in the C snippet even for a key
  that was suspended and then re-activated).
- *Rotate-recall works for signing keys.* The rotated-away key authorizes
  nothing; the successor verifies and chains back to the predecessor (C
  snippet).

Not guaranteed — the bearer-instrument boundary:

- *Recall of already-sealed payloads is NOT a user-record story.* A CP-ABE
  key already derived from the old attributes keeps opening the ciphertext
  it satisfied — the snippets all revoke the user first (the JS snippets
  derive the key AFTER the revocation) and then open the old payload
  anyway. Real recall is *re-keying*: re-encrypt under the next epoch's
  policy and derive fresh reader keys (the epoch-attribute pattern,
  demonstrated in every snippet; the old account stays terminal — the new
  epoch's audience is a new enrollment). The library has no revocation
  registry, no `crypto_abe_revoke`, and no re-encrypt — this is a
  recipe-level pattern, not a library feature (api-map §17, the R15 row).

  > [!NOTE] RESIDUAL SCOPE
  >
  > **What is real from JS (both bindings):** `abeKeygen(attrs)` derives a
  > reader key from the machine's own master authority and
  > `abeDecrypt(key, container)` opens the container `encrypt` returned
  > (api-map §9; executed by both snippets below — including the
  > bearer-instrument demonstration and the epoch-two re-seal).
  >
  > **What stays C-only in v1:** the keyring mutation tools'
  > sibling forms — `user_key_revoke` / `user_key_set_default` (the wire ops
  > `__revoke_key__` / `__set_default_key__` cover them power-side) and the
  > key_id-declaring sign path. The suspend/activate/rotate lifecycle is
  > JS-reachable now (parity-fill P2 — `suspendKey` / `activateKey` /
  > `rotateKey`, api-map §2; key_stale replays pin in P3's suspension
  > surface). No portable reader-key bytes ship: `AbeKey` is a
  > destroyable wrapper around the machine-derived key — the C-side
  > serialize/deserialize pair remains outside the JS surface by design
  > (the machine, not the file system, holds the key material).

- *Fine demotion is JS-reachable now (parity-fill P3).* `revokeRole(userId,
  role, signerId?)` on BOTH bindings drives `attribute_machine_revoke_role`
  — strips ONE role, works on suspended/revoked targets by design (R4-4),
  is admin-gated like its siblings, and the fail-closed flip pins: a policy
  gate that consulted the revoked role refuses at the NEXT execution
  (`bindings/wasm/test/roles-admin.js` + the admin block of node
  `test/test.js`). The user-level `revokeUser` stays the terminal tool;
  `suspendUser` / `activateUser` are the recoverable middle (suspension and
  reactivation each bump `keyVersion` — R8-A-5 — so a pre-suspension stamp
  replays into a genuine `key_stale` after the user returns, pinned from
  JS in the same tests).

## Variations

- *The epoch-attribute pattern (recipe-level, not a symbol)*: when a
  regulated audience churns, grant readers an ordinary attribute pair like
  `epoch:1`, include the epoch word in the seal policy
  (`'epoch_1 and member'`), and treat every audience mutation as a re-seal
  under the next epoch. The C snippet runs the whole cycle: epoch-one key
  opens epoch-one data; epoch-two data refuses the epoch-one key and opens
  for a fresh derivation. What the library gives you is the attribute
  system + ABE; the *convention* of what an epoch means (who bumps it,
  when re-seal happens) is yours.
- *Suspension vs revocation*: for the recoverable middle case
  (key-compromise recovery), user-level suspension is the JS-reachable
  tool now (parity-fill P3 — `suspendUser` / `activateUser`, both
  bindings) — KEY_SUSPENDED → activate with a version bump — so
  signatures made during the suspended window die even though the user
  returns. The recoverable/terminal pair is the surface's honest split.
- *Observability of the revocation*: to instrument a revocation UI, the
  same three signals exist on both JS bindings — the attribute-kind change
  event (`kind: 'attribute'`, `type: 'revoke_user'`) the engine fires
  straight out of the revoke and both wrappers forward, the `getUser`
  readback flipping to `revoked`, and the bumped `keyVersion`. The node
  snippet demonstrates the event end-to-end; the wasm snippet exercises
  the refusal + readback (same engine hook, same event in flight). In C
  you own the record directly.
- *The grammar pin, after the single-clause fix*: the CRABS policy
  evaluator accepts both prefix (`AND <l> <r>`) and infix (`<l> AND <r>`)
  forms, and a one-clause prefix policy `'AND role:member'` — a
  legal-looking string that used to mis-parse — now collapses to the bare
  token. The fail-closed rule still stands for every OTHER dangling shape
  (a bare `'AND'`, a compound dangling operator, a parenthesized
  sub-expression — all refuse). But the encrypt/decrypt surface is
  stricter: OpenABE's policy parser is infix-only, so a prefix `'AND
  member'` fails the *encrypt* call itself (noisy, fail-closed) — encode
  encrypt policies infix (`'epoch_1 and member'`), as this recipe's seal
  does.
- *Re-encryption recall is only as sound as the re-seal*: re-encrypt early
  — data sealed under epoch N stays openable to every epoch-N-derived key
  (bearer-instrument property), and an epoch bump does not help
  retroactively any more than revocation does.

## Verified against the code

<!-- PROVENANCE
target: all-bindings
seal: Node.encrypt — wasm bindings/wasm/index.d.ts:686, node :508 (node impl
  bindings/node/src/crabs_node.cc:3036-3060); CP-ABE authority is
  machine-held (attribute_machine.c:309 wires abe_mk into the state;
  wasm glue seals with it src/Util/wasm_helpers.c:1622-1628); container
  layout u16le policy byte length + policy bytes + u32le ciphertext length
  + ciphertext pinned by bindings/wasm/test/smoke.js:111-130; ABE-word map
  ('name:value' → name_value) src/Crypto/crypto.c:98-111
reader keys: Node.abeKeygen wasm :698 / node :520 (crabs_node.cc:3078);
  Node.abeDecrypt wasm :708 / node :529 (crabs_node.cc:3106-3119); AbeKey
  destroyable wrapper (wasm :57-59, node :41-43 — destroy idempotence
  pinned by both tests); typed `unauthorized` on unsatisfied policy (also
  the tamper path, GCM fail-closed); keygen and decrypt consult NO user
  status and NO revocation registry src/Crypto/crypto.c:1075-1105
  (keygen crypto.c:809-855) — the bearer-instrument fact
revoke: Node.revokeUser wasm :482 / node :308; C attribute_machine_revoke_user
  src/Attribute/attribute_machine.h:175 + .c:888-907 — admin-gated,
  TERMINAL (R8-C-4 refusal .c:841-843 — USER_REVOKED cannot be resurrected),
  bumps the version counter (.c:901)
epoch observable: UserInfo.keyVersion — REAL readback on BOTH bindings, node
  bindings/node/index.d.ts:145 (mapped crabs_node.cc:1567-1601), wasm
  :277-288 (mapped bindings/wasm/bindings-core.js:895-952 — former
  hardcoded stubs replaced; pinned by bindings/wasm/test/getuser-readback.js;
  node surface type-checked test/test.js:253)
fail-closed gates:
  non-ACTIVE user op refusal (mode A) src/Crypto/crypto.c:1395-1403 (R7-14)
  suspended/revoked keyring key refusal src/Crypto/crypto.c:1325
  grant whitelist (revoked cannot be re-armed, R4-2)
    src/Attribute/attribute_machine.c:585-588
  staleness gate CRABS_ERR_KEY_STALE — src/StateMachine/state_machine.c:873-884
    (R7-04; error src/CRABS/crabs.h:78)
keyring lifecycle JS-reachable (parity-fill P2, user-id-scoped over the
  user_t-scoped primitives): node.suspendKey/activateKey/rotateKey +
  listKeys/getDefaultKey — wasm bindings-core.js:931-1038 over
  crabs_wasm_user_key_* (src/Util/wasm_helpers.c:1638-1747), node
  crabs_node.cc:1593-1760; d.ts wasm :308-336/:525-529, node :160-196/:351-358;
  pinned bindings/wasm/test/keyring.js + node test/test.js keyring block.
  Engine facts unchanged: user_key_suspend / user_key_activate /
  user_key_rotate src/Attribute/attribute_machine.h:219-221 — exercised
  src/Attribute/attribute_machine.c key paths + test/test_key_lifecycle.cpp;
  suspension recoverable + version-bumped on activation (R8-A-5 — ops
  signed during the window stale even after return, .c:1265); activation
  does NOT restore a vacated default (user_key_activate touches no default
  slot, .c:1254-1273); rotation revokes old key + chains new via
  predecessor_key_id (test 258-287). Residual C-only method forms:
  user_key_revoke / user_key_set_default (the __revoke_key__ /
  __set_default_key__ wire ops cover them) and the key_id-declaring sign
  path (a keyring-ed user's legacy stamp refuses unauthorized, R8-C-2 —
  crypto.c:1349-1357, pinned in keyring.js)
fine demotion JS-reachable (parity-fill P3): node.revokeRole /
  suspendUser / activateUser — wasm bindings-core.js:1039-1087 over
  attribute_machine_revoke_role / _suspend_user / _activate_user
  (src/Attribute/attribute_machine.h:145-171; admin-gated — active +
  role:admin signer, .c:772-820), node crabs_node.cc:1783-1821; d.ts wasm
  :534-548, node :352-366; pinned bindings/wasm/test/roles-admin.js (strip,
  revoked-target R4-4, gate flip fail-closed, suspended-signer walls,
  key_stale replay after reactivation) + node test/test.js admin block
user-level suspension: suspension itself (attribute_machine_suspend_user
  src/Attribute/attribute_machine.c:821-857; key-compromise recovery uses
  its internal form, crypto.c:2035)
key-version bump sites: .c:495 (register), :597/:617 (grant), :878
  (suspend_user), :901 (revoke_user), :1231 (key suspend), :1265 (key
  activate, R8-A-5), :1161 (key revoke); user_key_register does NOT bump
  (.c:1091-1151) — the counter counts RECORD mutations
policy grammar: prefix AND infix both accepted; single-clause prefix
  collapse src/Crypto/crypto.c:680-699; dangling shapes refuse; OpenABE
  seal parser INFIX-ONLY (this fork case-insensitive) — prefix seal
  policies fail the encrypt call noisily; condition preprocessing
  src/Condition/condition.c:1501-1598
change events: the C engine fires a kind-'attribute' revoke_user event from
  attribute_machine_revoke_user (attribute_machine.c:904,
  _notify_attribute_change :550-556) and BOTH wrappers forward it — hook
  registered at machine creation with no kind filter (wasm
  src/Util/wasm_helpers.c:262 + _forward_change_to_js, node
  crabs_node.cc:1311 + EmitChange); the node snippet demonstrates the event
  end-to-end; getUser readback (revoked + keyVersion bump) real on both

target: crabs-wasm (snippet wasm/15-revocable-data.js)
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:774
  KeyPair.generate          bindings/wasm/index.d.ts:44
  registerUser              bindings/wasm/index.d.ts:480
  grantRole                 bindings/wasm/index.d.ts:481
  Node.revokeUser           bindings/wasm/index.d.ts:482 (C:
                            attribute_machine_revoke_user, .c:888-907)
  getUser (real readback)   bindings/wasm/index.d.ts:488
  addCounter                bindings/wasm/index.d.ts:490
  getCounter                bindings/wasm/index.d.ts:554
  setPolicy                 bindings/wasm/index.d.ts:638
  registerHandlerJs         bindings/wasm/index.d.ts:683
  HandlerState.incrementCounter bindings/wasm/index.d.ts:195
  Operation.create          bindings/wasm/index.d.ts:122
  Node.sign / Node.execute  bindings/wasm/index.d.ts:657 / :656
  Node.encrypt              bindings/wasm/index.d.ts:686
  Node.abeKeygen            bindings/wasm/index.d.ts:698
  Node.abeDecrypt           bindings/wasm/index.d.ts:708
  AbeKey.destroy            bindings/wasm/index.d.ts:57-59
  Node.destroy              bindings/wasm/index.d.ts:770
  (fail-closed user gate)   src/Crypto/crypto.c:1395-1403 (R7-14 collapse)
  (re-grant whitelist)      src/Attribute/attribute_machine.c:585-588 (R4-2)
  (keygen consults no user record) src/Crypto/crypto.c:809-855
maturity: revokeUser + readback + abeKeygen/abeDecrypt semantics STABLE
  (C-tested via the R4-2/R7-14 gates; pinned on this binding by
  test/abe-decrypt.js + test/getuser-readback.js)
test_ref: bindings/wasm/test/abe-decrypt.js (keygen/decrypt round trip +
  refusals + token map) + bindings/wasm/test/getuser-readback.js +
  bindings/wasm/test/smoke.js:111-130 (encrypt container layout)

target: crabs-node (snippet node/15-revocable-data.js)
verified: executed
symbols:
  NodeStatic.new            bindings/node/index.d.ts:641-643
  KeyPair.generate          bindings/node/index.d.ts:71
  registerUser              bindings/node/index.d.ts:304
  grantRole                 bindings/node/index.d.ts:305
  Node.revokeUser           bindings/node/index.d.ts:308
  getUser                   bindings/node/index.d.ts:311 (crabs_node.cc:1567-1601)
  UserInfo.keyVersion       bindings/node/index.d.ts:145 (crabs_node.cc)
  defineItem                bindings/node/index.d.ts:363
  Node.sign / Node.execute  bindings/node/index.d.ts:463 / :464
  Node.on                   bindings/node/index.d.ts:310
  Node.encrypt              bindings/node/index.d.ts:508 (crabs_node.cc:3036-3060)
  Node.abeKeygen            bindings/node/index.d.ts:520 (crabs_node.cc:3078-3104)
  Node.abeDecrypt           bindings/node/index.d.ts:529 (crabs_node.cc:3106-3119)
  AbeKey.destroy            bindings/node/index.d.ts:41-43 (crabs_node.cc:430-474)
  Operation.new             bindings/node/index.d.ts:139
  Operation.addResource     bindings/node/index.d.ts:83
  (change event shape)      bindings/node/src/crabs_node.cc (EmitChange)
  (fail-closed user gate)   src/Crypto/crypto.c:1395-1403 (R7-14 collapse)
  (re-grant whitelist)      src/Attribute/attribute_machine.c:585-588 (R4-2)
maturity: all STABLE; the revoke readback (keyVersion/status) is mapped
  directly from the machine — no stub; abeKeygen/abeDecrypt pinned by
  bindings/node/test/abe.js
test_ref: bindings/node/test/abe.js (keygen/decrypt round trip + refusals)
  + bindings/node/test/test.js:143-147 (op-event result field) + :253

target: native-c (snippet c/15-revocable-data.c)
verified: executed
symbols:
  attribute_machine_create       src/Attribute/attribute_machine.h:118 (abe_mk wiring .c:309)
  attribute_machine_register_user src/Attribute/attribute_machine.h:130
  attribute_machine_grant_role   src/Attribute/attribute_machine.h:133
  (find_user)                    src/Attribute/attribute_machine.h:187
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
test_ref: test/test_key_lifecycle.cpp:88-125 (suspend), :171-251 (activate +
  R8-A-5 note), :258-287 (rotate), :586-619 (state-machine suspend/activate
  ops) + test/test_crypto.cpp:163-301 (ABE round trip) +
  test/test_attribute_machine.cpp:561-584
-->