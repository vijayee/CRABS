---
number: 12
slug: federation-between-machines
title: Federating two machines' machines via attestations
section: Composition
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
---
## Intent

Machine A — a service, an org root, a coordinator — and machine B — a
regional instance, a team service — should cooperate without sharing an
admin key, a registry, or a trust-on-first-sight handshake. The requirement,
stated exactly:

- B's members can *prove* what A vouched for them, to B: a signed,
  TTL-bounded attribute grant from A that B's authorization can resolve;
- the vouch decays on its own (a TTL), can be cut early (revocation), and is
  killed instantly when A severs the federation (dissolution);
- a third party who was never shown A's manifest can still verify the
  severance happened (the signed tombstone).

## The naive version, and where it breaks

The naive federation exchanges *user lists*: A exports its member roster, B
imports it as local facts. The import is a snapshot that immediately goes
stale (revocation at A is invisible at B), it has no TTL, and it forges
authority — B now believes things about `alice` that `alice` and A may have
since changed. Copying A's admin credentials into B is worse: there is no
way to take an authority back that B already embedded (Recipe 11's naive
version, the worse half). A bespoke "verification service" in the middle
concentrates the same authority in a new single point that both machines
must now trust — and nothing about it is verifiable by a third party.

The credential you want is exactly an *attestation*: A signs a bounded factual
claim ("alice is role:member in machine-b until T"), B verifies it against
A's key chain, and every decay/sever case has a code-level answer.

## The shape

- *The vouch*: A's `attest` (`lineageAttest` on the node binding) signs a
  TTL-bounded attribute grant for a manifested child — wire image
  `u32le length + canonical body + 64-byte parent ECDSA`, body format v2,
  canonical body cap 512 bytes (`bindings/wasm/index.d.ts:725`,
  `bindings/node/index.d.ts:538`; C format constants
  `src/Lineage/lineage.h:32-39`; issuer semantics, manifest-gated, at
  `src/Lineage/lineage.h:670-685`). The stamped window is not_before ≤ now ≤
  expires_at, TTL from the blueprint's `attestationTtlMs`; the body binds
  the parent's key-chain version (A11-4), so verifying happens against the
  chain TIP only — a retired parent key verifies nothing
  (`src/Lineage/lineage.h:643-656`).
- *The consume — an endorsement policy on B*: B's policy carries
  `@parent/<attribute>` tokens; the executor's endorsement pipeline resolves
  each token against the attestations the op carries. It requires: the
  attestation verifies under the child's accepted parent-key chain TIP, it
  names B's exact parent id, it names the op's resolved signer, and its
  attribute list covers the token EXACTLY
  (`_verify_parent_endorsements`, `src/StateMachine/state_machine.c:709-762`;
  exact-coverage check `:663-689`). Every missing/invalid condition
  collapses to `unauthorized` — forged-parent, wrong-child, wrong-user,
  uncovered, expired, tampered, and an unbound machine all fail closed (the
  C snippet executes all of them; the JS batteries execute the JS-reachable
  subset: tampered, wrong-user, uncovered, wrong-child, expired). The
  consumer side is operator-controlled JS: `Operation.addAttestation`
  (both bindings, identical name) stages the credential field-wise onto the
  op — `parentId`/`childId`/`userId`/`attributes`/`notBefore`/`expiresAt`/
  `parentKeyVersion`/`signatureHex` — from the fields of the parent's
  attest wire image, which the canonical body layout makes parseable
  (`bindings/wasm/index.d.ts:9-25` the `AttestationFields` shape,
  `:102` the method; node `index.d.ts:39-55`, `:112`; wasm export
  `crabs_wasm_op_add_attestation`, `src/Util/wasm_helpers.c:810-865`;
  node direct fill `bindings/node/src/crabs_node.cc:870-979`).
- *The early stop*: `__revoke_attestation__` flips B's manifest entry to
  `attestation_revoked` — new vouches refuse while the machine keeps living
  (`src/Lineage/lineage.c:1752-1777`).
- *The sever*: `__dissolve_machine__` sets B's durable
  `lineage_parent_dissolved` flag — every `@parent/` endorsement on B fails
  closed *instantly*, even with a valid unexpired attestation in hand
  (`src/StateMachine/state_machine.c:716-723`; flag set at
  `src/Lineage/lineage.c:1807`).
- *The off-chain proof*: `lineageTombstone` mints A's ECDSA over the
  canonical body `u8 tag + string16 child_id + u64le parent_key_version`,
  honesty-gated (the entry must currently read DISSOLVED — minting one for a
  live child is a lie and refuses), and B consumes it through the
  `__receive_dissolution__` op, verifying tip-only and refusing re-delivery
  idempotently (`bindings/wasm/index.d.ts:730`,
  `bindings/node/index.d.ts:540-547`; delivery spec
  `src/Lineage/lineage.h:570-593`).

## What it guarantees / what it doesn't

Guaranteed (everything below is executed by the snippets):

- *Vouches are A's signature over a bounded claim.* The canonical body —
  parent/child/user ids, attribute list, window, and the parent key-version
  stamp — is signed as a unit; any body byte flip breaks verification
  (`src/Lineage/lineage.h:636-641`; the C snippet's tamper case). The stamp
  makes retired-key forgeries fail the tip gate
  (`src/Lineage/lineage.h:643-656`).
- *The window is enforced, with typed refusals on both ends*: an attestation
  issued with `expires_at` before `now` is refused at mint (`src/Lineage/lineage.h:620-629`);
  verification fails outside `not_before ≤ now ≤ expires_at`
  (`src/Lineage/lineage.h:636-641`; expiry verified in the C snippet and
  `test/test_lineage.cpp:416-417`).
- *B's authorization never trusts the payload, only the verification.* The
  endorsement pipeline re-verifies the attestation itself, per op, against
  the chain — a carried-but-unverified "credential" (forged, foreign,
  mis-addressed, stale) authorizes nothing (`src/StateMachine/state_machine.c:709-762`;
  the C snippet's negative battery).
- *Revocation and severance are distinct tools with real semantics*: a
  revoked child keeps living and loses only vouches; a dissolved child loses
  the bridge instantly and durably; a tombstone for a live child is refused
  (`src/Lineage/lineage.c:1937` honesty gate observed; manifest-gated
  issuance at `src/Lineage/lineage.h:670-685`).

Not guaranteed — the honesty this recipe owes:

- *The TTL fence is only as trustworthy as the clocks.* Expiry is checked
  against the child machine's time source; the default `SYSTEM_CLOCK` backs
  reads with the UNAUTHENTICATED platform clock
  (`src/StateMachine/state_machine.h:267-272`). A time-protocol host can
  keep vouches alive past expiry or kill fresh ones by its own clock. Both
  machines running the authenticated HTTPS time source (`setTimeSource`,
  api-map §6) is the configuration the windows are meaningful under — this
  is the trust caveat the README carries, not a footnote.
- *The consume is JS-bound as operator staging, NOT as a verifier.*
  `Operation.addAttestation` stages the credential onto the op and the
  snippets execute the endorsed op end-to-end (authorized, plus the
  tampered/wrong-user/uncovered/wrong-child/expired refusals). What stays
  C-only is the verifier surface itself: `attestation_deserialize`
  (`src/Lineage/lineage.h:666`) has no JS map entry, and the two fail-closed
  cases a JS harness cannot produce — a FORGED parent (the bindings only
  mint REAL parent-node-key attestations through `crabs_issue_attestation`)
  and an UNBOUND machine (spawn always binds; the C snippet executes both
  cases, `cookbook/snippets/c/12-federation-between-machines.c`). Nothing
  here is a gap: the executor's fails-closed battery is the boundary, and
  the JS batteries quote its `unauthorized` collapse verbatim.

- *Revocation is a one-way door for vouches, and the dissolve door stays
  open behind it*: an `attestation_revoked` entry refuses new vouches —
  yet still dissolves. The C header's `__revoke_attestation__` comment
  promises "dissolution stays available" (`src/Lineage/lineage.h:514-520`),
  and the dissolve op honors it: it refuses only an already-DISSOLVED
  entry (`src/Lineage/lineage.c:1790-1792`); a revoked entry proceeds to
  the DISSOLVED transition, which is also what makes its tombstone mint
  freely through the honesty gate (`src/Lineage/lineage.c:1941`).
  Treat a revoked federation as ended-for-vouches but still severable —
  the wasm snippet exercises the late dissolve end-to-end.
- *Peer federation does not exist.* `attest` is parent→child only, strictly
  manifest-gated: a machine cannot vouch for a machine it did not mint (the
  wasm snippet's `machine-ghost` refusal; `src/Lineage/lineage.h:670-685`).
  Two INDEPENDENT machines federating as equals has no v1 mechanism —
  "federation" here means *the minted-by-A half* of the shape.
- *The tombstone is a proof of severance, not of content.* It binds
  child_id + parent key version; it says nothing about what the child did
  before the sever, and its delivery model assumes the child's parent-key
  chain (Recipe 11).

## Variations

- *Sovereign children*: vouching works the same, but the lifecycle tool is
  `__withdraw_genesis__` (sovereign-only); dissolution refuses sovereign
  entries outright (`src/Lineage/lineage.h:608-614`, `:523-524`).
- *Parent key rotation*: attestations bind the mint-time chain version;
  after A rotates, old vouches stop verifying and children re-attest — the
  chain is capped at 8 entries and advance-only
  (`src/Lineage/lineage.h:643-656`, cap `:254`).
- *Re-delivery idempotency*: a `__receive_dissolution__` replay on an
  already-severed child refuses `already_performed` — the node snippet
  delivers the tombstone to the severed resident child and asserts exactly
  that (`src/Lineage/lineage.h:574-578`; node lineage smoke
  `bindings/node/lineage_smoke.mjs:198-239`).
- *Multi-member vouches*: the attributes field is a comma-separated list,
  and an endorsement resolves when the list CONTAINS the token — one vouch
  can cover several policy tokens (C snippet's covered-among-many case;
  `test/test_lineage.cpp:740-753`).

## Recipe

### crabs-wasm (browser / Node / edge)

Mint machine B, vouch for its members, EXECUTE a `@parent/`-endorsed op on
the child with the vouch attached (`Operation.addAttestation`: authorized,
plus tampered/wrong-user/expired refused), sever with the signed tombstone,
and — on a second machine — de-vouch with `__revoke_attestation__`, watching
the machine keep living while the vouches stop — then dissolve it anyway
(the door stays open; the late tombstone mints). The wire images are
structure-checked inline.

```snippet:wasm/12-federation-between-machines.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:740
  Node.setTime              bindings/wasm/index.d.ts:677
  Blueprint.create          bindings/wasm/index.d.ts:136-138
  Node.lineageInstall       bindings/wasm/index.d.ts:710
  Node.lineageSpawn         bindings/wasm/index.d.ts:712
  Node.lineageResidentChild bindings/wasm/index.d.ts:714
  childById                 bindings/wasm/index.d.ts:721
  Node.attest               bindings/wasm/index.d.ts:725
  Operation.addAttestation  bindings/wasm/index.d.ts:99 (AttestationFields :9-24)
  Operation.create          bindings/wasm/index.d.ts:111
  (wasm export)             crabs_wasm_op_add_attestation src/Util/wasm_helpers.c:810-865
  (executor consume)        src/StateMachine/state_machine.c:709-762
  (lineage ops)             src/Lineage/lineage.h:484-489
  Node.lineageTombstone     bindings/wasm/index.d.ts:730
  (revoke handler)          src/Lineage/lineage.c:1752-1777
  (dissolve + honesty gate) src/Lineage/lineage.c:1795-1801 + :1941
maturity: all STABLE
test_ref: bindings/wasm/test/attestations.js (endorsed attach + refusals + op-wire round trip) + bindings/wasm/lineage_smoke.mjs:82-186 (attest + tombstone)
-->

### crabs-node (native Node.js)

Same lifecycle on the native binding, plus the two halves the borrowed child
wrapper makes demoable: `__receive_dissolution__` consuming the tombstone
bytes and refusing re-delivery `already_performed` (the durable proof that
severance reached the child), and the `@parent/` endorsement consume on the
child machine itself (authorized + tampered/wrong-user/expired refusals).

```snippet:node/12-federation-between-machines.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  new Node                  bindings/node/index.d.ts:608
  Node.setTime              bindings/node/index.d.ts:502
  Blueprint.create          bindings/node/index.d.ts:179
  Node.lineageInstall       bindings/node/index.d.ts:522
  Node.lineageSpawn         bindings/node/index.d.ts:528
  Node.lineageChildren      bindings/node/index.d.ts:530
  Node.lineageResidentChild bindings/node/index.d.ts:532
  Node.lineageAttest        bindings/node/index.d.ts:538
  Operation.addAttestation  bindings/node/index.d.ts:112 (AttestationFields :39-55)
  (addon fill)              Operation::AddAttestation bindings/node/src/crabs_node.cc:870-979
  Node.lineageTombstone     bindings/node/index.d.ts:546
  Node.getNodeKey           bindings/node/index.d.ts:299
  (receive-dissolution spec) src/Lineage/lineage.h:570-593
maturity: all STABLE; receive-dissolution delivery STABLE (C-tested + demonstrated against the resident-severed wrapper)
test_ref: bindings/node/test/attestations.js (endorsed attach + refusals) + bindings/node/lineage_smoke.mjs:101-239 (attest, dissolve, tombstone, receive-dissolution idempotency)
-->

### C (native)

The consume half, on the engine the wrappers share: the child bound to its
parent, `@parent/role:writer` in the policy, alice's signed op carrying the
parent's attestation — authorized; then every failure mode refused — forged
parent, wrong child, wrong user, uncovered attributes, expired window,
tampered body, unbound machine.

```snippet:c/12-federation-between-machines.c
```

<!-- PROVENANCE
target: native-c
verified: executed
symbols:
  attestation_create             src/Lineage/lineage.h:630-634
  attestation_verify             src/Lineage/lineage.h:639-641
  attestation_verify_by_lineage_key src/Lineage/lineage.h:654-656
  attestation_serialize          src/Lineage/lineage.h:661-662
  attestation_deserialize        src/Lineage/lineage.h:666
  (op.attestations payload)      src/StateMachine/state_machine.h:96-97
  (_verify_parent_endorsements)  src/StateMachine/state_machine.c:709-762
  (exact coverage check)         src/StateMachine/state_machine.c:663-689
maturity: all exercised in C tests; forged-parent + unbound-machine are the cases a JS harness cannot mint
test_ref: test/test_lineage.cpp:396-508 (round trip + refusals) + :644-777 (endorsement pipeline)
-->

## Notes

- *Where each half runs*: issuance is a wrapper convenience over
  `crabs_issue_attestation` (manifest-gated, TTL from the blueprint) —
  wasm and node differ only in the method name (`attest` /
  `lineageAttest`) and the node binding's optional attributes argument
  (api-map §10). Consumption is split the same way the executor is: the
  attach is a JS struct fill (`Operation.addAttestation`, identical name,
  both bindings — the node addon stages it straight onto `op_->attestations`,
  the wasm export mirrors `crabs_wasm_op_add_lock_claim`'s slot growth), and
  the VERIFICATION is the executor's — `@parent/` policies refuse on the
  engine's own re-verification, never on the operator's word.
- *The wire is fully parseable from JS*: the canonical body layout is
  documented (`src/Lineage/lineage.c`, `_attestation_write_canonical_body` —
  u8 format_version + string16 ids/attributes + u64le window + u64le stamp,
  under the u32le length prefix), so the recipes parse the vouch field-wise
  themselves; `attestation_deserialize` (`src/Lineage/lineage.h:666`) stays
  C-only (no JS map entry). Tampering is therefore ALWAYS caught
  engine-side: a hand-edit to any field breaks the parent ECDSA over the
  body.
- *Time discipline, restated*: A stamps the window from ITS time source
  (`setTime` before `attest` — a machine never reads the wall clock itself,
  `src/Lineage/lineage.h:621-623`); B checks the window with B's own. The
  honest deployment configures the authenticated HTTPS time source on both
  (`setTimeSource`, api-map §6); with the default system clock the TTL is
  advice, not enforcement.
- *Tombstone bytes are delivery bytes*: the wire `lineageTombstone` returns
  is byte-for-byte what a `__receive_dissolution__` op transports
  (`src/Lineage/lineage.h:551-562`), so a relay can never mint a
  differently-framed dissolution. The node snippet's re-delivery refusal is
  the idempotency the C contract specifies.
- *Reconciliation note for implementers*: the old divergence is settled —
  `src/Lineage/lineage.h:514-520` promises a revoked child's "dissolution
  stays available", and the dissolve handler now honors it (it refuses only
  an already-DISSOLVED, sovereign, or withdrawn entry —
  `src/Lineage/lineage.c:1790-1801`; gated in
  `test/test_lineage.cpp` `DissolveAfterRevokeIsLegal`). Revoke-then-dissolve
  is legal; only re-dissolving an already-DISSOLVED entry is refused.