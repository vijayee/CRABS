---
number: 12
slug: federation-between-machines
title: Federating two machines' machines via attestations
section: Composition
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
teaches: attestations — vouches that cross machines and expire
---
## The problem

Machine A runs the roster for a federation: 120 members, their roles, the
attributes its services consult. Machine B is a regional node in the same
federation — its own registry, its own admin, its own policies. B needs to
write a policy like "only editors publish here", but B cannot answer "who
is an editor?" by itself, because editor-ness is a fact A holds. And A
cannot just tell B once: members come and go, the fact they vouch for has
a lifetime, and the whole tie can end — at which point a third party who
was never shown A's manifest should still be able to prove it ended.

Stated exactly, the requirement is:

- B's members can *prove* what A vouched for them, to B: a signed,
  TTL-bounded attribute grant from A that B's authorization can resolve;
- the vouch decays on its own (a TTL), can be cut early (revocation), and is
  killed instantly when A severs the federation (dissolution);
- severance has an off-chain proof that does not depend on anyone's
  goodwill.

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

## The idea

A *vouch* is the federated system's answer to sharing facts across
administrative boundaries without sharing *authority*. Three of its
properties are the concept:

- **A credential, not an import.** B never holds "facts about the world" —
  it holds A's signature over a bounded claim, with a window
  (not-before ≤ now ≤ expires-at) stamped into the signed body. Facts that
  go stale therefore *dry up on their own*: an expired vouch passes no
  check, so there is no "snapshot going stale" to manage — the decay is in
  the credential.
- **Verification lives with the verifier.** The vouch is carried on the op
  by whoever is submitting it, but it authorizes nothing by being present:
  the machine that resolves the policy *re-verifies the credential itself*,
  per op, against the issuer's key chain — checking the signature, the
  window, the named child, the named user, and that the vouch's attribute
  list actually covers the policy token. A carried-but-unverified
  credential — forged, foreign, mis-addressed, truncated — authorizes
  nothing.
- **The clock is part of the trust model.** Every "until T" is executed as
  two timestamps compared against the verifier's time source. Without an
  *authenticated* clock, the TTL is advice: a host that keeps its own clock
  can hold expired vouches alive or kill fresh ones by sheer skew. That is
  not a defect of any particular mechanism — it is what expiry *means*
  without authenticated time, and every TTL-bounded design inherits it.

And when the federation ends, the machinery gives the three responses
distinct shapes: decay (TTL), early stop (revoke vouches — the child keeps
living), sever (dissolve — the bridge fails closed instantly and durably),
each of which leaves a different provable residue for outsiders.

## How CRABS encodes it

- *The vouch*: A's `attest` (`lineageAttest` on the node binding) signs a
  TTL-bounded attribute grant for a manifested child — wire image
  `u32le length + canonical body + 64-byte parent ECDSA`, body format v2,
  canonical body cap 512 bytes. The stamped window is not_before ≤ now ≤
  expires_at, TTL from the blueprint's `attestationTtlMs`; the body binds
  the parent's key-chain version, so verifying happens against the
  chain TIP only — a retired parent key verifies nothing.
- *The consume — an endorsement policy on B*: B's policy carries
  `@parent/<attribute>` tokens; the executor's endorsement pipeline resolves
  each token against the attestations the op carries. It requires: the
  attestation verifies under the child's accepted parent-key chain TIP, it
  names B's exact parent id, it names the op's resolved signer, and its
  attribute list covers the token EXACTLY. Every missing/invalid condition
  collapses to `unauthorized` — forged-parent, wrong-child, wrong-user,
  uncovered, expired, tampered, and an unbound machine all fail closed (the
  C snippet executes all of them; the JS batteries execute the JS-reachable
  subset: tampered, wrong-user, uncovered, wrong-child, expired). The
  consumer side is operator-controlled JS: `Operation.addAttestation`
  (both bindings, identical name) stages the credential field-wise onto the
  op — `parentId`/`childId`/`userId`/`attributes`/`notBefore`/`expiresAt`/
  `parentKeyVersion`/`signatureHex` — from the fields of the parent's
  attest wire image, which the canonical body layout makes parseable.
- *The early stop*: `__revoke_attestation__` flips B's manifest entry to
  `attestation_revoked` — new vouches refuse while the machine keeps living.
- *The sever*: `__dissolve_machine__` sets B's durable
  `lineage_parent_dissolved` flag — every `@parent/` endorsement on B fails
  closed *instantly*, even with a valid unexpired attestation in hand.
- *The off-chain proof*: `lineageTombstone` mints A's ECDSA over the
  canonical body `u8 tag + string16 child_id + u64le parent_key_version`,
  honesty-gated (the entry must currently read DISSOLVED — minting one for a
  live child is a lie and refuses), and B consumes it through the
  `__receive_dissolution__` op, verifying tip-only and refusing re-delivery
  idempotently.
- *The time configuration*: A stamps the window from ITS time source (`setTime`
  before `attest` — a machine never reads the wall clock itself); B checks
  the window with B's own. Both machines running the authenticated HTTPS
  time source is the configuration the windows are meaningful under. With
  the default system clock the TTL is advice.

## Try it

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

### crabs-node (native Node.js)

Same lifecycle on the native binding, plus the two halves the borrowed child
wrapper makes demoable: `__receive_dissolution__` consuming the tombstone
bytes and refusing re-delivery `already_performed` (the durable proof that
severance reached the child), and the `@parent/` endorsement consume on the
child machine itself (authorized + tampered/wrong-user/expired refusals).

```snippet:node/12-federation-between-machines.js
```

### C (native)

The consume half, on the engine the wrappers share: the child bound to its
parent, `@parent/role:writer` in the policy, alice's signed op carrying the
parent's attestation — authorized; then every failure mode refused — forged
parent, wrong child, wrong user, uncovered attributes, expired window,
tampered body, unbound machine.

```snippet:c/12-federation-between-machines.c
```

## What it guarantees / what it doesn't

Guaranteed:

- *Vouches are A's signature over a bounded claim.* The canonical body —
  parent/child/user ids, attribute list, window, and the parent key-version
  stamp — is signed as a unit; any body byte flip breaks verification. The
  stamp makes retired-key forgeries fail the tip gate.
- *The window is enforced, with typed refusals on both ends*: an
  attestation issued with `expires_at` before `now` is refused at mint;
  verification fails outside `not_before ≤ now ≤ expires_at`.
- *B's authorization never trusts the payload, only the verification.* The
  endorsement pipeline re-verifies the attestation itself, per op, against
  the chain — a carried-but-unverified "credential" (forged, foreign,
  mis-addressed, stale) authorizes nothing.
- *Revocation and severance are distinct tools with real semantics*: a
  revoked child keeps living and loses only vouches; a dissolved child loses
  the bridge instantly and durably; a tombstone for a live child is refused.

Not guaranteed — the clock honesty and the shape boundary:

- *The TTL fence is only as trustworthy as the clocks.* Expiry is checked
  against the child machine's time source; the default `SYSTEM_CLOCK` backs
  reads with the UNAUTHENTICATED platform clock. A time-protocol host can
  keep vouches alive past expiry or kill fresh ones by its own clock. Both
  machines running the authenticated HTTPS time source (`setTimeSource`,
  api-map §6) is the configuration the windows are meaningful under — this
  is the trust caveat the README carries, not a footnote.
- *The consume is JS-bound as operator staging, NOT as a verifier.*
  `Operation.addAttestation` stages the credential onto the op and the
  snippets execute the endorsed op end-to-end. (Parity-fill P8 also
  surfaced READ-side wire parsing from JS: `Node.attestationFromWire`
  fields an attestation wire image on both bindings — that is op-transport
  staging, still not the verifier.) What stays C-only is the
  verifier surface itself: `attestation_deserialize` has no JS map entry,
  and the two fail-closed cases a JS harness cannot produce — a FORGED
  parent (the bindings only mint REAL parent-node-key attestations through
  `crabs_issue_attestation`) and an UNBOUND machine (spawn always binds;
  the C snippet executes both cases). Nothing here is a gap: the executor's
  fails-closed battery is the boundary, and the JS batteries quote its
  `unauthorized` collapse verbatim.
- *Revocation is a one-way door for vouches, and the dissolve door stays
  open behind it*: an `attestation_revoked` entry refuses new vouches —
  yet still dissolves. A revoked federation is ended-for-vouches but still
  severable — the wasm snippet exercises the late dissolve end-to-end.
- *Peer federation does not exist.* `attest` is parent→child only, strictly
  manifest-gated: a machine cannot vouch for a machine it did not mint (the
  wasm snippet's `machine-ghost` refusal). Two INDEPENDENT machines
  federating as equals has no v1 mechanism — "federation" here means *the
  minted-by-A half* of the shape.
- *The tombstone is a proof of severance, not of content.* It binds
  child_id + parent key version; it says nothing about what the child did
  before the sever, and its delivery model assumes the child's parent-key
  chain (Recipe 11).

## Variations

- *Sovereign children*: when the parent wants to seed a child and end its
  stake without dissolution, vouching works the same but the lifecycle tool
  is `__withdraw_genesis__` (sovereign-only); dissolution refuses sovereign
  entries outright.
- *Parent key rotation*: after A rotates, old vouches stop verifying and
  children re-attest — attestations bind the mint-time chain version, the
  chain is capped at 8 entries and advance-only.
- *Re-delivery idempotency*: relays can be at-least-once without harm — a
  `__receive_dissolution__` replay on an already-severed child refuses
  `already_performed` (the node snippet delivers the tombstone to the
  severed resident child and asserts exactly that).
- *Multi-member vouches*: one vouch can cover several policy tokens — the
  attributes field is a comma-separated list, and an endorsement resolves
  when the list CONTAINS the token (the C snippet's covered-among-many
  case).

## Verified against the code

<!-- PROVENANCE
target: all-bindings
issuance:
  attest/lineageAttest — wasm bindings/wasm/index.d.ts:759 (3 args), node
  :572 (`attributes` optional, name divergence per api-map §10); wrapper
  over crabs_issue_attestation src/Lineage/lineage.h:680-685;
  manifest-gated (a non-manifested child is refused — the wasm snippet's
  machine-ghost case); issuer machine stamps the window from ITS time
  source (a machine never reads the wall clock itself)
  src/Lineage/lineage.h:621-623
  wire image: u32le length + canonical body + 64-byte parent ECDSA; body
  format v2 (CRABS_ATTESTATION_FORMAT_VERSION 0x02 src/Lineage/lineage.h:32),
  canonical body cap 512 (:38); expires-before-now refused at mint
  :620-629; canonical body layout (u8 format_version + string16
  ids/attributes + u64le window + u64le stamp, under the u32le prefix) in
  lineage.c _attestation_write_canonical_body — fully parseable from JS
consume:
  @parent/<attr> endorsement tokens (blueprint + live policy grammar)
  src/Lineage/lineage.h:89-104; executor verifies op-carried attestations
  itself, per op: _verify_parent_endorsements
  src/StateMachine/state_machine.c:709-762 + exact-coverage check :663-689;
  chain-TIP-only verification attestation_verify_by_lineage_key
  src/Lineage/lineage.h:654-670 — a retired parent key verifies nothing
  (chain tip at :643-656, cap 8 entries :254, advance-only)
  every failure mode collapses to `unauthorized` on the JS surface —
  tampered, wrong-user, uncovered, wrong-child, expired (JS batteries);
  forged-parent + unbound-machine are C-executable-only (the snippets are
  in cookbook/snippets/c/12-federation-between-machines.c — the bindings
  only mint REAL parent attestations and spawn always binds)
  Operation.addAttestation: wasm bindings/wasm/index.d.ts:111
  (AttestationFields :9-24; optional numerics number|bigint), node :125
  (AttestationFields :52-66; number only — api-map known diff #5) — stage
  the credential field-wise; NOT part of the canonical signing form (each
  attestation carries its own parent ECDSA) but rides op wire v5+
  wasm export crabs_wasm_op_add_attestation src/Util/wasm_helpers.c:810-865;
  node direct fill Operation::AddAttestation bindings/node/src/crabs_node.cc:870-979
  no JS verifier surface: attestation_deserialize src/Lineage/lineage.h:666
  stays C-only — JS verifies by EXECUTING
early stop: __revoke_attestation__ flips the manifest entry to
  attestation_revoked; new vouches refuse, machine keeps living
  src/Lineage/lineage.c:1752-1777 (op type decl lineage.h:516-520 —
  "dissolution stays available", honored: dissolve refuses only an
  already-DISSOLVED entry :1790-1801, pinned by test/test_lineage.cpp
  DissolveAfterRevokeIsLegal + the wasm snippet's late dissolve; the
  revoked entry's own tombstone mints through the honesty gate :1941)
sever: __dissolve_machine__ sets B's durable lineage_parent_dissolved flag
  (src/Lineage/lineage.c:1807; enforcement
  src/StateMachine/state_machine.c:716-723 — every @parent/ endorsement on
  B fails closed instantly, even with a valid unexpired attestation)
off-chain proof: lineageTombstone — wasm bindings/wasm/index.d.ts:764,
  node :580; canonical body u8 tag + string16 child_id + u64le
  parent_key_version + 64-byte parent sig, NO length prefix; honesty gate
  (a live child refuses — the entry must currently read DISSOLVED,
  lineage.c:1937); tombstone wire bytes ARE the __receive_dissolution__
  delivery bytes (src/Lineage/lineage.h:551-562, delivery spec :570-593) —
  a relay can never mint a differently-framed dissolution; delivery is
  tip-verified and idempotent (replay refuses already_performed — node
  lineage smoke bindings/node/lineage_smoke.mjs:198-239)
clock: expiry executed against the verifier's time source; default
  SYSTEM_CLOCK reads the UNAUTHENTICATED platform clock
  src/StateMachine/state_machine.h:267-272; the authenticated HTTPS
  time source (setTimeSource/getTimeSource, api-map §6) is the
  configuration the windows are meaningful under

target: crabs-wasm (snippet wasm/12-federation-between-machines.js)
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:774
  Node.setTime              bindings/wasm/index.d.ts:711
  Blueprint.create          bindings/wasm/index.d.ts:150
  Node.lineageInstall       bindings/wasm/index.d.ts:744
  Node.lineageSpawn         bindings/wasm/index.d.ts:746
  Node.lineageResidentChild bindings/wasm/index.d.ts:748
  childById                 bindings/wasm/index.d.ts:755
  Node.attest               bindings/wasm/index.d.ts:759
  Operation.addAttestation  bindings/wasm/index.d.ts:111 (AttestationFields :9-24)
  Operation.create          bindings/wasm/index.d.ts:122
  (wasm export)             crabs_wasm_op_add_attestation src/Util/wasm_helpers.c:810-865
  (executor consume)        src/StateMachine/state_machine.c:709-762
  (lineage ops)             src/Lineage/lineage.h:484-489
  Node.lineageTombstone     bindings/wasm/index.d.ts:764
  (revoke handler)          src/Lineage/lineage.c:1752-1777
  (dissolve + honesty gate) src/Lineage/lineage.c:1795-1801 + :1941
maturity: all STABLE
test_ref: bindings/wasm/test/attestations.js (endorsed attach + refusals + op-wire round trip) + bindings/wasm/lineage_smoke.mjs:82-186 (attest + tombstone)

target: crabs-node (snippet node/12-federation-between-machines.js)
verified: executed
symbols:
  new Node                  bindings/node/index.d.ts:641-643
  Node.setTime              bindings/node/index.d.ts:536
  Blueprint.create          bindings/node/index.d.ts:192
  Node.lineageInstall       bindings/node/index.d.ts:556
  Node.lineageSpawn         bindings/node/index.d.ts:562
  Node.lineageChildren      bindings/node/index.d.ts:564
  Node.lineageResidentChild bindings/node/index.d.ts:566
  Node.lineageAttest        bindings/node/index.d.ts:572
  Operation.addAttestation  bindings/node/index.d.ts:125 (AttestationFields :52-66)
  (addon fill)              Operation::AddAttestation bindings/node/src/crabs_node.cc:870-979
  Node.lineageTombstone     bindings/node/index.d.ts:580
  Node.getNodeKey           bindings/node/index.d.ts:312
  (receive-dissolution spec) src/Lineage/lineage.h:570-593
maturity: all STABLE; receive-dissolution delivery STABLE (C-tested + demonstrated
  against the resident-severed wrapper)
test_ref: bindings/node/test/attestations.js (endorsed attach + refusals) + bindings/node/lineage_smoke.mjs:101-239 (attest, dissolve, tombstone, receive-dissolution idempotency)

target: native-c (snippet c/12-federation-between-machines.c)
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
maturity: all exercised in C tests; forged-parent + unbound-machine are the
  cases a JS harness cannot mint
test_ref: test/test_lineage.cpp:396-508 (round trip + refusals) + :644-777
  (endorsement pipeline) + :740-753 (covered-among-many vouch)
-->