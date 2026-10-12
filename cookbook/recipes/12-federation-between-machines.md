---
number: 12
slug: federation-between-machines
title: Federating two machines' machines via attestations
section: Composition
status: PARTIAL
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
  canonical body cap 512 bytes (`bindings/wasm/index.d.ts:357`,
  `bindings/node/index.d.ts:295-300`; C format constants
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
  (`_verify_parent_endorsements`, `src/StateMachine/state_machine.c:700-756`;
  exact-coverage check `:654-675`). Every failure collapses to
  `unauthorized` — forged-parent, wrong-child, wrong-user, uncovered,
  expired, tampered, and an unbound machine all fail closed (the C snippet
  executes all of them).
- *The early stop*: `__revoke_attestation__` flips B's manifest entry to
  `attestation_revoked` — new vouches refuse while the machine keeps living
  (`src/Lineage/lineage.c:1752-1777`).
- *The sever*: `__dissolve_machine__` sets B's durable
  `lineage_parent_dissolved` flag — every `@parent/` endorsement on B fails
  closed *instantly*, even with a valid unexpired attestation in hand
  (`src/StateMachine/state_machine.c:703-712`; flag set at
  `src/Lineage/lineage.c:1807`).
- *The off-chain proof*: `lineageTombstone` mints A's ECDSA over the
  canonical body `u8 tag + string16 child_id + u64le parent_key_version`,
  honesty-gated (the entry must currently read DISSOLVED — minting one for a
  live child is a lie and refuses), and B consumes it through the
  `__receive_dissolution__` op, verifying tip-only and refusing re-delivery
  idempotently (`bindings/wasm/index.d.ts:358-362`,
  `bindings/node/index.d.ts:295-308`; delivery spec
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
  issued with `expires_at` before `now` is refused at mint; verification
  fails outside `not_before ≤ now ≤ expires_at`
  (`src/Lineage/lineage.h:636-641`; expiry verified in the C snippet and
  `test/test_lineage.cpp:416-417`).
- *B's authorization never trusts the payload, only the verification.* The
  endorsement pipeline re-verifies the attestation itself, per op, against
  the chain — a carried-but-unverified "credential" (forged, foreign,
  mis-addressed, stale) authorizes nothing (`src/StateMachine/state_machine.c:700-756`;
  the C snippet's negative battery).
- *Revocation and severance are distinct tools with real semantics*: a
  revoked child keeps living and loses only vouches; a dissolved child loses
  the bridge instantly and durably; a tombstone for a live child is refused
  (`src/Lineage/lineage.c:1787-1790` honesty gate observed; manifest-gated
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
- *[The GAP — verification/attachment is C-only]:*

  > [!WARNING] GAP
  >
  > **Prose describes:** B resolving an A-signed attestation — attaching the
  > vouch to an op and letting B's `@parent/` endorsement policy authorize it.
  >
  > **Codebase status:** exists in C and is engine-tested: the op carries
  > `attestations[]` (`src/StateMachine/state_machine.h:90-97`, wire format
  > v5 per `CRABS_OP_FORMAT_VERSION` history `src/StateMachine/state_machine.h:60-64`),
  > the pipeline `_verify_parent_endorsements`
  > (`src/StateMachine/state_machine.c:700-756`), the chain-aware verifier
  > `attestation_verify_by_lineage_key` (`src/Lineage/lineage.h:655-656`),
  > tests at `test/test_lineage.cpp:644-777`. Neither JS binding exposes any
  > of it: grep both `.d.ts` files — the only attestation surface is
  > issuance (`bindings/wasm/index.d.ts:357`,
  > `bindings/node/index.d.ts:295-300`); no op-attestation attachment, no JS
  > deserializer (`attestation_deserialize`, `src/Lineage/lineage.h:666`, is
  > C-only).
  >
  > **Divergence:** the design (spec §attestation bridge) makes attestations
  > the cross-machine credential B's policies resolve against; JS consumers
  > can mint the credential (both snippets do) but cannot deliver or consume
  > one — the demoed consumption runs in the C snippet below, against the
  > same engine the bindings wrap.
  >
  > **Tracking:** an internal implementation plan (not published on this
  > site).
  >
  > **Agent action:** code block omitted on the JS surfaces for the consume
  > half — do not invent `op.attestations`, an `attachAttestation`, or an
  > attestation deserializer on either binding; the C section is where this
  > half is real.

  For that reason the frontmatter status is PARTIAL: the recipe *delivers*
  vouch/decay/sever/proof on wasm + node and consume on C, and nothing more.

- *Revocation is a one-way door, and the dissolve door closes behind it* (a
  divergent pair the engine settles): a `attestation_revoked` entry refuses
  new vouches — and also refuses `__dissolve_machine__`, because the
  dissolve op requires the entry to still be ACTIVE
  (`src/Lineage/lineage.c:1787-1790`, refused in the wasm snippet). The C
  header's `__revoke_attestation__` comment claims "dissolution stays
  available" (`src/Lineage/lineage.h:516-520`) — the handler's observed
  behavior is what this recipe documents; treat a revoked federation as
  ended-for-vouches and unrecoverable to the dissolve op.
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

Mint machine B, vouch for its members, sever with the signed tombstone,
and — on a second machine — de-vouch with `__revoke_attestation__`, watching
the machine keep living while the vouches stop. The wire images are
structure-checked inline.

```snippet:wasm/12-federation-between-machines.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:372
  Node.setTime              bindings/wasm/index.d.ts:309
  Blueprint.create          bindings/wasm/index.d.ts:79-81
  Node.lineageInstall       bindings/wasm/index.d.ts:342
  Node.lineageSpawn         bindings/wasm/index.d.ts:344
  Node.lineageResidentChild bindings/wasm/index.d.ts:346
  childById                 bindings/wasm/index.d.ts:353
  Node.attest               bindings/wasm/index.d.ts:357
  Operation.create          bindings/wasm/index.d.ts:52
  (lineage ops)             src/Lineage/lineage.h:484-489
  Node.lineageTombstone     bindings/wasm/index.d.ts:358-362
  (revoke handler)          src/Lineage/lineage.c:1752-1777
  (dissolve + honesty gate) src/Lineage/lineage.c:1787-1790 + :1807
maturity: all STABLE
test_ref: bindings/wasm/lineage_smoke.mjs:82-186 (attest + tombstone) + :121-141 (honesty gates)
-->

### crabs-node (native Node.js)

Same lifecycle on the native binding, plus the delivery half the borrowed
child wrapper makes demoable: `__receive_dissolution__` consuming the
tombstone bytes and refusing re-delivery `already_performed` — the durable
proof that severance reached the child.

```snippet:node/12-federation-between-machines.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  new Node                  bindings/node/index.d.ts:312
  Node.setTime              bindings/node/index.d.ts:264
  Blueprint.create          bindings/node/index.d.ts:100
  Node.lineageInstall       bindings/node/index.d.ts:284
  Node.lineageSpawn         bindings/node/index.d.ts:290
  Node.lineageChildren      bindings/node/index.d.ts:292
  Node.lineageResidentChild bindings/node/index.d.ts:294
  Node.lineageAttest        bindings/node/index.d.ts:300
  Node.lineageTombstone     bindings/node/index.d.ts:295-308
  Node.getNodeKey           bindings/node/index.d.ts:190
  (receive-dissolution spec) src/Lineage/lineage.h:570-593
maturity: attest/tombstone/lifecycle STABLE; receive-dissolution delivery STABLE (C-tested + demonstrated against the resident-severed wrapper)
test_ref: bindings/node/lineage_smoke.mjs:101-239 (attest, dissolve, tombstone, receive-dissolution idempotency)
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
  (op.attestations payload)      src/StateMachine/state_machine.h:90-97
  (_verify_parent_endorsements)  src/StateMachine/state_machine.c:700-756
  (exact coverage check)         src/StateMachine/state_machine.c:654-675
maturity: all exercised in C tests (the JS gap above)
test_ref: test/test_lineage.cpp:396-508 (round trip + refusals) + :644-777 (endorsement pipeline)
-->

## Notes

- *Where each half runs*: issuance is a wrapper convenience over
  `crabs_issue_attestation` (manifest-gated, TTL from the blueprint) —
  wasm and node differ only in the method name (`attest` /
  `lineageAttest`) and the node binding's optional attributes argument
  (api-map §10). Consumption is engine-only, which is why the recipe's one
  gap sits between the sections.
- *The length-prefix check is the whole JS-visible structure*: wasm/node
  consumers can assert `u32le total == wire.length - 4` and a non-zero
  trailing ECDSA — the canonical body (ids, window, stamp) is opaque to JS
  (`attestation_deserialize`, `src/Lineage/lineage.h:666`, has no JS map
  entry).
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
- *Reconciliation note for implementers*: `src/Lineage/lineage.h:516-520`
  says a revoked child's "dissolution stays available", while the dissolve
  handler refuses every non-ACTIVE entry (`src/Lineage/lineage.c:1787-1790`).
  This recipe documents the handler's observed behavior; until the two are
  reconciled, treat revoke-then-dissolve as refused.