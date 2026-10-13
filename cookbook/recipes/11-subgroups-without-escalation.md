---
number: 11
slug: subgroups-without-escalation
title: A group with subgroups that can't escalate
section: Composition
status: COMPLETE
maturity: STABLE
target: crabs-wasm
languages: c wasm node
teaches: attenuating authority down a machine tree
---
## The problem

A group of forty runs three subgroups: a billing team of three, a support
desk of five, a regional chapter of twelve. Each subgroup needs the
capabilities its charter names — a few items, a few policies, its own
roster — and the group's authority should not pour into it, nor the
subgroup's back out. So two directions of "can't escalate" need different
answers, and people habitually ask for a third:

- *Up*: a member who holds a role inside billing — the group holds no
  registration for them in a place its policies consult — gets nothing by
  walking over to the group machine and trying their luck.
- *Down*: the subgroup's own admin goes on growing their domain — a new
  ledger column, a new member, a new role — without asking the parent each
  time, because the subgroup is not a frozen grant, it is a workplace.
- And the trap: the easiest way to give the subgroup "its own authority" is
  to hand it a copy of the parent's admin key, which collapses both
  directions at once — the subgroup *is* the parent, authority-wise,
  forever.

The line to hold: attenuation at the moment of creation, self-governance
after it, and real teeth for the parent when its trust changes — not a cage.

## The naive version, and where it breaks

The naive version models subgroups as *role namespaces on one machine*: a
`billing` role, a policy `AND role:billing`, done. Three things break at
once. First, there is no attenuation to audit — the parent's admin can
retune any billing policy at any moment, and "billing" members are members
of the whole machine; nothing bounds what a billing policy can address. Second, the
subgroup has no authority of its own: its existence is a set of rows in the
parent's attribute machine, so "revoking the subgroup" means hand-editing
those rows and hoping the edits were all found. Third — the one that makes
the whole structure unsafe — every subgroup identity lives in one registry,
so any escalation inside the machine (a leaked admin key, a policy mistake)
is an escalation for *every* subgroup at once. Roles scale to dozens; they do
not scale to federated machines.

Granting an actual second machine a copy of the admin key is worse: now the
subgroup *is* the parent, authority-wise, forever — there is no way to take a
key back that a machine already embedded.

## The idea

Authority in large systems is *attenuated*, not shared: each level holds
exactly the capabilities its charter names, receives them from the level
above, and passes down only what it cares to delegate. Two properties make
attenuation sound, and both halves of the subgroup story are one of them:

- *Can't reach up* is the isolation half. A subgroup's members exist in the
  subgroup's registry only; authorization on the parent resolves through
  the parent's registry, so a subgroup role authorizes nothing above it.
  And the one legitimate bridge back out — the parent's vouch for a
  subgroup member — is issued and *verified* on the parent's side of the
  tie, against the parent's own key chain.
- *Can't grow* would be the sandbox half — and it does **not** hold,
  which is the honest surprise. A subgroup is a complete machine: its admin
  can mint items, register members, grant roles, and spawn its own
  subgroups further down. Attenuation is the *initial* grant, not a
  permanent ceiling. What confines is not the child's ceiling but the
  partition: a subgroup admin's misdeeds stay inside the subgroup.

What the parent keeps is not a dial back — there is no op that edits a live
child's charter or dials its power down. It keeps *severance-shaped* teeth:
stop vouching (attestations dry up on their own TTL), or sever the tie
outright. That asymmetry — a durable cut, not remote control — is what keeps
the parent from leaking back into the subgroup the very authority it gave
up.

## How CRABS encodes it

- *The charter is a Blueprint* — a serializable machine definition the
  parent authors before minting: item set, policy set, bootstrap admin,
  attestation TTL (`Blueprint.create` / `addItem` / `addPolicy` /
  `stampHash` / `serialize`). `stampHash` + `deserialize` verify the
  embedded SHA-256 on the wire image — the exact bytes a
  `__spawn_machine__` op transports.
- *Trust modes pick the authority story*: `SHARED_ROOT` — the child
  deliberately **borrows** the parent's attribute machine and MSK, one
  registry serves both; `DELEGATED_COPY` — a **fresh** CP-ABE authority is
  minted, the child's auth pipeline resolves users through its own
  registry; `SOVEREIGN` — constructed like delegated copy, but recorded as
  lineage-sovereign in the parent's manifest: the parent may only
  *withdraw* its genesis stake, never dissolve.
- *Spawn is validated, then committed atomically in the manifest*: duplicate
  child ids (and the parent's own machine id) are refused; the manifest
  entry is appended only after the child is fully built, so every failure
  leaves no residue (children cap: `CRABS_MAX_CHILD_MACHINES`).
- *The manifest is the parent's track record*: entries carry
  childId/mode/status/ttl (`childCount`…`children` on wasm;
  `lineageChildren` on node).
- *The teeth are lineage ops through the normal pipeline* —
  `lineageInstall` registers the six `__…__` op types, each policy
  `role:admin` by default and overridable. `__revoke_attestation__` stops
  vouching without dissolution (live attestations run out their TTL);
  `__dissolve_machine__` severs — it durably sets the child's
  `lineage_parent_dissolved` flag, after which *every* `@parent/`
  endorsement on the child fails closed, even with a valid unexpired
  attestation; `__withdraw_genesis__` is the sovereign-only counterpart.
  The off-chain proof of severance is the signed tombstone (Recipe 12's
  subject).
- *The bridge stays tip-verified in both directions*: the only cross-machine
  mechanism is the parent's attestation/tombstone signature, verified
  against the TIP of the child's accepted parent-key chain — a retired
  parent key verifies nothing.

## Try it

### crabs-wasm (browser / Node / edge)

Charter → spawn → manifest → refusal of a double-mint → dissolve →
attest-refusal → the signed tombstone, with the tombstone's exact byte layout
verified inline. The wasm binding returns the child as an opaque borrowed
pointer (the parent's resident registry owns it) — the subgroup's *inside*
story is the node section's demo.

```snippet:wasm/11-subgroups-without-escalation.js
```

### crabs-node (native Node.js)

Same flow, plus the subgroup's *inside* story — the node binding hands back a
full `Node` wrapper over the borrowed machine, so the isolation assertions
(registry separation, blueprint-scoped items, a subgroup member refusing on
the parent) and the "attenuation is the initial grant" honesty assertion
(`child.defineItem`) run for real. Blueprint construction/serialization is
synchronous on this binding.

```snippet:node/11-subgroups-without-escalation.js
```

### C (native)

The parent-side flow straight through the C engine: blueprint build +
validate, direct spawn, fresh-authority assertions (own attribute machine,
own MSK, parent binding pinned), duplicate-child refusal, dissolve through
the signed op pipeline, manifest + attest honesty checks.

```snippet:c/11-subgroups-without-escalation.c
```

## What it guarantees / what it doesn't

Guaranteed (everything below is executed by the snippets):

- *The subgroup's starting authority is the charter, verified.* Spawn
  accepts only blueprints that pass full structural validation and applies
  exactly the blueprint's items and policies to the fresh machine.
- *Subgroup members resolve nowhere on the parent.* The delegated child
  resolves ops through its own registry; the node snippet registers `clerk`
  in the subgroup, lands a `view` op on the child, and watches the same
  signer's op refuse `unauthorized` on the parent. The reverse holds too:
  the parent's `operator` does not appear in the subgroup registry.
- *The bridge out of the subgroup is parent-issued and tip-verified.* Every
  cross-machine credential is the parent's signature over a chain-tipped
  key version — a retired parent key verifies nothing. A subgroup cannot
  mint its own endorsements.
- *The parent's teeth are real teeth.* Dissolve is instant and durable,
  attest refuses for anything not ACTIVE, a duplicate mint is
  `duplicate_operation`, and sovereign children cannot be dissolved into a
  lesser state at all.

Not guaranteed — because attenuation is not a cage:

- *Can't-reach-up is not can't-grow.* After spawn, the subgroup's admin
  runs a *complete* machine: minting items, registering members, granting
  roles within its own domain — the node snippet demonstrates this on
  purpose (`child.defineItem('side-ledger')` succeeds). Nothing in `src/`
  restricts a spawned child's future self-governance. If the subgroup admin
  is untrustworthy within the subgroup, that failure is *confined* to the
  subgroup — and the parent's severance is the response.
- *The subgroup's bootstrap admin is parent-anchored.* A delegated child's
  genesis admin is registered in the child with the PARENT's node *public*
  key — the machine that minted the child vouches for its admin, and only
  the parent-key holder can act as that admin at genesis. "The subgroup is
  independent" is a matter of the parent handing over key custody
  out-of-band, which no library call does.
- *Dissolve does not reach into the subgroup's content.* Severance kills
  the parent bridge and the parent's registry slot; the child machine
  itself outlives the dissolve (both smokes demonstrate a functioning
  machine after severance).
- *Depth is not capped.* A subgroup can spawn its own subgroups; each
  machine caps its children at 64 and the parent-key chain per child at 8
  entries, but no lineage-depth limit exists — deep forests are a
  protocol-author concern.

## Variations

- *Shared authority on purpose*: when the subgroup is a department counter
  rather than an isolation boundary, `SHARED_ROOT` deliberately borrows the
  parent's registry and MSK — the right shape for shared, the wrong shape
  for isolation. The deny-then-grant flow in `test/test_lineage.cpp:965-988`
  is the tested pattern (a parent-granted `custody:<child>` attribute
  authorizes a shared child's op).
- *Sovereign minting*: when the parent wants to *seed* a subgroup and end
  its stake, `__withdraw_genesis__` stops attestations and ends the lineage
  without dissolution — and the dissolve op refuses sovereign children
  outright.
- *Blueprint policy scoping*: when a charter policy needs authority that
  resolves against the parent, it may use `@parent/<attr>` endorsement
  tokens — that machinery is Recipe 12's subject.
- *Watch the mint*: to observe subgroups appearing, `on('change')` emits a
  `spawn`-kind event attributed to the parent's node identity.

## Verified against the code

<!-- PROVENANCE
target: all-bindings
blueprint:
  machine_blueprint_t + append helpers src/Lineage/lineage.h:106-159
  (blueprint_add_item_with_domain :147-153 — sovereign items in charters)
  structural validation src/Lineage/lineage.h:161-182
  wire format v2, body cap :41-50; stampHash verifies embedded SHA-256
  bindings/wasm/index.d.ts:138-152 · node :176-194
  wasm Blueprint API: addItem :138 · addPolicy :140 · stampHash :142 ·
  serialize :144 · destroy :146 · Blueprint.create :150 · deserialize :151
  node Blueprint API: addItem :178 · addPolicy :180 · stampHash :182 ·
  serialize :184 · new (wire) :191 · create :192 · deserialize :194
  blueprint hash = integrity, NOT authenticity (a tamperer with the body
  can re-stamp the hash; provenance comes from the signed __spawn_machine__
  op) src/Lineage/lineage.h:212-214
trust modes src/Lineage/lineage.h:327-345:
  SHARED_ROOT borrows parent attr machine + MSK src/Lineage/lineage.c:1451-1455
  DELEGATED_COPY fresh CP-ABE authority + own registry src/Lineage/lineage.c:1472-1480
  SOVEREIGN withdraw-only (no dissolve) src/Lineage/lineage.h:523-524, 608-614
spawn:
  validated-then-committed (append after full build) src/Lineage/lineage.h:350-356
  duplicate-id + parent's-own-id refusals src/Lineage/lineage.c:1424-1447
  (a child naming itself like its parent is refused too)
  children cap CRABS_MAX_CHILD_MACHINES src/CRABS/data_model.h:391 (64)
  parent-key chain cap 8 entries src/Lineage/lineage.h:254
  resident-children registry anchors child lifetime src/Lineage/lineage.h:387-403
manifest reads:
  wasm childCount/childIndex/childById/children bindings/wasm/index.d.ts:750-757
  node lineageChildren bindings/node/index.d.ts:564 (ChildManifestEntry :197-204)
teeth (installed ops, role:admin defaults, overridable via state_add_policy):
  lineage_install src/Lineage/lineage.h:480-501 (idempotent;
    test/test_lineage.cpp:1926-1930)
  __revoke_attestation__ — stops vouching, live attestations run out TTL
    src/Lineage/lineage.h:516-520; handler src/Lineage/lineage.c:1752-1777
  __dissolve_machine__ — durable lineage_parent_dissolved flag, set
    src/Lineage/lineage.c:1807; after it, every @parent/ endorsement on the
    child fails closed even with a valid unexpired attestation
    src/StateMachine/state_machine.c:703-712
  __withdraw_genesis__ — sovereign-only withdrawal
  dissolve refuses only an already-DISSOLVED entry (re-dissolve);
    sovereign + withdrawn children refused outright
bridge (tip-verified):
  parent-key chain verification — retired key verifies nothing
    src/Lineage/lineage.h:643-656
  genesis admin registered with the PARENT's node public key
    src/Lineage/lineage.c:1472-1476
dissolve-after-revoke legality (revoke-then-dissolve is legal; the
  dissolve handler honors lineage.h:514-520's "dissolution stays available"):
  pinned by test/test_lineage.cpp DissolveAfterRevokeIsLegal + the wasm
  snippet's late dissolve

target: crabs-wasm (snippet wasm/11-subgroups-without-escalation.js)
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:774
  Node.setTime              bindings/wasm/index.d.ts:711
  Blueprint.addItem         bindings/wasm/index.d.ts:138
  Blueprint.addPolicy       bindings/wasm/index.d.ts:140
  Blueprint.stampHash       bindings/wasm/index.d.ts:142
  Blueprint.serialize       bindings/wasm/index.d.ts:144
  Blueprint.destroy         bindings/wasm/index.d.ts:146
  Blueprint.create          bindings/wasm/index.d.ts:150
  Blueprint.deserialize     bindings/wasm/index.d.ts:151
  Node.lineageInstall       bindings/wasm/index.d.ts:744
  Node.lineageSpawn         bindings/wasm/index.d.ts:746 (opaque borrowed
                            C pointer — the resident registry owns the child)
  Node.lineageResidentChild bindings/wasm/index.d.ts:748
  childCount/childIndex/childById/children bindings/wasm/index.d.ts:750-757
  Node.attest               bindings/wasm/index.d.ts:759
  Node.lineageTombstone     bindings/wasm/index.d.ts:764
  (spawn trust modes)       src/Lineage/lineage.c:1451-1480
  (append-after-full-build) src/Lineage/lineage.h:350-356
  (refusals)                src/Lineage/lineage.c:1424-1447
  (dissolve severance)      src/Lineage/lineage.c:1807 + src/StateMachine/state_machine.c:703-712
maturity: all STABLE
test_ref: bindings/wasm/lineage_smoke.mjs:32-198

target: crabs-node (snippet node/11-subgroups-without-escalation.js)
verified: executed
symbols:
  new Node                  bindings/node/index.d.ts:641-643
  Node.setTime              bindings/node/index.d.ts:536
  Blueprint.addItem         bindings/node/index.d.ts:178
  Blueprint.addPolicy       bindings/node/index.d.ts:180
  Blueprint.serialize       bindings/node/index.d.ts:184
  Blueprint.create          bindings/node/index.d.ts:192
  Blueprint.deserialize     bindings/node/index.d.ts:194
  Node.lineageInstall       bindings/node/index.d.ts:556
  Node.lineageSpawn         bindings/node/index.d.ts:562 (full borrowed
                            Node wrapper — the inside-the-subgroup story)
  Node.lineageChildren      bindings/node/index.d.ts:564
  Node.lineageResidentChild bindings/node/index.d.ts:566
  Node.lineageAttest        bindings/node/index.d.ts:572
  Node.registerUser/grantRole bindings/node/index.d.ts:304-305
  Node.defineItem           bindings/node/index.d.ts:363-364
  Node.getUser/getCounter   bindings/node/index.d.ts:311 / :383
  (fresh authority)         src/Lineage/lineage.c:1472-1480
  (dissolve severance)      src/Lineage/lineage.c:1807 + src/StateMachine/state_machine.c:703-712
maturity: all STABLE
test_ref: bindings/node/lineage_smoke.mjs:45-245 + bindings/node/test/test.js:132-185

target: native-c (snippet c/11-subgroups-without-escalation.c)
verified: executed
symbols:
  machine_blueprint_create       src/Lineage/lineage.h:126
  blueprint_add_item/policy      src/Lineage/lineage.h:134-156
  lineage_blueprint_validate     src/Lineage/lineage.h:182
  lineage_spawn_machine          src/Lineage/lineage.h:383-385
  lineage_query_children         src/Lineage/lineage.h:419-420
  lineage_query_resident_child   src/Lineage/lineage.h:392-393
  lineage_install                src/Lineage/lineage.h:501
  CRABS_LINEAGE_OP_DISSOLVE      src/Lineage/lineage.h:486
  crabs_issue_attestation        src/Lineage/lineage.h:680-685
  CRABS_MAX_CHILD_MACHINES       src/CRABS/data_model.h:391
maturity: all STABLE
test_ref: test/test_lineage.cpp:885-1163 (trust modes, duplicate ids) + :1930-2043 (op pipeline)

spawn-watch: on('change') emits a `spawn`-kind change event attributed to
  the parent's node identity (test/test_lineage.cpp:892-963)
-->