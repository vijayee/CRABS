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
## Intent

A group machine needs subgroups: a billing team, a support desk, a regional
chapter. Each subgroup should get the capabilities its charter names — a few
items, a few policies, its own roster — and the group's authority should not
leak into it, nor the subgroup's out to the group. "Can't escalate" has to
mean something specific here, so the requirement, stated exactly:

- the subgroup's *initial* authority is exactly the charter (a Blueprint) the
  parent machine minted — not whatever anyone asks for later;
- subgroup members resolve *nowhere* on the parent: being `role:member` in
  the subgroup authorizes nothing on the group machine;
- the parent keeps *real* teeth over what it minted: it can stop vouching,
  and it can sever the tie outright, durably, on evidence of its own decision.

## The naive version, and where it breaks

The naive version models subgroups as *role namespaces on one machine*: a
`billing` role, a policy `AND role:billing`, done. Three things break at once.
First, there is no attenuation to audit — the parent's admin can retune any
billing policy at any moment, and "billing" members are members of the whole
machine; nothing bounds what a billing policy can address. Second, the
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

## The shape

- *The charter is a Blueprint* — a serializable machine definition the parent
  authors before minting: item set, policy set, bootstrap admin, attestation
  TTL (`Blueprint.create` / `addItem` / `addPolicy` / `stampHash` /
  `serialize`, `bindings/wasm/index.d.ts:66-81`, node
  `bindings/node/index.d.ts:80-102`; C type `machine_blueprint_t` +
  append helpers, `src/Lineage/lineage.h:106-159`). `stampHash` +
  `deserialize` verify the embedded SHA-256 on the wire image — the exact
  bytes a `__spawn_machine__` op transports (format v2, body cap
  `src/Lineage/lineage.h:41-50`).
- *Trust modes pick the authority story* (`src/Lineage/lineage.h:327-345`):
  `SHARED_ROOT` — the child deliberately **borrows** the parent's attribute
  machine and MSK, one registry serves both (`src/Lineage/lineage.c:1451-1455`);
  `DELEGATED_COPY` — a **fresh** CP-ABE authority is minted, the child's auth
  pipeline resolves users through its own registry
  (`src/Lineage/lineage.c:1472-1480`); `SOVEREIGN` — constructed like
  delegated copy, but recorded as lineage-sovereign in the parent's manifest:
  the parent may only *withdraw* its genesis stake, never dissolve
  (`src/Lineage/lineage.h:523-524, 608-614`).
- *Spawn is validated, then committed atomically in the manifest*: duplicate
  child ids (and the parent's own machine id) are refused; the manifest
  entry is appended only after the child is fully built, so every failure
  leaves no residue (`src/Lineage/lineage.h:350-356`; refusals at
  `src/Lineage/lineage.c:1424-1447`; the children cap is
  `CRABS_MAX_CHILD_MACHINES`, `src/CRABS/data_model.h:391`).
- *The manifest is the parent's track record*: entries carry
  childId/mode/status/ttl (`childCount`…`children`, wasm
  `bindings/wasm/index.d.ts:348-355`; node `lineageChildren`,
  `bindings/node/index.d.ts:292`).
- *The teeth are lineage ops through the normal pipeline* —
  `lineageInstall` registers the six `__…__` op types, each policy
  `role:admin` by default and overridable (`src/Lineage/lineage.h:480-501`):
  `__revoke_attestation__` stops vouching without dissolution (live
  attestations run out their TTL, `src/Lineage/lineage.h:516-520`);
  `__dissolve_machine__` severs — it durably sets the child's
  `lineage_parent_dissolved` flag, after which *every* `@parent/` endorsement
  on the child fails closed, even with a valid unexpired attestation
  (`src/StateMachine/state_machine.c:703-712`, set at
  `src/Lineage/lineage.c:1807`); `__withdraw_genesis__` is the sovereign-only
  counterpart. The off-chain proof of severance is the signed tombstone
  (Recipe 12's subject).

## What it guarantees / what it doesn't

Guaranteed (everything below is executed by the snippets):

- *The subgroup's starting authority is the charter, verified.* Spawn accepts
  only blueprints that pass full structural validation — safe ids, legal
  trust mode, parseable policy expressions, unique item names, caps
  (`src/Lineage/lineage.h:161-182`) — and applies exactly the blueprint's
  items and policies to the fresh machine (`src/Lineage/lineage.c:1472-1480`;
  the snippets read `score` = 0 on the child and nothing else before the
  child's own admin acts).
- *Subgroup members resolve nowhere on the parent.* The delegated child
  resolves ops through its own registry (`src/Lineage/lineage.c:1479-1480`);
  the node snippet registers `clerk` in the subgroup, lands a `view` op on
  the child, and watches the same signer's op refuse `unauthorized` on the
  parent. The reverse holds too: the parent's `operator` does not appear in
  the subgroup's registry (`child.getUser` assertions).
- *The bridge out of the subgroup is parent-issued and tip-verified.* The
  only cross-machine mechanism is the parent's attestation/tombstone
  signature, verified against the TIP of the child's accepted parent-key
  chain — a retired parent key verifies nothing
  (`src/Lineage/lineage.h:643-656`). A subgroup cannot mint its own
  endorsements.
- *The parent's teeth are real teeth.* Dissolve is instant and durable
  (`src/StateMachine/state_machine.c:703-712`), attest refuses for anything
  not ACTIVE, a duplicate mint is `duplicate_operation`, and sovereign
  children cannot be dissolved into a lesser state at all.

Not guaranteed — and this is the load-bearing honesty of the recipe's title:

- *"Can't escalate" means can't reach up — not can't grow.* After spawn,
  the subgroup's admin runs a *complete* machine: it can mint more items,
  register members, and grant roles *within its own domain* — the node
  snippet demonstrates this on purpose (`child.defineItem('side-ledger')`
  succeeds). Nothing in `src/` restricts a spawned child's future
  self-governance; attenuation is the initial grant, not a sandbox. If the
  subgroup admin is untrustworthy within the subgroup, that failure is
  *confined* to the subgroup — that is the guarantee, and the parent's
  severance is the response.
- *The subgroup's bootstrap admin is parent-anchored.* A delegated child's
  genesis admin is registered in the child with the PARENT's node *public*
  key — the machine that minted the child vouches for its admin, and only
  the parent-key holder can act as that admin at genesis
  (`src/Lineage/lineage.c:1472-1476`). "The subgroup is independent" is a
  matter of the parent handing over key custody out-of-band, which no
  library call does.
- *Dissolve does not reach into the subgroup's content.* Severance kills the
  parent bridge and the parent's registry slot; the child machine itself
  outlives the dissolve (the wasm smoke's tombstone gates and the node
  smoke's `already_performed` re-delivery refusal both demonstrate a
  functioning machine after severance).
- *Depth is not capped.* A subgroup can spawn its own subgroups; each
  machine caps its children at 64 (`src/CRABS/data_model.h:391`) and the
  parent-key chain per child at 8 entries (`src/Lineage/lineage.h:254`), but
  no lineage-depth limit exists — deep forests are a protocol-author concern.

## Variations

- *Shared authority on purpose*: `SHARED_ROOT` subgroups deliberately borrow
  the parent's registry and MSK (`src/Lineage/lineage.c:1451-1455`) — the
  right shape for "a department counter", the wrong shape for isolation. The
  deny-then-grant flow in `test/test_lineage.cpp:965-988` is the tested
  pattern (a parent-granted `custody:<child>` attribute authorizes a shared
  child's op).
- *Sovereign minting*: the parent's stake in a subgroup it only wants to
  *seed* is recovered via `__withdraw_genesis__` — attestations stop, the
  lineage ends without dissolution (`src/Lineage/lineage.h:608-614`); the
  dissolve op refuses sovereign children outright
  (`src/Lineage/lineage.h:523-524`).
- *Blueprint policy scoping*: a blueprint policy may use `@parent/<attr>`
  endorsement tokens — authority that resolves against the parent's
  attestations, not the subgroup's own registry (`src/Lineage/lineage.h:89-104`,
  tested `test/test_lineage.cpp:144-180`). That machinery is Recipe 12's
  subject.
- *Watch the mint*: `on('change')` emits a `spawn`-kind event attributed to
  the parent's node identity (`test/test_lineage.cpp:892-963`).

## Recipe

### crabs-wasm (browser / Node / edge)

Charter → spawn → manifest → refusal of a double-mint → dissolve →
attest-refusal → the signed tombstone, with the tombstone's exact byte layout
verified inline. The wasm binding returns the child as an opaque borrowed
pointer (the parent's resident registry owns it) — the subgroup's *inside*
story is the node section's demo.

```snippet:wasm/11-subgroups-without-escalation.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:372
  Node.setTime              bindings/wasm/index.d.ts:309
  Blueprint.create          bindings/wasm/index.d.ts:79-81
  Blueprint.addItem         bindings/wasm/index.d.ts:68
  Blueprint.addPolicy       bindings/wasm/index.d.ts:70
  Blueprint.stampHash       bindings/wasm/index.d.ts:72
  Blueprint.serialize       bindings/wasm/index.d.ts:74
  Blueprint.deserialize     bindings/wasm/index.d.ts:81
  Blueprint.destroy         bindings/wasm/index.d.ts:75
  Node.lineageInstall       bindings/wasm/index.d.ts:342
  Node.lineageSpawn         bindings/wasm/index.d.ts:344
  Node.lineageResidentChild bindings/wasm/index.d.ts:346
  childCount/childIndex/childById/children bindings/wasm/index.d.ts:348-355
  Node.attest               bindings/wasm/index.d.ts:357
  Node.lineageTombstone     bindings/wasm/index.d.ts:358-362
  (spawn trust modes)       src/Lineage/lineage.c:1451-1480
  (append-after-full-build) src/Lineage/lineage.h:350-356
  (refusals)                src/Lineage/lineage.c:1424-1447
  (dissolve severance)      src/Lineage/lineage.c:1807 + src/StateMachine/state_machine.c:703-712
maturity: all STABLE
test_ref: bindings/wasm/lineage_smoke.mjs:32-198
-->

### crabs-node (native Node.js)

Same flow, plus the subgroup's *inside* story — the node binding hands back a
full `Node` wrapper over the borrowed machine, so the isolation assertions
(registry separation, blueprint-scoped items, a subgroup member refusing on
the parent) and the "attenuation is the initial grant" honesty assertion
(`child.defineItem`) run for real. Blueprint construction/serialization is
synchronous on this binding.

```snippet:node/11-subgroups-without-escalation.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  new Node                  bindings/node/index.d.ts:312
  Node.setTime              bindings/node/index.d.ts:264
  Blueprint.create          bindings/node/index.d.ts:100
  Blueprint.serialize       bindings/node/index.d.ts:92
  Blueprint.deserialize     bindings/node/index.d.ts:102
  Node.lineageInstall       bindings/node/index.d.ts:284
  Node.lineageSpawn         bindings/node/index.d.ts:290
  Node.lineageChildren      bindings/node/index.d.ts:292
  Node.lineageResidentChild bindings/node/index.d.ts:294
  Node.lineageAttest        bindings/node/index.d.ts:300
  Node.registerUser/grantRole bindings/node/index.d.ts:182-183
  Node.defineItem           bindings/node/index.d.ts:205-206
  Node.getUser/getCounter   bindings/node/index.d.ts:189,224
  (fresh authority)         src/Lineage/lineage.c:1472-1480
  (dissolve severance)      src/Lineage/lineage.c:1807 + src/StateMachine/state_machine.c:703-712
maturity: all STABLE
test_ref: bindings/node/lineage_smoke.mjs:45-245 + bindings/node/test/test.js:132-185
-->

### C (native)

The parent-side flow straight through the C engine: blueprint build +
validate, direct spawn, fresh-authority assertions (own attribute machine,
own MSK, parent binding pinned), duplicate-child refusal, dissolve through
the signed op pipeline, manifest + attest honesty checks.

```snippet:c/11-subgroups-without-escalation.c
```

<!-- PROVENANCE
target: native-c
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
-->

## Notes

- *Wasm vs node on the child pointer*: wasm's `lineageSpawn` returns an
  opaque borrowed C pointer and only the flat manifest accessors
  (`:348-355`); node returns a full `Node` wrapper and `lineageChildren()`
  (`:290-294`). The machine ownership story is identical in C — the parent's
  resident-children registry anchors the child's lifetime
  (`src/Lineage/lineage.h:387-403`).
- *Why duplicate ids matter*: the parent's manifest is the lineage's ledger;
  a double-mint would make "which subgroup is which" ambiguous. Both the
  live children AND the parent's own machine id are protected
  (`src/Lineage/lineage.c:1431-1445`) — and a spawned child naming itself
  like its parent is refused the same way, so a grandchild cannot shadow its
  parent's identity.
- *`lineageInstall` is idempotent and overridable*: it registers the six
  lineage ops with `role:admin` defaults; a protocol author can replace any
  of them with `state_add_policy` afterwards (`src/Lineage/lineage.h:495-501`,
  tested `test/test_lineage.cpp:1926-1930`).
- *The blueprint hash is integrity, not authenticity*: `deserialize`
  verifies the embedded SHA-256 and the structure, but a tamperer with the
  body can re-stamp the hash — provenance comes from the signed
  `__spawn_machine__` op, not from this hash
  (`src/Lineage/lineage.h:212-214`).
- *Where "can't escalate" ends*: the parent cannot *un-attenuate from
  outside* a subgroup it no longer trusts — the teeth are severance-shaped
  (revoke/dissolve/withdraw), not "dial back the subgroup's power" shaped.
  There is no op that edits a live child's charter; a subgroup whose charter
  is wrong is dissolved and re-spawned.