# JS↔C Binding Parity Fill — Design (round 2)

Date: 2026-10-13
Status: approved in conversation, pending spec review

## Purpose

Round two of the parity program (the audit: `2026-10-13` in-repo report summarized in
conversation; standing goal: JS reaches C capability parity). Nine binding-library
gaps fill, plus binding-to-binding alignment where the divergence is honest noise rather
than a real design statement. Branch `parity-fill` off master, same per-task
implement/review loop as round 1.

## The fill list

**P1. State restore + merge.** `Node.deserialize(bytes)` (wasm has Operation.deserialize
already; state-level is absent BOTH bindings), `Node.mergeState(bytes)` (the general
`crdt_merge_state` path, `crdt_merge.h:131`), and the sealed/signed state serializers
(`crabs_serialize_state_sealed/_keys/_keys_reported/_signed/_sealed_signed`,
serialization.h:55-90) surfaced as options on `Node.serialize({sealed: true | signed:
true, ...})` per what the C signatures support, + matching deserialize/unseal. The OT
ordered-set merge layer (**P5** below) rides through this: `mergeState` gets ordering
items merged by `crabs_ot_ordered_set_merge`. Recipe 8 flips COMPLETE when P1+P5 land.
Trust caveats (a state blob is a full machine; sealed keys story) documented in d.ts.

**P2. Keyring lifecycle.** `Node.suspendKey / activateKey / rotateKey` — C:
`user_key_suspend/activate/rotate` (attribute_machine.h:219-221; tested
test_key_lifecycle.cpp:96,180,269). Rotate follows the C predecessor-chain semantics
(old key revoked, stamps die — CRABS_ERR_KEY_STALE path).

**P3. Admin demotion + user suspension.** `Node.revokeRole` (inverse of grantRole,
attribute_machine.h:147), `Node.suspendUser / activateUser` (:149,:168). The
already-bound revokeUser stays.

**P4. ABE key transport.** `AbeKey.serialize()`/portable envelopes: C
`crypto_abe_user_key_serialize/deserialize` (crypto.h:140,144),
`crypto_master_key_serialize/deserialize` (:156,160), `crypto_key_envelope_*`
(:271-304) — surface: `AbeKey.toWire()` + `Node.abeKeyFromWire(bytes)`, and
`Node.mintKeyEnvelope(...)/decryptKeyEnvelope(...)` mirroring refresh_key's response
materialization (state_machine.c:2797). Secrets discipline: wire staging cleansed
(mirror the A11 rules).

**P5. OT merge layer** (recipe 8's PARTIAL): `crabs_ot_ordered_set_merge` +
`crabs_ot_ordered_set_merge_position_maps` (ot_ordered_set.h:114,117) +
`crabs_bst_merge` (position_map.h:65) — reachable via P1's mergeState AND a
direct item-level `node.mergeOrderedSet(name, fromItemSerialized?)` only if the C API
supports item-level merge transport; otherwise item merge happens inside mergeState
only, and the recipe documents that. Refusals (`_merge_preflight` NULL) stay honest.

**P6. OT document + tree, shipped UNBLESSED.** `crabs_ot_document_*` (RGA;
ot_document.h:79-119), `crabs_ot_tree_*` (ot_tree.h:71-115). `Node.addOTDocument /
addOTTree` + apply/readback, both bindings, marked PRESENT maturity; d.ts + api-map +
recipe 8's variations state: implemented, unbenchmarked — do not build rich text on
it until a benchmark exists (the old 8b facts live as a caveat, not a page).

**P7. Temporary-attribute issuance.** `Node.issueTemporary(attr, value, {roleAudience,
ttlMs})` — `attribute_machine_issue_temporary` (:200); JS only receives temp attrs via
triggers today; prune IS bound. Node parity: node's plain-token readback stays
canonical.

**P8. Lineage extras.** `Blueprint.addItemWithDomain` + blueprint-carried dedup specs
(`blueprint_add_item_with_domain` :147, `blueprint_add_op_type_def` :157);
parent-key rotation (`lineage_key_rotate` + `lineage_child_accept_key_transition`
:285,:318); `attestation_deserialize` (:666) as `Node.attestationFromWire(bytes)`.

**P9. Raft membership.** Wasm has raw change-membership exports
(`crabs_wasm_raft_change_membership`); node gets the module handle + the same surface
(`changeMembership(joint)` + joint/committed_members reads, raft_module.h:222,269-271).

**P10. Binding-to-binding alignment (the no-noise list).**
- node gains: OR-set pagination (`getSetSize/getSetElements/getSetTags`),
  `setRegisterBytes/getRegisterBytes`, `evaluateTriggers`, `Operation.deserialize`,
  BigInt-tolerant integer registers (wasm accepts both; node's "numbers only" note
  becomes "accepts Number and BigInt").
- wasm gains: `selfAssert`, `verifyIdentity`, `getHLC` (all node-only today; C APIs
  exist).
- Deliberately NOT aligned (documented as before): node keeps borrow-style lifetime
  (no Node.destroy — the wrapper story stands); wasm keeps `Node.off` + handler
  surface; node keeps `sign`/`signWithPrivateKey` sugar... (wasm has sign via
  Node/op too; only real divergences get aligned, judged per task).

## Surface rules (same as round 1)

- Every new method: failing binding test first; C gtest only where the C surface
  changes; d.ts updated in the same commit; recipes/api-map re-anchored when their
  claims flip (recipe 8 COMPLETE; recipe 15's C-only-keyring residual narrows; 8b
  caveat lands in recipe 8's content).
- The secrets rule: anything carrying key material stages cleansed, destroys
  idempotent.
- The wasm artifacts regenerate + commit at the phase end (A13 pattern).
- The stale-addon pitfall: after binding merges, main root needs `rm -rf
  bindings/node/build && npm run install`.

## Testing

Per-task: binding tests (both files where both bindings deliver), C suite green,
snippet harnesses green, browser green; per-task reviews (spec + quality) with
adversarial passes on P4 (key envelopes — the new secret transport) and P6 (surface
discipline: no API that implies blessed rich text); end-of-phase full battery + final
review + merge.

## Out of scope

- Benchmark for OT_DOCUMENT (P6 ships PRESENT, the caveat carries).
- Compaction/devtools/sig-scheme internals (INTERNAL rows stand).
- The 2P-SET data type (no add* consts; leave PRESENT/internal).