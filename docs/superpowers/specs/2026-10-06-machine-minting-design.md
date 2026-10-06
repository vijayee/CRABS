# Machine Minting (Sub-State Machines & Lineage) — Design

Date: 2026-10-06
Status: Approved for implementation planning

## Summary

CRABS machines can mint child machines. A parent state machine executes a
`__spawn_machine__` operation whose payload is a fully serializable
`machine_blueprint_t`; the parent records the spawned child in a
`child_manifest[]` living inside its own `state_t`. Three trust modes govern
the parent/child custody relationship, and one mechanism — signed cross-domain
attestations — bridges all of them. All machines become fully serializable
("smart contracts as data"): users, keys, op-type definitions, child manifests,
and the CP-ABE MSK (vault-encrypted at rest).

## Motivation

The Attribute Machine already uses the MSK to mint *keys*
(crypto_abe_keygen); this design extends the idea so machines mint
*machines*. The protocol spec (§630) already declares other machines
"reference" the Attribute Machine as root of trust, but no mechanism exists
for that reference — this closes the gap. The target use case is minting
whole protocols: a parent machine that authors and supervises sub-protocols
with distinct custody semantics.

## Requirements (from brainstorm)

1. All three custody semantics must be expressible, individually and in
   combination:
   - **Authority delegation** — child ops authorize only via parent-issued
     credentials; parent revocation freezes the child.
   - **Data isolation** — child CRDT items, locks, logs, and policies live in
     a separate namespace, not the parent's.
   - **Full sovereignty** — child runs its own trust root; parent retains
     provenance only.
2. Durable across restarts with identical authority. All CRABS machines are
   serializable end-to-end.
3. Full parent-side lineage: spawn, inspect, revoke attestation authority,
   dissolve, withdraw genesis.
4. Delegation crosses MSK domains via short-lived, parent-signed attribute
   attestations (not shared keys) — chosen as the single general bridge.
5. First milestone is full stack: library API + built-in ops + CLI + wasm
   bindings + devtools lineage UI.
6. Legacy (v9) serialized machines upgrade to v10 with a deterministic
   re-enrollment path (`crabs machine migrate`).

## Architecture

New module `src/Lineage/` (`lineage.h` / `lineage.c`), organized like the
other semantic directories (`Attribute/`, `Trigger/`, ...).

### Child manifest (parent state)

```c
typedef enum {
  LINEAGE_SHARED_ROOT      = 0,   // child binds to parent's attribute machine
  LINEAGE_DELEGATED_COPY   = 1,   // child gets fresh MSK minted by parent
  LINEAGE_SOVEREIGN        = 2    // child generates its own MSK
} lineage_trust_mode_e;

typedef enum {
  LINEAGE_ACTIVE    = 0,
  LINEAGE_DISSOLVED = 1,   // tombstone issued (non-sovereign only)
  LINEAGE_WITHDRAWN = 2    // genesis attestation removed (sovereign only)
} lineage_status_e;

typedef struct {
  char                 child_id[CRABS_MAX_USER_ID];
  lineage_trust_mode_e mode;
  uint8_t              genesis_snapshot_hash[32];  // SHA-256 of child's
                                                   // signed genesis snapshot
  uint8_t              genesis_attestation_signature[CRABS_SIG_SIZE];
  uint64_t             attestation_ttl_ms;
  uint64_t             spawned_at;
  lineage_status_e     status;
} child_manifest_entry_t;

#define CRABS_MAX_CHILD_MACHINES 64
```

The manifest is an array inside `state_t` (like `triggers[]`), so lineage is
parent state and serializes with it. The runtime live-registry of child
handles is process-local and rebuilt on load: child state files are read,
their genesis re-verified against the parent's manifest signature, then the
child handles activate.

### Spawn interface

`__spawn_machine__` is a **custom (non-builtin) op** registered like other
custom ops: policy created via the `__define_operation_type__` flow, handler
via `state_machine_register_handler`. Authorization (ABE policy, key
staleness, scheme allowlist, co-signatures) applies uniformly.

Built-in-lineage ops (provided by the Lineage module as ready-made handler +
policy pairs, registered as custom ops so authorization applies to each):

| Op                       | Purpose                                             |
|--------------------------|-----------------------------------------------------|
| `__spawn_machine__`      | Instantiate child from blueprint; append manifest.  |
| `__revoke_attestation__` | Parent stops issuing attestations for a child.      |
| `__dissolve_machine__`   | Parent-signed tombstone halts a delegated child.    |
| `__withdraw_genesis__`   | Sovereign-only: remove genesis attestation.         |

Read-only lineage access is API-first (`lineage_query_children`); the CLI and
devtools surface the same data.

## Trust profiles

- **SHARED_ROOT** — child's `state->attr_machine` points at the parent's
  attribute machine. One MSK, one users registry. Child users carry a
  required `custody:<child_id>` attribute, admin-granted; the privileged
  attribute blocklist still applies. Revocation at the parent is instant.
- **DELEGATED_COPY** — parent runs `crypto_abe_setup()` for a fresh child
  MSK at spawn and hands over a bootstrapped genesis. Child is self-sufficient
  for its own identities; live parent control arrives only through
  attestations.
- **SOVEREIGN** — child runs `crypto_abe_setup()` itself at genesis. Parent
  attests the genesis snapshot only. Cannot be dissolved;
  `__withdraw_genesis__` removes the parent's attestation from its own
  manifest, breaking lineage proof forward for descendants.

### The attestation bridge

Signed, short-lived, parent-issued attribute attestations — modeled on
`key_envelope_t` (format version 0x01 so it evolves independently of
envelope 0x03):

```
attestation_t {
  format_version = 0x01
  parent_id, child_id, user_id
  attributes[]                 // names + values from parent's registry
  not_before, expires_at       // not_before + ttl <= expires_at
  parent_key_chain             // key chain hashes used to attest
  signature[64]                // parent node ECDSA key
}
```

- Issued by the parent (new API `crabs_issue_attestation`); carried as op
  payload in the child.
- Child-side policy syntax gains `@parent/role:writer` (new token in
  `condition.c` parsing): the child verifies the attestation signature
  against the parent's node key (learned from its genesis snapshot), checks
  `child_id` match and validity window, then treats the covered attributes as
  satisfied for that user.
- Revocation = parent declines to re-sign; enforcement lag bounded by the
  TTL chosen at spawn. A `__dissolve_machine__` tombstone voids outstanding
  attestations immediately for non-sovereign children.

The bridge makes the modes compose: a sovereign child can still require
parent endorsement for specific op types.

## Blueprint payload

```c
typedef struct {
  char                 child_id[CRABS_MAX_USER_ID];
  lineage_trust_mode_e trust_mode;
  char                 bootstrap_admin[CRABS_MAX_USER_ID];
  uint64_t             attestation_ttl_ms;
  data_item_blueprint_t*   items;         // name, type, initial value, protocol state
  policy_blueprint_t*      policies;      // op_type -> ABE expression + scheme
                                          //   set + min_key_version
  op_type_def_blueprint_t* op_type_defs;  // dedup specs for child-defined ops
  uint32_t                 item_count, policy_count, op_type_def_count;
  uint8_t                  blueprint_hash[32];  // stamped at op-build time
} machine_blueprint_t;
```

- Excludes log, live handles, keys, MSK — born at instantiation, not carried.
- The genesis snapshot the parent attests is the serialized *empty* child
  state built from the blueprint, so provenance is over actual bytes.
- Validation reuses existing guards: `_is_safe_user_id` charset, privileged
  attribute blocklist, policy parsing via `condition.c`, dedup-spec rules.
  Failed validation returns before anything is minted.
- Limits: `CRABS_MAX_CHILD_MACHINES` on the manifest; config knobs cap
  items/policies per blueprint (DoS bound).

## Lifecycle semantics

- **Spawn**: blueprint validated, child instantiated per mode, manifest
  appended (only after successful instantiation — failed spawns leave no
  residue), child persisted to `machine-<child_id>.crabs`, change-hook event
  with new kinds `SPAWN` / `LINEAGE`.
- **Revoke attestation**: manifest marks the child as no longer attested;
  outstanding attestations ride out their TTL.
- **Dissolve**: parent signs a tombstone. SHARED_ROOT/DELEGATED_COPY
  children fail authorization on their next op (dissolved-parent => local
  attestations void immediately); manifest flips to DISSOLVED. Sovereign
  children cannot be dissolved — `CRABS_ERR_NOT_PERMITTED`.
- **Withdraw genesis**: sovereign-only; removes parent's attestation from
  its own manifest; forward lineage proof (grandchild chains) breaks.

Nothing crashes on lineage problems: any failed verification is a failed op
surfacing through the existing error enum.

## Serialization & durability (format v10)

- `crabs_serialize_state` bumps to **v10** with new sections: users + key
  registry (ABE and ECDSA per-user keys), `op_type_defs` (fixes the existing
  gap where the dedup registry does not persist), `child_manifest[]`.
- **MSK serialization**: new `master_key_serialize` / `master_key_deserialize`
  in `crypto.c`. At rest, MSK blobs are encrypted via the existing vault
  config; a machine with a vault configured persists the MSK on save;
  without a vault, the serializer refuses to persist an MSK (fail loud,
  never plaintext-MSK-on-disk).
- **Child persistence**: each child is its own state file
  (`machine-<child_id>.crabs`); the parent holds only the manifest. On load,
  runtime rebuilds child handles and re-verifies genesis against the manifest
  signature before activation.
- `key_envelope_t` stays 0x03; the new attestation format starts at 0x01.

## Migration (v9 → v10)

- v10 readers accept v9 files: absent sections restore empty (users, keys,
  op_type_defs, child manifest); a fresh MSK is generated. The machine comes
  up substrate-only and re-builds authority by re-enrollment — exactly today's
  `cli_node_load` behavior, now made deterministic and explicit.
- CLI `crabs machine migrate <legacy.crabs>` walks the rebuild: bootstrap
  admin → register users → grant attributes → `__refresh_abe_key__`.
- One-way, versioned: v10 never writes v9 files. Upgraded machines start
  with an empty lineage manifest and can spawn immediately.

Live post-deployment attribute additions need no migration: `register_user` /
`grant_role` / `__refresh_abe_key__` already re-mint credentials with new
attribute strings, and `min_key_version` forces the fleet forward. For
deployed machines the "translation" of old authorization format into new
attributes is re-enrollment, not a byte transform — v9 never carried
authority data to translate.

## Exposure surfaces

- **CLI**: `crabs machine spawn <child_id> <blueprint.cbp>` /
  `machine children` / `machine dissolve <id>` / `machine migrate
  <legacy.crabs>` — each maps 1:1 to a lineage op or the migration walk.
- **Wasm**: `crabs_blueprint_validate`, `crabs_spawn_machine`,
  `crabs_lineage_children`, `crabs_issue_attestation` — results cross the
  boundary as serialized bytes (same transport as `crabs_serialize_state`).
- **Devtools**: state-tree panel gains a **Lineage section** — parent/child
  tree rendered from the manifest, keyed by `child_id` (same pattern as the
  existing state-tree keying), with per-child status badges (ACTIVE /
  DISSOLVED / WITHDRAWN), attestation TTL countdowns, and child panels
  expandable via the existing state-inspector view. Spawn/revoke events flow
  through the existing change-hook pipeline (`SPAWN` / `LINEAGE` kinds), so
  the inspector updates live.

## Error handling

All lineage failures flow through the existing `crabs_error_e` enum; no new
global failure modes. Blueprint validation errors return before minting.
Failed spawns leave no manifest residue (manifest append commits only after
successful instantiation). Dissolve of a sovereign child returns
`CRABS_ERR_NOT_PERMITTED`.

## Testing

- **Unit**: blueprint validation negatives (unsafe ids, privileged attrs,
  malformed policies, over-limit counts); MSK serialize/deserialize
  round-trip; attestation sign/verify/expiry/`child_id`-mismatch/void-on-
  dissolve; v9→v10 migration gate.
- **Integration**: full custody lifecycle per mode — spawn under all three
  profiles, child op authorized, parent revokes attestation → child op fails
  after TTL (sovereign) / instantly (shared root); dissolve tombstone
  propagation; restart round-trip: spawn → save → reload → child still
  authorized, manifest intact, genesis re-verified against parent signature.
- **Wasm smoke**: spawn + inspect via bindings; devtools lineage section
  renders the tree.

## Trust-model caveat (README)

Delegation means a compromised parent can mint arbitrarily many
"legitimate" children, and cross-domain attestations carry trust only until
expiry. The README trust-boundary section must state: (1) the parent is the
provenance root for its descendants' custody chains; (2) SHARED_ROOT couples
parent and child identities by definition; (3) attested (cross-MSK) trust is
bounded by TTL lag, not by instant revocation; (4) sovereign children have no
parent control beyond provenance.