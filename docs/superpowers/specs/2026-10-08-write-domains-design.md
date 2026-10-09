# Write Domains: Per-Item Ownership, Ordering Election, and Merge Guarantees — Design

**Date:** 2026-10-08 (revised same day against current code: state format v13, full-consumption reader, lineage key chain)
**Status:** Proposed design

## Summary

Every data item in a CRABS machine belongs to exactly one **write domain**,
declared at definition time:

| Class | Writers | Ordering | Merge behavior |
|---|---|---|---|
| `SOVEREIGN` | one registered writer | writer's hash-chained sequence | fork = self-signed fraud proof → quarantine |
| `GROUP-ORDERED` | elected writer set | attached ordering module (Raft/CFT/BFT) | merge defers to module's committed log |
| `FREE-MERGE` | any authorized writer | CRDT/OT semantics | type merge / transform matrix (A5) |

The domain is metadata plus three rules: a validation rule in the execution
pipeline, a merge-dispatch rule in `crdt_merge`, and (for `SOVEREIGN`) an
equivocation-detection rule. No new crypto, no new network machinery.

## Motivation

The guarantee set of every prior amendment is domain-relative, but the
domain it assumed has been implicit:

- **Amendment 4 §11.2** already admits the dedup guard is eventual, not
  strict, under partition — "the window for concurrent votes is very small;
  the count may be off by 1 in rare cases." That is a *free-merge* result.
  The same `DedupSpec` on a sovereign item is strict: the writer's own
  sequence totally orders their operations, so the guard cannot race.
- **Timed transactions** (2026-09-03) documented clock-skew divergence —
  "two nodes can resolve the same schedule differently" — as acceptable
  because the affected items converge via CRDT merge. On a group-ordered
  item, that divergence is *unacceptable by definition* and must be routed
  through the ordering module instead.
- **Machine minting** (2026-10-06) made blueprints the unit of protocol
  definition, and blueprints are exactly where domain declarations belong.

This document makes the taxonomy explicit so that each feature's guarantee
is stated against the class it actually provides, and so applications
(account-model ledgers, guild treasuries, collaborative documents) can
*elect* ordering per item instead of inheriting a global one.

The governing sentence: **applications that share no machine share no
fate; within a machine, fate is scoped by item domain.**

## Decisions made

- **Domain is per-item, declared at creation, immutable in v1.** Changes of
  domain on a live item are out of scope (would require re-homing the item's
  log history); the escape hatch is define-new-item + migrate.
- **Machines carry a default domain** (default: `FREE-MERGE` — zero
  behavioral change for all existing machines and all pre-v14 serialized
  states).
- **Ordering modules are pluggable, following the Amendment 3 VTable
  pattern** (the signature-scheme registry precedent). A machine attaches
  at most one ordering module; it governs exactly the `GROUP-ORDERED` items
  of that machine and nothing else.
- **Sovereign equivocation is detection + quarantine, never adjudication.**
  A fork is two ops from the same writer with the same per-item sequence
  number and different resulting digests — incontrovertible, publishable,
  self-verifying evidence. Quarantine reuses the Amendment 4
  `ONE_SHOT_SET` machinery.
- **Cross-domain operations are allowed.** Each item enforces its own
  domain rule; atomicity across domains remains the transaction manager's
  (lock protocol's) job, unchanged.

## Data model

```c
typedef enum {
  CRABS_DOMAIN_FREE_MERGE    = 0x00,   // default; existing semantics
  CRABS_DOMAIN_SOVEREIGN     = 0x01,   // single registered writer
  CRABS_DOMAIN_GROUP_ORDERED = 0x02    // attached ordering module
} crabs_write_domain_e;

// data_item_t gains:
  crabs_write_domain_e write_domain;            // 0 on machines from pre-v14 states
  char     writer[CRABS_MAX_USER_ID];           // SOVEREIGN only; owner of the item ("" otherwise)
  uint64_t item_seq;                            // SOVEREIGN: writer-assigned monotonic sequence, starts 1
  uint8_t  item_digest[CRABS_HASH_SIZE];        // SOVEREIGN: SHA-256 of the item state after item_seq
                                                //   (zeroed when item_seq == 0)
  uint8_t  ordering_module;                     // GROUP_ORDERED: module id (0 = unset)
  // Quarantine (SOVEREIGN): fork evidence accumulated for this item.
  // Stored per item, capped; entries are the evidence digest pairs produced
  // by DETECT_EQUIVOCATION. Non-empty ⇒ writes by the flag writer rejected.
  uint8_t  fork_writers[CRABS_MAX_FORK_WRITERS][CRABS_MAX_USER_ID];
  uint8_t  fork_evidence_digests[CRABS_MAX_FORK_WRITERS][CRABS_HASH_SIZE];
  uint32_t fork_count;                          // ≤ CRABS_MAX_FORK_WRITERS
```

- `machine_blueprint_t`'s `data_item_blueprint_t` gains `write_domain`,
  `writer`, `ordering_module` (minting, 2026-10-06); blueprint wire format
  version bumps in the same step (blueprint bodies are hash-stamped; the
  stamp covers the new fields).
- `MachineConfig` gains `default_write_domain` (default `FREE_MERGE`).
- Serialization bumps to **v14** (current is 13): new per-item fields, all
  reads/writes gated on `version >= 14`. Pre-v14 states load as
  all-`FREE_MERGE` — additive fields with a zero default, no semantic
  change on upgrade. The state reader's full-consumption check (payload
  must be exactly consumed before the checksum) holds: the v14 gated
  sections consume exactly what the v14 writer emits, exactly as the
  v11→v12→v13 additions did.

## Sovereign op payload envelope

`DOMAIN_CHECK` needs `item_seq` and `prev_item_digest` from the op — and
payload formats are application-defined, so an application-specific payload
convention cannot be trusted to start with them. Sovereign ops therefore
carry a **mandatory reserved prefix** on the wire:

```c
// Wire envelope for every operation whose resources include a SOVEREIGN
// item. The prefix is written by the op serializer next to resources (not
// inside the application payload), so DOMAIN_CHECK is implementable for
// every payload format.
typedef struct {
  uint64_t item_seq;                      // expected: == item.item_seq
  uint8_t  prev_item_digest[CRABS_HASH_SIZE];  // expected: == item.item_digest
} crabs_sovereign_op_prefix_t;
// operation_t gains a per-resource array of these (capacity already
// CRABS_MAX_RESOURCES); the signing canonical form covers them;
// CRABS_OP_FORMAT_VERSION bumps (6) because the signed field set grows.
```

The signing canonical form must include the prefixes (signing format v3 →
v4, version byte bump): otherwise a writer could sign one op and rewire it
with a different `item_seq` prefix — the same rewind-to-strip class the
v3 bump closed for `op_version`.

## Ordering module interface (GROUP-ORDERED)

Consensus is composed, never embedded — a module is attached per machine
like a signature scheme is registered per node:

```c
typedef struct crabs_ordering_module {
    uint8_t     module_id;        // RAFT=0x01, CFT=0x02, BFT=0x03, CUSTOM≥0xF0
    const char *name;
    // Propose an op touching GROUP_ORDERED items; the module assigns the
    // authoritative position in the committed log.
    int (*propose)(state_t *state, operation_t *op,
                   uint64_t *committed_index /* out */);
    // Latest index the module has durably committed.
    uint64_t (*committed_tip)(state_t *state);
    // Whether this node may propose (leader / quorum member).
    bool (*can_propose)(state_t *state, const char *user_id);
} crabs_ordering_module_t;
```

- Module membership is expressed as attributes on the machine
  (`role:sequencer AND epoch:N`), so election and rotation ride the
  existing attribute machine — no separate membership machinery.
- A machine's `GROUP-ORDERED` items may be written **only** through
  the module's `propose` path. Direct local application is rejected
  (`CRABS_ERR_ORDERING_PATH`).
- Merge of a `GROUP-ORDERED` item: adopt the highest committed prefix;
  hold (do not apply) any uncommitted ops received via replication. CRDT
  replication still carries ops for audit; ordering authority is the
  module's.
- **Partition behavior is the feature:** when the module's quorum is
  unavailable, `GROUP-ORDERED` items halt writes *and only those items*.
  `FREE-MERGE` and `SOVEREIGN` items on the same machine keep moving.
  This is the separation-of-concerns property, enforced structurally
  rather than by operational discipline.
- **v1 scope: interface only.** No reference module ships in v1; the
  error table below already defines the fail-closed behavior (unregistered
  module id at load → group items read-only). Reference Raft/CFT/BFT
  modules as mintable machine templates are **future work** — the design
  intentionally leaves an empty-but-honest seam rather than a bespoke
  consensus implementation.

## SOVEREIGN items

### Writer binding

- `writer` binds a `user_id` (key rotation rides the Amendment 3 key
  registry; the binding is to the user, not a specific key).
- Every op touching a sovereign item carries the item's current
  `item_seq` + `prev_item_digest` in the reserved prefix above. On
  success, `item_seq += 1` and `item_digest` updates (digest computed over
  the item's post-op serialized form — the same shape the existing item
  serialization produces). The writer's ops on the item form a totally
  ordered, hash-chained subsequence of the audit log.

### Execution pipeline change

New pipeline step after the dedup guard (A4 §5.1 step 5), before handler:

```
Algorithm: DOMAIN_CHECK

for each item in op.resources:
  switch item.write_domain:
    case SOVEREIGN:
      if op.signer_id is empty:                  return NOT_ITEM_WRITER   // Mode B: unattributable
      if op.signer_id != item.writer:            return NOT_ITEM_WRITER
      if op.item_seq != item.item_seq:           return SEQ_MISMATCH
      if op.prev_item_digest != item.item_digest: return FORK_DETECTED   // § EQUVOCATION
      if writer is quarantined:                  return QUARANTINED      // checks first, cheap
    case GROUP_ORDERED:
      if not in_module_propose_path:             return ORDERING_PATH
    case FREE_MERGE:
      continue
```

**Triggers and effects touching sovereign items:** an effect that applies an
op to a `SOVEREIGN` item is rejected at the trigger-installer boundary — a
trigger may only be created if none of its effects touch an item this
creator is not the writer of (checked at `__create_trigger__` time;
re-checked at fire time since the writer binding... writer binding is
immutable in v1, so the create-time check suffices). This keeps trigger
effects inside the writer's authority instead of inventing a second
signing identity for effects.

### Equivocation detection and quarantine

A dishonest writer can only fork their *own* chain: two signed ops with
the same `item_seq` and different digests. The evidence convicts itself.

```
Algorithm: DETECT_EQUIVOCATION

Input:  T   — accepted op on sovereign item I by writer W
        T'  — prior op in log, T'.writer == W, T'.item_seq == T.item_seq,
              T'.digest != T.digest

1. construct report op __report_equivocation__:
     payload:  { item: I, writer: W, op_a: bytes(T'), op_b: bytes(T) }
     handler verifies BOTH signatures, seq equality, digest mismatch
2. on handler success, dedup mutation (A4) appends
     { W : SHA256(T' ‖ T) } to item.forks         (capped evidence list)
3. DOMAIN_CHECK rejects any later op by W touching I while
   item.forks contains W                          (QUARANTINED)
```

- Evidence verification happens **inside the handler**, so the flag is
  only set when the proof checks out. The `(T', T)` bytes travel in the
  log as durable `__equivocation_reported__` entries; any node verifies
  without trusting the reporter.
- `item.forks` appends are monotone (union-only, capped). A partition can
  delay quarantine but cannot forge it — false positives are impossible
  because the entry is honored only with attached, re-verified evidence.
- Both branches are retained in the log as evidence; neither branch's
  effects on the sovereign item are silently discarded — the application
  resolves content policy (the substrate's job ends at attribution).
- Quarantine is reversible only by application policy (v1: no un-quarantine
  op; the cap bounds griefing). Fork detection also fires at merge time —
  see the merge dispatch below — and cross-machine replication of the
  fork set follows normal item convergence... `fork_writers`/
  `fork_evidence_digests` merge as a monotone union (largest set wins);
  the full `(T', T)` op bytes stay in the log, so a replica that only
  merged digests can pull the evidence from its log when needed.

### Mode B caveat

Signer omission (privacy mode) is incompatible with the sovereignty check
by definition: the writer must be attributable. `SOVEREIGN` items require
Mode A signing. Documented, not configurable.

## GROUP-ORDERED items

As above: writes only via the module's committed log; merge adopts the
committed prefix. The atomic multi-resource lock protocol is unchanged and
remains the mechanism for atomicity *across* domains; note that under
partition a lock's strictness is the strictest participating domain —
locks spanning a partitioned group can wait, and that waiting is the
correct, scoped failure.

Reference modules (Raft/CFT/BFT) as mintable machine templates are future
work (see the v1 scope decision above).

## FREE-MERGE items (default)

Unchanged: Amendment 5 type merge and transform matrix, Amendment 1
trigger evaluation per node, Amendment 4 guards eventual as documented in
§11.2. This class remains correct for collaborative, non-scarce state:
documents, sets, feeds, profiles, content moderation queues.

## Where existing features sit

| Feature | Doc | SOVEREIGN | GROUP-ORDERED | FREE-MERGE |
|---|---|---|---|---|
| Triggers | A1 | effects bound to the writer (create-time check) | evaluate on committed state only | per-node, converge (as today) |
| CONTAINS policies | A2 | reads writer's view | reads committed view | reads local view |
| Sig agility | A3 | orthogonal — all domains | | |
| DedupSpec guards | A4 | **strict** (writer total order) | **strict once committed** | eventual (A4 §11.2 race stands) |
| OT/CRDT types | A5 | usable; writer serializes by construction | optional; forfeits offline editing | native home |
| HLC ordering | A6 | display/debug; chain is authoritative | advisory; module log authoritative | ordering as today |
| Timed transactions | 2026-09-03 | only writer's schedules | propose materialization through module | skew divergence caveat stands |
| Locks / tx manager | base spec | writer self-consistent | strict within committed view | FCFS as today |
| Minting / lineage | 2026-10-06 | blueprint declares domains; machine default; child custody unchanged | | |
| Key chain (2026-10-07) | | orthogonal — writer keys rotate via the A3 registry | | |

## Merge dispatch

`crdt_merge` gains a per-item dispatch before type merge:

```
Algorithm: CRDT_MERGE (domains)

for each (name, item_b) in state_b.items:
  item_a = merged.items[name]
  switch item_a.write_domain:
    case SOVEREIGN:
      if chains continue cleanly: accept item_b if ahead
      else (fork): retain both branches as evidence; merge fork sets
                   (monotone union); surface FORK_DETECTED
    case GROUP_ORDERED:
      adopt committed prefix from module log; hold uncommitted ops
    case FREE_MERGE:
      existing type-merge / transform (A5)
```

## API surface

- **C:** `crabs_define_item(..., .write_domain, .writer, .ordering_module)`;
  `crabs_register_ordering_module`; `crabs_report_equivocation`;
  `state_item_domain()`.
- **Bindings:** `node.defineItem(name, type, { domain: 'sovereign', writer })`;
  `node.reportEquivocation(item)`; `pendingSchedules`/snapshot rows gain
  `domain` (additive).
- **CLI:** `crabs machine spawn` blueprint files carry the new fields;
  `machine children` unchanged; `item info <name>` shows domain, writer,
  seq, module.
- **Devtools:** State tab renders a domain pill per item
  (`sovereign` / `group` / `free`); sovereign items show seq + digest head;
  a **Forks** section lists quarantined writers with verify-on-click
  evidence. All additive — devtools reads event-drain/snapshot views and
  never parses wire formats, so existing tooling stays compatible.

## Error handling

| Situation | Behavior |
|---|---|
| Op on sovereign item from non-writer / Mode B op | `CRABS_ERR_NOT_ITEM_WRITER` |
| Writer quarantined on that item | `CRABS_ERR_QUARANTINED` |
| Stale/duplicate `item_seq` | `CRABS_ERR_SEQ_MISMATCH` |
| Digest mismatch with same seq (fork) | `CRABS_ERR_FORK_DETECTED` → `__report_equivocation__` path |
| Direct apply to group-ordered item | `CRABS_ERR_ORDERING_PATH` (use module propose) |
| Equivocation report with unverifiable evidence | handler fails; flag **not** set; report rejected |
| Module quorum unavailable | propose fails; other domains unaffected |
| Unknown ordering module id at load | load succeeds; group items read-only until module registered |
| Quota: evidence fork Writers exceed cap | merge union truncated; report op still admitted (log is authoritative); DOMAIN_CHECK honors what is present |

## Security considerations

- **Sovereign writer key compromise** cedes the item (sovereignty is
  custody). Key rotation (A3) restores forward control; fork evidence and
  chain history are unaffected because the chain is content-hashed.
- **Quarantine is evidence-based local enforcement, not adjudication.**
  There is no vote on whether a fork happened — the signatures are the
  fact. Applications choose the consequence policy beyond op rejection.
- **A group-ordered module's participant set *is* its failure domain,**
  deliberately: the blast radius of a halt is exactly that machine's
  group-ordered items. Nothing else inherits it — including other items
  on the same machine.
- **Sybil resistance remains external-by-design** (per base spec §5.1):
  sovereignty binds one *user*, and who maps to one person is the
  attribute machine's enrollment policy, not the substrate's.
- **Signing-form versions move again** (v3 → v4, sovereign prefixes are
  signed). Pre-v4 signatures stop verifying — same pre-release posture as
  the v3 bump. Wire `CRABS_OP_FORMAT_VERSION` also bumps (5 → 6), since
  the per-resource sovereign prefix is a new v6 section.

## Testing

- **Native:** per-class op validation (writer match, seq continuity,
  module path); fork fabrication rejected; genuine fork → flag set,
  evidence verifies, later ops rejected; merge dispatch per class;
  partition test — group items halt, sovereign/free items proceed on the
  same machine; pre-v14 load preserves all-FREE-MERGE.
- **Cross-binding:** `lineage_smoke`-style parity test — sovereign machine
  minted, writer ops accepted, non-writer rejected, fork reported — must
  pass identically in `crabs-node` and `crabs-wasm` (extend
  `CROSS_PLATFORM_AUDIT.md`).
- **WASM smoke + demo:** p2p video platform gains one sovereign item
  (per-user counter signed only by its owner) alongside the existing
  free-merge items; devtools shows both pills in two tabs.
- **Guarantee regression test:** Amendment 4 §13.6 (concurrent same-user
  vote) run under `FREE_MERGE` (eventual) and under `SOVEREIGN`/
  `GROUP_ORDERED` (strict) — asserting *different* outcomes per class is
  the test that the taxonomy is real.

## Out of scope (v1)

- Domain changes on live items (define-new + migrate instead).
- Cross-machine atomic commit beyond the existing lock protocol.
- Light-client proofs for domain state.
- Global total order anywhere, for anything, ever.
- Reference ordering modules (Raft/CFT/BFT) — interface only in v1.
- Un-quarantine ops (no application policy surface for forks yet).

## Trust-model caveat (README)

The README trust-boundary section must state: (1) a sovereign item is only
as safe as its writer's key — sovereignty is custody, and compromise is
total for that item alone; (2) equivocation quarantine stops *future*
damage but does not rewrite signed history — history is evidence;
(3) group-ordered items inherit the liveness of their elected module —
that coupling is the price of strictness and it is chosen per item;
(4) free-merge guarantees are exactly those of A4 §11.2 — eventual,
never strict.
## As implemented (v1)

- **Fork fact = duplicate signed claim, not divergent result digests.** The
  §"Equivocation detection" sketch compared post-op resulting digests. As
  landed, the convictable fact is the *signed duplicate claim*: two
  DISTINCT serialized ops from the same writer naming the same sovereign
  item with EQUAL `(item_seq, prev_item_digest)` prefixes in their signed
  v6 sections — two signed claims to be the one continuation of the same
  chain head. Resulting-digest comparison would require re-executing
  evidence; the duplicate claim is verifiable from the signatures alone.
- **Evidence-key resolution = the writer's current key era.** Both evidence
  ops must verify under the writer's CURRENT keyring (Mode A, empty
  policy). A fork committed under a since-rotated key does not verify and
  cannot convict — historical-era fork adjudication is future work (the
  chain itself remains auditable off-band, since it is content-hashed).
- **GROUP_ORDERED is a read-only seam in v1.** A group item mints with
  `ordering_module == 0` (non-zero is refused at creation — no module id
  can resolve); every write path fails closed with
  `CRABS_ERR_ORDERING_PATH` until a module is registered (the module
  interface registration surface is future work, not v1).
- **Merge dispatch** (`CRDT_MERGE`): free items merge as before; sovereign
  chains accept a clean continuation, otherwise convict-by-union
  (replica-deterministic evidence digest: SHA-256 over min‖max of the two
  chain heads — not a shipped report) and withhold; group items hold
  divergences and surface them via the additive `CRABS_CHANGE_MERGE`
  (0x07) event kind (`__merge_held__` et al.).
- **Wire/state versions as shipped:** op format v6 (per-resource sovereign
  prefix section, last on the wire), signing format v4 (prefixes bound,
  field 19 at the end, count byte always written), blueprint body v2
  (leading `CRABS_BLUEPRINT_FORMAT_VERSION` byte), state format v14 for
  the per-item domain fields — and v15 landed on top: struct-backed
  counter/register values serialize their deterministic logical CONTENT
  (counter entries node-sorted; register payload+timestamp+node), which is
  what makes the sovereign chain digest cross-replica comparable at all.
- **v1 sovereign types:** COUNTER and REGISTER only (canonical
  serializations); SOVEREIGN on any other type is `CRABS_ERR_TYPE_MISMATCH`
  at authoring.
- **Fork-set cap:** 16 entries per item (`CRABS_MAX_FORK_WRITERS`),
  inline storage, union-only; a re-report of convicted evidence dedupes to
  `CRABS_ERR_DUPLICATE_OPERATION` (report ≠ a quarantining write, so
  reporting never deadlocks behind a quarantine).
