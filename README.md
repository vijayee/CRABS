<p align="center">
  <img src="Encryptstacean.png" alt="Encryptstacean" width="400">
</p>

# CRABS: Cryptographic Attribute-Based State Machines

**A C implementation of the CRABS protocol — self-sovereign attribute-based authorization with convergent state.**

---

## What is CRABS?

CRABS (Cryptographic Attribute-Based State machines) is a protocol that unifies **Attribute-Based Encryption (ABE)**, **Conflict-free Replicated Data Types (CRDTs)**, **Operational Transformation (OT)**, and **protocol state machines** into a single framework for decentralized authorization.

The key insight: **attributes are not keys — attributes are state**. The set of all users and their attributes is the state of a protocol-governed state machine (the Attribute Machine). Changing an attribute is a state transition governed by protocol rules, not a central authority. ABE keys are derived from the current state and become invalid when the state changes.

## Features

- **Attribute Machine** — Self-sovereign identity layer where attributes are protocol-governed state
- **OT/CRDT Hybrid Types** — Ordered sets, rich documents, and tree structures with move, swap, and intent-preserving merge
- **Threshold Triggers** — State-conditional attribute issuance that bridges dynamic state with cryptographic access
- **Cryptographic Agility** — Pluggable signature scheme interface (ECDSA, Ed25519, BLS, Dilithium, Falcon)
- **Idempotent Operations** — Declarative dedup specifications (`PER_USER`, `GLOBAL`, `CUSTOM`) with CRDT-safe convergence
- **Resource Locking Protocol** — Atomic multi-resource locking with timeout-based liveness guarantees
- **Key Versioning** — ABE keys derived from state versions with automatic invalidation on state changes
- **Unified Tombstone Compaction** — Vector-clock-safe garbage collection across all CRDT types
- **Dual Privacy Modes** — Mode A (auditable, signer identified) and Mode B (privacy-preserving, signer anonymous)

## Project Structure

```
├── src/
│   ├── CRABS/         Core protocol definitions and data model
│   ├── Attribute/     Attribute Machine implementation
│   ├── StateMachine/  Protocol state machine execution engine
│   ├── CRDT/          Basic CRDT types (G-Counter, PN-Counter, OR-Set, LWW-Register, RGA)
│   ├── OT/            OT/CRDT hybrid types (OT_ORDERED_SET, OT_DOCUMENT, OT_TREE)
│   ├── Crypto/        Cryptographic primitives and pluggable signature schemes
│   ├── Trigger/       Threshold triggers and condition evaluation
│   ├── Dedup/         Idempotent operation tracking (ONE_SHOT_SET, ONE_SHOT_FLAG)
│   ├── Compaction/    Unified tombstone management and vector clock safety checks
│   ├── Serialization/ Binary serialization with backward compatibility
│   ├── Condition/     Condition language parser and AST evaluator
│   ├── CLI/           Command-line interface and REPL
│   ├── Buffer/        Memory buffer management
│   ├── RefCounter/    Reference counting primitives
│   └── Util/          Utility functions
├── test/              Test suite
├── docs/              Style guide and documentation
```

## Building

### Prerequisites

- CMake 3.22+
- OpenSSL development libraries
- C11-capable compiler

### Build

```bash
mkdir build && cd build
cmake ..
make
```

### Run

```bash
./crabs_node
```

This starts the CRABS CLI with an interactive REPL for managing state machines, users, policies, and operations.

### Tests

```bash
cd build
ctest
```

## Protocol Specifications

| Document | Description |
|---|---|
| [CRABS Protocol Specification](./docs/CRABS%20Protocol%20Specification.md) | Core protocol specification (v1.5) |
| [Amendment 1](./docs/CRABS%20Protocol%20Specification%20v1.1%20Amendment%201.md) | State machine execution and locking protocol |
| [Amendment 2](./docs/CRABS%20Protocol%20Specification%20v1.2%20Amendment%202.md) | CRDT merge rules and type system |
| [Amendment 3](./docs/CRABS%20Protocol%20Specification%20v1.3%20Amendment%203.md) | OT/CRDT hybrid types |
| [Amendment 4](./docs/CRABS%20Protocol%20Specification%20v1.4%20Amendment%204.md) | Idempotent operations and dedup |
| [Amendment 5](./docs/CRABS%20Protocol%20Specification%20v1.5.2%20Amendment%205.md) | Tombstone compaction |

## Research Papers

- [CRABS (Short Paper)](./docs/CRABS.md) — Core protocol, algorithms, and security analysis
- [CRABS (Extended)](./docs/CRABS%20Extended.md) — OT/CRDT hybrids, threshold triggers, cryptographic agility, and compaction
- [CRABS.pdf](./docs/CRABS.pdf) — Short paper in LaTeX PDF format
- [CRABS_Extended.pdf](./docs/CRABS_Extended.pdf) — Extended paper in LaTeX PDF format

## Use Cases

- **Decentralized Autonomous Organizations (DAOs)** — Membership by attributes, not token holdings
- **Collaborative Content Platforms** — Tamper-proof metrics, threshold-gated moderation, OT/CRDT editing
- **Self-Sovereign Identity** — User-controlled attributes with verifier attestation and audit trail
- **Supply Chain Management** — Protocol-governed custody transfers across organizations

## Machine Minting (CLI)

A lineage-eligible machine can mint child machines from **blueprints**: a
parent vouches for a child's genesis, keeps it in a durable child manifest,
signs user attestations across the trust boundary, and ends a lineage through
dissolve or withdrawal. The trust-mode caveats live in the Trust Boundaries
section below.

`crabs machine <subcommand>` group (the child-machine lifecycle surface):

| Command | Effect |
|---|---|
| `machine blueprint new <child_id> <shared\|delegated\|sovereign> <bootstrap_admin> <attestation_ttl_ms>` | Open a machine blueprint draft on this node |
| `machine blueprint item <name> <data_type> <crdt_type>` | Append a replicated data item to the draft |
| `machine blueprint policy <operation> <expression>` | Append an authorization policy to the draft |
| `machine blueprint dedup <op_type> <dedup_type> [tracker_path\|flag_path\|condition] [rejection_message]` | Append an operation type definition (dedup: `none`, `per_user`, `global`, `custom`) |
| `machine blueprint save <file.cbp>` | Validate the draft and write the `.cbp` wire file |
| `machine blueprint validate <file.cbp>` | Validate a saved blueprint file (wire hash + structure) |
| `machine blueprint drop` | Discard the current draft |
| `machine spawn <file.cbp>` | Spawn a child machine (real `__spawn_machine__` op through the pipeline) |
| `machine children` | List the child manifest: mode, status, residency, attestation TTL |
| `machine attest <child_id> <user_id> <attributes>` | Mint and print a parent-signed, TTL-bounded attestation wire |
| `machine tombstone <child_id>` | Print the parent-signed dissolution tombstone wire for a DISSOLVED child (off-chain transport material; refuses a non-dissolved child) |
| `machine accept-tombstone <file>` | Deliver a tombstone hex file to THIS machine (real `__receive_dissolution__` op): verify the parent signature and durably sever the parent lineage |
| `machine dissolve <child_id>` | Dissolve a non-sovereign child (real `__dissolve_machine__` op) |
| `machine withdraw <child_id>` | Withdraw a sovereign child's genesis stake (real `__withdraw_genesis__` op) |
| `machine revoke-attestation <child_id>` | Stop issuing attestations for a child (real `__revoke_attestation__` op) |

The blueprint authoring commands are draft editing and never touch machine
state; spawn, dissolve, withdraw, revoke-attestation, and accept-tombstone are
signed operations through the same pipeline as `op submit`. The lineage op
handlers are runtime registrations on the machine (`lineage_install` in the
library/wasm path): after `crabs load-sealed` restores a saved machine, the
spawning protocol re-installs the lineage ops on the reloaded machine before
the lifecycle commands can act — the CLI refuses those commands loudly
otherwise.

A minimal spawn flow:

```bash
crabs seal-key import <seal.key>
crabs machine blueprint new child-red delegated child-admin 3600000
crabs machine blueprint item counter counter g_counter
crabs machine blueprint policy increment role:admin
crabs machine blueprint dedup increment none
crabs machine blueprint save /tmp/child-red.cbp
crabs machine spawn /tmp/child-red.cbp
crabs machine children
crabs machine attest child-red child-admin role:writer   # prints the wire hex
crabs machine dissolve child-red
crabs machine tombstone child-red                        # prints the tombstone hex
```

**Ending a lineage across processes.** Dissolving a child severs the lineage
in the parent's manifest immediately, but a child machine running in another
process learns of the severance only when the tombstone reaches it: the
parent operator runs `machine tombstone <child_id>` and hands the printed hex
to the child operator (out-of-band, like the attestation wire), who writes it
to a file and runs `machine accept-tombstone <file>` on the child machine.
The op verifies the tombstone's embedded parent ECDSA signature against the
persisted parent public key — carriage by the child admin authorizes nothing
about its content — and the dissolved state is durable across the child's own
save/reload, fail-closing every `@parent/` endorsement afterwards. A
re-delivery is refused as already-performed.
```

### Wasm lineage exports

The wasm module carries the same lineage surface (registered in
`build_wasm.sh`, both variants), with the JS wrappers living in
`bindings/wasm/bindings-core.js` (`Blueprint`, `Node.children/attest/...`):

- `crabs_wasm_register_lineage_ops` — registers the four lineage ops +
  default admin policies on a machine (`lineage_install`)
- Blueprint family — `crabs_wasm_lineage_blueprint_new` / `_add_item` /
  `_add_policy` / `_stamp_hash` / `_serialize` / `_deserialize` / `_destroy`
- Spawn family — `crabs_wasm_lineage_spawn` (child pointers are borrowed;
  the parent's resident-children registry anchors their lifetime),
  `crabs_wasm_lineage_query_resident_child`
- Manifest family — `crabs_wasm_lineage_children_count` / `_children_get_id`
  / `_get_mode` / `_get_status` / `_get_ttl_ms` / `_get_spawned_at` /
  `_find_manifest_entry`
- `crabs_wasm_lineage_attest` — issues a parent-signed attestation and
  returns its transport wire bytes

## Trust Boundaries: What Is Durable and What Is Not

Serialization v10 changes what a saved machine carries. A snapshot now holds the **full authority** of the machine: its users, key registries, operation-type definitions, and the CP-ABE master secret key (MSK). Restoring a snapshot restores the machine's authority as well as its state — which makes how that authority is protected the most important trust boundary in the system.

**The MSK never touches disk unsealed.** Saving a machine requires an operator-supplied AES-256-GCM seal key; saving without one is refused. Loading is symmetrical: `crabs load-sealed <path> <keyfile>` decrypts the snapshot with the seal key and restores the machine, MSK included.

**What happens when the seal key is wrong or absent:** the machine substrate (users, registries, operation types) is restored with a **fresh MSK**. This is a deliberately degraded state — the machine runs, but its authority is unproven. Treat post-fresh-MSK signatures as untrusted and re-enroll from the genesis admin via `crabs state migrate` rather than assuming the restored state was legitimately authorized.

**The seal key is the machine's crown jewel.** It lives in memory only — it is never persisted — and anyone holding both a snapshot and its seal key holds full authority over that machine. Protect the seal key accordingly.

**Sealing is confidentiality, not provenance.** Unsigned snapshots remain unauthenticated even in v10: the seal protects what is on disk, not who produced it. `key import` still verifies saved snapshots before trusting them.

**Legacy v9 snapshots** load with an empty registry (no users carried over). Run `crabs state migrate` after loading to re-enroll the bootstrap admin.

### Machine Minting and Lineage

Spawning child machines extends the trust boundary across machines, not just within one.

**The parent is the provenance root for its descendants' custody chains.** A parent machine holds full authority over its manifest of children and signs every child's genesis attestation. A compromised parent can mint arbitrarily many children that are, by every verifiable marker in the system, legitimate. Defending the parent node key and the parent snapshot is defending the supply chain of everything it spawns.

**SHARED_ROOT couples parent and child identities by definition.** A shared-root child runs on one attribute registry and one MSK — the parent's. There is no boundary to police between them: revoking a shared-attribute endorsement on the parent stops the child's authorization instantly, but the parent has (and needs) full custody of the child's authority. That single registry is an in-process invariant — each process holds its own machine copy, and reconciling shared-root authority across a reloaded parent/child pair is future work, not part of this design.

**Attested (cross-MSK) trust is bounded by TTL lag, not instant revocation.** Delegated and sovereign children run their own authority and ride on the parent's attestation, which carries a TTL. A revoked attestation only takes effect when the child's verification re-checks it or the TTL expires — a determined child can ride out a stale attestation until expiry. In-process severance happens immediately on a `dissolve` (tombstone) for resident children; a dissolved-but-distant child learns of the severance only once its operator hands it the parent's tombstone (`machine accept-tombstone` above) — until that delivery lands, treat attestation expiry, not dissolve delivery, as the guaranteed upper bound on cross-MSK trust for a detached child.

**Sovereign children are beyond parent control — beyond provenance.** The parent may not dissolve a sovereign child; the only lineage op that still applies is `__withdraw_genesis__`, which retracts the parent's genesis attestation from its own manifest. A withdrawn parent no longer vouches for the child, but the child's own authority is unaffected.

## License

MIT

---

<p align="center">
  <img src="Unlockster.png" alt="Unlockster" width="250">
</p>

<p align="center">
  <i>CRABS: Hard shell. Sharp pincers. No backdoors.</i>
</p>
