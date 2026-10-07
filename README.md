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

## Trust Boundaries: What Is Durable and What Is Not

Serialization v10 changes what a saved machine carries. A snapshot now holds the **full authority** of the machine: its users, key registries, operation-type definitions, and the CP-ABE master secret key (MSK). Restoring a snapshot restores the machine's authority as well as its state — which makes how that authority is protected the most important trust boundary in the system.

**The MSK never touches disk unsealed.** Saving a machine requires an operator-supplied AES-256-GCM seal key; saving without one is refused. Loading is symmetrical: `crabs load-sealed <path> <keyfile>` decrypts the snapshot with the seal key and restores the machine, MSK included.

**What happens when the seal key is wrong or absent:** the machine substrate (users, registries, operation types) is restored with a **fresh MSK**. This is a deliberately degraded state — the machine runs, but its authority is unproven. Treat post-fresh-MSK signatures as untrusted and re-enroll from the genesis admin via `crabs state migrate` rather than assuming the restored state was legitimately authorized.

**The seal key is the machine's crown jewel.** It lives in memory only — it is never persisted — and anyone holding both a snapshot and its seal key holds full authority over that machine. Protect the seal key accordingly.

**Sealing is confidentiality, not provenance.** Unsigned snapshots remain unauthenticated even in v10: the seal protects what is on disk, not who produced it. `key import` still verifies saved snapshots before trusting them.

**Legacy v9 snapshots** load with an empty registry (no users carried over). Run `crabs state migrate` after loading to re-enroll the bootstrap admin.

## License

MIT

---

<p align="center">
  <img src="Unlockster.png" alt="Unlockster" width="250">
</p>

<p align="center">
  <i>CRABS: Hard shell. Sharp pincers. No backdoors.</i>
</p>
