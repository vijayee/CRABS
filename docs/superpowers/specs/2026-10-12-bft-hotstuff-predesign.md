# BFT Ordering: HotStuff Pre-Design Note

**Date:** 2026-10-12
**Status:** Pre-design — recorded commitment; implementation deferred until a Byzantine-replica deployment story exists (see Decision triggers).

## Why this note exists

Crash-tolerant Raft (landed 2026-10-12) is honest about its boundary, and the README trust caveat states it: it handles crashed replicas, not lying ones. A compromised ordering replica — a rogue leader that drives two different logs to quorum, or a rogue replica that double-votes across competing quorums — is out of crash-Raft's scope. If CRABS deployments ever put an uncontrolled signer set on the ordering committee, a BFT module earns its cost. This note records the analysis NOW so the choice is principled later.

## Candidate comparison

| Protocol | Structure vs this reactor | Complexity | Notes |
|---|---|---|---|
| PBFT (classic) | three-phase, quadratic prepare phase, view-change dance | highest | historic fit; log mapping poor |
| Tendermint | round-robin proposers, quorum votes per round | high | rotation mitigates leader DoS; different commit shape |
| **HotStuff family** (chosen) | leader-based, pipelined votes → quorum certificates, log-shaped | moderate | "PBFT's safety, Raft's structure, linear message cost" |

**Chosen: two-chain/chained HotStuff** — leader-based like Raft; each phase collects signed votes into a **quorum certificate (QC)**; certificates chain commits; proposers rotate per view. It maps onto the landed reactor nearly 1:1: AppendEntries phases → vote/QC phases; election timeouts → view timeouts; persistence of log entries → persistence of QCs; log matching → QC-chain validation. Linear message cost and a simple safety argument (QC chain) make it the only BFT candidate worth its effort here.

## Prerequisites already in place

1. **Accountable equivocation punishment** — BFT requires catching rogues with self-evidencing proof. CRABS's sovereign-item fork quarantine (duplicate `(item_seq, prev_item_digest)` signed claims, `__report_equivocation__`) is that primitive; a BFT module consuming it needs a module-level variant (duplicate votes/duplicate proposals under one replica id → the same evidence shape, publishable in the module's op-adjacent log).
2. **Deterministic simulation harness** — partitions, message faults, slow hosts all scripted in C. BFT adds an "equivocating node" fault role to the same scripts; harness carries over untouched.
3. **Two-phase pipeline + ordered retry shelf** — the commit-stream semantics are identical for any log-indexed protocol.

## Prerequisite step: vtable formalization (`ordering_module_ops_t`)

Today's wiring is Raft-named (`state_attach_raft_module`, direct calls). Before any second module exists, formalize the swappable interface — a small refactor, zero pipeline changes:

```c
typedef struct ordering_module_ops_t {
  uint8_t      module_id;         // protocol identity; see naming below
  const char*  name;
  crabs_error_e (*propose)(void* module, const operation_t* op, uint64_t* proposal_id);
  bool          (*poll_outbound)(void* module, ordering_outbound_message_t* out);     // TRANSFER ON POLL
  bool          (*poll_persist)(void* module, ordering_persist_request_t* out);       // view; handle stays open
  bool          (*poll_notification)(void* module, ordering_notification_t* out);     // module-own queue = sole commit source
  crabs_error_e (*persist_complete)(void* module, uint64_t handle, bool ok);
  crabs_error_e (*recover_from_persist)(void* module, const uint8_t* batch, size_t len);
  bool          (*can_propose)(void* module, const char* user_id);
  uint64_t      (*committed_tip)(void* module);
  void*         (*export_state)(void* module);           /* module section carrier */
  crabs_error_e (*import_state)(void* module, const uint8_t* bytes, size_t len);
  void          (*destroy)(void* module);
} ordering_module_ops_t;
```

- `state_t` stores `{ordering_module_ops_t const* ops; void* module;}` instead of the raft pointer; `state_attach_raft_module` generalizes to attach-by-ops.
- Drain/notification kinds rename to ordering-neutral identities with a shared kind enum; payloads carry `module_id`.
- Raft becomes the first implementation of the table; the deterministic sim harness and all scenarios keep running through it.
- **Naming:** `BFT` is a fault class, not a protocol — the spec's `BFT=0x03` module-id slot should name `HOTSTUFF=0x03` (recorded here as the controller decision).
- Message marshaling stays opaque to hosts; the blob interface is protocol-agnostic already.

## Integration notes (HotStuff specifics)

- `can_propose` rule: current view's leader OR any replica holding a valid QC to the view tip (two-chain responsive variant).
- Commit stream: QCs chained; commit notification identical (log-indexed, monotone exactly-once semantics carry over).
- Module state section: term/view, last QC, pending QCs, replica table (rotation = a module-config choice per view), joint-consensus membership carry-over.
- Leader-DoS (censoring proposer): rotation per view is HotStuff's default answer; if a deployment needs stronger liveness under targeted censorship, Tendermint-style rotation is a config alternative — recorded, not designed.
- Log bound/refusal + growth-model notes carry over unchanged.

## Decision triggers (when to implement)

- A deployment story materializes where the ordering committee includes signers outside the operator's control (multi-org machine replication, validator-set machines).
- OR: a consumer asks for validator-style machines explicitly.

## Deliberately out of scope of this note

Light-client proofs; production-readiness claims; any estimate beyond "P2-class effort" (the landed Raft phase is the reference); Tendermint/BFT-Raft alternatives beyond the rotation note.