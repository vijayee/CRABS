# Machinery Stress + Property Harness (OT/CRDT/merge/compaction) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A seeded-random multi-replica stress harness that stresses the replicated-state machinery (OT documents/sets, CRDT merge, serialization, raft ordering, compaction/tombstone collection) far harder than functional tests do, with four cheap invariant properties wired in so it finds memory-safety bugs AND logic/convergence bugs.

**Architecture:** One new GoogleTest file (`test/test_stress.cpp`) containing (a) a deterministic seeded-RNG session engine that generates adversarial operational histories, and (b) four property assertions evaluated mid-session: replica-convergence content-hash equality, serialization round-trip byte identity, replay determinism, and compacted-vs-uncompacted convergence. Compaction and save/load are first-class randomized events, not afterthoughts. Detector triad: the same harness is executed under the native build, the sanitizer build (`build-san`), valgrind (`build-vg`), and the wasm bundle — each catches a different bug class (native ASan → CRABS UB; valgrind → uninstrumented OpenABE/RELIC; wasm → dlmalloc + different codegen; the 2026-10-15 chase found its root cause exactly this way).

**Tech stack:** C11 core + GoogleTest (existing FetchContent), existing sim harness idioms, existing build dirs (`build`, `build-san`, `build-vg`, wasm via `build_wasm.sh`).

**Build/test commands:**
```bash
cmake --build build -j$(nproc) && ./build/test/testcrabs --gtest_filter='Stress*'
setarch $(uname -m) -R cmake --build build-san -j$(nproc) && setarch $(uname -m) -R ./build-san/test/testcrabs --gtest_filter='Stress*'   # known ASLR startup quirk
setarch $(uname -m) -R cmake --build build-vg -j$(nproc) && valgrind --error-exitcode=9 ./build-vg/test/testcrabs --gtest_filter='Stress.CompactVsUncompactedConvergeAndRestore'
# wasm: source /home/victor/emsdk/emsdk_env.sh && OPENSSL_SRC=/tmp/openssl-3.4.0 bash build_wasm.sh
# then cp build-wasm/crabs.wasm build-wasm/crabs.js bindings/wasm/ (manual artifact copy — build does not)
# then npm --prefix bindings/wasm test   (bare cd does NOT survive background shells; npm --prefix does)
```

**Session-config knobs (env vars, all optional):**
- `CRABS_STRESS_SEED` (uint64, default 1) — master seed; the harness derives per-subtest seeds from it deterministically. On ANY failure, print `[STRESS] seed=<full-derivation> op_index=<n>` as the first line of stderr so a CI crash is one-env-var reproducible.
- `CRABS_STRESS_OPS` (default 4000 in CI mode; extended soak sets it to 50000+).
- `CRABS_STRESS_REPLICAS` (default 3, range 2..5).
- `CRABS_STRESS_COMPACTION_RATE` (default: compact every ~40 ops ± jitter) — compaction is interleaved mid-stream, sometimes against a peer currently OFFLINE.
- `CRABS_STRESS_SAVELOAD_RATE` (default: every ~100 ops) — random save/load round-trip churn.

**Interleaved event model** (every session runs all of them, randomized):
1. Random OT/CRDT ops on each replica (insert/delete/move/swap/split at adversarial positions: end-cluster, offset 0, far-past-end, identical-offset collisions, repeated ids).
2. Partition/heal cycles: a random replica goes offline for R ops (its ops queue), then merges back.
3. Compaction churn mid-stream — including against an OFFLINE peer (the dangerous case the peer_vc gating exists for).
4. Random save/load round-trip of one replica (state blob out, parse back in, keep running).

**The four properties (assert mid-session, not at the end):**
- **P1 Convergence equality** — after every heal/merge round: serialize each replica's state through `crabs_serialize_state` + `crypto_sha256`; all hashes MUST be equal (catches TP1-class divergence like the fixed move/move bug — silent, non-crashing).
- **P2 Round-trip identity** — after every save/load: `serialize(deserialize(serialize(s)))` MUST be byte-identical (catches canonicalization and writer/reader desync).
- **P3 Replay determinism** — a scratch replica built by replaying one replica's log from empty MUST produce the same P1-hash as the original.
- **P4 Compaction safety** — a replica that ran interleaved compaction MUST converge with an uncompacted replica of the same history (no resurrection, no fork), and restore-after-compaction must equal the in-memory pre-compaction state.

---

### Task S1: Seeded session engine + adversarial op generators

**Files:**
- Create: `test/test_stress.cpp` (harness core; all later tasks extend this file)
- Test: (this IS the test infrastructure — each generator lands with a smoke assertion)

- [ ] **Step 1: RNG + session skeleton**

```cpp
// test/test_stress.cpp — machinery stress + property harness.
// Stress framing (2026-10-16): benchmark-scale randomized workloads exercise
// free/realloc adjacencies, prune/compaction gating, and merge preflights
// far beyond functional loads; the four properties below convert the
// "no crash" signal into logic-bug detection as well. History: the wasm
// ot-document-tree flake that uncovered the OpenABE refcount UAF (2026-
// 10-15 chase) was exactly this shape of load.
#include <gtest/gtest.h>
#include <cstdint>
#include <cstdio>
extern "C" {
#include "../src/CRABS/data_model.h"
#include "../src/CRABS/crabs.h"
#include "../src/Crypto/crypto.h"
#include "../src/Serialization/serialization.h"
#include "../src/CRDT/crdt_merge.h"
#include "../src/OT/ot_document.h"
#include "../src/OT/ot_types.h"
// + the headers test_raft_sim.cpp includes for the sim harness — mirror its
// exact include block (grep '#include' at the top of test/test_raft_sim.cpp).
}

// SplitMix64: seed-independent, fast, deterministic; the session derives
// all streams (op choice, position, peers, event timing) from one uint64.
static uint64_t stress_next(uint64_t* state) {
  uint64_t z = (*state += 0x9E3779B97F4A7C15ull);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

// Prints the repro line FIRST so a crash mid-test leaves it on stderr.
static void stress_banner(const char* scenario, uint64_t seed,
                          uint32_t op_index) {
  fprintf(stderr, "[STRESS] scenario=%s seed=%llu ops=%u\n",
          scenario, (unsigned long long)seed, op_index);
}
```

- [ ] **Step 2: adversarial position sampler**

```cpp
// Positions deliberately stress the apply paths' clamp/no-op/bounds
// branches: 0, exactly tail, past tail, mid, and the same value as the
// previous op (same-offset collisions drive the tie-break paths).
static uint64_t sample_position(uint64_t* rng, uint64_t visible_count) {
  switch (stress_next(rng) % 6) {
    case 0: return 0;
    case 1: return visible_count == 0 ? 0 : visible_count;         // at tail
    case 2: return visible_count == 0 ? 0 : visible_count + 3;      // past tail
    case 3: return visible_count == 0 ? 0 : visible_count / 2;      // mid
    case 4: return 1;  // near-head
    default: return stress_next(rng) % (visible_count + 1);
  }
}
```

- [ ] **Step 3: op generator + session loop skeleton**

One `stress_run_session(scenario, seed, ops)` that owns `replica_count` `state_t*`, and per op index: pick a replica (weighted; a partitioned replica's ops QUEUE rather than apply — see S2), generate 1-3 OT ops (insert/delete/move/swap/split, mix per `scenario`), apply via the documented OT entry points (`crabs_execute_ot_operation` — mirror the exact call shape test_ot_execution.cpp uses for `execute_one_ot_op`), fire the interleaved events per the rates above, and call the property checks (S3/S4/S5/S6 — each task lands its check wired into the loop; until that task lands, its hook is a no-op FIXME-free stub is NOT allowed — see the ordering note: S3 lands FIRST making the loop complete).

ORDERING NOTE: land S3 (P1) before completing the session loop, so no disabled/stubbed path exists at any commit.

- [ ] **Step 4: smoke scenario**

```cpp
TEST(Stress, SmokeTwoReplicaShortSession) {
  // 50 ops, seed 1, 2 replicas, no partitions: the session must complete
  // with P1 equal and P2 round-trip holding. This pins the harness itself.
  EXPECT_NO_FATAL_FAILURE(stress_run_session("smoke", 1, 50));
}
```

- [ ] Run: `cmake --build build -j$(nproc) && ./build/test/testcrabs --gtest_filter='Stress.*'` — smoke passes.
- [ ] Commit: `git add test/test_stress.cpp && git commit -m "test(stress): seeded adversarial session engine + convergence-hash property"`

### Task S2: Partition/heal + queueing for offline replicas

**Files: Modify: `test/test_stress.cpp`**

- [ ] Offline replica: its generated ops queue (FIFO vector) and replay on heal; heal = the offline replica merges every other replica's serialized state (full-blob merge via `crabs_wasm_merge_state`'s C twin — the exact merge entry test_raft_sim.cpp / the merge tests use) and then replays its queued ops; other replicas merge IT. After the heal round: P1 must hold.
- [ ] Extend the smoke: `TEST(Stress, PartitionHealThreeReplicas)` — 300 ops, 6 partition rounds, seed 2. Pre-commit run ≥ 3 seeds to show the loop exercises heals deterministically (assert from the harness's own event counters that partitions occurred, not just that nothing crashed).
- [ ] Run + commit: `test(stress): partition/heal rounds with queued-op replay`

### Task S3: Property 1 — convergence content-hash equality (P1)

**Files: Modify: `test/test_stress.cpp`**

- [ ] Check: after each heal AND at session end, per replica: `crabs_serialize_state(state)` → `crypto_sha256` over the bytes → collect; assert all equal; on mismatch print the per-replica item dump (names + repr + counts) before failing.
- [ ] Note: serialize whole states INCLUDING the replica-local protocol_state/lock bytes can legitimately differ — use the state serializer's content-comparable path if one exists (the chain-preimage per-item forms — see `_serialize_data_item_chain_preimage`); if whole-state serialization includes runtime metadata, hash per-item preimages + item names instead and document the choice. Whatever is chosen must NOT depend on replica-local bytes (test first: two replicas that differ only in a taken lock must hash equal).
- [ ] Commit: `test(stress): P1 convergence content-hash equality`

### Task S4: Property 2 — save/load round-trip identity + churn (P2)

**Files: Modify: `test/test_stress.cpp`**

- [ ] At SAVELOAD_RATE: serialize replica k → `crabs_deserialize_state` → re-serialize → byte-compare (P2). The restored state REPLACES the live one (host-restore pattern), session continues on it (this is what makes restore paths hot).
- [ ] Sealed variant: run a share of round-trips through the sealed+signed form (`crabs_wasm_serialize_state_sealed_signed`'s C twin — mirror the state-restore test's idiom) to exercise the seal/trailer path mid-session.
- [ ] Commit: `test(stress): P2 round-trip identity with restore-continue churn`

### Task S5: Property 3 — replay determinism from an empty state (P3)

**Files: Modify: `test/test_stress.cpp`**

- [ ] Scratch replica: fresh `state_create` → serialize the live log… replay via the OT-op-log replay path (re-drive each log op through the executor). Assert P3 (same hash as P1).
- [ ] Rate-limit this property (it is O(history)): run every SAVELOAD round rather than every op.
- [ ] Commit: `test(stress): P3 replay-from-empty determinism`

### Task S6: Property 4 — compacted vs uncompacted convergence + offline-peer tombstone safety (P4)

**Files:**

- Modify: `test/test_stress.cpp`
- Reference first: `src/Compaction/compaction_engine.c` (rate limiting + gating), `src/Compaction/crdt_compaction.c` (tombstone thresholds), and the peer_vc STRONG/QUORUM safety check (crabs_compaction_engine_set_peer_vc) — mirror the existing compaction tests' setup idioms (grep `state_set_compaction_engine` / `set_peer_vc` in test/).

- [ ] The session alternates which replicas compact (some never compact — the uncompacted control); P1 must hold across compacted/uncompacted replicas after every heal (no resurrection/fork).
- [ ] Offline-compaction case: compact a replica WHILE its peer is offline and has unsynced tombstone-bearing ops; on heal, the offline peer's re-merge must not resurrect collected elements nor crash (P1 again + no-crash). This is the peer_vc gating's adversarial exercise — the vector clocks should make collection REFUSE or WAIT when the offline peer's ack isn't in; assert that behavior (a collected-then-resurrected element = the bug).
- [ ] Restore-after-compaction: a compacted replica's save/load must produce the same P1-hash as the uncompacted twin's (compaction must not change semantic state).
- [ ] Commit: `test(stress): P4 compaction safety — resurrection, offline-peer gating, restore parity`

### Task S7: CI wiring + matrix runs

**Files:**

- Modify: `test/CMakeLists.txt` (nothing needed if the gtest target already globs `test*.cpp` — CHECK; if explicit source list, add test_stress.cpp)
- Modify: `README.md` — one paragraph under the testing section documenting the harness (knobs, seeds, the detector triad, and the wasm run recipe from the command block above).

- [ ] CI mode default: 4000 ops × 3 scenarios × smoke seeds — must complete in < ~60 s native (measure; if slower, drop ops to 2000 and note).
- [ ] ASan matrix: `build-san` binary, filter Stress.*, at least 2 seeds (document in README: setarch -R quirk).
- [ ] Valgrind: single P4-asserted scenario (valgrind over 4000 ops is minutes) — runs on demand, documented as the OpenABE/RELIC eye.
- [ ] Wasm: drive a COMPANION mini-session through the wasm `Node`/binding surface (the OT document API — mirror ot-document-tree.js idioms) in a new `bindings/wasm/test/stress-session.js` (200 ops, seed from a literal), added to the wasm test chain in package.json. Same for the node binding chain if the surface allows it.
- [ ] Full suite green: native + sanitizer (the pre-existing skip allowed); node `npm test`; wasm `npm test`.
- [ ] Commit: `test(stress): CI wiring, sanitizer/valgrind matrix, wasm companion session` + wasm artifacts commit if rebuilt.

### Task S8: Extended soak (on-demand, not CI)

**Files:** none (run + records)

- [ ] `CRABS_STRESS_SEED=20261016 CRABS_STRESS_OPS=100000` native + ASan + valgrind-P4; wasm 2000-op run. Any trap/leak/property violation → the banner line makes it reproducible; triage with the hunt tooling from the 2026-10-15 chase (`CRABS_WASM_ASAN=1`, `/tmp/ec-soak.js` template for binding-level soaks, archive caches at `/home/victor/wasm-archives/`).
- [ ] Record outcomes (even "all clean, N ops" is a datum) in the harness file's header comment.

---

## Execution notes

- The plan's line-number references are NONE — implementations must grep for the quoted idioms (the codebase's audit-comment style makes the anchors unambiguous).
- Known environment gotchas (from this session): bare `cd` does not survive background shells → use `npm --prefix`; `build_wasm.sh` outputs to `build-wasm/` and does NOT copy into `bindings/wasm/` automatically; ASan needs `setarch -R`; the test binary runs directly rather than via plain ctest.
- Do not weaken properties to make sessions pass — a property violation IS a find. A seed that fails is recorded, triaged, and either fixed or (if genuinely value-dependent and unfixable) documented in the harness header with the failing seed.
- Out of scope (deliberate): performance measurement (the benchmark-vs-stress distinction — this harness measures nothing except wall time for CI budget), rich-text product features, and any wire-format changes.