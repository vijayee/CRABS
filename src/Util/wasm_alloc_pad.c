//
// wasm_alloc_pad.c — allocator padding for the WASM build (parity-fill P11)
//
// ROOT CAUSE RESOLVED (2026-10-15 chase): the OOB this pad absorbed was the
// OpenABE owned-alias refcount UAF (deps/openabe-c e158293, 2026-10-14) in
// wasm archives built BEFORE that fix. ASan-instrumented archives at the
// pre-fix revision reproduce heap-use-after-free immediately on
// state-restore.js: a 4-byte WRITE into the 728-byte RELIC group object
// that oabe_secret_key_destroy -> oabe_zp_destroy -> oabe_group_destroy
// frees while the CP context still holds the alias (the context was built
// by oabe_context_cp_new during crypto_abe_setup). The freed group's memory
// is recycled by ECDSA/BN allocations — which is why every earlier probe
// blamed "OpenSSL 3.4.0 EC-group construction" and why the write looked
// like an EC-keygen-adjacent few-byte overflow scribbling dlmalloc headers
// (the historical flake: RuntimeError: memory access out of bounds in
// emscripten_builtin_malloc/free). An OpenSSL upgrade experiment (3.5.9,
// pad dropped) correctly changed nothing. The Oct-14 13:13 archives
// predated e158293 (16:42), so every shipped bundle until the 2026-10-15
// rebuild carried a mitigated-only UAF; shipped bundles are now built on
// post-fix archives (genuinely UAF-free) and the pad is kept as cheap
// insurance. Historical P11 trail kept below for the record.
//
// WHY THE SHIM EXISTS (insurance posture, post-resolution)
//
// `-Wl,--wrap=malloc -Wl,--wrap=calloc` in build_wasm.sh routes every
// malloc/calloc allocation in the module — CRABS, OpenSSL, relic, OpenABE
// alike — through this padding shim, which requests 32 extra bytes from
// dlmalloc (realloc keeps dlmalloc's own path). A stray few-byte overflow
// lands in the pad instead of dlmalloc's metadata or a neighbor. Cost:
// 32 bytes per allocation. WASM-ONLY: the native build compiles this file
// out (guarded by __EMSCRIPTEN__) — glibc's chunk granularity absorbed the
// UAF's scribble window natively (the native binding passed plain glibc and
// MALLOC_CHECK_=3/MALLOC_PERTURB_ runs).
//
// HUNT TOOLING kept (proven during the chase):
//   CRABS_WASM_ALLOC_PAD=0    drop the pad entirely (regression-canary)
//   CRABS_WASM_ALLOC_GUARD=1  verify the pad as a lazy guard ring
//                             (malloc/calloc wrap scope unchanged; caught
//                             nothing — correct, the post-fix stack is clean)
//   CRABS_WASM_ASAN=1         ASan-instrument CRABS + link (needs ASan-built
//                             RELIC/OpenABE archives; pre-fix archives make
//                             ASan report the UAF immediately — repro:
//                             CRABS_WASM_ASAN=1 CRABS_WASM_ALLOC_PAD=0
//                             OPENABE_DIR=<worktree-at-7f187a0> build)
//   CRABS_WASM_COPT / CRABS_WASM_O2_LIST   optimization bisection gates
// Archive sets cached outside the build tree: /home/victor/wasm-archives/{orig,asan}.

#ifdef __EMSCRIPTEN__

#include "allocator.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CRABS_WASM_ALLOC_PAD 32

extern void* __real_malloc(size_t size);
extern void* __real_calloc(size_t count, size_t size);

// CRABS_WASM_ALLOC_GUARD=1 (baked at build): the pad becomes a VERIFIED
// guard checked LAZILY — a static ring records the last 64 wrapped
// allocations (pointer + user size), and every __wrap_malloc first
// re-verifies their guard bytes. A run of writes past some recently-made
// allocation is thus reported with the victim chunk's size and payload
// address (plus the caller-visible moment) WITHOUT wrapping free/realloc —
// the wrap scope stays exactly the shipped malloc/calloc pair. Allocation
// ordering is dlmalloc-identical to the shipped pad build; only the 32-byte
// pad is subdivided (8-byte size prefix + 24 guard bytes).
#ifdef CRABS_WASM_ALLOC_GUARD

#define CRABS_WASM_GUARD_BYTES 24
#define CRABS_WASM_GUARD_RING  64

typedef struct {
  uint64_t user_size;
} crabs_alloc_prefix_t;

typedef struct {
  void*   payload;
  uint64_t user_size;
} crabs_guard_ring_slot_t;

static crabs_guard_ring_slot_t crabs_guard_ring[CRABS_WASM_GUARD_RING];
static uint32_t crabs_guard_ring_next;

static void _guard_fill(void* payload, uint64_t user_size) {
  uint8_t* guard = (uint8_t*)payload + user_size;
  for (uint64_t i = 0; i < CRABS_WASM_GUARD_BYTES; i++) guard[i] = 0xC3;
}

static void _guard_report(const void* payload, uint64_t user_size) {
  fprintf(stderr,
          "WASM GUARD HIT: victim payload=0x%p user_size=%llu\n",
          payload, (unsigned long long)user_size);
  fflush(stderr);
  abort();
}

static void _guard_verify_ring(void) {
  for (uint32_t slot_index = 0; slot_index < CRABS_WASM_GUARD_RING;
       slot_index++) {
    const crabs_guard_ring_slot_t* slot = &crabs_guard_ring[slot_index];
    if (slot->payload == NULL) continue;
    const uint8_t* guard = (const uint8_t*)slot->payload + slot->user_size;
    for (uint64_t i = 0; i < CRABS_WASM_GUARD_BYTES; i++) {
      if (guard[i] != 0xC3) {
        fprintf(stderr,
                "WASM GUARD HIT (ring slot %u): victim payload=0x%p "
                "user_size=%llu, first dirty byte %llu = 0x%02x\n",
                slot_index, slot->payload,
                (unsigned long long)slot->user_size,
                (unsigned long long)i, guard[i]);
        fflush(stderr);
        abort();
      }
    }
  }
}

void* __wrap_malloc(size_t size) {
  _guard_verify_ring();
  size_t total = size + CRABS_WASM_GUARD_BYTES + sizeof(crabs_alloc_prefix_t);
  crabs_alloc_prefix_t* prefix = (crabs_alloc_prefix_t*)__real_malloc(total);
  if (prefix == NULL) return NULL;
  prefix->user_size = size;
  void* payload = (void*)(prefix + 1);
  _guard_fill(payload, size);
  crabs_guard_ring_slot_t* slot =
      &crabs_guard_ring[crabs_guard_ring_next % CRABS_WASM_GUARD_RING];
  slot->payload = payload;
  slot->user_size = size;
  crabs_guard_ring_next++;
  return payload;
}

void* __wrap_calloc(size_t count, size_t size) {
  size_t bytes = count * size;
  void* payload = __wrap_malloc(bytes);
  if (payload == NULL) return NULL;
  memset(payload, 0, bytes);
  return payload;
}

#else

void* __wrap_malloc(size_t size) {
  return __real_malloc(size + CRABS_WASM_ALLOC_PAD);
}

void* __wrap_calloc(size_t count, size_t size) {
  return __real_calloc(count, size + CRABS_WASM_ALLOC_PAD);
}

#endif // CRABS_WASM_ALLOC_GUARD

#else

// Native builds: the file must still contribute a translation unit so the
// build system's source glob stays uniform.
typedef int crabs_wasm_alloc_pad_not_needed;

#endif // __EMSCRIPTEN__