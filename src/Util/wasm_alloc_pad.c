//
// wasm_alloc_pad.c — allocator padding for the WASM build (parity-fill P11)
//
// WHY THIS EXISTS
//
// The wasm build of OpenSSL 3.4.0 (linux-generic32, no-asm, emcc 6) performs
// a small heap overflow during EC group construction: every
// crypto_ecdsa_generate / crypto_ecdsa_sign drives EC_KEY_new_by_curve_name
// → EC_GROUP_new_curve_GFp → ossl_ec_GFp_mont_group_set_curve →
// BN_MONT_CTX_set, and a few-byte write past an allocation in that path
// lands in the dlmalloc chunk slack or — when the allocation's usable size
// has none — in the NEXT chunk's header. Corrupted dlmalloc headers make a
// later large malloc/free walk unmapped memory, surfacing as
// `RuntimeError: memory access out of bounds` inside
// emscripten_builtin_malloc/free — the pre-existing wasm
// ot-document-tree.js Node.create flake (see the diagnosis block in
// bindings/wasm/test/ot-document-tree.js).
//
// P11 diagnosis trail, condensed:
//   - canary-guarded allocator: the scribble appears from the SECOND ECDSA
//     keygen of a process onward, inside EC_KEY_new_by_curve_name; per-op
//     signing draws the same path, so long OT runs accumulate scribbles
//     (monotonic failure gradient in op count).
//   - every CRABS file plus OpenSSL crypto/{bn,ec,rand} and crypto/mem*.c
//     was compiled with -fsanitize=address (objects before the archive) and
//     never reported: the wild write's destination is adjacency-dependent,
//     so a changed allocator layout moves it into live bytes silently.
//   - the native binding passes clean under plain glibc and under
//     MALLOC_CHECK_=3 + MALLOC_PERTURB_; not the C stack (8MB STACK_SIZE
//     still fails), not memory growth (static 512MB no-growth still fails),
//     not strict aliasing.
//
// THE FIX HERE
//
// `-Wl,--wrap=malloc -Wl,--wrap=calloc` in build_wasm.sh routes every
// malloc/calloc allocation in the module — CRABS, OpenSSL, relic, OpenABE
// alike — through this padding shim, which requests 32 extra bytes from
// dlmalloc (realloc keeps dlmalloc's own path: the observed overflow comes
// from zalloc/malloc-sized BN buffers). The overflow then always lands in
// the pad, never in dlmalloc's metadata or a neighbor's live bytes. Cost:
// 32 bytes per allocation. The native build
// compiles this file out (guarded by __EMSCRIPTEN__) and needs no padding —
// glibc's own chunk granularity already absorbs the few-byte overflow.
//
// When the OpenSSL wasm build is regenerated against a version that fixes
// the EC-group overflow, this shim and the build_wasm.sh wrap flags can be
// dropped together (search: CRABS_WASM_ALLOC_PAD).

#ifdef __EMSCRIPTEN__

#include "allocator.h"
#include "log.h"

#define CRABS_WASM_ALLOC_PAD 32

extern void* __real_malloc(size_t size);
extern void* __real_calloc(size_t count, size_t size);

void* __wrap_malloc(size_t size) {
  return __real_malloc(size + CRABS_WASM_ALLOC_PAD);
}

void* __wrap_calloc(size_t count, size_t size) {
  return __real_calloc(count, size + CRABS_WASM_ALLOC_PAD);
}

#else

// Native builds: the file must still contribute a translation unit so the
// build system's source glob stays uniform.
typedef int crabs_wasm_alloc_pad_not_needed;

#endif // __EMSCRIPTEN__