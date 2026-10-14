//
// wasm_init.c — OpenSSL initialization for the WASM build.
//
// OpenSSL 3.x's deprecated EC_KEY API (used by CRABS for secp256k1) doesn't
// auto-initialize the library context, unlike the EVP API (which SHA-256
// uses successfully). This constructor runs at WASM module load time and
// calls OPENSSL_init_crypto so the EC functions work.
//
// Only compiled for the WASM build (not included in the native or N-API
// builds where OpenSSL is already initialized or auto-inits correctly).
//

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __EMSCRIPTEN__
__attribute__((constructor))
static void _crabs_wasm_openssl_init(void) {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
    // RAND health check (audit MEDIUM): an Emscripten build whose DRBG is not
    // seeded must fail loudly at module load — not deep inside a signing call,
    // where an unnoticed RAND_bytes failure could mint weak keys. Every CRABS
    // randomness consumer flows through crypto_random_bytes, so an abort here
    // guarantees no weak key material is ever produced.
    if (RAND_status() != 1) {
        fputs("CRABS: OpenSSL RAND not seeded — aborting WASM startup\n", stderr);
        abort();
    }
}
#endif