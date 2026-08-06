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

#ifdef __EMSCRIPTEN__
__attribute__((constructor))
static void _crabs_wasm_openssl_init(void) {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
}
#endif