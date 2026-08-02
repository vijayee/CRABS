//
// CRABS v1.3: Signature Scheme Registry & VTable (Amendment 3, §2-3)
//

#include "sig_scheme.h"
#include "crypto.h"
#include "../Util/allocator.h"
#include "../Util/platform.h"
#include <string.h>

// ============================================================
// Global Registry
// ============================================================
static signature_vtable_t* _registry[CRABS_MAX_REGISTERED_SCHEMES];
static uint32_t _registry_count = 0;
static bool _registry_initialized = false;
// Guards register/get/cleanup so the registry can be used from multiple
// threads (audit L-3). Init-time registration and steady-state lookups are
// the common case; cleanup is expected only at shutdown.
// Audit X-1: use the platform abstraction instead of pthread directly so
// the registry compiles on Windows (CRITICAL_SECTION) and POSIX
// (pthread_mutex_t).
// De-wonk: on POSIX, use PTHREAD_MUTEX_INITIALIZER for static, race-free
// initialization. On Windows, CRITICAL_SECTION cannot be statically
// initialized, so use a lazy-init guard. The guard has a theoretical race
// if two threads call _ensure_registry_lock simultaneously before the lock
// is initialized; in practice, crypto_sig_scheme_init() is called at startup
// before multi-threaded use, so the race does not arise. If Windows
// multi-threaded use before init becomes a concern, switch to
// InitOnceExecuteOnce.
#ifdef _WIN32
static platform_mutex_t _registry_lock;
static bool _registry_lock_initialized = false;
static void _ensure_registry_lock(void) {
  if (_registry_lock_initialized) return;
  platform_mutex_init(&_registry_lock);
  _registry_lock_initialized = true;
}
#else
// POSIX: static initialization eliminates the race entirely.
static platform_mutex_t _registry_lock = PTHREAD_MUTEX_INITIALIZER;
static void _ensure_registry_lock(void) {
  // No-op: the mutex is statically initialized.
}
#endif

// ============================================================
// Registry API
// ============================================================
crabs_error_e crypto_sig_scheme_register(const signature_vtable_t* vtable) {
  if (vtable == NULL) return CRABS_ERR_INVALID_PARAM;
  if (vtable->generate_keypair == NULL) return CRABS_ERR_INVALID_PARAM;
  if (vtable->sign == NULL) return CRABS_ERR_INVALID_PARAM;
  if (vtable->verify == NULL) return CRABS_ERR_INVALID_PARAM;

  _ensure_registry_lock(); platform_mutex_lock(&_registry_lock);
  // Inline duplicate check (do NOT call crypto_sig_scheme_get here — it
  // locks the same _registry_lock, which would deadlock).
  for (uint32_t i = 0; i < _registry_count; i++) {
    if (_registry[i] != NULL && _registry[i]->scheme_id == vtable->scheme_id) {
      platform_mutex_unlock(&_registry_lock);
      return CRABS_ERR_SCHEME_ALREADY_REGISTERED;
    }
  }

  if (_registry_count >= CRABS_MAX_REGISTERED_SCHEMES) {
    platform_mutex_unlock(&_registry_lock);
    return CRABS_ERR_OOM;
  }

  signature_vtable_t* entry = get_clear_memory(sizeof(signature_vtable_t));
  if (entry == NULL) {
    platform_mutex_unlock(&_registry_lock);
    return CRABS_ERR_OOM;
  }
  memcpy(entry, vtable, sizeof(signature_vtable_t));
  _registry[_registry_count++] = entry;
  platform_mutex_unlock(&_registry_lock);
  return CRABS_SUCCESS;
}

const signature_vtable_t* crypto_sig_scheme_get(signature_scheme_e scheme_id) {
  _ensure_registry_lock(); platform_mutex_lock(&_registry_lock);
  for (uint32_t i = 0; i < _registry_count; i++) {
    if (_registry[i] != NULL && _registry[i]->scheme_id == scheme_id) {
      const signature_vtable_t* r = _registry[i];
      platform_mutex_unlock(&_registry_lock);
      return r;
    }
  }
  platform_mutex_unlock(&_registry_lock);
  return NULL;
}

uint32_t crypto_sig_scheme_list(signature_scheme_e* out, uint32_t max_count) {
  if (out == NULL) return 0;
  uint32_t count = _registry_count < max_count ? _registry_count : max_count;
  for (uint32_t i = 0; i < count; i++) {
    if (_registry[i] != NULL) {
      out[i] = _registry[i]->scheme_id;
    }
  }
  return count;
}

uint32_t crypto_sig_scheme_count(void) {
  return _registry_count;
}

// ============================================================
// Built-in ECDSA secp256k1 VTable Wrappers
// ============================================================

static crabs_error_e _ecdsa_generate_keypair(
    uint8_t* pk, uint32_t* pk_len,
    uint8_t* sk, uint32_t* sk_len) {
  if (pk == NULL || pk_len == NULL || sk == NULL || sk_len == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (*pk_len < 33 || *sk_len < 32) {
    return CRABS_ERR_INVALID_PARAM;
  }

  ecdsa_keypair_t* kp = crypto_ecdsa_generate();
  if (kp == NULL) return CRABS_ERR_CRYPTOGRAPHIC_ERROR;

  memcpy(pk, kp->public_key, 33);
  *pk_len = 33;
  memcpy(sk, kp->private_key, 32);
  *sk_len = 32;

  crypto_ecdsa_keypair_destroy(kp);
  return CRABS_SUCCESS;
}

static crabs_error_e _ecdsa_sign(
    const uint8_t* sk, uint32_t sk_len,
    const uint8_t* msg, uint32_t msg_len,
    uint8_t* sig, uint32_t* sig_len) {
  if (sk == NULL || msg == NULL || sig == NULL || sig_len == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (sk_len != 32 || *sig_len < CRABS_SIG_SIZE) {
    return CRABS_ERR_INVALID_PARAM;
  }

  crabs_error_e rc = crypto_ecdsa_sign(sk, msg, msg_len, sig);
  if (rc != CRABS_SUCCESS) return rc;

  *sig_len = CRABS_SIG_SIZE;
  return CRABS_SUCCESS;
}

static crabs_error_e _ecdsa_verify(
    const uint8_t* pk, uint32_t pk_len,
    const uint8_t* msg, uint32_t msg_len,
    const uint8_t* sig, uint32_t sig_len) {
  if (pk == NULL || msg == NULL || sig == NULL) {
    return CRABS_ERR_INVALID_PARAM;
  }
  if (pk_len != 33 || sig_len != CRABS_SIG_SIZE) {
    return CRABS_ERR_INVALID_PARAM;
  }

  bool ok = crypto_ecdsa_verify(pk, msg, msg_len, sig);
  return ok ? CRABS_SUCCESS : CRABS_ERR_CRYPTOGRAPHIC_ERROR;
}

// ============================================================
// Built-in VTable Instance
// ============================================================
static signature_vtable_t _ecdsa_secp256k1_vtable = {
  .scheme_id   = ECDSA_SECP256K1,
  .name        = "ECDSA secp256k1",
  .properties  = {
    .scheme_id    = ECDSA_SECP256K1,
    .name         = "ECDSA secp256k1",
    .security_level = 2,
    .is_post_quantum = false,
    .public_key_size  = 33,
    .secret_key_size  = 32,
    .signature_size   = 64,
    .supports_batch_verification = false,
    .supports_aggregation = false,
    .supports_threshold = false,
    .sign_speed   = 8,
    .verify_speed = 8,
    .keygen_speed = 7
  },
  .generate_keypair     = _ecdsa_generate_keypair,
  .sign                 = _ecdsa_sign,
  .verify               = _ecdsa_verify,
  .verify_batch         = NULL,
  .aggregate_signatures = NULL,
  .export_public_key    = NULL,
  .export_secret_key    = NULL,
  .import_public_key    = NULL,
  .import_secret_key    = NULL
};

// ============================================================
// Initialization
// ============================================================
void crypto_sig_scheme_init(void) {
  _ensure_registry_lock(); platform_mutex_lock(&_registry_lock);
  if (_registry_initialized) { platform_mutex_unlock(&_registry_lock); return; }
  _registry_initialized = true;
  platform_mutex_unlock(&_registry_lock);
  crypto_sig_scheme_register(&_ecdsa_secp256k1_vtable);
}

void crypto_sig_scheme_cleanup(void) {
  _ensure_registry_lock(); platform_mutex_lock(&_registry_lock);
  for (uint32_t i = 0; i < _registry_count; i++) {
    if (_registry[i] != NULL) {
      free(_registry[i]);
      _registry[i] = NULL;
    }
  }
  _registry_count = 0;
  _registry_initialized = false;
  platform_mutex_unlock(&_registry_lock);
}