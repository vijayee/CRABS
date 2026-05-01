# Signature VTable & Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement pluggable signature scheme registry and vtable interface per v1.3 Amendment 3 §2-3, with built-in ECDSA secp256k1 vtable.

**Architecture:** New `sig_scheme.h`/`sig_scheme.c` files in `src/Crypto/` define the `signature_scheme_e` enum, `scheme_properties_t` struct, `signature_vtable_t` function-pointer table, and a global registry. The built-in ECDSA secp256k1 vtable wraps existing `crypto_ecdsa_*` functions. A new error code `CRABS_ERR_SCHEME_ALREADY_REGISTERED` is added to `crabs.h`. Tests verify registration, lookup, listing, and ECDSA round-trip through the vtable.

**Tech Stack:** C11, OpenSSL (for ECDSA secp256k1), GoogleTest

---

## File Structure

| File | Responsibility |
|------|---------------|
| `src/Crypto/sig_scheme.h` | Public header: enum, properties, vtable, registry API |
| `src/Crypto/sig_scheme.c` | Registry implementation + built-in ECDSA vtable |
| `src/CRABS/crabs.h` | Add `CRABS_ERR_SCHEME_ALREADY_REGISTERED` error code + v1.3 operation names |
| `test/test_sig_scheme.cpp` | Tests for vtable, registry, ECDSA round-trip |
| `test/CMakeLists.txt` | Add `test_sig_scheme.cpp` to test executable |

---

### Task 1: Add Error Code and Operation Names to crabs.h

**Files:**
- Modify: `src/CRABS/crabs.h`

- [ ] **Step 1: Add CRABS_ERR_SCHEME_ALREADY_REGISTERED and v1.3 operation names**

Add to `crabs_error_e` after `CRABS_ERR_INVALID_PARAM`:

```c
  CRABS_ERR_SCHEME_ALREADY_REGISTERED = 0x5004
```

Add v1.3 operation name defines after the trigger operations:

```c
// Built-in Key Operations (v1.3 Amendment 3, §5)
#define CRABS_OP_REGISTER_KEY     "__register_key__"
#define CRABS_OP_REVOKE_KEY       "__revoke_key__"
#define CRABS_OP_SET_DEFAULT_KEY  "__set_default_key__"
```

- [ ] **Step 2: Rebuild to verify compilation**

Run: `cd /home/victor/Workspace/src/github.com/vijayee/CRABS/build && make -j$(nproc) 2>&1 | tail -5`
Expected: Build succeeds (no code references the new enum/defines yet)

- [ ] **Step 3: Commit**

```bash
cd /home/victor/Workspace/src/github.com/vijayee/CRABS
git add src/CRABS/crabs.h
git commit -m "feat: add scheme registry error code and v1.3 key operation names"
```

---

### Task 2: Create sig_scheme.h Header

**Files:**
- Create: `src/Crypto/sig_scheme.h`

- [ ] **Step 1: Write the header file**

```c
//
// CRABS v1.3: Signature Scheme Registry & VTable (Amendment 3, §2-3)
//

#ifndef CRABS_SIG_SCHEME_H
#define CRABS_SIG_SCHEME_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"

// ============================================================
// Signature Scheme Identifiers (§2.1)
// ============================================================
typedef enum {
  SCHEME_UNSPECIFIED    = 0x00,
  ECDSA_SECP256K1       = 0x01,
  ECDSA_P256            = 0x02,
  ED25519               = 0x03,
  SCHNORR_SECP256K1     = 0x04,
  BLS_BLS12_381         = 0x05,
  RSA_2048              = 0x06,
  RSA_4096              = 0x07,
  DILITHIUM_2           = 0x08,
  DILITHIUM_3           = 0x09,
  DILITHIUM_5           = 0x0A,
  FALCON_512            = 0x0B,
  FALCON_1024           = 0x0C,
  SPHINCS_PLUS_128S     = 0x0D,
  CUSTOM_BASE           = 0xF0,
  CUSTOM_MAX            = 0xFE,
  SCHEME_CUSTOM         = 0xFF
} signature_scheme_e;

// ============================================================
// Scheme Properties (§2.2)
// ============================================================
#define CRABS_MAX_SCHEME_NAME  64

typedef struct {
  signature_scheme_e scheme_id;
  char               name[CRABS_MAX_SCHEME_NAME];
  uint8_t            security_level;       // 1-5 (NIST levels)
  bool               is_post_quantum;

  uint16_t           public_key_size;      // Max public key bytes
  uint16_t           secret_key_size;      // Max secret key bytes
  uint16_t           signature_size;        // Max signature bytes

  bool               supports_batch_verification;
  bool               supports_aggregation;
  bool               supports_threshold;

  uint8_t            sign_speed;           // 1 (slow) to 10 (fast)
  uint8_t            verify_speed;
  uint8_t            keygen_speed;
} scheme_properties_t;

// ============================================================
// Signature VTable (§3.1)
// ============================================================
// Function pointer types for vtable operations
typedef crabs_error_e (*sig_generate_keypair_fn)(
    uint8_t* pk, uint32_t* pk_len,
    uint8_t* sk, uint32_t* sk_len);

typedef crabs_error_e (*sig_sign_fn)(
    const uint8_t* sk, uint32_t sk_len,
    const uint8_t* msg, uint32_t msg_len,
    uint8_t* sig, uint32_t* sig_len);

typedef crabs_error_e (*sig_verify_fn)(
    const uint8_t* pk, uint32_t pk_len,
    const uint8_t* msg, uint32_t msg_len,
    const uint8_t* sig, uint32_t sig_len);

typedef crabs_error_e (*sig_verify_batch_fn)(
    const uint8_t** pks, const uint32_t* pk_lens,
    const uint8_t** msgs, const uint32_t* msg_lens,
    const uint8_t** sigs, const uint32_t* sig_lens,
    uint32_t count);

typedef crabs_error_e (*sig_aggregate_fn)(
    const uint8_t** sigs, const uint32_t* sig_lens,
    uint32_t count,
    uint8_t* aggregated, uint32_t* aggregated_len);

typedef crabs_error_e (*sig_export_key_fn)(
    const uint8_t* key, uint32_t key_len,
    uint8_t* buf, uint32_t* buf_len);

typedef crabs_error_e (*sig_import_key_fn)(
    const uint8_t* buf, uint32_t buf_len,
    uint8_t* key, uint32_t* key_len);

typedef struct {
  signature_scheme_e      scheme_id;
  char                    name[CRABS_MAX_SCHEME_NAME];
  scheme_properties_t     properties;

  // Required
  sig_generate_keypair_fn generate_keypair;
  sig_sign_fn             sign;
  sig_verify_fn           verify;

  // Optional (may be NULL)
  sig_verify_batch_fn     verify_batch;
  sig_aggregate_fn        aggregate_signatures;
  sig_export_key_fn       export_public_key;
  sig_export_key_fn       export_secret_key;
  sig_import_key_fn       import_public_key;
  sig_import_key_fn       import_secret_key;
} signature_vtable_t;

// ============================================================
// Registry API (§3.2)
// ============================================================
#define CRABS_MAX_REGISTERED_SCHEMES  32

crabs_error_e  crypto_sig_scheme_register(const signature_vtable_t* vtable);
const signature_vtable_t* crypto_sig_scheme_get(signature_scheme_e scheme_id);
uint32_t       crypto_sig_scheme_list(signature_scheme_e* out, uint32_t max_count);
uint32_t       crypto_sig_scheme_count(void);
void           crypto_sig_scheme_init(void);

#endif // CRABS_SIG_SCHEME_H
```

- [ ] **Step 2: Verify header compiles**

Run: `cd /home/victor/Workspace/src/github.com/vijayee/CRABS/build && cmake .. 2>&1 | tail -3`
Expected: cmake succeeds (no .c file yet, just header check)

- [ ] **Step 3: Commit**

```bash
cd /home/victor/Workspace/src/github.com/vijayee/CRABS
git add src/Crypto/sig_scheme.h
git commit -m "feat: add signature scheme registry and vtable header (v1.3 §2-3)"
```

---

### Task 3: Implement sig_scheme.c — Registry + Built-in ECDSA VTable

**Files:**
- Create: `src/Crypto/sig_scheme.c`
- Modify: `src/CMakeLists.txt` (add sig_scheme.c to library sources)

- [ ] **Step 1: Write the implementation**

```c
//
// CRABS v1.3: Signature Scheme Registry & VTable (Amendment 3, §2-3)
//

#include "sig_scheme.h"
#include "crypto.h"
#include <stdlib.h>
#include <string.h>

// ============================================================
// Global Registry
// ============================================================
static signature_vtable_t* _registry[CRABS_MAX_REGISTERED_SCHEMES];
static uint32_t _registry_count = 0;
static bool _registry_initialized = false;

// ============================================================
// Registry API
// ============================================================
crabs_error_e crypto_sig_scheme_register(const signature_vtable_t* vtable) {
  if (vtable == NULL) return CRABS_ERR_INVALID_PARAM;
  if (vtable->generate_keypair == NULL) return CRABS_ERR_INVALID_PARAM;
  if (vtable->sign == NULL) return CRABS_ERR_INVALID_PARAM;
  if (vtable->verify == NULL) return CRABS_ERR_INVALID_PARAM;

  // Check if already registered
  if (crypto_sig_scheme_get(vtable->scheme_id) != NULL) {
    return CRABS_ERR_SCHEME_ALREADY_REGISTERED;
  }

  if (_registry_count >= CRABS_MAX_REGISTERED_SCHEMES) {
    return CRABS_ERR_OOM;
  }

  // Allocate and copy vtable
  signature_vtable_t* entry = get_clear_memory(sizeof(signature_vtable_t));
  memcpy(entry, vtable, sizeof(signature_vtable_t));
  _registry[_registry_count++] = entry;
  return CRABS_SUCCESS;
}

const signature_vtable_t* crypto_sig_scheme_get(signature_scheme_e scheme_id) {
  for (uint32_t i = 0; i < _registry_count; i++) {
    if (_registry[i] != NULL && _registry[i]->scheme_id == scheme_id) {
      return _registry[i];
    }
  }
  return NULL;
}

uint32_t crypto_sig_scheme_list(signature_scheme_e* out, uint32_t max_count) {
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
  if (_registry_initialized) return;
  _registry_initialized = true;
  crypto_sig_scheme_register(&_ecdsa_secp256k1_vtable);
}
```

- [ ] **Step 2: Add sig_scheme.c to the CMake library sources**

In `src/CMakeLists.txt`, add `Crypto/sig_scheme.c` to the library source list (find the existing `Crypto/crypto.c` entry and add alongside it).

- [ ] **Step 3: Build**

Run: `cd /home/victor/Workspace/src/github.com/vijayee/CRABS/build && cmake .. && make -j$(nproc) 2>&1 | tail -10`
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
cd /home/victor/Workspace/src/github.com/vijayee/CRABS
git add src/Crypto/sig_scheme.c src/Crypto/sig_scheme.h src/CMakeLists.txt
git commit -m "feat: implement signature scheme registry with built-in ECDSA vtable"
```

---

### Task 4: Write Tests for Signature Scheme Registry

**Files:**
- Create: `test/test_sig_scheme.cpp`
- Modify: `test/CMakeLists.txt`

- [ ] **Step 1: Write the test file**

```cpp
//
// CRABS-49: Signature VTable & Registry Tests
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/Crypto/sig_scheme.h"
#include "../src/Crypto/crypto.h"
#include "../src/CRABS/crabs.h"
}

// ============================================================
// Scheme Enum Values
// ============================================================

TEST(TestSigScheme, EnumValues) {
  EXPECT_EQ(SCHEME_UNSPECIFIED, 0x00);
  EXPECT_EQ(ECDSA_SECP256K1, 0x01);
  EXPECT_EQ(ED25519, 0x03);
  EXPECT_EQ(DILITHIUM_3, 0x09);
  EXPECT_EQ(SCHEME_CUSTOM, 0xFF);
}

// ============================================================
// Registry: Initialization & Lookup
// ============================================================

TEST(TestSigScheme, InitRegistersECDSA) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);
  EXPECT_EQ(vt->scheme_id, ECDSA_SECP256K1);
  EXPECT_STREQ(vt->name, "ECDSA secp256k1");
}

TEST(TestSigScheme, GetUnregisteredReturnsNull) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ED25519);
  EXPECT_EQ(vt, nullptr);
}

TEST(TestSigScheme, GetUnspecifiedReturnsNull) {
  const signature_vtable_t* vt = crypto_sig_scheme_get(SCHEME_UNSPECIFIED);
  EXPECT_EQ(vt, nullptr);
}

// ============================================================
// Registry: List & Count
// ============================================================

TEST(TestSigScheme, CountAfterInit) {
  crypto_sig_scheme_init();
  EXPECT_EQ(crypto_sig_scheme_count(), 1u);
}

TEST(TestSigScheme, ListSchemes) {
  crypto_sig_scheme_init();
  signature_scheme_e schemes[32];
  uint32_t count = crypto_sig_scheme_list(schemes, 32);
  EXPECT_EQ(count, 1u);
  EXPECT_EQ(schemes[0], ECDSA_SECP256K1);
}

TEST(TestSigScheme, ListWithSmallBuffer) {
  crypto_sig_scheme_init();
  signature_scheme_e schemes[1];
  uint32_t count = crypto_sig_scheme_list(schemes, 1);
  EXPECT_EQ(count, 1u);
}

// ============================================================
// Registry: Duplicate Registration
// ============================================================

TEST(TestSigScheme, RegisterDuplicateFails) {
  crypto_sig_scheme_init();
  signature_vtable_t dup = {};
  dup.scheme_id = ECDSA_SECP256K1;
  dup.generate_keypair = (sig_generate_keypair_fn)1;
  dup.sign = (sig_sign_fn)1;
  dup.verify = (sig_verify_fn)1;
  crabs_error_e rc = crypto_sig_scheme_register(&dup);
  EXPECT_EQ(rc, CRABS_ERR_SCHEME_ALREADY_REGISTERED);
}

// ============================================================
// Registry: Null Param Guards
// ============================================================

TEST(TestSigScheme, RegisterNullVtable) {
  EXPECT_EQ(crypto_sig_scheme_register(nullptr), CRABS_ERR_INVALID_PARAM);
}

TEST(TestSigScheme, RegisterNullRequiredFn) {
  signature_vtable_t vt = {};
  vt.scheme_id = (signature_scheme_e)0xF1;
  // generate_keypair is NULL
  vt.sign = (sig_sign_fn)1;
  vt.verify = (sig_verify_fn)1;
  EXPECT_EQ(crypto_sig_scheme_register(&vt), CRABS_ERR_INVALID_PARAM);

  vt.scheme_id = (signature_scheme_e)0xF2;
  vt.generate_keypair = (sig_generate_keypair_fn)1;
  vt.sign = nullptr;
  EXPECT_EQ(crypto_sig_scheme_register(&vt), CRABS_ERR_INVALID_PARAM);

  vt.scheme_id = (signature_scheme_e)0xF3;
  vt.sign = (sig_sign_fn)1;
  vt.verify = nullptr;
  EXPECT_EQ(crypto_sig_scheme_register(&vt), CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Scheme Properties
// ============================================================

TEST(TestSigScheme, ECDSAProperties) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  const scheme_properties_t* p = &vt->properties;
  EXPECT_EQ(p->scheme_id, ECDSA_SECP256K1);
  EXPECT_EQ(p->security_level, 2);
  EXPECT_FALSE(p->is_post_quantum);
  EXPECT_EQ(p->public_key_size, 33u);
  EXPECT_EQ(p->secret_key_size, 32u);
  EXPECT_EQ(p->signature_size, 64u);
  EXPECT_FALSE(p->supports_batch_verification);
  EXPECT_FALSE(p->supports_aggregation);
  EXPECT_FALSE(p->supports_threshold);
}

// ============================================================
// ECDSA VTable Round-Trip: Keypair → Sign → Verify
// ============================================================

TEST(TestSigScheme, ECDSAGenerateKeypair) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  uint8_t pk[33];
  uint32_t pk_len = sizeof(pk);
  uint8_t sk[32];
  uint32_t sk_len = sizeof(sk);

  crabs_error_e rc = vt->generate_keypair(pk, &pk_len, sk, &sk_len);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(pk_len, 33u);
  EXPECT_EQ(sk_len, 32u);
  // Compressed public key starts with 0x02 or 0x03
  EXPECT_TRUE(pk[0] == 0x02 || pk[0] == 0x03);
}

TEST(TestSigScheme, ECDSASignVerifyRoundTrip) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  // Generate keypair
  uint8_t pk[33]; uint32_t pk_len = sizeof(pk);
  uint8_t sk[32]; uint32_t sk_len = sizeof(sk);
  ASSERT_EQ(vt->generate_keypair(pk, &pk_len, sk, &sk_len), CRABS_SUCCESS);

  // Sign a message
  const uint8_t msg[] = "hello CRABS v1.3 sig scheme";
  uint8_t sig[CRABS_SIG_SIZE]; uint32_t sig_len = sizeof(sig);
  crabs_error_e rc = vt->sign(sk, sk_len, msg, sizeof(msg), sig, &sig_len);
  EXPECT_EQ(rc, CRABS_SUCCESS);
  EXPECT_EQ(sig_len, (uint32_t)CRABS_SIG_SIZE);

  // Verify
  rc = vt->verify(pk, pk_len, msg, sizeof(msg), sig, sig_len);
  EXPECT_EQ(rc, CRABS_SUCCESS);
}

TEST(TestSigScheme, ECDSAVerifyWrongMessageFails) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  uint8_t pk[33]; uint32_t pk_len = sizeof(pk);
  uint8_t sk[32]; uint32_t sk_len = sizeof(sk);
  ASSERT_EQ(vt->generate_keypair(pk, &pk_len, sk, &sk_len), CRABS_SUCCESS);

  const uint8_t msg[] = "correct message";
  uint8_t sig[CRABS_SIG_SIZE]; uint32_t sig_len = sizeof(sig);
  ASSERT_EQ(vt->sign(sk, sk_len, msg, sizeof(msg), sig, &sig_len), CRABS_SUCCESS);

  const uint8_t wrong_msg[] = "wrong message";
  crabs_error_e rc = vt->verify(pk, pk_len, wrong_msg, sizeof(wrong_msg), sig, sig_len);
  EXPECT_EQ(rc, CRABS_ERR_CRYPTOGRAPHIC_ERROR);
}

TEST(TestSigScheme, ECDSAVerifyWrongKeyFails) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  // Signer keypair
  uint8_t pk1[33]; uint32_t pk1_len = sizeof(pk1);
  uint8_t sk1[32]; uint32_t sk1_len = sizeof(sk1);
  ASSERT_EQ(vt->generate_keypair(pk1, &pk1_len, sk1, &sk1_len), CRABS_SUCCESS);

  // Different keypair
  uint8_t pk2[33]; uint32_t pk2_len = sizeof(pk2);
  uint8_t sk2[32]; uint32_t sk2_len = sizeof(sk2);
  ASSERT_EQ(vt->generate_keypair(pk2, &pk2_len, sk2, &sk2_len), CRABS_SUCCESS);

  const uint8_t msg[] = "test message";
  uint8_t sig[CRABS_SIG_SIZE]; uint32_t sig_len = sizeof(sig);
  ASSERT_EQ(vt->sign(sk1, sk1_len, msg, sizeof(msg), sig, &sig_len), CRABS_SUCCESS);

  // Verify with wrong public key
  crabs_error_e rc = vt->verify(pk2, pk2_len, msg, sizeof(msg), sig, sig_len);
  EXPECT_EQ(rc, CRABS_ERR_CRYPTOGRAPHIC_ERROR);
}

// ============================================================
// Null Param Guards for VTable Operations
// ============================================================

TEST(TestSigScheme, ECDSAGenerateKeypairNullParams) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  uint8_t buf[33]; uint32_t len = sizeof(buf);
  EXPECT_EQ(vt->generate_keypair(nullptr, &len, buf, &len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->generate_keypair(buf, nullptr, buf, &len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->generate_keypair(buf, &len, nullptr, &len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->generate_keypair(buf, &len, buf, nullptr), CRABS_ERR_INVALID_PARAM);
}

TEST(TestSigScheme, ECDSASignNullParams) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  uint8_t sk[32]; uint32_t sk_len = 32;
  uint8_t msg[] = "test"; uint32_t msg_len = 4;
  uint8_t sig[64]; uint32_t sig_len = 64;

  EXPECT_EQ(vt->sign(nullptr, sk_len, msg, msg_len, sig, &sig_len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->sign(sk, sk_len, nullptr, msg_len, sig, &sig_len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->sign(sk, sk_len, msg, msg_len, nullptr, &sig_len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->sign(sk, sk_len, msg, msg_len, sig, nullptr), CRABS_ERR_INVALID_PARAM);
}

TEST(TestSigScheme, ECDSAVerifyNullParams) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);

  uint8_t pk[33]; uint32_t pk_len = 33;
  uint8_t msg[] = "test"; uint32_t msg_len = 4;
  uint8_t sig[64]; uint32_t sig_len = 64;

  EXPECT_EQ(vt->verify(nullptr, pk_len, msg, msg_len, sig, sig_len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->verify(pk, pk_len, nullptr, msg_len, sig, sig_len), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(vt->verify(pk, pk_len, msg, msg_len, nullptr, sig_len), CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Optional VTable Functions Are NULL for ECDSA
// ============================================================

TEST(TestSigScheme, ECDSAOptionalFunctionsNull) {
  crypto_sig_scheme_init();
  const signature_vtable_t* vt = crypto_sig_scheme_get(ECDSA_SECP256K1);
  ASSERT_NE(vt, nullptr);
  EXPECT_EQ(vt->verify_batch, nullptr);
  EXPECT_EQ(vt->aggregate_signatures, nullptr);
  EXPECT_EQ(vt->export_public_key, nullptr);
  EXPECT_EQ(vt->export_secret_key, nullptr);
  EXPECT_EQ(vt->import_public_key, nullptr);
  EXPECT_EQ(vt->import_secret_key, nullptr);
}
```

- [ ] **Step 2: Add test_sig_scheme.cpp to CMakeLists.txt**

Add `test_sig_scheme.cpp` to the `add_executable(testcrabs ...)` list in `test/CMakeLists.txt`.

- [ ] **Step 3: Build and run tests**

Run: `cd /home/victor/Workspace/src/github.com/vijayee/CRABS/build && cmake .. && make -j$(nproc) 2>&1 | tail -5`
Then: `./test/testcrabs --gtest_filter="*SigScheme*" 2>&1`
Expected: All tests pass

- [ ] **Step 4: Run full test suite**

Run: `./test/testcrabs 2>&1 | tail -5`
Expected: All tests pass (no regressions)

- [ ] **Step 5: Commit**

```bash
cd /home/victor/Workspace/src/github.com/vijayee/CRABS
git add test/test_sig_scheme.cpp test/CMakeLists.txt
git commit -m "test: add signature scheme registry and vtable tests"
```

---

## Self-Review

**1. Spec coverage:**
- §2.1 Scheme Identifiers: Covered in Task 2 (enum) + Task 4 (enum values test)
- §2.2 Scheme Properties: Covered in Task 2 (struct) + Task 4 (properties test)
- §3.1 Signature VTable: Covered in Task 2 (struct with fn pointers) + Task 4 (round-trip tests)
- §3.2 Registry: Covered in Task 3 (register/get/list/count) + Task 4 (registry tests)
- Built-in ECDSA vtable: Covered in Task 3 (wrappers + vtable instance) + Task 4 (ECDSA tests)

**2. Placeholder scan:** No TBD, TODO, or placeholder patterns found.

**3. Type consistency:** `signature_scheme_e` enum values used consistently across header, implementation, and tests. `scheme_properties_t` and `signature_vtable_t` struct field names match between definition and usage. Function pointer typedefs match vtable struct fields.