# Durability Kernel (Serialization v10) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make CRABS machines fully durable — format v10 persists users, key registries, operation-type definitions, child-manifest-reserved space, and the ABE MSK (AES-256-GCM sealed at rest) — with a deterministic v9→v10 migration path.

**Architecture:** Three layers: (1) crypto primitives (`crypto_master_key_serialize/deserialize`, `crypto_seal/unseal`), (2) serialization v10 sections appended to the existing sequential blob layout before the checksum, (3) CLI seal-key custody plus the single-authority fix (the node's vestigial second MSK is removed). Plans 2 (lineage core) and 3 (surfaces) land on top of this format; the child-manifest section position is booked here and filled there.

**Tech Stack:** C11 (gcc via CMake), OpenSSL EVP (AES-256-GCM), OpenABE/relic (CP-ABE), GoogleTest via CTest.

**Spec:** `docs/superpowers/specs/2026-10-06-machine-minting-design.md`

**Style:** Follow `docs/STYLE_GUIDE.md` — `snake_case_t` types, `module_action()` function names, no single-letter variable names. No Co-Authored-By lines in commits.

**Build/test commands** (run from repo root; configure once per clean tree):
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTING=ON
cmake --build build -j
ctest --test-dir build/test --output-on-failure     # full suite
./build/test/testcrabs --gtest_filter='TestDurability.*'   # one suite
```

---

## File Structure

| File | Responsibility |
|---|---|
| `src/Crypto/crypto.h` / `.c` (Modify) | Master-key round-trip + AES-GCM seal/unseal |
| `src/Serialization/serialization.h` / `.c` (Modify) | Format v10 sections + keyed serialize/deserialize APIs |
| `src/CLI/cli.h` / `.c` (Modify) | Seal-key custody on `cli_node_t`, save fail-loud, sealed load, migration command |
| `test/test_crypto.cpp` (Modify) | MSK + seal unit tests |
| `test/test_serialization.cpp` (Modify) | v10 section round-trip tests |
| `test/test_durability.cpp` (Create) | Full restart round-trip integration tests |
| `test/test_cli.cpp` (Modify) | Existing save tests get a seal key; new seal-key tests |
| `test/CMakeLists.txt` (Modify) | Register `test_durability.cpp` |

---

### Task 1: Master key serialize/deserialize

**Files:**
- Modify: `src/Crypto/crypto.h` (after `crypto_abe_user_key_deserialize`, ~line 107)
- Modify: `src/Crypto/crypto.c` (after `crypto_abe_user_key_deserialize`, ~line 865)
- Test: `test/test_crypto.cpp` (append at end)

- [ ] **Step 1: Write the failing test**

Append to `test/test_crypto.cpp`:

```cpp
TEST(TestDurability, MasterKeySerializeRoundTripPreservesAuthority) {
  abe_master_key_t* original = crypto_abe_setup();
  ASSERT_NE(original, nullptr);

  size_t needed = crypto_master_key_serialize(original, nullptr, 0);
  ASSERT_GT(needed, (size_t)0);

  std::vector<uint8_t> blob(needed);
  size_t written = crypto_master_key_serialize(original, blob.data(), blob.size());
  ASSERT_EQ(written, needed);

  crypto_abe_master_key_destroy(original);

  abe_master_key_t* restored = crypto_master_key_deserialize(blob.data(), blob.size());
  ASSERT_NE(restored, nullptr);

  // The restored authority must mint keys in the SAME domain: encrypt with
  // the original MPK policy path and decrypt only with the restored keygen.
  abe_user_key_t* sk = crypto_abe_keygen(restored, "role:admin");
  ASSERT_NE(sk, nullptr);

  const uint8_t msg[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
  abe_ciphertext_t* ct = crypto_abe_encrypt(restored, msg, sizeof(msg), "role:admin");
  ASSERT_NE(ct, nullptr);

  uint8_t* out = NULL;
  size_t out_len = 0;
  crabs_error_e err = crypto_abe_decrypt(sk, ct, &out, &out_len);
  ASSERT_EQ(err, CRABS_SUCCESS);
  ASSERT_NE(out, nullptr);
  ASSERT_EQ(out_len, sizeof(msg));
  EXPECT_EQ(memcmp(out, msg, sizeof(msg)), 0);
  free(out);

  crypto_abe_ciphertext_destroy(ct);
  crypto_abe_user_key_destroy(sk);
  crypto_abe_master_key_destroy(restored);
}

TEST(TestDurability, MasterKeyDeserializeRejectsGarbage) {
  EXPECT_EQ(crypto_master_key_deserialize(nullptr, 10), nullptr);
  const uint8_t junk[16] = {0};
  EXPECT_EQ(crypto_master_key_deserialize(junk, sizeof(junk)), nullptr);
}
```

Note: the ABE setup in this test runs real Waters'09 pairing (2-5 s); the
suite already carries a 300 s per-test timeout (test/CMakeLists.txt), so no
timeout change is needed. Confirm `vector` and `cstring` includes exist at
the top of test_crypto.cpp (they do for serialization tests; add
`#include <vector>` / `#include <cstring>` here if missing).

- [ ] **Step 2: Run test to verify it fails**

```bash
cmake --build build -j && ./build/test/testcrabs --gtest_filter='TestDurability.*'
```
Expected: LINK ERROR — `crypto_master_key_serialize` not declared/defined.

- [ ] **Step 3: Implement**

In `src/Crypto/crypto.h`, after the `crypto_abe_user_key_deserialize` declaration (line ~107):

```c
// ============================================================
// Master Key Durability (§11.5): serialize + restore the CP-ABE
// authority (MPK + MSK) so a machine's authority survives restart.
// Wire format: 'M','K' magic (2 bytes) + format_version 0x01 +
// u32le public_params_len + public_params + u32le master_secret_len
// + master_secret (all lengths little-endian).
// ============================================================
#define CRABS_MSK_FORMAT_VERSION 0x01

size_t crypto_master_key_serialize(const abe_master_key_t* mk,
                                     uint8_t* buf, size_t buf_len);
// Reconstruct a full authority (context + params + secret) from bytes.
// Returns NULL on malformed input.
abe_master_key_t* crypto_master_key_deserialize(const uint8_t* buf, size_t len);
```

In `src/Crypto/crypto.c`, after `crypto_abe_user_key_deserialize` (line ~865):

```c
// ============================================================
// Master Key Durability (§11.5)
// ============================================================

size_t crypto_master_key_serialize(const abe_master_key_t* mk,
                                     uint8_t* buf, size_t buf_len) {
  if (!mk) return 0;
  size_t pp_len = oabe_bytestring_get_size(mk->public_params);
  size_t ms_len = oabe_bytestring_get_size(mk->master_secret);
  size_t total = 2 + 1 + 4 + pp_len + 4 + ms_len;
  if (!buf) return total;               // size probe
  if (buf_len < total) return 0;

  size_t off = 0;
  buf[off++] = 0x4D;                    // 'M'
  buf[off++] = 0x4B;                    // 'K'
  buf[off++] = CRABS_MSK_FORMAT_VERSION;
  uint32_t pp32 = (uint32_t)pp_len;
  uint32_t ms32 = (uint32_t)ms_len;
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    buf[off++] = (uint8_t)(pp32 >> (8 * byte_index));
  }
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    buf[off++] = (uint8_t)(ms32 >> (8 * byte_index));
  }
  memcpy(buf + off, oabe_bytestring_get_const_ptr(mk->public_params), pp_len);
  off += pp_len;
  memcpy(buf + off, oabe_bytestring_get_const_ptr(mk->master_secret), ms_len);
  off += ms_len;
  return off;
}

abe_master_key_t* crypto_master_key_deserialize(const uint8_t* buf, size_t len) {
  if (!buf || len < 2 + 1 + 4 + 4) return NULL;
  if (buf[0] != 0x4D || buf[1] != 0x4B || buf[2] != CRABS_MSK_FORMAT_VERSION) return NULL;
  _ensure_oabe_init();
  if (atomic_load(&_oabe_init_state) != 2) return NULL;

  size_t off = 3;
  uint32_t pp_len = 0;
  uint32_t ms_len = 0;
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    pp_len |= (uint32_t)buf[off++] << (8 * byte_index);
  }
  for (int byte_index = 0; byte_index < 4; byte_index++) {
    ms_len |= (uint32_t)buf[off++] << (8 * byte_index);
  }
  if (off + pp_len + ms_len > len) return NULL;

  abe_master_key_t* mk = get_clear_memory(sizeof(abe_master_key_t));
  if (!mk) return NULL;
  mk->ctx = oabe_context_cp_new();
  if (!mk->ctx) { free(mk); return NULL; }

  OABE_ByteString* pp = oabe_bytestring_new_from_data(buf + off, pp_len);
  OABE_ByteString* ms = oabe_bytestring_new_from_data(buf + off + pp_len, ms_len);
  if (!pp || !ms) {
    if (pp) oabe_bytestring_free(pp);
    if (ms) oabe_bytestring_free(ms);
    oabe_context_cp_free(mk->ctx);
    free(mk);
    return NULL;
  }
  if (oabe_context_cp_set_public_params(mk->ctx, pp) != OABE_SUCCESS ||
      oabe_context_cp_set_secret_key(mk->ctx, ms) != OABE_SUCCESS) {
    oabe_bytestring_free(pp);
    oabe_bytestring_free(ms);
    oabe_context_cp_free(mk->ctx);
    free(mk);
    return NULL;
  }
  // Duplicate the byte strings for the master key's own fields, then release
  // the temporaries — the ctx holds its own copies from the setters.
  oabe_bytestring_free(pp);
  oabe_bytestring_free(ms);
  if (oabe_context_cp_get_public_params(mk->ctx, &mk->public_params) != OABE_SUCCESS ||
      oabe_context_cp_get_secret_key(mk->ctx, &mk->master_secret) != OABE_SUCCESS) {
    crypto_abe_master_key_destroy(mk);
    return NULL;
  }
  return mk;
}
```

NOTE FOR THE IMPLEMENTER: verify at compile time that
`oabe_bytestring_new_from_data` copies (it does — used the same way in
`crypto_abe_keygen`, crypto.c:812) and that `atomic_uint`/`_oabe_init_state`
are already in scope in crypto.c (they are — `_ensure_oabe_init` uses them;
`key_seq` is zero-cleared by `get_clear_memory`, which keeps the per-authority
sequence well-defined after restore).

- [ ] **Step 4: Run test to verify it passes**

```bash
cmake --build build -j && ./build/test/testcrabs --gtest_filter='TestDurability.*'
```
Expected: 3 tests pass (the 2 new + 1 from Task 2 later; at this point 2).

- [ ] **Step 5: Commit**

```bash
git add src/Crypto/crypto.h src/Crypto/crypto.c test/test_crypto.cpp
git commit -m "feat: master key serialize/deserialize for authority durability"
```

---

### Task 2: AES-256-GCM seal/unseal

**Files:**
- Modify: `src/Crypto/crypto.h` (after Section "SHA-256 Hash", ~line 56)
- Modify: `src/Crypto/crypto.c`
- Test: `test/test_crypto.cpp` (append)

- [ ] **Step 1: Write the failing test**

```cpp
TEST(TestDurability, SealUnsealRoundTrip) {
  uint8_t seal_key[32];
  ASSERT_EQ(crypto_random_bytes(seal_key, sizeof(seal_key)), CRABS_SUCCESS);

  const uint8_t plain[100];
  for (size_t byte_index = 0; byte_index < sizeof(plain); byte_index++) {
    plain[byte_index] = (uint8_t)(byte_index * 3);
  }
  uint8_t sealed[200];
  size_t sealed_len = 0;
  ASSERT_EQ(crypto_seal(seal_key, plain, sizeof(plain),
                        sealed, &sealed_len), CRABS_SUCCESS);
  // 12-byte IV + 100 ciphertext + 16-byte tag
  ASSERT_EQ(sealed_len, sizeof(plain) + 16 + 12);

  uint8_t out[128];
  size_t out_len = 0;
  ASSERT_EQ(crypto_unseal(seal_key, sealed, sealed_len, out, &out_len),
            CRABS_SUCCESS);
  ASSERT_EQ(out_len, sizeof(plain));
  EXPECT_EQ(memcmp(out, plain, sizeof(plain)), 0);

  // Tamper with one ciphertext byte -> authentication failure.
  sealed[20] ^= 0x01;
  EXPECT_EQ(crypto_unseal(seal_key, sealed, sealed_len, out, &out_len),
            CRABS_ERR_UNAUTHORIZED);
  sealed[20] ^= 0x01;

  // Wrong key -> authentication failure.
  uint8_t wrong_key[32];
  memcpy(wrong_key, seal_key, 32);
  wrong_key[0] ^= 0xFF;
  EXPECT_EQ(crypto_unseal(wrong_key, sealed, sealed_len, out, &out_len),
            CRABS_ERR_UNAUTHORIZED);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cmake --build build -j && ./build/test/testcrabs --gtest_filter='TestDurability.Seal*'
```
Expected: LINK/COMPILE ERROR — `crypto_seal` not declared.

- [ ] **Step 3: Implement**

In `src/Crypto/crypto.h`:

```c
// ============================================================
// At-Rest Sealing (§11.5): AES-256-GCM envelope for durable
// secrets (MSK at rest). Sealed layout: IV(12) + ciphertext + tag(16).
// ============================================================
#define CRABS_SEAL_OVERHEAD 28   // 12-byte IV + 16-byte GCM tag

crabs_error_e crypto_seal(const uint8_t key[32],
                            const uint8_t* plain, size_t plain_len,
                            uint8_t* sealed, size_t* sealed_len);
crabs_error_e crypto_unseal(const uint8_t key[32],
                              const uint8_t* sealed, size_t sealed_len,
                              uint8_t* plain, size_t plain_cap,
                              size_t* plain_len);
```

In `src/Crypto/crypto.c` (include `<openssl/evp.h>` at the top of the OpenSSL
includes if not already present):

```c
// ============================================================
// At-Rest Sealing (§11.5)
// ============================================================

// AES-256-GCM helper: run one encrypt/decrypt pass. Returns OpenSSL EVP
// bytes written through out_len, or -1 on failure.
static int _aes_gcm_crypt(bool encrypt,
                            const uint8_t key[32], const uint8_t iv[12],
                            const uint8_t* input, size_t input_len,
                            uint8_t* output, uint8_t tag[16],
                            const uint8_t* tag_in) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return -1;
  int result = -1;

  do {
    if (EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv, encrypt) != 1)
      break;
    int out_len_tmp = 0;
    if (EVP_CipherUpdate(ctx, output, &out_len_tmp, input, (int)input_len) != 1)
      break;
    int written = out_len_tmp;
    if (encrypt) {
      if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) break;
    } else {
      if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag_in) != 1)
        break;
    }
    result = written;
  } while (false);

  EVP_CIPHER_CTX_free(ctx);
  return result;
}

crabs_error_e crypto_seal(const uint8_t key[32],
                            const uint8_t* plain, size_t plain_len,
                            uint8_t* sealed, size_t* sealed_len) {
  if (!key || (!plain && plain_len) || !sealed || !sealed_len) return CRABS_ERR_ARGS;
  if (*sealed_len < plain_len + CRABS_SEAL_OVERHEAD) return CRABS_ERR_ARGS;
  uint8_t iv[12];
  crabs_error_e err = crypto_random_bytes(iv, sizeof(iv));
  if (err != CRABS_SUCCESS) return err;
  memcpy(sealed, iv, 12);
  uint8_t* ciphertext = sealed + 12;
  uint8_t* tag = sealed + 12 + plain_len;
  if (_aes_gcm_crypt(true, key, iv, plain, plain_len, ciphertext, tag, NULL) < 0)
    return CRABS_ERR_EXEC;
  *sealed_len = plain_len + 12 + 16;
  return CRABS_SUCCESS;
}

crabs_error_e crypto_unseal(const uint8_t key[32],
                              const uint8_t* sealed, size_t sealed_len,
                              uint8_t* plain, size_t plain_cap,
                              size_t* plain_len) {
  if (!key || !sealed || !plain || !plain_len) return CRABS_ERR_ARGS;
  if (sealed_len < CRABS_SEAL_OVERHEAD) return CRABS_ERR_ARGS;
  size_t cipher_len = sealed_len - 12 - 16;
  if (cipher_len > plain_cap) return CRABS_ERR_ARGS;
  const uint8_t* iv = sealed;
  const uint8_t* ciphertext = sealed + 12;
  const uint8_t* tag = sealed + 12 + cipher_len;

  uint8_t scratch[65536];
  if (cipher_len > sizeof(scratch)) return CRABS_ERR_ARGS;
  int written = _aes_gcm_crypt(false, key, iv, ciphertext, cipher_len,
                                 scratch, NULL, tag);
  if (written < 0) return CRABS_ERR_UNAUTHORIZED;   // tag mismatch
  memcpy(plain, scratch, (size_t)written);
  *plain_len = (size_t)written;
  return CRABS_SUCCESS;
}
```

NOTE FOR THE IMPLEMENTER: the fixed 64 KiB scratch bounds attacker-supplied
MSK sections before authentication; MSK blobs in practice are a few KiB. If
`CRABS_ERR_UNAUTHORIZED`/`CRABS_ERR_ARGS` are not the exact enumerator names
in `crabs.h`, use the real ones (check `src/CRABS/crabs.h:20-70`).

- [ ] **Step 4: Run test to verify it passes**

```bash
cmake --build build -j && ./build/test/testcrabs --gtest_filter='TestDurability.Seal*'
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/Crypto/crypto.h src/Crypto/crypto.c test/test_crypto.cpp
git commit -m "feat: AES-256-GCM seal/unseal for durable secrets at rest"
```

---

### Task 3: Serialization v10 — op_type_defs, users + keyring, manifest space, MSK

**Files:**
- Modify: `src/Serialization/serialization.h:21` (version bump), API additions near state functions (~line 44)
- Modify: `src/Serialization/serialization.c` (serialize path after triggers, ~line 1440; deserialize after trigger restore)
- Test: `test/test_serialization.cpp` (append)

**Layout decision for v10** (appended after the v9 triggers section, BEFORE the checksum — order is contractual because the blob is sequential):

```
[v9 sections as today]
op_type_defs     : u32 count; entries { string16 op_type; dedup spec (below) }
user_registry    : u32 user_count; entries (below)
child_manifest   : u32 child_count  -- RESERVED in v10.0: Plan 1 always
                    writes 0 here and Plan 2 fills the section (format v10
                    layout final now, content arrives then)
msk              : u8 flag (0=absent; 1=sealed); if 1: u32 sealed_len + sealed
                    bytes (crypto_seal, 32-byte seal key)
[SHA-256 checksum as today]
```

User entry:
```
string16 user_id; u8 status; u64 key_version; u64 created_at; u64 updated_at;
u32 attribute_count; attributes { string16 value; string16 verified_by;
    u64 verified_at; u64 expires_at };
33-byte legacy public_key (fixed);
string16 default_key_id; u32 key_count;
keys { string16 key_id; u8 scheme; u32 public_key_len + bytes;
       string16 label; u64 registered_at; u64 last_used_at; u8 status;
       u64 expires_at; u64 suspended_at; u64 revoked_at;
       string16 predecessor_key_id };
u32 temp_attr_count; temp attrs { string16 name; string16 value;
    u64 issued_at; u64 expires_at }
```
(Serializer writes attributes inline including the `name` value embedded in
`attribute_value_t::value`; user_t stores role strings like `role:admin` —
the name/value split for persistence is preserved by serializing the
attribute's `value` field only, matching how `attribute_machine_find_attribute`
keys on `name`. The attribute NAME is recoverable from the value prefix
`name:value` — see the deserialize test asserting `role:admin` round-trips.)

Dedup spec entry:
```
u8 dedup_type; u32 tracker_path (string16); u32 flag_path (string16);
u32 condition (string16); mutation {u8 mutation_type; string16 set_path;
string16 element_value; string16 flag_path; string16 counter_path;
s64 delta; string16 target_path; string16 value};
string16 rejection_message
```

- [ ] **Step 1: Write the failing tests**

Append to `test/test_serialization.cpp`:

```cpp
TEST(TestSerialization, V10OpTypeDefsRoundTrip) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  dedup_spec_t spec = {0};
  spec.type = DEDUP_PER_USER;
  strncpy(spec.tracker_path, "trackers/op1", sizeof(spec.tracker_path) - 1);
  strncpy(spec.rejection_message, "duplicate op", sizeof(spec.rejection_message) - 1);
  ASSERT_EQ(state_add_op_type_def(state, "vote-once", &spec), CRABS_SUCCESS);

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);
  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);

  const op_type_def_t* def = state_find_op_type_def(restored, "vote-once");
  ASSERT_NE(def, nullptr);
  EXPECT_EQ(def->dedup.type, DEDUP_PER_USER);
  EXPECT_STREQ(def->dedup.tracker_path, "trackers/op1");
  EXPECT_STREQ(def->dedup.rejection_message, "duplicate op");

  serialized_buffer_destroy(buf);
  state_destroy(state);
  state_destroy(restored);
}

TEST(TestSerialization, V10UserRegistryRoundTripPreservesAttributesAndKeys) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  // Simulate a CLI-style machine: an attribute machine holding users.
  state->attr_machine = get_clear_memory(sizeof(attribute_machine_t));
  state->attr_machine->base_state = *state;   // alias for pointer wiring only
  user_t* writer = get_clear_memory(sizeof(user_t));
  strncpy(writer->user_id, "alice", CRABS_MAX_USER_ID - 1);
  writer->status = USER_ACTIVE;
  writer->key_version = 3;
  strncpy(writer->attributes[0].value, "role:writer", CRABS_MAX_POLICY_EXPR - 1);
  writer->attribute_count = 1;
  // Crypto random 33-byte key material is NOT validated here — serialization
  // is a byte-level round trip; validation belongs to register_user.
  user_key_t* key = get_clear_memory(sizeof(user_key_t));
  strncpy(key->key_id, "k1", CRABS_MAX_KEY_ID - 1);
  key->scheme = SIG_SCHEME_ECDSA_SECP256K1;
  key->public_key_len = 33;
  for (int byte_index = 0; byte_index < 33; byte_index++)
    key->public_key[byte_index] = (uint8_t)(byte_index + 1);
  key->status = KEY_ACTIVE;
  writer->keys = key;
  writer->key_count = 1;
  strncpy(writer->default_key_id, "k1", CRABS_MAX_KEY_ID - 1);
  state->attr_machine->users = writer;
  state->attr_machine->user_count = 1;
  // detach so state_destroy does not double free: we free manually below.

  serialized_buffer_t* buf = crabs_serialize_state(state);
  ASSERT_NE(buf, nullptr);

  state->attr_machine->users = NULL;   // detach before destroy
  state->attr_machine->base_state.attr_machine = NULL;
  state_destroy(state);
  user_key_destroy_all(writer);
  free(writer);

  state_t* restored = crabs_deserialize_state(buf->data, buf->len);
  ASSERT_NE(restored, nullptr);
  ASSERT_NE(restored->attr_machine, nullptr);
  user_t* restored_writer = attribute_machine_find_user(restored->attr_machine, "alice");
  ASSERT_NE(restored_writer, nullptr);
  EXPECT_EQ(restored_writer->status, USER_ACTIVE);
  EXPECT_EQ(restored_writer->key_version, 3);
  EXPECT_TRUE(attribute_machine_user_has_role(restored_writer, "role:writer"));
  ASSERT_EQ(restored_writer->key_count, 1);
  ASSERT_NE(restored_writer->keys, nullptr);
  EXPECT_STREQ(restored_writer->keys->key_id, "k1");
  EXPECT_EQ(restored_writer->keys->scheme, SIG_SCHEME_ECDSA_SECP256K1);
  EXPECT_EQ(restored_writer->keys->public_key[0], 1);

  state_destroy(restored);
  serialized_buffer_destroy(buf);
}

TEST(TestSerialization, V10SealedMskRoundTripRestoresAuthority) {
  state_t* state = state_create();
  ASSERT_NE(state, nullptr);
  uint8_t seal_key[32];
  ASSERT_EQ(crypto_random_bytes(seal_key, sizeof(seal_key)), CRABS_SUCCESS);

  serialized_buffer_t* buf = crabs_serialize_state_sealed(state, seal_key);
  ASSERT_NE(buf, nullptr);

  // Wrong key: substrate restores, MSK stays fresh.
  uint8_t wrong_key[32];
  memcpy(wrong_key, seal_key, 32);
  wrong_key[0] ^= 0xFF;
  state_t* wrong = crabs_deserialize_state_keys(buf->data, buf->len, wrong_key);
  ASSERT_NE(wrong, nullptr);
  ASSERT_NE(wrong->abe_mk, nullptr);   // fresh key, never NULL
  state_destroy(wrong);

  // Correct key: the restored MSK matches the original bit-for-bit (same
  // serialized MPK bytes) — the authority is preserved.
  uint8_t* original_msk = (uint8_t*)malloc(16384);
  size_t original_len = crypto_master_key_serialize(state->abe_mk, original_msk, 16384);
  ASSERT_GT(original_len, 0);

  state_t* restored = crabs_deserialize_state_keys(buf->data, buf->len, seal_key);
  ASSERT_NE(restored, nullptr);
  uint8_t* restored_msk = (uint8_t*)malloc(16384);
  size_t restored_len = crypto_master_key_serialize(restored->abe_mk, restored_msk, 16384);
  ASSERT_EQ(restored_len, original_len);
  EXPECT_EQ(memcmp(restored_msk, original_msk, original_len), 0);
  free(original_msk);
  free(restored_msk);

  // No key: MSK section cannot be unsealed — substrate restores with a FRESH
  // MSK (the compat path), never NULL.
  state_t* fresh = crabs_deserialize_state_keys(buf->data, buf->len, NULL);
  ASSERT_NE(fresh, nullptr);
  state_destroy(fresh);

  state_destroy(restored);
  serialized_buffer_destroy(buf);
  state_destroy(state);
}
```

NOTE: `state_add_op_type_def` / `state_find_op_type_def` — confirm the real
names for the dedup-registry add/find functions in `data_model.h`/`data_model.c`
and use those. If the add-path is `state_add_op_type_def(state, const char*, const dedup_spec_t*)`
use it; if it differs (e.g. `state_define_op_type`), adjust BOTH test and
plan call in this task before implementing.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cmake --build build -j && ./build/test/testcrabs --gtest_filter='TestSerialization.V10*'
```
Expected: COMPILE/LINK ERROR — `crabs_serialize_state_sealed` and
`crabs_deserialize_state_keys` undeclared.

- [ ] **Step 3: Implement**

In `src/Serialization/serialization.h`:

```c
#define CRABS_SERIAL_VERSION    10     // v10: users, keys, op_type_defs, MSK

// v10 keyed variants. crabs_serialize_state_sealed persists the machine's
// ABE master key sealed with AES-256-GCM under seal_key (32 bytes). The
// unkeyed APIs keep v9 semantics (no MSK section). crabs_deserialize_state_keys
// restores the sealed MSK when seal_key is provided and matches; when the
// file carries a sealed MSK but seal_key is NULL, the state loads with a
// FRESH MSK (substrate-only compatibility path) — the caller must treat
// authority as unproven in that case.
serialized_buffer_t* crabs_serialize_state_sealed(const state_t* state,
                                                    const uint8_t seal_key[32]);
state_t*             crabs_deserialize_state_keys(const uint8_t* data, size_t len,
                                                    const uint8_t seal_key[32]);
```

In `src/Serialization/serialization.c`, add static serializers before
`crabs_serialize_state` (pattern: the existing `_serialize_*` helpers) and
wire into `crabs_serialize_state` between the triggers section (line ~1440)
and the checksum (line ~1448):

```c
static void _serialize_dedup_spec(write_buf_t* buf, const dedup_spec_t* spec) {
  _write_uint8(buf, (uint8_t)spec->type);
  _write_string16(buf, spec->tracker_path);
  _write_string16(buf, spec->flag_path);
  _write_string16(buf, spec->condition);
  _write_uint8(buf, (uint8_t)spec->update.type);
  _write_string16(buf, spec->update.set_path);
  _write_string16(buf, spec->update.element_value);
  _write_string16(buf, spec->update.flag_path);
  _write_string16(buf, spec->update.counter_path);
  _write_uint64_le(buf, (uint64_t)spec->update.delta);
  _write_string16(buf, spec->update.target_path);
  _write_string16(buf, spec->update.value);
  _write_string16(buf, spec->rejection_message);
}

static void _serialize_user(write_buf_t* buf, const user_t* user) {
  _write_string16(buf, user->user_id);
  _write_uint8(buf, (uint8_t)user->status);
  _write_uint64_le(buf, user->key_version);
  _write_uint64_le(buf, user->created_at);
  _write_uint64_le(buf, user->updated_at);
  _write_uint32_le(buf, user->attribute_count);
  for (uint32_t attribute_index = 0; attribute_index < user->attribute_count;
       attribute_index++) {
    const attribute_value_t* attribute = &user->attributes[attribute_index];
    _write_string16(buf, attribute->value);
    _write_string16(buf, attribute->verified_by);
    _write_uint64_le(buf, attribute->verified_at);
    _write_uint64_le(buf, attribute->expires_at);
  }
  _write_bytes(buf, user->public_key, 33);
  _write_string16(buf, user->default_key_id);
  _write_uint32_le(buf, user->key_count);
  for (user_key_t* key = user->keys; key != NULL; key = key->next) {
    _write_string16(buf, key->key_id);
    _write_uint8(buf, (uint8_t)key->scheme);
    _write_uint32_le(buf, key->public_key_len);
    _write_bytes(buf, key->public_key, key->public_key_len);
    _write_string16(buf, key->label);
    _write_uint64_le(buf, key->registered_at);
    _write_uint64_le(buf, key->last_used_at);
    _write_uint8(buf, (uint8_t)key->status);
    _write_uint64_le(buf, key->expires_at);
    _write_uint64_le(buf, key->suspended_at);
    _write_uint64_le(buf, key->revoked_at);
    _write_string16(buf, key->predecessor_key_id);
  }
  // temp attrs: the linked list has no count field — count first.
  uint32_t temp_count = 0;
  for (temp_attr_list_t* temp = user->temp_attrs; temp != NULL; temp = temp->next)
    temp_count++;
  _write_uint32_le(buf, temp_count);
  for (temp_attr_list_t* temp = user->temp_attrs; temp != NULL; temp = temp->next) {
    _write_string16(buf, temp->name);
    _write_string16(buf, temp->value);
    _write_uint64_le(buf, temp->issued_at);
    _write_uint64_le(buf, temp->expires_at);
  }
}
```

In `crabs_serialize_state`, after the triggers block and before the checksum:

```c
  // op_type_defs (v10): the dedup registry — it was previously not persisted.
  _write_uint32_le(buf, state->op_type_def_count);
  for (uint32_t def_index = 0; def_index < state->op_type_def_count; def_index++) {
    _write_string16(buf, state->op_type_defs[def_index].op_type);
    _serialize_dedup_spec(buf, &state->op_type_defs[def_index].dedup);
  }

  // user registry (v10): users live on the linked attribute machine.
  uint32_t user_count = 0;
  if (state->attr_machine != NULL) user_count = state->attr_machine->user_count;
  _write_uint32_le(buf, user_count);
  if (state->attr_machine != NULL) {
    for (user_t* user = state->attr_machine->users; user != NULL; user = user->next) {
      _serialize_user(buf, user);
    }
  }

  // child manifest (v10): count placeholder — Plan 2 fills this section.
  _write_uint32_le(buf, 0);

  // MSK (v10): sealed under seal_key. The unkeyed serializer omits the MSK
  // (flag 0) — persisting an UNSEALED master key is never valid.
  uint8_t msk_present = (state->abe_mk != NULL) ? 1 : 0;
  _write_uint8(buf, msk_present);
  if (msk_present) {
    uint8_t msk_blob[16384];
    size_t msk_len = crypto_master_key_serialize(state->abe_mk, msk_blob, sizeof(msk_blob));
    uint8_t sealed_msk[16384 + CRABS_SEAL_OVERHEAD];
    size_t sealed_len = sizeof(sealed_msk);
    if (msk_len == 0 || seal_key == NULL ||
        crypto_seal(seal_key, msk_blob, msk_len, sealed_msk, &sealed_len) != CRABS_SUCCESS) {
      free(buf->data); free(buf); return NULL;   // fail loud: cannot persist authority
    }
    OPENSSL_cleanse(msk_blob, sizeof(msk_blob));
    _write_uint32_le(buf, (uint32_t)sealed_len);
    _write_bytes(buf, sealed_msk, sealed_len);
  }
```

In the keyed variants (new public functions in serialization.c): the
serializer's only difference between `crabs_serialize_state` and
`crabs_serialize_state_sealed` is the `seal_key` argument, so the ENTIRE body
of the current `crabs_serialize_state` moves into a static
`_serialize_state_internal(const state_t* state, const uint8_t seal_key[32])`,
and both public functions become thin wrappers:

```c
serialized_buffer_t* crabs_serialize_state(const state_t* state) {
  return _serialize_state_internal(state, NULL);
}

serialized_buffer_t* crabs_serialize_state_sealed(const state_t* state,
                                                    const uint8_t seal_key[32]) {
  if (state == NULL || seal_key == NULL) return NULL;
  // Fail loud: a "sealed" write without the machine's authority is not the
  // sealed format at all.
  if (state->abe_mk == NULL) return NULL;
  return _serialize_state_internal(state, seal_key);
}
```

And inside `_serialize_state_internal`, the sealed path fails the whole
serialize (returns NULL) when `state->abe_mk != NULL && seal_key == NULL` —
do NOT write flag 0 on the sealed path. The UNKEYED path
(`crabs_serialize_state`) keeps writing MSK flag 0 (substrate-only, same
as the v9 behavior of losing the MSK) so the dozens of existing library-level
tests that round-trip bare states keep working; the fail-loud ENFORCEMENT is
the CLI (`cli_node_save` refuses without a seal key, Task 4).

Deserialization: in `crabs_deserialize_state`, after the trigger restore and
before the checksum, gate on `version >= 10`:

```c
  // op_type_defs (v10)
  if (version >= 10) {
    uint32_t def_count;
    if (!_read_uint32_le(&buf, &def_count)) goto fail;
    if (def_count > CRABS_MAX_OP_TYPE_DEFS) goto fail;
    state->op_type_def_count = 0;
    for (uint32_t def_index = 0; def_index < def_count; def_index++) {
      op_type_def_t def;
      memset(&def, 0, sizeof(def));
      if (!_read_string16(&buf, def.op_type, CRABS_MAX_OP_NAME)) goto fail;
      uint8_t dedup_type;
      if (!_read_uint8(&buf, &dedup_type)) goto fail;
      def.dedup.type = (dedup_type_e)dedup_type;
      if (!_read_string16(&buf, def.dedup.tracker_path, CRABS_MAX_DEDUP_PATH)) goto fail;
      if (!_read_string16(&buf, def.dedup.flag_path, CRABS_MAX_DEDUP_PATH)) goto fail;
      if (!_read_string16(&buf, def.dedup.condition, CRABS_MAX_POLICY_EXPR)) goto fail;
      uint8_t mutation_type;
      if (!_read_uint8(&buf, &mutation_type)) goto fail;
      def.dedup.update.type = (mutation_type_e)mutation_type;
      if (!_read_string16(&buf, def.dedup.update.set_path, CRABS_MAX_DEDUP_PATH)) goto fail;
      if (!_read_string16(&buf, def.dedup.update.element_value, CRABS_MAX_USER_ID)) goto fail;
      if (!_read_string16(&buf, def.dedup.update.flag_path, CRABS_MAX_DEDUP_PATH)) goto fail;
      if (!_read_string16(&buf, def.dedup.update.counter_path, CRABS_MAX_DEDUP_PATH)) goto fail;
      uint64_t delta;
      if (!_read_uint64_le(&buf, &delta)) goto fail;
      def.dedup.update.delta = (int64_t)delta;
      if (!_read_string16(&buf, def.dedup.update.target_path, CRABS_MAX_DEDUP_PATH)) goto fail;
      if (!_read_string16(&buf, def.dedup.update.value, CRABS_MAX_DEDUP_PATH)) goto fail;
      if (!_read_string16(&buf, def.dedup.rejection_message, CRABS_MAX_DEDUP_MESSAGE)) goto fail;
      state->op_type_defs[state->op_type_def_count++] = def;
    }

    // user registry (v10): rebuild the user list on the state's (fresh) attr
    // machine shell so ownership matches state_create's
    // (users are freed by attribute_machine_destroy / state_destroy paths the
    // CLI already exercise — mirror cli.c:295-301 wiring).
    if (!_read_uint32_le(&buf, &user_count)) goto fail;
    if (user_count > CRABS_DESER_MAX_USERS) goto fail;
    for (uint32_t user_index = 0; user_index < user_count; user_index++) {
      if (!_deserialize_user(&buf, state->attr_machine)) goto fail;
    }

    // child manifest (v10): count is expected 0 until Plan 2; skip strictly.
    uint32_t child_count;
    if (!_read_uint32_le(&buf, &child_count)) goto fail;
    if (child_count != 0) goto fail;

    // MSK (v10)
    uint8_t msk_present;
    if (!_read_uint8(&buf, &msk_present)) goto fail;
    if (msk_present != 0) {
      uint32_t sealed_len;
      if (!_read_uint32_le(&buf, &sealed_len)) goto fail;
      if (sealed_len > 65536 + 64) goto fail;
      uint8_t* sealed_blob = get_memory(sealed_len);
      if (!sealed_blob) goto fail;
      if (!_read_bytes(&buf, sealed_blob, sealed_len)) { free(sealed_blob); goto fail; }
      if (seal_key != NULL) {
        uint8_t msk_plain[16384];
        size_t msk_plain_len = 0;
        if (crypto_unseal(seal_key, sealed_blob, sealed_len,
                          msk_plain, sizeof(msk_plain), &msk_plain_len) == CRABS_SUCCESS) {
          abe_master_key_t* restored_mk =
              crypto_master_key_deserialize(msk_plain, msk_plain_len);
          OPENSSL_cleanse(msk_plain, sizeof(msk_plain));
          if (restored_mk != NULL) {
            crypto_abe_master_key_destroy(state->abe_mk);   // discard fresh key
            state->abe_mk = restored_mk;
          }
        }
        OPENSSL_cleanse(sealed_blob, sealed_len);
        // Wrong/absent seal key: keep the fresh MSK (compat), never null.
      }
      free(sealed_blob);
    }
  }
```

Add `_deserialize_user` (writes into an attribute machine the deserializer
creates as a shell when the saved blob had users — mirror the CLI's wiring at
cli.c:295-301 so `state->attr_machine` EXISTS after `crabs_deserialize_state`
when the user registry is non-empty):

```c
static bool _deserialize_user(read_buf_t* buf, attribute_machine_t* am) {
  user_t* user = get_clear_memory(sizeof(user_t));
  if (!user) return false;
  if (!_read_string16(buf, user->user_id, CRABS_MAX_USER_ID)) goto fail;
  uint8_t status;
  if (!_read_uint8(buf, &status)) goto fail;
  user->status = (user_status_e)status;
  if (!_read_uint64_le(buf, &user->key_version)) goto fail;
  if (!_read_uint64_le(buf, &user->created_at)) goto fail;
  if (!_read_uint64_le(buf, &user->updated_at)) goto fail;
  if (!_read_uint32_le(buf, &user->attribute_count)) goto fail;
  if (user->attribute_count > CRABS_MAX_ATTRIBUTES) goto fail;
  for (uint32_t index = 0; index < user->attribute_count; index++) {
    attribute_value_t* attribute = &user->attributes[index];
    char name_and_value[CRABS_MAX_POLICY_EXPR];
    if (!_read_string16(buf, attribute->value, CRABS_MAX_POLICY_EXPR)) goto fail;
    strncpy(name_and_value, attribute->value, sizeof(name_and_value) - 1);
    // Attribute name precedes the first ':' in the stored "name:value" pair.
    char* colon = strchr(name_and_value, ':');
    if (colon == NULL) goto fail;   // stored attributes always carry name:value
    *colon = '\0';
    strncpy(attribute->verified_by, "", 1);
    if (!_read_string16(buf, attribute->verified_by, CRABS_MAX_USER_ID)) goto fail;
    if (!_read_uint64_le(buf, &attribute->verified_at)) goto fail;
    if (!_read_uint64_le(buf, &attribute->expires_at)) goto fail;
    (void)name_and_value;   // name is implicit in attribute->value lookups
  }
  if (!_read_bytes(buf, user->public_key, 33)) goto fail;
  if (!_read_string16(buf, user->default_key_id, CRABS_MAX_KEY_ID)) goto fail;
  if (!_read_uint32_le(buf, &user->key_count)) goto fail;
  if (user->key_count > CRABS_MAX_KEYS_PER_USER) goto fail;
  user_key_t** key_tail = &user->keys;
  for (uint32_t key_index = 0; key_index < user->key_count; key_index++) {
    user_key_t* key = get_clear_memory(sizeof(user_key_t));
    if (!key) goto fail;
    if (!_read_string16(buf, key->key_id, CRABS_MAX_KEY_ID)) goto fail;
    uint8_t scheme;
    if (!_read_uint8(buf, &scheme)) goto fail;
    key->scheme = (signature_scheme_e)scheme;
    if (!_read_uint32_le(buf, &key->public_key_len)) goto fail;
    if (key->public_key_len > CRABS_MAX_PUBLIC_KEY) goto fail;
    if (!_read_bytes(buf, key->public_key, key->public_key_len)) goto fail;
    if (!_read_string16(buf, key->label, CRABS_MAX_KEY_LABEL)) goto fail;
    if (!_read_uint64_le(buf, &key->registered_at)) goto fail;
    if (!_read_uint64_le(buf, &key->last_used_at)) goto fail;
    uint8_t key_status;
    if (!_read_uint8(buf, &key_status)) goto fail;
    key->status = (key_status_e)key_status;
    if (!_read_uint64_le(buf, &key->expires_at)) goto fail;
    if (!_read_uint64_le(buf, &key->suspended_at)) goto fail;
    if (!_read_uint64_le(buf, &key->revoked_at)) goto fail;
    if (!_read_string16(buf, key->predecessor_key_id, CRABS_MAX_KEY_ID)) goto fail;
    *key_tail = key;
    key_tail = &key->next;
  }
  uint32_t temp_count;
  if (!_read_uint32_le(buf, &temp_count)) goto fail;
  temp_attr_list_t** temp_tail = &user->temp_attrs;
  for (uint32_t temp_index = 0; temp_index < temp_count; temp_index++) {
    temp_attr_list_t* temp = get_clear_memory(sizeof(temp_attr_list_t));
    if (!temp) goto fail;
    if (!_read_string16(buf, temp->name, CRABS_MAX_POLICY_EXPR)) goto fail;
    if (!_read_string16(buf, temp->value, CRABS_MAX_POLICY_EXPR)) goto fail;
    if (!_read_uint64_le(buf, &temp->issued_at)) goto fail;
    if (!_read_uint64_le(buf, &temp->expires_at)) goto fail;
    *temp_tail = temp;
    temp_tail = &temp->next;
  }
  // Splice into the machine's list (the attribute machine is the owner).
  user_t** user_tail = &am->users;
  while (*user_tail != NULL) user_tail = &(*user_tail)->next;
  *user_tail = user;
  user->next = NULL;
  am->user_count++;
  return true;
fail:
  user_key_destroy_all(user);
  temp_attr_list_t* temp_next;
  for (temp_attr_list_t* temp = user->temp_attrs; temp != NULL; temp = temp_next) {
    temp_next = temp->next;
    free(temp);
  }
  free(user);
  return false;
}
```

CONSTANT CHECKS FOR THE IMPLEMENTER (all in headers, resolve before
compiling): `CRABS_MAX_ATTRIBUTES`, `CRABS_DESER_MAX_USERS` (if none exists,
either add one at 4096 beside the other CRABS_DESER_MAX_* caps in
serialization.c, or reuse an existing user-cap constant — check first),
`SIG_SCHEME_ECDSA_SECP256K1` (confirm the enumerator name in
`src/Crypto/sig_scheme.h`), and the attribute name/value convention (verify
how `attribute_machine_find_attribute` matches names — if user_t keeps
name/value as separate parallel arrays rather than the embedded
`name:value` string, serialize BOTH the name and value explicitly instead of
the split-on-colon logic and adjust the round-trip test to match).

- [ ] **Step 4: Run tests to verify they pass**

```bash
cmake --build build -j && ./build/test/testcrabs --gtest_filter='TestSerialization.*'
```
Expected: all pass (existing v9-era tests still green — the version gate
keeps old layouts parseable only as v10+ sections gated off).

- [ ] **Step 5: Run the full suite**

```bash
ctest --test-dir build/test --output-on-failure
```
Expected: green. If `test_cli.cpp` save tests fail, that is Task 4's scope —
fix them there, not here.

- [ ] **Step 6: Commit**

```bash
git add src/Serialization/serialization.h src/Serialization/serialization.c test/test_serialization.cpp
git commit -m "feat: serialization v10 — users, keyring, op-type defs, manifest space, sealed MSK"
```

---

### Task 4: CLI seal-key custody + save fail-loud + alias single authority

**Files:**
- Modify: `src/CLI/cli.h` (`cli_node_t` fields + new functions, ~lines 38-97)
- Modify: `src/CLI/cli.c` (init 134-163, load 203-309, save 384-429, dispatch ~1170)
- Test: `test/test_cli.cpp` (append + adjust the existing `save` test)

- [ ] **Step 1: Adjust existing save tests, then write new failing tests**

`crabs_serialize_state_sealed` fail-loud changes the contract: `cli_node_save`
now requires a seal key. In `test/test_cli.cpp`, every test that calls
`cli_node_save` gains, before the save:

```cpp
extern "C" {
#include "../src/Crypto/crypto.h"
}

// Shared in-file helper (add ONCE near the top of the test file):
static bool _apply_test_seal_key(cli_node_t* node) {
  const uint8_t test_seal_key[32] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
  };
  memcpy(node->seal_key, test_seal_key, sizeof(test_seal_key));
  node->seal_key_valid = true;
  return true;
}
```

New tests:

```cpp
TEST(TestCliDurability, SaveRefusesWithoutSealKey) {
  cli_node_t* node = cli_node_create();
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  EXPECT_NE(cli_node_save(node, "/tmp/crabs-noseal.crabs"), CLI_OK);
  cli_node_destroy(node);
}

TEST(TestCliDurability, SealKeyRoundTripPreservesUsersAndAuthority) {
  cli_node_t* node = cli_node_create();
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);
  ASSERT_TRUE(_apply_test_seal_key(node));
  // Register a second user through the attribute machine:
  ecdsa_keypair_t* other = crypto_ecdsa_generate();
  ASSERT_NE(other, nullptr);
  ASSERT_EQ(attribute_machine_register_user(node->attr_machine, "writer",
            other->public_key, "role:writer"), CRABS_SUCCESS);
  crypto_ecdsa_keypair_destroy(other);

  ASSERT_EQ(cli_node_save(node, "/tmp/crabs-durable.crabs"), CLI_OK);
  cli_node_destroy(node);

  cli_node_t* reloaded = cli_node_create();
  const uint8_t test_seal_key[32] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
  };
  uint8_t seal_hex[65];
  cli_bytes_to_hex(test_seal_key, 32, (char*)seal_hex);
  seal_hex[64] = '\0';
  ASSERT_EQ(cli_node_load_sealed(reloaded, "/tmp/crabs-durable.crabs",
            (const char*)seal_hex), CLI_OK);
  ASSERT_NE(attribute_machine_find_user(reloaded->attr_machine, "writer"), nullptr);
  ASSERT_NE(attribute_machine_find_user(reloaded->attr_machine, "admin"), nullptr);
  // Authority preserved: the reloaded MSK is in the same domain (it can
  // mint a user key that verifies against the machine's policy engine).
  user_t* writer = attribute_machine_find_user(reloaded->attr_machine, "writer");
  ASSERT_NE(writer, nullptr);
  abe_user_key_t* sk = crypto_abe_keygen(reloaded->attr_machine->base_state.abe_mk, "role:writer");
  ASSERT_NE(sk, nullptr);
  crypto_abe_user_key_destroy(sk);
  cli_node_destroy(reloaded);
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cmake --build build -j && ./build/test/testcrabs --gtest_filter='TestCliDurability.*'
```
Expected: COMPILE ERROR — `cli_node_load_sealed`, `seal_key` fields undeclared.

- [ ] **Step 3: Implement**

In `src/CLI/cli.h`, extend `cli_node_t` (after `loaded_unauthenticated`):

```c
  // Durability (v10): the operator's at-rest seal key for the machine MSK.
  // 32 raw bytes imported from a keyfile; never serialized anywhere.
  uint8_t seal_key[32];
  bool    seal_key_valid;
```

And the API block (after `cli_node_save` in "Node Lifecycle"):

```c
// Import the at-rest seal key (64 hex chars, decoded to 32 raw bytes).
// Once set, cli_node_save persists the ABE MSK sealed under it; cli_node_load
// unseals a saved MSK with it. Invalidates on overwrite (re-import allowed —
// the key is replaced wholesale). Stored in memory only.
cli_result_e cli_node_set_seal_key(cli_node_t* node, const char* key_hex);
// Load a state file whose MSK section is encrypted; equivalent to
// cli_node_load for the substrate, plus unsealing the MSK. key_hex is the
// 64-hex-char seal key (required when the file carries one).
cli_result_e cli_node_load_sealed(cli_node_t* node, const char* path,
                                    const char* key_hex);
```

In `src/CLI/cli.c`:

1. `cli_node_init` (line 139): DELETE the `node->abe_mk = crypto_abe_setup();`
   block (lines 139-140) and the `node->abe_mk = NULL;`/destroy handling at
   103/122. Reason: the attribute machine's base_state.abe_mk
   (attribute_machine.c:301) is THE single live authority; the second
   node->abe_mk instance was a second, unrelated MSK domain (latent bug —
   envelopes signed at cli.c:800 against it used different params than op
   verification). Set `node->abe_mk = NULL;` everywhere and replace the
   cli.c:800 call site's `node->abe_mk` argument with
   `node->attr_machine->base_state.abe_mk`.

2. `cli_node_load` (lines 285-301): replace the fresh-MSK wiring. The loaded
   state (from `crabs_deserialize_state`) already carries a working
   base_state.abe_mk (restored-or-fresh, decided in Task 3); DELETE
   `node->abe_mk = crypto_abe_setup();` (line 291) — the node's pointer
   becomes `node->abe_mk = NULL;` and the envelope call sites use
   `base_state.abe_mk`. Everything else in the load path is untouched.

3. New functions (before `cli_node_save`):

```c
cli_result_e cli_node_set_seal_key(cli_node_t* node, const char* key_hex) {
  if (node == NULL || key_hex == NULL) return CLI_ERR_ARGS;
  if (strlen(key_hex) != 64) {
    fprintf(stderr, "ERROR: seal key must be 64 hex chars (32 bytes)\n");
    return CLI_ERR_ARGS;
  }
  if (cli_hex_to_bytes(key_hex, node->seal_key, 32) != CLI_OK) return CLI_ERR_ARGS;
  node->seal_key_valid = true;
  return CLI_OK;
}

cli_result_e cli_node_load_sealed(cli_node_t* node, const char* path,
                                    const char* key_hex) {
  if (node == NULL || path == NULL || key_hex == NULL) return CLI_ERR_ARGS;
  if (node->initialized) return CLI_ERR_ARGS;
  if (cli_node_set_seal_key(node, key_hex) != CLI_OK) return CLI_ERR_ARGS;

  cli_result_e result = cli_node_load(node, path);
  if (result != CLI_OK) {
    // Do not leave a half-imported seal key on a failed load.
    node->seal_key_valid = false;
    OPENSSL_cleanse(node->seal_key, sizeof(node->seal_key));
    return result;
  }
  // The state's own MSK was already restored or regenerated inside
  // crabs_deserialize_state[_keys]; clean the key material from node
  // storage? NO — keep it: subsequent cli_node_save needs the same key.
  return CLI_OK;
}
```

4. `cli_node_load`'s deserialize call (line ~253/273): keep the plain calls
   for back-compat BUT thread the seal key when the node already has one.
   Since `crabs_deserialize_state_keys(data, len, seal_key)` accepts NULL,
   replace BOTH call sites with
   `crabs_deserialize_state_keys(data, payload_or_file_len, node->seal_key_valid ? node->seal_key : NULL)`.
   `load-sealed` sets the key BEFORE calling load, so this is the only
   plumbing needed.

5. `cli_node_save` (after the loaded_unauthenticated gate, line ~407):

```c
  // Durability: refuse to persist without a seal key — an unsealed snapshot
  // silently loses the machine's authority (fresh MSK on reload).
  if (!node->seal_key_valid) {
    fprintf(stderr,
            "ERROR: refusing to save — no at-rest seal key imported; the "
            "machine's ABE master key would be lost. Run 'seal-key import "
            "<keyfile>' first\n");
    return CLI_ERR_EXEC;
  }
  serialized_buffer_t* buf =
      crabs_serialize_state_sealed(&node->attr_machine->base_state, node->seal_key);
```

(replacing the `crabs_serialize_state_signed` call at line ~412; the signed
trailer logic stays exactly as is — seal and sign compose.)

6. Dispatch (cli.c ~1197 block): extend the `load` and `save` groups with:

```c
  if (strcmp(cmd, "seal-key") == 0) {
    if (argc >= 3 && strcmp(argv[2], "import") == 0) {
      if (argc < 4) {
        printf("Usage: %s seal-key import <keyfile with 64 hex chars>\n", argv[0]);
        return CLI_ERR_ARGS;
      }
      char hex[65] = {0};
      FILE* seal_file = fopen(argv[3], "r");
      if (seal_file == NULL) return CLI_ERR_IO;
      if (fread(hex, 1, 64, seal_file) != 64) { fclose(seal_file); return CLI_ERR_IO; }
      fclose(seal_file);
      cli_result_e result = cli_node_set_seal_key(node, hex);
      memset(hex, 0, sizeof(hex));
      if (result == CLI_OK) printf("Seal key imported (in memory only).\n");
      return result;
    }
    printf("Usage: %s seal-key import <keyfile>\n", argv[0]);
    return CLI_ERR_ARGS;
  }

  if (strcmp(cmd, "load-sealed") == 0) {
    if (argc < 4) {
      printf("Usage: %s load-sealed <path> <seal-key-file>\n", argv[0]);
      return CLI_ERR_ARGS;
    }
    char hex[65] = {0};
    FILE* seal_file = fopen(argv[3], "r");
    if (seal_file == NULL) return CLI_ERR_IO;
    if (fread(hex, 1, 64, seal_file) != 64) { fclose(seal_file); return CLI_ERR_IO; }
    fclose(seal_file);
    cli_result_e result = cli_node_load_sealed(node, argv[2], hex);
    memset(hex, 0, sizeof(hex));
    return result;
  }
```

Both land BEFORE the init gate (line 1214) alongside `load`/`save`. Also add
`"load-sealed"` and `"seal-key"` to the accepted-command list at line 1214
(the `!=` strcmp chain: `strcmp(cmd, "seal-key") != 0 && strcmp(cmd,
"load-sealed") != 0 && ...`).

7. `cli_print_usage` gains the two new commands (locate near main.c's usage
   strings via `_print_state_usage` style helpers in cli.c).

NOTE FOR THE IMPLEMENTER: `cli_node_destroy` (cli.c:122) frees
`node->abe_mk` when non-NULL — after this task `node->abe_mk` is always
NULL, so the branch is dead; leave the null check in place (it is harmless)
but verify no double-free by compiling and running the full CLI test suite.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cmake --build build -j && ./build/test/testcrabs --gtest_filter='TestCliDurability.*'
ctest --test-dir build/test --output-on-failure
```
Expected: new tests pass; full suite green.

- [ ] **Step 5: Commit**

```bash
git add src/CLI/cli.h src/CLI/cli.c test/test_cli.cpp
git commit -m "feat: CLI seal-key custody, save fail-loud, single live MSK authority"
```

---

### Task 5: v9→v10 migration (`machine migrate`)

**Files:**
- Modify: `src/CLI/cli.h` (add `cli_result_e cli_cmd_machine_migrate(cli_node_t* node);`)
- Modify: `src/CLI/cli.c` (impl + dispatch)
- Test: `test/test_cli.cpp` (append)

- [ ] **Step 1: Write the failing test**

The legacy-load reproduction: a state file WITHOUT a user registry (what every
v9 file effectively restores to — the loader rebuilds the attr machine with
`users = NULL`, cli.c:295-301), loaded and then migrated.

```cpp
TEST(TestCliDurability, MigrateRebuildsBootstrapAdminOnLegacyLoad) {
  // 1. "Legacy" content: a state whose config names an admin but whose user
  //    registry is empty (what every v9 file effectively restores to).
  state_t* legacy_state = state_create();
  strncpy(legacy_state->config.bootstrap_admin, "admin",
          CRABS_MAX_USER_ID - 1);
  serialized_buffer_t* legacy_blob = crabs_serialize_state(legacy_state);
  ASSERT_NE(legacy_blob, nullptr);
  state_destroy(legacy_state);
  FILE* legacy_file = fopen("/tmp/crabs-legacy.crabs", "wb");
  ASSERT_NE(legacy_file, nullptr);
  fwrite(legacy_blob->data, 1, legacy_blob->len, legacy_file);
  fclose(legacy_file);
  serialized_buffer_destroy(legacy_blob);

  // 2. Load it the way the loader handles empty-registry files.
  cli_node_t* node = cli_node_create();
  ASSERT_EQ(cli_node_load(node, "/tmp/crabs-legacy.crabs"), CLI_OK);
  ASSERT_EQ(attribute_machine_find_user(node->attr_machine, "admin"), nullptr)
      << "legacy load must start with no restored users";

  // 3. Migrate re-enrolls the bootstrap admin.
  ASSERT_EQ(cli_cmd_machine_migrate(node), CLI_OK);
  user_t* admin = attribute_machine_find_user(node->attr_machine, "admin");
  ASSERT_NE(admin, nullptr);
  EXPECT_TRUE(attribute_machine_user_has_role(admin, "role:admin"));
  EXPECT_EQ(admin->key_version, 1);

  // 4. Now save-able and durable: with a seal key the machine persists and
  //    reloads WITH the admin intact (authority survives restart).
  _apply_test_seal_key(node);
  ASSERT_EQ(cli_node_save(node, "/tmp/crabs-migrated.crabs"), CLI_OK);
  cli_node_destroy(node);

  cli_node_t* reloaded = cli_node_create();
  const uint8_t test_seal_key[32] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
  };
  char seal_hex[65];
  cli_bytes_to_hex(test_seal_key, 32, seal_hex);
  seal_hex[64] = '\0';
  ASSERT_EQ(cli_node_load_sealed(reloaded, "/tmp/crabs-migrated.crabs", seal_hex), CLI_OK);
  admin = attribute_machine_find_user(reloaded->attr_machine, "admin");
  ASSERT_NE(admin, nullptr);
  EXPECT_TRUE(attribute_machine_user_has_role(admin, "role:admin"));
  cli_node_destroy(reloaded);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cmake --build build -j && ./build/test/testcrabs --gtest_filter='TestCliDurability.Migrate*'
```
Expected: COMPILE ERROR — `cli_cmd_machine_migrate` undeclared.

- [ ] **Step 3: Implement**

In `src/CLI/cli.c`:

```c
cli_result_e cli_cmd_machine_migrate(cli_node_t* node) {
  if (node == NULL || !node->initialized || node->attr_machine == NULL)
    return CLI_ERR_NOT_INIT;
  attribute_machine_t* am = node->attr_machine;

  if (am->users != NULL) {
    // A v10 file already carries its authority; migration is a no-op there.
    printf("Machine already carries a user registry — nothing to migrate.\n");
    return CLI_OK;
  }
  const char* admin_id = am->base_state.config.bootstrap_admin;
  if (admin_id[0] == '\0') {
    fprintf(stderr, "ERROR: state has no bootstrap_admin to re-enroll\n");
    return CLI_ERR_EXEC;
  }
  // Re-run the §8.3 genesis for the recorded bootstrap admin, keyed to the
  // operator's imported node key (cli_node_load_key) — identical to the
  // bootstrap block in attribute_machine_create (attribute_machine.c:307+).

cli_result_e cli_cmd_machine_migrate(cli_node_t* node) {
  if (node == NULL || !node->initialized || node->attr_machine == NULL)
    return CLI_ERR_NOT_INIT;
  attribute_machine_t* am = node->attr_machine;
  if (am->users != NULL) {
    printf("Machine already carries a user registry — nothing to migrate.\n");
    return CLI_OK;
  }
  const char* admin_id = am->base_state.config.bootstrap_admin;
  if (admin_id[0] == '\0') {
    fprintf(stderr, "ERROR: state has no bootstrap_admin to re-enroll\n");
    return CLI_ERR_EXEC;
  }
  crabs_error_e err = attribute_machine_register_user(am, admin_id,
      am->base_state.node_public_key, "role:admin");
  if (err != CRABS_SUCCESS) {
    fprintf(stderr, "ERROR: re-enrolling bootstrap admin failed: %s\n",
            cli_error_string(err));
    return CLI_ERR_EXEC;
  }
  printf("Migrated: bootstrap admin '%s' re-enrolled (key_version=1).\n", admin_id);
  return CLI_OK;
}
```

(If `attribute_machine_register_user` rejects the privileged `role:admin`
initial attribute per R7-08, use the two-step the machine's own genesis uses:
register with no attributes, then grant `role:admin` through the same
internal path attribute_machine_create uses — grant_role is admin-gated, so
if the API blocks this, call the internal registration the crate uses at
genesis and document the reason in the PR. Verify which path applies by
reading the R7-08 check in attribute_machine.c before coding.)

Dispatch (put next to `state accept-unverified` at cli.c:1242):

```c
    if (strcmp(sub, "migrate") == 0)  return cli_cmd_machine_migrate(node);
```

and update `_print_state_usage`.

- [ ] **Step 4: Run test to verify it passes, then full suite**

```bash
cmake --build build -j && ./build/test/testcrabs --gtest_filter='TestCliDurability.Migrate*'
ctest --test-dir build/test --output-on-failure
```

- [ ] **Step 5: Commit**

```bash
git add src/CLI/cli.h src/CLI/cli.c test/test_cli.cpp
git commit -m "feat: machine migrate re-enrolls bootstrap admin on legacy snapshots"
```

---

### Task 6: Full restart round-trip integration test

**Files:**
- Create: `test/test_durability.cpp`
- Modify: `test/CMakeLists.txt` (add `test_durability.cpp` to the
  `add_executable(testcrabs ...)` source list, alphabetical after
  `test_data_model.cpp`)

- [ ] **Step 1: Write the integration test**

```cpp
#include <gtest/gtest.h>
#include <cstdio>
extern "C" {
#include "../src/CLI/cli.h"
#include "../src/Crypto/crypto.h"
#include "../src/Serialization/serialization.h"
}

// The full custody round trip: live machine -> save (sealed) -> destroy ->
// load (sealed) -> same authority, same users, old signatures still valid.
TEST(TestDurability, FullMachineSurvivesRestartAndKeepsAuthority) {
  // 1. Build a live machine through the CLI layer.
  cli_node_t* node = cli_node_create();
  ASSERT_EQ(cli_node_init(node, "admin"), CLI_OK);

  const uint8_t test_seal_key[32] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
  };
  memcpy(node->seal_key, test_seal_key, 32);
  node->seal_key_valid = true;

  // Register a second user + register their key in the keyring.
  ecdsa_keypair_t* writer_key = crypto_ecdsa_generate();
  ASSERT_NE(writer_key, nullptr);
  ASSERT_EQ(attribute_machine_register_user(node->attr_machine, "writer",
            writer_key->public_key, "role:writer"), CRABS_SUCCESS);
  ASSERT_EQ(cli_node_add_user_key(node, "writer", writer_key), CLI_OK);

  // Define a custom op with a PER_USER dedup spec (exercises the v10
  // op_type_defs section) and execute it once.
  dedup_spec_t spec = {0};
  spec.type = DEDUP_NONE;
  ASSERT_EQ(state_add_op_type_def(&node->attr_machine->base_state,
            "heartbeat", &spec), CRABS_SUCCESS);
  state_add_policy(&node->attr_machine->base_state, "heartbeat", "role:writer|role:admin");

  operation_t* op = operation_create("heartbeat");
  ASSERT_NE(op, nullptr);
  cli_bytes_to_hex(node->state->node_public_key, 33, op_hex_placeholder_removed);
  ASSERT_EQ(state_machine_execute(&node->attr_machine->base_state, op),
            CRABS_SUCCESS);
  operation_destroy(op);

  // 2. Save sealed, destroy everything.
  ASSERT_EQ(cli_node_save(node, "/tmp/crabs-integration.crabs"), CLI_OK);
  cli_node_destroy(node);

  // 3. Reload with the same seal key.
  cli_node_t* reloaded = cli_node_create();
  char seal_hex[65];
  {
    const uint8_t same_seal_key[32] = {
      1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
      17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
    };
    cli_bytes_to_hex(same_seal_key, 32, seal_hex);
    seal_hex[64] = '\0';
  }
  ASSERT_EQ(cli_node_load_sealed(reloaded, "/tmp/crabs-integration.crabs", seal_hex), CLI_OK);

  // 4. Identity survived.
  ASSERT_NE(attribute_machine_find_user(reloaded->attr_machine, "writer"), nullptr);
  user_t* writer = attribute_machine_find_user(reloaded->attr_machine, "writer");
  EXPECT_TRUE(attribute_machine_user_has_role(writer, "role:writer"));
  EXPECT_EQ(reloaded->attr_machine->base_state.log_count, original_log_count);
  EXPECT_NE(state_find_op_type_def(&reloaded->attr_machine->base_state,
            "heartbeat"), nullptr);

  // 5. Authority survived: a heartbeat from the writer is still authorized
  //    (same ABE domain, same policy engine).
  ecdsa_keypair_t* writer_key_restored = cli_node_get_user_key(reloaded, "writer");
  // The CLI keyring is runtime-only; re-import the restored user key.
  ASSERT_EQ(cli_node_add_user_key(reloaded, "writer", writer_key), CLI_OK);
  operation_t* op2 = operation_create("heartbeat");
  ASSERT_NE(op2, nullptr);
  memcpy(op2->signer_id, "writer", strlen("writer") + 1);
  ASSERT_EQ(state_machine_execute(&reloaded->attr_machine->base_state, op2),
            CRABS_SUCCESS);
  operation_destroy(op2);

  cli_node_destroy(reloaded);
}
```

NOTE FOR THE IMPLEMENTER: sign-capture details — the writer's ECDSA key pair
is the object the CLI keyring custodies; `cli_node_destroy` frees keyring
entries that are not the node key, so `writer_key` ownership passes to the
node at `cli_node_add_user_key`. After `cli_node_destroy(node)`, the test
must NOT free `writer_key` again (the node did it). Generate a SECOND key
for the reloaded side (as written) or re-create one. Fix the two
placeholder-ish lines marked `removed` by writing the actual calls:

```cpp
  // capture before destroy (do this INSIDE step 1, before save):
  uint64_t original_log_count = node->attr_machine->base_state.log_count;
  // op signature: state_machine_execute signs via the CLI keyring; pass the
  // signer id on the op:
  memcpy(op->signer_id, "writer", strlen("writer") + 1);
```

and drop the `cli_bytes_to_hex(node->state->node_public_key, ...)` line and
the `ecdsa_keypair_t* writer_key_restored` line entirely (dead ends, not
needed).

- [ ] **Step 2: Run test to verify it fails**

```bash
cmake --build build/test -j && ./build/test/testcrabs --gtest_filter='TestDurability.FullMachine*'
```
Expected: FAIL — file not yet in the CMake source list, then assertion
failures expose any wiring missed in Tasks 3-5.

- [ ] **Step 3: Register the file and get green**

Add `test_durability.cpp` to `test/CMakeLists.txt`, rebuild, run:

```bash
ctest --test-dir build/test --output-on-failure
```
Expected: full suite green.

- [ ] **Step 4: Commit**

```bash
git add test/test_durability.cpp test/CMakeLists.txt
git commit -m "test: full restart round-trip preserves machine authority and users"
```

---

### Task 7: README trust-model + durability documentation

**Files:**
- Modify: `README.md` (trust/security-boundary section)

- [ ] **Step 1: Add the durability section**

Add to README.md under the trust-model/security section (create the section
header if absent):

```markdown
## Trust Boundaries: What Is Durable and What Is Not

From serialization v10, a saved machine carries its full authority —
users, key registries, operation-type definitions, and the CP-ABE MSK —
but the MSK **only** at rest under an operator-supplied AES-256-GCM seal
key. Concretely:

- **The MSK never hits disk unsealed.** Saving without a seal key is
  refused; loading with the wrong seal key restores the machine's substrate
  with a FRESH MSK. Authority must be treated as unproven in that state —
  re-enroll from the genesis admin (`crabs state migrate`) rather than
  trusting post-fresh-MSK signatures.
- **The seal key is the machine's crown jewel.** It lives in memory only.
  Anyone holding both the snapshot and the seal key holds the authority —
  treat snapshots with seal-key custody as equivalent to MSK custody.
- **Unsigned snapshots remain unauthenticated**, even in v10: the sealed
  format protects confidentiality of the authority, not provenance. Import
  the node key (`key import`) to verify saved snapshots, as before.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: trust boundaries for v10 sealed durability"
```

---

## Plan Handoff

**Spec coverage check** — Plan 1 covers the spec's Serialization & durability
section (v10 sections, MSK serialize + vault-style at-rest sealing, migration)
and the trust-model caveat for durability. NOT covered here (by design):
child manifest content + spawn/lineage ops + attestations (Plan 2), and the
CLI lineage commands + wasm + devtools surfaces (Plan 3).

**After this plan executes:**
- Plan 2 (lineage core): authored against the landed v10 APIs —
  `crabs_serialize_state_sealed`, `crypto_master_key_*`, the sealed loader,
  and the manifest position booked in v10.
- Plan 3 (surfaces): CLI machine commands, wasm bindings, devtools Lineage
  section — authored after Plan 2's ops land so bindings cite real symbols.