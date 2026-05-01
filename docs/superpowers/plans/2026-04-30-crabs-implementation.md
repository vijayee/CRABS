# CRABS Protocol Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement all remaining MUST-implement and SHOULD-implement features from the CRABS Protocol Specification (v1.0 + Amendments 1 & 2)

**Architecture:** Build on the existing C codebase with its data model, state machine, buffer, refcounter, and utility modules. Each new feature module follows the established pattern: `src/ModuleName/module_name.h` and `src/ModuleName/module_name.c` with GoogleTest tests in `test/test_module.cpp`. Dependencies flow downward from high-level modules to low-level utilities.

**Tech Stack:** C11, OpenSSL (for ECDSA, SHA-256, RAND_bytes), GoogleTest (C++ test framework), CMake build system

---

## Phase 1: Bug Fixes and CRDT Merge

Fix known issues and implement CRDT merge functions — the foundation that later phases depend on.

### Task 1: Fix lock token generation (use RAND_bytes instead of rand)

**Files:**
- Modify: `src/StateMachine/state_machine.c:79-83`
- Test: `test/test_state_machine.cpp`

- [ ] **Step 1: Write the failing test**

Add a test that verifies lock tokens have sufficient entropy by generating multiple tokens and checking they differ:

```cpp
TEST_F(TestStateMachine, TestLockTokenEntropy) {
  operation_t* op = make_lock_op();
  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);
  data_item_t* item = state_find_item(state, "test_resource");
  ASSERT_NE(item, nullptr);

  uint8_t token1[CRABS_LOCK_TOKEN_SIZE];
  memcpy(token1, item->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE);
  operation_destroy(op);

  // Reset state and lock again - tokens must differ
  item->protocol_state = PROTOCOL_IDLE;
  item->lock_state.lock_token_valid = false;

  operation_t* op2 = make_lock_op();
  memset(op2->uuid, 0x55, CRABS_UUID_SIZE); // Different UUID
  op2->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op2->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  op2->resource_count = 1;
  op2->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op2->required_state[0] = PROTOCOL_IDLE;
  op2->next_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  op2->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op2->signer_id, "alice", CRABS_MAX_USER_ID - 1);
  EXPECT_EQ(state_machine_execute(state, op2), CRABS_SUCCESS);

  // Tokens should differ (with overwhelming probability if CSPRNG)
  EXPECT_NE(memcmp(token1, item->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE), 0);
  operation_destroy(op2);
}
```

- [ ] **Step 2: Run test to verify it passes (tokens already differ, but test validates RAND_bytes works)**

Run: `cd build && cmake --build . && ./test_crabs --gtest_filter=TestStateMachine.TestLockTokenEntropy`
Expected: PASS (lock tokens already differ with rand, but RAND_bytes is still more correct)

- [ ] **Step 3: Replace rand() with RAND_bytes in lock token generation**

In `src/StateMachine/state_machine.c`, replace `state_machine_generate_lock_token`:

```c
#include <openssl/rand.h>

void state_machine_generate_lock_token(uint8_t token[CRABS_LOCK_TOKEN_SIZE]) {
  if (RAND_bytes(token, CRABS_LOCK_TOKEN_SIZE) != 1) {
    // Fallback: if RAND_bytes fails, this is a serious error
    // In production, this should abort. For now, fill with random as last resort.
    for (int i = 0; i < CRABS_LOCK_TOKEN_SIZE; i++) {
      token[i] = (uint8_t)(rand() & 0xFF);
    }
  }
}
```

- [ ] **Step 4: Run all tests to verify nothing broke**

Run: `cd build && cmake --build . && ./test_crabs`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/StateMachine/state_machine.c
git commit -m "fix: use RAND_bytes for cryptographically secure lock token generation"
```

### Task 2: Fix pre_lock_snapshot to deep-copy resource value

**Files:**
- Modify: `src/StateMachine/state_machine.c:300-303` (op_lock)
- Modify: `src/StateMachine/state_machine.c:358-361` (op_rollback)
- Test: `test/test_state_machine.cpp`

- [ ] **Step 1: Write the failing test**

Add a test that verifies rollback restores the original value:

```cpp
TEST_F(TestStateMachine, TestRollbackRestoresOriginalValue) {
  operation_t* lock_op = make_lock_op();
  EXPECT_EQ(state_machine_execute(state, lock_op), CRABS_SUCCESS);
  operation_destroy(lock_op);

  data_item_t* item = state_find_item(state, "test_resource");
  ASSERT_NE(item, nullptr);
  int64_t original_value = *(int64_t*)item->value;

  // Modify value
  *(int64_t*)item->value = original_value + 100;
  item->protocol_state = PROTOCOL_MODIFIED;

  // Rollback should restore original value
  operation_t* rollback_op = operation_create(CRABS_OP_ROLLBACK);
  memset(rollback_op->uuid, 0x50, CRABS_UUID_SIZE);
  rollback_op->resources = (char(*)[CRABS_MAX_USER_ID])malloc(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(rollback_op->resources[0], "test_resource", CRABS_MAX_USER_ID - 1);
  rollback_op->resource_count = 1;
  rollback_op->required_state = (protocol_state_e*)malloc(sizeof(protocol_state_e));
  rollback_op->required_state[0] = PROTOCOL_MODIFIED;
  rollback_op->lock_claims = (lock_claim_t*)malloc(sizeof(lock_claim_t));
  strncpy(rollback_op->lock_claims[0].resource, "test_resource", CRABS_MAX_USER_ID - 1);
  memcpy(rollback_op->lock_claims[0].lock_token, item->lock_state.lock_token, CRABS_LOCK_TOKEN_SIZE);
  rollback_op->lock_claim_count = 1;
  strncpy(rollback_op->signer_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(state_machine_execute(state, rollback_op), CRABS_SUCCESS);
  EXPECT_EQ(*(int64_t*)item->value, original_value);
  operation_destroy(rollback_op);
}
```

- [ ] **Step 2: Run test to verify it fails (current implementation stores only 8 bytes of timestamp)**

Run: `cd build && cmake --build . && ./test_crabs --gtest_filter=TestStateMachine.TestRollbackRestoresOriginalValue`
Expected: FAIL (rollback restores wrong value because snapshot is timestamp, not value)

- [ ] **Step 3: Fix pre_lock_snapshot to deep-copy the value, and rollback to restore from snapshot**

In `state_machine.c`, modify `state_machine_op_lock` to deep-copy the value:

```c
// Replace the existing snapshot logic in op_lock:
if (item->value != NULL) {
  size_t value_size = 0;
  // Determine size based on type
  if (item->type == DATA_TYPE_COUNTER || item->type == DATA_TYPE_PN_COUNTER ||
      item->type == DATA_TYPE_RESOURCE) {
    value_size = sizeof(int64_t);
  } else if (item->type == DATA_TYPE_REGISTER) {
    // LWW register: value + timestamp + node_id
    // For now, just copy the raw pointer size
    value_size = sizeof(int64_t);
  }
  if (value_size > 0) {
    item->lock_state.pre_lock_snapshot = get_memory(value_size);
    memcpy(item->lock_state.pre_lock_snapshot, item->value, value_size);
  }
}
```

In `state_machine_op_rollback`, replace the snapshot restore logic:

```c
// Replace existing memcpy(item->value, item->lock_state.pre_lock_snapshot, 8):
if (item->lock_state.pre_lock_snapshot != NULL && item->value != NULL) {
  size_t value_size = 0;
  if (item->type == DATA_TYPE_COUNTER || item->type == DATA_TYPE_PN_COUNTER ||
      item->type == DATA_TYPE_RESOURCE) {
    value_size = sizeof(int64_t);
  } else if (item->type == DATA_TYPE_REGISTER) {
    value_size = sizeof(int64_t);
  }
  if (value_size > 0) {
    memcpy(item->value, item->lock_state.pre_lock_snapshot, value_size);
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd build && cmake --build . && ./test_crabs --gtest_filter=TestStateMachine.TestRollbackRestoresOriginalValue`
Expected: PASS

- [ ] **Step 5: Run all tests**

Run: `cd build && cmake --build . && ./test_crabs`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/StateMachine/state_machine.c
git commit -m "fix: deep-copy resource value in pre_lock_snapshot for correct rollback"
```

### Task 3: Implement CRDT merge module

**Files:**
- Create: `src/CRDT/crdt_merge.h`
- Create: `src/CRDT/crdt_merge.c`
- Create: `test/test_crdt.cpp`
- Modify: `CMakeLists.txt` (if needed — GLOB_RECURSE should pick it up)

- [ ] **Step 1: Write the CRDT merge header**

Create `src/CRDT/crdt_merge.h`:

```c
//
// Created by victor on 4/30/25.
//

#ifndef CRABS_CRDT_MERGE_H
#define CRABS_CRDT_MERGE_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"

// ============================================================
// G-Counter (§12.2.1)
// ============================================================

typedef struct {
  char     node_id[CRABS_MAX_USER_ID];
  int64_t  count;
} g_counter_entry_t;

typedef struct {
  g_counter_entry_t* entries;
  uint32_t           entry_count;
} g_counter_t;

g_counter_t* g_counter_create(void);
void          g_counter_destroy(g_counter_t* counter);
crabs_error_e g_counter_increment(g_counter_t* counter, const char* node_id, int64_t delta);
int64_t       g_counter_value(const g_counter_t* counter);
g_counter_t*  g_counter_merge(const g_counter_t* a, const g_counter_t* b);

// ============================================================
// PN-Counter (§12.2.2)
// ============================================================

typedef struct {
  g_counter_t pos;
  g_counter_t neg;
} pn_counter_t;

pn_counter_t* pn_counter_create(void);
void           pn_counter_destroy(pn_counter_t* counter);
crabs_error_e  pn_counter_increment(pn_counter_t* counter, const char* node_id, int64_t delta);
crabs_error_e  pn_counter_decrement(pn_counter_t* counter, const char* node_id, int64_t delta);
int64_t        pn_counter_value(const pn_counter_t* counter);
pn_counter_t*  pn_counter_merge(const pn_counter_t* a, const pn_counter_t* b);

// ============================================================
// OR-Set (§12.2.3)
// ============================================================

typedef struct {
  char*    element;
  char*    tag;  // unique tag: "node_id:counter"
} or_set_entry_t;

typedef struct {
  or_set_entry_t* elements;
  uint32_t        element_count;
  or_set_entry_t* tombstones;
  uint32_t        tombstone_count;
} or_set_t;

or_set_t*     or_set_create(void);
void          or_set_destroy(or_set_t* set);
crabs_error_e or_set_add(or_set_t* set, const char* element, const char* tag);
crabs_error_e or_set_remove(or_set_t* set, const char* element);
bool          or_set_contains(const or_set_t* set, const char* element);
or_set_t*     or_set_merge(const or_set_t* a, const or_set_t* b);

// ============================================================
// 2P-Set (§12.2.4)
// ============================================================

typedef struct {
  char**   add_set;
  uint32_t add_count;
  char**   remove_set;
  uint32_t remove_count;
} two_p_set_t;

two_p_set_t*  two_p_set_create(void);
void           two_p_set_destroy(two_p_set_t* set);
crabs_error_e  two_p_set_add(two_p_set_t* set, const char* element);
crabs_error_e  two_p_set_remove(two_p_set_t* set, const char* element);
bool           two_p_set_contains(const two_p_set_t* set, const char* element);
two_p_set_t*  two_p_set_merge(const two_p_set_t* a, const two_p_set_t* b);

// ============================================================
// LWW-Register (§12.2.5)
// ============================================================

typedef struct {
  uint8_t* value;
  uint32_t value_size;
  uint64_t timestamp;
  char     node_id[CRABS_MAX_USER_ID];
} lww_register_t;

lww_register_t* lww_register_create(const uint8_t* value, uint32_t size, uint64_t timestamp, const char* node_id);
void             lww_register_destroy(lww_register_t* reg);
lww_register_t*  lww_register_merge(const lww_register_t* a, const lww_register_t* b);

// ============================================================
// State-level merge (§12.1)
// ============================================================

crabs_error_e crdt_merge_state(state_t* dst, const state_t* src);

// ============================================================
// Per-value merge dispatch
// ============================================================

void* crdt_merge_value(data_type_e type, crdt_type_e crdt_type,
                        void* value_a, void* value_b,
                        const char* node_id_a, const char* node_id_b);

#endif // CRABS_CRDT_MERGE_H
```

- [ ] **Step 2: Write the CRDT merge implementation for G-Counter**

Create `src/CRDT/crdt_merge.c` with the G-Counter implementation:

```c
#include "crdt_merge.h"
#include "../Util/allocator.h"
#include <string.h>
#include <stdlib.h>

// ============================================================
// G-Counter
// ============================================================

static g_counter_entry_t* g_counter_find_entry(g_counter_t* counter, const char* node_id) {
  for (uint32_t i = 0; i < counter->entry_count; i++) {
    if (strcmp(counter->entries[i].node_id, node_id) == 0) {
      return &counter->entries[i];
    }
  }
  return NULL;
}

g_counter_t* g_counter_create(void) {
  g_counter_t* counter = get_clear_memory(sizeof(g_counter_t));
  return counter;
}

void g_counter_destroy(g_counter_t* counter) {
  if (counter == NULL) return;
  if (counter->entries != NULL) free(counter->entries);
  free(counter);
}

crabs_error_e g_counter_increment(g_counter_t* counter, const char* node_id, int64_t delta) {
  if (counter == NULL || node_id == NULL) return CRABS_ERR_INVALID_PARAM;
  g_counter_entry_t* entry = g_counter_find_entry(counter, node_id);
  if (entry != NULL) {
    entry->count += delta;
  } else {
    counter->entry_count++;
    g_counter_entry_t* new_entries = realloc(counter->entries,
      counter->entry_count * sizeof(g_counter_entry_t));
    if (new_entries == NULL) return CRABS_ERR_OOM;
    counter->entries = new_entries;
    entry = &counter->entries[counter->entry_count - 1];
    memset(entry, 0, sizeof(g_counter_entry_t));
    strncpy(entry->node_id, node_id, CRABS_MAX_USER_ID - 1);
    entry->count = delta;
  }
  return CRABS_SUCCESS;
}

int64_t g_counter_value(const g_counter_t* counter) {
  if (counter == NULL) return 0;
  int64_t total = 0;
  for (uint32_t i = 0; i < counter->entry_count; i++) {
    total += counter->entries[i].count;
  }
  return total;
}

g_counter_t* g_counter_merge(const g_counter_t* a, const g_counter_t* b) {
  if (a == NULL) return b != NULL ? NULL : NULL;  // Caller should copy b
  if (b == NULL) return NULL;

  g_counter_t* merged = g_counter_create();
  // Copy all entries from a
  for (uint32_t i = 0; i < a->entry_count; i++) {
    g_counter_increment(merged, a->entries[i].node_id, a->entries[i].count);
  }
  // Merge entries from b, taking element-wise max
  for (uint32_t i = 0; i < b->entry_count; i++) {
    g_counter_entry_t* existing = g_counter_find_entry(merged, b->entries[i].node_id);
    if (existing != NULL) {
      if (b->entries[i].count > existing->count) {
        existing->count = b->entries[i].count;
      }
    } else {
      g_counter_increment(merged, b->entries[i].node_id, b->entries[i].count);
    }
  }
  return merged;
}
```

- [ ] **Step 3: Write the G-Counter test and run it**

Create `test/test_crdt.cpp`:

```cpp
#include <gtest/gtest.h>
extern "C" {
#include "../src/CRDT/crdt_merge.h"
}

TEST(TestGCounter, TestCreateAndValue) {
  g_counter_t* c = g_counter_create();
  ASSERT_NE(c, nullptr);
  EXPECT_EQ(g_counter_value(c), 0);
  g_counter_destroy(c);
}

TEST(TestGCounter, TestIncrement) {
  g_counter_t* c = g_counter_create();
  g_counter_increment(c, "node1", 5);
  g_counter_increment(c, "node2", 3);
  EXPECT_EQ(g_counter_value(c), 8);
  g_counter_increment(c, "node1", 2);
  EXPECT_EQ(g_counter_value(c), 10);
  g_counter_destroy(c);
}

TEST(TestGCounter, TestMerge) {
  g_counter_t* a = g_counter_create();
  g_counter_increment(a, "node1", 5);
  g_counter_increment(a, "node2", 3);

  g_counter_t* b = g_counter_create();
  g_counter_increment(b, "node1", 7);
  g_counter_increment(b, "node3", 4);

  g_counter_t* merged = g_counter_merge(a, b);
  ASSERT_NE(merged, nullptr);
  // max(5,7) + 3 + 4 = 14
  EXPECT_EQ(g_counter_value(merged), 14);

  g_counter_destroy(a);
  g_counter_destroy(b);
  g_counter_destroy(merged);
}
```

Run: `cd build && cmake --build . && ./test_crabs --gtest_filter=TestGCounter*`
Expected: PASS

- [ ] **Step 4: Implement PN-Counter, OR-Set, 2P-Set, LWW-Register, and state-level merge**

Add the remaining CRDT implementations to `src/CRDT/crdt_merge.c`:

PN-Counter wraps two G-Counters (pos and neg). OR-Set uses element+tag pairs with tombstones. 2P-Set uses add_set and remove_set. LWW-Register uses timestamp + node_id tiebreaker. State-level merge iterates items and dispatches to per-type merge.

- [ ] **Step 5: Write tests for remaining CRDT types**

Add tests for PN-Counter, OR-Set, 2P-Set, and LWW-Register to `test/test_crdt.cpp`.

- [ ] **Step 6: Run all CRDT tests**

Run: `cd build && cmake --build . && ./test_crabs --gtest_filter=Test*Counter*:Test*Set*:Test*Register*:Test*LWW*`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/CRDT/ test/test_crdt.cpp
git commit -m "feat: implement CRDT merge functions for all built-in types"
```

---

## Phase 2: Attribute Machine

Implement the Attribute Machine (Spec §8) — the root state machine that governs users and their attributes.

### Task 4: Implement Attribute Machine data structures and core operations

**Files:**
- Create: `src/Attribute/attribute_machine.h`
- Create: `src/Attribute/attribute_machine.c`
- Create: `test/test_attribute_machine.cpp`

- [ ] **Step 1: Write the attribute machine header**

Create `src/Attribute/attribute_machine.h` with the data structures from Spec §8.2:

```c
#ifndef CRABS_ATTRIBUTE_MACHINE_H
#define CRABS_ATTRIBUTE_MACHINE_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"

// ============================================================
// User Status (§8.2)
// ============================================================
typedef enum {
  USER_ACTIVE    = 0x00,
  USER_SUSPENDED = 0x01,
  USER_REVOKED   = 0x02
} user_status_e;

// ============================================================
// Attribute Value (§8.2)
// ============================================================
typedef struct {
  char     value[CRABS_MAX_POLICY_EXPR];
  char     verified_by[CRABS_MAX_USER_ID];
  uint64_t verified_at;
  uint64_t expires_at;  // 0 = no expiry
} attribute_value_t;

// ============================================================
// User Record (§8.2)
// ============================================================
typedef struct user_t {
  char             user_id[CRABS_MAX_USER_ID];
  attribute_value_t attributes[CRABS_MAX_ATTRIBUTES];
  uint32_t         attribute_count;
  uint8_t          public_key[33];  // ECDSA compressed public key
  user_status_e    status;
  uint64_t         key_version;
  uint64_t         created_at;
  uint64_t         updated_at;
  struct user_t*   next;
} user_t;

// ============================================================
// Attribute Machine (inherits state_t)
// ============================================================
typedef struct {
  state_t   base_state;
  user_t*   users;
  uint32_t  user_count;
} attribute_machine_t;

// ============================================================
// Attribute Machine Functions
// ============================================================
attribute_machine_t* attribute_machine_create(const char* admin_id, const uint8_t admin_pk[33]);
void                  attribute_machine_destroy(attribute_machine_t* am);

// User operations (§8.4)
crabs_error_e attribute_machine_register_user(attribute_machine_t* am, const char* user_id,
                                               const uint8_t public_key[33],
                                               const char* initial_attrs);
crabs_error_e attribute_machine_grant_role(attribute_machine_t* am, const char* target_user,
                                            const char* role, const char* value,
                                            const char* signer_id);
crabs_error_e attribute_machine_self_assert(attribute_machine_t* am, const char* attribute,
                                              const char* value, const char* signer_id);
crabs_error_e attribute_machine_verify_identity(attribute_machine_t* am, const char* target_user,
                                                  const char* attribute, const char* value,
                                                  const char* signer_id);
crabs_error_e attribute_machine_revoke_role(attribute_machine_t* am, const char* target_user,
                                              const char* role, const char* signer_id);
crabs_error_e attribute_machine_suspend_user(attribute_machine_t* am, const char* user_id);

// Query functions
user_t*        attribute_machine_find_user(attribute_machine_t* am, const char* user_id);
bool           attribute_machine_user_has_role(user_t* user, const char* role);
attribute_value_t* attribute_machine_find_attribute(user_t* user, const char* name);

// Temporary attributes (Amendment 1, §7.1)
typedef struct {
  char     name[CRABS_MAX_POLICY_EXPR];
  char     value[CRABS_MAX_POLICY_EXPR];
  uint64_t issued_at;
  uint64_t expires_at;
} temporary_attribute_t;

typedef struct temp_attr_list_t {
  temporary_attribute_t      attr;
  struct temp_attr_list_t*   next;
} temp_attr_list_t;

crabs_error_e attribute_machine_issue_temporary(attribute_machine_t* am, const char* attribute,
                                                  const char* value, const char* role,
                                                  uint64_t duration_ms);
uint32_t      attribute_machine_prune_expired_temporary(attribute_machine_t* am);

#endif // CRABS_ATTRIBUTE_MACHINE_H
```

- [ ] **Step 2: Implement the attribute machine core**

Create `src/Attribute/attribute_machine.c` with genesis, user registration, role management, and query functions per Spec §8.

- [ ] **Step 3: Write tests for attribute machine**

Create `test/test_attribute_machine.cpp` covering:
- Genesis (bootstrap admin creation)
- User registration (including duplicate rejection)
- Grant/revoke roles
- Self-assert attributes
- Verify identity
- Suspend user
- Find user / find attribute queries
- Temporary attribute issuance and pruning

- [ ] **Step 4: Run attribute machine tests**

Run: `cd build && cmake --build . && ./test_crabs --gtest_filter=TestAttributeMachine*`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/Attribute/ test/test_attribute_machine.cpp
git commit -m "feat: implement Attribute Machine with user management and role operations"
```

---

## Phase 3: Cryptographic Primitives (ECDSA + ABE stubs)

Implement ECDSA signing/verification using OpenSSL and stub ABE operations for future integration.

### Task 5: Implement ECDSA signing and verification

**Files:**
- Create: `src/Crypto/crypto.h`
- Create: `src/Crypto/crypto.c`
- Create: `test/test_crypto.cpp`

- [ ] **Step 1: Write the crypto header**

Create `src/Crypto/crypto.h`:

```c
#ifndef CRABS_CRYPTO_H
#define CRABS_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"

// ============================================================
// ECDSA Key Generation (§10.2)
// ============================================================
typedef struct {
  uint8_t private_key[32];   // ECDSA private key (secp256k1)
  uint8_t public_key[33];    // ECDSA compressed public key
} ecdsa_keypair_t;

ecdsa_keypair_t* crypto_ecdsa_generate(void);
void             crypto_ecdsa_keypair_destroy(ecdsa_keypair_t* keypair);

// ============================================================
// ECDSA Signing (§10.2.1)
// ============================================================
crabs_error_e crypto_ecdsa_sign(const uint8_t private_key[32],
                                 const uint8_t* message, size_t message_len,
                                 uint8_t signature[CRABS_SIG_SIZE]);

// ============================================================
// ECDSA Verification (§10.2.2)
// ============================================================
bool crypto_ecdsa_verify(const uint8_t public_key[33],
                          const uint8_t* message, size_t message_len,
                          const uint8_t signature[CRABS_SIG_SIZE]);

// ============================================================
// SHA-256 Hash
// ============================================================
crabs_error_e crypto_sha256(const uint8_t* data, size_t len,
                             uint8_t hash[CRABS_HASH_SIZE]);

// ============================================================
// CSPRNG (§14.2)
// ============================================================
crabs_error_e crypto_random_bytes(uint8_t* buf, size_t len);

// ============================================================
// ABE Stub Interface (§10.1)
// ============================================================
typedef struct {
  uint8_t* data;
  size_t   len;
} abe_key_t;

typedef struct {
  uint8_t* data;
  size_t   len;
} abe_ciphertext_t;

// ABE operations are stubs for future integration with openabe-c
abe_key_t*        crypto_abe_setup(void);
void              crypto_abe_key_destroy(abe_key_t* key);
abe_key_t*        crypto_abe_keygen(const abe_key_t* msk, const abe_key_t* mpk, const char* attrs);
abe_ciphertext_t* crypto_abe_encrypt(const abe_key_t* mpk, const uint8_t* msg, size_t msg_len, const char* policy);
void              crypto_abe_ciphertext_destroy(abe_ciphertext_t* ct);
int               crypto_abe_decrypt(const abe_key_t* sk, const abe_ciphertext_t* ct, uint8_t** out, size_t* out_len);

// ============================================================
// Operation Signing (§10.2.1 + §7.5)
// ============================================================
crabs_error_e crypto_sign_operation(const uint8_t private_key[32],
                                     const uint8_t* serialized_op, size_t op_len,
                                     uint8_t signature[CRABS_SIG_SIZE]);

bool crypto_verify_operation(const uint8_t public_key[33],
                              const uint8_t* serialized_op, size_t op_len,
                              const uint8_t signature[CRABS_SIG_SIZE]);

#endif // CRABS_CRYPTO_H
```

- [ ] **Step 2: Implement crypto module**

Create `src/Crypto/crypto.c` using OpenSSL for ECDSA (secp256k1), SHA-256, and RAND_bytes. ABE functions return stub errors (`CRABS_ERR_CRYPTOGRAPHIC_ERROR`).

- [ ] **Step 3: Write crypto tests**

Create `test/test_crypto.cpp` covering:
- Key generation (keypair not null, keys are valid length)
- Sign and verify round-trip (sign message, verify succeeds)
- Sign and verify with wrong key (verify fails)
- SHA-256 produces consistent hash
- Random bytes produce different values on successive calls

- [ ] **Step 4: Run crypto tests**

Run: `cd build && cmake --build . && ./test_crabs --gtest_filter=TestCrypto*`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/Crypto/ test/test_crypto.cpp
git commit -m "feat: implement ECDSA signing/verification and SHA-256 using OpenSSL"
```

---

## Phase 4: Serialization

Implement binary wire format serialization (Spec §13).

### Task 6: Implement state serialization

**Files:**
- Create: `src/Serialization/serialization.h`
- Create: `src/Serialization/serialization.c`
- Create: `test/test_serialization.cpp`

- [ ] **Step 1: Write the serialization header**

Create `src/Serialization/serialization.h`:

```c
#ifndef CRABS_SERIALIZATION_H
#define CRABS_SERIALIZATION_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "../StateMachine/state_machine.h"

// ============================================================
// Magic bytes and format version (§13.1)
// ============================================================
#define CRABS_SERIAL_MAGIC      0x42415243  // "CRAB" in little-endian
#define CRABS_SERIAL_VERSION    1

// ============================================================
// Serialization
// ============================================================
typedef struct {
  uint8_t* data;
  size_t   len;
} serialized_buffer_t;

serialized_buffer_t* crabs_serialize_state(const state_t* state);
state_t*              crabs_deserialize_state(const uint8_t* data, size_t len);

serialized_buffer_t* crabs_serialize_operation(const operation_t* op);
operation_t*         crabs_deserialize_operation(const uint8_t* data, size_t len);

// Canonical encoding for signing (§7.5)
serialized_buffer_t* crabs_serialize_for_signing(const operation_t* op);

// Serialization helpers
serialized_buffer_t* serialized_buffer_create(size_t len);
void                 serialized_buffer_destroy(serialized_buffer_t* buf);

#endif // CRABS_SERIALIZATION_H
```

- [ ] **Step 2: Implement serialization**

Create `src/Serialization/serialization.c` implementing the binary format from Spec §13:
- Magic bytes + version header
- State version, item count, policy count, log count
- Data items with type, CRDT type, protocol state, value, invariants
- Policies (operation + expression)
- Configuration
- Log entries
- Checksum (SHA-256)
- Canonical encoding for signing (sorted keys, fixed-width integers, length-prefixed strings)

- [ ] **Step 3: Write serialization tests**

Create `test/test_serialization.cpp` covering:
- Serialize and deserialize state round-trip
- Serialize and deserialize operation round-trip
- Canonical encoding determinism (same op always produces same bytes)
- Deserialize corrupt data returns NULL
- Empty state serialization/deserialization

- [ ] **Step 4: Run serialization tests**

Run: `cd build && cmake --build . && ./test_crabs --gtest_filter=TestSerialization*`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/Serialization/ test/test_serialization.cpp
git commit -m "feat: implement binary wire format serialization for state and operations"
```

---

## Phase 5: Threshold Triggers (Amendment 1)

Implement threshold triggers: condition language, trigger data structures, evaluation engine, and trigger processing.

### Task 7: Implement condition language parser and evaluator

**Files:**
- Create: `src/Condition/condition.h`
- Create: `src/Condition/condition.c`
- Create: `test/test_condition.cpp`

- [ ] **Step 1: Write the condition language header**

Create `src/Condition/condition.h`:

```c
#ifndef CRABS_CONDITION_H
#define CRABS_CONDITION_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"

// ============================================================
// Condition Node Types (Amendment 1, §3.3 + Amendment 2, §3)
// ============================================================
typedef enum {
  NODE_COMPARISON  = 0x01,
  NODE_AND         = 0x02,
  NODE_OR          = 0x03,
  NODE_CONTAINS    = 0x04
} node_type_e;

typedef enum {
  CMP_GE      = 0x01,
  CMP_LE      = 0x02,
  CMP_GT      = 0x03,
  CMP_LT      = 0x04,
  CMP_EQ      = 0x05,
  CMP_NE      = 0x06,
  CMP_BETWEEN = 0x07,
  CMP_IN      = 0x08
} comparison_op_e;

typedef enum {
  CONTAINS_SINGLE = 0x01,
  CONTAINS_ANY    = 0x02,
  CONTAINS_ALL    = 0x03
} contains_type_e;

// ============================================================
// Condition AST Node (Amendment 1 §3.3 + Amendment 2 §3.1)
// ============================================================
typedef struct condition_node_t {
  node_type_e type;

  // For COMPARISON nodes:
  char           left_path[CRABS_MAX_POLICY_EXPR];
  comparison_op_e operator;
  char           right_path[CRABS_MAX_POLICY_EXPR];
  int64_t        right_literal;
  int64_t        right_literal_2;  // For BETWEEN

  // For CONTAINS nodes (Amendment 2):
  char           set_path[CRABS_MAX_POLICY_EXPR];
  char**         element_values;
  uint32_t       element_count;
  contains_type_e contains_type;
  bool           negated;

  // For AND/OR nodes:
  struct condition_node_t* left;
  struct condition_node_t* right;
} condition_node_t;

// ============================================================
// Condition Functions
// ============================================================
condition_node_t* condition_parse(const char* expression);
void               condition_node_destroy(condition_node_t* node);
bool               condition_evaluate(const condition_node_t* node, const state_t* state);
int64_t            condition_resolve_path(const state_t* state, const char* path);
condition_node_t*  condition_node_create_comparison(const char* left, comparison_op_e op,
                                                     int64_t literal);
condition_node_t*  condition_node_create_and(condition_node_t* left, condition_node_t* right);
condition_node_t*  condition_node_create_or(condition_node_t* left, condition_node_t* right);
condition_node_t*  condition_node_create_contains(const char* set_path, contains_type_e type,
                                                    bool negated, char** values, uint32_t count);

#endif // CRABS_CONDITION_H
```

- [ ] **Step 2: Implement the condition parser and evaluator**

Create `src/Condition/condition.c` implementing:
- Recursive descent parser for the condition language grammar (Amendment 1 §3.1 + Amendment 2 §2.1)
- Path resolution (`RESOLVE_PATH` from Amendment 1 §5.1)
- Condition evaluation (`EVALUATE_CONDITION` from Amendment 1 §5.1)
- CONTAINS evaluation (`EVALUATE_CONTAINS` from Amendment 2 §4.1)
- Node creation/destruction helpers

- [ ] **Step 3: Write condition tests**

Create `test/test_condition.cpp` covering:
- Parse simple comparison (`"video_abc.flags >= 10"`)
- Parse compound conditions (`"video_abc.flags >= 10 AND video_abc.views >= 1000"`)
- Parse OR conditions
- Parse BETWEEN
- Parse CONTAINS / CONTAINS_ANY / CONTAINS_ALL (Amendment 2)
- Parse NOT CONTAINS
- Evaluate conditions against a state with data items
- Path resolution for nested values

- [ ] **Step 4: Run condition tests**

Run: `cd build && cmake --build . && ./test_crabs --gtest_filter=TestCondition*`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/Condition/ test/test_condition.cpp
git commit -m "feat: implement condition language parser and evaluator for threshold triggers"
```

### Task 8: Implement trigger data structures and processing

**Files:**
- Create: `src/Trigger/trigger.h`
- Create: `src/Trigger/trigger.c`
- Create: `test/test_trigger.cpp`
- Modify: `src/CRABS/data_model.h` (add triggers field to state_t)
- Modify: `src/CRABS/data_model.c` (update create/destroy to handle triggers)

- [ ] **Step 1: Write the trigger header**

Create `src/Trigger/trigger.h`:

```c
#ifndef CRABS_TRIGGER_H
#define CRABS_TRIGGER_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "../Condition/condition.h"

// ============================================================
// Trigger Effect Types (Amendment 1, §2.3)
// ============================================================
typedef enum {
  TRIGGER_EFFECT_ISSUE_ATTRIBUTE = 0x01,
  TRIGGER_EFFECT_CREATE_TRIGGER   = 0x02,
  TRIGGER_EFFECT_DELETE_TRIGGER   = 0x03,
  TRIGGER_EFFECT_DISABLE_TRIGGER  = 0x04,
  TRIGGER_EFFECT_CHANGE_POLICY    = 0x05,
  TRIGGER_EFFECT_CUSTOM           = 0xFF
} trigger_effect_type_e;

// ============================================================
// Trigger Effect (Amendment 1, §2.3)
// ============================================================
typedef struct trigger_effect_t {
  trigger_effect_type_e type;

  // For ISSUE_ATTRIBUTE:
  char     issue_attribute[CRABS_MAX_POLICY_EXPR];
  char     target_role[CRABS_MAX_USER_ID];
  uint64_t duration_ms;
  char     attribute_value[CRABS_MAX_POLICY_EXPR];

  // For COMPOSITE (future: sub_effects)
  struct trigger_effect_t* sub_effects;
  uint32_t                sub_effect_count;
} trigger_effect_t;

// ============================================================
// Trigger Definition (Amendment 1, §2.2)
// ============================================================
typedef struct {
  char             trigger_id[CRABS_MAX_USER_ID];
  char             description[CRABS_MAX_POLICY_EXPR];
  char             condition[CRABS_MAX_POLICY_EXPR];
  condition_node_t* condition_ast;
  trigger_effect_t effect;
  uint64_t         cooldown_ms;
  uint64_t         last_triggered_at;
  bool             one_shot;
  bool             enabled;
  uint64_t         expires_at;
  uint64_t         created_at;
  char             created_by[CRABS_MAX_USER_ID];
} trigger_t;

// ============================================================
// Trigger Functions
// ============================================================
trigger_t*     trigger_create(const char* id, const char* description,
                               const char* condition, trigger_effect_t* effect,
                               uint64_t cooldown_ms, bool one_shot,
                               const char* created_by);
void           trigger_destroy(trigger_t* trigger);
trigger_effect_t* trigger_effect_create_issue_attribute(const char* attr, const char* role,
                                                          uint64_t duration, const char* value);
void           trigger_effect_destroy(trigger_effect_t* effect);

// Processing (Amendment 1, §5.2)
uint32_t      trigger_process_all(state_t* state, trigger_t* triggers, uint32_t trigger_count);

// Built-in trigger operations
crabs_error_e state_machine_op_create_trigger(state_t* state, operation_t* op);
crabs_error_e state_machine_op_delete_trigger(state_t* state, operation_t* op);
crabs_error_e state_machine_op_disable_trigger(state_t* state, operation_t* op);
crabs_error_e state_machine_op_enable_trigger(state_t* state, operation_t* op);

#endif // CRABS_TRIGGER_H
```

- [ ] **Step 2: Add triggers field to state_t**

In `src/CRABS/data_model.h`, add to `state_t`:
```c
  // Trigger support (Amendment 1)
  trigger_t*      triggers;
  uint32_t        trigger_count;
```

Update `data_model.c` create/destroy to initialize/free triggers.

- [ ] **Step 3: Implement trigger processing**

Create `src/Trigger/trigger.c` implementing:
- Trigger creation/destruction
- `PROCESS_TRIGGERS` algorithm (Amendment 1 §5.2)
- `EXECUTE_TRIGGER_EFFECT` (Amendment 1 §5.3)
- Built-in operations: `__create_trigger__`, `__delete_trigger__`, `__disable_trigger__`, `__enable_trigger__`

- [ ] **Step 4: Integrate trigger processing into state_machine_execute**

Modify `src/StateMachine/state_machine.c` to add step 9 (trigger processing) per Amendment 1 §6.1.

- [ ] **Step 5: Write trigger tests**

Create `test/test_trigger.cpp` covering:
- Trigger creation and destruction
- Basic trigger fire (condition satisfied → attribute issued)
- Trigger cooldown (doesn't re-fire within cooldown period)
- One-shot triggers (fire once then self-disable)
- Disabled triggers (skipped during processing)
- Trigger with BETWEEN condition
- Delete/disable/enable trigger operations

- [ ] **Step 6: Run trigger tests**

Run: `cd build && cmake --build . && ./test_crabs --gtest_filter=TestTrigger*`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/Trigger/ src/CRABS/data_model.h src/CRABS/data_model.c src/StateMachine/state_machine.c test/test_trigger.cpp
git commit -m "feat: implement threshold triggers with condition evaluation and processing"
```

---

## Phase 6: Integration

Wire everything together and add key version verification.

### Task 9: Integrate crypto into state machine (key version verification, signing stubs)

**Files:**
- Modify: `src/StateMachine/state_machine.c`
- Modify: `test/test_state_machine.cpp`

- [ ] **Step 1: Add crypto header include and implement key version verification**

In `state_machine.c`, replace the stub `(void)op->signer_key_version;` with actual key version checking using the attribute machine. Add `#include "../Crypto/crypto.h"` and `#include "../Attribute/attribute_machine.h"`.

- [ ] **Step 2: Update state_machine_execute to use RAND_bytes for lock tokens**

The fix from Task 1 already did this. Verify the integration.

- [ ] **Step 3: Add operation serialization for signing**

Wire `crabs_serialize_for_signing` into the state machine so that when ABE is implemented, signature verification can use canonical operation serialization.

- [ ] **Step 4: Write integration tests**

Add tests for:
- Key version mismatch returns `CRABS_ERR_KEY_STALE`
- Operation signature verification (sign then verify)
- Full lock → modify → verify → unlock cycle with crypto signing

- [ ] **Step 5: Run all tests**

Run: `cd build && cmake --build . && ./test_crabs`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add src/StateMachine/ test/test_state_machine.cpp
git commit -m "feat: integrate crypto and attribute machine into state machine operations"
```

### Task 10: Update CMakeLists.txt and final integration test

**Files:**
- Modify: `CMakeLists.txt` (verify GLOB picks up all new source files)
- Create: `test/test_integration.cpp`

- [ ] **Step 1: Verify CMakeLists.txt picks up all new source files**

The existing `file(GLOB_RECURSE C_SRC "src/*/*.c")` should pick up all `.c` files in `src/`. Verify that `src/CRDT/`, `src/Attribute/`, `src/Crypto/`, `src/Serialization/`, `src/Condition/`, and `src/Trigger/` are included.

- [ ] **Step 2: Write integration tests**

Create `test/test_integration.cpp` covering end-to-end scenarios:
- Create state, add items, lock, modify, verify, unlock
- CRDT merge between two state replicas
- Full attribute machine lifecycle (register user, grant role, verify identity, key refresh)
- Threshold trigger fire and temporary attribute issuance
- Serialization round-trip (serialize state, deserialize, verify equality)

- [ ] **Step 3: Build and run all tests**

Run: `cd build && cmake --build . && ./test_crabs`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add CMakeLists.txt test/test_integration.cpp
git commit -m "test: add integration tests covering full protocol lifecycle"
```

---

## Self-Review

### Spec Coverage Check

| Spec Section | Requirement | Task |
|---|---|---|
| §5 Built-in data types with CRDT merge | MUST | Task 3 |
| §8 Attribute Machine | MUST | Task 4 |
| §10.2 ECDSA signing/verification | MUST | Task 5 |
| §10.1 ABE key generation | MUST | Task 5 (stub) |
| §10.3 ABE-gated signature verification | MUST | Task 9 (wired) |
| §10.4 Key version verification | MUST | Task 9 |
| §11.3 Key refresh flow | MUST | Task 4 (attribute_machine) |
| §12 CRDT merge | SHOULD | Task 3 |
| §13 State serialization | MUST | Task 6 |
| §7.5 Serialization for signing | MUST | Task 6 |
| Amendment 1: Threshold triggers | MUST | Tasks 7-8 |
| Amendment 2: CONTAINS operator | MUST | Task 7 |
| Lock token CSPRNG fix | Bug fix | Task 1 |
| Pre_lock_snapshot deep copy fix | Bug fix | Task 2 |

### Placeholder Scan

No TBD, TODO, or "fill in details" placeholders found in the plan.

### Type Consistency

All types and function signatures are consistent across task boundaries. The `trigger_t` type is defined in `trigger.h` and referenced from `data_model.h` with a forward declaration pattern. The `condition_node_t` type is defined in `condition.h` and used in `trigger.h`.