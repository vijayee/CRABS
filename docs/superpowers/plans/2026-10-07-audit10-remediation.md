# Audit-10 Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every open finding in `docs/SECURITY_AUDIT_10.md` (A10-1..A10-4 are already fixed in openabe-c and out of scope), including the two user-approved feature-level items: the CLI "shell" REPL + `key import` wiring (A10-7/8) and the parent key-chain rotation (A10-M6), plus the signing-format version bump (A10-L7).

**Architecture:** CRABS is a C11 embedded state machine with ECDSA-signed ops, a CP-ABE capability vault (openabe-c submodule), and Node/WASM bindings. Fixes land as small, test-first changes per subsystem: state machine/serialization, lineage runtime registry + key chain, CLI REPL/custody, node bindings, and the openabe-c fork (separate repo at `/home/victor/Workspace/src/github.com/vijayee/openabe-to-c/openabe-c`, published to `origin/master`, then submodule-bumped in CRABS).

**Tech Stack:** C11 + OpenSSL, CMake/Ninja (`build/`, test via `ctest`), ctest suite of 1548 tests, node-addon-api bindings (`cmake-js`), googletest in openabe-c (`make test` there).

**Baseline command:** `cd build && ctest --output-on-failure` → must stay 1548/1548 passed (1 network skip) after every task unless a task deliberately changes behavior.

**Conventions:** follow `docs/STYLE_GUIDE.md` (no single-letter variable names; `type_action()` naming; refcounted structs). No "Co-Authored-By" lines in commits. Conventional commit prefixes.

**Wire break note:** v13 state format and signing-format v3 invalidate previously persisted signatures/states — pre-release, accepted per user decision.

---

## Phase 1 — State machine & serialization

### Task 1: A10-M1 — `operation_is_protected` covers lineage ops

**Files:**
- Modify: `src/StateMachine/state_machine.c:209-234`
- Modify: `src/StateMachine/state_machine.h:210` (declaration nearby)
- Modify: `src/Trigger/trigger.c:135-138`
- Test: `test/test_trigger.cpp`

Rationale: lineage op names (`__spawn_machine__` etc., lineage.h:256-260) are registered as *custom* ops, so the `operation_is_builtin()` guards at trigger.c:135 (CHANGE_POLICY effect) and state_machine.c:2189 (`__define_operation_type__`) pass through, letting a trigger creator rewrite lineage-op policies. Do NOT change `operation_is_builtin` itself — caller `state_machine.c:1175` (step-7b skip) and CLI cli.c:1098 rely on builtin/custom semantics; add a superset predicate.

- [ ] **Step 1: Write the failing test** (in `test/test_trigger.cpp`, any existing fixture that already creates a machine with triggers; use the helpers the file already has for `apply_op`-style op submission)

```c
// A trigger effect that rewrites a lineage op's policy must be rejected:
// the lineage lifecycle (spawn/dissolve/revoke-attestation) is protected
// even though lineage ops are custom-defined types.
TEST_F(TriggerPolicyTest, ChangePolicyCannotRewriteLineageOpPolicy) {
  // machine with lineage installed and an admin user, per file's fixture
  // (mirror the setup of the existing CHANGE_POLICY trigger test).
  // Trigger with effect = CHANGE_POLICY on __spawn_machine__:
  //   condition "true", effect_type CHANGE_POLICY,
  //   policy_operation "__spawn_machine__",
  //   policy_expression "role:admin" (still admin-only — the attack is the
  //   *rewrite itself*, so use an expression the trigger creator satisfies,
  //   e.g. "role:user" or merely re-pointing it)
  ASSERT_EQ(trigger install via __create_trigger__ op, CRABS_SUCCESS);
  ASSERT_EQ(submit benign op to fire trigger, CRABS_SUCCESS);
  // The policy for __spawn_machine__ must be unchanged:
  const char* p = state_get_policy(state, "__spawn_machine__");
  ASSERT_STREQ(p, "role:admin");
}
```

Match the existing test's assertion helpers — if `state_get_policy` doesn't exist, assert via the machine's public API used by sibling tests for policies.

- [ ] **Step 2: Run it — expect FAIL** (trigger installs and the lineage policy gets rewritten)

Run: `cd build && ctest -R TriggerPolicy --output-on-failure`

- [ ] **Step 3: Implement.** In `state_machine.c`, below `operation_is_builtin`, add:

```c
// v1.7: lineage operations are handler-registered custom types, but the
// lineage lifecycle must not be rewritable by triggers or re-definable by
// __define_operation_type__ (audit A10-M1). Protected = builtin ∪ lineage.
bool operation_is_protected(const char* type) {
  if (operation_is_builtin(type)) return true;
  return (strcmp(type, CRABS_LINEAGE_OP_SPAWN) == 0 ||
          strcmp(type, CRABS_LINEAGE_OP_REVOKE_ATTESTATION) == 0 ||
          strcmp(type, CRABS_LINEAGE_OP_DISSOLVE) == 0 ||
          strcmp(type, CRABS_LINEAGE_OP_WITHDRAW_GENESIS) == 0 ||
          strcmp(type, CRABS_LINEAGE_OP_RECEIVE_DISSOLUTION) == 0 ||
          strcmp(type, CRABS_LINEAGE_OP_PARENT_KEY_UPDATE) == 0);
}
```

(This already references the op added in Task 11; if Task 11 is done later, add that line then — implement now without it and extend in Task 11.) In `state_machine.h`, next to the `operation_is_builtin` declaration:

```c
bool operation_is_protected(const char* type);
```

In `trigger.c:135` change the guard to `if (operation_is_protected(trigger->effect.policy_operation))`. In `state_machine.c:2189` change the guard to `if (operation_is_protected(op->resources[0]))`.

- [ ] **Step 4: Run — expect PASS** + full suite green. Commit: `fix: protect lineage op policies from trigger rewrites and redefinition (A10-M1)`

### Task 2: A10-M2 — Mode B co-signer distinctness via resolved signer

**Files:**
- Modify: `src/StateMachine/state_machine.c:885-928` (`_verify_co_signatures`) and call sites at `:1088` and `:1302`
- Test: `test/test_state_machine.cpp`

- [ ] **Step 1: Write the failing test.** In Mode B (op submitted with empty `signer_id`), have the *primary* signer also appear as co-signer slot 0; expect `CRABS_ERR_UNAUTHORIZED`/threshold failure.

```c
TEST(CoSignatureTest, ModeBPrimarySignerCannotDoubleAsCoSigner) {
  // Build machine; user "alice" (role:admin); op type with policy
  // satisfied by alice and co_sign_threshold = 2.
  // Sign op with alice, leave op->signer_id = "" (Mode B), and put alice
  // in co_signers[0] with her signature, plus a second real co-signer "bob".
  // Distinctness must be enforced against the RESOLVED primary signer
  // (alice), so authorized = false even though 2 signature slots verify.
  ASSERT_NE(state_machine_execute(state, op), CRABS_SUCCESS);
}
```

- [ ] **Step 2: expect FAIL** (currently succeeds: distinctness compares against the empty `op->signer_id`).

- [ ] **Step 3: Implement.** Change the signature to take the resolved primary signer:

```c
static crabs_error_e _verify_co_signatures(
    state_t* state, const operation_t* op, policy_preprocess_result_t* pp,
    const char* resolved_signer)
```

In the distinctness loop (~:898-907) reject when the co-signer matches EITHER the wire primary signer OR the resolved signer:

```c
if (strcmp(cs->signer_id, op->signer_id) == 0 ||
    (resolved_signer != NULL && resolved_signer[0] != '\0' &&
     strcmp(cs->signer_id, resolved_signer) == 0)) {
  return CRABS_ERR_UNAUTHORIZED;
}
```

Update both call sites to pass `resolved_signer` (execute path: :1088; validate-only path: :1302 — verify the validate path has a resolved signer computed; if it computes one under a different name, pass that; if none exists there, it must compute one the same way before the call).

- [ ] **Step 4: PASS + full suite.** Commit: `fix: enforce co-signer distinctness against the resolved primary signer in Mode B (A10-M2)`

### Task 3: A10-L11 — Step-7b transition made atomic

**Files:**
- Modify: `src/StateMachine/state_machine.c:1175-1188`
- Test: `test/test_state_machine.cpp`

- [ ] **Step 1: Write failing test** — multi-resource non-builtin op where resource[0] is LOCKED and resource[1] is IDLE; expect the op to fail AND resource[0] to still be `PROTOCOL_LOCKED` (no partial apply).

```c
TEST(ProtocolTest, Step7bTransitionIsAtomic) {
  // resources {A (LOCKED), B (IDLE)}; submit non-builtin op via wildcard path
  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_PROTOCOL_VIOLATION);
  // A must NOT have been flipped to MODIFIED
  data_item_t* item_a = state_find_item(state, "A");
  EXPECT_EQ(item_a->protocol_state, PROTOCOL_LOCKED);
}
```

- [ ] **Step 2: expect FAIL** (A is already MODIFIED when the error returns).
- [ ] **Step 3: Implement** — pre-validate, then mutate:

```c
  if (!operation_is_builtin(op->type) && custom_handler == NULL) {
    // Pre-validate every resource BEFORE mutating any, so a later failure
    // cannot leave a partial apply (audit A10-L11: mutation without a log
    // entry must never happen).
    for (uint32_t i = 0; i < op->resource_count; i++) {
      data_item_t* item = state_find_item(state, op->resources[i]);
      if (item == NULL) return CRABS_ERR_RESOURCE_NOT_FOUND;
      if (item->type != DATA_TYPE_RESOURCE) continue;
      if (item->protocol_state != PROTOCOL_LOCKED) {
        return CRABS_ERR_PROTOCOL_VIOLATION;
      }
    }
    for (uint32_t i = 0; i < op->resource_count; i++) {
      data_item_t* item = state_find_item(state, op->resources[i]);
      if (item->type != DATA_TYPE_RESOURCE) continue;
      item->protocol_state = PROTOCOL_MODIFIED;
    }
  }
```

- [ ] **Step 4: PASS + full suite.** Commit: `fix: make wildcard protocol transition atomic across resources (A10-L11)`

### Task 4: A10-M7 — ordered-set deserializer cost bound

**Files:**
- Modify: `src/Serialization/serialization.c:35-36` (new constant) and `:468-481`
- Test: `test/test_serialization.cpp`

- [ ] **Step 1: Write failing test** — craft an ordered-set section header with `count = CRABS_DESER_MAX_LOG + 1` (1,000,001) and a tiny buffer; expect deserialize failure (not OOM-alloc attempt). And with count 20,000 over a plausible-size blob → failure.

```c
TEST(OrderedSetDeserialize, ElementCountIsBounded) {
  // build minimal blob with count field = 1000001, few actual bytes
  // expect crabs_deserialize_* to fail cleanly (NULL / error), not abort
}
```

- [ ] **Step 2: expect FAIL** (currently the count cap alone passes ≤1M and then O(n²)-scans + big alloc).
- [ ] **Step 3: Implement.** Add near serialization.c:36:

```c
// A10-M7: bound ordered-set elements like the OT tree (CRABS_DESER_MAX_TREE_
// NODES) so the per-element duplicate-id scan stays O(10⁴·10⁴) worst case,
// and add a remaining-buffer bound (id is fixed size; mirror the pc_count
// bound at :2823).
#define CRABS_DESER_MAX_SET_ELEMENTS 10000
```

Change the ordered-set read path:

```c
if (count > CRABS_DESER_MAX_SET_ELEMENTS) return false;
if (count > (buf.len - buf.offset) / CRABS_OT_OP_ID_SIZE) return false;  // check actual id size macro; pattern per pc_count at 2823
```

(`crabs_ot_op_id_t` — use its serialized fixed size; find via `_deserialize_ot_op_id`.)

- [ ] **Step 4: PASS + full suite.** Commit: `fix: cap and buffer-bound ordered-set deserialization (A10-M7)`

### Task 5: A10-L6 — state deserializer full-consumption check

**Files:**
- Modify: `src/Serialization/serialization.c` (`_deserialize_state_internal`, right before its success return — locate the final return after the last version-gated section; op deserializer precedent at :2618)
- Test: `test/test_serialization.cpp`

- [ ] **Step 1: Write failing test** — take a validly serialized state, append 16 junk bytes, deserialize; expect failure (currently succeeds, ignoring trailing bytes).

- [ ] **Step 2: expect FAIL.**
- [ ] **Step 3: Implement:**

```c
  // A10-L6: require the payload to be fully consumed (op deserializer
  // precedent). Trailing bytes mean corruption or a crafted dual-parse.
  if (buf.offset != buf.len) goto fail;
```

- [ ] **Step 4: PASS + full suite (if any existing test builds intentionally-padded blobs, fix the test construction, not the check).** Commit: `fix: reject trailing bytes in state deserialization (A10-L6)`

### Task 6: A10-L7 — signing format v3 includes `op_version`

**Files:**
- Modify: `src/Serialization/serialization.c:2850-2875` (`crabs_serialize_for_signing`) — and any sibling verifier that re-serializes (grep `crabs_serialize_for_signing` for the canonical-2 form construction duplicates; the deserializer reads the format byte — find how it's validated, grep `signing-format`)
- Test: `test/test_serialization.cpp`

- [ ] **Step 1: Write failing test** — serialize an op for signing with `op_version = 5`; assert the canonical form contains the version (e.g. byte-compare against a v3-shaped buffer, or simpler: sign two ops identical except `op_version=1` vs `op_version=5` — with the same key both signatures are currently identical (bug), after the fix they differ and cross-verification fails).

```c
TEST(Serialization, OpVersionIsPartOfSignedForm) {
  operation_t* op1 = make_valid_op_v1();  // op_version = 1
  operation_t* op5 = clone_with_version(op1, 5);  // payload shortened like a v1 op
  // same key signs both; verifier built from op5's v1-shaped fields must NOT
  // accept a signature minted over the v5 form (and vice versa)
  EXPECT_NE(sign(op1, key), sign(op5, key));
}
```

- [ ] **Step 2: expect FAIL** (both signatures identical).
- [ ] **Step 3: Implement.** In `crabs_serialize_for_signing`:

```c
  _write_uint8(buf, 0x03); // signing-format version 3: adds op_version (A10-L7)
  _write_string16(buf, op->type);
  _write_uint32(buf, op->op_version);   // NEW: rewind-to-strip is no longer signable
```

(Field order note: appending right after op.type keeps diffs simple; sign and verify share this one function so order only matters internally. Grep for a *second* construction site that re-serializes for verification — the co-signature and pending-signature paths must use this same builder.)

- [ ] **Step 4: PASS + full suite** (expect tests that hard-code canonical-2 layouts to be updated deliberately; those are approved changes). Commit: `fix: include op_version in the signed canonical form (signing format v3) (A10-L7)`

---

## Phase 2 — Lineage runtime registry & key chain

### Task 7: A10-5 — resident registry keyed by child_id, not manifest index

**Files:**
- Modify: `src/Lineage/lineage.c:965-1003` (`_lineage_find_resident_child`, `_lineage_drop_resident_child`) and `:1263-1283` (`lineage_query_resident_child`)
- Modify: `src/CRABS/data_model.h:437-446` (comment only)
- Test: `test/test_lineage.cpp`

Design: stop assuming positional alignment with the manifest. Registry entries are looked up by `child->base_state.lineage_self_id`. The spawn rollback at :1177-1178 keeps working (appends/removes at tail). After a restart the registry is simply empty until children are spawned again — any later spawn lands at slot 0 and **lookups must still resolve correctly**, which the id-keyed scan now guarantees. (Note explorer correction: what drifts is *runtime* dissolve targeting when old and new children coexist; the id-keyed scan fixes find/drop/query uniformly.)

- [ ] **Step 1: Write failing tests.**

```c
// (a) Restart-then-spawn: after loading a machine that already has manifest
// entries for A and B, spawn C, then dissolve A. A has no resident machine —
// dissolve must NOT touch C; C must be severed (flag set + slot dropped);
// dissolving C itself must succeed in-process.
TEST(LineageRegistry, RegistrySurvivesRestartReindexing) { … }
// (b) lineage_query_resident_child("B") must return NULL while only C is
// resident, and lineage_query_resident_child("C") must return C.
TEST(LineageRegistry, QueryKeyedByIdNotIndex) { … }
```

- [ ] **Step 2: expect FAIL** (C is at registry slot 0, so dissolve(A) finds C and severs the wrong machine; dissolving C fails the `child_index < resident_child_count` bound).
- [ ] **Step 3: Implement** — replace the positional logic:

```c
// A10-5: registry entries are matched by the child's lineage_self_id, NOT by
// manifest position — the manifest is persisted across a restart while the
// runtime registry starts empty, so positional alignment is a fiction.
static attribute_machine_t* _lineage_find_resident_child(
    state_t* parent, const char* child_id) {
  if (parent == NULL || child_id == NULL || parent->resident_children == NULL) {
    return NULL;
  }
  for (uint32_t slot = 0; slot < parent->resident_child_count; slot++) {
    attribute_machine_t* child = parent->resident_children[slot];
    if (child == NULL) continue;
    if (strcmp(child->base_state.lineage_self_id, child_id) == 0) {
      return child; // valid by construction (Task 8 liveness); NULLs are holes
    }
  }
  return NULL;
}

static void _lineage_drop_resident_child(state_t* parent, const char* child_id) {
  if (parent == NULL || child_id == NULL || parent->resident_children == NULL) {
    return;
  }
  for (uint32_t slot = 0; slot < parent->resident_child_count; slot++) {
    attribute_machine_t* child = parent->resident_children[slot];
    if (child == NULL) continue;
    if (strcmp(child->base_state.lineage_self_id, child_id) == 0) {
      parent->resident_children[slot] = NULL;
      return;
    }
  }
}
```

And `lineage_query_resident_child` (:1263-1283): delete the manifest index arithmetic; body becomes `return _lineage_find_resident_child(state, child_id);` (keep the public signature). Update the aligned-index comments at data_model.h:437-446:

```c
  // v1.7 (runtime ONLY, never serialized): registry of children spawned and
  // still resident in this process. UNOWNED POINTERS — each entry is a child
  // some caller built via lineage_spawn_machine and owns (destroys) itself;
  // the state only frees the POINTER ARRAY. Entries are matched by the
  // child's lineage_self_id (A10-5): the manifest is persisted across a
  // restart while this registry starts empty, so positions never correspond.
  // Dissolve NULLs its slot. Destroying a child out-of-band without a
  // dissolve leaves no dangling window: the destroy hook (A10-6) drops the
  // slot via lineage_resident_child_destroyed().
```

- [ ] **Step 4: PASS + full suite.** Commit: `fix: match resident lineage children by id, not manifest index (A10-5)`

### Task 8: A10-6 — liveness token ends the dissolve write-after-free

**Files:**
- Modify: `src/Attribute/attribute_machine.h` (add field), `src/Attribute/attribute_machine.c:381-416` (destroy hook), `src/Lineage/lineage.c:993-1003` (register sets owner), `src/CRABS/data_model.c:156` (state_destroy clears children's owner pointers)
- Test: `test/test_lineage.cpp`

Design: `attribute_machine_t` gains a runtime-only `lineage_owner_state` weak back-pointer, set only when the parent registers it. On `attribute_machine_destroy`, if the back-pointer is set, drop this child's slot in the owner's registry (by id — safe post-Task-7) and clear the pointer. On `state_destroy` (parent dying first), clear each resident child's `lineage_owner_state` so later child destruction doesn't touch freed parent memory.

- [ ] **Step 1: Write failing test.**

```c
TEST(LineageRegistry, OutOfBandChildDestroyIsSafeForDissolve) {
  // spawn C resident; destroy the child attribute machine directly
  // (documented-usage ownership); then run __dissolve_machine__ C.
  // Must be CRABS_SUCCESS (or NOT_FOUND semantics per dissolve's contract)
  // WITHOUT writing through the freed pointer. Build with ASAN/valgrind
  // locally if available; at minimum assert no crash and slot dropped.
  attribute_machine_destroy(child);   // out-of-band
  EXPECT_EQ(dissolve_lineage_op(parent_state, "C"), CRABS_SUCCESS);
}
```

- [ ] **Step 2: expect FAIL / crash under sanitizer** (current code writes through the freed slot).
- [ ] **Step 3: Implement.**

In `attribute_machine.h`, inside `attribute_machine_t`:

```c
  // Runtime ONLY. Weak pointer to the state that registered this machine as
  // a resident lineage child (set by _lineage_register_resident_child); NULL
  // when not a resident child. Cleared by the owner when it dies first.
  struct state_t* lineage_owner_state;
```

(Check the actual struct member style in the file and match; if `attribute_machine_t` embeds `state_t base_state` differently, place the field adjacent to other runtime-only fields.)

In `lineage.c` — `_lineage_register_resident_child`, before returning success:

```c
  parent->resident_children[parent->resident_child_count] = child;
  child->lineage_owner_state = parent;
  parent->resident_child_count += 1;
```

New public function (declare in lineage.h near `lineage_query_resident_child`):

```c
// A10-6: called from attribute_machine_destroy before a child machine is
// freed. If the child was registered as a resident lineage child, drop its
// slot in the owner's registry and detach, so no dangling pointer survives.
void lineage_resident_child_destroyed(attribute_machine_t* child) {
  if (child == NULL || child->lineage_owner_state == NULL) return;
  state_t* owner = child->lineage_owner_state;
  child->lineage_owner_state = NULL;
  _lineage_drop_resident_child(owner, child->base_state.lineage_self_id);
}
```

In `attribute_machine.c`, `attribute_machine_destroy` (first statement):

```c
  #include "../Lineage/lineage.h"
  ...
  lineage_resident_child_destroyed(machine);
```

In `data_model.c` `state_destroy` (:156 area), before freeing `resident_children`:

```c
  // A10-6: parent dies first — detach resident children's owner pointers so
  // later child destruction does not write into freed memory.
  for (uint32_t slot = 0; slot < state->resident_child_count; slot++) {
    attribute_machine_t* child = state->resident_children[slot];
    if (child != NULL) {
      child->lineage_owner_state = NULL;
    }
  }
```

(Match data_model.c's include of attribute_machine.h — verify it already has it; if not, add.)

- [ ] **Step 4: PASS + full suite + rebuild ASAN if the project has a sanitizer config (skip if not, note it).** Commit: `fix: drop resident lineage slot on child destroy — end dissolve UAF (A10-6)`

### Task 9: A10-L2 + A10-L3 — blueprint enum validation + comment honesty

**Files:**
- Modify: `src/Lineage/lineage.c:457-489` (`_blueprint_dedup_spec_read`), `:552-554` (item enum casts), `:883-951` (`lineage_blueprint_validate`), `:598-599` (comment), `src/Lineage/lineage.h:152` (comment)
- Test: `test/test_lineage.cpp`

- [ ] **Step 1: Write failing tests** — blueprint whose item declares `item_type = 0x42` / `crdt_type = 0x42`, or a dedup spec with `type = 0x42` / `mutation 0x42`: expect deserialize (or `lineage_blueprint_validate`) to reject with `CRABS_ERR_INVALID_PARAM`.
- [ ] **Step 2: expect FAIL.**
- [ ] **Step 3: Implement.** Validate at deserialize so bad bytes never load (fail-closed):

```c
// in _blueprint_dedup_spec_read, after unpacking raw_dedup_type (457):
if (raw_dedup_type != DEDUP_NONE && raw_dedup_type != DEDUP_PER_USER &&
    raw_dedup_type != DEDUP_GLOBAL && raw_dedup_type != DEDUP_CUSTOM) {
  return CRABS_ERR_INVALID_PARAM;
}
// same treatment for raw_mutation_type (467) against the MUTATION_* set:
if (raw_mutation_type != MUTATION_SET_ADD && raw_mutation_type != MUTATION_FLAG_SET &&
    raw_mutation_type != MUTATION_COUNTER_INCREMENT && raw_mutation_type != MUTATION_ASSIGN &&
    raw_mutation_type != MUTATION_CUSTOM) {
  return CRABS_ERR_INVALID_PARAM;
}
```

For items (:552-554), validate against the data_type_e / crdt_type_e values that `data_item_create` actually supports — derive the accepted set from the switch in `crdt_merge.c`/`data_model.c` `data_item_create`; safest exhaustive list (adjust to any `default:` supported values found):

```c
static bool _item_type_is_valid(uint8_t raw_type) {
  switch (raw_type) {
    case DATA_TYPE_COUNTER: case DATA_TYPE_PN_COUNTER: case DATA_TYPE_SET:
    case DATA_TYPE_2P_SET: case DATA_TYPE_REGISTER: case DATA_TYPE_DOCUMENT:
    case DATA_TYPE_RESOURCE: case DATA_TYPE_ONE_SHOT_SET:
    case DATA_TYPE_ONE_SHOT_FLAG: case DATA_TYPE_OT_ORDERED_SET:
    case DATA_TYPE_OT_DOCUMENT: case DATA_TYPE_OT_TABLE:
    case DATA_TYPE_OT_TREE: case DATA_TYPE_OT_ORDERED_MAP:
    case DATA_TYPE_CUSTOM:
      return true;
    default:
      return false;
  }
}
```

Mirror `_crdt_type_is_valid` with the CRDT_* enum. Reject in `lineage_blueprint_validate`'s items loop (lineage.c:915-930) AND at deserialize (:552-554) — belt and braces; deserialize rejection is the load path.

Comment fixes (A10-L3): lineage.h:152 and lineage.c:598-599 — replace the "a tampered body can never pass" claim:

```c
  // NOTE: the hash is an integrity check recomputed at serialize time; a
  // deliberate tamperer can re-stamp it. Provenance/authenticity comes from
  // the signed __spawn_machine__ op, not from this hash.
```

- [ ] **Step 4: PASS + full suite.** Commit: `fix: validate blueprint wire enums; correct blueprint-hash doc claim (A10-L2, A10-L3)`

### Task 10: A10-L17 — stale "runtime ONLY" comments

**Files:**
- Modify: `src/CRABS/data_model.h:431-435`

- [ ] **Step 1:** replace the `lineage_parent_dissolved` comment:

```c
// v1.7 (persists in the v12 binding-block tail, serialization.c): set on a
// spawned child when its parent executes __dissolve_machine__. On the wire
// the flag survives restarts; a resident child additionally gets severed
// immediately in-process (A10-5 registry drop). Default when the field is
// absent (v11 blobs): runtime false.
bool    lineage_parent_dissolved;
```

- [ ] **Step 2:** `cd build && ctest -R Lineage` green (comment-only, but confirm no doc/test cross-references break). Commit: `docs: correct lineage_parent_dissolved serialization comment (A10-L17)`

### Task 11: A10-M6 part 1 — parent key chain data model + core APIs

**Files:**
- Modify: `src/CRABS/data_model.h:416-448` (state_t lineage fields), `src/CRABS/data_model.c` (field zeroing in create/destroy as needed)
- Modify: `src/Lineage/lineage.h` (op name define, structs, API), `src/Lineage/lineage.c` (implementations)
- Test: `test/test_lineage.cpp`

Design (approved by user): children keep a bounded chain of parent node keys `{key_version, pk[33]}`; a signed transition record migrates them forward. Endorsement and tombstone verification accept any chain key (backward compatible — old attestations keep verifying). Parent persists `lineage_key_version` and the last signed transition so it can re-emit after restart.

Wire structures (canonical, sign/verify/serialize share one builder):

```c
// lineage.h — transition record canonical body (no signature):
//   tag(3) = 'P','K','T' + u64le new_key_version + new_pk(33) + old_pk(33)
//   + child_id (string16, the CHILD machine this record targets)
// full record = body + signature(64) over body, made by old_pk's private key.
#define LINEAGE_KEY_TRANSITION_CANONICAL_MAX (3 + 8 + 33 + 33 + 2 + CRABS_MAX_USER_ID)
#define LINEAGE_KEY_TRANSITION_WIRE_MAX (LINEAGE_KEY_TRANSITION_CANONICAL_MAX + CRABS_SIG_SIZE)
#define CRABS_MAX_LINEAGE_KEY_CHAIN 8
#define CRABS_LINEAGE_KEY_VERSION_START 1

typedef struct {
  uint64_t key_version;
  uint8_t  public_key[33];
} lineage_key_chain_entry_t;
```

state_t additions (after `lineage_parent_public_key`, data_model.h:423):

```c
  // A10-M6 (v13, runtime + wire): bounding chain of node keys this machine
  // will accept for parent attestations/tombstones. Entry [0] is the spawn
  // pin (== lineage_parent_public_key); forward-only via __parent_key_update__.
  lineage_key_chain_entry_t* lineage_key_chain;
  uint32_t                   lineage_key_chain_count;
  // Parent-side: version of this machine's node key in the lineage namespace.
  uint64_t                   lineage_key_version;
  // Parent-side: last signed transition (to re-emit __parent_key_update__ to
  // children after restart). Wire max LINEAGE_KEY_TRANSITION_WIRE_MAX.
  uint8_t*                   lineage_last_key_transition;
  uint32_t                   lineage_last_key_transition_len;
```

APIs in lineage.h:

```c
// Parent side: sign a key transition with the CURRENT node key and stash it
// for re-emission. Does NOT install the new key — pair with state_set_node_key
// via lineage_key_rotate below.
crabs_error_e lineage_key_rotate(state_t* parent_state,
                                 const uint8_t new_private_key[32],
                                 const uint8_t new_public_key[33],
                                 uint64_t now_ms,
                                 uint8_t** transition_out, size_t* transition_len);

// Child side: ingest a transition record (wire bytes). Verifies signature
// against the chain entry named by old_pk; enforces child_id == self,
// not dissolved, forward-only version (new == max + 1), pk not already known,
// chain capacity.
crabs_error_e lineage_child_accept_key_transition(state_t* child_state,
                                                  const uint8_t* record,
                                                  size_t record_len);

// Verify helper used by endorsement + tombstone paths: signature is valid if
// it verifies under ANY current chain entry.
bool lineage_verify_by_parent_key(state_t* state, const uint8_t* msg,
                                  size_t msg_len, const uint8_t sig[CRABS_SIG_SIZE]);
```

- [ ] **Step 1: Write failing tests** — (a) fresh spawn: chain == [(1, parent_pk)] (b) rotate: sign with new keypair, child accepts, chain == [(1, old), (2, new)] (c) endorsement/tombstone signed by NEW parent key verifies on child; by OLD key still verifies too (d) rollback rejected (new_version <= max), gap rejected, wrong child_id rejected, replay rejected (same version twice), capacity: 9th rotation rejected.
- [ ] **Step 2: expect FAIL** (APIs absent).
- [ ] **Step 3: Implement** the three functions + a static canonical body builder `_lineage_key_transition_body(state, new_pub, out, out_len, new_version)` used by sign/verify; the signature is made with `crypto_sign_operation(state->node_private_key, body, body_len, sig)`.
- [ ] **Step 4: PASS + full suite.** Commit: `feat: lineage parent key chain data model and rotate/accept APIs (A10-M6)`

### Task 12: A10-M6 part 2 — `__parent_key_update__` op + verify paths

**Files:**
- Modify: `src/Lineage/lineage.h:256-260` (op define), `src/Lineage/lineage.c:1444-1480` (install), new handler in lineage.c
- Modify: `src/StateMachine/state_machine.c:686-699` (endorsement verify → `lineage_verify_by_parent_key`), `src/Lineage/lineage.c:1622` (tombstone verify same)
- Test: `test/test_lineage.cpp` + extension of Task 1's protection (this op must be in `operation_is_protected`)

- [ ] **Step 1:** In lineage.h: `#define CRABS_LINEAGE_OP_PARENT_KEY_UPDATE "__parent_key_update__"`. In lineage_install: register op-type-def (no_dedup), policy `role:admin`, handler `lineage_op_parent_key_update`.
- [ ] **Step 2:** Handler body: extract the record from `op->payload` (cap `LINEAGE_KEY_TRANSITION_WIRE_MAX` via the op payload bound already enforced by the deserializer), call `lineage_child_accept_key_transition`. Submitting the op on the child requires its own policy gate (role:admin by default) AND the parent signature inside the record — two independent fail-closed gates.
- [ ] **Step 3:** Change the two verification sites to chain-aware verification:

```c
// state_machine.c:688 — was: attestation_verify(state->lineage_parent_public_key, …)
if (!attestation_verify_by_lineage_key(state, state->lineage_self_id,
                                       attestation, now_ms)) {
  continue;
}

// lineage.c:1622 — was: crypto_ecdsa_verify(state->lineage_parent_public_key, …)
if (!lineage_verify_by_parent_key(state, op->payload, body_len, signature)) {
  return CRABS_ERR_CRYPTOGRAPHIC_ERROR;
}
```

Add the small wrapper in lineage.c:

```c
bool attestation_verify_by_lineage_key(state_t* child_state,
                                       const char* child_id,
                                       const attestation_t* attestation,
                                       uint64_t now_ms) {
  for (uint32_t i = 0; i < child_state->lineage_key_chain_count; i++) {
    if (attestation_verify(child_state->lineage_key_chain[i].public_key,
                           child_id, attestation, now_ms)) {
      return true;
    }
  }
  return false;
}
```

(Add `attestation_verify_by_lineage_key` to lineage.h when bound; for an unbound machine `lineage_key_chain_count == 0` → verify fails closed, preserving the current "unbound rejects endorsements" behavior — double-check `_verify_parent_endorsements`' bound-check ordering and keep its explicit bound gate.)
- [ ] **Step 4: add `CRABS_LINEAGE_OP_PARENT_KEY_UPDATE` to `operation_is_protected` (Task 1).** Tests: op-driven end-to-end rotate delivered to a resident child; new-key endorsement authorizes; old-key endorsement still authorizes; dissolved-child rejects. PASS + full suite. Commit: `feat: __parent_key_update__ op wired to chain-aware lineage verification (A10-M6)`

### Task 13: A10-M6 part 3 — v13 wire format for chain + parent version + last transition

**Files:**
- Modify: `src/Serialization/serialization.h:21` (`CRABS_SERIAL_VERSION` 12 → 13, comment), `src/Serialization/serialization.c:1590-1602` (writer), `:2064-2088` (reader)
- Modify: `src/Lineage/lineage.c:1134` (spawn stamps chain[0] with parent's current `lineage_key_version`)
- Test: `test/test_serialization.cpp` + `test/test_durability.cpp`

- [ ] **Step 1:** Bump `#define CRABS_SERIAL_VERSION 13  // v13: lineage parent key chain (child side) + key version / last transition (parent side)`.
- [ ] **Step 2 (writer), append after the v12 flag at :1601, inside the `if (state->lineage_parent_bound)` block and then outside it for the parent side:**

```c
    // v13 (A10-M6): child-side parent key chain. Written only when bound;
    // count >= 1 always (entry [0] == the spawn pin).
    _write_uint8(buf, (uint8_t)(state->lineage_key_chain_count > 0
                                  ? state->lineage_key_chain_count : 1));
    for (uint32_t i = 0; i < state->lineage_key_chain_count; i++) {
      _write_uint64(buf, state->lineage_key_chain[i].key_version);
      _write_bytes(buf, state->lineage_key_chain[i].public_key, 33);
    }
  }
  // v13 (A10-M6): parent-side lineage key version + last signed transition.
  _write_uint64(buf, state->lineage_key_version);
  _write_bytes32(buf, state->lineage_last_key_transition,
                 state->lineage_last_key_transition_len);
```

- [ ] **Step 3 (reader), mirror, gated `if (version >= 13)`:** read chain count (cap `CRABS_MAX_LINEAGE_KEY_CHAIN`, reject 0), entries with bounds; entry [0] consistency: for v13 blobs, chain[0].public_key must equal the binding block's `public_key` (reject mismatch); `lineage_key_version` read; last transition read with a remaining-bytes length cap `LINEAGE_KEY_TRANSITION_WIRE_MAX`. For v11/v12 blobs: synthesize `chain = [{version 1, pinned pk}]`, `lineage_key_version = 1`.
- [ ] **Step 4:** spawn binding (lineage.c:1134) additionally sets chain[0] = {parent->lineage_key_version, parent pk}. Tests: round-trip v13 serialize→deserialize preserving chain and version; v12 blob loads with synthesized chain; v13 blob rejected by a reader pinned to 12 (existing "version ceiling" behavior). PASS + full suite. Commit: `feat: v13 state format — lineage key chain, key version, last transition (A10-M6)`

### Task 14: A10-L1 — genesis provenance verifier

**Files:**
- Modify: `src/Lineage/lineage.h` (API), `src/Lineage/lineage.c` (implementation), `src/CLI/cli.c` (`machine children` display), test_lineage.cpp

- [ ] **Step 1: Implement the verifier** promised by the spec:

```c
// Recompute and verify a manifest child's genesis provenance: the stored
// genesis_snapshot_hash matches a re-serialization of the child's genesis
// state, and the genesis_attestation_signature verifies under the parent's
// node key (any chain entry). Returns CRABS_SUCCESS, or
// CRABS_ERR_CRYPTOGRAPHIC_ERROR / RESOURCE_NOT_FOUND.
crabs_error_e lineage_verify_child_provenance(state_t* parent_state,
                                              const char* child_id);
```

Implementation notes: recompute via the same genesis-body path used at spawn (~lineage.c:1187); verify the attestation signature with `lineage_verify_by_parent_key`. If the genesis snapshot bytes are not retained (hash only), verify what is verifiable: signature-over-hash check — reconstruct from the stored signature against a canonical body containing the hash; if the original signing body is not reconstructible, return `CRABS_ERR_UNSUPPORTED` and document in the header comment what is and is not checkable. **Escalate to the user if the genesis body is not reconstructible at spawn time** — do not silently weaken the API.

- [ ] **Step 2: wire into CLI `machine children`** (cli.c `_machine_cmd_children`): add a per-child "provenance ok/failed" column when the verifier is applicable. Tests: positive (fresh spawn verifies), negative (tamper a manifest hash field → fails). Commit: `feat: genesis provenance verifier for child manifest entries (A10-L1)`

---

## Phase 3 — CLI

### Task 15: A10-7a — wire `key import` + custody hygiene (L4, L5)

**Files:**
- Modify: `src/CLI/cli.c:2398-2422` (key dispatcher), `:380-447` (`cli_node_load_key`), `:1998-2002` (`_print_key_usage` add import line)
- Test: `test/test_cli.cpp`

- [ ] **Step 1: Write failing test** — `cli_dispatch` on argv `{"crabs_node", "key", "import", hex}` returns CLI_OK and afterward `cli_node_save` proceeds past the sig-pending gate (fixture: pre-load a signed snapshot first per test_cli.cpp's existing harness pattern).

```cpp
TEST_F(TestCLI, KeyImportVerifiesPendingSnapshot) {
  // arrange a signed snapshot on disk (init → save → tamper nothing),
  // load it into a fresh node (state_sig_pending == true),
  ASSERT_NE(node->node_key_valid, true);
  const char* argv[] = {"crabs_node", "key", "import", PRIV_HEX};
  ASSERT_EQ(cli_dispatch(node, 4, argv), CLI_OK);
  EXPECT_EQ(node->state_sig_pending, false);
  EXPECT_EQ(node->node_key_valid, true);
}
```

- [ ] **Step 2: expect FAIL** ("Unknown key subcommand").
- [ ] **Step 3: Implement** in the key dispatcher (~cli.c:2404):

```c
  if (strcmp(sub, "import") == 0 && argc >= 4) {
    return cli_node_load_key(node, argv[3]);
  }
```

And in `_print_key_usage` add:

```c
  printf("  key import <hex|->     Import the node private key (64 hex chars; '-' reads hex from stdin)\n");
```

Support the stdin form per A10-L5 (key never in argv): only in `cli_node_load_key`, if `strcmp(private_key_hex, "-") == 0`, read a line from stdin (getline), trim, cleanse the line buffer after parse.

- [ ] **Step 4: custodes fixes (A10-L4)** in `cli_node_load_key`: at the hex-parse failure (`:385`), pub-derive failure (`:388`), and custody-NULL exit (`:426-430`), add `OPENSSL_cleanse(priv, 32); OPENSSL_cleanse(pub, 33);` before returning (pub is non-secret but cleanse for consistency is not required — only cleanse `priv`; note pub is harmless).
- [ ] **Step 5: PASS + full suite.** Commit: `fix: wire key import; support stdin form; cleanse on all exit paths (A10-7a, A10-L4, A10-L5)`

### Task 16: A10-7b — REPL shell

**Files:**
- Create: nothing new; Modify: `src/CLI/cli.c` (new `cli_shell_execute_line` + dispatcher hook at `cli_dispatch` top ~2122), `src/CLI/cli.h` (declaration), `src/CLI/main.c` (shell branch)
- Test: `test/test_cli.cpp`

- [ ] **Step 1: Write failing test:**

```cpp
TEST_F(TestCLI, ShellLinePersistsNodeAcrossCommands) {
  bool done = false;
  ASSERT_EQ(cli_shell_execute_line(node, (char*)"init admin", &done), CLI_OK);
  ASSERT_EQ(cli_shell_execute_line(node, (char*)"key generate", &done), CLI_OK);
  // node stays initialized across lines — proving persistence:
  EXPECT_EQ(node->initialized, true);
  EXPECT_EQ(cli_shell_execute_line(node, (char*)"save /tmp/shell_test.bin", &done), CLI_OK);
  ASSERT_EQ(cli_shell_execute_line(node, (char*)"exit", &done), CLI_OK);
  EXPECT_EQ(done, true);
}
```

- [ ] **Step 2: expect FAIL** (function absent).
- [ ] **Step 3: Implement** in cli.c:

```c
// A10-7b: run a single shell line against a persistent node. `line` is
// tokenized in place (whitespace-separated; max 32 tokens). `*should_exit`
// is set for "exit"/"quit"/EOF handling by the caller's loop.
cli_result_e cli_shell_execute_line(cli_node_t* node, char* line, bool* should_exit) {
  if (node == NULL || line == NULL || should_exit == NULL) return CLI_ERR_ARGS;
  char* argv[33];
  int argc = 0;
  char* tok = strtok(line, " \t\r\n");
  while (tok != NULL && argc < 32) {
    argv[argc++] = tok;
    tok = strtok(NULL, " \t\r\n");
  }
  if (argc == 0) return CLI_OK; // blank line
  if (strcmp(argv[0], "exit") == 0 || strcmp(argv[0], "quit") == 0) {
    *should_exit = true;
    return CLI_OK;
  }
  return cli_dispatch(node, argc, argv);
}
```

In `cli_dispatch`: add `exit`/`quit` to the known-command whitelist gate (it never reaches dispatch from the shell loop, but keep the whitelist consistent). In main.c:

```c
int main(int argc, char** argv) { … existing single-shot path for argc >= 2 …
  // shell mode: `crabs_node` (no args) or `crabs_node shell`
  …
  bool should_exit = false;
  char* line = NULL; size_t line_cap = 0;
  fputs("crabs> ", stdout);
  while (getline(&line, &line_cap, stdin) != -1) {
    cli_result_e r = cli_shell_execute_line(node, line, &should_exit);
    if (r != CLI_OK && r != CLI_ERR_ARGS) break;   // keep hard failures fatal
    if (should_exit) break;
    fputs("crabs> ", stdout);
  }
  free(line);
  cli_node_destroy(node);
  return 0;
}
```

(Arrange main.c so `argc >= 2` keeps the exact existing single-shot behavior — zero regression for the current users — and only argc == 1 or argv[1] == "shell" enters the loop.)
- [ ] **Step 4: PASS + full suite (including all existing single-shot tests).** Commit: `feat: crabs_node shell REPL — persistent node across commands (A10-7b)`

### Task 17: A10-M8 — warn list coverage

**Files:**
- Modify: `src/CLI/cli.c:1943-1975`

- [ ] **Step 1: Extend the if-chain** with `machine blueprint` (any sub — it mutates the spawn draft) and `state migrate`:

```c
  // A10-M8: blueprint editing mutates the draft; migrate rebinds the machine's
  // parent block. Both mutate state on top of an unauthenticated snapshot.
  if (strcmp(cmd, "machine") == 0 && sub != NULL &&
      (strcmp(sub, "blueprint") == 0 || strcmp(sub, "migrate") == 0)) return true;

  // 'key import' is not a mutation of machine state (it authenticates the
  // pending snapshot) — deliberately NOT warned.
```

(Verify how `state migrate` is actually dispatched — explorer says `cli_cmd_machine_migrate` hooks under `state` at cli.c:2239; match the real cmd/sub strings.)
- [ ] **Step 2:** failing test first — assert `_warn_first_unauthenticated_mutation` (or the observable warning output via the CLI result text) fires for `machine blueprint add …` and `state migrate …` on a loaded-unauthenticated node, using test_cli.cpp patterns (redirect stdout to a pipe or capture via the existing helpers).
- [ ] **Step 3: PASS + full suite.** Commit: `fix: warn on machine blueprint/migrate over unauthenticated snapshots (A10-M8)`

### Task 18: A10-L8 — 0600 state files

**Files:**
- Modify: `src/CLI/cli.c:536` (`cli_node_save`), include `<sys/stat.h>`, `<unistd.h>`

- [ ] **Step 1: Implement.**

```c
  FILE* f = fopen(path, "wb");
  if (f == NULL) return CLI_ERR_EXEC;
  // A10-L8: the state blob embeds sealed key material — restrict to owner
  // only regardless of umask.
  if (chmod(path, S_IRUSR | S_IWUSR) != 0) {
    fclose(f);
    return CLI_ERR_EXEC;
  }
```

- [ ] **Step 2: test** — save to a temp path, assert `stat().st_mode & 0777 == 0600`.
- [ ] **Step 3: PASS + full suite** (some tests may assert writable/readable only — permissions don't affect them; the running user owns the files). Commit: `fix: write state files 0600 (A10-L8)`

### Task 19: A10-L4 (CLI keygen) — cleanse after printing

**Files:**
- Modify: `src/CLI/cli.c:930-948`

- [ ] **Step 1: Implement** — keep the print (custody UX is deliberate), cleanse after:

```c
  printf("  Private Key: %s\n", priv_hex);
  OPENSSL_cleanse(priv_hex, sizeof(priv_hex));
```

(A grep the function for any earlier return paths that skip it.) Commit: `fix: cleanse keygen private-hex stack buffer after printing (A10-L4)`

---

## Phase 4 — Node bindings

### Task 20: A10-M3 — CreateTrigger null-node-key guard

**Files:**
- Modify: `bindings/node/src/crabs_node.cc:1361-1372`
- Test: `bindings/node/test/test.js` (or lineage_smoke pattern)

- [ ] **Step 1: Implement.**

```cpp
    // Sign with node key — adopted child wrappers carry no key (A10-M3).
    if (node_key_ == nullptr) {
      throw Napi::Error::New(env,
        "createTrigger: this machine carries no own node key");
    }
    serialized_buffer_t* ser = crabs_serialize_for_signing(op);
    if (ser == nullptr) {
      throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "createTrigger");
    }
    crypto_ecdsa_sign(node_key_->private_key, ser->data, ser->len, op->signature);
    serialized_buffer_destroy(ser);
```

- [ ] **Step 2: JS test** — mirroring lineage_smoke.mjs's adopted-wrapper idiom: `childWrapper.createTrigger({...})` now throws a JS Error (not segfault); `parentWrapper.createTrigger` still works. Run `cd bindings/node && node test/test.js` and `node lineage_smoke.mjs`.
- [ ] **Step 3: PASS.** Commit: `fix: guard node-key access in CreateTrigger for adopted wrappers (A10-M3)`

### Task 21: A10-M4 — EmitChange listener snapshot

**Files:**
- Modify: `bindings/node/src/crabs_node.cc:774-798`

- [ ] **Step 1: Implement** (FunctionReference is move-only; snapshot the live `Napi::Function` handles):

```cpp
    // A10-M4: a listener callback may register or unregister listeners on
    // this Node synchronously (push_back reallocates change_listeners_).
    // Iterate a snapshot of live Napi::Function handles instead of the
    // vector itself; the FunctionReference keeps each function alive for
    // the duration of this same HandleScope.
    std::vector<Napi::Function> snapshot;
    snapshot.reserve(change_listeners_.size());
    for (auto& listener : change_listeners_) {
      if (!listener.IsEmpty()) snapshot.push_back(listener.Value());
    }
    Napi::Value undefined_value = env.Undefined();
    for (auto& fn : snapshot) {
      try {
        fn.Call(undefined_value, {obj});
      } catch (...) {
        // A throwing listener must never break the state machine.
      }
    }
```

- [ ] **Step 2: JS test** — listener that registers a new listener on first event; assert both old and new listeners got the first event (or, precisely: no crash and subsequent events reach the new listener too), and a listener that unregisters itself doesn't break the loop. Run node tests.
- [ ] **Step 3: PASS.** Commit: `fix: snapshot change listeners during EmitChange dispatch (A10-M4)`

### Task 22: binding LOWs — cleanse, casts, truncation

**Files:**
- Modify: `bindings/node/src/crabs_node.cc:601-612, 1275-1284, 567-572,` and the `As<Napi::String>()` sites (`:924, :937, :1311-1324,` AddCounter etc.)

- [ ] **Step 1 (A10-L4):** in both sign paths, cleanse before throwing:

```cpp
      serialized_buffer_t* ser = crabs_serialize_for_signing(op->raw());
      if (!ser) {
        OPENSSL_cleanse(priv, 32);
        throw crabs_error(env, CRABS_ERR_SERIALIZATION_ERROR, "sign");
      }
```

(same shape at :605-606).
- [ ] **Step 2 (A10-L12):** add `if (!value.IsString()) throw Napi::TypeError::New(env, "…: expected string");` before each raw `.As<Napi::String>()` on externally supplied config fields (`CreateTrigger` cfg fields at :1311-1324, `RevokeUser` :924, `GetUser` :937, AddCounter args — grep `As<Napi::String>()` across the file and cover every call site that takes JS-provided values; node-addon-api currently fails these conversions cleanly but an explicit error message documents intent).
- [ ] **Step 3 (A10-L13):** in SetPayload (:567-572):

```cpp
      if (buf.Length() > UINT32_MAX) {
        throw Napi::Error::New(env, "setPayload: buffer too large");
      }
```

- [ ] **Step 4: PASS (node tests + smoke).** Commit: `fix: secret hygiene and input-strictness across node bindings (A10-L4/L12/L13)`

---

## Phase 5 — openabe-c fork (separate repo)

Work in `/home/victor/Workspace/src/github.com/vijayee/openabe-to-c/openabe-c` on `master`; push to origin; then bump the DEPS submodule in CRABS. Build: `make && LD_LIBRARY_PATH=build:deps/lib:deps/relic/build/lib make test` (147 tests). **Note:** the ABE-KEM DEM key-derivation change (Task 23) invalidates previously written ABE ciphertexts — pre-release accepted; document in the commit message.

### Task 23: A10-L15 — domain-separated DEM KDF

**Files:**
- Modify: `deps/openabe-c/src/abe/oabe_context.c:51-58` (`_dem_derive_symkey`) — in the fork checkout
- Test: fork `tests/test_abe.cpp`

- [ ] **Step 1: Implement:**

```c
static const uint8_t _DEM_KDF_LABEL[] = "CRABS-OPENABE-DEM-V2";

static OABE_ERROR _dem_derive_symkey(const OABE_GT *gt, uint8_t key[32]) {
  OABE_ByteString *bs = NULL;
  OABE_ERROR rc = oabe_gt_serialize(gt, &bs);
  if (rc != OABE_SUCCESS || !bs) return rc;
  /* Domain separation (A10-L15): bind the KDF to this DEM's purpose so the
     same GT serialization can never be reused as key material by another
     protocol layer sharing the fork's primitives. Breaks compatibility with
     ciphertexts written before this change by design. */
  EVP_MD_CTX *md = EVP_MD_CTX_new();
  OABE_ERROR rc2 = OABE_ERROR_OUT_OF_MEMORY;
  unsigned int hlen = 0;
  if (md) {
    if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(md, _DEM_KDF_LABEL, sizeof(_DEM_KDF_LABEL) - 1) == 1 &&
        EVP_DigestUpdate(md, oabe_bytestring_get_const_ptr(bs),
                         oabe_bytestring_get_size(bs)) == 1 &&
        EVP_DigestFinal_ex(md, key, &hlen) == 1 && hlen == 32) {
      rc2 = OABE_SUCCESS;
    }
    EVP_MD_CTX_free(md);
  }
  oabe_bytestring_free(bs);
  return rc2;
}
```

(Add `#include <openssl/evp.h>` if absent.)
- [ ] **Step 2:** the round-trip tests (EncryptDecryptKEM etc.) already exercise enc→dec with the new KDF; add a regression test asserting an OLD-format (unlabeled) ciphertext fails to decrypt: hard-code a pre-change encrypted blob and expect `OABE_ERROR_DECRYPTION_FAILED`.
- [ ] **Step 3:** commit in fork: `fix: domain-separate the DEM KDF (A10-L15)`; push; bump CRABS submodule (`chore: bump openabe-c — DEM KDF domain separation`).

### Task 24: A10-L16 — real secret-key scalar reconstruction

**Files:**
- Modify (fork): `deps/openabe-c/src/keys/oabe_key.c:897-997` (`oabe_secret_key_deserialize` + header decl), `deps/openabe-c/src/abe/oabe_context.c:893` (caller passes group), `deps/openabe-c/include/openabe/oabe_key.h:241`, fork tests
- Modify (CRABS after submodule bump): `src/Crypto/crypto.c:877-942` (`_restore_msk_scalars` removed/simplified)
- Test: fork test_abe.cpp + CRABS test suite

- [ ] **Step 1: Implement.** Change the signature to take the group (the scalars need `ctx->base.group` to deserialize ZPs):

```c
OABE_ERROR oabe_secret_key_deserialize(const OABE_ByteString *input,
                                       OABE_GroupHandle group,
                                       OABE_ABESecretKey **key);
```

Replace the alpha/beta "placeholder" blocks with real `oabe_zp_deserialize(group, alpha_bytes, &k->alpha)` / `&k->beta` (the wire layout — key_type(1) + scheme(1) + packed ZP alpha + packed ZP beta — is documented by CRABS's `_restore_msk_scalars`, crypto.c:877-892; mirror those bounds checks). Update the internal caller (:893) and fork tests. The ZP buffers get zeroized on failure paths like CRABS's restore code does.
- [ ] **Step 2 (CRABS):** after submodule bump, simplify `crypto.c`: `crypto_master_key_deserialize` drops `_restore_msk_scalars` entirely — `oabe_context_cp_set_secret_key` now restores real scalars; delete the local MSK-scalar parser (keep the OPENSSL_cleanse hygiene in the caller). Re-run CRABS durability tests (test_durability.cpp) which round-trip the MSK.
- [ ] **Step 3:** fork commit `fix: reconstruct master scalars on secret key deserialize (A10-L16)` + push; CRABS: submodule bump + commit `refactor: drop local MSK scalar restore now openabe-c restores them (A10-L16)`. Full suites green on both sides.

---

## Phase 6 — Docs & final verification

### Task 25: README trust-model updates (A10-M5, A10-L9, A10-L14)

**Files:**
- Modify: `README.md:193-240` (Trust Boundaries section)

- [ ] **Step 1:** In `### Machine Minting and Lineage` (README.md:207): keep the sovereignty paragraph but append the A10-M5 caveat — the child's genesis `role:admin` is keyed to the PARENT's node key at spawn, so a sovereign child's authority is *cryptographically* controllable by the parent until the operator performs a post-spawn key rotation (`lineage_key_rotate` + new genesis admin key handover); sovereignty in the state-machine sense (no dissolve/tombstone) is immediate, key-level sovereignty requires rotation. Add the A10-L9 caveat: attestation validity windows evaluate against the machine's configured time source — under the default SYSTEM_CLOCK in WASM this is the page-controllable `Date.now`. Add the A10-L14 note: the N-API `lineageSpawn`/wasm `lineage_spawn` binding calls the lineage API directly (no signed op, no log entry) — same-process trust only; the signed `__spawn_machine__` op path is the durable/audited one.
- [ ] **Step 2:** verify the amended text matches `docs/superpowers/specs/2026-10-06-machine-minting-design.md` and do not contradict it (update the spec doc too if it overclaims). Commit: `docs: trust-model caveats for sovereign custody, attestation clocks, direct-spawn binding (A10-M5/L9/L14)`

### Task 26: Final verification + audit doc update

- [ ] **Step 1:** CRABS: `cd build && ninja && ctest` — 1548/1548 (+ new tests). openabe-c fork: full `make test` green. Node: `node test/test.js` + `node lineage_smoke.mjs` green. WASM smoke script if runnable.
- [ ] **Step 2:** run the de-wonk skill over the whole change set.
- [ ] **Step 3:** update `docs/SECURITY_AUDIT_10.md` "Remediation status" marking all A10-x as FIXED with commit references. Commit: `docs: audit-10 remediation complete`.

---

## Self-review notes

- Spec coverage: all A10 HIGH/MEDIUM/LOW items map to tasks except A10-1..A10-4 (already fixed and submodule-bumped) and A10-8, which closes via Tasks 15/16/17 (sign-and-mutate now workable in one session, save gate + warnings intact).
- Type consistency: `lineage_key_chain_entry_t`, `lineage_verify_by_parent_key`, `lineage_resident_child_destroyed`, `operation_is_protected`, `cli_shell_execute_line` are consistent across tasks; Task 1's protection predicate gains the Task 11 op name last.
- Out-of-scope consciously: no changes to `operation_is_builtin` semantics (Task 1 rationale); wire breaks (v13, signing v3, DEM v2) are pre-release-accepted per user decisions.