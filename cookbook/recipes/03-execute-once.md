---
number: 3
slug: execute-once
title: Execute once, ever
section: Basics
status: PARTIAL
maturity: STABLE
target: crabs-wasm
languages: c wasm node
---
## Intent

You want an operation that runs at most one time, ever — a closeout, a
proposal execution, a one-way door. Not once per member (that is Recipe 2's
shape): once *globally*, where the second caller can be a different person,
on a different device, days later, and the machine itself refuses to run
the effect a second time.

## The naive version, and where it breaks

The naive version is an in-memory boolean. First run sets `done = true`;
the process restarts, the boolean is gone, and the closeout runs again —
over a state that was already closed. Persisting the boolean is the next
attempt, and it still breaks: write-ahead of the effect (crash between the
two) allows a second run, write-behind allows two concurrent writers to
both see `done = false` and both proceed. The useful primitive is a
*monotone* flag whose merge keeps the earliest setter — so no replica can
ever un-see an execution, and two replicas that saw different executions
agree on the first one.

The C catalog pairs that primitive with a `DEDUP_GLOBAL` spec whose guard
runs inside the executor (`src/Dedup/dedup.h`, `src/StateMachine/state_machine.c:1297-1316`)
— the strict version, C-only, and the reason this recipe is PARTIAL (see
`### The strict version (dedup)`).

## The shape

- The persisted outcome is a named `ONE_SHOT_FLAG` item:
  `addOneShotFlag('closeout_done')`. It reads false out of the mint, flips
  true once, and has no path back — `flagSet` has no false transition.
- Raising it is `flagSet(name, setBy, setAtMs)`; reading it is
  `flagValue(name)`. The C struct also records *who* and *when*
  (`src/CRDT/one_shot.h:37-41`), but no JS binding maps those reads — see
  the node snippet's note.
- The guard, on crabs-wasm, is a custom handler on the `closeout` op type
  that consults a `ONE_SHOT_SET` sentinel and returns
  `CRABS_ERR_ALREADY_EXECUTED` (0x7002) on the second attempt. A set is
  used instead of the flag because `HandlerState` exposes `flagSet` but no
  `flagValue` read (`bindings/wasm/index.d.ts:117` — the read exists only on
  `Node`, :293).
- Merge semantics of the flag: true dominates, the earliest timestamp wins,
  and ties break lexicographically by setter id (`test/test_one_shot.cpp:258-292`).

## What it guarantees / what it doesn't

Guaranteed on crabs-wasm: each signed `closeout` op is executed at most
once on that machine — the second attempt is rejected inside the machine
before any effect re-runs; the outcome flag, once true, cannot become
false again on any replica, and after replicas sync they agree on who
executed first (the earliest setter wins).

Not guaranteed: exclusivity *across* replicas that have not yet met. Two
replicas can each pass a local guard (both see an empty sentinel) and both
run the effect; the merged flag stays true either way, and the merged
sentinel set stays a single `run`, so the record converges — but the
effect ran twice. The registered `DEDUP_GLOBAL` spec has the same
single-flag shape and the same edge; what it adds is bypass-proof
enforcement on the signed-op path, and that is C-only. Also not
observable from JS: *which* attempt won (the setter/timestamp reads are
C-only, `src/CRDT/one_shot.h:37-41`).

## Variations

- Idempotent-skip instead of reject: the handler can return 0 on a second
  attempt and just not re-run the effect — the C executor does exactly this
  trick for replayed UUIDs (`CRABS_ERR_ALREADY_EXECUTED` is treated as an
  idempotent skip, `src/StateMachine/state_machine.c:1384-1386`).
- Once-per-window, not once-ever: a trigger with `cooldownMs` (Recipe 6's
  territory) gives you "no more than once per N milliseconds" rather than
  a one-way door.
- Once-per-resource instead of once-global: guard on
  `state.setContains('executed_' + payloadTarget, 'run')` — Recipe 2's
  per-user pattern, keyed by target instead of signer.

## Recipe

### crabs-wasm (browser / Node / edge)

```snippet:wasm/03-execute-once.js
```

<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create               bindings/wasm/index.d.ts:372
  KeyPair.generate          bindings/wasm/index.d.ts:21
  publicKeyHex              bindings/wasm/index.d.ts:15
  KeyPair.destroy           bindings/wasm/index.d.ts:17
  registerUser              bindings/wasm/index.d.ts:213
  grantRole                 bindings/wasm/index.d.ts:214
  addOneShotFlag            bindings/wasm/index.d.ts:227
  flagValue                 bindings/wasm/index.d.ts:293
  addOneShotSet             bindings/wasm/index.d.ts:226
  setPolicy                 bindings/wasm/index.d.ts:295
  registerHandlerJs         bindings/wasm/index.d.ts:303
  HandlerState.setContains  bindings/wasm/index.d.ts:123
  HandlerState.setAdd       bindings/wasm/index.d.ts:115
  HandlerState.flagSet      bindings/wasm/index.d.ts:117
  Operation.create          bindings/wasm/index.d.ts:52
  Operation.signerId        bindings/wasm/index.d.ts:28
  Node.sign                 bindings/wasm/index.d.ts:297
  Node.execute              bindings/wasm/index.d.ts:296
  Node.destroy              bindings/wasm/index.d.ts:368
  (handler return code)     src/CRABS/crabs.h:107 (CRABS_ERR_ALREADY_EXECUTED = 0x7002)
maturity: all STABLE
test_ref: bindings/wasm/test/smoke.js:59 (registerHandlerJs) + test/test_one_shot.cpp:172-201 (flag transitions once)
-->

### crabs-node (native Node.js)

```snippet:node/03-execute-once.js
```

<!-- PROVENANCE
target: crabs-node
verified: executed
symbols:
  NodeStatic.new    bindings/node/index.d.ts:312
  KeyPair.generate  bindings/node/index.d.ts:14
  publicKeyHex      bindings/node/index.d.ts:8
  registerUser      bindings/node/index.d.ts:182
  grantRole         bindings/node/index.d.ts:183
  addOneShotFlag    bindings/node/index.d.ts:197
  flagSet           bindings/node/index.d.ts:245
  flagValue         bindings/node/index.d.ts:246
  (unmapped reads)  src/CRDT/one_shot.h:37-41 (set_by/set_at live in the C struct, no JS row)
maturity: all STABLE
test_ref: test/test_one_shot.cpp:186-201 (SetIsIdempotent: second set keeps the first setter)
-->

### C (native)

```snippet:c/03-execute-once.c
```

<!-- PROVENANCE
target: native-c
verified: executed
symbols:
  one_shot_flag_create        src/CRDT/one_shot.h:43
  one_shot_flag_set           src/CRDT/one_shot.h:45
  one_shot_flag_value         src/CRDT/one_shot.h:46
  one_shot_flag_merge         src/CRDT/one_shot.h:47
  one_shot_flag_destroy       src/CRDT/one_shot.h:44
  (set_by / set_at fields)    src/CRDT/one_shot.h:37-41
  state_create                src/CRABS/data_model.h:684
  state_destroy               src/CRABS/data_model.h:685
  data_item_create            src/CRABS/data_model.h:636
  state_add_item              src/CRABS/data_model.h:719
  data_value_repr_t           src/CRABS/data_model.h:79-81
  state_register_op_type_def  src/CRABS/data_model.h:757
  state_find_op_type_def      src/CRABS/data_model.h:756
  dedup_spec_t                src/CRABS/data_model.h:364-374
  CRABS_MAX_DEDUP_PATH        src/CRABS/data_model.h:330
  dedup_check_guard_spec      src/Dedup/dedup.h:31-33
  dedup_apply_mutation_spec   src/Dedup/dedup.h:43-45
  operation_create            src/StateMachine/state_machine.h:243
  operation_destroy           src/StateMachine/state_machine.h:244
  CRABS_SUCCESS               src/CRABS/crabs.h:65
  CRABS_ERR_ALREADY_EXECUTED  src/CRABS/crabs.h:107
  crdt_value_destroy          src/CRDT/crdt_merge.h:141
maturity: all STABLE
test_ref: test/test_dedup.cpp:726-762 (GlobalExecutionOnceLifecycle) + test/test_one_shot.cpp:258-292 (merge keeps earlier setter)
-->

### The strict version (dedup)

> [!WARNING] GAP
>
> **Prose describes:** an operation type whose global "at most once" rule is
> installed on the machine itself — a registered `DEDUP_GLOBAL` spec — so
> every signed op of that type is guarded by the executor, the guard consults
> the flag the machine owns, and no caller code can forget or bypass it.
>
> **Codebase status:** exists only in C. The spec type is `DEDUP_GLOBAL`
> with a `flag_path` (`src/CRABS/data_model.h:364-374`), installed via
> `state_register_op_type_def` (`src/CRABS/data_model.h:757`), guarded by
> the executor through `dedup_check_guard_spec` (`src/Dedup/dedup.h:31-33`)
> at `src/StateMachine/state_machine.c:1302-1316`, rejecting with
> `CRABS_ERR_ALREADY_EXECUTED`. The C snippet above runs the real functions,
> library-style, on a bare `state_t` — mirroring `test/test_dedup.cpp:726-762`.
>
> **Divergence:** neither JS binding can install a spec — `Operation`
> (`bindings/wasm/index.d.ts:26-49`, `bindings/node/index.d.ts:19-44`) maps no
> dedup field and no `__define_operation_type__` payload builder. The wasm
> recipe above emulates the guard inside a custom handler (one machine's
> registry only); crabs-node has no handler surface at all, so its flag is
> raised by direct driver calls with no execute-time guard anywhere.
>
> **Tracking:** plan — `docs/superpowers/plans/2026-10-11-cookbook-github-pages.md`
> (this task's section). The api-map records the gap at "R3 | `ONE_SHOT_FLAG`,
> global dedup".
>
> **Agent action:** code block omitted. Do not fake a dedup field onto the
> JS `Operation`; the wasm handler pattern above is the strongest
> JS-reachable version.

### Notes

- `flagValue` is typed differently per binding: crabs-wasm returns `0`/`1`
  numbers (`bindings/wasm/bindings-core.js:964` passes the raw C `bool`
  through Emscripten's numeric ABI), crabs-node returns real booleans
  (`bindings/node/src/crabs_node.cc:1689-1690`). Compare truthiness, never
  `=== true`.
- The flag reads as `false` for an unknown item name (`src/Util/wasm_helpers.c:840-845`
  returns false when the item is missing), so a typo in a flag name looks
  like "not executed yet" rather than an error. Assert the name the first
  time you mint it.
- Why the sentinel set instead of guarding on the flag itself: a handler
  may write the flag but not read it — `HandlerState` has `flagSet`
  (`bindings/wasm/index.d.ts:117`) and no `flagValue`; the `Node`-level read
  (:293) is available only outside the handler. The set doubles as the
  guard record, and the flag stays the persisted outcome whose
  setter/timestamp the C core keeps forever.
- The "idempotent skip" nuance: a *replayed UUID* (same op bytes delivered
  twice) does not re-enter the handler at all — the transaction manager
  returns `CRABS_ERR_ALREADY_EXECUTED` and the executor treats it as
  success-without-effect (`src/StateMachine/state_machine.c:1372-1375`). The
  guard above covers the *different* case: a fresh op, signed again,
  intended to run the effect a second time.