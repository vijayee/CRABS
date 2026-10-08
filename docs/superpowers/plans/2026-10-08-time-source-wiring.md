# Authenticated Time-Source Wiring Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the already-built authenticated HTTPS time source selectable per machine — via CLI (`time-source https|system|show`) and Node bindings (`setTimeSource`/`getTimeSource`) — so the A10-L9 attestation-clock caveat is closable by configuration, without defaulting it on for every machine.

**Architecture:** A machine's clock is `state_t.hlc_state.time_source_ops` (`state_set_time_source`). `crabs_time_source_https_create(config)` already picks the correct transport per platform (native HTTPS / WASM sync bridge), so no wasm-specific work is needed. The CLI/node binding own the created ops object and must (a) destroy it at node destruction, (b) RE-APPLY it whenever the machine's state is replaced (`init`/`load`/`load-sealed` recreate or swap `state_t` — a configured source would otherwise silently fall back to the system clock), and (c) treat it as session-scoped runtime config (not serialized state).

**Tech Stack:** C11 CLI, node-addon-api bindings, ctest, node test.js.

**Baseline:** ctest 1599/1599 (1 skip). Time source covered by test/test_time_source.cpp.

**Key code facts:**

```c
// src/TimeSource/time_source.h
typedef struct {
  const char* server_url;          // NULL -> https://cloudflare.com/cdn-cgi/trace
  uint64_t    resync_interval_ms;  // default 30000
  uint64_t    timeout_ms;          // default 1000
  uint64_t    max_skew_ms;         // default 5000 (0 disables)
} crabs_time_source_config_t;
crabs_time_source_ops_t* crabs_time_source_https_create(const crabs_time_source_config_t* config);
void                     crabs_time_source_destroy(crabs_time_source_ops_t* ops);

// src/CRABS/data_model.c:228
void state_set_time_source(state_t* state, void* time_source_ops);  // stores raw pointer
```

- A failed fetch NEVER falls back to the local clock (R7-02) — with an authenticated config and an unreachable server, time reports invalid and window checks fail closed. README must keep saying so.

---

### Task 1: CLI `time-source` command

**Files:**
- Modify: `src/CLI/cli.h` (cli_node_t fields), `src/CLI/cli.c` (new `cli_node_set_time_source` + dispatcher arm + usage), `test/test_cli.cpp`

- [ ] **Step 1: failing tests** (TestCLI):
  - `TimeSource.HttpsSetsSourceAndSurvivesInitReload`: init → `time-source https https://example.com/x` → CLI_OK → `state_get_time_ms` path valid (assert via `node->` plumbing, not actual fetch: expose the applied marker). Reload (`load-sealed` or re-`init`) → still applied (the re-apply behavior).
  - `TimeSource.SystemClearsSource`
  - `TimeSource.ShowReportsCurrent`
  - `TimeSource.RefusesBeforeInit` (CLI_ERR_NOT_INIT)
- [ ] **Step 2: RED.**
- [ ] **Step 3: implement.** cli_node_t gains:
```c
  // Session-scoped time-source choice (A10-L9 wiring). NOT serialized —
  // implementations are code, not state. Applied (re-applied) to whichever
  // state_t the node currently carries after init/load.
  enum { CLI_TIME_SOURCE_SYSTEM = 0, CLI_TIME_SOURCE_HTTPS = 1 } mode stored as int;
  char https_url[256];              // "" = default endpoint
  crabs_time_source_ops_t* https_source;  // currently-created ops, or NULL
```
  New static `_apply_time_source(node)` (create+set or clear, idempotent), called at the END of `cli_node_init`, `cli_node_load` (success paths) and `load-sealed`. Dispatcher arm `time-source` with subs `https [url]` (validate: URL must start https:// — native parser enforces too, CLI message clearer), `system`, `show`. Usage + whitelist. `cli_node_destroy` destroys https_source.
- [ ] **Step 4: GREEN + full suite.** Commit: `feat: CLI time-source command — select authenticated HTTPS clock per machine`

### Task 2: Node bindings `setTimeSource` / `getTimeSource`

**Files:**
- Modify: `bindings/node/src/crabs_node.cc` (Node class: owned ops ptr + methods), `bindings/node/src/crabs_node.h` if exists, test/test.js

- [ ] **Step 1: failing JS tests:**
  - `setTimeSource({mode:'https', url:'https://example.com/x'})` → resolves; `getTimeSource()` → `{mode:'https', url:...}`.
  - `setTimeSource({mode:'system'})` → clears; `getTimeSource()` → `{mode:'system'}`.
  - `setTimeSource({mode:'bogus'})` → TypeError. Non-object arg → TypeError. A non-https url → error before any state change.
- [ ] **Step 2: RED** (method absent).
- [ ] **Step 3: implement.** Node gains owned `crabs_time_source_ops_t* time_source_;`; set: destroy old, create new with config{server_url=url or NULL, defaults else}, or NULL for system; applied IMMEDIATELY to the current machine state (`state_set_time_source(&am_->base_state, ops)` / NULL) — note node wrapper's machines (parent + adopted children) each have their own state_t: apply to THIS wrapper's machine only (document it: per-machine, not fleet-wide). Destroy in destructor (guard adopted wrappers: they create no wrapper-owned ops).
- [ ] **Step 4:** `node test/test.js` + smoke green; full ctest green. Commit: `feat: node bindings setTimeSource/getTimeSource — per-machine authenticated clock`

### Task 3: README + audit doc

**Files:**
- Modify: `README.md` (the A10-L9 caveat paragraph ~:221-227): replace "recommend configuring an authenticated time source" with the shipped surfaces (`crabs_node time-source https [url]`, `node.setTimeSource(...)`) and note the interval model (resync default 30 s, monotonic interpolation — no network call per auth check) + the fail-closed R7-02 behavior.
- Modify: `docs/SECURITY_AUDIT_10.md` A10-L9 entry status: FIXED via caveat + wiring commit refs.

- [ ] Commit: `docs: time-source caveat references shipped selection surfaces`

Report/verify per task with the usual two-stage review.