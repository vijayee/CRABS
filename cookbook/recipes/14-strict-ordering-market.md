---
number: 14
slug: strict-ordering-market
title: A market that needs strict ordering
section: Composition
status: UNSUPPORTED
maturity: DESIGNED
target: native-c
---
## What this page is

A gap report, not a recipe. A market — bids filling a fixed number of slots,
settled in *one* order every replica agrees on — is the shape where CRABS'
write domains deliberately stop: the `GROUP-ORDERED` domain exists, and v1
ships **no ordering module that could order it**. Unlike the sovereign
surface of Recipes 10 and 13, which is fully executable, the group-ordered
surface cannot deliver its own use case on *any* surface — declaring a
group-ordered item is possible, and everything the item would be FOR is
refused by design until a module exists. This page's recipe would be that
market; no runnable snippet exists because a snippet here would be a lie.

## What the machinery actually does (verified)

- *The domain exists and is honest about emptiness*: `CRABS_DOMAIN_GROUP_ORDERED`
  (`src/CRABS/crabs.h:57`); items carry `ordering_module`, "0 = unset — v1
  ships no modules, so a GROUP_ORDERED item with module 0 is read-only
  (DOMAIN_CHECK fails closed with CRABS_ERR_ORDERING_PATH) until a module is
  registered" (`src/CRABS/data_model.h:176-181`).
- *Creation refuses a real module id — on every surface*: C
  `data_item_create_with_options` refuses `ordering_module != 0`
  (`src/CRABS/data_model.c:161-172`, "v1 ships no ordering modules, so no
  module id can resolve — fail closed at creation"; the struct rule is
  `src/CRABS/data_model.h:204-212`), the blueprint validator refuses it too
  and the wire deserializer fails closed (`src/Lineage/lineage.h:175-182`
  validator, `:210-216` deserializer; refusals tested
  `test/test_lineage.cpp:1598-1611`); the JS bindings narrow `orderingModule`
  to 0 — wasm guards 256-truncation (`bindings/wasm/index.d.ts:186-187`,
  exercised `bindings/wasm/test/write-domains.js:57-61`), node documents
  "v1 ships no ordering modules, so only 0 is legal"
  (`bindings/node/index.d.ts:128-129`).
- *Direct writes are refused at the gate*: a direct op on a group-ordered
  item is `CRABS_ERR_ORDERING_PATH` — "direct write ... (module propose path
  required)" (`src/CRABS/crabs.h:128`; refusal at
  `src/StateMachine/state_machine.c:1078-1090`).
- *Merge cannot rescue divergence*: with no module there is no committed
  prefix to adopt; content divergence between two replicas of a
  group-ordered item is *held* (unresolvable in v1) and surfaced as a
  `__merge_held__` change event carrying the ordering-path error —
  convergence is still reported, the item's divergence is not silently
  merged (`src/CRDT/crdt_merge.c:742-755`,
  dispatch `:844-846`).
- *There is no module to register, anywhere*: the typed interface the design
  names (`crabs_ordering_module_t` with a `propose` entry point) appears in
  the design document only (`docs/superpowers/specs/2026-10-08-write-domains-design.md:137-148`);
  grep `src/` for an ordering-module registry, an election implementation,
  or a committed-prefix log — nothing exists, and no plan under
  `docs/superpowers/plans/` schedules one (the nearest mention is README
  wording about the v1 refusal, `docs/superpowers/plans/2026-10-09-deferred-remediation.md:41`).

## The naive version, and where it breaks

The naive market is two free-merge items — `bids` and `fills` — with a
policy, and the assumption that "first accepted wins". Every replica ACCEPTS
the two racing claim ops in its own arrival order, merge takes them both
(free-merge converges by combining, not ordering), and the machine converges
to a state where two buyers hold the same slot. Nothing in the free-merge
domain can distinguish a race's winner, because nothing in it represents an
order. A sovereign item (Recipe 13) fixes the per-writer problem only: one
writer's fills are chained, but the market's problem is a *shared* order
over many writers' claims — sovereignty's writer check would refuse every
second bidder's claim outright, which solves the double-sale by refusing the
market. And building the order at the application layer ("each claim carries
an id, replicas de-dupe by id") rebuilds the ordering module by hand, except
without the one thing the design requires: a commit point replicas agree on
across partitions.

## The design direction (cited, not implemented)

The project's own design document specifies what v1 lacks —
`docs/superpowers/specs/2026-10-08-write-domains-design.md`:

- an ordering module interface: a registered module with a `propose` entry
  point that "assigns the [order]" for ops touching GROUP_ORDERED items
  (:137-148); at most one module per machine (:57);
- election riding the policy grammar ("so election and rotation ride"
  `role:sequencer`-shaped attributes + epochs, :152-154);
- writes only through the module's propose path; merge adopts the *highest
  committed prefix* (:157); a module unavailable halts writes *of exactly
  those items* (:162); an unknown module id leaves items read-only at load
  (:168, :343);
- the error contract: direct apply to a group-ordered item is
  `CRABS_ERR_ORDERING_PATH` (:340) — the one error the current code actually
  emits, and the codebase's only live GROUP-ORDERED behavior
  (`src/StateMachine/state_machine.c:1078-1090`).

The implemented seam (refuse-at-the-gate, hold-divergence-at-merge) exists
precisely so that the eventual module plugs in without a format break. What
does not exist: election, proposal, a committed log, and any consumer of any
of it. The design doc's reference stack is Raft/CFT/BFT (:168) — none is
present in the tree.

## The verdict

`GROUP-ORDERED` is a sealed seam. Do not build a market, an exchange, or any
strictly-ordered shared state on it until an ordering module exists and a
test exercises propose→commit→merge across replicas; nothing in the code or
the plans promises when that is. The gap, in the standard form:

> [!WARNING] GAP
>
> **Prose describes:** a market whose fills one order decides — two members
> racing for the same buy slot converge on exactly one winner on every
> replica, under an elected ordering module whose committed prefix the
> merge adopts.
>
> **Codebase status:** the domain, the refusal, and the merge-hold exist and
> are tested: `CRABS_DOMAIN_GROUP_ORDERED` (`src/CRABS/crabs.h:57`), a
> non-zero `ordering_module` refused at creation on all three surfaces
> (`src/CRABS/data_model.c:161-172`, wasm `bindings/wasm/index.d.ts:186-187`,
> node `bindings/node/index.d.ts:128-129`; blueprint-side
> `src/Lineage/lineage.h:175-182`, tested
> `test/test_lineage.cpp:1598-1611`), direct writes refused
> `CRABS_ERR_ORDERING_PATH` (`src/StateMachine/state_machine.c:1078-1090`,
> enum `src/CRABS/crabs.h:128`), merge holds divergence unresolvably
> (`src/CRDT/crdt_merge.c:733-757`). But the mechanism the domain exists FOR
> — a registered ordering module with propose/commit, election, adopted
> prefix — is nowhere in `src/` (grep for a module registry, election, or
> committed-prefix log: zero matches in `src/`, `bindings/`, or `test/`;
> the type lives only in the design doc). No snippet on any surface can
> exercise a market; the recipes that DO ship strict behavior on other
> shapes are the sovereign chains of Recipes 10/13.
>
> **Divergence:** the design (`docs/superpowers/specs/2026-10-08-write-domains-design.md:131-168`)
> specifies an elected-module protocol with commit/adopt/halt semantics; the
> code implements the fail-closed seam around the hole the protocol would
> occupy. The intent cannot be delivered on any surface — not on the JS
> bindings, and not on C — so a snippet here would be fabrication rather
> than omission.
>
> **Tracking:** none found. No plan or tracking doc schedules an ordering
> module (nearest: README wording closure about the v1 refusal,
> `docs/superpowers/plans/2026-10-09-deferred-remediation.md:41`). This page
> is the tracking, until a real one exists (the status flips to PARTIAL the
> day a module + a multi-replica propose/commit/merge test land).
>
> **Agent action:** code block omitted — that is the entire recipe body, and
> it is deliberate. Do not write a market or any elected-order flow against
> `ordering_module` fields, do not pass a non-zero `orderingModule` (every
> surface refuses it), and do not present `CRABS_ERR_ORDERING_PATH` as an
> ordering mechanism — it is the refusal that buys the future surface clean.

## The bounded alternatives

What IS deliverable today, and where each stops:

- *Per-writer strict chains*: Recipe 13's sovereign items — one writer, an
  engine-advanced hash chain, gate-refused forks. Strictly ordered *per
  ledger*; no cross-item or cross-writer order (that gap is this page's).
- *Shared convergence without order*: Recipe 1's counters and Recipe 2's
  one-shot votes — commutative merges where "the order" is irrelevant by
  construction; use these instead of a market when the value is a sum or a
  count, not a sequence of grants.
- *Explicit coordination in the application*: a single designated writer
  running a sovereign chain on behalf of the market — Recipe 10's model —
  accepts the trust trade-off that the ordering actor is an application
  choice the engine does not elect or verify. See
  [Recipe 10 — private-but-accountable](/cookbook/private-but-accountable/).