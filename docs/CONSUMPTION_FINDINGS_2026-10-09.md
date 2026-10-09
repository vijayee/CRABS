# CRABS — Consumption Findings & Improvement Recommendations

Date: 2026-10-09
From: ResonantDAO Example (vijayee/resonantdao-example) — a live consumer of the WASM bindings (server Node + browser mirrors, ~15 op types, contribution economy on top)
Status: recommendations for discussion; no CRABS master changes proposed yet

This document records six friction points encountered while building a production-shaped consumer of CRABS across four implementation phases. Each finding is evidence-backed (the failure happened), states whether the underlying behavior is judged correct-by-design or a defect, and proposes the minimal fix. Ordering is by impact on consumers.

## 1. Integer-only registers: correct design, undocumented contract

**What happened.** A handler wrote a fractional value (`setRegister('dim:…', 0.5)`): real wasm threw `RangeError: The number 0.5 cannot be converted to a BigInt` three layers deep (`bindings-core.js:1227`); the consumer's jest mocks accepted floats, so nothing caught it until production code ran. Debugging cost: a full test cycle + an ad-hoc per-mille encoding amendment on the consumer side.

**Judgment.** Integer-only registers are *correct-by-design* for a replicated state machine — IEEE floats diverge across platforms and would break replica convergence. This is not a defect.

**The gap.** The contract is invisible: `index.d.ts` types `setRegister(name: string, value: number, …)`, and no README section states the integer-only rule. Consumers learn it from a production RangeError.

**Recommendations:**
- Document the contract (wasm README + JSDoc on the `setRegister` family): registers are BigInt-backed; non-integer values are rejected; consumers encode scaled values (e.g. per-mille) for fractional quantities.
- Add a wrapper-level guard in the glue (`setRegister`/`setRegisterBytes`): reject non-integer `value` *before* the wasm call with a descriptive error — "setRegister: registers are integer-only; encode fractional values in register units" — turning a mystery into a message. (Cheap, high value.)
- Optionally ship a reference `HandlerState` mock (or a parity test fixture) so consumers' own mocks stop masking real-wasm semantics — the mock/real divergence masked integer-only registers AND (see §2) tag-collision drops.

## 2. `setAdd` tag collision silently drops unrelated elements

**What happened.** In OR-Sets, adding element B under a tag already used for element A did not error — it silently dropped the add. A consumer's per-contribution tagging scheme (`tag = contributionId`) therefore erased every second verifier's membership record in a real, live replicated flow. Symptoms were invisible (state just had fewer elements); the bug surfaced only because an end-to-end test asserted a counter that came up short. The consumer fixed it by switching to composite tags (`{signer}:{contributionId}`).

**Judgment.** OR-Set semantics dedupe by `(element, tag)` *pair*; dropping a *different* element on tag collision contradicts the type. Either way, silent drops in a consensus store are dangerous.

**Recommendations:**
- Preferred: honor `(element, tag)` pairs — two different elements sharing a tag are both retained (tag uniqueness per element).
- If tag-collision-as-drop is intentional (e.g. an LWW-tag design), document it in the wasm README's set section AND fail loudly (`duplicate_tag` error) when the colliding tag carries a different element.

## 3. Handlers cannot read set contents

**What happened.** Handler JS sees `setContains` but no enumeration. Every handler that needed to *validate a payload claim against stored records* — verifiers of a claim, a contribution's actual dims, a round's settled contributions — fell back to trusting the payload (records become client-attested and merely re-computed deterministically). This is the consumer's single largest documented trust limitation today.

**Recommendations:**
- Expose read access on `HandlerState`/`Node`: `getSetElements(name): string[]`, `getSetTag(name, element): string` (and optionally a bounded enumerator for large sets, mirroring the existing `maxVoteCheck` discipline).
- Impact: handlers can verify payload claims against the record set — the payload-attestation class of limitation disappears instead of accumulating.

## 4. `setRegisterBytes` is not reachable from handlers

**What happened.** Identity exclusions ("the original verifier may not re-verify after an appeal") need per-resource strings. Registers are numeric; `setRegisterBytes` exists on `Node` — handler-side, a contribution's own record set holds it, but handlers can't read it (§3) — so identity exclusions were forced client-side.

**Recommendation:** expose `setRegisterBytes` (and `getRegisterBytes`) on `HandlerState` alongside the numeric register — combined with §3 it enables honest identity bookkeeping in handlers.

## 5. Version mismatch on deserialize is fail-closed but blind

**What happened.** The vendored client binary (older wire build) returned `0`/null when deserializing the server's ops — one-directional skew (client-old rejects server-new) that broke only the op type the server *authors* (`sync_roles`). Consumers' drift guards work, but the failure mode gives no reason: "deserialize failed" with no version information.

**Recommendations:** expose a wire-format accessor (`Operation.getWireVersion()` / a binary constant) so consumer harnesses can assert the *pairing* of binary versions and produce actionable failures ("binary emits wire v4; op requires ≥ v5") instead of null-vs-nonzero probing.

## 6. Divergent wrapper generations

**What happened.** The consumer ran the JS glue (`bindings-core.js`) server-side and a hand-written older-generation TS port client-side. When the wasm advanced (wire v5, signing format v3, new exports), the two wrappers went out of step — the exact skew behind a multi-day outage hunt.

**Recommendations:**
- Publish a wrapper *generation script* (or a shipped `bindings-core`-derived TS wrapper) so the Node/browser wrappers are built from one source of truth.
- Document which TS wrapper generation pairs with which `crabs.wasm` build (a one-line compatibility matrix in the wasm README).

## Already worked well

For balance, things the library team got right that made the consumer phases land:

- Deterministic per-node op execution with a signed op log: every consumer change converged across server + browser mirrors by construction.
- Declare-before-write (`addRegister`/`addORSet`) plus `duplicate_operation` on re-declare: strict enough to catch handler bugs early once discovered.
- Policy evaluation as ABE attribute expressions with the `OR` operator: the single-valued `role` attribute trap (custodian grant wipes member) was solvable consumer-side with `'role:member OR role:custodian'`.
- Fail-closed deserialization across versions (§5's problem is ergonomics, not safety).
- Schedules/pending-set determinism documented in the wasm README (unused by this consumer so far, but the trust boundary documentation is clear).

## Suggested acceptance order

1 and 2 (document + fail loudly — days of consumer pain each) → 3/4 (read APIs — removes the biggest consumer-side trust hack) → 5/6 (diagnostics + wrapper unification).