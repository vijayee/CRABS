---
number: 15
slug: hardware-attested-policy
title: A hardware-attested fact as policy
section: Ground truth
status: UNSUPPORTED
maturity: DESIGNED
target: native-c
---
## What this page is

A gap report, not a recipe. Hardware attestation is the shape where a
device's own silicon vouches for software state — a secure element or TPM
measurement becomes an ordinary CRABS attribute (`hw:tpm-2.0`), and a policy
clause like `AND hw:tpm-2.0` is satisfiable only by ops minted on hardware
that actually presented that measurement. CRABS ships real machinery for
*signed software vouches about other software* — the lineage attestations of
Recipe 12 — but nothing that binds an attribute's *origin* to hardware. This
page's recipe would be the bridge; no runnable snippet exists on any surface,
because a snippet here would be a lie.

## The intent, stated exactly

- A device's TPM/secure-element produces a measurement or a signed counter;
  that measurement enters the machine's attribute system as an attribute
  pair — `hw:tpm-2.0`, or a device-specific value bound to the device's
  identity.
- From there everything downstream already exists in CRABS: an op policy
  (`setPolicy('sign_led', 'AND role:member hw:tpm-2.0')`) or an encrypt
  policy (Recipe 6's ABE seal) restricts the gated thing to members whose
  `hw:` attribute was minted by the device, not the software.
- The attribute should also *decay like a measurement*: bounded by a TTL
  (a measurement is evidence about a boot, not a permanent rank) and
  revocable when the device is recomposed or lost.

## The naive version, and where it breaks

The naive version asserts the attribute from software. Two existing paths do
exactly this, and both make "attested" indistinguishable from "claimed":

- *Self-assertion*: on the node binding, `selfAssert(attribute, value,
  signerId)` attaches any attribute to your own record
  (`bindings/node/index.d.ts:184`). The attribute record stores the
  `verifiedBy` string — here, the signer asserting it about itself
  (`bindings/node/src/crabs_node.cc:1153`). Nothing in the record can
  distinguish "the TPM read this" from "the software wanted this".
- *Admin vouching per device*: `grantRole(targetUser, 'hw', 'tpm-2.0',
  signerId)` (both bindings) makes an administrator the source of truth.
  An admin who is socially engineered, rushed, or just tired of the process
  mints `hw:` facts as easily as role facts; the machine enforces the
  *signature*, never the *measurement*.

The machinery's own honesty is the tell: every attribute gate in the
evaluator is a *name/value token match* (`src/Crypto/crypto.c:1126-1163`)
over attributes that `grantRole`/`selfAssert` minted — the policy grammar
cannot even express "and the signer of this attribute must be a device",
only which id signed it (state_machine.c:652-653 documents the same
limitation for endorsements: "v1 evaluates no boolean logic over attested
attributes — attribute `dept:red` attested ⇔ endorsement
`@parent/dept:red` matched").

## What the machinery actually does (verified)

- *The attribute system has no source abstraction*: attributes arrive via
  `registerUser` initial-attrs, `grantRole`, node-only `selfAssert` /
  `verifyIdentity`, and trigger-issued temporaries (Recipe 6's
  `issue_attribute` fan-out, `src/Attribute/attribute_machine.c:954-1026`).
  All four sources are software components inside the machine; none can read
  a TPM. Grep `src/` and both `.d.ts` files for `hardware`, `secure`,
  `attested`, `hw:` — no hardware-attestation namespace exists anywhere in
  the shipped code.
- *The credential SHAPE the intent needs does exist* — for machine-to-machine
  vouching: a parent machine signs a TTL-bounded attribute grant that a
  child's policy resolves per op (`attestation_t`,
  `src/Lineage/lineage.h:89-104`; issuance manifest-gated at
  `src/Lineage/lineage.h:670-685`; consume pipeline
  `src/StateMachine/state_machine.c:700-756`). That is Recipe 12, and it is
  a *parent machine* signing — software vouching for software, with a key
  chain, not a device presenting a measurement.
- *The only TPM-shaped code in the tree is an unimplemented time-source
  slot*: `CRABS_TIME_SOURCE_TPM = 0x02` (`src/HLC/hlc.h:57`) is declared and
  never implemented — the HLC treats TPM exactly like NTP and consensus: it
  requires caller-attached `time_source_ops`, falls back to nothing, and
  fails closed (`src/HLC/hlc.c:276-286` — the R8-H-1 comment names TPM as a
  source that must have ops attached). The only time source `src/TimeSource/`
  actually implements is HTTPS (`src/TimeSource/time_source.c:2`, factory at
  `:201`), and the JS bindings narrow the choice to `'https' | 'system'`
  (`bindings/wasm/index.d.ts:313-321`, `bindings/node/index.d.ts:267-278`).
- *The design says TPM was considered — as a clock.* The protocol
  specification amendment defines `TIME_SOURCE_TPM` and a §7.3 "TPM Hardware
  Clock" with pseudocode (`docs/CRABS Protocol Specification v1.6 Amendment
  6.md:218` and `:669-689`), and its trust table ranks hardware-backed time
  as trusted at the hardware level (`:1080`). A TPM *time source* is not a
  TPM *attestation source*: the design's own scope is time integrity, not
  binding measurements into the attribute system.

## The verdict

A hardware-attested policy needs three things the codebase does not have: an
issuer that reads the device (the `hw:` namespace's source), the attribute
record carrying that origin ("attested by the device", not `verifiedBy:
'admin'`), and — for the seal half — a decryption path usable from hardware
holders. None is present in `src/`, `bindings/`, or the shipped designs. The
gap, in the standard form:

> [!WARNING] GAP
>
> **Prose describes:** a device measurement — a TPM/secure-element value —
> entering CRABS as a policy attribute (`hw:tpm-2.0`), so that authorization
> policies and ABE seal policies can require `AND hw:tpm-2.0` and be
> satisfiable only by ops minted on attested hardware.
>
> **Codebase status:** no such namespace exists. Grep of `src/` and both
> binding surfaces for `hardware`/`secure`/`attested`/`hw:` returns no
> attribute-issuer, no new attribute namespace, and no device-identity
> surface; the attribute system's only four input paths are
> register-attrs, `grantRole`, `selfAssert`/`verifyIdentity` (node only,
> `bindings/node/index.d.ts:184-185`), and trigger-issued temporaries — all
> software. The nearest implemented machinery is the lineage attestation —
> parent-signed, TTL-bounded, chain-key-bound (Recipe 12;
> `src/Lineage/lineage.h:89-104`, consume
> `src/StateMachine/state_machine.c:700-756`) — whose signer is a parent
> *machine*, never a device. The only TPM reference in the tree is the
> declared-unimplemented HLC enum `CRABS_TIME_SOURCE_TPM = 0x02`
> (`src/HLC/hlc.h:57`; ops-required, fail-closed `src/HLC/hlc.c:276-286`),
> and the bindings expose only `'https' | 'system'` time modes
> (`bindings/wasm/index.d.ts:313-321`, `bindings/node/index.d.ts:267-278`).
>
> **Divergence:** the protocol design ranks hardware-backed trust in its
> trust table and designs a TPM time source with pseudocode
> (`docs/CRABS Protocol Specification v1.6 Amendment 6.md:218`, `:669-689`,
> `:1080`), but only ever scopes it to *time integrity*; nothing in the
> design or code bridges a hardware measurement into the attribute/policy
> system — and the design's own consume-side comment records that v1
> evaluates no boolean logic over attested attributes
> (`src/StateMachine/state_machine.c:652-653`).
>
> **Tracking:** none found. No plan or design doc under `docs/` schedules a
> hardware-attestation attribute source (the TPM mentions are the protocol
> amendment's time-source design and the HTTPS time-source plan's enum
> table, `docs/superpowers/plans/2026-08-14-https-time-source.md:157,168`;
> the api-map's capability ledger records the same not-found verdict,
> `cookbook/api-map.md:289`).
>
> **Agent action:** code block omitted — that is the entire recipe body, and
> it is deliberate. Do not invent a `hw:*` attribute namespace, a
> `setTimeSource('tpm')` mode, or a device/TPM symbol on either binding; and
> do not present `grantRole('dev1', 'hw', 'tpm-2.0')` as attestation — it is
> the admin-vouch shape this page's naive version exists to condemn.

## The bounded alternative

The real machinery nearest to the intent is Recipe 12's lineage
attestation — a *parent machine* signing a TTL-bounded `name:value` grant
that a child's endorsement policy resolves per op
(`attestation_t`'s free-form attributes field,
`src/Lineage/lineage.h:92-104`).

What **repurposes today**: the wire-shape and consume path — a device-fleet
operator could mint `hw:tpm-2.0`-shaped vouches for child machines and let
policies require `@parent/hw:tpm-2.0`, with TTL decay and revocation already
implemented and engine-tested (`src/StateMachine/state_machine.c:700-756`,
`test/test_lineage.cpp:644-777`).

What is **still missing** — and why this page stays UNSUPPORTED: the vouch's
signer is the parent machine's software key, so "attested" still means
"the parent machine claimed it" — precisely the naive version's problem,
moved up one hop. What would close the gap is a source component that reads
a device measurement and gates the parent's issuance on it. That component
does not exist in `src/`, is scheduled by no plan, and — one layer further
down — the consume half of attestations is C-only today (Recipe 12's gap:
the JS bindings can mint attestations but not resolve them), so no browser
policy can participate even in the software-vouch version. See
[Recipe 12 — federation between machines](/cookbook/federation-between-machines/)
for the deliverable half.