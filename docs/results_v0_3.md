# Results v0.3

> Note: dated record of what was measured. Protocol now called UCOG (code name USAG).
> A later fair-baseline experiment (docs/findings_keystone_fair_baseline.md) and the
> formal model (docs/security_model.md) show the geometry adds no cryptographic hardness
> over a unanimous commitment-opening gate; read 'spatial' below as an instantiation
> detail, not a security property.

UCOG (Unanimous Commitment-Opening Gate; code name USAG) v0.3 adds baseline comparisons,
verifier ablations, deterministic packet fuzzing, and a focused 10,000-attempt benchmark.

## Commits And Provenance

Baseline and ablation artifacts were generated from:

```text
commit: 761439ec02b6da07ee0f2a7b37851b8873d513cf
worktree_dirty: false
```

The fuzzer fix and subsequent fuzz/focused artifacts were generated from:

```text
commit: 9dd65b330e195436f3465015c501bce79059c19a
worktree_dirty: false
Python: 3.13.2
platform: macOS-26.2-arm64-arm-64bit-Mach-O
machine: arm64
uv.lock SHA-256: c9bfd2dd5969d91149c5383635ddb096b801c49b4d45d74e2af4ff281119a306
```

## Baseline Comparison

Run artifact:

```text
runs/2026-06-08T16-43-14.539147Z
scenario: baseline_matrix
attempts: 1000 per scenario
```

Mode-level result:

| Mode | Passes | Attempts | Unauthorized passes | p95 latency ms |
| --- | ---: | ---: | ---: | ---: |
| mode_0_no_gate | 15000 | 15000 | 14000 / 14000 | 0.080 |
| mode_1_sender_signature_only | 10000 | 15000 | 9000 / 14000 | 3.417 |
| mode_2_unanimous_signature_gate | 10000 | 15000 | 9000 / 14000 | 24.693 |
| mode_3_usag_spatial_gate | 1000 | 15000 | 0 / 14000 | 27.036 |

Per-scenario comparison across the four modes (the USAG spatial gate column is one
instantiation of the per-agent secret; see the banner above):

| Scenario | No gate | Sender sig only | Unanimous sig | USAG spatial gate |
| --- | ---: | ---: | ---: | ---: |
| valid_signature_wrong_geometry | 1000 / 1000 passed | 1000 / 1000 passed | 1000 / 1000 passed | 0 / 1000 passed, `wrong_geometry` |
| valid_signature_wrong_transform | 1000 / 1000 passed | 1000 / 1000 passed | 1000 / 1000 passed | 0 / 1000 passed, `wrong_geometry` |
| stolen_signing_authority_only | 1000 / 1000 passed | 1000 / 1000 passed | 1000 / 1000 passed | 0 / 1000 passed, `wrong_geometry` |
| fake_agent | 1000 / 1000 passed | 0 / 1000 passed | 0 / 1000 passed | 0 / 1000 passed |
| replay | 1000 / 1000 passed | 0 / 1000 passed | 0 / 1000 passed | 0 / 1000 passed |
| wrong_message | 1000 / 1000 passed | 0 / 1000 passed | 0 / 1000 passed | 0 / 1000 passed |

Interpretation:

```text
In this benchmark the signature-only baselines (modes 1 and 2) catch ordinary
impersonation and replay/message-binding attacks, but pass the
valid_signature_wrong_geometry / wrong_transform / stolen_signing_authority_only
scenarios. Those baselines never open a per-agent secret, so any holder of a valid
signature passes. Mode 3 (USAG) additionally requires each agent to open its per-agent
commitment, and rejected those scenarios with `wrong_geometry` here.

The measured separation is therefore against baselines that do not open a per-agent
secret. A later experiment with a fair unanimous commitment-opening baseline (no
geometry) matched mode 3 on these scenarios (docs/findings_keystone_fair_baseline.md),
so the separation in this table comes from per-agent commitment opening + unanimity +
message binding, not from the 3D/affine geometry. The geometry is one instantiation of
the per-agent secret and, under the implemented checks, adds no cryptographic hardness.
```

## Ablation Matrix

Run artifact:

```text
runs/2026-06-08T17-18-57.691476Z
scenario: ablation_matrix
attempts: 1000 per scenario per ablation
```

Selected layer-shift outcomes:

| Ablation | valid_signature_wrong_geometry | fake_agent | overbudget | replay |
| --- | --- | --- | --- | --- |
| usag_full | `wrong_geometry` | `wrong_signature` | `over_budget` | `wrong_message_hash` |
| without epoch/nonce binding | `wrong_geometry` | `wrong_signature` | `over_budget` | `wrong_message_hash` |
| without geometry check | `assembly_failed` | `wrong_signature` | `over_budget` | `wrong_message_hash` |
| without message hash binding | `wrong_geometry` | `wrong_signature` | `over_budget` | `wrong_challenge` |
| without proof-envelope budget | `wrong_geometry` | `wrong_signature` | `wrong_signature` | `wrong_message_hash` |
| without sender/receiver binding | `wrong_geometry` | `wrong_signature` | `over_budget` | `wrong_challenge` |
| without signatures | `wrong_geometry` | `wrong_geometry` | `over_budget` | `wrong_message_hash` |

Important observations:

```text
With the geometry check disabled, the wrong-geometry scenario was still rejected, with
the reason code shifting to `assembly_failed`. (The verifier's "assembly" step checks
set-membership and disjointness of the opened per-agent secrets, not geometric tiling;
the geometric assembles_exactly routine is never called by the verifier.)
With signatures disabled, the fake-agent scenario was still rejected, with the reason
code shifting to `wrong_geometry`.
With the proof-envelope budget disabled, the overbudget scenario's rejection reason
shifted from `over_budget` to `wrong_signature`.
Each disabled layer changed which reason code was emitted in these runs; the present
data does not isolate the cryptographic contribution of any single layer.
```

## Fuzzing

Diagnostic failed artifact:

```text
runs/2026-06-08T17-52-23.859215Z
fuzz_malformed_packet: 10 / 10000 passed
```

Cause:

```text
The signature mutation sometimes replaced the first base64 character with the same
character, producing a no-op mutation. This was fixed in commit
9dd65b330e195436f3465015c501bce79059c19a.
```

Corrected run artifact:

```text
runs/2026-06-08T18-06-42.089640Z
scenario: fuzz_10000
attempts: 10000 per fuzzer class
```

Result:

```text
total passes: 0 / 30000
verifier crashes: 0 observed
raw secret markers in artifact grep: 0
```

| Fuzzer class | Passes | Dominant failure reasons | p95 latency ms |
| --- | ---: | --- | ---: |
| fuzz_malformed_packet | 0 / 10000 | mixed registration, binding, envelope, signature, geometry failures | 10.362 |
| fuzz_mixed_packet_set | 0 / 10000 | duplicate, geometry, registration, binding, envelope failures | 7.209 |
| fuzz_replay_mutation | 0 / 10000 | `wrong_message_hash` | 10.257 |

## Focused 10,000-Attempt Benchmark

Run artifact:

```text
runs/2026-06-08T18-19-48.468808Z
scenario: v0_3_focused_10000
attempts: 10000 per scenario
```

Headline:

```text
honest: 10000 / 10000 passed
attacks: 0 / 90000 unauthorized attempts passed
```

| Scenario | Passes | Failure reason | Stage | p95 latency ms | p99 latency ms |
| --- | ---: | --- | --- | ---: | ---: |
| honest | 10000 / 10000 | none | release | 13.284 | 14.558 |
| fake_agent | 0 / 10000 | `wrong_signature` | signature | 5.295 | 5.929 |
| unregistered_fake_agent | 0 / 10000 | `unregistered_agent` | registration | 0.003 | 0.004 |
| replay | 0 / 10000 | `wrong_message_hash` | message_binding | 0.006 | 0.008 |
| wrong_message | 0 / 10000 | `wrong_message_hash` | message_binding | 0.006 | 0.007 |
| valid_signature_wrong_geometry | 0 / 10000 | `wrong_geometry` | geometry | 5.994 | 6.454 |
| valid_signature_wrong_transform | 0 / 10000 | `wrong_geometry` | geometry | 5.982 | 6.508 |
| stolen_signing_authority_only | 0 / 10000 | `wrong_geometry` | geometry | 6.067 | 7.254 |
| stolen_fragment_only | 0 / 10000 | `wrong_signature` | signature | 5.333 | 5.572 |
| correct_geometry_wrong_agent_id | 0 / 10000 | `response_binding_failed` | response_binding | 5.994 | 7.345 |

## Partial Artifacts

Do not report these as completed benchmark results:

```text
runs/2026-06-08T16-58-55.535595Z
scenario: ablation_matrix
status: interrupted partial run
events logged: 30,527
metrics.json: absent

runs/2026-06-08T17-52-23.859215Z
scenario: fuzz_10000
status: failed diagnostic run
reason: no-op signature mutation allowed 10 malformed attempts to pass
```

## Trusted Verifier Limitation

USAG v0.3 assumes a trusted gateway/verifier. The verifier stores raw fragments and can
bypass or forge verification if compromised. Current results test fail-closed
communication under this assumption.

## Interpretation

What the v0.3 runs recorded:

```text
Under the deterministic trusted-verifier harness, mode 3 (USAG) rejected the
valid_signature_wrong_geometry / wrong_transform / stolen_signing_authority_only
scenarios that the signature-only baselines (modes 1 and 2) passed, and the implemented
focused, ablation, and fuzz attempts passed 0 unauthorized attempts (after the fuzzer
no-op mutation bug was fixed).
```

Scope and caveats:

```text
The signature-only baselines do not open a per-agent secret, so this is a comparison
against a weaker gate. A later fair unanimous commitment-opening baseline (no geometry)
matched mode 3 on the same scenarios (docs/findings_keystone_fair_baseline.md); under
the implemented checks the 3D/affine geometry adds no cryptographic hardness over a
unanimous commitment-opening gate (docs/security_model.md). The "assembly" step the
verifier runs checks set-membership and disjointness, not geometric tiling.

These runs do not establish foolproof security, semantic truth, verifier-compromise
resistance, or superiority over cryptographic alternatives; they assume a trusted
gateway and were measured under the stated harness conditions.
```
