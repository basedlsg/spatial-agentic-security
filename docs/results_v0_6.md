# Results v0.6

USAG v0.6 is **Snapshot-Boundary Forgery Matrix + AI/Inference Forgery Benchmark
+ Hardened Secret Redaction**.

Goal:

```text
Test whether an attacker who steals a single system snapshot, or an AI attacker
who only sees public protocol information and prior observations, can forge a
valid spatial proof or extract a raw secret. Make the secret-redaction check
systematic instead of an ad-hoc grep.
```

## Commits And Provenance

Implementation and benchmark commit:

```text
commit: e6aceba2739e8b69ef39a271a6f82076a223a74b
worktree_dirty: false
Python: 3.13.2
platform: macOS-26.2-arm64-arm-64bit-Mach-O
machine: arm64
uv.lock SHA-256: c9bfd2dd5969d91149c5383635ddb096b801c49b4d45d74e2af4ff281119a306
```

Verification:

```text
uv run --extra dev pytest
72 passed

uv lock --check
passed

git diff --check -- Spatial_Agentic_Security
passed
```

## What v0.6 Adds

```text
attacks/forgery_harness.py       one mechanism for snapshot-boundary and
                                 AI/inference attackers, plus positive controls
experiments/redaction.py         reusable secret-marker scanner over a run dir
runner.py                        ai_forgery_matrix and snapshot_forgery_matrix
                                 special scenarios, process_sidecar_shutdown,
                                 v0_6 groups and benchmark presets
```

## What Actually Protects A Proof (Threat-Model Clarification)

A v0.6 prerequisite was to state precisely where USAG's hardness lives, because
the original "spatial puzzle" framing can be read as "an AI cannot solve a 3D
puzzle", which the evidence does **not** support.

In this implementation a proof packet exposes only:

```text
hashes              proof_commitment, fragment_commitment (SHA-256)
ciphertext          encrypted_fragment_response (X25519 sealed box to the gateway)
signature           Ed25519 over the packet
public metadata     agent_id, epoch, message_id, challenge_id, sizes
```

The transformed coordinates are **never in plaintext** in a packet, and the
message-bound affine transform is **public and invertible**. Therefore forging a
proof reduces to:

```text
1. a SHA-256 preimage of the registered fragment commitment, and
2. an Ed25519 signature forgery, and
3. an X25519 sealed-box decryption (to read any geometry at all).
```

The affine transform adds per-message freshness and the assembly tiling check,
but provides **no standalone hardness**. USAG's protection is cryptographic, not
geometric. v0.6's benchmarks and positive controls are designed to demonstrate
exactly this.

## AI / Inference Forgery Benchmark

Run artifact:

```text
runs/2026-06-14T18-32-35.549643Z
scenario: ai_forgery_matrix
agents: 4
fragment_size: 16
attempts: 100 per attacker level
commit: e6aceba2739e8b69ef39a271a6f82076a223a74b
worktree_dirty: false
```

The default attacker is a **deterministic optimal-programmatic** strategy. Since
forging reduces to the three primitives above, no language model can outperform
the optimal algorithm with the same access. The programmatic attacker is thus an
**upper bound**: if it fails at an access level, no LLM with the same access can
succeed. A pluggable `AIForgeryProvider` lets a real model supply candidate raw
coordinates; the harness records the model's raw output without modification and
never rewrites a failed attempt. (No model API keys were configured on this host,
so only the upper-bound attacker was run; the model-provider path is exercised by
unit test.)

Access levels grant valid signing authority from level 1 onward, so the benchmark
isolates the **spatial-inference** question rather than re-testing Ed25519:

```text
ai_level_0_protocol_only        public protocol only; cannot sign as target
ai_level_1_signing_authority    stolen signing key; no fragment, no observations
ai_level_2_many_observations    stolen signing key; 8 prior rounds of packets
ai_level_3_partial_compromise   stolen signing key; one stolen OTHER-agent fragment
```

Headline:

```text
forgery attempts: 0 / 400 produced a valid proof
secrets extracted: 0 / 400
verifier crashes: 0
raw secret markers in artifact scan: 0
```

| Attacker level | Passes | Failure reason | Failure stage |
| --- | ---: | --- | --- |
| ai_level_0_protocol_only | 0 / 100 | `wrong_signature` | signature |
| ai_level_1_signing_authority | 0 / 100 | `wrong_geometry` | geometry |
| ai_level_2_many_observations | 0 / 100 | `wrong_geometry` | geometry |
| ai_level_3_partial_compromise | 0 / 100 | `wrong_geometry` | geometry |

Levels 1-3 clear the signature layer (stolen key) and are stopped only by the
commitment/geometry check. Eight prior rounds of observed packets (level 2) and a
stolen neighbouring fragment (level 3) do not help: the recorded inference method
remains `uniform_random_guess_from_public_commitment` (or
`substitute_stolen_neighbor_fragment`), because observed packets carry only hashes
and ciphertext.

Every attempt logs the full required field set. Example level-1 record:

```text
kind: ai_level_1_signing_authority
model: programmatic_optimal
provider: local_deterministic
temperature: 0.0
output_tokens: 48
parse_result: ok
inference_method: uniform_random_guess_from_public_commitment
failure_reason: wrong_geometry
failure_stage: geometry
message_passed: False
secret_extracted: False
verifier_crashed: False
raw_secret_in_view: False
```

## Snapshot-Boundary Forgery Matrix

Run artifact:

```text
runs/2026-06-14T18-32-54.322787Z
scenario: snapshot_forgery_matrix
agents: 4
fragment_size: 16
attempts: 100 per snapshot
commit: e6aceba2739e8b69ef39a271a6f82076a223a74b
worktree_dirty: false
```

Each attacker is handed exactly one stolen snapshot and tries to forge a proof
and/or extract a raw secret.

Headline:

```text
forgery attempts: 0 / 400 produced a valid proof
secrets extracted: 0 / 400
raw secret markers in artifact scan: 0
```

| Snapshot stolen | Passes | Failure reason | Failure stage |
| --- | ---: | --- | --- |
| verifier public state (no keys) | 0 / 100 | `wrong_signature` | signature |
| verifier public state + signing authority | 0 / 100 | `wrong_geometry` | geometry |
| old proof packets only | 0 / 100 | `wrong_signature` | signature |
| run-artifact directory | 0 / 100 | `wrong_signature` | signature |

Public verifier state, prior packets and the full run-artifact directory contain
only hashes, ciphertext and policy metadata, so none yield a raw fragment or a
releasable proof. With signing authority added (row 2) the attacker reaches and
fails the geometry check, generalising the v0.4 `verifier_snapshot_forgery`
result.

## Positive Controls (Harness Validation)

A benchmark that only ever reports "0 passed" is not credible unless the harness
can also report a real break. Both forgery matrices include two controls that are
**expected to succeed**, and both did (100 / 100 each, in both runs):

| Control | Passes | Secret extracted | Mechanism |
| --- | ---: | ---: | --- |
| control_geometry_leak | 100 / 100 | 100 / 100 | invert public transform on leaked coords |
| control_gateway_key_compromise | 100 / 100 | 100 / 100 | decrypt old ciphertext, invert transform |

These prove two things:

```text
1. The harness detects a genuine forgery (it is not rigged to always fail closed).
2. USAG's hardness is cryptographic: the moment plaintext geometry leaks, or the
   gateway decryption key is stolen, the raw fragment is recovered and a valid
   proof is forged. Host compromise (the gateway key) is explicitly outside the
   threat model.
```

## Process Sidecar Rerun (Including Shutdown)

Run artifact:

```text
runs/2026-06-14T18-33-14.376546Z
scenario: v0_6_process_sidecar
agents: 4
fragment_size: 16
attempts: 100 per scenario
commit: e6aceba2739e8b69ef39a271a6f82076a223a74b
worktree_dirty: false
```

Headline:

```text
honest: 100 / 100 passed
attacks/shutdown: 0 / 300 released a message
```

| Scenario | Passes | Failure reason | p95 latency ms | Max proof bytes |
| --- | ---: | --- | ---: | ---: |
| process_sidecar_honest | 100 / 100 | none | 6.827 | 4876 |
| process_sidecar_fake_agent | 0 / 100 | `wrong_signature` | 2.834 | 2440 |
| process_sidecar_replay | 0 / 100 | `wrong_message_hash` | 0.182 | 0 |
| process_sidecar_shutdown | 0 / 100 | `sidecar_shutdown_enforced` | 0.000 | 0 |

`process_sidecar_shutdown` tears the child sidecars down and then confirms a later
send is blocked (so 0 passes is the desired outcome). Replay still performs no
signature, decryption, or geometry work before failing at message binding:

```text
process_sidecar_replay signatures_verified p95: 0
process_sidecar_replay decryptions_performed p95: 0
process_sidecar_replay geometry_checks_performed p95: 0
```

## Focused Deterministic Regression

Run artifact:

```text
runs/2026-06-14T18-36-52.303343Z
scenario: v0_6_focused
agents: 8
fragment_size: 16
attempts: 1000 per scenario
commit: e6aceba2739e8b69ef39a271a6f82076a223a74b
worktree_dirty: false
```

Headline:

```text
honest: 1000 / 1000 passed
attacks: 0 / 10000 unauthorized attempts passed
```

| Scenario | Passes | Failure reason | p95 latency ms |
| --- | ---: | --- | ---: |
| honest | 1000 / 1000 | none | 14.216 |
| fake_agent | 0 / 1000 | `wrong_signature` | 7.880 |
| unregistered_fake_agent | 0 / 1000 | `unregistered_agent` | 0.157 |
| replay | 0 / 1000 | `wrong_message_hash` | 0.097 |
| wrong_message | 0 / 1000 | `wrong_message_hash` | 0.081 |
| valid_signature_wrong_geometry | 0 / 1000 | `wrong_geometry` | 6.922 |
| valid_signature_wrong_transform | 0 / 1000 | `wrong_geometry` | 7.438 |
| stolen_signing_authority_only | 0 / 1000 | `wrong_geometry` | 7.746 |
| stolen_fragment_only | 0 / 1000 | `wrong_signature` | 7.756 |
| correct_geometry_wrong_agent_id | 0 / 1000 | `response_binding_failed` | 10.208 |
| verifier_snapshot_forgery | 0 / 1000 | `wrong_geometry` | 9.168 |

This matches the v0.4 focused outcomes, confirming v0.6 did not regress existing
fail-closed behavior.

## Systematic Secret Redaction

v0.6 replaces ad-hoc greps with `experiments/redaction.py`, a reusable scanner
checking eleven markers (`"coords"`, `private_key`, `signing_key`, `"seed"`,
`seed:`, `full_puzzle`, `plaintext`, `decrypted`, `show_fragment`,
`show_private_key`, `show_seed`) over every text file in a run directory.

The forgery benchmarks write a `redaction.json` report and an automated test
(`test_v0_6_redaction_scan.py`) asserts a clean run has zero markers, with a
positive control proving the scanner flags a planted secret.

Scan over all four completed clean v0.6 run directories:

```text
runs/2026-06-14T18-32-35.549643Z   secret markers: 0
runs/2026-06-14T18-32-54.322787Z   secret markers: 0
runs/2026-06-14T18-33-14.376546Z   secret markers: 0
runs/2026-06-14T18-36-52.303343Z   secret markers: 0
```

## Resource Use

```text
ai_forgery_matrix        max RSS: 49.62 MB
snapshot_forgery_matrix  max RSS: 49.44 MB
v0_6_process_sidecar     max RSS: 49.53 MB
v0_6_focused             max RSS: 54.69 MB
```

## Deviations From The Proposed v0.6 Plan

```text
Container sidecar smoke (plan Goal 2) is deferred to v0.7. Docker is unstable on
this host, and a rushed container path would weaken rather than strengthen the
result. It is documented as optional and is not a v0.6 success gate. The
process-sidecar boundary (v0.5) plus the v0.6 shutdown scenario already exercise
the parent/child isolation question.

The AI-forgery attacker is granted valid signing authority from level 1 onward.
This is the stronger attacker and isolates the spatial-inference question instead
of re-testing the signature layer.

The AI-forgery default attacker is a deterministic optimal-programmatic upper
bound rather than a live model run, for the reason given above (an LLM cannot beat
the optimal algorithm against these primitives) and because no model keys were
configured. The model-provider interface is implemented and unit-tested.
```

## Interpretation

The v0.6 evidence supports this claim:

```text
Under the deterministic local simulator, an attacker holding any single stolen
snapshot (verifier public state, prior packets, or the run-artifact directory),
and an optimal inference attacker with public protocol information, prior
observations, valid signing authority, or a stolen neighbouring fragment, could
not forge a valid spatial proof or extract a raw secret across 800 forgery
attempts. Because forging reduces to standard SHA-256 / Ed25519 / X25519
assumptions, this upper-bound result also covers any language-model attacker with
the same access. Two positive controls confirm the harness detects real breaks
and that USAG's hardness is cryptographic, not geometric. The focused regression,
process-sidecar rerun (with shutdown), and a systematic redaction scan over all
four clean runs show no regression and zero secret markers.
```

It does not prove zero-knowledge security, compromised-host resistance (the
gateway-key control breaks confidentiality by design), OS/container sandboxing,
or that a real frontier model was run. It is an upper-bound argument plus an
implemented, unit-tested model hook, not a live model evaluation.

## Reproduce

```text
uv run --extra dev pytest
uv run usag-run benchmark v0_6_ai_forgery       --seed 60001
uv run usag-run benchmark v0_6_snapshot_forgery --seed 60002
uv run usag-run benchmark v0_6_process_sidecar  --seed 60003
uv run usag-run benchmark v0_6_focused          --seed 60004
```
