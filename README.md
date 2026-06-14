# Spatial Agentic Security

This repository implements **USAG: Unanimous Spatial Assembly Gate**, a research-grade
protocol simulator for fail-closed communication in AI-agent swarms.

USAG v1 answers one narrow question:

> Can an unauthorized or fake agent communicate inside a swarm without being born with
> the correct private spatial fragment?

The simulator is intentionally local and deterministic. It uses logical agents, private
sidecars, Ed25519 signatures, sealed proof payloads, finite-field 3D transforms, a central
gateway, one-shot proof envelopes, JSONL logs, and executable adversary classes. It does
not start real LLM agents or containers.

## First Demo

```bash
uv run --extra dev pytest
uv run spatial-swarm benchmark v0_2_matrix --attempts=1
uv run spatial-swarm benchmark baseline_matrix --attempts=1
uv run spatial-swarm benchmark ablation_matrix --attempts=1
uv run spatial-swarm benchmark fuzz_10000 --attempts=2
```

Every run writes a timestamped directory under `runs/`:

```text
runs/<timestamp>/
  config.yaml
  git_commit.txt
  environment.txt
  events.jsonl
  metrics.json
  summary.md
```

Logs include commitments, hashes, packet sizes, latencies, and failure reasons. They do
not include raw fragments, private signing keys, or decrypted sidecar payloads.

## What Is Implemented

- finite 3D grid over `F_p^3`
- deterministic disjoint fragment generation
- message-bound challenge generation
- invertible affine transforms per message
- private sidecars that hold fragments outside the logical agent
- optional process-backed sidecars with a minimal proof API
- Ed25519 signatures using PyNaCl
- sealed encrypted fragment responses using PyNaCl
- one submission per agent per message
- per-agent proof-size and timeout envelopes
- real verifier and assembly checks
- strict fail-closed swarm collapse on any failure
- adversaries for fake, replay, wrong-message, malformed, slow, duplicate, over-budget,
  stolen-fragment, verifier-snapshot-forgery, and partial-swarm attacks
- baseline comparison modes for no gate, sender-signature-only,
  unanimous-signature, and USAG spatial gate
- ablation modes that disable message binding, sender/receiver binding,
  epoch/nonce binding, proof envelopes, geometry checks, or signatures
- deterministic packet fuzzing for malformed packets, mixed packet sets, and replay mutations
- reproducible JSONL experiment logs and generated metrics
- pytest and Hypothesis coverage for protocol invariants

## What Is Not Claimed

USAG v1 does not prove message truth, prevent all misinformation, replace normal
cryptography, or claim that attacks are impossible. Report results as observed behavior
under stated configuration, for example:

```text
0 / 10,000 unauthorized messages passed under N=128, fragment_size=16.
```

The system is about membership and communication authorization, not semantic truth.

## Trusted Gateway And Sidecar Assumption

USAG v0.4 uses an ephemeral setup and a commitment verifier. Setup creates the full
puzzle, cuts it into sidecar pieces, records piece fingerprints, then deletes the full
puzzle and seed. The verifier-visible registry stores public keys, piece fingerprints,
and proof rules, not raw pieces.

This is still a local simulator with trusted gateway and sidecar assumptions. Sidecars
hold raw pieces, and the gateway/verifier decrypts submitted proof packets during a
temporary message check. A compromised host, gateway process, or sidecar can still forge,
bypass, or falsely reject communication.

USAG v0.5 adds an optional process sidecar runtime. With
`sidecar_runtime = "process"`, the parent process receives a restricted client exposing
only `health_check`, `submit_proof`, `rotate_epoch`, and `shutdown`; raw fragments and
private keys remain in the child sidecar process. The default stress benchmark path still
uses in-process sidecars to avoid spawning thousands of local processes.

USAG v0.6 adds a forgery harness and a systematic redaction scanner. Snapshot-boundary
attackers (verifier public state, prior packets, run-artifact directory) and AI/inference
attackers (access levels 0-3) run through one mechanism. The default attacker is a
deterministic optimal-programmatic upper bound: forging reduces to a SHA-256 preimage, an
Ed25519 forgery, and an X25519 sealed-box decryption, so no model with the same access can
do better. A pluggable provider records raw model output unmodified. Two positive controls
(geometry leak, gateway-key compromise) deliberately break through, proving the harness
detects real forgeries and that USAG's hardness is cryptographic, not "AI cannot solve a 3D
puzzle". The transform is public and invertible; the protection is the commitment,
encryption, and signature, not the geometry.

## Repository Map

```text
src/spatial_swarm/
  core/          logical agents, gateway, registry, messages, epochs
  geometry/      finite-grid coordinates, fragments, transforms, assembly
  crypto/        hashing, commitments, signatures, key helpers
  protocol/      challenge, proof packets, verifier, ejection, policies
  attacks/       executable adversary implementations
  experiments/   runner, configs, metrics, reports, baselines

experiments/     scenario entry points and YAML configs
tests/           unit, property, and security tests
docs/            threat model, protocol spec, limitations, paper outline
runs/            generated experiment artifacts
```

## Development

```bash
uv run --extra dev pytest
uv run usag-run --scenario run_all --agents 8 --fragment-size 16 --attempts 3
uv run spatial-swarm benchmark honest_1024
uv run spatial-swarm benchmark attack_scale_1024
uv run spatial-swarm benchmark v0_3_focused_10000
uv run spatial-swarm benchmark v0_4_focused_10000 --attempts=1000
uv run spatial-swarm benchmark v0_5_process_sidecar_smoke
uv run spatial-swarm benchmark v0_6_ai_forgery
uv run spatial-swarm benchmark v0_6_snapshot_forgery
uv run spatial-swarm benchmark v0_6_process_sidecar
uv run spatial-swarm benchmark v0_6_focused
```

The project supports Python 3.9+ because the current local system Python is 3.9.6.

Current clean benchmark summaries are in:

```text
docs/results_v0_2.md
docs/results_v0_3.md
docs/results_v0_4.md
docs/results_v0_5.md
docs/results_v0_6.md
```
