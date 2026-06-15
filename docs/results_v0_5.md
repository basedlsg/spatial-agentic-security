# Results v0.5

> Note: dated record of what was measured. Protocol now called UCOG (code name USAG).
> A later fair-baseline experiment (docs/findings_keystone_fair_baseline.md) and the
> formal model (docs/security_model.md) show the geometry adds no cryptographic hardness
> over a unanimous commitment-opening gate; read 'spatial' below as an instantiation
> detail, not a security property.

UCOG (Unanimous Commitment-Opening Gate; code name USAG) v0.5 is **Process Sidecar
Runtime + Minimal Sidecar API**.

Goal:

```text
The logical agent and gateway parent process can request proofs without direct access
to raw sidecar fragments or signing keys.
```

## Commits And Provenance

Implementation and benchmark commit:

```text
commit: 87a4f33fb936e101aefcb109a89935acbd6bab5e
worktree_dirty: false
Python: 3.13.2
platform: macOS-26.2-arm64-arm-64bit-Mach-O
machine: arm64
uv.lock SHA-256: c9bfd2dd5969d91149c5383635ddb096b801c49b4d45d74e2af4ff281119a306
```

Verification:

```text
uv run --extra dev pytest
49 passed

uv lock --check
passed

git diff --check -- Spatial_Agentic_Security
passed
```

## Runtime Model

v0.5 adds an optional process-backed sidecar runtime:

```text
sidecar_runtime = "process"
```

In this mode, setup starts one child process per sidecar. The parent process receives a
restricted `ProcessSidecarClient`, while the child process owns the raw fragment and
signing key.

The parent-visible sidecar API is limited to:

```text
health_check
submit_proof
rotate_epoch
shutdown
```

The process client does not expose:

```text
fragment
coords
signing_key
private_key
show_fragment
show_private_key
show_seed
```

The default high-volume benchmark path remains `sidecar_runtime = "in_process"` so tests
that create many swarms do not spawn thousands of local processes.

## New Tests

Added tests assert:

```text
ProcessSidecarClient exposes only the minimal API.
ProcessSidecarClient has no raw fragment or private-key attributes.
Honest messages pass through process-backed sidecars.
Fake-agent process-sidecar attempts fail closed.
Replay attempts fail before signature, decryption, or per-agent-secret work.
Sidecar shutdown terminates child processes.
Sidecar shutdown rejects later proof requests.
```

## Process Sidecar Smoke Run

Run artifact:

```text
runs/2026-06-12T10-59-47.288348Z
scenario: v0_5_process_sidecar_smoke
agents: 4
fragment_size: 16
attempts: 10 per scenario
commit: 87a4f33fb936e101aefcb109a89935acbd6bab5e
worktree_dirty: false
event_logging: events_jsonl
```

Headline:

```text
honest: 10 / 10 passed
attacks: 0 / 20 unauthorized attempts passed
```

| Scenario | Passes | Failure reason | p95 latency ms | Max proof bytes |
| --- | ---: | --- | ---: | ---: |
| process_sidecar_honest | 10 / 10 | none | 11.243 | 4868 |
| process_sidecar_fake_agent | 0 / 10 | `wrong_signature` | 7.411 | 2440 |
| process_sidecar_replay | 0 / 10 | `wrong_message_hash` | 0.154 | 0 |

Resource use:

```text
max RSS: 48.781 MB
```

Under the recorded run, replay attempts performed no signature checks, no decryptions,
and no per-agent-secret checks (the `geometry_checks_performed` metric is the per-agent
secret-check counter for the 3D/affine instantiation; under the implemented checks it
adds no cryptographic hardness):

```text
process_sidecar_replay signatures_verified p95: 0
process_sidecar_replay decryptions_performed p95: 0
process_sidecar_replay geometry_checks_performed p95: 0
```

## Secret Redaction Check

The following grep over the completed clean v0.5 artifact returned no matches:

```text
rg -n '"coords"|private_key|signing_key|plaintext|decrypted|show_fragment|\
show_private_key|show_seed|full_puzzle|"seed"|seed:' \
  runs/2026-06-12T10-59-47.288348Z
```

## Interpretation

What was observed in v0.5, under the stated conditions:

```text
Under the deterministic local simulator, UCOG ran sidecars as separate child
processes behind a minimal proof API while honest messages succeeded and fake-agent
and replay attempts failed closed, across the recorded attempt counts above.
```

This run did not measure OS sandboxing, container isolation, compromised-host
resistance, zero-knowledge properties, or high-volume process-sidecar scalability;
no claim is made about any of those. The fail-closed behavior recorded here reduces
to the underlying primitives (SHA-256 / Ed25519 / X25519) plus unanimity and message
binding; the 3D/affine "spatial" encoding is one instantiation of the per-agent secret
and, under the implemented checks, adds no cryptographic hardness (see
docs/findings_keystone_fair_baseline.md and docs/security_model.md).
