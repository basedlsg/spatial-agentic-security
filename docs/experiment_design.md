# Experiment Design

This document describes the experiments run against UCOG (Unanimous Commitment-Opening
Gate; code name USAG). Under the implemented checks, UCOG releases an inter-agent
message only when every required agent submits a fresh, message-bound, Ed25519-signed
proof that opens its per-agent SHA-256 commitment, decrypted by a trusted gateway. The
3D/affine "spatial" encoding is one instantiation of the per-agent secret and is treated
as an ablated design point; under the implemented checks it adds no cryptographic
hardness over a unanimous commitment-opening gate (see
docs/findings_keystone_fair_baseline.md and docs/security_model.md). References below to
"spatial" or "fragment" describe that instantiation, not a separate security property.

## Core Protocol Experiments

- E1: honest swarm passes
- E2: missing one agent fails
- E3: fake agent fails
- E4: replay proof fails
- E5: wrong-message proof fails
- E6: duplicate proof fails
- E7: over-budget proof fails
- E8: stolen single fragment fails
- E9: `k < N` compromised fragments fail
- E10: all `N` valid fragments pass

## Scale Ladder

```text
N = 4, 8, 16, 32, 64, 128, 256, 512, 1024
fragment_size = 8, 16, 32, 64
messages_per_run = 10, 100, 1000
```

The simulator uses logical protocol agents, not live LLMs or containers.

## Metrics

- unauthorized message pass rate
- honest pass rate
- false ejection rate
- replay success rate
- wrong-message success rate
- verifier latency p50, p95, p99, max
- proof bytes per agent and per message
- swarm collapse rate
- resource use
- attacker failure mode for future evals (the v0.6 "AI forgery" benchmark ran a
  deterministic optimal programmatic attacker; no model was run, and the observed
  outcome reduces to the underlying primitives — SHA-256 / Ed25519 / X25519 — not to
  model capability)

## Baselines

- normal direct communication
- central gateway only, no proof
- Ed25519 signature-only sender gate
- unanimous Ed25519 signature gate
- USAG spatial-instantiation gate (the spatial encoding as the per-agent secret; an
  ablated design point, not a distinct security property)

The measured separation in v0.3 was against signature baselines that never open a
per-agent secret; a fair unanimous commitment-opening baseline matches it (see
docs/findings_keystone_fair_baseline.md). The separation observed there is attributable
to the per-agent commitment opening, unanimity, and message binding, not to the geometry.

Baseline results are reported as measured under the same scenario, not as general
claims.
