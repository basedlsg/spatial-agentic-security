# Experiment Design

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
- LLM attacker failure mode for future evals

## Baselines

- normal direct communication
- central gateway only, no proof
- Ed25519 signature-only sender gate
- unanimous Ed25519 signature gate
- USAG spatial proof gate

The baseline results should be reported as measured under the same scenario, not as
general claims.
