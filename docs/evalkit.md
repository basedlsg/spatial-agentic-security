# Fail-closed gate evaluation kit

`spatial_swarm.evalkit` drives any message gate through a fixed evaluation and
reports the result in one shape, so different gates can be compared and a new gate
can be dropped in. It generalizes the v0.6 forgery harness, the redaction scanner,
and the failure-stage telemetry to run against any gate, not only USAG.

## What it runs

For a gate and a set of seeds it runs:

- one honest round per seed (every agent honest);
- one round per attacker-capability profile per seed;
- a redaction scan of the gate's observable output (`artifact_text`).

It reports, with exact Clopper-Pearson 95% intervals: the honest release rate, and
per capability the unauthorized-release rate, secret-leak count, and failure
reasons/stages.

## Capability profiles (`STANDARD_CAPABILITIES`)

```text
no_keys_no_secret           real attack  -> expected to fail closed
signing_key_only            real attack  -> expected to fail closed
secret_only                 real attack  -> expected to fail closed
decryption_key_compromise   positive control -> expected to RELEASE
leaked_secret               positive control -> expected to RELEASE
```

The two positive controls give the attacker everything needed, so they release.
They are included so a report that shows "0 unauthorized releases" for the real
attacks is accompanied by evidence that the kit registers a release when one
occurs.

## The `Gate` interface

```python
class Gate(Protocol):
    name: str
    def honest_round(self, agent_count, fragment_size, seed) -> RoundOutcome: ...
    def attack_round(self, agent_count, fragment_size, seed, capability) -> RoundOutcome: ...
    def artifact_text(self, agent_count, fragment_size, seed) -> str: ...
```

`RoundOutcome` carries `passed`, `failure_reason`, `failure_stage`, `secret_leaked`.
Reference gates: `USAGGate` (the spatial USAG pipeline) and `UCOGGate` (the
non-geometric unanimous commitment-opening gate).

## Run it

```python
from spatial_swarm.evalkit import evaluate_gate, USAGGate, UCOGGate

print(evaluate_gate(USAGGate(), seeds=range(3000, 3020)).render())
print(evaluate_gate(UCOGGate(), seeds=range(3000, 3020)).render())
```

Output for both reference gates over 20 seeds: honest 20/20 released; the three
real attacks 0/20 (interval upper bound ~0.17); the two positive controls 20/20
released; redaction clean. USAG rejects `signing_key_only` with `wrong_geometry`
and UCOG with `commitment_opening_failed` (same block, different stage).

A gate with no fail-closed behavior (releases everything) shows the three real
attacks at the full release rate, so the kit distinguishes it from a fail-closed
gate (see `tests/test_evalkit.py::test_kit_flags_a_non_fail_closed_gate`).

## Add a gate

Implement `Gate` for the new gate (map each capability onto the gate's own attack
construction) and pass an instance to `evaluate_gate`. `evaluate_gate` also accepts
a custom `capabilities` tuple.
