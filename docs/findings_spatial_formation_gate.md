# Finding draft: Spatial Formation Gate stress test

Status: prototype experiment design and first harness. This is the next experiment after
the partial-compromise shared-object result.

## Plain question

Can a local gate require a fresh private 3D movement formation before a coding swarm can
touch the filesystem, shell, repository, network, or credentials?

The old shared-object experiment asked whether a static 3D piece helped under partial
compromise. It did not. Stolen neighbors reduced the target residual because every piece
came from one shared object.

This experiment changes the object under test:

```text
old: one shared object split into neighboring pieces
new: one private action-bound proof per agent, optionally tied to a moving 3D path
```

## Arms

| Arm | Meaning |
| --- | --- |
| `random_baseline` | Independent action-bound random proof per required agent |
| `old_shared_object` | The old static shared-object geometry, kept as the failure baseline |
| `independent_static_geometry` | Each agent has an independent private static 3D object |
| `independent_trajectory` | Each agent has an independent private time-indexed 3D path |
| `coordinated_formation` | Private paths plus hidden final formation and collision rules |

## Current gate model

For each action:

1. The gate hashes the exact action.
2. The gate creates a fresh nonce.
3. The gate selects required agents from the action risk.
4. Each sidecar returns an HMAC tag over the action, nonce, and hidden factor digest.
5. Trajectory arms bind the tag to a hidden path digest.
6. The coordinated arm also checks collision-free paths and final formation.
7. A correct formation releases the action.
8. A wrong formation blocks and kills the session.

The LLM never sees the secrets in this model.

## Attack scenarios

The prototype harness measures:

```text
replay_old_formation
changed_action_reuse
same_nonce_reuse
one_stolen_sidecar
two_stolen_sidecars
fake_agent
solver_near_miss
model_generated_guess
collision_or_endpoint_mutation
poisoned_tool_metadata_reuse
wrong_timing_nonce
```

## Main metric

The main residual question is:

```text
Does stealing one or two sidecars reduce the residual for an unstolen target agent?
```

Expected first result:

```text
old_shared_object: yes, stolen sidecars reduce target residual
independent arms: no, stolen sidecars do not reduce an unstolen target residual
```

This is the direct correction to the old shared-object failure.

## Run

First prototype run:

```text
run_dir   : runs/2026-06-20T06-13-03.669741Z
trials    : 20
agents    : 5
grid      : 32 x 32 x 32
timesteps : 16
redaction : clean
digest    : metrics.json.sha256 matches metrics.json
```

Prototype command:

```bash
uv run --extra dev --extra solvers pytest tests/test_spatial_formation_gate.py
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.formation_gate --trials 20
```

## First prototype result

| arm | legitimate pass | max attack release | A0 to A3 target bits lost |
| --- | ---: | ---: | ---: |
| `random_baseline` | 1.00 | 0.00 | 0.00 |
| `old_shared_object` | 1.00 | 0.00 | 2.90 |
| `independent_static_geometry` | 1.00 | 0.00 | 0.00 |
| `independent_trajectory` | 1.00 | 0.00 | 0.00 |
| `coordinated_formation` | 1.00 | 0.00 | 0.00 |

The old shared object still shows the old failure mode. In this 20-trial run, the target
residual moved from 6.29 bits at A0 to 3.39 bits at A3, losing 2.90 bits when two
sidecars were stolen.

The independent and trajectory arms stayed flat for an unstolen target agent. Stealing
one sidecar reduces the number of missing required agents, but it does not reduce the
per-target uncertainty for an unstolen agent.

For the coordinated formation arm, all measured attacks blocked, killed the session, and
used the same public failure channel:

```text
unauthorized release rate : 0.00
blocked rate              : 1.00
one-shot shutdown rate    : 1.00
public response           : blocked
distinct check counts     : [35]
timing proxy leak bits    : 0.00
```

The first harness is intentionally simple. It uses HMAC tags and hidden digests, not
zero-knowledge proofs or hardware isolation. It is a measurement scaffold for the new
security shape.

## Caveats

```text
- This is not a TEE result.
- The timing metric is only a deterministic proxy over public reason/check-count shape.
- The HMAC proof is a simple first stand-in, not the final proof system.
- The old shared-object residual is still the strongest evidence that the old design
  should remain a baseline, not the main path.
```
