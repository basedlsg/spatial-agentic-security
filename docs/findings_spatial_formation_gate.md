# Finding: Spatial Formation Gate stress test

Status: strengthened experiment and measured result.

## Plain answer

The old shared-object experiment is now best understood as the negative baseline:
shared 3D structure leaks when neighboring pieces are stolen.

The Spatial Formation Gate experiment tests the replacement idea:

```text
A coding swarm cannot touch the device until a local gate receives a fresh,
action-bound, private 3D formation proof from the required agents.
```

The strengthened run is much better than the first prototype. It now covers more
trials, more action types, larger swarms, replay, action reuse, near misses, stolen
sidecars, coordinator forgery, analysis mode, weakest-agent behavior, ablations, and a
separate 10,000-trial cheap attack stress pass.

The main result:

```text
old shared object:
  stolen neighbors still collapse the target residual

independent per-agent and formation-gated designs:
  stolen neighbors did not reduce the unstolen target residual in this model

coordinated formation gate:
  0 observed unauthorized releases in the 1,000-trial full run
  0 observed unauthorized releases in 10,000 cheap trials per attack scenario

ablations:
  removing path, endpoint, nonce, or geometry checks makes specific attacks release
```

So the new experiment now supports the intended design pivot:

```text
do not use 3D as one shared secret object
use 3D as a local, fresh, action-bound formation gate
```

This is still not a proof that the gate is secure. It is a stronger prototype security
experiment showing that geometry is doing measurable work in this harness.

## Design Under Test

The old design was:

```text
one shared hidden 3D object -> neighboring agent pieces
```

That failed under partial compromise because pieces are correlated. If an attacker steals
neighboring pieces, the remaining search space for the target piece shrinks.

The new design is:

```text
one fresh local action -> required agents -> private proofs -> coordinated formation
```

For each action, the gate:

1. Hashes the exact action request.
2. Creates a fresh nonce.
3. Chooses required agents from the action risk.
4. Requires each sidecar to return an HMAC proof.
5. Binds each proof to the action hash, nonce, private path digest, and endpoint digest.
6. For the coordinated formation arm, checks path length, collisions, path crossing,
   forbidden regions, and final formation.
7. Releases the action only if the required proofs and formation checks pass.
8. Blocks and kills the session on a bad proof in deployment mode.

This is a measurement scaffold. The proof is an HMAC stand-in, not the final proof system.

## Arms

| Arm | Meaning |
| --- | --- |
| `random_baseline` | Independent action-bound random proof per required agent |
| `old_shared_object` | The old static shared-object geometry, kept as the failure baseline |
| `independent_static_geometry` | Each agent has an independent private static 3D object |
| `independent_trajectory` | Each agent has an independent private time-indexed 3D path |
| `coordinated_formation` | Private paths plus hidden final formation and collision rules |

## Strengthened Coverage

The first prototype was too small and too clean. The new harness adds the following.

Action types:

| Action | Risk | Median required agents |
| --- | --- | ---: |
| `read_file` | low | 2 |
| `edit_file` | medium | 4 |
| `run_command` | medium | 4 |
| `install_package` | high | 5 |
| `delete_file` | high | 5 |
| `push` | high | 5 |
| `credential_read` | high | 5 |

Attack scenarios:

```text
replay_old_formation
changed_action_reuse
changed_action_same_nonce_reuse
same_nonce_reuse
one_stolen_sidecar
two_stolen_sidecars
fake_agent
solver_near_miss
path_near_miss_same_endpoint
model_generated_guess
collision_or_endpoint_mutation
poisoned_tool_metadata_reuse
wrong_timing_nonce
coordinator_state_forgery
```

Additional diagnostics:

```text
larger swarm sweep: 5, 10, 20, 50 agents
action binding suite
replay suite
weakest-agent target-selection summary
geometry and binding ablations
analysis mode without session shutdown
timing/check-count probe
10,000 cheap trials per attack scenario
```

## Runs

Full strengthened run:

```bash
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.formation_gate \
  --trials 1000 \
  --diagnostic-trials 200 \
  --timing-trials 100 \
  --sweep-agents 5,10,20,50 \
  --sweep-trials 50
```

Artifact:

```text
runs/2026-06-20T12-05-25.268213Z
metrics.json.sha256: 218151ec842450b04632f0270afee9631eac356d00c118c3458e1991afbc32d4
redaction: clean
secret markers found: 0
```

Cheap attack stress run:

```bash
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.formation_gate \
  --trials 1 \
  --diagnostic-trials 1 \
  --timing-trials 1 \
  --cheap-attack-trials 10000
```

Artifact:

```text
runs/2026-06-20T12-15-13.772037Z
metrics.json.sha256: f94258a8c3feae50267a1f883cd0713ecfb0b9e982db8602cc8382fd23677502
redaction: clean
secret markers found: 0
```

Both run artifacts record `worktree_dirty: true` because the strengthened harness changes
were not committed yet when the runs were produced. The source changes are now part of
this experiment update.

## Headline Result

From the 1,000-trial full run:

| Arm | Legitimate pass | Max attack release | A0->A3 target bits lost |
| --- | ---: | ---: | ---: |
| `random_baseline` | 1.00 | 0.00 | 0.00 |
| `old_shared_object` | 1.00 | 0.00 | 2.53 |
| `independent_static_geometry` | 1.00 | 0.00 | 0.00 |
| `independent_trajectory` | 1.00 | 0.00 | 0.00 |
| `coordinated_formation` | 1.00 | 0.00 | 0.00 |

Plain meaning:

```text
The old shared object still leaks under stolen neighbors.
The independent and formation arms remove that specific target-residual collapse.
```

## Residual Under Partial Compromise

For the old shared-object arm:

| Access | Stolen sidecars | Median target residual count | Median target residual bits |
| --- | ---: | ---: | ---: |
| A0 public only | 0 | 81 | 6.34 |
| A2 one stolen sidecar | 1 | 33 | 5.04 |
| A3 two stolen sidecars | 2 | 14 | 3.81 |

Loss:

```text
A0->A3 target bits lost: 2.53
```

That is the same structural failure as the older partial-compromise study. The stolen
neighbor pieces remove possibilities from the target region.

For the independent and formation arms:

| Arm | A0 target bits | A2 target bits | A3 target bits | A0->A3 target bits lost |
| --- | ---: | ---: | ---: | ---: |
| `random_baseline` | 6.34 | 6.34 | 6.34 | 0.00 |
| `independent_static_geometry` | 6.34 | 6.34 | 6.34 | 0.00 |
| `independent_trajectory` | 6.34 | 6.34 | 6.34 | 0.00 |
| `coordinated_formation` | 6.34 | 6.34 | 6.34 | 0.00 |

The full required unknown bits still go down when sidecars are stolen, because fewer
required agents remain unknown. But the unstolen target agent does not become easier to
guess in these arms.

That distinction is the main security lesson:

```text
shared geometry leaks across agents
independent per-agent geometry does not show that cross-agent target leak here
```

## Coordinated Formation Attacks

In the 1,000-trial full run, every measured coordinated-formation attack blocked, killed
the session, and returned the same public reason: `blocked`.

| Scenario | Unauthorized release | Blocked | One-shot shutdown | Distinct check counts | Check-count leak bits |
| --- | ---: | ---: | ---: | --- | ---: |
| `replay_old_formation` | 0.00 | 1.00 | 1.00 | `[35]` | 0.00 |
| `changed_action_reuse` | 0.00 | 1.00 | 1.00 | `[35]` | 0.00 |
| `changed_action_same_nonce_reuse` | 0.00 | 1.00 | 1.00 | `[30]` | 0.00 |
| `same_nonce_reuse` | 0.00 | 1.00 | 1.00 | `[35]` | 0.00 |
| `one_stolen_sidecar` | 0.00 | 1.00 | 1.00 | `[35]` | 0.00 |
| `two_stolen_sidecars` | 0.00 | 1.00 | 1.00 | `[35]` | 0.00 |
| `fake_agent` | 0.00 | 1.00 | 1.00 | `[35]` | 0.00 |
| `solver_near_miss` | 0.00 | 1.00 | 1.00 | `[35]` | 0.00 |
| `path_near_miss_same_endpoint` | 0.00 | 1.00 | 1.00 | `[35]` | 0.00 |
| `model_generated_guess` | 0.00 | 1.00 | 1.00 | `[35]` | 0.00 |
| `collision_or_endpoint_mutation` | 0.00 | 1.00 | 1.00 | `[35]` | 0.00 |
| `poisoned_tool_metadata_reuse` | 0.00 | 1.00 | 1.00 | `[35]` | 0.00 |
| `wrong_timing_nonce` | 0.00 | 1.00 | 1.00 | `[35]` | 0.00 |
| `coordinator_state_forgery` | 0.00 | 1.00 | 1.00 | `[35]` | 0.00 |

The separate cheap stress run repeated those attack scenarios at 10,000 trials per
scenario:

```text
14 scenarios
10,000 trials per scenario
140,000 coordinated-gate attack attempts total
0 unauthorized releases
140,000 public blocked responses
140,000 one-shot shutdowns
```

This is stronger than the prototype, but it is still an observed-release result, not an
impossibility proof.

## Action Binding

The action-binding diagnostic used seven action types and 200 trials per action.

| Action | Legitimate pass | Changed action reuse release | Changed action same-nonce reuse release |
| --- | ---: | ---: | ---: |
| `read_file` | 1.00 | 0.00 | 0.00 |
| `edit_file` | 1.00 | 0.00 | 0.00 |
| `run_command` | 1.00 | 0.00 | 0.00 |
| `install_package` | 1.00 | 0.00 | 0.00 |
| `delete_file` | 1.00 | 0.00 | 0.00 |
| `push` | 1.00 | 0.00 | 0.00 |
| `credential_read` | 1.00 | 0.00 | 0.00 |

Plain meaning:

```text
A valid formation for one action did not release a different action in this run.
```

The most important practical case is covered:

```text
a valid formation for a harmless or medium action does not release a high-risk action
```

## Larger Swarms

The coordinated formation sweep used 50 trials per size.

| Agents | Legitimate pass | Max attack release | Required agents for high risk |
| ---: | ---: | ---: | ---: |
| 5 | 1.00 | 0.00 | 5 |
| 10 | 1.00 | 0.00 | 10 |
| 20 | 1.00 | 0.00 | 20 |
| 50 | 1.00 | 0.00 | 50 |

The harness had to be changed for this. The first fixed-template formation did not scale
to 50 agents because clamped endpoints could collide. The strengthened harness now uses
a scalable lattice-style formation and lane-shifted paths.

## Ablations

This is the most important addition. It tests whether geometry and binding actually do
work, or whether the system is only ordinary authentication with decoration.

Each ablation used 200 trials per scenario.

| Ablation | Changed action same nonce | Wrong timing nonce | Path near miss same endpoint | Endpoint mutation | Max release |
| --- | ---: | ---: | ---: | ---: | ---: |
| `full_geometry` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `no_action_binding` | 0.05 | 0.00 | 0.00 | 0.00 | 0.05 |
| `no_nonce_binding` | 0.00 | 1.00 | 0.00 | 0.00 | 1.00 |
| `no_path_binding` | 0.00 | 0.00 | 1.00 | 0.00 | 1.00 |
| `no_endpoint_binding` | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 |
| `no_geometry_binding` | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 |
| `no_action_or_geometry_binding` | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 |

Plain reading:

```text
nonce binding stops timing/replay reuse
path binding stops path near misses
endpoint binding stops endpoint mutation
geometry binding stops path and endpoint attacks
explicit action binding matters because geometry alone is not enough
```

The `no_action_binding` result is especially useful. Removing explicit action binding
allowed 5% changed-action same-nonce releases. Most changed-action attempts still failed
because the path and endpoint are indirectly action-derived, but a few had the same
required-agent shape and passed without explicit action binding.

That proves the action hash cannot be treated as redundant.

The `no_path_binding`, `no_endpoint_binding`, and `no_geometry_binding` rows prove that
geometry is not just decorative in this harness. Removing those geometry bindings turns
specific near-miss attacks into releases.

## Weakest-Agent Behavior

The old shared-object arm now reports target selection across agents instead of only the
fixed middle agent. This matters because attackers prefer the easiest target.

From 100 sampled old-shared trials:

| Measure | Bits lost from A0 to A3 |
| --- | ---: |
| All-agent min | 0.56 |
| All-agent p50 | 2.58 |
| All-agent p95 | 4.91 |
| All-agent max | 5.55 |
| Median agent loss | 2.47 |

Per-agent median bits lost:

| Agent | Median bits lost |
| --- | ---: |
| `agent_001` | 2.50 |
| `agent_002` | 2.81 |
| `agent_003` | 2.47 |
| `agent_004` | 2.47 |
| `agent_005` | 2.47 |

Easiest measured role:

```text
agent_002, 2.81 median bits lost
```

Hardest measured role:

```text
agent_003, 2.47 median bits lost
```

This confirms that the old shared-object failure is not just an average-case artifact.
Some target roles lose more bits than others.

## Analysis Mode

Deployment mode kills the session after a bad proof. That is good defense behavior, but
it can hide how close attacks were.

The strengthened harness also runs analysis mode with `one_shot=False`. In that mode,
bad attempts block but the session survives so the experiment can keep measuring.

Across all attack scenarios in analysis mode:

```text
release: 0.00
blocked: 1.00
session survived after block: 1.00
```

That means the zero-release result is not only caused by the one-shot kill switch.

## Timing And Failure Shape

The public failure channel is clean:

```text
public response: blocked
```

The check-count proxy showed zero leak bits within each attack scenario:

```text
timing_proxy_leak_bits: 0.00
```

But this is not a constant-time proof.

One scenario, `changed_action_same_nonce_reuse`, performed 30 checks instead of 35
because the forged challenge reused a lower-risk required-agent set. The rest of the
main coordinated-formation attack scenarios used 35 checks. Wall-clock timing also varied
with normal Python runtime noise:

```text
p50 elapsed range: about 1.43 ms to 2.58 ms
p95 elapsed range: about 1.78 ms to 3.69 ms
max observed outlier: 13.48 ms
```

So the honest conclusion is:

```text
the current public channel is silent
the current check-count proxy is stable inside each scenario
the implementation is not yet padded to constant resource use across all blocked cases
```

If this becomes a real gate, failures should be padded so every blocked path queries and
checks the same public shape regardless of risk, source action, or internal reason.

## What The Result Supports

I would trust these claims now:

```text
1. The old shared-object geometry leaks under neighbor compromise.
2. The reason is structural correlation between pieces of one object.
3. Independent per-agent proofs remove that target-residual collapse in this model.
4. Fresh action binding stops reuse of a valid formation for another action.
5. Nonce binding stops replay/timing reuse.
6. Path and endpoint binding stop near-miss geometry attacks.
7. The full coordinated formation gate blocked the measured attacks in 1,000 trials.
8. The cheap coordinated attack stress found 0 releases in 140,000 attempts.
9. Geometry is doing measurable work in this harness because ablations break it.
```

## What The Result Does Not Prove

I would not claim these yet:

```text
1. The Spatial Formation Gate is secure.
2. HMAC tags are the final proof system.
3. Timing, memory, logs, or side-channel leakage are solved.
4. A compromised sidecar process can be safely contained without hardware support.
5. A malicious coordinator can never shape traffic into a harmful edge case.
6. Zero observed releases means the real attack probability is zero.
7. The 50-agent sweep is enough to cover real swarm-scale operational behavior.
```

## Bottom Line

The experiment is now strong enough to pause before building more features.

The old result says:

```text
3D as one shared lock is the wrong shape
```

The new result says:

```text
3D as a fresh local formation gate is the more promising shape
```

The key improvement is not that every attack blocked. The key improvement is that the
ablations now fail in the expected places:

```text
remove nonce binding -> replay succeeds
remove path binding -> path near miss succeeds
remove endpoint binding -> endpoint mutation succeeds
remove geometry binding -> geometry attacks succeed
remove action binding -> changed-action reuse starts to leak through
```

That is the first solid evidence in this project that the formation geometry is not just
ceremony. It is still a prototype result, but it is now a useful prototype result.
