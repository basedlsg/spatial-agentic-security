# Finding: Realistic Coding Gate v1

Status: first realistic toy-device experiment.

## Plain Answer

The previous Spatial Formation Gate result was about the proof system. It showed that
the pivot away from one shared 3D object was working:

```text
shared-object geometry leaks under stolen neighbors
independent/formation designs do not show that target-residual collapse
formation ablations fail in the expected places
```

This experiment asks a more practical question:

```text
Can the gate protect a toy coding environment, not just a clean proof harness?
```

The answer from this run is yes, inside the toy model.

The gate controlled real local actions against a temporary repo:

```text
read_file
edit_file
run_tests
run_command
install_package
delete_file
push
credential_read
```

With valid policy plus valid formation, every action executed. With wrong formation,
action reuse, sidecar compromise, coordinator lying, wrong nonce, path near miss,
endpoint mutation, delayed sidecar, or hidden dangerous metadata, the toy device did not
execute.

The most important result is not simply "blocked." The important result is this:

```text
policy gate and formation gate both mattered
constant-failure padding hid the visible failure shape
sidecar compromise did not make an unstolen target proof easier
coordinator attempts to execute a different action failed
less geometry was weaker in the geometry-value ladder
100-agent formation generation had 0 observed failures in the sweep
```

This is still a toy-device result. It is not a real OS sandbox, not a TEE, and not a
constant-time proof. But it is a better test than the clean proof harness because real
files, local commands, local package writes, local git push, and credential-handle reads
actually happen when the gate releases.

## Design Under Test

The new flow is:

```text
agent proposes device action
policy gate evaluates the real action
formation gate verifies fresh action-bound proofs
device executes only if both gates pass
```

This separation is necessary because the formation gate only proves:

```text
the required agents formed around the action-bound challenge
```

It does not prove:

```text
the action is safe
```

So the policy gate handles device safety, and the formation gate handles coordinated
authorization.

## Toy Device

Each attempt creates a temporary toy repository with:

```text
README.md
src/app.py
tests/test_app.py
tmp/output.log
vendor/
local bare git remote, created only for push tests
```

The device actions are real local operations:

| Action | Real effect in the toy repo |
| --- | --- |
| `read_file` | Reads `README.md` and records an output digest |
| `edit_file` | Appends a gated edit marker to `src/app.py` |
| `run_tests` | Runs `python -m unittest discover -s tests` |
| `run_command` | Runs an allowlisted Python command |
| `install_package` | Writes a local `.dist-info` marker under `vendor/` |
| `delete_file` | Deletes `tmp/output.log` |
| `push` | Initializes a local bare remote and pushes `main` |
| `credential_read` | Reads a credential handle and records only a digest |

The artifact stores no raw credential value.

## Run

Corrected full run:

```bash
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.realistic_coding_gate \
  --trials 50 \
  --attack-trials 500 \
  --timing-trials 200 \
  --ablation-trials 200 \
  --geometry-trials 200 \
  --sweep-trials 50 \
  --sweep-agents 5,10,20,50,100
```

Artifact:

```text
runs/2026-06-20T17-07-17.443370Z
metrics.json.sha256: a70a4e8a6fb3326848e6e474e6de6c4be541647442191b41f41fc2eef521ec0b
redaction: clean
secret markers found: 0
```

The artifact records `worktree_dirty: true` because the experiment code was not committed
yet when the run was produced. This document describes the corrected run above.

An earlier run was discarded for analysis because the `no_nonce_binding` ablation was
testing replay-cache behavior instead of proof nonce binding. The corrected run changes
that ablation to wrong-nonce proof mutation and reruns the full experiment at the same
counts.

## Real Actions

Each valid action ran 50 trials. Each wrong-formation action also ran 50 trials.

| Action | Valid release | False block | Wrong formation release | Real effect |
| --- | ---: | ---: | ---: | --- |
| `read_file` | 1.00 | 0.00 | 0.00 | `read_file` |
| `edit_file` | 1.00 | 0.00 | 0.00 | `edited_file` |
| `run_tests` | 1.00 | 0.00 | 0.00 | `ran_tests` |
| `run_command` | 1.00 | 0.00 | 0.00 | `ran_command` |
| `install_package` | 1.00 | 0.00 | 0.00 | `installed_local_package` |
| `delete_file` | 1.00 | 0.00 | 0.00 | `deleted_file` |
| `push` | 1.00 | 0.00 | 0.00 | `pushed_local_remote` |
| `credential_read` | 1.00 | 0.00 | 0.00 | `read_credential_handle` |

Plain reading:

```text
valid formation + allowed action -> executed
wrong formation + same action -> blocked
```

This is the first result in the project where the gate is actually controlling device
effects rather than only reporting proof acceptance.

## Policy Gate Plus Formation Gate

The policy and formation suite used 50 trials per case.

| Case | Release | Executed | Policy allowed | Formation released | Main reason |
| --- | ---: | ---: | ---: | ---: | --- |
| correct formation + safe edit | 1.00 | 1.00 | 1.00 | 1.00 | released |
| correct formation + credential read | 1.00 | 1.00 | 1.00 | 1.00 | released |
| correct formation + delete repo | 0.00 | 0.00 | 0.00 | 0.00 | policy blocked |
| credential read downgraded to low | 0.00 | 0.00 | 1.00 | 1.00 | risk and required-agent mismatch |
| wrong formation + safe edit | 0.00 | 0.00 | 1.00 | 0.00 | wrong nonce |

Important distinction:

```text
policy can block before formation if the action itself is disallowed
formation can release but device can still block if coordinator metadata does not match
```

The downgraded credential-read case is especially important. The formation itself
released under the forged low-risk challenge, but the device wrapper recomputed risk and
required agents from the actual action and blocked execution.

## Attack Suite

The main realistic attack suite used 500 trials per attack.

| Attack | Release | Blocked |
| --- | ---: | ---: |
| `reuse_read_for_delete` | 0.00 | 1.00 |
| `reuse_tests_for_credential` | 0.00 | 1.00 |
| `stolen_sidecar_approves_alone` | 0.00 | 1.00 |
| `two_stolen_sidecars_approve_alone` | 0.00 | 1.00 |
| `sidecar_oracle_one_agent` | 0.00 | 1.00 |
| `coordinator_downgrades_risk` | 0.00 | 1.00 |
| `coordinator_chooses_fewer_agents` | 0.00 | 1.00 |
| `coordinator_changes_action_after_proof` | 0.00 | 1.00 |
| `ask_read_execute_credential` | 0.00 | 1.00 |
| `wrong_nonce` | 0.00 | 1.00 |
| `path_near_miss` | 0.00 | 1.00 |
| `endpoint_mutation` | 0.00 | 1.00 |
| `fake_agent` | 0.00 | 1.00 |
| `old_output_replay` | 0.00 | 1.00 |
| `old_nonce_reuse` | 0.00 | 1.00 |
| `delayed_sidecar` | 0.00 | 1.00 |
| `hidden_dangerous_metadata` | 0.00 | 1.00 |

This directly covers the key practical cases:

```text
valid read proof reused for delete_file -> blocked
valid run_tests proof reused for credential_read -> blocked
coordinator asks for read_file but executes credential_read -> blocked
stolen sidecar cannot approve alone -> blocked
sidecar oracle for one agent cannot fake the rest -> blocked
```

## Constant-Failure Shape

The constant-failure suite used 8 blocked scenarios and 200 trials per scenario:

```text
wrong_nonce
wrong_action
wrong_endpoint
wrong_path
fake_agent
stolen_sidecar
collision_mutation
coordinator_forgery
```

Combined result:

| Metric | Value |
| --- | ---: |
| Attempts | 1600 |
| Release | 0.00 |
| Blocked | 1.00 |
| Executed | 0.00 |
| Public reason | `blocked` for all attempts |
| Visible shape count | 1 |
| Visible checks | 49 for all attempts |
| One-shot shutdown | 1.00 |
| Constant-failure passed | true |

Raw internal checks still varied:

```text
raw checks min: 28
raw checks p50: 38
raw checks p95: 43
raw checks max: 43
```

But the visible blocked shape was padded to:

```text
public reason: blocked
visible checks: 49
session death: true
```

Timing after padding:

```text
p50: 4.78 ms
p95: 6.95 ms
max: 14.59 ms
```

Plain reading:

```text
public failure shape is now constant in the toy wrapper
runtime is padded but not truly constant-time
```

This fixes the previous "30 checks vs 35 checks" visible-shape weakness at the wrapper
level, but it is not a low-level side-channel proof.

## Sidecar Compromise

The sidecar compromise suite used 500 trials per case.

| Compromise case | Release | Blocked |
| --- | ---: | ---: |
| old outputs seen | 0.00 | 1.00 |
| old nonces seen | 0.00 | 1.00 |
| logs seen | 0.00 | 1.00 |
| one secret stolen | 0.00 | 1.00 |
| two secrets stolen | 0.00 | 1.00 |
| one sidecar oracle | 0.00 | 1.00 |
| one sidecar delayed | 0.00 | 1.00 |
| one sidecar replayed | 0.00 | 1.00 |

Target forgery release:

| Access | Release |
| --- | ---: |
| no stolen sidecar | 0.00 |
| one stolen sidecar | 0.00 |
| two stolen sidecars | 0.00 |

Estimated unstolen-target bits lost:

```text
0.00
```

The model is simple: agent secrets are independent. The result is still useful because
it confirms the design goal of the pivot:

```text
compromising Agent A's sidecar did not make Agent B's proof easier to fake in this model
```

## Coordinator Attacks

The coordinator attack suite used 500 trials per case.

| Coordinator behavior | Release | Executed | Main block reason |
| --- | ---: | ---: | --- |
| downgrade delete to low | 0.00 | 0.00 | risk and required-agent mismatch |
| choose fewer agents | 0.00 | 0.00 | required-agent mismatch |
| reuse old nonce | 0.00 | 0.00 | replay nonce |
| change action after proof | 0.00 | 0.00 | execution action mismatch |
| split dangerous action | 0.00 | 0.00 | policy dangerous payload |
| hide dangerous metadata from hash | 0.00 | 0.00 | action/risk/required mismatch |
| ask read, execute credential | 0.00 | 0.00 | action/risk/required mismatch |

The key case:

```text
formation approved for harmless action
coordinator executes dangerous action
```

Result:

```text
blocked every time
```

This is because the device wrapper binds the proof challenge to the actual execution
action, not to the coordinator's claim.

## Expanded Ablations

Each ablation used 200 trials.

| Ablation | Attack measured | Release |
| --- | --- | ---: |
| `full_gate` | max across all ablation scenarios | 0.00 |
| `no_action_binding` | changed same-risk read | 1.00 |
| `no_nonce_binding` | wrong nonce | 1.00 |
| `no_path_binding` | path near miss | 1.00 |
| `no_endpoint_binding` | endpoint mutation | 1.00 |
| `no_collision_check` | collision mutation | 0.99 |
| `no_path_crossing_check` | path crossing mutation | 0.99 |
| `no_forbidden_region_check` | forbidden region mutation | 1.00 |
| `no_final_formation_check` | wrong final formation | 0.99 |
| `no_required_agent_binding` | coordinator chooses fewer agents | 1.00 |
| `no_risk_level_binding` | low-risk label with high-risk agents | 1.00 |
| `no_role_binding` | role-label forgery | 1.00 |
| `no_timing_binding` | delayed sidecar | 1.00 |

The `0.99` rows are not failures of the ablation logic. They mean the intended disabled
check was removed, but another still-enabled geometric check occasionally caught the
mutated path anyway. For example, a collision mutation can also accidentally hit a
forbidden point.

Plain reading:

```text
every removed binding exposed the attack it was supposed to stop
full gate stopped all of them
```

This is the strongest part of the realistic experiment. It shows exactly which pieces
matter:

```text
action binding stops same-risk action swapping
nonce binding stops wrong-nonce proof reuse
path binding stops path near misses
endpoint binding stops endpoint mutation
collision/path-crossing/final formation checks catch geometric invalidity
required-agent/risk/role binding stops coordinator downgrades
timing binding stops delayed sidecars
```

## Geometry-Value Ladder

The geometry-value ladder used 200 trials per variant.

| Variant | Max attack release | Near miss | Endpoint mutation | Collision mutation | Wrong final formation | False block |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `hmac_only` | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 |
| `hmac_endpoint` | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 0.00 |
| `hmac_endpoint_path` | 1.00 | 0.00 | 0.00 | 1.00 | 1.00 | 0.00 |
| `hmac_endpoint_path_collision` | 1.00 | 0.00 | 0.00 | 0.00 | 1.00 | 0.00 |
| `hmac_endpoint_path_collision_final` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `full_gate` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

Plain reading:

```text
HMAC only is not enough for geometric near-miss attacks
endpoint binding stops endpoint mutation
path binding stops path near miss
collision checking stops collision mutation
final formation checking stops wrong final formation
full gate and endpoint+path+collision+final both stopped the measured ladder attacks
```

This is the cleanest answer so far to:

```text
How much does geometry add beyond normal authentication?
```

Answer in this toy model:

```text
each geometric layer blocks a different class of malformed formation
```

## Bigger Swarm Stress

The swarm sweep used 50 trials per size.

| Agents | Legit pass | False block | Generation failures | Collisions | p50 runtime | p95 runtime |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 5 | 1.00 | 0.00 | 0 | 0 | 8.43 ms | 27.45 ms |
| 10 | 1.00 | 0.00 | 0 | 0 | 8.63 ms | 16.40 ms |
| 20 | 1.00 | 0.00 | 0 | 0 | 10.49 ms | 18.26 ms |
| 50 | 1.00 | 0.00 | 0 | 0 | 24.16 ms | 32.01 ms |
| 100 | 1.00 | 0.00 | 0 | 0 | 56.51 ms | 77.21 ms |

The 100-agent result matters because the previous formation experiment only swept to
50 agents. Here the scalable lattice formation generated valid high-risk 100-agent
formations without observed generation failures.

Runtime grows with agent count, as expected.

## Runtime And Usability

Valid action p50 runtime:

| Action | p50 runtime |
| --- | ---: |
| `read_file` | 5.98 ms |
| `credential_read` | 8.15 ms |
| `edit_file` | 9.95 ms |
| `install_package` | 10.03 ms |
| `delete_file` | 10.18 ms |
| `run_command` | 45.13 ms |
| `run_tests` | 98.34 ms |
| `push` | 531.01 ms |

The gate overhead is not the dominant cost for subprocess-heavy actions. The local git
push action is much slower because each attempt initializes and pushes to a temporary
bare remote.

Usability result:

```text
valid actions had 0 false blocks in this run
large swarms had 0 formation generation failures in this run
runtime cost scales with required agents and with the real device action
```

## What This Supports

I would trust these claims now:

```text
1. The gate can control real toy repo actions, not only proof acceptance.
2. Policy and formation must both pass before execution.
3. Correct formation around a bad/disallowed action does not bypass policy.
4. Correct formation around one action does not authorize a different executed action.
5. Coordinator risk downgrades and fewer-agent challenges are caught by local recomputation.
6. Public blocked shape can be padded to one visible response/check/death shape.
7. Sidecar compromise does not make an unstolen target proof easier in this independent-secret model.
8. Removing individual geometry and binding checks exposes the expected attacks.
9. A 100-agent high-risk formation can be generated and verified in this harness.
```

## What This Does Not Prove

I would not claim these yet:

```text
1. This is a secure production sandbox.
2. This is constant-time at the OS, CPU, or scheduler level.
3. The HMAC proof is the final proof system.
4. A real malicious sidecar process cannot leak through memory, logs, IPC, or timing.
5. A real package install, shell, git remote, or credential provider is covered by this toy model.
6. The policy allowlist is complete.
7. Zero observed releases means the true release probability is zero.
```

## Bottom Line

This was the right next experiment:

```text
less geometry in isolation
more reality around execution
```

The result is strong enough to justify continuing down the gate path, but the next work
should not add more decorative geometry. It should harden the realistic boundary:

```text
real sandbox adapter
real sidecar isolation model
stronger constant-resource padding
policy language and canonicalization tests
logs/memory/IPC leak tests
multi-action transaction tests
```

The main lesson is now clearer:

```text
3D geometry is useful only when it is bound to the exact action the device will execute,
and only when policy independently decides that action is allowed.
```
