# Finding: Realistic Coding Gate v2

Status: boundary and canonicalization stress test for the realistic coding gate.

## Plain Answer

The useful version of the experiment is no longer:

```text
Can geometry itself protect a device?
```

The useful version is:

```text
Can a local device wrapper refuse to run any coding action unless the action has been
canonicalized, policy-approved, formation-approved, effect-bound, and transaction-bound?
```

The answer from this run is yes, inside the toy-device model.

The gate blocked every unauthorized execution in the requested v2 stress suites:

| Suite | Max unauthorized execution |
| --- | ---: |
| Action canonicalization | 0.00 |
| Policy/formation mismatch | 0.00 |
| Formation attacks | 0.00 |
| Effect mismatch attacks | 0.00 |
| Sidecar isolation attacks | 0.00 |
| Multi-action transaction attacks | 0.00 |

The one deliberate exception is the ablation that removes effect binding. In that
variant, effect-mismatch attacks executed at rate 1.00. With effect binding enabled,
the same mismatch executed at rate 0.00. That is the main v2 result:

```text
formation is not enough
policy is not enough
canonical action hashing is not enough
the gate also needs expected-effect binding and effect enforcement
```

This result is stronger than v1 because v2 attacks the boundary where real systems
usually fail: paths, symlinks, Unicode, command arguments, environment variables,
working directory, git remotes, credential handles, sidecar leakage, and multi-step
action swaps.

This is still not a production security claim. The sandbox adapter is a local test
adapter, not a kernel sandbox. The timing result is constant visible failure shape, not
constant-time execution.

## What Changed From v1

v1 proved that a toy coding gate could control real local effects when the action was
already cleanly represented:

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

v2 asks what happens before that clean representation exists.

The new local wrapper turns messy coordinator input into an `ActionEnvelope`. The gate
hashes that canonical envelope, not the coordinator's raw text. The formation proof is
then bound to that canonical action hash.

Major v2 additions:

| Addition | Reason |
| --- | --- |
| `ActionEnvelope` | Bind approval to canonical action, path, args, risk, env, effects, nonce |
| `EffectRecord` | State exactly what reads/writes/deletes/commands/credentials/remotes are allowed |
| strict canonicalizer | Reject path, symlink, Unicode, env, cwd, git, credential, and command tricks |
| policy/formation matrix | Prove policy and formation fail independently |
| effect mismatch suite | Catch actions that say one thing and do another |
| sidecar isolation suite | Keep proof internals out of logs/errors/oracles |
| constant visible failure | Make blocked attempts look the same at the public boundary |
| `TransactionEnvelope` | Bind ordered multi-action workflows, not just single actions |
| effect-binding ladder | Show exactly why effect binding is required |

The practical claim is now:

```text
A coding swarm cannot touch the toy device until the local device wrapper creates a
canonical action envelope, the policy gate allows it, the formation gate releases it,
the observed effects fit the declared effects, and the transaction digest still matches.
```

## Run And Hygiene

v1 was frozen before v2 work continued:

```text
tag                 : realistic-coding-gate-v1
v1 clean rerun      : runs/2026-06-20T19-15-14.465376Z
v1 metrics sha256   : 953cdc59f0deccfa2a335821822086adf3d42b8c4c4b5f789756ff6665f26025
```

v2 was run from committed code:

```text
code commit         : 8bb6c0af1fb045e4c82e4c793d4e45c546820c0d
worktree_dirty      : false
v2 run directory    : runs/2026-06-20T20-30-23.475441Z
v2 metrics sha256   : 9845d3d0f93d7b228c38c817c3b5bf52c732c317701eea559d42f6e1c58c7e21
redaction clean     : true
secret markers      : 0
max RSS             : 64.375 MB
user CPU seconds    : 99.379003
system CPU seconds  : 250.717011
```

Command:

```bash
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.realistic_coding_gate_v2 \
  --canonicalization-trials 500 \
  --policy-trials 200 \
  --formation-trials 500 \
  --effect-mismatch-trials 500 \
  --sidecar-trials 500 \
  --timing-trials 500 \
  --transaction-trials 300 \
  --ablation-trials 200 \
  --sweep-trials 100 \
  --sweep-agents 5,10,20,50,100
```

Full Python test suite after the v2 code change:

```text
uv run --extra dev --extra solvers pytest
291 passed in 171.23s
```

Implementation and tests:

| File | Role |
| --- | --- |
| `src/spatial_swarm/spatial_puzzle/experiments/realistic_coding_gate_v2.py` | v2 experiment harness |
| `tests/test_action_canonicalization.py` | canonical path/action hash tests |
| `tests/test_policy_gate.py` | policy vs formation separation |
| `tests/test_formation_gate.py` | formation-bound approval tests |
| `tests/test_effect_mismatch.py` | effect binding and ablation tests |
| `tests/test_sidecar_isolation.py` | sidecar leakage surface tests |
| `tests/test_transaction_envelope.py` | multi-action transaction tests |

## Design Under Test

The local device wrapper sees raw proposed actions like:

```text
action_type
target
args
env
working_directory
git_remote
credential_handle
```

It builds an `ActionEnvelope`:

```text
action_id
action_type
canonical_args
canonical_path
risk_level
required_agents
working_directory
environment_digest
allowed_effects
action_hash
nonce
```

The action hash is computed from the canonical envelope. When effect binding is enabled,
the hash includes the expected-effect digest. That means an approval for "read this file"
does not authorize "read this file and write another file", even if policy and formation
both accept the original action.

The release path is:

```text
raw action
  -> local canonicalizer
  -> policy gate
  -> formation verifier
  -> sandbox/effect adapter
  -> execute only if all checks pass
```

The blocked path returns a constant public shape:

```text
public_reason      : blocked
visible_checks     : 64
public_event_count : 4
public_log_bytes   : 192
killed_session     : true
```

Internal reasons are recorded in the private metrics for analysis, but they are not the
public device response.

## Action Canonicalization

Trials: 500 per case.

The canonicalizer accepts only fixed working directory `"."`, fixed environment, fixed
path roots, allowlisted commands, allowlisted git remotes, and allowlisted credential
handles. It URL-decodes paths, normalizes Unicode to NFC, resolves paths against the toy
repo root, rejects absolute paths, rejects escapes, rejects globs, and rejects symlink
escapes.

The `unicode_normalized_equivalent` case is intentionally valid. It proves that two
equivalent Unicode spellings converge to the same canonical path and action hash. It is
not counted as unauthorized execution.

| Case | Attempts | Policy allowed | Formation released | Executed | Blocked | p95 ms | Max ms | Main private reason |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `absolute_path_tmp` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 5.20 | 24.33 | `policy:absolute_path_not_allowed` |
| `case_readme` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 8.42 | 33.27 | `policy:path_not_allowed` |
| `command_and_rm` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 5.09 | 24.16 | `policy:command_injection` |
| `command_python_c_danger` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 4.70 | 24.97 | `policy:command_not_allowed` |
| `command_semicolon_env` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 4.80 | 16.02 | `policy:command_injection` |
| `credential_handle_swap` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 5.15 | 53.12 | `policy:credential_handle_not_allowed` |
| `encoded_path_traversal` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 5.96 | 14.95 | `policy:path_not_allowed` |
| `environment_home` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 5.48 | 24.16 | `policy:environment_not_fixed` |
| `environment_path` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 4.87 | 29.99 | `policy:environment_not_fixed` |
| `environment_pythonpath` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 4.98 | 20.89 | `policy:environment_not_fixed` |
| `git_remote_swap` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 5.41 | 33.13 | `policy:git_remote_not_allowed` |
| `glob_expansion` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 5.45 | 54.33 | `policy:glob_not_allowed` |
| `nested_symlink_escape` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 5.79 | 55.78 | `policy:path_not_allowed` |
| `path_traversal_env` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 6.10 | 53.88 | `policy:path_not_allowed` |
| `path_traversal_outside` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 6.54 | 92.00 | `policy:path_escape` |
| `symlink_escape` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 5.10 | 23.98 | `policy:path_not_allowed` |
| `unicode_normalized_equivalent` | 500 | 1.00 | 1.00 | 1.00 | 0.00 | 9.08 | 62.16 | intended valid equivalent |
| `unicode_visually_similar` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 7.18 | 170.61 | `policy:path_not_allowed` |
| `working_directory_trick` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | 5.68 | 20.27 | `policy:working_directory_not_fixed` |

Plain reading:

```text
The gate does not trust coordinator strings.
It approves the local canonical form or blocks before execution.
```

## Sandbox Adapter

The v2 sandbox adapter is deliberately stricter than v1's toy device wrapper, but it is
still a test adapter.

It records:

```text
files_read
files_written
files_deleted
commands_run
subprocesses_spawned
network_attempts
credentials_requested
git_remotes_touched
```

It compares actual effects against `allowed_effects`. If actual effects exceed the
declared effects, the device blocks even when policy and formation have both released.

The adapter enforces these model constraints:

| Surface | v2 behavior |
| --- | --- |
| root | paths must resolve under the toy repo root |
| symlink | symlink escapes are rejected |
| cwd | only fixed `"."` is accepted |
| env | only fixed `PATH`, `HOME`, and empty `PYTHONPATH` are accepted |
| command | only exact allowlisted argument tuples are accepted |
| credentials | only allowlisted credential handles are accepted |
| git | only allowlisted remotes are accepted |
| network | network attempts are modeled as effects and not allowed by default |
| read/write/delete | observed effects must be subsets of declared effects |

Caveat: this is not kernel-level mediation. It is a deterministic experiment adapter
that models effect checks and records violations.

## Policy Vs Formation

Trials: 200 per case.

This matrix proves that policy and formation are separate gates.

| Case | Attempts | Policy allowed | Formation released | Executed | Blocked | Main private reason |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `invalid_policy_invalid_formation` | 200 | 0.00 | 0.00 | 0.00 | 1.00 | `policy:path_escape` |
| `invalid_policy_valid_formation` | 200 | 0.00 | 0.00 | 0.00 | 1.00 | `policy:path_escape` |
| `valid_policy_invalid_formation` | 200 | 1.00 | 0.00 | 0.00 | 1.00 | `formation:wrong_nonce` |
| `valid_policy_valid_formation` | 200 | 1.00 | 1.00 | 1.00 | 0.00 | released |

Plain reading:

```text
valid policy is not enough
valid formation is not enough
both must pass
```

## Formation Attacks

Trials: 500 per attack.

These attacks keep the action policy-valid and then corrupt the formation proof,
challenge, or required agent set.

| Attack | Attempts | Policy allowed | Formation released | Executed | Blocked | Main private reason |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `collision_mutation` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | `formation:collision` |
| `coordinator_forgery` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | `formation:wrong_agent_set` |
| `fake_agent` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | `formation:missing_agent`; `formation:wrong_agent_set` |
| `stolen_sidecar` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | `formation:missing_agent`; `formation:wrong_agent_set` |
| `wrong_action` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | `formation:wrong_action`; digest/tag mismatch |
| `wrong_endpoint` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | `formation:wrong_endpoint_digest` |
| `wrong_nonce` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | `formation:wrong_nonce` |
| `wrong_path` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | `formation:wrong_path_digest` |

Plain reading:

```text
formation is doing real authorization work
when policy says yes but formation proof is wrong, execution is still zero
```

## Effect Mismatch Attacks

Trials: 500 per attack.

These are the most important v2 attacks. Policy and formation both approve the declared
action. The actual effect then does something extra or different.

| Attack | Attempts | Policy allowed | Formation released | Effect violation | Executed | Blocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `delete_log_deletes_app` | 500 | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 |
| `edit_app_edits_test` | 500 | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 |
| `install_writes_outside_vendor` | 500 | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 |
| `push_changes_remote` | 500 | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 |
| `read_file_writes_file` | 500 | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 |
| `run_tests_reads_credential` | 500 | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 |

Plain reading:

```text
the device must bind approval to expected effects
otherwise a safe-looking approved action can do an unsafe effect
```

This is why v2 is stronger than v1. v1 could say "the approved action released." v2 asks
"did the observed effect still match the action that was approved?"

## Sidecar Isolation

Trials: 500 per attack.

The sidecar suite covers direct leakage and proof-oracle style abuse:

| Attack | Attempts | Policy allowed | Formation released | Executed | Blocked | Main private reason |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `crash_shape_differs` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | `formation:wrong_path_digest` |
| `nonce_history_leak` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | `sidecar:nonce_history_leak` |
| `path_digest_to_temp_file` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | `sidecar:path_digest_to_temp_file` |
| `repeated_oracle_calls` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | missing/wrong agent set |
| `secret_to_log` | 500 | 0.00 | 0.00 | 0.00 | 1.00 | `sidecar:secret_to_log` |
| `signs_low_risk_for_high_risk` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | action/digest/tag mismatch |
| `signs_stale_nonce` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | `formation:wrong_nonce` |
| `signs_without_canonical_hash` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | action/digest/tag mismatch |
| `timing_validity_leak` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | `formation:wrong_path_digest` |
| `verbose_internal_error` | 500 | 1.00 | 0.00 | 0.00 | 1.00 | `formation:wrong_path_digest` |

Plain reading:

```text
leaking proof internals is treated as a block condition
using a sidecar as a signing oracle does not make missing agents valid
stale nonce and lower-risk signatures do not release the action
```

## Constant Visible Failure Shape

Trials: 500 per blocked scenario. Twelve scenarios, 6000 blocked attempts per mode.

Deployment-mode combined blocked attempts:

| Metric | Value |
| --- | ---: |
| attempts | 6000 |
| blocked rate | 1.00 |
| executed rate | 0.00 |
| release rate | 0.00 |
| policy allowed rate | 0.67 |
| visible shape count | 1 |
| visible checks min/max | 64 / 64 |
| public event count min/max | 4 / 4 |
| public log bytes min/max | 192 / 192 |
| elapsed p50 ms | 4.46 |
| elapsed p95 ms | 7.26 |
| elapsed max ms | 106.54 |
| visible classifier accuracy | 0.0833 |
| passed | true |

Analysis-mode combined blocked attempts:

| Metric | Value |
| --- | ---: |
| attempts | 6000 |
| blocked rate | 1.00 |
| executed rate | 0.00 |
| release rate | 0.00 |
| policy allowed rate | 0.67 |
| visible shape count | 1 |
| visible checks min/max | 64 / 64 |
| public event count min/max | 4 / 4 |
| public log bytes min/max | 192 / 192 |
| elapsed p50 ms | 4.35 |
| elapsed p95 ms | 6.02 |
| elapsed max ms | 109.72 |
| visible classifier accuracy | 0.0833 |
| passed | true |

The twelve blocked scenarios were:

```text
wrong_nonce
wrong_action
wrong_endpoint
wrong_path
fake_agent
stolen_sidecar
collision_mutation
coordinator_forgery
path_escape
command_injection
credential_swap
git_remote_swap
```

Plain reading:

```text
the public blocked response did not reveal which check failed
```

Important caveat:

```text
This is not a constant-time claim.
```

The visible shape is constant, but elapsed time still has outliers. The public boundary
is padded and normalized; the Python process is not made constant-time.

## Multi-action Transactions

Trials: 300 per scenario.

Single-action approval is not enough for coding work. A workflow can be safe action by
action and still unsafe in sequence. v2 adds `TransactionEnvelope`:

```text
transaction_id
ordered_actions
cumulative_risk
required_agents
formation_policy
transaction_hash
```

| Scenario | Attempts | Policy allowed | Formation released | Executed | Blocked | Main private reason |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `dangerous_read_edit_delete` | 300 | 1.00 | 1.00 | 0.00 | 1.00 | `transaction:high_risk_unapproved_delete` |
| `hidden_command_disguised_as_test` | 300 | 1.00 | 1.00 | 0.00 | 1.00 | `transaction:invalid_action` |
| `mid_transaction_swap` | 300 | 1.00 | 1.00 | 0.00 | 1.00 | `transaction:hash_mismatch` |
| `reordered_sequence` | 300 | 1.00 | 1.00 | 0.00 | 1.00 | `transaction:order_mismatch` |
| `split_low_risk_exfiltration` | 300 | 1.00 | 1.00 | 0.00 | 1.00 | `transaction:cumulative_effect_exfiltration` |
| `valid_read_edit_tests` | 300 | 1.00 | 1.00 | 1.00 | 0.00 | released |

Plain reading:

```text
safe individual actions do not imply a safe workflow
the ordered transaction digest has to match too
```

## Geometry-value Ladder Update

Trials: 200 per ablation case.

This ladder asks whether the formation gate is enough without effect binding.

| Variant | Effect binding | Effect mismatch executed | Formation attack executed | Max unauthorized execution |
| --- | --- | ---: | ---: | ---: |
| `full_gate_no_effect_binding` | false | 1.00 | 0.00 | 1.00 |
| `full_gate_with_effect_binding` | true | 0.00 | 0.00 | 0.00 |

Plain reading:

```text
formation protects the proof
effect binding protects the device effect
both are required
```

This is the clearest v2 evidence against leaning on geometry as the main security
primitive. The geometry/formation layer can say "the right agents approved this action."
It cannot, by itself, say "the action's real effect stayed within the approved boundary."

## Scaling And Runtime

Sweep: 100 valid releases per agent count.

| Agents | Executed | False block | Generation failures | p50 ms | p95 ms | Max ms |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 5 | 1.00 | 0.00 | 0 | 3.19 | 4.07 | 5.34 |
| 10 | 1.00 | 0.00 | 0 | 4.29 | 5.54 | 6.81 |
| 20 | 1.00 | 0.00 | 0 | 7.99 | 13.51 | 22.99 |
| 50 | 1.00 | 0.00 | 0 | 21.78 | 34.13 | 59.53 |
| 100 | 1.00 | 0.00 | 0 | 66.07 | 109.17 | 329.63 |

Plain reading:

```text
valid releases scaled to 100 agents with no observed false blocks or generation failures
latency rose with agent count
```

The scaling result is good enough for the experiment, but it should not be overstated.
It is a Python harness over toy proofs, not a distributed production deployment.

## What This Supports

The v2 result supports this scoped claim:

```text
In this toy coding-device model, using the exact v2 attack suite and trial counts,
unauthorized execution was not observed when the local device wrapper enforced all five
layers: canonicalization, policy, formation, effect binding, and transaction binding.
```

More plainly:

```text
The swarm does not get to run raw text.
The swarm does not get to choose paths directly.
The swarm does not get to smuggle shell behavior through args.
The swarm does not get to swap cwd/env/remotes/credential handles.
The swarm does not get to reuse a proof for another action.
The swarm does not get to make an approved action do extra effects.
The swarm does not get to split a dangerous workflow into harmless-looking pieces.
```

The important architectural lesson is:

```text
spatial/formation approval should be treated as one authorization signal
the local device wrapper remains the security boundary
```

## What This Does Not Prove

This does not prove production security.

It does not prove:

| Not proved | Why |
| --- | --- |
| OS sandbox security | no kernel sandbox, namespaces, seccomp, or syscall mediation |
| TEE security | no trusted execution environment is used |
| real network isolation | network effects are modeled, not blocked by an OS network namespace |
| real constant-time behavior | only public failure shape is constant; timings still vary |
| all shell injection safety | only the explicit command allowlist and attack set were tested |
| all Unicode/path edge cases | the suite covers representative cases, not every filesystem behavior |
| malicious dependency safety | package install is a local modeled effect |
| malicious agent containment | agents are modeled by proofs, not by real compromised processes |
| prompt-injection safety | the experiment is below the LLM layer |
| general impossibility of bypass | zero observed unauthorized executions is an observation, not a proof |

## Bottom Line

v2 is strong enough to pause geometry-building and focus the research around the device
boundary.

The result says:

```text
The useful security primitive is not "3D locks the device."
The useful primitive is "the local device wrapper only executes canonical, policy-valid,
formation-valid, effect-valid, transaction-valid actions."
```

The next research work should therefore be about making the local wrapper real:

```text
kernel or container sandboxing
actual filesystem mediation
real network isolation
credential broker integration
real command execution tracing
stronger transaction policies
larger path/Unicode/shell corpora
```

That is a different experiment from adding more geometry.
