# Finding: Real Sandbox Gate v3

## 1. Plain answer

The contained execution version worked under the tested model.

The full gate released every valid allowed action and released zero attacks. The important difference from v2 is that actions were no longer only modeled. The approved action was executed against a fresh disposable workspace through the v3 sandbox adapter, with Docker containment for command and git actions, fixed environment, network off by default, fake credential handles, local bare git remotes, filesystem snapshots, and effect binding.

Full run:

| field | value |
| --- | --- |
| run dir | `runs/2026-06-21T10-55-14.360372Z` |
| code commit | `f8c163f39ac33fdab942d5db068d17119b88e58b` |
| worktree dirty | `false` |
| metrics sha256 | `e55b90846e92ba72a57ce24b4c417ebbdfd3014a704d39d3a573c8c3c840a4d7` |
| full-gate attack releases | 0 |
| valid false blocks | 0 |
| transaction attack releases | 0 |
| raw credential leaks released | 0 |
| host effects detected | 0 |
| redaction clean | true |
| constant visible failure passed | true |

Quick mode was run first and passed before full mode:

| field | value |
| --- | --- |
| quick run dir | `runs/2026-06-21T09-13-11.135477Z` |
| quick metrics sha256 | `331135aea53ad1cf0a0da2b9c2906e49512df0814d24a0f2081a4371c056e49e` |
| quick full-gate attack releases | 0 |
| quick valid false blocks | 0 |
| quick redaction clean | true |

## 2. What changed from v2

v2 used a modeled effect adapter. It could say, "if this action wrote `src/app.py`, the gate would block it," but it did not run the action in a real disposable execution boundary.

v3 replaces that layer with a contained execution adapter:

| v2 | v3 |
| --- | --- |
| Modeled effects | Real filesystem snapshots before and after execution |
| Simulated commands | Docker-backed exact argv commands |
| Simulated git effects | Local bare remote inside the disposable workspace |
| Simulated credentials | Fake credential broker returning digests only |
| No real container boundary | Docker `--network none`, fixed cwd/env, memory/CPU/pid limits, no new privileges, dropped capabilities |
| No artifact-level sandbox config | `sandbox_config.json`, `effect_records.jsonl`, and CSV matrices written per run |

The core question changed from "does the wrapper logic block modeled mismatches?" to:

> Can the local wrapper enforce approved effects when actions actually run inside a contained workspace?

## 3. What stayed fixed

The experiment intentionally did not add new agents, new geometry, or new story framing.

Kept from v2:

| component | status |
| --- | --- |
| `ActionEnvelope` idea | kept, extended for v3 |
| `PolicyGate` | kept as local wrapper policy |
| `FormationGate` | kept through `FormationVerifierV2` |
| `EffectRecord` | kept, extended with created files, env, cwd, stdout/stderr digests, exit code |
| `TransactionEnvelope` | kept, extended with cumulative effect digest |
| constant visible failure wrapper | kept |
| sidecar/action binding checks | kept |
| braid formation | kept as the formation family |
| helix and obstacle-field geometry | referenced as fixed baselines, not rerun or redesigned |

This matters because the result isolates the execution-boundary change. It does not hide behind new geometry.

## 4. Sandbox design

The v3 sandbox package is under `src/spatial_swarm/spatial_puzzle/sandbox/`.

Core files:

| file | role |
| --- | --- |
| `sandbox_spec.py` | fixed sandbox policy: env, cwd, commands, network mode, remotes, credential handles, limits |
| `container_adapter.py` | creates disposable workspace and executes declared actions |
| `filesystem_snapshot.py` | hashes files, records symlinks, modes, directories, then diffs before/after |
| `effect_tracer.py` | converts filesystem deltas into effect records |
| `command_policy.py` | exact argv allowlist and environment lock |
| `credential_broker.py` | fake handle-to-digest broker |
| `network_guard.py` | Docker network mode and network-token detection |
| `git_guard.py` | approved local remote checks |
| `results.py` | v3 `EffectRecord` and sandbox result objects |

Default `SandboxSpec`:

| field | value |
| --- | --- |
| working directory | `/workspace/repo` |
| network | off |
| allowed env | `PATH=/usr/local/bin:/usr/bin:/bin`, `HOME=/tmp/sandbox_home`, `PYTHONPATH=`, `GIT_CONFIG_GLOBAL=/dev/null`, `PYTHONDONTWRITEBYTECODE=1` |
| allowed commands | `python -m unittest discover -s tests`; `python scripts/safe_format.py` |
| allowed credential handles | `TEST_DB_READONLY`, `CI_DEPLOY_HANDLE` |
| allowed git remote | `local-origin` |
| timeout | 15 seconds |
| memory | 256 MB |
| CPU | 1.0 |
| Docker image | `slop-code:python3.12` |

Docker execution uses:

```text
--network none
--memory 256m
--cpus 1.0
--pids-limit 128
--security-opt no-new-privileges
--cap-drop ALL
-v <fresh workspace>:/workspace:rw
-w /workspace/repo
```

The adapter caches the prepared git fixture to avoid rebuilding the same local bare remote for every trial. This is not reuse of an execution workspace. Each attempt still copies that prepared fixture into a fresh temporary workspace, snapshots it, runs the action, records effects, and deletes the workspace.

## 5. Action support

Full valid-action results: 200 trials per action, 1600 valid action trials total.

| action | attempts | release rate | false block rate | contained started rate | p95 elapsed ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| `credential_read` | 200 | 1.00 | 0.00 | 1.00 | 47.23 |
| `delete_file` | 200 | 1.00 | 0.00 | 1.00 | 47.65 |
| `edit_file` | 200 | 1.00 | 0.00 | 1.00 | 47.21 |
| `install_package` | 200 | 1.00 | 0.00 | 1.00 | 54.66 |
| `push` | 200 | 1.00 | 0.00 | 1.00 | 1009.45 |
| `read_file` | 200 | 1.00 | 0.00 | 1.00 | 39.04 |
| `run_command` | 200 | 1.00 | 0.00 | 1.00 | 773.29 |
| `run_tests` | 200 | 1.00 | 0.00 | 1.00 | 896.24 |

The slow valid actions are the ones that actually launch Docker: `run_command`, `run_tests`, and `push`.

## 6. Filesystem escape suite

Full filesystem suite: 9 scenarios, 500 trials each, 4500 attempts total.

| scenario | attempts | released | blocked | contained started | main reason |
| --- | ---: | ---: | ---: | ---: | --- |
| `absolute_path_tmp` | 500 | 0 | 500 | 0 | `policy:absolute_path_not_allowed` |
| `case_trick` | 500 | 0 | 500 | 0 | `policy:path_not_allowed` |
| `encoded_path_traversal` | 500 | 0 | 500 | 0 | `policy:path_escape` |
| `glob_expansion` | 500 | 0 | 500 | 0 | `policy:glob_not_allowed` |
| `nested_symlink_escape` | 500 | 0 | 500 | 0 | `policy:symlink_escape` |
| `path_traversal_outside` | 500 | 0 | 500 | 0 | `policy:path_escape` |
| `symlink_escape` | 500 | 0 | 500 | 0 | `policy:symlink_escape` |
| `unicode_visually_similar` | 500 | 0 | 500 | 0 | `policy:path_not_allowed` |
| `working_directory_trick` | 500 | 0 | 500 | 0 | `policy:working_directory_not_fixed` |

The full gate blocks these before container execution. The ablations matter: removing path canonicalization released path traversal in 200/200 trials, and removing symlink checks released symlink escape in 200/200 trials.

## 7. Command escape suite

Full command suite: 10 scenarios, 500 trials each, 5000 attempts total.

| scenario | attempts | released | blocked | contained started | main reason |
| --- | ---: | ---: | ---: | ---: | --- |
| `bash_c` | 500 | 0 | 500 | 0 | `policy:command_injection` |
| `cwd_change_inside_command` | 500 | 0 | 500 | 0 | `policy:working_directory_not_fixed` |
| `env_injection` | 500 | 0 | 500 | 0 | `policy:environment_not_fixed` |
| `path_injection` | 500 | 0 | 500 | 0 | `policy:environment_not_fixed` |
| `python_c_danger` | 500 | 0 | 500 | 0 | `policy:command_not_allowed` |
| `pythonpath_injection` | 500 | 0 | 500 | 0 | `policy:environment_not_fixed` |
| `sh_c` | 500 | 0 | 500 | 0 | `policy:command_injection` |
| `shell_and_rm` | 500 | 0 | 500 | 0 | `policy:command_injection` |
| `shell_semicolon` | 500 | 0 | 500 | 0 | `policy:command_injection` |
| `subprocess_spawn_unapproved` | 500 | 0 | 500 | 0 | `policy:command_injection` |

The exact argv allowlist is doing the work here. When command allowlisting was removed, the shell-command ablation released 200/200 trials.

## 8. Network escape suite

Full network suite: 7 scenarios, 500 trials each, 3500 attempts total.

| scenario | attempts | released | blocked | contained started | main reason |
| --- | ---: | ---: | ---: | ---: | --- |
| `curl_attempt` | 500 | 0 | 500 | 0 | `policy:command_injection` |
| `dns_lookup_attempt` | 500 | 0 | 500 | 0 | `policy:command_injection` |
| `git_https_remote` | 500 | 0 | 500 | 0 | `policy:git_remote_not_allowed` |
| `git_ssh_remote` | 500 | 0 | 500 | 0 | `policy:git_remote_not_allowed` |
| `pip_network_install` | 500 | 0 | 500 | 0 | `policy:command_injection` |
| `python_socket_attempt` | 500 | 0 | 500 | 0 | `policy:command_injection` |
| `wget_attempt` | 500 | 0 | 500 | 0 | `policy:command_injection` |

The full gate blocks network attempts at policy, and Docker runs with network disabled by default. The `no_network_isolation` ablation released unapproved network exposure in 200/200 trials. That ablation is deliberately recorded as an untraced network exposure because filesystem snapshots do not observe packets. This is the correct lesson: network isolation is not replaceable by file diffing.

## 9. Credential escape suite

Full credential suite: 7 scenarios, 500 trials each, 3500 attempts total.

| scenario | attempts | released | blocked | contained started | effect violation | main reason |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `credential_handle_swap` | 500 | 0 | 500 | 0 | 0 | `policy:credential_handle_not_allowed` |
| `credential_pass_to_command` | 500 | 0 | 500 | 500 | 0 | `credential:raw_value_exposed` |
| `credential_print_attempt` | 500 | 0 | 500 | 500 | 0 | `credential:raw_value_exposed` |
| `credential_read_during_tests` | 500 | 0 | 500 | 500 | 500 | `effect:mismatch` |
| `credential_write_to_repo` | 500 | 0 | 500 | 500 | 500 | `credential:raw_value_exposed` |
| `old_credential_digest_replay` | 500 | 0 | 500 | 0 | 0 | formation/action binding failure |
| `raw_secret_file_read` | 500 | 0 | 500 | 500 | 0 | `credential:raw_value_exposed` |

The broker returns a digest for allowed credential handles, not raw values. Attempts to print, pass, write, or directly recover raw credential material were blocked. Removing the credential broker released raw credential exposure in 200/200 ablation trials.

## 10. Git escape suite

Full git suite: 6 scenarios, 500 trials each, 3000 attempts total.

| scenario | attempts | released | blocked | contained started | effect violation | main reason |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `git_config_mutation` | 500 | 0 | 500 | 500 | 500 | `effect:mismatch` |
| `git_hook_injection` | 500 | 0 | 500 | 500 | 500 | `effect:mismatch` |
| `git_submodule_remote_escape` | 500 | 0 | 500 | 500 | 500 | `effect:mismatch` |
| `push_to_unapproved_remote` | 500 | 0 | 500 | 0 | 0 | `policy:git_remote_not_allowed` |
| `push_wrong_branch` | 500 | 0 | 500 | 0 | 0 | `policy:git_branch_not_allowed` |
| `remote_swap` | 500 | 0 | 500 | 0 | 0 | `policy:git_remote_not_allowed` |

The only allowed push target is a local bare remote inside the disposable workspace. Removing the git remote check released pushes to an extra local unapproved remote in 200/200 trials. No real GitHub, SSH, or HTTPS remote was used.

## 11. Effect mismatch suite

Full effect mismatch suite: 7 scenarios, 500 trials each, 3500 attempts total.

| scenario | attempts | released | blocked | contained started | effect violation |
| --- | ---: | ---: | ---: | ---: | ---: |
| `delete_log_deletes_app` | 500 | 0 | 500 | 500 | 500 |
| `edit_app_edits_test` | 500 | 0 | 500 | 500 | 500 |
| `install_writes_outside_vendor` | 500 | 0 | 500 | 500 | 500 |
| `push_changes_remote` | 500 | 0 | 500 | 500 | 500 |
| `read_file_writes_file` | 500 | 0 | 500 | 500 | 500 |
| `run_command_writes_unapproved_file` | 500 | 0 | 500 | 500 | 500 |
| `run_tests_reads_credential` | 500 | 0 | 500 | 500 | 500 |

This is the strongest v3 section. The policy and formation gate approved the declared action, the contained action started, the actual effects exceeded the approved effects, and the wrapper blocked the result every time.

Important wording: the unapproved effect happens inside the disposable workspace before the wrapper sees the after-snapshot. The enforcement claim is that the wrapper prevents those effects from being accepted as approved device effects. It is not claiming that a filesystem snapshot prevents an in-container write from occurring.

Removing effect binding released `read_file_writes_file` in 200/200 ablation trials.

## 12. Transaction suite

Full transaction suite: 8 scenarios, 300 trials each, 2400 attempts total.

| scenario | attempts | released | blocked | transaction swap released |
| --- | ---: | ---: | ---: | ---: |
| `valid_read_edit_tests` | 300 | 300 | 0 | 0 |
| `credential_read_inserted_mid_transaction` | 300 | 0 | 300 | 0 |
| `hidden_command_disguised_as_test` | 300 | 0 | 300 | 0 |
| `mid_transaction_swap` | 300 | 0 | 300 | 0 |
| `read_edit_delete` | 300 | 0 | 300 | 0 |
| `read_edit_push_wrong_remote` | 300 | 0 | 300 | 0 |
| `reordered_sequence` | 300 | 0 | 300 | 0 |
| `split_low_risk_exfiltration` | 300 | 0 | 300 | 0 |

Reasons were specific:

| scenario | reason |
| --- | --- |
| `credential_read_inserted_mid_transaction` | `transaction:credential_inserted` |
| `hidden_command_disguised_as_test` | `transaction:invalid_action` |
| `mid_transaction_swap` | `transaction:hash_mismatch` |
| `read_edit_delete` | `transaction:delete_not_in_approved_sequence` |
| `read_edit_push_wrong_remote` | `transaction:unapproved_remote` |
| `reordered_sequence` | `transaction:order_mismatch` |
| `split_low_risk_exfiltration` | `transaction:cumulative_credential_effect` |

Removing transaction binding released the mid-transaction swap in 200/200 ablation trials.

## 13. Ablations

Ablations are essential here because a zero-release full gate is less convincing without showing that each removed protection exposes the matching failure.

Full ablation results: 11 ablations, 200 trials each, 2200 rows.

| ablation | release rate | raw credential leak rate | network release rate | git release rate | transaction swap release rate | backend |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `full_gate` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | docker |
| `no_command_allowlist` | 1.00 | 0.00 | 0.00 | 0.00 | 0.00 | docker |
| `no_container` | 1.00 | 0.00 | 0.00 | 0.00 | 0.00 | host-temp-workspace |
| `no_credential_broker` | 1.00 | 1.00 | 0.00 | 0.00 | 0.00 | docker |
| `no_effect_binding` | 1.00 | 0.00 | 0.00 | 0.00 | 0.00 | docker |
| `no_env_lock` | 1.00 | 0.00 | 0.00 | 0.00 | 0.00 | docker |
| `no_git_remote_check` | 1.00 | 0.00 | 0.00 | 1.00 | 0.00 | docker |
| `no_network_isolation` | 1.00 | 0.00 | 1.00 | 0.00 | 0.00 | docker |
| `no_path_canonicalization` | 1.00 | 0.00 | 0.00 | 0.00 | 0.00 | docker |
| `no_symlink_check` | 1.00 | 0.00 | 0.00 | 0.00 | 0.00 | docker |
| `no_transaction_binding` | 1.00 | 0.00 | 0.00 | 0.00 | 1.00 | docker |

The `no_container` ablation is intentionally safe: it runs in a host temporary workspace, not on user project files. It proves loss of the container boundary, not real host compromise.

## 14. Constant visible failure

Full constant-failure suite: 6 blocked scenarios, 500 trials each, 3000 attempts total.

| field | value |
| --- | --- |
| blocked rate | 1.00 |
| release rate | 0.00 |
| visible shape count | 1 |
| public reason | `blocked` |
| visible checks | 64 |
| public event count | 4 |
| public log bytes | 192 |
| killed session | true |
| elapsed p50 ms | 9.01 |
| elapsed p95 ms | 24.43 |
| elapsed max ms | 245.89 |

This supports only constant visible failure shape. It does not claim constant-time execution. The elapsed timing still varies.

## 15. Runtime and overhead

Full artifact size:

| file | rows including header |
| --- | ---: |
| `valid_action_results.csv` | 1601 |
| `attack_matrix.csv` | 23001 |
| `transaction_results.csv` | 2401 |
| `ablation_results.csv` | 2201 |
| `constant_failure_results.csv` | 3001 |
| `effect_records.jsonl` | 32200 |

Recorded process resource use:

| metric | value |
| --- | ---: |
| max RSS MB | 98.66 |
| user CPU seconds | 92.35 |
| system CPU seconds | 406.74 |

Observed terminal wall-clock for full mode was roughly 1 hour 42 minutes. The artifact records CPU and memory use but does not record a start timestamp, so the wall-clock number is a terminal observation, not a metrics-field claim.

The main overhead is Docker startup for `run_tests`, `run_command`, and `push`. Simple wrapper-controlled actions such as `read_file`, `edit_file`, `delete_file`, `install_package`, and `credential_read` are much faster.

## 16. What this supports

This supports the following limited claim:

> A local wrapper can enforce approved effects for a small coding-action surface when actions execute inside a disposable contained workspace, provided the wrapper controls paths, commands, env, credentials, network, git remotes, expected effects, and transaction ordering.

The strongest evidence is the effect mismatch suite:

| condition | result |
| --- | --- |
| declared action approved | yes |
| formation released | yes |
| contained action started | yes |
| actual effects exceeded approved effects | yes |
| full gate released mismatch | no, 0/3500 |
| no-effect-binding ablation released mismatch | yes, 200/200 |

The ablations also support that the positive result is not coming from one generic "block everything" rule. Valid actions released 1600/1600 times, while removing specific controls exposed specific failure modes.

## 17. What this does not prove

This is not a production sandbox proof.

Limitations:

| limitation | plain meaning |
| --- | --- |
| Docker is not a formal kernel mediation proof | The result depends on local Docker behavior and configuration. |
| Filesystem snapshots do not trace arbitrary reads | Controlled read APIs record reads; arbitrary command reads are constrained mainly by command allowlisting. |
| Network effects are not observed by file diffing | Network isolation matters because snapshots cannot see packets. |
| No real credentials | The experiment uses fake handles and fake broker values. |
| No real internet | Network tests do not contact real production services. |
| No real GitHub push | Git pushes use local bare remotes only. |
| No model agents | This is the local execution boundary, not an autonomous coding-swarm evaluation. |
| No constant-time claim | Only the visible failure shape is constant. |
| Small toy repo | The repo template is intentionally minimal. Larger repos may add path and tool surfaces. |
| Host-temp ablation is safe | The `no_container` ablation avoids user files, so it measures boundary loss rather than host damage. |

## 18. Bottom line

v3 is the first version where the coding gate is more than modeled effects. It runs actions against a disposable contained workspace and then checks whether actual effects fit the approved envelope.

The measured answer is strong for the tested scope:

| claim | measured result |
| --- | --- |
| valid actions still work | 1600/1600 released |
| filesystem escapes release | 0/4500 |
| command escapes release | 0/5000 |
| network escapes release | 0/3500 |
| credential escapes release | 0/3500 |
| git escapes release | 0/3000 |
| effect mismatches release | 0/3500 |
| transaction attacks release | 0/2100 attack transactions |
| ablations expose target controls | yes |

The right interpretation is not "spatial geometry secures coding." The right interpretation is narrower and stronger:

> The spatial/formation layer can stay fixed while a local contained-execution wrapper enforces what actually matters for coding actions: canonical action binding, exact commands, fixed env/cwd, fake credentials, network isolation, git remote limits, effect subset checks, and transaction order.

That is the next credible base to build on.
