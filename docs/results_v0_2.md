# Results v0.2

These results come from raw artifacts in `runs/` generated on June 8, 2026. The v0.2
benchmark code was still in the working tree when these runs were generated, so the
artifact `git_commit.txt` files point at the previous commit. Treat this as a valid
engineering benchmark and rerun after the v0.2 commit before using the numbers in a paper.

## Test Result

```text
35 tests passed
```

## 1,000-Attempt Matrix

Run artifact:

```text
runs/2026-06-08T03-11-36.104115Z
```

Configuration:

```text
N = 8
fragment_size = 16
field = F_257^3
attempts = 1,000 per scenario
```

Summary:

```text
honest: 1000 / 1000 passed
all attack scenarios: 0 / 24,000 unauthorized attempts passed
```

Key attack outcomes:

| Scenario | Passes | Failure reason | Stage | p95 latency ms |
| --- | ---: | --- | --- | ---: |
| fake_agent | 0 / 1000 | `wrong_signature` | signature | 16.085 |
| unregistered_fake_agent | 0 / 1000 | `unregistered_agent` | registration | 0.012 |
| replay | 0 / 1000 | `wrong_message_hash` | message_binding | 0.022 |
| wrong_message | 0 / 1000 | `wrong_message_hash` | message_binding | 0.015 |
| overbudget | 0 / 1000 | `over_budget` | proof_envelope | 0.946 |
| underbudget | 0 / 1000 | `under_budget` | proof_envelope | 0.117 |
| malformed | 0 / 1000 | `malformed_packet` | registration | 0.099 |
| duplicate | 0 / 1000 | `duplicate_submission` | submission_policy | 30.049 |
| slow | 0 / 1000 | `late_packet` | timeout | 0.124 |
| missing | 0 / 1000 | `missing_packet` | assembly | 24.078 |
| partial_swarm | 0 / 1000 | `missing_packet` | assembly | 26.391 |
| stolen_piece | 0 / 1000 | `missing_packet` | assembly | 3.621 |
| stolen_signing_key_only | 0 / 1000 | `wrong_geometry` | geometry | 12.439 |
| stolen_fragment_only | 0 / 1000 | `wrong_signature` | signature | 9.410 |
| correct_geometry_wrong_agent_id | 0 / 1000 | `response_binding_failed` | response_binding | 12.258 |

## Packet Position Results

The verifier is fail-fast. Latency increases when the first bad packet appears later.

| Scenario | Position | Packets checked p50 | Stage | p95 latency ms |
| --- | --- | ---: | --- | ---: |
| valid_signature_wrong_geometry | early | 1 | geometry | 4.521 |
| valid_signature_wrong_geometry | middle | 4 | geometry | 19.694 |
| valid_signature_wrong_geometry | late | 8 | geometry | 51.148 |
| valid_signature_wrong_transform | early | 1 | geometry | 6.964 |
| valid_signature_wrong_transform | middle | 4 | geometry | 28.504 |
| valid_signature_wrong_transform | late | 8 | geometry | 27.935 |
| valid_signature_wrong_message_hash | early | 1 | message_binding | 0.012 |
| valid_signature_wrong_message_hash | middle | 4 | message_binding | 7.149 |
| valid_signature_wrong_message_hash | late | 8 | message_binding | 21.057 |

The message-hash variants perform no signature, decryption, or geometry work on the bad
packet itself. Middle/late latency reflects valid packets processed before the bad packet.

## 1024-Agent Honest Scale

Run artifact:

```text
runs/2026-06-08T03-28-56.200038Z
```

Result:

```text
N = 1024
attempts = 100
honest passes = 100 / 100
failure count = 0
p50 latency = 2101.368 ms
p95 latency = 3581.651 ms
p99 latency = 4081.861 ms
p95 proof bytes = 1,241,353
RSS = 104.844 MB
```

## 1024-Agent Attack Scale

Configuration:

```text
N = 1024
attempts = 100 per scenario
fragment_size = 16
```

| Scenario | Passes | Failure reason | Packets checked p50 | p95 latency ms | RSS MB |
| --- | ---: | --- | ---: | ---: | ---: |
| fake_agent_early | 0 / 100 | `wrong_signature` | 1 | 1.332 | 57.859 |
| fake_agent_middle | 0 / 100 | `wrong_signature` | 512 | 2060.847 | 83.031 |
| fake_agent_late | 0 / 100 | `wrong_signature` | 1024 | 7432.410 | 106.188 |
| valid_signature_wrong_geometry_early | 0 / 100 | `wrong_geometry` | 1 | 9.753 | 59.125 |
| valid_signature_wrong_geometry_middle | 0 / 100 | `wrong_geometry` | 512 | 2227.390 | 82.781 |
| valid_signature_wrong_geometry_late | 0 / 100 | `wrong_geometry` | 1024 | 3255.078 | 105.906 |
| replay_early | 0 / 100 | `wrong_message_hash` | 1 | 0.008 | 65.766 |
| replay_late | 0 / 100 | `wrong_message_hash` | 1024 | 1624.564 | 107.422 |

The `fake_agent_late` run had a high-tail outlier (`max = 80377.943 ms`). Treat that as a
measurement outlier to investigate before publication; do not smooth it away.

## Trusted Verifier Limitation

USAG v1 assumes a trusted gateway/verifier. The verifier stores raw fragment material and
commitments in the registry, decrypts submitted proof packets, and compares transformed
coordinates against registered fragments. A compromised gateway/verifier can forge,
bypass, or falsely reject communication.

## Interpretation

The v0.2 evidence supports this narrow claim:

```text
Under the deterministic trusted-verifier harness, honest messages passed and the
implemented unauthorized, malformed, replay, budget, stolen-material, and wrong-geometry
attacks failed closed.
```

It does not support claims of foolproof security, semantic truth, or superiority over
cryptographic signatures in general.
