# Results v0.2

> Note: dated record of what was measured. Protocol now called UCOG (code name USAG).
> A later fair-baseline experiment (docs/findings_keystone_fair_baseline.md) and the
> formal model (docs/security_model.md) show the geometry adds no cryptographic hardness
> over a unanimous commitment-opening gate; read 'spatial' below as an instantiation
> detail, not a security property.

These results were generated from a clean committed tree.

```text
commit: 761439ec02b6da07ee0f2a7b37851b8873d513cf
Python: 3.13.2
platform: macOS-26.2-arm64-arm-64bit-Mach-O
machine: arm64
uv.lock SHA-256: c9bfd2dd5969d91149c5383635ddb096b801c49b4d45d74e2af4ff281119a306
```

The earlier dirty-tree artifacts remain in `runs/` as engineering history, but the
artifacts below are the paper-grade v0.2 rerun.

## Test Result

```text
uv run --extra dev pytest
40 passed
uv lock --check
Resolved 27 packages
```

## 1,000-Attempt Matrix

Run artifact:

```text
runs/2026-06-08T12-14-14.051135Z
worktree_dirty: false
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

Key outcomes:

| Scenario | Passes | Failure reason | Stage | p95 latency ms |
| --- | ---: | --- | --- | ---: |
| fake_agent | 0 / 1000 | `wrong_signature` | signature | 28.027 |
| unregistered_fake_agent | 0 / 1000 | `unregistered_agent` | registration | 0.018 |
| replay | 0 / 1000 | `wrong_message_hash` | message_binding | 0.026 |
| wrong_message | 0 / 1000 | `wrong_message_hash` | message_binding | 0.023 |
| overbudget | 0 / 1000 | `over_budget` | proof_envelope | 1.365 |
| underbudget | 0 / 1000 | `under_budget` | proof_envelope | 0.118 |
| malformed | 0 / 1000 | `malformed_packet` | registration | 0.127 |
| duplicate | 0 / 1000 | `duplicate_submission` | submission_policy | 71.025 |
| missing | 0 / 1000 | `missing_packet` | assembly | 74.661 |
| partial_swarm | 0 / 1000 | `missing_packet` | assembly | 72.579 |
| stolen_signing_authority_only | 0 / 1000 | `wrong_geometry` | geometry | 87.879 |
| stolen_fragment_only | 0 / 1000 | `wrong_signature` | signature | 10.773 |
| correct_geometry_wrong_agent_id | 0 / 1000 | `response_binding_failed` | response_binding | 7.380 |

Packet-position outcomes:

| Scenario | Position | Passes | Failure stage | p95 latency ms |
| --- | --- | ---: | --- | ---: |
| valid_signature_wrong_geometry | early | 0 / 1000 | geometry | 1.885 |
| valid_signature_wrong_geometry | middle | 0 / 1000 | geometry | 7.416 |
| valid_signature_wrong_geometry | late | 0 / 1000 | geometry | 14.831 |
| valid_signature_wrong_transform | early | 0 / 1000 | geometry | 1.743 |
| valid_signature_wrong_transform | middle | 0 / 1000 | geometry | 6.735 |
| valid_signature_wrong_transform | late | 0 / 1000 | geometry | 13.484 |
| valid_signature_wrong_message_hash | early | 0 / 1000 | message_binding | 0.006 |
| valid_signature_wrong_message_hash | middle | 0 / 1000 | message_binding | 4.568 |
| valid_signature_wrong_message_hash | late | 0 / 1000 | message_binding | 11.175 |

The message-hash variants perform no signature, decryption, or geometry work on the bad
packet itself. Middle/late latency reflects valid packets processed before the bad packet.

## 1024-Agent Honest Scale

Run artifact:

```text
runs/2026-06-08T12-47-47.093587Z
worktree_dirty: false
```

Result:

```text
N = 1024
attempts = 100
honest passes = 100 / 100
failure count = 0
p50 latency = 2778.739 ms
p95 latency = 10562.068 ms
p99 latency = 49155.954 ms
max latency = 71462.827 ms
p95 proof bytes = 1,241,353
RSS = 106.484 MB
```

This run had high-tail latency outliers. They are preserved as measured and should be
investigated before making performance claims.

## 1024-Agent Attack Scale

Run artifact:

```text
runs/2026-06-08T14-52-34.372008Z
worktree_dirty: false
```

Configuration:

```text
N = 1024
attempts = 100 per scenario
fragment_size = 16
```

| Scenario | Passes | Failure reason | Stage | p95 latency ms | max latency ms |
| --- | ---: | --- | --- | ---: | ---: |
| fake_agent_early | 0 / 100 | `wrong_signature` | signature | 0.987 | 1.208 |
| fake_agent_middle | 0 / 100 | `wrong_signature` | signature | 826.098 | 876.899 |
| fake_agent_late | 0 / 100 | `wrong_signature` | signature | 1947.450 | 2427.208 |
| valid_signature_wrong_geometry_early | 0 / 100 | `wrong_geometry` | geometry | 3.915 | 22.953 |
| valid_signature_wrong_geometry_middle | 0 / 100 | `wrong_geometry` | geometry | 970.363 | 1228.849 |
| valid_signature_wrong_geometry_late | 0 / 100 | `wrong_geometry` | geometry | 21177.219 | 267434.703 |
| replay_early | 0 / 100 | `wrong_message_hash` | message_binding | 0.030 | 0.077 |
| replay_late | 0 / 100 | `wrong_message_hash` | message_binding | 14433.507 | 114357.261 |

Late-position geometry and replay cases had very large high-tail latencies. Treat these
as scale costs to optimize, not as values to smooth away.

## Trusted Verifier Limitation

USAG v0.2 assumes a trusted gateway/verifier. The verifier stores raw fragments and can
bypass or forge verification if compromised. Current results test fail-closed
communication under this assumption.

## Interpretation

The v0.2 evidence describes what was observed under the stated conditions:

```text
Under the deterministic trusted-verifier harness, honest messages passed and the
implemented unauthorized, malformed, replay, budget, stolen-material, and wrong-geometry
attacks failed closed.
```

This is a record of measured pass/fail outcomes on the implemented harness, not a
statement about security in general, semantic truth, verifier-compromise resistance, or
behavior relative to cryptographic signatures.

The `wrong_geometry` and `wrong_transform` rows above are measurements of one
instantiation of the per-agent secret (the 3D/affine encoding). A later fair-baseline
experiment (docs/findings_keystone_fair_baseline.md) found that a unanimous
commitment-opening baseline that never opens a per-agent geometric secret matches the
separation measured here, so the rows are reported as an ablated design point rather
than as a geometry-specific security property. The component the verifier checks at the
"assembly" stage is set-membership plus disjointness, not geometric tiling; see
docs/security_model.md.
