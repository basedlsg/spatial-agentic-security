# Results v0.1

USAG v0.1 established the first deterministic protocol result.

## Validated Points

```text
26 tests passed
honest communication: 100 / 100 passed
fake_agent: 0 / 100 passed
replay: 0 / 100 passed
wrong_message: 0 / 100 passed
overbudget: 0 / 100 passed
underbudget: 0 / 100 passed
unregistered_fake_agent: 0 / 100 passed
valid_signature_wrong_geometry: 0 / 100 passed
valid_signature_wrong_transform: 0 / 100 passed
```

The key v0.1 result is that a valid registered signature with wrong spatial material is
blocked by the spatial verifier:

```text
valid_signature_wrong_geometry -> wrong_geometry
valid_signature_wrong_transform -> wrong_geometry
```

This shows that the spatial layer is doing work beyond Ed25519 signatures.

## Corrected 1024-Agent Smoke

After fixing numeric agent ordering, the 1024-agent fake-late smoke result was:

```text
N = 1024
fragment_size = 16
unauthorized passes = 0 / 1
failure_reason = wrong_signature
p95 latency = 1585.532 ms
total proof bytes = 1,241,101
RSS = 56.55 MB
```

Earlier 1024-agent timing was superseded because lexicographic ordering placed
`agent_1024` before later numeric agents. Numeric ordering is now covered by regression
tests.

## Timing Interpretation

Attack latency depends on where the first bad packet appears. A wrong-message attack that
fails on the first packet is much faster than a wrong-message attack where valid packets
are verified before the bad packet appears. v0.2 splits early, middle, and late packet
positions explicitly.
