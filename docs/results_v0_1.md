# Results v0.1

> Note: dated record of what was measured. Protocol now called UCOG (code name USAG).
> A later fair-baseline experiment (docs/findings_keystone_fair_baseline.md) and the
> formal model (docs/security_model.md) show the geometry adds no cryptographic hardness
> over a unanimous commitment-opening gate; read 'spatial' below as an instantiation
> detail, not a security property.

This file is a dated record of the UCOG (Unanimous Commitment-Opening Gate; code name
USAG) v0.1 run. It records the first deterministic protocol measurements taken under the
conditions described below.

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

In this run, a valid registered signature submitted with wrong spatial material was
rejected by the verifier with reason `wrong_geometry`:

```text
valid_signature_wrong_geometry -> wrong_geometry
valid_signature_wrong_transform -> wrong_geometry
```

Under the conditions of this v0.1 run, these cases were measured against signature
baselines that never open a per-agent secret, so the observed rejection is consistent
with a verifier that requires opening a per-agent secret in addition to checking the
Ed25519 signature. A later fair-baseline experiment shows that a unanimous
commitment-opening gate without the spatial encoding produces the same separation, so the
geometry is not the source of the separation; the per-agent commitment opening plus
unanimity plus message binding is (see docs/findings_keystone_fair_baseline.md and
docs/security_model.md). The 3D/affine 'spatial' encoding here is one instantiation of
the per-agent secret and is treated as an ablated design point.

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
