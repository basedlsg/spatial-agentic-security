# Finding: random vs 3D secret, commitment scheme held constant

Status: internal finding (not a paper). Records measurements only.

Question: holding signatures, encryption, message binding, and the commitment
scheme fixed, does a 3D-structured secret change how hard it is to obtain a hidden
agent's secret, compared to a structureless random secret?

Two settings are measured: (A) the full protocol with encryption intact (via the
eval kit), and (B) a research harness with the encryption shield removed
(`experiments/spatial_hardness.py`), so the secret format itself is what is tested.

## Setting A — full crypto, random-secret gate vs 3D-points gate

Eval kit over 40 seeds (`evaluate_gate`), agent_count=4, fragment_size=8.

| gate | secret format | honest released | real-attack releases | positive-control releases |
| --- | --- | --- | --- | --- |
| UCOG | random 32-byte secret | 40/40 | 0 (×3 attacks) | 40 (×2 controls) |
| USAG | 3D F_257^3 points | 40/40 | 0 (×3 attacks) | 40 (×2 controls) |

The two gates produce the same release counts on every capability.

## Setting B — encryption removed, reconstruction harness

Three secret formats with the same commitment `H(swarm, agent, sorted(items))`:
`random` (k distinct ints, independent per agent), `points3d` (k points of a
shared F_p^3 cloud, partitioned), `voxel` (a shared voxel object partitioned into
connected k-voxel pieces).

### B1 — commitment-only search space

Small instances (k=2), brute-force sampler against the commitment, cap 200,000:

| instance | domain | found | guesses |
| --- | ---: | --- | ---: |
| random (M=128, k=2) | 8,128 | yes | 1 |
| points3d (p=5, k=2) | 7,750 | yes | 1,149 |
| voxel (2×2×2, k=2) | 28 | yes | 34 |

Realistic-parameter domain sizes (log2, k=16): random (M=2^32) = 467.7 bits;
points3d (p=257) = 340.0 bits; voxel (16^3) = 147.7 bits. At these parameters the
two geometry domains are smaller than the random domain.

### B2 — assembly-complement reconstruction (attacker observes the shared object + every other piece)

20 swarms, agent_count=4, k=4; recover one held-out piece.

| secret format | exact recovery | candidates for the missing piece |
| --- | ---: | ---: |
| random | 0 / 20 | 768,543,969,628,897,280 (= C(2^16, 4)) |
| points3d | 20 / 20 | 1 |
| voxel | 20 / 20 | 1 |

For the shared-object formats the missing piece equals `target \ union(others)`, so
it is determined exactly. For random the secrets are independent, so observing the
others leaves the full domain.

### B3 — candidates for the missing piece vs number of other pieces observed (shared object known)

| secret format | 0 others seen | 1 other seen | 2 others seen |
| --- | ---: | ---: | ---: |
| voxel (connected) | 107 | 2 | 1 |
| points3d | 495 | 70 | 1 |
| random | 7.69e17 | 7.69e17 | 7.69e17 |

For the geometry formats the candidate count decreases as more pieces are observed,
reaching 1 when all other pieces are observed. For random it is unchanged by
observation.

### B4 — observing one prior-round transformed piece (public transform)

The protocol's challenge transform is public and invertible. Attacker observes the
plaintext transformed coordinates of one prior round and inverts the public
transform. 20 trials, points3d, k=16:

```text
exact recovery: 20 / 20 from 1 observation
```

## Reproduce

```text
uv run --extra dev pytest tests/test_spatial_hardness.py tests/test_evalkit.py
uv run python -c "import json; from spatial_swarm.experiments.spatial_hardness import run_spatial_hardness as r; print(json.dumps(r(), indent=2, default=str))"
```

## Not run

An LLM reconstruction attacker (no model endpoint available in this environment).
The harness records no model-based attempt.
