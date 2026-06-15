# Finding: does 3D structure add attack cost over a random secret?

Status: internal finding (not a paper). Measurements only. Supersedes the shallow
`docs/findings_spatial_hardness.md` (which used a contiguous-chunk "voxel" model,
tiny instances, and `comb()` arithmetic instead of real solvers).

Question: holding the commitment, signatures, encryption, and message binding
fixed, and matching entropy, does a 3D-structured secret make recovering a hidden
agent secret harder than a structureless random secret? Tested with real solvers,
positive controls that gate the run, and Clopper-Pearson intervals.

Built in `src/spatial_swarm/spatial_lab/` (commit `9ed86802e1`). Representation
ladder: R0 random ints, R1 points in a shared F_p^3 cloud, R2 connected voxel
piece (public outer shape), R3 + published connector signature, R4 + published
topology signature. Two research "lab modes" hide geometric information so the
attacker faces a real search; the protocol's own transform is public/invertible,
so registration there is trivial.

## Method

- Entropy matched across representations (R0/R1 sized to the voxel bounding-cube
  combinatorial space); reported per representation; the run flags if bands diverge.
- Positive controls (planted identity pose; all-but-one piece revealed) run for
  every representation and gate the run (`positive_controls.valid`); a 0% attacker
  row therefore cannot be a silently broken solver.
- Solvers carry a time/node budget; `budget_hit` and `exhausted` are distinct.
- Two tiers: EXACT (n=3, k=4, 30 seeds, enumerable) and SCALING (n=4, k=8, 10
  seeds, budgeted). Both had `positive_controls.valid = True` and matched entropy
  (EXACT 14.1 bits, SCALING 32.0 bits, all representations).

## Lab A — unknown-pose registration

The attacker sees a piece under a hidden rigid pose (one of 24 rotations × an
11×11×11 = 1331 translation grid; pose space = 24·1331, ~11.6 bits) and must
recover the committed piece. Exhaustive pose search against the commitment oracle:

| tier | repr | exhaustive found | median nodes | pose-space bits | random-secret bits | bits saved by 1 observation |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| EXACT | R1–R4 | 30/30 each | 1111 | 11.6 | 14.1 | 2.5 |
| SCALING | R1–R4 | 10/10 each | 804 | 11.6 | 32.0 | 20.5 |

The pose space is fixed (~11.6 bits) regardless of the secret's entropy, so one
observation reduces the search from the full secret space to the pose space.
The local-window heuristic (small translation window) recovered fewer (e.g. EXACT
R2: 9/30) — an honest heuristic miss, not a budget stop. Neighbor-copy (submit a
stolen neighbor piece) recovered 5/30 for R2–R4 at EXACT and 0/30 for R1: at k=4
some voxel pieces are congruent, so a neighbor occasionally opens the target.

## Lab B — assembly constraint-search

The attacker knows the outer shape and the published constraints (none beyond the
shape for R2; connector signature for R3; + topology for R4) and searches connected
k-voxel subsets for one that opens the commitment.

EXACT-tier candidate count (median consistent candidates) vs number of other pieces
revealed:

| repr | 0 revealed | 1 revealed | 2 revealed |
| --- | ---: | ---: | ---: |
| R1 points | 495 | 70 | 1 |
| R2 voxel (shape only) | 27.5 | 7 | 1 |
| R3 voxel + connectors | 1 | 1 | 1 |
| R4 voxel + connectors + topology | 1 | 1 | 1 |
| R0 random | full secret space (constraints uninformative) | — | — |

Publishing the connector signature (R3) collapsed the candidate set to a single
piece even with no other pieces revealed.

SCALING-tier assembly found-rate (k=8 from a 32-voxel object, 2.5s/800k-node budget):

```text
R0 random : full secret space (no shared object)
R1 points : 0/10 found (budget_hit 10/10; median 308,212 nodes) -- no structure to prune
R2 voxel  : 10/10 found (median 1,038 nodes)
R3 voxel+connectors : 10/10 found (median 1,038 nodes)
R4 voxel+connectors+topology : 10/10 found (median 1,038 nodes)
```

The structured voxel representations (R2–R4) let the attacker find the piece in
~1,000 nodes, while the structureless points (R1) exceeded the budget on every
seed. (The SCALING candidate-count curve is empty because exact enumeration did
not complete within budget; counts are reported only when the search exhausted.)

## What the numbers show (direct readings)

- In Lab A, recovering a 3D piece hidden behind a rigid pose was a fixed ~11.6-bit
  search at both tiers, below the matched random-secret entropy (14.1 then 32.0
  bits); the gap grew with secret size.
- In Lab B, adding 3D structure lowered the attacker's candidate count and search
  cost: connectors collapsed the EXACT candidate set to 1, and voxel structure let
  the attacker solve SCALING instances that the structureless points/random
  representations did not.
- No tier or representation showed the 3D format raising attack cost above the
  matched random secret.

## Caveats

```text
- Set-based (R0/R1) and shape-based (R2-R4) secrets are matched only on
  commitment-only preimage entropy -- the one common unit, not "semantic difficulty".
- The pose space (24 x translation grid) is finite and chosen by the experiment;
  pose-space bits are reported next to solver time so a finite search is not read
  as cryptographic hardness.
- Lab A neighbor-copy hits at small k reflect piece congruence, a shape-reuse leak.
- The SCALING assembly candidate-count curve was not exhaustible within budget.
- An LLM attacker was not run (no model endpoint); the hook records status=not_run.
```

## Reproduce

```text
uv run --extra dev pytest tests/test_spatial_lab_*.py
uv run python -m spatial_swarm.spatial_lab.run --tier exact   --reprs R0,R1,R2,R3,R4 --lab both --seeds 30
uv run python -m spatial_swarm.spatial_lab.run --tier scaling --reprs R0,R1,R2,R3,R4 --lab both --seeds 10
```
