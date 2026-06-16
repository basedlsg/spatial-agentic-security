# Finding: an anti-leak spatial generator under neighbor compromise

Status: internal finding (not a paper). Measurements only. Separate experiment layer;
the UCOG protocol is unchanged. Follows `findings_spatial_partial_compromise_stress.md`,
which measured that the existing spatial generator produces correlated pieces, so stealing
neighbors collapses the target's residual.

## Question

The prior finding is not "3D is dead" — it is "this spatial generator creates correlated
pieces, and correlation helps the attacker under partial compromise." So: can a generator
that explicitly selects against neighbor leakage keep the target's residual higher under
one/two stolen neighbors than the old generator? Milestone: beat the old generator at
A2/A3. Random is the ceiling (an independent factor's residual does not move when
neighbors are stolen); approaching it is the stretch, not required yet.

## Method

From a pool of candidate puzzles, each is scored by its WORST-CASE residual after the
attacker steals one neighbor (A2) or two neighbors (A3) — worst-case = the minimum over
which neighbors are taken. Residual = connected k-subsets of (outer shape minus stolen
cells); hidden connectors/topology are never published. Three generators are compared on
the same pools:

```text
random_plus        : matched-entropy RANDOM second factor (residual flat under theft)
old spatial        : first candidate passing the A0-only acceptance (ambiguous at A0,
                     no neighbor-copy, no congruent neighbor)
anti-leak spatial  : among A0-acceptable candidates, the one MAXIMIZING the bottleneck
                     min(worst-A2, worst-A3)
```

Access levels reported: A0 (public only), A2 (one stolen neighbor), A3 (two stolen
neighbors), A4 (one stolen non-target sidecar == one neighbor in residual terms), A7
(solver near-miss == A0 residual). Per trial the old and anti-leak picks come from the
SAME pool, so the comparison isolates selection. `anti>old` is a paired count with a
Clopper-Pearson 95% interval. Tiers: n=5,k=4 (primary; two-neighbor theft stays
non-degenerate) and n=4,k=4 (harder; two-neighbor theft is near-degenerate).

## Configs, controls

```text
code commit : e07f9e9534   (worktree_dirty: true at run time)
tiers       : n5k4 (n=5 k=4), n4k4 (n=4 k=4); 20 trials each, pool 60, exact enumeration
positive_controls.valid : True (all 8)
redaction               : clean (secret_markers_found = 0, extended marker set)
```

## Results — residual (median) and one-shot success per access level

n=5,k=4 (random_plus matched 6.83 bits, one-shot 0.0088, flat under theft):

| level | old median | anti-leak median | old one-shot | anti one-shot | anti>old rate [95% CI] |
| --- | ---: | ---: | ---: | ---: | --- |
| A0_public_only | 64.0 | 114.0 | 0.016 | 0.009 | 0.75 [0.51, 0.91] |
| A2_one_stolen_neighbor | 24.5 | 45.5 | 0.042 | 0.022 | 0.80 [0.56, 0.94] |
| A3_two_stolen_neighbors | 3.0 | 17.0 | 0.333 | 0.059 | 0.85 [0.62, 0.97] |
| A4_one_stolen_sidecar_non_target | 24.5 | 45.5 | 0.042 | 0.022 | 0.80 [0.56, 0.94] |
| A7_solver_generated_near_miss | 64.0 | 114.0 | 0.016 | 0.009 | 0.75 [0.51, 0.91] |

n=4,k=4 (random_plus matched 6.39 bits, one-shot 0.0119, flat under theft):

| level | old median | anti-leak median | old one-shot | anti one-shot | anti>old rate [95% CI] |
| --- | ---: | ---: | ---: | ---: | --- |
| A0_public_only | 52.5 | 84.0 | 0.019 | 0.012 | 0.80 [0.56, 0.94] |
| A2_one_stolen_neighbor | 13.0 | 25.0 | 0.077 | 0.040 | 0.85 [0.62, 0.97] |
| A3_two_stolen_neighbors | 2.0 | 6.0 | 0.500 | 0.167 | 0.60 [0.36, 0.81] |
| A4_one_stolen_sidecar_non_target | 13.0 | 25.0 | 0.077 | 0.040 | 0.85 [0.62, 0.97] |
| A7_solver_generated_near_miss | 52.5 | 84.0 | 0.019 | 0.012 | 0.80 [0.56, 0.94] |

Anti-leak threshold yield (fraction of A0-acceptable puzzles also meeting A2/A3 targets):
n5k4 mean 0.196 (A2≥30, A3≥10); n4k4 mean 0.076 (A2≥15, A3≥6).

## Bits lost under theft (disentangling "bigger" from "less leaky")

The anti-leak selection also raises A0 residual (it favors bulkier targets), so part of
the A2/A3 lift is a larger starting point. The bits LOST from A0 to A2/A3 isolate the
correlation leak itself (computed from the medians above):

```text
n5k4  A0->A2 lost:  old 1.39 bits  | anti 1.32 bits   (similar)
n5k4  A0->A3 lost:  old 4.42 bits  | anti 2.75 bits   (anti retains ~1.67 more bits)
n4k4  A0->A2 lost:  old 2.01 bits  | anti 1.75 bits   (anti retains ~0.26 more bits)
n4k4  A0->A3 lost:  old 4.71 bits  | anti 3.81 bits   (anti retains ~0.90 more bits)
```

Gap to the random ceiling (one-shot, n5k4): random 0.0088; A2 old 4.8x vs anti 2.5x;
A3 old 38x vs anti 6.7x. (n4k4: random 0.0119; A2 old 6.5x vs anti 3.4x; A3 old 42x vs
anti 14x.)

## What the numbers show (direct readings)

- At A2 and A3 the anti-leak generator's residual median was higher than the old
  generator's at both tiers (n5k4 A2 24.5->45.5, A3 3->17; n4k4 A2 13->25, A3 2->6), and
  it was strictly higher than the old pick in 80-85% of trials at A2 and 60-85% at A3
  (the n4k4 A3 interval [0.36, 0.81] includes 0.5).
- The clearest genuine reduction in correlation leak was at A3 (two stolen neighbors):
  the anti-leak puzzles lost ~1.7 fewer bits (n5k4) / ~0.9 fewer bits (n4k4) going from A0
  to A3. At A2 the relative loss was similar to the old generator, so the A2 residual lift
  was largely from a larger A0 starting point.
- Anti-leak reduced the gap to the random ceiling but did not close it: at A3 its one-shot
  success was ~7x (n5k4) / ~14x (n4k4) the random factor's, versus ~38-42x for the old
  generator. The independent random factor remained the lowest one-shot success at every
  access level under theft.
- A4 matched A2 (one revealed neighbor); A7 matched A0 (a near-miss solver does not reduce
  the residual). Both improved with the anti-leak selection in step with A2 / A0.

## Claim (exact scope -- do not overstate)

```text
Under this attack set, at n=5,k=4 and n=4,k=4, with 20 trials and pool 60, and with the
random secret held as the lock: an anti-leak selection generator kept the target's median
residual higher than the old A0-only generator under one and two stolen neighbors (A2, A3),
strictly higher in a majority of trials (80-85% at A2; 60-85% at A3). Measured as bits lost
from A0, the generator's clearest genuine effect was at A3 (it retained ~0.9-1.7 more bits
under two-neighbor theft). It reduced but did not close the gap to a matched independent
random factor, whose residual does not move under theft.

This does NOT claim the spatial generator beats random, nor that it is leak-free. It
reports that, in this configuration, spatial correlation was made measurably less leaky
under neighbor compromise than the previous generator -- the milestone for this step.
```

## Caveats

```text
- The anti-leak generator also raises A0 residual; the A2 lift is largely a larger starting
  point (similar bits-lost). The bits-lost reading isolates the genuine A3 effect.
- "old spatial" = first A0-acceptable pool candidate; "anti-leak" = max-bottleneck pool
  candidate. Both drawn from the same pool, so the comparison is selection, not a new
  geometry primitive. A larger pool would raise the anti-leak pick further (and the cost).
- n4k4 two-neighbor theft leaves only two pieces' worth of cells, so A3 residual is small
  for both generators (old median 2); the anti-leak lift there is real but on small counts.
- random_plus is matched to the anti-leak A0 residual; it is a reference ceiling, not a
  per-generator control. The direct comparison is anti-leak vs old (same pool).
- 20 trials per tier; Clopper-Pearson intervals are wide. Exact enumeration only (k=4).
- Sealing/secret hygiene as in the prior docs; this experiment runs in-process.
```

## Reproduce

```text
uv run --extra dev --extra solvers pytest tests/test_anti_leak_generator.py
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.anti_leak_experiment --tier both
```
