# Spatial partial-compromise experiment deep dive

Status: internal analysis note. This is a long-form interpretation of the
partial-compromise experiment and its surrounding code, not a new experiment and not a
paper claim.

Primary result file:

- `docs/findings_spatial_partial_compromise_stress.md`

Primary run:

- `runs/2026-06-19T15-01-50.092325Z`

Primary harness:

- `src/spatial_swarm/spatial_puzzle/experiments/partial_compromise_stress.py`

## Executive summary

The latest all-tier partial-compromise run is strong enough to pause before building
more shared-object 3D mechanisms.

The measured story is consistent across the old lock-role experiment, the runtime
detector experiment, and the new partial-compromise experiment:

1. As a lock, 3D structure is worse than a high-entropy random secret, because public
   geometry gives an attacker structure to prune.
2. As a runtime detector, 3D adds no release/catch power beyond the commitment
   tripwire. If it reports detailed geometric failure reasons, it leaks.
3. Under partial compromise, shared-object 3D structure is correlated across agents.
   Stolen neighboring pieces shrink the target search region and collapse the target
   residual. An independent random second factor is immune to that specific leakage
   channel.
4. One-shot destruction is useful because it caps exploitation at one draw from the
   remaining residual. Limited retries make collapsed residuals exploitable.
5. The only measured non-negative role for the current spatial layer is
   generation-time hygiene: it can reject weak instances before deployment.

The critical distinction is this:

```text
The current spatial factor is one piece from a shared assembled object.
That makes neighboring pieces correlated by construction.
When a neighbor is stolen, the target candidate region shrinks by construction.
```

So the observed collapse is not just a bad random seed or an implementation accident.
It follows from the current representation: one shared outer object, partitioned into
connected per-agent pieces.

This does not prove that every possible "3D" design is dead. It does say the shared
assembly object should not be treated as a security hardening layer under neighbor
compromise. If spatial structure is kept, the next defensible fork is to make spatial
objects independent per agent, or keep 3D only as a generator/filtering/hygiene tool.

## What was being tested

The question was:

```text
Can a hidden 3D spatial second factor make partial compromise harder to use before a
one-shot system destroys itself than a random second factor of matched entropy?
```

The experiment deliberately keeps the random lock fixed. It does not replace the lock
with geometry. Instead, it layers a second factor on top of the lock and compares two
second-factor choices:

- `random_plus`: an independent random second factor with entropy matched to the spatial
  factor.
- `spatial`: a hidden-3D second factor, implemented as a connected piece from a shared
  voxel object.

The lock is assumed to hold under every access level. None of A0..A8 gives the attacker
the target's own random lock secret. The measured object is therefore the second
factor's residual under partial compromise.

The experiment is intentionally narrower than "is 3D useful?" It asks whether this
specific shared spatial second factor resists partial compromise better than an
independent random second factor at the same entropy scale.

## What was not being tested

The experiment does not test:

- A full production TEE deployment. The sealed runtime is process-level and reports
  `sgx=false`.
- A cryptographic break of SHA-256 commitments.
- LLM or vision candidate generation. A8 is recorded as `not_run`.
- Timing-channel indistinguishability. Silent mode means no reason bits, not equalized
  runtime.
- Independent per-agent spatial objects. The current spatial factor is shared-object
  only.
- Worst-case/easiest-target behavior across all pieces. The target is the sorted middle
  agent.
- Outer-shape-hidden variants. The PCS residual path assumes the attacker knows the
  full outer shape.

These exclusions matter because they define the exact scope of the result. The finding
is strong for the current design, but it should not be generalized into "all spatial
ideas are useless."

## Code map

Important PCS files:

| Area | File | Role |
| --- | --- | --- |
| Harness | `src/spatial_swarm/spatial_puzzle/experiments/partial_compromise_stress.py` | Runs E1..E6, writes artifacts, controls, digest, redaction |
| Arms | `src/spatial_swarm/spatial_puzzle/experiments/pcs_systems.py` | Builds `random_only`, `random_plus`, and `spatial` arms |
| Access levels | `src/spatial_swarm/spatial_puzzle/experiments/pcs_access.py` | Defines A0..A8 and computes residuals under each |
| Controls/redaction | `src/spatial_swarm/spatial_puzzle/experiments/pcs_metrics.py` | Positive controls, CIs, planted secret control, redaction |
| Generator | `src/spatial_swarm/spatial_puzzle/generators/build.py` | Builds hidden spatial solution and public views |
| Visibility | `src/spatial_swarm/spatial_puzzle/generators/visibility.py` | Defines `HiddenSolution`, `PublicView`, region and clue predicate |
| Rejection filtering | `src/spatial_swarm/spatial_puzzle/generators/rejection.py` | Rejects weak generated puzzles |
| Pure enumeration | `src/spatial_swarm/spatial_puzzle/solvers/pure_enum.py` | Counts connected k-subsets exactly when budget exhausts |
| Solver consumption | `src/spatial_swarm/spatial_puzzle/solvers/consume.py` | Applies clue predicate and commitment check |
| Detector | `src/spatial_swarm/spatial_puzzle/detector/geometric.py` | Geometry-layer detector and silent/verbose reason behavior |
| Baseline detector | `src/spatial_swarm/spatial_puzzle/detector/nongeometric.py` | Commitment-only tripwire |
| Attack classes | `src/spatial_swarm/spatial_puzzle/detector/attacks.py` | Constructs the 15 attack candidates |
| Failure policy | `src/spatial_swarm/spatial_puzzle/enclave/failure_policy.py` | One-shot and limited-retry lifecycle |
| Sealed service | `src/spatial_swarm/spatial_puzzle/enclave/service.py` | In-process sealed service |
| Entropy | `src/spatial_swarm/spatial_lab/entropy.py` | `log2 C(n,k)` and random alphabet matching |
| Representations | `src/spatial_swarm/spatial_lab/representations.py` | R0..R4 representation ladder |
| Shape generation | `src/spatial_swarm/spatial_lab/shapes.py` | Shared connected object and partitioned pieces |

Important artifacts from the full run:

| Artifact | Meaning |
| --- | --- |
| `runs/2026-06-19T15-01-50.092325Z/metrics.json` | Main machine-readable result |
| `runs/2026-06-19T15-01-50.092325Z/generator_rejection_histogram.json` | E4 rejection reasons |
| `runs/2026-06-19T15-01-50.092325Z/solver_bakeoff.json` | E5 solver cross-check |
| `runs/2026-06-19T15-01-50.092325Z/confidence_intervals.json` | CI summaries |
| `runs/2026-06-19T15-01-50.092325Z/redaction.json` | Secret-marker scan |
| `runs/2026-06-19T15-01-50.092325Z/metrics.json.sha256` | Digest of main metrics |
| `runs/2026-06-19T15-01-50.092325Z/events.jsonl` | Stage completion events |
| `runs/2026-06-19T15-01-50.092325Z/git_commit.txt` | Code commit and dirty bit at runtime |

## Current spatial construction

The spatial arm is built as:

```text
one connected outer object of n*k voxels
partitioned into n connected k-voxel pieces
one piece assigned to each agent
the target agent is the sorted middle agent
the target commitment is SHA-256 over the exact target piece
```

The generator path is:

```text
build_hidden_solution(...)
  -> generate_partitioned(...)
     -> target: connected voxel object
     -> pieces: agent_id -> connected k-cell piece
  -> commitments: agent_id -> commit(swarm_id, agent_id, repr_name, piece)
```

The relevant property is that all pieces are subsets of the same `target` object.
Neighbors are not independent samples. They are literal disjoint cells from the same
outer shape. Therefore, observing a neighbor reduces the cells available for the
unknown target.

This is why A2/A3 collapse the spatial residual.

## Current random-plus construction

The random-plus arm is not spatial. It is an independent random second factor using the
R0 representation:

```text
piece = k distinct integers drawn from alphabet size M
M = smallest alphabet such that log2 C(M,k) >= spatial_bits
```

The random-plus factor is deliberately independent across agents. Stolen neighboring
random factors reveal nothing about the target random factor.

Because `M` is an integer, entropy matching rounds upward. The random-plus arm carries
slightly more entropy than spatial:

| tier | spatial bits | random_plus bits | random advantage |
| --- | ---: | ---: | ---: |
| tiny | 4.4594 | 5.1293 | +0.6699 bits |
| medium | 12.1232 | 12.6517 | +0.5286 bits |
| large | 16.9619 | 17.4953 | +0.5333 bits |

This is conservative for the random baseline. It does not explain away the result, but
it should be kept in every caveat.

## Commitment model

The commitment is invariant across representations:

```text
commitment = SHA-256({
  kind,
  swarm_id,
  agent_id,
  repr,
  sorted_items
})
```

The commitment is the release floor. Runtime release requires a candidate to open the
commitment for the target agent. Geometry is layered around that check; it does not
replace it.

This matters because many experiment numbers are residual candidate counts, not counts
of commitment-opening candidates. In normal operation, only the true target piece opens
the target commitment.

## What "residual" means here

Residual is the number of attacker-consistent candidate second-factor pieces left after
public information is applied.

For spatial:

```text
residual = number of connected k-subsets
           of (outer_shape minus revealed_neighbor_cells)
           that satisfy any enabled public clue predicates
```

For E1/E2 PCS access levels, connector and topology clues are disabled:

```text
shape=True
revealed_count=A-level neighbor count
connector=False
topology=False
```

For random-plus:

```text
residual is the full matched random space
one-shot success = 2^-random_plus_bits
```

The experiment converts spatial residual to one-shot success as:

```text
one-shot success = 1 / residual
```

That models an attacker choosing one candidate from the consistent residual before the
one-shot destruction policy kills the swarm.

This is not the same as saying every residual candidate opens the commitment. The
commitment-opening candidate is still the true target piece. The residual is the
attacker's uncertainty set.

## Access levels A0..A8

The harness defines these access levels:

| Level | Description | Revealed neighbors | Runs |
| --- | --- | ---: | --- |
| A0 | public commitments and swarm metadata; no pieces | 0 | yes |
| A1 | old transcripts and proof metadata; no raw pieces | 0 | yes |
| A2 | one neighboring second-factor piece | 1 | yes |
| A3 | two neighboring second-factor pieces | 2 | yes |
| A4 | one full non-target sidecar | 1 | yes |
| A5 | verifier-visible state only; no secret/key | 0 | yes |
| A6 | run logs, metrics, redacted artifacts | 0 | yes |
| A7 | solver-generated near miss | 0 | yes |
| A8 | model-generated candidate | 0 | no, no endpoint |

In the current residual implementation:

- A0, A1, A5, A6, and A7 are equivalent for residual purposes.
- A2 and A4 are equivalent for residual purposes.
- A3 is the two-neighbor case.
- A8 is `not_run`.

The important implementation detail is that A2/A3 reveal raw neighboring pieces. They do
not reveal connector labels or topology in E1/E2. A4 is described as a full sidecar, but
in the PCS residual path it behaves as one raw non-target piece.

## Run configuration

The full completed run:

```text
run_dir     : runs/2026-06-19T15-01-50.092325Z
code commit : c54050c50aacc464014750c1a4f86523510eff72
dirty       : true at run time
workers     : 8
```

Tiers:

| tier | n | k | seeds | budget seconds | budget nodes |
| --- | ---: | ---: | ---: | ---: | ---: |
| tiny | 3 | 4 | 30 | 10 | 3,000,000 |
| medium | 4 | 8 | 30 | 20 | 5,000,000 |
| large | 5 | 10 | 10 | 30 | 8,000,000 |

Controls and hygiene:

| Check | Result |
| --- | --- |
| Positive controls | valid, all 8 passed |
| Planted secret control | detected |
| Redaction scan | clean |
| Secret markers found | 0 |
| Metrics digest | matched |
| Wrong proof destroyed | true |
| Second attempt denied | true |
| SGX | false |
| TEE attestation | false |
| Generation failures | 0 |

All E1/E2 spatial residuals enumerated at every tier and access level that ran:

```text
enum_rate = 1.0
budget_hit = 0.0
```

## Positive controls

The run is invalid unless all positive controls pass. The controls were:

1. True piece releases.
2. Wrong random piece blocks.
3. Commitment-opening candidate releases.
4. Verbose detector leaks reason bits on a wrong submission.
5. Silent detector leaks zero reason bits.
6. Solver solves a planted easy case.
7. Redaction scanner finds a planted secret.
8. One-shot destroy blocks a second attempt.

These controls passed in the full run.

## E1: partial-compromise residual and one-shot success

E1 is the core result. It asks how the spatial second-factor residual changes as the
attacker gets more partial compromise.

Spatial one-shot success is the median over seeds of `1 / residual`. Random-plus
one-shot success is `2^-bits`, constant across access levels.

| tier | spatial bits | random_plus bits | access | spatial residual median | spatial one-shot | random_plus one-shot |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| tiny | 4.46 | 5.13 | A0/A1/A5/A6/A7 | 30.5 | 3.28e-2 | 2.86e-2 |
| tiny | 4.46 | 5.13 | A2/A4 | 7.0 | 1.43e-1 | 2.86e-2 |
| tiny | 4.46 | 5.13 | A3 | 1.0 | 1.00 | 2.86e-2 |
| medium | 12.12 | 12.65 | A0/A1/A5/A6/A7 | 5685.5 | 1.76e-4 | 1.55e-4 |
| medium | 12.12 | 12.65 | A2/A4 | 351.0 | 2.86e-3 | 1.55e-4 |
| medium | 12.12 | 12.65 | A3 | 45.0 | 2.22e-2 | 1.55e-4 |
| large | 16.96 | 17.50 | A0/A1/A5/A6/A7 | 190700.0 | 5.43e-6 | 5.41e-6 |
| large | 16.96 | 17.50 | A2/A4 | 12895.0 | 7.76e-5 | 5.41e-6 |
| large | 16.96 | 17.50 | A3 | 3961.0 | 2.91e-4 | 5.41e-6 |

Interpretation:

- At A0, spatial and random-plus are effectively matched.
- At A2/A4, stealing one neighbor collapses spatial residual but leaves random-plus
  unchanged.
- At A3, stealing two neighbors collapses spatial residual much further.
- The result persists at medium and large, so it is not only a tiny-tier artifact.

The measured ratios make the collapse plain:

| tier | A0 residual | A2/A4 residual | A3 residual | A0 to A3 reduction |
| --- | ---: | ---: | ---: | ---: |
| tiny | 30.5 | 7.0 | 1.0 | 30.5x |
| medium | 5685.5 | 351.0 | 45.0 | 126.3x |
| large | 190700.0 | 12895.0 | 3961.0 | 48.1x |

The large tier still has a nontrivial A3 residual, but the one-shot success is still
about 54x worse than random-plus:

```text
large A3 spatial one-shot  = 2.91e-4
large random-plus one-shot = 5.41e-6
ratio                     ~= 53.8x
```

## E2: one-shot versus limited retries

E2 asks whether one-shot destruction actually matters once residuals collapse.

Definitions:

```text
one-shot = 1 / residual
retry_sys = fraction of seeds where residual <= 5
retry_exp = median min(1, 5 / residual)
```

`retry_sys` is a systematic-elimination attacker with 5 strikes. `retry_exp` is a
random-order expected recovery approximation with 5 strikes.

| tier | access | residual median | one-shot | retry_sys | retry_exp | random_plus one-shot | enumerated seeds |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| tiny | A0/A1/A5/A6/A7 | 30.5 | 3.28e-2 | 0.00 | 1.64e-1 | 2.86e-2 | 30 |
| tiny | A2/A4 | 7.0 | 1.43e-1 | 0.43 | 7.14e-1 | 2.86e-2 | 30 |
| tiny | A3 | 1.0 | 1.00 | 1.00 | 1.00 | 2.86e-2 | 30 |
| medium | A0/A1/A5/A6/A7 | 5685.5 | 1.76e-4 | 0.00 | 8.81e-4 | 1.55e-4 | 30 |
| medium | A2/A4 | 351.0 | 2.86e-3 | 0.07 | 1.43e-2 | 1.55e-4 | 30 |
| medium | A3 | 45.0 | 2.22e-2 | 0.47 | 1.11e-1 | 1.55e-4 | 30 |
| large | A0/A1/A5/A6/A7 | 190700.0 | 5.43e-6 | 0.00 | 2.71e-5 | 5.41e-6 | 10 |
| large | A2/A4 | 12895.0 | 7.76e-5 | 0.00 | 3.88e-4 | 5.41e-6 | 10 |
| large | A3 | 3961.0 | 2.91e-4 | 0.20 | 1.45e-3 | 5.41e-6 | 10 |

Interpretation:

- One-shot matters. It caps the attacker at `1/residual`.
- Retries make the collapsed residual operationally dangerous.
- Medium A3 is the clearest example: one-shot recovery is 2.22e-2, while five-strike
  expected recovery is 1.11e-1 and systematic recovery within 5 strikes is 0.47.
- Large A3 still shows retry sensitivity: systematic recovery within 5 strikes appears
  in 20% of the 10 seeds.

The runtime demonstration confirms the failure policy behavior:

| mode | queries to first flag | queries to shutdown | strikes |
| --- | ---: | ---: | ---: |
| one-shot | 1 | 1 | 1 |
| retry | 1 | 5 | 5 |

This is why the one-shot policy should be considered part of the defense. Without it,
the spatial residual collapse becomes much more exploitable.

## E3: silent versus verbose response

E3 asks whether the runtime geometric checks leak if they report detailed failure
reasons.

Silent mode:

```text
reason_bits = 0
response looks like the non-geometric tripwire
```

Verbose mode:

```text
reason_bits = log2(4) = 2
failure names one of:
  wrong_shape_membership
  wrong_connector_histogram
  wrong_topology_band
  wrong_proof_destroyed
```

Measured result:

| tier | shape-only residual median | residual after verbose reasons median | verbose max leak bits |
| --- | ---: | ---: | ---: |
| tiny | 29.5 | 1.0 | 4.88 |
| medium | 5490.0 | 1.0 | 12.42 |
| large | 155514 | 5 | 14.92 |

Interpretation:

- Silent mode leaks no measured reason bits.
- Verbose mode is unsafe. It becomes a fit/no-fit oracle over hidden geometry.
- The leak grows with tier because there is more candidate space to prune.
- Verbose reason vocabulary is only 2 bits per wrong response, but the induced pruning
  can collapse far more residual entropy across the candidate set.

Important caveat:

Silent mode was measured for reason-channel leakage, not timing leakage. Timing remains
an open leak surface.

## E4: generation-time hygiene

E4 asks whether the generator can reject weak spatial instances before deployment.

There are three modes:

| Mode | Meaning |
| --- | --- |
| unfiltered | Raw generated puzzle; measure whether it survives the rejection suite |
| filtered | Generate until ambiguity target >= 4 survives, max 80 attempts |
| adversarially_filtered | Ambiguity target >= 8 and reject if fast solver opens target |

Acceptance results:

| tier | unfiltered accepted | filtered accepted | filtered median attempts | adversarial accepted | adversarial median attempts |
| --- | ---: | ---: | ---: | ---: | ---: |
| tiny | 0/30 (0.00) | 1/30 (0.03) | 80.0 | 0/30 (0.00) | 80.0 |
| medium | 1/30 (0.03) | 28/30 (0.93) | 26.0 | 0/30 (0.00) | 80.0 |
| large | 1/10 (0.10) | 5/10 (0.50) | 74.5 | 1/10 (0.10) | 80.0 |

Main rejection reasons:

| tier | unfiltered reasons | filtered reasons | adversarial reasons |
| --- | --- | --- | --- |
| tiny | residual_collapse 30; solver_open_fast 30; congruence_leak 23; unique_by_connector_only 21 | residual_collapse 2321; unique_by_connector_only 1693; congruence_leak 1677 | residual_collapse 2400; solver_open_fast 2400; unique_by_connector_only 1740; congruence_leak 1730 |
| medium | residual_collapse 28; solver_open_fast 29; unique_by_connector_only 10; congruence_leak 6 | residual_collapse 841; unique_by_connector_only 425; congruence_leak 75 | residual_collapse 2391; solver_open_fast 2097; unique_by_connector_only 1136 |
| large | residual_collapse 9; solver_open_fast 4; unique_by_connector_only 3 | residual_collapse 602; unique_by_connector_only 25; congruence_leak 13 | residual_collapse 768; solver_open_fast 257; unique_by_connector_only 28 |

Interpretation:

- Generation filtering can be useful.
- Filtering is not free.
- Strict adversarial filtering has poor yield at every tier.
- The dominant failure mode is residual collapse, exactly the weakness the experiment
  is investigating.

The generator currently generates shapes and rejects weak ones. It does not directly
optimize for A2/A3 residual.

That distinction matters. A better generator could improve yield and may raise the
spatial residual, but it cannot remove the basic correlation that comes from shared
object partitioning unless the representation changes.

## E5: solver bake-off

E5 cross-checks the residual counting path.

| tier | residual | all solvers agree |
| --- | ---: | --- |
| tiny | 52 | true |
| medium | 6594 | true |
| large | 144143 | true |

Solvers:

- pure enum
- CP-SAT
- SAT
- SMT

The pure enumerator is the exact source when it exhausts without a budget hit. The
external solvers are cross-checks. In the recorded bake-off, all agree where counts are
available.

## Attack matrix: sealed silent tripwire

The attack matrix feeds one constructed candidate per attack class into the sealed
silent tripwire. The detector is non-geometric for the matrix; it measures the
commitment floor.

Every class was constructible for every seed:

```text
tiny   30/30
medium 30/30
large  10/10
```

Only two classes release:

```text
legit_true_piece
solver_opening_guess
```

Both are expected to release because they open the commitment.

Every wrong class was caught at every tier:

| attack class | released expected | tiny release/catch | medium release/catch | large release/catch |
| --- | --- | ---: | ---: | ---: |
| artifact_directory_forgery | false | 0.00 / 1.00 | 0.00 / 1.00 | 0.00 / 1.00 |
| congruent_shape | false | 0.00 / 1.00 | 0.00 / 1.00 | 0.00 / 1.00 |
| decoy_consistent_wrong | false | 0.00 / 1.00 | 0.00 / 1.00 | 0.00 / 1.00 |
| legit_true_piece | true | 1.00 / 0.00 | 1.00 / 0.00 | 1.00 / 0.00 |
| old_transcript_replay | false | 0.00 / 1.00 | 0.00 / 1.00 | 0.00 / 1.00 |
| one_stolen_sidecar_non_target | false | 0.00 / 1.00 | 0.00 / 1.00 | 0.00 / 1.00 |
| partial_gateway_snapshot_forgery | false | 0.00 / 1.00 | 0.00 / 1.00 | 0.00 / 1.00 |
| random_wrong_piece | false | 0.00 / 1.00 | 0.00 / 1.00 | 0.00 / 1.00 |
| repeated_adaptive_probe | false | 0.00 / 1.00 | 0.00 / 1.00 | 0.00 / 1.00 |
| silent_fit_no_fit_probe | false | 0.00 / 1.00 | 0.00 / 1.00 | 0.00 / 1.00 |
| solver_near_miss | false | 0.00 / 1.00 | 0.00 / 1.00 | 0.00 / 1.00 |
| solver_opening_guess | true | 1.00 / 0.00 | 1.00 / 0.00 | 1.00 / 0.00 |
| stolen_neighbor | false | 0.00 / 1.00 | 0.00 / 1.00 | 0.00 / 1.00 |
| two_stolen_neighbors | false | 0.00 / 1.00 | 0.00 / 1.00 | 0.00 / 1.00 |
| verbose_fit_no_fit_probe | false | 0.00 / 1.00 | 0.00 / 1.00 | 0.00 / 1.00 |

Interpretation:

- The commitment tripwire works.
- Runtime geometry does not improve release/catch in this harness.
- Geometry can add attribution or filtering ideas, but it does not replace the
  commitment floor.

## Why the collapse appears structural

The collapse follows from three implementation facts:

1. The target piece and neighbor pieces are disjoint subsets of one shared object.
2. The attacker is assumed to know the full outer shape in PCS.
3. A stolen neighbor reveals raw cells from that same object.

Then the target candidate region becomes:

```text
region = outer_shape - revealed_neighbor_cells
```

That is enough to force monotone residual shrinkage:

```text
A0 region size > A2 region size > A3 region size
```

The test suite encodes this as an invariant:

```text
A0 residual >= A2 residual >= A3 residual
```

This means the PCS result is not surprising once the representation is understood. The
experiment's value is that it quantifies the collapse, checks it at multiple tiers, and
compares it against a matched independent random factor.

## What is generator-specific versus structural

Structural:

- Pieces share one object.
- Neighbor pieces are correlated with the target.
- Revealing a neighbor removes cells from the target candidate region.
- Independent random factors do not have this leakage channel.

Generator-specific:

- Exact median residual values.
- Frequency of weak instances.
- Congruence leak rate.
- Unique connector/topology clue frequency.
- Adversarial filtering yield.
- How much A2/A3 can be improved by better search or optimization.

So a better generator could improve numbers. It could raise A2/A3 residual and reject
more bad cases. But as long as the design remains "shared object partitioned into
per-agent pieces," stolen neighbors will carry structural information about the target.

## Interpretation of `solver_opening_guess`

`solver_opening_guess` is not a wrong attack class. It is an idealized solver recovery
of the true target piece from the commitment search.

That class releases because it opens the commitment. It represents:

```text
the attacker found the true second factor
```

It should not be interpreted as the geometric detector failing to catch a wrong shape.
It is a positive opening case, like `legit_true_piece`.

## One-shot responsibility

One-shot destruction is tied to commitment failure.

The lifecycle behavior is:

```text
if candidate opens commitment:
    release
else:
    block
    increment wrong_count
    if one_shot and wrong_count >= strikes:
        state = dead
        wipe sidecars
        zeroize
```

This means the commitment check is the meaningful runtime gate. The spatial detector
can run checks and can report reasons, but it does not control release independently of
the commitment.

That explains the detector result:

```text
runtime 3D adds no catch beyond commitment
verbose runtime 3D leaks more than commitment
silent runtime 3D behaves like commitment-only
```

## Outer shape assumption

PCS assumes full outer shape is public for residual measurement.

This is stronger than the sealed service default, where `expose_outer_shape=False`.

That distinction matters:

- PCS is a conservative, shape-known attacker model.
- A deployment that hides outer shape may have a larger public residual.
- The current PCS result still says: if outer shape is known and neighbor pieces are
  stolen, shared-object spatial residual collapses.

Unmeasured variants worth separating later:

| Variant | Expected effect |
| --- | --- |
| Full outer shape known | Current PCS |
| Coarse bounding box only | Likely larger residual than PCS |
| Local neighborhood only | Possibly larger residual, depends on leak model |
| No global outer shape | Different experiment; may reduce spatial pruning |

## Timing caveat

Silent mode currently means:

```text
reason_bits = 0
opaque failure reason
same response vocabulary as baseline
```

It does not prove:

```text
equal execution time
equal failure-stage timing
equal resource usage
equal network-visible behavior
```

A real runtime deployment would need a timing indistinguishability check for at least:

- wrong commitment
- wrong shape membership
- wrong connector histogram
- wrong topology band
- stale transcript
- stolen neighbor submission
- near miss

That timing study has not been run in PCS.

## Relationship to earlier findings

This result fits the previous findings rather than contradicting them.

### Lock-role finding

Earlier result:

```text
3D as the lock performs worse than a high-entropy random secret.
Public spatial structure gives attackers a smaller residual than random.
```

PCS keeps the random lock and tests 3D only as a second factor. The same theme appears:
spatial structure creates exploitable correlation under observation.

### Runtime-detector finding

Earlier result:

```text
3D as a detector adds no catch beyond a plain commitment tripwire.
Verbose failure reasons leak.
```

PCS repeats that lesson under partial compromise:

- sealed silent tripwire catches wrong classes
- verbose reason channel collapses residual
- runtime geometry has no measured release/catch advantage

### Anti-leak generator finding

Earlier result:

```text
Selecting partitions that stay ambiguous under stolen neighbors improves residual.
It does not reach the random ceiling.
```

PCS supports this role assignment:

- generation-time filtering is useful
- runtime geometry is not useful as a security gate
- shared-object correlation remains the core weakness

## Current claim, exact scope

The strongest accurate claim is:

```text
Under this attack set, at these tiers, with these seeds, with a random secret still held
as the lock, and with the attacker knowing the full outer shape: a matched-entropy
spatial second factor built as a shared-object piece did not add one-shot resistance over
a matched independent random second factor at A0. Under stolen-neighbor access, the
spatial residual collapsed while the independent random factor stayed flat. One-shot
destruction capped exploitation; limited retries enabled it. Verbose geometric failure
responses leaked substantial residual information; silent responses did not leak reason
bits. Generation-time filtering rejected weak instances before deployment, but strict
adversarial filtering had poor yield.
```

The claim should not be overstated as:

```text
all 3D is useless
all spatial factors are insecure
geometry can never help
outer-shape-hidden designs are equivalent
independent per-agent spatial factors are dead
```

Those are not measured.

## Practical conclusion

For the current shared-object design:

```text
Do not treat shared 3D assembly structure as a runtime hardening layer under partial
compromise.
```

The safe default remains:

```text
random independent lock or second factor
commitment tripwire
one-shot destruction
silent response
redacted artifacts
no verbose geometric reasons
```

3D can still have roles, but the roles should be narrowed:

- generation-time weak-instance rejection
- visualization
- decoy/honeypot attribution if carefully isolated
- maybe independent per-agent spatial puzzles, if measured separately

## Recommended pause decision

Pause building more shared-object spatial mechanisms until one of these is true:

1. A new generator directly optimizes A2/A3 residual and can approach the independent
   random ceiling with acceptable yield.
2. The design changes from shared-object pieces to independent per-agent spatial
   objects.
3. The product goal changes from security hardening to visualization, hygiene, or
   attribution.

Continuing to scale the existing shared-object design without changing the correlation
model is unlikely to reverse the main conclusion. It may improve constants, but the
neighbor-correlation channel remains.

## Best next experiment if work resumes

The most valuable next experiment is not "larger shared-object pool" first. It is a
design fork:

```text
shared-object spatial factor
vs
independent per-agent spatial factor
vs
matched independent random factor
```

The independent per-agent spatial design would look like:

```text
each agent has its own private spatial object
no global shared outer shape
no neighboring piece is a subset of the target object's cells
swarm passes only if required private objects verify
```

Expected property:

```text
stealing neighbor A's spatial package reveals little or nothing about target B's spatial
package, because the two are independently generated.
```

This keeps "3D" while removing the shared-object neighbor-correlation channel.

The experiment should report:

- A0, A2, A3 residuals for shared spatial, independent spatial, and random-plus.
- Entropy gaps for all arms.
- Easiest, median, hardest target pieces per generated swarm.
- Public residual, hidden-valid residual, and commitment-opening residual as separate
  metrics.
- Full outer shape known versus outer shape hidden variants.
- Silent reason-channel leakage and timing leakage.
- Generation yield under explicit A2/A3 optimization.

## Metrics to add before another full run

The current full run is adequate for the stated claim. If the work resumes, add these
before spending more time on large runs:

### Target sensitivity

Current target:

```text
sorted middle agent
```

Add:

```text
easiest target
median target
hardest target
random target
```

Report residual distributions per target, not only medians across seeds.

### Residual separation

Current residual conflates attacker-consistent candidate count with success probability
via `1/residual`.

Add explicit columns:

```text
public_residual
hidden_valid_residual
commitment_opening_residual
```

Expected:

```text
commitment_opening_residual ~= 1
public_residual >= hidden_valid_residual >= commitment_opening_residual
```

This would make the interpretation cleaner.

### Shape-knowledge variants

Current PCS:

```text
full outer shape known
```

Add:

```text
bounding box only
local neighborhood only
no outer shape
```

### Sidecar detail variants

Current A2/A3:

```text
raw neighboring piece cells
```

A4 label implies more than the residual currently uses. Split sidecar variants:

```text
raw cells only
raw cells + connector hint
raw cells + topology hint
raw cells + all sidecar metadata
commitment only
```

### Timing leakage

Add timing indistinguishability tests for silent mode:

```text
wrong commitment
wrong shape
wrong connector
wrong topology
stale transcript
stolen neighbor
near miss
```

### Generator objective

Current generator:

```text
generate then reject
```

Add direct optimization:

```text
maximize min residual after one neighbor stolen
maximize min residual after two neighbors stolen
minimize unique local signatures
minimize congruent neighbor openings
minimize fast solver openings
```

This would tell us whether the shared-object design has enough room to improve, or
whether the random ceiling remains unreachable.

## Ruled-out interpretations

Do not return to these without new evidence:

### "The old full run skipped medium/large, so the result may disappear"

This was fixed. E2, E3, E4, and the attack matrix now run at every tier. Medium and
large did enumerate in the full run.

### "The collapse is only tiny-tier behavior"

False in the current data. Medium and large both show A2/A3 collapse.

### "Runtime 3D catches attacks that commitment misses"

Not in this harness. The silent tripwire catches wrong classes at the commitment floor.
The only releases are true commitment openings.

### "Verbose geometry is harmless because it only returns a small reason vocabulary"

False in the current data. The reason channel has 2 bits per response, but it acts as an
oracle that collapses residual by much more than 2 bits across the candidate set.

### "Random-plus only wins because it has slightly more entropy"

Random-plus does have 0.53 to 0.67 extra bits from integer rounding. That is a caveat
and conservative baseline advantage. It does not explain the stolen-neighbor behavior,
because random-plus stays flat while spatial residual collapses by much larger factors.

### "Adversarial filtering solves the problem"

Not currently. It has poor yield:

```text
tiny   0/30
medium 0/30
large  1/10
```

## Reproduction commands

Focused PCS tests:

```bash
uv run --extra dev --extra solvers pytest tests/test_partial_compromise_stress.py
```

Full test suite:

```bash
uv run --extra dev --extra solvers pytest
```

Full PCS experiment:

```bash
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.partial_compromise_stress --tier all
```

Expected full-run runtime from the completed run was around 1 hour 25 minutes with 8
workers, mostly because large E4 has long-tail generation workers.

## Final takeaway

The result is not "3D cannot ever help." The result is sharper:

```text
Shared-object spatial structure is the wrong security primitive for partial compromise
when neighboring pieces can be stolen.
```

The shared object creates correlation. Partial compromise consumes that correlation.
Random independent factors do not have that channel.

The useful path is to either:

1. demote shared 3D to generation-time hygiene or visualization, or
2. test a genuinely different spatial design with independent per-agent objects.

Building more on the current shared-object runtime security story is not justified by
the data currently in the repo.
