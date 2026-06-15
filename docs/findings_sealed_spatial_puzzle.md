# Finding: do hidden adversarial 3D spatial puzzles add attacker cost over a random secret?

Status: internal finding (not a paper). Measurements only. Follows
`docs/findings_spatial_structure_hardness.md`, which used *published* connector /
topology signatures and found 3D structure only lowered attacker cost. This run
builds the strongest spatial design the plan allows — an **adversarial generator**
that hides connectors/topology and publishes only lossy projections, four solver
paradigms that must agree, a leakage meter, a one-shot destruction model, and a
process-level sealed runtime — and measures the same question under partial
compromise and one-shot.

Question: holding the commitment fixed and matching entropy, does an adversarially
generated 3D polycube puzzle with hidden constraints make recovering a hidden agent
secret harder than a structureless random secret? The honesty frame (carried from
the plan): a random secret is the **residual-entropy ceiling** — structure can only
remove consistent completions, so `residual_spatial(O) <= residual_random(O)` at
matched entropy; offline cost ~ residual count; one-shot success prob ~ 1/residual.

Built in `src/spatial_swarm/spatial_puzzle/` (commit `d6fe01baa7`). Run:
`--experiment all --n 3 --k 4 --seeds 20`
(`runs/2026-06-15T09-28-34.138133Z`, EXACT/enumerable tier).
`positive_controls.valid = True` (planted instances every solver must solve).

## Method

- One shared boolean model per cell of `region = target − revealed`, `Σx_c = k`,
  6-connectivity, lossy-clue constraints; the SHA-256 commitment is the floor no
  solver shortcuts. Solvers prune geometry + clues; the residual after that is what
  the attacker faces.
- Four solver paradigms (pure-Python ESU enumeration, OR-Tools CP-SAT, PySAT,
  Z3/SMT) run the same instance; a count is reported only when `exhausted and not
  budget_hit`, and the bake-off requires all four to agree.
- The generator publishes only commitments plus lossy projections (connector
  histogram, coarse topology band, neighbors); no public field is injective on a
  piece. `rejection.py` rejects any puzzle whose residual collapses below the
  ambiguity target, whose single clue uniquely IDs a piece, or that a neighbor copy
  / fast solver opens.
- One-shot recovery probabilities use Clopper-Pearson 95% intervals over 4000 trials.

## Adversarial generator yield

20 seeds, `ambiguity_target = 4`, up to 80 generation attempts per seed:

| metric | value |
| --- | ---: |
| accepted puzzles | 1 / 20 (5%) |
| median accepted residual | 4 |

Rejection reasons (cumulative across all attempts):

```text
residual_collapse        1577   (residual fell below the ambiguity target)
unique_by_connector_only 1164   (connector projection alone pinned the piece)
congruence_leak          1145   (a neighbor piece is congruent -> neighbor-copy opens it)
unique_by_topology_only    39   (topology band alone pinned the piece)
```

Most generated puzzles were rejected because a single published projection, or a
congruent neighbor, reduced the residual to 1 — i.e. leaked the piece. Keeping a
puzzle ambiguous (residual ≥ 4) without any clue identifying it was rare (5%).

## Leakage ladder vs the random ceiling

20 seeds. Random ceiling = a random secret at matched entropy (its residual is
unchanged by spatial clues). `delta_below_random_ceiling_bits` = bits the
observation removes relative to that ceiling.

| observation level | residual (median) | one-shot prob | bits below ceiling |
| --- | ---: | ---: | ---: |
| O1 outer shape (= random ceiling) | 28.5 | 0.035 | 0.00 |
| O3 one neighbor revealed | 5.5 | 0.182 | 2.37 |
| O4 all neighbors revealed | 1.0 | 1.000 | 4.83 |
| O7 connector hint | 1.0 | 1.000 | 4.83 |
| O8 topology hint | 7.0 | 0.143 | 2.03 |
| O7+O8 both hints | 1.0 | 1.000 | 4.83 |
| O10 one stolen sidecar | 1.0 | 1.000 | 4.83 |

No observation level had a residual **above** the random ceiling. Every published
spatial clue (connector hint, topology hint, neighbor, stolen sidecar) moved the
residual at or below it; the connector hint and a single stolen sidecar each
collapsed it to 1.

## One-shot recovery (4000 trials, Clopper-Pearson 95%)

| secret | residual | recovery rate | 95% CI | analytic 1/R |
| --- | ---: | ---: | --- | ---: |
| random ceiling | 32 | 0.0298 | [0.0247, 0.0355] | 0.0313 |
| spatial, after a clue is published | 1 | 1.0000 | [0.9991, 1.0] | 1.0000 |

Under one-shot destruction, the random secret left the attacker at ~3% per-attempt
success; once any spatial clue was published the residual was 1, so recovery was
certain. The max-entropy random secret was the safer one-shot design here.

## Partial compromise (residual as sidecars are stolen)

20 seeds:

```text
0 revealed              35.0
1 revealed               8.5
1 revealed + hints       1.0
all revealed             1.0
```

Residual shrank monotonically as neighbor pieces were stolen; one neighbor plus the
published hints reduced it to a single candidate.

## Solver bake-off (commitment is the floor)

Seed 7, no clues beyond outer shape, 20s / 5M-node budget:

| solver | residual | nodes | wall |
| --- | ---: | ---: | ---: |
| pure_enum (ESU) | 52 | 52 | 0.001s |
| CP-SAT | 52 | 495 | 0.002s |
| SAT (PySAT) | 52 | 495 | 0.001s |
| SMT (Z3) | 52 | 495 | 0.002s |

All four paradigms agreed on residual = 52 (`all_agree_on_residual = True`). The
node gap (52 vs 495) is enumeration order — ESU walks only connected subsets; the
external solvers enumerate all C(12,4) = 495 k-subsets and filter — not a residual
difference. No solver returned fewer than 52: none shortcut the commitment.

## What the numbers show (direct readings)

- The adversarial generator accepted 5% of attempts; 95% were rejected because a
  single lossy projection or a congruent neighbor pinned the piece.
- Across the leakage ladder, no spatial observation level produced a residual above
  the matched random ceiling; published clues moved it to or below the ceiling.
- Under one-shot, the random secret gave the attacker ~3% per-attempt success; the
  spatial secret after any published clue gave 100% (residual 1).
- Four independent solver paradigms agreed on the residual; none recovered below it,
  so the measured residual is the commitment floor, not a solver artifact.
- In this run, hidden adversarial 3D structure did not raise attacker cost above the
  matched random secret; once any clue was published it lowered it.

## Caveats

```text
- Residual-entropy ceiling: structure can only remove consistent completions, so
  spatial residual <= random residual at matched entropy by construction. This run
  measures the gap; it does not (and cannot) show spatial above random.
- Residuals are conditional on "accepted by this generator" (5% yield); the
  acceptance rate and rejection histogram are reported so the conditioning is visible.
- EXACT tier only (n=3, k=4): solver node/time costs are not complexity lower bounds.
  The credibility is the four-paradigm agreement on exhausted counts, not the budgets.
- Sealing is process-level: restricted op allowlist, zeroization, no-retry, redacted
  logs. attestation is a stub (`sgx=False`); this machine is arm64 macOS with no SGX.
  None of this defends a compromised host; sealed memory + remote attestation need
  the deferred cloud-SGX runbook (`enclave/cloud_sgx_runbook.md`).
- A non-destructive fit/no-fit oracle would defeat one-shot regardless of residual;
  the one-shot model assumes a wrong proof destroys the swarm with no retry.
- An LLM attacker was not run (no model endpoint); the hook records status=not_run.
```

## Reproduce

```text
uv run --extra dev --extra solvers pytest tests/test_puzzle_*.py
uv run python -m spatial_swarm.spatial_puzzle.experiments.cli --experiment all --n 3 --k 4 --seeds 20
```
