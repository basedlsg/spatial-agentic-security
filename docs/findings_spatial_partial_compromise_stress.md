# Finding: 3D spatial structure under partial compromise + one-shot destruction

Status: internal finding (not a paper). Measurements only. Separate experiment layer;
the UCOG protocol (commitment/signature/encryption) is unchanged. Follows the lock-role
and detector-role findings (`findings_sealed_spatial_puzzle.md`,
`findings_spatial_detector.md`).

## Question

The random secret is the lock in every arm. Layered on top is a SECOND FACTOR. Does a
hidden 3D **spatial** second factor make partial compromise harder to use — before a
one-shot system destroys itself — than a **random** second factor of matched entropy?
Both the hypothesis (3D adds cost) and the null (it does not) are reported; neither is
favored.

## Method

Three arms at matched second-factor entropy, all keeping a random lock:

```text
random_only : no second factor (lock-only sanity)
random_plus : matched-entropy RANDOM second factor (independent of other agents)
spatial     : matched-entropy hidden-3D SPATIAL second factor (System B)
```

The lock is assumed to hold under every access level A0..A8 (none give the target's own
secret), so the measured quantity is the SECOND FACTOR's residual / one-shot success
under partial compromise. For the spatial factor the residual is the number of connected
k-subsets of the target's outer shape minus any stolen-neighbor cells (hidden
connectors/topology are never published — they only let the generator reject weak
puzzles). For the random factor the residual is the full matched space (stolen neighbors
of an independent secret reveal nothing). Six experiments: E1 partial-compromise matrix
(A0..A8), E2 one-shot (strikes=1) vs limited-retry (strikes=5), E3 silent vs verbose
response, E4 generation-time hygiene, E5 solver bake-off, E6 scaling tiers. Every rate
carries a Clopper-Pearson 95% interval; eight positive controls gate the run; secrets are
scanned out of all artifacts.

## Exact configs, controls, hygiene

```text
code commit : b38e2d6e88   (run produced under this code; worktree_dirty: true at run time)
tiers       : tiny  n=3 k=4  seeds=30  exact (budget 10s/3M)
              medium n=4 k=8 seeds=30  budgeted (per-seed 2s/500k; bake-off 20s/5M)
              large  n=5 k=10 seeds=10 budgeted (per-seed 2s/500k; bake-off 30s/8M)
positive_controls.valid : True (all 8)
planted_secret_control  : detected (4 markers)
redaction               : clean (secret_markers_found = 0, extended marker set)
sealed_runtime          : process ; tee_attestation = false ; sgx = false ;
                          wrong_proof_destroyed = true ; second_attempt_denied = true
generation_failures     : 0 at every tier
```

## E1 — second-factor one-shot success under partial compromise

Spatial = median over seeds of `1/residual`; random_plus = `2^-bits` (constant; the
independent factor's residual does not change with stolen neighbors). `enum_rate` = the
fraction of seeds whose spatial residual was exactly enumerated within budget.

tiny (n=3,k=4; spatial 4.46 bits, random_plus 5.13 bits; enum_rate 1.0 all levels):

| access level | spatial residual (med) | spatial one-shot | random_plus one-shot |
| --- | ---: | ---: | ---: |
| A0_public_only | 30.5 | 0.0328 | 0.0286 |
| A1_old_transcripts | 30.5 | 0.0328 | 0.0286 |
| A2_one_stolen_neighbor | 7.0 | 0.143 | 0.0286 |
| A3_two_stolen_neighbors | 1.0 | 1.000 | 0.0286 |
| A4_one_stolen_sidecar_non_target | 7.0 | 0.143 | 0.0286 |
| A5_partial_gateway_snapshot | 30.5 | 0.0328 | 0.0286 |
| A6_artifact_directory | 30.5 | 0.0328 | 0.0286 |
| A7_solver_generated_near_miss | 30.5 | 0.0328 | 0.0286 |
| A8_llm_or_vision_candidate | not_run | not_run | not_run |

medium (n=4,k=8; spatial 12.12 bits, random_plus 12.65 bits; enum_rate 1.0):

| access level | spatial residual (med) | spatial one-shot | random_plus one-shot |
| --- | ---: | ---: | ---: |
| A0 / A1 / A5 / A6 / A7 | 5685.5 | 1.76e-4 | 1.55e-4 |
| A2 / A4 (one neighbor) | 351.0 | 2.86e-3 | 1.55e-4 |
| A3 (two neighbors) | 45.0 | 2.22e-2 | 1.55e-4 |

large (n=5,k=10; spatial 16.96 bits, random_plus 17.50 bits; A0 enum_rate 0.5, A2/A3 1.0):

| access level | spatial residual (med) | spatial one-shot | random_plus one-shot |
| --- | ---: | ---: | ---: |
| A0 / A1 / A5 / A6 / A7 | 127658 | 7.83e-6 | 5.41e-6 |
| A2 / A4 (one neighbor) | 12895 | 7.76e-5 | 5.41e-6 |
| A3 (two neighbors) | 3961 | 2.91e-4 | 5.41e-6 |

## E2 — one-shot vs limited retries (tiny tier; exact)

`retry_sys` = fraction of seeds where the residual is ≤ 5 (recoverable by systematic
candidate-elimination within strikes=5). one-shot = median `1/residual`.

| access level | spatial residual (med) | one-shot recovery | retry(5) recovery |
| --- | ---: | ---: | ---: |
| A0 / A5 / A6 / A7 | 30.5 | 0.033 | 0.00 |
| A2 / A4 (one neighbor) | 7.0 | 0.143 | 0.43 |
| A3 (two neighbors) | 1.0 | 1.000 | 1.00 |

## E3 — silent vs verbose response (tiny tier; exact)

```text
silent_reason_bits  : 0.0   (pass/fail only)
verbose_reason_bits : 2.0   (which of 4 checks failed)
verbose max leak    : 4.88 bits  (residual collapses 29.5 -> 1 when the reason is returned)
```

## E4 — generation-time hygiene (tiny tier; exact, 30 seeds)

```text
unfiltered weak-instance acceptance : 0/30 (0.00)   reasons over raw puzzles:
    residual_collapse 30 | solver_open_fast 30 | congruence_leak 23 | unique_by_connector_only 21
filtered (ambiguity>=4)             : accepted 1/30 (0.033), median 80 generation attempts
adversarially filtered (>=8 + fast-solver reject) : accepted 0/30 (0.00), median 80 attempts
```

## E5 — solver bake-off (pure_enum / CP-SAT / SAT / SMT)

```text
tiny   : all_agree = True, residual = 52
medium : all_agree = True, residual = 6594
large  : all_agree = True, residual = 144143
```

## Attack classes (tiny tier; sealed silent tripwire)

13 of 15 classes caught at rate 1.00 (commitment floor); only `legit_true_piece` and
`solver_opening_guess` (a commitment-opening guess) release. The two probe classes and
`repeated_adaptive_probe` submit a wrong piece and are caught. No access level A0..A8
breaks the actual lock.

## What the numbers show (direct readings)

- At A0 (no stolen neighbors), the spatial factor's one-shot success is within ~1.1x of
  the matched random factor at every tier (tiny 0.0328 vs 0.0286; medium 1.76e-4 vs
  1.55e-4; large 7.83e-6 vs 5.41e-6). With no partial compromise, the spatial factor did
  not add measurable advantage over a matched random factor in this configuration.
- Under stolen neighbors (A2/A3/A4) the spatial residual collapsed and its one-shot
  success rose well above the flat random baseline at every tier (tiny A3 1.00 vs 0.0286;
  medium A3 0.0222 vs 1.55e-4; large A3 2.91e-4 vs 5.41e-6). The random factor was
  unchanged. In this configuration the spatial factor made partial compromise easier to
  use, not harder, on the residual / one-shot axis.
- Old transcripts (A1), gateway snapshot (A5), artifact directory (A6), and
  solver-generated near-miss (A7) left the spatial residual at the A0 value: they did not
  reduce it below the no-compromise level here.
- One-shot destruction capped per-attempt success at 1/residual; limited retries (5) let
  the collapsed residual be recovered by systematic elimination (retry 0.43 at A2, 1.00 at
  A3). One-shot contained, but did not remove, the partial-compromise leakage.
- A verbose response that named the failed geometric check collapsed the residual to 1
  (~4.88 bits); a silent response leaked 0 beyond pass/fail.
- Generation-time filtering rejected essentially all raw n=3,k=4 puzzles (residual
  collapse / fast-solver open / congruence / single-clue uniqueness); accepted yield was
  ~3% (standard) and ~0% (adversarial). The filter did reject weak instances; at this tier
  few puzzles met the bar.
- Four solver paradigms agreed on the residual at every tier; the commitment caught every
  partial-compromise-derived forgery.

## Claim (exact scope -- do not overstate)

```text
Under this attack set, at these tiers, with these seeds, and with the random secret held
as the lock: a matched-entropy spatial second factor did NOT add one-shot resistance over
a matched random second factor at A0 (no compromise), and its residual / one-shot success
got worse than the random factor as neighbors were stolen (A2/A3/A4), the gap present at
every tier. One-shot destruction capped exploitation; limited retries enabled it. A
verbose geometric response leaked the secret; a silent response did not. Generation-time
filtering rejected weak instances before deployment.

This does NOT claim 3D is useless or secure. It reports that, in this configuration, the
spatial factor's only measured non-negative role was generation-time hygiene; under
partial compromise its correlated structure reduced the attacker's residual relative to an
independent random factor.
```

## Caveats

```text
- Integer-alphabet granularity at small k limits the entropy match to ~0.5-0.7 bits;
  random_plus carried slightly MORE entropy than spatial (a conservative baseline -- it
  makes the random factor look slightly safer, not the spatial factor).
- medium/large used a 2s per-seed budget; reported residuals are exact only where
  enum_rate indicates (1.0 medium; A0 0.5 / A2,A3 1.0 large). Where enum_rate < 1 the
  median is conditional on the enumerated seeds. No residual is claimed exact unless
  exhausted; budget stops are reported as "not solved within budget", never "hard".
- E2, E4, and the full attack matrix are exact-tier-only (they need enumeration); at the
  budgeted tiers they are recorded as skipped.
- large is n=10 seeds; Clopper-Pearson intervals are wide.
- Sealing is process-level (sgx=false, tee_attestation=false); not a TEE result.
- A8 (LLM/vision) recorded as not_run (no model endpoint).
```

## Reproduce

```text
uv run --extra dev --extra solvers pytest tests/test_partial_compromise_stress.py
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.partial_compromise_stress --tier all
```
