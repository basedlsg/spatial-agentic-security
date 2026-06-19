# Finding: 3D spatial structure under partial compromise + one-shot destruction

Status: internal finding (not a paper). Measurements only. Separate experiment layer;
the UCOG protocol (commitment/signature/encryption) is unchanged. Follows the lock-role
and detector-role findings (`findings_sealed_spatial_puzzle.md`,
`findings_spatial_detector.md`).

## Question

The random secret is the lock in every arm. Layered on top is a SECOND FACTOR. Does a
hidden 3D spatial second factor make partial compromise harder to use before a one-shot
system destroys itself than a random second factor of matched entropy? Both the
hypothesis (3D adds cost) and the null (it does not) are reported; neither is favored.

## Method

Three arms at matched second-factor entropy, all keeping a random lock:

```text
random_only : no second factor (lock-only sanity)
random_plus : matched-entropy RANDOM second factor (independent of other agents)
spatial     : matched-entropy hidden-3D SPATIAL second factor (System B)
```

The lock is assumed to hold under every access level A0..A8 (none give the target's own
secret), so the measured quantity is the second factor's residual / one-shot success
under partial compromise. For the spatial factor the residual is the number of connected
k-subsets of the target's outer shape minus any stolen-neighbor cells. Hidden
connectors/topology are never published; they only let the generator reject weak
puzzles. For the random factor the residual is the full matched space, because stolen
neighbors of an independent secret reveal nothing.

Six experiments run at every tier: E1 partial-compromise matrix (A0..A8), E2 one-shot
(strikes=1) vs limited-retry (strikes=5), E3 silent vs verbose response, E4
generation-time hygiene, E5 solver bake-off, and E6 scaling tiers. Every rate carries a
Clopper-Pearson 95% interval in the artifact. Eight positive controls gate the run.
Secrets are scanned out of all artifacts.

## Run, controls, hygiene

```text
run_dir     : runs/2026-06-19T15-01-50.092325Z
code commit : c54050c50aacc464014750c1a4f86523510eff72
worktree_dirty at run time : true
workers     : 8

tiers       : tiny   n=3 k=4  seeds=30 budget 10s/3M
              medium n=4 k=8  seeds=30 budget 20s/5M
              large  n=5 k=10 seeds=10 budget 30s/8M

positive_controls.valid : true (all 8)
planted_secret_control  : detected
redaction               : clean (secret_markers_found = 0)
digest                  : metrics.json.sha256 matches metrics.json
sealed_runtime          : process ; tee_attestation = false ; sgx = false ;
                          wrong_proof_destroyed = true ; second_attempt_denied = true
generation_failures     : 0 at every tier
```

All spatial residuals in E1/E2 enumerated at every tier and access level that ran
(enum_rate 1.0; budget_hit 0.0). A8 remains `not_run` because no LLM/vision endpoint is
part of this experiment.

## E1 - second-factor one-shot success under partial compromise

Spatial is the median over seeds of `1/residual`; random_plus is `2^-bits` and is
constant across access levels. A0, A1, A5, A6, and A7 share the same spatial residual in
this model; A2 and A4 share the one-neighbor residual.

| tier | spatial bits | random_plus bits | access | spatial residual med | spatial one-shot | random_plus one-shot |
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

Direct reading: at A0 the spatial factor is essentially matched to random_plus; under
stolen neighbors the spatial residual collapses while random_plus stays flat.

## E2 - one-shot vs limited retries

`retry_sys` is the fraction of seeds where residual <= 5 and a systematic
candidate-elimination attacker can recover within strikes=5. `retry_exp` is the median
random-order expected recovery `min(1, 5/residual)`.

| tier | access | residual med | one-shot | retry_sys | retry_exp | random_plus one-shot | enumerated seeds |
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

Direct reading: one-shot destruction caps exploitation at `1/residual`, but limited
retries convert collapsed residuals into much higher recovery probability. The effect is
strongest at A3 and remains visible at medium/large.

## E3 - silent vs verbose response

Silent responses return no reason bits beyond pass/fail. Verbose responses name which
hidden check failed (2 reason bits, four check classes) and become a fit/no-fit oracle.

| tier | shape-only residual med | residual after verbose reasons med | verbose max leak bits |
| --- | ---: | ---: | ---: |
| tiny | 29.5 | 1.0 | 4.88 |
| medium | 5490.0 | 1.0 | 12.42 |
| large | 155514 | 5 | 14.92 |

Direct reading: silent leaks 0 reason bits; verbose leaks grow with tier and collapse
the residual by 4.88, 12.42, and 14.92 bits in these runs.

## E4 - generation-time hygiene

Unfiltered is the raw-puzzle weak-instance acceptance rate. Filtered requires ambiguity
>=4. Adversarially filtered requires ambiguity >=8 and rejects if a fast solver opens
the target.

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

Direct reading: generation-time filtering is the spatial layer's useful role here. It
rejects weak instances before deployment, but stricter adversarial filtering has poor
yield at every tier.

## E5 - solver bake-off

| tier | residual | all solvers agree |
| --- | ---: | --- |
| tiny | 52 | true |
| medium | 6594 | true |
| large | 144143 | true |

The bake-off uses pure_enum, CP-SAT, SAT, and SMT. The external solvers are used as
cross-checks; pure_enum provides the exact residual count.

## Attack matrix - sealed silent tripwire

Every class was constructible for every seed (tiny 30/30, medium 30/30, large 10/10).
The only released classes are the legitimate true piece and a solver opening guess; both
open the commitment by construction. Every other partial-compromise-derived wrong piece
is caught at the commitment floor.

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

## What the numbers show

- At A0, spatial and matched random are effectively equal in one-shot success at larger
  tiers (large 5.43e-6 vs 5.41e-6). 3D did not add measurable residual advantage over
  a matched independent random factor.
- Under stolen neighbors (A2/A3/A4), the spatial residual collapses and the spatial
  one-shot success rises above the random baseline at every tier. At medium A3 the gap is
  2.22e-2 vs 1.55e-4; at large A3 it is 2.91e-4 vs 5.41e-6.
- Old transcripts (A1), gateway snapshot (A5), artifact directory (A6), and
  solver-generated near-miss (A7) leave the spatial residual at the A0 value in this
  model.
- One-shot destruction limits each attack to one draw from the residual. Retries make
  collapsed residuals exploitable: medium A3 has retry_sys 0.47 and retry_exp 0.111;
  large A3 has retry_sys 0.20 and retry_exp 0.00145.
- Verbose geometric failure reasons are unsafe. The measured leak grows with tier; silent
  response is the only safe runtime behavior measured here.
- Generation-time filtering can reject weak spatial instances, but it is not free:
  adversarial filtering accepted 0/30 at tiny, 0/30 at medium, and 1/10 at large.
- The sealed silent tripwire still catches every wrong attack class. The 3D detector
  adds no catch beyond commitment, but commitment prevents release unless the guess opens.

## Claim (exact scope - do not overstate)

```text
Under this attack set, at these tiers, with these seeds, and with the random secret held
as the lock: a matched-entropy spatial second factor did NOT add one-shot resistance over
a matched random second factor at A0. As neighbors were stolen (A2/A3/A4), the spatial
residual collapsed while the independent random factor stayed flat. One-shot destruction
capped exploitation; limited retries enabled it. A verbose geometric response leaked
substantial residual information; a silent response did not. Generation-time filtering
rejected weak instances before deployment.

This does NOT claim 3D is useless or secure. It reports that, in this configuration, the
spatial factor's only measured non-negative role was generation-time hygiene; under
partial compromise its correlated structure reduced the attacker's residual relative to
an independent random factor.
```

## Caveats

```text
- Integer-alphabet granularity at small k limits entropy matching; random_plus carried
  slightly more entropy than spatial (gap 0.53-0.67 bits). That is conservative for the
  random baseline.
- Large uses only 10 seeds; Clopper-Pearson intervals are wide even when point estimates
  are 0.0 or 1.0.
- All E1/E2 spatial residuals enumerated in this run. Future larger tiers should still
  report exactness explicitly; no residual should be called exact unless the solver
  exhausted without a budget hit.
- Sealing is process-level (sgx=false, tee_attestation=false); this is not a TEE result.
- A8 (LLM/vision) is `not_run` because no model endpoint is part of this harness.
- The run used 8 worker processes to make the all-tier measurement feasible. Work is
  seed-independent and aggregated in seed order; metrics are deterministic for the fixed
  seeds.
```

## Reproduce

```text
uv run --extra dev --extra solvers pytest tests/test_partial_compromise_stress.py
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.partial_compromise_stress --tier all
```
