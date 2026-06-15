# Finding: 3D geometry as a tamper-detector vs a non-geometric tripwire

Status: internal finding (not a paper). Measurements only. Follows the lock-role
findings (`docs/findings_sealed_spatial_puzzle.md`, `docs/findings_spatial_structure_hardness.md`,
which measured that a 3D puzzle is a worse *lock* than a random secret). Here the
random committed secret is held as the lock and 3D is tested in the *detector* role.
Mirrors the keystone method (`docs/findings_keystone_fair_baseline.md`) one level up:
there it was geometry vs a plain commitment gate as a lock; here it is geometry vs a
plain tripwire as a detector.

## Question

Holding the random committed secret as the lock, does a **geometric detector** catch
any attack a **non-geometric tripwire** misses, at equal-or-lower false-positive rate,
and without leaking more about the secret?

## Method

Two detectors with an identical interface, geometry the only variable; both make the
same release/catch decision via the commitment-backed `SwarmLifecycle` (geometry is
layered on, never replaces the commitment):

```text
nongeometric_tripwire : commitment pass/fail + a probe counter; reason carries no
                        candidate information (reason_bits = 0). The baseline.
geometric_detector    : the same, plus runtime shape-membership / connector-histogram
                        / topology-band checks, in two modes --
                        silent  (checks run, opaque reason, reason_bits = 0)
                        verbose (returns which check failed, reason_bits > 0)
                        and an optional decoy/honeypot histogram (attribution only).
```

One shared attack suite is fed to both (the same candidate per seed; the detector
never reads the attack label): `legit_true_piece`, `random_wrong_piece`,
`stolen_neighbor`, `congruent_shape`, `solver_opening_guess` (the commitment-opening
guess, included to show both detectors are equally blind), `decoy_consistent_wrong`,
and `repeated_adaptive_probe` (a sequence against a swarm with `strikes>1`). A strike
counter was added to the failure policy (`strikes` default 1 = the original one-shot)
so the repeated-probing axis is measurable rather than degenerate. Every rate is
reported with a Clopper-Pearson 95% interval; six positive controls gate the run.

## Result (commit `a85d131635`, Python 3.13.2, deterministic)

`--experiment detector_keystone --n 3 --k 4 --seeds 12`, `strikes_probe=5`.
`positive_controls.valid = True` (blindness, catch floor, no-false-positive, silent
reason isolation, attack-class blindness, enumerator trust).

Detection rate (caught = commitment-blocked or flagged), all 12 seeds constructible:

| attack class | nongeometric | geo silent | geo verbose | geo decoy |
| --- | ---: | ---: | ---: | ---: |
| legit_true_piece | 0.00 | 0.00 | 0.00 | 0.00 |
| random_wrong_piece | 1.00 | 1.00 | 1.00 | 1.00 |
| stolen_neighbor | 1.00 | 1.00 | 1.00 | 1.00 |
| congruent_shape | 1.00 | 1.00 | 1.00 | 1.00 |
| solver_opening_guess | 0.00 | 0.00 | 0.00 | 0.00 |
| decoy_consistent_wrong | 1.00 | 1.00 | 1.00 | 1.00 |

Detection is identical across all four detectors on every class. Every wrong piece is
caught by the commitment; `solver_opening_guess` (a guess that opens the commitment)
is released by all four — both detectors are equally blind to it.

False-positive rate (flagging legitimate traffic): 0.000 for every detector
(CI [0.000, 0.265] at n=12).

Repeated probing (`strikes=5`), nongeometric vs geometric_verbose:

| metric | nongeometric | geometric_verbose |
| --- | ---: | ---: |
| queries to first flag (p50) | 1.0 | 1.0 |
| queries to shutdown (p50) | 5.0 | 5.0 |

Both flag on the first wrong proof and shut down on the same strike; the geometric
detector does not detect earlier.

Detector leakage (bits the response reveals about the secret beyond pass/fail):

| detector | marginal reason bits | note |
| --- | ---: | --- |
| nongeometric | 0.0 | pass/fail only |
| geometric silent | 0.0 | opaque reason, identical to baseline |
| geometric verbose | see below | returns which geometric check failed |

For the verbose detector, returning which check failed reveals the secret's
connector/topology, collapsing the attacker's residual from the shape-only level to
the both-hints level: median residual **29.0 → 1.0**, a leak of **4.86 bits**;
one-shot recovery probability rises from **0.033 → 1.0**; a fit/no-fit oracle of this
kind recovers in **6** queries (≈ log2(residual) + 1).

Decoy/honeypot attribution (the `decoy_consistent` label, distinct from detection):

| signal | rate | 95% CI |
| --- | ---: | --- |
| attribution on decoy-consistent attacker pieces | 1.00 | [0.735, 1.0] |
| attribution on legitimate traffic | 0.00 | [0.0, 0.265] |

Roll-up: `geometry_marginal_detection_advantage_count = 0`,
`geometric_matches_nongeometric_on_all_attacks = True`,
`false_positive_delta = 0.0`, `geometry_marginal_leakage_bits = 4.86`.

## Claim (exact scope -- do not overstate)

```text
On the implemented attack set, under the commitment-backed failure policy, at n=3 k=4
over 12 seeds: the geometric detector made the identical release/catch decision as the
non-geometric tripwire on every attack class (marginal detection advantage 0), and
did not flag legitimate traffic (false-positive delta 0). The only measured runtime
difference was leakage: a geometric detector that returns which check failed (verbose)
revealed the secret's connector/topology, collapsing the residual 29.0 -> 1.0 (~4.86
bits) and raising one-shot recovery 0.033 -> 1.0; a detector that runs the same checks
but returns an opaque reason (silent) leaked 0. A decoy/honeypot produced an
attribution label that fired on decoy-consistent attacker pieces (1.00) and never on
legitimate traffic (0.00), without changing the release decision.

This does NOT claim 3D geometry is useless for tamper-detection in the abstract. It
shows that, because the commitment is the catch floor, a runtime geometric check made
no additional catch in this configuration, and that returning geometric reasons is a
leak (a fit/no-fit oracle). The genuinely useful role 3D plays in this codebase is
generation-time hygiene (rejecting congruent / uniqueness-collapsing puzzles, in
generators/rejection.py), which is not a runtime detector and is not re-measured here.
```

## Caveats

```text
- The geometric detector cannot beat the commitment on catch-rate by construction: any
  piece that fails geometry also fails the commitment, and a piece that opens the
  commitment is the secret. The advantage = 0 result is structural; it is measured, not
  assumed.
- "Detect faster" is degenerate under commitment-keyed shutdown: both detectors flag on
  the first wrong proof and shut down on the same strike. The strike counter (strikes=5)
  makes this empirical rather than trivially 1; it does not create a geometric advantage.
- The verbose leak (4.86 bits) is realized only when the detector returns which check
  failed. The silent detector runs the same checks and leaks 0, so the leak is a design
  choice; the safe choice is to reveal nothing beyond pass/fail.
- Decoy attribution is conditional on the attacker submitting a decoy-consistent piece;
  legitimate traffic was never attributed (0/12). Attribution adds provenance on an
  already-caught attack; it does not raise detection or shorten time-to-detection.
- EXACT tier only (n=3, k=4); residual leak depends on enumerability within budget;
  Clopper-Pearson intervals are wide at n=12; the matrix has few capability profiles.
- Sealing is process-level (same as the prior docs): the detector runs in-process; this
  is not a TEE result.
```

## Reproduce

```text
uv run --extra dev --extra solvers pytest tests/test_puzzle_detector.py
uv run python -m spatial_swarm.spatial_puzzle.experiments.cli --experiment detector_keystone --n 3 --k 4 --seeds 12
```
