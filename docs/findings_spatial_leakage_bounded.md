# Finding: a leakage-bounded spatial construction (sparse placement)

Status: internal finding (not a paper). Measurements only. Follows
`findings_spatial_anti_leak_generator.md`, which reduced the neighbor-theft leak by
*selecting* low-correlation partitions from a pool. This tests a *designed* construction
instead, and asks how far it can push the leak toward the random ceiling.

## Question

Under partial compromise, a dense spatial partition (pieces tile the target) collapses the
target's residual when neighbors are stolen — because the pieces are correlated. Can a
**designed** construction bound that leak, and how close to a random secret (which loses
nothing under theft) can it get?

## Method

The construction: place the n committed k-pieces **sparsely** — farthest-point seeds, then
grow each into a connected k-piece — inside a public **ambient region larger than their
union**. Stealing a neighbor then removes cells far from the target and barely prunes its
candidate set. The single knob is the sparsity ratio `rho = |ambient| / (n*k)`; `rho = 1`
is the dense generator. This is faithful to the second-factor model (the factor is a
connected k-subset of a public region), with one honest design change: the region is
larger than the union of pieces (unowned filler cells).

Metric: **bits lost from A0 to A3** = `log2(residual_A0 / residual_A3)`, where A3 is the
worst case over which two neighbors are stolen. This is **scale-free** — it measures how
much theft prunes the target *relative to its own starting residual*, so a bigger ambient
region does not inflate it. A random factor matched to each construction's own A0 residual
loses **0** bits; the dense generator loses many; the question is how far sparse closes it.
Dense and sparse are compared **paired by seed**; `beats dense` is a Clopper-Pearson
proportion over trials.

## Configs, controls

```text
run_dir     : runs/2026-07-22T16-26-03.724624Z
code commit : afe15889e
tiers       : n3k4 (n=3 k=4), n4k4 (n=4 k=4); 20 trials each, exact enumeration
positive_controls.valid : True (all 8)
redaction               : clean (secret_markers_found = 0)
generation_failures     : 0 at both tiers
```

## Results — neighbor-theft leak vs sparsity

n=3, k=4 (dense A0 residual 31.5; matched-random one-shot 0.0312):

| construction | rho | A0 residual | A3 residual | bits lost A0→A3 | A3 one-shot (× random) | beats dense [95% CI] |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| dense | 1.0 | 31.5 | 1.0 | 4.97 | 1.000 (32×) | — |
| sparse | 1.5 | 63.5 | 7.0 | 3.63 | 0.143 (9.1×) | 0.85 [0.62, 0.97] |
| sparse | 2.0 | 120.5 | 21.0 | 2.24 | 0.048 (5.7×) | 0.90 [0.68, 0.99] |
| sparse | 2.5 | 186.0 | 66.0 | 1.42 | 0.015 (2.8×) | **1.00 [0.83, 1.00]** |
| sparse | 3.0 | 260.5 | 81.5 | 1.39 | 0.012 (3.2×) | **1.00 [0.83, 1.00]** |

n=4, k=4 (dense A0 residual 56; matched-random one-shot 0.0179):

| construction | rho | A0 residual | A3 residual | bits lost A0→A3 | A3 one-shot (× random) | beats dense [95% CI] |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| dense | 1.0 | 56.0 | 2.0 | 4.34 | 0.500 (28×) | — |
| sparse | 1.5 | 120.5 | 26.0 | 2.45 | 0.038 (4.6×) | 0.95 [0.75, 1.00] |
| sparse | 2.0 | 226.0 | 45.5 | 2.19 | 0.022 (4.9×) | 0.95 [0.75, 1.00] |
| sparse | 2.5 | 298.5 | 128.0 | 1.17 | 0.008 (2.3×) | **1.00 [0.83, 1.00]** |

## What the numbers show (direct readings)

- The neighbor-theft leak dropped **monotonically** with sparsity: from ~5.0 bits (dense)
  to ~1.2–1.4 bits (rho ≥ 2.5) at both tiers.
- At rho ≥ 2.5 the sparse construction lost fewer bits to two-neighbor theft than the
  dense generator in **every one of 20 paired trials** (1.00 [0.83, 1.00]).
- The A3 one-shot success gap to a matched random factor shrank from ~28–32× (dense) to
  ~2.3–3.2× (sparse) — the dense case is fully or near-fully recoverable under two-neighbor
  theft (A3 residual 1–2), the sparse case leaves the attacker at ~1/66–1/128.
- It **approaches but does not reach** random: the leak floors around ~1.2–1.4 bits and
  barely moved from rho 2.5 → 3.0 (1.42 → 1.39), so there are diminishing returns.
- Better than the anti-leak *selection* result (which floored ~2.75 bits at A3): a designed
  sparse construction closes more of the gap than pool selection did.

## Claim (exact scope — do not overstate)

```text
At n=3,k=4 and n=4,k=4, with 20 trials and exact enumeration: a sparse-placement
construction reduced the two-neighbor-theft leak (bits lost from A0 to A3) monotonically
with the sparsity ratio, from ~5.0 bits (dense) to ~1.2-1.4 bits (rho>=2.5), and lost
fewer bits than the dense generator in 100% of paired trials at rho>=2.5. It reduced the
A3 one-shot gap to a matched random factor from ~30x to ~2.3-3.2x.

This does NOT claim the construction reaches or beats random: the leak floored around
~1.2-1.4 bits and did not fall to 0. The reduction is scale-free (measured as bits lost
relative to each construction's own A0 residual), so it is not an artifact of a larger
region. The cost is an ambient public region 2.5-3x the piece cells.
```

## Caveats

```text
- Design change: the public region is larger than the union of pieces (unowned filler
  cells), so the published outer shape is bigger. The cost (region size) is reported as
  the sparsity ratio; the benefit (leak reduction) is scale-free bits lost.
- Approaches but does not reach random. A random factor loses 0 bits under theft by
  independence; the sparse construction floors ~1.2-1.4 bits because removing cells always
  removes some candidates from the target's finite local neighborhood.
- Placement is farthest-point greedy, not proven optimal; a construction with a *proved*
  neighbor-leakage bound (rather than a measured one) remains open.
- Exact tier only (k=4), 20 trials; Clopper-Pearson intervals are wide at the ends.
- Same lock model as the arc: this measures the second factor's residual under theft with
  the random lock held; it is not a standalone security claim.
```

## Reproduce

```text
uv run --extra dev --extra solvers pytest tests/test_leakage_bounded.py
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.leakage_bounded_experiment --tier both
```
