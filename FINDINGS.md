# Findings overview — does 3D spatial structure add anything to an agent-swarm gate?

Status: internal research record, measurements only. No result here is a paper claim.
Language follows `RESEARCH_INTEGRITY.md`: "0/N passed under this configuration", not
"impossible"; "fail-closed under stated assumptions", not "foolproof".

This file is the single narrative for the spatial-security arc. It states the question,
walks the experiments in order, gives the measured numbers, and draws the honest line
between what was shown and what was not. Each row links to the full finding.

---

## One-line result

> Under every framing tested — lock, runtime detector, and partial compromise — a
> hidden 3D **spatial** encoding added **no cryptographic hardness** over a random
> secret with a SHA-256 commitment. The security is the commitment + Ed25519 signature +
> sealed-box encryption + unanimity (UCOG). The geometry is an ablated design point. The
> one place spatial structure did measurable work was **generation-time hygiene**
> (rejecting weak instances before deployment), and a follow-up showed that hygiene can
> be improved but not made competitive with an independent random secret.

Both the hypothesis ("3D adds cost") and the null ("it does not") were reported at every
step; the null held.

---

## What is being tested

**UCOG** (Unanimous Commitment-Opening Gate; code name USAG) releases an inter-agent
message only when every required agent submits a fresh, message-bound, Ed25519-signed
proof that opens its per-agent SHA-256 commitment, decrypted by a trusted gateway. The
"spatial" layer is one instantiation of the per-agent secret: a 3D polycube piece under a
public affine transform. The research question, held fixed across the arc:

> Does the 3D/geometric structure catch any attack, or raise any attacker cost, that a
> plain committed *random* secret of matched entropy does not?

The threat model keeps the random lock intact and asks what the *geometry* adds on top.
Security definitions and reduction sketches (labeled "Claim", not proved) are in
[docs/security_model.md](docs/security_model.md): forgery reduces to Ed25519 EUF-CMA +
SHA-256 (2nd-)preimage + sealed-box IND-CCA2, and the geometry is argued inessential to
every guarantee.

---

## The experiment arc (in order)

| # | Question | Measured result | Finding |
| --- | --- | --- | --- |
| 1 | Does the geometry catch any attack a fair non-geometric unanimous gate misses? | On 13 scenarios (incl. the multi-agent/assembly class), a NO-geometry commitment-opening gate made the **identical** pass/fail decision as full USAG. Geometry's marginal advantage = **0**. The one geometric check (`assembles_exactly`) is **dead code** the verifier never calls. | [keystone_fair_baseline](docs/findings_keystone_fair_baseline.md) |
| 2 | At matched entropy, does a 3D secret resist recovery better than a random secret? | Across a leakage ladder, no spatial observation produced a residual **above** the matched random ceiling; published clues moved it to/below. Under one-shot, random left the attacker ~**3%** per-attempt; a spatial secret after any published clue → **100%** (residual 1). Four solver paradigms agreed on the residual. | [sealed_spatial_puzzle](docs/findings_sealed_spatial_puzzle.md), [spatial_structure_hardness](docs/findings_spatial_structure_hardness.md) |
| 3 | As a runtime **detector**, does a geometric check catch more than a plain commitment tripwire? | Detection was **identical** across nongeometric / geometric-silent / geometric-verbose / decoy on every attack class; both blind to a commitment-opening guess. Geometry's marginal detection advantage = **0**; false-positive delta = **0**. A **verbose** geometric response leaked ~**4.88 bits** (residual → 1); the silent one leaked **0**. A decoy adds *attribution*, not detection. | [spatial_detector](docs/findings_spatial_detector.md) |
| 4 | Under **partial compromise** (stolen neighbors) + one-shot, does spatial add cost vs a matched **random** second factor? | At A0 (no theft) spatial ≈ random. Under stolen neighbors the spatial residual **collapses** (medium n4k8: 5685 → 351 → 45) while the random factor stays **flat** (independent). One-shot caps per-attempt success at 1/residual; limited retries (strikes=5) convert the collapse into recovery. Verbose leak grew with scale (**4.88 → 12.42 → 14.92 bits**). | [spatial_partial_compromise_stress](docs/findings_spatial_partial_compromise_stress.md) |
| 5 | Can a generator be built that keeps the target ambiguous under stolen neighbors — beating the old generator? | Yes, by selection: n5k4 A3 residual **3 → 17** (one-shot 0.333 → 0.059), strictly higher than the old pick in **75–85%** of trials. But it **reduces, not closes**, the gap to a matched random factor (random one-shot 0.0088), and it is best-of-pool **selection**, not a designed construction. | [spatial_anti_leak_generator](docs/findings_spatial_anti_leak_generator.md) |
| 6 | Can a **designed** construction bound the neighbor-theft leak further? | Sparse placement (pieces spread in a public region larger than their union) cut the A0→A3 leak **monotonically** with sparsity ρ: **~5.0 bits (dense) → ~1.2–1.4 bits (ρ≥2.5)**, beating the dense generator in **100%** of paired trials at ρ≥2.5; A3 one-shot gap to random shrank ~30× → ~2.3–3.2×. It **approaches but does not reach** random (floors ~1.3 bits), at the cost of a 2.5–3× larger public region. | [spatial_leakage_bounded](docs/findings_spatial_leakage_bounded.md) |

Supporting/earlier records: [commitment_entropy](docs/findings_commitment_entropy.md),
[spatial_hardness](docs/findings_spatial_hardness.md) (superseded by #2).

---

## The structural reason the null keeps holding

A commitment binds the attacker's post-observation cost to the **residual candidate
count** — the number of secrets still consistent with what they have seen. Structure
(shape, connectors, topology, neighbor relations) can only **remove** consistent
completions, never add them. So at matched entropy:

```text
residual_spatial(observation)  <=  residual_random(observation)
```

by construction. A random secret is therefore the residual-entropy **ceiling**; "spatial
beats random" would require the inequality to reverse, which it cannot. Every experiment
measures the *gap below* that ceiling; none can (or did) show spatial above it. Under
partial compromise the gap widens, because spatial pieces are **correlated** (they
partition one object) while independent random secrets are not — stealing a neighbor
prunes the spatial residual and reveals nothing about a random one.

---

## What is actually contributed

Not "spatial security." Two things:

1. **An evaluation harness that tries hard to make a security claim true and reports when
   it isn't.** Adversary-uniform scenarios from one shared spec; a *fair* matched baseline
   that opens a per-agent secret (not a strawman metadata gate); matched-entropy controls;
   positive controls that **gate** the run (a 0% attacker row cannot be a broken solver);
   four independent solvers (pure-enum / CP-SAT / SAT / SMT) required to **agree** on
   exact residual counts; Clopper-Pearson 95% intervals on every rate; a redaction scanner
   with a planted-secret self-test; and describe-only reporting. This is the reusable,
   defensible artifact — a method for **falsifying** "mechanism X hardens an agent-swarm
   gate." It is written up as a standalone, reusable protocol in
   [METHODOLOGY.md](METHODOLOGY.md).

2. **Two substantive measurements** with the mechanism held honest: the partial-compromise
   correlation leak (spatial residual collapses under stolen neighbors while a matched
   random factor is immune), and the anti-leak result (that leak can be reduced by
   selecting low-correlation partitions, but not made competitive with random).

---

## What is NOT claimed

```text
- NOT "spatial geometry is provably useless." Shown: this construction does the job a
  plain commitment-opening does, on the implemented attack set. That is an ablation, not
  an impossibility theorem.
- NOT a cryptographic proof. docs/security_model.md gives reduction *sketches* labeled
  "Claim", informed by two audits; they are not machine-checked.
- NOT a TEE/hardware result. Sealing is process-level (op allowlist, zeroization,
  no-retry, redacted logs). Attestation is a stub (sgx=false); real sealed memory +
  remote attestation need a confidential VM (deferred, enclave/cloud_sgx_runbook.md).
- NOT a scaling lower bound. Budgeted solver costs are "not solved within budget", never
  "hard"; the credibility is four-solver agreement on exhausted counts, not run time.
- NOT an LLM/vision result. That attacker hook records status=not_run (no endpoint).
```

---

## Limitations and open questions

- A **designed** sparse-placement construction (#6) now bounds the neighbor-theft leak
  *measurably* — cutting it from ~5.0 to ~1.3 bits and beating the dense generator in 100%
  of trials — but it floors ~1.3 bits (does not reach random) and pays a 2.5–3× larger
  public region. The remaining open question is a construction with a **proved** (not just
  measured) neighbor-leakage bound, and whether the ~1.3-bit floor can be pushed lower.
- Exact enumeration bounds the tiers; sample sizes are modest (large tier n=10), so some
  Clopper-Pearson intervals are wide.
- The sealed-runtime story is unproven until a real confidential-VM run exists.

---

## Reproduce

```bash
uv run --extra dev --extra solvers pytest                                             # full suite
uv run --extra dev pytest tests/test_fair_baseline_keystone.py                        # #1 keystone
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.cli --experiment all --n 3 --k 4 --seeds 20        # #2 lock/leakage
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.cli --experiment detector_keystone --n 3 --k 4     # #3 detector
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.partial_compromise_stress --tier all               # #4 partial compromise
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.anti_leak_experiment --tier both                   # #5 anti-leak
```

Every run writes a timestamped `runs/<ts>/` with `config.yaml`, `environment.txt`,
`git_commit.txt`, `metrics.json` + `.sha256`, and `redaction.json`.

---

## Repository map (honest scope)

**The spatial-security arc (this record):**
`security_model.md`, and findings `keystone_fair_baseline`, `commitment_entropy`,
`spatial_hardness` / `spatial_structure_hardness`, `sealed_spatial_puzzle`,
`spatial_detector`, `spatial_partial_compromise_stress`, `spatial_anti_leak_generator`.
Code: `src/spatial_swarm/spatial_puzzle/` (generators, solvers, leakage, enclave,
detector, experiments) and `src/spatial_swarm/{core,protocol,crypto,evalkit,spatial_lab}`.

**Separate research threads also present on this branch** (distinct experiments, not part
of the arc above; see each doc for its own scope and results — not summarized here):
`findings_minimal_core_gate_v1`, `findings_realistic_coding_gate` / `_v2`,
`findings_real_sandbox_gate_v3`, `findings_geometric_formation_lab_v1`,
`findings_spatial_formation_gate`, `findings_coordinator_challenge_hardening_v1`, and the
`keystone_v2` local-model benchmark. These share the repo but are evaluated independently.
