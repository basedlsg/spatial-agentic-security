# A falsification protocol for agent-swarm security mechanisms

Status: methodology note. Describes the evaluation method this repository uses, so it can
be reused to test *any* proposed mechanism for hardening an AI-agent-swarm gate — not just
the 3D spatial one measured here.

## The problem it solves

Security claims about agent mechanisms are easy to overclaim. A "spatial layer" or a
"formation check" or a "behavioral oracle" is added to a gate, the gate blocks more fake
messages than some baseline, and the mechanism is credited. The usual failure is the
**baseline**: if the baseline is a strawman (e.g. it signs metadata but never opens a
per-agent secret), the mechanism looks load-bearing when a plain commitment would do the
same job. This repository's own v0.3 claim ("the spatial layer adds measurable protection")
was exactly this error; the protocol below is what caught it (geometry's marginal advantage
turned out to be **0** — see `docs/findings_keystone_fair_baseline.md`).

The protocol is a way to **try hard to make a security claim true, and report honestly when
it isn't.** It is designed so an honest negative is fully supported and a false positive
(strawman baseline, broken solver, entropy artifact, leaky reason channel) is structurally
prevented.

## The nine rules

Each rule states the requirement, why it matters, and where this repo implements it as a
worked example.

**1. Fair matched baseline — beat the mechanism against a baseline that does the same job
minus the mechanism.** Not a strawman. If the mechanism is a per-agent secret encoding, the
baseline must also open a per-agent secret; the only difference is the mechanism.
*Here:* `experiments/fair_baselines.py` runs a unanimous commitment-opening gate (UCOG, no
geometry) beside full USAG on one shared scenario set; "geometry's marginal advantage" is
the count of scenarios USAG catches that UCOG misses.

**2. Adversary-uniform scenarios — one shared attacker spec, expressed in each system's own
format; the system never reads the attack label.** Otherwise the evaluator leaks the answer
to the detector. *Here:* a shared `ScenarioSpec`; the detector's `submit` is tested to give
identical output when the attack label is replaced with garbage
(`docs/findings_spatial_detector.md`, "attack-class blindness" control).

**3. Matched entropy — when comparing "hardness", match the compared secrets on entropy,
the one common currency.** A structured secret and a random secret are only comparable at
equal brute-force space. *Here:* `spatial_lab/entropy.py` `smallest_alphabet_for_bits`
sizes a random factor to the spatial factor's entropy; `bands_overlap` checks the match and
the gap is reported.

**4. Residual-entropy framing — measure the attacker's post-observation residual candidate
count against a random-secret ceiling.** Structure can only *remove* consistent
completions, so a random secret is the ceiling; the mechanism's job is to not fall below it.
*Here:* the leakage meter and the partial-compromise study report residual and
`1/residual` one-shot success beside the matched random ceiling at every observation level.

**5. Positive controls that gate the run — planted cases the system MUST pass, so a 0%
attacker row cannot be a silently broken solver.** If any control fails, the run is invalid
and no finding is written. *Here:* eight controls (a true secret releases, a wrong secret
blocks, a commitment-opening guess releases, a verbose channel leaks, a silent channel
leaks zero, a solver solves a planted easy case, the redaction scanner finds a planted
secret, destroy blocks a second attempt); `positive_controls.valid` must be `True`.

**6. Multi-solver agreement — any exact count is trustworthy only if independent solvers
agree; a budget stop is "not solved within budget", never "hard".** *Here:* pure-Python
enumeration, OR-Tools CP-SAT, PySAT, and Z3/SMT must return the same residual on the exact
tier; scaling costs are never reported as complexity lower bounds.

**7. Confidence intervals on every rate — Clopper-Pearson exact binomial, no bare point
estimates.** *Here:* `experiments/stats.py` `clopper_pearson`; every release/catch/recovery
rate carries a 95% interval, and wide intervals at small samples are stated, not hidden.

**8. Redaction with a planted-secret self-test — scan all artifacts for secret markers, and
prove the scanner works by planting a secret it must find.** *Here:* `experiments/redaction.py`
plus a planted-secret control; a clean finding requires `secret_markers_found = 0` **and**
the planted control detected. (This bites: an early run leaked because the scanner's own
marker list was serialized into the metrics — caught and fixed.)

**9. Describe-only reporting with explicit scope — "0/N under this configuration", a
"Claim (exact scope)" block that lists what is *not* claimed, and caveats from adversarial
audits.** Never "impossible", "foolproof", "provably useless". *Here:* every findings doc
follows this shape; see `RESEARCH_INTEGRITY.md` for the standing rules.

## Provenance requirements

Determinism (fixed seeds), the code commit hash and dirty-tree flag in every run
directory, and a `metrics.json.sha256` binding the reported bytes. A finding cites the run
directory and commit so it can be re-run.

## Worked example — the protocol catching a false positive

The keystone question was "does USAG's geometry catch any attack a fair non-geometric
unanimous gate misses?" Applying rules 1–2 and 5–9: a fully-executed UCOG gate (no
geometry) was run beside full USAG on 13 scenarios including the multi-agent/assembly class
(the only class that could differ), adversary-uniform, encoded as regression invariants
across seeds and agent counts. Result: **UCOG matched USAG on all 13 scenarios; geometry's
marginal advantage = 0**; the one genuinely geometric check was dead code. The mechanism
was not load-bearing — the protocol surfaced it instead of crediting the mechanism.

The same protocol then held across the detector framing (marginal detection advantage 0),
the partial-compromise framing (spatial residual collapses under stolen neighbors while a
matched random factor stays flat), and the anti-leak / leakage-bounded follow-ups. The
method's value is exactly that it kept returning the honest answer under four different
framings a proponent might try.

## Applying it to a new mechanism (checklist)

```text
[ ] State the mechanism and the exact question ("does X catch/harden anything that
    <fair baseline without X> does not?").
[ ] Build the fair baseline: same job, minus X, fully executed (rule 1).
[ ] One shared adversary spec; verify label-blindness (rule 2).
[ ] If "hardness": match entropy; report residual vs the random ceiling (rules 3-4).
[ ] Positive controls that gate the run; invalid runs write no finding (rule 5).
[ ] Multi-solver agreement on any exact count; budget stops labeled honestly (rule 6).
[ ] Clopper-Pearson on every rate (rule 7).
[ ] Redaction scan + planted-secret self-test (rule 8).
[ ] Describe-only write-up with an explicit "not claimed" block (rule 9).
[ ] Commit hash + dirty flag + digest in the run directory (provenance).
```

## Honest limits of the methodology itself

- It falsifies *marginal* claims against a chosen baseline and attack set; it cannot prove
  a mechanism useless in the abstract, and a different threat model could change the answer.
- Multi-solver agreement gives confidence on enumerable instances; at scale it degrades to
  "not solved within budget", which is not a lower bound.
- Positive controls catch broken measurement, not an incomplete attack set; the attack set
  is only as good as the scenarios written, so a "completeness critic" pass (what attack is
  missing?) is a manual step the protocol does not automate.
- Security-model reductions here are labeled sketches, not machine-checked proofs
  (`docs/security_model.md`).
```
