# Finding: the geometry adds nothing over a fair unanimous baseline

Status: internal finding (not a paper). Recorded so later work does not re-derive
or over-state it.

## Question

Earlier results (v0.3) claimed "the spatial layer adds measurable protection over
signature baselines." That comparison used `baselines.py`, whose strongest gate
(`mode_2_unanimous_signature_gate`) signs only message metadata and is decided by
a hard-coded `ScenarioProfile` lookup -- it never forces an agent to OPEN a
per-agent secret. The keystone question:

> Does USAG's geometry catch any attack that a *fair* non-geometric baseline --
> a unanimous per-agent commitment-opening gate -- misses?

## Method

`experiments/fair_baselines.py` runs three gates **fully executed** and
**adversary-uniform** (same attacker capabilities, expressed in each gate's own
packet format from one shared `ScenarioSpec`):

```text
unanimous_signature_metadata   all N agents sign metadata; never opens a secret
unanimous_commitment_opening   UCOG: all N agents open a per-agent SHA-256-committed
                               secret, message-bound + signed. NO geometry, no
                               transform, no tiling. Mirrors USAG's verifier order.
usag_full                      the real USAG pipeline (runner scenarios)
```

The scenario set deliberately includes the multi-agent / assembly class
(`correct_geometry_wrong_agent_id`, `duplicate`, `partial_swarm`, `missing`) --
the only scenarios where a unanimous gate could differ from a single-agent one,
and so the only ones that could falsify the finding.

## Result (commit `0c603a0fb4`, Python 3.13.2, deterministic)

| scenario | unanimous_signature | UCOG (no geometry) | usag_full |
| --- | --- | --- | --- |
| honest | pass | pass | pass |
| fake_agent | fail `wrong_signature` | fail `wrong_signature` | fail `wrong_signature` |
| unregistered_fake_agent | fail `unregistered_agent` | fail `unregistered_agent` | fail `unregistered_agent` |
| replay | fail `wrong_message_hash` | fail `wrong_message_hash` | fail `wrong_message_hash` |
| stolen_fragment_only | fail `wrong_signature` | fail `wrong_signature` | fail `wrong_signature` |
| valid_signature_wrong_geometry | **pass (misses)** | fail `commitment_opening_failed` | fail `wrong_geometry` |
| valid_signature_wrong_transform | **pass (misses)** | fail `commitment_opening_failed` | fail `wrong_geometry` |
| stolen_signing_authority_only | **pass (misses)** | fail `commitment_opening_failed` | fail `wrong_geometry` |
| verifier_snapshot_forgery | **pass (misses)** | fail `commitment_opening_failed` | fail `wrong_geometry` |
| correct_geometry_wrong_agent_id | **pass (misses)** | fail `response_binding_failed` | fail `response_binding_failed` |
| duplicate | **pass (misses)** | fail `duplicate_submission` | fail `duplicate_submission` |
| partial_swarm | fail `missing_packet` | fail `missing_packet` | fail `missing_packet` |
| missing | fail `missing_packet` | fail `missing_packet` | fail `missing_packet` |

```text
UCOG matches USAG on all 13 scenarios:        True
USAG beats the metadata-signature gate on:    6 scenarios
...of those, UCOG (no geometry) also catches:  6 scenarios
geometry's marginal advantage over UCOG:       0 scenarios
```

Encoded as regression invariants in `tests/test_fair_baseline_keystone.py`
(holds across seeds 7 / 99 / 1337 / 20240, agent counts 6 and 8).

## Claim (exact scope -- do not overstate)

```text
Under USAG's stated trust model and on the implemented attack set, a fully
executed unanimous commitment-opening gate with NO geometry makes the identical
pass/fail decision as full USAG on every scenario, including the multi-agent /
assembly class. The 3D affine "spatial" machinery is not load-bearing: USAG's
security comes from per-agent committed-secret opening + unanimity + message
binding -- standard primitives.
```

This does **not** claim spatial structure is useless in the abstract. It shows
the specific construction here does the job a plain SHA-256 commitment-opening
would do. Restating it as "spatial geometry is provably useless for swarm gating"
would be an overclaim.

## Caveats (from two independent adversarial audits)

```text
- The four "valid-signature, wrong-secret" scenarios share ONE attacker
  capability profile (signing key, no secret); they pass/fail together by
  construction. The discriminating power comes from the assembly-class
  scenarios, not from those four. The matrix is ~6 distinct capability profiles,
  not 13 independent tests.
- USAG's verifier calls assembles_committed_piece_set (set-membership +
  disjointness), NOT the geometric assembles_exactly (assembly.py:22), which is
  never called by the verifier. The one genuinely geometric check is dead code.
- Both audits tried to construct an attack USAG catches and UCOG misses
  (piece-swap, wrong-but-disjoint coords, stale secret, coordinate overlap) and
  found none; coordinate overlap is unreachable because disjoint fragments under
  a bijection cannot collide.
```

## Why this matters for the reframe

This is the empirical basis for dropping the "Spatial/Assembly" framing as the
security thesis and re-pitching USAG honestly as a fail-closed **unanimous
commitment-opening message gate** plus the v0.6 evaluation methodology. The
geometry, if kept at all, is one ablated design point -- not the contribution.

## Reproduce

```text
uv run --extra dev pytest tests/test_fair_baseline_keystone.py
uv run python -c "from spatial_swarm.experiments.fair_baselines import run_fair_baseline_matrix as r; import json; print(json.dumps(r()['matrix'], indent=2))"
```
