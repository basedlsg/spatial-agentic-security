# Research Integrity

These rules apply to result generation and paper claims for UCOG (Unanimous
Commitment-Opening Gate; code name USAG). UCOG releases an inter-agent message only when
every required agent submits a fresh, message-bound, Ed25519-signed proof that opens its
per-agent SHA-256 commitment, decrypted by a trusted gateway. The 3D/affine "spatial"
encoding is one instantiation of the per-agent secret and is treated as an ablated design
point; under the implemented checks it adds no cryptographic hardness (see
docs/findings_keystone_fair_baseline.md and docs/security_model.md). The rules below use
"spatial"/"fragment"/"assembly" to refer to that instantiation and its code paths, not to
a security property.

1. Do not mock the verifier.
2. Do not mock the fragment system.
3. Do not fake attack results. Describe each attacker as implemented: e.g. the v0.6
   "AI forgery" benchmark ran a deterministic programmatic attacker (no model was run),
   so report it as a programmatic-attacker run reducing to the underlying primitives
   (SHA-256 / Ed25519 / X25519), not as evidence about model capability.
4. Do not manually edit metrics.
5. Do not hide failed experiments.
6. Do not compare against baselines that were not run.
7. Do not claim semantic truth or misinformation detection.
8. Do not leak raw fragments, raw coordinates, private keys, sidecar secrets, or private
   deterministic seeds in logs or metrics.
9. Do not use "foolproof" or "unbreakable." Use "fail-closed under stated assumptions."
10. Do not claim superiority over signatures unless a measured baseline supports the claim.
    Note: the measured v0.3 separation was against signature baselines that never open a
    per-agent secret; a fair unanimous commitment-opening baseline matches it
    (docs/findings_keystone_fair_baseline.md), so do not attribute the separation to the
    geometry.
11. Do not mock the verifier's assembly step (the implemented check is set-membership +
    disjointness; the geometric `assembles_exactly` is never called by the verifier).
    Do not describe this step as geometric tiling or as a "spatial proof of membership."
12. Do not report dirty-tree runs as paper-grade.
13. Do not manually delete or omit failed run artifacts from the research record.
14. Do not claim a 10,000-attempt headline unless that exact run completed and the raw
    metrics support it.
15. Do not claim gateway-compromise resistance while v0.3 uses a trusted verifier.
16. Do not log plaintext payloads, decrypted fragment responses, raw coordinates,
    private keys, raw fragments, or seeds.

Every benchmark plan should explicitly restate:

```text
Do not mock verifier success.
Do not mock the verifier's assembly step (set-membership + disjointness as implemented).
Do not manually edit metrics.
Do not hide failed runs.
Do not report dirty-tree runs as paper-grade.
Do not claim superiority over baselines unless baselines were run.
Do not claim misinformation detection.
Do not use "foolproof."
Do not log raw fragments, private keys, plaintext payloads, or seeds.
```
