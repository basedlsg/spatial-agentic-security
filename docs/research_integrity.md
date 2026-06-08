# Research Integrity

These rules apply to result generation and paper claims.

1. Do not mock the verifier.
2. Do not mock the fragment system.
3. Do not fake attack results.
4. Do not manually edit metrics.
5. Do not hide failed experiments.
6. Do not compare against baselines that were not run.
7. Do not claim semantic truth or misinformation detection.
8. Do not leak raw fragments, raw coordinates, private keys, sidecar secrets, or private
   deterministic seeds in logs or metrics.
9. Do not use "foolproof" or "unbreakable." Use "fail-closed under stated assumptions."
10. Do not claim superiority over signatures unless a measured baseline supports the claim.
11. Do not mock spatial assembly.
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
Do not mock spatial assembly.
Do not manually edit metrics.
Do not hide failed runs.
Do not report dirty-tree runs as paper-grade.
Do not claim superiority over baselines unless baselines were run.
Do not claim misinformation detection.
Do not use "foolproof."
Do not log raw fragments, private keys, plaintext payloads, or seeds.
```
