# Research Integrity Rules

1. Do not mock the verifier. A passing message must pass through the real gateway,
   real sidecars, real challenge generation, real proof packets, and real spatial assembly.
2. Do not mock the fragment system. Every agent must have a real generated fragment.
   Every proof must derive from that fragment.
3. Do not fake attack results. Fake agents are adversary implementations, but their
   behavior must be executable and logged.
4. Do not fake LLM results. Store exact model, provider, prompt, parameters, timestamp,
   output, token count, and failure reason for any future LLM attacker experiment.
5. Do not overstate results. If a test blocks 1000/1000 fake attempts, report
   "0/1000 passed under this configuration," not "impossible to attack."
6. Do not hide failed experiments. Failed runs must be logged and separated from valid
   completed runs.
7. Do not manually edit metrics. Metrics must be generated from raw JSONL logs by scripts.
8. Do not use synthetic data without labeling it.
9. Do not compare against baselines that were not run.
10. Do not claim misinformation detection unless semantic truth is evaluated.
11. Do not leak fragments in logs. Logs may include commitments, hashes, packet sizes,
    timings, and failure reasons.
12. Do not let the LLM see raw fragments. The sidecar owns the fragment.
13. Do not allow retries. One submission per agent per message.
14. Do not allow direct communication. All messages must go through the gateway.
15. Do not use "foolproof" in the paper. Use "fail-closed under stated assumptions."
