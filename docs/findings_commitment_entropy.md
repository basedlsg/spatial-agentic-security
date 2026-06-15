# Finding: commitment search space vs fragment_size

Status: internal finding (not a paper). Records the size of the per-agent
commitment's preimage search space as a function of `fragment_size`, flagged by
the security-model audit.

## What is measured

The per-agent secret is a set of `fragment_size` distinct points in F_p^3. The
registered commitment `H("commit", swarm_id, agent_id, p, coords)` is public. An
attacker that wants to open the commitment without the secret must search the set
of possible coordinate sets, of size `C(p^3, fragment_size)`. `fragment_secret_bits`
(`crypto/security_params.py`) reports `log2` of that size.

## Numbers for the default field p = 257 (grid p^3 ~= 2^24)

| fragment_size | search-space bits (log2 C(p^3, k)) |
| ---: | ---: |
| 1 | 24.0 |
| 2 | 47.0 |
| 3 | 69.5 |
| 4 | 91.5 |
| 5 | 113.2 |
| 6 | 134.6 |
| 8 | 176.8 |
| 16 (default) | 340.0 |
| 32 | 650.9 |

```text
min fragment_size for >= 128 bits at p=257: 6
min fragment_size for >= 256 bits at p=257: 12
```

## Notes

```text
- The default fragment_size = 16 gives ~340 bits of commitment search space.
- fragment_size <= 5 gives < 128 bits; fragment_size = 1 gives ~24 bits, which is
  small enough to enumerate.
- Several tests use fragment_size = 4 or 8 for speed; these are below (4) or above
  (8) the 128-bit point. The value is reported, not enforced: setup does not reject
  small fragment_size, so a deployment must pick a fragment_size whose reported
  search space meets its target.
- This bounds only the commitment-preimage search. The secrets are also derived
  deterministically from `seed` (see docs/security_model.md Section 5), so the
  realized entropy is additionally bounded by the entropy of `seed`.
```

## Reproduce

```text
uv run --extra dev pytest tests/test_security_params.py
uv run python -c "from spatial_swarm.crypto.security_params import fragment_secret_bits as f; print([round(f(k,257),1) for k in (1,4,8,16)])"
```
