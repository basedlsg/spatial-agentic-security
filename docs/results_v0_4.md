# Results v0.4

> Note: dated record of what was measured. Protocol now called UCOG (code name USAG).
> A later fair-baseline experiment (docs/findings_keystone_fair_baseline.md) and the
> formal model (docs/security_model.md) show the geometry adds no cryptographic hardness
> over a unanimous commitment-opening gate; read 'spatial' below as an instantiation
> detail, not a security property.

UCOG (Unanimous Commitment-Opening Gate; code name USAG) v0.4 is the **Ephemeral Setup + Commitment Verifier** design point.

Goal:

```text
The verifier can check the swarm without owning the full puzzle or raw pieces.
```

## Commits And Provenance

Implementation commit:

```text
commit: f2286ed8d9b6744e51b30767a85a127d39a8a7c6
```

Benchmark/logging commit used for completed clean artifacts:

```text
commit: 3bf60389b4bd8e8864abeceb0d4210eb093bf0fb
worktree_dirty: false
Python: 3.13.2
platform: macOS-26.2-arm64-arm-64bit-Mach-O
machine: arm64
uv.lock SHA-256: c9bfd2dd5969d91149c5383635ddb096b801c49b4d45d74e2af4ff281119a306
```

Verification:

```text
uv run --extra dev pytest
45 passed

uv lock --check
passed

git diff --check -- Spatial_Agentic_Security
passed
```

## Custody Model

Setup now performs birth-time puzzle custody:

```text
Setup creates the full puzzle.
Setup cuts it into pieces.
Setup gives one piece to each sidecar.
Setup creates fingerprints of each piece.
Setup deletes the full puzzle.
Setup deletes the seed.
Setup shuts down.
```

After setup, verifier-visible state stores:

```text
agent IDs
public verify keys
piece fingerprints
fragment sizes
finite-field modulus
message/proof rules
proof-size envelopes
active/inactive state
```

Verifier-visible state does not store:

```text
raw puzzle pieces
full puzzle
seed
private signing keys
private decryption keys after verifier shutdown
coordinates
plaintext proof payloads
```

The verifier checks a submitted transformed proof by decrypting the message-bound response,
applying the inverse challenge transform, recomputing the original piece fingerprint, and
comparing that fingerprint to the registered commitment. The "assembly" check the verifier
runs is a set-membership and disjointness check: it requires every committed agent to submit
exactly once and rejects duplicate submissions. (The geometric assembles_exactly routine is
not called by the verifier.)

Important simulator boundary:

```text
The local Gateway object still co-locates sidecars for simulation convenience. Sidecars
hold raw pieces. The verifier and registry do not.
```

## New Tests

Added tests assert (and pass under the implemented checks):

```text
After setup, verifier-visible registrations have no raw fragments.
After setup, the full puzzle is gone.
After setup, the seed is gone.
Temporary verifier exits after checking.
Run logs contain no raw setup or piece material.
With only verifier public state, the programmatic attacker's forged submission was rejected.
```

The new stolen-verifier-state attack is:

```text
verifier_snapshot_forgery
```

It gives the attacker only verifier-visible metadata and then attempts to fake an agent
piece. Expected result is `wrong_geometry`.

## Focused 1,000-Attempt Run

Run artifact:

```text
runs/2026-06-12T02-20-41.980345Z
scenario: v0_4_focused_10000
attempts: 1000 per scenario
commit: 3bf60389b4bd8e8864abeceb0d4210eb093bf0fb
worktree_dirty: false
event_logging: events_jsonl
```

Headline:

```text
honest: 1000 / 1000 passed
attacks: 0 / 10000 unauthorized attempts passed
```

| Scenario | Passes | Failure reason | p95 latency ms |
| --- | ---: | --- | ---: |
| honest | 1000 / 1000 | none | 14.041 |
| fake_agent | 0 / 1000 | `wrong_signature` | 8.681 |
| unregistered_fake_agent | 0 / 1000 | `unregistered_agent` | 0.062 |
| replay | 0 / 1000 | `wrong_message_hash` | 0.077 |
| wrong_message | 0 / 1000 | `wrong_message_hash` | 0.099 |
| valid_signature_wrong_geometry | 0 / 1000 | `wrong_geometry` | 6.775 |
| valid_signature_wrong_transform | 0 / 1000 | `wrong_geometry` | 6.702 |
| stolen_signing_authority_only | 0 / 1000 | `wrong_geometry` | 6.819 |
| stolen_fragment_only | 0 / 1000 | `wrong_signature` | 6.041 |
| correct_geometry_wrong_agent_id | 0 / 1000 | `response_binding_failed` | 9.981 |
| verifier_snapshot_forgery | 0 / 1000 | `wrong_geometry` | 6.910 |

Resource use:

```text
max RSS: 54.75 MB
```

## Fuzzing

Run artifact:

```text
runs/2026-06-12T02-30-38.756134Z
scenario: fuzz_10000
attempts: 10000 per fuzzer class
commit: 3bf60389b4bd8e8864abeceb0d4210eb093bf0fb
worktree_dirty: false
event_logging: events_jsonl
```

Result:

```text
total passes: 0 / 30000
verifier crashes: 0 observed
raw secret markers in artifact grep: 0
```

| Fuzzer class | Passes | Dominant failure reasons | p95 latency ms | p99 latency ms |
| --- | ---: | --- | ---: | ---: |
| fuzz_malformed_packet | 0 / 10000 | mixed binding, envelope, registration, geometry, signature failures | 12.075 | 15.034 |
| fuzz_mixed_packet_set | 0 / 10000 | duplicate, geometry, registration, binding, envelope failures | 7.475 | 9.684 |
| fuzz_replay_mutation | 0 / 10000 | `wrong_message_hash` | 10.995 | 13.759 |

Resource use:

```text
max RSS: 85.156 MB
```

## Secret Redaction Check

The following grep over completed clean v0.4 artifacts returned no matches:

```text
rg -n '"coords"|private_key|signing_key|plaintext|decrypted|full_puzzle|"seed"|seed:' \
  runs/2026-06-12T02-20-41.980345Z \
  runs/2026-06-12T02-30-38.756134Z
```

## Partial Or Non-Paper-Grade Artifacts

Do not report these as completed clean results:

```text
runs/2026-06-11T07-31-43.713264Z
scenario: v0_4_focused_10000
status: completed diagnostic run from dirty worktree
worktree_dirty: true

runs/2026-06-11T08-13-29.857168Z
scenario: v0_4_focused_10000
status: interrupted partial run
metrics.json: absent

runs/2026-06-11T14-12-39.542119Z
scenario: v0_4_focused_10000
status: interrupted partial run
metrics.json: absent

runs/2026-06-11T15-59-53.283549Z
scenario: v0_4_focused_10000
status: interrupted partial run
metrics.json: absent
```

## Interpretation

What was measured in v0.4:

```text
Under the deterministic local simulator, with the run counts and provenance recorded
above, the honest scenario passed and every listed attack/fuzz scenario was rejected
(0 passes), while verifier-visible state stored only public keys, piece fingerprints,
and policy metadata rather than raw puzzle pieces. The "geometry"-related rejections
reduce to the underlying primitives (SHA-256 commitment opening, Ed25519 signing,
X25519 message binding); see docs/findings_keystone_fair_baseline.md and
docs/security_model.md.
```

These runs were not designed to and do not measure zero-knowledge security,
compromised-host resistance, sidecar memory isolation, or production deployment safety.
