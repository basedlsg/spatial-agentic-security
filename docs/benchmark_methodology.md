# Benchmark Methodology

UCOG (Unanimous Commitment-Opening Gate; code name USAG) benchmarks are deterministic
protocol-harness runs. They use logical agents, private sidecars, finite-field geometry,
signed encrypted proof packets, a trusted gateway, and a trusted verifier.

UCOG releases an inter-agent message only when every required agent submits a fresh,
message-bound, Ed25519-signed proof that opens its per-agent SHA-256 commitment, decrypted
by a trusted gateway. The 3D/affine "spatial" encoding is one instantiation of the
per-agent secret and is treated as an ablated design point; under the implemented checks it
adds no cryptographic hardness (see docs/findings_keystone_fair_baseline.md and
docs/security_model.md).

## Default Configuration

```text
N = 8 agents unless the run says otherwise
fragment_size = 16 coordinates per agent
field = F_257^3
max_submissions = 1
direct agent-to-agent communication = disabled
retries = disabled
```

## Benchmark Presets

The CLI supports the reviewer-facing command form:

```bash
uv run spatial-swarm benchmark v0_2_matrix
uv run spatial-swarm benchmark honest_1024
uv run spatial-swarm benchmark attack_scale_1024
uv run spatial-swarm benchmark baseline_matrix
uv run spatial-swarm benchmark ablation_matrix
uv run spatial-swarm benchmark fuzz_10000
uv run spatial-swarm benchmark v0_3_focused_10000
```

Preset defaults:

| Preset | Scenario/group | Agents | Attempts |
| --- | --- | ---: | ---: |
| `v0_2_matrix` | v0.2 attack matrix | 8 | 1,000 |
| `honest_1024` | honest | 1,024 | 100 |
| `attack_scale_1024` | 1024-agent attack-scale group | 1,024 | 100 |
| `baseline_matrix` | baseline comparison | 8 | 1,000 |
| `ablation_matrix` | verifier ablation comparison | 8 | 1,000 |
| `fuzz_10000` | three fuzzer classes | 8 | 10,000 |
| `v0_3_focused_10000` | focused 10,000-attempt matrix | 8 | 10,000 |

Any preset can be overridden with explicit flags, for example:

```bash
uv run spatial-swarm benchmark baseline_matrix --attempts=10
```

## Attempt Semantics

One attempt is one proposed inter-agent message. A passing attempt means the gateway
released the message. A failed attempt means the gateway blocked it and collapsed the
current swarm epoch.

## Packet Position Semantics

Some scenarios replace one packet. Their names encode where the first bad packet appears:

```text
early  = first agent packet
middle = floor(N / 2)
late   = final agent packet
```

Latency depends on this position because the verifier exits on first failure after
validating preceding packets.

## Failure Stages

The verifier records the stage where a round terminated:

```text
registration
agent_status
epoch_binding
message_binding
challenge_binding
submission_policy
proof_envelope
timeout
signature
decrypt
response_binding
commitment
geometry
assembly
release
```

It also records:

```text
packets_checked_before_failure
signatures_verified
decryptions_performed
geometry_checks_performed
```

For successful honest messages, these counters describe work performed before release.

## Baseline Modes

v0.3 compares the same scenario labels against four gates:

```text
mode_0_no_gate
mode_1_sender_signature_only
mode_2_unanimous_signature_gate
mode_3_usag_spatial_gate
```

The first three modes are deterministic baseline simulations. Signature modes use real
Ed25519 signing and verification over message-bound payloads. They do not open any
per-agent secret. The fourth mode is the real USAG verifier (the code/CLI) running the same
scenario implementation used by the attack matrix.

For per-agent-secret attacks such as `valid_signature_wrong_geometry`, the baseline
assumption is that ordinary signatures are valid and only the per-agent secret material is
wrong. This baseline measures the difference between a signature-only check and the
commitment-opening check after normal signature checks have already succeeded. Note that
the v0.3 separation reported here was measured against signature baselines that never open
a per-agent secret; a fair unanimous commitment-opening baseline matches it (see
docs/findings_keystone_fair_baseline.md), so the measured separation comes from the
per-agent commitment opening plus unanimity plus message binding, not from the geometry.

## Ablation Modes

v0.3 can run the attack matrix against weakened verifier options:

```text
usag_full
usag_without_message_hash_binding
usag_without_sender_receiver_binding
usag_without_epoch_nonce_binding
usag_without_proof_envelope_budget
usag_without_geometry_check
usag_without_signatures
```

Disabling one check does not by itself cause an attack to pass. Later checks remain active
unless that ablation disables them too. For example, removing the per-piece geometry check
can move a wrong-geometry attack from `wrong_geometry` to `assembly_failed`; the run records
which stage terminated the round. The verifier's `assembly` stage checks set-membership and
disjointness over the opened per-agent secrets, not geometric tiling (the geometric
`assembles_exactly` routine is never called by the verifier).

## Fuzzing

The deterministic packet fuzzer mutates:

```text
agent_id
message_hash
challenge_hash
epoch
signature
encrypted payload
proof commitment
packet size
coordinates
packet order
submission number
timestamp
wrong-nonce transform
```

Fuzzer runs track whether any malformed or replay-mutated packet set passes, where it
fails, and whether the verifier crashes. A successful fuzz benchmark should report:

```text
0 malformed randomized attempts pass
0 verifier crashes
0 raw secrets logged
```

## Latency

Latency is verifier wall-clock time for one message round. It starts at verifier entry and
ends at first failure or message release. It does not include process startup time.

## Proof Bytes

Proof bytes are serialized JSON proof packet bytes accumulated by the verifier. They
include IDs, epoch, message/challenge hashes, proof commitment, encrypted fragment
response, Ed25519 signature, submission metadata, JSON syntax, and base64 overhead.

## Resource Use

RSS memory comes from `resource.getrusage(RUSAGE_SELF).ru_maxrss` and is converted to MB
for the current platform.

## Reporting Rules

Report zero observed unauthorized passes as an observation under a stated configuration,
not as impossibility.

Generated artifacts include:

```text
commit hash
project-scoped worktree dirty flag
timestamp
machine/platform
Python version
uv.lock SHA-256
config
metrics
JSONL events
```
