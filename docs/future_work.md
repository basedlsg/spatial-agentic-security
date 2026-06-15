# Future Work

This file describes the protocol now called UCOG (Unanimous Commitment-Opening Gate;
code name USAG). UCOG releases an inter-agent message only when every required agent
submits a fresh, message-bound, Ed25519-signed proof that opens its per-agent SHA-256
commitment, decrypted by a trusted gateway. The 3D/affine "spatial" encoding is one
instantiation of the per-agent secret and is treated as an ablated design point; under
the implemented checks it adds no cryptographic hardness (see
docs/findings_keystone_fair_baseline.md and docs/security_model.md). Milestone and CLI
labels below keep the "USAG" name where they refer to the code or to dated artifacts.

## Milestones

```text
USAG v0.3: baselines, ablations, fuzzing, and 10,000-attempt focused benchmark
USAG v0.4: ephemeral setup and commitment verifier
USAG v0.5: process sidecar runtime and minimal sidecar API
USAG v0.6: live four-agent workflow integration
```

v0.3 completion criteria:

```text
1. Clean rerun of v0.2 from committed tree.
2. No-gate baseline implemented.
3. Sender-signature baseline implemented.
4. Unanimous-signature baseline implemented.
5. USAG compared against all baselines.
6. Ablation suite implemented.
7. Random packet fuzzer implemented.
8. 10,000-attempt focused benchmark completed.
9. Results regenerated from raw logs.
10. Docs updated with honest limitations.
```

## Sidecar Hardening

v0.4 sidecar:

```text
sidecar stores raw fragment
sidecar stores signing key
LLM never sees either
gateway/verifier is trusted
```

v0.5 sidecar:

```text
separate process
narrow local API
refuses raw-fragment disclosure
proof requests flow through the parent gateway client
logs no secrets
```

future sidecar:

```text
Docker container
network only to gateway
read-only filesystem
memory and CPU limits
no shell access from LLM
rate-limits proof requests
```

future verifier (proposed directions, not yet implemented or measured):

```text
TEE or enclave-style key storage
commitment-based verification
zero-knowledge proof of valid transformed fragment
```

These are proposed directions only. The "transformed fragment" item refers to the spatial
encoding as one instantiation of the per-agent secret; it is listed as a future design
exploration and is not, under the implemented checks, a source of cryptographic hardness
(see docs/findings_keystone_fair_baseline.md and docs/security_model.md).

## Agent Framework Integration

After deterministic protocol baselines, ablations, fuzzing, and clean focused benchmarks,
integrate into a four-agent graph:

```text
Designer -> Coder -> Reviewer -> Tester
```

Each edge would route its inter-agent message through UCOG as an external gate. Do not
scale to hundreds of live LLM agents until the deterministic protocol and baseline results
are stable.

## LLM Attacker Benchmark

Future LLM attacker runs should record exact model, provider, prompt, parameters, output,
token count, latency, parse result, and verifier failure reason. Raw fragments must not be
provided to the model.
