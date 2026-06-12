# Future Work

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

future verifier:

```text
TEE or enclave-style key storage
commitment-based verification
zero-knowledge proof of valid transformed fragment
```

## Agent Framework Integration

After deterministic protocol baselines, ablations, fuzzing, and clean focused benchmarks,
integrate into a four-agent graph:

```text
Designer -> Coder -> Reviewer -> Tester
```

Each edge remains guarded externally by USAG. Do not scale to hundreds of live LLM agents
until the deterministic protocol and baseline results are stable.

## LLM Attacker Benchmark

Future LLM attacker runs should record exact model, provider, prompt, parameters, output,
token count, latency, parse result, and verifier failure reason. Raw fragments must not be
provided to the model.
