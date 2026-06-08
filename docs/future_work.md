# Future Work

## Sidecar Hardening

v1 sidecar:

```text
sidecar stores raw fragment
sidecar stores signing key
LLM never sees either
gateway/verifier is trusted
```

v2 sidecar:

```text
separate process
narrow local API
refuses raw-fragment disclosure
accepts proof requests only from gateway
logs no secrets
rate-limits proof requests
```

v3 sidecar:

```text
Docker container
network only to gateway
read-only filesystem
memory and CPU limits
no shell access from LLM
```

v4 sidecar:

```text
TEE or enclave-style key storage
commitment-based verification
zero-knowledge proof of valid transformed fragment
```

## Agent Framework Integration

After v0.2, integrate into a four-agent graph:

```text
Designer -> Coder -> Reviewer -> Tester
```

Each edge remains guarded externally by USAG. Do not scale to hundreds of live LLM agents
until the deterministic protocol and baseline results are stable.

## LLM Attacker Benchmark

Future LLM attacker runs should record exact model, provider, prompt, parameters, output,
token count, latency, parse result, and verifier failure reason. Raw fragments must not be
provided to the model.
