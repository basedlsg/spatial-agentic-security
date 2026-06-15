# Paper Outline

## Title

A Unanimous Commitment-Opening Gate for Fail-Closed Communication in AI Agent Swarms

## Abstract

This describes UCOG (Unanimous Commitment-Opening Gate; code name USAG), a fail-closed
communication mechanism implemented for multi-agent LLM systems. UCOG releases an
inter-agent message only when every required agent submits a fresh, message-bound,
Ed25519-signed proof that opens its per-agent SHA-256 commitment, decrypted by a trusted
gateway. The 3D/affine "spatial" encoding is one instantiation of the per-agent secret and
is treated as an ablated design point; under the implemented checks it adds no cryptographic
hardness over a non-geometric unanimous commitment-opening gate (see
docs/findings_keystone_fair_baseline.md and docs/security_model.md). The implementation was
exercised against fake-agent insertion, replay, wrong-message, over-budget, malformed-packet,
and partial-compromise scenarios, and the observed pass/block counts under the stated
conditions are reported.

## Sections

1. Introduction
2. Threat model
3. Related work
   - prompt infection
   - agent prompt injection benchmarks
   - secret sharing
   - distributed commit protocols
   - agent sandboxing
   - spatial reasoning limitations
4. Protocol design
5. Implementation
6. Experiments
7. Results
8. Limitations
9. Future work

## Reporting Language

Use:

```text
0 / 10,000 unauthorized messages passed under configuration X.
```

Avoid:

```text
USAG is impossible to attack.
USAG proves messages are true.
USAG is stronger than signatures in every setting.
```
