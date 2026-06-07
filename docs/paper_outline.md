# Paper Outline

## Title

Unanimous Spatial Assembly Gates for Fail-Closed Communication in AI Agent Swarms

## Abstract Claim

We present USAG, a fail-closed communication protocol for multi-agent LLM systems. USAG
requires every spawned agent to submit a message-bound spatial proof before any inter-agent
message is released. The protocol is evaluated against fake-agent insertion, replay,
wrong-message, over-budget, malformed-packet, and partial-compromise attacks.

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
