# Threat Model

USAG protects membership and communication authorization for a fixed swarm born in a
single epoch. It does not evaluate whether message content is true.

## In Scope

USAG v1 defends against:

- fake external agent entry
- fake agent impersonating a registered agent ID without the sidecar key and fragment
- compromised LLM brain without access to the sidecar fragment
- replay of an old valid proof packet
- proof for Message A submitted for Message B
- wrong sender, receiver, or epoch
- over-budget proof attempts
- malformed packets
- duplicate submissions
- missing or late fragments
- a single stolen fragment used alone
- a partial swarm where `k < N` fragments are controlled

## Out Of Scope

USAG v1 does not defend against:

- host compromise that reads sidecar memory
- gateway or verifier compromise
- all original sidecars approving a malicious message
- raw fragment leakage through modified logs
- prompt injection that can directly inspect sidecar memory
- network availability failures in a real deployment

## Security Posture

The system is intentionally fail-closed:

```text
missing proof
late proof
duplicate proof
malformed proof
wrong signature
wrong challenge
wrong message
wrong geometry
over-budget packet
```

Any one of these blocks the message, ejects the failing agent when identifiable, and
collapses the current swarm epoch.

## Core Claim

No message can pass between agents unless every original live agent proves possession of
its private spatial fragment for that exact message challenge.

## Non-Claims

USAG does not claim:

- message truth
- misinformation detection
- universal attack prevention
- superiority over signatures in all settings
- production-grade zero-knowledge privacy
