# Threat Model

UCOG (Unanimous Commitment-Opening Gate; code name USAG) is positioned to cover
membership and communication authorization for a fixed swarm born in a single epoch. It
does not evaluate whether message content is true.

UCOG releases an inter-agent message only when every required agent submits a fresh,
message-bound, Ed25519-signed proof that opens its per-agent SHA-256 commitment,
decrypted by a trusted gateway. The 3D/affine "spatial" encoding is one instantiation of
the per-agent secret and is treated as an ablated design point; under the implemented
checks it adds no cryptographic hardness (see
docs/findings_keystone_fair_baseline.md and docs/security_model.md).

## In Scope

Under the stated conditions, UCOG v1 was exercised against:

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
- replay of a valid proof into a different swarm (one with a distinct `swarm_id`),
  even when the other swarm reuses agent IDs, epoch, and key material

## Out Of Scope

UCOG v1 was not exercised against, and does not address:

- host compromise that reads sidecar memory
- gateway or verifier compromise
- all original sidecars approving a malicious message
- raw fragment leakage through modified logs
- prompt injection that can directly inspect sidecar memory
- network availability failures in a real deployment

## Security Posture

The system is implemented to fail closed. Each of the following conditions is rejected
by the verifier:

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

In the implementation, any one of these blocks the message, ejects the failing agent
when identifiable, and collapses the current swarm epoch.

## Core Behavior

A message is released only when every required agent opens its per-agent commitment
(message-bound and signed) for that exact message challenge. The verifier's "assembly"
step checks set-membership and disjointness of the opened secrets, not geometric tiling
(the geometric `assembles_exactly` is never called by the verifier).

## Non-Claims

UCOG does not claim:

- message truth
- misinformation detection
- universal attack prevention
- superiority over signatures in all settings
- production-grade zero-knowledge privacy

## Attack Coverage Table

| Attack | Current status | Expected result | Notes |
| --- | ---: | --- | --- |
| New unregistered agent | tested | fail | `unregistered_agent` |
| Impersonates registered ID without key | tested | fail | `wrong_signature` |
| Valid signature, wrong geometry | tested | fail | `wrong_geometry` |
| Replay old proof | tested | fail | `wrong_message_hash` |
| Replay proof into another swarm | tested | fail | `wrong_swarm` (needs unique `swarm_id` per deployment) |
| Wrong message proof | tested | fail | `wrong_message_hash` |
| Duplicate submission | tested | fail | `duplicate_submission` |
| Late packet | tested | fail | `late_packet` |
| Missing packet | tested | fail | `missing_packet` |
| Stolen signing key only | tested | fail | rejected at commitment opening (no valid per-agent secret) |
| Stolen fragment only | tested | fail | rejected at signature check |
| Stolen key plus fragment | documented | may pass | out of scope without sidecar hardening |
| Compromised gateway | documented | catastrophic | trusted verifier assumption |
| All agents approve malicious content | documented | may pass | semantic safety out of scope |
