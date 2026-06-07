# Limitations

USAG v1 is narrow by design.

## Protocol Limits

- It authorizes communication membership, not semantic truth.
- It sacrifices availability. One missing or late agent collapses the swarm.
- It assumes the gateway and verifier are trusted.
- It assumes sidecar memory is not accessible to the LLM brain.
- It assumes the host is not compromised.

## Privacy Limits

The v1 verifier holds trusted fragment records and decrypts transformed coordinates.
This is acceptable for a protocol simulator, but not for a production privacy claim.

Future privacy progression:

```text
v1: trusted verifier checks registered raw fragments
v2: verifier stores commitments and checks responses against commitments
v3: Merkle or vector commitments
v4: zero-knowledge proof of valid geometric transform
```

## Research Limits

Do not claim:

- foolproof security
- better-than-signatures without measured evidence
- misinformation prevention
- resistance to compromised gateway or host
- real-agent containment without container/network experiments

## Practical Limits

Starting with meshes, ZK, or thousands of live LLM agents would make results harder to
trust. USAG v1 intentionally starts with finite-grid coordinates and local protocol agents.
