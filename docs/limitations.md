# Limitations

USAG v1 is narrow by design.

## Protocol Limits

- It authorizes communication membership, not semantic truth.
- It sacrifices availability. One missing or late agent collapses the swarm.
- It assumes the gateway and verifier are trusted.
- It assumes sidecar memory is not accessible to the LLM brain.
- It assumes the host is not compromised.

## Privacy And Custody Limits

USAG v0.4 removes raw puzzle-piece custody from the verifier-visible registry. Setup
creates the full puzzle, cuts it into sidecar pieces, records fingerprints, deletes the
full puzzle, deletes the seed, and shuts down. The verifier checks submitted proofs
against fingerprints instead of stored raw fragments.

This is not a zero-knowledge privacy claim. The local simulator still co-locates gateway,
sidecars, and verifier in one process graph for testability. Sidecars hold raw pieces,
and the temporary verifier decrypts submitted transformed coordinates during a message
check. A compromised host, gateway process, or sidecar can still bypass or forge protocol
behavior.

Future privacy progression:

```text
v0.3: trusted verifier checks registered raw fragments
v0.4: verifier stores commitments and checks responses against commitments
v0.5: sidecar process isolation
future: Merkle/vector commitments or zero-knowledge proof of valid geometric transform
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
