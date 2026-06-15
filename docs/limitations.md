# Limitations

UCOG (Unanimous Commitment-Opening Gate; code name USAG) v1 is narrow by design. UCOG
releases an inter-agent message only when every required agent submits a fresh,
message-bound, Ed25519-signed proof that opens its per-agent SHA-256 commitment, decrypted
by a trusted gateway. The 3D/affine "spatial" encoding is one instantiation of the
per-agent secret and is treated as an ablated design point; under the implemented checks it
adds no cryptographic hardness over a unanimous commitment-opening gate (see
docs/findings_keystone_fair_baseline.md and docs/security_model.md).

## Protocol Limits

- It authorizes communication membership, not semantic truth.
- It withholds release when an agent is missing or late. One missing or late agent stops
  release for the swarm.
- It assumes the gateway and verifier are trusted.
- It assumes sidecar memory is not accessible to the LLM brain.
- It assumes the host is not compromised.

## Privacy And Custody Limits

USAG v0.4 removes raw puzzle-piece custody from the verifier-visible registry. Setup
creates the full per-agent secret material ("puzzle"), cuts it into sidecar pieces, records
fingerprints (commitments), deletes the full material, deletes the seed, and shuts down. The
verifier checks submitted proofs against fingerprints instead of stored raw fragments.

USAG v0.5 adds an optional process sidecar runtime with a restricted parent-visible API.
This is not a zero-knowledge privacy property or a hardened sandboxing property. The
process sidecar is a local child process, not a container, enclave, or OS isolation
boundary against a compromised host. Sidecars hold raw pieces, and the temporary verifier
decrypts submitted transformed coordinates during a message check. Under these conditions, a
compromised host, gateway process, or sidecar can bypass or forge protocol behavior.

Future privacy progression:

```text
v0.3: trusted verifier checks registered raw fragments
v0.4: verifier stores commitments and checks responses against commitments
v0.5: optional process sidecars with a minimal proof API
future: container/TEE sidecars, Merkle/vector commitments, or zero-knowledge proof of
        valid geometric transform
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
trust. UCOG v1 intentionally starts with finite-grid coordinates and local protocol agents
as one instantiation of the per-agent secret.
