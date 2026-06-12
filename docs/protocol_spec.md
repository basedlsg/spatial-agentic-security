# USAG Protocol Specification

USAG stands for **Unanimous Spatial Assembly Gate**.

Subtitle:

> Message-specific spatial proof-of-membership for fail-closed AI swarms.

## Swarm Birth

1. Spawn `N` logical agents.
2. Generate a canonical finite 3D grid `F_p^3`.
3. Setup creates the full puzzle.
4. Setup cuts the puzzle into `N` disjoint private coordinate fragments.
5. Setup gives each sidecar exactly one fragment.
6. Setup records each fragment fingerprint.
7. Setup deletes the full puzzle.
8. Setup deletes the seed.
9. Setup shuts down.
10. Register every agent with verifier-visible metadata:
   - `agent_id`
   - sidecar verify key
   - fragment commitment
   - fragment size
   - finite-field modulus
   - proof-size envelope
   - timeout envelope
   - `max_submissions = 1`

The logical agent receives no raw fragment, no sidecar key, no full puzzle, and no other
agent fragments.

## Message Flow

For every attempted communication:

1. The sender submits message `M` to the gateway.
2. The gateway freezes and canonicalizes `M`.
3. The gateway computes `message_id`.
4. The gateway computes:

   ```text
   challenge = H(canonical_message, sender_id, receiver_id, epoch, nonce)
   ```

5. The challenge generates an invertible affine transform over `F_p^3`.
6. Every sidecar receives the frozen message and challenge.
7. Every sidecar submits exactly one signed proof packet.
8. A temporary verifier starts for the message.
9. The verifier validates identity, epoch, message, challenge, budget, timing, signature,
   encrypted response, fingerprint-backed geometry, and full participation.
10. The temporary verifier deletes its memory and shuts down.
11. If all `N` original committed pieces are present and valid, the message is released.
12. Otherwise, the message is blocked and the swarm collapses.

## Geometry

The private fragment remains stable across messages. Each message challenge changes how
the fragment fits:

```text
T_C(x, y, z) = A_C * [x, y, z] + b_C mod p
```

`A_C` is a challenge-derived invertible `3x3` matrix and `b_C` is a challenge-derived
translation vector.

## Proof Packet

Each sidecar returns:

```json
{
  "agent_id": "agent_042",
  "epoch": "epoch_0007",
  "message_id": "hash_of_frozen_message",
  "challenge_id": "hash_of_challenge",
  "proof_version": "v1",
  "submission_number": 1,
  "proof_commitment": "...",
  "encrypted_fragment_response": "...",
  "signature": "...",
  "submitted_at_ms": 12.4
}
```

`encrypted_fragment_response` contains the message-bound transformed coordinates and is
sealed to the verifier. It is not written to logs.

## Verification Order

The verifier checks:

1. swarm is active
2. agent is registered
3. epoch matches
4. message hash matches
5. challenge hash matches
6. submission number is `1`
7. no duplicate submission exists
8. packet size is inside envelope
9. packet arrived inside timeout
10. sidecar signature is valid
11. encrypted response decrypts and parses
12. response binds to agent, message, and challenge
13. proof commitment matches transformed coordinates
14. inverse-transformed coordinates hash to the registered fragment commitment
15. every original agent submitted
16. all submitted transformed pieces are disjoint

## Failure Behavior

On any failure:

```text
message blocked
failing agent ejected when identifiable
swarm state = COLLAPSED
round logged
no retry
```

No partial quorum exists in v1.
