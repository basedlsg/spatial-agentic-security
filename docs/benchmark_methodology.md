# Benchmark Methodology

USAG benchmarks are deterministic protocol-harness runs. They use logical agents, private
sidecars, finite-field geometry, signed encrypted proof packets, a trusted gateway, and a
trusted verifier.

## Default Configuration

```text
N = 8 agents unless the run says otherwise
fragment_size = 16 coordinates per agent
field = F_257^3
max_submissions = 1
direct agent-to-agent communication = disabled
retries = disabled
```

## Attempt Semantics

One attempt is one proposed inter-agent message. A passing attempt means the gateway
released the message. A failed attempt means the gateway blocked it and collapsed the
current swarm epoch.

## Packet Position Semantics

Some scenarios replace one packet. Their names encode where the first bad packet appears:

```text
early  = first agent packet
middle = floor(N / 2)
late   = final agent packet
```

Latency depends on this position because the verifier exits on first failure after
validating preceding packets.

## Failure Stages

The verifier records the stage where a round terminated:

```text
registration
agent_status
epoch_binding
message_binding
challenge_binding
submission_policy
proof_envelope
timeout
signature
decrypt
response_binding
commitment
geometry
assembly
release
```

It also records:

```text
packets_checked_before_failure
signatures_verified
decryptions_performed
geometry_checks_performed
```

For successful honest messages, these counters describe work performed before release.

## Latency

Latency is verifier wall-clock time for one message round. It starts at verifier entry and
ends at first failure or message release. It does not include process startup time.

## Proof Bytes

Proof bytes are serialized JSON proof packet bytes accumulated by the verifier. They
include IDs, epoch, message/challenge hashes, proof commitment, encrypted fragment
response, Ed25519 signature, submission metadata, JSON syntax, and base64 overhead.

## Resource Use

RSS memory comes from `resource.getrusage(RUSAGE_SELF).ru_maxrss` and is converted to MB
for the current platform.

## Reporting Rules

Report zero observed unauthorized passes as an observation under a stated configuration,
not as impossibility.
