# Security Policy

USAG v1 is a research simulator. Do not deploy it as a production access-control system.

## Security Assumptions

- The gateway and verifier are trusted.
- Sidecar private keys and fragments are not exposed to the LLM brain.
- Agents cannot communicate except through the gateway.
- The host running the simulator is trusted.
- Logs and reports are generated only through repository code.

## Known Limitations

- If the host is compromised, sidecar memory and verifier state may be readable.
- If the verifier or gateway is compromised, the protocol is broken.
- If all original sidecars willingly authorize a malicious message, USAG will release it.
- USAG v1 uses a trusted verifier that can compare against registered raw fragments.
- Repeated transformed-coordinate observations may leak information if raw decrypted
  payloads are exposed outside the verifier.

## Reporting Issues

When reporting a security issue, include:

- the exact command or test scenario
- `runs/<run_id>/config.yaml` if applicable
- `metrics.json`
- the relevant redacted `events.jsonl` lines

Do not include raw fragments, private keys, decrypted proof payloads, or secrets.
