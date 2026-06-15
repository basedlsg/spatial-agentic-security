# Cloud SGX runbook (deferred: no SGX on the dev machine)

The dev machine is arm64 macOS without Intel SGX, so the hardware sealing and
attestation cannot run locally. What IS testable locally (and is, in the test suite):
the restricted API surface, one-shot destruction, zeroization, redacted logs, and the
attestation *stub* (`sgx=False`). What needs hardware is sealed enclave memory and a
real remote-attestation quote.

To run the sealed service under Gramine + Intel SGX:

1. Provision an SGX host (e.g. Azure DCsv3 confidential VM, or a bare-metal SGX server).
2. Install Gramine and the Intel SGX DCAP stack; verify `is-sgx-available`.
3. Build the manifest from `spatial_puzzle.manifest.template` (`gramine-manifest`),
   sign it (`gramine-sgx-sign`), and launch (`gramine-sgx`).
4. The service entrypoint runs `SealedService` behind the same restricted op set; the
   host invokes it over the existing pipe/socket client.
5. Obtain and verify the DCAP attestation quote (replaces the local stub); bind the
   enclave measurement to the published commitments.
6. Re-run the partial-compromise and one-shot experiments against the enclaved service
   and compare to the local (process-host) results.

Until step 1-6 are executed, all TEE-confidentiality claims are out of scope; the local
build provides only the software-level policy properties.
