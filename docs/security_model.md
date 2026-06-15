# Security model: definitions, claims, and reductions

Status: a written security argument for the honest reframe. **These are reduction
*sketches*, not complete or machine-checked proofs** -- the statements are labeled
"Claim" deliberately. The purpose is to define what the gate guarantees, reduce
forgery to standard primitives, and make explicit that the geometry is inessential
to every guarantee. Two independent cryptographer audits informed this revision;
their findings are folded in (independent key/secret corruption, the IND-CCA2
hybrid, key-anonymity, the `proof_commitment` ROM argument, and the cross-swarm
binding gap of Section 5).

Notation: `H` is SHA-256 (modeled as a random oracle; collision-, preimage- and
2nd-preimage-resistant). `Sign/Verify` is Ed25519 (EUF-CMA). `Enc/Dec` is the NaCl
`SealedBox` = X25519 + XSalsa20-Poly1305 with an **ephemeral sender key**, giving
IND-CCA2 **and** key-anonymity (IK-CCA2). `negl` is negligible in `λ`.

---

## 1. The protocol, abstractly: UCOG

We define the **Unanimous Commitment-Opening Gate (UCOG)**. USAG is an
instantiation (Section 6); the geometry is an instantiation choice, not part of
the definition.

`Setup(1^λ, N)` produces, for a swarm with id `swid`:

```text
per agent i in [N]:
    signing key  sk_i  (public verify key vk_i)          -- Ed25519
    secret       s_i  <-$ {0,1}^λ                          -- the per-agent secret
    commitment   C_i = H("commit", swid, i, s_i)          -- public
gateway:
    decryption key sk_G  (public encryption key pk_G)     -- X25519, full entropy
public registry  R = (swid, e, { (i, vk_i, C_i) }_{i in [N]})
```

(`swid` is bound into the signed payload and the fragment commitment in the
implementation, with the verifier rejecting a mismatch; see Section 5 for the
one residual.) A message `m` has a public canonical
encoding; `mid = H("msg", m)`.

**Proof** by agent `i` for message `m`:

```text
open_i  = (i, mid, s_i)
ct_i    = Enc_{pk_G}(open_i)
sigma_i = Sign_{sk_i}( ("proof", swid, i, mid, e) )
pi_i    = (i, e, mid, ct_i, sigma_i)
```

**Verify**(`R, m, {pi_i}`) releases `m` iff **all** hold:

```text
(participation)  exactly the registered active set [N] submits, once each
(per agent i)
  (binding)      pi_i.e = e  and  pi_i.mid = H("msg", m)
  (auth)         Verify_{vk_i}( ("proof", swid, i, mid, e), sigma_i ) = 1
  (opening)      Dec_{sk_G}(ct_i) = (i, mid, s')  with  H("commit", swid, i, s') = C_i
(disjointness)   the opened secrets are pairwise distinct
```

This is exactly `ucog_verify` in `experiments/fair_baselines.py`, and the
non-geometric core of the USAG verifier (`protocol/verifier.py`): registration ->
epoch -> message binding -> signature -> opening -> all-N participation ->
disjointness.

> Model vs code: the definition draws `s_i` uniformly at random. The code derives
> `s_i = H("ucog-secret", seed, i)` (and USAG derives fragments from `seed`), so
> the preimage hardness below is only as strong as `seed` being secret and
> high-entropy. This is a model-instantiation assumption, recorded in Section 5.

---

## 2. Trust model and adversary

```text
TRUSTED:   the gateway/verifier. It holds sk_G and DECRYPTS every ct_i.
UNTRUSTED: the network/observer; corrupted agents.
```

Adversary `A` gets `R`, `pk_G`, `e`, and the oracles:

- `OCorruptSign(i) -> sk_i` and `OCorruptSecret(i) -> s_i`, **independently** (this
  is the key refinement: a stolen signing key and a stolen secret are separate
  capabilities). Let `K = {i : A holds sk_i}`, `S = {i : A holds s_i}`. Agent `i`
  is **fully controlled** iff `i in K and i in S`.
- `OProof(i, m') -> pi_i` for honest messages of `A`'s choice (chosen-message;
  lets `A` observe honest traffic, including sealed `ct_i`).
- `A` does **not** get `sk_G` (gateway trusted; compromise is out of scope).

---

## 3. Integrity: Unanimous Membership-Unforgeability

Informally: a message is released only if, for **every** required agent, a party
holding that agent's secret **and** signing key produced a fresh proof for that
exact message. Stealing only the key, or only the secret, is insufficient.

**Game `G_forge(A, λ)`:**

```text
1. (R, sk_*, s_*, sk_G) <- Setup(1^λ, N)
2. A interacts with OCorruptSign, OCorruptSecret, OProof
3. A outputs (m*, {pi_i*}_{i in [N]})
A WINS iff:
   Verify(R, m*, {pi_i*}) = 1   AND
   ∃ required j that is NOT fully controlled (j ∉ K or j ∉ S)
     for which A never obtained pi_j for m* via OProof(j, m*)
   (i.e. agent j's accepted proof for m* was forged by A)
```

`Adv_forge(A) = Pr[A wins]`.

**Claim 1 (Unforgeability; reduction sketch).** For every PPT `A` making at most
`q` oracle queries,

```text
Adv_forge(A) ≤ N · Adv^{EUF-CMA}_{Ed25519}(B1)
             + N · ( Adv^{preimage}_{H}(B2) + Adv^{2nd-preimage}_{H}(B2)
                     + Adv^{IND-CCA2}_{SealedBox}(B3) )
             + q / 2^{|mid|}
```

negligible in `λ` for `N = poly(λ)` (the bound degrades **linearly in N** through
the slot-guess). The `q/2^{|mid|}` term bounds the chance some queried `m' ≠ m*`
collides under `H("msg",·)`; it may instead be folded into a collision-resistance
term for `H`.

**Proof sketch.** A win is witnessed by a forged proof `pi_j*` of a not-fully-
controlled `j`, accepted for the fresh `m*`. Acceptance forces both **(auth)** and
**(opening)** for `j`. Two cases on *why* `j` is not fully controlled:

- **`j ∉ K` (A lacks `sk_j`).** Then **(auth)** requires a valid `sigma_j*` under
  `vk_j` on `("proof", swid, j, mid*, e)`. `A` never learned `sk_j` and never
  queried `OProof(j, m*)`; and `mid* ≠ mid'` for every queried `m'` except with
  prob `≤ q/2^{|mid|}` (collision of `H("msg",·)`). So `sigma_j*` is an EUF-CMA
  **forgery**. Reduction `B1`: guess `j` (factor `N`), set `vk_j` = the EUF-CMA
  challenge key, **generate all `s_i` itself** (so it can honestly seal every
  `ct_i` for `OProof`), answer `sigma`-queries via the signing oracle, and output
  `(("proof", swid, j, mid*, e), sigma_j*)`. `B1` needs `s_j` (it has it, by
  generating it) but not `sk_j` -- the separation of the signed payload from the
  ciphertext (`_ucog_signed_payload` covers no secret) is what lets this work.

- **`j ∈ K` but `j ∉ S` (A has `sk_j`, lacks `s_j`).** Then `sigma_j*` is
  legitimately producible, so the binding falls on **(opening)**: `ct_j*` must
  decrypt to `s'` with `H("commit", swid, j, s') = C_j`. `A` knows only `C_j` and
  never saw `s_j` (the honest `ct_j` from `OProof` is sealed to the gateway, which
  `A` cannot open). Reduction `B2`: guess `j`, embed the hash-target as `C_j`
  (so `B2` does **not** know `s_j`), and answer `OProof(j, ·)` with a **dummy**
  sealed opening. `A` cannot distinguish the dummy from a real `ct_j` because it
  lacks `sk_G` -- this is exactly an IND-CCA2 hop, charged as `B3`. After the hop,
  `A`'s forged `ct_j*` yields `s'` with `H("commit", swid, j, s') = C_j`: if
  `s' = s_j` a preimage, else a 2nd-preimage. `B2` outputs `s'`.

Union over the two cases and the slot guess gives the bound. ∎ (sketch -- not a
complete proof)

**Lemma 1 (no replay).** A proof from `OProof(j, m')` with `m' ≠ m*` fails
**(binding)** for `m*`, since `pi_j.mid = H("msg", m') ≠ H("msg", m*)` except with
the collision term above. Freshness comes from message-id binding, not from any
per-message geometric transform.

**Corollary (both prongs are independently necessary).** For a not-fully-
controlled agent, release requires breaking **(auth)** *or* (when the key is
stolen but the secret is not) **(opening)** -- i.e., a stolen signing key alone, or
a stolen secret alone, never suffices. This is exactly the keystone result
(`docs/findings_keystone_fair_baseline.md`): `stolen_signing_authority_only`
(valid signature, no secret) fails at opening; `stolen_fragment_only` (secret,
wrong signature) fails at auth. The v0.6 forgery harness corroborates the
reduction's structure: the optimal programmatic attacker (which breaks no
primitive) never wins, while the positive controls that *do* hand it a broken
primitive succeed (`control_geometry_leak` = secret leaked;
`control_gateway_key_compromise` = `sk_G` leaked, defeating the `B3` hop).

---

## 4. Confidentiality of the secret (against the network)

**Claim 2 (transcript hiding, observer model; reduction sketch).** Against any PPT
observer that does **not** hold `sk_G`, the transcript `{pi_i}` is simulatable from
the public `(R, pk_G, e, m)` **together with the public fragment sizes `{k_i}`**, in
the random-oracle model, under IND-CCA2 **and** IK-CCA2 of the sealed box. Hence the
network learns nothing about the *value* of `s_i` beyond `C_i` (and its public
size `k_i`).

**Proof sketch.** Each `pi_i = (i, e, mid, ct_i, sigma_i)` (USAG additionally
carries a cleartext `proof_commitment` field; see below). `sigma_i` is over public
material. For `ct_i`: by IND-CCA2 the simulator replaces the plaintext with zeros,
and by IK-CCA2 the ciphertext reveals no recipient identity; the sealed box still
leaks plaintext **length**, so the simulator is given the public `k_i` (fixed by
setup and bounded by the proof-envelope size band the verifier enforces). For the
USAG `proof_commitment = H("proof_commitment", ..., normalize(T(s_i)))`: this is a
hash of the (transformed) secret and is **not** computable from public data; in
the ROM the simulator samples a uniform string of the right length, indistinguish-
able from the real value since `T(s_i)` is unknown to the observer (a standard-
model version needs `H` to be a hiding commitment). ∎ (sketch)

This is the only confidentiality the construction provides, and the only job the
sealed box does.

---

## 5. What is NOT proven (assumptions and limitations)

```text
- Trusted gateway. The gateway holds sk_G and DECRYPTS every opening, so it learns
  every s_i. The scheme is NOT zero-knowledge and NOT private against the verifier.
  Gateway compromise is catastrophic and out of scope.
- Trusted registry / PKI. R = (swid, e, {(i, vk_i, C_i)}) and pk_G are assumed to
  reach verifier and agents authentically. A man-in-the-middle at registration
  breaks everything; no bootstrapping/identity mechanism is modeled.
- Gateway-key entropy. sk_G must be sampled with full entropy and NOT derived from
  a public seed; likewise the per-agent secrets (the code derives both from `seed`,
  so seed secrecy is load-bearing).
- Cross-swarm replay (now bound; one residual). A per-swarm `swarm_id` is bound
  into the signed payload AND the fragment commitment, and the verifier rejects a
  mismatch (`FailureReason.WRONG_SWARM`); a proof from swarm A is rejected by swarm
  B even under identical keys (`tests/test_cross_swarm_replay.py`). RESIDUAL: the
  default `swarm_id` is derived deterministically from the seed for reproducible
  benchmarks, so two swarms sharing BOTH seed and swarm_id are the same swarm and
  interoperate -- deployments MUST pass a unique `swarm_id`. `pk_G` is still not
  bound into the payload. Anti-replay within a swarm also depends on the verifier's
  in-memory `_seen` set, which `shutdown()` clears.
- Disjointness is not an unforgeability primitive. The disjointness check rules out
  two agents presenting the same secret; it assumes honest, disjoint setup and adds
  no per-agent unforgeability. It is an anti-pooling / liveness check.
- Liveness / availability. Unanimity means one missing or slow agent blocks
  release. Claim 1 is an integrity statement and says nothing about this DoS surface.
- Side channels. The verifier short-circuits and logs failure_stage /
  packets_checked_before_failure / signatures_verified / decryptions_performed,
  revealing which prong failed and how far verification got -- a timing/oracle
  channel useful to a forger. Out of scope; would need constant-work verification.
- All-corrupt case. If every required agent is fully controlled, release is
  "authorized"; the gate cannot judge message content (semantic safety out of scope).
- Model. Definitions are single-round with honest delivery; no network/Byzantine/
  concurrency treatment. The (2nd-)preimage argument is cleanest in the ROM.
```

The single most valuable hardening (future work): replace "encrypt the opening to
the gateway, gateway recomputes the hash" with a real **proof of knowledge** of an
opening of `C_i` (a Merkle/vector-commitment opening, or a Sigma/ZK proof), so the
verifier learns nothing and need not be trusted with `sk_G`. That promotes Claim 2
from the observer model to the verifier model.

---

## 6. Where the geometry is: it contributes no hardness

USAG instantiates UCOG with `s_i` a set of `k` points in `F_p^3` (`p = 257`,
prime; coords drawn in `[0,p)` so the set lies in `F_p^3`) and, inside `ct_i`,
sends `T(s_i)` for a public per-message affine bijection `T` derived from `mid`
(`geometry/transform.py`, which rejects singular matrices so `T` is invertible);
the verifier applies `T^{-1}` before hashing. Because `T` is a public bijection on
`F_p^3` and both the commitment and the verifier hash the **same normalized
(sorted) representation**,

```text
H("commit", i, normalize(T^{-1}(T(s_i)))) = H("commit", i, normalize(s_i)) = C_i
```

so the opening check is identical to UCOG's (verified: `sidecar.py` builds the
commitment over `normalize_coords(coords)`; `verifier.py` recomputes over
`normalize_coords(inverse_transform.apply(coords))`). `T` contributes only
per-message ciphertext variation, which IND-CCA2 randomness and message binding
already provide (Claim 2, Lemma 1). USAG's "assembly" step calls
`assembles_committed_piece_set` (set-membership + disjointness), **not** the
geometric `assembles_exactly` (`geometry/assembly.py`), which is never reached by
the verifier (it is exercised only by `tests/test_assembly_requires_all.py`).

`T(s_i)` does literally appear in one cleartext field -- the per-message
`proof_commitment` -- but it carries no hardness: the verifier ignores its
geometric content and recomputes the commitment from the decrypted coordinates,
and Claim 2 simulates it in the ROM. **So the geometry contributes no hardness to
either claim.** It is an instantiation detail -- the formal counterpart of the
empirical keystone finding. (This is a statement about *this construction*; it is
not a claim that spatial structure can never help any scheme.)

---

## 7. One-line statement

```text
Under a trusted gateway, UCOG (and hence USAG) is argued to be a unanimous
membership-unforgeable message gate: releasing a message requires, for every
agent, a fresh Ed25519 signature AND a SHA-256 commitment opening of a per-agent
secret -- a stolen key alone or a stolen secret alone is insufficient -- with
forgery reducing to Ed25519 EUF-CMA, SHA-256 (2nd-)preimage resistance, and
IND-CCA2 of the sealed box. It hides the secret value from the network (IND-CCA2 +
key-anonymity, in the ROM) but NOT from the verifier, and the 3D/affine "spatial"
structure is inessential to every guarantee in this construction.
```
