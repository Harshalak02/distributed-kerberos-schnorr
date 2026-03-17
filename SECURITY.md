# SECURITY.md — Security Analysis

**CS5.470 Lab 3: Kerberos Under Partial Compromise**  
IIIT Hyderabad

---

## 1) Why One Compromised Authority Cannot Forge Tickets

### Cryptographic reason
Each authority has its own Schnorr keypair:

- private key: `x_i`
- public key: `y_i = g^{x_i} mod p`

A valid ticket needs **at least 2 valid signatures from distinct authorities** (2-of-3).  
A signature from authority `i` is:

- `R_i = g^{k_i} mod p`
- `e_i = H(m || R_i || ID_i) mod q`
- `s_i = k_i + e_i * x_i mod q`

Verification checks:

`g^{s_i} ≡ R_i * y_i^{e_i} (mod p)`

If only AS1 is compromised, attacker can generate valid `(R_1, s_1)` only for AS1.  
To forge AS2/AS3 signature, attacker needs `x_2` or `x_3`, which reduces to breaking discrete log (infeasible under assumptions).

### System reason
`verify_multisig(...)` only accepts when count of valid distinct signers meets threshold (`>=2`).  
So a single valid signer is rejected.

---

## 2) Why Two Compromised Authorities Break Security

With two compromised authorities (e.g., AS1 + AS2), attacker can produce two valid signatures on any malicious payload.  
That satisfies threshold policy, so ticket passes verification.

This is expected for 2-of-3: secure against **at most one** compromised authority, not two.

---

## 3) Why Requiring Two Independent Signatures Works

Each signature is bound to:

- exact payload bytes `m`
- commitment `R_i`
- authority identity `ID_i`

So:

- payload tampering invalidates signature (`e_i` changes),
- replaying one signer’s old partial on a new payload fails,
- combining one real + one fake signature fails threshold.

This is exactly the containment goal of the assignment.

---

## 4) Nonce Reuse Risks (Critical)

Schnorr uses:

`s = k + e*x mod q`

If same nonce `k` is reused across two different messages:

- `s1 = k + e1*x`
- `s2 = k + e2*x`

Then:

`x = (s1 - s2) * (e1 - e2)^{-1} mod q`

So private key is recoverable immediately.

### Mitigation in implementation
- Nonce is generated with OS CSPRNG via `secure_random_int(...)`.
- New nonce per signature call.
- Nonce not persisted/reused.

---

## 5) Key Leakage Impact

### One leaked authority key
- Attacker can sign as that one authority.
- Still cannot satisfy 2-of-3 alone.
- System remains secure against ticket forgery.

### Two leaked authority keys
- Attacker can forge threshold signatures.
- Security boundary exceeded (expected failure mode).

---

## 6) Replay, Freshness, and Determinism

### Freshness / replay controls
- AS checks request timestamp window and replay cache.
- TGS checks replay on authenticator timestamps.
- Service checks replay/lifetime for service tickets.

### Deterministic payload fields
`issue_time` is set deterministically from request/authenticator timestamps so authorities sign the same logical payload for same request round.  
This improves multisignature composability and avoids mixed-payload signer sets.

---

## 7) Confidentiality in Current Design

Compared to earlier plaintext JSON exchange, current design encrypts critical message bodies:

- AS sends encrypted inner reply (`as_reply_enc`, `as_reply_iv`) to client.
- Client→TGS sends encrypted TGT + encrypted authenticator.
- TGS sends encrypted inner reply (`tgs_reply_enc`, `tgs_reply_iv`) back.
- Client→Service sends encrypted service ticket and encrypted authenticator.

This better matches Kerberos-style secret transport.

---

## 8) Mandatory Attack Scenarios and Expected Outcomes

| Scenario | Expected Result |
|---|---|
| Single malicious authority forging ticket | Rejected (only 1 valid signer) |
| Modified ticket payload | Rejected (signature mismatch) |
| Replay old partial signature | Rejected (old partial not valid on new payload) |
| Leakage of one authority private key | Rejected (cannot forge second signer) |
| Authority offline | Accepted **if** two remaining authorities respond and sign consistently |
| Ticket with only one valid signature | Rejected (threshold not met) |

**Note on offline scenario:** if only one remaining authority is reachable/usable in that run, rejection is correct; scenario must be executed with two live authorities.

---

## 9) Performance Overhead

Relative to single-authority signing:

- cryptographic verification/signing cost increases (~2 signatures needed),
- network fan-out increases (contact multiple authorities),
- bandwidth overhead increases (extra signature fields).

In exchange, compromise resilience is significantly improved.

---

## 10) Security Boundary Summary

**Protected against:**
- one-authority compromise,
- payload tampering,
- single-signature submission,
- replayed partial signatures (when payload/time checks apply).

**Not protected against:**
- two-authority compromise in same tier (AS or TGS),
- transport MITM without TLS in real distributed deployment.

---

## 11) Recommended Production Hardening

1. Use TLS/mTLS for all inter-node channels.
2. Upgrade group/security parameters (≥2048-bit safe prime / stronger curve-based scheme).
3. Add strict clock sync assumptions (NTP + bounded skew policy).
4. Add audit logs for every sign/verify decision.
5. Implement key rotation and revocation policy with version pinning.
6. Isolate private keys (HSM/TPM where possible).
7. Add automated integration tests for all 6 mandatory attacks under controlled node up/down conditions.

---