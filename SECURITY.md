# SECURITY.md — Security Analysis

**CS5.470 Lab 3: Kerberos Under Partial Compromise**
IIIT Hyderabad

---

## 1. Why One Compromised Authority Cannot Forge Tickets

### Mathematical Argument

Each authority i holds a Schnorr key pair (xᵢ, yᵢ = g^{xᵢ} mod p).

A valid service ticket requires signatures from **at least 2 distinct authorities**.
Each signature (Rᵢ, sᵢ) satisfies:

```
g^{sᵢ} ≡ Rᵢ · yᵢ^{eᵢ}  (mod p)
where eᵢ = H(msg || Rᵢ || IDᵢ) mod q
```

An adversary who compromises AS1 can produce valid signatures for **AS1 only**.
To satisfy the 2-of-3 threshold, the adversary must also produce a valid signature
for AS2 (or AS3). This requires computing:

```
s₂ = k₂ + e₂ · x₂  mod q
```

Without knowing x₂, the adversary must solve the Discrete Logarithm Problem (DLP)
to find x₂ = log_g(y₂) mod p. Under standard cryptographic assumptions (hardness of
DLP in a 1024-bit group), this is computationally infeasible.

### Protocol-Level Argument

Even if the adversary guesses an s₂ and R₂, the verifier re-derives:
```
e₂ = H(msg || R₂ || ID₂)
```
and checks whether `g^{s₂} ≡ R₂ · y₂^{e₂} (mod p)`.

For a random (R₂, s₂) pair not derived from x₂, this equation holds with probability
at most 1/q ≈ 2⁻¹⁰²³, which is negligible.

**Conclusion**: One compromised authority provides no advantage to an adversary trying
to forge a second-authority signature.

---

## 2. Why Two Compromised Authorities Break Security

If authorities ASᵢ and ASⱼ are both compromised (adversary holds xᵢ and xⱼ),
the adversary can:

1. Choose any payload (e.g., `client_id = "root"`, arbitrary service)
2. Compute valid (Rᵢ, sᵢ) using xᵢ
3. Compute valid (Rⱼ, sⱼ) using xⱼ
4. Present both signatures → threshold=2 satisfied → ticket accepted

This is expected and correct — the 2-of-3 scheme guarantees security only against
**at most one** compromised authority. It does **not** protect against a Byzantine
majority (2 or more bad actors).

**Mitigation in production**: Use threshold t-of-n with t > n/2 for stronger guarantees.

---

## 3. Why 2 Independent Schnorr Signatures Prevent Single-Authority Forgery

### Binding to Message

The challenge `eᵢ = H(msg || Rᵢ || IDᵢ)` ties the signature to:
- The exact message content (ticket payload)
- The specific commitment Rᵢ chosen for this signature
- The identity of the authority (IDᵢ)

Changing any part of msg produces a completely different eᵢ, invalidating the signature.

### Independence of Authorities

The two required signatures use different private keys (x₁, x₂), different commitments
(R₁, R₂), different challenges (e₁, e₂), and different identities (ID₁, ID₂).

There is **no algebraic relationship** between the two signatures that an adversary could
exploit to derive one from the other. They are independently and separately verified
against distinct public keys y₁ and y₂.

### Why This Is Sufficient

The security reduces to the hardness of DLP: an adversary who knows only one private key
(and all public keys) has no computational shortcut to forge the second signature.
This is proven in the random oracle model under the DLP assumption.

---

## 4. Nonce Reuse Risks

### Why Nonce Reuse Is Catastrophic in Schnorr Signatures

In Schnorr, the response is `s = k + e·x mod q`.

If the same nonce k is reused for two different messages m₁ and m₂:
```
s₁ = k + e₁ · x  mod q
s₂ = k + e₂ · x  mod q
```

Subtracting:
```
s₁ - s₂ = (e₁ - e₂) · x  mod q
x = (s₁ - s₂) · (e₁ - e₂)⁻¹  mod q
```

The private key x is **immediately recovered** with two signature/message pairs and
standard modular arithmetic — no need to break DLP at all.

### Mitigation in This Implementation

- Every call to `schnorr_sign()` generates k using `secure_random_int(2, q-1)`,
  which draws from `os.urandom()` (OS-level CSPRNG).
- k is a local variable, never stored or reused.
- There is no stateful nonce counter that could wrap around or be reset.

**The implementation is nonce-safe by construction.**

---

## 5. Key Share Leakage Impact

### Single Key Leaked (ASᵢ compromised)

Impact is **limited**:
- Adversary can produce valid ASᵢ signatures on arbitrary payloads.
- Cannot forge signatures from the other two authorities.
- Cannot alone satisfy the 2-of-3 threshold.
- **System remains secure**.

Recommended response:
1. Revoke the compromised authority's key (increment key_version).
2. Issue new key pair for that authority.
3. Service servers check key_version ≥ MINIMUM_KEY_VERSION to reject old tickets.

### Two Keys Leaked (ASᵢ and ASⱼ compromised)

Impact is **total for the AS layer**:
- Adversary can forge tickets for any client, any service.
- The TGS multi-signature layer is now the only defence, which may also be undermined
  if the corresponding TGS keys are also leaked.
- **System is broken at the AS level**.

This is the expected security boundary of a 2-of-3 scheme.

### Comparison to Classical Kerberos

In classical Kerberos, leaking the AS master key immediately breaks the entire system
for every user. In this 2-of-3 scheme, leaking one key has **zero impact on valid ticket
forgery**. This is a strict security improvement.

---

## 6. Performance Overhead of Multi-Authority Signing

### Theoretical Analysis

| Operation | Single-Authority | 2-of-3 Multi-Sig |
|-----------|-----------------|------------------|
| AS contacts | 1 | 2–3 (parallel) |
| Schnorr sign ops | 1 mod-exp | 2–3 mod-exps |
| Schnorr verify ops | 1 | 2–3 |
| Network RTTs (sequential) | 1 | 2–3 |
| Network RTTs (parallel) | 1 | 1 (all contacted simultaneously) |

### Practical Observations

**Signature generation** (mod-exp in a 1024-bit group): ~1–5 ms per operation on modern hardware.
Signing 3 authorities ≈ 3–15 ms total, negligible compared to network latency.

**Verification** is approximately the same cost as generation (2 mod-exps per verification).
Verifying 2 signatures ≈ 2× single-sig cost, still sub-millisecond for the crypto itself.

**Network overhead**: The dominant cost. In a datacenter setting (1 ms RTT), contacting
3 AS nodes sequentially adds ~3 ms. If contacted in parallel (as in a production
implementation), the overhead is one extra RTT beyond single-authority.

**Ticket size**: Each Schnorr signature is ~256 bytes (R + s, both 128-byte big ints).
Two signatures add ~512 bytes. Negligible for ticket transport.

### Conclusion

The security improvement from 2-of-3 multi-sig comes at **low overhead**:
- ~2× cryptographic cost (acceptable)
- ~2–3× network contacts (parallelisable)
- Negligible bandwidth increase

The trade-off strongly favours multi-authority signing for any system where authority
compromise is a realistic threat.

---

## 7. Threat Model Summary

| Attack | Prevented? | Mechanism |
|--------|-----------|-----------|
| Single authority forges ticket | ✅ Yes | Threshold=2, DLP hardness |
| Payload tampering | ✅ Yes | H(msg‖R‖ID) binds to exact bytes |
| Signature replay | ✅ Yes | Payload includes fresh nonce + timestamp |
| One key leaked | ✅ Yes | Forging second sig requires DLP |
| Two keys leaked | ❌ No | Scheme boundary — expected behaviour |
| AES key guessing | ✅ Yes | AES-256 with OS-RNG keys |
| Nonce reuse | ✅ Yes | OS CSPRNG, no stored state |
| Key version rollback | ✅ Yes | Service checks key_version |
| One authority offline | ✅ Yes | 2-of-3 tolerates one offline node |

---

## 8. Recommended Hardening for Production

1. **Upgrade to 2048-bit group** for 112-bit security level.
2. **Replace HTTP with TLS (mTLS)** — all inter-process communication should be
   authenticated and encrypted.
3. **Distribute key generation** using a distributed key ceremony (no single party
   generates all keys).
4. **Use a hardware security module (HSM)** for each authority's private key storage.
5. **Implement key rotation** with automated revocation and re-issuance.
6. **Enforce freshness** with shorter ticket lifetimes and require online validation.
7. **Audit logging** — every signing event should be logged to an append-only store.
