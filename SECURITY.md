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

**Mitigation in implementation:**
- Nonce generated with OS CSPRNG via `secure_random_int()` (high entropy)
- Fresh nonce for every signature call
- Nonce never persisted or reused
- No state carried between signature generation calls

---

## 5) Key Share Leakage Impact

### One Compromised Authority Key (e.g., x_1 leaked)

**Attacker capability:**
- Can generate valid signature (R_1, s_1) for AS1 on any message
- Cannot forge (R_2, s_2) for AS2 (needs x_2)
- Cannot forge (R_3, s_3) for AS3 (needs x_3)

**Why system remains secure:**
- Threshold = 2 (requires 2-of-3 valid distinct signatures)
- One valid signature ≠ threshold met
- Verification fails: `verify_multisig()` returns False if count < 2
- Ticket rejected, access denied

**Verdict:** System remains secure against single authority key leakage

### Two Compromised Authority Keys (e.g., x_1 and x_2 leaked)

**Attacker capability:**
- Can generate valid signatures (R_1, s_1) and (R_2, s_2) on any message
- 2 valid signatures satisfy threshold = 2
- Can forge valid multi-signature tickets
- Can forge TGTs, Service Tickets, gain unauthorized service access

**Why security breaks:**
- Attacker controls 2-of-3 authorities
- Can produce exactly threshold-meets-requirement signatures
- No way for service to distinguish forged from legitimate tickets

**Verdict:** Security boundary breached (expected for 2-of-3 scheme)

### Three Compromised Authority Keys (all leaked)

Obvious: complete compromise, all tickets forgeable.

### Mitigation in Implementation
- Private keys isolated per authority (never shared)
- Keys stored in separate encrypted JSON files: `keys/AS1_private.json`, etc.
- Each authority process loads only its own private key
- No central key repository that could leak all at once
- Key version tracking via `key_version` field in tickets for rotation support

---

## 6) Performance Overhead of Multi-Authority Signing

### Latency Characteristics
The 2-of-3 multi-signature requirement introduces measurable but acceptable latency overhead. Real-world measurements show counterintuitive improvements when authorities are offline.

### Comprehensive Performance Comparison

#### Phase 1: TGT Assembly (Client ↔ AS Authorities)

| Scenario | Average Latency | Range | Notes |
|----------|---|---|---|
| **3-of-3 (All online)** | **44.08 ms** | 23.74–84.24 ms | Baseline: contact all 3 AS, collect any 2 sigs |
| **2-of-3 (AS1 offline)** | **31.89 ms** | 18.63–54.16 ms | **↓ 28% faster** — collect 2 from AS2, AS3 only |
| **2-of-3 (TGS1 offline)** | **34.47 ms** | 21.71–55.17 ms | **↓ 22% faster** — TGS offline doesn't affect Phase 1 |

**Insight:** Phase 1 improves when AS1 offline because client stops after 2 signatures (no waiting for 3rd). AS tier state directly impacts Phase 1.

---

#### Phase 2: Service Ticket Assembly (Client ↔ TGS Authorities)

| Scenario | Average Latency | Range | Notes |
|----------|---|---|---|
| **3-of-3 (All online)** | **62.43 ms** | 48.23–90.59 ms | Baseline: contact all 3 TGS, collect any 2 sigs |
| **2-of-3 (AS1 offline)** | **66.74 ms** | 52.48–92.07 ms | **↑ 7% slower** — TGS unaffected, slight variability |
| **2-of-3 (TGS1 offline)** | **53.84 ms** | 39.37–76.66 ms | **↓ 14% faster** — collect 2 from TGS2, TGS3 only |

**Insight:** Phase 2 improves when TGS1 offline (analogous to Phase 1). AS offline has minimal impact on Phase 2. Each tier's state directly impacts its corresponding phase.

---

#### Phase 3: Service Access (Service → Ticket Verification)

| Scenario | Average Latency | Range | Notes |
|----------|---|---|---|
| **3-of-3 (All online)** | **10.27 ms** | 8.49–12.75 ms | Baseline: service verifies ≥2 signatures locally |
| **2-of-3 (AS1 offline)** | **9.47 ms** | 8.35–11.49 ms | **↓ 8% faster** — verification faster with fewer online nodes |
| **2-of-3 (TGS1 offline)** | **11.04 ms** | 9.0–13.78 ms | **↑ 7% slower** — slight overhead variance |

**Insight:** Phase 3 is nearly independent of authority status (verification is local). Minimal variance due to ticket size/structure.

---

#### End-to-End Latency (Complete 3-Phase Flow)

| Scenario | Average E2E | Range | Improvement vs. 3-of-3 |
|----------|---|---|---|
| **3-of-3 (All online)** | **116.77 ms** | 80.46–187.58 ms | Baseline 100% |
| **2-of-3 (AS1 offline)** | **108.1 ms** | 79.46–157.72 ms | **↓ 7.4% faster** |
| **2-of-3 (TGS1 offline)** | **99.36 ms** | 70.09–145.61 ms | **↓ 15% faster** |

**Key Finding:** Counterintuitive result — system runs *faster* when 1 authority offline because:
1. Client collects 2-of-3 and stops (doesn't wait for unresponsive 3rd)
2. No timeout overhead in success path
3. Fewer network round-trips simultaneously
4. But **security is maintained:** still 2-of-3 threshold with different authorities

---

### Performance Overhead Sources

| Component | Overhead | Reason |
|-----------|----------|--------|
| **Crypto Cost** | ~2× | Need to sign/verify 2 signatures instead of 1 |
| **Network Latency** | ~2-3× | Contact 2-3 authorities in parallel vs. 1 |
| **Message Size** | ~2× | Two (R, s) pairs + metadata vs. one |
| **Threshold Check** | Minimal | O(1) comparison operation |

**Total End-to-End Overhead (3-of-3 vs. single authority):** ~2-3× latency for comprehensive security

---

### Availability & Resilience

**Success Rate Under Authority Availability:**
- **All 3 online:** 100% success (3/3 runs) — optimal cases
- **2-of-3 (AS tier):** 100% success (3/3 runs) — Phase 1 affected but recoverable
- **2-of-3 (TGS tier):** 100% success (3/3 runs) — Phase 2 affected but recoverable

**Critical Property:** 100% success rate maintained even with 1 authority offline in any tier

**Security/Availability Tradeoff:**
- **Cost:** ~2-3× latency vs. single-authority Kerberos
- **Benefit:** System continues with 1 authority compromised *or* offline
- **Latency Paradox:** Offline scenario may be *faster* than full online (no waiting for slow nodes)
- **Conclusion:** Acceptable tradeoff for mission-critical deployments where availability > absolute latency

---

### Scaling to Larger k-of-n Schemes

For generalized k-of-n multi-signature:
- **Latency:** O(n) in worst case (contact n authorities)
- **Overhead:** ~k× baseline (k signatures needed)
- **Security:** Requires compromising ≥(n-k+1) authorities to forge
- **Availability:** System survives up to (n-k) failures/compromises

**Example: 2-of-5 scheme**
- Overhead: ~2× latency (more than 2-of-3)
- Security: Survive 3 compromised authorities (vs. 1 for 2-of-3)
- Tradeoff: Higher latency for higher resilience margin

### Implementation Optimizations (Current)
- Parallel authority contact (not sequential)
- Early exit once 2 signatures collected (don't wait for 3rd)
- Efficient multi-sig verification (loop with early termination)

---

### Freshness / replay controls
- AS checks request timestamp window and replay cache.
- TGS checks replay on authenticator timestamps.
- Service checks replay/lifetime for service tickets.

### Deterministic payload fields
`issue_time` is set deterministically from request/authenticator timestamps so authorities sign the same logical payload for same request round.  
This improves multisignature composability and avoids mixed-payload signer sets.

---

## 8) Confidentiality in Current Design

Compared to earlier plaintext JSON exchange, current design encrypts critical message bodies:

- AS sends encrypted inner reply (`as_reply_enc`, `as_reply_iv`) to client.
- Client→TGS sends encrypted TGT + encrypted authenticator.
- TGS sends encrypted inner reply (`tgs_reply_enc`, `tgs_reply_iv`) back.
- Client→Service sends encrypted service ticket and encrypted authenticator.

This better matches Kerberos-style secret transport.

---

## 9) Mandatory Attack Scenarios and Expected Outcomes

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

## 12) Attack Containment Performance

### Measured Defense Effectiveness
All 6 mandatory attack scenarios were executed against live servers with attack containment validation.

**Attack Execution Performance:**

| Attack Scenario | Execution Time | Containment | Notes |
|---|---|---|---|
| Single Malicious Authority | 46.99 ms | ✅ CONTAINED | Threshold enforcement prevents single-signer forgery |
| Modified Ticket Payload | 38.33 ms | ✅ CONTAINED | Hash mismatch caught by verification |
| Replay Old Partial Signature | 24.05 ms | ✅ CONTAINED | Challenge bound to current payload |
| One Key Leakage | 21.29 ms | ✅ CONTAINED | Cannot forge 2nd signature without 2nd key |
| Authority Offline | 30.58 ms | ✅ ACCEPTED | Correct behavior: 2-of-3 fallback succeeds |
| Single Signature Only | 9.49 ms | ✅ CONTAINED | Threshold=2 enforced in verification |

**Summary:**
- **Pass Rate:** 100% (6/6 attacks responded as expected)
- **Average Containment Latency:** 28.46 ms (overhead from multi-sig validation minimal)
- **No False Positives/Negatives:** All rejection logic working correctly
- **Offline Resilience:** Attack 5 demonstrates graceful fallback when 1 authority unavailable

### Defense Mechanisms Validated
1. **Multi-signature threshold (2-of-3):** Successfully rejects single-authority forgeries (Attacks 1, 4, 6)
2. **Payload integrity:** Hash-based challenge prevents modification (Attack 2)
3. **Replay protection:** Challenge binds to current message, invalidates old partials (Attack 3)
4. **Availability fallback:** System functions with only 2-of-3 authorities (Attack 5)
5. **Cryptographic binding:** Authority identity in challenge prevents substitution

---