# Kerberos Under Partial Compromise using Schnorr Multi-Signatures

**CS5.470 – System and Network Security, Lab Assignment 3**
IIIT Hyderabad

---

## Overview

This project implements a Kerberos-inspired distributed authentication system that remains
secure even when **one** of the three authentication authorities is compromised. Security is
enforced through a **2-of-3 Schnorr multi-signature** scheme — no single authority can issue
a valid ticket alone.

---

## Architecture

```
  ┌──────────┐    Phase 1 (TGT)    ┌────┐ ┌────┐ ┌────┐
  │  Client  │ ──────────────────► │AS1 │ │AS2 │ │AS3 │
  │          │ ◄── partial sigs ── └────┘ └────┘ └────┘
  │          │
  │          │    Phase 2 (ST)     ┌─────┐ ┌─────┐ ┌─────┐
  │          │ ──────────────────► │TGS1 │ │TGS2 │ │TGS3 │
  │          │ ◄── partial sigs ── └─────┘ └─────┘ └─────┘
  │          │
  │          │    Phase 3          ┌────────────────┐
  │          │ ──────────────────► │  Service Server│
  └──────────┘                     └────────────────┘
```

Each authority is an **independent process** on its own port.
Authorities do **NOT** share private keys.

---

## File Structure

```
distributed-kerberos-schnorr/
├── master_keygen.py      — Generate Schnorr key pairs for all 6 authorities
├── crypto_utils.py       — All cryptographic primitives (manual implementation)
├── as_node.py            — Authentication Server nodes (AS1/AS2/AS3, ports 5001-5003)
├── tgs_node.py           — Ticket Granting Server nodes (TGS1/TGS2/TGS3, ports 6001-6003)
├── service_server.py     — Service Server with multi-sig ticket validation
├── client.py             — Kerberos client orchestrating 3-phase authentication
├── attacks.py            — 6 mandatory attack scenarios (local crypto testing)
├── perf_test.py          — Performance benchmarking (phase latencies, availability)
├── attack_perf_test.py   — Attack scenario performance (containment timing)
├── README.md             — This file
├── SECURITY.md           — Comprehensive security analysis (12 sections)
├── start_servers.sh      — Shell script to start all authorities
└── keys/                 — Generated key files (created by master_keygen.py)
    ├── AS1_private.json, AS1_public.json
    ├── AS2_private.json, AS2_public.json
    ├── AS3_private.json, AS3_public.json
    ├── TGS1_private.json, TGS1_public.json
    ├── TGS2_private.json, TGS2_public.json
    ├── TGS3_private.json, TGS3_public.json
    └── public_key_registry.json
```

---

## Prerequisites

```bash
pip install pycryptodome
```

Python 3.8+ required. Only `pycryptodome` (for AES block cipher) and standard library are used.
All Schnorr signature logic is manually implemented.

---

## Quick Start

### Step 1 — Generate Keys

```bash
python master_keygen.py
```

This creates `keys/AS1_private.json`, `keys/AS2_private.json`, ... and
`keys/public_key_registry.json`.

### Step 2 — Start All Servers (6 terminals or background processes)

```bash
# Terminal 1-3: AS nodes
python as_node.py AS1 5001
python as_node.py AS2 5002
python as_node.py AS3 5003

# Terminal 4-6: TGS nodes
python tgs_node.py TGS1 6001
python tgs_node.py TGS2 6002
python tgs_node.py TGS3 6003

# Terminal 7-8: Service servers
python service_server.py file_server  7001
python service_server.py print_server 7002
```

### Step 3 — Run Client

```bash
python client.py alice file_server
python client.py bob   print_server
```

Expected output shows:
- Phase 1: TGT with ≥2 AS signatures
- Phase 2: Service ticket with ≥2 TGS signatures
- Phase 3: `ACCESS GRANTED`

### Step 4 — Run Networked Attack Demonstrations (Against Live Servers)

```bash
python attacks.py
```

This runs all 6 attack scenarios against live authentication servers, demonstrating that:
- Attack 1-4, 6: Malicious attempts are **rejected** (proper containment)
- Attack 5: Offline authority scenario **accepted** (2-of-3 fallback works)

**Note:** attacks.py in local mode (no servers) performs pure cryptographic testing.
With servers running, attacks are networked and real-world validated.

### Step 5 — Performance Benchmarking (Phase Latencies)

```bash
python perf_test.py
```

Measures real-world latencies across:
- Phase 1: TGT assembly (client gathers ≥2 AS signatures)
- Phase 2: Service ticket assembly (client gathers ≥2 TGS signatures)
- Phase 3: Service access (ticket verification with ≥2 signatures)
- End-to-end latency (complete 3-phase flow)

Scenarios:
- All 3 authorities online (baseline)
- AS1 offline (2-of-3 fallback)
- TGS1 offline (2-of-3 fallback)

Results saved to `perf_results.json` with per-run and aggregate statistics.

### Step 6 — Attack Scenario Performance (Containment Latency)

```bash
python attack_perf_test.py
```

Measures real-world attack containment performance:
- Time to execute each attack scenario
- Whether rejection/containment happens as expected
- Skipped cases if servers intentionally offline
- Per-attack timing and defense mechanism validation

Results saved to `attack_perf_results.json` with detailed per-attack metrics.

### Step 7 — Self-Test Cryptographic Primitives

```bash
python crypto_utils.py
```

Validates all manual cryptographic implementations:
- Schnorr keygen (private/public key generation)
- Schnorr signing (commitment, challenge, response)
- Schnorr verification (discrete log binding)
- Multi-signature threshold checking (≥2 valid distinct signers)
- AES-256-CBC encryption/decryption
- PKCS#7 padding (manual implementation)
- SHA-256 hashing

---

## Implementation Summary

### Security Model
- **Threat Model:** At most 1 of 3 authorities compromised (AS tier and TGS tier independent)
- **Defense:** 2-of-3 Schnorr multi-signature required for ticket validity
- **Guarantee:** No single compromised authority can forge valid tickets
- **Fallback:** System survives 1 authority offline (2-of-3 threshold still met)

### Cryptographic Foundation
- **Manual Schnorr:** No external asymmetric crypto libraries; all logic implemented from first principles
- **Multi-Signature:** Threshold verification requires ≥2 valid distinct authority signatures
- **Payload Binding:** Each signature binds to exact client ID, service ID, timestamp, lifetime
- **Nonce Freshness:** New cryptographically-random nonce per signature (prevents discrete log recovery)
- **Symmetric Encryption:** AES-256-CBC with manual PKCS#7 padding for ticket encryption

### Distributed Architecture
- **6 Independent Server Processes:** 3 AS + 3 TGS (no shared state or keys)
- **Parallel Authority Contact:** Client simultaneously requests signatures from all authorities
- **Early Exit Policy:** Client stops after collecting 2-of-3 signatures (no unnecessary waits)
- **Per-Authority Keys:** Each authority has unique keypair; private keys never leave their process
- **Replay Protection:** Per-authority in-memory cache tracking (client_id, timestamp) pairs

### Testing & Validation
- **6 Mandatory Attacks:** All scenarios executed and contained (100% pass rate)
- **Performance Benchmarking:** Real-world latencies measured across 3 scenarios
- **Attack Performance:** Containment validation with per-attack timing (9.5–47 ms range)
- **Availability Testing:** Verified 100% success rate with 1 authority offline

### Documentation
See [SECURITY.md](SECURITY.md) for comprehensive analysis:
- Why one compromised authority cannot forge tickets (Sections 1-3)
- Nonce reuse risks and mitigation (Section 4)
- Key leakage impact analysis (Section 5)
- Performance overhead breakdown (Section 6)
- Attack containment validation (Sections 9, 12)

---

## Performance Results

Benchmark results from real execution (3 runs per scenario):

### Scenario 1: All Authorities Online (3-of-3)
| Metric | Average | Min | Max |
|--------|---------|-----|-----|
| **Phase 1 (TGT)** | 44.08 ms | 23.74 ms | 84.24 ms |
| **Phase 2 (ST)** | 62.43 ms | 48.23 ms | 90.59 ms |
| **Phase 3 (Access)** | 10.27 ms | 8.49 ms | 12.75 ms |
| **End-to-End** | 116.77 ms | 80.46 ms | 187.58 ms |
| **Success Rate** | **100%** (3/3) | — | — |

### Scenario 2: AS1 Offline (2-of-3 Fallback)
| Metric | Average | Min | Max |
|--------|---------|-----|-----|
| **Phase 1 (TGT)** | 31.89 ms | 18.63 ms | 54.16 ms |
| **Phase 2 (ST)** | 66.74 ms | 52.48 ms | 92.07 ms |
| **Phase 3 (Access)** | 9.47 ms | 8.35 ms | 11.49 ms |
| **End-to-End** | 108.1 ms | 79.46 ms | 157.72 ms |
| **Success Rate** | **100%** (3/3) | — | — |

**Key Finding:** Latency *improves* when one AS is offline (faster timeout, fewer signatures to wait for). System continues operating seamlessly.

### Scenario 3: TGS1 Offline (2-of-3 Fallback)
| Metric | Average | Min | Max |
|--------|---------|-----|-----|
| **Phase 1 (TGT)** | 34.47 ms | 21.71 ms | 55.17 ms |
| **Phase 2 (ST)** | 53.84 ms | 39.37 ms | 76.66 ms |
| **Phase 3 (Access)** | 11.04 ms | 9.0 ms | 13.78 ms |
| **End-to-End** | 99.36 ms | 70.09 ms | 145.61 ms |
| **Success Rate** | **100%** (3/3) | — | — |

**Key Finding:** Phase 2 latency reduces with one TGS offline (only 2 signatures collected). Availability preserved.

### Performance Summary
- **Baseline (all online):** ~117 ms end-to-end
- **With 1 offline:** ~99-108 ms (actually faster due to reduced coordination overhead)
- **Success rate:** 100% in all scenarios (including authority offline cases)
- **Overhead vs. single-authority Kerberos:** ~2-3× latency for 2-of-3 requirement

---

## Schnorr Multi-Signature Protocol Summary

### 2-of-3 Security Model
- Tickets require **at least 2 valid signatures from distinct authorities**
- Single authority compromise cannot forge valid tickets
- Single authority offline still allows 2-of-3 to succeed
- Two compromised authorities can forge (security boundary)

### Key Generation (per authority i)
```
x_i  ← rand(Zq)                    # Private key (unique per authority, never shared)
y_i  = g^{x_i} mod p               # Public key (published in public_key_registry.json)
```

### Signature Generation (message m, authority i)
```
k_i  ← secure_random_int(q)        # Fresh nonce — generated per signature, NEVER reused
R_i  = g^{k_i} mod p               # Commitment (publicly visible)
e_i  = H(m || R_i || ID_i) mod q  # Challenge (binds to payload and authority identity)
s_i  = k_i + e_i * x_i  mod q     # Response (only valid with correct x_i)
```
**Signature:** `(R_i, s_i)` — cryptographic proof that authority i endorsed message m

### Signature Verification (verify signature by authority i on message m)
```
e_i  = H(m || R_i || ID_i) mod q           # Recompute challenge
CheckPoint: g^{s_i} ≡ R_i · y_i^{e_i} (mod p)  # Verification equation must hold
```
**Why it works:**
- If authority i signed: knows x_i, so equation holds
- If attacker fabricated: doesn't know x_i, breaking discrete log, equation fails

### Multi-Signature Threshold Policy
```
ticket_valid = count_valid_distinct_signers >= 2
```
- Collect signatures from all 3 authorities (in parallel)
- For each signature, verify independently
- Count how many distinct authorities produced valid signatures
- **Accept only if count ≥ 2**

**Implementation:** `verify_multisig(signatures, public_key_registry)` in crypto_utils.py
- Loops through signatures array
- Calls `schnorr_verify()` for each
- Counts valid distinct authorities
- Returns True only if count ≥ 2

---

## Network Ports

| Authority | Type | Port |
|-----------|------|------|
| AS1       | AS   | 5001 |
| AS2       | AS   | 5002 |
| AS3       | AS   | 5003 |
| TGS1      | TGS  | 6001 |
| TGS2      | TGS  | 6002 |
| TGS3      | TGS  | 6003 |
| file_server | Service | 7001 |
| print_server | Service | 7002 |

---

## Ticket Structure

```json
{
  "client_id":    "alice",
  "service_id":   "file_server",
  "issue_time":   1700000000,
  "lifetime":     3600,
  "authority_id": "multi",
  "key_version":  1,
  "signatures": [
    {"R": "<b64>", "s": "<b64>", "authority_id": "TGS1"},
    {"R": "<b64>", "s": "<b64>", "authority_id": "TGS2"}
  ],
  "service_session_key_enc": "<b64 AES-256-CBC encrypted>",
  "service_session_key_iv":  "<b64>"
}
```

---

## Attack Scenarios (attacks.py)

| # | Scenario | Expected Result |
|---|----------|----------------|
| 1 | Single malicious authority forges ticket | Rejected (threshold=2) |
| 2 | Modified ticket payload | Rejected (hash mismatch) |
| 3 | Replay of old partial signature | Rejected (challenge binds to payload) |
| 4 | One authority's private key leaked | Rejected (cannot forge second sig) |
| 5 | One authority offline | Accepted (2 remaining authorities suffice) |
| 6 | Ticket with only one valid signature | Rejected (threshold=2 enforced) |

---

## Attack Performance Benchmark Results

Benchmark executed against live authentication servers measuring real-world attack containment latency.

### Overall Statistics
| Metric | Value |
|--------|-------|
| **Total Attacks** | 6 |
| **Pass Rate** | 100% (6/6) |
| **Contained** | 5 |
| **Accepted** | 1 (Attack 5 - offline scenario) |
| **Average Latency** | 28.46 ms |
| **Min Latency** | 9.49 ms |
| **Max Latency** | 46.99 ms |

### Per-Attack Timing & Containment
| Attack | Time (ms) | Expected | Actual | Status |
|--------|-----------|----------|--------|--------|
| 1: Single Malicious Authority | 46.99 | REJECTED | CONTAINED | ✅ |
| 2: Modified Ticket Payload | 38.33 | REJECTED | CONTAINED | ✅ |
| 3: Replay Old Partial Sig | 24.05 | REJECTED | CONTAINED | ✅ |
| 4: One Key Leakage | 21.29 | REJECTED | CONTAINED | ✅ |
| 5: Authority Offline | 30.58 | ACCEPTED | ACCEPTED | ✅ |
| 6: Single Signature Only | 9.49 | REJECTED | CONTAINED | ✅ |

### Key Findings
- **100% attack containment:** All malicious scenarios properly rejected
- **Attack 5 resilience:** Offline authority scenario accepted as expected (2-of-3 fallback working)
- **No skipped cases:** All attacks executed successfully against live servers
- **No errors:** All attack detection mechanisms functioning correctly
- **Latency range:** 9.49–46.99 ms per attack (minimal overhead)

## Cryptographic Domain Parameters

### MODP Group
- **Standard:** RFC 2409 Group 2 (1024-bit safe prime)
- **Safe Prime:** p = 2q + 1 where q is prime
- **Generator:** g = 2 (multiplicative generator of order q)
- **Subgroup:** All operations mod p in multiplicative group of order q

### Hash Function
- **Algorithm:** SHA-256 (via Python `hashlib`)
- **Usage:** Challenge computation e_i = H(m || R_i || ID_i) mod q
- **Output:** 256 bits, truncated to q-bit challenge

### Symmetric Encryption
- **Cipher:** AES-256-CBC (pycryptodome library)
- **Key Size:** 256 bits (32 bytes)
- **Mode:** Cipher Block Chaining (IV per ciphertext)
- **Padding:** PKCS#7 (manual implementation, not dependent on library)
- **Usage:** Encrypt tickets/replies from authorities to client

### Random Number Generation
- **Source:** `os.urandom()` — OS-level CSPRNG
- **Usage:** Fresh nonce per Schnorr signature via `secure_random_int(q)`
- **Critical:** Nonce reuse breaks security (allows private key recovery)

### Ticket Lifetime Parameters
- **TGT Lifetime:** 8 hours (28,800 seconds)
- **Service Ticket Lifetime:** 1 hour (3,600 seconds)
- **Timestamp Window:** ±5 seconds (replay protection tolerance)

**For detailed security analysis, see [SECURITY.md](SECURITY.md)**
