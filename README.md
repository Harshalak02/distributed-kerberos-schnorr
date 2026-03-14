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
kerberos_project/
├── master_keygen.py   — Generate Schnorr key pairs for all 6 authorities
├── crypto_utils.py    — All cryptographic primitives (manual implementation)
├── as_node.py         — Authentication Server (AS1/AS2/AS3)
├── tgs_node.py        — Ticket Granting Server (TGS1/TGS2/TGS3)
├── service_server.py  — Service Server (file_server / print_server)
├── client.py          — Kerberos client
├── attacks.py         — Attack scenario demonstrations
├── README.md
├── SECURITY.md
└── keys/              — Generated key files (created by master_keygen.py)
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

### Step 4 — Run Attack Demonstrations

```bash
python attacks.py
```

This runs all 6 attack scenarios **without** a live network (purely local crypto).

### Step 5 — Self-Test Cryptographic Primitives

```bash
python crypto_utils.py
```

---

## Schnorr Multi-Signature Protocol Summary

### Key Generation (per authority)
```
x_i  ← rand(Zq)          # private key
y_i  = g^{x_i} mod p     # public key
```

### Signature Generation (message m, authority i)
```
k_i  ← rand(Zq)                      # fresh nonce — NEVER reuse
R_i  = g^{k_i} mod p                 # commitment
e_i  = H(m || R_i || ID_i) mod q     # challenge
s_i  = k_i + e_i * x_i  mod q        # response
```
Signature: `(R_i, s_i)`

### Verification
```
e_i  = H(m || R_i || ID_i) mod q
g^{s_i} ≡ R_i · y_i^{e_i}  (mod p)  # must hold
```

### Multi-Signature Policy
A ticket is **valid** only if **≥ 2 independent** (R_i, s_i) pairs verify successfully
against their respective public keys y_i.

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

## Cryptographic Domain Parameters

- **Group**: 1024-bit MODP (RFC 2409 Group 2), safe prime `p`, `q = (p-1)/2`, `g = 2`
- **Hash**: SHA-256
- **Symmetric**: AES-256-CBC with manual PKCS#7 padding
- **RNG**: `os.urandom()` (OS-level CSPRNG)
