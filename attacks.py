"""
attacks.py

Mandatory attack scenario demonstrations for the Kerberos multi-signature system.

Scenarios implemented:
  1. Single malicious authority issuing a forged ticket
  2. Modified ticket payload (tampered content)
  3. Replay of an old partial signature
  4. Leakage of one authority's private signing key
  5. Authority offline scenario
  6. Ticket containing only one valid signature

Run:
  python attacks.py
"""

import json
import os
import sys
import time
import copy

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    schnorr_sign, schnorr_verify,
    schnorr_keygen,
    aes256_cbc_encrypt, aes256_cbc_decrypt,
    generate_aes_key,
    verify_multisig,
    bytes_to_b64, b64_to_bytes,
    int_to_b64, b64_to_int,
    secure_random_int,
    SCHNORR_P, SCHNORR_Q, SCHNORR_G,
    mod_exp
)

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")

PASS = "✅  CONTAINED"
FAIL = "❌  SYSTEM BROKEN"

DIVIDER = "=" * 65


def load_public_registry() -> dict:
    path = os.path.join(KEYS_DIR, "public_key_registry.json")
    with open(path) as f:
        raw = json.load(f)
    for k in raw:
        y = raw[k].get("y")
        if isinstance(y, str):
            raw[k]["y"] = b64_to_int(y)
    return raw


def load_private_key(authority_id: str) -> dict:
    path = os.path.join(KEYS_DIR, f"{authority_id}_private.json")
    with open(path) as f:
        return json.load(f)


def build_legitimate_ticket(client_id="alice", service_id="TGS") -> tuple:
    """Helper: build a valid 2-of-3 signed ticket and return (payload, sigs, registry)."""
    pub_reg = load_public_registry()

    ticket_payload = {
        "client_id":    client_id,
        "service_id":   service_id,
        "issue_time":   int(time.time()),
        "lifetime":     28800,
        "authority_id": "multi",
        "key_version":  1,
        "client_nonce": secure_random_int(1, 2**32)
    }
    msg_bytes = json.dumps(ticket_payload, sort_keys=True).encode()

    sigs = []
    for auth_id in ["AS1", "AS2"]:
        kd = load_private_key(auth_id)
        R, s = schnorr_sign(msg_bytes, kd["x"], auth_id)
        sigs.append({"R": R, "s": s, "authority_id": auth_id})

    return ticket_payload, sigs, pub_reg


# =============================================================================
# Attack 1: Single malicious authority tries to forge a ticket alone
# =============================================================================

def attack_1_single_malicious_authority():
    print(f"\n{DIVIDER}")
    print("ATTACK 1: Single Malicious Authority Forging a Ticket")
    print(DIVIDER)
    print("Scenario: AS1 is compromised. Adversary uses AS1's private key")
    print("          to sign a ticket for 'root' and presents only AS1's signature.")

    pub_reg = load_public_registry()
    kd = load_private_key("AS1")

    forged_payload = {
        "client_id":    "root",          # escalated privilege
        "service_id":   "TGS",
        "issue_time":   int(time.time()),
        "lifetime":     28800,
        "authority_id": "AS1",
        "key_version":  1,
        "client_nonce": 0
    }
    msg_bytes = json.dumps(forged_payload, sort_keys=True).encode()
    R, s = schnorr_sign(msg_bytes, kd["x"], "AS1")

    # Only one signature
    sigs = [{"R": R, "s": s, "authority_id": "AS1"}]

    as_reg = {k: v for k, v in pub_reg.items() if k.startswith("AS")}
    valid, valid_signers = verify_multisig(msg_bytes, sigs, as_reg, threshold=2)

    print(f"\n  Forged by:    AS1 only")
    print(f"  Valid signers: {valid_signers}")
    print(f"  Ticket accepted? {valid}")
    if not valid:
        print(f"  Result: {PASS}")
        print("  Reason: Threshold=2 requires TWO independent signatures.")
        print("          Single authority cannot satisfy the 2-of-3 policy.")
    else:
        print(f"  Result: {FAIL}")


# =============================================================================
# Attack 2: Modified ticket payload (integrity violation)
# =============================================================================

def attack_2_modified_payload():
    print(f"\n{DIVIDER}")
    print("ATTACK 2: Modified Ticket Payload (Tampering)")
    print(DIVIDER)
    print("Scenario: Signatures from AS1+AS2 cover the original payload.")
    print("          Adversary modifies client_id to 'root' AFTER signing.")

    ticket_payload, sigs, pub_reg = build_legitimate_ticket("alice")

    # Signatures cover original payload
    original_msg = json.dumps(ticket_payload, sort_keys=True).encode()

    # Tamper with client_id
    tampered_payload = dict(ticket_payload)
    tampered_payload["client_id"] = "root"
    tampered_msg = json.dumps(tampered_payload, sort_keys=True).encode()

    # Decode sigs for verification
    decoded_sigs = [{"R": s["R"], "s": s["s"], "authority_id": s["authority_id"]}
                    for s in sigs]

    as_reg = {k: v for k, v in pub_reg.items() if k.startswith("AS")}

    # Verify TAMPERED payload against original signatures
    valid, valid_signers = verify_multisig(tampered_msg, decoded_sigs, as_reg, threshold=2)

    print(f"\n  Original client_id:  alice")
    print(f"  Tampered client_id:  root")
    print(f"  Signatures valid on tampered payload? {valid}")
    if not valid:
        print(f"  Result: {PASS}")
        print("  Reason: Schnorr challenge e = H(msg || R || ID).")
        print("          Changing msg changes e, breaking the verification equation.")
    else:
        print(f"  Result: {FAIL}")


# =============================================================================
# Attack 3: Replay of an old partial signature
# =============================================================================

def attack_3_replay_old_signature():
    print(f"\n{DIVIDER}")
    print("ATTACK 3: Replay of Old Partial Signature")
    print(DIVIDER)
    print("Scenario: Adversary captures (R1, s1) from AS1 for an OLD ticket.")
    print("          Tries to reuse it in a NEW ticket.")

    pub_reg = load_public_registry()
    kd1 = load_private_key("AS1")

    # OLD ticket — signed at t=0
    old_payload = {
        "client_id":    "alice",
        "service_id":   "TGS",
        "issue_time":   1000000,   # old timestamp
        "lifetime":     28800,
        "authority_id": "AS1",
        "key_version":  1,
        "client_nonce": 11111111
    }
    old_msg = json.dumps(old_payload, sort_keys=True).encode()
    R_old, s_old = schnorr_sign(old_msg, kd1["x"], "AS1")

    # NEW ticket — different payload (current time, different nonce)
    new_payload = {
        "client_id":    "alice",
        "service_id":   "TGS",
        "issue_time":   int(time.time()),
        "lifetime":     28800,
        "authority_id": "AS1",
        "key_version":  1,
        "client_nonce": 22222222
    }
    new_msg = json.dumps(new_payload, sort_keys=True).encode()

    # Generate fresh AS2 signature for new payload
    kd2 = load_private_key("AS2")
    R2, s2 = schnorr_sign(new_msg, kd2["x"], "AS2")

    # Replay AS1's OLD signature against NEW payload
    mixed_sigs = [
        {"R": R_old, "s": s_old, "authority_id": "AS1"},  # replayed
        {"R": R2,    "s": s2,    "authority_id": "AS2"},   # fresh
    ]

    as_reg = {k: v for k, v in pub_reg.items() if k.startswith("AS")}
    valid, valid_signers = verify_multisig(new_msg, mixed_sigs, as_reg, threshold=2)

    print(f"\n  Old signature: covers issue_time=1000000, nonce=11111111")
    print(f"  New payload:   covers issue_time={new_payload['issue_time']}, nonce=22222222")
    print(f"  AS1 replayed, AS2 fresh. Ticket accepted? {valid}")
    if not valid:
        print(f"  Result: {PASS}")
        print("  Reason: e = H(msg || R || ID) binds signature to EXACT payload.")
        print("          Replayed (R_old, s_old) does not match new_msg hash.")
    else:
        print(f"  Result: {FAIL}")


# =============================================================================
# Attack 4: Leakage of one authority's private key
# =============================================================================

def attack_4_key_leakage():
    print(f"\n{DIVIDER}")
    print("ATTACK 4: Leakage of One Authority's Private Key")
    print(DIVIDER)
    print("Scenario: Adversary steals x1 (AS1's private key).")
    print("          Tries to forge a ticket signed only by AS1 (using leaked key).")

    pub_reg = load_public_registry()
    kd1 = load_private_key("AS1")
    leaked_x1 = kd1["x"]  # adversary has this

    forged_payload = {
        "client_id":    "evil_user",
        "service_id":   "TGS",
        "issue_time":   int(time.time()),
        "lifetime":     28800,
        "authority_id": "AS1",
        "key_version":  1,
        "client_nonce": 99999999
    }
    msg_bytes = json.dumps(forged_payload, sort_keys=True).encode()

    # Adversary can produce a valid AS1 signature using leaked key
    R1, s1 = schnorr_sign(msg_bytes, leaked_x1, "AS1")

    # Adversary does NOT have AS2's key, so produces a random fake signature
    fake_R = mod_exp(SCHNORR_G, secure_random_int(2, SCHNORR_Q - 1), SCHNORR_P)
    fake_s = secure_random_int(2, SCHNORR_Q - 1)

    mixed_sigs = [
        {"R": R1,     "s": s1,     "authority_id": "AS1"},  # genuine
        {"R": fake_R, "s": fake_s, "authority_id": "AS2"},  # forged
    ]

    as_reg = {k: v for k, v in pub_reg.items() if k.startswith("AS")}
    valid, valid_signers = verify_multisig(msg_bytes, mixed_sigs, as_reg, threshold=2)

    print(f"\n  AS1 signature (with leaked key): valid? "
          f"{schnorr_verify(msg_bytes, R1, s1, pub_reg['AS1']['y'], 'AS1')}")
    print(f"  AS2 signature (forged):          valid? "
          f"{schnorr_verify(msg_bytes, fake_R, fake_s, pub_reg['AS2']['y'], 'AS2')}")
    print(f"  Ticket accepted with forged AS2? {valid}")
    if not valid:
        print(f"  Result: {PASS}")
        print("  Reason: Even with one leaked key, adversary cannot forge the SECOND")
        print("          signature without breaking discrete logarithm for AS2.")
    else:
        print(f"  Result: {FAIL}")

    # Sanity: show that with BOTH real keys the ticket IS accepted
    kd2 = load_private_key("AS2")
    R2, s2 = schnorr_sign(msg_bytes, kd2["x"], "AS2")
    real_sigs = [
        {"R": R1, "s": s1, "authority_id": "AS1"},
        {"R": R2, "s": s2, "authority_id": "AS2"},
    ]
    valid2, _ = verify_multisig(msg_bytes, real_sigs, as_reg, threshold=2)
    print(f"\n  [Sanity] With both real keys → accepted? {valid2}  (should be True)")


# =============================================================================
# Attack 5: Authority offline scenario
# =============================================================================

def attack_5_authority_offline():
    print(f"\n{DIVIDER}")
    print("ATTACK 5: One Authority Offline")
    print(DIVIDER)
    print("Scenario: AS1 is offline (unreachable). Client can still authenticate")
    print("          using AS2 + AS3 signatures (system remains live).")

    pub_reg = load_public_registry()

    ticket_payload = {
        "client_id":    "bob",
        "service_id":   "TGS",
        "issue_time":   int(time.time()),
        "lifetime":     28800,
        "authority_id": "multi",
        "key_version":  1,
        "client_nonce": secure_random_int(1, 2**32)
    }
    msg_bytes = json.dumps(ticket_payload, sort_keys=True).encode()

    # AS1 is "offline" — only AS2 and AS3 respond
    sigs = []
    for auth_id in ["AS2", "AS3"]:
        kd = load_private_key(auth_id)
        R, s = schnorr_sign(msg_bytes, kd["x"], auth_id)
        sigs.append({"R": R, "s": s, "authority_id": auth_id})

    as_reg = {k: v for k, v in pub_reg.items() if k.startswith("AS")}
    valid, valid_signers = verify_multisig(msg_bytes, sigs, as_reg, threshold=2)

    print(f"\n  AS1 status:    OFFLINE")
    print(f"  AS2 + AS3:     responded and signed")
    print(f"  Valid signers: {valid_signers}")
    print(f"  Ticket accepted? {valid}")
    if valid:
        print(f"  Result: {PASS}")
        print("  Reason: 2-of-3 scheme tolerates one offline authority.")
        print("          Availability is maintained even under partial failure.")
    else:
        print(f"  Result: {FAIL}")


# =============================================================================
# Attack 6: Ticket with only one valid signature
# =============================================================================

def attack_6_single_signature():
    print(f"\n{DIVIDER}")
    print("ATTACK 6: Ticket with Only One Valid Signature")
    print(DIVIDER)
    print("Scenario: Adversary intercepts AS2's response and discards it,")
    print("          submitting a ticket with only AS1's signature.")

    pub_reg = load_public_registry()
    kd1 = load_private_key("AS1")

    ticket_payload = {
        "client_id":    "charlie",
        "service_id":   "TGS",
        "issue_time":   int(time.time()),
        "lifetime":     28800,
        "authority_id": "AS1",
        "key_version":  1,
        "client_nonce": secure_random_int(1, 2**32)
    }
    msg_bytes = json.dumps(ticket_payload, sort_keys=True).encode()
    R1, s1 = schnorr_sign(msg_bytes, kd1["x"], "AS1")

    # Only one signature submitted
    sigs = [{"R": R1, "s": s1, "authority_id": "AS1"}]

    as_reg = {k: v for k, v in pub_reg.items() if k.startswith("AS")}
    valid, valid_signers = verify_multisig(msg_bytes, sigs, as_reg, threshold=2)

    print(f"\n  Signatures submitted: 1 (AS1 only)")
    print(f"  Valid signers found:  {valid_signers}")
    print(f"  Ticket accepted?      {valid}")
    if not valid:
        print(f"  Result: {PASS}")
        print("  Reason: Policy requires threshold=2. Even a cryptographically")
        print("          valid single signature is INSUFFICIENT.")
    else:
        print(f"  Result: {FAIL}")


# =============================================================================
# Main runner
# =============================================================================

def run_all_attacks():
    print("\n" + DIVIDER)
    print("  KERBEROS MULTI-SIG ATTACK SIMULATION SUITE")
    print(DIVIDER)

    # Check keys exist
    if not os.path.exists(os.path.join(KEYS_DIR, "public_key_registry.json")):
        print("\n[!] Keys not found. Run 'python master_keygen.py' first.")
        sys.exit(1)

    attack_1_single_malicious_authority()
    attack_2_modified_payload()
    attack_3_replay_old_signature()
    attack_4_key_leakage()
    attack_5_authority_offline()
    attack_6_single_signature()

    print(f"\n{DIVIDER}")
    print("  All attack scenarios demonstrated.")
    print(DIVIDER)


if __name__ == "__main__":
    run_all_attacks()
