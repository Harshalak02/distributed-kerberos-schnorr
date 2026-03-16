"""
client.py

Kerberos client that:
  1. Contacts all 3 AS nodes and collects TGT partial signatures
  2. Assembles a TGT once ≥ 2 valid signatures are collected
  3. Contacts all 3 TGS nodes and collects service-ticket partial signatures
  4. Assembles a service ticket once ≥ 2 valid signatures are collected
  5. Presents the service ticket to the service server

Usage:
  python client.py <client_id> <service_id>
  python client.py alice file_server
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    schnorr_verify,
    aes256_cbc_decrypt, aes256_cbc_encrypt,
    verify_multisig,
    bytes_to_b64, b64_to_bytes,
    int_to_b64, b64_to_int,
    secure_random_int,
    generate_aes_key
)

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")

# Server configuration
AS_NODES = {
    "AS1": "http://127.0.0.1:5001",
    "AS2": "http://127.0.0.1:5002",
    "AS3": "http://127.0.0.1:5003",
}
TGS_NODES = {
    "TGS1": "http://127.0.0.1:6001",
    "TGS2": "http://127.0.0.1:6002",
    "TGS3": "http://127.0.0.1:6003",
}
SERVICE_NODES = {
    "file_server":  "http://127.0.0.1:7001",
    "print_server": "http://127.0.0.1:7002",
}

# Minimum valid signatures required
THRESHOLD = 2


# ---------------------------------------------------------------------------
# Low-level HTTP helpers
# ---------------------------------------------------------------------------

def http_post(url: str, payload: dict, timeout: int = 30) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={
            "Content-Type":   "application/json",
            "Content-Length": str(len(data)),
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return json.loads(body)
        except Exception:
            raise RuntimeError(f"HTTP {e.code}: {body}")


def http_get(url: str, timeout: int = 5) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def load_public_registry() -> dict:
    path = os.path.join(KEYS_DIR, "public_key_registry.json")
    with open(path) as f:
        raw = json.load(f)
    # Decode y values
    for k in raw:
        y = raw[k].get("y")
        if isinstance(y, str):
            raw[k]["y"] = b64_to_int(y)
        # else already int
    return raw


def derive_client_key(client_id: str) -> bytes:
    import hashlib
    return hashlib.sha256((client_id + "kerberos-demo-key").encode()).digest()


def derive_tgs_cluster_key() -> bytes:
    import hashlib
    return hashlib.sha256(b"tgs-cluster-shared-demo-key").digest()


def derive_service_key(service_id: str) -> bytes:
    import hashlib
    return hashlib.sha256((service_id + "-service-demo-key").encode()).digest()


# ---------------------------------------------------------------------------
# Phase 1: Obtain TGT (collect ≥2 AS signatures)
# ---------------------------------------------------------------------------

def obtain_tgt(client_id: str, public_registry: dict) -> dict:
    """
    Contact each AS node and collect partial TGT signatures.
    Returns assembled TGT dict once threshold is reached.
    """
    print(f"\n{'='*60}")
    print(f"[Client] Phase 1: Obtaining TGT for client={client_id}")
    print(f"{'='*60}")

    nonce = secure_random_int(1, 2**32)
    timestamp = int(time.time())

    auth_request = {
        "client_id":  client_id,
        "service_id": "TGS",
        "timestamp":  timestamp,
        "nonce":      nonce
    }

    collected_sigs = []          # list of {R, s, authority_id}
    canonical_payload_bytes = None
    session_key_enc = None
    session_key_iv = None
    canonical_payload = None     # use the first consistent payload

    for auth_id, base_url in AS_NODES.items():
        print(f"\n[Client] Contacting {auth_id} at {base_url}...")
        try:
            resp = http_post(f"{base_url}/authenticate", auth_request)
        except (urllib.error.URLError, OSError) as e:
            print(f"[Client] {auth_id} unreachable: {e}")
            continue

        if "error" in resp:
            print(f"[Client] {auth_id} returned error: {resp['error']}")
            continue

        as_reply_enc = b64_to_bytes(resp.get("as_reply_enc", ""))
        as_reply_iv = b64_to_bytes(resp.get("as_reply_iv", ""))

        client_key = derive_client_key(client_id)
        try:
            inner = aes256_cbc_decrypt(client_key, as_reply_enc, as_reply_iv)
            inner_resp = json.loads(inner.decode("utf-8"))
        except Exception as e:
            print(f"[Client] {auth_id} malformed encrypted response: {e}")
            continue

        # Extract and verify the signature
        sig = inner_resp.get("signature", {})
        ticket_payload = inner_resp.get("ticket_payload", {})

        R = b64_to_int(sig["R"])
        s = b64_to_int(sig["s"])
        a_id = sig["authority_id"]

        # Verify the signature against the public key
        y = public_registry.get(a_id, {}).get("y")
        if y is None:
            print(f"[Client] No public key for {a_id}, skipping.")
            continue

        msg_bytes = json.dumps(ticket_payload, sort_keys=True).encode("utf-8")
        if not schnorr_verify(msg_bytes, R, s, y, a_id):
            print(f"[Client] {auth_id} signature INVALID — skipping.")
            continue

        payload_bytes = json.dumps(ticket_payload, sort_keys=True).encode("utf-8")
        if canonical_payload_bytes is None:
            canonical_payload_bytes = payload_bytes
        elif payload_bytes != canonical_payload_bytes:
            print(f"[Client] {auth_id} payload mismatch with canonical payload — skipping.")
            continue

        print(f"[Client] {auth_id} signature VALID ✓")
        collected_sigs.append(sig)        # store encoded (b64) versions

        if session_key_enc is None:
            session_key_enc = inner_resp.get("session_key_enc")
            session_key_iv = inner_resp.get("session_key_iv")
            canonical_payload = ticket_payload

        if len(collected_sigs) >= THRESHOLD:
            print(f"\n[Client] Threshold ({THRESHOLD}) reached. TGT assembled.")
            break

    if len(collected_sigs) < THRESHOLD:
        raise RuntimeError(
            f"Could not collect enough valid TGT signatures "
            f"({len(collected_sigs)}/{THRESHOLD}). Check that ≥{THRESHOLD} AS nodes are running."
        )

    tgt = {
        "ticket_payload":  canonical_payload,
        "signatures":      collected_sigs,
        "session_key_enc": session_key_enc,
        "session_key_iv":  session_key_iv
    }
    return tgt


# ---------------------------------------------------------------------------
# Phase 2: Obtain Service Ticket (collect ≥2 TGS signatures)
# ---------------------------------------------------------------------------

def obtain_service_ticket(client_id: str, requested_service_id: str,
                           tgt: dict, public_registry: dict) -> dict:
    """
    Present TGT to TGS nodes and collect ≥2 service-ticket signatures.
    """
    print(f"\n{'='*60}")
    print(f"[Client] Phase 2: Obtaining Service Ticket for service={requested_service_id}")
    print(f"{'='*60}")

    # Decrypt session key (to be used for service session key decryption)
    client_key = derive_client_key(client_id)
    session_key = aes256_cbc_decrypt(
        client_key,
        b64_to_bytes(tgt["session_key_enc"]),
        b64_to_bytes(tgt["session_key_iv"])
    )

    authenticator = {
        "client_id": client_id,
        "timestamp": int(time.time()),
        "nonce":     secure_random_int(1, 2**32)
    }

    tgs_key = derive_tgs_cluster_key()
    tgt_bytes = json.dumps(tgt, sort_keys=True).encode("utf-8")
    tgt_enc, tgt_iv = aes256_cbc_encrypt(tgs_key, tgt_bytes)

    auth_bytes = json.dumps(authenticator, sort_keys=True).encode("utf-8")
    auth_enc, auth_iv = aes256_cbc_encrypt(session_key, auth_bytes)

    tgs_request = {
        "tgt_enc":              bytes_to_b64(tgt_enc),
        "tgt_iv":               bytes_to_b64(tgt_iv),
        "authenticator_enc":    bytes_to_b64(auth_enc),
        "authenticator_iv":     bytes_to_b64(auth_iv),
        "requested_service_id": requested_service_id
    }

    collected_sigs = []
    canonical_st_payload_bytes = None
    canonical_st_payload = None
    ssk_enc = None
    ssk_iv = None

    for tgs_id, base_url in TGS_NODES.items():
        print(f"\n[Client] Contacting {tgs_id} at {base_url}...")
        try:
            resp = http_post(f"{base_url}/grant_service_ticket", tgs_request)
        except (urllib.error.URLError, OSError) as e:
            print(f"[Client] {tgs_id} unreachable: {e}")
            continue

        if "error" in resp:
            print(f"[Client] {tgs_id} returned error: {resp['error']}")
            continue

        tgs_reply_enc = b64_to_bytes(resp.get("tgs_reply_enc", ""))
        tgs_reply_iv = b64_to_bytes(resp.get("tgs_reply_iv", ""))
        try:
            tgs_plain = aes256_cbc_decrypt(session_key, tgs_reply_enc, tgs_reply_iv)
            inner_resp = json.loads(tgs_plain.decode("utf-8"))
        except Exception as e:
            print(f"[Client] {tgs_id} malformed encrypted response: {e}")
            continue

        sig = inner_resp.get("signature", {})
        st_payload = inner_resp.get("service_ticket_payload", {})
        a_id = sig["authority_id"]

        # Verify TGS signature
        R = b64_to_int(sig["R"])
        s = b64_to_int(sig["s"])
        y = public_registry.get(a_id, {}).get("y")
        if y is None:
            print(f"[Client] No public key for {a_id}, skipping.")
            continue

        st_msg_bytes = json.dumps(st_payload, sort_keys=True).encode("utf-8")
        if not schnorr_verify(st_msg_bytes, R, s, y, a_id):
            print(f"[Client] {tgs_id} signature INVALID — skipping.")
            continue

        if canonical_st_payload_bytes is None:
            canonical_st_payload_bytes = st_msg_bytes
        elif st_msg_bytes != canonical_st_payload_bytes:
            print(f"[Client] {tgs_id} payload mismatch with canonical service ticket payload — skipping.")
            continue

        print(f"[Client] {tgs_id} signature VALID ✓")
        collected_sigs.append(sig)

        if canonical_st_payload is None:
            canonical_st_payload = st_payload
            ssk_enc = inner_resp.get("service_session_key_enc")
            ssk_iv  = inner_resp.get("service_session_key_iv")

        if len(collected_sigs) >= THRESHOLD:
            print(f"\n[Client] Threshold ({THRESHOLD}) reached. Service ticket assembled.")
            break

    if len(collected_sigs) < THRESHOLD:
        raise RuntimeError(
            f"Could not collect enough valid service-ticket signatures "
            f"({len(collected_sigs)}/{THRESHOLD})."
        )

    service_ticket = {
        "payload":                   canonical_st_payload,
        "signatures":                collected_sigs,
        "service_session_key_enc":   ssk_enc,
        "service_session_key_iv":    ssk_iv,
    }
    service_session_key = aes256_cbc_decrypt(
        session_key, b64_to_bytes(ssk_enc), b64_to_bytes(ssk_iv)
    )
    return service_ticket, service_session_key


# ---------------------------------------------------------------------------
# Phase 3: Present service ticket to service server
# ---------------------------------------------------------------------------

def access_service(client_id: str, service_id: str,
                   service_ticket: dict, service_session_key: bytes) -> dict:
    print(f"\n{'='*60}")
    print(f"[Client] Phase 3: Accessing service={service_id}")
    print(f"{'='*60}")

    base_url = SERVICE_NODES.get(service_id)
    if base_url is None:
        raise ValueError(f"Unknown service: {service_id}. "
                         f"Known: {list(SERVICE_NODES.keys())}")

    authenticator = {
        "client_id": client_id,
        "timestamp": int(time.time())
    }

    auth_bytes = json.dumps(authenticator, sort_keys=True).encode("utf-8")
    auth_enc, auth_iv = aes256_cbc_encrypt(service_session_key, auth_bytes)

    service_key = derive_service_key(service_id)
    service_ticket_for_service = {
        "payload": service_ticket["payload"],
        "signatures": service_ticket["signatures"],
        "service_session_key": bytes_to_b64(service_session_key),
    }
    ticket_bytes = json.dumps(service_ticket_for_service, sort_keys=True).encode("utf-8")
    ticket_enc, ticket_iv = aes256_cbc_encrypt(service_key, ticket_bytes)

    request = {
        "service_ticket_enc":    bytes_to_b64(ticket_enc),
        "service_ticket_iv":     bytes_to_b64(ticket_iv),
        "authenticator_enc":     bytes_to_b64(auth_enc),
        "authenticator_iv":      bytes_to_b64(auth_iv)
    }

    resp = http_post(f"{base_url}/access", request)
    return resp


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def run_client(client_id: str, service_id: str):
    print(f"\n[Client] Starting Kerberos authentication for client='{client_id}' → service='{service_id}'")

    public_registry = load_public_registry()

    # Phase 1
    tgt = obtain_tgt(client_id, public_registry)

    # Phase 2
    service_ticket, service_session_key = obtain_service_ticket(
        client_id, service_id, tgt, public_registry
    )

    # Phase 3
    result = access_service(client_id, service_id, service_ticket, service_session_key)

    print(f"\n{'='*60}")
    print(f"[Client] Service Response:")
    print(json.dumps(result, indent=2))
    print(f"{'='*60}")

    if result.get("status") == "ACCESS GRANTED":
        print(f"\n[Client] ✅  ACCESS GRANTED to '{service_id}' as '{client_id}'")
    else:
        print(f"\n[Client] ❌  Access denied: {result}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python client.py <client_id> <service_id>")
        print("  e.g. python client.py alice file_server")
        sys.exit(1)

    run_client(sys.argv[1], sys.argv[2])
