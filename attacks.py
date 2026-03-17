"""
attacks.py

Mandatory attack scenario demonstrations for the Kerberos multi-signature system,
executed over LIVE AS/TGS services via HTTP requests.

Scenarios implemented:
  1. Single malicious authority issuing forged ticket
  2. Modified ticket payload
  3. Replay of old partial signature
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
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    schnorr_sign,
    aes256_cbc_encrypt, aes256_cbc_decrypt,
    secure_random_int,
    bytes_to_b64, b64_to_bytes,
    int_to_b64,
    SCHNORR_G, SCHNORR_Q, SCHNORR_P,
    mod_exp,
)

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")

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

PASS = "✅  CONTAINED"
FAIL = "❌  SYSTEM BROKEN"
SKIP = "⚠️  SKIPPED"
DIVIDER = "=" * 72


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def http_post(url: str, payload: dict, timeout: int = 8) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Content-Length": str(len(data))},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return json.loads(body)
        except Exception:
            return {"error": f"HTTP {e.code}: {body}"}
    except urllib.error.URLError as e:
        return {"error": f"URLError: {e.reason}"}
    except OSError as e:
        return {"error": f"OSError: {e}"}


def derive_client_key(client_id: str) -> bytes:
    import hashlib
    return hashlib.sha256((client_id + "kerberos-demo-key").encode()).digest()


def derive_tgs_cluster_key() -> bytes:
    import hashlib
    return hashlib.sha256(b"tgs-cluster-shared-demo-key").digest()


def decode_as_reply(client_id: str, as_response: dict) -> dict:
    enc = b64_to_bytes(as_response["as_reply_enc"])
    iv = b64_to_bytes(as_response["as_reply_iv"])
    pt = aes256_cbc_decrypt(derive_client_key(client_id), enc, iv)
    return json.loads(pt.decode("utf-8"))


def load_private_key(authority_id: str) -> dict:
    path = os.path.join(KEYS_DIR, f"{authority_id}_private.json")
    with open(path) as f:
        return json.load(f)


def find_tgs_base() -> str:
    for _, base in TGS_NODES.items():
        r = http_post(f"{base}/grant_service_ticket", {})
        if isinstance(r, dict) and "URLError" not in str(r.get("error", "")):
            return base
    return ""


def build_tgs_request_from_ticket(ticket: dict, client_id: str, session_key: bytes,
                                  requested_service: str = "file_server") -> dict:
    tgs_key = derive_tgs_cluster_key()
    tgt_bytes = json.dumps(ticket, sort_keys=True).encode("utf-8")
    tgt_enc, tgt_iv = aes256_cbc_encrypt(tgs_key, tgt_bytes)

    authenticator = {
        "client_id": client_id,
        "timestamp": int(time.time()),
        "nonce": secure_random_int(1, 2**32),
    }
    auth_bytes = json.dumps(authenticator, sort_keys=True).encode("utf-8")
    auth_enc, auth_iv = aes256_cbc_encrypt(session_key, auth_bytes)

    return {
        "tgt_enc": bytes_to_b64(tgt_enc),
        "tgt_iv": bytes_to_b64(tgt_iv),
        "authenticator_enc": bytes_to_b64(auth_enc),
        "authenticator_iv": bytes_to_b64(auth_iv),
        "requested_service_id": requested_service,
    }


def request_as_partial(client_id: str, authority_id: str, timestamp: int, nonce: int,
                       service_id: str = "TGS", allow_replay_retry: bool = True) -> dict | None:
    base = AS_NODES[authority_id]
    req = {
        "client_id": client_id,
        "service_id": service_id,
        "timestamp": timestamp,
        "nonce": nonce,
    }

    attempts = 2 if allow_replay_retry else 1
    for attempt in range(attempts):
        req["timestamp"] = timestamp + attempt
        resp = http_post(f"{base}/authenticate", req)

        if "error" in resp:
            err = str(resp["error"])
            if "Replay detected" in err and attempt + 1 < attempts:
                continue
            print(f"  [{authority_id}] failed: {err}")
            return None

        try:
            return decode_as_reply(client_id, resp)
        except Exception as e:
            print(f"  [{authority_id}] decrypt/parse failed: {e}")
            return None

    return None


def collect_as_partials(client_id: str, required: int = 2, preferred: list[str] | None = None):
    ts = int(time.time())
    nonce = secure_random_int(1, 2**32)

    order = preferred[:] if preferred else list(AS_NODES.keys())
    for aid in AS_NODES:
        if aid not in order:
            order.append(aid)

    partials = []
    for aid in order:
        p = request_as_partial(client_id, aid, ts, nonce)
        if p is not None:
            partials.append((aid, p))
        if len(partials) >= required:
            break
    return partials


def build_ticket_from_as_partials(client_id: str, partial_pairs: list) -> tuple:
    if not partial_pairs:
        raise ValueError("No AS partials")

    buckets = {}
    for _, p in partial_pairs:
        payload = p["ticket_payload"]
        pbytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        key = bytes_to_b64(pbytes)
        b = buckets.setdefault(key, {"payload": payload, "partials": []})
        b["partials"].append(p)

    best = max(buckets.values(), key=lambda x: len(x["partials"]))
    partials = best["partials"]

    canonical_payload = best["payload"]
    signatures = [p["signature"] for p in partials]

    sk_enc = partials[0]["session_key_enc"]
    sk_iv = partials[0]["session_key_iv"]
    session_key = aes256_cbc_decrypt(
        derive_client_key(client_id), b64_to_bytes(sk_enc), b64_to_bytes(sk_iv)
    )

    ticket = {
        "ticket_payload": canonical_payload,
        "signatures": signatures,
        "session_key_enc": sk_enc,
        "session_key_iv": sk_iv,
    }
    return ticket, session_key


def print_tgs_result(result: dict, expect_reject: bool):
    accepted = "error" not in result
    print("  TGS response:", json.dumps(result, indent=2))
    print("  Ticket accepted by TGS?", accepted)
    if expect_reject:
        print("  Result:", PASS if not accepted else FAIL)
    else:
        print("  Result:", PASS if accepted else FAIL)


# ---------------------------------------------------------------------------
# Attacks
# ---------------------------------------------------------------------------

def attack_1_single_malicious_authority(tgs_base: str):
    print(f"\n{DIVIDER}\nATTACK 1: Single malicious authority forged ticket\n{DIVIDER}")
    print("Scenario: attacker uses leaked AS1 private key and sends only one signature.")

    kd1 = load_private_key("AS1")
    client_id = "evil_root"
    session_key = os.urandom(32)

    payload = {
        "client_id": client_id,
        "service_id": "TGS",
        "issue_time": int(time.time()),
        "lifetime": 28800,
        "key_version": kd1.get("key_version", 1),
        "client_nonce": 1111,
    }
    msg = json.dumps(payload, sort_keys=True).encode("utf-8")
    R1, s1 = schnorr_sign(msg, kd1["x"], "AS1")

    ck = derive_client_key(client_id)
    sk_enc, sk_iv = aes256_cbc_encrypt(ck, session_key)

    forged_ticket = {
        "ticket_payload": payload,
        "signatures": [{"R": int_to_b64(R1), "s": int_to_b64(s1), "authority_id": "AS1"}],
        "session_key_enc": bytes_to_b64(sk_enc),
        "session_key_iv": bytes_to_b64(sk_iv),
    }
    req = build_tgs_request_from_ticket(forged_ticket, client_id, session_key)
    result = http_post(f"{tgs_base}/grant_service_ticket", req)
    print_tgs_result(result, expect_reject=True)


def attack_2_modified_ticket_payload(tgs_base: str):
    print(f"\n{DIVIDER}\nATTACK 2: Modified ticket payload\n{DIVIDER}")
    print("Scenario: get valid signatures from any 2 AS nodes, then tamper payload.")

    client_id = "alice"
    partials = collect_as_partials(client_id, required=2, preferred=["AS1", "AS2", "AS3"])
    if len(partials) < 2:
        print(f"  {SKIP}: not enough AS nodes reachable for this scenario.")
        return

    ticket, session_key = build_ticket_from_as_partials(client_id, partials)

    tampered = dict(ticket)
    tampered_payload = dict(ticket["ticket_payload"])
    tampered_payload["client_id"] = "root"
    tampered["ticket_payload"] = tampered_payload

    req = build_tgs_request_from_ticket(tampered, client_id, session_key)
    result = http_post(f"{tgs_base}/grant_service_ticket", req)
    print_tgs_result(result, expect_reject=True)


def attack_3_replay_old_partial_signature(tgs_base: str):
    print(f"\n{DIVIDER}\nATTACK 3: Replay old partial signature\n{DIVIDER}")
    print("Scenario: replay AS1 signature from old round + AS2/AS3 from new round.")

    client_id = "alice_replay"

    ts_old = int(time.time()) - 20
    old = request_as_partial(client_id, "AS1", ts_old, 12345)
    if old is None:
        print(f"  {SKIP}: could not obtain old AS1 signature.")
        return

    ts_new = int(time.time())
    new = request_as_partial(client_id, "AS2", ts_new, 67890)
    if new is None:
        new = request_as_partial(client_id, "AS3", ts_new + 1, 67891)
    if new is None:
        print(f"  {SKIP}: could not obtain new second authority signature.")
        return

    mixed_ticket = {
        "ticket_payload": new["ticket_payload"],
        "signatures": [old["signature"], new["signature"]],
        "session_key_enc": new["session_key_enc"],
        "session_key_iv": new["session_key_iv"],
    }
    session_key = aes256_cbc_decrypt(
        derive_client_key(client_id),
        b64_to_bytes(new["session_key_enc"]),
        b64_to_bytes(new["session_key_iv"]),
    )

    req = build_tgs_request_from_ticket(mixed_ticket, client_id, session_key)
    result = http_post(f"{tgs_base}/grant_service_ticket", req)
    print_tgs_result(result, expect_reject=True)


def attack_4_one_key_leakage(tgs_base: str):
    print(f"\n{DIVIDER}\nATTACK 4: One authority private key leakage\n{DIVIDER}")
    print("Scenario: attacker has AS1 key, forges AS1 sig and fakes AS2 signature.")

    kd1 = load_private_key("AS1")
    client_id = "mallory"
    payload = {
        "client_id": client_id,
        "service_id": "TGS",
        "issue_time": int(time.time()),
        "lifetime": 28800,
        "key_version": kd1.get("key_version", 1),
        "client_nonce": 2222,
    }
    msg = json.dumps(payload, sort_keys=True).encode("utf-8")

    R1, s1 = schnorr_sign(msg, kd1["x"], "AS1")
    fake_R = mod_exp(SCHNORR_G, secure_random_int(2, SCHNORR_Q - 1), SCHNORR_P)
    fake_s = secure_random_int(2, SCHNORR_Q - 1)

    session_key = os.urandom(32)
    sk_enc, sk_iv = aes256_cbc_encrypt(derive_client_key(client_id), session_key)

    forged_ticket = {
        "ticket_payload": payload,
        "signatures": [
            {"R": int_to_b64(R1), "s": int_to_b64(s1), "authority_id": "AS1"},
            {"R": int_to_b64(fake_R), "s": int_to_b64(fake_s), "authority_id": "AS2"},
        ],
        "session_key_enc": bytes_to_b64(sk_enc),
        "session_key_iv": bytes_to_b64(sk_iv),
    }

    req = build_tgs_request_from_ticket(forged_ticket, client_id, session_key)
    result = http_post(f"{tgs_base}/grant_service_ticket", req)
    print_tgs_result(result, expect_reject=True)


def attack_5_authority_offline(tgs_base: str):
    print(f"\n{DIVIDER}\nATTACK 5: One authority offline\n{DIVIDER}")
    print("Scenario: AS1 is offline, but AS2+AS3 are enough for 2-of-3.")

    # Unique client id each run avoids replay-cache collisions.
    client_id = f"bob_offline_{int(time.time())}"
    ts = int(time.time())
    nonce = secure_random_int(1, 2**32)

    # Simulate offline AS1 by querying a wrong port.
    offline_url = "http://127.0.0.1:5999/authenticate"
    off_resp = http_post(offline_url, {
        "client_id": client_id,
        "service_id": "TGS",
        "timestamp": ts,
        "nonce": nonce,
    })
    print("  AS1 simulated offline response:", off_resp.get("error", "unreachable"))

    # Important: same ts+nonce for AS2 and AS3, and no replay-retry timestamp bump.
    p2 = request_as_partial(client_id, "AS2", ts, nonce, allow_replay_retry=False)
    p3 = request_as_partial(client_id, "AS3", ts, nonce, allow_replay_retry=False)

    if p2 is None or p3 is None:
        print(f"  {SKIP}: need both AS2 and AS3 alive for this scenario.")
        return

    ticket, session_key = build_ticket_from_as_partials(
        client_id, [("AS2", p2), ("AS3", p3)]
    )
    req = build_tgs_request_from_ticket(ticket, client_id, session_key)
    result = http_post(f"{tgs_base}/grant_service_ticket", req)
    print_tgs_result(result, expect_reject=False)


def attack_6_single_valid_signature(tgs_base: str):
    print(f"\n{DIVIDER}\nATTACK 6: Ticket with only one valid signature\n{DIVIDER}")
    print("Scenario: submit ticket containing only AS1 signature.")

    client_id = "charlie"
    ts = int(time.time())
    nonce = secure_random_int(1, 2**32)

    p1 = request_as_partial(client_id, "AS1", ts, nonce)
    if p1 is None:
        print(f"  {SKIP}: AS1 unavailable for this scenario.")
        return

    session_key = aes256_cbc_decrypt(
        derive_client_key(client_id),
        b64_to_bytes(p1["session_key_enc"]),
        b64_to_bytes(p1["session_key_iv"]),
    )

    ticket = {
        "ticket_payload": p1["ticket_payload"],
        "signatures": [p1["signature"]],
        "session_key_enc": p1["session_key_enc"],
        "session_key_iv": p1["session_key_iv"],
    }

    req = build_tgs_request_from_ticket(ticket, client_id, session_key)
    result = http_post(f"{tgs_base}/grant_service_ticket", req)
    print_tgs_result(result, expect_reject=True)


# ---------------------------------------------------------------------------
# Menu / Runner
# ---------------------------------------------------------------------------

def run_all_attacks(tgs_base: str):
    attack_1_single_malicious_authority(tgs_base)
    attack_2_modified_ticket_payload(tgs_base)
    attack_3_replay_old_partial_signature(tgs_base)
    attack_4_one_key_leakage(tgs_base)
    attack_5_authority_offline(tgs_base)
    attack_6_single_valid_signature(tgs_base)


def print_menu():
    print(f"\n{DIVIDER}")
    print("Choose attack:")
    print("  1) Single malicious authority forged ticket")
    print("  2) Modified ticket payload")
    print("  3) Replay old partial signature")
    print("  4) One private key leakage")
    print("  5) Authority offline scenario")
    print("  6) One valid signature only")
    print("  7) Run ALL attacks")
    print("  8) Refresh TGS endpoint")
    print("  0) Exit")
    print(DIVIDER)


def main():
    print("\n" + DIVIDER)
    print("  KERBEROS MULTI-SIG ATTACK SUITE (NETWORKED, MENU-DRIVEN)")
    print(DIVIDER)

    if not os.path.exists(os.path.join(KEYS_DIR, "public_key_registry.json")):
        print("\n[!] Keys not found. Run 'python master_keygen.py' first.")
        sys.exit(1)

    tgs_base = find_tgs_base()
    if not tgs_base:
        print(f"\n{SKIP}: no TGS endpoint reachable right now.")
        print("Start at least one TGS server (e.g., TGS1 on port 6001).")
    else:
        print(f"[*] Using TGS endpoint: {tgs_base}")

    while True:
        print_menu()
        choice = input("Enter choice: ").strip()

        if choice == "0":
            print("Exiting.")
            break
        if choice == "8":
            tgs_base = find_tgs_base()
            if not tgs_base:
                print(f"{SKIP}: still no TGS endpoint reachable.")
            else:
                print(f"[*] Refreshed TGS endpoint: {tgs_base}")
            continue

        if not tgs_base:
            print(f"{SKIP}: no TGS reachable. Start TGS and choose 8 to refresh.")
            continue

        try:
            if choice == "1":
                attack_1_single_malicious_authority(tgs_base)
            elif choice == "2":
                attack_2_modified_ticket_payload(tgs_base)
            elif choice == "3":
                attack_3_replay_old_partial_signature(tgs_base)
            elif choice == "4":
                attack_4_one_key_leakage(tgs_base)
            elif choice == "5":
                attack_5_authority_offline(tgs_base)
            elif choice == "6":
                attack_6_single_valid_signature(tgs_base)
            elif choice == "7":
                run_all_attacks(tgs_base)
            else:
                print("Invalid choice.")
        except Exception as e:
            print(f"{SKIP}: scenario aborted due to runtime error: {e}")


if __name__ == "__main__":
    main()