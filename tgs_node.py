"""
tgs_node.py

Ticket Granting Server node (TGS1 / TGS2 / TGS3).
Each TGS runs as an independent server on its own port.

Endpoints:
  POST /grant_service_ticket  — Client presents TGT + authenticator.
                                 TGS responds with service-ticket partial signature.
  GET  /public_key            — Returns this authority's public key.
  GET  /health                — Health check.

Usage:
  python tgs_node.py TGS1 6001
  python tgs_node.py TGS2 6002
  python tgs_node.py TGS3 6003
"""

import json
import os
import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    schnorr_sign, schnorr_verify,
    aes256_cbc_encrypt, aes256_cbc_decrypt,
    generate_aes_key,
    verify_multisig,
    bytes_to_b64, b64_to_bytes,
    int_to_b64, b64_to_int,
    sha256_hex
)

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")

# Service-ticket lifetime (1 hour)
ST_LIFETIME = 3600

# Replay cache
_replay_cache = {}
_replay_lock = threading.Lock()

# TGT signature threshold
TGT_THRESHOLD = 2


def load_private_key(authority_id: str) -> dict:
    path = os.path.join(KEYS_DIR, f"{authority_id}_private.json")
    with open(path) as f:
        return json.load(f)


def load_public_registry() -> dict:
    path = os.path.join(KEYS_DIR, "public_key_registry.json")
    with open(path) as f:
        return json.load(f)


def is_replay(client_id: str, authenticator_time: int) -> bool:
    key = (client_id, authenticator_time)
    now = int(time.time())
    with _replay_lock:
        expired = [k for k, t in _replay_cache.items() if now - t > ST_LIFETIME * 2]
        for k in expired:
            del _replay_cache[k]
        if key in _replay_cache:
            return True
        _replay_cache[key] = now
    return False


# Derive the same client key as AS does (demo purpose)
def derive_client_key(client_id: str) -> bytes:
    import hashlib
    return hashlib.sha256((client_id + "kerberos-demo-key").encode()).digest()


class TGSHandler(BaseHTTPRequestHandler):
    """HTTP handler for the Ticket Granting Server."""

    authority_id: str = None
    private_key_data: dict = None
    public_registry: dict = None

    def log_message(self, fmt, *args):
        print(f"[{self.authority_id}] {fmt % args}")

    def send_json(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode())

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/public_key":
            self.handle_public_key()
        elif parsed.path == "/health":
            self.send_json(200, {"status": "ok", "authority": self.authority_id})
        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/grant_service_ticket":
            self.handle_grant_service_ticket()
        else:
            self.send_json(404, {"error": "Not found"})

    def handle_public_key(self):
        kd = self.private_key_data
        self.send_json(200, {
            "authority_id": kd["authority_id"],
            "y": int_to_b64(kd["y"]),
            "key_version": kd["key_version"]
        })

    # ------------------------------------------------------------------
    def handle_grant_service_ticket(self):
        """
        Client sends:
            {
              "tgt": {
                  "ticket_payload":  { ... },          # plaintext TGT fields
                  "signatures":      [ {R, s, authority_id}, ... ],  # ≥2 AS signatures
                  "session_key_enc": "<b64>",
                  "session_key_iv":  "<b64>"
              },
              "authenticator": {
                  "client_id":   "alice",
                  "timestamp":   1700000001,
                  "nonce":       99887766
              },
              "requested_service_id": "file_server"
            }

        TGS verifies TGT multi-sig, then returns its own partial signature
        over a new service-ticket payload.
        """
        try:
            req = self.read_json_body()
            tgt = req.get("tgt", {})
            authenticator = req.get("authenticator", {})
            requested_service_id = req.get("requested_service_id", "")

            if not tgt or not authenticator or not requested_service_id:
                self.send_json(400, {"error": "tgt, authenticator, and requested_service_id required"})
                return

            ticket_payload = tgt.get("ticket_payload", {})
            tgt_signatures = tgt.get("signatures", [])
            session_key_enc = b64_to_bytes(tgt.get("session_key_enc", ""))
            session_key_iv = b64_to_bytes(tgt.get("session_key_iv", ""))

            client_id = authenticator.get("client_id", "")
            auth_time = authenticator.get("timestamp", 0)

            # --- Step 1: Replay protection ---
            if is_replay(client_id, auth_time):
                self.send_json(400, {"error": "Replay detected on authenticator"})
                return

            # --- Step 2: Decode signatures (R and s are base64-encoded big ints) ---
            decoded_sigs = []
            for sig in tgt_signatures:
                decoded_sigs.append({
                    "R":            b64_to_int(sig["R"]),
                    "s":            b64_to_int(sig["s"]),
                    "authority_id": sig["authority_id"]
                })

            # Build AS-portion of public registry (AS1/AS2/AS3 keys only)
            as_registry = {}
            for k, v in self.public_registry.items():
                if k.startswith("AS"):
                    y = v["y"]
                    as_registry[k] = {"y": b64_to_int(y) if isinstance(y, str) else y}

            # --- Step 3: Verify TGT multi-signature ---
            msg_bytes = json.dumps(ticket_payload, sort_keys=True).encode("utf-8")
            valid, valid_signers = verify_multisig(msg_bytes, decoded_sigs, as_registry,
                                                   threshold=TGT_THRESHOLD)
            if not valid:
                self.send_json(403, {
                    "error": "TGT rejected: insufficient valid AS signatures",
                    "valid_signers": valid_signers
                })
                return

            # --- Step 4: Verify ticket is still live ---
            issue_time = ticket_payload.get("issue_time", 0)
            lifetime = ticket_payload.get("lifetime", 0)
            if int(time.time()) > issue_time + lifetime:
                self.send_json(403, {"error": "TGT expired"})
                return

            # --- Step 5: Verify client_id matches TGT ---
            if ticket_payload.get("client_id") != client_id:
                self.send_json(403, {"error": "client_id mismatch between TGT and authenticator"})
                return

            # --- Step 6: Decrypt session key (client's long-term key) ---
            client_key = derive_client_key(client_id)
            try:
                session_key = aes256_cbc_decrypt(client_key, session_key_enc, session_key_iv)
            except Exception:
                self.send_json(403, {"error": "Could not decrypt session key — invalid client"})
                return

            kd = self.private_key_data
            x = kd["x"]
            key_version = kd["key_version"]

            # --- Step 7: Build service-ticket payload ---
            service_session_key = generate_aes_key()  # fresh key for client ↔ service

            service_ticket_payload = {
                "client_id":    client_id,
                "service_id":   requested_service_id,
                "issue_time":   int(time.time()),
                "lifetime":     ST_LIFETIME,
                "authority_id": self.authority_id,
                "key_version":  key_version,
            }

            st_msg_bytes = json.dumps(service_ticket_payload, sort_keys=True).encode("utf-8")

            # --- Step 8: Schnorr sign service-ticket payload ---
            R, s = schnorr_sign(st_msg_bytes, x, self.authority_id)

            # Encrypt service-session-key with session_key
            ssk_enc, ssk_iv = aes256_cbc_encrypt(session_key, service_session_key)

            response = {
                "authority_id":           self.authority_id,
                "key_version":            key_version,
                "service_ticket_payload": service_ticket_payload,
                "service_session_key_enc": bytes_to_b64(ssk_enc),
                "service_session_key_iv":  bytes_to_b64(ssk_iv),
                "signature": {
                    "R":            int_to_b64(R),
                    "s":            int_to_b64(s),
                    "authority_id": self.authority_id
                }
            }

            print(f"[{self.authority_id}] Issued ST partial signature for "
                  f"client={client_id} → service={requested_service_id}")
            self.send_json(200, response)

        except Exception as exc:
            import traceback
            traceback.print_exc()
            self.send_json(500, {"error": str(exc)})


# ---------------------------------------------------------------------------
def make_handler_class(authority_id: str, private_key_data: dict, public_registry: dict):
    class ConfiguredTGSHandler(TGSHandler):
        pass
    ConfiguredTGSHandler.authority_id = authority_id
    ConfiguredTGSHandler.private_key_data = private_key_data
    ConfiguredTGSHandler.public_registry = public_registry
    return ConfiguredTGSHandler


def run_tgs_server(authority_id: str, port: int):
    print(f"[{authority_id}] Loading keys...")
    private_key_data = load_private_key(authority_id)
    public_registry = load_public_registry()
    # y values may be stored as raw ints (from master_keygen) or b64 strings
    for k in public_registry:
        y = public_registry[k]["y"]
        if isinstance(y, str):
            public_registry[k]["y"] = b64_to_int(y)
        # else already an int — leave as-is

    print(f"[{authority_id}] Starting Ticket Granting Server on port {port}...")
    handler_class = make_handler_class(authority_id, private_key_data, public_registry)
    server = HTTPServer(("0.0.0.0", port), handler_class)
    print(f"[{authority_id}] Listening on http://0.0.0.0:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"[{authority_id}] Shutting down.")
        server.server_close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python tgs_node.py <AUTHORITY_ID> <PORT>")
        print("  e.g. python tgs_node.py TGS1 6001")
        sys.exit(1)

    authority_id = sys.argv[1]
    port = int(sys.argv[2])

    valid_ids = {"TGS1", "TGS2", "TGS3"}
    if authority_id not in valid_ids:
        print(f"Error: authority_id must be one of {valid_ids}")
        sys.exit(1)

    run_tgs_server(authority_id, port)
