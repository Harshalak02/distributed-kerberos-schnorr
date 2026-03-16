"""
as_node.py

Authentication Server node (AS1 / AS2 / AS3).
Each AS runs as a separate server on its own port.

Endpoints:
  POST /authenticate  — Client sends {client_id, service_id, timestamp}
                         AS responds with {session_key_enc, signature: {R, s, authority_id},
                                           ticket_payload_signed, key_version}
  GET  /public_key    — Returns this authority's public key info
  GET  /health        — Health check

Usage:
  python as_node.py AS1 5001
  python as_node.py AS2 5002
  python as_node.py AS3 5003
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
    generate_aes_key, generate_iv,
    sha256_hex, secure_random_int,
    bytes_to_b64, b64_to_bytes,
    int_to_b64, b64_to_int
)

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")

# TGT lifetime in seconds (8 hours)
TGT_LIFETIME = 8 * 3600

# In-memory replay cache: maps (client_id, timestamp) -> issue_time
_replay_cache = {}
_replay_lock = threading.Lock()


def load_private_key(authority_id: str) -> dict:
    path = os.path.join(KEYS_DIR, f"{authority_id}_private.json")
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Private key for {authority_id} not found at {path}. "
            "Run master_keygen.py first."
        )
    with open(path) as f:
        return json.load(f)


def load_public_registry() -> dict:
    path = os.path.join(KEYS_DIR, "public_key_registry.json")
    with open(path) as f:
        return json.load(f)


def is_replay(client_id: str, req_timestamp: int) -> bool:
    """Return True if this (client_id, timestamp) was seen recently."""
    key = (client_id, req_timestamp)
    now = int(time.time())
    with _replay_lock:
        # Purge old entries
        expired = [k for k, t in _replay_cache.items() if now - t > TGT_LIFETIME]
        for k in expired:
            del _replay_cache[k]
        if key in _replay_cache:
            return True
        _replay_cache[key] = now
    return False


class ASHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Authentication Server."""

    authority_id: str = None
    private_key_data: dict = None

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
        length = self.headers.get("Content-Length")
        raw = self.rfile.read(int(length)) if length else self.rfile.read()
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    # ------------------------------------------------------------------
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
        if parsed.path == "/authenticate":
            self.handle_authenticate()
        else:
            self.send_json(404, {"error": "Not found"})

    # ------------------------------------------------------------------
    def handle_public_key(self):
        kd = self.private_key_data
        self.send_json(200, {
            "authority_id": kd["authority_id"],
            "y": int_to_b64(kd["y"]),
            "p": int_to_b64(kd["p"]),
            "q": int_to_b64(kd["q"]),
            "g": int_to_b64(kd["g"]),
            "key_version": kd["key_version"]
        })

    # ------------------------------------------------------------------
    def handle_authenticate(self):
        """
        Client sends:
            {
              "client_id":   "alice",
              "service_id":  "TGS",
              "timestamp":   1700000000,
              "nonce":       12345678   (client-chosen, prevents replay)
            }

        AS responds (encrypted for the client):
            {
              "authority_id": "AS1",
              "as_reply_enc": "<base64 AES-256-CBC>",
              "as_reply_iv":  "<base64 IV>"
            }
        """
        try:
            req = self.read_json_body()
            client_id = req.get("client_id", "")
            service_id = req.get("service_id", "TGS")
            timestamp = req.get("timestamp", int(time.time()))
            client_nonce = req.get("nonce", 0)

            if not client_id:
                self.send_json(400, {"error": "client_id required"})
                return
             # Basic freshness check (5-minute skew window)
            now = int(time.time())
            if abs(now - int(timestamp)) > 300:
                self.send_json(400, {"error": "timestamp outside allowed freshness window"})
                return

            # Basic freshness check (5-minute skew window)
            now = int(time.time())
            if abs(now - int(timestamp)) > 300:
                self.send_json(400, {"error": "timestamp outside allowed freshness window"})
                return

            # Replay check
            if is_replay(client_id, timestamp):
                self.send_json(400, {"error": "Replay detected — duplicate timestamp"})
                return

            kd = self.private_key_data
            x = kd["x"]
            key_version = kd["key_version"]

            # Generate session key for client ↔ TGS
            session_key = generate_aes_key()

            # Build ticket payload (plaintext — will also go into signature)
            ticket_payload = {
                "client_id":    client_id,
                "service_id":   service_id,
                # Keep issue_time deterministic across AS authorities for same request,
                # so multiple signatures can be collected over the exact same payload.
                "issue_time":   int(timestamp),
                "lifetime":     TGT_LIFETIME,
                "key_version":  key_version,
                "client_nonce": client_nonce,
            }

            # Canonical message for signing = deterministic JSON dump
            msg_bytes = json.dumps(ticket_payload, sort_keys=True).encode("utf-8")

            # Schnorr sign the payload
            R, s = schnorr_sign(msg_bytes, x, self.authority_id)

            # Encrypt session key with a per-client AES key derived from SHA-256
            # In real Kerberos this would use the client's long-term key.
            # Here we derive a "client key" from SHA-256(client_id) for demonstration.
            client_key = derive_client_key(client_id)
            session_key_enc, sk_iv = aes256_cbc_encrypt(client_key, session_key)

            inner_reply = {
                "key_version":     key_version,
                "session_key_enc": bytes_to_b64(session_key_enc),
                "session_key_iv":  bytes_to_b64(sk_iv),
                "ticket_payload":  ticket_payload,
                "signature": {
                    "R":            int_to_b64(R),
                    "s":            int_to_b64(s),
                    "authority_id": self.authority_id
                }
            }
            inner_bytes = json.dumps(inner_reply, sort_keys=True).encode("utf-8")
            as_reply_enc, as_reply_iv = aes256_cbc_encrypt(client_key, inner_bytes)

            response = {
                "authority_id": self.authority_id,
                "as_reply_enc": bytes_to_b64(as_reply_enc),
                "as_reply_iv": bytes_to_b64(as_reply_iv),
            }

            print(f"[{self.authority_id}] Issued TGT partial signature for client={client_id}")
            self.send_json(200, response)

        except Exception as exc:
            print(f"[{self.authority_id}] ERROR in authenticate: {exc}")
            self.send_json(500, {"error": str(exc)})


# ---------------------------------------------------------------------------
# Key derivation helper (for demo — derives a 256-bit AES key from client_id)
# ---------------------------------------------------------------------------

def derive_client_key(client_id: str) -> bytes:
    """
    Derive a deterministic AES key for a client.
    In production this would be the client's Kerberos long-term secret.
    For this demo: SHA-256(client_id || "kerberos-demo-key")
    """
    import hashlib
    return hashlib.sha256((client_id + "kerberos-demo-key").encode()).digest()


# ---------------------------------------------------------------------------
# Server factory — creates a configured ASHandler class
# ---------------------------------------------------------------------------

def make_handler_class(authority_id: str, private_key_data: dict):
    class ConfiguredASHandler(ASHandler):
        pass
    ConfiguredASHandler.authority_id = authority_id
    ConfiguredASHandler.private_key_data = private_key_data
    return ConfiguredASHandler


def run_as_server(authority_id: str, port: int):
    print(f"[{authority_id}] Loading private key...")
    private_key_data = load_private_key(authority_id)
    print(f"[{authority_id}] Public key y = {hex(private_key_data['y'])[:20]}...")
    print(f"[{authority_id}] Starting Authentication Server on port {port}...")

    handler_class = make_handler_class(authority_id, private_key_data)
    server = HTTPServer(("0.0.0.0", port), handler_class)
    print(f"[{authority_id}] Listening on http://0.0.0.0:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"[{authority_id}] Shutting down.")
        server.server_close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python as_node.py <AUTHORITY_ID> <PORT>")
        print("  e.g. python as_node.py AS1 5001")
        sys.exit(1)

    authority_id = sys.argv[1]
    port = int(sys.argv[2])

    valid_ids = {"AS1", "AS2", "AS3"}
    if authority_id not in valid_ids:
        print(f"Error: authority_id must be one of {valid_ids}")
        sys.exit(1)

    run_as_server(authority_id, port)
