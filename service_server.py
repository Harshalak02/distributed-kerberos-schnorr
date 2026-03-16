"""
service_server.py

Service Server — verifies AES-encrypted service tickets and at least two
independent Schnorr signatures from TGS authorities.

Endpoints:
  POST /access       — Client presents service ticket bundle
  GET  /health       — Health check

Usage:
  python service_server.py file_server 7001
  python service_server.py print_server 7002
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
    schnorr_verify,
    aes256_cbc_encrypt, aes256_cbc_decrypt,
    verify_multisig,
    bytes_to_b64, b64_to_bytes,
    int_to_b64, b64_to_int
)

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")

# Service-ticket replay cache
_replay_cache = {}
_replay_lock = threading.Lock()

# Minimum valid key version (increment to invalidate old keys)
MINIMUM_KEY_VERSION = 1

# Threshold for TGS multi-signature
ST_THRESHOLD = 2


def derive_service_key(service_id: str) -> bytes:
    import hashlib
    return hashlib.sha256((service_id + "-service-demo-key").encode()).digest()


def load_public_registry() -> dict:
    path = os.path.join(KEYS_DIR, "public_key_registry.json")
    with open(path) as f:
        raw = json.load(f)
    # Convert y values from b64 strings to ints if needed
    for k in raw:
        y = raw[k].get("y")
        if isinstance(y, str):
            raw[k]["y"] = b64_to_int(y)
        # else already int
    return raw


def is_replay(client_id: str, issue_time: int) -> bool:
    key = (client_id, issue_time)
    now = int(time.time())
    with _replay_lock:
        expired = [k for k, t in _replay_cache.items() if now - t > 7200]
        for k in expired:
            del _replay_cache[k]
        if key in _replay_cache:
            return True
        _replay_cache[key] = now
    return False


class ServiceHandler(BaseHTTPRequestHandler):
    service_id: str = None
    public_registry: dict = None

    def log_message(self, fmt, *args):
        print(f"[ServiceServer:{self.service_id}] {fmt % args}")

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

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_json(200, {"status": "ok", "service": self.service_id})
        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/access":
            self.handle_access()
        else:
            self.send_json(404, {"error": "Not found"})

    # ------------------------------------------------------------------
    def handle_access(self):
        """
        Client sends:
            {
              "service_ticket_enc": "<b64 AES>",
              "service_ticket_iv":  "<b64 IV>",
              "authenticator_enc":  "<b64 AES>",
              "authenticator_iv":   "<b64 IV>"
            }

        Service verifies:
            1. AES encryption is valid
            2. At least 2 Schnorr TGS signatures are valid
            3. Ticket is not expired
            4. Ticket is not a replay
            5. Key version is not outdated
            6. service_id matches this server
        """
        try:
            req = self.read_json_body()
            ticket_enc = b64_to_bytes(req.get("service_ticket_enc", ""))
            ticket_iv = b64_to_bytes(req.get("service_ticket_iv", ""))
            auth_enc = b64_to_bytes(req.get("authenticator_enc", ""))
            auth_iv = b64_to_bytes(req.get("authenticator_iv", ""))

            if not ticket_enc or not ticket_iv or not auth_enc or not auth_iv:
                self.send_json(400, {"error": "encrypted service_ticket and authenticator required"})
                return

            service_key = derive_service_key(self.service_id)
            try:
                ticket_plain = aes256_cbc_decrypt(service_key, ticket_enc, ticket_iv)
                service_ticket = json.loads(ticket_plain.decode("utf-8"))
            except Exception:
                self.send_json(403, {"error": "Could not decrypt service ticket"})
                return

            st_payload = service_ticket.get("payload", {})
            st_signatures = service_ticket.get("signatures", [])
            service_session_key = b64_to_bytes(service_ticket.get("service_session_key", ""))

            # ---- 1. Verify ticket carries service session key ----
            if len(service_session_key) != 32:
                self.send_json(403, {"error": "Service session key missing/invalid in ticket"})
                return

            try:
                auth_plain = aes256_cbc_decrypt(service_session_key, auth_enc, auth_iv)
                authenticator = json.loads(auth_plain.decode("utf-8"))
            except Exception:
                self.send_json(403, {"error": "Authenticator decrypt/parse failed"})
                return

            client_id = authenticator.get("client_id", "")
            auth_time = authenticator.get("timestamp", 0)

            # ---- 2. Verify service_id matches ----
            if st_payload.get("service_id") != self.service_id:
                self.send_json(403, {
                    "error": f"Ticket intended for '{st_payload.get('service_id')}', "
                             f"not '{self.service_id}'"
                })
                return

            # ---- 3. Verify key version ----
            key_version = st_payload.get("key_version", 0)
            if key_version < MINIMUM_KEY_VERSION:
                self.send_json(403, {
                    "error": f"Outdated key version {key_version} "
                             f"(minimum {MINIMUM_KEY_VERSION}) — ticket rejected"
                })
                return

            # ---- 4. Verify ticket lifetime ----
            issue_time = st_payload.get("issue_time", 0)
            lifetime = st_payload.get("lifetime", 0)
            now = int(time.time())
            if now > issue_time + lifetime:
                self.send_json(403, {"error": "Service ticket expired"})
                return

            # ---- 5. Replay protection ----
            if is_replay(client_id, issue_time):
                self.send_json(403, {"error": "Replay detected — ticket already used"})
                return

            # ---- 6. Verify client_id ----
            if st_payload.get("client_id") != client_id:
                self.send_json(403, {"error": "client_id mismatch"})
                return

            # ---- 7. Decode and verify TGS multi-signatures ----
            decoded_sigs = []
            for sig in st_signatures:
                decoded_sigs.append({
                    "R":            b64_to_int(sig["R"]),
                    "s":            b64_to_int(sig["s"]),
                    "authority_id": sig["authority_id"]
                })

            # TGS-portion of registry
            tgs_registry = {k: v for k, v in self.public_registry.items() if k.startswith("TGS")}
            st_msg_bytes = json.dumps(st_payload, sort_keys=True).encode("utf-8")

            valid, valid_signers = verify_multisig(
                st_msg_bytes, decoded_sigs, tgs_registry, threshold=ST_THRESHOLD
            )

            if not valid:
                self.send_json(403, {
                    "error": "Service ticket rejected: insufficient valid TGS signatures",
                    "valid_signers": valid_signers,
                    "required": ST_THRESHOLD
                })
                return

            # Ensure payload key_version matches every valid signer's current key_version.
            for signer in valid_signers:
                expected_version = self.public_registry.get(signer, {}).get("key_version")
                if expected_version is not None and key_version != expected_version:
                    self.send_json(403, {
                        "error": (
                            f"Service ticket rejected: key_version mismatch for signer {signer} "
                            f"(payload={key_version}, registry={expected_version})"
                        )
                    })
                    return

            # ---- Access granted ----
            print(f"[ServiceServer:{self.service_id}] ACCESS GRANTED "
                  f"client={client_id}, signers={valid_signers}")
            self.send_json(200, {
                "status":        "ACCESS GRANTED",
                "service_id":    self.service_id,
                "client_id":     client_id,
                "valid_signers": valid_signers,
                "session_established": True
            })

        except Exception as exc:
            import traceback
            traceback.print_exc()
            self.send_json(500, {"error": str(exc)})


# ---------------------------------------------------------------------------

def make_handler_class(service_id: str, public_registry: dict):
    class ConfiguredServiceHandler(ServiceHandler):
        pass
    ConfiguredServiceHandler.service_id = service_id
    ConfiguredServiceHandler.public_registry = public_registry
    return ConfiguredServiceHandler


def run_service_server(service_id: str, port: int):
    print(f"[ServiceServer:{service_id}] Loading public key registry...")
    public_registry = load_public_registry()
    print(f"[ServiceServer:{service_id}] Starting on port {port}...")
    handler_class = make_handler_class(service_id, public_registry)
    server = HTTPServer(("0.0.0.0", port), handler_class)
    print(f"[ServiceServer:{service_id}] Listening on http://0.0.0.0:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"[ServiceServer:{service_id}] Shutting down.")
        server.server_close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python service_server.py <SERVICE_ID> <PORT>")
        print("  e.g. python service_server.py file_server 7001")
        sys.exit(1)
    run_service_server(sys.argv[1], int(sys.argv[2]))
