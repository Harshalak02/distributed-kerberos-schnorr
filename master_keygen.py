"""
master_keygen.py
Generates Schnorr key pairs for all AS and TGS authorities.
Saves keys to keys/ directory as JSON files.
"""

import json
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    SCHNORR_P, SCHNORR_Q, SCHNORR_G,
    schnorr_keygen,
    secure_random_int
)

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")


def generate_all_keys():
    """Generate Schnorr key pairs for AS1, AS2, AS3, TGS1, TGS2, TGS3."""
    os.makedirs(KEYS_DIR, exist_ok=True)

    authorities = [
        "AS1", "AS2", "AS3",
        "TGS1", "TGS2", "TGS3"
    ]

    master_public_keys = {}

    for authority_id in authorities:
        x, y = schnorr_keygen()

        # Save private key (only the authority itself should have this)
        private_data = {
            "authority_id": authority_id,
            "x": x,          # private key (integer)
            "y": y,          # public key  (integer)
            "p": SCHNORR_P,
            "q": SCHNORR_Q,
            "g": SCHNORR_G,
            "key_version": 1
        }

        private_path = os.path.join(KEYS_DIR, f"{authority_id}_private.json")
        with open(private_path, "w") as f:
            json.dump(private_data, f, indent=2)

        # Public key for distribution
        public_data = {
            "authority_id": authority_id,
            "y": y,
            "p": SCHNORR_P,
            "q": SCHNORR_Q,
            "g": SCHNORR_G,
            "key_version": 1
        }

        public_path = os.path.join(KEYS_DIR, f"{authority_id}_public.json")
        with open(public_path, "w") as f:
            json.dump(public_data, f, indent=2)

        master_public_keys[authority_id] = public_data
        print(f"[+] Generated keys for {authority_id}")
        print(f"    Private key (x): {hex(x)[:20]}...")
        print(f"    Public key  (y): {hex(y)[:20]}...")

    # Save master public key registry (shared with clients and service servers)
    registry_path = os.path.join(KEYS_DIR, "public_key_registry.json")
    with open(registry_path, "w") as f:
        json.dump(master_public_keys, f, indent=2)

    print(f"\n[+] Master public key registry saved to {registry_path}")
    print("[+] Key generation complete.")
    return master_public_keys


if __name__ == "__main__":
    generate_all_keys()
