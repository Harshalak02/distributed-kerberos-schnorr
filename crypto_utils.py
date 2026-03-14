"""
crypto_utils.py

All cryptographic primitives implemented MANUALLY:
  - Modular exponentiation
  - Modular arithmetic over Zq
  - Schnorr key generation
  - Schnorr signature generation & verification
  - SHA-256 (via hashlib — only hash function allowed)
  - AES-256-CBC with manual PKCS#7 padding
  - OS-level secure RNG

NO asymmetric crypto libraries are used.
AES is provided via the 'pycryptodome' library (symmetric only).
"""

import hashlib
import os
import struct
import json
from typing import Tuple

# ---------------------------------------------------------------------------
# Schnorr Domain Parameters (RFC 3526 / NIST-style 2048-bit safe prime)
# Using a 2048-bit safe prime p with q = (p-1)/2 for demonstration.
# For academic use we define a smaller but cryptographically-structured group.
# ---------------------------------------------------------------------------

# 1024-bit safe prime (p = 2q + 1 where q is prime) — standard for Schnorr demos
# Source: well-known 1024-bit MODP group (RFC 2409 Group 2)
SCHNORR_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF",
    16
)
# Order of the subgroup: q = (p - 1) / 2
SCHNORR_Q = (SCHNORR_P - 1) // 2
# Generator
SCHNORR_G = 2  # g=2 is a generator for the subgroup of order q in this group


# ---------------------------------------------------------------------------
# Modular arithmetic helpers (manual implementations)
# ---------------------------------------------------------------------------

def mod_exp(base: int, exp: int, mod: int) -> int:
    """
    Manual modular exponentiation using square-and-multiply (binary method).
    Computes base^exp mod mod without using pow() builtin.
    """
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        # If exp is odd, multiply result by base
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1          # exp = exp // 2
        base = (base * base) % mod  # square the base
    return result


def mod_inverse(a: int, m: int) -> int:
    """
    Modular multiplicative inverse using extended Euclidean algorithm.
    Returns x such that a*x ≡ 1 (mod m).
    Raises ValueError if inverse does not exist.
    """
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a},{m}) = {g}")
    return x % m


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm. Returns (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def mod_add(a: int, b: int, m: int) -> int:
    """Modular addition."""
    return (a + b) % m


def mod_mul(a: int, b: int, m: int) -> int:
    """Modular multiplication."""
    return (a * b) % m


# ---------------------------------------------------------------------------
# Secure randomness
# ---------------------------------------------------------------------------

def secure_random_int(lower: int, upper: int) -> int:
    """
    Generate a cryptographically secure random integer in [lower, upper).
    Uses os.urandom() (OS-level CSPRNG).
    """
    range_size = upper - lower
    if range_size <= 0:
        raise ValueError("upper must be greater than lower")
    # Number of bytes needed
    byte_len = (range_size.bit_length() + 7) // 8
    # Rejection sampling to avoid modular bias
    while True:
        rand_bytes = os.urandom(byte_len)
        rand_int = int.from_bytes(rand_bytes, "big")
        if rand_int < range_size:
            return lower + rand_int


def generate_aes_key() -> bytes:
    """Generate a 256-bit AES key using OS CSPRNG."""
    return os.urandom(32)


def generate_iv() -> bytes:
    """Generate a 128-bit AES IV using OS CSPRNG."""
    return os.urandom(16)


# ---------------------------------------------------------------------------
# SHA-256 wrapper
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    """SHA-256 hash of data."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """SHA-256 hash returned as hex string."""
    return hashlib.sha256(data).hexdigest()


def hash_to_int(data: bytes) -> int:
    """Hash data with SHA-256 and interpret result as integer."""
    return int.from_bytes(sha256(data), "big")


# ---------------------------------------------------------------------------
# Manual PKCS#7 padding
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS#7 padding to data.
    Pads with N bytes each of value N, where N = block_size - (len(data) % block_size).
    If data is already aligned, a full block of padding is added.
    """
    n = block_size - (len(data) % block_size)
    return data + bytes([n] * n)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """
    Remove PKCS#7 padding from data.
    Raises ValueError on invalid padding.
    """
    if not data:
        raise ValueError("Empty data")
    n = data[-1]
    if n == 0 or n > block_size:
        raise ValueError(f"Invalid PKCS#7 padding byte: {n}")
    if len(data) < n:
        raise ValueError("Data shorter than padding length")
    # Verify all padding bytes
    padding = data[-n:]
    if padding != bytes([n] * n):
        raise ValueError("Invalid PKCS#7 padding content")
    return data[:-n]


# ---------------------------------------------------------------------------
# AES-256-CBC (using pycryptodome for the block cipher primitive only)
# The PKCS#7 padding is our own manual implementation above.
# ---------------------------------------------------------------------------

def _get_aes_backend():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa
        return "cryptography"
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES  # noqa
        return "pycryptodome"
    except ImportError:
        pass
    raise RuntimeError(
        "No AES library found. Install with: pip install cryptography"
    )

_AES_BACKEND = _get_aes_backend()


def aes256_cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
    """
    AES-256-CBC encryption with manual PKCS#7 padding.
    Returns (ciphertext, iv).
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    if iv is None:
        iv = generate_iv()
    padded = pkcs7_pad(plaintext, 16)
    if _AES_BACKEND == "cryptography":
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()
    else:
        from Crypto.Cipher import AES as _AES
        cipher = _AES.new(key, _AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded)
    return ciphertext, iv


def aes256_cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """
    AES-256-CBC decryption with manual PKCS#7 unpadding.
    Returns plaintext bytes.
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    if _AES_BACKEND == "cryptography":
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
    else:
        from Crypto.Cipher import AES as _AES
        cipher = _AES.new(key, _AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
    return pkcs7_unpad(padded, 16)


# ---------------------------------------------------------------------------
# Schnorr Key Generation
# ---------------------------------------------------------------------------

def schnorr_keygen() -> Tuple[int, int]:
    """
    Generate a Schnorr key pair (x, y) where:
      x  — private key in Zq  (randomly chosen)
      y  — public key = g^x mod p
    Returns (x, y).
    """
    x = secure_random_int(2, SCHNORR_Q - 1)
    y = mod_exp(SCHNORR_G, x, SCHNORR_P)
    return x, y


# ---------------------------------------------------------------------------
# Schnorr Signature Generation & Verification
# ---------------------------------------------------------------------------

def schnorr_sign(message: bytes, x: int, authority_id: str) -> Tuple[int, int]:
    """
    Generate a Schnorr signature (R, s) for `message` using private key `x`.

    Protocol:
      1. Choose fresh nonce k ∈ Zq  (MUST be unique per signature)
      2. R = g^k mod p
      3. e = H(message || R || authority_id)  mod q
      4. s = (k + e * x) mod q

    Returns (R, s) as integers.
    WARNING: k must NEVER be reused. Each call draws a fresh k from OS CSPRNG.
    """
    p, q, g = SCHNORR_P, SCHNORR_Q, SCHNORR_G

    # Step 1: Fresh nonce (never reuse!)
    k = secure_random_int(2, q - 1)

    # Step 2: Commitment
    R = mod_exp(g, k, p)

    # Step 3: Challenge hash
    auth_bytes = authority_id.encode("utf-8")
    R_bytes = R.to_bytes((R.bit_length() + 7) // 8, "big")
    e_bytes = sha256(message + R_bytes + auth_bytes)
    e = int.from_bytes(e_bytes, "big") % q

    # Step 4: Response
    s = mod_add(k, mod_mul(e, x, q), q)

    return R, s


def schnorr_verify(message: bytes, R: int, s: int, y: int, authority_id: str) -> bool:
    """
    Verify a Schnorr signature (R, s).

    Checks: g^s ≡ R · y^e  (mod p)
    where    e = H(message || R || authority_id) mod q

    Returns True if valid, False otherwise.
    """
    p, q, g = SCHNORR_P, SCHNORR_Q, SCHNORR_G

    # Basic range checks
    if not (1 < R < p):
        return False
    if not (0 < s < q):
        return False

    # Recompute challenge
    auth_bytes = authority_id.encode("utf-8")
    R_bytes = R.to_bytes((R.bit_length() + 7) // 8, "big")
    e_bytes = sha256(message + R_bytes + auth_bytes)
    e = int.from_bytes(e_bytes, "big") % q

    # LHS: g^s mod p
    lhs = mod_exp(g, s, p)

    # RHS: R * y^e mod p
    ye = mod_exp(y, e, p)
    rhs = mod_mul(R, ye, p)

    return lhs == rhs


def verify_multisig(message: bytes, signatures: list, public_key_registry: dict,
                    threshold: int = 2) -> Tuple[bool, list]:
    """
    Verify that `message` has at least `threshold` valid independent Schnorr signatures.

    `signatures` is a list of dicts:
        {"R": int, "s": int, "authority_id": str}

    `public_key_registry` maps authority_id -> {"y": int, "key_version": int, ...}

    Returns (True, list_of_valid_authority_ids) if threshold is met,
            (False, list_of_valid_authority_ids) otherwise.
    """
    valid_signers = []
    seen_authorities = set()

    for sig in signatures:
        auth_id = sig.get("authority_id")
        R = sig.get("R")
        s = sig.get("s")

        if auth_id is None or R is None or s is None:
            continue
        if auth_id in seen_authorities:
            # Duplicate authority — only count once
            continue
        if auth_id not in public_key_registry:
            continue

        y = public_key_registry[auth_id]["y"]
        if schnorr_verify(message, R, s, y, auth_id):
            valid_signers.append(auth_id)
            seen_authorities.add(auth_id)

    return len(valid_signers) >= threshold, valid_signers


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def int_to_b64(n: int) -> str:
    """Encode a large integer as a base64 string for JSON transport."""
    import base64
    byte_len = (n.bit_length() + 7) // 8
    return base64.b64encode(n.to_bytes(byte_len, "big")).decode()


def b64_to_int(s: str) -> int:
    """Decode a base64 string back to a large integer."""
    import base64
    return int.from_bytes(base64.b64decode(s), "big")


def bytes_to_b64(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode()


def b64_to_bytes(s: str) -> bytes:
    import base64
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("[*] Testing modular exponentiation...")
    assert mod_exp(2, 10, 1000) == 24
    print("    mod_exp(2,10,1000) =", mod_exp(2, 10, 1000), "✓")

    print("[*] Testing PKCS#7 padding...")
    data = b"Hello"
    padded = pkcs7_pad(data)
    assert pkcs7_unpad(padded) == data
    print(f"    pad/unpad 'Hello' ✓")

    print("[*] Testing AES-256-CBC...")
    key = generate_aes_key()
    ct, iv = aes256_cbc_encrypt(key, b"Top Secret Message 123!")
    pt = aes256_cbc_decrypt(key, ct, iv)
    assert pt == b"Top Secret Message 123!"
    print("    AES encrypt/decrypt ✓")

    print("[*] Testing Schnorr key generation...")
    x, y = schnorr_keygen()
    print(f"    x (private): {hex(x)[:20]}...")
    print(f"    y (public):  {hex(y)[:20]}...")

    print("[*] Testing Schnorr sign/verify...")
    msg = b"test message for schnorr"
    R, s = schnorr_sign(msg, x, "AS1")
    assert schnorr_verify(msg, R, s, y, "AS1"), "Signature verification failed!"
    print("    Schnorr sign/verify ✓")

    print("[*] Testing bad signature detection...")
    assert not schnorr_verify(b"different message", R, s, y, "AS1")
    print("    Bad signature rejected ✓")

    print("[*] Testing multi-signature verification...")
    x2, y2 = schnorr_keygen()
    x3, y3 = schnorr_keygen()
    R2, s2 = schnorr_sign(msg, x2, "AS2")
    R3, s3 = schnorr_sign(msg, x3, "AS3")
    registry = {
        "AS1": {"y": y},
        "AS2": {"y": y2},
        "AS3": {"y": y3},
    }
    sigs = [
        {"R": R, "s": s, "authority_id": "AS1"},
        {"R": R2, "s": s2, "authority_id": "AS2"},
    ]
    ok, signers = verify_multisig(msg, sigs, registry, threshold=2)
    assert ok, "Multi-sig should pass with 2 valid signatures"
    print("    2-of-3 multi-sig ✓")

    print("\n[+] All crypto_utils tests passed.")
