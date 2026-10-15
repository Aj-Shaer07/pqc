"""Authenticated Encryption with Associated Data (AEAD) using ChaCha20-Poly1305."""

import json
import secrets
from typing import Any, Dict, Tuple
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def generate_mission_key() -> bytes:
    """Generate a random 256-bit (32-byte) key for ChaCha20-Poly1305."""
    return ChaCha20Poly1305.generate_key()


def encrypt_payload(
    key: bytes, payload: Dict[str, Any], aad: bytes = b"swarm_command"
) -> Tuple[bytes, bytes]:
    """
    Encrypts a JSON dictionary payload with ChaCha20-Poly1305.
    Returns (nonce, ciphertext).
    Validates key (32 bytes), payload (dict), and aad (bytes).
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError(f"ChaCha20 key must be exactly 32 bytes (got {len(key) if isinstance(key, bytes) else type(key)}).")
    if not isinstance(payload, dict):
        raise TypeError("Payload must be a dictionary.")
    if not isinstance(aad, bytes):
        raise TypeError("AAD must be bytes.")

    chacha = ChaCha20Poly1305(key)
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(payload, sort_keys=True).encode("utf-8")
    ciphertext = chacha.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_payload(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"swarm_command"
) -> Dict[str, Any]:
    """
    Decrypts and validates the ciphertext.
    Raises InvalidTag if tampering or wrong key is detected.
    Validates input lengths and UTF-8 JSON encoding.
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError(f"ChaCha20 key must be exactly 32 bytes (got {len(key) if isinstance(key, bytes) else type(key)}).")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError(f"Nonce must be exactly 12 bytes (got {len(nonce) if isinstance(nonce, bytes) else type(nonce)}).")
    if not isinstance(ciphertext, bytes) or len(ciphertext) < 16:
        raise ValueError(f"Ciphertext must be bytes with at least 16-byte Poly1305 MAC tag (got {len(ciphertext) if isinstance(ciphertext, bytes) else type(ciphertext)}).")
    if not isinstance(aad, bytes):
        raise TypeError("AAD must be bytes.")

    chacha = ChaCha20Poly1305(key)
    plaintext = chacha.decrypt(nonce, ciphertext, aad)
    try:
        return json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Decrypted payload is not valid UTF-8 JSON: {e}") from e
