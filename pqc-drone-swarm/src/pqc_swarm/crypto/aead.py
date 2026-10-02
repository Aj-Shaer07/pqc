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
    """
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
    """
    chacha = ChaCha20Poly1305(key)
    plaintext = chacha.decrypt(nonce, ciphertext, aad)
    return json.loads(plaintext.decode("utf-8"))
