"""Post-quantum signature and cryptographic primitives wrapper."""

import os
import sys
from typing import Tuple, Any

try:
    # 1. Direct standard import (works if falcon-py is installed or in PYTHONPATH)
    from falcon import Falcon
except ImportError:
    # 2. Resilient fallback: locate falcon_py directory dynamically
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _search_dirs = [
        os.getenv("FALCON_PATH", ""),
        os.path.abspath(os.path.join(_script_dir, "..", "..", "..", "falcon_py")),
        os.path.abspath(os.path.join(_script_dir, "..", "..", "..", "..", "falcon_py")),
        "/app/falcon_py",  # Common Docker mount point
    ]
    _found = False
    for candidate in _search_dirs:
        if candidate and os.path.isdir(candidate):
            if candidate not in sys.path:
                sys.path.insert(0, candidate)
            try:
                from falcon import Falcon
                _found = True
                break
            except ImportError:
                continue

    if not _found:
        raise ImportError(
            "Unable to load Falcon-512 engine from 'tprest/falcon.py'. "
            "Please ensure 'falcon-py' is installed ('pip install -e falcon_py') "
            "or set the FALCON_PATH environment variable."
        )


class FalconSigner:
    """Wrapper around Falcon-512 digital signature scheme."""

    def __init__(self, degree: int = 512):
        self.degree = degree
        self._engine = Falcon(degree)

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate a (private_key, public_key) pair."""
        return self._engine.keygen()

    # Canonical alias for cryptographic consistency across test harnesses
    generate_keypair = keygen

    def sign(self, private_key: Any, message: bytes) -> bytes:
        """Sign a message or digest with the private key."""
        if not (isinstance(private_key, (bytes, tuple)) and len(private_key) > 0):
            raise ValueError("private_key must be non-empty bytes or tuple.")
        if not isinstance(message, bytes) or len(message) == 0:
            raise ValueError("message must be non-empty bytes.")
        return self._engine.sign(private_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify the signature against the message and public key with defensive type checking."""
        if not isinstance(public_key, bytes) or len(public_key) == 0:
            return False
        if not isinstance(message, bytes) or len(message) == 0:
            return False
        if not isinstance(signature, bytes) or len(signature) == 0:
            return False
        try:
            return bool(self._engine.verify(public_key, message, signature))
        except Exception:
            return False
