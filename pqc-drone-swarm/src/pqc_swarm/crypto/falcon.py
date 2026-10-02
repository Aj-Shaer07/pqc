"""Post-quantum signature and cryptographic primitives wrapper."""

import os
import sys
from typing import Tuple

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

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign a message or digest with the private key."""
        return self._engine.sign(private_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify the signature against the message and public key."""
        try:
            return bool(self._engine.verify(public_key, message, signature))
        except Exception:
            return False
