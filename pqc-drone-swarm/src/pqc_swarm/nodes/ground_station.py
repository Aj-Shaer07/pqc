"""Ground Station implementation generating and dispatching mission commands."""

import time
import secrets
from typing import Any, Dict, Optional, Tuple
from pqc_swarm.crypto.falcon import FalconSigner
from pqc_swarm.crypto.aead import encrypt_payload
from pqc_swarm.models.messages import CommandMessage


class GroundStationNode:
    """The Ground Station generates cryptographic keys and signs mission commands."""

    def __init__(self, signer: Optional[FalconSigner] = None):
        self.signer = signer or FalconSigner(512)
        start = time.perf_counter()
        self.private_key, self.public_key = self.signer.keygen()
        self.keygen_time = time.perf_counter() - start

    def create_command(
        self,
        payload: Dict[str, Any],
        mission_key: bytes,
        command_id: Optional[str] = None,
        aad: bytes = b"swarm_command",
    ) -> Tuple[CommandMessage, float]:
        """
        Encrypts payload with mission_key using ChaCha20-Poly1305, wraps in a CommandMessage,
        and attaches a Falcon-512 digital signature.
        Returns (command_message, sign_time_seconds).
        """
        cid = command_id or secrets.token_hex(8)
        nonce, ciphertext = encrypt_payload(mission_key, payload, aad=aad)

        unsigned_cmd = CommandMessage(
            command_id=cid,
            timestamp=time.time(),
            nonce_hex=nonce.hex(),
            aad_hex=aad.hex(),
            ciphertext_hex=ciphertext.hex(),
        )

        sign_start = time.perf_counter()
        signature = self.signer.sign(self.private_key, unsigned_cmd.digest())
        sign_time = time.perf_counter() - sign_start

        signed_cmd = unsigned_cmd.with_signature(signature)
        return signed_cmd, sign_time
