"""Ground Station implementation generating and dispatching mission commands."""

import time
import secrets
from typing import Any, Dict, Optional, Tuple, List
from pqc_swarm.crypto.falcon import FalconSigner
from pqc_swarm.crypto.aead import encrypt_payload
from pqc_swarm.models.messages import CommandMessage


class GroundStationNode:
    """The Ground Station generates cryptographic keys and signs mission commands."""

    def __init__(
        self,
        signer: Optional[FalconSigner] = None,
        keypair: Optional[Tuple[bytes, bytes]] = None,
        operators: Optional[Dict[str, Tuple[bytes, bytes]]] = None,
    ):
        self.signer = signer or FalconSigner(512)
        if keypair is not None:
            self.private_key, self.public_key = keypair
            self.keygen_time = 0.0
        else:
            start = time.perf_counter()
            self.private_key, self.public_key = self.signer.keygen()
            self.keygen_time = time.perf_counter() - start

        # Multi-operator keypairs: operator_id -> (sk, pk)
        self.operators: Dict[str, Tuple[bytes, bytes]] = operators or {}
        if "OP_COMMANDER" not in self.operators:
            self.operators["OP_COMMANDER"] = (self.private_key, self.public_key)

    def add_operator(self, operator_id: str, keypair: Optional[Tuple[bytes, bytes]] = None) -> Tuple[bytes, bytes]:
        if keypair is None:
            keypair = self.signer.keygen()
        self.operators[operator_id] = keypair
        return keypair

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

    def create_multi_sig_command(
        self,
        payload: Dict[str, Any],
        mission_key: bytes,
        operator_ids: List[str],
        command_id: Optional[str] = None,
        aad: bytes = b"swarm_command",
    ) -> Tuple[CommandMessage, float]:
        """
        Encrypts payload with mission_key, and attaches signatures from the specified operator_ids.
        Returns (command_message, total_sign_time).
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
        signatures: List[Tuple[str, bytes]] = []
        for op_id in operator_ids:
            if op_id in self.operators:
                op_sk = self.operators[op_id][0]
                sig = self.signer.sign(op_sk, unsigned_cmd.digest())
                signatures.append((op_id, sig))

        sign_time = time.perf_counter() - sign_start
        signed_cmd = unsigned_cmd.with_operator_signatures(signatures)
        return signed_cmd, sign_time
