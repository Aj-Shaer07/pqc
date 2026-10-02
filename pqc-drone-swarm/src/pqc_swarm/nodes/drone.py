"""Autonomous Drone Node with decentralized threshold verification and execution."""

import time
from typing import Dict, List, Optional, Set, Tuple, Any
from pqc_swarm.crypto.falcon import FalconSigner
from pqc_swarm.crypto.sss import reconstruct_secret
from pqc_swarm.crypto.aead import decrypt_payload
from pqc_swarm.models.messages import CommandMessage, ApprovalMessage, ShareMessage
from pqc_swarm.models.registry import TrustRegistry


class DroneNode:
    """
    Decentralized Autonomous Drone.
    Holds its own keypair, Shamir share, and trust registry.
    Independently verifies GS commands, checks peer approvals, and executes payload upon reaching threshold.
    """

    def __init__(
        self,
        drone_id: str,
        share: Tuple[int, int],
        threshold: int,
        trust_registry: TrustRegistry,
        signer: Optional[FalconSigner] = None,
    ):
        self.drone_id = drone_id
        self.share = share  # (x, y)
        self.threshold = threshold
        self.trust_registry = trust_registry
        self.signer = signer or FalconSigner(512)

        start = time.perf_counter()
        self.private_key, self.public_key = self.signer.keygen()
        self.keygen_time = time.perf_counter() - start

        # Register self in trust registry
        self.trust_registry.register_drone(self.drone_id, self.public_key)

        # Internal decentralized tracking state per command
        # command_id -> set of drone_ids that provided verified approvals
        self.peer_approvals: Dict[str, Set[str]] = {}
        # command_id -> list of verified (x, y) shares
        self.collected_shares: Dict[str, List[Tuple[int, int]]] = {}
        # Cached active commands: command_id -> CommandMessage
        self.known_commands: Dict[str, CommandMessage] = {}

    def verify_gs_command(self, command: CommandMessage) -> Tuple[bool, float]:
        """
        Verify the Ground Station signature on an incoming command.
        Returns (is_valid, elapsed_seconds).
        """
        if not self.trust_registry.gs_public_key:
            return False, 0.0

        gs_pk = self.trust_registry.gs_public_key
        sig_bytes = bytes.fromhex(command.gs_signature_hex)

        start = time.perf_counter()
        is_valid = self.signer.verify(gs_pk, command.digest(), sig_bytes)
        elapsed = time.perf_counter() - start

        if is_valid:
            self.known_commands[command.command_id] = command
            if command.command_id not in self.peer_approvals:
                self.peer_approvals[command.command_id] = set()
            if command.command_id not in self.collected_shares:
                self.collected_shares[command.command_id] = []

        return is_valid, elapsed

    def create_approval(self, command_id: str) -> Tuple[ApprovalMessage, float]:
        """
        Sign and issue an approval for a verified command.
        Returns (approval_message, elapsed_seconds).
        """
        unsigned_app = ApprovalMessage(
            command_id=command_id,
            drone_id=self.drone_id,
            timestamp=time.time(),
            signature_hex="",
        )

        start = time.perf_counter()
        sig = self.signer.sign(self.private_key, unsigned_app.digest())
        elapsed = time.perf_counter() - start

        signed_app = ApprovalMessage(
            command_id=command_id,
            drone_id=self.drone_id,
            timestamp=unsigned_app.timestamp,
            signature_hex=sig.hex(),
        )

        # Self-approval recorded locally
        self.peer_approvals.setdefault(command_id, set()).add(self.drone_id)
        # Add own share to collected shares
        self.collected_shares.setdefault(command_id, []).append(self.share)

        return signed_app, elapsed

    def process_peer_approval(self, approval: ApprovalMessage) -> Tuple[bool, float]:
        """
        Decentralized verification of peer drone approvals.
        Ensures sender is trusted and Falcon signature is valid.
        """
        if not self.trust_registry.is_trusted(approval.drone_id):
            return False, 0.0

        peer_pk = self.trust_registry.get_public_key(approval.drone_id)
        if not peer_pk:
            return False, 0.0

        sig_bytes = bytes.fromhex(approval.signature_hex)
        start = time.perf_counter()
        is_valid = self.signer.verify(peer_pk, approval.digest(), sig_bytes)
        elapsed = time.perf_counter() - start

        if is_valid:
            self.peer_approvals.setdefault(approval.command_id, set()).add(approval.drone_id)

        return is_valid, elapsed

    def provide_share(self, command_id: str) -> ShareMessage:
        """Provide this drone's Shamir share signed for the given command."""
        share_msg = ShareMessage(
            command_id=command_id,
            drone_id=self.drone_id,
            x=self.share[0],
            y=self.share[1],
        )
        sig = self.signer.sign(self.private_key, share_msg.digest())
        return share_msg.with_signature(sig)

    def receive_share(self, share_msg: ShareMessage) -> bool:
        """Verify peer share signature and store for local reconstruction."""
        if not self.trust_registry.is_trusted(share_msg.drone_id):
            return False

        peer_pk = self.trust_registry.get_public_key(share_msg.drone_id)
        if not peer_pk:
            return False

        sig_bytes = bytes.fromhex(share_msg.signature_hex)
        if not self.signer.verify(peer_pk, share_msg.digest(), sig_bytes):
            return False

        stored = self.collected_shares.setdefault(share_msg.command_id, [])
        if not any(s[0] == share_msg.x for s in stored):
            stored.append((share_msg.x, share_msg.y))
        return True

    def can_execute(self, command_id: str) -> bool:
        """Check if local threshold condition is satisfied."""
        approvals = self.peer_approvals.get(command_id, set())
        shares = self.collected_shares.get(command_id, [])
        return len(approvals) >= self.threshold and len(shares) >= self.threshold

    def execute_command(self, command_id: str) -> Optional[Dict[str, Any]]:
        """
        Reconstruct mission key locally from collected shares and decrypt the command payload.
        """
        if not self.can_execute(command_id):
            return None

        command = self.known_commands.get(command_id)
        if not command:
            return None

        shares = self.collected_shares[command_id][: self.threshold]
        reconstructed_key_int = reconstruct_secret(shares)

        try:
            mission_key = reconstructed_key_int.to_bytes(32, byteorder="big")
        except OverflowError:
            return None

        nonce = bytes.fromhex(command.nonce_hex)
        ciphertext = bytes.fromhex(command.ciphertext_hex)
        aad = bytes.fromhex(command.aad_hex)

        try:
            payload = decrypt_payload(mission_key, nonce, ciphertext, aad=aad)
            return payload
        except Exception:
            return None
